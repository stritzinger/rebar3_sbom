-module(rebar3_sbom_prv).

-export([init/1, do/1, format_error/1]).

-include("rebar3_sbom.hrl").

%% ===================================================================
%% Public API
%% ===================================================================
-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider = providers:create([
            {name, ?PROVIDER},            % The 'user friendly' name of the task
            {module, ?MODULE},            % The module implementation of the task
            {bare, true},                 % The task can be run by the user, always true
            {deps, ?DEPS},                % The list of dependencies
            {example, "rebar3 sbom"},     % How to use the plugin
            {opts, [                      % list of options understood by the plugin
              {format, $F, "format", {string, "xml"}, "file format, [xml|json]"},
              {output, $o, "output", {string, ?DEFAULT_OUTPUT}, "the full path to the SBoM output file"},
              {force, $f, "force", {boolean, false}, "overwite existing files without prompting for confirmation"},
              {strict_version, $V, "strict_version", {boolean, true}, "modify the version number of the bom only when the content changes"}
            ]},
            {short_desc, "Generates CycloneDX SBoM"},
            {desc, "Generates a Software Bill-of-Materials (SBoM) in CycloneDX format"}
    ]),
    {ok, rebar_state:add_provider(State, Provider)}.

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, string()}.
do(State) ->
    {Args, _} = rebar_state:command_parsed_args(State),
    Format = proplists:get_value(format, Args),
    Output = proplists:get_value(output, Args),
    Force = proplists:get_value(force, Args),
    IsStrictVersion = proplists:get_value(strict_version, Args),
    [App0 | _] = rebar_state:project_apps(State),
    App = rebar_app_info:source(App0, root_app),

    FilePath = filepath(Output, Format),
    DepsInfo = [dep_info(Dep) || Dep <- rebar_state:all_deps(State)],
    AppInfo = dep_info(App),
    SBoM = rebar3_sbom_cyclonedx:bom({FilePath, Format}, IsStrictVersion, AppInfo, DepsInfo),
    Contents = case Format of
        "xml" -> rebar3_sbom_xml:encode(SBoM);
        "json" -> rebar3_sbom_json:encode(SBoM)
    end,
    case write_file(FilePath, Contents, Force) of
        ok ->
            rebar_api:info("CycloneDX SBoM written to ~s", [FilePath]),
            {ok, State};
        {error, Message} ->
            {error, {?MODULE, Message}}
    end.

-spec format_error(any()) -> iolist().
format_error(Message) ->
    io_lib:format("~s", [Message]).

dep_info(Dep) ->
    Name = rebar_app_info:name(Dep),
    Version = rebar_app_info:original_vsn(Dep),
    Source = rebar_app_info:source(Dep),
    Details = rebar_app_info:app_details(Dep),
    Deps = rebar_app_info:deps(Dep),
    Licenses0 = proplists:get_value(licenses, Details, []),
    HexMetadataLicenses = hex_metadata_licenses(Dep),
    ExternalReferences = case proplists:get_value(links, Details) of
        undefined ->
            undefined;
        Links ->
            find_references(Links)
    end,
    % remove duplicates, if any
    Licenses = lists:usort(Licenses0 ++ HexMetadataLicenses),
    Common =
        [
         {authors, proplists:get_value(maintainers, Details)},
         {description, proplists:get_value(description, Details)},
         {licenses, Licenses},
         {external_references, ExternalReferences},
         {dependencies, Deps}
        ],
    dep_info(Name, Version, Source, Common).

hex_metadata_licenses(Dep) ->
    DepDir = rebar_app_info:dir(Dep),
    % hardcoded in rebar3, too
    HexMetadataFile = "hex_metadata.config",
    HexMetadataPath = filename:join(DepDir, HexMetadataFile),

    case filelib:is_regular(HexMetadataPath) of
        true ->
            {ok, Terms} = file:consult(HexMetadataPath),
            HexMetadataLicenses = proplists:get_value(<<"licenses">>, Terms, []),
            [binary_to_list(HexMetadataLicense) || HexMetadataLicense <- HexMetadataLicenses];
        false ->
            []
    end.

find_references(Links) ->
    lists:filtermap(
        fun({Type, _}) ->
                lists:member(Type, valid_external_reference_types());
           (_) -> false
        end,
        Links
    ).

valid_external_reference_types() ->
    % https://cyclonedx.org/docs/1.6/json/#metadata_component_externalReferences_items_type
    ["vcs", "issue-tracker", "website", "advisories", "bom", "mailing-list",
     "social", "chat", "documentation", "support", "source-distribution",
     "distribution", "distribution-intake", "license", "build-meta", "build-system",
     "release-notes", "security-contact", "model-card", "log", "configuration",
     "evidence", "formulation", "attestation", "threat-model", "adversary-model",
     "risk-assessment", "vulnerability-assertion", "exploitability-statement",
     "pentest-report", "static-analysis-report", "dynamic-analysis-report",
     "runtime-analysis-report", "component-analysis-report", "maturity-report",
     "certification-report", "codified-infrastructure", "quality-metrics",
     "poam", "electronic-signature", "digital-signature", "rfc-9116", "other"].

dep_info(_Name, _Version, {pkg, Name, Version, Sha256}, Common) ->
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:hex(Name, Version)},
        {sha256, string:lowercase(Sha256)}
    | Common ];

dep_info(_Name, _Version, {pkg, Name, Version, _InnerChecksum, OuterChecksum, _RepoConfig}, Common) ->
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:hex(Name, Version)},
        {sha256, string:lowercase(OuterChecksum)}
    | Common ];

dep_info(Name, DepVersion, {git, Git, GitRef}, Common) ->
    {Version, Purl} =
        case GitRef of
            {tag, Tag} ->
                {Tag, rebar3_sbom_purl:git(Name, Git, Tag)};
            {branch, Branch} ->
                {DepVersion, rebar3_sbom_purl:git(Name, Git, Branch)};
            {ref, Ref} ->
                {DepVersion, rebar3_sbom_purl:git(Name, Git, Ref)}
        end,
    [
     {name, Name},
     {version, Version},
     {purl, Purl}
    | maybe_update_licenses(Purl, Common) ];
dep_info(Name, Version, {git_subdir, Git, Ref, _Dir}, Common) ->
    dep_info(Name, Version, {git, Git, Ref}, Common);

dep_info(Name, Version, root_app, Common) ->
    Purl = rebar3_sbom_purl:hex(Name, Version),
    [{name, Name}, {version, Version}, {purl, Purl} | Common].

filepath(?DEFAULT_OUTPUT, Format) ->
    "./bom." ++ Format;
filepath(Path, _Format) ->
    Path.

write_file(Filename, Contents, true) ->
    file:write_file(Filename, Contents);

write_file(Filename, Xml, false) ->
    case file:read_file_info(Filename) of
        {error, enoent} ->
            write_file(Filename, Xml, true);
        {ok, _FileInfo} ->
            Prompt = io_lib:format("File ~s exists; overwrite? [Y/N] ", [Filename]),
            case io:get_line(Prompt) of
                "y\n" -> write_file(Filename, Xml, true);
                "Y\n" -> write_file(Filename, Xml, true);
                _ -> {error, "Aborted"}
            end;
        Error ->
            Error
    end.

maybe_update_licenses(Purl, Common) ->
    case proplists:get_value(licenses, Common) of
        [_|_] ->
            %% Non-empty list, ok
            Common;
        _ ->
            %% [] or 'undefined'
            case Purl of
                <<"pkg:github/", GithubPurlString/binary>> ->
                    case get_github_license(GithubPurlString) of
                        {ok, SPDX_Id} ->
                            lists:keyreplace(licenses, 1, Common,
                                             {licenses, [SPDX_Id]});
                        _ ->
                            Common
                    end;
                _ ->
                    Common
            end
    end.

get_github_license(String) ->
    case re:split(String, <<"[/@]">>) of
        [Org, Repo, _Ref] ->
            get_github_license(Org, Repo);
        _ ->
            {error, string}
    end.

get_github_license(Org, Repo) ->
    URI =
        #{ scheme => <<"https">>,
           path => filename:join([<<"/repos">>, Org, Repo, <<"license">>]),
           host => <<"api.github.com">>
         },
    URIStr = uri_string:recompose(URI),
    Headers = #{<<"user-agent">> => <<"rebar3">>},
    case
        rebar_httpc_adapter:request(get, URIStr, Headers, undefined, #{})
    of
        {ok, {200, _ReplyHeaders, Body}} ->
            case jsone:decode(Body) of
                #{<<"license">> := #{<<"spdx_id">> := SPDX_Id}} ->
                    {ok, SPDX_Id};
                _ ->
                    {error, body}
            end;
        _ ->
            {error, request}
    end.
