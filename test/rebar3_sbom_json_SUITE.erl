-module(rebar3_sbom_json_SUITE).

% CT Exports
-export([all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).

% Testcases
-export([required_fields_test/1]).
-export([serial_number_test/1]).
-export([version_test/1]).

% metadata group test cases
-export([timestamp_test/1]).
-export([tools_test/1]).
-export([licenses_test/1]).
-export([component_test/1]).

% basic app with sbom group test cases
-export([serial_number_change_test/1]).
-export([version_increment_test/1]).
-export([timestamp_increases_test/1]).

% Includes
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("rebar3_sbom/include/rebar3_sbom.hrl").

% Macros
-define(SERIAL_NB_REGEX, "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").
-define(RFC3339_REGEX, "^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])[T\\s]([01]\\d|2[0-3]):([0-5]\\d):([0-5]\\d)(\\.\\d+)?(Z|[+-]([01]\\d|2[0-3]):[0-5]\\d)$").
-define(BOM_LINK_INTRO, "urn:cdx").
-define(VALID_HASH_ALGORITHMS, [<<"MD5">>,
                                 <<"SHA-1">>,
                                 <<"SHA-256">>,
                                 <<"SHA-384">>,
                                 <<"SHA-512">>,
                                 <<"SHA3-256">>,
                                 <<"SHA3-384">>,
                                 <<"SHA3-512">>,
                                 <<"BLAKE2b-256">>,
                                 <<"BLAKE2b-384">>,
                                 <<"BLAKE2b-512">>,
                                 <<"BLAKE3">>,
                                 <<"Streebog-256">>,
                                 <<"Streebog-512">>]).
-define(HASH_CONTENT_REGEX, "^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$").
-define(PURL_REGEX, "^pkg:[a-z][a-z0-9+.-]*/([^/@?#]+/)*[^/@?#]+(@[^?#]+)?(\\?[^#]+)?(#.+)?$").

%--- Common test functions -----------------------------------------------------

all() -> [{group, basic_app}].

groups() -> [{basic_app, [], [required_fields_test,
                              serial_number_test,
                              version_test,
                              {group, metadata},
                              {group, basic_app_with_sbom}]},
             {metadata, [], [timestamp_test,
                             tools_test, % TODO maybe add author test
                             licenses_test,
                             component_test]},
             {basic_app_with_sbom, [], [serial_number_change_test,
                                        version_increment_test,
                                        timestamp_increases_test]}].

init_per_suite(Config) ->
    application:load(rebar3_sbom),
    {ok, PluginVersion} = application:get_key(rebar3_sbom, vsn),
    {ok, PluginDescription} = application:get_key(rebar3_sbom, description),
    [{plugin_version, list_to_binary(PluginVersion)},
     {plugin_description, list_to_binary(PluginDescription)} | Config].

end_per_suite(_Config) ->
    ok.

init_per_group(basic_app, Config) ->
    State = init_rebar_state(Config),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, "bom.json"),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    SBoMJSON = json:decode(File),
    [{sbom_path, SBoMPath},
     {sbom_json, SBoMJSON} | Config];
init_per_group(basic_app_with_sbom, Config) ->
    timer:sleep(1000), % makes sure that new generated TS must be different
    State = init_rebar_state(Config),
    SBoMPath = ?config(sbom_path, Config),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{new_sbom_json, NewSBoMJSON} | Config];
init_per_group(metadata, Config) ->
    #{<<"metadata">> := Metadata} = ?config(sbom_json, Config),
    [{metadata, Metadata} | Config];
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _Config) ->
    ok.

%--- Tests ---------------------------------------------------------------------

%--- basic_app group ---
required_fields_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"bomFormat">> := BomFormat, <<"specVersion">> := SpecVersion} = SBoMJSON,
    ?assertEqual(<<"CycloneDX">>, BomFormat),
    ?assertEqual(<<?SPEC_VERSION/bitstring>>, SpecVersion).

serial_number_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"serialNumber">> := SerialNumber} = SBoMJSON,
    ?assertNotEqual(nomatch, re:run(SerialNumber, ?SERIAL_NB_REGEX)).

version_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"version">> := Version} = SBoMJSON,
    % Since the app doesn't have a sbom version should be 1
    ?assertEqual(1, Version).

%--- metadata group ---
timestamp_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := Metadata} = SBoMJSON,
    #{<<"timestamp">> := Timestamp} = Metadata,
    ?assertNotEqual(nomatch, re:run(Timestamp, ?RFC3339_REGEX)),
    timer:sleep(1000), % Make sure that TS is different
    SysTimeNow = erlang:system_time(second),
    StringTS = binary_to_list(Timestamp),
    TsSysTime = calendar:rfc3339_to_system_time(StringTS),
    ?assert(TsSysTime < SysTimeNow).

tools_test(Config) ->
    % Assume that in basic_app we only have a component for rebar3_sbom
    #{<<"tools">> := Tools} = ?config(metadata, Config),
    ?assertMatch([_], Tools),
    [Tool] = Tools,
    check_component_constraints(Tool),
    #{<<"type">> := Type, <<"name">> := Name, <<"isExternal">> := IsExternal,
      <<"version">> := Version, <<"description">> := Description,
      <<"hashes">> := Hashes, <<"purl">> := Purl,
      <<"licenses">> := [License]} = Tool,
    ?assertEqual(<<"application">>, Type),
    ?assertEqual(<<"rebar3_sbom">>, Name),
    ?assertNot(IsExternal),
    check_bom_ref_format(Tool),
    ?assertEqual(?config(plugin_version, Config), Version),
    ?assertEqual(?config(plugin_description, Config), Description),
    check_hashes_constraints(Hashes), % TODO Test if hashes values are correct
    check_purl_format(Purl),
    ?assertMatch(<<"pkg:hex/rebar3_sbom", _/bitstring>>, Purl),
    ?assertMatch(#{<<"license">> := #{<<"id">> := <<"Apache-2.0">>}}, License).

licenses_test(Config) ->
    Metadata = ?config(metadata, Config),
    ?assertMatch(#{<<"licenses">> := [_]}, Metadata,
                 "metadata.licenses is missing"),
    #{<<"licenses">> := [License]} = Metadata,
    ?assertMatch(#{<<"license">> := #{<<"id">> := <<"Apache-2.0">>}}, License).

component_test(Config) ->
    #{<<"component">> := Component} = ?config(metadata, Config),
    check_component_constraints(Component),
    #{<<"type">> := Type, <<"name">> := Name, <<"version">> := Version,
      <<"description">> := Description, <<"licenses">> := [License],
      <<"purl">> := Purl} = Component,
    ?assertEqual(<<"application">>, Type, "metadata.component.type"),
    ?assertEqual(<<"basic_app">>, Name, "metadata.component.name"),
    ?assertEqual(<<"0.1.0">>, Version, "metadata.component.version"),
    ?assertEqual(<<"An OTP application">>, Description,
                 "metadata.component.description"),
    % We don't check the hashes for now because it's not properly handled yet
    % A tarball will be required to generate an hash. Without it, we will skip
    % check_hashes_constraints(Hashes),
    ?assertMatch(#{<<"license">> := #{<<"id">> := <<"Apache-2.0">>}}, License,
                 "metadata.component.licenses[0].license.id"),
    check_purl_format(Purl),
    ?assertEqual(<<"pkg:hex/basic_app@0.1.0">>, Purl,
                 "metadata.component.purl").

%--- basic_app_with_sbom group ---
serial_number_change_test(Config) ->
    OldSBoMJSON = ?config(sbom_json, Config),
    NewSBoMJSON = ?config(new_sbom_json, Config),
    #{<<"serialNumber">> := OldSerialNumber} = OldSBoMJSON,
    #{<<"serialNumber">> := NewSerialNumber} = NewSBoMJSON,
    ?assertNotEqual(nomatch, re:run(NewSerialNumber, ?SERIAL_NB_REGEX)),
    ?assertNotEqual(OldSerialNumber, NewSerialNumber).

version_increment_test(Config) ->
    OldSBoMJSON = ?config(sbom_json, Config),
    NewSBoMJSON = ?config(new_sbom_json, Config),
    #{<<"version">> := OldVersion} = OldSBoMJSON,
    #{<<"version">> := NewVersion} = NewSBoMJSON,
    ?assertNotEqual(OldVersion, NewVersion),
    ?assert(NewVersion > OldVersion andalso NewVersion > 1).

timestamp_increases_test(Config) ->
    #{<<"metadata">> := OldMetaData} = ?config(sbom_json, Config),
    #{<<"timestamp">> := OldTs} = OldMetaData,
    #{<<"metadata">> := NewMetadata} = ?config(new_sbom_json, Config),
    #{<<"timestamp">> := NewTs} = NewMetadata,
    OldSysTime = calendar:rfc3339_to_system_time(binary_to_list(OldTs)),
    NewSysTime = calendar:rfc3339_to_system_time(binary_to_list(NewTs)),
    ?assert( OldSysTime < NewSysTime).

%--- Private -------------------------------------------------------------------
get_app_dir(DataDir) ->
    SplitDataDir = filename:split(DataDir),
    JoinedParentDir = filename:join(lists:droplast(SplitDataDir)),
    AppDir = filename:join(JoinedParentDir, "basic_app"),
    true = filelib:is_dir(AppDir),
    AppDir.

init_rebar_state(Config) ->
    DataDir = ?config(data_dir, Config),
    PrivDir = ?config(priv_dir, Config),
    AppDir = get_app_dir(DataDir),
    BaseDir = filename:join([PrivDir, "_build"]),
    State = rebar_state:new([
                {base_dir, BaseDir},
                {root_dir, AppDir}
               ]),
    RebarConfig = rebar_config:consult(AppDir),
    State2 = rebar_state:new(State, RebarConfig, AppDir),
    {ok, NewState} = rebar3_sbom_prv:init(State2),
    NewState.

check_component_constraints(Component) ->
    check_component_cyclonedx_constraints(Component),
    check_component_ort_constraints(Component).

% These are the constraints defined by the CycloneDX JSON reference
check_component_cyclonedx_constraints(Component) ->
    case Component of
        #{<<"version">> := _, <<"versionRange">> := _} ->
            ct:fail("Requirement 1: version and versionRange shall not be "
                    ++ "present simultaneously.");
        #{<<"isExternal">> := false, <<"versionRange">> := _} ->
            ct:fail("Requirement 2: versionRange must not be present when "
                    ++ "isExternal is false.");
        #{<<"author">> := _} ->
            ct:fail("author field is deprecated");
        #{<<"modified">> := _} ->
            ct:fail("modified field is deprecated");
        #{<<"type">> := Type, <<"name">> := _} ->
            ?assert(Type =/= <<"data">> orelse maps:is_key(<<"data">>, Component),
                    "If component.type is 'data', then component.data must be present"),
            ok;
        _ ->
            ct:fail("Missing required field 'type' and/or 'name'")
    end.

% These are the constraints that we impose for ORT
% Hashes might be needed but we also need to cover a few edge cases
check_component_ort_constraints(Component) ->
    ?assert(maps:is_key(<<"bom-ref">>, Component),
           "Component bom-ref is missing"),
    #{<<"bom-ref">> := BomRef} = Component,
    ?assertMatch([_ | _], binary_to_list(BomRef)),
    ?assert(maps:is_key(<<"version">>, Component) orelse
            maps:is_key(<<"versionRange">>, Component),
            "Component version or version range is missing"),
    ?assert(maps:is_key(<<"description">>, Component),
            "Component description is missing"),
    ?assert(maps:is_key(<<"licenses">>, Component),
            "Component licenses are required"),
    ?assert(maps:is_key(<<"purl">>, Component),
            "Component purl is missing").

check_bom_ref_format(Component) ->
    #{<<"bom-ref">> := BomRef} = Component,
    ?assertNotMatch(<<?BOM_LINK_INTRO, _/bitstring>>, BomRef).

check_hashes_constraints(Hashes) ->
    lists:foreach(fun(#{<<"alg">> := Alg, <<"content">> := Content}) ->
                        ?assert(lists:member(Alg, ?VALID_HASH_ALGORITHMS)),
                        ?assertNotEqual(nomatch, re:run(Content, ?HASH_CONTENT_REGEX));
                     (_) ->
                          ct:fail("The hash object doesn't have alg or/and" ++
                                  "content")
                  end, Hashes).

check_purl_format(Purl) ->
    ?assertNotEqual(nomatch, re:run(Purl, ?PURL_REGEX)).
