-module(rebar3_sbom_json_SUITE).

% CT Exports
-export([all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).

% Testcases
-export([required_fields_test/1]).


% Includes

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("rebar3_sbom/include/rebar3_sbom.hrl").

%--- Common test functions -----------------------------------------------------o

all() -> [{group, basic_app}].

groups() -> [{basic_app, [], [required_fields_test]}].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(basic_app, Config) ->
    State = init_rebar_state(Config),
    PrivDir = ?config(priv_dir, Config),
    Output = filename:join(PrivDir, "bom.json"),
    CommandParsedArgs = [{format, "json"},
                         {output, Output},
                         {force, false},
                         {strict_version, true}],
    State2 = rebar_state:command_parsed_args(State, {CommandParsedArgs, []}),
    {ok, _FinalState} = rebar3_sbom_prv:do(State2),
    
    ct:log("Output: ~p", [Output]),
    {ok, File} = file:read_file(Output),
    JsonTerm = json:decode(File),
    [{json_term, JsonTerm} | Config].


end_per_group(_, _Config) ->
    ok.

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _Config) ->
    ok.

%--- Tests ---------------------------------------------------------------------

required_fields_test(Config) ->
    JsonTerm = ?config(json_term, Config),
    #{<<"bomFormat">> := BomFormat, <<"specVersion">> := SpecVersion} = JsonTerm,
    ?assertEqual(<<"CycloneDX">>, BomFormat),
    ?assertEqual(<<?SPEC_VERSION/bitstring>>, SpecVersion).

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
    State2 = rebar_state:dir(State, AppDir),
    {ok, NewState} = rebar3:run(State2, ["compile"]),
    % ct:log("New State ~p", [NewState]),
    NewState.
