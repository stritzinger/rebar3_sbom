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

-export([timestamp_test/1]).

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

%--- Common test functions -----------------------------------------------------

all() -> [{group, basic_app}].

groups() -> [{basic_app, [], [required_fields_test,
                              serial_number_test,
                              version_test,
                              {group, metadata},
                              {group, basic_app_with_sbom}]},
             {metadata, [], [timestamp_test]},
             {basic_app_with_sbom, [], [serial_number_change_test,
                                        version_increment_test,
                                        timestamp_increases_test]}].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(basic_app, Config) ->
    State = init_rebar_state(Config),
    PrivDir = ?config(priv_dir, Config),
    SBoMPath = filename:join(PrivDir, "bom.json"),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false"],
    {ok, FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    SBoMJSON = json:decode(File),
    [{sbom_path, SBoMPath},
     {sbom_json, SBoMJSON},
     {rebar_state, FinalState} | Config];
init_per_group(basic_app_with_sbom, Config) ->
    timer:sleep(1000), % makes sure that new generated TS must be different
    State = ?config(rebar_state, Config),
    SBoMPath = ?config(sbom_path, Config),
    Cmd = ["sbom", "-F", "json", "-o", SBoMPath, "-V", "false", "-f"],
    {ok, _FinalState} = rebar3:run(State, Cmd),
    {ok, File} = file:read_file(SBoMPath),
    NewSBoMJSON = json:decode(File),
    [{new_sbom_json, NewSBoMJSON} | Config];
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _Config) ->
    ok.

%--- Tests ---------------------------------------------------------------------

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

timestamp_test(Config) ->
    SBoMJSON = ?config(sbom_json, Config),
    #{<<"metadata">> := Metadata} = SBoMJSON,
    #{<<"timestamp">> := Timestamp} = Metadata,
    ?assertNotEqual(nomatch, re:run(Timestamp, ?RFC3339_REGEX)),
    timer:sleep(1000), % Make sure that TS should be different
    SysTimeNow = erlang:system_time(second),
    TsSysTime = calendar:rfc3339_to_system_time(Timestamp),
    ?assert(TsSysTime < SysTimeNow).

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
    OldSysTime = calendar:rfc3339_to_system_time(OldTs),
    NewSysTime = calendar:rfc3339_to_system_time(NewTs),
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
    State2 = rebar_state:dir(State, AppDir),
    {ok, State3} = rebar3:run(State2, ["compile"]),
    {ok, NewState} = rebar3_sbom_prv:init(State3),
    NewState.
