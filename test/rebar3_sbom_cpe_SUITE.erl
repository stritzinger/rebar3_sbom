-module(rebar3_sbom_cpe_SUITE).

% CT Exports
-export([all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

% Testcases
-export([hex_core_cpe_test/1]).
-export([plug_cpe_test/1]).
-export([phoenix_cpe_test/1]).
-export([coherence_cpe_test/1]).
-export([xain_cpe_test/1]).
-export([sweet_xml_cpe_test/1]).
-export([no_url_test/1]).

% Includes
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%--- Common test functions -----------------------------------------------------

all() -> [hex_core_cpe_test,
          plug_cpe_test,
          phoenix_cpe_test,
          coherence_cpe_test,
          xain_cpe_test,
          sweet_xml_cpe_test,
          no_url_test].

init_per_suite(Config) ->
    Config.

end_per_suite(Config) ->
    Config.

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _Config) ->
    ok.

%--- Test cases ----------------------------------------------------------------

hex_core_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:hex(<<"hex_core">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:hex:hex_core:1.0.0:*:*:*:*:*:*:*">>, CPE).

plug_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:hex(<<"plug">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:elixir-plug:plug:1.0.0:*:*:*:*:*:*:*">>, CPE).

phoenix_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:hex(<<"phoenix">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:phoenixframework:phoenix:1.0.0:*:*:*:*:*:*:*">>, CPE).

coherence_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:hex(<<"coherence">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:coherence_project:coherence:1.0.0:*:*:*:*:*:*:*">>, CPE).

xain_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:hex(<<"xain">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:emetrotel:xain:1.0.0:*:*:*:*:*:*:*">>, CPE).

sweet_xml_cpe_test(_) ->
    CPE = rebar3_sbom_cpe:hex(<<"sweet_xml">>, <<"1.0.0">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:kbrw:sweet_xml:1.0.0:*:*:*:*:*:*:*">>, CPE).

no_url_test(_) ->
    CPE = rebar3_sbom_cpe:hex(<<"grisp">>, <<"1.0.0">>, undefined),
    ?assertEqual(undefined, CPE).
