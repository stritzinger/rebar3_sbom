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
-export([erlang_otp_cpe_test/1]).
-export([rebar3_cpe_test/1]).
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
          erlang_otp_cpe_test,
          rebar3_cpe_test,
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

erlang_otp_cpe_test(_) ->
    OTP_19_RC1_CPE = rebar3_sbom_cpe:hex(<<"erlang/otp">>, <<"19.0">>,
                                         undefined, #{update => <<"rc1">>}),
    ?assertEqual(<<"cpe:2.3:a:erlang:erlang\/otp:19.0:rc1:*:*:*:*:*:*:*">>,
                 OTP_19_RC1_CPE),
    OTP_28_CPE = rebar3_sbom_cpe:hex(<<"erlang/otp">>, <<"28.0">>, undefined,
                                     #{update => <<"-">>}),
    ?assertEqual(<<"cpe:2.3:a:erlang:erlang\/otp:28.0:-:*:*:*:*:*:*">>,
                 OTP_28_CPE).

rebar3_cpe_test(_) ->
    REBAR3_CPE = rebar3_sbom_cpe:hex(<<"rebar3">>, <<"3.14.1">>, undefined),
    ?assertEqual(<<"cpe:2.3:a:erlang:rebar3:3.14.1:*:*:*:*:*:*:*">>,
                 REBAR3_CPE).

no_url_test(_) ->
    CPE = rebar3_sbom_cpe:hex(<<"grisp">>, <<"1.0.0">>, undefined),
    ?assertEqual(undefined, CPE).
