-module(rebar3_sbom_cpe).

-export([hex/3]).

% Includes
-include("rebar3_sbom.hrl").

%--- Macros --------------------------------------------------------------------
-define(CPE_PREFIX, <<"cpe:", ?CPE_VERSION/binary>>).
% Includes the fields:
% - update
% - edition
% - language
% - target_sw
% - target_hw
% - other
-define(CPE_POSTFIX, <<":*:*:*:*:*:*:*">>).

% The CPE specs define 3 classes of parts:
% - a: application
% - o: operating system
% - h: hardware
% We only support application components for now.
-define(CPE_PART_APPLICATION, <<"a">>).

%--- API -----------------------------------------------------------------------

-spec hex(Name, Version, Url) -> CPE when
    Name :: bitstring(),
    Version :: bitstring(),
    Url :: bitstring() | undefined,
    CPE :: bitstring().
hex(<<"hex_core">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":hex:hex_core:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(<<"plug">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":elixir-plug:plug:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(<<"phoenix">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":phoenixframework:phoenix:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(<<"coherence">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":coherence_project:coherence:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(<<"xain">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":emetrotel:xain:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(<<"sweet_xml">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":kbrw:sweet_xml:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(<<"erlang/otp">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":erlang:erlang\/otp:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(<<"rebar3">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":erlang:rebar3:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(<<"elixir">>, Version, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":elixir-lang:elixir:", Version/bitstring, ?CPE_POSTFIX/binary>>;
hex(_Name, _Version, undefined) ->
    undefined;
hex(Name, Version, Url) ->
    Organization = github_url(Url),
    cpe(Organization, Name, Version).

%--- Private -------------------------------------------------------------------

-spec github_url(Url) -> Organization when
    Url :: bitstring(),
    Organization :: bitstring().
github_url(Url) ->
    <<"https://github.com/", Rest/bitstring>> = Url,
    [Organization | _] = string:split(Rest, "/"),
    Organization.

-spec cpe(Organization, Name, Version) -> CPE when
    Organization :: bitstring(),
    Name :: bitstring(),
    Version :: bitstring(),
    CPE :: bitstring().
cpe(Organization, Name, Version) ->
    <<?CPE_PREFIX/binary, ":a:", Organization/binary, ":", Name/binary, ":", Version/bitstring, ?CPE_POSTFIX/binary>>.
