-module(rebar3_sbom_cpe).

-export([hex/3]).
-export([hex/4]).

% Includes
-include("rebar3_sbom.hrl").

%--- Macros --------------------------------------------------------------------
-define(CPE_PREFIX, <<"cpe:", ?CPE_VERSION/binary>>).

% The CPE specs define 3 classes of parts:
% - a: application
% - o: operating system
% - h: hardware
% We only support application components for now.
-define(CPE_PART_APPLICATION, <<"a">>).

%--- Types ---------------------------------------------------------------------

-type cpe_opts() :: #{update => bitstring(),
                      edition => bitstring(),
                      language => bitstring(),
                      target_sw => bitstring(),
                      target_hw => bitstring()}.

%--- API -----------------------------------------------------------------------

-spec hex(Name, Version, Url) -> CPE when
    Name :: bitstring(),
    Version :: bitstring(),
    Url :: bitstring() | undefined,
    CPE :: bitstring().
hex(Name, Version, URL) ->
    hex(Name, Version, URL, #{}).

-spec hex(Name, Version, Url, Opts) -> CPE when
    Name :: bitstring(),
    Version :: bitstring(),
    Url :: bitstring() | undefined,
    Opts :: cpe_opts(),
    CPE :: bitstring().
hex(<<"hex_core">>, Version, _, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":hex:hex_core:", Version/bitstring, ":*:*:*:*:*:*:*">>;
hex(<<"plug">>, Version, _, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":elixir-plug:plug:", Version/bitstring, ":*:*:*:*:*:*:*">>;
hex(<<"phoenix">>, Version, _, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":phoenixframework:phoenix:", Version/bitstring, ":*:*:*:*:*:*:*">>;
hex(<<"coherence">>, Version, _, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":coherence_project:coherence:", Version/bitstring, ":*:*:*:*:*:*:*">>;
hex(<<"xain">>, Version, _, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":emetrotel:xain:", Version/bitstring, ":*:*:*:*:*:*:*">>;
hex(<<"sweet_xml">>, Version, _, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":kbrw:sweet_xml:", Version/bitstring, ":*:*:*:*:*:*:*">>;
hex(<<"crypto">>, Version, _, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":erlang:crypto:", Version/bitstring, ":*:*:*:*:*:*:*">>;
hex(<<"erlang/otp">>, Version, _, Opts) ->
    Update = maps:get(update, Opts, "*"),
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":erlang:erlang\/otp:", Version/bitstring, ":", Update/bitstring,
      ":*:*:*:*:*:*:*">>;
hex(<<"rebar3">>, Version, _, _) ->
    <<?CPE_PREFIX/binary, ":", ?CPE_PART_APPLICATION/binary,
      ":erlang:rebar3:", Version/bitstring, ":*:*:*:*:*:*:*">>;
hex(_Name, _Version, undefined, _) ->
    undefined;
hex(Name, Version, Url, _) ->
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
    <<"cpe:", ?CPE_VERSION/binary, ":a:", Organization/binary, ":", Name/binary, ":", Version/bitstring, ":*:*:*:*:*:*:*">>.
