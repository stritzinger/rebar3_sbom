-module(rebar3_sbom_cpe).

-export([hex/3]).

% Includes
-include("rebar3_sbom.hrl").

%--- API -----------------------------------------------------------------------

-spec hex(Name, Version, Url) -> CPE when
    Name :: bitstring(),
    Version :: bitstring(),
    Url :: bitstring() | undefined,
    CPE :: bitstring().
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
    <<"cpe:", ?CPE_VERSION/binary, ":a:", Organization/binary, ":", Name/binary, ":", Version/bitstring, ":*:*:*:*:*:*:*">>.
