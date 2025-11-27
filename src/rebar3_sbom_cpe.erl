-module(rebar3_sbom_cpe).

-export([hex/3]).

% Includes
-include("rebar3_sbom.hrl").

%--- API -----------------------------------------------------------------------

hex(_Name, _Version, undefined) ->
    undefined;
hex(Name, Version, Url) ->
    Organization = github_url(Url),
    cpe(Organization, Name, Version).

%--- Private -------------------------------------------------------------------

github_url(Url) ->
    <<"https://github.com/", Rest/bitstring>> = Url,
    case string:split(Rest, "/") of
        [Organization | _] ->
            Organization;
        _ ->
            undefined
    end.

cpe(Organization, Name, Version) ->
    io:format("Organization: ~p, Name: ~p, Version: ~p~n", [Organization, Name, Version]),
    <<"cpe:", ?CPE_VERSION/binary, ":a:", Organization/binary, ":", Name/binary, ":", Version/bitstring, ":*:*:*:*:*:*:*">>.