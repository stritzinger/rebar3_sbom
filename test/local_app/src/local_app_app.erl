%%%-------------------------------------------------------------------
%% @doc local_app public API
%% @end
%%%-------------------------------------------------------------------

-module(local_app_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    local_app_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
