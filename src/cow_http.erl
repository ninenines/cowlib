%% Copyright (c) 2013, Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(cow_http).

-export([parse_fullhost/1]).
-export([parse_fullpath/1]).
-export([parse_version/1]).

-include("cow_inline.hrl").

%% @doc Extract host and port from a binary.
%%
%% Because the hostname is case insensitive it is converted
%% to lowercase.

-spec parse_fullhost(binary()) -> {binary(), undefined | non_neg_integer()}.
parse_fullhost(Fullhost) ->
	parse_fullhost(Fullhost, false, <<>>).

parse_fullhost(<< $[, Rest/bits >>, false, <<>>) ->
	parse_fullhost(Rest, true, << $[ >>);
parse_fullhost(<<>>, false, Acc) ->
	{Acc, undefined};
parse_fullhost(<< $:, Rest/bits >>, false, Acc) ->
	{Acc, list_to_integer(binary_to_list(Rest))};
parse_fullhost(<< $], Rest/bits >>, true, Acc) ->
	parse_fullhost(Rest, false, << Acc/binary, $] >>);
parse_fullhost(<< C, Rest/bits >>, E, Acc) ->
	case C of
		?INLINE_LOWERCASE(parse_fullhost, Rest, E, Acc)
	end.

-ifdef(TEST).
parse_fullhost_test() ->
	{<<"example.org">>, 8080} = parse_fullhost(<<"example.org:8080">>),
	{<<"example.org">>, undefined} = parse_fullhost(<<"example.org">>),
	{<<"192.0.2.1">>, 8080} = parse_fullhost(<<"192.0.2.1:8080">>),
	{<<"192.0.2.1">>, undefined} = parse_fullhost(<<"192.0.2.1">>),
	{<<"[2001:db8::1]">>, 8080} = parse_fullhost(<<"[2001:db8::1]:8080">>),
	{<<"[2001:db8::1]">>, undefined} = parse_fullhost(<<"[2001:db8::1]">>),
	{<<"[::ffff:192.0.2.1]">>, 8080}
		= parse_fullhost(<<"[::ffff:192.0.2.1]:8080">>),
	{<<"[::ffff:192.0.2.1]">>, undefined}
		= parse_fullhost(<<"[::ffff:192.0.2.1]">>),
	ok.
-endif.

%% @doc Extract path and query string from a binary.

-spec parse_fullpath(binary()) -> {binary(), binary()}.
parse_fullpath(Fullpath) ->
	parse_fullpath(Fullpath, <<>>).

parse_fullpath(<<>>, Path) ->
	{Path, <<>>};
parse_fullpath(<< $?, Qs/binary >>, Path) ->
	{Path, Qs};
parse_fullpath(<< C, Rest/binary >>, SoFar) ->
	parse_fullpath(Rest, << SoFar/binary, C >>).

-ifdef(TEST).
parse_fullpath_test() ->
	{<<"*">>, <<>>} = parse_fullpath(<<"*">>),
	{<<"/">>, <<>>} = parse_fullpath(<<"/">>),
	{<<"/path/to/resource">>, <<>>} = parse_fullpath(<<"/path/to/resource">>),
	{<<"/">>, <<>>} = parse_fullpath(<<"/?">>),
	{<<"/">>, <<"q=cowboy">>} = parse_fullpath(<<"/?q=cowboy">>),
	{<<"/path/to/resource">>, <<"q=cowboy">>}
		= parse_fullpath(<<"/path/to/resource?q=cowboy">>),
	ok.
-endif.

%% @doc Convert an HTTP version to atom.

-spec parse_version(binary()) -> 'HTTP/1.1' | 'HTTP/1.0'.
parse_version(<<"HTTP/1.1">>) ->
	'HTTP/1.1';
parse_version(<<"HTTP/1.0">>) ->
	'HTTP/1.0'.

-ifdef(TEST).
parse_version_test() ->
	'HTTP/1.1' = parse_version(<<"HTTP/1.1">>),
	'HTTP/1.0' = parse_version(<<"HTTP/1.0">>),
	{'EXIT', _} = (catch parse_version(<<"HTTP/1.2">>)),
	ok.
-endif.
