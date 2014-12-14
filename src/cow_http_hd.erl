%% Copyright (c) 2014, Loïc Hoguin <essen@ninenines.eu>
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

-module(cow_http_hd).

-export([parse_accept/1]).
-export([parse_accept_charset/1]).
-export([parse_accept_encoding/1]).
-export([parse_accept_language/1]).
-export([parse_connection/1]).
-export([parse_content_length/1]).
-export([parse_expect/1]).
-export([parse_max_forwards/1]).
-export([parse_transfer_encoding/1]).

-type qvalue() :: 0..1000.
-export_type([qvalue/0]).

-include("cow_inline.hrl").

-ifdef(TEST).
-include_lib("triq/include/triq.hrl").
-endif.

%% @doc Parse the Accept header.

-spec parse_accept(binary()) -> [{{binary(), binary(), [{binary(), binary()}]}, qvalue(), [binary() | {binary(), binary()}]}].
parse_accept(<<"*/*">>) ->
	[{{<<"*">>, <<"*">>, []}, 1000, []}];
parse_accept(Accept) ->
	nonempty(media_range_list(Accept, [])).

media_range_list(<<>>, Acc) -> lists:reverse(Acc);
media_range_list(<< $\s, R/bits >>, Acc) -> media_range_list(R, Acc);
media_range_list(<< $\t, R/bits >>, Acc) -> media_range_list(R, Acc);
media_range_list(<< $,, R/bits >>, Acc) -> media_range_list(R, Acc);
media_range_list(<< C, R/bits >>, Acc) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_range_type, R, Acc, <<>>)
	end.

media_range_type(<< $/, R/bits >>, Acc, T) -> media_range_subtype(R, Acc, T, <<>>);
%% Special clause for badly behaving user agents that send * instead of */*.
media_range_type(<< _, R/bits >>, Acc, <<"*">>) -> media_range_before_param(R, Acc, <<"*">>, <<"*">>, []);
media_range_type(<< C, R/bits >>, Acc, T) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_range_type, R, Acc, T)
	end.

media_range_subtype(<<>>, Acc, T, S) when S =/= <<>> -> lists:reverse([{{T, S, []}, 1000, []}|Acc]);
media_range_subtype(<< $,, R/bits >>, Acc, T, S) when S =/= <<>> -> media_range_list(R, [{{T, S, []}, 1000, []}|Acc]);
media_range_subtype(<< $;, R/bits >>, Acc, T, S) when S =/= <<>> -> media_range_before_param(R, Acc, T, S, []);
media_range_subtype(<< $\s, R/bits >>, Acc, T, S) when S =/= <<>> -> media_range_before_semicolon(R, Acc, T, S, []);
media_range_subtype(<< $\t, R/bits >>, Acc, T, S) when S =/= <<>> -> media_range_before_semicolon(R, Acc, T, S, []);
media_range_subtype(<< C, R/bits >>, Acc, T, S) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_range_subtype, R, Acc, T, S)
	end.

media_range_before_semicolon(<<>>, Acc, T, S, P) -> lists:reverse([{{T, S, lists:reverse(P)}, 1000, []}|Acc]);
media_range_before_semicolon(<< $,, R/bits >>, Acc, T, S, P) -> media_range_list(R, [{{T, S, lists:reverse(P)}, 1000, []}|Acc]);
media_range_before_semicolon(<< $;, R/bits >>, Acc, T, S, P) -> media_range_before_param(R, Acc, T, S, P);
media_range_before_semicolon(<< $\s, R/bits >>, Acc, T, S, P) -> media_range_before_semicolon(R, Acc, T, S, P);
media_range_before_semicolon(<< $\t, R/bits >>, Acc, T, S, P) -> media_range_before_semicolon(R, Acc, T, S, P).

media_range_before_param(<< $\s, R/bits >>, Acc, T, S, P) -> media_range_before_param(R, Acc, T, S, P);
media_range_before_param(<< $\t, R/bits >>, Acc, T, S, P) -> media_range_before_param(R, Acc, T, S, P);
%% Special clause for badly behaving user agents that send .123 instead of 0.123.
media_range_before_param(<< $q, $=, $., R/bits >>, Acc, T, S, P) -> media_range_broken_weight(R, Acc, T, S, P);
media_range_before_param(<< $q, $=, R/bits >>, Acc, T, S, P) -> media_range_weight(R, Acc, T, S, P);
media_range_before_param(<< C, R/bits >>, Acc, T, S, P) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_range_param, R, Acc, T, S, P, <<>>)
	end.

media_range_param(<< $=, $", R/bits >>, Acc, T, S, P, K) -> media_range_quoted(R, Acc, T, S, P, K, <<>>);
media_range_param(<< $=, R/bits >>, Acc, T, S, P, K) -> media_range_value(R, Acc, T, S, P, K, <<>>);
media_range_param(<< C, R/bits >>, Acc, T, S, P, K) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_range_param, R, Acc, T, S, P, K)
	end.

media_range_quoted(<< $", R/bits >>, Acc, T, S, P, K, V) -> media_range_before_semicolon(R, Acc, T, S, [{K, V}|P]);
media_range_quoted(<< $\\, C, R/bits >>, Acc, T, S, P, K, V) when ?IS_VCHAR(C) -> media_range_quoted(R, Acc, T, S, P, K, << V/binary, C >>);
media_range_quoted(<< C, R/bits >>, Acc, T, S, P, K, V) when ?IS_VCHAR(C) -> media_range_quoted(R, Acc, T, S, P, K, << V/binary, C >>).

media_range_value(<<>>, Acc, T, S, P, K, V) -> lists:reverse([{{T, S, lists:reverse([{K, V}|P])}, 1000, []}|Acc]);
media_range_value(<< $,, R/bits >>, Acc, T, S, P, K, V) -> media_range_list(R, [{{T, S, lists:reverse([{K, V}|P])}, 1000, []}|Acc]);
media_range_value(<< $;, R/bits >>, Acc, T, S, P, K, V) -> media_range_before_param(R, Acc, T, S, [{K, V}|P]);
media_range_value(<< $\s, R/bits >>, Acc, T, S, P, K, V) -> media_range_before_semicolon(R, Acc, T, S, [{K, V}|P]);
media_range_value(<< $\t, R/bits >>, Acc, T, S, P, K, V) -> media_range_before_semicolon(R, Acc, T, S, [{K, V}|P]);
media_range_value(<< C, R/bits >>, Acc, T, S, P, K, V) when ?IS_TOKEN(C) -> media_range_value(R, Acc, T, S, P, K, << V/binary, C >>).

%% Special function for badly behaving user agents that send .123 instead of 0.123.
media_range_broken_weight(<< A, B, C, R/bits >>, Acc, T, S, P)
	when A >= $0, A =< $9, B >= $0, B =< $9, C >= $0, C =< $9 ->
		accept_before_semicolon(R, Acc, T, S, P, (A - $0) * 100 + (B - $0) * 10 + (C - $0), []);
media_range_broken_weight(<< A, B, R/bits >>, Acc, T, S, P)
	when A >= $0, A =< $9, B >= $0, B =< $9 ->
		accept_before_semicolon(R, Acc, T, S, P, (A - $0) * 100 + (B - $0) * 10, []);
media_range_broken_weight(<< A, R/bits >>, Acc, T, S, P)
	when A >= $0, A =< $9 ->
		accept_before_semicolon(R, Acc, T, S, P, (A - $0) * 100, []).

media_range_weight(<< "1.000", R/bits >>, Acc, T, S, P) -> accept_before_semicolon(R, Acc, T, S, P, 1000, []);
media_range_weight(<< "1.00", R/bits >>, Acc, T, S, P) -> accept_before_semicolon(R, Acc, T, S, P, 1000, []);
media_range_weight(<< "1.0", R/bits >>, Acc, T, S, P) -> accept_before_semicolon(R, Acc, T, S, P, 1000, []);
media_range_weight(<< "1.", R/bits >>, Acc, T, S, P) -> accept_before_semicolon(R, Acc, T, S, P, 1000, []);
media_range_weight(<< "1", R/bits >>, Acc, T, S, P) -> accept_before_semicolon(R, Acc, T, S, P, 1000, []);
media_range_weight(<< "0.", A, B, C, R/bits >>, Acc, T, S, P)
	when A >= $0, A =< $9, B >= $0, B =< $9, C >= $0, C =< $9 ->
		accept_before_semicolon(R, Acc, T, S, P, (A - $0) * 100 + (B - $0) * 10 + (C - $0), []);
media_range_weight(<< "0.", A, B, R/bits >>, Acc, T, S, P)
	when A >= $0, A =< $9, B >= $0, B =< $9 ->
		accept_before_semicolon(R, Acc, T, S, P, (A - $0) * 100 + (B - $0) * 10, []);
media_range_weight(<< "0.", A, R/bits >>, Acc, T, S, P)
	when A >= $0, A =< $9 ->
		accept_before_semicolon(R, Acc, T, S, P, (A - $0) * 100, []);
media_range_weight(<< "0.", R/bits >>, Acc, T, S, P) -> accept_before_semicolon(R, Acc, T, S, P, 0, []);
media_range_weight(<< "0", R/bits >>, Acc, T, S, P) -> accept_before_semicolon(R, Acc, T, S, P, 0, []).

accept_before_semicolon(<<>>, Acc, T, S, P, Q, E) -> lists:reverse([{{T, S, lists:reverse(P)}, Q, lists:reverse(E)}|Acc]);
accept_before_semicolon(<< $,, R/bits >>, Acc, T, S, P, Q, E) -> media_range_list(R, [{{T, S, lists:reverse(P)}, Q, lists:reverse(E)}|Acc]);
accept_before_semicolon(<< $;, R/bits >>, Acc, T, S, P, Q, E) -> accept_before_ext(R, Acc, T, S, P, Q, E);
accept_before_semicolon(<< $\s, R/bits >>, Acc, T, S, P, Q, E) -> accept_before_semicolon(R, Acc, T, S, P, Q, E);
accept_before_semicolon(<< $\t, R/bits >>, Acc, T, S, P, Q, E) -> accept_before_semicolon(R, Acc, T, S, P, Q, E).

accept_before_ext(<< $\s, R/bits >>, Acc, T, S, P, Q, E) -> accept_before_ext(R, Acc, T, S, P, Q, E);
accept_before_ext(<< $\t, R/bits >>, Acc, T, S, P, Q, E) -> accept_before_ext(R, Acc, T, S, P, Q, E);
accept_before_ext(<< C, R/bits >>, Acc, T, S, P, Q, E) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(accept_ext, R, Acc, T, S, P, Q, E, <<>>)
	end.

accept_ext(<<>>, Acc, T, S, P, Q, E, K) -> lists:reverse([{{T, S, lists:reverse(P)}, Q, lists:reverse([K|E])}|Acc]);
accept_ext(<< $,, R/bits >>, Acc, T, S, P, Q, E, K) -> media_range_list(R, [{{T, S, lists:reverse(P)}, Q, lists:reverse([K|E])}|Acc]);
accept_ext(<< $;, R/bits >>, Acc, T, S, P, Q, E, K) -> accept_before_ext(R, Acc, T, S, P, Q, [K|E]);
accept_ext(<< $\s, R/bits >>, Acc, T, S, P, Q, E, K) -> accept_before_semicolon(R, Acc, T, S, P, Q, [K|E]);
accept_ext(<< $\t, R/bits >>, Acc, T, S, P, Q, E, K) -> accept_before_semicolon(R, Acc, T, S, P, Q, [K|E]);
accept_ext(<< $=, $", R/bits >>, Acc, T, S, P, Q, E, K) -> accept_quoted(R, Acc, T, S, P, Q, E, K, <<>>);
accept_ext(<< $=, R/bits >>, Acc, T, S, P, Q, E, K) -> accept_value(R, Acc, T, S, P, Q, E, K, <<>>);
accept_ext(<< C, R/bits >>, Acc, T, S, P, Q, E, K) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(accept_ext, R, Acc, T, S, P, Q, E, K)
	end.

accept_quoted(<< $", R/bits >>, Acc, T, S, P, Q, E, K, V) -> accept_before_semicolon(R, Acc, T, S, P, Q, [{K, V}|E]);
accept_quoted(<< $\\, C, R/bits >>, Acc, T, S, P, Q, E, K, V) when ?IS_VCHAR(C) -> accept_quoted(R, Acc, T, S, P, Q, E, K, << V/binary, C >>);
accept_quoted(<< C, R/bits >>, Acc, T, S, P, Q, E, K, V) when ?IS_VCHAR(C) -> accept_quoted(R, Acc, T, S, P, Q, E, K, << V/binary, C >>).

accept_value(<<>>, Acc, T, S, P, Q, E, K, V) -> lists:reverse([{{T, S, lists:reverse(P)}, Q, lists:reverse([{K, V}|E])}|Acc]);
accept_value(<< $,, R/bits >>, Acc, T, S, P, Q, E, K, V) -> media_range_list(R, [{{T, S, lists:reverse(P)}, Q, lists:reverse([{K, V}|E])}|Acc]);
accept_value(<< $;, R/bits >>, Acc, T, S, P, Q, E, K, V) -> accept_before_semicolon(R, Acc, T, S, P, Q, [{K, V}|E]);
accept_value(<< $\s, R/bits >>, Acc, T, S, P, Q, E, K, V) -> accept_before_semicolon(R, Acc, T, S, P, Q, [{K, V}|E]);
accept_value(<< $\t, R/bits >>, Acc, T, S, P, Q, E, K, V) -> accept_before_semicolon(R, Acc, T, S, P, Q, [{K, V}|E]);
accept_value(<< C, R/bits >>, Acc, T, S, P, Q, E, K, V) when ?IS_TOKEN(C) -> accept_value(R, Acc, T, S, P, Q, E, K, << V/binary, C >>).

-ifdef(TEST).
parse_accept_test_() ->
	Tests = [
		{<<"audio/*; q=0.2, audio/basic">>, [
			{{<<"audio">>, <<"*">>, []}, 200, []},
			{{<<"audio">>, <<"basic">>, []}, 1000, []}
		]},
		{<<"text/plain; q=0.5, text/html, "
		   "text/x-dvi; q=0.8, text/x-c">>, [
		   {{<<"text">>, <<"plain">>, []}, 500, []},
		   {{<<"text">>, <<"html">>, []}, 1000, []},
		   {{<<"text">>, <<"x-dvi">>, []}, 800, []},
		   {{<<"text">>, <<"x-c">>, []}, 1000, []}
		]},
		{<<"text/*, text/html, text/html;level=1, */*">>, [
			{{<<"text">>, <<"*">>, []}, 1000, []},
			{{<<"text">>, <<"html">>, []}, 1000, []},
			{{<<"text">>, <<"html">>, [{<<"level">>, <<"1">>}]}, 1000, []},
			{{<<"*">>, <<"*">>, []}, 1000, []}
		]},
		{<<"text/*;q=0.3, text/html;q=0.7, text/html;level=1, "
		   "text/html;level=2;q=0.4, */*;q=0.5">>, [
		   {{<<"text">>, <<"*">>, []}, 300, []},
		   {{<<"text">>, <<"html">>, []}, 700, []},
		   {{<<"text">>, <<"html">>, [{<<"level">>, <<"1">>}]}, 1000, []},
		   {{<<"text">>, <<"html">>, [{<<"level">>, <<"2">>}]}, 400, []},
		   {{<<"*">>, <<"*">>, []}, 500, []}
		]},
		{<<"text/html;level=1;quoted=\"hi hi hi\";"
		   "q=0.123;standalone;complex=gits, text/plain">>, [
			{{<<"text">>, <<"html">>,
				[{<<"level">>, <<"1">>}, {<<"quoted">>, <<"hi hi hi">>}]}, 123,
				[<<"standalone">>, {<<"complex">>, <<"gits">>}]},
			{{<<"text">>, <<"plain">>, []}, 1000, []}
		]},
		{<<"text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2">>, [
			{{<<"text">>, <<"html">>, []}, 1000, []},
			{{<<"image">>, <<"gif">>, []}, 1000, []},
			{{<<"image">>, <<"jpeg">>, []}, 1000, []},
			{{<<"*">>, <<"*">>, []}, 200, []},
			{{<<"*">>, <<"*">>, []}, 200, []}
		]}
	],
	[{V, fun() -> R = parse_accept(V) end} || {V, R} <- Tests].

parse_accept_error_test_() ->
	Tests = [
		<<>>,
		<<"   ">>,
		<<"audio/basic, */;q=0.5">>,
		<<"audio/, audio/basic">>,
		<<"aud\tio/basic">>,
		<<"audio/basic;t=\"zero \\", 0, " woo\"">>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_accept(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_accept() ->
	horse:repeat(20000,
		parse_accept(<<"text/*;q=0.3, text/html;q=0.7, text/html;level=1, "
			"text/html;level=2;q=0.4, */*;q=0.5">>)
	).
-endif.

%% @doc Parse the Accept-Charset header.

-spec parse_accept_charset(binary()) -> [{binary(), qvalue()}].
parse_accept_charset(Charset) ->
	nonempty(conneg_list(Charset, [])).

conneg_list(<<>>, Acc) -> lists:reverse(Acc);
conneg_list(<< $\s, R/bits >>, Acc) -> conneg_list(R, Acc);
conneg_list(<< $\t, R/bits >>, Acc) -> conneg_list(R, Acc);
conneg_list(<< $\,, R/bits >>, Acc) -> conneg_list(R, Acc);
conneg_list(<< C, R/bits >>, Acc) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(conneg, R, Acc, <<>>)
	end.

conneg(<<>>, Acc, T) -> lists:reverse([{T, 1000}|Acc]);
conneg(<< $,, R/bits >>, Acc, T) -> conneg_list(R, [{T, 1000}|Acc]);
conneg(<< $;, R/bits >>, Acc, T) -> conneg_before_weight(R, Acc, T);
conneg(<< $\s, R/bits >>, Acc, T) -> conneg_before_semicolon(R, Acc, T);
conneg(<< $\t, R/bits >>, Acc, T) -> conneg_before_semicolon(R, Acc, T);
conneg(<< C, R/bits >>, Acc, T) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(conneg, R, Acc, T)
	end.

conneg_before_semicolon(<<>>, Acc, T) -> lists:reverse([{T, 1000}|Acc]);
conneg_before_semicolon(<< $,, R/bits >>, Acc, T) -> conneg_list(R, [{T, 1000}|Acc]);
conneg_before_semicolon(<< $;, R/bits >>, Acc, T) -> conneg_before_weight(R, Acc, T);
conneg_before_semicolon(<< $\s, R/bits >>, Acc, T) -> conneg_before_semicolon(R, Acc, T);
conneg_before_semicolon(<< $\t, R/bits >>, Acc, T) -> conneg_before_semicolon(R, Acc, T).

conneg_before_weight(<< $\s, R/bits >>, Acc, T) -> conneg_before_weight(R, Acc, T);
conneg_before_weight(<< $\t, R/bits >>, Acc, T) -> conneg_before_weight(R, Acc, T);
conneg_before_weight(<< $q, $=, R/bits >>, Acc, T) -> conneg_weight(R, Acc, T);
%% Special clause for broken user agents that confuse ; and , separators.
conneg_before_weight(<< C, R/bits >>, Acc, T) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(conneg, R, [{T, 1000}|Acc], <<>>)
	end.

conneg_weight(<< "1.000", R/bits >>, Acc, T) -> conneg_list_sep(R, [{T, 1000}|Acc]);
conneg_weight(<< "1.00", R/bits >>, Acc, T) -> conneg_list_sep(R, [{T, 1000}|Acc]);
conneg_weight(<< "1.0", R/bits >>, Acc, T) -> conneg_list_sep(R, [{T, 1000}|Acc]);
conneg_weight(<< "1.", R/bits >>, Acc, T) -> conneg_list_sep(R, [{T, 1000}|Acc]);
conneg_weight(<< "1", R/bits >>, Acc, T) -> conneg_list_sep(R, [{T, 1000}|Acc]);
conneg_weight(<< "0.", A, B, C, R/bits >>, Acc, T)
	when A >= $0, A =< $9, B >= $0, B =< $9, C >= $0, C =< $9 ->
		conneg_list_sep(R, [{T, (A - $0) * 100 + (B - $0) * 10 + (C - $0)}|Acc]);
conneg_weight(<< "0.", A, B, R/bits >>, Acc, T)
	when A >= $0, A =< $9, B >= $0, B =< $9 ->
		conneg_list_sep(R, [{T, (A - $0) * 100 + (B - $0) * 10}|Acc]);
conneg_weight(<< "0.", A, R/bits >>, Acc, T)
	when A >= $0, A =< $9 ->
		conneg_list_sep(R, [{T, (A - $0) * 100}|Acc]);
conneg_weight(<< "0.", R/bits >>, Acc, T) -> conneg_list_sep(R, [{T, 0}|Acc]);
conneg_weight(<< "0", R/bits >>, Acc, T) -> conneg_list_sep(R, [{T, 0}|Acc]).

conneg_list_sep(<<>>, Acc) -> lists:reverse(Acc);
conneg_list_sep(<< $\s, R/bits >>, Acc) -> conneg_list_sep(R, Acc);
conneg_list_sep(<< $\t, R/bits >>, Acc) -> conneg_list_sep(R, Acc);
conneg_list_sep(<< $,, R/bits >>, Acc) -> conneg_list(R, Acc).

-ifdef(TEST).
parse_accept_charset_test_() ->
	Tests = [
		{<<"iso-8859-5, unicode-1-1;q=0.8">>, [
			{<<"iso-8859-5">>, 1000},
			{<<"unicode-1-1">>, 800}
		]},
		%% Some user agents send this invalid value for the Accept-Charset header
		{<<"ISO-8859-1;utf-8;q=0.7,*;q=0.7">>, [
			{<<"iso-8859-1">>, 1000},
			{<<"utf-8">>, 700},
			{<<"*">>, 700}
		]}
	],
	[{V, fun() -> R = parse_accept_charset(V) end} || {V, R} <- Tests].

parse_accept_charset_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_accept_charset(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_accept_charset() ->
	horse:repeat(20000,
		parse_accept_charset(<<"iso-8859-5, unicode-1-1;q=0.8">>)
	).
-endif.

%% @doc Parse the Accept-Encoding header.

-spec parse_accept_encoding(binary()) -> [{binary(), qvalue()}].
parse_accept_encoding(Encoding) ->
	conneg_list(Encoding, []).

-ifdef(TEST).
parse_accept_encoding_test_() ->
	Tests = [
		{<<>>, []},
		{<<"*">>, [{<<"*">>, 1000}]},
		{<<"compress, gzip">>, [
			{<<"compress">>, 1000},
			{<<"gzip">>, 1000}
		]},
		{<<"compress;q=0.5, gzip;q=1.0">>, [
			{<<"compress">>, 500},
			{<<"gzip">>, 1000}
		]},
		{<<"gzip;q=1.0, identity; q=0.5, *;q=0">>, [
			{<<"gzip">>, 1000},
			{<<"identity">>, 500},
			{<<"*">>, 0}
		]}
	],
	[{V, fun() -> R = parse_accept_encoding(V) end} || {V, R} <- Tests].
-endif.

-ifdef(PERF).
horse_parse_accept_encoding() ->
	horse:repeat(20000,
		parse_accept_encoding(<<"gzip;q=1.0, identity; q=0.5, *;q=0">>)
	).
-endif.

%% @doc Parse the Accept-Language header.

-spec parse_accept_language(binary()) -> [{binary(), qvalue()}].
parse_accept_language(LanguageRange) ->
	nonempty(language_range_list(LanguageRange, [])).

language_range_list(<<>>, Acc) -> lists:reverse(Acc);
language_range_list(<< $\s, R/bits >>, Acc) -> language_range_list(R, Acc);
language_range_list(<< $\t, R/bits >>, Acc) -> language_range_list(R, Acc);
language_range_list(<< $\,, R/bits >>, Acc) -> language_range_list(R, Acc);
language_range_list(<< $*, R/bits >>, Acc) -> language_range_before_semicolon(R, Acc, <<"*">>);
language_range_list(<< C, R/bits >>, Acc) when ?IS_ALPHA(C) ->
	case C of
		?INLINE_LOWERCASE(language_range, R, Acc, 1, <<>>)
	end.

language_range(<<>>, Acc, _, T) -> lists:reverse([{T, 1000}|Acc]);
language_range(<< $,, R/bits >>, Acc, _, T) -> language_range_list(R, [{T, 1000}|Acc]);
language_range(<< $;, R/bits >>, Acc, _, T) -> language_range_before_weight(R, Acc, T);
language_range(<< $\s, R/bits >>, Acc, _, T) -> language_range_before_semicolon(R, Acc, T);
language_range(<< $\t, R/bits >>, Acc, _, T) -> language_range_before_semicolon(R, Acc, T);
language_range(<< $-, R/bits >>, Acc, _, T) -> language_range_sub(R, Acc, 0, << T/binary, $- >>);
language_range(<< _, _/bits >>, _, 8, _) -> error(badarg);
language_range(<< C, R/bits >>, Acc, N, T) when ?IS_ALPHA(C) ->
	case C of
		?INLINE_LOWERCASE(language_range, R, Acc, N + 1, T)
	end.

language_range_sub(<<>>, Acc, N, T) when N > 0 -> lists:reverse([{T, 1000}|Acc]);
language_range_sub(<< $,, R/bits >>, Acc, N, T) when N > 0 -> language_range_list(R, [{T, 1000}|Acc]);
language_range_sub(<< $;, R/bits >>, Acc, N, T) when N > 0 -> language_range_before_weight(R, Acc, T);
language_range_sub(<< $\s, R/bits >>, Acc, N, T) when N > 0 -> language_range_before_semicolon(R, Acc, T);
language_range_sub(<< $\t, R/bits >>, Acc, N, T) when N > 0 -> language_range_before_semicolon(R, Acc, T);
language_range_sub(<< $-, R/bits >>, Acc, N, T) when N > 0 -> language_range_sub(R, Acc, 0, << T/binary, $- >>);
language_range_sub(<< _, _/bits >>, _, 8, _) -> error(badarg);
language_range_sub(<< C, R/bits >>, Acc, N, T) when ?IS_ALPHA(C); ?IS_DIGIT(C) ->
	case C of
		?INLINE_LOWERCASE(language_range_sub, R, Acc, N + 1, T)
	end.

language_range_before_semicolon(<<>>, Acc, T) -> lists:reverse([{T, 1000}|Acc]);
language_range_before_semicolon(<< $,, R/bits >>, Acc, T) -> language_range_list(R, [{T, 1000}|Acc]);
language_range_before_semicolon(<< $;, R/bits >>, Acc, T) -> language_range_before_weight(R, Acc, T);
language_range_before_semicolon(<< $\s, R/bits >>, Acc, T) -> language_range_before_semicolon(R, Acc, T);
language_range_before_semicolon(<< $\t, R/bits >>, Acc, T) -> language_range_before_semicolon(R, Acc, T).

language_range_before_weight(<< $\s, R/bits >>, Acc, T) -> language_range_before_weight(R, Acc, T);
language_range_before_weight(<< $\t, R/bits >>, Acc, T) -> language_range_before_weight(R, Acc, T);
language_range_before_weight(<< $q, $=, R/bits >>, Acc, T) -> language_range_weight(R, Acc, T);
%% Special clause for broken user agents that confuse ; and , separators.
language_range_before_weight(<< C, R/bits >>, Acc, T) when ?IS_ALPHA(C) ->
	case C of
		?INLINE_LOWERCASE(language_range, R, [{T, 1000}|Acc], 1, <<>>)
	end.

language_range_weight(<< "1.000", R/bits >>, Acc, T) -> language_range_list_sep(R, [{T, 1000}|Acc]);
language_range_weight(<< "1.00", R/bits >>, Acc, T) -> language_range_list_sep(R, [{T, 1000}|Acc]);
language_range_weight(<< "1.0", R/bits >>, Acc, T) -> language_range_list_sep(R, [{T, 1000}|Acc]);
language_range_weight(<< "1.", R/bits >>, Acc, T) -> language_range_list_sep(R, [{T, 1000}|Acc]);
language_range_weight(<< "1", R/bits >>, Acc, T) -> language_range_list_sep(R, [{T, 1000}|Acc]);
language_range_weight(<< "0.", A, B, C, R/bits >>, Acc, T)
	when A >= $0, A =< $9, B >= $0, B =< $9, C >= $0, C =< $9 ->
		language_range_list_sep(R, [{T, (A - $0) * 100 + (B - $0) * 10 + (C - $0)}|Acc]);
language_range_weight(<< "0.", A, B, R/bits >>, Acc, T)
	when A >= $0, A =< $9, B >= $0, B =< $9 ->
		language_range_list_sep(R, [{T, (A - $0) * 100 + (B - $0) * 10}|Acc]);
language_range_weight(<< "0.", A, R/bits >>, Acc, T)
	when A >= $0, A =< $9 ->
		language_range_list_sep(R, [{T, (A - $0) * 100}|Acc]);
language_range_weight(<< "0.", R/bits >>, Acc, T) -> language_range_list_sep(R, [{T, 0}|Acc]);
language_range_weight(<< "0", R/bits >>, Acc, T) -> language_range_list_sep(R, [{T, 0}|Acc]).

language_range_list_sep(<<>>, Acc) -> lists:reverse(Acc);
language_range_list_sep(<< $\s, R/bits >>, Acc) -> language_range_list_sep(R, Acc);
language_range_list_sep(<< $\t, R/bits >>, Acc) -> language_range_list_sep(R, Acc);
language_range_list_sep(<< $,, R/bits >>, Acc) -> language_range_list(R, Acc).

-ifdef(TEST).
parse_accept_language_test_() ->
	Tests = [
		{<<"da, en-gb;q=0.8, en;q=0.7">>, [
			{<<"da">>, 1000},
			{<<"en-gb">>, 800},
			{<<"en">>, 700}
		]},
		{<<"en, en-US, en-cockney, i-cherokee, x-pig-latin, es-419">>, [
			{<<"en">>, 1000},
			{<<"en-us">>, 1000},
			{<<"en-cockney">>, 1000},
			{<<"i-cherokee">>, 1000},
			{<<"x-pig-latin">>, 1000},
			{<<"es-419">>, 1000}
		]}
	],
	[{V, fun() -> R = parse_accept_language(V) end} || {V, R} <- Tests].

parse_accept_language_error_test_() ->
	Tests = [
		<<>>,
		<<"loooooong">>,
		<<"en-us-loooooong">>,
		<<"419-en-us">>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_accept_language(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_accept_language() ->
	horse:repeat(20000,
		parse_accept_language(<<"da, en-gb;q=0.8, en;q=0.7">>)
	).
-endif.

%% @doc Parse the Connection header.

-spec parse_connection(binary()) -> [binary()].
parse_connection(<<"close">>) ->
	[<<"close">>];
parse_connection(<<"keep-alive">>) ->
	[<<"keep-alive">>];
parse_connection(Connection) ->
	nonempty(token_ci_list(Connection, [])).

-ifdef(TEST).
parse_connection_test_() ->
	Tests = [
		{<<"close">>, [<<"close">>]},
		{<<"ClOsE">>, [<<"close">>]},
		{<<"Keep-Alive">>, [<<"keep-alive">>]},
		{<<"keep-alive, Upgrade">>, [<<"keep-alive">>, <<"upgrade">>]}
	],
	[{V, fun() -> R = parse_connection(V) end} || {V, R} <- Tests].
-endif.

-ifdef(PERF).
horse_parse_connection_close() ->
	horse:repeat(200000,
		parse_connection(<<"close">>)
	).

horse_parse_connection_keepalive() ->
	horse:repeat(200000,
		parse_connection(<<"keep-alive">>)
	).

horse_parse_connection_keepalive_upgrade() ->
	horse:repeat(200000,
		parse_connection(<<"keep-alive, upgrade">>)
	).
-endif.

%% @doc Parse the Content-Length header.
%%
%% The value has at least one digit, and may be followed by whitespace.

-spec parse_content_length(binary()) -> non_neg_integer().
parse_content_length(<< $0 >>) -> 0;
parse_content_length(<< $0, R/bits >>) -> number(R, 0);
parse_content_length(<< $1, R/bits >>) -> number(R, 1);
parse_content_length(<< $2, R/bits >>) -> number(R, 2);
parse_content_length(<< $3, R/bits >>) -> number(R, 3);
parse_content_length(<< $4, R/bits >>) -> number(R, 4);
parse_content_length(<< $5, R/bits >>) -> number(R, 5);
parse_content_length(<< $6, R/bits >>) -> number(R, 6);
parse_content_length(<< $7, R/bits >>) -> number(R, 7);
parse_content_length(<< $8, R/bits >>) -> number(R, 8);
parse_content_length(<< $9, R/bits >>) -> number(R, 9).

-ifdef(TEST).
prop_parse_content_length() ->
	?FORALL(
		X,
		non_neg_integer(),
		X =:= parse_content_length(integer_to_binary(X))
	).

parse_content_length_test_() ->
	Tests = [
		{<<"0">>, 0},
		{<<"42    ">>, 42},
		{<<"69\t">>, 69},
		{<<"1337">>, 1337},
		{<<"1234567890">>, 1234567890},
		{<<"1234567890     ">>, 1234567890}
	],
	[{V, fun() -> R = parse_content_length(V) end} || {V, R} <- Tests].

parse_content_length_error_test_() ->
	Tests = [
		<<>>,
		<<"123, 123">>,
		<<"4.17">>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_content_length(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_content_length_zero() ->
	horse:repeat(100000,
		parse_content_length(<<"0">>)
	).

horse_parse_content_length_giga() ->
	horse:repeat(100000,
		parse_content_length(<<"1234567890">>)
	).
-endif.

%% @doc Parse the Expect header.

-spec parse_expect(binary()) -> continue.
parse_expect(<<"100-continue", Rest/bits >>) ->
	ws_end(Rest),
	continue;
parse_expect(<<"100-", C, O, N, T, I, M, U, E, Rest/bits >>)
	when C =:= $C orelse C =:= $c, O =:= $O orelse O =:= $o,
		N =:= $N orelse N =:= $n, T =:= $T orelse T =:= $t,
		I =:= $I orelse I =:= $i, M =:= $N orelse M =:= $n,
		U =:= $U orelse U =:= $u, E =:= $E orelse E =:= $e ->
	ws_end(Rest),
	continue.

-ifdef(TEST).
parse_expect_test_() ->
	Tests = [
		<<"100-continue">>,
		<<"100-CONTINUE">>,
		<<"100-Continue">>,
		<<"100-CoNtInUe">>,
		<<"100-continue    ">>
	],
	[{V, fun() -> continue = parse_expect(V) end} || V <- Tests].

parse_expect_error_test_() ->
	Tests = [
		<<>>,
		<<"   ">>,
		<<"200-OK">>,
		<<"Cookies">>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_expect(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_expect() ->
	horse:repeat(200000,
		parse_expect(<<"100-continue">>)
	).
-endif.

%% @doc Parse the Max-Forwards header.

-spec parse_max_forwards(binary()) -> integer().
parse_max_forwards(<< $0, R/bits >>) -> number(R, 0);
parse_max_forwards(<< $1, R/bits >>) -> number(R, 1);
parse_max_forwards(<< $2, R/bits >>) -> number(R, 2);
parse_max_forwards(<< $3, R/bits >>) -> number(R, 3);
parse_max_forwards(<< $4, R/bits >>) -> number(R, 4);
parse_max_forwards(<< $5, R/bits >>) -> number(R, 5);
parse_max_forwards(<< $6, R/bits >>) -> number(R, 6);
parse_max_forwards(<< $7, R/bits >>) -> number(R, 7);
parse_max_forwards(<< $8, R/bits >>) -> number(R, 8);
parse_max_forwards(<< $9, R/bits >>) -> number(R, 9).

-ifdef(TEST).
parse_max_forwards_test_() ->
	Tests = [
		{<<"0">>, 0},
		{<<"42    ">>, 42},
		{<<"69\t">>, 69},
		{<<"1337">>, 1337},
		{<<"1234567890">>, 1234567890},
		{<<"1234567890     ">>, 1234567890}
	],
	[{V, fun() -> R = parse_max_forwards(V) end} || {V, R} <- Tests].
-endif.

%% @doc Parse the Transfer-Encoding header.
%%
%% @todo Extension parameters.

-spec parse_transfer_encoding(binary()) -> [binary()].
parse_transfer_encoding(<<"chunked">>) ->
	[<<"chunked">>];
parse_transfer_encoding(TransferEncoding) ->
	nonempty(token_ci_list(TransferEncoding, [])).

-ifdef(TEST).
parse_transfer_encoding_test_() ->
	Tests = [
		{<<"a , , , ">>, [<<"a">>]},
		{<<" , , , a">>, [<<"a">>]},
		{<<"a , , b">>, [<<"a">>, <<"b">>]},
		{<<"chunked">>, [<<"chunked">>]},
		{<<"chunked, something">>, [<<"chunked">>, <<"something">>]}
	],
	[{V, fun() -> R = parse_transfer_encoding(V) end} || {V, R} <- Tests].

parse_transfer_encoding_error_test_() ->
	Tests = [
		<<>>,
		<<" ">>,
		<<" , ">>,
		<<",,,">>,
		<<"a b">>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_transfer_encoding(V)) end}
		|| V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_transfer_encoding_chunked() ->
	horse:repeat(200000,
		parse_transfer_encoding(<<"chunked">>)
	).

horse_parse_transfer_encoding_custom() ->
	horse:repeat(200000,
		parse_transfer_encoding(<<"chunked, something">>)
	).
-endif.

%% Internal.

%% Only return if the list is not empty.
nonempty(L) when L =/= [] -> L.

%% Parse a number optionally followed by whitespace.
number(<< $0, R/bits >>, Acc) -> number(R, Acc * 10);
number(<< $1, R/bits >>, Acc) -> number(R, Acc * 10 + 1);
number(<< $2, R/bits >>, Acc) -> number(R, Acc * 10 + 2);
number(<< $3, R/bits >>, Acc) -> number(R, Acc * 10 + 3);
number(<< $4, R/bits >>, Acc) -> number(R, Acc * 10 + 4);
number(<< $5, R/bits >>, Acc) -> number(R, Acc * 10 + 5);
number(<< $6, R/bits >>, Acc) -> number(R, Acc * 10 + 6);
number(<< $7, R/bits >>, Acc) -> number(R, Acc * 10 + 7);
number(<< $8, R/bits >>, Acc) -> number(R, Acc * 10 + 8);
number(<< $9, R/bits >>, Acc) -> number(R, Acc * 10 + 9);
number(<< $\s, R/bits >>, Acc) -> ws_end(R), Acc;
number(<< $\t, R/bits >>, Acc) -> ws_end(R), Acc;
number(<<>>, Acc) -> Acc.

ws_end(<< $\s, R/bits >>) -> ws_end(R);
ws_end(<< $\t, R/bits >>) -> ws_end(R);
ws_end(<<>>) -> ok.

%% Parse a list of case insensitive tokens.
token_ci_list(<<>>, Acc) -> lists:reverse(Acc);
token_ci_list(<< $\s, R/bits >>, Acc) -> token_ci_list(R, Acc);
token_ci_list(<< $\t, R/bits >>, Acc) -> token_ci_list(R, Acc);
token_ci_list(<< $,, R/bits >>, Acc) -> token_ci_list(R, Acc);
token_ci_list(<< C, R/bits >>, Acc) ->
	case C of
		?INLINE_LOWERCASE(token_ci_list, R, Acc, <<>>)
	end.

token_ci_list(<<>>, Acc, T) -> lists:reverse([T|Acc]);
token_ci_list(<< $\s, R/bits >>, Acc, T) -> token_ci_list_sep(R, Acc, T);
token_ci_list(<< $\t, R/bits >>, Acc, T) -> token_ci_list_sep(R, Acc, T);
token_ci_list(<< $,, R/bits >>, Acc, T) -> token_ci_list(R, [T|Acc]);
token_ci_list(<< C, R/bits >>, Acc, T) ->
	case C of
		?INLINE_LOWERCASE(token_ci_list, R, Acc, T)
	end.

token_ci_list_sep(<<>>, Acc, T) -> lists:reverse([T|Acc]);
token_ci_list_sep(<< $\s, R/bits >>, Acc, T) -> token_ci_list_sep(R, Acc, T);
token_ci_list_sep(<< $\t, R/bits >>, Acc, T) -> token_ci_list_sep(R, Acc, T);
token_ci_list_sep(<< $,, R/bits >>, Acc, T) -> token_ci_list(R, [T|Acc]).
