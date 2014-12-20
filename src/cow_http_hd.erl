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
-export([parse_content_encoding/1]).
-export([parse_content_language/1]).
-export([parse_content_length/1]).
-export([parse_content_type/1]).
-export([parse_date/1]).
-export([parse_etag/1]).
-export([parse_expect/1]).
-export([parse_expires/1]).
-export([parse_if_match/1]).
-export([parse_if_modified_since/1]).
-export([parse_if_none_match/1]).
-export([parse_if_unmodified_since/1]).
-export([parse_last_modified/1]).
-export([parse_max_forwards/1]).
-export([parse_sec_websocket_extensions/1]).
-export([parse_sec_websocket_protocol_client/1]).
-export([parse_sec_websocket_version_client/1]).
-export([parse_transfer_encoding/1]).
-export([parse_upgrade/1]).

-type etag() :: {weak | strong, binary()}.
-export_type([etag/0]).

-type media_type() :: {binary(), binary(), [{binary(), binary()}]}.
-export_type([media_type/0]).

-type qvalue() :: 0..1000.
-export_type([qvalue/0]).

-include("cow_inline.hrl").

-ifdef(TEST).
-include_lib("triq/include/triq.hrl").

vector(Min, Max, Dom) -> ?LET(N, choose(Min, Max), vector(N, Dom)).
small_list(Dom) -> vector(0, 10, Dom).
small_non_empty_list(Dom) -> vector(1, 10, Dom).

alpha_chars() -> "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".
alphanum_chars() -> "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".
digit_chars() -> "0123456789".

ows() -> list(oneof([$\s, $\t])).
alpha() -> oneof(alpha_chars()).
alphanum() -> oneof(alphanum_chars()).
digit() -> oneof(digit_chars()).

tchar() ->
	frequency([
		{1, oneof([$!, $#, $$, $%, $&, $', $*, $+, $-, $., $^, $_, $`, $|, $~])},
		{99, oneof(alphanum_chars())}
	]).

token() ->
	?LET(T,
		non_empty(list(tchar())),
		list_to_binary(T)).

obs_text() ->
	oneof([128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,
	146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,
	164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,
	182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,
	200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,
	218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,
	236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,
	254,255]).

qdtext() ->
	frequency([
		{99, oneof("\t\s!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~")},
		{1, obs_text()}
	]).

quoted_pair() ->
	[$\\, frequency([
		{99, oneof("\t\s!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")},
		{1, obs_text()}
	])].

quoted_string() ->
	[$", list(frequency([{100, qdtext()}, {1, quoted_pair()}])), $"].

%% Helper function for ( token / quoted-string ) values.
unquote([$", V, $"]) -> unquote(V, <<>>);
unquote(V) -> V.

unquote([], Acc) -> Acc;
unquote([[$\\, C]|Tail], Acc) -> unquote(Tail, << Acc/binary, C >>);
unquote([C|Tail], Acc) -> unquote(Tail, << Acc/binary, C >>).

parameter() ->
	?SUCHTHAT({K, _, _, _},
		{token(), oneof([token(), quoted_string()]), ows(), ows()},
		K =/= <<"q">>).

weight() ->
	frequency([
		{90, int(0, 1000)},
		{10, undefined}
	]).

%% Helper function for weight's qvalue formatting.
qvalue_to_iodata(0) -> <<"0">>;
qvalue_to_iodata(Q) when Q < 10 -> [<<"0.00">>, integer_to_binary(Q)];
qvalue_to_iodata(Q) when Q < 100 -> [<<"0.0">>, integer_to_binary(Q)];
qvalue_to_iodata(Q) when Q < 1000 -> [<<"0.">>, integer_to_binary(Q)];
qvalue_to_iodata(1000) -> <<"1">>.
-endif.

%% @doc Parse the Accept header.

-spec parse_accept(binary()) -> [{media_type(), qvalue(), [binary() | {binary(), binary()}]}].
parse_accept(<<"*/*">>) ->
	[{{<<"*">>, <<"*">>, []}, 1000, []}];
parse_accept(Accept) ->
	media_range_list(Accept, []).

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
media_range_type(<< $;, R/bits >>, Acc, <<"*">>) -> media_range_before_param(R, Acc, <<"*">>, <<"*">>, []);
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
accept_value(<< $;, R/bits >>, Acc, T, S, P, Q, E, K, V) -> accept_before_ext(R, Acc, T, S, P, Q, [{K, V}|E]);
accept_value(<< $\s, R/bits >>, Acc, T, S, P, Q, E, K, V) -> accept_before_semicolon(R, Acc, T, S, P, Q, [{K, V}|E]);
accept_value(<< $\t, R/bits >>, Acc, T, S, P, Q, E, K, V) -> accept_before_semicolon(R, Acc, T, S, P, Q, [{K, V}|E]);
accept_value(<< C, R/bits >>, Acc, T, S, P, Q, E, K, V) when ?IS_TOKEN(C) -> accept_value(R, Acc, T, S, P, Q, E, K, << V/binary, C >>).

-ifdef(TEST).
accept_ext() ->
	oneof([token(), parameter()]).

accept_params() ->
	frequency([
		{90, []},
		{10, small_list(accept_ext())}
	]).

accept() ->
	?LET({T, S, P, W, E},
		{token(), token(), small_list(parameter()), weight(), accept_params()},
		{T, S, P, W, E, iolist_to_binary([T, $/, S,
			[[OWS1, $;, OWS2, K, $=, V] || {K, V, OWS1, OWS2} <- P],
			case W of
				undefined -> [];
				_ -> [
					[<<";q=">>, qvalue_to_iodata(W)],
					[case Ext of
						{K, V, OWS1, OWS2} -> [OWS1, $;, OWS2, K, $=, V];
						K -> [$;, K]
					end || Ext <- E]]
			end])}
	).

prop_parse_accept() ->
	?FORALL(L,
		non_empty(list(accept())),
		begin
			<< _, Accept/binary >> = iolist_to_binary([[$,, A] || {_, _, _, _, _, A} <- L]),
			ResL = parse_accept(Accept),
			CheckedL = [begin
				ExpectedP = [{?INLINE_LOWERCASE_BC(K), unquote(V)} || {K, V, _, _} <- P],
				ExpectedE = [case Ext of
					{K, V, _, _} -> {?INLINE_LOWERCASE_BC(K), unquote(V)};
					K -> ?INLINE_LOWERCASE_BC(K)
				end || Ext <- E],
				ResT =:= ?INLINE_LOWERCASE_BC(T)
					andalso ResS =:= ?INLINE_LOWERCASE_BC(S)
					andalso ResP =:= ExpectedP
					andalso (ResW =:= W orelse (W =:= undefined andalso ResW =:= 1000))
					andalso ((W =:= undefined andalso ResE =:= []) orelse (W =/= undefined andalso ResE =:= ExpectedE))
			end || {{T, S, P, W, E, _}, {{ResT, ResS, ResP}, ResW, ResE}} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end
	).

parse_accept_test_() ->
	Tests = [
		{<<>>, []},
		{<<"   ">>, []},
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
accept_charset() ->
	?LET({C, W},
		{token(), weight()},
		{C, W, iolist_to_binary([C, case W of
			undefined -> [];
			_ -> [<<";q=">>, qvalue_to_iodata(W)]
		end])}
	).

prop_parse_accept_charset() ->
	?FORALL(L,
		non_empty(list(accept_charset())),
		begin
			<< _, AcceptCharset/binary >> = iolist_to_binary([[$,, A] || {_, _, A} <- L]),
			ResL = parse_accept_charset(AcceptCharset),
			CheckedL = [begin
				ResC =:= ?INLINE_LOWERCASE_BC(Ch)
					andalso (ResW =:= W orelse (W =:= undefined andalso ResW =:= 1000))
			end || {{Ch, W, _}, {ResC, ResW}} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

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
accept_encoding() ->
	?LET({E, W},
		{token(), weight()},
		{E, W, iolist_to_binary([E, case W of
			undefined -> [];
			_ -> [<<";q=">>, qvalue_to_iodata(W)]
		end])}
	).

prop_parse_accept_encoding() ->
	?FORALL(L,
		non_empty(list(accept_encoding())),
		begin
			<< _, AcceptEncoding/binary >> = iolist_to_binary([[$,, A] || {_, _, A} <- L]),
			ResL = parse_accept_encoding(AcceptEncoding),
			CheckedL = [begin
				ResE =:= ?INLINE_LOWERCASE_BC(E)
					andalso (ResW =:= W orelse (W =:= undefined andalso ResW =:= 1000))
			end || {{E, W, _}, {ResE, ResW}} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

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
language_range_tag() ->
	vector(1, 8, alpha()).

language_range_subtag() ->
	[$-, vector(1, 8, alphanum())].

language_range() ->
	[language_range_tag(), small_list(language_range_subtag())].

accept_language() ->
	?LET({R, W},
		{language_range(), weight()},
		{iolist_to_binary(R), W, iolist_to_binary([R, case W of
			undefined -> [];
			_ -> [<<";q=">>, qvalue_to_iodata(W)]
		end])}
	).

prop_parse_accept_language() ->
	?FORALL(L,
		non_empty(list(accept_language())),
		begin
			<< _, AcceptLanguage/binary >> = iolist_to_binary([[$,, A] || {_, _, A} <- L]),
			ResL = parse_accept_language(AcceptLanguage),
			CheckedL = [begin
				ResR =:= ?INLINE_LOWERCASE_BC(R)
					andalso (ResW =:= W orelse (W =:= undefined andalso ResW =:= 1000))
			end || {{R, W, _}, {ResR, ResW}} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

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
prop_parse_connection() ->
	?FORALL(L,
		non_empty(list(token())),
		begin
			<< _, Connection/binary >> = iolist_to_binary([[$,, C] || C <- L]),
			ResL = parse_connection(Connection),
			CheckedL = [?INLINE_LOWERCASE_BC(Co) =:= ResC || {Co, ResC} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

parse_connection_test_() ->
	Tests = [
		{<<"close">>, [<<"close">>]},
		{<<"ClOsE">>, [<<"close">>]},
		{<<"Keep-Alive">>, [<<"keep-alive">>]},
		{<<"keep-alive, Upgrade">>, [<<"keep-alive">>, <<"upgrade">>]}
	],
	[{V, fun() -> R = parse_connection(V) end} || {V, R} <- Tests].

parse_connection_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_connection(V)) end} || V <- Tests].
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

%% @doc Parse the Content-Encoding header.

-spec parse_content_encoding(binary()) -> [binary()].
parse_content_encoding(ContentEncoding) ->
	nonempty(token_ci_list(ContentEncoding, [])).

-ifdef(TEST).
parse_content_encoding_test_() ->
	Tests = [
		{<<"gzip">>, [<<"gzip">>]}
	],
	[{V, fun() -> R = parse_content_encoding(V) end} || {V, R} <- Tests].

parse_content_encoding_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_content_encoding(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_content_encoding() ->
	horse:repeat(200000,
		parse_content_encoding(<<"gzip">>)
	).
-endif.

%% @doc Parse the Content-Language header.
%%
%% We do not support irregular deprecated tags that do not match the ABNF.

-spec parse_content_language(binary()) -> [binary()].
parse_content_language(ContentLanguage) ->
	nonempty(langtag_list(ContentLanguage, [])).

langtag_list(<<>>, Acc) -> lists:reverse(Acc);
langtag_list(<< $\s, R/bits >>, Acc) -> langtag_list(R, Acc);
langtag_list(<< $\t, R/bits >>, Acc) -> langtag_list(R, Acc);
langtag_list(<< $,, R/bits >>, Acc) -> langtag_list(R, Acc);
langtag_list(<< A, B, C, R/bits >>, Acc) when ?IS_ALPHA(A), ?IS_ALPHA(B), ?IS_ALPHA(C) ->
	langtag_extlang(R, Acc, << ?LC(A), ?LC(B), ?LC(C) >>, 0);
langtag_list(<< A, B, R/bits >>, Acc) when ?IS_ALPHA(A), ?IS_ALPHA(B) ->
	langtag_extlang(R, Acc, << ?LC(A), ?LC(B) >>, 0);
langtag_list(<< X, R/bits >>, Acc) when X =:= $x; X =:= $X -> langtag_privateuse_sub(R, Acc, << $x >>, 0).

langtag_extlang(<<>>, Acc, T, _) -> lists:reverse([T|Acc]);
langtag_extlang(<< $,, R/bits >>, Acc, T, _) -> langtag_list(R, [T|Acc]);
langtag_extlang(<< $\s, R/bits >>, Acc, T, _) -> langtag_list_sep(R, [T|Acc]);
langtag_extlang(<< $\t, R/bits >>, Acc, T, _) -> langtag_list_sep(R, [T|Acc]);
langtag_extlang(<< $-, A, B, C, D, E, F, G, H, R/bits >>, Acc, T, _)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G), ?IS_ALPHANUM(H) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G), ?LC(H) >>);
langtag_extlang(<< $-, A, B, C, D, E, F, G, R/bits >>, Acc, T, _)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G) >>);
langtag_extlang(<< $-, A, B, C, D, E, F, R/bits >>, Acc, T, _)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F) >>);
langtag_extlang(<< $-, A, B, C, D, E, R/bits >>, Acc, T, _)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D), ?IS_ALPHANUM(E) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E) >>);
langtag_extlang(<< $-, A, B, C, D, R/bits >>, Acc, T, _)
		when ?IS_ALPHA(A), ?IS_ALPHA(B), ?IS_ALPHA(C), ?IS_ALPHA(D) ->
	langtag_region(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D) >>);
langtag_extlang(<< $-, A, B, C, R/bits >>, Acc, T, N)
		when ?IS_ALPHA(A), ?IS_ALPHA(B), ?IS_ALPHA(C) ->
	case N of
		2 -> langtag_script(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C) >>);
		_ -> langtag_extlang(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C) >>, N + 1)
	end;
langtag_extlang(R, Acc, T, _) -> langtag_region(R, Acc, T).

langtag_script(<<>>, Acc, T) -> lists:reverse([T|Acc]);
langtag_script(<< $,, R/bits >>, Acc, T) -> langtag_list(R, [T|Acc]);
langtag_script(<< $\s, R/bits >>, Acc, T) -> langtag_list_sep(R, [T|Acc]);
langtag_script(<< $\t, R/bits >>, Acc, T) -> langtag_list_sep(R, [T|Acc]);
langtag_script(<< $-, A, B, C, D, E, F, G, H, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G), ?IS_ALPHANUM(H) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G), ?LC(H) >>);
langtag_script(<< $-, A, B, C, D, E, F, G, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G) >>);
langtag_script(<< $-, A, B, C, D, E, F, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F) >>);
langtag_script(<< $-, A, B, C, D, E, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D), ?IS_ALPHANUM(E) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E) >>);
langtag_script(<< $-, A, B, C, D, R/bits >>, Acc, T)
		when ?IS_ALPHA(A), ?IS_ALPHA(B), ?IS_ALPHA(C), ?IS_ALPHA(D) ->
	langtag_region(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D) >>);
langtag_script(R, Acc, T) ->
	langtag_region(R, Acc, T).

langtag_region(<<>>, Acc, T) -> lists:reverse([T|Acc]);
langtag_region(<< $,, R/bits >>, Acc, T) -> langtag_list(R, [T|Acc]);
langtag_region(<< $\s, R/bits >>, Acc, T) -> langtag_list_sep(R, [T|Acc]);
langtag_region(<< $\t, R/bits >>, Acc, T) -> langtag_list_sep(R, [T|Acc]);
langtag_region(<< $-, A, B, C, D, E, F, G, H, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G), ?IS_ALPHANUM(H) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G), ?LC(H) >>);
langtag_region(<< $-, A, B, C, D, E, F, G, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G) >>);
langtag_region(<< $-, A, B, C, D, E, F, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F) >>);
langtag_region(<< $-, A, B, C, D, E, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D), ?IS_ALPHANUM(E) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E) >>);
langtag_region(<< $-, A, B, C, D, R/bits >>, Acc, T)
		when ?IS_DIGIT(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D) ->
	langtag_variant(R, Acc, << T/binary, $-, A, ?LC(B), ?LC(C), ?LC(D) >>);
langtag_region(<< $-, A, B, R/bits >>, Acc, T) when ?IS_ALPHA(A), ?IS_ALPHA(B) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B) >>);
langtag_region(<< $-, A, B, C, R/bits >>, Acc, T) when ?IS_DIGIT(A), ?IS_DIGIT(B), ?IS_DIGIT(C) ->
	langtag_variant(R, Acc, << T/binary, $-, A, B, C >>);
langtag_region(R, Acc, T) ->
	langtag_variant(R, Acc, T).

langtag_variant(<<>>, Acc, T) -> lists:reverse([T|Acc]);
langtag_variant(<< $,, R/bits >>, Acc, T) -> langtag_list(R, [T|Acc]);
langtag_variant(<< $\s, R/bits >>, Acc, T) -> langtag_list_sep(R, [T|Acc]);
langtag_variant(<< $\t, R/bits >>, Acc, T) -> langtag_list_sep(R, [T|Acc]);
langtag_variant(<< $-, A, B, C, D, E, F, G, H, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G), ?IS_ALPHANUM(H) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G), ?LC(H) >>);
langtag_variant(<< $-, A, B, C, D, E, F, G, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G) >>);
langtag_variant(<< $-, A, B, C, D, E, F, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F) >>);
langtag_variant(<< $-, A, B, C, D, E, R/bits >>, Acc, T)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D), ?IS_ALPHANUM(E) ->
	langtag_variant(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E) >>);
langtag_variant(<< $-, A, B, C, D, R/bits >>, Acc, T)
		when ?IS_DIGIT(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D) ->
	langtag_variant(R, Acc, << T/binary, $-, A, ?LC(B), ?LC(C), ?LC(D) >>);
langtag_variant(R, Acc, T) ->
	langtag_extension(R, Acc, T).

langtag_extension(<<>>, Acc, T) -> lists:reverse([T|Acc]);
langtag_extension(<< $,, R/bits >>, Acc, T) -> langtag_list(R, [T|Acc]);
langtag_extension(<< $\s, R/bits >>, Acc, T) -> langtag_list_sep(R, [T|Acc]);
langtag_extension(<< $\t, R/bits >>, Acc, T) -> langtag_list_sep(R, [T|Acc]);
langtag_extension(<< $-, X, R/bits >>, Acc, T) when X =:= $x; X =:= $X -> langtag_privateuse_sub(R, Acc, << T/binary, $-, $x >>, 0);
langtag_extension(<< $-, S, R/bits >>, Acc, T) when ?IS_ALPHANUM(S) -> langtag_extension_sub(R, Acc, << T/binary, $-, ?LC(S) >>, 0).

langtag_extension_sub(<<>>, Acc, T, N) when N > 0 -> lists:reverse([T|Acc]);
langtag_extension_sub(<< $,, R/bits >>, Acc, T, N) when N > 0 -> langtag_list(R, [T|Acc]);
langtag_extension_sub(<< $\s, R/bits >>, Acc, T, N) when N > 0 -> langtag_list_sep(R, [T|Acc]);
langtag_extension_sub(<< $\t, R/bits >>, Acc, T, N) when N > 0 -> langtag_list_sep(R, [T|Acc]);
langtag_extension_sub(<< $-, A, B, C, D, E, F, G, H, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G), ?IS_ALPHANUM(H) ->
	langtag_extension_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G), ?LC(H) >>, N + 1);
langtag_extension_sub(<< $-, A, B, C, D, E, F, G, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G) ->
	langtag_extension_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G) >>, N + 1);
langtag_extension_sub(<< $-, A, B, C, D, E, F, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F) ->
	langtag_extension_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F) >>, N + 1);
langtag_extension_sub(<< $-, A, B, C, D, E, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D), ?IS_ALPHANUM(E) ->
	langtag_extension_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E) >>, N + 1);
langtag_extension_sub(<< $-, A, B, C, D, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D)  ->
	langtag_extension_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D) >>, N + 1);
langtag_extension_sub(<< $-, A, B, C, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C)  ->
	langtag_extension_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C) >>, N + 1);
langtag_extension_sub(<< $-, A, B, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B)  ->
	langtag_extension_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B) >>, N + 1);
langtag_extension_sub(R, Acc, T, N) when N > 0 ->
	langtag_extension(R, Acc, T).

langtag_privateuse_sub(<<>>, Acc, T, N) when N > 0 -> lists:reverse([T|Acc]);
langtag_privateuse_sub(<< $,, R/bits >>, Acc, T, N) when N > 0 -> langtag_list(R, [T|Acc]);
langtag_privateuse_sub(<< $\s, R/bits >>, Acc, T, N) when N > 0 -> langtag_list_sep(R, [T|Acc]);
langtag_privateuse_sub(<< $\t, R/bits >>, Acc, T, N) when N > 0 -> langtag_list_sep(R, [T|Acc]);
langtag_privateuse_sub(<< $-, A, B, C, D, E, F, G, H, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G), ?IS_ALPHANUM(H) ->
	langtag_privateuse_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G), ?LC(H) >>, N + 1);
langtag_privateuse_sub(<< $-, A, B, C, D, E, F, G, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F), ?IS_ALPHANUM(G) ->
	langtag_privateuse_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F), ?LC(G) >>, N + 1);
langtag_privateuse_sub(<< $-, A, B, C, D, E, F, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D),
			?IS_ALPHANUM(E), ?IS_ALPHANUM(F)  ->
	langtag_privateuse_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E), ?LC(F) >>, N + 1);
langtag_privateuse_sub(<< $-, A, B, C, D, E, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D), ?IS_ALPHANUM(E) ->
	langtag_privateuse_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D), ?LC(E) >>, N + 1);
langtag_privateuse_sub(<< $-, A, B, C, D, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C), ?IS_ALPHANUM(D) ->
	langtag_privateuse_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C), ?LC(D) >>, N + 1);
langtag_privateuse_sub(<< $-, A, B, C, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B), ?IS_ALPHANUM(C) ->
	langtag_privateuse_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B), ?LC(C) >>, N + 1);
langtag_privateuse_sub(<< $-, A, B, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A), ?IS_ALPHANUM(B) ->
	langtag_privateuse_sub(R, Acc, << T/binary, $-, ?LC(A), ?LC(B) >>, N + 1);
langtag_privateuse_sub(<< $-, A, R/bits >>, Acc, T, N)
		when ?IS_ALPHANUM(A) ->
	langtag_privateuse_sub(R, Acc, << T/binary, $-, ?LC(A) >>, N + 1).

langtag_list_sep(<<>>, Acc) -> lists:reverse(Acc);
langtag_list_sep(<< $,, R/bits >>, Acc) -> langtag_list(R, Acc);
langtag_list_sep(<< $\s, R/bits >>, Acc) -> langtag_list_sep(R, Acc);
langtag_list_sep(<< $\t, R/bits >>, Acc) -> langtag_list_sep(R, Acc).

-ifdef(TEST).
langtag_language() -> vector(2, 3, alpha()).
langtag_extlang() -> vector(0, 3, [$-, alpha(), alpha(), alpha()]).
langtag_script() -> oneof([[], [$-, alpha(), alpha(), alpha(), alpha()]]).
langtag_region() -> oneof([[], [$-, alpha(), alpha()], [$-, digit(), digit(), digit()]]).

langtag_variant() ->
	small_list(frequency([
		{4, [$-, vector(5, 8, alphanum())]},
		{1, [$-, digit(), alphanum(), alphanum(), alphanum()]}
	])).

langtag_extension() ->
	small_list([$-, ?SUCHTHAT(S, alphanum(), S =/= $x andalso S =/= $X),
		small_non_empty_list([$-, vector(2, 8, alphanum())])
	]).

langtag_privateuse() -> oneof([[], [$-, langtag_privateuse_nodash()]]).
langtag_privateuse_nodash() -> [oneof([$x, $X]), small_non_empty_list([$-, vector(1, 8, alphanum())])].
private_language_tag() -> ?LET(T, langtag_privateuse_nodash(), iolist_to_binary(T)).

language_tag() ->
	?LET(IoList,
		[langtag_language(), langtag_extlang(), langtag_script(), langtag_region(),
			langtag_variant(), langtag_extension(), langtag_privateuse()],
		iolist_to_binary(IoList)).

content_language() ->
	?LET(L,
		non_empty(list(frequency([
			{90, language_tag()},
			{10, private_language_tag()}
		]))),
		begin
			<< _, ContentLanguage/binary >> = iolist_to_binary([[$,, T] || T <- L]),
			{L, ContentLanguage}
		end).

prop_parse_content_language() ->
	?FORALL({L, ContentLanguage},
		content_language(),
		begin
			ResL = parse_content_language(ContentLanguage),
			CheckedL = [?INLINE_LOWERCASE_BC(T) =:= ResT || {T, ResT} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

parse_content_language_test_() ->
	Tests = [
		{<<"de">>, [<<"de">>]},
		{<<"fr">>, [<<"fr">>]},
		{<<"ja">>, [<<"ja">>]},
		{<<"zh-Hant">>, [<<"zh-hant">>]},
		{<<"zh-Hans">>, [<<"zh-hans">>]},
		{<<"sr-Cyrl">>, [<<"sr-cyrl">>]},
		{<<"sr-Latn">>, [<<"sr-latn">>]},
		{<<"zh-cmn-Hans-CN">>, [<<"zh-cmn-hans-cn">>]},
		{<<"cmn-Hans-CN">>, [<<"cmn-hans-cn">>]},
		{<<"zh-yue-HK">>, [<<"zh-yue-hk">>]},
		{<<"yue-HK">>, [<<"yue-hk">>]},
		{<<"zh-Hans-CN">>, [<<"zh-hans-cn">>]},
		{<<"sr-Latn-RS">>, [<<"sr-latn-rs">>]},
		{<<"sl-rozaj">>, [<<"sl-rozaj">>]},
		{<<"sl-rozaj-biske">>, [<<"sl-rozaj-biske">>]},
		{<<"sl-nedis">>, [<<"sl-nedis">>]},
		{<<"de-CH-1901">>, [<<"de-ch-1901">>]},
		{<<"sl-IT-nedis">>, [<<"sl-it-nedis">>]},
		{<<"hy-Latn-IT-arevela">>, [<<"hy-latn-it-arevela">>]},
		{<<"de-DE">>, [<<"de-de">>]},
		{<<"en-US">>, [<<"en-us">>]},
		{<<"es-419">>, [<<"es-419">>]},
		{<<"de-CH-x-phonebk">>, [<<"de-ch-x-phonebk">>]},
		{<<"az-Arab-x-AZE-derbend">>, [<<"az-arab-x-aze-derbend">>]},
		{<<"x-whatever">>, [<<"x-whatever">>]},
		{<<"qaa-Qaaa-QM-x-southern">>, [<<"qaa-qaaa-qm-x-southern">>]},
		{<<"de-Qaaa">>, [<<"de-qaaa">>]},
		{<<"sr-Latn-QM">>, [<<"sr-latn-qm">>]},
		{<<"sr-Qaaa-RS">>, [<<"sr-qaaa-rs">>]},
		{<<"en-US-u-islamcal">>, [<<"en-us-u-islamcal">>]},
		{<<"zh-CN-a-myext-x-private">>, [<<"zh-cn-a-myext-x-private">>]},
		{<<"en-a-myext-b-another">>, [<<"en-a-myext-b-another">>]},
		{<<"mn-Cyrl-MN">>, [<<"mn-cyrl-mn">>]},
		{<<"MN-cYRL-mn">>, [<<"mn-cyrl-mn">>]},
		{<<"mN-cYrL-Mn">>, [<<"mn-cyrl-mn">>]},
		{<<"az-Arab-IR">>, [<<"az-arab-ir">>]},
		{<<"zh-gan">>, [<<"zh-gan">>]},
		{<<"zh-yue">>, [<<"zh-yue">>]},
		{<<"zh-cmn">>, [<<"zh-cmn">>]},
		{<<"de-AT">>, [<<"de-at">>]},
		{<<"de-CH-1996">>, [<<"de-ch-1996">>]},
		{<<"en-Latn-GB-boont-r-extended-sequence-x-private">>,
			[<<"en-latn-gb-boont-r-extended-sequence-x-private">>]},
		{<<"el-x-koine">>, [<<"el-x-koine">>]},
		{<<"el-x-attic">>, [<<"el-x-attic">>]},
		{<<"fr, en-US, es-419, az-Arab, x-pig-latin, man-Nkoo-GN">>,
			[<<"fr">>, <<"en-us">>, <<"es-419">>, <<"az-arab">>, <<"x-pig-latin">>, <<"man-nkoo-gn">>]},
		{<<"da">>, [<<"da">>]},
		{<<"mi, en">>, [<<"mi">>, <<"en">>]}
	],
	[{V, fun() -> R = parse_content_language(V) end} || {V, R} <- Tests].

parse_content_language_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_content_language(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_content_language() ->
	horse:repeat(100000,
		parse_content_language(<<"fr, en-US, es-419, az-Arab, x-pig-latin, man-Nkoo-GN">>)
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
		{<<"3495">>, 3495},
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

%% @doc Parse the Content-Type header.

-spec parse_content_type(binary()) -> media_type().
parse_content_type(<< C, R/bits >>) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_type, R, <<>>)
	end.

media_type(<< $/, C, R/bits >>, T) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_subtype, R, T, <<>>)
	end;
media_type(<< C, R/bits >>, T) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_type, R, T)
	end.

media_subtype(<<>>, T, S) -> {T, S, []};
media_subtype(<< $;, R/bits >>, T, S) -> media_before_param(R, T, S, []);
media_subtype(<< $\s, R/bits >>, T, S) -> media_before_semicolon(R, T, S, []);
media_subtype(<< $\t, R/bits >>, T, S) -> media_before_semicolon(R, T, S, []);
media_subtype(<< C, R/bits >>, T, S) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_subtype, R, T, S)
	end.

media_before_semicolon(<<>>, T, S, P) -> {T, S, lists:reverse(P)};
media_before_semicolon(<< $;, R/bits >>, T, S, P) -> media_before_param(R, T, S, P);
media_before_semicolon(<< $\s, R/bits >>, T, S, P) -> media_before_semicolon(R, T, S, P);
media_before_semicolon(<< $\t, R/bits >>, T, S, P) -> media_before_semicolon(R, T, S, P).

media_before_param(<< $\s, R/bits >>, T, S, P) -> media_before_param(R, T, S, P);
media_before_param(<< $\t, R/bits >>, T, S, P) -> media_before_param(R, T, S, P);
media_before_param(<< "charset=", $", R/bits >>, T, S, P) -> media_charset_quoted(R, T, S, P, <<>>);
media_before_param(<< "charset=", R/bits >>, T, S, P) -> media_charset(R, T, S, P, <<>>);
media_before_param(<< C, R/bits >>, T, S, P) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_param, R, T, S, P, <<>>)
	end.

media_charset_quoted(<< $", R/bits >>, T, S, P, V) ->
	media_before_semicolon(R, T, S, [{<<"charset">>, V}|P]);
media_charset_quoted(<< $\\, C, R/bits >>, T, S, P, V) when ?IS_VCHAR(C) ->
	case C of
		?INLINE_LOWERCASE(media_charset_quoted, R, T, S, P, V)
	end;
media_charset_quoted(<< C, R/bits >>, T, S, P, V) when ?IS_VCHAR(C) ->
	case C of
		?INLINE_LOWERCASE(media_charset_quoted, R, T, S, P, V)
	end.

media_charset(<<>>, T, S, P, V) -> {T, S, lists:reverse([{<<"charset">>, V}|P])};

media_charset(<< $;, R/bits >>, T, S, P, V) -> media_before_param(R, T, S, [{<<"charset">>, V}|P]);
media_charset(<< $\s, R/bits >>, T, S, P, V) -> media_before_semicolon(R, T, S, [{<<"charset">>, V}|P]);
media_charset(<< $\t, R/bits >>, T, S, P, V) -> media_before_semicolon(R, T, S, [{<<"charset">>, V}|P]);
media_charset(<< C, R/bits >>, T, S, P, V) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_charset, R, T, S, P, V)
	end.

media_param(<< $=, $", R/bits >>, T, S, P, K) -> media_quoted(R, T, S, P, K, <<>>);
media_param(<< $=, R/bits >>, T, S, P, K) -> media_value(R, T, S, P, K, <<>>);
media_param(<< C, R/bits >>, T, S, P, K) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(media_param, R, T, S, P, K)
	end.

media_quoted(<< $", R/bits >>, T, S, P, K, V) -> media_before_semicolon(R, T, S, [{K, V}|P]);
media_quoted(<< $\\, C, R/bits >>, T, S, P, K, V) when ?IS_VCHAR(C) -> media_quoted(R, T, S, P, K, << V/binary, C >>);
media_quoted(<< C, R/bits >>, T, S, P, K, V) when ?IS_VCHAR(C) -> media_quoted(R, T, S, P, K, << V/binary, C >>).

media_value(<<>>, T, S, P, K, V) -> {T, S, lists:reverse([{K, V}|P])};
media_value(<< $;, R/bits >>, T, S, P, K, V) -> media_before_param(R, T, S, [{K, V}|P]);
media_value(<< $\s, R/bits >>, T, S, P, K, V) -> media_before_semicolon(R, T, S, [{K, V}|P]);
media_value(<< $\t, R/bits >>, T, S, P, K, V) -> media_before_semicolon(R, T, S, [{K, V}|P]);
media_value(<< C, R/bits >>, T, S, P, K, V) when ?IS_TOKEN(C) -> media_value(R, T, S, P, K, << V/binary, C >>).

-ifdef(TEST).
media_type_parameter() ->
	frequency([
		{90, parameter()},
		{10, {<<"charset">>, oneof([token(), quoted_string()]), <<>>, <<>>}}
	]).

media_type() ->
	?LET({T, S, P},
		{token(), token(), small_list(media_type_parameter())},
		{T, S, P, iolist_to_binary([T, $/, S, [[OWS1, $;, OWS2, K, $=, V] || {K, V, OWS1, OWS2} <- P]])}
	).

prop_parse_content_type() ->
	?FORALL({T, S, P, MediaType},
		media_type(),
		begin
			{ResT, ResS, ResP} = parse_content_type(MediaType),
			ExpectedP = [case ?INLINE_LOWERCASE_BC(K) of
				<<"charset">> -> {<<"charset">>, ?INLINE_LOWERCASE_BC(unquote(V))};
				LowK -> {LowK, unquote(V)}
			end || {K, V, _, _} <- P],
			ResT =:= ?INLINE_LOWERCASE_BC(T)
				andalso ResS =:= ?INLINE_LOWERCASE_BC(S)
				andalso ResP =:= ExpectedP
		end
	).

parse_content_type_test_() ->
	Tests = [
		{<<"text/html;charset=utf-8">>,
			{<<"text">>, <<"html">>, [{<<"charset">>, <<"utf-8">>}]}},
		{<<"text/html;charset=UTF-8">>,
			{<<"text">>, <<"html">>, [{<<"charset">>, <<"utf-8">>}]}},
		{<<"Text/HTML;Charset=\"utf-8\"">>,
			{<<"text">>, <<"html">>, [{<<"charset">>, <<"utf-8">>}]}},
		{<<"text/html; charset=\"utf-8\"">>,
			{<<"text">>, <<"html">>, [{<<"charset">>, <<"utf-8">>}]}},
		{<<"text/html; charset=ISO-8859-4">>,
			{<<"text">>, <<"html">>, [{<<"charset">>, <<"iso-8859-4">>}]}},
		{<<"text/plain; charset=iso-8859-4">>,
			{<<"text">>, <<"plain">>, [{<<"charset">>, <<"iso-8859-4">>}]}},
		{<<"multipart/form-data  \t;Boundary=\"MultipartIsUgly\"">>,
			{<<"multipart">>, <<"form-data">>, [
				{<<"boundary">>, <<"MultipartIsUgly">>}
			]}},
		{<<"foo/bar; one=FirstParam; two=SecondParam">>,
			{<<"foo">>, <<"bar">>, [
				{<<"one">>, <<"FirstParam">>},
				{<<"two">>, <<"SecondParam">>}
			]}}
	],
	[{V, fun() -> R = parse_content_type(V) end} || {V, R} <- Tests].
-endif.

-ifdef(PERF).
horse_parse_content_type() ->
	horse:repeat(200000,
		parse_content_type(<<"text/html;charset=utf-8">>)
	).
-endif.

%% @doc Parse the Date header.

-spec parse_date(binary()) -> calendar:datetime().
parse_date(Date) ->
	cow_date:parse_date(Date).

-ifdef(TEST).
parse_date_test_() ->
	Tests = [
		{<<"Tue, 15 Nov 1994 08:12:31 GMT">>, {{1994, 11, 15}, {8, 12, 31}}}
	],
	[{V, fun() -> R = parse_date(V) end} || {V, R} <- Tests].
-endif.

%% @doc Parse the ETag header.

-spec parse_etag(binary()) -> etag().
parse_etag(<< $W, $/, $", R/bits >>) ->
	etag(R, weak, <<>>);
parse_etag(<< $", R/bits >>) ->
	etag(R, strong, <<>>).

etag(<< $", R/bits >>, Strength, Tag) ->
	ws_end(R),
	{Strength, Tag};
etag(<< C, R/bits >>, Strength, Tag) when ?IS_ETAGC(C) ->
	etag(R, Strength, << Tag/binary, C >>).

-ifdef(TEST).
etagc() ->
	?SUCHTHAT(C, int(16#21, 16#ff), C =/= 16#22 andalso C =/= 16#7f).

etag() ->
	?LET({Strength, Tag},
		{oneof([weak, strong]), list(etagc())},
		begin
			TagBin = list_to_binary(Tag),
			{{Strength, TagBin},
				case Strength of
					weak -> << $W, $/, $", TagBin/binary, $" >>;
					strong -> << $", TagBin/binary, $" >>
				end}
		end).

prop_parse_etag() ->
	?FORALL({Tag, TagBin},
		etag(),
		Tag =:= parse_etag(TagBin)).

parse_etag_test_() ->
	Tests = [
		{<<"\"xyzzy\"">>, {strong, <<"xyzzy">>}},
		{<<"W/\"xyzzy\"">>, {weak, <<"xyzzy">>}},
		{<<"\"\"">>, {strong, <<>>}}
	],
	[{V, fun() -> R = parse_etag(V) end} || {V, R} <- Tests].

parse_etag_error_test_() ->
	Tests = [
		<<>>,
		<<"\"">>,
		<<"W">>,
		<<"W/">>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_etag(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_etag() ->
	horse:repeat(200000,
		parse_etag(<<"W/\"xyzzy\"">>)
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
expect() ->
	?LET(E,
		[$1, $0, $0, $-,
			oneof([$c, $C]), oneof([$o, $O]), oneof([$n, $N]),
			oneof([$t, $T]), oneof([$i, $I]), oneof([$n, $N]),
			oneof([$u, $U]), oneof([$e, $E])],
		list_to_binary(E)).

prop_parse_expect() ->
	?FORALL(E, expect(), continue =:= parse_expect(E)).

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

%% @doc Parse the Expires header.
%%
%% Recipients must interpret invalid date formats as a date
%% in the past. The value "0" is commonly used.

-spec parse_expires(binary()) -> calendar:datetime().
parse_expires(<<"0">>) ->
	{{1, 1, 1}, {0, 0, 0}};
parse_expires(Expires) ->
	try
		cow_date:parse_date(Expires)
	catch _:_ ->
		{{1, 1, 1}, {0, 0, 0}}
	end.

-ifdef(TEST).
parse_expires_test_() ->
	Tests = [
		{<<"0">>, {{1, 1, 1}, {0, 0, 0}}},
		{<<"Thu, 01 Dec 1994 nope invalid">>, {{1, 1, 1}, {0, 0, 0}}},
		{<<"Thu, 01 Dec 1994 16:00:00 GMT">>, {{1994, 12, 1}, {16, 0, 0}}}
	],
	[{V, fun() -> R = parse_expires(V) end} || {V, R} <- Tests].
-endif.

-ifdef(PERF).
horse_parse_expires_0() ->
	horse:repeat(200000,
		parse_expires(<<"0">>)
	).

horse_parse_expires_invalid() ->
	horse:repeat(200000,
		parse_expires(<<"Thu, 01 Dec 1994 nope invalid">>)
	).
-endif.

%% @doc Parse the If-Match header.

-spec parse_if_match(binary()) -> '*' | [etag()].
parse_if_match(<<"*">>) ->
	'*';
parse_if_match(IfMatch) ->
	nonempty(etag_list(IfMatch, [])).

etag_list(<<>>, Acc) -> lists:reverse(Acc);
etag_list(<< $\s, R/bits >>, Acc) -> etag_list(R, Acc);
etag_list(<< $\t, R/bits >>, Acc) -> etag_list(R, Acc);
etag_list(<< $,, R/bits >>, Acc) -> etag_list(R, Acc);
etag_list(<< $W, $/, $", R/bits >>, Acc) -> etag(R, Acc, weak, <<>>);
etag_list(<< $", R/bits >>, Acc) -> etag(R, Acc, strong, <<>>).

etag(<< $", R/bits >>, Acc, Strength, Tag) -> etag_list_sep(R, [{Strength, Tag}|Acc]);
etag(<< C, R/bits >>, Acc, Strength, Tag) when ?IS_ETAGC(C) -> etag(R, Acc, Strength, << Tag/binary, C >>).

etag_list_sep(<<>>, Acc) -> lists:reverse(Acc);
etag_list_sep(<< $\s, R/bits >>, Acc) -> etag_list_sep(R, Acc);
etag_list_sep(<< $\t, R/bits >>, Acc) -> etag_list_sep(R, Acc);
etag_list_sep(<< $,, R/bits >>, Acc) -> etag_list(R, Acc).

-ifdef(TEST).
prop_parse_if_match() ->
	?FORALL(L,
		non_empty(list(etag())),
		begin
			<< _, IfMatch/binary >> = iolist_to_binary([[$,, T] || {_, T} <- L]),
			ResL = parse_if_match(IfMatch),
			CheckedL = [T =:= ResT || {{T, _}, ResT} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

parse_if_match_test_() ->
	Tests = [
		{<<"\"xyzzy\"">>, [{strong, <<"xyzzy">>}]},
		{<<"\"xyzzy\", \"r2d2xxxx\", \"c3piozzzz\"">>,
			[{strong, <<"xyzzy">>}, {strong, <<"r2d2xxxx">>}, {strong, <<"c3piozzzz">>}]},
		{<<"*">>, '*'}
	],
	[{V, fun() -> R = parse_if_match(V) end} || {V, R} <- Tests].

parse_if_match_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_if_match(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_if_match() ->
	horse:repeat(200000,
		parse_if_match(<<"\"xyzzy\", \"r2d2xxxx\", \"c3piozzzz\"">>)
	).
-endif.

%% @doc Parse the If-Modified-Since header.

-spec parse_if_modified_since(binary()) -> calendar:datetime().
parse_if_modified_since(IfModifiedSince) ->
	cow_date:parse_date(IfModifiedSince).

-ifdef(TEST).
parse_if_modified_since_test_() ->
	Tests = [
		{<<"Sat, 29 Oct 1994 19:43:31 GMT">>, {{1994, 10, 29}, {19, 43, 31}}}
	],
	[{V, fun() -> R = parse_if_modified_since(V) end} || {V, R} <- Tests].
-endif.

%% @doc Parse the If-None-Match header.

-spec parse_if_none_match(binary()) -> '*' | [etag()].
parse_if_none_match(<<"*">>) ->
	'*';
parse_if_none_match(IfNoneMatch) ->
	nonempty(etag_list(IfNoneMatch, [])).

-ifdef(TEST).
parse_if_none_match_test_() ->
	Tests = [
		{<<"\"xyzzy\"">>, [{strong, <<"xyzzy">>}]},
		{<<"W/\"xyzzy\"">>, [{weak, <<"xyzzy">>}]},
		{<<"\"xyzzy\", \"r2d2xxxx\", \"c3piozzzz\"">>,
			[{strong, <<"xyzzy">>}, {strong, <<"r2d2xxxx">>}, {strong, <<"c3piozzzz">>}]},
		{<<"W/\"xyzzy\", W/\"r2d2xxxx\", W/\"c3piozzzz\"">>,
			[{weak, <<"xyzzy">>}, {weak, <<"r2d2xxxx">>}, {weak, <<"c3piozzzz">>}]},
		{<<"*">>, '*'}
	],
	[{V, fun() -> R = parse_if_none_match(V) end} || {V, R} <- Tests].

parse_if_none_match_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_if_none_match(V)) end} || V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_if_none_match() ->
	horse:repeat(200000,
		parse_if_none_match(<<"W/\"xyzzy\", W/\"r2d2xxxx\", W/\"c3piozzzz\"">>)
	).
-endif.

%% @doc Parse the If-Unmodified-Since header.

-spec parse_if_unmodified_since(binary()) -> calendar:datetime().
parse_if_unmodified_since(IfModifiedSince) ->
	cow_date:parse_date(IfModifiedSince).

-ifdef(TEST).
parse_if_unmodified_since_test_() ->
	Tests = [
		{<<"Sat, 29 Oct 1994 19:43:31 GMT">>, {{1994, 10, 29}, {19, 43, 31}}}
	],
	[{V, fun() -> R = parse_if_unmodified_since(V) end} || {V, R} <- Tests].
-endif.

%% @doc Parse the Last-Modified header.

-spec parse_last_modified(binary()) -> calendar:datetime().
parse_last_modified(LastModified) ->
	cow_date:parse_date(LastModified).

-ifdef(TEST).
parse_last_modified_test_() ->
	Tests = [
		{<<"Tue, 15 Nov 1994 12:45:26 GMT">>, {{1994, 11, 15}, {12, 45, 26}}}
	],
	[{V, fun() -> R = parse_last_modified(V) end} || {V, R} <- Tests].
-endif.

%% @doc Parse the Max-Forwards header.

-spec parse_max_forwards(binary()) -> non_neg_integer().
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
prop_parse_max_forwards() ->
	?FORALL(
		X,
		non_neg_integer(),
		X =:= parse_max_forwards(integer_to_binary(X))
	).

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

parse_max_forwards_error_test_() ->
	Tests = [
		<<>>,
		<<"123, 123">>,
		<<"4.17">>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_content_length(V)) end} || V <- Tests].
-endif.

%% @doc Parse the Sec-WebSocket-Extensions request header.

-spec parse_sec_websocket_extensions(binary()) -> [{binary(), [binary() | {binary(), binary()}]}].
parse_sec_websocket_extensions(SecWebSocketExtensions) ->
	nonempty(ws_extension_list(SecWebSocketExtensions, [])).

ws_extension_list(<<>>, Acc) -> lists:reverse(Acc);
ws_extension_list(<< $\s, R/bits >>, Acc) -> ws_extension_list(R, Acc);
ws_extension_list(<< $\t, R/bits >>, Acc) -> ws_extension_list(R, Acc);
ws_extension_list(<< $,, R/bits >>, Acc) -> ws_extension_list(R, Acc);
ws_extension_list(<< C, R/bits >>, Acc) when ?IS_TOKEN(C) -> ws_extension(R, Acc, << C >>).

ws_extension(<<>>, Acc, E) -> lists:reverse([{E, []}|Acc]);
ws_extension(<< $,, R/bits >>, Acc, E) -> ws_extension_list(R, [{E, []}|Acc]);
ws_extension(<< $;, R/bits >>, Acc, E) -> ws_extension_before_param(R, Acc, E, []);
ws_extension(<< $\s, R/bits >>, Acc, E) -> ws_extension_before_semicolon(R, Acc, E, []);
ws_extension(<< $\t, R/bits >>, Acc, E) -> ws_extension_before_semicolon(R, Acc, E, []);
ws_extension(<< C, R/bits >>, Acc, E) when ?IS_TOKEN(C) -> ws_extension(R, Acc, << E/binary, C >>).

ws_extension_before_semicolon(<<>>, Acc, E, P) -> lists:reverse([{E, lists:reverse(P)}|Acc]);
ws_extension_before_semicolon(<< $,, R/bits >>, Acc, E, P) -> ws_extension_list(R, [{E, lists:reverse(P)}|Acc]);
ws_extension_before_semicolon(<< $;, R/bits >>, Acc, E, P) -> ws_extension_before_param(R, Acc, E, P);
ws_extension_before_semicolon(<< $\s, R/bits >>, Acc, E, P) -> ws_extension_before_semicolon(R, Acc, E, P);
ws_extension_before_semicolon(<< $\t, R/bits >>, Acc, E, P) -> ws_extension_before_semicolon(R, Acc, E, P).

ws_extension_before_param(<< $\s, R/bits >>, Acc, E, P) -> ws_extension_before_param(R, Acc, E, P);
ws_extension_before_param(<< $\t, R/bits >>, Acc, E, P) -> ws_extension_before_param(R, Acc, E, P);
ws_extension_before_param(<< C, R/bits >>, Acc, E, P) when ?IS_TOKEN(C) -> ws_extension_param(R, Acc, E, P, << C >>).

ws_extension_param(<<>>, Acc, E, P, K) -> lists:reverse([{E, lists:reverse([K|P])}|Acc]);
ws_extension_param(<< $\s, R/bits >>, Acc, E, P, K) -> ws_extension_before_semicolon(R, Acc, E, [K|P]);
ws_extension_param(<< $\t, R/bits >>, Acc, E, P, K) -> ws_extension_before_semicolon(R, Acc, E, [K|P]);
ws_extension_param(<< $,, R/bits >>, Acc, E, P, K) -> ws_extension_list(R, [{E, lists:reverse([K|P])}|Acc]);
ws_extension_param(<< $;, R/bits >>, Acc, E, P, K) -> ws_extension_before_param(R, Acc, E, [K|P]);
ws_extension_param(<< $=, $", R/bits >>, Acc, E, P, K) -> ws_extension_quoted(R, Acc, E, P, K, <<>>);
ws_extension_param(<< $=, C, R/bits >>, Acc, E, P, K) when ?IS_TOKEN(C) -> ws_extension_value(R, Acc, E, P, K, << C >>);
ws_extension_param(<< C, R/bits >>, Acc, E, P, K) when ?IS_TOKEN(C) -> ws_extension_param(R, Acc, E, P, << K/binary, C >>).

ws_extension_quoted(<< $", R/bits >>, Acc, E, P, K, V) -> ws_extension_before_semicolon(R, Acc, E, [{K, V}|P]);
ws_extension_quoted(<< $\\, C, R/bits >>, Acc, E, P, K, V) when ?IS_TOKEN(C) -> ws_extension_quoted(R, Acc, E, P, K, << V/binary, C >>);
ws_extension_quoted(<< C, R/bits >>, Acc, E, P, K, V) when ?IS_TOKEN(C) -> ws_extension_quoted(R, Acc, E, P, K, << V/binary, C >>).

ws_extension_value(<<>>, Acc, E, P, K, V) -> lists:reverse([{E, lists:reverse([{K, V}|P])}|Acc]);
ws_extension_value(<< $\s, R/bits >>, Acc, E, P, K, V) -> ws_extension_before_semicolon(R, Acc, E, [{K, V}|P]);
ws_extension_value(<< $\t, R/bits >>, Acc, E, P, K, V) -> ws_extension_before_semicolon(R, Acc, E, [{K, V}|P]);
ws_extension_value(<< $,, R/bits >>, Acc, E, P, K, V) -> ws_extension_list(R, [{E, lists:reverse([{K, V}|P])}|Acc]);
ws_extension_value(<< $;, R/bits >>, Acc, E, P, K, V) -> ws_extension_before_param(R, Acc, E, [{K, V}|P]);
ws_extension_value(<< C, R/bits >>, Acc, E, P, K, V) when ?IS_TOKEN(C) -> ws_extension_value(R, Acc, E, P, K, << V/binary, C >>).

-ifdef(TEST).
quoted_token() ->
	?LET(T,
		non_empty(list(frequency([
			{99, tchar()},
			{1, [$\\, tchar()]}
		]))),
		[$", T, $"]).

ws_extension() ->
	?LET({E, PL},
		{token(), small_list({ows(), ows(), oneof([token(), {token(), oneof([token(), quoted_token()])}])})},
		{E, PL, iolist_to_binary([E,
			[case P of
				{OWS1, OWS2, {K, V}} -> [OWS1, $;, OWS2, K, $=, V];
				{OWS1, OWS2, K} -> [OWS1, $;, OWS2, K]
			end || P <- PL]
		])}).

prop_parse_sec_websocket_extensions() ->
	?FORALL(L,
		non_empty(list(ws_extension())),
		begin
			<< _, SecWebsocketExtensions/binary >> = iolist_to_binary([[$,, E] || {_, _, E} <- L]),
			ResL = parse_sec_websocket_extensions(SecWebsocketExtensions),
			CheckedL = [begin
				ExpectedPL = [case P of
					{_, _, {K, V}} -> {K, unquote(V)};
					{_, _, K} -> K
				end || P <- PL],
				E =:= ResE andalso ExpectedPL =:= ResPL
			end || {{E, PL, _}, {ResE, ResPL}} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

parse_sec_websocket_extensions_test_() ->
	Tests = [
		{<<"foo">>, [{<<"foo">>, []}]},
		{<<"bar; baz=2">>, [{<<"bar">>, [{<<"baz">>, <<"2">>}]}]},
		{<<"foo, bar; baz=2">>, [{<<"foo">>, []}, {<<"bar">>, [{<<"baz">>, <<"2">>}]}]},
		{<<"deflate-stream">>, [{<<"deflate-stream">>, []}]},
		{<<"mux; max-channels=4; flow-control, deflate-stream">>,
			[{<<"mux">>, [{<<"max-channels">>, <<"4">>}, <<"flow-control">>]}, {<<"deflate-stream">>, []}]},
		{<<"private-extension">>, [{<<"private-extension">>, []}]}
	],
	[{V, fun() -> R = parse_sec_websocket_extensions(V) end} || {V, R} <- Tests].

parse_sec_websocket_extensions_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_sec_websocket_extensions(V)) end}
		|| V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_sec_websocket_extensions() ->
	horse:repeat(200000,
		parse_sec_websocket_extensions(<<"mux; max-channels=4; flow-control, deflate-stream">>)
	).
-endif.

%% @doc Parse the Sec-WebSocket-Protocol request header.

-spec parse_sec_websocket_protocol_client(binary()) -> [binary()].
parse_sec_websocket_protocol_client(SecWebSocketProtocol) ->
	nonempty(token_ci_list(SecWebSocketProtocol, [])).

-ifdef(TEST).
parse_sec_websocket_protocol_client_test_() ->
	Tests = [
		{<<"chat, superchat">>, [<<"chat">>, <<"superchat">>]}
	],
	[{V, fun() -> R = parse_sec_websocket_protocol_client(V) end} || {V, R} <- Tests].

parse_sec_websocket_protocol_client_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_sec_websocket_protocol_client(V)) end}
		|| V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_sec_websocket_protocol_client() ->
	horse:repeat(200000,
		parse_sec_websocket_protocol_client(<<"chat, superchat">>)
	).
-endif.

%% @doc Parse the Sec-WebSocket-Version request header.

-spec parse_sec_websocket_version_client(binary()) -> 0..255.
parse_sec_websocket_version_client(SecWebSocketVersion) when byte_size(SecWebSocketVersion) < 4 ->
	Version = binary_to_integer(SecWebSocketVersion),
	true = Version >= 0 andalso Version =< 255,
	Version.

-ifdef(TEST).
prop_parse_sec_websocket_version_client() ->
	?FORALL(Version,
		int(0, 255),
		Version =:= parse_sec_websocket_version_client(integer_to_binary(Version))).

parse_sec_websocket_version_client_test_() ->
	Tests = [
		{<<"13">>, 13},
		{<<"25">>, 25}
	],
	[{V, fun() -> R = parse_sec_websocket_version_client(V) end} || {V, R} <- Tests].

parse_sec_websocket_version_client_error_test_() ->
	Tests = [
		<<>>,
		<<" ">>,
		<<"7, 8, 13">>,
		<<"invalid">>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_sec_websocket_version_client(V)) end}
		|| V <- Tests].
-endif.

-ifdef(PERF).
horse_parse_sec_websocket_version_client_13() ->
	horse:repeat(200000,
		parse_sec_websocket_version_client(<<"13">>)
	).

horse_parse_sec_websocket_version_client_255() ->
	horse:repeat(200000,
		parse_sec_websocket_version_client(<<"255">>)
	).
-endif.

%% @doc Parse the Transfer-Encoding header.
%%
%% @todo This function does not support parsing of transfer-parameter.

-spec parse_transfer_encoding(binary()) -> [binary()].
parse_transfer_encoding(<<"chunked">>) ->
	[<<"chunked">>];
parse_transfer_encoding(TransferEncoding) ->
	nonempty(token_ci_list(TransferEncoding, [])).

-ifdef(TEST).
prop_parse_transfer_encoding() ->
	?FORALL(L,
		non_empty(list(token())),
		begin
			<< _, TransferEncoding/binary >> = iolist_to_binary([[$,, C] || C <- L]),
			ResL = parse_transfer_encoding(TransferEncoding),
			CheckedL = [?INLINE_LOWERCASE_BC(Co) =:= ResC || {Co, ResC} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

parse_transfer_encoding_test_() ->
	Tests = [
		{<<"a , , , ">>, [<<"a">>]},
		{<<" , , , a">>, [<<"a">>]},
		{<<"a , , b">>, [<<"a">>, <<"b">>]},
		{<<"chunked">>, [<<"chunked">>]},
		{<<"chunked, something">>, [<<"chunked">>, <<"something">>]},
		{<<"gzip, chunked">>, [<<"gzip">>, <<"chunked">>]}
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

%% @doc Parse the Upgrade header.
%%
%% It is unclear from the RFC whether the values here are
%% case sensitive.
%%
%% We handle them in a case insensitive manner because they
%% are described as case insensitive in the Websocket RFC.

-spec parse_upgrade(binary()) -> [binary()].
parse_upgrade(Upgrade) ->
	nonempty(protocol_list(Upgrade, [])).

protocol_list(<<>>, Acc) -> lists:reverse(Acc);
protocol_list(<< $\s, R/bits >>, Acc) -> protocol_list(R, Acc);
protocol_list(<< $\t, R/bits >>, Acc) -> protocol_list(R, Acc);
protocol_list(<< $,, R/bits >>, Acc) -> protocol_list(R, Acc);
protocol_list(<< C, R/bits >>, Acc) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(protocol_name, R, Acc, <<>>)
	end.

protocol_name(<<>>, Acc, P) -> lists:reverse([P|Acc]);
protocol_name(<< $\s, R/bits >>, Acc, P) -> protocol_list_sep(R, [P|Acc]);
protocol_name(<< $\t, R/bits >>, Acc, P) -> protocol_list_sep(R, [P|Acc]);
protocol_name(<< $,, R/bits >>, Acc, P) -> protocol_list(R, [P|Acc]);
protocol_name(<< $/, C, R/bits >>, Acc, P) ->
	case C of
		?INLINE_LOWERCASE(protocol_version, R, Acc, << P/binary, $/ >>)
	end;
protocol_name(<< C, R/bits >>, Acc, P) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(protocol_name, R, Acc, P)
	end.

protocol_version(<<>>, Acc, P) -> lists:reverse([P|Acc]);
protocol_version(<< $\s, R/bits >>, Acc, P) -> protocol_list_sep(R, [P|Acc]);
protocol_version(<< $\t, R/bits >>, Acc, P) -> protocol_list_sep(R, [P|Acc]);
protocol_version(<< $,, R/bits >>, Acc, P) -> protocol_list(R, [P|Acc]);
protocol_version(<< C, R/bits >>, Acc, P) when ?IS_TOKEN(C) ->
	case C of
		?INLINE_LOWERCASE(protocol_version, R, Acc, P)
	end.

protocol_list_sep(<<>>, Acc) -> lists:reverse(Acc);
protocol_list_sep(<< $\s, R/bits >>, Acc) -> protocol_list_sep(R, Acc);
protocol_list_sep(<< $\t, R/bits >>, Acc) -> protocol_list_sep(R, Acc);
protocol_list_sep(<< $,, R/bits >>, Acc) -> protocol_list(R, Acc).

-ifdef(TEST).
protocols() ->
	?LET(P,
		oneof([token(), [token(), $/, token()]]),
		iolist_to_binary(P)).

prop_parse_upgrade() ->
	?FORALL(L,
		non_empty(list(protocols())),
		begin
			<< _, Upgrade/binary >> = iolist_to_binary([[$,, P] || P <- L]),
			ResL = parse_upgrade(Upgrade),
			CheckedL = [?INLINE_LOWERCASE_BC(P) =:= ResP || {P, ResP} <- lists:zip(L, ResL)],
			[true] =:= lists:usort(CheckedL)
		end).

parse_upgrade_test_() ->
	Tests = [
		{<<"HTTP/2.0, SHTTP/1.3, IRC/6.9, RTA/x11">>,
			[<<"http/2.0">>, <<"shttp/1.3">>, <<"irc/6.9">>, <<"rta/x11">>]},
		{<<"HTTP/2.0">>, [<<"http/2.0">>]}
	],
	[{V, fun() -> R = parse_transfer_encoding(V) end} || {V, R} <- Tests].

parse_upgrade_error_test_() ->
	Tests = [
		<<>>
	],
	[{V, fun() -> {'EXIT', _} = (catch parse_upgrade(V)) end}
		|| V <- Tests].
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
