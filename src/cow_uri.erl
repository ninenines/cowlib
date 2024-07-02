%% Copyright (c) 2016-2024, Loïc Hoguin <essen@ninenines.eu>
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

-module(cow_uri).

-include("cow_inline.hrl").

-export([urldecode/1]).
-export([urlencode/1]).

%% Decode a percent encoded string. (RFC3986 2.1)
%%
%% Inspiration for some of the optimisations done here come
%% from the new `json` module as it was in mid-2024.
%%
%% Possible input includes:
%%
%% * nothing encoded (no % character):
%%   We want to return the binary as-is to avoid an allocation.
%%
%% * small number of encoded characters:
%%   We can "skip" words of text.
%%
%% * mostly encoded characters (non-ascii languages)
%%   We can decode characters in bulk.

-define(IS_PLAIN(C), (
	(C =:= $!) orelse (C =:= $$) orelse (C =:= $&) orelse (C =:= $') orelse
	(C =:= $() orelse (C =:= $)) orelse (C =:= $*) orelse (C =:= $+) orelse
	(C =:= $,) orelse (C =:= $-) orelse (C =:= $.) orelse (C =:= $0) orelse
	(C =:= $1) orelse (C =:= $2) orelse (C =:= $3) orelse (C =:= $4) orelse
	(C =:= $5) orelse (C =:= $6) orelse (C =:= $7) orelse (C =:= $8) orelse
	(C =:= $9) orelse (C =:= $:) orelse (C =:= $;) orelse (C =:= $=) orelse
	(C =:= $@) orelse (C =:= $A) orelse (C =:= $B) orelse (C =:= $C) orelse
	(C =:= $D) orelse (C =:= $E) orelse (C =:= $F) orelse (C =:= $G) orelse
	(C =:= $H) orelse (C =:= $I) orelse (C =:= $J) orelse (C =:= $K) orelse
	(C =:= $L) orelse (C =:= $M) orelse (C =:= $N) orelse (C =:= $O) orelse
	(C =:= $P) orelse (C =:= $Q) orelse (C =:= $R) orelse (C =:= $S) orelse
	(C =:= $T) orelse (C =:= $U) orelse (C =:= $V) orelse (C =:= $W) orelse
	(C =:= $X) orelse (C =:= $Y) orelse (C =:= $Z) orelse (C =:= $_) orelse
	(C =:= $a) orelse (C =:= $b) orelse (C =:= $c) orelse (C =:= $d) orelse
	(C =:= $e) orelse (C =:= $f) orelse (C =:= $g) orelse (C =:= $h) orelse
	(C =:= $i) orelse (C =:= $j) orelse (C =:= $k) orelse (C =:= $l) orelse
	(C =:= $m) orelse (C =:= $n) orelse (C =:= $o) orelse (C =:= $p) orelse
	(C =:= $q) orelse (C =:= $r) orelse (C =:= $s) orelse (C =:= $t) orelse
	(C =:= $u) orelse (C =:= $v) orelse (C =:= $w) orelse (C =:= $x) orelse
	(C =:= $y) orelse (C =:= $z) orelse (C =:= $~)
)).

urldecode(Binary) ->
	skip_dec(Binary, Binary, 0).

%% This functions helps avoid a binary allocation when
%% there is nothing to decode.
skip_dec(Binary, Orig, Len) ->
	case Binary of
		<<C1, C2, C3, C4, Rest/bits>>
				when ?IS_PLAIN(C1) andalso ?IS_PLAIN(C2)
				andalso ?IS_PLAIN(C3) andalso ?IS_PLAIN(C4) ->
			skip_dec(Rest, Orig, Len + 4);
		_ ->
			dec(Binary, [], Orig, 0, Len)
	end.

%% This clause helps speed up decoding of highly encoded values.
dec(<<$%, H1, L1, $%, H2, L2, $%, H3, L3, $%, H4, L4, Rest/bits>>, Acc, Orig, Skip, Len) ->
	C1 = ?UNHEX(H1, L1),
	C2 = ?UNHEX(H2, L2),
	C3 = ?UNHEX(H3, L3),
	C4 = ?UNHEX(H4, L4),
	case Len of
		0 ->
			dec(Rest, [Acc|<<C1, C2, C3, C4>>], Orig, Skip + 12, 0);
		_ ->
			Part = binary_part(Orig, Skip, Len),
			dec(Rest, [Acc, Part|<<C1, C2, C3, C4>>], Orig, Skip + Len + 12, 0)
	end;
dec(<<$%, H, L, Rest/bits>>, Acc, Orig, Skip, Len) ->
	C = ?UNHEX(H, L),
	case Len of
		0 ->
			dec(Rest, [Acc|<<C>>], Orig, Skip + 3, 0);
		_ ->
			Part = binary_part(Orig, Skip, Len),
			dec(Rest, [Acc, Part|<<C>>], Orig, Skip + Len + 3, 0)
	end;
%% This clause helps speed up decoding of barely encoded values.
dec(<<C1, C2, C3, C4, Rest/bits>>, Acc, Orig, Skip, Len)
				when ?IS_PLAIN(C1) andalso ?IS_PLAIN(C2)
				andalso ?IS_PLAIN(C3) andalso ?IS_PLAIN(C4) ->
	dec(Rest, Acc, Orig, Skip, Len + 4);
dec(<<C, Rest/bits>>, Acc, Orig, Skip, Len) when ?IS_PLAIN(C) ->
	dec(Rest, Acc, Orig, Skip, Len + 1);
dec(<<>>, _, Orig, 0, _) ->
	Orig;
dec(<<>>, Acc, _, _, 0) ->
	iolist_to_binary(Acc);
dec(<<>>, Acc, Orig, Skip, Len) ->
	Part = binary_part(Orig, Skip, Len),
	iolist_to_binary([Acc|Part]);
dec(_, _, Orig, Skip, Len) ->
	error({invalid_byte, binary:at(Orig, Skip + Len)}).

-ifdef(TEST).
urldecode_test_() ->
	Tests = [
		{<<"%20">>, <<" ">>},
		{<<"+">>, <<"+">>},
		{<<"%00">>, <<0>>},
		{<<"%fF">>, <<255>>},
		{<<"123">>, <<"123">>},
		{<<"%i5">>, error},
		{<<"%5">>, error}
	],
	[{Qs, fun() ->
		E = try urldecode(Qs) of
			R -> R
		catch _:_ ->
			error
		end
	end} || {Qs, E} <- Tests].

urldecode_identity_test_() ->
	Tests = [
		<<"%20">>,
		<<"+">>,
		<<"nothingnothingnothingnothing">>,
		<<"Small+fast+modular+HTTP+server">>,
		<<"Small%20fast%20modular%20HTTP%20server">>,
		<<"Small%2F+fast%2F+modular+HTTP+server.">>,
		<<"%E3%83%84%E3%82%A4%E3%83%B3%E3%82%BD%E3%82%A6%E3%83"
			"%AB%E3%80%9C%E8%BC%AA%E5%BB%BB%E3%81%99%E3%82%8B%E6%97%8B%E5"
			"%BE%8B%E3%80%9C">>
	],
	[{V, fun() -> V = urlencode(urldecode(V)) end} || V <- Tests].

horse_urldecode() ->
	horse:repeat(100000,
		urldecode(<<"nothingnothingnothingnothing">>)
	).

horse_urldecode_hex() ->
	horse:repeat(100000,
		urldecode(<<"Small%2C%20fast%2C%20modular%20HTTP%20server.">>)
	).

horse_urldecode_jp_hex() ->
	horse:repeat(100000,
		urldecode(<<"%E3%83%84%E3%82%A4%E3%83%B3%E3%82%BD%E3%82%A6%E3%83"
			"%AB%E3%80%9C%E8%BC%AA%E5%BB%BB%E3%81%99%E3%82%8B%E6%97%8B%E5"
			"%BE%8B%E3%80%9C">>)
	).

horse_urldecode_jp_mixed_hex() ->
	horse:repeat(100000,
		urldecode(<<"%E3%83%84%E3%82%A4%E3%83%B3%E3%82%BD%E3123%82%A6%E3%83"
			"%AB%E3%80%9C%E8%BC%AA%E5%BB%BB%E3%81%99%E3%82%8B%E6%97%8B%E5"
			"%BE%8B%E3%80%9C">>)
	).

horse_urldecode_worst_case_hex() ->
	horse:repeat(100000,
		urldecode(<<"%e3%83123%84%e3123%82%a4123%e3%83123%b3%e3123%82%bd123">>)
	).
-endif.

%% @doc Percent encode a string. (RFC3986 2.1)
%%
%% This function is meant to be used for path components.

-spec urlencode(B) -> B when B::binary().
urlencode(B) ->
	urlencode(B, <<>>).

urlencode(<< $!, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $! >>);
urlencode(<< $$, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $$ >>);
urlencode(<< $&, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $& >>);
urlencode(<< $', Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $' >>);
urlencode(<< $(, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $( >>);
urlencode(<< $), Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $) >>);
urlencode(<< $*, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $* >>);
urlencode(<< $+, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $+ >>);
urlencode(<< $,, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $, >>);
urlencode(<< $-, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $- >>);
urlencode(<< $., Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $. >>);
urlencode(<< $0, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $0 >>);
urlencode(<< $1, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $1 >>);
urlencode(<< $2, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $2 >>);
urlencode(<< $3, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $3 >>);
urlencode(<< $4, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $4 >>);
urlencode(<< $5, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $5 >>);
urlencode(<< $6, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $6 >>);
urlencode(<< $7, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $7 >>);
urlencode(<< $8, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $8 >>);
urlencode(<< $9, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $9 >>);
urlencode(<< $:, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $: >>);
urlencode(<< $;, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $; >>);
urlencode(<< $=, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $= >>);
urlencode(<< $@, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $@ >>);
urlencode(<< $A, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $A >>);
urlencode(<< $B, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $B >>);
urlencode(<< $C, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $C >>);
urlencode(<< $D, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $D >>);
urlencode(<< $E, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $E >>);
urlencode(<< $F, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $F >>);
urlencode(<< $G, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $G >>);
urlencode(<< $H, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $H >>);
urlencode(<< $I, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $I >>);
urlencode(<< $J, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $J >>);
urlencode(<< $K, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $K >>);
urlencode(<< $L, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $L >>);
urlencode(<< $M, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $M >>);
urlencode(<< $N, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $N >>);
urlencode(<< $O, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $O >>);
urlencode(<< $P, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $P >>);
urlencode(<< $Q, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $Q >>);
urlencode(<< $R, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $R >>);
urlencode(<< $S, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $S >>);
urlencode(<< $T, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $T >>);
urlencode(<< $U, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $U >>);
urlencode(<< $V, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $V >>);
urlencode(<< $W, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $W >>);
urlencode(<< $X, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $X >>);
urlencode(<< $Y, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $Y >>);
urlencode(<< $Z, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $Z >>);
urlencode(<< $_, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $_ >>);
urlencode(<< $a, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $a >>);
urlencode(<< $b, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $b >>);
urlencode(<< $c, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $c >>);
urlencode(<< $d, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $d >>);
urlencode(<< $e, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $e >>);
urlencode(<< $f, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $f >>);
urlencode(<< $g, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $g >>);
urlencode(<< $h, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $h >>);
urlencode(<< $i, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $i >>);
urlencode(<< $j, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $j >>);
urlencode(<< $k, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $k >>);
urlencode(<< $l, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $l >>);
urlencode(<< $m, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $m >>);
urlencode(<< $n, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $n >>);
urlencode(<< $o, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $o >>);
urlencode(<< $p, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $p >>);
urlencode(<< $q, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $q >>);
urlencode(<< $r, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $r >>);
urlencode(<< $s, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $s >>);
urlencode(<< $t, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $t >>);
urlencode(<< $u, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $u >>);
urlencode(<< $v, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $v >>);
urlencode(<< $w, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $w >>);
urlencode(<< $x, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $x >>);
urlencode(<< $y, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $y >>);
urlencode(<< $z, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $z >>);
urlencode(<< $~, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $~ >>);
urlencode(<< C, Rest/bits >>, Acc) ->
	H = hex(C bsr 4),
	L = hex(C band 16#0f),
	urlencode(Rest, << Acc/bits, $%, H, L >>);
urlencode(<<>>, Acc) ->
	Acc.

hex( 0) -> $0;
hex( 1) -> $1;
hex( 2) -> $2;
hex( 3) -> $3;
hex( 4) -> $4;
hex( 5) -> $5;
hex( 6) -> $6;
hex( 7) -> $7;
hex( 8) -> $8;
hex( 9) -> $9;
hex(10) -> $A;
hex(11) -> $B;
hex(12) -> $C;
hex(13) -> $D;
hex(14) -> $E;
hex(15) -> $F.

-ifdef(TEST).
urlencode_test_() ->
	Tests = [
		{<<255, 0>>, <<"%FF%00">>},
		{<<255, " ">>, <<"%FF%20">>},
		{<<"+">>, <<"+">>},
		{<<"aBc123">>, <<"aBc123">>},
		{<<"!$&'()*+,:;=@-._~">>, <<"!$&'()*+,:;=@-._~">>}
	],
	[{V, fun() -> E = urlencode(V) end} || {V, E} <- Tests].

urlencode_identity_test_() ->
	Tests = [
		<<"+">>,
		<<"nothingnothingnothingnothing">>,
		<<"Small fast modular HTTP server">>,
		<<"Small, fast, modular HTTP server.">>,
		<<227,131,132,227,130,164,227,131,179,227,130,189,227,
			130,166,227,131,171,227,128,156,232,188,170,229,187,187,227,
			129,153,227,130,139,230,151,139,229,190,139,227,128,156>>
	],
	[{V, fun() -> V = urldecode(urlencode(V)) end} || V <- Tests].

horse_urlencode() ->
	horse:repeat(100000,
		urlencode(<<"nothingnothingnothingnothing">>)
	).

horse_urlencode_spaces() ->
	horse:repeat(100000,
		urlencode(<<"Small fast modular HTTP server">>)
	).

horse_urlencode_jp() ->
	horse:repeat(100000,
		urlencode(<<227,131,132,227,130,164,227,131,179,227,130,189,227,
			130,166,227,131,171,227,128,156,232,188,170,229,187,187,227,
			129,153,227,130,139,230,151,139,229,190,139,227,128,156>>)
	).

horse_urlencode_mix() ->
	horse:repeat(100000,
		urlencode(<<"Small, fast, modular HTTP server.">>)
	).
-endif.
