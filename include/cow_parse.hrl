%% Copyright (c) 2015, Loïc Hoguin <essen@ninenines.eu>
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

-ifndef(COW_PARSE_HRL).
-define(COW_PARSE_HRL, 1).

-define(IS_ALPHA(C),
	C =:= $a orelse C =:= $b orelse C =:= $c orelse C =:= $d orelse C =:= $e orelse
	C =:= $f orelse C =:= $g orelse C =:= $h orelse C =:= $i orelse C =:= $j orelse
	C =:= $k orelse C =:= $l orelse C =:= $m orelse C =:= $n orelse C =:= $o orelse
	C =:= $p orelse C =:= $q orelse C =:= $r orelse C =:= $s orelse C =:= $t orelse
	C =:= $u orelse C =:= $v orelse C =:= $w orelse C =:= $x orelse C =:= $y orelse
	C =:= $z orelse
	C =:= $A orelse C =:= $B orelse C =:= $C orelse C =:= $D orelse C =:= $E orelse
	C =:= $F orelse C =:= $G orelse C =:= $H orelse C =:= $I orelse C =:= $J orelse
	C =:= $K orelse C =:= $L orelse C =:= $M orelse C =:= $N orelse C =:= $O orelse
	C =:= $P orelse C =:= $Q orelse C =:= $R orelse C =:= $S orelse C =:= $T orelse
	C =:= $U orelse C =:= $V orelse C =:= $W orelse C =:= $X orelse C =:= $Y orelse
	C =:= $Z
).

-define(IS_ALPHANUM(C), ?IS_ALPHA(C) orelse ?IS_DIGIT(C)).
-define(IS_CHAR(C), C > 0, C < 128).

-define(IS_DIGIT(C),
	C =:= $0 orelse C =:= $1 orelse C =:= $2 orelse C =:= $3 orelse C =:= $4 orelse
	C =:= $5 orelse C =:= $6 orelse C =:= $7 orelse C =:= $8 orelse C =:= $9).

-define(IS_ETAGC(C), C =:= 16#21; C >= 16#23, C =/= 16#7f).

-define(IS_HEX(C),
	?IS_DIGIT(C) orelse
	C =:= $a orelse C =:= $b orelse C =:= $c orelse
	C =:= $d orelse C =:= $e orelse C =:= $f orelse
	C =:= $A orelse C =:= $B orelse C =:= $C orelse
	C =:= $D orelse C =:= $E orelse C =:= $F).

-define(IS_LHEX(C),
	?IS_DIGIT(C) orelse
	C =:= $a orelse C =:= $b orelse C =:= $c orelse
	C =:= $d orelse C =:= $e orelse C =:= $f).

-define(IS_TOKEN(C),
	?IS_ALPHA(C) orelse ?IS_DIGIT(C)
	orelse C =:= $! orelse C =:= $# orelse C =:= $$ orelse C =:= $% orelse C =:= $&
	orelse C =:= $' orelse C =:= $* orelse C =:= $+ orelse C =:= $- orelse C =:= $.
	orelse C =:= $^ orelse C =:= $_ orelse C =:= $` orelse C =:= $| orelse C =:= $~).

-define(IS_TOKEN68(C),
	?IS_ALPHA(C) orelse ?IS_DIGIT(C) orelse
		C =:= $- orelse C =:= $. orelse C =:= $_ orelse
		C =:= $~ orelse C =:= $+ orelse C =:= $/).

-define(IS_URI_UNRESERVED(C),
	?IS_ALPHA(C) orelse ?IS_DIGIT(C) orelse
	C =:= $- orelse C =:= $. orelse C =:= $_ orelse C =:= $~).

-define(IS_URI_SUB_DELIMS(C),
	C =:= $! orelse C =:= $$ orelse C =:= $& orelse C =:= $' orelse
	C =:= $( orelse C =:= $) orelse C =:= $* orelse C =:= $+ orelse
	C =:= $, orelse C =:= $; orelse C =:= $=).

-define(IS_VCHAR(C), C =:= $\t; C > 31, C < 127).
-define(IS_VCHAR_OBS(C), C =:= $\t; C > 31, C =/= 127).
-define(IS_WS(C), C =:= $\s orelse C =:= $\t).
-define(IS_WS_COMMA(C), ?IS_WS(C) orelse C =:= $,).

-endif.
