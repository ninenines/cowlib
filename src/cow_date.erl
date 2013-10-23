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

-module(cow_date).

-export([rfc2109/1]).

%% @doc Return the date formatted according to RFC2109.

-spec rfc2109(calendar:datetime()) -> binary().
rfc2109({Date = {Y, Mo, D}, {H, Mi, S}}) ->
	Wday = calendar:day_of_the_week(Date),
	<< (weekday(Wday))/binary, ", ", (pad_int(D))/binary, "-",
		(month(Mo))/binary, "-", (list_to_binary(integer_to_list(Y)))/binary,
		" ", (pad_int(H))/binary, $:, (pad_int(Mi))/binary,
		$:, (pad_int(S))/binary, " GMT" >>.

-ifdef(TEST).
rfc2109_test_() ->
	Tests = [
		{<<"Sat, 14-May-2011 14:25:33 GMT">>, {{2011, 5, 14}, {14, 25, 33}}},
		{<<"Sun, 01-Jan-2012 00:00:00 GMT">>, {{2012, 1,  1}, { 0,  0,  0}}}
	],
	[{R, fun() -> R = rfc2109(D) end} || {R, D} <- Tests].
-endif.

%% Internal.

-spec pad_int(0..59) -> binary().
pad_int(X) when X < 10 ->
	<< $0, ($0 + X) >>;
pad_int(X) ->
	list_to_binary(integer_to_list(X)).

-spec weekday(1..7) -> <<_:24>>.
weekday(1) -> <<"Mon">>;
weekday(2) -> <<"Tue">>;
weekday(3) -> <<"Wed">>;
weekday(4) -> <<"Thu">>;
weekday(5) -> <<"Fri">>;
weekday(6) -> <<"Sat">>;
weekday(7) -> <<"Sun">>.

-spec month(1..12) -> <<_:24>>.
month( 1) -> <<"Jan">>;
month( 2) -> <<"Feb">>;
month( 3) -> <<"Mar">>;
month( 4) -> <<"Apr">>;
month( 5) -> <<"May">>;
month( 6) -> <<"Jun">>;
month( 7) -> <<"Jul">>;
month( 8) -> <<"Aug">>;
month( 9) -> <<"Sep">>;
month(10) -> <<"Oct">>;
month(11) -> <<"Nov">>;
month(12) -> <<"Dec">>.
