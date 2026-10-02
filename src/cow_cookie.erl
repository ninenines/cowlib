%% Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

-module(cow_cookie).

-export([parse_cookie/1]).
-export([parse_cookie/2]).
-export([parse_set_cookie/1]).
-export([cookie/1]).
-export([setcookie/3]).

-type cookie_attrs() :: #{
	expires => calendar:datetime(),
	max_age => calendar:datetime(),
	domain => binary(),
	path => binary(),
	secure => true,
	http_only => true,
	same_site => default | none | strict | lax
}.
-export_type([cookie_attrs/0]).

-type cookie_opts() :: #{
	domain => binary(),
	http_only => boolean(),
	max_age => non_neg_integer(),
	path => binary(),
	same_site => default | none | strict | lax,
	secure => boolean()
}.
-export_type([cookie_opts/0]).

-type parse_opts() :: #{max_cookies => non_neg_integer()}.
-export_type([parse_opts/0]).

-include("cow_inline.hrl").
-include("cow_parse.hrl").

%% RFC6265bis 5.6. Name plus value, after trimming.
-define(MAX_COOKIE_OCTETS, 4096).
%% RFC6265bis 5.5. Recommended maximum cookie lifetime.
-define(MAX_COOKIE_AGE, 34560000).

%% cookie-octet, excluding CTLs, whitespace, DQUOTE, comma, semicolon
%% and backslash.
-define(IS_COOKIE_OCTET(C),
	(C =:= 16#21) orelse
	(C >= 16#23 andalso C =< 16#2B) orelse
	(C >= 16#2D andalso C =< 16#3A) orelse
	(C >= 16#3C andalso C =< 16#5B) orelse
	(C >= 16#5D andalso C =< 16#7E)).

%% av-octet: any CHAR except CTLs or ";".
-define(IS_AV_OCTET(C),
	(C >= 16#20 andalso C =< 16#3A) orelse
	(C >= 16#3C andalso C =< 16#7E)).

-ifdef(TEST).
-include_lib("stdlib/include/assert.hrl").
-endif.

%% Cookie header.

-spec parse_cookie(binary()) -> [{binary(), binary()}].
parse_cookie(Cookie) ->
	parse_cookie(Cookie, #{}).

-spec parse_cookie(binary(), parse_opts()) -> [{binary(), binary()}].
parse_cookie(Cookie, Opts) ->
	Max = maps:get(max_cookies, Opts, 100),
	parse_cookie(Cookie, [], Max).

parse_cookie(<<>>, Acc, _) ->
	lists:reverse(Acc);
parse_cookie(<< $\s, Rest/binary >>, Acc, Max) ->
	parse_cookie(Rest, Acc, Max);
parse_cookie(<< $\t, Rest/binary >>, Acc, Max) ->
	parse_cookie(Rest, Acc, Max);
parse_cookie(<< $,, Rest/binary >>, Acc, Max) ->
	parse_cookie(Rest, Acc, Max);
parse_cookie(<< $;, Rest/binary >>, Acc, Max) ->
	parse_cookie(Rest, Acc, Max);
parse_cookie(_, Acc, Max) when length(Acc) =:= Max ->
	error(limit_reached);
parse_cookie(Cookie, Acc, Max) ->
	parse_cookie_name(Cookie, Acc, <<>>, Max).

parse_cookie_name(<<>>, Acc, Name, _) ->
	lists:reverse([{<<>>, parse_cookie_trim(Name)}|Acc]);
parse_cookie_name(<< $=, _/binary >>, _, <<>>, _) ->
	error(badarg);
parse_cookie_name(<< $=, Rest/binary >>, Acc, Name, Max) ->
	parse_cookie_value(Rest, Acc, Name, <<>>, Max);
parse_cookie_name(<< $,, _/binary >>, _, _, _) ->
	error(badarg);
parse_cookie_name(<< $;, Rest/binary >>, Acc, Name, Max) ->
	parse_cookie(Rest, [{<<>>, parse_cookie_trim(Name)}|Acc], Max);
parse_cookie_name(<< C, _/binary >>, _, _, _) when C < 32; C =:= 127 ->
	error(badarg);
parse_cookie_name(<< C, Rest/binary >>, Acc, Name, Max) ->
	parse_cookie_name(Rest, Acc, << Name/binary, C >>, Max).

parse_cookie_value(<<>>, Acc, Name, Value, _) ->
	lists:reverse([{Name, parse_cookie_trim(Value)}|Acc]);
parse_cookie_value(<< $;, Rest/binary >>, Acc, Name, Value, Max) ->
	parse_cookie(Rest, [{Name, parse_cookie_trim(Value)}|Acc], Max);
parse_cookie_value(<< C, _/binary >>, _, _, _, _) when C < 32; C =:= 127 ->
	error(badarg);
parse_cookie_value(<< C, Rest/binary >>, Acc, Name, Value, Max) ->
	parse_cookie_value(Rest, Acc, Name, << Value/binary, C >>, Max).

parse_cookie_trim(Value = <<>>) ->
	Value;
parse_cookie_trim(Value) ->
	case binary:last(Value) of
		$\s ->
			Size = byte_size(Value) - 1,
			<< Value2:Size/binary, _ >> = Value,
			parse_cookie_trim(Value2);
		_ ->
			Value
	end.

-ifdef(TEST).
parse_cookie_test_() ->
	%% {Value, Result}.
	Tests = [
		{<<"name=value; name2=value2">>, [
			{<<"name">>, <<"value">>},
			{<<"name2">>, <<"value2">>}
		]},
		%% Space in value.
		{<<"foo=Thu Jul 11 2013 15:38:43 GMT+0400 (MSK)">>,
			[{<<"foo">>, <<"Thu Jul 11 2013 15:38:43 GMT+0400 (MSK)">>}]},
		%% Comma in value. Google Analytics sets that kind of cookies.
		{<<"refk=sOUZDzq2w2; sk=B602064E0139D842D620C7569640DBB4C81C45080651"
			"9CC124EF794863E10E80; __utma=64249653.825741573.1380181332.1400"
			"015657.1400019557.703; __utmb=64249653.1.10.1400019557; __utmc="
			"64249653; __utmz=64249653.1400019557.703.13.utmcsr=bluesky.chic"
			"agotribune.com|utmccn=(referral)|utmcmd=referral|utmcct=/origin"
			"als/chi-12-indispensable-digital-tools-bsi,0,0.storygallery">>, [
				{<<"refk">>, <<"sOUZDzq2w2">>},
				{<<"sk">>, <<"B602064E0139D842D620C7569640DBB4C81C45080651"
					"9CC124EF794863E10E80">>},
				{<<"__utma">>, <<"64249653.825741573.1380181332.1400"
					"015657.1400019557.703">>},
				{<<"__utmb">>, <<"64249653.1.10.1400019557">>},
				{<<"__utmc">>, <<"64249653">>},
				{<<"__utmz">>, <<"64249653.1400019557.703.13.utmcsr=bluesky.chic"
					"agotribune.com|utmccn=(referral)|utmcmd=referral|utmcct=/origin"
					"als/chi-12-indispensable-digital-tools-bsi,0,0.storygallery">>}
		]},
		%% Potential edge cases (initially from Mochiweb).
		{<<"foo=\\x">>, [{<<"foo">>, <<"\\x">>}]},
		{<<"foo=;bar=">>, [{<<"foo">>, <<>>}, {<<"bar">>, <<>>}]},
		{<<"foo=\\\";;bar=good ">>,
			[{<<"foo">>, <<"\\\"">>}, {<<"bar">>, <<"good">>}]},
		{<<"foo=\"\\\";bar=good">>,
			[{<<"foo">>, <<"\"\\\"">>}, {<<"bar">>, <<"good">>}]},
		{<<>>, []}, %% Flash player.
		{<<"foo=bar , baz=wibble ">>, [{<<"foo">>, <<"bar , baz=wibble">>}]},
		%% Technically invalid, but seen in the wild
		{<<"foo">>, [{<<>>, <<"foo">>}]},
		{<<"foo ">>, [{<<>>, <<"foo">>}]},
		{<<"foo;">>, [{<<>>, <<"foo">>}]},
		{<<"bar;foo=1">>, [{<<>>, <<"bar">>}, {<<"foo">>, <<"1">>}]}
	],
	[{V, fun() -> R = parse_cookie(V) end} || {V, R} <- Tests].

parse_cookie_error_test_() ->
	%% Value.
	Tests = [
		<<"=">>
	],
	[{V, fun() -> ?assertError(badarg, parse_cookie(V)) end} || V <- Tests].

%% Every CTL, including those previously accepted, is rejected inside
%% a name or a value. Leading tab is still a separator.
parse_cookie_ctl_test_() ->
	Ctl = lists:seq(0, 31) ++ [127],
	Inside = [{<<C>>, fun() ->
		?assertError(badarg, parse_cookie(<<"a=", C>>)),
		?assertError(badarg, parse_cookie(<<C, "=b">>))
	end} || C <- Ctl],
	Edges = [
		{<<"space in value">>, fun() ->
			[{<<"a">>, <<"b c">>}] = parse_cookie(<<"a=b c">>)
		end},
		{<<"tilde">>, fun() ->
			[{<<"a">>, <<"~">>}] = parse_cookie(<<"a=~">>)
		end},
		{<<"leading tab">>, fun() ->
			[{<<"a">>, <<"b">>}] = parse_cookie(<<$\t, "a=b">>)
		end},
		{<<"tab inside name">>, fun() ->
			?assertError(badarg, parse_cookie(<<"a", $\t, "=b">>))
		end}
	],
	Inside ++ Edges.

parse_cookie_max_cookies_test() ->
	Pair = <<"a=b">>,
	%% 100 pairs accepted by default.
	OK = iolist_to_binary(lists:join(<<"; ">>, lists:duplicate(100, Pair))),
	Cookies = parse_cookie(OK),
	100 = length(Cookies),
	%% 101st pair is rejected.
	Over = iolist_to_binary([OK, <<"; ">>, Pair]),
	?assertError(limit_reached, parse_cookie(Over)),
	%% Custom limit: at most N pairs; exceeding errors (no truncation).
	[{<<"a">>, <<"b">>}] = parse_cookie(Pair, #{max_cookies => 1}),
	Two = <<Pair/binary, "; ", Pair/binary>>,
	?assertError(limit_reached, parse_cookie(Two, #{max_cookies => 1})),
	?assertError(limit_reached, parse_cookie(Pair, #{max_cookies => 0})),
	ok.
-endif.

%% Set-Cookie header.

-spec parse_set_cookie(binary())
	-> {ok, binary(), binary(), cookie_attrs()}
	| ignore.
parse_set_cookie(SetCookie) ->
	case has_non_ws_ctl(SetCookie) of
		true ->
			ignore;
		false ->
			{NameValuePair, UnparsedAttrs} = take_until_semicolon(SetCookie, <<>>),
			{Name, Value} = case binary:split(NameValuePair, <<$=>>) of
				[Value0] -> {<<>>, trim(Value0)};
				[Name0, Value0] -> {trim(Name0), trim(Value0)}
			end,
			case {Name, Value} of
				{<<>>, <<>>} ->
					ignore;
				_ when byte_size(Name) + byte_size(Value) > ?MAX_COOKIE_OCTETS ->
					ignore;
				_ ->
					Attrs = parse_set_cookie_attrs(UnparsedAttrs, #{}),
					{ok, Name, Value, Attrs}
			end
	end.

has_non_ws_ctl(<<>>) ->
	false;
has_non_ws_ctl(<<C,R/bits>>) ->
	if
		C =< 16#08 -> true;
		C >= 16#0A, C =< 16#1F -> true;
		C =:= 16#7F -> true;
		true -> has_non_ws_ctl(R)
	end.

parse_set_cookie_attrs(<<>>, Attrs) ->
	Attrs;
parse_set_cookie_attrs(<<$;,Rest0/bits>>, Attrs) ->
	{Av, Rest} = take_until_semicolon(Rest0, <<>>),
	{Name, Value} = case binary:split(Av, <<$=>>) of
		[Name0] -> {trim(Name0), <<>>};
		[Name0, Value0] -> {trim(Name0), trim(Value0)}
	end,
	if
		byte_size(Value) > 1024 ->
			parse_set_cookie_attrs(Rest, Attrs);
		true ->
			case parse_set_cookie_attr(?LOWER(Name), Value) of
				{ok, AttrName, AttrValue} ->
					parse_set_cookie_attrs(Rest, Attrs#{AttrName => AttrValue});
				{ignore, AttrName} ->
					parse_set_cookie_attrs(Rest, maps:remove(AttrName, Attrs));
				ignore ->
					parse_set_cookie_attrs(Rest, Attrs)
			end
	end.

take_until_semicolon(Rest = <<$;,_/bits>>, Acc) -> {Acc, Rest};
take_until_semicolon(<<C,R/bits>>, Acc) -> take_until_semicolon(R, <<Acc/binary,C>>);
take_until_semicolon(<<>>, Acc) -> {Acc, <<>>}.

trim(String) ->
	string:trim(String, both, [$\s, $\t]).

parse_set_cookie_attr(<<"expires">>, Value) ->
	try cow_date:parse_date(Value) of
		DateTime ->
			{ok, expires, cap_cookie_expiry(DateTime)}
	catch _:_ ->
		ignore
	end;
parse_set_cookie_attr(<<"max-age">>, Value = <<C, _/bits>>) when ?IS_DIGIT(C); C =:= $- ->
	try binary_to_integer(Value) of
		MaxAge when MaxAge =< 0 ->
			%% Year 0 corresponds to 1 BC.
			{ok, max_age, {{0, 1, 1}, {0, 0, 0}}};
		MaxAge ->
			CurrentTime = erlang:universaltime(),
			{ok, max_age, calendar:gregorian_seconds_to_datetime(
				calendar:datetime_to_gregorian_seconds(CurrentTime)
				+ min(MaxAge, ?MAX_COOKIE_AGE))}
	catch _:_ ->
		ignore
	end;
parse_set_cookie_attr(<<"domain">>, Value) ->
	case Value of
		<<>> ->
			ignore;
		<<".",Rest/bits>> ->
			{ok, domain, ?LOWER(Rest)};
		_ ->
			{ok, domain, ?LOWER(Value)}
	end;
parse_set_cookie_attr(<<"path">>, Value) ->
	case Value of
		<<"/",_/bits>> ->
			{ok, path, Value};
		%% When the path is not absolute, or the path is empty, the default-path will be used.
		%% Note that the default-path is also used when there are no path attributes,
		%% so we are simply ignoring the attribute here.
		_ ->
			{ignore, path}
	end;
parse_set_cookie_attr(<<"secure">>, _) ->
	{ok, secure, true};
parse_set_cookie_attr(<<"httponly">>, _) ->
	{ok, http_only, true};
parse_set_cookie_attr(<<"samesite">>, Value) ->
	case ?LOWER(Value) of
		<<"none">> ->
			{ok, same_site, none};
		<<"strict">> ->
			{ok, same_site, strict};
		<<"lax">> ->
			{ok, same_site, lax};
		%% Unknown values and lack of value are equivalent.
		_ ->
			{ok, same_site, default}
	end;
parse_set_cookie_attr(_, _) ->
	ignore.

%% Expiry more than 400 days out is reduced to 400 days.
cap_cookie_expiry(DateTime) ->
	Now = erlang:universaltime(),
	Limit = calendar:gregorian_seconds_to_datetime(
		calendar:datetime_to_gregorian_seconds(Now) + ?MAX_COOKIE_AGE),
	case DateTime > Limit of
		true -> Limit;
		false -> DateTime
	end.

-ifdef(TEST).
parse_set_cookie_test_() ->
	Tests = [
		{<<"a=b">>, {ok, <<"a">>, <<"b">>, #{}}},
		{<<"a=b; Secure">>, {ok, <<"a">>, <<"b">>, #{secure => true}}},
		{<<"a=b; HttpOnly">>, {ok, <<"a">>, <<"b">>, #{http_only => true}}},
		{<<"a=b; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Expires=Wed, 21 Oct 2015 07:29:00 GMT">>,
			{ok, <<"a">>, <<"b">>, #{expires => {{2015,10,21},{7,29,0}}}}},
		{<<"a=b; Max-Age=999; Max-Age=0">>,
			{ok, <<"a">>, <<"b">>, #{max_age => {{0,1,1},{0,0,0}}}}},
		{<<"a=b; Domain=example.org; Domain=foo.example.org">>,
			{ok, <<"a">>, <<"b">>, #{domain => <<"foo.example.org">>}}},
		{<<"a=b; Path=/path/to/resource; Path=/">>,
			{ok, <<"a">>, <<"b">>, #{path => <<"/">>}}},
		{<<"a=b; SameSite=UnknownValue">>, {ok, <<"a">>, <<"b">>, #{same_site => default}}},
		{<<"a=b; SameSite=None">>, {ok, <<"a">>, <<"b">>, #{same_site => none}}},
		{<<"a=b; SameSite=Lax">>, {ok, <<"a">>, <<"b">>, #{same_site => lax}}},
		{<<"a=b; SameSite=Strict">>, {ok, <<"a">>, <<"b">>, #{same_site => strict}}},
		{<<"a=b; SameSite=Lax; SameSite=Strict">>,
			{ok, <<"a">>, <<"b">>, #{same_site => strict}}},
		{<<"a=b; Max-Age=-123">>,
			{ok, <<"a">>, <<"b">>, #{max_age => {{0,1,1},{0,0,0}}}}},
		{<<"a=b; Max-Age=-0">>,
			{ok, <<"a">>, <<"b">>, #{max_age => {{0,1,1},{0,0,0}}}}},
		{<<"a=b; Max-Age=+0">>, {ok, <<"a">>, <<"b">>, #{}}},
		{<<"a=b; Max-Age=+123">>, {ok, <<"a">>, <<"b">>, #{}}}
	],
	[{SetCookie, fun() -> Res = parse_set_cookie(SetCookie) end}
		|| {SetCookie, Res} <- Tests].

parse_set_cookie_size_test() ->
	A4096 = binary:copy(<<"a">>, 4096),
	A4097 = binary:copy(<<"a">>, 4097),
	B4095 = binary:copy(<<"b">>, 4095),
	B4096 = binary:copy(<<"b">>, 4096),
	{ok, A4096, <<>>, #{}} = parse_set_cookie(<<A4096/binary, "=">>),
	{ok, <<>>, A4096, #{}} = parse_set_cookie(A4096),
	{ok, <<"a">>, B4095, #{}} = parse_set_cookie(<<"a=", B4095/binary>>),
	ignore = parse_set_cookie(<<A4097/binary, "=">>),
	ignore = parse_set_cookie(A4097),
	ignore = parse_set_cookie(<<"a=", B4096/binary>>),
	%% Trimmed whitespace does not count toward the limit.
	{ok, A4096, <<>>, #{}} = parse_set_cookie(<<$\s, A4096/binary, $=, $\s>>),
	ignore = parse_set_cookie(<<$\s, A4097/binary>>),
	ok.

parse_set_cookie_age_limit_test() ->
	Before = erlang:universaltime(),
	{ok, <<"a">>, <<"b">>, #{max_age := AtLimit}} =
		parse_set_cookie(<<"a=b; Max-Age=",
			(integer_to_binary(?MAX_COOKIE_AGE))/binary>>),
	{ok, <<"a">>, <<"b">>, #{max_age := Over}} =
		parse_set_cookie(<<"a=b; Max-Age=",
			(integer_to_binary(?MAX_COOKIE_AGE + 1))/binary>>),
	{ok, <<"a">>, <<"b">>, #{max_age := Huge}} =
		parse_set_cookie(<<"a=b; Max-Age=",
			(integer_to_binary(?MAX_COOKIE_AGE * 10))/binary>>),
	After = erlang:universaltime(),
	true = expiry_in_window(AtLimit, Before, After),
	true = expiry_in_window(Over, Before, After),
	true = expiry_in_window(Huge, Before, After),
	%% A date inside the window is kept. A date past it is reduced.
	Near = calendar:gregorian_seconds_to_datetime(
		calendar:datetime_to_gregorian_seconds(erlang:universaltime()) + 86400),
	Far = calendar:gregorian_seconds_to_datetime(
		calendar:datetime_to_gregorian_seconds(erlang:universaltime())
		+ ?MAX_COOKIE_AGE + 86400 * 10),
	NearBin = cow_date:rfc1123(Near),
	FarBin = cow_date:rfc1123(Far),
	{ok, <<"a">>, <<"b">>, #{expires := Near}} =
		parse_set_cookie(<<"a=b; Expires=", NearBin/binary>>),
	Before2 = erlang:universaltime(),
	{ok, <<"a">>, <<"b">>, #{expires := Capped}} =
		parse_set_cookie(<<"a=b; Expires=", FarBin/binary>>),
	After2 = erlang:universaltime(),
	true = expiry_in_window(Capped, Before2, After2),
	false = Capped =:= Far,
	ok.

expiry_in_window(Got, Before, After) ->
	GotSecs = calendar:datetime_to_gregorian_seconds(Got),
	Low = calendar:datetime_to_gregorian_seconds(Before) + ?MAX_COOKIE_AGE,
	High = calendar:datetime_to_gregorian_seconds(After) + ?MAX_COOKIE_AGE,
	GotSecs >= Low andalso GotSecs =< High.
-endif.

%% Build a cookie header.

-spec cookie([{iodata(), iodata()}]) -> iolist().
cookie([]) ->
	[];
cookie([{<<>>, Value}]) ->
	[cookie_chars(Value, value)];
cookie([{Name, Value}]) ->
	[cookie_chars(Name, name), $=, cookie_chars(Value, value)];
cookie([{<<>>, Value}|Tail]) ->
	[cookie_chars(Value, value), $;, $\s|cookie(Tail)];
cookie([{Name, Value}|Tail]) ->
	[cookie_chars(Name, name), $=, cookie_chars(Value, value), $;, $\s|cookie(Tail)].

%% Echo stored octets, including those outside cookie-octet.
%% A semicolon or an '=' in the name makes the pair ambiguous.
%% Controls other than tab are not valid in a header value.
cookie_chars(Chars, Kind) ->
	Bin = iolist_to_binary(Chars),
	ok = validate_cookie_chars(Bin, Kind),
	Bin.

validate_cookie_chars(<<>>, _) ->
	ok;
validate_cookie_chars(<<C, _/bits>>, _)
		when C < 32, C =/= $\t; C =:= 127; C =:= $; ->
	error(badarg);
validate_cookie_chars(<<$=, _/bits>>, name) ->
	error(badarg);
validate_cookie_chars(<<_, R/bits>>, Kind) ->
	validate_cookie_chars(R, Kind).

-ifdef(TEST).
cookie_test_() ->
	Tests = [
		{[], <<>>},
		{[{<<"a">>, <<"b">>}], <<"a=b">>},
		{[{<<"a">>, <<"b">>}, {<<"c">>, <<"d">>}], <<"a=b; c=d">>},
		{[{<<>>, <<"b">>}, {<<"c">>, <<"d">>}], <<"b; c=d">>},
		{[{<<"a">>, <<"b">>}, {<<>>, <<"d">>}], <<"a=b; d">>},
		%% Octets outside cookie-octet are echoed.
		{[{<<"a">>, <<"b c">>}], <<"a=b c">>},
		{[{<<"a">>, <<"b,c">>}], <<"a=b,c">>},
		{[{<<"a b">>, <<"c">>}], <<"a b=c">>},
		{[{<<"a">>, <<"\"b\"">>}], <<"a=\"b\"">>},
		{[{[<<"a">>], [<<"b">>, <<"c">>]}], <<"a=bc">>}
	],
	[{Res, fun() -> Res = iolist_to_binary(cookie(Cookies)) end}
		|| {Cookies, Res} <- Tests].

%% A semicolon or '=' in the name makes the pair ambiguous.
%% Controls other than tab are not valid in a header value.
cookie_error_test_() ->
	Tests = [
		[{<<"a">>, <<"b;c">>}],
		[{<<"a;b">>, <<"c">>}],
		[{<<>>, <<"a;b">>}],
		[{<<"a">>, <<"b">>}, {<<"c">>, <<"d;e">>}],
		[{[<<"a;">>], <<"b">>}],
		[{<<"a">>, <<"b\r\nX: y">>}],
		[{<<"a\n">>, <<"b">>}],
		[{<<"a\r">>, <<"b">>}],
		[{<<>>, <<"b\n">>}],
		[{<<"a">>, <<0>>}],
		[{<<1>>, <<"b">>}],
		[{<<"a">>, <<31>>}],
		[{<<"a">>, <<127>>}],
		[{<<"a=b">>, <<"c">>}],
		[{[<<"a">>, <<$\n>>], <<"b">>}]
	],
	[{iolist_to_binary(io_lib:format("~p failure", [V])),
		fun() -> ?assertError(_, cookie(V)) end} || V <- Tests].

cookie_header_safe_test_() ->
	Tests = [
		{[{<<"a">>, <<"b\tc">>}], <<"a=b\tc">>},
		{[{<<"a">>, <<"b=c">>}], <<"a=b=c">>},
		{[{<<>>, <<"test=2">>}], <<"test=2">>},
		{[{<<"a">>, <<128>>}], <<"a=", 128>>},
		{[{<<"a">>, <<195, 169>>}], <<"a=", 195, 169>>}
	],
	[{R, fun() -> R = iolist_to_binary(cookie(V)) end} || {V, R} <- Tests].
-endif.

%% Convert a cookie name, value and options to its iodata form.
%%
%% Initially from Mochiweb:
%%   * Copyright 2007 Mochi Media, Inc.
%% Initial binary implementation:
%%   * Copyright 2011 Thomas Burdick <thomas.burdick@gmail.com>
%%
%% @todo Cowlib 3.0: rename to set_cookie/3.

-spec setcookie(iodata(), iodata(), cookie_opts()) -> iolist().
setcookie(Name0, Value0, Opts) ->
	Name = iolist_to_binary(Name0),
	Value = iolist_to_binary(Value0),
	validate_cookie_name(Name),
	validate_cookie_value(Value),
	[Name, <<"=">>, Value, attributes(maps:to_list(Opts))].

validate_cookie_name(<<>>) ->
	error(badarg);
validate_cookie_name(Name) ->
	validate_token(Name).

validate_token(<<>>) ->
	ok;
validate_token(<<C, R/bits>>) when ?IS_TOKEN(C) ->
	validate_token(R).

%% cookie-value is *cookie-octet or a quoted run of cookie-octets.
%% The quotes are part of the value.
validate_cookie_value(<<$", R/bits>>) ->
	validate_quoted_cookie_value(R);
validate_cookie_value(Value) ->
	validate_cookie_octets(Value).

validate_quoted_cookie_value(<<$">>) ->
	ok;
validate_quoted_cookie_value(<<C, R/bits>>) when ?IS_COOKIE_OCTET(C) ->
	validate_quoted_cookie_value(R).

validate_cookie_octets(<<>>) ->
	ok;
validate_cookie_octets(<<C, R/bits>>) when ?IS_COOKIE_OCTET(C) ->
	validate_cookie_octets(R).

validate_av_octets(<<>>) ->
	ok;
validate_av_octets(<<C, R/bits>>) when ?IS_AV_OCTET(C) ->
	validate_av_octets(R).

attributes([]) -> [];
attributes([{domain, Domain0}|Tail]) ->
	Domain = iolist_to_binary(Domain0),
	validate_av_octets(Domain),
	[<<"; Domain=">>, Domain|attributes(Tail)];
attributes([{http_only, false}|Tail]) -> attributes(Tail);
attributes([{http_only, true}|Tail]) -> [<<"; HttpOnly">>|attributes(Tail)];
attributes([{max_age, MaxAge}|Tail]) when is_integer(MaxAge), MaxAge >= 0 ->
	[<<"; Max-Age=">>, integer_to_binary(MaxAge)|attributes(Tail)];
attributes([Opt={max_age, _}|_]) ->
	error({badarg, Opt});
attributes([{path, Path0}|Tail]) ->
	Path = iolist_to_binary(Path0),
	validate_av_octets(Path),
	[<<"; Path=">>, Path|attributes(Tail)];
attributes([{secure, false}|Tail]) -> attributes(Tail);
attributes([{secure, true}|Tail]) -> [<<"; Secure">>|attributes(Tail)];
attributes([{same_site, default}|Tail]) -> attributes(Tail);
attributes([{same_site, none}|Tail]) -> [<<"; SameSite=None">>|attributes(Tail)];
attributes([{same_site, lax}|Tail]) -> [<<"; SameSite=Lax">>|attributes(Tail)];
attributes([{same_site, strict}|Tail]) -> [<<"; SameSite=Strict">>|attributes(Tail)];
%% Skip unknown options.
attributes([_|Tail]) -> attributes(Tail).

-ifdef(TEST).
setcookie_test_() ->
	%% {Name, Value, Opts, Result}
	Tests = [
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{http_only => true, domain => <<"acme.com">>},
			<<"Customer=WILE_E_COYOTE; "
				"Domain=acme.com; HttpOnly">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{path => <<"/acme">>},
			<<"Customer=WILE_E_COYOTE; Path=/acme">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{secure => true},
			<<"Customer=WILE_E_COYOTE; Secure">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{secure => false, http_only => false},
			<<"Customer=WILE_E_COYOTE">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{same_site => default},
			<<"Customer=WILE_E_COYOTE">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{same_site => none},
			<<"Customer=WILE_E_COYOTE; SameSite=None">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{same_site => lax},
			<<"Customer=WILE_E_COYOTE; SameSite=Lax">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{same_site => strict},
			<<"Customer=WILE_E_COYOTE; SameSite=Strict">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{path => <<"/acme">>, badoption => <<"negatory">>},
			<<"Customer=WILE_E_COYOTE; Path=/acme">>}
	],
	[{R, fun() -> R = iolist_to_binary(setcookie(N, V, O)) end}
		|| {N, V, O, R} <- Tests].

setcookie_max_age_test() ->
	F = fun(N, V, O) ->
		iolist_to_binary(setcookie(N, V, O))
	end,
	<<"Customer=WILE_E_COYOTE; Max-Age=0">> = F(<<"Customer">>, <<"WILE_E_COYOTE">>,
		#{max_age => 0}),
	<<"Customer=WILE_E_COYOTE; Max-Age=111; Secure">> = F(<<"Customer">>, <<"WILE_E_COYOTE">>,
		#{max_age => 111, secure => true}),
	?assertError({badarg, {max_age, -111}},
		F(<<"Customer">>, <<"WILE_E_COYOTE">>, #{max_age => -111})),
	<<"Customer=WILE_E_COYOTE; Max-Age=86417">> = F(<<"Customer">>, <<"WILE_E_COYOTE">>,
		#{max_age => 86417}),
	ok.

%% Name is a token. Value is cookie-octet, or a quoted cookie-octet run.
setcookie_grammar_test_() ->
	Tests = [
		{<<"!">>, <<"!">>, <<"!=!">>},
		{[<<"Na">>, <<"me">>], <<"a=b">>, <<"Name=a=b">>},
		{<<"Name">>, <<"\"ab\"">>, <<"Name=\"ab\"">>},
		{<<"Name">>, <<"\"\"">>, <<"Name=\"\"">>},
		{<<"Name">>, <<16#21>>, <<"Name=", 16#21>>},
		{<<"Name">>, <<16#7E>>, <<"Name=", 16#7E>>},
		{<<"Name">>, <<16#5D>>, <<"Name=", 16#5D>>}
	],
	[{R, fun() -> R = iolist_to_binary(setcookie(N, V, #{})) end}
		|| {N, V, R} <- Tests].

setcookie_grammar_error_test_() ->
	Tests = [
		{<<>>, <<"Value">>},
		{<<" ">>, <<"Value">>},
		{<<"(">>, <<"Value">>},
		{<<"/">>, <<"Value">>},
		{<<":">>, <<"Value">>},
		{<<"Na=me">>, <<"Value">>},
		{<<"Name">>, <<" ">>},
		{<<"Name">>, <<",">>},
		{<<"Name">>, <<";">>},
		{<<"Name">>, <<"\\">>},
		{<<"Name">>, <<"\"">>},
		{<<"Name">>, <<"\"a b\"">>},
		{<<"Name">>, <<"\"b">>},
		{<<"Name">>, <<"\"ab\"c">>},
		{<<"Name">>, <<"\"a\"b\"">>},
		{<<"Name">>, <<16#20>>},
		{<<"Name">>, <<16#7F>>},
		{<<"Name">>, <<16#22>>}
	],
	[{iolist_to_binary(io_lib:format("{~p, ~p} failure", [N, V])),
		fun() -> ?assertError(_, setcookie(N, V, #{})) end}
		|| {N, V} <- Tests].

setcookie_attr_grammar_test_() ->
	Tests = [
		{#{path => <<"foo">>}, <<"Name=Value; Path=foo">>},
		{#{path => <<"/a b">>}, <<"Name=Value; Path=/a b">>},
		{#{path => <<"/", 16#7E>>}, <<"Name=Value; Path=/", 16#7E>>},
		{#{domain => <<"ex ample.com">>}, <<"Name=Value; Domain=ex ample.com">>},
		{#{domain => <<".example.org">>}, <<"Name=Value; Domain=.example.org">>},
		{#{path => [<<"/a">>, <<"/b">>]}, <<"Name=Value; Path=/a/b">>}
	],
	[{R, fun() -> R = iolist_to_binary(setcookie(<<"Name">>, <<"Value">>, O)) end}
		|| {O, R} <- Tests].

setcookie_attr_grammar_error_test_() ->
	Tests = [
		#{path => <<"/a;b">>},
		#{path => <<"/a", 0>>},
		#{path => <<"/a", 31>>},
		#{path => <<"/a", 127>>},
		#{path => <<"/a", 128>>},
		#{domain => <<"ex.com;">>},
		#{domain => <<"ex.com", 10>>},
		#{domain => <<"ex", 16#7F, ".com">>}
	],
	[{iolist_to_binary(io_lib:format("~p failure", [O])),
		fun() -> ?assertError(_, setcookie(<<"Name">>, <<"Value">>, O)) end}
		|| O <- Tests].

setcookie_failures_test_() ->
	F = fun(N, V) ->
		try setcookie(N, V, #{}) of
			_ ->
				false
		catch _:_ ->
			true
		end
	end,
	Tests = [
		{<<"Na=me">>, <<"Value">>},
		{<<"Name;">>, <<"Value">>},
		{<<"\r\name">>, <<"Value">>},
		{<<"Name">>, <<"Value;">>},
		{<<"Name">>, <<"\value">>}
	],
	[{iolist_to_binary(io_lib:format("{~p, ~p} failure", [N, V])),
		fun() -> true = F(N, V) end}
		|| {N, V} <- Tests].

setcookie_attr_failures_test_() ->
	F = fun(Opts) ->
		try setcookie(<<"Name">>, <<"Value">>, Opts) of
			_ ->
				false
		catch _:_ ->
			true
		end
	end,
	Tests = [
		#{path => <<"/a; Secure">>},
		#{domain => <<"ex.com; Path=/">>},
		#{path => [<<"/a">>, <<";HttpOnly">>]}
	],
	[{iolist_to_binary(io_lib:format("~p failure", [O])),
		fun() -> true = F(O) end}
		|| O <- Tests].
-endif.
