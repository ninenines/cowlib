%% Copyright (c) 2019, Loïc Hoguin <essen@ninenines.eu>
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

%% The mapping between Erlang and structured headers types is as follow:
%%
%% List: list()
%% Dictionary: map()
%% Bare item: one bare_item() that can be of type:
%% Integer: integer()
%% Decimal: {decimal, {integer(), integer()}}
%% String: {string, binary()}
%% Token: {token, binary()}
%% Byte sequence: {binary, binary()}
%% Boolean: boolean()
%% And finally:
%% Type with Parameters: {with_params, Type, Parameters}
%% Parameters: [{binary(), bare_item()}]

-module(cow_http_struct_hd).

-export([parse_dictionary/1]).
-export([parse_item/1]).
-export([parse_list/1]).
-export([dictionary/1]).
-export([item/1]).
-export([list/1]).

-include("cow_parse.hrl").

-type sh_list() :: [sh_item() | sh_inner_list()].
-type sh_inner_list() :: sh_with_params([sh_item()]).
-type sh_params() :: #{binary() => sh_bare_item()}.
-type sh_dictionary() :: {#{binary() => sh_item() | sh_inner_list()}, [binary()]}.
-type sh_item() :: sh_with_params(sh_bare_item()).
-type sh_bare_item() :: integer() | sh_decimal() | boolean()
	| {string | token | binary, binary()}.
-type sh_decimal() :: {decimal, {integer(), integer()}}.
-type sh_with_params(Type) :: {with_params, Type, sh_params()}.

-define(IS_LC_ALPHA(C),
	(C =:= $a) or (C =:= $b) or (C =:= $c) or (C =:= $d) or (C =:= $e) or
	(C =:= $f) or (C =:= $g) or (C =:= $h) or (C =:= $i) or (C =:= $j) or
	(C =:= $k) or (C =:= $l) or (C =:= $m) or (C =:= $n) or (C =:= $o) or
	(C =:= $p) or (C =:= $q) or (C =:= $r) or (C =:= $s) or (C =:= $t) or
	(C =:= $u) or (C =:= $v) or (C =:= $w) or (C =:= $x) or (C =:= $y) or
	(C =:= $z)
).

%% Parsing.

-spec parse_dictionary(binary()) -> sh_dictionary().
parse_dictionary(<<>>) ->
	{#{}, []};
parse_dictionary(<<C,R/bits>>) when ?IS_LC_ALPHA(C) or (C =:= $*) ->
	{Dict, Order, <<>>} = parse_dict_key(R, #{}, [], <<C>>),
	{Dict, Order}.

parse_dict_key(<<$=,$(,R0/bits>>, Acc, Order, K) ->
	{Item, R} = parse_inner_list(R0, []),
	parse_dict_before_sep(R, Acc#{K => Item}, [K|Order]);
parse_dict_key(<<$=,R0/bits>>, Acc, Order, K) ->
	{Item, R} = parse_item1(R0),
	parse_dict_before_sep(R, Acc#{K => Item}, [K|Order]);
parse_dict_key(<<C,R/bits>>, Acc, Order, K)
		when ?IS_LC_ALPHA(C) or ?IS_DIGIT(C)
			or (C =:= $_) or (C =:= $-) or (C =:= $.) or (C =:= $*) ->
	parse_dict_key(R, Acc, Order, <<K/binary,C>>);
parse_dict_key(<<$;,R0/bits>>, Acc, Order, K) ->
	{Params, R} = parse_before_param(R0, #{}),
	parse_dict_before_sep(R, Acc#{K => {with_params, true, Params}}, [K|Order]);
parse_dict_key(R, Acc, Order, K) ->
	parse_dict_before_sep(R, Acc#{K => {with_params, true, #{}}}, [K|Order]).

parse_dict_before_sep(<<$\s,R/bits>>, Acc, Order) ->
	parse_dict_before_sep(R, Acc, Order);
parse_dict_before_sep(<<C,R/bits>>, Acc, Order) when C =:= $, ->
	parse_dict_before_member(R, Acc, Order);
parse_dict_before_sep(<<>>, Acc, Order) ->
	{Acc, lists:reverse(Order), <<>>}.

parse_dict_before_member(<<$\s,R/bits>>, Acc, Order) ->
	parse_dict_before_member(R, Acc, Order);
parse_dict_before_member(<<C,R/bits>>, Acc, Order) when ?IS_LC_ALPHA(C) or (C =:= $*) ->
	parse_dict_key(R, Acc, Order, <<C>>).

-spec parse_item(binary()) -> sh_item().
parse_item(Bin) ->
	{Item, <<>>} = parse_item1(Bin),
	Item.

parse_item1(Bin) ->
	case parse_bare_item(Bin) of
		{Item, <<$;,R/bits>>} ->
			{Params, Rest} = parse_before_param(R, #{}),
			{{with_params, Item, Params}, Rest};
		{Item, Rest} ->
			{{with_params, Item, #{}}, Rest}
	end.

-spec parse_list(binary()) -> sh_list().
parse_list(<<>>) ->
	[];
parse_list(Bin) ->
	parse_list_before_member(Bin, []).

parse_list_member(<<$(,R0/bits>>, Acc) ->
	{Item, R} = parse_inner_list(R0, []),
	parse_list_before_sep(R, [Item|Acc]);
parse_list_member(R0, Acc) ->
	{Item, R} = parse_item1(R0),
	parse_list_before_sep(R, [Item|Acc]).

parse_list_before_sep(<<$\s,R/bits>>, Acc) ->
	parse_list_before_sep(R, Acc);
parse_list_before_sep(<<$,,R/bits>>, Acc) ->
	parse_list_before_member(R, Acc);
parse_list_before_sep(<<>>, Acc) ->
	lists:reverse(Acc).

parse_list_before_member(<<$\s,R/bits>>, Acc) ->
	parse_list_before_member(R, Acc);
parse_list_before_member(R, Acc) ->
	parse_list_member(R, Acc).

%% Internal.

parse_inner_list(<<$\s,R/bits>>, Acc) ->
	parse_inner_list(R, Acc);
parse_inner_list(<<$),$;,R0/bits>>, Acc) ->
	{Params, R} = parse_before_param(R0, #{}),
	{{with_params, lists:reverse(Acc), Params}, R};
parse_inner_list(<<$),R/bits>>, Acc) ->
	{{with_params, lists:reverse(Acc), #{}}, R};
parse_inner_list(R0, Acc) ->
	{Item, R = <<C,_/bits>>} = parse_item1(R0),
	true = (C =:= $\s) orelse (C =:= $)),
	parse_inner_list(R, [Item|Acc]).

parse_before_param(<<$\s,R/bits>>, Acc) ->
	parse_before_param(R, Acc);
parse_before_param(<<C,R/bits>>, Acc) when ?IS_LC_ALPHA(C) or (C =:= $*) ->
	parse_param(R, Acc, <<C>>).

parse_param(<<$;,R/bits>>, Acc, K) ->
	false = maps:is_key(K, Acc),
	parse_before_param(R, Acc#{K => true});
parse_param(<<$=,R0/bits>>, Acc, K) ->
	case parse_bare_item(R0) of
		{Item, <<$;,R/bits>>} ->
			parse_before_param(R, Acc#{K => Item});
		{Item, R} ->
			{Acc#{K => Item}, R}
	end;
parse_param(<<C,R/bits>>, Acc, K)
		when ?IS_LC_ALPHA(C) or ?IS_DIGIT(C)
			or (C =:= $_) or (C =:= $-) or (C =:= $.) or (C =:= $*) ->
	parse_param(R, Acc, <<K/binary,C>>);
parse_param(R, Acc, K) ->
	false = maps:is_key(K, Acc),
	{Acc#{K => true}, R}.

%% Integer or decimal.
parse_bare_item(<<$-,R/bits>>) -> parse_number(R, 0, <<$->>);
parse_bare_item(<<C,R/bits>>) when ?IS_DIGIT(C) -> parse_number(R, 1, <<C>>);
%% String.
parse_bare_item(<<$",R/bits>>) -> parse_string(R, <<>>);
%% Token.
parse_bare_item(<<C,R/bits>>) when ?IS_ALPHA(C) or (C =:= $*) -> parse_token(R, <<C>>);
%% Byte sequence.
parse_bare_item(<<$:,R/bits>>) -> parse_binary(R, <<>>);
%% Boolean.
parse_bare_item(<<"?0",R/bits>>) -> {false, R};
parse_bare_item(<<"?1",R/bits>>) -> {true, R}.

parse_number(<<C,R/bits>>, L, Acc) when ?IS_DIGIT(C) ->
	parse_number(R, L+1, <<Acc/binary,C>>);
parse_number(<<$.,R/bits>>, L, Acc) ->
	parse_decimal(R, L, 0, Acc, <<>>);
parse_number(R, L, Acc) when L =< 15 ->
	{binary_to_integer(Acc), R}.

parse_decimal(<<C,R/bits>>, L1, L2, IntAcc, FracAcc) when ?IS_DIGIT(C) ->
	parse_decimal(R, L1, L2+1, IntAcc, <<FracAcc/binary,C>>);
parse_decimal(R, L1, L2, IntAcc, FracAcc0) when L1 =< 12, L2 >= 1, L2 =< 3 ->
	%% While not strictly required this gives a more consistent representation.
	FracAcc = case FracAcc0 of
		<<$0>> -> <<>>;
		<<$0,$0>> -> <<>>;
		<<$0,$0,$0>> -> <<>>;
		<<A,B,$0>> -> <<A,B>>;
		<<A,$0,$0>> -> <<A>>;
		<<A,$0>> -> <<A>>;
		_ -> FracAcc0
	end,
	Mul = case byte_size(FracAcc) of
		3 -> 1000;
		2 -> 100;
		1 -> 10;
		0 -> 1
	end,
	Int = binary_to_integer(IntAcc),
	Frac = case FracAcc of
		<<>> -> 0;
		%% Mind the sign.
		_ when Int < 0 -> -binary_to_integer(FracAcc);
		_ -> binary_to_integer(FracAcc)
	end,
	{{decimal, {Int * Mul + Frac, -byte_size(FracAcc)}}, R}.

parse_string(<<$\\,$",R/bits>>, Acc) ->
	parse_string(R, <<Acc/binary,$">>);
parse_string(<<$\\,$\\,R/bits>>, Acc) ->
	parse_string(R, <<Acc/binary,$\\>>);
parse_string(<<$",R/bits>>, Acc) ->
	{{string, Acc}, R};
parse_string(<<C,R/bits>>, Acc) when
		C >= 16#20, C =< 16#21;
		C >= 16#23, C =< 16#5b;
		C >= 16#5d, C =< 16#7e ->
	parse_string(R, <<Acc/binary,C>>).

parse_token(<<C,R/bits>>, Acc) when ?IS_TOKEN(C) or (C =:= $:) or (C =:= $/) ->
	parse_token(R, <<Acc/binary,C>>);
parse_token(R, Acc) ->
	{{token, Acc}, R}.

parse_binary(<<$:,R/bits>>, Acc) ->
	{{binary, base64:decode(Acc)}, R};
parse_binary(<<C,R/bits>>, Acc) when ?IS_ALPHANUM(C) or (C =:= $+) or (C =:= $/) or (C =:= $=) ->
	parse_binary(R, <<Acc/binary,C>>).

-ifdef(TEST).
parse_struct_hd_test_() ->
	Files = filelib:wildcard("deps/structured-header-tests/*.json"),
	lists:flatten([begin
		{ok, JSON} = file:read_file(File),
		Tests = jsx:decode(JSON, [return_maps]),
		[
			{iolist_to_binary(io_lib:format("~s: ~s", [filename:basename(File), Name])), fun() ->
				%% The implementation is strict. We fail whenever we can.
				CanFail = maps:get(<<"can_fail">>, Test, false),
				MustFail = maps:get(<<"must_fail">>, Test, false),
				Expected = case MustFail of
					true -> undefined;
					false -> expected_to_term(maps:get(<<"expected">>, Test))
				end,
				Raw = raw_to_binary(Raw0),
				case HeaderType of
					<<"dictionary">> when MustFail; CanFail ->
						{'EXIT', _} = (catch parse_dictionary(Raw));
					%% The test "binary.json: non-zero pad bits" does not fail
					%% due to our reliance on Erlang/OTP's base64 module.
					<<"item">> when CanFail ->
						case (catch parse_item(Raw)) of
							{'EXIT', _} -> ok;
							Expected -> ok
						end;
					<<"item">> when MustFail ->
						{'EXIT', _} = (catch parse_item(Raw));
					<<"list">> when MustFail; CanFail ->
						{'EXIT', _} = (catch parse_list(Raw));
					<<"dictionary">> ->
						{Expected, _Order} = (catch parse_dictionary(Raw));
					<<"item">> ->
						Expected = (catch parse_item(Raw));
					<<"list">> ->
						Expected = (catch parse_list(Raw))
				end
			end}
		|| Test=#{
			<<"name">> := Name,
			<<"header_type">> := HeaderType,
			<<"raw">> := Raw0
		} <- Tests]
	end || File <- Files]).

%% Item.
expected_to_term(E=[_, Params]) when is_map(Params) ->
	e2t(E);
%% Outer list.
expected_to_term(Expected) when is_list(Expected) ->
	[e2t(E) || E <- Expected];
expected_to_term(Expected) ->
	e2t(Expected).

%% Dictionary.
e2t(Dict) when is_map(Dict) ->
	maps:map(fun(_, V) -> e2t(V) end, Dict);
%% Inner list.
e2t([List, Params]) when is_list(List) ->
	{with_params, [e2t(E) || E <- List],
		maps:map(fun(_, P) -> e2tb(P) end, Params)};
%% Item.
e2t([Bare, Params]) ->
	{with_params, e2tb(Bare),
		maps:map(fun(_, P) -> e2tb(P) end, Params)}.

%% Bare item.
e2tb(#{<<"__type">> := <<"token">>, <<"value">> := V}) ->
	{token, V};
e2tb(#{<<"__type">> := <<"binary">>, <<"value">> := V}) ->
	{binary, base32:decode(V)};
e2tb(V) when is_binary(V) ->
	{string, V};
e2tb(V) when is_float(V) ->
	%% There should be no rounding needed for the test cases.
	{decimal, decimal:to_decimal(V, #{precision => 3, rounding => round_down})};
e2tb(V) ->
	V.

%% The Cowlib parsers currently do not support resuming parsing
%% in the case of multiple headers. To make tests work we modify
%% the raw value the same way Cowboy does when encountering
%% multiple headers: by adding a comma and space in between.
%%
%% Similarly, the Cowlib parsers expect the leading and trailing
%% whitespace to be removed before calling the parser.
raw_to_binary(RawList) ->
	trim_ws(iolist_to_binary(lists:join(<<", ">>, RawList))).

trim_ws(<<$\s,R/bits>>) -> trim_ws(R);
trim_ws(R) -> trim_ws_end(R, byte_size(R) - 1).

trim_ws_end(_, -1) ->
	<<>>;
trim_ws_end(Value, N) ->
	case binary:at(Value, N) of
		$\s -> trim_ws_end(Value, N - 1);
		_ ->
			S = N + 1,
			<< Value2:S/binary, _/bits >> = Value,
			Value2
	end.
-endif.

%% Building.

-spec dictionary(#{binary() => sh_item() | sh_inner_list()}
		| [{binary(), sh_item() | sh_inner_list()}])
	-> iolist().
%% @todo Also accept this? dictionary({Map, Order}) ->
dictionary(Map) when is_map(Map) ->
	dictionary(maps:to_list(Map));
dictionary(KVList) when is_list(KVList) ->
	lists:join(<<", ">>, [
		case Value of
			true -> Key;
			_ -> [Key, $=, item_or_inner_list(Value)]
		end
	|| {Key, Value} <- KVList]).

-spec item(sh_item()) -> iolist().
item({with_params, BareItem, Params}) ->
	[bare_item(BareItem), params(Params)].

-spec list(sh_list()) -> iolist().
list(List) ->
	lists:join(<<", ">>, [item_or_inner_list(Value) || Value <- List]).

item_or_inner_list(Value={with_params, List, _}) when is_list(List) ->
	inner_list(Value);
item_or_inner_list(Value) ->
	item(Value).

inner_list({with_params, List, Params}) ->
	[$(, lists:join($\s, [item(Value) || Value <- List]), $), params(Params)].

bare_item({string, String}) ->
	[$", escape_string(String, <<>>), $"];
%% @todo Must fail if Token has invalid characters.
bare_item({token, Token}) ->
	Token;
bare_item({binary, Binary}) ->
	[$:, base64:encode(Binary), $:];
bare_item({decimal, {Base, Exp}}) when Exp >= 0 ->
	Mul = case Exp of
		0 -> 1;
		1 -> 10;
		2 -> 100;
		3 -> 1000;
		4 -> 10000;
		5 -> 100000;
		6 -> 1000000;
		7 -> 10000000;
		8 -> 100000000;
		9 -> 1000000000;
		10 -> 10000000000;
		11 -> 100000000000;
		12 -> 1000000000000
	end,
	MaxLenWithSign = if
		Base < 0 -> 13;
		true -> 12
	end,
	Bin = integer_to_binary(Base * Mul),
	true = byte_size(Bin) =< MaxLenWithSign,
	[Bin, <<".0">>];
bare_item({decimal, {Base, -1}}) ->
	Int = Base div 10,
	Frac = abs(Base) rem 10,
	[integer_to_binary(Int), $., integer_to_binary(Frac)];
bare_item({decimal, {Base, -2}}) ->
	Int = Base div 100,
	Frac = abs(Base) rem 100,
	[integer_to_binary(Int), $., integer_to_binary(Frac)];
bare_item({decimal, {Base, -3}}) ->
	Int = Base div 1000,
	Frac = abs(Base) rem 1000,
	[integer_to_binary(Int), $., integer_to_binary(Frac)];
bare_item({decimal, {Base, Exp}}) ->
	Div = exp_div(Exp),
	Int0 = Base div Div,
	true = abs(Int0) < 1000000000000,
	Frac0 = abs(Base) rem Div,
	DivFrac = Div div 1000,
	Frac1 = Frac0 div DivFrac,
	{Int, Frac} = if
		(Frac0 rem DivFrac) > (DivFrac div 2) ->
			case Frac1 of
				999 when Int0 < 0 -> {Int0 - 1, 0};
				999 -> {Int0 + 1, 0};
				_ -> {Int0, Frac1 + 1}
			end;
		true ->
			{Int0, Frac1}
	end,
	[integer_to_binary(Int), $., if
		Frac < 10 -> [$0, $0, integer_to_binary(Frac)];
		Frac < 100 -> [$0, integer_to_binary(Frac)];
		true -> integer_to_binary(Frac)
	end];
bare_item(Integer) when is_integer(Integer) ->
	integer_to_binary(Integer);
bare_item(true) ->
	<<"?1">>;
bare_item(false) ->
	<<"?0">>.

exp_div(0) -> 1;
exp_div(N) -> 10 * exp_div(N + 1).

escape_string(<<>>, Acc) -> Acc;
escape_string(<<$\\,R/bits>>, Acc) -> escape_string(R, <<Acc/binary,$\\,$\\>>);
escape_string(<<$",R/bits>>, Acc) -> escape_string(R, <<Acc/binary,$\\,$">>);
escape_string(<<C,R/bits>>, Acc) -> escape_string(R, <<Acc/binary,C>>).

params(Params) ->
	maps:fold(fun
		(Key, true, Acc) ->
			[[$;, Key]|Acc];
		(Key, Value, Acc) ->
			[[$;, Key, $=, bare_item(Value)]|Acc]
	end, [], Params).

-ifdef(TEST).
struct_hd_identity_test_() ->
	Files = filelib:wildcard("deps/structured-header-tests/*.json"),
	lists:flatten([begin
		{ok, JSON} = file:read_file(File),
		Tests = jsx:decode(JSON, [return_maps]),
		[
			{iolist_to_binary(io_lib:format("~s: ~s", [filename:basename(File), Name])), fun() ->
				Expected = expected_to_term(Expected0),
				case HeaderType of
					<<"dictionary">> ->
						{Expected, _Order} = parse_dictionary(iolist_to_binary(dictionary(Expected)));
					<<"item">> ->
						Expected = parse_item(iolist_to_binary(item(Expected)));
					<<"list">> ->
						Expected = parse_list(iolist_to_binary(list(Expected)))
				end
			end}
		|| #{
			<<"name">> := Name,
			<<"header_type">> := HeaderType,
			%% We only run tests that must not fail.
			<<"expected">> := Expected0
		} <- Tests]
	end || File <- Files]).
-endif.
