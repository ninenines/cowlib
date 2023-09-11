%% Copyright (c) 2015-2023, Loïc Hoguin <essen@ninenines.eu>
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

%% The current implementation is not suitable for use in
%% intermediaries as the information about headers that
%% should never be indexed is currently lost.

-module(cow_hpack).
-dialyzer(no_improper_lists).

-export([init/0]).
-export([init/1]).
-export([set_max_size/2]).

-export([decode/1]).
-export([decode/2]).

-export([encode/1]).
-export([encode/2]).
-export([encode/3]).

-record(state, {
	size = 0 :: non_neg_integer(),
	max_size = 4096 :: non_neg_integer(),
	configured_max_size = 4096 :: non_neg_integer(),
	dyn_table = [] :: [{pos_integer(), {binary(), binary()}}]
}).

-define(STATIC_HEADERS, [
		{<<":authority">>, <<>>},
		{<<":method">>, <<"GET">>},
		{<<":method">>, <<"POST">>},
		{<<":path">>, <<"/">>},
		{<<":path">>, <<"/index.html">>},
		{<<":scheme">>, <<"http">>},
		{<<":scheme">>, <<"https">>},
		{<<":status">>, <<"200">>},
		{<<":status">>, <<"204">>},
		{<<":status">>, <<"206">>},
		{<<":status">>, <<"304">>},
		{<<":status">>, <<"400">>},
		{<<":status">>, <<"404">>},
		{<<":status">>, <<"500">>},
		{<<"accept-charset">>, <<>>},
		{<<"accept-encoding">>, <<"gzip, deflate">>},
		{<<"accept-language">>, <<>>},
		{<<"accept-ranges">>, <<>>},
		{<<"accept">>, <<>>},
		{<<"access-control-allow-origin">>, <<>>},
		{<<"age">>, <<>>},
		{<<"allow">>, <<>>},
		{<<"authorization">>, <<>>},
		{<<"cache-control">>, <<>>},
		{<<"content-disposition">>, <<>>},
		{<<"content-encoding">>, <<>>},
		{<<"content-language">>, <<>>},
		{<<"content-length">>, <<>>},
		{<<"content-location">>, <<>>},
		{<<"content-range">>, <<>>},
		{<<"content-type">>, <<>>},
		{<<"cookie">>, <<>>},
		{<<"date">>, <<>>},
		{<<"etag">>, <<>>},
		{<<"expect">>, <<>>},
		{<<"expires">>, <<>>},
		{<<"from">>, <<>>},
		{<<"host">>, <<>>},
		{<<"if-match">>, <<>>},
		{<<"if-modified-since">>, <<>>},
		{<<"if-none-match">>, <<>>},
		{<<"if-range">>, <<>>},
		{<<"if-unmodified-since">>, <<>>},
		{<<"last-modified">>, <<>>},
		{<<"link">>, <<>>},
		{<<"location">>, <<>>},
		{<<"max-forwards">>, <<>>},
		{<<"proxy-authenticate">>, <<>>},
		{<<"proxy-authorization">>, <<>>},
		{<<"range">>, <<>>},
		{<<"referer">>, <<>>},
		{<<"refresh">>, <<>>},
		{<<"retry-after">>, <<>>},
		{<<"server">>, <<>>},
		{<<"set-cookie">>, <<>>},
		{<<"strict-transport-security">>, <<>>},
		{<<"transfer-encoding">>, <<>>},
		{<<"user-agent">>, <<>>},
		{<<"vary">>, <<>>},
		{<<"via">>, <<>>},
		{<<"www-authenticate">>, <<>>}
	]).

-opaque state() :: #state{}.
-export_type([state/0]).

-type opts() :: map().
-export_type([opts/0]).

-ifdef(TEST).
-include_lib("proper/include/proper.hrl").
-endif.

%% State initialization.

-spec init() -> state().
init() ->
	#state{}.

-spec init(non_neg_integer()) -> state().
init(MaxSize) ->
	#state{max_size=MaxSize, configured_max_size=MaxSize}.

%% Update the configured max size.
%%
%% When decoding, the local endpoint also needs to send a SETTINGS
%% frame with this value and it is then up to the remote endpoint
%% to decide what actual limit it will use. The actual limit is
%% signaled via dynamic table size updates in the encoded data.
%%
%% When encoding, the local endpoint will call this function after
%% receiving a SETTINGS frame with this value. The encoder will
%% then use this value as the new max after signaling via a dynamic
%% table size update. The value given as argument may be lower
%% than the one received in the SETTINGS.

-spec set_max_size(non_neg_integer(), State) -> State when State::state().
set_max_size(MaxSize, State) ->
	State#state{configured_max_size=MaxSize}.

%% Decoding.

-spec decode(binary()) -> {cow_http:headers(), state()}.
decode(Data) ->
	decode(Data, init()).

-spec decode(binary(), State) -> {cow_http:headers(), State} when State::state().
%% Dynamic table size update is only allowed at the beginning of a HEADERS block.
decode(<< 0:2, 1:1, Rest/bits >>, State=#state{configured_max_size=ConfigMaxSize}) ->
	{MaxSize, Rest2} = dec_int5(Rest),
	if
		MaxSize =< ConfigMaxSize ->
			State2 = table_update_size(MaxSize, State),
			decode(Rest2, State2)
	end;
decode(Data, State) ->
	decode(Data, State, []).

decode(<<>>, State, Acc) ->
	{lists:reverse(Acc), State};
%% Indexed header field representation.
decode(<< 1:1, Rest/bits >>, State, Acc) ->
	dec_indexed(Rest, State, Acc);
%% Literal header field with incremental indexing: new name.
decode(<< 0:1, 1:1, 0:6, Rest/bits >>, State, Acc) ->
	dec_lit_index_new_name(Rest, State, Acc);
%% Literal header field with incremental indexing: indexed name.
decode(<< 0:1, 1:1, Rest/bits >>, State, Acc) ->
	dec_lit_index_indexed_name(Rest, State, Acc);
%% Literal header field without indexing: new name.
decode(<< 0:8, Rest/bits >>, State, Acc) ->
	dec_lit_no_index_new_name(Rest, State, Acc);
%% Literal header field without indexing: indexed name.
decode(<< 0:4, Rest/bits >>, State, Acc) ->
	dec_lit_no_index_indexed_name(Rest, State, Acc);
%% Literal header field never indexed: new name.
%% @todo Keep track of "never indexed" headers.
decode(<< 0:3, 1:1, 0:4, Rest/bits >>, State, Acc) ->
	dec_lit_no_index_new_name(Rest, State, Acc);
%% Literal header field never indexed: indexed name.
%% @todo Keep track of "never indexed" headers.
decode(<< 0:3, 1:1, Rest/bits >>, State, Acc) ->
	dec_lit_no_index_indexed_name(Rest, State, Acc).

%% Indexed header field representation.

%% We do the integer decoding inline where appropriate, falling
%% back to dec_big_int for larger values.
dec_indexed(<<2#1111111:7, 0:1, Int:7, Rest/bits>>, State, Acc) ->
	{Name, Value} = table_get(127 + Int, State),
	decode(Rest, State, [{Name, Value}|Acc]);
dec_indexed(<<2#1111111:7, Rest0/bits>>, State, Acc) ->
	{Index, Rest} = dec_big_int(Rest0, 127, 0),
	{Name, Value} = table_get(Index, State),
	decode(Rest, State, [{Name, Value}|Acc]);
dec_indexed(<<Index:7, Rest/bits>>, State, Acc) ->
	{Name, Value} = table_get(Index, State),
	decode(Rest, State, [{Name, Value}|Acc]).

%% Literal header field with incremental indexing.

dec_lit_index_new_name(Rest, State, Acc) ->
	{Name, Rest2} = dec_str(Rest),
	dec_lit_index(Rest2, State, Acc, Name).

%% We do the integer decoding inline where appropriate, falling
%% back to dec_big_int for larger values.
dec_lit_index_indexed_name(<<2#111111:6, 0:1, Int:7, Rest/bits>>, State, Acc) ->
	Name = table_get_name(63 + Int, State),
	dec_lit_index(Rest, State, Acc, Name);
dec_lit_index_indexed_name(<<2#111111:6, Rest0/bits>>, State, Acc) ->
	{Index, Rest} = dec_big_int(Rest0, 63, 0),
	Name = table_get_name(Index, State),
	dec_lit_index(Rest, State, Acc, Name);
dec_lit_index_indexed_name(<<Index:6, Rest/bits>>, State, Acc) ->
	Name = table_get_name(Index, State),
	dec_lit_index(Rest, State, Acc, Name).

dec_lit_index(Rest, State, Acc, Name) ->
	{Value, Rest2} = dec_str(Rest),
	State2 = table_insert({Name, Value}, State),
	decode(Rest2, State2, [{Name, Value}|Acc]).

%% Literal header field without indexing.

dec_lit_no_index_new_name(Rest, State, Acc) ->
	{Name, Rest2} = dec_str(Rest),
	dec_lit_no_index(Rest2, State, Acc, Name).

%% We do the integer decoding inline where appropriate, falling
%% back to dec_big_int for larger values.
dec_lit_no_index_indexed_name(<<2#1111:4, 0:1, Int:7, Rest/bits>>, State, Acc) ->
	Name = table_get_name(15 + Int, State),
	dec_lit_no_index(Rest, State, Acc, Name);
dec_lit_no_index_indexed_name(<<2#1111:4, Rest0/bits>>, State, Acc) ->
	{Index, Rest} = dec_big_int(Rest0, 15, 0),
	Name = table_get_name(Index, State),
	dec_lit_no_index(Rest, State, Acc, Name);
dec_lit_no_index_indexed_name(<<Index:4, Rest/bits>>, State, Acc) ->
	Name = table_get_name(Index, State),
	dec_lit_no_index(Rest, State, Acc, Name).

dec_lit_no_index(Rest, State, Acc, Name) ->
	{Value, Rest2} = dec_str(Rest),
	decode(Rest2, State, [{Name, Value}|Acc]).

%% @todo Literal header field never indexed.

%% Decode an integer.

%% The HPACK format has 4 different integer prefixes length (from 4 to 7)
%% and each can be used to create an indefinite length integer if all bits
%% of the prefix are set to 1.

dec_int5(<< 2#11111:5, Rest/bits >>) ->
	dec_big_int(Rest, 31, 0);
dec_int5(<< Int:5, Rest/bits >>) ->
	{Int, Rest}.

dec_big_int(<< 0:1, Value:7, Rest/bits >>, Int, M) ->
	{Int + (Value bsl M), Rest};
dec_big_int(<< 1:1, Value:7, Rest/bits >>, Int, M) ->
	dec_big_int(Rest, Int + (Value bsl M), M + 7).

%% Decode a string.

dec_str(<<0:1, 2#1111111:7, Rest0/bits>>) ->
	{Length, Rest1} = dec_big_int(Rest0, 127, 0),
	<<Str:Length/binary, Rest/bits>> = Rest1,
	{Str, Rest};
dec_str(<<0:1, Length:7, Rest0/bits>>) ->
	<<Str:Length/binary, Rest/bits>> = Rest0,
	{Str, Rest};
dec_str(<<1:1, 2#1111111:7, Rest0/bits>>) ->
	{Length, Rest} = dec_big_int(Rest0, 127, 0),
	dec_huffman(Rest, Length, 0, <<>>);
dec_str(<<1:1, Length:7, Rest/bits>>) ->
	dec_huffman(Rest, Length, 0, <<>>).

%% We use a lookup table that allows us to benefit from
%% the binary match context optimization. A more naive
%% implementation using bit pattern matching cannot reuse
%% a match context because it wouldn't always match on
%% byte boundaries.
%%
%% See cow_hpack_dec_huffman_lookup.hrl for more details.

dec_huffman(<<A:4, B:4, R/bits>>, Len, Huff0, Acc) when Len > 1 ->
	{_, CharA, Huff1} = dec_huffman_lookup(Huff0, A),
	{_, CharB, Huff} = dec_huffman_lookup(Huff1, B),
	case {CharA, CharB} of
		{undefined, undefined} -> dec_huffman(R, Len - 1, Huff, Acc);
		{CharA, undefined} -> dec_huffman(R, Len - 1, Huff, <<Acc/binary, CharA>>);
		{undefined, CharB} -> dec_huffman(R, Len - 1, Huff, <<Acc/binary, CharB>>);
		{CharA, CharB} -> dec_huffman(R, Len - 1, Huff, <<Acc/binary, CharA, CharB>>)
	end;
dec_huffman(<<A:4, B:4, Rest/bits>>, 1, Huff0, Acc) ->
	{_, CharA, Huff} = dec_huffman_lookup(Huff0, A),
	{ok, CharB, _} = dec_huffman_lookup(Huff, B),
	case {CharA, CharB} of
		%% {undefined, undefined} (> 7-bit final padding) is rejected with a crash.
		{CharA, undefined} ->
			{<<Acc/binary, CharA>>, Rest};
		{undefined, CharB} ->
			{<<Acc/binary, CharB>>, Rest};
		_ ->
			{<<Acc/binary, CharA, CharB>>, Rest}
	end;
%% Can only be reached when the string length to decode is 0.
dec_huffman(Rest, 0, _, <<>>) ->
	{<<>>, Rest}.

-include("cow_hpack_dec_huffman_lookup.hrl").

-ifdef(TEST).
%% Test case extracted from h2spec.
decode_reject_eos_test() ->
	{'EXIT', _} = (catch decode(<<16#0085f2b24a84ff874951fffffffa7f:120>>)),
	ok.

req_decode_test() ->
	%% First request (raw then huffman).
	{Headers1, State1} = decode(<< 16#828684410f7777772e6578616d706c652e636f6d:160 >>),
	{Headers1, State1} = decode(<< 16#828684418cf1e3c2e5f23a6ba0ab90f4ff:136 >>),
	Headers1 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>}
	],
	#state{size=57, dyn_table=[{57,{<<":authority">>, <<"www.example.com">>}}]} = State1,
	%% Second request (raw then huffman).
	{Headers2, State2} = decode(<< 16#828684be58086e6f2d6361636865:112 >>, State1),
	{Headers2, State2} = decode(<< 16#828684be5886a8eb10649cbf:96 >>, State1),
	Headers2 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"cache-control">>, <<"no-cache">>}
	],
	#state{size=110, dyn_table=[
		{53,{<<"cache-control">>, <<"no-cache">>}},
		{57,{<<":authority">>, <<"www.example.com">>}}]} = State2,
	%% Third request (raw then huffman).
	{Headers3, State3} = decode(<< 16#828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565:232 >>, State2),
	{Headers3, State3} = decode(<< 16#828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf:192 >>, State2),
	Headers3 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":path">>, <<"/index.html">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"custom-key">>, <<"custom-value">>}
	],
	#state{size=164, dyn_table=[
		{54,{<<"custom-key">>, <<"custom-value">>}},
		{53,{<<"cache-control">>, <<"no-cache">>}},
		{57,{<<":authority">>, <<"www.example.com">>}}]} = State3,
	ok.

resp_decode_test() ->
	%% Use a max_size of 256 to trigger header evictions.
	State0 = init(256),
	%% First response (raw then huffman).
	{Headers1, State1} = decode(<< 16#4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d:560 >>, State0),
	{Headers1, State1} = decode(<< 16#488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3:432 >>, State0),
	Headers1 = [
		{<<":status">>, <<"302">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	#state{size=222, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State1,
	%% Second response (raw then huffman).
	{Headers2, State2} = decode(<< 16#4803333037c1c0bf:64 >>, State1),
	{Headers2, State2} = decode(<< 16#4883640effc1c0bf:64 >>, State1),
	Headers2 = [
		{<<":status">>, <<"307">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	#state{size=222, dyn_table=[
		{42,{<<":status">>, <<"307">>}},
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}}]} = State2,
	%% Third response (raw then huffman).
	{Headers3, State3} = decode(<< 16#88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31:784 >>, State2),
	{Headers3, State3} = decode(<< 16#88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007:632 >>, State2),
	Headers3 = [
		{<<":status">>, <<"200">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:22 GMT">>},
		{<<"location">>, <<"https://www.example.com">>},
		{<<"content-encoding">>, <<"gzip">>},
		{<<"set-cookie">>, <<"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1">>}
	],
	#state{size=215, dyn_table=[
		{98,{<<"set-cookie">>, <<"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1">>}},
		{52,{<<"content-encoding">>, <<"gzip">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:22 GMT">>}}]} = State3,
	ok.

table_update_decode_test() ->
	%% Use a max_size of 256 to trigger header evictions
	%% when the code is not updating the max size.
	State0 = init(256),
	%% First response (raw then huffman).
	{Headers1, State1} = decode(<< 16#4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d:560 >>, State0),
	{Headers1, State1} = decode(<< 16#488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3:432 >>, State0),
	Headers1 = [
		{<<":status">>, <<"302">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	#state{size=222, configured_max_size=256, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State1,
	%% Set a new configured max_size to avoid header evictions.
	State2 = set_max_size(512, State1),
	%% Second response with the table size update (raw then huffman).
	MaxSize = enc_big_int(512 - 31, <<>>),
	{Headers2, State3} = decode(
		iolist_to_binary([<< 2#00111111>>, MaxSize, <<16#4803333037c1c0bf:64>>]),
		State2),
	{Headers2, State3} = decode(
		iolist_to_binary([<< 2#00111111>>, MaxSize, <<16#4883640effc1c0bf:64>>]),
		State2),
	Headers2 = [
		{<<":status">>, <<"307">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	#state{size=264, configured_max_size=512, dyn_table=[
		{42,{<<":status">>, <<"307">>}},
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State3,
	ok.

table_update_decode_smaller_test() ->
	%% Use a max_size of 256 to trigger header evictions
	%% when the code is not updating the max size.
	State0 = init(256),
	%% First response (raw then huffman).
	{Headers1, State1} = decode(<< 16#4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d:560 >>, State0),
	{Headers1, State1} = decode(<< 16#488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3:432 >>, State0),
	Headers1 = [
		{<<":status">>, <<"302">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	#state{size=222, configured_max_size=256, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State1,
	%% Set a new configured max_size to avoid header evictions.
	State2 = set_max_size(512, State1),
	%% Second response with the table size update smaller than the limit (raw then huffman).
	MaxSize = enc_big_int(400 - 31, <<>>),
	{Headers2, State3} = decode(
		iolist_to_binary([<< 2#00111111>>, MaxSize, <<16#4803333037c1c0bf:64>>]),
		State2),
	{Headers2, State3} = decode(
		iolist_to_binary([<< 2#00111111>>, MaxSize, <<16#4883640effc1c0bf:64>>]),
		State2),
	Headers2 = [
		{<<":status">>, <<"307">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	#state{size=264, configured_max_size=512, dyn_table=[
		{42,{<<":status">>, <<"307">>}},
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State3,
	ok.

table_update_decode_too_large_test() ->
	%% Use a max_size of 256 to trigger header evictions
	%% when the code is not updating the max size.
	State0 = init(256),
	%% First response (raw then huffman).
	{Headers1, State1} = decode(<< 16#4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d:560 >>, State0),
	{Headers1, State1} = decode(<< 16#488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3:432 >>, State0),
	Headers1 = [
		{<<":status">>, <<"302">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	#state{size=222, configured_max_size=256, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State1,
	%% Set a new configured max_size to avoid header evictions.
	State2 = set_max_size(512, State1),
	%% Second response with the table size update (raw then huffman).
	MaxSize = enc_big_int(1024 - 31, <<>>),
	{'EXIT', _} = (catch decode(
		iolist_to_binary([<< 2#00111111>>, MaxSize, <<16#4803333037c1c0bf:64>>]),
		State2)),
	{'EXIT', _} = (catch decode(
		iolist_to_binary([<< 2#00111111>>, MaxSize, <<16#4883640effc1c0bf:64>>]),
		State2)),
	ok.

table_update_decode_zero_test() ->
	State0 = init(256),
	%% First response (raw then huffman).
	{Headers1, State1} = decode(<< 16#4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d:560 >>, State0),
	{Headers1, State1} = decode(<< 16#488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3:432 >>, State0),
	Headers1 = [
		{<<":status">>, <<"302">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	#state{size=222, configured_max_size=256, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State1,
	%% Set a new configured max_size to avoid header evictions.
	State2 = set_max_size(512, State1),
	%% Second response with the table size update (raw then huffman).
	%% We set the table size to 0 to evict all values before setting
	%% it to 512 so we only get the second request indexed.
	MaxSize = enc_big_int(512 - 31, <<>>),
	{Headers1, State3} = decode(iolist_to_binary([
		<<2#00100000, 2#00111111>>, MaxSize,
		<<16#4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d:560>>]),
		State2),
	{Headers1, State3} = decode(iolist_to_binary([
		<<2#00100000, 2#00111111>>, MaxSize,
		<<16#488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3:432>>]),
		State2),
	#state{size=222, configured_max_size=512, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State3,
	ok.

horse_decode_raw() ->
	horse:repeat(20000,
		do_horse_decode_raw()
	).

do_horse_decode_raw() ->
	{_, State1} = decode(<<16#828684410f7777772e6578616d706c652e636f6d:160>>),
	{_, State2} = decode(<<16#828684be58086e6f2d6361636865:112>>, State1),
	{_, _} = decode(<<16#828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565:232>>, State2),
	ok.

horse_decode_huffman() ->
	horse:repeat(20000,
		do_horse_decode_huffman()
	).

do_horse_decode_huffman() ->
	{_, State1} = decode(<<16#828684418cf1e3c2e5f23a6ba0ab90f4ff:136>>),
	{_, State2} = decode(<<16#828684be5886a8eb10649cbf:96>>, State1),
	{_, _} = decode(<<16#828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf:192>>, State2),
	ok.
-endif.

%% Encoding.

-spec encode(cow_http:headers()) -> {iodata(), state()}.
encode(Headers) ->
	encode(Headers, init(), huffman, []).

-spec encode(cow_http:headers(), State) -> {iodata(), State} when State::state().
encode(Headers, State=#state{max_size=MaxSize, configured_max_size=MaxSize}) ->
	encode(Headers, State, huffman, []);
encode(Headers, State0=#state{configured_max_size=MaxSize}) ->
	State1 = table_update_size(MaxSize, State0),
	{Data, State} = encode(Headers, State1, huffman, []),
	{[enc_int5(MaxSize, 2#001)|Data], State}.

-spec encode(cow_http:headers(), State, opts()) -> {iodata(), State} when State::state().
encode(Headers, State=#state{max_size=MaxSize, configured_max_size=MaxSize}, Opts) ->
	encode(Headers, State, huffman_opt(Opts), []);
encode(Headers, State0=#state{configured_max_size=MaxSize}, Opts) ->
	State1 = table_update_size(MaxSize, State0),
	{Data, State} = encode(Headers, State1, huffman_opt(Opts), []),
	{[enc_int5(MaxSize, 2#001)|Data], State}.

huffman_opt(#{huffman := false}) -> no_huffman;
huffman_opt(_) -> huffman.

%% @todo Handle cases where no/never indexing is expected.
encode([], State, _, Acc) ->
	{lists:reverse(Acc), State};
encode([{Name, Value0}|Tail], State, HuffmanOpt, Acc) ->
	%% We conditionally call iolist_to_binary/1 because a small
	%% but noticeable speed improvement happens when we do this.
	Value = if
		is_binary(Value0) -> Value0;
		true -> iolist_to_binary(Value0)
	end,
	Header = {Name, Value},
	case table_find(Header, State) of
		%% Literal header field representation: new name.
		{_, not_found} ->
			State2 = table_insert(Header, State),
			encode(Tail, State2, HuffmanOpt,
				[[<< 0:1, 1:1, 0:6 >>|[enc_str(Name, HuffmanOpt)|enc_str(Value, HuffmanOpt)]]|Acc]);
		%% Indexed header field representation.
		{field, Index} ->
			encode(Tail, State, HuffmanOpt,
				[enc_int7(Index, 2#1)|Acc]);
		%% Literal header field representation: indexed name.
		{name, Index} ->
			State2 = table_insert(Header, State),
			encode(Tail, State2, HuffmanOpt,
				[[enc_int6(Index, 2#01)|enc_str(Value, HuffmanOpt)]|Acc])
	end.

%% Encode an integer.

enc_int5(Int, Prefix) when Int < 31 ->
	<< Prefix:3, Int:5 >>;
enc_int5(Int, Prefix) ->
	enc_big_int(Int - 31, << Prefix:3, 2#11111:5 >>).

enc_int6(Int, Prefix) when Int < 63 ->
	<< Prefix:2, Int:6 >>;
enc_int6(Int, Prefix) ->
	enc_big_int(Int - 63, << Prefix:2, 2#111111:6 >>).

enc_int7(Int, Prefix) when Int < 127 ->
	<< Prefix:1, Int:7 >>;
enc_int7(Int, Prefix) ->
	enc_big_int(Int - 127, << Prefix:1, 2#1111111:7 >>).

enc_big_int(Int, Acc) when Int < 128 ->
	<<Acc/binary, Int:8>>;
enc_big_int(Int, Acc) ->
	enc_big_int(Int bsr 7, <<Acc/binary, 1:1, Int:7>>).

%% Encode a string.

enc_str(Str, huffman) ->
	Str2 = enc_huffman(Str, <<>>),
	[enc_int7(byte_size(Str2), 2#1)|Str2];
enc_str(Str, no_huffman) ->
	[enc_int7(byte_size(Str), 2#0)|Str].

enc_huffman(<<>>, Acc) ->
	case bit_size(Acc) rem 8 of
		1 -> << Acc/bits, 2#1111111:7 >>;
		2 -> << Acc/bits, 2#111111:6 >>;
		3 -> << Acc/bits, 2#11111:5 >>;
		4 -> << Acc/bits, 2#1111:4 >>;
		5 -> << Acc/bits, 2#111:3 >>;
		6 -> << Acc/bits, 2#11:2 >>;
		7 -> << Acc/bits, 2#1:1 >>;
		0 -> Acc
	end;
enc_huffman(<< 0, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111000:13 >>);
enc_huffman(<< 1, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111011000:23 >>);
enc_huffman(<< 2, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111100010:28 >>);
enc_huffman(<< 3, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111100011:28 >>);
enc_huffman(<< 4, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111100100:28 >>);
enc_huffman(<< 5, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111100101:28 >>);
enc_huffman(<< 6, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111100110:28 >>);
enc_huffman(<< 7, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111100111:28 >>);
enc_huffman(<< 8, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111101000:28 >>);
enc_huffman(<< 9, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111101010:24 >>);
enc_huffman(<< 10, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111111111100:30 >>);
enc_huffman(<< 11, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111101001:28 >>);
enc_huffman(<< 12, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111101010:28 >>);
enc_huffman(<< 13, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111111111101:30 >>);
enc_huffman(<< 14, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111101011:28 >>);
enc_huffman(<< 15, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111101100:28 >>);
enc_huffman(<< 16, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111101101:28 >>);
enc_huffman(<< 17, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111101110:28 >>);
enc_huffman(<< 18, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111101111:28 >>);
enc_huffman(<< 19, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111110000:28 >>);
enc_huffman(<< 20, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111110001:28 >>);
enc_huffman(<< 21, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111110010:28 >>);
enc_huffman(<< 22, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111111111110:30 >>);
enc_huffman(<< 23, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111110011:28 >>);
enc_huffman(<< 24, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111110100:28 >>);
enc_huffman(<< 25, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111110101:28 >>);
enc_huffman(<< 26, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111110110:28 >>);
enc_huffman(<< 27, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111110111:28 >>);
enc_huffman(<< 28, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111111000:28 >>);
enc_huffman(<< 29, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111111001:28 >>);
enc_huffman(<< 30, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111111010:28 >>);
enc_huffman(<< 31, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111111011:28 >>);
enc_huffman(<< 32, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#010100:6 >>);
enc_huffman(<< 33, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111000:10 >>);
enc_huffman(<< 34, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111001:10 >>);
enc_huffman(<< 35, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111010:12 >>);
enc_huffman(<< 36, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111001:13 >>);
enc_huffman(<< 37, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#010101:6 >>);
enc_huffman(<< 38, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111000:8 >>);
enc_huffman(<< 39, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111010:11 >>);
enc_huffman(<< 40, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111010:10 >>);
enc_huffman(<< 41, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111011:10 >>);
enc_huffman(<< 42, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111001:8 >>);
enc_huffman(<< 43, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111011:11 >>);
enc_huffman(<< 44, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111010:8 >>);
enc_huffman(<< 45, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#010110:6 >>);
enc_huffman(<< 46, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#010111:6 >>);
enc_huffman(<< 47, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#011000:6 >>);
enc_huffman(<< 48, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#00000:5 >>);
enc_huffman(<< 49, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#00001:5 >>);
enc_huffman(<< 50, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#00010:5 >>);
enc_huffman(<< 51, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#011001:6 >>);
enc_huffman(<< 52, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#011010:6 >>);
enc_huffman(<< 53, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#011011:6 >>);
enc_huffman(<< 54, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#011100:6 >>);
enc_huffman(<< 55, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#011101:6 >>);
enc_huffman(<< 56, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#011110:6 >>);
enc_huffman(<< 57, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#011111:6 >>);
enc_huffman(<< 58, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1011100:7 >>);
enc_huffman(<< 59, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111011:8 >>);
enc_huffman(<< 60, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111100:15 >>);
enc_huffman(<< 61, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#100000:6 >>);
enc_huffman(<< 62, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111011:12 >>);
enc_huffman(<< 63, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111100:10 >>);
enc_huffman(<< 64, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111010:13 >>);
enc_huffman(<< 65, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#100001:6 >>);
enc_huffman(<< 66, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1011101:7 >>);
enc_huffman(<< 67, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1011110:7 >>);
enc_huffman(<< 68, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1011111:7 >>);
enc_huffman(<< 69, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1100000:7 >>);
enc_huffman(<< 70, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1100001:7 >>);
enc_huffman(<< 71, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1100010:7 >>);
enc_huffman(<< 72, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1100011:7 >>);
enc_huffman(<< 73, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1100100:7 >>);
enc_huffman(<< 74, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1100101:7 >>);
enc_huffman(<< 75, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1100110:7 >>);
enc_huffman(<< 76, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1100111:7 >>);
enc_huffman(<< 77, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1101000:7 >>);
enc_huffman(<< 78, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1101001:7 >>);
enc_huffman(<< 79, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1101010:7 >>);
enc_huffman(<< 80, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1101011:7 >>);
enc_huffman(<< 81, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1101100:7 >>);
enc_huffman(<< 82, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1101101:7 >>);
enc_huffman(<< 83, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1101110:7 >>);
enc_huffman(<< 84, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1101111:7 >>);
enc_huffman(<< 85, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1110000:7 >>);
enc_huffman(<< 86, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1110001:7 >>);
enc_huffman(<< 87, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1110010:7 >>);
enc_huffman(<< 88, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111100:8 >>);
enc_huffman(<< 89, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1110011:7 >>);
enc_huffman(<< 90, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111101:8 >>);
enc_huffman(<< 91, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111011:13 >>);
enc_huffman(<< 92, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111110000:19 >>);
enc_huffman(<< 93, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111100:13 >>);
enc_huffman(<< 94, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111100:14 >>);
enc_huffman(<< 95, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#100010:6 >>);
enc_huffman(<< 96, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111101:15 >>);
enc_huffman(<< 97, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#00011:5 >>);
enc_huffman(<< 98, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#100011:6 >>);
enc_huffman(<< 99, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#00100:5 >>);
enc_huffman(<< 100, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#100100:6 >>);
enc_huffman(<< 101, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#00101:5 >>);
enc_huffman(<< 102, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#100101:6 >>);
enc_huffman(<< 103, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#100110:6 >>);
enc_huffman(<< 104, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#100111:6 >>);
enc_huffman(<< 105, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#00110:5 >>);
enc_huffman(<< 106, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1110100:7 >>);
enc_huffman(<< 107, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1110101:7 >>);
enc_huffman(<< 108, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#101000:6 >>);
enc_huffman(<< 109, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#101001:6 >>);
enc_huffman(<< 110, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#101010:6 >>);
enc_huffman(<< 111, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#00111:5 >>);
enc_huffman(<< 112, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#101011:6 >>);
enc_huffman(<< 113, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1110110:7 >>);
enc_huffman(<< 114, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#101100:6 >>);
enc_huffman(<< 115, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#01000:5 >>);
enc_huffman(<< 116, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#01001:5 >>);
enc_huffman(<< 117, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#101101:6 >>);
enc_huffman(<< 118, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1110111:7 >>);
enc_huffman(<< 119, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111000:7 >>);
enc_huffman(<< 120, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111001:7 >>);
enc_huffman(<< 121, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111010:7 >>);
enc_huffman(<< 122, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111011:7 >>);
enc_huffman(<< 123, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111110:15 >>);
enc_huffman(<< 124, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111100:11 >>);
enc_huffman(<< 125, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111101:14 >>);
enc_huffman(<< 126, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111101:13 >>);
enc_huffman(<< 127, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111111100:28 >>);
enc_huffman(<< 128, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111100110:20 >>);
enc_huffman(<< 129, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111010010:22 >>);
enc_huffman(<< 130, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111100111:20 >>);
enc_huffman(<< 131, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111101000:20 >>);
enc_huffman(<< 132, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111010011:22 >>);
enc_huffman(<< 133, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111010100:22 >>);
enc_huffman(<< 134, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111010101:22 >>);
enc_huffman(<< 135, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111011001:23 >>);
enc_huffman(<< 136, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111010110:22 >>);
enc_huffman(<< 137, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111011010:23 >>);
enc_huffman(<< 138, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111011011:23 >>);
enc_huffman(<< 139, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111011100:23 >>);
enc_huffman(<< 140, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111011101:23 >>);
enc_huffman(<< 141, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111011110:23 >>);
enc_huffman(<< 142, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111101011:24 >>);
enc_huffman(<< 143, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111011111:23 >>);
enc_huffman(<< 144, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111101100:24 >>);
enc_huffman(<< 145, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111101101:24 >>);
enc_huffman(<< 146, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111010111:22 >>);
enc_huffman(<< 147, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111100000:23 >>);
enc_huffman(<< 148, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111101110:24 >>);
enc_huffman(<< 149, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111100001:23 >>);
enc_huffman(<< 150, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111100010:23 >>);
enc_huffman(<< 151, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111100011:23 >>);
enc_huffman(<< 152, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111100100:23 >>);
enc_huffman(<< 153, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111011100:21 >>);
enc_huffman(<< 154, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111011000:22 >>);
enc_huffman(<< 155, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111100101:23 >>);
enc_huffman(<< 156, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111011001:22 >>);
enc_huffman(<< 157, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111100110:23 >>);
enc_huffman(<< 158, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111100111:23 >>);
enc_huffman(<< 159, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111101111:24 >>);
enc_huffman(<< 160, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111011010:22 >>);
enc_huffman(<< 161, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111011101:21 >>);
enc_huffman(<< 162, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111101001:20 >>);
enc_huffman(<< 163, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111011011:22 >>);
enc_huffman(<< 164, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111011100:22 >>);
enc_huffman(<< 165, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111101000:23 >>);
enc_huffman(<< 166, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111101001:23 >>);
enc_huffman(<< 167, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111011110:21 >>);
enc_huffman(<< 168, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111101010:23 >>);
enc_huffman(<< 169, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111011101:22 >>);
enc_huffman(<< 170, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111011110:22 >>);
enc_huffman(<< 171, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111110000:24 >>);
enc_huffman(<< 172, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111011111:21 >>);
enc_huffman(<< 173, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111011111:22 >>);
enc_huffman(<< 174, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111101011:23 >>);
enc_huffman(<< 175, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111101100:23 >>);
enc_huffman(<< 176, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111100000:21 >>);
enc_huffman(<< 177, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111100001:21 >>);
enc_huffman(<< 178, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111100000:22 >>);
enc_huffman(<< 179, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111100010:21 >>);
enc_huffman(<< 180, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111101101:23 >>);
enc_huffman(<< 181, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111100001:22 >>);
enc_huffman(<< 182, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111101110:23 >>);
enc_huffman(<< 183, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111101111:23 >>);
enc_huffman(<< 184, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111101010:20 >>);
enc_huffman(<< 185, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111100010:22 >>);
enc_huffman(<< 186, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111100011:22 >>);
enc_huffman(<< 187, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111100100:22 >>);
enc_huffman(<< 188, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111110000:23 >>);
enc_huffman(<< 189, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111100101:22 >>);
enc_huffman(<< 190, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111100110:22 >>);
enc_huffman(<< 191, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111110001:23 >>);
enc_huffman(<< 192, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111100000:26 >>);
enc_huffman(<< 193, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111100001:26 >>);
enc_huffman(<< 194, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111101011:20 >>);
enc_huffman(<< 195, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111110001:19 >>);
enc_huffman(<< 196, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111100111:22 >>);
enc_huffman(<< 197, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111110010:23 >>);
enc_huffman(<< 198, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111101000:22 >>);
enc_huffman(<< 199, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111101100:25 >>);
enc_huffman(<< 200, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111100010:26 >>);
enc_huffman(<< 201, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111100011:26 >>);
enc_huffman(<< 202, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111100100:26 >>);
enc_huffman(<< 203, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111011110:27 >>);
enc_huffman(<< 204, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111011111:27 >>);
enc_huffman(<< 205, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111100101:26 >>);
enc_huffman(<< 206, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111110001:24 >>);
enc_huffman(<< 207, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111101101:25 >>);
enc_huffman(<< 208, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111110010:19 >>);
enc_huffman(<< 209, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111100011:21 >>);
enc_huffman(<< 210, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111100110:26 >>);
enc_huffman(<< 211, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111100000:27 >>);
enc_huffman(<< 212, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111100001:27 >>);
enc_huffman(<< 213, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111100111:26 >>);
enc_huffman(<< 214, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111100010:27 >>);
enc_huffman(<< 215, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111110010:24 >>);
enc_huffman(<< 216, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111100100:21 >>);
enc_huffman(<< 217, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111100101:21 >>);
enc_huffman(<< 218, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111101000:26 >>);
enc_huffman(<< 219, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111101001:26 >>);
enc_huffman(<< 220, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111111101:28 >>);
enc_huffman(<< 221, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111100011:27 >>);
enc_huffman(<< 222, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111100100:27 >>);
enc_huffman(<< 223, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111100101:27 >>);
enc_huffman(<< 224, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111101100:20 >>);
enc_huffman(<< 225, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111110011:24 >>);
enc_huffman(<< 226, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111101101:20 >>);
enc_huffman(<< 227, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111100110:21 >>);
enc_huffman(<< 228, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111101001:22 >>);
enc_huffman(<< 229, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111100111:21 >>);
enc_huffman(<< 230, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111101000:21 >>);
enc_huffman(<< 231, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111110011:23 >>);
enc_huffman(<< 232, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111101010:22 >>);
enc_huffman(<< 233, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111101011:22 >>);
enc_huffman(<< 234, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111101110:25 >>);
enc_huffman(<< 235, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111101111:25 >>);
enc_huffman(<< 236, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111110100:24 >>);
enc_huffman(<< 237, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111110101:24 >>);
enc_huffman(<< 238, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111101010:26 >>);
enc_huffman(<< 239, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111110100:23 >>);
enc_huffman(<< 240, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111101011:26 >>);
enc_huffman(<< 241, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111100110:27 >>);
enc_huffman(<< 242, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111101100:26 >>);
enc_huffman(<< 243, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111101101:26 >>);
enc_huffman(<< 244, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111100111:27 >>);
enc_huffman(<< 245, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111101000:27 >>);
enc_huffman(<< 246, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111101001:27 >>);
enc_huffman(<< 247, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111101010:27 >>);
enc_huffman(<< 248, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111101011:27 >>);
enc_huffman(<< 249, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#1111111111111111111111111110:28 >>);
enc_huffman(<< 250, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111101100:27 >>);
enc_huffman(<< 251, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111101101:27 >>);
enc_huffman(<< 252, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111101110:27 >>);
enc_huffman(<< 253, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111101111:27 >>);
enc_huffman(<< 254, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#111111111111111111111110000:27 >>);
enc_huffman(<< 255, R/bits >>, A) -> enc_huffman(R, << A/bits, 2#11111111111111111111101110:26 >>).

-ifdef(TEST).
req_encode_test() ->
	%% First request (raw then huffman).
	Headers1 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>}
	],
	{Raw1, State1} = encode(Headers1, init(), #{huffman => false}),
	<< 16#828684410f7777772e6578616d706c652e636f6d:160 >> = iolist_to_binary(Raw1),
	{Huff1, State1} = encode(Headers1),
	<< 16#828684418cf1e3c2e5f23a6ba0ab90f4ff:136 >> = iolist_to_binary(Huff1),
	#state{size=57, dyn_table=[{57,{<<":authority">>, <<"www.example.com">>}}]} = State1,
	%% Second request (raw then huffman).
	Headers2 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"cache-control">>, <<"no-cache">>}
	],
	{Raw2, State2} = encode(Headers2, State1, #{huffman => false}),
	<< 16#828684be58086e6f2d6361636865:112 >> = iolist_to_binary(Raw2),
	{Huff2, State2} = encode(Headers2, State1),
	<< 16#828684be5886a8eb10649cbf:96 >> = iolist_to_binary(Huff2),
	#state{size=110, dyn_table=[
		{53,{<<"cache-control">>, <<"no-cache">>}},
		{57,{<<":authority">>, <<"www.example.com">>}}]} = State2,
	%% Third request (raw then huffman).
	Headers3 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":path">>, <<"/index.html">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"custom-key">>, <<"custom-value">>}
	],
	{Raw3, State3} = encode(Headers3, State2, #{huffman => false}),
	<< 16#828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565:232 >> = iolist_to_binary(Raw3),
	{Huff3, State3} = encode(Headers3, State2),
	<< 16#828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf:192 >> = iolist_to_binary(Huff3),
	#state{size=164, dyn_table=[
		{54,{<<"custom-key">>, <<"custom-value">>}},
		{53,{<<"cache-control">>, <<"no-cache">>}},
		{57,{<<":authority">>, <<"www.example.com">>}}]} = State3,
	ok.

resp_encode_test() ->
	%% Use a max_size of 256 to trigger header evictions.
	State0 = init(256),
	%% First response (raw then huffman).
	Headers1 = [
		{<<":status">>, <<"302">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	{Raw1, State1} = encode(Headers1, State0, #{huffman => false}),
	<< 16#4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d:560 >> = iolist_to_binary(Raw1),
	{Huff1, State1} = encode(Headers1, State0),
	<< 16#488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3:432 >> = iolist_to_binary(Huff1),
	#state{size=222, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = State1,
	%% Second response (raw then huffman).
	Headers2 = [
		{<<":status">>, <<"307">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	{Raw2, State2} = encode(Headers2, State1, #{huffman => false}),
	<< 16#4803333037c1c0bf:64 >> = iolist_to_binary(Raw2),
	{Huff2, State2} = encode(Headers2, State1),
	<< 16#4883640effc1c0bf:64 >> = iolist_to_binary(Huff2),
	#state{size=222, dyn_table=[
		{42,{<<":status">>, <<"307">>}},
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}}]} = State2,
	%% Third response (raw then huffman).
	Headers3 = [
		{<<":status">>, <<"200">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:22 GMT">>},
		{<<"location">>, <<"https://www.example.com">>},
		{<<"content-encoding">>, <<"gzip">>},
		{<<"set-cookie">>, <<"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1">>}
	],
	{Raw3, State3} = encode(Headers3, State2, #{huffman => false}),
	<< 16#88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31:784 >> = iolist_to_binary(Raw3),
	{Huff3, State3} = encode(Headers3, State2),
	<< 16#88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007:632 >> = iolist_to_binary(Huff3),
	#state{size=215, dyn_table=[
		{98,{<<"set-cookie">>, <<"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1">>}},
		{52,{<<"content-encoding">>, <<"gzip">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:22 GMT">>}}]} = State3,
	ok.

%% This test assumes that table updates work correctly when decoding.
table_update_encode_test() ->
	%% Use a max_size of 256 to trigger header evictions
	%% when the code is not updating the max size.
	DecState0 = EncState0 = init(256),
	%% First response.
	Headers1 = [
		{<<":status">>, <<"302">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	{Encoded1, EncState1} = encode(Headers1, EncState0),
	{Headers1, DecState1} = decode(iolist_to_binary(Encoded1), DecState0),
	#state{size=222, configured_max_size=256, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = DecState1,
	#state{size=222, configured_max_size=256, dyn_table=[
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = EncState1,
	%% Set a new configured max_size to avoid header evictions.
	DecState2 = set_max_size(512, DecState1),
	EncState2 = set_max_size(512, EncState1),
	%% Second response.
	Headers2 = [
		{<<":status">>, <<"307">>},
		{<<"cache-control">>, <<"private">>},
		{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
		{<<"location">>, <<"https://www.example.com">>}
	],
	{Encoded2, EncState3} = encode(Headers2, EncState2),
	{Headers2, DecState3} = decode(iolist_to_binary(Encoded2), DecState2),
	#state{size=264, max_size=512, dyn_table=[
		{42,{<<":status">>, <<"307">>}},
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = DecState3,
	#state{size=264, max_size=512, dyn_table=[
		{42,{<<":status">>, <<"307">>}},
		{63,{<<"location">>, <<"https://www.example.com">>}},
		{65,{<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>}},
		{52,{<<"cache-control">>, <<"private">>}},
		{42,{<<":status">>, <<"302">>}}]} = EncState3,
	ok.

%% Check that encode/2 is using the new table size after calling
%% set_max_size/1 and that adding entries larger than the max size
%% results in an empty table.
table_update_encode_max_size_0_test() ->
	%% Encoding starts with default max size
	EncState0 = init(),
	%% Decoding starts with max size of 0
	DecState0 = init(0),
	%% First request.
	Headers1 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>}
	],
	{Encoded1, EncState1} = encode(Headers1, EncState0),
	{Headers1, DecState1} = decode(iolist_to_binary(Encoded1), DecState0),
	#state{size=57, dyn_table=[{57,{<<":authority">>, <<"www.example.com">>}}]} = EncState1,
	#state{size=0, dyn_table=[]} = DecState1,
	%% Settings received after the first request.
	EncState2 = set_max_size(0, EncState1),
	#state{configured_max_size=0, max_size=4096,
	       size=57, dyn_table=[{57,{<<":authority">>, <<"www.example.com">>}}]} = EncState2,
	%% Second request.
	Headers2 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"cache-control">>, <<"no-cache">>}
	],
	{Encoded2, EncState3} = encode(Headers2, EncState2),
	{Headers2, DecState2} = decode(iolist_to_binary(Encoded2), DecState1),
	#state{configured_max_size=0, max_size=0, size=0, dyn_table=[]} = EncState3,
	#state{size=0, dyn_table=[]} = DecState2,
	ok.

encode_iolist_test() ->
	Headers = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"content-type">>, [<<"image">>,<<"/">>,<<"png">>,<<>>]}
	],
	{_, _} = encode(Headers),
	ok.

horse_encode_raw() ->
	horse:repeat(20000,
		do_horse_encode_raw()
	).

do_horse_encode_raw() ->
	Headers1 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>}
	],
	{_, State1} = encode(Headers1, init(), #{huffman => false}),
	Headers2 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"cache-control">>, <<"no-cache">>}
	],
	{_, State2} = encode(Headers2, State1, #{huffman => false}),
	Headers3 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":path">>, <<"/index.html">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"custom-key">>, <<"custom-value">>}
	],
	{_, _} = encode(Headers3, State2, #{huffman => false}),
	ok.

horse_encode_huffman() ->
	horse:repeat(20000,
		do_horse_encode_huffman()
	).

do_horse_encode_huffman() ->
	Headers1 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>}
	],
	{_, State1} = encode(Headers1),
	Headers2 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"cache-control">>, <<"no-cache">>}
	],
	{_, State2} = encode(Headers2, State1),
	Headers3 = [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":path">>, <<"/index.html">>},
		{<<":authority">>, <<"www.example.com">>},
		{<<"custom-key">>, <<"custom-value">>}
	],
	{_, _} = encode(Headers3, State2),
	ok.
-endif.

%% Static and dynamic tables.

%% @todo There must be a more efficient way.
table_find(Header = {Name, _}, #state{dyn_table=DynamicTable}) ->
	case table_find_index_by_field(Header, DynamicTable) of
		{_, not_found} ->
			table_find_index_by_name(Name, DynamicTable);
		Found ->
			Found
	end.
table_find_index_by_field(Header, DynamicTable) ->
	case find_index_in_static(Header) of
		not_found ->
			{field, table_find_field_dyn(Header, DynamicTable, length(?STATIC_HEADERS) + 1)};
		Index ->
			{field, Index}
	end.
table_find_index_by_name(Name, DynamicTable) ->
	case find_index_in_static(Name) of
		not_found ->
			{name, table_find_name_dyn(Name, DynamicTable, length(?STATIC_HEADERS) + 1)};
		Index ->
			{name, Index}
	end.

table_find_field_dyn(_, [], _) -> not_found;
table_find_field_dyn(Header, [{_, Header}|_], Index) -> Index;
table_find_field_dyn(Header, [_|Tail], Index) -> table_find_field_dyn(Header, Tail, Index + 1).

table_find_name_dyn(_, [], _) -> not_found;
table_find_name_dyn(Name, [{Name, _}|_], Index) -> Index;
table_find_name_dyn(Name, [_|Tail], Index) -> table_find_name_dyn(Name, Tail, Index + 1).

find_index_in_static(Field) when is_binary(Field) ->
	case lists:keyfind(Field, 1, ?STATIC_HEADERS) of
		false ->
			not_found;
		Header ->
			find_index_in_static(?STATIC_HEADERS, Header, 1)
	end;
find_index_in_static(Header) when is_tuple(Header) ->
	case lists:member(Header, ?STATIC_HEADERS) of
		true ->
			find_index_in_static(?STATIC_HEADERS, Header, 1);
		false ->
			not_found
	end;
find_index_in_static(_) ->
	not_found.

find_index_in_static([], _, _) ->
	not_found;
find_index_in_static([CurrentHeader | Rest], Header, Index) ->
	case CurrentHeader of
		Header ->
			Index;
		_ ->
			find_index_in_static(Rest, Header, Index + 1)
	end.

get_header(Index, List) when is_integer(Index) andalso Index > 0 andalso Index =< length(List) ->
	lists:nth(Index, List);
get_header(_, _) ->
	{<<>>, <<>>}.

get_header_in_static(Index) ->
	get_header(Index, ?STATIC_HEADERS).

get_header_in_dynamic(Index, DynamicTable) when is_integer(Index) ->
	{_, Header} = get_header(Index - length(?STATIC_HEADERS), DynamicTable),
	case Header of
		<<>> -> {<<>>, <<>>};
		_ -> Header
	end;
get_header_in_dynamic(_, _) ->
	{<<>>, <<>>}.

table_get(Index, #state{dyn_table=DynamicTable}) when is_integer(Index) ->
	case get_header_in_static(Index) of
		{<<>>, <<>>} ->
			get_header_in_dynamic(Index, DynamicTable);
		Found ->
			Found
	end;
table_get(_, _) ->
	{<<>>, <<>>}.

table_get_name(Index, State) ->
	{Name, _} = table_get(Index, State),
	Name.

table_insert(Entry = {Name, Value}, State=#state{size=Size, max_size=MaxSize, dyn_table=DynamicTable}) ->
	EntrySize = byte_size(Name) + byte_size(Value) + 32,
	if
		EntrySize + Size =< MaxSize ->
			%% Add entry without eviction
			State#state{size=Size + EntrySize, dyn_table=[{EntrySize, Entry}|DynamicTable]};
		EntrySize =< MaxSize ->
			%% Evict, then add entry
			{DynamicTable2, Size2} = table_resize(DynamicTable, MaxSize - EntrySize, 0, []),
			State#state{size=Size2 + EntrySize, dyn_table=[{EntrySize, Entry}|DynamicTable2]};
		EntrySize > MaxSize ->
			%% "an attempt to add an entry larger than the
			%% maximum size causes the table to be emptied
			%% of all existing entries and results in an
			%% empty table" (RFC 7541, 4.4)
			State#state{size=0, dyn_table=[]}
	end.

table_resize([], _, Size, Acc) ->
	{lists:reverse(Acc), Size};
table_resize([{EntrySize, _}|_], MaxSize, Size, Acc) when Size + EntrySize > MaxSize ->
	{lists:reverse(Acc), Size};
table_resize([Entry = {EntrySize, _}|Tail], MaxSize, Size, Acc) ->
	table_resize(Tail, MaxSize, Size + EntrySize, [Entry|Acc]).

table_update_size(0, State) ->
	State#state{size=0, max_size=0, dyn_table=[]};
table_update_size(MaxSize, State=#state{size=CurrentSize})
		when CurrentSize =< MaxSize ->
	State#state{max_size=MaxSize};
table_update_size(MaxSize, State=#state{dyn_table=DynTable}) ->
	{DynTable2, Size} = table_resize(DynTable, MaxSize, 0, []),
	State#state{size=Size, max_size=MaxSize, dyn_table=DynTable2}.

-ifdef(TEST).
prop_str_raw() ->
	?FORALL(Str, binary(), begin
		{Str, <<>>} =:= dec_str(iolist_to_binary(enc_str(Str, no_huffman)))
	end).

prop_str_huffman() ->
	?FORALL(Str, binary(), begin
		{Str, <<>>} =:= dec_str(iolist_to_binary(enc_str(Str, huffman)))
	end).
-endif.
