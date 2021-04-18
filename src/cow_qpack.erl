%% Copyright (c) 2020, Loïc Hoguin <essen@ninenines.eu>
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

-module(cow_qpack).
-dialyzer(no_improper_lists).

-export([init/0]).

-export([decode_field_section/3]).
-export([execute_encoder_instructions/2]).
-export([decoder_cancel_stream/1]).

-export([encode_field_section/3]).
-export([execute_decoder_instructions/2]).

-record(state, {
	%% Entries common to encoder and decoder.
	size = 0 :: non_neg_integer(),
	max_table_capacity = 0 :: non_neg_integer(),
	num_dropped = 0 :: non_neg_integer(),
	dyn_table = [] :: [{pos_integer(), {binary(), binary()}}],

	%% Entries specific to encoder.
	draining_index = 0
}).

-opaque state() :: #state{}.
-export_type([state/0]).

%-ifdef(TEST).
%-include_lib("proper/include/proper.hrl").
%-endif.

-include("cow_hpack_common.hrl").

%% State initialization.

-spec init() -> state().
init() ->
	#state{}.

%% Decoding.

-spec decode_field_section(binary(), non_neg_integer(), State)
	-> {ok, cow_http:headers(), binary(), State}
	| {error, qpack_decompression_failed | qpack_encoder_stream_error, atom()}
	when State::state().
decode_field_section(Data, StreamID, State0) ->
	{EncodedInsertCount, <<S:1,Rest0/bits>>} = dec_big_int(Data, 0, 0),
	ReqInsertCount = decode_req_insert_count(EncodedInsertCount, State0),
	{DeltaBase, Rest} = dec_int7(Rest0),
	Base = case S of
		0 -> ReqInsertCount + DeltaBase;
		1 -> ReqInsertCount - DeltaBase - 1
	end,
	case decode(Rest, State0, Base, []) of
		{ok, Headers, State} when ReqInsertCount =:= 0 ->
			{ok, Headers, <<>>, State};
		{ok, Headers, State} ->
			{ok, Headers, enc_int7(StreamID, 2#1), State};
		Error ->
			Error
	end.

decode_req_insert_count(0, _) ->
	0;
decode_req_insert_count(EncodedInsertCount, #state{max_table_capacity=MaxTableCapacity,
		num_dropped=NumDropped, dyn_table=DynamicTable}) ->
	MaxEntries = MaxTableCapacity div 32,
	FullRange = 2 * MaxEntries,
	if
		EncodedInsertCount > FullRange ->
			{error, qpack_decompression_failed, 'TODO'};
		true ->
			TotalNumberOfInserts = NumDropped + length(DynamicTable),
			MaxValue = TotalNumberOfInserts + MaxEntries,
			MaxWrapped = (MaxValue div FullRange) * FullRange,
			ReqInsertCount = MaxWrapped + EncodedInsertCount - 1,
			if
				ReqInsertCount > MaxValue ->
					if
						ReqInsertCount =< FullRange ->
							{error, qpack_decompression_failed, 'TODO'};
						true ->
							ReqInsertCount - FullRange
					end;
				ReqInsertCount =:= 0 ->
					{error, qpack_decompression_failed, 'TODO'};
				true ->
					ReqInsertCount
			end
	end.

decode(<<>>, State, _, Acc) ->
	{ok, lists:reverse(Acc), State};
%% Indexed field line.
decode(<<2#1:1,T:1,Rest0/bits>>, State, Base, Acc) ->
	{Index, Rest} = dec_int6(Rest0),
	Entry = case T of
		0 -> table_get_dyn_pre_base(Index, Base, State);
		1 -> table_get_static(Index)
	end,
	decode(Rest, State, Base, [Entry|Acc]);
%% Indexed field line with post-base index.
decode(<<2#0001:4,Rest0/bits>>, State, Base, Acc) ->
	{Index, Rest} = dec_int4(Rest0),
	Entry = table_get_dyn_post_base(Index, Base, State),
	decode(Rest, State, Base, [Entry|Acc]);
%% Literal field line with name reference.
decode(<<2#01:2,N:1,T:1,Rest0/bits>>, State, Base, Acc) ->
	%% @todo N=1 the encoded field line MUST be encoded as literal, need to return metadata about this?
	{NameIndex, <<H:1,Rest1/bits>>} = dec_int4(Rest0),
	Name = case T of
%		0 -> table_get_name_dyn_rel( @todo
		1 -> table_get_name_static(NameIndex)
	end,
	{ValueLen, Rest2} = dec_int7(Rest1),
	{Value, Rest} = maybe_dec_huffman(Rest2, ValueLen, H),
	decode(Rest, State, Base, [{Name, Value}|Acc]);
%% Literal field line with post-base name reference.
decode(<<2#0000:4,N:1,Rest0/bits>>, State, Base, Acc) ->
	%% @todo N=1 the encoded field line MUST be encoded as literal, need to return metadata about this?
	{NameIndex, <<H:1,Rest1/bits>>} = dec_int3(Rest0),
	%% @todo NameIndex < Base
	%% @todo table_get_name_dyn_post_base(
	{ValueLen, Rest2} = dec_int7(Rest1),
	<<ValueStr:ValueLen/binary,Rest/bits>> = Rest2,
	%% @todo huffman decode when H=1
	todo;
%% Literal field line with literal name.
decode(<<2#001:3,N:1,NameH:1,Rest0/bits>>, State, Base, Acc) ->
	%% @todo N=1 the encoded field line MUST be encoded as literal, need to return metadata about this?
	{NameLen, Rest1} = dec_int3(Rest0),
	<<NameStr:NameLen/binary,ValueH:1,Rest2/bits>> = Rest1,
	%% @todo huffman decode when NameH=1
	{ValueLen, Rest3} = dec_int7(Rest2),
	<<ValueStr:ValueLen/binary,Rest/bits>> = Rest3,
	%% @todo huffman decode when ValueH=1
	todo.

-spec execute_encoder_instructions(binary(), State)
	-> {ok, State} | {error, qpack_encoder_stream_error, atom()}
	when State::state().
execute_encoder_instructions(<<>>, State) ->
	{ok, State};
%% Set dynamic table capacity.
execute_encoder_instructions(<<2#001:3,Rest0/bits>>, State) ->
	{Capacity, Rest} = dec_int5(Rest0),
	%% @todo + may result in an error
	execute_encoder_instructions(Rest, State#state{max_table_capacity=Capacity});
%% Insert with name reference.
execute_encoder_instructions(<<2#1:1,T:1,Rest0/bits>>, State0) ->
	{NameIndex, <<H:1,Rest1/bits>>} = dec_int6(Rest0),
	Name = case T of
		0 -> table_get_name_dyn_rel(NameIndex, State0);
		1 -> table_get_name_static(NameIndex)
	end,
	{ValueLen, Rest2} = dec_int7(Rest1),
	{Value, Rest} = maybe_dec_huffman(Rest2, ValueLen, H),
	State = table_insert({Name, Value}, State0),
	execute_encoder_instructions(Rest, State);
%% Insert with literal name.
execute_encoder_instructions(<<2#01:2,NameH:1,Rest0/bits>>, State0) ->
	{NameLen, Rest1} = dec_int5(Rest0),
	{Name, <<ValueH:1,Rest2/bits>>} = maybe_dec_huffman(Rest1, NameLen, NameH),
	{ValueLen, Rest3} = dec_int7(Rest2),
	{Value, Rest} = maybe_dec_huffman(Rest3, ValueLen, ValueH),
	State = table_insert({Name, Value}, State0),
	execute_encoder_instructions(Rest, State);
%% Duplicate.
execute_encoder_instructions(<<2#000:3,Rest0/bits>>, State0) ->
	{Index, Rest} = dec_int5(Rest0),
	Entry = table_get_dyn_rel(Index, State0),
	State = table_insert(Entry, State0),
	execute_encoder_instructions(Rest, State).

decoder_cancel_stream(StreamID) ->
	enc_int6(StreamID, 2#01).

dec_int3(<<2#111:3,Rest/bits>>) ->
	dec_big_int(Rest, 7, 0);
dec_int3(<<Int:3,Rest/bits>>) ->
	{Int, Rest}.

dec_int4(<<2#1111:4,Rest/bits>>) ->
	dec_big_int(Rest, 15, 0);
dec_int4(<<Int:4,Rest/bits>>) ->
	{Int, Rest}.

dec_int6(<<2#111111:6,Rest/bits>>) ->
	dec_big_int(Rest, 63, 0);
dec_int6(<<Int:6,Rest/bits>>) ->
	{Int, Rest}.

dec_int7(<<2#1111111:7,Rest/bits>>) ->
	dec_big_int(Rest, 127, 0);
dec_int7(<<Int:7,Rest/bits>>) ->
	{Int, Rest}.

maybe_dec_huffman(Data, ValueLen, 0) ->
	<<Value:ValueLen/binary,Rest/bits>> = Data,
	{Value, Rest};
maybe_dec_huffman(Data, ValueLen, 1) ->
	dec_huffman(Data, ValueLen, 0, <<>>).

%% Encoding.

-spec encode_field_section(cow_http:headers(), non_neg_integer(), State)
	-> {ok, iodata(), binary(), State} when State::state().
%% @todo Would be good to know encoder stream flow control to avoid writing there. Opts?
encode_field_section(Headers, StreamID, State0) ->
	%% @todo Avoid this call, duplicate like in cow_hpack.
	encode_field_section(Headers, StreamID, State0, #{}).

encode_field_section(Headers, StreamID, State0=#state{max_table_capacity=MaxTableCapacity,
		num_dropped=NumDropped, dyn_table=DynamicTable}, Opts) ->
	Base = NumDropped + length(DynamicTable) + 1,
	{ReqInsertCount, EncData, Data, State} = encode(
		Headers, StreamID, State0,
		huffman_opt(Opts), 0, Base, [], []),
	case ReqInsertCount of
		0 ->
			{ok, [<<0:16>>|Data], EncData, State};
		_ ->
			MaxEntries = MaxTableCapacity div 32,
			EncInsertCount = (ReqInsertCount rem (2 * MaxEntries)) + 1,
			{S, DeltaBase} = if
				ReqInsertCount > Base ->
					{2#1, ReqInsertCount - Base};
				%% We never have a base higher than ReqInsertCount because
				%% we are updating the dynamic table as we go.
				ReqInsertCount =:= Base ->
					{2#0, 0}
			end,
			{ok, [enc_big_int(EncInsertCount, <<>>), enc_int7(DeltaBase, S)|Data], EncData, State}
	end.

encode([], _, State, HuffmanOpt, ReqInsertCount, _, EncAcc, Acc) ->
	{ReqInsertCount, lists:reverse(EncAcc), lists:reverse(Acc), State};
encode([{Name, Value0}|Tail], StreamID, State0, HuffmanOpt, ReqInsertCount0, Base, EncAcc, Acc) ->
	%% We conditionally call iolist_to_binary/1 because a small
	%% but noticeable speed improvement happens when we do this.
	%% (Or at least it did for cow_hpack.)
	Value = if
		is_binary(Value0) -> Value0;
		true -> iolist_to_binary(Value0)
	end,
	Entry = {Name, Value},
	DrainIndex = 1, %% @todo
	case table_find_static(Entry) of
		not_found ->
			case table_find_dyn(Entry, State0) of
				not_found ->
					case table_find_name_static(Name) of
						not_found ->
							todo;
						StaticNameIndex ->
							case table_can_insert(Entry, State0) of
								true ->
									State = table_insert(Entry, State0),
									#state{num_dropped=NumDropped, dyn_table=DynamicTable} = State,
									ReqInsertCount = NumDropped + length(DynamicTable),
									PostBaseIndex = length(EncAcc),
									encode(Tail, StreamID, State, HuffmanOpt, ReqInsertCount, Base,
										[[enc_int6(StaticNameIndex, 2#11)|enc_str(Value, HuffmanOpt)]|EncAcc],
										[enc_int4(PostBaseIndex, 2#0001)|Acc]);
								false ->
									encode(Tail, StreamID, State0, HuffmanOpt, ReqInsertCount0, Base, EncAcc,
										[[enc_int4(StaticNameIndex, 2#0101)|enc_str(Value, HuffmanOpt)]|Acc])
							end
					end;
				%% When the index is below the drain index and there is enough
				%% space in the table for duplicating the value, we do that
				%% and use the duplicated index. If we can't then we must not
				%% use the dynamic index for the field.
				DynIndex when DynIndex =< DrainIndex ->
					case table_can_insert(Entry, State0) of
						true ->
							State = table_insert(Entry, State0),
							#state{num_dropped=NumDropped, dyn_table=DynamicTable} = State,
							ReqInsertCount = NumDropped + length(DynamicTable),
							%% - 1 because we already inserted the new entry in the table.
							DynIndexRel = ReqInsertCount - DynIndex - 1,
							PostBaseIndex = length(EncAcc),
							encode(Tail, StreamID, State, HuffmanOpt, ReqInsertCount, Base,
								[enc_int5(DynIndexRel, 2#000)|EncAcc],
								[enc_int6(Base - ReqInsertCount, 2#10)|Acc]);
						false ->
							todo %% @todo Same as not_found.
					end;
				DynIndex ->
					%% @todo We should check whether the value is below the drain index
					%% and if that's the case we either duplicate or not use the index
					%% depending on capacity.
					ReqInsertCount = if
						ReqInsertCount0 > DynIndex -> ReqInsertCount0;
						true -> DynIndex
					end,
					encode(Tail, StreamID, State0, HuffmanOpt, ReqInsertCount0, Base, EncAcc,
						[enc_int6(Base - DynIndex, 2#10)|Acc])
			end;
		StaticIndex ->
			encode(Tail, StreamID, State0, HuffmanOpt, ReqInsertCount0, Base, EncAcc,
				[enc_int6(StaticIndex, 2#11)|Acc])
	end.

-spec execute_decoder_instructions(binary(), State)
	-> {ok, State} | {error, qpack_decoder_stream_error, atom()}
	when State::state().
execute_decoder_instructions(<<>>, State) ->
	{ok, State};
%% Section acknowledgement.
execute_decoder_instructions(<<2#1:1,Rest0/bits>>, State) ->
	{StreamID, Rest} = dec_int7(Rest0),
	%% @todo Keep track of references.
	execute_decoder_instructions(Rest, State);
%% Stream cancellation.
execute_decoder_instructions(<<2#01:2,Rest0/bits>>, State) ->
	{StreamID, Rest} = dec_int6(Rest0),
	%% @todo Drop references.
	execute_decoder_instructions(Rest, State);
%% Insert count increment.
execute_decoder_instructions(<<2#00:2,Rest0/bits>>, State) ->
	{Increment, Rest} = dec_int6(Rest0),
	%% @todo Keep track of references.
	execute_decoder_instructions(Rest, State).

%% @todo spec
encoder_set_table_capacity(Capacity, State) ->
	{ok, enc_int5(Capacity, 2#001), State#state{max_table_capacity=Capacity}}.

%% @todo spec
encoder_insert_entry(Entry={Name, Value}, State0, Opts) ->
	State = table_insert(Entry, State0),
	HuffmanOpt = huffman_opt(Opts),
	case table_find_name_static(Name) of
		not_found ->
			case table_find_name_dyn(Name, State0) of
				not_found ->
					{ok, [enc_str6(Name, HuffmanOpt, 2#01)|enc_str(Value, HuffmanOpt)], State};
				DynNameIndex ->
					#state{num_dropped=NumDropped0, dyn_table=DynamicTable0} = State0,
					DynNameIndexRel = NumDropped0 + length(DynamicTable0) - DynNameIndex,
					{ok, [enc_int6(DynNameIndexRel, 2#10)|enc_str(Value, HuffmanOpt)], State}
			end;
		StaticNameIndex ->
			todo
	end.

huffman_opt(#{huffman := false}) -> no_huffman;
huffman_opt(_) -> huffman.

enc_int4(Int, Prefix) when Int < 15 ->
	<<Prefix:4, Int:4>>;
enc_int4(Int, Prefix) ->
	enc_big_int(Int - 15, <<Prefix:4, 2#1111:4>>).

enc_str6(Str, huffman, Prefix) ->
	Str2 = enc_huffman(Str, <<>>),
	[enc_int5(byte_size(Str2), Prefix * 2 + 2#1)|Str2];
enc_str6(Str, no_huffman, Prefix) ->
	[enc_int5(byte_size(Str), Prefix * 2 + 2#0)|Str].

%% Static and dynamic tables.

table_find_static({<<":authority">>, <<>>}) -> 0;
table_find_static({<<":path">>, <<"/">>}) -> 1;
table_find_static({<<"age">>, <<"0">>}) -> 2;
table_find_static({<<"content-disposition">>, <<>>}) -> 3;
table_find_static({<<"content-length">>, <<"0">>}) -> 4;
table_find_static({<<"cookie">>, <<>>}) -> 5;
table_find_static({<<"date">>, <<>>}) -> 6;
table_find_static({<<"etag">>, <<>>}) -> 7;
table_find_static({<<"if-modified-since">>, <<>>}) -> 8;
table_find_static({<<"if-none-match">>, <<>>}) -> 9;
table_find_static({<<"last-modified">>, <<>>}) -> 10;
table_find_static({<<"link">>, <<>>}) -> 11;
table_find_static({<<"location">>, <<>>}) -> 12;
table_find_static({<<"referer">>, <<>>}) -> 13;
table_find_static({<<"set-cookie">>, <<>>}) -> 14;
table_find_static({<<":method">>, <<"CONNECT">>}) -> 15;
table_find_static({<<":method">>, <<"DELETE">>}) -> 16;
table_find_static({<<":method">>, <<"GET">>}) -> 17;
table_find_static({<<":method">>, <<"HEAD">>}) -> 18;
table_find_static({<<":method">>, <<"OPTIONS">>}) -> 19;
table_find_static({<<":method">>, <<"POST">>}) -> 20;
table_find_static({<<":method">>, <<"PUT">>}) -> 21;
table_find_static({<<":scheme">>, <<"http">>}) -> 22;
table_find_static({<<":scheme">>, <<"https">>}) -> 23;
table_find_static({<<":status">>, <<"103">>}) -> 24;
table_find_static({<<":status">>, <<"200">>}) -> 25;
table_find_static({<<":status">>, <<"304">>}) -> 26;
table_find_static({<<":status">>, <<"404">>}) -> 27;
table_find_static({<<":status">>, <<"503">>}) -> 28;
table_find_static({<<"accept">>, <<"*/*">>}) -> 29;
table_find_static({<<"accept">>, <<"application/dns-message">>}) -> 30;
table_find_static({<<"accept-encoding">>, <<"gzip, deflate, br">>}) -> 31;
table_find_static({<<"accept-ranges">>, <<"bytes">>}) -> 32;
table_find_static({<<"access-control-allow-headers">>, <<"cache-control">>}) -> 33;
table_find_static({<<"access-control-allow-headers">>, <<"content-type">>}) -> 34;
table_find_static({<<"access-control-allow-origin">>, <<"*">>}) -> 35;
table_find_static({<<"cache-control">>, <<"max-age=0">>}) -> 36;
table_find_static({<<"cache-control">>, <<"max-age=2592000">>}) -> 37;
table_find_static({<<"cache-control">>, <<"max-age=604800">>}) -> 38;
table_find_static({<<"cache-control">>, <<"no-cache">>}) -> 39;
table_find_static({<<"cache-control">>, <<"no-store">>}) -> 40;
table_find_static({<<"cache-control">>, <<"public, max-age=31536000">>}) -> 41;
table_find_static({<<"content-encoding">>, <<"br">>}) -> 42;
table_find_static({<<"content-encoding">>, <<"gzip">>}) -> 43;
table_find_static({<<"content-type">>, <<"application/dns-message">>}) -> 44;
table_find_static({<<"content-type">>, <<"application/javascript">>}) -> 45;
table_find_static({<<"content-type">>, <<"application/json">>}) -> 46;
table_find_static({<<"content-type">>, <<"application/x-www-form-urlencoded">>}) -> 47;
table_find_static({<<"content-type">>, <<"image/gif">>}) -> 48;
table_find_static({<<"content-type">>, <<"image/jpeg">>}) -> 49;
table_find_static({<<"content-type">>, <<"image/png">>}) -> 50;
table_find_static({<<"content-type">>, <<"text/css">>}) -> 51;
table_find_static({<<"content-type">>, <<"text/html; charset=utf-8">>}) -> 52;
table_find_static({<<"content-type">>, <<"text/plain">>}) -> 53;
table_find_static({<<"content-type">>, <<"text/plain;charset=utf-8">>}) -> 54;
table_find_static({<<"range">>, <<"bytes=0-">>}) -> 55;
table_find_static({<<"strict-transport-security">>, <<"max-age=31536000">>}) -> 56;
table_find_static({<<"strict-transport-security">>, <<"max-age=31536000; includesubdomains">>}) -> 57;
table_find_static({<<"strict-transport-security">>, <<"max-age=31536000; includesubdomains; preload">>}) -> 58;
table_find_static({<<"vary">>, <<"accept-encoding">>}) -> 59;
table_find_static({<<"vary">>, <<"origin">>}) -> 60;
table_find_static({<<"x-content-type-options">>, <<"nosniff">>}) -> 61;
table_find_static({<<"x-xss-protection">>, <<"1; mode=block">>}) -> 62;
table_find_static({<<":status">>, <<"100">>}) -> 63;
table_find_static({<<":status">>, <<"204">>}) -> 64;
table_find_static({<<":status">>, <<"206">>}) -> 65;
table_find_static({<<":status">>, <<"302">>}) -> 66;
table_find_static({<<":status">>, <<"400">>}) -> 67;
table_find_static({<<":status">>, <<"403">>}) -> 68;
table_find_static({<<":status">>, <<"421">>}) -> 69;
table_find_static({<<":status">>, <<"425">>}) -> 70;
table_find_static({<<":status">>, <<"500">>}) -> 71;
table_find_static({<<"accept-language">>, <<>>}) -> 72;
table_find_static({<<"access-control-allow-credentials">>, <<"FALSE">>}) -> 73;
table_find_static({<<"access-control-allow-credentials">>, <<"TRUE">>}) -> 74;
table_find_static({<<"access-control-allow-headers">>, <<"*">>}) -> 75;
table_find_static({<<"access-control-allow-methods">>, <<"get">>}) -> 76;
table_find_static({<<"access-control-allow-methods">>, <<"get, post, options">>}) -> 77;
table_find_static({<<"access-control-allow-methods">>, <<"options">>}) -> 78;
table_find_static({<<"access-control-expose-headers">>, <<"content-length">>}) -> 79;
table_find_static({<<"access-control-request-headers">>, <<"content-type">>}) -> 80;
table_find_static({<<"access-control-request-method">>, <<"get">>}) -> 81;
table_find_static({<<"access-control-request-method">>, <<"post">>}) -> 82;
table_find_static({<<"alt-svc">>, <<"clear">>}) -> 83;
table_find_static({<<"authorization">>, <<>>}) -> 84;
table_find_static({<<"content-security-policy">>, <<"script-src 'none'; object-src 'none'; base-uri 'none'">>}) -> 85;
table_find_static({<<"early-data">>, <<"1">>}) -> 86;
table_find_static({<<"expect-ct">>, <<>>}) -> 87;
table_find_static({<<"forwarded">>, <<>>}) -> 88;
table_find_static({<<"if-range">>, <<>>}) -> 89;
table_find_static({<<"origin">>, <<>>}) -> 90;
table_find_static({<<"purpose">>, <<"prefetch">>}) -> 91;
table_find_static({<<"server">>, <<>>}) -> 92;
table_find_static({<<"timing-allow-origin">>, <<"*">>}) -> 93;
table_find_static({<<"upgrade-insecure-requests">>, <<"1">>}) -> 94;
table_find_static({<<"user-agent">>, <<>>}) -> 95;
table_find_static({<<"x-forwarded-for">>, <<>>}) -> 96;
table_find_static({<<"x-frame-options">>, <<"deny">>}) -> 97;
table_find_static({<<"x-frame-options">>, <<"sameorigin">>}) -> 98;
table_find_static(_) -> not_found.

table_find_name_static(<<":authority">>) -> 0;
table_find_name_static(<<":path">>) -> 1;
table_find_name_static(<<"age">>) -> 2;
table_find_name_static(<<"content-disposition">>) -> 3;
table_find_name_static(<<"content-length">>) -> 4;
table_find_name_static(<<"cookie">>) -> 5;
table_find_name_static(<<"date">>) -> 6;
table_find_name_static(<<"etag">>) -> 7;
table_find_name_static(<<"if-modified-since">>) -> 8;
table_find_name_static(<<"if-none-match">>) -> 9;
table_find_name_static(<<"last-modified">>) -> 10;
table_find_name_static(<<"link">>) -> 11;
table_find_name_static(<<"location">>) -> 12;
table_find_name_static(<<"referer">>) -> 13;
table_find_name_static(<<"set-cookie">>) -> 14;
table_find_name_static(<<":method">>) -> 15;
table_find_name_static(<<":scheme">>) -> 22;
table_find_name_static(<<":status">>) -> 24;
table_find_name_static(<<"accept">>) -> 29;
table_find_name_static(<<"accept-encoding">>) -> 31;
table_find_name_static(<<"accept-ranges">>) -> 32;
table_find_name_static(<<"access-control-allow-headers">>) -> 33;
table_find_name_static(<<"access-control-allow-origin">>) -> 35;
table_find_name_static(<<"cache-control">>) -> 36;
table_find_name_static(<<"content-encoding">>) -> 42;
table_find_name_static(<<"content-type">>) -> 44;
table_find_name_static(<<"range">>) -> 55;
table_find_name_static(<<"strict-transport-security">>) -> 56;
table_find_name_static(<<"vary">>) -> 59;
table_find_name_static(<<"x-content-type-options">>) -> 61;
table_find_name_static(<<"x-xss-protection">>) -> 62;
table_find_name_static(<<"accept-language">>) -> 72;
table_find_name_static(<<"access-control-allow-credentials">>) -> 73;
table_find_name_static(<<"access-control-allow-methods">>) -> 76;
table_find_name_static(<<"access-control-expose-headers">>) -> 79;
table_find_name_static(<<"access-control-request-headers">>) -> 80;
table_find_name_static(<<"access-control-request-method">>) -> 81;
table_find_name_static(<<"alt-svc">>) -> 83;
table_find_name_static(<<"authorization">>) -> 84;
table_find_name_static(<<"content-security-policy">>) -> 85;
table_find_name_static(<<"early-data">>) -> 86;
table_find_name_static(<<"expect-ct">>) -> 87;
table_find_name_static(<<"forwarded">>) -> 88;
table_find_name_static(<<"if-range">>) -> 89;
table_find_name_static(<<"origin">>) -> 90;
table_find_name_static(<<"purpose">>) -> 91;
table_find_name_static(<<"server">>) -> 92;
table_find_name_static(<<"timing-allow-origin">>) -> 93;
table_find_name_static(<<"upgrade-insecure-requests">>) -> 94;
table_find_name_static(<<"user-agent">>) -> 95;
table_find_name_static(<<"x-forwarded-for">>) -> 96;
table_find_name_static(<<"x-frame-options">>) -> 97;
table_find_name_static(_) -> not_found.

table_get_static(0) -> {<<":authority">>, <<>>};
table_get_static(1) -> {<<":path">>, <<"/">>};
table_get_static(2) -> {<<"age">>, <<"0">>};
table_get_static(3) -> {<<"content-disposition">>, <<>>};
table_get_static(4) -> {<<"content-length">>, <<"0">>};
table_get_static(5) -> {<<"cookie">>, <<>>};
table_get_static(6) -> {<<"date">>, <<>>};
table_get_static(7) -> {<<"etag">>, <<>>};
table_get_static(8) -> {<<"if-modified-since">>, <<>>};
table_get_static(9) -> {<<"if-none-match">>, <<>>};
table_get_static(10) -> {<<"last-modified">>, <<>>};
table_get_static(11) -> {<<"link">>, <<>>};
table_get_static(12) -> {<<"location">>, <<>>};
table_get_static(13) -> {<<"referer">>, <<>>};
table_get_static(14) -> {<<"set-cookie">>, <<>>};
table_get_static(15) -> {<<":method">>, <<"CONNECT">>};
table_get_static(16) -> {<<":method">>, <<"DELETE">>};
table_get_static(17) -> {<<":method">>, <<"GET">>};
table_get_static(18) -> {<<":method">>, <<"HEAD">>};
table_get_static(19) -> {<<":method">>, <<"OPTIONS">>};
table_get_static(20) -> {<<":method">>, <<"POST">>};
table_get_static(21) -> {<<":method">>, <<"PUT">>};
table_get_static(22) -> {<<":scheme">>, <<"http">>};
table_get_static(23) -> {<<":scheme">>, <<"https">>};
table_get_static(24) -> {<<":status">>, <<"103">>};
table_get_static(25) -> {<<":status">>, <<"200">>};
table_get_static(26) -> {<<":status">>, <<"304">>};
table_get_static(27) -> {<<":status">>, <<"404">>};
table_get_static(28) -> {<<":status">>, <<"503">>};
table_get_static(29) -> {<<"accept">>, <<"*/*">>};
table_get_static(30) -> {<<"accept">>, <<"application/dns-message">>};
table_get_static(31) -> {<<"accept-encoding">>, <<"gzip, deflate, br">>};
table_get_static(32) -> {<<"accept-ranges">>, <<"bytes">>};
table_get_static(33) -> {<<"access-control-allow-headers">>, <<"cache-control">>};
table_get_static(34) -> {<<"access-control-allow-headers">>, <<"content-type">>};
table_get_static(35) -> {<<"access-control-allow-origin">>, <<"*">>};
table_get_static(36) -> {<<"cache-control">>, <<"max-age=0">>};
table_get_static(37) -> {<<"cache-control">>, <<"max-age=2592000">>};
table_get_static(38) -> {<<"cache-control">>, <<"max-age=604800">>};
table_get_static(39) -> {<<"cache-control">>, <<"no-cache">>};
table_get_static(40) -> {<<"cache-control">>, <<"no-store">>};
table_get_static(41) -> {<<"cache-control">>, <<"public, max-age=31536000">>};
table_get_static(42) -> {<<"content-encoding">>, <<"br">>};
table_get_static(43) -> {<<"content-encoding">>, <<"gzip">>};
table_get_static(44) -> {<<"content-type">>, <<"application/dns-message">>};
table_get_static(45) -> {<<"content-type">>, <<"application/javascript">>};
table_get_static(46) -> {<<"content-type">>, <<"application/json">>};
table_get_static(47) -> {<<"content-type">>, <<"application/x-www-form-urlencoded">>};
table_get_static(48) -> {<<"content-type">>, <<"image/gif">>};
table_get_static(49) -> {<<"content-type">>, <<"image/jpeg">>};
table_get_static(50) -> {<<"content-type">>, <<"image/png">>};
table_get_static(51) -> {<<"content-type">>, <<"text/css">>};
table_get_static(52) -> {<<"content-type">>, <<"text/html; charset=utf-8">>};
table_get_static(53) -> {<<"content-type">>, <<"text/plain">>};
table_get_static(54) -> {<<"content-type">>, <<"text/plain;charset=utf-8">>};
table_get_static(55) -> {<<"range">>, <<"bytes=0-">>};
table_get_static(56) -> {<<"strict-transport-security">>, <<"max-age=31536000">>};
table_get_static(57) -> {<<"strict-transport-security">>, <<"max-age=31536000; includesubdomains">>};
table_get_static(58) -> {<<"strict-transport-security">>, <<"max-age=31536000; includesubdomains; preload">>};
table_get_static(59) -> {<<"vary">>, <<"accept-encoding">>};
table_get_static(60) -> {<<"vary">>, <<"origin">>};
table_get_static(61) -> {<<"x-content-type-options">>, <<"nosniff">>};
table_get_static(62) -> {<<"x-xss-protection">>, <<"1; mode=block">>};
table_get_static(63) -> {<<":status">>, <<"100">>};
table_get_static(64) -> {<<":status">>, <<"204">>};
table_get_static(65) -> {<<":status">>, <<"206">>};
table_get_static(66) -> {<<":status">>, <<"302">>};
table_get_static(67) -> {<<":status">>, <<"400">>};
table_get_static(68) -> {<<":status">>, <<"403">>};
table_get_static(69) -> {<<":status">>, <<"421">>};
table_get_static(70) -> {<<":status">>, <<"425">>};
table_get_static(71) -> {<<":status">>, <<"500">>};
table_get_static(72) -> {<<"accept-language">>, <<>>};
table_get_static(73) -> {<<"access-control-allow-credentials">>, <<"FALSE">>};
table_get_static(74) -> {<<"access-control-allow-credentials">>, <<"TRUE">>};
table_get_static(75) -> {<<"access-control-allow-headers">>, <<"*">>};
table_get_static(76) -> {<<"access-control-allow-methods">>, <<"get">>};
table_get_static(77) -> {<<"access-control-allow-methods">>, <<"get, post, options">>};
table_get_static(78) -> {<<"access-control-allow-methods">>, <<"options">>};
table_get_static(79) -> {<<"access-control-expose-headers">>, <<"content-length">>};
table_get_static(80) -> {<<"access-control-request-headers">>, <<"content-type">>};
table_get_static(81) -> {<<"access-control-request-method">>, <<"get">>};
table_get_static(82) -> {<<"access-control-request-method">>, <<"post">>};
table_get_static(83) -> {<<"alt-svc">>, <<"clear">>};
table_get_static(84) -> {<<"authorization">>, <<>>};
table_get_static(85) -> {<<"content-security-policy">>, <<"script-src 'none'; object-src 'none'; base-uri 'none'">>};
table_get_static(86) -> {<<"early-data">>, <<"1">>};
table_get_static(87) -> {<<"expect-ct">>, <<>>};
table_get_static(88) -> {<<"forwarded">>, <<>>};
table_get_static(89) -> {<<"if-range">>, <<>>};
table_get_static(90) -> {<<"origin">>, <<>>};
table_get_static(91) -> {<<"purpose">>, <<"prefetch">>};
table_get_static(92) -> {<<"server">>, <<>>};
table_get_static(93) -> {<<"timing-allow-origin">>, <<"*">>};
table_get_static(94) -> {<<"upgrade-insecure-requests">>, <<"1">>};
table_get_static(95) -> {<<"user-agent">>, <<>>};
table_get_static(96) -> {<<"x-forwarded-for">>, <<>>};
table_get_static(97) -> {<<"x-frame-options">>, <<"deny">>};
table_get_static(98) -> {<<"x-frame-options">>, <<"sameorigin">>}.

table_get_name_static(0) -> <<":authority">>;
table_get_name_static(1) -> <<":path">>;
table_get_name_static(2) -> <<"age">>;
table_get_name_static(3) -> <<"content-disposition">>;
table_get_name_static(4) -> <<"content-length">>;
table_get_name_static(5) -> <<"cookie">>;
table_get_name_static(6) -> <<"date">>;
table_get_name_static(7) -> <<"etag">>;
table_get_name_static(8) -> <<"if-modified-since">>;
table_get_name_static(9) -> <<"if-none-match">>;
table_get_name_static(10) -> <<"last-modified">>;
table_get_name_static(11) -> <<"link">>;
table_get_name_static(12) -> <<"location">>;
table_get_name_static(13) -> <<"referer">>;
table_get_name_static(14) -> <<"set-cookie">>;
table_get_name_static(15) -> <<":method">>;
table_get_name_static(16) -> <<":method">>;
table_get_name_static(17) -> <<":method">>;
table_get_name_static(18) -> <<":method">>;
table_get_name_static(19) -> <<":method">>;
table_get_name_static(20) -> <<":method">>;
table_get_name_static(21) -> <<":method">>;
table_get_name_static(22) -> <<":scheme">>;
table_get_name_static(23) -> <<":scheme">>;
table_get_name_static(24) -> <<":status">>;
table_get_name_static(25) -> <<":status">>;
table_get_name_static(26) -> <<":status">>;
table_get_name_static(27) -> <<":status">>;
table_get_name_static(28) -> <<":status">>;
table_get_name_static(29) -> <<"accept">>;
table_get_name_static(30) -> <<"accept">>;
table_get_name_static(31) -> <<"accept-encoding">>;
table_get_name_static(32) -> <<"accept-ranges">>;
table_get_name_static(33) -> <<"access-control-allow-headers">>;
table_get_name_static(34) -> <<"access-control-allow-headers">>;
table_get_name_static(35) -> <<"access-control-allow-origin">>;
table_get_name_static(36) -> <<"cache-control">>;
table_get_name_static(37) -> <<"cache-control">>;
table_get_name_static(38) -> <<"cache-control">>;
table_get_name_static(39) -> <<"cache-control">>;
table_get_name_static(40) -> <<"cache-control">>;
table_get_name_static(41) -> <<"cache-control">>;
table_get_name_static(42) -> <<"content-encoding">>;
table_get_name_static(43) -> <<"content-encoding">>;
table_get_name_static(44) -> <<"content-type">>;
table_get_name_static(45) -> <<"content-type">>;
table_get_name_static(46) -> <<"content-type">>;
table_get_name_static(47) -> <<"content-type">>;
table_get_name_static(48) -> <<"content-type">>;
table_get_name_static(49) -> <<"content-type">>;
table_get_name_static(50) -> <<"content-type">>;
table_get_name_static(51) -> <<"content-type">>;
table_get_name_static(52) -> <<"content-type">>;
table_get_name_static(53) -> <<"content-type">>;
table_get_name_static(54) -> <<"content-type">>;
table_get_name_static(55) -> <<"range">>;
table_get_name_static(56) -> <<"strict-transport-security">>;
table_get_name_static(57) -> <<"strict-transport-security">>;
table_get_name_static(58) -> <<"strict-transport-security">>;
table_get_name_static(59) -> <<"vary">>;
table_get_name_static(60) -> <<"vary">>;
table_get_name_static(61) -> <<"x-content-type-options">>;
table_get_name_static(62) -> <<"x-xss-protection">>;
table_get_name_static(63) -> <<":status">>;
table_get_name_static(64) -> <<":status">>;
table_get_name_static(65) -> <<":status">>;
table_get_name_static(66) -> <<":status">>;
table_get_name_static(67) -> <<":status">>;
table_get_name_static(68) -> <<":status">>;
table_get_name_static(69) -> <<":status">>;
table_get_name_static(70) -> <<":status">>;
table_get_name_static(71) -> <<":status">>;
table_get_name_static(72) -> <<"accept-language">>;
table_get_name_static(73) -> <<"access-control-allow-credentials">>;
table_get_name_static(74) -> <<"access-control-allow-credentials">>;
table_get_name_static(75) -> <<"access-control-allow-headers">>;
table_get_name_static(76) -> <<"access-control-allow-methods">>;
table_get_name_static(77) -> <<"access-control-allow-methods">>;
table_get_name_static(78) -> <<"access-control-allow-methods">>;
table_get_name_static(79) -> <<"access-control-expose-headers">>;
table_get_name_static(80) -> <<"access-control-request-headers">>;
table_get_name_static(81) -> <<"access-control-request-method">>;
table_get_name_static(82) -> <<"access-control-request-method">>;
table_get_name_static(83) -> <<"alt-svc">>;
table_get_name_static(84) -> <<"authorization">>;
table_get_name_static(85) -> <<"content-security-policy">>;
table_get_name_static(86) -> <<"early-data">>;
table_get_name_static(87) -> <<"expect-ct">>;
table_get_name_static(88) -> <<"forwarded">>;
table_get_name_static(89) -> <<"if-range">>;
table_get_name_static(90) -> <<"origin">>;
table_get_name_static(91) -> <<"purpose">>;
table_get_name_static(92) -> <<"server">>;
table_get_name_static(93) -> <<"timing-allow-origin">>;
table_get_name_static(94) -> <<"upgrade-insecure-requests">>;
table_get_name_static(95) -> <<"user-agent">>;
table_get_name_static(96) -> <<"x-forwarded-for">>;
table_get_name_static(97) -> <<"x-frame-options">>;
table_get_name_static(98) -> <<"x-frame-options">>.

%% @todo We should check if we can evict.
%% @todo We should make sure we have a large enough flow control window.
table_can_insert({Name, Value}, #state{size=Size, max_table_capacity=MaxTableCapacity}) ->
	EntrySize = byte_size(Name) + byte_size(Value) + 32,
	if
		EntrySize + Size =< MaxTableCapacity ->
			true;
		true ->
			false
	end.

table_insert(Entry={Name, Value}, State=#state{size=Size0, max_table_capacity=MaxTableCapacity,
		num_dropped=NumDropped, dyn_table=DynamicTable0}) ->
	EntrySize = byte_size(Name) + byte_size(Value) + 32,
	if
		EntrySize + Size0 =< MaxTableCapacity ->
			State#state{size=Size0 + EntrySize, dyn_table=[{EntrySize, Entry}|DynamicTable0]};
		EntrySize =< MaxTableCapacity ->
			case table_evict(DynamicTable0, MaxTableCapacity - EntrySize, 0, []) of
				Error={error, _, _} ->
					Error;
				{DynamicTable, Size, NewDropped} ->
					State#state{size=Size + EntrySize, num_dropped=NumDropped + NewDropped,
						dyn_table=[{EntrySize, Entry}|DynamicTable]}
			end;
		true -> % EntrySize > MaxTableCapacity ->
			{error, qpack_encoder_stream_error, 'TODO'}
	end.

table_evict([], _, Size, Acc) ->
	{lists:reverse(Acc), Size, 0};
%% @todo Need to check whether entries are evictable.
table_evict(Dropped=[{EntrySize, _}|_], MaxSize, Size, Acc) when Size + EntrySize > MaxSize ->
	{lists:reverse(Acc), Size, length(Dropped)};
table_evict([Entry = {EntrySize, _}|Tail], MaxSize, Size, Acc) ->
	table_evict(Tail, MaxSize, Size + EntrySize, [Entry|Acc]).

table_find_dyn(Entry, #state{num_dropped=NumDropped, dyn_table=DynamicTable}) ->
	table_find_dyn(Entry, DynamicTable, NumDropped + length(DynamicTable)).

table_find_dyn(_, [], _) ->
	not_found;
table_find_dyn(Entry, [{_, Entry}|_], Index) ->
	Index;
table_find_dyn(Entry, [_|Tail], Index) ->
	table_find_dyn(Entry, Tail, Index - 1).

table_find_name_dyn(Name, #state{num_dropped=NumDropped, dyn_table=DynamicTable}) ->
	table_find_name_dyn(Name, DynamicTable, NumDropped + length(DynamicTable)).

table_find_name_dyn(_, [], _) ->
	not_found;
table_find_name_dyn(Name, [{_, {Name, _}}|_], Index) ->
	Index;
table_find_name_dyn(Name, [_|Tail], Index) ->
	table_find_name_dyn(Name, Tail, Index - 1).

%% @todo These functions may error out if the encoder is invalid (2.2.3. Invalid References).
table_get_dyn_abs(Index, #state{num_dropped=NumDropped, dyn_table=DynamicTable}) ->
	%% @todo Perhaps avoid this length/1 call.
	{_, Header} = lists:nth(NumDropped + length(DynamicTable) - Index, DynamicTable),
	Header.

table_get_dyn_rel(Index, #state{dyn_table=DynamicTable}) ->
	{_, Header} = lists:nth(1 + Index, DynamicTable),
	Header.

table_get_name_dyn_rel(Index, State) ->
	{Name, _} = table_get_dyn_rel(Index, State),
	Name.

table_get_dyn_pre_base(Index, Base, #state{num_dropped=NumDropped, dyn_table=DynamicTable}) ->
	%% @todo Perhaps avoid this length/1 call.
	BaseOffset = NumDropped + length(DynamicTable) - Base,
	{_, Header} = lists:nth(1 + Index + BaseOffset, DynamicTable),
	Header.

table_get_dyn_post_base(Index, Base, State) ->
	table_get_dyn_abs(Base + Index, State).

-ifdef(TEST).
%% @todo table_insert_test including evictions

table_get_dyn_abs_test() ->
	State0 = (init())#state{max_table_capacity=1000},
	State1 = table_insert({<<"g">>, <<"h">>},
		table_insert({<<"e">>, <<"f">>},
		table_insert({<<"c">>, <<"d">>},
		table_insert({<<"a">>, <<"b">>},
		State0)))),
	{<<"a">>, <<"b">>} = table_get_dyn_abs(0, State1),
	{<<"c">>, <<"d">>} = table_get_dyn_abs(1, State1),
	{<<"e">>, <<"f">>} = table_get_dyn_abs(2, State1),
	{<<"g">>, <<"h">>} = table_get_dyn_abs(3, State1),
	%% Evict one member from the table.
	#state{dyn_table=DynamicTable} = State1,
	State2 = State1#state{num_dropped=1, dyn_table=lists:reverse(tl(lists:reverse(DynamicTable)))},
	{<<"c">>, <<"d">>} = table_get_dyn_abs(1, State2),
	{<<"e">>, <<"f">>} = table_get_dyn_abs(2, State2),
	{<<"g">>, <<"h">>} = table_get_dyn_abs(3, State2),
	ok.

table_get_dyn_rel_test() ->
	State0 = (init())#state{max_table_capacity=1000},
	State1 = table_insert({<<"g">>, <<"h">>},
		table_insert({<<"e">>, <<"f">>},
		table_insert({<<"c">>, <<"d">>},
		table_insert({<<"a">>, <<"b">>},
		State0)))),
	{<<"g">>, <<"h">>} = table_get_dyn_rel(0, State1),
	{<<"e">>, <<"f">>} = table_get_dyn_rel(1, State1),
	{<<"c">>, <<"d">>} = table_get_dyn_rel(2, State1),
	{<<"a">>, <<"b">>} = table_get_dyn_rel(3, State1),
	%% Evict one member from the table.
	#state{dyn_table=DynamicTable} = State1,
	State2 = State1#state{num_dropped=1, dyn_table=lists:reverse(tl(lists:reverse(DynamicTable)))},
	{<<"g">>, <<"h">>} = table_get_dyn_rel(0, State2),
	{<<"e">>, <<"f">>} = table_get_dyn_rel(1, State2),
	{<<"c">>, <<"d">>} = table_get_dyn_rel(2, State2),
	%% Add a member to the table.
	State3 = table_insert({<<"i">>, <<"j">>}, State2),
	{<<"i">>, <<"j">>} = table_get_dyn_rel(0, State3),
	{<<"g">>, <<"h">>} = table_get_dyn_rel(1, State3),
	{<<"e">>, <<"f">>} = table_get_dyn_rel(2, State3),
	{<<"c">>, <<"d">>} = table_get_dyn_rel(3, State3),
	ok.

table_get_dyn_pre_base_test() ->
	State0 = (init())#state{max_table_capacity=1000},
	State1 = table_insert({<<"g">>, <<"h">>},
		table_insert({<<"e">>, <<"f">>},
		table_insert({<<"c">>, <<"d">>},
		table_insert({<<"a">>, <<"b">>},
		State0)))),
	{<<"e">>, <<"f">>} = table_get_dyn_pre_base(0, 3, State1),
	{<<"c">>, <<"d">>} = table_get_dyn_pre_base(1, 3, State1),
	{<<"a">>, <<"b">>} = table_get_dyn_pre_base(2, 3, State1),
	%% Evict one member from the table.
	#state{dyn_table=DynamicTable} = State1,
	State2 = State1#state{num_dropped=1, dyn_table=lists:reverse(tl(lists:reverse(DynamicTable)))},
	{<<"e">>, <<"f">>} = table_get_dyn_pre_base(0, 3, State2),
	{<<"c">>, <<"d">>} = table_get_dyn_pre_base(1, 3, State2),
	%% Add a member to the table.
	State3 = table_insert({<<"i">>, <<"j">>}, State2),
	{<<"e">>, <<"f">>} = table_get_dyn_pre_base(0, 3, State3),
	{<<"c">>, <<"d">>} = table_get_dyn_pre_base(1, 3, State3),
	ok.

table_get_dyn_post_base_test() ->
	State0 = (init())#state{max_table_capacity=1000},
	State1 = table_insert({<<"g">>, <<"h">>},
		table_insert({<<"e">>, <<"f">>},
		table_insert({<<"c">>, <<"d">>},
		table_insert({<<"a">>, <<"b">>},
		State0)))),
	{<<"e">>, <<"f">>} = table_get_dyn_post_base(0, 2, State1),
	{<<"g">>, <<"h">>} = table_get_dyn_post_base(1, 2, State1),
	%% Evict one member from the table.
	#state{dyn_table=DynamicTable} = State1,
	State2 = State1#state{num_dropped=1, dyn_table=lists:reverse(tl(lists:reverse(DynamicTable)))},
	{<<"e">>, <<"f">>} = table_get_dyn_post_base(0, 2, State2),
	{<<"g">>, <<"h">>} = table_get_dyn_post_base(1, 2, State2),
	%% Add a member to the table.
	State3 = table_insert({<<"i">>, <<"j">>}, State2),
	{<<"e">>, <<"f">>} = table_get_dyn_post_base(0, 2, State3),
	{<<"g">>, <<"h">>} = table_get_dyn_post_base(1, 2, State3),
	{<<"i">>, <<"j">>} = table_get_dyn_post_base(2, 2, State3),
	ok.
-endif.

-ifdef(TEST).
appendix_b_decoder_test() ->
	%% Stream: 0
	{ok, [
		{<<":path">>, <<"/index.html">>}
	], <<>>, DecState0} = decode_field_section(<<
		16#0000:16,
		16#510b:16, 16#2f69:16, 16#6e64:16, 16#6578:16,
		16#2e68:16, 16#746d:16, 16#6c
	>>, 0, init()),
	#state{
		size=0,
		max_table_capacity=0,
		num_dropped=0,
		dyn_table=[]
	} = DecState0,
	%% Stream: Encoder
	{ok, DecState1} = execute_encoder_instructions(<<
		16#3fbd01:24,
		16#c00f:16, 16#7777:16, 16#772e:16, 16#6578:16,
		16#616d:16, 16#706c:16, 16#652e:16, 16#636f:16,
		16#6d,
		16#c10c:16, 16#2f73:16, 16#616d:16, 16#706c:16,
		16#652f:16, 16#7061:16, 16#7468:16
	>>, DecState0),
	#state{
		size=106,
		max_table_capacity=220,
		num_dropped=0,
		%% The dynamic table is in reverse order.
		dyn_table=[
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		]
	} = DecState1,
	%% Stream: 4
	{ok, [
		{<<":authority">>, <<"www.example.com">>},
		{<<":path">>, <<"/sample/path">>}
	], <<16#84>>, DecState2} = decode_field_section(<<
		16#0381:16,
		16#10,
		16#11
	>>, 4, DecState1),
	DecState1 = DecState2,
%% @todo
%% Stream: Decoder
%	{ok, EncState3} = execute_decoder_instructions(<<
%		16#84
%	>>, EncState2),
	%% Stream: Encoder
	{ok, DecState3} = execute_encoder_instructions(<<
		16#4a63:16, 16#7573:16, 16#746f:16, 16#6d2d:16,
		16#6b65:16, 16#790c:16, 16#6375:16, 16#7374:16,
		16#6f6d:16, 16#2d76:16, 16#616c:16, 16#7565:16
	>>, DecState2),
	#state{
		size=160,
		max_table_capacity=220,
		num_dropped=0,
		dyn_table=[
			{54, {<<"custom-key">>, <<"custom-value">>}},
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		]
	} = DecState3,
%% @todo
%% Stream: Decoder
%	{ok, EncStateX} = execute_decoder_instructions(<<
%		16#01
%	>>, EncStateY),
	%% Stream: Encoder
	{ok, DecState4} = execute_encoder_instructions(<<
		16#02
	>>, DecState3),
	#state{
		size=217,
		max_table_capacity=220,
		num_dropped=0,
		dyn_table=[
			{57, {<<":authority">>, <<"www.example.com">>}},
			{54, {<<"custom-key">>, <<"custom-value">>}},
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		]
	} = DecState4,
	%% Stream: 8
	%%
	%% Note that this one is not really received by the decoder
	%% so we will ignore the decoder state and instructions before we continue.
	{ok, [
		{<<":authority">>, <<"www.example.com">>},
		{<<":path">>, <<"/">>},
		{<<"custom-key">>, <<"custom-value">>}
	], <<16#88>>, IgnoredDecState} = decode_field_section(<<
		16#0500:16,
		16#80,
		16#c1,
		16#81
	>>, 8, DecState4),
	%% @todo True for now, but we need to keep track of non-evictable entries. (Even in the decoder though?)
	DecState4 = IgnoredDecState,
	%% Stream: Decoder - Stream Cancellation (Stream=8)
	<<16#48>> = decoder_cancel_stream(8),
%% @todo
%% Stream: Decoder
%	{ok, EncStateX} = execute_decoder_instructions(<<
%		16#48
%	>>, EncStateY),
	{ok, DecState5} = execute_encoder_instructions(<<
		16#810d:16, 16#6375:16, 16#7374:16, 16#6f6d:16,
		16#2d76:16, 16#616c:16, 16#7565:16, 16#32
	>>, DecState4),
	#state{
		size=215,
		max_table_capacity=220,
		num_dropped=1,
		dyn_table=[
			{55, {<<"custom-key">>, <<"custom-value2">>}},
			{57, {<<":authority">>, <<"www.example.com">>}},
			{54, {<<"custom-key">>, <<"custom-value">>}},
			{49, {<<":path">>, <<"/sample/path">>}}
		]
	} = DecState5,
	ok.

appendix_b_encoder_test() ->
	%% Stream: 0
	{ok, Data0, EncData0, EncState0} = encode_field_section([
		{<<":path">>, <<"/index.html">>}
	], 0, init(), #{huffman => false}),
	<<>> = iolist_to_binary(EncData0),
	<<
		16#0000:16,
		16#510b:16, 16#2f69:16, 16#6e64:16, 16#6578:16,
		16#2e68:16, 16#746d:16, 16#6c
	>> = iolist_to_binary(Data0),
	#state{
		size=0,
		max_table_capacity=0,
		num_dropped=0,
		dyn_table=[],
		draining_index=0
	} = EncState0,
	%% Stream: Encoder
	{ok, <<16#3fbd01:24>>, EncState1} = encoder_set_table_capacity(220, EncState0),
	#state{
		size=0,
		max_table_capacity=220,
		num_dropped=0,
		dyn_table=[],
		draining_index=0
	} = EncState1,
	%% Stream: 4 (and Encoder)
	{ok, Data2, EncData2, EncState2} = encode_field_section([
		{<<":authority">>, <<"www.example.com">>},
		{<<":path">>, <<"/sample/path">>}
	], 4, EncState1, #{huffman => false}),
	<<
		16#c00f:16, 16#7777:16, 16#772e:16, 16#6578:16,
		16#616d:16, 16#706c:16, 16#652e:16, 16#636f:16,
		16#6d,
		16#c10c:16, 16#2f73:16, 16#616d:16, 16#706c:16,
		16#652f:16, 16#7061:16, 16#7468:16
	>> = iolist_to_binary(EncData2),
	<<
		16#0381:16,
		16#10,
		16#11
	>> = iolist_to_binary(Data2),
	#state{
		size=106,
		max_table_capacity=220,
		num_dropped=0,
		%% The dynamic table is in reverse order.
		dyn_table=[
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		],
		draining_index=0
	} = EncState2,
	%% Stream: Decoder
	{ok, EncState3} = execute_decoder_instructions(<<16#84>>, EncState2),
	%% @todo We should keep track of what was acknowledged.
	#state{
		size=106,
		max_table_capacity=220,
		num_dropped=0,
		%% The dynamic table is in reverse order.
		dyn_table=[
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		],
		draining_index=0
	} = EncState3,
	%% Stream: Encoder
	{ok, EncData4, EncState4} = encoder_insert_entry(
		{<<"custom-key">>, <<"custom-value">>},
		EncState3, #{huffman => false}),
	<<
		16#4a63:16, 16#7573:16, 16#746f:16, 16#6d2d:16,
		16#6b65:16, 16#790c:16, 16#6375:16, 16#7374:16,
		16#6f6d:16, 16#2d76:16, 16#616c:16, 16#7565:16
	>> = iolist_to_binary(EncData4),
	%% @todo This is probably where we ought to increment the draining_index.
	#state{
		size=160,
		max_table_capacity=220,
		num_dropped=0,
		%% The dynamic table is in reverse order.
		dyn_table=[
			{54, {<<"custom-key">>, <<"custom-value">>}},
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		],
		draining_index=0
	} = EncState4,
	%% Stream: Decoder
	{ok, EncState5} = execute_decoder_instructions(<<16#01>>, EncState4),
	%% @todo We should keep track of what was acknowledged.
	#state{
		size=160,
		max_table_capacity=220,
		num_dropped=0,
		%% The dynamic table is in reverse order.
		dyn_table=[
			{54, {<<"custom-key">>, <<"custom-value">>}},
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		],
		draining_index=0
	} = EncState5,
	%% Stream: 8 (and Encoder)
	{ok, Data6, EncData6, EncState6} = encode_field_section([
		{<<":authority">>, <<"www.example.com">>},
		{<<":path">>, <<"/">>},
		{<<"custom-key">>, <<"custom-value">>}
	], 8, EncState5),
	<<16#02>> = iolist_to_binary(EncData6),
	<<
		16#0500:16,
		16#80,
		16#c1,
		16#81
	>> = iolist_to_binary(Data6),
	#state{
		size=217,
		max_table_capacity=220,
		num_dropped=0,
		%% The dynamic table is in reverse order.
		dyn_table=[
			{57, {<<":authority">>, <<"www.example.com">>}},
			{54, {<<"custom-key">>, <<"custom-value">>}},
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		],
		draining_index=0
	} = EncState6,
	%% Stream: Decoder
	{ok, EncState7} = execute_decoder_instructions(<<16#48>>, EncState6),
	%% @todo We should keep track of references.
	#state{
		size=217,
		max_table_capacity=220,
		num_dropped=0,
		%% The dynamic table is in reverse order.
		dyn_table=[
			{57, {<<":authority">>, <<"www.example.com">>}},
			{54, {<<"custom-key">>, <<"custom-value">>}},
			{49, {<<":path">>, <<"/sample/path">>}},
			{57, {<<":authority">>, <<"www.example.com">>}}
		],
		draining_index=0
	} = EncState7,
	%% Stream: Encoder
	{ok, EncData8, EncState8} = encoder_insert_entry(
		{<<"custom-key">>, <<"custom-value2">>},
		EncState7, #{huffman => false}),
	<<
		16#810d:16, 16#6375:16, 16#7374:16, 16#6f6d:16,
		16#2d76:16, 16#616c:16, 16#7565:16, 16#32
	>> = iolist_to_binary(EncData8),
	#state{
		size=215,
		max_table_capacity=220,
		num_dropped=1,
		%% The dynamic table is in reverse order.
		dyn_table=[
			{55, {<<"custom-key">>, <<"custom-value2">>}},
			{57, {<<":authority">>, <<"www.example.com">>}},
			{54, {<<"custom-key">>, <<"custom-value">>}},
			{49, {<<":path">>, <<"/sample/path">>}}
		],
		draining_index=0
	} = EncState8,
	ok.
-endif.
