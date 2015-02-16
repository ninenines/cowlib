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

-module(cow_ws).

-export([parse_header/3]).
-export([parse_close_code/2]).
-export([parse_payload/9]).
-export([frame/2]).

-type close_code() :: 1000..1003 | 1006..1011 | 3000..4999.
-export_type([close_code/0]).

-type frag_state() :: undefined | {fin | nofin, text | binary}.
-export_type([frag_state/0]).

-type frame() :: close | ping | pong
	| {text | binary | close | ping | pong, iodata()}
	| {close, close_code(), iodata()}.
-export_type([frame/0]).

-type extensions() :: map().
-type frame_type() :: fragment | text | binary | close | ping | pong.
-type mask_key() :: undefined | 0..16#ffffffff.
-type rsv() :: <<_:3>>.
-type utf8_state() :: <<>> | <<_:8>> | <<_:16>> | <<_:24>>.

%% @doc Parse and validate the Websocket frame header.
%%
%% This function also updates the fragmentation state according to
%% information found in the frame's header.

-spec parse_header(binary(), extensions(), frag_state())
	-> error | more | {frame_type(), frag_state(), rsv(), non_neg_integer(), mask_key(), binary()}.
%% RSV bits MUST be 0 unless an extension is negotiated
%% that defines meanings for non-zero values.
parse_header(<< _:1, Rsv:3, _/bits >>, Extensions, _) when Extensions =:= #{}, Rsv =/= 0 -> error;
%% Last 2 RSV bits MUST be 0 if deflate-frame extension is used.
parse_header(<< _:2, 1:1, _/bits >>, #{deflate_frame := _}, _) -> error;
parse_header(<< _:3, 1:1, _/bits >>, #{deflate_frame := _}, _) -> error;
%% Invalid opcode. Note that these opcodes may be used by extensions.
parse_header(<< _:4, 3:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 4:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 5:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 6:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 7:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 11:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 12:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 13:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 14:4, _/bits >>, _, _) -> error;
parse_header(<< _:4, 15:4, _/bits >>, _, _) -> error;
%% Control frames MUST NOT be fragmented.
parse_header(<< 0:1, _:3, Opcode:4, _/bits >>, _, _) when Opcode >= 8 -> error;
%% A frame MUST NOT use the zero opcode unless fragmentation was initiated.
parse_header(<< _:4, 0:4, _/bits >>, _, undefined) -> error;
%% Non-control opcode when expecting control message or next fragment.
parse_header(<< _:4, 1:4, _/bits >>, _, {_, _}) -> error;
parse_header(<< _:4, 2:4, _/bits >>, _, {_, _}) -> error;
parse_header(<< _:4, 3:4, _/bits >>, _, {_, _}) -> error;
parse_header(<< _:4, 4:4, _/bits >>, _, {_, _}) -> error;
parse_header(<< _:4, 5:4, _/bits >>, _, {_, _}) -> error;
parse_header(<< _:4, 6:4, _/bits >>, _, {_, _}) -> error;
parse_header(<< _:4, 7:4, _/bits >>, _, {_, _}) -> error;
%% Close control frame length MUST be 0 or >= 2.
parse_header(<< _:4, 8:4, _:1, 1:7, _/bits >>, _, _) -> error;
%% Close control frame with incomplete close code. Need more data.
parse_header(Data = << _:4, 8:4, 0:1, Len:7, _/bits >>, _, _) when Len > 1, byte_size(Data) < 4 -> more;
parse_header(Data = << _:4, 8:4, 1:1, Len:7, _/bits >>, _, _) when Len > 1, byte_size(Data) < 8 -> more;
%% 7 bits payload length.
parse_header(<< Fin:1, Rsv:3/bits, Opcode:4, 0:1, Len:7, Rest/bits >>, _, FragState) when Len < 126 ->
	parse_header(Opcode, Fin, FragState, Rsv, Len, undefined, Rest);
parse_header(<< Fin:1, Rsv:3/bits, Opcode:4, 1:1, Len:7, MaskKey:32, Rest/bits >>, _, FragState) when Len < 126 ->
	parse_header(Opcode, Fin, FragState, Rsv, Len, MaskKey, Rest);
%% 16 bits payload length.
parse_header(<< Fin:1, Rsv:3/bits, Opcode:4, 0:1, 126:7, Len:16, Rest/bits >>, _, FragState) when Len > 125, Opcode < 8 ->
	parse_header(Opcode, Fin, FragState, Rsv, Len, undefined, Rest);
parse_header(<< Fin:1, Rsv:3/bits, Opcode:4, 1:1, 126:7, Len:16, MaskKey:32, Rest/bits >>, _, FragState) when Len > 125, Opcode < 8 ->
	parse_header(Opcode, Fin, FragState, Rsv, Len, MaskKey, Rest);
%% 63 bits payload length.
parse_header(<< Fin:1, Rsv:3/bits, Opcode:4, 0:1, 127:7, 0:1, Len:63, Rest/bits >>, _, FragState) when Len > 16#ffff, Opcode < 8 ->
	parse_header(Opcode, Fin, FragState, Rsv, Len, undefined, Rest);
parse_header(<< Fin:1, Rsv:3/bits, Opcode:4, 1:1, 127:7, 0:1, Len:63, MaskKey:32, Rest/bits >>, _, FragState) when Len > 16#ffff, Opcode < 8 ->
	parse_header(Opcode, Fin, FragState, Rsv, Len, MaskKey, Rest);
%% When payload length is over 63 bits, the most significant bit MUST be 0.
parse_header(<< _:9, 127:7, 1:1, _/bits >>, _, _) -> error;
%% For the next two clauses, it can be one of the following:
%%
%% * The minimal number of bytes MUST be used to encode the length
%% * All control frames MUST have a payload length of 125 bytes or less
parse_header(<< _:8, 0:1, 126:7, _:16, _/bits >>, _, _) -> error;
parse_header(<< _:8, 1:1, 126:7, _:48, _/bits >>, _, _) -> error;
parse_header(<< _:8, 0:1, 127:7, _:64, _/bits >>, _, _) -> error;
parse_header(<< _:8, 1:1, 127:7, _:96, _/bits >>, _, _) -> error;
%% Need more data.
parse_header(_, _, _) -> more.

parse_header(Opcode, Fin, FragState, Rsv, Len, MaskKey, Rest) ->
	Type = opcode_to_frame_type(Opcode),
	Type2 = case Fin of
		0 -> fragment;
		1 -> Type
	end,
	{Type2, frag_state(Type, Fin, FragState), Rsv, Len, MaskKey, Rest}.

opcode_to_frame_type(0) -> fragment;
opcode_to_frame_type(1) -> text;
opcode_to_frame_type(2) -> binary;
opcode_to_frame_type(8) -> close;
opcode_to_frame_type(9) -> ping;
opcode_to_frame_type(10) -> pong.

frag_state(Type, 0, undefined) -> {nofin, Type};
frag_state(fragment, 0, FragState = {nofin, _}) -> FragState;
frag_state(fragment, 1, {nofin, Type}) -> {fin, Type};
frag_state(_, 1, FragState) -> FragState.

%% @doc Parse and validate the close frame's close code.
%%
%% The close code is part of the payload and must therefore be unmasked.

-spec parse_close_code(binary(), mask_key()) -> {ok, close_code(), binary()} | error.
parse_close_code(<< MaskedCode:2/binary, Rest/bits >>, MaskKey) ->
	<< Code:16 >> = unmask(MaskedCode, MaskKey, 0),
	if
		Code < 1000; Code =:= 1004; Code =:= 1005; Code =:= 1006;
				(Code > 1011) and (Code < 3000); Code > 4999 ->
			error;
		true ->
			{ok, Code, Rest}
	end.

%% @doc Parse and validate the frame's payload.
%%
%% Validation is only required for text and close frames which feature
%% a UTF-8 payload.

-spec parse_payload(binary(), mask_key(), utf8_state(), non_neg_integer(),
		frame_type(), non_neg_integer(), frag_state(), extensions(), rsv())
	-> {ok, binary(), utf8_state(), binary()} | {more, binary(), utf8_state()} | error.
parse_payload(Data, MaskKey, Utf8State, ParsedLen, Type, Len, FragState, #{deflate_frame := Inflate}, << 1:1, 0:2 >>) ->
	{Data2, Rest, Eof} = split_payload(Data, Len),
	Payload = inflate_frame(unmask(Data2, MaskKey, ParsedLen), Inflate, FragState, Eof),
	validate_payload(Payload, Rest, Utf8State, ParsedLen, Type, FragState, Eof);
parse_payload(Data, MaskKey, Utf8State, ParsedLen, Type, Len, FragState, _, << 0:3 >>) ->
	{Data2, Rest, Eof} = split_payload(Data, Len),
	Payload = unmask(Data2, MaskKey, ParsedLen),
	validate_payload(Payload, Rest, Utf8State, ParsedLen, Type, FragState, Eof).

split_payload(Data, Len) ->
	case byte_size(Data) of
		Len ->
			{Data, <<>>, true};
		DataLen when DataLen < Len ->
			{Data, <<>>, false};
		_ ->
			<< Data2:Len/binary, Rest/bits >> = Data,
			{Data2, Rest, true}
	end.

unmask(Data, MaskKey, 0) ->
	do_unmask(Data, MaskKey, <<>>);
%% We unmask on the fly so we need to continue from the right mask byte.
unmask(Data, MaskKey, UnmaskedLen) ->
	Left = UnmaskedLen rem 4,
	Right = 4 - Left,
	MaskKey2 = (MaskKey bsl (Left * 8)) + (MaskKey bsr (Right * 8)),
	do_unmask(Data, MaskKey2, <<>>).

do_unmask(<<>>, _, Unmasked) ->
	Unmasked;
do_unmask(<< O:32, Rest/bits >>, MaskKey, Acc) ->
	T = O bxor MaskKey,
	do_unmask(Rest, MaskKey, << Acc/binary, T:32 >>);
do_unmask(<< O:24 >>, MaskKey, Acc) ->
	<< MaskKey2:24, _:8 >> = << MaskKey:32 >>,
	T = O bxor MaskKey2,
	<< Acc/binary, T:24 >>;
do_unmask(<< O:16 >>, MaskKey, Acc) ->
	<< MaskKey2:16, _:16 >> = << MaskKey:32 >>,
	T = O bxor MaskKey2,
	<< Acc/binary, T:16 >>;
do_unmask(<< O:8 >>, MaskKey, Acc) ->
	<< MaskKey2:8, _:24 >> = << MaskKey:32 >>,
	T = O bxor MaskKey2,
	<< Acc/binary, T:8 >>.

%% @todo Try using iodata() and see if it improves anything.
inflate_frame(Data, Inflate, fin, true) ->
	iolist_to_binary(zlib:inflate(Inflate, << Data/binary, 0, 0, 255, 255 >>));
inflate_frame(Data, Inflate, _, _) ->
	iolist_to_binary(zlib:inflate(Inflate, Data)).

%% Text frames and close control frames MUST have a payload that is valid UTF-8.
validate_payload(Payload, Rest, Utf8State, _, Type, _, Eof) when Type =:= text; Type =:= close ->
	case validate_utf8(<< Utf8State/binary, Payload/binary >>) of
		false -> error;
		Utf8State when not Eof -> {more, Payload, Utf8State};
		<<>> when Eof -> {ok, Payload, <<>>, Rest};
		_ -> error
	end;
validate_payload(Payload, Rest, Utf8State, _, fragment, {Fin, text}, Eof) ->
	case validate_utf8(<< Utf8State/binary, Payload/binary >>) of
		false -> error;
		<<>> when Eof -> {ok, Payload, <<>>, Rest};
		Utf8State2 when Eof, Fin =:= nofin -> {ok, Payload, Utf8State2, Rest};
		Utf8State2 when not Eof -> {more, Payload, Utf8State2};
		_ -> error
	end;
validate_payload(Payload, _, Utf8State, _, _, _, false) ->
	{more, Payload, Utf8State};
validate_payload(Payload, Rest, Utf8State, _, _, _, true) ->
	{ok, Payload, Utf8State, Rest}.

%% Returns <<>> if the argument is valid UTF-8, false if not,
%% or the incomplete part of the argument if we need more data.
validate_utf8(Valid = <<>>) ->
	Valid;
validate_utf8(<< _/utf8, Rest/bits >>) ->
	validate_utf8(Rest);
%% 2 bytes. Codepages C0 and C1 are invalid; fail early.
validate_utf8(<< 2#1100000:7, _/bits >>) ->
	false;
validate_utf8(Incomplete = << 2#110:3, _:5 >>) ->
	Incomplete;
%% 3 bytes.
validate_utf8(Incomplete = << 2#1110:4, _:4 >>) ->
	Incomplete;
validate_utf8(Incomplete = << 2#1110:4, _:4, 2#10:2, _:6 >>) ->
	Incomplete;
%% 4 bytes. Codepage F4 may have invalid values greater than 0x10FFFF.
validate_utf8(<< 2#11110100:8, 2#10:2, High:6, _/bits >>) when High >= 2#10000 ->
	false;
validate_utf8(Incomplete = << 2#11110:5, _:3 >>) ->
	Incomplete;
validate_utf8(Incomplete = << 2#11110:5, _:3, 2#10:2, _:6 >>) ->
	Incomplete;
validate_utf8(Incomplete = << 2#11110:5, _:3, 2#10:2, _:6, 2#10:2, _:6 >>) ->
	Incomplete;
%% Invalid.
validate_utf8(_) ->
	false.

%% @doc Construct an unmasked Websocket frame.

-spec frame(frame(), extensions()) -> iodata().
%% Control frames. Control packets must not be > 125 in length.
frame(close, _) ->
	<< 1:1, 0:3, 8:4, 0:8 >>;
frame(ping, _) ->
	<< 1:1, 0:3, 9:4, 0:8 >>;
frame(pong, _) ->
	<< 1:1, 0:3, 10:4, 0:8 >>;
frame({close, Payload}, Extensions) ->
	frame({close, 1000, Payload}, Extensions);
frame({close, StatusCode, Payload}, _) ->
	Len = 2 + iolist_size(Payload),
	true = Len =< 125,
	[<< 1:1, 0:3, 8:4, 0:1, Len:7, StatusCode:16 >>, Payload];
frame({ping, Payload}, _) ->
	Len = iolist_size(Payload),
	true = Len =< 125,
	[<< 1:1, 0:3, 9:4, 0:1, Len:7 >>, Payload];
frame({pong, Payload}, _) ->
	Len = iolist_size(Payload),
	true = Len =< 125,
	[<< 1:1, 0:3, 10:4, 0:1, Len:7 >>, Payload];
%% Data frames, deflate-frame extension.
frame({text, Payload}, #{deflate_frame := Deflate}) ->
	Payload2 = deflate_frame(Payload, Deflate),
	Len = payload_length(Payload2),
	[<< 1:1, 1:1, 0:2, 1:4, 0:1, Len/bits >>, Payload2];
frame({binary, Payload}, #{deflate_frame := Deflate}) ->
	Payload2 = deflate_frame(Payload, Deflate),
	Len = payload_length(Payload2),
	[<< 1:1, 1:1, 0:2, 2:4, 0:1, Len/bits >>, Payload2];
%% Data frames.
frame({text, Payload}, _) ->
	Len = payload_length(Payload),
	[<< 1:1, 0:3, 1:4, 0:1, Len/bits >>, Payload];
frame({binary, Payload}, _) ->
	Len = payload_length(Payload),
	[<< 1:1, 0:3, 2:4, 0:1, Len/bits >>, Payload].

payload_length(Payload) ->
	case byte_size(Payload) of
		N when N =< 125 -> << N:7 >>;
		N when N =< 16#ffff -> << 126:7, N:16 >>;
		N when N =< 16#7fffffffffffffff -> << 127:7, N:64 >>
	end.

deflate_frame(Payload, Deflate) ->
	Deflated = iolist_to_binary(zlib:deflate(Deflate, Payload, sync)),
	Len = byte_size(Deflated) - 4,
	case Deflated of
		<< Body:Len/binary, 0:8, 0:8, 255:8, 255:8 >> -> Body;
		_ -> Deflated
	end.
