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

-module(cow_http2).

%% Parsing.
-export([parse/1]).
-export([parse_settings_payload/1]).

%% Building.
-export([data/3]).
-export([data_header/3]).
-export([goaway/3]).
-export([headers/3]).
-export([ping/1]).
-export([ping_ack/1]).
-export([priority/4]).
-export([push_promise/3]).
-export([rst_stream/2]).
-export([settings/1]).
-export([settings_payload/1]).
-export([settings_ack/0]).
%% Splitting.
-export([split_continuation/3]).
-export([split_continuation/4]).
-export([split_data/3]).
-export([split_data/4]).
-export([split_headers/3]).
-export([split_headers/4]).
-export([split_push_promise/3]).
-export([split_push_promise/4]).
%% Framing.
-export([frame_continuation/3]).
-export([frame_data/3]).
-export([frame_goaway/2]).
-export([frame_headers/3]).
-export([frame_ping/3]).
-export([frame_priority/2]).
-export([frame_push_promise/3]).
-export([frame_rst_stream/2]).
-export([frame_settings/3]).

-type streamid() :: pos_integer().
-type fin() :: fin | nofin.
-type head_fin() :: head_fin | head_nofin.
-type exclusive() :: exclusive | shared.
-type weight() :: 1..256.
-type settings() :: map().

-type error() :: no_error
	| protocol_error
	| internal_error
	| flow_control_error
	| settings_timeout
	| stream_closed
	| frame_size_error
	| refused_stream
	| cancel
	| compression_error
	| connect_error
	| enhance_your_calm
	| inadequate_security
	| http_1_1_required
	| unknown_error.
-export_type([error/0]).

-type frame() :: {data, streamid(), fin(), binary()}
	| {headers, streamid(), fin(), head_fin(), binary()}
	| {headers, streamid(), fin(), head_fin(), exclusive(), streamid(), weight(), binary()}
	| {priority, streamid(), exclusive(), streamid(), weight()}
	| {rst_stream, streamid(), error()}
	| {settings, settings()}
	| settings_ack
	| {push_promise, streamid(), head_fin(), streamid(), binary()}
	| {ping, integer()}
	| {ping_ack, integer()}
	| {goaway, streamid(), error(), binary()}
	| {window_update, non_neg_integer()}
	| {window_update, streamid(), non_neg_integer()}
	| {continuation, streamid(), head_fin(), binary()}.
-export_type([frame/0]).

%% Parsing.

%%
%% DATA frames.
%%
parse(<< _:24, 0:8, _:9, 0:31, _/bits >>) ->
	{connection_error, protocol_error, 'DATA frames MUST be associated with a stream. (RFC7540 6.1)'};
parse(<< Len0:24, 0:8, _:4, 1:1, _:35, PadLen:8, _/bits >>) when PadLen >= Len0 ->
	{connection_error, protocol_error, 'Length of padding MUST be less than length of payload. (RFC7540 6.1)'};
%% No padding.
parse(<< Len:24, 0:8, _:4, 0:1, _:2, FlagEndStream:1, _:1, StreamID:31, Data:Len/binary, Rest/bits >>) ->
	{ok, {data, StreamID, parse_fin(FlagEndStream), Data}, Rest};
%% Padding.
parse(<< Len0:24, 0:8, _:4, 1:1, _:2, FlagEndStream:1, _:1, StreamID:31, PadLen:8, Rest0/bits >>)
		when byte_size(Rest0) >= Len0 - 1 ->
	Len = Len0 - PadLen - 1,
	case Rest0 of
		<< Data:Len/binary, 0:PadLen/unit:8, Rest/bits >> ->
			{ok, {data, StreamID, parse_fin(FlagEndStream), Data}, Rest};
		_ ->
			{connection_error, protocol_error, 'Padding octets MUST be set to zero. (RFC7540 6.1)'}
	end;
%%
%% HEADERS frames.
%%
parse(<< _:24, 1:8, _:9, 0:31, _/bits >>) ->
	{connection_error, protocol_error, 'HEADERS frames MUST be associated with a stream. (RFC7540 6.2)'};
parse(<< Len0:24, 1:8, _:4, 1:1, _:35, PadLen:8, _/bits >>) when PadLen >= Len0 ->
	{connection_error, protocol_error, 'Length of padding MUST be less than length of payload. (RFC7540 6.2)'};
parse(<< Len0:24, 1:8, _:2, 1:1, _:1, 1:1, _:35, PadLen:8, _/bits >>) when PadLen >= Len0 - 5 ->
	{connection_error, protocol_error, 'Length of padding MUST be less than length of payload. (RFC7540 6.2)'};
%% No padding, no priority.
parse(<< Len:24, 1:8, _:2, 0:1, _:1, 0:1, FlagEndHeaders:1, _:1, FlagEndStream:1, _:1, StreamID:31,
		HeaderBlockFragment:Len/binary, Rest/bits >>) ->
	{ok, {headers, StreamID, parse_fin(FlagEndStream), parse_head_fin(FlagEndHeaders), HeaderBlockFragment}, Rest};
%% Padding, no priority.
parse(<< Len0:24, 1:8, _:2, 0:1, _:1, 1:1, FlagEndHeaders:1, _:1, FlagEndStream:1, _:1, StreamID:31,
		PadLen:8, Rest0/bits >>) when byte_size(Rest0) >= Len0 - 1 ->
	Len = Len0 - PadLen - 1,
	case Rest0 of
		<< HeaderBlockFragment:Len/binary, 0:PadLen/unit:8, Rest/bits >> ->
			{ok, {headers, StreamID, parse_fin(FlagEndStream), parse_head_fin(FlagEndHeaders), HeaderBlockFragment}, Rest};
		_ ->
			{connection_error, protocol_error, 'Padding octets MUST be set to zero. (RFC7540 6.2)'}
	end;
%% No padding, priority.
parse(<< Len0:24, 1:8, _:2, 1:1, _:1, 0:1, FlagEndHeaders:1, _:1, FlagEndStream:1, _:1, StreamID:31,
		E:1, DepStreamID:31, Weight:8, Rest0/bits >>) when byte_size(Rest0) >= Len0 - 5 ->
	Len = Len0 - 5,
	<< HeaderBlockFragment:Len/binary, Rest/bits >> = Rest0,
	{ok, {headers, StreamID, parse_fin(FlagEndStream), parse_head_fin(FlagEndHeaders),
		parse_exclusive(E), DepStreamID, Weight + 1, HeaderBlockFragment}, Rest};
%% Padding, priority.
parse(<< Len0:24, 1:8, _:2, 1:1, _:1, 1:1, FlagEndHeaders:1, _:1, FlagEndStream:1, _:1, StreamID:31,
		PadLen:8, E:1, DepStreamID:31, Weight:8, Rest0/bits >>) when byte_size(Rest0) >= Len0 - 6 ->
	Len = Len0 - PadLen - 6,
	case Rest0 of
		<< HeaderBlockFragment:Len/binary, 0:PadLen/unit:8, Rest/bits >> ->
			{ok, {headers, StreamID, parse_fin(FlagEndStream), parse_head_fin(FlagEndHeaders),
				parse_exclusive(E), DepStreamID, Weight + 1, HeaderBlockFragment}, Rest};
		_ ->
			{connection_error, protocol_error, 'Padding octets MUST be set to zero. (RFC7540 6.2)'}
	end;
%%
%% PRIORITY frames.
%%
parse(<< 5:24, 2:8, _:9, 0:31, _/bits >>) ->
	{connection_error, protocol_error, 'PRIORITY frames MUST be associated with a stream. (RFC7540 6.3)'};
parse(<< 5:24, 2:8, _:9, StreamID:31, E:1, DepStreamID:31, Weight:8, Rest/bits >>) ->
	{ok, {priority, StreamID, parse_exclusive(E), DepStreamID, Weight + 1}, Rest};
%% @todo figure out how to best deal with frame size errors; if we have everything fine
%% if not we might want to inform the caller how much he should expect so that it can
%% decide if it should just close the connection
parse(<< BadLen:24, 2:8, _:9, StreamID:31, _:BadLen/binary, Rest/bits >>) ->
	{stream_error, StreamID, frame_size_error, 'PRIORITY frames MUST be 5 bytes wide. (RFC7540 6.3)', Rest};
%%
%% RST_STREAM frames.
%%
parse(<< 4:24, 3:8, _:9, 0:31, _/bits >>) ->
	{connection_error, protocol_error, 'RST_STREAM frames MUST be associated with a stream. (RFC7540 6.4)'};
parse(<< 4:24, 3:8, _:9, StreamID:31, ErrorCode:32, Rest/bits >>) ->
	{ok, {rst_stream, StreamID, parse_error_code(ErrorCode)}, Rest};
%% @todo same as priority
parse(<< BadLen:24, 3:8, _:9, StreamID:31, _:BadLen/binary, Rest/bits >>) ->
	{stream_error, StreamID, frame_size_error, 'RST_STREAM frames MUST be 4 bytes wide. (RFC7540 6.4)', Rest};
%%
%% SETTINGS frames.
%%
parse(<< 0:24, 4:8, _:7, 1:1, _:1, 0:31, Rest/bits >>) ->
	{ok, settings_ack, Rest};
parse(<< _:24, 4:8, _:7, 1:1, _:1, 0:31, _/bits >>) ->
	{connection_error, frame_size_error, 'SETTINGS frames with the ACK flag set MUST have a length of 0. (RFC7540 6.5)'};
parse(<< Len:24, 4:8, _:7, 0:1, _:1, 0:31, _/bits >>) when Len rem 6 =/= 0 ->
	{connection_error, frame_size_error, 'SETTINGS frames MUST have a length multiple of 6. (RFC7540 6.5)'};
parse(<< Len:24, 4:8, _:7, 0:1, _:1, 0:31, Rest/bits >>) when byte_size(Rest) >= Len ->
	parse_settings_payload(Rest, Len, #{});
parse(<< _:24, 4:8, _:7, 0:1, _:1, BadStreamID:31, _/bits >>) when BadStreamID =/= 0 ->
	{connection_error, protocol_error, 'SETTINGS frames MUST NOT be associated with a stream. (RFC7540 6.5)'};
%%
%% PUSH_PROMISE frames.
%%
parse(<< _:24, 5:8, _:9, 0:31, _/bits >>) ->
	{connection_error, protocol_error, 'PUSH_PROMISE frames MUST be associated with a stream. (RFC7540 6.6)'};
parse(<< Len0:24, 5:8, _:4, 1:1, _:35, PadLen:8, _/bits >>) when PadLen >= Len0 ->
	{connection_error, protocol_error, 'Length of padding MUST be less than length of payload. (RFC7540 6.6)'};
parse(<< Len0:24, 5:8, _:4, 0:1, FlagEndHeaders:1, _:3, StreamID:31, _:1, PromisedStreamID:31, Rest0/bits >>)
		when byte_size(Rest0) >= Len0 - 4 ->
	Len = Len0 - 4,
	<< HeaderBlockFragment:Len/binary, Rest/bits >> = Rest0,
	{ok, {push_promise, StreamID, parse_head_fin(FlagEndHeaders), PromisedStreamID, HeaderBlockFragment}, Rest};
parse(<< Len0:24, 5:8, _:4, 1:1, FlagEndHeaders:1, _:3, StreamID:31, PadLen:8, _:1, PromisedStreamID:31, Rest0/bits >>)
		when byte_size(Rest0) >= Len0 - 5 ->
	Len = Len0 - PadLen - 5,
	case Rest0 of
		<< HeaderBlockFragment:Len/binary, 0:PadLen/unit:8, Rest/bits >> ->
			{ok, {push_promise, StreamID, parse_head_fin(FlagEndHeaders), PromisedStreamID, HeaderBlockFragment}, Rest};
		_ ->
			{connection_error, protocol_error, 'Padding octets MUST be set to zero. (RFC7540 6.6)'}
	end;
%%
%% PING frames.
%%
parse(<< 8:24, 6:8, _:7, 1:1, _:1, 0:31, Opaque:64, Rest/bits >>) ->
	{ok, {ping_ack, Opaque}, Rest};
parse(<< 8:24, 6:8, _:7, 0:1, _:1, 0:31, Opaque:64, Rest/bits >>) ->
	{ok, {ping, Opaque}, Rest};
parse(<< 8:24, 6:8, _:104, _/bits >>) ->
	{connection_error, protocol_error, 'PING frames MUST NOT be associated with a stream. (RFC7540 6.7)'};
parse(<< Len:24, 6:8, _/bits >>) when Len =/= 8 ->
	{connection_error, frame_size_error, 'PING frames MUST be 8 bytes wide. (RFC7540 6.7)'};
%%
%% GOAWAY frames.
%%
parse(<< Len0:24, 7:8, _:9, 0:31, _:1, LastStreamID:31, ErrorCode:32, Rest0/bits >>) when byte_size(Rest0) >= Len0 - 8 ->
	Len = Len0 - 8,
	<< DebugData:Len/binary, Rest/bits >> = Rest0,
	{ok, {goaway, LastStreamID, parse_error_code(ErrorCode), DebugData}, Rest};
parse(<< Len0:24, 7:8, _:40, _:Len0/binary, _/bits >>) ->
	{connection_error, protocol_error, 'GOAWAY frames MUST NOT be associated with a stream. (RFC7540 6.8)'};
%%
%% WINDOW_UPDATE frames.
%%
parse(<< 4:24, 8:8, _:9, 0:31, _:1, 0:31, _/bits >>) ->
	{connection_error, protocol_error, 'WINDOW_UPDATE frames MUST have a non-zero increment. (RFC7540 6.9)'};
parse(<< 4:24, 8:8, _:9, 0:31, _:1, Increment:31, Rest/bits >>) ->
	{ok, {window_update, Increment}, Rest};
parse(<< 4:24, 8:8, _:9, StreamID:31, _:1, 0:31, _/bits >>) ->
	{stream_error, StreamID, protocol_error, 'WINDOW_UPDATE frames MUST have a non-zero increment. (RFC7540 6.9)'};
parse(<< 4:24, 8:8, _:9, StreamID:31, _:1, Increment:31, Rest/bits >>) ->
	{ok, {window_update, StreamID, Increment}, Rest};
parse(<< Len:24, 8:8, _/bits >>) when Len =/= 4->
	{connection_error, frame_size_error, 'WINDOW_UPDATE frames MUST be 4 bytes wide. (RFC7540 6.9)'};
%%
%% CONTINUATION frames.
%%
parse(<< _:24, 9:8, _:9, 0:31, _/bits >>) ->
	{connection_error, protocol_error, 'CONTINUATION frames MUST be associated with a stream. (RFC7540 6.10)'};
parse(<< Len:24, 9:8, _:5, FlagEndHeaders:1, _:3, StreamID:31, HeaderBlockFragment:Len/binary, Rest/bits >>) ->
	{ok, {continuation, StreamID, parse_head_fin(FlagEndHeaders), HeaderBlockFragment}, Rest};
%%
%% Incomplete frames.
%%
parse(<< Len:24, _/bits >>) ->
	{more, Len + 9};
parse(_) ->
	{more, 9}.

-ifdef(TEST).
parse_continuation_test() ->
	Continuation = iolist_to_binary(frame_continuation(1, #{ end_headers => 1 }, #{ header_block_fragment => <<>> })),
	_ = [{more, _} = parse(binary:part(Continuation, 0, I)) || I <- lists:seq(1, byte_size(Continuation) - 1)],
	{ok, {continuation, 1, head_fin, <<>>}, <<>>} = parse(Continuation),
	{ok, {continuation, 1, head_fin, <<>>}, << 42 >>} = parse(<< Continuation/binary, 42 >>),
	Continuation2 = iolist_to_binary(split_continuation(2, #{ end_headers => 1 }, #{ header_block_fragment => <<"abc">> }, 2)),
	{ok, {continuation, 2, head_nofin, <<"ab">>}, Rest0} = parse(Continuation2),
	{ok, {continuation, 2, head_fin, <<"c">>}, <<>>} = parse(Rest0),
	Continuation3 = iolist_to_binary(frame_continuation(0, #{}, #{})),
	{connection_error, protocol_error, 'CONTINUATION frames MUST be associated with a stream. (RFC7540 6.10)'} = parse(Continuation3),
	ok.

parse_data_test() ->
	Data = iolist_to_binary(data(1, fin, <<>>)),
	_ = [{more, _} = parse(binary:part(Data, 0, I)) || I <- lists:seq(1, byte_size(Data) - 1)],
	{ok, {data, 1, fin, <<>>}, <<>>} = parse(Data),
	{ok, {data, 1, fin, <<>>}, << 42 >>} = parse(<< Data/binary, 42 >>),
	Data2 = iolist_to_binary(split_data(2, #{
		end_stream => 1,
		padded => 1
	}, #{
		data => <<"abc">>,
		pad_length => 2
	}, 3)),
	{ok, {data, 2, nofin, <<"a">>}, Rest0} = parse(Data2),
	{ok, {data, 2, nofin, <<"b">>}, Rest1} = parse(Rest0),
	{ok, {data, 2, fin, <<"c">>}, <<>>} = parse(Rest1),
	Data3 = iolist_to_binary(frame_data(0, #{}, #{})),
	{connection_error, protocol_error, 'DATA frames MUST be associated with a stream. (RFC7540 6.1)'} = parse(Data3),
	Data4 = << 0:24, 0:8, 0:4, 1:1, 0:4, 2:31, 1:8, 0:8 >>,
	{connection_error, protocol_error, 'Length of padding MUST be less than length of payload. (RFC7540 6.1)'} = parse(Data4),
	Data5 = << 2:24, 0:8, 0:4, 1:1, 0:4, 2:31, 1:8, 1:8 >>,
	{connection_error, protocol_error, 'Padding octets MUST be set to zero. (RFC7540 6.1)'} = parse(Data5),
	ok.

parse_goaway_test() ->
	Goaway = iolist_to_binary(goaway(1, no_error, <<"closing connection">>)),
	_ = [{more, _} = parse(binary:part(Goaway, 0, I)) || I <- lists:seq(1, byte_size(Goaway) - 1)],
	{ok, {goaway, 1, no_error, <<"closing connection">>}, <<>>} = parse(Goaway),
	{ok, {goaway, 1, no_error, <<"closing connection">>}, << 42 >>} = parse(<< Goaway/binary, 42 >>),
	ErrorCodes = [
		no_error,
		protocol_error,
		internal_error,
		flow_control_error,
		settings_timeout,
		stream_closed,
		frame_size_error,
		refused_stream,
		cancel,
		compression_error,
		connect_error,
		enhance_your_calm,
		inadequate_security,
		http_1_1_required
	],
	_ = [begin
		{ok, {goaway, 2, ErrorCode, <<>>}, <<>>} = parse(iolist_to_binary(goaway(2, ErrorCode, <<>>)))
	end || ErrorCode <- ErrorCodes],
	Goaway2 = iolist_to_binary(frame_goaway(3, #{})),
	{connection_error, protocol_error, 'GOAWAY frames MUST NOT be associated with a stream. (RFC7540 6.8)'} = parse(Goaway2),
	ok.

parse_headers_test() ->
	%% No padding, no priority.
	Headers = iolist_to_binary(headers(1, fin, <<>>)),
	_ = [{more, _} = parse(binary:part(Headers, 0, I)) || I <- lists:seq(1, byte_size(Headers) - 1)],
	{ok, {headers, 1, fin, head_fin, <<>>}, <<>>} = parse(Headers),
	{ok, {headers, 1, fin, head_fin, <<>>}, << 42 >>} = parse(<< Headers/binary, 42 >>),
	%% Padding, priority.
	Headers2 = iolist_to_binary(split_headers(5, #{
		end_stream => 0,
		end_headers => 1,
		padded => 1,
		priority => 1
	}, #{
		pad_length => 2,
		exclusive => 1,
		stream_dependency => 3,
		weight => 16,
		header_block_fragment => <<"abc">>
	}, 9)),
	{ok, {headers, 5, nofin, head_nofin, exclusive, 3, 16, <<"a">>}, Rest0} = parse(Headers2),
	{ok, {continuation, 5, head_fin, <<"bc">>}, <<>>} = parse(Rest0),
	%% No padding, priority.
	Headers3 = iolist_to_binary(split_headers(5, #{
		end_stream => 1,
		end_headers => 0,
		padded => 0,
		priority => 1
	}, #{
		exclusive => 0,
		stream_dependency => 3,
		weight => 1,
		header_block_fragment => <<"abc">>
	}, 6)),
	{ok, {headers, 5, fin, head_nofin, shared, 3, 1, <<"a">>}, Rest1} = parse(Headers3),
	{ok, {continuation, 5, head_nofin, <<"bc">>}, <<>>} = parse(Rest1),
	%% Padding, no priority.
	Headers4 = iolist_to_binary(split_headers(5, #{
		end_stream => 0,
		end_headers => 0,
		padded => 1,
		priority => 0
	}, #{
		pad_length => 2,
		header_block_fragment => <<"abc">>
	}, 4)),
	{ok, {headers, 5, nofin, head_nofin, <<"a">>}, Rest2} = parse(Headers4),
	{ok, {continuation, 5, head_nofin, <<"bc">>}, <<>>} = parse(Rest2),
	Headers5 = iolist_to_binary(headers(0, fin, <<>>)),
	{connection_error, protocol_error, 'HEADERS frames MUST be associated with a stream. (RFC7540 6.2)'} = parse(Headers5),
	Headers6 = << 0:24, 1:8, 0:4, 1:1, 0:4, 2:31, 1:8, 0:8 >>,
	{connection_error, protocol_error, 'Length of padding MUST be less than length of payload. (RFC7540 6.2)'} = parse(Headers6),
	Headers7 = << 2:24, 1:8, 0:2, 1:1, 0:1, 1:1, 0:3, 0:1, 1:31, 1:8, 0:40, 0:8 >>,
	{connection_error, protocol_error, 'Length of padding MUST be less than length of payload. (RFC7540 6.2)'} = parse(Headers7),
	ok.

parse_ping_test() ->
	Ping = ping(1234567890),
	_ = [{more, _} = parse(binary:part(Ping, 0, I)) || I <- lists:seq(1, byte_size(Ping) - 1)],
	{ok, {ping, 1234567890}, <<>>} = parse(Ping),
	{ok, {ping, 1234567890}, << 42 >>} = parse(<< Ping/binary, 42 >>),
	PingAck = ping_ack(1234567890),
	_ = [{more, _} = parse(binary:part(PingAck, 0, I)) || I <- lists:seq(1, byte_size(PingAck) - 1)],
	{ok, {ping_ack, 1234567890}, <<>>} = parse(PingAck),
	{ok, {ping_ack, 1234567890}, << 42 >>} = parse(<< PingAck/binary, 42 >>),
	ok.

parse_priority_test() ->
	Priority = iolist_to_binary(priority(3, exclusive, 1, 16)),
	_ = [{more, _} = parse(binary:part(Priority, 0, I)) || I <- lists:seq(1, byte_size(Priority) - 1)],
	{ok, {priority, 3, exclusive, 1, 16}, <<>>} = parse(Priority),
	{ok, {priority, 3, exclusive, 1, 16}, << 42 >>} = parse(<< Priority/binary, 42 >>),
	Priority2 = iolist_to_binary(priority(5, shared, 3, 256)),
	{ok, {priority, 5, shared, 3, 256}, <<>>} = parse(Priority2),
	Priority3 = iolist_to_binary(priority(0, exclusive, 0, 1)),
	{connection_error, protocol_error, 'PRIORITY frames MUST be associated with a stream. (RFC7540 6.3)'} = parse(Priority3),
	Priority4 = << 6:24, 2:8, 0:8, 0:1, 1:31, 0:48 >>,
	{stream_error, 1, frame_size_error, 'PRIORITY frames MUST be 5 bytes wide. (RFC7540 6.3)', <<>>} = parse(Priority4),
	ok.

parse_push_promise_test() ->
	%% No padding.
	PushPromise = iolist_to_binary(push_promise(1, 3, <<>>)),
	_ = [{more, _} = parse(binary:part(PushPromise, 0, I)) || I <- lists:seq(1, byte_size(PushPromise) - 1)],
	{ok, {push_promise, 1, head_fin, 3, <<>>}, <<>>} = parse(PushPromise),
	{ok, {push_promise, 1, head_fin, 3, <<>>}, << 42 >>} = parse(<< PushPromise/binary, 42 >>),
	%% Padding.
	PushPromise2 = iolist_to_binary(split_push_promise(3, #{
		end_headers => 1,
		padded => 1
	}, #{
		pad_length => 2,
		promised_stream_id => 5,
		header_block_fragment => <<"abc">>
	}, 8)),
	{ok, {push_promise, 3, head_nofin, 5, <<"a">>}, Rest0} = parse(PushPromise2),
	{ok, {continuation, 3, head_fin, <<"bc">>}, <<>>} = parse(Rest0),
	PushPromise3 = << 2:24, 5:8, 0:4, 1:1, 1:1, 0:2, 0:1, 3:31, 2:8, 0:1, 5:31, 0:16 >>,
	{connection_error, protocol_error, 'Length of padding MUST be less than length of payload. (RFC7540 6.6)'} = parse(PushPromise3),
	PushPromise4 = << 7:24, 5:8, 0:4, 1:1, 1:1, 0:2, 0:1, 3:31, 2:8, 0:1, 5:31, 1:16 >>,
	{connection_error, protocol_error, 'Padding octets MUST be set to zero. (RFC7540 6.6)'} = parse(PushPromise4),
	ok.

parse_rst_stream_test() ->
	RstStream = iolist_to_binary(rst_stream(1, no_error)),
	_ = [{more, _} = parse(binary:part(RstStream, 0, I)) || I <- lists:seq(1, byte_size(RstStream) - 1)],
	{ok, {rst_stream, 1, no_error}, <<>>} = parse(RstStream),
	{ok, {rst_stream, 1, no_error}, << 42 >>} = parse(<< RstStream/binary, 42 >>),
	ErrorCodes = [
		no_error,
		protocol_error,
		internal_error,
		flow_control_error,
		settings_timeout,
		stream_closed,
		frame_size_error,
		refused_stream,
		cancel,
		compression_error,
		connect_error,
		enhance_your_calm,
		inadequate_security,
		http_1_1_required
	],
	_ = [begin
		{ok, {rst_stream, 2, ErrorCode}, <<>>} = parse(iolist_to_binary(rst_stream(2, ErrorCode)))
	end || ErrorCode <- ErrorCodes],
	RstStream2 = iolist_to_binary(frame_rst_stream(0, #{})),
	{connection_error, protocol_error, 'RST_STREAM frames MUST be associated with a stream. (RFC7540 6.4)'} = parse(RstStream2),
	RstStream3 = << 5:24, 3:8, 0:8, 0:1, 3:31, 0:40 >>,
	{stream_error, 3, frame_size_error, 'RST_STREAM frames MUST be 4 bytes wide. (RFC7540 6.4)', <<>>} = parse(RstStream3),
	ok.

parse_settings_test() ->
	Settings = iolist_to_binary(settings(#{ max_frame_size => 16#4000 })),
	_ = [{more, _} = parse(binary:part(Settings, 0, I)) || I <- lists:seq(1, byte_size(Settings) - 1)],
	{ok, {settings, #{ max_frame_size := 16#4000 }}, <<>>} = parse(Settings),
	{ok, {settings, #{ max_frame_size := 16#4000 }}, << 42 >>} = parse(<< Settings/binary, 42 >>),
	SettingsAck = iolist_to_binary(settings_ack()),
	_ = [{more, _} = parse(binary:part(SettingsAck, 0, I)) || I <- lists:seq(1, byte_size(SettingsAck) - 1)],
	{ok, settings_ack, <<>>} = parse(SettingsAck),
	{ok, settings_ack, << 42 >>} = parse(<< SettingsAck/binary, 42 >>),
	SettingsAck2 = << 1:24, 4:8, 0:7, 1:1, 0:1, 0:31, 0:8 >>,
	{connection_error, frame_size_error, 'SETTINGS frames with the ACK flag set MUST have a length of 0. (RFC7540 6.5)'} = parse(SettingsAck2),
	Settings3 = iolist_to_binary(settings(#{})),
	{ok, {settings, #{}}, <<>>} = parse(Settings3),
	Fields4 = #{
		header_table_size => 4096,
		enable_push => true,
		max_concurrent_streams => 100,
		initial_window_size => 65535,
		max_frame_size => 16384,
		max_header_list_size => 1
	},
	Settings4 = iolist_to_binary(settings(Fields4)),
	{ok, {settings, Fields4}, <<>>} = parse(Settings4),
	Settings5 = << 1:24, 4:8, 0:8, 0:1, 0:31, 0:8 >>,
	{connection_error, frame_size_error, 'SETTINGS frames MUST have a length multiple of 6. (RFC7540 6.5)'} = parse(Settings5),
	Settings6 = << 0:24, 4:8, 0:8, 0:1, 1:31 >>,
	{connection_error, protocol_error, 'SETTINGS frames MUST NOT be associated with a stream. (RFC7540 6.5)'} = parse(Settings6),
	Settings7 = << 6:24, 4:8, 0:8, 0:1, 0:31, 2:16, 2:32 >>,
	{connection_error, protocol_error, 'The SETTINGS_ENABLE_PUSH value MUST be 0 or 1. (RFC7540 6.5.2)'} = parse(Settings7),
	Settings8 = << 6:24, 4:8, 0:8, 0:1, 0:31, 4:16, 16#80000000:32 >>,
	{connection_error, flow_control_error, 'The maximum SETTINGS_INITIAL_WINDOW_SIZE value is 0x7fffffff. (RFC7540 6.5.2)'} = parse(Settings8),
	Settings9 = << 6:24, 4:8, 0:8, 0:1, 0:31, 5:16, 16#3fff:32 >>,
	{connection_error, protocol_error, 'The SETTINGS_MAX_FRAME_SIZE value must be > 0x3fff. (RFC7540 6.5.2)'} = parse(Settings9),
	Settings10 = << 6:24, 4:8, 0:8, 0:1, 0:31, 5:16, 16#1000000:32 >>,
	{connection_error, protocol_error, 'The SETTINGS_MAX_FRAME_SIZE value must be =< 0xffffff. (RFC7540 6.5.2)'} = parse(Settings10),
	ok.

parse_windows_update_test() ->
	WindowUpdate = << 4:24, 8:8, 0:9, 0:31, 0:1, 12345:31 >>,
	_ = [{more, _} = parse(binary:part(WindowUpdate, 0, I)) || I <- lists:seq(1, byte_size(WindowUpdate) - 1)],
	{ok, {window_update, 12345}, <<>>} = parse(WindowUpdate),
	{ok, {window_update, 12345}, << 42 >>} = parse(<< WindowUpdate/binary, 42 >>),
	ok.
-endif.

parse_fin(0) -> nofin;
parse_fin(1) -> fin.

parse_head_fin(0) -> head_nofin;
parse_head_fin(1) -> head_fin.

parse_exclusive(0) -> shared;
parse_exclusive(1) -> exclusive.

parse_error_code( 0) -> no_error;
parse_error_code( 1) -> protocol_error;
parse_error_code( 2) -> internal_error;
parse_error_code( 3) -> flow_control_error;
parse_error_code( 4) -> settings_timeout;
parse_error_code( 5) -> stream_closed;
parse_error_code( 6) -> frame_size_error;
parse_error_code( 7) -> refused_stream;
parse_error_code( 8) -> cancel;
parse_error_code( 9) -> compression_error;
parse_error_code(10) -> connect_error;
parse_error_code(11) -> enhance_your_calm;
parse_error_code(12) -> inadequate_security;
parse_error_code(13) -> http_1_1_required;
parse_error_code(_) -> unknown_error.

parse_settings_payload(SettingsPayload) ->
	{ok, {settings, Settings}, <<>>}
		= parse_settings_payload(SettingsPayload, byte_size(SettingsPayload), #{}),
	Settings.

parse_settings_payload(Rest, 0, Settings) ->
	{ok, {settings, Settings}, Rest};
%% SETTINGS_HEADER_TABLE_SIZE.
parse_settings_payload(<< 1:16, Value:32, Rest/bits >>, Len, Settings) ->
	parse_settings_payload(Rest, Len - 6, Settings#{header_table_size => Value});
%% SETTINGS_ENABLE_PUSH.
parse_settings_payload(<< 2:16, 0:32, Rest/bits >>, Len, Settings) ->
	parse_settings_payload(Rest, Len - 6, Settings#{enable_push => false});
parse_settings_payload(<< 2:16, 1:32, Rest/bits >>, Len, Settings) ->
	parse_settings_payload(Rest, Len - 6, Settings#{enable_push => true});
parse_settings_payload(<< 2:16, _:32, _/bits >>, _, _) ->
	{connection_error, protocol_error, 'The SETTINGS_ENABLE_PUSH value MUST be 0 or 1. (RFC7540 6.5.2)'};
%% SETTINGS_MAX_CONCURRENT_STREAMS.
parse_settings_payload(<< 3:16, Value:32, Rest/bits >>, Len, Settings) ->
	parse_settings_payload(Rest, Len - 6, Settings#{max_concurrent_streams => Value});
%% SETTINGS_INITIAL_WINDOW_SIZE.
parse_settings_payload(<< 4:16, Value:32, _/bits >>, _, _) when Value > 16#7fffffff ->
	{connection_error, flow_control_error, 'The maximum SETTINGS_INITIAL_WINDOW_SIZE value is 0x7fffffff. (RFC7540 6.5.2)'};
parse_settings_payload(<< 4:16, Value:32, Rest/bits >>, Len, Settings) ->
	parse_settings_payload(Rest, Len - 6, Settings#{initial_window_size => Value});
%% SETTINGS_MAX_FRAME_SIZE.
parse_settings_payload(<< 5:16, Value:32, _/bits >>, _, _) when Value =< 16#3fff ->
	{connection_error, protocol_error, 'The SETTINGS_MAX_FRAME_SIZE value must be > 0x3fff. (RFC7540 6.5.2)'};
parse_settings_payload(<< 5:16, Value:32, Rest/bits >>, Len, Settings) when Value =< 16#ffffff ->
	parse_settings_payload(Rest, Len - 6, Settings#{max_frame_size => Value});
parse_settings_payload(<< 5:16, _:32, _/bits >>, _, _) ->
	{connection_error, protocol_error, 'The SETTINGS_MAX_FRAME_SIZE value must be =< 0xffffff. (RFC7540 6.5.2)'};
%% SETTINGS_MAX_HEADER_LIST_SIZE.
parse_settings_payload(<< 6:16, Value:32, Rest/bits >>, Len, Settings) ->
	parse_settings_payload(Rest, Len - 6, Settings#{max_header_list_size => Value});
parse_settings_payload(<< _:48, Rest/bits >>, Len, Settings) ->
	parse_settings_payload(Rest, Len - 6, Settings).

%% Building.

data(StreamID, IsFin, Data) ->
	split_data(StreamID, #{
		end_stream => flag_fin(IsFin)
	}, #{
		data => Data
	}).

data_header(StreamID, IsFin, Len) ->
	FlagEndStream = flag_fin(IsFin),
	<< Len:24, 0:15, FlagEndStream:1, 0:1, StreamID:31 >>.

goaway(LastStreamID, Reason, AdditionalDebugData) ->
	ErrorCode = error_code(Reason),
	frame_goaway(0, #{
		last_stream_id => LastStreamID,
		error_code => ErrorCode,
		additional_debug_data => AdditionalDebugData
	}).

headers(StreamID, IsFin, HeaderBlockFragment) ->
	split_headers(StreamID, #{
		end_headers => 1,
		end_stream => flag_fin(IsFin)
	}, #{
		header_block_fragment => HeaderBlockFragment
	}).

ping(Opaque) ->
	frame_ping(0, #{
		ack => 0
	}, #{
		opaque => Opaque
	}).

ping_ack(Opaque) ->
	frame_ping(0, #{
		ack => 1
	}, #{
		opaque => Opaque
	}).

priority(StreamID, Exclusive, StreamDependency, Weight) ->
	frame_priority(StreamID, #{
		exclusive => exclusive(Exclusive),
		stream_dependency => StreamDependency,
		weight => Weight
	}).

push_promise(StreamID, PromisedStreamID, HeaderBlockFragment) ->
	split_push_promise(StreamID, #{
		end_headers => 1
	}, #{
		header_block_fragment => HeaderBlockFragment,
		promised_stream_id => PromisedStreamID
	}).

rst_stream(StreamID, Reason) ->
	ErrorCode = error_code(Reason),
	frame_rst_stream(StreamID, #{
		error_code => ErrorCode
	}).

settings(Settings=#{}) ->
	frame_settings(0, #{
		ack => 0
	}, Settings).

settings_payload(Settings) when is_map(Settings) and map_size(Settings) == 0 ->
	<<>>;
settings_payload(Settings) when is_map(Settings) ->
	settings_payload([
		header_table_size,
		enable_push,
		max_concurrent_streams,
		initial_window_size,
		max_frame_size,
		max_header_list_size
	], Settings, []).

settings_payload([header_table_size | Parameters], Settings=#{header_table_size := Value}, SettingsPayload)
		when is_integer(Value), Value >= 0, Value =< 16#ffffffff ->
	settings_payload(Parameters, Settings, [SettingsPayload, << 1:16, Value:32 >>]);
settings_payload([enable_push | Parameters], Settings=#{enable_push := false}, SettingsPayload) ->
	settings_payload(Parameters, Settings, [SettingsPayload, << 2:16, 0:32 >>]);
settings_payload([enable_push | Parameters], Settings=#{enable_push := true}, SettingsPayload) ->
	settings_payload(Parameters, Settings, [SettingsPayload, << 2:16, 1:32 >>]);
settings_payload([max_concurrent_streams | Parameters], Settings=#{max_concurrent_streams := Value}, SettingsPayload)
		when is_integer(Value), Value >= 0, Value =< 16#ffffffff  ->
	settings_payload(Parameters, Settings, [SettingsPayload, << 3:16, Value:32 >>]);
settings_payload([initial_window_size | Parameters], Settings=#{initial_window_size := Value}, SettingsPayload)
		when is_integer(Value), Value >= 0, Value =< 16#7fffffff ->
	settings_payload(Parameters, Settings, [SettingsPayload, << 4:16, Value:32 >>]);
settings_payload([max_frame_size | Parameters], Settings=#{max_frame_size := Value}, SettingsPayload)
		when is_integer(Value), Value > 16#3fff, Value =< 16#ffffff ->
	settings_payload(Parameters, Settings, [SettingsPayload, << 5:16, Value:32 >>]);
settings_payload([max_header_list_size | Parameters], Settings=#{max_header_list_size := Value}, SettingsPayload)
		when is_integer(Value), Value >= 0, Value =< 16#ffffffff ->
	settings_payload(Parameters, Settings, [SettingsPayload, << 6:16, Value:32 >>]);
settings_payload([Key | Parameters], Settings, SettingsPayload) ->
	case maps:find(Key, Settings) of
		{ok, Value} ->
			erlang:error({badarg, [Key, Value]});
		error ->
			settings_payload(Parameters, Settings, SettingsPayload)
	end;
settings_payload([], _Settings, SettingsPayload) ->
	SettingsPayload.

settings_ack() ->
	frame_settings(0, #{
		ack => 1
	}, #{}).

%% Splitting.

split_continuation(StreamID, Flags, Fields) ->
	split_continuation(StreamID, Flags, Fields, 16#4000).

split_continuation(StreamID, Flags, Fields, FrameSize) when FrameSize > 0 ->
	HeaderBlockFragment = maps:get(header_block_fragment, Fields, []),
	Len = iolist_size(HeaderBlockFragment),
	if
		FrameSize < Len ->
			ContFlags = Flags#{ end_headers => 0 },
			ContFields = Fields#{ header_block_fragment => [] },
			split_continuation(StreamID, iolist_to_binary(HeaderBlockFragment), ContFlags, ContFields, Flags, FrameSize, []);
		true ->
			frame_continuation(StreamID, Flags, Fields)
	end.

split_continuation(StreamID, Block, ContFlags, ContFields, Flags, FrameSize, Acc) when FrameSize < byte_size(Block) ->
	<< Chunk:FrameSize/binary, Rest/binary >> = Block,
	Frame = frame_continuation(StreamID, ContFlags, ContFields#{ header_block_fragment => Chunk }),
	split_continuation(StreamID, Rest, ContFlags, ContFields, Flags, FrameSize, [Acc, Frame]);
split_continuation(StreamID, Block, _ContFlags, Fields, Flags, _FrameSize, Acc) ->
	Frame = frame_continuation(StreamID, Flags, Fields#{ header_block_fragment => Block }),
	[Acc, Frame].

split_data(StreamID, Flags, Fields) ->
	split_data(StreamID, Flags, Fields, 16#4000).

split_data(StreamID, Flags, Fields, FrameSize) when FrameSize > 0 ->
	FlagPadded = maps:get(padded, Flags, 0),
	PadLength = maps:get(pad_length, Fields, 0) band 16#ff,
	Data = maps:get(data, Fields, []),
	LenPadded = case FlagPadded of 1 -> 1 + PadLength; _ -> 0 end,
	Len = iolist_size(Data) + LenPadded,
	if
		FrameSize < Len ->
			ContFlags = Flags#{ end_stream => 0 },
			ContFields = Fields#{ data => [] },
			NewFrameSize = if
				FrameSize =< LenPadded ->
					1;
				true ->
					FrameSize - LenPadded
			end,
			split_data(StreamID, iolist_to_binary(Data), ContFlags, ContFields, Flags, NewFrameSize, []);
		true ->
			frame_data(StreamID, Flags, Fields)
	end.

split_data(StreamID, Data, ContFlags, ContFields, Flags, FrameSize, Acc) when FrameSize < byte_size(Data) ->
	<< Chunk:FrameSize/binary, Rest/binary >> = Data,
	Frame = frame_data(StreamID, ContFlags, ContFields#{ data => Chunk }),
	split_data(StreamID, Rest, ContFlags, ContFields, Flags, FrameSize, [Acc, Frame]);
split_data(StreamID, Data, _ContFlags, Fields, Flags, _FrameSize, Acc) ->
	Frame = frame_data(StreamID, Flags, Fields#{ data => Data }),
	[Acc, Frame].

split_headers(StreamID, Flags, Fields) ->
	split_headers(StreamID, Flags, Fields, 16#4000).

split_headers(StreamID, Flags, Fields, FrameSize) when FrameSize > 0 ->
	FlagPadded = maps:get(padded, Flags, 0),
	PadLength = maps:get(pad_length, Fields, 0) band 16#ff,
	FlagPriority = maps:get(priority, Flags, 0),
	LenPadded = case FlagPadded of 1 -> 1 + PadLength; _ -> 0 end,
	LenPriority = case FlagPriority of 1 -> 5; _ -> 0 end,
	HeaderBlockFragment = maps:get(header_block_fragment, Fields, []),
	Len = iolist_size(HeaderBlockFragment) + LenPadded + LenPriority,
	if
		FrameSize < Len ->
			HeadersSize = max(FrameSize - LenPadded - LenPriority, 0),
			<< Chunk:HeadersSize/binary, Rest/binary >> = iolist_to_binary(HeaderBlockFragment),
			ContFlags = Flags#{ end_headers => 0 },
			ContFields = Fields#{ header_block_fragment => [] },
			HeadersFields = Fields#{ header_block_fragment => Chunk },
			Headers = frame_headers(StreamID, ContFlags, HeadersFields),
			split_continuation(StreamID, Rest, ContFlags, ContFields, Flags, FrameSize, Headers);
		true ->
			frame_headers(StreamID, Flags, Fields)
	end.

split_push_promise(StreamID, Flags, Fields) ->
	split_push_promise(StreamID, Flags, Fields, 16#4000).

split_push_promise(StreamID, Flags, Fields, FrameSize) when FrameSize > 0 ->
	FlagPadded = maps:get(padded, Flags, 0),
	PadLength = maps:get(pad_length, Fields, 0) band 16#ff,
	LenPadded = case FlagPadded of 1 -> 1 + PadLength; _ -> 0 end,
	HeaderBlockFragment = maps:get(header_block_fragment, Fields, []),
	Len = iolist_size(HeaderBlockFragment) + LenPadded + 4,
	if
		FrameSize < Len ->
			PushPromiseSize = max(FrameSize - LenPadded - 4, 0),
			<< Chunk:PushPromiseSize/binary, Rest/binary >> = iolist_to_binary(HeaderBlockFragment),
			ContFlags = Flags#{ end_headers => 0 },
			ContFields = Fields#{ header_block_fragment => [] },
			PushPromiseFields = Fields#{ header_block_fragment => Chunk },
			PushPromise = frame_push_promise(StreamID, ContFlags, PushPromiseFields),
			split_continuation(StreamID, Rest, ContFlags, ContFields, Flags, FrameSize, PushPromise);
		true ->
			frame_push_promise(StreamID, Flags, Fields)
	end.

%% Framing.

frame_continuation(StreamID, Flags, Fields) ->
	FlagEndHeaders = maps:get(end_headers, Flags, 0),
	HeaderBlockFragment = maps:get(header_block_fragment, Fields, []),
	Len = iolist_size(HeaderBlockFragment),
	[
		<<
			Len:24, 9:8,
			0:5, FlagEndHeaders:1, 0:2,
			0:1, StreamID:31
		>>,
		HeaderBlockFragment
	].

frame_data(StreamID, Flags, Fields) ->
	FlagEndStream = maps:get(end_stream, Flags, 0),
	FlagPadded = maps:get(padded, Flags, 0),
	PadLength = maps:get(pad_length, Fields, 0) band 16#ff,
	Data = maps:get(data, Fields, []),
	LenPadded = case FlagPadded of 1 -> 1 + PadLength; _ -> 0 end,
	Len = iolist_size(Data) + LenPadded,
	[
		<<
			Len:24, 0:8,
			0:4, FlagPadded:1, 0:2, FlagEndStream:1,
			0:1, StreamID:31,
			PadLength:(FlagPadded * 8)
		>>,
		Data,
		<< 0:(FlagPadded * PadLength * 8) >>
	].

frame_goaway(StreamID, Fields) ->
	LastStreamID = maps:get(last_stream_id, Fields, 0),
	ErrorCode = maps:get(error_code, Fields, 0),
	AdditionalDebugData = maps:get(additional_debug_data, Fields, []),
	Len = 8 + iolist_size(AdditionalDebugData),
	[
		<<
			Len:24, 7:8,
			0:8,
			0:1, StreamID:31,
			0:1, LastStreamID:31,
			ErrorCode:32
		>>,
		AdditionalDebugData
	].

frame_headers(StreamID, Flags, Fields) ->
	FlagEndStream = maps:get(end_stream, Flags, 0),
	FlagEndHeaders = maps:get(end_headers, Flags, 0),
	FlagPadded = maps:get(padded, Flags, 0),
	PadLength = maps:get(pad_length, Fields, 0) band 16#ff,
	FlagPriority = maps:get(priority, Flags, 0),
	Exclusive = maps:get(exclusive, Fields, 0),
	StreamDependency = maps:get(stream_dependency, Fields, 0),
	Weight = (maps:get(weight, Fields, 0) - 1) band 16#ff,
	HeaderBlockFragment = maps:get(header_block_fragment, Fields, []),
	LenPadded = case FlagPadded of 1 -> 1 + PadLength; _ -> 0 end,
	LenPriority = case FlagPriority of 1 -> 5; _ -> 0 end,
	Len = iolist_size(HeaderBlockFragment) + LenPadded + LenPriority,
	[
		<<
			Len:24, 1:8,
			0:2, FlagPriority:1, 0:1, FlagPadded:1, FlagEndHeaders:1, 0:1, FlagEndStream:1,
			0:1, StreamID:31,
			PadLength:(FlagPadded * 8),
			Exclusive:(FlagPriority * 1),
			StreamDependency:(FlagPriority * 31),
			Weight:(FlagPriority * 8)
		>>,
		HeaderBlockFragment,
		<< 0:(FlagPadded * PadLength * 8) >>
	].

frame_ping(StreamID, Flags, Fields) ->
	FlagAck = maps:get(ack, Flags, 0),
	Opaque = maps:get(opaque, Fields, 0),
	<<
		8:24, 6:8,
		0:7, FlagAck:1,
		0:1, StreamID:31,
		Opaque:64
	>>.

frame_priority(StreamID, Fields) ->
	Exclusive = maps:get(exclusive, Fields, 0),
	StreamDependency = maps:get(stream_dependency, Fields, 0),
	Weight = (maps:get(weight, Fields, 0) - 1) band 16#ff,
	<<
		5:24, 2:8,
		0:8,
		0:1, StreamID:31,
		Exclusive:1, StreamDependency:31,
		Weight:8
	>>.

frame_push_promise(StreamID, Flags, Fields) ->
	FlagEndHeaders = maps:get(end_headers, Flags, 0),
	FlagPadded = maps:get(padded, Flags, 0),
	PadLength = maps:get(pad_length, Fields, 0) band 16#ff,
	PromisedStreamID = maps:get(promised_stream_id, Fields, 0),
	HeaderBlockFragment = maps:get(header_block_fragment, Fields, []),
	LenPadded = case FlagPadded of 1 -> 1 + PadLength; _ -> 0 end,
	Len = iolist_size(HeaderBlockFragment) + LenPadded + 4,
	[
		<<
			Len:24, 5:8,
			0:4, FlagPadded:1, FlagEndHeaders:1, 0:2,
			0:1, StreamID:31,
			PadLength:(FlagPadded * 8),
			0:1, PromisedStreamID:31
		>>,
		HeaderBlockFragment,
		<< 0:(FlagPadded * PadLength * 8) >>
	].

frame_rst_stream(StreamID, Fields) ->
	ErrorCode = maps:get(error_code, Fields, 0),
	<<
		4:24, 3:8,
		0:8,
		0:1, StreamID:31,
		ErrorCode:32
	>>.

frame_settings(StreamID, Flags, Fields) ->
	FlagAck = maps:get(ack, Flags, 0),
	SettingsPayload = case FlagAck of 1 -> []; 0 -> settings_payload(Fields) end,
	Len = iolist_size(SettingsPayload),
	[
		<<
			Len:24, 4:8,
			0:7, FlagAck:1,
			0:1, StreamID:31
		>>,
		SettingsPayload
	].

flag_fin(nofin) -> 0;
flag_fin(fin) -> 1.

error_code(no_error) -> 0;
error_code(protocol_error) -> 1;
error_code(internal_error) -> 2;
error_code(flow_control_error) -> 3;
error_code(settings_timeout) -> 4;
error_code(stream_closed) -> 5;
error_code(frame_size_error) -> 6;
error_code(refused_stream) -> 7;
error_code(cancel) -> 8;
error_code(compression_error) -> 9;
error_code(connect_error) -> 10;
error_code(enhance_your_calm) -> 11;
error_code(inadequate_security) -> 12;
error_code(http_1_1_required) -> 13.

exclusive(shared) -> 0;
exclusive(exclusive) -> 1.
