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

-module(cow_sse).

-export([init/0]).
-export([init/1]).
-export([parse/2]).
-export([events/1]).
-export([event/1]).

-record(state, {
	state_name = bom :: bom | events,
	buffer = <<>> :: binary(),
	last_event_id = <<>> :: binary(),
	last_event_id_set = false :: boolean(),
	event_type = <<>> :: binary(),
	data = [] :: iolist(),
	retry = undefined :: undefined | non_neg_integer(),
	%% Bytes of the current event on the wire. The unfinished
	%% line stays in the buffer and is not included.
	event_size = 0 :: non_neg_integer(),
	%% 10 KiB. infinity disables the limit.
	max_event_size = 10240 :: pos_integer() | infinity,
	%% The previous line ended on CR. The next LF is part
	%% of that break, not a new empty line.
	ended_cr = false :: boolean()
}).
-type state() :: #state{}.
-export_type([state/0]).

-type parsed_event() :: #{
	last_event_id := binary(),
	event_type := binary(),
	data := iolist()
}.

-type event() :: #{
	comment => iodata(),
	data => iodata(),
	event => iodata() | atom(),
	id => iodata(),
	retry => non_neg_integer()
}.
-export_type([event/0]).

-include("cow_parse.hrl").

-ifdef(TEST).
-include_lib("stdlib/include/assert.hrl").
-endif.

-spec init() -> state().
init() ->
	#state{}.

-spec init(#{max_event_size => pos_integer() | infinity}) -> state().
init(Opts) ->
	#state{max_event_size=maps:get(max_event_size, Opts, 10240)}.

%% @todo Add a function to retrieve the retry value from the state.

-spec parse(binary(), State)
	-> {event, parsed_event(), State}
	| {more, State}
	| {error, limit_reached}
	when State::state().
parse(Data0, State=#state{state_name=bom, buffer=Buffer}) ->
	Data1 = case Buffer of
		<<>> -> Data0;
		_ -> << Buffer/binary, Data0/binary >>
	end,
	case Data1 of
		%% Skip the BOM.
		<< 16#fe, 16#ff, Data/bits >> ->
			parse_event(Data, State#state{state_name=events, buffer= <<>>});
		%% Not enough data to know wether we have a BOM.
		<< 16#fe >> ->
			{more, State#state{buffer=Data1}};
		<<>> ->
			{more, State};
		%% No BOM.
		_ ->
			parse_event(Data1, State#state{state_name=events, buffer= <<>>})
	end;
%% The previous line ended on CR. A LF is the other half of that break.
parse(<<$\n, Data/binary>>, State=#state{ended_cr=true, buffer= <<>>}) ->
	parse(Data, State#state{ended_cr=false});
parse(<<>>, State=#state{ended_cr=true, buffer= <<>>}) ->
	{more, State};
parse(Data, State=#state{ended_cr=true, buffer= <<>>}) ->
	parse(Data, State#state{ended_cr=false});
%% Try to process data from the buffer if there is no new input.
parse(<<>>, State=#state{buffer=Buffer}) ->
	parse_event(Buffer, State#state{buffer= <<>>});
%% Otherwise process the input data as-is.
parse(Data0, State=#state{buffer=Buffer}) ->
	Data = case Buffer of
		<<>> -> Data0;
		_ -> << Buffer/binary, Data0/binary >>
	end,
	parse_event(Data, State).

parse_event(Data, State) ->
	case next_line(Data) of
		{cr_line, Pos, Len} ->
			take_line(Data, Pos, Len, true, State);
		{line, Pos, Len} ->
			take_line(Data, Pos, Len, false, State);
		%% The unfinished line is checked but not added. The newline
		%% that completes it counts the whole line. A CR at the end of
		%% a non-empty line is unfinished too: the next byte may be LF.
		more ->
			case event_size_exceeded(byte_size(Data), State) of
				true ->
					{error, limit_reached};
				false ->
					{more, State#state{buffer=Data}}
			end
	end.

take_line(Data, Pos, Len, EndedCr, State) ->
	case event_size_exceeded(Pos + Len, State) of
		true ->
			{error, limit_reached};
		false ->
			<<Line:Pos/binary, _:Len/binary, Rest/binary>> = Data,
			State1 = State#state{event_size=State#state.event_size + Pos + Len},
			case parse_line(Line, State1) of
				{ok, State2} ->
					parse_event(Rest, State2#state{ended_cr=EndedCr});
				{event, Event, State2} ->
					{event, Event, State2#state{buffer=Rest, ended_cr=EndedCr}}
			end
	end.

%% CRLF is one break. A CR at the end of a non-empty line is not
%% a break until the next byte. A CR that is the whole line ends
%% the event; a later LF belongs to that same break.
next_line(Data) ->
	case scan(Data, 0) of
		{cr, Pos, 1} when Pos + 1 =:= byte_size(Data) ->
			case Pos of
				0 ->
					{cr_line, 0, 1};
				_ ->
					more
			end;
		{cr, Pos, 1} ->
			{line, Pos, 1};
		{lf, Pos, 1} ->
			{line, Pos, 1};
		{cr_lf, Pos, 2} ->
			{line, Pos, 2};
		nomatch ->
			more
	end.

scan(<<A, B, C, D, Rest/bits>>, Pos)
		when A =/= $\r andalso A =/= $\n
		andalso B =/= $\r andalso B =/= $\n
		andalso C =/= $\r andalso C =/= $\n
		andalso D =/= $\r andalso D =/= $\n ->
	scan(Rest, Pos + 4);
scan(<<$\r, $\n, _/bits>>, Pos) ->
	{cr_lf, Pos, 2};
scan(<<$\r, _/bits>>, Pos) ->
	{cr, Pos, 1};
scan(<<$\n, _/bits>>, Pos) ->
	{lf, Pos, 1};
scan(<<_, Rest/bits>>, Pos) ->
	scan(Rest, Pos + 1);
scan(<<>>, _) ->
	nomatch.

event_size_exceeded(Size, #state{event_size=Acc, max_event_size=Max}) ->
	Acc + Size > Max.

%% Dispatch events on empty line.
parse_line(<<>>, State) ->
	dispatch_event(State);
%% Ignore comments.
parse_line(<< $:, _/bits >>, State) ->
	{ok, State};
%% Normal line.
parse_line(Line, State) ->
	case binary:split(Line, [<<":\s">>, <<":">>]) of
		[Field, Value] ->
			process_field(Field, Value, State);
		[Field] ->
			process_field(Field, <<>>, State)
	end.

process_field(<<"event">>, Value, State) ->
	{ok, State#state{event_type=Value}};
process_field(<<"data">>, Value, State=#state{data=Data}) ->
	{ok, State#state{data=[<<$\n>>, Value|Data]}};
process_field(<<"id">>, Value, State) ->
	{ok, State#state{last_event_id=binary:copy(Value), last_event_id_set=true}};
process_field(<<"retry">>, Value = <<C, _/bits>>, State) when ?IS_DIGIT(C) ->
	try
		{ok, State#state{retry=binary_to_integer(Value)}}
	catch _:_ ->
		{ok, State}
	end;
process_field(_, _, State) ->
	{ok, State}.

%% Data is an empty string; abort.
dispatch_event(State=#state{last_event_id_set=false, data=[]}) ->
	{ok, State#state{event_type= <<>>, event_size=0}};
%% Data is an empty string but we have a last_event_id:
%% propagate it on its own so that the caller knows the
%% most recent ID.
dispatch_event(State=#state{last_event_id=LastEventID, data=[]}) ->
	{event, #{
		last_event_id => LastEventID
	}, State#state{last_event_id_set=false, event_type= <<>>, event_size=0}};
%% Dispatch the event.
%%
%% Always remove the last linebreak from the data.
dispatch_event(State=#state{last_event_id=LastEventID,
		event_type=EventType, data=[_|Data]}) ->
	{event, #{
		last_event_id => LastEventID,
		event_type => case EventType of
			<<>> -> <<"message">>;
			_ -> EventType
		end,
		data => lists:reverse(Data)
	}, State#state{last_event_id_set=false, event_type= <<>>,
		data=[], event_size=0}}.

-ifdef(TEST).
parse_example1_test() ->
	{event, #{
		event_type := <<"message">>,
		last_event_id := <<>>,
		data := Data
	}, State} = parse(<<
		"data: YHOO\n"
		"data: +2\n"
		"data: 10\n"
		"\n">>, init()),
	<<"YHOO\n+2\n10">> = iolist_to_binary(Data),
	{more, _} = parse(<<>>, State),
	ok.

parse_example2_test() ->
	{event, #{
		event_type := <<"message">>,
		last_event_id := <<"1">>,
		data := Data1
	}, State0} = parse(<<
		": test stream\n"
		"\n"
		"data: first event\n"
		"id: 1\n"
		"\n"
		"data:second event\n"
		"id\n"
		"\n"
		"data:  third event\n"
		"\n">>, init()),
	<<"first event">> = iolist_to_binary(Data1),
	{event, #{
		event_type := <<"message">>,
		last_event_id := <<>>,
		data := Data2
	}, State1} = parse(<<>>, State0),
	<<"second event">> = iolist_to_binary(Data2),
	{event, #{
		event_type := <<"message">>,
		last_event_id := <<>>,
		data := Data3
	}, State} = parse(<<>>, State1),
	<<" third event">> = iolist_to_binary(Data3),
	{more, _} = parse(<<>>, State),
	ok.

parse_example3_test() ->
	{event, #{
		event_type := <<"message">>,
		last_event_id := <<>>,
		data := Data1
	}, State0} = parse(<<
		"data\n"
		"\n"
		"data\n"
		"data\n"
		"\n"
		"data:\n">>, init()),
	<<>> = iolist_to_binary(Data1),
	{event, #{
		event_type := <<"message">>,
		last_event_id := <<>>,
		data := Data2
	}, State} = parse(<<>>, State0),
	<<"\n">> = iolist_to_binary(Data2),
	{more, _} = parse(<<>>, State),
	ok.

parse_example4_test() ->
	{event, Event, State0} = parse(<<
		"data:test\n"
		"\n"
		"data: test\n"
		"\n">>, init()),
	{event, Event, State} = parse(<<>>, State0),
	{more, _} = parse(<<>>, State),
	ok.

parse_id_without_data_test() ->
	{event, Event1, State0} = parse(<<
		"id: 1\n"
		"\n"
		"data: data\n"
		"\n"
		"id: 2\n"
		"\n">>, init()),
	1 = maps:size(Event1),
	#{last_event_id := <<"1">>} = Event1,
	{event, #{
		event_type := <<"message">>,
		last_event_id := <<"1">>,
		data := Data
	}, State1} = parse(<<>>, State0),
	<<"data">> = iolist_to_binary(Data),
	{event, Event2, State} = parse(<<>>, State1),
	1 = maps:size(Event2),
	#{last_event_id := <<"2">>} = Event2,
	{more, _} = parse(<<>>, State),
	ok.

parse_repeated_id_without_data_test() ->
	{event, Event1, State0} = parse(<<
		"id: 1\n"
		"\n"
		"event: message\n" %% This will be ignored since there's no data.
		"\n"
		"id: 1\n"
		"\n"
		"id: 2\n"
		"\n">>, init()),
	{event, Event1, State1} = parse(<<>>, State0),
	1 = maps:size(Event1),
	#{last_event_id := <<"1">>} = Event1,
	{event, Event2, State} = parse(<<>>, State1),
	1 = maps:size(Event2),
	#{last_event_id := <<"2">>} = Event2,
	{more, _} = parse(<<>>, State),
	ok.

parse_split_event_test() ->
	{more, State} = parse(<<
		"data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">>, init()),
	{event, _, _} = parse(<<"==\n\n">>, State),
	ok.

parse_retry_error_test_() ->
	Tests = [
		<<"-1000">>,
		<<"-0">>,
		<<"+0">>,
		<<"+1000">>
	],
	[{V, fun() ->
		{event, #{data := Data}, State} = parse(<<
			"retry: ", V/binary, "\n"
			"data: x\n"
			"\n">>, init()),
		<<"x">> = iolist_to_binary(Data),
		undefined = State#state.retry
	end} || V <- Tests].

%% "data: ab\n\n" is 10 bytes. The blank line is part of that.
parse_max_event_size_test() ->
	{event, #{data := Data}, St0} = parse(<<"data: ab\n\n">>,
		init(#{max_event_size => 10})),
	<<"ab">> = iolist_to_binary(Data),
	{event, #{last_event_id := <<"z">>}, _} = parse(<<"id: z\n\n">>, St0),
	{error, limit_reached} = parse(<<"data: ab\n\n">>,
		init(#{max_event_size => 9})),
	{more, _} = parse(<<"data: ab\n">>, init(#{max_event_size => 9})),
	%% "data: ab" is 8. A rejected read leaves the previous state.
	{more, St1} = parse(<<"data: ab">>, init(#{max_event_size => 10})),
	{error, limit_reached} = parse(<<"xxx">>, St1),
	{event, _, _} = parse(<<"\n\n">>, St1),
	{more, _} = parse(binary:copy(<<$a>>, 10240), init()),
	{error, limit_reached} = parse(binary:copy(<<$a>>, 10241), init()),
	{more, _} = parse(binary:copy(<<$a>>, 10241),
		init(#{max_event_size => infinity})),
	ok.

%% ": x\n" + "data: a\n" + "\n" is 13. "retry: 1000\n" is 12.
%% "data: a\r\n" is 9. "id: i\n\n" is 7 and "data: z\n\n" is 9.
parse_max_event_size_lines_test() ->
	{event, _, _} = parse(<<": x\ndata: a\n\n">>,
		init(#{max_event_size => 13})),
	{error, limit_reached} = parse(<<": x\ndata: a\n\n">>,
		init(#{max_event_size => 12})),
	{error, limit_reached} = parse(<<"retry: 1000\n">>,
		init(#{max_event_size => 11})),
	{more, #state{retry=1000}} = parse(<<"retry: 1000\n">>,
		init(#{max_event_size => 12})),
	{more, _} = parse(<<"data: a\r\n">>, init(#{max_event_size => 9})),
	{error, limit_reached} = parse(<<"data: a\r\n">>,
		init(#{max_event_size => 8})),
	{event, _, St} = parse(<<"id: i\n\n">>, init(#{max_event_size => 9})),
	{event, _, _} = parse(<<"data: z\n\n">>, St),
	ok.

%% Parsing stops at the event. The next call sees what follows.
parse_max_event_size_tail_test() ->
	Huge = binary:copy(<<$x>>, 1000),
	{event, #{data := Data}, St0} = parse(<<"data: a\n\n", Huge/binary>>,
		init(#{max_event_size => 9})),
	<<"a">> = iolist_to_binary(Data),
	Huge = St0#state.buffer,
	{error, limit_reached} = parse(<<>>, St0),
	{event, _, St1} = parse(<<"data: a\n\nid: z\n\n", Huge/binary>>,
		init(#{max_event_size => 9})),
	{event, #{last_event_id := <<"z">>}, St2} = parse(<<>>, St1),
	Huge = St2#state.buffer,
	{error, limit_reached} = parse(<<>>, St2),
	%% "data: b\n" starts an event that does not fit.
	{event, _, St3} = parse(<<"data: a\n\ndata: b\n", Huge/binary>>,
		init(#{max_event_size => 9})),
	<<"data: b\n", Huge/binary>> = St3#state.buffer,
	{error, limit_reached} = parse(<<>>, St3),
	%% "data: ab\n\n" is 10.
	{event, #{last_event_id := <<"z">>}, St4} = parse(<<"id: z\n\ndata: ab\n\n">>,
		init(#{max_event_size => 9})),
	<<"data: ab\n\n">> = St4#state.buffer,
	{error, limit_reached} = parse(<<>>, St4),
	{event, _, St5} = parse(<<"data: a\n\ndata: b">>,
		init(#{max_event_size => 20})),
	<<"data: b">> = St5#state.buffer,
	ok.

%% The id outlives the event. Copy it so the input can be dropped.
parse_max_event_size_id_copy_test() ->
	Pad = binary:copy(<<$z>>, 500),
	Id = binary:copy(<<$i>>, 80),
	Bin = <<"id: ", Id/binary, "\n\n", Pad/binary>>,
	{event, #{last_event_id := Got}, _} = parse(Bin,
		init(#{max_event_size => 200})),
	Id = Got,
	erlang:garbage_collect(),
	80 = binary:referenced_byte_size(Got),
	ok.

%% A CR at the end of the buffer may start a CRLF. Do not end the
%% event, or the next LF resets the size and the limit can be bypassed.
parse_crlf_hold_test() ->
	{event, #{last_event_id := <<"Z">>, data := Data0}, _} =
		parse(<<"id: Z\r\ndata: a\r\n\r\n">>, init(#{max_event_size => 100})),
	<<"a">> = iolist_to_binary(Data0),
	{more, S1} = parse(<<"id: Z\r">>, init(#{max_event_size => 100})),
	{event, #{last_event_id := <<"Z">>, data := Data1}, _} =
		parse(<<"\ndata: a\r\n\r\n">>, S1),
	<<"a">> = iolist_to_binary(Data1),
	Max = init(#{max_event_size => 20}),
	{error, limit_reached} =
		parse(<<"data: hello\r\ndata: world\r\n\r\n">>, Max),
	{more, M1} = parse(<<"data: hello\r">>, Max),
	{error, limit_reached} = parse(<<"\ndata: world\r\n\r\n">>, M1),
	{error, limit_reached} = parse(<<"data: ab\r\n\n">>,
		init(#{max_event_size => 10})),
	{more, C1} = parse(<<"data: ab\r">>, init(#{max_event_size => 10})),
	{error, limit_reached} = parse(<<"\n\n">>, C1),
	%% A CR that is the blank line ends the event. A later LF
	%% belongs to that break.
	{event, #{data := Data2}, E1} = parse(<<"data: a\r\n\r">>, init()),
	<<"a">> = iolist_to_binary(Data2),
	true = E1#state.ended_cr,
	{more, E2} = parse(<<"\n">>, E1),
	false = E2#state.ended_cr,
	<<>> = E2#state.buffer,
	{event, #{data := Data3}, E3} = parse(<<"data: a\r\r">>, init()),
	<<"a">> = iolist_to_binary(Data3),
	{event, #{data := Data4}, _} = parse(<<"\ndata: b\n\n">>, E3),
	<<"b">> = iolist_to_binary(Data4),
	{event, #{last_event_id := <<"Z">>}, I1} = parse(<<"id: Z\r\r">>, init()),
	{more, _} = parse(<<"\n">>, I1),
	{event, #{data := Data5}, E5} = parse(<<"data: a\r\r\n">>, init()),
	<<"a">> = iolist_to_binary(Data5),
	false = E5#state.ended_cr,
	ok.

parse_many_events_test() ->
	%% Each event fits. The batch does not. All of them are returned.
	Bin = binary:copy(<<"data: a\n\n">>, 50),
	50 = drain_events(parse(Bin, init(#{max_event_size => 20})), 0),
	ok.

drain_events({event, #{data := Data}, State}, N) ->
	<<"a">> = iolist_to_binary(Data),
	drain_events(parse(<<>>, State), N + 1);
drain_events({more, _}, N) ->
	N.
-endif.

-spec events([event()]) -> iolist().
events(Events) ->
	[event(Event) || Event <- Events].

-spec event(event()) -> iolist().
event(Event) ->
	[
		event_comment(Event),
		event_id(Event),
		event_name(Event),
		event_data(Event),
		event_retry(Event),
		$\n
	].

event_comment(#{comment := Comment}) ->
	prefix_lines(Comment, <<>>);
event_comment(_) ->
	[].

event_id(#{id := ID}) ->
	nomatch = binary:match(iolist_to_binary(ID),
		[<<"\r\n">>, <<"\r">>, <<"\n">>]),
	[<<"id: ">>, ID, $\n];
event_id(_) ->
	[].

event_name(#{event := Name0}) ->
	Name = if
		is_atom(Name0) -> atom_to_binary(Name0, utf8);
		true -> iolist_to_binary(Name0)
	end,
	nomatch = binary:match(Name,
		[<<"\r\n">>, <<"\r">>, <<"\n">>]),
	[<<"event: ">>, Name, $\n];
event_name(_) ->
	[].

event_data(#{data := Data}) ->
	prefix_lines(Data, <<"data">>);
event_data(_) ->
	[].

event_retry(#{retry := Retry}) ->
	[<<"retry: ">>, integer_to_binary(Retry), $\n];
event_retry(_) ->
	[].

prefix_lines(IoData, Prefix) ->
	Lines = binary:split(iolist_to_binary(IoData),
		[<<"\r\n">>, <<"\r">>, <<"\n">>], [global]),
	[[Prefix, <<": ">>, Line, $\n] || Line <- Lines].

-ifdef(TEST).
event_test() ->
	_ = event(#{}),
	_ = event(#{comment => "test"}),
	_ = event(#{data => "test"}),
	_ = event(#{data => "test\ntest\ntest"}),
	_ = event(#{data => "test\ntest\ntest\n"}),
	_ = event(#{data => <<"test\ntest\ntest">>}),
	_ = event(#{data => [<<"test">>, $\n, <<"test">>, [$\n, "test"]]}),
	_ = event(#{event => test}),
	_ = event(#{event => "test"}),
	_ = event(#{id => "test"}),
	_ = event(#{retry => 5000}),
	_ = event(#{event => "test", data => "test"}),
	_ = event(#{id => "test", event => "test", data => "test"}),
	_ = event(#{data => "test\r\ntest"}),
	_ = event(#{data => "test\rtest\r"}),
	_ = event(#{data => "test\ntest"}),
	ok.

event_error_test() ->
	?assertError(_, event(#{id => "test\n"})),
	?assertError(_, event(#{id => "test\r"})),
	?assertError(_, event(#{id => "test\r\n"})),
	?assertError(_, event(#{event => "test\n"})),
	?assertError(_, event(#{event => "test\r"})),
	?assertError(_, event(#{event => "test\r\n"})),
	ok.

identity_test_() ->
	Tests = [
		#{data => <<"hello">>},
		#{event => <<"update">>, data => <<"hello">>},
		#{id => <<"42">>, data => <<"hello">>},
		#{data => <<"a\nb">>},
		#{data => <<"multi\nline\ndata">>},
		#{event => <<"update">>, data => <<"hello">>},
		#{id => <<"abc">>, data => <<"x">>},
		#{comment => <<"c1">>, data => <<"d1">>, event => <<"e1">>, id => <<"i1">>},
		#{data => <<>>},
		#{data => <<"data with trailing newline\n">>},
		#{data => <<"\n">>},
		#{data => <<"\n\n">>},
		#{data => <<"">>, id => <<"1">>},
		#{data => <<"z">>},
		#{id => <<"17">>},
		#{data => << <<$a>> || _ <- lists:seq(1,200) >>},
		#{data => <<"こんにちは世界">>},
		#{retry => 30000, data => <<"reconnect">>}
	],
	[{lists:flatten(io_lib:format("~0p", [V])),
		fun() -> true = do_identity_result(V) =:= do_identity_build_parse(V) end}
			|| V <- Tests].

do_identity_build_parse(Event) ->
	{event, Parsed, _} = parse(iolist_to_binary(event(Event)), init()),
	case Parsed of
		#{data := Data} -> Parsed#{data => iolist_to_binary(Data)};
		_ -> Parsed
	end.

do_identity_result(E=#{id := ID}) when map_size(E) =:= 1 ->
	#{
		last_event_id => ID
	};
do_identity_result(Event) ->
	#{
		event_type => maps:get(event, Event, <<"message">>),
		data => maps:get(data, Event, <<>>),
		last_event_id => maps:get(id, Event, <<>>)
	}.
-endif.
