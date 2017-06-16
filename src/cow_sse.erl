%% Copyright (c) 2017, Loïc Hoguin <essen@ninenines.eu>
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
-export([parse/2]).

-record(state, {
	state_name = bom :: bom | events,
	buffer = <<>> :: binary(),
	last_event_id = <<>> :: binary(),
	event_type = <<>> :: binary(),
	data = [] :: iolist(),
	retry = undefined :: undefined | non_neg_integer()
}).
-type state() :: #state{}.
-export_type([state/0]).

-type event() :: #{
	last_event_id := binary(),
	event_type := binary(),
	data := iolist()
}.

-spec init() -> state().
init() ->
	#state{}.

%% @todo Add a function to retrieve the retry value from the state.

-spec parse(binary(), state())
	-> {event, event(), State} | {more, State}.
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

parse_event(Data, State0) ->
	case binary:split(Data, [<<"\r\n">>, <<"\r">>, <<"\n">>]) of
		[Line, Rest] ->
			case parse_line(Line, State0) of
				{ok, State} ->
					parse_event(Rest, State);
				{event, Event, State} ->
					{event, Event, State#state{buffer=Rest}}
			end;
		[_] ->
			{more, State0#state{buffer=Data}}
	end.

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
	{ok, State#state{last_event_id=Value}};
process_field(<<"retry">>, Value, State) ->
	try
		{ok, State#state{retry=binary_to_integer(Value)}}
	catch _:_ ->
		{ok, State}
	end;
process_field(_, _, State) ->
	{ok, State}.

%% Data is an empty string; abort.
dispatch_event(State=#state{data=[]}) ->
	{ok, State#state{event_type= <<>>}};
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
	}, State#state{event_type= <<>>, data=[]}}.

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

parse_split_event_test() ->
	{more, State} = parse(<<
		"data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">>, init()),
	{event, _, _} = parse(<<"==\n\n">>, State),
	ok.

-endif.
