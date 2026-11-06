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
	%% 10 KiB. infinity disables the limit.
	max_event_size = 10240 :: pos_integer() | infinity
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
	-> {event, parsed_event(), State} | {more, State} | {error, limit_reached}
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
			more(Data1, State);
		<<>> ->
			more(<<>>, State);
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
			more(Data, State0)
	end.

%% Soft limit for an unfinished event: buffer when the rough
%% size is =< max_event_size. A finished event is already in
%% memory and is delivered even past the limit. Bytes left
%% after it are checked on the next call.
%%
%% Count "id: \n" when this event set the id, "event: \n" when
%% the type is set, and the tail as-is. Each data line is two
%% list cells, so length div 2 is the line count. 7 per line
%% is "data: \n". iolist_size already includes the stored
%% newline, so add 6 per line. Data, the event type and the
%% tail are not copied; the caller must not grow one binary
%% forever.
more(Buffer, State=#state{max_event_size=Max}) ->
	case event_size(Buffer, State) =< Max of
		true ->
			{more, State#state{buffer=Buffer}};
		false ->
			{error, limit_reached}
	end.

event_size(Buffer, #state{data=Data, event_type=EventType,
		last_event_id=LastEventID, last_event_id_set=Set}) ->
	byte_size(Buffer) + id_size(Set, LastEventID)
		+ event_type_size(EventType) + data_size(Data).

id_size(false, _) ->
	0;
id_size(true, ID) ->
	byte_size(ID) + 5.

event_type_size(<<>>) ->
	0;
event_type_size(Type) ->
	byte_size(Type) + 8.

data_size(Data) ->
	iolist_size(Data) + 6 * (length(Data) div 2).

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
%% The id is kept for later events, so do not leave it
%% as a sub-binary of the input.
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
	{ok, State#state{event_type= <<>>}};
%% Data is an empty string but we have a last_event_id:
%% propagate it on its own so that the caller knows the
%% most recent ID.
dispatch_event(State=#state{last_event_id=LastEventID, data=[]}) ->
	{event, #{
		last_event_id => LastEventID
	}, State#state{last_event_id_set=false, event_type= <<>>}};
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
	}, State#state{last_event_id_set=false, event_type= <<>>, data=[]}}.

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

%% The limit applies when the event is not yet complete. Equal
%% to the limit is kept. A finished event is delivered even past
%% the limit. "data: hi\n" is 9 bytes.
parse_max_event_size_test() ->
	Max10 = init(#{max_event_size => 10}),
	{more, S0} = parse(<<"data: hi\n">>, Max10),
	{event, #{data := Hi}, S1} = parse(<<"\n">>, S0),
	<<"hi">> = iolist_to_binary(Hi),
	{more, _} = parse(<<>>, S1),
	{more, _} = parse(<<"data: hi\n">>, init(#{max_event_size => 9})),
	St = init(#{max_event_size => 8}),
	{error, limit_reached} = parse(<<"data: hi\n">>, St),
	{more, _} = parse(<<"data: h\n">>, St),
	{event, #{data := Hi}, _} = parse(<<"data: hi\n\n">>,
		init(#{max_event_size => 1})),
	{event, _, _} = parse(<<"data: hi\n\n">>, init()),
	{event, _, _} = parse(<<"data: hi\n\n">>, init(#{})),
	{event, _, _} = parse(<<"data: hi\n\n">>,
		init(#{max_event_size => infinity})),
	%% init/0 and a missing key use 10 KiB. The tail is counted as-is.
	{more, _} = parse(binary:copy(<<$a>>, 10240), init()),
	{error, limit_reached} = parse(binary:copy(<<$a>>, 10241), init()),
	{more, _} = parse(binary:copy(<<$a>>, 10240), init(#{})),
	{error, limit_reached} = parse(binary:copy(<<$a>>, 10241), init(#{})),
	ok.

%% "event: ping\n" is 12, "id: ab\n" is 7, two data lines are 16.
%% The id kept after dispatch is not counted for the next event.
%% A finished retry is an integer and is not counted.
parse_max_event_size_fields_test() ->
	{more, _} = parse(<<"event: ping\n">>, init(#{max_event_size => 12})),
	{error, limit_reached} = parse(<<"event: ping\n">>,
		init(#{max_event_size => 11})),
	{more, _} = parse(<<"id: ab\n">>, init(#{max_event_size => 7})),
	{error, limit_reached} = parse(<<"id: ab\n">>,
		init(#{max_event_size => 6})),
	{more, _} = parse(<<"data: a\ndata: b\n">>, init(#{max_event_size => 16})),
	{error, limit_reached} = parse(<<"data: a\ndata: b\n">>,
		init(#{max_event_size => 15})),
	{event, _, S} = parse(<<"id: ab\n\n">>, init(#{max_event_size => 9})),
	{more, _} = parse(<<"data: z\n">>, S),
	{more, _} = parse(<<"retry: 1000\ndata: z\n">>,
		init(#{max_event_size => 9})),
	ok.

%% The id outlives the event. Copy it so the input is not retained.
parse_max_event_size_id_copy_test() ->
	Pad = binary:copy(<<$x>>, 1000),
	Id = binary:copy(<<$i>>, 80),
	Bin = <<"id: ", Id/binary, "\n: ", Pad/binary, "\n">>,
	{more, #state{last_event_id=Stored}} =
		parse(Bin, init(#{max_event_size => 100})),
	Id = Stored,
	erlang:garbage_collect(),
	80 = binary:referenced_byte_size(Stored),
	ok.
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
