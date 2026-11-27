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

-module(cow_multipart).

%% Parsing.
-export([parse_headers/2]).
-export([parse_body/2]).

%% Building.
-export([boundary/0]).
-export([first_part/2]).
-export([part/2]).
-export([close/1]).

%% Headers.
-export([form_data/1]).
-export([parse_content_disposition/1]).
-export([parse_content_transfer_encoding/1]).
-export([parse_content_type/1]).

-type headers() :: [{iodata(), iodata()}].
-export_type([headers/0]).

-include("cow_inline.hrl").
-include("cow_parse.hrl").

-define(TEST1_MIME, <<
	"This is a message with multiple parts in MIME format.\r\n"
	"--frontier\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"This is the body of the message.\r\n"
	"--frontier\r\n"
	"Content-Type: application/octet-stream\r\n"
	"Content-Transfer-Encoding: base64\r\n"
	"\r\n"
	"PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPHA+VGhpcyBpcyB0aGUg\r\n"
	"Ym9keSBvZiB0aGUgbWVzc2FnZS48L3A+CiAgPC9ib2R5Pgo8L2h0bWw+Cg==\r\n"
	"--frontier--"
>>).
-define(TEST1_BOUNDARY, <<"frontier">>).

-define(TEST2_MIME, <<
	"--AaB03x\r\n"
	"Content-Disposition: form-data; name=\"submit-name\"\r\n"
	"\r\n"
	"Larry\r\n"
	"--AaB03x\r\n"
	"Content-Disposition: form-data; name=\"files\"\r\n"
	"Content-Type: multipart/mixed; boundary=BbC04y\r\n"
	"\r\n"
	"--BbC04y\r\n"
	"Content-Disposition: file; filename=\"file1.txt\"\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"... contents of file1.txt ...\r\n"
	"--BbC04y\r\n"
	"Content-Disposition: file; filename=\"file2.gif\"\r\n"
	"Content-Type: image/gif\r\n"
	"Content-Transfer-Encoding: binary\r\n"
	"\r\n"
	"...contents of file2.gif...\r\n"
	"--BbC04y--\r\n"
	"--AaB03x--"
>>).
-define(TEST2_BOUNDARY, <<"AaB03x">>).

-define(TEST3_MIME, <<
	"This is the preamble.\r\n"
	"--boundary\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"This is the body of the message.\r\n"
	"--boundary--"
	"\r\nThis is the epilogue. Here it includes leading CRLF"
>>).
-define(TEST3_BOUNDARY, <<"boundary">>).

-define(TEST4_MIME, <<
	"This is the preamble.\r\n"
	"--boundary\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"This is the body of the message.\r\n"
	"--boundary--"
	"\r\n"
>>).
-define(TEST4_BOUNDARY, <<"boundary">>).

%% RFC 2046, Section 5.1.1
-define(TEST5_MIME, <<
        "This is the preamble.  It is to be ignored, though it\r\n"
        "is a handy place for composition agents to include an\r\n"
        "explanatory note to non-MIME conformant readers.\r\n"
        "\r\n"
        "--simple boundary\r\n",
        "\r\n"
        "This is implicitly typed plain US-ASCII text.\r\n"
        "It does NOT end with a linebreak."
        "\r\n"
        "--simple boundary\r\n",
        "Content-type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        "This is explicitly typed plain US-ASCII text.\r\n"
        "It DOES end with a linebreak.\r\n"
        "\r\n"
        "--simple boundary--\r\n"
        "\r\n"
        "This is the epilogue.  It is also to be ignored."
>>).
-define(TEST5_BOUNDARY, <<"simple boundary">>).

%% Parsing.
%%
%% The multipart format is defined in RFC 2045.

%% @doc Parse the headers for the next multipart part.
%%
%% This function skips any preamble before the boundary.
%% The preamble may be retrieved using parse_body/2.
%%
%% This function will accept input of any size, it is
%% up to the caller to limit it if needed.

-spec parse_headers(binary(), binary())
	-> more | {more, binary()}
	| {ok, headers(), binary()}
	| {done, binary()}.
%% If the stream starts with the boundary we can make a few assumptions
%% and quickly figure out if we got the complete list of headers.
parse_headers(<< "--", Stream/bits >>, Boundary) ->
	BoundarySize = byte_size(Boundary),
	case Stream of
		%% Last boundary. Return the epilogue.
		<< Boundary:BoundarySize/binary, "--", Stream2/bits >> ->
			{done, Stream2};
		<< Boundary:BoundarySize/binary, Stream2/bits >> ->
			%% We have all the headers only if there is a \r\n\r\n
			%% somewhere in the data after the boundary.
			case binary:match(Stream2, <<"\r\n\r\n">>) of
				nomatch ->
					more;
				_ ->
					before_parse_headers(Stream2)
			end;
		%% If there isn't enough to represent Boundary \r\n\r\n
		%% then we definitely don't have all the headers.
		_ when byte_size(Stream) < byte_size(Boundary) + 4 ->
			more;
		%% Otherwise we have preamble data to skip.
		%% We still got rid of the first two misleading bytes.
		_ ->
			skip_preamble(Stream, Boundary)
	end;
%% Otherwise we have preamble data to skip.
parse_headers(Stream, Boundary) ->
	skip_preamble(Stream, Boundary).

%% We need to find the boundary and a \r\n\r\n after that.
%% Since the boundary isn't at the start, it must be right
%% after a \r\n too.
skip_preamble(Stream, Boundary) ->
	case binary:match(Stream, <<"\r\n--", Boundary/bits >>) of
		%% No boundary, need more data.
		nomatch ->
			%% We can safely skip the size of the stream
			%% minus the last 3 bytes which may be a partial boundary.
			SkipSize = byte_size(Stream) - 3,
			case SkipSize > 0 of
				false ->
					more;
				true ->
					<< _:SkipSize/binary, Stream2/bits >> = Stream,
					{more, Stream2}
			end;
		{Start, Length} ->
			Start2 = Start + Length,
			<< _:Start2/binary, Stream2/bits >> = Stream,
			case Stream2 of
				%% Last boundary. Return the epilogue.
				<< "--", Stream3/bits >> ->
					{done, Stream3};
				_ ->
					case binary:match(Stream, <<"\r\n\r\n">>) of
						%% We don't have the full headers.
						nomatch ->
							{more, Stream2};
						_ ->
							before_parse_headers(Stream2)
					end
			end
	end.

before_parse_headers(<< "\r\n\r\n", Stream/bits >>) ->
	%% This indicates that there are no headers, so we can abort immediately.
	{ok, [], Stream};
before_parse_headers(<< "\r\n", Stream/bits >>) ->
	%% There is a line break right after the boundary, skip it.
	parse_hd_name(Stream, [], <<>>).

parse_hd_name(<< $:, Rest/bits >>, H, SoFar) when SoFar =/= <<>> ->
	parse_hd_before_value(Rest, H, SoFar);
parse_hd_name(<< C, Rest/bits >>, H, SoFar) when ?IS_FTEXT(C) ->
	?LOWER(parse_hd_name, Rest, H, SoFar);
parse_hd_name(<< _, _/bits >>, _, _) ->
	error(invalid_header_name).

parse_hd_before_value(<< $\s, Rest/bits >>, H, N) ->
	parse_hd_before_value(Rest, H, N);
parse_hd_before_value(<< $\t, Rest/bits >>, H, N) ->
	parse_hd_before_value(Rest, H, N);
parse_hd_before_value(Buffer, H, N) ->
	parse_hd_value(Buffer, H, N, <<>>).

parse_hd_value(<< $\r, Rest/bits >>, Headers, Name, SoFar) ->
	case Rest of
		<< "\n\r\n", Rest2/bits >> ->
			{ok, [{Name, SoFar}|Headers], Rest2};
		%% Unfolding removes the CRLF and keeps the WSP.
		%% Do not collapse that WSP the way cow_http1 does.
		%% Before any value octet the WSP is still leading.
		<< $\n, C, Rest2/bits >>
				when C =:= $\s, SoFar =:= <<>>;
					C =:= $\t, SoFar =:= <<>> ->
			parse_hd_before_value(Rest2, Headers, Name);
		<< $\n, C, Rest2/bits >>
				when C =:= $\s, SoFar =/= <<>>;
					C =:= $\t, SoFar =/= <<>> ->
			parse_hd_value(Rest2, Headers, Name, << SoFar/binary, C >>);
		<< $\n, Rest2/bits >> ->
			parse_hd_name(Rest2, [{Name, SoFar}|Headers], <<>>);
		_ ->
			error(invalid_header_value)
	end;
%% VCHAR, SP, HTAB, or obs-text. 0x80-0xFF stays because
%% browsers send raw UTF-8 in filename and name.
parse_hd_value(<< C, Rest/bits >>, H, N, SoFar) when ?IS_VCHAR_OBS(C) ->
	parse_hd_value(Rest, H, N, << SoFar/binary, C >>);
parse_hd_value(<< _, _/bits >>, _, _, _) ->
	error(invalid_header_value).

%% @doc Parse the body of the current multipart part.
%%
%% The body is everything until the next boundary.

-spec parse_body(binary(), binary())
	-> {ok, binary()} | {ok, binary(), binary()}
	| done | {done, binary()} | {done, binary(), binary()}.
parse_body(Stream, Boundary) ->
	BoundarySize = byte_size(Boundary),
	case Stream of
		<< "--", Boundary:BoundarySize/binary, _/bits >> ->
			done;
		_ ->
			case binary:match(Stream, << "\r\n--", Boundary/bits >>) of
				%% No boundary, check for a possible partial at the end.
				%% Return more or less of the body depending on the result.
				nomatch ->
					StreamSize = byte_size(Stream),
					From = StreamSize - BoundarySize - 3,
					MatchOpts = if
						%% Binary too small to contain boundary, check it fully.
						From < 0 -> [];
						%% Optimize, only check the end of the binary.
						true -> [{scope, {From, StreamSize - From}}]
					end,
					case binary:match(Stream, <<"\r">>, MatchOpts) of
						nomatch ->
							{ok, Stream};
						{Pos, _} ->
							case Stream of
								<< Body:Pos/binary >> ->
									{ok, Body};
								<< Body:Pos/binary, Rest/bits >> ->
									{ok, Body, Rest}
							end
					end;
				%% Boundary found, this is the last chunk of the body.
				{Pos, _} ->
					case Stream of
						<< Body:Pos/binary, "\r\n" >> ->
							{done, Body};
						<< Body:Pos/binary, "\r\n", Rest/bits >> ->
							{done, Body, Rest};
						<< Body:Pos/binary, Rest/bits >> ->
							{done, Body, Rest}
					end
			end
	end.

-ifdef(TEST).
parse_test() ->
	H1 = [{<<"content-type">>, <<"text/plain">>}],
	Body1 = <<"This is the body of the message.">>,
	H2 = lists:sort([{<<"content-type">>, <<"application/octet-stream">>},
		{<<"content-transfer-encoding">>, <<"base64">>}]),
	Body2 = <<"PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPHA+VGhpcyBpcyB0aGUg\r\n"
		"Ym9keSBvZiB0aGUgbWVzc2FnZS48L3A+CiAgPC9ib2R5Pgo8L2h0bWw+Cg==">>,
	{ok, H1, Rest} = parse_headers(?TEST1_MIME, ?TEST1_BOUNDARY),
	{done, Body1, Rest2} = parse_body(Rest, ?TEST1_BOUNDARY),
	done = parse_body(Rest2, ?TEST1_BOUNDARY),
	{ok, H2Unsorted, Rest3} = parse_headers(Rest2, ?TEST1_BOUNDARY),
	H2 = lists:sort(H2Unsorted),
	{done, Body2, Rest4} = parse_body(Rest3, ?TEST1_BOUNDARY),
	done = parse_body(Rest4, ?TEST1_BOUNDARY),
	{done, <<>>} = parse_headers(Rest4, ?TEST1_BOUNDARY),
	ok.

parse_interleaved_test() ->
	H1 = [{<<"content-disposition">>, <<"form-data; name=\"submit-name\"">>}],
	Body1 = <<"Larry">>,
	H2 = lists:sort([{<<"content-disposition">>, <<"form-data; name=\"files\"">>},
		{<<"content-type">>, <<"multipart/mixed; boundary=BbC04y">>}]),
	InH1 = lists:sort([{<<"content-disposition">>, <<"file; filename=\"file1.txt\"">>},
		{<<"content-type">>, <<"text/plain">>}]),
	InBody1 = <<"... contents of file1.txt ...">>,
	InH2 = lists:sort([{<<"content-disposition">>, <<"file; filename=\"file2.gif\"">>},
		{<<"content-type">>, <<"image/gif">>},
		{<<"content-transfer-encoding">>, <<"binary">>}]),
	InBody2 = <<"...contents of file2.gif...">>,
	{ok, H1, Rest} = parse_headers(?TEST2_MIME, ?TEST2_BOUNDARY),
	{done, Body1, Rest2} = parse_body(Rest, ?TEST2_BOUNDARY),
	done = parse_body(Rest2, ?TEST2_BOUNDARY),
	{ok, H2Unsorted, Rest3} = parse_headers(Rest2, ?TEST2_BOUNDARY),
	H2 = lists:sort(H2Unsorted),
	{_, ContentType} = lists:keyfind(<<"content-type">>, 1, H2),
	{<<"multipart">>, <<"mixed">>, [{<<"boundary">>, InBoundary}]}
		= parse_content_type(ContentType),
	{ok, InH1Unsorted, InRest} = parse_headers(Rest3, InBoundary),
	InH1 = lists:sort(InH1Unsorted),
	{done, InBody1, InRest2} = parse_body(InRest, InBoundary),
	done = parse_body(InRest2, InBoundary),
	{ok, InH2Unsorted, InRest3} = parse_headers(InRest2, InBoundary),
	InH2 = lists:sort(InH2Unsorted),
	{done, InBody2, InRest4} = parse_body(InRest3, InBoundary),
	done = parse_body(InRest4, InBoundary),
	{done, Rest4} = parse_headers(InRest4, InBoundary),
	{done, <<>>} = parse_headers(Rest4, ?TEST2_BOUNDARY),
	ok.

parse_epilogue_test() ->
	H1 = [{<<"content-type">>, <<"text/plain">>}],
	Body1 = <<"This is the body of the message.">>,
	Epilogue = <<"\r\nThis is the epilogue. Here it includes leading CRLF">>,
	{ok, H1, Rest} = parse_headers(?TEST3_MIME, ?TEST3_BOUNDARY),
	{done, Body1, Rest2} = parse_body(Rest, ?TEST3_BOUNDARY),
	done = parse_body(Rest2, ?TEST3_BOUNDARY),
	{done, Epilogue} = parse_headers(Rest2, ?TEST3_BOUNDARY),
	ok.

parse_epilogue_crlf_test() ->
	H1 = [{<<"content-type">>, <<"text/plain">>}],
	Body1 = <<"This is the body of the message.">>,
	Epilogue = <<"\r\n">>,
	{ok, H1, Rest} = parse_headers(?TEST4_MIME, ?TEST4_BOUNDARY),
	{done, Body1, Rest2} = parse_body(Rest, ?TEST4_BOUNDARY),
	done = parse_body(Rest2, ?TEST4_BOUNDARY),
	{done, Epilogue} = parse_headers(Rest2, ?TEST4_BOUNDARY),
	ok.

parse_rfc2046_test() ->
	%% The following is an example included in RFC 2046, Section 5.1.1.
	Body1 = <<"This is implicitly typed plain US-ASCII text.\r\n"
		"It does NOT end with a linebreak.">>,
	Body2 = <<"This is explicitly typed plain US-ASCII text.\r\n"
		"It DOES end with a linebreak.\r\n">>,
	H2 = [{<<"content-type">>, <<"text/plain; charset=us-ascii">>}],
	Epilogue = <<"\r\n\r\nThis is the epilogue.  It is also to be ignored.">>,
	{ok, [], Rest} = parse_headers(?TEST5_MIME, ?TEST5_BOUNDARY),
	{done, Body1, Rest2} = parse_body(Rest, ?TEST5_BOUNDARY),
	{ok, H2, Rest3} = parse_headers(Rest2, ?TEST5_BOUNDARY),
	{done, Body2, Rest4} = parse_body(Rest3, ?TEST5_BOUNDARY),
	{done, Epilogue} = parse_headers(Rest4, ?TEST5_BOUNDARY),
	ok.

parse_partial_test() ->
	{ok, <<0:8000, "abcdef">>, <<"\rghij">>}
		= parse_body(<<0:8000, "abcdef\rghij">>, <<"boundary">>),
	{ok, <<"abcdef">>, <<"\rghij">>}
		= parse_body(<<"abcdef\rghij">>, <<"boundary">>),
	{ok, <<"abc">>, <<"\rdef">>}
		= parse_body(<<"abc\rdef">>, <<"boundaryboundary">>),
	{ok, <<0:8000, "abcdef">>, <<"\r\nghij">>}
		= parse_body(<<0:8000, "abcdef\r\nghij">>, <<"boundary">>),
	{ok, <<"abcdef">>, <<"\r\nghij">>}
		= parse_body(<<"abcdef\r\nghij">>, <<"boundary">>),
	{ok, <<"abc">>, <<"\r\ndef">>}
		= parse_body(<<"abc\r\ndef">>, <<"boundaryboundary">>),
	{ok, <<"boundary">>, <<"\r">>}
		= parse_body(<<"boundary\r">>, <<"boundary">>),
	{ok, <<"boundary">>, <<"\r\n">>}
		= parse_body(<<"boundary\r\n">>, <<"boundary">>),
	{ok, <<"boundary">>, <<"\r\n-">>}
		= parse_body(<<"boundary\r\n-">>, <<"boundary">>),
	{ok, <<"boundary">>, <<"\r\n--">>}
		= parse_body(<<"boundary\r\n--">>, <<"boundary">>),
	ok.

parse_hd_name_test_() ->
	Boundary = <<"deadbeef">>,
	Tests = [
		{<<"x/y: v\r\n\r\n">>, [{<<"x/y">>, <<"v">>}]},
		{<<"X(Y): v\r\n\r\n">>, [{<<"x(y)">>, <<"v">>}]},
		{<<"!: v\r\n\r\n">>, [{<<"!">>, <<"v">>}]},
		{<<"9: v\r\n\r\n">>, [{<<"9">>, <<"v">>}]},
		{<<";: v\r\n\r\n">>, [{<<";">>, <<"v">>}]},
		{<<"~: v\r\n\r\n">>, [{<<"~">>, <<"v">>}]}
	],
	[{V, fun() ->
		{ok, Expected, <<"--deadbeef--">>} = parse_headers(
			<<"--deadbeef\r\n", V/binary, "--deadbeef--">>, Boundary)
	end} || {V, Expected} <- Tests].

parse_hd_name_error_test_() ->
	Boundary = <<"deadbeef">>,
	Tests = [
		<<": v\r\n\r\n">>,
		<<" : v\r\n\r\n">>,
		<<"Name : v\r\n\r\n">>,
		<<"X Y: v\r\n\r\n">>,
		<<"a\t: v\r\n\r\n">>,
		<<$a, 31, ": v\r\n\r\n">>,
		<<$a, 127, ": v\r\n\r\n">>,
		<<$a, 128, ": v\r\n\r\n">>
	],
	[{V, fun() ->
		ok = try parse_headers(<<"--deadbeef\r\n", V/binary>>, Boundary) of
			_ -> error(unexpected_success)
		catch
			error:invalid_header_name -> ok
		end
	end} || V <- Tests].

parse_hd_value_test_() ->
	Boundary = <<"deadbeef">>,
	Tests = [
		{<<"n:\r\n\r\n">>, [{<<"n">>, <<>>}]},
		{<<"n: \t \r\n\r\n">>, [{<<"n">>, <<>>}]},
		{<<"n:   v\r\n\r\n">>, [{<<"n">>, <<"v">>}]},
		{<<"n:\tv\r\n\r\n">>, [{<<"n">>, <<"v">>}]},
		{<<"n: \t v\r\n\r\n">>, [{<<"n">>, <<"v">>}]},
		{<<"n:\r\n v\r\n\r\n">>, [{<<"n">>, <<"v">>}]},
		{<<"n:\r\n\tv\r\n\r\n">>, [{<<"n">>, <<"v">>}]},
		{<<"n: v \r\n\r\n">>, [{<<"n">>, <<"v ">>}]},
		{<<"n: v\t\r\n\r\n">>, [{<<"n">>, <<"v\t">>}]},
		{<<"n: v \t \r\n\r\n">>, [{<<"n">>, <<"v \t ">>}]},
		{<<"n: a \tb\r\n\r\n">>, [{<<"n">>, <<"a \tb">>}]},
		{<<"n: !\r\n\r\n">>, [{<<"n">>, <<"!">>}]},
		{<<"n: ~\r\n\r\n">>, [{<<"n">>, <<"~">>}]},
		{<<$n, ": ", 128, "\r\n\r\n">>, [{<<"n">>, <<128>>}]},
		{<<$n, ": ", 255, "\r\n\r\n">>, [{<<"n">>, <<255>>}]},
		{<<"n: ", 195, 169, "\r\n\r\n">>, [{<<"n">>, <<195, 169>>}]},
		{<<"n: %22%0A%0D\\\"\r\n\r\n">>, [{<<"n">>, <<"%22%0A%0D\\\"">>}]},
		{<<"n: v \r\nx: y\r\n\r\n">>,
			[{<<"x">>, <<"y">>}, {<<"n">>, <<"v ">>}]},
		{<<"n: ab\r\n cd\r\n\r\n">>, [{<<"n">>, <<"ab cd">>}]},
		{<<"n: ab\r\n\tcd\r\n\r\n">>, [{<<"n">>, <<"ab\tcd">>}]},
		{<<"n: ab\r\n  cd\r\n\r\n">>, [{<<"n">>, <<"ab  cd">>}]},
		{<<"n: ab\r\n \tcd\r\n\r\n">>, [{<<"n">>, <<"ab \tcd">>}]},
		{<<"n: ab \r\n cd\r\n\r\n">>, [{<<"n">>, <<"ab  cd">>}]},
		{<<"n: ab\r\n cd\r\n ef\r\n\r\n">>, [{<<"n">>, <<"ab cd ef">>}]},
		{<<"n: v\r\n \r\n\r\n">>, [{<<"n">>, <<"v ">>}]},
		{<<"n: v\r\n\t\r\n\r\n">>, [{<<"n">>, <<"v\t">>}]},
		{<<"n:\r\n  v\r\n\r\n">>, [{<<"n">>, <<"v">>}]},
		{<<"n:\r\n \tv\r\n\r\n">>, [{<<"n">>, <<"v">>}]},
		{<<"n:\r\n \r\n\r\n">>, [{<<"n">>, <<>>}]},
		{<<"n:\r\n\t\r\n\r\n">>, [{<<"n">>, <<>>}]},
		{<<"n: filename=\"evil\r\n .php\"\r\n\r\n">>,
			[{<<"n">>, <<"filename=\"evil .php\"">>}]},
		{<<"n: name=\"a\"\r\n\tb\r\n\r\n">>,
			[{<<"n">>, <<"name=\"a\"\tb">>}]},
		{<<"n: ab\r\nx: y\r\n\r\n">>,
			[{<<"x">>, <<"y">>}, {<<"n">>, <<"ab">>}]}
	],
	[{V, fun() ->
		{ok, Expected, <<"--deadbeef--">>} = parse_headers(
			<<"--deadbeef\r\n", V/binary, "--deadbeef--">>, Boundary)
	end} || {V, Expected} <- Tests].

%% Many leading folds must stay linear. Copying the tail on
%% each fold is quadratic.
parse_hd_leading_fold_cost_test() ->
	_ = leading_fold_reductions(200),
	R1 = leading_fold_reductions(1000),
	R8 = leading_fold_reductions(8000),
	case R8 < R1 * 24 of
		true -> ok;
		false -> error({R1, R8})
	end.

leading_fold_reductions(N) ->
	Fold = binary:copy(<<"\r\n ">>, N),
	Bin = <<"--deadbeef\r\nn:", Fold/binary, "v\r\n\r\n--deadbeef--">>,
	{reductions, R0} = erlang:process_info(self(), reductions),
	{ok, [{<<"n">>, <<"v">>}], <<"--deadbeef--">>}
		= parse_headers(Bin, <<"deadbeef">>),
	{reductions, R1} = erlang:process_info(self(), reductions),
	R1 - R0.

parse_hd_value_error_test_() ->
	Boundary = <<"deadbeef">>,
	Tests = [
		<<$n, ": a", 1, "b\r\n\r\n">>,
		<<$n, ": a", 31, "b\r\n\r\n">>,
		<<$n, ": a", 127, "b\r\n\r\n">>,
		<<"n: a\nb\r\n\r\n">>,
		<<"n: a\rb\r\n\r\n">>,
		<<"n: a\r\r\n\r\n">>,
		<<$n, ": ", 10, "\r\n\r\n">>,
		<<$n, ": ", 127, "\r\n\r\n">>
	],
	[{V, fun() ->
		ok = try parse_headers(<<"--deadbeef\r\n", V/binary>>, Boundary) of
			_ -> error(unexpected_success)
		catch
			error:invalid_header_value -> ok
		end
	end} || V <- Tests].

parse_headers_reject_nul_test_() ->
	Boundary = <<"deadbeef">>,
	Tests = [
		<<"--deadbeef\r\n", 0, "x-bad: value\r\n\r\nbody\r\n--deadbeef--">>,
		<<"--deadbeef\r\nx-", 0, "bad: value\r\n\r\nbody\r\n--deadbeef--">>,
		<<"--deadbeef\r\nx-bad", 0, ": value\r\n\r\nbody\r\n--deadbeef--">>,
		<<"--deadbeef\r\nx-bad: ", 0, "value\r\n\r\nbody\r\n--deadbeef--">>,
		<<"--deadbeef\r\nx-bad: val", 0, "ue\r\n\r\nbody\r\n--deadbeef--">>,
		<<"--deadbeef\r\nx-bad: value", 0, "\r\n\r\nbody\r\n--deadbeef--">>,
		<<"--deadbeef\r\n"
			"content-disposition: form-data; name=\"a\"; "
			"filename=\"fi", 0, "le.txt\"\r\n"
			"\r\nbody\r\n--deadbeef--">>
	],
	[{iolist_to_binary(V), fun() ->
		ok = try parse_headers(iolist_to_binary(V), Boundary) of
			_ -> error(unexpected_success)
		catch
			error:invalid_header_name -> ok;
			error:invalid_header_value -> ok
		end
	end} || V <- Tests].

perf_parse_multipart(Stream, Boundary) ->
	case parse_headers(Stream, Boundary) of
		{ok, _, Rest} ->
			{_, _, Rest2} = parse_body(Rest, Boundary),
			perf_parse_multipart(Rest2, Boundary);
		{done, _} ->
			ok
	end.

horse_parse() ->
	horse:repeat(50000,
		perf_parse_multipart(?TEST1_MIME, ?TEST1_BOUNDARY)
	).
-endif.

%% Building.

%% @doc Generate a new random boundary.
%%
%% The boundary generated has a low probability of ever appearing
%% in the data.

-spec boundary() -> binary().
boundary() ->
	cow_base64url:encode(crypto:strong_rand_bytes(48), #{padding => false}).

%% @doc Return the first part's head.
%%
%% This works exactly like the part/2 function except there is
%% no leading \r\n. It's not required to use this function,
%% just makes the output a little smaller and prettier.

-spec first_part(binary(), headers()) -> iodata().
first_part(Boundary, Headers) ->
	[<<"--">>, Boundary, <<"\r\n">>, headers_to_iolist(Headers, [])].

%% @doc Return a part's head.

-spec part(binary(), headers()) -> iodata().
part(Boundary, Headers) ->
	[<<"\r\n--">>, Boundary, <<"\r\n">>, headers_to_iolist(Headers, [])].

headers_to_iolist([], Acc) ->
	lists:reverse([<<"\r\n">>|Acc]);
headers_to_iolist([{N0, V0}|Tail], Acc) ->
	N = ensure_hd_name(N0),
	V = ensure_hd_value(V0),
	%% We don't want to create a sublist so we list the
	%% values in reverse order so that it gets reversed properly.
	headers_to_iolist(Tail, [<<"\r\n">>, V, <<": ">>, N|Acc]).

-spec ensure_hd_name(iodata()) -> binary().
ensure_hd_name(Name0) ->
	Name = iolist_to_binary(Name0),
	ok = validate_hd_name(Name),
	Name.

validate_hd_name(Name) when Name =/= <<>> ->
	validate_hd_name1(Name).

validate_hd_name1(<< C, R/bits >>) when ?IS_FTEXT(C) ->
	validate_hd_name1(R);
validate_hd_name1(<<>>) ->
	ok.

-spec ensure_hd_value(iodata()) -> binary().
ensure_hd_value(Value0) ->
	Value = iolist_to_binary(Value0),
	ok = validate_hd_value(Value),
	Value.

validate_hd_value(<< C, R/bits >>) when ?IS_VCHAR_OBS(C) ->
	validate_hd_value(R);
validate_hd_value(<<>>) ->
	ok.

%% @doc Return the closing delimiter of the multipart message.

-spec close(binary()) -> iodata().
close(Boundary) ->
	[<<"\r\n--">>, Boundary, <<"--">>].

-ifdef(TEST).
build_test() ->
	Result = string:lowercase(?TEST1_MIME),
	Result = string:lowercase(iolist_to_binary([
		<<"This is a message with multiple parts in MIME format.\r\n">>,
		first_part(?TEST1_BOUNDARY, [{<<"content-type">>, <<"text/plain">>}]),
		<<"This is the body of the message.">>,
		part(?TEST1_BOUNDARY, [
			{<<"content-type">>, <<"application/octet-stream">>},
			{<<"content-transfer-encoding">>, <<"base64">>}]),
		<<"PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPHA+VGhpcyBpcyB0aGUg\r\n"
			"Ym9keSBvZiB0aGUgbWVzc2FnZS48L3A+CiAgPC9ib2R5Pgo8L2h0bWw+Cg==">>,
		close(?TEST1_BOUNDARY)
	])),
	ok.

part_hd_name_test() ->
	[<<"\r\n--">>, <<"b">>, <<"\r\n">>,
		[<<"Content-Type">>, <<": ">>, <<"text/plain">>, <<"\r\n">>, <<"\r\n">>]]
		= part(<<"b">>, [{["Content-", "Type"], <<"text/plain">>}]),
	[<<"\r\n--">>, <<"b">>, <<"\r\n">>,
		[<<"x/y">>, <<": ">>, <<"v">>, <<"\r\n">>, <<"\r\n">>]]
		= part(<<"b">>, [{<<"x/y">>, <<"v">>}]),
	ok.

ensure_hd_name_test_() ->
	Tests = [
		{<<"!">>, <<"!">>},
		{<<$9>>, <<$9>>},
		{<<$;>>, <<$;>>},
		{<<$~>>, <<$~>>},
		{<<"x/y">>, <<"x/y">>},
		{<<"x(y)">>, <<"x(y)">>},
		{<<"\"(),/;<=>?@[\\]{}">>, <<"\"(),/;<=>?@[\\]{}">>},
		{<<"Content-Type">>, <<"Content-Type">>},
		{["Content-", "Type"], <<"Content-Type">>},
		{[$C, $o, $n, $t, $e, $n, $t, $-, $T, $y, $p, $e], <<"Content-Type">>}
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() -> Expected = ensure_hd_name(V) end}
			|| {V, Expected} <- Tests].

ensure_hd_name_error_test_() ->
	Tests = [
		<<>>,
		<<" ">>, <<"\t">>,
		<<":">>, <<"a b">>, <<"a:b">>, <<"a\tb">>,
		<<0>>, <<31>>, <<32>>, <<58>>, <<127>>, <<128>>,
		<<195, 169>>,
		["a", $\s, "b"],
		undefined
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() ->
			ok = try ensure_hd_name(V) of
				_ -> error(unexpected_success)
			catch
				error:function_clause -> ok;
				error:badarg -> ok
			end
		end} || V <- Tests].

part_hd_name_error_test_() ->
	Tests = [
		<<>>,
		<<" ">>,
		["a", $\s, "b"],
		undefined
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() ->
			ok = try part(<<"b">>, [{V, <<"v">>}]) of
				_ -> error(unexpected_success)
			catch
				error:function_clause -> ok;
				error:badarg -> ok
			end
		end} || V <- Tests].

part_hd_value_test() ->
	[<<"\r\n--">>, <<"b">>, <<"\r\n">>, [
		<<"n">>, <<": ">>, <<"a b">>, <<"\r\n">>,
		<<"n2">>, <<": ">>, <<>>, <<"\r\n">>,
		<<"\r\n">>
	]] = part(<<"b">>, [
		{<<"n">>, ["a", $\s, "b"]},
		{<<"n2">>, <<>>}
	]),
	[<<"\r\n--">>, <<"b">>, <<"\r\n">>, [
		<<"n">>, <<": ">>, <<" v ">>, <<"\r\n">>,
		<<"\r\n">>
	]] = part(<<"b">>, [{<<"n">>, <<" v ">>}]),
	ok.

ensure_hd_value_test_() ->
	Tests = [
		{<<>>, <<>>},
		{<<"v">>, <<"v">>},
		{<<" ">>, <<" ">>},
		{<<"\t">>, <<"\t">>},
		{<<" v ">>, <<" v ">>},
		{<<"\tv\t">>, <<"\tv\t">>},
		{<<"a b">>, <<"a b">>},
		{<<"a\tb">>, <<"a\tb">>},
		{<<"!">>, <<"!">>},
		{<<"~">>, <<"~">>},
		{<<128>>, <<128>>},
		{<<255>>, <<255>>},
		{<<195, 169>>, <<195, 169>>},
		{<<"%22%0A%0D\\\"">>, <<"%22%0A%0D\\\"">>},
		{["a", $\s, "b"], <<"a b">>},
		{[$a, $\s, $b], <<"a b">>}
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() -> Expected = ensure_hd_value(V) end}
			|| {V, Expected} <- Tests].

ensure_hd_value_error_test_() ->
	Tests = [
		<<0>>, <<1>>, <<31>>, <<10>>, <<13>>, <<127>>,
		<<"a\nb">>, <<"a\rb">>, <<"a\r\n\r\nb">>,
		undefined
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() ->
			ok = try ensure_hd_value(V) of
				_ -> error(unexpected_success)
			catch
				error:function_clause -> ok;
				error:badarg -> ok
			end
		end} || V <- Tests].

part_hd_value_error_test_() ->
	Tests = [
		<<"a\r\n\r\nb">>,
		<<"\n">>,
		<<1>>,
		undefined
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() ->
			ok = try part(<<"b">>, [{<<"n">>, V}]) of
				_ -> error(unexpected_success)
			catch
				error:function_clause -> ok;
				error:badarg -> ok
			end
		end} || V <- Tests].

identity_test() ->
	B = boundary(),
	Preamble = <<"This is a message with multiple parts in MIME format.">>,
	H1 = [{<<"content-type">>, <<"text/plain">>}],
	Body1 = <<"This is the body of the message.">>,
	H2 = lists:sort([{<<"content-type">>, <<"application/octet-stream">>},
		{<<"content-transfer-encoding">>, <<"base64">>}]),
	Body2 = <<"PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPHA+VGhpcyBpcyB0aGUg\r\n"
		"Ym9keSBvZiB0aGUgbWVzc2FnZS48L3A+CiAgPC9ib2R5Pgo8L2h0bWw+Cg==">>,
	Epilogue = <<"Gotta go fast!">>,
	M = iolist_to_binary([
		Preamble,
		part(B, H1), Body1,
		part(B, H2), Body2,
		close(B),
		Epilogue
	]),
	{done, Preamble, M2} = parse_body(M, B),
	{ok, H1, M3} = parse_headers(M2, B),
	{done, Body1, M4} = parse_body(M3, B),
	{ok, H2Unsorted, M5} = parse_headers(M4, B),
	H2 = lists:sort(H2Unsorted),
	{done, Body2, M6} = parse_body(M5, B),
	{done, Epilogue} = parse_headers(M6, B),
	ok.

perf_build_multipart() ->
	B = boundary(),
	[
		<<"preamble\r\n">>,
		first_part(B, [{<<"content-type">>, <<"text/plain">>}]),
		<<"This is the body of the message.">>,
		part(B, [
			{<<"content-type">>, <<"application/octet-stream">>},
			{<<"content-transfer-encoding">>, <<"base64">>}]),
		<<"PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPHA+VGhpcyBpcyB0aGUg\r\n"
			"Ym9keSBvZiB0aGUgbWVzc2FnZS48L3A+CiAgPC9ib2R5Pgo8L2h0bWw+Cg==">>,
		close(B),
		<<"epilogue">>
	].

horse_build() ->
	horse:repeat(50000,
		perf_build_multipart()
	).
-endif.

%% Headers.

%% @doc Convenience function for extracting information from headers
%% when parsing a multipart/form-data stream.

-spec form_data(headers() | #{binary() => binary()})
	-> {data, binary()}
	| {file, binary(), binary(), binary()}.
form_data(Headers) when is_map(Headers) ->
	form_data(maps:to_list(Headers));
form_data(Headers) ->
	{_, DispositionBin} = lists:keyfind(<<"content-disposition">>, 1, Headers),
	{<<"form-data">>, Params} = parse_content_disposition(DispositionBin),
	{_, FieldName} = lists:keyfind(<<"name">>, 1, Params),
	case lists:keyfind(<<"filename">>, 1, Params) of
		false ->
			{data, FieldName};
		{_, Filename} ->
			Type = case lists:keyfind(<<"content-type">>, 1, Headers) of
				false -> <<"text/plain">>;
				{_, T} -> T
			end,
			{file, FieldName, Filename, Type}
	end.

-ifdef(TEST).
form_data_test_() ->
	Tests = [
		{[{<<"content-disposition">>, <<"form-data; name=\"submit-name\"">>}],
			{data, <<"submit-name">>}},
		{[{<<"content-disposition">>,
				<<"form-data; name=\"files\"; filename=\"file1.txt\"">>},
			{<<"content-type">>, <<"text/x-plain">>}],
			{file, <<"files">>, <<"file1.txt">>, <<"text/x-plain">>}}
	],
	[{lists:flatten(io_lib:format("~p", [V])),
		fun() -> R = form_data(V) end} || {V, R} <- Tests].
-endif.

%% @doc Parse an RFC 2183 content-disposition value.
%% @todo Decode RFC 8187/2231 extended parameters.

-spec parse_content_disposition(binary())
	-> {binary(), [{binary(), binary()}]}.
parse_content_disposition(Bin) ->
	parse_cd_type(Bin, <<>>).

parse_cd_type(<<>>, Acc) ->
	{Acc, []};
parse_cd_type(<< C, Rest/bits >>, Acc) ->
	case C of
		$; -> {Acc, parse_before_param(Rest, [], disposition)};
		$\s -> {Acc, parse_before_param(Rest, [], disposition)};
		$\t -> {Acc, parse_before_param(Rest, [], disposition)};
		_ -> ?LOWER(parse_cd_type, Rest, Acc)
	end.

-ifdef(TEST).
parse_content_disposition_test_() ->
	Tests = [
		{<<"inline">>, {<<"inline">>, []}},
		{<<"attachment">>, {<<"attachment">>, []}},
		{<<"attachment; filename=genome.jpeg;"
			"  modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";">>,
			{<<"attachment">>, [
				{<<"filename">>, <<"genome.jpeg">>},
				{<<"modification-date">>, <<"Wed, 12 Feb 1997 16:29:51 -0500">>}
			]}},
		{<<"form-data; name=\"user\"">>,
			{<<"form-data">>, [{<<"name">>, <<"user">>}]}},
		{<<"form-data; NAME=\"submit-name\"">>,
			{<<"form-data">>, [{<<"name">>, <<"submit-name">>}]}},
		{<<"form-data; name=\"files\"; filename=\"file1.txt\"">>,
			{<<"form-data">>, [
				{<<"name">>, <<"files">>},
				{<<"filename">>, <<"file1.txt">>}
			]}},
		{<<"file; filename=\"file1.txt\"">>,
			{<<"file">>, [{<<"filename">>, <<"file1.txt">>}]}},
		{<<"file; filename=\"file2.gif\"">>,
			{<<"file">>, [{<<"filename">>, <<"file2.gif">>}]}},
		{<<"form-data; name=\"file\"; filename=\"z:\\tmp\\test.txt\"">>,
			{<<"form-data">>, [
				{<<"name">>, <<"file">>},
				{<<"filename">>, <<"z:\\tmp\\test.txt">>}
			]}},
		{<<"form-data; name=\"a\\b\"">>,
			{<<"form-data">>, [{<<"name">>, <<"a\\b">>}]}},
		{<<"form-data; filename=\"foo\\\"">>,
			{<<"form-data">>, [{<<"filename">>, <<"foo\\">>}]}},
		{<<"form-data; name=\"a%22b%0D%0A\"">>,
			{<<"form-data">>, [{<<"name">>, <<"a%22b%0D%0A">>}]}}
	],
	[{V, fun() -> R = parse_content_disposition(V) end} || {V, R} <- Tests].

horse_parse_content_disposition_attachment() ->
	horse:repeat(100000,
		parse_content_disposition(<<"attachment; filename=genome.jpeg;"
			"  modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";">>)
	).

horse_parse_content_disposition_form_data() ->
	horse:repeat(100000,
		parse_content_disposition(
			<<"form-data; name=\"files\"; filename=\"file1.txt\"">>)
	).

horse_parse_content_disposition_inline() ->
	horse:repeat(100000,
		parse_content_disposition(<<"inline">>)
	).
-endif.

%% @doc Parse an RFC 2045 content-transfer-encoding header.

-spec parse_content_transfer_encoding(binary()) -> binary().
parse_content_transfer_encoding(Bin) ->
	?LOWER(Bin).

-ifdef(TEST).
parse_content_transfer_encoding_test_() ->
	Tests = [
		{<<"7bit">>, <<"7bit">>},
		{<<"7BIT">>, <<"7bit">>},
		{<<"8bit">>, <<"8bit">>},
		{<<"binary">>, <<"binary">>},
		{<<"quoted-printable">>, <<"quoted-printable">>},
		{<<"base64">>, <<"base64">>},
		{<<"Base64">>, <<"base64">>},
		{<<"BASE64">>, <<"base64">>},
		{<<"bAsE64">>, <<"base64">>}
	],
	[{V, fun() -> R = parse_content_transfer_encoding(V) end}
		|| {V, R} <- Tests].

horse_parse_content_transfer_encoding() ->
	horse:repeat(100000,
		parse_content_transfer_encoding(<<"QUOTED-PRINTABLE">>)
	).
-endif.

%% @doc Parse an RFC 2045 content-type header.

-spec parse_content_type(binary())
	-> {binary(), binary(), [{binary(), binary()}]}.
parse_content_type(Bin) ->
	parse_ct_type(Bin, <<>>).

parse_ct_type(<< C, Rest/bits >>, Acc) ->
	case C of
		$/ -> parse_ct_subtype(Rest, Acc, <<>>);
		_ -> ?LOWER(parse_ct_type, Rest, Acc)
	end.

parse_ct_subtype(<<>>, Type, Subtype) when Subtype =/= <<>> ->
	{Type, Subtype, []};
parse_ct_subtype(<< C, Rest/bits >>, Type, Acc) ->
	case C of
		$; -> {Type, Acc, parse_before_param(Rest, [], content_type)};
		$\s -> {Type, Acc, parse_before_param(Rest, [], content_type)};
		$\t -> {Type, Acc, parse_before_param(Rest, [], content_type)};
		_ -> ?LOWER(parse_ct_subtype, Rest, Type, Acc)
	end.

-ifdef(TEST).
parse_content_type_test_() ->
	Tests = [
		{<<"image/gif">>,
			{<<"image">>, <<"gif">>, []}},
		{<<"text/plain">>,
			{<<"text">>, <<"plain">>, []}},
		{<<"text/plain; charset=us-ascii">>,
			{<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]}},
		{<<"text/plain; charset=\"us-ascii\"">>,
			{<<"text">>, <<"plain">>, [{<<"charset">>, <<"us-ascii">>}]}},
		{<<"text/plain; charset=\"a\\b\"">>,
			{<<"text">>, <<"plain">>, [{<<"charset">>, <<"ab">>}]}},
		{<<"text/plain; charset=\"a\\\\b\"">>,
			{<<"text">>, <<"plain">>, [{<<"charset">>, <<"a\\b">>}]}},
		{<<"multipart/form-data; boundary=AaB03x">>,
			{<<"multipart">>, <<"form-data">>,
				[{<<"boundary">>, <<"AaB03x">>}]}},
		{<<"multipart/mixed; boundary=BbC04y">>,
			{<<"multipart">>, <<"mixed">>, [{<<"boundary">>, <<"BbC04y">>}]}},
		{<<"multipart/mixed; boundary=--------">>,
			{<<"multipart">>, <<"mixed">>, [{<<"boundary">>, <<"--------">>}]}},
		{<<"application/x-horse; filename=genome.jpeg;"
				"  some-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";"
				"  charset=us-ascii; empty=; number=12345">>,
			{<<"application">>, <<"x-horse">>, [
				{<<"filename">>, <<"genome.jpeg">>},
				{<<"some-date">>, <<"Wed, 12 Feb 1997 16:29:51 -0500">>},
				{<<"charset">>, <<"us-ascii">>},
				{<<"empty">>, <<>>},
				{<<"number">>, <<"12345">>}
			]}}
	],
	[{V, fun() -> R = parse_content_type(V) end}
		|| {V, R} <- Tests].

horse_parse_content_type_zero() ->
	horse:repeat(100000,
		parse_content_type(<<"text/plain">>)
	).

horse_parse_content_type_one() ->
	horse:repeat(100000,
		parse_content_type(<<"text/plain; charset=\"us-ascii\"">>)
	).

horse_parse_content_type_five() ->
	horse:repeat(100000,
		parse_content_type(<<"application/x-horse; filename=genome.jpeg;"
			"  some-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";"
			"  charset=us-ascii; empty=; number=12345">>)
	).
-endif.

%% @doc Parse RFC 2045 parameters.

parse_before_param(<<>>, Params, _Kind) ->
	lists:reverse(Params);
parse_before_param(<< C, Rest/bits >>, Params, Kind) ->
	case C of
		$; -> parse_before_param(Rest, Params, Kind);
		$\s -> parse_before_param(Rest, Params, Kind);
		$\t -> parse_before_param(Rest, Params, Kind);
		_ -> ?LOWER(parse_param_name, Rest, Params, Kind, <<>>)
	end.

parse_param_name(<<>>, Params, _Kind, Acc) ->
	lists:reverse([{Acc, <<>>}|Params]);
parse_param_name(<< C, Rest/bits >>, Params, Kind, Acc) ->
	case C of
		$= -> parse_param_value(Rest, Params, Kind, Acc);
		_ -> ?LOWER(parse_param_name, Rest, Params, Kind, Acc)
	end.

parse_param_value(<<>>, Params, _Kind, Name) ->
	lists:reverse([{Name, <<>>}|Params]);
parse_param_value(<< $", Rest/bits >>, Params, disposition, Name) ->
	parse_cd_quoted_value(Rest, Params, Name, <<>>);
parse_param_value(<< $", Rest/bits >>, Params, content_type, Name) ->
	parse_ct_quoted_value(Rest, Params, Name, <<>>);
parse_param_value(<< C, Rest/bits >>, Params, Kind, Name) ->
	case C of
		$; -> parse_before_param(Rest, [{Name, <<>>}|Params], Kind);
		$\s -> parse_before_param(Rest, [{Name, <<>>}|Params], Kind);
		$\t -> parse_before_param(Rest, [{Name, <<>>}|Params], Kind);
		C -> parse_param_value(Rest, Params, Kind, Name, << C >>)
	end.

parse_param_value(<<>>, Params, _Kind, Name, Acc) ->
	lists:reverse([{Name, Acc}|Params]);
parse_param_value(<< C, Rest/bits >>, Params, Kind, Name, Acc) ->
	case C of
		$; -> parse_before_param(Rest, [{Name, Acc}|Params], Kind);
		$\s -> parse_before_param(Rest, [{Name, Acc}|Params], Kind);
		$\t -> parse_before_param(Rest, [{Name, Acc}|Params], Kind);
		C -> parse_param_value(Rest, Params, Kind, Name, << Acc/binary, C >>)
	end.

%% We expect a final $" so no need to test for <<>>.
parse_cd_quoted_value(<< $", Rest/bits >>, Params, Name, Acc) ->
	parse_before_param(Rest, [{Name, Acc}|Params], disposition);
%% HTML multipart leaves "\" as a byte inside quotes.
%% This is an HTML exception to the RFC 822 quoted-pair algorithm.
parse_cd_quoted_value(<< C, Rest/bits >>, Params, Name, Acc)
		when C =/= $\r ->
	parse_cd_quoted_value(Rest, Params, Name, << Acc/binary, C >>).

%% We expect a final $" so no need to test for <<>>.
parse_ct_quoted_value(<< $\\, C, Rest/bits >>, Params, Name, Acc) ->
	parse_ct_quoted_value(Rest, Params, Name, << Acc/binary, C >>);
parse_ct_quoted_value(<< $", Rest/bits >>, Params, Name, Acc) ->
	parse_before_param(Rest, [{Name, Acc}|Params], content_type);
parse_ct_quoted_value(<< C, Rest/bits >>, Params, Name, Acc)
		when C =/= $\r ->
	parse_ct_quoted_value(Rest, Params, Name, << Acc/binary, C >>).
