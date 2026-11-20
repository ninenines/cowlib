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

%% This module contains functions and types common
%% to all or most HTTP versions.
-module(cow_http).

%% The HTTP/1 functions have been moved to cow_http1.
%% In order to remain backward compatible we redirect
%% calls to cow_http1. The type version() was moved
%% and no fallback is provided.
%%
%% @todo Cowlib 3.0: remove the cow_http1 aliases.
-export([parse_request_line/1]).
-export([parse_status_line/1]).
-export([status_to_integer/1]).
-export([parse_headers/1]).
-export([parse_version/1]).
-export([request/4]).
-export([response/3]).
-export([headers/1]).
-export([version/1]).

%% Functions used by HTTP/2+.

-export([format_semantic_error/1]).
-export([merge_pseudo_headers/2]).
-export([process_headers/5]).
-export([remove_http1_headers/1]).
-export([parse_fullpath/1]).

%% Validation functions.

-export([ensure_absolute_path/1]).
-export([ensure_field_value/1]).
-export([ensure_scheme/1]).
-export([ensure_token/1]).
-export([ensure_token_lowercase/1]).

%% Types used by all versions of HTTP.

-type status() :: 100..999.
-export_type([status/0]).

-type headers() :: [{binary(), iodata()}].
-export_type([headers/0]).

%% Types used by HTTP/2+.

-type pseudo_headers() :: #{} %% Trailers
	| #{ %% Responses.
		status := cow_http:status()
	} | #{ %% Normal CONNECT requests.
		method := binary(),
		authority := binary()
	} | #{ %% Extended CONNECT requests.
		method := binary(),
		scheme := binary(),
		authority := binary(),
		path := binary(),
		protocol := binary()
	} | #{ %% Other requests.
		method := binary(),
		scheme := binary(),
		authority => binary(),
		path := binary()
	}.
-export_type([pseudo_headers/0]).

-type fin() :: fin | nofin.
-export_type([fin/0]).

-include("cow_parse.hrl").

-ifdef(TEST).
-include_lib("stdlib/include/assert.hrl").
-endif.

%% HTTP/1 function aliases.

-spec parse_request_line(binary()) -> {binary(), binary(), cow_http1:version(), binary()}.
parse_request_line(Data) -> cow_http1:parse_request_line(Data).

-spec parse_status_line(binary()) -> {cow_http1:version(), status(), binary(), binary()}.
parse_status_line(Data) -> cow_http1:parse_status_line(Data).

-spec status_to_integer(status() | binary()) -> status().
status_to_integer(Status) -> cow_http1:status_to_integer(Status).

-spec parse_headers(binary()) -> {[{binary(), binary()}], binary()}.
parse_headers(Data) -> cow_http1:parse_headers(Data).

-spec parse_version(binary()) -> cow_http1:version().
parse_version(Data) -> cow_http1:parse_version(Data).

-spec request(binary(), iodata(), cow_http1:version(), headers()) -> iodata().
request(Method, Path, Version, Headers) -> cow_http1:request(Method, Path, Version, Headers).

-spec response(status() | binary(), cow_http1:version(), headers()) -> iodata().
response(Status, Version, Headers) -> cow_http1:response(Status, Version, Headers).

-spec headers(headers()) -> iodata().
headers(Headers) -> cow_http1:headers(Headers).

-spec version(cow_http1:version()) -> binary().
version(Version) -> cow_http1:version(Version).

%% Functions used by HTTP/2+.

%% Semantic errors are common to all HTTP versions.

-spec format_semantic_error(atom()) -> atom().

format_semantic_error(connect_invalid_content_length_2xx) ->
	'Content-length header received in a 2xx response to a CONNECT request. (RFC7230 3.3.2).';
format_semantic_error(invalid_content_length_header) ->
	'The content-length header is invalid. (RFC7230 3.3.2)';
format_semantic_error(invalid_content_length_header_1xx) ->
	'Content-length header received in a 1xx response. (RFC7230 3.3.2)';
format_semantic_error(invalid_content_length_header_204) ->
	'Content-length header received in a 204 response. (RFC7230 3.3.2)';
format_semantic_error(multiple_content_length_headers) ->
	'Multiple content-length headers were received. (RFC7230 3.3.2)'.

%% Merge pseudo headers at the start of headers.

-spec merge_pseudo_headers(pseudo_headers(), headers()) -> headers().

merge_pseudo_headers(PseudoHeaders, Headers0) ->
	lists:foldl(fun
		({status, Status}, Acc) when is_integer(Status) ->
			[{<<":status">>, integer_to_binary(Status)}|Acc];
		({Name, Value}, Acc) ->
			[{iolist_to_binary([$:, atom_to_binary(Name)]), Value}|Acc]
		end, Headers0, maps:to_list(PseudoHeaders)).

%% Process HTTP/2+ headers. This is done after decoding them.

-spec process_headers(headers(), request | push_promise | response | trailers,
		binary() | undefined, fin(), #{enable_connect_protocol => boolean(), any() => any()})
	-> {headers, headers(), pseudo_headers(), non_neg_integer() | undefined}
	| {push_promise, headers(), pseudo_headers()}
	| {trailers, headers()}
	| {error, atom()}.

process_headers(Headers0, Type, ReqMethod, IsFin, LocalSettings)
		when Type =:= request; Type =:= push_promise ->
	IsExtendedConnectEnabled = maps:get(enable_connect_protocol, LocalSettings, false),
	case request_pseudo_headers(Headers0, #{}) of
		%% Extended CONNECT method (HTTP/2: RFC8441, HTTP/3: RFC9220).
		{ok, PseudoHeaders=#{method := <<"CONNECT">>, scheme := _,
			authority := _, path := _, protocol := _}, Headers}
			when IsExtendedConnectEnabled ->
			regular_headers(Headers, Type, ReqMethod, IsFin, PseudoHeaders);
		{ok, #{method := <<"CONNECT">>, scheme := _,
			authority := _, path := _}, _}
			when IsExtendedConnectEnabled ->
			{error, extended_connect_missing_protocol};
		{ok, #{protocol := _}, _} ->
			{error, invalid_protocol_pseudo_header};
		%% Normal CONNECT (no scheme/path).
		{ok, PseudoHeaders = #{method := <<"CONNECT">>, authority := _}, Headers}
				when map_size(PseudoHeaders) =:= 2 ->
			regular_headers(Headers, Type, ReqMethod, IsFin, PseudoHeaders);
		{ok, #{method := <<"CONNECT">>, authority := _}, _} ->
			{error, connect_invalid_pseudo_header};
		{ok, #{method := <<"CONNECT">>}, _} ->
			{error, connect_missing_authority};
		%% Other requests.
		{ok, PseudoHeaders = #{method := _, scheme := _, path := _}, Headers} ->
			regular_headers(Headers, Type, ReqMethod, IsFin, PseudoHeaders);
		{ok, _, _} ->
			{error, missing_pseudo_header};
		Error = {error, _} ->
			Error
	end;
process_headers(Headers0, Type = response, ReqMethod, IsFin, _LocalSettings) ->
	case response_pseudo_headers(Headers0, #{}) of
		{ok, PseudoHeaders=#{status := _}, Headers} ->
			regular_headers(Headers, Type, ReqMethod, IsFin, PseudoHeaders);
		{ok, _, _} ->
			{error, missing_pseudo_header};
		Error = {error, _} ->
			Error
	end;
process_headers(Headers, Type = trailers, ReqMethod, IsFin, _LocalSettings) ->
	case trailers_have_pseudo_headers(Headers) of
		false ->
			regular_headers(Headers, Type, ReqMethod, IsFin, #{});
		true ->
			{error, trailer_invalid_pseudo_header}
	end.

request_pseudo_headers([{<<":method">>, _}|_], #{method := _}) ->
	{error, multiple_method_pseudo_headers};
request_pseudo_headers([{<<":method">>, Method}|Tail], PseudoHeaders) ->
	try validate_token(Method) of
		ok -> request_pseudo_headers(Tail, PseudoHeaders#{method => Method})
	catch _:_ ->
		{error, invalid_pseudo_header}
	end;
request_pseudo_headers([{<<":scheme">>, _}|_], #{scheme := _}) ->
	{error, multiple_scheme_pseudo_headers};
request_pseudo_headers([{<<":scheme">>, Scheme}|Tail], PseudoHeaders) ->
	try validate_scheme(Scheme) of
		ok -> request_pseudo_headers(Tail, PseudoHeaders#{scheme => Scheme})
	catch _:_ ->
		{error, invalid_pseudo_header}
	end;
request_pseudo_headers([{<<":authority">>, _}|_], #{authority := _}) ->
	{error, multiple_authority_pseudo_headers};
request_pseudo_headers([{<<":authority">>, Authority}|Tail], PseudoHeaders) ->
	try validate_field_value(Authority) of
		ok -> request_pseudo_headers(Tail, PseudoHeaders#{authority => Authority})
	catch _:_ ->
		{error, invalid_pseudo_header}
	end;
request_pseudo_headers([{<<":path">>, _}|_], #{path := _}) ->
	{error, multiple_path_pseudo_headers};
%% <<>> and <<"*">> are judged once method and scheme are known.
request_pseudo_headers([{<<":path">>, <<>>}|Tail], PseudoHeaders) ->
	request_pseudo_headers(Tail, PseudoHeaders#{path => <<>>});
request_pseudo_headers([{<<":path">>, <<"*">>}|Tail], PseudoHeaders) ->
	request_pseudo_headers(Tail, PseudoHeaders#{path => <<"*">>});
request_pseudo_headers([{<<":path">>, Path}|Tail], PseudoHeaders) ->
	try validate_absolute_path(Path) of
		ok -> request_pseudo_headers(Tail, PseudoHeaders#{path => Path})
	catch _:_ ->
		{error, invalid_pseudo_header}
	end;
request_pseudo_headers([{<<":protocol">>, _}|_], #{protocol := _}) ->
	{error, multiple_protocol_pseudo_headers};
request_pseudo_headers([{<<":protocol">>, Protocol}|Tail], PseudoHeaders) ->
	try validate_token(Protocol) of
		ok -> request_pseudo_headers(Tail, PseudoHeaders#{protocol => Protocol})
	catch _:_ ->
		{error, invalid_pseudo_header}
	end;
request_pseudo_headers([{<<":", _/bits>>, _}|_], _) ->
	{error, invalid_pseudo_header};
%% <<>> is allowed only when the scheme is not http or https.
%% <<"*">> is allowed only for OPTIONS with an http or https scheme.
request_pseudo_headers(Headers, PseudoHeaders=#{path := <<>>, scheme := Scheme}) ->
	case is_http_scheme(Scheme) of
		true ->
			{error, invalid_pseudo_header};
		false ->
			{ok, PseudoHeaders, Headers}
	end;
request_pseudo_headers(Headers, PseudoHeaders=#{path := <<"*">>,
		method := <<"OPTIONS">>, scheme := Scheme}) ->
	case is_http_scheme(Scheme) of
		true ->
			{ok, PseudoHeaders, Headers};
		false ->
			{error, invalid_pseudo_header}
	end;
request_pseudo_headers(_, #{path := <<"*">>, method := Method})
		when Method =/= <<"OPTIONS">> ->
	{error, invalid_pseudo_header};
request_pseudo_headers(Headers, PseudoHeaders) ->
	{ok, PseudoHeaders, Headers}.

is_http_scheme(<<H, T1, T2, P>>) ->
	(H =:= $h orelse H =:= $H) andalso
	(T1 =:= $t orelse T1 =:= $T) andalso
	(T2 =:= $t orelse T2 =:= $T) andalso
	(P =:= $p orelse P =:= $P);
is_http_scheme(<<H, T1, T2, P, S>>) ->
	(H =:= $h orelse H =:= $H) andalso
	(T1 =:= $t orelse T1 =:= $T) andalso
	(T2 =:= $t orelse T2 =:= $T) andalso
	(P =:= $p orelse P =:= $P) andalso
	(S =:= $s orelse S =:= $S);
is_http_scheme(_) ->
	false.

response_pseudo_headers([{<<":status">>, _}|_], #{status := _}) ->
	{error, multiple_status_pseudo_headers};
response_pseudo_headers([{<<":status">>, Status}|Tail], PseudoHeaders) ->
	try cow_http:status_to_integer(Status) of
		IntStatus ->
			response_pseudo_headers(Tail, PseudoHeaders#{status => IntStatus})
	catch _:_ ->
		{error, invalid_status_pseudo_header}
	end;
response_pseudo_headers([{<<":", _/bits>>, _}|_], _) ->
	{error, invalid_pseudo_header};
response_pseudo_headers(Headers, PseudoHeaders) ->
	{ok, PseudoHeaders, Headers}.

trailers_have_pseudo_headers([]) ->
	false;
trailers_have_pseudo_headers([{<<":", _/bits>>, _}|_]) ->
	true;
trailers_have_pseudo_headers([_|Tail]) ->
	trailers_have_pseudo_headers(Tail).

%% Rejecting invalid regular headers might be a bit too strong for clients.
regular_headers(Headers, Type, ReqMethod, IsFin, PseudoHeaders) ->
	case regular_headers(Headers, Type) of
		ok when Type =:= request ->
			request_expected_size(Headers, IsFin, PseudoHeaders);
		ok when Type =:= push_promise ->
			return_push_promise(Headers, PseudoHeaders);
		ok when Type =:= response ->
			response_expected_size(Headers, ReqMethod, IsFin, PseudoHeaders);
		ok when Type =:= trailers ->
			return_trailers(Headers);
		Error = {error, _} ->
			Error
	end.

regular_headers([{<<>>, _}|_], _) ->
	{error, empty_header_name};
regular_headers([{<<":", _/bits>>, _}|_], _) ->
	{error, pseudo_header_after_regular};
regular_headers([{<<"connection">>, _}|_], _) ->
	{error, invalid_connection_header};
regular_headers([{<<"keep-alive">>, _}|_], _) ->
	{error, invalid_keep_alive_header};
regular_headers([{<<"proxy-authenticate">>, _}|_], _) ->
	{error, invalid_proxy_authenticate_header};
regular_headers([{<<"proxy-authorization">>, _}|_], _) ->
	{error, invalid_proxy_authorization_header};
regular_headers([{<<"transfer-encoding">>, _}|_], _) ->
	{error, invalid_transfer_encoding_header};
regular_headers([{<<"upgrade">>, _}|_], _) ->
	{error, invalid_upgrade_header};
regular_headers([{<<"te">>, Value}|_], request) when Value =/= <<"trailers">> ->
	{error, invalid_te_value};
regular_headers([{<<"te">>, _}|_], Type) when Type =/= request ->
	{error, invalid_te_header};
regular_headers([{Name, Value}|Tail], Type) ->
	try validate_token_lowercase(Name) of
		ok ->
			try validate_field_value(Value) of
				ok -> regular_headers(Tail, Type)
			catch _:_ ->
				{error, invalid_header_value}
			end
	catch _:_ ->
		{error, invalid_header_name}
	end;
regular_headers([], _) ->
	ok.

-ifdef(TEST).
process_headers_name_test() ->
	Name = <<"!#$%&'*+-.^_`|~09az">>,
	{headers, [{Name, <<"v">>}], #{method := <<"GET">>}, 0} = process_headers([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{Name, <<"v">>}
	], request, undefined, fin, #{}),
	ok.

process_headers_name_error_test_() ->
	Names = [
		<<"a b">>,
		<<"a\tb">>,
		<<"a:b">>,
		<<"a(b)">>,
		<<$a, 16#7f>>,
		<<$a, 16#80>>,
		<<"A">>
	],
	[{Name, fun() ->
		{error, invalid_header_name} = process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{Name, <<"v">>}
		], request, undefined, fin, #{})
	end} || Name <- Names].

process_headers_value_test_() ->
	Good = [
		<<>>,
		<<"a">>,
		<<"!">>,
		<<"~">>,
		<<"text/html; charset=utf-8">>,
		<<"a b">>,
		<<"a  b">>,
		<<"a\tb">>,
		<<"a\t\tb">>,
		<<$a, 16#80>>,
		<<16#80>>,
		<<16#ff>>,
		<<$a, 16#80, $b>>
	],
	[{Value, fun() ->
		{headers, [{<<"accept">>, Value}], #{method := <<"GET">>}, 0}
			= process_headers([
				{<<":method">>, <<"GET">>},
				{<<":scheme">>, <<"http">>},
				{<<":path">>, <<"/">>},
				{<<"accept">>, Value}
			], request, undefined, fin, #{})
	end} || Value <- Good].

process_headers_value_error_test_() ->
	Bad = [
		<<" ">>,
		<<$\t>>,
		<<" a">>,
		<<$\t, $a>>,
		<<"a ">>,
		<<$a, $\t>>,
		<<" a ">>,
		<<0>>,
		<<$\n>>,
		<<$\r>>,
		<<$a, 0>>,
		<<$a, $\n>>,
		<<$a, $\r>>,
		<<127>>,
		<<$a, 127>>,
		<<1>>,
		<<31>>,
		<<$a, 8>>,
		<<$a, 11>>,
		<<$a, 12>>
	],
	[{Value, fun() ->
		{error, invalid_header_value} = process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"accept">>, Value}
		], request, undefined, fin, #{})
	end} || Value <- Bad].

%% Not a binary: binary:last/1 raises badarg.
process_headers_value_not_binary_test() ->
	{error, invalid_header_value} = process_headers([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>},
		{<<"accept">>, <<$a, 1:4>>}
	], request, undefined, fin, #{}),
	ok.

process_headers_authority_test() ->
	{headers, [], #{authority := <<"example.com">>}, 0} = process_headers([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"example.com">>},
		{<<":path">>, <<"/">>}
	], request, undefined, fin, #{}),
	{headers, [], #{authority := <<"example.com:443">>}, 0} = process_headers([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"example.com:443">>},
		{<<":path">>, <<"/">>}
	], request, undefined, fin, #{}),
	ok.

process_headers_authority_error_test_() ->
	Authorities = [
		<<" example.com">>,
		<<"example.com ">>,
		<<"example.com\t">>
	],
	[{Authority, fun() ->
		{error, invalid_pseudo_header} = process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"https">>},
			{<<":authority">>, Authority},
			{<<":path">>, <<"/">>}
		], request, undefined, fin, #{})
	end} || Authority <- Authorities].

%% Not a binary: binary:last/1 raises badarg.
process_headers_authority_not_binary_test() ->
	{error, invalid_pseudo_header} = process_headers([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<$a, 1:4>>},
		{<<":path">>, <<"/">>}
	], request, undefined, fin, #{}),
	ok.

process_headers_path_test_() ->
	Reqs = [
		{<<"/">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>}
		]},
		{<<"//x">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"//x">>}
		]},
		{<<"/foo:bar">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo:bar">>}
		]},
		{<<"/foo@bar">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo@bar">>}
		]},
		{<<"/foo*">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo*">>}
		]},
		{<<"/foo(bar)">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo(bar)">>}
		]},
		{<<"/%2f">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/%2f">>}
		]},
		{<<"/%2F">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/%2F">>}
		]},
		%% WHATWG leaves these raw. % that is not two hex digits stays.
		{<<"/foo[]">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo[]">>}
		]},
		{<<"/a|b">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a|b">>}
		]},
		{<<"/%">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/%">>}
		]},
		{<<"/%2">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/%2">>}
		]},
		{<<"/%GG">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/%GG">>}
		]},
		{<<"/?a[]=1">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a[]=1">>}
		]},
		{<<"/?q=100%">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?q=100%">>}
		]},
		{<<"/?a^b">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a^b">>}
		]},
		{<<"/?a`b">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a`b">>}
		]},
		{<<"/?{x}">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?{x}">>}
		]},
		{<<"/?a\\b">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a\\b">>}
		]},
		{<<"/?a|b">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a|b">>}
		]},
		{<<"/?">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?">>}
		]},
		{<<"/?a?b">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a?b">>}
		]},
		{<<"/?a/b">>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a/b">>}
		]},
		{<<"*">>, [
			{<<":method">>, <<"OPTIONS">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"*">>}
		]},
		{<<"*">>, [
			{<<":method">>, <<"OPTIONS">>},
			{<<":scheme">>, <<"https">>},
			{<<":path">>, <<"*">>}
		]},
		{<<"*">>, [
			{<<":method">>, <<"OPTIONS">>},
			{<<":scheme">>, <<"HTTP">>},
			{<<":path">>, <<"*">>}
		]},
		{<<>>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"ftp">>},
			{<<":path">>, <<>>}
		]},
		{<<>>, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"FTP">>},
			{<<":path">>, <<>>}
		]},
		%% :path may precede :method and :scheme.
		{<<"*">>, [
			{<<":path">>, <<"*">>},
			{<<":method">>, <<"OPTIONS">>},
			{<<":scheme">>, <<"http">>}
		]}
	],
	[{iolist_to_binary(io_lib:format("~0p ~0p", [Path, Headers])), fun() ->
		{headers, [], #{path := Path}, _} = process_headers(Headers,
			request, undefined, fin, #{})
	end} || {Path, Headers} <- Reqs].

process_headers_path_error_test_() ->
	Reqs = [
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<>>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"https">>},
			{<<":path">>, <<>>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"HTTP">>},
			{<<":path">>, <<>>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"*">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"https">>},
			{<<":path">>, <<"*">>}
		],
		[
			{<<":method">>, <<"options">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"*">>}
		],
		[
			{<<":method">>, <<"OPTIONS">>},
			{<<":scheme">>, <<"ftp">>},
			{<<":path">>, <<"*">>}
		],
		[
			{<<":method">>, <<"OPTIONS">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"*?">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"ftp">>},
			{<<":path">>, <<"foo">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo bar">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo\tbar">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a\\b">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a^b">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a`b">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/{x}">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a b">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a<b>">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a>b">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a\"b">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a", 127>>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a", 128>>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo#bar">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a\r">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a\n">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/a\0">>}
		],
		[
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"ftp">>},
			{<<":path">>, <<"/a b">>}
		]
	],
	[{iolist_to_binary(io_lib:format("~0p", [Headers])), fun() ->
		{error, invalid_pseudo_header} = process_headers(Headers,
			request, undefined, fin, #{})
	end} || Headers <- Reqs].

process_headers_response_value_test() ->
	{headers, [{<<"server">>, <<"Erlang">>}], #{status := 200}, 0}
		= process_headers([
			{<<":status">>, <<"200">>},
			{<<"server">>, <<"Erlang">>}
		], response, <<"GET">>, fin, #{}),
	{error, invalid_header_value} = process_headers([
		{<<":status">>, <<"200">>},
		{<<"server">>, <<"a", 127>>}
	], response, <<"GET">>, fin, #{}),
	ok.

process_headers_trailers_value_test() ->
	{trailers, [{<<"x">>, <<"a b">>}]} = process_headers([
		{<<"x">>, <<"a b">>}
	], trailers, <<"GET">>, fin, #{}),
	{error, invalid_header_value} = process_headers([
		{<<"x">>, <<" a">>}
	], trailers, <<"GET">>, fin, #{}),
	ok.
-endif.

request_expected_size(Headers, IsFin, PseudoHeaders) ->
	case [CL || {<<"content-length">>, CL} <- Headers] of
		[] when IsFin =:= fin ->
			return_headers(Headers, PseudoHeaders, 0);
		[] ->
			return_headers(Headers, PseudoHeaders, undefined);
		[<<"0">>] ->
			return_headers(Headers, PseudoHeaders, 0);
		[_] when IsFin =:= fin ->
			{error, non_zero_length_with_fin_flag};
		[BinLen] ->
			parse_expected_size(Headers, PseudoHeaders, BinLen);
		_ ->
			{error, multiple_content_length_headers}
	end.

response_expected_size(Headers, ReqMethod, IsFin, PseudoHeaders = #{status := Status}) ->
	case [CL || {<<"content-length">>, CL} <- Headers] of
		[] when IsFin =:= fin ->
			return_headers(Headers, PseudoHeaders, 0);
		[] ->
			return_headers(Headers, PseudoHeaders, undefined);
		[_] when Status >= 100, Status =< 199 ->
			{error, invalid_content_length_header_1xx};
		[<<"0">>] when Status =:= 204, ReqMethod =/= <<"CONNECT">> ->
			return_headers(Headers, PseudoHeaders, 0);
		[_] when Status =:= 204 ->
			{error, invalid_content_length_header_204};
		[_] when Status >= 200, Status =< 299, ReqMethod =:= <<"CONNECT">> ->
			{error, connect_invalid_content_length_2xx};
		%% Responses to HEAD requests, and 304 responses may contain
		%% a content-length header that must be ignored. (RFC7230 3.3.2)
		[_] when ReqMethod =:= <<"HEAD">> ->
			return_headers(Headers, PseudoHeaders, 0);
		[_] when Status =:= 304 ->
			return_headers(Headers, PseudoHeaders, 0);
		[<<"0">>] when IsFin =:= fin ->
			return_headers(Headers, PseudoHeaders, 0);
		[_] when IsFin =:= fin ->
			{error, non_zero_length_with_fin_flag};
		[BinLen] ->
			parse_expected_size(Headers, PseudoHeaders, BinLen);
		_ ->
			{error, multiple_content_length_headers}
	end.

parse_expected_size(Headers, PseudoHeaders, BinLen) ->
	try cow_http_hd:parse_content_length(BinLen) of
		Len ->
			return_headers(Headers, PseudoHeaders, Len)
	catch _:_ ->
		{error, invalid_content_length_header}
	end.

return_headers(Headers, PseudoHeaders, Len) ->
	{headers, Headers, PseudoHeaders, Len}.

return_push_promise(Headers, PseudoHeaders) ->
	{push_promise, Headers, PseudoHeaders}.

return_trailers(Headers) ->
	{trailers, Headers}.

%% Remove HTTP/1-specific headers.

-spec remove_http1_headers(headers()) -> headers().

remove_http1_headers(Headers) ->
	RemoveHeaders0 = [
		<<"keep-alive">>,
		<<"proxy-connection">>,
		<<"transfer-encoding">>,
		<<"upgrade">>
	],
	RemoveHeaders = case lists:keyfind(<<"connection">>, 1, Headers) of
		false ->
			RemoveHeaders0;
		{_, ConnHd} ->
			%% We do not need to worry about any "close" header because
			%% that header name is reserved.
			Connection = cow_http_hd:parse_connection(ConnHd),
			Connection ++ [<<"connection">>|RemoveHeaders0]
	end,
	lists:filter(fun({Name, _}) ->
		not lists:member(Name, RemoveHeaders)
	end, Headers).

%% Extract path and query string from a binary.

-spec parse_fullpath(binary()) -> {binary(), binary()}.

parse_fullpath(Fullpath) ->
	case binary:split(Fullpath, <<$?>>) of
		[Path] -> {Path, <<>>};
		[Path, Query] -> {Path, Query}
	end.

-ifdef(TEST).
parse_fullpath_test() ->
	{<<"*">>, <<>>} = parse_fullpath(<<"*">>),
	{<<"/">>, <<>>} = parse_fullpath(<<"/">>),
	{<<"/path/to/resource">>, <<>>} = parse_fullpath(<<"/path/to/resource">>),
	{<<"/">>, <<>>} = parse_fullpath(<<"/?">>),
	{<<"/">>, <<"q=cowboy">>} = parse_fullpath(<<"/?q=cowboy">>),
	{<<"/path/to/resource">>, <<"q=cowboy">>}
		= parse_fullpath(<<"/path/to/resource?q=cowboy">>),
	ok.
-endif.

%% Validation functions.

%% absolute-path [ "?" query ]. (RFC9110 4.1)
%% A % that is not two hex digits stays as an octet. WHATWG leaves it raw.
-spec ensure_absolute_path(binary()) -> binary().

ensure_absolute_path(Path) ->
	ok = validate_absolute_path(Path),
	Path.

validate_absolute_path(<<$/, Rest/bits>>) ->
	validate_absolute_path(Rest, path).

validate_absolute_path(<<$?, Rest/bits>>, path) ->
	validate_absolute_path(Rest, query);
validate_absolute_path(<<C, Rest/bits>>, path) when ?IS_PCHAR(C); C =:= $/ ->
	validate_absolute_path(Rest, path);
validate_absolute_path(<<C, Rest/bits>>, query) when ?IS_QUERY(C) ->
	validate_absolute_path(Rest, query);
validate_absolute_path(<<>>, _) ->
	ok.

-ifdef(TEST).
ensure_absolute_path_test_() ->
	Paths = [
		<<"/">>, <<"//x">>, <<"/a/../b">>, <<"/.">>,
		<<"/foo:bar">>, <<"/foo@bar">>, <<"/foo*">>, <<"/foo(bar)">>,
		<<"/%2f">>, <<"/%2F">>,
		<<"/foo[]">>, <<"/a|b">>, <<"/%">>, <<"/%2">>, <<"/%GG">>,
		<<"/?a[]=1">>, <<"/?q=100%">>, <<"/?a^b">>, <<"/?a`b">>,
		<<"/?{x}">>, <<"/?a\\b">>, <<"/?a|b">>,
		<<"/?">>, <<"/?a?b">>, <<"/?a/b">>
	],
	[{Path, fun() -> Path = ensure_absolute_path(Path) end} || Path <- Paths].

ensure_absolute_path_error_test_() ->
	Paths = [
		<<>>, <<"*">>, <<"*?">>, <<"foo">>,
		<<"/foo bar">>, <<"/foo\tbar">>,
		<<"/a\\b">>, <<"/a^b">>, <<"/a`b">>, <<"/{x}">>,
		<<"/?a b">>, <<"/?a<b>">>, <<"/?a>b">>, <<"/?a\"b">>,
		<<"/a", 127>>, <<"/a", 128>>,
		<<"/foo#bar">>, <<"/a\r">>, <<"/a\n">>, <<"/a\0">>,
		undefined
	],
	[{iolist_to_binary(io_lib:format("~0p", [Path])),
		fun() -> ?assertError(_, ensure_absolute_path(Path)) end} || Path <- Paths].
-endif.

%% Empty, or field-content. (RFC9110 5.5)
%% Must not start or end with SP or HTAB.
-spec ensure_field_value(binary()) -> binary().

ensure_field_value(Value) ->
	ok = validate_field_value(Value),
	Value.

validate_field_value(Value) ->
	ok = validate_field_value_ends(Value),
	validate_field_chars(Value).

validate_field_value_ends(<<>>) ->
	ok;
validate_field_value_ends(<<C, _/bits>> = Value) when C =/= $\s, C =/= $\t ->
	ok = validate_field_value_last(binary:last(Value)).

validate_field_value_last(C) when C =/= $\s, C =/= $\t ->
	ok.

validate_field_chars(<<C, R/bits>>) when ?IS_VCHAR_OBS(C) ->
	validate_field_chars(R);
validate_field_chars(<<>>) ->
	ok.

-spec ensure_scheme(binary()) -> binary().

ensure_scheme(Scheme) ->
	ok = validate_scheme(Scheme),
	Scheme.

validate_scheme(<<C,R/bits>>) when ?IS_ALPHA(C) ->
	validate_scheme1(R).

validate_scheme1(<<C,R/bits>>)
		when ?IS_ALPHA(C) or ?IS_DIGIT(C) or
		(C =:= $+) or (C =:= $-) or (C =:= $.) ->
	validate_scheme1(R);
validate_scheme1(<<>>) ->
	ok.

-ifdef(TEST).

ensure_scheme_test_() ->
	Tests = [
		<<"a">>, <<"a0">>,
		<<"a+">>, <<"a-">>, <<"a.">>,
		<<"GET">>,
		<<"foo">>,
		<<"foo-bar">>,
		<<"foo+bar">>,
		<<"foo.bar">>,
		%% Long.
		<< <<$a>> || _ <- lists:seq(1, 1024) >>
	],
	[{V, fun() -> V = ensure_scheme(V) end} || V <- Tests].

ensure_scheme_error_test_() ->
	Tests = [
		%% Empty.
		<<>>,
		%% Invalid first.
		<<"9http">>,
		<<"-http">>,
		<<"+http">>,
		<<".http">>,
		<<" http">>,
		<<"_http">>,
		%% Invalid chars.
		<<"a!">>, <<"a#">>, <<"a'">>, <<"a*">>,
		<<"a^">>, <<"a_">>, <<"a`">>, <<"a|">>, <<"a~">>,
		<<"a ">>, <<"a,">>, <<"a:">>, <<"a;">>, <<"a\"">>,
		<<"a(">>, <<"a)">>, <<"a<">>, <<"a>">>, <<"a[">>,
		<<"a]">>, <<"a{">>, <<"a}">>, <<"a\\">>, <<"a?">>,
		<<"a@">>, <<"a\r">>, <<"a\n">>, <<"a\0">>,
		<<$a,16#1f>>, <<$a,16#7f>>, <<$a,16#80>>,
		<<195,169>>, %% é
		%% Invalid type.
		undefined
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() -> ?assertError(_, ensure_scheme(V)) end} || V <- Tests].

-endif.

-spec ensure_token(binary()) -> binary().

ensure_token(Token) ->
	ok = validate_token(Token),
	Token.

validate_token(Token) when Token =/= <<>> ->
	validate_token1(Token).

validate_token1(<<C,R/bits>>) when ?IS_TOKEN(C) -> validate_token1(R);
validate_token1(<<>>) -> ok.

-spec ensure_token_lowercase(binary()) -> binary().

ensure_token_lowercase(Token) ->
	ok = validate_token_lowercase(Token),
	Token.

validate_token_lowercase(Token) when Token =/= <<>> ->
	validate_token_lowercase1(Token).

validate_token_lowercase1(<<C, R/bits>>) when ?IS_LTOKEN(C) ->
	validate_token_lowercase1(R);
validate_token_lowercase1(<<>>) ->
	ok.

-ifdef(TEST).

ensure_field_value_test_() ->
	Tests = [
		{<<>>, <<>>},
		{<<"a">>, <<"a">>},
		{<<"a b">>, <<"a b">>},
		{<<"a\tb">>, <<"a\tb">>},
		{<<128>>, <<128>>},
		{<<255>>, <<255>>},
		{<< <<$a>> || _ <- lists:seq(1, 1024) >>,
			<< <<$a>> || _ <- lists:seq(1, 1024) >>}
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() -> Expected = ensure_field_value(V) end} || {V, Expected} <- Tests].

ensure_field_value_error_test_() ->
	Tests = [
		<<" ">>, <<"\t">>,
		<<" a">>, <<"a ">>, <<"\ta">>, <<"a\t">>, <<" a ">>,
		<<"a", 0>>, <<"a\r">>, <<"a\n">>,
		<<31>>, <<127>>,
		["a", <<" b">>],
		undefined, 256
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() -> ?assertError(_, ensure_field_value(V)) end}
			|| V <- Tests].

ensure_token_test_() ->
	Tests = [
		<<$a>>, <<$0>>, <<"!">>, <<"#">>,
		<<"$">>, <<"%">>, <<"&">>, <<"'">>,
		<<"*">>, <<"+">>, <<"-">>, <<".">>,
		<<"^">>, <<"_">>, <<"`">>, <<"|">>, <<"~">>,
		<<"GET">>,
		<<"foo">>,
		<<"foo-bar">>,
		<<"!#$%&'*+-.^_`|~09azAZ">>,
		%% Long.
		<< <<$a>> || _ <- lists:seq(1, 1024) >>
	],
	[{V, fun() -> V = ensure_token(V) end} || V <- Tests].

ensure_token_error_test_() ->
	Tests = [
		%% Empty.
		<<>>,
		%% Invalid chars.
		<<" ">>, <<",">>, <<":">>, <<";">>, <<"\"">>,
		<<"(">>, <<")">>, <<"<">>, <<">">>, <<"[">>,
		<<"]">>, <<"{">>, <<"}">>, <<"\\">>, <<"?">>,
		<<"@">>, <<$\r>>, <<$\n>>, <<0>>,
		<<16#1f>>, <<16#7f>>, <<16#80>>,
		<<195,169>>, %% é
		%% Invalid in middle.
		<<"a b">>, <<"a,b">>, <<"a:b">>,
		%% Invalid type.
		undefined
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() -> ?assertError(_, ensure_token(V)) end} || V <- Tests].

ensure_token_lowercase_test_() ->
	Tests = [
		<<$a>>, <<$0>>, <<"!">>,
		<<"foo-bar">>,
		<<"!#$%&'*+-.^_`|~09az">>
	],
	[{V, fun() -> V = ensure_token_lowercase(V) end} || V <- Tests].

ensure_token_lowercase_error_test_() ->
	Tests = [
		<<>>,
		<<"A">>, <<"GET">>,
		<<" ">>, <<":">>, <<$\r>>, <<$\n>>, <<0>>,
		<<16#7f>>,
		undefined
	],
	[{iolist_to_binary(io_lib:format("~0p", [V])),
		fun() -> ?assertError(_, ensure_token_lowercase(V)) end}
			|| V <- Tests].

-endif.
