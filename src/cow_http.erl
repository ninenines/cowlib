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

-export([ensure_scheme/1]).
-export([ensure_token/1]).

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
		{ok, PseudoHeaders=#{method := <<"CONNECT">>, scheme := Scheme,
			authority := _, path := Path, protocol := _}, Headers}
			when IsExtendedConnectEnabled ->
			case validate_request_path(<<"CONNECT">>, Scheme, Path) of
				ok -> regular_headers(Headers, Type, ReqMethod, IsFin, PseudoHeaders);
				error -> {error, invalid_pseudo_header}
			end;
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
		{ok, PseudoHeaders = #{method := Method, scheme := Scheme, path := Path}, Headers} ->
			case validate_request_path(Method, Scheme, Path) of
				ok -> regular_headers(Headers, Type, ReqMethod, IsFin, PseudoHeaders);
				error -> {error, invalid_pseudo_header}
			end;
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
	case validate_authority(Authority) of
		ok -> request_pseudo_headers(Tail, PseudoHeaders#{authority => Authority});
		error -> {error, invalid_pseudo_header}
	end;
request_pseudo_headers([{<<":path">>, _}|_], #{path := _}) ->
	{error, multiple_path_pseudo_headers};
request_pseudo_headers([{<<":path">>, Path}|Tail], PseudoHeaders) ->
	case validate_path(Path) of
		ok -> request_pseudo_headers(Tail, PseudoHeaders#{path => Path});
		error -> {error, invalid_pseudo_header}
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
request_pseudo_headers(Headers, PseudoHeaders) ->
	{ok, PseudoHeaders, Headers}.

%% http(s) :path must start with / once '?' is split off, or be
%% exactly "*". Asterisk-form is only method OPTIONS. The scheme
%% match is case insensitive, and :path may arrive before :scheme.
validate_request_path(Method, Scheme, Path) ->
	case string:lowercase(Scheme) of
		Http when Http =:= <<"http">>; Http =:= <<"https">> ->
			validate_http_path(Method, Path);
		_ ->
			ok
	end.

validate_http_path(<<"OPTIONS">>, <<"*">>) ->
	ok;
validate_http_path(_, Path) ->
	case parse_fullpath(Path) of
		{<<$/, _/bits>>, _} -> ok;
		_ -> error
	end.

%% An empty host that carries a port is not an empty authority.
%% A missing port stays undefined. A present port is 1..65535.
validate_authority(Authority) ->
	try cow_http_hd:parse_host(Authority) of
		{<<>>, undefined} ->
			ok;
		{<<>>, _} ->
			error;
		{_, undefined} ->
			ok;
		{_, Port} when Port > 0, Port =< 65535 ->
			ok;
		_ ->
			error
	catch _:_ ->
		error
	end.

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
regular_headers([{<<"host">>, Value}|Tail], Type)
		when Type =:= request; Type =:= push_promise ->
	case validate_authority(Value) of
		ok -> regular_headers(Tail, Type);
		error -> {error, invalid_header_value}
	end;
regular_headers([{Name, Value}|Tail], Type) ->
	case validate_header_name(Name) of
		ok ->
			case validate_header(Value) of
				ok -> regular_headers(Tail, Type);
				error -> {error, invalid_header_value}
			end;
		error ->
			{error, invalid_header_name}
	end;
regular_headers([], _) ->
	ok.

%% Lowercase token. (RFC 9110 5.6.2, RFC 9113 8.2.1)
validate_header_name(<<C, R/bits>>) when ?IS_TOKEN(C), (C < $A orelse C > $Z) ->
	validate_header_name(R);
validate_header_name(<<>>) ->
	ok;
validate_header_name(_) ->
	error.

%% Reject CR, LF and NUL anywhere, and leading or trailing SP/HTAB.
validate_header(<<>>) ->
	ok;
validate_header(<<C, _/bits>>) when ?IS_WS(C) ->
	error;
validate_header(Value) ->
	case binary:last(Value) of
		C when ?IS_WS(C) ->
			error;
		_ ->
			case binary:match(Value, [<<$\r>>, <<$\n>>, <<$\0>>]) of
				nomatch -> ok;
				_ -> error
			end
	end.

%% Reject CR, LF, NUL, SP and # anywhere, and leading or trailing HTAB.
validate_path(<<>>) ->
	ok;
validate_path(<<C, _/bits>>) when ?IS_WS(C) ->
	error;
validate_path(Value) ->
	case binary:last(Value) of
		C when ?IS_WS(C) ->
			error;
		_ ->
			case binary:match(Value, [<<$\s>>, <<$\r>>, <<$\n>>, <<$\0>>, <<$\#>>]) of
				nomatch -> ok;
				_ -> error
			end
	end.

-ifdef(TEST).
process_headers_test() ->
	{headers, [{<<"x-foo">>, <<"a b">>}, {<<"x-empty">>, <<>>}],
			#{method := <<"GET">>, scheme := <<"http">>,
				authority := <<>>, path := <<"/">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<>>},
			{<<":path">>, <<"/">>},
			{<<"x-foo">>, <<"a b">>},
			{<<"x-empty">>, <<>>}
		], request, undefined, fin, #{}),
	{headers, [], #{method := <<"OPTIONS">>, scheme := <<"http">>, path := <<"*">>}, 0}
		= process_headers([
			{<<":method">>, <<"OPTIONS">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"*">>}
		], request, undefined, fin, #{}),
	{headers, [], #{scheme := <<"http">>, path := <<"//evil.com/x">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"//evil.com/x">>}
		], request, undefined, fin, #{}),
	{headers, [], #{scheme := <<"foo">>, path := <<"bar">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"foo">>},
			{<<":path">>, <<"bar">>}
		], request, undefined, fin, #{}),
	{headers, [], #{path := <<"/foo\tbar">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo\tbar">>}
		], request, undefined, fin, #{}),
	{headers, [], #{path := <<"/x?q">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"https">>},
			{<<":path">>, <<"/x?q">>}
		], request, undefined, fin, #{}),
	%% A non-http scheme may omit the path component.
	{headers, [], #{scheme := <<"foo">>, path := <<>>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"foo">>},
			{<<":path">>, <<>>}
		], request, undefined, fin, #{}),
	{headers, [], #{authority := <<"%2Ftmp%2Fsock">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<"%2Ftmp%2Fsock">>},
			{<<":path">>, <<"/">>}
		], request, undefined, fin, #{}),
	{headers, [], #{authority := <<"[2001:db8::1]">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"https">>},
			{<<":authority">>, <<"[2001:db8::1]">>},
			{<<":path">>, <<"/">>}
		], request, undefined, fin, #{}),
	{headers, [], #{authority := <<"localhost:1">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<"localhost:1">>},
			{<<":path">>, <<"/">>}
		], request, undefined, fin, #{}),
	{headers, [], #{authority := <<"localhost:65535">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<"localhost:65535">>},
			{<<":path">>, <<"/">>}
		], request, undefined, fin, #{}),
	{headers, [{<<"host">>, <<>>}], #{authority := <<>>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<>>},
			{<<":path">>, <<"/">>},
			{<<"host">>, <<>>}
		], request, undefined, fin, #{}),
	{headers, [{<<"host">>, <<"localhost:8080">>}], #{}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"host">>, <<"localhost:8080">>}
		], request, undefined, fin, #{}),
	{headers, [{<<"!#$%&'*+-.^_`|~">>, <<"z">>}],
			#{method := <<"GET">>, path := <<"/">>}, 0}
		= process_headers([
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"!#$%&'*+-.^_`|~">>, <<"z">>}
		], request, undefined, fin, #{}),
	{headers, [], #{method := <<"CONNECT">>, authority := <<"example.com:443">>}, 0}
		= process_headers([
			{<<":method">>, <<"CONNECT">>},
			{<<":authority">>, <<"example.com:443">>}
		], request, undefined, fin, #{}),
	{headers, [], #{protocol := <<"websocket">>, path := <<"/">>}, 0}
		= process_headers([
			{<<":method">>, <<"CONNECT">>},
			{<<":scheme">>, <<"https">>},
			{<<":authority">>, <<"example.com">>},
			{<<":path">>, <<"/">>},
			{<<":protocol">>, <<"websocket">>}
		], request, undefined, fin, #{enable_connect_protocol => true}),
	{headers, [{<<"x-foo">>, <<"a\tb">>}], #{status := 200}, 0}
		= process_headers([
			{<<":status">>, <<"200">>},
			{<<"x-foo">>, <<"a\tb">>}
		], response, <<"GET">>, fin, #{}),
	{trailers, [{<<"x-foo">>, <<"a b">>}]}
		= process_headers([{<<"x-foo">>, <<"a b">>}], trailers, undefined, fin, #{}),
	ok.

process_headers_error_test_() ->
	Tests = [
		%% Field names are lowercase tokens.
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"content-length ">>, <<"1">>}
		], invalid_header_name},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"x foo">>, <<"a">>}
		], invalid_header_name},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<$x, 1, $y>>, <<"a">>}
		], invalid_header_name},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"x:y">>, <<"a">>}
		], invalid_header_name},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"x/y">>, <<"a">>}
		], invalid_header_name},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"Content-Length">>, <<"1">>}
		], invalid_header_name},
		%% No leading or trailing SP/HTAB in values.
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"x-foo">>, <<" leading">>}
		], invalid_header_value},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"x-foo">>, <<"trailing ">>}
		], invalid_header_value},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"x-foo">>, <<"\tleading">>}
		], invalid_header_value},
		{trailers, #{}, [
			{<<"x-foo">>, <<"trailing\t">>}
		], invalid_header_value},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"x-foo">>, <<"a\r\nb">>}
		], invalid_header_value},
		%% http(s) :path must start with /, or be OPTIONS *. :path may precede :scheme.
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<>>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":path">>, <<>>},
			{<<":scheme">>, <<"HTTPS">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"https">>},
			{<<":path">>, <<"?">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"?q">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<" /">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/ ">>}
		], invalid_pseudo_header},
		{request, #{enable_connect_protocol => true}, [
			{<<":method">>, <<"CONNECT">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<"example.com">>},
			{<<":path">>, <<>>},
			{<<":protocol">>, <<"websocket">>}
		], invalid_pseudo_header},
		{request, #{enable_connect_protocol => true}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"https">>},
			{<<":authority">>, <<"example.com">>},
			{<<":path">>, <<"/">>},
			{<<":protocol">>, <<"websocket">>}
		], invalid_protocol_pseudo_header},
		%% http(s) :path starts with / unless it is OPTIONS *.
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"*">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"OPTIONS">>},
			{<<":scheme">>, <<"https">>},
			{<<":path">>, <<"*?q">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"@evil.com/x">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"https">>},
			{<<":path">>, <<".evil.com">>}
		], invalid_pseudo_header},
		%% SP ends an HTTP/1 request-target, including in the query.
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/foo bar">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/?a b">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"foo">>},
			{<<":path">>, <<"/a b">>}
		], invalid_pseudo_header},
		{response, #{}, [
			{<<":status">>, <<"200">>},
			{<<"x foo">>, <<"a">>}
		], invalid_header_name},
		%% :authority is a host, not an arbitrary field value.
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<"a b@c/d">>},
			{<<":path">>, <<"/">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<"user@host">>},
			{<<":path">>, <<"/">>}
		], invalid_pseudo_header},
		%% A port is 1..65535. An empty host with a port is not an empty authority.
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<"localhost:0">>},
			{<<":path">>, <<"/">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<"localhost:65536">>},
			{<<":path">>, <<"/">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":authority">>, <<":80">>},
			{<<":path">>, <<"/">>}
		], invalid_pseudo_header},
		{request, #{}, [
			{<<":method">>, <<"GET">>},
			{<<":scheme">>, <<"http">>},
			{<<":path">>, <<"/">>},
			{<<"host">>, <<"localhost:0">>}
		], invalid_header_value}
	],
	[{iolist_to_binary(io_lib:format("~0p", [Headers])),
		fun() ->
			{error, Reason} = process_headers(Headers, Type, undefined, fin, Settings)
		end} || {Type, Settings, Headers, Reason} <- Tests].
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

-ifdef(TEST).

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

-endif.
