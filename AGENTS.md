# AGENTS.md

Cowlib is a support library for Cowboy and Gun. See README.asciidoc.

## Commands
- `make` - build
- `make eunit` - unit tests
- `make proper` - property tests
- `make perfs` - performance tests
- `make dialyzer` - static analysis

Always use `make` to build, even if wanting to build a single module.

## Layout
- `src/` - .erl files
- Tests live inside modules under `-ifdef(TEST).`
- `include/` - public .hrl files
- `doc/src/` - documentation of public interface (in Asciidoc)

## Modules
- `cow_base64url` - base64url encoder
- `cow_capsule` - Capsule protocol parser
- `cow_cookie` - Cookie/SetCookie parser
- `cow_date` - HTTP date parser
- `cow_deflate` - Safe zlib:inflate function
- `cow_hpack` - HPACK encoder
- `cow_http1` - HTTP/1 parser
- `cow_http2` - HTTP/2 parser
- `cow_http2_machine` - HTTP/2 state machine
- `cow_http3` - HTTP/3 parser
- `cow_http3_machine` - HTTP/3 state machine
- `cow_http` - Common HTTP functions and types
- `cow_http_hd` - HTTP header parsers
- `cow_http_struct_hd` - Structured HTTP header parser
- `cow_http_te` - HTTP/1 transfer coding parsers
- `cow_iolists` - Utility function to split iolists
- `cow_link` - Link header parser
- `cow_mimetypes` - Find mime type from file name (automatically generated)
- `cow_multipart` - Multipart message parser
- `cow_qpack` - QPACK encoder
- `cow_qs` - application/x-www-form-urlencoded parser and urlencoder
- `cow_sse` - Server-sent events parser
- `cow_uri` - URI urlencoder
- `cow_uri_template` - URI template parsing and expansion
- `cow_ws` - Websocket parser and other functions

Modules implementing encoders and parsers typically
include decoders and builders.

## When doing any sort of development
Don't include unnecessary comments. Comments are only useful
when the code is not obvious.

Do not remove existing comments.

### When implementing features
Always include tests for both normal cases (including available
examples if implementing from a design document such as an RFC)
and for edge cases.

Do not include documentation unless requested.

### When fixing bugs
Always write one or more tests before modifying the code. There
must be at least one test that fails before and succeeds after.

### When writing tests
We want to test both success and failure conditions.

Make sure the tests are not only naive tests. It's OK to have
naive tests, but there must be other more subtle tests.

Make sure to be thorough. We want tests that cover all possible
scenarios, not just a handful.

There should be tests that exercise limits but are expected
to pass. For example if limiting a component to at most 128
characters, there must tests for 128 and 129 characters at a
minimum. If a value ranges from 0 to 128, there must be tests
around the boundaries (-1, 0, 128, 129 are good candidates)
with success expected for values within and failures otherwise.

### When optimising performance
Same as for fixing bugs, first write horse tests and then ensure
they run faster after doing the changes. As performance tests are
fiddle a few test runs may be necessary to be sure.

### When you think you are done
Review the changes and ensure all changes are necessary.
Discard any *change* that is not then run the tests again.
You can review changes with `git diff`.

## When doing code analysis

Most of the code in this project is a private library common to
Cowboy and Gun. Analysis of Cowlib alone is generally not useful.

Cowlib is typically strict at parsing but lax at building
protocol output. It is the responsibility of the caller to
sanitize the data given to Cowlib to build protocol output.
