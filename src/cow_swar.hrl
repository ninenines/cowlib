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

%% SWAR (SIMD Within A Register) helpers for validating 7 bytes at once.
%%
%% We use 56 bits (7 bytes) because it is the largest value that fits
%% in a BEAM small integer (59-bit on 64-bit). This ensures bitwise and
%% arithmetic guard operations (band, bor, bxor, +, -) compile to fast
%% native code without bignum fallback.
%%
%% Call sites must provide a byte-by-byte fallback when the SWAR check
%% fails; the same fallback is also responsible for handling tails
%% shorter than 7 bytes.
%%
%% Inspired by the technique introduced in erlang/otp#10938
%% (json:escape_binary, string:length).

-define(SWAR_MASK80, 16#80808080808080).
-define(SWAR_MASK01, 16#01010101010101).

%% Detect if any byte in a 56-bit word is zero (Mycroft's trick).
%%
%% Full formula: ((V - 0x01..01) band (bnot V) band 0x80..80) =/= 0.
%%   - (V - 0x01..01) borrows into a byte's high bit when that byte
%%     underflows: true for byte 0x00, but ALSO for any byte >= 0x80,
%%     whose high bit the subtraction does not clear.
%%   - band (bnot V) keeps only lanes whose original byte was < 0x80,
%%     discarding the >= 0x80 false positives from the previous step.
%%   - band 0x80..80 isolates the per-byte high bit; non-zero => a 0x00.
%%
%% We drop the (bnot V) term. This is safe ONLY because every caller
%% gates this macro behind `W band ?SWAR_MASK80 =:= 0 andalso ...`, so
%% ?no_zero_byte runs exclusively on all-ASCII words (every byte < 0x80,
%% XORed with an ASCII constant that is also < 0x80). With no byte >= 0x80
%% the high-byte false positives (bnot V) guards against cannot occur, so
%% the reduced check is exact on these inputs.
%%
%% Dropping bnot also avoids a JIT cost: bnot has no always-small fast
%% path and would emit bignum-fallback type checks even when the result
%% fits in a small.
%%
%% Consequence: a 7-byte window containing any non-ASCII byte (>= 0x80)
%% fails the SWAR_MASK80 guard, short-circuits the andalso, and is NOT
%% taken by this fast path. Such windows fall through to the byte-by-byte
%% slow path, which handles them correctly. That is a deliberate fast-path
%% miss, not an error. The ?is_safe_ascii_swar predicate macro that wraps
%% this trick is therefore intentionally conservative: it REQUIRES all
%% 7 bytes to be ASCII (high bit clear) AND free of their delimiter(s),
%% so a window with any non-ASCII byte takes the slow path on purpose
%% even when it contains no delimiter. Per essen's review this is
%% acceptable: such windows are handled correctly, just more slowly.
-define(no_zero_byte(V),
	((V) - ?SWAR_MASK01) band ?SWAR_MASK80 =:= 0
).

%% Generalized SWAR safe-ASCII predicate: true iff every one of the 7 bytes
%% in W is ASCII (high bit clear) AND differs from each delimiter argument.
%% Reusable across Cowlib, Cowboy and Gun (they include cow_swar.hrl, which
%% owns ?SWAR_MASK80/?SWAR_MASK01/?no_zero_byte that this expands to).
%%
%% Each delimiter A is broadcast across all 7 lanes by ?SWAR_MASK01 * (A);
%% because A is a literal char constant at every call site the compiler
%% folds the multiply at COMPILE time (verified: no '*' BIF is emitted and
%% the folded 56-bit constant, e.g. 16#3A3A3A3A3A3A3A for $:, appears
%% directly in the .beam assembly). XOR zeroes any lane equal to A, and
%% ?no_zero_byte detects it. Delimiter args MUST be compile-time literals
%% (a $char or integer literal); a runtime variable would emit a real
%% runtime multiply and lose the optimization (and is illegal in a guard).
-define(is_safe_ascii_swar(W, A),
	(W) band ?SWAR_MASK80 =:= 0 andalso
	?no_zero_byte((W) bxor (?SWAR_MASK01 * (A)))
).
-define(is_safe_ascii_swar(W, A, B),
	(W) band ?SWAR_MASK80 =:= 0 andalso
	?no_zero_byte((W) bxor (?SWAR_MASK01 * (A))) andalso
	?no_zero_byte((W) bxor (?SWAR_MASK01 * (B)))
).
-define(is_safe_ascii_swar(W, A, B, C),
	(W) band ?SWAR_MASK80 =:= 0 andalso
	?no_zero_byte((W) bxor (?SWAR_MASK01 * (A))) andalso
	?no_zero_byte((W) bxor (?SWAR_MASK01 * (B))) andalso
	?no_zero_byte((W) bxor (?SWAR_MASK01 * (C)))
).

%% ASCII lowercase 7 bytes in parallel.
%%
%% For each lane, set bit 5 if the byte is in [0x41..0x5A] (A-Z),
%% leave it alone otherwise. The standard range trick: bit 7 of
%% (b + 0x3F) is set when b >= 0x41; bit 7 of (b + 0x25) is set
%% when b >= 0x5B. So uppercase lanes are exactly those with
%% bit 7 set in the first and clear in the second. Flipping bit
%% 7 of the second term (bxor 0x80..80) lets us combine the two
%% with a single band; the result has bit 7 set per uppercase
%% lane. Shifting right by 2 moves that flag into bit 5, the
%% 0x20 position; bor with the original W lowercases.
%%
%% Callers must verify `W band ?SWAR_MASK80 =:= 0` first: the
%% lane additions assume each byte is < 0x80, otherwise carries
%% propagate between lanes and the formula breaks.
-define(swar_lower(W),
	((W) bor (
		((((W) + 16#3F3F3F3F3F3F3F)
			band (((W) + 16#25252525252525) bxor ?SWAR_MASK80)
			band ?SWAR_MASK80) bsr 2)
	))
).
