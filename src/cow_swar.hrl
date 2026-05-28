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
%% This simplified variant omits the standard `band (bnot V)` term.
%% The full formula is `((V - 0x01..01) band (bnot V) band 0x80..80)`.
%% The `bnot V` term filters out false positives when bytes have the
%% high bit set; we drop it because every caller verifies
%% `W band ?SWAR_MASK80 =:= 0` (via andalso short-circuit) before
%% invoking ?no_zero_byte, which guarantees all bytes are < 128 so
%% XOR results stay 7-bit.
%%
%% `bnot` is also avoided because the JIT lacks an always-small fast
%% path for it and would emit bignum fallback calls even when the
%% result fits in a small.
%%
%% Borrow propagation between bytes may cause rare false positives
%% (a non-zero byte adjacent to a zero byte being flagged as zero),
%% but these are harmless: callers fall through to a correct
%% byte-by-byte path on a false positive.
-define(no_zero_byte(V),
	((V) - ?SWAR_MASK01) band ?SWAR_MASK80 =:= 0
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
