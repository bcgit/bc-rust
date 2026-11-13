#!/usr/bin/env bash
# Builds the `bc-rust` CLI and runs it through AES-CCM, AES-CFB128 and AES-CFB8 examples.
#
# Each example is checked, not just shown: CCM against SP 800-38C Appendix C Examples 1 and 2
# (nonce supplied, so the output is a known answer) and the round trips, AAD binding and tamper
# detection the subcommand help promises; CFB128 and CFB8 against SP 800-38A Appendix F.3 with
# the IV supplied through `--iv`, and with the default generated IV for round trip, output
# length, pipeline composition and the tamper-propagation behaviour each mode's help describes.
#
# Usage: ./dev_scripts/cli_ccm_cfb_examples.sh [--release]
# Exit status is non-zero if any check fails. Needs `xxd` and `cmp`.

set -u
cd "$(dirname "$0")/.."

PROFILE=debug
CARGO_FLAGS=()
if [ "${1:-}" = "--release" ]; then
    PROFILE=release
    CARGO_FLAGS=(--release)
fi

export PATH="$HOME/.cargo/bin:$PATH"
echo "## building bc-rust ($PROFILE)"
cargo build -p cli "${CARGO_FLAGS[@]}" || exit 1
BC="./target/$PROFILE/bc-rust"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
check() { # check <description> <command...>; passes if the command exits 0
    local desc=$1; shift
    if "$@"; then pass "$desc"; else fail "$desc"; fi
}
hex() { xxd -p | tr -d '\n'; }
unhex() { xxd -r -p; }

# A throwaway key for the round-trip examples. Never put a real key on a command line; the
# commands take `--key-file` for that, and the CFB examples below use it.
KEY=000102030405060708090a0b0c0d0e0f
KEY_FILE="$WORK/key.bin"
echo -n "$KEY" | unhex > "$KEY_FILE"

###############################################################################################
echo
echo "## AES-128-CCM: known answers from SP 800-38C Appendix C"
echo "#  (nonce is supplied, not generated, so the output is reproducible)"

# C.1 Example 1: Klen = 128, Tlen = 32, Nlen = 56, Alen = 64, Plen = 32.
K1=404142434445464748494a4b4c4d4e4f
N1=10111213141516
A1=0001020304050607
P1=20212223
C1=7162015b4dac255d     # ciphertext || 4-byte tag
out=$(echo -n "$P1" | unhex | $BC aes128-ccm -d encrypt --key $K1 --nonce $N1 --aad $A1 --tag-len 4 -x)
check "Example 1 encrypt: $out" [ "$out" = "$C1" ]
out=$(echo -n "$C1" | unhex | $BC aes128-ccm -d decrypt --key $K1 --nonce $N1 --aad $A1 --tag-len 4 -x)
check "Example 1 decrypt: $out" [ "$out" = "$P1" ]

# C.2 Example 2: Klen = 128, Tlen = 48, Nlen = 64, Alen = 128, Plen = 128.
N2=1011121314151617
A2=000102030405060708090a0b0c0d0e0f
P2=202122232425262728292a2b2c2d2e2f
C2=d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd     # ciphertext || 6-byte tag
out=$(echo -n "$P2" | unhex | $BC aes128-ccm -d encrypt --key $K1 --nonce $N2 --aad $A2 --tag-len 6 -x)
check "Example 2 encrypt: $out" [ "$out" = "$C2" ]
out=$(echo -n "$C2" | unhex | $BC aes128-ccm -d decrypt --key $K1 --nonce $N2 --aad $A2 --tag-len 6 -x)
check "Example 2 decrypt: $out" [ "$out" = "$P2" ]

echo
echo "## AES-128-CCM: round trip, AAD binding, tamper detection (12-byte nonce, 16-byte tag)"
NONCE=000000000000000000000001     # a message counter; MUST be unique per key
MSG="$WORK/msg.txt"
printf 'The quick brown fox jumps over the lazy dog. %s\n' "$(date -u +%FT%TZ)" > "$MSG"
AAD_FILE="$WORK/aad.bin"
printf 'header: v1, msg 1' > "$AAD_FILE"

$BC aes128-ccm -d encrypt -k "$KEY_FILE" --nonce $NONCE --aad-file "$AAD_FILE" < "$MSG" > "$WORK/msg.ccm"
check "ciphertext is input + 16 tag bytes ($(stat -c %s "$WORK/msg.ccm") = $(stat -c %s "$MSG") + 16)" \
    [ "$(stat -c %s "$WORK/msg.ccm")" -eq $(( $(stat -c %s "$MSG") + 16 )) ]

$BC aes128-ccm -d decrypt -k "$KEY_FILE" --nonce $NONCE --aad-file "$AAD_FILE" < "$WORK/msg.ccm" > "$WORK/msg.out"
check "decrypt round-trips" cmp -s "$MSG" "$WORK/msg.out"

# AAD is authenticated: a different AAD must fail, and must write nothing.
if $BC aes128-ccm -d decrypt -k "$KEY_FILE" --nonce $NONCE --aad 00 < "$WORK/msg.ccm" > "$WORK/bad.out" 2>/dev/null; then
    fail "decrypt with the wrong AAD was accepted"
else
    check "decrypt with the wrong AAD fails and writes no plaintext" [ ! -s "$WORK/bad.out" ]
fi

# Tamper: flip one bit of the first ciphertext byte.
python3 -c "
import sys; d = bytearray(open(sys.argv[1], 'rb').read()); d[0] ^= 1; open(sys.argv[2], 'wb').write(d)
" "$WORK/msg.ccm" "$WORK/msg.tampered"
if $BC aes128-ccm -d decrypt -k "$KEY_FILE" --nonce $NONCE --aad-file "$AAD_FILE" < "$WORK/msg.tampered" > "$WORK/bad.out" 2>/dev/null; then
    fail "tampered ciphertext was accepted"
else
    check "tampered ciphertext fails and writes no plaintext" [ ! -s "$WORK/bad.out" ]
fi

# Shorter tag, 7-byte nonce (the largest payload limit), encrypt | decrypt in one pipeline.
out=$($BC aes128-ccm -d encrypt -k "$KEY_FILE" --nonce 01020304050607 --tag-len 8 < "$MSG" \
    | $BC aes128-ccm -d decrypt -k "$KEY_FILE" --nonce 01020304050607 --tag-len 8)
check "7-byte nonce, 8-byte tag, encrypt | decrypt pipeline round-trips" [ "$out" = "$(cat "$MSG")" ]

###############################################################################################
# SP 800-38A Appendix F.3, AES-128: the same key and IV for both modes; CFB8 uses the first 18
# plaintext bytes (F.3.7, 18 segments), CFB128 all 64 (F.3.13, 4 segments).
K38A=2b7e151628aed2a6abf7158809cf4f3c
IV38A=000102030405060708090a0b0c0d0e0f
P38A=6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
C_CFB=3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6
P_CFB8=${P38A:0:36}
C_CFB8=3b79424c9c0dd436bace9e0ed4586a4f32b9

for MODE in cfb cfb8; do
    CMD="aes128-$MODE"
    if [ "$MODE" = cfb ]; then P=$P38A; C=$C_CFB; SEC="F.3.13 / F.3.14"; else P=$P_CFB8; C=$C_CFB8; SEC="F.3.7 / F.3.8"; fi

    echo
    echo "## AES-128-${MODE^^}: known answers from SP 800-38A Appendix $SEC, IV supplied with --iv"
    echo "#  (with --iv, encrypt writes only ciphertext and decrypt reads only ciphertext)"
    out=$(echo -n "$P" | unhex | $BC $CMD -d encrypt --key $K38A --iv $IV38A -x)
    check "encrypt: $out" [ "$out" = "$C" ]
    out=$(echo -n "$C" | unhex | $BC $CMD -d decrypt --key $K38A --iv $IV38A -x)
    check "decrypt: $out" [ "$out" = "$P" ]

    # The same IV from a file of raw bytes, and --iv on both ends of a pipeline.
    echo -n "$IV38A" | unhex > "$WORK/iv.bin"
    out=$(echo -n "$P" | unhex | $BC $CMD -d encrypt --key $K38A --iv-file "$WORK/iv.bin" -x)
    check "encrypt with --iv-file gives the same answer" [ "$out" = "$C" ]
    out=$($BC $CMD -d encrypt -k "$KEY_FILE" --iv $IV38A < "$MSG" | $BC $CMD -d decrypt -k "$KEY_FILE" --iv $IV38A)
    check "encrypt --iv | decrypt --iv round-trips, ciphertext only in the pipe" [ "$out" = "$(cat "$MSG")" ]
    check "ciphertext with --iv is exactly the input length" \
        [ "$($BC $CMD -d encrypt -k "$KEY_FILE" --iv $IV38A < "$MSG" | wc -c)" -eq "$(stat -c %s "$MSG")" ]

    # A wrong-length IV is refused before anything is read.
    if echo -n 00 | $BC $CMD -d encrypt --key $K38A --iv 0001 > /dev/null 2>&1; then
        fail "a 2-byte IV was accepted"
    else
        pass "a 2-byte IV is refused"
    fi

    echo
    echo "## AES-128-${MODE^^}: default, IV generated and prepended (first 16 bytes of output)"

    $BC $CMD -d encrypt -k "$KEY_FILE" < "$MSG" > "$WORK/msg.$MODE"
    check "ciphertext is 16-byte IV + input ($(stat -c %s "$WORK/msg.$MODE") = 16 + $(stat -c %s "$MSG"))" \
        [ "$(stat -c %s "$WORK/msg.$MODE")" -eq $(( 16 + $(stat -c %s "$MSG") )) ]

    $BC $CMD -d decrypt -k "$KEY_FILE" < "$WORK/msg.$MODE" > "$WORK/msg.out"
    check "decrypt round-trips" cmp -s "$MSG" "$WORK/msg.out"

    # Two encryptions of the same message differ: the IV is fresh each time.
    $BC $CMD -d encrypt -k "$KEY_FILE" < "$MSG" > "$WORK/msg2.$MODE"
    check "a second encryption has a different IV and ciphertext" [ "$(hex < "$WORK/msg.$MODE")" != "$(hex < "$WORK/msg2.$MODE")" ]

    # Pipeline: encrypt | decrypt with no file in between, any length (here 1 byte and 100 KiB).
    out=$(printf 'x' | $BC $CMD -d encrypt -k "$KEY_FILE" | $BC $CMD -d decrypt -k "$KEY_FILE")
    check "1-byte message through an encrypt | decrypt pipeline" [ "$out" = "x" ]
    head -c 102400 /dev/urandom > "$WORK/big.bin"
    $BC $CMD -d encrypt -k "$KEY_FILE" < "$WORK/big.bin" | $BC $CMD -d decrypt -k "$KEY_FILE" > "$WORK/big.out"
    check "100 KiB through an encrypt | decrypt pipeline" cmp -s "$WORK/big.bin" "$WORK/big.out"

    # No integrity: a flipped ciphertext bit decrypts "successfully" to corrupted plaintext.
    # CFB128: the same bit of the same block flips and the NEXT block is garbled, then it resyncs.
    # CFB8: the same bit of the same byte flips and the next 16 bytes are garbled, then it resyncs.
    # Flip bit 0 of plaintext byte 20 (ciphertext byte 16 + 20).
    python3 -c "
import sys; d = bytearray(open(sys.argv[1], 'rb').read()); d[16 + 20] ^= 1; open(sys.argv[2], 'wb').write(d)
" "$WORK/msg.$MODE" "$WORK/msg.$MODE.tampered"
    $BC $CMD -d decrypt -k "$KEY_FILE" < "$WORK/msg.$MODE.tampered" > "$WORK/tampered.out"
    check "tampering is NOT detected (exit 0, output produced)" [ -s "$WORK/tampered.out" ]
    if [ "$MODE" = cfb ]; then garble_from=32; garble_to=48; else garble_from=21; garble_to=37; fi
    python3 - "$MSG" "$WORK/tampered.out" $garble_from $garble_to <<'EOF'
import sys
a = open(sys.argv[1], 'rb').read(); b = open(sys.argv[2], 'rb').read()
lo, hi = int(sys.argv[3]), int(sys.argv[4])
diff = [i for i in range(len(a)) if a[i] != b[i]]
assert len(a) == len(b), "length changed"
assert diff[0] == 20 and a[20] ^ b[20] == 1, f"byte 20 should differ by exactly bit 0, got {diff[:3]}"
assert all(lo <= i < hi for i in diff[1:]), f"corruption outside [{lo},{hi}): {diff}"
assert all(a[i] == b[i] for i in range(hi, len(a))), "did not resynchronise"
print(f"  ok    flipped bit lands on plaintext byte 20, bytes {lo}..{hi-1} garbled, then resynchronised")
EOF
    [ $? -eq 0 ] || fail "tamper propagation did not match the mode's description"
done

###############################################################################################
echo
if [ $FAILURES -eq 0 ]; then
    echo "all checks passed"
else
    echo "$FAILURES check(s) FAILED"
    exit 1
fi
