#!/usr/bin/env bash
# Checks that HMAC (over SHA-256, SHA-512, SHA3-256, SM3 and RIPEMD-160), HKDF (over SHA-256,
# SHA-512 and SHA3-256), BLAKE3 in its three modes and AES-GCM-SIV leave nothing of what they
# handled on the stack they used, over dev_scripts/symmetric_stack_harness: for each operation it
# paints the stack, runs the operation, copies the dead stack out and searches the copy for the
# words of every secret the operation handled (the key and the message; HMAC's padded key
# blocks, its two pad states and the inner hash's states; HKDF's IKM, PRK, PRK-keyed pads, each
# T(i) and the OKM; BLAKE3's chaining values and derived key; GCM-SIV's per-nonce keys, POLYVAL
# accumulators and key stream). The operations are HMAC's key construction, one-shots and
# streaming workers with their in-place finals; HKDF's extract, expand, the two together and its
# KDF derivation; BLAKE3's hash, XOF, streaming in 64-byte steps and in one, squeezer and its
# suspend and resume, keyed hash and derive_key, over one chunk and over several; and GCM-SIV's
# encryption and decryption in place, a decryption that fails its tag included. Reported, and not
# failing the check: an HMAC worker finished by value, PBKDF2, and an AES key's construction.
#
# Each operation is also run twice at the same addresses over different secrets, and the two
# copies of the stack compared: but for what it hands out and the registers the call's first
# frames saved, they must be the same. That needs no known value, so it reaches the
# intermediates the search has no name for.
#
# Controls: nothing run must leave nothing and the same stack twice, a copy of a key left in a
# frame must be found by the search and by the comparison, and a u32 left over an address or a
# byte left zero-extended by the comparison, so that a check that finds nothing is noticed.
#
# What a pass shows: that in a release build for the host, by the installed toolchain, the wipes
# reach as far as the operations write. The wipes are sized by measurement on x86-64 Linux, and
# a wipe's own frame never clears the registers it saves or the padding above its array, which
# differ by target, so CI runs this on x86-64 and arm64 Linux
# (.github/workflows/symmetric-stack.yml). A pass says
# nothing of another target or another compiler, and nothing of a debug build, whose frames are
# larger and are not covered. It does not look at registers, at the heap, or at what a caller
# does with a key it was returned.
#
#   ./dev_scripts/check_symmetric_stack.sh
set -euo pipefail

cd "$(dirname "$0")/symmetric_stack_harness"

# Built where it is then run from, whatever CARGO_TARGET_DIR or a cargo config says.
rm -rf target
cargo build --release --target-dir target
target/release/symmetric_stack_harness
