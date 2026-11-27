#!/usr/bin/env bash
# Checks that SM2 public key encryption and decryption (bouncycastle_ec::sm2::encryption), SM2
# signing (bouncycastle_ec::sm2::sm2), and the handling of their private keys leave nothing of what
# they handled on the stack they used, over dev_scripts/sm2_stack_harness: for each operation it
# paints the stack, runs the operation, copies the dead stack out and searches the copy for the
# words of every secret the operation handled (the private key, the RNG's output and k, as bytes and
# as limbs; the shared point's coordinates, as bytes, as limbs and as SM3 reads them; the first hash
# values of the key stream; the message; and the hash a refused decryption computed). The operations
# are the loading, encoding, copying and generation of a private key and the derivation of its
# public key; encryption and decryption where the message lies and into a buffer in both orders;
# encryption that draws k twice; decryption refused for a changed C3, a changed C2, an all-zero key
# stream and a C1 that is not a point; the loading, encoding, copying and generation of a signing
# key and its public key; and the drawing of k (create_signer), the one-shot signing (sign_out,
# sign) and the streaming final, where the signing key's dA, (1 + dA)^-1, the RNG's output and k are
# searched for.
#
# Each operation is also run twice at the same addresses over different secrets (two draws of
# the RNG, two private keys), and the two copies of the stack compared: but for the ciphertext,
# they must be the same, to the byte below the call. That needs no known value, so it reaches
# the arithmetic's intermediates, which the search has no name for.
#
# Controls: nothing run must leave nothing and the same stack twice, and a copy of a private key
# left in a frame must be found by the search and by the comparison, so that a check that finds
# nothing is noticed.
#
# What a pass shows: that in a release build for the host, by the installed toolchain, the
# wipes reach as far as the operations write. The wipes are sized by measurement on x86-64
# Linux (the encryption, key and signing wipes also with room over arm64 Linux), and CI runs
# this on both (.github/workflows/sm2-stack.yml). A pass says nothing of another target or
# another compiler, and nothing of a debug build, whose frames are larger and are not covered.
# It does not look at registers, at the heap, or at what a caller does with a key it was
# returned, and what the caller's own registers held, callee- and caller-saved, which a library
# frame may save, is out of its scope: the harness zeroes them before each operation.
#
#   ./dev_scripts/check_sm2_stack.sh
set -euo pipefail

cd "$(dirname "$0")/sm2_stack_harness"

# Built where it is then run from, whatever CARGO_TARGET_DIR or a cargo config says.
rm -rf target
cargo build --release --target-dir target
target/release/sm2_stack_harness
