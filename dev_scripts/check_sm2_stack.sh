#!/usr/bin/env bash
# Checks that SM2 public key encryption and decryption (bouncycastle_ec::sm2::encryption) and
# the handling of their private key leave nothing of what they handled on the stack they used,
# over dev_scripts/sm2_stack_harness: for each operation it paints the stack, runs the
# operation, copies the dead stack out and searches the copy for the words of every secret the
# operation handled (the private key, the RNG's output and k, as bytes and as limbs; the shared
# point's coordinates, as bytes, as limbs and as SM3 reads them; the first hash values of the
# key stream; the message; and the hash a refused decryption computed). The operations are the
# loading, encoding, copying and generation of a private key and the derivation of its public
# key; encryption and decryption where the message lies and into a buffer in both orders;
# encryption that draws k twice; and decryption refused for a changed C3, a changed C2, an
# all-zero key stream and a C1 that is not a point.
#
# Each operation is also run twice at the same addresses over different secrets (two draws of
# the RNG, two private keys), and the two copies of the stack compared: but for the ciphertext
# and for the registers the call's first frames saved, they must be the same. That needs no
# known value, so it reaches the arithmetic's intermediates, which the search has no name for.
#
# Controls: nothing run must leave nothing and the same stack twice, and a copy of a private key
# left in a frame must be found by the search and by the comparison, so that a check that finds
# nothing is noticed.
#
# What a pass shows: that in a release build for the host, by the installed toolchain, the
# wipes reach as far as the operations write. The wipes are sized by measurement on x86-64
# Linux, with room over what was measured in review on arm64 Linux, and CI runs this on both
# (.github/workflows/sm2-stack.yml). A pass says nothing of another target or another compiler,
# and nothing of a debug build, whose frames are larger and are not covered. It does not look at
# registers, at the heap, or at what a caller does with a key it was returned.
#
#   ./dev_scripts/check_sm2_stack.sh
set -euo pipefail

cd "$(dirname "$0")/sm2_stack_harness"

# Built where it is then run from, whatever CARGO_TARGET_DIR or a cargo config says.
rm -rf target
cargo build --release --target-dir target
target/release/sm2_stack_harness
