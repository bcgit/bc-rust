#!/usr/bin/env bash
# Checks that ECDSA signing and the handling of its private keys (bouncycastle_ec::ecdsa), and the
# decoding and generation of ECC CDH private keys (bouncycastle_ec::eccdh), leave nothing of what
# they handled on the stack they used, over each of the seven curves, over
# dev_scripts/ecdsa_stack_harness: for each operation it paints the stack, runs the operation,
# copies the dead stack out and searches the copy for the words of every secret the operation
# handled (the private key d, and for signing the RNG's output and k, as bytes and as limbs). The
# operations are the decoding, copying, re-pairing and generation of a private key, the drawing
# of k (create_signer), the random and the deterministic one-shots and the streaming finals.
#
# Each operation is also run twice at the same addresses over different secrets (two keys, two
# draws of the RNG), and the two copies of the stack compared: but for the signature, the public
# key and the registers the call's first frames saved, they must be the same. That needs no known
# value, so it reaches the arithmetic's intermediates, which the search has no name for.
#
# Controls: nothing run must leave nothing and the same stack twice, and a copy of a private key
# left in a frame must be found by the search and by the comparison, so that a check that finds
# nothing is noticed.
#
# What a pass shows: that in a release build for the host, by the installed toolchain, the
# wipes reach as far as the operations write. The wipes are sized by measurement on x86-64
# Linux, and CI runs this on x86-64 and arm64 Linux (.github/workflows/ecdsa-stack.yml). A pass
# says nothing of another target or another compiler, and nothing of a debug build, whose frames
# are larger and are not covered. It does not look at registers, at the heap, or at what a caller
# does with a key it was returned.
#
#   ./dev_scripts/check_ecdsa_stack.sh
set -euo pipefail

cd "$(dirname "$0")/ecdsa_stack_harness"

# Built where it is then run from, whatever CARGO_TARGET_DIR or a cargo config says.
rm -rf target
cargo build --release --target-dir target
target/release/ecdsa_stack_harness
