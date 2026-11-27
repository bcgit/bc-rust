#!/usr/bin/env bash
# Checks that ECDSA signing and the handling of its private keys (bouncycastle_ec::ecdsa), ECC
# CDH's private keys and agreement (bouncycastle_ec::eccdh), DHKEM over the NIST curves and
# X448 with its labeled HKDF steps (bouncycastle_ec::dhkem), and Ed25519, Ed448, X25519 and X448
# (bouncycastle_ec::ed) leave nothing of what they handled on the stack they used, the first two
# over each of the seven curves, over dev_scripts/ecdsa_stack_harness: for each operation it
# paints the stack, runs the operation, copies the dead stack out and searches
# the copy for the words of every secret the operation handled (the private keys, the RNG's
# output, k, the Diffie-Hellman products, the DHKEM's PRK and shared secret and what a KDF
# derived, as bytes and as limbs). The operations are the decoding, encoding, copying,
# re-pairing and generation of a private key and the derivation of its public key, the drawing
# of k (create_signer), the random and the deterministic one-shots and the streaming finals, the
# agreement, and the DHKEM's private-key decoding, DeriveKeyPair, Encap, Decap, AuthEncap and
# AuthDecap. EdDSA's keys are generated, decoded, copied and encoded, their public keys read, and
# each signs through the one-shots and the pre-hash variant's streaming final, searched for the
# private key, its digest, s, prefix, the digest of the nonce and r; X25519's and X448's keys go
# through the same and agree, searched for the key as given and clamped and for K. DHKEM over
# X25519, and the comparison of two runs of X25519's scalar multiplications, are run and
# reported, and do not fail the check: its scalar multiplication leaves part of its field
# inversion, by decision.
#
# Each operation is also run twice at the same addresses over different secrets (two keys, two
# draws of the RNG), and the two copies of the stack compared: but for the signature, the public
# key and the ciphertext, they must be the same, to the byte below the call. That needs no known
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
# does with a key it was returned, and what the caller's own registers held, callee- and
# caller-saved, which a library frame may save, is out of its scope: the harness zeroes them
# before each operation.
#
#   ./dev_scripts/check_ecdsa_stack.sh
set -euo pipefail

cd "$(dirname "$0")/ecdsa_stack_harness"

# Built where it is then run from, whatever CARGO_TARGET_DIR or a cargo config says.
rm -rf target
cargo build --release --target-dir target
target/release/ecdsa_stack_harness
