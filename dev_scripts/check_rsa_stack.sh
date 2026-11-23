#!/usr/bin/env bash
# Checks that the private-key operations of bouncycastle-rsa leave nothing of the key on the
# stack they used, over dev_scripts/rsa_stack_harness: for each operation it paints the stack,
# runs the operation, copies the dead stack out and searches the copy for the words of every
# secret the operation handled (the key's components as limbs and as encoded bytes, the
# Montgomery constants of p and q, the CRT's intermediates, and what a decryption recovers and
# derives). The operations are key generation, the construction, decoding, encoding and cloning
# of a private key, signing (PKCS#1 v1.5 and PSS; one-shot, streaming and from a hash), RSASVE
# decapsulation raw and through HKDF, RSAES-OAEP decapsulation and recovery, RSASVE
# encapsulation through HKDF, `keygen::is_probable_prime`, and the validation of a key pair.
#
# Two controls: nothing run must leave nothing, and a copy of p left in a frame must be found,
# so that a search that finds nothing is noticed.
#
# What a pass shows: that in a release build for the host, x86-64, by the installed toolchain,
# the wipes reach as far as the operations write. The wipes are sized by measurement, so a pass
# says nothing of another target or another compiler, and nothing of a debug build, whose frames
# are larger and are not covered. It does not look at registers, at the heap, or at what a
# caller does with a key it was returned.
#
#   ./dev_scripts/check_rsa_stack.sh                  # RSA-2048
#   ./dev_scripts/check_rsa_stack.sh 2048 3072 4096 8192
set -euo pipefail

cd "$(dirname "$0")/rsa_stack_harness"
SIZES=${*:-"2048"}
status=0

rm -rf target
cargo build --release
for size in $SIZES; do
    echo "RSA-$size"
    target/release/rsa_stack_harness "$size" || status=1
done
exit $status
