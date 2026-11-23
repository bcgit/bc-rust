#!/usr/bin/env bash
# Checks that the RSA private-key arithmetic does nothing that depends on the key, on the host,
# under valgrind memcheck, over dev_scripts/rsa_ct_harness, which runs the arithmetic with the
# secrets left undefined: memcheck then reports any conditional jump or address computed from
# them. The checked exponentiation and the congruences are not public API (every public
# operation over them branches on their verdict, which memcheck would report), so the library
# is built here with `--cfg bouncycastle_rsa_ct_harness`, which adds a module that names them
# and changes nothing else.
#
# - context: `MontgomeryContext::for_secret_modulus` over an undefined modulus, the setup the
#   CRT makes over p and over q in every private-key operation.
# - crt: the size's `crt_exp` at RSA-2048 with p, q, dP, dQ and qInv undefined: the two
#   exponentiations, the recombination, the check of the result against e and the masked write
#   of the output, which is all of RSASP1 and RSADP below the range check of their input.
# - import: the size's `crt_congruences` at RSA-2048 with p, q, dP, dQ and qInv undefined:
#   the three congruences a private key's constructor and decoder check of its components.
#
# All three must be clean. The three controls must be reported, so that a memcheck that reports
# nothing is noticed: the variable-time `for_public_modulus` over the same undefined modulus, a
# branch on what `crt_exp` returns, which shows that the key it ran over was undefined, and a
# branch on the congruences' verdicts.
#
# Not covered: key generation and `RsaPrivateComponents::validate`, which are not constant time
# and do not claim to be; the range and parity checks a constructor makes of its components
# before the congruences, which branch on what they find; the padding schemes above the CRT
# (the EME-OAEP decode has check_oaep_ct.sh); and anything memcheck cannot see, an instruction
# whose time depends on its operands or a target other than the host.
#
#   sudo apt-get install valgrind
#   ./dev_scripts/check_rsa_ct.sh
set -euo pipefail

cd "$(dirname "$0")/rsa_ct_harness"
status=0

if ! command -v valgrind >/dev/null; then
    echo "FAIL: valgrind is not installed, so the memcheck run cannot be made"
    exit 2
fi
rm -rf target
RUSTFLAGS="--cfg bouncycastle_rsa_ct_harness" cargo build --release --bin memcheck
for mode in context crt import control-context control-crt control-import; do
    rc=0
    valgrind -q --malloc-fill=0x00 --error-exitcode=9 target/release/memcheck "$mode" >"target/memcheck-$mode.log" 2>&1 || rc=$?
    case "$mode:$rc" in
        control-context:9) echo "ok   memcheck control-context: the variable-time setup is reported" ;;
        control-crt:9)     echo "ok   memcheck control-crt: the branch on the result is reported" ;;
        control-import:9)  echo "ok   memcheck control-import: the branch on the verdicts is reported" ;;
        control-*)         echo "FAIL memcheck $mode: exit $rc, nothing was reported where something must be, so a clean run proves nothing"
                           status=1 ;;
        *:0) echo "ok   memcheck $mode: nothing depends on the key" ;;
        *)   echo "FAIL memcheck $mode: exit $rc"
             cat "target/memcheck-$mode.log"
             status=1 ;;
    esac
done
exit $status
