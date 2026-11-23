#!/usr/bin/env bash
# Checks that the EME-OAEP decoding (`decode_out` in crypto/modexp/src/rsa/eme_oaep.rs) does nothing
# that depends on the encoded message, in two ways, over dev_scripts/oaep_ct_harness, which
# includes that file by path.
#
# 1. On the host, under valgrind memcheck, with the encoded message left undefined: memcheck
#    reports any conditional jump or address computed from it. Both paths (a message of any
#    length, and of an exact length) must be clean, and the control, a variable-time search for
#    the separator, must be reported, so that a memcheck that reports nothing is noticed.
# 2. On the targets whose multiply is not fixed-latency, in the assembly: the decode must hold
#    no multiply or divide, and no call but the buffer clear, the two MGF calls and the panics
#    of its length checks. The two MGF calls must be found, so that a grep that matches nothing
#    is noticed. The decode's loops branch on lengths, so branches are not grepped for; the
#    memcheck run is what covers them.
#
#   sudo apt-get install valgrind
#   rustup toolchain install nightly --profile minimal --component rust-src
#   ./dev_scripts/check_oaep_ct.sh                    # thumbv6m-none-eabi riscv32i-unknown-none-elf
#   ./dev_scripts/check_oaep_ct.sh thumbv6m-none-eabi
set -euo pipefail

cd "$(dirname "$0")/oaep_ct_harness"
TARGETS=${*:-"thumbv6m-none-eabi riscv32i-unknown-none-elf"}
status=0

if ! command -v valgrind >/dev/null; then
    echo "FAIL: valgrind is not installed, so the memcheck run cannot be made"
    exit 2
fi
rm -rf target
cargo build --release --bin memcheck
for mode in any exact control; do
    rc=0
    valgrind -q --error-exitcode=9 target/release/memcheck "$mode" >"target/memcheck-$mode.log" 2>&1 || rc=$?
    case "$mode:$rc" in
        control:9) echo "ok   memcheck control: the variable-time search is reported" ;;
        control:*) echo "FAIL memcheck control: exit $rc, the variable-time search was not reported, so a clean run proves nothing"
                   status=1 ;;
        *:0) echo "ok   memcheck $mode: nothing depends on the encoded message" ;;
        *)   echo "FAIL memcheck $mode: exit $rc"
             cat "target/memcheck-$mode.log"
             status=1 ;;
    esac
done

# Prints the instruction lines of the function whose mangled symbol contains $2 in $1.
body() {
    awk -v f="$2" '$0 ~ f && /:$/ { on = 1 } on { print } on && /^\.Lfunc_end/ { exit }' "$1" |
        grep -vE '^\s*(\.|@|#|//)' | grep -vE ':\s*$' || true
}

for t in $TARGETS; do
    case "$t" in
        thumb*|arm*)
            arith='\b(mul|muls|smull|umull|mla|sdiv|udiv)\b|__aeabi_(l?mul|u?l?divmod|u?idiv)|__(u?div|u?mod|mul)'
            call='\b(bl|blx)\b' ;;
        riscv*)
            arith='\b(mul|mulh|mulhu|mulhsu|div|divu|rem|remu)\b|__(u?div|u?mod|mul)'
            call='\b(call|jalr|tail)\b' ;;
        *) echo "no mnemonic table for $t"; exit 2 ;;
    esac

    # `--emit asm` writes beside the intermediate artifacts, which newer cargo keeps in a build
    # directory separate from the target directory; pinning both to `target` keeps the file
    # findable on every cargo.
    cargo +nightly rustc --release --lib --target "$t" -Zbuild-std=core \
        --config 'build.build-dir="target"' -- --emit asm
    asm=$(find target -name 'oaep_ct_harness-*.s' -path "*$t*" | head -n 1)
    if [ -z "$asm" ]; then
        echo "FAIL $t: no oaep_ct_harness-*.s under $(pwd)/target"
        exit 2
    fi

    n=$(body "$asm" decode_out | wc -l)
    mgf=$(body "$asm" decode_out | grep -E "$call" | grep -c 'mgf1_xor' || true)
    hits=$(body "$asm" decode_out | grep -cE "$arith" || true)
    other=$(body "$asm" decode_out | grep -E "$call" | grep -vE 'mgf1_xor|memset|memclr|panic' || true)
    if [ "$n" -eq 0 ]; then
        echo "FAIL $t decode_out: not found in the assembly (renamed or inlined?), nothing was checked"
        status=1
    elif [ "$mgf" -ne 2 ]; then
        echo "FAIL $t decode_out: $mgf MGF call(s) found where two are made, so the grep proves nothing"
        status=1
    elif [ "$hits" -ne 0 ] || [ -n "$other" ]; then
        echo "FAIL $t decode_out: a multiply, divide or unexpected call in $n instructions"
        body "$asm" decode_out | grep -E "$arith" || true
        echo "$other"
        status=1
    else
        echo "ok   $t decode_out: no multiply, divide or unexpected call in $n instructions"
    fi
done
exit $status
