#!/usr/bin/env bash
# Checks that the AES round-key widening (`PlaneWord::splat` in crypto/aes/src/bitslice.rs)
# compiles to no multiply, call or branch on the targets whose multiply is not fixed-latency.
# Builds dev_scripts/aes_ct_harness with the nightly toolchain and `-Zbuild-std=core` (the
# targets have no shipped `core`), emits the assembly and greps the four `splat*` bodies: the
# barriered pair must be clean, and the plain pair must show the multiply the barrier prevents,
# so that a grep that matches nothing is noticed. Targets may be given as arguments.
#
#   rustup toolchain install nightly --profile minimal --component rust-src
#   ./dev_scripts/check_aes_ct_asm.sh                 # thumbv6m-none-eabi riscv32i-unknown-none-elf
#   ./dev_scripts/check_aes_ct_asm.sh thumbv6m-none-eabi
set -euo pipefail

cd "$(dirname "$0")/aes_ct_harness"
TARGETS=${*:-"thumbv6m-none-eabi riscv32i-unknown-none-elf"}
status=0

# Prints the instruction lines of the function whose mangled symbol contains $2 in $1.
body() {
    awk -v f="$2" '$0 ~ f && /:$/ { on = 1 } on { print } on && /^\.Lfunc_end/ { exit }' "$1" |
        grep -vE '^\s*(\.|@|#|//)' | grep -vE ':\s*$' || true
}

for t in $TARGETS; do
    case "$t" in
        thumb*|arm*)
            bad='\b(mul|muls|smull|umull|mla|bl|blx|b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)|cbz|cbnz|it|ite|itt)\b|__aeabi_'
            mul='\b(mul|muls|smull|umull)\b|__aeabi_lmul|__aeabi_.*mul' ;;
        riscv*)
            bad='\b(mul|mulh|mulhu|mulhsu|call|jal|jalr|tail|b(eq|ne|lt|ge|ltu|geu|nez|eqz|lez|gez|ltz|gtz))\b|__mul'
            mul='\bmul|__mul' ;;
        avr*)
            bad='\b(mul|muls|mulsu|fmul|call|rcall|icall|br(eq|ne|cs|cc|sh|lo|mi|pl|ge|lt|hs|vs|vc|ie|id|ts|tc)|sbrc|sbrs|cpse)\b|__mul'
            mul='\bmul|__mul' ;;
        *) echo "no mnemonic table for $t"; exit 2 ;;
    esac

    rm -rf "target/$t"
    cargo +nightly rustc --quiet --release --target "$t" -Zbuild-std=core -- --emit asm
    asm=$(ls "target/$t/release/deps/"aes_ct_harness-*.s)

    for f in splat32_barrier splat64_barrier; do
        hits=$(body "$asm" "$f" | grep -cE "$bad" || true)
        n=$(body "$asm" "$f" | wc -l)
        if [ "$hits" -ne 0 ]; then
            echo "FAIL $t $f: $hits multiply/call/branch line(s) in $n instructions"
            body "$asm" "$f" | grep -E "$bad"
            status=1
        else
            echo "ok   $t $f: no multiply, call or branch in $n instructions"
        fi
    done
    control=$(for f in splat32_plain splat64_plain; do body "$asm" "$f"; done | grep -cE "$mul" || true)
    if [ "$control" -eq 0 ]; then
        echo "FAIL $t: the unbarriered bodies show no multiply, so the grep proves nothing"
        status=1
    else
        echo "ok   $t control: the unbarriered bodies show the multiply ($control line(s))"
    fi
done
exit $status
