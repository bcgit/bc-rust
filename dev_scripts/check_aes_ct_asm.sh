#!/usr/bin/env bash
# Checks that the AES round-key widening (`PlaneWord::splat` in crypto/aes/src/bitslice.rs) and
# the TDES round function (`spread` in crypto/tdes/src/des.rs) compile to no multiply, call or
# branch on the targets whose multiply is not fixed-latency.
# Builds dev_scripts/aes_ct_harness with the nightly toolchain and `-Zbuild-std=core` (the
# targets have no shipped `core`), emits the assembly and greps the checked bodies: the barriered
# `splat` pair and the TDES round function must be clean, every checked body must be found (an
# empty body would pass vacuously), and the unbarriered controls must show the multiply the
# barrier prevents, so that a grep that matches nothing is noticed -- each control on its own
# where the target has a multiplier (thumbv6m), pooled where it has none (rv32i lowers a small
# constant multiply to shifts, and only the 64-bit one calls `__muldi3`). Targets may be given as
# arguments.
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

    rm -rf target
    # `--emit asm` writes beside the intermediate artifacts, which newer cargo keeps in a build
    # directory separate from the target directory; pinning both to `target` keeps the file
    # findable on every cargo, and `find` does not depend on the exact layout within it.
    cargo +nightly rustc --release --target "$t" -Zbuild-std=core \
        --config 'build.build-dir="target"' -- --emit asm
    asm=$(find target -name 'aes_ct_harness-*.s' -path "*$t*" | head -n 1)
    if [ -z "$asm" ]; then
        echo "FAIL $t: no aes_ct_harness-*.s under $(pwd)/target"
        find target -name '*.s' | head
        exit 2
    fi

    # splat is straight-line code, so any call or branch in it is a fault; the TDES round function
    # has a loop counter and a buffer clear, which are not secret-dependent, so for it only a
    # multiply counts.
    for spec in splat32_barrier:all splat64_barrier:all tdes_rounds:mul; do
        f=${spec%%:*}; kind=${spec##*:}
        if [ "$kind" = all ]; then pat=$bad; what="multiply, call or branch"; else pat=$mul; what="multiply"; fi
        hits=$(body "$asm" "$f" | grep -cE "$pat" || true)
        n=$(body "$asm" "$f" | wc -l)
        if [ "$n" -eq 0 ]; then
            echo "FAIL $t $f: not found in the assembly (renamed or inlined?), nothing was checked"
            status=1
        elif [ "$hits" -ne 0 ]; then
            echo "FAIL $t $f: $hits $what line(s) in $n instructions"
            body "$asm" "$f" | grep -E "$pat"
            status=1
        else
            echo "ok   $t $f: no $what in $n instructions"
        fi
    done
    # The controls: the same code with the barrier off must show a multiply, or the grep proves
    # nothing. Each control on its own where the target has a multiplier; pooled where it has none.
    control=0
    for f in splat32_plain splat64_plain spread_plain; do
        n=$(body "$asm" "$f" | wc -l)
        hits=$(body "$asm" "$f" | grep -cE "$mul" || true)
        if [ "$n" -eq 0 ]; then
            echo "FAIL $t $f: control not found in the assembly"
            status=1
        fi
        case "$t" in
            thumb*|arm*)
                if [ "$hits" -eq 0 ]; then
                    echo "FAIL $t $f: the unbarriered body shows no multiply, so the grep proves nothing"
                    status=1
                else
                    echo "ok   $t $f: control shows the multiply ($hits line(s))"
                fi ;;
        esac
        control=$((control + hits))
    done
    if [ "$control" -eq 0 ]; then
        echo "FAIL $t: no unbarriered body shows a multiply, so the grep proves nothing"
        status=1
    else
        echo "ok   $t control: the unbarriered bodies show the multiply ($control line(s))"
    fi
done
exit $status
