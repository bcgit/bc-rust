#!/usr/bin/env bash
# The tdes-* subcommands' data limit, end to end through the binary. SP 800-67 Rev 2 Sec 3.4
# allows one key bundle 2^20 64-bit blocks (8 MiB) of protection; `encrypt` refuses input past
# that with the usual `Error:` line, before any byte past the bound is processed. CBC's PKCS7
# padding adds up to a block, so its bound is one byte lower; CFB64 takes exactly 8 MiB. The
# bound counts the blocks TDEA processes, so CFB8 (one block per byte) stops at 1 MiB and TKW
# (six calls per 4-byte semiblock) at 699,048 bytes. CTR never reaches it: its 6-byte nonce
# leaves a 16-bit counter, so the library's own keystream limit (2^16 blocks, 512 KiB) binds
# first, as `DataLimitExceeded`. Decryption is not limited. This lives here rather than in
# `tdes_cli_tests.rs` because 8 MiB through a debug build of the bit-sliced engine takes a minute
# or two per run.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KEY=0123456789abcdef23456789abcdef01456789abcdef0123
LIMIT=$((1 << 23))

# `zeros N` writes N zero bytes.
zeros() { head -c "$1" /dev/zero; }

test_cbc_refuses_a_padded_message_past_the_limit() {
    expect_fail "8 MiB pads to 2^20 + 1 blocks" \
        "$BC_RUST" tdes-cbc -d encrypt --key "$KEY" < <(zeros "$LIMIT")
    assert_stderr_has "Error: TDEA: one key bundle may protect at most 2^20 blocks"
}

test_cbc_takes_a_message_that_pads_to_the_limit() {
    expect_ok "8 MiB less one byte pads to exactly 2^20 blocks" \
        "$BC_RUST" tdes-cbc -d encrypt --key "$KEY" < <(zeros $((LIMIT - 1))) >/dev/null
}

test_cfb_refuses_one_byte_past_the_limit() {
    expect_fail "tdes-cfb: 2^20 blocks plus a byte" \
        "$BC_RUST" tdes-cfb -d encrypt --key "$KEY" < <(zeros $((LIMIT + 1)))
    assert_stderr_has "Error: TDEA: one key bundle may protect at most 2^20 blocks"
}

test_cfb8_counts_a_block_per_byte() {
    expect_ok "tdes-cfb8: 2^20 bytes is 2^20 blocks" \
        "$BC_RUST" tdes-cfb8 -d encrypt --key "$KEY" < <(zeros $((1 << 20))) >/dev/null
    expect_fail "tdes-cfb8: 2^20 bytes plus one" \
        "$BC_RUST" tdes-cfb8 -d encrypt --key "$KEY" < <(zeros $(((1 << 20) + 1)))
    assert_stderr_has "Error: TDEA: one key bundle may protect at most 2^20 blocks"
}

test_tkw_counts_six_blocks_per_semiblock() {
    local bound=$(((1 << 20) / 6 * 4))
    expect_ok "tdes-tkw: $bound bytes is 2^20 blocks" \
        "$BC_RUST" tdes-tkw -d encrypt --key "$KEY" < <(zeros "$bound") >/dev/null
    expect_fail "tdes-tkw: one semiblock more" \
        "$BC_RUST" tdes-tkw -d encrypt --key "$KEY" < <(zeros $((bound + 4)))
    assert_stderr_has "Error: TDEA: one key bundle may protect at most 2^20 blocks"
}

test_ctr_runs_out_of_counter_first() {
    expect_fail "tdes-ctr: 2^16 blocks plus a byte exhausts the 16-bit counter" \
        "$BC_RUST" tdes-ctr -d encrypt --key "$KEY" < <(zeros $(((1 << 19) + 1)))
    assert_stderr_has "DataLimitExceeded"
}

test_decrypt_is_not_limited() {
    # 2^20 + 1 blocks of ciphertext decrypt (ECB, no padding), since the limit is on protecting.
    expect_ok "tdes-ecb decrypt past the limit" \
        "$BC_RUST" tdes-ecb -d decrypt --key "$KEY" < <(zeros $((LIMIT + 8))) >/dev/null
}

run_all
