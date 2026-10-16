# Shared helpers for the bc-rust CLI shell tests. Sourced by each test_*.sh; not run directly.
#
# A test file defines functions named test_* and ends with `run_all`. Each test runs in its own
# subshell under `set -e`, so any failing command or assertion fails that test and no other, and
# every input it needs comes from the binary itself: keys and data from `bc-rust rng`, hex from
# `bc-rust hex-encode` / `hex-decode`.
#
# Scratch files live under /tmp/bc-rust-cli-tests/<test file>.<random>/, one subdirectory per
# test, which $TMP points at while the test runs. The whole directory is removed when every test
# in the file passed, and left in place -- with its path printed -- when any failed, so the files
# a failing test was working on can be inspected.
#
# The binary is target/debug/bc-rust, relative to the repository root; set BC_RUST to override.

set -u

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/../.." && pwd)"
BC_RUST="${BC_RUST:-$REPO_ROOT/target/debug/bc-rust}"

if [ ! -x "$BC_RUST" ]; then
    echo "bc-rust binary not found at $BC_RUST -- run \`cargo build -p cli\` first" >&2
    exit 2
fi

SCRATCH_ROOT=/tmp/bc-rust-cli-tests
mkdir -p "$SCRATCH_ROOT"
SCRATCH="$(mktemp -d "$SCRATCH_ROOT/$(basename "$0" .sh).XXXXXXXX")"

PASS=0
FAIL=0

# ---- running --------------------------------------------------------------------------------

# Runs one test function in a subshell, in its own scratch subdirectory, and records the result.
# A test's stderr is shown only when it fails.
run_test() {
    local name=$1
    local dir="$SCRATCH/$name"
    local rc
    mkdir -p "$dir"
    # The subshell must not be the condition of the `if`: bash ignores `set -e` everywhere inside
    # an `if` condition, even when set within it, which would let every assertion but the last
    # in a test pass silently. Take the status first, then test it.
    ( set -e; TMP="$dir"; LAST_STDERR="$dir/.last_stderr"; "$name" ) 2>"$dir/.stderr"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        PASS=$((PASS + 1))
        echo "ok   $name"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL $name"
        sed 's/^/     | /' "$dir/.stderr"
    fi
}

# Runs every function named test_* defined so far, then prints a summary. The scratch directory
# is removed only if everything passed. Exits non-zero if any test failed, which is what
# test_all.sh counts.
run_all() {
    local t
    for t in $(compgen -A function test_); do
        run_test "$t"
    done
    echo "$(basename "$0"): $PASS passed, $FAIL failed"
    if [ "$FAIL" -eq 0 ]; then
        rm -rf "$SCRATCH"
        return 0
    fi
    echo "scratch files left in $SCRATCH"
    return 1
}

# ---- inputs ---------------------------------------------------------------------------------

# N random bytes on stdout, from the library's own RNG.
rng() {
    "$BC_RUST" rng --len "$1"
}

# The hex of a file, as one line with no newline.
hex() {
    "$BC_RUST" hex-encode <"$1"
}

# The bytes of a hex string on stdout.
unhex() {
    printf '%s' "$1" | "$BC_RUST" hex-decode
}

# ---- bytes ----------------------------------------------------------------------------------

# `keylen BITS` prints the key length in bytes: `keylen 128` is 16.
keylen() {
    echo $(($1 / 8))
}

# `byte_at FILE OFFSET` prints the decimal value of the byte at OFFSET (0-based).
byte_at() {
    od -An -tu1 -j "$2" -N 1 "$1" | tr -d ' '
}

# `slice FILE OFFSET LEN` prints LEN bytes of FILE starting at OFFSET (0-based).
slice() {
    dd if="$1" bs=1 skip="$2" count="$3" status=none
}

# `flip_byte FILE OFFSET [MASK]` XORs the byte at OFFSET with MASK, 0x01 by default, in place.
flip_byte() {
    local file=$1 offset=$2 mask=${3:-1} byte
    byte=$(byte_at "$file" "$offset")
    printf "\\$(printf '%03o' $((byte ^ mask)))" | dd of="$file" bs=1 seek="$offset" conv=notrunc status=none
}

# `flip_hex HEX INDEX MASK` prints HEX with byte INDEX XORed by MASK.
flip_hex() {
    local hex=$1 idx=$2 mask=$3 byte
    byte=$(printf '%02x' $((0x${hex:$((2 * idx)):2} ^ mask)))
    printf '%s%s%s' "${hex:0:$((2 * idx))}" "$byte" "${hex:$((2 * idx + 2))}"
}

# `hex_out CMD...` runs CMD and prints its hex output as one line: `-x` output ends in a newline,
# which is dropped here.
hex_out() {
    "$@" | tr -d '\n'
}

# ---- assertions -----------------------------------------------------------------------------

fail() {
    echo "assertion failed: $*" >&2
    return 1
}

assert_same() {
    cmp -s "$1" "$2" || fail "$3 (files differ: $1 vs $2)"
}

assert_differs() {
    ! cmp -s "$1" "$2" || fail "$3 (files are identical: $1 vs $2)"
}

assert_size() {
    local actual
    actual=$(wc -c <"$1")
    [ "$actual" -eq "$2" ] || fail "$3 (expected $2 bytes, got $actual)"
}

assert_eq() {
    [ "$1" = "$2" ] || fail "$3 (expected '$2', got '$1')"
}

# Runs a command that must fail. Its stderr is saved for assert_stderr_has; its stdout is
# discarded. Inherits stdin, so `expect_fail "..." cmd <file` works.
expect_fail() {
    local msg=$1
    shift
    if "$@" >/dev/null 2>"$LAST_STDERR"; then
        fail "$msg (command succeeded: $*)"
    fi
}

# Runs a command that must succeed, saving its stderr for assert_stderr_has.
expect_ok() {
    local msg=$1
    shift
    "$@" 2>"$LAST_STDERR" || fail "$msg (command failed: $*; stderr: $(cat "$LAST_STDERR"))"
}

assert_stderr_has() {
    grep -q -- "$1" "$LAST_STDERR" || fail "stderr should mention '$1', got: $(cat "$LAST_STDERR")"
}
