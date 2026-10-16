#!/usr/bin/env bash
# Builds the CLI, then runs every cli/tests/test_*.sh against target/debug/bc-rust and reports
# the totals.
#
#     cli/tests/test_all.sh
#
# Each test file is independent and exits non-zero if any of its tests failed; this script only
# counts files. Set BC_RUST to test a binary somewhere else, in which case nothing is built.

set -u

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/../.." && pwd)"

if [ -z "${BC_RUST:-}" ]; then
    echo "=== cargo build -p cli"
    cargo build -p cli --manifest-path "$REPO_ROOT/Cargo.toml" || exit 2
    echo
fi

passed=0
failed=0
failed_files=()

for file in "$TESTS_DIR"/test_*.sh; do
    [ "$(basename "$file")" = "test_all.sh" ] && continue
    echo "=== $(basename "$file")"
    if bash "$file"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        failed_files+=("$(basename "$file")")
    fi
    echo
done

echo "test files: $passed passed, $failed failed"
if [ "$failed" -ne 0 ]; then
    printf '  failed: %s\n' "${failed_files[@]}"
    exit 1
fi
