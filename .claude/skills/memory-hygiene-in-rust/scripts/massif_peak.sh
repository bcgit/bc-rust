#!/usr/bin/env bash
# Peak stack of one or more mem_usage_benches functions, via valgrind massif.
#
#   massif_peak.sh <bin> <label> <bench_fn>...
#   e.g. massif_peak.sh bench_mldsa_mem_usage after bench_mldsa44_sign bench_mldsa44_verify
#
# For each function it rewrites main() of mem_usage_benches/<bin>.rs to call only that function,
# builds --release, runs the binary under massif with --heap=no --stacks=yes, and prints
# "<label> <fn> <peak_bytes>". The bench source is restored afterwards (also on failure).
# Per-run artifacts go to $MASSIF_OUT (default /tmp/massif_peak): the massif file, stdout and stderr
# of the bench, so outputs can be diffed between labels (signatures must be identical, verifies
# must succeed) and the massif time series can be inspected:
#   awk -F= '/^time=/{t=$2} /^mem_stacks_B=/{print t, $2}' $MASSIF_OUT/massif_<label>_<fn>.out
#
# Run from the repository root. Do not edit the bench source while this is running.
set -euo pipefail
BIN=$1; LABEL=$2; shift 2
OUT=${MASSIF_OUT:-/tmp/massif_peak}; mkdir -p "$OUT"
F="mem_usage_benches/$BIN.rs"
SAVED="$OUT/${BIN}_saved_${LABEL}.rs"
cp "$F" "$SAVED"
trap 'cp "$SAVED" "$F"' EXIT
for fn in "$@"; do
  cp "$SAVED" "$F"
  python3 - "$F" "$fn" <<'PY'
import sys
path, fn = sys.argv[1], sys.argv[2]
src = open(path).read()
i = src.index("fn main() {")
open(path, "w").write(src[:i] + "fn main() {\n    " + fn + "()\n}\n")
PY
  cargo build -q --release -p mem_usage_benches --bin "$BIN"
  massif="$OUT/massif_${LABEL}_${fn}.out"
  valgrind --tool=massif --heap=no --stacks=yes --massif-out-file="$massif" \
    -- "target/release/$BIN" >"$OUT/out_${LABEL}_${fn}.txt" 2>"$OUT/err_${LABEL}_${fn}.txt" || true
  peak=$(grep '^mem_stacks_B=' "$massif" | cut -d= -f2 | sort -n | tail -1)
  echo "$LABEL $fn $peak"
done
