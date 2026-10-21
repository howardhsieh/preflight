#!/usr/bin/env bash
# Scan the N most-starred GitHub repositories, PAR at a time, and collect one
# JSON line per repository into results.jsonl.
set -euo pipefail

N="${1:-1000}"
PAR="${PAR:-6}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
export BENCH_DIR="${BENCH_DIR:-${TMPDIR:-/tmp}/preflight-bench}"
OUT="${BENCH_OUT:-$HERE/results.jsonl}"
LIST="$BENCH_DIR/repos.txt"

mkdir -p "$BENCH_DIR/repos" "$BENCH_DIR/out"
(cd "$ROOT" && go build -o "$BENCH_DIR/preflight" ./cmd/preflight)

# The search API returns at most 1000 results, 100 per page. Refetch when a
# previous, smaller run left a short list behind.
if [ ! -s "$LIST" ] || [ "$(wc -l < "$LIST")" -lt "$N" ]; then
  pages=$(( (N + 99) / 100 ))
  : > "$LIST"
  for p in $(seq 1 "$pages"); do
    gh api "search/repositories?q=stars:>1000&sort=stars&order=desc&per_page=100&page=$p" \
      --jq '.items[] | "\(.full_name) \(.stargazers_count)"' >> "$LIST"
    sleep 2
  done
fi

head -n "$N" "$LIST" | xargs -P "$PAR" -L 1 "$HERE/scan-one.sh"

cat "$BENCH_DIR"/out/*.json > "$OUT"
echo "wrote $(wc -l < "$OUT") results to $OUT"
