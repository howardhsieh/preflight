#!/usr/bin/env bash
# Worker for run.sh: clone and scan one repository, write one JSON line to
# $WORK/out/<owner>__<repo>.json. Safe to run many in parallel.
set -uo pipefail

full="$1"; stars="$2"
WORK="${BENCH_DIR:?}"; BIN="$WORK/preflight"
name="${full//\//__}"
out="$WORK/out/$name.json"
[ -s "$out" ] && exit 0

dest="$WORK/repos/$name"
rm -rf "$dest"
if ! "$BIN" clone "https://github.com/$full.git" "$dest" --timeout 5m -f json --fail-on none -o "$dest.json" 2>"$dest.err"; then
  echo "{\"repo\":\"$full\",\"stars\":$stars,\"error\":\"clone-or-scan-failed\"}" > "$out"
  echo "$full ERROR $(tail -1 "$dest.err" 2>/dev/null)"
  rm -rf "$dest" "$dest.json" "$dest.err"
  exit 0
fi
python3 - "$full" "$stars" "$dest.json" > "$out" <<'EOF'
import json, sys
full, stars, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
r = json.load(open(path))
findings = [{k: f.get(k) for k in ("rule_id", "severity", "file", "message", "evidence")} for f in r["findings"]]
print(json.dumps({"repo": full, "stars": stars, "verdict": r["verdict"], "score": r["score"],
                  "files": r["files_scanned"], "findings": findings}))
EOF
echo "$full $(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["verdict"], r["score"], len(r["findings"]))' "$dest.json")"
rm -rf "$dest" "$dest.json" "$dest.err"
