#!/usr/bin/env bash
# Rebuild docs/demo.gif: build preflight, generate the inert demo repository,
# and record the tape with vhs (brew install vhs).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$root" && go build -ldflags "-X main.version=$(git describe --tags --always)" -o "$work/bin/preflight" ./cmd/preflight)
"$root/docs/demo/make-demo-repo.sh" "$work/trading-dashboard" >/dev/null

cd "$root"
PATH="$work/bin:$PATH" DEMO_DIR="$work/trading-dashboard" vhs docs/demo/demo.tape
ls -la docs/demo.gif
