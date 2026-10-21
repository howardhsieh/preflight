#!/usr/bin/env python3
"""Summarize bench/results.jsonl: verdict rates and the noisiest rules."""
import collections
import json
import sys


def main(path: str) -> None:
    rows = [json.loads(l) for l in open(path) if l.strip()]
    ok = [r for r in rows if "verdict" in r]
    errs = len(rows) - len(ok)
    verdicts = collections.Counter(r["verdict"] for r in ok)
    by_rule = collections.Counter()
    repos_by_rule = collections.defaultdict(set)
    sev_by_rule = {}
    for r in ok:
        for f in r["findings"]:
            by_rule[f["rule_id"]] += 1
            repos_by_rule[f["rule_id"]].add(r["repo"])
            sev_by_rule[f["rule_id"]] = f["severity"]

    n = len(ok)
    print(f"repos scanned: {n}  (errors: {errs})")
    for v in ("CLEAN", "REVIEW", "DANGER"):
        print(f"  {v:7s} {verdicts[v]:5d}  {100 * verdicts[v] / max(n, 1):5.1f}%")
    print()
    print(f"{'rule':7s} {'sev':9s} {'findings':>8s} {'repos':>6s}  {'% repos':>7s}")
    for rule, cnt in by_rule.most_common():
        reps = len(repos_by_rule[rule])
        print(f"{rule:7s} {sev_by_rule[rule]:9s} {cnt:8d} {reps:6d}  {100 * reps / max(n, 1):6.1f}%")

    print("\nDANGER / REVIEW repos:")
    for r in sorted(ok, key=lambda r: -r["score"]):
        if r["verdict"] == "CLEAN":
            continue
        rules = sorted({f["rule_id"] for f in r["findings"] if f["severity"] in ("high", "critical")})
        print(f"  {r['verdict']:6s} {r['score']:3d}  {r['repo']:45s} {' '.join(rules)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "bench/results.jsonl")
