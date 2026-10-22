# False-positive benchmark

`run.sh` clones the most-starred GitHub repositories (shallow, hooks disabled) and runs
`preflight scan` over each one. Popular repositories are assumed benign, so any
`DANGER` verdict is a false positive and every finding is a candidate for tuning.

```bash
bench/run.sh 1000            # clones into $TMPDIR/preflight-bench, writes results.jsonl
python3 bench/summarize.py bench/results.jsonl
```

Repositories are fetched with `preflight clone`, so this doubles as an integration test
of the hardened clone path. Nothing in the cloned repositories is ever executed.

Results and the tuning history are in [results.md](results.md); the raw JSONL is not committed.
`scan-one.sh` is the per-repository worker that `run.sh` runs in parallel.
