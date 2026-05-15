# Hashcat Scheduler Experiment (Minimal)

This directory contains a minimal reproducible experiment config for `hashcat_scheduler.py`.

## What the config is

`example_config.json` defines three attack arms plus scheduler parameters (`random_seed`, `randomize_warmup`, `alpha`, `epsilon`) used for fixed-runtime-slice comparisons.

## Arms in `example_config.json`

1. **SecLists DNS wordlist** (`seclists-dns`)
   - Type: `dictionary`
2. **Pre-generated PCFG wordlist** (`pcfg-100m`)
   - Type: `dictionary`
   - PCFG guesses are generated ahead of time and treated exactly like a normal wordlist.
3. **Brute-force RFC1035-style label charset length 6** (`alnum-hyphen-len6`)
   - Type: `brute_force`
   - Targets RFC1035-compatible label characters: lowercase letters, digits, and hyphen (`-`).
   - Charset: `abcdefghijklmnopqrstuvwxyz0123456789-` via `custom_charset_1` and mask `?1?1?1?1?1?1`.

## Runtime, scheduling, and reproducibility

- Runtime is allocated in fixed slices (`--slice-seconds`, default 60).
- Scheduling modes:
  - `sequential`
  - `round_robin`
  - `adaptive`
- Adaptive mode runs a warm-up slice for every non-exhausted arm before score-based selection.
- Reward is computed per slice as:
  - `new_cracks / runtime_seconds`
- Set a reproducible scheduler seed in config with `"random_seed"`, or override with CLI `--random-seed`.
- Scheduler choices (warm-up shuffle/exploration decisions) are reproducible with the same seed and inputs.
- Exact cracking results can still vary slightly because runtime-limited hashcat execution is not perfectly deterministic.

## Tracking details

- Every scheduler run creates its own run potfile in `--out-dir` (`run.pot`), plus `jobs.jsonl`, `hits.jsonl`, `run_summary.json`, and per-job logs in `hashcat_logs/`.
- `hashcat.out` is not created by default; the potfile is the canonical cracked-output store.
- `jobs.jsonl` stores parsed hashcat status/statistics fields for downstream plotting.
- `--verbose` adds scheduler-level detail (command + parsed status summary) without live streaming raw hashcat output.
- By default, hashcat uses normal kernel selection; set `"pure_kernels": true` in config or pass `--pure-kernels` to use `--optimized-kernel-disable` for cracking jobs.
- Brute-force masks use hashcat keyspace tracking (`--keyspace`) with skip/limit progression.
- Dictionary attacks (including pre-generated PCFG files) use line-based skip/limit tracking.

## Example command

```bash
python3 hashcat_scheduler.py \
  --hashes hashes.txt \
  --hash-mode 8300 \
  --config examples/example_config.json \
  --out-dir runs/seeded-example \
  --schedule adaptive \
  --total-slices 30 \
  --random-seed 1337
```
