# Adaptive Hashcat Scheduler

A lightweight experimental scheduler for comparative hash cracking experiments under fixed runtime budgets. The primary target use case is NSEC3 hash cracking research. This repository is for controlled strategy-allocation evaluation, not for production cracking orchestration.

## Features

- Fixed runtime slices (default 60 seconds)
- Multiple scheduling modes (`sequential`, `round_robin`, `adaptive`)
- Reproducible scheduler decisions via fixed random seeds
- Per-run potfile isolation in `--out-dir` (no default hashcat outfile)
- Per-slice JSONL metrics logging
- Per-job raw hashcat logs (`stdout`/`stderr`) in `hashcat_logs/`
- Brute-force keyspace tracking (`hashcat --keyspace`)
- Dictionary line-based skip/limit tracking

## Supported attack strategies

- **Dictionary attacks** (`-a 0`)
- **Pre-generated PCFG wordlists** (treated exactly as dictionary inputs)
- **Brute-force mask attacks** (`-a 3`)

Current brute-force example targets RFC1035-compatible label characters: lowercase letters, digits, and hyphen.

## Scheduling modes

- **`sequential`**: divide `total_slices` into a fixed per-arm budget, then run each arm consecutively in config order.
  - Budgeting rule: `total_slices // enabled_arms` per arm, with any remainder distributed in config order.
  - If an arm exhausts early, its remaining assigned slices are skipped (not redistributed).
- **`round_robin`**: rotate across non-exhausted arms.
- **`adaptive`**: warm-up + nonstationary bandit-style score tracking.

Adaptive mode uses:

- One warm-up slice per non-exhausted arm, in config order
- During warm-up, each arm uses an arm-local temporary potfile (`<out_dir>/warmup_potfiles/<arm_name>.pot`)
- Reward per slice:
  - Warm-up: `reward = arm_local_cracks / runtime_seconds`
  - Adaptive phase: `reward = marginal_new_cracks / runtime_seconds` using shared `run.pot`

- Exponential recency update:

`score_new = score_old + alpha * (reward - score_old)`

- Epsilon exploration for randomized arm selection

## Reproducibility

- Set `random_seed` in config and/or `--random-seed` on CLI.
- Scheduler randomness for epsilon exploration is deterministic for a fixed seed.
- Crack throughput/results can still vary slightly between runs because runtime-limited hashcat execution depends on hardware scheduling, thermal state, driver behavior, and timing.

## Repository structure

```text
.
├── hashcat_scheduler.py
├── examples/
├── runs/
└── README.md
```

## Example config

See: `examples/example_config.json`.

## Example command

```bash
python3 hashcat_scheduler.py \
  --hashes hashes.txt \
  --hash-mode 8300 \
  --config examples/example_config.json \
  --out-dir runs/example \
  --schedule adaptive \
  --total-slices 30
```

## Output files

Each run writes to `--out-dir`:

- `run.pot` (run-local potfile; canonical cracked-output store)
- `hashcat_logs/job_XXXXXX.log` (raw hashcat command output and parsed status JSON objects)
- `jobs.jsonl` (per-slice execution metrics)
- `hits.jsonl` (newly cracked entries)
- `run_summary.json` (final aggregate summary)

`jobs.jsonl` now includes parsed hashcat status fields (progress/speed/recovery/status/session/runtime estimates) when available, with `null` values when unavailable.

Use `--verbose` to print extra scheduler details (command + parsed status summary) without streaming full live hashcat output.

## Important limitations

- PCFG is handled as a static pre-generated wordlist, not as an online generator.
- Runtime-limited cracking is not perfectly deterministic.
- Dictionary/brute-force offset advancement can be approximate when hashcat progress fields are incomplete.
- The scheduler is intentionally minimal and experimental.
