# Adaptive Hashcat Scheduler

A lightweight experimental scheduler for comparative hash cracking experiments under fixed runtime budgets. The primary target use case is NSEC3 hash cracking research. This repository is for controlled strategy-allocation evaluation, not for production cracking orchestration.

## Features

- Fixed runtime slices (default 60 seconds)
- Multiple scheduling modes (`sequential`, `round_robin`, `adaptive`)
- Reproducible scheduler decisions via fixed random seeds
- Per-run potfile/outfile isolation in `--out-dir`
- Per-slice JSONL metrics logging
- Brute-force keyspace tracking (`hashcat --keyspace`)
- Dictionary line-based skip/limit tracking

## Supported attack strategies

- **Dictionary attacks** (`-a 0`)
- **Pre-generated PCFG wordlists** (treated exactly as dictionary inputs)
- **Brute-force mask attacks** (`-a 3`)

Current brute-force example targets RFC1035-compatible label characters: lowercase letters, digits, and hyphen.

## Scheduling modes

- **`sequential`**: run arms in config order until exhaustion, then move to the next.
- **`round_robin`**: rotate across non-exhausted arms.
- **`adaptive`**: warm-up + nonstationary bandit-style score tracking.

Adaptive mode uses:

- One warm-up slice per non-exhausted arm
- Reward per slice:

`reward = new_cracks / runtime_seconds`

- Exponential recency update:

`score_new = score_old + alpha * (reward - score_old)`

- Epsilon exploration for randomized arm selection

## Reproducibility

- Set `random_seed` in config and/or `--random-seed` on CLI.
- Scheduler randomness (warm-up shuffle and epsilon exploration) is deterministic for a fixed seed.
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

- `run.pot` (run-local potfile)
- `hashcat.out` (run-local outfile)
- `jobs.jsonl` (per-slice execution metrics)
- `hits.jsonl` (newly cracked entries)
- `run_summary.json` (final aggregate summary)

## Important limitations

- PCFG is handled as a static pre-generated wordlist, not as an online generator.
- Runtime-limited cracking is not perfectly deterministic.
- Dictionary/brute-force offset advancement can be approximate when hashcat progress fields are incomplete.
- The scheduler is intentionally minimal and experimental.
