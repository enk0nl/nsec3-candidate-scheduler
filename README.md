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
- Dictionary cursor tracking from hashcat status JSON for NSEC3-style salted cracking

## Simplified experiment model

This scheduler is currently tuned for hashcat mode 8300 / NSEC3-style salted cracking. Arms are explicit dictionary, brute-force mask, or one optional queue-driven feedback arm. Rewards remain `new discoveries / actual runtime`, with adaptive scores updated by alpha/epsilon bandit logic. Dictionary cursor tracking uses hashcat status JSON progress divided by `recovered_salts_total`; if that progress cannot be parsed, the dictionary cursor is not advanced. Feedback state lives in the four feedback files listed below: discoveries expand each base once, enqueue unseen `<base>.<common>` and `<common>.<base>` candidates, and drain the queue into `feedback_slice_candidates.txt` when the feedback arm runs. Optional `force_every_slices` cadence applies only after adaptive warm-up and only to available arms. Known limitation: feedback slice candidate resume may not perfectly preserve partial progress within a drained feedback slice.

## Supported attack strategies

- **Dictionary attacks** (`-a 0`)
- **Pre-generated PCFG wordlists** (treated exactly as dictionary inputs)
- **Brute-force mask attacks** (`-a 3`, one arm can run one or many explicit masks)
- **Feedback attacks** (`type: "feedback"`) that expand newly cracked DNS names with configured common labels and run queued candidates as dictionary slices

Current brute-force example targets RFC1035-compatible label characters: lowercase letters, digits, and hyphen.
For `type: "brute_force"`, configure either:

- `"mask": "?1?1?1?1?1"` (single mask), or
- `"masks": ["?1?1?1", "?1?1?1?1", "?1?1?1?1?1"]` (multiple masks in order).

Multiple masks are attempted in config order with independent per-mask keyspace/skip/exhausted state. This replaces using `--increment`, so resume/chunk behavior stays explicit and auditable (especially useful for DNS labels where short names like `www` require shorter masks).

## Feedback arms

A feedback arm is optional and is only registered when explicitly present in the config with `"type": "feedback"`. Set `"enabled": false` to leave it out of scheduling. At most one enabled feedback arm may be configured. `common_labels` is required and must be a non-empty list of strings. Feedback bases and common labels are normalized to lowercase and stripped of surrounding whitespace; single labels, multi-label names, underscores, hyphens, and digits are allowed. Empty names, leading/trailing dots, empty dot components, embedded whitespace, labels longer than 63 characters, and names longer than 253 characters are rejected.

After each slice, newly cracked names are expanded into both `<discovered>.<common>` and `<common>.<discovered>` candidates, deduplicated through persistent feedback state files in the run output directory, and appended to `feedback_queue.txt`. The feedback arm is eligible only while that queue has items. When selected, the queue is written to `feedback_slice_candidates.txt`, drained, and run through hashcat as a dictionary slice using the same runtime limit and reward calculation as other arms.

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

Optional per-arm forced cadence can be configured with `"force_every_slices": N`, where `N` is a positive integer. Forced cadence applies only after adaptive warm-up: if an available arm has not run for at least `N` adaptive-phase slices, it is selected before normal epsilon-greedy selection. If multiple available arms are due, the scheduler selects the most overdue arm by overdue ratio, then fewest runs, lowest runtime, and name.

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
- `hashcat_logs/job_XXXXXX.log` (raw hashcat command output; parsed status JSON objects are included only with `--verbose-debug`)
- `jobs.jsonl` (per-slice execution metrics)
- `hits.jsonl` (newly cracked entries)
- `run_summary.json` (final aggregate summary)
- `feedback_queue.txt`, `feedback_seen_candidates.txt`, `feedback_expanded_bases.txt`, and `feedback_slice_candidates.txt` when a feedback arm is configured

`jobs.jsonl` now includes parsed hashcat status fields (progress/speed/recovery/status/session/runtime estimates) when available, with `null` values when unavailable.

Use `--verbose` to print extra scheduler details without streaming full live hashcat output. Use `--verbose-debug` only when raw parsed status JSON dumps are needed.

## Important limitations

- PCFG is handled as a static pre-generated wordlist, not as an online generator.
- Runtime-limited cracking is not perfectly deterministic.
- Dictionary cursor advancement uses hashcat status JSON progress scaled by recovered salts; if status progress cannot be parsed, the dictionary cursor is left unchanged. Experimental dictionary chunking is available only when `dictionary_candidate_limit` is set to a positive integer in config; the default is `null`/absent and does not pass `--limit`.
- Dictionary/brute-force offset advancement can be approximate when hashcat progress fields are incomplete.
- The scheduler is intentionally minimal and experimental.

## Running the scheduler

The package entry point is now:

```bash
python3 -m adaptive_hashcat_scheduler run \
  --hashes /path/to/nsec3_hashcat.txt \
  --hash-mode 8300 \
  --config configs/adaptive_predictive_feedback.json \
  --out-dir runs/adaptive_predictive \
  --schedule adaptive \
  --total-slices 150 \
  --slice-seconds 60 \
  --verbose
```

The legacy `hashcat_scheduler.py` script remains as a thin wrapper around the package CLI. Dictionary arms still use hashcat JSON progress scaled by `recovered_salts_total` to advance the candidate cursor for NSEC3 mode 8300, and brute-force arms remain explicit mask arms.

## Training directional predictive feedback models

Train both directional adjacent-label models from a hashcat potfile or a plain cracked-name file:

```bash
python3 -m adaptive_hashcat_scheduler train-predictive-feedback \
  --input /path/to/training.pot \
  --input-format auto \
  --output-prefix-model models/prefix_pairs.tsv \
  --output-suffix-model models/suffix_pairs.tsv
```

Potfile parsing uses the final colon-separated field as the cracked DNS value, which is required for NSEC3 hashcat mode 8300 potfiles.

## Prefix model vs suffix model

The two predictive arms intentionally use separate directional models:

- Prefix model: `source/context -> likely left label`. From `child.parent`, it learns `parent -> child` and is used by `predictive_prefix` to generate `predicted.base`.
- Suffix model: `source/context -> likely right label`. From `child.parent`, it learns `child -> parent` and is used by `predictive_suffix` to generate `base.predicted`.

For `k2._domainkey.example`, the prefix model learns `_domainkey -> k2` and `example -> _domainkey`; the suffix model learns `k2 -> _domainkey` and `_domainkey -> example`.

## Enabling predictive_prefix and predictive_suffix arms

Predictive arms are never injected automatically. Add each arm explicitly to the config. Each arm has independent scheduling state and independent text files named after the arm, for example `predictive-prefix_queue.txt`, `predictive-prefix_seen_candidates.txt`, and `predictive-prefix_expanded_bases.txt`.

See `configs/adaptive_predictive_feedback.json` for a complete example with `predictive_prefix` and `predictive_suffix` arms.

## Candidate generation

After every slice, newly cracked DNS names are normalized and passed to feedback arms. With the recommended initial setting, `base_mode = "full"` and `prediction_source = "leftmost"`, the model predicts from the leftmost label while generated candidates retain the full discovered base.

- `predictive_prefix` generates `prediction + "." + base`.
- `predictive_suffix` generates `base + "." + prediction`.
- The optional `feedback` arm remains common-label based and generates both `base.common` and `common.base`.

## Forced cadence

Any arm may set `force_every_slices`. During the adaptive phase, available overdue arms are selected before epsilon-greedy selection. If multiple arms are due, the scheduler chooses the highest overdue ratio, then fewest runs, lowest runtime, and finally name.

## Known limitations

- The predictive model is a simple adjacent-pair model with trigram smoothing.
- The scheduler is tuned for DNS/NSEC3 hashcat mode 8300.
- Text-file feedback queues may need SQLite or another transactional store later.
- Feedback slice partial resume is limited because v1 drains the full queue into the slice file.
- Separate prefix/suffix predictors may produce overlapping candidates; dedupe is per-arm in v1.
