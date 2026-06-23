# NSEC3 Candidate Scheduler

Adaptive scheduler for DNS/NSEC3 candidate generation and hashcat-based validation. It runs configured candidate-generation arms, measures discoveries per slice, and allocates later slices with epsilon-greedy scoring.

## Requirements

- Python 3.10+
- hashcat available on `PATH` or passed with `--hashcat-bin`
- Hash files and wordlists supplied by the operator
- Optional OSINT tools: Amass and Subfinder

This repository does not currently include model files under `models/`. Predictive feedback arms require trained adjacent-label pair models, and static-affix feedback arms require mined prefix/suffix files.

## Install

```sh
python3 -m pip install -e ".[test]"
```

The package installs the `nsec3-candidate-scheduler` console script. The module entrypoint remains available with `python3 -m nsec3_candidate_scheduler`.

## Quick start

`example_config.json` is a reference config. Enabled arms use tiny smoke-test wordlists under `wordlists/`; disabled arms show placeholder paths for experiment-scale inputs.

```sh
python3 -m nsec3_candidate_scheduler run \
  --config example_config.json \
  --hashes /path/to/hashes.txt \
  --hash-mode 8300 \
  --out-dir runs/example \
  --total-slices 10
```

## Core concepts

- **Arm name**: stable configured instance identifier, using `family/mechanism` form such as `feedback/parent-domain`.
- **Arm type**: flat implementation selector such as `parent_domain_feedback`.
- **Slice**: one hashcat execution window. An arm-level `slice_seconds` overrides the CLI value for that arm.
- **Warm-up**: default `warmup.scoring=arm_local` uses per-arm potfiles for warm-up scoring; adaptive scoring always uses shared marginal discoveries.

## Arm families

| Family | Canonical examples | Types |
| --- | --- | --- |
| Wordlist | `wordlist/seclists`, `wordlist/pcfg-100m` | `dictionary` |
| Brute force | `bruteforce/rfc1035-len2-5` | `brute_force` |
| Feedback | `feedback/predictive-prefix`, `feedback/parent-domain` | `predictive_prefix`, `predictive_suffix`, `permutation`, `static_affix_feedback`, `parent_domain_feedback` |
| OSINT | `osint/amass`, `osint/subfinder` | `amass_osint`, `subfinder_osint` |

## Output files

The run directory contains `jobs.jsonl`, `run.pot`, per-job hashcat logs, warm-up potfiles when arm-local warm-up is used, feedback state under `feedback/<safe-arm-name>/`, and OSINT state under `osint/<safe-arm-name>/`.

Feedback state uses `feedback/<arm>/queue.txt`, `feedback/<arm>/generated_candidates.sqlite`, and `queue.txt`, `slice_candidates.txt`, `active_slice.json`, `expanded_bases.txt`, and optionally `generated_candidates.sqlite` or `generated_candidates.txt` depending on the dedupe backend.

## Documentation

- `docs/config.md`: configuration reference.
- `docs/state-and-logs.md`: run directory, `jobs.jsonl`, potfiles, hashcat logs, and resume state.
- `docs/feedback.md`: feedback lifecycle, dedupe backends, and queue files.
- `docs/osint.md`: Amass/Subfinder behavior and OSINT completion states.

## Testing

```sh
python3 -m pytest -v tests
```

## Safety and scope

NSEC3 Candidate Scheduler launches hashcat and optional OSINT binaries configured by the operator. It does not manage OSINT provider credentials, does not bundle large wordlists or models, and does not auto-migrate old run directories after arm names change. Use a fresh `out_dir` after renaming arms.

## Optimized kernels

Hashcat optimized kernels (`-O`) are used by default because they are faster. Some long/problematic candidates can fail under optimized kernels, so the scheduler defaults to automatic optimized-kernel failover: it logs the failed optimized attempt as `valid_work=false` and `scored=false`, disables optimized kernels for the rest of the run, retries the failed slice once unoptimized, and records retry metadata in `jobs.jsonl`.

Default automatic failover:

```sh
python3 -m nsec3_candidate_scheduler run \
  --hashes hashes.txt \
  --hash-mode 8300 \
  --config example_config.json \
  --out-dir out \
  --schedule adaptive \
  --total-slices 150 \
  --slice-seconds 60
```

Disable optimized kernels from the start:

```sh
python3 -m nsec3_candidate_scheduler run \
  --hashes hashes.txt \
  --hash-mode 8300 \
  --config example_config.json \
  --out-dir out \
  --schedule adaptive \
  --total-slices 150 \
  --slice-seconds 60 \
  --no-optimized-kernels
```

Keep optimized kernels enabled and disable automatic failover:

```sh
python3 -m nsec3_candidate_scheduler run \
  --hashes hashes.txt \
  --hash-mode 8300 \
  --config example_config.json \
  --out-dir out \
  --schedule adaptive \
  --total-slices 150 \
  --slice-seconds 60 \
  --no-optimized-kernel-failover
```

The corresponding config keys are `hashcat.optimized_kernels` and `hashcat.optimized_kernel_failover`.
