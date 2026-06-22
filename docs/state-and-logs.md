# State and logs

## Run directory

| Path | Purpose |
| --- | --- |
| `jobs.jsonl` | Slice records and OSINT completion events. |
| `run.pot` | Shared hashcat potfile. |
| `warmup_baseline.potfile` | Baseline for arm-local warm-up scoring. |
| `warmup_potfiles/<safe-arm-name>.potfile` | Per-arm warm-up potfiles when `warmup.scoring=arm_local`. |
| `hashcat_logs/job_000001.log` | Combined stdout/stderr per executed slice. |
| `feedback/<safe-arm-name>/` | Feedback queue and dedupe state. |
| `osint/<safe-arm-name>/` | OSINT process state and candidate wordlists. |

Configured arm names are preserved in logs as `arm`. File paths use `nsec3_candidate_scheduler.naming.safe_name()`, so `feedback/parent-domain` maps to `feedback-parent-domain`. Arm renames are state-breaking; use a fresh `out_dir` after renaming arms.

## `jobs.jsonl`

Slice records include `arm`, `arm_family`, `arm_short_name`, `arm_type`, `selection_reason`, `requested_slice_seconds`, `runtime_seconds`, score fields, crack counts, hashcat exit status, and arm-specific metrics. OSINT completion records use `event="osint_completed"` with `status` equal to `ready`, `exhausted`, or `failed`.

## Feedback state

| File | Purpose |
| --- | --- |
| `queue.txt` | Pending candidates not yet assigned to hashcat. |
| `slice_candidates.txt` | Current active hashcat input slice. |
| `active_slice.json` | Active slice metadata and skip/cursor. |
| `expanded_bases.txt` | Bases already expanded. |
| `generated_candidates.sqlite` | Persistent generated-candidate dedupe ledger when backend is `sqlite`. |
| `generated_candidates.txt` | Optional legacy/audit output only. |

Completed slice files are not retained by default. If `retain_completed_slices` is enabled, completed slice snapshots may be kept for audit/debugging.

## OSINT state

OSINT arms write under `osint/<safe-arm-name>/`: `state.json`, tool log, tool err, tool pid, `raw_names.txt`, and `candidates.txt`. Amass uses `amass.log`, `amass.err`, and `amass.pid`; Subfinder uses `subfinder.log`, `subfinder.err`, and `subfinder.pid`.
