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

### Optimized-kernel failover fields

Optimized-kernel-specific hashcat execution failures are logged but are not treated as valid cracking work. `valid_work=false` means hashcat launched but the result should not be treated as a valid slice; `scored=false` means the arm reward/score is not updated from that attempt.

When automatic failover is enabled, the failed optimized attempt includes fields such as:

```json
{
  "hashcat_optimized_kernels": true,
  "hashcat_optimized_kernel_hint": "Hashcat failed with optimized kernels enabled. Retrying with unoptimized kernels.",
  "optimized_kernel_failover_enabled": true,
  "valid_work": false,
  "scored": false,
  "retryable": true,
  "retry_reason": "optimized_kernel_failure",
  "retry_scheduled": true
}
```



All-hashes token-length failures use the same failover metadata with a more specific retry reason and parse counts:

```json
{
  "hashcat_optimized_kernels": true,
  "hashcat_optimized_kernel_hint": "Hashcat rejected all hashes with Token length exception while optimized kernels were enabled. Retrying with unoptimized kernels.",
  "optimized_kernel_failover_enabled": true,
  "valid_work": false,
  "scored": false,
  "retryable": true,
  "retry_reason": "optimized_kernel_all_hashes_token_length",
  "retry_scheduled": true,
  "hashcat_parse_error_count": 22,
  "hashcat_parse_error_total": 22
}
```

The trigger requires both a summary such as `Token length exception: 22/22 hashes` and `No hashes loaded`. A partial summary such as `Token length exception: 2/22 hashes` is not treated as a global optimized-kernel failover signal by default. If the unoptimized retry also fails with all hashes rejected, the retry record is classified as a hashfile/hash-mode/input-format problem and no further retry is scheduled:

```json
{
  "hashcat_optimized_kernels": false,
  "valid_work": false,
  "scored": false,
  "retry_scheduled": false,
  "hashcat_failure_class": "hashfile_parse_error_all_hashes_token_length",
  "hashcat_parse_error_count": 22,
  "hashcat_parse_error_total": 22
}
```

The retry record links back to the failed job and runs without optimized kernels:

```json
{
  "hashcat_optimized_kernels": false,
  "retry_of_job_id": 24,
  "retry_reason": "optimized_kernel_failure"
}
```

When `--no-optimized-kernel-failover` or `hashcat.optimized_kernel_failover=false` is used, the failed optimized attempt includes:

```json
{
  "hashcat_optimized_kernels": true,
  "hashcat_optimized_kernel_hint": "Hashcat failed with optimized kernels enabled. Automatic failover is disabled; continuing with optimized kernels.",
  "optimized_kernel_failover_enabled": false,
  "valid_work": false,
  "scored": false,
  "retryable": false,
  "retry_reason": "optimized_kernel_failure",
  "retry_scheduled": false
}
```

`retry_scheduled=true` means the scheduler will retry the same slice with optimized kernels disabled. `retry_of_job_id` links the retry job to the failed optimized-kernel attempt. `optimized_kernel_failover_enabled=false` means the operator chose to continue optimized despite failures.
