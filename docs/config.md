# Configuration reference

`load_config()` validates every arm entry, including disabled arms. Name/type/schema errors fail early. File paths and external resources are validated only for enabled arms, so disabled placeholder model arms remain loadable.

## Top-level fields

| Field | Type | Notes |
| --- | --- | --- |
| `random_seed` | integer | RNG seed for adaptive selection. |
| `alpha` | number | Exponential score update factor. |
| `epsilon` | number | Adaptive exploration probability. |
| `warmup.scoring` | `arm_local` or `shared_marginal` | Default is `arm_local`. Adaptive scoring always uses shared marginal discoveries. |
| `hashcat.optimized_kernels` | boolean | Default enabled unless CLI disables it. |
| `stopping.stop_when_all_hashes_cracked` | boolean | Default true. Stop before scheduling another slice once all target hash sides are present in the shared potfile. |
| `arms` | array | Arm definitions. |

Arm names are stable identifiers and use `family/mechanism` form. Canonical names include `wordlist/seclists`, `wordlist/pcfg-100m`, `bruteforce/rfc1035-len2-5`, `feedback/predictive-prefix`, `feedback/predictive-suffix`, `feedback/permutation-numeric`, `feedback/static-affix-top5000`, `feedback/parent-domain`, `osint/amass`, and `osint/subfinder`.

Arm types remain flat: `dictionary`, `brute_force`, `feedback`, `predictive_prefix`, `predictive_suffix`, `permutation`, `static_affix_feedback`, `parent_domain_feedback`, `amass_osint`, and `subfinder_osint`.

## Common arm fields

| Field | Type | Notes |
| --- | --- | --- |
| `name` | string | Required, unique, no `..`, no empty path segment, no leading/trailing whitespace. |
| `type` | string | Required implementation selector. Unknown disabled types fail validation. |
| `enabled` | boolean | Disabled arms are schema-validated but not instantiated. |
| `slice_seconds` | positive integer | Optional per-arm override for CLI `--slice-seconds`. Logged as `requested_slice_seconds`. |
| `force_every_slices` | positive integer | Optional adaptive cadence override. |
| `min_slices_between_runs` | non-negative integer | Feedback/OSINT cooldown. |
| `min_queue_size` | non-negative integer | Feedback queue gate. |

## Dictionary arms

`type: "dictionary"` requires `wordlist` when enabled. `candidate_count` may be supplied manually; otherwise the total may be unknown unless `count_candidates_at_startup` is true. Startup counting scans the wordlist, so keep `count_candidates_at_startup` false for large files unless the scan is intentional. `large_wordlist_scan_warning_bytes` controls the scan warning threshold.

## Brute-force arms

`type: "brute_force"` uses hashcat masks and optional custom charsets. It is warm-up eligible and does not use feedback queue state.

## Feedback arms

Feedback arms read newly cracked labels and enqueue generated candidates for later hashcat dictionary slices. Types: `feedback`, `predictive_prefix`, `predictive_suffix`, `permutation`, `static_affix_feedback`, `parent_domain_feedback`.

Predictive feedback arms require trained adjacent-label pair models via `model`. static-affix feedback arms require mined prefix/suffix files via `prefixes` and `suffixes`. This repository does not currently include model files under `models/`; predictive and static-affix source files must be supplied by the operator. Model-dependent arms are disabled by default in `example_config.json`; disabled placeholder paths are allowed.

Dedupe backends:

| Backend | Files | Notes |
| --- | --- | --- |
| `sqlite` | `generated_candidates.sqlite` | Default persistent generated-candidate dedupe ledger; uses `INSERT OR IGNORE`. |
| `text` | `generated_candidates.txt` | Legacy persistent ledger and audit output. Heavy for large runs. |
| `none` | no generated ledger | Disables persistent historical generated-candidate dedupe. Current batch, `queue.txt`, active slice, and already-cracked dedupe still apply. |

Recommended defaults: `generated_candidates_backend="none"` for `feedback/predictive-prefix`, `feedback/predictive-suffix`, and `feedback/static-affix-top5000`; `sqlite` for `feedback/permutation-numeric` and `feedback/parent-domain`. `retain_generated_candidates_text=false` avoids optional audit text output with SQLite.

Queue files are text files. `queue.txt` is still loaded and rewritten for slicing and membership checks; this is a known scalability limit.

## OSINT arms

`amass_osint` and `subfinder_osint` start external collection and become dictionary arms after candidates are ready. They are not warm-up eligible. `run_immediately_when_ready` defaults to true; the first run happens at the next adaptive slice, not during warm-up. Completion emits a `jobs.jsonl` event, not a slice.

Amass fields include `amass_binary`, `domains`, `start_on_run_start`, `poll_interval_seconds`, `run_immediately_when_ready`, `include_single_label`, `include_multi_label`, `max_candidates`, `dedupe`, and `keep_running_on_exit`. Config parsing does not run an unbounded Amass version check.

Subfinder fields include `subfinder_binary`, `domain`, `start_on_run_start`, `poll_interval_seconds`, `run_immediately_when_ready`, `include_single_label`, `include_multi_label`, `max_candidates`, `dedupe`, and `keep_running_on_exit`.

## Logging

Normal output contains slice progress, final summary, OSINT start/completion lines, actual errors, and concrete disk threshold warnings. Arm inventory, backend policy, unavailable-arm details, and queue diagnostics are verbose/debug output.

## Hashcat optimized kernels and failover

Hashcat optimized kernels (`-O`) are enabled by default with `hashcat.optimized_kernels=true`. They are faster, but hashcat can reject some long or otherwise problematic candidate/hash combinations while optimized kernels are enabled. The scheduler therefore also defaults `hashcat.optimized_kernel_failover=true`: when an optimized-kernel-specific hashcat error is detected, the failed attempt is logged as invalid work, optimized kernels are disabled globally for the remainder of the run, and the same slice is retried once without `-O`.

Automatic failover also covers the hashcat parse pattern where optimized kernels are enabled, every hash is rejected, and no hashes are loaded, for example:

```text
* Token length exception: 22/22 hashes
  No hashes loaded.
```

If the unoptimized retry succeeds, treat the original failure as an optimized-kernel compatibility issue. If the unoptimized retry also reports `Token length exception: N/N hashes` with `No hashes loaded`, the scheduler records a hashfile/hash-mode/input-format error instead and does not retry again. Partial token-length summaries such as `Token length exception: 2/22 hashes` do not trigger global optimized-kernel failover by default because they usually indicate mixed or malformed input rows.

```json
{
  "hashcat": {
    "optimized_kernels": true,
    "optimized_kernel_failover": true
  }
}
```

Operators who prefer speed and accept that some arms or candidate sets may fail can keep optimized kernels enabled and disable automatic failover:

```json
{
  "hashcat": {
    "optimized_kernels": true,
    "optimized_kernel_failover": false
  }
}
```

Fully unoptimized operation disables `-O` from the start. In that mode the failover setting is effectively irrelevant because optimized kernels are already disabled:

```json
{
  "hashcat": {
    "optimized_kernels": false,
    "optimized_kernel_failover": true
  }
}
```

CLI precedence is: `--no-optimized-kernels` overrides `hashcat.optimized_kernels`, and `--optimized-kernel-failover` / `--no-optimized-kernel-failover` override `hashcat.optimized_kernel_failover`. Use `--no-optimized-kernels` to start without optimized kernels, `--optimized-kernel-failover` for the default automatic retry policy, and `--no-optimized-kernel-failover` to log optimized-kernel failures without retrying unoptimized.

## All-hashes-cracked stopping

By default, the scheduler stops when all non-empty target hashfile lines are represented by unique hash sides in the shared `run.pot`. Empty plaintext potfile entries count as cracked hashes. The final job that reaches full coverage is recorded in `jobs.jsonl`; no further warm-up, adaptive, forced-cadence, feedback, dictionary, brute-force, OSINT, or retry slices are scheduled afterward.

```json
{
  "stopping": {
    "stop_when_all_hashes_cracked": true
  }
}
```

Use `stopping.stop_when_all_hashes_cracked=false` or the CLI flag `--no-stop-when-all-hashes-cracked` only when intentionally preserving the old behavior. The positive CLI flag `--stop-when-all-hashes-cracked` restores the default.
