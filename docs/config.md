# Scheduler configuration

The canonical example config lives at the repository root as `example_config.json`. Copy it before editing:

```bash
cp example_config.json my_config.json
```

You do not need to enable every arm. Keep only the dictionary, brute-force, predictive, permutation, static-affix, or parent-domain arms that are useful for your run. Existing configs without a `warmup` block still default to `warmup.scoring = "arm_local"`; the other supported warm-up scoring mode is `"shared_marginal"`.

Feedback arms are not warm-up eligible, but they observe shared-new discoveries during warm-up and may enqueue candidates. Adaptive scoring always uses shared marginal discoveries, even when warm-up uses arm-local scoring.

Feedback runtime state is written under:

```text
<out_dir>/feedback/<arm>/
```

For example, feedback arms use `feedback/<arm>/queue.txt` and `feedback/<arm>/generated_candidates.txt`. The `generated_candidates.txt` file is a generated-candidate dedupe ledger; it is not tested, cracked, or validated history.

## Model-dependent feedback arms

This repository does not currently include model files under `models/`. Predictive feedback arms require trained adjacent-label pair models, and static-affix feedback arms require mined prefix/suffix files generated from your own data. The example config documents the available settings but keeps these model-dependent arms disabled by default; replace the `/path/to/...` placeholders before enabling them. Release packages may include real models later.

Use the provided predictive training command to create prefix/suffix pair TSV files from a potfile or cracked-name list. Static affix prefix/suffix files should be mined from your own corpus until packaged release models are available.

## Amass OSINT delayed dictionary arm

`type: "amass_osint"` adds a delayed external-source arm that behaves like a dictionary arm after its OSINT collection has finished. Amass is **not bundled** with this scheduler: install and configure Amass v5.1.1 or newer yourself, including all Amass data-source configuration. The scheduler does not configure Amass data sources.

Minimal disabled-by-default example:

```json
{
  "name": "amass-osint",
  "type": "amass_osint",
  "enabled": false,
  "amass_binary": "/home/vboxuser/go/bin/amass",
  "domains": "example.nl,example.com",
  "start_on_run_start": true,
  "poll_interval_seconds": 5,
  "run_immediately_when_ready": true,
  "include_single_label": true,
  "include_multi_label": true,
  "max_candidates": null,
  "dedupe": true,
  "min_slices_between_runs": 0
}
```

`domains` is required and may be a single string, a comma-separated string, or a JSON list. The scheduler normalizes it to `domains_list` and a comma-separated `domains_arg`; for example, `"example.nl, example.com"` becomes `domains_arg = "example.nl,example.com"`.

At scheduler startup, each enabled Amass OSINT arm starts exactly one background enum process:

```text
<amass_binary> enum -d <domains_arg>
```

For multiple domains, this remains one process and one comma-separated `-d` value, for example:

```text
/home/vboxuser/go/bin/amass enum -d example.nl,example.com
```

After that single enum process exits successfully, the scheduler fetches names with exactly one subs command using the same comma-separated domains argument:

```text
<amass_binary> subs -names -d <domains_arg>
```

For example:

```text
/home/vboxuser/go/bin/amass subs -names -d example.nl,example.com
```

The arm writes state under `<out_dir>/osint/<arm>/`, including `amass.log`, `amass.err`, `amass.pid`, `amass.status.json`, `raw_names.txt`, `candidates.txt`, `generated_candidates.txt`, and `state.json`. It does not write Amass state under `feedback/` and does not create per-domain process files.

Candidate conversion strips the matching configured base-domain suffix from each full name returned by Amass. For overlapping configured domains, the longest matching suffix wins. For example, with `example.nl` and `sub.example.nl`, `a.sub.example.nl` becomes `a`, not `a.sub`. Names equal to a base domain, outside configured domains, or invalid under the scheduler DNS candidate normalizer are rejected. `include_single_label` and `include_multi_label` control whether candidates such as `www` and `dev.api` are emitted. Duplicate relative candidates are deduped by default, including duplicates that came from different base domains.

The Amass OSINT arm is delayed and not warm-up eligible. While Amass is running, it is unavailable and consumes no scheduler slices. If Amass is still running when the slice budget ends, it may never be used in that scheduler run. When candidates are ready, the arm uses `<out_dir>/osint/<arm>/candidates.txt` as a normal hashcat dictionary wordlist with the shared potfile and normal dictionary progress accounting.

By default, `run_immediately_when_ready: true` sets `first_run_pending` as soon as candidates are written. During the adaptive phase, this makes the arm run at the next possible scheduler slice before forced cadence, epsilon exploration, or highest-score selection. After that first valid execution, normal scoring and cooldown rules apply. Set `run_immediately_when_ready: false` to disable this priority and let normal selection rules choose the arm.
