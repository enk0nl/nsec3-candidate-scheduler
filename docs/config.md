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

## Subfinder OSINT arm (`subfinder_osint`)

`subfinder_osint` is a delayed external-source OSINT arm. It is not a feedback arm and is not warm-up eligible. When a scheduler run starts, the arm can start one Subfinder process in the background and allow the scheduler to continue running other arms while Subfinder is still collecting names.

Subfinder is **not bundled** with this scheduler. Install Subfinder separately and configure any providers or API keys in Subfinder itself; the scheduler does not manage Subfinder provider configuration. The scheduler starts Subfinder with only:

```sh
subfinder -silent -d <domain>
```

For example:

```json
{
  "name": "subfinder-osint",
  "type": "subfinder_osint",
  "enabled": false,
  "subfinder_binary": "/home/vboxuser/go/bin/subfinder",
  "domain": "example.nl",
  "start_on_run_start": true,
  "poll_interval_seconds": 5,
  "run_immediately_when_ready": true,
  "include_single_label": true,
  "include_multi_label": true,
  "max_candidates": null,
  "dedupe": true,
  "min_slices_between_runs": 0,
  "keep_running_on_exit": false
}
```

`domain` is required and must be a single non-empty base domain. Multi-domain Subfinder arms are not currently supported; define separate arms if needed.

Subfinder output is captured under the run OSINT state directory, for example:

```text
<out_dir>/osint/subfinder-osint/subfinder.log
<out_dir>/osint/subfinder-osint/subfinder.err
<out_dir>/osint/subfinder-osint/subfinder.pid
<out_dir>/osint/subfinder-osint/subfinder.status.json
<out_dir>/osint/subfinder-osint/raw_names.txt
<out_dir>/osint/subfinder-osint/candidates.txt
<out_dir>/osint/subfinder-osint/generated_candidates.txt
<out_dir>/osint/subfinder-osint/state.json
```

When Subfinder exits successfully, the scheduler reads the full names from `subfinder.log`, writes them to `raw_names.txt`, strips the configured base-domain suffix, and writes relative candidate labels to `candidates.txt`. For `domain: "example.nl"`, `sub.example.nl` becomes `sub`, `sub.sub.example.nl` becomes `sub.sub`, and the base domain itself (`example.nl`) is rejected because it would produce an empty candidate. Names outside the configured domain are rejected. The resulting relative candidates are normalized and validated with the same DNS candidate rules used by the OSINT helper path before hashcat sees them.

Candidate generation options:

* `include_single_label` controls candidates such as `sub`.
* `include_multi_label` controls candidates such as `sub.sub`.
* `dedupe` preserves first occurrence while removing duplicates.
* `max_candidates` optionally caps accepted candidates.

While Subfinder is running, the arm is unavailable and consumes no scheduler slice. Once candidates are ready, the arm behaves like a dictionary/wordlist arm over `<out_dir>/osint/<arm>/candidates.txt`, using the run hash mode, shared potfile, optimized-kernel setting, skip/progress accounting, runtime-limited slices, and normal shared marginal scoring.

By default, `run_immediately_when_ready: true` makes the arm run once at the next possible adaptive slice after it becomes ready. This immediate first run is prioritized before forced cadence, epsilon exploration, and highest-score selection. Set `run_immediately_when_ready: false` to disable that first-run priority and let normal selection rules apply. If Subfinder is still running when the configured slice budget ends, the generated wordlist may never be used in that scheduler run. On scheduler exit, a still-running Subfinder process is terminated unless `keep_running_on_exit: true` is set.
