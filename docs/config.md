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
