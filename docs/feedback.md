# Feedback arms

Feedback arms expand discoveries into new candidates, append accepted candidates to `queue.txt`, and run later slices from `slice_candidates.txt`. Normal code uses `enqueue_generated_candidates()`. Legacy queue APIs remain internal compatibility wrappers and are not the normal SQLite/none flow.

## Arm types

| Name | Type | Input |
| --- | --- | --- |
| `feedback/predictive-prefix` | `predictive_prefix` | User-supplied adjacent-label pair model. |
| `feedback/predictive-suffix` | `predictive_suffix` | User-supplied adjacent-label pair model. |
| `feedback/permutation-numeric` | `permutation` | Numeric/alpha variant rules. |
| `feedback/static-affix-top5000` | `static_affix_feedback` | User-supplied prefix/suffix source files. |
| `feedback/parent-domain` | `parent_domain_feedback` | Parent labels from cracked multi-label names. |

## Dedupe behavior

`sqlite` is the default generated-candidate ledger and avoids full text-ledger loads. `text` is legacy and uses `generated_candidates.txt`. `none` creates no persistent generated ledger; it still dedupes the current batch, `queue.txt`, active slice, and already-cracked candidates.

`queue.txt` remains a text queue. Slicing and membership checks load and rewrite it; large queues may need a SQLite queue in a later pass.

## Active slices

A feedback arm writes a runnable slice to `slice_candidates.txt` and records cursor metadata in `active_slice.json`. On resume, the arm continues the active slice before taking more from `queue.txt`. Completed slice files are removed by default unless `retain_completed_slices` is enabled.
