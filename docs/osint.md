# OSINT arms

OSINT arms collect names with an external tool, strip configured base-domain suffixes, normalize relative labels, and then run the resulting `candidates.txt` as a dictionary wordlist.

## Amass

`osint/amass` (`type: "amass_osint"`) starts one process for the configured comma-separated domains:

```sh
<amass_binary> enum -d example.nl,example.com
```

After the enum process exits successfully, results are collected with:

```sh
<amass_binary> subs -names -d example.nl,example.com
```

## Subfinder

`osint/subfinder` (`type: "subfinder_osint"`) starts one process for one domain:

```sh
<subfinder_binary> -silent -d example.nl
```

## State and completion

State lives under `osint/<safe-arm-name>/` and includes `state.json`, tool log, tool err, tool pid, `raw_names.txt`, and `candidates.txt`. OSINT arms do not write `generated_candidates.txt` by default.

When collection reaches a terminal state, the scheduler prints one completion line and writes one `osint_completed` event:

| Status | Meaning |
| --- | --- |
| `ready` | Candidates were written; with `run_immediately_when_ready=true`, the arm runs at the next adaptive slice. |
| `exhausted` | Collection succeeded but produced zero usable candidates. |
| `failed` | Tool execution or result collection failed. |

OSINT arms are delayed, not warm-up eligible, and completion events are not counted as slices. If a tool is still running when the slice budget ends, the scheduler may terminate it unless `keep_running_on_exit=true`.
