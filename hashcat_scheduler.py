#!/usr/bin/env python3
"""Minimal adaptive hashcat scheduler for fixed runtime slice experiments.

Notes:
- This script uses one shared potfile per run to avoid double-counting cracks.
- PCFG candidate files should be pre-generated and configured as dictionary-style arms.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import math
import os
import random
import shlex
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


EXIT_MEANINGS = {
    0: "success",
    1: "exhausted",
    4: "runtime_reached",
}


@dataclasses.dataclass
class ArmState:
    name: str
    arm_type: str
    config: Dict[str, Any]
    next_skip: int = 0
    keyspace: Optional[int] = None
    exhausted: bool = False
    score: float = 0.0
    jobs_run: int = 0
    runtime: float = 0.0
    total_new_cracks: int = 0


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def count_lines(path: str) -> int:
    n = 0
    with open(path, "rb") as f:
        for _ in f:
            n += 1
    return n


def parse_hashcat_status_lines(output_text: str) -> List[Dict[str, Any]]:
    parsed: List[Dict[str, Any]] = []
    for raw_line in output_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            parsed.append(obj)
    return parsed


def parse_hashcat_summary_fields(status: Dict[str, Any]) -> Dict[str, Any]:
    progress_cur = None
    progress_end = None
    progress_percent = None
    progress_val = status.get("progress")
    if isinstance(progress_val, list) and len(progress_val) >= 2:
        progress_cur, progress_end = progress_val[0], progress_val[1]
    elif isinstance(progress_val, int):
        progress_cur = progress_val
    if isinstance(progress_cur, int) and isinstance(progress_end, int) and progress_end > 0:
        progress_percent = (progress_cur / progress_end) * 100.0

    restore_cur = None
    restore_total = None
    restore_val = status.get("restore_point")
    if isinstance(restore_val, list) and len(restore_val) >= 2:
        restore_cur, restore_total = restore_val[0], restore_val[1]
    elif isinstance(restore_val, int):
        restore_cur = restore_val

    speed_raw = status.get("speed_raw")
    speed_hps = speed_raw
    if isinstance(speed_raw, list) and speed_raw:
        speed_hps = speed_raw[0]
    elif not isinstance(speed_raw, (int, float)):
        speed_hps = None

    return {
        "hashcat_status": status.get("status"),
        "hashcat_status_text": status.get("status_text"),
        "hashcat_session": status.get("session"),
        "hashcat_guess_base": status.get("guess_base"),
        "hashcat_guess_base_count": status.get("guess_base_count"),
        "hashcat_guess_base_offset": status.get("guess_base_offset"),
        "hashcat_guess_mask_length": status.get("guess_mask_length"),
        "hashcat_progress_cur": progress_cur,
        "hashcat_progress_end": progress_end,
        "hashcat_progress_percent": progress_percent,
        "hashcat_restore_point": restore_cur,
        "hashcat_restore_total": restore_total,
        "hashcat_speed_raw": speed_raw,
        "hashcat_speed_hps": speed_hps,
        "hashcat_recovered_hashes_cur": status.get("recovered_hashes", [None, None])[0] if isinstance(status.get("recovered_hashes"), list) and status.get("recovered_hashes") else None,
        "hashcat_recovered_hashes_total": status.get("recovered_hashes", [None, None])[1] if isinstance(status.get("recovered_hashes"), list) and len(status.get("recovered_hashes")) > 1 else None,
        "hashcat_recovered_salts_cur": status.get("recovered_salts", [None, None])[0] if isinstance(status.get("recovered_salts"), list) and status.get("recovered_salts") else None,
        "hashcat_recovered_salts_total": status.get("recovered_salts", [None, None])[1] if isinstance(status.get("recovered_salts"), list) and len(status.get("recovered_salts")) > 1 else None,
        "hashcat_devices": status.get("devices"),
        "hashcat_runtime_start": status.get("time_start"),
        "hashcat_runtime_estimated_stop": status.get("estimated_stop"),
    }


def format_speed_hps(speed_hps: Any) -> str:
    if not isinstance(speed_hps, (int, float)):
        return "unknown"
    abs_speed = abs(speed_hps)
    if abs_speed >= 1_000_000_000:
        return f"{speed_hps / 1_000_000_000:.1f} GH/s"
    if abs_speed >= 1_000_000:
        return f"{speed_hps / 1_000_000:.1f} MH/s"
    if abs_speed >= 1_000:
        return f"{speed_hps / 1_000:.1f} KH/s"
    return f"{speed_hps:.1f} H/s"


def run_cmd(cmd: List[str], stdin_text: Optional[str] = None) -> Tuple[int, str, str]:
    p = subprocess.run(
        cmd,
        input=stdin_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return p.returncode, p.stdout, p.stderr


def parse_status_json(output: str) -> Dict[str, Any]:
    last: Dict[str, Any] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and "status" in obj:
                last = obj
    return last


def parse_hashcat_outfile(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if ":" not in line:
                continue
            h, v = line.split(":", 1)
            out[h] = v
    return out


def merge_potfile_entries(dest_path: str, source_path: str) -> Tuple[int, int]:
    """Merge source potfile entries into destination, deduplicated by hash."""
    dest_entries = parse_hashcat_outfile(dest_path)
    before = len(dest_entries)
    source_entries = parse_hashcat_outfile(source_path)
    dest_entries.update(source_entries)
    after = len(dest_entries)
    ensure_dir(os.path.dirname(dest_path))
    with open(dest_path, "w", encoding="utf-8") as f:
        for h, v in dest_entries.items():
            f.write(f"{h}:{v}\n")
    return len(source_entries), after - before


def compute_bruteforce_keyspace(arm: ArmState) -> int:
    cmd = ["hashcat", "--keyspace", "-a", "3", arm.config["mask"]]
    charset_keys = [("custom_charset1", "custom_charset_1"), ("custom_charset2", "custom_charset_2"), ("custom_charset3", "custom_charset_3"), ("custom_charset4", "custom_charset_4")]
    for legacy_key, underscored_key in charset_keys:
        cs_value = arm.config.get(underscored_key, arm.config.get(legacy_key))
        if cs_value is not None:
            idx = underscored_key[-1]
            cmd.extend([f"-{idx}", str(cs_value)])
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        raise RuntimeError(f"hashcat --keyspace failed for {arm.name}: rc={rc}, out={out[:300]}, err={err[:300]}")
    for tok in out.split():
        if tok.isdigit():
            return int(tok)
    raise RuntimeError(f"unable to parse keyspace for {arm.name}: {out[:400]}")


def choose_next_arm(
    states: List[ArmState],
    schedule: str,
    warmup_remaining: List[str],
    epsilon: float,
    rng: random.Random,
    sequential_remaining: Optional[Dict[str, int]] = None,
) -> Tuple[Optional[ArmState], str]:
    live = [a for a in states if not a.exhausted]
    if not live:
        return None, "none"
    if schedule == "sequential":
        if not sequential_remaining:
            return None, "none"
        for a in states:
            if sequential_remaining.get(a.name, 0) > 0:
                return a, "sequential_budget"
        return None, "none"
    if schedule == "round_robin":
        return sorted(live, key=lambda a: (a.jobs_run, states.index(a)))[0], "round_robin"
    # adaptive
    if warmup_remaining:
        remaining_set = set(warmup_remaining)
        for a in live:
            if a.name in remaining_set:
                warmup_remaining.remove(a.name)
                return a, "warmup"
    if rng.random() < epsilon:
        return rng.choice(live), "epsilon_exploration"
    return sorted(live, key=lambda a: (-a.score, a.jobs_run, a.runtime, a.name))[0], "highest_score"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hashes", required=True)
    ap.add_argument("--hash-mode", type=int, default=8300)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--slice-seconds", type=int, default=60)
    ap.add_argument("--schedule", choices=["sequential", "round_robin", "adaptive"], required=True)
    ap.add_argument("--total-slices", type=int)
    ap.add_argument("--total-seconds", type=int)
    ap.add_argument("--alpha", type=float)
    ap.add_argument("--epsilon", type=float)
    ap.add_argument("--random-seed", type=int)
    ap.add_argument("--default-limit", type=int, default=1000000)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not args.total_slices and not args.total_seconds:
        print("need --total-slices or --total-seconds", file=sys.stderr)
        return 2
    if args.total_slices and args.total_seconds:
        print("use only one of --total-slices or --total-seconds", file=sys.stderr)
        return 2

    ensure_dir(args.out_dir)
    potfile = os.path.join(args.out_dir, "run.pot")
    warmup_potfiles_dir = os.path.join(args.out_dir, "warmup_potfiles")
    hashcat_logs_dir = os.path.join(args.out_dir, "hashcat_logs")
    jobs_path = os.path.join(args.out_dir, "jobs.jsonl")
    hits_path = os.path.join(args.out_dir, "hits.jsonl")
    summary_path = os.path.join(args.out_dir, "run_summary.json")

    ensure_dir(hashcat_logs_dir)
    ensure_dir(warmup_potfiles_dir)
    for p in (potfile, jobs_path, hits_path):
        if os.path.exists(p):
            os.remove(p)

    cfg = read_json(args.config)
    alpha = args.alpha if args.alpha is not None else float(cfg.get("alpha", 0.2))
    epsilon = args.epsilon if args.epsilon is not None else float(cfg.get("epsilon", 0.1))
    random_seed = args.random_seed if args.random_seed is not None else int(cfg.get("random_seed", 0))
    rng = random.Random(random_seed)

    # Scheduler-level arm selection decisions are reproducible with the same seed and inputs.
    # Hashcat runtime-limited cracking throughput can still vary slightly due to hardware/runtime effects
    # (driver behavior, thermal throttling, OS scheduling, and timing jitter).
    arms_cfg = cfg.get("arms", [])
    if not arms_cfg:
        print("config has no arms", file=sys.stderr)
        return 2

    # "source" (e.g., "pcfg") is metadata only; scheduler behavior is determined by "type".
    # Pre-generated PCFG candidate files should use type="dictionary" and a wordlist path.
    states: List[ArmState] = [ArmState(name=a["name"], arm_type=a["type"], config=a) for a in arms_cfg]
    for st in states:
        if st.arm_type == "dictionary":
            st.keyspace = count_lines(st.config["wordlist"])
        elif st.arm_type == "brute_force":
            st.keyspace = compute_bruteforce_keyspace(st)
        else:
            print(f"unknown arm type in config: {st.arm_type}", file=sys.stderr)
            return 2

    warmup = [a.name for a in states if not a.exhausted]
    sequential_allocations: Dict[str, int] = {}
    sequential_remaining: Dict[str, int] = {}
    sequential_skipped_slices: Dict[str, int] = {}
    if args.schedule == "sequential":
        if not args.total_slices:
            print("sequential schedule requires --total-slices", file=sys.stderr)
            return 2
        arm_count = len(states)
        base = args.total_slices // arm_count
        remainder = args.total_slices % arm_count
        for idx, arm in enumerate(states):
            allocation = base + (1 if idx < remainder else 0)
            sequential_allocations[arm.name] = allocation
            sequential_remaining[arm.name] = allocation
            sequential_skipped_slices[arm.name] = 0

    start_ts = time.time()
    start_iso = utc_now()
    prev_hits = parse_hashcat_outfile(potfile)
    total_cracks = len(prev_hits)
    job_id = 0
    total_hashcat_status_events = 0

    while True:
        if args.total_slices and job_id >= args.total_slices:
            break
        if args.total_seconds and (time.time() - start_ts) >= args.total_seconds:
            break

        arm, selection_reason = choose_next_arm(
            states,
            args.schedule,
            warmup if args.schedule == "adaptive" else [],
            epsilon,
            rng,
            sequential_remaining if args.schedule == "sequential" else None,
        )
        if arm is None:
            break

        skip_before = arm.next_skip
        limit = args.default_limit
        if arm.keyspace is not None:
            remain = arm.keyspace - arm.next_skip
            if remain <= 0:
                arm.exhausted = True
                if args.schedule == "sequential" and sequential_remaining.get(arm.name, 0) > 0:
                    sequential_skipped_slices[arm.name] += sequential_remaining[arm.name]
                    sequential_remaining[arm.name] = 0
                continue
            limit = min(limit, remain)

        is_adaptive_warmup = args.schedule == "adaptive" and selection_reason == "warmup"
        phase = "warmup" if is_adaptive_warmup else "adaptive"
        arm_potfile = (
            os.path.join(warmup_potfiles_dir, f"{arm.name}.pot")
            if is_adaptive_warmup
            else potfile
        )
        potfile_scope = "arm_local" if is_adaptive_warmup else "shared"

        cmd = [
            "hashcat", "-m", str(args.hash_mode),
            "-a", "0" if arm.arm_type == "dictionary" else "3",
            "--runtime", str(args.slice_seconds),
            "--status", "--status-json", "--status-timer", "5",
            "--potfile-path", arm_potfile,
            args.hashes,
        ]

        if arm.arm_type == "dictionary":
            cmd.extend(["--skip", str(arm.next_skip), "--limit", str(limit), arm.config["wordlist"]])
        elif arm.arm_type == "brute_force":
            cmd.extend(["--skip", str(arm.next_skip), "--limit", str(limit)])
            charset_keys = [("custom_charset1", "custom_charset_1"), ("custom_charset2", "custom_charset_2"), ("custom_charset3", "custom_charset_3"), ("custom_charset4", "custom_charset_4")]
            for legacy_key, underscored_key in charset_keys:
                cs_value = arm.config.get(underscored_key, arm.config.get(legacy_key))
                if cs_value is not None:
                    idx = underscored_key[-1]
                    cmd.extend([f"-{idx}", str(cs_value)])
            cmd.append(arm.config["mask"])
        else:
            print(f"unknown arm type: {arm.arm_type}", file=sys.stderr)
            arm.exhausted = True
            continue

        cmd_text = " ".join(shlex.quote(tok) for tok in cmd)
        if args.verbose:
            print(f"[job {job_id + 1}] command: {cmd_text}")
        score_before = arm.score
        t0 = time.time()
        rc, stdout_text, stderr_text = run_cmd(cmd)
        runtime_seconds = max(0.0, time.time() - t0)
        status_events = parse_hashcat_status_lines(stdout_text + "\n" + stderr_text)
        total_hashcat_status_events += len(status_events)
        status = status_events[-1] if status_events else {}
        hashcat_fields = parse_hashcat_summary_fields(status)

        arm_after_hits = parse_hashcat_outfile(arm_potfile)
        arm_local_cracks = len(arm_after_hits)
        marginal_new_cracks = 0
        new_pairs: List[Tuple[str, str]] = []
        if is_adaptive_warmup:
            _, merged_new = merge_potfile_entries(potfile, arm_potfile)
            marginal_new_cracks = merged_new
            total_cracks = len(parse_hashcat_outfile(potfile))
            prev_hits = parse_hashcat_outfile(potfile)
        else:
            after_hits = parse_hashcat_outfile(potfile)
            new_pairs = [(h, v) for h, v in after_hits.items() if h not in prev_hits]
            prev_hits = after_hits
            marginal_new_cracks = len(new_pairs)
            total_cracks = len(after_hits)

        parsed_restore = hashcat_fields["hashcat_restore_point"]
        parsed_progress_cur = hashcat_fields["hashcat_progress_cur"] if isinstance(hashcat_fields["hashcat_progress_cur"], int) else None
        parsed_progress_total = hashcat_fields["hashcat_progress_end"] if isinstance(hashcat_fields["hashcat_progress_end"], int) else None

        progress_source = "unknown"
        next_skip = arm.next_skip
        effective_limit = int(limit)
        if arm.arm_type == "dictionary":
            if isinstance(parsed_restore, int):
                next_skip = max(next_skip, parsed_restore)
                progress_source = "restore_point"
            else:
                # Conservative fallback: advance by planned limit if no better parser signal exists.
                next_skip = arm.next_skip + effective_limit
                progress_source = "limit"
        elif arm.arm_type == "brute_force":
            if isinstance(parsed_restore, int) and parsed_restore > 0:
                next_skip = max(next_skip, parsed_restore)
                progress_source = "restore_point"
            elif (
                isinstance(parsed_progress_cur, int) and parsed_progress_cur > 0
                and isinstance(parsed_progress_total, int) and parsed_progress_total > 0
                and isinstance(arm.keyspace, int) and arm.keyspace > 0
            ):
                scaled_advance = math.floor((parsed_progress_cur / parsed_progress_total) * arm.keyspace)
                advance = min(scaled_advance, effective_limit)
                next_skip = min(arm.next_skip + advance, arm.keyspace)
                progress_source = "progress_scaled_to_keyspace"
            elif rc == 1:
                next_skip = arm.next_skip + effective_limit
                progress_source = "limit_fallback_exhausted"
            else:
                progress_source = "unknown"
        else:
            if isinstance(parsed_restore, int):
                next_skip = max(next_skip, parsed_restore)
                progress_source = "restore_point"

        arm.next_skip = next_skip
        if arm.keyspace is not None and arm.next_skip >= arm.keyspace:
            arm.exhausted = True
        if rc == 1:
            arm.exhausted = True

        if is_adaptive_warmup:
            reward_used_for_score = (arm_local_cracks / runtime_seconds) if runtime_seconds > 0 else 0.0
        else:
            reward_used_for_score = (marginal_new_cracks / runtime_seconds) if runtime_seconds > 0 else 0.0
        reward = reward_used_for_score
        arm.score = arm.score + alpha * (reward - arm.score)
        arm.jobs_run += 1
        arm.runtime += runtime_seconds
        arm.total_new_cracks += marginal_new_cracks
        if args.schedule == "sequential":
            if sequential_remaining.get(arm.name, 0) > 0:
                sequential_remaining[arm.name] -= 1
            if arm.exhausted and sequential_remaining.get(arm.name, 0) > 0:
                sequential_skipped_slices[arm.name] += sequential_remaining[arm.name]
                sequential_remaining[arm.name] = 0

        job_id += 1
        exit_meaning = EXIT_MEANINGS.get(rc, "error")

        rec = {
            "timestamp": utc_now(),
            "job_id": job_id,
            "schedule": args.schedule,
            "random_seed": random_seed,
            "selection_reason": selection_reason,
            "phase": phase,
            "potfile_scope": potfile_scope,
            "arm": arm.name,
            "attack_type": arm.arm_type,
            "hash_mode": args.hash_mode,
            "skip_before": skip_before,
            "limit": int(limit),
            "effective_limit": effective_limit,
            "next_skip_after": arm.next_skip,
            "keyspace": arm.keyspace,
            "runtime_seconds": runtime_seconds,
            "exit_code": rc,
            "exit_meaning": exit_meaning,
            "progress_source": progress_source,
            "parsed_progress_cur": parsed_progress_cur,
            "parsed_progress_total": parsed_progress_total,
            "parsed_restore_point": parsed_restore,
            "new_cracks": marginal_new_cracks,
            "arm_local_cracks": arm_local_cracks,
            "marginal_new_cracks": marginal_new_cracks,
            "reward_used_for_score": reward_used_for_score,
            "total_cracks": total_cracks,
            "reward": reward,
            "score_before": score_before,
            "score_after": arm.score,
            "exhausted": arm.exhausted,
        }
        rec.update(hashcat_fields)
        with open(jobs_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

        log_path = os.path.join(hashcat_logs_dir, f"job_{job_id:06d}.log")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"timestamp: {utc_now()}\n")
            f.write(f"job_id: {job_id}\n")
            f.write(f"arm: {arm.name}\n")
            f.write(f"attack_type: {arm.arm_type}\n")
            f.write(f"command: {cmd_text}\n")
            f.write(f"exit_code: {rc}\n")
            f.write("stdout:\n")
            f.write(stdout_text)
            f.write("\nstderr:\n")
            f.write(stderr_text)
            f.write("\nparsed_status_json_objects:\n")
            for obj in status_events:
                f.write(json.dumps(obj, sort_keys=True) + "\n")

        with open(hits_path, "a", encoding="utf-8") as f:
            for h, v in new_pairs:
                f.write(json.dumps({"timestamp": utc_now(), "job_id": job_id, "arm": arm.name, "hash": h, "value": v}) + "\n")

        progress_cur = hashcat_fields["hashcat_progress_cur"] if hashcat_fields["hashcat_progress_cur"] is not None else "unknown"
        progress_end = hashcat_fields["hashcat_progress_end"] if hashcat_fields["hashcat_progress_end"] is not None else "unknown"
        status_text = hashcat_fields["hashcat_status_text"] or hashcat_fields["hashcat_status"] or "unknown"
        print(f"[job {job_id}] {args.schedule} / selected {selection_reason}")
        if is_adaptive_warmup:
            print("  phase: warm-up (score based on arm-local cracks)")
        else:
            print("  phase: adaptive (score based on marginal new cracks)")
        print(f"  arm: {arm.name} ({arm.arm_type})")
        print(f"  skip: {skip_before} -> {arm.next_skip} / keyspace={arm.keyspace if arm.keyspace is not None else 'unknown'}")
        print(f"  runtime: {runtime_seconds:.1f}s, exit={rc} {exit_meaning}")
        print(f"  cracks: arm_local={arm_local_cracks}, marginal_new={marginal_new_cracks}, total={total_cracks}, reward={reward:.3f}/s")
        print(f"  score: {score_before:.3f} -> {arm.score:.3f}")
        print(f"  hashcat: status={status_text}, progress={progress_cur}/{progress_end}, speed={format_speed_hps(hashcat_fields['hashcat_speed_hps'])}")
        if args.verbose:
            print(f"  hashcat status events parsed: {len(status_events)}")
            if status_events:
                print(f"  last status json: {json.dumps(status_events[-1], sort_keys=True)}")

        if rc not in (0, 1, 4):
            print(f"warning: arm={arm.name} rc={rc}, continuing", file=sys.stderr)

        if all(a.exhausted for a in states):
            break

    end_iso = utc_now()
    total_runtime = time.time() - start_ts
    summary = {
        "config": cfg,
        "random_seed": random_seed,
        "start_timestamp": start_iso,
        "end_timestamp": end_iso,
        "total_runtime_seconds": total_runtime,
        "total_slices": job_id,
        "total_cracks": total_cracks,
        "hashcat_logs_dir": hashcat_logs_dir,
        "potfile_path": potfile,
        "total_hashcat_status_events": total_hashcat_status_events,
        "sequential_allocations": sequential_allocations if args.schedule == "sequential" else None,
        "sequential_skipped_slices": sequential_skipped_slices if args.schedule == "sequential" else None,
        "arms": {
            a.name: {
                "score": a.score,
                "jobs_run": a.jobs_run,
                "runtime": a.runtime,
                "next_skip": a.next_skip,
                "keyspace": a.keyspace,
                "exhausted": a.exhausted,
                "total_new_cracks": a.total_new_cracks,
                "speed_hps_estimate": (a.total_new_cracks / a.runtime) if a.runtime > 0 else None,
            }
            for a in states
        },
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
