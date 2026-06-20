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
from typing import Any, Dict, Iterable, List, Optional, Tuple


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
    masks: List[str] = dataclasses.field(default_factory=list)
    current_mask_index: int = 0
    mask_keyspaces: Dict[str, int] = dataclasses.field(default_factory=dict)
    mask_next_skip: Dict[str, int] = dataclasses.field(default_factory=dict)
    mask_exhausted: Dict[str, bool] = dataclasses.field(default_factory=dict)
    last_run_adaptive_slice: int = 0


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
    progress_val = status.get("progress")
    if isinstance(progress_val, list) and len(progress_val) >= 2:
        progress_cur, progress_end = progress_val[0], progress_val[1]
    elif isinstance(progress_val, int):
        progress_cur = progress_val

    restore_cur = None
    restore_val = status.get("restore_point")
    if isinstance(restore_val, list) and restore_val:
        restore_cur = restore_val[0]
    elif isinstance(restore_val, int):
        restore_cur = restore_val

    speed_raw = status.get("speed_raw")
    speed_hps = speed_raw
    if isinstance(speed_raw, list) and speed_raw:
        speed_hps = speed_raw[0]
    elif not isinstance(speed_raw, (int, float)):
        speed_hps = None

    recovered_hashes = status.get("recovered_hashes")
    recovered_salts = status.get("recovered_salts")
    return {
        "hashcat_status": status.get("status"),
        "hashcat_progress_cur": progress_cur,
        "hashcat_progress_end": progress_end,
        "hashcat_restore_point": restore_cur,
        "hashcat_speed_hps": speed_hps,
        "hashcat_recovered_hashes_cur": recovered_hashes[0] if isinstance(recovered_hashes, list) and recovered_hashes else None,
        "hashcat_recovered_hashes_total": recovered_hashes[1] if isinstance(recovered_hashes, list) and len(recovered_hashes) > 1 else None,
        "hashcat_recovered_salts_total": recovered_salts[1] if isinstance(recovered_salts, list) and len(recovered_salts) > 1 else None,
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


def parse_hashcat_outfile(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if ":" not in line:
                continue
            h, v = line.rsplit(":", 1)
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



def normalize_dns_name(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if not normalized or normalized.startswith(".") or normalized.endswith("."):
        return None
    if any(ch.isspace() for ch in normalized):
        return None
    if len(normalized) > 253:
        return None
    parts = normalized.split(".")
    if any(part == "" or len(part) > 63 for part in parts):
        return None
    return normalized

def load_set(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    values: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            value = line.rstrip("\n")
            if value:
                values.add(value)
    return values


def append_lines(path: str, lines: Iterable[str]) -> None:
    items = list(lines)
    if not items:
        return
    ensure_dir(os.path.dirname(path))
    with open(path, "a", encoding="utf-8") as f:
        for line in items:
            f.write(f"{line}\n")


def validate_feedback_config(arm_config: Dict[str, Any]) -> Dict[str, Any]:
    labels = arm_config.get("common_labels")
    if not isinstance(labels, list) or not labels:
        raise ValueError(f"feedback arm {arm_config.get('name', '<unnamed>')} common_labels must be a non-empty list of strings")
    normalized_labels: List[str] = []
    for raw_label in labels:
        normalized = normalize_dns_name(raw_label)
        if normalized is None:
            raise ValueError(f"feedback arm {arm_config.get('name', '<unnamed>')} common_labels must contain only non-empty DNS name strings without empty dot components")
        normalized_labels.append(normalized)
    enabled = arm_config.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError(f"feedback arm {arm_config.get('name', '<unnamed>')} enabled must be a boolean when provided")
    validated = dict(arm_config)
    validated["common_labels"] = normalized_labels
    validated["enabled"] = enabled
    return validated


def feedback_paths(out_dir: str) -> Dict[str, str]:
    return {
        "queue": os.path.join(out_dir, "feedback_queue.txt"),
        "seen": os.path.join(out_dir, "feedback_seen_candidates.txt"),
        "expanded": os.path.join(out_dir, "feedback_expanded_bases.txt"),
        "slice": os.path.join(out_dir, "feedback_slice_candidates.txt"),
    }


def feedback_queue_has_items(path: str) -> bool:
    if not os.path.exists(path):
        return False
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return any(line.strip() for line in f)


def expand_feedback_from_discoveries(new_discoveries: Iterable[str], feedback_config: Dict[str, Any], out_dir: str) -> Dict[str, int]:
    paths = feedback_paths(out_dir)
    queue_before = count_lines(paths["queue"]) if os.path.exists(paths["queue"]) else 0
    seen = load_set(paths["seen"])
    expanded = load_set(paths["expanded"])
    bases_to_append: List[str] = []
    candidates_to_append: List[str] = []
    rejected_bases = 0
    generated = 0
    duplicates = 0
    bases_expanded = 0
    for raw in new_discoveries:
        base = normalize_dns_name(raw)
        if base is None or base in expanded:
            rejected_bases += 1
            continue
        bases_expanded += 1
        bases_to_append.append(base)
        expanded.add(base)
        for label in feedback_config["common_labels"]:
            for candidate in (f"{base}.{label}", f"{label}.{base}"):
                generated += 1
                if candidate in seen:
                    duplicates += 1
                    continue
                seen.add(candidate)
                candidates_to_append.append(candidate)
    append_lines(paths["queue"], candidates_to_append)
    append_lines(paths["seen"], candidates_to_append)
    append_lines(paths["expanded"], bases_to_append)
    return {
        "feedback_bases_expanded": bases_expanded,
        "feedback_generated_candidates": generated,
        "feedback_duplicates_skipped": duplicates,
        "feedback_rejected_bases": rejected_bases,
        "feedback_queue_size_before": queue_before,
        "feedback_candidates_enqueued": len(candidates_to_append),
        "feedback_queue_size_after": queue_before + len(candidates_to_append),
    }


def run_feedback_slice(out_dir: str) -> Tuple[str, int, int]:
    paths = feedback_paths(out_dir)
    queued: List[str] = []
    if os.path.exists(paths["queue"]):
        with open(paths["queue"], "r", encoding="utf-8", errors="replace") as f:
            queued = [line.strip() for line in f if line.strip()]
    with open(paths["slice"], "w", encoding="utf-8") as f:
        for candidate in queued:
            f.write(f"{candidate}\n")
    open(paths["queue"], "w", encoding="utf-8").close()
    return paths["slice"], len(queued), 0

def build_charset_args(arm: ArmState) -> List[str]:
    args: List[str] = []
    charset_keys = [("custom_charset1", "custom_charset_1"), ("custom_charset2", "custom_charset_2"), ("custom_charset3", "custom_charset_3"), ("custom_charset4", "custom_charset_4")]
    for legacy_key, underscored_key in charset_keys:
        cs_value = arm.config.get(underscored_key, arm.config.get(legacy_key))
        if cs_value is not None:
            idx = underscored_key[-1]
            args.extend([f"-{idx}", str(cs_value)])
    return args


def current_mask(arm: ArmState) -> Optional[str]:
    if 0 <= arm.current_mask_index < len(arm.masks):
        return arm.masks[arm.current_mask_index]
    return None


def current_mask_keyspace(arm: ArmState) -> Optional[int]:
    mask = current_mask(arm)
    return arm.mask_keyspaces.get(mask) if mask is not None else None


def current_mask_next_skip(arm: ArmState) -> int:
    mask = current_mask(arm)
    return arm.mask_next_skip.get(mask, 0) if mask is not None else 0


def advance_to_next_unexhausted_mask(arm: ArmState) -> bool:
    for idx, mask in enumerate(arm.masks):
        if not arm.mask_exhausted.get(mask, False):
            arm.current_mask_index = idx
            return True
    arm.current_mask_index = len(arm.masks)
    return False


def brute_force_arm_exhausted(arm: ArmState) -> bool:
    return all(arm.mask_exhausted.get(mask, False) for mask in arm.masks)


def compute_bruteforce_keyspace(arm: ArmState, mask: str) -> int:
    cmd = ["hashcat", "--keyspace", "-a", "3"]
    cmd.extend(build_charset_args(arm))
    cmd.append(mask)
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
    out_dir: Optional[str] = None,
    current_adaptive_slice: int = 0,
) -> Tuple[Optional[ArmState], str]:
    def eligible(arm: ArmState) -> bool:
        if arm.exhausted:
            return False
        if arm.arm_type == "feedback":
            if out_dir is None:
                return False
            return feedback_queue_has_items(feedback_paths(out_dir)["queue"])
        if arm.arm_type == "brute_force":
            mask = current_mask(arm)
            if mask is None:
                return False
            keyspace = arm.mask_keyspaces.get(mask)
            if keyspace is not None and arm.mask_next_skip.get(mask, 0) >= keyspace:
                return False
            return True
        if arm.keyspace is not None and arm.next_skip >= arm.keyspace:
            return False
        return True

    live = [a for a in states if eligible(a)]
    if not live:
        return None, "none"
    if schedule == "sequential":
        if not sequential_remaining:
            return None, "none"
        for a in states:
            if sequential_remaining.get(a.name, 0) > 0 and eligible(a):
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
    due_arms: List[Tuple[float, int, float, str, ArmState]] = []
    for a in live:
        interval = a.config.get("force_every_slices")
        if interval is None:
            continue
        slices_since = current_adaptive_slice - a.last_run_adaptive_slice
        if slices_since >= interval:
            overdue_ratio = slices_since / interval
            due_arms.append((overdue_ratio, a.jobs_run, a.runtime, a.name, a))
    if due_arms:
        return sorted(due_arms, key=lambda item: (-item[0], item[1], item[2], item[3]))[0][4], "forced_cadence"
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
    ap.add_argument("--verbose-debug", action="store_true", help="print raw hashcat status JSON and per-slice debug samples")
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
    dictionary_candidate_limit = cfg.get("dictionary_candidate_limit")
    if dictionary_candidate_limit is not None and (isinstance(dictionary_candidate_limit, bool) or not isinstance(dictionary_candidate_limit, int) or dictionary_candidate_limit <= 0):
        print("dictionary_candidate_limit must be a positive integer or null when provided", file=sys.stderr)
        return 2
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
    enabled_feedback_arms: List[Dict[str, Any]] = []
    normalized_arms_cfg: List[Dict[str, Any]] = []
    try:
        for arm_cfg in arms_cfg:
            force_every_slices = arm_cfg.get("force_every_slices")
            if force_every_slices is not None and (isinstance(force_every_slices, bool) or not isinstance(force_every_slices, int) or force_every_slices <= 0):
                raise ValueError(f"arm {arm_cfg.get('name', '<unnamed>')} force_every_slices must be a positive integer when provided")
            if arm_cfg.get("type") == "feedback":
                validated_feedback = validate_feedback_config(arm_cfg)
                if validated_feedback.get("enabled", True):
                    enabled_feedback_arms.append(validated_feedback)
                    normalized_arms_cfg.append(validated_feedback)
                continue
            normalized_arms_cfg.append(arm_cfg)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if len(enabled_feedback_arms) > 1:
        print("multiple enabled feedback arms are not supported; configure at most one enabled type=feedback arm", file=sys.stderr)
        return 2

    states: List[ArmState] = [ArmState(name=a["name"], arm_type=a["type"], config=a) for a in normalized_arms_cfg]
    feedback_config = enabled_feedback_arms[0] if enabled_feedback_arms else None
    for feedback_path in feedback_paths(args.out_dir).values():
        if feedback_config is not None and not os.path.exists(feedback_path):
            open(feedback_path, "w", encoding="utf-8").close()
    for st in states:
        if st.arm_type == "dictionary":
            st.keyspace = count_lines(st.config["wordlist"])
        elif st.arm_type == "feedback":
            st.keyspace = None
        elif st.arm_type == "brute_force":
            has_mask = "mask" in st.config
            has_masks = "masks" in st.config
            if has_mask and has_masks:
                print(f"brute_force arm {st.name} cannot define both mask and masks", file=sys.stderr)
                return 2
            if has_masks:
                if not isinstance(st.config["masks"], list) or not st.config["masks"] or not all(isinstance(m, str) and m for m in st.config["masks"]):
                    print(f"brute_force arm {st.name} masks must be a non-empty list of strings", file=sys.stderr)
                    return 2
                st.masks = list(st.config["masks"])
            elif has_mask and isinstance(st.config["mask"], str) and st.config["mask"]:
                st.masks = [st.config["mask"]]
            else:
                print(f"brute_force arm {st.name} must define mask or masks", file=sys.stderr)
                return 2
            for mask in st.masks:
                ks = compute_bruteforce_keyspace(st, mask)
                st.mask_keyspaces[mask] = ks
                st.mask_next_skip[mask] = 0
                st.mask_exhausted[mask] = False
            advance_to_next_unexhausted_mask(st)
            st.keyspace = sum(st.mask_keyspaces.values())
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
    current_adaptive_slice = 0

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
            args.out_dir,
            current_adaptive_slice,
        )
        if arm is None:
            break

        selection_adaptive_slice = current_adaptive_slice
        force_interval = arm.config.get("force_every_slices")
        slices_since_last_run = (selection_adaptive_slice - arm.last_run_adaptive_slice) if force_interval is not None else None
        overdue_ratio = (slices_since_last_run / force_interval) if force_interval is not None and slices_since_last_run is not None else None
        forced_cadence_due = selection_reason == "forced_cadence"

        active_mask = current_mask(arm) if arm.arm_type == "brute_force" else None
        if arm.arm_type == "brute_force" and active_mask is None:
            arm.exhausted = True
            continue
        skip_before = current_mask_next_skip(arm) if arm.arm_type == "brute_force" else arm.next_skip
        limit = args.default_limit
        keyspace_for_job = current_mask_keyspace(arm) if arm.arm_type == "brute_force" else arm.keyspace
        if keyspace_for_job is not None:
            remain = keyspace_for_job - skip_before
            if remain <= 0:
                if arm.arm_type == "brute_force" and active_mask is not None:
                    arm.mask_exhausted[active_mask] = True
                    if not advance_to_next_unexhausted_mask(arm):
                        arm.exhausted = True
                else:
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
        feedback_slice_candidates = None
        feedback_queue_size_before = None
        feedback_candidates_written = None
        feedback_queue_size_after = None
        if arm.arm_type == "feedback":
            feedback_slice_candidates, feedback_candidates_written, feedback_queue_size_after = run_feedback_slice(args.out_dir)
            feedback_queue_size_before = feedback_candidates_written
            limit = feedback_candidates_written
            effective_limit = feedback_candidates_written

        cmd = [
            "hashcat", "-m", str(args.hash_mode),
            "-a", "3" if arm.arm_type == "brute_force" else "0",
            "--runtime", str(args.slice_seconds),
            "--status", "--status-json", "--status-timer", "5",
            "--potfile-path", arm_potfile,
            args.hashes,
        ]

        if arm.arm_type == "dictionary":
            cmd.extend(["--skip", str(arm.next_skip)])
            if dictionary_candidate_limit is not None:
                cmd.extend(["--limit", str(dictionary_candidate_limit)])
            cmd.append(arm.config["wordlist"])
        elif arm.arm_type == "feedback":
            if feedback_slice_candidates is None:
                print(f"feedback arm {arm.name} has no slice candidate file", file=sys.stderr)
                continue
            cmd.extend([feedback_slice_candidates])
        elif arm.arm_type == "brute_force":
            cmd.extend(["--skip", str(skip_before), "--limit", str(limit)])
            cmd.extend(build_charset_args(arm))
            cmd.append(active_mask)
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
            before_shared_hits = parse_hashcat_outfile(potfile)
            arm_new_pairs = [(h, v) for h, v in arm_after_hits.items() if h not in before_shared_hits]
            _, merged_new = merge_potfile_entries(potfile, arm_potfile)
            marginal_new_cracks = merged_new
            new_pairs = arm_new_pairs
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
        parsed_recovered_salts_total = hashcat_fields["hashcat_recovered_salts_total"] if isinstance(hashcat_fields["hashcat_recovered_salts_total"], int) else None

        progress_source = "unknown"
        dictionary_candidate_cursor = None
        next_skip = arm.next_skip
        effective_limit = int(limit)
        if arm.arm_type == "dictionary":
            if isinstance(parsed_progress_cur, int) and isinstance(parsed_recovered_salts_total, int) and parsed_recovered_salts_total > 0:
                dictionary_candidate_cursor = math.floor(parsed_progress_cur / parsed_recovered_salts_total)
            if isinstance(dictionary_candidate_cursor, int) and dictionary_candidate_cursor > skip_before:
                next_skip = dictionary_candidate_cursor
                if keyspace_for_job is not None:
                    next_skip = min(next_skip, keyspace_for_job)
                progress_source = "progress_scaled_by_salts"
            else:
                next_skip = skip_before
                progress_source = "unknown"
        elif arm.arm_type == "brute_force":
            if isinstance(parsed_restore, int) and parsed_restore > skip_before:
                next_skip = min(parsed_restore, keyspace_for_job)
                progress_source = "restore_point"
            elif (
                isinstance(parsed_progress_cur, int) and parsed_progress_cur > 0
                and isinstance(parsed_progress_total, int) and parsed_progress_total > 0
                and isinstance(keyspace_for_job, int) and keyspace_for_job > 0
            ):
                brute_force_progress_end = min(skip_before + effective_limit, keyspace_for_job)
                brute_force_progress_position = math.floor(
                    (parsed_progress_cur / parsed_progress_total) * brute_force_progress_end
                )
                next_skip = max(skip_before, brute_force_progress_position)
                next_skip = min(next_skip, keyspace_for_job)
                progress_source = "progress_scaled_to_slice_end"
            elif rc == 1:
                next_skip = min(skip_before + effective_limit, keyspace_for_job)
                progress_source = "limit_fallback"
            else:
                progress_source = "unknown"
        else:
            if isinstance(parsed_restore, int):
                next_skip = max(next_skip, parsed_restore)
                progress_source = "restore_point"

        if arm.arm_type == "brute_force" and active_mask is not None:
            arm.mask_next_skip[active_mask] = next_skip
            if keyspace_for_job is not None and next_skip >= keyspace_for_job:
                arm.mask_exhausted[active_mask] = True
            if rc == 1:
                arm.mask_exhausted[active_mask] = True
            if arm.mask_exhausted[active_mask]:
                advance_to_next_unexhausted_mask(arm)
            arm.exhausted = brute_force_arm_exhausted(arm)
        else:
            arm.next_skip = next_skip
            if arm.arm_type != "feedback":
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
        if args.schedule == "adaptive" and not is_adaptive_warmup:
            if rc in EXIT_MEANINGS:
                arm.last_run_adaptive_slice = current_adaptive_slice
            current_adaptive_slice += 1

        feedback_expansion = {
            "feedback_bases_expanded": 0,
            "feedback_generated_candidates": 0,
            "feedback_duplicates_skipped": 0,
            "feedback_rejected_bases": 0,
            "feedback_queue_size_before": None,
            "feedback_candidates_enqueued": 0,
            "feedback_queue_size_after": None,
        }
        if feedback_config is not None and new_pairs:
            feedback_expansion = expand_feedback_from_discoveries((v for _, v in new_pairs), feedback_config, args.out_dir)

        job_id += 1
        exit_meaning = EXIT_MEANINGS.get(rc, "error")

        rec = {
            "timestamp": utc_now(),
            "job_id": job_id,
            "schedule": args.schedule,
            "random_seed": random_seed,
            "selection_reason": selection_reason,
            "forced_cadence_due": forced_cadence_due,
            "forced_cadence_interval": force_interval,
            "slices_since_last_run": slices_since_last_run,
            "overdue_ratio": overdue_ratio,
            "current_adaptive_slice": selection_adaptive_slice,
            "phase": phase,
            "potfile_scope": potfile_scope,
            "arm": arm.name,
            "attack_type": arm.arm_type,
            "hash_mode": args.hash_mode,
            "skip_before": skip_before,
            "limit": int(limit),
            "effective_limit": effective_limit,
            "next_skip_after": arm.mask_next_skip.get(active_mask) if arm.arm_type == "brute_force" else arm.next_skip,
            "keyspace": keyspace_for_job,
            "runtime_seconds": runtime_seconds,
            "exit_code": rc,
            "exit_meaning": exit_meaning,
            "progress_source": progress_source,
            "parsed_progress_cur": parsed_progress_cur,
            "parsed_progress_total": parsed_progress_total,
            "parsed_restore_point": parsed_restore,
            "parsed_recovered_salts_total": parsed_recovered_salts_total,
            "dictionary_candidate_cursor": dictionary_candidate_cursor,
            "dictionary_candidate_limit": dictionary_candidate_limit,
            "new_cracks": marginal_new_cracks,
            "arm_local_cracks": arm_local_cracks,
            "marginal_new_cracks": marginal_new_cracks,
            "reward_used_for_score": reward_used_for_score,
            "total_cracks": total_cracks,
            "reward": reward,
            "score_before": score_before,
            "score_after": arm.score,
            "exhausted": arm.exhausted,
            "feedback_slice_candidates": feedback_slice_candidates,
            "feedback_queue_size_before_slice": feedback_queue_size_before,
            "feedback_candidates_written_to_slice": feedback_candidates_written,
            "feedback_queue_size_after_slice": feedback_queue_size_after,
            **feedback_expansion,
        }
        if arm.arm_type == "brute_force" and active_mask is not None:
            rec.update({
                "brute_force_mask": active_mask,
                "brute_force_mask_index": arm.masks.index(active_mask),
                "brute_force_masks_total": len(arm.masks),
                "brute_force_mask_keyspace": keyspace_for_job,
                "brute_force_mask_skip_before": skip_before,
                "brute_force_mask_next_skip_after": arm.mask_next_skip.get(active_mask),
                "brute_force_mask_exhausted": arm.mask_exhausted.get(active_mask, False),
            })
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
            if arm.arm_type == "feedback":
                f.write(f"feedback_queue_size_before: {feedback_queue_size_before}\n")
                f.write(f"feedback_candidates_written_to_slice: {feedback_candidates_written}\n")
                f.write(f"feedback_queue_size_after: {feedback_queue_size_after}\n")
            if feedback_config is not None:
                f.write(f"feedback_bases_expanded: {feedback_expansion['feedback_bases_expanded']}\n")
                f.write(f"feedback_generated_candidates: {feedback_expansion['feedback_generated_candidates']}\n")
                f.write(f"feedback_duplicates_skipped: {feedback_expansion['feedback_duplicates_skipped']}\n")
                f.write(f"feedback_rejected_bases: {feedback_expansion['feedback_rejected_bases']}\n")
            f.write("stdout:\n")
            f.write(stdout_text)
            f.write("\nstderr:\n")
            f.write(stderr_text)
            if args.verbose_debug:
                f.write("\nparsed_status_json_objects:\n")
                for obj in status_events:
                    f.write(json.dumps(obj, sort_keys=True) + "\n")

        with open(hits_path, "a", encoding="utf-8") as f:
            for h, v in new_pairs:
                f.write(json.dumps({"timestamp": utc_now(), "job_id": job_id, "arm": arm.name, "hash": h, "value": v}) + "\n")

        progress_cur = hashcat_fields["hashcat_progress_cur"] if hashcat_fields["hashcat_progress_cur"] is not None else "unknown"
        progress_end = hashcat_fields["hashcat_progress_end"] if hashcat_fields["hashcat_progress_end"] is not None else "unknown"
        status_text = hashcat_fields["hashcat_status"] or "unknown"
        print(f"[job {job_id}] {args.schedule} / selected {selection_reason}")
        if forced_cadence_due:
            print(f"  forced cadence: interval={force_interval}, slices_since_last_run={slices_since_last_run}, overdue_ratio={overdue_ratio:.3f}")
        if is_adaptive_warmup:
            print("  phase: warm-up (score based on arm-local cracks)")
        else:
            print("  phase: adaptive (score based on marginal new cracks)")
        print(f"  arm: {arm.name} ({arm.arm_type})")
        if arm.arm_type == "brute_force" and active_mask is not None:
            print(f"  mask: {active_mask} index={arm.masks.index(active_mask)+1}/{len(arm.masks)}")
            print(f"  skip: {skip_before} -> {arm.mask_next_skip.get(active_mask)} / keyspace={keyspace_for_job if keyspace_for_job is not None else 'unknown'} source={progress_source}")
        else:
            print(f"  skip: {skip_before} -> {arm.next_skip} / keyspace={arm.keyspace if arm.keyspace is not None else 'unknown'} source={progress_source}")
        print(f"  runtime: {runtime_seconds:.1f}s, exit={rc} {exit_meaning}")
        print(f"  cracks: arm_local={arm_local_cracks}, marginal_new={marginal_new_cracks}, total={total_cracks}, reward={reward:.3f}/s")
        if arm.arm_type == "feedback":
            print(f"  feedback slice: queue_before={feedback_queue_size_before}, written={feedback_candidates_written}, queue_after={feedback_queue_size_after}")
        if feedback_config is not None and (feedback_expansion["feedback_bases_expanded"] or feedback_expansion["feedback_generated_candidates"]):
            print(
                "  feedback expansion: "
                f"bases={feedback_expansion['feedback_bases_expanded']}, "
                f"generated={feedback_expansion['feedback_generated_candidates']}, "
                f"duplicates={feedback_expansion['feedback_duplicates_skipped']}, "
                f"rejected_bases={feedback_expansion['feedback_rejected_bases']}, "
                f"queue_before={feedback_expansion['feedback_queue_size_before']}, "
                f"queue_after={feedback_expansion['feedback_queue_size_after']}"
            )
        print(f"  score: {score_before:.3f} -> {arm.score:.3f}")
        print(f"  hashcat: status={status_text}, progress={progress_cur}/{progress_end}, speed={format_speed_hps(hashcat_fields['hashcat_speed_hps'])}")
        if args.verbose:
            print(f"  hashcat status events parsed: {len(status_events)}")
        if args.verbose_debug and status_events:
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
        "dictionary_candidate_limit": dictionary_candidate_limit,
        "adaptive_slices": current_adaptive_slice,
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
                "last_run_adaptive_slice": a.last_run_adaptive_slice,
                "force_every_slices": a.config.get("force_every_slices"),
                "speed_hps_estimate": (a.total_new_cracks / a.runtime) if a.runtime > 0 else None,
                "current_mask_index": a.current_mask_index if a.arm_type == "brute_force" else None,
                "masks": [
                    {"mask": m, "keyspace": a.mask_keyspaces.get(m), "next_skip": a.mask_next_skip.get(m), "exhausted": a.mask_exhausted.get(m)}
                    for m in a.masks
                ] if a.arm_type == "brute_force" else None,
            }
            for a in states
        },
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
