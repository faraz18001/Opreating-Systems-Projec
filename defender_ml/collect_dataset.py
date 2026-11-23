#!/usr/bin/env python3
import argparse
import csv
import json
import os
import queue
import random
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEURISTIC_DIR = PROJECT_ROOT / "defender_heuristic"
for p in (str(PROJECT_ROOT), str(HEURISTIC_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from defender_ml.features import (  # noqa: E402
    DEFAULT_RULES_PATH,
    FEATURE_NAMES,
    extract_features,
    extract_features_from_record,
    load_rule_sets,
)
from telemetry import collect_context  # noqa: E402

DEFAULT_SENSOR = PROJECT_ROOT / "ebpf" / "build" / "sensor"
DEFAULT_BPF_OBJ = PROJECT_ROOT / "ebpf" / "build" / "probes.bpf.o"
DEFAULT_LOADER = PROJECT_ROOT / "red_team" / "build" / "loader"
DEFAULT_LOG = PROJECT_ROOT / "logs" / "defender_events.jsonl"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "data" / "dataset.csv"
CSV_HEADER = [*FEATURE_NAMES, "label", "source", "group_id"]

KTHREAD_SPOOF_NAMES = ["[ksoftirqd/0]", "[migration/1]", "[rcu_preempt]", "[kswapd0]"]
MEMFD_ALIASES = ["pulse-shm", "wayland-cursor", "pipewire-buf", "jit_worker"]
ARGV0_SPOOFS = ["firefox", "pipewire", "chromium", "runc"]


def _write_rows(output_path: Path, rows: List[List[object]], reset: bool) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = reset or not output_path.exists() or output_path.stat().st_size == 0
    mode = "w" if reset else "a"
    with open(output_path, mode, newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(CSV_HEADER)
        writer.writerows(rows)


def collect_live(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        sys.stderr.write("error: live eBPF collection requires root privileges. Run with sudo.\n")
        return 1
    if not args.sensor.exists() or not args.bpf_obj.exists():
        sys.stderr.write("error: eBPF binaries not found. Run 'make' first.\n")
        return 1

    rule_sets = load_rule_sets(args.rules)
    tracked_pids: Set[int] = set()
    own_pid = os.getpid()

    proc = subprocess.Popen(
        [str(args.sensor), str(args.bpf_obj)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    stop_requested = False

    def _handle_stop(signum, frame):
        nonlocal stop_requested
        stop_requested = True
        if proc.poll() is None:
            proc.terminate()

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    rows: List[List[object]] = []
    start = time.monotonic()
    print(
        f"[collector] capturing live eBPF features (label={args.label}, duration={args.duration}s)...",
        flush=True,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        if stop_requested or (args.duration > 0 and (time.monotonic() - start) >= args.duration):
            break
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        pid = int(event.get("pid", 0) or 0)
        if pid in (own_pid, proc.pid):
            continue

        ev_type = str(event.get("type", ""))
        if ev_type == "memfd_create":
            tracked_pids.add(pid)

        ctx = collect_context(
            pid=pid,
            fallback_ppid=int(event.get("ppid", 0) or 0),
            fd=int(event.get("fd", -1)),
            inspect_entropy=ev_type in ("execveat", "execve_fd"),
        )
        feats = extract_features(
            event,
            ctx,
            created_memfd=(pid in tracked_pids),
            rule_sets=rule_sets,
        )
        rows.append([*feats, int(args.label), "live_ebpf", f"live_{pid}"])

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

    _write_rows(args.output, rows, reset=args.reset)
    print(f"[collector] wrote {len(rows)} live rows to {args.output}")
    return 0


def collect_attacks(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        sys.stderr.write("error: attack collection requires root privileges. Run with sudo.\n")
        return 1
    if not args.sensor.exists() or not args.bpf_obj.exists() or not args.loader.exists():
        sys.stderr.write("error: sensor or loader binaries not found. Run 'make' first.\n")
        return 1

    rule_sets = load_rule_sets(args.rules)
    _, kthread_prefixes = rule_sets
    tracked_pids: Set[int] = set()
    attack_pids: Set[int] = set()
    pid_lock = threading.Lock()
    ev_queue: queue.Queue = queue.Queue(maxsize=1000)

    proc = subprocess.Popen(
        [str(args.sensor), str(args.bpf_obj)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    stop_requested = threading.Event()

    def _handle_stop(signum, frame):
        stop_requested.set()
        if proc.poll() is None:
            proc.terminate()

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    def _reader():
        assert proc.stdout is not None
        for line in proc.stdout:
            try:
                ev_queue.put(json.loads(line))
            except json.JSONDecodeError:
                continue
        ev_queue.put(None)

    def _launcher():
        time.sleep(1.2)
        for r in range(args.rounds):
            if stop_requested.is_set():
                break
            variants = [
                ["--ticks", "2"],
                ["--ticks", "2", "--no-masquerade"],
                ["--ticks", "2", "--name", KTHREAD_SPOOF_NAMES[r % len(KTHREAD_SPOOF_NAMES)]],
                ["--ticks", "2", "--memfd-name", MEMFD_ALIASES[r % len(MEMFD_ALIASES)]],
                ["--ticks", "2", "--argv0", ARGV0_SPOOFS[r % len(ARGV0_SPOOFS)], "--name", "[kworker/u8:2]"],
            ]
            for v_args in variants:
                if stop_requested.is_set():
                    break
                child = subprocess.Popen(
                    [str(args.loader), *v_args],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                with pid_lock:
                    attack_pids.add(child.pid)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
                time.sleep(0.08)
        time.sleep(0.3)
        stop_requested.set()
        if proc.poll() is None:
            proc.terminate()

    reader_t = threading.Thread(target=_reader, daemon=True)
    launcher_t = threading.Thread(target=_launcher, daemon=True)
    reader_t.start()
    launcher_t.start()

    print(
        f"[collector] running {args.rounds} varied attack rounds ({args.rounds * 5} executions)...",
        flush=True,
    )

    rows: List[List[object]] = []
    while True:
        try:
            event = ev_queue.get(timeout=0.5)
        except queue.Empty:
            if stop_requested.is_set() and proc.poll() is not None:
                break
            continue
        if event is None:
            break

        pid = int(event.get("pid", 0) or 0)
        ev_type = str(event.get("type", ""))
        if ev_type == "memfd_create":
            tracked_pids.add(pid)
            continue

        with pid_lock:
            is_ours = pid in attack_pids
        if not is_ours:
            continue

        ev_name = str(event.get("name", ""))
        if ev_type == "prctl_set_name" and not any(ev_name.startswith(p) for p in kthread_prefixes):
            continue
        if ev_type not in ("execveat", "execve_fd", "prctl_set_name"):
            continue

        ctx = collect_context(
            pid=pid,
            fallback_ppid=int(event.get("ppid", 0) or 0),
            fd=int(event.get("fd", -1)),
            inspect_entropy=ev_type in ("execveat", "execve_fd"),
        )
        feats = extract_features(
            event,
            ctx,
            created_memfd=(pid in tracked_pids),
            rule_sets=rule_sets,
        )
        rows.append([*feats, 1, "live_ebpf", f"atk_{pid}"])

    launcher_t.join(timeout=2)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

    _write_rows(args.output, rows, reset=args.reset)
    print(f"[collector] wrote {len(rows)} clean attack rows across {len(attack_pids)} PIDs -> {args.output}")
    return 0


def _infer_log_label(record: Dict, allowlist_comms: Set[str], kthread_prefixes: Tuple[str, ...]) -> Optional[int]:
    ev_type = str(record.get("type", ""))
    ev_comm = str(record.get("comm", ""))
    ev_name = str(record.get("name", ""))
    exe = str(record.get("exe", ""))
    ancestry = [str(x) for x in (record.get("ancestry") or [])]

    if ev_type == "memfd_create":
        return 0

    is_masquerade = ev_type == "prctl_set_name" and any(ev_name.startswith(p) for p in kthread_prefixes)
    if is_masquerade:
        return 1

    is_allowlisted = (
        ev_comm in allowlist_comms
        or (len(ancestry) > 0 and ancestry[0] in allowlist_comms)
        or (len(ancestry) > 1 and ancestry[1] in allowlist_comms)
    )
    if is_allowlisted:
        return 0

    if ev_type == "execveat" and ("memfd:" in exe or ev_comm == "loader" or "jit_cache" in ev_name):
        return 1
    if ev_type == "execve_fd" and "/proc/" in ev_name and "/fd/" in ev_name:
        return 1
    if ev_type == "prctl_set_name":
        return 0

    return None


def import_log(args: argparse.Namespace) -> int:
    if not args.log.exists():
        sys.stderr.write(f"error: log file not found: {args.log}\n")
        return 1

    rule_sets = load_rule_sets(args.rules)
    allowlist_comms, kthread_prefixes = rule_sets
    tracked_pids: Set[int] = set()
    rows: List[List[object]] = []
    skipped = 0

    with open(args.log, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            feats = extract_features_from_record(rec, rule_sets=rule_sets, tracked_pids=tracked_pids)
            label = _infer_log_label(rec, allowlist_comms, kthread_prefixes)
            if label is None:
                skipped += 1
                continue

            pid = int(rec.get("pid", 0) or 0)
            rows.append([*feats, label, "live_log", f"log_{pid}"])

    _write_rows(args.output, rows, reset=args.reset)
    benign = sum(1 for r in rows if r[-3] == 0)
    malicious = sum(1 for r in rows if r[-3] == 1)
    print(
        f"[collector] imported {len(rows)} rows from {args.log} "
        f"(benign={benign}, malicious={malicious}, skipped={skipped}) -> {args.output}"
    )
    return 0


def bootstrap_dataset(args: argparse.Namespace) -> int:
    rng = random.Random(args.seed)
    n_total = max(40, args.samples)
    n_benign = n_total // 2
    n_malicious = n_total - n_benign
    rows: List[List[object]] = []

    for i in range(n_benign):
        grp = f"syn_b_{i // 2}"
        archetype = i % 5
        if archetype == 0:
            # Desktop / audio / systemd memfd_create allocation
            feats = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, -1.0]
        elif archetype == 1:
            # Non-allowlisted utility creating a benign memfd buffer without exec
            feats = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, -1.0]
        elif archetype == 2:
            # Allowlisted runtime (e.g. runc, systemd-executor, chromium) re-exec via /proc/self/fd
            ent = round(rng.uniform(4.6, 7.3), 4)
            has_memfd = 1.0 if rng.random() < 0.35 else 0.0
            feats = [0.0, 0.0, 1.0, 0.0, has_memfd, 0.0, has_memfd, 1.0, 0.0, 1.0, ent]
        elif archetype == 3:
            # Allowlisted program invoking execveat with AT_EMPTY_PATH
            ent = round(rng.uniform(4.4, 7.1), 4)
            feats = [0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, ent]
        else:
            # Normal worker thread renaming itself without kthread bracket prefix
            feats = [0.0, 0.0, 0.0, 1.0, 1.0 if rng.random() < 0.4 else 0.0, 0.0, 0.0, 0.0, 0.0, 1.0 if rng.random() < 0.5 else 0.0, -1.0]
        rows.append([*feats, 0, "synthetic_bootstrap", grp])

    for i in range(n_malicious):
        grp = f"syn_m_{i // 2}"
        archetype = i % 4
        if archetype == 0:
            # Standard memfd_create + execveat fileless loader (varied binary entropy)
            ent = round(rng.uniform(2.1, 7.9), 4)
            feats = [0.0, 1.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, ent]
        elif archetype == 1:
            # Forked-child fileless execveat where child inherited memfd (tracked_memfd=0)
            ent = round(rng.uniform(2.3, 7.9), 4)
            feats = [0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, ent]
        elif archetype == 2:
            # Non-allowlisted process executing via /proc/self/fd/<n>
            ent = round(rng.uniform(2.2, 7.8), 4)
            has_memfd = 1.0 if rng.random() < 0.65 else 0.0
            feats = [0.0, 0.0, 1.0, 0.0, has_memfd, 0.0, has_memfd, 1.0, 0.0, 0.0, ent]
        else:
            # Kernel thread masquerade via prctl(PR_SET_NAME, "[kworker...]")
            tracked = 1.0 if rng.random() < 0.8 else 0.0
            spoof_allow = 1.0 if rng.random() < 0.15 else 0.0
            feats = [0.0, 0.0, 0.0, 1.0, tracked, 0.0, tracked, 0.0, 1.0, spoof_allow, -1.0]
        rows.append([*feats, 1, "synthetic_bootstrap", grp])

    rng.shuffle(rows)
    _write_rows(args.output, rows, reset=args.reset)
    print(
        f"[collector] generated {len(rows)} bootstrap rows "
        f"(benign={n_benign}, malicious={n_malicious}) -> {args.output}"
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect labeled eBPF telemetry datasets for defender_ml")
    parser.add_argument("--mode", choices=["live", "collect-attacks", "import-log", "bootstrap"], required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output CSV dataset path")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES_PATH, help="Path to rules.yaml")
    parser.add_argument("--reset", action="store_true", help="Overwrite dataset CSV instead of appending")
    parser.add_argument("--label", type=int, choices=[0, 1], default=0, help="Label for --mode live (0=benign, 1=malicious)")
    parser.add_argument("--duration", type=float, default=30.0, help="Capture duration in seconds for --mode live")
    parser.add_argument("--sensor", type=Path, default=DEFAULT_SENSOR, help="Path to eBPF sensor binary")
    parser.add_argument("--bpf-obj", type=Path, default=DEFAULT_BPF_OBJ, help="Path to probes.bpf.o")
    parser.add_argument("--loader", type=Path, default=DEFAULT_LOADER, help="Path to red_team loader binary")
    parser.add_argument("--rounds", type=int, default=8, help="Attack rounds (5 variants per round) for --mode collect-attacks")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="Path to defender_events.jsonl for --mode import-log")
    parser.add_argument("--samples", type=int, default=400, help="Row count for --mode bootstrap")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for --mode bootstrap")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mode == "live":
        return collect_live(args)
    if args.mode == "collect-attacks":
        return collect_attacks(args)
    if args.mode == "import-log":
        return import_log(args)
    return bootstrap_dataset(args)


if __name__ == "__main__":
    sys.exit(main())
