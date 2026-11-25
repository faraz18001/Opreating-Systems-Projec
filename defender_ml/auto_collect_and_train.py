#!/usr/bin/env python3
import argparse
import csv
import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Set

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEURISTIC_DIR = PROJECT_ROOT / "defender_heuristic"
for p in (str(PROJECT_ROOT), str(HEURISTIC_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from defender_ml.collect_dataset import CSV_HEADER  # noqa: E402
from defender_ml.features import DEFAULT_RULES_PATH, extract_features, load_rule_sets  # noqa: E402
from telemetry import collect_context  # noqa: E402

SENSOR_BIN = PROJECT_ROOT / "ebpf" / "build" / "sensor"
BPF_OBJ = PROJECT_ROOT / "ebpf" / "build" / "probes.bpf.o"
COLLECTOR_SCRIPT = PROJECT_ROOT / "defender_ml" / "collect_dataset.py"
TRAIN_SCRIPT = PROJECT_ROOT / "defender_ml" / "train.py"
DATASET_PATH = PROJECT_ROOT / "defender_ml" / "data" / "dataset.csv"
MODEL_PATH = PROJECT_ROOT / "defender_ml" / "model.joblib"
METRICS_PATH = PROJECT_ROOT / "defender_ml" / "metrics.json"


def restore_ownership(paths) -> None:
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if not sudo_uid or not sudo_gid:
        return
    uid, gid = int(sudo_uid), int(sudo_gid)
    for path in paths:
        if path.exists():
            try:
                os.chown(path, uid, gid)
            except OSError:
                pass


def capture_benign_live(
    output_path: Path,
    rules_path: Path,
    target_rows: int,
    max_seconds: float,
) -> int:
    rule_sets = load_rule_sets(rules_path)
    tracked_pids: Set[int] = set()
    own_pid = os.getpid()

    proc = subprocess.Popen(
        [str(SENSOR_BIN), str(BPF_OBJ)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

    stop_requested = False

    def _handle_stop(signum, frame):
        nonlocal stop_requested
        stop_requested = True

    prev_sigint = signal.signal(signal.SIGINT, _handle_stop)
    prev_sigterm = signal.signal(signal.SIGTERM, _handle_stop)

    captured = 0
    stop_reason = "unknown"
    start = time.monotonic()
    deadline = start + max_seconds if max_seconds > 0 else None

    print(
        f"[auto] capturing benign desktop eBPF events "
        f"(target={target_rows} rows, max={max_seconds / 60:.1f} min, Ctrl+C to finish early)",
        flush=True,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not output_path.exists() or output_path.stat().st_size == 0

    try:
        with open(output_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(CSV_HEADER)
                f.flush()

            assert proc.stdout is not None
            fd = proc.stdout.fileno()
            pending = b""

            while True:
                if stop_requested:
                    stop_reason = "user interrupt"
                    break
                if target_rows > 0 and captured >= target_rows:
                    stop_reason = "target row count reached"
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    stop_reason = "time limit reached"
                    break

                ready, _, _ = select.select([fd], [], [], 0.5)
                if not ready:
                    if proc.poll() is not None:
                        stop_reason = f"sensor exited (code={proc.returncode})"
                        break
                    continue

                chunk = os.read(fd, 8192)
                if not chunk:
                    stop_reason = f"sensor EOF (code={proc.poll()})"
                    break

                pending += chunk
                lines = pending.split(b"\n")
                pending = lines.pop()

                for raw_line in lines:
                    if target_rows > 0 and captured >= target_rows:
                        break
                    try:
                        event = json.loads(raw_line.decode("utf-8", errors="replace"))
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
                    writer.writerow([*feats, 0, "live_benign", f"benign_{pid}"])
                    f.flush()
                    captured += 1

                    if captured % 25 == 0 or captured == target_rows:
                        elapsed_min = (time.monotonic() - start) / 60.0
                        print(
                            f"[auto] benign progress: {captured}/{target_rows} rows ({elapsed_min:.1f} min)",
                            flush=True,
                        )
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        signal.signal(signal.SIGTERM, prev_sigterm)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        if proc.stderr and stop_reason.startswith("sensor"):
            err_txt = proc.stderr.read().decode("utf-8", errors="replace").strip()
            if err_txt:
                sys.stderr.write(f"[auto] sensor stderr: {err_txt}\n")

    print(f"[auto] capture stopped ({stop_reason})", flush=True)
    return captured


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Background live eBPF data collector and automatic ML retrainer"
    )
    parser.add_argument("--target-benign", type=int, default=300, help="Stop live capture after N benign rows")
    parser.add_argument("--max-minutes", type=float, default=20.0, help="Maximum live capture duration in minutes")
    parser.add_argument("--bootstrap", type=int, default=0, help="Optional synthetic boundary rows (default 0 = 100% real data)")
    parser.add_argument("--append", action="store_true", help="Append to existing dataset instead of resetting")
    parser.add_argument("--output", type=Path, default=DATASET_PATH, help="Dataset CSV path")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write("error: run with sudo so eBPF probes can attach.\n")
        return 1

    if not SENSOR_BIN.exists() or not BPF_OBJ.exists():
        sys.stderr.write("error: eBPF binaries missing. Run 'make' first.\n")
        return 1

    if not args.append:
        if args.bootstrap > 0:
            subprocess.run(
                [
                    sys.executable,
                    str(COLLECTOR_SCRIPT),
                    "--mode",
                    "bootstrap",
                    "--reset",
                    "--samples",
                    str(args.bootstrap),
                    "--output",
                    str(args.output),
                ],
                check=True,
            )
        elif args.output.exists():
            args.output.unlink()

    benign_count = capture_benign_live(
        output_path=args.output,
        rules_path=DEFAULT_RULES_PATH,
        target_rows=args.target_benign,
        max_seconds=args.max_minutes * 60.0,
    )
    print(f"[auto] finished live benign capture: {benign_count} rows", flush=True)

    if benign_count == 0 and args.bootstrap == 0 and not args.append:
        sys.stderr.write("error: 0 benign rows captured; cannot train a 2-class model yet. Re-run while opening apps.\n")
        return 1

    # Roughly 9 attack rows are captured per round; scale rounds to balance benign rows.
    attack_rounds = max(8, min(40, round(benign_count / 9.0)))
    print(f"[auto] running {attack_rounds} balanced attack rounds to match benign volume...", flush=True)
    subprocess.run(
        [
            sys.executable,
            str(COLLECTOR_SCRIPT),
            "--mode",
            "collect-attacks",
            "--rounds",
            str(attack_rounds),
            "--output",
            str(args.output),
        ],
        check=True,
    )

    print("[auto] training and evaluating all 4 ML classifiers...", flush=True)
    subprocess.run(
        [sys.executable, str(TRAIN_SCRIPT), "--dataset", str(args.output)],
        check=True,
    )

    restore_ownership([args.output.parent, args.output, MODEL_PATH, METRICS_PATH])
    print("[auto] complete. Updated dataset.csv, model.joblib, and metrics.json.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
