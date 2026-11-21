#!/usr/bin/env python3
import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFENDER = PROJECT_ROOT / "defender_heuristic" / "main.py"
LOADER = PROJECT_ROOT / "red_team" / "build" / "loader"
BENCH_LOG = PROJECT_ROOT / "logs" / "benchmark_events.jsonl"


def read_rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    kb = int(line.split()[1])
                    return kb / 1024.0
    except OSError:
        pass
    return 0.0


def is_stopped(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("State:"):
                    return "T" in line.split()[1]
    except OSError:
        return False
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark eBPF defender MTTI, FPR, and RAM overhead")
    parser.add_argument("--runs", type=int, default=5, help="Number of malicious and benign runs")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write("error: run benchmark with sudo so eBPF probes can attach.\n")
        return 1

    if BENCH_LOG.exists():
        BENCH_LOG.unlink()

    defender_proc = subprocess.Popen(
        [sys.executable, str(DEFENDER), "--log", str(BENCH_LOG)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(1.5)
    if defender_proc.poll() is not None:
        sys.stderr.write(f"error: defender exited early:\n{defender_proc.stderr.read()}\n")
        return 1

    frozen_count = 0
    false_positives = 0

    for _ in range(args.runs):
        p = subprocess.Popen(
            [str(LOADER), "--ticks", "6"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 1.5
        was_frozen = False
        while time.monotonic() < deadline:
            if is_stopped(p.pid):
                was_frozen = True
                break
            if p.poll() is not None:
                break
            time.sleep(0.01)

        if was_frozen:
            frozen_count += 1
        try:
            os.kill(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait(timeout=2)
        time.sleep(0.1)

    for _ in range(args.runs):
        p = subprocess.Popen(
            [str(LOADER), "--benign-memfd"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            p.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            if is_stopped(p.pid):
                false_positives += 1
            os.kill(p.pid, signal.SIGKILL)
            p.wait(timeout=2)

    rss_mb = read_rss_mb(defender_proc.pid)
    defender_proc.terminate()
    try:
        defender_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        defender_proc.kill()

    mttis = []
    if BENCH_LOG.exists():
        with open(BENCH_LOG, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("action") == "FROZEN" and rec.get("mtti_ms") is not None:
                    mttis.append(float(rec["mtti_ms"]))

    det_rate = (frozen_count / args.runs) * 100.0 if args.runs else 0.0
    fpr = (false_positives / args.runs) * 100.0 if args.runs else 0.0
    avg_mtti = f"{statistics.mean(mttis):.3f} ms" if mttis else "n/a"
    min_mtti = f"{min(mttis):.3f} ms" if mttis else "n/a"
    max_mtti = f"{max(mttis):.3f} ms" if mttis else "n/a"

    print("Evaluation Summary:")
    print(f"  Detection & Freeze Rate  : {frozen_count}/{args.runs} ({det_rate:.1f}%)")
    print(f"  False Positive Rate      : {false_positives}/{args.runs} ({fpr:.1f}%)")
    print(f"  Mean Time to Intercept   : {avg_mtti}")
    print(f"  Min / Max MTTI           : {min_mtti} / {max_mtti}")
    print(f"  Defender Python RSS RAM  : {rss_mb:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
