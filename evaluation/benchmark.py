#!/usr/bin/env python3
import argparse
import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFENDER = PROJECT_ROOT / "defender_heuristic" / "main.py"
LOADER = PROJECT_ROOT / "red_team" / "build" / "loader"


def read_rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return 0.0


def read_cpu_ticks(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
            parts = f.read().rsplit(")", 1)[1].split()
            return int(parts[11]) + int(parts[12])
    except (OSError, IndexError, ValueError):
        return 0


def is_stopped(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("State:"):
                    return "T" in line.split()[1]
    except OSError:
        return False
    return False


class MockC2:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        self.sock.settimeout(0.15)
        self.leaks = []
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
                data = conn.recv(512).decode("utf-8", errors="replace").strip()
                if data:
                    self.leaks.append(data)
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def reset(self):
        self.leaks.clear()

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def run_mode(mode_name: str, kernel_freeze: bool, runs: int, c2: MockC2) -> dict:
    log_path = PROJECT_ROOT / "logs" / f"bench_{mode_name}.jsonl"
    log_path.unlink(missing_ok=True)

    cmd = [sys.executable, str(DEFENDER), "--log", str(log_path)]
    if kernel_freeze:
        cmd.append("--kernel-freeze")

    defender_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(1.3)
    if defender_proc.poll() is not None:
        raise RuntimeError(defender_proc.stderr.read())

    c2.reset()
    t0 = time.monotonic()
    cpu0 = read_cpu_ticks(defender_proc.pid)
    frozen_count = 0
    false_positives = 0

    for _ in range(runs):
        p = subprocess.Popen(
            [str(LOADER), "--ticks", "6", "--exfil-port", str(c2.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 1.2
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
        time.sleep(0.08)

    for _ in range(runs):
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

    elapsed = max(time.monotonic() - t0, 0.001)
    cpu1 = read_cpu_ticks(defender_proc.pid)
    hz = os.sysconf("SC_CLK_TCK")
    cpu_pct = ((cpu1 - cpu0) / hz) / elapsed * 100.0
    rss_mb = read_rss_mb(defender_proc.pid)
    leaks = len(c2.leaks)

    defender_proc.terminate()
    try:
        defender_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        defender_proc.kill()

    mttis = []
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("action") == "FROZEN" and rec.get("mtti_ms") is not None:
                mttis.append(float(rec["mtti_ms"]))

    return {
        "mode": mode_name,
        "frozen": frozen_count,
        "runs": runs,
        "fpr": false_positives,
        "leaks": leaks,
        "avg_mtti": statistics.mean(mttis) if mttis else None,
        "rss_mb": rss_mb,
        "cpu_pct": cpu_pct,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare Userspace vs In-Kernel eBPF mitigation")
    parser.add_argument("--runs", type=int, default=5, help="Runs per mode")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write("error: run benchmark with sudo so eBPF probes can attach.\n")
        return 1

    c2 = MockC2()
    try:
        u = run_mode("userspace", False, args.runs, c2)
        k = run_mode("in_kernel", True, args.runs, c2)
    finally:
        c2.close()

    print(f"Benchmark Comparison ({args.runs} malicious + {args.runs} benign runs per mode):")
    for r in (u, k):
        mtti_s = f"{r['avg_mtti']:.4f} ms" if r["avg_mtti"] is not None else "n/a"
        print(
            f"  {r['mode']:<10} | frozen={r['frozen']}/{r['runs']} "
            f"| c2_leaks={r['leaks']}/{r['runs']} | fpr={r['fpr']}/{r['runs']} "
            f"| mean_mtti={mtti_s} | rss={r['rss_mb']:.1f} MB | cpu={r['cpu_pct']:.2f}%"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
