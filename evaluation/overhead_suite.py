#!/usr/bin/env python3
import argparse
import ctypes
import json
import os
import select
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFENDER = PROJECT_ROOT / "defender_heuristic" / "main.py"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"

IN_CREATE = 0x00000100
IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_DELETE = 0x00000200
FIM_MASK = IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE


def read_rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024.0, 2)
    except OSError:
        pass
    return 0.0


def run_syscall_workload(iterations: int, work_dir: Path) -> dict:
    t0 = time.perf_counter()
    for i in range(iterations):
        fd = os.memfd_create(f"bench_{i & 63}", os.MFD_CLOEXEC)
        os.close(fd)
    memfd_us = ((time.perf_counter() - t0) / iterations) * 1_000_000.0

    fs_iters = max(200, iterations // 5)
    t1 = time.perf_counter()
    for i in range(fs_iters):
        p = work_dir / f"tmp_{i & 31}.bin"
        p.write_bytes(b"benchmark-payload")
        p.unlink(missing_ok=True)
    fs_us = ((time.perf_counter() - t1) / fs_iters) * 1_000_000.0

    return {
        "memfd_us_per_op": round(memfd_us, 3),
        "fs_us_per_op": round(fs_us, 3),
    }


class InotifyFimWatcher:
    def __init__(self, watch_dir: Path):
        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK)
        self.libc.inotify_add_watch(self.fd, str(watch_dir).encode(), FIM_MASK)
        self._stop = False
        self.events_seen = 0
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    buf = os.read(self.fd, 8192)
                    if buf:
                        self.events_seen += 1
                except OSError:
                    break

    def close(self) -> None:
        self._stop = True
        self._thread.join(timeout=1)
        os.close(self.fd)


def measure_defender_config(name: str, extra_args: list, iterations: int, work_dir: Path) -> dict:
    log_path = PROJECT_ROOT / "logs" / f"overhead_{name}.jsonl"
    log_path.unlink(missing_ok=True)
    cmd = [sys.executable, str(DEFENDER), "--no-forensics", "--log", str(log_path), *extra_args]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.3)

    try:
        wl = run_syscall_workload(iterations, work_dir)
        rss = read_rss_mb(proc.pid)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_path.unlink(missing_ok=True)

    return {
        "config": name,
        "memfd_us_per_op": wl["memfd_us_per_op"],
        "fs_us_per_op": wl["fs_us_per_op"],
        "rss_mb": rss,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Syscall latency & RSS overhead comparison: Baseline vs FIM vs eBPF")
    parser.add_argument("--iterations", type=int, default=3000, help="memfd_create/close iterations per config")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write("error: run with sudo so eBPF probes can attach.\n")
        return 1

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="osproj_bench_") as tmp:
        work_dir = Path(tmp)

        base_wl = run_syscall_workload(args.iterations, work_dir)
        results = [{
            "config": "baseline_none",
            "memfd_us_per_op": base_wl["memfd_us_per_op"],
            "fs_us_per_op": base_wl["fs_us_per_op"],
            "rss_mb": 0.0,
        }]

        fim = InotifyFimWatcher(work_dir)
        try:
            fim_wl = run_syscall_workload(args.iterations, work_dir)
        finally:
            fim.close()
        results.append({
            "config": "traditional_fim_inotify",
            "memfd_us_per_op": fim_wl["memfd_us_per_op"],
            "fs_us_per_op": fim_wl["fs_us_per_op"],
            "rss_mb": read_rss_mb(os.getpid()),
            "fim_batches_seen": fim.events_seen,
        })

        results.append(measure_defender_config("ebpf_userspace_heur", ["--no-shadow"], args.iterations, work_dir))
        results.append(measure_defender_config("ebpf_userspace_ml", ["--engine", "ml"], args.iterations, work_dir))
        results.append(measure_defender_config("ebpf_inkernel_vfs", ["--kernel-freeze", "--no-shadow"], args.iterations, work_dir))

    base_memfd = results[0]["memfd_us_per_op"]
    base_fs = results[0]["fs_us_per_op"]

    print(f"Syscall Overhead Comparison ({args.iterations} memfd_create+close ops, {max(200, args.iterations // 5)} fs create+unlink ops):")
    print(f"{'Configuration':<26} {'memfd (µs)':>11} {'Δ memfd':>10} {'fs (µs)':>10} {'Δ fs':>9} {'RSS (MB)':>10}")
    for r in results:
        dm = ((r["memfd_us_per_op"] - base_memfd) / max(base_memfd, 0.001)) * 100.0
        df = ((r["fs_us_per_op"] - base_fs) / max(base_fs, 0.001)) * 100.0
        r["memfd_overhead_pct"] = round(dm, 1)
        r["fs_overhead_pct"] = round(df, 1)
        print(
            f"{r['config']:<26} {r['memfd_us_per_op']:>11.3f} {dm:>+9.1f}% "
            f"{r['fs_us_per_op']:>10.3f} {df:>+8.1f}% {r['rss_mb']:>10.1f}"
        )

    out_file = RESULTS_DIR / "overhead_report.json"
    out_file.write_text(json.dumps({"iterations": args.iterations, "results": results}, indent=2), encoding="utf-8")
    print(f"\nSaved report -> {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
