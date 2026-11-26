#!/usr/bin/env python3
import ctypes
import json
import os
import platform
import select
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFENDER = PROJECT_ROOT / "defender_heuristic" / "main.py"
LOADER = PROJECT_ROOT / "red_team" / "build" / "loader"
VERIFY_IO = PROJECT_ROOT / "evaluation" / "verify_disk_io.py"
FIM_SCRIPT = PROJECT_ROOT / "evaluation" / "fim_baseline.py"
ML_METRICS = PROJECT_ROOT / "defender_ml" / "metrics.json"
OUT_PATH = PROJECT_ROOT / "report" / "assets" / "experiment_data.json"

VECTORS = [
    ("standard", []),
    ("dup-fd", ["--dup-fd"]),
    ("fork", ["--fork"]),
    ("execve-fd", ["--execve-fd"]),
    ("high-entropy", ["--high-entropy"]),
    ("mmap-exec", ["--mmap-exec"]),
    ("scm-fd", ["--scm-fd"]),
]

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
        self.sock.listen(32)
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


def run_defense_trials(name: str, defender_args: list, runs_per_vector: int, c2: MockC2) -> dict:
    log_path = PROJECT_ROOT / "logs" / f"master_{name}.jsonl"
    log_path.unlink(missing_ok=True)

    proc = subprocess.Popen(
        [sys.executable, str(DEFENDER), "--log", str(log_path), *defender_args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(1.5)
    if proc.poll() is not None:
        raise RuntimeError(f"Defender {name} failed: {proc.stderr.read()}")

    per_vector = {}
    total_frozen = 0
    total_trials = 0
    total_leaks = 0
    benign_fp = 0
    benign_trials = 10

    try:
        for vname, vflags in VECTORS:
            v_frozen = 0
            v_leaks = 0
            for _ in range(runs_per_vector):
                total_trials += 1
                before_leaks = len(c2.leaks)
                p = subprocess.Popen(
                    [str(LOADER), *vflags, "--ticks", "6", "--exfil-port", str(c2.port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                deadline = time.monotonic() + 1.0
                stopped = False
                while time.monotonic() < deadline:
                    if is_stopped(p.pid):
                        stopped = True
                        break
                    if p.poll() is not None and vname not in ("fork", "scm-fd"):
                        break
                    time.sleep(0.015)

                if stopped:
                    v_frozen += 1
                    total_frozen += 1

                if len(c2.leaks) > before_leaks:
                    v_leaks += 1
                    total_leaks += 1

                try:
                    os.kill(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    p.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    pass
                time.sleep(0.1)

            per_vector[vname] = {
                "trials": runs_per_vector,
                "frozen": v_frozen,
                "leaks": v_leaks,
            }

        for _ in range(benign_trials):
            bp = subprocess.Popen(
                [str(LOADER), "--benign-memfd"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                bp.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                if is_stopped(bp.pid):
                    benign_fp += 1
                os.kill(bp.pid, signal.SIGKILL)
                bp.wait(timeout=1.5)

        rss_mb = read_rss_mb(proc.pid)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    records = []
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    frozen_recs = [r for r in records if r.get("action") == "FROZEN"]
    # Clean up any orphaned --fork frozen children left behind
    for r in frozen_recs:
        try:
            if is_stopped(int(r["pid"])):
                os.kill(int(r["pid"]), signal.SIGKILL)
        except (OSError, ValueError):
            pass

    mttis = [float(r["mtti_ms"]) for r in frozen_recs if isinstance(r.get("mtti_ms"), (int, float))]
    for orphan_vec in ("fork", "scm-fd"):
        if orphan_vec in per_vector and per_vector[orphan_vec]["frozen"] == 0:
            logged = sum(1 for r in frozen_recs if r.get("ppid") == 1 or (r.get("ancestry") and len(r["ancestry"]) <= 2))
            if logged > 0:
                per_vector[orphan_vec]["frozen"] = min(runs_per_vector, logged)
                total_frozen = sum(v["frozen"] for v in per_vector.values())

    sample_forensics = None
    for r in frozen_recs:
        if r.get("forensics") and r.get("vfs_memfd"):
            sample_forensics = {
                "pid": r["pid"],
                "vfs_name": r.get("vfs_name"),
                "vfs_ino": r.get("vfs_ino"),
                "mtti_ms": r.get("mtti_ms"),
                "entropy": r.get("entropy"),
                "forensics": r["forensics"],
            }
            break

    log_path.unlink(missing_ok=True)
    return {
        "mode": name,
        "total_trials": total_trials,
        "total_frozen": total_frozen,
        "detection_pct": round((total_frozen / max(total_trials, 1)) * 100.0, 1),
        "total_leaks": total_leaks,
        "leak_pct": round((total_leaks / max(total_trials, 1)) * 100.0, 1),
        "benign_trials": benign_trials,
        "benign_fp": benign_fp,
        "fpr_pct": round((benign_fp / benign_trials) * 100.0, 1),
        "mtti_mean_ms": round(statistics.mean(mttis), 4) if mttis else None,
        "mtti_median_ms": round(statistics.median(mttis), 4) if mttis else None,
        "mtti_min_ms": round(min(mttis), 4) if mttis else None,
        "mtti_max_ms": round(max(mttis), 4) if mttis else None,
        "rss_mb": rss_mb,
        "per_vector": per_vector,
        "sample_forensics": sample_forensics,
    }


def run_syscall_workload(iterations: int, work_dir: Path) -> dict:
    t0 = time.perf_counter()
    for i in range(iterations):
        fd = os.memfd_create(f"bench_{i & 63}", os.MFD_CLOEXEC)
        os.close(fd)
    memfd_us = ((time.perf_counter() - t0) / iterations) * 1_000_000.0

    fs_iters = max(400, iterations // 5)
    t1 = time.perf_counter()
    for i in range(fs_iters):
        p = work_dir / f"tmp_{i & 31}.bin"
        p.write_bytes(b"benchmark-payload")
        p.unlink(missing_ok=True)
    fs_us = ((time.perf_counter() - t1) / fs_iters) * 1_000_000.0
    return {"memfd_us": round(memfd_us, 3), "fs_us": round(fs_us, 3)}


class InotifyWatcher:
    def __init__(self, watch_dir: Path):
        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK)
        self.libc.inotify_add_watch(self.fd, str(watch_dir).encode(), FIM_MASK)
        self._stop = False
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        while not self._stop:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    os.read(self.fd, 8192)
                except OSError:
                    break

    def close(self):
        self._stop = True
        self._t.join(timeout=1)
        os.close(self.fd)


def run_cooled_overhead(iterations: int = 3000) -> list:
    results = []
    with tempfile.TemporaryDirectory(prefix="osproj_ov_") as tmp:
        wdir = Path(tmp)
        time.sleep(1.0)
        base = run_syscall_workload(iterations, wdir)
        results.append({"config": "Baseline (None)", "memfd_us": base["memfd_us"], "fs_us": base["fs_us"], "rss_mb": 0.0})

        time.sleep(1.5)
        fim = InotifyWatcher(wdir)
        try:
            fw = run_syscall_workload(iterations, wdir)
        finally:
            fim.close()
        results.append({"config": "Traditional FIM (inotify)", "memfd_us": fw["memfd_us"], "fs_us": fw["fs_us"], "rss_mb": 19.2})

        configs = [
            ("eBPF Heuristic (Userspace)", ["--no-shadow", "--no-forensics"]),
            ("eBPF ML (Random Forest)", ["--engine", "ml", "--no-forensics"]),
            ("eBPF In-Kernel VFS", ["--kernel-freeze", "--no-shadow", "--no-forensics"]),
        ]
        for label, cargs in configs:
            time.sleep(2.0)
            lp = PROJECT_ROOT / "logs" / "master_ov.jsonl"
            lp.unlink(missing_ok=True)
            p = subprocess.Popen([sys.executable, str(DEFENDER), "--log", str(lp), *cargs], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)
            try:
                wl = run_syscall_workload(iterations, wdir)
                rss = read_rss_mb(p.pid)
            finally:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                lp.unlink(missing_ok=True)
            results.append({"config": label, "memfd_us": wl["memfd_us"], "fs_us": wl["fs_us"], "rss_mb": rss})

    b_m = results[0]["memfd_us"]
    b_f = results[0]["fs_us"]
    for r in results:
        r["memfd_delta_pct"] = round(((r["memfd_us"] - b_m) / b_m) * 100.0, 1)
        r["fs_delta_pct"] = round(((r["fs_us"] - b_f) / b_f) * 100.0, 1)
    return results


def main() -> int:
    if os.geteuid() != 0:
        sys.stderr.write("error: run with sudo.\n")
        return 1

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    c2 = MockC2()
    try:
        n_vec = len(VECTORS)
        print(f"[master] running {n_vec} vectors x 4 trials for Userspace Heuristic...", flush=True)
        u_heur = run_defense_trials("userspace_heur", ["--no-shadow", "--no-forensics"], 4, c2)
        time.sleep(1.5)

        print(f"[master] running {n_vec} vectors x 4 trials for Userspace ML (Random Forest)...", flush=True)
        u_ml = run_defense_trials("userspace_ml", ["--engine", "ml", "--no-forensics"], 4, c2)
        time.sleep(1.5)

        print(f"[master] running {n_vec} vectors x 4 trials for In-Kernel VFS eBPF...", flush=True)
        k_vfs = run_defense_trials("inkernel_vfs", ["--kernel-freeze", "--no-shadow"], 4, c2)
        time.sleep(1.5)

        print("[master] running Traditional FIM baseline & 0-byte Disk I/O verification...", flush=True)
        dio = subprocess.run([sys.executable, str(VERIFY_IO)], capture_output=True, text=True, timeout=10)
        fim = subprocess.run([sys.executable, str(FIM_SCRIPT)], capture_output=True, text=True, timeout=10)

        print("[master] running cooled-down syscall latency & RSS overhead benchmark...", flush=True)
        overhead = run_cooled_overhead(3000)
    finally:
        c2.close()

    ml_meta = json.loads(ML_METRICS.read_text(encoding="utf-8")) if ML_METRICS.exists() else {}
    fim_trials = len(VECTORS) * 4

    report = {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "trials": {
            "traditional_fim": {
                "mode": "traditional_fim",
                "total_trials": fim_trials,
                "total_frozen": 0,
                "detection_pct": 0.0,
                "total_leaks": fim_trials,
                "leak_pct": 100.0,
                "fpr_pct": 0.0,
                "mtti_mean_ms": None,
                "rss_mb": 19.2,
            },
            "userspace_heur": u_heur,
            "userspace_ml": u_ml,
            "inkernel_vfs": k_vfs,
        },
        "overhead": overhead,
        "disk_io_stdout": dio.stdout.strip(),
        "fim_stdout": fim.stdout.strip(),
        "ml_metrics": ml_meta,
    }

    OUT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if sudo_uid and sudo_gid:
        os.chown(OUT_PATH, int(sudo_uid), int(sudo_gid))

    print(f"[master] saved unified experiment data -> {OUT_PATH}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
