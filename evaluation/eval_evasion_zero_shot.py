#!/usr/bin/env python3
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEUR_DIR = PROJECT_ROOT / "defender_heuristic"
for p in (str(PROJECT_ROOT), str(HEUR_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from classifier import HeuristicClassifier  # noqa: E402
from defender_ml.classifier import MLClassifier  # noqa: E402
from telemetry import collect_context  # noqa: E402

SENSOR = PROJECT_ROOT / "ebpf" / "build" / "sensor"
BPF_OBJ = PROJECT_ROOT / "ebpf" / "build" / "probes.bpf.o"
LOADER = PROJECT_ROOT / "red_team" / "build" / "loader"
RULES = HEUR_DIR / "rules.yaml"
MODEL = PROJECT_ROOT / "defender_ml" / "model.joblib"

VECTORS = [
    ("standard", ["--ticks", "1"]),
    ("dup-fd", ["--dup-fd", "--ticks", "1"]),
    ("fork", ["--fork", "--ticks", "1"]),
    ("execve-fd", ["--execve-fd", "--ticks", "1"]),
    ("high-entropy", ["--high-entropy", "--ticks", "1"]),
    ("mmap-exec", ["--mmap-exec", "--ticks", "1"]),
    ("scm-fd", ["--scm-fd", "--ticks", "1"]),
]


def eval_vector(name: str, extra_args: list, runs: int = 3) -> dict:
    heur_clf = HeuristicClassifier(RULES)
    ml_clf = MLClassifier(MODEL, RULES)

    sensor = subprocess.Popen(
        [str(SENSOR), str(BPF_OBJ)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    time.sleep(0.6)

    heur_caught = 0
    ml_caught = 0
    entropies = []
    probs = []
    exec_events_seen = 0

    try:
        assert sensor.stdout is not None
        fd = sensor.stdout.fileno()
        pending = b""

        for _ in range(runs):
            p = subprocess.Popen(
                [str(LOADER), *extra_args],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 1.1

            run_heur_hit = False
            run_ml_hit = False

            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.02)
                if not ready:
                    if p.poll() is not None and name not in ("fork", "scm-fd") and (run_heur_hit or run_ml_hit):
                        break
                    continue
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                pending += chunk
                lines = pending.split(b"\n")
                pending = lines.pop()

                for raw in lines:
                    try:
                        ev = json.loads(raw.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError:
                        continue

                    ev_type = ev.get("type", "")
                    comm = ev.get("comm", "")
                    ev_name = ev.get("name", "")
                    if (
                        ev_type != "mprotect_exec"
                        and comm not in ("loader", "[kworker/u8:2]")
                        and "jit_cache" not in ev_name
                        and "/proc/" not in ev_name
                    ):
                        continue

                    pid = int(ev["pid"])
                    ctx = collect_context(
                        pid=pid,
                        fallback_ppid=int(ev.get("ppid", 0)),
                        fd=int(ev.get("fd", -1)),
                        inspect_entropy=ev_type in ("execveat", "execve_fd"),
                    )
                    hv = heur_clf.evaluate(ev, ctx)
                    mv = ml_clf.evaluate(ev, ctx)

                    if ev_type in ("execveat", "execve_fd", "mprotect_exec"):
                        exec_events_seen += 1
                        if ctx.entropy is not None:
                            entropies.append(ctx.entropy)
                        probs.append(mv.prob)

                    if hv.action == "FREEZE":
                        run_heur_hit = True
                    if mv.action == "FREEZE":
                        run_ml_hit = True

            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

            if run_heur_hit:
                heur_caught += 1
            if run_ml_hit:
                ml_caught += 1
    finally:
        sensor.terminate()
        try:
            sensor.wait(timeout=2)
        except subprocess.TimeoutExpired:
            sensor.kill()

    avg_ent = sum(entropies) / len(entropies) if entropies else None
    avg_prob = sum(probs) / len(probs) if probs else None
    return {
        "vector": name,
        "runs": runs,
        "exec_seen": exec_events_seen,
        "heur_caught": heur_caught,
        "ml_caught": ml_caught,
        "avg_prob": avg_prob,
        "avg_entropy": avg_ent,
    }


def main() -> int:
    if os.geteuid() != 0:
        sys.stderr.write("error: run with sudo so eBPF probes can attach.\n")
        return 1

    print(f"{'Vector':<14} {'ExecSeen':>8} {'Heuristic':>10} {'ML(100%Real)':>14} {'Avg P(mal)':>11} {'Avg Entropy':>12}")
    for name, args in VECTORS:
        r = eval_vector(name, args, runs=3)
        prob_s = f"{r['avg_prob']:.3f}" if r["avg_prob"] is not None else "n/a"
        ent_s = f"{r['avg_entropy']:.2f}" if r["avg_entropy"] is not None else "n/a"
        print(
            f"{r['vector']:<14} {r['exec_seen']:>8} "
            f"{r['heur_caught']}/{r['runs']:<8} "
            f"{r['ml_caught']}/{r['runs']:<12} "
            f"{prob_s:>11} {ent_s:>12}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
