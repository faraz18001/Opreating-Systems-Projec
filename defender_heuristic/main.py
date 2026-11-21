#!/usr/bin/env python3
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from classifier import HeuristicClassifier
from mitigator import freeze_process
from telemetry import collect_context

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SENSOR = PROJECT_ROOT / "ebpf" / "build" / "sensor"
DEFAULT_BPF_OBJ = PROJECT_ROOT / "ebpf" / "build" / "probes.bpf.o"
DEFAULT_RULES = Path(__file__).resolve().parent / "rules.yaml"
DEFAULT_LOG = PROJECT_ROOT / "logs" / "defender_events.jsonl"


def run_defender(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        sys.stderr.write("error: eBPF probes require root privileges. Run with sudo.\n")
        return 1

    if not args.sensor.exists() or not args.bpf_obj.exists():
        sys.stderr.write("error: eBPF binaries not found. Run 'make' first.\n")
        return 1

    args.log.parent.mkdir(parents=True, exist_ok=True)
    classifier = HeuristicClassifier(args.rules)
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

    mode = "dry-run" if args.dry_run else "active-sigstop"
    print(f"[defender] listening via {args.sensor} (mode={mode})", flush=True)

    with open(args.log, "a", encoding="utf-8") as log_file:
        assert proc.stdout is not None
        for line in proc.stdout:
            if stop_requested:
                break

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            pid = int(event.get("pid", 0))
            if pid in (own_pid, proc.pid):
                continue

            ev_type = event.get("type", "")
            inspect_entropy = ev_type in ("execveat", "execve_fd")
            ctx = collect_context(
                pid=pid,
                fallback_ppid=int(event.get("ppid", 0)),
                fd=int(event.get("fd", -1)),
                inspect_entropy=inspect_entropy,
            )
            verdict = classifier.evaluate(event, ctx)
            if verdict.action == "ALREADY_FROZEN":
                continue

            display_action = verdict.action
            mtti_ms = None
            mitigation_err = None

            if verdict.action == "FREEZE":
                if args.dry_run:
                    display_action = "WOULD_FREEZE"
                else:
                    res = freeze_process(pid, int(event["ktime_ns"]))
                    mtti_ms = res.mtti_ms
                    mitigation_err = res.error
                    if res.success:
                        classifier.mark_frozen(pid)
                        display_action = "FROZEN"
                    else:
                        display_action = "FREEZE_ERR"

            ts = time.strftime("%H:%M:%S")
            record = {
                "ts": ts,
                "epoch": time.time(),
                "pid": pid,
                "ppid": ctx.ppid,
                "type": ev_type,
                "comm": event.get("comm", ""),
                "name": event.get("name", ""),
                "exe": ctx.exe,
                "ancestry": [c for _, c in ctx.ancestry],
                "score": verdict.score,
                "entropy": verdict.entropy,
                "action": display_action,
                "mtti_ms": mtti_ms,
                "error": mitigation_err,
                "reasons": verdict.reasons,
            }
            log_file.write(json.dumps(record) + "\n")
            log_file.flush()

            if args.show_all or display_action != "ALLOW":
                label = f"{record['comm']}->{record['name']}" if record["name"] else record["comm"]
                mtti_str = f"{mtti_ms:.3f}ms" if mtti_ms is not None else "-"
                ent_str = f"{verdict.entropy:.2f}" if verdict.entropy is not None else "-"
                reason_str = "; ".join(verdict.reasons)
                if mitigation_err:
                    reason_str = f"{reason_str} (err={mitigation_err})"
                print(
                    f"[{ts}] pid={pid} event={ev_type} label={label} "
                    f"score={verdict.score} entropy={ent_str} action={display_action} "
                    f"mtti={mtti_str} reasons={reason_str}",
                    flush=True,
                )

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

    if proc.returncode not in (0, None, -signal.SIGTERM, -signal.SIGINT):
        err_out = proc.stderr.read() if proc.stderr else ""
        if err_out:
            sys.stderr.write(err_out)
        return proc.returncode

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Autonomous eBPF fileless malware defender (heuristic)")
    parser.add_argument("--sensor", type=Path, default=DEFAULT_SENSOR, help="Path to compiled eBPF sensor binary")
    parser.add_argument("--bpf-obj", type=Path, default=DEFAULT_BPF_OBJ, help="Path to compiled probes.bpf.o")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Path to rules.yaml")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="Path to JSONL event log")
    parser.add_argument("--dry-run", action="store_true", help="Classify and log without sending SIGSTOP")
    parser.add_argument("--show-all", action="store_true", help="Print benign ALLOW events as well")
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(run_defender(parse_args()))
