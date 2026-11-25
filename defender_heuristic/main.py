#!/usr/bin/env python3
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from classifier import HeuristicClassifier
from forensics import capture_ram_forensics
from mitigator import freeze_process
from telemetry import collect_context

DEFAULT_SENSOR = PROJECT_ROOT / "ebpf" / "build" / "sensor"
DEFAULT_BPF_OBJ = PROJECT_ROOT / "ebpf" / "build" / "probes.bpf.o"
DEFAULT_RULES = Path(__file__).resolve().parent / "rules.yaml"
DEFAULT_MODEL = PROJECT_ROOT / "defender_ml" / "model.joblib"
DEFAULT_LOG = PROJECT_ROOT / "logs" / "defender_events.jsonl"


def _load_ml_classifier(model_path: Path, rules_path: Path, required: bool):
    try:
        from defender_ml.classifier import MLClassifier

        return MLClassifier(model_path=model_path, rules_path=rules_path)
    except Exception as exc:
        if required:
            sys.stderr.write(f"error: unable to load ML classifier ({exc}).\n")
            sys.stderr.write("hint: install scikit-learn/joblib/numpy and run 'python3 defender_ml/train.py'.\n")
            raise
        return None


def run_defender(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        sys.stderr.write("error: eBPF probes require root privileges. Run with sudo.\n")
        return 1

    if not args.sensor.exists() or not args.bpf_obj.exists():
        sys.stderr.write("error: eBPF binaries not found. Run 'make' first.\n")
        return 1

    args.log.parent.mkdir(parents=True, exist_ok=True)
    heur_clf = HeuristicClassifier(args.rules)

    ml_clf = None
    if args.engine == "ml":
        try:
            ml_clf = _load_ml_classifier(args.model, args.rules, required=True)
        except Exception:
            return 1
    elif not args.no_shadow and args.model.exists():
        ml_clf = _load_ml_classifier(args.model, args.rules, required=False)

    own_pid = os.getpid()
    sensor_cmd = [str(args.sensor), str(args.bpf_obj)]
    if args.kernel_freeze and not args.dry_run:
        sensor_cmd.append("--kernel-freeze")

    proc = subprocess.Popen(
        sensor_cmd,
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

    mode = "dry-run" if args.dry_run else ("in-kernel" if args.kernel_freeze else "userspace")
    shadow_str = "on" if (ml_clf is not None) else "off"
    print(f"[defender] listening via {args.sensor} (engine={args.engine}, mode={mode}, shadow={shadow_str})", flush=True)

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
            kernel_frozen = bool(event.get("kernel_frozen", False))
            inspect_entropy = ev_type in ("execveat", "execve_fd")
            ctx = collect_context(
                pid=pid,
                fallback_ppid=int(event.get("ppid", 0)),
                fd=int(event.get("fd", -1)),
                inspect_entropy=inspect_entropy,
            )

            t_h0 = time.perf_counter()
            heur_verdict = heur_clf.evaluate(event, ctx)
            heur_ms = round((time.perf_counter() - t_h0) * 1000.0, 4)

            ml_verdict = None
            if ml_clf is not None and (args.engine == "ml" or not args.no_shadow):
                ml_verdict = ml_clf.evaluate(event, ctx)

            verdict = ml_verdict if (args.engine == "ml" and ml_verdict is not None) else heur_verdict
            if verdict.action == "ALREADY_FROZEN":
                continue

            display_action = verdict.action
            mtti_ms = None
            mitigation_err = None
            freeze_mode = "in-kernel" if kernel_frozen else "userspace"

            if kernel_frozen:
                ktime_ns = int(event.get("ktime_ns", 0))
                fktime_ns = int(event.get("freeze_ktime_ns", 0))
                if fktime_ns >= ktime_ns and ktime_ns > 0:
                    mtti_ms = round((fktime_ns - ktime_ns) / 1_000_000.0, 4)
                else:
                    mtti_ms = 0.005
                heur_clf.mark_frozen(pid)
                if ml_clf is not None:
                    ml_clf.mark_frozen(pid)
                display_action = "FROZEN"
                verdict.reasons.append("frozen synchronously in-kernel via bpf_send_signal(SIGSTOP)")
            elif verdict.action == "FREEZE":
                if args.dry_run:
                    display_action = "WOULD_FREEZE"
                else:
                    res = freeze_process(pid, int(event["ktime_ns"]))
                    mtti_ms = res.mtti_ms
                    mitigation_err = res.error
                    if res.success:
                        heur_clf.mark_frozen(pid)
                        if ml_clf is not None:
                            ml_clf.mark_frozen(pid)
                        display_action = "FROZEN"
                    else:
                        display_action = "FREEZE_ERR"

            agree = None
            if ml_verdict is not None and heur_verdict.action != "ALREADY_FROZEN" and ml_verdict.action != "ALREADY_FROZEN":
                agree = heur_verdict.action == ml_verdict.action

            forensics = None
            if display_action == "FROZEN" and not args.no_forensics:
                forensics = capture_ram_forensics(pid=pid, fd=int(event.get("fd", -1)))

            ts = time.strftime("%H:%M:%S")
            record = {
                "ts": ts,
                "epoch": time.time(),
                "pid": pid,
                "ppid": ctx.ppid,
                "type": ev_type,
                "comm": event.get("comm", ""),
                "name": event.get("name", ""),
                "vfs_memfd": bool(event.get("vfs_memfd", False)),
                "vfs_ino": int(event.get("vfs_ino", 0) or 0),
                "vfs_name": event.get("vfs_name", ""),
                "exe": ctx.exe,
                "ancestry": [c for _, c in ctx.ancestry],
                "engine": args.engine,
                "score": verdict.score,
                "entropy": verdict.entropy,
                "action": display_action,
                "freeze_mode": freeze_mode if display_action == "FROZEN" else None,
                "mtti_ms": mtti_ms,
                "error": mitigation_err,
                "reasons": verdict.reasons,
                "forensics": forensics,
                "heur_action": heur_verdict.action,
                "heur_score": heur_verdict.score,
                "heur_ms": heur_ms,
                "ml_action": ml_verdict.action if ml_verdict is not None else None,
                "ml_prob": ml_verdict.prob if ml_verdict is not None else None,
                "ml_ms": ml_verdict.infer_ms if ml_verdict is not None else None,
                "agree": agree,
            }
            log_file.write(json.dumps(record) + "\n")
            log_file.flush()

            if args.show_all or display_action != "ALLOW":
                label = f"{record['comm']}->{record['name']}" if record["name"] else record["comm"]
                mtti_str = f"{mtti_ms:.4f}ms" if mtti_ms is not None else "-"
                ent_str = f"{verdict.entropy:.2f}" if verdict.entropy is not None else "-"
                ml_str = f" ml={ml_verdict.action}({ml_verdict.prob:.2f})" if ml_verdict is not None else ""
                reason_str = "; ".join(verdict.reasons)
                if mitigation_err:
                    reason_str = f"{reason_str} (err={mitigation_err})"
                print(
                    f"[{ts}] pid={pid} event={ev_type} label={label} engine={args.engine} "
                    f"score={verdict.score} entropy={ent_str} action={display_action} "
                    f"mode={freeze_mode} mtti={mtti_str}{ml_str} reasons={reason_str}",
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
    parser = argparse.ArgumentParser(description="Autonomous eBPF fileless malware defender")
    parser.add_argument("--sensor", type=Path, default=DEFAULT_SENSOR, help="Path to compiled eBPF sensor binary")
    parser.add_argument("--bpf-obj", type=Path, default=DEFAULT_BPF_OBJ, help="Path to compiled probes.bpf.o")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Path to rules.yaml")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL, help="Path to trained ML joblib bundle")
    parser.add_argument("--engine", choices=["heuristic", "ml"], default="heuristic", help="Active classifier engine")
    parser.add_argument("--no-shadow", action="store_true", help="Disable shadow ML scoring when engine=heuristic")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="Path to JSONL event log")
    parser.add_argument("--kernel-freeze", action="store_true", help="Freeze tracked memfd exec inside eBPF via bpf_send_signal")
    parser.add_argument("--no-forensics", action="store_true", help="Disable automatic RAM ELF forensic carving")
    parser.add_argument("--dry-run", action="store_true", help="Classify and log without sending SIGSTOP")
    parser.add_argument("--show-all", action="store_true", help="Print benign ALLOW events as well")
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(run_defender(parse_args()))
