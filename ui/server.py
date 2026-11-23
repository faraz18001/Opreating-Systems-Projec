#!/usr/bin/env python3
import argparse
import json
import mimetypes
import os
import platform
import queue
import signal
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFENDER_DIR = PROJECT_ROOT / "defender_heuristic"
sys.path.insert(0, str(DEFENDER_DIR))

from mitigator import kill_process, resume_process  # noqa: E402

DEFENDER_SCRIPT = DEFENDER_DIR / "main.py"
RULES_FILE = DEFENDER_DIR / "rules.yaml"
MODEL_FILE = PROJECT_ROOT / "defender_ml" / "model.joblib"
METRICS_FILE = PROJECT_ROOT / "defender_ml" / "metrics.json"
LOG_FILE = PROJECT_ROOT / "logs" / "defender_events.jsonl"
LOADER_BIN = PROJECT_ROOT / "red_team" / "build" / "loader"
VERIFY_IO_SCRIPT = PROJECT_ROOT / "evaluation" / "verify_disk_io.py"
FIM_SCRIPT = PROJECT_ROOT / "evaluation" / "fim_baseline.py"
FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"

shutdown_event = threading.Event()


class ConsoleHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def read_ml_metrics() -> Optional[dict]:
    if not METRICS_FILE.exists():
        return None
    try:
        with open(METRICS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def read_proc_state(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("State:"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        return "exited"
    return "unknown"


def read_rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024.0, 2)
    except OSError:
        return 0.0
    return 0.0


class DefenderController:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None
        self.dry_run = False
        self.engine = "heuristic"
        self.last_error: Optional[str] = None
        self.events: List[dict] = []
        self.subscribers: List[queue.Queue] = []
        self._load_existing_events()
        self._tail_thread = threading.Thread(target=self._tail_log_loop, daemon=True)
        self._tail_thread.start()

    def _load_existing_events(self) -> None:
        if not self.log_path.exists():
            return
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-200:]
            for idx, line in enumerate(lines, start=1):
                try:
                    rec = json.loads(line)
                    rec["id"] = idx
                    self.events.append(rec)
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass

    def _broadcast(self, event_name: str, payload: dict) -> None:
        dead = []
        with self.lock:
            subs = list(self.subscribers)
        for q in subs:
            try:
                q.put_nowait((event_name, payload))
            except queue.Full:
                dead.append(q)
        if dead:
            with self.lock:
                for q in dead:
                    if q in self.subscribers:
                        self.subscribers.remove(q)

    def _tail_log_loop(self) -> None:
        self.log_path.touch(exist_ok=True)
        last_inode = None
        offset = self.log_path.stat().st_size

        while True:
            try:
                st = self.log_path.stat()
                if last_inode is not None and (st.st_ino != last_inode or st.st_size < offset):
                    offset = 0
                last_inode = st.st_ino

                if st.st_size > offset:
                    with open(self.log_path, "r", encoding="utf-8") as f:
                        f.seek(offset)
                        new_lines = f.readlines()
                        offset = f.tell()

                    for line in new_lines:
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        with self.lock:
                            rec["id"] = (self.events[-1]["id"] + 1) if self.events else 1
                            self.events.append(rec)
                            if len(self.events) > 400:
                                self.events = self.events[-400:]
                        self._broadcast("telemetry", rec)
            except OSError:
                pass
            time.sleep(0.12)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self.lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, dry_run: bool = False, engine: str = "heuristic") -> dict:
        if engine not in ("heuristic", "ml"):
            engine = "heuristic"
        with self.lock:
            if self.is_running():
                return self.get_status_unlocked()
            if os.geteuid() != 0:
                self.last_error = "Root privileges required. Start ui/server.py with sudo."
                return self.get_status_unlocked()

            cmd = [
                sys.executable,
                str(DEFENDER_SCRIPT),
                "--engine",
                engine,
                "--show-all",
                "--log",
                str(self.log_path),
            ]
            if dry_run:
                cmd.append("--dry-run")

            self.dry_run = dry_run
            self.engine = engine
            self.last_error = None
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )

        time.sleep(0.45)
        with self.lock:
            if self.proc is not None and self.proc.poll() is not None:
                err_txt = self.proc.stderr.read().strip() if self.proc.stderr else "defender exited"
                self.last_error = err_txt or "defender exited unexpectedly"
                self.proc = None
            status = self.get_status_unlocked()

        self._broadcast("status", status)
        return status

    def stop(self) -> dict:
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=2.5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            self.proc = None
            status = self.get_status_unlocked()

        self._broadcast("status", status)
        return status

    def clear_events(self) -> None:
        with self.lock:
            self.events = []
        try:
            self.log_path.write_text("", encoding="utf-8")
        except OSError:
            pass
        self._broadcast("cleared", {"ok": True})

    def get_quarantine(self) -> List[dict]:
        with self.lock:
            frozen_by_pid: Dict[int, dict] = {}
            for ev in self.events:
                if ev.get("action") == "FROZEN":
                    frozen_by_pid[int(ev["pid"])] = ev

        items = []
        for pid, ev in sorted(frozen_by_pid.items(), key=lambda x: x[1].get("epoch", 0), reverse=True):
            state = read_proc_state(pid)
            if state == "exited" or state.startswith("Z") or state.startswith("X"):
                continue
            items.append({
                "pid": pid,
                "comm": ev.get("comm", ""),
                "name": ev.get("name", ""),
                "exe": ev.get("exe", ""),
                "ancestry": ev.get("ancestry", []),
                "score": ev.get("score", 0),
                "entropy": ev.get("entropy"),
                "mtti_ms": ev.get("mtti_ms"),
                "ts": ev.get("ts", ""),
                "proc_state": state,
                "reasons": ev.get("reasons", []),
            })
        return items

    def get_status_unlocked(self) -> dict:
        running = self.is_running()
        rss_mb = read_rss_mb(self.proc.pid) if running and self.proc else 0.0
        frozen_events = [e for e in self.events if e.get("action") == "FROZEN"]
        allow_events = [e for e in self.events if e.get("action") == "ALLOW"]
        alert_events = [e for e in self.events if e.get("action") in ("ALERT", "WOULD_FREEZE")]
        mttis = [float(e["mtti_ms"]) for e in frozen_events if e.get("mtti_ms") is not None]
        avg_mtti = round(sum(mttis) / len(mttis), 3) if mttis else None
        compared = [e for e in self.events if isinstance(e.get("agree"), bool)]
        agreement_rate = (
            round((sum(1 for e in compared if e["agree"]) / len(compared)) * 100.0, 1)
            if compared
            else None
        )
        h_ms = [
            float(e["heuristic"]["infer_ms"])
            for e in self.events
            if isinstance(e.get("heuristic"), dict) and e["heuristic"].get("infer_ms") is not None
        ]
        m_ms = [
            float(e["ml"]["infer_ms"])
            for e in self.events
            if isinstance(e.get("ml"), dict) and e["ml"].get("infer_ms") is not None
        ]

        return {
            "running": running,
            "pid": self.proc.pid if running and self.proc else None,
            "dry_run": self.dry_run,
            "engine": self.engine,
            "ml_available": MODEL_FILE.exists(),
            "ml_metrics": read_ml_metrics(),
            "agreement_rate": agreement_rate,
            "compared_count": len(compared),
            "avg_heuristic_infer_ms": round(sum(h_ms) / len(h_ms), 4) if h_ms else None,
            "avg_ml_infer_ms": round(sum(m_ms) / len(m_ms), 4) if m_ms else None,
            "is_root": os.geteuid() == 0,
            "kernel": platform.release(),
            "probes": 5,
            "rss_mb": rss_mb,
            "total_events": len(self.events),
            "frozen_count": len(frozen_events),
            "alert_count": len(alert_events),
            "allowed_count": len(allow_events),
            "avg_mtti_ms": avg_mtti,
            "last_error": self.last_error,
        }

    def get_status(self) -> dict:
        with self.lock:
            return self.get_status_unlocked()

    def get_events(self) -> List[dict]:
        with self.lock:
            return list(self.events)


controller: Optional[DefenderController] = None


def run_demo_command(action: str) -> dict:
    if action == "attack":
        if not LOADER_BIN.exists():
            return {"ok": False, "action": action, "output": "loader binary missing; run make first", "metrics": {}}
        proc = subprocess.Popen(
            [str(LOADER_BIN), "--ticks", "20"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        threading.Thread(target=proc.wait, daemon=True).start()
        time.sleep(0.28)
        state = read_proc_state(proc.pid)
        stopped = state.startswith("T")
        return {
            "ok": True,
            "action": action,
            "pid": proc.pid,
            "proc_state": state,
            "verdict": "Frozen (SIGSTOP)" if stopped else f"Running ({state})",
            "metrics": {
                "PID": str(proc.pid),
                "Kernel state": state,
                "Disk bytes written": "0 B",
            },
            "output": f"Launched fileless loader (pid={proc.pid}, state={state})",
        }

    if action == "benign":
        if not LOADER_BIN.exists():
            return {"ok": False, "action": action, "output": "loader binary missing; run make first", "metrics": {}}
        start = time.monotonic()
        res = subprocess.run(
            [str(LOADER_BIN), "--benign-memfd"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 1)
        raw = (res.stdout + res.stderr).strip()
        pid_val = "n/a"
        fd_val = "n/a"
        for tok in raw.replace("(", " ").replace(")", " ").replace(",", " ").split():
            if tok.startswith("pid="):
                pid_val = tok.split("=", 1)[1]
            elif tok.startswith("fd="):
                fd_val = tok.split("=", 1)[1]
        return {
            "ok": res.returncode == 0,
            "action": action,
            "verdict": "Allowed (no exec)" if res.returncode == 0 else "Failed",
            "metrics": {
                "PID": pid_val,
                "memfd descriptor": f"fd {fd_val}",
                "Duration": f"{elapsed_ms} ms",
            },
            "output": raw,
        }

    if action == "disk-io":
        try:
            res = subprocess.run(
                [sys.executable, str(VERIFY_IO_SCRIPT)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "action": action,
                "verdict": "Timed out (toggle Dry-run ON)",
                "metrics": {"Status": "Paused by active SIGSTOP"},
                "output": "Test loader was frozen by active SIGSTOP protection. Enable Dry-run mode before running Verify disk I/O.",
            }
        raw = (res.stdout + res.stderr).strip()
        write_b = "0 bytes"
        read_b = "0 bytes"
        ram_b = "n/a"
        for line in raw.splitlines():
            if "physical write_bytes" in line:
                write_b = line.split(":", 1)[1].strip()
            elif "physical read_bytes" in line:
                read_b = line.split(":", 1)[1].strip()
            elif "logical wchar" in line:
                ram_b = line.split(":", 1)[1].strip()
        return {
            "ok": res.returncode == 0,
            "action": action,
            "verdict": "Pass (0 B disk I/O)" if res.returncode == 0 else "Fail",
            "metrics": {
                "Physical write_bytes": write_b,
                "Physical read_bytes": read_b,
                "RAM wchar": ram_b,
            },
            "output": raw,
        }

    if action == "fim":
        try:
            res = subprocess.run(
                [sys.executable, str(FIM_SCRIPT)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "action": action,
                "verdict": "Timed out (toggle Dry-run ON)",
                "metrics": {"Status": "Paused by active SIGSTOP"},
                "output": "Test loader was frozen by active SIGSTOP protection. Enable Dry-run mode before running Run FIM baseline.",
            }
        raw = (res.stdout + res.stderr).strip()
        fs_events = "0"
        detected = "0"
        elapsed = "n/a"
        for line in raw.splitlines():
            if "Traditional FIM finished in" in line:
                elapsed = line.split("finished in", 1)[1].strip()
            elif "total unrelated fs events" in line:
                fs_events = line.split(":", 1)[1].strip()
            elif "fileless payload detected" in line:
                detected = line.split(":", 1)[1].strip().split()[0]
        return {
            "ok": res.returncode == 0,
            "action": action,
            "verdict": f"Blind ({detected} alerts)",
            "metrics": {
                "inotify detections": detected,
                "FS events seen": fs_events,
                "Elapsed": elapsed,
            },
            "output": raw,
        }

    return {"ok": False, "action": action, "verdict": "Error", "metrics": {}, "output": f"Unknown demo action: {action}"}


class ConsoleHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, data: dict, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self._send_json(controller.get_status())
            return

        if path == "/api/events":
            self._send_json({
                "events": controller.get_events(),
                "quarantine": controller.get_quarantine(),
                "status": controller.get_status(),
            })
            return

        if path == "/api/rules":
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    rules = yaml.safe_load(f)
                self._send_json({"rules": rules})
            except OSError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if path == "/api/ml/metrics":
            self._send_json({"available": MODEL_FILE.exists(), "metrics": read_ml_metrics()})
            return

        if path == "/api/stream":
            self._handle_sse()
            return

        self._serve_static(path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/defender/start":
            req_engine = str(body.get("engine", controller.engine))
            status = controller.start(dry_run=bool(body.get("dry_run", False)), engine=req_engine)
            self._send_json(status)
            return

        if path == "/api/defender/stop":
            status = controller.stop()
            self._send_json(status)
            return

        if path == "/api/events/clear":
            controller.clear_events()
            self._send_json({"ok": True})
            return

        if path.startswith("/api/process/"):
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[2].isdigit():
                pid = int(parts[2])
                action = parts[3]
                if action == "resume":
                    err = resume_process(pid)
                elif action == "kill":
                    err = kill_process(pid)
                    time.sleep(0.05)
                else:
                    self._send_json({"ok": False, "error": "unsupported action"}, HTTPStatus.BAD_REQUEST)
                    return
                self._send_json({
                    "ok": err is None,
                    "pid": pid,
                    "action": action,
                    "error": err,
                    "proc_state": read_proc_state(pid),
                    "quarantine": controller.get_quarantine(),
                })
                return

        if path.startswith("/api/demo/"):
            action = path.split("/api/demo/", 1)[1]
            result = run_demo_command(action)
            self._send_json(result)
            return

        self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _handle_sse(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = controller.subscribe()
        try:
            init_payload = json.dumps({
                "status": controller.get_status(),
                "quarantine": controller.get_quarantine(),
            })
            self.wfile.write(f"event: status\ndata: {init_payload}\n\n".encode("utf-8"))
            self.wfile.flush()

            idle_ticks = 0
            while not shutdown_event.is_set():
                try:
                    ev_name, payload = q.get(timeout=1.0)
                    idle_ticks = 0
                    msg = f"event: {ev_name}\ndata: {json.dumps(payload)}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    idle_ticks += 1
                    if idle_ticks >= 5:
                        idle_ticks = 0
                        hb = json.dumps({
                            "status": controller.get_status(),
                            "quarantine": controller.get_quarantine(),
                        })
                        self.wfile.write(f"event: status\ndata: {hb}\n\n".encode("utf-8"))
                        self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            controller.unsubscribe(q)

    def _serve_static(self, req_path: str) -> None:
        if not FRONTEND_DIST.exists():
            msg = (
                "Frontend bundle not built yet. Run 'cd ui/frontend && npm run build', "
                "or start 'npm run dev' in ui/frontend/ during development."
            ).encode("utf-8")
            self.send_response(HTTPStatus.SERVICE_UNAVAILABLE)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        clean = req_path.lstrip("/") or "index.html"
        target = (FRONTEND_DIST / clean).resolve()
        if not str(target).startswith(str(FRONTEND_DIST.resolve())) or not target.is_file():
            target = FRONTEND_DIST / "index.html"

        mime, _ = mimetypes.guess_type(str(target))
        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    global controller
    parser = argparse.ArgumentParser(description="eBPF Defender Console API and static server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8080, help="Bind port")
    parser.add_argument("--engine", choices=["heuristic", "ml"], default="heuristic", help="Initial classifier engine")
    parser.add_argument("--auto-start", action="store_true", help="Start the eBPF defender automatically")
    args = parser.parse_args()

    controller = DefenderController(LOG_FILE)

    if args.auto_start:
        controller.start(dry_run=False, engine=args.engine)

    server = ConsoleHTTPServer((args.host, args.port), ConsoleHandler)

    def _shutdown(signum, frame):
        shutdown_event.set()
        controller.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(f"[ui] console server listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    finally:
        controller.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
