#!/usr/bin/env python3
import argparse
import json
import mimetypes
import os
import platform
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFENDER_DIR = PROJECT_ROOT / "defender_heuristic"
sys.path.insert(0, str(DEFENDER_DIR))

from mitigator import kill_process, resume_process  # noqa: E402

DEFENDER_SCRIPT = DEFENDER_DIR / "main.py"
MODEL_FILE = PROJECT_ROOT / "defender_ml" / "model.joblib"
ML_METRICS_FILE = PROJECT_ROOT / "defender_ml" / "metrics.json"
LOG_FILE = PROJECT_ROOT / "logs" / "defender_events.jsonl"
LOADER_BIN = PROJECT_ROOT / "red_team" / "build" / "loader"
VERIFY_IO_SCRIPT = PROJECT_ROOT / "evaluation" / "verify_disk_io.py"
FIM_SCRIPT = PROJECT_ROOT / "evaluation" / "fim_baseline.py"
FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"

shutdown_event = threading.Event()


def read_ml_metrics() -> Optional[dict]:
    if not ML_METRICS_FILE.exists():
        return None
    try:
        return json.loads(ML_METRICS_FILE.read_text(encoding="utf-8"))
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


class ConsoleHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockC2Server:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.lock = threading.Lock()
        self.leaks: List[dict] = []
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
                raw = conn.recv(512).decode("utf-8", errors="replace").strip()
                conn.close()
                if raw:
                    entry = {
                        "ts": time.strftime("%H:%M:%S"),
                        "bytes": len(raw.encode("utf-8")),
                        "payload": raw,
                    }
                    with self.lock:
                        self.leaks.append(entry)
                        if len(self.leaks) > 50:
                            self.leaks = self.leaks[-50:]
            except socket.timeout:
                continue
            except OSError:
                break

    def snapshot(self) -> List[dict]:
        with self.lock:
            return list(self.leaks)

    def clear(self) -> None:
        with self.lock:
            self.leaks.clear()

    def close(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class DefenderController:
    def __init__(self, log_path: Path, c2: MockC2Server):
        self.log_path = log_path
        self.c2 = c2
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None
        self.kernel_freeze = True
        self.engine = "heuristic"
        self.last_error: Optional[str] = None
        self.events: List[dict] = []
        self.subscribers: List[queue.Queue] = []
        self.disk_io_proof: Optional[dict] = None
        self.fim_proof: Optional[dict] = None
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

        while not shutdown_event.is_set():
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
                            if len(self.events) > 300:
                                self.events = self.events[-300:]
                        self._broadcast("telemetry", rec)
            except OSError:
                pass
            time.sleep(0.1)

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

    def start(self, kernel_freeze: Optional[bool] = None, engine: Optional[str] = None) -> dict:
        with self.lock:
            if kernel_freeze is not None:
                self.kernel_freeze = kernel_freeze
            if engine in ("heuristic", "ml"):
                self.engine = engine
            if self.is_running():
                return self.get_status_unlocked()
            if os.geteuid() != 0:
                self.last_error = "Root privileges required. Start ui/server.py with sudo."
                return self.get_status_unlocked()
            if self.engine == "ml" and not MODEL_FILE.exists():
                self.last_error = "ML model bundle missing. Run 'python3 defender_ml/train.py'."
                return self.get_status_unlocked()

            cmd = [
                sys.executable,
                str(DEFENDER_SCRIPT),
                "--show-all",
                "--engine",
                self.engine,
                "--log",
                str(self.log_path),
            ]
            if self.kernel_freeze:
                cmd.append("--kernel-freeze")

            self.last_error = None
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )

        time.sleep(0.55)
        with self.lock:
            if self.proc is not None and self.proc.poll() is not None:
                err_txt = self.proc.stderr.read().strip() if self.proc.stderr else "defender exited"
                self.last_error = err_txt or "defender exited unexpectedly"
                self.proc = None
            status = self.get_status_unlocked()

        self._broadcast("status", {"status": status, "quarantine": self.get_quarantine(), "c2_leaks": self.c2.snapshot()})
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

        self._broadcast("status", {"status": status, "quarantine": self.get_quarantine(), "c2_leaks": self.c2.snapshot()})
        return status

    def reconfigure(self, kernel_freeze: Optional[bool] = None, engine: Optional[str] = None) -> dict:
        was_running = self.is_running()
        if was_running:
            self.stop()
        with self.lock:
            if kernel_freeze is not None:
                self.kernel_freeze = kernel_freeze
            if engine in ("heuristic", "ml"):
                self.engine = engine
        if was_running:
            return self.start(kernel_freeze=self.kernel_freeze, engine=self.engine)
        status = self.get_status()
        self._broadcast("status", {"status": status, "quarantine": self.get_quarantine(), "c2_leaks": self.c2.snapshot()})
        return status

    def clear_all(self) -> None:
        with self.lock:
            self.events = []
        self.c2.clear()
        try:
            self.log_path.write_text("", encoding="utf-8")
        except OSError:
            pass
        self._broadcast("cleared", {"ok": True})

    def get_quarantine(self) -> List[int]:
        with self.lock:
            frozen_pids = {int(ev["pid"]) for ev in self.events if ev.get("action") == "FROZEN"}
        alive_stopped = []
        for pid in sorted(frozen_pids, reverse=True):
            if read_proc_state(pid).startswith("T"):
                alive_stopped.append(pid)
        return alive_stopped

    def get_status_unlocked(self) -> dict:
        running = self.is_running()
        rss_mb = read_rss_mb(self.proc.pid) if running and self.proc else 0.0
        frozen_events = [e for e in self.events if e.get("action") == "FROZEN"]
        allow_events = [e for e in self.events if e.get("action") == "ALLOW"]
        mttis = [float(e["mtti_ms"]) for e in frozen_events if e.get("mtti_ms") is not None]
        avg_mtti = round(sum(mttis) / len(mttis), 4) if mttis else None
        leaks = self.c2.snapshot()

        compared = [e for e in self.events if e.get("agree") is not None]
        agreed = sum(1 for e in compared if e.get("agree") is True)
        agreement_rate = round((agreed / len(compared)) * 100.0, 1) if compared else None

        heur_times = [float(e["heur_ms"]) for e in self.events if isinstance(e.get("heur_ms"), (int, float))]
        ml_times = [float(e["ml_ms"]) for e in self.events if isinstance(e.get("ml_ms"), (int, float))]

        return {
            "running": running,
            "engine": self.engine,
            "mode": "in-kernel" if self.kernel_freeze else "userspace",
            "kernel_freeze": self.kernel_freeze,
            "is_root": os.geteuid() == 0,
            "kernel": platform.release(),
            "probes": 6,
            "c2_port": self.c2.port,
            "rss_mb": rss_mb,
            "total_events": len(self.events),
            "frozen_count": len(frozen_events),
            "allowed_count": len(allow_events),
            "avg_mtti_ms": avg_mtti,
            "c2_leak_count": len(leaks),
            "c2_leak_bytes": sum(item["bytes"] for item in leaks),
            "ml_available": MODEL_FILE.exists(),
            "ml_metrics": read_ml_metrics(),
            "compared_count": len(compared),
            "agreement_rate": agreement_rate,
            "avg_heuristic_infer_ms": round(sum(heur_times) / len(heur_times), 4) if heur_times else None,
            "avg_ml_infer_ms": round(sum(ml_times) / len(ml_times), 4) if ml_times else None,
            "disk_io_proof": self.disk_io_proof,
            "fim_proof": self.fim_proof,
            "last_error": self.last_error,
        }

    def get_status(self) -> dict:
        with self.lock:
            return self.get_status_unlocked()

    def get_events(self) -> List[dict]:
        with self.lock:
            return list(self.events)


c2_server = MockC2Server()
controller = DefenderController(LOG_FILE, c2_server)


def run_demo_command(action: str) -> dict:
    if action == "attack":
        if not LOADER_BIN.exists():
            return {"ok": False, "error": "loader binary missing; run make first"}
        before_leaks = len(c2_server.snapshot())
        proc = subprocess.Popen(
            [str(LOADER_BIN), "--ticks", "20", "--exfil-port", str(c2_server.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        threading.Thread(target=proc.wait, daemon=True).start()
        time.sleep(0.28)
        state = read_proc_state(proc.pid)
        after_leaks = len(c2_server.snapshot())
        return {
            "ok": True,
            "pid": proc.pid,
            "proc_state": state,
            "frozen": state.startswith("T"),
            "leaked": after_leaks > before_leaks,
        }

    if action == "benign":
        if not LOADER_BIN.exists():
            return {"ok": False, "error": "loader binary missing; run make first"}
        res = subprocess.run([str(LOADER_BIN), "--benign-memfd"], capture_output=True, text=True, timeout=5)
        return {"ok": res.returncode == 0}

    if action in ("disk-io", "fim"):
        was_running = controller.is_running()
        if was_running:
            controller.stop()
        try:
            script = VERIFY_IO_SCRIPT if action == "disk-io" else FIM_SCRIPT
            res = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=10)
            raw = (res.stdout + res.stderr).strip()
            if action == "disk-io":
                write_b = 0
                ram_b = 0
                for line in raw.splitlines():
                    if "physical write_bytes" in line:
                        try:
                            write_b = int(line.split(":", 1)[1].strip().split()[0])
                        except ValueError:
                            pass
                    elif "logical wchar" in line:
                        try:
                            ram_b = int(line.split(":", 1)[1].strip().split()[0])
                        except ValueError:
                            pass
                proof = {"ok": res.returncode == 0, "write_bytes": write_b, "ram_bytes": ram_b, "ts": time.strftime("%H:%M:%S")}
                controller.disk_io_proof = proof
                return proof
            else:
                detected = 0
                for line in raw.splitlines():
                    if "fileless payload detected" in line:
                        try:
                            detected = int(line.split(":", 1)[1].strip().split()[0])
                        except ValueError:
                            pass
                proof = {"ok": res.returncode == 0, "detected": detected, "ts": time.strftime("%H:%M:%S")}
                controller.fim_proof = proof
                return proof
        finally:
            if was_running:
                controller.start()

    return {"ok": False, "error": f"unknown action: {action}"}


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
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/status":
            self._send_json(controller.get_status())
            return

        if path == "/api/ml/metrics":
            self._send_json({"available": MODEL_FILE.exists(), "metrics": read_ml_metrics()})
            return

        if path == "/api/events":
            self._send_json({
                "events": controller.get_events(),
                "quarantine": controller.get_quarantine(),
                "c2_leaks": c2_server.snapshot(),
                "status": controller.get_status(),
            })
            return

        if path == "/api/stream":
            self._handle_sse()
            return

        self._serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        body = self._read_json_body()

        if path == "/api/defender/start":
            kf = body.get("kernel_freeze")
            eng = body.get("engine")
            self._send_json(
                controller.start(
                    kernel_freeze=bool(kf) if kf is not None else None,
                    engine=str(eng) if eng in ("heuristic", "ml") else None,
                )
            )
            return

        if path == "/api/defender/stop":
            self._send_json(controller.stop())
            return

        if path == "/api/defender/mode":
            kf = body.get("kernel_freeze")
            eng = body.get("engine")
            self._send_json(
                controller.reconfigure(
                    kernel_freeze=bool(kf) if kf is not None else None,
                    engine=str(eng) if eng in ("heuristic", "ml") else None,
                )
            )
            return

        if path == "/api/events/clear":
            controller.clear_all()
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
                    "error": err,
                    "quarantine": controller.get_quarantine(),
                })
                return

        if path.startswith("/api/demo/"):
            action = path.split("/api/demo/", 1)[1]
            self._send_json(run_demo_command(action))
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
            snap = {
                "status": controller.get_status(),
                "quarantine": controller.get_quarantine(),
                "c2_leaks": c2_server.snapshot(),
            }
            self.wfile.write(f"event: status\ndata: {json.dumps(snap)}\n\n".encode("utf-8"))
            self.wfile.flush()

            idle_ticks = 0
            while not shutdown_event.is_set():
                try:
                    ev_name, payload = q.get(timeout=1.0)
                    idle_ticks = 0
                    self.wfile.write(f"event: {ev_name}\ndata: {json.dumps(payload)}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    idle_ticks += 1
                    if idle_ticks >= 4:
                        idle_ticks = 0
                        hb = {
                            "status": controller.get_status(),
                            "quarantine": controller.get_quarantine(),
                            "c2_leaks": c2_server.snapshot(),
                        }
                        self.wfile.write(f"event: status\ndata: {json.dumps(hb)}\n\n".encode("utf-8"))
                        self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            controller.unsubscribe(q)

    def _serve_static(self, req_path: str) -> None:
        if not FRONTEND_DIST.exists():
            msg = b"Frontend bundle not built. Run 'cd ui/frontend && npm run build'."
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
    parser = argparse.ArgumentParser(description="MemGuard eBPF Console API and static server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8080, help="Bind port")
    parser.add_argument("--engine", choices=["heuristic", "ml"], default="heuristic", help="Initial classifier engine")
    parser.add_argument("--userspace", action="store_true", help="Default to userspace pidfd_send_signal mode")
    parser.add_argument("--auto-start", action="store_true", help="Start the eBPF defender automatically")
    args = parser.parse_args()

    controller.engine = args.engine
    if args.userspace:
        controller.kernel_freeze = False
    if args.auto_start:
        controller.start()

    server = ConsoleHTTPServer((args.host, args.port), ConsoleHandler)

    def _shutdown(signum, frame):
        shutdown_event.set()
        controller.stop()
        c2_server.close()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(
        f"[ui] console listening on http://{args.host}:{args.port} "
        f"(engine={controller.engine}, mock C2 on 127.0.0.1:{c2_server.port})",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        shutdown_event.set()
        controller.stop()
        c2_server.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
