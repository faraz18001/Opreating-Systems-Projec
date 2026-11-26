#!/usr/bin/env python3
import argparse
import json
import mimetypes
import os
import platform
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFENDER_DIR = PROJECT_ROOT / "defender_heuristic"
sys.path.insert(0, str(DEFENDER_DIR))

from mitigator import kill_process, resume_process  # noqa: E402

DEFENDER_SCRIPT = DEFENDER_DIR / "main.py"
MODEL_FILE = PROJECT_ROOT / "defender_ml" / "model.joblib"
ML_METRICS_FILE = PROJECT_ROOT / "defender_ml" / "metrics.json"
LOG_FILE = PROJECT_ROOT / "logs" / "defender_events.jsonl"
TRACES_DIR = PROJECT_ROOT / "logs" / "traces"
LOADER_BIN = PROJECT_ROOT / "red_team" / "build" / "loader"
VERIFY_IO_SCRIPT = PROJECT_ROOT / "evaluation" / "verify_disk_io.py"
FIM_SCRIPT = PROJECT_ROOT / "evaluation" / "fim_baseline.py"
FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"

TRACE_ID_RE = re.compile(r"TRC-\d{1,8}")
shutdown_event = threading.Event()


def _start_pipe_drainer(pipe) -> Callable[[], str]:
    """Drain a subprocess pipe asynchronously so SIGSTOP cannot deadlock reads
    and SIGCONT never hits SIGPIPE."""
    buf = bytearray()
    buf_lock = threading.Lock()

    def _drain() -> None:
        try:
            fd = pipe.fileno()
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                with buf_lock:
                    if len(buf) < 65536:
                        buf.extend(chunk[: 65536 - len(buf)])
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    threading.Thread(target=_drain, daemon=True).start()

    def _read() -> str:
        with buf_lock:
            return bytes(buf).decode("utf-8", errors="replace").strip()

    return _read


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
        self._seq = 0
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
                    with self.lock:
                        self._seq += 1
                        entry = {
                            "id": self._seq,
                            "ts": time.strftime("%H:%M:%S"),
                            "bytes": len(raw.encode("utf-8")),
                            "payload": raw,
                        }
                        self.leaks.append(entry)
                        if len(self.leaks) > 50:
                            self.leaks = self.leaks[-50:]
            except socket.timeout:
                continue
            except OSError:
                break

    def latest_id(self) -> int:
        with self.lock:
            return self._seq

    def snapshot_since(self, min_id: int) -> List[dict]:
        with self.lock:
            return [dict(item) for item in self.leaks if int(item.get("id", 0)) > min_id]

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
    def __init__(self, log_path: Path, c2: MockC2Server, traces_dir: Optional[Path] = None):
        self.log_path = log_path
        self.c2 = c2
        self.traces_dir = traces_dir or TRACES_DIR
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None
        self.kernel_freeze = True
        self.engine = "heuristic"
        self.last_error: Optional[str] = None
        self.events: List[dict] = []
        self.traces: List[dict] = []
        self._trace_seq = 0
        self.subscribers: List[queue.Queue] = []
        self.disk_io_proof: Optional[dict] = None
        self.fim_proof: Optional[dict] = None
        self._load_existing_events()
        self._load_existing_traces()
        self._tail_thread = threading.Thread(target=self._tail_log_loop, daemon=True)
        self._tail_thread.start()

    def _load_existing_traces(self) -> None:
        if not self.traces_dir.exists():
            return
        loaded = []
        max_seq = 0
        for p in sorted(self.traces_dir.glob("TRC-*.json")):
            m = re.fullmatch(r"TRC-(\d+)", p.stem)
            if not m:
                continue
            max_seq = max(max_seq, int(m.group(1)))
            try:
                trace = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(trace, dict) and trace.get("trace_id"):
                    loaded.append(trace)
            except (OSError, json.JSONDecodeError):
                continue
        loaded.sort(key=lambda t: (float(t.get("epoch", 0)), str(t.get("trace_id", ""))))
        self.traces = loaded[-200:]
        self._trace_seq = max_seq

        key_to_tid = {}
        for t in self.traces:
            tid = t["trace_id"]
            for ev in t.get("timeline") or []:
                key_to_tid[(ev.get("ts"), ev.get("pid"), ev.get("type"))] = tid
        for ev in self.events:
            tid = key_to_tid.get((ev.get("ts"), ev.get("pid"), ev.get("type")))
            if tid and not ev.get("trace_id"):
                ev["trace_id"] = tid

    @staticmethod
    def _trace_summary(trace: dict) -> dict:
        timeline = trace.get("timeline") or []
        return {
            "trace_id": trace.get("trace_id"),
            "ts": trace.get("ts"),
            "epoch": trace.get("epoch"),
            "duration_ms": trace.get("duration_ms"),
            "kind": trace.get("kind"),
            "vector": trace.get("vector"),
            "root_pid": trace.get("root_pid"),
            "related_pids": trace.get("related_pids") or [],
            "proc_state": trace.get("proc_state"),
            "exit_code": trace.get("exit_code"),
            "outcome": trace.get("outcome"),
            "frozen": trace.get("frozen"),
            "leaked": trace.get("leaked"),
            "new_quarantine_pids": trace.get("new_quarantine_pids") or [],
            "defender": trace.get("defender") or {},
            "summary": trace.get("summary") or {},
            "event_ids": [ev.get("id") for ev in timeline if ev.get("id") is not None],
            "types": list(dict.fromkeys(str(ev.get("type")) for ev in timeline if ev.get("type"))),
            "comms": list(dict.fromkeys(str(ev.get("comm")) for ev in timeline if ev.get("comm"))),
        }

    @staticmethod
    def _build_search_text(trace: dict) -> str:
        parts: List[str] = [
            str(trace.get("trace_id", "")),
            str(trace.get("kind", "")),
            str(trace.get("vector", "")),
            str(trace.get("outcome", "")),
            str(trace.get("proc_state", "")),
            str(trace.get("command", "")),
            str(trace.get("root_pid", "")),
            *(str(p) for p in (trace.get("related_pids") or [])),
            *(str(p) for p in (trace.get("new_quarantine_pids") or [])),
            str((trace.get("defender") or {}).get("engine", "")),
            str((trace.get("defender") or {}).get("mode", "")),
            str(trace.get("stdout", "")),
            str(trace.get("stderr", "")),
        ]
        for c in trace.get("c2_events") or []:
            parts.append(str(c.get("payload", "")))
        for ev in trace.get("timeline") or []:
            parts.extend([
                str(ev.get("pid", "")),
                str(ev.get("ppid", "")),
                str(ev.get("comm", "")),
                str(ev.get("name", "")),
                str(ev.get("type", "")),
                str(ev.get("action", "")),
                str(ev.get("exe", "")),
                str(ev.get("vfs_name", "")),
                str(ev.get("vfs_ino", "")),
                *(str(r) for r in (ev.get("reasons") or [])),
                *(str(a) for a in (ev.get("ancestry") or [])),
            ])
        return " ".join(p for p in parts if p).lower()

    def next_trace_id(self) -> str:
        with self.lock:
            self._trace_seq += 1
            return f"TRC-{self._trace_seq:04d}"

    def latest_event_id(self) -> int:
        with self.lock:
            return int(self.events[-1]["id"]) if self.events else 0

    def collect_events_since(self, min_id: int, root_pid: int) -> Tuple[List[dict], List[int]]:
        with self.lock:
            candidates = [ev for ev in self.events if int(ev.get("id", 0)) > min_id]
            pid_set = {int(root_pid)}
            changed = True
            while changed:
                changed = False
                for ev in candidates:
                    try:
                        pid = int(ev.get("pid", -1))
                        ppid = int(ev.get("ppid", -1))
                    except (TypeError, ValueError):
                        continue
                    if ppid in pid_set and pid > 0 and pid not in pid_set:
                        pid_set.add(pid)
                        changed = True
            matched = []
            for ev in candidates:
                try:
                    pid = int(ev.get("pid", -1))
                    ppid = int(ev.get("ppid", -1))
                except (TypeError, ValueError):
                    continue
                if pid in pid_set or ppid in pid_set:
                    matched.append(dict(ev))
            matched.sort(key=lambda e: (int(e.get("id", 0)), float(e.get("epoch", 0))))
            return matched, sorted(pid_set)

    def save_trace(self, trace: dict) -> dict:
        trace = dict(trace)
        trace["search_text"] = self._build_search_text(trace)
        trace_id = trace["trace_id"]
        try:
            self.traces_dir.mkdir(parents=True, exist_ok=True)
            (self.traces_dir / f"{trace_id}.json").write_text(
                json.dumps(trace, indent=2), encoding="utf-8"
            )
        except OSError:
            pass

        ev_ids = {ev.get("id") for ev in (trace.get("timeline") or []) if ev.get("id") is not None}
        with self.lock:
            if ev_ids:
                for ev in self.events:
                    if ev.get("id") in ev_ids:
                        ev["trace_id"] = trace_id
            self.traces.append(trace)
            if len(self.traces) > 200:
                self.traces = self.traces[-200:]
        summary = self._trace_summary(trace)
        self._broadcast("trace", summary)
        return trace

    def search_traces(self, query: str = "") -> List[dict]:
        tokens = [tok for tok in query.strip().lower().split() if tok]
        with self.lock:
            items = list(reversed(self.traces))
        if not tokens:
            return [self._trace_summary(t) for t in items]
        matched = []
        for t in items:
            hay = t.get("search_text") or self._build_search_text(t)
            if all(tok in hay for tok in tokens):
                matched.append(self._trace_summary(t))
        return matched

    def get_trace(self, trace_id: str) -> Optional[dict]:
        if not TRACE_ID_RE.fullmatch(trace_id):
            return None
        with self.lock:
            for t in reversed(self.traces):
                if t.get("trace_id") == trace_id:
                    out = dict(t)
                    out.pop("search_text", None)
                    return out
        p = self.traces_dir / f"{trace_id}.json"
        if p.exists():
            try:
                out = json.loads(p.read_text(encoding="utf-8"))
                out.pop("search_text", None)
                return out
            except (OSError, json.JSONDecodeError):
                return None
        return None

    def _load_existing_events(self) -> None:
        if not self.log_path.exists():
            return
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                raw_lines = f.readlines()[-1200:]
            parsed = []
            for line in raw_lines:
                try:
                    parsed.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            threats = [r for r in parsed if r.get("action") != "ALLOW"][-60:]
            benign = [r for r in parsed if r.get("action") == "ALLOW"][-180:]
            merged = sorted(threats + benign, key=lambda r: r.get("epoch", 0))
            for idx, rec in enumerate(merged, start=1):
                rec["id"] = idx
                self.events.append(rec)
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
            self.traces = []
            self._trace_seq = 0
        self.c2.clear()
        try:
            self.log_path.write_text("", encoding="utf-8")
        except OSError:
            pass
        try:
            if self.traces_dir.exists():
                for p in self.traces_dir.glob("TRC-*.json"):
                    p.unlink(missing_ok=True)
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
            "probes": 9,
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
            "trace_count": len(self.traces),
            "last_error": self.last_error,
        }

    def get_status(self) -> dict:
        with self.lock:
            return self.get_status_unlocked()

    def get_events(self) -> List[dict]:
        with self.lock:
            return list(self.events)


c2_server: Optional[MockC2Server] = None
controller: Optional[DefenderController] = None


VECTOR_FLAGS = {
    "standard": [],
    "dup-fd": ["--dup-fd"],
    "fork": ["--fork"],
    "execve-fd": ["--execve-fd"],
    "high-entropy": ["--high-entropy"],
    "mmap-exec": ["--mmap-exec"],
    "scm-fd": ["--scm-fd"],
}


def _save_iteration_trace(
    *,
    trace_id: str,
    kind: str,
    vector: str,
    extra_flags: List[str],
    cmd: List[str],
    start_epoch: float,
    root_pid: int,
    proc_state: str,
    exit_code: Optional[int],
    frozen: bool,
    new_frozen: List[int],
    stdout_text: str,
    stderr_text: str,
    c2_events: List[dict],
    timeline: List[dict],
    related_pids: List[int],
    status_snap: dict,
) -> dict:
    end_epoch = time.time()
    leaked = len(c2_events) > 0
    if kind == "attack":
        if frozen:
            outcome = "FROZEN"
        elif leaked:
            outcome = "EXFILTRATED"
        elif not status_snap.get("running"):
            outcome = "UNMONITORED"
        else:
            outcome = "COMPLETED"
    else:
        if frozen or any(e.get("action") == "FROZEN" for e in timeline):
            outcome = "FALSE_POSITIVE"
        elif exit_code == 0:
            outcome = "ALLOWED"
        else:
            outcome = "FAILED"

    mttis = [float(e["mtti_ms"]) for e in timeline if e.get("mtti_ms") is not None]
    scores = [float(e["score"]) for e in timeline if isinstance(e.get("score"), (int, float))]
    entropies = [float(e["entropy"]) for e in timeline if isinstance(e.get("entropy"), (int, float))]

    trace = {
        "trace_id": trace_id,
        "ts": time.strftime("%H:%M:%S"),
        "epoch": round(start_epoch, 3),
        "duration_ms": round((end_epoch - start_epoch) * 1000.0, 2),
        "kind": kind,
        "vector": vector,
        "flags": extra_flags,
        "command": " ".join(cmd),
        "root_pid": root_pid,
        "related_pids": related_pids,
        "proc_state": proc_state,
        "exit_code": exit_code,
        "outcome": outcome,
        "frozen": frozen,
        "leaked": leaked,
        "new_quarantine_pids": sorted(new_frozen),
        "defender": {
            "running": bool(status_snap.get("running")),
            "engine": status_snap.get("engine"),
            "mode": status_snap.get("mode"),
            "kernel_freeze": bool(status_snap.get("kernel_freeze")),
        },
        "summary": {
            "event_count": len(timeline),
            "frozen_events": sum(1 for e in timeline if e.get("action") == "FROZEN"),
            "allowed_events": sum(1 for e in timeline if e.get("action") == "ALLOW"),
            "c2_leak_count": len(c2_events),
            "c2_leak_bytes": sum(int(c.get("bytes", 0)) for c in c2_events),
            "max_score": max(scores) if scores else None,
            "min_mtti_ms": min(mttis) if mttis else None,
            "max_entropy": max(entropies) if entropies else None,
        },
        "stdout": stdout_text,
        "stderr": stderr_text,
        "c2_events": c2_events,
        "timeline": timeline,
    }
    return controller.save_trace(trace)


def run_demo_command(action: str, body: Optional[dict] = None) -> dict:
    if action == "attack":
        if not LOADER_BIN.exists():
            return {"ok": False, "error": "loader binary missing; run make first"}
        vector = str((body or {}).get("vector", "standard"))
        extra_flags = VECTOR_FLAGS.get(vector, [])
        trace_id = controller.next_trace_id()
        start_epoch = time.time()
        before_event_id = controller.latest_event_id()
        before_c2_id = c2_server.latest_id()
        before_q = set(controller.get_quarantine())
        cmd = [str(LOADER_BIN), *extra_flags, "--ticks", "20", "--exfil-port", str(c2_server.port)]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        read_stdout = _start_pipe_drainer(proc.stdout)
        read_stderr = _start_pipe_drainer(proc.stderr)
        threading.Thread(target=proc.wait, daemon=True).start()
        time.sleep(0.42)
        status_snap = controller.get_status()
        timeline, related_pids = controller.collect_events_since(before_event_id, proc.pid)
        if status_snap.get("running") and not timeline:
            for _ in range(2):
                time.sleep(0.06)
                timeline, related_pids = controller.collect_events_since(before_event_id, proc.pid)
                if timeline:
                    break
        state = read_proc_state(proc.pid)
        c2_events = c2_server.snapshot_since(before_c2_id)
        new_frozen = sorted(set(controller.get_quarantine()) - before_q)
        frozen = state.startswith("T") or len(new_frozen) > 0
        _save_iteration_trace(
            trace_id=trace_id,
            kind="attack",
            vector=vector,
            extra_flags=extra_flags,
            cmd=cmd,
            start_epoch=start_epoch,
            root_pid=proc.pid,
            proc_state=state,
            exit_code=proc.poll(),
            frozen=frozen,
            new_frozen=new_frozen,
            stdout_text=read_stdout(),
            stderr_text=read_stderr(),
            c2_events=c2_events,
            timeline=timeline,
            related_pids=related_pids,
            status_snap=status_snap,
        )
        return {
            "ok": True,
            "trace_id": trace_id,
            "vector": vector,
            "pid": proc.pid,
            "proc_state": state,
            "frozen": frozen,
            "leaked": len(c2_events) > 0,
        }

    if action == "benign":
        if not LOADER_BIN.exists():
            return {"ok": False, "error": "loader binary missing; run make first"}
        trace_id = controller.next_trace_id()
        start_epoch = time.time()
        before_event_id = controller.latest_event_id()
        before_c2_id = c2_server.latest_id()
        before_q = set(controller.get_quarantine())
        cmd = [str(LOADER_BIN), "--benign-memfd"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        read_stdout = _start_pipe_drainer(proc.stdout)
        read_stderr = _start_pipe_drainer(proc.stderr)
        try:
            exit_code: Optional[int] = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            exit_code = None
        status_snap = controller.get_status()
        timeline, related_pids = controller.collect_events_since(before_event_id, proc.pid)
        if status_snap.get("running") and not timeline:
            for _ in range(3):
                time.sleep(0.06)
                timeline, related_pids = controller.collect_events_since(before_event_id, proc.pid)
                if timeline:
                    break
        state = "exited" if exit_code is not None else read_proc_state(proc.pid)
        c2_events = c2_server.snapshot_since(before_c2_id)
        new_frozen = sorted(set(controller.get_quarantine()) - before_q)
        frozen = state.startswith("T") or len(new_frozen) > 0
        _save_iteration_trace(
            trace_id=trace_id,
            kind="benign",
            vector="benign-memfd",
            extra_flags=["--benign-memfd"],
            cmd=cmd,
            start_epoch=start_epoch,
            root_pid=proc.pid,
            proc_state=state,
            exit_code=exit_code,
            frozen=frozen,
            new_frozen=new_frozen,
            stdout_text=read_stdout(),
            stderr_text=read_stderr(),
            c2_events=c2_events,
            timeline=timeline,
            related_pids=related_pids,
            status_snap=status_snap,
        )
        return {"ok": exit_code == 0, "trace_id": trace_id}

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
        self.send_header("Connection", "close")
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
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self._send_json(controller.get_status())
            return

        if path == "/api/ml/metrics":
            self._send_json({"available": MODEL_FILE.exists(), "metrics": read_ml_metrics()})
            return

        if path == "/api/events":
            self._send_json({
                "events": controller.get_events(),
                "traces": controller.search_traces(),
                "quarantine": controller.get_quarantine(),
                "c2_leaks": c2_server.snapshot(),
                "status": controller.get_status(),
            })
            return

        if path == "/api/traces":
            q = parse_qs(parsed.query).get("q", [""])[0]
            self._send_json({"traces": controller.search_traces(q)})
            return

        if path.startswith("/api/traces/"):
            trace_id = path.split("/api/traces/", 1)[1].strip("/")
            trace = controller.get_trace(trace_id)
            if trace is None:
                self._send_json({"error": "trace not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(trace)
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
            self._send_json(run_demo_command(action, body))
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
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    global c2_server, controller
    parser = argparse.ArgumentParser(description="MemGuard eBPF Console API and static server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8080, help="Bind port")
    parser.add_argument("--engine", choices=["heuristic", "ml"], default="heuristic", help="Initial classifier engine")
    parser.add_argument("--userspace", action="store_true", help="Default to userspace pidfd_send_signal mode")
    parser.add_argument("--auto-start", action="store_true", help="Start the eBPF defender automatically")
    args = parser.parse_args()

    c2_server = MockC2Server()
    controller = DefenderController(LOG_FILE, c2_server)

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
