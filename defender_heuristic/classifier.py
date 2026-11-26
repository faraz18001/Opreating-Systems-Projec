import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

from telemetry import ProcessContext


@dataclass
class Verdict:
    score: int
    action: str
    reasons: List[str] = field(default_factory=list)
    entropy: Optional[float] = None


@dataclass
class PidState:
    last_seen: float
    created_memfd: bool = False
    memfd_name: str = ""
    exec_from_memfd: bool = False
    masqueraded: bool = False
    frozen: bool = False


class HeuristicClassifier:
    def __init__(self, rules_path: Path):
        with open(rules_path, "r", encoding="utf-8") as f:
            self.rules = yaml.safe_load(f)

        self.thresholds = self.rules["thresholds"]
        self.weights = self.rules["weights"]
        self.kthread_prefixes = tuple(self.rules.get("kthread_prefixes", []))
        self.allowlist_comms: Set[str] = set(self.rules.get("allowlist_comms", []))
        self.pid_states: Dict[int, PidState] = {}
        self._last_gc = time.monotonic()

    def _gc_states(self, now: float) -> None:
        if now - self._last_gc < 30.0:
            return
        self._last_gc = now
        stale = [pid for pid, st in self.pid_states.items() if now - st.last_seen > 120.0]
        for pid in stale:
            del self.pid_states[pid]

    def _is_allowlisted(self, event_comm: str, ctx: ProcessContext) -> bool:
        if event_comm in self.allowlist_comms or ctx.comm in self.allowlist_comms:
            return True
        if len(ctx.ancestry) > 1:
            parent_pid, parent_comm = ctx.ancestry[1]
            # Never trust PID 1 (systemd/init) as an allowlisted parent: orphaned processes reparent to PID 1.
            if parent_pid != 1 and parent_comm != "systemd" and parent_comm in self.allowlist_comms:
                return True
        return False

    def _matches_kthread(self, name: str) -> bool:
        return any(name.startswith(prefix) for prefix in self.kthread_prefixes)

    def evaluate(self, event: dict, ctx: ProcessContext) -> Verdict:
        now = time.monotonic()
        self._gc_states(now)

        pid = int(event["pid"])
        ev_type = event["type"]
        ev_name = event.get("name", "")
        ev_comm = event.get("comm", "")
        tracked_memfd = bool(event.get("tracked_memfd", False))
        vfs_memfd = bool(event.get("vfs_memfd", False))
        vfs_name = event.get("vfs_name", "")
        vfs_ino = int(event.get("vfs_ino", 0) or 0)

        state = self.pid_states.get(pid)
        if state is None:
            state = PidState(last_seen=now)
            self.pid_states[pid] = state
        else:
            state.last_seen = now

        if state.frozen:
            return Verdict(score=0, action="ALREADY_FROZEN", reasons=["pid already frozen"], entropy=ctx.entropy)

        score = 0
        reasons: List[str] = []

        if ev_type == "memfd_create":
            state.created_memfd = True
            state.memfd_name = ev_name
            return Verdict(score=0, action="ALLOW", reasons=["memfd buffer created"], entropy=ctx.entropy)

        if vfs_memfd and ev_type in ("execveat", "execve_fd"):
            score += self.weights.get("vfs_verified_memfd", 75)
            reasons.append(f"kernel VFS verified tmpfs {vfs_name or 'memfd'} (inode {vfs_ino})")
            state.exec_from_memfd = True
        elif ev_type == "execveat":
            if tracked_memfd or state.created_memfd:
                score += self.weights["tracked_memfd_execveat"]
                reasons.append(f"execveat on tracked memfd ({ev_name or state.memfd_name})")
                state.exec_from_memfd = True
            else:
                score += self.weights["untracked_empty_path_execveat"]
                reasons.append("execveat with AT_EMPTY_PATH")

        elif ev_type == "execve_fd":
            if "/proc/" in ev_name and "/fd/" in ev_name:
                score += self.weights["proc_fd_execve"]
                reasons.append(f"execve via proc fd path ({ev_name})")
                state.exec_from_memfd = True

        elif ev_type == "mprotect_exec":
            score += self.weights.get("anon_mprotect_exec", 75)
            reasons.append(f"anonymous W->X mprotect(PROT_EXEC) transition ({ev_name or 'anon'})")

        elif ev_type == "prctl_set_name":
            if self._matches_kthread(ev_name):
                score += self.weights["kthread_masquerade"]
                reasons.append(f"kthread masquerade via prctl ({ev_name})")
                state.masqueraded = True
            if tracked_memfd or state.created_memfd or state.exec_from_memfd:
                score += self.weights["memfd_plus_prctl_rename"]
                reasons.append("memfd process renamed via prctl")

        if ctx.exe.startswith("/memfd:") or "memfd:" in ctx.exe:
            score += self.weights["memfd_deleted_exe"]
            reasons.append(f"anonymous memfd exe ({ctx.exe})")

        if ctx.entropy is not None and ctx.entropy >= self.thresholds["high_entropy"]:
            score += self.weights["high_entropy"]
            reasons.append(f"high binary entropy ({ctx.entropy:.2f})")

        if self._is_allowlisted(ev_comm, ctx) and not state.masqueraded:
            score += self.weights["allowlisted_parent"]
            reasons.append("allowlisted desktop/audio ancestry")

        if score >= self.thresholds["freeze"]:
            action = "FREEZE"
        elif score >= self.thresholds["alert"]:
            action = "ALERT"
        else:
            action = "ALLOW"

        return Verdict(score=score, action=action, reasons=reasons, entropy=ctx.entropy)

    def mark_frozen(self, pid: int) -> None:
        if pid in self.pid_states:
            self.pid_states[pid].frozen = True
