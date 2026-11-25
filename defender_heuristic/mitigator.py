import ctypes
import glob
import os
import platform
import signal
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set

SYS_PIDFD_SEND_SIGNAL_MAP = {
    "x86_64": 424,
    "aarch64": 424,
}

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_SYS_PIDFD_SEND_SIGNAL = SYS_PIDFD_SEND_SIGNAL_MAP.get(platform.machine(), 424)


@dataclass
class MitigationResult:
    pid: int
    success: bool
    mtti_ms: float
    frozen_pids: List[int] = field(default_factory=list)
    error: Optional[str] = None


def send_signal_via_pidfd(pid: int, sig: int) -> Optional[str]:
    pidfd = -1
    try:
        pidfd = os.pidfd_open(pid, 0)
        ret = _libc.syscall(
            ctypes.c_long(_SYS_PIDFD_SEND_SIGNAL),
            ctypes.c_int(pidfd),
            ctypes.c_int(sig),
            ctypes.c_void_p(0),
            ctypes.c_uint(0),
        )
        if ret != 0:
            err = ctypes.get_errno()
            return os.strerror(err)
        return None
    except OSError as exc:
        return exc.strerror or str(exc)
    finally:
        if pidfd >= 0:
            try:
                os.close(pidfd)
            except OSError:
                pass


def collect_descendants(root_pid: int) -> List[int]:
    order: List[int] = []
    seen: Set[int] = {root_pid}
    stack = [root_pid]

    while stack:
        cur = stack.pop()
        for child_file in glob.glob(f"/proc/{cur}/task/*/children"):
            try:
                with open(child_file, "r", encoding="utf-8") as f:
                    for tok in f.read().split():
                        if tok.isdigit():
                            cpid = int(tok)
                            if cpid not in seen:
                                seen.add(cpid)
                                order.append(cpid)
                                stack.append(cpid)
            except OSError:
                continue
    return order


def freeze_process(pid: int, event_ktime_ns: int) -> MitigationResult:
    err = send_signal_via_pidfd(pid, signal.SIGSTOP)
    now_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    mtti_ms = max(0.0, (now_ns - event_ktime_ns) / 1_000_000.0)

    frozen = [pid] if err is None else []
    for child in collect_descendants(pid):
        if send_signal_via_pidfd(child, signal.SIGSTOP) is None:
            frozen.append(child)

    return MitigationResult(
        pid=pid,
        success=(err is None),
        mtti_ms=round(mtti_ms, 3),
        frozen_pids=frozen,
        error=err,
    )


def resume_process(pid: int) -> Optional[str]:
    for child in collect_descendants(pid):
        send_signal_via_pidfd(child, signal.SIGCONT)
    return send_signal_via_pidfd(pid, signal.SIGCONT)


def kill_process(pid: int) -> Optional[str]:
    for child in collect_descendants(pid):
        send_signal_via_pidfd(child, signal.SIGKILL)
    return send_signal_via_pidfd(pid, signal.SIGKILL)
