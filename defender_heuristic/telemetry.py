import math
import os
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class ProcessContext:
    pid: int
    ppid: int = 0
    comm: str = ""
    exe: str = ""
    cmdline: str = ""
    ancestry: List[Tuple[int, str]] = field(default_factory=list)
    entropy: Optional[float] = None


def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _read_ppid(pid: int) -> int:
    status = _read_text(f"/proc/{pid}/status")
    for line in status.splitlines():
        if line.startswith("PPid:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def _read_exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def get_ancestry(pid: int, max_depth: int = 5) -> List[Tuple[int, str]]:
    chain: List[Tuple[int, str]] = []
    cur = pid
    seen = set()
    for _ in range(max_depth):
        if cur <= 1 or cur in seen:
            break
        seen.add(cur)
        comm = _read_text(f"/proc/{cur}/comm")
        if not comm:
            break
        chain.append((cur, comm))
        cur = _read_ppid(cur)
    return chain


def read_binary_entropy(pid: int, fd: int = -1, sample_bytes: int = 65536) -> Optional[float]:
    paths = []
    if fd >= 0:
        paths.append(f"/proc/{pid}/fd/{fd}")
    paths.append(f"/proc/{pid}/exe")

    for path in paths:
        try:
            with open(path, "rb") as f:
                data = f.read(sample_bytes)
            if data:
                return calculate_shannon_entropy(data)
        except OSError:
            continue
    return None


def collect_context(pid: int, fallback_ppid: int = 0, fd: int = -1, inspect_entropy: bool = False) -> ProcessContext:
    comm = _read_text(f"/proc/{pid}/comm")
    exe = _read_exe(pid)
    raw_cmd = _read_text(f"/proc/{pid}/cmdline")
    cmdline = raw_cmd.replace("\x00", " ").strip()
    ppid = _read_ppid(pid) or fallback_ppid
    ancestry = get_ancestry(pid)
    entropy = read_binary_entropy(pid, fd=fd) if inspect_entropy else None

    return ProcessContext(
        pid=pid,
        ppid=ppid,
        comm=comm,
        exe=exe,
        cmdline=cmdline,
        ancestry=ancestry,
        entropy=entropy,
    )
