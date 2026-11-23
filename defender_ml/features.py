import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEURISTIC_DIR = PROJECT_ROOT / "defender_heuristic"
if str(HEURISTIC_DIR) not in sys.path:
    sys.path.insert(0, str(HEURISTIC_DIR))

from telemetry import ProcessContext  # noqa: E402

AT_EMPTY_PATH = 0x1000
DEFAULT_RULES_PATH = HEURISTIC_DIR / "rules.yaml"

FEATURE_NAMES: List[str] = [
    "is_memfd_create",
    "is_execveat",
    "is_execve_fd",
    "is_prctl_rename",
    "tracked_memfd",
    "has_empty_path_flag",
    "has_memfd_exe",
    "has_proc_fd_path",
    "is_kthread_masquerade",
    "is_allowlisted",
    "entropy",
]


def load_rule_sets(rules_path: Path = DEFAULT_RULES_PATH) -> Tuple[Set[str], Tuple[str, ...]]:
    """Load allowlisted process names and kernel-thread masquerade prefixes."""
    with open(rules_path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f) or {}
    allowlist = set(rules.get("allowlist_comms", []))
    kthread_prefixes = tuple(rules.get("kthread_prefixes", []))
    return allowlist, kthread_prefixes


def _matches_kthread(name: str, kthread_prefixes: Tuple[str, ...]) -> bool:
    return any(name.startswith(prefix) for prefix in kthread_prefixes)


def _compute_feature_vector(
    ev_type: str,
    ev_name: str,
    ev_comm: str,
    tracked_memfd: bool,
    flags: int,
    exe: str,
    ctx_comm: str,
    ancestry_names: Iterable[str],
    entropy: Optional[float],
    allowlist_comms: Set[str],
    kthread_prefixes: Tuple[str, ...],
) -> List[float]:
    ancestry_list = list(ancestry_names)
    parent_comm = ancestry_list[1] if len(ancestry_list) > 1 else ""
    is_allowlisted = (
        ev_comm in allowlist_comms
        or ctx_comm in allowlist_comms
        or parent_comm in allowlist_comms
    )

    has_empty_path = (ev_type == "execveat") and ((flags & AT_EMPTY_PATH) != 0)
    has_memfd_exe = exe.startswith("/memfd:") or ("memfd:" in exe)
    has_proc_fd_path = ("/proc/" in ev_name) and ("/fd/" in ev_name)
    is_kthread = (ev_type == "prctl_set_name") and _matches_kthread(ev_name, kthread_prefixes)
    entropy_val = float(entropy) if entropy is not None else -1.0

    return [
        1.0 if ev_type == "memfd_create" else 0.0,
        1.0 if ev_type == "execveat" else 0.0,
        1.0 if ev_type == "execve_fd" else 0.0,
        1.0 if ev_type == "prctl_set_name" else 0.0,
        1.0 if tracked_memfd else 0.0,
        1.0 if has_empty_path else 0.0,
        1.0 if has_memfd_exe else 0.0,
        1.0 if has_proc_fd_path else 0.0,
        1.0 if is_kthread else 0.0,
        1.0 if is_allowlisted else 0.0,
        entropy_val,
    ]


def extract_features(
    event: Dict,
    ctx: ProcessContext,
    created_memfd: bool = False,
    exec_from_memfd: bool = False,
    rule_sets: Optional[Tuple[Set[str], Tuple[str, ...]]] = None,
) -> List[float]:
    """Convert a live eBPF event and /proc ProcessContext into a numeric vector."""
    allowlist_comms, kthread_prefixes = rule_sets or load_rule_sets()
    ev_type = str(event.get("type", ""))
    ev_name = str(event.get("name", ""))
    ev_comm = str(event.get("comm", ""))
    flags = int(event.get("flags", 0) or 0)
    tracked = bool(event.get("tracked_memfd", False)) or created_memfd or exec_from_memfd
    ancestry_names = [name for _, name in ctx.ancestry]

    return _compute_feature_vector(
        ev_type=ev_type,
        ev_name=ev_name,
        ev_comm=ev_comm,
        tracked_memfd=tracked,
        flags=flags,
        exe=ctx.exe,
        ctx_comm=ctx.comm,
        ancestry_names=ancestry_names,
        entropy=ctx.entropy,
        allowlist_comms=allowlist_comms,
        kthread_prefixes=kthread_prefixes,
    )


def extract_features_from_record(
    record: Dict,
    rule_sets: Optional[Tuple[Set[str], Tuple[str, ...]]] = None,
    tracked_pids: Optional[Set[int]] = None,
) -> List[float]:
    """Convert a logged JSONL telemetry record into the identical feature vector."""
    allowlist_comms, kthread_prefixes = rule_sets or load_rule_sets()
    pid = int(record.get("pid", 0) or 0)
    ev_type = str(record.get("type", ""))
    ev_name = str(record.get("name", ""))
    ev_comm = str(record.get("comm", ""))
    exe = str(record.get("exe", ""))
    ancestry = [str(x) for x in (record.get("ancestry") or [])]
    ctx_comm = ancestry[0] if ancestry else ""
    reasons_text = " ".join(str(r) for r in (record.get("reasons") or []))

    if tracked_pids is not None and ev_type == "memfd_create":
        tracked_pids.add(pid)

    tracked = (
        ev_type == "memfd_create"
        or (tracked_pids is not None and pid in tracked_pids)
        or ("tracked memfd" in reasons_text)
        or ("memfd process" in reasons_text)
    )
    flags = AT_EMPTY_PATH if ev_type == "execveat" else 0

    return _compute_feature_vector(
        ev_type=ev_type,
        ev_name=ev_name,
        ev_comm=ev_comm,
        tracked_memfd=tracked,
        flags=flags,
        exe=exe,
        ctx_comm=ctx_comm,
        ancestry_names=ancestry,
        entropy=record.get("entropy"),
        allowlist_comms=allowlist_comms,
        kthread_prefixes=kthread_prefixes,
    )
