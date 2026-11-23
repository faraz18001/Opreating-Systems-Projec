import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEURISTIC_DIR = PROJECT_ROOT / "defender_heuristic"
for p in (str(PROJECT_ROOT), str(HEURISTIC_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from defender_ml.features import (  # noqa: E402
    DEFAULT_RULES_PATH,
    FEATURE_NAMES,
    extract_features,
    load_rule_sets,
)
from telemetry import ProcessContext  # noqa: E402


@dataclass
class MLVerdict:
    score: int
    action: str
    reasons: List[str] = field(default_factory=list)
    entropy: Optional[float] = None
    prob: float = 0.0
    infer_ms: float = 0.0
    model_label: str = ""


@dataclass
class MLPidState:
    last_seen: float
    created_memfd: bool = False
    exec_from_memfd: bool = False
    frozen: bool = False


class MLClassifier:
    """Scikit-learn inference wrapper matching HeuristicClassifier's verdict contract."""

    def __init__(self, model_path: Path, rules_path: Path = DEFAULT_RULES_PATH):
        if not model_path.exists():
            raise FileNotFoundError(f"ML model bundle not found: {model_path}")

        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.model_key = bundle.get("model_key", "random_forest")
        self.model_label = bundle.get("model_label", "Random Forest")
        thresholds = bundle.get("thresholds", {})
        self.alert_threshold = float(thresholds.get("alert", 0.45))
        self.freeze_threshold = float(thresholds.get("freeze", 0.75))
        self.rule_sets = load_rule_sets(rules_path)
        self.pid_states: Dict[int, MLPidState] = {}
        self._last_gc = time.monotonic()

    def _gc_states(self, now: float) -> None:
        if now - self._last_gc < 30.0:
            return
        self._last_gc = now
        stale = [pid for pid, st in self.pid_states.items() if now - st.last_seen > 120.0]
        for pid in stale:
            del self.pid_states[pid]

    def _describe_active_signals(self, vec: List[float], ev_name: str, ctx: ProcessContext) -> List[str]:
        signals: List[str] = []
        active = {name: val for name, val in zip(FEATURE_NAMES, vec)}
        if active["is_execveat"] and active["tracked_memfd"]:
            signals.append(f"execveat on tracked memfd ({ev_name})")
        elif active["is_execveat"] and active["has_empty_path_flag"]:
            signals.append("execveat with AT_EMPTY_PATH")
        if active["is_execve_fd"] and active["has_proc_fd_path"]:
            signals.append(f"execve via proc fd path ({ev_name})")
        if active["is_kthread_masquerade"]:
            signals.append(f"kthread masquerade via prctl ({ev_name})")
        if active["has_memfd_exe"]:
            signals.append(f"anonymous memfd exe ({ctx.exe})")
        if active["is_allowlisted"]:
            signals.append("allowlisted process/parent ancestry")
        return signals

    def evaluate(self, event: dict, ctx: ProcessContext) -> MLVerdict:
        now = time.monotonic()
        self._gc_states(now)

        pid = int(event["pid"])
        ev_type = str(event.get("type", ""))
        ev_name = str(event.get("name", ""))

        state = self.pid_states.get(pid)
        if state is None:
            state = MLPidState(last_seen=now)
            self.pid_states[pid] = state
        else:
            state.last_seen = now

        if state.frozen:
            return MLVerdict(
                score=0,
                action="ALREADY_FROZEN",
                reasons=["pid already frozen"],
                entropy=ctx.entropy,
                model_label=self.model_label,
            )

        if ev_type == "memfd_create":
            state.created_memfd = True
        elif ev_type in ("execveat", "execve_fd") and (bool(event.get("tracked_memfd")) or state.created_memfd):
            state.exec_from_memfd = True

        t0 = time.perf_counter()
        vec = extract_features(
            event,
            ctx,
            created_memfd=state.created_memfd,
            exec_from_memfd=state.exec_from_memfd,
            rule_sets=self.rule_sets,
        )
        proba = self.model.predict_proba(np.asarray([vec], dtype=np.float64))[0]
        classes = list(getattr(self.model, "classes_", [0, 1]))
        mal_idx = classes.index(1) if 1 in classes else (len(classes) - 1)
        prob = float(proba[mal_idx])
        infer_ms = round((time.perf_counter() - t0) * 1000.0, 4)

        if prob >= self.freeze_threshold:
            action = "FREEZE"
        elif prob >= self.alert_threshold:
            action = "ALERT"
        else:
            action = "ALLOW"

        reasons = [f"ML {self.model_label} P(malicious)={prob:.2f}"]
        reasons.extend(self._describe_active_signals(vec, ev_name, ctx))

        return MLVerdict(
            score=int(round(prob * 100)),
            action=action,
            reasons=reasons,
            entropy=ctx.entropy,
            prob=round(prob, 4),
            infer_ms=infer_ms,
            model_label=self.model_label,
        )

    def mark_frozen(self, pid: int) -> None:
        if pid in self.pid_states:
            self.pid_states[pid].frozen = True
