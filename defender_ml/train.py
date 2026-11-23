#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defender_ml.features import FEATURE_NAMES  # noqa: E402

DEFAULT_DATASET = Path(__file__).resolve().parent / "data" / "dataset.csv"
DEFAULT_MODEL = Path(__file__).resolve().parent / "model.joblib"
DEFAULT_METRICS = Path(__file__).resolve().parent / "metrics.json"

MODEL_SPECS = [
    ("random_forest", "Random Forest", lambda: RandomForestClassifier(n_estimators=30, max_depth=6, random_state=42)),
    ("decision_tree", "Decision Tree", lambda: DecisionTreeClassifier(max_depth=6, random_state=42)),
    ("logistic_regression", "Logistic Regression", lambda: Pipeline([("scaler", StandardScaler()), ("clf", LogisticRegression(max_iter=500, random_state=42))])),
    ("knn", "KNN (k=5)", lambda: Pipeline([("scaler", StandardScaler()), ("clf", KNeighborsClassifier(n_neighbors=5))])),
]


def load_dataset(csv_path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, Dict[str, int]]:
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    X_rows: List[List[float]] = []
    y_rows: List[int] = []
    groups: List[str] = []
    sources: Counter = Counter()

    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            X_rows.append([float(row[name]) for name in FEATURE_NAMES])
            y_rows.append(int(float(row["label"])))
            groups.append(row.get("group_id") or f"row_{idx}")
            sources[row.get("source") or "unknown"] += 1

    if not X_rows:
        raise ValueError(f"Dataset is empty: {csv_path}")

    return (
        np.asarray(X_rows, dtype=np.float64),
        np.asarray(y_rows, dtype=np.int64),
        np.asarray(groups),
        dict(sources),
    )


def split_grouped(
    X: np.ndarray, y: np.ndarray, groups: np.ndarray
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    unique_groups = np.unique(groups)
    if len(unique_groups) >= 4:
        for seed in (42, 7, 13, 99):
            splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
            train_idx, test_idx = next(splitter.split(X, y, groups))
            if len(np.unique(y[train_idx])) == 2 and len(np.unique(y[test_idx])) == 2:
                return X[train_idx], X[test_idx], y[train_idx], y[test_idx]

    return train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)


def benchmark_single_row_ms(model, sample_row: np.ndarray, repeats: int = 200) -> float:
    row = sample_row.reshape(1, -1)
    # Warm up once before timing
    model.predict_proba(row)
    start = time.perf_counter()
    for _ in range(repeats):
        model.predict_proba(row)
    elapsed_ms = ((time.perf_counter() - start) / repeats) * 1000.0
    return round(elapsed_ms, 4)


def extract_feature_importances(model) -> List[Dict[str, object]]:
    estimator = model.named_steps["clf"] if hasattr(model, "named_steps") else model
    if hasattr(estimator, "feature_importances_"):
        raw = estimator.feature_importances_
    elif hasattr(estimator, "coef_"):
        raw = np.abs(estimator.coef_[0])
        total = float(np.sum(raw))
        raw = raw / total if total > 0 else raw
    else:
        return []

    pairs = [
        {"feature": name, "importance": round(float(val), 4)}
        for name, val in zip(FEATURE_NAMES, raw)
    ]
    pairs.sort(key=lambda x: x["importance"], reverse=True)
    return pairs


def train_and_evaluate(args: argparse.Namespace) -> int:
    X, y, groups, sources = load_dataset(args.dataset)
    if len(np.unique(y)) < 2:
        sys.stderr.write("error: dataset must contain both benign (0) and malicious (1) labels.\n")
        return 1

    X_train, X_test, y_train, y_test = split_grouped(X, y, groups)

    results = []
    trained_models = {}

    for key, label, factory in MODEL_SPECS:
        clf = factory()
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        infer_ms = benchmark_single_row_ms(clf, X_test[0])

        trained_models[key] = clf
        results.append({
            "key": key,
            "label": label,
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
            "fpr": round(float(fpr), 4),
            "avg_infer_ms": infer_ms,
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
        })

    selected_clf = trained_models[args.model]
    selected_label = next(lbl for k, lbl, _ in MODEL_SPECS if k == args.model)

    bundle = {
        "model": selected_clf,
        "model_key": args.model,
        "model_label": selected_label,
        "feature_names": FEATURE_NAMES,
        "thresholds": {
            "alert": args.alert_threshold,
            "freeze": args.freeze_threshold,
        },
    }
    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.model_out)

    metrics_payload = {
        "selected_model": args.model,
        "selected_label": selected_label,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "thresholds": bundle["thresholds"],
        "dataset": {
            "total_rows": int(len(y)),
            "train_rows": int(len(y_train)),
            "test_rows": int(len(y_test)),
            "benign_rows": int(np.sum(y == 0)),
            "malicious_rows": int(np.sum(y == 1)),
            "sources": sources,
        },
        "models": results,
        "feature_importances": extract_feature_importances(selected_clf),
    }
    with open(args.metrics_out, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"Dataset: {len(y)} rows (train={len(y_train)}, test={len(y_test)}, sources={sources})")
    print(f"{'Model':<22} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'FPR':>7} {'Infer(ms)':>10}")
    print("-" * 73)
    for r in results:
        mark = "*" if r["key"] == args.model else " "
        print(
            f"{mark}{r['label']:<21} {r['accuracy']:>7.4f} {r['precision']:>7.4f} "
            f"{r['recall']:>7.4f} {r['f1']:>7.4f} {r['fpr']:>7.4f} {r['avg_infer_ms']:>10.4f}"
        )
    print(f"\nSaved live model ({selected_label}) -> {args.model_out}")
    print(f"Saved evaluation metrics       -> {args.metrics_out}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train and benchmark defender_ml classifiers")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET, help="Input CSV dataset path")
    parser.add_argument("--model", choices=[k for k, _, _ in MODEL_SPECS], default="random_forest")
    parser.add_argument("--model-out", type=Path, default=DEFAULT_MODEL, help="Output joblib bundle path")
    parser.add_argument("--metrics-out", type=Path, default=DEFAULT_METRICS, help="Output metrics JSON path")
    parser.add_argument("--alert-threshold", type=float, default=0.45)
    parser.add_argument("--freeze-threshold", type=float, default=0.75)
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(train_and_evaluate(parse_args()))
