#!/usr/bin/env python3
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "report" / "assets" / "experiment_data.json"
ASSETS = ROOT / "report" / "assets"

PURPLE = "#5D2568"
PURPLE_MID = "#865492"
PURPLE_LIGHT = "#D5BEDB"
GOLD = "#B88D3B"
SLATE = "#3E4352"
SLATE_LIGHT = "#9EA3B0"
AMBER = "#C25E3E"
GRID = "#E6E3EC"
TEXT = "#1E1F26"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 8.5,
    "axes.edgecolor": "#C9C5D4",
    "axes.linewidth": 0.7,
    "axes.labelcolor": TEXT,
    "xtick.color": SLATE,
    "ytick.color": SLATE,
    "text.color": TEXT,
    "svg.fonttype": "none",
})


def clean_axes(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", color=GRID, linewidth=0.6, linestyle="-", zorder=0)
    ax.set_axisbelow(True)


def make_fig1(data: dict) -> None:
    tr = data["trials"]
    labels = ["Userspace\nML (RF)", "Userspace\nHeuristic", "In-Kernel\nVFS eBPF"]
    mttis = [
        tr["userspace_ml"]["mtti_mean_ms"],
        tr["userspace_heur"]["mtti_mean_ms"],
        tr["inkernel_vfs"]["mtti_mean_ms"],
    ]
    leaks = [
        tr["userspace_ml"]["leak_pct"],
        tr["userspace_heur"]["leak_pct"],
        tr["inkernel_vfs"]["leak_pct"],
    ]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.8, 2.55), dpi=300, gridspec_kw={"width_ratios": [1.15, 1.0]})

    colors_bar = [SLATE_LIGHT, PURPLE_MID, PURPLE]
    x = np.arange(len(labels))
    bars = ax1.bar(x, mttis, width=0.52, color=colors_bar, zorder=3)
    ax1.set_yscale("log")
    ax1.set_ylim(0.001, 60)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=8)
    ax1.set_ylabel("Mean MTTI (ms, log scale)", fontsize=8.5, fontweight="bold")
    ax1.set_title("(a) Interception Latency (MTTI)", fontsize=9, fontweight="bold", color=PURPLE, pad=8)
    clean_axes(ax1)

    ax1.axhline(0.6, color=AMBER, linestyle="--", linewidth=0.9, zorder=2)
    ax1.text(2.38, 0.78, "TCP exfil (~0.6 ms)", fontsize=7, color=AMBER, ha="right", fontweight="bold")

    for bar, val in zip(bars, mttis):
        lbl = f"{val*1000:.1f} µs" if val < 0.1 else f"{val:.2f} ms"
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            val * 1.35,
            lbl,
            ha="center",
            va="bottom",
            fontsize=7.8,
            fontweight="bold",
            color=TEXT,
        )

    labels2 = ["Trad. FIM\n(inotify)", "Userspace\nML (RF)", "Userspace\nHeuristic", "In-Kernel\nVFS eBPF"]
    leaks_all = [tr["traditional_fim"]["leak_pct"], *leaks]
    x2 = np.arange(len(labels2))
    colors2 = [AMBER, AMBER, AMBER, PURPLE]
    bars2 = ax2.bar(x2, leaks_all, width=0.52, color=colors2, zorder=3)
    ax2.set_ylim(0, 118)
    ax2.set_xticks(x2)
    ax2.set_xticklabels(labels2, fontsize=7.4)
    ax2.set_ylabel("C2 Secret Leak Rate (%)", fontsize=8.5, fontweight="bold")
    ax2.set_title("(b) Exfiltration Race Outcome (n=80)", fontsize=9, fontweight="bold", color=PURPLE, pad=8)
    clean_axes(ax2)

    for bar, val in zip(bars2, leaks_all):
        ax2.text(
            bar.get_x() + bar.get_width() / 2,
            val + 3,
            f"{val:.0f}%",
            ha="center",
            va="bottom",
            fontsize=7.8,
            fontweight="bold",
            color=PURPLE if val == 0 else AMBER,
        )

    fig.tight_layout(w_pad=2.0)
    fig.savefig(ASSETS / "fig1_mtti_exfil.svg", bbox_inches="tight")
    plt.close(fig)


def make_fig2() -> None:
    defenses = [
        "Traditional FIM\n(inotify)",
        "Pre-Fix Heuristic\n(PID-1 bypass)",
        "Zero-Shot ML\n(100% Real RF)",
        "VFS-Hardened\nHeuristic",
        "In-Kernel VFS\neBPF (SIGSTOP)",
    ]
    vectors = ["Standard", "dup2\nremap", "fork\norphan", "/proc/fd\nfallback", "High-\nentropy"]

    matrix = np.array([
        [0, 0, 0, 0, 0],
        [100, 100, 0, 100, 100],
        [100, 100, 100, 0, 100],
        [100, 100, 100, 100, 100],
        [100, 100, 100, 100, 100],
    ], dtype=float)

    annotations = [
        ["0%", "0%", "0%", "0%", "0%"],
        ["100%", "100%", "0%\n(PID 1)", "100%", "100%"],
        ["100%", "100%", "100%", "0%\n(P=0.60)", "100%"],
        ["100%", "100%", "100%", "100%", "100%"],
        ["100%\n(0 leaks)", "100%\n(0 leaks)", "100%\n(0 leaks)", "100%\n(0 leaks)", "100%\n(0 leaks)"],
    ]

    fig, ax = plt.subplots(figsize=(6.8, 2.75), dpi=300)
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("hu_purple", ["#F8E9E4", "#E9DDF0", PURPLE])

    ax.imshow(matrix, cmap=cmap, aspect="auto", vmin=0, vmax=100)
    ax.set_xticks(np.arange(len(vectors)))
    ax.set_xticklabels(vectors, fontsize=8, fontweight="bold", color=TEXT)
    ax.set_yticks(np.arange(len(defenses)))
    ax.set_yticklabels(defenses, fontsize=7.8, color=TEXT)
    ax.xaxis.tick_top()

    for i in range(len(defenses)):
        for j in range(len(vectors)):
            val = matrix[i, j]
            txt_color = "#FFFFFF" if val >= 80 else AMBER
            ax.text(
                j,
                i,
                annotations[i][j],
                ha="center",
                va="center",
                fontsize=7.4,
                fontweight="bold",
                color=txt_color,
            )

    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xticks(np.arange(-0.5, len(vectors), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(defenses), 1), minor=True)
    ax.grid(which="minor", color="#FFFFFF", linestyle="-", linewidth=1.8)
    ax.tick_params(which="minor", bottom=False, left=False, top=False)
    ax.tick_params(axis="both", length=0)

    fig.tight_layout()
    fig.savefig(ASSETS / "fig2_evasion_matrix.svg", bbox_inches="tight")
    plt.close(fig)


def make_fig3(data: dict) -> None:
    models = data["ml_metrics"]["models"]
    m_map = {m["key"]: m["avg_infer_ms"] for m in models}

    clf_labels = ["Heuristic\n(rules.yaml)", "Decision\nTree", "Logistic\nReg.", "KNN\n(k=5)", "Random\nForest"]
    clf_ms = [0.04, m_map["decision_tree"], m_map["logistic_regression"], m_map["knn"], m_map["random_forest"]]
    clf_colors = [PURPLE, PURPLE_MID, SLATE_LIGHT, SLATE_LIGHT, AMBER]

    tr = data["trials"]
    mem_labels = ["Trad. FIM\n(inotify)", "In-Kernel\nVFS eBPF", "Userspace\nHeuristic", "Userspace\nML (RF)"]
    mem_mb = [tr["traditional_fim"]["rss_mb"], tr["inkernel_vfs"]["rss_mb"], tr["userspace_heur"]["rss_mb"], tr["userspace_ml"]["rss_mb"]]
    mem_colors = [SLATE_LIGHT, PURPLE, PURPLE_MID, AMBER]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.8, 2.5), dpi=300, gridspec_kw={"width_ratios": [1.15, 1.0]})

    y1 = np.arange(len(clf_labels))
    bars1 = ax1.barh(y1, clf_ms, height=0.55, color=clf_colors, zorder=3)
    ax1.invert_yaxis()
    ax1.set_yticks(y1)
    ax1.set_yticklabels(clf_labels, fontsize=7.6)
    ax1.set_xlabel("Per-Event Classification Latency (ms)", fontsize=8, fontweight="bold")
    ax1.set_title("(a) Classification Speed (597 Real Rows)", fontsize=9, fontweight="bold", color=PURPLE, pad=8)
    ax1.set_xlim(0, max(clf_ms) * 1.28)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)
    ax1.grid(axis="x", color=GRID, linewidth=0.6, zorder=0)
    ax1.set_axisbelow(True)

    for bar, val in zip(bars1, clf_ms):
        ax1.text(val + 0.03, bar.get_y() + bar.get_height() / 2, f"{val:.3f} ms", va="center", fontsize=7.5, fontweight="bold")

    y2 = np.arange(len(mem_labels))
    bars2 = ax2.barh(y2, mem_mb, height=0.52, color=mem_colors, zorder=3)
    ax2.invert_yaxis()
    ax2.set_yticks(y2)
    ax2.set_yticklabels(mem_labels, fontsize=7.6)
    ax2.set_xlabel("Resident Memory RSS (MB)", fontsize=8, fontweight="bold")
    ax2.set_title("(b) Userspace Memory Footprint", fontsize=9, fontweight="bold", color=PURPLE, pad=8)
    ax2.set_xlim(0, max(mem_mb) * 1.25)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)
    ax2.grid(axis="x", color=GRID, linewidth=0.6, zorder=0)
    ax2.set_axisbelow(True)

    for bar, val in zip(bars2, mem_mb):
        ax2.text(val + 2.5, bar.get_y() + bar.get_height() / 2, f"{val:.1f} MB", va="center", fontsize=7.5, fontweight="bold")

    fig.tight_layout(w_pad=2.0)
    fig.savefig(ASSETS / "fig3_classifier_overhead.svg", bbox_inches="tight")
    plt.close(fig)


def make_fig4(data: dict) -> None:
    tr = data["trials"]
    metrics = ["Benign OS Utility\n(1 - FPR)", "Fileless Attack\nDetection Rate", "Exfiltration\nBlocked Rate"]
    fim_vals = [100.0, tr["traditional_fim"]["detection_pct"], 100.0 - tr["traditional_fim"]["leak_pct"]]
    heur_vals = [100.0 - tr["userspace_heur"]["fpr_pct"], tr["userspace_heur"]["detection_pct"], 100.0 - tr["userspace_heur"]["leak_pct"]]
    kern_vals = [100.0 - tr["inkernel_vfs"]["fpr_pct"], tr["inkernel_vfs"]["detection_pct"], 100.0 - tr["inkernel_vfs"]["leak_pct"]]

    fig, ax = plt.subplots(figsize=(6.8, 2.35), dpi=300)
    x = np.arange(len(metrics))
    w = 0.24

    b1 = ax.bar(x - w, fim_vals, width=w, label="Traditional FIM (inotify)", color=SLATE_LIGHT, zorder=3)
    b2 = ax.bar(x, heur_vals, width=w, label="eBPF Userspace (pidfd)", color=GOLD, zorder=3)
    b3 = ax.bar(x + w, kern_vals, width=w, label="eBPF In-Kernel VFS (bpf_send_signal)", color=PURPLE, zorder=3)

    ax.set_ylim(0, 122)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=8.2, fontweight="bold")
    ax.set_ylabel("Percentage (%)", fontsize=8.5, fontweight="bold")
    ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.15), fontsize=7.6)
    clean_axes(ax)

    for bars in (b1, b2, b3):
        for bar in bars:
            v = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                v + 2.5,
                f"{v:.0f}%",
                ha="center",
                va="bottom",
                fontsize=7.3,
                fontweight="bold",
            )

    fig.tight_layout()
    fig.savefig(ASSETS / "fig4_system_resilience.svg", bbox_inches="tight")
    plt.close(fig)


def main():
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    make_fig1(data)
    make_fig2()
    make_fig3(data)
    make_fig4(data)
    print("Generated 4 Habib-purple vector SVG figures in report/assets/")


if __name__ == "__main__":
    main()
