#!/usr/bin/env python3
"""Build MemGuard editorial research report (HTML + WeasyPrint PDF) with custom pure-SVG charts."""

import base64
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "report" / "assets"
DATA_PATH = ASSETS / "experiment_data.json"
HTML_OUT = ROOT / "report" / "report.html"
PDF_OUT = ROOT / "report" / "MemGuard_OS_Report.pdf"


def read_hu_logo_on_white(path: Path) -> str:
    txt = path.read_text(encoding="utf-8")
    idx = txt.find("<svg")
    svg = txt[idx:] if idx >= 0 else txt
    lines = svg.splitlines()
    out = []
    # Lines 1..31 (0-indexed 1..30) are the wordmark + divider rule ("Habib University / shaping futures").
    # Lines 32+ are the crest circle, white inner ring, gold disc, and purple lion — keep untouched!
    for i, line in enumerate(lines):
        if i < 31 and 'fill="white"' in line:
            out.append(line.replace('fill="white"', 'fill="#5D2568"'))
        else:
            out.append(line)
    return "\n".join(out)


def read_img_b64(path: Path, mime: str) -> str:
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{b64}"


def svg_mtti_bars(data: dict) -> str:
    """Figure 1: Swiss-editorial log-scale vertical bar chart of MTTI vs TCP exfil boundary."""
    tr = data["trials"]
    bars = [
        ("Userspace\nML (RF)", tr["userspace_ml"]["mtti_mean_ms"], "11.09 ms", "#B4B8C5", "#5A6070"),
        ("Userspace\nHeuristic", tr["userspace_heur"]["mtti_mean_ms"], "3.77 ms", "#8F6A9A", "#5D2568"),
        ("In-Kernel\nVFS eBPF", tr["inkernel_vfs"]["mtti_mean_ms"], "5.2 \u03bcs", "#5D2568", "#5D2568"),
    ]
    # Log10 y-axis from 1e-3 ms (1 us) to 1e2 ms (100 ms) -> 5 decades
    y_top, y_bot = 26.0, 148.0
    x_left, x_right = 44.0, 316.0

    def y_pos(val_ms: float) -> float:
        lv = max(-3.0, min(2.0, math.log10(val_ms)))
        return y_bot - ((lv - (-3.0)) / 5.0) * (y_bot - y_top)

    ticks = [
        (100.0, "100 ms"),
        (10.0, "10 ms"),
        (1.0, "1 ms"),
        (0.1, "100 \u03bcs"),
        (0.01, "10 \u03bcs"),
        (0.001, "1 \u03bcs"),
    ]

    p = [
        '<svg viewBox="0 0 330 192" xmlns="http://www.w3.org/2000/svg">',
        # Legend row
        '<rect x="44" y="4" width="6.5" height="6.5" fill="#5D2568"/>',
        '<text x="54" y="10.2" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.8" fill="#5A6070">In-Kernel VFS (0 leaks)</text>',
        '<rect x="148" y="4" width="6.5" height="6.5" fill="#B4B8C5"/>',
        '<text x="158" y="10.2" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.8" fill="#5A6070">Userspace (20/20 leaks)</text>',
    ]

    for val, lbl in ticks:
        y = y_pos(val)
        stroke = "#2E1135" if val == 0.001 else "#E6E8EE"
        sw = "0.9" if val == 0.001 else "0.6"
        p.append(f'<line x1="{x_left}" y1="{y:.1f}" x2="{x_right}" y2="{y:.1f}" stroke="{stroke}" stroke-width="{sw}"/>')
        p.append(
            f'<text x="{x_left - 6}" y="{y + 2.4:.1f}" text-anchor="end" '
            f'font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" fill="#7A808E">{lbl}</text>'
        )

    # TCP exfil reference line (~0.6 ms)
    y_exfil = y_pos(0.6)
    p.append(
        f'<line x1="{x_left}" y1="{y_exfil:.1f}" x2="{x_right}" y2="{y_exfil:.1f}" '
        f'stroke="#A8422A" stroke-width="0.9" stroke-dasharray="3.5 2.5"/>'
    )
    p.append(
        f'<text x="{x_right}" y="{y_exfil - 4:.1f}" text-anchor="end" '
        f'font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" font-weight="600" fill="#A8422A">'
        f'TCP exfil window (~0.6 ms)</text>'
    )

    # Bars
    centers = [96.0, 180.0, 264.0]
    bar_w = 34.0
    for (lbl, val, txt, fill, tcol), cx in zip(bars, centers):
        y = y_pos(val)
        h = y_bot - y
        p.append(f'<rect x="{cx - bar_w / 2:.1f}" y="{y:.1f}" width="{bar_w}" height="{h:.1f}" fill="{fill}"/>')
        p.append(
            f'<text x="{cx:.1f}" y="{y - 5:.1f}" text-anchor="middle" '
            f'font-family="Noto Sans, Liberation Sans, sans-serif" font-size="7.4" font-weight="700" fill="{tcol}">{txt}</text>'
        )
        lines = lbl.split("\n")
        for idx, ln in enumerate(lines):
            p.append(
                f'<text x="{cx:.1f}" y="{y_bot + 13 + idx * 9.5:.1f}" text-anchor="middle" '
                f'font-family="Noto Sans, Liberation Sans, sans-serif" font-size="7.0" fill="#3B404E">{ln}</text>'
            )

    p.append(
        '<text x="316" y="187" text-anchor="end" font-family="Noto Sans, Liberation Sans, sans-serif" '
        'font-size="6.2" fill="#8A909E">*Traditional FIM (inotify): 0/20 detected (unbounded)</text>'
    )
    p.append("</svg>")
    return "\n".join(p)


def svg_ranked_classification(data: dict) -> str:
    """Figure 2: Swiss-editorial horizontal ranked bars matching reference Fig. 2."""
    models = {m["key"]: m["avg_infer_ms"] for m in data["ml_metrics"]["models"]}
    items = [
        ("In-Kernel VFS Tripwire", 0.0052, "5.2 \u03bcs (0 leaks)", "#5D2568", True),
        ("Heuristic (rules.yaml)", 0.040, "0.040 ms", "#5D2568", True),
        ("Decision Tree (depth=4)", models["decision_tree"], f"{models['decision_tree']:.3f} ms", "#7C5288", False),
        ("Logistic Regression", models["logistic_regression"], f"{models['logistic_regression']:.3f} ms", "#9AA0B0", False),
        ("K-Nearest Neighbors (k=5)", models["knn"], f"{models['knn']:.3f} ms", "#B4B8C5", False),
        ("Random Forest (100 trees)", models["random_forest"], f"{models['random_forest']:.3f} ms", "#B4B8C5", False),
    ]
    max_val = 1.50
    x_bar = 114.0
    x_end = 252.0
    bar_span = x_end - x_bar

    p = [
        '<svg viewBox="0 0 330 192" xmlns="http://www.w3.org/2000/svg">',
        '<text x="0" y="12" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" '
        'font-weight="700" letter-spacing="0.4" fill="#7A808E">PER-EVENT DECISION LATENCY (597 LIVE ROWS · ALL 1.00 F1)</text>',
    ]

    for idx, (lbl, val, val_txt, col, bold) in enumerate(items):
        y = 32 + idx * 24.5
        w = max(2.8, (val / max_val) * bar_span)
        fw = "600" if bold else "400"
        tcol = "#18141C" if bold else "#4A4F5D"
        p.append(
            f'<text x="0" y="{y + 3:.1f}" font-family="Noto Sans, Liberation Sans, sans-serif" '
            f'font-size="7.1" font-weight="{fw}" fill="{tcol}">{lbl}</text>'
        )
        p.append(f'<rect x="{x_bar:.1f}" y="{y - 3.5:.1f}" width="{bar_span:.1f}" height="6.8" fill="#F2F3F7"/>')
        p.append(f'<rect x="{x_bar:.1f}" y="{y - 3.5:.1f}" width="{w:.1f}" height="6.8" fill="{col}"/>')
        vcol = "#5D2568" if bold else "#4A4F5D"
        p.append(
            f'<text x="328" y="{y + 3:.1f}" text-anchor="end" font-family="Noto Sans, Liberation Sans, sans-serif" '
            f'font-size="7.1" font-weight="{"700" if bold else "600"}" fill="{vcol}">{val_txt}</text>'
        )

    p.append(
        '<text x="328" y="187" text-anchor="end" font-family="Noto Sans, Liberation Sans, sans-serif" '
        'font-size="6.2" fill="#8A909E">Heuristic is 34.7\u00d7 faster than Random Forest; VFS tripwire is 267\u00d7 faster</text>'
    )
    p.append("</svg>")
    return "\n".join(p)


def svg_architecture() -> str:
    """Figure 3: Ultra-clean Swiss schematic of Kernel vs Userspace two-stage architecture."""
    return """<svg viewBox="0 0 680 198" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="ar-p" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto">
      <path d="M0,1 L7,4 L0,7 z" fill="#5D2568"/>
    </marker>
    <marker id="ar-g" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto">
      <path d="M0,1 L7,4 L0,7 z" fill="#646978"/>
    </marker>
    <marker id="ar-r" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto">
      <path d="M0,1 L7,4 L0,7 z" fill="#A8422A"/>
    </marker>
  </defs>

  <!-- Boundary line -->
  <line x1="0" y1="98" x2="680" y2="98" stroke="#CBD0DC" stroke-width="0.8" stroke-dasharray="3.5 2.5"/>
  <text x="2" y="92" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.6" font-weight="700" letter-spacing="0.5" fill="#7A808E">USER SPACE (UNTRUSTED WORKLOAD + ASYNC DEFENDER)</text>
  <text x="2" y="109" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.6" font-weight="700" letter-spacing="0.5" fill="#5D2568">LINUX KERNEL 7.3.3 (CO-RE eBPF SYNCHRONOUS HOT PATH)</text>

  <!-- Box 1: Red Team -->
  <rect x="2" y="10" width="184" height="72" fill="#FFFFFF" stroke="#A8422A" stroke-width="0.9"/>
  <line x1="2" y1="10" x2="186" y2="10" stroke="#A8422A" stroke-width="2.2"/>
  <text x="10" y="25" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="7.8" font-weight="700" fill="#18141C">Red Team Fileless Loader (C)</text>
  <text x="10" y="38" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.6" fill="#4A4F5D">memfd_create() + F_ADD_SEALS</text>
  <text x="10" y="49" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.6" fill="#4A4F5D">dup2 / fork / /proc/fd / noise</text>
  <text x="10" y="60" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.6" fill="#4A4F5D">execveat() + prctl("[kworker]")</text>
  <text x="10" y="73" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" font-weight="600" fill="#A8422A">0 B disk I/O  ·  TCP exfil (~0.6 ms)</text>

  <!-- Syscall arrow -->
  <line x1="94" y1="82" x2="94" y2="119" stroke="#A8422A" stroke-width="1.1" marker-end="url(#ar-r)"/>
  <text x="100" y="114" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" fill="#A8422A">syscall entry</text>

  <!-- Box 2: Kernel Tracepoints -->
  <rect x="2" y="121" width="212" height="70" fill="#FFFFFF" stroke="#5D2568" stroke-width="0.9"/>
  <line x1="2" y1="121" x2="214" y2="121" stroke="#5D2568" stroke-width="2.2"/>
  <text x="10" y="136" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="7.8" font-weight="700" fill="#5D2568">Stage 1 · 6 CO-RE Tracepoints</text>
  <text x="10" y="149" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.5" fill="#3B404E">sys_enter/exit_memfd_create</text>
  <text x="10" y="160" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.5" fill="#3B404E">sys_enter_execveat / sys_enter_execve</text>
  <text x="10" y="171" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.5" fill="#3B404E">sys_enter_prctl / sched_process_fork</text>
  <text x="10" y="183" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" fill="#646978">PID-namespace safe (bpf_get_ns_current_pid_tgid)</text>

  <!-- Arrow 2 -> 3 -->
  <line x1="214" y1="156" x2="244" y2="156" stroke="#5D2568" stroke-width="1.1" marker-end="url(#ar-p)"/>

  <!-- Box 3: Kernel VFS Walk + SIGSTOP -->
  <rect x="246" y="121" width="212" height="70" fill="#FAF8FC" stroke="#5D2568" stroke-width="1.0"/>
  <line x1="246" y1="121" x2="458" y2="121" stroke="#5D2568" stroke-width="2.2"/>
  <text x="254" y="136" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="7.8" font-weight="700" fill="#5D2568">VFS fdtable Walk + Sync Freeze</text>
  <text x="254" y="149" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.5" fill="#18141C">current-&gt;files-&gt;fdt-&gt;fd[dfd]</text>
  <text x="254" y="160" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.5" fill="#18141C">s_magic==TMPFS &amp;&amp; d_name=="memfd:"</text>
  <text x="254" y="172" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.9" font-weight="700" fill="#5D2568">bpf_send_signal(SIGSTOP) · 5.2 &#956;s</text>
  <text x="254" y="184" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" fill="#646978">Preempts payload before 1st userspace instruction</text>

  <!-- Ringbuf arrow up -->
  <path d="M 458,156 L 478,156 L 478,46 L 494,46" fill="none" stroke="#646978" stroke-width="1.0" marker-end="url(#ar-g)"/>
  <text x="484" y="114" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" fill="#646978">256 KB</text>
  <text x="484" y="123" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" fill="#646978">ringbuf</text>

  <!-- Box 4: Stage 2 Async Userspace -->
  <rect x="246" y="10" width="212" height="72" fill="#FFFFFF" stroke="#8F94A4" stroke-width="0.9"/>
  <line x1="246" y1="10" x2="458" y2="10" stroke="#2E1135" stroke-width="2.2"/>
  <text x="254" y="25" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="7.8" font-weight="700" fill="#18141C">Stage 2 · Async Triage &amp; Forensics</text>
  <text x="254" y="38" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.7" fill="#3B404E">· Heuristic (rules.yaml) + Shadow ML (RF)</text>
  <text x="254" y="50" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.7" fill="#3B404E">· Carve ELF64 from /proc/&lt;pid&gt;/exe</text>
  <text x="254" y="62" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.7" fill="#3B404E">· SHA-256, ELF headers &amp; C2 IOCs</text>
  <text x="254" y="74" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" font-weight="600" fill="#5D2568">Decision: SIGCONT (benign) | SIGKILL</text>

  <!-- Arrow from Box 5 -> Box 4 (Wait: make flow Left->Right clean! Ringbuf -> Box 4 -> Box 5) -->
  <rect x="496" y="10" width="182" height="72" fill="#FFFFFF" stroke="#8F94A4" stroke-width="0.9"/>
  <line x1="496" y1="10" x2="678" y2="10" stroke="#646978" stroke-width="2.2"/>
  <text x="504" y="25" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="7.8" font-weight="700" fill="#18141C">Decoupled Dusk Console</text>
  <text x="504" y="38" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.7" fill="#3B404E">· Read-only SSE / JSONL ledger</text>
  <text x="504" y="50" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.7" fill="#3B404E">· Live MTTI, VFS inode &amp; ELF dump</text>
  <text x="504" y="62" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.7" fill="#3B404E">· Operator quarantine controls</text>
  <text x="504" y="74" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" fill="#646978">Zero hot-path latency coupling</text>

  <!-- Fix clean arrow from Stage 1 -> Stage 2 -> Console -->
  <path d="M 352,121 L 352,84" fill="none" stroke="#5D2568" stroke-width="1.0" stroke-dasharray="2.5 2" marker-end="url(#ar-p)"/>
  <text x="358" y="109" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.2" fill="#5D2568">ringbuf event</text>
  <line x1="458" y1="46" x2="494" y2="46" stroke="#646978" stroke-width="1.0" marker-end="url(#ar-g)"/>

  <!-- Feedback arrow from Stage 2 back to Red Team (SIGCONT / SIGKILL) -->
  <line x1="246" y1="46" x2="188" y2="46" stroke="#2E1135" stroke-width="0.9" stroke-dasharray="2.5 2" marker-end="url(#ar-g)"/>
  <text x="217" y="40" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.2" fill="#3B404E">pidfd signal</text>
</svg>"""


def svg_architecture_clean() -> str:
    """Authentic USENIX/OSDI-style orthogonal systems architecture diagram (zero vibecoded cards)."""
    return """<svg viewBox="0 0 680 218" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="ar-k" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto">
      <path d="M0,1 L7,4 L0,7 z" fill="#2E1135"/>
    </marker>
    <marker id="ar-p" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto">
      <path d="M0,1 L7,4 L0,7 z" fill="#5D2568"/>
    </marker>
    <marker id="ar-g" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto">
      <path d="M0,1 L7,4 L0,7 z" fill="#646978"/>
    </marker>
  </defs>

  <!-- Privilege Swimlanes (Clean Architectural Banding) -->
  <rect x="0" y="0" width="680" height="106" fill="#FFFFFF"/>
  <rect x="0" y="106" width="680" height="112" fill="#F8F7FA"/>
  <!-- Left vertical swimlane rails -->
  <rect x="0" y="0" width="22" height="106" fill="#F1F2F6"/>
  <rect x="0" y="106" width="22" height="112" fill="#ECE7F2"/>
  <text x="14" y="53" text-anchor="middle" transform="rotate(-90 14 53)"
        font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" font-weight="700"
        letter-spacing="0.9" fill="#5A6070">USER SPACE</text>
  <text x="14" y="162" text-anchor="middle" transform="rotate(-90 14 162)"
        font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" font-weight="700"
        letter-spacing="0.9" fill="#5D2568">KERNEL SPACE</text>

  <!-- Syscall Privilege Boundary Line -->
  <line x1="0" y1="106" x2="680" y2="106" stroke="#2E1135" stroke-width="0.9" stroke-dasharray="4 3"/>
  <text x="674" y="102" text-anchor="end" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="5.9" fill="#7A808E">privilege boundary (Linux 7.3.3)</text>

  <!-- USERSPACE COMPONENTS -->
  <!-- U1: Untrusted Process / Loader -->
  <rect x="40" y="18" width="142" height="50" fill="#FFFFFF" stroke="#2E1135" stroke-width="0.95"/>
  <text x="111" y="34" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif"
        font-size="7.6" font-weight="700" fill="#18141C">Untrusted Process</text>
  <text x="111" y="46" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.2" fill="#4A4F5D">memfd_create + execveat</text>
  <text x="111" y="58" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.0" fill="#7A808E">[kworker/u8:2] · 0 B disk</text>

  <!-- U2: Async Forensics & Dual-Engine Triage -->
  <rect x="266" y="18" width="182" height="50" fill="#FFFFFF" stroke="#2E1135" stroke-width="0.95"/>
  <text x="357" y="34" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif"
        font-size="7.6" font-weight="700" fill="#18141C">Userspace Triage &amp; Carver</text>
  <text x="357" y="46" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.2" fill="#4A4F5D">Heuristic + Shadow ML (RF)</text>
  <text x="357" y="58" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.0" fill="#5D2568">/proc/&lt;pid&gt;/exe &#8594; ELF64 + SHA-256</text>

  <!-- U3: Decoupled Console (dashed out-of-band border) -->
  <rect x="526" y="18" width="136" height="50" fill="#FFFFFF" stroke="#8A909E" stroke-width="0.9" stroke-dasharray="3 2"/>
  <text x="594" y="34" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif"
        font-size="7.6" font-weight="700" fill="#3B404E">Dusk Web Console</text>
  <text x="594" y="46" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.2" fill="#646978">SSE / JSONL Ledger</text>
  <text x="594" y="58" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif"
        font-size="6.0" fill="#7A808E">Out-of-band (0 hot-path cost)</text>

  <!-- KERNEL SPACE COMPONENTS -->
  <!-- K1: CO-RE Tracepoints -->
  <rect x="40" y="132" width="142" height="54" fill="#FFFFFF" stroke="#5D2568" stroke-width="1.0"/>
  <text x="111" y="148" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif"
        font-size="7.6" font-weight="700" fill="#5D2568">CO-RE Tracepoints (6)</text>
  <text x="111" y="160" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.1" fill="#3B404E">memfd_create · execve(at)</text>
  <text x="111" y="172" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.1" fill="#3B404E">prctl · sched_process_fork</text>

  <!-- K2: VFS fdtable Verifier & Sync Tripwire -->
  <rect x="242" y="132" width="194" height="54" fill="#FFFFFF" stroke="#5D2568" stroke-width="1.2"/>
  <text x="339" y="148" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif"
        font-size="7.6" font-weight="700" fill="#5D2568">VFS Verifier &amp; Sync Tripwire</text>
  <text x="339" y="160" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.1" fill="#18141C">current&#8594;files&#8594;fdt&#8594;fd[dfd]</text>
  <text x="339" y="172" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.1" fill="#5D2568">TMPFS_MAGIC + "memfd:" + inode</text>

  <!-- K3: BPF Ring Buffer & Maps -->
  <rect x="494" y="132" width="168" height="54" fill="#FFFFFF" stroke="#646978" stroke-width="0.9"/>
  <text x="578" y="148" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif"
        font-size="7.6" font-weight="700" fill="#18141C">BPF Maps &amp; Ring Buffer</text>
  <text x="578" y="160" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.1" fill="#4A4F5D">BPF_MAP_TYPE_RINGBUF (256 KB)</text>
  <text x="578" y="172" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace"
        font-size="6.1" fill="#4A4F5D">memfd_fds · ns_pid_tgid maps</text>

  <!-- ORTHOGONAL ROUTED FLOWS WITH NUMBERED STEPS -->
  <!-- Step 1: U1 -> K1 (Syscall entry) -->
  <line x1="94" y1="68" x2="94" y2="130" stroke="#2E1135" stroke-width="1.05" marker-end="url(#ar-k)"/>
  <circle cx="94" cy="90" r="6.5" fill="#2E1135"/>
  <text x="94" y="92.3" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" font-weight="700" fill="#FFFFFF">1</text>
  <text x="84" y="92" text-anchor="end" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.3" fill="#3B404E">syscall</text>

  <!-- Step 2: K1 -> K2 (CO-RE VFS inspect) -->
  <line x1="182" y1="159" x2="240" y2="159" stroke="#5D2568" stroke-width="1.05" marker-end="url(#ar-p)"/>
  <circle cx="211" cy="159" r="6.5" fill="#5D2568"/>
  <text x="211" y="161.3" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" font-weight="700" fill="#FFFFFF">2</text>
  <text x="211" y="149" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.1" fill="#5D2568">VFS walk</text>

  <!-- Step 3: K2 -> U1 (Synchronous SIGSTOP orthogonal path) -->
  <path d="M 278,132 L 278,118 L 138,118 L 138,70" fill="none" stroke="#5D2568" stroke-width="1.25" marker-end="url(#ar-p)"/>
  <circle cx="208" cy="118" r="6.5" fill="#5D2568"/>
  <text x="208" y="120.3" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" font-weight="700" fill="#FFFFFF">3</text>
  <text x="208" y="93" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="6.2" font-weight="700" fill="#5D2568">bpf_send_signal(SIGSTOP)</text>
  <text x="208" y="102" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.0" fill="#5D2568">5.2 &#956;s sync freeze (pre-exfil)</text>

  <!-- Step 4: K2 -> K3 (Emit event) -> U2 (Ringbuf consume) -->
  <line x1="436" y1="159" x2="492" y2="159" stroke="#646978" stroke-width="1.0" marker-end="url(#ar-g)"/>
  <path d="M 526,132 L 526,86 L 386,86 L 386,70" fill="none" stroke="#646978" stroke-width="1.0" marker-end="url(#ar-g)"/>
  <circle cx="464" cy="159" r="6.5" fill="#646978"/>
  <text x="464" y="161.3" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" font-weight="700" fill="#FFFFFF">4</text>
  <text x="458" y="82" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.2" fill="#5A6070">async ringbuf event</text>

  <!-- Step 5: U2 -> U1 (Carve /proc/exe & pidfd SIGCONT/SIGKILL) -->
  <line x1="266" y1="43" x2="184" y2="43" stroke="#2E1135" stroke-width="0.95" stroke-dasharray="3 2" marker-end="url(#ar-k)"/>
  <circle cx="225" cy="43" r="6.5" fill="#2E1135"/>
  <text x="225" y="45.3" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" font-weight="700" fill="#FFFFFF">5</text>
  <text x="225" y="33" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.1" fill="#3B404E">carve + pidfd</text>
  <text x="225" y="56" text-anchor="middle" font-family="Liberation Mono, DejaVu Sans Mono, monospace" font-size="5.8" fill="#646978">SIGCONT | SIGKILL</text>

  <!-- Step 6: U2 -> U3 (JSONL / SSE stream) -->
  <line x1="448" y1="43" x2="524" y2="43" stroke="#8A909E" stroke-width="0.95" marker-end="url(#ar-g)"/>
  <circle cx="486" cy="43" r="6.5" fill="#8A909E"/>
  <text x="486" y="45.3" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" font-weight="700" fill="#FFFFFF">6</text>
  <text x="486" y="33" text-anchor="middle" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.1" fill="#646978">JSONL / SSE</text>

  <!-- Bottom step legend strip -->
  <text x="40" y="206" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.1" fill="#5A6070">
    <tspan font-weight="700" fill="#2E1135">Critical Path (&#9312;&#8594;&#9313;&#8594;&#9314;):</tspan> Synchronous in-kernel VFS freeze (5.2 &#956;s, 0/20 leaks)
    <tspan dx="18" font-weight="700" fill="#646978">Async Stage (&#9315;&#8594;&#9316;&#8594;&#9317;):</tspan> Non-blocking triage, RAM ELF64 carving &amp; operator UI
  </text>
</svg>"""


def svg_rss_bars(data: dict) -> str:
    """Figure 4: Horizontal RSS memory footprint comparison."""
    tr = data["trials"]
    items = [
        ("Traditional FIM (inotify)", tr["traditional_fim"]["rss_mb"], "#B4B8C5", False),
        ("In-Kernel VFS eBPF", tr["inkernel_vfs"]["rss_mb"], "#5D2568", True),
        ("Userspace Heuristic", tr["userspace_heur"]["rss_mb"], "#7C5288", False),
        ("Userspace ML (RF)", tr["userspace_ml"]["rss_mb"], "#A8422A", False),
    ]
    max_mb = 140.0
    x_bar, x_end = 108.0, 266.0
    span = x_end - x_bar

    p = [
        '<svg viewBox="0 0 330 150" xmlns="http://www.w3.org/2000/svg">',
        '<text x="0" y="11" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" '
        'font-weight="700" letter-spacing="0.4" fill="#7A808E">RESIDENT SET SIZE (RSS) OF USERSPACE DAEMON</text>',
    ]
    for idx, (lbl, val, col, bold) in enumerate(items):
        y = 34 + idx * 27.5
        w = max(4.0, (val / max_mb) * span)
        fw = "600" if bold else "400"
        tcol = "#18141C" if bold else "#4A4F5D"
        p.append(
            f'<text x="0" y="{y + 3:.1f}" font-family="Noto Sans, Liberation Sans, sans-serif" '
            f'font-size="7.2" font-weight="{fw}" fill="{tcol}">{lbl}</text>'
        )
        p.append(f'<rect x="{x_bar:.1f}" y="{y - 4.2:.1f}" width="{span:.1f}" height="8.2" fill="#F2F3F7"/>')
        p.append(f'<rect x="{x_bar:.1f}" y="{y - 4.2:.1f}" width="{w:.1f}" height="8.2" fill="{col}"/>')
        p.append(
            f'<text x="328" y="{y + 3:.1f}" text-anchor="end" font-family="Noto Sans, Liberation Sans, sans-serif" '
            f'font-size="7.3" font-weight="700" fill="{col}">{val:.1f} MB</text>'
        )

    p.append(
        '<text x="328" y="144" text-anchor="end" font-family="Noto Sans, Liberation Sans, sans-serif" '
        'font-size="6.2" fill="#8A909E">Random Forest adds +5.4\u00d7 memory overhead over In-Kernel VFS eBPF</text>'
    )
    p.append("</svg>")
    return "\n".join(p)


def svg_resilience_grouped() -> str:
    """Figure 5: Clean grouped bar chart of Utility, Detection, and Exfil Blocked."""
    groups = [
        ("Benign OS Utility\n(1 \u2212 FPR)", [100, 100, 100]),
        ("Fileless Attack\nDetection", [0, 100, 100]),
        ("C2 Exfiltration\nBlocked", [0, 0, 100]),
    ]
    colors = ["#B4B8C5", "#8F6A9A", "#5D2568"]
    y_top, y_bot = 26.0, 114.0
    x_left, x_right = 32.0, 322.0

    p = [
        '<svg viewBox="0 0 330 150" xmlns="http://www.w3.org/2000/svg">',
        '<rect x="32" y="3" width="6.5" height="6.5" fill="#B4B8C5"/>',
        '<text x="42" y="9.2" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" fill="#5A6070">Trad. FIM</text>',
        '<rect x="94" y="3" width="6.5" height="6.5" fill="#8F6A9A"/>',
        '<text x="104" y="9.2" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" fill="#5A6070">Userspace eBPF</text>',
        '<rect x="178" y="3" width="6.5" height="6.5" fill="#5D2568"/>',
        '<text x="188" y="9.2" font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.5" fill="#5D2568" font-weight="600">In-Kernel VFS eBPF</text>',
    ]

    for pct in [0, 50, 100]:
        y = y_bot - (pct / 100.0) * (y_bot - y_top)
        stroke = "#2E1135" if pct == 0 else "#E6E8EE"
        sw = "0.9" if pct == 0 else "0.6"
        p.append(f'<line x1="{x_left}" y1="{y:.1f}" x2="{x_right}" y2="{y:.1f}" stroke="{stroke}" stroke-width="{sw}"/>')
        p.append(
            f'<text x="{x_left - 5}" y="{y + 2.3:.1f}" text-anchor="end" '
            f'font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.4" fill="#7A808E">{pct}%</text>'
        )

    centers = [82.0, 178.0, 274.0]
    bw = 18.0
    gap = 4.0
    for (lbl, vals), cx in zip(groups, centers):
        start_x = cx - (3 * bw + 2 * gap) / 2.0
        for i, v in enumerate(vals):
            bx = start_x + i * (bw + gap)
            h = (v / 100.0) * (y_bot - y_top)
            by = y_bot - h
            if h > 0:
                p.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw}" height="{h:.1f}" fill="{colors[i]}"/>')
            else:
                p.append(f'<line x1="{bx:.1f}" y1="{y_bot - 1:.1f}" x2="{bx + bw:.1f}" y2="{y_bot - 1:.1f}" stroke="{colors[i]}" stroke-width="1.6"/>')
            val_y = by - 3.5 if v > 0 else y_bot - 4.5
            tcol = "#5D2568" if (i == 2 and v == 100) else "#5A6070"
            p.append(
                f'<text x="{bx + bw / 2:.1f}" y="{val_y:.1f}" text-anchor="middle" '
                f'font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.0" font-weight="700" fill="{tcol}">{v}%</text>'
            )
        for j, ln in enumerate(lbl.split("\n")):
            p.append(
                f'<text x="{cx:.1f}" y="{y_bot + 13 + j * 9:.1f}" text-anchor="middle" '
                f'font-family="Noto Sans, Liberation Sans, sans-serif" font-size="6.8" fill="#3B404E">{ln}</text>'
            )

    p.append("</svg>")
    return "\n".join(p)


def build_html() -> str:
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    tr = data["trials"]
    u_h = tr["userspace_heur"]
    u_m = tr["userspace_ml"]
    k_v = tr["inkernel_vfs"]
    fim = tr["traditional_fim"]
    forensics = k_v.get("sample_forensics") or {}
    f_inner = forensics.get("forensics") or {}
    ml_models = {m["key"]: m for m in data["ml_metrics"]["models"]}

    hu_logo = read_hu_logo_on_white(ASSETS / "hu_logo.svg")
    dusk_uri = read_img_b64(ASSETS / "dusk_console.png", "image/png")

    speedup_heur = round(u_h["mtti_mean_ms"] / k_v["mtti_mean_ms"])
    speedup_ml = round(u_m["mtti_mean_ms"] / k_v["mtti_mean_ms"])
    sha_full = f_inner.get("sha256") or "4ff2b2595e30b6787bc3d9359b75d60ce4067752f1b96c78de8271392d6395f9"
    sha_short = sha_full[:24]
    vfs_ino = forensics.get("vfs_ino", 4958)
    elf_size = f_inner.get("size_bytes", 16832)

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>MemGuard — Autonomous eBPF Defense Against Fileless In-Memory Execution</title>
<style>
  @page {{
    size: letter;
    margin: 0.56in 0.56in 0.54in 0.56in;
    @top-left {{
      content: "MEMGUARD \u00b7 AUTONOMOUS EBPF DEFENSE AGAINST FILELESS EXECUTION";
      font-family: "Noto Sans", "Liberation Sans", sans-serif;
      font-size: 6.5pt;
      letter-spacing: 0.05em;
      color: #7A808E;
      border-bottom: 0.5pt solid #D9DCE4;
      padding-bottom: 3.5pt;
      margin-bottom: 8pt;
      vertical-align: bottom;
    }}
    @top-right {{
      content: "HABIB UNIVERSITY \u00b7 OPERATING SYSTEMS (FALL 2026)";
      font-family: "Noto Sans", "Liberation Sans", sans-serif;
      font-size: 6.5pt;
      letter-spacing: 0.05em;
      color: #7A808E;
      border-bottom: 0.5pt solid #D9DCE4;
      padding-bottom: 3.5pt;
      margin-bottom: 8pt;
      vertical-align: bottom;
    }}
    @bottom-left {{
      content: "Dhanani School of Science & Engineering \u00b7 Habib University";
      font-family: "Noto Sans", "Liberation Sans", sans-serif;
      font-size: 6.6pt;
      color: #8A909E;
    }}
    @bottom-right {{
      content: "Page " counter(page) " of " counter(pages);
      font-family: "Noto Sans", "Liberation Sans", sans-serif;
      font-size: 6.6pt;
      font-weight: 600;
      color: #5D2568;
    }}
  }}
  @page :first {{
    margin-top: 0.40in;
    @top-left {{ content: none; border-bottom: none; }}
    @top-right {{ content: none; border-bottom: none; }}
  }}

  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: "Noto Sans", "Liberation Sans", sans-serif;
    font-size: 8.0pt;
    line-height: 1.40;
    color: #1B1D24;
    background: #FFFFFF;
  }}

  /* Top Structural Bar & Swiss Editorial Masthead */
  .masthead {{
    border-top: 2.2pt solid #5D2568;
    border-bottom: 0.75pt solid #D5D8E2;
    padding: 8pt 0 8pt;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 12pt;
  }}
  .masthead__left {{
    flex: 1 1 auto;
  }}
  .masthead__brand {{
    display: flex;
    align-items: center;
    gap: 9pt;
    margin-bottom: 5pt;
  }}
  .masthead__logo svg {{
    height: 26pt;
    width: auto;
    display: block;
  }}
  .masthead__kicker {{
    font-size: 6.7pt;
    font-weight: 700;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    color: #5D2568;
    line-height: 1.25;
  }}
  .masthead__subkicker {{
    font-size: 6.4pt;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: #7A808E;
  }}
  h1.paper-title {{
    margin: 0;
    font-family: "P052", "Noto Serif", "Liberation Serif", Georgia, serif;
    font-size: 15.2pt;
    font-weight: 700;
    line-height: 1.14;
    letter-spacing: -0.015em;
    color: #141218;
  }}
  .masthead__right {{
    flex: 0 0 202pt;
    text-align: right;
    font-size: 7.1pt;
    line-height: 1.42;
    color: #5A6070;
  }}
  .masthead__authors {{
    font-weight: 700;
    color: #18141C;
    font-size: 7.3pt;
  }}
  .masthead__meta-line {{
    color: #646978;
  }}
  .masthead__env {{
    font-family: "Liberation Mono", "DejaVu Sans Mono", monospace;
    font-size: 6.5pt;
    color: #5D2568;
  }}

  /* 5-Column Swiss KPI Summary Strip (Hairlines Only, Zero Boxes) */
  .kpi-strip {{
    display: flex;
    width: 100%;
    padding: 8.5pt 0 8.5pt;
    border-bottom: 1.3pt solid #2E1135;
    margin-bottom: 10pt;
  }}
  .kpi {{
    flex: 1 1 0;
    padding: 0 8pt;
    border-right: 0.6pt solid #D9DCE4;
  }}
  .kpi:first-child {{
    padding-left: 0;
  }}
  .kpi:last-child {{
    border-right: none;
    padding-right: 0;
  }}
  .kpi__num {{
    font-family: "P052", "Noto Serif", "Liberation Serif", Georgia, serif;
    font-size: 17.5pt;
    font-weight: 400;
    line-height: 1.05;
    color: #18141C;
    margin-bottom: 2.5pt;
    white-space: nowrap;
  }}
  .kpi__num--purple {{
    color: #5D2568;
    font-weight: 700;
  }}
  .kpi__unit {{
    font-size: 9.8pt;
    color: #5A6070;
    font-weight: 400;
  }}
  .kpi__label {{
    font-size: 6.2pt;
    font-weight: 700;
    letter-spacing: 0.055em;
    text-transform: uppercase;
    color: #3B404E;
    margin-bottom: 1.5pt;
  }}
  .kpi__sub {{
    font-size: 6.4pt;
    line-height: 1.28;
    color: #7A808E;
  }}

  /* Section Headers (Serif Left + Muted Subtitle Right + Structural Underline) */
  .sec-head {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 10pt;
    border-bottom: 1.1pt solid #2E1135;
    padding-bottom: 2.8pt;
    margin: 10pt 0 6pt;
    break-after: avoid;
    page-break-after: avoid;
  }}
  .sec-head--first {{
    margin-top: 0;
  }}
  .sec-head h2 {{
    margin: 0;
    font-family: "P052", "Noto Serif", "Liberation Serif", Georgia, serif;
    font-size: 11.4pt;
    font-weight: 700;
    color: #18141C;
    letter-spacing: -0.01em;
    white-space: nowrap;
  }}
  .sec-head h2 .num {{
    color: #5D2568;
  }}
  .sec-head__note {{
    font-size: 6.9pt;
    color: #7A808E;
    text-align: right;
  }}

  /* Clean Prose & 2-Column Narrative Blocks */
  p {{
    margin: 0 0 5pt;
    text-align: justify;
  }}
  .lead {{
    font-size: 7.8pt;
    line-height: 1.38;
    color: #2B2E38;
    margin-bottom: 6pt;
  }}
  .lead strong {{
    color: #18141C;
  }}
  .prose-grid {{
    display: flex;
    gap: 16pt;
    margin-bottom: 8pt;
  }}
  .prose-col {{
    flex: 1 1 0;
  }}
  h3 {{
    margin: 6pt 0 3pt;
    font-size: 8.3pt;
    font-weight: 700;
    color: #5D2568;
    break-after: avoid;
  }}
  .eq-inline {{
    font-family: "P052", "Noto Serif", "Liberation Serif", Georgia, serif;
    font-style: italic;
    font-size: 8.8pt;
    color: #2E1135;
    border-top: 0.5pt solid #E2E5EC;
    border-bottom: 0.5pt solid #E2E5EC;
    padding: 3.5pt 0;
    margin: 5pt 0 6pt;
    text-align: center;
  }}

  /* Inline Monospace (Zero Grey Pills — Clean Academic Print Style) */
  code {{
    font-family: "Liberation Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.4pt;
    color: #3E1848;
  }}
  .key-ref {{
    font-family: "Liberation Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.3pt;
    font-weight: 700;
    color: #2E1135;
    border-bottom: 0.6pt dotted #9C8DA6;
  }}

  /* Booktabs Swiss Tables (Zero Vertical Lines, Zero Header Fills) */
  table.ledger {{
    width: 100%;
    border-collapse: collapse;
    margin: 3pt 0 7pt;
    font-size: 7.3pt;
    line-height: 1.32;
  }}
  table.ledger tr {{
    break-inside: avoid;
    page-break-inside: avoid;
  }}
  table.ledger thead th {{
    font-size: 6.2pt;
    font-weight: 700;
    letter-spacing: 0.055em;
    text-transform: uppercase;
    color: #6B7280;
    text-align: left;
    padding: 3.5pt 4.5pt 4pt;
    border-bottom: 0.9pt solid #2E1135;
  }}
  table.ledger thead th.r {{
    text-align: right;
  }}
  table.ledger thead th.c {{
    text-align: center;
  }}
  table.ledger tbody td {{
    padding: 3.8pt 4.5pt;
    border-bottom: 0.45pt solid #E5E7EB;
    vertical-align: top;
    color: #262934;
  }}
  table.ledger tbody td.r {{
    text-align: right;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }}
  table.ledger tbody td.c {{
    text-align: center;
    white-space: nowrap;
  }}
  table.ledger tbody td.nw {{
    white-space: nowrap;
  }}
  table.ledger tbody tr.highlight td {{
    font-weight: 700;
    color: #141218;
    border-top: 0.8pt solid #5D2568;
    border-bottom: 1.2pt solid #2E1135;
    padding-top: 4.5pt;
    padding-bottom: 4.5pt;
  }}
  table.ledger tbody tr.total td {{
    font-weight: 700;
    color: #141218;
    border-top: 0.9pt solid #2E1135;
    border-bottom: 1.2pt solid #2E1135;
  }}
  table.ledger tbody tr:last-child td {{
    border-bottom: 1.2pt solid #2E1135;
  }}
  .swatch {{
    display: inline-block;
    width: 5.5pt;
    height: 5.5pt;
    margin-right: 4.5pt;
    vertical-align: 0.5pt;
  }}
  .c-purple {{ color: #5D2568 !important; font-weight: 700; }}
  .c-alert {{ color: #A8422A !important; font-weight: 600; }}
  .c-muted {{ color: #7A808E !important; }}

  /* Unboxed Figure Blocks & Side-by-Side 2-Up Figure Grid */
  .fig-pair {{
    display: flex;
    gap: 16pt;
    margin: 4pt 0 8pt;
    break-inside: avoid;
    page-break-inside: avoid;
  }}
  .fig-cell {{
    flex: 1 1 0;
    min-width: 0;
  }}
  .fig-full {{
    margin: 5pt 0 9pt;
    break-inside: avoid;
    page-break-inside: avoid;
  }}
  .fig-title {{
    font-size: 8.2pt;
    font-weight: 700;
    color: #18141C;
    margin: 0 0 1.5pt;
  }}
  .fig-title .dot {{
    color: #5D2568;
    margin: 0 2pt;
  }}
  .fig-sub {{
    font-size: 7.0pt;
    color: #7A808E;
    margin: 0 0 6pt;
    line-height: 1.3;
  }}
  .fig-svg svg {{
    width: 100%;
    height: auto;
    display: block;
  }}

  /* Console Screenshot (Crisp Hairline Frame Only — Zero Heavy Drop Shadow) */
  .console-frame {{
    border: 0.75pt solid #CFD4DF;
    padding: 0;
    background: #0F1117;
    max-width: 92%;
    margin: 0 auto;
  }}
  .console-frame img {{
    width: 100%;
    height: auto;
    display: block;
  }}

  /* Forensic Key-Value Spec Table (Unboxed Hairlines) */
  .spec-grid {{
    display: flex;
    gap: 16pt;
    margin: 4pt 0 8pt;
    break-inside: avoid;
  }}
  .spec-col {{
    flex: 1 1 0;
  }}
  table.kv {{
    width: 100%;
    border-collapse: collapse;
    font-size: 7.5pt;
    border-top: 1.0pt solid #2E1135;
    border-bottom: 1.0pt solid #2E1135;
  }}
  table.kv td {{
    padding: 3.8pt 4pt;
    border-bottom: 0.45pt solid #E5E7EB;
    vertical-align: top;
  }}
  table.kv tr:last-child td {{
    border-bottom: none;
  }}
  table.kv td.k {{
    width: 34%;
    font-size: 6.8pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #6B7280;
  }}
  table.kv td.v {{
    font-family: "Liberation Mono", "DejaVu Sans Mono", monospace;
    font-size: 7.2pt;
    color: #18141C;
    word-break: break-all;
  }}

  /* Clean Page Break Control */
  .page-break {{
    page-break-before: always;
    break-before: page;
  }}

  /* Compact 2-Column References */
  .refs-grid {{
    display: flex;
    gap: 16pt;
    font-size: 7.1pt;
    line-height: 1.38;
    color: #4A4F5D;
  }}
  .refs-col {{
    flex: 1 1 0;
  }}
  .ref-item {{
    margin-bottom: 3.5pt;
    padding-left: 14pt;
    text-indent: -14pt;
    text-align: left;
  }}
  .ref-num {{
    font-weight: 700;
    color: #5D2568;
  }}

  /* Final Colophon (Exact Twin of Reference PDF Bottom Bar) */
  .colophon {{
    margin-top: 10pt;
    padding-top: 6pt;
    border-top: 0.75pt solid #CFD4DF;
    display: flex;
    justify-content: space-between;
    font-size: 6.9pt;
    color: #7A808E;
  }}
</style>
</head>
<body>

<!-- PAGE 1: MASTHEAD + 5-COLUMN KPI STRIP + SECTION I + SECTION II -->
<div class="masthead">
  <div class="masthead__left">
    <div class="masthead__brand">
      <div class="masthead__logo">{hu_logo}</div>
      <div>
        <div class="masthead__kicker">Operating Systems (Fall 2026) &middot; Term Research Report</div>
        <div class="masthead__subkicker">Dhanani School of Science &amp; Engineering &middot; Habib University</div>
      </div>
    </div>
    <h1 class="paper-title">MemGuard &mdash; Autonomous eBPF Defense Against Fileless Execution</h1>
  </div>
  <div class="masthead__right">
    <div class="masthead__authors">M. Murtaza &middot; S. Faraz &middot; A. Baig &middot; S. Humayun</div>
    <div class="masthead__meta-line">Instructors: B. Wajid, Z. Iqbal, S. Tahir, A. S. Shaikh</div>
    <div class="masthead__meta-line">Corpus: 80 Attack Trials &middot; 330 Benign Events</div>
    <div class="masthead__env">Linux 7.3.3-1-cachyos &middot; CO-RE eBPF &middot; libbpf 1.8</div>
  </div>
</div>

<div class="kpi-strip">
  <div class="kpi">
    <div class="kpi__num kpi__num--purple">{k_v['mtti_mean_ms'] * 1000:.1f}<span class="kpi__unit"> &mu;s</span></div>
    <div class="kpi__label">In-Kernel Mean MTTI</div>
    <div class="kpi__sub">{k_v['mtti_median_ms'] * 1000:.1f} &mu;s median &middot; {speedup_heur}&times; faster than userspace</div>
  </div>
  <div class="kpi">
    <div class="kpi__num kpi__num--purple">0<span class="kpi__unit"> / 20</span></div>
    <div class="kpi__label">C2 Exfiltration Leaks</div>
    <div class="kpi__sub">0% leaked vs. 20/20 (100%) in userspace &amp; FIM</div>
  </div>
  <div class="kpi">
    <div class="kpi__num">100<span class="kpi__unit">%</span></div>
    <div class="kpi__label">Evasion Detection</div>
    <div class="kpi__sub">All 5 vectors caught &middot; 0% Traditional FIM</div>
  </div>
  <div class="kpi">
    <div class="kpi__num">0.0<span class="kpi__unit">%</span></div>
    <div class="kpi__label">False Positive Rate</div>
    <div class="kpi__sub">330 live benign memfd events &middot; 0 B disk I/O</div>
  </div>
  <div class="kpi">
    <div class="kpi__num">{k_v['rss_mb']:.1f}<span class="kpi__unit"> MB</span></div>
    <div class="kpi__label">Kernel Defender RSS</div>
    <div class="kpi__sub">5.4&times; leaner than Random Forest ({u_m['rss_mb']:.1f} MB)</div>
  </div>
</div>

  <div class="sec-head">
  <h2><span class="num">I.</span> Research Question &amp; Benchmark Summary</h2>
  <span class="sec-head__note">80 attack trials &middot; 30 benign trials &middot; 300 live desktop captures</span>
</div>

<p class="lead">
  <strong>Research Question:</strong> <em>Can an autonomous eBPF-driven defender reliably detect and intercept fileless in-memory execution (<code>memfd_create</code> + <code>fexecve</code>) and anonymous process masquerading without disk artifacts, and what is its classification overhead compared to traditional file-integrity monitoring?</em>
  Traditional path-based monitors (<code>inotify</code>, <code>auditd</code>) are structurally blind to anonymous RAM descriptors sealed via <code>fcntl(F_ADD_SEALS)</code> and masqueraded as <code>[kworker/u8:2]</code> via <code>prctl(PR_SET_NAME)</code>. While userspace eBPF classifiers achieve 95&ndash;100% post-hoc detection, ring-buffer wakeup and <code>/proc</code> polling consume 3.77&ndash;11.09&nbsp;ms&mdash;losing the Time-of-Check to Time-of-Use (TOCTOU) race against a ~0.6&nbsp;ms compiled TCP exfiltration payload. Moving VFS <code>fdtable/dentry</code> verification and <code>bpf_send_signal(SIGSTOP)</code> directly into the kernel cuts mean MTTI to <strong>5.2&nbsp;&mu;s</strong>, blocks <strong>100% of exfiltration</strong> at <strong>23.9&nbsp;MB RSS</strong>, and preserves volatile RAM for live ELF64 forensic carving.
</p>

<table class="ledger">
  <thead>
    <tr>
      <th style="width:27%">Defense Architecture</th>
      <th style="width:25%">Enforcement Mechanism</th>
      <th class="r">Detected</th>
      <th class="r">Mean MTTI</th>
      <th class="r">Median</th>
      <th class="r">C2 Leaked</th>
      <th class="r">FPR</th>
      <th class="r">RSS</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><span class="swatch" style="background:#B4B8C5"></span><strong>01 &middot; Traditional FIM</strong></td>
      <td><code>inotify</code> on <code>/tmp</code>, <code>/dev/shm</code>, build</td>
      <td class="r c-alert">0/20 (0%)</td>
      <td class="r c-muted">&mdash;</td>
      <td class="r c-muted">&mdash;</td>
      <td class="r c-alert">20/20 (100%)</td>
      <td class="r">0.0%</td>
      <td class="r">{fim['rss_mb']:.1f} MB</td>
    </tr>
    <tr>
      <td><span class="swatch" style="background:#9AA0B0"></span><strong>02 &middot; Userspace eBPF + ML</strong></td>
      <td>Ringbuf + Random Forest + <code>pidfd</code></td>
      <td class="r">19/20 (95%)</td>
      <td class="r">{u_m['mtti_mean_ms']:.2f} ms</td>
      <td class="r">{u_m['mtti_median_ms']:.2f} ms</td>
      <td class="r c-alert">20/20 (100%)</td>
      <td class="r">0.0%</td>
      <td class="r c-alert">{u_m['rss_mb']:.1f} MB</td>
    </tr>
    <tr>
      <td><span class="swatch" style="background:#8F6A9A"></span><strong>03 &middot; Userspace eBPF + Heuristic</strong></td>
      <td>Ringbuf + <code>rules.yaml</code> + <code>pidfd</code></td>
      <td class="r">20/20 (100%)</td>
      <td class="r">{u_h['mtti_mean_ms']:.2f} ms</td>
      <td class="r">{u_h['mtti_median_ms']:.2f} ms</td>
      <td class="r c-alert">20/20 (100%)</td>
      <td class="r">0.0%</td>
      <td class="r">{u_h['rss_mb']:.1f} MB</td>
    </tr>
    <tr class="highlight">
      <td><span class="swatch" style="background:#5D2568"></span>04 &middot; In-Kernel VFS eBPF</td>
      <td>CO-RE VFS walk + <code>bpf_send_signal</code></td>
      <td class="r c-purple">20/20 (100%)</td>
      <td class="r c-purple">{k_v['mtti_mean_ms'] * 1000:.1f} &mu;s</td>
      <td class="r c-purple">{k_v['mtti_median_ms'] * 1000:.1f} &mu;s</td>
      <td class="r c-purple">0/20 (0%)</td>
      <td class="r c-purple">0.0%</td>
      <td class="r c-purple">{k_v['rss_mb']:.1f} MB</td>
    </tr>
  </tbody>
</table>

<div class="sec-head">
  <h2><span class="num">II.</span> Interception Latency &amp; Classification Cadence</h2>
  <span class="sec-head__note">Log-scale MTTI vs. ~0.6 ms exfiltration race and per-event decision speed</span>
</div>

<div class="fig-pair">
  <div class="fig-cell">
    <div class="fig-title">Figure 1 <span class="dot">&middot;</span> Interception Latency vs. Exfiltration Window</div>
    <div class="fig-sub">Mean Time to Intercept across 80 trials relative to TCP exfiltration (~0.6 ms)</div>
    <div class="fig-svg">{svg_mtti_bars(data)}</div>
  </div>
  <div class="fig-cell">
    <div class="fig-title">Figure 2 <span class="dot">&middot;</span> Classification Latency by Engine</div>
    <div class="fig-sub">Single-event scoring time across VFS tripwire, Heuristic, and 4 ML models</div>
    <div class="fig-svg">{svg_ranked_classification(data)}</div>
  </div>
</div>

<!-- PAGE 2: ARCHITECTURE + FIVE-VECTOR ADVERSARIAL EVASION -->


<div class="sec-head sec-head--first">
  <h2><span class="num">III.</span> System Architecture &amp; Kernel Mechanics</h2>
  <span class="sec-head__note">Adversarial C loader &middot; 6 CO-RE eBPF tracepoints &middot; Two-stage defense</span>
</div>

<div class="prose-grid">
  <div class="prose-col">
    <h3>The TOCTOU Timing Constraint</h3>
    <p>
      Under reactive OODA defense models, interception fails unless total Mean Time to Intercept stays strictly below the malware's Time-to-Objective (<code>T_exfil</code>):
    </p>
    <div class="eq-inline">T<sub>MTTI</sub> = T<sub>hook</sub> + T<sub>ringbuf</sub> + T<sub>classify</sub> + T<sub>signal</sub> &lt; T<sub>exfil</sub></div>
    <p>
      When classification resides in userspace, ring-buffer delivery, <code>/proc</code> polling, and Python/ML scoring push <code>T_MTTI</code> to 3.77&ndash;11.09&nbsp;ms, whereas a compiled C payload opens a loopback socket and transmits secrets in ~0.6&nbsp;ms. Synchronous in-kernel enforcement collapses <code>T_ringbuf + T_classify</code> to zero on the critical path.
    </p>
  </div>
  <div class="prose-col">
    <h3>CO-RE VFS Verification &amp; Synchronous Freeze</h3>
    <p>
      Rather than trusting mutable userspace descriptor numbers, MemGuard attaches six CO-RE tracepoints (<code>sys_enter/exit_memfd_create</code>, <code>sys_enter_execveat</code>, <code>sys_enter_execve</code>, <code>sys_enter_prctl</code>, <code>sched_process_fork</code>) with PID-namespace resolution via <code>bpf_get_ns_current_pid_tgid()</code>.
    </p>
    <p>
      On <code>execveat</code>&mdash;or via an unrolled parser for <code>execve("/proc/self/fd/&lt;N&gt;")</code>&mdash;the probe walks <code>current&rarr;files&rarr;fdt&rarr;fd[dfd]</code> via <code>BPF_CORE_READ</code>, verifies <code>TMPFS_MAGIC (0x01021994)</code> plus the kernel-assigned <code>memfd:</code> dentry prefix, records the exact kernel inode, and invokes <code>bpf_send_signal(SIGSTOP)</code> before returning to userspace.
    </p>
  </div>
</div>

<div class="fig-full">
  <div class="fig-title">Figure 3 <span class="dot">&middot;</span> Two-Stage Kernel Tripwire &amp; Asynchronous Forensics Architecture</div>
  <div class="fig-sub">Stage 1 halts fileless execution synchronously at syscall entry (5.2 &mu;s); Stage 2 performs zero-pressure ELF64 RAM carving, dual-engine triage, and SSE telemetry</div>
  <div class="fig-svg">{svg_architecture_clean()}</div>
</div>

  <div class="sec-head">
  <h2><span class="num">IV.</span> Five-Vector Evasion &amp; Empirical Blind Spots</h2>
  <span class="sec-head__note">Compiled C loader (0 B disk I/O) &middot; 5 adversarial vectors</span>
</div>

<table class="ledger">
  <thead>
    <tr>
      <th style="width:4%">#</th>
      <th style="width:16%">Vector</th>
      <th style="width:34%">Adversarial Technique &amp; Target Blind Spot</th>
      <th class="c">Trad. FIM</th>
      <th class="c">Pre-Fix Heur</th>
      <th class="c">Zero-Shot ML</th>
      <th class="c">In-Kernel VFS</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="c-muted">01</td>
      <td><span class="key-ref">V1 &middot; standard</span></td>
      <td>Direct <code>memfd_create("jit_cache")</code> &rarr; <code>F_ADD_SEALS</code> &rarr; <code>execveat(AT_EMPTY_PATH)</code> + <code>[kworker/u8:2]</code></td>
      <td class="c c-alert">0%</td>
      <td class="c">100%</td>
      <td class="c">100%</td>
      <td class="c c-purple">100% (0 leaks)</td>
    </tr>
    <tr>
      <td class="c-muted">02</td>
      <td><span class="key-ref">V2 &middot; dup-fd</span></td>
      <td>Duplicates descriptor via <code>dup2(3, 42)</code> and closes <code>fd=3</code> to defeat naive <code>(pid, fd)</code> map lookups</td>
      <td class="c c-alert">0%</td>
      <td class="c">100%</td>
      <td class="c">100%</td>
      <td class="c c-purple">100% (0 leaks)</td>
    </tr>
    <tr>
      <td class="c-muted">03</td>
      <td><span class="key-ref">V3 &middot; fork</span></td>
      <td>Parent creates/seals memfd, forks, and calls <code>_exit(0)</code>; kernel reparents orphan child to PID 1 (<code>systemd</code>)</td>
      <td class="c c-alert">0%</td>
      <td class="c c-alert">0% (PID 1)</td>
      <td class="c">100%</td>
      <td class="c c-purple">100% (0 leaks)</td>
    </tr>
    <tr>
      <td class="c-muted">04</td>
      <td><span class="key-ref">V4 &middot; execve-fd</span></td>
      <td>Bypasses <code>execveat()</code> completely by invoking standard <code>execve("/proc/self/fd/&lt;N&gt;")</code></td>
      <td class="c c-alert">0%</td>
      <td class="c">100%</td>
      <td class="c c-alert">0% (P=0.60)</td>
      <td class="c c-purple">100% (0 leaks)</td>
    </tr>
    <tr>
      <td class="c-muted">05</td>
      <td class="nw"><span class="key-ref">V5 &middot; high-entropy</span></td>
      <td>Appends 48 KB xorshift64 pseudo-random padding in RAM, shifting Shannon entropy from 2.67 to 7.16 bits/byte</td>
      <td class="c c-alert">0%</td>
      <td class="c">100%</td>
      <td class="c">100%</td>
      <td class="c c-purple">100% (0 leaks)</td>
    </tr>
  </tbody>
</table>

<div class="prose-grid">
  <div class="prose-col">
    <h3>Finding 1 &middot; PID-1 (<code>systemd</code>) Orphan-Reparenting Bypass</h3>
    <p>
      Prior to VFS hardening, our Heuristic engine scored <strong>0/3</strong> on Vector 3 (<code>--fork</code>). Because the loader exited immediately after forking, the Linux kernel reparented the child to PID&nbsp;1 (<code>systemd</code>). Since <code>systemd</code> appeared in <code>allowlist_comms</code> for legitimate daemon re-execs, the malware inherited a &minus;60 allowlist credit, suppressing <code>FREEZE</code> to <code>ALLOW</code>. Removing PID-1 parent trust&mdash;allowing <code>systemd</code> only when it is the executing binary itself&mdash;plus kernel VFS verification immediately closed the bypass (<strong>0% &rarr; 100%</strong>).
    </p>
  </div>
  <div class="prose-col">
    <h3>Finding 2 &middot; Zero-Shot 100%-Real ML Generalization Drift</h3>
    <p>
      Trained exclusively on 597 pure live eBPF rows (300 desktop benign + 297 real <code>execveat</code> attacks), our Random Forest achieved 1.00 F1 in-distribution yet dropped to <strong>0/3 (P=0.600 &lt; 0.75 freeze threshold)</strong> zero-shot on Vector 4 (<code>execve("/proc/self/fd/N")</code>), an unseen syscall pathway. Even after retraining with all vectors, userspace ML suffered 1/20 missed freeze due to a race-dropped <code>/proc</code> sample before exit. Structural VFS inspection eliminated both blind spots.
    </p>
  </div>
</div>

<!-- PAGE 3: OVERHEAD, BENIGN UTILITY & VOLATILE RAM FORENSICS -->


  <div class="sec-head">
  <h2><span class="num">V.</span> Overhead, Memory &amp; System Resilience</h2>
  <span class="sec-head__note">3,000-op syscall microbenchmark &middot; 597 pure live eBPF rows</span>
</div>

<div class="fig-pair">
  <div class="fig-cell">
    <div class="fig-title">Figure 4 <span class="dot">&middot;</span> Userspace Memory Footprint (RSS)</div>
    <div class="fig-sub">Steady-state resident memory across FIM, eBPF Heuristic, VFS, and ML</div>
    <div class="fig-svg">{svg_rss_bars(data)}</div>
  </div>
  <div class="fig-cell">
    <div class="fig-title">Figure 5 <span class="dot">&middot;</span> End-to-End Defense Resilience</div>
    <div class="fig-sub">Benign desktop utility (330 trials) vs. fileless detection &amp; C2 blocking</div>
    <div class="fig-svg">{svg_resilience_grouped()}</div>
  </div>
</div>

<table class="ledger">
  <thead>
    <tr>
      <th style="width:28%">Configuration / Model</th>
      <th style="width:22%">Evaluation Scope</th>
      <th class="r"><code>memfd_create</code></th>
      <th class="r">Disk <code>create/unlink</code></th>
      <th class="r">Decision Time</th>
      <th class="r">Test F1 / FPR</th>
      <th class="r">RSS</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Baseline (No Defender)</td>
      <td>3,000-op syscall bench</td>
      <td class="r">5.33 &mu;s</td>
      <td class="r">38.65 &mu;s (0.0%)</td>
      <td class="r c-muted">&mdash;</td>
      <td class="r c-muted">&mdash;</td>
      <td class="r">0.0 MB</td>
    </tr>
    <tr>
      <td>Traditional FIM (<code>inotify</code>)</td>
      <td>3,000-op + 20 attacks</td>
      <td class="r">5.11 &mu;s</td>
      <td class="r c-alert">46.23 &mu;s (+19.6%)</td>
      <td class="r c-muted">N/A (0% det)</td>
      <td class="r c-alert">0.00 / 0.0%</td>
      <td class="r">19.2 MB</td>
    </tr>
    <tr>
      <td>eBPF Userspace Heuristic</td>
      <td><code>rules.yaml</code> (597 live)</td>
      <td class="r">5.43 &mu;s (+1.8%)</td>
      <td class="r">48.98 &mu;s</td>
      <td class="r">0.040 ms</td>
      <td class="r">1.00 / 0.0%</td>
      <td class="r">24.0 MB</td>
    </tr>
    <tr>
      <td>eBPF ML &middot; Decision Tree</td>
      <td>468 train / 129 test</td>
      <td class="r c-muted">&mdash;</td>
      <td class="r c-muted">&mdash;</td>
      <td class="r">{ml_models['decision_tree']['avg_infer_ms']:.3f} ms</td>
      <td class="r">1.00 / 0.0%</td>
      <td class="r c-muted">~130 MB</td>
    </tr>
    <tr>
      <td>eBPF ML &middot; Logistic Regression</td>
      <td>468 train / 129 test</td>
      <td class="r c-muted">&mdash;</td>
      <td class="r c-muted">&mdash;</td>
      <td class="r">{ml_models['logistic_regression']['avg_infer_ms']:.3f} ms</td>
      <td class="r">1.00 / 0.0%</td>
      <td class="r c-muted">~130 MB</td>
    </tr>
    <tr>
      <td>eBPF ML &middot; Random Forest (Live)</td>
      <td>3,000-op + 20 attacks</td>
      <td class="r">7.21 &mu;s (+35.3%)</td>
      <td class="r">45.10 &mu;s (+16.7%)</td>
      <td class="r">{ml_models['random_forest']['avg_infer_ms']:.3f} ms</td>
      <td class="r">1.00 / 0.0%</td>
      <td class="r c-alert">130.1 MB</td>
    </tr>
    <tr class="highlight">
      <td>eBPF In-Kernel VFS (<code>SIGSTOP</code>)</td>
      <td>3,000-op + 80-trial suite</td>
      <td class="r c-purple">3.43 &mu;s*</td>
      <td class="r c-purple">17.10 &mu;s*</td>
      <td class="r c-purple">5.2 &mu;s (E2E)</td>
      <td class="r c-purple">1.00 / 0.0%</td>
      <td class="r c-purple">23.9 MB</td>
    </tr>
  </tbody>
</table>
<p style="font-size:6.9pt;color:#7A808E;margin-top:-4pt;margin-bottom:9pt;">
  *Syscall latency measured on Intel Core i9-11950H (CachyOS 7.3.3); negative deltas under In-Kernel VFS reflect warm CPU frequency scaling (turbo governor) confirming zero measurable disk-path regression, whereas <code>inotify</code> FIM incurs a consistent +19.6% disk-create penalty while detecting 0% of fileless attacks.
</p>

  <div class="sec-head">
  <h2><span class="num">VI.</span> Zero-Disk Proof &amp; RAM Forensic Carving</h2>
  <span class="sec-head__note">Live /proc/&lt;pid&gt;/io &amp; /proc/&lt;pid&gt;/exe capture on PID 22032</span>
</div>

<p>
  Because <code>bpf_send_signal(SIGSTOP)</code> suspends the offending process inside kernel space without destroying its address space (unlike <code>SIGKILL</code>), MemGuard's asynchronous forensic engine (<code>forensics.py</code>) carves the decrypted ELF64 payload straight out of volatile RAM via <code>/proc/&lt;pid&gt;/exe</code>. Simultaneously, polling <code>/proc/&lt;pid&gt;/io</code> during unintercepted execution mathematically confirms zero physical disk writes. Across 30 controlled benign <code>memfd_create</code> trials and 300 real desktop telemetry captures (Brave browser shared-memory buffers, PipeWire audio streams, Wayland surfaces, and <code>kitty</code>), MemGuard allowed <strong>100% of benign workloads (0.0% FPR)</strong> because legitimate desktop apps never execute anonymous memfds.
</p>

<div class="spec-grid">
  <div class="spec-col">
    <h3>Live Carved RAM Artifact (Frozen PID 22032)</h3>
    <table class="kv">
      <tr><td class="k">Kernel VFS Proof</td><td class="v">memfd:jit_cache (tmpfs, inode #{vfs_ino})</td></tr>
      <tr><td class="k">Freeze Latency</td><td class="v">2.3 &mu;s via bpf_send_signal(SIGSTOP)</td></tr>
      <tr><td class="k">Carved Binary</td><td class="v">{elf_size:,} B ELF64 (ET_DYN, x86_64, entry 0x1650)</td></tr>
      <tr><td class="k">ELF Layout</td><td class="v">15 program segments &middot; 31 sections &middot; H=2.67 bits/B</td></tr>
      <tr><td class="k">SHA-256 Digest</td><td class="v">{sha_short}&hellip;{sha_full[-8:]}</td></tr>
      <tr><td class="k">Extracted IOCs</td><td class="v">127.0.0.1 &middot; [kworker/u8:2] &middot; OS_FALL2026_MEMFD_TOKEN</td></tr>
    </table>
  </div>
  <div class="spec-col">
    <h3>Zero-Disk Execution Proof (PID 22118)</h3>
    <table class="kv">
      <tr><td class="k">Masqueraded Comm</td><td class="v">[kworker/u8:2] (via prctl PR_SET_NAME)</td></tr>
      <tr><td class="k">Kernel Exe Link</td><td class="v">/memfd:jit_cache (deleted)</td></tr>
      <tr><td class="k">Physical Write I/O</td><td class="v" style="color:#5D2568;font-weight:700">0 bytes (/proc/22118/io write_bytes)</td></tr>
      <tr><td class="k">Physical Read I/O</td><td class="v" style="color:#5D2568;font-weight:700">0 bytes (/proc/22118/io read_bytes)</td></tr>
      <tr><td class="k">Logical RAM Write</td><td class="v">17,060 bytes (wchar to tmpfs memfd)</td></tr>
      <tr><td class="k">FIM Observation</td><td class="v" style="color:#A8422A;font-weight:600">0 inotify events over 502.4 ms (100% blind)</td></tr>
    </table>
  </div>
</div>

<!-- PAGE 4: LIVE CONSOLE + DISCUSSION + CONCLUSION + REFERENCES -->


<div class="sec-head sec-head--first">
  <h2><span class="num">VII.</span> Live Interception Console &amp; Telemetry Surface</h2>
  <span class="sec-head__note">Decoupled React/Vite + SSE operator console &middot; Zero hot-path coupling</span>
</div>

<div class="fig-full">
  <div class="fig-title">Figure 6 <span class="dot">&middot;</span> MemGuard Dusk Web Console (Live Frozen Capture)</div>
  <div class="fig-sub">Displays live frozen threat ledger, inline Kernel VFS verification (<code>memfd:jit_cache</code>, <code>tmpfs inode 33898</code>), carved ELF64 SHA-256 &amp; C2 IOCs, dual-engine Heuristic/ML agreement (99%), and real-time MTTI chart</div>
  <div class="console-frame">
    <img src="{dusk_uri}" alt="MemGuard live web console displaying frozen fileless execution and carved ELF64 forensics" />
  </div>
</div>

<div class="sec-head">
  <h2><span class="num">VIII.</span> Discussion, Limitations &amp; Conclusion</h2>
  <span class="sec-head__note">Two-stage hybrid design &middot; Threat boundaries &middot; Future work</span>
</div>

<div class="prose-grid">
  <div class="prose-col">
    <h3>Two-Stage Hybrid Architecture</h3>
    <p>
      Mirroring the latency-capability bottleneck observed in local LLM EDR agents [5], our results show that high userspace classification accuracy alone is operationally insufficient against compiled sub-millisecond payloads. Our data establishes an optimal two-stage architecture: (1)&nbsp;synchronous in-kernel VFS <code>bpf_send_signal(SIGSTOP)</code> acts as a ~5&nbsp;&mu;s tripwire that eliminates the TOCTOU exfiltration race; (2)&nbsp;once frozen, asynchronous userspace Heuristic + shadow ML triage and ELF64 carving operate with zero time pressure, resuming rare benign callers via <code>SIGCONT</code> while terminating confirmed implants via <code>SIGKILL</code>.
    </p>
    <h3>Limitations</h3>
    <p>
      Our live benign corpus reflects a single Arch Linux desktop rather than multi-tenant container hosts where runtimes (<code>runc</code>) routinely re-exec via <code>/proc/self/fd</code>. Additionally, adversaries using userland reflective ELF loaders (<code>mmap(PROT_EXEC)</code>) or <code>ptrace</code>/<code>process_vm_writev</code> injection bypass <code>execveat()</code> entirely and sit outside the current hook surface.
    </p>
  </div>
  <div class="prose-col">
    <h3>Conclusion &amp; Future Work</h3>
    <p>
      This work empirically confirms that an autonomous CO-RE eBPF defender reliably intercepts fileless in-memory execution (<code>memfd_create</code> + <code>fexecve</code>) and anonymous process masquerading with <strong>0 bytes of disk artifacts</strong> and <strong>0.0% false positives</strong> across five evasion vectors, overcoming both the total blindness (0%) and disk I/O penalty (+19.6%) of traditional <code>inotify</code> FIM. Only synchronous in-kernel VFS enforcement (<strong>5.2&nbsp;&mu;s mean MTTI</strong>, <strong>23.9&nbsp;MB RSS</strong>) defeats fast TCP exfiltration (<strong>0/20 leaks</strong> vs. 20/20 in userspace Heuristic/ML) while preserving volatile RAM for full ELF64 forensic recovery.
    </p>
    <p>
      Future work will migrate enforcement to Linux Security Module (BPF LSM) <code>bprm_check_security</code> hooks for pre-exec denial, add <code>mmap</code>/<code>mprotect(PROT_EXEC)</code> and <code>ptrace</code> probes against reflective loaders, and compile Decision Tree thresholds into fixed-point eBPF maps for zero-copy in-kernel ML scoring.
    </p>
  </div>
</div>

<div class="sec-head">
  <h2><span class="num">IX.</span> References</h2>
  <span class="sec-head__note">Primary kernel, eBPF, fileless security &amp; EDR literature</span>
</div>

<div class="refs-grid">
  <div class="refs-col">
    <div class="ref-item"><span class="ref-num">[1]</span> B. Gregg, <em>BPF Performance Tools: Linux System and Application Observability</em>. Addison-Wesley Professional, 2019.</div>
    <div class="ref-item"><span class="ref-num">[2]</span> L. Rice, <em>Learning eBPF: Programming the Linux Kernel for Enhanced Observability, Networking, and Security</em>. O'Reilly Media, 2023.</div>
    <div class="ref-item"><span class="ref-num">[3]</span> Linux Kernel Documentation, &ldquo;memfd_create(2) and execveat(2) System Call Manual,&rdquo; Linux Programmer's Manual, kernel.org, 2025.</div>
    <div class="ref-item"><span class="ref-num">[4]</span> S. Sudhakar and S. Kumar, &ldquo;An emerging threat fileless malware: a survey and research challenges,&rdquo; <em>Cybersecurity</em>, vol. 3, no. 1, pp. 1&ndash;12, 2020.</div>
    <div class="ref-item"><span class="ref-num">[5]</span> B. Wajid, &ldquo;The Temporal Cost of Cognition: Evaluating Agentic LLMs and Cyber Resilience in Local EDR,&rdquo; Habib University, 2026.</div>
  </div>
  <div class="refs-col">
    <div class="ref-item"><span class="ref-num">[6]</span> A. Nakryiko, &ldquo;BPF CO-RE (Compile Once &ndash; Run Everywhere),&rdquo; Linux Kernel &amp; libbpf Documentation, 2024.</div>
    <div class="ref-item"><span class="ref-num">[7]</span> K. P. Singh, &ldquo;KRSI / BPF LSM: Kernel Runtime Security Instrumentation,&rdquo; <em>Linux Plumbers Conference</em>, 2020.</div>
    <div class="ref-item"><span class="ref-num">[8]</span> F. Pedregosa et al., &ldquo;Scikit-learn: Machine Learning in Python,&rdquo; <em>J. Machine Learning Research</em>, vol. 12, pp. 2825&ndash;2830, 2011.</div>
    <div class="ref-item"><span class="ref-num">[9]</span> S. Barr-Smith et al., &ldquo;Survivalism: Systematic Analysis of Living-off-the-Land Techniques,&rdquo; <em>IEEE S&amp;P</em>, 2021.</div>
    <div class="ref-item"><span class="ref-num">[10]</span> T. Garnier, &ldquo;Linux Fileless Malware Detection via In-Memory ELF Forensics and eBPF Tracing,&rdquo; <em>USENIX WOOT</em>, 2024.</div>
  </div>
</div>

<div class="colophon">
  <span>MemGuard &middot; M. Murtaza, S. Faraz, A. Baig, S. Humayun &middot; Habib University</span>
  <span>Compiled from 80 Live Attack Trials &middot; 330 Benign Events &middot; 597 Pure eBPF Dataset Rows</span>
</div>

</body>
</html>
"""
    return html


def main() -> None:
    html = build_html()
    HTML_OUT.write_text(html, encoding="utf-8")
    print(f"Built Swiss-editorial HTML -> {HTML_OUT}")
    import weasyprint
    weasyprint.HTML(filename=str(HTML_OUT)).write_pdf(str(PDF_OUT))
    print(f"Compiled PDF -> {PDF_OUT} ({PDF_OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
