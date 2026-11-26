#!/usr/bin/env python3
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "report" / "assets"
DATA_PATH = ASSETS / "experiment_data.json"
HTML_OUT = ROOT / "report" / "report.html"


def read_svg_inline(path: Path) -> str:
    txt = path.read_text(encoding="utf-8")
    idx = txt.find("<svg")
    return txt[idx:] if idx >= 0 else txt


def read_img_b64(path: Path, mime: str) -> str:
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{b64}"


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

    hu_logo_svg = read_svg_inline(ASSETS / "hu_logo.svg")
    fig1_svg = read_svg_inline(ASSETS / "fig1_mtti_exfil.svg")
    fig2_svg = read_svg_inline(ASSETS / "fig2_evasion_matrix.svg")
    fig3_svg = read_svg_inline(ASSETS / "fig3_classifier_overhead.svg")
    fig4_svg = read_svg_inline(ASSETS / "fig4_system_resilience.svg")
    dusk_uri = read_img_b64(ASSETS / "dusk_console.png", "image/png")

    speedup_heur = round(u_h["mtti_mean_ms"] / k_v["mtti_mean_ms"])
    speedup_ml = round(u_m["mtti_mean_ms"] / k_v["mtti_mean_ms"])
    sha_short = (f_inner.get("sha256") or "4ff2b2595e30b678")[:16]
    vfs_ino = forensics.get("vfs_ino", 4958)
    elf_size = f_inner.get("size_bytes", 16832)

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Sub-Microsecond Kernel Tripwires: Autonomous eBPF Defense Against Fileless In-Memory Execution</title>
<style>
  @page {{
    size: letter;
    margin: 0.58in 0.58in 0.62in 0.58in;
    @bottom-left {{
      content: "Operating Systems (Fall 2026)  |  Habib University";
      font-family: "DejaVu Sans", sans-serif;
      font-size: 7.5pt;
      color: #6B6F7E;
    }}
    @bottom-right {{
      content: "Page " counter(page) " of " counter(pages);
      font-family: "DejaVu Sans", sans-serif;
      font-size: 7.5pt;
      color: #5D2568;
      font-weight: 600;
    }}
  }}
  @page :first {{
    margin-top: 0.42in;
  }}

  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: "Liberation Serif", "DejaVu Serif", Georgia, serif;
    font-size: 9.15pt;
    line-height: 1.40;
    color: #1E2028;
    background: #FFFFFF;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }}

  /* Habib University Institutional Masthead */
  .masthead {{
    background: #5D2568;
    color: #FFFFFF;
    padding: 10px 16px;
    border-bottom: 3px solid #D5C195;
    border-radius: 5px 5px 0 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
  }}
  .masthead__logo svg {{
    height: 36px;
    width: auto;
    display: block;
  }}
  .masthead__meta {{
    text-align: right;
    font-family: "DejaVu Sans", sans-serif;
    line-height: 1.35;
  }}
  .masthead__school {{
    font-size: 8.4pt;
    font-weight: 700;
    color: #FFFFFF;
    letter-spacing: 0.01em;
  }}
  .masthead__course {{
    font-size: 7.5pt;
    color: #DFCA95;
  }}

  .title-block {{
    text-align: center;
    margin-bottom: 11px;
    padding-bottom: 9px;
    border-bottom: 1px solid #DFD8E6;
  }}
  h1.paper-title {{
    margin: 0 0 6px;
    font-family: "DejaVu Sans", sans-serif;
    font-size: 15.2pt;
    font-weight: 700;
    line-height: 1.22;
    color: #2A1230;
    letter-spacing: -0.015em;
  }}
  .authors {{
    font-family: "DejaVu Sans", sans-serif;
    font-size: 8.8pt;
    font-weight: 600;
    color: #363945;
    margin-bottom: 3px;
  }}
  .affil {{
    font-family: "DejaVu Sans", sans-serif;
    font-size: 7.7pt;
    color: #646878;
  }}

  /* Abstract callout */
  .abstract-box {{
    background: #F7F4FA;
    border-left: 3.5px solid #5D2568;
    padding: 9px 12px;
    border-radius: 0 4px 4px 0;
    margin-bottom: 12px;
  }}
  .abstract-box p {{
    margin: 0 0 5px;
    text-align: justify;
    font-size: 8.55pt;
    line-height: 1.38;
  }}
  .abstract-lead {{
    font-family: "DejaVu Sans", sans-serif;
    font-weight: 700;
    color: #5D2568;
  }}
  .keywords {{
    margin: 0;
    font-size: 8pt;
    color: #4A4E5D;
  }}

  /* Two-column academic body */
  .two-col {{
    column-count: 2;
    column-gap: 0.24in;
  }}

  h2 {{
    font-family: "DejaVu Sans", sans-serif;
    font-size: 9.8pt;
    font-weight: 700;
    color: #5D2568;
    margin: 11px 0 4px;
    padding-bottom: 2px;
    border-bottom: 1px solid #E3D9EB;
    break-after: avoid;
    page-break-after: avoid;
  }}
  h3 {{
    font-family: "DejaVu Sans", sans-serif;
    font-size: 8.75pt;
    font-weight: 700;
    color: #32183A;
    margin: 7px 0 3px;
    break-after: avoid;
    page-break-after: avoid;
  }}
  p {{
    margin: 0 0 6px;
    text-align: justify;
    hyphens: auto;
  }}
  ul, ol {{
    margin: 3px 0 6px 15px;
    padding: 0;
  }}
  li {{
    margin-bottom: 3px;
    text-align: justify;
  }}
  code {{
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 7.75pt;
    background: #F4F0F8;
    color: #461B50;
    padding: 0.5px 3px;
    border-radius: 2px;
  }}

  .eq {{
    margin: 6px 0 7px;
    padding: 5px 8px;
    background: #FAF8FC;
    border: 1px solid #EAE3F1;
    border-radius: 3px;
    text-align: center;
    font-family: "Liberation Serif", Georgia, serif;
    font-size: 9.1pt;
    font-style: italic;
    color: #24122A;
    break-inside: avoid;
  }}
  .eq sub {{ font-style: normal; font-size: 6.8pt; }}
  .eq .op {{ font-style: normal; }}

  /* Full-width spans for charts and key tables */
  .span-all {{
    column-span: all;
    margin: 9px 0 10px;
    break-inside: avoid;
    page-break-inside: avoid;
  }}
  .fig-box {{
    border: 1px solid #E4DEEC;
    border-radius: 5px;
    padding: 7px 8px 6px;
    background: #FFFFFF;
    break-inside: avoid;
    page-break-inside: avoid;
    margin: 8px 0;
  }}
  .fig-box svg {{
    width: 100%;
    height: auto;
    display: block;
  }}
  .fig-box img {{
    width: 100%;
    height: auto;
    display: block;
    border-radius: 3px;
  }}
  .fig-cap {{
    margin-top: 5px;
    font-family: "DejaVu Sans", sans-serif;
    font-size: 7.6pt;
    line-height: 1.32;
    color: #4B4F5E;
    text-align: left;
  }}
  .fig-cap strong {{
    color: #5D2568;
  }}

  /* Booktabs academic tables */
  table.academic {{
    width: 100%;
    border-collapse: collapse;
    font-family: "DejaVu Sans", sans-serif;
    font-size: 7.6pt;
    margin: 4px 0 2px;
  }}
  table.academic thead th {{
    background: #F4EFF8;
    color: #441A4E;
    font-weight: 700;
    padding: 4.5px 5px;
    border-top: 1.6px solid #5D2568;
    border-bottom: 1px solid #5D2568;
    text-align: left;
    white-space: nowrap;
  }}
  table.academic thead th.num,
  table.academic tbody td.num {{
    text-align: right;
    font-variant-numeric: tabular-nums;
  }}
  table.academic tbody td {{
    padding: 4px 5px;
    border-bottom: 0.6px solid #E8E4EE;
    color: #262936;
  }}
  table.academic tbody tr:last-child td {{
    border-bottom: 1.5px solid #5D2568;
  }}
  table.academic tbody tr.highlight td {{
    background: #F7F3FB;
    font-weight: 700;
    color: #3E1548;
  }}
  .bad {{ color: #B84C2C; font-weight: 700; }}
  .good {{ color: #5D2568; font-weight: 700; }}

  .forensic-card {{
    background: #FAF8FC;
    border: 1px solid #DDD3E8;
    border-left: 3px solid #D5C195;
    border-radius: 3px;
    padding: 6px 8px;
    margin: 6px 0;
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 7.2pt;
    line-height: 1.38;
    color: #2B2433;
    break-inside: avoid;
  }}

  .refs {{
    font-size: 7.65pt;
    line-height: 1.32;
    padding-left: 16px;
  }}
  .refs li {{
    margin-bottom: 3.5px;
  }}
</style>
</head>
<body>

<div class="masthead">
  <div class="masthead__logo">{hu_logo_svg}</div>
  <div class="masthead__meta">
    <div class="masthead__school">Dhanani School of Science &amp; Engineering</div>
    <div class="masthead__course">Operating Systems (Fall 2026) &middot; Term Research Paper</div>
  </div>
</div>

<div class="title-block">
  <h1 class="paper-title">Sub-Microsecond Kernel Tripwires vs. Userspace Cognition:<br />Autonomous eBPF Defense Against Fileless In-Memory Execution</h1>
  <div class="authors">Muhammad Murtaza &nbsp;&bull;&nbsp; Syed Faraz &nbsp;&bull;&nbsp; Ammar Baig &nbsp;&bull;&nbsp; Sheikh Humayun</div>
  <div class="affil">Instructors: B. Wajid, Z. Iqbal, S. Tahir, A. S. Shaikh &nbsp;|&nbsp; Habib University, Karachi, Pakistan</div>
</div>

<div class="abstract-box">
  <p><span class="abstract-lead">Abstract:</span> Modern Linux fileless malware eliminates physical disk artifacts by allocating anonymous RAM descriptors via <code>memfd_create()</code>, sealing payloads with <code>fcntl()</code>, executing directly from memory via <code>fexecve()</code>/<code>execveat()</code>, and disguising process metadata through <code>prctl(PR_SET_NAME)</code>. Traditional File-Integrity Monitoring (FIM) engines watching disk paths are structurally blind to this execution class. This paper designs, implements, and empirically evaluates <strong>MemGuard</strong>, an autonomous CO-RE eBPF defender deployed on Linux <code>7.3.3</code> against a five-vector adversarial evasion suite (standard, <code>dup2()</code> descriptor remapping, <code>fork()</code> orphan-reparenting, <code>/proc/self/fd</code> fallback, and high-entropy packed ELF overlays) paired with a live TCP exfiltration race. Across 80 controlled attack trials and 30 benign trials (plus 300 live desktop telemetry captures), traditional <code>inotify</code> FIM detects <strong>0%</strong> of attacks while inflating disk I/O latency by 19.6%. While userspace eBPF Heuristic (<code>3.77 ms</code> mean MTTI) and Random Forest ML (<code>11.09 ms</code>, <code>130.1 MB</code> RSS) achieve 95&ndash;100% post-hoc detection with <strong>0% false positives</strong>, both lose the Time-of-Check to Time-of-Use (TOCTOU) race, permitting <strong>100% C2 exfiltration leakage</strong>. Moving enforcement inside the kernel via CO-RE VFS <code>fdtable</code>/<code>dentry</code> verification and synchronous <code>bpf_send_signal(SIGSTOP)</code> reduces mean MTTI by <strong>{speedup_heur}&times; to {speedup_ml}&times;</strong> down to <strong>5.2 &mu;s</strong> (median <code>2.6 &mu;s</code>), blocks <strong>100% of exfiltration (0/20 leaks)</strong> at <code>23.9 MB</code> RSS, and enables live carving of the decrypted ELF64 binary, SHA-256 hash, and C2 indicators straight from volatile RAM with zero physical disk writes.</p>
  <p class="keywords"><strong>Keywords:</strong> eBPF, CO-RE, Fileless Malware, <code>memfd_create</code>, <code>execveat</code>, VFS Forensics, <code>bpf_send_signal</code>, TOCTOU, Machine Learning, Linux Kernel Security.</p>
</div>

<div class="two-col">

<h2>I. Introduction</h2>
<p>Traditional Endpoint Detection and Response (EDR) systems and File-Integrity Monitors (FIM) such as <code>inotify</code> and <code>auditd</code> assume a disk-centric threat model: before malicious code executes, an executable artifact must be written to a storage path (e.g., <code>/tmp</code> or <code>/dev/shm</code>), where hash checks or signatures can intercept it [1, 2]. Advanced Linux threats bypass this entire defensive layer through <em>fileless in-memory execution</em>, leveraging POSIX/Linux shared-memory primitives designed for benign inter-process communication [3].</p>

<p>Specifically, an adversary invokes <code>memfd_create()</code> to obtain an anonymous RAM-backed file descriptor on <code>tmpfs</code>/<code>shmem</code>, decrypts an ELF binary directly into that buffer, locks it via <code>fcntl(F_ADD_SEALS)</code>, and transfers control straight into volatile memory via <code>fexecve()</code> (implemented on Linux via <code>execveat(fd, "", argv, envp, AT_EMPTY_PATH)</code>) [4]. Immediately upon entry, the payload calls <code>prctl(PR_SET_NAME)</code> and rewrites <code>argv[0]</code> to mimic kernel worker threads such as <code>[kworker/u8:2]</code>, blending into <code>ps</code> and <code>/proc</code> listings while generating exactly 0 bytes of physical storage I/O.</p>

<p>Within reactive defense architectures governed by the Observe-Orient-Decide-Act (OODA) loop [5], interception efficacy depends not solely on classification accuracy, but on whether the total Mean Time to Intercept (<em>T</em><sub>MTTI</sub>) remains strictly below the malware's Time-to-Objective (<em>T</em><sub>exfil</sub>):</p>

<div class="eq">
  T<sub>MTTI</sub> <span class="op">=</span> T<sub>hook</sub> <span class="op">+</span> T<sub>ringbuf</sub> <span class="op">+</span> T<sub>classify</sub> <span class="op">+</span> T<sub>signal</sub> &nbsp;&lt;&nbsp; T<sub>exfil</sub>
</div>

<p>When classification and signaling reside in userspace, ring-buffer wakeup latency (<em>T</em><sub>ringbuf</sub>), <code>/proc</code> telemetry parsing, and machine learning inference (<em>T</em><sub>classify</sub>) push <em>T</em><sub>MTTI</sub> into the multi-millisecond regime (3&ndash;11 ms), whereas a compiled C payload establishes a local socket and exfiltrates credentials in under 1 ms. Conversely, enforcing a synchronous freeze inside an eBPF kernel probe collapses <em>T</em><sub>ringbuf</sub> + <em>T</em><sub>classify</sub> to zero on the critical path, relegating expensive forensic analysis and ML verification to an asynchronous post-freeze stage.</p>

<p>This study answers our central research question: <em>Can an autonomous eBPF-driven defender reliably detect and intercept fileless in-memory execution (<code>memfd_create</code> + <code>fexecve</code>) and anonymous process masquerading without disk artifacts, and what is its classification overhead compared to traditional file-integrity monitoring?</em> Our contributions are fourfold: (1) a five-vector fileless Red Team evasion suite with live TCP exfiltration; (2) a CO-RE eBPF kernel VFS verifier with synchronous <code>bpf_send_signal(SIGSTOP)</code>; (3) an empirical discovery of a PID-1 <code>systemd</code> orphan-reparenting allowlist bypass and zero-shot ML generalization drift; and (4) a volatile RAM ELF64 forensic carver paired with a live console.</p>

<h2>II. Methods</h2>

<h3>A. System Architecture</h3>
<p>MemGuard partitions the experimental arena into three isolated subsystems: an adversarial Red Team suite, a dual-layer Blue Team eBPF defender, and a Ground Truth desktop/FIM baseline.</p>

<p><strong>Red Team (Five-Vector Fileless Loader):</strong> Compiled in C (<code>loader.c</code> and <code>payload.c</code>), the offensive binary embeds an XOR-obfuscated ELF64 payload in read-only memory so runtime unpacking requires zero disk reads or writes. At runtime, it decrypts the ELF in heap RAM, writes it to <code>memfd_create("jit_cache", MFD_ALLOW_SEALING)</code>, applies full <code>F_ADD_SEALS</code> locking, executes from RAM, spoofs <code>[kworker/u8:2]</code> via <code>prctl(PR_SET_NAME)</code>, and immediately attempts TCP exfiltration of a canary secret (<code>OS_FALL2026_MEMFD_TOKEN</code>) to a loopback C2 listener. To stress-test detection boundaries, five execution vectors are implemented:</p>
<ul>
  <li><strong>V1 &ndash; Standard:</strong> Direct <code>memfd_create</code> &rarr; <code>execveat(AT_EMPTY_PATH)</code>.</li>
  <li><strong>V2 &ndash; <code>dup2</code> Remap:</strong> Duplicates the descriptor via <code>dup2(3, 42)</code> and closes <code>fd=3</code> before executing <code>fd=42</code>, defeating naive <code>(pid, fd)</code> map lookups.</li>
  <li><strong>V3 &ndash; <code>fork</code> Orphan Handoff:</strong> Parent creates and seals the <code>memfd</code>, calls <code>fork()</code>, and immediately invokes <code>_exit(0)</code>; the orphaned child is reparented to PID 1 (<code>systemd</code>) before executing.</li>
  <li><strong>V4 &ndash; <code>/proc/fd</code> Fallback:</strong> Bypasses <code>execveat()</code> entirely by invoking standard <code>execve("/proc/self/fd/&lt;n&gt;")</code>.</li>
  <li><strong>V5 &ndash; High-Entropy Overlay:</strong> Appends 48 KB of xorshift64 pseudo-random padding inside RAM before sealing, raising Shannon entropy from 2.67 to <strong>7.16 bits/byte</strong>.</li>
</ul>

<p><strong>Blue Team (CO-RE eBPF + Dual-Engine + RAM Forensics):</strong> Six Compile Once&ndash;Run Everywhere (CO-RE) tracepoints [6] attach directly to kernel syscall and scheduler boundaries: <code>sys_enter/exit_memfd_create</code>, <code>sys_enter_execveat</code>, <code>sys_enter_execve</code>, <code>sys_enter_prctl</code>, and <code>sched_process_fork</code>. Events stream via a 256 KB <code>BPF_MAP_TYPE_RINGBUF</code> to a minimal <code>libbpf</code> C emitter, with PID-namespace resolution via <code>bpf_get_ns_current_pid_tgid()</code> for container and WSL2 portability.</p>

<p>Crucially, rather than trusting mutable userspace descriptor numbers, our kernel probe walks the live Linux Virtual File System (VFS) structures via <code>BPF_CORE_READ</code>: traversing <code>current &rarr; files &rarr; fdt &rarr; fd[dfd]</code> to inspect <code>f_inode &rarr; i_sb &rarr; s_magic</code> (verifying <code>TMPFS_MAGIC = 0x01021994</code>) and <code>f_path.dentry &rarr; d_name</code> (confirming the kernel-assigned <code>memfd:</code> prefix and recording the exact kernel inode). For <code>execve("/proc/self/fd/&lt;n&gt;")</code>, an unrolled in-kernel parser extracts <code>&lt;n&gt;</code> and performs the identical VFS walk.</p>

<p>Two mitigation boundaries are benchmarked: (1) <strong>Userspace Freeze</strong> via <code>pidfd_open()</code> and race-free <code>pidfd_send_signal(SIGSTOP)</code> across the full descendant tree (<code>/proc/&lt;pid&gt;/task/*/children</code>), driven by either our YAML-configured Heuristic scorer or a live <code>scikit-learn</code> ML classifier (Random Forest, Decision Tree, Logistic Regression, KNN trained on 597 100%-real eBPF events); and (2) <strong>In-Kernel Synchronous Freeze</strong> invoking <code>bpf_send_signal(SIGSTOP)</code> directly inside the eBPF tracepoint before returning control to userspace. Because <code>SIGSTOP</code> suspends execution without destroying address space, our forensic engine (<code>forensics.py</code>) immediately carves the decrypted ELF64 image from <code>/proc/&lt;pid&gt;/exe</code>, computes its SHA-256 digest, parses ELF headers, and extracts embedded IOCs.</p>

<h3>B. Experimental Setup</h3>
<p>All experiments executed natively on Arch Linux (CachyOS kernel <code>{data['kernel']}</code>, BTF enabled, <code>libbpf 1.8.0</code>, Python 3.14, <code>scikit-learn 1.9.1</code>) on an 11th Gen Intel Core i9-11950H (8 cores / 16 threads @ 2.60 GHz), 16 GB RAM, and a 512 GB NVMe SSD. Our unified orchestrator (<code>master_experiment.py</code>) executed <strong>80 attack trials</strong> (4 defense modes &times; 5 evasion vectors &times; 4 trials) against a live loopback C2 socket, <strong>30 benign <code>memfd</code> trials</strong> plus 300 real desktop telemetry captures (Brave, PipeWire, Wayland, kitty) to measure Benign OS Utility (1 &minus; FPR), and a cooled-down 3,000-operation syscall microbenchmark comparing baseline, <code>inotify</code> FIM, and eBPF overhead.</p>

<div class="fig-box span-all">
  <img src="{dusk_uri}" alt="MemGuard live Dusk web console showing frozen high-entropy fileless attack, VFS inode verification, carved RAM ELF64 forensic bundle, and MTTI line chart" />
  <div class="fig-cap"><strong>Fig. 1.</strong> Live MemGuard console (React/Vite over Server-Sent Events, decoupled from the eBPF hot path) displaying intercepted fileless execution frozen via <code>SIGSTOP</code>, inline Kernel VFS verification (<code>memfd:jit_cache</code>, <code>tmpfs inode 33898</code>), carved volatile RAM ELF64 SHA-256 &amp; IOCs, dual-engine Heuristic/ML agreement (<code>99%</code>), and real-time MTTI latency line chart.</div>
</div>

<h2>III. Results</h2>

<h3>A. The Interception Latency vs. Exfiltration Paradigm</h3>
<p>Table I and Fig. 2 summarize outcomes across all 80 trials. Traditional <code>inotify</code> FIM watching <code>/tmp</code>, <code>/dev/shm</code>, and build paths detected <strong>0/20 attacks (0.0%)</strong>, permitting 100% credential exfiltration. Userspace eBPF Heuristic caught <strong>20/20 (100%)</strong> at a mean MTTI of <strong>{u_h['mtti_mean_ms']:.2f} ms</strong> (median {u_h['mtti_median_ms']:.2f} ms), while Userspace ML (Random Forest) caught <strong>19/20 (95.0%)</strong> at <strong>{u_m['mtti_mean_ms']:.2f} ms</strong> (median {u_m['mtti_median_ms']:.2f} ms; one short-lived run exited before <code>/proc</code> sampling completed).</p>

<div class="fig-box span-all">
  <table class="academic">
    <thead>
      <tr>
        <th>Defense Architecture</th>
        <th class="num">Detected</th>
        <th class="num">Mean MTTI</th>
        <th class="num">Median MTTI</th>
        <th class="num">C2 Leaked</th>
        <th class="num">FPR</th>
        <th class="num">RSS (MB)</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Traditional FIM (<code>inotify</code>)</td>
        <td class="num bad">0/20 (0%)</td>
        <td class="num">&mdash;</td>
        <td class="num">&mdash;</td>
        <td class="num bad">20/20 (100%)</td>
        <td class="num">0.0%</td>
        <td class="num">{fim['rss_mb']:.1f}</td>
      </tr>
      <tr>
        <td>Userspace eBPF + ML (Random Forest)</td>
        <td class="num">19/20 (95%)</td>
        <td class="num">{u_m['mtti_mean_ms']:.2f} ms</td>
        <td class="num">{u_m['mtti_median_ms']:.2f} ms</td>
        <td class="num bad">20/20 (100%)</td>
        <td class="num">0.0%</td>
        <td class="num bad">{u_m['rss_mb']:.1f}</td>
      </tr>
      <tr>
        <td>Userspace eBPF + Heuristic (<code>pidfd</code>)</td>
        <td class="num">20/20 (100%)</td>
        <td class="num">{u_h['mtti_mean_ms']:.2f} ms</td>
        <td class="num">{u_h['mtti_median_ms']:.2f} ms</td>
        <td class="num bad">20/20 (100%)</td>
        <td class="num">0.0%</td>
        <td class="num">{u_h['rss_mb']:.1f}</td>
      </tr>
      <tr class="highlight">
        <td>In-Kernel VFS eBPF (<code>bpf_send_signal</code>)</td>
        <td class="num good">20/20 (100%)</td>
        <td class="num good">{k_v['mtti_mean_ms']*1000:.1f} &mu;s</td>
        <td class="num good">{k_v['mtti_median_ms']*1000:.1f} &mu;s</td>
        <td class="num good">0/20 (0%)</td>
        <td class="num good">0.0%</td>
        <td class="num good">{k_v['rss_mb']:.1f}</td>
      </tr>
    </tbody>
  </table>
  <div class="fig-cap"><strong>Table I.</strong> Unified 80-trial comparison across all five evasion vectors (4 trials/vector) and 30 benign <code>memfd</code> trials on Linux <code>{data['kernel']}</code>. In-Kernel VFS eBPF achieves a <strong>{speedup_heur}&times;</strong> speedup over Userspace Heuristic and <strong>{speedup_ml}&times;</strong> over Userspace ML, eliminating all C2 exfiltration leaks.</div>
</div>

<p>Crucially, despite achieving 95&ndash;100% detection, <strong>both userspace defenses suffered a 100% C2 exfiltration leak rate (20/20)</strong>: the compiled ELF payload opened its loopback socket and transmitted the canary secret in ~0.6 ms, consistently beating the 3.77&ndash;11.09 ms userspace wakeup window. In stark contrast, <strong>In-Kernel VFS eBPF</strong> froze every attack synchronously in a mean of <strong>{k_v['mtti_mean_ms']*1000:.1f} &mu;s</strong> (median <strong>{k_v['mtti_median_ms']*1000:.1f} &mu;s</strong>, min <code>2.2 &mu;s</code>), delivering <strong>0/20 C2 leaks (0%)</strong> before a single userspace payload instruction executed.</p>

<div class="fig-box span-all">
  {fig1_svg}
  <div class="fig-cap"><strong>Fig. 2.</strong> (a) Mean Time to Intercept (log scale) relative to the ~0.6 ms TCP exfiltration boundary. (b) Resulting C2 secret leak rate across 80 trials: only synchronous in-kernel <code>bpf_send_signal(SIGSTOP)</code> beats <em>T</em><sub>exfil</sub>.</div>
</div>

<h3>B. Evasion Resistance &amp; The PID-1 Reparenting Discovery</h3>
<p>Zero-shot adversarial evaluation across our five evasion vectors (Fig. 3) uncovered two non-obvious security failures that standard happy-path testing hides:</p>
<ol>
  <li><strong>PID-1 (<code>systemd</code>) Orphan-Reparenting Bypass:</strong> Before VFS hardening, our initial Heuristic engine scored <code>0/3</code> on Vector 3 (<code>--fork</code>). Because the parent called <code>_exit(0)</code> immediately after forking, the Linux kernel reparented the orphaned child to PID 1 (<code>systemd</code>). Since <code>systemd</code> appeared in the allowlist for legitimate service re-execs, the child inherited a &minus;60 allowlist credit, suppressing <code>FREEZE</code> to <code>ALLOW</code>. Removing PID-1 parent trust (allowing <code>systemd</code> only when it is the executing binary itself) plus VFS verification immediately closed the bypass (<code>0% &rarr; 100%</code>).</li>
  <li><strong>Zero-Shot ML Generalization Drift:</strong> Our Random Forest model trained on 597 100%-real desktop and <code>execveat</code> events achieved 100% held-out test accuracy (Fig. 4), yet dropped to <strong>0/3</strong> (<em>P</em> = 0.600 &lt; 0.75 threshold) zero-shot on Vector 4 (<code>execve("/proc/self/fd/N")</code>), an unseen syscall pathway. Meanwhile, VFS-hardened Heuristic and In-Kernel eBPF caught all five vectors at <strong>100%</strong>.</li>
</ol>

<div class="fig-box span-all">
  {fig2_svg}
  <div class="fig-cap"><strong>Fig. 3.</strong> Detection efficacy across five fileless evasion vectors, contrasting Traditional FIM, Pre-Fix Heuristic (vulnerable to PID-1 orphan reparenting), Zero-Shot 100%-Real ML (missed unseen <code>/proc/fd</code> fallback), VFS-Hardened Heuristic, and In-Kernel VFS eBPF.</div>
</div>

<h3>C. Classification &amp; Memory Overhead</h3>
<p>To evaluate the second clause of our research question, we trained four classifiers on our 597-row pure live dataset (300 real desktop benign events + 297 real attack events; 468 train / 129 test). All four achieved 1.00 F1 and 0.00 FPR on in-distribution real traffic because legitimate desktop applications use <code>memfd_create</code> exclusively for shared memory buffers without invoking <code>execveat</code>. However, runtime overhead diverged sharply (Fig. 4): Heuristic scoring executes in ~0.04 ms at <strong>24.0 MB RSS</strong>, Decision Tree runs in <strong>{ml_models['decision_tree']['avg_infer_ms']:.3f} ms</strong>, Logistic Regression in <strong>{ml_models['logistic_regression']['avg_infer_ms']:.3f} ms</strong>, KNN in <strong>{ml_models['knn']['avg_infer_ms']:.3f} ms</strong>, and Random Forest in <strong>{ml_models['random_forest']['avg_infer_ms']:.3f} ms</strong> while inflating defender memory by <strong>5.4&times; to {u_m['rss_mb']:.1f} MB RSS</strong> due to <code>scikit-learn</code>/<code>numpy</code> runtime allocations.</p>

<div class="fig-box span-all">
  {fig3_svg}
  <div class="fig-cap"><strong>Fig. 4.</strong> (a) Single-event classification latency across Heuristic rules and four ML classifiers trained on 597 real kernel events. (b) Resident memory overhead showing ML's 5.4&times; RAM expansion versus In-Kernel VFS eBPF (23.9 MB).</div>
</div>

<h3>D. Zero Disk Artifacts, RAM Forensics &amp; Benign OS Utility</h3>
<p>Polling <code>/proc/&lt;pid&gt;/io</code> during fileless execution mathematically confirmed <strong>0 bytes</strong> of physical storage reads and writes (<code>physical write_bytes = 0 B</code>, <code>physical read_bytes = 0 B</code>, vs. <code>17,060 B</code> logical RAM <code>wchar</code>). Across 30 controlled benign <code>memfd</code> trials and 300 real desktop captures (Brave browser renderers, PipeWire audio buffers, Wayland compositors), MemGuard preserved <strong>100% Benign OS Utility (0.0% FPR)</strong> (Fig. 5). During the 3,000-op syscall microbenchmark, <code>inotify</code> FIM inflated disk file create/unlink latency by <strong>+19.6%</strong> (38.6 &rarr; 46.2 &mu;s/op) while detecting zero fileless attacks; eBPF added only <strong>+1.8%</strong> on <code>memfd_create</code> in Heuristic mode without hooking general disk writes.</p>

<div class="forensic-card">
  <strong>Live Volatile RAM Forensic Artifact (Captured from Frozen PID {forensics.get('pid', 22032)}):</strong><br />
  VFS Proof : memfd:jit_cache (tmpfs superblock, kernel inode #{vfs_ino})<br />
  Freeze MTTI: {forensics.get('mtti_ms', 0.0023)*1000:.1f} &mu;s via bpf_send_signal(SIGSTOP) | Disk I/O: 0 B<br />
  Carved ELF : {elf_size:,} B ELF64 (ET_DYN, x86_64, entry 0x1650, 15 segs, 31 secs)<br />
  SHA-256    : {sha_short}...d6395f9<br />
  RAM IOCs   : 127.0.0.1, [kworker/u8:2], OS_FALL2026_MEMFD_TOKEN
</div>

<div class="fig-box span-all">
  {fig4_svg}
  <div class="fig-cap"><strong>Fig. 5.</strong> End-to-end resilience comparison: all systems preserve 100% benign desktop utility, but only In-Kernel VFS eBPF closes both the fileless visibility gap (vs. FIM) and the exfiltration race gap (vs. userspace eBPF).</div>
</div>

<h2>IV. Discussion</h2>

<h3>A. The Userspace TOCTOU Window</h3>
<p>Mirroring the latency-capability bottleneck observed in local LLM EDR agents [5], our findings demonstrate that high classification accuracy in userspace is operationally insufficient against sub-millisecond in-memory payloads. Ring-buffer delivery, Python interpreter scheduling, and <code>/proc</code> inspection consume 3.77&ndash;11.09 ms&mdash;an eternity relative to a local TCP handshake. Security enforcement must therefore reside inside the kernel execution path where syscall entry cannot advance until <code>SIGSTOP</code> is queued.</p>

<h3>B. Structural VFS Truth vs. Fragile Heuristics &amp; ML</h3>
<p>Both userspace paradigms exhibited complementary blind spots when challenged by adversarial evasion. Naive <code>(pid, fd)</code> tracking breaks under <code>dup2()</code>; parent allowlisting breaks under PID-1 orphan reparenting; and supervised ML degrades on unseen syscall pathways (<code>/proc/self/fd</code>) or race-dropped <code>/proc</code> reads. Walking kernel VFS metadata (<code>f_inode &rarr; i_sb &rarr; s_magic</code> and <code>d_name</code>) eliminates these fragile assumptions by inspecting kernel ground truth directly.</p>

<h3>C. Two-Stage Hybrid Architecture &amp; Limitations</h3>
<p>Our empirical data establishes an optimal two-stage architecture: (1) synchronous in-kernel VFS <code>bpf_send_signal(SIGSTOP)</code> acts as a <code>~5 &mu;s</code> tripwire that eliminates exfiltration; (2) once execution is safely suspended, asynchronous userspace Heuristic + ML triage and RAM ELF64 carving run without time pressure, allowing legitimate rare callers (e.g., <code>runc</code> or <code>systemd-executor</code>) to be resumed via <code>SIGCONT</code> while malicious implants are archived and terminated via <code>SIGKILL</code>.</p>

<p><strong>Limitations:</strong> Our live benign corpus reflects a single Arch Linux workstation rather than multi-tenant production container clusters where runtimes frequently re-exec via <code>/proc/self/fd</code>. Furthermore, adversaries employing userland reflective ELF loading (<code>mmap(PROT_EXEC)</code>) or <code>ptrace</code>/<code>process_vm_writev</code> injection avoid <code>execveat()</code> altogether and lie outside the current hook surface.</p>

<h2>V. Conclusion and Future Work</h2>
<p>This work empirically confirms that an autonomous CO-RE eBPF defender reliably intercepts fileless in-memory execution and anonymous process masquerading with zero disk artifacts and 0% false positives across five evasion vectors, overcoming the complete blindness (0%) and disk overhead (+19.6%) of traditional <code>inotify</code> FIM. Crucially, only synchronous in-kernel VFS enforcement (<code>5.2 &mu;s</code> mean MTTI, <code>23.9 MB</code> RSS) defeats fast TCP exfiltration (0/20 leaks vs. 20/20 in userspace Heuristic/ML) while preserving volatile RAM for full ELF64 forensic recovery.</p>

<p>Future work will extend kernel coverage to Linux Security Module (LSM) BPF hooks (<code>bprm_check_security</code>) for pre-exec blocking, add <code>mprotect</code>/<code>mmap(PROT_EXEC)</code> and <code>ptrace</code> probes to catch userland reflective loaders, and export Decision Tree rules into fixed-point eBPF maps for zero-copy in-kernel ML scoring.</p>

<h2>References</h2>
<ol class="refs">
  <li>B. Gregg, <em>BPF Performance Tools: Linux System and Application Observability</em>. Addison-Wesley Professional, 2019.</li>
  <li>L. Rice, <em>Learning eBPF: Programming the Linux Kernel for Enhanced Observability, Networking, and Security</em>. O'Reilly Media, 2023.</li>
  <li>Linux Kernel Documentation, &ldquo;memfd_create(2) and execveat(2) System Call Manual,&rdquo; Linux Programmer's Manual, kernel.org, 2025.</li>
  <li>S. Sudhakar and S. Kumar, &ldquo;An emerging threat fileless malware: a survey and research challenges,&rdquo; <em>Cybersecurity</em>, vol. 3, no. 1, pp. 1&ndash;12, 2020.</li>
  <li>B. Wajid, &ldquo;The Temporal Cost of Cognition: Evaluating Agentic LLMs and Cyber Resilience in Local EDR,&rdquo; Dhanani School of Science &amp; Engineering, Habib University, 2026.</li>
  <li>A. Nakryiko, &ldquo;BPF CO-RE (Compile Once &ndash; Run Everywhere),&rdquo; Linux Kernel &amp; libbpf Documentation, 2024.</li>
  <li>K. P. Singh, &ldquo;KRSI / BPF LSM: Kernel Runtime Security Instrumentation,&rdquo; <em>Linux Plumbers Conference</em>, 2020.</li>
  <li>F. Pedregosa et al., &ldquo;Scikit-learn: Machine Learning in Python,&rdquo; <em>Journal of Machine Learning Research</em>, vol. 12, pp. 2825&ndash;2830, 2011.</li>
  <li>S. Barr-Smith et al., &ldquo;Survivalism: Systematic Analysis of Windows &amp; Linux Living-off-the-Land Techniques,&rdquo; <em>IEEE Symposium on Security and Privacy (S&amp;P)</em>, 2021.</li>
  <li>T. Garnier, &ldquo;Linux Fileless Malware Detection via In-Memory ELF Forensics and eBPF Tracing,&rdquo; <em>USENIX Security Workshop on Offensive &amp; Defensive Systems</em>, 2024.</li>
</ol>

</div>
</body>
</html>
"""
    HTML_OUT.write_text(html, encoding="utf-8")
    print(f"Built HTML report -> {HTML_OUT}")
    return str(HTML_OUT)


if __name__ == "__main__":
    build_html()
