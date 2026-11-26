# MemGuard — Autonomous eBPF Defense Against Fileless In-Memory Malware

**Course:** Operating Systems (Fall 2026) — Habib University  
**Instructors:** B. Wajid, Z. Iqbal, S. Tahir, A. S. Shaikh  
**Team Members:** Muhammad Murtaza, Syed Faraz, Ammar Baig, Sheikh Humayun  

> **Research Question:**  
> *"Can an autonomous eBPF-driven defender reliably detect and intercept fileless in-memory execution (`memfd_create` + `fexecve`) and anonymous process masquerading without disk artifacts, and what is its classification overhead compared to traditional file-integrity monitoring?"*

---

## 1. Plain-English Overview (Start Here)

### What Problem Does MemGuard Solve?
Normally, when malware runs on Linux, it writes a file onto the disk (often inside `/tmp` or `/dev/shm`). Antivirus scanners and File Integrity Monitors (**FIM**, like `inotify`) watch disk folders and catch those files.

**Fileless malware never touches the disk.** Instead, it abuses built-in Linux RAM features:
1. Creates an invisible in-memory file using `memfd_create()` (lives only in kernel `tmpfs` RAM).
2. Unpacks or decrypts an executable directly into that memory descriptor and seals it (`fcntl(F_ADD_SEALS)`).
3. Runs directly from memory via `execveat(AT_EMPTY_PATH)` / `/proc/.../fd/<N>` — **or** skips `memfd` altogether with anonymous executable pages (`mmap(PROT_READ|PROT_WRITE)` followed by `mprotect(PROT_EXEC)`).
4. Uses `prctl(PR_SET_NAME)` and `argv[0]` spoofing to disguise itself as a harmless kernel thread like `[kworker/u8:2]`.

Because **0 bytes ever hit the hard drive**, traditional disk-based `inotify` FIM tools detect **0%** of these attacks.

### How MemGuard Works (Two-Stage Architecture)
MemGuard places sensors directly inside the **Linux kernel** using **CO-RE eBPF** (`libbpf`):

1. **Stage 1 — Kernel Sensor & Synchronous Tripwire (`ebpf/`, 9 tracepoints):**
   - Watches `memfd_create` (`enter`/`exit`), `execveat`, `execve`, `prctl`, `sched_process_fork`, `mmap` (`enter`/`exit`), and `mprotect`.
   - Works across containers and WSL2 PID namespaces (`bpf_get_ns_current_pid_tgid()`).
   - Instead of trusting mutable userspace FD numbers, the kernel probe walks VFS kernel structures (`current -> files -> fdt -> fd[dfd]`), verifies `TMPFS_MAGIC` (`0x01021994`) + `"memfd:"` dentry prefix + inode, parses `/proc/self/fd/`, `/proc/thread-self/fd/`, and cross-process `/proc/<pid>/fd/` execution paths, and flags anonymous `W -> X` memory transitions (with an in-kernel JIT allowlist for `node`, browsers, and Python).
   - In **In-kernel** mode (`bpf_send_signal(SIGSTOP)`), suspicious `memfd` executions or non-allowlisted anonymous `mprotect(PROT_EXEC)` calls are frozen inside the kernel within microseconds before exfiltrating data to a C2 server.

2. **Stage 2 — Userspace Dual-Engine Triage, Safety Resume & Forensics (`defender_heuristic/` + `defender_ml/`):**
   - **Heuristic Classifier (`rules.yaml`):** Weighted rule scoring (default freeze threshold `70`) with `allowlist_comms` for legitimate apps (PipeWire, Wayland, Firefox, Chrome/Brave, Electron, Node, `runc`, `systemd`).
   - **ML Classifier (`defender_ml/model.joblib`):** `scikit-learn` pipeline (Random Forest by default, benchmarked alongside Decision Tree, Logistic Regression, and KNN) over 11 kernel/telemetry features.
   - **Stage-2 Auto-`SIGCONT` Safety:** If the kernel freezes a call (`kernel_freeze`) that userspace scores as `ALLOW`, MemGuard automatically sends `SIGCONT` (`resume_process`) so desktop apps are not left paused.
   - **Volatile RAM Carving (`forensics.py`):** While an attack is paused via `SIGSTOP`, MemGuard extracts the decrypted ELF64 image directly from `/proc/<pid>/exe`, computes SHA-256, parses ELF headers, and extracts IOCs.

3. **Live Web Console (`ui/`):**
   - Real-time React + Vite + SSE dashboard featuring:
     - **Single-Vector & 7-Vector Auto-Sweep (`Run all (7)`):** Test any single attack vector (V1–V7) or run all 7 automatically in sequence.
     - **Overlapping Heuristic vs. ML Comparison Modal (`Compare graphs` / `Graph`):** Darkened blurred pop-up comparing per-event inference latency and MTTI against the ~0.6 ms TCP exfiltration boundary.
     - **Searchable Per-Iteration Execution Traces (`Traces` tab + `TraceModal`):** Every attack/benign run writes `logs/traces/TRC-XXXX.json` with `stdout`/`stderr`, expanded parent/child PIDs, chronological kernel/classifier steps, VFS inodes, loopback C2 leaks, and raw JSON.

### Supported Attack Evasion Vectors (V1–V7)

| Vector | Loader Flag | Technique Tested |
| :--- | :--- | :--- |
| **V1 · Standard** | *(default)* | `memfd_create` → `F_ADD_SEALS` → `execveat(AT_EMPTY_PATH)` + `[kworker/u8:2]` masquerade |
| **V2 · dup2 remap** | `--dup-fd` | Duplicates descriptor via `dup2(3, 42)` and closes `fd=3` to bypass `(pid, fd)` maps |
| **V3 · fork handoff** | `--fork` | Forks child and exits parent immediately (`_exit(0)`), reparenting child to PID 1 (`systemd`) |
| **V4 · /proc/fd fallback** | `--execve-fd` | Avoids `execveat()` by calling `execve("/proc/self/fd/<N>")` |
| **V5 · High-entropy** | `--high-entropy` | Appends 48 KB pseudo-random xorshift64 padding in RAM (~7.16 bits/byte entropy) |
| **V6 · mmap W→X** | `--mmap-exec` | Allocates `mmap(RW)` and flips to `mprotect(RX)` shellcode without `memfd_create` or `execveat` |
| **V7 · SCM_RIGHTS** | `--scm-fd` | Forks receiver *before* `memfd_create`, passes FD over Unix `SCM_RIGHTS`, runs `execve("/proc/<pid>/fd/<N>")` |

---

## 2. Repository Structure

```text
OS_Project_main/
├── Makefile                            # Compiles red_team loader + eBPF vmlinux.h, probes, sensor
├── requirements.txt                    # Core Python deps (pyyaml, scikit-learn, joblib, numpy)
├── proposal.pdf                        # Original project proposal
├── README.md                           # This guide
├── red_team/
│   ├── payload.c                       # Fileless ELF payload (prctl spoof + loopback C2 exfil)
│   ├── pack_payload.py                 # XOR-packs compiled payload into header bytes
│   └── loader.c                        # 7-vector attack loader & --benign-memfd generator
├── ebpf/
│   ├── events.h                        # Shared kernel <-> userspace structs (9 event types)
│   ├── probes.bpf.c                    # 9 CO-RE tracepoints + VFS fd/memfd + W->X verification
│   └── sensor.c                        # libbpf ring-buffer consumer emitting JSON lines
├── defender_heuristic/
│   ├── rules.yaml                      # Rule weights, thresholds, kthread prefixes, allowlist
│   ├── telemetry.py                    # Reads /proc/<pid>/exe, 5-level ancestry, Shannon entropy
│   ├── classifier.py                   # Rule scoring engine (HeuristicClassifier)
│   ├── forensics.py                    # Carves paused ELF64 images from /proc/<pid>/exe
│   ├── mitigator.py                    # pidfd_send_signal (SIGSTOP / SIGCONT / SIGKILL) + MTTI
│   └── main.py                         # Main daemon (--engine heuristic|ml, --kernel-freeze, JSONL)
├── defender_ml/
│   ├── features.py                     # 11-feature extractor shared across training & live scoring
│   ├── collect_dataset.py              # Captures live, attack, JSONL-imported, or bootstrap CSVs
│   ├── auto_collect_and_train.py       # One-command live benign + attack capture + 4-model trainer
│   ├── train.py                        # GroupShuffleSplit 4-model trainer -> model.joblib + metrics.json
│   ├── classifier.py                   # MLClassifier wrapper matching Heuristic interface
│   ├── data/                           # CSV datasets (wsl_*.csv, dataset.csv; add cachyos_*.csv here)
│   ├── model.joblib                    # Trained scikit-learn model bundle
│   └── metrics.json                    # Accuracy/F1/FPR/inference latency JSON for all 4 models
├── evaluation/
│   ├── master_experiment.py            # Runs 7-vector trials across modes + FIM + overhead -> experiment_data.json
│   ├── eval_evasion_zero_shot.py       # Per-vector zero-shot comparison (Heuristic vs ML)
│   ├── overhead_suite.py               # 3,000-op syscall & RSS overhead benchmark -> evaluation/results/
│   ├── benchmark.py                    # Quick MTTI, detection, FPR & RSS comparison script
│   ├── verify_disk_io.py               # Proves 0 bytes written to physical disk via /proc/<pid>/io
│   └── fim_baseline.py                 # Proves traditional inotify FIM misses fileless execution
├── report/
│   ├── generate_charts.py              # Generates standalone SVG charts (fig1..fig4) in report/assets/
│   ├── build_report.py                 # Generates report/report.html & compiles report/MemGuard_OS_Report.pdf
│   ├── report.html                     # Generated HTML report
│   ├── MemGuard_OS_Report.pdf          # Final compiled WeasyPrint PDF report
│   └── assets/                         # experiment_data.json, dusk_console.png, hu_logo.svg, fig*.svg
└── ui/
    ├── server.py                       # HTTP + SSE API, MockC2Server, & logs/traces/TRC-*.json store
    └── frontend/                       # React + Vite Dusk UI (App.jsx, CompareModal.jsx, TraceModal.jsx, MttiStrip.jsx)
```

---

## 3. Requirements & Pre-Flight Check

> **Important:** MemGuard hooks Linux kernel tracepoints. Run everything inside **Native Linux** (CachyOS / Arch / Ubuntu) or **Windows WSL2 (Ubuntu)**—not Windows PowerShell/CMD.

### Software Requirements
* Linux kernel with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
* **`sudo` / root privileges** (needed to attach eBPF probes and signal processes)
* `gcc`, `clang`, `llvm`, `bpftool`, `libbpf`, `libelf`, `zlib`, `make`
* Python **3.10+** (`pyyaml`, `scikit-learn`, `joblib`, `numpy`, plus `matplotlib` & `weasyprint` for charts/PDF)
* Node.js **18+** & `npm`

### Check Kernel BTF Support
```bash
uname -r
ls -l /sys/kernel/btf/vmlinux
```
If `/sys/kernel/btf/vmlinux` prints a file size (several MB), your kernel is ready. (On WSL2, if it is missing, run `wsl --update` in Windows.)

---

## 4. Setup & Build Instructions

### Option A: Arch Linux / CachyOS (Recommended for Data Collection & Final Report)

1. **Install system, ML, charting, and PDF packages:**
   ```bash
   sudo pacman -S --needed base-devel clang llvm bpf libbpf \
       python python-yaml python-scikit-learn python-joblib python-numpy \
       python-matplotlib python-weasyprint pango cairo gdk-pixbuf2 \
       nodejs npm
   ```

2. **Clone or pull latest code, then compile C/eBPF binaries:**
   ```bash
   git clone https://github.com/faraz18001/Opreating-Systems-Projec.git OS_Project_main
   cd OS_Project_main
   # Or, if already cloned:
   # git pull origin main

   make clean && make
   ```
   Confirm `red_team/build/loader`, `ebpf/vmlinux.h`, `ebpf/build/probes.bpf.o`, and `ebpf/build/sensor` exist.

3. **Build the React Web UI:**
   ```bash
   cd ui/frontend
   npm install
   npm run build
   cd ../..
   ```

---

### Option B: Ubuntu / Debian / Windows WSL2 (Ubuntu)

> **WSL2 Tip:** Always clone and run inside WSL's Linux filesystem (`~/OS_Project_main`), **not** `/mnt/c/...` or OneDrive (prevents `CRLF`/`LF` issues and slow builds).

1. **Install packages:**
   ```bash
   sudo apt update
   sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
       python3 python3-pip python3-venv python3-yaml python3-sklearn python3-joblib python3-numpy \
       linux-tools-common linux-tools-generic nodejs npm \
       libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev
   ```

2. **Compile C & eBPF binaries:**
   * On **Native Ubuntu/Debian**:
     ```bash
     make clean && make
     ```
   * On **WSL2** (Ubuntu's default `bpftool` wrapper rejects `-microsoft-standard-WSL2`, so pass the real binary path):
     ```bash
     rm -f ebpf/vmlinux.h
     make clean
     make BPFTOOL=$(find /usr/lib/linux-tools -name bpftool 2>/dev/null | head -n 1)
     ```

3. **Build the React Web UI:**
   ```bash
   cd ui/frontend
   npm install
   npm run build
   cd ../..
   ```

4. **Optional `.venv` for generating the PDF report (`weasyprint` + `matplotlib`) on WSL2/Ubuntu:**
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt weasyprint matplotlib
   ```

---

## 5. Quick Start: Run MemGuard Yourself (See the New UI)

Stop any old defender process first (`Ctrl+C`) so two eBPF sensors don't fight over events, then start the console server with `sudo`:

```bash
cd ~/OS_Project_main

# On Native Linux / CachyOS (default port 8080):
sudo python3 ui/server.py --auto-start

# On WSL2 (use port 8081 if port 8080 is taken by Open WebUI or another app):
sudo python3 ui/server.py --port 8081 --auto-start
```

Open **`http://127.0.0.1:8080`** (or **`http://127.0.0.1:8081`** on WSL2) in your browser.

### What to Try in the New UI
1. **Top Bar Modes:** Toggle **`Heuristic`** vs **`ML`**, and **`In-kernel`** (`bpf_send_signal`, ~µs freeze before C2 leak) vs **`Userspace`** (`pidfd_send_signal`, loses race to C2).
2. **Single Vector vs. 7-Vector Auto-Sweep:**
   - Pick any vector (`V1` through `V7`, including `V6 · mmap W→X` and `V7 · SCM_RIGHTS /proc/pid/fd`) and click **`Simulate attack`**.
   - Or click **`Run all (7)`** once to automatically iterate through all 7 vectors sequentially (click **`Stop (k/7)`** anytime to abort).
3. **Darkened Overlapping Comparison Chart:** Click **`Compare graphs`** (in the *Interception latency* panel) or **`Graph`** (in *Evaluation metrics*) to open the darkened blurred modal plotting **Heuristic vs. ML** latency and **MTTI** series overlapping against the ~0.6 ms exfiltration line.
4. **Searchable Per-Iteration Logs / Traces:**
   - Click any cyan **`TRC-0001`** badge inside the `Threats` / `All` stream, or switch to the **`Traces (N)`** tab.
   - Type in the search box to filter across trace IDs, PIDs, vectors (`mmap-exec`, `scm-fd`), syscalls (`MPROTECT_EXEC`, `EXECVEAT`), VFS inodes, `stdout`, or C2 payloads.
   - Click any trace row to open the **`TraceModal`** popup showing the full process tree, chronological kernel/classifier timeline, dual Heuristic vs ML verdict, carved ELF forensics, `stdout`/`stderr`, loopback C2 packets, and raw JSON (saved on disk under `logs/traces/TRC-XXXX.json`).
5. **Quarantine & Verification Lab:** Expand any frozen event to **`Resume (SIGCONT)`** or **`Terminate (SIGKILL)`**, and click **`Verify`** (0-byte disk I/O), **`Test`** (benign memfd), or **`Compare`** (`inotify` FIM baseline).  
   *(Tip: Switch to `Userspace` or turn **`Sensor active`** off before clicking `Verify` / `Compare` if in-kernel freeze catches the test loader before `/proc/io` finishes.)*

### Terminal-Only Commands (Optional CLI Usage)
```bash
# Run defender directly in terminal
sudo python3 defender_heuristic/main.py --show-all                  # Heuristic + ML shadow
sudo python3 defender_heuristic/main.py --kernel-freeze --show-all  # In-kernel SIGSTOP freeze
sudo python3 defender_heuristic/main.py --engine ml --show-all      # Active ML mode
sudo python3 defender_heuristic/main.py --dry-run --show-all        # Log only, no freeze

# Run red-team loader manually in a second terminal
./red_team/build/loader --benign-memfd
./red_team/build/loader --ticks 5
./red_team/build/loader --mmap-exec --ticks 5
./red_team/build/loader --scm-fd --ticks 5
```

---

## 6. CachyOS Workflow: Collect Real Desktop Data, Benchmark, Get Graphs & Generate Report

Follow these exact steps on **CachyOS** to gather realistic benign background telemetry from real desktop applications (browsers, PipeWire, Wayland, terminals, editors), run the full 7-vector benchmark suite, refresh charts, and regenerate the PDF report.

*(Make sure `ui/server.py` is **stopped** before collecting data or running benchmarks.)*

### Step 1: Collect Realistic Desktop Data & Train All 4 ML Models

**Option 1 (Fastest — One Automated Command):**  
Starts the eBPF sensor, records up to **300 real benign desktop events** while you actively use your CachyOS apps, automatically runs balanced attack rounds (including varied masquerading/memfd profiles), and trains all 4 models (`Random Forest`, `Decision Tree`, `Logistic Regression`, `KNN`):
```bash
sudo python3 defender_ml/auto_collect_and_train.py --target-benign 300 --max-minutes 15
```
> **While this is running (important!):** Open Firefox/Chromium/Brave, play a video or music (triggers PipeWire/Wayland shared `memfd`s), open a terminal/editor, and optionally run a few `./red_team/build/loader --benign-memfd` commands in another terminal. It finishes automatically once 300 benign rows are reached (or press `Ctrl+C` early to proceed straight to attack rounds + training).

**Option 2 (Manual / Keep Separate CachyOS CSV Files to Merge Later):**
```bash
# 1. Record 4 minutes of real desktop benign events (keep browsing/playing audio while it runs!)
sudo python3 defender_ml/collect_dataset.py --mode live --label 0 --duration 240 \
    --output defender_ml/data/cachyos_benign.csv --reset

# 2. Record 15 rounds of labeled red-team attacks
sudo python3 defender_ml/collect_dataset.py --mode collect-attacks --rounds 15 \
    --output defender_ml/data/cachyos_attacks.csv --reset

# 3. Fix root file ownership on CSVs
sudo chown -R $USER:$USER defender_ml/data/

# 4. Merge CachyOS (and optional WSL2) CSVs into defender_ml/data/dataset.csv and train
python3 - <<'EOF'
import csv
from pathlib import Path

data_dir = Path("defender_ml/data")
rows_all, header = [], None
for fname in ("cachyos_benign.csv", "cachyos_attacks.csv", "wsl_benign.csv", "wsl_attacks.csv"):
    p = data_dir / fname
    if not p.exists():
        continue
    with open(p, newline="", encoding="utf-8") as f:
        r = list(csv.reader(f))
    if r:
        header = r[0]
        rows_all.extend(r[1:])

out = data_dir / "dataset.csv"
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(header)
    w.writerows(rows_all)
print(f"Merged {len(rows_all)} rows -> {out}")
EOF

python3 defender_ml/train.py
```
This outputs **`defender_ml/model.joblib`** and **`defender_ml/metrics.json`**.

---

### Step 2: Run the Benchmarks & Zero-Shot Evaluation Scripts

Run all evaluation scripts in order on CachyOS:

```bash
# 1. Unified multi-vector suite (Heuristic, ML, In-Kernel VFS, FIM, Disk I/O, Cooled 3000-op overhead)
#    Saves all measured results -> report/assets/experiment_data.json
sudo python3 evaluation/master_experiment.py

# 2. Per-vector zero-shot comparison across V1..V7 (Heuristic vs ML detection & probability)
sudo python3 evaluation/eval_evasion_zero_shot.py

# 3. Standalone syscall latency & RSS suite -> evaluation/results/overhead_report.json
sudo python3 evaluation/overhead_suite.py --iterations 3000

# 4. Standalone quick MTTI/FPR check (optional)
sudo python3 evaluation/benchmark.py --runs 5
```

Verify `report/assets/experiment_data.json` updated cleanly with your CachyOS kernel (`uname -r`), fresh trial numbers, and `ml_metrics`.

---

### Step 3: Generate Standalone Charts (`fig1`–`fig4`) & Compile the PDF Report

Once `report/assets/experiment_data.json` is updated:

```bash
# Generate the 4 standalone Habib-purple SVG charts in report/assets/:
#   fig1_mtti_exfil.svg, fig2_evasion_matrix.svg,
#   fig3_classifier_overhead.svg, fig4_system_resilience.svg
python3 report/generate_charts.py

# Generate report/report.html and compile report/MemGuard_OS_Report.pdf:
python3 report/build_report.py          # CachyOS / Native Linux (uses python-weasyprint)
# .venv/bin/python report/build_report.py   # Ubuntu / WSL2 if using .venv
```

> **Note on Report Numbers:** Both `generate_charts.py` and `build_report.py` read live metrics directly from `report/assets/experiment_data.json`. Because `build_report.py` also contains narrative prose/tables summarizing the earlier 5-vector (80-trial) baseline and marking V6/V7 as wired extensions, review any updated CachyOS 7-vector percentages printed by `master_experiment.py` and `eval_evasion_zero_shot.py` if you want those tables updated to reflect 28 trials/mode.

---

### Step 4: Commit CachyOS Data & Updated Report
```bash
sudo chown -R $USER:$USER defender_ml/ evaluation/results/ report/
git status
git add defender_ml/data/ defender_ml/model.joblib defender_ml/metrics.json \
        evaluation/results/ report/assets/experiment_data.json \
        report/assets/fig*.svg report/report.html report/MemGuard_OS_Report.pdf
git commit -m "Add CachyOS real desktop data, 7-vector benchmark results, and updated PDF report"
git push origin main
```

---

## 7. Troubleshooting

| Issue | Fix |
| :--- | :--- |
| `WARNING: bpftool not found for kernel ...-microsoft-standard-WSL2` | Run `rm -f ebpf/vmlinux.h && make BPFTOOL=$(find /usr/lib/linux-tools -name bpftool 2>/dev/null \| head -n 1)` |
| `OSError: [Errno 98] Address already in use` on port `8080` | Pass `--port 8081` or stop old processes: `sudo pkill -f "ui/server.py\|ebpf/build/sensor"` |
| `Permission denied` on `logs/`, `logs/traces/`, or `defender_ml/data/` | Clear or reclaim root-owned outputs: `sudo chown -R $USER:$USER logs/ defender_ml/` |
| `Frontend bundle not built yet` (HTTP 503) | Build the UI bundle: `cd ui/frontend && npm install && npm run build && cd ../..` |
| `ModuleNotFoundError: No module named 'weasyprint'` | On CachyOS: `sudo pacman -S python-weasyprint pango cairo`; on WSL2/Ubuntu: install in `.venv` (`.venv/bin/pip install weasyprint`) |
| Git shows unexpected line-ending diffs on WSL2 | Keep the repo inside WSL native Linux home (`~/OS_Project_main`), never `/mnt/c/...` |
