# MemGuard — Fileless In-Memory Malware & Autonomous eBPF Defense

**Course:** Operating Systems (Fall 2026)  
**Instructors:** B. Wajid, Z. Iqbal, S. Tahir, A. S. Shaikh  
**Team Members:** Muhammad Murtaza, Syed Faraz, Ammar Baig, Sheikh Humayun  

> **Research Question:**  
> *"Can an autonomous eBPF-driven defender reliably detect and intercept fileless in-memory execution (`memfd_create` + `fexecve`) and anonymous process masquerading without disk artifacts, and what is its classification overhead compared to traditional file-integrity monitoring?"*

---

## 1. Plain-English Overview (Start Here If You Know Nothing About the Project)

### What Problem Does This Project Solve?
Normally, when malware infects a Linux computer, it saves an executable file onto the hard drive (often in `/tmp` or `/dev/shm`) and runs it. Traditional antivirus tools and **File Integrity Monitors (FIM)** watch the hard drive for new or modified files, inspect them, and block them.

**Fileless malware** skips the hard drive completely. Using built-in Linux kernel features, a program can:
1. Ask Linux to create an **invisible file that lives only in RAM** (`memfd_create`).
2. Decrypt or unpack a hidden program straight into that RAM buffer.
3. Seal the memory buffer (`fcntl(F_ADD_SEALS)`) so the kernel allows executing it.
4. Run the program directly from RAM (`execveat` with `AT_EMPTY_PATH`, which `fexecve` calls under the hood).
5. Rename itself in `/proc` using `prctl(PR_SET_NAME)` to look like a harmless Linux kernel background thread (for example, `[kworker/u8:2]`).

Because **0 bytes ever hit the physical disk**, disk scanners and `inotify`-based FIM tools see nothing.

### How MemGuard Defends Against It
Instead of watching the hard drive, **MemGuard** puts lightweight sensors directly inside the **Linux Kernel** using **eBPF (Extended Berkeley Packet Filter)**:

1. **Kernel Tripwire (`ebpf/`):** 5 eBPF tracepoints watch `memfd_create`, `execveat`, `execve`, and `prctl` system calls across the OS. It is **PID-namespace aware** (`bpf_get_ns_current_pid_tgid()`), so it works accurately both on native Linux and inside WSL2/containers.
2. **Telemetry Enrichment (`defender_heuristic/telemetry.py`):** When a suspicious syscall fires, Python reads `/proc/<pid>/` to gather the executable link (`/memfd:...`), up to 5 levels of parent process ancestry, and **Shannon entropy** of the binary bytes.
3. **Dual-Engine Classification (`defender_heuristic/` + `defender_ml/`):**
   * **Heuristic Engine:** Rule-based weighted scoring (`rules.yaml`) that catches fileless execution and process masquerading while allowlisting legitimate apps that use `memfd` (such as PipeWire, Wayland, Chrome/Firefox, `runc`, and `systemd`).
   * **ML Engine:** A trained `scikit-learn` classifier (Random Forest by default, benchmarked against Decision Tree, Logistic Regression, and KNN) using 11 extracted features per event.
   * **Shadow Scoring (Zero Race Conditions):** Only **one** eBPF sensor runs at a time. Both engines score the exact same event for live side-by-side comparison, while only the currently active engine triggers process freezing.
4. **Millisecond Containment (`mitigator.py`):** Confirmed threats are frozen immediately using `pidfd_send_signal(..., SIGSTOP)` so they can be inspected, resumed (`SIGCONT`), or terminated (`SIGKILL`).
5. **Live Web Console (`ui/`):** A React + Vite dashboard streamed via Server-Sent Events (SSE) with a real-time syscall ledger, forensic inspector, quarantine controls, MTTI latency chart, and built-in Verification Lab.

### Architecture Flow

```text
+-----------------------------------------------------------------------+
| RED TEAM (Controlled Simulation in red_team/)                         |
| 1. pack_payload.py XOR-scrambles payload ELF (0x5A) into C header     |
| 2. loader.c decrypts bytes in RAM -> memfd_create("jit_cache")        |
| 3. fcntl(F_ADD_SEALS) locks RAM fd -> syscall(SYS_execveat, fd, "")   |
| 4. payload.c calls prctl(PR_SET_NAME, "[kworker/u8:2]")               |
+-----------------------------------+-----------------------------------+
                                    |  (Caught at Linux Syscall Boundary)
                                    v
+-----------------------------------------------------------------------+
| BLUE TEAM: eBPF Kernel Sensor (ebpf/probes.bpf.c + ebpf/sensor.c)     |
| - Hooks memfd_create (enter/exit), execveat, execve, prctl            |
| - Resolves PID in defender's namespace via bpf_get_ns_current_pid_tgid|
| - Tracks memfd descriptors in BPF hash maps -> streams via ringbuf    |
+-----------------------------------+-----------------------------------+
                                    |  JSON lines over stdout pipe
                                    v
+-----------------------------------------------------------------------+
| TELEMETRY & DUAL-ENGINE CLASSIFIER (defender_heuristic/ + defender_ml)|
| - telemetry.py: /proc/<pid>/exe, 5-level ancestry, Shannon entropy    |
| - HeuristicClassifier (rules.yaml) + MLClassifier (model.joblib)      |
| - Active engine decides: ALLOW / ALERT / FREEZE                       |
+-----------------------------------+-----------------------------------+
                                    |  pidfd_open + syscall 424 (SIGSTOP)
                                    v
+-----------------------------------------------------------------------+
| CONTAINMENT & WEB CONSOLE (ui/server.py + ui/frontend/)               |
| - Freezes offending process in milliseconds (measures MTTI)           |
| - Streams live events via SSE to MemGuard dashboard (Resume / Kill)   |
+-----------------------------------------------------------------------+
```

---

## 2. Complete Repository Layout (File-by-File Guide)

```text
OS_Project/
├── Makefile                        # Builds red_team loader + eBPF vmlinux.h, probes, and sensor
├── requirements.txt                # Python dependencies (pyyaml, scikit-learn, joblib, numpy)
├── proposal.pdf                    # Project proposal, research question, and evaluation metrics
├── README.md                       # Complete setup, architecture, usage, and ML guide
├── red_team/                       # Safe, controlled fileless attack simulator
│   ├── payload.c                   # Target payload: spoofs comm via prctl() & prints heartbeats
│   ├── pack_payload.py             # XOR-obfuscates compiled payload ELF into payload_bytes.h
│   └── loader.c                    # In-memory loader (memfd_create + seals + execveat) & --benign-memfd
├── ebpf/                           # Linux kernel eBPF probes & user-space ringbuf reader
│   ├── events.h                    # Shared sensor_event & pidns_cfg structs (kernel <-> user)
│   ├── probes.bpf.c                # 5 kernel syscall tracepoints + namespace-aware PID tracking
│   └── sensor.c                    # libbpf loader: configures ns_config, attaches probes, prints JSON
├── defender_heuristic/             # Rule-based defender, telemetry collector, & SIGSTOP mitigator
│   ├── rules.yaml                  # Heuristic weights, thresholds, kthread prefixes, & allowlist
│   ├── telemetry.py                # Reads /proc/<pid> ancestry, exe symlink, & Shannon entropy
│   ├── classifier.py               # HeuristicClassifier: stateful per-PID rule scoring engine
│   ├── mitigator.py                # pidfd_send_signal wrapper for SIGSTOP / SIGCONT / SIGKILL + MTTI
│   └── main.py                     # Main defender daemon (--engine heuristic|ml, shadow scoring, JSONL log)
├── defender_ml/                    # Machine learning dataset, training, & inference pipeline
│   ├── __init__.py                 # Package marker
│   ├── features.py                 # Converts live events or JSONL logs into 11 numeric ML features
│   ├── collect_dataset.py          # Captures labeled CSV datasets (live, collect-attacks, import-log, bootstrap)
│   ├── train.py                    # Benchmarks RF, Decision Tree, LogReg, & KNN; saves model + metrics
│   ├── classifier.py               # MLClassifier: loads model.joblib and matches Verdict interface
│   ├── data/                       # Captured CSV telemetry datasets (e.g., wsl_benign.csv, wsl_attacks.csv)
│   ├── model.joblib                # Trained scikit-learn model bundle (generated by train.py)
│   └── metrics.json                # 4-model offline accuracy/latency report & feature importances
├── evaluation/                     # Verification & benchmarking scripts
│   ├── verify_disk_io.py           # Samples /proc/<pid>/io to prove 0 physical disk bytes written
│   ├── fim_baseline.py             # Runs Linux inotify FIM during attack to prove disk-FIM blindness
│   └── benchmark.py                # Automated multi-run MTTI, Detection Rate, FPR, & RAM benchmark
└── ui/                             # MemGuard Web Dashboard (Python API/SSE + React/Vite frontend)
    ├── server.py                   # HTTP + SSE API server, process control, & Verification Lab runner
    └── frontend/                   # React 19 + Vite 6 console UI
        ├── index.html              # HTML entry point
        ├── package.json            # Frontend dependencies & npm scripts
        ├── vite.config.js          # Vite dev proxy (/api -> 127.0.0.1:8080)
        └── src/
            ├── App.jsx             # Main console state, SSE stream, engine switcher, & syscall ledger
            ├── main.jsx            # React mount entry
            ├── components/
            │   ├── DemoLab.jsx             # 4-scenario Verification Lab controls & raw trace viewer
            │   ├── InspectorPane.jsx       # Selected PID forensics + Quarantine Resume/Kill controls
            │   ├── MttiStrip.jsx           # Interactive SVG interception latency (MTTI) chart
            │   └── MlComparisonPanel.jsx   # 4-model comparison table & live Heuristic-vs-ML metrics
            └── styles/
                ├── tokens.css      # Dusk color, spacing, and typography CSS variables
                ├── base.css        # Base resets and font rules
                └── app.css         # Component and responsive layout styles
```

---

## 3. System Requirements & Pre-Check

> **Important:** MemGuard monitors **Linux kernel syscalls**. It **cannot** be built or run directly in Windows PowerShell/CMD—you must use either **Native Linux** (e.g., Ubuntu, Debian, Arch/CachyOS) or **Windows + WSL2 (Ubuntu)**.

### Kernel & Tooling Requirements
* Linux kernel with **eBPF** and **BTF** enabled (`/sys/kernel/btf/vmlinux` must exist)
* **`sudo` / root privileges** (required to load eBPF kernel programs and send `pidfd_send_signal`)
* `gcc`, `clang`, `llvm`, `bpftool`, `libbpf`, `libelf`, `zlib`
* Python **3.10+** (`pyyaml`, `scikit-learn`, `joblib`, `numpy`)
* Node.js **18+** & `npm` (to build the React web dashboard)

### Step 0: Check Kernel BTF Support
Open your Linux or WSL2 terminal and run:
```bash
uname -r
ls -l /sys/kernel/btf/vmlinux
```
* **If `/sys/kernel/btf/vmlinux` prints a file size (several MB):** Your kernel supports CO-RE eBPF. Continue to Section 4.
* **If it says `No such file or directory`:** That kernel lacks `CONFIG_DEBUG_INFO_BTF=y`. Use a standard Linux VM (Ubuntu 22.04/24.04) or update your WSL2 kernel (`wsl --update` in Windows).

---

## 4. Complete Setup & Build Instructions

Follow **either** the **Native Linux** path or the **Windows + WSL2** path below.

### Option A: Native Linux (Arch / CachyOS)

1. **Clone the repository and install packages:**
   ```bash
   git clone https://github.com/faraz18001/Opreating-Systems-Projec.git
   cd Opreating-Systems-Projec

   sudo pacman -S --needed base-devel clang llvm bpf libbpf \
       python python-yaml python-scikit-learn python-joblib python-numpy nodejs npm
   ```

2. **Compile the red-team binaries and eBPF sensor:**
   ```bash
   make clean && make
   ```
   This creates `red_team/build/loader`, `ebpf/vmlinux.h`, `ebpf/build/probes.bpf.o`, and `ebpf/build/sensor`.

3. **Build the React web UI:**
   ```bash
   cd ui/frontend
   npm install
   npm run build
   cd ../..
   ```

---

### Option B: Native Linux (Ubuntu / Debian)

1. **Clone the repository and install packages:**
   ```bash
   git clone https://github.com/faraz18001/Opreating-Systems-Projec.git
   cd Opreating-Systems-Projec

   sudo apt update
   sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
       python3 python3-pip python3-yaml python3-sklearn python3-joblib python3-numpy \
       linux-tools-common linux-tools-$(uname -r) nodejs npm
   ```

2. **Compile C/eBPF binaries and build the UI:**
   ```bash
   make clean && make
   cd ui/frontend && npm install && npm run build && cd ../..
   ```

---

### Option C: Windows + WSL2 (Ubuntu)

> **Important WSL2 Tip:** Clone inside WSL's native Linux filesystem (`~/OS_Project_main`), **not** inside `/mnt/c/...` or OneDrive. Opening Windows folders from WSL causes `CRLF`/`LF` fake Git diffs, permission issues, and slow `npm`/`make` builds.

1. **Clone directly inside WSL2:**
   ```bash
   cd ~
   git clone https://github.com/faraz18001/Opreating-Systems-Projec.git OS_Project_main
   cd ~/OS_Project_main
   ```

2. **Install Ubuntu dependencies:**
   ```bash
   sudo apt update
   sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
       python3 python3-pip python3-yaml python3-sklearn python3-joblib python3-numpy \
       linux-tools-common linux-tools-generic nodejs npm
   ```

3. **Compile C & eBPF binaries (WSL2 `bpftool` fix):**  
   Ubuntu's default `bpftool` wrapper fails on `-microsoft-standard-WSL2` kernel names. Pass the real `bpftool` binary path directly to `make`:
   ```bash
   rm -f ebpf/vmlinux.h
   make BPFTOOL=$(find /usr/lib/linux-tools -name bpftool 2>/dev/null | head -n 1)
   ```
   Verify that `red_team/build/loader`, `ebpf/build/probes.bpf.o`, and `ebpf/build/sensor` all exist without errors.

4. **Build the React frontend:**
   ```bash
   cd ui/frontend
   npm install
   npm run build
   cd ../..
   ```

---

## 5. How to Run & Demo Everything

### Method 1: MemGuard Live Web Console (Recommended)

1. **Start the backend server with `sudo`:**
   ```bash
   # Native Linux (default port 8080):
   sudo python3 ui/server.py --auto-start

   # WSL2 (use --port 8081 if port 8080 is already used by another Windows/WSL app):
   sudo python3 ui/server.py --port 8081 --auto-start
   ```
   *(Optional: pass `--engine ml` to start directly with the ML classifier active, provided `defender_ml/model.joblib` has been trained.)*

2. **Open the dashboard in your browser:**
   * Native Linux: `http://127.0.0.1:8080`
   * WSL2: `http://127.0.0.1:8081`

3. **Run the 2-Phase Live Demo inside the "Verification lab" panel:**
   * **Phase 1 — Active Protection (`Sensor active` ON, `Dry-run` OFF):**
     1. Click **`Run benign`** → creates an unexecuted `memfd` buffer and logs **`Allowed`**.
     2. Click **`Launch attack`** **2–3 times** (wait ~1 sec each) → executes the fileless XOR-decrypted payload disguised as `[kworker/u8:2]`. Watch it appear as **`Frozen`**, populate **Mean time to intercept (MTTI)**, and show up in **Quarantined processes** (test **Inspect**, **Resume**, and **Kill**).
     3. Switch between **`Heuristic engine`** and **`ML engine`** tabs at the top to compare the 4-model ML benchmark, feature importances, live agreement rate, and per-event inference latency.
   * **Phase 2 — Flip `Dry-run` ON (top-right toggle) before clicking the next two buttons:**
     4. Click **`Verify disk I/O`** → proves `0 bytes` written to physical disk (`Pass (0 B disk I/O)`).
     5. Click **`Run FIM baseline`** → runs traditional `inotify` on `/tmp`, `/dev/shm`, and `red_team/build` to prove disk FIM detects **`0`** alerts.  
     *(Why enable Dry-run? Both scripts run `loader` and wait for it to finish; with active `SIGSTOP` ON, MemGuard freezes the test loader mid-run and the check times out cleanly with a reminder to toggle Dry-run ON.)*

---

### Method 2: CLI Mode (Terminal Only)

*(Stop `ui/server.py` with `Ctrl+C` first so two defenders do not compete.)*

* **Run the defender in terminal:**
  ```bash
  # Heuristic mode (runs ML in shadow mode if model.joblib exists):
  sudo python3 defender_heuristic/main.py --show-all

  # ML active mitigation mode:
  sudo python3 defender_heuristic/main.py --engine ml --show-all

  # Dry-run logging only (no SIGSTOP):
  sudo python3 defender_heuristic/main.py --dry-run --show-all
  ```

* **Trigger the red-team loader manually in a second terminal:**
  ```bash
  ./red_team/build/loader --ticks 10                         # Full fileless attack
  ./red_team/build/loader --ticks 6 --no-masquerade          # Without prctl rename
  ./red_team/build/loader --benign-memfd                     # Benign shared-memory buffer
  ```

* **Run the automated evaluation benchmarks:**
  ```bash
  # Multi-run Detection/Freeze Rate, False Positive Rate, MTTI, & RSS RAM:
  sudo python3 evaluation/benchmark.py --runs 5

  # Standalone 0-byte physical disk I/O proof (no sudo needed):
  python3 evaluation/verify_disk_io.py

  # Standalone inotify FIM blindness proof (no sudo needed):
  python3 evaluation/fim_baseline.py
  ```

---

## 6. ML Pipeline Guide (`defender_ml/`): Collecting, Merging & Training

MemGuard's ML classifier does **not** use mismatched public datasets. Instead, it extracts **11 kernel/telemetry features** (`defender_ml/features.py`) directly from your own Linux eBPF events:

> `is_memfd_create`, `is_execveat`, `is_execve_fd`, `is_prctl_rename`, `tracked_memfd`, `has_empty_path_flag`, `has_memfd_exe`, `has_proc_fd_path`, `is_kthread_masquerade`, `is_allowlisted`, `entropy`

Thresholds in `MLClassifier`: `prob >= 0.75` → **`FREEZE`**, `prob >= 0.45` → **`ALERT`**, `< 0.45` → **`ALLOW`**.

### Why Collect on Both WSL2 and Native Desktop Linux (CachyOS)?
* **WSL2** captures container (`runc`), `systemd`, and controlled loader/benign-buffer behavior, **but has no native Linux GUI/audio apps**.
* **CachyOS** captures real desktop `memfd` consumers (**Firefox, Chromium, PipeWire, Wayland, VS Code**) alongside native-kernel attack runs.
* Combining both (at a ~60% benign / ~40% malicious ratio) prevents overfitting to one machine and evaluates desktop safety honestly.

### Step-by-Step Real Data Collection & Training

*(Always stop `ui/server.py` before collecting so nothing freezes processes mid-capture.)*

1. **On WSL2 — Collect Benign Data (`wsl_benign.csv`):**
   * *Terminal 1 (4-minute live capture):*
     ```bash
     sudo python3 defender_ml/collect_dataset.py --mode live --label 0 --duration 240 \
         --output defender_ml/data/wsl_benign.csv --reset
     ```
   * *Terminal 2 (run **while Terminal 1 is still listening**):*
     ```bash
     for i in $(seq 1 60); do
         ./red_team/build/loader --benign-memfd --memfd-name "audio_buf_$i"
     done
     for i in $(seq 1 15); do
         docker run --rm alpine true 2>/dev/null || true
     done
     ```

2. **On WSL2 — Collect Varied Attack Data (`wsl_attacks.csv`):**  
   `--mode collect-attacks` spawns 5 varied attack profiles per round (default `[kworker/u8:2]`, `--no-masquerade`, rotating kthread names, rotating `memfd` names, and spoofed `--argv0` names) and tracks **only its own spawned PIDs** so background `runc`/`systemd` traffic is never mislabeled:
   ```bash
   sudo python3 defender_ml/collect_dataset.py --mode collect-attacks \
       --output defender_ml/data/wsl_attacks.csv --rounds 15 --reset
   sudo chown -R $USER:$USER defender_ml/data/
   ```

3. **On Native Desktop Linux (CachyOS) — Collect Desktop Benign & Attack Data:**
   * Run a 4-minute benign capture while actively browsing in Firefox/Chromium, playing PipeWire audio, opening VS Code/Wayland windows, and running benign `memfd` buffers:
     ```bash
     sudo python3 defender_ml/collect_dataset.py --mode live --label 0 --duration 240 \
         --output defender_ml/data/cachyos_benign.csv --reset
     ```
   * Collect 10 rounds of native-kernel attacks:
     ```bash
     sudo python3 defender_ml/collect_dataset.py --mode collect-attacks \
         --output defender_ml/data/cachyos_attacks.csv --rounds 10 --reset
     sudo chown -R $USER:$USER defender_ml/data/
     ```
   * Commit and push `cachyos_benign.csv` and `cachyos_attacks.csv` to `main`.

4. **Merge All Real CSVs (~60/40 Balanced) & Train All 4 Models:**
   ```bash
   git pull origin main

   python3 - <<'EOF'
   import csv, random
   from pathlib import Path

   data_dir = Path("defender_ml/data")
   rng = random.Random(42)

   def read_rows(name):
       p = data_dir / name
       if not p.exists():
           return [], []
       with open(p, newline="", encoding="utf-8") as f:
           r = list(csv.reader(f))
       return r[0], r[1:]

   header, wsl_b = read_rows("wsl_benign.csv")
   _, wsl_a = read_rows("wsl_attacks.csv")
   _, cac_b = read_rows("cachyos_benign.csv")
   _, cac_a = read_rows("cachyos_attacks.csv")

   # Cap CachyOS benign at 220 evenly sampled rows to avoid severe class imbalance
   if len(cac_b) > 220:
       cac_b = rng.sample(cac_b, 220)

   merged = wsl_b + cac_b + wsl_a + cac_a
   benign = sum(1 for row in merged if row[-3] == "0")
   malicious = sum(1 for row in merged if row[-3] == "1")

   out = data_dir / "dataset.csv"
   with open(out, "w", newline="", encoding="utf-8") as f:
       w = csv.writer(f)
       w.writerow(header)
       w.writerows(merged)

   print(f"Merged -> {out}: {len(merged)} rows "
         f"(benign={benign} [{benign/len(merged)*100:.1f}%], "
         f"malicious={malicious} [{malicious/len(merged)*100:.1f}%])")
   EOF

   python3 defender_ml/train.py
   ```
   `train.py` uses `GroupShuffleSplit` (grouped by PID session so events from the same process never leak across train and test sets), benchmarks **Random Forest**, **Decision Tree**, **Logistic Regression**, and **KNN (`k=5`)**, and saves `defender_ml/model.joblib` and `defender_ml/metrics.json`.  
   *(To switch the live model from Random Forest to the faster Decision Tree: `python3 defender_ml/train.py --model decision_tree`.)*

5. **Alternative Quick Modes (`collect_dataset.py`):**
   * `--mode import-log --log logs/defender_events.jsonl` — converts previously captured JSONL logs into labeled CSV rows.
   * `--mode bootstrap --samples 400 --reset` — generates a deterministic offline baseline for rapid testing without waiting for live captures.

---

## 7. Troubleshooting & Common Fixes

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `WARNING: bpftool not found for kernel ...-microsoft-standard-WSL2` during `make` | Ubuntu's `bpftool` wrapper rejects WSL2's custom kernel string | Run `rm -f ebpf/vmlinux.h && make BPFTOOL=$(find /usr/lib/linux-tools -name bpftool 2>/dev/null \| head -n 1)` |
| `OSError: [Errno 98] Address already in use` starting `ui/server.py` | Port `8080` (or previous SSE connection) is still occupied | Run `sudo pkill -9 -f "ui/server.py\|defender_heuristic/main.py\|ebpf/build/sensor" \|\| true` or pass `--port 8081` |
| `Permission denied` on `logs/defender_events.jsonl` or `defender_ml/data/*.csv` | Files created under `sudo` are owned by `root` | Run `sudo rm -f logs/defender_events.jsonl` or `sudo chown -R $USER:$USER defender_ml/data/` |
| `Frontend bundle not built yet` (HTTP 503) in browser | `ui/frontend/dist/` is gitignored and not built yet | Run `cd ui/frontend && npm install && npm run build && cd ../..` |
| `Verify disk I/O` or `Run FIM baseline` times out in the UI | Active `SIGSTOP` froze the test loader mid-run | Flip the **`Dry-run`** switch **ON** in the top bar before running those two checks |
| `Freeze failed` (`No such process`) on short-lived helpers like `runc` | Short-lived process exited before Python finished reading `/proc` and sending `SIGSTOP` | Expected for sub-10ms helpers; `runc`, `systemd`, and `systemd-executor` are allowlisted in `defender_heuristic/rules.yaml` |
| VS Code shows 30 files as Modified (`M`) when opening `/mnt/c/...` from WSL | Windows `CRLF` vs. Linux `LF` line endings and file permissions | Clone and work inside WSL native home (`~/OS_Project_main`) instead of `/mnt/c/...` |

---

## 8. Current Status & Known Limitations

### Verified & Working
* **Red Team + eBPF + Heuristic Containment:** End-to-end `memfd_create` + sealed `execveat` + `prctl` masquerading simulation, 5 kernel tracepoints, `/proc` ancestry/entropy telemetry, and `pidfd_send_signal(SIGSTOP)` freeze + quarantine controls verified live on both native Linux and WSL2 (`6.6.87.2-microsoft-standard-WSL2`).
* **ML Pipeline & Dual-Engine UI:** `defender_ml/` feature extraction, collector (`live`, `collect-attacks`, `import-log`, `bootstrap`), 4-model trainer, shadow scoring in `defender_heuristic/main.py`, and the **ML engine** React console tab are built and verified.
* **Initial WSL2 Datasets Collected:** Real `live_ebpf` captures collected on WSL2 (`wsl_benign.csv`: 112 benign rows across 112 PIDs; `wsl_attacks.csv`: 135 attack rows across 75 PIDs).

### Pending & Known Engineering Limitations
* **Final Multi-Host Merge:** Pending merge with native desktop CachyOS captures (`cachyos_benign.csv`, `cachyos_attacks.csv`) to replace the temporary bootstrap-backed `model.joblib` with a 100% real-telemetry bundle.
* **User-Space Containment Window:** Because eBPF tracepoints stream events to user-space Python before `pidfd_send_signal(SIGSTOP)` executes, there is a small (~3–6 ms) window where the payload runs before freezing (unlike synchronous in-kernel blocking via BPF LSM `bprm_check_security`).
* **Inherited-FD `fork()` Edge Case:** `memfd_fds` in `ebpf/probes.bpf.c` keys by `{tgid, fd}` and does not clean entries on `close()`/`exit()`. If a parent calls `memfd_create()`, forks a child, and the child executes the inherited descriptor via `execveat`, `tracked_memfd` reports `false` (scoring `45` = `ALERT` heuristically via `AT_EMPTY_PATH` instead of `70` = `FREEZE`).
* **Heavy-Load Benchmarking:** `evaluation/benchmark.py` currently measures idle MTTI, freeze rate, synthetic FPR, and Python RSS RAM; extending it to measure CPU % overhead and MTTI under heavy CPU-bound contention (e.g., local AI inference / `stress-ng`) vs. `inotify` FIM is recommended for final report plots.
