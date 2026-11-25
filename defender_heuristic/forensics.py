import hashlib
import json
import os
import re
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE_DIR = PROJECT_ROOT / "evidence"

IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KTHREAD_RE = re.compile(rb"\[(?:kworker|ksoftirqd|migration|rcu_|kswapd|watchdog)[^\x00\r\n]{0,24}\]")
TOKEN_RE = re.compile(rb"(?:EXFIL|SECRET|TOKEN|OS_FALL\d+)[A-Za-z0-9_=\-:/.\[\]]{2,48}")

ELF_TYPES = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
ELF_MACHINES = {62: "x86_64", 183: "aarch64", 3: "x86"}


def parse_elf64_header(data: bytes) -> Dict[str, object]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {"valid_elf": False}

    ei_class = data[4]
    if ei_class != 2:
        return {"valid_elf": True, "bits": 32}

    e_type, e_machine, _e_ver, e_entry, _e_phoff, _e_shoff, _e_flags, _ehsize, _phent, e_phnum, _shent, e_shnum = (
        struct.unpack_from("<HHIQQQIHHHHH", data, 16)
    )
    return {
        "valid_elf": True,
        "bits": 64,
        "type": ELF_TYPES.get(e_type, str(e_type)),
        "arch": ELF_MACHINES.get(e_machine, str(e_machine)),
        "entry": hex(e_entry),
        "segments": e_phnum,
        "sections": e_shnum,
    }


def extract_iocs(data: bytes) -> List[str]:
    found: List[str] = []
    seen = set()

    for regex in (IPV4_RE, KTHREAD_RE, TOKEN_RE):
        for match in regex.findall(data):
            text = match.decode("ascii", errors="ignore").strip()
            if not text or text in seen:
                continue
            if text in ("0.0.0.0", "255.255.255.255"):
                continue
            seen.add(text)
            found.append(text)
            if len(found) >= 8:
                return found
    return found


def capture_ram_forensics(
    pid: int,
    fd: int = -1,
    evidence_dir: Path = DEFAULT_EVIDENCE_DIR,
    max_bytes: int = 2 * 1024 * 1024,
) -> Optional[dict]:
    sources = [f"/proc/{pid}/exe"]
    if fd >= 0:
        sources.append(f"/proc/{pid}/fd/{fd}")

    raw = b""
    source_used = ""
    for src in sources:
        try:
            with open(src, "rb") as f:
                raw = f.read(max_bytes)
            if raw:
                source_used = src
                break
        except OSError:
            continue

    if not raw:
        return None

    sha256 = hashlib.sha256(raw).hexdigest()
    elf_info = parse_elf64_header(raw)
    iocs = extract_iocs(raw)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    bundle_dir = evidence_dir / f"pid_{pid}_{stamp}"
    saved_path = None
    try:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        elf_path = bundle_dir / "payload.elf"
        with open(elf_path, "wb") as out:
            out.write(raw)
        os.chmod(elf_path, 0o600)

        report = {
            "pid": pid,
            "captured_at": stamp,
            "source": source_used,
            "size_bytes": len(raw),
            "sha256": sha256,
            "elf": elf_info,
            "iocs": iocs,
        }
        (bundle_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        saved_path = str(bundle_dir.relative_to(PROJECT_ROOT))
    except OSError:
        saved_path = None

    return {
        "size_bytes": len(raw),
        "sha256": sha256,
        "elf": elf_info,
        "iocs": iocs,
        "bundle": saved_path,
    }
