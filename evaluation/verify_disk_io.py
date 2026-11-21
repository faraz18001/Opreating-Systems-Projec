#!/usr/bin/env python3
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOADER = PROJECT_ROOT / "red_team" / "build" / "loader"


def read_proc_io(pid: int) -> dict:
    stats = {}
    try:
        with open(f"/proc/{pid}/io", "r", encoding="utf-8") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    stats[k.strip()] = int(v.strip())
    except OSError:
        pass
    return stats


def main() -> int:
    if not LOADER.exists():
        sys.stderr.write("error: loader binary not found. Run 'make' first.\n")
        return 1

    proc = subprocess.Popen(
        [str(LOADER), "--ticks", "2"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    last_io = {}
    while proc.poll() is None:
        sample = read_proc_io(proc.pid)
        if sample:
            last_io = sample
        time.sleep(0.05)

    out, err = proc.communicate()
    if out:
        print(out.strip())
    if err:
        sys.stderr.write(err)

    write_bytes = last_io.get("write_bytes", -1)
    read_bytes = last_io.get("read_bytes", -1)
    wchar = last_io.get("wchar", -1)

    print(f"\nDisk I/O verification for pid={proc.pid}:")
    print(f"  physical write_bytes : {write_bytes} bytes")
    print(f"  physical read_bytes  : {read_bytes} bytes")
    print(f"  logical wchar (RAM)  : {wchar} bytes")

    if write_bytes == 0:
        print("Result: PASS (0 bytes written to physical disk)")
        return 0

    print("Result: FAIL (unexpected disk writes or /proc/<pid>/io unreadable)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
