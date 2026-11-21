#!/usr/bin/env python3
import ctypes
import os
import select
import struct
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOADER = PROJECT_ROOT / "red_team" / "build" / "loader"

IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
WATCH_MASK = IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def main() -> int:
    if not LOADER.exists():
        sys.stderr.write("error: loader binary not found. Run 'make' first.\n")
        return 1

    in_fd = libc.inotify_init1(os.O_NONBLOCK)
    if in_fd < 0:
        sys.stderr.write("error: inotify_init1 failed\n")
        return 1

    watch_dirs = ["/tmp", "/dev/shm", str(PROJECT_ROOT / "red_team" / "build")]
    wd_map = {}
    for d in watch_dirs:
        if os.path.isdir(d):
            wd = libc.inotify_add_watch(in_fd, d.encode(), WATCH_MASK)
            if wd >= 0:
                wd_map[wd] = d

    print(f"Traditional FIM (inotify) watching: {', '.join(wd_map.values())}")
    start = time.monotonic()
    proc = subprocess.Popen(
        [str(LOADER), "--ticks", "1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    fim_events = []
    while proc.poll() is None:
        r, _, _ = select.select([in_fd], [], [], 0.05)
        if r:
            buf = os.read(in_fd, 4096)
            offset = 0
            while offset + 16 <= len(buf):
                wd, mask, _cookie, name_len = struct.unpack_from("iIII", buf, offset)
                offset += 16
                raw_name = buf[offset:offset + name_len].rstrip(b"\x00").decode("utf-8", errors="replace")
                offset += name_len
                fim_events.append((wd_map.get(wd, "?"), raw_name, mask))

    out, _ = proc.communicate()
    elapsed_ms = (time.monotonic() - start) * 1000.0
    os.close(in_fd)

    if out:
        print(out.strip())

    malware_hits = [e for e in fim_events if "jit_cache" in e[1] or "payload" in e[1] or "kworker" in e[1]]
    print(f"\nTraditional FIM finished in {elapsed_ms:.1f} ms")
    print(f"  total unrelated fs events : {len(fim_events)}")
    print(f"  fileless payload detected : {len(malware_hits)} (traditional FIM is blind to memfd)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
