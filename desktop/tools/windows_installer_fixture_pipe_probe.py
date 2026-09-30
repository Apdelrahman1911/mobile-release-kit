"""Three closed Windows byte-stream probes for the retained-shell original owner.

Not a configurable process tool and never a substitute for installer evidence.
Only the pinned hosted Python invokes this file with -I -S -B.
"""
from __future__ import annotations

import os
import sys


def write_all(fd: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        count = os.write(fd, remaining)
        if count <= 0:
            raise OSError("Original probe write did not advance")
        remaining = remaining[count:]


def main() -> int:
    if sys.platform != "win32" or sys.version.split()[0] != "3.14.7":
        return 2
    if len(sys.argv) != 2 or sys.argv[1] not in ("balanced", "overflow", "writer-fault"):
        return 2
    # os.write on the actual redirected originals: no newline, buffering, thread,
    # child, file or synthetic completion. More than the default pipe capacity.
    if sys.argv[1] == "overflow":
        for _ in range(40):
            write_all(1, b"O" * 2048)
    else:
        for _ in range(15):
            write_all(1, b"O" * 2048)
            write_all(2, b"E" * 2048)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
