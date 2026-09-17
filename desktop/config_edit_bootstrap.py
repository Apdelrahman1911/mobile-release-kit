"""Dedicated fixed main-thread edit bootstrap. No project imports or fallback."""
import os
import sys
import time


def main() -> int:
    started = time.monotonic()
    if (len(sys.argv) != 2 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or not os.path.isabs(sys.argv[1])
            or sys.version_info < (3, 11) or not (sys.platform.startswith("linux") or sys.platform == "darwin")):
        return 78
    sys.path.insert(0, sys.argv[1])
    from mobile_release._desktop_edit_engine import main as run_engine
    return run_engine(started=started)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78  # No traceback, private file content, argv or native path.
    raise SystemExit(code)
