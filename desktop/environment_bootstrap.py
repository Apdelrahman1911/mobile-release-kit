"""Fixed isolated main-thread diagnostics entry; no CLI/runtime fallback.

The native owner separately qualifies source/ZIP runtime, neutral cwd and host.
No renderer-provided executable, environment, tool path or command is accepted.
"""
import os
import sys
import time


def main() -> int:
    started = time.monotonic()  # Includes the service and ordinary owner imports.
    if (len(sys.argv) != 2 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform not in {"linux", "darwin"} or not os.path.isabs(sys.argv[1])
            or not os.path.isabs(__file__)):
        return 78
    sys.path.insert(0, sys.argv[1])  # Sole already-qualified fixed core directory/ZIP.
    from mobile_release._desktop_environment_engine import main as run_engine
    return run_engine(started=started)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78  # No traceback, private output, paths, argv or draft values.
    raise SystemExit(code)
