"""Fixed Linux GitHub read-only entry; no mode, host, trust or token arguments.

This source does not qualify a development or packaged runtime. The native
original owner must separately admit the interpreter, imports and sibling CA.
"""
import os
import sys
import time


def main() -> int:
    started = time.monotonic()  # Includes the service/HTTP/TLS import cost.
    if (len(sys.argv) != 2 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "linux" or not os.path.isabs(sys.argv[1])
            or not os.path.isabs(__file__)):
        return 78
    # The original native owner supplies this fixed core, never a project path.
    # Trust is the fixed sibling of THIS bootstrap, not another argv/env input.
    runtime_dir = os.path.dirname(__file__)
    sys.path.insert(0, sys.argv[1])
    from mobile_release._desktop_github_engine import main as run_engine

    return run_engine(started=started, runtime_dir=runtime_dir)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78  # No traceback, paths, request, token or import diagnostics.
    raise SystemExit(code)
