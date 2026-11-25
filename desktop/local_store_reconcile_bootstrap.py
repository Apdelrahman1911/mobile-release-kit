"""Fixed isolated macOS Store-reconcile entry; no CLI/environment fallback."""
import os
import sys
import time


def main() -> int:
    started = time.monotonic()  # Import/setup time consumes the same work limit.
    if (len(sys.argv) != 2 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "darwin" or not os.path.isabs(sys.argv[1])
            or not os.path.isabs(__file__)):
        return 78
    sys.path.insert(0, sys.argv[1])  # Sole native-qualified installed core ZIP.
    from mobile_release._desktop_store_reconcile_engine import main as run_engine
    return run_engine(started=started)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78  # No provider output, credential, path, or traceback.
    raise SystemExit(code)
