"""Fixed isolated Android build entry; no CLI, tool or runtime fallback.

The native owner must separately qualify the original runtime, neutral cwd and
protected toolchain. This bootstrap cannot turn checked paths into custody.
"""
import os
import sys
import time


def main() -> int:
    started = time.monotonic()  # Before core imports; never reset by a stage.
    if (len(sys.argv) != 2 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "linux" or not os.path.isabs(sys.argv[1])
            or not os.path.isabs(__file__)):
        return 78
    sys.path.insert(0, sys.argv[1])  # Sole native-qualified fixed core directory/ZIP.
    from mobile_release._desktop_android_build_engine import main as run_engine
    return run_engine(started=started)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78  # No traceback, project/private paths or credential values.
    raise SystemExit(code)
