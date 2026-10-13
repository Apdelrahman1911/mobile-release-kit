"""Fixed isolated Android build entry; no CLI, tool or runtime fallback.

The native owner must separately qualify the original runtime, neutral cwd and
protected toolchain. This bootstrap cannot turn checked paths into custody.
"""
import os
import sys
import time


def _supported_host() -> bool:
    if sys.platform == "linux":
        return True  # Existing Linux gate; the native owner admits its exact ABI.
    if sys.platform != "darwin":
        return False
    # Host shape only; the native owner still proves exact ABI and refuses Rosetta.
    try:
        machine = os.uname().machine
        return machine == "arm64" or (machine == "x86_64" and sys.maxsize == 2**63 - 1)
    except OSError:
        return False


def main() -> int:
    started = time.monotonic()  # Before host checks/core imports; never reset by a stage.
    if (len(sys.argv) != 2 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or not _supported_host() or not os.path.isabs(sys.argv[1])
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
