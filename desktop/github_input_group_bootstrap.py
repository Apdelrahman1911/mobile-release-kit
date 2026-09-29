"""Fixed Linux input-group entry. It cannot select a CLI or another action family."""
import os
import sys
import time


def main() -> int:
    started = time.monotonic()
    if (len(sys.argv) != 2 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "linux" or not os.path.isabs(sys.argv[1])
            or not os.path.isabs(__file__)):
        return 78
    runtime_dir = os.path.dirname(__file__)
    sys.path.insert(0, sys.argv[1])
    from mobile_release._desktop_github_preflight_engine import main as run_engine
    from mobile_release._github_action_family import Family

    return run_engine(started=started, runtime_dir=runtime_dir, family=Family.INPUT_GROUP)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78
    raise SystemExit(code)
