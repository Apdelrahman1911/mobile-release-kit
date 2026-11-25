"""Fixed Push facet on the original GitLocal/GitRemote native owner."""
import os
from pathlib import Path
import sys
import time


def main():
    started = time.monotonic()
    if (len(sys.argv) != 3 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "darwin" or not os.path.isabs(__file__)
            or not os.path.isabs(sys.argv[1]) or not os.path.isabs(sys.argv[2])):
        return 78
    sys.path.insert(0, sys.argv[1])
    from mobile_release.desktop_git_push import main as worker
    from mobile_release.git_push_transaction import Launch
    launch = Launch(Path(sys.executable), Path(__file__).with_name("git_push_helper_bootstrap.py"),
                    Path(sys.argv[1]), Path(sys.argv[2]))
    return worker(started=started, launch=launch)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78
    raise SystemExit(code)
