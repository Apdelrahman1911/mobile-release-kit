"""Fixed stock-Git helper entry. No ambient account, command or HTTP route."""
import os
from pathlib import Path
import sys
import time


def main():
    started = time.monotonic()
    if (len(sys.argv) != 5 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "darwin" or not os.path.isabs(__file__)
            or not os.path.isabs(sys.argv[1]) or not os.path.isabs(sys.argv[2])):
        return 78
    sys.path.insert(0, sys.argv[1])
    from mobile_release.desktop_git_remote_helper import main as helper
    return helper(remote=sys.argv[3], url=sys.argv[4], runtime_dir=Path(sys.argv[2]), started=started)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78
    # The entry already completed all ordinary pipe/HTTP closes. Do not run
    # buffered-stream flushing or a destructor after its FD8 returned frame.
    # Kernel exit closes the BORROWED inherited copy; the ORIGINAL C/A/W and
    # parent pair still require actual joins plus all-copy EOF and close.
    os._exit(code)
