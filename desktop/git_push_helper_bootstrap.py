"""Two fixed Push roles on the existing GitRemote C/A/W, never a runner API."""
import os
from pathlib import Path
import sys
import time


def main():
    started = time.monotonic()
    if (len(sys.argv) not in (6, 11) or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "darwin" or not os.path.isabs(__file__)
            or not os.path.isabs(sys.argv[1]) or not os.path.isabs(sys.argv[2])):
        return 78
    sys.path.insert(0, sys.argv[1])
    if len(sys.argv) == 6 and sys.argv[3] == "push-helper":
        from mobile_release.desktop_git_push_helper import main as helper
        return helper(remote=sys.argv[4], url=sys.argv[5], runtime_dir=Path(sys.argv[2]), started=started)
    if len(sys.argv) == 11 and sys.argv[3] in ("push-hook", "push-new-branch-hook"):
        from mobile_release._git_push_private_protocol import Clock
        from mobile_release.desktop_git_push_hook import main as hook
        for value in sys.argv[7:9]:
            if not value.isascii() or not value.isdecimal() or not 1 <= len(value) <= 19:
                return 78
        return hook(mode=sys.argv[4], clock=Clock(sys.argv[5], int(sys.argv[7]), int(sys.argv[8])),
                    review_digest=sys.argv[6], remote=sys.argv[9], url=sys.argv[10],
                    kind="push" if sys.argv[3] == "push-hook" else "push-new-branch",
                    runtime_dir=Path(sys.argv[2]), started=started)
    return 78


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78
    # Actual entry closes its ordinary originals first. Kernel exit is not
    # native finality: parent still joins C/A/W and every FD8 copy to EOF.
    os._exit(code)
