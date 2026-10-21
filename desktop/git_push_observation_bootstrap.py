"""Three fixed roles in ONE held observer entry; no extra execution owner."""
import os
from pathlib import Path
import sys
import time


def main():
    started = time.monotonic()
    if (len(sys.argv) not in (3, 6, 11) or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "darwin" or not os.path.isabs(__file__)
            or not os.path.isabs(sys.argv[1]) or not os.path.isabs(sys.argv[2])):
        return 78
    sys.path.insert(0, sys.argv[1])
    if len(sys.argv) == 6 and sys.argv[3] == "push-helper":
        from mobile_release._git_push_observation_entry import helper
        return helper(remote=sys.argv[4], url=sys.argv[5], runtime_dir=Path(sys.argv[2]), started=started)
    if len(sys.argv) == 11 and sys.argv[3] == "push-hook":
        from mobile_release._git_push_private_protocol import Clock
        from mobile_release.desktop_git_push_hook import main as hook
        for value in sys.argv[7:9]:
            if not value.isascii() or not value.isdecimal() or not 1 <= len(value) <= 19:
                return 78
        return hook(mode=sys.argv[4], clock=Clock(sys.argv[5], int(sys.argv[7]), int(sys.argv[8])),
                    review_digest=sys.argv[6], remote=sys.argv[9], url=sys.argv[10],
                    runtime_dir=Path(sys.argv[2]), started=started)
    if len(sys.argv) != 3:
        return 78
    from mobile_release._git_push_observation_entry import install_worker_probe
    from mobile_release.desktop_git_push import main as worker
    from mobile_release.git_push_transaction import Launch
    install_worker_probe()
    return worker(started=started, launch=Launch(Path(sys.executable), Path(__file__),
                  Path(sys.argv[1]), Path(sys.argv[2])))


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78
    if len(sys.argv) in (6, 11):
        os._exit(code)  # Parent still requires original C/A/W and ALL-copy EOF.
    raise SystemExit(code)
