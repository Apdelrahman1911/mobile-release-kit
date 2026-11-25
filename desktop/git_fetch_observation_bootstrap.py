"""Two fixed observer roles in ONE held file, not a new process runner."""
import os
from pathlib import Path
import sys
import time


def main():
    started = time.monotonic()
    if (len(sys.argv) not in (3, 5) or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "darwin" or not os.path.isabs(__file__)
            or not os.path.isabs(sys.argv[1]) or not os.path.isabs(sys.argv[2])):
        return 78
    sys.path.insert(0, sys.argv[1])
    from mobile_release import _git_fetch_observation_entry as observation
    if len(sys.argv) == 5:
        return observation.helper(remote_name=sys.argv[3], url=sys.argv[4],
                                  runtime_dir=Path(sys.argv[2]), started=started)
    observation.install_worker_probe()
    from mobile_release.desktop_git_remote import main as worker
    from mobile_release.git_fetch_transaction import Launch
    return worker(started=started, launch=Launch(Path(sys.executable), Path(__file__),
                  Path(sys.argv[1]), Path(sys.argv[2])))


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78
    if len(sys.argv) == 5:
        # Actual Entry closed ordinary pipes before its frame. Kernel exit is
        # the only close of this borrowed FD8 copy; parent joins/EOF still win.
        os._exit(code)
    raise SystemExit(code)
