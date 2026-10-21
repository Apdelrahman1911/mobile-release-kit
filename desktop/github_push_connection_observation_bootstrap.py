"""Nonshipping installed observer only; unchanged original Connection engine."""
import os
import sys
import time


def main():
    started = time.monotonic()
    if (len(sys.argv) != 2 or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or sys.version_info < (3, 11)
            or sys.platform != "darwin" or not os.path.isabs(__file__)
            or not os.path.isabs(sys.argv[1])):
        return 78
    sys.path.insert(0, sys.argv[1])
    from mobile_release import _github_connection_transport as http
    from mobile_release._git_push_observation_http import Supplier
    from mobile_release._desktop_github_engine import main as engine
    supplier = Supplier()
    http._make_live_exchange = supplier.factory
    return engine(started=started, runtime_dir=os.path.dirname(__file__))


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78
    raise SystemExit(code)
