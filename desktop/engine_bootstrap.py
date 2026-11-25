"""Trusted desktop runtime bootstrap; invoked only with Python -I -S -B.

Currently used only by an explicitly trusted development build. Production
launch is disabled pending native executable/import custody; preparing a runtime
manifest does not supply that custody. This accepts no project path, method,
environment-selected module or fallback.
"""

import os
import sys


def main() -> int:
    if (
        len(sys.argv) != 2
        or not sys.flags.isolated
        or not sys.flags.no_site
        or not sys.dont_write_bytecode
        or not os.path.isabs(sys.argv[1])
        or sys.version_info < (3, 11)
    ):
        return 78
    # -I removed cwd/user paths; -S suppresses sitecustomize and .pth execution.
    # Rust selects the explicit trusted development source before launching;
    # don't resolve a project-controlled or environment-based path here.
    sys.path.insert(0, sys.argv[1])
    from mobile_release._desktop_engine import main as run_engine

    return run_engine()


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        code = 78  # Never publish import paths, input values or a traceback.
    raise SystemExit(code)
