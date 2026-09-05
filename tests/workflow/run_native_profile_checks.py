"""Required credential-free macOS gate. Missing tooling/skipped tests are FAIL."""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERNS = ("test_ios_profile_authority.py", "test_ios_profile_trust.py", "test_ios_profile_installation.py",
            "test_default_cancellation.py", "test_profile_processes.py", "test_macho_native.py")


def run(*, installed_wheel=False) -> int:
    if sys.platform != "darwin":
        print("FAIL: required native Apple profile verification needs macOS", file=sys.stderr)
        return 1
    for command in (("/usr/bin/openssl", "version"), ("/usr/bin/xcrun", "--find", "clang"),
                    ("/usr/bin/xcrun", "--find", "dsymutil"), ("/usr/bin/codesign", "--verify", "--strict", "/usr/bin/true")):
        subprocess.run(command, stdin=subprocess.DEVNULL, check=True, timeout=30)
    from mobile_release import cancellation, ios_profile_auth, ios_profile_trust, ios_profiles
    if installed_wheel:
        for module in (cancellation, ios_profiles, ios_profile_auth, ios_profile_trust):
            if Path(module.__file__).resolve().is_relative_to(ROOT):
                raise AssertionError("wheel test imported the repository instead of the installed package")
        ios_profile_trust.apple_roots()  # Actual independent resource pins; no native trust seam.
    suite = unittest.TestSuite()
    for pattern in PATTERNS:
        tests = unittest.TestLoader().discover(str(ROOT / "tests"), pattern=pattern)
        if tests.countTestCases() == 0:
            raise AssertionError(f"required native test group is empty: {pattern}")
        suite.addTests(tests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print("FAIL: required native verification must not contain skipped tests", file=sys.stderr)
    return 0 if result.wasSuccessful() and not result.skipped else 1


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--installed-wheel"]):
        raise SystemExit("usage: run_native_profile_checks.py [--installed-wheel]")
    raise SystemExit(run(installed_wheel=bool(sys.argv[1:])))
