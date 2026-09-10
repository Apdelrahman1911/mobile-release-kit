"""Required credential-free macOS gate. Missing tooling/skipped tests are FAIL."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERNS = ("test_ios_profile_authority.py", "test_ios_profile_trust.py", "test_ios_profile_installation.py",
            "test_default_cancellation.py", "test_profile_processes.py", "test_macho_native.py")
PREREQUISITES = (
    ("openssl-version", ("/usr/bin/openssl", "version")),
    ("clang-discovery", ("/usr/bin/xcrun", "--find", "clang")),
    ("dsymutil-discovery", ("/usr/bin/xcrun", "--find", "dsymutil")),
    ("system-code", ("/usr/bin/codesign", "--verify", "--strict", "/usr/bin/true")),
)
DIAGNOSTIC_PREFIX = "MRK_NATIVE_DIAGNOSTIC="
MAX_DIAGNOSTIC_RECORDS = 16
MAX_DIAGNOSTIC_BYTES = 16 * 1024


def _expected_native_ids() -> tuple[str, ...]:
    """Reuse the fixed immutable source inventory, never import test modules.

    This gate already runs under the original outer command/aggregate deadline.
    Do not create another time budget just to collect optional failure metadata.
    """
    spec = importlib.util.spec_from_file_location(
        "_mrk_native_inventory", ROOT / ".github/scripts/ci_checks.py",
    )
    if spec is None or spec.loader is None:
        raise AssertionError("required fixed native inventory helper is missing")
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)  # Reviewed inert definitions, not a CLI entry point.
    if checks.NATIVE_PATTERNS != PATTERNS:
        raise AssertionError("required native patterns differ from their source authority")
    return checks.expected_python_ids(ROOT, "native")


def _product_modules():
    from mobile_release import cancellation, ios_profile_auth, ios_profile_trust, ios_profiles
    return cancellation, ios_profiles, ios_profile_auth, ios_profile_trust


def _diagnostic_ids(expected) -> frozenset[str]:
    classes = {identifier.rsplit(".", 1)[0] for identifier in expected}
    modules = {identifier.rsplit(".", 2)[0] for identifier in expected}
    return frozenset(expected) | frozenset(
        f"{operation} ({name})" for operations, names in (
            (("setUpClass", "tearDownClass"), classes), (("setUpModule", "tearDownModule"), modules),
        ) for operation in operations for name in names
    )


def _failure_record(identifier: str, outcome: str, error: BaseException | None) -> dict:
    """Finite observations from the actual exception, never args or display text."""
    category, number, returncode = "none", None, None
    if error is not None:
        if isinstance(error, subprocess.CalledProcessError):
            category = "nonzero-exit"
            observed = error.returncode
            if type(observed) is int and -255 <= observed <= 255 and observed != 0:
                returncode = observed
        elif isinstance(error, subprocess.TimeoutExpired):
            category = "timeout"
        elif isinstance(error, OSError):
            category = "os-error"
            observed = error.errno
            if type(observed) is int and 0 < observed < 4096:
                number = observed
        else:
            for kind, label in ((AssertionError, "assertion-error"), (ValueError, "value-error"),
                                (TypeError, "type-error"), (MemoryError, "memory-error"),
                                (Exception, "exception"), (BaseException, "base-exception")):
                if isinstance(error, kind):
                    category = label
                    break
    return {"id": identifier, "outcome": outcome, "category": category, "errno": number, "returncode": returncode}


def _emit_diagnostic(phase: str, records: list[dict]) -> None:
    if phase not in {"prerequisite", "tests"} or not 1 <= len(records) <= MAX_DIAGNOSTIC_RECORDS:
        raise AssertionError("native diagnostic contract differs")
    envelope = {"schema": 1, "phase": phase, "records": records}
    # A prerequisite's inherited stderr may end in a partial line. Keep the
    # one diagnostic envelope framed without capturing or replaying that text.
    line = "\n" + DIAGNOSTIC_PREFIX + json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=True, allow_nan=False) + "\n"
    if len(line.encode("ascii")) > MAX_DIAGNOSTIC_BYTES:
        raise AssertionError("native diagnostic exceeds its fixed bound")
    written = sys.stderr.write(line)
    if type(written) is not int or written != len(line):
        raise OSError("native diagnostic write was incomplete")
    sys.stderr.flush()


def _publish_failure(phase: str, records: list[dict], original: BaseException | None = None) -> None:
    # Only call after failure is established. There is one attempt, no fallback
    # stream/retry, and a broken diagnostic can never turn this into success.
    if not records:
        return  # Unknown/unavailable attribution is not a fabricated record.
    try:
        _emit_diagnostic(phase, records)
    except BaseException as publication:
        if original is None and not isinstance(publication, Exception):
            raise  # Preserve an interruption when no earlier raised error owns it.
        if original is not None:
            try:
                original.add_note("Native failure diagnostic publication failed")
            except BaseException:
                pass  # Never replace the original prerequisite/interruption.


def _result_class(expected, state):
    allowed = _diagnostic_ids(expected)

    class Result(unittest.TextTestResult):
        def record_native(self, test, outcome, error=None):
            state["failed"] = True
            if len(state["records"]) >= MAX_DIAGNOSTIC_RECORDS:
                return
            try:
                identifier = getattr(test, "test_case", test).id()
                if type(identifier) is not str or identifier not in allowed or len(identifier) > 512:
                    return
                exception = error[1] if error is not None else None
                state["records"].append(_failure_record(identifier, outcome, exception))
            except Exception:
                # The actual adverse callback already latches failure. A
                # superclass reporting error can precede its base storage
                # (addSubTest), so attribution never assumes that append.
                # Optional attribution failure must not retry the callback.
                # BaseException interruptions still propagate to run().
                return

        def super_then_record(self, method, arguments, test, outcome, error=None):
            try:
                method(*arguments)
            except BaseException:
                # TextTestResult can fail while reporting before or after base
                # storage. Attribute the actual callback either way, but
                # re-raise the very same reporting failure.
                try:
                    self.record_native(test, outcome, error)
                except BaseException:
                    pass
                raise
            self.record_native(test, outcome, error)

        def addError(self, test, error):
            self.super_then_record(super().addError, (test, error), test, "error", error)

        def addFailure(self, test, error):
            self.super_then_record(super().addFailure, (test, error), test, "failure", error)

        def addSkip(self, test, reason):
            self.super_then_record(super().addSkip, (test, reason), test, "skip")

        def addExpectedFailure(self, test, error):
            self.super_then_record(super().addExpectedFailure, (test, error), test, "expected-failure", error)

        def addUnexpectedSuccess(self, test):
            self.super_then_record(super().addUnexpectedSuccess, (test,), test, "unexpected-success")

        def addSubTest(self, test, subtest, error):
            if error is None:
                super().addSubTest(test, subtest, error)
            else:
                outcome = "failure" if issubclass(error[0], test.failureException) else "error"
                self.super_then_record(super().addSubTest, (test, subtest, error), test, outcome, error)

    return Result


def run(*, installed_wheel=False) -> int:
    if sys.platform != "darwin":
        print("FAIL: required native Apple profile verification needs macOS", file=sys.stderr)
        return 1
    for role, command in PREREQUISITES:
        try:
            subprocess.run(command, stdin=subprocess.DEVNULL, check=True, timeout=30)
        except BaseException as error:
            try:
                records = [_failure_record(role, "error", error)]
            except BaseException:
                records = []
            _publish_failure("prerequisite", records, error)
            raise
    expected = _expected_native_ids()
    modules = _product_modules()
    if installed_wheel:
        for module in modules:
            if Path(module.__file__).resolve().is_relative_to(ROOT):
                raise AssertionError("wheel test imported the repository instead of the installed package")
        modules[-1].apple_roots()  # Actual independent resource pins; no native trust seam.
    suite = unittest.TestSuite()
    for pattern in PATTERNS:
        tests = unittest.TestLoader().discover(str(ROOT / "tests"), pattern=pattern)
        if tests.countTestCases() == 0:
            raise AssertionError(f"required native test group is empty: {pattern}")
        suite.addTests(tests)
    state = {"failed": False, "records": []}
    try:
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2,
                                         resultclass=_result_class(expected, state)).run(suite)
        if result.skipped:
            print("FAIL: required native verification must not contain skipped tests", file=sys.stderr)
        success = result.wasSuccessful() and not result.skipped and not state["failed"]
    except BaseException as error:
        if state["failed"]:
            _publish_failure("tests", state["records"], error)
        raise
    if not success:
        _publish_failure("tests", state["records"])
    return 0 if success else 1


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--installed-wheel"]):
        raise SystemExit("usage: run_native_profile_checks.py [--installed-wheel]")
    raise SystemExit(run(installed_wheel=bool(sys.argv[1:])))
