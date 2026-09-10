from __future__ import annotations

import errno
import io
import itertools
import json
import os
import subprocess
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from . import run_native_profile_checks
from .test_ci_verification import controller_module, coordinator_shell, fixture_paths
from .workflow_harness import evaluate_condition, load_workflow


_NATIVE_COMMANDS = (
    ("openssl-version", ("/usr/bin/openssl", "version")),
    ("clang-discovery", ("/usr/bin/xcrun", "--find", "clang")),
    ("dsymutil-discovery", ("/usr/bin/xcrun", "--find", "dsymutil")),
    ("system-code", ("/usr/bin/codesign", "--verify", "--strict", "/usr/bin/true")),
)
_FIXTURE_MODULE = "unit.native_diagnostic_fixture"
_FIXTURE_METHODS = ("test_01_before", "test_02_subject", "test_03_after",
                    "test_04_support", "test_05_support", "test_06_support")
_FIXTURE_IDS = tuple(f"{_FIXTURE_MODULE}.Fixture.{name}" for name in _FIXTURE_METHODS)


def _inert_native_suites(outcome="success", *, subtests=3, unknown_id=False):
    """Six explicitly supplied inert tests, never native discovery or imports."""
    events = []

    class Fixture(unittest.TestCase):
        def test_01_before(self):
            events.append("before")

        def test_02_subject(self):
            events.append("subject")
            if outcome in {"error", "expected-failure"}:
                raise OSError(errno.EIO, "PRIVATE_NATIVE_MESSAGE", "/PRIVATE_NATIVE_FILENAME")
            if outcome == "failure":
                self.fail("PRIVATE_NATIVE_ASSERTION")
            if outcome == "skip":
                self.skipTest("PRIVATE_NATIVE_SKIP")
            if outcome == "subtests":
                for number in range(subtests):
                    with self.subTest(private="PRIVATE_NATIVE_PARAMETER", index=number):
                        raise OSError(errno.ENOSPC, "PRIVATE_NATIVE_SUBTEST")

        def test_03_after(self):
            events.append("after")

        def test_04_support(self):
            pass

        def test_05_support(self):
            pass

        def test_06_support(self):
            pass

    Fixture.__module__, Fixture.__qualname__ = _FIXTURE_MODULE, "Fixture"
    if outcome in {"expected-failure", "unexpected-success"}:
        Fixture.test_02_subject = unittest.expectedFailure(Fixture.test_02_subject)
    if unknown_id:
        Fixture.id = lambda self: "PRIVATE_UNRECOGNIZED_ID"

    def class_failure(_cls):
        raise OSError(errno.EACCES, "PRIVATE_NATIVE_CLASS_SETUP")

    def module_failure():
        raise OSError(errno.EPERM, "PRIVATE_NATIVE_MODULE_SETUP")

    module = ModuleType(_FIXTURE_MODULE)
    if outcome in {"setUpClass", "tearDownClass"}:
        setattr(Fixture, outcome, classmethod(class_failure))
    if outcome in {"setUpModule", "tearDownModule"}:
        setattr(module, outcome, module_failure)
    suites = [unittest.TestSuite([Fixture(name)]) for name in _FIXTURE_METHODS]
    return suites, module, events


@contextmanager
def _inert_native_gate(*, suites=None, stderr=None, platform="darwin", run_effect=None,
                       runner=unittest.TextTestRunner):
    """Replace every command, inventory, product-import and discovery effect.

    Real unittest executes only explicitly constructed inert local fixtures.
    The aggregate Bash and workflow/YAML tests in this module are NOT part of
    the focused fake-only batch that uses this context manager.
    """
    gate = run_native_profile_checks
    events, calls = [], []
    output = io.StringIO() if stderr is None else stderr

    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        events.append("prerequisite")
        if run_effect is not None:
            run_effect(len(calls) - 1)
        return SimpleNamespace(returncode=0)

    def inventory():
        events.append("inventory")
        return _FIXTURE_IDS

    products = tuple(SimpleNamespace(__file__=f"/installed/mobile_release/{name}.py",
                                     apple_roots=Mock(return_value=()))
                     for name in ("cancellation", "ios_profiles", "ios_profile_auth", "ios_profile_trust"))

    def product_modules():
        events.append("product-import")
        return products

    pending = iter(suites if suites is not None else [unittest.TestSuite()] * len(gate.PATTERNS))

    def discover(path, *, pattern):
        events.append("discover")
        return next(pending)

    discovered = Mock(side_effect=discover)
    loader = Mock(return_value=SimpleNamespace(discover=discovered))
    expected = Mock(side_effect=inventory)
    imported = Mock(side_effect=product_modules)
    process = SimpleNamespace(run=command, DEVNULL=subprocess.DEVNULL,
                              CalledProcessError=subprocess.CalledProcessError, TimeoutExpired=subprocess.TimeoutExpired)
    framework = SimpleNamespace(TestSuite=unittest.TestSuite, TextTestResult=unittest.TextTestResult,
                                TextTestRunner=runner, TestLoader=loader)
    with patch.multiple(gate, subprocess=process, unittest=framework,
                        sys=SimpleNamespace(platform=platform, stderr=output),
                        _expected_native_ids=expected, _product_modules=imported):
        yield SimpleNamespace(events=events, calls=calls, stderr=output, inventory=expected,
                              products=imported, product_values=products, loader=loader, discover=discovered)


def _native_envelopes(output):
    return [json.loads(line[len(run_native_profile_checks.DIAGNOSTIC_PREFIX):])
            for line in output.splitlines() if line.startswith(run_native_profile_checks.DIAGNOSTIC_PREFIX)]


class _DiagnosticSink(io.StringIO):
    """Only the diagnostic attempt fails; ordinary unittest output is retained."""

    def __init__(self, fault):
        super().__init__()
        self.fault, self.attempts, self.diagnostic_written = fault, 0, False
        self.interruption = KeyboardInterrupt("PRIVATE_DIAGNOSTIC_INTERRUPT")

    def write(self, text):
        if text.startswith("\n" + run_native_profile_checks.DIAGNOSTIC_PREFIX):
            self.attempts += 1
            if self.fault == "write":
                raise OSError(errno.EIO, "PRIVATE_DIAGNOSTIC_WRITE")
            if self.fault == "interrupt":
                raise self.interruption
            if self.fault == "short":
                return len(text) - 1
            self.diagnostic_written = True
        return super().write(text)

    def flush(self):
        if self.fault == "flush" and self.diagnostic_written:
            raise OSError(errno.EIO, "PRIVATE_DIAGNOSTIC_FLUSH")
        return super().flush()

    def close(self):
        self.fault = None
        super().close()


class NativeProfileCITests(unittest.TestCase):
    def test_macos_upload_process_contracts_require_all_suites_and_pinned_ruby(self):
        workflow = load_workflow(Path(__file__).parents[2] / ".github/workflows/ci.yml")
        native = workflow["jobs"]["test-native-profiles"]
        linux_ruby = next(step for step in workflow["jobs"]["test-linux"]["steps"]
                          if step.get("uses", "").startswith("ruby/setup-ruby@"))
        ruby = next(step for step in native["steps"]
                    if step.get("uses", "").startswith("ruby/setup-ruby@"))
        self.assertEqual(ruby["uses"], linux_ruby["uses"])
        self.assertEqual(ruby["with"], {"ruby-version": "3.3.12", "bundler": "none", "bundler-cache": False})
        step = native["steps"][-1]
        self.assertEqual(step["run"], coordinator_shell("macos"))
        self.assertLess(native["steps"].index(ruby), native["steps"].index(step))
        for required in (ruby, step):
            self.assertNotIn("if", required)
            self.assertNotIn("continue-on-error", required)
        controller = controller_module()
        paths = fixture_paths(controller)
        steps = controller.catalog(paths, "macos", deadline=12345.0)
        suites = {
            "ruby-native-capture": ("test_native_upload_validation.rb", 13),
            "ruby-native-signal-observation": ("test_native_signal_observation.rb", 1),
            "ruby-ios_upload_validation": ("test_ios_upload_validation.rb", 26),
            "ruby-android_upload_validation": ("test_android_upload_validation.rb", 26),
        }
        actual = [item for item in steps if item.id in suites]
        self.assertEqual([item.id for item in actual], list(suites))
        for item in actual:
            filename, count = suites[item.id]
            self.assertEqual(item.argv, (*paths.bundle, "exec", str(paths.ruby),
                                       str(paths.source / "tests/workflow" / filename), "--verbose"))
            self.assertEqual(item.parser, "minitest")
            self.assertEqual(item.expected_tests, count)
        ids = [item.id for item in steps]
        # Exercise the actual dispatcher with an inert result producer. A
        # filename in YAML cannot prove execution or first-failure behavior.
        for failed in (None, *suites):
            with self.subTest(failed=failed):
                calls = []

                def perform(item):
                    calls.append(item.id)
                    return controller.CheckResult(item.id != failed)

                report = controller.execute_pipeline(steps, perform, platform="macos")
                self.assertEqual(report.ok, failed is None)
                expected_calls = ids if failed is None else ids[:ids.index(failed) + 1]
                self.assertEqual(calls, expected_calls)
                if failed is not None:
                    self.assertTrue(all(row["status"] == "UNEXECUTED" for row in report.rows[len(calls):]))

    def test_protected_aggregate_always_runs_and_fails_for_any_unsuccessful_predecessor(self):
        workflow = load_workflow(Path(__file__).parents[2] / ".github/workflows/ci.yml")
        aggregate = workflow["jobs"]["test"]
        self.assertEqual(set(aggregate["needs"]), {"test-linux", "test-native-profiles"})
        self.assertEqual(aggregate["permissions"], {})
        self.assertNotIn("continue-on-error", aggregate)
        self.assertEqual(len(aggregate["steps"]), 1)
        step = aggregate["steps"][0]
        self.assertNotIn("if", step)
        self.assertNotIn("continue-on-error", step)
        self.assertEqual(step["env"], {"LINUX_RESULT": "${{ needs.test-linux.result }}", "NATIVE_RESULT": "${{ needs.test-native-profiles.result }}"})
        self.assertEqual(step["run"], 'set -euo pipefail\n[[ "$LINUX_RESULT" == success && "$NATIVE_RESULT" == success ]]\n')
        for linux, native in itertools.product(("success", "failure", "cancelled", "skipped", ""), repeat=2):
            with self.subTest(linux=linux, native=native):
                expected = linux == native == "success"
                self.assertTrue(evaluate_condition(aggregate.get("if"), {}, success=expected,
                                                   cancelled="cancelled" in (linux, native)))
                result = subprocess.run(["bash", "-c", step["run"]], capture_output=True, timeout=5,
                                        env={"PATH": os.environ["PATH"], "LINUX_RESULT": linux, "NATIVE_RESULT": native})
                self.assertEqual(result.returncode == 0, expected)
        native_job = workflow["jobs"]["test-native-profiles"]
        self.assertEqual(native_job["runs-on"], "macos-26")
        self.assertEqual(native_job["permissions"], {"contents": "read"})
        self.assertNotIn("if", native_job)
        self.assertNotIn("continue-on-error", native_job)
        self.assertNotIn("environment", native_job)
        self.assertEqual(native_job["steps"][-1]["run"], coordinator_shell("macos"))
        controller = controller_module()
        paths = fixture_paths(controller)
        catalog = controller.catalog(paths, "macos", deadline=12345.0)
        checks = [item for item in catalog if item.id in {"native-profile-source", "native-profile-wheel"}]
        self.assertEqual([item.id for item in checks], ["native-profile-source", "native-profile-wheel"])
        gate = str(paths.source / "tests/workflow/run_native_profile_checks.py")
        self.assertEqual(checks[0].argv, (str(paths.source_python), "-I", "-B", gate))
        self.assertEqual(checks[1].argv, (str(paths.wheel_python), "-I", "-B", gate, "--installed-wheel"))
        self.assertTrue(all(item.parser == "native" for item in checks))
        self.assertTrue(all(item.cwd == paths.work and not item.cwd.is_relative_to(paths.source) for item in checks))
        ids = [item.id for item in catalog]
        self.assertLess(ids.index("wheel-inspect"), ids.index("native-profile-wheel"))
        self.assertLess(ids.index("wheel-install"), ids.index("native-profile-wheel"))

    def test_native_gate_rejects_unavailable_platform_missing_tooling_empty_suite_and_skips(self):
        gate = run_native_profile_checks
        with _inert_native_gate(platform="linux") as fixture:
            self.assertEqual(gate.run(), 1)
        self.assertEqual(fixture.events, [])
        missing = FileNotFoundError(errno.ENOENT, "PRIVATE_MISSING_NATIVE_TOOL")

        def fail(_index):
            raise missing

        with _inert_native_gate(run_effect=fail) as fixture, self.assertRaises(FileNotFoundError) as raised:
            gate.run()
        self.assertIs(raised.exception, missing)
        fixture.inventory.assert_not_called()
        fixture.products.assert_not_called()
        fixture.loader.assert_not_called()
        with _inert_native_gate() as fixture, self.assertRaisesRegex(AssertionError, "empty"):
            gate.run()
        self.assertEqual(fixture.events, ["prerequisite"] * 4 + ["inventory", "product-import", "discover"])
        suites, module, _ = _inert_native_suites("skip")
        with patch.dict(sys.modules, {_FIXTURE_MODULE: module}), _inert_native_gate(suites=suites) as fixture:
            self.assertEqual(gate.run(), 1)
        diagnostic, = _native_envelopes(fixture.stderr.getvalue())
        self.assertEqual(diagnostic["records"], [{"id": _FIXTURE_IDS[1], "outcome": "skip", "category": "none",
                                                  "errno": None, "returncode": None}])

    def test_native_prerequisites_retain_actual_role_and_stop_before_imports(self):
        gate = run_native_profile_checks
        for failed_index, (role, _command) in enumerate(_NATIVE_COMMANDS):
            with self.subTest(role=role):
                original = subprocess.CalledProcessError(7, ["PRIVATE_COMMAND"], output=b"PRIVATE_OUTPUT",
                                                          stderr=b"PRIVATE_STDERR")

                def fail(index):
                    if index == failed_index:
                        raise original

                # Preserve a genuine partial inherited-stderr tail; the actual
                # emitter must start its one diagnostic on a new physical line.
                output = io.StringIO()
                output.write("PRIVATE_INHERITED_STDERR_TAIL")
                with _inert_native_gate(run_effect=fail, stderr=output) as fixture:
                    with self.assertRaises(subprocess.CalledProcessError) as raised:
                        gate.run()
                self.assertIs(raised.exception, original)
                self.assertEqual(fixture.calls, [(command, {"stdin": subprocess.DEVNULL, "check": True, "timeout": 30})
                                                for _, command in _NATIVE_COMMANDS[:failed_index + 1]])
                self.assertEqual(fixture.events, ["prerequisite"] * (failed_index + 1))
                fixture.inventory.assert_not_called()
                fixture.products.assert_not_called()
                fixture.loader.assert_not_called()
                diagnostic, = _native_envelopes(output.getvalue())
                self.assertEqual(diagnostic, {"schema": 1, "phase": "prerequisite", "records": [
                    {"id": role, "outcome": "error", "category": "nonzero-exit", "errno": None, "returncode": 7}]})
                self.assertNotIn("PRIVATE", json.dumps(diagnostic))
                self.assertIn("TAIL\n" + gate.DIAGNOSTIC_PREFIX, output.getvalue())

                controller = controller_module()
                paths = SimpleNamespace(source=Path("/synthetic/native-source"))
                checks = SimpleNamespace(expected_python_ids=Mock(return_value=_FIXTURE_IDS))
                captured = SimpleNamespace(ok=False, returncode=1, waited=True, stdout_eof=True, stderr_eof=True,
                    domain_finality=True, timed_out=False, cancelled=False, stdout=b"", stderr=output.getvalue().encode(),
                    persisted=(), duration=0.01, cleanup_errors=(), primary_error="command exited 1")
                step = controller.Step("native-profile-source", parser="native")
                with patch.multiple(controller, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                                    time=SimpleNamespace(monotonic=lambda: 1.0)):
                    public = controller.failure_details(captured, step, paths, checks=checks,
                                                        deadline=10.0, platform="macos")
                    with self.assertRaises(controller.VerificationError):
                        controller.parse_capture(step, captured, paths, "macos", checks)
                self.assertEqual(public["native_diagnostic"], diagnostic)
                self.assertNotIn("PRIVATE", json.dumps(public))
                checks.expected_python_ids.assert_called_once_with(paths.source, "native", deadline=10.0)

    def test_native_prerequisite_fields_are_finite_and_publication_preserves_original(self):
        gate = run_native_profile_checks
        cases = [(subprocess.CalledProcessError(value, "PRIVATE_COMMAND"), "nonzero-exit", None,
                  value if type(value) is int and -255 <= value <= 255 and value != 0 else None)
                 for value in (-255, -1, 1, 255, -256, 256, 0, True, "PRIVATE_RETURN_CODE", None)]
        cases += [(subprocess.TimeoutExpired("PRIVATE_COMMAND", 30, output=b"PRIVATE_OUTPUT"), "timeout", None, None)]
        cases += [(OSError(value, "PRIVATE_OS_MESSAGE", "/PRIVATE_OS_PATH"), "os-error",
                   value if type(value) is int and 0 < value < 4096 else None, None)
                  for value in (errno.EIO, 4095, 0, 4096, -1, True, "PRIVATE_ERRNO", None)]
        cases += [(error("PRIVATE_MESSAGE"), category, None, None) for error, category in (
            (AssertionError, "assertion-error"), (ValueError, "value-error"), (TypeError, "type-error"),
            (MemoryError, "memory-error"), (RuntimeError, "exception"), (KeyboardInterrupt, "base-exception"),
            (SystemExit, "base-exception"))]
        for original, category, number, code in cases:
            with self.subTest(category=category, errno=number, returncode=code):
                def fail(_index):
                    raise original

                with _inert_native_gate(run_effect=fail) as fixture, self.assertRaises(type(original)) as raised:
                    gate.run()
                self.assertIs(raised.exception, original)
                diagnostic, = _native_envelopes(fixture.stderr.getvalue())
                self.assertEqual(diagnostic["records"], [{"id": "openssl-version", "outcome": "error",
                    "category": category, "errno": number, "returncode": code}])
                self.assertNotIn("PRIVATE", json.dumps(diagnostic))
                self.assertEqual(len(fixture.calls), 1)
                fixture.inventory.assert_not_called()
                fixture.products.assert_not_called()
                fixture.loader.assert_not_called()

        for fault in ("write", "short", "flush", "interrupt"):
            with self.subTest(publication=fault):
                original = subprocess.CalledProcessError(9, "PRIVATE_COMMAND")
                output = _DiagnosticSink(fault)

                def fail(_index):
                    raise original

                with _inert_native_gate(run_effect=fail, stderr=output) as fixture:
                    with self.assertRaises(subprocess.CalledProcessError) as raised:
                        gate.run()
                self.assertIs(raised.exception, original)
                self.assertEqual(output.attempts, 1)
                self.assertEqual(original.__notes__, ["Native failure diagnostic publication failed"])
                self.assertEqual(len(fixture.calls), 1)
                fixture.inventory.assert_not_called()
                fixture.products.assert_not_called()
                fixture.loader.assert_not_called()
                output.fault = None

        record = gate._failure_record("openssl-version", "error", OSError(errno.EIO, "PRIVATE"))
        for phase, records in (("unknown", [record]), ("tests", []), ("tests", [record] * 17),
                               ("tests", [{**record, "id": "x" * (16 * 1024)}])):
            with self.subTest(emission_phase=phase, record_count=len(records)):
                with _inert_native_gate() as fixture, self.assertRaises(AssertionError):
                    gate._emit_diagnostic(phase, records)
                self.assertEqual(fixture.stderr.getvalue(), "")

    def test_native_callbacks_cover_methods_subtests_and_fixture_lifecycle(self):
        gate = run_native_profile_checks
        for outcome in ("success", "error", "failure", "skip", "expected-failure", "unexpected-success", "subtests",
                        "setUpClass", "tearDownClass", "setUpModule", "tearDownModule"):
            with self.subTest(outcome=outcome):
                suites, module, events = _inert_native_suites(outcome)
                with patch.dict(sys.modules, {_FIXTURE_MODULE: module}), _inert_native_gate(suites=suites) as fixture:
                    status = gate.run()
                self.assertEqual(status, 0 if outcome == "success" else 1)
                self.assertEqual(fixture.calls, [(command, {"stdin": subprocess.DEVNULL, "check": True, "timeout": 30})
                                                for _, command in _NATIVE_COMMANDS])
                self.assertEqual(fixture.events, ["prerequisite"] * 4 + ["inventory", "product-import"] + ["discover"] * 6)
                self.assertEqual([call.kwargs for call in fixture.discover.call_args_list],
                                 [{"pattern": pattern} for pattern in gate.PATTERNS])
                if outcome == "success":
                    self.assertEqual(_native_envelopes(fixture.stderr.getvalue()), [])
                    self.assertEqual(events, ["before", "subject", "after"])
                    continue
                diagnostic, = _native_envelopes(fixture.stderr.getvalue())
                self.assertEqual(set(diagnostic), {"schema", "phase", "records"})
                self.assertEqual((diagnostic["schema"], diagnostic["phase"]), (1, "tests"))
                records = diagnostic["records"]
                identifier = _FIXTURE_IDS[1]
                if outcome in {"setUpClass", "tearDownClass"}:
                    identifier = f"{outcome} ({_FIXTURE_MODULE}.Fixture)"
                elif outcome in {"setUpModule", "tearDownModule"}:
                    identifier = f"{outcome} ({_FIXTURE_MODULE})"
                expected_outcome = outcome if outcome in {"failure", "skip", "expected-failure", "unexpected-success"} else "error"
                category = "none" if outcome in {"skip", "unexpected-success"} else "assertion-error" if outcome == "failure" else "os-error"
                number = (errno.EACCES if outcome in {"setUpClass", "tearDownClass"} else
                          errno.EPERM if outcome in {"setUpModule", "tearDownModule"} else
                          errno.ENOSPC if outcome == "subtests" else errno.EIO) if category == "os-error" else None
                self.assertEqual(records, [{"id": identifier, "outcome": expected_outcome, "category": category,
                                            "errno": number, "returncode": None}] * (3 if outcome == "subtests" else 1))
                self.assertNotIn("PRIVATE", json.dumps(diagnostic))
                self.assertEqual(events, [] if outcome in {"setUpClass", "setUpModule"} else ["before", "subject", "after"])

    def test_native_callbacks_are_bounded_recorded_after_super_and_publication_stays_failed(self):
        gate = run_native_profile_checks
        suites, module, events = _inert_native_suites("subtests", subtests=20)
        retained, observed = [], []

        class RetainingRunner(unittest.TextTestRunner):
            def _makeResult(self):
                result = super()._makeResult()
                retained.append(result)
                return result

        actual_record = gate._failure_record

        def after_super(identifier, outcome, error):
            self.assertEqual(len(retained[0].errors), len(observed) + 1)
            observed.append(identifier)
            return actual_record(identifier, outcome, error)

        with patch.dict(sys.modules, {_FIXTURE_MODULE: module}), \
                _inert_native_gate(suites=suites, runner=RetainingRunner) as fixture, \
                patch.object(gate, "_failure_record", side_effect=after_super):
            self.assertEqual(gate.run(), 1)
        self.assertEqual(len(retained[0].errors), 20)
        self.assertEqual(observed, [_FIXTURE_IDS[1]] * 16)
        diagnostic, = _native_envelopes(fixture.stderr.getvalue())
        self.assertEqual(len(diagnostic["records"]), 16)
        self.assertEqual({row["id"] for row in diagnostic["records"]}, {_FIXTURE_IDS[1]})
        self.assertEqual(events, ["before", "subject", "after"])

        for fault in ("unknown-id", "write", "short", "flush", "interrupt"):
            with self.subTest(fault=fault):
                suites, module, _ = _inert_native_suites("error", unknown_id=fault == "unknown-id")
                output = _DiagnosticSink(fault)
                with patch.dict(sys.modules, {_FIXTURE_MODULE: module}), _inert_native_gate(suites=suites, stderr=output):
                    if fault == "interrupt":
                        with self.assertRaises(KeyboardInterrupt) as raised:
                            gate.run()
                        self.assertIs(raised.exception, output.interruption)
                    else:
                        self.assertEqual(gate.run(), 1)
                self.assertEqual(output.attempts, 0 if fault == "unknown-id" else 1)
                if fault == "unknown-id":
                    self.assertEqual(_native_envelopes(output.getvalue()), [])
                output.fault = None

    def test_native_superclass_reporting_failure_preserves_original_callback_and_exception(self):
        gate = run_native_profile_checks
        for outcome, status_text in (("error", "ERROR"), ("failure", "FAIL"), ("skip", "skipped 'PRIVATE_NATIVE_SKIP'"),
                                     ("expected-failure", "expected failure"), ("unexpected-success", "unexpected success"),
                                     ("subtests", "ERROR")):
            with self.subTest(outcome=outcome):
                reporting = OSError(errno.EDQUOT, "PRIVATE_SUPERCLASS_REPORTING_FAILURE")
                retained = []

                class BrokenStatus(io.StringIO):
                    def write(self, text):
                        if text == status_text:
                            raise reporting
                        return super().write(text)

                class RetainingRunner(unittest.TextTestRunner):
                    def _makeResult(self):
                        result = super()._makeResult()
                        retained.append(result)
                        return result

                suites, module, _ = _inert_native_suites(outcome)
                output = BrokenStatus()
                with patch.dict(sys.modules, {_FIXTURE_MODULE: module}), \
                        _inert_native_gate(suites=suites, stderr=output, runner=RetainingRunner):
                    with self.assertRaises(OSError) as raised:
                        gate.run()
                self.assertIs(raised.exception, reporting)
                result = retained[0]
                saved = (result.failures if outcome == "failure" else result.skipped if outcome == "skip" else
                         result.expectedFailures if outcome == "expected-failure" else
                         result.unexpectedSuccesses if outcome == "unexpected-success" else result.errors)
                # TextTestResult reports subtests before base storage. A status
                # error prevents that append; only the outer-method reporting
                # error is stored. Our diagnostics independently retain both.
                self.assertEqual(len(saved), 1)
                diagnostic, = _native_envelopes(output.getvalue())
                self.assertEqual(len(diagnostic["records"]), 2 if outcome == "subtests" else 1)
                row = diagnostic["records"][0]
                self.assertEqual(row["id"], _FIXTURE_IDS[1])
                self.assertEqual(row["outcome"], "error" if outcome == "subtests" else outcome)
                self.assertEqual(row["errno"], errno.ENOSPC if outcome == "subtests" else
                                 errno.EIO if outcome in {"error", "expected-failure"} else None)
                if outcome == "subtests":
                    self.assertEqual(diagnostic["records"][1], {"id": _FIXTURE_IDS[1], "outcome": "error",
                        "category": "os-error", "errno": errno.EDQUOT, "returncode": None})
                self.assertNotIn("PRIVATE", json.dumps(diagnostic))

    def test_native_inventory_reuses_exact_fixed_source_authority_without_budget(self):
        gate = run_native_profile_checks
        for case in ("success", "missing-loader", "pattern-drift", "inventory-error"):
            with self.subTest(case=case):
                events = []
                original = ValueError("PRIVATE_SOURCE_INVENTORY_FAILURE")

                def expected(*args, **kwargs):
                    events.append(("inventory", args, kwargs))
                    if case == "inventory-error":
                        raise original
                    return _FIXTURE_IDS

                checks = SimpleNamespace(NATIVE_PATTERNS=gate.PATTERNS if case != "pattern-drift" else (),
                                         expected_python_ids=expected)
                loader = SimpleNamespace(exec_module=lambda module: events.append(("definitions", module)))
                spec = SimpleNamespace(loader=None if case == "missing-loader" else loader)
                specs = Mock(return_value=spec)
                modules = Mock(return_value=checks)
                facade = SimpleNamespace(util=SimpleNamespace(spec_from_file_location=specs, module_from_spec=modules))
                with patch.object(gate, "importlib", facade):
                    if case == "success":
                        self.assertEqual(gate._expected_native_ids(), _FIXTURE_IDS)
                    elif case == "inventory-error":
                        with self.assertRaises(ValueError) as raised:
                            gate._expected_native_ids()
                        self.assertIs(raised.exception, original)
                    else:
                        with self.assertRaises(AssertionError):
                            gate._expected_native_ids()
                specs.assert_called_once_with("_mrk_native_inventory", gate.ROOT / ".github/scripts/ci_checks.py")
                if case == "missing-loader":
                    modules.assert_not_called()
                    self.assertEqual(events, [])
                else:
                    modules.assert_called_once_with(spec)
                    expected_events = [("definitions", checks)]
                    if case != "pattern-drift":
                        expected_events.append(("inventory", (gate.ROOT, "native"), {}))
                    self.assertEqual(events, expected_events)


if __name__ == "__main__":
    unittest.main()
