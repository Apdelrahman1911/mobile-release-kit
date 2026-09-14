"""Inert optional matrix/G diagnostics; no native/process or coverage evidence."""
from __future__ import annotations

import ast
import copy
import dataclasses
import io
import json
import linecache
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import local_signing_matrix_diagnostic as diagnostic
from .local_signing_regression_fixture import RegressionResult
from . import test_ci_controller as controller_tests
from .test_ci_verification import controller_module


IDS = ("1" * 64, "2" * 64)
SOURCE_MAP = (("/fixed/outer.py", "tests/workflow/run_local_signing_matrix.py"),
              ("/fixed/original.py", "tests/unit/test_local_signing.py"))


def error_tuple(filename, *, depth=0, category="ValueError"):
    namespace = {}
    exec(compile("def descend(depth):\n    if depth: return descend(depth - 1)\n"
                 f"    raise {category}('PRIVATE original message /PRIVATE/path')\n", filename, "exec"), namespace)
    try:
        namespace["descend"](depth)
    except BaseException as error:
        return type(error), error, error.__traceback__


def context():
    return diagnostic.Phase("source", 20.0, "ubuntu-24.04", 0, IDS, (IDS[1],), SOURCE_MAP)


class MatrixDiagnosticTests(unittest.TestCase):
    def test_actual_producer_and_independent_parser_agree_on_closed_optional_schema(self):
        controller = controller_module()
        scope = controller.SigningMatrixDiagnostic("source", "ubuntu-24.04", 0, IDS, (IDS[1],),
                                                    tuple(pair[1] for pair in SOURCE_MAP))
        outer = error_tuple(SOURCE_MAP[0][0])
        clock = SimpleNamespace(monotonic=lambda: 10.0)
        with patch.object(diagnostic, "time", clock), patch.object(controller, "time", clock):
            selected, output = context(), io.StringIO()
            with patch.object(diagnostic, "CURRENT", selected), patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
                diagnostic.mark("helper", IDS[1])
                diagnostic.original_g_failure(error_tuple(SOURCE_MAP[1][0], category="AssertionError"))
                record = diagnostic.emit(selected, outer)
                self.assertIsNone(diagnostic.emit(selected, outer))
            packet = output.getvalue().encode("ascii")
            parse = lambda raw: controller.signing_matrix_failure(raw, scope, deadline=20.0)
            self.assertEqual(parse(packet), record)
            self.assertIsNotNone(record["originalGFailure"])
            self.assertLessEqual(len(packet), 2048)
            self.assertEqual(packet.count(diagnostic.PREFIX.encode()), 1)
            self.assertNotIn(b"PRIVATE", packet)

            def wire(value):
                return (diagnostic.PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")

            mutations = (
                {"schema": True}, {"phase": "wheel"}, {"caseId": "3" * 64}, {"stage": "foreign"},
                {"caseId": None}, {"category": "PrivateError"}, {"message": "PRIVATE"},
                {"locations": [{"file": "/PRIVATE/file.py", "line": 1}]},
                {"locations": [{"file": scope.files[0], "line": True}]},
                {"locations": [{"file": scope.files[0], "line": 1}] * 4},
                {"caseId": IDS[0]}, {"stage": "cleanup"},
                {"originalGFailure": {"category": "none", "locations": []}},
                {"originalGFailure": {"category": "value-error", "locations": [], "message": "PRIVATE"}},
            )
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    self.assertIsNone(parse(wire({**record, **mutation})))
            missing = copy.deepcopy(record)
            del missing["originalGFailure"]
            for invalid in (wire(missing), packet + packet, packet[:-1], bytearray(packet), b"x" * 65537,
                            packet.replace(b'"schema":1', b'"schema":1,"schema":1'),
                            packet.replace(b"{", b"{ ", 1), diagnostic.PREFIX.encode() + b" " * 2048 + b"\n"):
                self.assertIsNone(parse(invalid))
            self.assertEqual(parse(b"PRIVATE unrelated stderr\n" + packet), record)
            for changed in (dataclasses.replace(scope, phase="adapter"), dataclasses.replace(scope, shard=True),
                            dataclasses.replace(scope, operating_system="foreign"),
                            dataclasses.replace(scope, files=("/PRIVATE/file.py",))):
                self.assertIsNone(controller.signing_matrix_failure(packet, changed, deadline=20.0))
            selected, output = context(), io.StringIO()
            with patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
                record = diagnostic.emit(selected, outer)  # No case or G tuple before helper work.
            self.assertEqual(record["caseId"], None)
            self.assertEqual(record["originalGFailure"], None)
            self.assertEqual(parse(output.getvalue().encode("ascii")), record)

    def test_shared_raw_frame_and_location_budgets_do_not_read_source_or_exception_messages(self):
        clock, output, visits = SimpleNamespace(monotonic=lambda: 10.0), io.StringIO(), []
        first = error_tuple(SOURCE_MAP[1][0], depth=80, category="AssertionError")
        outer = error_tuple(SOURCE_MAP[0][0], depth=80)
        original_locations = diagnostic._locations

        def locations(frame, source_map, budget, maximum):
            before = budget[0]
            result = original_locations(frame, source_map, budget, maximum)
            visits.append(before - budget[0])
            return result

        with patch.object(diagnostic, "time", clock), patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
            selected = context()
            with patch.object(diagnostic, "CURRENT", selected), patch.object(diagnostic, "_locations", locations), \
                    patch.object(Path, "resolve", side_effect=AssertionError("no diagnostic resolution")), \
                    patch.object(Path, "read_text", side_effect=AssertionError("no diagnostic source read")), \
                    patch.object(linecache, "getline", side_effect=AssertionError("no diagnostic source lookup")):
                diagnostic.mark("helper", IDS[1])
                diagnostic.original_g_failure(first)
                record = diagnostic.emit(selected, outer)
            self.assertEqual(visits, [16, 48])
            self.assertEqual(selected.budget, [0])
            self.assertEqual(len(record["originalGFailure"]["locations"]), 2)
            self.assertEqual(len(record["locations"]), 2)
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertEqual(set(record["originalGFailure"]), {"category", "locations"})
            self.assertLessEqual(len(output.getvalue().encode("ascii")), 2048)

    def test_original_g_latch_precedes_projection_and_later_cleanup_cannot_replace_first(self):
        first = error_tuple(SOURCE_MAP[1][0], category="AssertionError")
        later = error_tuple(SOURCE_MAP[1][0], category="OSError")
        for mode in ("error", "failure", "subtest", "missing-first-tuple", "projection-error"):
            with self.subTest(mode=mode), patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 10.0)):
                selected = context()
                test = unittest.FunctionTestCase(lambda: None)
                result = RegressionResult(test, deadline=20.0)
                calls, original_locations = [], diagnostic._locations

                def project(*args):
                    calls.append(result.first_failure)
                    self.assertTrue(result.regression_failed)
                    self.assertTrue(result.shouldStop)
                    self.assertIsNotNone(result.first_failure)
                    if mode == "projection-error":
                        raise KeyboardInterrupt("PRIVATE optional projection")
                    return original_locations(*args)

                with patch.object(diagnostic, "CURRENT", selected), patch.object(diagnostic, "_locations", project):
                    diagnostic.mark("helper", IDS[1])
                    if mode == "failure":
                        result.addFailure(test, first)
                    elif mode == "subtest":
                        result.addSubTest(test, test, first)
                    elif mode == "missing-first-tuple":
                        result.addSkip(test, "PRIVATE skip")
                    else:
                        result.addError(test, first)
                    preserved = result.first_failure
                    original = copy.deepcopy(selected.g_failure)
                    result.addError(test, later)
                    result.addFailure(test, later)
                self.assertEqual(result.first_failure, preserved)
                self.assertEqual(selected.g_failure, original)
                self.assertTrue(selected.g_seen)
                self.assertEqual(selected.budget, [48])
                self.assertEqual(len(calls), int(mode != "missing-first-tuple"))
                if mode in {"missing-first-tuple", "projection-error"}:
                    self.assertIsNone(original)
                else:
                    self.assertEqual(original["category"], "assertion-error")
                output = io.StringIO()
                with patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
                    outer = diagnostic.emit(selected, error_tuple(SOURCE_MAP[0][0]))
                self.assertEqual(outer["originalGFailure"], original)
                self.assertEqual(outer["category"], "value-error")

    def test_invalid_stage_case_tuple_expiry_and_unavailable_output_never_retry_projection(self):
        original = error_tuple(SOURCE_MAP[0][0])
        for mode in ("stage", "case", "tuple", "deadline", "writer", "short-write"):
            with self.subTest(mode=mode):
                clock, writes = [10.0], []

                def write(value):
                    writes.append(value)
                    if mode == "writer":
                        raise KeyboardInterrupt("PRIVATE optional stderr")
                    return 0 if mode == "short-write" else len(value)

                with patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: clock[0])), \
                        patch.object(diagnostic, "sys", SimpleNamespace(stderr=SimpleNamespace(write=write, flush=lambda: None))):
                    selected = context()
                    with patch.object(diagnostic, "CURRENT", selected):
                        if mode == "stage":
                            diagnostic.mark("foreign-stage")
                        elif mode == "case":
                            diagnostic.mark("helper", "3" * 64)
                    if mode == "deadline":
                        clock[0] = 20.0
                    actual = (original[0], original[1], None) if mode == "tuple" else original
                    self.assertIsNone(diagnostic.emit(selected, actual))
                    self.assertIsNone(diagnostic.emit(selected, original))
                self.assertEqual(len(writes), int(mode in {"writer", "short-write"}))
                self.assertNotIn("PRIVATE", "".join(writes))

    def test_actual_outer_wrapper_reraises_identical_original_after_finally_and_clears_context(self):
        path = Path(__file__).with_name("run_local_signing_matrix.py")
        tree = ast.parse(path.read_text(), str(path))
        function, = (node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "phase")
        for failed_projection in (False, True):
            with self.subTest(failed_projection=failed_projection), \
                    patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 10.0)):
                original, selected, events = ValueError("PRIVATE original"), context(), []

                def inner(_args, _scope, binding):
                    binding[0] = selected
                    diagnostic.CURRENT = selected
                    diagnostic.mark("helper", IDS[0])
                    try:
                        raise original
                    finally:
                        events.append("original-finally")

                def emit(bound, error):
                    self.assertEqual(events, ["original-finally"])
                    self.assertIs(bound, selected)
                    self.assertIs(error[1], original)
                    self.assertIs(diagnostic.CURRENT, selected)
                    events.append("emit")
                    if failed_projection:
                        raise KeyboardInterrupt("PRIVATE optional writer")

                namespace = {"matrix_diagnostic": diagnostic, "_phase": inner}
                exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
                with patch.object(diagnostic, "emit", emit), patch.object(diagnostic, "CURRENT", object()):
                    with self.assertRaises(ValueError) as caught:
                        namespace["phase"](object(), {})
                    self.assertIs(caught.exception, original)
                    self.assertIsNone(diagnostic.CURRENT)
                    self.assertEqual(events, ["original-finally", "emit"])
                    namespace["_phase"] = lambda *_args: 0
                    self.assertEqual(namespace["phase"](object(), {}), 0)
                    self.assertIsNone(diagnostic.CURRENT)
                    self.assertEqual(events, ["original-finally", "emit"])

    def test_failed_unknown_expired_and_optional_parser_error_never_read_outputs_or_become_pass(self):
        tests = controller_tests.SigningMatrixControllerTests()
        for mode in ("failure", "unknown", "parser-error", "expired", "marker-on-zero"):
            with self.subTest(mode=mode):
                rig = tests.rig()
                identifier = next(value for value in rig.selected
                                  if rig.contract.layered_catalog().case(value, "ubuntu-24.04").kind == "regression")
                value = {"schema": 1, "phase": "source", "caseId": identifier, "stage": "helper",
                         "category": "assertion-error", "locations": [],
                         "originalGFailure": {"category": "os-error", "locations": []}}
                packet = diagnostic.PREFIX.encode() + rig.contract.canonical(value) + b"\n"
                rig.capture_changes["source"] = {"stderr": packet}
                if mode != "marker-on-zero":
                    rig.capture_changes["source"].update(ok=False, returncode=73)
                if mode == "unknown":
                    rig.capture_changes["source"].update(waited=False, stdout_eof=False, domain_finality=False)
                    rig.idle_error = True
                if mode == "expired":
                    original_idle = rig.session.ensure_idle

                    def expire(*, deadline):
                        original_idle(deadline=deadline)
                        if rig.captures:
                            rig.clock = deadline + 1.0

                    rig.session.ensure_idle = expire
                parser = patch.object(rig.controller, "signing_matrix_failure", side_effect=RuntimeError("PRIVATE parser")) \
                    if mode == "parser-error" else nullcontext()
                with parser:
                    result = tests.execute(rig)
                self.assertFalse(result.ok)
                self.assertEqual(result.error, "MATRIX_PHASE_CAPTURE_RECORD" if mode == "marker-on-zero"
                                 else "COMMAND_EXIT_OR_FINALITY")
                self.assertEqual(len(rig.captures), 1)
                run = next(index for index, event in enumerate(rig.events) if event[0] == "run")
                self.assertFalse(any(event[0] in {"read", "finalized", "publish"} for event in rig.events[run + 1:]))
                row = result.details["phases"][0]
                self.assertEqual(row["status"], "FAIL")
                self.assertEqual("matrix_failure" in row, mode in {"failure", "unknown"})
                if mode in {"failure", "unknown"}:
                    self.assertEqual(row["matrix_failure"], value)
                if mode in {"expired", "parser-error"}:
                    self.assertEqual(row["matrix_diagnostic_error"], {"error": "SIGNING_MATRIX_DIAGNOSTIC_UNAVAILABLE"})
                if mode == "unknown":
                    self.assertIs(row["capture"]["domain_finality"], False)
                    self.assertIn("idle_error", row)
                self.assertNotIn("PRIVATE", json.dumps(result.details))

    def test_matrix_scope_cannot_admit_adapter_wrong_os_shard_or_deadline(self):
        rig = controller_tests.SigningMatrixControllerTests().rig()
        scope = rig.controller.SigningMatrixDiagnostic("source", "ubuntu-24.04", 0,
                                                       tuple(rig.selected), (), ())
        original = rig.controller.matrix_phase_argv(rig.paths, rig.selection, "source", deadline=20.0)
        variants = []
        for flag, value in (("--phase", "wheel"), ("--os", "macos-26"), ("--shard", "1"), ("--deadline", "21.0")):
            argv = list(original)
            argv[argv.index(flag) + 1] = value
            variants.append(argv)
        variants.extend([list(original) + ["--phase", "source"], list(original) + ["--adapter-phase", "source"]])
        with rig.scope_context():
            for argv in variants:
                with self.subTest(argv=argv[-2:]), self.assertRaisesRegex(rig.controller.VerificationError,
                                                                          "SIGNING_MATRIX_DIAGNOSTIC_SCOPE"):
                    rig.controller.original_native_capture(rig.session, argv, rig.paths, [], "source",
                        deadline=20.0, seconds=420, env={}, signing_matrix_diagnostic=scope)
        self.assertEqual(rig.events, [])
