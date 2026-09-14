"""Inert optional matrix/G diagnostics; no native/process or coverage evidence."""
from __future__ import annotations

import ast
import copy
import dataclasses
import io
import json
import linecache
from contextlib import contextmanager, nullcontext
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import local_signing_matrix_diagnostic as diagnostic
from . import local_signing_matrix_contract as contract
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


def context(bindings=()):
    return diagnostic.Phase("source", 20.0, "ubuntu-24.04", 0, IDS, (IDS[1],), SOURCE_MAP, bindings)


def wire(value, *, worker=False):
    return ((diagnostic.WORKER_PREFIX if worker else diagnostic.PREFIX)
            + json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


@contextmanager
def original_g_worker(selected):
    """Inert original fork-copy shape; never a process/finality receipt."""
    diagnostic.mark("helper", IDS[1])
    launcher = diagnostic.prepare_worker("regression", 18.0)
    worker = copy.copy(launcher)
    worker.budget = list(launcher.budget)
    parent = diagnostic.os.getpid()
    with patch.object(diagnostic, "CURRENT_WORKER", None), \
            patch.object(diagnostic, "os", SimpleNamespace(getpid=lambda: parent + 1)):
        diagnostic.enter_worker(worker)
        yield launcher, worker


class MatrixDiagnosticTests(unittest.TestCase):
    def test_profile_capture_uses_original_result_only_after_failure_latch_with_shared_bounds(self):
        bindings = ((IDS[1], "profile-signal", ("mutation-search",)),)
        reported = ('Traceback (most recent call last):\n'
                    '  File "/fixed/outer.py", line 7, in outer\n'
                    '    PRIVATE source text\n'
                    '  File "/PRIVATE/ignored.py", line 8, in ignored\n'
                    '  File "/fixed/original.py", line 9, in original\n'
                    'ValueError: PRIVATE message\n')
        controller = controller_module()
        scope = controller.SigningMatrixDiagnostic("source", "ubuntu-24.04", 0, IDS, (IDS[1],),
                                                    tuple(pair[1] for pair in SOURCE_MAP), bindings)
        for mode in ("captured", "empty", "oversized", "too-many-lines", "malformed-frame", "wrong-mode",
                     "stale", "formatted-only", "projection-error"):
            with self.subTest(mode=mode), patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                    patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 10.0)):
                selected, output = context(bindings), io.StringIO()
                first = error_tuple(SOURCE_MAP[1][0], depth=80, category="AssertionError")
                stderr = {"empty": "", "oversized": "x" * 8193 + "\n",
                          "too-many-lines": reported + "PRIVATE\n" * 32,
                          "malformed-frame": reported.replace('line 7', 'line ?')}.get(mode, reported)
                captured = CompletedProcess(["PRIVATE argv"], 1, "\u00e9", stderr)
                result = RegressionResult(unittest.FunctionTestCase(lambda: None), deadline=20.0)
                project, visits, locations = diagnostic._profile_child, [], diagnostic._locations

                def checked(bound, exception):
                    self.assertTrue(result.regression_failed and result.shouldStop)
                    self.assertEqual(result.first_failure, "failure")
                    self.assertIs(exception, first[1])
                    if mode == "projection-error":
                        raise MemoryError("PRIVATE optional projection")
                    return project(bound, exception)

                def counted(frame, source_map, budget, maximum):
                    before = budget[0]
                    value = locations(frame, source_map, budget, maximum)
                    visits.append(before - budget[0])
                    return value

                with patch.object(diagnostic, "CURRENT", selected), \
                        patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)), \
                        patch.object(diagnostic, "_profile_child", checked), patch.object(diagnostic, "_locations", counted):
                    with original_g_worker(selected) as (launcher, worker):
                        if mode == "formatted-only":
                            first[1].args = (reported,)  # Formatted assertions are never capture authority.
                        else:
                            diagnostic.attach_profile_capture(first[1], captured,
                                                              "foreign" if mode == "wrong-mode" else "mutation-search")
                        if mode == "captured":
                            self.assertIs(vars(first[1])[diagnostic._PROFILE_CAPTURE][3], captured)
                        self.assertIsNone(selected.child)
                        if mode == "stale":
                            retained = vars(first[1])[diagnostic._PROFILE_CAPTURE]
                            vars(first[1])[diagnostic._PROFILE_CAPTURE] = (object(), *retained[1:])
                        result.reject("failure", first)
                        record = diagnostic.emit_worker(worker, error_tuple(SOURCE_MAP[0][0], depth=80))
                    outer = error_tuple(SOURCE_MAP[0][0], depth=80)
                    diagnostic.attach_case_capture(outer[1], launcher, (0, 91, 0, True, False))
                    parent = diagnostic.emit(selected, outer)
                self.assertEqual(record["originalGFailure"]["category"], "assertion-error")
                self.assertEqual(controller.signing_matrix_failure(output.getvalue().encode("ascii"), scope,
                                                                  deadline=20.0), {**parent, "workerFailure": record})
                self.assertNotIn("PRIVATE", output.getvalue())
                if mode in {"wrong-mode", "stale", "formatted-only", "projection-error"}:
                    self.assertIsNone(record["child"])
                else:
                    child = record["child"]
                    self.assertEqual((child["returncode"], child["stdoutBytes"], child["stderrBytes"]),
                                     (1, 2, len(stderr.encode("utf-8"))))
                    self.assertEqual(child["stderrKind"], "stderr-reported" if mode == "captured" else
                                     "empty" if mode == "empty" else "unavailable")
                    if mode == "captured":
                        self.assertEqual(child["locations"], [{"file": SOURCE_MAP[0][1], "line": 7},
                                                              {"file": SOURCE_MAP[1][1], "line": 9}])
                        self.assertEqual(record["locations"], [])
                        self.assertEqual(visits, [16, 0, 0])  # W/L zero remaining location capacity stays zero.
                        self.assertEqual(worker.budget, [0])
                        self.assertEqual(parent["locations"], [])
                        self.assertIsNone(parent["originalGFailure"])

    def test_semantic_worker_and_original_launcher_are_separate_bounded_correlated_data(self):
        bindings = ((IDS[0], "semantic-worker", ("seed", "semantic-main", "semantic-resolution")),)
        controller = controller_module()
        scope = controller.SigningMatrixDiagnostic("source", "ubuntu-24.04", 0, IDS, (IDS[1],),
                                                    tuple(pair[1] for pair in SOURCE_MAP), bindings)
        pid, output, visits = [7], io.StringIO(), []
        locations = diagnostic._locations

        def counted(frame, source_map, budget, maximum):
            before = budget[0]
            result = locations(frame, source_map, budget, maximum)
            visits.append(before - budget[0])
            return result

        with patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                patch.object(diagnostic, "os", SimpleNamespace(getpid=lambda: pid[0])), \
                patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)), \
                patch.object(diagnostic, "_locations", counted):
            selected = context(bindings)
            with patch.object(diagnostic, "CURRENT", selected):
                diagnostic.mark("helper", IDS[0])
                launcher = diagnostic.prepare_worker("semantic-main", 18.0)
                worker = copy.copy(launcher)  # Inert separate memory; no fork/process is executed.
                pid[0] = 8
                diagnostic.enter_worker(worker)
                worker_error = error_tuple(SOURCE_MAP[1][0], depth=80)
                observed = diagnostic.emit_worker(worker, worker_error)
                self.assertIsNone(diagnostic.emit_worker(worker, worker_error))
                pid[0] = 7
                self.assertIsNone(launcher.pid)  # No W-local memory is consulted by the launcher.
                original = error_tuple(SOURCE_MAP[0][0], depth=80, category="AssertionError")
                diagnostic.attach_case_capture(original[1], launcher, (0, 91, 0, True, False))
                record = diagnostic.emit(selected, original)
            self.assertEqual(visits, [16, 48])
            self.assertEqual(selected.budget, [0])
            self.assertEqual(record["child"], {"role": "semantic-worker", "step": "semantic-main",
                "expectedExit": 0, "workerExit": 91, "anchorExit": 0, "terminalParsed": True, "anchorExpired": False})
            parse = lambda raw: controller.signing_matrix_failure(raw, scope, deadline=20.0)
            worker_wire, main_wire = wire(observed, worker=True), wire(record)
            self.assertEqual(output.getvalue().encode("ascii"), worker_wire + main_wire)
            self.assertEqual(parse(worker_wire + main_wire), {**record, "workerFailure": observed})
            self.assertEqual(parse(main_wire), record)  # Missing W remains unknown, never guessed from91.
            self.assertEqual(sum(len(value["locations"]) for value in (observed, record)), 4)
            self.assertLessEqual(len(worker_wire), 768)
            self.assertLessEqual(len(main_wire), 1280)
            self.assertLessEqual(len(worker_wire + main_wire), 2048)
            self.assertNotIn(b"PRIVATE", worker_wire + main_wire)
            for invalid in (worker_wire, main_wire + worker_wire, worker_wire * 2 + main_wire,
                            worker_wire + main_wire * 2,
                            wire({**observed, "caseId": IDS[1]}, worker=True) + main_wire,
                            wire({**observed, "step": "seed"}, worker=True) + main_wire,
                            wire({**observed, "phase": "wheel"}, worker=True) + main_wire,
                            wire({**observed, "message": "PRIVATE"}, worker=True) + main_wire,
                            wire({**observed, "schema": True}, worker=True) + main_wire,
                            wire({**observed, "locations": observed["locations"] * 2}, worker=True) + main_wire,
                            worker_wire + wire({**record, "child": None}),
                            worker_wire + wire({**record, "child": {**record["child"], "workerExit": None}})):
                self.assertIsNone(parse(invalid))

    def test_prebound_semantic_quota_survives_missing_optional_tuple_and_worker_writer_failure(self):
        bindings = ((IDS[0], "semantic-worker", ("semantic-main",)),)
        controller = controller_module()
        scope = controller.SigningMatrixDiagnostic("source", "ubuntu-24.04", 0, IDS, (IDS[1],),
                                                    tuple(pair[1] for pair in SOURCE_MAP), bindings)
        pid, writes = [7], []

        def broken_write(value):
            writes.append(value)
            raise OSError("PRIVATE optional writer")

        with patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                patch.object(diagnostic, "os", SimpleNamespace(getpid=lambda: pid[0])):
            selected, output = context(bindings), io.StringIO()
            with patch.object(diagnostic, "CURRENT", selected):
                diagnostic.mark("helper", IDS[0])
                worker = diagnostic.prepare_worker("semantic-main", 18.0)
                self.assertIsNone(diagnostic.prepare_worker("foreign-step", 18.0))
                pid[0] = 8
                diagnostic.enter_worker(worker)
                with patch.object(diagnostic, "sys", SimpleNamespace(stderr=SimpleNamespace(write=broken_write))):
                    error = error_tuple(SOURCE_MAP[1][0], depth=80)
                    self.assertIsNone(diagnostic.emit_worker(worker, error))
                    self.assertIsNone(diagnostic.emit_worker(worker, error))
                pid[0] = 7
                with patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)), \
                        patch.object(diagnostic, "_case_child", side_effect=MemoryError("PRIVATE optional attachment")):
                    record = diagnostic.emit(selected, error_tuple(SOURCE_MAP[0][0], depth=80))
            self.assertEqual(len(writes), 1)
            self.assertIsNone(record["child"])
            self.assertEqual(len(record["locations"]), 2)
            self.assertLessEqual(len(output.getvalue().encode("ascii")), 1280)
            self.assertEqual(controller.signing_matrix_failure(wire(record), scope, deadline=20.0), record)
            self.assertIsNone(controller.signing_matrix_failure(
                wire({**record, "locations": record["locations"] + record["locations"][:1]}), scope, deadline=20.0))
            long_file = "tests/" + "a" * 247 + ".py"
            large = {"schema": 1, "phase": "source", "caseId": IDS[0], "step": "semantic-main",
                     "category": "assertion-error", "locations": [{"file": long_file, "line": 999999}] * 2}
            self.assertGreater(len(wire(large, worker=True)), 768)
            self.assertIsNone(controller.signing_matrix_failure(wire(large, worker=True) + wire(record),
                dataclasses.replace(scope, files=(*scope.files, long_file)), deadline=20.0))

    def test_prelaunch_child_bindings_come_from_actual_case_modes_and_all_mac9_steps(self):
        with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            catalog = contract.layered_catalog()
            for operating_system, shard in (("ubuntu-24.04", 12), ("ubuntu-24.04", 11), ("macos-26", 12), ("macos-26", 7)):
                bindings = contract.diagnostic_child_bindings(operating_system, shard, deadline=20.0)
                self.assertEqual(len({row[0] for row in bindings}), len(bindings))
                for identifier, role, selectors in bindings:
                    self.assertIn(identifier, catalog.shard_ids(operating_system, shard))
                    item = catalog.case(identifier, operating_system)
                    if role == "profile-signal":
                        original = catalog.REGRESSION.case(item.name)
                        self.assertEqual((original.helper, selectors), (role, (original.variant,)))
                    else:
                        self.assertEqual(item.kind, "semantic")
            # Original Mac9 failure keeps its identity, not its old cost packing.
            failed = "1b95d952a4fca459d9699aaf1173a4e0145a738a7a99b2fb13a77596760648b8"
            shard, = (index for index in range(catalog.SHARDS) if failed in catalog.shard_ids("macos-26", index))
            bindings = dict((identifier, (role, selectors)) for identifier, role, selectors in
                            contract.diagnostic_child_bindings("macos-26", shard, deadline=20.0))
            self.assertEqual(bindings[failed],
                             ("semantic-worker", ("seed", "semantic-main", "semantic-resolution")))

    def test_original_profile_and_postcleanup_launcher_hook_failures_preserve_identical_exception(self):
        unit = Path(__file__).parents[1] / "unit/test_ios_profile_installation.py"
        unit_tree = ast.parse(unit.read_text(), str(unit))
        boundary = next(node for node in ast.walk(unit_tree)
                        if isinstance(node, ast.FunctionDef) and node.name == "run_boundary")
        assertion = next(node for node in boundary.body if isinstance(node, ast.Try))
        path = Path(__file__).with_name("local_signing_case_owner.py")
        tree = ast.parse(path.read_text(), str(path))
        launcher = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_worker")
        attachment = next(node for node in launcher.body if isinstance(node, ast.Try)
                          and any(isinstance(child, ast.Attribute) and child.attr == "attach_case_capture"
                                  for child in ast.walk(node)))
        prepare = next(node for node in launcher.body if isinstance(node, ast.Try)
                       and any(isinstance(child, ast.Attribute) and child.attr == "prepare_worker"
                               for child in ast.walk(node)))
        for failed_hook in (False, True):
            with self.subTest(failed_hook=failed_hook):
                original, calls = AssertionError("PRIVATE original assertion"), []
                process, worker = CompletedProcess(["PRIVATE"], 1, "", "PRIVATE stderr"), object()

                def offer(*args):
                    self.assertIs(args[0], original)
                    calls.append(args)
                    if failed_hook:
                        raise KeyboardInterrupt("PRIVATE optional hook")

                def fail(*_args):
                    raise original

                with patch.object(diagnostic, "attach_profile_capture", offer), self.assertRaises(AssertionError) as caught:
                    exec(compile(ast.Module(body=[assertion], type_ignores=[]), str(unit), "exec"),
                         {"self": SimpleNamespace(assertEqual=fail), "process": process, "mode": "mutation-search"})
                self.assertIs(caught.exception, original)
                self.assertEqual(calls, [(original, process, "mutation-search")])
                calls.clear()
                namespace = {"primary": original, "cleanup_errors": [], "matrix_context": worker,
                    "matrix_diagnostic": SimpleNamespace(attach_case_capture=offer), "expect": 0,
                    "worker_code": 91, "anchor_code": 0, "settled": True, "anchor_expired": False,
                    "ADAPTER_DIAGNOSTIC_CONTEXT": None}
                with self.assertRaises(AssertionError) as caught:
                    exec(compile(ast.Module(body=[attachment], type_ignores=[]), str(path), "exec"), namespace)
                self.assertIs(caught.exception, original)
                self.assertEqual(calls, [(original, worker, (0, 91, 0, True, False))])
                self.assertEqual(original._case_cleanup_errors, ())
                namespace = {"matrix_diagnostic": SimpleNamespace(prepare_worker=fail), "name": "seed", "hard": 20.0}
                exec(compile(ast.Module(body=[prepare], type_ignores=[]), str(path), "exec"), namespace)
                self.assertIsNone(namespace["matrix_context"])

    def test_actual_worker_latches_error_before_optional_hooks_and_keeps_original_cleanup(self):
        path = Path(__file__).with_name("local_signing_case_owner.py")
        tree = ast.parse(path.read_text(), str(path))
        worker = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_worker")
        lifetime = next(node for node in worker.body if isinstance(node, ast.Try))
        latch = lifetime.handlers[0].body[0]
        self.assertIsInstance(latch, ast.Assign)
        self.assertEqual((latch.targets[0].id, latch.value.id), ("code", "WORKER_ERROR"))

        class InertExit(BaseException):
            pass

        for broken in ("enter_worker", "emit_worker", None):
            with self.subTest(broken=broken):
                events, original = [], ValueError("PRIVATE original W failure")

                def enter(_context):
                    events.append("enter")
                    if broken == "enter_worker":
                        raise KeyboardInterrupt("PRIVATE enter")

                def emit(_context, error):
                    self.assertIs(error[1], original)
                    events.append("emit")
                    if broken == "emit_worker":
                        raise KeyboardInterrupt("PRIVATE emit")

                def task():
                    events.append("task")
                    raise original

                def receive(_fd, data, _deadline):
                    data.extend(b"RUN\n")
                    return True

                def leave(code):
                    raise InertExit(code)

                def require(value, _message):
                    self.assertTrue(value)

                namespace = {"WORKER_ERROR": 91, "matrix_diagnostic": SimpleNamespace(enter_worker=enter, emit_worker=emit),
                    "os": SimpleNamespace(getppid=lambda: 7, getpgrp=lambda: 8, _exit=leave),
                    "require": require, "send": lambda *_: None, "receive": receive, "remaining": lambda _: 1,
                    "ADAPTER_DIAGNOSTIC_CONTEXT": None, "adapter_progress": lambda *_: None,
                    "emit_adapter_failure": lambda *_args, **_kwargs: events.append("original-adapter-projection"),
                    "traceback": SimpleNamespace(format_exc=lambda: "PRIVATE original error projection")}
                exec(compile(ast.Module(body=[worker], type_ignores=[]), str(path), "exec"), namespace)
                handles = SimpleNamespace(errors=[], close_except=lambda *_: events.append("close"),
                                          get=lambda _: 123, close=lambda _: None)
                with self.assertRaises(InertExit) as caught:
                    namespace["_worker"](handles, 7, 8, Path("/not-created"), "semantic-main", task, 20.0,
                        lambda path, _value: events.append(path.name), hard=25.0, matrix_context=object())
                self.assertEqual(caught.exception.args, (91,))
                self.assertEqual(events, ["close", "enter", "task", "emit", "original-adapter-projection",
                                          "semantic-main-error.json", "close"])

    def test_actual_producer_and_independent_parser_agree_on_closed_optional_schema(self):
        controller = controller_module()
        scope = controller.SigningMatrixDiagnostic("source", "ubuntu-24.04", 0, IDS, (IDS[1],),
                                                    tuple(pair[1] for pair in SOURCE_MAP))
        outer = error_tuple(SOURCE_MAP[0][0])
        clock = SimpleNamespace(monotonic=lambda: 10.0)
        with patch.object(diagnostic, "time", clock), patch.object(controller, "time", clock):
            selected, output = context(), io.StringIO()
            with patch.object(diagnostic, "CURRENT", selected), patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
                with original_g_worker(selected) as (launcher, worker):
                    diagnostic.original_g_failure(error_tuple(SOURCE_MAP[1][0], category="AssertionError"))
                    worker_record = diagnostic.emit_worker(worker, outer)
                self.assertIsNone(selected.g_failure)
                self.assertIsNone(launcher.g_failure)
                self.assertEqual(launcher.budget, [64])
                diagnostic.attach_case_capture(outer[1], launcher, (0, 91, 0, True, False))
                record = diagnostic.emit(selected, outer)
                self.assertIsNone(diagnostic.emit(selected, outer))
            packet = output.getvalue().encode("ascii")
            parse = lambda raw: controller.signing_matrix_failure(raw, scope, deadline=20.0)
            projected = {**record, "workerFailure": worker_record}
            worker_wire = wire(worker_record, worker=True)
            self.assertEqual(parse(packet), projected)
            self.assertEqual(parse(wire(record)), record)  # Missing W remains UNKNOWN diagnostic DATA.
            self.assertEqual(parse(wire({**record, "child": None})), {**record, "child": None})
            self.assertIsNotNone(worker_record["originalGFailure"])
            self.assertIsNone(record["originalGFailure"])
            self.assertLessEqual(len(worker_wire), 1536)
            self.assertLessEqual(len(wire(record)), 512)
            self.assertLessEqual(len(packet), 2048)
            self.assertEqual(packet.count(diagnostic.PREFIX.encode()), 1)
            self.assertNotIn(b"PRIVATE", packet)

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
                    self.assertIsNone(parse(worker_wire + wire({**record, **mutation})))
            for mutation in ({"role": "semantic-worker"}, {"step": "seed"}, {"caseId": IDS[0]},
                             {"schema": 1}, {"schema": True}, {"message": "PRIVATE"},
                             {"locations": worker_record["locations"] * 4},
                             {"child": {"role": "profile-signal"}},
                             {"originalGFailure": {"category": "value-error", "locations": [], "extra": 0}}):
                with self.subTest(worker_mutation=mutation):
                    self.assertIsNone(parse(wire({**worker_record, **mutation}, worker=True) + wire(record)))
            missing = copy.deepcopy(record)
            del missing["originalGFailure"]
            for invalid in (wire(missing), worker_wire, wire(record) + worker_wire, worker_wire + packet,
                            worker_wire + wire({**record, "child": None}),
                            packet + packet, packet[:-1], bytearray(packet), b"x" * 65537,
                            packet.replace(b'"schema":2', b'"schema":2,"schema":2'),
                            packet.replace(b"{", b"{ ", 1), diagnostic.PREFIX.encode() + b" " * 2048 + b"\n"):
                self.assertIsNone(parse(invalid))
            self.assertEqual(parse(b"PRIVATE unrelated stderr\n" + packet), projected)
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
                with original_g_worker(selected) as (launcher, worker):
                    diagnostic.original_g_failure(first)
                    record = diagnostic.emit_worker(worker, outer)
                diagnostic.attach_case_capture(outer[1], launcher, (0, 91, 0, True, False))
                parent = diagnostic.emit(selected, outer)
            self.assertEqual(visits, [16, 16, 0])
            self.assertEqual(worker.budget, [32])  # Unused profile-line reservation is never reused.
            self.assertEqual(len(record["originalGFailure"]["locations"]), 2)
            self.assertEqual(len(record["locations"]), 2)
            self.assertEqual(parent["locations"], [])
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

                with patch.object(diagnostic, "CURRENT", selected), original_g_worker(selected) as (_launcher, worker):
                    with patch.object(diagnostic, "_locations", project):
                        if mode == "failure":
                            result.addFailure(test, first)
                        elif mode == "subtest":
                            result.addSubTest(test, test, first)
                        elif mode == "missing-first-tuple":
                            result.addSkip(test, "PRIVATE skip")
                        else:
                            result.addError(test, first)
                        preserved = result.first_failure
                        original = copy.deepcopy(worker.g_failure)
                        result.addError(test, later)
                        result.addFailure(test, later)
                    self.assertEqual(result.first_failure, preserved)
                    self.assertEqual(worker.g_failure, original)
                    self.assertTrue(worker.g_seen)
                    self.assertEqual(worker.budget, [48])
                    self.assertEqual(len(calls), int(mode != "missing-first-tuple"))
                    if mode in {"missing-first-tuple", "projection-error"}:
                        self.assertIsNone(original)
                    else:
                        self.assertEqual(original["category"], "assertion-error")
                    output = io.StringIO()
                    with patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
                        outer = diagnostic.emit_worker(worker, error_tuple(SOURCE_MAP[0][0]))
                    self.assertEqual(outer["originalGFailure"], original)
                    self.assertEqual(outer["category"], "value-error")

    def test_g_callbacks_require_original_worker_pid_thread_case_and_unrenewed_deadline(self):
        bindings = ((IDS[1], "profile-signal", ("mutation-search",)),)
        original = error_tuple(SOURCE_MAP[1][0], category="AssertionError")
        capture = CompletedProcess(["PRIVATE"], 1, "", "")
        for mode in ("parent", "nested-pid", "thread", "context", "expired"):
            with self.subTest(mode=mode), patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 10.0)):
                selected = context(bindings)
                with patch.object(diagnostic, "CURRENT", selected):
                    diagnostic.mark("helper", IDS[1])
                    self.assertIsNone(diagnostic.prepare_worker("seed", 18.0))
                    if mode == "parent":
                        diagnostic.original_g_failure(original)
                        diagnostic.attach_profile_capture(original[1], capture, "mutation-search")
                        self.assertFalse(selected.g_seen)
                    else:
                        with original_g_worker(selected) as (_launcher, worker):
                            if mode == "nested-pid":
                                changed = patch.object(diagnostic, "os", SimpleNamespace(getpid=lambda: worker.pid + 1))
                            elif mode == "thread":
                                changed = patch.object(diagnostic, "threading", SimpleNamespace(current_thread=lambda: object()))
                            elif mode == "context":
                                changed = patch.object(diagnostic, "CURRENT", object())
                            else:
                                changed = patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 18.0))
                            with changed:
                                diagnostic.attach_profile_capture(original[1], capture, "mutation-search")
                                diagnostic.original_g_failure(original)
                            self.assertIsNone(worker.g_failure)
                            self.assertEqual(worker.deadline, 18.0)
                            self.assertEqual(worker.g_seen, mode == "expired")
                    self.assertNotIn(diagnostic._PROFILE_CAPTURE, vars(original[1]))

        writes = []
        with patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            selected = context(bindings)
            with patch.object(diagnostic, "CURRENT", selected), original_g_worker(selected) as (_launcher, worker):
                diagnostic.original_g_failure(original)

                def fail_write(value):
                    writes.append(value)
                    raise OSError("PRIVATE optional output")

                with patch.object(diagnostic, "sys", SimpleNamespace(stderr=SimpleNamespace(write=fail_write))):
                    self.assertIsNone(diagnostic.emit_worker(worker, original))
                    self.assertIsNone(diagnostic.emit_worker(worker, original))
                self.assertTrue(worker.emitted)
                self.assertEqual(len(writes), 1)
                self.assertLessEqual(len(writes[0].encode("ascii")), 1536)

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
                value = {"schema": 2, "phase": "source", "caseId": identifier, "stage": "helper",
                         "category": "assertion-error", "locations": [],
                         "originalGFailure": None,
                         "child": {"role": "regression-worker", "step": "regression", "expectedExit": 0,
                                   "workerExit": 91, "anchorExit": 0, "terminalParsed": True, "anchorExpired": False}}
                worker = {"schema": 2, "phase": "source", "caseId": identifier, "step": "regression",
                          "role": "regression-worker", "category": "assertion-error", "locations": [],
                          "originalGFailure": {"category": "os-error", "locations": []}, "child": None}
                packet = wire(worker, worker=True) + wire(value)
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
                    self.assertEqual(row["matrix_failure"], {**value, "workerFailure": worker})
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
