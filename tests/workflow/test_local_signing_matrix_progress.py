"""Inert matrix progress DATA; no process, filesystem, native or CI receipt."""
from __future__ import annotations

import dataclasses
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import local_signing_matrix_diagnostic as diagnostic
from .test_ci_verification import controller_module


IDS = ("1" * 64, "2" * 64)
SOURCE_MAP = (("/fixed/phase.py", "tests/workflow/run_local_signing_matrix.py"),)


def packet(**changes):
    value = {"schema": 1, "phase": "source", "caseId": IDS[0], "ordinal": 1,
             "event": "helper-start", "elapsedMs": 0}
    value.update(changes)
    return b"MRK_SIGNING_MATRIX_PROGRESS=" + json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


class MatrixProgressTests(unittest.TestCase):
    def test_original_phase_emits_only_ordered_bound_data_from_its_original_pid_and_thread(self):
        controller = controller_module()
        thread, pid, clock, output = [object()], [7], [10.0], io.StringIO()
        owner_thread = thread[0]
        scope = controller.SigningMatrixDiagnostic("source", "ubuntu-24.04", 47, IDS, (), ())
        with patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: clock[0])), \
                patch.object(controller, "time", SimpleNamespace(monotonic=lambda: clock[0])), \
                patch.object(diagnostic, "os", SimpleNamespace(getpid=lambda: pid[0])), \
                patch.object(diagnostic, "threading", SimpleNamespace(current_thread=lambda: thread[0])), \
                patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
            context = diagnostic.Phase("source", 20.0, "ubuntu-24.04", 47, IDS, (), SOURCE_MAP)
            with patch.object(diagnostic, "CURRENT", context):
                pid[0] = 8
                diagnostic.mark("helper", IDS[0])
                pid[0] = 7
                thread[0] = object()
                diagnostic.mark("helper", IDS[0])
                thread[0] = owner_thread
                self.assertEqual((context.progress_attempts, output.getvalue()), (0, ""))
                diagnostic.mark("admission")
                for identifier in IDS:
                    diagnostic.mark("helper", identifier)
                    clock[0] += .25
                    diagnostic.mark("typed-result", identifier)
                    diagnostic.mark("persist", identifier)
                    diagnostic.mark("cleanup", identifier)
                diagnostic.mark("publication")
                diagnostic.mark("helper", IDS[0])  # A completed sequence cannot restart.
            raw = output.getvalue().encode("ascii")
            lines = raw.splitlines(keepends=True)
            self.assertEqual(len(lines), 4)
            self.assertEqual(lines, [packet(), packet(event="helper-returned", elapsedMs=250),
                                    packet(caseId=IDS[1], ordinal=2, elapsedMs=250),
                                    packet(caseId=IDS[1], ordinal=2, event="helper-returned", elapsedMs=500)])
            self.assertEqual(context.progress_attempts, 4)
            self.assertEqual(context.progress_bytes, len(raw))
            self.assertFalse(context.progress_available)
            self.assertEqual((context.deadline, context.budget), (20.0, [48]))
            for length in range(5):
                with self.subTest(prefix_events=length):
                    observed = controller.signing_matrix_progress(b"".join(lines[:length]), scope, deadline=20.0)
                    self.assertEqual(observed, {"eventCount": length, "lastEvent": (
                        json.loads(lines[length - 1].split(b"=", 1)[1]) if length else None)})

    def test_progress_failure_is_absorbing_charged_before_io_and_does_not_disable_original_failure_data(self):
        for mode in ("write", "short-write", "flush", "format", "line-bound", "byte-bound", "wrong-order", "expired"):
            with self.subTest(mode=mode):
                writes, clock = [], [10.0]

                def write(value):
                    self.assertEqual(context.progress_attempts, 1)
                    self.assertFalse(context.progress_available)
                    self.assertEqual(context.progress_bytes, len(value.encode("ascii")))
                    writes.append(value)
                    if mode == "write":
                        raise OSError("PRIVATE writer failure")
                    return 0 if mode == "short-write" else len(value)

                def flush():
                    if mode == "flush":
                        raise KeyboardInterrupt("PRIVATE optional flush")

                def dumps(*args, **kwargs):
                    if mode == "format":
                        raise MemoryError("PRIVATE formatter failure")
                    if mode == "line-bound":
                        return " " * 256
                    return json.dumps(*args, **kwargs)

                with patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: clock[0])):
                    context = diagnostic.Phase("source", 20.0, "ubuntu-24.04", 0, IDS, (), SOURCE_MAP)
                    if mode == "byte-bound":
                        context.progress_bytes = 16 * 1024
                    if mode == "expired":
                        clock[0] = 20.0
                    with patch.object(diagnostic, "CURRENT", context), \
                            patch.object(diagnostic, "json", SimpleNamespace(dumps=dumps)), \
                            patch.object(diagnostic, "sys", SimpleNamespace(stderr=SimpleNamespace(write=write, flush=flush))):
                        diagnostic.mark("helper", IDS[int(mode == "wrong-order")])
                        diagnostic.mark("typed-result", IDS[0])
                        diagnostic.mark("helper", IDS[1])
                    self.assertEqual(context.progress_attempts, 1)
                    self.assertEqual(len(writes), int(mode in {"write", "short-write", "flush"}))
                    self.assertFalse(context.progress_available)
                    self.assertTrue(context.available)
                    self.assertEqual(context.deadline, 20.0)
                    if mode != "expired":
                        output = io.StringIO()
                        try:
                            raise ValueError("PRIVATE original exception")
                        except ValueError as error:
                            actual = (type(error), error, error.__traceback__)
                        with patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
                            failure = diagnostic.emit(context, actual)
                        self.assertEqual(failure["category"], "value-error")
                        self.assertEqual(failure["caseId"], IDS[1])
                        self.assertNotIn("PRIVATE", output.getvalue())

    def test_whole_selected_list_has_fixed_event_byte_line_and_elapsed_limits_without_replenishment(self):
        controller = controller_module()
        for count in (32, 33):
            with self.subTest(cases=count):
                identifiers = tuple(f"{value:064x}" for value in range(1, count + 1))
                output = io.StringIO()
                with patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                        patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                        patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
                    context = diagnostic.Phase("source", 430.0, "macos-26", 47, identifiers, (), SOURCE_MAP)
                    with patch.object(diagnostic, "CURRENT", context):
                        for identifier in identifiers:
                            diagnostic.mark("helper", identifier)
                            diagnostic.mark("typed-result", identifier)
                        diagnostic.mark("helper", identifiers[0])
                    raw = output.getvalue().encode("ascii")
                    self.assertEqual(context.progress_attempts, 64 if count == 32 else 0)
                    self.assertLessEqual(context.progress_bytes, 16 * 1024)
                    self.assertEqual(context.progress_bytes, len(raw))
                    self.assertTrue(all(len(line) <= 256 for line in raw.splitlines(keepends=True)))
                    scope = controller.SigningMatrixDiagnostic("source", "macos-26", 47, identifiers, (), ())
                    self.assertEqual(controller.signing_matrix_progress(raw, scope, deadline=20.0)["eventCount"],
                                     64 if count == 32 else 0)
                    if count == 32:
                        self.assertIsNone(controller.signing_matrix_progress(raw + raw[:raw.index(b"\n") + 1],
                                                                            scope, deadline=20.0))
                self.assertEqual(context.budget, [48])
        clock, output = [10.0], io.StringIO()
        with patch.object(diagnostic, "time", SimpleNamespace(monotonic=lambda: clock[0])), \
                patch.object(diagnostic, "sys", SimpleNamespace(stderr=output)):
            context = diagnostic.Phase("source", 500.0, "ubuntu-24.04", 0, IDS, (), SOURCE_MAP)
            clock[0] = 431.0
            with patch.object(diagnostic, "CURRENT", context):
                diagnostic.mark("helper", IDS[0])
            self.assertEqual(output.getvalue(), "")
            self.assertFalse(context.progress_available)

    def test_independent_parser_rejects_private_foreign_ambiguous_or_out_of_order_success_stderr(self):
        controller = controller_module()
        scope = controller.SigningMatrixDiagnostic("source", "ubuntu-24.04", 47, IDS, (), ())
        with patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            parse = lambda raw: controller.signing_matrix_progress(raw, scope, deadline=20.0)
            raw = packet()
            expected = {"eventCount": 1, "lastEvent": json.loads(raw.split(b"=", 1)[1])}
            self.assertEqual(parse(raw), expected)
            for changes in ({"schema": True}, {"schema": 2}, {"phase": "wheel"}, {"caseId": "3" * 64},
                            {"caseId": IDS[1]}, {"ordinal": True}, {"ordinal": 0}, {"ordinal": 2},
                            {"event": "helper-returned"}, {"event": "complete"}, {"event": False},
                            {"elapsedMs": True}, {"elapsedMs": -1}, {"elapsedMs": 420001},
                            {"message": "PRIVATE"}, {"pid": 7}, {"path": "/PRIVATE/path"}):
                with self.subTest(changes=changes):
                    self.assertIsNone(parse(packet(**changes)))
            returned = packet(event="helper-returned", elapsedMs=2)
            for invalid in (raw + raw, returned + raw, raw + returned + raw,
                            packet(elapsedMs=3) + returned, raw[:-1], raw + b"PRIVATE stderr\n",
                            b"PRIVATE stderr\n" + raw, raw + b"MRK_SIGNING_MATRIX_FAILURE={}\n",
                            raw.replace(b"{", b"{ ", 1), raw.replace(b'"schema":1', b'"schema":1,"schema":1'),
                            b"MRK_SIGNING_MATRIX_PROGRESS=" + b" " * 256 + b"\n", b"x" * 65537, bytearray(raw)):
                self.assertIsNone(parse(invalid))
            for changed in (dataclasses.replace(scope, phase="adapter"), dataclasses.replace(scope, shard=48),
                            dataclasses.replace(scope, shard=True), dataclasses.replace(scope, operating_system="foreign"),
                            dataclasses.replace(scope, identifiers=(IDS[0], IDS[0]))):
                self.assertIsNone(controller.signing_matrix_progress(raw, changed, deadline=20.0))
            self.assertEqual(controller.signing_matrix_progress(raw + b"PRIVATE trailing traceback\n", scope,
                                                               deadline=20.0, failed_capture=True), expected)
            self.assertIsNone(controller.signing_matrix_progress(b"PRIVATE prefix\n" + raw, scope,
                                                                deadline=20.0, failed_capture=True))
            self.assertIsNone(controller.signing_matrix_progress(raw + raw, scope, deadline=20.0, failed_capture=True))
        with patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 20.0)), \
                self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
            controller.signing_matrix_progress(raw, scope, deadline=20.0)


if __name__ == "__main__":
    unittest.main()
