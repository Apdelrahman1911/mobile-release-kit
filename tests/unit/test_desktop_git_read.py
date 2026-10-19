"""Inert protocol/closed adapter tests. NO Git/C/A/W/native process executes.

Source originals are synthetic task-owned files. Operation fixtures deliberately
replace only test DATA/clock/guard observations and fake the C/A/W return at the
unchanged original run_owned boundary. They do not qualify installed custody.
Shared hooks must be applied (or exactly projected) before running this module.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_read_protocol as wire
from mobile_release import git_repository_read as read
from mobile_release import git_service as core
from mobile_release._desktop_git_read_control import GitReadInput
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain
from mobile_release.cancellation import DefaultCancellation
from mobile_release.desktop_git_read import GitReadOperation, _Engine
from mobile_release.owned_process import ProcessCleanupError, run_owned
from test_git_repository_read import FakeGit, HEAD, UPSTREAM


def frame(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def fixture():
    def file(owner, mode=0o644, size=12):
        return {"identity": [1, 2, stat.S_IFREG | mode, owner, 1001, 1, size, 123, 456], "sha256": "a" * 64}
    directory = [1, 2, stat.S_IFDIR | 0o700, 1001, 1001]
    return {"protocol": wire.PROTOCOL, "id": "git-read-fixture",
        "action": {"kind": "observe", "expectedRevision": None, "paths": [], "staged": False},
        "context": {"projectId": "project-fixture", "generation": 1, "revision": "2"},
        "native": {"uid": 1001, "gid": 1001, "root": "/fixture/project",
            "directories": {name: list(directory) for name in ("root", "git", "objects")},
            "tool": file(0, 0o755), "files": {name: file(1001) for name in ("HEAD", "config", "index")}},
        "clock": {"workEndNs": 100_000_000_000, "hardEndNs": 110_000_000_000}}


class ProtocolTests(unittest.TestCase):
    def test_fixed_provider_no_path_or_command_fields_and_exact_actions(self):
        request = wire.parse_request(frame(fixture()))
        self.assertEqual(request.tool.path, Path("/Library/Developer/CommandLineTools/usr/bin/git"))
        self.assertEqual(request.action, wire.Action("observe", None, (), False))
        self.assertNotIn("/fixture", repr(request))
        for key, value in (("executable", "/usr/bin/git"), ("argv", ["fetch"]), ("environment", {}), ("authority", True)):
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                data = fixture(); data["native"][key] = value; wire.parse_request(frame(data))
        for name in ("add", "commit", "fetch", "push", "reset", "config", "log", "status", None, ["observe"]):
            with self.subTest(name=name), self.assertRaises(wire.ProtocolError):
                data = fixture(); data["action"]["kind"] = name; wire.parse_request(frame(data))

    def test_diff_history_require_exact_reviewed_revision_and_closed_paths(self):
        for name in ("diff", "history"):
            data = fixture(); data["action"].update(kind=name, expectedRevision="a" * 64,
                                                   paths=["a.txt"] if name == "diff" else [])
            request = wire.parse_request(frame(data))
            self.assertEqual(request.action.expected_revision, "a" * 64)
            for replacement in (None, "a" * 63, True, "a" * 63 + "\n"):
                with self.subTest(name=name, value=replacement), self.assertRaises(wire.ProtocolError):
                    data["action"]["expectedRevision"] = replacement; wire.parse_request(frame(data))
        for paths in ([], ["b", "a"], ["a", "a"], [".git/config"], ["../other"], ["/absolute"],
                      ["a\nsecret"], ["x/" * 33 + "a"], ["\ud800"], [str(i) for i in range(65)]):
            with self.subTest(paths=paths), self.assertRaises(wire.ProtocolError):
                data = fixture(); data["action"].update(kind="diff", expectedRevision="a" * 64, paths=paths)
                wire.parse_request(frame(data))

    def test_source_snapshots_require_actual_supported_layout_shapes(self):
        for field, value in (("uid", 0), ("root", "relative"), ("root", "/a/../b"),
                              ("root", "/a//b"), ("root", "/a/.git"), ("root", "/a\\b")):
            with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                data = fixture(); data["native"][field] = value; wire.parse_request(frame(data))
        for field, index, value in (("tool", 3, 1001), ("tool", 2, stat.S_IFREG | 0o4755),
                                    ("tool", 2, stat.S_IFLNK | 0o755), ("tool", 5, 2),
                                    ("tool", 6, wire.TOOL_LIMIT + 1), ("index", 6, core.MAX_INDEX_BYTES + 1)):
            with self.subTest(field=field, index=index), self.assertRaises(wire.ProtocolError):
                data = fixture()
                selected = data["native"][field] if field == "tool" else data["native"]["files"][field]
                selected["identity"][index] = value; wire.parse_request(frame(data))
        data = fixture(); data["native"]["files"]["index"] = None
        self.assertTrue(wire.parse_request(frame(data)).index_absent)

    def test_duplicate_coalesced_oversized_nested_and_float_frames_refuse(self):
        original = frame(fixture())
        cases = (original + b"\n", original + original, b"x" * (wire.REQUEST_LIMIT + 1),
                 original.replace(b'"generation":1', b'"generation":1,"generation":1'),
                 original.replace(b'"generation":1', b'"generation":1.0'),
                 b'{"a":' * 10 + b"null" + b"}" * 10 + b"\n")
        for raw in cases:
            with self.subTest(length=len(raw)), self.assertRaises(wire.ProtocolError):
                wire.parse_request(raw)

    def test_exact_original_clock_span_and_no_boolean_or_repeated_deadline(self):
        for key, value in (("workEndNs", 0), ("workEndNs", True), ("hardEndNs", 111_000_000_000),
                            ("hardEndNs", 100_000_000_000), ("hardEndNs", 1 << 63)):
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                data = fixture(); data["clock"][key] = value; wire.parse_request(frame(data))
        request = wire.parse_request(frame(fixture()))
        ready = json.loads(wire.ready(request))
        self.assertEqual(ready["digest"], hashlib.sha256(frame(fixture())).hexdigest())
        self.assertEqual(wire.go(request), b"MRK-GIT-READ-GO/1 " + request.digest.encode() + b"\n")

    def test_terminal_requires_matching_actual_result_type_and_failure_cutoff(self):
        request = wire.parse_request(frame(fixture()))
        result = read.ReadObservation(core.Observation("a" * 64, HEAD, "refs/heads/Main", (), (), ()),
                                      "b" * 64, read.Tracking("not-configured"))
        raw = wire.terminal(request, "ok", reason=None, result=result, first_failure_ns=None,
                            cleanup_end_ns=request.hard_end_ns)
        decoded = json.loads(raw)
        self.assertEqual(decoded["result"]["observation"]["head"], HEAD)
        self.assertEqual(set(decoded), {"protocol", "id", "digest", "action", "status", "reason", "result",
                                       "firstFailureNs", "cleanupEndNs"})
        for selected in (None, {}, result.as_dict(), core.Diff("a" * 64, False, ("a",), "text", None)):
            with self.subTest(type=type(selected)), self.assertRaises(wire.ProtocolError):
                wire.terminal(request, "ok", reason=None, result=selected, first_failure_ns=None,
                              cleanup_end_ns=request.hard_end_ns)
        for first, end in ((None, request.hard_end_ns), (1, 10_000_000_002), (1, request.hard_end_ns + 1)):
            with self.subTest(first=first), self.assertRaises(wire.ProtocolError):
                wire.terminal(request, "refused", reason="unsupported-repository", first_failure_ns=first,
                              cleanup_end_ns=end)


class ControlTests(unittest.TestCase):
    def test_original_source_type_only_not_subclass_or_neighbor_domain(self):
        source = GitReadInput(time.monotonic())
        self.assertIs(source_domain(source), SavedCommandDomain.GitRead)
        class Lookalike(GitReadInput):
            pass
        with self.assertRaises(ValueError):
            source_domain(Lookalike(time.monotonic()))
        source._domain = SavedCommandDomain.GitHubAuth
        with self.assertRaises(ValueError):
            source_domain(source)

    def test_clock_bridge_only_shortens_native_original_and_never_rebinds(self):
        source = GitReadInput(50)
        class Guard:
            @staticmethod
            def check():
                pass
        source.guard = Guard()  # Test-only no actual guard, pipe or process.
        with patch.object(source, "_frame", return_value=frame(fixture())), \
             patch.object(time, "CLOCK_UPTIME_RAW", 1, create=True), \
             patch.object(time, "clock_gettime_ns", return_value=90_000_000_000), \
             patch.object(time, "monotonic", return_value=80):
            source.request()
            self.assertLessEqual(source.work_end, 90)
            self.assertLessEqual(source.hard_end, 100)
            with self.assertRaises(wire.ProtocolError):
                source.request()

    def test_first_failure_is_latched_before_clock_call_and_only_shortens(self):
        source = GitReadInput(50)
        source.initial = wire.parse_request(frame(fixture()))
        source.cleanup_end_ns = source.initial.hard_end_ns
        with patch.object(time, "CLOCK_UPTIME_RAW", 1, create=True), \
             patch.object(time, "clock_gettime_ns", return_value=90_000_000_000) as clock, \
             patch.object(time, "monotonic", side_effect=[80.0, 80.001]):
            source.failure_observed()
            self.assertEqual(source.first_failure, 80)
            self.assertEqual(source.hard_end, 90)
            self.assertLessEqual(source.first_failure_ns, 89_999_000_001)
            source.failure_observed()
            clock.assert_called_once()
        source = GitReadInput(50)
        failure = KeyboardInterrupt()
        with patch.object(time, "CLOCK_UPTIME_RAW", 1, create=True), \
             patch.object(time, "clock_gettime_ns", side_effect=failure) as clock:
            with self.assertRaises(KeyboardInterrupt) as raised:
                source.failure_observed()
            self.assertIs(raised.exception, failure)
            source.failure_observed()
            clock.assert_called_once()
            self.assertIsNone(source.first_failure_ns)


@contextmanager
def synthetic_operation():
    with tempfile.TemporaryDirectory(prefix="mrk-git-worker-data-") as directory:
        base = Path(directory)
        root = base / "project"
        root.mkdir(mode=0o700)
        for name in (".git", ".git/objects", ".git/objects/info", ".git/objects/pack", ".git/refs",
                     ".git/refs/heads", ".git/refs/remotes", ".git/refs/remotes/Origin"):
            (root / name).mkdir(mode=0o700)
        files = {"HEAD": b"ref: refs/heads/Main\n", "config": b"[core]\nbare=false\n",
                 "index": b"inert-not-a-git-index", "refs/heads/Main": (HEAD + "\n").encode(),
                 "refs/remotes/Origin/Main": (UPSTREAM + "\n").encode()}
        for name, content in files.items():
            (root / ".git" / name).write_bytes(content)
        tool = base / "inert-tool-not-executable"
        tool.write_bytes(b"DATA, never executed")
        def snapshot(path):
            return wire.FileSnapshot(path, wire.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        # Explicit synthetic DATA replacement: production parser rejects a
        # non-CLT tool and uid0. No native admission is manufactured here.
        request = replace(wire.parse_request(frame(fixture())), uid=os.getuid(), gid=os.getgid(), root=root,
            directories=tuple((path, wire.directory_identity(path.stat())) for path in
                              (root, root / ".git", root / ".git/objects")), tool=snapshot(tool),
            files=tuple(snapshot(root / ".git" / name) for name in ("HEAD", "config", "index")))
        source = GitReadInput(time.monotonic())
        guard = DefaultCancellation(ProcessCleanupError, "Inert test failure")
        source.acquired = True  # DATA fixture only: no FD0/pipe/signal claim.
        source.initial, source.request_returned = request, True
        original_mkdtemp = tempfile.mkdtemp
        with patch.object(guard, "check", return_value=None), \
             patch("subprocess.Popen", side_effect=AssertionError("NO process in Git DATA tests")), \
             patch.object(core.tempfile, "mkdtemp", side_effect=lambda **kw: original_mkdtemp(dir=base, **kw)):
            guard._install_saved_command_source(source)
            operation = GitReadOperation(request, source, guard)
            source.ready_sent = source.go_returned = source.active = True
            try:
                yield operation
            finally:
                operation.cleanup()
                source.close()


class OperationTests(unittest.TestCase):
    def test_original_shared_seam_uses_fixed_view_and_unpublished_caw_cannot_claim_success(self):
        with synthetic_operation() as operation:
            operation.admit()
            fake = FakeGit()
            with patch("mobile_release._command_process.run_command", side_effect=fake) as command:
                with self.assertRaises(wire.ProtocolError):
                    operation.run()
                self.assertEqual(command.call_count, 1)
            self.assertIsNone(operation.result)
            self.assertFalse(operation.returned)

    def test_fake_returned_caw_ledger_drives_one_finite_observation_without_child(self):
        with synthetic_operation() as operation:
            operation.admit()
            fake = FakeGit()
            def returned(argv, **options):
                ledger, record = operation.guard.lifetime_ledger, object()
                ledger._bind_command(record)  # FAKE original producer, not native evidence.
                result = fake(argv, **options)
                ledger._finish_command(record, dispatched=True, contained=True, cleanup_complete=True)
                return result
            with patch("mobile_release._command_process.run_command", side_effect=returned) as command:
                operation.run()
                self.assertTrue(operation.returned)
                self.assertEqual(operation.result.observation.head, HEAD)
                self.assertEqual(operation.calls, command.call_count)
                with self.assertRaises(wire.ProtocolError):
                    operation.run()
                for _, options in command.call_args_list:
                    self.assertEqual(options["environ"]["GIT_ALLOW_PROTOCOL"], "")
                    self.assertEqual(options["environ"]["GIT_CONFIG_SYSTEM"], os.devnull)
                    self.assertLessEqual(options["timeout"], 10)
                    self.assertIs(options["cancellation"], operation.guard)

    def test_absent_pending_command_foreign_args_or_environment_cannot_reach_caw(self):
        cases = ({}, {"argv": ["/bin/sh", "-c", "true"]}, {"environ": {"PATH": "/tmp"}},
                 {"capture": False}, {"text": True}, {"on_start": lambda _: None},
                 {"execution_scope": object()}, {"journal_binding": object()}, {"_evidence": object()})
        for changes in cases:
            with self.subTest(keys=list(changes)), synthetic_operation() as operation:
                operation.admit(); operation.entered = True
                options = dict(argv=[str(wire.TOOL_PATH), "--version"], environ={}, cwd=operation.request.root,
                               timeout=10, capture=True, text=False, output_limit=1024, cancellation=operation.guard)
                options.update(changes)
                with patch("mobile_release._command_process.run_command") as command, self.assertRaises(wire.ProtocolError):
                    run_owned(**options)
                command.assert_not_called()

    def test_changed_original_file_refuses_before_any_command(self):
        with synthetic_operation() as operation:
            operation.admit()
            operation.request.files[1].path.write_bytes(b"changed inert config\n")
            with patch("mobile_release._command_process.run_command") as command, self.assertRaises(wire.ProtocolError):
                operation.run()
            command.assert_not_called()
            self.assertIsNone(operation.result)

    def test_unknown_original_caw_is_absorbing_and_never_retried(self):
        with synthetic_operation() as operation:
            operation.admit()
            failure = ProcessCleanupError("Synthetic unknown", dispatched=True, contained=False)
            with patch("mobile_release._command_process.run_command", side_effect=failure) as command:
                with self.assertRaises(ProcessCleanupError) as raised:
                    operation.run()
                self.assertIs(raised.exception, failure)
                with self.assertRaises(wire.ProtocolError):
                    operation.run()
                command.assert_called_once()
            operation.cleanup()
            self.assertTrue(operation.unknown)
            self.assertFalse(operation.closed)

    def test_lost_original_close_return_is_never_retried(self):
        with synthetic_operation() as operation:
            operation.admit()
            selected = operation.originals[-1].fd
            original_close = os.close
            calls, failure = [], KeyboardInterrupt()
            def close(fd):
                calls.append(fd)
                original_close(fd)
                if fd == selected:
                    raise failure  # Test FD actually closed, return deliberately lost.
            with patch.object(os, "close", side_effect=close):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    operation.cleanup()
                self.assertIs(raised.exception, failure)
                operation.cleanup()
            self.assertEqual(calls.count(selected), 1)
            self.assertTrue(operation.unknown)
            self.assertFalse(operation.closed)

    def test_terminal_cannot_publish_before_actual_lifetime_is_complete(self):
        # Pure actual-engine terminal predicate; no stdout, signal, IO or child.
        with synthetic_operation() as operation:
            operation.admit()
            engine = _Engine.__new__(_Engine)
            engine.operation, engine.request, engine.guard, engine.input = operation, operation.request, operation.guard, operation.source
            engine.frames, engine.primary = 1, None
            sent = []
            engine.write = lambda raw, **_: sent.append(json.loads(raw))
            engine.terminal()
            self.assertEqual(sent[0]["status"], "cleanup-unknown")
            self.assertIsNone(sent[0]["result"])
