"""Actual Init worker/control/owned dispatch, with INERT Git and FAKE C/A/W.

The same original file readers and no-replace private-directory move are real;
the selected source/ACK and command ledger fixtures are explicitly not native
admission or durable journal evidence. Popen is forbidden. No real Git runs.
"""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
import stat
import time
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_init as codec
from mobile_release import _desktop_git_local_protocol as wire
from mobile_release import _desktop_git_read_protocol as fields
from mobile_release import git_repository_init as init
from mobile_release import git_service as core
from mobile_release.desktop_git_local import GitLocalOperation, _Engine
from mobile_release.owned_process import run_owned
import test_desktop_git_local_protocol as old_wire
from test_git_repository_init import InitFixture, CONFIG


def row(phase="prepare"):
    value = old_wire.fixture(phase=phase)
    value["action"] = {"kind": "initialize"}
    old = value["native"]
    value["native"] = {"uid": old["uid"], "gid": old["gid"], "root": old["root"],
                       "directory": old["directories"]["root"], "tool": old["tool"], "candidate": None}
    if phase == "apply":
        value["native"]["candidate"] = {"name": init.PRIVATE_PREFIX + "a" * 32,
            **{name: [1, index + 3, stat.S_IFDIR | 0o700, 1001, 1001]
               for index, name in enumerate(("outer", "worktree", "git", "template"))}}
    return value


class InitProtocolTests(unittest.TestCase):
    def test_closed_action_never_accepts_executable_source_revision_or_branch(self):
        for phase in ("prepare", "apply"):
            request = wire.parse_request(old_wire.frame(row(phase)))
            self.assertIs(type(request.action), codec.Action)
            self.assertEqual(request.action.as_dict(), {"kind": "initialize"})
            self.assertEqual(request.files, ())
            self.assertEqual(request.init_sources is None, phase == "prepare")
            self.assertEqual(str(request.tool.path), str(wire.TOOL_PATH))
            self.assertFalse(request.index_absent)  # No fabricated Git index observation.
        for extra in ({"expectedRevision": "a" * 64}, {"name": "other"}, {"force": False}, {"remote": None},
                      {"url": "https://example.invalid"}, {"paths": []}, {"identity": None}):
            value = row(); value["action"].update(extra)
            with self.subTest(extra=extra), self.assertRaises(wire.ProtocolError):
                wire.parse_request(old_wire.frame(value))

    def test_candidate_only_apply_exact_private_layout_original_provider(self):
        changes = (
            lambda v: v["native"].pop("candidate"),
            lambda v: v["native"].update(candidate=None),
            lambda v: v["native"]["candidate"].update(name="../.git"),
            lambda v: v["native"]["candidate"].update(fd=3),
            lambda v: v["native"]["candidate"].update(git=v["native"]["directory"]),
            lambda v: v["native"]["candidate"]["git"].__setitem__(1, 3),
            lambda v: v["native"]["candidate"]["git"].__setitem__(2, stat.S_IFDIR | 0o755),
            lambda v: v["native"]["candidate"]["git"].__setitem__(0, 2),
            lambda v: v["native"]["tool"]["identity"].__setitem__(3, 1001),
            lambda v: v["native"].update(toolPath="/usr/bin/git"),
            lambda v: v["native"].update(files={}),
        )
        for change in changes:
            value = row("apply"); change(value)
            with self.subTest(value=value), self.assertRaises(wire.ProtocolError):
                wire.parse_request(old_wire.frame(value))
        value = row(); value["native"]["candidate"] = row("apply")["native"]["candidate"]
        with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(value))

    def test_old_actions_keep_their_original_native_grammar(self):
        for action in ("stage", "unstage", "commit"):
            value = old_wire.fixture(action)
            self.assertIsNone(wire.parse_request(old_wire.frame(value)).init_sources)
            value["native"]["candidate"] = None
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(value))
        original = wire.parse_request(old_wire.frame(old_wire.fixture()))
        for reason in init.REASONS:
            wire.terminal(wire.parse_request(old_wire.frame(row())), "refused", reason=reason,
                          first_failure_ns=100_000_000_000, cleanup_end_ns=110_000_000_000)
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(original, "refused", reason=reason,
                              first_failure_ns=100_000_000_000, cleanup_end_ns=110_000_000_000)


class InitWorkerTests(InitFixture):
    @contextmanager
    def operation(self, phase="apply"):
        engine = _Engine(time.monotonic())
        source, guard = engine.input, engine.guard
        tool = self.base / "inert-tool"
        tool.write_bytes(b"not executable: private comparison DATA only")
        digest = hashlib.sha256(tool.read_bytes()).hexdigest()
        before = init.GitInitRepository(self.root, git_executable=wire.TOOL_PATH, work_end=source.work_end,
                                        tool_digest=digest, _run=self.fake).prepare_init()
        candidate = None if phase == "prepare" else self.candidate()
        paths = (self.root,) if candidate is None else (self.root, candidate.outer.path, candidate.worktree.path,
                                                       candidate.git.path, candidate.template.path)
        value = row(phase)
        if phase == "apply": value["reviewDigest"] = before.digest
        # Parser correctly rejects uid0/unprotected fixture tool. This DATA
        # substitution supplies real private files for worker comparisons only.
        request = replace(wire.parse_request(old_wire.frame(value)), root=self.root, uid=os.getuid(), gid=os.getgid(),
            directories=tuple((p, fields.directory_identity(p.lstat())) for p in paths),
            tool=fields.FileSnapshot(tool, fields.identity(tool.lstat()), digest),
            init_sources=None if candidate is None else codec.Sources(candidate.outer.path.name, paths[1:]))
        engine.request = source.initial = request
        source.request_returned = source.acquired = True
        guard._install_saved_command_source(source)  # No stdio, handlers or native source acquired.
        operation = engine.operation = GitLocalOperation(request, source, guard, engine)
        source.ready_sent = source.go_returned = source.active = True
        def ledger_return(argv, **options):
            ledger, record = guard.lifetime_ledger, object()
            ledger._bind_command(record)  # Explicitly FAKE contained/cleanup receipts.
            result = self.fake(argv, **options)
            ledger._finish_command(record, dispatched=True, contained=True, cleanup_complete=True)
            return result
        try:
            with patch.object(guard, "check", return_value=None), \
                    patch("mobile_release._command_process.run_command", side_effect=ledger_return) as calls:
                yield operation, calls
        finally:
            operation.cleanup()
            source.close()

    @staticmethod
    def ack(source):
        return b"MRK-GIT-LOCAL-ACK/1 " + source.initial.digest.encode() + b" " + source.candidate.digest.encode() + b" 5\n"

    def test_prepare_opens_only_original_readers_no_git_candidate_or_mutation(self):
        with self.operation("prepare") as (op, calls):
            op.admit()
            fds = [original.fd for original in op.originals]
            with patch.object(op.engine, "write") as write, \
                    patch.object(os, "mkdir", side_effect=AssertionError("Readonly Prepare cannot create metadata")):
                op.run()
            calls.assert_not_called(); write.assert_not_called()
            self.assertTrue(op.returned)
            self.assertIs(type(op.review), init.InitReview)
            self.assertIsNone(op.diff); self.assertIsNone(op.result)
            self.assertFalse(op.source.candidate_claimed)
            self.assertEqual(len(op.originals), 2)
            self.assertFalse((self.root / ".git").exists())
            self.assertFalse(any(p.name.startswith(init.PRIVATE_PREFIX) for p in self.root.iterdir()))
            op.cleanup()
            self.assertTrue(op.closed)
            for fd in fds:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_original_apply_captures_same_readers_ack_move_and_positive_terminal(self):
        with self.operation() as (op, calls):
            op.admit()
            original_git = next(v for v in op.originals if v.path.name == ".git")
            fd, identity = original_git.fd, original_git.identity
            with patch.object(op.engine, "write") as write, \
                    patch.object(op.source, "_frame", side_effect=lambda _: self.ack(op.source)):
                op.run()
            self.assertTrue(op.returned and op.source.candidate_returned)
            self.assertEqual(calls.call_count, 2); self.assertEqual(write.call_count, 1)
            self.assertEqual(op.calls, 2)
            self.assertEqual(op.publication(), "init-returned")
            self.assertEqual(op.result.state, "succeeded")
            self.assertEqual(len(op.init_state.generated), 8)
            self.assertIs(original_git, next(v for v in op.originals if v.path == original_git.path))
            self.assertEqual(original_git.fd, fd)
            self.assertEqual(fields.directory_identity(os.fstat(fd)), identity)
            self.assertEqual(fields.directory_identity((self.root / ".git").lstat()), identity)
            op.source_post(hash_files=True)
            data = json.loads(wire.terminal(op.request, "ok", reason=None, result=op.result,
                publication=op.publication(), first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns))
            self.assertIsNone(data["result"]["observation"])
            self.assertEqual(data["result"]["intent"], op.source.candidate.intent.as_dict())
            op.cleanup()
            self.assertTrue(op.closed and all(v.closed for v in op.originals))
            self.assertEqual((self.root / ".git/config").read_bytes(), CONFIG)
            with self.assertRaises(OSError): os.fstat(fd)

    def test_missing_or_wrong_go_never_enters_private_git(self):
        with self.operation() as (op, calls):
            op.admit()
            op.source.go_returned = op.source.ready_sent = op.source.active = False
            op.source.ready()
            with patch.object(op.source, "_frame", return_value=b"MRK-GIT-LOCAL-GO/1 " + b"f" * 64 + b"\n"):
                with self.assertRaises(wire.ProtocolError): op.source.go()
            calls.assert_not_called()
            self.assertFalse(op.entered or op.source.candidate_claimed)
            self.assertFalse((self.root / ".git").exists())

    def test_late_original_go_refuses_before_dispatch(self):
        with self.operation() as (op, calls):
            op.admit()
            op.source.go_returned = op.source.ready_sent = op.source.active = False
            op.source.ready()
            op.source.work_end = time.monotonic() - 1
            with patch.object(op.source, "_frame", return_value=wire.go(op.request)):
                with self.assertRaises(fields.ProtocolError): op.source.go()
            calls.assert_not_called()
            self.assertFalse(op.entered or op.source.candidate_claimed)

    def test_lost_ack_retains_generated_readers_and_never_moves_or_replays(self):
        with self.operation() as (op, calls):
            op.admit()
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=KeyboardInterrupt("inert lost ACK")):
                with self.assertRaises(KeyboardInterrupt): op.run()
            self.assertTrue(op.source.candidate_claimed)
            self.assertFalse(op.source.candidate_returned or op.repository._transaction.attempted)
            self.assertIsNotNone(op.init_state.captured)
            self.assertEqual(len(op.init_state.generated), 8)
            self.assertFalse((self.root / ".git").exists())
            self.assertTrue(op.init_state.borrowed.git.path.is_dir())
            with self.assertRaises(wire.ProtocolError): op.source.handoff(op.source.candidate)
            self.assertEqual(calls.call_count, 2)

    def test_original_final_dispatch_rejects_changed_environment(self):
        with self.operation() as (op, calls):
            op.admit()
            def changed(argv, **options):
                options["environ"] = {**options["environ"], "GIT_CONFIG_GLOBAL": "/untrusted/config"}
                return run_owned(argv, **options)
            with patch("mobile_release.desktop_git_local.run_owned", side_effect=changed):
                with self.assertRaises(wire.ProtocolError): op.run()
            calls.assert_not_called()
            self.assertFalse(op.source.candidate_claimed)
            self.assertEqual(init.names(op.init_state.borrowed.git.path), ())

    def test_original_final_dispatch_rechecks_absence_before_dispatch(self):
        with self.operation() as (op, calls):
            op.admit()
            def changed(argv, **options):
                (self.root / ".git").mkdir()
                (self.root / ".git/foreign").write_bytes(b"keep user metadata\n")
                return run_owned(argv, **options)
            with patch("mobile_release.desktop_git_local.run_owned", side_effect=changed):
                with self.assertRaises(core.GitError): op.run()
            calls.assert_not_called()
            self.assertEqual((self.root / ".git/foreign").read_bytes(), b"keep user metadata\n")
            self.assertFalse(op.source.candidate_claimed)

    def test_original_final_dispatch_rechecks_the_actual_held_tool_identity(self):
        with self.operation() as (op, calls):
            op.admit()
            def changed(argv, **options):
                op.request.tool.path.write_bytes(b"changed inert tool contents before dispatch\n")
                return run_owned(argv, **options)
            with patch("mobile_release.desktop_git_local.run_owned", side_effect=changed):
                # The SAME original GitRead reader reports the identity
                # mismatch before the owned command backend is entered.
                with self.assertRaises(fields.ProtocolError): op.run()
            calls.assert_not_called()
            self.assertFalse(op.source.candidate_claimed)
            self.assertEqual(init.names(op.init_state.borrowed.git.path), ())

    def test_plain_completed_process_is_not_original_caw_finality(self):
        with self.operation() as (op, _):
            op.admit()
            with patch("mobile_release._command_process.run_command", side_effect=self.fake) as calls:
                with self.assertRaises(wire.ProtocolError): op.run()
            self.assertEqual(calls.call_count, 1)
            self.assertFalse(op.returned or op.source.candidate_claimed)
            self.assertFalse((self.root / ".git").exists())

    def test_source_close_unknown_never_claims_closed_or_retries_original_fd(self):
        with self.operation("prepare") as (op, _):
            op.admit(); op.run()
            original = op.originals[-1]
            fd = original.fd
            actual_close = os.close
            def fail(number):
                if number == fd: raise OSError("inert original close did not return")
                return actual_close(number)
            with patch.object(os, "close", side_effect=fail) as close:
                with self.assertRaises(OSError): op.cleanup()
                before = close.call_count
                op.cleanup()
                self.assertEqual(close.call_count, before)
            self.assertTrue(original.unknown and original.close_claimed and op.unknown)
            self.assertFalse(op.closed)
            # Only the fixture knows its mocked close did not enter the OS.
            # Retire that exact real fd without changing any original outcome.
            actual_close(fd)


if __name__ == "__main__":
    unittest.main()
