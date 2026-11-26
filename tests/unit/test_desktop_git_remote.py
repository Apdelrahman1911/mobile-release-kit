"""Actual fixed worker/control with explicitly fake C/A/W/channel returns.

No native library, descriptor mapping, token source, HTTP, Git or subprocess is
run. Source FDs are ONLY new test-owned files. This proves composition/refusal
logic, never installed source/credential/journal/lifetime qualification.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import PropertyMock, patch

from mobile_release import _desktop_git_remote_protocol as wire
from mobile_release import _desktop_git_read_protocol as fields
from mobile_release import git_repository_read as read
from mobile_release import git_repository_fetch as fetch
from mobile_release import git_service as core
from mobile_release._desktop_git_remote_control import GitRemoteInput
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain
from mobile_release._git_remote_input_channel import OriginalInputChannel
from mobile_release.desktop_git_remote import GitRemoteOperation, _Engine
from mobile_release.git_remote_wire import Selection
from mobile_release.owned_process import ProcessCleanupError, run_owned
import test_git_repository_fetch as fixture_core
from test_desktop_git_remote_protocol import fixture, frame, ack


@contextmanager
def original(*, phase="apply"):
    world = fixture_core.FetchTests("test_fixed_candidate_ack_links_cas_and_all_core_closes")
    world.setUp()
    op = None
    try:
        root, fake = world.root, world.fake
        observer = read.GitReadRepository(root, git_executable=wire.TOOL_PATH,
            work_end=time.monotonic() + 45, _run=fake)
        observed = observer.observe()
        seed = fetch.GitFetchRepository(root, git_executable=wire.TOOL_PATH, work_end=time.monotonic() + 45,
            launch=fixture_core.LAUNCH, _run=fake, _remote=fake)
        reviewed = seed.prepare_fetch("origin", world.target, expected_revision=observed.observation.revision,
                                       expected_reference_revision=observed.reference_revision)
        row = fixture(phase=phase)
        row["action"]["expectedRevision"] = observed.observation.revision
        row["action"]["expectedReferenceRevision"] = observed.reference_revision
        row["target"]["login"] = world.target.login
        if phase == "apply":
            row["reviewDigest"] = reviewed.digest
        inert_tool = world.base / "inert-tool"
        inert_tool.write_bytes(b"not executable: source comparison fixture")
        def snapshot(path):
            return fields.FileSnapshot(path, fields.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        # Deliberate DATA replacement: parser rejects uid0/non-CLT provider in
        # production. This fixture does not supply installed native authority.
        request = replace(wire.parse_request(frame(row)), uid=os.getuid(), gid=os.getgid(), root=root,
            directories=tuple((p, fields.directory_identity(p.stat())) for p in (root, root/".git", root/".git/objects")),
            tool=snapshot(inert_tool), files=tuple(snapshot(root/".git"/name) for name in ("HEAD", "config", "index")))
        engine = _Engine(time.monotonic(), fixture_core.LAUNCH)
        source, guard = engine.input, engine.guard
        engine.request = source.initial = request
        source.request_returned = source.acquired = True
        guard._install_saved_command_source(source)  # Exact type only; no signals/FD0 acquired.
        op = engine.operation = GitRemoteOperation(request, source, guard, engine)
        source.ready_sent = source.go_returned = source.active = True
        source._token = "inert-not-a-credential"
        seen, remote = [], []

        def fake_channel(channel, original_source):
            channel.source = original_source
            channel.closed = channel.unknown = channel.failed = False
            channel.get_entered = channel.get_sent = True
            channel.command = SimpleNamespace(_exported=True)
            channel.binding = SimpleNamespace(target=request.target)
        def fake_finish(channel, actual):
            assert actual is op and op.remote_returned and not op.unknown
            channel.closed = True
            return True
        def returned(argv, **options):
            ledger, record = guard.lifetime_ledger, object()
            ledger._bind_command(record)  # FAKE positive C/A/W, never native proof.
            result = fake(argv, **{k:v for k,v in options.items() if k not in ("on_start", "cleanup", "journal_binding")})
            ledger._finish_command(record, dispatched=True, contained=True, cleanup_complete=True)
            seen.append(tuple(argv))
            return result
        def remote_return(channel, argv, *, environ, cwd, timeout, output_limit, text):
            assert channel is source.channel.command
            op.command_arguments(argv, environ=environ, cwd=cwd, capture=True, text=text, output_limit=output_limit,
                on_start=None, cleanup=False, execution_scope=None, journal_binding=None, evidence=None)
            remote.append(tuple(argv))
            return returned(argv, cwd=cwd, environ=environ, capture=True, text=False, timeout=timeout,
                            output_limit=output_limit, cancellation=guard, execution_scope=None)
        def acknowledge(_):
            sent = source.candidate
            publisher = fixture_core.Owner(root, op.review.plan, op.review.digest)
            world.owners.append(publisher)
            marker = publisher.record_intent(sent.intent)  # Test-owned O_EXCL/fsync only, not native ACK.
            return frame(ack(request, sent, marker))
        with ExitStack() as stack:
            stack.enter_context(patch.object(guard, "check", return_value=None))
            stack.enter_context(patch.object(time, "CLOCK_UPTIME_RAW", 1, create=True))
            stack.enter_context(patch.object(time, "clock_gettime_ns", return_value=95_000_000_000))
            stack.enter_context(patch.object(OriginalInputChannel, "__init__", fake_channel))
            stack.enter_context(patch.object(OriginalInputChannel, "acquire", return_value=None))
            stack.enter_context(patch.object(OriginalInputChannel, "finish", fake_finish))
            stack.enter_context(patch.object(OriginalInputChannel, "accept_return", return_value=None, create=True))
            stack.enter_context(patch("mobile_release._command_process.run_command", side_effect=returned))
            stack.enter_context(patch("mobile_release._command_process._run_git_remote_command", side_effect=remote_return))
            stack.enter_context(patch.object(engine, "write"))
            stack.enter_context(patch.object(source, "_frame", side_effect=acknowledge))
            yield op, world, seen, remote
    finally:
        try:
            if op is not None:
                if op.repository is not None:
                    world.repositories.append(op.repository)
                try:
                    op.cleanup()
                finally:
                    op.source.close()
        finally:
            world.doCleanups()


class ControlTests(unittest.TestCase):
    def test_exact_domain_is_not_gitlocal_read_alias_or_a_subclass(self):
        source = GitRemoteInput(time.monotonic())
        self.assertIs(source_domain(source), SavedCommandDomain.GitRemote)
        class Other(GitRemoteInput):
            pass
        with self.assertRaises(ValueError):
            source_domain(Other(time.monotonic()))
        source._domain = SavedCommandDomain.GitLocal
        with self.assertRaises(ValueError):
            source_domain(source)

    def test_first_failure_cannot_renew_original_work_or_cleanup_clock(self):
        source = GitRemoteInput(50)
        source.initial = wire.parse_request(frame(fixture()))
        with patch.object(time, "CLOCK_UPTIME_RAW", 1, create=True), \
                patch.object(time, "clock_gettime_ns", return_value=90_000_000_000) as clock, \
                patch.object(time, "monotonic", side_effect=[80., 80.001]):
            source.failure_observed(); source.failure_observed()
        self.assertEqual((source.work_end, source.hard_end, source.first_failure), (95, 90, 80))
        clock.assert_called_once()
        self.assertLessEqual(source.first_failure_ns, 89_999_000_001)

    def test_private_token_claim_is_spent_before_owner_check_and_never_retried(self):
        with original() as (op, _, __, ___):
            source = op.source
            channel = source.channel = SimpleNamespace(get_entered=True)
            sentinel = KeyboardInterrupt("inert owner interruption")
            with patch.object(op, "credential_current", side_effect=sentinel) as current:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    source.take_helper_token(channel)
                self.assertIs(caught.exception, sentinel)
                with self.assertRaises(wire.ProtocolError):
                    source.take_helper_token(channel)
                current.assert_called_once()
            source.channel = None  # No descriptor/process existed in this DATA case.


class OperationTests(unittest.TestCase):
    def test_apply_uses_same_original_command_gate_ack_and_positive_receipt(self):
        with original() as (op, world, seen, remote):
            op.admit(); old_fds = tuple(row.fd for row in op.originals)
            op.run()
            self.assertTrue(op.returned and op.source.candidate_returned and op.source.channel.closed)
            self.assertEqual(op.result.state, "succeeded")
            self.assertEqual((len(remote), world.fake.cas), (1, 1))
            self.assertEqual(op.calls, len(seen))
            self.assertIs(op.publication().intent, op.result.intent)
            self.assertIsNone(op.result.observation)
            op.cleanup()
            self.assertTrue(op.closed)
            for fd in old_fds:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_prepare_one_remote_metadata_no_ack_and_no_original_ref_change(self):
        with original(phase="prepare") as (op, world, seen, remote):
            op.admit(); op.run()
            self.assertTrue(op.returned)
            self.assertEqual(op.review.plan.target.selected.oid, fixture_core.NEW)
            self.assertEqual([row[0][0] for row in world.fake.private], ["ls-remote"])
            self.assertEqual((len(remote), world.fake.cas), (1, 0))
            self.assertIsNone(op.result)
            self.assertFalse(op.source.candidate_claimed)
            self.assertEqual(op.calls, len(seen))

    def test_unbound_arbitrary_command_never_reaches_fake_original_runner(self):
        with original() as (op, _, seen, remote):
            op.admit(); op.entered = True
            with self.assertRaises(wire.ProtocolError):
                run_owned(["/bin/sh", "-c", "false"], cwd=op.request.root, environ={}, capture=True,
                          text=False, timeout=1, output_limit=1024, cancellation=op.guard)
            self.assertEqual((seen, remote), ([], []))

    def test_lost_candidate_ack_is_once_only_and_cannot_publish(self):
        with original() as (op, world, _, remote):
            op.admit()
            original_error = KeyboardInterrupt("inert missing ACK")
            with patch.object(op.source, "_frame", side_effect=original_error):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    op.run()
            self.assertIs(caught.exception, original_error)
            self.assertTrue(op.source.candidate_claimed)
            self.assertFalse(op.source.candidate_returned)
            self.assertIsNone(op.repository._transaction.publication)
            self.assertEqual((len(remote), world.fake.cas), (1, 0))
            with self.assertRaises(wire.ProtocolError):
                op.source.handoff(op.source.candidate)

    def test_missing_fake_caw_completion_is_not_a_closed_channel_or_success(self):
        with original(phase="prepare") as (op, world, _, __):
            op.admit()
            def missing(channel, argv, **options):
                record = object()
                op.guard.lifetime_ledger._bind_command(record)
                raise ProcessCleanupError("inert C/A/W return missing", dispatched=True)
            with patch("mobile_release._command_process._run_git_remote_command", side_effect=missing):
                with self.assertRaises(ProcessCleanupError):
                    op.run()
            self.assertTrue(op.unknown and op.repository._unknown)
            self.assertFalse(op.source.channel.closed)
            self.assertFalse(op.returned)
            self.assertEqual(world.fake.cas, 0)


class TerminalTests(unittest.TestCase):
    def terminal(self, op):
        op.cleanup()
        op.source.close()
        engine = op.engine
        engine.frames = 1 + int(op.source.candidate_claimed)
        engine.candidate_written = op.source.candidate_claimed
        # The fixture never installed native/signal handlers. Explicitly fake
        # only this last DATA predicate; source-file closes above are actual.
        with patch.object(type(op.guard), "handler_state", new_callable=PropertyMock, return_value="RESTORED"):
            engine.terminal()
        return json.loads(engine.write.call_args.args[0])

    def test_joined_positive_core_without_late_failure_keeps_success(self):
        with original() as (op, world, _, __):
            op.admit(); op.run()
            self.assertTrue(op.core_returned and op.returned)
            row = self.terminal(op)
            self.assertEqual((row["status"], row["result"]["state"], row["result"]["effectPhase"]),
                             ("ok", "succeeded", "ref-published"))
            self.assertEqual(row["publication"]["reference"]["oid"], fixture_core.NEW)
            self.assertEqual(world.fake.cas, 1)

    def test_stop_after_core_postcheck_cannot_turn_published_result_into_success(self):
        with original() as (op, world, _, __):
            op.admit(); op.run()
            op.source.stop("timed-out")
            row = self.terminal(op)
            self.assertEqual((row["status"], row["result"]["state"], row["result"]["reason"]),
                             ("ok", "recovery-required", "deadline"))
            self.assertEqual(row["result"]["effectPhase"], "ref-published")
            self.assertIsNotNone(row["publication"])
            self.assertIsNotNone(row["firstFailureNs"])
            self.assertEqual(world.fake.cas, 1)

    def test_stop_or_stale_source_between_core_and_postcheck_keeps_only_recovery(self):
        for stopped, reason in ((True, "authorization"), (False, "stale-observation")):
            with self.subTest(stopped=stopped), original() as (op, world, _, __):
                op.admit()
                actual = op.source_post
                def post(*, hash_files):
                    if op.core_returned:
                        if stopped:
                            op.source.stop()
                        raise core.GitError(reason)
                    return actual(hash_files=hash_files)
                with patch.object(op, "source_post", side_effect=post):
                    with self.assertRaises(core.GitError) as caught:
                        op.run()
                op.engine.primary = caught.exception
                op.source.failure_observed()
                self.assertTrue(op.core_returned)
                self.assertFalse(op.returned)
                row = self.terminal(op)
                self.assertEqual((row["status"], row["result"]["state"], row["result"]["reason"]),
                                 ("ok", "recovery-required", reason))
                self.assertEqual(row["publication"]["phase"], "ref-published")
                self.assertEqual(world.fake.cas, 1)

    def test_unknown_close_never_exposes_a_positive_publication_as_joined(self):
        with original() as (op, _, __, ___):
            op.admit(); op.run()
            op.unknown = True  # Explicitly fake an original unknown-close fact.
            row = self.terminal(op)
            self.assertEqual((row["status"], row["reason"]), ("cleanup-unknown", "unknown"))
            self.assertIsNone(row["result"])
            self.assertIsNone(row["publication"])

    def test_stop_without_core_return_is_not_a_partial_result(self):
        with original() as (op, world, _, __):
            op.admit(); op.source.stop()
            row = self.terminal(op)
            self.assertEqual((row["status"], row["reason"]), ("cancelled", "authorization"))
            self.assertIsNone(row["result"])
            self.assertIsNone(row["publication"])
            self.assertEqual(world.fake.cas, 0)


if __name__ == "__main__":
    unittest.main()
