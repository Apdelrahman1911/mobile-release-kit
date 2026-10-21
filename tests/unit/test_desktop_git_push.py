"""SAME worker/input/channel/core, real private fixtures; fake C/A/W and peer.

No native socket, child, HTTP, secret, Store ACK or join is supplied. The only
FDs acquired are ordinary files under the existing test's private temporary
directory. Fake leases/EOF and ledger returns are explicit DATA, not native
qualification. Production phase methods and command/source gates are used.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest.mock import PropertyMock, patch

from mobile_release import _desktop_git_push_protocol as wire
from mobile_release import _desktop_git_read_protocol as fields
from mobile_release import _git_push_private_protocol as private
from mobile_release import git_push_body as bodies
from mobile_release import git_push_wire as packets
from mobile_release import git_repository_push as push
from mobile_release import git_repository_read as read
from mobile_release import git_remote_control as controls
from mobile_release import git_service as core
from mobile_release._desktop_git_push_control import GitPushInput
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain
from mobile_release._git_push_input_channel import PushInputChannel
from mobile_release._native_process import NativeProcessError
from mobile_release.desktop_git_push import GitPushOperation, _Engine
from mobile_release.owned_process import ProcessCleanupError, run_owned
from test_desktop_git_push_protocol import fixture, frame, ack
from test_git_remote_input_channel import IO, Lease
import test_git_repository_push as existing
from test_git_push_wire import packet, pack


@contextmanager
def original(*, phase="apply", first_publication=False):
    world = existing.GitPushRepositoryTests("test_review_then_one_apply_keeps_every_original_dirty_index_ref_and_config_byte")
    world.setUp()
    op = None
    try:
        root, fake = world.root, world.fake
        repository_type, target, selected = push.GitPushRepository, existing.TARGET, existing.SELECTED
        if first_publication:
            from mobile_release import git_repository_push_new_branch as first
            import test_git_repository_push_new_branch as first_fixture
            world.fake = fake = first_fixture.FakeFirst(root)
            repository_type, target, selected = first.GitPushNewBranchRepository, first_fixture.TARGET, first_fixture.SELECTED
        observer = read.GitReadRepository(root, git_executable=wire.TOOL_PATH,
            work_end=time.monotonic() + 45, _run=fake)
        observed = observer.observe()
        seed = repository_type(root, git_executable=wire.TOOL_PATH, work_end=time.monotonic() + 45,
            launch=existing.LAUNCH, _run=fake, _remote=world.remote)
        world.repositories.append(seed)
        # Local-only DATA digest preparation; not a native Prepare/consent.
        session = seed._session()
        plan = seed._capture(session, target, observed.observation.revision, observed.reference_revision)
        reviewed = push.PushReview(plan, push._review_digest(plan))
        assert seed._finish_sessions(False)
        row = fixture(phase=phase)
        row["action"].update(expectedRevision=observed.observation.revision,
            expectedReferenceRevision=observed.reference_revision,
            localRef=selected.local_ref, remoteRef=selected.remote_ref, oldOid=selected.old_oid, newOid=selected.new_oid,
            kind=packets.selection_kind(selected), remote=None if first_publication else "origin")
        if phase == "apply":
            row["reviewDigest"] = reviewed.digest
        inert_tool = world.base / "inert-tool"
        inert_tool.write_bytes(b"not executable: source comparison only")
        def snapshot(path):
            return fields.FileSnapshot(path, fields.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        # Explicit DATA replacement; no Linux uid0/provider is admitted by the
        # production parser or native SourceBook. All paths are test-owned.
        request = replace(wire.parse_request(frame(row)), uid=os.getuid(), gid=os.getgid(), root=root,
            directories=tuple((p, fields.directory_identity(p.stat())) for p in (root, root/".git", root/".git/objects")),
            tool=snapshot(inert_tool), files=tuple(snapshot(root/".git"/name) for name in ("HEAD", "config", "index")))
        engine = _Engine(time.monotonic(), replace(existing.LAUNCH, context=None))
        source, guard = engine.input, engine.guard
        engine.request = source.initial = request
        source.request_returned = source.acquired = True
        guard._install_saved_command_source(source)  # No signals/FD0/native source.
        op = engine.operation = GitPushOperation(request, source, guard, engine)
        source.ready_sent = source.go_returned = source.active = True
        source._token = "inert-not-a-credential"
        mode = SimpleNamespace(before_hook=None, after_send=None, before_return=None,
            omit_return=False, lose_caw=False, returned_state="ok", ack_error=None, ack_stop=False,
            duplicate_hook=False, send_before_hook=False, extra_eof=False)
        seen, remote, writes = [], [], []

        def acquire(channel):
            # Actual constructor ran, but no native method/runtime is called.
            # Reuse prior explicit fake lease/IO fixtures, not a second runner.
            channel.entered = True
            channel.client, channel.peer, channel.io = Lease(), Lease(), IO()
            channel.acquisition = SimpleNamespace(cleanup_unknown=False, settled=True,
                leases=(channel.client, channel.peer), close_launch=lambda: None)
            channel.command = SimpleNamespace(_exported=True)
            channel.binding = channel._binding(request, bytes.fromhex(request.digest[:32]), (os.getuid(), 1, 2))

        def local_returned(argv, **options):
            record = object()
            guard.lifetime_ledger._bind_command(record)  # Deliberately fake C/A/W.
            result = fake(argv, **{key: value for key, value in options.items()
                                  if key not in ("on_start", "cleanup", "journal_binding")})
            guard.lifetime_ledger._finish_command(record, dispatched=True, contained=True, cleanup_complete=True)
            seen.append(tuple(argv))
            return result

        def pump(channel, raw):
            channel.io.blocks.append(raw)
            source.poll(guard)
            source.poll(guard)  # Flush only the response emitted by that phase.
            assert not channel.outgoing

        def remote_returned(command, argv, *, environ, cwd, timeout, output_limit, text):
            channel = source.channel
            assert command is channel.command and not op.remote_returned
            op.command_arguments(argv, environ=environ, cwd=cwd, capture=True, text=text, output_limit=output_limit,
                on_start=None, cleanup=False, execution_scope=None, journal_binding=None, evidence=None)
            record = object()
            guard.lifetime_ledger._bind_command(record)  # Deliberately fake C/A/W.
            remote.append(tuple(argv)); seen.append(tuple(argv))
            if mode.lose_caw:
                raise ProcessCleanupError("inert missing original C/A/W", dispatched=True)
            try:
                pump(channel, channel.binding.request())
                assert channel.get_sent and source._token_consumed and source._token is None
                tx = op.repository._transaction
                if mode.before_hook is not None:
                    mode.before_hook(tx, channel)
                if mode.returned_state != "refused":
                    if mode.send_before_hook:
                        value = packets.BodyDigest(160, "b" * 64, 32, "c" * 40, 0)
                        stamp = list(tx.view.body_initial); stamp[3] = value.body_bytes
                        pump(channel, channel.binding.send(value, tuple(stamp)))
                    pump(channel, channel.binding.hook().request())
                    assert channel.hook_returned and tx.hook_returned
                    if mode.duplicate_hook:
                        pump(channel, channel.binding.hook().request())
                    if phase == "apply":
                        assert source.candidate_returned and tx.acknowledged and not op.remote_returned
                        offered = packets.advertisement(packet(b"# service=git-receive-pack\n") + b"0000"
                            + packet((selected.old_oid + " " + ("capabilities^{}" if first_publication else selected.remote_ref)).encode()
                                     + b"\0report-status\n") + b"0000", selected)
                        update = packets.command(packet((selected.old_oid + " " + selected.new_oid + " " + selected.remote_ref).encode()
                            + b"\0 report-status") + b"0000", selected, offered)
                        stream = packets.PackStream(update, selected, offered)
                        body = pack(); stream.feed(body); digest = stream.finish()
                        path = tx.view.root / bodies.NAME
                        path.write_bytes(update.raw + body)  # Test-owned simulated helper, no pack-objects.
                        pump(channel, channel.binding.send(digest, bodies._stamp(path.lstat())))
                        assert channel.send_returned and tx.send_consumed
                        writes.append(digest)
                        if mode.after_send is not None:
                            mode.after_send(tx, channel)
                        response = packets.status_response(packet(b"unpack ok\n")
                            + packet(("ok " + selected.remote_ref + "\n").encode()) + b"0000", selected, offered, update)
                    else:
                        response = None
                        assert not source.candidate_claimed and tx.intent is None and tx.view.body_initial is None
                else:
                    response = None
                if mode.before_return is not None:
                    mode.before_return(tx, channel)
                if not mode.omit_return:
                    state = mode.returned_state
                    failure = None if state == "ok" else "forbidden" if state == "refused" else "cleanup-unknown"
                    http_control = controls.empty() if failure is None else controls.refusal(controls.empty(), failure)
                    raw = channel.binding.returned(state, failure,
                        first_failure_ns=None if state == "ok" else 95_000_000_000,
                        cleanup_end_ns=request.hard_end_ns if state == "ok" else 105_000_000_000,
                        control=http_control, advertisement_sha256="e" * 64,
                        response=response, after_sha256="f" * 64 if response is not None else None)
                    channel.io.blocks.append(raw)
                channel.io.blocks.append(b"" if not mode.extra_eof else b"extra")
                return subprocess.CompletedProcess(argv, 0, b"Done\n", b"")
            finally:
                guard.lifetime_ledger._finish_command(record, dispatched=True, contained=True, cleanup_complete=True)

        def acknowledge(_):
            sent, tx = source.candidate, op.repository._transaction
            assert sent.intent is tx.intent and source.candidate_waiting and tx.ack_entered
            assert not tx.acknowledged and not op.remote_returned and op.pending.claimed
            if mode.ack_error is not None:
                raise mode.ack_error
            if mode.ack_stop:
                source.stop()
            return frame(ack(request, sent))

        with ExitStack() as stack:
            # Same real cancellation check/poll; only the absent native stdin
            # is inert. The actual private channel poll remains exercised.
            stack.enter_context(patch.object(source, "_poll_control_only", return_value=None))
            stack.enter_context(patch.object(time, "CLOCK_UPTIME_RAW", 1, create=True))
            stack.enter_context(patch.object(time, "clock_gettime_ns", return_value=95_000_000_000))
            stack.enter_context(patch.object(PushInputChannel, "acquire", acquire))
            stack.enter_context(patch("mobile_release._command_process.run_command", side_effect=local_returned))
            stack.enter_context(patch("mobile_release._command_process._run_git_remote_command", side_effect=remote_returned))
            stack.enter_context(patch.object(engine, "write"))
            stack.enter_context(patch.object(source, "_frame", side_effect=acknowledge))
            yield op, world, mode, seen, remote, writes
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


class WorkerTests(unittest.TestCase):
    def test_original_worker_hook_ack_send_return_and_source_close_sequence(self):
        with original() as (op, world, mode, seen, remote, sends):
            originals = {name: (world.root/name).read_bytes() for name in
                (".git/HEAD", ".git/index", ".git/config", ".git/refs/heads/main", ".git/"+existing.TRACKING, "a.txt", "b.txt")}
            op.admit(); fds = tuple(row.fd for row in op.originals)
            op.run()
            self.assertEqual((op.result.state, op.result.settlement), ("succeeded", "settled"))
            self.assertEqual((len(remote), len(sends), op.calls), (1, 1, len(seen)))
            channel = op.source.channel
            self.assertTrue(channel.return_checked and channel.eof and channel.closed and op.returned)
            self.assertEqual((channel.client.calls, channel.peer.calls), (1, 1))
            self.assertIs(op.transmission(), op.repository._transaction.receipt)
            for name, raw in originals.items():
                self.assertEqual((world.root/name).read_bytes(), raw)
            op.cleanup()
            self.assertTrue(op.closed)
            for fd in fds:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_review_is_same_remote_command_but_no_candidate_body_or_send(self):
        with original(phase="prepare") as (op, _, __, seen, remote, sends):
            op.admit(); op.run()
            self.assertTrue(op.core_returned and op.returned and op.source.channel.closed)
            self.assertIn("--dry-run", remote[0])
            self.assertEqual((len(remote), sends, op.calls), (1, [], len(seen)))
            self.assertFalse(op.source.candidate_claimed)
            self.assertIsNone(op.result)
            self.assertIsNone(op.repository._transaction.view.body_initial)

    def test_fixed_domain_rejects_other_subclass_and_unbound_command_before_runner(self):
        self.assertIs(source_domain(GitPushInput(time.monotonic())), SavedCommandDomain.GitRemote)
        class Other(GitPushInput):
            pass
        with self.assertRaises(ValueError):
            source_domain(Other(time.monotonic()))
        with original() as (op, _, __, seen, remote, sends):
            op.admit(); op.entered = True
            with self.assertRaises(Exception):
                run_owned(["/bin/sh", "-c", "false"], cwd=op.request.root, environ={}, capture=True,
                    text=False, timeout=1, output_limit=1024, cancellation=op.guard)
            self.assertEqual((seen, remote, sends), ([], [], []))

    def test_candidate_handoff_refuses_after_command_return_not_forged_from_json(self):
        with original() as (op, _, mode, __, ___, sends):
            op.admit()
            def before(tx, channel):
                op.remote_returned = True  # Deliberately contradictory original fact.
            mode.before_hook = before
            with self.assertRaises(Exception):
                op.run()
            self.assertFalse(op.source.candidate_claimed)
            self.assertEqual(sends, [])

    def test_lost_candidate_ack_or_ack_stop_never_reaches_send_and_is_not_replayable(self):
        for stopped in (False, True):
            with self.subTest(stopped=stopped), original() as (op, _, mode, __, remote, sends):
                mode.ack_stop = stopped
                if not stopped:
                    mode.ack_error = OSError("inert lost candidate ACK")
                op.admit()
                try:
                    op.run()
                except BaseException as error:
                    self.assertIsInstance(error, (OSError, KeyboardInterrupt, ProcessCleanupError,
                                                  core.GitError, wire.ProtocolError, ValueError))
                self.assertTrue(op.source.candidate_claimed)
                self.assertFalse(op.source.candidate_returned)
                self.assertEqual((len(remote), sends), (1, []))
                self.assertIsNotNone(op.repository._transaction.intent)
                self.assertFalse(op.repository._transaction.send_entered)
                with self.assertRaises(Exception):
                    op.source.handoff(op.source.candidate)

    def test_wrong_phase_duplicate_hook_and_early_send_cannot_obtain_second_ack(self):
        for field in ("duplicate_hook", "send_before_hook"):
            with self.subTest(field=field), original() as (op, _, mode, __, remote, sends):
                setattr(mode, field, True)
                op.admit()
                try:
                    op.run()
                except (ProcessCleanupError, core.GitError, wire.ProtocolError, NativeProcessError, ValueError):
                    pass
                self.assertEqual((len(remote), sends), (1, []))
                self.assertLessEqual(op.engine.write.call_count, 1)
                self.assertTrue(op.source.channel.failed)

    def test_missing_caw_or_helper_frame_is_unknown_not_git_zero_success(self):
        for field in ("lose_caw", "omit_return", "extra_eof"):
            with self.subTest(field=field), original() as (op, _, mode, __, remote, sends):
                setattr(mode, field, True)
                op.admit()
                with self.assertRaises((ProcessCleanupError, core.GitError, wire.ProtocolError, NativeProcessError, ValueError)):
                    op.run()
                self.assertTrue(op.unknown and op.repository._unknown)
                self.assertFalse(op.returned)
                self.assertEqual(len(remote), 1)
                if field == "lose_caw":
                    self.assertFalse(op.source.channel.finish_entered)
                    self.assertEqual(sends, [])

    def test_original_helper_earlier_first_failure_controls_merge_before_known_refusal(self):
        with original() as (op, _, mode, __, remote, sends):
            mode.returned_state = "refused"
            op.admit(); op.run()
            self.assertNotEqual(op.result.state, "succeeded")
            self.assertFalse(op.source.candidate_claimed)
            self.assertTrue(op.source.channel.closed and op.source.channel.eof)
            self.assertEqual(op.source.first_failure_ns, 95_000_000_000)
            self.assertEqual(op.source.cleanup_end_ns, 105_000_000_000)
            self.assertEqual(op.source.http_control["reason"], "forbidden")
            self.assertEqual((len(remote), sends), (1, []))


class TerminalTests(unittest.TestCase):
    def terminal(self, op):
        op.cleanup(); op.source.close()
        engine = op.engine
        engine.frames = 1 + int(op.source.candidate_claimed)
        engine.candidate_written = op.source.candidate_claimed
        # No native handlers were installed by this fixture. Source FD closes
        # above are real; this last handler-state DATA predicate is explicit.
        with patch.object(type(op.guard), "handler_state", new_callable=PropertyMock, return_value="RESTORED"):
            engine.terminal()
        return json.loads(engine.write.call_args.args[0])

    def test_joined_result_has_only_original_send_receipt_no_local_tracking_observation(self):
        with original() as (op, _, __, ___, ____, _____):
            op.admit(); op.run()
            row = self.terminal(op)
            self.assertEqual((row["status"], row["result"]["state"], row["result"]["effectPhase"]),
                             ("ok", "succeeded", "remote-returned"))
            self.assertIsNone(row["result"]["observation"])
            self.assertIsNotNone(row["transmission"]["body"]["sha256"])

    def test_late_stop_retains_receipt_but_only_recovery_not_success(self):
        with original() as (op, _, __, ___, ____, _____):
            op.admit(); op.run(); op.source.stop("timed-out")
            row = self.terminal(op)
            self.assertEqual((row["status"], row["result"]["state"], row["result"]["reason"]),
                             ("ok", "recovery-required", "deadline"))
            self.assertIsNotNone(row["transmission"])
            self.assertIsNotNone(row["firstFailureNs"])

    def test_actual_retained_apply_view_encodes_nested_path_without_claiming_send_or_finality(self):
        with original() as (op, world, mode, _, remote, sends):
            mode.returned_state = "refused"
            op.admit(); op.run()
            tx = op.repository._transaction
            self.assertTrue(tx.retained and tx.view.retained)
            self.assertEqual(tx.view.root.parent, tx.scratch)
            path = str(tx.view.root.relative_to(world.root / ".git"))
            self.assertRegex(path, r"^mrk-git-[a-z0-9_]{1,32}/mrk-git-push-[a-z0-9_]{1,32}$")
            self.assertEqual(tx.diagnostics(), ("not-sent", (path,)))
            row = self.terminal(op)
            self.assertEqual((row["status"], row["result"]["state"]), ("ok", "recovery-required"))
            self.assertEqual(row["result"]["retainedPaths"], [path])
            self.assertIsNone(row["result"]["intent"])
            self.assertIsNone(row["transmission"])
            self.assertEqual((len(remote), sends), (1, []))
            self.assertTrue(tx.view.root.is_dir())  # No cleanup/retry from diagnostic DATA.

    def test_unknown_native_or_private_close_cannot_publish_joined_send_receipt(self):
        with original() as (op, _, __, ___, ____, _____):
            op.admit(); op.run(); op.unknown = True  # Explicit fake unknown fact.
            row = self.terminal(op)
            self.assertEqual((row["status"], row["reason"]), ("cleanup-unknown", "unknown"))
            self.assertIsNone(row["result"]); self.assertIsNone(row["transmission"])


if __name__ == "__main__":
    unittest.main()
