"""Original C/A/W command contracts and isolated synthetic-command regressions.

Only CommandContractTests is inert/local. OwnedProcessTests creates processes and
must run through the reviewed disposable/native owner, never the shared host.
Historical raw-supervisor framing/selector fixtures are replaced by the bounded
Wire tests; profile fork/FD/scratch coverage lives in profile_process_owner and
profile_resource_fixture, not a second Popen owner here.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import mobile_release
from mobile_release import _command_process as command, owned_process as owned
from mobile_release.cancellation import DefaultCancellation


@contextmanager
def original_command_outcomes():
    """Observe original publications; an unpublished later call stays UNKNOWN."""
    run, publish = command.run_command, command._Outer.publish
    outcomes, active = [], []
    def called(*args, **kwargs):
        index = len(outcomes)
        outcomes.append(None)  # Retained before the actual command can start.
        active.append(index)
        try:
            return run(*args, **kwargs)
        finally:
            assert active.pop() == index
    def published(engine):
        outcome = publish(engine)
        assert active and outcomes[active[-1]] is None
        assert engine.slot.read() is outcome
        outcomes[active[-1]] = outcome
        return outcome
    with patch.object(command, "run_command", new=called), \
         patch.object(command._Outer, "publish", new=published):
        yield outcomes


def all_original_commands_final(outcomes):
    return bool(outcomes) and all(value is not None and value.original_finality is not None for value in outcomes)


class _InertLease:
    """No descriptor is opened, closed, read or written by this test stand-in."""
    def __init__(self, number=101):
        self.number, self.state, self.calls = number, "OPEN", 0

    def fileno(self):
        if self.state != "OPEN":
            raise AssertionError("retired test descriptor reused")
        return self.number

    def close(self):
        self.calls += 1
        self.state = "CLOSED"


class CommandContractTests(unittest.TestCase):
    """Finite protocols/ordering only: no native child, thread, FD or signal."""
    def setUp(self):
        for name in ("create",):
            blocked = patch.object(command.native, name, side_effect=AssertionError("inert check attempted native creation"))
            blocked.start(); self.addCleanup(blocked.stop)
        for name in ("kill", "killpg", "fork", "execve", "pipe", "open"):
            blocked = patch.object(command.os, name, side_effect=AssertionError("inert check attempted an OS effect"))
            blocked.start(); self.addCleanup(blocked.stop)
        blocked = patch.object(command.threading.Thread, "start", side_effect=AssertionError("inert check started a thread"))
        blocked.start(); self.addCleanup(blocked.stop)

    def context(self, role="O"):
        now = time.monotonic_ns()
        return command._Context(role, b"n" * 16, now + 30 * command.NANOSECOND,
                                now + 33 * command.NANOSECOND)

    def frozen(self, **kwargs):
        values = dict(environ={"PATH": ":relative:relative:/bin", "EMPTY": ""},
                      cwd=Path("/fictional/cwd"), capture=True, output_limit=8192, nonce=b"n" * 16)
        values.update(kwargs)
        return command._freeze_command(["tool", "", "surrogate-\udcff"], **values)

    def wire(self, ctx=None, *, diagnostics=False):
        ctx = self.context() if ctx is None else ctx
        with patch.object(command.os, "set_blocking"):
            return command._Wire(ctx, _InertLease(101), _InertLease(102), diagnostics=diagnostics)

    def test_adapter_passes_authoritative_objects_without_manufacturing_a_result(self):
        result = subprocess.CompletedProcess(["fixture"], -9, "", "")
        source, binding, guard = object(), object(), object()
        with patch.object(command, "run_command", return_value=result) as run:
            self.assertIs(owned.run_owned(["fixture"], execution_scope=source,
                                         journal_binding=binding, cancellation=guard), result)
        self.assertIs(run.call_args.kwargs["execution_scope"], source)
        self.assertIs(run.call_args.kwargs["journal_binding"], binding)
        self.assertIs(run.call_args.kwargs["cancellation"], guard)

    def test_native_record_roundtrip_preserves_bytes_and_original_path_components(self):
        env = {"PATH": ":relative:relative:/bin", "EMPTY": "", "LARGE": "x" * 9000}
        env.update({"KEY" + str(i): str(i) for i in range(90)})
        frozen = self.frozen(environ=env)
        m = frozen.manifest
        self.assertEqual(len(m.encode()), 154)
        self.assertEqual(command.Manifest.decode(m.encode()), m)
        content = b"".join(frozen.pieces())
        self.assertEqual(len(content), m.record_bytes)
        self.assertEqual(hashlib.sha256(content).digest(), m.digest)
        decoded = command.NativeRecordDecoder(m)
        for index in range(0, len(content), 31):
            decoded.feed(content[index:index + 31])
        decoded.finish()
        self.assertEqual(decoded.argv, [b"tool", b"", b"surrogate-\xff"])
        self.assertEqual(decoded.directories, [b"", b"relative", b"relative", b"/bin"])
        self.assertEqual(decoded.environment[b"LARGE"], b"x" * 9000)
        self.assertGreater(len(decoded.environment), 64)
        self.assertEqual(decoded.cwd, b"/fictional/cwd")

    def test_exact_chunk_shape_and_host_envelope_do_not_limit_argv_to_native_config_size(self):
        frozen = command._freeze_command(["/fictional/tool", "a" * 90_000], environ={}, cwd=Path("/"),
                                         capture=False, output_limit=1, nonce=b"n" * 16)
        chunks = list(frozen.chunks())
        self.assertEqual([len(chunk) for chunk in chunks[:-1]], [command.CHUNK])
        self.assertEqual(sum(map(len, chunks)), frozen.manifest.record_bytes)
        self.assertFalse(frozen.manifest.search)
        self.assertEqual(frozen.directories, ())
        with patch.object(command.os, "sysconf", return_value=True), self.assertRaises(owned.ProcessError):
            self.frozen()
        with patch.object(command.os, "sysconf", return_value=2), self.assertRaises(owned.ProcessError):
            self.frozen(environ={"a": ""})

    def test_native_decoder_rejection_is_sticky_including_entry_and_finish_failures(self):
        frozen = self.frozen()
        content = b"".join(frozen.chunks())
        for kind in ("empty", "wrong-count", "truncated", "trailing", "duplicate-complete"):
            with self.subTest(kind=kind):
                decoder = command.NativeRecordDecoder(frozen.manifest)
                with self.assertRaises(owned.ProcessError):
                    if kind == "empty": decoder.feed(b"")
                    elif kind == "wrong-count": decoder.feed((99).to_bytes(8, "big") + content[8:])
                    elif kind == "truncated": decoder.feed(content[:-1]); decoder.finish()
                    elif kind == "trailing": decoder.feed(content + b"x")
                    else: decoder.feed(content); decoder.feed(b"x")
                self.assertTrue(decoder.poisoned)
                with self.assertRaises(owned.ProcessError): decoder.feed(content)
                with self.assertRaises(owned.ProcessError): decoder.finish()
        with self.assertRaises(owned.ProcessError):
            dataclasses.replace(frozen.manifest, record_bytes=frozen.manifest.record_bytes + 1).validate()

    def test_json_budget_stops_before_encoding_large_shared_reference_vector(self):
        original = command.json.JSONEncoder.iterencode
        emitted = []
        def counted(encoder, value, *args, **kwargs):
            for fragment in original(encoder, value, *args, **kwargs):
                emitted.append(len(fragment))
                yield fragment
        # Only one modest string is allocated here. The historical whole-JSON
        # encode of all4096 references would need multi-GiB temporary storage.
        argument = "a" * (owned.REQUEST_LIMIT - 200)
        with patch.object(command.json.JSONEncoder, "iterencode", new=counted):
            with self.assertRaises(owned.ProcessError):
                command._freeze_command([argument] * 4096, environ={}, cwd=Path("/"),
                    capture=False, output_limit=1, nonce=b"n" * 16)
        self.assertLess(len(emitted), 20)
        self.assertLess(sum(emitted), owned.REQUEST_LIMIT * 3)
        frozen = self.frozen()
        expected = owned._json({"argv": list(frozen.args), "cwd": "/fictional/cwd", "capture": True, "limit": 8192})
        self.assertEqual(frozen.manifest.json_size, len(expected))

    def test_grant_attempt_precedes_first_possible_write_and_retirement_never_retries_it(self):
        for write_result in (BlockingIOError(), 2):
            with self.subTest(write_result=type(write_result).__name__):
                wire = self.wire()
                route = command._Route(command.Tag.RUN_TOOL)
                wire.ctx.routes.append(route)
                wire.queue(command.Tag.RUN_TOOL, command._scalar(wire.ctx.nonce), route)
                def write(_fd, _value):
                    self.assertTrue(route.attempted)
                    if isinstance(write_result, BaseException): raise write_result
                    return write_result
                with patch.object(command.os, "write", side_effect=write) as write_call:
                    self.assertFalse(wire.flush())
                    route.retire()
                    self.assertFalse(wire.flush())
                self.assertEqual(write_call.call_count, 1)
                self.assertTrue(route.attempted and route.retired)
                self.assertEqual(wire.writer.calls, 1)
                with self.assertRaises(owned.ProcessError): route.queue()

    def test_wire_bounds_and_semantic_failure_never_admit_a_replacement_frame(self):
        wire = self.wire()
        data = bytearray(b"\xff\x00\x00\x00\x01x")
        def read(_fd, size):
            result = bytes(data[:size]); del data[:size]; return result
        with patch.object(command.os, "read", side_effect=read):
            with self.assertRaises(owned.ProcessError): wire.read()
            self.assertTrue(wire.poisoned)
            with self.assertRaises(owned.ProcessError): wire.read()
            self.assertFalse(wire.drain_to_eof())
            self.assertTrue(wire.drain_to_eof())
        manifest = self.frozen().manifest
        wire = self.wire()
        wire.expected_manifest = manifest
        wire.queue(command.Tag.MANIFEST, manifest.encode())
        wire.out = None  # Inert completed transport; do not fabricate ownership.
        with self.assertRaises(owned.ProcessError): wire.queue(command.Tag.RUN_TOOL, command._scalar(wire.ctx.nonce))
        with self.assertRaises(owned.ProcessError): wire.queue(command.Tag.DATA, b"x")

    def test_first_error_and_failure_endpoint_survive_later_interruptions_and_clock_failure(self):
        ctx = self.context()
        first, later = ValueError("first"), KeyboardInterrupt()
        now = time.monotonic_ns()
        with patch.object(command.time, "monotonic_ns", return_value=now): ctx.record(first)
        endpoint = ctx.cutoff()
        with patch.object(command.time, "monotonic_ns", return_value=now + 10 * command.NANOSECOND): ctx.record(later)
        self.assertIs(ctx.primary, first)
        self.assertIs(ctx.first_interruption, later)
        self.assertEqual(ctx.cutoff(), endpoint)
        ctx = self.context()
        with patch.object(command.time, "monotonic_ns", side_effect=OSError("clock")): ctx.record(first)
        self.assertIs(ctx.primary, first)
        self.assertEqual(ctx.cutoff(), 0)
        self.assertTrue(ctx.cleanup_unknown)

    def test_close_custody_is_retired_once_even_when_return_is_lost(self):
        ctx, lease = self.context(), _InertLease()
        def failed_close():
            lease.calls += 1
            lease.state = "UNKNOWN"
            raise OSError("fictional close publication")
        lease.close = failed_close
        ctx.close(lease)
        ctx.close(lease)
        self.assertEqual(lease.calls, 1)
        self.assertTrue(ctx.cleanup_unknown)
        self.assertIsInstance(ctx.primary, OSError)

    def test_retained_context_fork_refusal_precedes_inherited_lock_or_callbacks(self):
        ctx = self.context()
        ctx.lock = Mock(side_effect=AssertionError("inherited mutex"))
        acquisition = Mock()
        ctx.acquisitions = [acquisition]
        route = command._Route(command.Tag.CREATE_W, attempted=True)
        ctx.routes.append(route)
        with patch.object(command.os, "getpid", return_value=ctx.pid + 1):
            with self.assertRaises(owned.ProcessCleanupError): ctx.record(ValueError("child"))
        acquisition._relinquish_inherited.assert_called_once_with()
        self.assertTrue(route.attempted and route.retired)
        self.assertIsNone(ctx.primary)
        ctx.lock.assert_not_called()

    def test_original_numeric_route_is_unusable_after_first_wait_retirement(self):
        ctx = self.context("C")
        anchor = SimpleNamespace(pid=2001, wait_state="OWNED", numeric_retired=False)
        ctx.child_acquisition._child = anchor
        group = command._AnchorGroup(ctx, anchor)
        with patch.object(command.os, "killpg") as signal_group:
            group.terminate()
            anchor.numeric_retired = True
            with self.assertRaises(owned.ProcessError): group.probe()
            with self.assertRaises(owned.ProcessError): group.terminate()
        self.assertEqual(signal_group.call_count, 1)

    def test_worker_rejection_has_exactly_one_nonblocking_attempt_even_on_partial_write(self):
        worker = command._Worker.__new__(command._Worker)
        worker.ctx = self.context("W")
        worker.upstream = self.wire(worker.ctx)
        worker.mapping = {4: worker.upstream.writer}
        worker.exec_retired = worker.reject_attempted = False
        with patch.object(command.os, "write", return_value=1) as write:
            with self.assertRaises(owned.ProcessError): worker._reject("exec", 2)
            with self.assertRaises(owned.ProcessError): worker._reject("exec", 2)
        self.assertTrue(worker.exec_retired and worker.reject_attempted)
        self.assertEqual(write.call_count, 1)
        self.assertLessEqual(len(write.call_args.args[1]), 512)

    def test_terminal_cannot_invent_local_create_or_run_and_127_is_not_exec_rejection(self):
        guard = DefaultCancellation(owned.ProcessCleanupError, "fixture")
        engine = command._Outer(guard, True, 30, None, None, suppress_cancel=False)
        engine.frozen = self.frozen(nonce=engine.nonce)
        engine.sealed = True
        fields = dict(create=True, run=True, no_target=None, wait={"kind": "exit", "code": 127},
                      producer=True, result=True, stdout=0, stderr=0, fence=None)
        with self.assertRaises(owned.ProcessError): engine._terminal(command._scalar(engine.nonce, **fields))
        engine.create_route.attempted = engine.run_route.attempted = True
        engine.prepared, engine.ready = {"group": 2002, "signals": 0}, True
        self.assertEqual(engine._terminal(command._scalar(engine.nonce, **fields))["wait"]["code"], 127)
        with self.assertRaises(owned.ProcessError):
            engine._terminal(command._scalar(engine.nonce, **{**fields, "no_target": "EXEC_REJECTED"}))
        fields["wait"] = {"kind": "signal", "code": signal.SIGKILL}
        fields["no_target"] = "EXEC_REJECTED"
        self.assertEqual(engine._terminal(command._scalar(engine.nonce, **fields))["no_target"], "EXEC_REJECTED")

    def test_latched_helper_stop_cannot_be_erased_by_a_later_terminal_epoch(self):
        for role in ("A", "C"):
            for edge in ("before-snapshot", "after-snapshot", "armed-tail"):
                with self.subTest(role=role, edge=edge):
                    ctx = self.context(role)
                    wire = self.wire(ctx)
                    wire.sent.append(command.Tag.TERMINAL)
                    wire.writer.close()
                    if edge == "before-snapshot":
                        ctx.helper_signal(signal.SIGTERM, None)
                    epoch = ctx.error_epoch, ctx.signal_epoch
                    if edge == "after-snapshot":
                        ctx.helper_signal(signal.SIGTERM, None)
                    if edge == "armed-tail":
                        def signalled_check():
                            ctx.helper_signal(signal.SIGTERM, None)
                            raise AssertionError("armed signal returned")
                        with patch.object(ctx, "settled", side_effect=signalled_check), \
                             patch.object(command.os, "_exit", side_effect=SystemExit(command.HELPER_UNKNOWN)) as exited:
                            with self.assertRaises(SystemExit) as caught:
                                command._terminal_code(ctx, wire, epoch, allowed=True)
                            self.assertEqual(caught.exception.code, command.HELPER_UNKNOWN)
                            exited.assert_called_once_with(command.HELPER_UNKNOWN)
                    else:
                        # Calling the real terminal gate on an actual resource-
                        # free context does not fabricate a native finality.
                        ctx.check_tail()  # Stop never cancels the required tail.
                        self.assertEqual(command._terminal_code(ctx, wire, epoch, allowed=True),
                            command.HELPER_FAILED if edge == "before-snapshot" else command.HELPER_UNKNOWN)

    def test_c_result_and_terminal_status_preserve_signal_during_fence_or_publication(self):
        # Inert orchestration only: native producer/fence prerequisites are
        # isolated here, never presented as original process or disk evidence.
        for edge in ("none", "fence", "serialization", "publication"):
            with self.subTest(edge=edge):
                ctx = self.context("C")
                owner = command._Custodian.__new__(command._Custodian)
                owner.ctx, owner.upstream = ctx, self.wire(ctx)
                owner.relay, owner.producer, owner.account = (ctx.acquisition() for _ in range(3))
                owner._settle_producers = lambda: None
                owner._producer_settled = lambda: True
                owner.seal_descendants = lambda: None
                def fence(_seal):
                    if edge == "fence": ctx.helper_signal(signal.SIGTERM, None)
                owner.writer = SimpleNamespace(publish=fence, close=lambda: True, complete=True)
                owner.writer_prepared = True
                owner._relay_output = lambda: True
                owner.anchor_work = dict(result=True, no_child=False, run=True, rejected=None,
                                         wait={"kind": "exit", "code": 0})
                owner.wait = SimpleNamespace(status_code=command.HELPER_OK)
                owner.output_overflow = owner.source_failed = False
                owner.output = [b"", b""]
                owner.create_route = owner.run_route = SimpleNamespace(attempted=True)
                frames = []
                encode = command._scalar
                def scalar(nonce, **fields):
                    if edge == "serialization" and "fence" in fields:
                        ctx.helper_signal(signal.SIGTERM, None)
                    return encode(nonce, **fields)
                def send(wire, tag, content, *_args, **_kwargs):
                    wire.sent.append(tag)
                    if tag is command.Tag.TERMINAL:
                        frames.append(owned._parse(content))
                        if edge == "publication": ctx.helper_signal(signal.SIGTERM, None)
                with patch.object(command, "_scalar", new=scalar), patch.object(command, "_send", new=send):
                    result = owner.finish()
                self.assertEqual(len(frames), 1)
                self.assertIs(frames[0]["result"], edge != "fence")
                self.assertTrue(frames[0]["producer"] and frames[0]["fence"])
                self.assertEqual(result, command.HELPER_OK if edge == "none" else
                                 command.HELPER_FAILED if edge == "fence" else command.HELPER_UNKNOWN)

    def event(self, ordinal, operation, edge, *, written=0, flags=0, outcome=None, identity=True):
        if outcome is None:
            outcome = command.FenceEventOutcome.PENDING if edge == command.FenceEdge.BEFORE else command.FenceEventOutcome.OK
        created = (1, 2, os.getuid(), os.getgid(), stat.S_IFREG | 0o600, 1)
        return command.FenceObservation(b"n" * 16, 1, ordinal, operation, edge, outcome,
                                        written, 100, flags, 1 if identity else 0,
                                        created if identity else None,
                                        b"x" * 50 if edge == command.FenceEdge.PARTIAL else b"")

    def test_fence_automaton_preserves_original_identity_and_rejects_replay(self):
        decoder = command.FenceObservationDecoder(b"n" * 16, 1, uid=os.getuid())
        events = [self.event(1, command.FenceOperation.PENDING_CREATE, command.FenceEdge.BEFORE, identity=False),
                  self.event(2, command.FenceOperation.PENDING_CREATE, command.FenceEdge.AFTER),
                  self.event(3, command.FenceOperation.PENDING_WRITE, command.FenceEdge.BEFORE),
                  self.event(4, command.FenceOperation.PENDING_WRITE, command.FenceEdge.PARTIAL, written=7)]
        for event in events:
            self.assertEqual(decoder.accept(event.encode()), event)
            self.assertEqual(len(event.ack()), 28)
        self.assertEqual(len(events[-1].encode()), 119)
        with self.assertRaises(owned.ProcessError): decoder.accept(events[-1].encode())
        self.assertTrue(decoder.poisoned)
        with self.assertRaises(owned.ProcessError): decoder.accept(events[0].encode())

    def test_retired_observer_with_possible_delivery_waits_original_loss_not_late_ack(self):
        ctx = self.context("C")
        writer = SimpleNamespace(ctx=ctx, policy=command.FenceObservationPolicy.TRACE_V1,
                                 creation_identity=None, observation_identity_unavailable=False)
        wire = SimpleNamespace(eof=False, reader=_InertLease(), read=Mock(side_effect=AssertionError("late ACK read")))
        observer = command._FenceObserver(writer, wire, _key=command._KEY)
        observer.retired = observer.delivery_possible = True
        def drain(): wire.eof = True; return True
        wire.drain_to_eof = Mock(side_effect=drain)
        with patch.object(command, "_pause"):
            observer._hold_after_retirement()
        self.assertTrue(observer.owner_loss)
        self.assertIsInstance(ctx.primary, owned.ProcessError)
        wire.read.assert_not_called()
        wire.drain_to_eof.assert_called_once_with()

    def test_original_checkpoint_failure_holds_late_ack_until_original_loss_or_cutoff(self):
        cases = (("lost-send", "eof"), ("lost-send", "parent"),
                 ("wrong-ack", "eof"), ("wrong-ack", "parent"),
                 ("wrong-ack", "deadline"), ("live-stall", "deadline"))
        for failure, ending in cases:
            with self.subTest(failure=failure, ending=ending):
                ctx = self.context("C")
                wire = self.wire(ctx, diagnostics=True)
                writer = SimpleNamespace(ctx=ctx, fields={"sequence": 1},
                    policy=command.FenceObservationPolicy.TRACE_V1,
                    creation_identity=None, observation_identity_unavailable=False)
                observer = command._FenceObserver(writer, wire, _key=command._KEY)
                raw, writes, held = bytearray(), [], []
                state = {"now": time.monotonic_ns(), "release": False, "pauses": 0}
                original_cutoff = ctx.cutoff()
                def encoded_ack(content):
                    return bytes((command.Tag.FENCE_ACK,)) + len(content).to_bytes(4, "big") + content
                def write(fd, content):
                    self.assertTrue(observer.delivery_possible)
                    self.assertFalse(observer.acknowledged)
                    self.assertEqual(fd, wire.writer.number)
                    writes.append(bytes(content))
                    ack = observer.outstanding.ack()
                    if failure == "wrong-ack":
                        raw.extend(encoded_ack(ack[:-1] + bytes((ack[-1] ^ 1,))))
                    if failure != "live-stall":
                        raw.extend(encoded_ack(ack))  # Late matching ACK is not release.
                    if failure == "lost-send":
                        raise OSError("original event write return lost")
                    return len(content)
                def read(fd, count):
                    self.assertEqual(fd, wire.reader.number)
                    if raw:
                        chunk = bytes(raw[:count]); del raw[:count]
                        return chunk
                    if state["release"] and ending == "eof":
                        return b""  # Only this original read observes EOF.
                    raise BlockingIOError()
                def pause(_cutoff):
                    if observer.retired:
                        if wire.eof:
                            self.assertTrue(state["release"] and ending == "eof")
                            self.assertFalse(observer.acknowledged)
                            return  # Positive original EOF is reconciled next loop.
                        self.assertFalse(observer.acknowledged or observer.owner_loss or wire.eof)
                        self.assertFalse(raw, "late ACK was not consumed by original drain")
                        held.append(True)
                        if len(held) == 2:
                            if ending == "deadline": state["now"] = ctx.cutoff()
                            else: state["release"] = True
                    elif failure == "live-stall":
                        state["pauses"] += 1
                        if state["pauses"] == 3: state["now"] = ctx.cutoff()
                def checkpoint():
                    observer.checkpoint(command.FenceOperation.PENDING_CREATE, command.FenceEdge.BEFORE,
                        command.FenceEventOutcome.PENDING, written=0, total=100, sync_flags=0)
                with patch.object(command.os, "write", new=write), patch.object(command.os, "read", new=read), \
                     patch.object(command, "_pause", new=pause), \
                     patch.object(command.time, "monotonic_ns", side_effect=lambda: state["now"]), \
                     patch.object(ctx, "parent_lost", side_effect=lambda: ending == "parent" and state["release"]):
                    if ending == "deadline":
                        with self.assertRaises(owned.ProcessError): checkpoint()
                        with self.assertRaises(owned.ProcessError): checkpoint()
                    else:
                        checkpoint()
                        self.assertTrue(observer.owner_loss)
                        checkpoint()  # Retired observation cannot publish a new event.
                self.assertTrue(observer.retired and observer.delivery_possible)
                self.assertFalse(observer.acknowledged)
                self.assertEqual(observer.ordinal, 1)
                self.assertEqual(len(writes), 1)
                self.assertLessEqual(ctx.cutoff(), original_cutoff)
                if failure != "live-stall": self.assertEqual(len(held), 2)


class CommandSourceOwnerTests(unittest.TestCase):
    """Real task-local locked source; no process, thread or signal mutation."""
    def test_source_caller_uses_actual_zero_handler_owner_before_any_native_effect(self):
        from mobile_release import discovery, local_signing
        entries = []
        custom = lambda _number, _frame: None
        with tempfile.TemporaryDirectory(prefix="mrk-command-source-") as name, \
             patch.object(signal, "getsignal", return_value=custom), \
             patch.object(signal, "signal", side_effect=AssertionError("custom handler changed")), \
             patch.object(command.native.Acquisition, "_runtime", side_effect=AssertionError("native effect")):
            home = Path(name) / "home"; home.mkdir(mode=0o700)
            with local_signing.local_signing_lease(home=home) as lease:
                source = lease.execution_source()
                self.assertIs(type(source), command.AccountExecutionSource)
                self.assertEqual(lease.cancellation._signals, {})
                def inert_body(engine, *_args):
                    entries.append(engine)
                    self.assertIs(engine.guard, lease.cancellation)
                    self.assertIs(engine.scope._source, source)
                    self.assertFalse(engine.owns)
                with patch.object(command._Outer, "body", new=inert_body):
                    self.assertIsNone(discovery._run(home, ["fictional"], execution_source=source))
                self.assertEqual(len(entries), 1)
                self.assertEqual(lease.cancellation.lifetime_ledger.verdict().commands, 1)
                self.assertEqual(entries[0].scope.outcome.read().no_target.kind, "NO_W_CREATION")

    def test_explicit_wrong_owner_rejects_without_consuming_the_actual_scope(self):
        from mobile_release import local_signing
        custom = lambda _number, _frame: None
        with tempfile.TemporaryDirectory(prefix="mrk-command-source-") as name, \
             patch.object(signal, "getsignal", return_value=custom), \
             patch.object(signal, "signal", side_effect=AssertionError("custom handler changed")), \
             patch.object(command.native.Acquisition, "_runtime", side_effect=AssertionError("native effect")):
            home = Path(name) / "home"; home.mkdir(mode=0o700)
            with local_signing.local_signing_lease(home=home) as lease:
                scope = lease.execution_source().new_scope()
                wrong = DefaultCancellation(owned.ProcessCleanupError, "wrong owner")
                with patch.object(command, "_Outer", side_effect=AssertionError("engine created")):
                    with self.assertRaises(owned.ProcessError):
                        owned.run_owned(["fictional"], execution_scope=scope, cancellation=wrong)
                self.assertFalse(scope._used)
                self.assertIsNone(scope.outcome.read())
                self.assertIsNone(lease.cancellation.lifetime_ledger._command)
                self.assertEqual(lease.cancellation.lifetime_ledger.verdict().commands, 0)


class OwnedProcessTests(unittest.TestCase):
    """Native evidence: only under the reviewed disposable/native test owner."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mrk-owned-command-"))
        self.unconfirmed_fixtures = []
        observation = original_command_outcomes()
        self.outcomes = observation.__enter__()
        self.addCleanup(observation.__exit__, None, None, None)
        self.addCleanup(self.remove_settled_fixture)

    def remove_settled_fixture(self):
        if not all_original_commands_final(self.outcomes) or self.unconfirmed_fixtures:
            self.fail(f"original fixture finality unconfirmed; preserving {self.root}")
        shutil.rmtree(self.root)

    def command(self, code):
        return [sys.executable, "-I", "-S", "-B", "-c", code]

    def test_fork_at_original_child_handoff_or_active_io_preserves_parent_worker(self):
        fixture = Path(__file__).parents[1] / "workflow/owned_process_fork_fixture.py"
        for mode in ("command-open", "command-active"):
            with self.subTest(mode=mode):
                root = self.root / mode; root.mkdir(mode=0o700)
                self.unconfirmed_fixtures.append(root)
                result = owned.run_owned([sys.executable, "-I", "-S", "-B", str(fixture),
                                         str(Path(mobile_release.__file__).resolve().parent.parent), str(root), mode],
                                         timeout=25)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(result.stderr)
                self.assertTrue(json.loads(result.stdout)["checkedBeforeFallback"])
                self.unconfirmed_fixtures.remove(root)

    def test_complete_results_nonzero_output_bounds_and_no_echoed_private_request(self):
        result = owned.run_owned(self.command('import sys; print("fictional"); print("fixture-error",file=sys.stderr); sys.exit(7)'), cwd=self.root)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (7, "fictional\n", "fixture-error\n"))
        result = owned.run_owned(self.command('print("not captured")'), cwd=self.root, capture=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        with self.assertRaises(owned.ProcessError) as raised:
            owned.run_owned(self.command('import os; os.write(1,b"private-canary"*1000)'), cwd=self.root, output_limit=256)
        self.assertTrue(raised.exception.dispatched and raised.exception.contained)
        self.assertNotIn("private-canary", str(raised.exception))

    def test_callback_cancellation_and_exec_rejection_are_not_normal_127(self):
        target = self.root / "never-created"
        original = KeyboardInterrupt()
        def cancel(_pid): raise original
        with self.assertRaises(KeyboardInterrupt) as raised:
            owned.run_owned(self.command(f'from pathlib import Path; Path({str(target)!r}).touch()'), on_start=cancel)
        self.assertIs(raised.exception, original)
        self.assertFalse(target.exists())
        with self.assertRaises(owned.ProcessError) as raised:
            owned.run_owned(["/this-fictional-command-does-not-exist"], cwd=self.root)
        self.assertFalse(raised.exception.dispatched)
        self.assertTrue(raised.exception.contained)
        self.assertEqual(owned.run_owned(self.command("raise SystemExit(127)")).returncode, 127)
        result = owned.run_owned(self.command("import os,signal;os.kill(os.getpid(),signal.SIGTERM)"))
        self.assertEqual(result.returncode, -signal.SIGTERM)

    def test_owned_descendants_settle_before_success_timeout_or_failure_returns(self):
        for mode in ("success", "failure", "timeout"):
            with self.subTest(mode=mode):
                ready, heartbeat, stop = (self.root / (mode + "-" + name) for name in ("ready", "heartbeat", "stop"))
                child = ("import os,time\nfrom pathlib import Path\n"
                         f"Path({str(ready)!r}).write_text(str(os.getpid()))\nend=time.monotonic()+12\n"
                         f"while not Path({str(stop)!r}).exists() and time.monotonic()<end:\n"
                         f" Path({str(heartbeat)!r}).write_text(str(time.monotonic()))\n time.sleep(.01)\n")
                code = ("import subprocess,time\nfrom pathlib import Path\n"
                        f"subprocess.Popen({self.command(child)!r},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                        f"while not Path({str(heartbeat)!r}).exists():time.sleep(.01)\n"
                        + ("time.sleep(10)" if mode == "timeout" else f"raise SystemExit({7 if mode == 'failure' else 0})"))
                try:
                    if mode == "timeout":
                        with self.assertRaises(owned.ProcessError) as raised:
                            owned.run_owned(self.command(code), timeout=3)
                        self.assertTrue(raised.exception.dispatched and raised.exception.contained)
                    else:
                        result = owned.run_owned(self.command(code), timeout=8)
                        self.assertEqual(result.returncode, 7 if mode == "failure" else 0)
                    self.assertTrue(heartbeat.is_file(), "real descendant never acknowledged")
                    observed = heartbeat.read_text(); time.sleep(.03)
                    self.assertEqual(heartbeat.read_text(), observed)
                    self.assertTrue(all_original_commands_final(self.outcomes))
                finally:
                    stop.touch()  # Cooperative fixture only; never signal a recorded PID.

    def test_frozen_env_and_surrogate_bytes_reach_the_actual_same_pid_exec(self):
        env = {"PATH": os.defpath, "EMPTY": "", "LARGE": "x" * 9000, "RAW": "\udcff"}
        env.update({"KEY" + str(index): str(index) for index in range(90)})
        code = ("import os,sys,json; print(json.dumps([os.fsencode(sys.argv[1]).hex(),"
                "os.environb[b'RAW'].hex(),len(os.environb[b'LARGE']),os.environb[b'EMPTY'].hex()]))")
        result = owned.run_owned(self.command(code) + ["\udcff"], environ=env, cwd=self.root)
        self.assertEqual(json.loads(result.stdout), ["ff", "ff", 9000, ""])

    def test_root_cleanup_can_finish_after_already_delivered_default_cancellation(self):
        guard = DefaultCancellation(owned.ProcessCleanupError, "fixture restoration")
        guard.install(); guard.activate()
        try:
            with self.assertRaises(KeyboardInterrupt): guard.interrupt(signal.SIGINT, None)
            with guard.deferred(check_on_exit=False):
                result = owned.run_owned(self.command("pass"), cancellation=guard, cleanup=True)
                self.assertEqual(result.returncode, 0)
            self.assertFalse(guard.lifetime_ledger.fatal)
        finally:
            guard.restore()


if __name__ == "__main__":
    unittest.main()
