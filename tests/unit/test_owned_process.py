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
        from .test_lifetime_evidence import fork_registry_model
        self.enterContext(fork_registry_model())
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

    def _inert_no_child_anchor(self):
        # Real finish/parser/terminal code around an explicitly resource-free
        # no-child branch. No invented native process or wait receipt is used.
        ctx = self.context("A")
        owner = command._Anchor.__new__(command._Anchor)
        owner.ctx, owner.upstream = ctx, self.wire(ctx)
        owner.relay, owner.account, owner.producer = (ctx.acquisition() for _ in range(3))
        owner.mapping = {6: _InertLease(103), 7: _InertLease(104)}
        owner.group = SimpleNamespace(retired=False)
        owner.child = owner.downstream = owner.wait = owner.rejection = owner.work_done = None
        owner.moved = True
        owner.armed = owner.no_child = owner.worker_protocol_failed = owner.group_done = False
        owner.create_route = command._Route(command.Tag.CREATE_W)
        owner.run_route = command._Route(command.Tag.RUN_TOOL)
        ctx.routes.extend((owner.create_route, owner.run_route))
        return owner

    @contextmanager
    def _inert_anchor_transport(self, owner, frames, *, clock=None, after_read=None):
        pending = bytearray(b"".join(bytes((tag,)) + len(body).to_bytes(4, "big") + body
                                   for tag, body in frames))
        written = []

        def read(descriptor, maximum):
            self.assertEqual(descriptor, owner.upstream.reader.number)
            data = bytes(pending[:maximum])
            del pending[:maximum]
            if after_read is not None:
                after_read(pending)
            return data

        def write(descriptor, data):
            self.assertEqual(descriptor, owner.upstream.writer.number)
            self.assertEqual(int.from_bytes(data[1:5], "big"), len(data) - 5)
            written.append((command.Tag(data[0]), bytes(data[5:])))
            return len(data)

        clock = [time.monotonic_ns()] if clock is None else clock
        with patch.object(command.os, "read", side_effect=read), \
             patch.object(command.os, "write", side_effect=write), \
             patch.object(command.time, "monotonic_ns", side_effect=lambda: clock[0]), \
             patch.object(command, "_pause", return_value=None):
            yield written

    def _inert_custodian(self, expected=command.Tag.PREPARED, *, create=True):
        owner = command._Custodian.__new__(command._Custodian)
        owner.ctx = self.context("C")
        owner.downstream = self.wire(owner.ctx)
        owner._parent = lambda: None
        owner.anchor_hello, owner.group_done_sent = True, False
        owner.anchor_protocol_failed = False
        owner.anchor_expected = owner.anchor_reply = None
        owner.anchor_work = owner.anchor_terminal = None
        owner.child = owner.wait = owner.seal = owner.group = None
        owner.create_route = command._Route(command.Tag.CREATE_W)
        owner.run_route = command._Route(command.Tag.RUN_TOOL)
        owner.ctx.routes.extend((owner.create_route, owner.run_route))
        owner._expect_anchor(command.Tag.PREPARED)
        if expected is command.Tag.READY:
            owner._anchor_frame(command.Tag.PREPARED, command._scalar(owner.ctx.nonce))
            owner._receive_anchor(command.Tag.PREPARED)
            owner._expect_anchor(command.Tag.READY)
            if create:
                owner.create_route.queue()
                owner.create_route.attempt()
        return owner

    def _inert_custodian_settlement(self, owner):
        created = owner.create_route.attempted
        return command._scalar(owner.ctx.nonce, create=created, run=False,
                               no_child=not created, moved=True, armed=False, rejected=None,
                               wait={"kind": "signal", "code": signal.SIGKILL} if created else None,
                               producer=True, result=True)

    def test_custodian_handshake_wait_preserves_early_original_settlement(self):
        for expected in (command.Tag.PREPARED, command.Tag.READY):
            with self.subTest(expected=expected):
                owner = self._inert_custodian(expected)
                body = self._inert_custodian_settlement(owner)
                with self._inert_anchor_transport(SimpleNamespace(upstream=owner.downstream),
                                                  [(command.Tag.WORK_DONE, body)]) as writes:
                    with self.assertRaises(owned.ProcessError) as raised:
                        owner._receive_anchor(expected)
                self.assertEqual(owner.anchor_work, command._settlement_fields(body, owner.ctx))
                self.assertIs(owner.ctx.primary, raised.exception)
                self.assertTrue(owner.ctx.stopped and owner.ctx.launch_retired)
                self.assertTrue(owner.create_route.retired and owner.run_route.retired)
                self.assertFalse(owner.downstream.poisoned or owner.anchor_reply is not None)
                self.assertFalse(owner._producer_settled())  # DATA is not original lifetime proof.
                self.assertIsNone(owner.seal)
                self.assertEqual(writes, [])

        # Reproduce the old generic-receive failure without native execution;
        # its contract remains strict rather than accepting arbitrary frames.
        owner = self._inert_custodian()
        with self._inert_anchor_transport(SimpleNamespace(upstream=owner.downstream),
                [(command.Tag.WORK_DONE, self._inert_custodian_settlement(owner))]):
            with self.assertRaises(owned.ProcessError):
                command._receive(owner.downstream, command.Tag.PREPARED, lambda: None)
        self.assertTrue(owner.downstream.poisoned)
        self.assertIsNone(owner.anchor_work)

    def test_custodian_late_handshake_is_once_only_data_after_failure(self):
        for expected in (command.Tag.PREPARED, command.Tag.READY):
            for failed in (False, True):
                with self.subTest(expected=expected, failed=failed):
                    owner = self._inert_custodian(expected)
                    reply = command._scalar(owner.ctx.nonce, **({"moved": True}
                                            if expected is command.Tag.READY else {}))
                    work = self._inert_custodian_settlement(owner)
                    original = KeyboardInterrupt("original modeled cancellation") if failed else None
                    if original is not None:
                        owner.ctx.record(original)
                    cutoff = owner.ctx.cutoff()
                    with self._inert_anchor_transport(SimpleNamespace(upstream=owner.downstream),
                            [(expected, reply), (command.Tag.WORK_DONE, work)]) as writes, \
                         patch.object(command.os, "getpgid", side_effect=AssertionError("numeric query")), \
                         patch.object(command.os, "getsid", side_effect=AssertionError("numeric query")):
                        if failed:
                            owner._anchor_frames()  # Cleanup uses the same phase-bound router.
                        else:
                            self.assertEqual(owner._receive_anchor(expected), reply)
                        owner._anchor_frames()
                        with self.assertRaises(KeyboardInterrupt if failed else owned.ProcessError) as raised:
                            owner._receive_anchor(expected)
                    self.assertEqual(owner.anchor_reply, reply)
                    self.assertEqual(owner.anchor_work, command._settlement_fields(work, owner.ctx))
                    self.assertFalse(owner.downstream.poisoned)
                    self.assertFalse(owner.run_route.attempted or owner.group_done_sent)
                    self.assertIs(owner.anchor_expected, expected)
                    self.assertEqual(writes, [])
                    if failed:
                        self.assertIs(raised.exception, original)
                        self.assertIs(owner.ctx.primary, original)
                        self.assertEqual(owner.ctx.cutoff(), cutoff)

    def test_custodian_router_rejects_unadmitted_wrong_phase_and_replayed_frames(self):
        cases = ("unadmitted-prepared", "unadmitted-work", "unadmitted-terminal",
                 "premature-ready", "no-create", "false-moved", "foreign-nonce",
                 "malformed", "duplicate-prepared", "duplicate-ready", "after-work")
        for case in cases:
            with self.subTest(case=case):
                expected = (command.Tag.READY if case in {"no-create", "false-moved", "duplicate-ready"}
                            else command.Tag.PREPARED)
                owner = self._inert_custodian(expected, create=case != "no-create")
                tag = expected
                fields = {"moved": case != "false-moved"} if expected is command.Tag.READY else {}
                nonce = b"x" * 16 if case == "foreign-nonce" else owner.ctx.nonce
                if case == "premature-ready":
                    tag, fields = command.Tag.READY, {"moved": True}
                elif case == "malformed":
                    fields = {"unexpected": True}
                body = command._scalar(nonce, **fields)
                if case.startswith("unadmitted-"):
                    owner.anchor_hello = False
                    if case == "unadmitted-work":
                        tag, body = command.Tag.WORK_DONE, self._inert_custodian_settlement(owner)
                    elif case == "unadmitted-terminal":
                        tag = command.Tag.TERMINAL
                elif case.startswith("duplicate-"):
                    owner._anchor_frame(tag, body)
                elif case == "after-work":
                    owner._anchor_frame(command.Tag.WORK_DONE, self._inert_custodian_settlement(owner))
                with self._inert_anchor_transport(SimpleNamespace(upstream=owner.downstream), [(tag, body)]) as writes:
                    with self.assertRaises(owned.ProcessError):
                        owner._anchor_frames()
                self.assertTrue(owner.downstream.poisoned and owner.anchor_protocol_failed)
                self.assertTrue(owner.ctx.stopped and owner.ctx.launch_retired)
                self.assertFalse(owner.run_route.attempted or owner.group_done_sent)
                self.assertEqual(writes, [])

    def test_anchor_crossed_stop_preserves_original_settlement_and_failure(self):
        for order in ("no-stop", "before-work-done", "crossed", "crossed-prior-error"):
            with self.subTest(order=order):
                owner = self._inert_no_child_anchor()
                ctx, wire = owner.ctx, owner.upstream
                now = time.monotonic_ns()
                stop_at = now + command.NANOSECOND
                stop = (command.Tag.STOP, command._scalar(ctx.nonce, cutoff=stop_at))
                done = (command.Tag.GROUP_DONE, command._scalar(ctx.nonce))
                frames = [done] if order == "no-stop" else [stop, done]
                first = ValueError("prior original failure") if order == "crossed-prior-error" else None
                with self._inert_anchor_transport(owner, frames, clock=[now]) as written:
                    if first is not None:
                        ctx.record(first)
                    if order == "before-work-done":
                        with self.assertRaises(owned.ProcessError):
                            command._check_stop(ctx, wire)
                        first = ctx.primary
                    code = owner.finish()
                self.assertEqual([tag for tag, _body in written], [command.Tag.WORK_DONE, command.Tag.TERMINAL])
                self.assertEqual(written[0][1], written[1][1])
                self.assertEqual(written[0][1], owner.work_done)
                self.assertTrue(owner.group_done and owner.group.retired and owner._local_producers())
                self.assertEqual(code, command.HELPER_OK if order == "no-stop" else command.HELPER_FAILED)
                self.assertEqual(ctx.stop_received, order != "no-stop")
                if order != "no-stop":
                    self.assertTrue(ctx.stopped and ctx.launch_retired)
                    self.assertEqual(ctx.cutoff(), stop_at)
                    self.assertIsNotNone(ctx.primary)
                if first is not None:
                    self.assertIs(ctx.primary, first)
                self.assertEqual(wire.writer.calls, 1)
                self.assertTrue(all(lease.calls == 1 for lease in owner.mapping.values()))

        custodian = command._Custodian.__new__(command._Custodian)
        custodian.ctx, custodian.downstream = self.context("C"), SimpleNamespace(writer=_InertLease())
        custodian.anchor_work = {"observed": "original WORK_DONE"}
        with patch.object(command, "_send", side_effect=AssertionError("no stop after observed WORK_DONE")):
            custodian._stop_anchor()

    def test_anchor_signal_failure_preserves_original_wait_and_settlement(self):
        for missing in (None, "wait", "eof", "group-done"):
            with self.subTest(missing=missing):
                owner = self._inert_no_child_anchor()
                ctx = owner.ctx
                owner.downstream = self.wire(ctx)
                owner.downstream.reader.number, owner.downstream.writer.number = 105, 106
                # This is an inert original-child model, not a native child or
                # a receipt usable as evidence outside this ordering test.
                child = SimpleNamespace(numeric_retired=False, wait_state="OWNED", receipt=None)
                receipt = SimpleNamespace(status_kind="signal", status_code=signal.SIGKILL)
                ctx.child_acquisition._child, ctx.child_acquisition._attempted = child, True
                owner.create_route.queue()
                owner.create_route.attempt()
                first, signal_error = ValueError("original pre-ready failure"), PermissionError("inert group signal")
                clock, events = [time.monotonic_ns()], []

                def terminate():
                    self.assertFalse(child.numeric_retired)
                    self.assertEqual(child.wait_state, "OWNED")
                    self.assertEqual(owner.downstream.writer.state, "CLOSED")
                    events.append("terminate")
                    raise signal_error

                def retire_numeric():
                    self.assertFalse(child.numeric_retired)
                    child.numeric_retired = True
                    events.append("retire")

                def poll_wait():
                    self.assertIs(ctx.child_acquisition.child, child)
                    self.assertTrue(child.numeric_retired)
                    self.assertIsNone(child.receipt)
                    events.append("wait")
                    if missing == "wait":
                        clock[0] = endpoint
                        return None  # Original cutoff expires without a receipt.
                    child.receipt, child.wait_state = receipt, "WAITED"
                    return receipt

                owner.group.terminate = Mock(side_effect=terminate)
                child.retire_numeric, child.poll_wait = Mock(side_effect=retire_numeric), Mock(side_effect=poll_wait)

                def after_parent_read(pending):
                    if not pending:
                        self.assertEqual([tag for tag, _body in written], [command.Tag.WORK_DONE])
                        self.assertTrue(owner._local_producers())
                        events.append("group-eof" if missing == "group-done" else "group-done")

                frames = [] if missing == "group-done" else [(command.Tag.GROUP_DONE, command._scalar(ctx.nonce))]
                with self._inert_anchor_transport(owner, frames, clock=clock, after_read=after_parent_read) as written:
                    ctx.record(first)
                    endpoint = ctx.cutoff()
                    clock[0] += 1_000_000  # Later cleanup cannot renew the original failure's grace.
                    parent_read, parent_write = command.os.read, command.os.write

                    def read(descriptor, maximum):
                        if descriptor == owner.downstream.reader.number:
                            self.assertTrue(child.numeric_retired)
                            events.append("worker-pending" if missing == "eof" else "worker-eof")
                            if missing == "eof":
                                clock[0] = endpoint
                                raise BlockingIOError()
                            return b""
                        return parent_read(descriptor, maximum)

                    def write(descriptor, content):
                        tag = command.Tag(content[0])
                        if tag is command.Tag.WORK_DONE:
                            self.assertIs(owner.wait, child.receipt)
                            self.assertTrue(owner._local_producers())
                            self.assertFalse(owner.group_done)
                        elif tag is command.Tag.TERMINAL:
                            self.assertTrue(owner.group_done and owner.group.retired)
                        events.append(tag.name)
                        return parent_write(descriptor, content)

                    with patch.object(command.os, "read", side_effect=read), \
                         patch.object(command.os, "write", side_effect=write):
                        code = owner.finish()

                owner.group.terminate.assert_called_once_with()
                child.retire_numeric.assert_called_once_with()
                child.poll_wait.assert_called_once_with()
                self.assertEqual(events[:3], ["terminate", "retire", "wait"])
                self.assertIs(ctx.primary, first)
                self.assertIn(signal_error, ctx.secondary)
                self.assertTrue(ctx.stopped and ctx.launch_retired)
                self.assertEqual(ctx.cutoff(), endpoint)
                self.assertTrue(owner.create_route.retired and owner.run_route.retired)
                self.assertFalse(owner.run_route.attempted)
                self.assertEqual(owner.downstream.eof, missing != "eof")
                for lease in (owner.downstream.reader, owner.downstream.writer, owner.upstream.writer,
                              *owner.mapping.values()):
                    self.assertEqual((lease.state, lease.calls), ("CLOSED", 1))
                if missing == "wait":
                    self.assertIsNone(owner.wait)
                    self.assertIsNone(child.receipt)
                    self.assertTrue(ctx.cleanup_unknown)
                else:
                    self.assertIs(owner.wait, receipt)
                    self.assertIs(owner.wait, child.receipt)
                if missing is None:
                    self.assertEqual(code, command.HELPER_FAILED)
                    self.assertFalse(ctx.cleanup_unknown)
                    self.assertEqual(ctx.secondary, [signal_error])
                    self.assertTrue(owner.group_done and owner.group.retired and owner._local_producers())
                    self.assertEqual(events, ["terminate", "retire", "wait", "worker-eof", "WORK_DONE",
                                              "group-done", "TERMINAL"])
                    self.assertEqual([tag for tag, _body in written], [command.Tag.WORK_DONE, command.Tag.TERMINAL])
                    self.assertEqual(written[0][1], written[1][1])
                    fields = command._settlement_fields(written[0][1], ctx)
                    self.assertTrue(fields["producer"] and fields["create"] and fields["moved"])
                    self.assertFalse(fields["no_child"] or fields["run"] or fields["armed"])
                    self.assertEqual(fields["wait"], {"kind": "signal", "code": signal.SIGKILL})
                else:
                    self.assertEqual(code, command.HELPER_UNKNOWN)
                    self.assertFalse(owner.group_done)
                    self.assertEqual([tag for tag, _body in written],
                                     [command.Tag.WORK_DONE] if missing == "group-done" else [])
                    self.assertEqual(owner._local_producers(), missing == "group-done")

    def test_unmoved_anchor_signal_failure_cannot_admit_wait_or_settlement(self):
        owner = self._inert_no_child_anchor()
        owner.moved = False
        owner.ctx.child_acquisition._child = SimpleNamespace()
        owner.ctx.child_acquisition._attempted = True
        first, signal_error = ValueError("original unmapped failure"), PermissionError("inert group signal")
        owner.group.terminate = Mock(side_effect=signal_error)
        with patch.object(owner, "body", side_effect=first), \
             patch.object(command, "_wait_original") as wait, patch.object(command, "_send") as send:
            code = owner.run()
        self.assertEqual(code, command.HELPER_UNKNOWN)
        owner.group.terminate.assert_called_once_with()
        wait.assert_not_called()
        send.assert_not_called()
        self.assertIs(owner.ctx.primary, first)
        self.assertIn(signal_error, owner.ctx.secondary)
        self.assertTrue(owner.ctx.cleanup_unknown)
        self.assertFalse(owner.moved or owner.group.retired or owner.group_done)
        self.assertIsNone(owner.wait)
        self.assertIsNone(owner.work_done)

    def test_anchor_settlement_requires_original_group_done_and_unrenewed_cutoff(self):
        for case in ("eof", "stop-eof", "truncated", "expiry-after-read", "already-expired"):
            with self.subTest(case=case):
                owner = self._inert_no_child_anchor()
                ctx = owner.ctx
                clock = [time.monotonic_ns()]
                stop_at = clock[0] + command.NANOSECOND
                stop = (command.Tag.STOP, command._scalar(ctx.nonce, cutoff=stop_at))
                done = (command.Tag.GROUP_DONE, command._scalar(ctx.nonce))
                frames = [] if case == "eof" else [stop] if case == "stop-eof" else [stop, done]
                if case == "already-expired":
                    ctx.failure_cutoff = clock[0]

                def after_read(pending):
                    if case == "expiry-after-read" and not pending:
                        clock[0] = stop_at

                with self._inert_anchor_transport(owner, frames, clock=clock, after_read=after_read) as written:
                    if case == "truncated":
                        with patch.object(command.os, "read", side_effect=[b"\x0a\x00", b""]):
                            code = owner.finish()
                    else:
                        code = owner.finish()
                self.assertEqual(code, command.HELPER_UNKNOWN)
                self.assertFalse(owner.group_done)
                self.assertNotIn(command.Tag.TERMINAL, [tag for tag, _body in written])
                self.assertEqual(owner.upstream.writer.calls, 1)
                if case == "expiry-after-read":
                    self.assertEqual(ctx.cutoff(), stop_at)
                    self.assertTrue(ctx.stop_received)

    def test_stop_admission_is_one_use_canonical_and_normal_receivers_still_abort(self):
        for receiver in ("receive", "check-stop"):
            for cutoff in ("earlier", "later"):
                with self.subTest(receiver=receiver, cutoff=cutoff):
                    owner = self._inert_no_child_anchor()
                    ctx = owner.ctx
                    now = time.monotonic_ns()
                    advertised = now + (1 if cutoff == "earlier" else 10) * command.NANOSECOND
                    stop = (command.Tag.STOP, command._scalar(ctx.nonce, cutoff=advertised))
                    with self._inert_anchor_transport(owner, [stop], clock=[now]):
                        first = ValueError("preserve first error")
                        ctx.record(first)
                        endpoint = ctx.cutoff()
                        with self.assertRaises(owned.ProcessError if receiver == "check-stop" else ValueError):
                            if receiver == "receive":
                                command._receive(owner.upstream, command.Tag.GROUP_DONE, lambda: None, normal=False)
                            else:
                                command._check_stop(ctx, owner.upstream)
                        self.assertTrue(ctx.stop_received)
                        self.assertIs(ctx.primary, first)
                        self.assertEqual(ctx.cutoff(), min(endpoint, advertised))
                        with self.assertRaises(owned.ProcessError):
                            command._accept_stop(ctx, stop[1])
                        self.assertEqual(ctx.cutoff(), min(endpoint, advertised))

        owner = self._inert_no_child_anchor()
        ctx = owner.ctx
        body = command._scalar(ctx.nonce, cutoff=ctx.run)
        with patch.object(ctx, "record", side_effect=RuntimeError("lost failure-record return")):
            with self.assertRaises(RuntimeError):
                command._accept_stop(ctx, body)
        self.assertTrue(ctx.stop_received)
        with self.assertRaises(owned.ProcessError):
            command._accept_stop(ctx, body)
        ctx = self.context("A")
        with patch.object(command.os, "getpid", return_value=ctx.pid + 1):
            with self.assertRaises(owned.ProcessCleanupError):
                command._accept_stop(ctx, body)
        self.assertFalse(ctx.stop_received)

    def test_anchor_tail_rejects_invalid_or_replayed_controls_without_terminal(self):
        cases = ("duplicate", "cross-phase-duplicate", "wrong-nonce", "noncanonical", "extra-field",
                 "bool-cutoff", "zero-cutoff", "past-hard", "wrong-tag", "wrong-done-nonce")
        for case in cases:
            with self.subTest(case=case):
                owner = self._inert_no_child_anchor()
                ctx, wire = owner.ctx, owner.upstream
                fields = {"cutoff": ctx.run}
                nonce = b"x" * 16 if case == "wrong-nonce" else ctx.nonce
                if case == "extra-field": fields["extra"] = 1
                if case == "bool-cutoff": fields["cutoff"] = True
                if case == "zero-cutoff": fields["cutoff"] = 0
                if case == "past-hard": fields["cutoff"] = ctx.hard + 1
                content = command._scalar(nonce, **fields) + (b"\n" if case == "noncanonical" else b"")
                stop = (command.Tag.STOP, content)
                done = (command.Tag.GROUP_DONE, command._scalar(
                    b"x" * 16 if case == "wrong-done-nonce" else ctx.nonce))
                frames = [stop, stop, done] if case in {"duplicate", "cross-phase-duplicate"} else [stop, done]
                if case == "wrong-tag": frames = [(command.Tag.HELLO, command._scalar(ctx.nonce)), done]
                with self._inert_anchor_transport(owner, frames) as written:
                    if case == "cross-phase-duplicate":
                        with self.assertRaises(owned.ProcessError):
                            command._check_stop(ctx, wire)
                    code = owner.finish()
                self.assertEqual(code, command.HELPER_UNKNOWN)
                self.assertFalse(owner.group_done)
                self.assertTrue(wire.poisoned)
                self.assertNotIn(command.Tag.TERMINAL, [tag for tag, _body in written])

        for condition in ("unsettled", "unsent", "pending-write", "failed-write", "in-flight-write"):
            owner = self._inert_no_child_anchor()
            owner.no_child, owner.work_done = True, b"inert already-sent payload"
            for lease in owner.mapping.values(): lease.close()
            owner.upstream.sent.append(command.Tag.WORK_DONE)
            if condition == "unsettled": owner.no_child = False
            if condition == "unsent": owner.upstream.sent.clear()
            if condition == "pending-write": owner.upstream.out = b"pending"
            if condition == "failed-write": owner.upstream.write_failed = True
            if condition == "in-flight-write": owner.upstream.write_in_flight = True
            with self.subTest(condition=condition), \
                 patch.object(command.os, "read", side_effect=AssertionError("inadmissible tail read")):
                with self.assertRaises(owned.ProcessError):
                    owner._await_group_done()
                self.assertFalse(owner.group_done)

    def test_fence_pair_distinguishes_absence_content_and_state_without_weakening(self):
        from mobile_release import local_signing as signing
        session = signing.SigningSession.__new__(signing.SigningSession)
        session._fence_binding = lambda operation: {"version": 2}
        record = {"version": 2, "outcome": "producer-settled"}
        content = signing._fence_json(record)
        details = dict(st_dev=11, st_ino=12, st_mode=stat.S_IFREG | 0o600, st_nlink=2,
                       st_uid=13, st_gid=14, st_size=len(content), st_mtime_ns=15, st_ctime_ns=16,
                       st_atime_ns=17)
        pending = (content, SimpleNamespace(**details))
        cases = ["pending-absent", "final-absent", "contents", *details]
        for case in cases:
            with self.subTest(case=case):
                changed = dict(details)
                if case in changed: changed[case] += 1
                final = (content + b" " if case == "contents" else content, SimpleNamespace(**changed))
                inputs = [None if case == "pending-absent" else pending,
                          None if case == "final-absent" else final]
                session._fence_file = Mock(side_effect=inputs)
                if case == "st_atime_ns":
                    result = session._read_fence_pair({"phase": "ARMED"})
                    self.assertEqual(result["fence"]["identity"], {"device": 11, "inode": 12})
                    self.assertEqual(result["outcome"], "producer-settled")
                else:
                    message = ("fence is missing" if case.endswith("absent") else
                               "fence contents differ" if case == "contents" else "fence file states differ")
                    with self.assertRaisesRegex(signing.CredentialError, message):
                        session._read_fence_pair({"phase": "ARMED"})
                self.assertEqual([call.args[0] for call in session._fence_file.call_args_list],
                                 ["command-final.pending", "command-final.json"])

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
        for edge in ("none", "failed-anchor", "fence", "serialization", "publication"):
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
                owner.wait = SimpleNamespace(status_code=(command.HELPER_FAILED if edge == "failed-anchor"
                                                         else command.HELPER_OK))
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
                self.assertIs(frames[0]["result"], edge not in {"fence", "failed-anchor"})
                self.assertTrue(frames[0]["producer"] and frames[0]["fence"])
                self.assertEqual(result, command.HELPER_OK if edge == "none" else
                                 command.HELPER_FAILED if edge in {"fence", "failed-anchor"} else command.HELPER_UNKNOWN)

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

    def test_pause_waits_only_original_readiness_with_fresh_bounded_time(self):
        for start, after_registration, expected in ((0, 0, 10), (0, 999_500_000, 0),
                                                    (0, 1_000_000_000, None),
                                                    (1_000_000_000, None, None)):
            with self.subTest(start=start, after_registration=after_registration):
                reader, writer = _InertLease(4097), _InertLease(4098)
                watcher = Mock()
                # Even error/hangup readiness cannot become IO, EOF or finality.
                watcher.poll.return_value = [(4097, command.select.POLLERR | command.select.POLLHUP)]
                with patch.object(command.select, "poll", return_value=watcher) as factory, \
                     patch.object(command.time, "monotonic_ns", side_effect=[start, after_registration]), \
                     patch.object(command.time, "sleep") as sleep, \
                     patch.object(command.os, "read") as read, patch.object(command.os, "write") as write, \
                     patch.object(reader, "fileno", wraps=reader.fileno) as original_fd:
                    command._pause(1_000_000_000, readers=(reader,), writers=(reader, writer))
                    sleep.assert_not_called(); read.assert_not_called(); write.assert_not_called()
                    if after_registration is None:
                        factory.assert_not_called(); original_fd.assert_not_called()
                    else:
                        self.assertEqual(watcher.register.call_args_list, [
                            unittest.mock.call(4097, command.select.POLLIN | command.select.POLLOUT),
                            unittest.mock.call(4098, command.select.POLLOUT)])
                    if expected is None: watcher.poll.assert_not_called()
                    else: watcher.poll.assert_called_once_with(expected)

        for operation, failure in (("fileno", SystemExit(3)), ("register", OSError("registration")),
                                   ("poll", KeyboardInterrupt())):
            with self.subTest(operation=operation):
                reader, watcher = _InertLease(), Mock()
                selected = reader if operation == "fileno" else watcher
                with patch.object(command.select, "poll", return_value=watcher), \
                     patch.object(command.time, "monotonic_ns", return_value=0), \
                     patch.object(command.time, "sleep") as sleep, \
                     patch.object(selected, operation, side_effect=failure):
                    with self.assertRaises(type(failure)) as caught:
                        command._pause(1_000_000_000, readers=(reader,))
                    self.assertIs(caught.exception, failure)
                    sleep.assert_not_called()
        with patch.object(command.time, "monotonic_ns", return_value=0), \
             patch.object(command.time, "sleep") as sleep, patch.object(command.select, "poll") as factory:
            command._pause(5_000_000)
            sleep.assert_called_once_with(.005)
            factory.assert_not_called()

    def test_outer_wait_only_pauses_without_progress_and_rechecks_before_success(self):
        for ending in ("ready", "delayed", "eof-ready", "eof-incomplete", "cancelled", "expired"):
            with self.subTest(ending=ending):
                ctx = self.context()
                engine = command._Outer.__new__(command._Outer)
                engine.ctx, engine.wire = ctx, SimpleNamespace(eof=False, reader=_InertLease())
                engine.readers, engine.output_eof = [_InertLease(102), _InertLease(103)], [False, True]
                state = {"ready": False, "pumps": 0, "now": time.monotonic_ns()}
                interruption = KeyboardInterrupt()
                def pump():
                    state["pumps"] += 1
                    self.assertLessEqual(state["pumps"], 2)
                    state["ready"] = ending != "eof-incomplete" and not (
                        ending == "delayed" and state["pumps"] == 1)
                    engine.wire.eof = ending.startswith("eof-")
                    if ending == "cancelled": ctx.primary = interruption
                    if ending == "expired": state["now"] = ctx.run
                engine._pump = pump
                with patch.object(command.time, "monotonic_ns", side_effect=lambda: state["now"]), \
                     patch.object(command, "_pause") as pause:
                    if ending == "cancelled":
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            engine._until(lambda: state["ready"])
                        self.assertIs(caught.exception, interruption)
                    elif ending in ("expired", "eof-incomplete"):
                        with self.assertRaises(owned.ProcessError):
                            engine._until(lambda: state["ready"])
                    else:
                        engine._until(lambda: state["ready"])
                    if ending == "delayed":
                        pause.assert_called_once_with(ctx.run, readers=(engine.wire.reader, engine.readers[0]))
                    else: pause.assert_not_called()
                self.assertEqual(state["pumps"], 2 if ending == "delayed" else 1)

    def test_fence_checkpoint_only_pauses_for_incomplete_send_or_unavailable_ack(self):
        for ending in ("ready", "partial", "eagain", "delayed-ack", "lost", "expired"):
            with self.subTest(ending=ending):
                ctx = self.context("C")
                wire = self.wire(ctx, diagnostics=True)
                writer = SimpleNamespace(ctx=ctx, fields={"sequence": 1},
                    policy=command.FenceObservationPolicy.TRACE_V1,
                    creation_identity=None, observation_identity_unavailable=False)
                observer = command._FenceObserver(writer, wire, _key=command._KEY)
                raw, pauses = bytearray(), []
                state = {"writes": 0, "reads": 0, "now": time.monotonic_ns()}
                def ack():
                    value = observer.outstanding.ack()
                    raw.extend(bytes((command.Tag.FENCE_ACK,)) + len(value).to_bytes(4, "big") + value)
                def write(fd, content):
                    self.assertEqual(fd, wire.writer.number)
                    self.assertTrue(observer.delivery_possible)
                    self.assertFalse(observer.acknowledged)
                    state["writes"] += 1
                    self.assertLessEqual(state["writes"], 2)
                    if ending == "partial" and state["writes"] == 1: return 1
                    if ending == "eagain" and state["writes"] == 1: raise BlockingIOError()
                    if ending == "lost": wire.eof = True
                    elif ending == "expired": state["now"] = ctx.cutoff()
                    elif ending != "delayed-ack": ack()
                    return len(content)
                def read(fd, count):
                    self.assertEqual(fd, wire.reader.number)
                    state["reads"] += 1
                    if not raw: raise BlockingIOError()
                    chunk = bytes(raw[:count]); del raw[:count]
                    return chunk
                def pause(cutoff, *, readers=(), writers=()):
                    self.assertEqual(cutoff, ctx.cutoff())
                    self.assertFalse(observer.acknowledged)
                    pauses.append(cutoff)
                    self.assertEqual(len(pauses), 1)
                    if ending == "delayed-ack":
                        self.assertEqual((readers, writers), ((wire.reader,), ()))
                        self.assertIsNone(wire.out)
                        self.assertEqual(state["reads"], 1)
                        ack()
                    else:
                        self.assertEqual((readers, writers), ((), (wire.writer,)))
                        self.assertIn(ending, ("partial", "eagain"))
                        self.assertIsNotNone(wire.out)
                        self.assertEqual(state["reads"], 0)
                with patch.object(command.os, "write", new=write), patch.object(command.os, "read", new=read), \
                     patch.object(command.time, "monotonic_ns", side_effect=lambda: state["now"]), \
                     patch.object(command, "_pause", new=pause):
                    arguments = (command.FenceOperation.PENDING_CREATE, command.FenceEdge.BEFORE,
                                 command.FenceEventOutcome.PENDING)
                    if ending == "expired":
                        with self.assertRaises(owned.ProcessError):
                            observer.checkpoint(*arguments, written=0, total=100, sync_flags=0)
                    else:
                        observer.checkpoint(*arguments, written=0, total=100, sync_flags=0)
                self.assertEqual(len(pauses), int(ending in ("partial", "eagain", "delayed-ack")))
                self.assertEqual(state["writes"], 2 if ending in ("partial", "eagain") else 1)
                self.assertEqual(observer.ordinal, 1)
                self.assertIs(observer.acknowledged, ending not in ("lost", "expired"))
                if ending in ("lost", "expired"):
                    self.assertEqual(state["reads"], 0)
                    self.assertTrue(observer.retired)
                    self.assertIsInstance(ctx.primary, owned.ProcessError)
                else:
                    self.assertFalse(observer.retired)
                    self.assertIsNone(ctx.primary)
                    self.assertEqual(raw, b"")

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
                def pause(_cutoff, **_readiness):
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

    @contextmanager
    def source_lease(self, *, recovery=False):
        from mobile_release import local_signing

        custom = lambda _number, _frame: None
        with tempfile.TemporaryDirectory(prefix="mrk-command-source-") as name, \
             patch.object(signal, "getsignal", return_value=custom), \
             patch.object(signal, "signal", side_effect=AssertionError("custom handler changed")), \
             patch.object(command.native.Acquisition, "_runtime", side_effect=AssertionError("native effect")), \
             patch.object(command.threading.Thread, "start", side_effect=AssertionError("thread started")):
            home = Path(name) / "home"; home.mkdir(mode=0o700)
            with local_signing.local_signing_lease(home=home, recovery=recovery) as lease:
                yield lease

    def assert_normal_revoked(self, lease, source, selected):
        from mobile_release import discovery, local_signing

        before = lease.cancellation.lifetime_ledger.verdict()
        with patch.object(command, "_Outer", side_effect=AssertionError("engine created")):
            for call in (lease.execution_source, source.new_scope, lease.session,
                         lambda: discovery._run(lease.home, ["fictional"], execution_source=source),
                         lambda: owned.run_owned(["fictional"], execution_scope=selected),
                         lambda: selected._consume(SimpleNamespace(nonce=selected.nonce), None)):
                with self.assertRaises(local_signing.SigningPending):
                    call()
        self.assertTrue(lease._normal_execution_revoked)
        self.assertFalse(selected._used)
        self.assertIsNone(selected.outcome.read())
        self.assertIsNone(lease.cancellation.lifetime_ledger._command)
        self.assertEqual(lease.cancellation.lifetime_ledger.verdict(), before)

    def test_failure_flags_revoke_active_closed_retained_and_preselected_normal_execution(self):
        for flag in ("unresolved", "journal_failed"):
            for closed in (False, True):
                with self.subTest(flag=flag, closed=closed), self.source_lease() as lease:
                    session = lease.session()
                    source = lease.execution_source()
                    selected = source.new_scope()
                    setattr(session, flag, True)
                    if closed:
                        session.close()  # No prior admission observation may be required.
                        self.assertIsNone(lease.active)
                    self.assert_normal_revoked(lease, source, selected)
                    self.assertFalse(lease.cancellation.lifetime_ledger.fatal)
                    setattr(session, flag, False)  # Cannot reset the lease's observed latch.
                    self.assert_normal_revoked(lease, source, selected)

    def test_pending_close_needs_original_disposal_but_never_opened_close_is_healthy(self):
        from mobile_release.errors import CredentialError

        for disposition in ("never-opened", "pending", "disposed"):
            with self.subTest(disposition=disposition), self.source_lease() as lease:
                session = lease.session()
                source = lease.execution_source()
                selected = source.new_scope()
                if disposition != "never-opened":
                    session.open(create=True)
                if disposition == "disposed":
                    # Only native preference observation is modeled. The actual
                    # owned directory removal/fsync/close path supplies the fact.
                    with patch.object(session, "observe", return_value={"default": "/fictional/default", "search": []}):
                        session.cleanup_preparation()
                    self.assertTrue(session._disposal_complete)
                session.close()
                self.assertFalse(session.unresolved or session.journal_failed)
                self.assertFalse(lease.cancellation.lifetime_ledger.fatal)
                self.assertIsNone(lease.active)
                if disposition == "pending":
                    self.assertFalse(session._disposal_complete)
                    self.assert_normal_revoked(lease, source, selected)
                else:
                    source._check()
                    self.assertIs(source.new_scope()._source, source)
                    lease.session().close()
                    self.assertFalse(lease._normal_execution_revoked)
                with self.assertRaisesRegex(CredentialError, "session opening cannot be repeated"):
                    session.open(create=True)

    def test_open_and_disposal_return_loss_cannot_publish_completion_or_permit_reentry(self):
        from mobile_release import local_signing
        from mobile_release.errors import CredentialError

        for boundary in ("mkdir", "open", "rmdir", "fsync"):
            with self.subTest(boundary=boundary), self.source_lease() as lease:
                session = lease.session()
                source = lease.execution_source()
                selected = source.new_scope()
                modeled, hits = SimpleNamespace(**vars(os)), []
                if boundary == "mkdir":
                    def mkdir(name, *args, **kwargs):
                        os.mkdir(name, *args, **kwargs)
                        hits.append(name)
                        self.assertTrue(session._open_attempted)
                        raise OSError("original mkdir return lost")
                    modeled.mkdir = mkdir
                    with patch.object(local_signing, "os", modeled), self.assertRaises(OSError):
                        session.open(create=True)
                    self.assertIsNone(session._create_origin)
                elif boundary == "open":
                    def opened(*_args, **_kwargs):
                        # Acquisition-return model: no fabricated FD enters any
                        # syscall, but the real caller must already be armed.
                        hits.append("open-return")
                        self.assertTrue(session._open_attempted)
                        raise OSError("modeled open return lost")
                    with patch.object(local_signing, "_open_dir", side_effect=opened), self.assertRaises(OSError):
                        session.open(create=True)
                    self.assertIsNone(session.fd)
                else:
                    session.open(create=True)
                    if boundary == "rmdir":
                        def rmdir(name, *args, **kwargs):
                            os.rmdir(name, *args, **kwargs)
                            if name == session.name:
                                hits.append(name)
                                raise OSError("original removal return lost")
                        modeled.rmdir = rmdir
                    else:
                        def fsync(fd):
                            os.fsync(fd)
                            if fd == lease.fd:
                                hits.append(fd)
                                raise OSError("original parent sync return lost")
                        modeled.fsync = fsync
                    with patch.object(local_signing, "os", modeled), \
                         patch.object(session, "observe", return_value={"default": "/fictional/default", "search": []}), \
                         self.assertRaises(OSError):
                        session.cleanup_preparation()
                self.assertEqual(len(hits), 1)
                self.assertTrue(session._open_attempted)
                self.assertFalse(session._disposal_complete)
                session.close()
                self.assertFalse(lease.cancellation.lifetime_ledger.fatal)
                self.assert_normal_revoked(lease, source, selected)
                with self.assertRaisesRegex(CredentialError, "session opening cannot be repeated"):
                    session.open(create=True)

    def test_failed_close_latches_before_diagnostics_and_attempts_each_independent_slot_once(self):
        from mobile_release import local_signing

        with self.assertRaises(owned.ProcessError) as final_failure, self.source_lease() as lease:
            session = lease.session()
            source = lease.execution_source()
            selected = source.new_scope()
            # Isolated descriptor-custody model; neither number reaches the OS.
            session.native_fd, session.fd = 311, 312
            closes = []
            failure = OSError("modeled close return loss")
            merge = local_signing.preserve_lifetime_error
            def close(number):
                closes.append(number)
                if number == 311:
                    raise failure
            def aggregate(*args, **kwargs):
                if kwargs.get("previous") is failure:
                    self.assertTrue(lease._normal_execution_revoked)
                return merge(*args, **kwargs)
            with patch.object(local_signing, "_close", side_effect=close), \
                 patch.object(local_signing, "preserve_lifetime_error", side_effect=aggregate):
                with self.assertRaises(owned.ProcessCleanupError):
                    session.close()
                session.close()
            self.assertEqual(closes, [311, 312])
            self.assertTrue(lease._normal_execution_revoked)
            self.assertTrue(lease.cancellation.lifetime_ledger.fatal)
            self.assertIsNone(lease.active)
            with patch.object(command, "_Outer", side_effect=AssertionError("engine created")), \
                 self.assertRaises(owned.ProcessCleanupError):
                owned.run_owned(["fictional"], execution_scope=selected)
            self.assertFalse(selected._used)
        self.assertTrue(final_failure.exception.fatal)
        self.assertTrue(lease.cancellation.lifetime_ledger.fatal)
        self.assertIsNone(lease.fd)
        self.assertIsNone(lease.home_fd)
        self.assertEqual(lease.cancellation.handler_state, "RESTORED")

    def test_revoked_lease_reentry_precedes_private_material_and_profile_authentication(self):
        from mobile_release import credentials, local_signing

        with self.source_lease() as lease:
            session = lease.session()
            session.unresolved = True
            session.close()
            with patch.object(credentials, "_private_path_error", side_effect=AssertionError("private path observed")), \
                 patch.object(credentials, "read_external_bytes", side_effect=AssertionError("private input read")), \
                 patch.object(credentials, "invocation_custody", side_effect=AssertionError("invocation acquired")), \
                 patch.object(credentials, "finite_scratch", side_effect=AssertionError("private scratch acquired")), \
                 patch.object(credentials, "_materialize", side_effect=AssertionError("material written")), \
                 patch.object(credentials, "_authenticated_signing_profile", side_effect=AssertionError("profile authenticated")):
                with self.assertRaises(local_signing.SigningPending):
                    with credentials.materialize_build_inputs(
                        SimpleNamespace(root=lease.home),
                        values={"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH": "/fictional/input.p12"},
                        platforms=("ios",), signing_lease=lease,
                    ):
                        self.fail("revoked materialization entered")
                with self.assertRaises(local_signing.SigningPending):
                    with credentials._temporary_apple_signing_environment(
                        p12=Path("/fictional/input.p12"), password="fictional", profile=Path("/fictional/input.profile"),
                        directory=lease.home, project_root=lease.home.parent / "project", lease=lease,
                    ):
                        self.fail("revoked signing entered")

    def test_original_profile_conflict_close_revokes_even_without_session_failure_flags(self):
        from mobile_release import credentials, local_signing
        from mobile_release.errors import CredentialError

        with self.assertRaises(owned.ProcessError) as final_failure, self.source_lease() as lease:
            project, private = lease.home.parent / "project", lease.home.parent / "private"
            project.mkdir(mode=0o700)
            private.mkdir(mode=0o700)
            p12, source = private / "input.p12", private / "input.profile"
            p12.write_bytes(b"fictional-p12")
            source.write_bytes(b"fictional profile")
            p12.chmod(0o600)
            source.chmod(0o600)
            sessions, native_cleanup = [], []
            def prepare(session, *_args):
                sessions.append(session)
                session.intent = {"profile": {"stage": "fictional-stage"}}
                session.state = {"inflight": None}
            @contextmanager
            def conflict(*_args, on_conflict, **_kwargs):
                on_conflict()
                raise CredentialError("modeled profile conflict")
                yield  # pragma: no cover - preserves the actual context protocol.
            with patch.object(credentials, "_authenticated_signing_profile",
                              return_value=(b"fictional", {"UUID": "12345678-1234-1234-1234-1234567890AB"})), \
                 patch.object(local_signing.SigningSession, "prepare", new=prepare), \
                 patch.object(local_signing.SigningSession, "cleanup_native", new=lambda session: native_cleanup.append(session)), \
                 patch.object(local_signing.SigningSession, "finish", side_effect=AssertionError("conflicted session finalized")), \
                 patch.object(credentials, "_temporary_profile_installation", new=conflict), \
                 self.assertRaises(owned.ProcessError):
                with credentials._temporary_apple_signing_environment(
                    p12=p12, password="fictional", profile=source,
                    directory=private, project_root=project, lease=lease,
                ):
                    self.fail("conflicted signing entered")
            self.assertEqual(len(sessions), 1)
            self.assertEqual(native_cleanup, sessions)
            session = sessions[0]
            self.assertFalse(session.unresolved or session.journal_failed)
            self.assertTrue(session._open_attempted and session.closed)
            self.assertFalse(session._disposal_complete)
            self.assertIsNone(lease.active)
            self.assertTrue(lease._normal_execution_revoked)
        self.assertTrue(final_failure.exception.fatal)
        self.assertTrue(lease.cancellation.lifetime_ledger.fatal)
        self.assertIsNone(lease.fd)
        self.assertIsNone(lease.home_fd)
        self.assertEqual(lease.cancellation.handler_state, "RESTORED")

    def test_settlement_policy_allows_nonzero_and_healthy_inflight_but_revokes_exec_ambiguity(self):
        # Only caller policy is modeled here; this is not native finality evidence.
        for returncode in (0, 7, None):
            with self.subTest(returncode=returncode), self.source_lease() as lease:
                session = lease.session()
                source = lease.execution_source()
                session.state = {"inflight": {"kind": "observe", "phase": "PREPARED"}, "native": {}}
                for phase in ("PREPARED", "ARMED"):
                    session.state["inflight"]["phase"] = phase
                    scope = source.new_scope()
                    scope._consume(SimpleNamespace(nonce=scope.nonce), None)
                    self.assertTrue(scope._used)
                session._command_scope, session._command_binding = source.new_scope(), object()
                result = SimpleNamespace(returncode=returncode)
                policy_outcome = SimpleNamespace(execution_unknown=returncode is None, no_target=None,
                                                 termination="normal-exit", returncode=returncode)
                def settled(_settlement):
                    session.state["inflight"] = None
                with patch.object(session, "_original_outcome", return_value=policy_outcome), \
                     patch.object(session, "inventory", return_value={}), \
                     patch.object(session, "_read_fence_pair", return_value={"outcome": "producer-settled"}), \
                     patch.object(session, "_settle_operation", side_effect=settled), \
                     patch("mobile_release.local_signing._names", return_value=set()):
                    if returncode is None:
                        with self.assertRaises(owned.ProcessOutcomeUnknown) as caught:
                            session.finish_original_command_if_settled(result=result)
                        self.assertTrue(caught.exception.dispatched and caught.exception.contained and caught.exception.cleanup_complete)
                        self.assertFalse(caught.exception.fatal)
                    else:
                        self.assertTrue(session.finish_original_command_if_settled(result=result))
                self.assertFalse(lease.cancellation.lifetime_ledger.fatal)
                if returncode is None:
                    self.assert_normal_revoked(lease, source, session._command_scope)
                else:
                    self.assertFalse(session.unresolved or session.journal_failed)
                    source._check()
                    self.assertFalse(lease._normal_execution_revoked)

    def test_fresh_recovery_still_requires_its_exact_separate_authorization(self):
        from mobile_release import local_signing
        from mobile_release.errors import CredentialError

        with self.source_lease(recovery=True) as lease:
            session = lease.session()
            for authorization in (None, object()):
                with self.assertRaises(CredentialError):
                    lease.execution_source(authorization=authorization)
            attempt = local_signing._RecoveryAttempt(session, _key=local_signing._RECOVERY_KEY)
            session._recovery_attempt = attempt
            source = lease.execution_source(authorization=attempt)
            self.assertIs(source.new_scope()._source, source)
            session.journal_failed = True
            with self.assertRaises(CredentialError):
                source.new_scope()
            self.assertFalse(lease._normal_execution_revoked)

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

    def _command_case(self, mode, *, suffix="", interruption=None):
        from workflow import command_bootstrap_fixture
        root = self.root / (mode + suffix)
        self.unconfirmed_fixtures.append(root)  # Before any case-owned acquisition.
        return command_bootstrap_fixture.CommandCase(command, root, mode, interruption=interruption)

    def _release_command_case(self, case):
        case.release()
        self.unconfirmed_fixtures.remove(case.root)

    def test_guarded_worker_tail_and_report_loss_preserve_original_outcomes(self):
        negative = ("body-return", "body-systemexit", "report-format-error",
                    "reject-zero", "reject-eagain", "reject-error")
        incomplete = ("reject-partial", "arm-missing", "arm-partial")
        for mode in (*negative, "reject-full", *incomplete, "post-map-pre-ready"):
            # An assertion/finality failure leaves its root registered and stops
            # the batch; there is no healthy continuation after UNKNOWN.
            # Separate stdout leaves unittest's stderr success line intact.
            # Only this fixed enum is reported, before any case acquisition.
            sys.stdout.write("\nMRK_OWNED_COMMAND_MODE=" + mode + "\n")
            sys.stdout.flush()
            case = self._command_case(mode)
            with case:
                if mode in negative:
                    result = owned.run_owned(["/this-fictional-command-does-not-exist"], timeout=5)
                else:
                    with self.assertRaises(owned.ProcessError) as raised:
                        owned.run_owned(["/this-fictional-command-does-not-exist"], timeout=5)
            case.require_finality()
            outcome, worker = case.outcome, case.rows["W"]
            self.assertTrue(outcome.create_w.attempted and outcome.create_w.retired)
            self.assertTrue(outcome.run_tool.retired)
            self.assertIn("hello", worker)
            self.assertEqual(outcome.termination, "signal-wait")
            self.assertEqual(outcome.returncode, -signal.SIGKILL)
            self.assertIn("self_raise", worker)
            self.assertNotIn("self_kill", worker)
            self.assertNotIn("park", worker)
            if mode == "post-map-pre-ready":
                self.assertIn("pre_ready", worker)
                self.assertNotIn("ready", worker)
                self.assertFalse(outcome.run_tool.attempted)
                self.assertEqual(outcome.no_target.kind, "CLOSED_BEFORE_RUN")
                self.assertEqual(outcome.result_integrity, "complete")
                self.assertFalse(raised.exception.dispatched)
            else:
                self.assertIn("ready", worker)
                self.assertTrue(outcome.run_tool.attempted)
                if mode not in {"arm-missing", "arm-partial"}:
                    self.assertIn("exec_armed", worker)
                if mode == "reject-full":
                    self.assertEqual(outcome.no_target.kind, "EXEC_REJECTED")
                    self.assertEqual(outcome.result_integrity, "complete")
                    self.assertFalse(raised.exception.dispatched)
                    self.assertEqual(worker["reject_done"]["attempts"], 1)
                else:
                    self.assertIsNone(outcome.no_target)
                    self.assertTrue(outcome.execution_unknown)
                    if mode in negative:
                        self.assertEqual((result.returncode, result.stdout, result.stderr), (-signal.SIGKILL, "", ""))
                        self.assertEqual(outcome.result_integrity, "complete")
                    else:
                        self.assertEqual(outcome.result_integrity, "incomplete")
                        self.assertTrue(raised.exception.dispatched)
            if mode.startswith("reject-"):
                write = worker["reject_write"]
                self.assertTrue(write["retired"] and write["nonblocking"])
                self.assertEqual(write["attempt"], 1)
                self.assertEqual(worker["reject_enter"]["stage"], "exec")
                self.assertEqual(worker["reject_enter"]["errno"], command.errno.ENOENT)
                if mode == "reject-full":
                    self.assertEqual(write["count"], write["size"])
                elif mode == "reject-partial":
                    self.assertEqual(write["count"], 3)
                    self.assertGreater(write["size"], 3)
                    self.assertNotIn("reject_done", worker)
                else:
                    self.assertEqual(write["count"], 0)
                    self.assertNotIn("reject_done", worker)
            elif mode in {"body-return", "body-systemexit"}:
                self.assertIn("body_return", worker)
                self.assertNotIn("reject_enter", worker)
                if mode == "body-systemexit":
                    self.assertEqual(worker["system_exit"]["code"], 127)
                    self.assertEqual(worker["system_exit"]["returned"], command.HELPER_UNKNOWN)
            elif mode == "report-format-error":
                self.assertTrue(worker["format_error"]["retired"])
                self.assertNotIn("reject_write", worker)
            elif mode in {"arm-missing", "arm-partial"}:
                self.assertNotIn("exec_armed", worker)
                self.assertFalse(case.rows["A"]["worker_result"]["armed"])
                self.assertIn(mode.replace("-", "_"), worker)
                if mode == "arm-partial":
                    self.assertEqual(worker["arm_partial"]["count"], 3)
                    self.assertGreater(worker["arm_partial"]["size"], 3)
            self._release_command_case(case)

    def test_worker_self_stop_fallback_and_original_owner_deadline(self):
        case = self._command_case("first-self-stop")
        with case:
            result = owned.run_owned(["/fictional-unreached-command"], timeout=5)
        pids = case.require_finality()
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertTrue(case.outcome.execution_unknown)
        self.assertEqual(case.rows["W"]["self_raise"]["signal"], int(signal.SIGKILL))
        self.assertEqual(case.rows["W"]["self_kill"]["self_pid"], pids["W"])
        self.assertNotIn("park", case.rows["W"])
        self._release_command_case(case)

        for cancel in (False, True):
            original = KeyboardInterrupt("fixed original park cancellation") if cancel else None
            case = self._command_case("both-self-stop", suffix="-cancel" if cancel else "-timeout",
                                      interruption=original)
            with case, self.assertRaises(KeyboardInterrupt if cancel else owned.ProcessError) as raised:
                owned.run_owned(["/fictional-unreached-command"], timeout=2 if not cancel else 5)
            pids = case.require_finality()
            self.assertIn("self_raise", case.rows["W"])
            self.assertEqual(case.rows["W"]["self_kill"]["self_pid"], pids["W"])
            self.assertIn("park", case.rows["W"])
            self.assertEqual(case.rows["A"]["owner_wait"]["kind"], "signal")
            self.assertEqual(case.rows["A"]["owner_wait"]["code"], int(signal.SIGKILL))
            signals = [case.rows[role]["group_kill"] for role in ("A", "C")
                       if "group_kill" in case.rows[role]]
            self.assertTrue(signals)
            self.assertTrue(all(row["group"] == pids["A"] and not row["retired"]
                                and row["before_cutoff"] for row in signals))
            self.assertEqual(case.outcome._engine.ctx.hard - case.outcome._engine.ctx.run, command.CLEANUP_NS)
            if cancel:
                self.assertTrue(case.interrupted)
                self.assertIs(raised.exception, original)
                self.assertIs(case.outcome._engine.ctx.primary, original)
            else:
                self.assertIs(raised.exception, case.outcome._engine.ctx.primary)
                self.assertEqual(str(raised.exception), command.TIMEOUT)
            self._release_command_case(case)

    def test_native_target_inherits_exact_signal_policy_and_mask(self):
        source = Path(__file__).parents[1] / "workflow/command_signal_probe.c"
        target = self.root / "command-signal-probe"
        compiler = ["/usr/bin/xcrun", "clang"] if sys.platform == "darwin" else ["/usr/bin/cc"]
        built = owned.run_owned([*compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", "-O0",
                                 str(source), "-o", str(target)], timeout=15)
        self.assertTrue(all_original_commands_final(self.outcomes))
        self.assertEqual(built.returncode, 0, built.stderr)
        defaults = [getattr(signal, name) for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ") if hasattr(signal, name)]
        selected = list(dict.fromkeys([signal.SIGINT, signal.SIGTERM, signal.SIGCHLD, signal.SIGUSR1, *defaults]))
        previous = {number: signal.getsignal(number) for number in selected}
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        try:
            for index, (int_policy, term_policy) in enumerate(((signal.SIG_DFL, signal.SIG_DFL),
                    (signal.SIG_IGN, signal.SIG_DFL), (signal.SIG_DFL, signal.SIG_IGN))):
                for number, policy in ((signal.SIGINT, int_policy), (signal.SIGTERM, term_policy),
                                       (signal.SIGCHLD, signal.SIG_DFL), (signal.SIGUSR1, signal.SIG_IGN)):
                    signal.signal(number, policy)
                for number in defaults:
                    signal.signal(number, signal.SIG_IGN)  # Prove restoration, not an already-default value.
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2, signal.SIGALRM})
                expected_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                case = self._command_case("observe", suffix=f"-signal-{index}")
                with case:
                    result = owned.run_owned([str(target)], timeout=5)
                pids = case.require_finality()
                self.assertEqual((result.returncode, result.stderr), (0, ""))
                self.assertEqual(case.outcome.termination, "normal-exit")
                self.assertFalse(case.outcome.execution_unknown)
                observed = json.loads(result.stdout)
                self.assertEqual(observed["pid"], pids["W"])
                self.assertEqual(observed["nsig"], signal.NSIG)
                expected_policy = {int(number): 0 for number in defaults}
                expected_policy.update({int(signal.SIGINT): int(int_policy == signal.SIG_IGN),
                                        int(signal.SIGTERM): int(term_policy == signal.SIG_IGN),
                                        int(signal.SIGCHLD): 0, int(signal.SIGUSR1): 1})
                self.assertEqual(dict(observed["policy"]), expected_policy)
                mask = observed["mask"]
                self.assertEqual([row[0] for row in mask], list(range(1, signal.NSIG)))
                for number, member in mask:
                    if member == -1:
                        self.assertNotIn(number, signal.valid_signals())
                    else:
                        self.assertEqual(member, int(number in expected_mask))
                self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), expected_mask)
                self._release_command_case(case)
        finally:
            # Do not reuse an unresolved signal/process owner for another case.
            if all_original_commands_final(self.outcomes):
                for number, policy in previous.items():
                    signal.signal(number, policy)
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

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
