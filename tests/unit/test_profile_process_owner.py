"""Pure/fake-only owner contracts; NEVER native lifecycle/ABI evidence.

All descriptors, child receipts, groups and task joins below are inert models.
Real O/C/K/V publication, EOF, native delay and descriptor-map evidence lives in
the separately owned process-bearing fixture suites, not these unit controls.
"""
from __future__ import annotations

import copy
import gc
import json
import signal
import threading
import types
import unittest
import weakref
from pathlib import Path
from unittest.mock import Mock, patch

from mobile_release import _profile_process as owner
from mobile_release.cancellation import DefaultCancellation
from mobile_release.errors import ValidationError


class _Acquisition:
    def __init__(self, *, failure_recorder=None):
        self.failure_recorder = failure_recorder
        self.child = None
        self.attempted = False
        self.settled = True
        self.cleanup_unknown = False
        self.cleanup_errors = ()
        self.interruption = None
        self.leases = []
        self.launch_retired = False
        self.grants = []

    def grant(self, thread, check):
        if self.launch_retired or self.grants:
            raise AssertionError("fake acquisition was reopened")
        self.grants.append((thread, check))

    def close_launch(self):
        self.launch_retired = True


class _Lease:
    def __init__(self, number=100, error=None):
        self.number, self.error = number, error
        self.state = "OPEN"
        self.unknown = False
        self.close_calls = 0

    def fileno(self):
        if self.state != "OPEN":
            raise AssertionError("retired fake descriptor reused")
        return self.number

    def close(self):
        self.close_calls += 1
        if self.error is not None:
            self.state, self.unknown = "UNKNOWN", True
            raise self.error
        self.state = "CLOSED"


class _Child:
    def __init__(self, results=(), *, pid=431):
        self.pid = pid
        self.results = list(results)
        self.numeric_retired = False
        self.wait_state = "OWNED"
        self.receipt = None
        self.polls = 0

    def retire_numeric(self):
        self.numeric_retired = True

    def poll_wait(self):
        if not self.numeric_retired:
            raise AssertionError("first wait did not retire numeric authority")
        self.polls += 1
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            self.wait_state = "UNKNOWN"
            raise result
        if result is None:
            self.wait_state = "POLLABLE"
        else:
            self.receipt, self.wait_state = result, "REAPED"
        return result


class _Channel:
    def __init__(self, context, reader=None, writer=None, *_edges):
        self.context = context
        self.reader = _Lease(101) if reader is None else reader
        self.writer = _Lease(102) if writer is None else writer
        self.reader_closed = self.writer_closed = False
        self.eof = True
        self.pending = []
        self.offers = []
        self.frames = []
        self.encoder = types.SimpleNamespace(seen=set())
        self.sent = set()
        self.write_attempted = set()
        self.write_failed = False
        self.write_in_flight = False
        self.on_flush = lambda _frame: None

    def send(self, kind, **fields):
        if self.writer_closed:
            raise AssertionError("fake control writer was retired")
        self.encoder.seen.add(kind)
        frame = {"v": 1, "type": kind, **fields}
        self.offers.append(frame)
        self.pending.append(frame)

    def send_frame(self, frame):
        self.send(frame["type"], **{key: value for key, value in frame.items() if key not in ("v", "type")})

    def flush(self, *, deadline_ns=None):
        # An explicit inert write-return model, NOT native write/EOF evidence.
        if self.pending and not self.writer_closed:
            frame = self.pending.pop(0)
            self.write_attempted.add(frame["type"])
            self.sent.add(frame["type"])
            self.on_flush(frame)

    def pump(self):
        self.flush()

    def take(self):
        frames, self.frames = self.frames, []
        return frames

    def close_reader(self):
        if not self.reader_closed:
            self.reader_closed = True
            self.context.close(self.reader)

    def close_writer(self):
        if not self.writer_closed:
            self.writer_closed = True
            self.context.close(self.writer)


class _Cancellation(DefaultCancellation):
    def __init__(self):
        super().__init__(ValidationError, "fixed restoration failure")
        self.calls = []
        self.restore_action = lambda: None

    def install(self):
        self.calls.append("install")  # No real handler mutation.

    def restore(self):
        self.calls.append("restore")
        self.depth += 1
        self.restore_action()


def _context(role="outer", *, run=10_000_000_000, hard=13_000_000_000, cancellation=None, parent_pid=None):
    with patch.object(owner.native, "Acquisition", _Acquisition):
        return owner._Context(role, run, hard, cancellation=cancellation, parent_pid=parent_pid)


def _receipt(pid=431, kind="exit", code=0):
    return types.SimpleNamespace(pid=pid, status_kind=kind, status_code=code)


def _configuration(role="custodian"):
    return {"v": 1, "type": "CONFIG", "role": role, "cwd": "/private/profile",
            "validator_argv": ["/usr/bin/python3", "-I"], "validator_env": {"LANG": "C"},
            "run_deadline_ns": 10_000_000_000, "hard_cleanup_deadline_ns": 13_000_000_000,
            "max_output_bytes": 1024, "capture_kind": "profile"}


def _hello():
    return {"v": 1, "type": "HELLO", "pid": 431, "ppid": 430, "sid": 431,
            "pgid": 431, "fd_map_version": 1}


def _failed():
    return {"v": 1, "type": "FINAL", "outcome": "failed", "cleanup": "confirmed",
            "keeper": {"state": "not_attempted"}, "validator": {"state": "not_attempted"},
            "group": {"state": "not_created"}}


def _quiescing():
    return {"v": 1, "type": "QUIESCING"}


def _model_custodian_input_retirement(custodian):
    """Scoped inert full-write -> clean input EOF -> close -> FINAL model.

    Do not stub retirement itself or globally default input EOF to success. The
    real retirement method must drive this sequence in each full C-run table.
    """
    channel, context = custodian.outer, custodian.context
    channel.eof = False
    channel.decoder = owner.Decoder("o_to_c")
    events = []
    original_close = channel.close_reader

    def flush(frame):
        if frame["type"] == "QUIESCING":
            if not custodian.outer_retiring or channel.reader_closed or "QUIESCING" not in channel.sent:
                raise AssertionError("modeled notification did not retain its original reader")
            events.append("QUIESCING")
            channel.decoder.eof()  # Explicit clean framing completion, not eof alone.
            channel.eof = True
            events.append("control_eof")
        elif frame["type"] == "FINAL":
            if events != ["QUIESCING", "control_eof", "reader_closed"] or id(channel.reader) not in context.closed:
                raise AssertionError("modeled FINAL preceded accounted input retirement")
            events.append("FINAL")

    def close_reader():
        if not channel.reader_closed:
            if events != ["QUIESCING", "control_eof"] or not channel.decoder.ended or channel.decoder.failed:
                raise AssertionError("modeled input close lacked clean notification/EOF")
            original_close()
            events.append("reader_closed")

    channel.on_flush, channel.close_reader = flush, close_reader
    return events


def _packet(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return len(raw).to_bytes(4, "big") + raw


def _wire_channel(context, incoming, outgoing):
    with patch.object(owner.os, "set_blocking"):
        return owner._Channel(context, _Lease(201), _Lease(202), incoming, outgoing)


def _custodian(context):
    descriptors = {fd: _Lease(300 + fd) for fd in range(3, 8)}
    context.io.leases.extend(descriptors.values())
    with patch.object(owner, "_Channel", _Channel), patch.object(owner.os, "set_blocking"):
        return owner._Custodian(context, descriptors)


def _keeper(context):
    descriptors = {fd: _Lease(300 + fd) for fd in range(3, 8)}
    context.io.leases.extend(descriptors.values())
    with patch.object(owner, "_Channel", _Channel), patch.object(owner.os, "getpid", return_value=431):
        return owner._Keeper(context, descriptors)


def _settled_child(context, *, pid=431, kind="exit", code=0):
    child = _Child(pid=pid)
    child.receipt = _receipt(pid=pid, kind=kind, code=code)
    child.numeric_retired, child.wait_state = True, "REAPED"
    context.child_acquisition.child = child
    context.child_acquisition.attempted = True
    return child


class ProfileOwnerProtocolTests(unittest.TestCase):
    def test_incremental_framing_requires_real_complete_records_and_clean_eof(self):
        decoder = owner.Decoder("c_to_o")
        prefix = owner.Protocol.encode(_hello()) + owner.Protocol.encode(_quiescing())
        wire = prefix + owner.Protocol.encode(_failed())
        frames = []
        for index, byte in enumerate(wire):
            frames.extend(decoder.feed(bytes((byte,))))
            if index + 1 == len(prefix):
                self.assertEqual(frames, [_hello(), _quiescing()])
                self.assertFalse(decoder.direction.terminal)
                self.assertFalse(decoder.ended)
        self.assertEqual(frames, [_hello(), _quiescing(), _failed()])
        decoder.eof()
        with self.assertRaises(ValidationError):
            decoder.feed(b"")
        truncated = owner.Decoder("c_to_o")
        truncated.feed(wire[:7])
        with self.assertRaises(ValidationError):
            truncated.eof()
        controls = owner.Decoder("o_to_c")
        controls.feed(owner.Protocol.encode(_configuration()) + b"\0\0")
        with self.assertRaises(ValidationError):
            controls.eof()
        self.assertTrue(controls.failed)
        self.assertFalse(controls.ended)

    def test_duplicate_json_keys_unknown_fields_and_boolean_integers_are_rejected(self):
        raw = b'{"v":1,"v":1,"type":"ADMIT"}'
        with self.assertRaises(ValidationError):
            owner.Decoder("o_to_c").feed(len(raw).to_bytes(4, "big") + raw)
        cases = []
        for name in ("v", "pid", "ppid", "sid", "pgid", "fd_map_version"):
            frame = _hello()
            frame[name] = True
            cases.append(frame)
        cases.extend(({**_hello(), "private_marker": "must not escape"},
                      {**_hello(), "pid": 0}, {**_hello(), "pid": 1 << 31},
                      {**_hello(), "pid": 3.0}))
        for frame in cases:
            with self.subTest(frame=frame), self.assertRaisesRegex(ValidationError, "private process protocol is invalid"):
                owner.Protocol.encode(frame)

    def test_nonconfiguration_lengths_are_rejected_before_payload_buffering(self):
        for edge in ("c_to_o", "k_to_c"):
            with self.subTest(edge=edge), self.assertRaises(ValidationError):
                owner.Decoder(edge).feed((owner.FRAME_LIMIT + 1).to_bytes(4, "big"))
        decoder = owner.Decoder("o_to_c")
        decoder.feed(owner.Protocol.encode(_configuration()))
        with self.assertRaises(ValidationError):
            decoder.feed((owner.FRAME_LIMIT + 1).to_bytes(4, "big"))
        for length in (0, owner.CONFIG_LIMIT + 1):
            with self.assertRaises(ValidationError):
                owner.Decoder("o_to_c").feed(length.to_bytes(4, "big"))

    def test_decoder_rejection_is_absorbing_and_cannot_accumulate_later_chunks(self):
        for initial in (((1 << 32) - 1).to_bytes(4, "big"), b"\0\0\0\0", _packet({"type": "HELLO"})):
            decoder = owner.Decoder("c_to_o")
            with self.subTest(initial=initial[:4]), self.assertRaises(ValidationError):
                decoder.feed(initial)
            self.assertTrue(decoder.failed)
            self.assertEqual(decoder.pending, b"")
            self.assertIsNone(decoder.length)
            for content in (b"x" * (owner.CONFIG_LIMIT * 2), owner.Protocol.encode(_hello()), b""):
                with self.assertRaises(ValidationError):
                    decoder.feed(content)
                self.assertEqual(decoder.pending, b"")
                self.assertIsNone(decoder.length)
            with self.assertRaises(ValidationError):
                decoder.eof()
        truncated = owner.Decoder("c_to_o")
        truncated.feed(b"\0\0")
        with self.assertRaises(ValidationError):
            truncated.eof()
        self.assertTrue(truncated.failed)
        self.assertEqual(truncated.pending, b"")
        with self.assertRaises(ValidationError):
            truncated.feed(owner.Protocol.encode(_hello()))

    def test_cancel_remains_legal_after_commit_and_release_but_never_reopens_run(self):
        direction = owner._Direction("o_to_c")
        for frame in (_configuration(), {"v": 1, "type": "ADMIT"}, {"v": 1, "type": "RUN"},
                      {"v": 1, "type": "COMMIT"},
                      {"v": 1, "type": "CANCEL", "reason_code": "cancelled", "cleanup_deadline_ns": 11}):
            direction.accept(frame)
        with self.assertRaises(ValidationError):
            direction.accept({"v": 1, "type": "RUN"})
        keeper = owner._Direction("c_to_k")
        for frame in (_configuration("keeper"), {"v": 1, "type": "GROUP_RETIRED", "group_id": 431, "absent": True},
                      {"v": 1, "type": "RELEASE"},
                      {"v": 1, "type": "CANCEL", "reason_code": "deadline", "cleanup_deadline_ns": 11}):
            keeper.accept(frame)
        with self.assertRaises(ValidationError):
            keeper.accept({"v": 1, "type": "RUN"})

        # Local retirement does not reject already in-flight legal controls,
        # install their configuration, or grant any work. Only CANCEL still acts.
        context = _context("custodian", parent_pid=429)
        custodian = _custodian(context)
        custodian.outer = _wire_channel(context, "o_to_c", "c_to_o")
        custodian.outer_retiring = True
        cancel = {"v": 1, "type": "CANCEL", "reason_code": "cancelled", "cleanup_deadline_ns": 2_000_000_000}
        content = b"".join(owner.Protocol.encode(frame) for frame in
                           (_configuration(), {"v": 1, "type": "ADMIT"}, {"v": 1, "type": "RUN"},
                            {"v": 1, "type": "COMMIT"}, cancel))
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=429), patch.object(owner.os, "read", return_value=content), patch.object(owner, "_validate_configuration") as configure, patch.object(context, "check") as check:
            custodian.pump_outer()
        configure.assert_not_called()
        check.assert_not_called()
        self.assertIsNone(custodian.config)
        self.assertIsNone(custodian.directory)
        self.assertFalse(custodian.admitted or custodian.run_granted or custodian.committed)
        self.assertEqual(custodian.outer.decoder.direction.seen, {"CONFIG", "ADMIT", "RUN", "COMMIT", "CANCEL"})
        self.assertEqual((context.reason, context.failure_limit), ("cancelled", cancel["cleanup_deadline_ns"]))
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=429), patch.object(owner.os, "read", return_value=owner.Protocol.encode({"v": 1, "type": "RUN"})):
            with self.assertRaises(ValidationError):
                custodian.pump_outer()
        self.assertTrue(custodian.outer.decoder.failed)

    def test_terminal_variants_are_closed_and_unknown_cannot_confirm_cleanup(self):
        owner.Protocol.encode(_failed())
        real_keeper = {"state": "reaped", "pid": 431, "status_kind": "exit", "status_code": 0}
        frame = {**_failed(), "keeper": real_keeper, "group": {"state": "retired", "id": 431, "absent": True}}
        owner.Protocol.encode(frame)  # Clean pre-V failure, not successful validation.
        for mutate in (
            lambda f: f["validator"].update(pid=0),
            lambda f: f.update(keeper={"state": "unknown"}),
            lambda f: f.update(group={"state": "retired", "id": 431, "absent": False}),
            lambda f: f.update(keeper={**real_keeper, "pid": 432}),
            lambda f: f.update(group_absent=True),
            lambda f: f.update(outcome="ok"),
        ):
            invalid = copy.deepcopy(frame)
            mutate(invalid)
            with self.assertRaises(ValidationError):
                owner.Protocol.encode(invalid)
        unknown = {**_failed(), "cleanup": "unknown", "keeper": {"state": "unknown"},
                   "validator": {"state": "unknown"}, "group": {"state": "unknown"}}
        owner.Protocol.encode(unknown)

    def test_confirmed_terminal_never_aliases_unexpected_keeper_exit_or_role_identity(self):
        validator = {"state": "reaped", "pid": 432, "status_kind": "exit", "status_code": 7}
        for code in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            frame = {**_failed(), "keeper": {"state": "reaped", "pid": 431, "status_kind": "exit", "status_code": code},
                     "validator": validator, "group": {"state": "retired", "id": 431, "absent": True}}
            owner.Protocol.encode(frame)
            for replacement in ({**frame["keeper"], "status_code": 1},
                                {**frame["keeper"], "status_code": 3},
                                {**frame["keeper"], "status_kind": "signal", "status_code": 9}):
                with self.assertRaises(ValidationError):
                    owner.Protocol.encode({**frame, "keeper": replacement})
                owner.Protocol.encode({**frame, "keeper": replacement, "cleanup": "unknown"})
            with self.assertRaises(ValidationError):
                owner.Protocol.encode({**frame, "validator": {**validator, "pid": 431}})

    def test_wrong_phase_status_repeated_terminal_and_unhashable_enums_fail_closed(self):
        status = {"v": 1, "type": "STATUS", "validator_pid": 433, "status_kind": "exit", "status_code": 0}
        with self.assertRaises(ValidationError):
            owner.Decoder("k_to_c").feed(_packet(status))
        reserved = {"v": 1, "type": "RESERVED", "keeper_pid": 432, "group_id": 432, "session_id": 431}
        ready = {"v": 1, "type": "READY", "validator_pid": 433, "group_id": 432, "keeper_pgid": 431}
        prefixes = ((), (_hello(),), (_hello(), reserved), (_hello(), reserved, ready),
                    (_hello(), reserved, ready, status))
        for prefix in prefixes:
            decoder = owner.Decoder("c_to_o")
            decoder.feed(b"".join(owner.Protocol.encode(frame) for frame in (*prefix, _quiescing())))
            self.assertFalse(decoder.direction.terminal)
            self.assertEqual(decoder.feed(owner.Protocol.encode(_failed())), [_failed()])
            with self.assertRaises(ValidationError):
                decoder.feed(owner.Protocol.encode(_failed()))
        for edge in ("o_to_c", "c_to_k", "k_to_c"):
            with self.subTest(edge=edge), self.assertRaises(ValidationError):
                owner.Decoder(edge).feed(owner.Protocol.encode(_quiescing()))
        for frame in (_quiescing(), _hello(), reserved, ready, status):
            decoder = owner.Decoder("c_to_o")
            decoder.feed(owner.Protocol.encode(_hello()) + owner.Protocol.encode(_quiescing()))
            with self.subTest(after_quiescing=frame["type"]), self.assertRaises(ValidationError):
                decoder.feed(owner.Protocol.encode(frame))
        with self.assertRaises(ValidationError):
            owner.Protocol.encode({**_quiescing(), "cleanup": "confirmed"})
        with self.assertRaises(ValidationError):
            owner.Decoder("c_to_o").feed(owner.Protocol.encode(_failed()))
        for outcome, code in (("ok", 0), ("rejected", 7)):
            terminal = {**_failed(), "outcome": outcome,
                        "keeper": {"state": "reaped", "pid": 432, "status_kind": "exit", "status_code": 0},
                        "validator": {"state": "reaped", "pid": 433, "status_kind": "exit", "status_code": code},
                        "group": {"state": "retired", "id": 432, "absent": True}}
            decoder = owner.Decoder("c_to_o")
            decoder.feed(b"".join(owner.Protocol.encode(frame) for frame in (_hello(), reserved, ready, _quiescing())))
            with self.subTest(outcome=outcome, missing="STATUS"), self.assertRaises(ValidationError):
                decoder.feed(owner.Protocol.encode(terminal))
        for field, value in (("role", []), ("capture_kind", {}), ("run_deadline_ns", True)):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                owner.Protocol.encode({**_configuration(), field: value})

    def test_frame_sent_event_requires_actual_full_fake_write_and_eof_is_not_a_close(self):
        context, reader, writer = _context(), _Lease(201), _Lease(202)
        with patch.object(owner.os, "set_blocking"):
            channel = owner._Channel(context, reader, writer, "o_to_c", "c_to_o")
        channel.send_frame(_hello())
        packet_length = len(channel.pending[0][1])
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", side_effect=(2, packet_length - 2)), patch.object(owner, "_role_event") as event:
            channel.flush()
            self.assertIn("HELLO", channel.write_attempted)
            self.assertNotIn("HELLO", channel.sent)
            event.assert_not_called()
            channel.flush()
            self.assertIn("HELLO", channel.sent)
            self.assertEqual(event.call_args.args, ("outer", "frame_sent"))
        with patch.object(owner.os, "read", return_value=b""), patch.object(owner, "_role_event") as event:
            channel.read()
            self.assertTrue(channel.eof)
            self.assertEqual(event.call_args.args, ("outer", "control_eof"))
        self.assertEqual(reader.close_calls, 0)


class ProfileOwnerChannelTests(unittest.TestCase):
    def test_queued_or_partially_written_grants_are_never_completed_after_failure(self):
        reserved = {"v": 1, "type": "RESERVED", "keeper_pid": 432, "group_id": 432, "session_id": 431}
        ready = {"v": 1, "type": "READY", "validator_pid": 433, "group_id": 432, "keeper_pgid": 431}
        moved = {**ready, "type": "MOVED"}
        status = {"v": 1, "type": "STATUS", "validator_pid": 433, "status_kind": "exit", "status_code": 0}
        final = {"v": 1, "type": "FINAL", "outcome": "ok", "cleanup": "confirmed",
                 "keeper": {"state": "reaped", "pid": 432, "status_kind": "exit", "status_code": 0},
                 "validator": owner._status_record(status), "group": {"state": "retired", "id": 432, "absent": True}}
        admit, run, commit = ({"v": 1, "type": name} for name in ("ADMIT", "RUN", "COMMIT"))
        cases = (("c_to_o", "o_to_c", [_configuration()], admit),
                 ("c_to_o", "o_to_c", [_configuration(), admit], run),
                 ("c_to_o", "o_to_c", [_configuration(), admit, run], commit),
                 ("o_to_c", "c_to_o", [_hello()], reserved),
                 ("o_to_c", "c_to_o", [_hello(), reserved], ready),
                 ("c_to_k", "k_to_c", [_hello()], moved),
                 ("o_to_c", "c_to_o", [_hello(), reserved, ready, status, _quiescing()], final))
        for incoming, outgoing, prefix, grant in cases:
            for partial in (False, True):
                with self.subTest(kind=grant["type"], partial=partial):
                    context = _context()
                    channel = _wire_channel(context, incoming, outgoing)
                    with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)):
                        for frame in prefix:
                            channel.send_frame(frame)
                            channel.flush()
                        channel.send_frame(grant)
                        if partial:
                            with patch.object(owner.os, "write", return_value=2):
                                channel.flush()
                        first = ValidationError(owner.ERROR)
                        context.record(first)
                        with patch.object(owner.os, "write") as syscall, self.assertRaises(ValidationError) as raised:
                            channel.flush()
                    self.assertIs(raised.exception, first)
                    syscall.assert_not_called()
                    self.assertNotIn(grant["type"], channel.sent)
                    self.assertTrue(channel.writer_closed)
                    self.assertEqual(channel.pending, [])
                    self.assertEqual(channel.writer.close_calls, 1)

    def test_cancel_deadline_and_retired_launch_veto_the_live_prewrite_boundary(self):
        for grant, prefix in (("ADMIT", ()), ("RUN", ("ADMIT",)), ("COMMIT", ("ADMIT", "RUN"))):
            for veto in ("cancelled", "deadline", "launch_retired"):
                for partial in (False, True):
                    context = _context()
                    channel = _wire_channel(context, "c_to_o", "o_to_c")
                    with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)):
                        channel.send_frame(_configuration())
                        channel.flush()
                        for kind in prefix:
                            channel.send(kind)
                            channel.flush()
                        channel.send(grant)
                        if partial:
                            with patch.object(owner.os, "write", return_value=2):
                                channel.flush()
                    now = 1
                    if veto == "cancelled":
                        context.cancelled = True
                    elif veto == "deadline":
                        now = context.run
                    else:
                        context.retire_launch()
                        self.assertIsNone(context.primary)
                    with self.subTest(grant=grant, veto=veto, partial=partial), patch.object(owner.time, "monotonic_ns", return_value=now), patch.object(owner.os, "write") as syscall:
                        with self.assertRaises(ValidationError):
                            channel.flush()
                        channel.flush()  # A later cleanup turn cannot reopen it.
                        syscall.assert_not_called()
                    self.assertEqual(grant in channel.write_attempted, partial)
                    self.assertNotIn(grant, channel.sent)
                    self.assertTrue(channel.writer_closed)
                    self.assertEqual(channel.writer.close_calls, 1)
                    self.assertEqual(channel.pending, [])

    def test_fake_control_write_effect_then_exception_is_unknown_and_never_replayed(self):
        context = _context()
        channel = _wire_channel(context, "o_to_c", "c_to_o")
        channel.send_frame(_hello())
        first = KeyboardInterrupt("PRIVATE_WRITE_RETURN")
        effects = []

        def write(_fd, content):
            effects.append(bytes(content))  # Inert possible-effect model only.
            raise first

        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", side_effect=write) as syscall:
            with self.assertRaises(KeyboardInterrupt) as raised:
                channel.flush()
            channel.flush()
        self.assertIs(raised.exception, first)
        self.assertIs(context.primary, first)
        self.assertIs(context.interruption, first)
        self.assertEqual(syscall.call_count, 1)
        self.assertEqual(len(effects), 1)
        self.assertTrue(channel.write_failed)
        self.assertTrue(context.cleanup_unknown)
        self.assertEqual(channel.pending, [])
        self.assertNotIn("HELLO", channel.sent)
        self.assertEqual(channel.writer.close_calls, 1)

    def test_genuine_modeled_would_block_alone_preserves_a_retryable_write_offset(self):
        context = _context()
        channel = _wire_channel(context, "o_to_c", "c_to_o")
        channel.send_frame(_hello())
        original = bytes(channel.pending[0][1])
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", side_effect=BlockingIOError):
            channel.flush()
        self.assertEqual(bytes(channel.pending[0][1]), original)
        self.assertFalse(channel.write_failed)
        self.assertFalse(channel.write_in_flight)
        self.assertFalse(channel.writer_closed)
        self.assertNotIn("HELLO", channel.sent)
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)):
            channel.flush()
        self.assertIn("HELLO", channel.sent)
        self.assertEqual(channel.pending, [])

    def test_partial_write_offset_publication_failure_is_absorbing_before_any_retry(self):
        context = _context()
        channel = _wire_channel(context, "c_to_o", "o_to_c")
        channel.send("CANCEL", reason_code="cancelled", cleanup_deadline_ns=context.hard)
        first = SystemExit(29)

        class Pending(list):
            def __setitem__(self, _index, _value):
                raise first  # Inert loss AFTER the positive write return.

        channel.pending = Pending(channel.pending)
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", return_value=2) as syscall:
            with self.assertRaises(SystemExit) as raised:
                channel.flush()
            channel.flush()
        self.assertIs(raised.exception, first)
        self.assertIs(context.primary, first)
        self.assertIs(context.interruption, first)
        self.assertEqual(syscall.call_count, 1)
        self.assertTrue(channel.write_in_flight)
        self.assertTrue(channel.write_failed)
        self.assertTrue(channel.writer_closed)
        self.assertEqual(channel.pending, [])
        self.assertNotIn("CANCEL", channel.sent)

    def test_post_write_observation_error_is_not_mistaken_for_would_block(self):
        context = _context()
        channel = _wire_channel(context, "o_to_c", "c_to_o")
        channel.send_frame(_hello())
        first = BlockingIOError("PRIVATE_PROGRESS_PUBLICATION")

        def observe(_role, event, **_evidence):
            if event == "frame_sent":
                raise first

        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)) as syscall, patch.object(owner, "_role_event", side_effect=observe):
            with self.assertRaises(BlockingIOError) as raised:
                channel.flush()
            channel.flush()
        self.assertIs(raised.exception, first)
        self.assertEqual(syscall.call_count, 1)
        self.assertIn("HELLO", channel.sent)  # Actual full-return model is retained.
        self.assertTrue(channel.write_failed)
        self.assertTrue(channel.write_in_flight)
        self.assertTrue(context.cleanup_unknown)
        self.assertTrue(channel.writer_closed)

    def test_write_argument_error_is_not_mistaken_for_syscall_would_block(self):
        context = _context()
        channel = _wire_channel(context, "o_to_c", "c_to_o")
        channel.send_frame(_hello())
        first = BlockingIOError("PRIVATE_WRITE_ARGUMENT")
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(channel.writer, "fileno", side_effect=first), patch.object(owner.os, "write") as syscall:
            with self.assertRaises(BlockingIOError) as raised:
                channel.flush()
            channel.flush()
        self.assertIs(raised.exception, first)
        self.assertIs(context.primary, first)
        syscall.assert_not_called()
        self.assertNotIn("HELLO", channel.write_attempted)
        self.assertNotIn("HELLO", channel.sent)
        self.assertTrue(channel.write_failed)
        self.assertTrue(channel.write_in_flight)
        self.assertTrue(context.cleanup_unknown)
        self.assertTrue(channel.writer_closed)

    def test_unsettled_write_latch_vetoes_retry_even_if_its_error_handler_was_lost(self):
        context = _context()
        channel = _wire_channel(context, "c_to_o", "o_to_c")
        channel.send("CANCEL", reason_code="cancelled", cleanup_deadline_ns=context.hard)
        channel.write_in_flight = True  # Explicit inert missing-publication model.
        self.assertFalse(channel.write_failed)
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write") as syscall:
            with self.assertRaises(ValidationError):
                channel.flush()
        syscall.assert_not_called()
        self.assertTrue(channel.write_failed)
        self.assertTrue(channel.writer_closed)
        self.assertTrue(context.cleanup_unknown)
        self.assertEqual(channel.pending, [])

    def test_invalid_write_returns_never_advance_an_offset_or_allow_a_retry(self):
        for result in (True, 0, -1, None, owner.CONFIG_LIMIT * 2):
            context = _context()
            channel = _wire_channel(context, "o_to_c", "c_to_o")
            channel.send_frame(_hello())
            with self.subTest(result=result), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "write", return_value=result) as syscall:
                with self.assertRaises(ValidationError):
                    channel.flush()
                channel.flush()
            self.assertEqual(syscall.call_count, 1)
            self.assertTrue(channel.write_failed)
            self.assertNotIn("HELLO", channel.sent)
            self.assertTrue(context.cleanup_unknown)


class ProfileOwnerDeadlineTests(unittest.TestCase):
    def test_nested_cutoffs_share_one_original_clock_and_never_renew(self):
        now = 100_000_000_000
        deadline = types.SimpleNamespace(expires_at=1000.0)
        with patch.object(owner.time, "monotonic_ns", return_value=now) as clock:
            limits = owner._Deadlines.from_inspection(deadline)
        self.assertEqual(limits, owner._Deadlines(now + 30_000_000_000, now + 25_000_000_000,
                                                now + 20_000_000_000, now + 28_000_000_000,
                                                now + 33_000_000_000))
        clock.assert_called_once_with()
        deadline.expires_at = 101.25
        with patch.object(owner.time, "monotonic_ns", return_value=now):
            limits = owner._Deadlines.from_inspection(deadline)
        self.assertEqual(set(vars(limits).values()), {101_250_000_000})

    def test_expired_nonfinite_and_boolean_shared_endpoints_never_acquire(self):
        for endpoint in (True, float("inf"), float("nan"), -1, 1.0):
            with self.subTest(endpoint=endpoint), patch.object(owner.time, "monotonic_ns", return_value=1_000_000_000):
                with self.assertRaisesRegex(ValidationError, "authentication timed out"):
                    owner._Deadlines.from_inspection(types.SimpleNamespace(expires_at=endpoint))

    def test_float_endpoint_conversion_never_rounds_past_the_existing_shared_cutoff(self):
        endpoint = 100_000_000.00000001
        numerator, denominator = endpoint.as_integer_ratio()
        exact_floor = numerator * owner.NANOSECOND // denominator
        self.assertGreater(int(endpoint * owner.NANOSECOND), exact_floor)
        with patch.object(owner.time, "monotonic_ns", return_value=100_000_000 * owner.NANOSECOND):
            limits = owner._Deadlines.from_inspection(types.SimpleNamespace(expires_at=endpoint))
        self.assertEqual(set(vars(limits).values()), {exact_floor})

    def test_first_failure_fixes_one_cleanup_grace_and_later_cancel_only_shortens(self):
        context = _context("custodian", parent_pid=429)
        first = ValidationError(owner.ERROR)
        with patch.object(owner.time, "monotonic_ns", return_value=2_000_000_000):
            context.record(first)
        with patch.object(owner.time, "monotonic_ns", return_value=4_000_000_000):
            context.record(KeyboardInterrupt("later"))
            self.assertEqual(context.failure_limit, 5_000_000_000)
            context.cancel_frame({"reason_code": "deadline", "cleanup_deadline_ns": 4_500_000_000})
        self.assertEqual(context.begin_cleanup(), 4_500_000_000)
        self.assertIs(context.primary, first)
        custodian = _custodian(context)
        channel = custodian.outer = _wire_channel(context, "o_to_c", "c_to_o")
        context.io.leases.extend((channel.reader, channel.writer))
        cancel = {"v": 1, "type": "CANCEL", "reason_code": "cancelled", "cleanup_deadline_ns": 4_250_000_000}
        with patch.object(owner.time, "monotonic_ns", return_value=4_000_000_000), patch.object(owner.os, "getppid", return_value=429), patch.object(owner.os, "read", side_effect=(owner.Protocol.encode(cancel), b"")), patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)), patch.object(owner, "_pause"):
            self.assertTrue(custodian.retire_outer_control())
        self.assertIs(context.primary, first)
        self.assertEqual(context.failure_limit, 4_250_000_000)
        self.assertEqual(context.cleanup_limit, 4_250_000_000)
        self.assertEqual(channel.write_limits["QUIESCING"], 4_500_000_000)
        self.assertTrue(channel.decoder.ended)
        self.assertEqual(channel.reader.close_calls, 1)

    def test_cleanup_flush_rechecks_a_shortened_cutoff_after_its_pump(self):
        context = _context()
        channel = _wire_channel(context, "c_to_o", "o_to_c")
        now = 1_000_000_000
        with patch.object(owner.time, "monotonic_ns", return_value=now):
            original = context.begin_cleanup()
            channel.send("CANCEL", reason_code="cancelled", cleanup_deadline_ns=original)

            def shorten():
                context.cancel_frame({"reason_code": "deadline", "cleanup_deadline_ns": now})

            with patch.object(owner.os, "write") as syscall, patch.object(owner, "_pause"):
                with self.assertRaises(ValidationError):
                    owner._flush_until(channel, original, shorten)
        syscall.assert_not_called()
        self.assertEqual(context.cleanup_cutoff(original), now)
        self.assertNotIn("CANCEL", channel.sent)
        self.assertTrue(channel.writer_closed)

    def test_task_settlement_does_not_reuse_a_cached_grace_after_cancel(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        thread = Mock()
        thread.is_alive.return_value = True
        slot.actual = slot.returned = slot.constructed = thread
        now = 1_000_000_000

        def shorten():
            context.cancel_frame({"reason_code": "deadline", "cleanup_deadline_ns": now})

        with patch.object(owner.time, "monotonic_ns", return_value=now), patch.object(owner, "_pause"):
            owner._settle_tasks(context, shorten)
        self.assertEqual(thread.join.call_count, 1)
        self.assertFalse(slot.joined)
        self.assertTrue(context.cleanup_unknown)
        self.assertEqual(context.cleanup_limit, now)

    def test_late_failure_report_does_not_reopen_completed_numeric_cleanup(self):
        context = _context("custodian", run=25_000_000_000, hard=28_000_000_000)
        with patch.object(owner.time, "monotonic_ns", return_value=1_000_000_000):
            original = context.begin_cleanup()
        channel = _wire_channel(context, "o_to_c", "c_to_o")
        with patch.object(owner.time, "monotonic_ns", return_value=25_000_000_000), patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)) as syscall, patch.object(owner, "_pause"):
            context.record(ValidationError(owner.TIMEOUT), "deadline")
            self.assertEqual(context.cleanup_cutoff(context.hard), original)
            self.assertEqual(context.control_cutoff(context.hard), 28_000_000_000)
            channel.send_frame(_quiescing())
            channel.send_frame(_failed())
            owner._flush_until(channel, context.hard, lambda: None, cleanup_bound=False)
        self.assertEqual(syscall.call_count, 2)
        self.assertIn("FINAL", channel.sent)
        self.assertEqual(context.cleanup_limit, original)

    def test_fixed_bootstrap_suffixes_do_not_accept_a_command_or_relative_interpreter(self):
        with patch.object(owner, "_module_root", return_value="/installed/lib"), patch.object(owner, "_interpreter", return_value="/usr/bin/python3"):
            command = owner.helper_argv("keeper", parent_context={"parent_pid": 430, "session_id": 430},
                                        deadlines={"run_deadline_ns": 20, "hard_cleanup_deadline_ns": 23})
            self.assertEqual(command[:6], ("/usr/bin/python3", "-I", "-S", "-B", "-c", owner.HELPER_BOOTSTRAP))
            self.assertEqual(command[-5:], ("keeper", "430", "430", "20", "23"))
            self.assertEqual(owner._worker_argv(Path("/private/profile"), 19)[-3:],
                             ("--worker", "/private/profile", "19"))
            with self.assertRaises(ValidationError):
                owner.helper_argv([], parent_context={}, deadlines={})
        with patch.object(owner.sys, "executable", "python"):
            with self.assertRaises(ValidationError):
                owner._interpreter()


class ProfileOwnerTaskTests(unittest.TestCase):
    def test_task_slot_is_rooted_before_start_and_lost_start_return_is_not_no_attempt(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        failure = KeyboardInterrupt("start publication")
        fake_thread = Mock()

        def start():
            self.assertIn(slot, context.tasks)
            slot.actual = fake_thread  # Model the target's self-publication.
            raise failure

        fake_thread.start.side_effect = start
        with patch.object(owner.threading, "Thread", return_value=fake_thread):
            with self.assertRaises(KeyboardInterrupt) as raised:
                slot.start()
        self.assertIs(raised.exception, failure)
        self.assertIsNone(slot.returned)
        self.assertFalse(slot.joined)
        self.assertEqual(owner._task_child_record(context), {"state": "unknown"})

    def test_reference_mismatch_and_late_retirement_never_grant_native_creation(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        slot.actual, slot.returned, slot.constructed = object(), object(), object()
        with self.assertRaises(ValidationError):
            slot.reconcile_and_grant()
        self.assertFalse(slot.acquisition.grants)
        slot.actual = slot.returned = slot.constructed = threading.current_thread()
        context.retire_launch()
        with patch.object(owner.time, "monotonic_ns", return_value=1):
            with self.assertRaises(ValidationError):
                slot.reconcile_and_grant()
        self.assertFalse(slot.acquisition.grants)
        with patch.object(owner.native, "create") as create:
            slot._body()
        create.assert_not_called()

    def test_fake_join_requires_actual_join_call_publication_and_body_tail(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        fake_thread = Mock()
        fake_thread.is_alive.return_value = False
        slot.actual = slot.returned = slot.constructed = fake_thread
        with patch.object(owner.time, "monotonic_ns", return_value=1):
            self.assertFalse(slot.join_once(1_000_000_000))
            self.assertFalse(slot.joined)
            slot.body_done = True
            self.assertTrue(slot.join_once(1_000_000_000))
        self.assertEqual(fake_thread.join.call_count, 2)
        self.assertTrue(slot.acquisition.launch_retired)

    def test_childless_slot_is_no_attempt_only_after_permanent_retirement_and_join(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        context.retire_launch()
        self.assertEqual(owner._task_child_record(context), {"state": "unknown"})
        slot.joined = True  # Explicit inert receipt model, not native join evidence.
        self.assertEqual(owner._task_child_record(context), {"state": "not_attempted"})
        slot.acquisition.attempted = True
        self.assertEqual(owner._task_child_record(context), {"state": "unknown"})

    def test_leaf_first_record_beats_later_caller_interrupt_before_creator_handoff(self):
        context = _context()
        first, later = ValidationError(owner.ERROR), KeyboardInterrupt("later caller")
        with patch.object(owner.time, "monotonic_ns", return_value=1):
            context.child_acquisition.failure_recorder(first)
            context.record(later, "cancelled")
            context.record(first, "creation")  # Later creator-return observation.
        self.assertIs(context.primary, first)
        self.assertIs(context.interruption, later)
        self.assertEqual(context.secondary, [later])

    def test_caller_first_and_actual_later_leaf_interruption_keep_exact_identity(self):
        context = _context()
        first, later = SystemExit(37), KeyboardInterrupt("cleanup")
        with patch.object(owner.time, "monotonic_ns", return_value=1):
            context.record(first, "cancelled")
            context.io.failure_recorder(ValidationError(owner.ERROR))
            context.child_acquisition.interruption = later
            context.collect_native()
        self.assertIs(context.primary, first)
        self.assertIs(context.interruption, first)
        self.assertIn(later, context.secondary)
        self.assertEqual(context.primary.code, 37)

    def test_task_body_catches_publication_failure_without_automatic_thread_reporting(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        first = RuntimeError("PRIVATE_TASK_MARKER")
        with patch.object(owner, "_role_event", side_effect=first), patch.object(owner.threading, "excepthook") as reporter:
            slot._body()
        self.assertIs(slot.error, first)
        self.assertIs(context.primary, first)
        self.assertTrue(slot.body_done)
        self.assertFalse(slot.joined)
        reporter.assert_not_called()
        self.assertNotIn("PRIVATE_TASK_MARKER", str(owner._public_error(first)))

    def test_prepublication_target_failure_can_join_the_normally_returned_original_thread(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        first = RuntimeError("PRIVATE_BEFORE_SELF_PUBLICATION")
        thread = Mock()
        thread.is_alive.return_value = False
        thread.start.side_effect = slot._body  # Synchronous inert target, no task.
        with patch.object(owner.threading, "Thread", return_value=thread), patch.object(owner.threading, "current_thread", side_effect=first), patch.object(owner.native, "create") as create, patch.object(owner.time, "monotonic_ns", return_value=1):
            slot.start()
        self.assertIsNone(slot.actual)
        self.assertIs(slot.returned, thread)
        self.assertIs(slot.constructed, thread)
        self.assertTrue(slot.started)
        self.assertTrue(slot.body_done)
        self.assertIs(slot.error, first)
        self.assertIs(context.primary, first)
        self.assertEqual(owner._task_child_record(context), {"state": "unknown"})
        with patch.object(owner.time, "monotonic_ns", return_value=1):
            self.assertTrue(slot.join_once(context.run))
        thread.join.assert_called_once()
        create.assert_not_called()
        self.assertFalse(slot.acquisition.grants)
        self.assertEqual(owner._task_child_record(context), {"state": "not_attempted"})

    def test_task_recorder_failure_is_contained_before_private_diagnostics_or_reporting(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        first, later = RuntimeError("PRIVATE_TARGET_CHAIN"), KeyboardInterrupt("PRIVATE_RECORDER_CHAIN")
        first.__cause__ = RuntimeError("PRIVATE_CAUSE_CHAIN")

        def broken_record(error, *_args, **_kwargs):
            self.assertIs(error, first)
            self.assertIsNone(slot.error)  # Common boundary precedes task latch.
            raise later

        with patch.object(slot.published, "set", side_effect=first), patch.object(context, "record", side_effect=broken_record), patch.object(owner.threading, "excepthook") as reporter, patch.object(owner.time, "monotonic_ns", return_value=1):
            slot._body()
        self.assertIs(context.primary, first)
        self.assertIs(slot.error, first)
        self.assertIs(context.interruption, later)
        self.assertIn(later, context.secondary)
        self.assertTrue(context.cleanup_unknown)
        self.assertTrue(slot.body_done)
        self.assertTrue(slot.launch_retired)
        self.assertFalse(slot.joined)
        reporter.assert_not_called()
        self.assertNotIn("PRIVATE", str(owner._public_error(first)))

    def test_task_retirement_and_collection_tail_errors_preserve_the_first_actual_interrupt(self):
        context = _context()
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=()), "custodian")
        context.tasks.append(slot)
        first, retirement, tail = SystemExit(37), OSError("PRIVATE_RETIREMENT"), RuntimeError("PRIVATE_COLLECTION")
        with patch.object(slot.published, "set", side_effect=first), patch.object(slot.granted, "set", side_effect=retirement), patch.object(context, "collect_native", side_effect=tail), patch.object(owner.threading, "excepthook") as reporter, patch.object(owner.time, "monotonic_ns", return_value=1):
            slot._body()
        self.assertIs(context.primary, first)
        self.assertIs(context.interruption, first)
        self.assertIs(slot.error, first)
        self.assertEqual(context.primary.code, 37)
        self.assertIn(retirement, context.secondary)
        self.assertIn(tail, context.secondary)
        self.assertTrue(context.cleanup_unknown)
        self.assertTrue(slot.body_done)
        self.assertFalse(slot.launch)
        reporter.assert_not_called()

    def test_outermost_target_containment_keeps_unjoined_native_sources_in_custody(self):
        context = _context()
        source = _Lease(220)
        context.io.leases.append(source)
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=(source,)), "custodian")
        context.tasks.append(slot)
        first, later = RuntimeError("PRIVATE_TARGET_TAIL"), RuntimeError("PRIVATE_COLLECTOR_TAIL")
        with patch.object(slot, "_owned_body", side_effect=first), patch.object(context, "record", side_effect=later), patch.object(context, "contain_target_error", side_effect=later), patch.object(owner.threading, "excepthook") as reporter:
            slot._body()
        context.close_all()
        self.assertIs(slot.error, first)
        self.assertIs(context.emergency_primary, first)
        self.assertIs(context.emergency_secondary, later)
        self.assertTrue(slot.body_done)
        self.assertTrue(context.cleanup_unknown)
        self.assertEqual(source.close_calls, 0)
        self.assertFalse(context.resources_confirmed())
        reporter.assert_not_called()

    def test_unjoined_creator_sources_and_native_custody_are_not_released(self):
        context = _context()
        source, independent = _Lease(201), _Lease(202)
        context.io.leases.extend((source, independent))
        slot = owner.TaskSlot(context, types.SimpleNamespace(fd_sources=(source,)), "custodian")
        context.tasks.append(slot)
        context.close_all()
        self.assertEqual(source.close_calls, 0)
        self.assertEqual(independent.close_calls, 1)
        self.assertFalse(context.resources_confirmed())
        slot.joined = True
        context.close_all()
        self.assertEqual(source.close_calls, 1)
        self.assertEqual(independent.close_calls, 1)


class ProfileOwnerWaitAndGroupTests(unittest.TestCase):
    def test_first_consuming_wait_retires_numeric_routes_and_zero_alone_repolls(self):
        context, receipt = _context(), _receipt()
        child = _Child((None, receipt))
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner, "_pause"), patch.object(owner, "_role_event") as event:
            actual = owner._wait_child(context, child, 1_000_000_000, lambda: None, "custodian_reaped", phase="CLEANUP")
        self.assertIs(actual, receipt)
        self.assertEqual(child.polls, 2)
        self.assertTrue(child.numeric_retired)
        self.assertIs(event.call_args.kwargs["receipt"], receipt)

        context, receipt = _context("keeper"), _receipt(pid=432)
        child = _Child((None, receipt), pid=432)
        context.child_acquisition.child = child
        context.child_acquisition.attempted = True
        pump = Mock(side_effect=AssertionError("single cleanup turn must yield to its caller"))
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner, "_pause") as pause, patch.object(owner, "_role_event") as event:
            self.assertIsNone(owner._wait_child(context, child, context.run, pump, "validator_reaped", phase="CLEANUP", single_turn=True))
            self.assertEqual((child.polls, child.wait_state, child.numeric_retired), (1, "POLLABLE", True))
            self.assertIsNone(child.receipt)
            self.assertEqual(child.results, [receipt])
            self.assertIsNone(context.primary)
            self.assertIsNone(context.cleanup_limit)
            self.assertIsNone(context.failure_limit)
            event.assert_not_called()
            pause.assert_not_called()
            pump.assert_not_called()
            self.assertIs(owner._wait_child(context, child, context.run, pump, "validator_reaped", phase="CLEANUP", single_turn=True), receipt)
            self.assertEqual((child.polls, child.wait_state), (2, "REAPED"))
            self.assertIs(child.receipt, receipt)
            event.assert_called_once_with("keeper", "validator_reaped", receipt=receipt)
            pause.assert_not_called()
            pump.assert_not_called()
            self.assertFalse(context.cleanup_unknown)

    def test_unknown_wait_is_absorbing_and_never_numeric_retried(self):
        for role, single_turn in (("outer", False), ("keeper", True)):
            context, child = _context(role), _Child((ChildProcessError("missing private wait"),))
            pump = Mock(side_effect=AssertionError("unknown wait must not pump"))
            with self.subTest(role=role, single_turn=single_turn), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner, "_pause") as pause, patch.object(owner, "_role_event") as event:
                self.assertIsNone(owner._wait_child(context, child, 1_000_000_000, pump, "validator_reaped", phase="CLEANUP", single_turn=single_turn))
                first, fixed = context.primary, context.failure_limit
                self.assertIsNone(owner._wait_child(context, child, 1_000_000_000, pump, "validator_reaped", phase="CLEANUP", single_turn=single_turn))
                self.assertIs(context.primary, first)
                self.assertEqual(context.failure_limit, fixed)
                pump.assert_not_called()
                pause.assert_not_called()
                event.assert_not_called()
            self.assertEqual(child.polls, 1)
            self.assertEqual(child.wait_state, "UNKNOWN")
            self.assertTrue(context.cleanup_unknown)

    def test_wait_poll_and_group_syscall_use_the_shortened_live_cleanup_cutoff(self):
        now = 1_000_000_000
        context, child = _context(), _Child((None, _receipt()))

        def shorten():
            context.cancel_frame({"reason_code": "deadline", "cleanup_deadline_ns": now})

        with patch.object(owner.time, "monotonic_ns", return_value=now), patch.object(owner, "_pause"):
            original = context.begin_cleanup()
            self.assertIsNone(owner._wait_child(context, child, original, shorten, "custodian_reaped", phase="CLEANUP"))
        self.assertEqual(child.polls, 1)
        self.assertIsNone(child.receipt)
        self.assertTrue(context.cleanup_unknown)
        context = _context("custodian")
        group = owner._GroupReservation(context, _Child())
        with patch.object(owner.time, "monotonic_ns", return_value=now), patch.object(owner.os, "killpg") as syscall:
            context.begin_cleanup()
            with patch.object(owner, "_role_event", side_effect=lambda *_args, **_kwargs: shorten()):
                with self.assertRaises(ValidationError):
                    group.request(0)
        syscall.assert_not_called()

        context, receipt = _context("keeper"), _receipt(pid=432)
        child = _Child((None, receipt), pid=432)
        pump = Mock(side_effect=AssertionError("single turn cannot consume another control turn"))
        with patch.object(owner.time, "monotonic_ns", return_value=now), patch.object(owner, "_pause") as pause:
            original = context.begin_cleanup()
            self.assertIsNone(owner._wait_child(context, child, original, pump, "validator_reaped", phase="CLEANUP", single_turn=True))
            first = context.cancel_frame({"reason_code": "deadline", "cleanup_deadline_ns": now})
            self.assertIsNone(owner._wait_child(context, child, original, pump, "validator_reaped", phase="CLEANUP", single_turn=True))
            self.assertIs(context.primary, first)
            self.assertEqual((context.failure_limit, context.cleanup_limit), (now, now))
            self.assertEqual(child.polls, 1)
            self.assertEqual(child.results, [receipt])
            self.assertIsNone(child.receipt)
            self.assertTrue(context.cleanup_unknown)
            pump.assert_not_called()
            pause.assert_not_called()

    def test_readonly_group_retirement_vetoes_every_request_including_signal_zero(self):
        context, keeper = _context("custodian"), _Child()
        group = owner._GroupReservation(context, keeper)
        for name in ("id", "retired", "absent"):
            with self.assertRaises(AttributeError):
                setattr(group, name, 9)
        group.retire(absent=False)
        with patch.object(owner.os, "killpg") as syscall:
            for signum in (0, int(signal.SIGKILL)):
                with self.assertRaises(ValidationError):
                    group.request(signum)
        syscall.assert_not_called()

    def test_post_observer_identity_retirement_is_rechecked_before_group_syscall(self):
        context, keeper = _context("custodian"), _Child()
        group = owner._GroupReservation(context, keeper)
        with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner, "_role_event", side_effect=lambda *_args, **_kwargs: keeper.retire_numeric()), patch.object(owner.os, "killpg") as syscall:
            with self.assertRaises(ValidationError):
                group.request(0)
        syscall.assert_not_called()

    def test_persistent_eperm_group_cleanup_has_one_bound_and_retires_before_keeper_wait(self):
        context, keeper = _context("custodian"), _Child()
        context.child_acquisition.child = keeper
        context.child_acquisition.attempted = True
        custodian = owner._Custodian.__new__(owner._Custodian)
        custodian.context, custodian.keeper = context, keeper
        custodian.cleanup_claimed = False
        custodian.outer = _Channel(context)
        custodian.payload = _Lease(203)
        custodian.keeper_channel = _Channel(context)
        custodian.keeper_channel.eof = False
        custodian.keeper_channel.write_attempted.add("RUN")
        custodian.keeper_channel.sent.add("RUN")
        custodian.group = owner._GroupReservation(context, keeper)
        custodian.run_sent = True
        custodian.routes_retired = custodian.release_sent = False
        custodian.released = None
        custodian.safe_pump = Mock()
        clock = iter(range(0, 30_000_000_000, 100_000_000))

        def wait(_ctx, _child, _cutoff, _pump, _event, *, phase):
            self.assertEqual(phase, "CLEANUP")
            self.assertTrue(custodian.group.retired)
            self.assertTrue(custodian.routes_retired)
            self.assertFalse(custodian.group.absent)
            return None

        with patch.object(owner.time, "monotonic_ns", side_effect=lambda: next(clock)), patch.object(owner, "_pause"), patch.object(owner.os, "killpg", side_effect=PermissionError) as syscall, patch.object(owner, "_wait_child", side_effect=wait):
            custodian.cleanup_descendants()
            count = syscall.call_count
            self.assertGreater(count, 0)
            self.assertLess(count, 80)
            with self.assertRaises(ValidationError):
                custodian.cleanup_descendants()
            self.assertEqual(syscall.call_count, count)
        self.assertTrue(context.cleanup_unknown)


class ProfileOwnerWorkWaitTests(unittest.TestCase):
    def test_work_timeout_and_parent_cancel_continue_same_child_only_for_cleanup(self):
        for stop in ("timeout", "timeout_before_pump", "parent_cancel"):
            context = _context("keeper", parent_pid=430)
            keeper, receipt = _keeper(context), _receipt(pid=432)
            child = _Child((None, receipt), pid=432)
            context.child_acquisition.child = child
            context.child_acquisition.attempted = True
            keeper.config, keeper.run_granted = _configuration("keeper"), True
            keeper.channel.eof = False
            now, turns, failure = [owner.NANOSECOND], [], []
            original_pump, original_wait, original_poll = keeper.pump, owner._wait_child, child.poll_wait

            def poll():
                actual = original_poll()
                if stop == "timeout_before_pump" and actual is None:
                    now[0] = context.run
                return actual

            def pump():
                turns.append((child.polls, child.wait_state))
                if len(turns) == 1 and stop != "timeout_before_pump":
                    if stop == "parent_cancel":
                        keeper.channel.frames = [{"v": 1, "type": "CANCEL", "reason_code": "cancelled",
                                                  "cleanup_deadline_ns": context.hard}]
                    original_pump()
                    if stop == "timeout":
                        now[0] = context.run
                elif len(turns) == (1 if stop == "timeout_before_pump" else 2):
                    failure.append((context.primary, context.failure_limit))
                    now[0] += owner.NANOSECOND
                    keeper.channel.frames = [{"v": 1, "type": "GROUP_RETIRED", "group_id": 431, "absent": True},
                                              {"v": 1, "type": "RELEASE"}]
                    original_pump()
                else:
                    now[0] = context.hard  # A broken fake path must not spin.
                    raise AssertionError("unexpected fake keeper pump")

            # Real owner control flow, but NO native acquisition, process wait,
            # group move/request, descriptor syscall, pause, or helper_main.
            with self.subTest(stop=stop), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(owner.os, "getppid", return_value=430), patch.object(owner.os, "_exit") as terminate, patch.object(owner, "_pause"), patch.object(owner, "_hello", return_value={**_hello(), "sid": 430}), patch.object(owner, "_spawn", return_value=child) as spawn, patch.object(keeper, "move_out", side_effect=lambda **_options: setattr(keeper, "moved", True)) as move, patch.object(keeper, "fallback_group", side_effect=AssertionError("unexpected fake fallback")) as fallback, patch.object(keeper, "pump", side_effect=pump), patch.object(child, "poll_wait", side_effect=poll), patch.object(owner, "_wait_child", wraps=original_wait) as waits:
                result = keeper.run()
                self.assertTrue(context.resources_confirmed())
                terminate.assert_not_called()
            self.assertEqual(result, owner.HELPER_SETTLED if stop == "parent_cancel" else owner.HELPER_FAILED)
            self.assertEqual(turns, [(1, "POLLABLE")] * (1 if stop == "timeout_before_pump" else 2))
            self.assertEqual([call.kwargs["phase"] for call in waits.call_args_list], ["WORK", "CLEANUP"])
            self.assertTrue(all(call.args[0] is context and call.args[1] is child for call in waits.call_args_list))
            self.assertEqual(spawn.call_count, 1)
            move.assert_called_once_with(positive=True)
            fallback.assert_not_called()
            self.assertIs(keeper.validator, child)
            self.assertIs(context.child_acquisition.child, child)
            self.assertIs(keeper.receipt, receipt)
            self.assertIs(child.receipt, receipt)
            self.assertEqual((child.polls, child.wait_state, child.numeric_retired), (2, "REAPED", True))
            self.assertEqual(context.secondary, [])
            self.assertFalse(context.cleanup_unknown)
            first_time = owner.NANOSECOND if stop == "parent_cancel" else context.run
            fixed = min(context.hard, first_time + owner.CLEANUP_SECONDS * owner.NANOSECOND)
            self.assertEqual(len(failure), 1)
            self.assertIs(failure[0][0], context.primary)
            self.assertEqual((failure[0][1], context.failure_limit, context.cleanup_limit), (fixed, fixed, fixed))
            if stop == "parent_cancel":
                self.assertIs(context.primary, keeper.parent_cancellation)
            else:
                self.assertEqual(context.primary.args, (owner.TIMEOUT,))
                self.assertEqual(context.reason, "deadline")
            self.assertNotIn("STATUS", {frame["type"] for frame in keeper.channel.offers})
            self.assertNotIn("STATUS", keeper.channel.sent)
            self.assertIn("RELEASED", keeper.channel.sent)
            self.assertEqual(keeper.channel.offers[-1]["validator"], owner._receipt_record(receipt))
            self.assertTrue(keeper.channel.writer_closed)
            self.assertEqual([lease.close_calls for lease in keeper.descriptors.values()], [1] * 5)

        # Model the real dependency: C withholds group retirement/RELEASE until
        # original K consumes V's receipt. No control frame supplies that receipt.
        # A missing interleaved reap advances the same clock to bounded failure.
        for stop in ("timeout", "parent_cancel", "eof", "parent_lost"):
            context = _context("keeper", parent_pid=430)
            keeper, receipt = _keeper(context), _receipt(pid=432)
            child = _Child((None, None, receipt), pid=432)
            context.child_acquisition.child = child
            context.child_acquisition.attempted = True
            keeper.config, keeper.run_granted = _configuration("keeper"), True
            keeper.channel.eof = False
            now, parent, failure, timeline, receipts, fallback_calls = [owner.NANOSECOND], [430], [], [], [], []
            original_pump, original_wait, original_poll = keeper.pump, owner._wait_child, child.poll_wait

            def poll():
                self.assertFalse(keeper.released)
                actual = original_poll()  # Also requires numeric retirement before first poll.
                timeline.append(("poll", child.polls))
                return actual

            def pump():
                if context.primary is None:
                    timeline.append(("work_control", child.polls))
                    if stop == "parent_cancel":
                        keeper.channel.frames = [{"v": 1, "type": "CANCEL", "reason_code": "cancelled",
                                                  "cleanup_deadline_ns": context.hard}]
                    original_pump()
                    if stop != "parent_cancel":
                        now[0] = context.run
                    return
                timeline.append(("cleanup_control", child.polls))
                if not failure:
                    failure.append((context.primary, context.failure_limit, context.cleanup_limit))
                if child.receipt is receipt:
                    self.assertIs(keeper.receipt, receipt)
                    keeper.channel.frames = [{"v": 1, "type": "GROUP_RETIRED", "group_id": 431, "absent": True},
                                              {"v": 1, "type": "RELEASE"}]
                elif child.polls == 2 and stop in ("eof", "parent_lost"):
                    timeline.append(("parent_input_lost", child.polls))
                    if stop == "eof":
                        keeper.channel.eof = True  # Explicit inert original-channel EOF model.
                    else:
                        parent[0] = 999
                original_pump()

            def observe(role, event, **evidence):
                if event == "validator_reaped":
                    self.assertEqual(role, "keeper")
                    self.assertFalse(keeper.released)
                    self.assertIs(evidence["receipt"], child.receipt)
                    receipts.append(evidence["receipt"])
                    timeline.append(("receipt", child.polls))
                elif event == "group_retired":
                    self.assertIs(child.receipt, receipt)
                    timeline.append(("group_retired", child.polls))

            def pause(cutoff, *_args):
                timeline.append(("pause", child.polls))
                now[0] = min(context.cleanup_cutoff(cutoff), now[0] + owner.NANOSECOND // 4)

            def fallback():
                fallback_calls.append((child.polls, now[0]))
                timeline.append(("fallback", child.polls))
                self.assertIn(stop, ("eof", "parent_lost"))
                self.assertEqual(child.polls, 2)  # No extra poll after the control loss.
                self.assertIsNone(child.receipt)
                self.assertLess(now[0], failure[0][1])
                self.assertTrue(keeper.eof_seen if stop == "eof" else parent[0] != context.parent_pid)
                keeper.group_retired = keeper.group_absent = True  # No real group operation.

            with self.subTest(causal_cleanup=stop), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(owner.os, "getppid", side_effect=lambda: parent[0]), patch.object(owner.os, "_exit") as terminate, patch.object(owner, "_pause", side_effect=pause), patch.object(owner, "_hello", return_value={**_hello(), "sid": 430}), patch.object(owner, "_spawn", return_value=child) as spawn, patch.object(keeper, "move_out", side_effect=lambda **_options: setattr(keeper, "moved", True)) as move, patch.object(keeper, "fallback_group", side_effect=fallback), patch.object(keeper, "pump", side_effect=pump), patch.object(child, "poll_wait", side_effect=poll), patch.object(owner, "_role_event", side_effect=observe), patch.object(owner, "_wait_child", wraps=original_wait) as waits:
                result = keeper.run()
                self.assertTrue(context.resources_confirmed())
                terminate.assert_not_called()
            expected = owner.HELPER_UNKNOWN if stop == "parent_lost" else owner.HELPER_SETTLED if stop == "parent_cancel" else owner.HELPER_FAILED
            self.assertEqual(result, expected)
            self.assertEqual([call.kwargs["phase"] for call in waits.call_args_list], ["WORK", "CLEANUP", "CLEANUP"])
            self.assertEqual([call.kwargs.get("single_turn", False) for call in waits.call_args_list],
                             [False, True, stop in ("timeout", "parent_cancel")])
            self.assertTrue(all(call.args[0] is context and call.args[1] is child for call in waits.call_args_list))
            self.assertEqual(spawn.call_count, 1)
            move.assert_called_once_with(positive=True)
            self.assertIs(keeper.validator, child)
            self.assertIs(context.child_acquisition.child, child)
            self.assertIs(keeper.receipt, receipt)
            self.assertEqual(receipts, [receipt])
            self.assertEqual((child.polls, child.wait_state, child.numeric_retired), (3, "REAPED", True))
            self.assertLess(timeline.index(("cleanup_control", 1)), timeline.index(("poll", 2)))
            self.assertLess(timeline.index(("poll", 2)), timeline.index(("cleanup_control", 2)))
            self.assertLess(timeline.index(("cleanup_control", 2)), timeline.index(("poll", 3)))
            self.assertEqual(len(failure), 1)
            self.assertIs(context.primary, failure[0][0])
            self.assertEqual((context.failure_limit, context.cleanup_limit), failure[0][1:])
            self.assertLess(now[0], context.failure_limit)
            self.assertFalse(context.cleanup_unknown)
            if stop in ("timeout", "parent_cancel"):
                self.assertEqual(fallback_calls, [])
                self.assertTrue(keeper.released)
                self.assertLess(timeline.index(("receipt", 3)), timeline.index(("group_retired", 3)))
                self.assertEqual(context.secondary, [])
            else:
                self.assertEqual(len(fallback_calls), 1)
                self.assertFalse(keeper.released)
                self.assertLess(timeline.index(("parent_input_lost", 2)), timeline.index(("fallback", 2)))
                self.assertLess(timeline.index(("fallback", 2)), timeline.index(("poll", 3)))
                if stop == "eof":
                    self.assertTrue(keeper.eof_seen)
                    self.assertEqual(len(context.secondary), 1)
            if stop == "parent_cancel":
                self.assertIs(context.primary, keeper.parent_cancellation)
            else:
                self.assertEqual(context.primary.args, (owner.TIMEOUT,))
                self.assertEqual(context.reason, "deadline")
            self.assertNotIn("STATUS", {frame["type"] for frame in keeper.channel.offers})
            self.assertNotIn("STATUS", keeper.channel.sent)
            self.assertIn("RELEASED", keeper.channel.sent)
            self.assertEqual(keeper.channel.offers[-1]["validator"], owner._receipt_record(receipt))
            self.assertTrue(keeper.channel.writer_closed)
            self.assertEqual([lease.close_calls for lease in keeper.descriptors.values()], [1] * 5)

    def test_work_stops_before_first_poll_without_renewing_existing_cleanup_grace(self):
        for stop in ("parent_cancel", "timeout", "latched_signal"):
            context, receipt = _context("keeper", parent_pid=430), _receipt(pid=432)
            child = _Child((receipt,), pid=432)
            context.child_acquisition.child = child
            context.child_acquisition.attempted = True
            now, first = [owner.NANOSECOND], None
            pump = Mock(side_effect=AssertionError("stopped WORK must not pump"))
            with self.subTest(stop=stop), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(owner, "_pause") as pause, patch.object(owner.os, "_exit") as terminate:
                if stop == "parent_cancel":
                    first = context.cancel_frame({"v": 1, "type": "CANCEL", "reason_code": "cancelled",
                                                  "cleanup_deadline_ns": context.hard})
                    fixed = context.failure_limit
                    now[0] += owner.NANOSECOND  # The original grace has already started.
                elif stop == "timeout":
                    now[0] = context.run
                    fixed = context.hard
                else:
                    context.helper_signal(signal.SIGTERM, None)  # Inert callback, not an actual signal.
                    fixed = now[0] + owner.CLEANUP_SECONDS * owner.NANOSECOND
                self.assertIsNone(owner._wait_child(context, child, context.run, pump, "validator_reaped", phase="WORK"))
                self.assertEqual((child.polls, child.wait_state, child.numeric_retired), (0, "OWNED", True))
                if first is not None:
                    self.assertIs(context.primary, first)
                first = context.primary
                self.assertIsNotNone(first)
                self.assertEqual(first.args, (owner.TIMEOUT if stop == "timeout" else owner.ERROR,))
                self.assertEqual(context.failure_limit, fixed)
                self.assertFalse(context.cleanup_unknown)
                now[0] += owner.NANOSECOND
                self.assertLess(now[0], fixed)
                self.assertIs(owner._wait_child(context, child, context.hard, pump, "validator_reaped", phase="CLEANUP"), receipt)
                self.assertEqual(context.begin_cleanup(), fixed)
                pause.assert_not_called()
                terminate.assert_not_called()
            self.assertEqual(child.polls, 1)
            self.assertIs(child.receipt, receipt)
            self.assertIs(context.child_acquisition.child, child)
            self.assertIs(context.primary, first)
            self.assertEqual(context.failure_limit, fixed)
            self.assertEqual(context.secondary, [])
            self.assertFalse(context.cleanup_unknown)
            pump.assert_not_called()

    def test_late_work_receipt_and_last_prestatus_cancel_never_emit_status(self):
        for stop in ("late_receipt", "prestatus_cancel"):
            context = _context("keeper", parent_pid=430)
            keeper, receipt = _keeper(context), _receipt(pid=432)
            child = _Child((receipt,), pid=432)
            context.child_acquisition.child = child
            context.child_acquisition.attempted = True
            keeper.config, keeper.run_granted = _configuration("keeper"), True
            keeper.channel.eof = False
            now = [owner.NANOSECOND]
            original_poll, original_wait = child.poll_wait, owner._wait_child

            def poll():
                actual = original_poll()
                if stop == "late_receipt":
                    now[0] = context.run  # Positive wait publication, but no run time remains.
                return actual

            def wait(ctx, original, cutoff, pump, event, *, phase):
                actual = original_wait(ctx, original, cutoff, pump, event, phase=phase)
                if stop == "prestatus_cancel":
                    self.assertIs(actual, receipt)
                    keeper.channel.frames = [{"v": 1, "type": "CANCEL", "reason_code": "cancelled",
                                              "cleanup_deadline_ns": context.hard}]
                    keeper.pump()  # Actual owner CANCEL observation after wait return.
                return actual

            with self.subTest(stop=stop), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(owner.os, "getppid", return_value=430), patch.object(owner.os, "_exit") as terminate, patch.object(owner, "_pause"), patch.object(owner, "_hello", return_value={**_hello(), "sid": 430}), patch.object(owner, "_spawn", return_value=child), patch.object(keeper, "move_out", side_effect=lambda **_options: setattr(keeper, "moved", True)), patch.object(child, "poll_wait", side_effect=poll), patch.object(owner, "_wait_child", side_effect=wait) as waits:
                with self.assertRaises(ValidationError) as raised:
                    keeper.work()  # All effects use the inert channel/child/lease models.
                terminate.assert_not_called()
            self.assertEqual(waits.call_count, 1)
            self.assertEqual(waits.call_args.kwargs["phase"], "WORK")
            self.assertIs(raised.exception, context.primary)
            self.assertEqual(context.primary.args, (owner.TIMEOUT if stop == "late_receipt" else owner.ERROR,))
            if stop == "prestatus_cancel":
                self.assertIs(context.primary, keeper.parent_cancellation)
                self.assertIs(keeper.receipt, receipt)
            else:
                self.assertIsNone(keeper.receipt)
            self.assertIs(context.child_acquisition.child, child)
            self.assertIs(child.receipt, receipt)  # The genuine model receipt remains cleanup evidence.
            self.assertEqual((child.polls, child.wait_state, child.numeric_retired), (1, "REAPED", True))
            self.assertEqual(owner._task_child_record(context), owner._receipt_record(receipt))
            self.assertEqual(context.secondary, [])
            self.assertFalse(context.cleanup_unknown)
            self.assertNotIn("STATUS", {frame["type"] for frame in keeper.channel.offers})
            self.assertNotIn("STATUS", keeper.channel.sent)

    def test_work_poll_publication_and_observation_failures_never_become_soft_timeouts(self):
        for fault in ("poll_interrupt", "missing_wait", "lost_positive", "lost_zero", "observer", "pump"):
            context = _context("keeper", parent_pid=430)
            keeper, receipt = _keeper(context), _receipt(pid=432)
            error = {"poll_interrupt": SystemExit(17), "missing_wait": ChildProcessError("fake missing wait"),
                     "observer": BlockingIOError("fake receipt observation"), "pump": OSError("fake control pump")}.get(fault)
            results = (error,) if fault in ("poll_interrupt", "missing_wait") else (
                (None, receipt) if fault in ("lost_zero", "pump") else (receipt,))
            child = _Child(results, pid=432)
            context.child_acquisition.child = child
            context.child_acquisition.attempted = True
            keeper.validator = child
            keeper.moved = keeper.released = keeper.group_retired = keeper.group_absent = True
            keeper.channel.eof = False
            now, original_poll = [owner.NANOSECOND], child.poll_wait

            def poll():
                try:
                    actual = original_poll()
                finally:
                    if fault != "pump":
                        now[0] = context.run
                if fault == "lost_positive":
                    child.wait_state, child.receipt = "CONSUMED", None
                elif fault == "lost_zero":
                    child.wait_state = "WAIT_IN_FLIGHT"
                return actual

            def observe(_role, event, **_evidence):
                if fault == "observer" and event == "validator_reaped":
                    raise error  # Never soften an observer failure into a run deadline.

            def pump():
                if fault != "pump":
                    raise AssertionError("unexpected fake WORK pump")
                now[0] = context.run
                raise error

            with self.subTest(fault=fault), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(owner.os, "getppid", return_value=430), patch.object(owner.os, "_exit") as terminate, patch.object(owner, "_pause"), patch.object(owner, "_role_event", side_effect=observe), patch.object(child, "poll_wait", side_effect=poll), patch.object(keeper, "move_out", side_effect=AssertionError("unexpected fake group move")) as move, patch.object(keeper, "fallback_group", side_effect=AssertionError("unexpected fake fallback")) as fallback:
                self.assertIsNone(owner._wait_child(context, child, context.run, pump, "validator_reaped", phase="WORK"))
                first, fixed = context.primary, context.failure_limit
                self.assertIsNotNone(first)
                self.assertTrue(context.cleanup_unknown)
                if error is not None:
                    self.assertIs(first, error)
                else:
                    self.assertEqual(first.args, (owner.CLEANUP_ERROR,))
                keeper.work = Mock(side_effect=first)
                # Real cleanup skips UNKNOWN/known receipts, vetoes ambiguous
                # publication, and may reap POLLABLE without clearing UNKNOWN.
                self.assertEqual(keeper.run(), owner.HELPER_UNKNOWN)
                terminate.assert_not_called()
            move.assert_not_called()
            fallback.assert_not_called()
            self.assertIs(context.primary, first)
            self.assertEqual((fixed, context.failure_limit), (context.hard, context.hard))
            self.assertTrue(context.cleanup_unknown)
            self.assertFalse(context.resources_confirmed())
            self.assertIs(context.child_acquisition.child, child)
            self.assertEqual(child.polls, 2 if fault == "pump" else 1)
            self.assertTrue(child.numeric_retired)
            self.assertFalse(any(type(item) is ValidationError and item.args == (owner.TIMEOUT,)
                                 for item in (context.primary, *context.secondary)))
            if fault in ("observer", "pump"):
                self.assertIs(child.receipt, receipt)
                self.assertEqual(keeper.channel.offers[-1]["validator"], owner._receipt_record(receipt))
            else:
                self.assertIsNone(child.receipt)
                self.assertEqual(keeper.channel.offers[-1]["validator"], {"state": "unknown"})
            if fault == "poll_interrupt":
                self.assertIs(context.interruption, error)
            self.assertNotIn("STATUS", {frame["type"] for frame in keeper.channel.offers})
            self.assertTrue(keeper.channel.writer_closed)

    def test_unknown_custody_and_cleanup_cutoffs_veto_work_and_cleanup_polls(self):
        faults = ("UNKNOWN", "WAIT_IN_FLIGHT", "CONSUMED", "REAPED", "acquisition_unknown",
                  "acquisition_unsettled", "hard_cutoff", "cancel_cutoff", "failure_grace")
        for phase, single_turn in (("WORK", False), ("CLEANUP", False), ("CLEANUP", True)):
            for fault in faults + (("explicit_cutoff",) if phase == "CLEANUP" else ()):
                context, receipt = _context("keeper"), _receipt(pid=432)
                child = _Child((receipt,), pid=432)
                context.child_acquisition.child = child
                context.child_acquisition.attempted = True
                now = [owner.NANOSECOND]
                pump = Mock(side_effect=AssertionError("unknown custody must not pump"))
                with self.subTest(phase=phase, single_turn=single_turn, fault=fault), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(owner, "_pause") as pause, patch.object(owner, "_role_event") as event:
                    if fault in ("UNKNOWN", "WAIT_IN_FLIGHT", "CONSUMED", "REAPED"):
                        child.wait_state = fault  # REAPED without its receipt is ambiguous too.
                    elif fault == "acquisition_unknown":
                        context.child_acquisition.cleanup_unknown = True
                    elif fault == "acquisition_unsettled":
                        context.child_acquisition.settled = False
                    elif fault == "hard_cutoff":
                        now[0] = context.hard
                    elif fault == "explicit_cutoff":
                        now[0] = context.run  # CLEANUP never borrows later hard grace.
                    elif fault == "cancel_cutoff":
                        context.cancel_frame({"v": 1, "type": "CANCEL", "reason_code": "deadline",
                                              "cleanup_deadline_ns": now[0]})
                    else:
                        context.record(ValidationError(owner.ERROR), "cancelled")
                        now[0] = context.failure_limit
                    first = context.primary
                    cutoff = context.run if phase == "WORK" or fault == "explicit_cutoff" else context.hard
                    self.assertIsNone(owner._wait_child(context, child, cutoff, pump, "validator_reaped", phase=phase, single_turn=single_turn))
                    if first is not None:
                        self.assertIs(context.primary, first)
                    first, fixed = context.primary, context.failure_limit
                    self.assertTrue(context.cleanup_unknown)
                    now[0] += owner.NANOSECOND
                    self.assertIsNone(owner._wait_child(context, child, cutoff, pump, "validator_reaped", phase=phase, single_turn=single_turn))
                    self.assertIs(context.primary, first)
                    self.assertEqual(context.failure_limit, fixed)
                    pause.assert_not_called()
                    event.assert_not_called()
                self.assertTrue(context.cleanup_unknown)
                self.assertIs(context.child_acquisition.child, child)
                self.assertEqual(child.polls, 0)
                self.assertTrue(child.numeric_retired)
                self.assertIsNone(child.receipt)
                self.assertEqual(child.results, [receipt])
                pump.assert_not_called()

        # The new scheduling mode is private keeper cleanup, not an alternate
        # WORK wait or a truthy input which can silently change caller behavior.
        invalid = (("outer", "CLEANUP", True), ("custodian", "CLEANUP", True),
                   ("keeper", "WORK", True), ("keeper", "invalid", True),
                   *(("keeper", "CLEANUP", value) for value in (0, 1, None, "true", {})))
        for role, phase, single_turn in invalid:
            context, receipt = _context(role), _receipt(pid=432)
            child = _Child((receipt,), pid=432)
            pump = Mock(side_effect=AssertionError("invalid wait mode must not pump"))
            with self.subTest(role=role, phase=phase, single_turn=single_turn), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner, "_pause") as pause, patch.object(owner, "_role_event") as event:
                self.assertIsNone(owner._wait_child(context, child, context.hard, pump, "validator_reaped", phase=phase, single_turn=single_turn))
                self.assertEqual(child.polls, 0)
                self.assertFalse(child.numeric_retired)
                self.assertEqual(child.results, [receipt])
                self.assertTrue(context.cleanup_unknown)
                self.assertEqual(context.primary.args, (owner.CLEANUP_ERROR,))
                pump.assert_not_called()
                pause.assert_not_called()
                event.assert_not_called()


class ProfileOwnerHandshakeTests(unittest.TestCase):
    def test_outer_grants_and_commit_require_full_writes_not_enqueue_flags(self):
        context = _context()
        outer = owner._Outer(context, Path("/private/profile"), owner._Deadlines(10, 10, 10, 13, 13))
        outer.child = _Child(pid=430)
        outer.channel = _Channel(context)
        outer.channel.eof = False
        outer.hello = {"v": 1, "type": "HELLO", "pid": 430, "ppid": 429, "sid": 430, "pgid": 430, "fd_map_version": 1}
        outer.channel.encoder.seen.update(("CONFIG", "ADMIT", "RUN", "COMMIT"))
        outer.channel.write_attempted.update(("ADMIT", "RUN", "COMMIT"))
        reserved = {"v": 1, "type": "RESERVED", "keeper_pid": 431, "group_id": 431, "session_id": 430}
        ready = {"v": 1, "type": "READY", "validator_pid": 432, "group_id": 431, "keeper_pgid": 430}
        status = {"v": 1, "type": "STATUS", "validator_pid": 432, "status_kind": "exit", "status_code": 0}
        final = {"v": 1, "type": "FINAL", "outcome": "ok", "cleanup": "confirmed",
                 "keeper": {"state": "reaped", "pid": 431, "status_kind": "exit", "status_code": 0},
                 "validator": owner._status_record(status), "group": {"state": "retired", "id": 431, "absent": True}}
        with patch.object(owner.os, "getpid", return_value=429), patch.object(owner.time, "monotonic_ns", return_value=1):
            for grant, frame, attribute in (("ADMIT", reserved, "reserved"), ("RUN", ready, "ready")):
                outer.channel.frames = [frame]
                with self.assertRaises(ValidationError):
                    outer.process_frames()
                self.assertIsNone(getattr(outer, attribute))
                outer.channel.sent.add(grant)  # Explicit inert positive-write model.
                outer.channel.frames = [frame]
                outer.process_frames()
                self.assertEqual(getattr(outer, attribute), frame)
            outer.channel.frames = [status]
            outer.process_frames()
            outer.content, outer.payload_eof, outer.commit_requested = b"modeled content", True, True
            outer.channel.frames = [_quiescing()]
            outer.process_frames()
            self.assertTrue(outer.control_retiring)
            outer.channel.frames = [final]
            with self.assertRaises(ValidationError):
                outer.process_frames()
            self.assertFalse(outer.committed)
            self.assertIsNone(outer.final)
            # A separate model has its full COMMIT before Q; never manufacture
            # a late successful grant on the already-retired writer above.
            accepted_context = _context()
            accepted = owner._Outer(accepted_context, Path("/private/profile"), owner._Deadlines(10, 10, 10, 13, 13))
            accepted.child, accepted.channel = _Child(pid=430), _Channel(accepted_context)
            accepted.channel.eof = False
            accepted.channel.sent.update(("ADMIT", "RUN", "COMMIT"))
            accepted.channel.write_attempted.update(("ADMIT", "RUN", "COMMIT"))
            accepted.hello, accepted.reserved, accepted.ready, accepted.status = outer.hello, reserved, ready, status
            accepted.content, accepted.payload_eof, accepted.commit_requested = b"modeled content", True, True
            accepted.channel.frames = [_quiescing(), final]
            accepted.process_frames()
        self.assertTrue(accepted.committed)
        self.assertEqual(accepted.final, final)

        # Retirement preserves an existing CANCEL's exact offset/deadline (and
        # nonauthorizing CONFIG bytes), including genuine modeled would-block.
        for pending in ("none", "new_cancel", "queued", "partial", "sent", "config_prefix"):
            context = _context()
            limits = owner._Deadlines(context.run, context.run, context.run, context.hard, context.hard)
            outer = owner._Outer(context, Path("/private/profile"), limits)
            outer.child, outer.channel = _Child(pid=430), _wire_channel(context, "c_to_o", "o_to_c")
            channel = outer.channel
            context.io.leases.extend((channel.reader, channel.writer))
            first = None if pending == "none" else ValidationError(owner.ERROR)
            with self.subTest(retiring_pending=pending), patch.object(owner.time, "monotonic_ns", return_value=owner.NANOSECOND):
                if pending == "config_prefix":
                    channel.send_frame(_configuration())
                    with patch.object(owner.os, "write", return_value=2):
                        channel.flush()
                if first is not None:
                    context.record(first, "io")
                    if pending != "new_cancel":
                        channel.send("CANCEL", reason_code=context.reason, cleanup_deadline_ns=context.failure_limit)
                        if pending in ("partial", "sent"):
                            with patch.object(owner.os, "write", side_effect=lambda _fd, content: 2 if pending == "partial" else len(content)):
                                channel.flush()
                before = [(frame, bytes(content)) for frame, content in channel.pending]
                original_limits = dict(channel.write_limits)
                channel.frames = channel.decoder.feed(owner.Protocol.encode(_quiescing()))
                with patch.object(owner.os, "write", side_effect=BlockingIOError):
                    outer.process_frames()
                self.assertTrue(outer.control_retiring and context.launch_closed)
                self.assertIs(context.primary, first)
                self.assertIsNone(outer.final)
                self.assertIsNone(outer.receipt)
                self.assertFalse(outer.confirmed or outer.committed)
                if before:
                    self.assertEqual([(frame, bytes(content)) for frame, content in channel.pending], before)
                    self.assertEqual(channel.write_limits, original_limits)
                    self.assertFalse(channel.writer_closed)
                elif pending == "new_cancel":
                    self.assertEqual(channel.pending[0][0], {"v": 1, "type": "CANCEL", "reason_code": "io",
                                                           "cleanup_deadline_ns": context.failure_limit})
                    self.assertFalse(channel.writer_closed)
                with patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)):
                    for _ in range(3):
                        outer.process_frames()  # Empty receive turn still progresses retirement.
                self.assertFalse(channel.pending or channel.write_failed or channel.write_in_flight)
                self.assertTrue(channel.writer_closed)
                self.assertEqual(channel.writer.close_calls, 1)
                self.assertIn(id(channel.writer), context.closed)
                self.assertEqual("CANCEL" in channel.sent, first is not None)
                self.assertFalse(context.cleanup_unknown)
                context.record(ValidationError(owner.ERROR), "cancelled")
                with patch.object(owner.os, "write") as syscall:
                    outer.process_frames()
                syscall.assert_not_called()  # Late failure cannot reopen a retired route.
                self.assertEqual(channel.writer.close_calls, 1)
                self.assertEqual("CANCEL" in channel.sent, first is not None)

        for grant, prefix in (("ADMIT", ()), ("RUN", ("ADMIT",)), ("COMMIT", ("ADMIT", "RUN"))):
            for partial in (False, True):
                context = _context()
                outer = owner._Outer(context, Path("/private/profile"), owner._Deadlines(context.run, context.run, context.run, context.hard, context.hard))
                outer.child, outer.channel = _Child(pid=430), _wire_channel(context, "c_to_o", "o_to_c")
                channel = outer.channel
                frames = [_configuration(), *({"v": 1, "type": kind} for kind in prefix)]
                with self.subTest(retiring_grant=grant, partial=partial), patch.object(owner.time, "monotonic_ns", return_value=1):
                    with patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)):
                        for frame in frames:
                            channel.send_frame(frame)
                            channel.flush()
                    channel.send(grant)
                    if partial:
                        with patch.object(owner.os, "write", return_value=2):
                            channel.flush()
                    first = ValidationError(owner.ERROR)
                    context.record(first, "io")
                    channel.send("CANCEL", reason_code=context.reason, cleanup_deadline_ns=context.failure_limit)
                    channel.frames = channel.decoder.feed(owner.Protocol.encode(_quiescing()))
                    with patch.object(owner.os, "write") as syscall, self.assertRaises(ValidationError) as raised:
                        outer.process_frames()
                    self.assertIs(raised.exception, first)
                    syscall.assert_not_called()
                    self.assertTrue(outer.control_retiring)
                    self.assertEqual(grant in channel.write_attempted, partial)
                    self.assertNotIn(grant, channel.sent)
                    self.assertNotIn("CANCEL", channel.write_attempted)
                    self.assertNotIn("CANCEL", channel.sent)
                    self.assertEqual(channel.pending, [])
                    self.assertEqual(channel.writer.close_calls, 1)
                    decoder = owner.Decoder("o_to_c")
                    decoder.feed(b"".join(owner.Protocol.encode(frame) for frame in frames)
                                 + (owner.Protocol.encode({"v": 1, "type": grant})[:2] if partial else b""))
                    if partial:
                        with self.assertRaises(ValidationError):
                            decoder.eof()  # Discarded trailing CANCEL cannot repair a prefix.
                        self.assertTrue(decoder.failed)
                    else:
                        decoder.eof()  # No invented consumed prefix for a wholly unsent grant.
                        self.assertTrue(decoder.ended)

        # Exercise every actual work enqueue site without filesystem/process IO.
        # Q arrives one pump before FINAL, so simply failing at send()/missing
        # finality cannot accidentally pass the "no later grant" control.
        from mobile_release import ios_profiles

        hello = {"v": 1, "type": "HELLO", "pid": 430, "ppid": 429, "sid": 430, "pgid": 430, "fd_map_version": 1}
        for stage in ("ADMIT", "RUN", "COMMIT"):
            context = _context()
            outer = owner._Outer(context, Path("/private/profile"), owner._Deadlines(context.run, context.run, context.run, context.hard, context.hard))
            channel = _wire_channel(context, "c_to_o", "o_to_c")
            null_read, null_write, control_read, status_write, payload_read, payload_write = (_Lease(401 + index) for index in range(6))
            context.io.leases.extend((null_read, null_write, control_read, channel.writer, channel.reader, status_write, payload_read, payload_write))
            context.io.open_null = Mock(side_effect=(null_read, null_write))
            context.io.pipe = Mock(side_effect=((control_read, channel.writer), (channel.reader, status_write), (payload_read, payload_write)))
            terminal = _failed()
            groups = [[hello]]
            if stage != "ADMIT":
                groups.append([reserved])
                terminal = {**terminal, "keeper": {"state": "reaped", "pid": 431, "status_kind": "exit", "status_code": 2},
                            "group": {"state": "retired", "id": 431, "absent": True}}
            if stage == "COMMIT":
                groups.append([ready, status])
                terminal["validator"] = owner._status_record(status)
            groups[-1].append(_quiescing())
            groups.append([terminal])
            chunks = [b"".join(owner.Protocol.encode(frame) for frame in group) for group in groups]
            outer.read_payload = Mock(side_effect=lambda: setattr(outer, "payload_eof", True))
            with self.subTest(before_grant=stage), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getpid", return_value=429), patch.object(owner.os, "getsid", return_value=429), patch.object(owner.os, "set_blocking"), patch.object(Path, "lstat", return_value=types.SimpleNamespace(st_mode=0o40700)), patch.object(owner, "_Channel", return_value=channel), patch.object(owner, "_spawn", return_value=_Child(pid=430)), patch.object(owner, "helper_argv", return_value=("/fake/helper",)), patch.object(owner, "_configuration", return_value=_configuration()), patch.object(ios_profiles, "profile_environment", return_value={"LANG": "C"}), patch.object(ios_profiles, "completed_content", return_value=b"modeled content") as parse, patch.object(owner.os, "read", side_effect=chunks), patch.object(owner.os, "write", side_effect=lambda _fd, content: len(content)), patch.object(owner, "_pause"), patch.object(channel, "send", wraps=channel.send) as send:
                with self.assertRaises(ValidationError) as raised:
                    outer.work()
                self.assertEqual(raised.exception.args, (ios_profiles.AUTHENTICATION_ERROR,))
                self.assertEqual(outer.final, terminal)
                self.assertTrue(outer.control_retiring and channel.writer_closed)
                self.assertIsNone(context.primary)
                sent_kinds = [call.args[0] for call in send.call_args_list]
                self.assertEqual(sent_kinds, ["CONFIG"] + ([] if stage == "ADMIT" else ["ADMIT"] if stage == "RUN" else ["ADMIT", "RUN"]))
                parse.assert_not_called()
                self.assertFalse(outer.commit_requested)
                self.assertEqual(channel.writer.close_calls, 1)
                context.close_all()  # Only inert leases were ever acquired.

    def test_helpers_require_actual_hello_and_reserved_before_accepting_admission(self):
        context = _context("custodian", parent_pid=429)
        custodian = _custodian(context)
        custodian.outer.eof = False
        custodian.config = _configuration()
        custodian.reserved = True
        with patch.object(owner.os, "getppid", return_value=429), patch.object(owner.time, "monotonic_ns", return_value=1):
            for kind, needed, attribute in (("ADMIT", "HELLO", "admitted"), ("RUN", "RESERVED", "run_granted")):
                custodian.outer.encoder.seen.add(needed)
                custodian.outer.frames = [{"v": 1, "type": kind}]
                with self.assertRaises(ValidationError):
                    custodian.pump_outer()
                self.assertFalse(getattr(custodian, attribute))
                custodian.outer.sent.add(needed)
                custodian.outer.frames = [{"v": 1, "type": kind}]
                custodian.pump_outer()
                self.assertTrue(getattr(custodian, attribute))
        context = _context("keeper", parent_pid=430)
        keeper = _keeper(context)
        keeper.config = _configuration("keeper")
        keeper.channel.eof = False
        keeper.channel.encoder.seen.add("HELLO")
        keeper.channel.frames = [{"v": 1, "type": "RUN"}]
        with patch.object(owner.os, "getppid", return_value=430), patch.object(owner.time, "monotonic_ns", return_value=1):
            with self.assertRaises(ValidationError):
                keeper.pump()
            self.assertFalse(keeper.run_granted)
            keeper.channel.sent.add("HELLO")
            keeper.channel.frames = [{"v": 1, "type": "RUN"}]
            keeper.pump()
        self.assertTrue(keeper.run_granted)

    def test_no_grant_and_disjoint_role_identities_constrain_outer_terminal_records(self):
        base = {**_failed(), "keeper": {"state": "reaped", "pid": 431, "status_kind": "exit", "status_code": 2},
                "validator": {"state": "reaped", "pid": 432, "status_kind": "exit", "status_code": 0},
                "group": {"state": "retired", "id": 431, "absent": True}}
        cases = ((set(), base), ({"ADMIT"}, base),
                 ({"ADMIT", "RUN"}, {**base, "keeper": {**base["keeper"], "pid": 429}}),
                 ({"ADMIT", "RUN"}, {**base, "keeper": {**base["keeper"], "pid": 430}}),
                 ({"ADMIT", "RUN"}, {**base, "validator": {**base["validator"], "pid": 429}}),
                 ({"ADMIT", "RUN"}, {**base, "validator": {**base["validator"], "pid": 430}}),
                 ({"ADMIT", "RUN"}, {**base, "validator": {**base["validator"], "pid": 431}}))
        with patch.object(owner.os, "getpid", return_value=429), patch.object(owner.time, "monotonic_ns", return_value=1):
            for attempted, frame in cases:
                context = _context()
                outer = owner._Outer(context, Path("/private/profile"), owner._Deadlines(10, 10, 10, 13, 13))
                outer.child, outer.channel = _Child(pid=430), _Channel(context)
                outer.channel.eof = False
                outer.channel.write_attempted = attempted
                outer.channel.frames = [_quiescing()]
                outer.process_frames()
                self.assertTrue(outer.control_retiring)
                self.assertIsNone(context.primary)
                outer.channel.frames = [frame]
                with self.subTest(attempted=attempted, keeper=frame["keeper"], validator=frame["validator"]), self.assertRaises(ValidationError):
                    outer.process_frames()
                self.assertIsNone(outer.final)


class ProfileOwnerHelperTerminalTests(unittest.TestCase):
    def test_custodian_validates_released_before_publication_and_preserves_moved_evidence(self):
        actual = {"state": "reaped", "pid": 432, "status_kind": "exit", "status_code": 0}
        for candidate, known_status, attempted in (({"state": "not_attempted"}, None, {"RUN"}),
                                                    ({**actual, "pid": 433}, None, {"RUN"}),
                                                    ({**actual, "status_code": 1}, actual, {"RUN"}),
                                                    (actual, None, set())):
            context = _context("custodian", parent_pid=429)
            custodian = _custodian(context)
            custodian.keeper = _Child(pid=431)
            custodian.group = owner._GroupReservation(context, custodian.keeper)
            custodian.moved = {"validator_pid": 432, "group_id": 431, "keeper_pgid": 430}
            custodian.validator = known_status
            custodian.keeper_channel = _Channel(context)
            custodian.keeper_channel.eof = False
            custodian.keeper_channel.sent.add("RUN")
            custodian.keeper_channel.write_attempted = attempted
            custodian.keeper_channel.frames = [{"v": 1, "type": "RELEASED", "validator": candidate}]
            with self.subTest(candidate=candidate, known_status=known_status, attempted=attempted), patch.object(owner.os, "getpid", return_value=430), self.assertRaises(ValidationError):
                custodian.pump_keeper()
            self.assertIsNone(custodian.released)
            self.assertEqual(custodian.validator, known_status)
            self.assertEqual(custodian.moved["validator_pid"], 432)
            self.assertFalse(custodian.ready)  # READY/STATUS never reached O.

    def test_custodian_status_discriminator_requires_released_eof_absence_and_requested_zero(self):
        # Every receipt/group/close is an explicit inert model. This table is
        # the offer/code logic only, never real helper settlement evidence.
        cases = (("exit", 0, True, True, True, True, True),
                 ("exit", 2, True, True, True, True, True),
                 ("exit", 2, True, True, True, False, True),
                 ("exit", 0, True, True, True, False, False),
                 ("exit", 1, True, True, True, True, False),
                 ("exit", 3, True, True, True, True, False),
                 ("signal", 9, True, True, True, True, False),
                 ("exit", 0, False, True, True, True, False),
                 ("exit", 0, True, False, True, True, False),
                 ("exit", 0, True, True, False, True, False))
        validator = {"state": "reaped", "pid": 432, "status_kind": "exit", "status_code": 0}
        for kind, code, released, eof, absent, requested, expected in cases:
            with self.subTest(case=(kind, code, released, eof, absent, requested)):
                context = _context("custodian", parent_pid=429)
                custodian = _custodian(context)
                retirement = _model_custodian_input_retirement(custodian)
                custodian.keeper = _settled_child(context, kind=kind, code=code)
                custodian.keeper_receipt = custodian.keeper.receipt
                custodian.group = owner._GroupReservation(context, custodian.keeper)
                custodian.group.retire(absent=absent)
                custodian.validator = validator
                custodian.released = validator if released else None
                custodian.released_after_request = requested
                custodian.keeper_channel = _Channel(context)
                custodian.keeper_channel.eof = eof
                context.io.leases.extend((custodian.keeper_channel.reader, custodian.keeper_channel.writer))
                custodian.work = Mock(side_effect=ValidationError(owner.ERROR))

                def cleanup():
                    context.retire_launch()
                    custodian.keeper_channel.close_reader()
                    custodian.keeper_channel.close_writer()

                custodian.cleanup_descendants = cleanup
                custodian.write_payload = Mock()
                with patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=429), patch.object(owner, "_pause"):
                    result = custodian.run()
                offered = custodian.outer.offers[-1]
                owner.Protocol.encode(offered)
                self.assertEqual(offered["outcome"], "failed")
                self.assertEqual(offered["cleanup"], "confirmed" if expected else "unknown")
                self.assertEqual(offered["validator"], validator)  # Never erase a known real-record model.
                self.assertEqual(offered["keeper"], owner._receipt_record(custodian.keeper.receipt))
                self.assertEqual(result, owner.HELPER_FAILED if expected else owner.HELPER_UNKNOWN)
                custodian.write_payload.assert_not_called()
                self.assertEqual(retirement, ["QUIESCING", "control_eof", "reader_closed", "FINAL"])

        # Real protocol/channel code with inert syscall-return models. A sent
        # set member or eof flag alone cannot prove retirement. All waits share
        # the original failure endpoint; the missing-EOF clock advances.
        faults = (None, "early_eof", "missing_eof", "eof_flag_only", "partial_frame", "read_error",
                  "unsent", "partial_write", "write_tail", "reader_close", "late_eof", "late_close", "parent_lost")
        for fault in faults:
            context = _context("custodian", parent_pid=429)
            custodian = _custodian(context)
            channel = custodian.outer = _wire_channel(context, "o_to_c", "c_to_o")
            context.io.leases.extend((channel.reader, channel.writer))
            now = [owner.NANOSECOND]
            first, later = ValidationError(owner.ERROR), OSError("PRIVATE_INPUT_RETIREMENT")
            reads, writes, events = [], [], []
            original_close = channel.reader.close

            def write(_fd, content):
                self.assertTrue(custodian.outer_retiring)
                self.assertFalse(channel.reader_closed)
                writes.append(bytes(content))
                if fault == "unsent" or fault == "partial_write" and len(writes) > 1:
                    raise BlockingIOError
                if fault == "partial_write":
                    return 2
                if fault == "eof_flag_only":
                    channel.eof = True  # Deliberately missing decoder completion.
                return len(content)

            def read(_fd, _limit):
                reads.append(None)
                if "QUIESCING" not in channel.sent or fault == "missing_eof":
                    raise BlockingIOError
                if fault == "read_error":
                    raise later
                if fault == "partial_frame" and len(reads) == 1:
                    return b"\0\0"
                if fault == "late_eof":
                    now[0] = fixed
                return b""

            def observe(_role, event, **evidence):
                events.append(event)
                if fault == "write_tail" and event == "frame_sent" and evidence["frame"]["type"] == "QUIESCING":
                    raise later  # Actual full return, lost observation tail.

            def close():
                original_close()
                if fault == "late_close":
                    now[0] = fixed

            def pause(*_args):
                now[0] = min(fixed, now[0] + owner.NANOSECOND)

            with self.subTest(input_retirement=fault), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(owner.os, "getppid", return_value=999 if fault == "parent_lost" else 429), patch.object(owner.os, "write", side_effect=write), patch.object(owner.os, "read", side_effect=read), patch.object(owner, "_role_event", side_effect=observe), patch.object(owner, "_pause", side_effect=pause), patch.object(channel.reader, "close", side_effect=close):
                if fault == "early_eof":
                    cancel = {"v": 1, "type": "CANCEL", "reason_code": "cancelled", "cleanup_deadline_ns": 4 * owner.NANOSECOND}
                    with patch.object(owner.os, "read", return_value=owner.Protocol.encode(cancel)):
                        custodian.pump_outer()
                    first = context.primary
                    self.assertEqual(context.reason, "cancelled")
                else:
                    context.record(first, "io")
                fixed = context.failure_limit
                if fault == "early_eof":
                    with patch.object(owner.os, "read", return_value=b""):
                        custodian.pump_outer()
                    self.assertTrue(channel.eof and channel.decoder.ended)
                    self.assertTrue(custodian.outer_eof_seen)
                    self.assertGreater(len(context.secondary), 0)
                    self.assertIs(context.primary, first)
                if fault == "reader_close":
                    channel.reader.error = later
                result = custodian.retire_outer_control()
                expected = fault in (None, "early_eof")
                self.assertEqual(result, expected)
                self.assertIs(context.primary, first)
                self.assertEqual((context.failure_limit, context.cleanup_limit), (fixed, fixed))
                self.assertEqual(context.cleanup_unknown, not expected)
                self.assertTrue(custodian.outer_retiring)
                self.assertTrue(channel.reader_closed)
                self.assertEqual(channel.reader.close_calls, 1)
                self.assertLessEqual(len(reads), 4)
                self.assertLessEqual(len(writes), 4)
                self.assertIsNone(context._helper_offer)  # Input proof never offers FINAL.
                if expected:
                    self.assertTrue(channel.eof and channel.decoder.ended and not channel.decoder.failed)
                    self.assertEqual(channel.sent, {"QUIESCING"})
                    self.assertFalse(channel.pending or channel.write_failed or channel.write_in_flight)
                    self.assertEqual(events, ["control_eof", "frame_sent", "descriptor_closed"] if fault == "early_eof"
                                     else ["frame_sent", "control_eof", "descriptor_closed"])
                elif fault in ("unsent", "partial_write", "parent_lost"):
                    self.assertNotIn("QUIESCING", channel.sent)
                elif fault == "write_tail":
                    self.assertIn("QUIESCING", channel.sent)
                    self.assertTrue(channel.write_failed and channel.write_in_flight)
                elif fault == "partial_frame":
                    self.assertTrue(channel.eof and channel.decoder.failed)
                    self.assertFalse(channel.decoder.ended)
                if fault in ("missing_eof", "unsent", "partial_write", "late_eof", "late_close"):
                    self.assertEqual(now[0], fixed)

    def test_custodian_zero_only_carries_ok_or_rejected_and_keeper_two_forces_failed(self):
        for keeper_code, validator_code, outcome, expected in ((0, 0, "ok", 0), (0, 7, "rejected", 0), (2, 0, "failed", 2)):
            context = _context("custodian", parent_pid=429)
            custodian = _custodian(context)
            retirement = _model_custodian_input_retirement(custodian)
            custodian.keeper = _settled_child(context, code=keeper_code)
            custodian.keeper_receipt = custodian.keeper.receipt
            custodian.group = owner._GroupReservation(context, custodian.keeper)
            custodian.group.retire(absent=True)
            custodian.validator = {"state": "reaped", "pid": 432, "status_kind": "exit", "status_code": validator_code}
            custodian.released = custodian.validator
            custodian.released_after_request = True
            custodian.ready = True
            custodian.committed = outcome == "ok"
            custodian.keeper_channel = _Channel(context)
            context.io.leases.extend((custodian.keeper_channel.reader, custodian.keeper_channel.writer))

            def cleanup():
                context.retire_launch()
                custodian.keeper_channel.close_reader()
                custodian.keeper_channel.close_writer()
                # Match the real descendant-cleanup tail: unused null/source
                # copies must close BEFORE the payload success resource gate.
                context.close_all(exclude=(custodian.outer.reader, custodian.outer.writer, custodian.payload))

            custodian.work = Mock()
            custodian.cleanup_descendants = cleanup
            custodian.write_payload = Mock()  # Not payload/COMMIT or native evidence.
            with self.subTest(keeper_code=keeper_code, validator_code=validator_code), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=429), patch.object(owner, "_pause"):
                result = custodian.run()
            offered = custodian.outer.offers[-1]
            owner.Protocol.encode(offered)
            self.assertEqual(offered["outcome"], outcome)
            self.assertEqual(offered["cleanup"], "confirmed")
            self.assertEqual(result, expected)
            self.assertEqual(custodian.write_payload.call_count, int(outcome == "ok"))
            self.assertEqual(custodian.descriptors[5].close_calls, 1)
            self.assertEqual(custodian.descriptors[7].close_calls, 1)
            self.assertEqual(custodian.committed, outcome == "ok")
            self.assertEqual(retirement, ["QUIESCING", "control_eof", "reader_closed", "FINAL"])

    def test_keeper_parent_cancel_never_erases_a_local_failure_before_or_after_it(self):
        for order in ("parent_only", "local_first", "local_later", "local_signal"):
            context = _context("keeper", parent_pid=430)
            keeper = _keeper(context)
            keeper.validator = _settled_child(context, pid=432)
            keeper.receipt = keeper.validator.receipt
            keeper.moved = keeper.released = keeper.group_retired = keeper.group_absent = True
            keeper.channel.eof = False
            first = ValidationError(owner.ERROR)

            def work():
                if order == "local_first":
                    context.record(first)
                keeper.channel.frames = [{"v": 1, "type": "CANCEL", "reason_code": "cancelled", "cleanup_deadline_ns": 3_000_000_000}]
                keeper.pump()
                if order == "local_later":
                    context.record(first)
                elif order == "local_signal":
                    context.signal_epoch += 1
                    context.cancelled = True

            keeper.work = work
            with self.subTest(order=order), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=430), patch.object(owner, "_pause"):
                result = keeper.run()
            self.assertEqual(result, owner.HELPER_SETTLED if order == "parent_only" else owner.HELPER_FAILED)
            self.assertIn("RELEASED", keeper.channel.sent)
            self.assertTrue(keeper.channel.writer_closed)
            self.assertFalse(context.cleanup_unknown)
            if order == "local_first":
                self.assertIs(context.primary, first)
                self.assertIsNot(context.primary, keeper.parent_cancellation)
            else:
                self.assertIs(context.primary, keeper.parent_cancellation)
            if order == "local_later":
                self.assertIn(first, context.secondary)

    def test_post_offer_helper_writer_close_failure_overrides_zero_and_two(self):
        for role in ("custodian", "keeper"):
            context = _context(role, parent_pid=429 if role == "custodian" else 430)
            first = OSError("PRIVATE_STATUS_TAIL_CLOSE")
            if role == "custodian":
                helper = _custodian(context)
                retirement = _model_custodian_input_retirement(helper)
                helper.work = Mock(side_effect=ValidationError(owner.ERROR))
                helper.cleanup_descendants = Mock(side_effect=context.retire_launch)
                channel = helper.outer
                intended = owner.HELPER_FAILED  # Proved no K attempt in this model.
            else:
                helper = _keeper(context)
                helper.validator = _settled_child(context, pid=432)
                helper.receipt = helper.validator.receipt
                helper.moved = helper.released = helper.group_retired = helper.group_absent = True
                helper.work = Mock()
                channel = helper.channel
                intended = owner.HELPER_SETTLED
            channel.eof = False
            channel.writer.error = first
            with self.subTest(role=role, intended=intended), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=context.parent_pid), patch.object(owner, "_pause"):
                result = helper.run()
            self.assertEqual(result, owner.HELPER_UNKNOWN)
            self.assertTrue(context.cleanup_unknown)
            self.assertEqual(channel.writer.close_calls, 1)
            self.assertIn("FINAL" if role == "custodian" else "RELEASED", channel.sent)
            if role == "custodian":
                self.assertEqual(retirement, ["QUIESCING", "control_eof", "reader_closed", "FINAL"])
                self.assertEqual(channel.offers[-1]["cleanup"], "confirmed")
                self.assertEqual(channel.offers[-1]["keeper"], {"state": "not_attempted"})
            else:
                self.assertEqual(channel.offers[-1]["validator"], owner._receipt_record(helper.receipt))

    def test_terminal_tail_rechecks_epochs_deadline_parent_and_real_writer_state(self):
        for intended in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            for fault in (None, "error", "signal", "signal_during_clock", "deadline", "parent", "unsent", "unclosed", "write_unknown", "resources_unknown"):
                context = _context("keeper", parent_pid=430)
                channel = _Channel(context)
                channel.sent.add("RELEASED")
                channel.writer_closed = True
                epoch = context.error_epoch, context.signal_epoch
                now, parent = 1, 430
                if fault == "error":
                    with patch.object(owner.time, "monotonic_ns", return_value=1):
                        context.record(KeyboardInterrupt("PRIVATE_AFTER_OFFER"))
                elif fault == "signal":
                    context.signal_epoch += 1
                    context.cancelled = True
                elif fault == "deadline":
                    now = context.run
                elif fault == "parent":
                    parent = 999
                elif fault == "unsent":
                    channel.sent.clear()
                elif fault == "unclosed":
                    channel.writer_closed = False
                elif fault == "write_unknown":
                    channel.write_failed = True
                elif fault == "resources_unknown":
                    context.child_acquisition.cleanup_unknown = True

                def clock():
                    if fault == "signal_during_clock":
                        context.signal_epoch += 1
                        context.cancelled = True
                    return now

                with self.subTest(intended=intended, fault=fault), patch.object(owner.time, "monotonic_ns", side_effect=clock), patch.object(owner.os, "getppid", return_value=parent):
                    actual = context.terminal_code(intended, epoch, context.run, channel, "RELEASED")
                self.assertEqual(actual, intended if fault is None else owner.HELPER_UNKNOWN)


class ProfileOwnerHelperHandoffTests(unittest.TestCase):
    def _offer(self, intended):
        # Inert offer/close models for the predicate, NOT real helper settlement.
        context = _context("keeper", parent_pid=430)
        channel = _Channel(context)
        context.io.leases.extend((channel.reader, channel.writer))
        epoch = context.error_epoch, context.signal_epoch
        offer = context.offer_terminal(intended, epoch, context.run, channel, "RELEASED")
        channel.sent.add("RELEASED")
        channel.close_reader()
        channel.close_writer()
        return context, channel, offer

    def test_handoff_preserves_original_offer_and_accepts_only_matching_settled_codes(self):
        for intended in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            context, _channel, offer = self._offer(intended)
            with self.subTest(intended=intended), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=430), patch.object(owner.os, "_exit") as terminate, patch.object(owner.signal, "signal") as install:
                saved = context.terminal_code(*offer)
                self.assertEqual(saved, intended)
                self.assertFalse(context._helper_terminal_armed)
                with patch.object(context, "terminal_code", wraps=context.terminal_code) as recheck:
                    self.assertEqual(context.helper_handoff(saved), intended)
                    recheck.assert_called_once_with(*offer)
                self.assertTrue(context._helper_terminal_armed)
                self.assertIs(context._helper_offer, offer)
                with self.assertRaises(ValidationError):
                    context.offer_terminal(intended, (99, 99), context.hard, _channel, "RELEASED")
                self.assertIs(context._helper_offer, offer)
                terminate.assert_not_called()
                install.assert_not_called()  # No disposition swap in the handoff.

    def test_unknown_invalid_mismatched_and_missing_offers_never_arm_or_upgrade(self):
        for intended in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            for saved in (owner.HELPER_UNKNOWN, 3, True, False, None, str(intended), 2 if intended == 0 else 0):
                context, _channel, offer = self._offer(intended)
                with self.subTest(intended=intended, saved=saved), patch.object(context, "terminal_code") as recheck, patch.object(owner.os, "_exit") as terminate:
                    self.assertEqual(context.helper_handoff(saved), owner.HELPER_UNKNOWN)
                    self.assertFalse(context._helper_terminal_armed)
                    self.assertIs(context._helper_offer, offer)
                    recheck.assert_not_called()
                    terminate.assert_not_called()
            context = _context("keeper", parent_pid=430)
            with patch.object(context, "terminal_code") as recheck, patch.object(owner.os, "_exit") as terminate:
                self.assertEqual(context.helper_handoff(intended), owner.HELPER_UNKNOWN)
                self.assertFalse(context._helper_terminal_armed)
                recheck.assert_not_called()
                terminate.assert_not_called()

    def test_prearm_signal_after_saved_code_invalidates_the_original_offer_without_exiting(self):
        for intended in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            for signum in (signal.SIGINT, signal.SIGTERM):
                context, _channel, offer = self._offer(intended)
                with self.subTest(intended=intended, signum=signum), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=430), patch.object(owner.os, "_exit") as terminate:
                    saved = context.terminal_code(*offer)
                    self.assertEqual(saved, intended)
                    context.helper_signal(signum, None)  # Direct inert callback invocation only.
                    self.assertFalse(context._helper_terminal_armed)
                    self.assertEqual(context.signal_epoch, offer[1][1] + 1)
                    self.assertTrue(context.cancelled)
                    self.assertEqual(context.helper_handoff(saved), owner.HELPER_UNKNOWN)
                    self.assertTrue(context._helper_terminal_armed)
                    self.assertIs(context._helper_offer, offer)
                    self.assertEqual(offer[1], (0, 0))  # Never resnapshot the newer latch.
                    terminate.assert_not_called()

    def test_armed_callback_cannot_leave_saved_zero_or_two_during_or_after_handoff(self):
        class ExitEffect(BaseException):
            pass  # Fake nonreturning effect; NEVER execute real os._exit.

        for intended in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            for phase in ("inside_recheck", "after_handoff"):
                for signum in (signal.SIGINT, signal.SIGTERM):
                    context, _channel, offer = self._offer(intended)
                    effect = ExitEffect()
                    with self.subTest(intended=intended, phase=phase, signum=signum), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=430), patch.object(owner.os, "_exit", side_effect=effect) as terminate, patch.object(context, "record") as record, patch.object(context, "close_all") as close, patch.object(context, "retire_launch") as retire:
                        saved = context.terminal_code(*offer)
                        self.assertEqual(saved, intended)
                        if phase == "inside_recheck":
                            original = context.terminal_code

                            def checked(*proof):
                                value = original(*proof)
                                context.helper_signal(signum, None)  # After the final epoch gate.
                                return value

                            with patch.object(context, "terminal_code", side_effect=checked):
                                self.assertEqual(context.helper_handoff(saved), owner.HELPER_UNKNOWN)
                        else:
                            self.assertEqual(context.helper_handoff(saved), intended)
                            with self.assertRaises(ExitEffect) as raised:
                                context.helper_signal(signum, None)  # Saved return already exists.
                            self.assertIs(raised.exception, effect)
                        terminate.assert_called_once_with(owner.HELPER_UNKNOWN)
                        record.assert_not_called()
                        close.assert_not_called()
                        retire.assert_not_called()
                        self.assertTrue(context._helper_terminal_armed)
                        self.assertEqual((context.error_epoch, context.signal_epoch), offer[1])
                        self.assertFalse(context.cancelled)  # The armed callback only exits.

    def test_handoff_rechecks_original_cutoff_parent_transport_and_closed_resources(self):
        for intended in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            for fault in ("error", "deadline", "shortened", "parent", "unsent", "unclosed", "write_failed", "in_flight", "resources", "missing_close"):
                context, channel, offer = self._offer(intended)
                now, parent = [1], [430]
                with self.subTest(intended=intended, fault=fault), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(owner.os, "getppid", side_effect=lambda: parent[0]), patch.object(owner.os, "_exit") as terminate:
                    saved = context.terminal_code(*offer)
                    self.assertEqual(saved, intended)
                    if fault == "error":
                        context.record(ValidationError(owner.ERROR))
                    elif fault == "deadline":
                        now[0] = offer[2]
                    elif fault == "shortened":
                        context.failure_limit = now[0]
                    elif fault == "parent":
                        parent[0] = 999
                    elif fault == "unsent":
                        channel.sent.clear()
                    elif fault == "unclosed":
                        channel.writer_closed = False
                    elif fault == "write_failed":
                        channel.write_failed = True
                    elif fault == "in_flight":
                        channel.write_in_flight = True
                    elif fault == "resources":
                        context.child_acquisition.cleanup_unknown = True
                    else:
                        context.closed.remove(id(channel.reader))
                    self.assertEqual(context.helper_handoff(saved), owner.HELPER_UNKNOWN)
                    self.assertTrue(context._helper_terminal_armed)
                    self.assertIs(context._helper_offer, offer)
                    terminate.assert_not_called()

    def test_final_recheck_exception_is_unknown_without_cleanup_retry_or_exception_exit(self):
        for intended in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            for error in (KeyboardInterrupt("PRIVATE_HANDOFF"), SystemExit(0), BlockingIOError("PRIVATE_HANDOFF")):
                context, _channel, offer = self._offer(intended)
                with self.subTest(intended=intended, error=type(error).__name__), patch.object(owner.os, "_exit") as terminate, patch.object(context, "terminal_code", side_effect=error), patch.object(context, "record") as record, patch.object(context, "close_all") as close, patch.object(context, "retire_launch") as retire:
                    self.assertEqual(context.helper_handoff(intended), owner.HELPER_UNKNOWN)
                    self.assertTrue(context._helper_terminal_armed)
                    self.assertIs(context._helper_offer, offer)
                    terminate.assert_not_called()
                    record.assert_not_called()
                    close.assert_not_called()
                    retire.assert_not_called()

    def test_handoff_proof_and_arm_errors_are_terminal_unknown_without_cleanup(self):
        for intended in (owner.HELPER_SETTLED, owner.HELPER_FAILED):
            for fault in ("proof", "before_arm", "after_arm"):
                error = SystemExit(0)

                class FaultContext(owner._Context):
                    fault_stage = None

                    def __getattribute__(self, name):
                        if name == "_helper_offer" and object.__getattribute__(self, "fault_stage") == "proof":
                            raise error  # Inert lost proof-read model.
                        return object.__getattribute__(self, name)

                    def __setattr__(self, name, value):
                        if name == "_helper_terminal_armed" and value is True:
                            stage = object.__getattribute__(self, "fault_stage")
                            if stage == "before_arm":
                                raise error
                            object.__setattr__(self, name, value)
                            if stage == "after_arm":
                                raise error  # Arm publication happened, return was lost.
                            return
                        object.__setattr__(self, name, value)

                with patch.object(owner, "_Context", FaultContext):
                    context, _channel, offer = self._offer(intended)
                with self.subTest(intended=intended, fault=fault), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=430), patch.object(owner.os, "_exit") as terminate:
                    saved = context.terminal_code(*offer)
                    self.assertEqual(saved, intended)
                    context.fault_stage = fault
                    with patch.object(context, "terminal_code") as recheck, patch.object(context, "record") as record, patch.object(context, "close_all") as close, patch.object(context, "retire_launch") as retire:
                        self.assertEqual(context.helper_handoff(saved), owner.HELPER_UNKNOWN)
                        recheck.assert_not_called()
                        record.assert_not_called()
                        close.assert_not_called()
                        retire.assert_not_called()
                    context.fault_stage = None
                    self.assertIs(context._helper_offer, offer)
                    self.assertEqual(context._helper_terminal_armed, fault == "after_arm")
                    terminate.assert_not_called()

    def test_preoffer_signal_cannot_hide_in_latch_tail_or_a_fresher_decision_epoch(self):
        for role in ("custodian", "keeper"):
            for phase in ("latch_tail", "decision"):
                context = _context(role, parent_pid=429 if role == "custodian" else 430)
                if role == "custodian":
                    helper = _custodian(context)
                    retirement = _model_custodian_input_retirement(helper)
                    helper.keeper = _settled_child(context)
                    helper.keeper_receipt = helper.keeper.receipt
                    helper.group = owner._GroupReservation(context, helper.keeper)
                    helper.group.retire(absent=True)
                    helper.validator = {"state": "reaped", "pid": 432, "status_kind": "exit", "status_code": 7}
                    helper.released, helper.released_after_request, helper.ready = helper.validator, True, True
                    helper.keeper_channel = _Channel(context)
                    context.io.leases.extend((helper.keeper_channel.reader, helper.keeper_channel.writer))

                    def cleanup():
                        context.retire_launch()
                        helper.keeper_channel.close_reader()
                        helper.keeper_channel.close_writer()

                    helper.cleanup_descendants = cleanup
                    helper.write_payload = Mock()
                    channel = helper.outer
                else:
                    helper = _keeper(context)
                    helper.validator = _settled_child(context, pid=432)
                    helper.receipt = helper.validator.receipt
                    helper.moved = helper.released = helper.group_retired = helper.group_absent = True
                    channel = helper.channel
                helper.work = Mock()
                channel.eof = False
                original_observe, original_resources = context.observe_helper_latches, context.resources_confirmed
                stage = {"decision": False, "injected": False}

                def observe():
                    original_observe()
                    if phase == "latch_tail":
                        context.helper_signal(signal.SIGTERM, None)
                        stage["injected"] = True
                    else:
                        stage["decision"] = True

                def resources(**options):
                    if stage["decision"] and not stage["injected"]:
                        context.helper_signal(signal.SIGTERM, None)
                        stage["injected"] = True
                    return original_resources(**options)

                with self.subTest(role=role, phase=phase), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(owner.os, "getppid", return_value=context.parent_pid), patch.object(owner.os, "_exit") as terminate, patch.object(owner, "_pause"), patch.object(context, "observe_helper_latches", side_effect=observe), patch.object(context, "resources_confirmed", side_effect=resources):
                    saved = helper.run()  # Only the existing inert role model; NEVER helper_main.
                    self.assertTrue(stage["injected"])
                    expected = owner.HELPER_FAILED if phase == "latch_tail" else owner.HELPER_UNKNOWN
                    self.assertEqual(saved, expected)
                    self.assertEqual(context.helper_handoff(saved), expected)
                    self.assertEqual(context._helper_terminal_armed, phase == "latch_tail")
                    self.assertEqual(context._helper_offer[1][1], int(phase == "latch_tail"))
                    self.assertEqual(context.signal_epoch, 1)
                    terminate.assert_not_called()
                    if role == "custodian":
                        self.assertEqual(retirement, ["QUIESCING", "control_eof", "reader_closed", "FINAL"])


class ProfileOwnerFinalityTests(unittest.TestCase):
    def setUp(self):
        # These registries contain only fake contexts in this suite. Real native
        # UNKNOWN custody must never be reset by a verifier or application.
        self.registry = patch.object(owner, "_CUSTODY", [])
        self.registry.start()
        self.addCleanup(self.registry.stop)

    def test_unknown_strongly_retains_exact_scratch_and_blocks_process_reuse(self):
        class Scratch:
            pass

        finality, scratch = owner.CaptureFinality(), Scratch()
        reference = weakref.ref(scratch)
        finality.bind_scratch(scratch)
        finality._begin(_context())
        finality._unknown()
        del scratch
        gc.collect()
        self.assertIs(reference(), finality._scratch)
        self.assertFalse(finality.cleanup_allowed)
        self.assertIn(finality, owner._CUSTODY)
        with self.assertRaises(ValidationError):
            finality._finish()
        with self.assertRaises(ValidationError):
            owner.CaptureFinality()._begin(_context())

    def test_exited_active_owner_is_unknown_even_if_explicit_tail_publication_is_lost(self):
        context, finality = _context(), owner.CaptureFinality()
        finality._begin(context)
        context.exited = True
        self.assertEqual(finality.state, "UNKNOWN")
        self.assertFalse(finality.cleanup_allowed)
        with self.assertRaises(ValidationError):
            owner.CaptureFinality()._begin(_context())
        with self.assertRaises(AttributeError):
            finality.state = "FINALIZED"

    def test_actual_close_failure_is_not_retried_or_reported_as_resource_finality(self):
        context = _context()
        first, later = ValidationError(owner.ERROR), KeyboardInterrupt("close cleanup")
        lease = _Lease(error=later)
        context.io.leases.append(lease)
        context.record(first)
        context.close(lease)
        context.close_all()
        self.assertEqual(lease.close_calls, 1)
        self.assertIs(context.primary, first)
        self.assertIs(context.interruption, later)
        self.assertFalse(context.resources_confirmed())

    def test_good_final_offer_requires_real_model_receipt_status_eof_payload_eof_and_closes(self):
        cases = ((0, "ok", True, True, "confirmed", True), (0, "rejected", True, True, "confirmed", True),
                 (2, "failed", True, True, "confirmed", True), (1, "failed", True, True, "confirmed", False),
                 (0, "failed", True, True, "confirmed", False), (2, "ok", True, True, "confirmed", False),
                 (2, "rejected", True, True, "confirmed", False), (1, "ok", True, True, "confirmed", False),
                 (0, "ok", False, True, "confirmed", False), (0, "ok", True, False, "confirmed", False),
                 (0, "ok", True, True, "unknown", False))
        cases = tuple((*case, None) for case in cases) + (
            (0, "ok", True, True, "confirmed", False, "no_notification"),
            (0, "ok", True, True, "confirmed", False, "notification_only"),
            (0, "ok", True, True, "confirmed", False, "writer_close_error"),
            (0, "ok", True, True, "confirmed", False, "missing_writer_close"))
        for exitcode, outcome, status_eof, payload_eof, cleanup, expected, fault in cases:
            with self.subTest(case=(exitcode, outcome, status_eof, payload_eof, cleanup, fault)):
                context = _context()
                receipt = _receipt(code=exitcode)
                child = _Child()
                child.receipt = receipt
                context.child_acquisition.child = child
                context.child_acquisition.attempted = True
                outer = owner._Outer(context, Path("/private/profile"), owner._Deadlines(10, 10, 10, 13, 13))
                outer.channel, outer.payload, outer.child = _Channel(context), _Lease(203), child
                outer.channel.eof = False
                context.io.leases.extend((outer.channel.reader, outer.channel.writer, outer.payload))
                original_close = context.close

                def close(lease):
                    if fault == "missing_writer_close" and lease is outer.channel.writer:
                        return  # Explicit lost dispatch: no lease close or context receipt.
                    original_close(lease)

                with patch.object(context, "close", side_effect=close):
                    if fault == "writer_close_error":
                        outer.channel.writer.error = OSError("PRIVATE_RETIRE_CLOSE")
                    if fault != "no_notification":
                        outer.channel.frames = [_quiescing()]
                        with patch.object(owner.time, "monotonic_ns", return_value=1):
                            outer.process_frames()
                        self.assertTrue(outer.control_retiring)
                        self.assertIsNone(outer.final)
                    outer.channel.eof, outer.payload_eof = status_eof, payload_eof
                    # Explicit parsed-terminal model, never a substitute for Q.
                    if fault != "notification_only":
                        outer.final = {"outcome": outcome, "cleanup": cleanup}
                    outer.safe_pump = Mock()
                    clock = iter((1, 20_000_000_000, 20_000_000_000, 20_000_000_000))
                    with patch.object(owner.time, "monotonic_ns", side_effect=lambda: next(clock, 20_000_000_000)), patch.object(owner, "_wait_child", return_value=receipt):
                        outer.cleanup()
                self.assertEqual(outer.confirmed, expected)
                self.assertEqual([lease.close_calls for lease in context.io.leases], [1, 0 if fault == "missing_writer_close" else 1, 1])
                if fault == "missing_writer_close":
                    self.assertNotIn(id(outer.channel.writer), context.closed)
                if fault == "writer_close_error":
                    self.assertTrue(context.cleanup_unknown)

    def test_capture_cleanup_is_shielded_unconditional_and_does_not_mask_body_primary(self):
        guard, finality = _Cancellation(), owner.CaptureFinality()
        first = ValidationError(owner.ERROR)
        captured = []

        class Outer:
            def __init__(self, context, *_args):
                self.context = context
                self.cleanup_claimed = False
                self.confirmed = False
                self.safe_pump = lambda: None
                captured.append(self)

            def run(self):
                raise first

            def cleanup(self):
                self.cleanup_claimed = True
                if guard.depth <= 0:
                    raise AssertionError("cleanup dispatch was not shielded")
                guard.cancelled = True  # Deferred default signal, not an actual KI.
                self.confirmed = True

        deadline = types.SimpleNamespace(expires_at=100.0, check=lambda: None)
        with patch.object(owner.native, "Acquisition", _Acquisition), patch.object(owner, "_Outer", Outer), patch.object(owner.time, "monotonic_ns", return_value=1):
            with self.assertRaises(ValidationError) as raised:
                owner.capture_profile(Path("/private/profile"), deadline, cancellation=guard, finality=finality)
        self.assertIs(raised.exception, first)
        self.assertTrue(captured[0].cleanup_claimed)
        self.assertEqual(finality.state, "NO_PRODUCERS")
        self.assertNotIn("restore", guard.calls)  # Borrowed exact guard remains owned outside.

    def test_owned_restore_is_attempted_after_cleanup_dispatch_error_and_original_interrupt_survives(self):
        from mobile_release import ios_profiles

        guard, finality = _Cancellation(), owner.CaptureFinality()
        first, later = SystemExit(29), KeyboardInterrupt("late restore")
        guard.restore_action = Mock(side_effect=later)

        class Outer:
            def __init__(self, context, *_args):
                self.context = context
                self.cleanup_claimed = False
                self.confirmed = False
                self.safe_pump = lambda: None

            def run(self):
                raise first

            def cleanup(self):
                self.cleanup_claimed = True
                raise OSError("PRIVATE_CLEANUP_MARKER")

        deadline = types.SimpleNamespace(expires_at=100.0, check=lambda: None)
        with patch.object(owner.native, "Acquisition", _Acquisition), patch.object(owner, "_Outer", Outer), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(ios_profiles, "_profile_cancellation", return_value=guard):
            with self.assertRaises(SystemExit) as raised:
                owner.capture_profile(Path("/private/profile"), deadline, finality=finality)
        self.assertIs(raised.exception, first)
        self.assertEqual(raised.exception.code, 29)
        self.assertEqual(guard.calls, ["install", "restore"])
        self.assertEqual(finality.state, "UNKNOWN")
        self.assertIn(later, finality._owner.secondary)

    def test_final_pending_cancellation_vetoes_an_otherwise_complete_modeled_offer(self):
        from mobile_release import ios_profiles

        guard, finality = _Cancellation(), owner.CaptureFinality()
        actions = []

        class Outer:
            def __init__(self, context, *_args):
                self.context = context
                self.cleanup_claimed = False
                self.confirmed = False
                self.final = {"outcome": "ok"}
                self.safe_pump = lambda: None
                child = _Child()
                child.receipt = _receipt()
                context.child_acquisition.child = child
                context.child_acquisition.attempted = True

            def run(self):
                self.cleanup()
                return b"fictional profile"

            def cleanup(self):
                self.cleanup_claimed = self.confirmed = True
                actions.append("cleanup")

        def restore():
            self.assertEqual(actions, ["cleanup"])
            actions.append("restore")
            guard.cancelled = True

        guard.restore_action = restore
        deadline = types.SimpleNamespace(expires_at=100.0, check=lambda: None)
        with patch.object(owner.native, "Acquisition", _Acquisition), patch.object(owner, "_Outer", Outer), patch.object(owner.time, "monotonic_ns", return_value=1), patch.object(ios_profiles, "_profile_cancellation", return_value=guard):
            with self.assertRaises(KeyboardInterrupt):
                owner.capture_profile(Path("/private/profile"), deadline, finality=finality)
        self.assertEqual(actions, ["cleanup", "restore"])
        self.assertEqual(finality.state, "FINALIZED")  # Cleanup, NOT authorization.

    def test_physical_finality_during_cleanup_grace_never_extends_capture_acceptance(self):
        guard, finality = _Cancellation(), owner.CaptureFinality()
        now = [1_000_000_000]
        captured = []

        class Outer:
            def __init__(self, context, *_args):
                self.context = context
                self.cleanup_claimed = False
                self.confirmed = False
                self.final = {"outcome": "ok"}
                self.safe_pump = lambda: None
                _settled_child(context)
                captured.append(self)

            def run(self):
                self.cleanup()
                return b"modeled late profile"

            def cleanup(self):
                self.cleanup_claimed = self.confirmed = True
                now[0] = self.context.run + owner.NANOSECOND
                if now[0] >= self.context.hard:
                    raise AssertionError("model must settle inside original cleanup grace")

        deadline = types.SimpleNamespace(expires_at=1000.0, check=lambda: None)
        with patch.object(owner.native, "Acquisition", _Acquisition), patch.object(owner, "_Outer", Outer), patch.object(owner.time, "monotonic_ns", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(ValidationError, "authentication timed out"):
                owner.capture_profile(Path("/private/profile"), deadline, cancellation=guard, finality=finality)
        self.assertTrue(captured[0].confirmed)
        self.assertEqual(finality.state, "FINALIZED")  # Settled, but never authorized.
        self.assertEqual(captured[0].context.run, 31_000_000_000)
        self.assertEqual(captured[0].context.hard, 34_000_000_000)

    def test_final_gate_uses_the_common_recorded_primary_not_its_private_catch(self):
        guard, finality = _Cancellation(), owner.CaptureFinality()
        first = ValidationError(owner.ERROR)
        common_record = owner._Context.record

        class Outer:
            def __init__(self, context, *_args):
                self.context = context
                self.cleanup_claimed = self.confirmed = True
                self.final = {"outcome": "ok"}
                self.safe_pump = lambda: None
                _settled_child(context)

            def run(self):
                return None  # Deliberate final acceptance error, no producer.

        def record(context, error, reason="lifecycle", *, cleanup=False):
            # Inert ordering model: a different source reaches the common
            # recorder before the final gate's own caught error reaches it.
            common_record(context, first, "creation")
            common_record(context, error, reason, cleanup=cleanup)

        deadline = types.SimpleNamespace(expires_at=100.0, check=lambda: None)
        with patch.object(owner.native, "Acquisition", _Acquisition), patch.object(owner, "_Outer", Outer), patch.object(owner._Context, "record", record), patch.object(owner.time, "monotonic_ns", return_value=1):
            with self.assertRaises(ValidationError) as raised:
                owner.capture_profile(Path("/private/profile"), deadline, cancellation=guard, finality=finality)
        self.assertIs(raised.exception, first)
        self.assertIs(finality._owner.primary, first)
        self.assertEqual(finality.state, "FINALIZED")
        self.assertTrue(any(type(error) is ValidationError and error.args == (owner.CLEANUP_ERROR,)
                            for error in finality._owner.secondary))

    def test_final_cannot_erase_reserved_keeper_or_published_validator_evidence(self):
        context = _context()
        outer = owner._Outer(context, Path("/private/profile"), owner._Deadlines(10, 10, 10, 13, 13))
        outer.child = _Child(pid=430)
        outer.channel = _Channel(context)
        outer.channel.eof = False
        outer.channel.write_attempted.update(("ADMIT", "RUN"))
        outer.reserved = {"keeper_pid": 431, "group_id": 431, "session_id": 430}
        outer.channel.frames = [_quiescing()]
        with patch.object(owner.time, "monotonic_ns", return_value=1):
            outer.process_frames()
        self.assertTrue(outer.control_retiring)
        self.assertIsNone(context.primary)
        outer.channel.take = Mock(return_value=[_failed()])
        with self.assertRaises(ValidationError):
            outer.process_frames()
        outer.ready = {"validator_pid": 432, "group_id": 431, "keeper_pgid": 430}
        frame = {**_failed(), "keeper": {"state": "reaped", "pid": 431, "status_kind": "exit", "status_code": 0},
                 "group": {"state": "retired", "id": 431, "absent": True}}
        outer.channel.take = Mock(return_value=[frame])
        with self.assertRaises(ValidationError):
            outer.process_frames()
        self.assertIsNone(outer.final)


if __name__ == "__main__":
    unittest.main()
