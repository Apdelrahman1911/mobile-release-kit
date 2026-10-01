"""Notes DATA, clock and scripted-memory seams; no Windows DLL or NTFS qualification."""
import json
import struct
import unittest

from mobile_release._desktop_edit_protocol import (
    METADATA_PROTOCOL, NOTES_PROTOCOL, VERSION_PROTOCOL, WORKFLOW_PROTOCOL,
    ProtocolError, notes_registered_identity, parse_request, registered_identity,
)
from mobile_release._required_notes_windows_contract import (
    WindowsNotesContractError, canonical_u64, material, registered_root,
)
from mobile_release._desktop_notes_windows import (
    NotesUnknown, _decode_observation_batch, _decode_presence,
)


def _root():
    return {"platform": "windows-ntfs-v1", "volumeSerial": "ffffffffffffffff",
            "fileId": "1234567890abcdef1234567890abcdef"}


def _material():
    return {**_root(), "kind": "file", "attributes": 128,
            "securityTransitionKey": "9007199254740993",
            "size": "18446744073709551615", "sha256": "a" * 64}


class WindowsNotesDataContractTests(unittest.TestCase):
    def test_exact_root_is_notes_only_and_lossless(self):
        value = _root()
        self.assertEqual(registered_root(value), value)
        self.assertEqual(notes_registered_identity(value), value)
        self.assertIsNot(registered_root(value), value)
        with self.assertRaises(ProtocolError):
            registered_identity(value)
        posix = {"device": "9007199254740993", "inode": "18446744073709551615",
                 "mode": 0o040700, "uid": 1000, "gid": 1000}
        self.assertEqual(notes_registered_identity(posix), registered_identity(posix))
        self.assertEqual(notes_registered_identity(posix)["device"], 9007199254740993)

    def test_root_rejects_lossy_or_open_shapes(self):
        mutations = (
            {**_root(), "volumeSerial": 18446744073709551615},
            {**_root(), "volumeSerial": "FFFFFFFFFFFFFFFF"},
            {**_root(), "volumeSerial": "0" * 15},
            {**_root(), "fileId": "g" * 32},
            {**_root(), "uid": 1000},
            {key: value for key, value in _root().items() if key != "platform"},
        )
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(WindowsNotesContractError):
                registered_root(value)

    def test_material_preserves_full_u64_and_closed_kind(self):
        source = _material()
        self.assertEqual(material(source, directory=False), source)
        self.assertEqual(canonical_u64(source["securityTransitionKey"]), 9007199254740993)
        with self.assertRaises(WindowsNotesContractError):
            material(source, directory=False, limit=65536)
        directory = {key: value for key, value in source.items() if key not in {"size", "sha256"}}
        directory.update(kind="directory", attributes=16)
        self.assertEqual(material(directory, directory=True), directory)
        with self.assertRaises(WindowsNotesContractError):
            material(directory, directory=False)
        with self.assertRaises(WindowsNotesContractError):
            material(source, directory=True)

    def test_material_rejects_noncanonical_and_missing_security_binding(self):
        for value in ("00", "+1", "-1", "18446744073709551616", 1, True, 1.5, None):
            with self.subTest(value=value), self.assertRaises(WindowsNotesContractError):
                material({**_material(), "size": value}, directory=False)
        for value in ("0", "01", 1, True, None):
            with self.subTest(value=value), self.assertRaises(WindowsNotesContractError):
                material({**_material(), "securityTransitionKey": value}, directory=False)
        for patch in ({"attributes": True}, {"attributes": 2**32}, {"sha256": "A" * 64},
                      {"mode": 0o600}, {"kind": "symlink"}):
            with self.subTest(patch=patch), self.assertRaises(WindowsNotesContractError):
                material({**_material(), **patch}, directory=False)

    def test_private_open_accepts_windows_data_only_for_notes(self):
        def frame(protocol, params):
            return (json.dumps({"protocol": protocol, "session": "a" * 32, "seq": 0,
                                "op": "open", "params": params}, separators=(",", ":")) + "\n").encode()
        common = {"root": r"C:\projects\mobile", "registeredIdentity": _root()}
        request = parse_request(frame(NOTES_PROTOCOL, {**common, "context": {"kind": "ios-beta-review"}}),
                                sequence=0, session=None, protocol=NOTES_PROTOCOL)
        self.assertEqual(request.params["registeredIdentity"], _root())
        for protocol in (WORKFLOW_PROTOCOL, VERSION_PROTOCOL, METADATA_PROTOCOL):
            params = dict(common)
            if protocol == METADATA_PROTOCOL:
                params.update(platform="ios", locale="en-US")
            with self.subTest(protocol=protocol), self.assertRaises(ProtocolError):
                parse_request(frame(protocol, params), sequence=0, session=None, protocol=protocol)


def _source_record(*, created=False):
    raw = bytearray(320)
    raw[:8] = b"MRKNOB1\0"
    struct.pack_into("<IIQII", raw, 8, 320, 1, 9007199254740993,
                     3 if created else 1, 1 | 16 | (0 if created else 128))
    # Original u64 fields must survive decoding, not JS/float round trips.
    struct.pack_into("<10Q", raw, 32, 101, 102, 103, 104, 105, 106, 107,
                     108 if created else 0, 109, 18446744073709551615)
    raw[112:128] = bytes.fromhex("1234567890abcdef1234567890abcdef")
    struct.pack_into("<IIQQII", raw, 128, 2, 128, 0, 4096, 1, 0)
    struct.pack_into("<qqq", raw, 160, -1, 9223372036854775807, -9223372036854775808)
    raw[184:216] = b"a" * 32
    raw[216:248] = b"b" * 32
    raw[248:280] = b"c" * 32
    struct.pack_into("<Q", raw, 312, 0 if created else 102)
    return bytes(raw)


def _batch(record):
    return struct.pack("<III", 1, 12 + len(record), len(record)) + record


class WindowsNotesObservationDataTests(unittest.TestCase):
    def test_exact_native_integer_and_timestamp_widths(self):
        values = _decode_observation_batch(_batch(_source_record()), owner=9007199254740993,
                                           scope=1, operation=9, expected_count=1)
        observed = values[0]
        self.assertEqual(observed.owner, 9007199254740993)
        self.assertEqual(observed.volume_serial, 18446744073709551615)
        self.assertEqual(observed.change, -9223372036854775808)
        self.assertEqual(observed.source_facts(), tuple(sorted(dict(observed.source_facts()).items())))
        self.assertEqual(dict(observed.source_facts())["write"], "9223372036854775807")

    def test_created_source_is_not_material_or_capture_baseline(self):
        raw = _source_record(created=True)
        observed, = _decode_observation_batch(_batch(raw), owner=9007199254740993,
                                               scope=3, operation=9, expected_count=1)
        self.assertEqual(observed.original_capture, 0)
        self.assertFalse(observed.flags & 128)
        forged = bytearray(raw)
        struct.pack_into("<I", forged, 28, observed.flags | 128)
        with self.assertRaises(NotesUnknown):
            _decode_observation_batch(_batch(bytes(forged)), owner=9007199254740993,
                                      scope=3, operation=9, expected_count=1)

    def test_exact_batch_length_owner_scope_and_reserved_fields(self):
        original = _source_record()
        for raw, owner, scope in (
                (_batch(original) + b"\0", 9007199254740993, 1),
                (_batch(original), 9007199254740992, 1),
                (_batch(original), 9007199254740993, 2),
                (_batch(original[:-1]), 9007199254740993, 1)):
            with self.subTest(owner=owner, scope=scope, size=len(raw)), self.assertRaises(NotesUnknown):
                _decode_observation_batch(raw, owner=owner, scope=scope, operation=9, expected_count=1)
        reserved = bytearray(original)
        struct.pack_into("<I", reserved, 156, 1)
        with self.assertRaises(NotesUnknown):
            _decode_observation_batch(_batch(bytes(reserved)), owner=9007199254740993,
                                      scope=1, operation=9, expected_count=1)

    def test_absent_child_requires_actual_roster_or_original_parent_absence(self):
        raw = bytearray(164)
        raw[:8] = b"MRKNPF1\0"
        struct.pack_into("<IIQII", raw, 8, 160, 2, 9, 1, 2)
        struct.pack_into("<7Q", raw, 32, 1, 2, 3, 0, 4, 0, 5)
        raw[88:120] = b"a" * 32
        struct.pack_into("<4IQ", raw, 136, 0, 0, 4, 0, 6)
        raw[160:] = b"note"
        value = _decode_presence(bytes(raw), owner=9, scope=1)
        self.assertEqual(value.original_parent_absent_key, 6)
        struct.pack_into("<Q", raw, 152, 0)
        with self.assertRaises(NotesUnknown):
            _decode_presence(bytes(raw), owner=9, scope=1)




def _schedule_record(stage, *, pool=None, **credits):
    names = ("passes", "frames", "user_checks", "acquisitions", "records",
             "bridge_calls", "read_bytes", "roster_entries", "retained_heap")
    if pool is None:
        pool = 1 if stage <= 12 else 2 if stage <= 15 else 3
    return struct.pack("<8I4Q", stage, pool, *(credits.get(name, 0) for name in names), 0)


def _schedule_table(records):
    return struct.pack("<II", len(records), 8 + sum(4 + len(row) for row in records)) + b"".join(
        struct.pack("<I", len(row)) + row for row in records)


def _schedule_values(changes=None):
    from mobile_release._desktop_notes_windows import _decode_table
    changes = {} if changes is None else changes
    return _decode_table(_schedule_table([
        _schedule_record(stage, **changes.get(stage, {})) for stage in range(1, 17)]), kind=6, scope=0)


class WindowsNotesScheduleDataTests(unittest.TestCase):
    def test_every_factory_requires_schedule_key_and_scope_zero_accepts_its_snapshot(self):
        from mobile_release._desktop_notes_windows import _Bridge, _LogicalData, _decode_factory
        for operation, scope, known in ((1, 0, 0), (4, 1, 0), (4, 2, 3), (4, 3, 3),
                                         (5, 1, 0), (6, 1, 0), (7, 1, 3), (18, 3, 15)):
            raw = bytearray(128)
            raw[:8] = b"MRKNFG1\0"
            struct.pack_into("<IIQII", raw, 8, 128, operation, 9, scope, 1)
            struct.pack_into("<9Q", raw, 32, 10, 11, 0 if scope == 0 else 12,
                             13, 0 if scope == 0 else 14, 0, 0, 0, 15)
            struct.pack_into("<6I", raw, 104, 0, 0, 0, 0, known, 0)
            with self.subTest(operation=operation, scope=scope):
                report = _decode_factory(bytes(raw), operation=operation, owner=9, scope=scope)
                self.assertEqual(report.schedule_data_key, 15)
                struct.pack_into("<Q", raw, 96, 0)
                with self.assertRaises(NotesUnknown):
                    _decode_factory(bytes(raw), operation=operation, owner=9, scope=scope)
                if scope == 0:
                    # Actual factory integration, with inert decoded tables:
                    # scope zero has a schedule, not mappings or filesystem effects.
                    bridge = object.__new__(_Bridge)
                    bridge._lease_key, bridge._schedule_snapshot = 11, None
                    schedule = _schedule_values({1: {"bridge_calls": 2}})
                    logical = (_LogicalData(1, 1, 0, 0, 1, None, 107, "", ""),)
                    bridge._table = lambda key, kind, scope: logical if kind == 1 else schedule if kind == 6 else ()
                    result = bridge._factory_tables(report)
                    self.assertEqual(result.schedule, schedule)
                    self.assertIs(bridge._schedule_snapshot, result.schedule)

    def test_exact_unique_stages_pools_and_finality_without_inventing_wire_order(self):
        from mobile_release._desktop_notes_windows import _decode_table
        rows = [_schedule_record(stage) for stage in range(1, 17)]
        actual = _decode_table(_schedule_table(list(reversed(rows))), kind=6, scope=3)
        self.assertEqual([row.stage for row in actual], list(range(1, 17)))
        for changed in (
                rows[:-1], rows[:-1] + [rows[0]],
                rows[:12] + [_schedule_record(13, pool=1)] + rows[13:],
                rows[:-1] + [_schedule_record(16, passes=1)],
                rows[:-1] + [_schedule_record(17)]):
            with self.subTest(records=len(changed)), self.assertRaises(NotesUnknown):
                _decode_table(_schedule_table(changed), kind=6, scope=3)
        finality = _schedule_values({16: {"bridge_calls": 1024, "retained_heap": 4096}})
        self.assertEqual((finality[-1].bridge_calls, finality[-1].retained_heap), (1024, 4096))

    def test_global_and_each_pool_are_checked_against_actual_info_not_per_original_limits(self):
        # Each overflowing member is individually within the global wire cap.
        totals = {"passes": 4096, "frames": 65536, "user_checks": 15360,
                  "acquisitions": 154, "records": 32768, "bridge_calls": 132096,
                  "read_bytes": 1073741824, "roster_entries": 524288, "retained_heap": 33554432}
        pools = {"passes": 2048, "frames": 32768, "user_checks": 7680,
                 "bridge_calls": 65536, "read_bytes": 536870912}
        self.assertEqual(_schedule_values({1: {"records": 129}})[0].records, 129)
        for name, limit in totals.items():
            changes = {1: {name: limit // 2 + 1}, 13: {name: limit - limit // 2}}
            with self.subTest(global_metric=name), self.assertRaises(NotesUnknown):
                _schedule_values(changes)
        for name, limit in pools.items():
            for first, second in ((1, 2), (13, 14)):
                _schedule_values({first: {name: limit}})
                with self.subTest(pool_metric=name, pool_stage=first), self.assertRaises(NotesUnknown):
                    _schedule_values({first: {name: limit}, second: {name: 1}})
        with self.assertRaises(NotesUnknown):
            _schedule_values({16: {"bridge_calls": 1025}})

    def test_fresh_factory_snapshots_cannot_refund_or_move_allocated_stage_credits(self):
        from mobile_release._desktop_notes_windows import _admit_schedule
        old = _schedule_values({1: {"bridge_calls": 2, "records": 129},
                                16: {"bridge_calls": 5, "retained_heap": 4096}})
        new = _schedule_values({1: {"bridge_calls": 3, "records": 129},
                                13: {"passes": 1},
                                16: {"bridge_calls": 5, "retained_heap": 4096}})
        self.assertEqual(_admit_schedule(tuple(reversed(new)), old), new)
        self.assertEqual(_admit_schedule(old, old), old)  # immutable allocation need not grow
        for changes in (
                {1: {"bridge_calls": 1, "records": 129}, 16: {"bridge_calls": 5, "retained_heap": 4096}},
                {2: {"bridge_calls": 2, "records": 129}, 16: {"bridge_calls": 5, "retained_heap": 4096}},
                {1: {"bridge_calls": 2, "records": 129}, 16: {"bridge_calls": 5, "retained_heap": 4095}}):
            with self.assertRaises(NotesUnknown):
                _admit_schedule(_schedule_values(changes), old)


def _clock_input():
    """Real EditInput clock/poll logic with no descriptors, supplier or native calls."""
    from types import SimpleNamespace
    from unittest.mock import patch
    from mobile_release import _desktop_edit_control as control
    with patch.object(control.sys, "platform", "linux"):
        source = control.EditInput(100.0, protocol=NOTES_PROTOCOL)
    stdio = SimpleNamespace(lost=False, known=True, reads=0, next_chunk=None)
    stdio._lost_custody = lambda: stdio.lost
    stdio._notes_native_supplier_known = lambda original, guard: stdio.known and not stdio.lost
    def read(limit):
        stdio.reads += 1
        return stdio.next_chunk
    stdio.read_available = read
    guard = SimpleNamespace(cancelled=False, lifetime_ledger=SimpleNamespace(fatal=False))
    guard._check_owner = source._owner
    guard._abort = lambda error: setattr(guard.lifetime_ledger, "fatal", True)
    guard._poll_edit_stop = lambda: source.poll(guard)
    def check():
        guard._poll_edit_stop()
        if guard.cancelled:
            raise ProtocolError("inert clock fixture observed STOP")
    guard.check = check
    source._windows_stdio, source.guard, source.active = stdio, guard, True
    return source, guard, stdio


class WindowsNotesClockTests(unittest.TestCase):
    def test_producer_stops_early_but_preowned_settlement_and_finality_share_original_end(self):
        from unittest.mock import patch
        from mobile_release import _desktop_edit_control as control
        source, guard, stdio = _clock_input()
        with patch.object(control.time, "monotonic", return_value=119.0) as clock:
            source.before_notes_entry()
            self.assertFalse(source.stopped)
            self.assertEqual(source._notes_endpoint(), 130.0)
            clock.return_value = 120.0
            with self.assertRaises(ProtocolError):
                source.before_notes_entry()
            self.assertTrue(source._notes_deadline_reached)
            self.assertTrue(guard.cancelled)
            self.assertEqual(source._notes_filesystem_end, 130.0)
            reads = stdio.reads
            clock.return_value = 129.0
            source.before_notes_settlement()
            source.before_notes_finality()
            self.assertEqual(stdio.reads, reads)  # no new input producer after STOP
            clock.return_value = 130.0
            with self.assertRaises(ProtocolError):
                source.before_notes_settlement()
            with self.assertRaises(ProtocolError):
                source.before_notes_finality()
            self.assertEqual(source._notes_filesystem_end, 130.0)

    def test_late_observation_or_repeated_stop_never_renews_cleanup_or_next_request(self):
        from unittest.mock import patch
        from mobile_release import _desktop_edit_control as control
        source, guard, _ = _clock_input()
        with patch.object(control.time, "monotonic", return_value=140.0) as clock:
            source.poll(guard)
            self.assertEqual(source._notes_filesystem_end, 130.0)  # not now+grace
            source._stop()
            source._notes_cleanup_started()
            source.active_end = 500.0  # even changed later phase DATA cannot extend E
            self.assertEqual(source._notes_filesystem_endpoint(), 130.0)
            clock.return_value = 141.0
            with self.assertRaises(ProtocolError):
                source.before_notes_settlement()
            source.active = False
            with self.assertRaises(ProtocolError):
                source.request(1, "inert-session")
            source.active = True
            with self.assertRaises(ProtocolError):
                source.idle()
            self.assertEqual(source._notes_filesystem_end, 130.0)

    def test_healthy_idle_and_scope_finality_do_not_freeze_but_first_recovery_does(self):
        from unittest.mock import patch
        from mobile_release import _desktop_edit_control as control
        source, guard, stdio = _clock_input()
        with patch.object(control.time, "monotonic", return_value=101.0) as clock:
            source._notes_native_boundary(settlement=True)  # shared stdio's idle pause
            source.before_notes_finality()  # healthy scope17 has no recovery transition
            self.assertIsNone(source._notes_filesystem_end)
            source.idle()
            self.assertEqual((source._notes_endpoint(), source._notes_producer_endpoint()), (1000.0, 990.0))
            clock.return_value = 102.0
            stdio.next_chunk = b"{"  # a partial request starts the existing30s phase
            source.poll(guard)
            self.assertEqual((source.active_end, source._notes_producer_endpoint()), (132.0, 122.0))
            self.assertIsNone(source._notes_filesystem_end)
            # Accepted Apply uses its original active endpoint, not a new review deadline.
            source.apply_active, source.active_end, source.active = True, 1200.0, True
            source.buffer.clear()
            stdio.next_chunk = None
            source.before_notes_settlement()
            self.assertEqual(source._notes_filesystem_end, 1200.0)
            self.assertFalse(source.stopped)
            self.assertFalse(source._notes_deadline_reached)
            source.active_end = 1300.0
            source.before_notes_settlement()
            self.assertEqual(source._notes_endpoint(), 1200.0)

    def test_terminal_output_cannot_lend_its_two_seconds_to_filesystem_or_finality(self):
        from unittest.mock import patch
        from mobile_release import _desktop_edit_control as control
        source, _, _ = _clock_input()
        with patch.object(control.time, "monotonic", return_value=101.0) as clock:
            source._stop()
            self.assertFalse(source._notes_deadline_reached)
            source._notes_cleanup_attempted = True
            clock.return_value = 150.0
            source._notes_terminal_started()
            self.assertEqual((source._notes_endpoint(), source._notes_filesystem_endpoint()), (152.0, 130.0))
            source._notes_terminal_check()
            for operation in (source.before_notes_entry, source.before_notes_settlement,
                              source.before_notes_finality,
                              lambda: source._notes_native_boundary(settlement=True)):
                with self.assertRaises(ProtocolError):
                    operation()
            clock.return_value = 152.0
            with self.assertRaises(ProtocolError):
                source._notes_terminal_check()
            self.assertFalse(source._notes_deadline_reached)  # output expiry is not a new FS reason

    def test_frozen_cleanup_does_not_restore_unknown_supplier_custody(self):
        from unittest.mock import patch
        from mobile_release import _desktop_edit_control as control
        with patch.object(control.time, "monotonic", return_value=125.0):
            for lost, known in ((True, True), (False, False)):
                source, _, stdio = _clock_input()
                source._stop()
                stdio.lost, stdio.known = lost, known
                with self.assertRaises(ProtocolError):
                    source.before_notes_finality()
                if lost:
                    with self.assertRaises(ProtocolError):
                        source.before_notes_settlement()
                self.assertEqual(source._notes_filesystem_end, 130.0)


# These fixtures exercise the Python ABI boundary with returning DATA only.
# They do not load a Windows DLL, acquire a project, or qualify NTFS behavior.
class _ScriptedFunction:
    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = []

    def __call__(self, request, source, reply, destination):
        request, reply = request._obj, reply._obj
        self.calls.append((request.operation, id(request), id(reply)))
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        fields = {
            "size": 80, "version": 1, "status": 0, "error": 0,
            "owner": 9, "token": 0, "sequence": len(self.calls), "epoch": 0,
            "output_len": 0, "count": 0, "total": 0, "flags": 0,
            "first_failure": 0,
        }
        raw = step.get("body", b"")
        fields.update({key: value for key, value in step.items() if key != "body"})
        fields["output_len"] = len(raw)
        for name, value in fields.items():
            setattr(reply, name, value)
        if raw:
            destination[:len(raw)] = raw
        return fields["status"]


class _UnusedInfo:
    def __call__(self, *args):
        raise AssertionError("the DATA fixture must not pretend to run ABI admission")


class _BoundaryInput:
    def __init__(self):
        self.boundaries = []
        self.stopped = False
        self.settlement_expired = False

    def before_notes_entry(self):
        self.boundaries.append("ordinary")
        if self.stopped:
            raise ProtocolError("the fixture ordinary producer stopped")

    def before_notes_settlement(self):
        self.boundaries.append("recovery")
        if self.settlement_expired:
            raise ProtocolError("the fixture original filesystem endpoint expired")

    def before_notes_finality(self):
        self.boundaries.append("finality")


def _bridge_fixture(steps):
    import ctypes
    from types import SimpleNamespace
    from mobile_release._desktop_notes_windows import _Bridge
    native = _ScriptedFunction(steps)
    input_owner = _BoundaryInput()
    bridge = _Bridge(input_owner, object(), ctypes,
                     SimpleNamespace(mrk_notes_v1_call=native, mrk_notes_v1_info=_UnusedInfo()))
    # These DATA fixtures bypass only the surrounding original-process owner.
    # D1's independent lifecycle tests exercise the real binding/context seam.
    bridge._context = lambda: None
    bridge._prepared, bridge._owner_key, bridge._scope_number = True, 9, 3
    return bridge, input_owner, native


def _effect_bytes(operation, *, object_key=101, operation_key=101,
                  return_kind=2, bits=1, flags=3, information=0):
    kinds = {22: 1, 23: 2, 25: 3, 26: 4, 28: 5, 29: 6, 31: 7}
    raw = bytearray(80)
    raw[:8] = b"MRKNEF1\0"
    struct.pack_into("<II5Q", raw, 8, 80, kinds[operation], 9, object_key, 1, 1, operation_key)
    struct.pack_into("<4IQ", raw, 56, return_kind, bits, 0, flags, information)
    return bytes(raw)


class WindowsNotesCallCustodyTests(unittest.TestCase):
    def test_malformed_return_retains_original_cell_and_forbids_even_status(self):
        from mobile_release._desktop_notes_windows import NotesUnknown
        bridge, boundary, native = _bridge_fixture([{"size": 79}])
        with self.assertRaises(NotesUnknown):
            bridge.check_lease()
        self.assertIs(bridge._pending, bridge._ordinary_frame)
        self.assertTrue(bridge._ordinary_frame.returned)
        self.assertTrue(bridge._wire_lost)
        with self.assertRaises(NotesUnknown):
            bridge.status()
        with self.assertRaises(NotesUnknown):
            bridge.scope_status(3, settle=False)
        self.assertEqual(len(native.calls), 1)
        self.assertEqual(boundary.boundaries, ["ordinary"])

    def test_missing_actual_return_never_enters_another_cell(self):
        from mobile_release._desktop_notes_windows import NotesUnknown
        bridge, _, native = _bridge_fixture([KeyboardInterrupt()])
        with self.assertRaises(NotesUnknown):
            bridge.check_lease()
        self.assertIs(bridge._pending, bridge._ordinary_frame)
        self.assertFalse(bridge._ordinary_frame.returned)
        with self.assertRaises(NotesUnknown):
            bridge.retire()
        self.assertEqual(len(native.calls), 1)

    def test_fully_decoded_unknown_allows_only_original_separate_finality(self):
        from mobile_release._desktop_notes_windows import NotesUnknown
        bridge, boundary, native = _bridge_fixture([
            {"status": 4, "error": 36, "first_failure": 36, "flags": 1},
            {"status": 0, "first_failure": 36, "flags": 1},
        ])
        with self.assertRaises(NotesUnknown):
            bridge.check_lease()
        self.assertIsNone(bridge._pending)
        self.assertTrue(bridge._unknown)
        with self.assertRaises(NotesUnknown):
            bridge.check_lease()
        observed = bridge.status()
        self.assertEqual(observed.flags, 1)  # UNKNOWN is not settled success.
        self.assertEqual([row[0] for row in native.calls], [3, 41])
        self.assertNotEqual(native.calls[0][1:], native.calls[1][1:])
        self.assertEqual(boundary.boundaries, ["ordinary", "finality"])

    def test_original_failure_and_terminal_bits_survive_later_malformed_payload(self):
        from mobile_release._desktop_notes_windows import NotesUnknown
        bridge, _, native = _bridge_fixture([
            {"status": 0, "token": 77, "count": 2, "total": 2,
             "flags": 1024 | 8 | 16, "body": b"\0" * 80},
        ])
        move = bridge._keep(77, "move", scope=3, logical=8, object_key=101)
        original = bridge._keep(101, "object", scope=3, logical=8, object_key=101)
        parent = bridge._keep(12, "object", scope=3, logical=1, object_key=12)
        pass_key = bridge._keep(13, "pass", scope=3, logical=1, object_key=12)
        object_pass = bridge._keep(14, "pass", scope=3, logical=8, object_key=101)
        from mobile_release._desktop_notes_windows import _MoveData, _Pass
        stream = _Pass(pass_key, parent, True, complete=True)
        content = _Pass(object_pass, original, False, complete=True)
        bridge._passes[12], bridge._passes[101] = stream, content
        bridge._move_facts[77] = _MoveData(77, 8, 101, 1, 1, 0, 0, 0, 0,
                                          15, 2, "commit.pending", "COMMITTED")
        with self.assertRaises(NotesUnknown):
            bridge.finish_move(move, content, stream, stream, (original, parent))
        self.assertEqual(bridge._terminal_bits, 1024)
        self.assertIs(bridge._pending, bridge._ordinary_frame)
        with self.assertRaises(NotesUnknown):
            bridge.status()
        self.assertEqual(len(native.calls), 1)

    def test_first_failure_cannot_be_replaced_by_cleanup_error(self):
        from mobile_release._desktop_notes_windows import NotesFailure, NotesUnknown
        bridge, _, _ = _bridge_fixture([
            {"status": 4, "error": 36, "first_failure": 36, "flags": 1},
            {"status": 3, "error": 12, "first_failure": 36, "flags": 1},
        ])
        with self.assertRaises(NotesUnknown):
            bridge.check_lease()
        original = bridge._first_failure_return
        with self.assertRaises(NotesFailure):
            bridge.status()
        self.assertEqual(bridge._first_failure, 36)
        self.assertIs(bridge._first_failure_return, original)


class WindowsNotesPrimitiveDataTests(unittest.TestCase):
    def test_bool_bits_and_partial_write_are_actual_native_values(self):
        bridge, _, _ = _bridge_fixture([])
        from mobile_release._desktop_notes_windows import _ReplyData
        reply = _ReplyData(0, 0, 9, 101, 1, 1, 80, 1, 1, 24, 0)
        value = bridge._effect(25, 101, _effect_bytes(25, bits=0xFFFFFFFF), reply, expected_object=101)
        self.assertEqual(value.return_bits, 0xFFFFFFFF)
        value = bridge._effect(23, 101, _effect_bytes(23, information=2), reply,
                                expected_object=101, input_length=7)
        self.assertEqual(value.information, 2)
        with self.assertRaises(NotesUnknown):
            bridge._effect(23, 101, _effect_bytes(23, information=8), reply,
                           expected_object=101, input_length=7)

    def test_pending_status_and_proved_no_effect_are_not_success(self):
        bridge, _, _ = _bridge_fixture([])
        from mobile_release._desktop_notes_windows import _ReplyData
        reply = _ReplyData(0, 0, 9, 101, 1, 1, 80, 1, 1, 24, 0)
        for raw in (_effect_bytes(25, return_kind=1, bits=0x103),
                    _effect_bytes(25, flags=7)):
            with self.subTest(raw=raw.hex()), self.assertRaises(NotesUnknown):
                bridge._effect(25, 101, raw, reply, expected_object=101)

    def test_read_stream_requires_actual_eof_and_retains_original_pass(self):
        bridge, _, native = _bridge_fixture([
            {"token": 77},
            {"token": 77, "body": b"note", "count": 4, "total": 4},
            {"status": 1, "token": 77, "count": 0, "total": 4},
        ])
        original = bridge._keep(101, "object", scope=3, logical=7, object_key=101)
        stream = bridge.begin_pass(original, directory=False)
        self.assertEqual(bridge.next_read(stream), b"note")
        self.assertFalse(stream.complete)
        self.assertIsNone(bridge.next_read(stream))
        self.assertTrue(stream.complete)
        self.assertEqual(stream.total, 4)
        self.assertEqual([row[0] for row in native.calls], [10, 11, 11])

    def test_created_source_cannot_anchor_current_material(self):
        bridge, _, native = _bridge_fixture([])
        from mobile_release._desktop_notes_windows import (
            NotesRefused, _NativeObservation, _Pass, _decode_observation,
        )
        original = bridge._keep(101, "object", scope=3, logical=103, object_key=101)
        bridge._owner_key = 9007199254740993
        source = _decode_observation(_source_record(created=True), owner=bridge._owner_key, scope=3)
        source_key = bridge._keep(source.observation_key, "current_source",
                                  scope=3, logical=103, object_key=101)
        pass_key = bridge._keep(109, "pass", scope=3, logical=103, object_key=101)
        stream = _Pass(pass_key, original, False, complete=True)
        bridge._passes[101] = stream
        with self.assertRaises(NotesRefused):
            bridge.observe(original, stream, accepted=_NativeObservation(source_key, original, source))
        self.assertFalse(native.calls)

    def test_joined_exit_is_row_bound_and_uses_ordinary_stop_boundary(self):
        from mobile_release._desktop_notes_windows import NotesRefused
        bridge, boundary, native = _bridge_fixture([{"token": 77}])
        root = bridge._keep(101, "object", scope=3, logical=1, object_key=101)
        unrelated = bridge._keep(202, "object", scope=3, logical=7, object_key=202)
        bridge._recovery_entered = bridge._recovery_joined = True
        bridge._recovery_mode = "joined"
        bridge._joined_exit_objects = frozenset({101})
        with self.assertRaises(NotesRefused):
            bridge.begin_pass(unrelated, directory=True)
        self.assertFalse(native.calls)
        boundary.stopped = True
        with self.assertRaises(ProtocolError):
            bridge.begin_pass(root, directory=True)
        self.assertFalse(native.calls)
        self.assertEqual(boundary.boundaries, ["ordinary"])
        boundary.stopped = False
        stream = bridge.begin_pass(root, directory=True)
        self.assertEqual(stream.key.value, 77)
        self.assertEqual(bridge._recovery_calls, 1)
        self.assertEqual(bridge._producer_calls, 0)
        self.assertEqual(boundary.boundaries, ["ordinary", "ordinary"])


class WindowsNotesTransactionJoinTests(unittest.TestCase):
    def test_fixed_recovery_always_joins_and_preserves_first_error(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        from mobile_release.init_transaction import InitWorkspace
        events = []
        primary, secondary = RuntimeError("first fixture failure"), RuntimeError("join fixture failure")
        workspace = object.__new__(InitWorkspace)
        workspace._recovery_claimed = False
        workspace._creation = {"state": "CREATED"}
        workspace.private_identity = {"fixture": True}
        workspace._typed_profile = None
        workspace._terminal_ambiguous = False
        workspace._terminal_seen = None
        workspace._terminal_durable = False
        workspace._cleanup_mode = False
        workspace._notes_cleanup_errors = []
        workspace._guard = SimpleNamespace(deferred=lambda **kwargs: nullcontext(),
                                            _abort=lambda error: events.append("abort"))
        workspace._checkpoint = lambda: None
        def recover():
            events.append("recover")
            raise primary
        def join():
            events.append("join")
            raise secondary
        workspace.recover = recover
        workspace._notes = SimpleNamespace(
            begin_fixed_recovery=lambda: events.append("begin"),
            finish_fixed_recovery=join,
            record_core_failure=lambda error: events.append("failure"),
        )
        with self.assertRaises(RuntimeError) as caught:
            workspace._fixed_recovery()
        self.assertIs(caught.exception, primary)
        self.assertEqual(workspace._notes_cleanup_errors, [secondary])
        self.assertEqual(events, ["begin", "recover", "failure", "join", "failure"])
        self.assertFalse(workspace._cleanup_mode)
        self.assertTrue(workspace._recovery_claimed)



def _epoch_record(original, observation, *, parent=0, name="", directory=False, security=16):
    raw = bytearray(_source_record(created=True))
    encoded = name.encode("utf-8")
    struct.pack_into("<IIQII", raw, 8, 320, 2, 9, 3, (2 if directory else 1) | 8 | 128 | security)
    struct.pack_into("<10Q", raw, 32, original.value, observation, original.logical,
                     3, 3, 106, 107, 2, 109, 18446744073709551615)
    raw[112:128] = original.value.to_bytes(16, "little")
    struct.pack_into("<IIQQII", raw, 128, 1 if directory else 2, 16 if directory else 128,
                     0, 4096, 1, 0)
    raw[248:280] = (b"\0" if directory else b"c") * 32
    raw[280:312] = (b"c" if directory else b"\0") * 32
    raw.extend(struct.pack("<4QII", parent, 0 if not parent else 701,
                           0 if not parent else 3, 77, len(encoded), 0))
    raw.extend(encoded)
    return bytes(raw)


def _epoch_batch(*records):
    return struct.pack("<II", len(records), 8 + sum(4 + len(record) for record in records)) + b"".join(
        struct.pack("<I", len(record)) + record for record in records)


def _retained_pass(bridge, original, token, *, directory):
    from mobile_release._desktop_notes_windows import _Pass
    key = bridge._keep(token, "pass", scope=3, logical=original.logical, object_key=original.value)
    stream = _Pass(key, original, directory, complete=True)
    bridge._passes[original.value] = stream
    return stream


def _frozen_pair(bridge):
    from mobile_release._desktop_notes_windows import _MoveData
    original = bridge._keep(101, "object", scope=3, logical=7, object_key=101)
    root = bridge._keep(201, "object", scope=3, logical=1, object_key=201)
    journal = bridge._keep(202, "object", scope=3, logical=9, object_key=202)
    forward = bridge._keep(77, "move", scope=3, logical=7, object_key=101)
    inverse = bridge._keep(78, "move", scope=3, logical=7, object_key=101)
    bridge._move_facts[77] = _MoveData(77, 7, 101, 1, 9, 78, 0, 0, 0, 11, 0, "note", "backup-0")
    bridge._move_facts[78] = _MoveData(78, 7, 101, 9, 1, 0, 77, 0, 0, 12, 8, "backup-0", "note")
    return forward, inverse, original, root, journal


class WindowsNotesCorrectiveAdmissionTests(unittest.TestCase):
    def test_one_pair_then_optional_fixed_continuation_keeps_same_reserve_and_error(self):
        from mobile_release._desktop_notes_windows import NotesRefused
        steps = [
            {"flags": 256, "first_failure": 13},
            {"token": 78, "flags": 256 | 8 | 16, "first_failure": 13, "count": 1, "total": 1,
             "body": _effect_bytes(26, operation_key=78)},
            {"token": 78, "flags": 256, "first_failure": 13, "count": 3, "total": 3},
            {"flags": 256, "first_failure": 13},
            {"flags": 256, "first_failure": 13},
        ]
        bridge, boundary, native = _bridge_fixture(steps)
        forward, inverse, original, root, journal = _frozen_pair(bridge)
        native.steps[2]["body"] = _epoch_batch(
            _epoch_record(original, 801, parent=201, name="note"),
            _epoch_record(journal, 802, parent=201, name="journal", directory=True),
            _epoch_record(root, 803, directory=True))
        bridge._failed, bridge._first_failure = True, 13
        first_return = object()
        bridge._first_failure_return = first_return
        bridge.begin_compensation(forward, inverse, originals=(original, root, journal))
        self.assertEqual(bridge._recovery_mode, "corrective")
        with self.assertRaises(NotesRefused):
            bridge.begin_compensation()  # Inverse not finalized; no new phase.
        unrelated = bridge._keep(301, "object", scope=3, logical=17, object_key=301)
        with self.assertRaises(NotesRefused):
            bridge.begin_pass(unrelated, directory=True)
        content = _retained_pass(bridge, original, 701, directory=False)
        old = _retained_pass(bridge, journal, 702, directory=True)
        new = _retained_pass(bridge, root, 703, directory=True)
        bridge.move(inverse, new)
        self.assertFalse(bridge._corrective_inverse_finished)
        with self.assertRaises(NotesRefused):
            bridge.begin_compensation()
        bridge.finish_move(inverse, content, old, new, (original, journal, root))
        self.assertTrue(bridge._corrective_inverse_finished)
        bridge.begin_compensation()
        bridge.join_compensation()
        self.assertEqual(bridge._recovery_mode, "joined")
        with self.assertRaises(NotesRefused):
            bridge.begin_compensation()
        with self.assertRaises(NotesRefused):
            bridge.join_compensation()
        self.assertEqual([row[0] for row in native.calls], [36, 26, 27, 36, 37])
        self.assertEqual(boundary.boundaries, ["recovery"] * 5)
        self.assertEqual((bridge._producer_calls, bridge._recovery_calls), (0, 5))
        self.assertEqual(bridge._first_failure, 13)
        self.assertIs(bridge._first_failure_return, first_return)

    def test_stop_preserves_only_preowned_correction_and_expiry_consumes_its_choice(self):
        from mobile_release._desktop_notes_windows import NotesRefused
        bridge, boundary, native = _bridge_fixture([{"flags": 256, "first_failure": 18}])
        forward, inverse, original, root, journal = _frozen_pair(bridge)
        bridge._failed, bridge._first_failure = True, 18
        boundary.stopped = True
        bridge.begin_compensation(forward, inverse, originals=(original, root, journal))
        self.assertEqual([row[0] for row in native.calls], [36])
        self.assertEqual(boundary.boundaries, ["recovery"])
        self.assertEqual((bridge._producer_calls, bridge._recovery_calls), (0, 1))
        with self.assertRaises(NotesRefused):
            bridge.begin_compensation(forward, inverse, originals=(original, root, journal))
        expired, stopped, unopened = _bridge_fixture([])
        forward, inverse, original, root, journal = _frozen_pair(expired)
        stopped.stopped = stopped.settlement_expired = True
        with self.assertRaises(ProtocolError):
            expired.begin_compensation(forward, inverse, originals=(original, root, journal))
        with self.assertRaises(NotesRefused):
            expired.begin_compensation()
        self.assertEqual(expired._recovery_mode, "none")
        self.assertFalse(unopened.calls)
        self.assertEqual(expired._recovery_calls, 0)

    def test_exact_pair_rejects_another_original_with_the_same_logical_role(self):
        from mobile_release._desktop_notes_windows import NotesRefused
        bridge, _, native = _bridge_fixture([])
        forward, inverse, original, root, journal = _frozen_pair(bridge)
        replacement = bridge._keep(102, "object", scope=3, logical=7, object_key=102)
        with self.assertRaises(NotesRefused):
            bridge.begin_compensation(forward, inverse, originals=(replacement, root, journal))
        self.assertFalse(native.calls)

    def test_dot_only_roster_batch_is_not_eof_and_does_not_reset_total(self):
        bridge, _, native = _bridge_fixture([
            {"token": 77},
            {"token": 77, "body": struct.pack("<II", 0, 8), "count": 0, "total": 0},
            {"status": 1, "token": 77, "count": 0, "total": 0},
        ])
        root = bridge._keep(101, "object", scope=3, logical=1, object_key=101)
        stream = bridge.begin_pass(root, directory=True)
        self.assertEqual(bridge.next_roster(stream), ())
        self.assertFalse(stream.complete)
        self.assertEqual(stream.total, 0)
        self.assertIsNone(bridge.next_roster(stream))
        self.assertTrue(stream.complete)
        self.assertEqual([row[0] for row in native.calls], [12, 13, 13])
        self.assertEqual(bridge._producer_calls, 3)

    def test_unframed_zero_row_ok_is_malformed_not_eof(self):
        bridge, _, _ = _bridge_fixture([{"token": 77}, {"token": 77, "count": 0, "total": 0}])
        root = bridge._keep(101, "object", scope=3, logical=1, object_key=101)
        stream = bridge.begin_pass(root, directory=True)
        with self.assertRaises(NotesUnknown):
            bridge.next_roster(stream)
        self.assertFalse(stream.complete)
        self.assertIs(bridge._pending, bridge._ordinary_frame)


# This finite in-memory object model tests COMMON ADAPTER routing, not NTFS.
# Actual ABI parsing/frame custody above and native platform qualification are
# deliberately separate risks; this fixture never opens a file or DLL.
def _move_scope_fixture(*, inverse=False, published=False, collision=False,
                        post_error=None, publish_post_error=None, terminal=False,
                        corrective_post_error=None):
    from types import SimpleNamespace
    from mobile_release._desktop_notes_windows import (
        _LogicalData, _MoveData, _NotesScope, _OriginalObject, _SecurityData,
        _decode_effect, _decode_observation,
    )
    bridge, boundary, _ = _bridge_fixture([])
    events, failures = [], []
    lease = SimpleNamespace(bridge=bridge, _run=lambda operation, *a, **k: operation(*a, **k))
    scope = _NotesScope(lease, 3)
    workspace = SimpleNamespace(
        _installing=False, _install_started=False,
        _publishing_terminal="COMMITTED" if terminal else None,
        _terminal_ambiguous=False, _terminal_seen=None, _terminal_durable=False,
        _reason="none", _notes_cleanup_errors=[], parents={})
    workspace._namespace_check = lambda **kwargs: None
    def remember(error):
        failures.append(error)
        bridge._failed = True
        if isinstance(error, NotesUnknown):
            bridge._unknown = bridge._wire_lost = True
    workspace._notes_failure = remember
    scope.workspace = workspace
    scope._workspace = lambda: workspace
    root_key = bridge._keep(201, "object", scope=3, logical=1, object_key=201)
    journal_key = bridge._keep(202, "object", scope=3, logical=9, object_key=202)
    object_key = bridge._keep(101, "object", scope=3, logical=16, object_key=101)
    root = _OriginalObject(root_key, _LogicalData(1, 1, 0, 0, 1, None, 107, "", ""),
                           False, "held", None)
    journal = _OriginalObject(journal_key, _LogicalData(9, 9, 1, 0, 1, None, 107, "journal", "journal"),
                              True, "held", (1, "journal"))
    original = _OriginalObject(object_key, _LogicalData(16, 16, 9, 65536, 4 | 8, None, 107,
                                                       "journal/new-0", "new-0"),
                               True, "held", (1, "note") if inverse else (9, "new-0"))
    scope._root = root
    scope._objects = {201: root, 202: journal, 101: original}
    scope._sources = {1: root}
    scope._created = {9: journal, 16: original}
    scope._declared_edges = {(1, "journal"), (1, "note"), (9, "new-0")}
    kind = 15 if terminal else 3 if collision else 13
    forward = _MoveData(77, 16, 101, 9, 1, 0 if terminal or collision else 78, 0, 0,
                         0 if terminal or collision else 501, kind,
                         2 if terminal else 1 if collision else 0, "new-0", "note")
    undo = _MoveData(78, 16, 101, 1, 9, 0, 77, 502, 0, 14, 8, "note", "new-0")
    scope._moves = (forward, undo)
    bridge._move_facts = {77: forward, 78: undo}
    scope._security = (_SecurityData(501, 16, 101, 502, 77, 91, 107, 1, 1),
                       _SecurityData(502, 16, 101, 501, 78, 91, 107, 2, 2))
    bridge._security_facts = {row.action_key: row for row in scope._security}
    model = SimpleNamespace(physical=original.location, security=32 if published else 16, observation=800)
    def observed(value):
        model.observation += 1
        edge = model.physical if value is original else value.location
        parent = 0 if edge is None else next(
            item.key.value for item in (root, journal) if item.row.logical_key == edge[0])
        raw = _epoch_record(value.key, model.observation, parent=parent,
                             name="" if edge is None else edge[1], directory=value is not original,
                             security=model.security if value is original else 16)
        data = _decode_observation(raw, owner=9, scope=3)
        return bridge._observation(value.key, data, operation=16)
    for index, value in enumerate((root, journal, original)):
        value.acknowledged = observed(value)
        _retained_pass(bridge, value.key, 701 + index, directory=value is not original)
    scope._refresh = lambda value, **kwargs: (value.acknowledged, None, ())
    scope._raw_pass = lambda value, **kwargs: (bridge._passes[value.key.value], None, ())
    scope._post_passes = lambda values: {value.key.value: bridge._passes[value.key.value] for value in values}
    def move(key, destination):
        row = bridge._move_facts[key.value]
        events.append((26, key.value))
        if not collision:
            model.physical = (row.to_parent_logical_key, row.to_name)
        return _decode_effect(_effect_bytes(26, operation_key=key.value, flags=11 if collision else 3),
                              owner=9, operation=26)
    def finish_move(key, object_pass, old, new, originals):
        events.append((27, key.value))
        if key.value == 77 and post_error is not None:
            if isinstance(post_error, ProtocolError):
                boundary.stopped = True
            raise post_error
        if key.value == 78 and corrective_post_error is not None:
            raise corrective_post_error
        if terminal:
            bridge._terminal_bits = 1024
        if key.value == 78 and bridge._recovery_mode == "corrective":
            bridge._corrective_inverse_finished = True
        return tuple(observed(scope._objects[key.value]) for key in originals)
    def security(key, *, publish):
        operation = 28 if publish else 29
        events.append((operation, key.value))
        model.security = 32 if publish else 16
        effect = _decode_effect(_effect_bytes(operation, operation_key=key.value),
                                owner=9, operation=operation)
        bridge._security_effects[key.value] = effect
        return effect
    def finish_security(key, *, publish, object_pass, parent, originals):
        events.append((30, key.value))
        if publish and publish_post_error is not None:
            raise publish_post_error
        return tuple(observed(scope._objects[value.value]) for value in originals)
    def observe(key, stream, *, accepted):
        events.append((16, key.value))
        return observed(scope._objects[key.value])
    def begin(forward_key, inverse_key, *, originals):
        boundary.before_notes_settlement()  # same preowned pair; no lifetime renewal
        events.append((36, inverse_key.value))
        bridge._recovery_mode = "corrective"
    bridge.move, bridge.finish_move = move, finish_move
    bridge.security, bridge.finish_security = security, finish_security
    bridge.observe, bridge.begin_compensation = observe, begin
    if published:
        bridge._security_effects[501] = _decode_effect(_effect_bytes(28, operation_key=501), owner=9, operation=28)
    def perform():
        source, destination = (root, journal) if inverse else (journal, root)
        row = undo if inverse else forward
        scope._perform_move(source, row.from_name, destination, row.to_name, None, directory=False)
    return SimpleNamespace(scope=scope, bridge=bridge, boundary=boundary, workspace=workspace,
                           original=original, model=model, events=events, failures=failures, perform=perform)


class WindowsNotesMoveLifecycleTests(unittest.TestCase):
    def test_forward_move_finishes27_before_actual_publish28_and30(self):
        fixture = _move_scope_fixture()
        fixture.perform()
        self.assertEqual(fixture.events, [(26, 77), (27, 77), (28, 501), (30, 501)])
        self.assertEqual(fixture.original.location, (1, "note"))
        self.assertEqual(fixture.model.security, 32)

    def test_inverse_restores_actual_published_security_before_moving(self):
        fixture = _move_scope_fixture(inverse=True, published=True)
        fixture.perform()
        self.assertEqual(fixture.events, [(29, 502), (30, 502), (26, 78), (27, 78)])
        self.assertEqual(fixture.original.location, (9, "new-0"))
        self.assertEqual(fixture.model.security, 16)

    def test_never_started28_uses_actual_private16_not_an_invented_setter(self):
        fixture = _move_scope_fixture(inverse=True)
        fixture.perform()
        self.assertEqual(fixture.events, [(16, 101), (26, 78), (27, 78)])
        self.assertNotIn(502, fixture.bridge._security_effects)

    def test_probe_candidate_is_file_exists_only_after_complete27(self):
        fixture = _move_scope_fixture(collision=True)
        with self.assertRaises(FileExistsError):
            fixture.perform()
        self.assertEqual(fixture.events, [(26, 77), (27, 77)])
        failure = RuntimeError("known full probe POST failed")
        fixture = _move_scope_fixture(collision=True, post_error=failure)
        with self.assertRaises(RuntimeError) as caught:
            fixture.perform()
        self.assertIs(caught.exception, failure)
        self.assertEqual(fixture.events, [(26, 77), (27, 77)])
        self.assertFalse(fixture.scope._corrective_attempted)

    def test_known_failed27_corrects_exact_original_and_rethrows_same_conflict(self):
        from mobile_release.init_transaction import InitConflict
        failure = InitConflict("fixture postcondition conflict")
        fixture = _move_scope_fixture(post_error=failure)
        with self.assertRaises(InitConflict) as caught:
            fixture.perform()
        self.assertIs(caught.exception, failure)
        self.assertEqual(fixture.events, [(26, 77), (27, 77), (36, 78), (16, 101), (26, 78), (27, 78)])
        self.assertIs(fixture.failures[0], failure)
        self.assertEqual(fixture.original.location, (9, "new-0"))
        self.assertTrue(fixture.bridge._corrective_inverse_finished)
        self.assertEqual(fixture.bridge._recovery_mode, "corrective")  # NOT an invented Joined.
        self.assertEqual(fixture.workspace._notes_cleanup_errors, [])

    def test_known_publish30_failure_requires_real_restore_before_corrective_inverse(self):
        failure = RuntimeError("fixture publish full POST failed")
        fixture = _move_scope_fixture(publish_post_error=failure)
        with self.assertRaises(RuntimeError) as caught:
            fixture.perform()
        self.assertIs(caught.exception, failure)
        self.assertEqual(fixture.events, [(26, 77), (27, 77), (28, 501), (30, 501),
                                          (36, 78), (29, 502), (30, 502), (26, 78), (27, 78)])
        self.assertEqual(fixture.model.security, 16)

    def test_corrective_failure_is_retained_without_replacing_primary_or_claiming_join(self):
        first, corrective = RuntimeError("fixture first"), RuntimeError("fixture inverse POST")
        fixture = _move_scope_fixture(post_error=first, corrective_post_error=corrective)
        with self.assertRaises(RuntimeError) as caught:
            fixture.perform()
        self.assertIs(caught.exception, first)
        self.assertEqual(fixture.workspace._notes_cleanup_errors, [corrective])
        self.assertEqual(fixture.failures, [first, corrective])
        self.assertFalse(fixture.bridge._corrective_inverse_finished)
        self.assertFalse(fixture.bridge._recovery_joined)

    def test_unknown_and_terminal_forbid_correction_but_stop_preserves_preowned_inverse(self):
        unknown = _move_scope_fixture(post_error=NotesUnknown("fixture unknown DATA"))
        with self.assertRaises(NotesUnknown):
            unknown.perform()
        self.assertEqual(unknown.events, [(26, 77), (27, 77)])
        stopped = _move_scope_fixture(post_error=ProtocolError("fixture STOP before POST"))
        with self.assertRaises(ProtocolError):
            stopped.perform()
        self.assertEqual(stopped.events, [(26, 77), (27, 77), (36, 78), (16, 101), (26, 78), (27, 78)])
        self.assertEqual(stopped.workspace._notes_cleanup_errors, [])
        self.assertFalse(stopped.bridge._recovery_joined)  # still rethrows STOP, not Save/Joined
        expired = _move_scope_fixture(post_error=ProtocolError("fixture STOP after original deadline"))
        expired.boundary.settlement_expired = True
        with self.assertRaises(ProtocolError):
            expired.perform()
        self.assertEqual(expired.events, [(26, 77), (27, 77)])
        self.assertEqual(len(expired.workspace._notes_cleanup_errors), 1)
        terminal = _move_scope_fixture(terminal=True, post_error=RuntimeError("fixture terminal POST"))
        with self.assertRaises(RuntimeError):
            terminal.perform()
        self.assertEqual(terminal.events, [(26, 77), (27, 77)])
        self.assertTrue(terminal.workspace._terminal_ambiguous)



class WindowsNotesCoreFailureCustodyTests(unittest.TestCase):
    def test_observed_clock_expiry_uses_existing_reason19_without_replacing_first_failure(self):
        from types import SimpleNamespace
        from mobile_release._desktop_notes_windows import _NotesLease
        bridge, boundary, native = _bridge_fixture([{"first_failure": 13}])
        bridge._failed, bridge._first_failure = True, 13
        first_return = object()
        bridge._first_failure_return = first_return
        lease = object.__new__(_NotesLease)
        lease.owner = SimpleNamespace(guard=SimpleNamespace(cancelled=True))
        lease.input = SimpleNamespace(_notes_deadline_reached=True)
        lease.bridge = bridge
        lease.check_lease_binding = lambda owner: None
        lease.record_core_failure(ProtocolError("actual clock expiry observed before this hook"))
        self.assertEqual([row[0] for row in native.calls], [35])
        self.assertEqual(bridge._last_frame.request.number, 19)
        self.assertEqual(bridge._first_failure, 13)
        self.assertIs(bridge._first_failure_return, first_return)
        self.assertEqual(boundary.boundaries, ["finality"])

    def test_outer_core_hook_preserves_known_return_unknown_but_not_malformed_data(self):
        from types import SimpleNamespace
        from mobile_release._desktop_notes_windows import _NotesLease
        bridge, boundary, native = _bridge_fixture([
            {"status": 4, "error": 36, "first_failure": 36, "flags": 1},
            {"status": 0, "first_failure": 36, "flags": 1},
        ])
        lease = object.__new__(_NotesLease)
        aborted = []
        lease.owner = SimpleNamespace(guard=SimpleNamespace(_abort=aborted.append))
        lease.bridge = bridge
        lease.check_lease_binding = lambda owner: None
        with self.assertRaises(NotesUnknown) as caught:
            bridge.check_lease()
        primary = caught.exception
        lease.record_core_failure(primary)
        self.assertIs(bridge._known_unknown_error, primary)
        self.assertIsNone(bridge._pending)
        self.assertFalse(bridge._wire_lost)
        self.assertTrue(bridge._unknown)
        bridge.status()
        self.assertEqual([row[0] for row in native.calls], [3, 41])
        self.assertEqual(boundary.boundaries, ["ordinary", "finality"])
        malformed = NotesUnknown("a later original DATA association is invalid")
        lease.record_core_failure(malformed)
        self.assertTrue(bridge._wire_lost)
        with self.assertRaises(NotesUnknown):
            bridge.status()
        self.assertEqual(len(native.calls), 2)
        self.assertEqual(aborted, [primary, malformed])


def _absent_leaf_scope_fixture(*, malformed_leaf=False):
    """Finite DATA model: real common observe/parent/source-absence routing."""
    from types import SimpleNamespace
    from mobile_release._desktop_notes_windows import _LogicalData, _NotesScope, _OriginalObject
    from mobile_release.init_transaction import InitWorkspace
    def absence(*, fact, original, parent, name, roster=0, parent_absence=0):
        encoded = name.encode("utf-8")
        raw = bytearray(160 + len(encoded))
        raw[:8] = b"MRKNPF1\0"
        struct.pack_into("<IIQII", raw, 8, 160, 2, 9, 3, 2 if parent_absence else 1)
        struct.pack_into("<7Q", raw, 32, fact, original, parent,
                         0 if parent_absence else 801, 1, roster, fact + 100)
        raw[88:120] = b"a" * 32
        struct.pack_into("<4IQ", raw, 136, 0, 0, len(encoded), 0, parent_absence)
        raw[160:] = encoded
        return _batch(bytes(raw))
    bridge, boundary, native = _bridge_fixture([
        {"token": 601, "count": 1, "total": 1,
         "body": absence(fact=601, original=202, parent=201, name="notes", roster=701)},
        {"token": 602, "count": 1, "total": 1,
         "body": absence(fact=602, original=101, parent=202, name="release.txt",
                         parent_absence=999 if malformed_leaf else 601)},
    ])
    lease = SimpleNamespace(bridge=bridge, _run=lambda operation, *a, **k: operation(*a, **k))
    scope = _NotesScope(lease, 3)
    workspace = object.__new__(InitWorkspace)
    workspace._notes = scope
    workspace._guard = None
    workspace._checkpoint = lambda: None
    workspace.parents = {"notes": None}
    workspace._parent_facts = {}
    workspace._captured = {}
    workspace._raw_observations = {}
    workspace.observed_bytes = 0
    scope.workspace = workspace
    scope._workspace = lambda: workspace
    root_key = bridge._keep(201, "object", scope=3, logical=1, object_key=201)
    parent_key = bridge._keep(202, "object", scope=3, logical=2, object_key=202)
    leaf_key = bridge._keep(101, "object", scope=3, logical=3, object_key=101)
    root = _OriginalObject(root_key, _LogicalData(1, 1, 0, 0, 1, None, 107, "", ""),
                           False, "held", None)
    parent = _OriginalObject(parent_key, _LogicalData(3, 2, 1, 0, 1, None, 107, "notes", "notes"),
                             False, "declared", (1, "notes"))
    leaf = _OriginalObject(leaf_key, _LogicalData(7, 3, 2, 65536, 0, None, 107,
                                                "notes/release.txt", "release.txt"),
                           False, "declared", (2, "release.txt"))
    scope._root = root
    scope._sources = {1: root, 2: parent, 3: leaf}
    scope._objects = {201: root, 202: parent, 101: leaf}
    scope._rows = {value.row.logical_key: value.row for value in (root, parent, leaf)}
    scope._paths = {value.row.path: value.row.logical_key for value in (root, parent, leaf)}
    scope._declared_edges = {(1, "notes"), (2, "release.txt")}
    root_pass = _retained_pass(bridge, root_key, 701, directory=True)
    scope._refresh = lambda original, **kwargs: (None, None, ())
    scope._raw_pass = lambda original, **kwargs: (root_pass, None, ())
    acquisitions = []
    def refuse_acquisition(*args):
        acquisitions.append(args)
        raise AssertionError("an original absent-parent chain must never acquire a child")
    bridge.acquire_object = refuse_acquisition
    return SimpleNamespace(scope=scope, bridge=bridge, boundary=boundary, native=native,
                           workspace=workspace, parent=parent, leaf=leaf, acquisitions=acquisitions)


class WindowsNotesMissingParentTests(unittest.TestCase):
    def test_common_observe_finishes_exact_leaf_absence_before_returning_none(self):
        fixture = _absent_leaf_scope_fixture()
        observed = fixture.workspace.observe("notes/release.txt", limit=65536)
        self.assertIsNone(observed.before)
        self.assertIsNone(observed.data)
        self.assertEqual(fixture.leaf.state, "absent")
        self.assertIs(fixture.leaf.absence.object, fixture.leaf.key)
        self.assertEqual(fixture.leaf.absence.data.original_parent_absent_key,
                         fixture.parent.absence.key.value)
        self.assertEqual([row[0] for row in fixture.native.calls], [14, 14])
        self.assertFalse(fixture.acquisitions)
        self.assertEqual(fixture.scope._borrow_count, 0)
        # A second traversal may reuse only that authentic original proof.
        with fixture.scope.parent("notes/release.txt") as parent:
            self.assertIsNone(parent)
        self.assertEqual([row[0] for row in fixture.native.calls], [14, 14])

    def test_stop_or_lost_frame_cannot_turn_declared_leaf_into_absence(self):
        for stopped in (True, False):
            with self.subTest(stopped=stopped):
                fixture = _absent_leaf_scope_fixture()
                fixture.scope._ensure_source(2)  # original parent14 already returned
                if stopped:
                    fixture.boundary.stopped = True
                else:
                    fixture.bridge._wire_lost = True
                with self.assertRaises(ProtocolError if stopped else NotesUnknown):
                    fixture.workspace.observe("notes/release.txt", limit=65536)
                self.assertEqual(fixture.leaf.state, "declared")
                self.assertIsNone(fixture.leaf.absence)
                self.assertNotIn("notes/release.txt", fixture.workspace._captured)
                self.assertEqual([row[0] for row in fixture.native.calls], [14])
                self.assertFalse(fixture.acquisitions)

    def test_undeclared_held_or_borrowed_absence_never_becomes_leaf_proof(self):
        from mobile_release._desktop_notes_windows import NotesRefused
        from mobile_release.init_transaction import InitConflict
        for variant, error in (("undeclared", NotesRefused), ("held", InitConflict),
                               ("borrowed_parent_proof", NotesUnknown)):
            with self.subTest(variant=variant):
                fixture = _absent_leaf_scope_fixture()
                fixture.scope._ensure_source(2)
                if variant == "undeclared":
                    del fixture.scope._paths["notes/release.txt"]
                elif variant == "held":
                    fixture.leaf.state = "held"
                else:
                    fixture.leaf.state = "absent"
                    fixture.leaf.absence = fixture.parent.absence
                with self.assertRaises(error):
                    fixture.workspace.observe("notes/release.txt", limit=65536)
                self.assertEqual([row[0] for row in fixture.native.calls], [14])
                self.assertNotIn("notes/release.txt", fixture.workspace._captured)
                self.assertFalse(fixture.acquisitions)

    def test_wrong_returned_parent_absence_key_is_unknown_not_an_absent_leaf(self):
        fixture = _absent_leaf_scope_fixture(malformed_leaf=True)
        with self.assertRaises(NotesUnknown):
            fixture.workspace.observe("notes/release.txt", limit=65536)
        self.assertEqual(fixture.leaf.state, "declared")
        self.assertIsNone(fixture.leaf.absence)
        self.assertTrue(fixture.bridge._wire_lost)
        self.assertNotIn("notes/release.txt", fixture.workspace._captured)
        self.assertEqual([row[0] for row in fixture.native.calls], [14, 14])
        self.assertFalse(fixture.acquisitions)

    def test_cached_absence_still_rechecks_root_through_real_stop_and_loss_guard(self):
        from mobile_release._desktop_notes_windows import _NotesScope
        for stopped in (True, False):
            with self.subTest(stopped=stopped):
                fixture = _absent_leaf_scope_fixture()
                fixture.workspace.observe("notes/release.txt", limit=65536)
                proof = fixture.leaf.absence
                # Restore the actual first-ancestor raw-pass path. The guard
                # must refuse before any new scripted native entry or receipt.
                fixture.scope._refresh = _NotesScope._refresh.__get__(fixture.scope)
                fixture.scope._raw_pass = _NotesScope._raw_pass.__get__(fixture.scope)
                if stopped:
                    fixture.boundary.stopped = True
                else:
                    fixture.bridge._wire_lost = True
                with self.assertRaises(ProtocolError if stopped else NotesUnknown):
                    with fixture.scope.parent("notes/release.txt"):
                        self.fail("cached absence must not bypass original root admission")
                self.assertIs(fixture.leaf.absence, proof)
                self.assertEqual([row[0] for row in fixture.native.calls], [14, 14])
                self.assertEqual(fixture.scope._borrow_count, 0)
                self.assertFalse(fixture.acquisitions)
