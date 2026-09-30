"""Focused B1/B2 actual-helper DATA fixtures; no native supplier qualification.

Only fixed ABI functions are faked. No real HANDLE, process, descriptor or
standard stream is closed. These tests do not authorize a runtime/backend.
Production has no fixture reset, substitute owner or alternate loader entry.
"""
import ctypes
import _io
import time
from contextlib import ExitStack
import os
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _desktop_image_writer_windows as m


class Function:
    def __init__(self, call):
        self.call = call
        self.argtypes = self.restype = None

    def __call__(self, *args):
        return self.call(*args)


class Dll:
    def __init__(self):
        self.Request, self.Reply, self.Info = m._types(ctypes)
        self.calls = []
        self.events = []
        self.bad_info = False
        self.bad_return = False
        self.fail = None
        self.next_token = 1
        self.reads = 0
        self.begun = False
        self.sequence = 0
        self.unknown_facts = False
        self.bad_effect = False
        self.accepted_disposition_failure = False
        self.pending_deletion = False
        self.disposition_closed = False
        self.mrk_iw_v1_info = Function(self.info)
        self.mrk_iw_v1_call = Function(self.call)

    def info(self, destination, size):
        value = ctypes.cast(destination, ctypes.POINTER(self.Info)).contents
        values = (168, 1, 64, 80, 8, 8, 65536, 65536, 38, 16, 38, 32,
                  512 * 1024, 18, m._LAYOUT_TAG, 0)
        for (name, _), number in zip(self.Info._fields_[:16], values):
            setattr(value, name, number)
        value.request_offsets[:] = [0, 4, 8, 12, 16, 24, 32, 40, 48, 52, 56, 60]
        value.reply_offsets[:] = [0, 4, 8, 12, 16, 24, 32, 40, 48, 52, 56, 60, 64, 68]
        if self.bad_info:
            value.version = 2
        return m._OK

    def call(self, request, source, reply, output):
        r = ctypes.cast(request, ctypes.POINTER(self.Request)).contents
        value = ctypes.cast(reply, ctypes.POINTER(self.Reply)).contents
        self.calls.append(r.operation)
        self.events.append("dll")
        if self.fail == r.operation:
            raise OSError("fixed simulated native-call uncertainty")
        value.size, value.version, value.status = 80, 1, m._OK
        value.owner = (os.getpid() << 32) | 1
        if r.operation not in (1, 18):
            self.sequence += 1
            value.flags = 8 | 16
        if self.begun:
            value.flags |= 64
        value.sequence = self.sequence
        value.first_failure = 35 if self.pending_deletion else 0
        data = b""
        if r.operation == 1:
            wire = ctypes.string_at(source, r.input_len)
            child, moves, deletes = struct.unpack_from("<III", wire, 8)
            rows = []
            for kind, count in enumerate((child + 1, moves, deletes), 1):
                for index in range(count):
                    rows.append(struct.pack("<IIQ", kind, index, self.next_token))
                    self.next_token += 1
            data = b"".join(rows)
            value.count = value.total = len(rows)
        elif r.operation == 2:
            self.begun = True
            value.flags |= 64
        elif r.operation in (4, 5):
            value.token = self.next_token
            self.next_token += 1
        elif r.operation == 6:
            self.reads += 1
            if self.reads == 1:
                data = b"bounded image bytes"
            elif self.reads == 2:
                value.status = m._EOF
            else:
                value.status, value.error = m._REFUSED, 4
        elif r.operation == 7:
            name = b"keep.png"
            data = struct.pack("<IIII16s", 2, 32, len(name), 0, b"x" * 16) + name
            value.count = 1
        elif r.operation == 13 and self.accepted_disposition_failure:
            # Fixed DATA fixture: accepted disposition, then known failed check.
            self.pending_deletion = True
            value.status, value.error, value.first_failure = m._FAILED, 35, 35
        elif r.operation == 14 and self.pending_deletion:
            self.disposition_closed = True
        elif r.operation == 17:
            if self.pending_deletion:
                # Original parent/context remain protected: retirement is no substitute.
                value.status, value.error = m._UNKNOWN, 36
                value.flags |= 32
                self.unknown_facts = True
            else:
                value.flags |= 2 | 4
        elif r.operation == 18:
            value.flags = 32 if self.unknown_facts else 0
            if r.number == 1:
                data = struct.pack("<12Q", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 131072, self.sequence)
            elif r.number == 2:
                data = struct.pack("<8I4Q", 4, 0, 1 | 8 | 16 | 32, 1, 0, 0, 0,
                                   1 if self.bad_effect else 0, 4, 0, 0, 0)
                value.count = value.total = 1
            elif r.number == 6:
                data = struct.pack("<Q16s", 7, b"i" * 16)
        if self.bad_return:
            value.version = 2
        value.output_len = len(data)
        if data:
            ctypes.memmove(output, data, len(data))
        return value.status


class OriginalGuard:
    """One original boundary DATA fixture, no clock or refresh/retry API."""
    def __init__(self, dll):
        self.dll = dll
        self.stop = False
        self.hard_deadline_expired = False
        self.custody_valid = True

    def producing(self):
        self._admit("guard")
        if self.stop:
            raise m.BridgeRefused("fixed cooperative STOP")

    def settlement(self):
        self._admit("settlement")  # STOP does not revoke an otherwise valid once-close.

    def _admit(self, event):
        self.dll.events.append(event)
        if self.hard_deadline_expired or not self.custody_valid:
            raise m.BridgeRefused("fixed original custody/deadline refusal")


class WindowsImageCallerTests(unittest.TestCase):
    def setUp(self):
        # Test fixture only: each fake has no native DLL/book or global effects.
        self.data_owners = []
        self.patchers = [
            patch.object(m, "_ATTEMPTED", False),
            patch.object(m, "_RETAINED_DLL", None),
            patch.object(m, "_RETAINED_OWNER", None),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def open(self, dll=None, guard=None, settlement_guard=None, *, check_abi=True):
        # B1's historical wire tests construct the real inert adapter directly.
        # They do NOT claim a completed production bootstrap, authorize a load,
        # or weaken the new exact EditInput-bound production factory.
        dll = dll or Dll()
        if guard is None:
            guard = lambda: dll.events.append("guard")
        if settlement_guard is None:
            settlement_guard = lambda: dll.events.append("settlement")
        owner = m._Bridge(ctypes, dll, *m._types(ctypes), guard, settlement_guard)
        self.data_owners.append(owner)
        if check_abi:
            owner._check_abi()
        return owner, dll

    def test_import_and_off_image_do_not_load_or_fall_back(self):
        self.assertNotIn("ctypes", m.__dict__)
        with patch.object(ctypes, "WinDLL", create=True) as load:
            with self.assertRaises(m.BridgeRefused):
                m._open_for_original_image_child(
                    domain="configuration", installed_python="x", before_entry=lambda: None,
                    before_settlement=lambda: None)
            load.assert_not_called()
        self.assertFalse(m._ATTEMPTED)

    def test_fixed_loader_argtypes_layout_and_strong_original(self):
        owner, dll = self.open()
        self.assertIs(owner._dll, dll)
        self.assertIs(self.data_owners[-1], owner)
        self.assertIsNone(m._RETAINED_OWNER)
        self.assertIsNone(m._RETAINED_DLL)
        self.assertEqual(len(dll.mrk_iw_v1_call.argtypes), 4)
        self.assertIs(dll.mrk_iw_v1_call.restype, ctypes.c_uint32)
        self.assertEqual(ctypes.sizeof(owner._Request), 64)
        self.assertEqual(ctypes.sizeof(owner._Reply), 80)
        self.assertEqual(ctypes.sizeof(owner._Info), 168)
        self.assertEqual(dll.calls, [])

    def test_bad_abi_keeps_exact_inert_adapter_info_and_module(self):
        dll = Dll()
        dll.bad_info = True
        owner, _ = self.open(dll, check_abi=False)
        with patch.object(ctypes, "WinDLL", create=True) as load:
            with self.assertRaises(m.BridgeUnknown):
                owner._check_abi()
            load.assert_not_called()
        self.assertIs(owner._dll, dll)
        self.assertTrue(owner._unknown)
        self.assertIsNotNone(owner._info_pending)
        self.assertEqual(owner._info_pending.version, 2)
        self.assertEqual(dll.calls, [])

    def test_plan_closed_shape_ascii_tags_and_capacity(self):
        data = m._plan_bytes(r"C:\project", (), (), ())
        self.assertEqual(data, b"MRKIW1\0\0" + struct.pack("<IIII", 0, 0, 0, 10) + b"C:\\project")
        for children in (((0, 11, "x"),), ((0, 9, "é"),), ((False, 9, "x"),), tuple((0, 9, "x") for _ in range(39))):
            with self.assertRaises(m.BridgeRefused):
                m._plan_bytes(r"C:\project", children, (), ())
        with self.assertRaises(m.BridgeRefused):
            m._plan_bytes(r"C:\project", [], (), ())

    def test_prepare_actual_opaque_graph_and_cross_owner_refusal(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project", ((0, 2, "images"), (1, 9, "new.png")))
        self.assertEqual(len(owner._images), 3)
        owner.begin()
        token = owner.image_key(2)
        foreign = m._Token(object(), token._value, 1, 2)
        before = tuple(dll.calls)
        with self.assertRaises(m.BridgeRefused):
            owner.acquire(foreign)
        self.assertEqual(tuple(dll.calls), before)
        with self.assertRaises(m.BridgeRefused):
            owner.prepare(r"C:\different")
        owner.acquire(token)
        self.assertEqual(dll.calls[-1], 3)

    def test_pass_eof_and_repeated_original_refusal_not_new_lease(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        owner.begin()
        key = owner.begin_read(owner.image_key(0))
        self.assertEqual(owner.read_next(key), b"bounded image bytes")
        self.assertIsNone(owner.read_next(key))
        with self.assertRaises(m.BridgeRefused):
            owner.read_next(key)
        self.assertFalse(owner._unknown)
        self.assertEqual(owner._pass_count, 1)
        self.assertEqual(dll.calls[-3:], [6, 6, 6])

    def test_roster_is_closed_data_and_not_a_path_permission(self):
        owner, _ = self.open()
        owner.prepare(r"C:\project")
        owner.begin()
        key = owner.begin_roster(owner.image_key(0))
        values = owner.roster_next(key)
        self.assertEqual(values, ((2, 32, b"x" * 16, "keep.png"),))
        self.assertIsInstance(values, tuple)

    def test_input_capacity_refuses_before_fixed_entry(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        owner.begin()
        before = len(dll.calls)
        with self.assertRaises(m.BridgeRefused):
            owner.write_chunk(owner.image_key(0), b"x" * 65537)
        self.assertEqual(len(dll.calls), before)

    def test_unknown_keeps_exact_original_frame_and_no_close_retry(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        owner.begin()
        dll.fail = 3
        with self.assertRaises(m.BridgeUnknown):
            owner.acquire(owner.image_key(0))
        pending = owner._pending
        self.assertIsNotNone(pending)
        before = len(dll.calls)
        with self.assertRaises(m.BridgeUnknown):
            owner.retire_handles()
        self.assertEqual(len(dll.calls), before)
        self.assertIs(owner._pending, pending)
        self.assertIs(self.data_owners[-1], owner)
        self.assertIs(owner._dll, dll)
        dll.unknown_facts = True
        values = owner.observe()
        self.assertEqual(len(values), 1)
        self.assertTrue(owner._unknown)
        self.assertIs(owner._pending, pending)

    def test_failed_data_observation_frame_is_not_replaced(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        dll.fail = 18
        with self.assertRaises(m.BridgeUnknown):
            owner.observe()
        pending = owner._observation_pending
        before = len(dll.calls)
        with self.assertRaises(m.BridgeUnknown):
            owner.observe()
        self.assertIs(owner._observation_pending, pending)
        self.assertEqual(len(dll.calls), before)

    def test_guard_precedes_entry_and_no_post_return_callback(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        dll.events.clear()
        owner.begin()
        self.assertEqual(dll.events, ["guard", "dll"])
        self.assertIsNotNone(owner._last_reply)
        self.assertIsNone(owner._pending)

    def test_malformed_actual_return_stays_rooted_and_unknown(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        dll.bad_return = True
        with self.assertRaises(m.BridgeUnknown):
            owner.begin()
        self.assertEqual(owner._last_reply.version, 2)
        self.assertIsNotNone(owner._pending)
        self.assertTrue(owner._unknown)

    def test_observation_presence_and_reserved_fields_are_checked(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        values = owner.observe(2)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0][0], 4)
        dll.bad_effect = True
        with self.assertRaises(m.BridgeUnknown):
            owner.observe(2)
        self.assertIsNotNone(owner._observation_pending)

    def test_retirement_is_handle_fact_not_transaction_success(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        owner.retire_handles()
        self.assertTrue(owner._retired)
        self.assertEqual(owner._last_reply.flags & 2, 2)
        before = len(dll.calls)
        with self.assertRaises(m.BridgeUnknown):
            owner.retire_handles()
        self.assertEqual(len(dll.calls), before)


    def test_settlement_boundary_is_mandatory_before_any_activation(self):
        with patch.object(ctypes, "WinDLL", create=True) as load:
            with self.assertRaises(m.BridgeRefused):
                m._open_for_original_image_child(
                    domain="metadata_images", installed_python=r"C:\versions\fixed\python\python.exe",
                    before_entry=lambda: None, before_settlement=object())
            load.assert_not_called()
        self.assertFalse(m._ATTEMPTED)
        self.assertIsNone(m._RETAINED_DLL)

    def test_closed_operation_routing_refuses_before_any_guard_or_native_entry(self):
        owner, dll = self.open()
        owner.prepare(r"C:\project")
        before = tuple(dll.calls)
        dll.events.clear()
        for operation in (0, 19, True):
            with self.assertRaises(m.BridgeRefused):
                owner._invoke(operation)
        self.assertEqual(tuple(dll.calls), before)
        self.assertEqual(dll.events, [])
        self.assertEqual(m._SETTLEMENT_OPERATIONS, (14, 16, 17))

    def test_stop_vetoes_producing_but_allows_original_once_close_and_retire(self):
        dll = Dll()
        guard = OriginalGuard(dll)
        owner, _ = self.open(dll, guard.producing, guard.settlement)
        self.assertIs(owner._before_entry.__self__, guard)
        self.assertIs(owner._before_settlement.__self__, guard)
        owner.prepare(r"C:\project")
        owner.begin()
        key = owner.image_key(0)
        guard.stop = True
        dll.events.clear()
        before = tuple(dll.calls)
        with self.assertRaises(m.BridgeRefused):
            owner.acquire(key)
        self.assertEqual(tuple(dll.calls), before)
        owner.close(key)
        owner.retire_handles()
        self.assertEqual(dll.calls[-2:], [16, 17])
        self.assertEqual(dll.events, ["guard", "settlement", "dll", "settlement", "dll"])
        self.assertTrue(owner._retired)
        self.assertIsNone(owner._pending)
        before = tuple(dll.calls)
        with self.assertRaises(m.BridgeUnknown):
            owner.retire_handles()
        self.assertEqual(tuple(dll.calls), before)

    def test_accepted_disposition_known_failure_stop_still_allows_only_its_once_close(self):
        dll = Dll()
        guard = OriginalGuard(dll)
        owner, _ = self.open(dll, guard.producing, guard.settlement)
        owner.prepare(r"C:\project", ((0, 8, "new-a"),), deletes=((1, 0, "new-a"),))
        owner.begin()
        deletion = owner.delete_key(0)
        dll.accepted_disposition_failure = True
        with self.assertRaises(m.BridgeFailure):
            owner.dispose(deletion)
        self.assertTrue(dll.pending_deletion)
        self.assertTrue(owner._failed)
        self.assertFalse(owner._unknown)
        guard.stop = True
        dll.events.clear()
        before = tuple(dll.calls)
        # Closed forward opcodes are vetoed even before any operand can be resolved.
        for operation in (13, 15):
            with self.assertRaises(m.BridgeUnknown):
                owner._invoke(operation, a=deletion._value)
        self.assertEqual(tuple(dll.calls), before)
        self.assertEqual(dll.events, [])
        owner.close_disposed(deletion)
        self.assertTrue(dll.disposition_closed)
        self.assertEqual(dll.calls.count(14), 1)
        self.assertEqual(owner._last_reply.first_failure, 35)
        self.assertEqual(dll.events, ["settlement", "dll"])
        self.assertIsNone(owner._pending)
        # The protected pending parent/namespace cannot be replaced by "retire".
        with self.assertRaises(m.BridgeUnknown):
            owner.retire_handles()
        self.assertEqual(dll.calls[-1], 17)
        self.assertFalse(owner._last_reply.flags & 2)
        self.assertIsNotNone(owner._pending)
        original = owner._pending
        before = tuple(dll.calls)
        with self.assertRaises(m.BridgeUnknown):
            owner.close_disposed(deletion)
        self.assertEqual(tuple(dll.calls), before)
        self.assertIs(owner._pending, original)
        self.assertEqual(dll.calls.count(14), 1)

    def test_stop_does_not_refresh_the_original_hard_deadline_for_settlement(self):
        dll = Dll()
        guard = OriginalGuard(dll)
        owner, _ = self.open(dll, guard.producing, guard.settlement)
        owner.prepare(r"C:\project")
        owner.begin()
        guard.stop = guard.hard_deadline_expired = True
        before = tuple(dll.calls)
        original_reply = owner._last_reply
        dll.events.clear()
        for operation in (14, 16, 17):
            with self.assertRaises(m.BridgeRefused):
                owner._invoke(operation)
        self.assertEqual(tuple(dll.calls), before)
        self.assertEqual(dll.events, ["settlement"] * 3)
        self.assertIs(owner._last_reply, original_reply)
        self.assertIsNone(owner._pending)
        self.assertFalse(owner._retired)

    def test_stop_does_not_replace_expired_original_custody_for_settlement(self):
        dll = Dll()
        guard = OriginalGuard(dll)
        owner, _ = self.open(dll, guard.producing, guard.settlement)
        owner.prepare(r"C:\project")
        owner.begin()
        guard.stop = True
        guard.custody_valid = False
        before = tuple(dll.calls)
        dll.events.clear()
        for operation in (14, 16, 17):
            with self.assertRaises(m.BridgeRefused):
                owner._invoke(operation)
        self.assertEqual(tuple(dll.calls), before)
        self.assertEqual(dll.events, ["settlement"] * 3)
        self.assertIsNone(owner._pending)
        self.assertFalse(owner._unknown)

    def test_returned_settlement_is_retained_before_later_deadline_refusal(self):
        dll = Dll()
        guard = OriginalGuard(dll)
        owner, _ = self.open(dll, guard.producing, guard.settlement)
        owner.prepare(r"C:\project")
        owner.begin()
        guard.stop = True
        actual_call = dll.mrk_iw_v1_call.call

        def call_then_expire(*arguments):
            status = actual_call(*arguments)
            guard.hard_deadline_expired = True
            return status

        dll.mrk_iw_v1_call.call = call_then_expire
        dll.events.clear()
        owner.close(owner.image_key(0))
        self.assertEqual(dll.events, ["settlement", "dll"])
        self.assertEqual(owner._returned_status, m._OK)
        self.assertTrue(owner._last_reply.flags & 16)
        self.assertIsNone(owner._pending)
        original_reply = owner._last_reply
        before = tuple(dll.calls)
        with self.assertRaises(m.BridgeRefused):
            owner.retire_handles()
        self.assertEqual(tuple(dll.calls), before)
        self.assertIs(owner._last_reply, original_reply)

class StdioDll(Dll):
    """Scripted fixed ABI DATA, never a syscall or numerical HANDLE owner."""
    def __init__(self):
        super().__init__()
        self.SRequest, self.SReply, self.SInfo = m._stdio_types(ctypes)
        self.stdio_frames = []
        self.stdio_calls = []
        self.stdio_bad_info = False
        self.mrk_stdio_v1_info = Function(self.stdio_info)
        self.mrk_stdio_v1_call = Function(self.stdio_call)

    def queue(self, operation, role=0, **fields):
        self.stdio_frames.append((operation, role, fields))

    def stdio_info(self, destination, size):
        value = ctypes.cast(destination, ctypes.POINTER(self.SInfo)).contents
        value.fields[:] = (148, 1, 40, 80, 8, 8, 65536, 14, 0x49533131,
                           512 * 1024, 131072, 1024, 96, 3, 0, 0)
        value.request_offsets[:] = (0, 4, 8, 12, 16, 24, 28, 32)
        value.reply_offsets[:] = (0, 4, 8, 12, 16, 24, 28, 32, 36, 40, 64, 68, 72)
        if self.stdio_bad_info:
            value.fields[7] = 18  # B1 is not the stdio ABI.
        return m._STD_IDLE

    def stdio_call(self, request, source, reply, output):
        r = ctypes.cast(request, ctypes.POINTER(self.SRequest)).contents
        value = ctypes.cast(reply, ctypes.POINTER(self.SReply)).contents
        payload = ctypes.string_at(source, r.length) if r.operation in (7, 12) else b""
        self.stdio_calls.append((r.operation, r.role, r.generation, r.length, r.capacity, payload))
        self.events.append(("stdio", r.operation, r.role))
        assert self.stdio_frames, "unexpected fixed ABI entry"
        operation, role, fields = self.stdio_frames.pop(0)
        assert (r.operation, r.role) == (operation, role)
        fields = dict(fields)
        error = fields.pop("exception", None)
        if error is not None:
            raise error
        data = fields.pop("data", b"")
        returned_status = fields.pop("return_status", None)
        value.size, value.version, value.status = 80, 1, m._STD_IDLE
        value.output_len = len(data)
        for name, number in fields.items():
            if name == "mappings":
                value.mappings[:] = number
            elif name == "reserved":
                value.reserved[:] = number
            else:
                setattr(value, name, number)
        assert len(data) <= r.capacity
        if data:
            ctypes.memmove(output, data, len(data))
        return value.status if returned_status is None else returned_status


class StdioBoundaryData:
    """Boundary callbacks ONLY for isolated adapter tests; real factory rejects this."""
    def __init__(self):
        self.cleanup = False
        self.terminals = 0

    def _image_native_boundary(self, *, settlement=False, terminal=False):
        if self.cleanup and not settlement:
            raise KeyboardInterrupt

    def _image_endpoint(self):
        return 111.0 if self.cleanup else 130.0

    def _image_cleanup_started(self):
        self.cleanup = True

    def before_image_entry(self):
        self._image_native_boundary()

    def _image_handoff_check(self):
        self._image_native_boundary()

    def _image_terminal_started(self):
        self.terminals += 1
        self.cleanup = True

    def _image_terminal_check(self):
        self._image_native_boundary(settlement=True, terminal=True)


class SupplierRaw:
    """No OS descriptor exists: closing these DATA chains only sets booleans."""
    def __init__(self, number, events):
        self.number, self.events = number, events
        self.closefd, self.closed = False, False

    def fileno(self):
        return self.number

    def close(self):
        self.events.append(("raw-close", self.number))
        self.closed = True


class SupplierReader:
    def __init__(self, raw):
        self.raw, self.closed = raw, False

    def fileno(self):
        return self.raw.fileno()

    def close(self):
        self.raw.close()
        self.closed = True


class SupplierWriter(SupplierReader):
    pass


class SupplierText:
    def __init__(self, buffer):
        self.buffer, self.closed = buffer, False

    def fileno(self):
        return self.buffer.fileno()

    def close(self):
        self.buffer.close()
        self.closed = True


class WindowsImageStdioTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.now = self.stack.enter_context(patch.object(time, "monotonic", return_value=101.0))
        for name, value in (("_ATTEMPTED", False), ("_STDIO_ATTEMPTED", False),
                            ("_RETAINED_DLL", None), ("_RETAINED_STDIO", None),
                            ("_RETAINED_OWNER", None)):
            self.stack.enter_context(patch.object(m, name, value))

    def transport(self, *, bound=True):
        dll = StdioDll()
        value = m._ChildStdio(ctypes, dll, 100.0, (), (101, 102, 103))
        value._check_abi()
        # These are inert adapter-state fixtures, not production bootstrap receipts.
        value._supplier_retired = value._handoff_complete = True
        value._claims[:] = (True, True, True)
        if bound:
            value._input = StdioBoundaryData()
        return value, dll

    def actual_input(self, value, *, engine=None):
        from mobile_release._desktop_edit_control import EditInput, IMAGES_PROTOCOL
        from mobile_release.cancellation import DefaultCancellation
        from mobile_release.errors import ValidationError
        self.stack.enter_context(patch.object(sys, "platform", "win32"))
        source = EditInput(100.0, protocol=IMAGES_PROTOCOL, _windows_stdio=value) if engine is None else engine.input
        guard = DefaultCancellation(ValidationError, "fixed original DATA guard") if engine is None else engine.guard
        if engine is None:
            source._prepare_windows_owner(guard)
        with (patch("mobile_release.cancellation.signal.getsignal", return_value=object()),
              patch("mobile_release.cancellation.signal.signal") as setter):
            guard.install()
            setter.assert_not_called()  # zero owned handlers; no real signal mutation
        self.addCleanup(guard.restore)
        source.acquired, source.fd = True, 0  # handoff already-complete DATA for isolated guard tests
        guard._install_edit_source(source)
        with patch.object(source, "poll", return_value=None):
            guard.activate()
        return source, guard

    def queue_sibling_close(self, dll, role, *, flags=1, generation=0, requested=0):
        dll.queue(14, role, status=m._STD_IDLE, flags=flags, generation=generation, requested=requested)
        dll.queue(11, role, status=m._STD_CLOSED, flags=flags, generation=generation,
                  requested=requested, close_mask=7)

    def supplier(self, dll):
        originals = []
        for number in range(3):
            raw = SupplierRaw(number, dll.events)
            buffered = (SupplierReader if number == 0 else SupplierWriter)(raw)
            originals.append((SupplierText(buffered), buffered, raw))
        return tuple(originals)

    def supplier_environment(self):
        context = ExitStack()
        for name in ("stdin", "stdout", "stderr", "__stdin__", "__stdout__", "__stderr__"):
            context.enter_context(patch.object(sys, name, None))
        for name, value in (("TextIOWrapper", SupplierText), ("BufferedReader", SupplierReader),
                            ("BufferedWriter", SupplierWriter), ("FileIO", SupplierRaw)):
            context.enter_context(patch.object(_io, name, value))
        context.enter_context(patch.dict(sys.modules, {
            "msvcrt": SimpleNamespace(get_osfhandle=lambda number: (101, 102, 103)[number])}))
        return context

    def queue_supplier(self, dll):
        dll.queue(1, mappings=(101, 102, 103))
        for operation in (2, 3, 4, 5):
            dll.queue(operation)

    def queued_full_handoff(self, dll, *, read_limit):
        prologue, ack = b"p" * 96, b"a" * 96  # actual native parser belongs to native tests, not this fake
        dll.queue(6, status=m._STD_COMPLETE, generation=1, requested=96, transferred=96)
        dll.queue(10, status=m._STD_COMPLETE, generation=1, requested=96, transferred=96, data=prologue)
        dll.queue(12, generation=1, requested=96)
        dll.queue(13, data=ack)
        dll.queue(7, 1, status=m._STD_COMPLETE, generation=1, requested=96, transferred=96)
        dll.queue(10, 1, status=m._STD_COMPLETE, generation=1, requested=96, transferred=96, flags=4)
        dll.queue(14, 1, generation=1, requested=96, transferred=96, flags=4)
        # Same original initial phase: guard activation and B1 before-entry poll.
        dll.queue(6, status=m._STD_PENDING, generation=2, requested=read_limit, flags=4)
        dll.queue(8, status=m._STD_PENDING, generation=2, requested=read_limit, flags=4)


    def test_stdio_layout_offsets_are_distinct_from_the_unchanged_b1_wire(self):
        value, dll = self.transport()
        self.assertEqual(tuple(ctypes.sizeof(t) for t in (value._Request, value._Reply, value._Info)), (40, 80, 148))
        self.assertEqual([getattr(value._Request, name).offset for name, _ in value._Request._fields_],
                         [0, 4, 8, 12, 16, 24, 28, 32])
        self.assertEqual([getattr(value._Reply, name).offset for name, _ in value._Reply._fields_],
                         [0, 4, 8, 12, 16, 24, 28, 32, 36, 40, 64, 68, 72])
        self.assertEqual(len(dll.mrk_stdio_v1_call.argtypes), 4)
        self.assertIs(dll.mrk_stdio_v1_call.restype, ctypes.c_uint32)
        self.assertEqual(m._SETTLEMENT_OPERATIONS, (14, 16, 17))

    def test_successful_zero_read_is_not_native_broken_peer_eof(self):
        value, dll = self.transport()
        dll.queue(6, status=m._STD_COMPLETE, generation=1, requested=4)
        dll.queue(10, status=m._STD_COMPLETE, generation=1, requested=4)
        self.assertIsNone(value.read_available(4))
        self.assertEqual(value._state[0], m._STD_IDLE)
        dll.queue(6, status=m._STD_EOF, generation=2, requested=4)
        self.assertEqual(value.read_available(4), b"")
        self.assertEqual([r[0] for r in dll.stdio_calls], [6, 10, 6])

    def test_partial_read_takes_only_returned_extent_under_same_generation(self):
        value, dll = self.transport()
        dll.queue(6, status=m._STD_COMPLETE, generation=1, requested=5, transferred=5)
        value._invoke(6, length=5)  # start five; later takes may consume smaller extents
        dll.queue(10, status=m._STD_COMPLETE, generation=1, requested=5, transferred=2, data=b"ab")
        self.assertEqual(value.read_available(2), b"ab")
        self.assertEqual(value._remaining[0], 3)
        dll.queue(10, status=m._STD_COMPLETE, generation=1, requested=5, transferred=3, data=b"cde")
        self.assertEqual(value.read_available(3), b"cde")
        self.assertEqual(value._state[0], m._STD_IDLE)
        self.assertEqual(value._generation[0], 1)

    def test_cancel_return_never_completes_or_reissues_the_original_operation(self):
        for returned_error in (0, 1168):  # success/NOT_FOUND DATA; native classification has separate tests
            with self.subTest(returned_error=returned_error):
                value, dll = self.transport()
                dll.queue(6, status=m._STD_PENDING, generation=1, requested=8)
                value._invoke(6, length=8)
                dll.queue(9, status=m._STD_PENDING, generation=1, requested=8, error=returned_error)
                value._invoke(9)
                self.assertEqual(value._state[0], m._STD_PENDING)
                self.assertEqual(value._generation[0], 1)
                dll.queue(8, status=m._STD_CANCELLED, generation=1, requested=8, error=995)
                value._invoke(8)
                self.assertEqual(value._state[0], m._STD_CANCELLED)
                self.assertEqual([r[0] for r in dll.stdio_calls], [6, 9, 8])
                self.assertEqual([r[2] for r in dll.stdio_calls], [0, 1, 1])

    def test_partial_write_continues_only_the_actual_remaining_bytes(self):
        value, dll = self.transport()
        dll.queue(7, 1, status=m._STD_COMPLETE, generation=1, requested=4, transferred=2)
        dll.queue(10, 1, status=m._STD_COMPLETE, generation=1, requested=4, transferred=2)
        dll.queue(7, 1, status=m._STD_COMPLETE, generation=2, requested=2, transferred=2)
        dll.queue(10, 1, status=m._STD_COMPLETE, generation=2, requested=2, transferred=2)
        value.write_frame(b"abcd")
        self.assertEqual([r[5] for r in dll.stdio_calls if r[0] == 7], [b"abcd", b"cd"])
        self.assertFalse(value._write_broken)
        self.assertEqual(value._generation[1], 2)

    def test_zero_write_latches_failure_and_never_appends_a_terminal(self):
        value, dll = self.transport()
        dll.queue(7, 1, status=m._STD_COMPLETE, generation=1, requested=4)
        dll.queue(10, 1, status=m._STD_COMPLETE, generation=1, requested=4)
        with self.assertRaises(m.BridgeFailure):
            value.write_frame(b"abcd")
        self.assertTrue(value._write_broken)
        before = tuple(dll.stdio_calls)
        with self.assertRaises(m.BridgeRefused):
            value.write_frame(b'{"terminal":true}', terminal=True)
        self.assertEqual(tuple(dll.stdio_calls), before)

    def test_partial_prefix_then_failed_write_remains_sticky_without_a_terminal(self):
        value, dll = self.transport()
        dll.queue(7, 1, status=m._STD_COMPLETE, generation=1, requested=4, transferred=2)
        dll.queue(10, 1, status=m._STD_COMPLETE, generation=1, requested=4, transferred=2)
        dll.queue(7, 1, status=m._STD_FAILED, generation=2, requested=2, error=109)
        with self.assertRaises(m.BridgeFailure):
            value.write_frame(b"abcd")
        self.assertTrue(value._write_broken)
        self.assertIsNone(value._pending)  # known ABI failure is not a lost returning frame
        before = tuple(dll.stdio_calls)
        with self.assertRaises(m.BridgeRefused):
            value.write_frame(b"terminal\n", terminal=True)
        self.assertEqual(tuple(dll.stdio_calls), before)
        self.assertEqual([r[5] for r in dll.stdio_calls if r[0] == 7], [b"abcd", b"cd"])

    def test_stale_completion_generation_roots_actual_malformed_frame(self):
        value, dll = self.transport()
        dll.queue(6, status=m._STD_PENDING, generation=1, requested=4)
        value._invoke(6, length=4)
        dll.queue(8, status=m._STD_COMPLETE, generation=2, requested=4, transferred=4)
        with self.assertRaises(m.BridgeUnknown):
            value._invoke(8)
        frame = value._pending
        self.assertIs(frame[2], value._last_reply)
        self.assertEqual(frame[2].generation, 2)
        self.assertTrue(value._lost_custody())
        before = tuple(dll.stdio_calls)
        with self.assertRaises(m.BridgeUnknown):
            value.close_role(2)
        self.assertIs(value._pending, frame)
        self.assertEqual(tuple(dll.stdio_calls), before)

    def test_unrequested_extent_cannot_authorize_a_new_generation(self):
        value, dll = self.transport()
        dll.queue(6, status=m._STD_COMPLETE, generation=1, requested=5, transferred=5)
        with self.assertRaises(m.BridgeUnknown):
            value._invoke(6, length=4)
        self.assertEqual(value._generation[0], 0)
        self.assertEqual(value._pending[0].length, 4)
        self.assertEqual(value._pending[2].requested, 5)
        self.assertTrue(value._lost_custody())

    def test_valid_unknown_retains_failure_but_allows_only_sibling_settlement(self):
        value, dll = self.transport()
        dll.queue(6, status=m._STD_UNKNOWN, generation=1, requested=4, flags=1)
        with self.assertRaises(m.BridgeUnknown):
            value._invoke(6, length=4)
        frame = value._failure_frame
        self.assertIsNotNone(frame)
        self.assertIsNone(value._pending)
        self.assertFalse(value._lost_custody())
        self.queue_sibling_close(dll, 2)
        value.close_role(2)
        self.assertTrue(value._closed[2])
        self.assertTrue(value._unknown)
        self.assertIs(value._failure_frame, frame)
        before = tuple(dll.stdio_calls)
        with self.assertRaises(m.BridgeUnknown):
            value._invoke(7, 1, length=1, payload=b"x", terminal=True)
        self.assertEqual(tuple(dll.stdio_calls), before)

    def test_lost_call_frame_forbids_even_sibling_abi_entry(self):
        value, dll = self.transport()
        dll.queue(6, exception=OSError("fixed lost ABI return"))
        with self.assertRaises(OSError):
            value._invoke(6, length=4)
        frame = value._pending
        self.assertIsNotNone(frame)
        self.assertTrue(value._lost_custody())
        with self.assertRaises(m.BridgeUnknown):
            value._invoke(14, 2)
        self.assertEqual(len(dll.stdio_calls), 1)
        self.assertIs(value._pending, frame)

    def test_mismatched_info_is_retained_before_any_channel_claim(self):
        dll = StdioDll()
        dll.stdio_bad_info = True
        value = m._ChildStdio(ctypes, dll, 100.0, (), (101, 102, 103))
        with self.assertRaises(m.BridgeUnknown):
            value._check_abi()
        original = value._info_pending
        self.assertIsNotNone(original)
        with self.assertRaises(m.BridgeUnknown):
            value._invoke(1)
        self.assertIs(value._info_pending, original)
        self.assertEqual(dll.stdio_calls, [])


    def test_actual_edit_input_valid_native_unknown_stops_without_lost_custody(self):
        value, dll = self.transport(bound=False)
        source, guard = self.actual_input(value)
        source.active = True  # the actual active EditInput reads exactly one STOP byte
        dll.queue(6, status=m._STD_UNKNOWN, generation=1, requested=1, flags=1)
        source.poll(guard)
        frame = value._failure_frame
        self.assertIsNotNone(frame)
        self.assertIsNone(value._pending)
        self.assertFalse(value._lost_custody())
        self.assertTrue(value._unknown)
        self.assertTrue(source.stopped)
        self.assertTrue(guard.cancelled)
        self.assertFalse(source.custody_unknown)
        self.assertFalse(guard.lifetime_ledger.fatal)
        self.queue_sibling_close(dll, 2)
        value.close_role(2)
        self.assertTrue(value._closed[2])
        self.assertTrue(value._unknown)
        self.assertIs(value._failure_frame, frame)
        before = tuple(dll.stdio_calls)
        with self.assertRaises(KeyboardInterrupt):
            source.before_image_entry()
        self.assertEqual(tuple(dll.stdio_calls), before)

    def test_actual_edit_input_malformed_return_latches_fatal_and_roots_exact_frame(self):
        value, dll = self.transport(bound=False)
        source, guard = self.actual_input(value)
        source.active = True
        dll.queue(6, status=m._STD_COMPLETE, generation=2, requested=1, transferred=1)
        source.poll(guard)
        frame = value._pending
        self.assertIsNotNone(frame)
        self.assertIs(frame[2], value._last_reply)
        self.assertEqual(frame[0].generation, 0)
        self.assertEqual(frame[2].generation, 2)
        self.assertTrue(value._lost_custody())
        self.assertTrue(source.stopped)
        self.assertTrue(source.custody_unknown)
        self.assertTrue(guard.cancelled)
        self.assertTrue(guard.lifetime_ledger.fatal)
        before = tuple(dll.stdio_calls)
        with self.assertRaises(m.BridgeUnknown):
            value.close_role(2)
        self.assertIs(value._pending, frame)
        self.assertEqual(tuple(dll.stdio_calls), before)

    def test_actual_engine_closes_both_siblings_before_generic_cleanup_abort(self):
        from mobile_release import _desktop_edit_engine as engine_module
        value, dll = self.transport(bound=False)
        self.stack.enter_context(patch.object(sys, "platform", "win32"))
        self.stack.enter_context(patch.object(m, "_RETAINED_STDIO", value))
        engine = engine_module._Engine(100.0, domain="metadata_images", _image_stdio=value)
        source, guard = self.actual_input(value, engine=engine)
        entered_fatal = []
        original_call = dll.mrk_stdio_v1_call.call

        def observed_call(*arguments):
            entered_fatal.append(guard.lifetime_ledger.fatal)
            return original_call(*arguments)

        dll.mrk_stdio_v1_call.call = observed_call
        # Valid returned native Unknown for input close, not a lost ctypes frame.
        dll.queue(11, status=m._STD_UNKNOWN, flags=1)
        self.queue_sibling_close(dll, 2)
        self.queue_sibling_close(dll, 1)
        with self.assertRaises(Exception):
            engine.cleanup()  # actual _attempt_all calls guard._abort only after close_input returns
        self.assertEqual([(r[0], r[1]) for r in dll.stdio_calls],
                         [(11, 0), (14, 2), (11, 2), (14, 1), (11, 1)])
        self.assertEqual(entered_fatal, [False] * 5)
        self.assertTrue(engine.error_closed)
        self.assertTrue(engine.output_closed)
        self.assertFalse(source.closed)
        self.assertTrue(source.close_claimed)
        self.assertFalse(source.custody_unknown)
        self.assertIsNone(value._pending)
        self.assertEqual(value._failure_frame[0].operation, 11)
        self.assertEqual(value._failure_frame[0].role, 0)
        self.assertEqual(value._closed, [False, True, True])
        self.assertTrue(value._unknown)
        self.assertTrue(guard.lifetime_ledger.fatal)
        before = tuple(dll.stdio_calls)
        engine.close_output()  # no retry after the two positive original receipts
        self.assertEqual(tuple(dll.stdio_calls), before)
        self.assertEqual(dll.stdio_frames, [])

    def test_late_expiry_spends_original_phase_endpoint_not_discovery_time(self):
        from mobile_release._desktop_edit_protocol import ProtocolError
        value, dll = self.transport(bound=False)
        source, guard = self.actual_input(value)
        self.now.return_value = 1000.0
        source._image_cleanup_started()
        self.assertEqual((source.cleanup_start, source.soft_end, source.hard_end), (130.0, 138.0, 140.0))
        self.now.return_value = 1001.0
        source._image_cleanup_started()
        self.assertEqual((source.cleanup_start, source.soft_end, source.hard_end), (130.0, 138.0, 140.0))
        with self.assertRaises(ProtocolError):
            source._image_native_boundary(settlement=True)
        with self.assertRaises(ProtocolError):
            value.close_role(2)
        self.assertEqual(dll.stdio_calls, [])

    def test_terminal_allowance_is_once_two_seconds_and_capped_by_original_hard_end(self):
        from mobile_release._desktop_edit_protocol import ProtocolError
        for start, end in ((108.0, 110.0), (110.5, 111.0)):
            with self.subTest(start=start):
                self.now.return_value = 101.0
                value, dll = self.transport(bound=False)
                source, guard = self.actual_input(value)
                dll.queue(11, status=m._STD_CLOSED, close_mask=7)
                source.close()
                guard.restore()
                self.assertEqual(guard.handler_state, "RESTORED")
                self.assertEqual((source.cleanup_start, source.hard_end), (101.0, 111.0))
                self.now.return_value = start
                source._image_terminal_started()
                self.assertEqual(source._terminal_end, end)
                self.assertLessEqual(source._terminal_end - start, 2.0)
                before = tuple(dll.stdio_calls)
                with self.assertRaises(ProtocolError):
                    source._image_terminal_started()
                self.assertEqual(source._terminal_end, end)
                self.now.return_value = end
                with self.assertRaises(ProtocolError):
                    source._image_terminal_check()
                self.assertEqual(tuple(dll.stdio_calls), before)

    def test_supplier_wrong_closefd_or_exact_type_refuses_before_any_claim_or_close(self):
        for fault in ("closefd", "type"):
            with self.subTest(fault=fault):
                dll = StdioDll()
                originals = self.supplier(dll)
                if fault == "closefd":
                    originals[0][2].closefd = True
                else:
                    originals = ((object(), originals[0][1], originals[0][2]), *originals[1:])
                value = m._ChildStdio(ctypes, dll, 100.0, originals, (101, 102, 103))
                dll.queue(1, mappings=(101, 102, 103))
                with self.supplier_environment(), self.assertRaises(m.BridgeRefused):
                    value._admit_supplier()
                self.assertEqual([r[0] for r in dll.stdio_calls], [1])
                self.assertFalse(value._supplier_retired)
                self.assertEqual(value._claims, [False, False, False])
                self.assertFalse(any(chain[2].closed for chain in originals))
                self.assertFalse(any(event[0] == "raw-close" for event in dll.events))

    def full_original_binding(self):
        """Actual bootstrap -> supplier retirement -> handoff -> guard, fake fixed ABI only."""
        from mobile_release._desktop_edit_control import EditInput, IMAGES_PROTOCOL
        from mobile_release.cancellation import DefaultCancellation
        from mobile_release.errors import ValidationError
        flags = SimpleNamespace(**{name: getattr(sys.flags, name)
                                   for name in dir(sys.flags) if not name.startswith("_")})
        flags.isolated = flags.no_site = 1
        for name, replacement in (("platform", "win32"), ("executable", r"C:\fixed\python\python.exe"),
                                  ("flags", flags), ("dont_write_bytecode", True)):
            self.stack.enter_context(patch.object(sys, name, replacement))
        self.stack.enter_context(self.supplier_environment())
        dll = StdioDll()
        originals = self.supplier(dll)
        loader = self.stack.enter_context(patch.object(ctypes, "WinDLL", return_value=dll, create=True))
        self.queue_supplier(dll)
        value = m._bootstrap_image_stdio(started=100.0, originals=originals, mappings=(101, 102, 103))
        source = EditInput(100.0, protocol=IMAGES_PROTOCOL, _windows_stdio=value)
        guard = DefaultCancellation(ValidationError, "fixed original full binding DATA")
        source._prepare_windows_owner(guard)
        with (patch("mobile_release.cancellation.signal.getsignal", return_value=object()),
              patch("mobile_release.cancellation.signal.signal") as setter):
            guard.install()
            setter.assert_not_called()
        self.addCleanup(guard.restore)
        self.queued_full_handoff(dll, read_limit=min(65536, source.request_limit + 1))
        source.acquire()  # actual native-handshake adapter path; no acquired-state bypass
        guard._install_edit_source(source)
        guard.activate()  # actual poll, not patched in this full binding path
        self.assertTrue(source.acquired)
        self.assertIs(source.guard, guard)
        self.assertIs(guard._edit_source, source)
        self.assertTrue(guard._activated)
        self.assertTrue(value._handoff_complete)
        self.assertTrue(all(all(part.closed for part in chain) for chain in originals))
        self.assertEqual(dll.events[:8], [("stdio", 1, 0), ("raw-close", 0), ("raw-close", 1),
                                        ("raw-close", 2), ("stdio", 2, 0), ("stdio", 3, 0),
                                        ("stdio", 4, 0), ("stdio", 5, 0)])
        loader.assert_called_once_with(r"C:\fixed\python\mrk_image_writer_native.dll", winmode=0x900)
        return value, dll, source, guard, loader

    def test_full_actual_binding_uses_same_dll_and_exact_bound_methods_only_once(self):
        value, dll, source, guard, loader = self.full_original_binding()
        options = dict(domain="metadata_images", installed_python=sys.executable,
                       before_entry=source.before_image_entry,
                       before_settlement=source.before_image_settlement, _stdio_context=value)
        before = tuple(dll.stdio_calls)
        with self.assertRaises(m.BridgeRefused):
            m._open_for_original_image_child(**{**options, "before_entry": lambda: source.before_image_entry()})
        with self.assertRaises(m.BridgeRefused):
            m._open_for_original_image_child(**{**options, "_stdio_context": StdioBoundaryData()})
        self.assertFalse(m._ATTEMPTED)
        self.assertEqual(tuple(dll.stdio_calls), before)
        owner = m._open_for_original_image_child(**options)
        self.assertIs(owner, m._RETAINED_OWNER)
        self.assertIs(owner._dll, dll)
        self.assertIs(m._RETAINED_DLL, dll)
        self.assertIs(m._RETAINED_STDIO, value)
        self.assertFalse(owner._unknown)
        self.assertEqual(dll.calls, [])
        self.assertEqual(dll.stdio_frames, [])
        before = tuple(dll.stdio_calls)
        with self.assertRaises(m.BridgeRefused):
            m._open_for_original_image_child(**options)
        self.assertEqual(tuple(dll.stdio_calls), before)
        self.assertEqual(loader.call_count, 1)

    def test_full_binding_bad_b1_abi_roots_actual_owner_and_info_without_reload(self):
        value, dll, source, guard, loader = self.full_original_binding()
        dll.bad_info = True
        options = dict(domain="metadata_images", installed_python=sys.executable,
                       before_entry=source.before_image_entry,
                       before_settlement=source.before_image_settlement, _stdio_context=value)
        with self.assertRaises(m.BridgeUnknown):
            m._open_for_original_image_child(**options)
        owner = m._RETAINED_OWNER
        self.assertIsNotNone(owner)
        self.assertIs(owner._dll, dll)
        self.assertTrue(owner._unknown)
        self.assertIsNotNone(owner._info_pending)
        self.assertEqual(owner._info_pending.version, 2)
        before = tuple(dll.stdio_calls)
        with self.assertRaises(m.BridgeRefused):
            m._open_for_original_image_child(**options)
        self.assertEqual(tuple(dll.stdio_calls), before)
        self.assertIs(m._RETAINED_OWNER, owner)
        self.assertEqual(loader.call_count, 1)

    def test_closed_windows_dispatch_refuses_before_any_posix_root_or_lease(self):
        from mobile_release import _desktop_edit_engine as engine_module
        # The validators have independent tests. This fixed returned family DATA
        # isolates the actual closed dispatch and does not admit a Windows backend.
        identity = SimpleNamespace(family="windows")
        with (patch.object(engine_module, "image_registered_identity", return_value=identity),
              patch.object(engine_module, "admit_image_root"),
              patch.object(engine_module, "_root") as root,
              patch.object(engine_module, "InitRootLease") as lease):
            with self.assertRaises(engine_module.ConfigEditFailure) as result:
                engine_module._admit_image_backend(r"C:\project", {})
        self.assertEqual(result.exception.outcome.reason, "unsupported_platform")
        root.assert_not_called()
        lease.assert_not_called()


if __name__ == "__main__":
    unittest.main()
