"""Fixed-purpose Windows stdio DATA/scripted-memory tests, not native evidence.

No WinDLL/load, real pipe/descriptor/supplier claim, project IO, handler install,
native process, or test-binary discovery occurs here. Fixture admission/active
bits are DATA. The separate selected-test owner must allow ctypes memory, NOT
DLL loading; this suite does not weaken the existing import-denial owner.
"""
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import patch
import sys
import unittest

from mobile_release import _desktop_image_writer_windows as stdio
from mobile_release import _desktop_edit_control as control
from mobile_release._desktop_edit_protocol import IMAGES_PROTOCOL, NOTES_PROTOCOL, ProtocolError
from mobile_release.cancellation import DefaultCancellation


class _NoNative:
    def __init__(self):
        self.calls = 0

    def __call__(self, *args):
        self.calls += 1
        raise AssertionError("the DATA fixture must not enter Info or a native Notes function")


class _StdioCalls:
    def __init__(self, steps=()):
        self.steps = list(steps)
        self.calls = []
        self.requested = [0, 0, 0]

    def __call__(self, request, source, reply, destination):
        r, out = request._obj, reply._obj
        self.calls.append((r.operation, r.role))
        if self.steps:
            step = self.steps.pop(0)
        elif r.operation == 11:
            step = {"status": stdio._STD_CLOSED, "close_mask": 7}
        else:
            raise AssertionError("no scripted stdio return is admitted")
        if isinstance(step, BaseException):
            raise step
        if r.operation in (6, 7):
            self.requested[r.role] = r.length
        values = dict(size=80, version=1, status=stdio._STD_COMPLETE, error=0,
                      generation=r.generation + int(r.operation in (6, 7)),
                      requested=self.requested[r.role], transferred=0, flags=0,
                      close_mask=0, output_len=0, first_failure=0)
        values.update(step)
        for name, value in values.items():
            setattr(out, name, value)
        return out.status


@contextmanager
def _context(purpose=stdio._STD_NOTES, *, bound=True, steps=()):
    import ctypes
    image_calls, notes_calls = _StdioCalls(steps), _StdioCalls(steps)
    info, notes_info, notes_native = _NoNative(), _NoNative(), _NoNative()
    dll = SimpleNamespace(mrk_stdio_v1_call=image_calls,
                          mrk_notes_stdio_v1_call=notes_calls,
                          mrk_stdio_v1_info=info,
                          mrk_notes_v1_info=notes_info,
                          mrk_notes_v1_call=notes_native)
    owner = stdio._ChildStdio(ctypes, dll, 100.0, ((), (), ()), (101, 102, 103), purpose=purpose)
    # These are DATA post-admission records, not fake successful supplier closes.
    owner._supplier_retired = True
    owner._claims[:] = [True, True, True]
    with ExitStack() as stack:
        stack.enter_context(patch.multiple(stdio, _STDIO_ATTEMPTED=True, _STDIO_PURPOSE=purpose,
                                           _RETAINED_STDIO=owner, _RETAINED_DLL=dll,
                                           _ATTEMPTED=False, _RETAINED_OWNER=None))
        # Construct the real typed input without acquiring any standard descriptor.
        with patch.object(control, "sys", SimpleNamespace(platform="linux")):
            original = control.EditInput(100.0, protocol=NOTES_PROTOCOL if purpose == stdio._STD_NOTES else IMAGES_PROTOCOL)
        original._windows_stdio = owner
        guard = DefaultCancellation(ProtocolError, "stdio DATA fixture")
        original.guard = guard
        guard._edit_source = original
        guard._activated = True  # DATA marker only; no install/activate call.
        if bound:
            owner._bind_input(original)
            original.acquired = original.active = True
            original.frames = 1
            owner._handoff_complete = True
        yield SimpleNamespace(owner=owner, input=original, guard=guard, dll=dll, ctypes=ctypes,
                              calls=notes_calls if purpose == stdio._STD_NOTES else image_calls,
                              image_calls=image_calls, notes_calls=notes_calls,
                              info=info, notes_info=notes_info, notes_native=notes_native)


class WindowsStdioPurposeTests(unittest.TestCase):
    def test_fixed_bootstrap_domains_preserve_unix_and_route_distinct_keywords(self):
        from desktop import config_edit_bootstrap as bootstrap
        for platform, domain, keyword, allowed in (
                ("win32", "metadata_images", "_image_stdio", True),
                ("win32", "required_notes", "_notes_stdio", True),
                ("linux", "required_notes", None, True),
                ("darwin", "required_notes", None, True),
                ("linux", "metadata_images", None, True),
                ("darwin", "metadata_images", None, False),
                ("win32", "metadata_text", None, False),
                ("win32", "configuration", None, False)):
            with self.subTest(platform=platform, domain=domain):
                events, calls = [], []
                context = object()
                class Paths(list):
                    def insert(self, index, value):
                        events.append("path")
                        super().insert(index, value)
                fake_sys = SimpleNamespace(platform=platform, argv=["bootstrap", "/fixed/core.zip", domain],
                                           flags=SimpleNamespace(isolated=True, no_site=True),
                                           dont_write_bytecode=True, version_info=(3, 11), path=Paths())
                def capture():
                    events.append("capture")
                    return ("originals", "mappings")
                def admit(**kwargs):
                    events.append("admit")
                    self.assertEqual(kwargs, dict(started=100.0, originals="originals", mappings="mappings"))
                    return context
                def run(**kwargs):
                    calls.append(kwargs)
                    return 17
                engine = SimpleNamespace(main=run)
                with patch.object(bootstrap, "sys", fake_sys), \
                     patch.object(bootstrap, "os", SimpleNamespace(path=SimpleNamespace(isabs=lambda value: value == "/fixed/core.zip"))), \
                     patch.object(bootstrap.time, "monotonic", return_value=100.0), \
                     patch.object(bootstrap, "_IMAGE_STDIO_CONTEXT", None), \
                     patch.object(bootstrap, "_capture_image_stdio", side_effect=capture), \
                     patch.object(stdio, "_bootstrap_image_stdio", side_effect=admit) as image, \
                     patch.object(stdio, "_bootstrap_notes_stdio", side_effect=admit) as notes, \
                     patch.dict(sys.modules, {"mobile_release._desktop_edit_engine": engine}):
                    self.assertEqual(bootstrap.main(), 17 if allowed else 78)
                    if not allowed:
                        self.assertEqual((events, calls), ([], []))
                    else:
                        expected = dict(started=100.0, domain=domain)
                        if keyword:
                            expected[keyword] = context
                        self.assertEqual(calls, [expected])
                        self.assertEqual(events, ["capture", "path", "admit"] if keyword else ["path"])
                    self.assertEqual(image.call_count, int(keyword == "_image_stdio" and allowed))
                    self.assertEqual(notes.call_count, int(keyword == "_notes_stdio" and allowed))

    def test_first_invalid_bootstrap_consumes_same_and_cross_purpose_retry(self):
        for first, later, purpose in (
                (stdio._bootstrap_image_stdio, stdio._bootstrap_notes_stdio, stdio._STD_IMAGE),
                (stdio._bootstrap_notes_stdio, stdio._bootstrap_image_stdio, stdio._STD_NOTES)):
            with patch.multiple(stdio, _STDIO_ATTEMPTED=False, _STDIO_PURPOSE=None,
                                _RETAINED_DLL=None, _RETAINED_STDIO=None), \
                 patch.object(stdio, "sys", SimpleNamespace(platform="linux")):
                for invoke in (first, first, later):
                    with self.assertRaises(stdio.BridgeRefused):
                        invoke(started=100.0, originals=((), (), ()), mappings=(101, 102, 103))
                self.assertTrue(stdio._STDIO_ATTEMPTED)
                self.assertEqual(stdio._STDIO_PURPOSE, purpose)
                self.assertIsNone(stdio._RETAINED_DLL)

    def test_failed_first_supplier_admission_keeps_one_dll_and_context(self):
        calls = []
        dll = object()
        class Child:
            def __init__(self, *args, purpose):
                self.purpose, self._unknown = purpose, False
            def _admit_supplier(self):
                raise RuntimeError("scripted admission failure, no native call")
        def load(*args, **kwargs):
            calls.append((args, kwargs))
            return dll
        fake_sys = SimpleNamespace(platform="win32", flags=SimpleNamespace(isolated=True, no_site=True),
                                   dont_write_bytecode=True, executable=r"C:\runtime\python\python.exe")
        with patch.multiple(stdio, _STDIO_ATTEMPTED=False, _STDIO_PURPOSE=None,
                            _RETAINED_DLL=None, _RETAINED_STDIO=None), \
             patch.object(stdio, "sys", fake_sys), patch.object(stdio, "_ChildStdio", Child), \
             patch.dict(sys.modules, {"ctypes": SimpleNamespace(WinDLL=load)}):
            with self.assertRaises(stdio.BridgeUnknown):
                stdio._bootstrap_notes_stdio(started=100.0, originals=((), (), ()), mappings=(101, 102, 103))
            retained = stdio._RETAINED_STDIO
            self.assertIs(stdio._RETAINED_DLL, dll)
            self.assertTrue(retained._unknown)
            for invoke in (stdio._bootstrap_notes_stdio, stdio._bootstrap_image_stdio):
                with self.assertRaises(stdio.BridgeRefused):
                    invoke(started=100.0, originals=((), (), ()), mappings=(101, 102, 103))
            self.assertIs(stdio._RETAINED_STDIO, retained)
            self.assertEqual(len(calls), 1)

    def test_original_context_rejects_other_purpose_start_and_retag(self):
        for purpose, own, other in (
                (stdio._STD_IMAGE, stdio._original_image_stdio, stdio._original_notes_stdio),
                (stdio._STD_NOTES, stdio._original_notes_stdio, stdio._original_image_stdio)):
            with _context(purpose, bound=False) as f:
                self.assertIs(own(f.owner, 100.0), f.owner)
                for invoke, started in ((other, 100.0), (own, 101.0)):
                    with self.assertRaises(stdio.BridgeRefused):
                        invoke(f.owner, started)
                with self.assertRaises(AttributeError):
                    f.owner._purpose = stdio._STD_IMAGE
                with self.assertRaises(AttributeError):
                    del f.owner._purpose
                self.assertEqual(f.calls.calls, [])

    def test_input_binding_refuses_cross_protocol_or_changed_start_without_claim(self):
        with _context(bound=False) as f:
            for field, wrong in (("protocol", IMAGES_PROTOCOL), ("started", 101.0)):
                original = getattr(f.input, field)
                setattr(f.input, field, wrong)
                with self.assertRaises(stdio.BridgeRefused):
                    f.owner._bind_input(f.input)
                self.assertIsNone(f.owner._input)
                setattr(f.input, field, original)
            f.owner._bind_input(f.input)
            self.assertIs(f.owner._input, f.input)
            self.assertEqual(f.calls.calls, [])

    def test_notes_binding_and_bridge_construction_enter_no_native_function(self):
        from mobile_release._desktop_notes_windows import _Bridge
        with _context() as f, patch.object(f.guard, "_poll_edit_stop", side_effect=AssertionError("no constructor poll")):
            c, dll = stdio._original_notes_native_binding(f.input, f.guard)
            self.assertIs(c, f.ctypes); self.assertIs(dll, f.dll)
            bridge = _Bridge(f.input, f.guard, c, dll)
            self.assertIs(bridge._dll, dll)
            self.assertEqual(bridge._owner_key, 0)
            self.assertFalse(bridge._prepared)
            self.assertEqual((f.info.calls, f.notes_info.calls, f.notes_native.calls), (0, 0, 0))
            self.assertEqual(f.calls.calls, [])
            with self.assertRaises(stdio.BridgeRefused):
                stdio._original_notes_native_binding(f.input, f.guard)

    def test_native_binding_refuses_image_foreign_guard_and_inactive_source(self):
        with _context(stdio._STD_IMAGE) as f:
            with self.assertRaises(stdio.BridgeRefused):
                stdio._original_notes_native_binding(f.input, f.guard)
        with _context() as f:
            with self.assertRaises(stdio.BridgeRefused):
                stdio._original_notes_native_binding(f.input, object())
            f.guard._edit_source = None
            with self.assertRaises(stdio.BridgeRefused):
                stdio._original_notes_native_binding(f.input, f.guard)
            self.assertFalse(stdio._ATTEMPTED)
            self.assertEqual(f.calls.calls, [])

    def test_returned_operation_unknown_keeps_only_supplier_knowledge(self):
        with _context(steps=({"status": stdio._STD_UNKNOWN, "flags": 1},)) as f, \
             patch.object(control.time, "monotonic", return_value=101.0):
            with self.assertRaises(stdio.BridgeUnknown):
                f.owner._invoke(6, length=1)
            self.assertTrue(f.owner._unknown)
            self.assertFalse(f.owner._lost_custody())
            self.assertTrue(f.owner._notes_native_supplier_known(f.input, f.guard))
            f.input.before_notes_finality()
            with self.assertRaises(stdio.BridgeUnknown):
                f.owner._invoke(6, length=1)
            with self.assertRaises(stdio.BridgeRefused):
                stdio._original_notes_native_binding(f.input, f.guard)
            self.assertEqual(f.calls.calls, [(6, 0)])

    def test_malformed_or_unreturned_stdio_frame_cannot_supply_notes_finality(self):
        for step in ({"size": 79}, KeyboardInterrupt()):
            with self.subTest(step=type(step).__name__), _context(steps=(step,)) as f, \
                 patch.object(control.time, "monotonic", return_value=101.0):
                with self.assertRaises((stdio.BridgeUnknown, KeyboardInterrupt)):
                    f.owner._invoke(6, length=1)
                self.assertTrue(f.owner._lost_custody())
                self.assertIsNotNone(f.owner._pending)
                self.assertFalse(f.owner._notes_native_supplier_known(f.input, f.guard))
                with self.assertRaises(ProtocolError):
                    f.input.before_notes_finality()
                self.assertEqual(f.calls.calls, [(6, 0)])

    def test_idle_pause_never_polls_or_freezes_a_healthy_notes_phase(self):
        with _context() as f, patch.object(control.time, "monotonic", return_value=101.0), \
             patch.object(control.time, "sleep") as sleep, \
             patch.object(f.input, "before_notes_settlement", side_effect=AssertionError("idle is not recovery")):
            f.owner._pause()
            self.assertIsNone(f.input._notes_filesystem_end)
            self.assertEqual(f.input._notes_endpoint(), 130.0)
            sleep.assert_called_once_with(0.1)
            self.assertEqual(f.calls.calls, [])

    def test_pregrant_stdin_close_uses_original_end_without_terminal_allowance(self):
        with _context() as f, patch.object(control.time, "monotonic", return_value=125.0):
            f.owner.close_role(0)
            self.assertEqual(f.calls.calls, [(11, 0)])
            self.assertTrue(f.owner._closed[0])
            self.assertIsNone(f.input._notes_terminal_end)
        with _context() as f, patch.object(control.time, "monotonic", return_value=130.0):
            with self.assertRaises(ProtocolError):
                f.owner.close_role(0)
            self.assertEqual(f.calls.calls, [])
            self.assertIsNone(f.input._notes_terminal_end)

    def test_postgrant_allows_only_output_roles_and_closed_output_operations(self):
        with _context() as f, patch.object(control.time, "monotonic", return_value=150.0):
            f.input._notes_cleanup_attempted = True
            f.input._notes_terminal_started()
            self.assertEqual(f.input._notes_terminal_end, 152.0)
            allowed = {7, 8, 9, 10, 11, 14}
            for role in (0, 1, 2):
                for operation in range(1, 15):
                    if role in (1, 2) and operation in allowed:
                        continue
                    with self.assertRaises(stdio.BridgeRefused):
                        f.owner._invoke(operation, role, terminal=True)
            with self.assertRaises(stdio.BridgeRefused):
                f.owner.close_role(0)
            self.assertEqual(f.calls.calls, [])
            f.owner.close_role(2); f.owner.close_role(1)
            self.assertEqual(f.calls.calls, [(11, 2), (11, 1)])
            with self.assertRaises(ProtocolError):
                f.input.before_notes_finality()
            self.assertEqual(f.input._notes_filesystem_endpoint(), 130.0)

    def test_partial_output_failure_never_appends_a_terminal_frame(self):
        steps = ({"transferred": 2}, {"transferred": 2},
                 {"status": stdio._STD_FAILED, "error": 5})
        with _context(steps=steps) as f, patch.object(control.time, "monotonic", return_value=101.0), \
             patch.object(f.owner, "_write_boundary", return_value=None):
            with self.assertRaises(stdio.BridgeFailure):
                f.owner.write_frame(b"abcdef")
            self.assertTrue(f.owner._write_broken)
            self.assertTrue(f.input.stopped)
            self.assertEqual(f.input._notes_filesystem_end, 130.0)
            self.assertEqual(f.calls.calls, [(7, 1), (10, 1), (7, 1)])
            f.input._notes_cleanup_attempted = True
            with self.assertRaises(stdio.BridgeRefused):
                f.owner.write_frame(b"terminal\n", terminal=True)
            self.assertEqual(f.calls.calls, [(7, 1), (10, 1), (7, 1)])

    def test_image_callback_order_and_preterminal_close_dispatch_stay_unchanged(self):
        with _context(stdio._STD_IMAGE) as f:
            events = []
            def record(name):
                return lambda: events.append(name)
            original = SimpleNamespace(_image_handoff_check=record("handoff"),
                                       before_image_entry=record("entry"),
                                       _image_terminal_check=record("terminal"))
            f.owner._input = original
            f.owner._write_boundary(handoff=True, terminal=False)
            f.owner._write_boundary(handoff=False, terminal=False)
            f.owner._write_boundary(handoff=False, terminal=True)
            self.assertEqual(events, ["handoff", "entry", "terminal"])
            observed = []
            f.owner._settle_pending = lambda role, *, terminal: observed.append(("settle", role, terminal))
            def close(operation, role, *, terminal):
                observed.append((operation, role, terminal))
                return SimpleNamespace(status=stdio._STD_CLOSED, close_mask=7), b""
            f.owner._invoke = close
            f.owner.close_role(0)
            self.assertEqual(observed, [("settle", 0, True), (11, 0, True)])
