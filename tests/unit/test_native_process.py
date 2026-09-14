"""Native ownership contracts.

NativeProcessTests is fake-only.  The two explicitly named native classes MUST
run only in the reviewed disposable native owner, after actual header admission.
They are not a safe shared-host discovery selector, and never skip a missing
capability into PASS.  No fixture child/FD/task is acquired at module top level.
The two deliberate-UNKNOWN lifecycle proofs each require their own fixed
singleton Session capture: after the bounded proof, only result reporting may
follow until the existing owner genuinely disposes of that process/domain.
The stdlib ctypes import itself initializes its default Python-API handle and
declarations: even the fake-only class needs that import explicitly admitted;
it is NOT a literal zero-FFI shared-host import/discovery selector.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
import select
import signal
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import ExitStack, contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from mobile_release import _native_process as m


class _World:
    """Pure owned-descriptor/native-return model, never a native test receipt."""

    def __init__(self, family="linux-glibc"):
        with patch.object(m.sys, "platform", "linux" if family == "linux-glibc" else "darwin"), \
                patch.object(m.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")):
            self.abi = m._abi_types()
        self.abi.constants["SIGCHLD"] = 17 if family == "linux-glibc" else 20
        self.abi.constants["NSIG"] = 65 if family == "linux-glibc" else 32
        self.events, self.instances, self.fds = [], [], {}
        self.next_fd, self.next_inode, self.next_pid = 20, 1000, 700
        self.handler, self.signal_flags = 0, 0
        self.overrides = {}
        self.attribute_flags = {}
        self.wait_results = []
        world = self

        class FakeNative:
            def __init__(self):
                self.abi = world.abi
                self.last_errno = 0
                world.instances.append(self)

            def call(self, name, *arguments):
                return world.native(self, name, *arguments)

        self.native_type = FakeNative

    @staticmethod
    def denied(*_args, **_kwargs):
        raise AssertionError("unexpected real acquisition or numeric request")

    @contextmanager
    def installed(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(m, "_Native", self.native_type))
            for name, function in (("pipe", self.pipe), ("open", self.open),
                                   ("fstat", self.fstat), ("stat", self.stat),
                                   ("set_inheritable", self.set_inheritable),
                                   ("waitpid", self.waitpid), ("close", self.denied),
                                   ("kill", self.denied), ("killpg", self.denied),
                                   ("dup", self.denied), ("dup2", self.denied),
                                   ("posix_spawn", self.denied)):
                stack.enter_context(patch.object(m.os, name, function))
            stack.enter_context(patch.object(m.signal, "signal", self.denied))
            yield self

    def allocate(self, kind, access, *, inode=None, flags=1, minimum=20):
        descriptor = max(self.next_fd, minimum)
        self.next_fd = descriptor + 1
        if inode is None:
            self.next_inode += 1
            inode = self.next_inode
        self.fds[descriptor] = {"kind": kind, "access": access, "flags": flags,
                                "inode": inode, "rdev": 7 if kind == "null" else 0}
        return descriptor

    def pipe(self):
        self.events.append(("pipe",))
        if "pipe" in self.overrides:
            return self.overrides["pipe"]()
        self.next_inode += 1
        return (self.allocate("pipe", os.O_RDONLY, inode=self.next_inode),
                self.allocate("pipe", os.O_WRONLY, inode=self.next_inode))

    def open(self, path, flags):
        self.events.append(("open", path, flags))
        if "open" in self.overrides:
            return self.overrides["open"](path, flags)
        if path != "/dev/null":
            raise AssertionError("unexpected path")
        return self.allocate("null", flags & os.O_ACCMODE)

    def fstat(self, descriptor):
        row = self.fds[descriptor]
        return types.SimpleNamespace(st_mode=stat.S_IFIFO if row["kind"] == "pipe" else stat.S_IFCHR,
                                     st_dev=2, st_ino=row["inode"], st_rdev=row["rdev"])

    def stat(self, path):
        if path != "/dev/null":
            raise AssertionError("unexpected path")
        return types.SimpleNamespace(st_mode=stat.S_IFCHR, st_dev=2, st_ino=5, st_rdev=7)

    def set_inheritable(self, descriptor, inheritable):
        self.events.append(("set_inheritable", descriptor, inheritable))
        self.fds[descriptor]["flags"] = 0 if inheritable else 1

    def native(self, instance, name, *args):
        label = name
        if name == "fcntl":
            label = {self.abi.constants["F_DUPFD_CLOEXEC"]: "duplicate",
                     self.abi.constants["F_GETFD"]: "getfd",
                     self.abi.constants["F_GETFL"]: "getfl"}[args[1]]
        self.events.append((label, *args))
        if label in self.overrides:
            return self.overrides[label](*args)
        if name == "fcntl":
            descriptor, command, minimum = args
            if label == "duplicate":
                row = self.fds[descriptor]
                return self.allocate(row["kind"], row["access"], inode=row["inode"], minimum=minimum)
            return self.fds[descriptor]["flags" if label == "getfd" else "access"]
        if name == "close":
            del self.fds[args[0]]
        elif name == "sigaction":
            if args[1] is not None:
                raise AssertionError("caller signal policy was changed")
            args[2]._obj.handler, args[2]._obj.flags = self.handler, self.signal_flags
        elif name == "posix_spawnattr_setflags":
            self.attribute_flags[id(args[0]._obj)] = args[1]
        elif name == "posix_spawnattr_getflags":
            args[1]._obj.value = self.attribute_flags[id(args[0]._obj)]
        elif name == "posix_spawn":
            self.next_pid += 1
            args[0]._obj.value = self.next_pid
        return 0

    def waitpid(self, pid, options):
        self.events.append(("waitpid", pid, options))
        if "waitpid" in self.overrides:
            return self.overrides["waitpid"](pid, options)
        if not self.wait_results:
            raise AssertionError("unplanned wait")
        result = self.wait_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    @staticmethod
    def owner(check=lambda: None, *, recorder=None):
        acquisition = m.Acquisition(failure_recorder=recorder)
        acquisition.grant(threading.current_thread(), check)
        return acquisition

    def sources(self, io, count=3):
        sources = [io.open_null(writable=False), io.open_null(writable=True), io.open_null(writable=True)]
        if count == 8:
            control, _ = io.pipe()
            _, status = io.pipe()
            sources.extend((control, status, io.open_null(writable=False),
                            io.open_null(writable=True), io.open_null(writable=True)))
        return tuple(sources)

    @staticmethod
    def spec(sources):
        return m.SpawnSpec("/fixed/python", ("/fixed/python", "-I", "-S", "-B", "-c", "pass"),
                           (("LC_ALL", "C"),), sources)

    def child(self):
        io, acquisition = self.owner(), self.owner()
        child = m.create(acquisition, self.spec(self.sources(io)))
        return io, acquisition, child


class NativeProcessTests(unittest.TestCase):
    def test_import_has_no_native_acquisition_or_implicit_reaper(self):
        source = Path(m.__file__).read_text(encoding="utf-8")
        probe = types.ModuleType("mobile_release._native_process_import_probe")
        probe.__file__ = m.__file__
        with patch.dict(sys.modules, {probe.__name__: probe}), \
                patch.object(ctypes, "CDLL", side_effect=_World.denied), \
                patch.object(os, "pipe", side_effect=_World.denied), \
                patch.object(os, "open", side_effect=_World.denied), \
                patch.object(os, "waitpid", side_effect=_World.denied), \
                patch.object(threading.Thread, "start", side_effect=_World.denied):
            exec(compile(source, m.__file__, "exec"), probe.__dict__)
        for cls in (probe.Acquisition, probe.Child, probe.FDLease):
            self.assertNotIn("__del__", cls.__dict__)
        for forbidden in ("subprocess", "Popen", "posix_spawnp", "find_library", "PyDLL"):
            self.assertNotIn(forbidden, probe.__dict__)

    def test_spawn_spec_is_immutable_and_strictly_bounded(self):
        empty = tuple(m.FDLease(m.Acquisition()) for _ in range(3))
        spec = _World.spec(empty)
        with self.assertRaises(FrozenInstanceError):
            spec.argv = ("/elsewhere",)
        cases = [dict(executable="relative"), dict(executable="/bad\0path"), dict(argv=[]),
                 dict(argv=("/other",)), dict(env={}), dict(env=(("A", "a"), ("A", "b"))),
                 dict(env=(("A=B", "x"),)), dict(env=(("", "x"),)),
                 dict(env=((True, "x"),)), dict(argv=("/fixed/python", "x" * 8193)),
                 dict(argv=("/fixed/python",) + ("x",) * 64),
                 dict(argv=("/fixed/python",) + ("é" * 4096,) * 8),
                 dict(fd_sources=empty + (empty[0],)), dict(fd_sources=(None,) * 3)]
        original = {name: getattr(spec, name) for name in ("executable", "argv", "env", "fd_sources")}
        for change in cases:
            with self.subTest(change=list(change)), self.assertRaises(m.NativeProcessError):
                m.SpawnSpec(**(original | change))

    def test_closed_and_wrong_creator_grants_make_zero_acquisitions(self):
        world = _World()
        with world.installed():
            acquisition = m.Acquisition()
            with self.assertRaises(m.NativeProcessError):
                acquisition.pipe()
            acquisition.grant(threading.Thread(), lambda: None)  # Object only, never started.
            with self.assertRaises(m.NativeProcessError):
                acquisition.open_null(writable=False)
            acquisition.close_launch()
            with self.assertRaises(m.NativeProcessError):
                acquisition.grant(threading.current_thread(), lambda: None)
            self.assertTrue(acquisition.launch_retired)
            self.assertEqual(world.events, [])
            self.assertEqual(world.instances, [])

        # Inert model only: never clear or substitute a genuine native receipt.
        retained = [object()]
        with patch.object(sys.modules[__name__], "_RETAINED_NATIVE_FIXTURES", retained), \
                patch.object(m, "Acquisition", side_effect=_World.denied) as acquisition, \
                patch.object(m, "assert_child_waitability", side_effect=_World.denied) as waitability, \
                patch.object(time, "monotonic", side_effect=_World.denied) as clock:
            with self.assertRaisesRegex(AssertionError,
                                        "^native fixture reuse is forbidden after retained UNKNOWN$"):
                _NativeFixture()
            self.assertIs(_RETAINED_NATIVE_FIXTURES, retained)
            self.assertEqual(len(retained), 1)
            acquisition.assert_not_called()
            waitability.assert_not_called()
            clock.assert_not_called()

    def test_declared_abi_uses_actual_layouts_and_shared_binding_signatures(self):
        world = _World()
        with patch.object(m, "_abi_types", return_value=world.abi), \
                patch.object(ctypes, "CDLL", side_effect=_World.denied):
            record = m.declared_abi()
            self.assertEqual(record["file_actions"]["size"], ctypes.sizeof(world.abi.file_actions))
            self.assertEqual(record["sigaction"]["fields"]["flags"]["offset"],
                             world.abi.sigaction.flags.offset)
            self.assertEqual(record["functions"]["fcntl"],
                             {"return": "int", "args": ["int", "int"], "variadic": True})
            self.assertEqual(record["functions"]["close"],
                             {"return": "int", "args": ["int"], "variadic": False})
            self.assertEqual(record["constants"]["NSIG"], 65)

            class WrongContainer(ctypes.Structure):
                _fields_ = [("allocated", ctypes.c_int)]

            world.abi.file_actions = WrongContainer
            self.assertEqual(m.declared_abi()["file_actions"]["size"], 4)
            with self.assertRaises(m.NativeProcessError):
                m._admit_abi(world.abi)

    def test_unknown_abi_and_missing_public_symbols_fail_before_acquisition(self):
        with patch.object(m.sys, "platform", "unsupported"), \
                patch.object(ctypes, "CDLL", side_effect=_World.denied):
            with self.assertRaises(m.NativeProcessError):
                m._Native()
        abi = _World().abi

        class MissingLibrary:
            def __getitem__(self, name):
                raise AttributeError(name)

        with patch.object(m, "_abi_types", return_value=abi), \
                patch.object(ctypes, "CDLL", return_value=MissingLibrary()), \
                patch.object(os, "pipe", side_effect=_World.denied):
            acquisition = _World.owner()
            with self.assertRaises(m.NativeProcessError):
                acquisition.pipe()
            self.assertFalse(acquisition.attempted)
            self.assertTrue(acquisition.launch_retired)
            self.assertEqual(acquisition.leases, ())
            with self.assertRaises(m.NativeProcessError):
                acquisition.pipe()

    def test_cdll_fcntl_binding_is_truly_variadic_and_private_per_acquisition(self):
        abi, libraries = _World().abi, []

        class Function:
            def __init__(self, name):
                self.name, self.calls = name, []

            def __call__(self, *args):
                self.calls.append(args)
                return b"2.39" if self.name == "gnu_get_libc_version" else 0

        class Library:
            def __init__(self, name, *, use_errno):
                self.name, self.use_errno, self.functions = name, use_errno, {}
                libraries.append(self)

            def __getitem__(self, name):
                result = Function(name)
                self.functions[name] = result
                return result

        with patch.object(m, "_abi_types", return_value=abi), patch.object(ctypes, "CDLL", Library):
            first, second = m._Native(), m._Native()
            first.call("fcntl", 21, abi.constants["F_DUPFD_CLOEXEC"], 8)
        function = first.functions["fcntl"]
        self.assertEqual(function.argtypes, [ctypes.c_int, ctypes.c_int])
        self.assertIs(type(function.calls[0][2]), ctypes.c_int)
        self.assertEqual(function.calls[0][2].value, 8)
        self.assertIsNot(function, second.functions["fcntl"])
        self.assertTrue(all(item.name is None and item.use_errno is True for item in libraries))

    def test_sigchld_inspection_rejects_disposal_without_changing_caller_policy(self):
        for handler, flags, accepted in ((1, 0, False), (0, 2, False), (1234, 1, True), (0, 0, True)):
            world = _World()
            with self.subTest(handler=handler, flags=flags), world.installed():
                io, acquisition = world.owner(), world.owner()
                spec = world.spec(world.sources(io))
                world.handler, world.signal_flags = handler, flags
                if accepted:
                    self.assertIs(m.create(acquisition, spec), acquisition.child)
                else:
                    with self.assertRaises(m.NativeProcessError):
                        m.create(acquisition, spec)
                    self.assertFalse(acquisition.attempted)
                self.assertTrue(all(event[2] is None for event in world.events if event[0] == "sigaction"))
                self.assertEqual((world.handler, world.signal_flags), (handler, flags))

    def test_signal_signature_compares_only_actual_policy_membership(self):
        # Actual ABI structs in memory only: no live native snapshot, setter,
        # process, descriptor or thread is needed to test this equality oracle.
        with patch.object(ctypes, "CDLL", side_effect=_World.denied), \
                patch.object(m, "_Native", side_effect=_World.denied):
            for family in ("linux-glibc", "darwin"):
                world = _World(family)
                native = types.SimpleNamespace(abi=world.abi, call=_World.denied)
                before = world.abi.sigaction()
                before.handler, before.flags = 1234, 0x100000
                signals = (1, world.abi.constants["SIGCHLD"], world.abi.constants["NSIG"] - 1)
                mask = sum(1 << (number - 1) for number in signals)
                if family == "linux-glibc":
                    before.mask[0], before.restorer = mask, 5678
                else:
                    before.mask = mask
                original = bytes(before)
                expected = (before.handler, before.flags,
                            tuple(number in signals for number in range(1, world.abi.constants["NSIG"])))
                if family == "linux-glibc":
                    expected += (before.restorer,)
                self.assertEqual(_signal_signature(native, before), expected)
                self.assertEqual(bytes(before), original)

                def compare(changed, *, equal):
                    left, right = bytes(before), bytes(changed)
                    actual = _signal_signature(native, before), _signal_signature(native, changed)
                    if equal:
                        self.assertEqual(*actual)
                    else:
                        self.assertNotEqual(*actual)
                    self.assertEqual(bytes(before), left)
                    self.assertEqual(bytes(changed), right)

                unused = world.abi.sigaction.from_buffer_copy(original)
                if family == "linux-glibc":
                    for index in range(1, len(unused.mask)):
                        unused.mask[index] = index * 0x10203
                else:
                    unused.mask ^= 1 << (world.abi.constants["NSIG"] - 1)
                with self.subTest(family=family, field="unused-mask-storage"):
                    self.assertNotEqual(bytes(unused), original)
                    compare(unused, equal=True)
                for number in signals:
                    changed = world.abi.sigaction.from_buffer_copy(original)
                    if family == "linux-glibc":
                        changed.mask[0] ^= 1 << (number - 1)
                    else:
                        changed.mask ^= 1 << (number - 1)
                    with self.subTest(family=family, signal=number):
                        compare(changed, equal=False)
                fields = (("handler", before.handler + 1), ("flags", before.flags ^ 1),
                          ("flags", before.flags ^ (1 << 31)))
                if family == "linux-glibc":
                    fields += (("restorer", before.restorer + 1),)
                for field, value in fields:
                    changed = world.abi.sigaction.from_buffer_copy(original)
                    setattr(changed, field, value)
                    with self.subTest(family=family, field=field, value=value):
                        compare(changed, equal=False)
                self.assertEqual(world.events, [])
                self.assertEqual(world.instances, [])

    def test_fd_factory_slots_are_prepublished_and_adoption_is_exact(self):
        world = _World()
        with world.installed():
            io = world.owner()

            def pipe():
                self.assertEqual([item.state for item in io.leases], ["ACQUIRING", "ACQUIRING"])
                return (world.allocate("pipe", os.O_RDONLY), world.allocate("pipe", os.O_WRONLY))

            world.overrides["pipe"] = pipe
            reader, writer = io.pipe()
            self.assertIs(io.leases[0], reader)
            self.assertIs(io.leases[1], writer)
            world.fds[5] = {"kind": "pipe", "access": os.O_RDONLY, "flags": 0, "inode": 900, "rdev": 0}
            adopted = io.adopt_fd(5, access=os.O_RDONLY, kind="pipe")
            self.assertEqual(adopted.fileno(), 5)
            self.assertEqual([event for event in world.events if event[0] == "set_inheritable"],
                             [("set_inheritable", 5, False)])
            for descriptor in (0, 1, 2, 5, 8):
                with self.subTest(fd=descriptor), self.assertRaises(m.NativeProcessError):
                    io.adopt_fd(descriptor, access=os.O_RDONLY, kind="pipe")

    def test_lost_fd_publication_is_unknown_and_never_closes_a_guessed_number(self):
        world, interruption = _World(), KeyboardInterrupt("private acquisition marker")
        with world.installed():
            io = world.owner()

            def pipe():
                world.allocate("pipe", os.O_RDONLY)
                world.allocate("pipe", os.O_WRONLY)
                raise interruption

            world.overrides["pipe"] = pipe
            with self.assertRaises(KeyboardInterrupt) as caught:
                io.pipe()
            self.assertIs(caught.exception, interruption)
            self.assertEqual([item.state for item in io.leases], ["UNKNOWN", "UNKNOWN"])
            for lease in io.leases:
                with self.assertRaises(m.NativeProcessError):
                    lease.close()
            self.assertTrue(io.cleanup_unknown)
            self.assertTrue(io.launch_retired)
            self.assertFalse(io.attempted)
            self.assertFalse(any(item[0] == "close" for item in world.events))

    def test_callback_failure_permanently_retires_admission_before_acquisition(self):
        world, interruption = _World(), SystemExit("private callback cancellation")
        with world.installed():
            def check():
                raise interruption

            acquisition = world.owner(check)
            with self.assertRaises(SystemExit) as caught:
                acquisition.pipe()
            self.assertIs(caught.exception, interruption)
            self.assertIs(acquisition.interruption, interruption)
            self.assertTrue(acquisition.launch_retired)
            self.assertTrue(acquisition.settled)
            self.assertFalse(acquisition.cleanup_unknown)
            self.assertEqual(acquisition.leases, ())
            self.assertEqual(world.instances, [])
            self.assertEqual(world.events, [])
            with self.assertRaises(m.NativeProcessError):
                acquisition.open_null(writable=True)

    def test_maps_use_high_atomic_sources_and_exact_final_native_closure(self):
        for family in ("linux-glibc", "darwin"):
            for count in (3, 8):
                world = _World(family)
                with self.subTest(family=family, count=count), world.installed():
                    io, acquisition = world.owner(), world.owner()
                    sources = world.sources(io, count)
                    originals = {source.fileno(): dict(world.fds[source.fileno()]) for source in sources}
                    child = m.create(acquisition, world.spec(sources))
                    self.assertIs(child, acquisition.child)
                    dup2 = [item for item in world.events if item[0] == "posix_spawn_file_actions_adddup2"]
                    self.assertEqual([item[3] for item in dup2], list(range(count)))
                    self.assertTrue(all(item[2] >= 8 and item[2] not in originals for item in dup2))
                    copies = [item for item in world.events if item[0] == "duplicate"]
                    self.assertEqual(len(copies), count)
                    self.assertTrue(all(item[2:] == (world.abi.constants["F_DUPFD_CLOEXEC"], 8) for item in copies))
                    closing = [item for item in world.events if item[0] == "posix_spawn_file_actions_addclosefrom_np"]
                    if family == "linux-glibc":
                        self.assertEqual(len(closing), 1)
                        self.assertEqual(closing[0][2], count)
                        action_events = [item for item in world.events if "_add" in item[0]]
                        self.assertIs(action_events[-1], closing[0])
                    else:
                        self.assertEqual(closing, [])
                        self.assertEqual(set(world.attribute_flags.values()), {0x4000})
                    self.assertEqual({fd: world.fds[fd] for fd in originals}, originals)
                    self.assertTrue(all(item.state == "CLOSED" for item in acquisition.leases))

    def test_wrong_direction_type_and_aliased_pipe_are_not_spawned(self):
        for defect in ("direction", "helper_type", "pipe_alias"):
            world = _World()
            with self.subTest(defect=defect), world.installed():
                io, acquisition = world.owner(), world.owner()
                sources = list(world.sources(io, 8 if defect == "helper_type" else 3))
                if defect == "direction":
                    sources[0] = io.open_null(writable=True)
                elif defect == "helper_type":
                    sources[0], _ = io.pipe()
                else:
                    _, writer = io.pipe()
                    sources[1] = sources[2] = writer
                with self.assertRaises(m.NativeProcessError):
                    m.create(acquisition, world.spec(tuple(sources)))
                self.assertFalse(acquisition.attempted)
                self.assertFalse(any(item[0] == "posix_spawn" for item in world.events))
                self.assertTrue(all(not item._borrowers for item in io.leases))

    def test_atomic_duplicate_error_never_uses_a_nonatomic_fallback(self):
        world = _World()
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            spec = world.spec(world.sources(io))
            world.overrides["duplicate"] = lambda *_args: -1
            with self.assertRaises(m.NativeProcessError):
                m.create(acquisition, spec)
            self.assertFalse(acquisition.attempted)
            self.assertFalse(acquisition.cleanup_unknown)
            self.assertEqual([item.state for item in acquisition.leases], ["NEW"])
            self.assertFalse(any(item[0] in ("set_inheritable", "posix_spawn") for item in world.events))

    def test_bad_duplicate_flags_close_only_the_genuinely_acquired_duplicate(self):
        world = _World()
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            spec = world.spec(world.sources(io))
            originals = set(world.fds)
            world.overrides["getfd"] = lambda fd, *_args: 1 if fd in originals else 0
            with self.assertRaises(m.NativeProcessError):
                m.create(acquisition, spec)
            self.assertFalse(acquisition.attempted)
            self.assertEqual(set(world.fds), originals)
            self.assertEqual(len([item for item in world.events if item[0] == "close"]), 1)

    def test_lost_duplicate_publication_keeps_unknown_slot_without_numeric_recovery(self):
        world = _World()
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            sources = world.sources(io)
            originals = set(world.fds)
            error = MemoryError("private duplicate result loss")

            def duplicate(fd, *_args):
                self.assertEqual(acquisition.leases[-1].state, "ACQUIRING")
                self.assertIn(acquisition, sources[0]._borrowers)
                row = world.fds[fd]
                world.allocate(row["kind"], row["access"], inode=row["inode"])
                raise error

            world.overrides["duplicate"] = duplicate
            with self.assertRaises(MemoryError) as caught:
                m.create(acquisition, world.spec(sources))
            self.assertIs(caught.exception, error)
            self.assertFalse(acquisition.attempted)
            self.assertTrue(acquisition.cleanup_unknown)
            self.assertEqual([lease.state for lease in acquisition.leases], ["UNKNOWN"])
            self.assertIs(acquisition._prepared.duplicates[0], acquisition.leases[0])
            self.assertEqual(len(set(world.fds) - originals), 1)
            self.assertFalse(any(event[0] in ("close", "posix_spawn", "waitpid") for event in world.events))

    def test_pipe_alias_identity_is_rejected_across_distinct_leases(self):
        world = _World()
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            _, first = io.pipe()
            descriptor = world.allocate("pipe", os.O_WRONLY, inode=first._identity[1])
            second = io._new_lease()
            second._publish(descriptor, io._native, os.O_WRONLY, "pipe")
            second._validate()
            self.assertIsNot(first, second)
            self.assertNotEqual(first.fileno(), second.fileno())
            with self.assertRaises(m.NativeProcessError):
                m.create(acquisition, world.spec((io.open_null(writable=False), first, second)))
            self.assertFalse(acquisition.attempted)
            self.assertFalse(any(event[0] == "duplicate" for event in world.events))

    def test_darwin_flags_and_getter_publication_are_real_admission_gates(self):
        for result, flags, destroy in ((0, 0, True), (False, 0x4000, False), (22, 0x4000, True)):
            world = _World("darwin")
            with self.subTest(result=result, flags=flags), world.installed():
                io, acquisition = world.owner(), world.owner()

                def getter(_attributes, output):
                    output._obj.value = flags
                    return result

                world.overrides["posix_spawnattr_getflags"] = getter
                with self.assertRaises(m.NativeProcessError):
                    m.create(acquisition, world.spec(world.sources(io)))
                self.assertFalse(acquisition.attempted)
                self.assertEqual(sum(event[0] == "posix_spawnattr_destroy" for event in world.events), int(destroy))
                self.assertEqual(sum(event[0] == "posix_spawn_file_actions_destroy" for event in world.events), 1)

    def test_waitability_is_rechecked_immediately_before_the_native_attempt(self):
        world = _World()
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            inspections = []

            def inspect(_signo, new, output):
                self.assertIsNone(new)
                inspections.append(output)
                output._obj.handler = 0 if len(inspections) == 1 else 1
                output._obj.flags = 0
                return 0

            world.overrides["sigaction"] = inspect
            with self.assertRaises(m.NativeProcessError):
                m.create(acquisition, world.spec(world.sources(io)))
            self.assertFalse(acquisition.attempted)
            self.assertEqual(len(inspections), 2)
            self.assertTrue(all(lease.state == "CLOSED" for lease in acquisition.leases))
            self.assertEqual(acquisition._prepared.actions.state, "RETIRED")
            self.assertFalse(any(event[0] == "posix_spawn" for event in world.events))

    def test_init_and_setter_failures_destroy_only_confirmed_containers(self):
        cases = (("posix_spawn_file_actions_init", 12, False),
                 ("posix_spawn_file_actions_adddup2", 22, True),
                 ("posix_spawn_file_actions_adddup2", MemoryError("lost setter"), False))
        for operation, failure, destroy in cases:
            world = _World()
            with self.subTest(operation=operation, failure=type(failure).__name__), world.installed():
                io, acquisition = world.owner(), world.owner()
                spec = world.spec(world.sources(io))

                def fail(*_args):
                    if isinstance(failure, BaseException):
                        raise failure
                    return failure

                world.overrides[operation] = fail
                with self.assertRaises((m.NativeProcessError, MemoryError)):
                    m.create(acquisition, spec)
                self.assertFalse(acquisition.attempted)
                self.assertEqual(sum(item[0] == "posix_spawn_file_actions_destroy" for item in world.events),
                                 int(destroy))
                self.assertTrue(all(item.state == "CLOSED" for item in acquisition.leases))

    def test_destroy_and_close_failures_preserve_child_and_first_primary_order(self):
        world = _World()
        later = KeyboardInterrupt("private later cancellation")
        with world.installed():
            recorded = []

            def record(error):
                if not any(error is earlier for earlier in recorded):
                    recorded.append(error)

            io, acquisition = world.owner(), world.owner(recorder=record)
            spec = world.spec(world.sources(io))
            first = OSError("private destroy marker")

            def destroy(*_args):
                raise first

            count = 0

            def close(fd):
                nonlocal count
                self.assertIs(recorded[0], first)
                count += 1
                del world.fds[fd]
                if count == 1:
                    raise later
                return 0

            world.overrides.update(posix_spawn_file_actions_destroy=destroy, close=close)
            with self.assertRaises(OSError) as caught:
                m.create(acquisition, spec)
            self.assertIs(caught.exception, first)
            self.assertEqual(recorded, [first, later])
            self.assertIsNotNone(acquisition.child)
            self.assertIs(acquisition.interruption, later)
            self.assertTrue(acquisition.cleanup_unknown)
            self.assertEqual(count, 3)
            self.assertTrue(all("private" not in code for code in acquisition.cleanup_errors))
            self.assertEqual(sum(item[0] == "posix_spawn_file_actions_destroy" for item in world.events), 1)

    def test_shared_recorder_orders_body_and_caller_errors_at_the_actual_catches(self):
        for caller_first in (False, True):
            world = _World()
            native_error = OSError("private native failure")
            caller_error = KeyboardInterrupt("private caller interruption")
            lock, recorded = threading.Lock(), []  # No task is started by this pure control.

            def record(error):
                with lock:
                    if not any(error is earlier for earlier in recorded):
                        recorded.append(error)

            with self.subTest(caller_first=caller_first), world.installed():
                io, acquisition = world.owner(), world.owner(recorder=record)

                def spawn(*_args):
                    if caller_first:
                        record(caller_error)  # The caller records during the outstanding native call.
                    raise native_error

                def destroy(*_args):
                    self.assertIs(recorded[0], caller_error if caller_first else native_error)
                    if not caller_first:
                        record(caller_error)  # Separate cleanup cannot overtake an already caught body error.
                    return 0

                world.overrides.update(posix_spawn=spawn, posix_spawn_file_actions_destroy=destroy)
                with self.assertRaises(OSError) as caught:
                    m.create(acquisition, world.spec(world.sources(io)))
                record(caught.exception)  # The later whole-task handoff is the SAME object.
                self.assertIs(caught.exception, native_error)
                self.assertEqual(recorded, [caller_error, native_error] if caller_first else [native_error, caller_error])
                self.assertTrue(all(lease.state == "CLOSED" for lease in acquisition.leases))

    def test_recorder_failure_keeps_original_primary_and_required_cleanup(self):
        for first in (OSError("private original operation"), SystemExit("private original interruption")):
            world, later = _World(), KeyboardInterrupt("private recorder interruption")
            with self.subTest(first=type(first).__name__), world.installed():
                seen = []

                def record(error):
                    if not seen:
                        self.assertIsNone(acquisition._first_error)
                        self.assertIsNone(acquisition.interruption)
                        self.assertFalse(acquisition.launch_retired)
                    seen.append(error)
                    raise later

                io, acquisition = world.owner(), world.owner(recorder=record)

                def spawn(*_args):
                    raise first

                world.overrides["posix_spawn"] = spawn
                with self.assertRaises(type(first)) as caught:
                    m.create(acquisition, world.spec(world.sources(io)))
                self.assertIs(caught.exception, first)
                self.assertIs(acquisition._first_error, first)
                self.assertIs(acquisition._recorder_error, later)
                self.assertIs(seen[0], first)
                self.assertIs(acquisition.interruption, first if isinstance(first, SystemExit) else later)
                self.assertTrue(acquisition.cleanup_unknown)
                self.assertIn("failure_record", acquisition.cleanup_errors)
                self.assertTrue(all("private" not in code for code in acquisition.cleanup_errors))
                self.assertEqual(acquisition._prepared.actions.state, "RETIRED")
                self.assertTrue(all(lease.state == "CLOSED" for lease in acquisition.leases))
                self.assertTrue(acquisition.settled)

    def test_io_and_wait_errors_reach_the_bound_recorder_without_late_forwarding(self):
        world, records = _World(), []
        with world.installed():
            first = OSError("private IO publication error")

            def record(error):
                if not any(error is earlier for earlier in records):
                    records.append(error)

            def pipe():
                raise first

            io = world.owner(recorder=record)
            world.overrides["pipe"] = pipe
            with self.assertRaises(OSError) as caught:
                io.pipe()
            self.assertIs(caught.exception, first)
            self.assertEqual(records, [first])
            del world.overrides["pipe"]
            fresh_io, acquisition = world.owner(), world.owner(recorder=record)
            child = m.create(acquisition, world.spec(world.sources(fresh_io)))
            wait_error = ChildProcessError(errno.ECHILD, "private lost wait")
            world.wait_results.append(wait_error)
            with self.assertRaises(ChildProcessError) as caught:
                child.poll_wait()
            self.assertIs(caught.exception, wait_error)
            self.assertEqual(records, [first, wait_error])
            self.assertIs(acquisition._failure_recorder, record)
            self.assertEqual(child.wait_state, "UNKNOWN")

    def test_first_body_interruption_identity_survives_later_cleanup_errors(self):
        world = _World()
        first = SystemExit("private original cancellation")
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            spec = world.spec(world.sources(io))

            def spawn(*args):
                args[0]._obj.value = 701
                raise first

            world.overrides["posix_spawn"] = spawn
            world.overrides["posix_spawn_file_actions_destroy"] = lambda *_args: 22
            with self.assertRaises(SystemExit) as caught:
                m.create(acquisition, spec)
            self.assertIs(caught.exception, first)
            self.assertIs(acquisition.interruption, first)
            self.assertTrue(acquisition.cleanup_unknown)
            self.assertIsNone(acquisition.child)

    def test_first_body_error_survives_unexpected_cleanup_tail_interruption(self):
        world = _World()
        first, later = OSError("private first failure"), KeyboardInterrupt("private later interruption")
        with world.installed():
            io, acquisition = world.owner(), world.owner()

            def spawn(*_args):
                raise first

            world.overrides["posix_spawn"] = spawn
            with patch.object(m, "_close_transients", side_effect=later):
                with self.assertRaises(OSError) as caught:
                    m.create(acquisition, world.spec(world.sources(io)))
            self.assertIs(caught.exception, first)
            self.assertIs(acquisition.interruption, later)
            self.assertIn("cleanup_tail", acquisition.cleanup_errors)
            self.assertTrue(acquisition.settled)
            self.assertTrue(acquisition.cleanup_unknown)
            self.assertTrue(acquisition._prepared.strings)
            self.assertTrue(all(lease._borrowers for lease in acquisition._borrowed))

    def test_native_error_or_pid_output_alone_is_unknown_not_no_attempt(self):
        for result, pid in ((2, 0), (2, 701), (0, 0), (False, 701)):
            world = _World()
            with self.subTest(result=result, pid=pid), world.installed():
                io, acquisition = world.owner(), world.owner()
                spec = world.spec(world.sources(io))

                def spawn(*args):
                    args[0]._obj.value = pid
                    return result

                world.overrides["posix_spawn"] = spawn
                with self.assertRaises(m.NativeProcessError):
                    m.create(acquisition, spec)
                self.assertTrue(acquisition.attempted)
                self.assertEqual(acquisition.state, "UNKNOWN")
                self.assertIsNone(acquisition.child)
                self.assertTrue(acquisition.cleanup_unknown)
                self.assertTrue(acquisition.launch_retired)
                with self.assertRaises(m.NativeProcessError):
                    m.create(acquisition, spec)
                self.assertFalse(any(item[0] == "waitpid" for item in world.events))

    def test_lost_spawn_publication_retains_original_buffers_without_numeric_recovery(self):
        world = _World()
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            spec = world.spec(world.sources(io))

            def spawn(*args):
                self.assertFalse(acquisition.settled)
                self.assertEqual(acquisition.state, "ATTEMPTING")
                prepared = acquisition._prepared
                self.assertEqual(prepared.path.raw, b"/fixed/python\0")
                self.assertIsNone(prepared.argv[len(spec.argv)])
                self.assertIsNone(prepared.env[len(spec.env)])
                args[0]._obj.value = 701
                raise MemoryError("post native return loss")

            world.overrides["posix_spawn"] = spawn
            with self.assertRaises(MemoryError):
                m.create(acquisition, spec)
            self.assertTrue(acquisition.settled)  # Leaf returned, NOT an invented task join.
            self.assertTrue(acquisition.cleanup_unknown)
            self.assertIsNone(acquisition.child)
            self.assertEqual(acquisition._prepared.pid.value, 701)
            self.assertTrue(acquisition._prepared.strings)
            self.assertIs(acquisition._prepared.native, acquisition._native)

    def test_late_native_return_cannot_reopen_launch_or_discard_child_custody(self):
        world = _World()
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            spec = world.spec(world.sources(io))

            def spawn(*args):
                acquisition.close_launch()
                args[0]._obj.value = 701
                return 0

            world.overrides["posix_spawn"] = spawn
            child = m.create(acquisition, spec)
            self.assertIs(child, acquisition.child)
            self.assertTrue(acquisition.launch_retired)
            with self.assertRaises(m.NativeProcessError):
                acquisition.grant(threading.current_thread(), lambda: None)
            self.assertEqual(child.pid, 701)

    def test_borrowed_sources_cannot_close_during_a_native_call(self):
        world = _World()
        with world.installed():
            io, acquisition = world.owner(), world.owner()
            sources = world.sources(io)

            def spawn(*args):
                with self.assertRaises(m.NativeProcessError):
                    sources[0].close()
                self.assertEqual(sources[0].state, "OPEN")
                args[0]._obj.value = 701
                return 0

            world.overrides["posix_spawn"] = spawn
            m.create(acquisition, world.spec(sources))
            sources[0].close()
            self.assertEqual(sources[0].state, "CLOSED")

    def test_first_wait_retires_numeric_routes_before_every_exact_poll(self):
        world = _World()
        with world.installed():
            _, acquisition, child = world.child()
            calls = []

            def wait(pid, flags):
                self.assertTrue(child.numeric_retired)
                self.assertEqual(child.wait_state, "WAIT_IN_FLIGHT")
                self.assertEqual((pid, flags), (child.pid, os.WNOHANG))
                calls.append(pid)
                return (0, 0) if len(calls) == 1 else (pid, 7 << 8)

            world.overrides["waitpid"] = wait
            self.assertIsNone(child.poll_wait())
            self.assertEqual(child.wait_state, "POLLABLE")
            receipt = child.poll_wait()
            self.assertEqual((receipt.pid, receipt.status_kind, receipt.status_code, receipt.raw_status),
                             (child.pid, "exit", 7, 7 << 8))
            self.assertIs(child.poll_wait(), receipt)
            self.assertEqual(len(calls), 2)
            self.assertFalse(acquisition.cleanup_unknown)

    def test_echild_eintr_and_lost_wait_publication_are_absorbing_unknown(self):
        failures = (ChildProcessError(errno.ECHILD, "no child"), InterruptedError(errno.EINTR, "interrupted"),
                    MemoryError("post-consumption result lost"), KeyboardInterrupt("actual first interruption"))
        for error in failures:
            world = _World()
            with self.subTest(error=type(error).__name__), world.installed():
                _, acquisition, child = world.child()
                world.wait_results.append(error)
                with self.assertRaises(type(error)) as caught:
                    child.poll_wait()
                self.assertIs(caught.exception, error)
                self.assertEqual(child.wait_state, "UNKNOWN")
                self.assertTrue(child.numeric_retired)
                self.assertTrue(acquisition.cleanup_unknown)
                if isinstance(error, KeyboardInterrupt):
                    self.assertIs(acquisition.interruption, error)
                with self.assertRaises(m.NativeProcessError):
                    child.poll_wait()
                self.assertEqual(sum(item[0] == "waitpid" for item in world.events), 1)

    def test_only_exact_terminal_statuses_become_wait_receipts(self):
        invalid = (None, (), (True, 0), (701, True), (0, 1), (702, 0),
                   (701, (signal.SIGSTOP << 8) | 0x7f), (701, 0xffff))
        for returned in invalid:
            world = _World()
            with self.subTest(returned=returned), world.installed():
                _, _, child = world.child()
                world.wait_results.append(returned)
                with self.assertRaises((m.NativeProcessError, ValueError)):
                    child.poll_wait()
                self.assertEqual(child.wait_state, "UNKNOWN")
                self.assertIsNone(child.receipt)
        world = _World()
        with world.installed():
            _, _, child = world.child()
            world.wait_results.append((child.pid, int(signal.SIGTERM)))
            receipt = child.poll_wait()
            self.assertEqual((receipt.status_kind, receipt.status_code), ("signal", signal.SIGTERM))

    def test_wait_owner_cannot_change_after_a_genuine_zero(self):
        world = _World()
        with world.installed():
            _, acquisition, child = world.child()
            world.wait_results.append((0, 0))
            self.assertIsNone(child.poll_wait())
            other = threading.Thread()  # Never started, so this remains a pure case.
            with patch.object(m.threading, "current_thread", return_value=other), self.assertRaises(m.NativeProcessError):
                child.poll_wait()
            self.assertEqual(child.wait_state, "UNKNOWN")
            self.assertTrue(acquisition.cleanup_unknown)
            self.assertEqual(sum(item[0] == "waitpid" for item in world.events), 1)

    def test_no_attempt_does_not_mean_initially_closed_or_empty_child_slot(self):
        acquisition = m.Acquisition()
        self.assertTrue(acquisition.settled)
        self.assertIsNone(acquisition.child)
        self.assertFalse(acquisition.attempted)
        self.assertFalse(acquisition.launch_retired)
        self.assertFalse(hasattr(acquisition, "joined"))
        self.assertFalse(hasattr(acquisition, "no_producers"))
        acquisition.close_launch()
        self.assertTrue(acquisition.launch_retired)
        with self.assertRaises(m.NativeProcessError):
            acquisition.grant(threading.current_thread(), lambda: None)

    def test_close_is_once_even_after_errno_or_lost_return(self):
        for failure in (-1, MemoryError("close consumed then result lost"), None):
            world = _World()
            with self.subTest(failure=type(failure).__name__), world.installed():
                io = world.owner()
                lease = io.open_null(writable=False)
                original = lease.fileno()

                def close(fd):
                    self.assertEqual(fd, original)
                    self.assertEqual(lease.state, "CLOSE_IN_FLIGHT")
                    del world.fds[fd]
                    if isinstance(failure, BaseException):
                        raise failure
                    return 0 if failure is None else failure

                world.overrides["close"] = close
                if failure is None:
                    lease.close()
                    lease.close()
                    self.assertEqual(lease.state, "CLOSED")
                else:
                    with self.assertRaises((m.NativeProcessError, MemoryError)):
                        lease.close()
                    with self.assertRaises(m.NativeProcessError):
                        lease.close()
                    self.assertTrue(lease.unknown)
                    self.assertTrue(io.cleanup_unknown)
                with self.assertRaises(m.NativeProcessError):
                    lease.fileno()
                self.assertEqual(sum(item[0] == "close" for item in world.events), 1)


# These roots intentionally have no finalizer.  A failed native fixture cannot
# turn an unknown creator/child/resource into a guessed cleanup or silent reuse.
_RETAINED_NATIVE_FIXTURES = []


class _NativeScratch:
    """Exact private fixture directory; UNKNOWN never authorizes its deletion."""

    def __init__(self):
        self.directory = self.fifo = None
        self.directory_identity = self.fifo_identity = None
        self.state = "NEW"

    @staticmethod
    def identity(path):
        info = os.lstat(path)
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid

    def acquire(self, *, fifo):
        self.state = "ACQUIRING"
        try:
            self.directory = Path(tempfile.mkdtemp(prefix="mrk-native-control-"))
            self.directory_identity = self.identity(self.directory)
            mode = self.directory_identity[2]
            if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o700:
                raise AssertionError("native fixture private directory mode differs")
            if self.directory_identity[3] != os.getuid():
                raise AssertionError("native fixture private directory owner differs")
            if fifo:
                self.fifo = self.directory / "release.fifo"
                os.mkfifo(self.fifo, 0o600)
                self.fifo_identity = self.identity(self.fifo)
                if (not stat.S_ISFIFO(self.fifo_identity[2])
                        or stat.S_IMODE(self.fifo_identity[2]) != 0o600
                        or self.fifo_identity[3] != os.getuid()):
                    raise AssertionError("native fixture FIFO type differs")
            self.state = "OWNED"
        except BaseException:
            self.state = "UNKNOWN"
            raise

    def remove(self):
        if self.state == "NEW":
            return
        if self.state != "OWNED" or self.identity(self.directory) != self.directory_identity:
            raise AssertionError("native fixture scratch custody is unknown")
        expected = [] if self.fifo is None else [self.fifo]
        if list(self.directory.iterdir()) != expected:
            raise AssertionError("native fixture scratch contents differ")
        if self.fifo is not None and self.identity(self.fifo) != self.fifo_identity:
            raise AssertionError("native fixture FIFO identity differs")
        self.state = "REMOVING"  # No retry or pathname reconstruction after a lost return.
        if self.fifo is not None:
            os.unlink(self.fifo)
        if self.identity(self.directory) != self.directory_identity:
            raise AssertionError("native fixture scratch identity changed")
        os.rmdir(self.directory)
        self.state = "REMOVED"


class _NativeTask:
    """A prepublished fixture task, granted only after actual self reconciliation."""

    def __init__(self, fixture, acquisition, spec, function):
        self.fixture, self.acquisition, self.spec, self.function = fixture, acquisition, spec, function
        self.observed_thread = None
        self.started, self.permission, self.finished = threading.Event(), threading.Event(), threading.Event()
        self.allowed = self.start_attempted = self.joined = False
        self.error = self.launch_error = self.result = None
        self.grants = 0
        self.thread = threading.Thread(target=self.run, name="mrk-owned-native-test-creator", daemon=False)

    def run(self):
        try:
            self.observed_thread = threading.current_thread()
            self.started.set()
            if not self.permission.wait(max(0.0, self.fixture.expires - time.monotonic())):
                raise AssertionError("native fixture task permission deadline expired")
            if not self.allowed:
                return
            if self.observed_thread is not self.thread:
                raise AssertionError("native fixture creator identity differs")
            self.result = self.function(self.acquisition, self.spec)
        except BaseException as error:
            self.error = error
            self.acquisition.close_launch()
        finally:
            self.finished.set()  # A tail observation, never a substitute for join.

    def launch(self, check):
        try:
            self.fixture.check()
            self.start_attempted = True
            self.thread.start()
            if not self.started.wait(max(0.0, self.fixture.expires - time.monotonic())):
                raise AssertionError("native fixture creator did not publish itself")
            if self.observed_thread is not self.thread:
                raise AssertionError("native fixture creator reconciliation differs")
            self.fixture.check()
            check()
            self.acquisition.grant(self.thread, check)
            self.grants += 1
            self.allowed = True
            self.permission.set()
        except BaseException as error:
            self.launch_error = error
            self.acquisition.close_launch()
            self.allowed = False
            self.permission.set()  # Reject a possibly started task; do not lose it.
            raise

    def join(self):
        if self.joined or not self.start_attempted:
            return
        self.thread.join(max(0.0, self.fixture.expires - time.monotonic()))
        if (self.thread.is_alive() or self.observed_thread is not self.thread
                or not self.finished.is_set()):
            raise AssertionError("native fixture creator was not genuinely joined")
        self.joined = True


class _NativeFixture:
    """Small fixed-child controls, ONLY within the reviewed hosted native owner."""

    def __init__(self):
        if _RETAINED_NATIVE_FIXTURES:
            raise AssertionError("native fixture reuse is forbidden after retained UNKNOWN")
        self.expires = time.monotonic() + 10.0
        self.io = m.Acquisition()
        self.io.grant(threading.current_thread(), self.check)
        self.acquisitions, self.tasks = [], []
        self.controls = []
        self.scratch = None
        self.closed = False
        m.assert_child_waitability()

    def check(self):
        if time.monotonic() >= self.expires:
            raise AssertionError("native primitive fixture deadline expired")

    def acquisition(self, *, grant=True):
        acquisition = m.Acquisition()
        self.acquisitions.append(acquisition)  # Before any native attempt.
        if grant:
            acquisition.grant(threading.current_thread(), self.check)
        return acquisition

    def start(self, spec, *, function=m.create, check=None, acquisition=None):
        if acquisition is None:
            acquisition = self.acquisition(grant=False)
        elif acquisition not in self.acquisitions or acquisition._grant_used:
            raise AssertionError("native fixture creator acquisition was not prepublished")
        task = _NativeTask(self, acquisition, spec, function)
        self.tasks.append(task)  # Before Thread.start, including an exceptional start.
        task.launch(self.check if check is None else check)
        return task

    def private_scratch(self, *, fifo=True):
        if self.scratch is not None:
            raise AssertionError("native fixture scratch acquisition was repeated")
        self.scratch = _NativeScratch()  # Before directory/FIFO acquisition.
        self.scratch.acquire(fifo=fifo)
        return self.scratch

    def nulls(self):
        return (self.io.open_null(writable=False), self.io.open_null(writable=True),
                self.io.open_null(writable=True))

    @staticmethod
    def spec(code, sources, arguments=()):
        executable = str(Path(sys.executable).absolute())
        return m.SpawnSpec(executable, (executable, "-I", "-S", "-B", "-c", code, *arguments),
                           (("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"), ("LC_ALL", "C"), ("LANG", "C")),
                           tuple(sources))

    def create(self, spec):
        acquisition = self.acquisition()
        return m.create(acquisition, spec)

    def wait(self, child):
        while True:
            self.check()
            receipt = child.poll_wait()
            if receipt is not None:
                return receipt
            time.sleep(0.005)

    def read(self, reader, *, exact=None):
        descriptor = reader.fileno()
        os.set_blocking(descriptor, False)
        output = bytearray()
        while True:
            self.check()
            ready, _, _ = select.select([descriptor], [], [], max(0.0, min(0.02, self.expires - time.monotonic())))
            if ready:
                try:
                    raw = os.read(descriptor, 1024 if exact is None else exact - len(output))
                except BlockingIOError:
                    continue
                if not raw:
                    if exact is not None and len(output) != exact:
                        raise AssertionError("native fixture output was truncated")
                    return bytes(output)
                output.extend(raw)
                if exact is not None and len(output) == exact:
                    return bytes(output)
                if len(output) > 8192:
                    raise AssertionError("native fixture output exceeded its bound")

    def finish(self):
        if self.closed:
            return
        self.closed = True
        errors = []
        self.io.close_launch()
        for acquisition in self.acquisitions:
            acquisition.close_launch()
        # Release owned, unborrowed writers before waits; their real EOF may be
        # the fixed child's progress condition.  Never close a native source in
        # an outstanding creator, and never signal a numeric cleanup guess.
        for lease in self.io.leases:
            if lease._borrowers or any(not task.joined and lease in task.spec.fd_sources for task in self.tasks):
                continue
            try:
                lease.close()
            except BaseException as error:
                errors.append(error)
        for task in self.tasks:
            try:
                task.acquisition.close_launch()
                if not task.allowed:
                    task.permission.set()
                task.join()
                if task.error is not None:
                    errors.append(task.error)
                if task.launch_error is not None:
                    errors.append(task.launch_error)
            except BaseException as error:
                errors.append(error)
        for lease in self.io.leases:
            if lease.state in ("NEW", "CLOSED"):
                continue
            if lease._borrowers or any(not task.joined and lease in task.spec.fd_sources for task in self.tasks):
                errors.append(AssertionError("native fixture source still belongs to an unjoined creator"))
                continue
            try:
                lease.close()
            except BaseException as error:
                errors.append(error)
        for acquisition in self.acquisitions:
            child = acquisition.child
            try:
                if any(task.acquisition is acquisition and not task.joined for task in self.tasks):
                    raise AssertionError("native fixture child still belongs to an unjoined creator")
                if child is not None and child.wait_state != "UNKNOWN":
                    self.wait(child)
                if (not acquisition.settled or acquisition.cleanup_unknown
                        or (acquisition.attempted and (child is None or child.receipt is None))):
                    raise AssertionError("native fixture child custody remains unknown")
            except BaseException as error:
                errors.append(error)
        if self.io.cleanup_unknown or not self.io.settled:
            errors.append(AssertionError("native fixture descriptor custody remains unknown"))
        if not errors and self.scratch is not None:
            try:
                self.scratch.remove()
            except BaseException as error:
                errors.append(error)
        if errors:
            _RETAINED_NATIVE_FIXTURES.append(self)
            raise BaseExceptionGroup("native fixture finality could not be confirmed", errors)


class NativeProcessCompatibilityTests(unittest.TestCase):
    def test_native_public_api_atomic_duplication(self):
        """Actual CDLL/atomic-FD/container calls, deliberately NO child/wait."""
        fixture = _NativeFixture()
        acquisition = fixture.acquisition()
        try:
            sources = fixture.nulls()
            original = [(source.fileno(), os.get_inheritable(source.fileno()), os.fstat(source.fileno()))
                        for source in sources]
            prepared = m._prepare(acquisition, fixture.spec("pass", sources))
            self.assertFalse(acquisition.attempted)
            self.assertIsNone(acquisition.child)
            self.assertEqual(len(prepared.duplicates), 3)
            for duplicate, source in zip(prepared.duplicates, sources):
                self.assertGreaterEqual(duplicate.fileno(), 8)
                self.assertNotEqual(duplicate.fileno(), source.fileno())
                self.assertFalse(os.get_inheritable(duplicate.fileno()))
                self.assertEqual(os.fstat(duplicate.fileno()).st_rdev, os.fstat(source.fileno()).st_rdev)
            for source, (descriptor, inheritable, info) in zip(sources, original):
                self.assertEqual(source.fileno(), descriptor)
                self.assertEqual(os.get_inheritable(descriptor), inheritable)
                self.assertEqual(os.fstat(descriptor), info)
            acquisition.close_launch()
            self.assertIsNone(m._close_transients(acquisition))
            self.assertEqual(prepared.actions.state, "RETIRED")
            if prepared.attributes is not None:
                self.assertEqual(prepared.attributes.state, "RETIRED")
            self.assertTrue(all(item.state == "CLOSED" for item in prepared.duplicates))
        finally:
            # A pre-attempt exception still requires actual container/dup closes.
            acquisition.close_launch()
            cleanup = m._close_transients(acquisition)
            fixture.finish()
            if cleanup is not None:
                raise cleanup

    def test_native_helper_and_validator_fd_maps(self):
        code = ("import fcntl,json,os,stat,sys\n"
                "n,output,low,high=map(int,sys.argv[1:5])\n"
                "rows=[]\n"
                "for fd in range(n):\n"
                " s=os.fstat(fd); rows.append([fd,stat.S_IFMT(s.st_mode),fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE,s.st_dev,s.st_ino,s.st_rdev])\n"
                "extras=[]\n"
                "for fd in (low,high):\n"
                " try: s=os.fstat(fd); extras.append([fd,s.st_dev,s.st_ino])\n"
                " except OSError as e:\n"
                "  if e.errno!=9: raise\n"
                "  extras.append([fd,None,None])\n"
                "os.write(output,json.dumps({'rows':rows,'extras':extras},separators=(',',':')).encode('ascii'))\n")
        for count in (3, 8):
            with self.subTest(map=count):
                fixture = _NativeFixture()
                try:
                    sentinel, _ = fixture.io.pipe()
                    low = sentinel.fileno()
                    self.assertLessEqual(low, 7, "fresh native fixture lacks the required owned low collision")
                    native = fixture.io._runtime()
                    high_lease = fixture.io._new_lease()
                    high_lease._state = "ACQUIRING"
                    high = fixture.io._invoke("fd_duplicate", native.call, "fcntl", low,
                                              native.abi.constants["F_DUPFD_CLOEXEC"], 64, roots=(high_lease,))
                    self.assertIs(type(high), int)
                    self.assertGreaterEqual(high, 64)
                    high_lease._publish(high, native, os.O_RDONLY, "pipe")
                    high_lease._validate()
                    os.set_inheritable(low, True)
                    os.set_inheritable(high, True)
                    sentinel_info = os.fstat(low)
                    output_reader, output_writer = fixture.io.pipe()
                    if count == 3:
                        sources = (fixture.io.open_null(writable=False), output_writer,
                                   fixture.io.open_null(writable=True))
                        output = 1
                    else:
                        control, _ = fixture.io.pipe()
                        _, status_writer = fixture.io.pipe()
                        sources = (*fixture.nulls(), control, status_writer,
                                   fixture.io.open_null(writable=False), output_writer,
                                   fixture.io.open_null(writable=True))
                        output = 6
                    modes = [os.O_RDONLY, os.O_WRONLY, os.O_WRONLY, os.O_RDONLY,
                             os.O_WRONLY, os.O_RDONLY, os.O_WRONLY, os.O_WRONLY][:count]
                    expected = []
                    for index, source in enumerate(sources):
                        info = os.fstat(source.fileno())
                        expected.append([index, stat.S_IFMT(info.st_mode), modes[index],
                                         info.st_dev, info.st_ino, info.st_rdev])
                    child = fixture.create(fixture.spec(code, sources, tuple(map(str, (count, output, low, high)))))
                    output_writer.close()  # Genuine EOF is independent of the result/wait.
                    record = json.loads(fixture.read(output_reader).decode("ascii"))
                    self.assertEqual(fixture.wait(child).status_code, 0)
                    self.assertEqual(record["rows"], expected)
                    for fd, device, inode in record["extras"]:
                        self.assertNotEqual((device, inode), (sentinel_info.st_dev, sentinel_info.st_ino))
                        if fd == high or fd >= count:
                            self.assertIsNone(device)
                            self.assertIsNone(inode)
                    self.assertEqual(os.fstat(low), sentinel_info)
                    self.assertEqual(os.fstat(high), sentinel_info)
                    self.assertTrue(os.get_inheritable(low))
                    self.assertTrue(os.get_inheritable(high))
                finally:
                    fixture.finish()


    def test_native_exact_terminal_wait_receipts(self):
        code = ("import os,signal,sys\n"
                "if os.read(0,1)!=b'x': sys.exit(98)\n"
                "mode=sys.argv[1]\n"
                "if mode=='signal':\n"
                " signal.signal(signal.SIGTERM,signal.SIG_DFL); os.kill(os.getpid(),signal.SIGTERM)\n"
                " sys.exit(99)\n"
                "sys.exit(int(mode))\n")
        for mode, kind, status in (("0", "exit", 0), ("7", "exit", 7), ("signal", "signal", signal.SIGTERM)):
            with self.subTest(mode=mode):
                fixture = _NativeFixture()
                try:
                    reader, writer = fixture.io.pipe()
                    sources = (reader, fixture.io.open_null(writable=True), fixture.io.open_null(writable=True))
                    child = fixture.create(fixture.spec(code, sources, (mode,)))
                    self.assertIsNone(child.poll_wait())  # Child cannot finish before this owned input.
                    self.assertTrue(child.numeric_retired)
                    self.assertEqual(os.write(writer.fileno(), b"x"), 1)
                    writer.close()
                    receipt = fixture.wait(child)
                    self.assertEqual((receipt.pid, receipt.status_kind, receipt.status_code),
                                     (child.pid, kind, status))
                    self.assertIs(child.poll_wait(), receipt)
                    self.assertEqual(os.waitstatus_to_exitcode(receipt.raw_status),
                                     status if kind == "exit" else -status)
                finally:
                    fixture.finish()


class _FifoAction:
    """Test-only open8 AFTER all dup2 actions, BEFORE final native closure.

    native_process_abi.c statically checks this exact prototype and mode_t:
    unsigned int/4 Linux, unsigned short/2 Darwin.  It is NOT a production
    declaration, import effect, helper role, native extension or schema field.
    Linux's genuine final closefrom closes8; Darwin gets test-only public
    addclose8 (also header-checked), after the FIFO action, before exec.
    """

    def __init__(self, acquisition, path):
        self.acquisition, self.path = acquisition, path
        self.original_update = m._update
        self.prepared = self.function = self.close_function = self.path_buffer = None
        self.installed = False
        self.entered, self.returned = threading.Event(), threading.Event()

    def update(self, acquisition, prepared, container, name, *arguments):
        result = self.original_update(acquisition, prepared, container, name, *arguments)
        if (acquisition is self.acquisition and name == "posix_spawn_file_actions_adddup2"
                and arguments[1] == len(prepared.duplicates) - 1 and not self.installed):
            self.prepared = prepared
            native, c = prepared.native, prepared.native.abi.c
            self.function = native.library["posix_spawn_file_actions_addopen"]
            mode_t = c.c_uint if native.abi.family == "linux-glibc" else c.c_ushort
            self.function.argtypes = [c.c_void_p, c.c_int, c.c_void_p, c.c_int, mode_t]
            self.function.restype = c.c_int
            self.path_buffer = c.create_string_buffer(os.fsencode(self.path))
            acquisition._check()
            try:
                result = acquisition._invoke("fixture_fifo_addopen", self.function,
                                              c.byref(container.storage), 8, self.path_buffer,
                                              os.O_RDONLY, 0, roots=(self, prepared, container))
                if type(result) is not int or result != 0:
                    raise AssertionError("test-only public FIFO action was not admitted")
                if native.abi.family == "darwin":
                    self.close_function = native.library["posix_spawn_file_actions_addclose"]
                    self.close_function.argtypes = [c.c_void_p, c.c_int]
                    self.close_function.restype = c.c_int
                    result = acquisition._invoke("fixture_fifo_addclose", self.close_function,
                                                  c.byref(container.storage), 8,
                                                  roots=(self, prepared, container))
                    if type(result) is not int or result != 0:
                        raise AssertionError("test-only public FIFO closing action was not admitted")
                self.installed = True
            except BaseException as error:
                acquisition._record_error(error)
                container.state = "UNKNOWN"
                acquisition._remember("fixture_fifo_addopen", error)
                raise
        return result


def _native_sigaction(native, new=None):
    action = native.abi.sigaction()
    result = native.call("sigaction", native.abi.constants["SIGCHLD"],
                         None if new is None else ctypes.byref(new), ctypes.byref(action))
    if type(result) is not int or result != 0:
        raise AssertionError("native fixture signal policy operation failed")
    return action


def _signal_signature(native, action):
    # Public signal membership, not the unused part of libc's sigset storage.
    # The admitted LP64 layouts have 64 meaningful Linux bits in the first
    # unsigned-long word and 31 Darwin bits in its unsigned-int mask.
    mask = action.mask[0] if native.abi.family == "linux-glibc" else action.mask
    members = tuple(bool(mask & (1 << (number - 1))) for number in range(1, native.abi.constants["NSIG"]))
    fields = action.handler, action.flags, members
    if native.abi.family == "linux-glibc":
        return (*fields, action.restorer)
    return fields


class NativeProcessLifecycleTests(unittest.TestCase):
    def test_native_fifo_open_delay_keeps_foreground_cutoff_runnable(self):
        """A real pre-exec libc stall; an independent process releases the FIFO.

        Even a GIL-holding mutant is released by that process, not a Python
        timer/task which the mutant itself could prevent from running.  No
        sleep is inserted before posix_spawn.  All tasks/children are genuinely
        joined/waited using the original ten-second fixture cleanup endpoint.
        """
        controller_code = (
            "import errno,os,stat,sys,time\n"
            "path,dev,ino=sys.argv[1:4]; dev=int(dev); ino=int(ino)\n"
            "os.write(1,b'r')\n"
            "if os.read(0,1)!=b'x': sys.exit(91)\n"
            "start=time.monotonic(); release=start+2.0; stop=start+5.0\n"
            "while time.monotonic()<release: time.sleep(max(0.0,min(0.01,release-time.monotonic())))\n"
            "descriptor=None\n"
            "while time.monotonic()<stop:\n"
            " try:\n"
            "  descriptor=os.open(path,os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC|os.O_NOFOLLOW); break\n"
            " except OSError as error:\n"
            "  if error.errno!=errno.ENXIO: raise\n"
            "  time.sleep(0.01)\n"
            "if descriptor is None: sys.exit(92)\n"
            "try:\n"
            " info=os.fstat(descriptor)\n"
            " if not stat.S_ISFIFO(info.st_mode) or (info.st_dev,info.st_ino)!=(dev,ino): sys.exit(93)\n"
            "finally: os.close(descriptor)\n"
            "os.write(1,b'released')\n")
        fixture = _NativeFixture()
        try:
            scratch = fixture.private_scratch()
            release_reader, release_writer = fixture.io.pipe()
            output_reader, output_writer = fixture.io.pipe()
            controller_spec = fixture.spec(controller_code,
                                           (release_reader, output_writer, fixture.io.open_null(writable=True)),
                                           (str(scratch.fifo), str(scratch.fifo_identity[0]),
                                            str(scratch.fifo_identity[1])))
            controller = fixture.create(controller_spec)
            output_writer.close()
            self.assertEqual(fixture.read(output_reader, exact=1), b"r")
            target = fixture.acquisition(grant=False)
            sources = fixture.nulls()
            spec = fixture.spec("import os; os._exit(0)", sources)
            gate = _FifoAction(target, scratch.fifo)
            fixture.controls.append(gate)
            original_call = m._Native.call

            def invoke(native, name, *arguments):
                if native is target._native and name == "posix_spawn":
                    if not gate.installed or gate.prepared is not target._prepared:
                        raise AssertionError("native delay action is not rooted by its genuine acquisition")
                    gate.entered.set()
                    try:
                        return original_call(native, name, *arguments)
                    finally:
                        gate.returned.set()
                return original_call(native, name, *arguments)

            cutoff = time.monotonic() + 0.6

            def launch_check():
                fixture.check()
                if time.monotonic() >= cutoff:
                    raise AssertionError("native fixture original launch cutoff expired")

            self.assertEqual(os.write(release_writer.fileno(), b"x"), 1)
            release_writer.close()
            with patch.object(m, "_update", gate.update), patch.object(m._Native, "call", invoke):
                task = fixture.start(spec, acquisition=target, check=launch_check)
                self.assertTrue(gate.entered.wait(max(0.0, cutoff - time.monotonic())))
                self.assertLess(time.monotonic(), cutoff, "foreground did not run during the actual native call")
                self.assertFalse(gate.returned.is_set())
                prepared = target._prepared
                while time.monotonic() < cutoff:
                    time.sleep(0.005)  # Foreground deadline handling, AFTER actual call entry.
                target.close_launch()
                self.assertFalse(gate.returned.is_set(), "FIFO did not delay the actual public spawn call")
                self.assertFalse(target.settled)
                self.assertFalse(task.joined)
                self.assertIsNone(target.child)
                self.assertIs(target._prepared, prepared)
                self.assertEqual(prepared.actions.state, "INITIALIZED")
                self.assertTrue(all(lease.state == "OPEN" for lease in prepared.duplicates))
                self.assertTrue(all(target in source._borrowers for source in sources))
                self.assertEqual(target._calls[-1].name, "native_return")
                self.assertEqual(target._calls[-1].state, "IN_FLIGHT")
                with self.assertRaises(m.NativeProcessError):
                    target.grant(threading.current_thread(), lambda: None)
                task.join()  # Original endpoint; controller opens only its exact FIFO.
                self.assertIsNone(task.error)
                self.assertTrue(task.joined)
                self.assertIs(task.result, target.child)
                self.assertTrue(gate.returned.is_set())
                self.assertTrue(target.launch_retired)
                self.assertEqual(task.grants, 1)
                with self.assertRaises(m.NativeProcessError):
                    m.create(target, spec)
            self.assertEqual(fixture.read(output_reader), b"released")
            self.assertEqual(fixture.wait(controller).status_code, 0)
            self.assertEqual(fixture.wait(target.child).status_code, 0)
            self.assertTrue(all(lease.state == "CLOSED" for lease in prepared.duplicates))
        finally:
            fixture.finish()
        self.assertEqual(scratch.state, "REMOVED")

    def test_native_sigchld_disposal_policies_reject_without_attempt(self):
        for policy in ("ignore", "no_child_wait"):
            with self.subTest(policy=policy):
                fixture = _NativeFixture()
                native = fixture.io._runtime()
                saved = _native_sigaction(native)
                try:
                    sources = fixture.nulls()
                    acquisition = fixture.acquisition()
                    candidate = native.abi.sigaction.from_buffer_copy(bytes(saved))
                    if policy == "ignore":
                        candidate.handler = native.abi.constants["SIG_IGN"]
                    else:
                        candidate.flags |= native.abi.constants["SA_NOCLDWAIT"]
                    _native_sigaction(native, candidate)
                    before = _signal_signature(native, _native_sigaction(native))
                    with self.assertRaises(m.NativeProcessError):
                        m.assert_child_waitability()
                    with self.assertRaises(m.NativeProcessError):
                        m.create(acquisition, fixture.spec("pass", sources))
                    self.assertFalse(acquisition.attempted)
                    self.assertIsNone(acquisition.child)
                    self.assertEqual(acquisition.leases, ())
                    self.assertFalse(acquisition.cleanup_unknown)
                    self.assertEqual(_signal_signature(native, _native_sigaction(native)), before)
                finally:
                    try:
                        _native_sigaction(native, saved)
                    finally:
                        fixture.finish()

    def test_native_nonreaping_caller_policy_and_independent_exact_owners(self):
        fixture = _NativeFixture()
        native = fixture.io._runtime()
        saved_action = _native_sigaction(native)
        saved_handler = signal.getsignal(signal.SIGCHLD)
        seen = []

        def handler(signum, _frame):
            seen.append(signum)  # Deliberately does NOT call wait or change policy.

        try:
            signal.signal(signal.SIGCHLD, handler)
            before = _signal_signature(native, _native_sigaction(native))
            acquisitions = [fixture.acquisition(grant=False), fixture.acquisition(grant=False)]
            published = [threading.Event(), threading.Event()]
            writers, specs = [], []
            for status in (0, 7):
                reader, writer = fixture.io.pipe()
                writers.append(writer)
                code = "import os,sys; sys.exit(int(sys.argv[1]) if os.read(0,1)==b'x' else 98)"
                specs.append(fixture.spec(code, (reader, fixture.io.open_null(writable=True),
                                                  fixture.io.open_null(writable=True)), (str(status),)))
            barrier = threading.Barrier(2)
            original_call = m._Native.call

            def invoke(owner_native, name, *arguments):
                if name == "posix_spawn" and any(owner_native is acquisition._native for acquisition in acquisitions):
                    barrier.wait(max(0.0, fixture.expires - time.monotonic()))
                return original_call(owner_native, name, *arguments)

            def create_and_wait(acquisition, spec):
                index = acquisitions.index(acquisition)
                child = m.create(acquisition, spec)
                published[index].set()
                return child, fixture.wait(child), threading.current_thread()

            with patch.object(m._Native, "call", invoke):
                tasks = [fixture.start(spec, acquisition=acquisition, function=create_and_wait)
                         for acquisition, spec in zip(acquisitions, specs)]
                for event in published:
                    self.assertTrue(event.wait(max(0.0, fixture.expires - time.monotonic())))
                self.assertNotEqual(acquisitions[0].child.pid, acquisitions[1].child.pid)
                for writer in writers:
                    self.assertEqual(os.write(writer.fileno(), b"x"), 1)
                    writer.close()
                for task in tasks:
                    task.join()
                    self.assertIsNone(task.error)
                    child, receipt, actual_owner = task.result
                    self.assertIs(child, task.acquisition.child)
                    self.assertIs(receipt, child.receipt)
                    self.assertIs(child._wait_owner, task.thread)
                    self.assertIs(actual_owner, task.thread)
                    self.assertEqual(receipt.status_kind, "exit")
                self.assertEqual([task.result[1].status_code for task in tasks], [0, 7])
            self.assertIsNot(acquisitions[0]._native, acquisitions[1]._native)
            self.assertIsNot(acquisitions[0]._native.functions["fcntl"], acquisitions[1]._native.functions["fcntl"])
            after = _signal_signature(native, _native_sigaction(native))
            self.assertEqual(after[0], before[0])  # Handler.
            self.assertEqual(after[1], before[1])  # All flags.
            self.assertEqual(after[2], before[2])  # Every valid signal bit.
            if native.abi.family == "linux-glibc":
                self.assertEqual(after[3], before[3])  # Exact restorer.
            self.assertIs(signal.getsignal(signal.SIGCHLD), handler)
            self.assertTrue(all(signum == signal.SIGCHLD for signum in seen))
        finally:
            try:
                fixture.finish()
            finally:
                signal.signal(signal.SIGCHLD, saved_handler)
                _native_sigaction(native, saved_action)

    def test_native_consumed_wait_result_loss_never_retries_numeric_custody(self):
        """Negative proof: the observer's wait is genuine, the product receipt is NOT.

        The original child is actually consumed by its one exact owner before
        simulated publication loss.  UNKNOWN stays retained; there is no second
        wait, PID probe/signal, invented receipt or claim of product finality.
        """
        fixture = _NativeFixture()
        expected_unknown = False
        try:
            child = fixture.create(fixture.spec("import os; os._exit(7)", fixture.nulls()))
            genuine_wait = os.waitpid
            observed, requests = [], []
            lost = MemoryError("deliberate post-consumption publication loss")

            def consume_then_lose(pid, options):
                self.assertTrue(child.numeric_retired)
                self.assertEqual(child.wait_state, "WAIT_IN_FLIGHT")
                self.assertEqual((pid, options), (child.pid, os.WNOHANG))
                requests.append((pid, options))
                result = genuine_wait(pid, options)
                if result[0] != 0:
                    observed.append(result)  # Test observer ONLY; never given to Child as a receipt.
                    raise lost
                return result

            with patch.object(m.os, "waitpid", consume_then_lose), \
                    patch.object(m.os, "kill", side_effect=_World.denied), \
                    patch.object(m.os, "killpg", side_effect=_World.denied):
                with self.assertRaises(MemoryError) as caught:
                    fixture.wait(child)
                self.assertIs(caught.exception, lost)
                self.assertEqual(observed, [(child.pid, 7 << 8)])
                self.assertEqual(child.wait_state, "UNKNOWN")
                self.assertIsNone(child.receipt)
                calls = len(requests)
                with self.assertRaises(m.NativeProcessError):
                    child.poll_wait()
                self.assertEqual(len(requests), calls)
                expected_unknown = True
        finally:
            if expected_unknown:
                with patch.object(m.os, "waitpid", side_effect=_World.denied), \
                        patch.object(m.os, "kill", side_effect=_World.denied), \
                        patch.object(m.os, "killpg", side_effect=_World.denied):
                    with self.assertRaises(BaseExceptionGroup):
                        fixture.finish()
                self.assertIn(fixture, _RETAINED_NATIVE_FIXTURES)
            else:
                fixture.finish()

    def test_native_error_startup_is_unknown_not_a_wait_receipt(self):
        """A genuine native startup error does not prove an internal wait/finality."""
        fixture = _NativeFixture()
        expected_unknown = False
        try:
            scratch = fixture.private_scratch(fifo=False)
            path = str(scratch.directory / "deliberately-absent-executable")
            acquisition = fixture.acquisition()
            spec = m.SpawnSpec(path, (path,), (("LC_ALL", "C"),), fixture.nulls())
            with patch.object(m.os, "waitpid", side_effect=_World.denied), \
                    patch.object(m.os, "kill", side_effect=_World.denied), \
                    patch.object(m.os, "killpg", side_effect=_World.denied):
                with self.assertRaises(m.NativeProcessError):
                    m.create(acquisition, spec)
                native_returns = [call for call in acquisition._calls if call.name == "native_return"]
                self.assertEqual(len(native_returns), 1)
                self.assertEqual(native_returns[0].state, "RETURNED")
                self.assertEqual(native_returns[0].value, errno.ENOENT)
                self.assertTrue(acquisition.attempted)
                self.assertTrue(acquisition.cleanup_unknown)
                self.assertEqual(acquisition.state, "UNKNOWN")
                self.assertIsNone(acquisition.child)
                self.assertTrue(acquisition.launch_retired)
                self.assertTrue(all(lease.state == "CLOSED" for lease in acquisition.leases))
                expected_unknown = True
        finally:
            if expected_unknown:
                with patch.object(m.os, "waitpid", side_effect=_World.denied):
                    with self.assertRaises(BaseExceptionGroup):
                        fixture.finish()
                self.assertIn(fixture, _RETAINED_NATIVE_FIXTURES)
                self.assertEqual(scratch.state, "OWNED")
                self.assertEqual(scratch.identity(scratch.directory), scratch.directory_identity)
            else:
                fixture.finish()
