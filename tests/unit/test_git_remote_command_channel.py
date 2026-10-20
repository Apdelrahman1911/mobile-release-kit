"""Private map DATA/ordering tests: no actual FD, child, ABI, token or network.

Run against the exact two Root hook projections, not an unpatched parent.  The
small fake descriptor table models returns of the existing acquisition; it does
not qualify installed sockets, inheritance, EOF or C/A/W containment.
"""
from __future__ import annotations

import os
import stat
import sys
import threading
import types
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from mobile_release import _command_process as command
from mobile_release import _git_remote_command_channel as channel
from mobile_release import _native_process as native


NONCE = b"n" * 16
STAMP = (501, 4, 900)
_SOURCE_STAT = os.stat


class _Returns:
    """Finite fake syscall table. Import/construct never opens a real handle."""

    def __init__(self):
        self.rows, self.calls, self.next = {}, [], 100
        self.fail_close = self.fail_inherit = self.fail_duplicate = None
        self.abi = types.SimpleNamespace(family="linux-glibc", constants={
            "F_DUPFD_CLOEXEC": 1030, "F_GETFL": 3, "F_GETFD": 1, "FD_CLOEXEC": 1,
        })
        self.last_errno = 0

    def installed(self, test):
        stack = test.enterContext(ExitStack())
        stack.enter_context(patch.object(native, "_Native", _Returns))
        for name, function in (("fstat", self.stat), ("stat", self.null_stat),
                               ("set_inheritable", self.inherit)):
            stack.enter_context(patch.object(native.os, name, function))
        for name in ("pipe", "open", "close", "dup", "dup2", "fork", "execve",
                     "posix_spawn", "kill", "killpg", "waitpid"):
            stack.enter_context(patch.object(native.os, name,
                side_effect=AssertionError("unexpected real effect in DATA test")))
        stack.enter_context(patch.object(threading.Thread, "start",
            side_effect=AssertionError("unexpected worker in DATA test")))
        stack.enter_context(patch.object(native, "create",
            side_effect=AssertionError("unexpected actual child in DATA test")))
        return self

    def stat(self, fd):
        row = self.rows[fd]
        return types.SimpleNamespace(st_mode=row["mode"], st_uid=row["stamp"][0],
            st_dev=row["stamp"][1], st_ino=row["stamp"][2], st_rdev=7)

    def null_stat(self, path, **options):
        if os.fspath(path) == "/dev/null":
            return types.SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=7)
        # Path.resolve/import/traceback only inspect ordinary source files.
        # Their metadata is not a descriptor or native admission fixture.
        return _SOURCE_STAT(path, **options)

    def inherit(self, fd, value):
        self.calls.append(("inherit", fd, value))
        if self.fail_inherit is not None:
            raise self.fail_inherit
        self.rows[fd]["flags"] = 0 if value else 1

    def call(self, name, *args):
        self.calls.append((name, *args))
        if name == "close":
            if self.fail_close is not None:
                raise self.fail_close
            del self.rows[args[0]]
            return 0
        assert name == "fcntl"
        fd, operation, value = args
        if operation == 3:
            return self.rows[fd]["access"]
        if operation == 1:
            return self.rows[fd]["flags"]
        assert operation == 1030
        if self.fail_duplicate is not None:
            raise self.fail_duplicate
        self.next = max(self.next + 1, value)
        self.rows[self.next] = dict(self.rows[fd], flags=1)
        return self.next

    def acquisition(self):
        result = native.Acquisition()
        result.grant(threading.current_thread(), lambda: None)
        result._native, result._native_ready = self, True
        return result

    def lease(self, owner, fd, kind, access, binding=None):
        mode = {"pipe": stat.S_IFIFO, "null": stat.S_IFCHR,
                "git_remote_socket": stat.S_IFSOCK, "account_hold": stat.S_IFDIR}[kind]
        stamp = (501, 4, fd + 1000) if binding is None else binding._identity
        self.rows[fd] = dict(mode=mode, stamp=stamp, access=access, flags=1)
        lease = owner._new_lease()
        lease._git_remote_binding = binding
        lease._publish(fd, self, access, kind)
        lease._identity, lease._validated = stamp[1:], True
        return lease


class GitRemoteCommandChannelTests(unittest.TestCase):
    def setUp(self):
        self.world = _Returns().installed(self)

    def bootstrap(self, version=2):
        return native._issue_command_bootstrap(role="C", command_nonce=NONCE,
            parent_pid=1001, parent_session=1002, parent_group=1003,
            fd_map_version=version, git_remote_identity=STAMP if version == 2 else None)

    def sources(self, owner, binding=None):
        kinds = ("null", "null", "null", "pipe", "pipe", "null", "pipe", "pipe")
        modes = (os.O_RDONLY, os.O_WRONLY, os.O_WRONLY, os.O_RDONLY,
                 os.O_WRONLY, os.O_RDONLY, os.O_WRONLY, os.O_WRONLY)
        result = tuple(self.world.lease(owner, 20 + i, kind, modes[i])
                       for i, kind in enumerate(kinds))
        if binding is not None:
            result += (self.world.lease(owner, 8, "git_remote_socket", os.O_RDWR, binding),)
        return result

    def permit(self, owner, sources, binding=None):
        return native._issue_command_map(owner, role="C", command_nonce=NONCE,
            executable="/fixed/python", argv=("/fixed/python",), env=(),
            fd_sources=sources, git_remote_binding=binding)

    def spec(self, owner, binding=None):
        sources = self.sources(owner, binding)
        permit = self.permit(owner, sources, binding)
        return native.SpawnSpec("/fixed/python", ("/fixed/python",), (), sources, permit)

    def original(self):
        """Fake future input type only; never a production entry issuer."""
        fixture = types.ModuleType("mobile_release._desktop_git_remote_control")
        class GitRemoteInput:
            def _owner(self):
                self.owner_calls += 1
                self.on_owner()
            def require_operation(self):
                return types.SimpleNamespace(command_arguments=self.arguments)
        fixture.GitRemoteInput = GitRemoteInput
        self.enterContext(patch.dict(sys.modules, {fixture.__name__: fixture}))
        source = GitRemoteInput()
        source.owner_calls, source.on_owner = 0, lambda: None
        source.arguments = Mock(return_value=None)
        guard = types.SimpleNamespace(check=Mock(return_value=None),
            _saved_command_input=lambda: source)
        source.guard = guard
        owner = self.world.acquisition()
        binding = channel.SocketBinding(source, NONCE, STAMP, _key=channel._KEY)
        lease = self.world.lease(owner, 8, "git_remote_socket", os.O_RDWR, binding)
        original = channel.OriginalChannel(source, lease, guard, _key=channel._KEY)
        source.credential_channel = original
        context = types.SimpleNamespace(guard=guard, role="O", pid=os.getpid(),
            owner=threading.current_thread(), nonce=NONCE, check=Mock(return_value=None))
        return original, source, context

    def test_old_map_shape_and_null_signing_slot_are_unchanged(self):
        owner = self.world.acquisition()
        spec = self.spec(owner)
        self.assertEqual(spec.command_map._map_version, 1)
        spec.command_map._consume(owner, spec)
        self.assertEqual(len(spec.fd_sources), 8)
        self.assertIsNone(self.bootstrap(1).git_remote_binding)
        self.assertEqual(self.world.calls, [])

    def test_ninth_descriptor_requires_actual_original_permit(self):
        owner = self.world.acquisition()
        binding = self.bootstrap().git_remote_binding
        sources = self.sources(owner, binding)
        with self.assertRaises(native.NativeProcessError):
            native.SpawnSpec("/fixed/python", ("/fixed/python",), (), sources)
        with self.assertRaises(native.NativeProcessError):
            self.permit(owner, sources)
        self.assertEqual(self.world.calls, [])

    def test_equal_map_data_or_foreign_lease_does_not_replace_original(self):
        owner = self.world.acquisition()
        binding = self.bootstrap().git_remote_binding
        spec = self.spec(owner, binding)
        foreign = self.world.lease(owner, 9, "git_remote_socket", os.O_RDWR, binding)
        altered = native.SpawnSpec(spec.executable, spec.argv, spec.env,
                                  (*spec.fd_sources[:8], foreign), spec.command_map)
        with self.assertRaises(native.NativeProcessError):
            spec.command_map._consume(owner, altered)
        with self.assertRaises(native.NativeProcessError):
            self.permit(owner, spec.fd_sources, types.SimpleNamespace(
                _nonce=NONCE, _identity=STAMP, _origin=binding._origin))
        self.assertEqual(self.world.calls, [])

    def test_wrong_acquisition_or_nonce_cannot_consume_map(self):
        owner = self.world.acquisition()
        spec = self.spec(owner, self.bootstrap().git_remote_binding)
        with self.assertRaises(native.NativeProcessError):
            spec.command_map._consume(self.world.acquisition(), spec)
        wrong = channel.SocketBinding(object(), b"x" * 16, STAMP, _key=channel._KEY)
        with self.assertRaises(native.NativeProcessError):
            self.permit(owner, spec.fd_sources, wrong)
        self.assertEqual(self.world.calls, [])

    def test_equal_socket_stamp_does_not_replace_retained_binding(self):
        owner = self.world.acquisition()
        original = self.bootstrap().git_remote_binding
        other = self.bootstrap().git_remote_binding
        spec = self.spec(owner, original)
        spec.fd_sources[8]._git_remote_binding = other
        with self.assertRaises(native.NativeProcessError):
            spec.command_map._consume(owner, spec)
        self.assertTrue(spec.command_map._used)
        self.assertEqual(self.world.calls, [])

    def test_remote_map_cannot_mix_signing_account_or_upgrade_v1(self):
        with self.assertRaises(native.NativeProcessError):
            native._issue_command_bootstrap(role="C", command_nonce=NONCE,
                parent_pid=1, parent_session=2, parent_group=3, fd_map_version=2,
                git_remote_identity=STAMP, account_binding=(os.getuid(), 4, 5))
        with self.assertRaises(native.NativeProcessError):
            native._issue_command_bootstrap(role="C", command_nonce=NONCE,
                parent_pid=1, parent_session=2, parent_group=3, fd_map_version=1,
                git_remote_identity=STAMP)
        owner = self.world.acquisition()
        spec = self.spec(owner, self.bootstrap().git_remote_binding)
        spec.fd_sources[5]._kind = "account_hold"
        with self.assertRaises(native.NativeProcessError):
            spec.command_map._consume(owner, spec)
        self.assertEqual(self.world.calls, [])

    def test_original_map_adopts_socket_into_existing_close_roster_once(self):
        owner, bootstrap = self.world.acquisition(), self.bootstrap()
        self.world.rows[8] = dict(mode=stat.S_IFSOCK, stamp=STAMP,
                                  access=os.O_RDWR, flags=0)
        lease = channel.adopt(bootstrap, owner)
        self.assertIs(owner.leases[0], lease)
        self.assertEqual(lease.fileno(), 8)
        with self.assertRaises(native.NativeProcessError):
            channel.adopt(bootstrap, self.world.acquisition())
        lease.close()
        lease.close()  # Already-known closed original is idempotent.
        self.assertEqual([call for call in self.world.calls if call[0] == "close"], [("close", 8)])

    def test_wrong_descriptor_identity_refuses_but_retains_owned_route(self):
        owner, bootstrap = self.world.acquisition(), self.bootstrap()
        self.world.rows[8] = dict(mode=stat.S_IFSOCK, stamp=(501, 4, 901),
                                  access=os.O_RDWR, flags=0)
        with self.assertRaises(native.NativeProcessError):
            channel.adopt(bootstrap, owner)
        self.assertEqual(owner.leases[0].state, "OPEN")
        self.assertTrue(bootstrap.git_remote_binding._adopted)
        self.assertFalse(any(call[0] == "inherit" for call in self.world.calls))
        owner.leases[0].close()

    def test_inheritance_interruption_is_absorbing_and_same_exception(self):
        owner, bootstrap = self.world.acquisition(), self.bootstrap()
        self.world.rows[8] = dict(mode=stat.S_IFSOCK, stamp=STAMP,
                                  access=os.O_RDWR, flags=0)
        interruption = KeyboardInterrupt()
        self.world.fail_inherit = interruption
        with self.assertRaises(KeyboardInterrupt) as caught:
            channel.adopt(bootstrap, owner)
        self.assertIs(caught.exception, interruption)
        self.assertTrue(owner.cleanup_unknown)
        with self.assertRaises(native.NativeProcessError):
            channel.adopt(bootstrap, self.world.acquisition())
        self.assertEqual(len([x for x in self.world.calls if x[0] == "inherit"]), 1)

    def test_unknown_close_retires_fd_before_call_and_cannot_retry(self):
        owner = self.world.acquisition()
        lease = self.sources(owner, self.bootstrap().git_remote_binding)[8]
        self.world.fail_close = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            lease.close()
        self.assertEqual(lease.state, "UNKNOWN")
        self.assertIsNone(lease._fd)
        self.assertTrue(owner.cleanup_unknown)
        with self.assertRaises(native.NativeProcessError):
            lease.close()
        self.assertEqual(len([x for x in self.world.calls if x[0] == "close"]), 1)

    def test_v2_duplication_floor_and_destinations_do_not_change_v1(self):
        updates = []
        class Prepared:
            def __init__(self, runtime):
                self.native, self.duplicates = runtime, []
                self.attributes, self.actions = None, object()
            def buffers(self, *_):
                pass
        with patch.object(native, "_Prepared", Prepared), \
             patch.object(native, "_waitability"), patch.object(native, "_initialize"), \
             patch.object(native, "_update", side_effect=lambda *a: updates.append(a[3:])):
            for version in (1, 2):
                owner = self.world.acquisition()
                binding = None if version == 1 else self.bootstrap().git_remote_binding
                spec = self.spec(owner, binding)
                before = len(self.world.calls)
                prepared = native._prepare(owner, spec)
                floor = 8 if version == 1 else 9
                duplicates = [call for call in self.world.calls[before:]
                              if call[0] == "fcntl" and call[2] == 1030]
                self.assertEqual(len(duplicates), floor)
                self.assertEqual({call[3] for call in duplicates}, {floor})
                self.assertEqual(updates[-1], ("posix_spawn_file_actions_addclosefrom_np", floor))
                if version == 2:
                    self.assertIs(prepared.duplicates[8]._git_remote_binding, binding)

    def test_exact_private_loader_recipe_and_hello_follow_retained_map(self):
        for version in (1, 2):
            owner = self.world.acquisition()
            binding = None if version == 1 else self.bootstrap().git_remote_binding
            ctx = types.SimpleNamespace(role="O", nonce=NONCE, pid=os.getpid(), run=100,
                hard=200, child_acquisition=owner, check=lambda: None, git_remote_binding=binding)
            sources = self.sources(owner, binding)
            spec = command._command_spec(ctx, "C", sources)
            self.assertEqual(spec.command_map._map_version, version)
            self.assertEqual(spec.argv[-1] if version == 1 else spec.argv[-2], str(version))
            if version == 2:
                self.assertEqual(spec.argv[-1], "501,4,900")
            hello = command._scalar_fields(command._hello(ctx), NONCE,
                {"role", "pid", "parent", "session", "group", "map"})
            self.assertEqual(hello["map"], version)
        self.assertEqual(self.world.calls, [])

    def test_hello_cannot_upgrade_or_downgrade_original_map(self):
        for version in (1, 2):
            owner = self.world.acquisition()
            child = native.Child(owner, _key=native._CHILD_KEY)
            child._pid, child._wait_state = 1001, "OWNED"
            owner._child = child
            binding = None if version == 1 else self.bootstrap().git_remote_binding
            ctx = types.SimpleNamespace(nonce=NONCE, pid=1000,
                child_acquisition=owner, git_remote_binding=binding)
            def payload(value):
                return command._scalar(NONCE, role="C", pid=1001, parent=1000,
                    session=1002, group=1003, map=value)
            with patch.object(command.os, "getsid", return_value=1002), \
                 patch.object(command.os, "getpgid", return_value=1003):
                command._admit_hello(ctx, child, payload(version), "C", 1002, 1003)
                with self.assertRaises(command.ProcessError):
                    command._admit_hello(ctx, child, payload(3 - version), "C", 1002, 1003)
        self.assertEqual(self.world.calls, [])

    def test_binding_numbers_are_canonical_comparisons_not_socket_authority(self):
        self.assertEqual(channel.parsed_binding("0,0,0"), (0, 0, 0))
        for text in ("501,04,900", "501,4,-1", "501,4,900,0", "501,4,900\n",
                     "501,4," + "9" * 21, "True,4,900"):
            with self.subTest(text=text), self.assertRaises(native.NativeProcessError):
                channel.parsed_binding(text)
        with self.assertRaises(native.NativeProcessError):
            channel.adopt(self.bootstrap(1), self.world.acquisition())
        self.assertEqual(self.world.calls, [])

    def test_missing_original_input_owner_is_unavailable_and_consumes_attempt(self):
        owner, source, guard = self.world.acquisition(), object(), object()
        binding = channel.SocketBinding(source, NONCE, STAMP, _key=channel._KEY)
        lease = self.world.lease(owner, 8, "git_remote_socket", os.O_RDWR, binding)
        original = channel.OriginalChannel(source, lease, guard, _key=channel._KEY)
        with self.assertRaises(native.NativeProcessError):
            original.admit_command(guard, ("/fixed/git", "fetch"))
        self.assertTrue(original._entered)
        self.assertFalse(original._admitted)
        with self.assertRaises(native.NativeProcessError):
            original.admit_command(guard, ("/fixed/git", "fetch"))
        context = types.SimpleNamespace(guard=guard, role="O", pid=os.getpid(),
            owner=threading.current_thread(), nonce=NONCE)
        with self.assertRaises(native.NativeProcessError):
            original.bind_context(context)
        self.assertEqual(self.world.calls, [])

    def test_original_attempt_is_consumed_before_owner_callback(self):
        original, source, _ = self.original()
        def reentry():
            with self.assertRaises(native.NativeProcessError):
                original.admit_command(source.guard, ("/fixed/git", "fetch"))
        source.on_owner = reentry
        original.admit_command(source.guard, ("/fixed/git", "fetch"))
        self.assertTrue(original._admitted)
        self.assertEqual(source.owner_calls, 1)
        source.arguments.assert_called_once()

    def test_export_once_keeps_original_endpoint_until_its_owner_closes(self):
        original, source, context = self.original()
        original.admit_command(source.guard, ("/fixed/git", "fetch"))
        original.bind_context(context)
        outer = self.world.acquisition()
        duplicate = original.export(context, outer)
        self.assertIs(outer.leases[0], duplicate)
        self.assertIs(duplicate._git_remote_binding, context.git_remote_binding)
        self.assertEqual(original.lease.state, "OPEN")
        self.assertFalse(original.lease._borrowers)
        with self.assertRaises(native.NativeProcessError):
            original.export(context, self.world.acquisition())
        duplicate.close()
        self.assertEqual(original.lease.state, "OPEN")
        original.lease.close()
        self.assertEqual(len([x for x in self.world.calls if x[0] == "close"]), 2)

    def test_late_revoke_before_duplicate_cannot_retry_or_dispose_original(self):
        original, source, context = self.original()
        original.admit_command(source.guard, ("/fixed/git", "fetch"))
        original.bind_context(context)
        denied = RuntimeError("fixture revoked")
        context.check.side_effect = denied
        outer = self.world.acquisition()
        before = len(self.world.calls)
        with self.assertRaises(RuntimeError) as caught:
            original.export(context, outer)
        self.assertIs(caught.exception, denied)
        self.assertEqual(self.world.calls[before:], [])
        self.assertEqual(original.lease.state, "OPEN")
        self.assertEqual(outer.leases, ())
        context.check.side_effect = None
        with self.assertRaises(native.NativeProcessError):
            original.export(context, outer)

    def test_unknown_duplicate_preserves_borrow_and_original_interruption(self):
        original, source, context = self.original()
        original.admit_command(source.guard, ("/fixed/git", "fetch"))
        original.bind_context(context)
        interrupted = KeyboardInterrupt()
        self.world.fail_duplicate = interrupted
        outer = self.world.acquisition()
        with self.assertRaises(KeyboardInterrupt) as caught:
            original.export(context, outer)
        self.assertIs(caught.exception, interrupted)
        self.assertTrue(outer.cleanup_unknown)
        self.assertEqual(outer.leases[0].state, "UNKNOWN")
        self.assertIn(outer, original.lease._borrowers)
        with self.assertRaises(native.NativeProcessError):
            original.lease.close()
        with self.assertRaises(native.NativeProcessError):
            original.export(context, outer)
        self.assertEqual(len([x for x in self.world.calls if x[0] == "fcntl" and x[2] == 1030]), 1)
        self.assertFalse(any(x[0] == "close" for x in self.world.calls))

    def test_revoked_after_returned_duplicate_keeps_exact_owned_close_route(self):
        original, source, context = self.original()
        original.admit_command(source.guard, ("/fixed/git", "fetch"))
        original.bind_context(context)
        denied = RuntimeError("fixture revoked")
        context.check.side_effect = [None, denied]
        outer = self.world.acquisition()
        with self.assertRaises(RuntimeError) as caught:
            original.export(context, outer)
        self.assertIs(caught.exception, denied)
        self.assertTrue(outer.launch_retired)
        self.assertFalse(outer.cleanup_unknown)
        self.assertEqual(outer.leases[0].state, "OPEN")
        self.assertFalse(original.lease._borrowers)
        outer.leases[0].close()
        original.lease.close()
        self.assertEqual(len([x for x in self.world.calls if x[0] == "close"]), 2)

    def test_ordinary_command_entry_cannot_accept_an_extra_endpoint(self):
        with patch.object(command, "_run_command", return_value="old-result") as run:
            result = command.run_command(("/fixed/git",), environ={}, cwd=None,
                timeout=1, capture=True, output_limit=1, cancellation=None,
                on_start=None, cleanup=False, execution_scope=None, journal_binding=None)
            self.assertEqual(result, "old-result")
            self.assertNotIn("_git_remote_channel", run.call_args.kwargs)
            with self.assertRaises(TypeError):
                command.run_command(("/fixed/git",), _git_remote_channel=object())
        self.assertEqual(self.world.calls, [])


if __name__ == "__main__":
    unittest.main()
