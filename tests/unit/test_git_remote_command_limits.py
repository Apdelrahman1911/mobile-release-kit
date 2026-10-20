"""Inert original-W effect/ordering tests, not resource or native qualification.

All descriptor/syscall returns come from the existing finite channel fixture.
getrlimit/setrlimit and target exec are replaced; no process limit, signal
disposition, descriptor, child, Git command, socket or network is changed.
Run with the exact Root command hook and current native-map source projection.
"""
from __future__ import annotations

import os
import resource
import types
import unittest
from unittest.mock import Mock, patch

from mobile_release import _command_process as command
from mobile_release import _git_remote_command_channel as channel
from mobile_release import _git_remote_command_limits as limits
from mobile_release import _native_process as native
from test_git_remote_command_channel import _Returns, NONCE, STAMP


class _ExecReached(BaseException):
    """An inert return boundary, never an actual exec or settlement receipt."""


class GitRemoteCommandLimitTests(unittest.TestCase):
    def setUp(self):
        self.world = _Returns().installed(self)
        self.enterContext(patch.object(command.time, "monotonic_ns", return_value=1))
        self.enterContext(patch.object(os, "getuid", return_value=STAMP[0]))
        self.enterContext(patch.object(os, "geteuid", return_value=STAMP[0]))
        self.values = {resource.RLIMIT_FSIZE: (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
                       resource.RLIMIT_CORE: (0, resource.RLIM_INFINITY)}
        self.calls = []
        self.after = lambda: None
        self.enterContext(patch.object(resource, "getrlimit", self.get))
        self.enterContext(patch.object(resource, "setrlimit", self.set))
        if hasattr(resource, "prlimit"):
            self.enterContext(patch.object(resource, "prlimit",
                side_effect=AssertionError("unexpected real limit effect")))

    def get(self, which):
        self.calls.append(("get", which))
        result = self.values[which]
        self.after()
        return result

    def set(self, which, value):
        self.calls.append(("set", which, value))
        self.values[which] = value
        self.after()

    def worker(self, role="W", remote=True):
        parent = os.getppid()
        ctx = command._Context(role, NONCE, 100, 100 + command.CLEANUP_NS, parent=parent)
        io, account = ctx.start_io(), ctx.start_io()
        for owner in (io, account):
            owner._native, owner._native_ready = self.world, True
        bootstrap = native._issue_command_bootstrap(role=role if role != "O" else "W",
            command_nonce=NONCE, parent_pid=parent, parent_session=1002, parent_group=1003,
            fd_map_version=2 if remote else 1, git_remote_identity=STAMP if remote else None)
        mapping = {fd: self.world.lease(io, fd, "pipe", os.O_RDONLY if fd == 3 else os.O_WRONLY)
                   for fd in (3, 4, 6, 7)}
        mapping[5] = self.world.lease(account, 5, "null", os.O_RDONLY)
        ctx.git_remote_binding = bootstrap.git_remote_binding
        if remote:
            import stat
            self.world.rows[8] = dict(mode=stat.S_IFSOCK, stamp=STAMP, access=os.O_RDWR, flags=0)
            mapping[8] = channel.adopt(bootstrap, io)
        # The original constructor is exercised with inert map/pipe returns;
        # its newly created acquisitions remain the ones used by the W guard.
        def original_map(context, original, relay, account_owner):
            self.assertIs(context, ctx)
            self.assertIs(original, bootstrap)
            # No real descriptor move: transfer this fixture's fake rows to
            # the SAME constructor acquisitions before they can be used.
            for fd, lease in mapping.items():
                owner = account_owner if fd == 5 else relay
                lease._owner._leases.remove(lease)
                lease._owner = owner
                owner._leases.append(lease)
                owner._native, owner._native_ready = self.world, True
            return mapping
        with patch.object(command, "_bootstrap_map", original_map), \
             patch.object(command, "_Wire", return_value=types.SimpleNamespace(read_data=0)):
            worker = command._Worker(ctx, bootstrap)
        self.world.calls.clear()
        return worker, mapping.get(8)

    def apply(self, worker, endpoint):
        limits.apply_worker_limits(worker, endpoint)

    def test_actual_worker_owns_fixed_lowering_and_readbacks_once(self):
        w, endpoint = self.worker()
        clocks = w.ctx.run, w.ctx.hard, w.ctx.failure_cutoff, w.ctx.cleanup_cutoff
        self.assertFalse(w.git_remote_limits_entered)
        self.apply(w, endpoint)
        self.assertTrue(w.git_remote_limits_entered)
        fsize, core = resource.RLIMIT_FSIZE, resource.RLIMIT_CORE
        self.assertEqual(self.calls, [("get", fsize), ("get", core),
            ("set", core, (0, 0)), ("set", fsize, (limits.FILE_BYTES, limits.FILE_BYTES)),
            ("get", core), ("get", fsize)])
        self.assertEqual([e.operation for e in w.effects], [
            "git_remote_fsize_before", "git_remote_core_before", "git_remote_core_limit",
            "git_remote_fsize_limit", "git_remote_core_after", "git_remote_fsize_after"])
        self.assertTrue(all(e.state == "RETURNED" for e in w.effects))
        self.assertEqual((w.ctx.run, w.ctx.hard, w.ctx.failure_cutoff, w.ctx.cleanup_cutoff), clocks)
        self.assertEqual(endpoint.state, "OPEN")
        self.assertTrue(self.world.rows[8]["flags"] & 1)
        before = list(self.calls)
        with self.assertRaises(command.ProcessError): self.apply(w, endpoint)
        self.assertEqual(self.calls, before)

    def test_old_maps_other_roles_or_equal_endpoint_data_cannot_lower_limits(self):
        cases = [self.worker(remote=False), *(self.worker(role=role) for role in ("O", "C", "A"))]
        w, endpoint = self.worker()
        equal = self.world.lease(w.io, 18, "git_remote_socket", os.O_RDWR, endpoint._git_remote_binding)
        cases.append((w, equal))
        for worker, source in cases:
            with self.subTest(role=worker.ctx.role, remote=source is not None):
                with self.assertRaises((command.ProcessError, native.NativeProcessError)):
                    self.apply(worker, source)
        self.assertEqual(self.calls, [])

    def test_foreign_original_nonce_or_bootstrap_is_not_same_worker(self):
        for field in ("nonce", "bootstrap", "lease_owner", "adopted"):
            w, endpoint = self.worker()
            if field == "nonce": w.ctx.nonce = b"z" * 16
            elif field == "bootstrap":
                endpoint._git_remote_binding._origin = types.SimpleNamespace(
                    role="W", fd_map_version=2, command_nonce=NONCE)
            elif field == "lease_owner": endpoint._owner = w.account
            else: endpoint._git_remote_binding._adopted = False
            with self.subTest(field=field), self.assertRaises((command.ProcessError, native.NativeProcessError)):
                self.apply(w, endpoint)
        self.assertEqual(self.calls, [])

    def test_root_changed_identity_retired_or_unknown_worker_refuses_without_effect(self):
        for field in ("root", "euid", "stopped", "launch_retired", "cleanup_unknown", "exited", "exec_retired"):
            w, endpoint = self.worker()
            with self.subTest(field=field):
                if field == "root":
                    with patch.object(os, "getuid", return_value=0), self.assertRaises(command.ProcessError):
                        self.apply(w, endpoint)
                elif field == "euid":
                    with patch.object(os, "geteuid", return_value=STAMP[0] + 1), self.assertRaises(command.ProcessError):
                        self.apply(w, endpoint)
                else:
                    setattr(w if field == "exec_retired" else w.ctx, field, True)
                    with self.assertRaises(command.ProcessError): self.apply(w, endpoint)
        self.assertEqual(self.calls, [])

    def test_stricter_inherited_limits_are_never_raised(self):
        for value in ((0, 0), (limits.FILE_BYTES - 1, resource.RLIM_INFINITY),
                      (limits.FILE_BYTES - 1, limits.FILE_BYTES - 1)):
            w, endpoint = self.worker()
            self.values[resource.RLIMIT_FSIZE] = value
            self.calls.clear()
            with self.subTest(value=value), self.assertRaises(command.ProcessError): self.apply(w, endpoint)
            self.assertFalse(any(c[0] == "set" for c in self.calls))
            self.assertEqual(self.values[resource.RLIMIT_FSIZE], value)

    def test_equal_or_larger_finite_limits_are_supported_without_any_increase(self):
        for value in ((limits.FILE_BYTES, limits.FILE_BYTES), (limits.FILE_BYTES, limits.FILE_BYTES + 1),
                      (limits.FILE_BYTES + 1, resource.RLIM_INFINITY)):
            w, endpoint = self.worker()
            self.values[resource.RLIMIT_FSIZE] = value
            self.apply(w, endpoint)
            self.assertEqual(self.values[resource.RLIMIT_FSIZE], (limits.FILE_BYTES, limits.FILE_BYTES))

    def test_unsupported_constants_and_malformed_native_pairs_fail_closed(self):
        for name, value in (("RLIMIT_CORE", None), ("RLIMIT_FSIZE", True),
                            ("RLIMIT_CORE", resource.RLIMIT_FSIZE), ("RLIM_INFINITY", 0)):
            w, endpoint = self.worker()
            with self.subTest(name=name), patch.object(resource, name, value), self.assertRaises(command.ProcessError):
                self.apply(w, endpoint)
        self.assertEqual(self.calls, [])
        for value in ([1, 2], (False, 1), (1,), (resource.RLIM_INFINITY, 1), (-2, -2), (3, 2)):
            w, endpoint = self.worker()
            self.values[resource.RLIMIT_FSIZE] = value
            self.calls.clear()
            with self.subTest(pair=value), self.assertRaises(command.ProcessError): self.apply(w, endpoint)
            self.assertFalse(any(c[0] == "set" for c in self.calls))

    def test_setup_interruption_stays_in_original_ledger_and_cannot_retry_or_restore(self):
        w, endpoint = self.worker()
        interrupted = KeyboardInterrupt()
        def after():
            if self.calls[-1][0] == "set": raise interrupted
        self.after = after
        with self.assertRaises(KeyboardInterrupt) as caught: self.apply(w, endpoint)
        self.assertIs(caught.exception, interrupted)
        self.assertEqual(w.effects[-1].state, "UNKNOWN")
        self.assertEqual(self.values[resource.RLIMIT_CORE], (0, 0))
        before = list(self.calls)
        with self.assertRaises(command.ProcessError): self.apply(w, endpoint)
        self.assertEqual(self.calls, before)
        self.assertEqual(endpoint.state, "OPEN")
        self.assertFalse(any(call[0] == "close" for call in self.world.calls))

    def test_stop_after_each_return_prevents_every_later_effect(self):
        for cutoff in range(1, 7):
            w, endpoint = self.worker()
            self.calls.clear()
            def after():
                if len(self.calls) == cutoff: w.ctx.stopped = True
            self.after = after
            with self.subTest(cutoff=cutoff), self.assertRaises(command.ProcessError): self.apply(w, endpoint)
            self.assertEqual(len(self.calls), cutoff)
            self.assertTrue(all(e.state == "RETURNED" for e in w.effects))
            self.assertTrue(self.world.rows[8]["flags"] & 1)

    def test_readback_or_final_original_drift_never_becomes_limit_success(self):
        for field in ("core", "fsize", "descriptor"):
            w, endpoint = self.worker()
            self.calls.clear()
            def after():
                if len(self.calls) == 4:
                    if field == "core": self.values[resource.RLIMIT_CORE] = (1, 1)
                    elif field == "fsize": self.values[resource.RLIMIT_FSIZE] = (limits.FILE_BYTES + 1,) * 2
                if len(self.calls) == 6 and field == "descriptor":
                    self.world.rows[8]["stamp"] = (STAMP[0], STAMP[1], STAMP[2] + 1)
            self.after = after
            with self.subTest(field=field), self.assertRaises((command.ProcessError, native.NativeProcessError)):
                self.apply(w, endpoint)
            self.assertEqual(len([c for c in self.calls if c[0] == "set"]), 2)

    def test_reentry_is_latched_before_original_owner_callback(self):
        w, endpoint = self.worker()
        original, attempted = w.ctx.owner_check, []
        def checked():
            if not attempted:
                attempted.append(True)
                with self.assertRaises(command.ProcessError): self.apply(w, endpoint)
            original()
        with patch.object(w.ctx, "owner_check", checked): self.apply(w, endpoint)
        self.assertEqual(attempted, [True])
        self.assertEqual(len(self.calls), 6)

    def run_fixed_worker(self, w):
        """Only substitute protocol/OS returns; execute the real Worker.run."""
        manifest = types.SimpleNamespace(capture=False, search=False, record_bytes=0)
        decoded = types.SimpleNamespace(finish=lambda: None, argv=[b"/fixed/git", b"fetch"],
            cwd=b"/owned/private", environment={}, directories=[])
        for fd, access in ((0, os.O_RDONLY), (1, os.O_WRONLY), (2, os.O_WRONLY)):
            self.world.lease(w.io, fd, "null", access)
        with patch.object(command, "_send"), patch.object(command, "_hello", return_value=b"hello"), \
             patch.object(command, "_receive", side_effect=[b"config", b"manifest", command._scalar(NONCE)]), \
             patch.object(command, "_config", return_value=(manifest, 0, None, None)), \
             patch.object(command.Manifest, "decode", return_value=manifest), \
             patch.object(command, "NativeRecordDecoder", return_value=decoded), \
             patch.object(command.os, "chdir", return_value=None), \
             patch.object(command.signal, "signal", return_value=None), \
             patch.object(command.os, "execve", side_effect=_ExecReached) as execute:
            try: w.run()
            except _ExecReached: return execute
            self.fail("fixed worker did not reach inert exec boundary")

    def test_actual_worker_hook_precedes_inheritance_cwd_and_exec_old_map_unchanged(self):
        w, _ = self.worker()
        self.run_fixed_worker(w).assert_called_once_with(b"/fixed/git", (b"/fixed/git", b"fetch"), {})
        operations = [e.operation for e in w.effects]
        self.assertLess(operations.index("git_remote_fsize_after"), operations.index("git_remote_inheritance"))
        self.assertLess(operations.index("git_remote_inheritance"), operations.index("cwd"))
        self.assertLess(operations.index("cwd"), operations.index("exec"))
        ordinary, _ = self.worker(remote=False)
        before = list(self.calls)
        with patch.object(limits, "apply_worker_limits", side_effect=AssertionError("old map widened")):
            self.run_fixed_worker(ordinary).assert_called_once()
        self.assertEqual(self.calls, before)
        self.assertFalse(ordinary.git_remote_limits_entered)

    def test_actual_worker_cannot_exec_after_unsupported_limit(self):
        w, _ = self.worker()
        self.values[resource.RLIMIT_FSIZE] = (1, 1)
        with self.assertRaises(command.ProcessError): self.run_fixed_worker(w)
        operations = [e.operation for e in w.effects]
        self.assertNotIn("git_remote_inheritance", operations)
        self.assertNotIn("cwd", operations)
        self.assertNotIn("exec", operations)


if __name__ == "__main__":
    unittest.main()
