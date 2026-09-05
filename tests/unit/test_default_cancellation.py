"""Cleanup dispatch and actual profile resources, without credentials/Store work."""
from __future__ import annotations

import os
import signal
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from sys import exc_info
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import ios_profiles as profiles
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.errors import CredentialError, ValidationError
from mobile_release.inspection import InspectionDeadline

from workflow.profile_resource_fixture import run_case


class DefaultCancellationTests(unittest.TestCase):
    def guard(self):
        return DefaultCancellation(CredentialError, "fixed restoration failure")

    def test_scope_acquires_nothing_and_claimed_cleanup_never_replays_even_after_failure(self):
        for fail in (False, True):
            calls = []
            def cleanup():
                calls.append(True)
                if fail:
                    raise ValidationError("cleanup failure")
            guard = self.guard()
            with self.subTest(fail=fail), patch("mobile_release.cancellation.signal.signal", side_effect=AssertionError("no handler installation")):
                scope = CleanupScope(guard, cleanup, owns_cancellation=False)
                self.assertEqual(calls, [])
                try:
                    try:
                        with scope:
                            self.assertEqual(calls, [])
                    finally:
                        scope.__exit__(*exc_info())
                except ValidationError:
                    self.assertTrue(fail)
                else:
                    self.assertFalse(fail)
                self.assertFalse(scope.__exit__(None, None, None))
            self.assertEqual(calls, [True])

    def test_pending_cancellation_preserves_body_or_cleanup_error_and_checks_only_normal_exit(self):
        for body_fails, cleanup_fails in ((False, False), (True, False), (False, True), (True, True)):
            guard = self.guard()
            body_error, cleanup_error = ValueError("body error"), ValidationError("cleanup error")
            calls = []
            def cleanup():
                calls.append(True)
                guard.cancelled = True
                if cleanup_fails:
                    raise cleanup_error
            scope = CleanupScope(guard, cleanup, owns_cancellation=True)
            expected = ValidationError if cleanup_fails else ValueError if body_fails else KeyboardInterrupt
            with self.subTest(body=body_fails, cleanup=cleanup_fails), self.assertRaises(expected) as raised:
                try:
                    with scope:
                        guard.activate()
                        if body_fails:
                            raise body_error
                finally:
                    scope.__exit__(*exc_info())
            self.assertEqual(calls, [True])
            if body_fails or cleanup_fails:
                self.assertIs(raised.exception, cleanup_error if cleanup_fails else body_error)

    def test_borrowed_cleanup_retains_outer_guard_until_all_independent_resources_finish(self):
        guard, calls = self.guard(), []
        def inner_cleanup():
            guard.cancelled = True
            calls.append("inner")
        def outer_cleanup():
            inner = CleanupScope(guard, inner_cleanup, owns_cancellation=False)
            try:
                with inner:
                    pass
            finally:
                inner.__exit__(*exc_info())
            calls.append("outer")
            self.assertEqual(guard.depth, 1)
        outer = CleanupScope(guard, outer_cleanup, owns_cancellation=True)
        with self.assertRaises(KeyboardInterrupt):
            try:
                with outer:
                    guard.activate()
            finally:
                outer.__exit__(*exc_info())
        self.assertEqual(calls, ["inner", "outer"])

    def test_restoration_attempts_every_handler_with_int_last_and_preserves_fixed_failure(self):
        for fail_at in (signal.SIGTERM, signal.SIGINT):
            guard = self.guard()
            guard.previous = {signal.SIGINT: signal.default_int_handler, signal.SIGTERM: signal.SIG_DFL}
            calls = []
            def restore(signum, handler):
                calls.append(signum)
                if signum == fail_at:
                    raise OSError("private-native-canary")
            scope = CleanupScope(guard, lambda: setattr(guard, "cancelled", True), owns_cancellation=True)
            with self.subTest(fail_at=fail_at), patch("mobile_release.cancellation.signal.signal", side_effect=restore), self.assertRaisesRegex(CredentialError, "fixed restoration failure") as raised:
                try:
                    with scope:
                        pass
                finally:
                    scope.__exit__(*exc_info())
            self.assertNotIn("private-native-canary", str(raised.exception))
            self.assertEqual(calls, [signal.SIGTERM, signal.SIGINT])


@unittest.skipUnless(os.name == "posix", "profile resource ownership needs POSIX")
class ProfileResourceSignalTests(unittest.TestCase):
    def boundary(self, mode, signum=signal.SIGINT):
        with tempfile.TemporaryDirectory(prefix="mrk-resource-boundary-") as name:
            result = run_case(Path(name), mode, signum)
        self.assertTrue(result["boundaryReached"])
        self.assertEqual(result["cleanupAttempts"], 1)
        return result

    def test_first_signals_at_real_cleanup_entry_dispatch_and_restoration_cover_all_parent_owners(self):
        for area in ("read", "source", "capture"):
            for phase in ("cleanup-entry", "cleanup-claimed", "cleanup-dispatch", "restore-entry", "restore-active"):
                for signum in (signal.SIGINT, signal.SIGTERM):
                    with self.subTest(area=area, phase=phase, signum=signum):
                        result = self.boundary(f"{area}-{phase}", signum)
                        self.assertTrue(result["handlersRestored"] and result["checkedBeforeFallback"])

    def test_actual_raw_descriptor_and_scratch_acquisition_io_and_close_boundaries_are_owned(self):
        for area, phases in (("read", ("open", "fstat", "read", "close")),
                             ("source", ("scratch-create", "input-open", "input-write", "input-close", "scratch-cleanup")),
                             ("capture", ("selector-create", "selector-register", "selector-close"))):
            for phase in phases:
                for signum in (signal.SIGINT, signal.SIGTERM):
                    with self.subTest(area=area, phase=phase, signum=signum):
                        self.boundary(f"{area}-{phase}", signum)

    def test_restored_int_or_term_cannot_turn_completed_resource_cleanup_into_success(self):
        for area in ("read", "source", "capture"):
            for phase in ("restore-term", "restore-int", "restored-term-fatal"):
                with self.subTest(area=area, phase=phase):
                    result = self.boundary(f"{area}-{phase}")
                    if phase == "restored-term-fatal":
                        self.assertTrue(result["hostTerminatedAfterCleanup"])

    def test_real_selector_close_failure_still_reaps_group_closes_stream_and_cleans_outer_scratch(self):
        for area in ("capture", "source"):
            for phase in ("selector-create-failure", "selector-register-failure", "selector-close-failure", "selector-close-unresolved"):
                with self.subTest(area=area, phase=phase):
                    result = self.boundary(f"{area}-{phase}")
                    self.assertTrue(result["leadersReaped"] and result["streamsClosed"] and result["scratchRemoved"])
                    self.assertEqual(result["unresolvedCleanupReported"], phase == "selector-close-unresolved")
                    self.assertEqual(result["selectorsClosed"], phase != "selector-close-unresolved")

    def test_io_and_scratch_failures_restore_handlers_close_descriptors_and_report_unresolved_state(self):
        for area, phases in (("read", ("fstat-failure", "read-failure")),
                             ("source", ("input-write-failure", "scratch-cleanup-failure", "scratch-cleanup-unresolved"))):
            for phase in phases:
                with self.subTest(area=area, phase=phase):
                    result = self.boundary(f"{area}-{phase}")
                    self.assertTrue(result["rawDescriptorsClosed"] and result["handlersRestored"])
                    self.assertEqual(result["scratchRemoved"], phase != "scratch-cleanup-unresolved")
                    self.assertEqual(result["unresolvedCleanupReported"], phase == "scratch-cleanup-unresolved")

    def test_repeated_default_signals_do_not_abandon_a_claimed_resource_cleanup(self):
        for area in ("read", "source", "capture"):
            for signum in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(area=area, signum=signum):
                    self.boundary(f"{area}-cleanup-entry-repeat", signum)


class ProfileResourceIOTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-profile-io-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "input"
        self.content = b"fictional-input" * 100
        self.source.write_bytes(self.content)

    def test_raw_reader_handles_short_reads_bounds_and_premature_eof_without_file_wrappers(self):
        real_read = os.read
        with patch.object(profiles.os, "read", side_effect=lambda fd, count: real_read(fd, min(7, count))), patch.object(profiles.os, "fdopen", side_effect=AssertionError("raw ownership must not rely on file wrappers")):
            self.assertEqual(profiles.read_profile_bytes(self.source, maximum=len(self.content)), self.content)
        with patch.object(profiles.os, "read", return_value=b""), self.assertRaisesRegex(ValidationError, "changed"):
            profiles.read_profile_bytes(self.source)
        for bound in (0, -1, True, "4", profiles.MAX_PROFILE_BYTES + 1):
            with self.subTest(bound=bound), self.assertRaises(ValidationError):
                profiles.read_profile_bytes(self.source, maximum=bound)

    def test_exclusive_private_source_handles_short_failed_and_zero_writes_before_capture(self):
        real_write, real_temp = os.write, tempfile.TemporaryDirectory
        for phase in ("short", "zero", "failed"):
            scratches, captured = [], []
            def temporary(*args, **kwargs):
                handle = real_temp(*args, dir=self.root, **kwargs)
                scratches.append(handle)
                return handle
            def write(descriptor, content):
                if phase == "zero":
                    return 0
                if phase == "failed":
                    raise OSError("private-native-canary")
                return real_write(descriptor, content[:7])
            def capture(directory, deadline, *, cancellation):
                captured.append(True)
                self.assertEqual((directory / "cms.der").read_bytes(), self.content)
                self.assertEqual(stat.S_IMODE((directory / "cms.der").stat().st_mode), 0o600)
                self.assertEqual(cancellation.depth, 0)
                return b"verified"
            with self.subTest(phase=phase), patch.object(profiles, "sys", SimpleNamespace(platform="darwin")), patch.object(profiles.tempfile, "TemporaryDirectory", side_effect=temporary), patch.object(profiles.os, "write", side_effect=write), patch.object(profiles, "_capture_profile", side_effect=capture):
                if phase == "short":
                    self.assertEqual(profiles.authenticate_cms(self.content, deadline=InspectionDeadline()), b"verified")
                else:
                    with self.assertRaises(ValidationError) as raised:
                        profiles.authenticate_cms(self.content, deadline=InspectionDeadline())
                    self.assertNotIn("private-native-canary", str(raised.exception))
                    self.assertEqual(captured, [])
            self.assertTrue(scratches)
            self.assertTrue(all(not Path(handle.name).exists() for handle in scratches))

    def test_ambiguous_raw_close_is_one_attempt_and_never_closes_reused_foreign_descriptor(self):
        real_open, real_close, real_fstat = os.open, os.close, os.fstat
        for area in ("read", "source"):
            for completed in (False, True):
                descriptors, close_calls = [], []
                foreign_path = self.root / "foreign"
                def opening(path, *args, **kwargs):
                    descriptor = real_open(path, *args, **kwargs)
                    if Path(path) == self.source or Path(path).name == "cms.der":
                        descriptors.append(descriptor)
                    return descriptor
                def closing(descriptor):
                    if descriptor in descriptors:
                        close_calls.append(descriptor)
                        self.assertEqual(len(close_calls), 1, "ambiguous close was replayed")
                        if completed:
                            real_close(descriptor)
                            foreign = real_open(foreign_path, os.O_RDWR | os.O_CREAT, 0o600)
                            if foreign != descriptor:
                                os.dup2(foreign, descriptor)
                                real_close(foreign)
                        raise OSError("private-native-canary")
                    return real_close(descriptor)
                try:
                    with self.subTest(area=area, completed=completed), patch.object(profiles, "sys", SimpleNamespace(platform="darwin")), patch.object(profiles.os, "open", side_effect=opening), patch.object(profiles.os, "close", side_effect=closing), patch.object(profiles, "_capture_profile", side_effect=AssertionError("failed source close reached worker")):
                        with self.assertRaisesRegex(ValidationError, "descriptor cleanup could not be confirmed") as raised:
                            if area == "read":
                                profiles.read_profile_bytes(self.source)
                            else:
                                profiles.authenticate_cms(self.content, deadline=InspectionDeadline())
                        self.assertNotIn("private-native-canary", str(raised.exception))
                    self.assertEqual(close_calls, descriptors)
                    self.assertEqual(len(descriptors), 1)
                    details = real_fstat(descriptors[0])  # Unresolved native close is reported, NOT falsely called closed.
                    if completed:
                        self.assertEqual(details.st_ino, foreign_path.stat().st_ino)
                finally:
                    for descriptor in descriptors:
                        try:
                            real_close(descriptor)
                        except OSError:
                            pass


if __name__ == "__main__":
    unittest.main()
