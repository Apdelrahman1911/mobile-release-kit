"""Cleanup dispatch and actual profile resources, without credentials/Store work."""
from __future__ import annotations

import os
import gc
import signal
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from sys import exc_info
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import ios_profiles as profiles
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.errors import CredentialError, ValidationError
from mobile_release.inspection import InspectionDeadline

from workflow.profile_resource_fixture import UNKNOWN_RESOURCE_MODES, run_case
from workflow.profile_process_fixture import (
    FixtureWorkspace, assert_fixture_idle, retain_fixture_custody,
)


@contextmanager
def resource_case():
    """Do not let a subTest swallow an adverse fixture result and admit work."""
    assert_fixture_idle()
    try:
        yield
    except BaseException as error:
        retain_fixture_custody(error)
        raise


@contextmanager
def isolated_profile_records():
    """Model only producers; preserve every remaining actual resource record.

    Native acquisition is prohibited, but descriptors, scratch and handler
    scopes are real. Expected-error PASS cannot discard their retained custody
    when these registry patches restore. There is no reset or retry API.
    """
    assert_fixture_idle()  # Before replacing a registry which carries custody.
    with ExitStack() as stack:
        records = {}
        originals = {}
        for name in ("_PROFILE_SCRATCH_LEASES", "_PROFILE_RESOURCE_SCOPES"):
            originals[name] = getattr(profiles, name)
            replacement = type(originals[name])()
            stack.enter_context(patch.object(profiles, name, replacement))
            records[name] = replacement
        # A faulty migration must fail before starting an owner/task, not turn
        # this unit fixture into an uncontained native capture.
        capture = stack.enter_context(patch("mobile_release._profile_process.capture_profile",
                                           side_effect=AssertionError("fake-only fixture reached a real capture")))
        create = stack.enter_context(patch("mobile_release._native_process.create",
                                          side_effect=AssertionError("fake-only fixture attempted a native child")))
        try:
            yield records
            capture.assert_not_called()
            create.assert_not_called()
        except BaseException as error:
            retain_fixture_custody(error)
            raise
        finally:
            # The product removes settled records itself. Merge ALL remaining
            # records even on expected-error PASS, before restoring the actual
            # containers. A fake producer is not filesystem/FD finality.
            for name, replacement in records.items():
                for record in replacement:
                    if not any(record is existing for existing in originals[name]):
                        originals[name].append(record)
                    retain_fixture_custody(record)


class DefaultCancellationTests(unittest.TestCase):
    def setUp(self):
        assert_fixture_idle()

    def guard(self):
        assert_fixture_idle()
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

    def test_restoration_return_loss_not_deferred_cancellation_requires_unknown_scope(self):
        self.assertEqual({mode for mode in UNKNOWN_RESOURCE_MODES if mode.endswith("-restore-int")},
                         {"read-restore-int", "source-restore-int", "capture-restore-int"})
        for selected in (signal.SIGTERM, signal.SIGINT):
            guard = self.guard()
            guard.previous = {signal.SIGINT: signal.default_int_handler, signal.SIGTERM: signal.SIG_DFL}
            guard.depth = 0
            handlers = {signum: guard.interrupt for signum in guard.previous}
            calls, cleaned, registry = [], [], []
            original = KeyboardInterrupt("modeled final restoration return loss")

            def restore(signum, handler):
                previous = handlers[signum]
                handlers[signum] = handler
                calls.append(signum)
                if signum == selected:
                    if selected == signal.SIGINT:
                        raise original  # The final setter has not returned.
                    guard.interrupt(signal.SIGINT, None)  # Still the deferred guard.
                return previous

            # Entirely inert scope: no handler is installed, and no descriptor,
            # scratch, child or task exists. Replacing this model-only registry
            # does not release any real resource or previous retained owner.
            with self.subTest(restored=selected), patch.object(profiles, "_PROFILE_RESOURCE_SCOPES", registry), patch("mobile_release.cancellation.signal.signal", side_effect=restore):
                scope = profiles._ProfileCleanupScope(
                    guard, lambda: cleaned.append(True), owns_cancellation=True, descriptors=(),
                )
                with self.assertRaises(KeyboardInterrupt) as raised:
                    try:
                        with scope:
                            pass
                    finally:
                        scope.__exit__(*exc_info())
                unknown = selected == signal.SIGINT
                self.assertEqual(calls, [signal.SIGTERM, signal.SIGINT])
                self.assertEqual(cleaned, [True])
                self.assertEqual(handlers, guard.previous)
                self.assertTrue(scope.claimed and scope._settled)
                self.assertEqual(scope.retained, unknown)
                self.assertEqual(registry, [scope] if unknown else [])
                self.assertEqual(len(scope._cleanup_errors), int(unknown))
                self.assertIs(scope._primary_error, raised.exception)
                if unknown:
                    self.assertIs(raised.exception, original)
                else:
                    self.assertTrue(guard.cancelled)


@unittest.skipUnless(os.name == "posix", "profile resource ownership needs POSIX")
class ProfileResourceSignalTests(unittest.TestCase):
    def setUp(self):
        assert_fixture_idle()

    def boundary(self, mode, signum=signal.SIGINT):
        assert_fixture_idle()
        with FixtureWorkspace(prefix="mrk-resource-boundary-") as workspace:
            result = run_case(workspace, mode, signum)
            self.assertTrue(result["boundaryReached"])
            self.assertEqual(result["cleanupAttempts"], 1)
            self.assertTrue(result["checkedBeforeFallback"])
            self.assertTrue(result["nativeWaitsConfirmed"] or result["noProducerAttempt"])
            return result

    def test_first_signals_at_real_cleanup_entry_dispatch_and_restoration_cover_all_parent_owners(self):
        for area in ("read", "source", "capture"):
            for phase in ("cleanup-entry", "cleanup-claimed", "cleanup-dispatch", "restore-entry", "restore-active"):
                for signum in (signal.SIGINT, signal.SIGTERM):
                    assert_fixture_idle()
                    with self.subTest(area=area, phase=phase, signum=signum), resource_case():
                        result = self.boundary(f"{area}-{phase}", signum)
                        self.assertTrue(result["handlersRestored"] and result["rawDescriptorsClosed"] and result["leasesClosed"])

    def test_actual_raw_descriptor_scratch_and_pipe_acquisition_io_and_close_boundaries_are_owned(self):
        for area, phases in (("read", ("open", "fstat", "read", "close")),
                             ("source", ("scratch-create", "input-open", "input-write", "input-close", "scratch-cleanup")),
                             ("capture", ("pipe-create", "payload-register", "control-close", "status-close", "payload-close"))):
            for phase in phases:
                for signum in (signal.SIGINT, signal.SIGTERM):
                    assert_fixture_idle()
                    with self.subTest(area=area, phase=phase, signum=signum), resource_case():
                        result = self.boundary(f"{area}-{phase}", signum)
                        self.assertTrue(result["handlersRestored"] and result["rawDescriptorsClosed"] and result["leasesClosed"])
                        if area == "source" and phase != "scratch-cleanup" or phase in {"pipe-create", "payload-register"}:
                            self.assertTrue(result["noProducerAttempt"])

    def test_restored_int_or_term_cannot_turn_completed_resource_cleanup_into_success(self):
        # TERM is restored first while INT still reaches the deferred guard.
        # Losing the final INT setter's return is isolated in the three tests
        # below; a restored-handler observation cannot clear that uncertainty.
        for area in ("read", "source", "capture"):
            assert_fixture_idle()
            with self.subTest(area=area), resource_case():
                result = self.boundary(f"{area}-restore-term")
                self.assertTrue(result["rawDescriptorsClosed"] and result["leasesClosed"])
                self.assertTrue(result["handlersRestored"])

    def _unknown_restored_int(self, mode):
        self.assertIn(mode, ("read-restore-int", "source-restore-int", "capture-restore-int"))
        result = self.boundary(mode)
        area = mode.split("-", 1)[0]
        self.assertTrue(result["rawDescriptorsClosed"] and result["leasesClosed"] and result["handlersRestored"])
        self.assertTrue(result["retainedCustody"] and result["retainedAfterGC"] and result["reuseRefused"])
        self.assertFalse(result["noRetainedState"])
        self.assertEqual(result["noProducerAttempt"], area == "read")
        self.assertEqual(result["nativeWaitsConfirmed"], area != "read")
        self.assertEqual(result["producerFinalities"], {"read": [], "source": ["FINALIZED"], "capture": ["UNKNOWN"]}[area])
        self.assertEqual(result["producerCleanupAllowed"], area != "capture")
        self.assertEqual(result["scratchRemoved"], area != "capture")
        self.assertEqual(result["scratchRetained"], area == "capture")

    def test_unknown_read_restored_int(self):
        self._unknown_restored_int("read-restore-int")

    def test_unknown_source_restored_int(self):
        self._unknown_restored_int("source-restore-int")

    def test_unknown_capture_restored_int(self):
        self._unknown_restored_int("capture-restore-int")

    def _unknown_restored_term(self, mode):
        result = self.boundary(mode)
        self.assertTrue(result["rawDescriptorsClosed"] and result["leasesClosed"])
        self.assertTrue(result["hostTerminatedAfterCleanup"])
        # A killed host cannot finalize its still-active caller lease or
        # fabricate completed restoration. Its original domain is disposable.
        self.assertTrue(result["retainedCustody"])
        self.assertFalse(result["handlersRestored"])

    def test_unknown_read_restored_term_fatal(self):
        self._unknown_restored_term("read-restored-term-fatal")

    def test_unknown_source_restored_term_fatal(self):
        self._unknown_restored_term("source-restored-term-fatal")

    def test_unknown_capture_restored_term_fatal(self):
        self._unknown_restored_term("capture-restored-term-fatal")

    def test_real_pipe_lease_failures_preserve_waits_close_once_and_retain_unknown_outer_scratch(self):
        phases = ("pipe-create-failure", "payload-register-failure")
        for area in ("capture", "source"):
            for phase in phases:
                assert_fixture_idle()
                with self.subTest(area=area, phase=phase), resource_case():
                    result = self.boundary(f"{area}-{phase}")
                    self.assertTrue(result["rawDescriptorsClosed"] and result["handlersRestored"])
                    self.assertTrue(result["leasesClosed"])
                    self.assertTrue(result["noProducerAttempt"] and result["scratchRemoved"])

    def _unknown_pipe_lease(self, mode):
        result = self.boundary(mode)
        self.assertTrue(result["rawDescriptorsClosed"] and result["handlersRestored"])
        self.assertEqual(result["leasesClosed"], not mode.endswith("-unresolved"))
        self.assertTrue(result["nativeWaitsConfirmed"])
        self.assertTrue(result["scratchRetained"] and result["retainedCustody"])
        self.assertTrue(result["retainedAfterGC"] and result["reuseRefused"])

    def test_unknown_capture_control_close_failure(self):
        self._unknown_pipe_lease("capture-control-close-failure")

    def test_unknown_capture_status_close_failure(self):
        self._unknown_pipe_lease("capture-status-close-failure")

    def test_unknown_capture_payload_close_failure(self):
        self._unknown_pipe_lease("capture-payload-close-failure")

    def test_unknown_capture_payload_close_unresolved(self):
        self._unknown_pipe_lease("capture-payload-close-unresolved")

    def test_unknown_source_control_close_failure(self):
        self._unknown_pipe_lease("source-control-close-failure")

    def test_unknown_source_status_close_failure(self):
        self._unknown_pipe_lease("source-status-close-failure")

    def test_unknown_source_payload_close_failure(self):
        self._unknown_pipe_lease("source-payload-close-failure")

    def test_unknown_source_payload_close_unresolved(self):
        self._unknown_pipe_lease("source-payload-close-unresolved")

    def test_io_and_scratch_failures_restore_handlers_close_descriptors_and_report_unresolved_state(self):
        for area, phases in (("read", ("fstat-failure", "read-failure")),
                             ("source", ("input-write-failure",))):
            for phase in phases:
                assert_fixture_idle()
                with self.subTest(area=area, phase=phase), resource_case():
                    result = self.boundary(f"{area}-{phase}")
                    self.assertTrue(result["rawDescriptorsClosed"] and result["handlersRestored"])
                    self.assertTrue(result["scratchRemoved"])
                    self.assertFalse(result["retainedCustody"])

    def _unknown_scratch_cleanup(self, mode):
        result = self.boundary(mode)
        self.assertTrue(result["rawDescriptorsClosed"] and result["handlersRestored"])
        self.assertEqual(result["scratchRemoved"], not mode.endswith("-unresolved"))
        self.assertTrue(result["retainedCustody"])
        self.assertTrue(result["retainedAfterGC"] and result["reuseRefused"])

    def test_unknown_source_scratch_cleanup_failure(self):
        self._unknown_scratch_cleanup("source-scratch-cleanup-failure")

    def test_unknown_source_scratch_cleanup_unresolved(self):
        self._unknown_scratch_cleanup("source-scratch-cleanup-unresolved")

    def test_repeated_default_signals_do_not_abandon_a_claimed_resource_cleanup(self):
        for area in ("read", "source", "capture"):
            for signum in (signal.SIGINT, signal.SIGTERM):
                assert_fixture_idle()
                with self.subTest(area=area, signum=signum), resource_case():
                    result = self.boundary(f"{area}-cleanup-entry-repeat", signum)
                    self.assertTrue(result["rawDescriptorsClosed"] and result["leasesClosed"] and result["handlersRestored"])

    def test_private_cleanup_prologue_preserves_incoming_system_exit_before_its_first_assignment(self):
        for area in ("read", "source"):
            for signum in (signal.SIGINT, signal.SIGTERM):
                assert_fixture_idle()
                with self.subTest(area=area, signum=signum), resource_case():
                    result = self.boundary(f"{area}-cleanup-prologue-systemexit", signum)
                    self.assertTrue(result["originalIdentityPreserved"])
                    self.assertTrue(result["rawDescriptorsClosed"] and result["leasesClosed"] and result["handlersRestored"])


class ProfileResourceIOTests(unittest.TestCase):
    def setUp(self):
        assert_fixture_idle()
        self.workspace = FixtureWorkspace(prefix="mrk-profile-io-")
        self.addCleanup(self.workspace.__exit__, None, None, None)
        self.root = self.workspace.path
        self.source = self.root / "input"
        self.content = b"fictional-input" * 100
        self.source.write_bytes(self.content)

    def test_raw_reader_handles_short_reads_bounds_and_premature_eof_without_file_wrappers(self):
        real_read = os.read
        assert_fixture_idle()
        with patch.object(profiles.os, "read", side_effect=lambda fd, count: real_read(fd, min(7, count))), patch.object(profiles.os, "fdopen", side_effect=AssertionError("raw ownership must not rely on file wrappers")):
            self.assertEqual(profiles.read_profile_bytes(self.source, maximum=len(self.content)), self.content)
        assert_fixture_idle()
        with patch.object(profiles.os, "read", return_value=b""), self.assertRaisesRegex(ValidationError, "changed"):
            profiles.read_profile_bytes(self.source)
        for bound in (0, -1, True, "4", profiles.MAX_PROFILE_BYTES + 1):
            assert_fixture_idle()
            with self.subTest(bound=bound), resource_case(), self.assertRaises(ValidationError):
                profiles.read_profile_bytes(self.source, maximum=bound)
        self.workspace.allow_removal()

    def test_exclusive_private_source_handles_short_failed_and_zero_writes_before_capture(self):
        real_write, real_mkdtemp = os.write, tempfile.mkdtemp
        for phase in ("short", "zero", "failed"):
            assert_fixture_idle()
            scratches, captured = [], []
            def temporary(*args, **kwargs):
                path = real_mkdtemp(*args, dir=self.root, **kwargs)
                scratches.append(Path(path))
                return path
            def write(descriptor, content):
                if phase == "zero":
                    return 0
                if phase == "failed":
                    raise OSError("private-native-canary")
                return real_write(descriptor, content[:7])
            def capture(directory, deadline, *, cancellation, finality):
                captured.append(True)
                self.assertEqual((directory / "cms.der").read_bytes(), self.content)
                self.assertEqual(stat.S_IMODE((directory / "cms.der").stat().st_mode), 0o600)
                self.assertEqual(cancellation.depth, 0)
                self.assertEqual(finality.state, "NO_PRODUCERS")
                self.assertTrue(finality.cleanup_allowed)
                return b"verified"
            with self.subTest(phase=phase), isolated_profile_records(), patch.object(profiles, "sys", SimpleNamespace(platform="darwin")), patch.object(profiles.tempfile, "mkdtemp", side_effect=temporary), patch.object(profiles.os, "write", side_effect=write), patch.object(profiles, "_capture_profile", side_effect=capture):
                if phase == "short":
                    self.assertEqual(profiles.authenticate_cms(self.content, deadline=InspectionDeadline()), b"verified")
                else:
                    with self.assertRaises(ValidationError) as raised:
                        profiles.authenticate_cms(self.content, deadline=InspectionDeadline())
                    self.assertNotIn("private-native-canary", str(raised.exception))
                    self.assertEqual(captured, [])
            self.assertTrue(scratches)
            self.assertTrue(all(not path.exists() for path in scratches))
        self.workspace.allow_removal()

    def _unknown_raw_close(self, area, *, completed):
        real_open, real_close, real_fstat = os.open, os.close, os.fstat
        real_mkdtemp = tempfile.mkdtemp
        descriptors, close_calls = [], []
        owned_live = set()
        reused = []
        foreign_path = self.root / "foreign"
        def opening(path, *args, **kwargs):
            descriptor = real_open(path, *args, **kwargs)
            if Path(path) == self.source or Path(path).name == "cms.der":
                descriptors.append(descriptor)
                owned_live.add(descriptor)
            return descriptor
        def closing(descriptor):
            if descriptor in descriptors:
                close_calls.append(descriptor)
                self.assertEqual(len(close_calls), 1, "ambiguous close was replayed")
                if completed:
                    self.assertIn(descriptor, owned_live)
                    owned_live.remove(descriptor)  # Retire BEFORE the one fixture close attempt.
                    real_close(descriptor)
                    foreign = real_open(foreign_path, os.O_RDWR | os.O_CREAT, 0o600)
                    owned_live.add(foreign)
                    reused.append(foreign)
                    # Do not force reuse by dup2 into an unleased number:
                    # require a genuine kernel return or fail closed.
                    self.assertEqual(foreign, descriptor, "kernel did not return the retired fixture descriptor")
                raise OSError("private-native-canary")
            return real_close(descriptor)
        def temporary(*args, **kwargs):
            return real_mkdtemp(*args, dir=self.root, **kwargs)
        with isolated_profile_records() as records:
            try:
                with patch.object(profiles, "sys", SimpleNamespace(platform="darwin")), patch.object(profiles.tempfile, "mkdtemp", side_effect=temporary), patch.object(profiles.os, "open", side_effect=opening), patch.object(profiles.os, "close", side_effect=closing), patch.object(profiles, "_capture_profile", side_effect=AssertionError("failed source close reached worker")):
                    with self.assertRaisesRegex(ValidationError, "descriptor cleanup could not be confirmed") as raised:
                        if area == "read":
                            profiles.read_profile_bytes(self.source)
                        else:
                            profiles.authenticate_cms(self.content, deadline=InspectionDeadline())
                    self.workspace.retain()
                    self.assertNotIn("private-native-canary", str(raised.exception))
                retained_scopes = [scope for scope in records["_PROFILE_RESOURCE_SCOPES"] if scope.retained]
                self.assertEqual(len(retained_scopes), 1)
                self.assertTrue(any(descriptor.state == "UNKNOWN" for descriptor in retained_scopes[0]._descriptors))
                if area == "source":
                    self.assertEqual(len(records["_PROFILE_SCRATCH_LEASES"]), 1)
                    self.assertTrue(records["_PROFILE_SCRATCH_LEASES"][0].retained)
                self.assertEqual(close_calls, descriptors)
                self.assertEqual(len(descriptors), 1)
                if completed:
                    # The product may sanitize the injection's assertion;
                    # independently reject a nonreuse instead of passing.
                    self.assertEqual(reused, descriptors)
                self.assertEqual(owned_live, set(descriptors))
                details = real_fstat(descriptors[0])  # Unknown is NOT falsely called closed.
                if completed:
                    self.assertEqual(details.st_ino, foreign_path.stat().st_ino)
            finally:
                # Close only exact still-owned kernel returns. Retire
                # each before its one attempt; never retry a stale FD.
                while owned_live:
                    descriptor = owned_live.pop()
                    real_close(descriptor)
        # Registry restoration is not a reset, even after exact fixture FD
        # cleanup. Product UNKNOWN survives until this original domain exits.
        self.assertTrue(any(scope.retained for scope in profiles._PROFILE_RESOURCE_SCOPES))

    def test_unknown_read_raw_close_before_completion(self):
        self._unknown_raw_close("read", completed=False)

    def test_unknown_read_raw_close_after_completion(self):
        self._unknown_raw_close("read", completed=True)

    def test_unknown_source_raw_close_before_completion(self):
        self._unknown_raw_close("source", completed=False)

    def test_unknown_source_raw_close_after_completion(self):
        self._unknown_raw_close("source", completed=True)


class ProfileScratchFinalityTests(unittest.TestCase):
    """Modeled producers, real retained filesystem and restoration custody."""

    def setUp(self):
        assert_fixture_idle()
        self.workspace = FixtureWorkspace(prefix="mrk-profile-lease-")
        self.addCleanup(self.workspace.__exit__, None, None, None)
        self.root = self.workspace.path
        self.native = self.enterContext(patch("mobile_release._native_process.create",
                                             side_effect=AssertionError("scratch unit fixture may not create a child")))

    def temporary(self, *args, **kwargs):
        return self.real_mkdtemp(*args, dir=self.root, **kwargs)

    def test_lease_constructor_is_inert_and_gc_is_not_an_implicit_cleanup_owner(self):
        from mobile_release._profile_process import CaptureFinality

        self.real_mkdtemp = tempfile.mkdtemp
        with isolated_profile_records() as records:
            finality = CaptureFinality()
            with patch.object(profiles.tempfile, "mkdtemp", side_effect=AssertionError("constructor acquired scratch")):
                lease = profiles.ScratchLease(finality)
            self.assertEqual(lease.state, "UNACQUIRED")
            self.assertIsNone(lease.path)
            self.assertEqual(finality.state, "NO_PRODUCERS")
            self.assertTrue(finality.cleanup_allowed)
            for target, attribute, value in ((lease, "state", "REMOVED"),
                                              (finality, "state", "FINALIZED"),
                                              (finality, "cleanup_allowed", True)):
                # A failed inert setter assertion must stop before acquire(),
                # not be swallowed while this same lease is still active.
                with self.assertRaises(AttributeError):
                    setattr(target, attribute, value)
            with patch.object(profiles.tempfile, "mkdtemp", side_effect=self.temporary):
                path = lease.acquire()
            self.assertEqual(lease.path, path)
            self.assertEqual(lease.state, "OWNED")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            (path / "cms.der").write_bytes(b"fictional source")
            identity = id(lease)
            del lease, finality
            gc.collect()
            retained = [item for item in records["_PROFILE_SCRATCH_LEASES"] if id(item) == identity]
            self.assertEqual(len(retained), 1, "scratch custody was not strongly rooted")
            self.assertTrue(path.is_dir(), "GC impersonated an explicit cleanup owner")
            lease = retained[0]
            lease.cleanup()
            self.assertEqual(lease.state, "REMOVED")
            self.assertFalse(path.exists())
            lease.cleanup()  # A settled lease never replays native removal.
            self.assertNotIn(lease, records["_PROFILE_SCRATCH_LEASES"])
        self.native.assert_not_called()
        self.workspace.allow_removal()

    def test_attempted_unpublished_scratch_acquisition_retains_unknown_across_unwind_and_gc(self):
        from mobile_release._profile_process import CaptureFinality

        self.real_mkdtemp = tempfile.mkdtemp
        created = []
        original = KeyboardInterrupt("original caller interruption")
        def unpublished(*args, **kwargs):
            path = Path(self.temporary(*args, **kwargs))
            created.append(path)
            raise original

        with isolated_profile_records() as records:
            lease = profiles.ScratchLease(CaptureFinality())
            with patch.object(profiles.tempfile, "mkdtemp", side_effect=unpublished):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    lease.acquire()
            self.assertIs(raised.exception, original)
            self.assertEqual(lease.state, "UNKNOWN")
            self.assertTrue(lease.retained)
            self.assertIsNone(lease.path, "a lost return must not invent an acquired path")
            self.workspace.retain()
            identity = id(lease)
            del lease
            gc.collect()
            retained = [item for item in records["_PROFILE_SCRATCH_LEASES"] if id(item) == identity]
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].state, "UNKNOWN")
            self.assertTrue(all(path.is_dir() for path in created))
            with self.assertRaises(ValidationError):
                retained[0].cleanup()
            self.assertTrue(all(path.is_dir() for path in created))
            with patch.object(profiles.tempfile, "mkdtemp") as scratch, patch.object(profiles, "sys", SimpleNamespace(platform="darwin")):
                with self.assertRaises(ValidationError):
                    profiles.authenticate_cms(b"fictional source", deadline=InspectionDeadline())
                with self.assertRaises(ValidationError):
                    profiles._capture_profile(self.root, InspectionDeadline())
            scratch.assert_not_called()
        # Knowing the exact test path and positive NO_PRODUCERS cannot reset
        # the product's unpublished-acquisition UNKNOWN or authorize removal.
        self.native.assert_not_called()
        self.assertTrue(any(id(item) == identity for item in profiles._PROFILE_SCRATCH_LEASES))

    def _unknown_replacement(self, replacement):
        from mobile_release._profile_process import CaptureFinality

        self.real_mkdtemp = tempfile.mkdtemp
        with isolated_profile_records() as records:
            lease = profiles.ScratchLease(CaptureFinality())
            with patch.object(profiles.tempfile, "mkdtemp", side_effect=self.temporary):
                path = lease.acquire()
            saved = path
            if replacement != "unexpected-child":
                saved = path.with_name(path.name + "-owned")
                path.rename(saved)
            if replacement == "directory":
                path.mkdir(mode=0o700)
                foreign = path
            elif replacement == "symlink":
                foreign = path.with_name(path.name + "-foreign")
                foreign.mkdir(mode=0o700)
                path.symlink_to(foreign, target_is_directory=True)
            else:
                foreign = path / "unexpected-directory"
                foreign.mkdir(mode=0o700)
            marker = foreign / "keep"
            marker.write_bytes(b"test-owned but not lease-owned")
            with self.assertRaises(ValidationError):
                lease.cleanup()
            self.assertEqual(lease.state, "UNKNOWN")
            self.assertTrue(lease.retained)
            self.workspace.retain()
            self.assertIn(lease, records["_PROFILE_SCRATCH_LEASES"])
            gc.collect()
            self.assertTrue(saved.is_dir())
            # Exact, bounded diagnostic reporting of this already-known marker,
            # not a new product owner or permission to traverse/remove scratch.
            expected = b"test-owned but not lease-owned"
            with marker.open("rb") as stream:
                self.assertEqual(stream.read(len(expected) + 1), expected)
            with self.assertRaises(ValidationError):
                profiles._require_profile_scratch_available()
        self.native.assert_not_called()
        self.assertIn(lease, profiles._PROFILE_SCRATCH_LEASES)

    def test_unknown_directory_replacement(self):
        self._unknown_replacement("directory")

    def test_unknown_symlink_replacement(self):
        self._unknown_replacement("symlink")

    def test_unknown_unexpected_child(self):
        self._unknown_replacement("unexpected-child")

    def _unknown_caller_exit(self, kind, *, fail_cleanup, fail_restore):
        self.real_mkdtemp = tempfile.mkdtemp
        real_cleanup, real_signal = profiles.ScratchLease.cleanup, signal.signal
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        original = kind("original caller object")
        original_notes = object()
        original.__notes__ = original_notes  # Caller metadata need not be a list.
        captured, cleaned, restored = [], [], []

        def capture(_directory, _deadline, *, cancellation, finality):
            self.assertEqual(finality.state, "NO_PRODUCERS")
            self.assertEqual(cancellation.depth, 0)
            captured.append(True)
            raise original

        def cleanup(lease):
            cleaned.append(lease)
            if fail_cleanup:
                raise OSError("private-native-canary")
            return real_cleanup(lease)

        def signal_api(signum, handler):
            result = real_signal(signum, handler)
            if captured and handler == previous.get(signum):
                restored.append(signum)
                if fail_restore:
                    raise OSError("private-native-canary")
            return result

        with isolated_profile_records() as records:
            with patch.object(profiles, "sys", SimpleNamespace(platform="darwin")), patch.object(profiles.tempfile, "mkdtemp", side_effect=self.temporary), patch.object(profiles, "_capture_profile", side_effect=capture), patch.object(profiles.ScratchLease, "cleanup", autospec=True, side_effect=cleanup), patch("mobile_release.cancellation.signal.signal", side_effect=signal_api):
                with self.assertRaises(kind) as raised:
                    profiles.authenticate_cms(b"fictional source", deadline=InspectionDeadline())
            self.workspace.retain()
            self.assertIs(raised.exception, original)
            self.assertIs(original.__notes__, original_notes)
            self.assertEqual(captured, [True])
            self.assertEqual(len(cleaned), 1)
            self.assertEqual(restored, [signal.SIGTERM, signal.SIGINT])
            self.assertNotIn("private-native-canary", str(raised.exception))
            # The injector performed each actual restoration before raising.
            # Observe those exact handlers without a second post-UNKNOWN setter.
            for signum, handler in previous.items():
                self.assertIs(signal.getsignal(signum), handler)
            self.assertEqual(len(records["_PROFILE_RESOURCE_SCOPES"]), 1)
            scope = records["_PROFILE_RESOURCE_SCOPES"][0]
            self.assertTrue(scope._retained and scope.retained)
            self.assertEqual(cleaned[0].state, "OWNED" if fail_cleanup else "REMOVED")
            if fail_cleanup:
                self.assertTrue(cleaned[0].path.is_dir())
                self.assertIn(cleaned[0], records["_PROFILE_SCRATCH_LEASES"])
            else:
                self.assertFalse(cleaned[0].path.exists())
                self.assertNotIn(cleaned[0], records["_PROFILE_SCRATCH_LEASES"])
        self.native.assert_not_called()
        self.assertIn(scope, profiles._PROFILE_RESOURCE_SCOPES)
        self.assertTrue(scope.retained)  # Observer-known restoration is no reset.

    def test_unknown_keyboard_interrupt_cleanup_failure(self):
        self._unknown_caller_exit(KeyboardInterrupt, fail_cleanup=True, fail_restore=False)

    def test_unknown_keyboard_interrupt_restore_failure(self):
        self._unknown_caller_exit(KeyboardInterrupt, fail_cleanup=False, fail_restore=True)

    def test_unknown_keyboard_interrupt_cleanup_and_restore_failure(self):
        self._unknown_caller_exit(KeyboardInterrupt, fail_cleanup=True, fail_restore=True)

    def test_unknown_system_exit_cleanup_failure(self):
        self._unknown_caller_exit(SystemExit, fail_cleanup=True, fail_restore=False)

    def test_unknown_system_exit_restore_failure(self):
        self._unknown_caller_exit(SystemExit, fail_cleanup=False, fail_restore=True)

    def test_unknown_system_exit_cleanup_and_restore_failure(self):
        self._unknown_caller_exit(SystemExit, fail_cleanup=True, fail_restore=True)


if __name__ == "__main__":
    unittest.main()
