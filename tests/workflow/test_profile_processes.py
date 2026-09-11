"""Real O/C/K/V custody; completion bytes never substitute for finality."""
from __future__ import annotations

import gc
import os
import signal
import unittest
import weakref
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _profile_process as owner
from mobile_release import ios_profiles
from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline
from mobile_release.ios_profiles import (
    COMPLETION_MAGIC, COMPLETION_MARKER, MAX_PROFILE_BYTES, authenticate_cms, completed_content, completion_frame,
)

from . import profile_process_fixture as fixture
from .profile_process_fixture import PAYLOAD_MUTATION_MODES, FixtureWorkspace, backpressure_case, run_case


@unittest.skipUnless(os.name == "posix", "release workers require POSIX process groups")
class ProfileProcessTests(unittest.TestCase):
    def setUp(self):
        fixture.assert_fixture_idle()

    def test_completion_frame_is_exact_bounded_nonempty_and_rejects_all_partial_results(self):
        payload = b"plausible-profile" + COMPLETION_MAGIC + COMPLETION_MARKER
        frame = completion_frame(payload)
        self.assertEqual(completed_content(frame), payload)
        largest = b"v" * MAX_PROFILE_BYTES
        self.assertEqual(completed_content(completion_frame(largest)), largest)
        for wrong in (b"", b"v" * (MAX_PROFILE_BYTES + 1), "not-bytes", bytearray(b"v")):
            with self.subTest(type=type(wrong)), self.assertRaises(ValidationError):
                completion_frame(wrong)
        malformed = [frame + b"x", frame * 2, b"x" + frame[1:], frame[:-1] + b"x", bytearray(frame)]
        malformed.extend(frame[:end] for end in range(len(frame)))
        malformed.extend(COMPLETION_MAGIC + size.to_bytes(4, "big") + payload + COMPLETION_MARKER
                         for size in (0, len(payload) - 1, len(payload) + 1, MAX_PROFILE_BYTES + 1, 0xffffffff))
        for index, wrong in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(ValidationError):
                completed_content(wrong)

    def test_expired_shared_deadline_never_starts_a_worker_or_creates_private_scratch(self):
        deadline = InspectionDeadline(); deadline._expires_at = 0
        with patch.object(owner.native, "create") as spawn, patch.object(ios_profiles.tempfile, "mkdtemp") as scratch:
            with self.assertRaisesRegex(ValidationError, "shared time bound"):
                authenticate_cms(b"profile", deadline=deadline)
        spawn.assert_not_called(); scratch.assert_not_called()

    def test_group_ownership_is_established_before_spawn_and_never_kills_someone_elses_group(self):
        # Numeric messages are not grants. A cancelled O admits neither K nor V;
        # a C-cancel before RUN owns/reaps K but truthfully records no V attempt.
        for mode in ("before-admit-cancel", "before-run-cancel"):
            fixture.assert_fixture_idle()
            with self.subTest(mode=mode), FixtureWorkspace() as workspace:
                result = run_case(workspace, mode)
                self.assertEqual(result["result"], "cancelled")
                self.assertTrue(result["deadBeforeFallback"] and result["scratchRemoved"])
                self.assertEqual(result["finality"], "FINALIZED")

    def test_success_and_custom_handlers_still_reap_live_descendants_and_keep_capabilities_out(self):
        for mode in ("success", "custom-handler"):
            fixture.assert_fixture_idle()
            with self.subTest(mode=mode), FixtureWorkspace() as workspace:
                result = run_case(workspace, mode)
                self.assertEqual(result["result"], "success")
                self.assertTrue(result["deadBeforeFallback"] and result["scratchRemoved"])
                # run_case binds real helper maps before grants, null-only V,
                # exact O/C/K waits, actual EOFs, close-once leases and task joins.
                self.assertTrue(result["realEOFAheadOfCommit"])

    def test_timeout_observes_a_real_orphaned_pipe_before_cleanup(self):
        with FixtureWorkspace() as workspace:
            result = run_case(workspace, "pipe-timeout")
            self.assertEqual(result["result"], "rejected")
            self.assertTrue(result["deadBeforeFallback"] and result["orphanPipeObserved"])
            self.assertEqual(result["finality"], "FINALIZED")
            self.assertTrue(result["scratchRemoved"] and result["noRetainedCustody"])
            # The live descendant is in G, but only Python C holds this writer;
            # V never inherits a payload writer merely to recreate an old test.

    def test_cancellation_during_spawn_registration_and_active_native_work_is_contained(self):
        for mode in ("spawn-return-cancel", "payload-register-cancel", "cancel",
                     *("completion-cancel", "completion-interrupt") * 3):
            fixture.assert_fixture_idle()
            with self.subTest(mode=mode), FixtureWorkspace() as workspace:
                result = run_case(workspace, mode)
                self.assertEqual(result["result"], "cancelled")
                self.assertTrue(result["deadBeforeFallback"] and result["scratchRemoved"])

    def test_parent_capture_deadline_still_overrides_a_complete_success_frame(self):
        with FixtureWorkspace() as workspace:
            result = run_case(workspace, "committed-timeout")
            self.assertEqual(result["result"], "rejected")
            self.assertTrue(result["deadBeforeFallback"] and result["scratchRemoved"])

    def test_failure_overflow_and_io_failure_reject_partial_content_without_leaking_workers(self):
        for mode in ("failure", "read-failure", "partial-write-failure", *sorted(PAYLOAD_MUTATION_MODES)):
            fixture.assert_fixture_idle()
            with self.subTest(mode=mode), FixtureWorkspace() as workspace:
                result = run_case(workspace, mode)
                self.assertEqual(result["result"], "rejected")
                self.assertTrue(result["deadBeforeFallback"])
                self.assertFalse(result["syntheticMalformedHelper"])
                self.assertEqual(result["finality"], "FINALIZED")
                self.assertTrue(result["scratchRemoved"] and result["noRetainedCustody"])
                if mode in PAYLOAD_MUTATION_MODES:
                    # These are actual C/K/V lifecycles, not missing-HELLO peers.
                    # The original O parser/overflow gate must reject the bytes.
                    self.assertTrue(result["scratchRemoved"])
                    self.assertEqual(result["payloadOverflowVeto"], mode == "overflow")
                    self.assertEqual(result["payloadParserRejected"], mode != "overflow")

    def _unknown_malformed_c(self, mode):
        with FixtureWorkspace() as workspace:
            result = run_case(workspace, mode)
            self.assertEqual(result["result"], "rejected")
            self.assertEqual(result["finality"], "UNKNOWN")
            self.assertTrue(result["syntheticMalformedHelper"] and result["deadBeforeFallback"])
            # A real malformed-C wait is not valid terminal no-K accounting.
            self.assertTrue(result["scratchRetained"] and result["retainedAfterGC"] and result["reuseRefused"])
            self.assertTrue(result["domainDisposalRequired"] and workspace.retained)
            self.assertFalse(result["scratchRemoved"] or result["noRetainedCustody"])

    def test_unknown_malformed_c_full_zero_retains_scratch(self):
        self._unknown_malformed_c("full-zero")

    def test_unknown_malformed_c_full_failure_retains_scratch(self):
        self._unknown_malformed_c("full-failure")

    def _unknown_parent_loss(self, mode):
        with FixtureWorkspace() as workspace:
            result = run_case(workspace, mode)
            self.assertEqual(result["finality"], "UNKNOWN")
            self.assertEqual(result["completionInterleavingReached"], mode != "orphan")
            self.assertTrue(result["workerGroupAbsent"] and result["hardKillScratchRemainsPrivate"])
            self.assertTrue(result["custodianWaitMissing"] and result["domainDisposalRequired"])
            self.assertTrue(result["scratchRetained"] and workspace.retained)
            # Existing K/V/G proofs do not establish C's physical cessation or
            # replace the lost original O-to-C wait with the fixture-driver wait.
            self.assertNotIn("deadBeforeFallback", result)

    def test_unknown_marker_parent_death_requires_domain_disposal(self):
        self._unknown_parent_loss("marker-parent-death")

    def test_unknown_committed_parent_death_requires_domain_disposal(self):
        self._unknown_parent_loss("committed-parent-death")

    def test_killed_ancestor_cannot_strand_independent_native_worker_group(self):
        self._unknown_parent_loss("orphan")

    def test_independent_supervisor_deadline_and_backpressure_kill_native_workers_without_inheriting_payload(self):
        with FixtureWorkspace() as workspace:
            result = run_case(workspace, "supervisor-timeout")
            self.assertEqual(result["result"], "rejected")
            self.assertTrue(result["deadBeforeFallback"])
            self.assertEqual(result["finality"], "FINALIZED")
            self.assertTrue(result["scratchRemoved"] and result["noRetainedCustody"])
        with FixtureWorkspace() as workspace:
            result = backpressure_case(workspace)
            self.assertEqual(result["result"], "rejected")
            self.assertTrue(result["deadBeforeFallback"] and result["backpressureObserved"])
            self.assertEqual(result["finality"], "FINALIZED")
            self.assertTrue(result["scratchRemoved"] and result["noRetainedCustody"])

    def test_commit_follows_actual_payload_eof_and_withheld_commit_cannot_deadlock_writer_close(self):
        for mode in ("commit-after-eof", "withhold-commit", "short-write"):
            fixture.assert_fixture_idle()
            with self.subTest(mode=mode), FixtureWorkspace() as workspace:
                result = run_case(workspace, mode)
                self.assertTrue(result["realEOFAheadOfCommit"] and result["deadBeforeFallback"])
                self.assertEqual(result["commitWithheld"], mode == "withhold-commit")
                self.assertEqual(result["result"], "rejected" if mode == "withhold-commit" else "success")
                self.assertEqual(result["finality"], "FINALIZED")
                self.assertTrue(result["scratchRemoved"] and result["noRetainedCustody"])
                self.assertLess(result["elapsed"], 12)


@unittest.skipUnless(os.name == "posix", "release workers require POSIX process groups")
class ProfileGroupCleanupTests(unittest.TestCase):
    def setUp(self):
        fixture.assert_fixture_idle()

    def test_only_real_esrch_retires_group_routing_not_permission_or_successful_delivery(self):
        # Fake-only syscall boundary. Persistent-exhaustion and unknown-wait
        # controls live with the actual owner unit tests, not retired Popen code.
        for outcomes in ((PermissionError(), ProcessLookupError()), (None, None, ProcessLookupError())):
            keeper = SimpleNamespace(pid=987654, numeric_retired=False)
            group = owner._GroupReservation(SimpleNamespace(role="custodian"), keeper)
            with self.subTest(outcomes=outcomes), patch.object(owner.os, "killpg", side_effect=outcomes) as kill:
                for index in range(len(outcomes)):
                    present = group.request(int(signal.SIGKILL))
                    self.assertEqual(present, index < len(outcomes) - 1)
                    self.assertEqual(group.retired, not present)
                    self.assertFalse(keeper.numeric_retired)
                self.assertTrue(group.absent)
                with self.assertRaises(ValidationError):
                    group.request(0)
            self.assertEqual(kill.call_count, len(outcomes))
            self.assertTrue(all(call.args == (keeper.pid, int(signal.SIGKILL)) for call in kill.call_args_list))

    def test_retired_mismatched_and_observer_mutated_routes_are_vetoed_before_numeric_syscall(self):
        for mutation in ("group-retired", "child-retired", "identity", "observer"):
            keeper = SimpleNamespace(pid=987654, numeric_retired=False)
            group = owner._GroupReservation(SimpleNamespace(role="custodian"), keeper)
            if mutation == "group-retired":
                group.retire(absent=False)
            elif mutation == "child-retired":
                keeper.numeric_retired = True
            elif mutation == "identity":
                keeper.pid += 1
            def observe(_role, event, **_evidence):
                if mutation == "observer" and event == "group_request":
                    keeper.numeric_retired = True
            with self.subTest(mutation=mutation), patch.object(owner, "_role_event", side_effect=observe), patch.object(owner.os, "killpg") as kill:
                with self.assertRaises(ValidationError):
                    group.request(0)
            kill.assert_not_called()
        for value in (-1, 1, True, "0"):
            keeper = SimpleNamespace(pid=987654, numeric_retired=False)
            group = owner._GroupReservation(SimpleNamespace(role="custodian"), keeper)
            with self.subTest(value=value), patch.object(owner.os, "killpg") as kill, self.assertRaises(ValidationError):
                group.request(value)
            kill.assert_not_called()
        for field in ("id", "retired", "absent"):
            with self.subTest(field=field), self.assertRaises(AttributeError):
                setattr(group, field, 0)

    def test_actual_zombie_is_observed_before_its_owning_keeper_consumes_the_wait(self):
        with FixtureWorkspace() as workspace:
            result = run_case(workspace, "zombie")
            self.assertEqual(result["result"], "success")
            self.assertTrue(result["zombieObserved"] and result["deadBeforeFallback"] and result["scratchRemoved"])

    def _unknown_payload_close(self, mode):
        with FixtureWorkspace() as workspace:
            result = run_case(workspace, mode)
            self.assertEqual(result["result"], "rejected")
            self.assertEqual(result["finality"], "UNKNOWN")
            self.assertTrue(result["deadBeforeFallback"] and result["scratchRetained"])
            self.assertTrue(result["retainedAfterGC"] and result["reuseRefused"])
            self.assertTrue(result["domainDisposalRequired"] and workspace.retained)
            self.assertFalse(result["scratchRemoved"] or result["noRetainedCustody"])

    def test_unknown_payload_writer_close_failure_retains_scratch(self):
        self._unknown_payload_close("payload-writer-close-failure")

    def test_unknown_payload_reader_close_failure_retains_scratch(self):
        self._unknown_payload_close("payload-reader-close-failure")

    def test_unknown_payload_reader_close_unresolved_retains_scratch(self):
        self._unknown_payload_close("payload-reader-close-unresolved")


class ProfileFixtureBookkeepingTests(unittest.TestCase):
    """Fake-only negative controls of fixture bookkeeping, never native proof."""

    def setUp(self):
        fixture.assert_fixture_idle()
        # No driver construction, original wait, creator start or native call is
        # allowed while testing the fixture's own failure bookkeeping.
        for target, name in ((fixture.subprocess, "Popen"), (owner.native, "create"),
                             (owner.native, "assert_child_waitability"), (owner.native.Child, "poll_wait"),
                             (owner.threading.Thread, "start"), (fixture.os, "fork"),
                             (fixture.os, "kill"), (fixture.os, "killpg"), (fixture.os, "waitpid")):
            trap = self.enterContext(patch.object(target, name,
                                                  side_effect=AssertionError("fake-only bookkeeping acquired a resource"), create=True))
            self.addCleanup(trap.assert_not_called)

    def test_driver_roots_an_unknown_stream_after_receipt_and_never_replays_its_close(self):
        calls = []
        class Stream:
            def __init__(self, name):
                self.name = name
            def close(self):
                calls.append(self.name)
                if self.name == "stdout":
                    raise OSError("modeled stream close publication loss")

        stdout, stderr = Stream("stdout"), Stream("stderr")
        driver = fixture.FixtureDriver.__new__(fixture.FixtureDriver)
        driver.process = SimpleNamespace(stdout=stdout, stderr=stderr)
        driver.receipt = object()  # A model ONLY; never passed to a finality oracle.
        driver.requests_retired, driver.wait_unknown = True, False
        driver._signals = set()
        driver.stream_states = {"stdout": "OPEN", "stderr": "OPEN"}
        driver.stream_eof = {"stdout": True, "stderr": True}
        custody = []
        with patch.object(fixture, "_UNKNOWN_DRIVERS", custody), \
             patch.object(fixture, "_FIXTURE_ADVERSE", []), patch.object(fixture, "_DRIVER_CUSTODY", []):
            with self.assertRaisesRegex(AssertionError, "fixture controller cleanup is unresolved"):
                driver.__exit__(None, None, None)
            self.assertEqual(driver.stream_states, {"stdout": "UNKNOWN", "stderr": "CLOSED"})
            self.assertEqual(custody, [driver])
            driver_ref, stream_ref = weakref.ref(driver), weakref.ref(stdout)
            del driver, stdout, stderr
            gc.collect()
            self.assertIsNotNone(driver_ref())
            self.assertIs(stream_ref(), driver_ref().process.stdout)
            self.assertFalse(driver_ref().__exit__(ValueError, ValueError("body"), None))
            self.assertEqual(calls, ["stdout", "stderr"])
            self.assertEqual(len(custody), 1)
            with patch.object(fixture.tempfile, "mkdtemp", side_effect=AssertionError("poisoned fixture acquired another root")) as temporary:
                with self.assertRaisesRegex(AssertionError, "Session disposal"):
                    FixtureWorkspace()
                with self.assertRaisesRegex(AssertionError, "Session disposal"):
                    fixture.FixtureDriver(["inert"])
                temporary.assert_not_called()

        for module, name in ((ios_profiles, "_PROFILE_SCRATCH_LEASES"),
                             (ios_profiles, "_PROFILE_RESOURCE_SCOPES"), (owner, "_CUSTODY")):
            # Inert registry entries: even an unfinished/unpublished record
            # must veto another acquisition, and restoring a registry is not
            # a reset of the already-latched adverse fixture domain.
            model = object()
            with self.subTest(registry=name), patch.object(fixture, "_FIXTURE_ADVERSE", []) as adverse:
                with patch.object(module, name, [model]):
                    with self.assertRaisesRegex(AssertionError, "Session disposal"):
                        fixture.assert_fixture_idle()
                self.assertEqual(adverse, [model])
                with self.assertRaisesRegex(AssertionError, "Session disposal"):
                    fixture.assert_fixture_idle()

        def inert_driver():
            result = fixture.FixtureDriver.__new__(fixture.FixtureDriver)
            result.process = SimpleNamespace(pid=101, returncode=None)
            result.requests_retired, result.wait_unknown = False, False
            result.receipt, result._finish_cutoff = None, 5
            result._signals = set()
            result.stream_states = {name: "CLOSED" for name in ("stdout", "stderr")}
            result.stream_eof = {name: False for name in ("stdout", "stderr")}
            return result

        # These are inert wait doubles, not evidence of an OS child receipt.
        driver = inert_driver()
        returns = iter(((0, 0), (101, 0)))
        def original_wait(pid, options):
            self.assertTrue(driver.requests_retired)
            return next(returns)
        with patch.object(fixture.os, "waitpid", side_effect=original_wait) as wait, \
             patch.object(fixture.time, "monotonic", return_value=0), patch.object(fixture.time, "sleep") as sleep:
            self.assertEqual(driver._wait(cutoff=5), (101, 0))
            self.assertEqual(driver._wait(cutoff=99), (101, 0))
            self.assertEqual([call.args for call in wait.call_args_list], [(101, os.WNOHANG)] * 2)
            sleep.assert_called_once_with(.01)

        # Inert fallback wait/close doubles: neither a receipt nor closing both
        # streams may stand in for missing original EOF observations.
        for stdout_eof, stderr_eof in ((False, False), (True, False), (False, True), (True, True)):
            driver = inert_driver()
            driver._finish_cutoff = None
            driver.stream_states = {name: "OPEN" for name in ("stdout", "stderr")}
            driver.stream_eof = {"stdout": stdout_eof, "stderr": stderr_eof}
            closed = []
            driver.process.stdout = SimpleNamespace(close=lambda: closed.append("stdout"))
            driver.process.stderr = SimpleNamespace(close=lambda: closed.append("stderr"))
            with self.subTest(stdout_eof=stdout_eof, stderr_eof=stderr_eof), \
                 patch.object(fixture, "_UNKNOWN_DRIVERS", []) as unknown, \
                 patch.object(fixture, "_FIXTURE_ADVERSE", []) as adverse, \
                 patch.object(fixture, "_DRIVER_CUSTODY", [driver]) as custody, \
                 patch.object(fixture.os, "waitpid", return_value=(101, 0)) as wait, \
                 patch.object(fixture.time, "monotonic", return_value=0), \
                 patch.object(driver, "request_signal") as signal_request:
                if stdout_eof and stderr_eof:
                    self.assertFalse(driver.__exit__(None, None, None))
                    self.assertEqual((custody, unknown, adverse), ([], [], []))
                else:
                    with self.assertRaisesRegex(AssertionError, "fixture controller cleanup is unresolved"):
                        driver.__exit__(None, None, None)
                    for roots in (custody, unknown, adverse):
                        self.assertIn(driver, roots)
                    self.assertFalse(driver.__exit__(ValueError, ValueError("original body error"), None))
                self.assertEqual(driver.receipt, (101, 0))
                self.assertTrue(driver.requests_retired)
                self.assertEqual(driver._finish_cutoff, 3)
                self.assertEqual(driver.stream_eof, {"stdout": stdout_eof, "stderr": stderr_eof})
                self.assertEqual(driver.stream_states, {"stdout": "CLOSED", "stderr": "CLOSED"})
                self.assertEqual(closed, ["stdout", "stderr"])
                wait.assert_called_once_with(101, os.WNOHANG)
                signal_request.assert_called_once_with(signal.SIGKILL)

        for publication in (None, (102, 0), (0, 1), (101, 127), OSError("modeled lost wait return"), "expired", "pid0-cutoff"):
            driver = inert_driver()
            result = (0, 0) if publication == "pid0-cutoff" else publication
            with self.subTest(publication=publication), patch.object(fixture, "_UNKNOWN_DRIVERS", []), \
                 patch.object(fixture, "_FIXTURE_ADVERSE", []), patch.object(fixture, "_DRIVER_CUSTODY", []), \
                 patch.object(fixture.os, "waitpid", return_value=result,
                              side_effect=publication if isinstance(publication, BaseException) else None) as wait, \
                 patch.object(fixture.time, "monotonic", side_effect=[0, 5] if publication == "pid0-cutoff" else None,
                              return_value=5 if publication == "expired" else 0), \
                 patch.object(driver, "request_signal", side_effect=AssertionError("retired route reopened")) as signal_request:
                with self.assertRaises((AssertionError, OSError)):
                    driver._wait(cutoff=99)  # Must still be capped by original5.
                self.assertTrue(driver.requests_retired and driver.wait_unknown)
                self.assertIn(driver, fixture._UNKNOWN_DRIVERS)
                self.assertIn(driver, fixture._FIXTURE_ADVERSE)
                attempts = wait.call_count
                self.assertEqual(attempts, 0 if publication == "expired" else 1)
                with self.assertRaises(AssertionError):
                    driver._wait(cutoff=99)
                self.assertFalse(driver.__exit__(ValueError, ValueError("original body error"), None))
                self.assertEqual(wait.call_count, attempts)
                signal_request.assert_not_called()

        # finish must consume actual bytes-empty from BOTH original streams
        # before its sole admitted wait. No observer or selector is real here.
        class Selector:
            def __init__(self):
                self.pending = {}
            def __enter__(self):
                return self
            def __exit__(self, *error):
                return False
            def register(self, stream, events, name):
                self.pending[name] = SimpleNamespace(fd=stream.fileno(), fileobj=stream, data=name)
            def get_map(self):
                return self.pending
            def select(self, timeout):
                return [(key, None) for key in tuple(self.pending.values())]
            def unregister(self, stream):
                name = next(name for name, key in self.pending.items() if key.fileobj is stream)
                del self.pending[name]

        driver = inert_driver()
        driver._finish_cutoff = None
        driver.process.stdout = SimpleNamespace(fileno=lambda: 10)
        driver.process.stderr = SimpleNamespace(fileno=lambda: 11)
        driver.stream_eof = {name: False for name in ("stdout", "stderr")}
        def at_wait(*, cutoff):
            self.assertEqual(cutoff, 5)
            self.assertEqual(driver.stream_eof, {"stdout": True, "stderr": True})
            self.assertTrue(driver.requests_retired)
        with patch.object(fixture.selectors, "DefaultSelector", return_value=Selector()), \
             patch.object(fixture.os, "set_blocking"), patch.object(fixture.os, "read", return_value=b"") as read, \
             patch.object(fixture.time, "monotonic", return_value=0), patch.object(driver, "_wait", side_effect=at_wait) as wait, \
             patch.object(fixture, "process_state", side_effect=AssertionError("finish launched another observer")) as observe:
            self.assertEqual(driver.finish(timeout=5), (b"", b""))
            self.assertEqual([call.args for call in read.call_args_list], [(10, 65536), (11, 65536)])
            wait.assert_called_once_with(cutoff=5)
            observe.assert_not_called()

    def test_partial_binding_entry_restores_prior_and_changed_targets_preserving_the_first_error(self):
        real_patch = patch.object
        original_helper, original_worker = owner.helper_argv, owner._worker_argv
        for restoration_error in (False, True):
            custody, installed, restored = [], [], []
            first_error = SystemExit(47)
            cleanup_error = OSError("modeled restoration publication loss")
            def installing(target, name, implementation):
                patcher = real_patch(target, name, implementation)
                class PartialPatch:
                    def __enter__(self):
                        result = patcher.__enter__()
                        installed.append(name)
                        if len(installed) == 2:
                            raise first_error  # The target REALLY changed before this lost return.
                        return result
                    def __exit__(self, *error):
                        restored.append(name)
                        result = patcher.__exit__(*error)
                        if restoration_error and name == "_worker_argv":
                            raise cleanup_error  # Real restoration happened; never replay uncertainty.
                        return result
                return PartialPatch()

            binding = fixture.ProfileBindings(None, "success")
            with self.subTest(restoration_error=restoration_error), real_patch(fixture, "_BINDING_CUSTODY", custody), real_patch(fixture.patch, "object", installing):
                with self.assertRaises(SystemExit) as raised:
                    binding.__enter__()
                self.assertIs(raised.exception, first_error)
                self.assertIs(owner.helper_argv, original_helper)
                self.assertIs(owner._worker_argv, original_worker)
                self.assertEqual(installed, ["helper_argv", "_worker_argv"])
                self.assertEqual(restored, ["_worker_argv", "helper_argv"])
                if restoration_error:
                    self.assertEqual(binding.patch_state, "UNKNOWN")
                    self.assertEqual(binding._patch_errors, [cleanup_error])
                    self.assertEqual(custody, [binding])
                    binding_ref = weakref.ref(binding)
                    # Clear the test exception's traceback, not a product error:
                    # its frames must not impersonate the fixture's strong root.
                    first_error.__traceback__ = cleanup_error.__traceback__ = None
                    del binding
                    gc.collect()
                    self.assertIsNotNone(binding_ref())
                    self.assertFalse(binding_ref().__exit__(SystemExit, first_error, None))
                else:
                    self.assertEqual(binding.patch_state, "CLOSED")
                    self.assertEqual(custody, [])
                    self.assertFalse(binding.__exit__(None, None, None))
                self.assertEqual(restored, ["_worker_argv", "helper_argv"])

    def test_modeled_reaped_and_joined_flags_without_original_operation_returns_are_rejected(self):
        binding = fixture.ProfileBindings(None, "success")
        receipt = SimpleNamespace(pid=987654, status_kind="exit", status_code=0)
        child = SimpleNamespace(pid=receipt.pid, receipt=receipt, wait_state="REAPED", numeric_retired=True)
        thread = SimpleNamespace(is_alive=lambda: False)
        task = SimpleNamespace(child_role="custodian", acquisition=SimpleNamespace(child=child),
                               actual=thread, joined=True, body_done=True)
        binding.tasks[id(task)] = task
        binding.children["custodian"] = child
        with patch.object(binding, "log", side_effect=AssertionError("invented evidence reached the fixture log")) as log:
            with self.assertRaisesRegex(AssertionError, "original Child.poll_wait return"):
                binding.observe("outer", "custodian_reaped", receipt=receipt)
            with self.assertRaisesRegex(AssertionError, "original Thread.join return"):
                binding.observe("outer", "task_joined", task=task)
        log.assert_not_called()
        self.assertEqual(binding.wait_witnesses, {})
        self.assertEqual(binding.join_witnesses, {})
        # A first poll returning pid0 would leave no reaped-event witness.
        # Reject unretired/missing/mismatched group routes BEFORE the captured
        # original operation (the setUp trap), not after an apparent receipt.
        for route in ("missing", "unretired", "mismatched"):
            unwaited = SimpleNamespace(pid=987654, wait_state="OWNED", numeric_retired=True)
            binding = fixture.ProfileBindings(None, "success", "custodian")
            if route != "missing":
                binding.group = SimpleNamespace(id=unwaited.pid, keeper=object() if route == "mismatched" else unwaited,
                                                retired=route == "mismatched")
            with self.subTest(route=route), binding:
                with self.assertRaisesRegex(AssertionError, "keeper poll preceded its exact group retirement"):
                    owner.native.Child.poll_wait(unwaited)
            self.assertEqual(binding.patch_state, "CLOSED")
            self.assertEqual(binding.wait_witnesses, {})


if __name__ == "__main__":
    unittest.main()
