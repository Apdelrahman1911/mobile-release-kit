"""Native-profile credential/cancellation boundary, with real process cleanup."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline
from mobile_release.ios_profile_auth import supervise
from mobile_release import ios_profiles
from mobile_release.ios_profiles import (
    COMPLETION_MAGIC, COMPLETION_MARKER, MAX_PROFILE_BYTES, authenticate_cms, completed_content, completion_frame,
)

from .profile_process_fixture import backpressure_case, kill_owned_group, run_case
from .process_fixture import process_state


@unittest.skipUnless(os.name == "posix", "release workers require POSIX process groups")
class ProfileProcessTests(unittest.TestCase):
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
        with patch("mobile_release.ios_profiles.subprocess.Popen") as spawn, patch("mobile_release.ios_profiles.tempfile.TemporaryDirectory") as scratch:
            with self.assertRaisesRegex(ValidationError, "shared time bound"):
                authenticate_cms(b"profile", deadline=deadline)
        spawn.assert_not_called(); scratch.assert_not_called()

    def test_group_ownership_is_established_before_spawn_and_never_kills_someone_elses_group(self):
        with patch("mobile_release.ios_profile_auth.os.getpgrp", return_value=-1), patch("mobile_release.ios_profile_auth.subprocess.Popen") as spawn, patch("mobile_release.ios_profile_auth.os.killpg") as kill:
            self.assertEqual(supervise(Path("/unused"), os.getpid()), 1)
        spawn.assert_not_called(); kill.assert_not_called()

    def test_success_and_custom_handlers_still_reap_live_descendants_and_keep_capabilities_out(self):
        for mode in ("success", "custom-handler"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
                result = run_case(Path(root), mode)
                self.assertEqual(result["result"], "success")
                self.assertTrue(result["deadBeforeFallback"] and result["scratchRemoved"])

    def test_timeout_observes_a_real_orphaned_pipe_before_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
            result = run_case(Path(root), "pipe-timeout")
        self.assertTrue(result["deadBeforeFallback"] and result["orphanPipeObserved"])

    def test_cancellation_during_spawn_registration_and_active_native_work_is_contained(self):
        for mode in ("popen-cancel", "register-cancel", "cancel", *("completion-cancel", "completion-interrupt") * 3):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
                result = run_case(Path(root), mode)
                self.assertEqual(result["result"], "cancelled")
                self.assertTrue(result["deadBeforeFallback"] and result["scratchRemoved"])

    def test_parent_capture_deadline_still_overrides_a_complete_success_frame(self):
        with tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
            result = run_case(Path(root), "committed-timeout")
        self.assertEqual(result["result"], "rejected")
        self.assertTrue(result["deadBeforeFallback"] and result["scratchRemoved"])

    def test_failure_overflow_and_io_failure_reject_partial_content_without_leaking_workers(self):
        for mode in ("failure", "overflow", "read-failure", "partial-marker", "full-zero", "full-failure", "extra-frame", "concatenated-frame"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
                result = run_case(Path(root), mode)
                self.assertEqual(result["result"], "rejected")
                self.assertTrue(result["deadBeforeFallback"] and result["scratchRemoved"])

    def test_actual_supervisor_retains_cleanup_ownership_before_and_after_success_commit_if_parent_dies(self):
        for mode in ("marker-parent-death", "committed-parent-death"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
                result = run_case(Path(root), mode)
                self.assertTrue(result["completionInterleavingReached"])
                self.assertTrue(result["deadBeforeFallback"] and result["hardKillScratchRemainsPrivate"])

    def test_killed_ancestor_cannot_strand_independent_native_worker_group(self):
        with tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
            result = run_case(Path(root), "orphan")
        self.assertTrue(result["deadBeforeFallback"] and result["hardKillScratchRemainsPrivate"])

    def test_independent_supervisor_deadline_and_backpressure_kill_inherited_native_workers(self):
        with tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
            result = run_case(Path(root), "supervisor-timeout")
        self.assertTrue(result["deadBeforeFallback"])
        with tempfile.TemporaryDirectory(prefix="mrk-profile-process-") as root:
            result = backpressure_case(Path(root))
        self.assertTrue(result["deadBeforeFallback"] and result["backpressureObserved"])


@unittest.skipUnless(os.name == "posix", "release workers require POSIX process groups")
class ProfileGroupCleanupTests(unittest.TestCase):
    def test_cleanup_requires_group_absence_and_reaped_leader_not_merely_signal_delivery(self):
        for outcomes in ([PermissionError(), ProcessLookupError()], [None, None, ProcessLookupError()]):
            process = SimpleNamespace(pid=987654, returncode=None)
            def wait(*, timeout):
                self.assertGreater(timeout, 0)
                self.assertLessEqual(timeout, 0.05)
                process.returncode = -signal.SIGKILL
            process.wait = Mock(side_effect=wait)
            with self.subTest(outcomes=outcomes), patch.object(ios_profiles.os, "killpg", side_effect=outcomes) as kill, patch.object(ios_profiles, "time", SimpleNamespace(monotonic=lambda: 0, sleep=lambda delay: None)):
                ios_profiles._reap_profile_group(process)
            self.assertEqual(kill.call_count, len(outcomes))  # Stop at ESRCH, never earlier/later.
            self.assertEqual(process.wait.call_count, len(outcomes))
            self.assertTrue(all(call.args == (process.pid, signal.SIGKILL) for call in kill.call_args_list))

    def test_persistent_permission_present_group_and_wait_errors_are_bounded_explicit_failure(self):
        for error, result in ((PermissionError(), -signal.SIGKILL), (None, -signal.SIGKILL),
                              (OSError("private-canary"), -signal.SIGKILL), (ProcessLookupError(), None)):
            process = SimpleNamespace(pid=987654, returncode=result,
                                      wait=Mock(side_effect=subprocess.TimeoutExpired("fixed", .05) if result is None else None))
            with self.subTest(error=error, result=result), patch.object(ios_profiles.os, "killpg", side_effect=error) as kill, patch.object(ios_profiles, "CLEANUP_RETRIES", 3), patch.object(ios_profiles, "time", SimpleNamespace(monotonic=lambda: 0, sleep=lambda delay: None)):
                with self.assertRaisesRegex(ValidationError, "cleanup could not be confirmed") as raised:
                    ios_profiles._reap_profile_group(process)
                self.assertNotIn("private-canary", str(raised.exception))
            self.assertLessEqual(kill.call_count, 3)
            if isinstance(error, ProcessLookupError):
                self.assertEqual(kill.call_count, 1)  # Even an unreaped leader cannot authorize another signal.
        process = SimpleNamespace(pid=987654, returncode=None, wait=Mock(side_effect=OSError("private-canary")))
        with patch.object(ios_profiles.os, "killpg"), self.assertRaisesRegex(ValidationError, "cleanup could not be confirmed"):
            ios_profiles._reap_profile_group(process)

    def test_actual_zombie_group_is_reaped_and_absent_after_cleanup(self):
        for descendant in (False, True):
            script = ("import os,signal,time; "
                      + ("child=os.fork(); time.sleep(10) if child==0 else None; " if descendant else "")
                      + "os.killpg(os.getpgrp(),signal.SIGKILL)")
            process = subprocess.Popen([sys.executable, "-I", "-S", "-c", script], start_new_session=True,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                # Observe without wait/poll: leave our own leader a zombie so the
                # macOS EPERM path is real, not a mocked permission failure.
                limit = time.monotonic() + 5
                while True:
                    state = process_state(process.pid, group=process.pid, deadline=limit)
                    if state == "zombie":
                        break
                    self.assertNotEqual(state, "absent", "unreaped child disappeared before zombie observation")
                    self.assertLess(time.monotonic(), limit, "owned child never reached zombie state")
                    time.sleep(.01)
                if sys.platform == "darwin":
                    with self.assertRaises(PermissionError):
                        os.killpg(process.pid, signal.SIGKILL)
                ios_profiles._reap_profile_group(process)
                self.assertEqual(process.returncode, -signal.SIGKILL)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process.pid, 0)
            finally:
                kill_owned_group(process.pid, process=process)
                process.wait(timeout=3)

    def test_complete_frame_cannot_escape_cleanup_failure_and_stream_handlers_are_still_closed_restored(self):
        frame = completion_frame(b"fictional-verified-payload")
        command = [sys.executable, "-I", "-S", "-c",
                   f"import os,signal; os.write(1,bytes.fromhex('{frame.hex()}')); os.killpg(os.getpgrp(),signal.SIGKILL)"]
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        real_spawn = subprocess.Popen
        for mode in ("permission", "close"):
            launched, streams = [], []
            def spawn(*args, **kwargs):
                process = real_spawn(*args, **kwargs)
                launched.append(process); streams.append(process.stdout)
                if mode == "close":
                    stream = process.stdout
                    class FailingClose:
                        def fileno(self): return stream.fileno()
                        def close(self):
                            stream.close()
                            raise OSError("private-canary")
                    process.stdout = FailingClose()
                return process
            try:
                with self.subTest(mode=mode), tempfile.TemporaryDirectory() as name, patch.object(ios_profiles, "worker_command", return_value=command), patch.object(ios_profiles.subprocess, "Popen", side_effect=spawn), patch.object(ios_profiles, "CLEANUP_RETRIES", 2):
                    permission = patch.object(ios_profiles.os, "killpg", side_effect=PermissionError()) if mode == "permission" else patch.object(ios_profiles, "CAPTURE_SECONDS", 30)
                    with permission, self.assertRaisesRegex(ValidationError, "cleanup could not be confirmed") as raised:
                        ios_profiles._capture_profile(Path(name), InspectionDeadline())
                    self.assertNotIn("private-canary", str(raised.exception))
                self.assertEqual({sig: signal.getsignal(sig) for sig in before}, before)
                self.assertTrue(all(stream.closed for stream in streams))
                self.assertTrue(all(process.returncode == -signal.SIGKILL for process in launched))
            finally:
                for process in launched:
                    kill_owned_group(process.pid, process=process)
                    process.wait(timeout=3)
                for stream in streams:
                    stream.close()


if __name__ == "__main__":
    unittest.main()
