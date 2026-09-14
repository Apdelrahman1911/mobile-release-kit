"""Original launcher loss stays UNKNOWN despite positive A/W cleanup witnesses."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sys
import unittest
from types import SimpleNamespace

import mobile_release
from mobile_release import _native_process  # Preload before intentional UNKNOWN.

from . import local_signing_launcher_loss_fixture as fixture
from .profile_process_fixture import FixtureDriver, FixtureWorkspace


class SigningLauncherLossTests(unittest.TestCase):
    def test_real_launcher_death_uses_original_anchor_cleanup_and_requires_domain_disposal(self):
        # Literal poison singleton only: no native/process invocation on a shared
        # host. The existing outside-identity Session owns the final disposal.
        with FixtureWorkspace(prefix="mrk-signing-launcher-loss-") as workspace:
            root, root_identity = workspace.path, workspace._identity
            package_root = Path(mobile_release.__file__).resolve().parent.parent
            native_origin = Path(_native_process.__file__).resolve()
            self.assertEqual(native_origin.parent, package_root / "mobile_release")
            argv = (sys.executable, "-I", "-S", "-B", str(Path(fixture.__file__).resolve()), str(package_root), str(root))
            environment = {"PATH": "/usr/bin:/bin", "TMPDIR": str(root), "TMP": str(root), "TEMP": str(root)}
            with FixtureDriver(argv, env=environment) as driver:
                workspace.retain()  # Immediately; root was already removal-disallowed.
                launcher = driver.process.pid
                stdout, stderr = driver.finish(timeout=12)
            # Only original captured bytes and already-owned object/scalar state
            # after retention: no new import, path resolution, census or owner.
            self.assertEqual(driver.process.returncode, 73)
            self.assertEqual(driver.receipt[0], launcher)
            self.assertEqual(os.waitstatus_to_exitcode(driver.receipt[1]), 73)
            self.assertTrue(all(driver.stream_eof.values()))
            self.assertEqual(set(driver.stream_states.values()), {"CLOSED"})
            self.assertTrue(driver.requests_retired)
            self.assertFalse(driver.wait_unknown)
            result = fixture.validate_events(stdout, stderr, launcher)
            self.assertEqual(result["finality"], "UNKNOWN")
            self.assertFalse(result["originalAnchorWait"])
            self.assertTrue(result["originalWorkerWait"] and result["originalWorkerStatusEOF"]
                            and result["groupAbsentWhileReserved"] and result["domainDisposalRequired"])
            self.assertTrue(workspace.retained)
            self.assertFalse(workspace.removal_allowed)
            # This is retained scalar custody, NOT a post-loss filesystem proof.
            self.assertEqual(workspace._identity, root_identity)


def _events():
    rows = []
    def add(role, event, **fields):
        rows.append({"role": role, "event": event, "pid": {"L": 30, "A": 31, "W": 32}[role], **fields})
    add("A", "held_writer", launcher=30, home_group=30)
    add("W", "inherited_writer_closed", anchor=31, group=31)
    add("L", "run_sent", before_deadline=True)
    add("A", "worker_run", worker=32, group=31)
    add("W", "started", anchor=31, before_deadline=True)
    add("L", "readiness", exact_frame=True, eof=True, readiness_closed=True, anchor_wait_attempted=False, before_deadline=True)
    add("A", "parent_loss", launcher=30, observed_parent=1, held_writer=True, before_deadline=True)
    add("A", "group_signal", group=31, signal=int(signal.SIGKILL), outside=True, before_deadline=True)
    add("A", "worker_wait", worker=32, exitcode=-int(signal.SIGKILL), terminal=True)
    add("A", "worker_eof", worker=32)
    add("A", "group_absent", group=31, reserved=True, outside=True, before_deadline=True)
    add("A", "exit_attempt", exitAttemptCode=0, original_group_retired=True, production_handles_closed=True, extra_writer_closed=True,
        readiness_closed=True, before_deadline=True)
    return rows


def _encode(rows):
    return b"".join(json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
                    for row in rows)


class SigningLauncherLossObservationTests(unittest.TestCase):
    def test_captured_oracle_rejects_missing_misbound_nonloss_and_laundered_finality(self):
        baseline = _events()
        result = fixture.validate_events(_encode(baseline), b"", 30)
        self.assertEqual(result["finality"], "UNKNOWN")
        self.assertFalse(result["originalAnchorWait"])
        # Kernel scheduling may reverse actual W wait and W-status EOF.
        reversed_wait_eof = baseline[:]
        reversed_wait_eof[8:10] = reversed(reversed_wait_eof[8:10])
        self.assertEqual(fixture.validate_events(_encode(reversed_wait_eof), b"", 30), result)
        for event, field, value in (("parent_loss", "observed_parent", 30), ("parent_loss", "held_writer", False),
                                    ("parent_loss", "before_deadline", False), ("group_signal", "group", 32),
                                    ("worker_wait", "exitcode", 0), ("worker_wait", "worker", 99),
                                    ("exit_attempt", "exitAttemptCode", 91), ("exit_attempt", "exitAttemptCode", False),
                                    ("exit_attempt", "original_group_retired", False),
                                    ("exit_attempt", "production_handles_closed", False),
                                    ("readiness", "anchor_wait_attempted", True), ("readiness", "eof", False)):
            rows = [dict(row) for row in baseline]
            next(row for row in rows if row["event"] == event)[field] = value
            with self.subTest(event=event, field=field), self.assertRaises(AssertionError):
                fixture.validate_events(_encode(rows), b"", 30)
        premature_absence = baseline[:]
        premature_absence[8], premature_absence[10] = premature_absence[10], premature_absence[8]
        wrong_route = baseline + [{"role": "A", "event": "control_route", "pid": 31, "route": "eof"}]
        invalid = [_encode(baseline[:-1]), _encode(baseline + baseline[-1:]), _encode(baseline)[:-1],
                   _encode(premature_absence), _encode(wrong_route), b"x" * (fixture.MAX_EVENTS * fixture.MAX_EVENT_BYTES + 1)]
        for stdout in invalid:
            with self.subTest(length=len(stdout)), self.assertRaises(AssertionError):
                fixture.validate_events(stdout, b"", 30)
        with self.assertRaises(AssertionError):
            fixture.validate_events(_encode(baseline), b"unexpected", 30)
        with self.assertRaises(AssertionError):
            fixture.validate_events(_encode(baseline), b"", 99)

    def test_anchor_observation_failure_cannot_replace_requested_exit_or_unwind(self):
        calls = []
        class Exited(BaseException):
            pass
        def real_exit(code):
            calls.append(code)
            raise Exited
        def failed_observation(code, *, original_group_retired):
            raise OSError("inert observation failure")
        observation = SimpleNamespace(role="A", real_exit=real_exit, anchor_exit=failed_observation,
                                      real_anchor=self.test_anchor_observation_failure_cannot_replace_requested_exit_or_unwind)
        for origin in (observation.real_anchor, failed_observation):
            observation.real_anchor = origin
            for code in (0, fixture.owner.WORKER_ERROR):
                with self.assertRaises(Exited):
                    fixture._ObservedOS(observation)._exit(code)
        self.assertEqual(calls, [0, fixture.owner.WORKER_ERROR] * 2)

    def test_launcher_wait_observation_preserves_original_return_and_failure_before_cutoff(self):
        slot, returned, original_error = object(), object(), ChildProcessError("inert lost wait")
        calls = []
        def real_wait(actual):
            calls.append(actual)
            if len(calls) == 2:
                raise original_error
            return returned
        # No initialized cutoff/emit method: neither is needed to retain the
        # attempted latch and transparently execute the actual original wait.
        observation = SimpleNamespace(role="L", hard=None, launcher_waited=False, real_wait=real_wait)
        self.assertIs(fixture._Observation.wait(observation, slot), returned)
        self.assertTrue(observation.launcher_waited)
        with self.assertRaises(ChildProcessError) as raised:
            fixture._Observation.wait(observation, slot)
        self.assertIs(raised.exception, original_error)
        self.assertEqual(calls, [slot, slot])
