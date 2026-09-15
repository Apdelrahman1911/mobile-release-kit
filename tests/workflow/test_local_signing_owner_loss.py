"""Original launcher loss stays UNKNOWN despite positive A/W cleanup witnesses."""
from __future__ import annotations

import ast
import json
import math
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


class InheritedForkFixtureContractTests(unittest.TestCase):
    """Actual small helper definitions with inert clock/wait/context inputs only."""

    class Clock:
        def __init__(self):
            self.now, self.sleeps = 100.0, []

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.sleeps.append(seconds)
            self.now += seconds

    def helpers(self, clock, waiting=None):
        def forbidden_wait(*args):
            raise AssertionError("inert wait was not supplied")
        namespace = {"math": math, "time": clock,
                     "os": SimpleNamespace(waitpid=waiting or forbidden_wait, WNOHANG=1,
                                           waitstatus_to_exitcode=lambda status: status // 256),
                     "case_owner": SimpleNamespace(CASE_DEADLINE=None),
                     "worker_timeout": lambda name: {"account-native-flow": 120}[name]}
        root = Path(__file__).resolve().parents[1]
        for path, names in (
                (root / "workflow/local_signing_fork_fixture.py",
                 {"_remaining", "_wait_released", "reap", "_exit_context", "_cleanup"}),
                (root / "unit/test_local_signing_native.py", {"_inherited_cutoff", "_inherited_timeout"})):
            tree = ast.parse(path.read_bytes(), filename=str(path))
            selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
            self.assertEqual({node.name for node in selected}, names)
            self.assertEqual(len(selected), len(names))
            self.assertTrue(all(not node.decorator_list for node in selected))
            # Never import the raw fixture/native unittest graph or execute its
            # entrypoint, class bodies, original OS module or resource setup.
            exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
        return namespace

    def test_caller_cutoff_caps_original_budget_and_capture_uses_remaining(self):
        clock = self.Clock()
        helpers = self.helpers(clock)
        self.assertEqual(helpers["_inherited_cutoff"](), 220.0)
        helpers["case_owner"].CASE_DEADLINE = 108.9
        cutoff = helpers["_inherited_cutoff"]()
        self.assertEqual(cutoff, 108.9)
        clock.now = 101.1
        self.assertEqual(helpers["_inherited_timeout"](cutoff), 7)
        for invalid in (float("inf"), float("nan"), 110, "110"):
            helpers["case_owner"].CASE_DEADLINE = invalid
            with self.subTest(invalid=invalid), self.assertRaises(AssertionError):
                helpers["_inherited_cutoff"]()
        for expired in (101.1, 101.9, 99.0):
            with self.subTest(expired=expired), self.assertRaises(AssertionError):
                helpers["_inherited_timeout"](expired)

    def test_release_wait_requires_timely_observation_without_short_timer_or_renewal(self):
        clock = self.Clock()
        helpers = self.helpers(clock)
        helpers["_wait_released"](SimpleNamespace(exists=lambda: clock.now >= 105.0), 109.0)
        self.assertGreaterEqual(clock.now, 105.0)  # Beyond the removed4s timer.
        self.assertLess(clock.now, 109.0)
        clock.now = 100.0
        with self.assertRaises(AssertionError):
            helpers["_wait_released"](SimpleNamespace(exists=lambda: False), 100.02)
        self.assertEqual(clock.now, 100.02)
        def late_release():
            clock.now = 110.0
            return True
        clock.now = 109.0
        with self.assertRaises(AssertionError):
            helpers["_wait_released"](SimpleNamespace(exists=late_release), 110.0)
        calls = []
        with self.assertRaises(AssertionError):
            helpers["_wait_released"](SimpleNamespace(exists=lambda: calls.append(True)), 109.0)
        self.assertEqual(calls, [])

    def test_reap_retires_consumed_unknown_and_late_results_without_retry(self):
        pid = 41
        for variant in ("no-result", "nonzero", "wrong-pid", "wrong-zero", "wrong-type", "raised", "late-status", "late-zero"):
            with self.subTest(variant=variant):
                clock, pending, calls = self.Clock(), [pid], []
                original = OSError("inert wait return unavailable")
                def waiting(actual, flags):
                    self.assertEqual((actual, flags), (pid, 1))
                    self.assertNotIn(pid, pending)  # Already retired at the effect boundary.
                    calls.append(actual)
                    if variant == "raised": raise original
                    if variant.startswith("late-"): clock.now = 101.0
                    return ((0, 0) if variant == "no-result" and len(calls) == 1 or variant == "late-zero"
                            else (pid, 256) if variant == "nonzero" else (pid + 1, 0) if variant == "wrong-pid"
                            else (0, 1) if variant == "wrong-zero" else (pid, False) if variant == "wrong-type"
                            else (pid, 0))
                helpers = self.helpers(clock, waiting)
                if variant == "no-result":
                    helpers["reap"](pid, pending, 101.0)
                    self.assertEqual(calls, [pid, pid])
                    self.assertEqual(pending, [])
                    continue
                with self.assertRaises((AssertionError, OSError)) as raised:
                    helpers["reap"](pid, pending, 101.0)
                primary = raised.exception
                if variant == "raised": self.assertIs(primary, original)
                self.assertEqual(pending, [pid] if variant == "late-zero" else [])
                secondary = helpers["_cleanup"](primary, [lambda: helpers["reap"](pid, pending, 101.0)])
                self.assertEqual(len(secondary), 1)
                self.assertEqual(primary.fork_fixture_cleanup_errors, secondary)
                self.assertEqual(calls, [pid])  # No ambiguous/consumed or expired retry.

    def test_cleanup_retires_contexts_and_preserves_first_error_with_all_secondary_errors(self):
        helpers = self.helpers(self.Clock())
        primary, first, second = AssertionError("original body"), OSError("first exit"), RuntimeError("second exit")
        calls, owners = [], {}
        def context(name, error):
            def close(*info):
                self.assertNotIn(name, owners)
                self.assertIs(info[1], primary)
                calls.append(name)
                raise error
            return SimpleNamespace(__exit__=close)
        owners.update(signing=context("signing", first), lease=context("lease", second))
        actions = [lambda: helpers["_exit_context"](owners, "signing", (AssertionError, primary, None)),
                   lambda: helpers["_exit_context"](owners, "lease", (AssertionError, primary, None)),
                   lambda: calls.append("independent")]
        with self.assertRaises(AssertionError) as raised:
            try:
                raise primary
            finally:
                secondary = helpers["_cleanup"](sys.exc_info()[1], actions)
        self.assertIs(raised.exception, primary)
        self.assertEqual(secondary, (first, second))
        self.assertEqual(primary.fork_fixture_cleanup_errors, secondary)
        self.assertEqual(calls, ["signing", "lease", "independent"])
        self.assertEqual(owners, {})
        self.assertEqual(helpers["_cleanup"](None, actions[:2]), ())
        self.assertEqual(calls, ["signing", "lease", "independent"])
        def fail(error):
            raise error
        with self.assertRaises(OSError) as raised:
            helpers["_cleanup"](None, [lambda: fail(first), lambda: fail(second), lambda: calls.append("last")])
        self.assertIs(raised.exception, first)
        self.assertEqual(first.fork_fixture_cleanup_errors, (second,))
        self.assertEqual(calls[-1], "last")
