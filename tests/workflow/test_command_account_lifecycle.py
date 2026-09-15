"""Finite account/no-target witnesses; native cases need the reviewed owner."""
from __future__ import annotations

import errno
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from workflow import command_account_lifecycle_fixture as fixture
from workflow import command_bootstrap_fixture as bootstrap
from workflow.profile_process_fixture import FixtureWorkspace


class CommandAccountLifecycleContractTests(unittest.TestCase):
    def test_fresh_recovery_factories_preserve_readers_and_route_all_phases(self):
        persistent = fixture.persistent
        original_trace = persistent.Trace
        phases = ("final-automatic", "final-no-resolution", "final-owner-resolution")
        for kind in ("callable", "class"):
            for scenario in ("automatic", "manual", "factory-failure", "recovery-failure"):
                with self.subTest(kind=kind, scenario=scenario), \
                        FixtureWorkspace(prefix="mrk-recovery-factory-inert-") as workspace:
                    root = workspace.path
                    persistent.write_json(root / "probe.json", {"synthetic": True})
                    constructed, entered, dispatched = [], [], []
                    failure = OSError("inert recovery failure")
                    preferences = None if scenario == "automatic" else ["inert-original"]
                    case = self

                    class Recorder:
                        def __init__(self, actual_root, name):
                            case.assertEqual(actual_root, root)
                            # Real private-file read: rebinding Trace to either
                            # this class or a lambda must not break its namespace.
                            case.assertEqual(persistent.read_case_json(root, "probe"), {"synthetic": True})
                            case.assertIs(persistent.Trace, original_trace)
                            constructed.append(name)
                            self.name = name
                            if scenario == "factory-failure" and name == phases[1]:
                                raise failure

                    trace_factory = Recorder if kind == "class" else lambda *args: Recorder(*args)

                    def recover(actual_root, trace, *, manual="none", expected_preferences=None):
                        self.assertEqual(actual_root, root)
                        self.assertIsInstance(trace, Recorder)
                        self.assertIs(expected_preferences, preferences)
                        entered.append((trace.name, manual))
                        if scenario == "recovery-failure" and trace.name == phases[2]:
                            raise failure
                        refused = scenario != "automatic" and trace.name != phases[2]
                        return {"refused": "inert-unknown" if refused else None,
                                "result": None if refused else {"status": "recovered"}}

                    def worker(actual_root, name, task, *, timeout):
                        # Synchronous doubles only; no process, account lease or
                        # native finality receipt is acquired or manufactured.
                        self.assertEqual(actual_root, root)
                        self.assertEqual(timeout, persistent.worker_timeout(
                            "automatic-recovery" if name == phases[0] else "manual-recovery"))
                        dispatched.append(name)
                        persistent.write_json(root / (name + ".json"), task())

                    with patch.object(persistent, "run_worker", new=worker), \
                            patch.object(persistent, "recovery_flow", new=recover), \
                            patch.object(fixture.fence, "result_worker", new=lambda _root, _name, task: task()):
                        if scenario == "automatic":
                            # Exercise the actual account caller as well as the
                            # injected constructors; its guarded worker stays intact.
                            result = fixture.fresh_recovery(root, trace_factory)
                            self.assertEqual(result, {"refused": None, "result": {"status": "recovered"}})
                        elif scenario == "manual":
                            self.assertEqual(persistent.recover_final(root, expected_preferences=preferences,
                                trace_factory=trace_factory),
                                {"automatic": "refused-unknown-resource", "manual": "recovered"})
                        else:
                            with self.assertRaises(OSError) as caught:
                                persistent.recover_final(root, expected_preferences=preferences,
                                                         trace_factory=trace_factory)
                            self.assertIs(caught.exception, failure)
                    count = 1 if scenario == "automatic" else 2 if scenario == "factory-failure" else 3
                    self.assertEqual(constructed, list(phases[:count]))
                    self.assertEqual(dispatched, constructed)
                    entered_count = count - (scenario == "factory-failure")
                    self.assertEqual(entered, list(zip(phases, ("none", "observe", "resolve")))[:entered_count])
                    self.assertIs(persistent.Trace, original_trace)
                    workspace.allow_removal()  # No native fixture resources existed.

    def test_independent_contender_failure_never_retries_a_retired_descriptor(self):
        # Inert descriptor scalars and callables, never a process/finality or
        # manufactured production account description.
        for failure in (False, True):
            contender = bootstrap._AccountContender(None, None)
            contender.fd, contender.state = 88, "OPEN"
            calls = []

            def close(descriptor):
                calls.append(descriptor)
                self.assertIsNone(contender.fd)
                self.assertEqual(contender.state, "UNKNOWN")
                if failure:
                    raise OSError(errno.EIO, "inert close return")

            local_os = SimpleNamespace(**vars(os))
            local_os.close = close
            with patch.object(bootstrap, "os", new=local_os):
                if failure:
                    with self.assertRaises(OSError):
                        contender.close()
                else:
                    contender.close()
                contender.close()
            self.assertEqual(calls, [88])
            self.assertEqual(contender.state, "UNKNOWN" if failure else "CLOSED")


class CommandAccountLifecycleTests(unittest.TestCase):
    def _case(self, selected, *, retain):
        with FixtureWorkspace(prefix="mrk-command-account-") as workspace:
            case_root = workspace.path
            if not retain:
                # The original case's actual worker custody authorizes child
                # disposal; the workspace then owns only its unchanged root.
                case_root = workspace.path / "case"
                case_root.mkdir(mode=0o700)
            result = fixture.run_case(case_root, selected)
            wait = result["originalWait"]
            self.assertTrue(wait["originalAnchorWait"] and wait["originalWorkerWait"]
                            and wait["originalStatusEOF"] and wait["groupAbsentBeforeAnchorWait"])
            if retain:
                workspace.retain()  # Original failed O/C is never relabelled whole-task finality.
                self.assertTrue(workspace.retained and not workspace.removal_allowed)
            else:
                self.assertTrue(result["original"]["sameLeaseDisposed"])
                self.assertEqual(result["original"]["noTarget"], "NO_W_CREATION")
                fixture.persistent.remove_case(case_root)
                self.assertEqual(list(workspace.path.iterdir()), [])
                workspace.allow_removal()

    def test_prepared_no_target_original_fence_and_same_lease_cleanup(self):
        self._case("prepared-positive", retain=False)

    def test_prepared_input_withdrawal_c_loss_fresh_prefix_recovery(self):
        self._case("prepared-prefix", retain=True)

    def test_original_hold_survives_true_parent_loss_and_is_absent_from_worker_map(self):
        self._case("hold-parent-loss", retain=True)
