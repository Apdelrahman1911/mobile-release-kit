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
