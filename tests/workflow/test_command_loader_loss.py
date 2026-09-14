"""Two literal disposable singletons; original early W loss remains UNKNOWN."""
from __future__ import annotations

import json
import unittest

from mobile_release import _command_process as command, owned_process as owned

from . import command_bootstrap_fixture as fixture
from .profile_process_fixture import FixtureWorkspace


class CommandBootstrapContractTests(unittest.TestCase):
    def test_fixed_recipe_and_observation_parser_reject_ambiguous_inputs(self):
        settings = ("observe", "/fixed/command_bootstrap_fixture.py", "/fixed/case",
                    ((1, 2, 3), (1, 4, 3), (1, 5, 3)))
        original = command._BOOTSTRAP
        changed = fixture.build_bootstrap(original, settings)
        self.assertEqual(changed.count("while True:"), original.count("while True:"))
        self.assertEqual(changed.count("except BaseException:"), original.count("except BaseException:"))
        self.assertEqual(changed.count("_stage = 1"), 1)
        self.assertEqual(changed.count("_stage = 2"), 1)
        self.assertLessEqual(len(changed.encode()), 8192)
        for source, selected in ((changed, settings), (original + original, settings),
                                 (original.replace('if _role == "W":', 'if False:'), settings),
                                 (original, ("unlisted", *settings[1:]))):
            with self.assertRaises(AssertionError):
                fixture.build_bootstrap(source, selected)
        row = {"r": "W", "p": 123, "n": "a" * 32, "e": "park"}
        raw = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.assertEqual(fixture.parse_trace(raw), {"park": row})
        self.assertEqual(fixture.parse_trace(raw[:-1], partial=True), {})
        for data in (raw[:-1], raw + raw, b"x" * (fixture.MAX_TRACE_BYTES + 1)):
            with self.assertRaises((AssertionError, ValueError)):
                fixture.parse_trace(data)


class CommandLoaderLossTests(unittest.TestCase):
    def _loss(self, mode, marker):
        with FixtureWorkspace(prefix="mrk-command-loader-loss-") as workspace:
            root, identity = workspace.path, workspace._identity
            case = fixture.CommandCase(command, root / "case", mode)
            workspace.retain()  # Never remove UNKNOWN scratch in this process.
            with case, self.assertRaises(owned.ProcessError) as raised:
                owned.run_owned(["/fictional-unreached-command"], timeout=4)
            # All following checks use preowned/captured objects and bytes only.
            pids = case.bind_observations()
            outcome = case.outcome
            self.assertIsNone(outcome.original_finality)
            self.assertIsNone(outcome.no_target)
            self.assertEqual(outcome.result_integrity, "incomplete")
            self.assertTrue(outcome.create_w.attempted and outcome.create_w.retired)
            self.assertFalse(outcome.run_tool.attempted)
            self.assertTrue(outcome.run_tool.retired)
            self.assertFalse(raised.exception.contained or raised.exception.cleanup_complete)
            self.assertIn(marker, case.rows["W"])
            self.assertNotIn("hello", case.rows["W"])
            self.assertNotIn("anchor_moved", case.rows["A"])
            self.assertNotIn("owner_finish", case.rows["A"])
            self.assertEqual(case.rows["A"]["group_kill"]["group"], pids["A"])
            self.assertFalse(case.rows["A"]["group_kill"]["retired"])
            self.assertTrue(workspace.retained)
            self.assertFalse(workspace.removal_allowed)
            self.assertEqual(workspace._identity, identity)

    def test_preguard_normal_127_never_becomes_a_command_result(self):
        self._loss("preguard-127", "preguard")

    def test_guarded_import_failure_requires_original_domain_disposal(self):
        self._loss("guarded-import", "guarded_import")
