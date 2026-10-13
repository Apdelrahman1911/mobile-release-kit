"""Pure protocol checks; importing the DATA adapter never starts AppKit."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest


@unittest.skipIf(sys.platform == "win32", "The macOS DATA adapter imports POSIX pwd")
class PanelReadinessDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / "desktop/tools/macos_panel_reachability.py"
        spec = importlib.util.spec_from_file_location("mrk_panel_probe_data", path)
        cls.adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.adapter)

    def value(self):
        # Synthetic failed-preparation DATA, with no traversal or retirement.
        value = {key: False for key in (
            "semanticOpenIdentity", "acceptingActionSent", "prepared", "bodyEntered", "bodyReturned",
            "preProof", "postProof", "custodyKnown", "complete", "closeReturned", "completionReturned",
            "panelReleased", "parentReleased", "poolReturned",
        )}
        value.update(schemaVersion=1, scope="fresh-normal-parent-not-installed-tauri", readOnly=True,
                     timely=True, reason="parent-main-window", rows=[], selectorQueries=0,
                     selectorReturns=0, holders=0, holdersReleased=0, startStatus=-1,
                     directoryStatus=-1, closeStatus=-1, releaseStatus=-1,
                     parentReadinessInBudgetEventProgress=0,
                     parentReadinessLastInBudgetMainWindow=0,
                     parentReadinessLastInBudgetActiveEligible=0)
        return value

    def wire(self, value):
        return b"MRK_PANEL_REACHABILITY=" + json.dumps(value, separators=(",", ":")).encode() + b"\n"

    def test_readiness_domains_reject_inexact_types_and_impossible_partial_states(self):
        domains = {
            "parentReadinessInBudgetEventProgress": (0, 1, 3, 7),
            "parentReadinessLastInBudgetMainWindow": (0, 1, 2, 3),
            "parentReadinessLastInBudgetActiveEligible": (0, 1, 3, 5, 7, 13, 15),
        }
        for field, allowed in domains.items():
            for observation in range(17):
                with self.subTest(field=field, observation=observation):
                    value = self.value()
                    value[field] = observation
                    if observation in allowed:
                        self.adapter.native_data(self.wire(value))
                    else:
                        with self.assertRaises(self.adapter.Refused):
                            self.adapter.native_data(self.wire(value))
            for observation in (True, False, None, -1, 1.0, "1", [], {}):
                with self.subTest(field=field, inexact=observation):
                    value = self.value()
                    value[field] = observation
                    with self.assertRaises(self.adapter.Refused):
                        self.adapter.native_data(self.wire(value))

    def test_readiness_fields_are_mandatory_closed_and_not_causally_cross_filtered(self):
        value = self.value()
        # Different instants can legitimately disagree. Do not manufacture a
        # simultaneous-state interpretation or filter away an original refusal.
        value.update(parentReadinessInBudgetEventProgress=7,
                     parentReadinessLastInBudgetMainWindow=1,
                     parentReadinessLastInBudgetActiveEligible=15)
        self.assertEqual(self.adapter.native_data(self.wire(value)), value)
        for field in tuple(key for key in value if key.startswith("parentReadiness")):
            missing = dict(value)
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(self.adapter.Refused):
                self.adapter.native_data(self.wire(missing))
        unknown = dict(value, parentReadinessRawEvent="not-allowed")
        with self.assertRaises(self.adapter.Refused):
            self.adapter.native_data(self.wire(unknown))
        duplicate = self.wire(value)[:-2] + b',"parentReadinessInBudgetEventProgress":7}\n'
        with self.assertRaises(self.adapter.Refused):
            self.adapter.native_data(duplicate)


if __name__ == "__main__":
    unittest.main()
