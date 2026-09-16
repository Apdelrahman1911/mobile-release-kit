"""Seven fixed native Store boundaries, selected one subcase per original domain.

The controller owns the complete15-source/14-wheel row inventory. Ordinary
discovery is not an execution route: selected() refuses without that original
configuration. No source/platform substitute, registry reset or skipped row.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

from workflow.store_lane_native_fixture import Case, MAX_CASE, PREFIX, selected


class StoreLaneNativeTests(unittest.TestCase):
    def _case(self):
        configuration = selected(self._testMethodName)
        self.observation = Case(configuration).run()
        self.assertEqual(self.observation["testId"], PREFIX + self._testMethodName)
        self.assertEqual(self.observation["subcase"], configuration.subcase)
        self.assertEqual(self.observation["phase"], configuration.phase)
        self.assertGreater(self.observation["persistedBytes"], 0)
        self.assertLessEqual(self.observation["persistedBytes"], MAX_CASE)
        self.assertEqual(self.observation["fixtureRemoved"], not self.observation["productRetained"])
        return configuration.subcase, self.observation["facts"]

    def _settled(self, facts, code):
        self.assertEqual(facts["returncode"], code)
        self.assertTrue(facts["commandFinality"])
        self.assertTrue(facts["terminalBound"])
        self.assertTrue(facts["productFilesDisposed"])
        self.assertTrue(facts["attemptRetired"])
        self.assertTrue(facts["handlersRestored"])
        self.assertEqual(facts["receiptAcceptable"], code == 0)
        self.assertFalse(self.observation["productRetained"])
        observed = facts["observation"]
        self.assertEqual(observed["stage"], "before-terminal-link")
        self.assertEqual(observed["terminalLinkCalls"], 1)
        # Frozen before calling the original link. Positive result/terminal
        # verification, not a fabricated observer callback, proves its return.
        self.assertEqual(observed["terminalLinkReturned"], 0)
        self.assertTrue(observed["originalSlotsCovered"])
        self.assertGreater(observed["originalSlotsCount"], 0)
        self.assertTrue(all(item["retired"] for item in observed["slots"]))
        self.assertEqual(observed["rootIdentity"], observed["cwdIdentity"])
        self.assertEqual(observed["cwd"], observed["binding"]["root"])
        self.assertEqual(observed["rootCanonical"], observed["binding"]["root"])
        self.assertEqual(observed["rootIdentity"]["device"], observed["binding"]["root_device"])
        self.assertEqual(observed["rootIdentity"]["inode"], observed["binding"]["root_inode"])
        self.assertEqual(observed["fastlane"]["version"], "2.235.0")
        self.assertEqual(observed["fastlane"]["macos"], sys.platform == "darwin")
        self.assertFalse(observed["fastlane"]["testMode"])
        return observed

    def _unknown(self, facts):
        self.assertEqual(facts["returncode"], 76)
        self.assertTrue(facts["commandFinality"])
        self.assertFalse(facts["terminalBound"])
        self.assertFalse(facts["receiptAcceptable"])
        self.assertTrue(facts["handlersRestored"])
        self.assertTrue(self.observation["productRetained"])
        self.assertFalse(self.observation["fixtureRemoved"])
        self.assertTrue(Path(facts["retainedProductRoot"]).is_dir())
        self.assertTrue(Path(facts["retainedMarker"]).is_file())
        return facts["observation"]

    def _nested_observation(self, observed, platform):
        nested = observed["nested"]
        self.assertEqual(nested["platform"], platform)
        self.assertTrue(nested["sameOriginalInvocation"])
        self.assertTrue(nested["sameOriginalSession"])
        self.assertTrue(nested["sameOriginalResult"])
        self.assertTrue(nested["resultFrozen"])
        self.assertTrue(nested["retired"])
        self.assertFalse(nested["fallbackUsed"])
        capture = nested["capture"]
        for field in ("finalized", "settled", "productionFinality", "originalWaitObserved", "tasksJoined", "leasesClosed", "allActualEOFObserved"):
            self.assertTrue(capture[field], field)
        self.assertFalse(capture["unknown"])
        self.assertEqual(capture["observerErrors"], [])
        self.assertEqual(capture["final"]["group"]["state"], "retired")
        self.assertTrue(capture["final"]["group"]["absent"])
        return nested

    def test_real_success_exit_and_original_fd_retirement(self):
        mode, facts = self._case()
        if mode == "ordinary-at-exit-control":
            self.assertEqual(self.observation["phase"], "source")
            self.assertEqual(facts, {"ordinaryHookObserved": True})
            return
        self.assertEqual(mode, "success0")
        observed = self._settled(facts, 0)
        self.assertIn("original-document-closed-and-recorded", observed["events"])
        self.assertIsNone(observed["primaryClass"])
        self.assertEqual(facts["inventoryRoles"], [])

    def test_real_ordinary_failure_is_settled75_without_receipt(self):
        mode, facts = self._case()
        self.assertEqual(mode, "ordinary75")
        observed = self._settled(facts, 75)
        self.assertTrue(observed["ordinaryPrimarySame"])
        self.assertEqual(observed["primaryClass"], "StoreLaneNativeFixture::OrdinaryFailure")
        self.assertNotIn("original-document-closed-and-recorded", observed["events"])
        self.assertEqual(facts["inventoryRoles"], [])

    def test_arbitrary_system_exit_is_unknown76(self):
        mode, facts = self._case()
        self.assertIn(mode, ("system-exit0", "system-exit75"))
        observed = self._unknown(facts)
        self.assertEqual(observed["primaryClass"], "SystemExit")
        self.assertEqual(observed["stage"], "unknown-cleanup")
        self.assertEqual(observed["terminalLinkCalls"], 0)
        self.assertEqual(facts["terminalNames"], [])

    def test_real_close_and_link_return_loss_refuse_binding(self):
        mode, facts = self._case()
        self.assertIn(mode, ("terminal-close-return-loss", "terminal-link-return-loss"))
        observed = self._unknown(facts)
        terminal = [item for item in observed["slots"] if Path(item["path"]).name == "terminal.part"]
        self.assertEqual(len(terminal), 1)
        self.assertEqual(terminal[0]["calls"], 1)
        self.assertEqual(terminal[0]["returns"], 1)
        self.assertTrue(terminal[0]["closed"])
        if mode == "terminal-close-return-loss":
            self.assertEqual(observed["primaryClass"], "IOError")
            self.assertEqual(observed["stage"], "unknown-cleanup")
            self.assertFalse(terminal[0]["retired"])
            self.assertEqual(observed["terminalLinkCalls"], 0)
            self.assertEqual(facts["terminalNames"], ["terminal.part"])
        else:
            # The diagnostic closed after the real link, before the declared
            # lost-return exception was raised. The actual76 proves refusal.
            self.assertIsNone(observed["primaryClass"])
            self.assertEqual(observed["stage"], "link-return-lost")
            self.assertTrue(terminal[0]["retired"])
            self.assertEqual(observed["terminalLinkCalls"], 1)
            self.assertEqual(observed["terminalLinkReturned"], 1)
            self.assertEqual(facts["terminalNames"], ["terminal.json", "terminal.part"])

    def test_real_nested_family_settles_before_composite_disposal(self):
        mode, facts = self._case()
        self.assertIn(mode, ("nested-ios-success", "nested-android-success", "nested-android-inherited-pipe"))
        observed = self._settled(facts, 0)
        nested = self._nested_observation(observed, "ios" if mode == "nested-ios-success" else "android")
        capture = nested["capture"]
        self.assertLess(observed["events"].index("same-original-nested-call-retired"),
                        observed["events"].index("original-document-closed-and-recorded"))
        if mode.endswith("inherited-pipe"):
            self.assertTrue(nested["descendant"]["stdoutOpen"])
            self.assertTrue(nested["descendant"]["stderrOpen"])
            self.assertEqual(nested["descendant"]["group"], capture["final"]["group"]["id"])
        else:
            self.assertIsNone(nested["descendant"])

    def test_pinned_fastlane_bridges_own_generated_entries_before_dispatch(self):
        mode, facts = self._case()
        self.assertIn(mode, ("bridge-success", "bridge-ordinary-error"))
        observed = self._settled(facts, 0 if mode == "bridge-success" else 75)
        nested = self._nested_observation(observed, "ios")
        self.assertEqual(nested["artifact"], observed["binding"]["artifact"])
        self.assertIsNone(nested["descendant"])
        events = observed["events"]
        self.assertEqual(events.count("same-original-nested-call-retired"), 1)
        self.assertEqual(events.count("original-bridge-executor-dispatch"), 1)
        self.assertLess(events.index("same-original-nested-call-retired"), events.index("original-bridge-executor-dispatch"))
        bridge = observed["bridge"]
        self.assertTrue(bridge["syntheticExecutor"])
        self.assertTrue(bridge["sameOriginalValidationAtDispatch"])
        self.assertEqual(bridge["fastlaneVersion"], "2.235.0")
        self.assertEqual(bridge["dispatches"], 1)
        self.assertEqual([item["placeholder"] for item in bridge["commands"]], [False, True])
        roles = {"pilot-root", "package-ipa", "key-dir", "key"}
        if sys.platform == "darwin":
            roles.update(("package", "package-metadata", "upload-asset"))
        self.assertEqual(set(bridge["rolesBeforeDispatch"]), roles)
        self.assertEqual(set(facts["inventoryRoles"]), roles)
        self.assertEqual(set(observed["fastlane"]["methods"]), {"pipe", "key", "transporter", "package", "pilot"})
        self.assertEqual(len(observed["fastlane"]["files"]), 5)
        if mode == "bridge-success":
            self.assertIn("real-pilot-package-key-and-pipe-bodies-returned", observed["events"])
            self.assertLess(events.index("original-bridge-executor-dispatch"), events.index("real-pilot-package-key-and-pipe-bodies-returned"))
            self.assertLess(events.index("real-pilot-package-key-and-pipe-bodies-returned"), events.index("original-document-closed-and-recorded"))
            self.assertTrue(observed["pipe"]["retired"])
            self.assertTrue(observed["pipe"]["endpointsRetired"])
            self.assertTrue(observed["pipe"]["eof"])
            self.assertEqual(observed["pipe"]["waitState"], "reaped")
            self.assertEqual(observed["pipe"]["status"], 0)
        else:
            self.assertTrue(observed["ordinaryPrimarySame"])
            self.assertEqual(observed["primaryClass"], "StoreLaneNativeFixture::OrdinaryFailure")
            self.assertIsNone(observed["pipe"])
            self.assertNotIn("real-pilot-package-key-and-pipe-bodies-returned", events)
            self.assertNotIn("original-document-closed-and-recorded", events)

    def test_native_shared_clock_labels_samples_and_expiry(self):
        mode, facts = self._case()
        self.assertIn(mode, ("clock-brackets", "clock-expired", "clock-wrong-label"))
        expected = {"linux": ("clock_gettime(CLOCK_MONOTONIC)", "linux-monotonic-v1"),
                    "darwin": ("mach_absolute_time()", "darwin-uptime-raw-v1")}
        implementation, label = expected[sys.platform]
        if mode == "clock-brackets":
            self.assertEqual(facts["pythonImplementation"], "cpython")
            self.assertEqual(facts["pythonClock"], implementation)
            self.assertEqual(facts["platform"], sys.platform)
            self.assertEqual(len(facts["clockSamples"]), 3)
            for sample in facts["clockSamples"]:
                self.assertEqual(sample["label"], label)
                for key in ("ruby", "helper", "fixture"):
                    self.assertLessEqual(sample["before"], sample[key])
                    self.assertLessEqual(sample[key], sample["after"])
                self.assertLessEqual(sample["before"] / 1e9, sample["installed"])
                self.assertLessEqual(sample["installed"], sample["after"] / 1e9)
            return
        self.assertTrue(facts["runtimeOnly"])
        self.assertEqual(facts["returncode"], 76)
        self.assertFalse(facts["compositeSealShortened"])
        if mode == "clock-expired":
            observed = facts["observation"]
            self.assertEqual(observed["stage"], "unknown-cleanup")
            self.assertEqual(observed["clock"]["label"], label)
            self.assertLess(observed["clock"]["entered"], observed["clock"]["run"])
            self.assertLessEqual(observed["clock"]["run"], observed["clock"]["after"])
        else:
            self.assertIsNone(facts["observation"])
