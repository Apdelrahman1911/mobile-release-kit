"""DATA-only protocol regressions; no compile, launch, AppKit or process owner."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest


@unittest.skipIf(sys.platform == "win32", "The hosted Mac DATA adapter imports POSIX APIs")
class M2EntryDataTests(unittest.TestCase):
    SOURCE = "2cbb3e8f1b8e6b47230fb50f0651b661a4d3735a"

    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / "desktop/tools/macos_m2_entry_feasibility.py"
        spec = importlib.util.spec_from_file_location("mrk_m2_entry_data_test", path)
        cls.adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.adapter)

    def value(self):
        payload = dict.fromkeys((
            "entryPidPreserved originalAccount gateIdentity gateInheritedWithoutCLOEXEC gateMarkedCLOEXEC "
            "exclusiveWouldBlock executableIsPayload mainBundleIsPayload mainBundleIDIsPayload "
            "runningObjectExists runningExecutableIsPayload runningBundleIsEntry runningIDIsEntry "
            "didFinishLaunching windowVisible appActive"
        ).split(), True)
        payload.update(schemaVersion=1, source=self.SOURCE, scope="synthetic-appkit-payload-not-tauri",
                       processIdentifier=321, runningExecutableIsEntry=False,
                       runningBundleIsPayload=False, runningIDIsPayload=False)
        value = dict.fromkeys((
            "launchRequested launchReferenceReturned referencePIDMatchesPayload referenceBundleIsEntry "
            "referenceExecutableIsEntry exclusiveBlockedWhilePayloadAlive normalQuitRequestSent "
            "terminationObserved exclusiveAvailableAfterTermination rootCloseReturned timely observationComplete"
        ).split(), True)
        value.update(schemaVersion=1, source=self.SOURCE, scope="synthetic-nsworkspace-entry-feasibility",
                     launchErrorReported=False, workDeadlineFailed=False,
                     referenceBundleIsPayload=False, referenceExecutableIsPayload=False,
                     completionCount=1, completionBodyDoneCount=1, completionHandoffCount=1,
                     originalAppExitStatus=None, allWorkerFinality="not-established-by-NSRunningApplication",
                     firstFailure="none", payloadStart=payload,
                     payloadQuit={"schemaVersion": 1, "source": self.SOURCE,
                                  "normalQuitDelegateObserved": True, "gateStillHeldAtWillTerminate": True})
        return value

    def wire(self, value):
        return b"MRK_M2_ENTRY=" + json.dumps(value, separators=(",", ":")).encode() + b"\n"

    def parse(self, value):
        return self.adapter.native_data(self.wire(value), self.SOURCE)

    def test_distinct_entry_and_payload_identities_do_not_invent_product_finality(self):
        value = self.value()
        self.assertEqual(self.parse(value), value)
        self.assertTrue(self.adapter.supported_observation(self.parse(value)))
        for path, pairs in ((value, self.adapter.REFERENCE_IDENTITY_PAIRS),
                            (value["payloadStart"], self.adapter.PAYLOAD_IDENTITY_PAIRS)):
            for a, b in pairs:
                path[a], path[b] = False, True
        self.assertTrue(self.adapter.supported_observation(self.parse(value)))
        self.assertIsNone(self.parse(value)["originalAppExitStatus"])

    def test_incomplete_or_late_observations_are_preserved_but_never_pass(self):
        changes = (((), "firstFailure", "observation-deadline"), ((), "timely", False),
                   ((), "workDeadlineFailed", True),
                   ((), "completionBodyDoneCount", 0), ((), "terminationObserved", False),
                   ((), "normalQuitRequestSent", False), ((), "exclusiveAvailableAfterTermination", False),
                   ((), "launchErrorReported", True), ((), "referencePIDMatchesPayload", False),
                   (("payloadStart",), "appActive", False), (("payloadStart",), "mainBundleIsPayload", False),
                   (("payloadStart",), "gateMarkedCLOEXEC", False),
                   (("payloadQuit",), "gateStillHeldAtWillTerminate", False))
        for path, field, failed in changes:
            value = self.value()
            destination = value[path[0]] if path else value
            destination[field] = failed
            with self.subTest(field=field):
                self.assertEqual(self.parse(value), value)
                self.assertFalse(self.adapter.supported_observation(self.parse(value)))
        value = self.value()
        value.update(payloadStart=None, payloadQuit=None, firstFailure="launch-completion",
                     observationComplete=False, completionCount=0, completionBodyDoneCount=0, completionHandoffCount=0)
        self.assertFalse(self.adapter.supported_observation(self.parse(value)))
        # SOURCE boundary evidence, not native clock simulation: now == deadline
        # and now > deadline both fail the strict comparison. The irreversible
        # gate must surround actual setup/pump/record/native-observation sites.
        native = Path(__file__).resolve().parents[2] / "desktop/native/macos-m2-entry"
        observer = (native / "observe.m").read_text()
        self.assertIn("return now >= 0 && now < deadline;", (native / "fixture.h").read_text())
        self.assertIn("if (*failed || !mrk_before(deadline)) { *failed = YES; return NO; }", observer)
        gate = "if (!admit_work(work_end, &work_deadline_failed)) break;"
        launch_gate = observer.index("if (admit_work(work_end, &work_deadline_failed)) {")
        self.assertLess(observer.index("NSURL *entry_url ="), launch_gate)
        self.assertLess(launch_gate, observer.index("requested = YES;"))
        self.assertLess(launch_gate, observer.index("[workspace openApplicationAtURL:entry_url"))
        loop = observer[observer.index("while (admit_work(work_end, &work_deadline_failed)) {"):]
        self.assertLess(loop.index("progress_events();"), loop.index(gate))
        self.assertLess(loop.index(gate), loop.index("if (!handoff_count"))
        read = loop[loop.index('int read = read_record(root, "payload-start.json", &payload_start);'):]
        self.assertLess(read.index(gate), read.index("if (read < 0)"))
        final = read[read.index("blocked_alive = pid_matches &&"):]
        self.assertLess(final.index(gate), final.index("if (!pid_matches || !blocked_alive)"))
        self.assertIn('(work_deadline_failed || !payload_start) && [first isEqualToString:@"none"]', final)
        self.assertIn('BOOL complete = [first isEqualToString:@"none"] && !work_deadline_failed && timely', final)
        self.assertEqual(observer.count("work_deadline_failed = NO;"), 1)
        self.assertEqual(observer.count("*failed = YES;"), 1)

    def test_unknown_identity_is_not_success_and_conflicting_identity_is_rejected(self):
        for pair in self.adapter.REFERENCE_IDENTITY_PAIRS:
            self.check_pair((), pair)
        for pair in self.adapter.PAYLOAD_IDENTITY_PAIRS:
            self.check_pair(("payloadStart",), pair)

    def check_pair(self, path, pair):
        value = self.value()
        destination = value[path[0]] if path else value
        destination[pair[0]] = destination[pair[1]] = False
        self.assertFalse(self.adapter.supported_observation(self.parse(value)))
        destination[pair[0]] = destination[pair[1]] = True
        with self.assertRaises(self.adapter.Refused):
            self.parse(value)

    def test_closed_contract_rejects_type_coercion_source_substitution_and_extra_claims(self):
        changes = (((), "schemaVersion", True), ((), "source", "f" * 40), ((), "timely", 1),
                   ((), "completionCount", True), ((), "completionCount", 3), ((), "firstFailure", []),
                   ((), "originalAppExitStatus", 0), ((), "allWorkerFinality", "joined"),
                   ((), "installedProductQualified", True), (("payloadStart",), "processIdentifier", True),
                   (("payloadStart",), "processIdentifier", 321.0), (("payloadStart",), "processIdentifier", 2**31),
                   (("payloadQuit",), "normalQuitDelegateObserved", "true"))
        for path, field, invalid in changes:
            value = self.value()
            destination = value[path[0]] if path else value
            destination[field] = invalid
            with self.subTest(field=field, invalid=invalid), self.assertRaises(self.adapter.Refused):
                self.parse(value)
        for path in ((), ("payloadStart",), ("payloadQuit",)):
            value = self.value()
            del (value[path[0]] if path else value)["source"]
            with self.assertRaises(self.adapter.Refused):
                self.parse(value)

    def test_wire_is_bounded_single_record_duplicate_free_and_not_a_transcript(self):
        good = self.wire(self.value())
        duplicate = good[:-2] + b',"timely":true}\n'
        for invalid in (good + good, b"log\n" + good, good[:-1], duplicate, "not-bytes",
                        b"MRK_M2_ENTRY={\xff}\n", b"MRK_M2_ENTRY={\n", b"MRK_M2_ENTRY=NaN\n",
                        b"MRK_M2_ENTRY=" + b" " * 32769 + b"\n"):
            with self.subTest(kind=type(invalid).__name__), self.assertRaises(self.adapter.Refused):
                self.adapter.native_data(invalid, self.SOURCE)


if __name__ == "__main__":
    unittest.main()
