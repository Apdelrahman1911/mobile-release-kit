"""Pure DATA parser coverage, not macOS/Xcode execution or product evidence."""
import importlib.util
import json
from pathlib import Path
from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[2] / "desktop/tools/macos_xcode_build_facts.py"
SPEC = importlib.util.spec_from_file_location("macos_xcode_build_facts", PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fixture(**changes):
    body = {"procName": "XCBBuildService", "procPath": "/Applications/Xcode.app/Contents/SharedFrameworks/XCBBuildService",
            "procLaunch": "2026-10-02 12:00:00.000 +0000", "captureTime": "2026-10-02 12:00:01.000 +0000",
            "exception": {"type": "EXC_CRASH", "signal": "SIGXFSZ"},
            "termination": {"namespace": "SIGNAL", "code": 25},
            "asi": {"private": "PRIVATE-MUST-NOT-LEAVE"}, "usedImages": [{"path": "PRIVATE-MUST-NOT-LEAVE"}]}
    body.update(changes)
    return (json.dumps({"bug_type": "309", "name": "XCBBuildService"}) + "\n" + json.dumps(body)).encode()


def retained_build():
    begin = M.timestamp("2026-10-02T12:00:00Z")
    before = {"schemaVersion": 1, "scope": M.SCOPE, "originalDirectory": "1:2:501",
              "beginEpochSeconds": begin, "productQualified": False, "serviceLimitsObserved": False}
    after = {"schemaVersion": 1, "scope": M.SCOPE, "beginEpochSeconds": begin, "endEpochSeconds": begin + 2,
             "originalBuildExit": 65, "productQualified": False, "serviceLimitsObserved": False,
             "processOwnershipOrFinalityEstablished": False}
    return {"source-commit.txt": b"a" * 40 + b"\n", "source-tree.txt": b"b" * 40 + b"\n",
            "run-attempt.txt": b"31/1\n", "build.status": b"65\n",
            "build-infrastructure-before.json": json.dumps(before).encode(),
            "build-infrastructure-after.json": json.dumps(after).encode()}


class XcodeBuildFactsDataTests(unittest.TestCase):
    def parse(self, raw):
        begin = M.timestamp("2026-10-02T12:00:00Z")
        return M.closed_crash_facts(raw, begin, begin + 2, "/Applications/Xcode.app/Contents")

    def test_signal_is_closed_correlation_not_identity_or_cause(self):
        value = self.parse(fixture())
        self.assertEqual(value["signal"], "SIGXFSZ")
        self.assertEqual(value["terminationCode"], 25)
        self.assertTrue(value["captureInBuildInterval"] and value["launchInBuildInterval"] and value["sameToolchainContents"])
        self.assertFalse(value["processOwnershipEstablished"] or value["rawReportRetained"])
        self.assertNotIn("PRIVATE", json.dumps(value))
        self.assertNotIn("procPath", value)
        for signal in ("SIGABRT", "SIGSEGV", "PRIVATE-MUST-NOT-LEAVE", None):
            value = self.parse(fixture(exception={"type": "PRIVATE", "signal": signal}, termination={"namespace": "PRIVATE", "code": True}))
            self.assertEqual(value["signal"], signal if signal in M.SIGNALS else "unavailable-or-other")
            self.assertEqual(value["exception"], "unavailable-or-other")
            self.assertIsNone(value["terminationCode"])
            self.assertNotIn("PRIVATE", json.dumps(value))

    def test_time_or_toolchain_mismatch_is_not_reclassified_as_matching(self):
        value = self.parse(fixture(procLaunch="2026-10-02T11:00:00Z", captureTime="2026-10-02T12:00:05Z"))
        self.assertFalse(value["captureInBuildInterval"] or value["launchInBuildInterval"])
        for path in ("/Applications/Xcode.app/Contents-other/service", "/Applications/Xcode.app/Contents/../service", "PRIVATE", None):
            self.assertFalse(self.parse(fixture(procPath=path))["sameToolchainContents"])

    def test_nonfatal_and_simulated_are_explicit_not_inferred_from_a_signal(self):
        missing = self.parse(fixture())
        self.assertIsNone(missing["isNonFatal"])
        self.assertIsNone(missing["isSimulated"])
        for nonfatal, simulated in ((True, False), (False, True)):
            value = self.parse(fixture(isNonFatal=nonfatal, isSimulated=simulated))
            self.assertEqual((value["isNonFatal"], value["isSimulated"]), (nonfatal, simulated))
            self.assertFalse(value["processOwnershipEstablished"])
        for key in ("isNonFatal", "isSimulated"):
            for value in (1, "PRIVATE-MUST-NOT-LEAVE", None):
                with self.assertRaises(ValueError):
                    self.parse(fixture(**{key: value}))

    def test_late_report_keeps_original_failed_result_and_capture_interval(self):
        original = M.late_build_inputs(retained_build(), "1:2:501", "a" * 40, "b" * 40, "31/1")
        self.assertEqual(original["originalBuildExit"], 65)
        self.assertEqual(original["endEpochSeconds"] - original["beginEpochSeconds"], 2)
        self.assertFalse(original["productQualified"] or original["processOwnershipOrFinalityEstablished"])
        # Publication twenty seconds later does not make a later crash match.
        for capture, matches in (("2026-10-02T12:00:01Z", True), ("2026-10-02T12:00:05Z", False)):
            facts = M.closed_crash_facts(fixture(captureTime=capture), original["beginEpochSeconds"],
                                        original["endEpochSeconds"], "/Applications/Xcode.app/Contents")
            self.assertEqual(facts["captureInBuildInterval"], matches)

    def test_late_observation_refuses_changed_bindings_success_or_conflicting_originals(self):
        for name, replacement in (("source-commit.txt", b"c" * 40 + b"\n"),
                                  ("source-tree.txt", b"c" * 40 + b"\n"),
                                  ("run-attempt.txt", b"31/2\n"), ("build.status", b"0\n")):
            raw = retained_build()
            raw[name] = replacement
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.late_build_inputs(raw, "1:2:501", "a" * 40, "b" * 40, "31/1")
        for key, value in (("originalBuildExit", 0), ("originalBuildExit", True),
                           ("beginEpochSeconds", 0), ("endEpochSeconds", float("nan")),
                           ("productQualified", True), ("schemaVersion", True)):
            raw = retained_build()
            after = json.loads(raw["build-infrastructure-after.json"])
            after[key] = value
            raw["build-infrastructure-after.json"] = json.dumps(after).encode()
            if key == "originalBuildExit" and type(value) is int:
                raw["build.status"] = (str(value) + "\n").encode()
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                M.late_build_inputs(raw, "1:2:501", "a" * 40, "b" * 40, "31/1")
        with self.assertRaises(ValueError):
            M.late_build_inputs(retained_build(), "1:3:501", "a" * 40, "b" * 40, "31/1")

    def test_malformed_ambiguous_or_oversize_reports_are_unavailable(self):
        for raw in (b"", fixture() + b"{}", fixture()[:-1], b"x" * (M.MAX_REPORT_BYTES + 1),
                    fixture().replace(b'"code": 25', b'"code": 25, "code": 25'),
                    fixture().replace(b'"code": 25', b'"code": NaN'),
                    fixture(procName="PRIVATE"), fixture(procLaunch="invalid"),
                    fixture(captureTime="2026-10-02T12:00:01"), fixture(exception=[])):
            with self.assertRaises((ValueError, OverflowError)):
                self.parse(raw)

    def test_empty_scans_recheck_the_original_endpoint(self):
        for observed in (9, 10, 11):
            with patch.object(M.os, "open", return_value=37), \
                    patch.object(M.os, "close"), \
                    patch.object(M.os, "scandir", side_effect=lambda _: nullcontext([])), \
                    patch.object(M.time, "monotonic", return_value=observed):
                derived = M.derived_sizes(36, 32768, 10)
                crashes = M.crash_snapshot(0, 2, "/Applications/Xcode.app/Contents", 10)
            self.assertEqual(derived["complete"], observed < 10)
            self.assertEqual(crashes["complete"], observed < 10)
            self.assertEqual(derived["largestFiles"], [])
            self.assertEqual(crashes["facts"], [])

    def test_last_report_finishing_late_retains_only_provisional_facts(self):
        entry = SimpleNamespace(name="XCBBuildService-synthetic.ips",
                                stat=lambda **_: SimpleNamespace(st_mode=M.stat.S_IFREG, st_mtime=1))
        with patch.object(M.os, "open", return_value=37), patch.object(M.os, "close"), \
                patch.object(M.os, "scandir", side_effect=[nullcontext([entry]), nullcontext([])]), \
                patch.object(M, "read_at", return_value=fixture()), \
                patch.object(M.time, "time", return_value=2), \
                patch.object(M.time, "monotonic", side_effect=[9, 10]):
            value = M.crash_snapshot(0, 2, "/Applications/Xcode.app/Contents", 10)
        self.assertFalse(value["complete"])
        self.assertEqual(len(value["facts"]), 1)
        self.assertEqual(value["facts"][0]["signal"], "SIGXFSZ")
        self.assertFalse(value["facts"][0]["processOwnershipEstablished"])


if __name__ == "__main__":
    unittest.main()
