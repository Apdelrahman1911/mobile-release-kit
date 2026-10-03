"""DATA/inert-FS regressions; no compile, launch, AppKit or process owner."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


@unittest.skipIf(sys.platform == "win32", "The hosted Mac DATA adapter imports POSIX APIs")
class M2EntryDataTests(unittest.TestCase):
    SOURCE = "2cbb3e8f1b8e6b47230fb50f0651b661a4d3735a"
    APPKIT = (
        ("sharedApplication", "payload-appkit-shared.json", "shared-application-returned"),
        ("activationPolicy", "payload-appkit-policy.json", "activation-policy-returned"),
        ("beforeRun", "payload-appkit-before-run.json", "setup-complete-before-run"),
        ("didFinishLaunching", "payload-appkit-did-finish.json", "did-finish-launching-entered"),
        ("runReturned", "payload-appkit-run-returned.json", "run-returned"),
    )

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

    def early_value(self):
        value = self.value()
        value.update(firstFailure="payload-terminated-before-observation",
                     referencePIDMatchesPayload=False, exclusiveBlockedWhilePayloadAlive=False,
                     normalQuitRequestSent=False, observationComplete=False,
                     payloadStart=None, payloadQuit=None)
        for pair in self.adapter.REFERENCE_IDENTITY_PAIRS:
            for flag in pair:
                value[flag] = False
        return value

    def gate_value(self):
        return {"schemaVersion": 1, "source": self.SOURCE, "case": "ls-full-payload",
                "phase": "entry-gate-admission", "selectedReturnCode": 66,
                "originalRootDescriptor": 0, "gateOpenDescriptor": 1,
                "gateOpenErrno": None, "gateMatchAccepted": False,
                "rejectedGateCloseReturned": True}

    def failed_value(self):
        return {"schemaVersion": 1, "source": self.SOURCE, "case": "ls-full-payload",
                "phase": "entry-exec-returned", "execErrno": self.adapter.errno.ENOENT,
                "execReturnedENOENT": True, "originalGateStillHeld": True}

    def main_value(self, phase="main-admitted-before-appkit"):
        value = {"schemaVersion": 1, "source": self.SOURCE, "case": "ls-full-payload",
                 "phase": phase, "selectedReturnCode": None, "gateMatchAccepted": True,
                 **dict.fromkeys(self.adapter.MAIN_FLAGS, True)}
        if phase == "main-gate-refused":
            value.update(selectedReturnCode=65, gateMatchAccepted=False,
                         **dict.fromkeys(self.adapter.MAIN_FLAGS, None))
        elif phase == "main-handoff-refused":
            value.update(selectedReturnCode=66, entryPidPreserved=False)
        return value

    def progress_value(self, *slots, policy=True):
        phases = {slot: phase for slot, _, phase in self.APPKIT}
        value = dict.fromkeys(phases)
        for slot in slots:
            value[slot] = {"schemaVersion": 1, "source": self.SOURCE, "case": "ls-full-payload",
                           "phase": phases[slot], "policySwitchAccepted": policy if slot == "activationPolicy" else None,
                           "selectedReturnCode": (67 if slot == "activationPolicy" and policy is False
                                                  else 74 if slot == "runReturned" else None)}
        return value

    def test_full_payload_boundary_distinguishes_gate_exec_and_main_without_feasibility(self):
        native = self.parse(self.early_value())
        for gate in (self.gate_value(),
                     dict(self.gate_value(), originalRootDescriptor=3, gateOpenDescriptor=4),
                     dict(self.gate_value(), gateOpenDescriptor=-1, gateOpenErrno=24,
                          gateMatchAccepted=None, rejectedGateCloseReturned=None)):
            with self.subTest(gate=gate):
                value = self.adapter.boundary_diagnostic(native, 1, gate, None, None, self.SOURCE)
                self.assertEqual(value["boundaryOutcome"], "entry-gate-refused")
                self.assertEqual(value["entryGateRefusal"], gate)
                self.assertIsNone(value["failedExec"])
                self.assertIsNone(value["payloadMain"])
                self.assertTrue(value["expectedBoundaryObserved"])
        for code in (1, self.adapter.errno.ENOENT, 13, 86, 2**31 - 1):
            failed = dict(self.failed_value(), execErrno=code, execReturnedENOENT=code == self.adapter.errno.ENOENT)
            value = self.adapter.boundary_diagnostic(native, 1, None, failed, None, self.SOURCE)
            self.assertEqual(value["boundaryOutcome"], "entry-exec-returned")
            self.assertEqual(value["failedExec"], failed)
            self.assertTrue(value["expectedBoundaryObserved"])
        for phase in ("main-gate-refused", "main-handoff-refused", "main-admitted-before-appkit"):
            main = self.main_value(phase)
            value = self.adapter.boundary_diagnostic(native, 1, None, None, main, self.SOURCE)
            self.assertEqual(value["boundaryOutcome"], phase)
            self.assertEqual(value["payloadMain"], main)
            self.assertTrue(value["expectedBoundaryObserved"])
        self.assertFalse(self.adapter.supported_observation(native))
        self.assertIsNone(native["originalAppExitStatus"])
        self.assertEqual(native["allWorkerFinality"], "not-established-by-NSRunningApplication")
        self.assertEqual(native["firstFailure"], "payload-terminated-before-observation")

        # Every subset, including gaps, is valid best-effort DATA; none supplies
        # a missing main record or upgrades the original diagnostic gates.
        for include_main in (False, True):
            for mask in range(1 << len(self.APPKIT)):
                slots = [slot for bit, (slot, _, _) in enumerate(self.APPKIT) if mask & (1 << bit)]
                progress = self.progress_value(*slots)
                result = self.adapter.boundary_diagnostic(
                    native, 1, None, None, self.main_value() if include_main else None,
                    self.SOURCE, progress=progress)
                with self.subTest(include_main=include_main, slots=slots):
                    self.assertEqual(result["appKitProgress"], progress)
                    self.assertEqual(result["boundaryOutcome"], "main-admitted-before-appkit" if include_main else "unresolved")
                    self.assertIs(result["expectedBoundaryObserved"], include_main)
                    self.assertEqual(set(result["appKitProgress"]), {slot for slot, _, _ in self.APPKIT})
        for slots in (("activationPolicy",), ("sharedApplication", "activationPolicy")):
            progress = self.progress_value(*slots, policy=False)
            result = self.adapter.boundary_diagnostic(native, 1, None, None, self.main_value(), self.SOURCE,
                                                      progress=progress)
            self.assertEqual(result["appKitProgress"], progress)
            self.assertEqual(result["boundaryOutcome"], "main-admitted-before-appkit")
            self.assertTrue(result["expectedBoundaryObserved"])
            self.assertIsNone(native["originalAppExitStatus"])

    def test_full_payload_boundary_rejects_conflict_unknown_late_or_close_failure(self):
        native = self.parse(self.early_value())
        value = self.adapter.boundary_diagnostic(native, 1, None, None, None, self.SOURCE)
        self.assertEqual(value["boundaryOutcome"], "unresolved")
        self.assertFalse(value["expectedBoundaryObserved"])
        for gate, failed, main in ((self.gate_value(), self.failed_value(), None),
                                   (self.gate_value(), None, self.main_value()),
                                   (None, self.failed_value(), self.main_value()),
                                   (self.gate_value(), self.failed_value(), self.main_value())):
            with self.assertRaisesRegex(self.adapter.Refused, "diagnostic-conflicting-outcomes"):
                self.adapter.boundary_diagnostic(native, 1, gate, failed, main, self.SOURCE)
        for gate, failed in ((dict(self.gate_value(), rejectedGateCloseReturned=False), None),
                             (None, dict(self.failed_value(), originalGateStillHeld=False))):
            value = self.adapter.boundary_diagnostic(native, 1, gate, failed, None, self.SOURCE)
            self.assertFalse(value["expectedBoundaryObserved"])
            self.assertNotEqual(value["boundaryOutcome"], "unresolved")
        for status in (0, 64, 255):
            self.assertFalse(self.adapter.boundary_diagnostic(
                native, status, self.gate_value(), None, None, self.SOURCE)["expectedBoundaryObserved"])
        for status in (True, -1, 256, "1"):
            with self.assertRaisesRegex(self.adapter.Refused, "diagnostic-owner-status"):
                self.adapter.boundary_diagnostic(native, status, self.gate_value(), None, None, self.SOURCE)
        changes = (("timely", False), ("workDeadlineFailed", True), ("rootCloseReturned", False),
                   ("terminationObserved", False), ("exclusiveAvailableAfterTermination", False),
                   ("launchRequested", False), ("launchReferenceReturned", False),
                   ("launchErrorReported", True), ("normalQuitRequestSent", True),
                   ("referencePIDMatchesPayload", True), ("exclusiveBlockedWhilePayloadAlive", True),
                   ("referenceExecutableIsEntry", True), ("observationComplete", True),
                   ("firstFailure", "root-close"), ("completionCount", 2),
                   ("completionBodyDoneCount", 0), ("completionHandoffCount", 2))
        for key, changed in changes:
            value = self.early_value()
            value[key] = changed
            with self.subTest(key=key):
                result = self.adapter.boundary_diagnostic(
                    self.parse(value), 1, self.gate_value(), None, None, self.SOURCE)
                self.assertFalse(result["expectedBoundaryObserved"])

        for slot, _, _ in self.APPKIT:
            for gate, failed, main in ((self.gate_value(), None, None), (None, self.failed_value(), None),
                                       (None, None, self.main_value("main-gate-refused")),
                                       (None, None, self.main_value("main-handoff-refused"))):
                with self.subTest(slot=slot, gate=gate, failed=failed, main=main), \
                        self.assertRaisesRegex(self.adapter.Refused, "diagnostic-appkit-after-refusal"):
                    self.adapter.boundary_diagnostic(native, 1, gate, failed, main, self.SOURCE,
                                                     progress=self.progress_value(slot))
        for later in ("beforeRun", "didFinishLaunching", "runReturned"):
            with self.subTest(later=later), \
                    self.assertRaisesRegex(self.adapter.Refused, "diagnostic-appkit-policy-conflict"):
                self.adapter.boundary_diagnostic(
                    native, 1, None, None, self.main_value(), self.SOURCE,
                    progress=self.progress_value("activationPolicy", later, policy=False))
        for later in ("payloadStart", "payloadQuit"):
            changed = self.early_value()
            changed[later] = self.value()[later]
            with self.subTest(later=later), \
                    self.assertRaisesRegex(self.adapter.Refused, "diagnostic-appkit-policy-conflict"):
                self.adapter.boundary_diagnostic(
                    self.parse(changed), 1, None, None, self.main_value(), self.SOURCE,
                    progress=self.progress_value("activationPolicy", policy=False))

    def test_gate_refusal_shape_preserves_original_open_and_consuming_close_outcomes(self):
        changes = (("schemaVersion", True), ("source", "f" * 40), ("case", "direct"),
                   ("phase", "payload"), ("selectedReturnCode", True), ("selectedReturnCode", 76),
                   ("originalRootDescriptor", True), ("originalRootDescriptor", -1),
                   ("originalRootDescriptor", 2**31), ("gateOpenDescriptor", True),
                   ("gateOpenDescriptor", -2), ("gateOpenDescriptor", 2**31), ("gateOpenDescriptor", 0),
                   ("gateOpenErrno", 0), ("gateMatchAccepted", True), ("gateMatchAccepted", None),
                   ("rejectedGateCloseReturned", None), ("rejectedGateCloseReturned", 1), ("extra", False))
        for key, changed in changes:
            value = self.gate_value()
            value[key] = changed
            with self.subTest(key=key), self.assertRaises(self.adapter.Refused):
                self.adapter.gate_refusal(value, self.SOURCE)
        for key in self.gate_value():
            value = self.gate_value()
            del value[key]
            with self.subTest(missing=key), self.assertRaises(self.adapter.Refused):
                self.adapter.gate_refusal(value, self.SOURCE)
        opened = dict(self.gate_value(), gateOpenDescriptor=-1, gateOpenErrno=24,
                      gateMatchAccepted=None, rejectedGateCloseReturned=None)
        for key, changed in (("gateOpenErrno", None), ("gateOpenErrno", True),
                             ("gateOpenErrno", 0), ("gateOpenErrno", 2**31),
                             ("gateMatchAccepted", False), ("rejectedGateCloseReturned", True)):
            with self.subTest(key=key), self.assertRaises(self.adapter.Refused):
                self.adapter.gate_refusal(dict(opened, **{key: changed}), self.SOURCE)
        # A consuming close failure is preserved as DATA, not discarded or success.
        value = dict(self.gate_value(), rejectedGateCloseReturned=False)
        self.assertEqual(self.adapter.gate_refusal(value, self.SOURCE), value)

    def test_diagnostic_reader_distinguishes_initial_absence_from_changed_or_unproved_file(self):
        path = Path("/private/tmp/mrk-m2-inert-root/entry-gate-refused.json")
        with patch.object(Path, "lstat", side_effect=FileNotFoundError), \
                patch.object(self.adapter, "read_file") as reader:
            self.assertIsNone(self.adapter.read_diagnostic(path, 501, 20))
            self.adapter.require_absent(path, "occupied")
            reader.assert_not_called()
        for method in (lambda: self.adapter.read_diagnostic(path, 501, 20),
                       lambda: self.adapter.require_absent(path, "occupied")):
            with patch.object(Path, "lstat", side_effect=PermissionError), self.assertRaises(PermissionError):
                method()
        with patch.object(Path, "lstat", return_value=object()), \
                patch.object(self.adapter, "read_file", side_effect=FileNotFoundError), \
                self.assertRaises(FileNotFoundError):
            self.adapter.read_diagnostic(path, 501, 20)
        with patch.object(Path, "lstat", return_value=object()), \
                self.assertRaisesRegex(self.adapter.Refused, "occupied"):
            self.adapter.require_absent(path, "occupied")
        body = json.dumps(self.gate_value()).encode()
        original = (7, 3, stat.S_IFREG | 0o400, 501, 20, 1, len(body), 100, 100)
        with patch.object(Path, "lstat", return_value=object()), \
                patch.object(self.adapter, "read_file", return_value=(body, original)) as reader:
            self.assertEqual(self.adapter.read_diagnostic(path, 501, 20), self.gate_value())
            reader.assert_called_once_with(path, 4096)
        for index, changed in ((2, stat.S_IFREG | 0o600), (2, stat.S_IFLNK | 0o400),
                               (3, 502), (4, 0), (5, 2)):
            invalid = list(original)
            invalid[index] = changed
            with self.subTest(index=index), patch.object(Path, "lstat", return_value=object()), \
                    patch.object(self.adapter, "read_file", return_value=(body, tuple(invalid))), \
                    self.assertRaisesRegex(self.adapter.Refused, "diagnostic-record-original"):
                self.adapter.read_diagnostic(path, 501, 20)
        with self.assertRaisesRegex(self.adapter.Refused, "diagnostic-record-name"):
            self.adapter.read_diagnostic(path.with_name("payload-start.json"), 501, 20)

        for slot, name, _ in self.APPKIT:
            candidate = path.with_name(name)
            with patch.object(Path, "lstat", side_effect=FileNotFoundError), \
                    patch.object(self.adapter, "read_file") as reader:
                self.assertIsNone(self.adapter.read_diagnostic(candidate, 501, 20))
                reader.assert_not_called()
            with patch.object(Path, "lstat", return_value=object()), \
                    patch.object(self.adapter, "read_file", side_effect=FileNotFoundError), \
                    self.assertRaises(FileNotFoundError):
                self.adapter.read_diagnostic(candidate, 501, 20)
            value = self.progress_value(slot)[slot]
            encoded = json.dumps(value).encode()
            proof = (7, 3, stat.S_IFREG | 0o400, 501, 20, 1, len(encoded), 100, 100)
            with patch.object(Path, "lstat", return_value=object()), \
                    patch.object(self.adapter, "read_file", return_value=(encoded, proof)) as reader:
                self.assertEqual(self.adapter.read_diagnostic(candidate, 501, 20), value)
                reader.assert_called_once_with(candidate, 4096)
            for invalid in (b'{"phase":"x","phase":"x"}', b'NaN', b'{\xff}', b'{'):
                proof = (7, 3, stat.S_IFREG | 0o400, 501, 20, 1, len(invalid), 100, 100)
                with patch.object(Path, "lstat", return_value=object()), \
                        patch.object(self.adapter, "read_file", return_value=(invalid, proof)), \
                        self.assertRaises(self.adapter.Refused):
                    self.adapter.read_diagnostic(candidate, 501, 20)
        for name in ("payload-appkit-other.json", ".payload-appkit-policy.json.inflight"):
            with patch.object(Path, "lstat") as named:
                with self.assertRaisesRegex(self.adapter.Refused, "diagnostic-record-name"):
                    self.adapter.read_diagnostic(path.with_name(name), 501, 20)
                named.assert_not_called()

    def test_diagnostic_source_keeps_original_gate_verdict_and_single_ls_owner_path(self):
        root = Path(__file__).resolve().parents[2]
        entry = (root / "desktop/native/macos-m2-entry/entry.c").read_text()
        fixture = (root / "desktop/native/macos-m2-entry/fixture.h").read_text()
        capture = fixture[fixture.index("static inline int mrk_open_gate_captured("):
                          fixture.index("static inline int mrk_open_gate(int root)")]
        self.assertEqual(capture.count("openat("), 1)
        self.assertEqual(capture.count("mrk_gate_matches("), 1)
        self.assertEqual(capture.count("mrk_close("), 1)
        self.assertNotIn("mrk_record(", capture)
        order = [capture.index(part) for part in (
            "int fd = openat(", "int open_error = fd < 0 ? errno : 0;",
            "if (fd < 0) return -1;", "int matched = mrk_gate_matches(",
            "int closed = mrk_close(&fd);")]
        self.assertEqual(order, sorted(order))
        self.assertIn("return mrk_open_gate_captured(root, NULL);", fixture)
        refusal = entry.index("if (gate < 0) {")
        self.assertNotIn("mrk_record(", entry[:refusal])
        self.assertLess(entry.index("mrk_open_gate_captured(root, &gate_outcome)"), refusal)
        self.assertLess(refusal, entry.index('mrk_record(root, "entry-gate-refused.json"'))
        self.assertLess(entry.index("return selected_return;"), entry.index("if (flock(gate, LOCK_SH | LOCK_NB))"))
        self.assertIn("const int selected_return = 66;", entry)
        self.assertIn("if (argc != 1 || !mrk_account()) return 64;", entry)
        self.assertIn("if (root < 0) return 65;", entry)
        self.assertEqual(entry.count("execve("), 1)
        self.assertNotIn("mrk_close(&gate)", entry[entry.index("execve("):])
        source = (root / "desktop/tools/macos_m2_entry_feasibility.py").read_text()
        main = source[source.index("def main():"):]
        launch = 'observed = call("one-launchservices-observation", [str(observer)], 60)'
        self.assertEqual(main.count(launch), 1)
        self.assertLess(main.index('for name in FIXED_RECORDS:'), main.index(launch))
        self.assertIn('require_absent(work / ("." + name + ".inflight"),', main)
        self.assertEqual(main.count('bundle("Mobile Release Kit.app"'), 1)
        for role in ("compile-payload", "sign-payload", "verify-payload-signature"):
            self.assertEqual(main.count('zero("' + role + '"'), 1)
            self.assertLess(main.index('zero("' + role + '"'), main.index(launch))
        self.assertIn('"payload": tree(payload)', main)
        self.assertIn('tree(payload) == bundle_pins["payload"]', main)
        self.assertNotIn('call("exclusive-refusal"', main)
        self.assertNotIn('call("real-failed-exec"', main)
        self.assertNotIn('report["feasibilityObserved"] =', main)
        for field in ("feasibilityObserved", "installedProductQualified", "tauriQualified",
                      "credentialQualified", "maintenanceAvailable"):
            self.assertIn('"' + field + '": False', main)
        self.assertIn('"scope": "m2-full-payload-boundary-diagnostic-only"', main)
        self.assertIn('report["diagnosticComplete"] = diagnostic_complete', main)
        self.assertIn('return 0 if diagnostic_complete else 1', main)
        self.assertIn('result = owner.run_owned(argv, environ=environment, cwd=work, timeout=timeout,', main)
        self.assertIn('native.get("observationComplete") and native.get("terminationObserved")', main)
        self.assertNotIn('native.get("diagnosticComplete")', main)

        self.assertEqual(self.adapter.APPKIT_RECORDS, self.APPKIT)
        diagnostics = ("entry-gate-refused.json", "entry-failed-exec.json", "payload-main.json",
                       *(name for _, name, _ in self.APPKIT))
        self.assertEqual(self.adapter.DIAGNOSTIC_RECORDS, diagnostics)
        self.assertEqual(self.adapter.FIXED_RECORDS,
                         (*diagnostics, "entry-busy.json", "payload-start.json", "payload-quit.json"))
        self.assertEqual(len(set(self.adapter.FIXED_RECORDS)), 11)
        self.assertEqual(self.adapter.LIMIT, 65536)
        roles = self.adapter.re.findall(r'(?:zero|call)\("([^"\n]+)"', main)
        self.assertEqual(roles, ["compiler-version", "sdk-version", "compile-entry", "sign-entry",
                                "verify-entry-signature", "entry-linked-images", "entry-load-commands",
                                "compile-payload", "sign-payload", "verify-payload-signature",
                                "compile-observer", "one-launchservices-observation"])
        readback = 'progress = {slot: read_diagnostic(work / name, uid, gid) for slot, name, _ in APPKIT_RECORDS}'
        self.assertEqual(main.count(readback), 1)
        self.assertLess(main.index(launch), main.index(readback))
        self.assertLess(main.index(readback), main.index('report["diagnostic"] = boundary_diagnostic('))
        self.assertIn('progress=progress)', main)
        self.assertIn('need(len(body) <= 262144, "report-bound")', main)
        cleanup = main[main.index('if work is not None and "work_original" in locals():'):]
        self.assertNotIn('appKitProgress', cleanup)
        self.assertIn('inflight or not native.get("observationComplete", False)', cleanup)
        self.assertIn('native.get("observationComplete") and native.get("terminationObserved")', cleanup)
        self.assertEqual(self.adapter.digest(entry.encode()),
                         "20e625f08a20cd0cc1d32f21161acac14b9e98e90e56119db8465756d282e1b7")
        observer = (root / "desktop/native/macos-m2-entry/observe.m").read_text()
        self.assertEqual(self.adapter.digest(observer.encode()),
                         "c0bbb06aa575e6ab107e26019dac9fe59bda2ebfa7da18121e28a1b7cf1b2759")
        self.assertEqual(fixture.count("Eleven fixed public diagnostic records"), 1)
        self.assertEqual(self.adapter.digest(fixture.replace("Eleven fixed public diagnostic records",
                                                            "Six fixed public diagnostic records").encode()),
                         "559d117f17f66e00254777eec93317c28627b89e3efde96d4e7ac934978ed4e5")


    def test_returned_exec_errno_is_strict_and_not_an_exit_receipt(self):
        self.assertEqual(self.adapter.returned_exec(self.failed_value(), self.SOURCE), self.failed_value())
        changes = (("schemaVersion", True), ("source", "f" * 40), ("case", "ls-payload-absent"),
                   ("phase", "payload-main"), ("execErrno", True), ("execErrno", 0), ("execErrno", -1),
                   ("execErrno", 2**31), ("execErrno", "2"), ("execErrno", None),
                   ("execReturnedENOENT", False), ("execReturnedENOENT", 1),
                   ("originalGateStillHeld", 1), ("extra", 0))
        for key, changed in changes:
            with self.subTest(key=key, changed=changed), self.assertRaises(self.adapter.Refused):
                self.adapter.returned_exec(dict(self.failed_value(), **{key: changed}), self.SOURCE)
        for key in self.failed_value():
            value = self.failed_value()
            del value[key]
            with self.subTest(missing=key), self.assertRaises(self.adapter.Refused):
                self.adapter.returned_exec(value, self.SOURCE)
        failed = dict(self.failed_value(), originalGateStillHeld=False)
        self.assertEqual(self.adapter.returned_exec(failed, self.SOURCE), failed)

    def test_payload_main_union_requires_exact_original_predicate_facts(self):
        for phase in ("main-gate-refused", "main-handoff-refused", "main-admitted-before-appkit"):
            value = self.main_value(phase)
            self.assertEqual(self.adapter.payload_main(value, self.SOURCE), value)
            for key in value:
                changed = dict(value)
                del changed[key]
                with self.subTest(phase=phase, missing=key), self.assertRaises(self.adapter.Refused):
                    self.adapter.payload_main(changed, self.SOURCE)
            for key, bad in (("schemaVersion", True), ("source", "f" * 40), ("case", "ls-payload-absent"),
                             ("phase", "pre-main"), ("phase", []), ("extra", False),
                             ("selectedReturnCode", True), ("selectedReturnCode", 64)):
                with self.subTest(phase=phase, key=key), self.assertRaises(self.adapter.Refused):
                    self.adapter.payload_main(dict(value, **{key: bad}), self.SOURCE)
        gate = self.main_value("main-gate-refused")
        for key in ("gateMatchAccepted", *self.adapter.MAIN_FLAGS):
            with self.subTest(key=key), self.assertRaises(self.adapter.Refused):
                self.adapter.payload_main(dict(gate, **{key: True}), self.SOURCE)
        for phase in ("main-handoff-refused", "main-admitted-before-appkit"):
            value = self.main_value(phase)
            for key in self.adapter.MAIN_FLAGS:
                for bad in (None, 1, "true"):
                    with self.subTest(phase=phase, key=key, bad=bad), self.assertRaises(self.adapter.Refused):
                        self.adapter.payload_main(dict(value, **{key: bad}), self.SOURCE)
            with self.assertRaises(self.adapter.Refused):
                self.adapter.payload_main(dict(value, gateMatchAccepted=False), self.SOURCE)
        with self.assertRaises(self.adapter.Refused):
            self.adapter.payload_main(dict(self.main_value("main-handoff-refused"), entryPidPreserved=True), self.SOURCE)
        for key in self.adapter.MAIN_FLAGS[:3]:
            with self.subTest(key=key), self.assertRaises(self.adapter.Refused):
                self.adapter.payload_main(dict(self.main_value(), **{key: False}), self.SOURCE)
        # The original main predicate does not select66 on the executable flag.
        value = dict(self.main_value(), executableIsPayload=False)
        self.assertEqual(self.adapter.payload_main(value, self.SOURCE), value)

        empty = self.progress_value()
        self.assertEqual(self.adapter.appkit_progress(empty, self.SOURCE), empty)
        for invalid in (None, False, 0, [], "", {}, {**empty, "success": False}):
            with self.subTest(progress=invalid), self.assertRaisesRegex(self.adapter.Refused, "appkit-progress-slots"):
                self.adapter.appkit_progress(invalid, self.SOURCE)
        for slot, _, _ in self.APPKIT:
            missing = dict(empty)
            del missing[slot]
            with self.subTest(missing_slot=slot), self.assertRaisesRegex(self.adapter.Refused, "appkit-progress-slots"):
                self.adapter.appkit_progress(missing, self.SOURCE)
            for invalid in (False, 1, [], "record"):
                with self.subTest(slot=slot, row=invalid), self.assertRaises(self.adapter.Refused):
                    self.adapter.appkit_progress({**empty, slot: invalid}, self.SOURCE)
            for policy in ((True, False) if slot == "activationPolicy" else (True,)):
                progress = self.progress_value(slot, policy=policy)
                row = progress[slot]
                self.assertEqual(self.adapter.appkit_progress(progress, self.SOURCE), progress)
                for key in row:
                    changed = dict(row)
                    del changed[key]
                    with self.subTest(slot=slot, policy=policy, missing=key), self.assertRaises(self.adapter.Refused):
                        self.adapter.appkit_progress({**empty, slot: changed}, self.SOURCE)
                for key, invalid in (("schemaVersion", True), ("schemaVersion", "1"), ("schemaVersion", 0),
                                     ("source", "f" * 40), ("source", None), ("case", "direct"),
                                     ("phase", []), ("phase", "not-reached"), ("success", True)):
                    with self.subTest(slot=slot, policy=policy, key=key, invalid=invalid), \
                            self.assertRaises(self.adapter.Refused):
                        self.adapter.appkit_progress({**empty, slot: {**row, key: invalid}}, self.SOURCE)
                for other, _, phase in self.APPKIT:
                    if other != slot:
                        with self.subTest(slot=slot, mismatched_file_phase=phase), \
                                self.assertRaisesRegex(self.adapter.Refused, "appkit-progress-phase"):
                            self.adapter.appkit_progress({**empty, slot: {**row, "phase": phase}}, self.SOURCE)
                invalid_policy = (None, 0, 1, "true") if slot == "activationPolicy" else (False, True, 0, "null")
                for invalid in invalid_policy:
                    with self.subTest(slot=slot, invalid_policy=invalid), \
                            self.assertRaisesRegex(self.adapter.Refused, "appkit-progress-policy"):
                        self.adapter.appkit_progress({**empty, slot: {**row, "policySwitchAccepted": invalid}}, self.SOURCE)
                for invalid in (None, False, True, 0, 1, 66, 67, 74, 75, "67", "74", 67.0, 74.0):
                    if type(invalid) is type(row["selectedReturnCode"]) and invalid == row["selectedReturnCode"]:
                        continue
                    with self.subTest(slot=slot, policy=policy, invalid_return=invalid), \
                            self.assertRaisesRegex(self.adapter.Refused, "appkit-progress-selected-return"):
                        self.adapter.appkit_progress({**empty, slot: {**row, "selectedReturnCode": invalid}}, self.SOURCE)

    def test_boundary_correspondence_keeps_full_payload_evidence_separate(self):
        full = self.parse(self.value())
        main = self.main_value()
        value = self.adapter.boundary_diagnostic(full, 0, None, None, main, self.SOURCE)
        self.assertEqual(value["boundaryOutcome"], "full-payload-observed")
        self.assertTrue(value["expectedBoundaryObserved"])
        self.assertIsNone(full["originalAppExitStatus"])
        for gate, failed, main in ((self.gate_value(), None, None), (None, self.failed_value(), None),
                                   (None, None, self.main_value("main-gate-refused")),
                                   (None, None, self.main_value("main-handoff-refused"))):
            with self.assertRaisesRegex(self.adapter.Refused, "diagnostic-impossible-phase-records"):
                self.adapter.boundary_diagnostic(full, 0, gate, failed, main, self.SOURCE)
        for key in self.adapter.MAIN_FLAGS:
            changed = self.value()
            changed["payloadStart"][key] = False
            with self.subTest(key=key), self.assertRaisesRegex(self.adapter.Refused, "diagnostic-main-start-facts"):
                self.adapter.boundary_diagnostic(self.parse(changed), 0, None, None, self.main_value(), self.SOURCE)
        for status in (1, 64, 255):
            value = self.adapter.boundary_diagnostic(full, status, None, None, self.main_value(), self.SOURCE)
            self.assertFalse(value["expectedBoundaryObserved"])

        # Earlier callback/start DATA is compatible with a later unexpected
        # run return, but even otherwise-full native DATA cannot make it normal.
        for slots in (("runReturned",), tuple(slot for slot, _, _ in self.APPKIT)):
            progress = self.progress_value(*slots)
            result = self.adapter.boundary_diagnostic(full, 0, None, None, self.main_value(), self.SOURCE,
                                                      progress=progress)
            self.assertEqual(result["appKitProgress"], progress)
            self.assertEqual(result["boundaryOutcome"], "main-admitted-before-appkit")
            self.assertFalse(result["expectedBoundaryObserved"])
            self.assertIsNotNone(full["payloadStart"])
            self.assertIsNone(full["originalAppExitStatus"])
        partial = self.value()
        partial.update(firstFailure="observation-deadline", observationComplete=False,
                       normalQuitRequestSent=False, payloadQuit=None)
        progress = self.progress_value("didFinishLaunching", "runReturned")
        result = self.adapter.boundary_diagnostic(self.parse(partial), 1, None, None, self.main_value(), self.SOURCE,
                                                  progress=progress)
        self.assertEqual(result["appKitProgress"], progress)
        self.assertFalse(result["expectedBoundaryObserved"])
        # Absent best-effort witnesses do not erase the old independent gates.
        for slots in ((), ("didFinishLaunching",), ("activationPolicy", "beforeRun")):
            result = self.adapter.boundary_diagnostic(full, 0, None, None, self.main_value(), self.SOURCE,
                                                      progress=self.progress_value(*slots))
            self.assertEqual(result["boundaryOutcome"], "full-payload-observed")
            self.assertTrue(result["expectedBoundaryObserved"])

    def test_missing_main_and_late_phase_data_never_become_a_premain_diagnosis(self):
        for native, status in ((self.parse(self.value()), 0), (self.parse(self.early_value()), 1)):
            value = self.adapter.boundary_diagnostic(native, status, None, None, None, self.SOURCE)
            self.assertEqual(value["boundaryOutcome"], "unresolved")
            self.assertFalse(value["expectedBoundaryObserved"])
        for key, changed in (("timely", False), ("workDeadlineFailed", True), ("rootCloseReturned", False),
                             ("terminationObserved", False), ("exclusiveAvailableAfterTermination", False),
                             ("completionCount", 2), ("completionBodyDoneCount", 0)):
            native = self.early_value()
            native[key] = changed
            result = self.adapter.boundary_diagnostic(self.parse(native), 1, None, None, self.main_value(), self.SOURCE)
            self.assertEqual(result["boundaryOutcome"], "main-admitted-before-appkit")
            self.assertFalse(result["expectedBoundaryObserved"])
        path = Path("/private/tmp/mrk-m2-inert-root/payload-main.json")
        with patch.object(Path, "lstat", side_effect=FileNotFoundError), \
                patch.object(self.adapter, "read_file") as reader:
            self.assertIsNone(self.adapter.read_diagnostic(path, 501, 20))
            reader.assert_not_called()

        progress = self.progress_value(*(slot for slot, _, _ in self.APPKIT))
        for native, status in ((self.parse(self.value()), 0), (self.parse(self.early_value()), 1)):
            result = self.adapter.boundary_diagnostic(native, status, None, None, None, self.SOURCE,
                                                      progress=progress)
            self.assertEqual(result["appKitProgress"], progress)
            self.assertEqual(result["boundaryOutcome"], "unresolved")
            self.assertFalse(result["expectedBoundaryObserved"])
        for key, changed in (("timely", False), ("workDeadlineFailed", True), ("rootCloseReturned", False),
                             ("terminationObserved", False), ("exclusiveAvailableAfterTermination", False),
                             ("completionCount", 2), ("completionBodyDoneCount", 0), ("completionHandoffCount", 2)):
            native = self.early_value()
            native[key] = changed
            result = self.adapter.boundary_diagnostic(self.parse(native), 1, None, None, self.main_value(), self.SOURCE,
                                                      progress=progress)
            self.assertEqual(result["appKitProgress"], progress)
            self.assertEqual(result["boundaryOutcome"], "main-admitted-before-appkit")
            self.assertFalse(result["expectedBoundaryObserved"])

    def test_payload_main_sink_preserves_original_pool_guards_and_refusals(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "desktop/native/macos-m2-entry/payload.m").read_text()
        helper = source[source.index("static void publish_main_outcome("):source.index("int main(int argc, char **argv)")]
        main = source[source.index("int main(int argc, char **argv)"):]
        for forbidden in ("mrk_root(", "mrk_open_gate(", "mrk_gate_matches(", "mrk_exclusive_probe(",
                          "flock(", "fcntl(", "open(", "openat(", "NSApplication", "@autoreleasepool"):
            self.assertNotIn(forbidden, helper)
        self.assertEqual(helper.count("mrk_record("), 1)
        self.assertIn('(void)mrk_record(root_original, "payload-main.json", record);', helper)
        self.assertEqual(main.count("mrk_root("), 1)
        self.assertEqual(main.count("mrk_gate_matches("), 1)
        self.assertEqual(main.count("publish_main_outcome("), 3)
        order = [main.index(part) for part in (
            "@autoreleasepool {", "if (argc != 3 || !mrk_account()", "root_original = mrk_root();",
            "if (root_original < 0) return 65;", "int gate_matched = mrk_gate_matches(",
            "publish_main_outcome(MAIN_GATE_REFUSED);", "entry_pid_preserved = getpid() == original_pid;",
            "inherited_without_cloexec = fcntl(", "marked_cloexec = !fcntl(",
            "executable_is_payload = !_NSGetExecutablePath(", "if (!entry_pid_preserved ||",
            "publish_main_outcome(MAIN_HANDOFF_REFUSED);", "publish_main_outcome(MAIN_ADMITTED);",
            "NSApplication *app = NSApplication.sharedApplication;")]
        self.assertEqual(order, sorted(order))
        self.assertIn("publish_main_outcome(MAIN_GATE_REFUSED);\n            return 65;", main)
        self.assertIn("publish_main_outcome(MAIN_HANDOFF_REFUSED);\n            return 66;", main)
        for forbidden in ("constructor", "dup(", "dup2(", "F_DUPFD", "finishLaunching]"):
            self.assertNotIn(forbidden, source)
        entry = (root / "desktop/native/macos-m2-entry/entry.c").read_text()
        returned = entry[entry.index("    execve("):]
        self.assertLess(returned.index("int exec_error = errno;"), returned.index("root = mrk_root();"))
        self.assertIn('"execErrno\\":%d,', returned)
        self.assertIn("_exit(exec_error == ENOENT && held && written && root_closed ? 76 : 71);", returned)

        marker = "/* Five fixed progress witnesses, once per site through the admitted root.\n"
        self.assertEqual(source.count(marker), 1)
        start, end = source.index(marker), source.index("@interface M2Payload :")
        appkit = source[start:end]
        for forbidden in ("mrk_root(", "mrk_open_gate(", "mrk_gate_matches(", "mrk_exclusive_probe(",
                          "flock(", "fcntl(", "open(", "openat(", "NSApplication", "NSString", "@autoreleasepool"):
            self.assertNotIn(forbidden, appkit)
        self.assertEqual(self.adapter.re.findall(r"    (APPKIT_[A-Z_]+) = 1U << ([0-4])", appkit),
                         [("APPKIT_SHARED_RETURNED", "0"), ("APPKIT_POLICY_RETURNED", "1"),
                          ("APPKIT_BEFORE_RUN", "2"), ("APPKIT_DID_FINISH", "3"), ("APPKIT_RUN_RETURNED", "4")])
        self.assertEqual(appkit.count("case APPKIT_"), 5)
        self.assertEqual(source.count("appkit_attempted"), 3)
        self.assertEqual(source.count("static unsigned appkit_attempted;"), 1)
        self.assertEqual(appkit.count("mrk_record("), 1)
        self.assertIn("(void)mrk_record(root_original, name, record);", appkit)
        self.assertIn("char record[768];", appkit)
        self.assertIn("if (n > 0 && (size_t)n < sizeof(record))", appkit)
        attempt_order = [appkit.index(part) for part in (
            "default: return;", "unsigned bit = (unsigned)progress;", "if (appkit_attempted & bit) return;",
            "appkit_attempted |= bit;", "int n = snprintf(", "(void)mrk_record(")]
        self.assertEqual(attempt_order, sorted(attempt_order))
        for _, name, phase in self.APPKIT:
            self.assertEqual(appkit.count('"' + name + '"'), 1)
            self.assertEqual(appkit.count('"' + phase + '"'), 1)
        self.assertEqual(source.count("publish_appkit_progress("), 6)  # Definition plus five sites.
        for original in ("NSApplication.sharedApplication", "setActivationPolicy:", "[app run]"):
            self.assertEqual(source.count(original), 1)
        self.assertIn("NSApplication *app = NSApplication.sharedApplication;\n"
                      "        publish_appkit_progress(APPKIT_SHARED_RETURNED, NO);", main)
        self.assertIn("app.mainMenu = main;\n        publish_appkit_progress(APPKIT_BEFORE_RUN, NO);\n"
                      "        [app run];", main)
        for parts in (("const BOOL policy_accepted = [app setActivationPolicy:",
                       "const int selected_policy_return = policy_accepted ? 0 : 67;",
                       "publish_appkit_progress(APPKIT_POLICY_RETURNED, policy_accepted);",
                       "if (!policy_accepted) return selected_policy_return;"),
                      ("[app run];", "const int selected_run_return = 74;",
                       "publish_appkit_progress(APPKIT_RUN_RETURNED, NO);", "return selected_run_return;")):
            selected_order = [main.index(part) for part in parts]
            self.assertEqual(selected_order, sorted(selected_order))
        callback_start = source.index("- (void)applicationDidFinishLaunching:")
        callback_end = source.index("- (void)applicationDidBecomeActive:")
        callback = source[callback_start:callback_end]
        callback_call = "    publish_appkit_progress(APPKIT_DID_FINISH, NO);\n"
        self.assertIn("    (void)notification;\n" + callback_call + "    self.didFinishLaunching = YES;", callback)
        # Undo only the five new call-site splices and private helper/latch.
        # This must restore the complete accepted source, not a refreshed baseline.
        restored = source[:start] + source[end:]
        policy_capture = (
            "        const BOOL policy_accepted = [app setActivationPolicy:NSApplicationActivationPolicyRegular];\n"
            "        const int selected_policy_return = policy_accepted ? 0 : 67;\n"
            "        publish_appkit_progress(APPKIT_POLICY_RETURNED, policy_accepted);\n"
            "        if (!policy_accepted) return selected_policy_return;\n")
        run_return = (
            "        const int selected_run_return = 74;\n"
            "        publish_appkit_progress(APPKIT_RUN_RETURNED, NO);\n"
            "        return selected_run_return; /* Unexpected run-loop return is not normal Quit/finality. */\n")
        for added, original in (
                (callback_call, ""), ("        publish_appkit_progress(APPKIT_SHARED_RETURNED, NO);\n", ""),
                (policy_capture, "        if (![app setActivationPolicy:NSApplicationActivationPolicyRegular]) return 67;\n"),
                ("        publish_appkit_progress(APPKIT_BEFORE_RUN, NO);\n", ""),
                (run_return, "        return 74; /* Unexpected run-loop return is not normal Quit/finality. */\n")):
            self.assertEqual(restored.count(added), 1)
            restored = restored.replace(added, original, 1)
        self.assertEqual(len(restored.encode()), 8811)
        self.assertEqual(self.adapter.digest(restored.encode()),
                         "3ebbf701af360d2a6147ac5f688c1df4d2d8fef2ace55d748b6aa09417c532d2")
        old_callback = restored[restored.index("- (void)applicationDidFinishLaunching:"):
                                restored.index("- (void)applicationDidBecomeActive:")]
        self.assertEqual(callback.replace(callback_call, "", 1), old_callback)
        # Carry forward the preceding packet's older whole-payload reversal/pin.
        old_marker = "/* One best-effort phase record, only after the original main root admission.\n"
        old_start, old_end = restored.index(old_marker), restored.index("int main(int argc, char **argv)")
        older = restored[:old_start] + restored[old_end:]
        gate_capture = (
            "        if (root_original < 0) return 65;\n"
            "        int gate_matched = mrk_gate_matches(root_original, gate_original);\n"
            "        if (!gate_matched) {\n"
            "            publish_main_outcome(MAIN_GATE_REFUSED);\n"
            "            return 65;\n"
            "        }\n")
        handoff_capture = (
            "        if (!entry_pid_preserved || !inherited_without_cloexec || !marked_cloexec) {\n"
            "            publish_main_outcome(MAIN_HANDOFF_REFUSED);\n"
            "            return 66;\n"
            "        }\n")
        for added, original in (
                (gate_capture, "        if (root_original < 0 || !mrk_gate_matches(root_original, gate_original)) return 65;\n"),
                (handoff_capture, "        if (!entry_pid_preserved || !inherited_without_cloexec || !marked_cloexec) return 66;\n"),
                ("        publish_main_outcome(MAIN_ADMITTED);\n", "")):
            self.assertEqual(older.count(added), 1)
            older = older.replace(added, original, 1)
        self.assertEqual(len(older.encode()), 6922)
        self.assertEqual(self.adapter.digest(older.encode()),
                         "43c10da47c2584b459dccb1b0f01b8b4cc5067caa12fe5c342c8f530d26244cf")

    @contextmanager
    def created_root(self, gid=0):
        """Replace every filesystem call; object tokens cannot name real FDs."""
        adapter = self.adapter
        parent, root = object(), object()
        work = Path("/private/tmp/mrk-m2-inert-root")
        def info(inode, mode, uid, group):
            return dict(st_dev=7, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=group,
                        st_nlink=2, st_size=64, st_mtime_ns=100, st_ctime_ns=100)
        state = SimpleNamespace(parent=info(1, stat.S_IFDIR | 0o1777, 0, 0),
                                root=info(2, stat.S_IFDIR | 0o700, 501, gid),
                                parent_named={}, root_named={}, events=[], closed=[],
                                collision=False, group_error=False, group_unchanged=False,
                                after_group_named={}, close_failures=set(), diagnostics={})

        def opened(name, flags, *, dir_fd=None):
            self.assertEqual(flags, adapter.os.O_RDONLY | adapter.os.O_DIRECTORY | adapter.os.O_NOFOLLOW
                             | adapter.os.O_NONBLOCK | adapter.os.O_CLOEXEC)
            if dir_fd is None:
                self.assertEqual(name, work.parent)
                state.events.append("open-parent")
                return parent
            self.assertIs(dir_fd, parent)
            self.assertEqual(name, work.name)
            state.events.append("open-root")
            return root

        def mkdir(name, mode, *, dir_fd):
            self.assertEqual((name, mode), (work.name, 0o700))
            self.assertIs(dir_fd, parent)
            state.events.append("mkdir")
            if state.collision:
                raise FileExistsError("inert collision")

        def fstat(fd):
            self.assertIn(fd, (parent, root))
            return SimpleNamespace(**(state.parent if fd is parent else state.root))

        def named(name, *, follow_symlinks, dir_fd=None):
            self.assertFalse(follow_symlinks)
            if dir_fd is None:
                self.assertEqual(name, work.parent)
                return SimpleNamespace(**{**state.parent, **state.parent_named})
            self.assertIs(dir_fd, parent)
            self.assertEqual(name, work.name)
            state.events.append("named-root")
            return SimpleNamespace(**{**state.root, **state.root_named})

        def chown(fd, uid, group):
            self.assertIs(fd, root)
            self.assertEqual((uid, group), (-1, 20))
            state.events.append("select-group")
            if state.group_error:
                raise OSError("inert group failure")
            if not state.group_unchanged:
                state.root.update(st_gid=group, st_ctime_ns=101)
            state.root_named.update(state.after_group_named)

        def close(fd):
            self.assertIn(fd, (parent, root))
            self.assertNotIn(fd, state.closed)
            state.closed.append(fd)
            label = "root" if fd is root else "parent"
            state.events.append("close-" + label)
            if label in state.close_failures:
                raise OSError("inert close failure")

        with patch.object(adapter.os, "open", side_effect=opened), \
                patch.object(adapter.os, "mkdir", side_effect=mkdir), \
                patch.object(adapter.os, "fstat", side_effect=fstat), \
                patch.object(adapter.os, "stat", side_effect=named), \
                patch.object(adapter.os, "fchown", side_effect=chown), \
                patch.object(adapter.os, "close", side_effect=close):
            state.prepare = lambda: adapter.prepare_work_root(work, 501, 20, state.diagnostics)
            yield state

    def test_new_root_selects_inherited_group_before_establishing_original(self):
        for inherited in (0, 20):
            with self.subTest(inherited=inherited), self.created_root(inherited) as state:
                original = state.prepare()
                self.assertEqual(original, (7, 2, stat.S_IFDIR | 0o700, 501, 20))
                self.assertEqual(state.events.count("select-group"), int(inherited != 20))
                self.assertEqual(state.events[-2:], ["close-root", "close-parent"])
                self.assertEqual(state.diagnostics["initialRoot"]["gid"], inherited)
                self.assertEqual(state.diagnostics["finalRoot"]["gid"], 20)
                self.assertTrue(state.diagnostics["rootPrepared"])
                self.assertEqual(state.diagnostics["closeFailures"], [])
                if inherited != 20:
                    self.assertLess(state.events.index("named-root"), state.events.index("select-group"))

    def test_occupied_or_unproved_root_never_selects_a_group(self):
        cases = (("collision", None, None), ("parent", "st_mode", stat.S_IFDIR | 0o777),
                 ("parent", "st_uid", 501), ("parent_named", "st_ino", 99),
                 ("root", "st_uid", 502), ("root", "st_mode", stat.S_IFDIR | 0o750),
                 ("root_named", "st_ino", 99), ("root_named", "st_ctime_ns", 101))
        for target, field, value in cases:
            with self.subTest(target=target, field=field), self.created_root() as state:
                if target == "collision":
                    state.collision = True
                else:
                    getattr(state, target)[field] = value
                with self.assertRaises((self.adapter.Refused, FileExistsError)):
                    state.prepare()
                self.assertNotIn("select-group", state.events)
                self.assertFalse(state.diagnostics["rootPrepared"])
                self.assertEqual(state.events[-1], "close-parent")
                if target in ("parent", "parent_named", "collision"):
                    self.assertNotIn("open-root", state.events)

    def test_group_change_or_named_postcondition_failure_cannot_prepare_root(self):
        for case in ("group_error", "group_unchanged", "named-changed"):
            with self.subTest(case=case), self.created_root() as state:
                if case == "named-changed":
                    state.after_group_named["st_ino"] = 99
                else:
                    setattr(state, case, True)
                with self.assertRaises((self.adapter.Refused, OSError)):
                    state.prepare()
                self.assertFalse(state.diagnostics["rootPrepared"])
                self.assertEqual(state.events[-2:], ["close-root", "close-parent"])
                self.assertEqual(state.events.count("select-group"), 1)

    def test_close_failures_are_collected_once_and_block_root_admission(self):
        for failures in ({"root"}, {"parent"}, {"root", "parent"}):
            with self.subTest(failures=failures), self.created_root() as state:
                state.close_failures = failures
                with self.assertRaisesRegex(self.adapter.Refused, "fixture-(root|parent)-close"):
                    state.prepare()
                self.assertFalse(state.diagnostics["rootPrepared"])
                self.assertEqual(set(state.diagnostics["closeFailures"]), failures)
                self.assertEqual(state.events[-2:], ["close-root", "close-parent"])
        with self.created_root() as state:
            state.group_error, state.close_failures = True, {"root"}
            with self.assertRaisesRegex(OSError, "inert group failure"):
                state.prepare()
            self.assertEqual(state.diagnostics["closeFailures"], ["root"])
            self.assertEqual(state.events[-2:], ["close-root", "close-parent"])

    def test_gate_admission_requires_native_shape_and_selected_root_account(self):
        valid = (7, 3, stat.S_IFREG | 0o444, 501, 20, 1, 0, 100, 100)
        diagnostics = {}
        path = Path("/private/tmp/mrk-m2-inert-root/maintenance-use.lock")
        with patch.object(self.adapter, "read_file", return_value=(b"", valid)) as reader:
            self.assertEqual(self.adapter.admit_gate(path, 501, 20, diagnostics), valid)
            reader.assert_called_once_with(path, 0)
        self.assertEqual(diagnostics["gate"]["gid"], 20)
        for index, value in ((2, stat.S_IFREG | 0o644), (2, stat.S_IFDIR | 0o444),
                             (3, 502), (4, 0), (5, 2), (6, 1)):
            changed = list(valid); changed[index] = value
            with self.subTest(index=index, value=value), \
                    patch.object(self.adapter, "read_file", return_value=(b"", tuple(changed))), \
                    self.assertRaisesRegex(self.adapter.Refused, "fixture-gate-shape-owner"):
                self.adapter.admit_gate(path, 501, 20, {})

    def test_fixture_admission_precedes_every_native_tool_call(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "desktop/tools/macos_m2_entry_feasibility.py").read_text()
        main = source[source.index("def main():"):]
        phases = [main.index(part) for part in (
            'work_original = prepare_work_root(', 'for name in ("build", "tmp", "app-tmp", "evidence"):',
            'write_new(work / "maintenance-use.lock"', 'gate_original = admit_gate(',
            'write_new(work / "build/fixture_config.h"', 'version = zero("compiler-version"')]
        self.assertEqual(phases, sorted(phases))
        self.assertIn('signature(work.lstat())[:5] == work_original, "work-changed"', main)

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
