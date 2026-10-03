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
        return {"schemaVersion": 1, "source": self.SOURCE, "case": "ls-payload-absent",
                "phase": "entry-gate-admission", "selectedReturnCode": 66,
                "originalRootDescriptor": 0, "gateOpenDescriptor": 1,
                "gateOpenErrno": None, "gateMatchAccepted": False,
                "rejectedGateCloseReturned": True}

    def failed_value(self):
        return {"schemaVersion": 1, "source": self.SOURCE,
                "execReturnedENOENT": True, "originalGateStillHeld": True}

    def test_startup_diagnostic_distinguishes_gate_and_failed_exec_without_feasibility(self):
        native = self.parse(self.early_value())
        for gate in (self.gate_value(),
                     dict(self.gate_value(), originalRootDescriptor=3, gateOpenDescriptor=4),
                     dict(self.gate_value(), gateOpenDescriptor=-1, gateOpenErrno=24,
                          gateMatchAccepted=None, rejectedGateCloseReturned=None)):
            with self.subTest(gate=gate):
                value = self.adapter.startup_diagnostic(native, 1, gate, None, self.SOURCE)
                self.assertEqual(value["entryOutcome"], "entry-gate-refused")
                self.assertEqual(value["entryGateRefusal"], gate)
                self.assertIsNone(value["failedExec"])
                self.assertTrue(value["expectedControlObserved"])
        failed = self.failed_value()
        value = self.adapter.startup_diagnostic(native, 1, None, failed, self.SOURCE)
        self.assertEqual(value["entryOutcome"], "entry-reached-exec-enoent")
        self.assertEqual(value["failedExec"], failed)
        self.assertTrue(value["expectedControlObserved"])
        self.assertFalse(self.adapter.supported_observation(native))
        self.assertIsNone(native["originalAppExitStatus"])
        self.assertEqual(native["allWorkerFinality"], "not-established-by-NSRunningApplication")
        self.assertEqual(native["firstFailure"], "payload-terminated-before-observation")

    def test_startup_diagnostic_rejects_conflict_and_cannot_complete_unknown_late_or_close_failure(self):
        native = self.parse(self.early_value())
        value = self.adapter.startup_diagnostic(native, 1, None, None, self.SOURCE)
        self.assertEqual(value["entryOutcome"], "unresolved")
        self.assertFalse(value["expectedControlObserved"])
        with self.assertRaisesRegex(self.adapter.Refused, "diagnostic-conflicting-outcomes"):
            self.adapter.startup_diagnostic(native, 1, self.gate_value(), self.failed_value(), self.SOURCE)
        gate = dict(self.gate_value(), rejectedGateCloseReturned=False)
        value = self.adapter.startup_diagnostic(native, 1, gate, None, self.SOURCE)
        self.assertEqual(value["entryOutcome"], "entry-gate-refused")
        self.assertFalse(value["expectedControlObserved"])
        for flag in ("execReturnedENOENT", "originalGateStillHeld"):
            failed = self.failed_value()
            failed[flag] = False
            value = self.adapter.startup_diagnostic(native, 1, None, failed, self.SOURCE)
            self.assertEqual(value["entryOutcome"], "unresolved")
            self.assertFalse(value["expectedControlObserved"])
        for status in (0, 64, 255):
            self.assertFalse(self.adapter.startup_diagnostic(
                native, status, self.gate_value(), None, self.SOURCE)["expectedControlObserved"])
        for status in (True, -1, 256, "1"):
            with self.assertRaisesRegex(self.adapter.Refused, "diagnostic-owner-status"):
                self.adapter.startup_diagnostic(native, status, self.gate_value(), None, self.SOURCE)
        changes = (("timely", False), ("workDeadlineFailed", True), ("rootCloseReturned", False),
                   ("terminationObserved", False), ("exclusiveAvailableAfterTermination", False),
                   ("launchRequested", False), ("launchReferenceReturned", False),
                   ("launchErrorReported", True), ("normalQuitRequestSent", True),
                   ("referencePIDMatchesPayload", True), ("exclusiveBlockedWhilePayloadAlive", True),
                   ("referenceExecutableIsEntry", True), ("observationComplete", True),
                   ("firstFailure", "root-close"), ("completionCount", 2),
                   ("completionBodyDoneCount", 0), ("completionHandoffCount", 2),
                   ("payloadStart", self.value()["payloadStart"]), ("payloadQuit", self.value()["payloadQuit"]))
        for key, changed in changes:
            value = self.early_value()
            value[key] = changed
            with self.subTest(key=key):
                result = self.adapter.startup_diagnostic(
                    self.parse(value), 1, self.gate_value(), None, self.SOURCE)
                self.assertFalse(result["expectedControlObserved"])

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
        self.assertLess(main.index('for name in ("Mobile Release Kit.app", *DIAGNOSTIC_RECORDS'), main.index(launch))
        self.assertNotIn('bundle("Mobile Release Kit.app"', main)
        self.assertNotIn('call("exclusive-refusal"', main)
        self.assertNotIn('call("real-failed-exec"', main)
        self.assertNotIn('report["feasibilityObserved"] =', main)
        self.assertIn('"feasibilityObserved": False', main)
        self.assertIn('report["diagnosticComplete"] = diagnostic_complete', main)
        self.assertIn('return 0 if diagnostic_complete else 1', main)
        self.assertIn('result = owner.run_owned(argv, environ=environment, cwd=work, timeout=timeout,', main)

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
