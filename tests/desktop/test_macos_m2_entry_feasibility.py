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
