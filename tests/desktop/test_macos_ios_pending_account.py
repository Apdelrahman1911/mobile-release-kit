"""Bounded DATA regressions only; no core/native import, child or account action.

The literal native producer is inspected as SOURCE and is never executed here.
Synthetic reports below cannot provide runtime/native qualification evidence.
"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import stat
from subprocess import CompletedProcess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[2]
PATH = ROOT / "desktop/tools/macos_aqua_qualification.py"
SPEC = importlib.util.spec_from_file_location("_mrk_pending_account_data", PATH)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
UID, GID = 501, 20
BINDING = M.Binding("a" * 40, "123", "1")


def private_data():
    home = "/Users/runner"
    return {"home": home, "homeIdentity": [7, 1, stat.S_IFDIR | 0o700, UID, GID],
            "leaseIdentity": [7, 2, stat.S_IFDIR | 0o700, UID, GID],
            "sessionIdentity": [7, 3, stat.S_IFDIR | 0o700, UID, GID],
            "nativeIdentity": [7, 4, stat.S_IFDIR | 0o700, UID, GID], "token": "e" * 32,
            "baseline": {"default": home + "/Library/Keychains/login.keychain-db", "search": [home + "/Library/Keychains/login.keychain-db"]},
            "members": [{"path": home + "/Library/Keychains/login.keychain-db", "identity": [7, 5, stat.S_IFREG | 0o600, UID, GID, 1]}],
            "controls": {name: {"bytes": 2, "sha256": M.digest(b"{}")} for name in ("intent.json", "state.json")},
            "native": {"signing.keychain-db": {"device": 7, "inode": 6}}}


def child_data(mode):
    result = {"schemaVersion": 1, "scope": "real-core-pending-account-fixture-v1" if mode == "produce" else "real-core-account-baseline-readback-v1",
              "case": M.IOS_ACCOUNT_CASE, "commands": 17 if mode == "produce" else 2, "profileCalls": 0,
              "commandFinalities": True, "leaseClosed": True, "sessionClosed": True, "handlersRestored": True,
              "fixtureDescriptorsClosed": True, "originalDeadlineMet": True, "keychainContentsRead": False}
    if mode == "produce":
        result.update(pendingLeft=True, private=private_data())
    else:
        result.update(pendingAbsent=True, baselinePreferencesMatched=True, baselineMemberIdentitiesMatched=True)
    return result


def returned(argv, mode, value=None):
    return CompletedProcess(argv, 0, json.dumps(child_data(mode) if value is None else value, separators=(",", ":")).encode() + b"\n", b"")


class InertAccountFixtures:
    def __init__(self):
        self.cases = (M.IOS_ACCOUNT_CASE,)
        self.path = BINDING.root()
        self.inflight = self.last_returned = False
        self.account_produced = self.account_app_returned = self.account_readback = False
        self.account_attempts = {"produce": False, "observe": False}
        self.account_private_sha = "f" * 64
        self.account_home = "/Users/runner"
        self.events = []

    def recovery_runtime_paths(self):
        if self.inflight:
            raise AssertionError("runtime read during unknown invocation")
        return "/inert-installed/python3", "/inert-installed/core.zip"

    def accept_account_producer(self, value):
        if self.inflight or not self.last_returned:
            raise AssertionError("producer did not return")
        self.events.append("producer-accepted")
        self.account_produced = True

    def _account_current(self, *, after):
        if self.inflight:
            raise AssertionError("readback during unknown invocation")
        self.events.append("after-readback" if after else "before-readback")


class PendingAccountRecoveryDataTests(unittest.TestCase):
    def test_pair_matches_closed_dynamic_originals_and_every_finality_is_required(self):
        value = M._expected_ios_pending_report()
        for i, (operation, generation) in enumerate((("1" * 32, "2" * 32), ("3" * 32, "4" * 32))):
            value["prepared"][i].update(operationId=operation, ownerGeneration=generation)
            value["prepared"][i]["context"]["projectId"] = "current-project"
            value["originals"][i]["facts"].update(operationId=operation, ownerGeneration=generation)
            value["originals"][i]["terminal"]["report"]["account"]["session"] = "9" * 32
        value["prepared"][1]["context"]["recovery"]["session"] = "9" * 32
        value["statusCallsReturned"] = 12
        self.assertEqual(M._ios_pending_report(value), value)
        for i in range(2):
            facts = value["originals"][i]["facts"]
            for field, entry in facts.items():
                if type(entry) is bool:
                    bad = deepcopy(value); bad["originals"][i]["facts"][field] = not entry
                    with self.subTest(original=i, field=field), self.assertRaises(M.Refused):
                        M._ios_pending_report(bad)
            for field in ("complete", "contained", "handlersRestored", "inputClosed", "invocationClosed", "snapshotClosed",
                          "filesClosed", "namespaceClosed", "signingClosed", "buildInputsClosed", "materialRetired"):
                bad = deepcopy(value); bad["originals"][i]["terminal"]["lifetime"][field] = False
                with self.subTest(original=i, field=field), self.assertRaises(M.Refused):
                    M._ios_pending_report(bad)

    def test_pair_refuses_reused_session_order_consent_and_changed_budget(self):
        mutations = (
            lambda v: v["originals"].reverse(),
            lambda v: v["prepared"][1].update(operationId=v["prepared"][0]["operationId"]),
            lambda v: v["prepared"][1].update(ownerGeneration=v["prepared"][0]["ownerGeneration"]),
            lambda v: v["originals"][1]["terminal"]["report"]["account"].update(session="f" * 32),
            lambda v: v["originals"][0]["terminal"]["report"]["account"].update(next="manual"),
            lambda v: v["originals"][1]["terminal"]["lifetime"].update(commands=0),
            lambda v: v["originals"][1]["terminal"]["lifetime"].update(commands=33),
            lambda v: v["originals"][1]["terminal"]["lifetime"].update(profileCalls=1),
            lambda v: v.update(freshUncheckedReviews=False), lambda v: v.update(explicitAcknowledgements=False),
            lambda v: v.update(observationMs=515001), lambda v: v.update(outerInvocationMs=525001),
            lambda v: v.update(requests=[1, 1, 1, 2]), lambda v: v.update(statusCallsReturned=True),
            lambda v: v.update(shippingBinaryQualified=True), lambda v: v.update(extra=True),
        )
        for mutation in mutations:
            value = M._expected_ios_pending_report(); mutation(value)
            with self.subTest(mutation=mutations.index(mutation)), self.assertRaises(M.Refused):
                M._ios_pending_report(value)

    def test_private_baseline_is_finite_same_account_and_never_keychain_contents(self):
        original = private_data()
        self.assertEqual(M._ios_account_private(original, UID, "/Users/runner"), original)
        mutations = (
            lambda v: v.update(home="/Users/another"), lambda v: v.update(token="foreign"),
            lambda v: v["homeIdentity"].__setitem__(3, 0), lambda v: v["leaseIdentity"].__setitem__(2, stat.S_IFDIR | 0o775),
            lambda v: v["baseline"].update(search=[]), lambda v: v["baseline"].update(search=v["baseline"]["search"] * 9),
            lambda v: v["baseline"].update(default="/Users/runner/foreign"),
            lambda v: v["members"][0].update(path="/Users/another/Library/Keychains/login.keychain-db"),
            lambda v: v["members"][0]["identity"].__setitem__(2, stat.S_IFLNK | 0o600),
            lambda v: v["members"][0]["identity"].__setitem__(5, 2),
            lambda v: v["native"]["signing.keychain-db"].update(inode=5),
            lambda v: v["controls"]["state.json"].update(bytes=512*1024+1),
            lambda v: v.update(keychainContents="must-never-be-accepted"),
        )
        for mutation in mutations:
            value = deepcopy(original); mutation(value)
            with self.subTest(mutation=mutations.index(mutation)), self.assertRaises(M.Refused):
                M._ios_account_private(value, UID, "/Users/runner")
        value = deepcopy(original); raw = "/Users/runner/Library/Keychains/../foreign"
        value["baseline"] = {"default": raw, "search": [raw]}; value["members"][0]["path"] = raw
        with self.assertRaises(M.Refused): M._ios_account_private(value, UID, "/Users/runner")

    def test_private_receipt_refuses_incomplete_ambiguous_or_unbounded_returns(self):
        for mode in ("produce", "observe"):
            good = returned([], mode)
            self.assertEqual(M._ios_account_child_result(good, mode, UID, "/Users/runner"), child_data(mode))
            for result in (CompletedProcess([], 1, good.stdout, b""), CompletedProcess([], 0, good.stdout, b"error"),
                           CompletedProcess([], 0, good.stdout + good.stdout, b""), CompletedProcess([], 0, b"{}" * 9000 + b"\n", b""),
                           CompletedProcess([], 0, b'{"x":1,"x":2}\n', b""), CompletedProcess([], 0, b"{\n", b"")):
                with self.assertRaises(M.Refused): M._ios_account_child_result(result, mode, UID, "/Users/runner")
            for field in ("commandFinalities", "leaseClosed", "sessionClosed", "handlersRestored", "fixtureDescriptorsClosed", "originalDeadlineMet"):
                value = child_data(mode); value[field] = False
                with self.assertRaises(M.Refused): M._ios_account_child_result(returned([], mode, value), mode, UID, "/Users/runner")

    def test_original_child_clocks_clean_environment_and_one_use_calls(self):
        fixture = InertAccountFixtures(); calls = []
        def owner(argv, **options):
            mode = argv[7]; calls.append(mode)
            self.assertEqual(argv[1:5], ["-I", "-S", "-B", "-c"])
            self.assertEqual(argv[5], M.IOS_ACCOUNT_CORE_PROGRAM)
            self.assertEqual(options["timeout"], 180 if mode == "produce" else 90)
            self.assertEqual(options["output_limit"], 16*1024 if mode == "produce" else 2048)
            self.assertNotIn("HOME", options["environ"])
            self.assertEqual(set(options["environ"]), {"TMPDIR", "PATH", "LANG", "LC_ALL", "TZ", "USER", "LOGNAME", "__CF_USER_TEXT_ENCODING"})
            self.assertEqual(int(argv[9]), 1_000_000_000 + (150 if mode == "produce" else 60)*1_000_000_000)
            self.assertEqual(int(argv[10]) - int(argv[9]), 25_000_000_000)
            self.assertTrue(fixture.inflight)
            return returned(argv, mode)
        with patch("time.monotonic_ns", side_effect=[1_000_000_000, 2_000_000_000, 3_000_000_000]):
            M._run_ios_account_child(fixture, owner, UID, "runner", "produce")
        self.assertFalse(fixture.inflight); self.assertTrue(fixture.last_returned)
        with self.assertRaises(M.Refused): M._run_ios_account_child(fixture, owner, UID, "runner", "produce")
        with self.assertRaises(M.Refused): M._run_ios_account_child(fixture, owner, UID, "runner", "observe")
        fixture.account_app_returned = True
        with patch("time.monotonic_ns", side_effect=[1_000_000_000, 2_000_000_000, 3_000_000_000]):
            M._run_ios_account_child(fixture, owner, UID, "runner", "observe")
        self.assertEqual(calls, ["produce", "observe"])
        self.assertTrue(fixture.account_readback)
        with self.assertRaises(M.Refused): M._run_ios_account_child(fixture, owner, UID, "runner", "observe")

    def test_unknown_or_late_original_return_never_enters_app_or_readback(self):
        error = RuntimeError("inert lost original return")
        def lost(*args, **kwargs): raise error
        def foreign(argv, **kwargs): return returned(["foreign"], "produce")
        for owner in (lost, foreign):
            fixture = InertAccountFixtures()
            with patch("time.monotonic_ns", return_value=1_000_000_000):
                with self.assertRaises((RuntimeError, M.Refused)) as raised:
                    M._run_ios_account_child(fixture, owner, UID, "runner", "produce")
            if owner is lost: self.assertIs(raised.exception, error)
            self.assertTrue(fixture.inflight); self.assertFalse(fixture.last_returned)
            self.assertFalse(fixture.account_produced); self.assertEqual(fixture.events, [])
            with self.assertRaises(M.Refused): M._run_ios_account_child(fixture, owner, UID, "runner", "observe")
        fixture = InertAccountFixtures()
        with patch("time.monotonic_ns", side_effect=[1_000_000_000, 176_000_000_000]):
            with self.assertRaises(M.Refused):
                M._run_ios_account_child(fixture, lambda argv, **kw: returned(argv, "produce"), UID, "runner", "produce")
        self.assertFalse(fixture.inflight); self.assertTrue(fixture.last_returned)
        self.assertFalse(fixture.account_produced); self.assertTrue(fixture.account_attempts["produce"])
        self.assertEqual(fixture.events, [])

    def test_three_originals_are_serial_and_failure_never_dispatches_the_next_leg(self):
        class Fixtures(InertAccountFixtures):
            def before_call(inner, case):
                self.assertTrue(inner.account_produced); self.assertFalse(inner.inflight)
                inner.events.append("before-app")

            def accept_account_app(inner, report):
                self.assertFalse(inner.inflight); self.assertTrue(inner.last_returned)
                M._ios_pending_report(report)
                inner.account_app_returned = True
                inner.events.append("app-accepted")

            def readback_account(inner, report):
                self.assertTrue(inner.account_readback); self.assertFalse(inner.inflight)
                M._ios_pending_report(report)
                inner.events.append("final-readback")
                return {"inertComparisonOnly": True}

        for fault in (None, "producer-unknown", "app-failed"):
            fixture = Fixtures(); calls = []; emitted = []
            def owner(argv, **options):
                self.assertTrue(fixture.inflight)
                if argv[0] == M.EXECUTABLE:
                    calls.append("app")
                    self.assertTrue(fixture.account_produced)
                    value = M.expected_result(BINDING, M.IOS_ACCOUNT_CASE)
                    body = M.MARKER + json.dumps(value, separators=(",", ":")).encode() + b"\n"
                    return CompletedProcess(argv, 1 if fault == "app-failed" else 0, body, b"")
                mode = argv[7]; calls.append(mode)
                if fault == "producer-unknown": raise RuntimeError("inert unknown original")
                if mode == "observe": self.assertTrue(fixture.account_app_returned)
                return returned(argv, mode)
            with patch("time.monotonic_ns", return_value=1_000_000_000):
                if fault is None:
                    self.assertEqual(M.run_cases(BINDING, fixture, owner, UID, "runner", emitted.append, M.IOS_ACCOUNT_CASE), ())
                else:
                    with self.assertRaises((M.Refused, RuntimeError)):
                        M.run_cases(BINDING, fixture, owner, UID, "runner", emitted.append, M.IOS_ACCOUNT_CASE)
            self.assertEqual(calls, ["produce"] if fault == "producer-unknown" else ["produce", "app"] if fault else ["produce", "app", "observe"])
            self.assertEqual(len(emitted), 0 if fault else 1)
            if fault is None: self.assertEqual(fixture.events[-1], "final-readback")
            self.assertEqual(fixture.inflight, fault == "producer-unknown")

    def test_account_descriptor_limit_precedes_open_and_close_is_consuming(self):
        fixture = M.Fixtures(BINDING, UID, GID, M.IOS_ACCOUNT_CASE)
        fixture.account_fds = set(range(32))
        with patch.object(fixture, "_open", side_effect=AssertionError("must not open")) as opened:
            with self.assertRaises(M.Refused): fixture._account_open("inert")
            opened.assert_not_called()
        fixture.fds = {99}; fixture.account_fds = {99}
        with patch.object(M.os, "close", side_effect=OSError("inert close result unavailable")) as closed:
            self.assertFalse(fixture._close(99))
            self.assertNotIn(99, fixture.fds); self.assertNotIn(99, fixture.account_fds)
            with self.assertRaises(M.Refused): fixture._close(99)
            closed.assert_called_once_with(99)
        self.assertEqual(fixture.close_errors, 1); self.assertIsNotNone(fixture.first_close_error)

    def test_independent_readback_refuses_baseline_substitution_or_retained_owned_name(self):
        fixture = M.Fixtures(BINDING, UID, GID, M.IOS_ACCOUNT_CASE)
        fixture.account_private = private_data(); fixture.account_home = "/Users/runner"; fixture.account_lease = 11
        fixture._roster = lambda fd, roster, label: self.assertEqual((fd, roster), (11, ()))
        baseline = (7, 5, stat.S_IFREG | 0o600, UID, GID, 1, 12, 100, 100)
        owned = (7, 6, stat.S_IFREG | 0o600, UID, GID, 1, 12, 100, 100)
        fixture.account_baseline_files = [(18, "login.keychain-db", 14, baseline)]
        fixture.account_native_files = [(13, "signing.keychain-db", 15, owned, None)]
        live = {14: baseline, 15: (*owned[:5], 0, *owned[6:])}
        named = {(18, "login.keychain-db"): baseline}
        def info(row):
            return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), row)))
        def named_info(name, *, dir_fd, follow_symlinks):
            self.assertIs(follow_symlinks, False)
            if (dir_fd, name) not in named: raise FileNotFoundError()
            return info(named[dir_fd, name])
        with patch.object(M.os, "fstat", side_effect=lambda fd: info(live[fd])), patch.object(M.os, "stat", side_effect=named_info):
            fixture._account_current(after=True)
            named[18, "login.keychain-db"] = (7, 105, *baseline[2:])
            with self.assertRaises(M.Refused): fixture._account_current(after=True)
            named[18, "login.keychain-db"] = baseline
            live[15] = owned
            with self.assertRaises(M.Refused): fixture._account_current(after=True)
            live[15] = (*owned[:5], 0, *owned[6:]); named[13, "signing.keychain-db"] = owned
            with self.assertRaises(M.Refused): fixture._account_current(after=True)

    def test_closed_scope_fixture_and_public_parser_do_not_widen_nine_case_roster(self):
        self.assertEqual(M.argument_scope(["--scope", M.IOS_ACCOUNT_CASE]), M.IOS_ACCOUNT_CASE)
        self.assertEqual(M.selected_cases(M.IOS_ACCOUNT_CASE), (M.IOS_ACCOUNT_CASE,))
        self.assertNotIn(M.IOS_ACCOUNT_CASE, M.IOS_CURRENT_CASES); self.assertEqual(len(M.IOS_CURRENT_CASES), 9)
        self.assertEqual(M.case_timeout(M.IOS_ACCOUNT_CASE), 525)
        files, directories = M.fixture_data(M.IOS_ACCOUNT_CASE, False)
        self.assertEqual(set(files), {".gitignore", "keep.txt"})
        self.assertEqual(M.fixture_data(M.IOS_ACCOUNT_CASE, True), (files, directories))
        value = M.expected_result(BINDING, M.IOS_ACCOUNT_CASE)
        capture = M.MARKER + json.dumps(value, separators=(",", ":")).encode() + b"\n"
        self.assertLessEqual(len(capture) - len(M.MARKER) - 1, M.JSON_LIMIT)
        self.assertEqual(M.parse_result(capture, b"", BINDING, M.IOS_ACCOUNT_CASE), value)

    def test_current_core_source_and_targeted_workflow_preserve_owners_and_private_data(self):
        source = M.IOS_ACCOUNT_CORE_PROGRAM
        for required in ("signing.local_signing_lease(cancellation=guard)", "session.open(create=True)", "session.prepare(",
                         "session.activate()", "session.observe(journal=False)", "command_finality()", "scope.__exit__(*sys.exc_info())",
                         "time.monotonic_ns()<work", "time.monotonic_ns()<final", "len(fds)<32", "len(baseline[\"search\"])<=8"):
            self.assertIn(required, source)
        for forbidden in ("session.cleanup_native(", "session.cleanup_profile(", "session.finish(", "_normal_execution_revoked = False",
                          "delete-keychain", "security import", "os.unlink(", "os.rmdir(", "subprocess.run(", "subprocess.Popen("):
            self.assertNotIn(forbidden, source)
        self.assertIn('result=run_owned(argv,**options);row[2]=result', source)
        owner = (ROOT / "desktop/src-tauri/src/saved_command_owner.rs").read_text()
        for gate in ("IOS_SIGNED_NATIVE_QUALIFIED", "IOS_RECOVERY_NATIVE_QUALIFIED"):
            self.assertIn(f"const {gate}: bool = false;", owner)
        self.assertIn('originals: [Option<InstalledIOSOriginal>; 2]', owner)
        self.assertIn('Arc::ptr_eq(&inspected.original, &first.original)', owner)
        self.assertIn('observation.control.slot_for(selected)', owner)
        # Legacy signed/unsigned cases remain slot0-only. Both overrides are
        # compiled only on the intended native observation target; keep their
        # existing clocks while preventing a removed single-original field
        # from escaping focused local SOURCE checks.
        signed = owner.split("let clocks = if prepared.projection.context.signed_ios()\n", 1)[1].split("let material_matches", 1)[0]
        unsigned = owner.split("fn start_clocks(&self, admitted: Instant) -> Clocks {", 1)[1].split("fn offline_installed_selected", 1)[0]
        for block, operation, selected in ((signed, "IOSSignedExport", "Clocks::installed_ios_signed(admitted_at)"),
                                           (unsigned, "IOSUnsignedArchive", "Clocks::installed_ios(admitted)")):
            self.assertIn(f"o.originals[0].is_none() && o.control.permits_mode(ios_wire::Operation::{operation})", block)
            self.assertNotIn("o.original.", block)
            self.assertIn(selected, block)
        workflow = (ROOT / ".github/workflows/desktop-macos-aqua.yml").read_text()
        self.assertEqual(workflow.count("macos_aqua_qualification.py --scope ios-recovery-pending"), 1)
        step = workflow.split("      - name: One real pending account recovery through ordinary Inspect and exact Recover\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("timeout-minutes: 15", step)
        self.assertIn("[[ $status == 0 ]] || exit \"$status\"", step)
        exports = workflow.split("      - name: Preserve bounded original evidence; upload alone is not an Aqua pass\n", 1)[1].split("      - name:", 1)[0]
        self.assertNotIn("account-baseline.json", exports); self.assertNotIn(".mobile-release-signing", exports)
        for leaf in ("aqua-ios-account-results.jsonl", "aqua-ios-account-failure.jsonl", "aqua-ios-account.status"):
            self.assertIn("${{ steps.work.outputs.root }}/" + leaf + "\n", exports)


if __name__ == "__main__":
    unittest.main()
