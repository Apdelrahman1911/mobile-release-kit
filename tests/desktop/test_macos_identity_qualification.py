"""Public private-FS fixtures through the actual identity transaction core.

No Mac, process, build, Store or installed finality is simulated/qualified.
The exact precursor body is exercised on the main thread; its late mutation
never replaces a transaction result or suppresses original cleanup.
"""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

from mobile_release import init_transaction as tx, project_identity as identity
from mobile_release import project_identity_edit as edit, project_identity_recovery as recovery
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.errors import ValidationError
from mobile_release.init_workspace_custody import InitRootLease
from mobile_release.api._snapshot import project_snapshot

LEAF = Path(__file__).resolve().parents[2] / "desktop/tools/macos_identity_qualification.py"
spec = importlib.util.spec_from_file_location("identity_qualification", LEAF)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
namespace = {}
exec(compile(fixture.PRODUCER_BODY, "<fixed identity precursor>", "exec"), namespace)
produce = namespace["produce"]


def snapshot(root):
    return {p.relative_to(root).as_posix(): ((s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns), p.read_bytes())
            for p in root.rglob("*") if p.is_file() for s in (p.stat(),)}


class IdentityInstalledFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mrk-identity-qualification-")
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)

    def root(self, case):
        root = self.parent / case
        root.mkdir(mode=0o700)
        rows, directories = fixture.fixture_data(case, False)
        for name in directories:
            if name != ".":
                (root / name).mkdir(mode=0o700)
        for name, body in rows.items():
            (root / name).write_bytes(body)
            (root / name).chmod(0o600)
        return root

    @contextmanager
    def lease(self, root, recover=False):
        s = root.stat()
        guard = DefaultCancellation(ValidationError, "identity fixture close failed")
        lease = InitRootLease(root, cancellation=guard, profile=tx.TypedEditProfile.PROJECT_IDENTITY,
            registered_identity={"device": s.st_dev, "inode": s.st_ino, "mode": s.st_mode, "uid": s.st_uid, "gid": s.st_gid},
            identity_recovery=recover)
        scope = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
        try:
            with scope:
                guard.install(); guard.activate(); lease.acquire()
                yield lease
        finally:
            scope.__exit__(*sys.exc_info())
        self.assertTrue(lease.closed)
        self.assertFalse(guard.lifetime_ledger.fatal)
        self.assertEqual(guard.handler_state, "RESTORED")

    def test_literal_android_and_ios_prepare_close_then_real_apply(self):
        for case in fixture.CASES[:2]:
            with self.subTest(case=case):
                root = self.root(case)
                original = snapshot(root)
                selected = identity.IdentitySelection("ios", "Reader", "iosApp/Reader.xcodeproj", "unknown") if case == fixture.CASES[1] else identity.IdentitySelection("android", ":app", continuity="unknown")
                # Exact explicit preview remains read-only, then real Close.
                with self.lease(root) as lease:
                    captured = edit.capture_project_identity_edit(lease, selected)
                    self.assertEqual(captured.view["state"], "supported", captured.view)
                    plan = edit.prepare_project_identity_edit(lease, captured, expected_revision=captured.revision,
                        desired_identity=fixture.NEW, intent="new-application")
                    self.assertEqual(snapshot(root), original)
                    edit.discard_project_identity_edit(plan)
                self.assertEqual(snapshot(root), original)
                with self.lease(root) as lease:
                    captured = edit.capture_project_identity_edit(lease, selected)
                    plan = edit.prepare_project_identity_edit(lease, captured, expected_revision=captured.revision,
                        desired_identity=fixture.NEW, intent="new-application")
                    result = edit.apply_project_identity_edit(lease, plan)
                    self.assertEqual((result.effect, result.journal, result.resources, result.reason), ("committed", "clean", "settled", "none"))
                final = snapshot(root)
                self.assertEqual({p: v[1] for p, v in final.items()}, fixture.files(case, "final"))
                for path, (fact, body) in original.items():
                    if body == final[path][1]:
                        self.assertEqual(final[path], (fact, body))

    def test_genuine_late_inventory_precursors_and_original_recovery(self):
        for case in fixture.RECOVERY_CASES:
            with self.subTest(case=case):
                root = self.root(case)
                original = snapshot(root)
                evidence = produce(root, case)
                checked = fixture.producer_result(subprocess.CompletedProcess([], 0, json.dumps(evidence).encode(), b""), case, self.need)
                self.assertFalse(checked["processLossEvidence"])
                self.assertGreater(checked["attemptedDescriptors"], 0)
                pending = snapshot(root)
                self.assertEqual(set(pending), set(fixture.files(case, "pending")) | set(fixture.controls(case, "pending")))
                for path, body in fixture.files(case, "pending").items():
                    self.assertEqual(pending[path][1], body, path)
                for index, path in ((1, fixture.ANDROID_PATH), (2, fixture.CONFIG_PATH)):
                    backup = pending[f"{fixture.PENDING}/old-{index}"]
                    self.assertEqual(backup[0][:8], original[path][0][:8])
                    self.assertEqual(backup[1], original[path][1])
                if case == fixture.CASES[2]:
                    # Caller keeps exactly its returned foreign original OUTSIDE
                    # the project. No journal or header grants this path.
                    foreign = root / "gradle.properties"
                    os.rename(foreign, self.parent / "owned-foreign-control")
                else:
                    for path in (fixture.ANDROID_PATH, "keep.txt"):
                        with (root / path).open("ab") as out:
                            out.write(fixture.LATER)
                before_recover = snapshot(root)
                with self.lease(root, recover=True) as lease:
                    checkout = recovery.capture_project_identity_recovery(lease)
                    self.assertEqual(checkout.view["state"], "recoverable", checkout.view)
                    self.assertEqual(checkout.view["action"], "committed_cleanup" if case == fixture.CASES[3] else "rollback")
                    plan = recovery.prepare_project_identity_recovery(lease, checkout, checkout.revision)
                    self.assertEqual(snapshot(root), before_recover)
                    if case == fixture.CASES[3]:
                        with patch("mobile_release.project_identity_recovery._public_bytes", side_effect=AssertionError("terminal cleanup read application source")), \
                             patch("mobile_release.project_identity_recovery.recovery_inventory", side_effect=AssertionError("terminal cleanup inventoried application source")):
                            result = recovery.apply_project_identity_recovery(lease, plan)
                    else:
                        result = recovery.apply_project_identity_recovery(lease, plan)
                    self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                        ("committed" if case == fixture.CASES[3] else "rolled_back", "clean", "settled", "none"))
                final = snapshot(root)
                self.assertEqual({p: v[1] for p, v in final.items()}, fixture.files(case, "final"))
                if case == fixture.CASES[3]:
                    self.assertEqual(final, {p: v for p, v in before_recover.items() if not p.startswith(fixture.PENDING + "/")})
                else:
                    for path, (fact, body) in original.items():
                        self.assertEqual(final[path][0][:8], fact[:8])
                        self.assertEqual(final[path][1], body)

    def test_precursor_refuses_bad_root_case_and_boolean_settlement(self):
        root = self.root(fixture.CASES[0])
        before = snapshot(root)
        for case in (fixture.CASES[0], fixture.CASES[2]):
            with self.assertRaises(ValueError):
                produce(root, case)
        self.assertEqual(snapshot(root), before)
        root = self.root(fixture.CASES[2])
        value = produce(root, fixture.CASES[2])
        for key, replacement in (("originalDescriptorsClosed", 1), ("processLossEvidence", True), ("resources", "unknown")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture.producer_result(subprocess.CompletedProcess([], 0, json.dumps({**value, key: replacement}).encode(), b""), fixture.CASES[2], self.need)

    def test_same_fixture_descriptor_owner_captures_real_pending_and_later_user_edit(self):
        # Existing finite owner methods, not a mock FS or a new cleanup class.
        path = LEAF.with_name("macos_aqua_qualification.py")
        source = importlib.util.spec_from_file_location("_identity_original_fixture_owner", path)
        parent = importlib.util.module_from_spec(source)
        sys.modules[source.name] = parent
        self.addCleanup(sys.modules.pop, source.name)
        source.loader.exec_module(parent)
        case = fixture.CASES[3]
        root = self.root(case)
        owner = parent.Fixtures(parent.Binding("a" * 40, "1", "1"), os.getuid(), os.getgid())
        owner.cases = (case,)
        owner.projects[case] = owner._open(root, directory=True)
        try:
            original = fixture.capture(owner, case, "initial")
            produce(root, case)
            pending = fixture.capture(owner, case, "pending")
            fixture._transition(original, pending, case, "pending")
            for name in (fixture.ANDROID_PATH, "keep.txt"):
                fixture._later_edit(owner, case, name, pending[name])
            before = fixture.capture(owner, case, "before")
            self.assertEqual(before[fixture.ANDROID_PATH][0][:6], pending[fixture.ANDROID_PATH][0][:6])
            self.assertEqual(before["keep.txt"][0][:6], original["keep.txt"][0][:6])
            self.assertEqual(len(owner.fds), 1, "All temporary original reads/writes must actually close")
            (root / "unexpected.properties").write_bytes(b"unrelated foreign control")
            with self.assertRaises(parent.Refused):
                fixture.capture(owner, case, "before")
            self.assertEqual(len(owner.fds), 1)
        finally:
            for fd in tuple(owner.fds):
                self.assertTrue(owner._close(fd))
        self.assertFalse(owner.fds)
        self.assertEqual(owner.close_errors, 0)

    def test_report_parser_keeps_original_ids_unknown_and_claims_strict(self):
        for case in fixture.CASES:
            value = self.report_data(case)
            self.assertIs(fixture.report(value, case, self.need), value)
            for key, replacement in (("nativeFinality", "unknown"), ("originalsJoined", 1), ("lateSettled", True), ("writerFrames", 4)):
                changed = json.loads(json.dumps(value)); changed["sessions"][0][key] = replacement
                with self.subTest(case=case, key=key), self.assertRaises(ValueError):
                    fixture.report(changed, case, self.need)
            for key in ("processLossEvidence", "buildOrStoreVerified", "shippingBinaryQualified", "identityUiAutomation", "namespaceRefactor"):
                with self.subTest(case=case, key=key), self.assertRaises(ValueError):
                    fixture.report({**value, key: True}, case, self.need)
        value = self.report_data(fixture.CASES[0])
        value["sessions"][1]["sessionId"] = value["sessions"][0]["sessionId"]
        with self.assertRaises(ValueError):
            fixture.report(value, fixture.CASES[0], self.need)

    def test_native_and_hosted_public_literals_are_identical(self):
        text = (LEAF.parents[1] / "src-tauri/src/installed_shell_observation_macos_identity.rs").read_text()
        for name, body in (("SOURCE", fixture.SOURCE), ("PBX", fixture.PBX), ("SCHEME", fixture.SCHEME),
                           ("XCCONFIG", fixture.XCCONFIG), ("ANDROID_CONFIG", fixture.config(fixture.CASES[0])),
                           ("IOS_CONFIG", fixture.config(fixture.CASES[1]))):
            found = re.search(r"const " + name + r': &\[u8\] = br###"(.*?)"###;', text, re.S)
            self.assertIsNotNone(found, name)
            self.assertEqual(found.group(1).encode(), body, name)
            self.assertLessEqual(len(body), 4096, "Existing original public file reader bound")
        compile(fixture.PRODUCER, "<fixed isolated identity precursor>", "exec")

    def test_actual_passive_snapshot_uses_each_case_not_old_android_observer_literals(self):
        for case in fixture.CASES:
            with self.subTest(case=case):
                root = self.root(case)
                if case in fixture.RECOVERY_CASES:
                    produce(root, case)
                before = snapshot(root)
                with patch("subprocess.Popen", side_effect=AssertionError("Passive identity snapshot executed a project")):
                    value = project_snapshot(str(root))
                self.assertEqual(snapshot(root), before)
                raw = fixture.config(case)
                if case in fixture.RECOVERY_CASES:
                    raw = raw.replace(fixture.OLD.encode(), fixture.NEW.encode())
                self.assertEqual(value["config"]["data"], json.loads(raw))
                self.assertEqual(value["config"]["state"], "format-valid")
                self.assertEqual(value["issues"], [])
                self.assertFalse(value["discovery"]["partial"])
                hints = value["discovery"]["hints"]
                self.assertEqual(hints["versionSource"], "version.properties")
                self.assertEqual(hints["versionNameKey"], "VERSION_NAME")
                self.assertEqual(hints["versionBuildKey"], "BUILD_NUMBER")
                if case == fixture.CASES[1]:
                    self.assertNotIn("android", hints)
                    # Required identity facts, not a golden of every passive
                    # hint. appTargets is additive guidance, not edit authority.
                    ios = hints["ios"]
                    project = fixture.PBX_PATH.rsplit("/", 1)[0]
                    self.assertEqual(ios["bundleId"], fixture.OLD)
                    self.assertEqual(ios["bundleIds"], [fixture.OLD])
                    self.assertEqual(ios["project"], project)
                    self.assertEqual(ios["projects"], [project])
                    self.assertEqual(ios["scheme"], "Reader")
                    self.assertEqual(ios["schemes"], ["Reader"])
                    self.assertEqual([target["name"] for row in ios["appTargets"]
                        if row["project"] == project for target in row["targets"]], ["Reader"])
                else:
                    self.assertEqual(hints["android"], {"module": ":app", "buildFile": fixture.ANDROID_PATH,
                        "applicationId": fixture.NEW if case in fixture.RECOVERY_CASES else fixture.OLD,
                        "namespace": "com.example.source", "debugApplicationIdSuffix": ".debug"})

    @staticmethod
    def report_data(case):
        """Inert parser comparison only; no constructor for native facts."""
        import hashlib
        rows = []
        for i in range(2 if case == fixture.CASES[0] else 1):
            closed = case == fixture.CASES[0] and i == 0
            rows.append({"sessionId": str(i+1) * 32, "projectId": "fixture", "ownerGeneration": "e" * 32,
                "revision": "a" * 32, "planToken": "b" * 32, "intent": "recover" if case in fixture.RECOVERY_CASES else "edit",
                "coreOutcome": {"effect": "not_started" if closed else "rolled_back" if case == fixture.CASES[2] else "committed",
                    "journal": "not_created" if closed else "clean", "resources": "settled", "reason": "cancelled" if closed else "none"},
                "nativeReason": "discarded" if closed else "none", "nativeFinality": "settled", "lateSettled": False,
                "reviewMatched": True, "originalsJoined": True, "writerFrames": 2 if closed else 3, "stdoutFrames": 3,
                "closedWithoutApply": closed, "fileReadback": True})
        return {"scope": "original-project-identity-v1", "case": case, "identityUiAutomation": False, "sessions": rows,
            "files": {p: hashlib.sha256(b).hexdigest() for p, b in fixture.files(case, "final").items()},
            "controlledPrecursorRequired": case in fixture.RECOVERY_CASES, "processLossEvidence": False,
            "buildOrStoreVerified": False, "namespaceRefactor": False, "shippingBinaryQualified": False}

    @staticmethod
    def need(value, reason):
        if not value:
            raise ValueError(reason)


if __name__ == "__main__":
    unittest.main()
