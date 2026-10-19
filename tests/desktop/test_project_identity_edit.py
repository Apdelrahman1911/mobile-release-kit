"""Synthetic registered-root tests through the real existing transaction owner.

No build/provider/credential processes. Faults occur after returned owned
effects and suppress only same-invocation cleanup: controlled-error recovery,
not an abrupt process/power-loss or installed-platform qualification claim.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from mobile_release import config_edit
from mobile_release import init_transaction as tx
from mobile_release import github_workflow_recovery as workflow_recovery
from mobile_release import project_identity as identity
from mobile_release import project_identity_edit as edit
from mobile_release import project_identity_recovery as recover
from mobile_release import project_identity_targets as targets
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.config_edit import ConfigEditFailure
from mobile_release.config_payloads import prepare_edit_ignore
from mobile_release.errors import ValidationError
from mobile_release.init_workspace_custody import InitRootLease
from tests.unit.test_project_identity import ANDROID, IOS, NEW, OLD, PBX, SCHEME, android, ios

PROFILE = tx.TypedEditProfile.PROJECT_IDENTITY


def full9(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def namespace(root):
    return {path.relative_to(root).as_posix(): (full9(path.lstat()), path.read_bytes() if path.is_file() else None)
            for path in (root, *sorted(root.rglob("*")))}


class IdentityNativeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-identity-fixture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.selection = ANDROID
        self.sources = android()
        self.sources[identity.IGNORE_PATH] = prepare_edit_ignore(b"# owned synthetic fixture\n")[0]
        self.write_sources()
        self.sentinel = self.root / "app" / "src" / "Unrelated.kt"
        self.sentinel.parent.mkdir()
        self.sentinel.write_bytes(b'package com.example.source\n// source sentinel: do not edit\n')
        self.sentinel_before = full9(self.sentinel.stat()), self.sentinel.read_bytes()

    def write_sources(self):
        for path, raw in self.sources.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o640)

    @contextmanager
    def lease(self, *, recovery=False, profile=PROFILE, workflow=False):
        registered = self.root.stat()
        guard = DefaultCancellation(ValidationError, "identity fixture custody failed")
        lease = InitRootLease(self.root, cancellation=guard, profile=profile, identity_recovery=recovery,
            workflow_recovery=workflow,
            registered_identity={"device": registered.st_dev, "inode": registered.st_ino,
                "mode": registered.st_mode, "uid": registered.st_uid, "gid": registered.st_gid})
        cleanup = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
        try:
            with cleanup:
                guard.install()
                guard.activate()
                lease.acquire()
                yield lease
        finally:
            cleanup.__exit__(*sys.exc_info())
        self.assertTrue(lease.closed)
        self.assertFalse(guard.lifetime_ledger.fatal)
        self.assertEqual(guard.handler_state, "RESTORED")

    def prepared(self, lease, desired=NEW):
        checkout = edit.capture_project_identity_edit(lease, self.selection)
        self.assertEqual(checkout.view["state"], "supported", checkout.view)
        before = namespace(self.root)
        plan = edit.prepare_project_identity_edit(lease, checkout, expected_revision=checkout.revision,
            desired_identity=desired, intent="new-application")
        self.assertEqual(namespace(self.root), before, "Prepare must not create private or public output")
        self.assertNotIn(b"Unrelated.kt", json.dumps(plan.view).encode())
        return checkout, plan

    def assert_originals(self, inodes=None):
        for path, raw in self.sources.items():
            self.assertEqual((self.root / path).read_bytes(), raw, path)
            self.assertEqual(stat.S_IMODE((self.root / path).stat().st_mode), 0o640)
            if inodes:
                self.assertEqual((self.root / path).stat().st_ino, inodes[path])
        self.assertEqual((full9(self.sentinel.stat()), self.sentinel.read_bytes()), self.sentinel_before)
        self.assertFalse(any((self.root / name).exists() for name in tx.ALL_STATE_NAMES))

    def pending(self, point):
        move, state, unlink = tx.InitWorkspace._move, tx.InitWorkspace._state_move, tx.InitWorkspace._unlink
        failure, reached = OSError("synthetic owned identity cut"), []

        def stopped_move(owner, source_fd, source, destination_fd, destination, expected, **kwargs):
            result = move(owner, source_fd, source, destination_fd, destination, expected, **kwargs)
            selected = ((point == "backup-config" and source == "mobile-release.json") or
                        (point == "installed-source" and destination == "build.gradle.kts") or
                        (point == "committed" and destination == "COMMITTED"))
            if selected and not reached:
                reached.append(owner)
                raise failure
            return result

        def stopped_state(owner, old, new):
            if point == "preparing" and (old, new) == (tx.PREPARING, tx.READY) and not reached:
                reached.append(owner)
                raise failure
            return state(owner, old, new)

        def stopped_unlink(owner, name, **kwargs):
            result = unlink(owner, name, **kwargs)
            if point == "suffix" and name == "plan.json" and not reached:
                reached.append(owner)
                raise failure
            return result

        with self.lease() as lease:
            _, plan = self.prepared(lease)
            with ExitStack() as stack:
                stack.enter_context(patch.object(tx.InitWorkspace, "_move", stopped_move))
                stack.enter_context(patch.object(tx.InitWorkspace, "_state_move", stopped_state))
                stack.enter_context(patch.object(tx.InitWorkspace, "_unlink", stopped_unlink))
                if point != "suffix":
                    stack.enter_context(patch.object(tx.InitWorkspace, "_fixed_recovery", return_value=None))
                outcome = edit.apply_project_identity_edit(lease, plan)
            self.assertEqual((outcome.journal, outcome.resources, outcome.reason),
                             ("recovery_required", "settled", "filesystem_error"), outcome)
            self.assertEqual(len(reached), 1)
            self.assertIs(reached[0]._primary, failure)
        return outcome

    def recovered(self):
        with self.lease(recovery=True) as lease:
            checkout = recover.capture_project_identity_recovery(lease)
            self.assertEqual(checkout.view["state"], "recoverable", checkout.view)
            before = namespace(self.root)
            plan = recover.prepare_project_identity_recovery(lease, checkout, checkout.revision)
            self.assertEqual(namespace(self.root), before)
            outcome = recover.apply_project_identity_recovery(lease, plan)
            self.assertEqual((outcome.journal, outcome.resources, outcome.reason), ("clean", "settled", "none"), outcome)
            self.assertEqual(recover.apply_project_identity_recovery(lease, plan).reason, "invalid_params")
            return outcome

    def test_actual_android_apply_preserves_namespace_unrelated_sources_and_modes(self):
        inodes = {path: (self.root / path).stat().st_ino for path in self.sources}
        with self.lease() as lease:
            checkout, plan = self.prepared(lease)
            self.assertEqual(checkout.revision, plan.revision)
            for value in (checkout, plan):
                for cloning in (copy.copy, copy.deepcopy):
                    with self.assertRaises(TypeError):
                        cloning(value)
            outcome = edit.apply_project_identity_edit(lease, plan)
            self.assertEqual(outcome, config_edit.CoreEditOutcome("committed", "clean", "settled", "none"))
            self.assertTrue(edit.identity_outcome_invalidates(outcome))
            self.assertEqual(edit.apply_project_identity_edit(lease, plan).reason, "invalid_params")
        for path, raw in self.sources.items():
            changed = path in {identity.CONFIG_PATH, "app/build.gradle.kts"}
            self.assertEqual((self.root / path).read_bytes(), raw.replace(OLD.encode(), NEW.encode()) if changed else raw)
            self.assertEqual((self.root / path).stat().st_ino == inodes[path], not changed)
            self.assertEqual(stat.S_IMODE((self.root / path).stat().st_mode), 0o640)
        self.assertEqual((full9(self.sentinel.stat()), self.sentinel.read_bytes()), self.sentinel_before)
        self.assertFalse(any((self.root / name).exists() for name in tx.ALL_STATE_NAMES))

    def test_actual_ios_target_apply_does_not_rewrite_other_project_text(self):
        self.sources.update(ios())
        self.selection = IOS
        self.write_sources()
        with self.lease() as lease:
            _, plan = self.prepared(lease)
            outcome = edit.apply_project_identity_edit(lease, plan)
            self.assertEqual(outcome.effect, "committed", outcome)
        self.assertEqual((self.root / PBX).read_bytes(), self.sources[PBX].replace(OLD.encode(), NEW.encode()))
        self.assertEqual((self.root / "app/build.gradle.kts").read_bytes(), self.sources["app/build.gradle.kts"])
        self.assertEqual((self.root / SCHEME).read_bytes(), self.sources[SCHEME])

    def test_saved_ios_scheme_is_an_original_readonly_dependency_not_renderer_target_authority(self):
        self.sources.update(ios())
        self.selection = IOS
        self.write_sources()
        with self.lease() as lease:
            _, plan = self.prepared(lease)
            scheme = self.root / SCHEME
            scheme.write_bytes(scheme.read_bytes().replace(b'buildForArchiving="YES"', b'buildForArchiving="NO"'))
            before = namespace(self.root)
            outcome = edit.apply_project_identity_edit(lease, plan)
            self.assertEqual((outcome.effect, outcome.journal, outcome.reason),
                             ("not_started", "not_created", "stale_revision"))
            self.assertEqual(namespace(self.root), before)

    def test_same_identity_is_noop_even_existing_and_never_creates_journal(self):
        self.selection = identity.IdentitySelection("android", ":app")
        with self.lease() as lease:
            _, plan = self.prepared(lease, OLD)
            before = namespace(self.root)
            self.assertEqual(plan.view["state"], "unchanged")
            outcome = edit.apply_project_identity_edit(lease, plan)
            self.assertEqual(outcome.effect, "unchanged", outcome)
            self.assertFalse(edit.identity_outcome_invalidates(outcome))
            self.assertEqual(namespace(self.root), before)
        self.assert_originals()

    def test_changed_readonly_control_added_control_or_inode_consumes_review(self):
        for mutation in ("bytes", "inode", "added"):
            with self.subTest(mutation=mutation):
                with self.lease() as lease:
                    _, plan = self.prepared(lease)
                    control = self.root / "settings.gradle.kts"
                    if mutation == "bytes":
                        control.write_bytes(control.read_bytes() + b"// changed\n")
                    elif mutation == "inode":
                        replacement = self.root / "settings.replacement"
                        replacement.write_bytes(control.read_bytes())
                        replacement.chmod(0o640)
                        os.replace(replacement, control)
                    else:
                        (self.root / "gradle.properties").write_bytes(b"org.gradle.jvmargs=-Xmx256m\n")
                    before = namespace(self.root)
                    outcome = edit.apply_project_identity_edit(lease, plan)
                    self.assertEqual(outcome.effect, "not_started", outcome)
                    self.assertEqual(outcome.reason, "stale_revision", outcome)
                    self.assertEqual(namespace(self.root), before)
                    self.assertEqual(edit.apply_project_identity_edit(lease, plan).reason, "invalid_params")
                self.write_sources()
                (self.root / "gradle.properties").unlink(missing_ok=True)

    def test_missing_ignore_proof_refuses_without_creating_any_state(self):
        (self.root / identity.IGNORE_PATH).write_bytes(b"build/\n")
        with self.lease() as lease:
            before = namespace(self.root)
            with self.assertRaises(ConfigEditFailure) as error:
                edit.capture_project_identity_edit(lease, self.selection)
            self.assertEqual(error.exception.outcome.reason, "ignore_conflict")
            self.assertEqual(namespace(self.root), before)

    def test_unsupported_source_reports_precise_safe_location_and_prepare_keeps_it(self):
        path = self.root / "app/build.gradle.kts"
        path.write_bytes(path.read_bytes().replace(OLD.encode(), b"${PRIVATE_VALUE_NOT_FOR_PUBLIC_OUTPUT}"))
        with self.lease() as lease:
            before = namespace(self.root)
            checkout = edit.capture_project_identity_edit(lease, self.selection)
            self.assertEqual(checkout.view["state"], "unsupported")
            diagnostic = checkout.view["diagnostics"][0]
            self.assertEqual((diagnostic["code"], diagnostic["path"], diagnostic["line"]),
                             ("dynamic-identity", "app/build.gradle.kts", 5))
            self.assertIn("manually", diagnostic["help"])
            self.assertNotIn("PRIVATE_VALUE", json.dumps(checkout.view))
            with self.assertRaises(identity.IdentityInputError) as error:
                edit.prepare_project_identity_edit(lease, checkout, expected_revision=checkout.revision,
                    desired_identity=NEW, intent="new-application")
            self.assertEqual(error.exception.diagnostic.as_dict(), diagnostic)
            with self.assertRaises(ConfigEditFailure):
                edit.prepare_project_identity_edit(lease, checkout, expected_revision=checkout.revision,
                    desired_identity=NEW, intent="new-application")
            self.assertEqual(namespace(self.root), before)

    def test_applied_provider_blocks_prepare_without_reading_or_rewriting_provider_configuration(self):
        path = "app/build.gradle.kts"
        self.sources[path] = self.sources[path].replace(b'id("com.android.application")',
            b'id("com.android.application"); id("com.google.gms.google-services")')
        self.write_sources()
        provider = self.root / "app/google-services.json"
        provider.write_bytes(b'{"synthetic_private_provider":"DO_NOT_READ_OR_CHANGE"}\n')
        observe, read_paths = tx.InitWorkspace.observe, []

        def observed(owner, path, **kwargs):
            read_paths.append(path)
            return observe(owner, path, **kwargs)

        with self.lease() as lease, patch.object(tx.InitWorkspace, "observe", observed):
            before = namespace(self.root)
            checkout = edit.capture_project_identity_edit(lease, self.selection)
            self.assertEqual(checkout.view["state"], "supported")
            with self.assertRaises(identity.IdentityInputError) as error:
                edit.prepare_project_identity_edit(lease, checkout, expected_revision=checkout.revision,
                    desired_identity=NEW, intent="new-application")
            self.assertEqual((error.exception.diagnostic.code, error.exception.diagnostic.path),
                             ("dependent-service", path))
            self.assertNotIn("app/google-services.json", read_paths)
            self.assertEqual(namespace(self.root), before)
            with self.assertRaises(ConfigEditFailure):
                edit.prepare_project_identity_edit(lease, checkout, expected_revision=checkout.revision,
                    desired_identity=NEW, intent="new-application")

    def test_original_transaction_automatically_rolls_back_a_returned_source_install_error(self):
        inodes = {path: (self.root / path).stat().st_ino for path in self.sources}
        move, reached = tx.InitWorkspace._move, []

        def fail(owner, source_fd, source, destination_fd, destination, expected, **kwargs):
            value = move(owner, source_fd, source, destination_fd, destination, expected, **kwargs)
            if destination == "build.gradle.kts" and source.startswith("new-") and not reached:
                reached.append(True)
                raise OSError("synthetic returned install failure")
            return value

        with self.lease() as lease:
            _, plan = self.prepared(lease)
            with patch.object(tx.InitWorkspace, "_move", fail):
                outcome = edit.apply_project_identity_edit(lease, plan)
            self.assertEqual(outcome, config_edit.CoreEditOutcome("rolled_back", "clean", "settled", "filesystem_error"))
        self.assertEqual(reached, [True])
        self.assert_originals(inodes)

    def late_control(self, point):
        """Inject only a synthetic foreign control, never a second writer."""
        move, state, rename_factory = tx.InitWorkspace._move, tx.InitWorkspace._state_move, tx._rename_function
        foreign, body = self.root / "gradle.properties", b"APP_ID=com.example.foreign\n"
        reached, inodes = [], {path: (self.root / path).stat().st_ino for path in self.sources}

        def inject():
            self.assertFalse(reached)
            foreign.write_bytes(body)
            reached.append(True)

        def changed_state(owner, old, new):
            value = state(owner, old, new)
            if point == "ready" and (old, new) == (tx.PREPARING, tx.READY):
                inject()
            return value

        def changed_move(owner, source_fd, source, destination_fd, destination, expected, **kwargs):
            if point == "before-commit" and destination == "COMMITTED":
                inject()
            value = move(owner, source_fd, source, destination_fd, destination, expected, **kwargs)
            if ((point == "backup-config" and source == "mobile-release.json") or
                    (point == "installed-config" and destination == "mobile-release.json" and source.startswith("new-"))):
                inject()
            return value

        def changed_factory():
            rename = rename_factory()

            def changed_rename(source_fd, source, destination_fd, destination):
                value = rename(source_fd, source, destination_fd, destination)
                if point == "returned-commit" and destination == "COMMITTED":
                    inject()
                return value

            return changed_rename

        with self.lease() as lease:
            _, plan = self.prepared(lease)
            with patch.object(tx.InitWorkspace, "_state_move", changed_state), \
                 patch.object(tx.InitWorkspace, "_move", changed_move), \
                 patch.object(tx, "_rename_function", changed_factory):
                outcome = edit.apply_project_identity_edit(lease, plan)
            effect = "committed" if point == "returned-commit" else "not_started" if point == "ready" else "unknown"
            self.assertEqual(outcome, config_edit.CoreEditOutcome(effect, "recovery_required", "settled", "stale_revision"))
            self.assertEqual(edit.apply_project_identity_edit(lease, plan).reason, "invalid_params")
            self.assertTrue(edit.identity_outcome_invalidates(outcome))
        self.assertEqual(reached, [True])
        self.assertEqual(foreign.read_bytes(), body)
        self.assertTrue((self.root / tx.READY).is_dir())
        before = namespace(self.root)
        with self.lease(recovery=True) as lease:
            checkout = recover.capture_project_identity_recovery(lease)
            if point == "returned-commit":
                self.assertEqual(checkout.view["action"], "committed_cleanup")
            else:
                self.assertEqual((checkout.view["state"], checkout.view["reason"]), ("conflict", "inventory_changed"))
        self.assertEqual(namespace(self.root), before, "Inspection must preserve all foreign and pending files")
        if point == "returned-commit":
            foreign_before = full9(foreign.stat()), foreign.read_bytes()
            self.assertEqual(self.recovered().effect, "committed")
            self.assertEqual((full9(foreign.stat()), foreign.read_bytes()), foreign_before)
            for path in (identity.CONFIG_PATH, "app/build.gradle.kts"):
                self.assertIn(NEW.encode(), (self.root / path).read_bytes())
        else:
            foreign.unlink()  # Explicitly remove only this test's synthetic output.
            self.recovered()
            self.assert_originals(inodes)

    def test_new_control_after_ready_preserves_pending_before_any_publication(self):
        self.late_control("ready")

    def test_new_control_during_backed_up_config_gap_preserves_pending(self):
        self.late_control("backup-config")

    def test_new_control_after_last_file_install_cannot_commit(self):
        self.late_control("installed-config")

    def test_new_control_at_terminal_move_entry_cannot_commit(self):
        self.late_control("before-commit")

    def test_new_control_during_returned_commit_retains_known_commit_not_clean_or_rollback(self):
        self.late_control("returned-commit")

    def test_wrong_revision_or_forged_payload_never_becomes_a_raw_write(self):
        with self.lease() as lease:
            checkout = edit.capture_project_identity_edit(lease, self.selection)
            with self.assertRaises(ConfigEditFailure) as error:
                edit.prepare_project_identity_edit(lease, checkout, expected_revision="0" * 32,
                    desired_identity=NEW, intent="new-application")
            self.assertEqual(error.exception.outcome.reason, "stale_revision")
            with self.assertRaises(ConfigEditFailure):
                edit.prepare_project_identity_edit(lease, checkout, expected_revision=checkout.revision,
                    desired_identity=NEW, intent="new-application")
        with self.lease() as lease:
            _, plan = self.prepared(lease)
            object.__setattr__(plan, "_payloads", tuple(b"arbitrary replacement" for _ in plan._payloads))
            before = namespace(self.root)
            outcome = edit.apply_project_identity_edit(lease, plan)
            self.assertEqual(outcome.effect, "not_started")
            self.assertEqual(namespace(self.root), before)
        self.assert_originals()

    def test_public_opaque_symlink_refuses_but_private_trees_are_not_inspected(self):
        private = self.root / ".private-identity-fixture"
        private.mkdir()
        (private / "build.gradle.kts").write_bytes(b"private sentinel: must not be read")
        original_stat = os.stat

        def check(path, *args, **kwargs):
            self.assertNotEqual(path, private.name, "private directory must be pruned before stat")
            return original_stat(path, *args, **kwargs)

        with self.lease() as lease, patch.object(targets.os, "stat", check):
            checkout = edit.capture_project_identity_edit(lease, self.selection)
            self.assertEqual(checkout.view["state"], "supported")
        for name in ("opaque-public-link", "opaque-\u2603-link"):
            link = self.root / name
            link.symlink_to("app", target_is_directory=True)
            with self.subTest(name=name), self.lease() as lease:
                with self.assertRaises(ConfigEditFailure):
                    edit.capture_project_identity_edit(lease, self.selection)
            link.unlink()

    def test_registered_root_required_and_nonidentity_profile_cannot_capture(self):
        guard = DefaultCancellation(ValidationError, "synthetic failure")
        with self.assertRaises(tx.InitOperationFailure):
            InitRootLease(self.root, cancellation=guard, profile=PROFILE)
        with self.lease(profile=tx.TypedEditProfile.RELEASE_VERSION) as lease:
            before = namespace(self.root)
            with self.assertRaises(ConfigEditFailure):
                edit.capture_project_identity_edit(lease, self.selection)
            self.assertEqual(namespace(self.root), before)

    def test_recovery_rederives_after_backup_or_installed_source_and_restores_original_inodes(self):
        for cut in ("backup-config", "installed-source", "preparing"):
            with self.subTest(cut=cut):
                inodes = {path: (self.root / path).stat().st_ino for path in self.sources}
                self.pending(cut)
                outcome = self.recovered()
                self.assertIn(outcome.effect, {"rolled_back", "not_started"})
                self.assert_originals(inodes)

    def test_known_commit_cleanup_and_suffix_never_read_or_undo_new_public_edits(self):
        for cut in ("committed", "suffix"):
            with self.subTest(cut=cut):
                outcome = self.pending(cut)
                self.assertEqual(outcome.effect, "committed")
                self.assertTrue(edit.identity_outcome_invalidates(outcome))
                source = self.root / "app/build.gradle.kts"
                source.write_bytes(b"// later unrelated user edit: preserve, not even an identity declaration\n")
                later = source.read_bytes(), full9(source.stat())
                with patch.object(recover, "recovery_inventory", side_effect=AssertionError("terminal public read")), \
                     patch.object(tx.InitWorkspace, "_current", side_effect=AssertionError("terminal public read")):
                    fixed = self.recovered()
                self.assertEqual(fixed.effect, "committed")
                self.assertEqual((source.read_bytes(), full9(source.stat())), later)
                self.write_sources()

    def test_added_control_blocks_recovery_and_preserves_original_journal(self):
        self.pending("installed-source")
        (self.root / "gradle.properties").write_bytes(b"APP_ID=com.example.injected\n")
        with self.lease(recovery=True) as lease:
            before = namespace(self.root)
            checkout = recover.capture_project_identity_recovery(lease)
            self.assertEqual((checkout.view["state"], checkout.view["reason"]), ("conflict", "inventory_changed"))
            with self.assertRaises(ConfigEditFailure):
                recover.prepare_project_identity_recovery(lease, checkout, checkout.revision)
            self.assertEqual(namespace(self.root), before)

    def test_recovery_is_profile_bound_and_late_control_invalidates_one_use_grant(self):
        self.pending("installed-source")
        with self.lease(profile=tx.TypedEditProfile.GITHUB_WORKFLOWS, workflow=True) as lease:
            before = namespace(self.root)
            checkout = workflow_recovery.capture_github_workflow_recovery(lease)
            self.assertEqual(checkout.view["state"], "conflict")
            with self.assertRaises(ConfigEditFailure):
                recover.capture_project_identity_recovery(lease)
            self.assertEqual(namespace(self.root), before)
        with self.lease(recovery=True) as lease:
            checkout = recover.capture_project_identity_recovery(lease)
            plan = recover.prepare_project_identity_recovery(lease, checkout, checkout.revision)
            (self.root / "app/gradle.properties").write_bytes(b"APP_ID=com.example.changed\n")
            before = namespace(self.root)
            outcome = recover.apply_project_identity_recovery(lease, plan)
            self.assertEqual(outcome.reason, "stale_revision")
            self.assertEqual(namespace(self.root), before)
            self.assertEqual(recover.apply_project_identity_recovery(lease, plan).reason, "stale_revision")

    def test_known_commit_or_any_uncertainty_requires_invalidation_not_reservation_reset(self):
        for effect, journal, resources, reason in (
                ("committed", "clean", "settled", "none"),
                ("committed", "recovery_required", "settled", "filesystem_error"),
                ("committed", "clean", "unknown", "custody_unknown"),
                ("not_started", "unknown", "settled", "filesystem_error"),
                ("unknown", "unknown", "unknown", "custody_unknown")):
            self.assertTrue(edit.identity_outcome_invalidates(config_edit.CoreEditOutcome(effect, journal, resources, reason)))
        self.assertTrue(edit.identity_outcome_invalidates(None))

    def test_forged_nonidentity_source_transform_is_not_adopted(self):
        self.pending("preparing")
        journal = self.root / tx.PREPARING
        plan = json.loads((journal / "plan.json").read_bytes())
        index = next(index for index, row in enumerate(plan["files"]) if row["path"] == "app/build.gradle.kts")
        staged = journal / f"new-{index}"
        data = staged.read_bytes().replace(b"com.example.source", b"com.example.hacked")
        staged.write_bytes(data)
        row = plan["files"][index]["after"]
        row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        plan_raw = tx._json(plan)
        (journal / "plan.json").write_bytes(plan_raw)
        for marker, state in (("commit.pending", "COMMITTED"), ("rollback.pending", "ROLLED_BACK")):
            raw = tx._json({"schemaVersion": 1, "transactionId": plan["transactionId"],
                           "planSha256": hashlib.sha256(plan_raw).hexdigest(), "state": state})
            (journal / marker).write_bytes(raw)
        with self.lease(recovery=True) as lease:
            before = namespace(self.root)
            checkout = recover.capture_project_identity_recovery(lease)
            self.assertEqual(checkout.view["state"], "conflict", checkout.view)
            self.assertEqual(namespace(self.root), before)

    def test_descriptor_cannot_grant_arbitrary_paths_or_existing_identity_rewrite(self):
        found = identity.analyze_project_identity(self.sources, self.selection)
        prepared = identity.prepare_project_identity(found, NEW, expected_revision=found.revision, intent="new-application")
        descriptor = targets.descriptor(prepared)
        self.assertEqual(targets.from_context(descriptor.context()), descriptor)
        for mutate in (lambda row: row["sources"][0].update(path="../../outside"),
                       lambda row: row["sources"][0].update(path="release/secret.txt"),
                       lambda row: row["selection"].update(continuity="existing"),
                       lambda row: row.update(extra=True), lambda row: row.update(schemaVersion=True)):
            value = descriptor.context()
            mutate(value)
            with self.assertRaises(targets.DescriptorError):
                targets.from_context(value)


if __name__ == "__main__":
    unittest.main()
