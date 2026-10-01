"""Focused required-note policy/descriptor checks and separately selected Linux IO.

Data and descriptor classes reuse the existing inert custody fixture. The
RequiredNotesFilesystemTests class performs genuine original transactions and
MUST run only under Root's independently admitted task-private execution owner.
No Store call, process spawn or external credential is used by these fixtures.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import unittest
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import config_edit as shared, init_transaction as tx
from mobile_release import metadata_text as text, required_notes as notes, required_notes_edit as edit
from mobile_release.api import _metadata_validation as saved
from mobile_release.errors import ValidationError
from test_metadata_text import config, no_io
from test_metadata_text_edit import (COVERED, REVISION, TOKEN, inert_metadata_scope, observed, raw_facts)
from test_workflow_transaction_profile import (InertGuard, ROOT, directory, inert_custody,
                                               stat_value, workspace, binding)

PROFILE = tx.TypedEditProfile.METADATA_TEXT
VERSION = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=42\n"


def configured(kind="android-build"):
    data = config()
    data["version"] = {"source": "app/config/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"}
    data["metadata"]["root"] = "public/store"
    context = {"kind": kind, "locale": "en-US"} if kind.startswith("android-") else {"kind": kind}
    return data, context


def target_fixture(custody, *, kind="android-build", raw=None, counterpart=None):
    data, context = configured(kind)
    configured_notes = notes.notes_configuration(json.dumps(data), context)
    selected = notes.required_note_selection(configured_notes, VERSION if kind.startswith("android-") else None)
    values = {text.CONFIG_PATH: json.dumps(data).encode(), text.IGNORE_PATH: COVERED, selected.path: raw}
    if selected.version_source is not None:
        values[selected.version_source] = VERSION
        values[selected.counterpart_path] = counterpart
    lease = custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(), profile=PROFILE,
                                  purpose=custody._LeasePurpose.REQUIRED_NOTES, registered_identity=dict(ROOT))
    lease._acquired = True
    owner = workspace(PROFILE)
    inert_metadata_scope(custody, lease, owner)
    stable_parents = {"release", "app", "app/config"}
    if raw is not None or counterpart is not None:
        stable_parents.update(selected.directories)
    all_parent_paths = sorted({"/".join(path.split("/")[:depth]) for path in values for depth in range(1, len(path.split("/")))})
    parent_data = {path: stat_value(inode=60 + i) if path in stable_parents else None for i, path in enumerate(all_parent_paths)}
    originals = {path: observed(path, value, 30 + i) for i, (path, value) in enumerate(values.items())}
    facts = {path: raw_facts(value, 30 + i) for i, (path, value) in enumerate(values.items())}
    calls = []
    def observe(path, *, limit):
        assert path in originals and (values[path] is None or len(values[path]) <= limit)
        calls.append((path, limit))
        owner._captured[path] = originals[path]
        owner._raw_observations[path] = facts[path]
        for depth in range(1, len(path.split("/"))):
            ancestor = "/".join(path.split("/")[:depth]); value = parent_data[ancestor]
            owner.parents[ancestor] = tx._dir_identity(value) if value else None
            owner._parent_facts[ancestor] = tuple(sorted(directory(value).items())) if value else None
        return originals[path]
    owner.observe = observe
    fixed = tuple(owner.observe(path, limit=limit) for path, limit in zip(text.DEPENDENCY_PATHS, text.DEPENDENCY_LIMITS))
    targets = lease.bind_required_notes_targets(owner, fixed, context)
    original = owner.observe(selected.path, limit=selected.editor_byte_limit)
    revision = lease.bind_revision(owner, (*targets.dependency_observations, original))
    owner._rooted_revision = revision
    return lease, owner, targets, revision, originals, calls


class RequiredNotesDataIntegrationTests(unittest.TestCase):
    def test_baseline_and_selection_share_orientation_strict_data_and_no_authority(self):
        with no_io():
            for kind in ("android-build", "android-default", "ios-beta-review"):
                data, context = configured(kind)
                android = kind.startswith("android-")
                selected = notes.required_note_selection(notes.notes_configuration(json.dumps(data), context), VERSION if android else None)
                raw, other = b"Reviewed note.\r\n", b"TODO" if android else None
                baseline = notes.notes_baseline(json.dumps(data).encode(), VERSION if android else None, raw, other)
                admitted = notes.admit_notes_baseline(notes.notes_context(context), baseline)
                self.assertEqual(admitted, baseline)
                admitted["config"]["byteLength"] = 1
                self.assertNotEqual(admitted, baseline)
                projected = notes.notes_selection_view(selected, raw, other)
                if android:
                    self.assertEqual(projected["effective"], {"source": "exact", "valid": kind == "android-build"})
                else:
                    self.assertIsNone(projected["effective"])
                    self.assertIsNone(baseline["version"])
                    self.assertIsNone(baseline["counterpart"])
                for key in ("byteLength", "sha256"):
                    invalid = copy.deepcopy(baseline); invalid["config"][key] = True
                    with self.assertRaises(notes.RequiredNotesInputError):
                        notes.admit_notes_baseline(notes.notes_context(context), invalid)
                with self.assertRaises(notes.RequiredNotesInputError):
                    notes.admit_notes_baseline(notes.notes_context(context), {**baseline, "path": selected.path})

    def test_private_original_guard_checks_secrets_even_after_android_first_failure(self):
        with no_io():
            data, context = configured()
            selected = notes.required_note_selection(notes.notes_configuration(json.dumps(data), context), VERSION)
            raw = b"x" * 501 + b" password=inert-private-marker"
            self.assertEqual(notes.check_required_note("android-build", raw).issues, ("notes.android-length",))
            # Eight raw value characters become seven in the normalized generic
            # checker. Raw disclosure admission must still refuse; first-error
            # length, NUL and placeholder checks cannot hide the same match.
            threshold = '{"client_secret":"abc\r\ndef"}'
            self.assertFalse(any(code == "metadata.secret-pattern" for code, _ in
                                 notes.check_metadata_text("required-note", threshold).issues))
            for kind in notes.KINDS:
                data, context = configured(kind)
                selected = notes.required_note_selection(notes.notes_configuration(json.dumps(data), context),
                                                         VERSION if kind.startswith("android-") else None)
                for content in (raw, threshold.encode(), ("x" * 501 + threshold).encode(),
                                ("\x00" + threshold).encode(), ("TODO " + threshold).encode()):
                    self.assertTrue(notes.required_note_sensitive(kind, content.decode()))
                    with self.assertRaises(shared.ConfigEditFailure) as caught:
                        edit._safe_original(content, selected)
                    self.assertEqual(caught.exception.outcome.reason, "invalid_params")
                    self.assertNotIn("inert-private-marker", str(caught.exception))
                self.assertFalse(notes.required_note_sensitive(kind, "Reviewed release instructions.\r\n"))
            for kind, content in (("other", "safe"), ("android-build", "\ud800"),
                                  ("ios-app-review", "x" * 65538)):
                with self.assertRaises(notes.RequiredNotesInputError):
                    notes.required_note_sensitive(kind, content)

    def test_saved_apple_notes_use_same_policy_exact_caps_and_content_free_codes(self):
        with no_io():
            for kind, raw, code in (("testflight-what-to-test", b"x" * 4001, "metadata.length"),
                                    ("ios-beta-review", b"password=inert-private-marker", "metadata.secret-pattern"),
                                    ("ios-app-review", b"\xff", "metadata.utf8")):
                calls = []
                def read(path, *, limit, binary):
                    calls.append((path, limit, binary)); return raw
                row = saved._ios_note(SimpleNamespace(read=read), "public/store", kind)
                self.assertIn(code, row["issues"])
                self.assertEqual(calls, [("public/store/" + notes.IOS_PATHS[kind], notes.editor_byte_limit(kind), True)])
                self.assertEqual(set(row), {"kind", "id", "path", "locale", "required", "state", "issues"})
                wire = json.dumps(row)
                self.assertNotIn(hashlib.sha256(raw).hexdigest(), wire)
                self.assertNotIn("inert-private-marker", wire)


class RequiredNotesPurposeTests(unittest.TestCase):
    """Only construction/admission predicates; the original IO entry is a trap.

    A Darwin policy decision is not a Mac filesystem/runtime qualification.
    No original directory acquisition is permitted or reported as successful.
    """
    def test_exact_purpose_profile_pair_is_latched_before_acquire_and_cannot_be_retargeted(self):
        with inert_custody() as custody:
            purpose = custody._LeasePurpose.REQUIRED_NOTES
            for invalid in (True, False, "required_notes", {"purpose": "required_notes"}, object()):
                with self.subTest(invalid=type(invalid).__name__), self.assertRaises(tx.InitOperationFailure) as failed:
                    custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(), profile=PROFILE,
                                          purpose=invalid, registered_identity=dict(ROOT))
                self.assertEqual(failed.exception.outcome.reason, "invalid_params")
            for profile in tx.TypedEditProfile:
                if profile is PROFILE:
                    continue
                with self.subTest(profile=profile), self.assertRaises(tx.InitOperationFailure) as failed:
                    custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(), profile=profile,
                                          purpose=purpose, registered_identity=dict(ROOT))
                self.assertEqual(failed.exception.outcome.reason, "invalid_params")
            for selected in (None, purpose):
                lease = custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(), profile=PROFILE,
                                              purpose=selected, registered_identity=dict(ROOT))
                for field, value in (("_purpose", purpose if selected is None else None), ("_profile", tx.TypedEditProfile.CONFIGURATION)):
                    with self.assertRaises(AttributeError): setattr(lease, field, value)
                    with self.assertRaises(AttributeError): delattr(lease, field)
                with self.assertRaises(tx.InitOperationFailure):
                    lease.__init__(Path("/inert-other"), cancellation=InertGuard())
                self.assertIs(lease._purpose, selected)
                self.assertIs(lease.profile, PROFILE)
                self.assertFalse(lease._acquire_claimed or lease._acquired)

    def test_darwin_exception_reaches_only_configuration_or_fixed_notes_acquisition_trap(self):
        with inert_custody() as custody:
            choices = [(profile, None) for profile in tx.TypedEditProfile]
            choices.append((PROFILE, custody._LeasePurpose.REQUIRED_NOTES))
            for platform in ("linux", "darwin", "win32"):
                for profile, purpose in choices:
                    with self.subTest(platform=platform, profile=profile, notes=purpose is not None):
                        guard = InertGuard(); guard._activated = True
                        guard._borrowable = lambda: None; guard.check = lambda: None
                        lease = custody.InitRootLease(Path("/inert-not-opened"), cancellation=guard, profile=profile,
                            purpose=purpose, registered_identity=None if profile is tx.TypedEditProfile.CONFIGURATION else dict(ROOT))
                        reached = Mock(side_effect=AssertionError("inert acquisition boundary; never a successful original"))
                        lease.directory.acquire = reached
                        with patch.object(custody.sys, "platform", platform), self.assertRaises(tx.InitOperationFailure) as failed:
                            lease.acquire()
                        allowed = platform == "linux" or platform == "darwin" and (
                            profile is tx.TypedEditProfile.CONFIGURATION or purpose is custody._LeasePurpose.REQUIRED_NOTES)
                        self.assertEqual(reached.call_count, int(allowed))
                        self.assertEqual(failed.exception.outcome.reason, "filesystem_error" if allowed else "unsupported_platform")
                        self.assertTrue(lease._acquire_claimed)
                        self.assertFalse(lease._acquired)

    def test_converse_target_binding_refuses_before_workspace_or_io_on_both_platforms(self):
        with inert_custody() as custody:
            for platform in ("linux", "darwin"):
                for purpose in (None, custody._LeasePurpose.REQUIRED_NOTES):
                    with self.subTest(platform=platform, notes=purpose is not None):
                        lease = custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(), profile=PROFILE,
                            purpose=purpose, registered_identity=dict(ROOT))
                        checked = Mock(side_effect=AssertionError("a foreign purpose must not enter native check")); lease.check = checked
                        with patch.object(custody.sys, "platform", platform), self.assertRaises(tx.InitOperationFailure) as failed:
                            if purpose is None:
                                lease.bind_required_notes_targets(object(), (), {"kind": "ios-app-review"})
                            else:
                                lease.bind_metadata_targets(object(), (), "android", "en-US")
                        self.assertEqual(failed.exception.outcome.reason, "invalid_params")
                        checked.assert_not_called()
                        self.assertIsNone(lease._metadata_targets)


class RequiredNotesTargetTests(unittest.TestCase):
    def test_original_descriptor_separates_extra_readonly_parents_and_one_payload(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            _, owner, targets, revision, _, calls = target_fixture(custody)
            self.assertEqual(targets.dependency_paths, (*text.DEPENDENCY_PATHS, "app/config/version.properties",
                                                      "public/store/android/en-US/changelogs/default.txt"))
            self.assertEqual(targets.dependency_limits, (*text.DEPENDENCY_LIMITS, 65536, 2000))
            self.assertEqual(targets.payload_limits, (2000,))
            self.assertEqual(targets.paths, ("public/store/android/en-US/changelogs/42.txt",))
            self.assertEqual(set(targets.dependency_only_parents), {"release", "app", "app/config"})
            self.assertEqual(targets.transition_directories, targets.directories)
            self.assertEqual(calls, list(zip(targets.observation_paths, targets.observation_limits)))
            self.assertEqual(revision.missing_metadata_directories, targets.directories)
            self.assertNotIn("app/config", revision.missing_metadata_directories)
            self.assertIs(owner._metadata_targets, revision._metadata_targets)
            with self.assertRaises(tx.InitOperationFailure):
                owner._scope.lease.bind_required_notes_targets(owner, targets.dependency_observations[:2], {"kind": "ios-app-review"})

    def test_recheck_refuses_version_counterpart_presence_and_readonly_parent_changes(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for change in (None, "version", "counterpart", "readonly-parent"):
                lease, _, targets, revision, original, _ = target_fixture(custody)
                current = workspace(PROFILE); current._metadata_targets = targets
                inert_metadata_scope(custody, lease, current)
                rows = dict(original); facts = dict(revision._raw); parents = dict(revision._parent_facts)
                if change == "version":
                    path = targets.selection.version_source; rows[path] = observed(path, VERSION.replace(b"42", b"43"), 900)
                if change == "counterpart":
                    path = targets.selection.counterpart_path; rows[path] = observed(path, b"Appeared", 901)
                if change == "readonly-parent":
                    value = dict(parents["app/config"]); value["uid"] += 1; parents["app/config"] = tuple(sorted(value.items()))
                def observe(path, *, limit):
                    current._captured[path] = rows[path]
                    current._raw_observations[path] = facts[path]
                    current._parent_facts.update(parents)
                    return rows[path]
                current.observe = observe
                with patch.object(notes, "required_note_selection", side_effect=AssertionError("must not retarget")):
                    if change is None:
                        lease._recheck(current, revision)
                        self.assertIs(current._rooted_revision, revision)
                    else:
                        with self.subTest(change=change), self.assertRaises(tx.InitOperationFailure) as caught:
                            lease._recheck(current, revision)
                        self.assertEqual(caught.exception.outcome.reason, "stale_revision")

    def test_absent_dependency_is_exact_and_truncated_payload_limits_cannot_skip_apply(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            _, owner, targets, revision, originals, _ = target_fixture(custody)
            active = [None]
            @contextmanager
            def parent(path):
                active[0] = path; yield None if originals.get(path) is not None and originals[path].data is None else 400
            def read(_fd, _name, _limit):
                item = originals[active[0]]; owner._last_read_facts = dict(revision._raw)[item.path]
                return None if item.before is None else (item.before, item.data)
            owner._parent, owner._read = parent, read
            owner._current = lambda _path, **_kwargs: None
            owner._metadata_dependencies_check()
            object.__setattr__(targets, "_payload_limits", ())
            owner._prepare = Mock(side_effect=AssertionError("no staging from incomplete cardinality"))
            with self.assertRaises(tx.InitOperationFailure):
                owner.apply_metadata_text_typed([(originals[targets.paths[0]], b"Reviewed note.")])
            owner._prepare.assert_not_called()

    def test_journal_uses_note_payload_cap_not_version_dependency_cap(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for size in (2000, 2001):
                _, owner, targets, _, originals, _ = target_fixture(custody, raw=b"Old note", counterpart=b"Default note")
                header = {"schemaVersion": 1, "transactionId": "d" * 32, "root": dict(owner.root_identity), "domain": "metadata_text"}
                plan = {**header, "directories": [{"path": path, "before": owner.parents[path], "after": None}
                                                   for path in targets.directories],
                        "files": [{"path": targets.paths[0], "before": originals[targets.paths[0]].before,
                                   "after": binding(b"x" * size, 900)}]}
                contents = {"header.json": tx._json(header), "plan.json": tx._json(plan),
                            "commit.pending": owner._marker(plan, "COMMITTED"), "rollback.pending": owner._marker(plan, "ROLLED_BACK")}
                entries = {name: (binding(raw, 950 + i), raw) for i, (name, raw) in enumerate(contents.items())}
                owner._read = lambda _fd, name, _limit=tx.MAX_FILE_BYTES: entries.get(name)
                owner._bind_workflow_controls(400, contents["header.json"], contents["plan.json"], plan)
                owner._workflow_complete = True
                if size == 2000:
                    self.assertEqual(owner._load(400), plan)
                else:
                    with self.assertRaises(ValidationError): owner._load(400)


class RequiredNotesFilesystemTests(unittest.TestCase):
    """Genuine original Linux transactions; Root selects this class separately."""

    @contextmanager
    def project(self, *, kind="android-build", raw=None, counterpart=None):
        import tempfile
        from mobile_release.cancellation import CleanupScope, DefaultCancellation
        from mobile_release.init_workspace_custody import InitRootLease, _LeasePurpose
        self.assertTrue(sys.platform.startswith("linux"), "current typed note backend requires Linux qualification")
        data, context = configured(kind)
        with tempfile.TemporaryDirectory(prefix="mrk-required-notes-") as folder:
            root = Path(folder); (root / "release").mkdir(); (root / text.IGNORE_PATH).write_bytes(COVERED)
            (root / text.CONFIG_PATH).write_bytes(json.dumps(data).encode())
            if kind.startswith("android-"):
                path = root / data["version"]["source"]; path.parent.mkdir(parents=True); path.write_bytes(VERSION)
            selection = notes.required_note_selection(notes.notes_configuration(json.dumps(data), context),
                                                       VERSION if kind.startswith("android-") else None)
            for relative, content in ((selection.path, raw), (selection.counterpart_path, counterpart)):
                if relative is not None and content is not None:
                    path = root / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content); path.chmod(0o640)
            unrelated = root / "keep.txt"; unrelated.write_bytes(b"Unrelated fixture source.\n")
            before = {path: (root / path).stat() for path in (*text.DEPENDENCY_PATHS, "keep.txt")}
            if selection.version_source is not None:
                before[selection.version_source] = (root / selection.version_source).stat()
            registered = root.stat(); guard = DefaultCancellation(ValidationError, "required-note fixture cleanup failed")
            lease = InitRootLease(root, cancellation=guard, profile=PROFILE,
                purpose=_LeasePurpose.REQUIRED_NOTES,
                registered_identity={"device": registered.st_dev, "inode": registered.st_ino,
                                     "mode": registered.st_mode, "uid": registered.st_uid, "gid": registered.st_gid})
            cleanup = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
            try:
                with cleanup:
                    guard.install(); guard.activate(); lease.acquire()
                    yield root, context, selection, lease, before
            finally:
                cleanup.__exit__(*sys.exc_info())
            self.assertTrue(lease.closed)
            self.assertFalse(guard.lifetime_ledger.fatal)
            self.assertEqual(guard.handler_state, "RESTORED")

    @staticmethod
    def facts(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    def prepare(self, lease, context, text_value):
        checkout = edit.capture_required_notes_edit(lease, context)
        plan = edit.prepare_required_notes_edit(lease, checkout, checkout.revision, context, checkout.baseline, text_value)
        return checkout, plan

    def assert_clean(self, root):
        self.assertTrue(all(not (root / state).exists() for state in tx.ALL_STATE_NAMES))

    def test_new_android_note_creates_only_original_target_and_preserves_readonly_facts(self):
        with self.project() as (root, context, selection, lease, before):
            checkout, plan = self.prepare(lease, context, "Improved release.\r\n")
            self.assertEqual(plan.view["action"], "create")
            self.assertNotIn("app/config", plan.view["createDirectories"])
            outcome = edit.apply_required_notes_edit(lease, plan)
            self.assertEqual(outcome, shared.CoreEditOutcome("committed", "clean", "settled", "none"))
            self.assertEqual((root / selection.path).read_bytes(), b"Improved release.\r\n")
            self.assertFalse((root / selection.counterpart_path).exists())
            for path, original in before.items(): self.assertEqual(self.facts((root / path).stat()), self.facts(original))
            self.assert_clean(root)
            self.assertEqual(edit.apply_required_notes_edit(lease, plan).reason, "invalid_params")
            edit.discard_required_notes_edit(plan)
            self.assertEqual(plan.view, {}); self.assertEqual(checkout.baseline, {})

    def test_default_and_apple_replacement_preserve_original_mode_and_counterpart(self):
        for kind in ("android-default", "ios-beta-review", "ios-app-review", "testflight-what-to-test"):
            other = b"Exact build note." if kind.startswith("android-") else None
            with self.subTest(kind=kind), self.project(kind=kind, raw=b"Old reviewed note.\r\n", counterpart=other) as (root, context, selection, lease, _):
                _, plan = self.prepare(lease, context, "New reviewed note.\r\n")
                self.assertEqual(plan.view["before"], {"state": "present", "text": "Old reviewed note.\r\n"})
                self.assertEqual(plan.view["action"], "replace")
                result = edit.apply_required_notes_edit(lease, plan)
                self.assertEqual((result.effect, result.journal, result.reason), ("committed", "clean", "none"))
                self.assertEqual((root / selection.path).read_bytes(), b"New reviewed note.\r\n")
                self.assertEqual(stat.S_IMODE((root / selection.path).stat().st_mode), 0o640)
                if other is not None: self.assertEqual((root / selection.counterpart_path).read_bytes(), other)
                self.assert_clean(root)

    def test_changed_version_counterpart_or_readonly_parent_refuses_without_retargeting(self):
        for change in ("version", "counterpart", "parent"):
            with self.subTest(change=change), self.project(raw=b"Old note.") as (root, context, selection, lease, _):
                _, plan = self.prepare(lease, context, "New note.")
                if change == "version": (root / selection.version_source).write_bytes(VERSION.replace(b"42", b"43"))
                elif change == "counterpart": (root / selection.counterpart_path).write_bytes(b"New default appeared.")
                else:
                    parent = root / "app/config"
                    original_mode = stat.S_IMODE(parent.stat().st_mode)
                    parent.chmod(original_mode ^ stat.S_IXGRP)
                    self.assertNotEqual(stat.S_IMODE(parent.stat().st_mode), original_mode)
                result = edit.apply_required_notes_edit(lease, plan)
                self.assertEqual((result.effect, result.journal, result.reason), ("not_started", "not_created", "stale_revision"))
                self.assertEqual((root / selection.path).read_bytes(), b"Old note.")
                self.assertFalse((root / selection.path.replace("42.txt", "43.txt")).exists())
                self.assert_clean(root)

    def test_failure_after_install_rolls_back_one_leaf_and_original_created_parents(self):
        for original in (None, b"Old reviewed note."):
            with self.subTest(replace=original is not None), self.project(raw=original) as (root, context, selection, lease, _):
                _, plan = self.prepare(lease, context, "New reviewed note.")
                publish = tx.InitWorkspace._publish_terminal; injected = []
                def fail_once(owner, fd, data, state):
                    if state == "COMMITTED" and not injected:
                        injected.append(True); raise OSError("fixture failure before commit decision")
                    return publish(owner, fd, data, state)
                with patch.object(tx.InitWorkspace, "_publish_terminal", fail_once):
                    result = edit.apply_required_notes_edit(lease, plan)
                self.assertEqual(injected, [True])
                self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                                 ("rolled_back", "clean", "settled", "filesystem_error"))
                if original is None:
                    self.assertFalse((root / selection.path).exists())
                    self.assertTrue(all(not (root / path).exists() for path in selection.directories))
                else:
                    self.assertEqual((root / selection.path).read_bytes(), original)
                    self.assertEqual(stat.S_IMODE((root / selection.path).stat().st_mode), 0o640)
                self.assertFalse((root / selection.counterpart_path).exists())
                self.assert_clean(root)

    def test_exact_raw_noop_and_linked_original_refusal_never_create_a_journal(self):
        original = b"Reviewed note.\r\n"
        with self.project(raw=original) as (root, context, selection, lease, _):
            before = (root / selection.path).stat()
            _, plan = self.prepare(lease, context, original.decode())
            self.assertEqual(plan.view["action"], "preserve")
            self.assertEqual(edit.apply_required_notes_edit(lease, plan), shared.CoreEditOutcome("unchanged", "not_created", "settled", "none"))
            self.assertEqual(self.facts((root / selection.path).stat()), self.facts(before)); self.assert_clean(root)
        for link in ("symbolic", "hard"):
            with self.subTest(link=link), self.project() as (root, context, selection, lease, _):
                target = root / selection.path; target.parent.mkdir(parents=True)
                source = root / "selected-original.txt"; source.write_bytes(original)
                if link == "symbolic": target.symlink_to(source)
                else: os.link(source, target)
                with self.assertRaises(shared.ConfigEditFailure): edit.capture_required_notes_edit(lease, context)
                self.assertEqual(source.read_bytes(), original); self.assert_clean(root)


if __name__ == "__main__":
    unittest.main()
