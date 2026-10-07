"""Real typed saved-text journals and joined restart regressions.

Run only inside the lead's reviewed nonroot Linux/macOS filesystem/process
boundary. The first restart child intentionally exits after an actual fsynced
move; only its original joined outcome permits a second process or disposal.
No native UI, Store, network, credential or installed-runtime proof is implied.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager, nullcontext
from pathlib import Path
from unittest.mock import patch

# This sole fixed child entry imports the same admitted SOURCE, not a test
# substitute engine or an arbitrary caller-selected module/search path.
if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--restart-child":
    sys.path.insert(0, str(Path(__file__).absolute().parents[2] / "src"))

from mobile_release import config_edit as shared
from mobile_release import init_transaction as tx
from mobile_release import metadata_text as text
from mobile_release import metadata_text_edit as text_edit
from mobile_release import release_version_edit as version_edit
from mobile_release import saved_text_recovery as recovery
from mobile_release import version_text as version
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.errors import ValidationError
from mobile_release.init_workspace_custody import InitRootLease, LockedInitScope


OLD_VERSION = b"# Keep this comment\r\n VERSION_NAME = '1.2.3' \nBUILD_NUMBER = \"7\"\r\nOTHER = keep"
VALUES = {"name": "2.3.4", "build": "8"}
CASES = ("android", "ios", "version")
SESSION = "0123456789abcdef0123456789abcdef"
INTERRUPTED = 86


class _Pause(Exception):
    """Known test edge after/before the stated actual original operation."""


def _config():
    return {"schemaVersion": 1,
        "version": {"source": "public/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified"},
        "metadata": {"root": "public/store", "androidLocales": ["en-US", "fr-FR"], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []}}


def _profile(case):
    assert case in CASES
    return tx.TypedEditProfile.RELEASE_VERSION if case == "version" else tx.TypedEditProfile.METADATA_TEXT


def _selection(case):
    raw = json.dumps(_config())
    return version.public_version_selection(raw) if case == "version" else text.public_text_selection(raw, case, "en-US")


def _fields(case, *, changed=False):
    return [{"id": identity, "text": ("https://public.invalid/policy" if identity.endswith("_url.txt") else
             "Changed public copy" if changed else "Original public copy")}
            for identity in _selection(case).ids]


def _facts(path):
    v = path.lstat()
    return (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_gid, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)


def _snapshot(root):
    # Bounded private fixtures only. Never follows a test symlink.
    rows = {}
    for path in sorted(root.rglob("*")):
        v = path.lstat()
        rows[path.relative_to(root).as_posix()] = (_facts(path),
            os.readlink(path) if stat.S_ISLNK(v.st_mode) else path.read_bytes() if stat.S_ISREG(v.st_mode) else None)
    return rows


def _change_same_byte_facts(path, *, ctime_only):
    """Real private-fixture metadata change, never an invented stat return."""
    before, raw = path.stat(), path.read_bytes()
    time.sleep(0.002)  # Fixed separation from the just-returned original rename.
    if ctime_only:
        mode = stat.S_IMODE(before.st_mode)
        path.chmod(mode ^ 0o100)
        path.chmod(mode)
    else:
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    after = path.stat()
    assert path.read_bytes() == raw and after.st_ino == before.st_ino and after.st_dev == before.st_dev
    if ctime_only:
        assert (after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns) == (
            before.st_mode, before.st_uid, before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns)
        assert after.st_ctime_ns != before.st_ctime_ns
    else:
        assert after.st_mtime_ns != before.st_mtime_ns
    return _facts(path)


def _init_project(root, case, *, empty=False):
    root.mkdir(mode=0o700)
    (root / "release").mkdir()
    (root / "release/mobile-release.json").write_text(json.dumps(_config()), encoding="utf-8")
    # Metadata deliberately remains seven-only; version preserves the existing
    # larger exact ignore policy, not a newly permissive common subset.
    ignore = tx.IGNORE_LINES if case == "version" else tx.METADATA_IGNORE_LINES
    (root / ".gitignore").write_text("\n".join(ignore) + "\n", encoding="utf-8")
    (root / "unrelated.txt").write_bytes(b"unrelated public fixture original\n")
    if not empty:
        selection = _selection(case)
        bodies = [OLD_VERSION] if case == "version" else [row["text"].encode() for row in _fields(case)]
        for path, body in zip(selection.paths, bodies):
            item = root / path
            item.parent.mkdir(parents=True, exist_ok=True)
            item.write_bytes(body); item.chmod(0o640)
    return root


@contextmanager
def _project(case, *, empty=False):
    with tempfile.TemporaryDirectory(prefix="mrk-saved-text-recovery-",
            dir="/private/tmp" if sys.platform == "darwin" else None) as directory:
        yield _init_project(Path(directory) / "project", case, empty=empty)


@contextmanager
def _live_lease(root, case, *, restoring):
    v = root.stat()
    guard = DefaultCancellation(ValidationError, "saved-text fixture cleanup failed")
    lease = InitRootLease(root, cancellation=guard, profile=_profile(case), saved_text_recovery=restoring,
        registered_identity={"device": v.st_dev, "inode": v.st_ino, "mode": v.st_mode, "uid": v.st_uid, "gid": v.st_gid})
    cleanup = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
    try:
        with cleanup:
            guard.install(); guard.activate(); lease.acquire()
            yield lease, guard
    finally:
        cleanup.__exit__(*sys.exc_info())
        if not lease.closed or guard.handler_state != "RESTORED":
            raise AssertionError("original lease/handler did not settle")


def _normal(lease, case):
    if case == "version":
        checkout = version_edit.capture_release_version_edit(lease)
        plan = version_edit.prepare_release_version_edit(lease, checkout, checkout.revision, checkout.baseline,
            "create" if checkout.values is None else "edit", VALUES)
        assert plan.view["validation"]["valid"] is True
    else:
        checkout = text_edit.capture_metadata_text_edit(lease, case, "en-US")
        plan = text_edit.prepare_metadata_text_edit(lease, checkout, checkout.revision, checkout.baseline, _fields(case, changed=True))
        assert plan.view["validation"]["valid"] is True
    assert any(body is not None for body in plan._payloads)
    return checkout, plan


def _stage(root, case, phase):
    """Use actual writer controls/staging, then retire the original lease.

    These known boundary pauses are NOT fresh-process evidence; the separate
    joined-child group below proves that no Python authority crosses restart.
    """
    assert phase in {"preparing", "ready_old", "between", "mixed", "committed", "rolled_back",
                     "preparing_partial", "committed_partial", "rolled_back_partial"}
    with _live_lease(root, case, restoring=False) as (lease, guard):
        checkout, prepared = _normal(lease, case)
        payloads = tuple(file.data if raw is None else raw for file, raw in zip(checkout._files, prepared._payloads))
        with lease.workspace_scope(checkout._revision) as w:
            w.rename = tx._rename_function()
            changes = [(file.observed(), raw) for file, raw in zip(checkout._files, prepared._payloads)]
            moving_state = w._state_move
            def state_move(old, new):
                if phase.startswith("preparing") and (old, new) == w._state_names[:2]:
                    raise _Pause("after staged original fsyncs, before READY")
                return moving_state(old, new)
            with patch.object(w, "_state_move", new=state_move):
                try:
                    plan = w._prepare(changes)
                except _Pause:
                    assert phase.startswith("preparing")
                    with w._private(w._state_names[0]) as fd:
                        plan = w._load(fd)
            if not phase.startswith("preparing") and phase != "ready_old":
                with w._private(w._state_names[1]) as fd:
                    moving = w._move
                    stopping = "new-0" if phase == "between" or case == "version" else "new-1"
                    def move(src_fd, src, dst_fd, dst, expected, **kwargs):
                        if phase in {"between", "mixed", "rolled_back", "rolled_back_partial"} and src == stopping:
                            raise _Pause("before one new original file move")
                        return moving(src_fd, src, dst_fd, dst, expected, **kwargs)
                    w._installing = True
                    try:
                        with patch.object(w, "_move", new=move):
                            try:
                                w._install(fd, plan)
                            except _Pause:
                                assert phase in {"between", "mixed", "rolled_back", "rolled_back_partial"}
                    finally:
                        w._installing = False
                    if phase.startswith("rolled_back"):
                        w._rollback(fd, plan)
            if phase.endswith("_partial"):
                moving_state(w.state(), w._state_names[2])
                unlink = w._unlink
                removed = []
                def interrupted(name, **kwargs):
                    unlink(name, **kwargs)
                    if name not in tx.CONTROLS and name not in w._state_names:
                        removed.append(name)
                        raise _Pause("after exactly one original DATA removal")
                with patch.object(w, "_unlink", new=interrupted):
                    try:
                        w._cleanup()
                    except _Pause:
                        pass
                assert len(removed) == 1
            assert not guard.lifetime_ledger.fatal
        return plan, payloads


def _prepare(lease):
    checkout = recovery.capture_saved_text_recovery(lease)
    prepared = recovery.prepare_saved_text_recovery(lease, checkout, checkout.revision)
    return checkout, prepared


class SavedTextRecoveryFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(sys.platform.startswith("linux") or sys.platform == "darwin")
        self.assertNotEqual(os.geteuid(), 0, "reviewed nonroot fixture boundary required")

    def assert_clean(self, root, case, *, empty=False, committed=False, payloads=(), modes=()):
        self.assertTrue(all(not (root / name).exists() for name in tx.ALL_STATE_NAMES))
        if empty and not committed:
            self.assertFalse((root / "public").exists())
        else:
            expected = payloads if committed else ([OLD_VERSION] if case == "version" else
                                                    [row["text"].encode() for row in _fields(case)])
            for index, (path, raw) in enumerate(zip(_selection(case).paths, expected)):
                self.assertEqual((root / path).read_bytes(), raw)
                # New-file mode is the actual writer's captured mode under the
                # reviewed caller umask, not a fabricated unconditional 0644.
                expected_mode = modes[index] if empty else 0o640
                self.assertEqual(stat.S_IMODE((root / path).stat().st_mode), expected_mode)
                if empty: self.assertEqual(expected_mode & ~0o644, 0)
        self.assertEqual((root / "unrelated.txt").read_bytes(), b"unrelated public fixture original\n")

    def test_actual_writer_all_actions_new_parents_and_three_closed_rosters(self):
        phases = (("preparing", False), ("ready_old", False), ("between", False), ("mixed", False),
                  ("committed", False), ("rolled_back", False), ("preparing_partial", False),
                  ("committed_partial", False), ("rolled_back_partial", False),
                  ("preparing", True), ("mixed", True), ("committed", True))
        for case in CASES:
            for phase, empty in phases:
                with self.subTest(case=case, phase=phase, empty=empty), _project(case, empty=empty) as root:
                    kept = {p: _facts(root / p) for p in ("release", "release/mobile-release.json", ".gitignore", "unrelated.txt")}
                    originals = {} if empty else {p: _facts(root / p) for p in _selection(case).paths}
                    plan, payloads = _stage(root, case, phase)
                    self.assertEqual(plan["schemaVersion"], 2)
                    self.assertEqual(plan["recovery"]["policy"], "saved-text-recovery-v1")
                    committed = phase.startswith("committed")
                    action = "committed_cleanup" if committed else "preparing_cleanup" if phase.startswith("preparing") else (
                        "rolled_back_cleanup" if phase.startswith("rolled_back") else "rollback")
                    effect = {"rollback": "rolled_back", "rolled_back_cleanup": "rolled_back",
                              "committed_cleanup": "committed", "preparing_cleanup": "not_started"}[action]
                    at_inspection = _snapshot(root)
                    with _live_lease(root, case, restoring=True) as (lease, guard):
                        checkout, prepared = _prepare(lease)
                        self.assertEqual(checkout.view["action"], action)
                        self.assertEqual(checkout.view["domain"], "release_version" if case == "version" else "metadata_text")
                        self.assertEqual([row["path"] for row in checkout.view["files"]], list(_selection(case).paths))
                        self.assertEqual(checkout.view, prepared.view)
                        self.assertNotEqual(checkout.revision, prepared.token)
                        self.assertIs(type(checkout._revision), recovery.SavedTextRecoveryRevision)
                        self.assertIsNone(lease._revision)
                        # Neither readonly scope changes any captured payload or control.
                        self.assertEqual(_snapshot(root), at_inspection)
                        with patch.object(tx.InitWorkspace, "recover", side_effect=AssertionError("no generic recovery")), \
                             patch.object(tx.InitWorkspace, "_fixed_recovery", side_effect=AssertionError("no old writer authority")), \
                             patch.object(tx.InitWorkspace, "_install", side_effect=AssertionError("never retry save")):
                            outcome = recovery.apply_saved_text_recovery(lease, prepared)
                        self.assertEqual(outcome, shared.CoreEditOutcome(effect, "clean", "settled", "none"))
                        # Every actual cleanup return retired exactly its
                        # captured slot; actual rename ctime was not a blanket
                        # later exception and does not make rollback refuse.
                        book = lease._scopes[-1].workspace._saved_text_current
                        self.assertTrue(all(fact.binding is None and fact.raw is None
                            for (where, _), (_, fact) in book.items() if where in {"private", "journal"}))
                        for path in _selection(case).paths:
                            fact, actual = book["public", path][1], root / path
                            if actual.exists():
                                self.assertEqual(dict(fact.raw)["ctime"], actual.stat().st_ctime_ns)
                                self.assertEqual(dict(fact.raw)["mtime"], actual.stat().st_mtime_ns)
                            else:
                                self.assertIsNone(fact.binding)
                        self.assertEqual(recovery.apply_saved_text_recovery(lease, prepared).reason, "invalid_params")
                        self.assertEqual(len(lease._scopes), 3)
                        for scope in lease._scopes:
                            w = scope.workspace
                            self.assertEqual(w._creation, {"state": "NEW"})
                            self.assertIsNone(w._rooted_revision)
                            self.assertFalse(w._workflow_complete or w._install_started)
                            self.assertEqual(w._captured, {})
                        self.assertFalse(guard.lifetime_ledger.fatal)
                    self.assert_clean(root, case, empty=empty, committed=committed, payloads=payloads,
                        modes=tuple((row["after"] or row["before"])["mode"] for row in plan["files"]))
                    for p, facts in kept.items():
                        self.assertEqual(_facts(root / p), facts)
                    if not committed:
                        for p, facts in originals.items():
                            self.assertEqual(_facts(root / p)[:-1], facts[:-1])

    def test_legacy_partial_forged_and_cross_domain_controls_preserve_every_original(self):
        mutations = ("legacy", "missing_plan", "header_tmp", "missing_pending", "duplicate_terminal", "foreign_domain",
                     "unknown_entry", "context_selection", "context_digest", "root", "device", "plan_limit", "marker")
        for change in mutations:
            with self.subTest(change=change), _project("android") as root:
                _stage(root, "android", "committed_partial")
                journal = root / tx.METADATA_CLEANUP
                if change == "missing_plan": (journal / "plan.json").unlink()
                elif change == "header_tmp": (journal / "header.json").rename(journal / "header.tmp")
                elif change == "missing_pending": (journal / "rollback.pending").unlink()
                elif change == "duplicate_terminal": (journal / "commit.pending").write_bytes((journal / "COMMITTED").read_bytes())
                elif change == "unknown_entry": (journal / "user-note.txt").write_bytes(b"must remain")
                elif change == "marker": (journal / "COMMITTED").write_bytes(b"{}\n")
                else:
                    header = json.loads((journal / "header.json").read_bytes())
                    plan = json.loads((journal / "plan.json").read_bytes())
                    if change == "legacy":
                        header["schemaVersion"] = 1; del header["recovery"]
                        plan["schemaVersion"] = 1; del plan["recovery"]
                    elif change == "foreign_domain": header["domain"] = "release_version"
                    elif change == "context_selection": header["recovery"]["selection"]["locale"] = "de-DE"
                    elif change == "context_digest": header["recovery"]["config"]["sha256"] = "0" * 64
                    elif change == "root": header["root"]["inode"] += 1
                    elif change == "device": plan["files"][0]["after"]["device"] += 1
                    elif change == "plan_limit": plan["files"][0]["after"]["size"] = text.MAX_TEXT_BYTES + 1
                    if change in {"context_selection", "context_digest"}: plan.update(header)
                    (journal / "header.json").write_bytes(tx._json(header))
                    (journal / "plan.json").write_bytes(tx._json(plan))
                before = _snapshot(root)
                with _live_lease(root, "android", restoring=True) as (lease, _):
                    checkout = recovery.capture_saved_text_recovery(lease)
                    self.assertEqual(checkout.view["state"], "conflict")
                    self.assertEqual(checkout.view["reason"], "legacy_journal" if change == "legacy" else
                                     "foreign_journal" if change in {"foreign_domain", "root"} else
                                     "dependency_changed" if change.startswith("context") else
                                     "incomplete_journal" if change in {"missing_plan", "header_tmp", "missing_pending", "duplicate_terminal"} else "invalid_journal")
                    self.assertIsNone(checkout._revision)
                    self.assertIsNone(checkout.view["selection"])
                    self.assertEqual(checkout.view["files"], [])
                    self.assertEqual(checkout.view["privateCleanup"]["fileCount"], 0)
                    with self.assertRaises(shared.ConfigEditFailure):
                        recovery.prepare_saved_text_recovery(lease, checkout, checkout.revision)
                self.assertEqual(_snapshot(root), before)

    def test_changed_dependencies_targets_aliases_and_original_identities_are_not_adopted(self):
        for change in ("config", "ignore", "target", "alias", "hardlink", "symlink", "private_mode", "private_owner"):
            with self.subTest(change=change), _project("version") as root:
                _stage(root, "version", "committed")
                journal = root / tx.VERSION_READY
                target = root / _selection("version").source
                if change in {"config", "ignore"}:
                    path = root / ("release/mobile-release.json" if change == "config" else ".gitignore")
                    path.write_bytes(path.read_bytes() + b" ")
                elif change == "target": target.write_bytes(b"VERSION_NAME=9.9\nBUILD_NUMBER=99\n")
                elif change == "alias": target.with_name("Version.properties").write_bytes(b"must remain")
                elif change == "hardlink": os.link(journal / "old-0", journal / "unknown-hardlink")
                elif change == "symlink":
                    (journal / "old-0").rename(journal / "held-original")
                    (journal / "old-0").symlink_to("held-original")
                elif change == "private_mode": journal.chmod(0o755)
                before = _snapshot(root)
                with _live_lease(root, "version", restoring=True) as (lease, _):
                    try:
                        # A nonroot fixture cannot chown a real journal to a
                        # foreign UID. Vary only the expected-owner observation;
                        # actual fd/stat/name/mode reads remain unchanged.
                        owner = (patch.object(tx.os, "geteuid", return_value=os.geteuid() + 1)
                                 if change == "private_owner" else nullcontext())
                        with owner:
                            checkout = recovery.capture_saved_text_recovery(lease)
                    except shared.ConfigEditFailure as error:
                        self.assertIn(change, {"alias", "hardlink", "symlink", "private_mode", "private_owner"})
                        self.assertNotEqual(error.outcome.reason, "none")
                    else:
                        self.assertEqual(checkout.view["state"], "conflict")
                        self.assertIsNone(checkout._revision)
                self.assertEqual(_snapshot(root), before)

    def test_qualified_revision_and_exact_consent_are_one_use_without_serialized_authority(self):
        for bad in ("revision", "discard", "config", "ignore", "target", "journal", "root"):
            with self.subTest(bad=bad), _project("version") as root:
                _stage(root, "version", "committed")
                with _live_lease(root, "version", restoring=True) as (lease, _):
                    checkout = recovery.capture_saved_text_recovery(lease)
                    for value in (checkout, checkout._revision):
                        with self.assertRaises(TypeError): copy.copy(value)
                        with self.assertRaises(TypeError): copy.deepcopy(value)
                        with self.assertRaises(AttributeError): value._token = "e" * 32
                    with self.assertRaises(TypeError): recovery.SavedTextRecoveryRevision()
                    self.assertEqual(recovery.apply_saved_text_recovery(lease, {"revision": checkout.revision,
                        "inspection": checkout.view}).reason, "invalid_params")
                    if bad in {"revision", "discard"}:
                        if bad == "discard": recovery.discard_saved_text_recovery(checkout)
                        with self.assertRaises(shared.ConfigEditFailure):
                            recovery.prepare_saved_text_recovery(lease, checkout, "f" * 32 if bad == "revision" else checkout.revision)
                    else:
                        prepared = recovery.prepare_saved_text_recovery(lease, checkout, checkout.revision)
                        if bad in {"config", "ignore", "target"}:
                            path = root / {"config": "release/mobile-release.json", "ignore": ".gitignore",
                                           "target": _selection("version").source}[bad]
                            path.write_bytes(path.read_bytes() + b" ")
                        elif bad == "journal":
                            old = root / tx.VERSION_READY
                            moved = root.parent / "original-journal"
                            old.rename(moved); old.mkdir(mode=0o700)
                            for path in moved.iterdir(): path.rename(old / path.name)
                        else: root.chmod(0o750)
                        outcome = recovery.apply_saved_text_recovery(lease, prepared)
                        self.assertEqual(outcome, shared.CoreEditOutcome("committed", "recovery_required", "settled", "stale_revision"))
                        self.assertEqual(recovery.apply_saved_text_recovery(lease, prepared).reason, "invalid_params")
                    self.assertTrue((root / tx.VERSION_READY).exists())
                    self.assertEqual(lease.last_outcome.effect, "committed")
                    self.assertNotEqual(lease.last_outcome.journal, "clean")

    def test_idle_and_discard_keep_truthful_attention_without_an_earlier_synthetic_error(self):
        for case in CASES:
            with self.subTest(case=case), _project(case) as root:
                with _live_lease(root, case, restoring=True) as (lease, _):
                    checkout = recovery.capture_saved_text_recovery(lease)
                    self.assertEqual(checkout.view["state"], "idle")
                    self.assertIsNone(checkout._revision)
                    recovery.discard_saved_text_recovery(checkout)
                    self.assertEqual(lease.last_outcome, tx.InitApplyOutcome("not_started", "not_created", "settled", "none"))
                _stage(root, case, "committed")
                before = _snapshot(root)
                with _live_lease(root, case, restoring=True) as (lease, _):
                    checkout = recovery.capture_saved_text_recovery(lease)
                    recovery.discard_saved_text_recovery(checkout)
                    self.assertEqual(lease.last_outcome, tx.InitApplyOutcome("committed", "recovery_required", "settled", "none"))
                    self.assertIsNone(lease._scopes[0].workspace._terminal_seen)
                self.assertEqual(_snapshot(root), before)

    def test_real_rename_fsync_and_cleanup_failures_never_retry_or_erase_the_first_outcome(self):
        for failure in ("rename_return", "terminal_fsync", "cleanup_return"):
            with self.subTest(failure=failure), _project("version") as root:
                _stage(root, "version", "committed" if failure == "cleanup_return" else "between")
                with _live_lease(root, "version", restoring=True) as (lease, _):
                    _, prepared = _prepare(lease)
                    calls = []
                    first = OSError("fixed fixture interruption; not a public reason")
                    method = "_unlink" if failure == "cleanup_return" else "_fsync" if failure == "terminal_fsync" else "_move"
                    original = getattr(tx.InitWorkspace, method)
                    def fail(w, *args, **kwargs):
                        value = original(w, *args, **kwargs)
                        selected = (w._saved_text_recovery is not None and
                            (failure != "terminal_fsync" or w._publishing_terminal == "ROLLED_BACK" and w._terminal_seen == "ROLLED_BACK"))
                        if selected and not calls:
                            calls.append(args)
                            raise first
                        return value
                    with patch.object(tx.InitWorkspace, method, new=fail):
                        outcome = recovery.apply_saved_text_recovery(lease, prepared)
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(outcome.reason, "filesystem_error")
                    self.assertEqual(outcome.resources, "settled")
                    self.assertEqual(outcome.journal, "recovery_required")
                    self.assertEqual(outcome.effect, "committed" if failure == "cleanup_return" else
                                     "rolled_back" if failure == "terminal_fsync" else "unknown")
                    self.assertIs(lease._scopes[-1].workspace._restoration_primary, first)
                    self.assertEqual(recovery.apply_saved_text_recovery(lease, prepared).reason, "invalid_params")
                # A separate new inspection may finish the complete retained
                # controls. It never retroactively changes the failed result.
                with _live_lease(root, "version", restoring=True) as (lease, _):
                    _, prepared = _prepare(lease)
                    self.assertEqual(recovery.apply_saved_text_recovery(lease, prepared).reason, "none")
                self.assert_clean(root, "version", committed=failure == "cleanup_return",
                    payloads=[version.prepare_payload(_selection("version"), OLD_VERSION, "edit", VALUES)[0]])

        # An actual existing root descriptor is not the selected file's
        # parent. In particular the destination variant would otherwise move
        # the original old-0 into a different, initially absent root filename.
        for wrong in ("source_parent", "destination_parent"):
            with self.subTest(wrong=wrong), _project("version") as root:
                _stage(root, "version", "between")
                journal = root / tx.VERSION_READY
                captured = _snapshot(journal)
                with _live_lease(root, "version", restoring=True) as (lease, _):
                    _, prepared = _prepare(lease)
                    moving, routed = tx.InitWorkspace._move, []
                    def redirect(w, src_fd, src, dst_fd, dst, expected, **kwargs):
                        if w._saved_text_recovery is not None and src == "old-0" and not routed:
                            routed.append((src, dst))
                            if wrong == "source_parent": src_fd = w.fd
                            else: dst_fd = w.fd
                        return moving(w, src_fd, src, dst_fd, dst, expected, **kwargs)
                    with patch.object(tx.InitWorkspace, "_move", new=redirect):
                        outcome = recovery.apply_saved_text_recovery(lease, prepared)
                    self.assertEqual(len(routed), 1)
                    self.assertEqual(outcome, shared.CoreEditOutcome("unknown", "recovery_required", "settled", "stale_revision"))
                    self.assertIsInstance(lease._scopes[-1].workspace._restoration_primary, tx.InitConflict)
                self.assertEqual(_snapshot(journal), captured)
                self.assertFalse((root / Path(_selection("version").source).name).exists())
                self.assertEqual((journal / "old-0").read_bytes(), OLD_VERSION)
                self.assertFalse((journal / "ROLLED_BACK").exists())

    def test_real_read_and_original_scope_close_interruptions_preserve_known_effect_and_unknown_finality(self):
        # Read AFTER its actual full original return, but before the fresh
        # recheck can publish permission for any move/cleanup.
        with _project("version") as root:
            _stage(root, "version", "committed")
            before = _snapshot(root)
            with _live_lease(root, "version", restoring=True) as (lease, guard):
                _, prepared = _prepare(lease)
                calls, first = [], OSError("fixed lost bounded-read return")
                original = tx.InitWorkspace._read
                def read(w, *args, **kwargs):
                    value = original(w, *args, **kwargs)
                    if w._saved_text_recovery is not None and not calls:
                        calls.append(args); raise first
                    return value
                with patch.object(tx.InitWorkspace, "_read", new=read), \
                     patch.object(tx.InitWorkspace, "_move", side_effect=AssertionError("no effect after failed entry read")), \
                     patch.object(tx.InitWorkspace, "_unlink", side_effect=AssertionError("no cleanup after failed entry read")):
                    outcome = recovery.apply_saved_text_recovery(lease, prepared)
                self.assertEqual(len(calls), 1)
                self.assertEqual(outcome, shared.CoreEditOutcome("committed", "recovery_required", "settled", "filesystem_error"))
                self.assertFalse(guard.lifetime_ledger.fatal)
                self.assertEqual(recovery.recovery_outcome(lease, reason="cancelled").reason, "filesystem_error")
                self.assertEqual(recovery.apply_saved_text_recovery(lease, prepared).reason, "invalid_params")
            self.assertEqual(_snapshot(root), before)
        # The test wrapper observes ALL actual original closes first and then
        # loses the scope return. Production must still report unknown; that
        # fixture-only knowledge permits disposal, never result promotion.
        with _project("version") as root:
            _stage(root, "version", "committed")
            closed = []
            with self.assertRaises(ValidationError):
                with _live_lease(root, "version", restoring=True) as (lease, guard):
                    _, prepared = _prepare(lease)
                    original, first = LockedInitScope.close, OSError("fixed lost original scope-close return")
                    def close(scope):
                        value = original(scope)
                        if scope.lease is lease and len(lease._scopes) == 3 and scope is lease._active and not closed:
                            self.assertTrue(scope.closed)
                            self.assertTrue(scope.lock.number is None and scope.meta.number is None)
                            closed.append(scope); raise first
                        return value
                    with patch.object(LockedInitScope, "close", new=close):
                        outcome = recovery.apply_saved_text_recovery(lease, prepared)
                    self.assertEqual(len(closed), 1)
                    self.assertEqual(outcome, shared.CoreEditOutcome("committed", "clean", "unknown", "filesystem_error"))
                    self.assertTrue(guard.lifetime_ledger.fatal)
                    self.assertEqual(recovery.recovery_outcome(lease, reason="cancelled").reason, "filesystem_error")
                    self.assertEqual(recovery.apply_saved_text_recovery(lease, prepared).reason, "invalid_params")
            self.assertTrue(lease.closed and guard.handler_state == "RESTORED" and all(scope.closed for scope in lease._scopes))
            self.assert_clean(root, "version", committed=True,
                payloads=[version.prepare_payload(_selection("version"), OLD_VERSION, "edit", VALUES)[0]])

    def test_final_public_recheck_protects_last_backup_after_original_state_move(self):
        with _project("version") as root:
            _stage(root, "version", "committed")
            with _live_lease(root, "version", restoring=True) as (lease, _):
                _, prepared = _prepare(lease)
                original = tx.InitWorkspace._state_move
                def change(w, old, new):
                    original(w, old, new)
                    if w._saved_text_recovery is not None:
                        (root / _selection("version").source).write_bytes(b"user changed after confirmation\n")
                with patch.object(tx.InitWorkspace, "_state_move", new=change):
                    outcome = recovery.apply_saved_text_recovery(lease, prepared)
                self.assertEqual(outcome, shared.CoreEditOutcome("committed", "recovery_required", "settled", "stale_revision"))
            self.assertEqual((root / tx.VERSION_CLEANUP / "old-0").read_bytes(), OLD_VERSION)
            self.assertEqual((root / _selection("version").source).read_bytes(), b"user changed after confirmation\n")


        # Late public/dependency edits and same-inode/same-byte private
        # metadata drift occur AFTER cleanup_entries has returned, but BEFORE
        # the first backup deletion. The entire original private inventory,
        # including the deliberately changed entry, must still be retained.
        changes = ("target", "dependency", "old_mtime", "old_ctime", "new_mtime", "new_ctime",
                   "control_mtime", "control_ctime")
        for case in ("android", "version"):
            for change in changes:
                with self.subTest(case=case, change=change), _project(case) as root:
                    preparing = change.startswith("new_")
                    _stage(root, case, "preparing" if preparing else "committed")
                    names = tx.VERSION_STATE_NAMES if case == "version" else tx.METADATA_STATE_NAMES
                    journal = root / names[0 if preparing else 1]
                    captured = _snapshot(journal)
                    selected_path = _selection(case).paths[0]
                    with _live_lease(root, case, restoring=True) as (lease, _):
                        _, prepared = _prepare(lease)
                        entries = recovery.SavedTextRecoveryRevision.cleanup_entries
                        read, unlink = tx.InitWorkspace._read, os.unlink
                        armed, changed, deleted = [], [], []
                        def after_entries(revision, w):
                            value = entries(revision, w)
                            armed.append(w)
                            return value
                        def read_after(w, fd, name, *args, **kwargs):
                            if armed and w is armed[0] and not changed and tx._dir_identity(os.fstat(fd)) == w.private_identity:
                                private = root / names[2]
                                if change == "target":
                                    path = root / selected_path
                                    path.write_bytes(b"user changed after cleanup inventory grant\n")
                                elif change == "dependency":
                                    path = root / "release/mobile-release.json"
                                    path.write_bytes(path.read_bytes() + b" ")
                                else:
                                    slot = "old-0" if change.startswith("old_") else "new-0" if change.startswith("new_") else "header.json"
                                    path = private / slot
                                    _change_same_byte_facts(path, ctime_only=change.endswith("ctime"))
                                    captured[slot] = (_facts(path), path.read_bytes())
                                changed.append((path, _facts(path), path.read_bytes()))
                            return read(w, fd, name, *args, **kwargs)
                        def removing(name, *args, **kwargs):
                            deleted.append(name)
                            return unlink(name, *args, **kwargs)
                        with patch.object(recovery.SavedTextRecoveryRevision, "cleanup_entries", new=after_entries), \
                             patch.object(tx.InitWorkspace, "_read", new=read_after), \
                             patch.object(tx.os, "unlink", new=removing):
                            outcome = recovery.apply_saved_text_recovery(lease, prepared)
                        self.assertEqual(len(armed), 1)
                        self.assertEqual(len(changed), 1)
                        self.assertEqual(deleted, [])
                        self.assertEqual(outcome, shared.CoreEditOutcome("not_started" if preparing else "committed",
                            "recovery_required", "settled", "stale_revision"))
                        self.assertIsInstance(lease._scopes[-1].workspace._restoration_primary, tx.InitConflict)
                        self.assertEqual(recovery.apply_saved_text_recovery(lease, prepared).reason, "invalid_params")
                    self.assertEqual(_snapshot(root / names[2]), captured)
                    path, facts, raw = changed[0]
                    self.assertEqual((_facts(path), path.read_bytes()), (facts, raw))

        # Exact ctime after a RETURNED owned restore is now the current fact,
        # not permanently ignored because this file once moved. A later user
        # metadata change must stop before rollback.pending becomes terminal.
        for case in ("android", "version"):
            with self.subTest(case=case, point="after_restore_before_marker"), _project(case) as root:
                _stage(root, case, "between")
                names = tx.VERSION_STATE_NAMES if case == "version" else tx.METADATA_STATE_NAMES
                journal = root / names[1]
                old = (journal / "old-0").read_bytes()
                controls = {path.name: (_facts(path), path.read_bytes()) for path in journal.iterdir() if path.name in tx.CONTROLS}
                with _live_lease(root, case, restoring=True) as (lease, _):
                    _, prepared = _prepare(lease)
                    moving, changed = tx.InitWorkspace._move, []
                    target = root / _selection(case).paths[0]
                    def after_restore(w, src_fd, src, dst_fd, dst, expected, **kwargs):
                        value = moving(w, src_fd, src, dst_fd, dst, expected, **kwargs)
                        if w._saved_text_recovery is not None and src == "old-0" and not changed:
                            changed.append(_change_same_byte_facts(target, ctime_only=True))
                        return value
                    with patch.object(tx.InitWorkspace, "_move", new=after_restore), \
                         patch.object(recovery.SavedTextRecoveryRevision, "cleanup_entries",
                                      side_effect=AssertionError("no cleanup after changed restored original")):
                        outcome = recovery.apply_saved_text_recovery(lease, prepared)
                    self.assertEqual(len(changed), 1)
                    self.assertEqual(outcome, shared.CoreEditOutcome("unknown", "recovery_required", "settled", "stale_revision"))
                    self.assertIsNone(lease._scopes[-1].workspace._terminal_seen)
                self.assertEqual((target.read_bytes(), _facts(target)), (old, changed[0]))
                self.assertFalse((journal / "old-0").exists())
                self.assertFalse((journal / "ROLLED_BACK").exists())
                self.assertEqual({path.name: (_facts(path), path.read_bytes()) for path in journal.iterdir() if path.name in tx.CONTROLS}, controls)


def _child_engine(root, domain, mode):
    """Fixed real IO adapter around the original engine, not another process owner."""
    from mobile_release import _desktop_edit_engine as engine
    from mobile_release import _desktop_edit_protocol as wire
    from mobile_release._desktop_edit_control import EditInput

    assert domain in {"metadata_text", "release_version"} and mode in {"interrupt", "recover"}
    assert root.is_absolute() and os.geteuid() != 0
    case = "android" if domain == "metadata_text" else "version"
    reader, writer = os.pipe()
    os.dup2(reader, 0); os.close(reader)
    child = engine._Engine(time.monotonic(), domain=domain)
    original_request, original_move = EditInput.request, tx.InitWorkspace._move
    def feed(control, sequence, session):
        assert control is child.input and session in {None, SESSION}
        if sequence == 0:
            v = root.stat()
            params = {"root": str(root), "registeredIdentity": {"device": str(v.st_dev), "inode": str(v.st_ino),
                "mode": v.st_mode, "uid": v.st_uid, "gid": v.st_gid}}
            if mode == "recover": params["intent"] = "recover"
            elif case != "version": params.update(platform=case, locale="en-US")
            op = "open"
        elif sequence == 1:
            checkout = child.authority
            params = {"revision": checkout.revision}
            if mode == "recover": params["intent"] = "recover"
            elif case == "version": params.update(expectedBaseline=checkout.baseline, intent="edit", values=VALUES)
            else: params.update(expectedBaseline=checkout.baseline, fields=_fields(case, changed=True))
            op = "prepare"
        else:
            assert sequence == 2
            params = {"planToken": child.authority.token}
            if mode == "recover": params["intent"] = "recover"
            op = "apply"
        raw = json.dumps({"protocol": wire.METADATA_PROTOCOL if case != "version" else wire.VERSION_PROTOCOL,
            "session": SESSION, "seq": sequence, "op": op, "params": params}, separators=(",", ":")).encode()+b"\n"
        assert len(raw) < 4096 and os.write(writer, raw) == len(raw)
        return original_request(control, sequence, session)
    def interrupt(w, source_fd, source, destination_fd, destination, expected, **kwargs):
        value = original_move(w, source_fd, source, destination_fd, destination, expected, **kwargs)
        if mode == "interrupt" and destination == "old-0" and w._saved_text_recovery is None:
            # The ORIGINAL _move has returned only after both actual directory
            # fsyncs and exact destination checks. Do not run Python finally.
            os._exit(INTERRUPTED)
        return value
    scope = CleanupScope(child.guard, child.cleanup, owns_cancellation=True, first_primary=True)
    try:
        with patch.object(EditInput, "request", new=feed), patch.object(tx.InitWorkspace, "_move", new=interrupt):
            try:
                try:
                    with scope: child.run()
                finally: scope.__exit__(*sys.exc_info())
            except BaseException as error:
                child._remember(error)
            child.terminal()
        assert mode == "recover", "first child failed to reach the actual fixed move boundary"
        assert child.outcome == shared.CoreEditOutcome("rolled_back", "clean", "settled", "none")
        assert child.input.closed and child.lease.closed and child.guard.handler_state == "RESTORED"
        with _live_lease(root, case, restoring=False) as (lease, _):
            checkout = (version_edit.capture_release_version_edit(lease) if case == "version" else
                        text_edit.capture_metadata_text_edit(lease, case, "en-US"))
            loaded = [{"path": f.path, **text.content_digest(f.data)} for f in checkout._files]
            if case == "version":
                assert checkout.values == {"name": "1.2.3", "build": "7"}
                version_edit.discard_release_version_edit(checkout)
            else: text_edit.discard_metadata_text_edit(checkout)
        raw = json.dumps({"freshLoad": loaded, "domain": domain, "engineResourcesSettled": True}, separators=(",", ":")).encode()+b"\n"
        assert len(raw) <= 4096 and os.write(1, raw) == len(raw)
        return 0
    finally:
        os.close(writer)
        child.close_output()


class SavedTextRecoveryRestartTests(unittest.TestCase):
    """Actual C/A/W original join precedes every second child and cleanup."""
    def test_two_new_processes_per_domain_recover_only_persisted_fsynced_originals(self):
        from mobile_release import owned_process as owned
        from unit.test_owned_process import original_command_outcomes, all_original_commands_final

        self.assertTrue(sys.platform.startswith("linux") or sys.platform == "darwin")
        self.assertNotEqual(os.geteuid(), 0)
        fixture = Path(tempfile.mkdtemp(prefix="mrk-saved-text-process-",
            dir="/private/tmp" if sys.platform == "darwin" else None))
        outcomes = []
        safe = True
        try:
            with original_command_outcomes() as observed:
                outcomes = observed
                for domain, case in (("metadata_text", "android"), ("release_version", "version")):
                    root = _init_project(fixture / domain, case)
                    before = {p: (_facts(root / p), (root / p).read_bytes()) for p in _selection(case).paths}
                    for mode, expected in (("interrupt", INTERRUPTED), ("recover", 0)):
                        self.assertTrue(not observed or all_original_commands_final(observed))
                        index = len(observed)
                        safe = False
                        result = owned.run_owned([sys.executable, "-I", "-S", "-B", str(Path(__file__).absolute()),
                            "--restart-child", str(root), domain, mode], cwd=root,
                            environ={"PATH": "/usr/bin:/bin", "HOME": str(fixture), "TMPDIR": str(fixture), "LC_ALL": "C", "LANG": "C"},
                            timeout=20, output_limit=64 * 1024)
                        self.assertEqual(len(observed), index + 1)
                        actual = observed[index]
                        self.assertIsNotNone(actual)
                        self.assertIsNotNone(actual.original_finality)
                        safe = True  # This original lifetime is known; result success is still checked separately.
                        self.assertEqual(actual.result_integrity, "complete")
                        self.assertIsNone(actual.no_target)
                        self.assertEqual((actual.termination, actual.returncode), ("normal-exit", expected))
                        self.assertTrue(actual.create_w.attempted and actual.create_w.retired)
                        self.assertTrue(actual.run_tool.attempted and actual.run_tool.retired)
                        self.assertEqual(result.returncode, expected, result.stderr)
                        self.assertEqual(result.stderr, "")
                        frames = [json.loads(line) for line in result.stdout.splitlines()]
                        if mode == "interrupt":
                            self.assertEqual([f["kind"] for f in frames], ["opened", "prepared"])
                            journal = root / (tx.METADATA_READY if case == "android" else tx.VERSION_READY)
                            self.assertTrue((journal / "old-0").is_file() and (journal / "new-0").is_file())
                            self.assertFalse((root / _selection(case).paths[0]).exists())
                        else:
                            self.assertEqual([f["kind"] for f in frames[:3]], ["opened", "prepared", "terminal"])
                            self.assertEqual(frames[0]["result"]["recovery"], frames[1]["result"]["recovery"])
                            self.assertEqual(frames[0]["result"]["recovery"]["action"], "rollback")
                            terminal = frames[2]["result"]
                            self.assertEqual(terminal, {"kind": "outcome", "planToken": frames[1]["result"]["planToken"],
                                "effect": "rolled_back", "journal": "clean", "resources": "settled", "reason": "none"})
                            self.assertEqual(frames[3], {"freshLoad": [{"path": p, **text.content_digest(body)} for p, (_, body) in before.items()],
                                "domain": domain, "engineResourcesSettled": True})
                            self.assertEqual(len(frames), 4)
                    for p, (facts, body) in before.items():
                        self.assertEqual((root / p).read_bytes(), body)
                        self.assertEqual(_facts(root / p)[:-1], facts[:-1])
                    self.assertTrue(all(not (root / n).exists() for n in tx.ALL_STATE_NAMES))
                self.assertEqual(len(observed), 4)
        finally:
            if not safe or not all_original_commands_final(outcomes):
                self.fail("original restart child lifetime unknown; preserving private fixture")
            shutil.rmtree(fixture)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--restart-child":
        raise SystemExit(_child_engine(Path(sys.argv[2]), sys.argv[3], sys.argv[4]))
    unittest.main()
