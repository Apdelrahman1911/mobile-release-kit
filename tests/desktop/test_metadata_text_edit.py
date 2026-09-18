"""Inert metadata adapter/target/state checks, not native qualification.

As in the existing configuration/workflow tests, exact native names are replaced
only inside this test by inert types. The real custody definitions are exercised
separately against the existing inert-custody harness. No project descriptor,
flock, process, signal, write, native probe or actual recovery is acquired.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import config_edit as shared
from mobile_release import init_transaction as tx
from mobile_release import metadata_text as text
from mobile_release import metadata_text_edit as edit
from mobile_release.config_payloads import sufficient_ignore_rules
from mobile_release.errors import ValidationError

from test_metadata_text import config, fields, forbidden, no_io
from test_workflow_transaction_profile import (InertGuard, ROOT, binding, directory, inert_custody,
                                              stat_value, workspace)

PROFILE = tx.TypedEditProfile.METADATA_TEXT
REVISION, TOKEN = "a" * 32, "b" * 32
COVERED = ("\n".join(tx.IGNORE_LINES) + "\n").encode()
_NATIVE = {"ctypes", "_ctypes", "fcntl", "subprocess", "socket"}
_OWNERS = {"mobile_release.init_workspace_custody", "mobile_release.build_inputs", "mobile_release.cancellation",
           "mobile_release.owned_process", "mobile_release._native_process", "mobile_release._desktop_edit_engine",
           "mobile_release.cli", "mobile_release.credentials", "mobile_release.stores", "mobile_release.preflight"}


def observed(path, raw, inode):
    return tx.ObservedFile(path, None if raw is None else binding(raw, inode), raw)


def raw_facts(raw, inode):
    return None if raw is None else tuple(sorted(dict(device=9, inode=inode, mode=0o644, uid=1001,
                                                     gid=1002, links=1, size=len(raw), mtime=100, ctime=101).items()))


@dataclass(frozen=True)
class InertOutcome:
    effect: str
    journal: str
    resources: str
    reason: str


class InertFailure(BaseException):
    def __init__(self, outcome):
        self.outcome = outcome
        super().__init__("private-native-error-marker")


@dataclass(frozen=True, eq=False)
class InertRevision:
    token: str
    metadata_selection: text.PublicTextSelection
    missing_metadata_directories: tuple
    profile: tx.TypedEditProfile = PROFILE

    @property
    def missing_workflow_directories(self):
        raise AssertionError("metadata is not the workflow roster")

    @property
    def release_directory_absent(self):
        raise AssertionError("metadata is not a configuration edit")


class InertWorkspace:
    def __init__(self, lease, phase):
        self.lease, self.phase = lease, phase

    def observe(self, path, *, limit):
        assert self.phase == 0 and self.lease.active
        assert path in self.lease.originals
        self.lease.reads.append((path, limit))
        if path == self.lease.read_failure:
            raise InertFailure(InertOutcome("not_started", "not_created", "settled", "filesystem_error"))
        return self.lease.originals[path]

    def apply_metadata_text_typed(self, changes):
        assert self.phase == 2 and self.lease.active and self.lease.profile is PROFILE
        assert tuple(item.path for item, _ in changes) == self.lease.selection.paths
        assert all(path not in text.DEPENDENCY_PATHS for path in self.lease.selection.paths)
        self.lease.applies.append(changes)
        if self.lease.on_apply is not None:
            self.lease.on_apply()
        if self.lease.apply_failure is not None:
            raise self.lease.apply_failure
        if self.lease.apply_result is not None:
            return self.lease.apply_result
        return InertOutcome("unchanged", "not_created", "settled", "none") if all(
            payload is None for _, payload in changes) else InertOutcome("committed", "clean", "settled", "none")

    apply = apply_typed = apply_workflows_typed = recover = _prepare = forbidden


class InertScope:
    def __init__(self, lease, revision):
        self.lease, self.revision, self.phase = lease, revision, len(lease.scopes)

    def __enter__(self):
        assert not self.lease.active and self.phase in {0, 1, 2}
        assert (self.revision is None if self.phase == 0 else self.revision is self.lease.revision)
        self.lease.scopes.append(self.revision)
        if self.phase in self.lease.enter_failures:
            raise self.lease.enter_failures[self.phase]
        self.lease.active = True
        self.lease.workspace = InertWorkspace(self.lease, self.phase)
        return self.lease.workspace

    def __exit__(self, *_args):
        self.lease.active = False
        self.lease.closes.append(self.phase)
        if self.phase in self.lease.close_failures:
            raise self.lease.close_failures[self.phase]
        return False


class InertLease:
    def __init__(self, values=None, *, platform="android", config_raw=None, ignore=COVERED, profile=PROFILE):
        self.platform, self.profile = platform, profile
        self.config = json.dumps(config()).encode() if config_raw is None else config_raw
        self.selection = text.public_text_selection(self.config.decode(), platform, "en-US")
        if values is None:
            values = [None] * len(self.selection.paths)
        assert len(values) == len(self.selection.paths)
        raw = (self.config, ignore, *values)
        paths = (*text.DEPENDENCY_PATHS, *self.selection.paths)
        self.originals = {path: observed(path, value, 30 + index) for index, (path, value) in enumerate(zip(paths, raw))}
        missing = self.selection.directories if all(value is None for value in values) else ()
        self.revision = InertRevision(REVISION, self.selection, missing, profile)
        self.scopes, self.closes, self.reads, self.applies = [], [], [], []
        self.enter_failures, self.close_failures = {}, {}
        self.active = self.capture_attempted = self.targets_bound = self.revision_bound = False
        self.apply_result = self.apply_failure = self.on_apply = self.workspace = self.read_failure = None

    def workspace_scope(self, revision=None):
        if revision is None:
            assert not self.capture_attempted
            self.capture_attempted = True
        return InertScope(self, revision)

    def bind_metadata_targets(self, owner, dependencies, platform, locale):
        assert self.active and owner is self.workspace and not self.targets_bound
        assert platform == self.platform and locale == "en-US"
        assert len(dependencies) == 2 and all(item is self.originals[path] for item, path in zip(dependencies, text.DEPENDENCY_PATHS))
        if not sufficient_ignore_rules(dependencies[1].data):
            raise InertFailure(InertOutcome("not_started", "not_created", "settled", "ignore_conflict"))
        self.targets_bound = True
        return SimpleNamespace(paths=self.selection.paths)

    def bind_revision(self, owner, originals):
        assert self.active and owner is self.workspace and self.targets_bound and not self.revision_bound
        assert tuple(item.path for item in originals) == tuple(self.originals)
        assert all(item is self.originals[item.path] for item in originals)
        self.revision_bound = True
        return self.revision


class NoNativeImports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname in _OWNERS or fullname.split(".", 1)[0] in _NATIVE:
            raise AssertionError("forbidden native/owner import")
        return None


@contextmanager
def inert_adapter():
    custody = ModuleType("mobile_release.init_workspace_custody")
    custody.__file__ = "<explicit-inert-metadata-fixture>"
    custody.InitRootLease, custody.RootedRevision = InertLease, InertRevision
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules))
        for name in tuple(sys.modules):
            if name in _OWNERS or name.split(".", 1)[0] in _NATIVE:
                del sys.modules[name]
        sys.modules[custody.__name__] = custody
        stack.enter_context(patch.object(sys, "meta_path", [NoNativeImports(), *sys.meta_path]))
        stack.enter_context(no_io())
        actual = tx.InitWorkspace
        for name in ("__init__", "borrowed", "observe", "apply", "apply_typed", "apply_workflows_typed",
                     "apply_metadata_text_typed", "recover", "_fixed_recovery"):
            stack.enter_context(patch.object(actual, name, side_effect=forbidden))
        stack.enter_context(patch.object(tx, "_rename_function", side_effect=forbidden))
        stack.enter_context(patch.object(tx, "InitWorkspace", InertWorkspace))
        stack.enter_context(patch.object(tx, "InitApplyOutcome", InertOutcome))
        stack.enter_context(patch.object(tx, "InitOperationFailure", InertFailure))
        stack.enter_context(patch.object(shared.uuid, "uuid4", return_value=SimpleNamespace(hex=TOKEN)))
        yield


def prepared(lease, value=None):
    checkout = edit.capture_metadata_text_edit(lease, lease.platform, "en-US")
    plan = edit.prepare_metadata_text_edit(lease, checkout, checkout.revision, checkout.baseline,
                                          fields(lease.platform) if value is None else value)
    return checkout, plan


class MetadataTextAdapterTests(unittest.TestCase):
    def test_create_exact_review_roster_no_raw_checkout_and_dependency_separation(self):
        with inert_adapter():
            for platform in ("android", "ios"):
                lease = InertLease(platform=platform)
                with patch.object(text, "public_text_selection", side_effect=forbidden):
                    checkout, plan = prepared(lease)
                self.assertFalse(lease.applies)
                self.assertEqual(lease.closes, [0, 1])
                self.assertEqual(lease.reads, [*zip(text.DEPENDENCY_PATHS, text.DEPENDENCY_LIMITS),
                                              *((path, text.MAX_TEXT_BYTES) for path in lease.selection.paths)])
                self.assertNotIn("text", json.dumps(checkout.baseline))
                view = plan.view
                self.assertEqual(set(view), {"schemaVersion", "platform", "locale", "metadataRoot", "files", "createDirectories", "validation"})
                self.assertEqual([row["path"] for row in view["files"]], list(lease.selection.paths))
                self.assertEqual([row["action"] for row in view["files"]], ["create"] * len(lease.selection.paths))
                self.assertEqual(view["createDirectories"], list(lease.selection.directories))
                self.assertNotIn("release", view["createDirectories"])
                self.assertTrue(view["validation"]["valid"])
                self.assertLessEqual(len(json.dumps(view, ensure_ascii=False, separators=(",", ":")).encode()), text.MAX_PREPARED_BYTES)
                outcome = edit.apply_metadata_text_edit(lease, plan)
                self.assertEqual(outcome, shared.CoreEditOutcome("committed", "clean", "settled", "none"))
                self.assertEqual(len(lease.applies), 1)
                self.assertEqual([item.path for item, _ in lease.applies[0]], list(lease.selection.paths))
                self.assertEqual(lease.closes, [0, 1, 2])

    def test_replace_preserve_noop_and_raw_newline_style_warning(self):
        with inert_adapter():
            values = [b"Approved\r\n", b"Approved public copy", b"Old full description\r"]
            lease = InertLease(values)
            submitted = fields()
            submitted[0]["text"] = "Approved\n"
            checkout, plan = prepared(lease, submitted)
            self.assertEqual([row["action"] for row in plan.view["files"]], ["replace", "preserve", "replace"])
            self.assertEqual([row["lineEndingsChanged"] for row in plan.view["files"]], [True, False, True])
            self.assertEqual(plan.view["files"][0]["before"]["text"], "Approved\r\n")
            detached = plan.view
            detached["files"][0]["after"]["text"] = "Changed outside the original plan"
            submitted[0]["text"] = "Changed after Prepare"
            edit.apply_metadata_text_edit(lease, plan)
            self.assertEqual([payload for _, payload in lease.applies[0]], [b"Approved\n", None, b"Approved public copy"])
            unchanged = fields()
            lease = InertLease([row["text"].encode() for row in unchanged])
            checkout, plan = prepared(lease, unchanged)
            self.assertEqual([row["action"] for row in plan.view["files"]], ["preserve"] * 3)
            self.assertEqual(edit.apply_metadata_text_edit(lease, plan), shared.CoreEditOutcome("unchanged", "not_created", "settled", "none"))

    def test_stale_baseline_invalid_text_cross_profile_and_one_use_consume_before_scope(self):
        with inert_adapter():
            for case in ("baseline", "revision", "invalid_text", "malformed_fields", "foreign_lease"):
                lease = InertLease()
                checkout = edit.capture_metadata_text_edit(lease, "android", "en-US")
                expected, revision, supplied, selected = checkout.baseline, checkout.revision, fields(), lease
                if case == "baseline": expected["config"]["sha256"] = "0" * 64
                if case == "revision": revision = "c" * 32
                if case == "invalid_text": supplied[0]["text"] = "TODO"
                if case == "malformed_fields": supplied.reverse()
                if case == "foreign_lease": selected = InertLease()
                with self.subTest(case=case), self.assertRaises(shared.ConfigEditFailure) as caught:
                    edit.prepare_metadata_text_edit(selected, checkout, revision, expected, supplied)
                self.assertEqual(caught.exception.outcome.reason, "stale_revision" if case in {"baseline", "revision"} else "invalid_params")
                self.assertEqual(len(lease.scopes), 1)
                with self.assertRaises(shared.ConfigEditFailure):
                    edit.prepare_metadata_text_edit(lease, checkout, checkout.revision, checkout.baseline, fields())
            for profile in (tx.TypedEditProfile.CONFIGURATION, tx.TypedEditProfile.GITHUB_WORKFLOWS):
                lease = InertLease(profile=profile)
                with self.assertRaises(shared.ConfigEditFailure):
                    edit.capture_metadata_text_edit(lease, "android", "en-US")
                self.assertFalse(lease.scopes)

    def test_tokens_projections_and_copies_do_not_reconstruct_authority_or_retry_apply(self):
        with inert_adapter():
            lease = InertLease()
            checkout, plan = prepared(lease)
            for value in (checkout, plan):
                with self.assertRaises(TypeError): copy.copy(value)
                with self.assertRaises(TypeError): copy.deepcopy(value)
                with self.assertRaises(AttributeError): value._state = "prepared"
            with self.assertRaises(TypeError): edit.MetadataCheckout()
            with self.assertRaises(TypeError): edit.PreparedMetadataEdit()
            self.assertEqual(edit.apply_metadata_text_edit(lease, plan.view).reason, "invalid_params")
            self.assertEqual(edit.apply_metadata_text_edit(lease, plan.token).reason, "invalid_params")
            nested = []
            lease.on_apply = lambda: nested.append(edit.apply_metadata_text_edit(lease, plan))
            edit.apply_metadata_text_edit(lease, plan)
            self.assertEqual(nested[0].reason, "invalid_params")
            self.assertEqual(edit.apply_metadata_text_edit(lease, plan).reason, "invalid_params")
            self.assertEqual(len(lease.applies), 1)
            edit.discard_metadata_text_edit(plan)
            self.assertEqual(len(lease.scopes), 3)

    def test_config_ignore_secret_or_cleanup_failure_never_yields_partial_review(self):
        with inert_adapter():
            for values in [[b"password=private-fixture-marker", None, None], [b"\xff", None, None]]:
                lease = InertLease(values)
                with self.assertRaises(shared.ConfigEditFailure) as caught:
                    edit.capture_metadata_text_edit(lease, "android", "en-US")
                self.assertNotIn("private-fixture-marker", str(caught.exception))
                self.assertEqual(caught.exception.outcome.reason, "invalid_params")
                self.assertFalse(lease.applies)
            lease = InertLease(ignore=("\n".join(tx.IGNORE_LINES[:4]) + "\n").encode())
            with self.assertRaises(shared.ConfigEditFailure) as caught:
                edit.capture_metadata_text_edit(lease, "android", "en-US")
            self.assertEqual(caught.exception.outcome.reason, "ignore_conflict")
            self.assertEqual(len(lease.reads), 2)
            lease = InertLease()
            lease.close_failures[0] = InertFailure(InertOutcome("not_started", "not_created", "unknown", "custody_unknown"))
            with self.assertRaises(shared.ConfigEditFailure) as caught:
                edit.capture_metadata_text_edit(lease, "android", "en-US")
            self.assertEqual(caught.exception.outcome.resources, "unknown")
            self.assertFalse(lease.applies)

    def test_stale_dependency_at_prepare_or_apply_and_committed_cleanup_unknown_stay_distinct(self):
        with inert_adapter():
            for phase in (1, 2):
                lease = InertLease()
                checkout = edit.capture_metadata_text_edit(lease, "android", "en-US")
                lease.enter_failures[phase] = InertFailure(InertOutcome("not_started", "not_created", "settled", "stale_revision"))
                if phase == 1:
                    with self.assertRaises(shared.ConfigEditFailure) as caught:
                        edit.prepare_metadata_text_edit(lease, checkout, checkout.revision, checkout.baseline, fields())
                    self.assertEqual(caught.exception.outcome.reason, "stale_revision")
                else:
                    plan = edit.prepare_metadata_text_edit(lease, checkout, checkout.revision, checkout.baseline, fields())
                    self.assertEqual(edit.apply_metadata_text_edit(lease, plan).reason, "stale_revision")
                    self.assertEqual(edit.apply_metadata_text_edit(lease, plan).reason, "invalid_params")
                self.assertFalse(lease.applies)
            lease = InertLease()
            checkout, plan = prepared(lease)
            lease.apply_result = InertOutcome("committed", "clean", "settled", "none")
            lease.close_failures[2] = InertFailure(InertOutcome("not_started", "not_created", "unknown", "custody_unknown"))
            result = edit.apply_metadata_text_edit(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources), ("committed", "clean", "unknown"))
            self.assertEqual(len(lease.applies), 1)


def inert_metadata_scope(custody, lease, owner):
    """Type-correct DATA only; no scope constructor, handles or native methods."""
    scope = object.__new__(custody.LockedInitScope)
    scope.lease, scope.workspace = lease, owner
    lease._active, owner._scope = scope, scope
    return scope


def captured_target_fixture(custody, *, raw_values=None, ignore=COVERED):
    lease = custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(), profile=PROFILE,
                                  registered_identity=dict(ROOT))
    lease._acquired = True
    owner = workspace(PROFILE)
    inert_metadata_scope(custody, lease, owner)
    config_bytes = json.dumps(config()).encode()
    dependencies = (observed(text.CONFIG_PATH, config_bytes, 30), observed(text.IGNORE_PATH, ignore, 31))
    release = stat_value(inode=20)
    owner.parents = {"release": tx._dir_identity(release)}
    owner._parent_facts = {"release": tuple(sorted(directory(release).items()))}
    owner._captured = {item.path: item for item in dependencies}
    owner._raw_observations = {item.path: raw_facts(item.data, 30 + index)
                               for index, item in enumerate(dependencies)}
    targets = lease.bind_metadata_targets(owner, dependencies, "android", "en-US")
    raw_values = [None] * len(targets.paths) if raw_values is None else raw_values
    originals = tuple(observed(path, raw, 40 + index) for index, (path, raw) in enumerate(zip(targets.paths, raw_values)))
    for index, path in enumerate(targets.directories):
        value = stat_value(inode=60 + index) if any(raw is not None for raw in raw_values) else None
        owner.parents[path] = tx._dir_identity(value) if value else None
        owner._parent_facts[path] = tuple(sorted(directory(value).items())) if value else None
    owner._captured.update({item.path: item for item in originals})
    owner._raw_observations.update({item.path: raw_facts(item.data, 40 + index)
                                    for index, item in enumerate(originals)})
    revision = lease.bind_revision(owner, (*dependencies, *originals))
    owner._rooted_revision = revision
    return lease, owner, targets, revision, dependencies, originals


@contextmanager
def inert_current_reads(target, revision, *, change=None):
    """Exercise actual _current/_parent using original named DATA, never IO.

    Unlike a mocked _current result, this retains the exact reader-to-parent
    and reader-to-raw-fact handoffs used by consuming metadata comparisons.
    """
    parents = {path: dict(facts) if facts is not None else None for path, facts in revision._parent_facts}
    raw = dict(revision._raw)
    rows = {path: (before, data) for path, before, data in revision._files}
    last = revision.metadata_selection.paths[-1]
    if change is not None and change.startswith("file-"):
        facts = dict(raw[last])
        facts[change[5:]] += 1
        raw[last] = tuple(sorted(facts.items()))
    if change is not None and change.startswith("parent-"):
        path = revision.metadata_selection.directories[0]  # Target-only parent in this fixture.
        parents[path][change[7:]] += 1
    paths = {400: "", **{500 + index: path for index, path in enumerate(parents)}}
    descriptors = {path: fd for fd, path in paths.items()}

    def relative(fd, name):
        return paths[fd] + "/" + name if paths[fd] else name

    def directory_stat(path):
        facts = parents[path]
        if facts is None:
            return None
        return stat_value(inode=facts["inode"], mode=stat.S_IFDIR | facts["mode"],
                          uid=facts["uid"], gid=facts["gid"])

    def named(fd, name):
        path = relative(fd, name)
        assert path in parents
        return directory_stat(path)

    def descriptor(name, _flags, *, dir_fd):
        return nullcontext(descriptors[relative(dir_fd, name)])

    def read(fd, name, _limit, *, owner):
        assert owner is target
        path = relative(fd, name)
        assert path in revision.metadata_selection.paths
        if path == last and change in {"io", "policy"}:
            raise OSError("inert unrelated IO failure") if change == "io" else ValidationError("inert unrelated policy failure")
        before, data = rows[path]
        owner._last_read_facts = raw[path]
        if before is None:
            return None
        before = dict(before)
        if path == last and change == "binding":
            before["sha256"] = "f" * 64
        return before, data

    with patch.object(target, "_alias"), patch.object(target, "_descriptor", side_effect=descriptor), \
            patch.object(tx, "_stat", side_effect=named), patch.object(tx, "_read", side_effect=read), \
            patch.object(os, "fstat", side_effect=lambda fd: stat_value() if fd == 400 else directory_stat(paths[fd])):
        yield


def metadata_journal_fixture(custody, *, replace=False):
    values = [b"Old title", b"Preserved summary", b"Preserved description"] if replace else None
    lease, owner, targets, revision, dependencies, originals = captured_target_fixture(custody, raw_values=values)
    header = {"schemaVersion": 1, "transactionId": "d" * 32, "root": dict(owner.root_identity), "domain": "metadata_text"}
    dirs = [{"path": path, "before": owner.parents[path],
             "after": None if owner.parents[path] is not None else dict(device=9, inode=80 + index, mode=0o755)}
            for index, path in enumerate(targets.directories)]
    files = [{"path": item.path, "before": item.before,
              "after": binding(b"New public text", 90 + index) if not replace or index == 0 else None}
             for index, item in enumerate(originals)]
    plan = {**header, "directories": dirs, "files": files}
    contents = {"header.json": tx._json(header), "plan.json": tx._json(plan),
                "commit.pending": owner._marker(plan, "COMMITTED"), "rollback.pending": owner._marker(plan, "ROLLED_BACK")}
    entries = {name: (binding(raw, 100 + index), raw) for index, (name, raw) in enumerate(contents.items())}
    owner._read = lambda _fd, name, _limit=tx.MAX_FILE_BYTES: entries.get(name)
    owner._bind_workflow_controls(400, contents["header.json"], contents["plan.json"], plan)
    owner._workflow_complete = True
    return lease, owner, targets, revision, dependencies, originals, plan, entries


class MetadataTargetAndStateTests(unittest.TestCase):
    def test_original_descriptor_and_revision_are_immutable_and_keep_dependency_only_parent(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            lease, owner, targets, revision, dependencies, originals = captured_target_fixture(custody)
            self.assertIs(owner._metadata_targets, targets)
            self.assertIs(revision._metadata_targets, targets)
            self.assertEqual(targets.observation_paths, (*text.DEPENDENCY_PATHS, *targets.paths))
            self.assertEqual(targets.dependency_only_parents, {"release": owner.parents["release"]})
            self.assertEqual(revision.missing_metadata_directories, targets.directories)
            for value in (targets, revision):
                with self.assertRaises(TypeError): copy.copy(value)
                with self.assertRaises(TypeError): copy.deepcopy(value)
                with self.assertRaises(AttributeError): value._profile = tx.TypedEditProfile.CONFIGURATION
            with self.assertRaises(TypeError): custody.MetadataTargets()
            with self.assertRaises(tx.InitOperationFailure): _ = revision.release_directory_absent
            with self.assertRaises(tx.InitOperationFailure): _ = revision.missing_workflow_directories
            with self.assertRaises(tx.InitOperationFailure):
                lease.bind_metadata_targets(owner, dependencies, "ios", "en-US")
            foreign = workspace(PROFILE)
            foreign._metadata_targets = targets
            with self.assertRaises(tx.InitOperationFailure) as caught:
                targets._check_workspace(foreign)
            self.assertEqual(caught.exception.outcome.reason, "invalid_params")
            original_scope = lease._active
            try:
                foreign._scope = SimpleNamespace(lease=lease, workspace=foreign)
                lease._active = foreign._scope
                with self.assertRaises(tx.InitOperationFailure) as caught:
                    targets._check_workspace(foreign)
                self.assertEqual(caught.exception.outcome.reason, "invalid_params")
                inert_metadata_scope(custody, lease, foreign)
                lease._active = original_scope
                with self.assertRaises(tx.InitOperationFailure) as caught:
                    targets._check_workspace(foreign)
                self.assertEqual(caught.exception.outcome.reason, "invalid_params")
            finally:
                lease._active = original_scope

    def test_legacy_four_ignore_lines_and_negation_refuse_before_any_target_binding(self):
        self.assertEqual(tx.STATE_NAMES, (tx.PREPARING, tx.READY, tx.CLEANUP))
        self.assertEqual(len(tx.IGNORE_LINES), 7)
        self.assertEqual(tx.IGNORE_LINES[4:], tuple(name + "/" for name in tx.METADATA_STATE_NAMES))
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()):
            for ignored in [None, b"", ("\n".join(tx.IGNORE_LINES[:4]) + "\n").encode(), COVERED + b"!user-intent\n"]:
                with self.subTest(ignored=ignored is None), self.assertRaises(tx.InitOperationFailure) as caught:
                    captured_target_fixture(custody, ignore=ignored)
                self.assertEqual(caught.exception.outcome.reason, "ignore_conflict")
            self.assertTrue(sufficient_ignore_rules(b"!earlier-intent\n" + COVERED))

    def test_recheck_uses_original_config_ignore_and_parent_facts_without_retargeting(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for mutation in (None, "config", "ignore", "parent", "raw"):
                lease, owner, targets, revision, dependencies, originals = captured_target_fixture(custody)
                current = workspace(PROFILE)
                current._metadata_targets = targets
                inert_metadata_scope(custody, lease, current)
                by_path = {item.path: item for item in (*dependencies, *originals)}
                raw = dict(revision._raw)
                parents = dict(revision._parent_facts)
                if mutation in {"config", "ignore"}:
                    path = text.CONFIG_PATH if mutation == "config" else text.IGNORE_PATH
                    by_path[path] = observed(path, by_path[path].data + b" ", 700)
                if mutation == "parent": parents["release"] = (("inode", 999),)
                if mutation == "raw": raw[text.CONFIG_PATH] = (("inode", 999),)
                def observe(path, *, limit):
                    current._captured[path] = by_path[path]
                    current._raw_observations[path] = raw[path]
                    current._parent_facts.update(parents)
                    return by_path[path]
                current.observe = observe
                with patch.object(text, "public_text_selection", side_effect=forbidden):
                    if mutation is None:
                        lease._recheck(current, revision)
                        self.assertIs(current._rooted_revision, revision)
                    else:
                        with self.subTest(mutation=mutation), self.assertRaises(tx.InitOperationFailure) as caught:
                            lease._recheck(current, revision)
                        self.assertEqual(caught.exception.outcome.reason, "stale_revision")
                self.assertIs(lease._metadata_targets, targets)

    def test_dependency_consuming_check_compares_original_bytes_binding_raw_and_parent_facts(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for changed in (None, "bytes", "binding", "raw", "parent"):
                lease, owner, targets, revision, dependencies, originals = captured_target_fixture(custody)
                values = {item.path: (dict(item.before), item.data) for item in dependencies}
                expected = dict(targets._raw)
                if changed == "bytes": values[text.CONFIG_PATH] = (values[text.CONFIG_PATH][0], b"replacement config")
                if changed == "binding": values[text.CONFIG_PATH][0]["inode"] += 1
                if changed == "raw": expected[text.CONFIG_PATH] = (("inode", 999),)
                if changed == "parent": owner._parent_facts["release"] = (("inode", 999),)
                active = [None]
                @contextmanager
                def parent(path):
                    active[0] = path
                    yield 400
                def read(_fd, _name, _limit):
                    owner._last_read_facts = expected[active[0]]
                    return values[active[0]]
                owner._parent, owner._read = parent, read
                if changed is None:
                    owner._metadata_dependencies_check()
                else:
                    with self.subTest(changed=changed), self.assertRaises(tx.InitConflict):
                        owner._metadata_dependencies_check()

    def test_metadata_roster_never_inherits_static_config_or_workflow_and_apply_is_one_use(self):
        for attribute in ("paths", "observation_limits", "payload_limits", "directories"):
            with self.assertRaises(ValueError): getattr(PROFILE, attribute)
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for wrong in ("apply_typed", "apply_workflows_typed"):
                lease, owner, targets, revision, dependencies, originals = captured_target_fixture(custody)
                with self.assertRaises(tx.InitOperationFailure): getattr(owner, wrong)([])
                self.assertTrue(owner._typed_claimed)
                with self.assertRaises(tx.InitOperationFailure): owner.apply_metadata_text_typed([])
            lease, owner, targets, revision, dependencies, originals = captured_target_fixture(
                custody, raw_values=[b"Existing public title", b"Existing summary", b"Existing description"])
            owner._metadata_dependencies_check = Mock()
            with inert_current_reads(owner, revision):
                result = owner.apply_metadata_text_typed([(item, None) for item in originals])
            self.assertEqual((result.effect, result.journal, result.reason), ("unchanged", "not_created", "none"))
            owner._metadata_dependencies_check.assert_called_once()
            with self.assertRaises(ValidationError): owner.apply([(dependencies[0], b"must not write config")])

    def test_noop_consumes_actual_current_raw_and_target_parent_facts_not_just_binding(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for change in (None, "file-uid", "file-gid", "file-mtime", "file-ctime", "parent-uid", "parent-gid",
                           "binding", "io", "policy"):
                lease, owner, targets, revision, dependencies, originals = captured_target_fixture(
                    custody, raw_values=[b"Original title", b"Original summary", b"Original description"])
                owner._metadata_dependencies_check = Mock()  # Its actual consuming comparison is tested separately.
                owner._mkdir = Mock(side_effect=forbidden)
                with self.subTest(change=change), inert_current_reads(owner, revision, change=change):
                    if change is None:
                        result = owner.apply_metadata_text_typed([(item, None) for item in originals])
                        self.assertEqual((result.effect, result.journal, result.reason), ("unchanged", "not_created", "none"))
                    else:
                        with self.assertRaises(tx.InitOperationFailure) as caught:
                            owner.apply_metadata_text_typed([(item, None) for item in originals])
                        result = caught.exception.outcome
                        expected = "filesystem_error" if change in {"io", "policy"} else "stale_revision"
                        self.assertEqual((result.effect, result.journal, result.reason), ("not_started", "not_created", expected))
                        self.assertFalse(owner._unchanged)
                owner._mkdir.assert_not_called()
                self.assertIs(owner._rooted_revision, revision)
                self.assertIs(revision._metadata_targets, targets)

    def test_only_actual_comparison_conflicts_change_metadata_reason_and_legacy_types_stay(self):
        with no_io():
            for profile in (None, tx.TypedEditProfile.CONFIGURATION, tx.TypedEditProfile.GITHUB_WORKFLOWS, PROFILE):
                owner = workspace(profile)
                owner._expect_unchanged(True, "constant comparison")
                with self.assertRaises(ValidationError) as caught:
                    owner._expect_unchanged(False, "constant comparison")
                self.assertIs(type(caught.exception), tx.InitConflict if profile is PROFILE else ValidationError)
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for failure in (OSError("inert IO"), ValidationError("inert policy"), tx.InitConflict("inert changed observation")):
                lease, owner, targets, revision, dependencies, originals = captured_target_fixture(custody)
                current = workspace(PROFILE)
                current._metadata_targets = targets
                inert_metadata_scope(custody, lease, current)
                current.observe = Mock(side_effect=failure)
                with self.assertRaises(tx.InitOperationFailure) as caught:
                    lease._recheck(current, revision)
                self.assertEqual(caught.exception.outcome.reason,
                                 "stale_revision" if isinstance(failure, tx.InitConflict) else "filesystem_error")
                self.assertIsNone(current._rooted_revision)

    def test_legacy_domains_reject_even_empty_or_header_tmp_only_metadata_state_before_open(self):
        with no_io():
            for profile in (None, tx.TypedEditProfile.CONFIGURATION, tx.TypedEditProfile.GITHUB_WORKFLOWS):
                for name in tx.METADATA_STATE_NAMES:
                    for contents in ((), ("header.tmp",)):
                        owner = workspace(profile)
                        owner._list = lambda _fd: [name]
                        owner._private = Mock(side_effect=forbidden)
                        with patch.object(tx, "_stat", side_effect=lambda _fd, path: object() if path == name else None):
                            with self.subTest(profile=profile, name=name, contents=contents), self.assertRaises(ValidationError):
                                owner.recover()
                        owner._private.assert_not_called()
            owner = workspace()
            owner._list = lambda _fd: [tx.METADATA_PREPARING.upper()]
            with self.assertRaises(ValidationError): owner.state()
            for name in tx.ALL_STATE_NAMES:
                self.assertTrue(tx.is_state_name(name.upper()))
                with self.assertRaises(ValidationError): tx.validate_paths([name + "/file"])
            owner = workspace(PROFILE)
            owner._list = lambda _fd: [tx.READY]
            with patch.object(tx, "_stat", side_effect=lambda _fd, name: object() if name == tx.READY else None), \
                    self.assertRaises(ValidationError):
                owner.state()

    def test_metadata_namespace_is_selected_at_first_mkdir_before_any_header(self):
        class FirstEffect(BaseException):
            pass

        with no_io():
            owner = workspace(PROFILE)
            owner._metadata_dependencies_check = Mock()
            owner._current = lambda _path: None
            owner._mkdir = Mock(side_effect=FirstEffect)
            owner._private = Mock(side_effect=forbidden)
            selection = text.public_text_selection(json.dumps(config()), "android", "en-US")
            owner._rooted_revision = SimpleNamespace(_raw=tuple((path, None) for path in selection.paths))
            changes = [(observed(path, None, 40 + index), b"Public copy")
                       for index, path in enumerate(selection.paths)]
            with self.assertRaises(FirstEffect): owner._prepare(changes)
            owner._mkdir.assert_called_once_with(tx.METADATA_PREPARING, 0o700, dir_fd=400)
            owner._private.assert_not_called()
            owner._metadata_dependencies_check.assert_called_once()

    def test_metadata_journal_requires_original_domain_bytes_inventory_and_retains_dependency_parent(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for change in (None, "domain", "config_target", "new_control_inode"):
                lease, owner, targets, revision, dependencies, originals, plan, entries = metadata_journal_fixture(custody)
                if change == "domain":
                    raw = tx._json({**plan, "domain": "github_workflows"})
                    entries["plan.json"] = (binding(raw, 101), raw)
                if change == "config_target":
                    changed = copy.deepcopy(plan)
                    changed["files"][0]["path"] = text.CONFIG_PATH
                    raw = tx._json(changed)
                    entries["plan.json"] = (binding(raw, 101), raw)
                if change == "new_control_inode":
                    before, raw = entries["header.json"]
                    entries["header.json"] = ({**before, "inode": 999}, raw)
                if change is None:
                    self.assertEqual(owner._load(400), plan)
                    self.assertEqual(owner.parents["release"], dict(dict(targets._parents)["release"]))
                    self.assertNotIn("release", [entry["path"] for entry in plan["directories"]])
                    self.assertEqual([entry["path"] for entry in plan["files"]], list(targets.paths))
                else:
                    with self.subTest(change=change), self.assertRaises(ValidationError): owner._load(400)

    def test_metadata_replacement_cleanup_uses_original_old_backup_and_never_adopts_replacement(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for changed in (False, True):
                lease, owner, targets, revision, dependencies, originals, plan, entries = metadata_journal_fixture(custody, replace=True)
                entries["COMMITTED"] = entries.pop("commit.pending")
                entries["old-0"] = (dict(originals[0].before), originals[0].data)
                if changed: entries["old-0"][0]["inode"] += 1
                owner._metadata_dependencies_check = lambda: None
                owner._private = lambda _state: nullcontext(400)
                owner._private_check = lambda *_args: None
                owner._list = lambda _fd: list(entries)
                owner._binding = lambda _fd, name, **_kwargs: entries[name][0] if name in entries else None
                owner._fsync = lambda _fd: None
                def unlink(name, **_kwargs):
                    if name != tx.METADATA_CLEANUP:
                        entries.pop(name)
                owner._unlink = Mock(side_effect=unlink)
                with patch.object(tx, "_stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644)):
                    if changed:
                        with self.assertRaises(ValidationError): owner._cleanup()
                        owner._unlink.assert_not_called()
                    else:
                        owner._cleanup()
                        self.assertTrue(owner._journal_clean)
                        self.assertFalse(entries)
                        self.assertEqual(owner._unlink.call_args.args[0], tx.METADATA_CLEANUP)

    def test_incomplete_metadata_state_and_nonoriginal_recovery_are_retained_without_retry(self):
        with no_io():
            owner = workspace(PROFILE)
            owner._creation["state"] = "CREATED"
            owner.private_identity = dict(device=9, inode=99, mode=0o700)
            owner.recover = Mock(side_effect=forbidden)
            with self.assertRaises(ValidationError): owner._fixed_recovery()
            self.assertTrue(owner._recovery_claimed)
            self.assertEqual(owner.current_outcome().journal, "recovery_required")
            owner.recover.assert_not_called()
            owner._workflow_complete = True
            with self.assertRaises(ValidationError): owner._fixed_recovery()
            owner.recover.assert_not_called()
            fresh = workspace(PROFILE)
            fresh.state = Mock(side_effect=forbidden)
            with self.assertRaises(ValidationError): fresh.recover()
            fresh.state.assert_not_called()


if __name__ == "__main__":
    unittest.main()
