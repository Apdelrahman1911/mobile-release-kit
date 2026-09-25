"""Focused SOURCE tests: pure spans and the existing inert custody/facade seams.

No native qualification, actual project IO, process or recovery is implied.
The metadata seam remains seven-only; this separate profile requires all ten.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import unittest
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import _desktop_edit_protocol as wire
from mobile_release import config_edit as shared
from mobile_release import init_transaction as tx
from mobile_release import release_version_edit as edit
from mobile_release import version_text as text
from mobile_release.api import ApiError, execute
from mobile_release.config import parse_key_value_text, release_version_from_values
from mobile_release.config_payloads import prepare_edit_ignore, sufficient_ignore_rules
from mobile_release.errors import ValidationError

from test_metadata_text import config, forbidden, no_io
from test_metadata_text_edit import (InertFailure, InertLease, InertOutcome, InertScope,
                                     InertWorkspace, inert_adapter, inert_metadata_scope,
                                     observed, raw_facts)
from test_workflow_transaction_profile import (InertGuard, ROOT, directory, inert_custody,
                                               stat_value, workspace)

PROFILE = tx.TypedEditProfile.RELEASE_VERSION
REVISION, TOKEN, SESSION = "a" * 32, "b" * 32, "c" * 32
COVERED = ("\n".join(tx.IGNORE_LINES) + "\n").encode()
SEVEN = ("\n".join(tx.METADATA_IGNORE_LINES) + "\n").encode()
ORIGINAL = b"# Keep this comment\r\n VERSION_NAME = '1.2.3' \nBUILD_NUMBER = \"7\"\r\nOTHER = keep"
VALUES = {"name": "2.3.4", "build": "8"}


def selection(source="public/version.properties", *, ios=True):
    data = config()
    data["version"]["source"] = source
    if not ios:
        data["ios"] = {"enabled": False}
    return text.public_version_selection(json.dumps(data))


class VersionTextTests(unittest.TestCase):
    def test_only_two_inner_spans_change_quotes_spaces_comments_and_no_final_newline(self):
        with no_io():
            chosen = selection()
            payload, after, values = text.prepare_payload(chosen, ORIGINAL, "edit", VALUES)
            self.assertEqual(after, ORIGINAL.replace(b"'1.2.3'", b"'2.3.4'").replace(b'"7"', b'"8"'))
            self.assertEqual(payload, after)
            self.assertEqual(values, VALUES)
            parsed = parse_key_value_text(after.decode())
            self.assertEqual(parsed, {"VERSION_NAME": "2.3.4", "BUILD_NUMBER": "8", "OTHER": "keep"})
            self.assertEqual(release_version_from_values(parsed, name_key=chosen.name_key,
                build_key=chosen.build_key, ios_enabled=chosen.ios_enabled, source_label="fixture").build, 8)
            self.assertEqual(text.line_endings(after.decode()), ["crlf", "lf"])
            self.assertFalse(text.final_newline(after.decode()))

    def test_python_only_separators_stay_out_of_the_shared_ruby_parser_corpus(self):
        # Python's whole-file parser already accepts these; this writer preserves
        # their exact UTF-8 bytes rather than broadening another consumer.
        for separator in ("\r\n", "\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            for final in ("", separator):
                raw = ("# café" + separator + "VERSION_NAME=1.2" + separator + "BUILD_NUMBER=7" + final).encode()
                with self.subTest(separator=repr(separator), final=bool(final)), no_io():
                    payload, after, _ = text.prepare_payload(selection(), raw, "edit", VALUES)
                    self.assertEqual(payload, after)
                    self.assertEqual(after, raw.replace(b"1.2", b"2.3.4").replace(b"NUMBER=7", b"NUMBER=8"))
                    self.assertEqual(text.line_endings(raw.decode()), text.line_endings(after.decode()))
                    self.assertEqual(text.final_newline(raw.decode()), text.final_newline(after.decode()))

    def test_noop_preserves_exact_bytes_and_creation_is_explicit_exact_lf(self):
        with no_io():
            chosen = selection()
            self.assertEqual(text.prepare_payload(chosen, ORIGINAL, "edit", {"name": "1.2.3", "build": "7"}),
                             (None, ORIGINAL, {"name": "1.2.3", "build": "7"}))
            payload, after, _ = text.prepare_payload(chosen, None, "create", VALUES)
            self.assertEqual(payload, after)
            self.assertEqual(after, b"VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n")
            for raw, intent in ((ORIGINAL, "create"), (None, "edit"), (b"", "create"), (b"", "edit")):
                with self.subTest(raw=raw is None, intent=int), self.assertRaises(text.VersionTextInputError):
                    text.prepare_payload(chosen, raw, intent, VALUES)

    def test_policy_invalid_unambiguous_original_is_correctable_not_creation(self):
        with no_io():
            chosen = selection()
            raw = b"VERSION_NAME=bad\nBUILD_NUMBER=0\n"
            original = text.original_text(chosen, raw)
            self.assertEqual(original.values, ("bad", "0"))
            self.assertEqual(text.prepare_payload(chosen, raw, "edit", VALUES)[1],
                             b"VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n")
            long = b"VERSION_NAME=" + b"x" * 200 + b"\nBUILD_NUMBER=0\n"
            self.assertEqual(text.original_text(chosen, long).values[0], "x" * 200)

    def test_whole_grammar_aliases_unsupported_atoms_encoding_secrets_and_bounds_refuse(self):
        bad = [b"", b"VERSION_NAME=1.2\n", b"BUILD_NUMBER=7\n", b"\xff",
               b"\xef\xbb\xbfVERSION_NAME=1.2\nBUILD_NUMBER=7\n",
               b"VERSION_NAME=1.2\nBUILD_NUMBER=7\nOTHER=x\nOTHER=y\n",
               b"VERSION_NAME=1.2\nversion_name=1.2\nBUILD_NUMBER=7\n",
               b"VERSION_NAME=1.2 # inline annotation\nBUILD_NUMBER=7\n",
               b"VERSION_NAME='1.2\"\nBUILD_NUMBER=7\n",
               b"VERSION_NAME=1.2\nBUILD_NUMBER=7\nUNRELATED=$HOME\n",
               b"VERSION_NAME=1.2\nBUILD_NUMBER=7\n# -----BEGIN PRIVATE KEY-----\n",
               b"#" + b"x" * text.MAX_VERSION_BYTES + b"\nVERSION_NAME=1.2\nBUILD_NUMBER=7\n"]
        with no_io():
            for raw in bad:
                with self.subTest(size=len(raw)), self.assertRaises(text.VersionTextInputError) as caught:
                    text.original_text(selection(), raw)
                self.assertEqual(str(caught.exception), "Saved version input was refused")

    def test_proposed_strings_use_shared_policy_without_trim_coercion_or_auto_bump(self):
        with no_io():
            for build in ("1", "2100000000"):
                self.assertEqual(text.validate_values(selection(), {"name": "1.2", "build": build})["build"], build)
            for value in ({"name": "1.2", "build": n} for n in ("0", "01", "2100000001", " 7", "+7", "7\n", "１", 7, True)):
                with self.subTest(build=value["build"]), self.assertRaises(text.VersionTextInputError):
                    text.validate_values(selection(), value)
            for name in ("1", "1.2.3.4", "1.2-beta", " 1.2", "1.2 ", "é.2", "1." + "2" * 64):
                with self.subTest(name=name), self.assertRaises(text.VersionTextInputError):
                    text.validate_values(selection(), {"name": name, "build": "7"})
            self.assertEqual(text.validate_values(selection(ios=False), {"name": "1.2.3.4-beta", "build": "7"})["name"], "1.2.3.4-beta")

    def test_selection_refuses_dependency_control_and_private_aliases(self):
        with no_io():
            for path in ("release/mobile-release.json", "RELEASE/MOBILE-RELEASE.JSON", ".gitignore",
                         ".mobile-release-version/file", "release/private/version", "../version"):
                with self.subTest(path=path), self.assertRaises(text.VersionTextInputError):
                    selection(path)
            data = config()
            data["version"]["buildKey"] = data["version"]["nameKey"]
            with self.assertRaises(text.VersionTextInputError):
                text.public_version_selection(json.dumps(data))

    def test_ten_rule_migration_and_explicit_seven_rule_metadata_proof(self):
        with no_io():
            self.assertEqual(len(tx.IGNORE_LINES), 10)
            self.assertEqual(len(tx.METADATA_IGNORE_LINES), 7)
            self.assertFalse(sufficient_ignore_rules(SEVEN))
            self.assertTrue(sufficient_ignore_rules(SEVEN, tx.METADATA_IGNORE_LINES))
            after, additions = prepare_edit_ignore(SEVEN)
            self.assertEqual(additions, tuple(name + "/" for name in tx.VERSION_STATE_NAMES))
            self.assertEqual(after, COVERED)
            self.assertFalse(sufficient_ignore_rules(COVERED + b"!later-intent\n"))
            self.assertTrue(sufficient_ignore_rules(b"!earlier-intent\n" + COVERED))

    def test_closed_version_frames_and_public_api_remain_separate(self):
        params = {"revision": REVISION, "expectedBaseline": text.baseline(b"{}", ORIGINAL), "intent": "edit", "values": VALUES}
        def frame(values, protocol=wire.VERSION_PROTOCOL):
            return (json.dumps({"protocol": protocol, "session": SESSION, "seq": 1, "op": "prepare", "params": values},
                               separators=(",", ":")) + "\n").encode()
        with no_io():
            self.assertEqual(wire.parse_request(frame(params), sequence=1, session=SESSION, protocol=wire.VERSION_PROTOCOL).op, "prepare")
            for bad in ({**params, "source": "elsewhere"}, {**params, "intent": "create"},
                        {**params, "values": {**VALUES, "build": 8}},
                        {**params, "expectedBaseline": {**params["expectedBaseline"], "extra": True}}):
                with self.subTest(bad=tuple(bad)), self.assertRaises(wire.ProtocolError):
                    wire.parse_request(frame(bad), sequence=1, session=SESSION, protocol=wire.VERSION_PROTOCOL)
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(params), sequence=1, session=SESSION, protocol=wire.METADATA_PROTOCOL)
            for method in ("release.version.edit", "release.version.prepare", "release.version.apply", "release.version.create"):
                with self.subTest(method=method), self.assertRaises(ApiError):
                    execute(method, {})


@dataclass(frozen=True, eq=False)
class VersionRevision:
    token: str
    version_selection: text.VersionSelection
    missing_version_directories: tuple[str, ...]
    profile: tx.TypedEditProfile = PROFILE


class VersionWorkspace(InertWorkspace):
    def apply_version_typed(self, changes):
        assert self.phase == 2 and self.lease.active and self.lease.profile is PROFILE
        assert tuple(item.path for item, _ in changes) == self.lease.selection.paths
        assert len(changes) == 1 and changes[0][0].path not in text.DEPENDENCY_PATHS
        self.lease.applies.append(changes)
        if self.lease.on_apply is not None:
            self.lease.on_apply()
        if self.lease.apply_failure is not None:
            raise self.lease.apply_failure
        if self.lease.apply_result is not None:
            return self.lease.apply_result
        return InertOutcome("unchanged", "not_created", "settled", "none") if changes[0][1] is None else InertOutcome("committed", "clean", "settled", "none")

    apply_metadata_text_typed = forbidden


class VersionScope(InertScope):
    def __enter__(self):
        super().__enter__()
        self.lease.workspace = VersionWorkspace(self.lease, self.phase)
        return self.lease.workspace


class VersionLease(InertLease):
    def __init__(self, raw=ORIGINAL, *, ignore=COVERED, profile=PROFILE):
        self.profile = profile
        data = config()
        data["version"]["source"] = "public/version.properties"
        self.config = json.dumps(data).encode()
        self.selection = text.public_version_selection(self.config.decode())
        self.originals = {path: observed(path, value, 30 + index)
                          for index, (path, value) in enumerate(zip((*text.DEPENDENCY_PATHS, self.selection.source), (self.config, ignore, raw)))}
        self.revision = VersionRevision(REVISION, self.selection, self.selection.directories if raw is None else (), profile)
        self.scopes, self.closes, self.reads, self.applies = [], [], [], []
        self.enter_failures, self.close_failures = {}, {}
        self.active = self.capture_attempted = self.targets_bound = self.revision_bound = False
        self.apply_result = self.apply_failure = self.on_apply = self.workspace = self.read_failure = None

    def workspace_scope(self, revision=None):
        if revision is None:
            assert not self.capture_attempted
            self.capture_attempted = True
        return VersionScope(self, revision)

    def bind_version_targets(self, owner, dependencies):
        assert self.active and owner is self.workspace and not self.targets_bound
        assert len(dependencies) == 2 and all(item is self.originals[path] for item, path in zip(dependencies, text.DEPENDENCY_PATHS))
        if not sufficient_ignore_rules(dependencies[1].data):
            raise InertFailure(InertOutcome("not_started", "not_created", "settled", "ignore_conflict"))
        self.targets_bound = True
        return SimpleNamespace(paths=self.selection.paths)

    bind_metadata_targets = forbidden


@contextmanager
def version_adapter():
    # Reuse exactly the existing facade seam/traps; no production injection hook.
    with inert_adapter():
        custody = sys.modules["mobile_release.init_workspace_custody"]
        with patch.object(custody, "InitRootLease", VersionLease), patch.object(custody, "RootedRevision", VersionRevision), \
                patch.object(tx, "InitWorkspace", VersionWorkspace):
            yield


def prepared(lease, values=VALUES):
    checkout = edit.capture_release_version_edit(lease)
    plan = edit.prepare_release_version_edit(lease, checkout, checkout.revision, checkout.baseline,
                                            "create" if checkout.values is None else "edit", values)
    return checkout, plan


class VersionAdapterTests(unittest.TestCase):
    def test_edit_create_noop_review_uses_one_target_and_readonly_dependencies(self):
        with version_adapter():
            for raw, values, action in ((ORIGINAL, VALUES, "replace"), (None, VALUES, "create"),
                                       (ORIGINAL, {"name": "1.2.3", "build": "7"}, "preserve")):
                with self.subTest(action=action):
                    lease = VersionLease(raw)
                    checkout, plan = prepared(lease, values)
                    self.assertEqual(lease.reads, list(zip((*text.DEPENDENCY_PATHS, lease.selection.source),
                                                         (*text.DEPENDENCY_LIMITS, text.MAX_VERSION_BYTES))))
                    self.assertEqual(lease.closes, [0, 1])
                    self.assertEqual(plan.view["file"]["action"], action)
                    self.assertEqual(plan.view["createDirectories"], ["public"] if raw is None else [])
                    self.assertEqual(plan.view["file"]["before"]["state"], "absent" if raw is None else "present")
                    self.assertEqual(plan.view["file"]["after"]["text"].encode(),
                                     text.prepare_payload(lease.selection, raw, "create" if raw is None else "edit", values)[1])
                    result = edit.apply_release_version_edit(lease, plan)
                    self.assertEqual(result.effect, "unchanged" if action == "preserve" else "committed")
                    self.assertEqual(len(lease.applies), 1)
                    self.assertEqual(lease.closes, [0, 1, 2])
                    self.assertEqual(edit.apply_release_version_edit(lease, plan).reason, "invalid_params")
                    self.assertFalse(lease.active)
                    self.assertEqual(checkout.selection.source, lease.selection.source)

    def test_malformed_prepare_or_stale_expected_baseline_consumes_once_before_scope(self):
        with version_adapter():
            for kind in ("values", "baseline", "revision", "intent"):
                lease = VersionLease()
                checkout = edit.capture_release_version_edit(lease)
                baseline = checkout.baseline
                if kind == "baseline":
                    baseline["savedVersion"]["sha256"] = "0" * 64
                with self.subTest(kind=kind), self.assertRaises(shared.ConfigEditFailure) as caught:
                    edit.prepare_release_version_edit(lease, checkout, "d" * 32 if kind == "revision" else checkout.revision,
                        baseline, "create" if kind == "intent" else "edit", {"name": "1.2", "build": "0"} if kind == "values" else VALUES)
                self.assertEqual(caught.exception.outcome.reason, "stale_revision" if kind in ("baseline", "revision") else "invalid_params")
                with self.assertRaises(shared.ConfigEditFailure):
                    edit.prepare_release_version_edit(lease, checkout, checkout.revision, checkout.baseline, "edit", VALUES)
                self.assertEqual(lease.closes, [0])

    def test_empty_malformed_and_unreadable_sources_do_not_become_create(self):
        with version_adapter():
            for raw in (b"", b"VERSION_NAME=1.2\n", b"\xff"):
                lease = VersionLease(raw)
                with self.subTest(raw=raw), self.assertRaises(shared.ConfigEditFailure):
                    edit.capture_release_version_edit(lease)
                self.assertEqual(lease.closes, [0])
                self.assertFalse(lease.applies)
            lease = VersionLease(None)
            lease.read_failure = lease.selection.source
            with self.assertRaises(shared.ConfigEditFailure) as caught:
                edit.capture_release_version_edit(lease)
            self.assertEqual(caught.exception.outcome.reason, "filesystem_error")

    def test_policy_invalid_original_loads_and_seven_only_ignore_refuses_version(self):
        with version_adapter():
            lease = VersionLease(b"VERSION_NAME=bad\nBUILD_NUMBER=0\n")
            checkout, _ = prepared(lease)
            self.assertEqual(checkout.values, {"name": "bad", "build": "0"})
            for profile in (tx.TypedEditProfile.CONFIGURATION, tx.TypedEditProfile.METADATA_TEXT):
                with self.subTest(profile=profile), self.assertRaises(shared.ConfigEditFailure):
                    edit.capture_release_version_edit(VersionLease(profile=profile))
            with self.assertRaises(shared.ConfigEditFailure) as caught:
                edit.capture_release_version_edit(VersionLease(ignore=SEVEN))
            self.assertEqual(caught.exception.outcome.reason, "ignore_conflict")

    def test_no_copy_or_cross_lease_plan_replay_and_known_commit_survives_cleanup_loss(self):
        with version_adapter():
            lease = VersionLease()
            checkout, plan = prepared(lease)
            for authority in (checkout, plan):
                with self.assertRaises(TypeError):
                    copy.copy(authority)
                with self.assertRaises(TypeError):
                    copy.deepcopy(authority)
            view = plan.view
            view["values"]["name"] = "9.9"
            self.assertEqual(plan.view["values"], VALUES)
            lease.close_failures[2] = InertFailure(InertOutcome("not_started", "not_created", "unknown", "custody_unknown"))
            result = edit.apply_release_version_edit(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources), ("committed", "clean", "unknown"))
            self.assertEqual(len(lease.applies), 1)
            other = VersionLease()
            _, foreign = prepared(other)
            self.assertEqual(edit.apply_release_version_edit(lease, foreign).reason, "invalid_params")
            self.assertEqual(edit.apply_release_version_edit(other, foreign).reason, "invalid_params")
            self.assertFalse(other.applies)

    def test_discard_and_stale_original_scope_never_reopen_or_retry(self):
        with version_adapter():
            for phase in (1, 2):
                lease = VersionLease()
                lease.enter_failures[phase] = InertFailure(InertOutcome("not_started", "not_created", "settled", "stale_revision"))
                if phase == 1:
                    with self.assertRaises(shared.ConfigEditFailure):
                        prepared(lease)
                else:
                    _, plan = prepared(lease)
                    self.assertEqual(edit.apply_release_version_edit(lease, plan).reason, "stale_revision")
                self.assertFalse(lease.applies)
            lease = VersionLease()
            checkout, plan = prepared(lease)
            edit.discard_release_version_edit(checkout)
            edit.discard_release_version_edit(plan)
            self.assertEqual(edit.apply_release_version_edit(lease, plan).reason, "invalid_params")


def captured_version(custody, *, raw=ORIGINAL, ignore=COVERED):
    lease = custody.InitRootLease(Path("/inert-not-opened"), cancellation=InertGuard(), profile=PROFILE,
                                 registered_identity=dict(ROOT))
    lease._acquired = True
    owner = workspace(PROFILE)
    inert_metadata_scope(custody, lease, owner)
    data = config()
    data["version"]["source"] = "public/version.properties"
    config_raw = json.dumps(data).encode()
    dependencies = (observed(text.CONFIG_PATH, config_raw, 30), observed(text.IGNORE_PATH, ignore, 31))
    release = stat_value(inode=20)
    owner.parents = {"release": tx._dir_identity(release)}
    owner._parent_facts = {"release": tuple(sorted(directory(release).items()))}
    owner._captured = {item.path: item for item in dependencies}
    owner._raw_observations = {item.path: raw_facts(item.data, 30 + index) for index, item in enumerate(dependencies)}
    targets = lease.bind_version_targets(owner, dependencies)
    original = observed(targets.paths[0], raw, 40)
    parent = stat_value(inode=60) if raw is not None else None
    owner.parents["public"] = tx._dir_identity(parent) if parent else None
    owner._parent_facts["public"] = tuple(sorted(directory(parent).items())) if parent else None
    owner._captured[original.path] = original
    owner._raw_observations[original.path] = raw_facts(raw, 40)
    revision = lease.bind_revision(owner, (*dependencies, original))
    owner._rooted_revision = revision
    return lease, owner, targets, revision, dependencies, original


class VersionOriginalCustodyTests(unittest.TestCase):
    def test_concrete_descriptor_one_source_and_original_dependency_parent_never_becomes_a_target(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            lease, owner, targets, revision, dependencies, original = captured_version(custody, raw=None)
            self.assertIs(type(targets), custody.VersionTargets)
            self.assertIs(revision._version_targets, targets)
            self.assertIsNone(revision._metadata_targets)
            self.assertEqual(targets.paths, ("public/version.properties",))
            self.assertEqual(targets.dependency_only_parents, {"release": owner.parents["release"]})
            self.assertEqual(revision.missing_version_directories, ("public",))
            self.assertEqual(targets.observation_paths, (*text.DEPENDENCY_PATHS, original.path))
            for authority in (targets, revision):
                with self.assertRaises(TypeError):
                    copy.copy(authority)
                with self.assertRaises(AttributeError):
                    authority._selection = selection("different/version")
            with self.assertRaises(TypeError):
                custody.VersionTargets()
            with self.assertRaises(tx.InitOperationFailure):
                lease.bind_version_targets(owner, dependencies)
            with self.assertRaises(tx.InitOperationFailure):
                _ = revision.metadata_selection
            foreign = workspace(tx.TypedEditProfile.METADATA_TEXT)
            foreign._version_targets = targets
            with self.assertRaises(tx.InitOperationFailure):
                targets._check_workspace(foreign)

    def test_actual_binder_requires_ten_and_noop_rechecks_original_dependencies(self):
        with inert_custody() as custody, patch.object(os, "fstat", return_value=stat_value()), \
                patch.object(custody.uuid, "uuid4", return_value=SimpleNamespace(hex=REVISION)):
            for ignored in (None, b"", SEVEN, COVERED + b"!later\n"):
                with self.subTest(ignored=ignored is None), self.assertRaises(tx.InitOperationFailure) as caught:
                    captured_version(custody, ignore=ignored)
                self.assertEqual(caught.exception.outcome.reason, "ignore_conflict")
            lease, owner, targets, revision, dependencies, original = captured_version(custody)
            owner._metadata_dependencies_check = Mock(side_effect=tx.InitConflict("changed dependency"))
            with self.assertRaises(tx.InitOperationFailure) as caught:
                owner.apply_version_typed([(original, None)])
            result = caught.exception.outcome
            self.assertEqual(result.reason, "stale_revision")
            self.assertEqual(result.effect, "not_started")
            owner._metadata_dependencies_check.assert_called_once()
            self.assertIs(lease._revision, revision)
            self.assertIs(lease._version_targets, targets)

    def test_version_namespace_isolated_before_first_header_and_foreign_state_not_recovered(self):
        class FirstEffect(BaseException):
            pass

        with no_io():
            self.assertEqual(tx.STATE_NAMES, (tx.PREPARING, tx.READY, tx.CLEANUP))
            for profile in (None, tx.TypedEditProfile.CONFIGURATION, tx.TypedEditProfile.GITHUB_WORKFLOWS):
                for name in tx.VERSION_STATE_NAMES:
                    owner = workspace(profile)
                    owner._list = lambda _fd: [name]
                    owner._private = Mock(side_effect=forbidden)
                    with patch.object(tx, "_stat", side_effect=lambda _fd, path: object() if path == name else None), \
                            self.assertRaises(ValidationError):
                        owner.recover()
                    owner._private.assert_not_called()
            for name in tx.VERSION_STATE_NAMES:
                self.assertTrue(tx.is_state_name(name.upper()))
                with self.assertRaises(ValidationError):
                    tx.validate_paths([name + "/file"])
            owner = workspace(PROFILE)
            owner._metadata_dependencies_check = Mock()
            owner._current = lambda _path: None
            owner._mkdir = Mock(side_effect=FirstEffect)
            owner._private = Mock(side_effect=forbidden)
            path = "public/version.properties"
            owner._rooted_revision = SimpleNamespace(_raw=((path, None),))
            with self.assertRaises(FirstEffect):
                owner._prepare([(observed(path, None, 40), b"VERSION_NAME=1.2\nBUILD_NUMBER=7\n")])
            owner._mkdir.assert_called_once_with(tx.VERSION_PREPARING, 0o700, dir_fd=400)
            owner._private.assert_not_called()
            owner._metadata_dependencies_check.assert_called_once()


if __name__ == "__main__":
    unittest.main()
