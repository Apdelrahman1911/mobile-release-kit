"""In-memory adapter checks with an explicitly installed inert native seam.

No real lease/workspace is constructed. No filesystem fixture, descriptor,
flock, signal owner, subprocess, thread, native probe, transaction or recovery
is executed. The fixture types below replace only the exact concrete import
names used by the adapter; this is not production backend injection support.
Independent approval of exact source/check commands is required before running.
"""
from __future__ import annotations

import builtins
import copy
import hashlib
import importlib
import json
import os
import sys
import unittest
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from mobile_release import config_edit as edit
from mobile_release import init_transaction as transaction
from mobile_release.api._json import bounded_json_text
from mobile_release.config import MAX_CONFIG_BYTES
from mobile_release.config_payloads import IGNORE_LINES, MAX_IGNORE_BYTES, serialize_config_data

_REVISION = "a" * 32
_PLAN = "b" * 32
_COVERED = ("\n".join(IGNORE_LINES) + "\n").encode()
_NATIVE_FORBIDDEN = {"ctypes", "_ctypes", "fcntl"}
_OWNER_FORBIDDEN = {
    "mobile_release.cli", "mobile_release.init_workspace_custody", "mobile_release.cancellation",
    "mobile_release.build_inputs", "mobile_release.owned_process", "mobile_release._native_process",
    "mobile_release._command_process", "mobile_release._profile_process", "mobile_release.credentials",
    "mobile_release.preflight", "mobile_release.local_signing", "mobile_release.android",
    "mobile_release.ios", "mobile_release.stores", "mobile_release.workflow",
}


def draft() -> dict:
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def observed(path: str, data: bytes | None, inode: int) -> transaction.ObservedFile:
    before = None if data is None else {
        "device": 9, "inode": inode, "mode": 0o640, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    return transaction.ObservedFile(path, before, data)


@dataclass(frozen=True)
class InertOutcome:
    effect: str
    journal: str
    resources: str
    reason: str


class InertFailure(BaseException):
    def __init__(self, outcome):
        self.outcome = outcome
        super().__init__("private-native-message-must-not-be-published")


@dataclass(frozen=True, eq=False)
class InertRevision:
    token: str
    release_directory_absent: bool
    profile: transaction.TypedEditProfile = transaction.TypedEditProfile.CONFIGURATION


class InertWorkspace:
    def __init__(self, lease, phase):
        self.lease, self.phase = lease, phase

    def observe(self, path, *, limit):
        assert self.phase == 0 and self.lease.active
        self.lease.reads.append((path, limit))
        return self.lease.originals[0 if path == edit.CONFIG_PATH else 1]

    def apply_typed(self, changes):
        assert self.phase == 2 and self.lease.active
        assert type(changes) is list and len(changes) == 2
        assert tuple(item.path for item, _ in changes) == (edit.CONFIG_PATH, edit.IGNORE_PATH)
        self.lease.applies.append(changes)
        if self.lease.apply_failure is not None:
            raise self.lease.apply_failure
        if self.lease.apply_result is not None:
            return self.lease.apply_result
        if all(payload is None for _, payload in changes):
            return InertOutcome("unchanged", "not_created", "settled", "none")
        return InertOutcome("committed", "clean", "settled", "none")

    def _prepare(self, *args, **kwargs):
        raise AssertionError("staging is never an editor Prepare operation")

    def apply(self, *args, **kwargs):
        raise AssertionError("no legacy apply fallback")

    def recover(self, *args, **kwargs):
        raise AssertionError("no adapter recovery authority")


class InertScope:
    def __init__(self, lease, revision):
        self.lease, self.revision = lease, revision
        self.phase = len(lease.scopes)

    def __enter__(self):
        assert not self.lease.active
        self.lease.scopes.append(self.revision)
        if self.phase == 0:
            assert self.revision is None
        else:
            assert self.phase in {1, 2} and self.revision is self.lease.revision
        if self.phase in self.lease.enter_failures:
            raise self.lease.enter_failures[self.phase]
        self.lease.active = True
        self.lease.workspace = InertWorkspace(self.lease, self.phase)
        return self.lease.workspace

    def __exit__(self, *args):
        self.lease.active = False
        self.lease.closed.append(self.phase)
        if self.phase in self.lease.close_failures:
            raise self.lease.close_failures[self.phase]
        return False


class InertLease:
    profile = transaction.TypedEditProfile.CONFIGURATION

    def __init__(self, config=None, ignore=None, *, release_absent=True):
        self.originals = (observed(edit.CONFIG_PATH, config, 10), observed(edit.IGNORE_PATH, ignore, 11))
        self.revision = InertRevision(_REVISION, release_absent)
        self.scopes, self.reads, self.closed, self.applies = [], [], [], []
        self.enter_failures, self.close_failures = {}, {}
        self.apply_failure = self.apply_result = self.workspace = None
        self.active = self.capture_attempted = self.bound = False

    def workspace_scope(self, revision=None):
        if revision is None:
            assert not self.capture_attempted
            self.capture_attempted = True
        return InertScope(self, revision)

    def bind_revision(self, workspace, originals):
        assert workspace is self.workspace and self.active and not self.bound
        assert type(originals) is tuple and len(originals) == 2
        assert all(original is expected for original, expected in zip(originals, self.originals))
        self.bound = True
        return self.revision


class NoNativeImports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname in _OWNER_FORBIDDEN or fullname.split(".", 1)[0] in _NATIVE_FORBIDDEN:
            raise AssertionError("forbidden native/owner import")
        return None


def no_io(stack: ExitStack) -> None:
    stack.enter_context(patch.object(builtins, "open", side_effect=AssertionError("filesystem IO")))
    for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "listdir", "fsync",
                 "mkdir", "rename", "replace", "unlink", "rmdir", "system", "register_at_fork",
                 "urandom", "pipe", "pipe2", "dup", "dup2", "fork", "posix_spawn", "execve", "waitpid", "kill"):
        stack.enter_context(patch.object(os, name, create=True, side_effect=AssertionError("native IO")))
    for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
        stack.enter_context(patch.object(Path, name, side_effect=AssertionError("path IO")))


@contextmanager
def inert_native():
    custody = ModuleType("mobile_release.init_workspace_custody")
    custody.__file__ = "<explicit-inert-config-edit-fixture>"
    custody.InitRootLease = InertLease
    custody.RootedRevision = InertRevision
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules))
        for name in tuple(sys.modules):
            if name in _OWNER_FORBIDDEN or name.split(".", 1)[0] in _NATIVE_FORBIDDEN:
                del sys.modules[name]
        sys.modules[custody.__name__] = custody
        stack.enter_context(patch.object(sys, "meta_path", [NoNativeImports(), *sys.meta_path]))
        no_io(stack)
        # This patch is the exact imported concrete seam, not a caller-supplied
        # Protocol. All real transaction entrypoints remain unreachable.
        real_workspace = transaction.InitWorkspace
        for name in ("__init__", "__enter__", "borrowed", "observe", "apply", "apply_typed", "recover"):
            stack.enter_context(patch.object(real_workspace, name, create=True, side_effect=AssertionError("real transaction")))
        stack.enter_context(patch.object(transaction, "_rename_function", side_effect=AssertionError("native probe")))
        stack.enter_context(patch.object(transaction, "InitWorkspace", InertWorkspace))
        stack.enter_context(patch.object(transaction, "InitApplyOutcome", InertOutcome, create=True))
        stack.enter_context(patch.object(transaction, "InitOperationFailure", InertFailure, create=True))
        token = stack.enter_context(patch.object(edit.uuid, "uuid4", return_value=SimpleNamespace(hex=_PLAN)))
        yield token


def prepare(lease, value=None):
    checkout = edit.capture_config_edit(lease)
    value = draft() if value is None else value
    return checkout, edit.prepare_config_edit(lease, checkout, checkout.revision, checkout.base, value)


class ConfigEditTests(unittest.TestCase):
    def assert_refused(self, reason, callback):
        with self.assertRaises(edit.ConfigEditFailure) as caught:
            callback()
        self.assertEqual(caught.exception.outcome.reason, reason)
        self.assertNotIn("private-native", str(caught.exception))
        return caught.exception.outcome

    def test_workflow_lease_cannot_capture_configuration_files(self):
        with inert_native():
            lease = InertLease()
            lease.profile = transaction.TypedEditProfile.GITHUB_WORKFLOWS
            self.assert_refused("invalid_params", lambda: edit.capture_config_edit(lease))
            self.assertEqual(lease.scopes, [])
            self.assertEqual(lease.reads, [])

    def test_capture_publishes_only_settled_two_slot_base_and_revision(self):
        value = draft()
        with inert_native() as token:
            lease = InertLease(serialize_config_data(value), _COVERED, release_absent=False)
            checkout = edit.capture_config_edit(lease)
            self.assertEqual(checkout.revision, _REVISION)
            self.assertEqual(checkout.base, value)
            self.assertEqual(lease.reads, [(edit.CONFIG_PATH, MAX_CONFIG_BYTES), (edit.IGNORE_PATH, MAX_IGNORE_BYTES)])
            self.assertEqual(lease.closed, [0])
            self.assertFalse(lease.active)
            self.assertEqual(lease.applies, [])
            token.assert_not_called()
            changed = checkout.base
            changed["android"]["applicationId"] = "changed.only.in.ui"
            self.assertEqual(checkout.base, value)
            self.assertNotIn("org.fixture", repr(checkout))

    def test_invalid_existing_config_is_never_create_permission(self):
        invalid_version = draft()
        invalid_version["schemaVersion"] = 2
        cases = (b"not-json-private-value", b"\xff", b"[]", b'{"schemaVersion":1,"schemaVersion":1}',
                 serialize_config_data(invalid_version))
        with inert_native():
            for raw in cases:
                lease = InertLease(raw, _COVERED, release_absent=False)
                with self.subTest(size=len(raw)):
                    outcome = self.assert_refused("invalid_config", lambda: edit.capture_config_edit(lease))
                    self.assertEqual(outcome, edit.CoreEditOutcome("not_started", "not_created", "settled", "invalid_config"))
                    self.assertEqual(lease.applies, [])
                    self.assertEqual(lease.closed, [0])

    def test_ignore_utf8_admission_is_separate_from_prepare_negation_policy(self):
        with inert_native():
            lease = InertLease(None, b"\xff")
            self.assert_refused("ignore_conflict", lambda: edit.capture_config_edit(lease))
            lease = InertLease(None, b"!private-original-intent\n")
            checkout = edit.capture_config_edit(lease)
            self.assertIsNone(checkout.base)
            self.assert_refused("ignore_conflict", lambda: edit.prepare_config_edit(
                lease, checkout, checkout.revision, None, draft()))
            self.assertEqual(lease.scopes, [None])

    def test_create_inventory_and_payloads_are_exactly_the_two_fixed_slots(self):
        with inert_native() as token:
            lease = InertLease()
            token.side_effect = lambda: (self.assertEqual(lease.closed, [0, 1]),
                                         self.assertFalse(lease.active), SimpleNamespace(hex=_PLAN))[-1]
            checkout, plan = prepare(lease)
            view = plan.view
            self.assertEqual(set(view), {"schemaVersion", "files", "createReleaseDirectory",
                                         "rewritesConfigFormatting", "ignoreAdditions", "preview"})
            self.assertEqual(view["files"], [
                {"path": edit.CONFIG_PATH, "action": "create", "beforeBytes": None,
                 "afterBytes": len(serialize_config_data(draft()))},
                {"path": edit.IGNORE_PATH, "action": "create", "beforeBytes": None,
                 "afterBytes": len(_COVERED)},
            ])
            self.assertTrue(view["createReleaseDirectory"])
            self.assertFalse(view["rewritesConfigFormatting"])
            self.assertEqual(view["ignoreAdditions"], list(IGNORE_LINES))
            self.assertTrue(view["preview"]["validation"]["valid"])
            self.assertEqual(view["preview"]["comparison"]["kind"], "proposed-create")
            self.assertEqual((plan.token, plan.revision), (_PLAN, checkout.revision))
            self.assertIs(lease.scopes[1], lease.revision)
            self.assertEqual(lease.applies, [])
            result = edit.apply_config_edit(lease, plan)
            self.assertEqual(result, edit.CoreEditOutcome("committed", "clean", "settled", "none"))
            self.assertEqual([payload for _, payload in lease.applies[0]], [serialize_config_data(draft()), _COVERED])
            self.assertTrue(all(item.before is None for item, _ in lease.applies[0]))
            self.assertIs(lease.scopes[2], lease.revision)
            self.assertEqual(lease.closed, [0, 1, 2])

    def test_create_does_not_claim_an_existing_release_directory(self):
        with inert_native():
            lease = InertLease(None, _COVERED, release_absent=False)
            _, plan = prepare(lease)
            self.assertFalse(plan.view["createReleaseDirectory"])
            self.assertEqual(plan.view["files"][0]["action"], "create")
            self.assertEqual(plan.view["files"][1]["action"], "preserve")
            self.assertEqual(plan.view["ignoreAdditions"], [])

    def test_semantic_noop_preserves_original_raw_sizes_and_none_payloads(self):
        value = draft()
        raw = b" \r\n" + json.dumps(dict(reversed(list(value.items()))), separators=(",", ":")).encode() + b"\r\n"
        ignored = ("\r\n".join("/" + line for line in IGNORE_LINES)).encode()
        with inert_native():
            lease = InertLease(raw, ignored, release_absent=False)
            _, plan = prepare(lease, value)
            view = plan.view
            self.assertEqual([slot["action"] for slot in view["files"]], ["preserve", "preserve"])
            self.assertEqual([slot["afterBytes"] for slot in view["files"]], [len(raw), len(ignored)])
            self.assertNotEqual(len(raw), len(serialize_config_data(value)))
            self.assertFalse(view["rewritesConfigFormatting"])
            self.assertFalse(view["createReleaseDirectory"])
            self.assertFalse(view["preview"]["comparison"]["semanticallyChanged"])
            self.assertEqual(edit.apply_config_edit(lease, plan),
                             edit.CoreEditOutcome("unchanged", "not_created", "settled", "none"))
            self.assertEqual([payload for _, payload in lease.applies[0]], [None, None])
            self.assertEqual([item.data for item, _ in lease.applies[0]], [raw, ignored])

    def test_real_config_change_uses_shared_bytes_and_formatting_review(self):
        before, after = draft(), draft()
        after["source"]["projectReadTokenRequired"] = True
        with inert_native():
            lease = InertLease(json.dumps(before, separators=(",", ":")).encode(), _COVERED, release_absent=False)
            _, plan = prepare(lease, after)
            self.assertEqual([slot["action"] for slot in plan.view["files"]], ["replace", "preserve"])
            self.assertTrue(plan.view["rewritesConfigFormatting"])
            self.assertFalse(plan.view["createReleaseDirectory"])
            self.assertEqual(plan.view["ignoreAdditions"], [])
            self.assertEqual(edit.apply_config_edit(lease, plan).effect, "committed")
            self.assertEqual([payload for _, payload in lease.applies[0]], [serialize_config_data(after), None])

    def test_config_noop_can_still_have_a_reviewed_ignore_append(self):
        ignored = b"# retained\r\n/.mobile-release/\r\n"
        with inert_native():
            lease = InertLease(serialize_config_data(draft()), ignored, release_absent=False)
            _, plan = prepare(lease)
            self.assertEqual([slot["action"] for slot in plan.view["files"]], ["preserve", "append"])
            self.assertFalse(plan.view["rewritesConfigFormatting"])
            self.assertEqual(plan.view["ignoreAdditions"], list(IGNORE_LINES[1:]))
            self.assertEqual(edit.apply_config_edit(lease, plan).effect, "committed")
            self.assertIsNone(lease.applies[0][0][1])
            self.assertEqual(lease.applies[0][1][1], ignored + ("\n".join(IGNORE_LINES[1:]) + "\n").encode())

    def test_wrong_owner_revision_or_base_consumes_the_single_prepare_attempt(self):
        with inert_native() as token:
            for case, reason in (("owner", "invalid_params"), ("revision_type", "invalid_params"),
                                 ("revision_format", "invalid_params"), ("revision", "stale_revision"),
                                 ("null_base", "stale_revision"), ("different_base", "stale_revision")):
                lease = InertLease(serialize_config_data(draft()), _COVERED, release_absent=False)
                checkout = edit.capture_config_edit(lease)
                supplied_lease = InertLease() if case == "owner" else lease
                revision = {"revision_type": 1, "revision_format": "not-a-token", "revision": "c" * 32}.get(case, checkout.revision)
                base = None if case == "null_base" else checkout.base
                if case == "different_base":
                    base["source"]["productionBranch"] = "different"
                with self.subTest(case=case):
                    self.assert_refused(reason, lambda: edit.prepare_config_edit(
                        supplied_lease, checkout, revision, base, draft()))
                    self.assert_refused("invalid_params", lambda: edit.prepare_config_edit(
                        lease, checkout, checkout.revision, checkout.base, draft()))
                    self.assertEqual(lease.scopes, [None])
            token.assert_not_called()
            lease = InertLease()
            checkout = edit.capture_config_edit(lease)
            self.assert_refused("stale_revision", lambda: edit.prepare_config_edit(
                lease, checkout, checkout.revision, draft(), draft()))

    def test_plan_owns_deep_immutable_bytes_and_never_exposes_binding_dicts(self):
        before, after = draft(), draft()
        after["projectChecks"]["preflight"] = [["private-command", "original-private-argument"]]
        expected_bytes = serialize_config_data(after)
        with inert_native():
            lease = InertLease(serialize_config_data(before), _COVERED, release_absent=False)
            checkout = edit.capture_config_edit(lease)
            base = checkout.base
            plan = edit.prepare_config_edit(lease, checkout, checkout.revision, base, after)
            original_view = plan.view
            after["projectChecks"]["preflight"][0][1] = "newer-ui-argument"
            base["android"]["applicationId"] = "different.base"
            exposed = plan.view
            exposed["files"].append({"path": "must-not-write"})
            exposed["ignoreAdditions"].append("must-not-add/")
            lease.originals[0].before["mode"] = 0o600
            with self.assertRaises(AttributeError):
                plan._payloads = (b"replacement", b"replacement")
            with self.assertRaises(AttributeError):
                del checkout._base_json
            self.assertEqual(plan.view, original_view)
            self.assertEqual(edit.apply_config_edit(lease, plan).effect, "committed")
            changes = lease.applies[0]
            self.assertEqual(len(changes), 2)
            self.assertEqual(changes[0][1], expected_bytes)
            self.assertEqual(changes[0][0].before["mode"], 0o640)
            self.assertIsNot(changes[0][0].before, lease.originals[0].before)

    def test_constructor_copy_clone_and_wrong_lease_do_not_transfer_authority(self):
        with inert_native():
            for constructor in (edit.ConfigCheckout, edit.PreparedConfigEdit):
                with self.assertRaises(TypeError):
                    constructor()
            lease = InertLease()
            checkout, plan = prepare(lease)
            for value in (checkout, plan):
                for copier in (copy.copy, copy.deepcopy, lambda item: item.__reduce_ex__(4)):
                    with self.assertRaises(TypeError):
                        copier(value)
            clone = object.__new__(edit.PreparedConfigEdit)
            for slot in edit.PreparedConfigEdit.__slots__:
                object.__setattr__(clone, slot, getattr(plan, slot))
            self.assertEqual(edit.apply_config_edit(lease, clone).reason, "invalid_params")
            self.assertEqual(edit.apply_config_edit(InertLease(), plan).reason, "invalid_params")
            self.assertEqual(edit.apply_config_edit(lease, plan).reason, "invalid_params")
            self.assertEqual(lease.applies, [])
            for fake in ({"revision": checkout.revision}, SimpleNamespace(revision=checkout.revision),
                         object.__new__(edit.ConfigCheckout)):
                self.assert_refused("invalid_params", lambda: edit.prepare_config_edit(
                    lease, fake, checkout.revision, None, draft()))

    def test_discard_is_idempotent_in_memory_and_retires_all_associated_authority(self):
        with inert_native():
            lease = InertLease()
            checkout = edit.capture_config_edit(lease)
            edit.discard_config_edit(checkout)
            edit.discard_config_edit(checkout)
            self.assert_refused("invalid_params", lambda: edit.prepare_config_edit(
                lease, checkout, checkout.revision, None, draft()))
            self.assertEqual(lease.scopes, [None])
            lease = InertLease()
            checkout, plan = prepare(lease)
            edit.discard_config_edit(checkout)
            edit.discard_config_edit(plan)
            self.assertEqual(edit.apply_config_edit(lease, plan).reason, "invalid_params")
            self.assertEqual(len(lease.scopes), 2)
            self.assertEqual(lease.applies, [])
            self.assert_refused("invalid_params", lambda: edit.discard_config_edit({}))

    def test_original_revision_pending_busy_and_cancelled_rechecks_have_no_retry(self):
        reasons = ("stale_revision", "pending_state", "busy", "cancelled", "unsupported_platform")
        with inert_native():
            for phase in (1, 2):
                for reason in reasons:
                    lease = InertLease()
                    lease.enter_failures[phase] = InertFailure(InertOutcome("not_started", "not_created", "settled", reason))
                    checkout = edit.capture_config_edit(lease)
                    with self.subTest(phase=phase, reason=reason):
                        if phase == 1:
                            self.assert_refused(reason, lambda: edit.prepare_config_edit(
                                lease, checkout, checkout.revision, None, draft()))
                            self.assert_refused("invalid_params", lambda: edit.prepare_config_edit(
                                lease, checkout, checkout.revision, None, draft()))
                        else:
                            plan = edit.prepare_config_edit(lease, checkout, checkout.revision, None, draft())
                            self.assertEqual(edit.apply_config_edit(lease, plan).reason, reason)
                            self.assertEqual(edit.apply_config_edit(lease, plan).reason, "invalid_params")
                        self.assertEqual(lease.applies, [])
                        self.assertIs(lease.scopes[-1], lease.revision)

    def test_typed_apply_failures_preserve_orthogonal_effect_journal_and_reason(self):
        cases = (InertOutcome("not_started", "clean", "settled", "cancelled"),
                 InertOutcome("not_started", "recovery_required", "settled", "filesystem_error"),
                 InertOutcome("rolled_back", "clean", "settled", "cancelled"),
                 InertOutcome("committed", "recovery_required", "settled", "filesystem_error"),
                 InertOutcome("committed", "unknown", "unknown", "cancelled"),
                 InertOutcome("unknown", "unknown", "unknown", "custody_unknown"))
        with inert_native():
            for native in cases:
                lease = InertLease()
                lease.apply_failure = InertFailure(native)
                _, plan = prepare(lease)
                with self.subTest(effect=native.effect, journal=native.journal):
                    self.assertEqual(edit.apply_config_edit(lease, plan), edit.CoreEditOutcome(
                        native.effect, native.journal, native.resources, native.reason))
                    self.assertFalse(lease.active)
                    self.assertEqual(lease.closed, [0, 1, 2])
                    self.assertEqual(edit.apply_config_edit(lease, plan).reason, "invalid_params")

    def test_close_failures_are_copied_after_scope_exit_and_keep_known_primary_facts(self):
        with inert_native():
            cases = (
                (InertOutcome("committed", "clean", "settled", "none"),
                 InertOutcome("committed", "clean", "unknown", "custody_unknown"), "custody_unknown"),
                (InertOutcome("committed", "recovery_required", "settled", "cancelled"),
                 InertOutcome("committed", "unknown", "unknown", "filesystem_error"), "cancelled"),
                (InertOutcome("rolled_back", "clean", "settled", "cancelled"),
                 InertOutcome("rolled_back", "unknown", "unknown", "custody_unknown"), "cancelled"),
            )
            for returned, close, expected_reason in cases:
                lease = InertLease()
                lease.apply_result = returned
                lease.close_failures[2] = InertFailure(close)
                _, plan = prepare(lease)
                original_copy = edit._native_outcome

                def checked_copy(*args):
                    self.assertFalse(lease.active)
                    return original_copy(*args)

                with self.subTest(effect=returned.effect), patch.object(edit, "_native_outcome", side_effect=checked_copy):
                    result = edit.apply_config_edit(lease, plan)
                    self.assertEqual(result.effect, returned.effect)
                    self.assertEqual(result.journal, close.journal)
                    self.assertEqual(result.resources, "unknown")
                    self.assertEqual(result.reason, expected_reason)

    def test_capture_and_prepare_publish_nothing_if_the_short_scope_close_is_unknown(self):
        with inert_native() as token:
            for phase in (0, 1):
                lease = InertLease()
                lease.close_failures[phase] = InertFailure(InertOutcome(
                    "not_started", "not_created", "unknown", "custody_unknown"))
                with self.subTest(phase=phase):
                    if phase == 0:
                        result = self.assert_refused("custody_unknown", lambda: edit.capture_config_edit(lease))
                    else:
                        checkout = edit.capture_config_edit(lease)
                        result = self.assert_refused("custody_unknown", lambda: edit.prepare_config_edit(
                            lease, checkout, checkout.revision, None, draft()))
                    self.assertEqual(result.resources, "unknown")
                    self.assertEqual(lease.applies, [])
            token.assert_not_called()

    def test_unknown_or_impossible_native_reports_have_no_duck_typed_fallback(self):
        invalid = (
            {"effect": "committed", "journal": "clean", "resources": "settled", "reason": "none"},
            InertOutcome("committed", "not_created", "settled", "none"),
            InertOutcome("unknown", "unknown", "settled", "none"),
            InertOutcome("committed", "clean", "settled", "private-unreviewed-reason"),
            InertOutcome("unchanged", "clean", "settled", "none"),
        )
        with inert_native():
            for native in invalid:
                lease = InertLease()
                lease.apply_result = native
                _, plan = prepare(lease)
                with self.subTest(native_type=type(native).__name__):
                    result = edit.apply_config_edit(lease, plan)
                    self.assertEqual(result, edit.CoreEditOutcome("unknown", "unknown", "unknown", "custody_unknown"))
                    self.assertEqual(len(lease.applies), 1)
            lease = InertLease()
            lease.apply_failure = OSError("private-native-path-value")
            _, plan = prepare(lease)
            self.assertEqual(edit.apply_config_edit(lease, plan).effect, "unknown")
            lease = InertLease()
            lease.close_failures[2] = OSError("private-close-value")
            _, plan = prepare(lease)
            result = edit.apply_config_edit(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                             ("committed", "clean", "unknown", "custody_unknown"))

    def test_json_shape_complexity_utf8_and_size_bounds_precede_native_prepare(self):
        cyclic = draft()
        cyclic["cycle"] = cyclic
        deep = draft()
        nested = deep
        for _ in range(30):
            nested["nested"] = {}
            nested = nested["nested"]
        large, nonfinite, surrogate, nodes = draft(), draft(), draft(), draft()
        large["$schema"] = "x:" + "x" * MAX_CONFIG_BYTES
        nonfinite["value"] = float("nan")
        surrogate["value"] = "\ud800"
        nodes["value"] = [0] * 8_001

        class NotJson(dict):
            def items(self):
                raise AssertionError("caller subclass must not execute")

        values = ([], NotJson(draft()), cyclic, deep, large, nonfinite, surrogate, nodes)
        with inert_native():
            for value in values:
                lease = InertLease()
                checkout = edit.capture_config_edit(lease)
                with self.subTest(value_type=type(value).__name__):
                    self.assert_refused("invalid_params", lambda: edit.prepare_config_edit(
                        lease, checkout, checkout.revision, None, value))
                    self.assertEqual(lease.scopes, [None])

    def test_pair_generated_config_and_complete_view_have_independent_output_bounds(self):
        with inert_native():
            pair_base = draft()
            pair_base["projectChecks"]["preflight"] = [["x" * 3100] * 64 for _ in range(2)]
            pair_draft = copy.deepcopy(pair_base)
            pair_draft["source"]["projectReadTokenRequired"] = True
            self.assertLess(len(serialize_config_data(pair_base)), MAX_CONFIG_BYTES)
            pair_json = json.dumps({"base": pair_base, "draft": pair_draft}, separators=(",", ":")).encode()
            self.assertGreater(len(pair_json), edit.MAX_PAIR_BYTES)
            lease = InertLease(serialize_config_data(pair_base), _COVERED, release_absent=False)
            checkout = edit.capture_config_edit(lease)
            self.assert_refused("invalid_params", lambda: edit.prepare_config_edit(
                lease, checkout, checkout.revision, checkout.base, pair_draft))
            self.assertEqual(lease.scopes, [None])

            expanded = draft()
            expanded["projectChecks"]["preflight"] = [["x" * 4080] * 64 for _ in range(2)]
            self.assertLess(len(bounded_json_text(expanded).encode()), MAX_CONFIG_BYTES)
            self.assertGreater(len(serialize_config_data(expanded)), MAX_CONFIG_BYTES)
            lease = InertLease()
            checkout = edit.capture_config_edit(lease)
            self.assert_refused("invalid_params", lambda: edit.prepare_config_edit(
                lease, checkout, checkout.revision, None, expanded))
            self.assertEqual(lease.scopes, [None])

            # An explicitly inert near-bound preview proves the envelope is
            # checked too; it does not assert a reachable real help-string size.
            near = edit.preview_config(None, draft())
            size = len(bounded_json_text(near, max_bytes=edit.MAX_RESULT_BYTES).encode())
            near["fields"][0]["reason"] += "x" * (edit.MAX_RESULT_BYTES - 16 - size)
            self.assertLess(len(bounded_json_text(near, max_bytes=edit.MAX_RESULT_BYTES).encode()), edit.MAX_RESULT_BYTES)
            lease = InertLease()
            checkout = edit.capture_config_edit(lease)
            with patch.object(edit, "preview_config", return_value=near):
                self.assert_refused("invalid_params", lambda: edit.prepare_config_edit(
                    lease, checkout, checkout.revision, None, draft()))
            self.assertEqual(lease.scopes, [None])

    def test_review_and_error_surfaces_do_not_disclose_values_or_unknown_keys(self):
        value = draft()
        value["projectChecks"]["preflight"] = [["private-executable-marker", "private-argument-marker"]]
        with inert_native():
            lease = InertLease(None, b"# private-ignore-marker\n" + _COVERED)
            checkout, plan = prepare(lease, value)
            surface = json.dumps(plan.view) + repr(plan) + repr(checkout)
            for private in ("private-executable-marker", "private-argument-marker", "private-ignore-marker"):
                self.assertNotIn(private, surface)
            invalid = draft()
            invalid["private-unknown-key-marker"] = "private-unknown-value-marker"
            lease = InertLease()
            checkout = edit.capture_config_edit(lease)
            with self.assertRaises(edit.ConfigEditFailure) as caught:
                edit.prepare_config_edit(lease, checkout, checkout.revision, None, invalid)
            self.assertEqual(caught.exception.outcome.reason, "invalid_config")
            self.assertNotIn("private-", str(caught.exception))

    def test_fresh_import_is_passive_and_existing_engine_save_gates_stay_closed(self):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules))
            for name in tuple(sys.modules):
                if (name == "mobile_release" or name.startswith("mobile_release.")
                        or name.split(".", 1)[0] in _NATIVE_FORBIDDEN):
                    del sys.modules[name]
            stack.enter_context(patch.object(sys, "meta_path", [NoNativeImports(), *sys.meta_path]))
            no_io(stack)
            passive_transaction = importlib.import_module("mobile_release.init_transaction")
            for name in ("__init__", "__enter__", "borrowed", "observe", "apply", "apply_typed", "recover"):
                stack.enter_context(patch.object(passive_transaction.InitWorkspace, name, create=True,
                                                  side_effect=AssertionError("real transaction")))
            stack.enter_context(patch.object(passive_transaction, "_rename_function", side_effect=AssertionError("native probe")))
            fresh = importlib.import_module("mobile_release.config_edit")
            api = importlib.import_module("mobile_release.api")
            engine = importlib.import_module("mobile_release._desktop_engine")
            self.assertEqual(fresh.CONFIG_PATH, edit.CONFIG_PATH)
            self.assertFalse(_OWNER_FORBIDDEN & set(sys.modules))
            self.assertFalse(_NATIVE_FORBIDDEN & {name.split(".", 1)[0] for name in sys.modules})
            self.assertTrue(api.execute("config.preview", {"base": None, "draft": draft()})["validation"]["valid"])
            actions = api.execute("capabilities", {})["actions"]
            self.assertTrue(all(item["available"] is False for item in actions))
            for method in ("config.save", "project.initialize", "assets.import"):
                with self.assertRaises(api.ApiError):
                    api.execute(method, {})
                raw = json.dumps({"protocol": 1, "id": "inert", "method": method, "params": {}}, separators=(",", ":")).encode() + b"\n"
                with self.assertRaises(engine.ProtocolError):
                    engine.parse_request(raw)
            for forbidden in ("mobile_release.init_workspace_custody", "ctypes"):
                with self.assertRaisesRegex(AssertionError, "forbidden native/owner import"):
                    importlib.import_module(forbidden)
            # Negative control invokes only the patched constructor.
            with self.assertRaisesRegex(AssertionError, "real transaction"):
                passive_transaction.InitWorkspace(Path("/must-not-open"))


if __name__ == "__main__":
    unittest.main()
