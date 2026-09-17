"""Bounded in-memory workflow adapter checks, not native qualification.

The exact imported lease/workspace names are replaced by explicit inert types,
as in test_config_edit. No real custody object, resource file, descriptor,
flock, signal, thread, process, transaction, recovery or filesystem probe runs.
The synthetic resource exercises the existing proposal service, not a second
generator or a claim about canonical/installed/native workflow behavior.
Source and exact command admission are required separately before execution.
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

from mobile_release import config_edit as shared
from mobile_release import github_workflow_edit as edit
from mobile_release import init_transaction as transaction
from mobile_release.api import _github_setup as setup
from mobile_release.api.contracts import ApiError
from mobile_release.workflow_payloads import GITHUB_WORKFLOWS, render_workflow_caller

_PROFILE = transaction.TypedEditProfile.GITHUB_WORKFLOWS
_PATHS = tuple(path for _, path in GITHUB_WORKFLOWS)
_IDS = tuple(identity for identity, _ in GITHUB_WORKFLOWS)
_REVISION, _PLAN = "a" * 32, "b" * 32
_REPOSITORY, _SHA = "Example/mobile-release-kit", "A" * 40
_NATIVE_FORBIDDEN = {"ctypes", "_ctypes", "fcntl", "subprocess", "socket"}
_OWNER_FORBIDDEN = {
    "mobile_release.cli", "mobile_release.init_workspace_custody", "mobile_release.cancellation",
    "mobile_release.build_inputs", "mobile_release.owned_process", "mobile_release._native_process",
    "mobile_release._command_process", "mobile_release._profile_process", "mobile_release.credentials",
    "mobile_release.preflight", "mobile_release.local_signing", "mobile_release.android",
    "mobile_release.ios", "mobile_release.stores", "mobile_release.workflow",
    "mobile_release._desktop_edit_engine",
}


def draft():
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def resource_bytes():
    def help_row(identity):
        return {"id": identity, "label": identity, "what": "what", "why": "why",
                "where": "where", "format": "format", "failure": "failure"}

    inputs = [{**help_row(identity), "requiredness": "optional" if identity == "suppliedSnapshot" else "required"}
              for identity in setup.INPUT_IDS]
    templates = {identity: "# inert fixture only\nuses: __MOBILE_RELEASE_KIT_REPOSITORY__/"
                 f".github/workflows/reusable-{identity}.yml@__MOBILE_RELEASE_KIT_SHA__\n"
                 for identity in _IDS}
    value = {"schemaVersion": 1, "workflows": templates,
             "help": {"schemaVersion": 1, "inputs": inputs,
                      "guidance": [help_row(identity) for identity in setup.GUIDANCE_IDS]}}
    return json.dumps(value, separators=(",", ":")).encode()


def expected_payloads():
    templates = json.loads(resource_bytes())["workflows"]
    return tuple(render_workflow_caller(templates[identity].encode(), _REPOSITORY, _SHA) for identity in _IDS)


def observed(path, data, inode):
    before = None if data is None else {"device": 9, "inode": inode, "mode": 0o640,
                                       "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
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
        super().__init__("private-native-message-or-path")


@dataclass(frozen=True, eq=False)
class InertRevision:
    token: str
    missing_workflow_directories: tuple
    profile: transaction.TypedEditProfile = _PROFILE

    @property
    def release_directory_absent(self):
        raise AssertionError("configuration revision facts are not workflow facts")


class InertWorkspace:
    def __init__(self, lease, phase):
        self.lease, self.phase = lease, phase

    def observe(self, path, *, limit):
        assert self.phase == 0 and self.lease.active and self.lease.profile is _PROFILE
        self.lease.reads.append((path, limit))
        index = _PATHS.index(path)
        if index == self.lease.read_failure_at:
            raise InertFailure(InertOutcome("not_started", "not_created", "settled", "filesystem_error"))
        return self.lease.originals[index]

    def apply_workflows_typed(self, changes):
        assert self.phase == 2 and self.lease.active and self.lease.profile is _PROFILE
        assert type(changes) is list and len(changes) == 4
        assert tuple(item.path for item, _ in changes) == _PATHS
        for item, payload in changes:
            assert type(item) is transaction.ObservedFile
            assert payload is None or item.before is None and type(payload) is bytes and len(payload) <= 16 * 1024
        self.lease.applies.append(changes)
        if self.lease.on_apply is not None:
            self.lease.on_apply()
        if self.lease.apply_failure is not None:
            raise self.lease.apply_failure
        if self.lease.apply_result is not None:
            return self.lease.apply_result
        return InertOutcome("unchanged", "not_created", "settled", "none") if all(
            payload is None for _, payload in changes) else InertOutcome("committed", "clean", "settled", "none")

    def apply_typed(self, *args):
        raise AssertionError("configuration facade is not workflow authority")

    def apply(self, *args):
        raise AssertionError("no legacy writer")

    def _prepare(self, *args):
        raise AssertionError("no staging during editor Prepare")

    def recover(self, *args):
        raise AssertionError("no adapter recovery")


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
    def __init__(self, values=(None, None, None, None), *, missing=None, profile=_PROFILE):
        assert len(values) == 4
        if missing is None:
            missing = (".github", ".github/workflows") if all(value is None for value in values) else ()
        self.profile = profile
        self.originals = tuple(observed(path, value, 10 + index)
                               for index, (path, value) in enumerate(zip(_PATHS, values)))
        self.revision = InertRevision(_REVISION, missing, profile)
        self.scopes, self.reads, self.closed, self.applies = [], [], [], []
        self.enter_failures, self.close_failures = {}, {}
        self.apply_failure = self.apply_result = self.workspace = self.on_apply = None
        self.read_failure_at = None
        self.active = self.capture_attempted = self.bound = False

    def workspace_scope(self, revision=None):
        if revision is None:
            assert not self.capture_attempted
            self.capture_attempted = True
        return InertScope(self, revision)

    def bind_revision(self, workspace, originals):
        assert workspace is self.workspace and self.active and not self.bound
        assert type(originals) is tuple and len(originals) == 4
        assert all(item is expected for item, expected in zip(originals, self.originals))
        self.bound = True
        return self.revision


class NoNativeImports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname in _OWNER_FORBIDDEN or fullname.split(".", 1)[0] in _NATIVE_FORBIDDEN:
            raise AssertionError("forbidden native/owner import")
        return None


def no_io(stack):
    stack.enter_context(patch.object(builtins, "open", side_effect=AssertionError("filesystem IO")))
    for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "listdir", "fsync", "mkdir",
                 "rename", "replace", "unlink", "rmdir", "system", "register_at_fork", "urandom", "pipe",
                 "pipe2", "dup", "dup2", "fork", "posix_spawn", "execve", "waitpid", "kill"):
        stack.enter_context(patch.object(os, name, create=True, side_effect=AssertionError("native IO")))
    for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
        stack.enter_context(patch.object(Path, name, side_effect=AssertionError("path IO")))


@contextmanager
def inert_native():
    custody = ModuleType("mobile_release.init_workspace_custody")
    custody.__file__ = "<explicit-inert-workflow-edit-fixture>"
    custody.InitRootLease, custody.RootedRevision = InertLease, InertRevision
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules))
        for name in tuple(sys.modules):
            if name in _OWNER_FORBIDDEN or name.split(".", 1)[0] in _NATIVE_FORBIDDEN:
                del sys.modules[name]
        sys.modules[custody.__name__] = custody
        stack.enter_context(patch.object(sys, "meta_path", [NoNativeImports(), *sys.meta_path]))
        no_io(stack)
        real_workspace = transaction.InitWorkspace
        for name in ("__init__", "__enter__", "borrowed", "observe", "apply", "apply_typed",
                     "apply_workflows_typed", "recover", "_fixed_recovery"):
            stack.enter_context(patch.object(real_workspace, name, create=True, side_effect=AssertionError("real transaction")))
        stack.enter_context(patch.object(transaction, "_rename_function", side_effect=AssertionError("native probe")))
        stack.enter_context(patch.object(transaction, "InitWorkspace", InertWorkspace))
        stack.enter_context(patch.object(transaction, "InitApplyOutcome", InertOutcome))
        stack.enter_context(patch.object(transaction, "InitOperationFailure", InertFailure))
        stack.enter_context(patch.object(setup, "_read_resource_bytes", return_value=resource_bytes()))
        token = stack.enter_context(patch.object(shared.uuid, "uuid4", return_value=SimpleNamespace(hex=_PLAN)))
        yield token


def prepare(lease, value=None):
    checkout = edit.capture_github_workflow_edit(lease)
    return checkout, edit.prepare_github_workflow_edit(
        lease, checkout, checkout.revision, draft() if value is None else value, _REPOSITORY, _SHA)


class GitHubWorkflowEditTests(unittest.TestCase):
    def assert_refused(self, reason, callback):
        with self.assertRaises(shared.ConfigEditFailure) as caught:
            callback()
        self.assertEqual(caught.exception.outcome.reason, reason)
        self.assertNotIn("private-", str(caught.exception))
        return caught.exception.outcome

    def test_roster_is_shared_and_passive_proposals_keep_false_authority_facts(self):
        self.assertIs(setup.WORKFLOWS, GITHUB_WORKFLOWS)
        self.assertEqual(_PROFILE.paths, _PATHS)
        with inert_native():
            result = setup.propose_github_setup(draft(), _REPOSITORY, _SHA, None)
            self.assertEqual([row["id"] for row in result["workflows"]], list(_IDS))
            for fact in ("githubContacted", "repositoryObserved", "toolingRefResolved", "applyAvailable", "snapshotProvided"):
                self.assertIs(result["facts"][fact], False)
            self.assertTrue(all(row["comparison"] == "not-supplied" for row in result["workflows"]))

    def test_capture_publishes_only_settled_fixed_digest_summaries(self):
        original = b"private-original-workflow-value\n"
        with inert_native() as token:
            lease = InertLease((None, original, None, None))
            checkout = edit.capture_github_workflow_edit(lease)
            expected = [{"id": identity, "state": "absent"} for identity in _IDS]
            expected[1] = {"id": _IDS[1], "state": "present", "byteLength": len(original),
                           "sha256": hashlib.sha256(original).hexdigest()}
            self.assertEqual(checkout.observed, expected)
            self.assertEqual(checkout.revision, _REVISION)
            self.assertEqual(lease.reads, list(zip(_PATHS, (1024 * 1024,) * 4)))
            self.assertEqual(lease.closed, [0])
            self.assertFalse(lease.active)
            self.assertFalse(lease.applies)
            token.assert_not_called()
            exposed = checkout.observed
            exposed[1]["sha256"] = "c" * 64
            self.assertEqual(checkout.observed, expected)
            self.assertNotIn("private-original", json.dumps(checkout.observed) + repr(checkout))

    def test_wrong_profile_is_rejected_before_observation_and_config_cannot_adopt_workflows(self):
        with inert_native():
            lease = InertLease(profile=transaction.TypedEditProfile.CONFIGURATION)
            self.assert_refused("invalid_params", lambda: edit.capture_github_workflow_edit(lease))
            self.assertEqual((lease.scopes, lease.reads), ([], []))
            lease = InertLease()
            self.assert_refused("invalid_params", lambda: shared.capture_config_edit(lease))
            self.assertEqual((lease.scopes, lease.reads), ([], []))
            checkout = edit.capture_github_workflow_edit(lease)
            self.assert_refused("invalid_params", lambda: shared.prepare_config_edit(
                lease, checkout, checkout.revision, None, draft()))
            for foreign in (object.__new__(shared.ConfigCheckout), {"revision": checkout.revision},
                            SimpleNamespace(revision=checkout.revision)):
                self.assert_refused("invalid_params", lambda: edit.prepare_github_workflow_edit(
                    lease, foreign, checkout.revision, draft(), _REPOSITORY, _SHA))
            self.assertEqual(edit.apply_github_workflow_edit(
                lease, object.__new__(shared.PreparedConfigEdit)).reason, "invalid_params")

    def test_successful_review_and_apply_use_shared_generation_once_and_four_fixed_slots(self):
        with inert_native() as token, patch.object(setup, "propose_github_setup", wraps=setup.propose_github_setup) as proposed:
            expected = expected_payloads()
            value = draft()
            value["projectChecks"]["preflight"] = [["private-draft-command", "private-draft-argument"]]
            lease = InertLease()
            token.side_effect = lambda: (self.assertEqual(lease.closed, [0, 1]),
                                         self.assertFalse(lease.active), SimpleNamespace(hex=_PLAN))[-1]
            checkout, plan = prepare(lease, value)
            self.assertIs(type(plan), edit.PreparedWorkflowEdit)
            self.assertEqual((plan.kind, plan.revision, plan.token), ("prepared", checkout.revision, _PLAN))
            view = plan.view
            self.assertEqual(set(view), {"schemaVersion", "files", "createDirectories", "templateSet", "tooling"})
            self.assertEqual(view["createDirectories"], [".github", ".github/workflows"])
            self.assertEqual([row["path"] for row in view["files"]], list(_PATHS))
            self.assertEqual([row["action"] for row in view["files"]], ["create"] * 4)
            self.assertEqual([row["generated"]["content"].encode() for row in view["files"]], list(expected))
            self.assertTrue(all(row["observed"] == {"state": "absent"} for row in view["files"]))
            self.assertEqual(view["templateSet"]["resourceSha256"], hashlib.sha256(resource_bytes()).hexdigest())
            self.assertEqual(view["tooling"]["sha"], _SHA.lower())
            self.assertEqual(view["tooling"]["state"], "format-only")
            self.assertNotIn("private-draft", json.dumps(view))
            proposed.assert_called_once()
            self.assertIsNot(proposed.call_args.args[0], value)
            self.assertIsNot(proposed.call_args.args[0]["projectChecks"], value["projectChecks"])
            self.assertIsNone(proposed.call_args.args[3])
            with patch.object(setup, "propose_github_setup", side_effect=AssertionError("Apply must not regenerate")):
                result = edit.apply_github_workflow_edit(lease, plan)
            self.assertEqual(result, shared.CoreEditOutcome("committed", "clean", "settled", "none"))
            self.assertEqual([payload for _, payload in lease.applies[0]], list(expected))
            self.assertTrue(all(item.before is None for item, _ in lease.applies[0]))
            self.assertEqual(lease.closed, [0, 1, 2])
            self.assertIs(lease.scopes[1], lease.revision)
            self.assertIs(lease.scopes[2], lease.revision)
            self.assertEqual(len(lease.reads), 4)

    def test_stable_missing_directory_states_are_projected_without_guessing(self):
        with inert_native():
            for missing in ((), (".github/workflows",), (".github", ".github/workflows")):
                with self.subTest(missing=missing):
                    _, plan = prepare(InertLease(missing=missing))
                    self.assertEqual(plan.view["createDirectories"], list(missing))
            for missing in ((".github",), (".github/workflows", ".github"), [".github/workflows"], ("../other",)):
                lease = InertLease(missing=missing)
                self.assert_refused("custody_unknown", lambda: edit.capture_github_workflow_edit(lease))
            lease = InertLease((b"present", None, None, None), missing=(".github/workflows",))
            self.assert_refused("custody_unknown", lambda: edit.capture_github_workflow_edit(lease))

    def test_exact_preserve_noop_and_mixed_creation_never_replace_existing_bytes(self):
        with inert_native():
            generated = expected_payloads()
            lease = InertLease(generated)
            _, plan = prepare(lease)
            self.assertEqual([row["action"] for row in plan.view["files"]], ["preserve"] * 4)
            self.assertEqual(plan.view["createDirectories"], [])
            self.assertEqual(edit.apply_github_workflow_edit(lease, plan),
                             shared.CoreEditOutcome("unchanged", "not_created", "settled", "none"))
            self.assertEqual([payload for _, payload in lease.applies[0]], [None] * 4)
            self.assertEqual([item.data for item, _ in lease.applies[0]], list(generated))
            self.assertTrue(all(item.before["mode"] == 0o640 for item, _ in lease.applies[0]))
            lease = InertLease((None, generated[1], None, generated[3]))
            _, plan = prepare(lease)
            self.assertEqual([row["action"] for row in plan.view["files"]], ["create", "preserve", "create", "preserve"])
            self.assertEqual(edit.apply_github_workflow_edit(lease, plan).effect, "committed")
            self.assertEqual([payload for _, payload in lease.applies[0]], [generated[0], None, generated[2], None])

    def test_differing_originals_refuse_entire_bundle_without_token_or_yaml(self):
        with inert_native() as token:
            generated = expected_payloads()
            originals = (b"private-existing-content\n", generated[1], None, generated[3] + b"\r\n")
            lease = InertLease(originals)
            checkout, result = prepare(lease)
            self.assertIs(type(result), edit.WorkflowConflict)
            self.assertEqual((result.kind, result.revision), ("conflict", checkout.revision))
            self.assertFalse(hasattr(result, "token"))
            self.assertEqual(result.outcome, shared.CoreEditOutcome("not_started", "not_created", "settled", "none"))
            view = result.view
            self.assertEqual(set(view), {"schemaVersion", "reason", "conflicts"})
            self.assertEqual(view["reason"], "existing_workflow_differs")
            self.assertEqual([row["id"] for row in view["conflicts"]], [_IDS[0], _IDS[3]])
            for row, original in zip(view["conflicts"], (originals[0], originals[3])):
                self.assertEqual(row["observed"], {"state": "present", "byteLength": len(original),
                                                   "sha256": hashlib.sha256(original).hexdigest()})
            encoded = json.dumps(view)
            for forbidden in ("private-existing", "content", "generated", "planToken", "path"):
                self.assertNotIn(forbidden, encoded)
            self.assertLess(len(encoded.encode()), 4096)
            token.assert_not_called()
            self.assertEqual(lease.closed, [0, 1])
            self.assert_refused("invalid_params", lambda: edit.prepare_github_workflow_edit(
                lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
            self.assertEqual(edit.apply_github_workflow_edit(lease, result).reason, "invalid_params")
            edit.discard_github_workflow_edit(checkout)
            edit.discard_github_workflow_edit(checkout)
            self.assertEqual(lease.applies, [])
            exposed = result.view
            exposed["conflicts"].clear()
            self.assertEqual(result.view, view)
            _, all_conflict = prepare(InertLease((b"different",) * 4))
            self.assertEqual([row["id"] for row in all_conflict.view["conflicts"]], list(_IDS))
            self.assertLess(len(json.dumps(all_conflict.view).encode()), 4096)

    def test_observation_or_conflict_recheck_failure_never_publishes_partial_rows(self):
        with inert_native() as token:
            lease = InertLease()
            lease.read_failure_at = 2
            with self.assertRaises(shared.ConfigEditFailure) as caught:
                edit.capture_github_workflow_edit(lease)
            self.assertEqual(caught.exception.outcome.reason, "filesystem_error")
            self.assertFalse(hasattr(caught.exception, "view"))
            self.assertEqual(len(lease.reads), 3)
            self.assertFalse(lease.bound)
            self.assertEqual(lease.closed, [0])
            lease = InertLease((b"different", None, None, None))
            checkout = edit.capture_github_workflow_edit(lease)
            lease.enter_failures[1] = InertFailure(InertOutcome("not_started", "not_created", "settled", "stale_revision"))
            self.assert_refused("stale_revision", lambda: edit.prepare_github_workflow_edit(
                lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
            token.assert_not_called()
            self.assertEqual(lease.applies, [])

    def test_malformed_capture_bindings_and_foreign_revision_have_no_authority(self):
        with inert_native():
            for case in ("path", "digest", "size-bool", "full-mode", "oversize", "false-absent", "duck-row", "profile"):
                lease = InertLease((b"private-original", None, None, None), missing=())
                original = lease.originals[0]
                if case == "path":
                    original = transaction.ObservedFile("../private-path", original.before, original.data)
                elif case == "digest":
                    original.before["sha256"] = "f" * 64
                elif case == "size-bool":
                    original.before["size"] = True
                elif case == "full-mode":
                    original.before["mode"] = 0o100640  # File snapshot mode is permission-only; root ABI is separate.
                elif case == "oversize":
                    original = observed(_PATHS[0], b"x" * (1024 * 1024 + 1), 10)
                elif case == "false-absent":
                    original = transaction.ObservedFile(_PATHS[0], None, b"private-present")
                elif case == "duck-row":
                    original = SimpleNamespace(path=original.path, before=original.before, data=original.data)
                else:
                    lease.revision = InertRevision(_REVISION, (), transaction.TypedEditProfile.CONFIGURATION)
                lease.originals = (original, *lease.originals[1:])
                with self.subTest(case=case):
                    self.assert_refused("custody_unknown", lambda: edit.capture_github_workflow_edit(lease))
                self.assertEqual(lease.closed, [0])
                self.assertEqual(lease.applies, [])

    def test_wrong_owner_revision_and_invalid_input_consume_the_prepare_attempt(self):
        with inert_native() as token:
            for case, reason in (("owner", "invalid_params"), ("revision-type", "invalid_params"),
                                 ("revision-format", "invalid_params"), ("revision", "stale_revision"),
                                 ("pin", "invalid_params"), ("draft", "invalid_config")):
                lease = InertLease()
                checkout = edit.capture_github_workflow_edit(lease)
                owner = InertLease() if case == "owner" else lease
                revision = {"revision-type": True, "revision-format": "bad", "revision": "c" * 32}.get(case, checkout.revision)
                value = draft()
                if case == "draft":
                    value["private-unknown-key"] = "private-value"
                with self.subTest(case=case):
                    self.assert_refused(reason, lambda: edit.prepare_github_workflow_edit(
                        owner, checkout, revision, value, _REPOSITORY, "main" if case == "pin" else _SHA))
                    self.assert_refused("invalid_params", lambda: edit.prepare_github_workflow_edit(
                        lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                    self.assertEqual(lease.scopes, [None])
            token.assert_not_called()

    def test_bounded_draft_and_closed_signature_precede_native_prepare(self):
        cyclic, deep, oversized, nodes, nonfinite, surrogate = (draft() for _ in range(6))
        cyclic["cycle"] = cyclic
        nested = deep
        for _ in range(30):
            nested["nested"] = {}
            nested = nested["nested"]
        oversized["value"] = "x" * setup.MAX_CONFIG_BYTES
        nodes["value"] = [0] * 8001
        nonfinite["value"], surrogate["value"] = float("nan"), "\ud800"

        class NotJson(dict):
            def items(self):
                raise AssertionError("caller code must not execute")

        with inert_native(), patch.object(setup, "propose_github_setup", side_effect=AssertionError("before service")):
            for value in (None, [], NotJson(draft()), cyclic, deep, oversized, nodes, nonfinite, surrogate):
                lease = InertLease()
                checkout = edit.capture_github_workflow_edit(lease)
                self.assert_refused("invalid_params", lambda: edit.prepare_github_workflow_edit(
                    lease, checkout, checkout.revision, value, _REPOSITORY, _SHA))
                self.assertEqual(lease.scopes, [None])
        function = edit.prepare_github_workflow_edit
        self.assertEqual(function.__code__.co_varnames[:function.__code__.co_argcount],
                         ("lease", "checkout", "expected_revision", "draft", "tooling_repository", "tooling_sha"))

    def test_resource_refusals_and_memory_interrupts_are_closed_and_not_config_conflicts(self):
        with inert_native():
            for code in ("invalid_params", "resource_unavailable", "proposal_output_limit", "private-error-code"):
                lease = InertLease()
                checkout = edit.capture_github_workflow_edit(lease)
                with patch.object(setup, "propose_github_setup", side_effect=ApiError(code, "private-error-value")):
                    self.assert_refused("invalid_params" if code == "invalid_params" else "filesystem_error",
                                        lambda: edit.prepare_github_workflow_edit(
                                            lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                self.assertEqual(lease.scopes, [None])
            lease = InertLease()
            checkout = edit.capture_github_workflow_edit(lease)
            with patch.object(setup, "propose_github_setup", side_effect=KeyboardInterrupt):
                self.assert_refused("cancelled", lambda: edit.prepare_github_workflow_edit(
                    lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))

    def test_malformed_generated_roster_paths_hashes_and_bounds_grant_no_plan(self):
        with inert_native() as token:
            original = setup.propose_github_setup(draft(), _REPOSITORY, _SHA, None)
            for change in ("count", "id", "path", "extra", "comparison", "size-bool", "hash",
                           "oversize", "view-limit", "validation", "template"):
                result = copy.deepcopy(original)
                row = result["workflows"][0]
                if change == "count":
                    result["workflows"].pop()
                elif change == "id":
                    row["id"] = _IDS[1]
                elif change == "path":
                    row["path"] = "../private-unrelated-file"
                elif change == "extra":
                    row["private-key"] = "private-value"
                elif change == "comparison":
                    row["comparison"] = "supplied-digest-match"
                elif change == "size-bool":
                    row["byteLength"] = True
                elif change == "hash":
                    row["sha256"] = "f" * 64
                elif change == "oversize":
                    row["content"] = "x" * (16 * 1024 + 1)
                    row["byteLength"] = len(row["content"])
                    row["sha256"] = hashlib.sha256(row["content"].encode()).hexdigest()
                elif change == "view-limit":
                    # An inert producer can fit byte budgets while JSON escapes
                    # overflow the complete view. This must reject, not truncate.
                    for item in result["workflows"]:
                        item["content"] = "\x01" * 16000
                        item["byteLength"] = len(item["content"])
                        item["sha256"] = hashlib.sha256(item["content"].encode()).hexdigest()
                elif change == "validation":
                    result["validation"]["valid"] = False
                else:
                    result["templateSet"]["resourceVersion"] = True
                lease = InertLease()
                checkout = edit.capture_github_workflow_edit(lease)
                with self.subTest(change=change), patch.object(setup, "propose_github_setup", return_value=result):
                    self.assert_refused("filesystem_error", lambda: edit.prepare_github_workflow_edit(
                        lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                self.assertEqual(lease.scopes, [None])
            token.assert_not_called()

    def test_prepare_claim_precedes_generation_and_invalid_token_retires_the_checkout(self):
        with inert_native() as token:
            lease = InertLease()
            checkout = edit.capture_github_workflow_edit(lease)
            original = setup.propose_github_setup

            def reentered(*args):
                self.assert_refused("invalid_params", lambda: edit.prepare_github_workflow_edit(
                    lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                return original(*args)

            with patch.object(setup, "propose_github_setup", side_effect=reentered):
                plan = edit.prepare_github_workflow_edit(lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA)
            self.assertIs(type(plan), edit.PreparedWorkflowEdit)
            self.assertEqual(len(lease.scopes), 2)
            token.assert_called_once()
            for invalid in (_REVISION, "not-a-token", True):
                lease = InertLease()
                checkout = edit.capture_github_workflow_edit(lease)
                token.return_value = SimpleNamespace(hex=invalid)
                self.assert_refused("custody_unknown", lambda: edit.prepare_github_workflow_edit(
                    lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                self.assert_refused("invalid_params", lambda: edit.prepare_github_workflow_edit(
                    lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                self.assertEqual(lease.closed, [0, 1])
                self.assertEqual(lease.applies, [])

    def test_private_authorities_deep_frozen_views_and_one_use_apply(self):
        with inert_native():
            generated = expected_payloads()
            lease = InertLease((None, generated[1], None, None))
            value = draft()
            checkout, plan = prepare(lease, value)
            original_view = plan.view
            value["source"]["candidateBranch"] = "newer-ui-draft"
            view = plan.view
            view["files"][0]["generated"]["content"] = "must-not-be-written"
            view["createDirectories"].append("must-not-create")
            lease.originals[1].before["mode"] = 0o600
            for constructor in (edit.WorkflowCheckout, edit.PreparedWorkflowEdit, edit.WorkflowConflict):
                with self.assertRaises(TypeError):
                    constructor()
            for authority in (checkout, plan):
                for copier in (copy.copy, copy.deepcopy, lambda item: item.__reduce_ex__(4)):
                    with self.assertRaises(TypeError):
                        copier(authority)
            with self.assertRaises(AttributeError):
                plan._payloads = (b"must-not-write",) * 4
            self.assertEqual(plan.view, original_view)
            lease.on_apply = lambda: self.assertEqual(edit.apply_github_workflow_edit(lease, plan).reason, "invalid_params")
            self.assertEqual(edit.apply_github_workflow_edit(lease, plan).effect, "committed")
            self.assertEqual([payload for _, payload in lease.applies[0]], [generated[0], None, generated[2], generated[3]])
            self.assertEqual(lease.applies[0][1][0].before["mode"], 0o640)
            self.assertIsNot(lease.applies[0][1][0].before, lease.originals[1].before)
            self.assertEqual(edit.apply_github_workflow_edit(lease, plan).reason, "invalid_params")
            self.assertEqual(len(lease.applies), 1)

    def test_clone_wrong_owner_and_discard_never_transfer_or_reacquire_authority(self):
        with inert_native():
            lease = InertLease()
            checkout, plan = prepare(lease)
            clone = object.__new__(edit.PreparedWorkflowEdit)
            for slot in edit.PreparedWorkflowEdit.__slots__:
                object.__setattr__(clone, slot, getattr(plan, slot))
            self.assertEqual(edit.apply_github_workflow_edit(lease, clone).reason, "invalid_params")
            self.assertEqual(edit.apply_github_workflow_edit(InertLease(), plan).reason, "invalid_params")
            self.assertEqual(edit.apply_github_workflow_edit(lease, plan).reason, "invalid_params")
            self.assertEqual(lease.applies, [])
            edit.discard_github_workflow_edit(checkout)
            edit.discard_github_workflow_edit(plan)
            edit.discard_github_workflow_edit(plan)
            self.assertEqual(len(lease.scopes), 2)
            lease = InertLease()
            checkout = edit.capture_github_workflow_edit(lease)
            edit.discard_github_workflow_edit(checkout)
            self.assert_refused("invalid_params", lambda: edit.prepare_github_workflow_edit(
                lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
            self.assertEqual(lease.scopes, [None])

    def test_stale_busy_pending_cancelled_rechecks_are_original_and_never_retried(self):
        with inert_native():
            for phase in (1, 2):
                for reason in ("stale_revision", "busy", "pending_state", "cancelled", "unsupported_platform"):
                    lease = InertLease()
                    lease.enter_failures[phase] = InertFailure(InertOutcome("not_started", "not_created", "settled", reason))
                    checkout = edit.capture_github_workflow_edit(lease)
                    if phase == 1:
                        self.assert_refused(reason, lambda: edit.prepare_github_workflow_edit(
                            lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                        self.assert_refused("invalid_params", lambda: edit.prepare_github_workflow_edit(
                            lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                    else:
                        plan = edit.prepare_github_workflow_edit(lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA)
                        self.assertEqual(edit.apply_github_workflow_edit(lease, plan).reason, reason)
                        self.assertEqual(edit.apply_github_workflow_edit(lease, plan).reason, "invalid_params")
                    self.assertIs(lease.scopes[-1], lease.revision)
                    self.assertEqual(lease.applies, [])

    def test_unknown_scope_close_prevents_capture_prepared_and_conflict_publication(self):
        with inert_native() as token:
            for phase, values in ((0, (None,) * 4), (1, (None,) * 4), (1, (b"different", None, None, None))):
                lease = InertLease(values)
                lease.close_failures[phase] = InertFailure(InertOutcome("not_started", "not_created", "unknown", "custody_unknown"))
                if phase == 0:
                    outcome = self.assert_refused("custody_unknown", lambda: edit.capture_github_workflow_edit(lease))
                else:
                    checkout = edit.capture_github_workflow_edit(lease)
                    outcome = self.assert_refused("custody_unknown", lambda: edit.prepare_github_workflow_edit(
                        lease, checkout, checkout.revision, draft(), _REPOSITORY, _SHA))
                self.assertEqual(outcome.resources, "unknown")
                self.assertFalse(lease.active)
                self.assertEqual(lease.applies, [])
            token.assert_not_called()

    def test_native_outcomes_preserve_commit_rollback_and_recovery_facts(self):
        cases = (InertOutcome("not_started", "recovery_required", "settled", "filesystem_error"),
                 InertOutcome("rolled_back", "clean", "settled", "cancelled"),
                 InertOutcome("committed", "recovery_required", "settled", "filesystem_error"),
                 InertOutcome("committed", "unknown", "unknown", "cancelled"),
                 InertOutcome("unknown", "unknown", "unknown", "custody_unknown"))
        with inert_native():
            for native in cases:
                lease = InertLease()
                lease.apply_failure = InertFailure(native)
                _, plan = prepare(lease)
                result = edit.apply_github_workflow_edit(lease, plan)
                self.assertEqual(result, shared.CoreEditOutcome(native.effect, native.journal, native.resources, native.reason))
                self.assertEqual(lease.closed, [0, 1, 2])
                self.assertEqual(edit.apply_github_workflow_edit(lease, plan).reason, "invalid_params")

    def test_outcome_copy_follows_scope_exit_and_late_close_cannot_erase_commit(self):
        with inert_native():
            lease = InertLease()
            lease.apply_result = InertOutcome("committed", "recovery_required", "settled", "cancelled")
            lease.close_failures[2] = InertFailure(InertOutcome("committed", "unknown", "unknown", "filesystem_error"))
            _, plan = prepare(lease)
            copy_outcome = shared._native_outcome

            def after_exit(*args):
                self.assertFalse(lease.active)
                return copy_outcome(*args)

            with patch.object(shared, "_native_outcome", side_effect=after_exit):
                result = edit.apply_github_workflow_edit(lease, plan)
            self.assertEqual(result, shared.CoreEditOutcome("committed", "unknown", "unknown", "cancelled"))
            lease = InertLease()
            lease.close_failures[2] = OSError("private-close-path")
            _, plan = prepare(lease)
            self.assertEqual(edit.apply_github_workflow_edit(lease, plan),
                             shared.CoreEditOutcome("committed", "clean", "unknown", "custody_unknown"))

    def test_malformed_and_configuration_only_native_reports_cannot_be_success(self):
        with inert_native():
            for native in ({"effect": "committed"}, InertOutcome("committed", "not_created", "settled", "none"),
                           InertOutcome("committed", "clean", "settled", "private-unknown-reason")):
                lease = InertLease()
                lease.apply_result = native
                _, plan = prepare(lease)
                self.assertEqual(edit.apply_github_workflow_edit(lease, plan),
                                 shared.CoreEditOutcome("unknown", "unknown", "unknown", "custody_unknown"))
            lease = InertLease()
            lease.apply_result = InertOutcome("committed", "clean", "settled", "ignore_conflict")
            _, plan = prepare(lease)
            self.assertEqual(edit.apply_github_workflow_edit(lease, plan),
                             shared.CoreEditOutcome("committed", "clean", "unknown", "custody_unknown"))
            self.assertEqual(shared.CoreEditOutcome("not_started", "not_created", "settled", "ignore_conflict").reason,
                             "ignore_conflict")  # Existing configuration enum is unchanged.

    def test_fresh_import_is_passive_and_adds_no_passive_apply_capability(self):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules))
            for name in tuple(sys.modules):
                if name == "mobile_release" or name.startswith("mobile_release.") or name.split(".", 1)[0] in _NATIVE_FORBIDDEN:
                    del sys.modules[name]
            stack.enter_context(patch.object(sys, "meta_path", [NoNativeImports(), *sys.meta_path]))
            no_io(stack)
            fresh = importlib.import_module("mobile_release.github_workflow_edit")
            api = importlib.import_module("mobile_release.api")
            self.assertEqual(fresh.GITHUB_WORKFLOWS, GITHUB_WORKFLOWS)
            self.assertFalse(_OWNER_FORBIDDEN & set(sys.modules))
            self.assertFalse(_NATIVE_FORBIDDEN & {name.split(".", 1)[0] for name in sys.modules})
            self.assertTrue(all(action["available"] is False for action in api.execute("capabilities", {})["actions"]))
            for method in ("github.setup.apply", "github.workflows.apply", "config.save"):
                with self.assertRaises(api.ApiError):
                    api.execute(method, {})


if __name__ == "__main__":
    unittest.main()
