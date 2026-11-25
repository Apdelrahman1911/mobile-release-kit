"""Private create/preserve initialization through the original edit owner.

No CLI launch, force overwrite, passive-method grant or persisted-path adoption.
The unsaved input is generated once at Open; Prepare and Apply recheck the same
complete original inventory. Configuration/workflow differences are a bounded
business refusal, not a token or an excuse to replace user content.
"""
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

from . import config_edit as shared
from .api import preview_config
from .api._json import bounded_json_text
from .config import parse_config_text
from .config_edit import ConfigEditFailure, CoreEditOutcome
from .config_payloads import prepare_edit_ignore
from .errors import ValidationError
from .initialization_targets import (DescriptorError, INVENTORY_BYTES, VIEW_BYTES,
                                     InitializationTargets, kind, prepare_input)
from .init_transaction import TypedEditProfile
from .workflow_payloads import GITHUB_WORKFLOWS

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease

_PROFILE = TypedEditProfile.PROJECT_INITIALIZATION


class InitializationCheckout(shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_revision", "_files", "_targets", "_state", "_prepared")

    @property
    def revision(self) -> str:
        return self._revision.token

    @property
    def observed(self) -> dict[str, int]:
        return {"schemaVersion": 1, "fileCount": len(self._files),
                "directoryCount": len(self._targets.directories)}


class PreparedInitialization(shared._PrivateAuthority):
    __slots__ = ("_identity", "_checkout", "_token", "_payloads", "_view_json", "_state")

    @property
    def revision(self) -> str:
        return self._checkout.revision

    @property
    def token(self) -> str:
        return self._token

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)


class InitializationConflict(shared._PrivateAuthority):
    __slots__ = ("_revision", "_view_json")

    @property
    def revision(self) -> str:
        return self._revision

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)

    @property
    def outcome(self) -> CoreEditOutcome:
        return shared._not_started("none")


def _lease_matches(lease: object) -> bool:
    from .init_workspace_custody import InitRootLease
    return (type(lease) is InitRootLease and lease.profile is _PROFILE
            and not lease._workflow_recovery_mode and not lease._saved_text_recovery_mode
            and not lease._image_recovery_mode)


def _checkout(value: object) -> bool:
    return type(value) is InitializationCheckout and getattr(value, "_identity", None) is value


def _prepared(value: object) -> bool:
    return (type(value) is PreparedInitialization and getattr(value, "_identity", None) is value
            and _checkout(getattr(value, "_checkout", None)) and value._checkout._prepared is value)


def capture_project_initialization(lease: InitRootLease, draft: object,
                                   tooling_repository: object, tooling_sha: object) -> InitializationCheckout:
    if not _lease_matches(lease):
        shared._reject("invalid_params")
    try:
        data = prepare_input(draft, tooling_repository, tooling_sha)
    except DescriptorError:
        shared._reject("invalid_config")
    native = shared._native_contract()
    try:
        with lease.workspace_scope() as workspace:
            targets = lease.bind_initialization_targets(workspace, data)
            originals = tuple(workspace.observe(path, limit=limit) for path, limit in zip(data.paths, data.limits))
            data.check_budget(sum(len(item.data) if item.data is not None else 0 for item in originals))
            revision = lease.bind_revision(workspace, originals)
        files = tuple(shared._snapshot(item, path, limit) for item, path, limit in zip(originals, data.paths, data.limits))
        if (type(revision) is not native.revision or revision.profile is not _PROFILE
                or revision._initialization_targets is not targets or type(targets) is not InitializationTargets
                or type(revision.token) is not str or shared._TOKEN.fullmatch(revision.token) is None):
            raise shared._ContractViolation()
        checkout = object.__new__(InitializationCheckout)
        for name, value in (("_identity", checkout), ("_lease", lease), ("_revision", revision),
                            ("_files", files), ("_targets", targets), ("_state", shared._CAPTURED), ("_prepared", None)):
            object.__setattr__(checkout, name, value)
        return checkout
    except BaseException as error:
        raise ConfigEditFailure(shared._settled_failure(native, error)) from None


def _derive(checkout: InitializationCheckout) -> tuple[tuple[bytes | None, ...] | None, bytes]:
    data = checkout._targets._input
    conflicts = [{"kind": kind(index), "path": data.paths[index], "beforeBytes": len(item.data)}
                 for index, item in enumerate(checkout._files)
                 if index != 1 and index < 6 and item.data is not None and item.data != data.desired(index)]
    if conflicts:
        return None, bounded_json_text({"schemaVersion": 1, "reason": "existing_targets_differ", "files": conflicts},
                                       max_bytes=4096, max_nodes=128, max_depth=8).encode("utf-8")
    payloads: list[bytes | None] = []
    rows: list[dict[str, Any]] = []
    additions: tuple[str, ...] = ()
    for index, (path, original) in enumerate(zip(data.paths, checkout._files)):
        before = original.data
        if index == 1:
            try:
                desired, additions = prepare_edit_ignore(before if before is not None else b"")
            except ValidationError:
                shared._reject("ignore_conflict")
            payload = None if before == desired else desired
        else:
            payload = data.desired(index) if before is None else None
        payloads.append(payload)
        rows.append({"index": index, "kind": kind(index), "path": path,
                     "action": "preserve" if payload is None else "create" if before is None else "append",
                     "beforeBytes": None if before is None else len(before),
                     "afterBytes": len(payload) if payload is not None else len(before)})
    parents = dict(checkout._revision._parents)
    directories = [path for path in data.directories if parents[path] is None]
    # The complete path list has a separate smaller wire budget; large metadata
    # contents are never projected into a native or renderer review.
    bounded_json_text({"files": rows, "createDirectories": directories}, max_bytes=INVENTORY_BYTES,
                      max_nodes=12000, max_depth=8)
    data.check_budget(sum(len(item.data) if item.data is not None else 0 for item in checkout._files),
                      sum(len(payload) if payload is not None else 0 for payload in payloads))
    draft = parse_config_text(data.configuration.decode("utf-8"))
    base = None if checkout._files[0].data is None else draft
    preview = preview_config(base, draft)
    if preview["validation"]["valid"] is not True or preview["comparison"]["state"] != "complete":
        raise shared._ContractViolation()
    view = {"schemaVersion": 1, "kind": "project-initialization", "files": rows,
            "directoryCount": len(data.directories), "createDirectories": directories,
            "configurationPreview": preview, "ignoreAdditions": list(additions),
            "workflows": [{"id": identity, "path": path, "content": raw.decode("utf-8"),
                           "byteLength": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                          for (identity, path), raw in zip(GITHUB_WORKFLOWS, data.workflows)],
            "templateSet": data.template(), "tooling": data.tooling()}
    return tuple(payloads), bounded_json_text(view, max_bytes=VIEW_BYTES, max_nodes=20000,
                                              max_depth=30).encode("utf-8")


def prepare_project_initialization(lease: InitRootLease, checkout: InitializationCheckout,
                                   expected_revision: str) -> PreparedInitialization | InitializationConflict:
    if not _checkout(checkout) or checkout._state != shared._CAPTURED:
        shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", shared._PREPARING)
    try:
        if not _lease_matches(lease) or lease is not checkout._lease:
            shared._reject("invalid_params")
        if type(expected_revision) is not str or shared._TOKEN.fullmatch(expected_revision) is None:
            shared._reject("invalid_params")
        if expected_revision != checkout.revision:
            shared._reject("stale_revision")
        payloads, view = _derive(checkout)
        with lease.workspace_scope(checkout._revision):
            pass  # A known conflict also requires the same complete recheck/close.
        if payloads is None:
            conflict = object.__new__(InitializationConflict)
            object.__setattr__(conflict, "_revision", checkout.revision)
            object.__setattr__(conflict, "_view_json", view)
            object.__setattr__(checkout, "_state", shared._RETIRED)
            return conflict
        token = shared.uuid.uuid4().hex
        if type(token) is not str or shared._TOKEN.fullmatch(token) is None or token == checkout.revision:
            shared._reject("custody_unknown")
        plan = object.__new__(PreparedInitialization)
        for name, value in (("_identity", plan), ("_checkout", checkout), ("_token", token), ("_payloads", payloads),
                            ("_view_json", view), ("_state", shared._PREPARED)):
            object.__setattr__(plan, name, value)
        object.__setattr__(checkout, "_prepared", plan)
        object.__setattr__(checkout, "_state", shared._PREPARED)
        return plan
    except BaseException as error:
        object.__setattr__(checkout, "_state", shared._RETIRED)
        if type(error) is ConfigEditFailure:
            raise
        raise ConfigEditFailure(shared._settled_failure(shared._native_contract(), error)) from None


def apply_project_initialization(lease: InitRootLease, plan: PreparedInitialization) -> CoreEditOutcome:
    if not _prepared(plan) or plan._state != shared._PREPARED or plan._checkout._state != shared._PREPARED:
        return shared._not_started("invalid_params")
    object.__setattr__(plan, "_state", shared._RETIRED)
    checkout = plan._checkout
    object.__setattr__(checkout, "_state", shared._RETIRED)
    if not _lease_matches(lease) or lease is not checkout._lease:
        return shared._not_started("invalid_params")
    native = shared._native_contract()
    result = None
    try:
        with lease.workspace_scope(checkout._revision) as workspace:
            # These are the actual rechecked capture objects, not cloned row
            # identities reconstructed from renderer or journal DATA.
            changes = [(workspace._captured[path], payload) for path, payload in
                       zip(checkout._targets.paths, plan._payloads)]
            result = workspace.apply_initialization_typed(changes)
    except BaseException as error:
        provisional = shared._native_outcome(native, result) if type(result) is native.outcome else None
        return shared._settled_failure(native, error, provisional)
    provisional = shared._native_outcome(native, result)
    expected = ("unchanged", "not_created") if all(item is None for item in plan._payloads) else ("committed", "clean")
    if provisional.reason == "none" and (provisional.effect, provisional.journal) != expected:
        return shared._uncertain(provisional)
    return provisional


def discard_project_initialization(authority: InitializationCheckout | PreparedInitialization) -> None:
    if _checkout(authority):
        checkout = authority
    elif _prepared(authority):
        checkout = authority._checkout
    else:
        shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", shared._RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", shared._RETIRED)


def capture_project_initialization_recovery(lease: InitRootLease):
    from .github_workflow_recovery import _capture_recovery
    return _capture_recovery(lease, _PROFILE)


def prepare_project_initialization_recovery(lease: InitRootLease, checkout: Any, expected_revision: str):
    from .github_workflow_recovery import _prepare_recovery
    return _prepare_recovery(lease, checkout, expected_revision, _PROFILE)


def apply_project_initialization_recovery(lease: InitRootLease, plan: Any) -> CoreEditOutcome:
    from .github_workflow_recovery import _apply_recovery
    return _apply_recovery(lease, plan, _PROFILE)


def discard_project_initialization_recovery(authority: Any) -> None:
    from .github_workflow_recovery import _discard_recovery
    _discard_recovery(authority, _PROFILE)
