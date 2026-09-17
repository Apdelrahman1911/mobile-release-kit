"""Private one-shot, create-or-exact-preserve editing of four workflow callers.

The passive proposal service supplies bytes, never filesystem authority. Only
the original workflow-profile lease and its settled scopes can capture/recheck
the fixed originals. This adapter has no recovery, arbitrary path/YAML input,
configuration save, CLI, credentials, remote setup or dispatch operation.

Shared configuration-edit helpers retain the concrete native seam, immutable
snapshots and orthogonal outcome/close handling. Their failure carrier/reason
enum is unchanged; its exception text is not a workflow UI message. A differing
workflow is a separate no-token result, not an invented configuration reason.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any, Literal, TypedDict, cast

from . import config_edit as _shared
from .api import _github_setup as _setup
from .api._json import bounded_json_text
from .api.contracts import ApiError, GitHubTemplateSet, GitHubToolingReference
from .config_edit import ConfigEditFailure, CoreEditOutcome
from .errors import ConfigurationError
from .init_transaction import TypedEditProfile
from .workflow_payloads import GITHUB_WORKFLOWS

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease, RootedRevision

WorkflowId = Literal["preflight", "candidate", "external-testing", "production-submit"]
WorkflowDirectory = Literal[".github", ".github/workflows"]
_PROFILE = TypedEditProfile.GITHUB_WORKFLOWS
_PATHS = tuple(path for _, path in GITHUB_WORKFLOWS)
_MISSING_DIRECTORIES = ((), (".github/workflows",), (".github", ".github/workflows"))
_SMALL_VIEW_BYTES = 4 * 1024  # Leaves room inside the unchanged 16 KiB terminal.


class AbsentWorkflowObservation(TypedDict):
    state: Literal["absent"]


class PresentWorkflowObservation(TypedDict):
    state: Literal["present"]
    byteLength: int
    sha256: str


class AbsentWorkflowSummary(AbsentWorkflowObservation):
    id: WorkflowId


class PresentWorkflowSummary(PresentWorkflowObservation):
    id: WorkflowId


class GeneratedWorkflowView(TypedDict):
    content: str
    byteLength: int
    sha256: str


class WorkflowFileView(TypedDict):
    id: WorkflowId
    path: str
    action: Literal["create", "preserve"]
    observed: AbsentWorkflowObservation | PresentWorkflowObservation
    generated: GeneratedWorkflowView


class PreparedWorkflowView(TypedDict):
    schemaVersion: Literal[1]
    files: list[WorkflowFileView]
    createDirectories: list[WorkflowDirectory]
    templateSet: GitHubTemplateSet
    tooling: GitHubToolingReference


class WorkflowConflictFile(TypedDict):
    id: WorkflowId
    observed: PresentWorkflowObservation


class WorkflowConflictView(TypedDict):
    schemaVersion: Literal[1]
    reason: Literal["existing_workflow_differs"]
    conflicts: list[WorkflowConflictFile]


class WorkflowCheckout(_shared._PrivateAuthority):
    """Original workflow capture; projections do not transfer its authority."""

    __slots__ = ("_identity", "_lease", "_revision", "_revision_token", "_files",
                 "_observed_json", "_state", "_prepared")
    _identity: WorkflowCheckout
    _lease: InitRootLease
    _revision: RootedRevision
    _revision_token: str
    _files: tuple[_shared._FileSnapshot, ...]
    _observed_json: bytes
    _state: str
    _prepared: PreparedWorkflowEdit | None

    def __repr__(self) -> str:
        return "<WorkflowCheckout>"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def observed(self) -> list[AbsentWorkflowSummary | PresentWorkflowSummary]:
        return cast(list[AbsentWorkflowSummary | PresentWorkflowSummary], json.loads(self._observed_json))


class PreparedWorkflowEdit(_shared._PrivateAuthority):
    """One immutable generated plan bound to its original workflow checkout."""

    __slots__ = ("_identity", "_checkout", "_token", "_payloads", "_view_json", "_state")
    _identity: PreparedWorkflowEdit
    _checkout: WorkflowCheckout
    _token: str
    _payloads: tuple[bytes | None, ...]
    _view_json: bytes
    _state: str

    def __repr__(self) -> str:
        return "<PreparedWorkflowEdit>"

    @property
    def kind(self) -> Literal["prepared"]:
        return "prepared"

    @property
    def token(self) -> str:
        return self._token

    @property
    def revision(self) -> str:
        return self._checkout.revision

    @property
    def view(self) -> PreparedWorkflowView:
        return cast(PreparedWorkflowView, json.loads(self._view_json))


class WorkflowConflict(_shared._PrivateAuthority):
    """Closed, detached refusal data, deliberately without any Apply token."""

    __slots__ = ("_revision_token", "_view_json")
    _revision_token: str
    _view_json: bytes

    def __repr__(self) -> str:
        return "<WorkflowConflict>"

    @property
    def kind(self) -> Literal["conflict"]:
        return "conflict"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def view(self) -> WorkflowConflictView:
        return cast(WorkflowConflictView, json.loads(self._view_json))

    @property
    def outcome(self) -> CoreEditOutcome:
        # Business refusal is separate from native/transaction failure. The
        # original outer owner must still settle and merge its actual facts.
        return _shared._not_started("none")


def _authentic_checkout(value: object) -> bool:
    return type(value) is WorkflowCheckout and getattr(value, "_identity", None) is value


def _authentic_plan(value: object) -> bool:
    return (type(value) is PreparedWorkflowEdit and getattr(value, "_identity", None) is value
            and _authentic_checkout(getattr(value, "_checkout", None))
            and getattr(value._checkout, "_prepared", None) is value)


def _workflow_outcome(value: CoreEditOutcome) -> CoreEditOutcome:
    if value.reason == "ignore_conflict":
        # A configuration-only native report is not an admissible workflow
        # reason. Keep irreversible effect facts, but fail its custody claim.
        return CoreEditOutcome(value.effect, value.journal, "unknown", "custody_unknown")
    return value


def _failure(native: _shared._NativeContract, error: BaseException,
             previous: CoreEditOutcome | None = None) -> CoreEditOutcome:
    return _workflow_outcome(_shared._settled_failure(native, error, previous))


def _lease_matches(native: _shared._NativeContract, lease: object) -> bool:
    return type(lease) is native.lease and getattr(lease, "profile", None) is _PROFILE


def _admit_revision(native: _shared._NativeContract, revision: object,
                    files: tuple[_shared._FileSnapshot, ...]) -> None:
    if (type(revision) is not native.revision or revision.profile is not _PROFILE
            or type(revision.token) is not str or _shared._TOKEN.fullmatch(revision.token) is None
            or type(revision.missing_workflow_directories) is not tuple
            or revision.missing_workflow_directories not in _MISSING_DIRECTORIES
            or revision.missing_workflow_directories and any(item.data is not None for item in files)):
        raise _shared._ContractViolation()


def _observed(file: _shared._FileSnapshot) -> AbsentWorkflowObservation | PresentWorkflowObservation:
    if file.data is None:
        return {"state": "absent"}
    return {"state": "present", "byteLength": len(file.data),
            "sha256": hashlib.sha256(file.data).hexdigest()}


def capture_github_workflow_edit(lease: InitRootLease) -> WorkflowCheckout:
    """Capture only the four fixed originals after the workflow profile check."""
    try:
        native = _shared._native_contract()
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None
    if not _lease_matches(native, lease):
        _shared._reject("invalid_params")
    if (_PROFILE.paths != _PATHS
            or _PROFILE.observation_limits != (_setup.MAX_SNAPSHOT_FILE_BYTES,) * len(_PATHS)):
        _shared._reject("custody_unknown")
    try:
        with lease.workspace_scope() as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            originals = tuple(workspace.observe(path, limit=limit)
                              for path, limit in zip(_PATHS, _PROFILE.observation_limits))
            revision = lease.bind_revision(workspace, originals)
    except BaseException as error:
        # No partial rows escape an unsafe/unreadable/unstable observation.
        raise ConfigEditFailure(_failure(native, error)) from None
    try:
        files = tuple(_shared._snapshot(item, path, limit) for item, path, limit in
                      zip(originals, _PATHS, _PROFILE.observation_limits))
        _admit_revision(native, revision, files)
        summaries = [{"id": identity, **_observed(item)}
                     for (identity, _), item in zip(GITHUB_WORKFLOWS, files)]
        observed_json = bounded_json_text(summaries, max_bytes=_SMALL_VIEW_BYTES,
                                         max_nodes=256, max_depth=8).encode("utf-8")
        checkout = object.__new__(WorkflowCheckout)
        for name, value in (("_identity", checkout), ("_lease", lease), ("_revision", revision),
                            ("_revision_token", revision.token), ("_files", files),
                            ("_observed_json", observed_json), ("_state", _shared._CAPTURED),
                            ("_prepared", None)):
            object.__setattr__(checkout, name, value)
        return checkout
    except (AttributeError, _shared._ContractViolation):
        raise ConfigEditFailure(_shared._uncertain()) from None
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None


def _proposal(draft: object, repository: object, sha: object) -> dict[str, Any]:
    if type(draft) is not dict:
        _shared._reject("invalid_params")
    try:
        # This is deep freezing, not a second schema/source/credential policy.
        frozen = json.loads(bounded_json_text(draft, max_bytes=_setup.MAX_CONFIG_BYTES,
                                             max_nodes=_setup.MAX_DOCUMENT_NODES,
                                             max_depth=_setup.MAX_DOCUMENT_DEPTH))
    except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
        _shared._reject("invalid_params")
    try:
        result = _setup.propose_github_setup(frozen, repository, sha, None)
    except ApiError as error:
        _shared._reject("invalid_params" if error.code == "invalid_params" else "filesystem_error")
    if (type(result) is not dict or type(result.get("schemaVersion")) is not int
            or result["schemaVersion"] != 1):
        _shared._reject("filesystem_error")
    if result.get("state") == "invalid":
        _shared._reject("invalid_config")
    if (result.get("state") != "proposed" or type(result.get("validation")) is not dict
            or result["validation"].get("valid") is not True):
        _shared._reject("filesystem_error")
    return cast(dict[str, Any], result)


def _derive(checkout: WorkflowCheckout, draft: object, repository: object, sha: object
            ) -> tuple[tuple[bytes | None, ...] | None, bytes]:
    """None payload tuple means closed conflict data, never a prepared plan."""
    proposed = _proposal(draft, repository, sha)
    try:
        # Admit only projection/integrity facts here. The shared service alone
        # owns pin grammar, schema policy, packaged resource choice and rendering.
        template = _setup._object(proposed["templateSet"], {"coreVersion", "resourceVersion", "resourceSha256"})
        tooling = _setup._object(proposed["tooling"], {"repository", "sha", "schemaReference", "state"})
        _setup._require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", _setup._text(template["coreVersion"], 32)) is not None
                        and type(template["resourceVersion"]) is int and template["resourceVersion"] == 1
                        and type(template["resourceSha256"]) is str
                        and _shared._DIGEST.fullmatch(template["resourceSha256"]) is not None)
        _setup._text(tooling["repository"], 140, plain=True)
        _setup._text(tooling["schemaReference"], 512, plain=True)
        _setup._require(type(tooling["sha"]) is str and re.fullmatch(r"[0-9a-f]{40}", tooling["sha"]) is not None
                        and tooling["state"] == "format-only")
        records = proposed["workflows"]
        _setup._require(type(records) is list and len(records) == len(GITHUB_WORKFLOWS))
        payloads: list[bytes | None] = []
        files: list[WorkflowFileView] = []
        conflicts: list[WorkflowConflictFile] = []
        total = 0
        for (identity, path), original, record in zip(GITHUB_WORKFLOWS, checkout._files, records):
            row = _setup._object(record, {"id", "path", "content", "byteLength", "sha256", "comparison"})
            _setup._require(row["id"] == identity and row["path"] == path and row["comparison"] == "not-supplied")
            content = _setup._text(row["content"], _setup.MAX_WORKFLOW_BYTES).encode("utf-8")
            total += len(content)
            _setup._require(total <= _setup.MAX_WORKFLOWS_BYTES and type(row["byteLength"]) is int
                            and row["byteLength"] == len(content) and type(row["sha256"]) is str
                            and row["sha256"] == hashlib.sha256(content).hexdigest())
            observed = _observed(original)
            if original.data is not None and original.data != content:
                conflicts.append({"id": cast(WorkflowId, identity),
                                  "observed": cast(PresentWorkflowObservation, observed)})
                continue
            payloads.append(content if original.data is None else None)
            files.append({"id": cast(WorkflowId, identity), "path": path,
                          "action": "create" if original.data is None else "preserve",
                          "observed": observed,
                          "generated": {"content": row["content"], "byteLength": len(content),
                                        "sha256": row["sha256"]}})
        if conflicts:
            conflict: WorkflowConflictView = {"schemaVersion": 1, "reason": "existing_workflow_differs",
                                             "conflicts": conflicts}
            return None, bounded_json_text(conflict, max_bytes=_SMALL_VIEW_BYTES,
                                           max_nodes=256, max_depth=8).encode("utf-8")
        view: PreparedWorkflowView = {
            "schemaVersion": 1, "files": files,
            "createDirectories": list(checkout._revision.missing_workflow_directories),
            "templateSet": cast(GitHubTemplateSet, template), "tooling": cast(GitHubToolingReference, tooling),
        }
        return tuple(payloads), bounded_json_text(view, max_bytes=_setup.MAX_RESULT_BYTES,
                                                  max_nodes=8_000, max_depth=16).encode("utf-8")
    except (KeyError, ValueError, TypeError, UnicodeError, RecursionError, ConfigurationError):
        raise ConfigEditFailure(_shared._not_started("filesystem_error")) from None


def prepare_github_workflow_edit(lease: InitRootLease, checkout: WorkflowCheckout,
                                 expected_revision: str, draft: object,
                                 tooling_repository: object, tooling_sha: object
                                 ) -> PreparedWorkflowEdit | WorkflowConflict:
    """Consume once, generate once, then recheck the original rooted revision."""
    if not _authentic_checkout(checkout) or getattr(checkout, "_state", None) != _shared._CAPTURED:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._PREPARING)
    try:
        if lease is not checkout._lease:
            _shared._reject("invalid_params")
        if type(expected_revision) is not str or _shared._TOKEN.fullmatch(expected_revision) is None:
            _shared._reject("invalid_params")
        if expected_revision != checkout.revision:
            _shared._reject("stale_revision")
        try:
            native = _shared._native_contract()
        except BaseException as error:
            raise ConfigEditFailure(_shared._pure_failure(error)) from None
        if not _lease_matches(native, lease):
            _shared._reject("invalid_params")
        _admit_revision(native, checkout._revision, checkout._files)
        payloads, view_json = _derive(checkout, draft, tooling_repository, tooling_sha)
        try:
            with lease.workspace_scope(checkout._revision) as workspace:
                if type(workspace) is not native.workspace:
                    raise _shared._ContractViolation()
                # Recheck even a differing-file refusal. A stale or failed
                # observation is not permission to publish current-looking rows.
        except BaseException as error:
            raise ConfigEditFailure(_failure(native, error)) from None
        if payloads is None:
            conflict = object.__new__(WorkflowConflict)
            object.__setattr__(conflict, "_revision_token", checkout.revision)
            object.__setattr__(conflict, "_view_json", view_json)
            object.__setattr__(checkout, "_state", _shared._RETIRED)
            return conflict
        token = _shared.uuid.uuid4().hex
        if type(token) is not str or _shared._TOKEN.fullmatch(token) is None or token == checkout.revision:
            _shared._reject("custody_unknown")
        plan = object.__new__(PreparedWorkflowEdit)
        for name, value in (("_identity", plan), ("_checkout", checkout), ("_token", token),
                            ("_payloads", payloads), ("_view_json", view_json), ("_state", _shared._PREPARED)):
            object.__setattr__(plan, name, value)
        object.__setattr__(checkout, "_prepared", plan)
        object.__setattr__(checkout, "_state", _shared._PREPARED)
        return plan
    except ConfigEditFailure:
        object.__setattr__(checkout, "_state", _shared._RETIRED)
        raise
    except BaseException as error:
        object.__setattr__(checkout, "_state", _shared._RETIRED)
        raise ConfigEditFailure(_shared._pure_failure(error)) from None


def apply_github_workflow_edit(lease: InitRootLease, plan: PreparedWorkflowEdit) -> CoreEditOutcome:
    """Consume before acquisition; use only the closed workflow typed facade."""
    if (not _authentic_plan(plan) or getattr(plan, "_state", None) != _shared._PREPARED
            or plan._checkout._state != _shared._PREPARED):
        return _shared._not_started("invalid_params")
    object.__setattr__(plan, "_state", _shared._RETIRED)
    checkout = plan._checkout
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if lease is not checkout._lease:
        return _shared._not_started("invalid_params")
    try:
        native = _shared._native_contract()
    except BaseException as error:
        return _shared._pure_failure(error)
    if (not _lease_matches(native, lease) or type(checkout._revision) is not native.revision
            or checkout._revision.profile is not _PROFILE):
        return _shared._not_started("invalid_params")
    native_result: object = None
    try:
        with lease.workspace_scope(checkout._revision) as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            changes = [(item.observed(), payload) for item, payload in zip(checkout._files, plan._payloads)]
            native_result = workspace.apply_workflows_typed(changes)
    except BaseException as error:
        try:
            provisional = _workflow_outcome(_shared._native_outcome(native, native_result))
        except _shared._ContractViolation:
            provisional = None
        return _failure(native, error, provisional)
    try:
        provisional = _workflow_outcome(_shared._native_outcome(native, native_result))
    except _shared._ContractViolation:
        return _shared._uncertain()
    if provisional.reason == "none":
        expected = ("unchanged", "not_created") if all(item is None for item in plan._payloads) else ("committed", "clean")
        if (provisional.effect, provisional.journal) != expected:
            return _shared._uncertain(provisional)
    return provisional


def discard_github_workflow_edit(authority: WorkflowCheckout | PreparedWorkflowEdit) -> None:
    """Retire original in-memory authority only; no transaction/cleanup IO."""
    if _authentic_checkout(authority):
        checkout = authority
    elif _authentic_plan(authority):
        checkout = authority._checkout
    else:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", _shared._RETIRED)
