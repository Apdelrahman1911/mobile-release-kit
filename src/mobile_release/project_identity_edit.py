"""One-shot project identity editing through the existing registered root owner.

No live route is enabled by import. Tokens/views are DATA, not substitutes for
the original lease, captured inventory, inode facts or one-use prepared object.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from . import config_edit as shared
from .config_edit import ConfigEditFailure, CoreEditOutcome
from .init_transaction import TypedEditProfile
from .project_identity import (MAX_FILE_BYTES, MAX_TOTAL_BYTES, IdentityInputError,
                               IdentitySelection, prepare_project_identity)
from .project_identity_targets import IdentityTargets, capture_inventory

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease, RootedRevision

_PROFILE = TypedEditProfile.PROJECT_IDENTITY


class IdentityCheckout(shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_revision", "_revision_token", "_targets", "_analysis",
                 "_files", "_state", "_prepared")

    def __repr__(self) -> str:
        return "<IdentityCheckout>"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def view(self) -> dict[str, Any]:
        result = self._analysis.view
        result["revision"] = self.revision
        return result


class PreparedIdentityEdit(shared._PrivateAuthority):
    __slots__ = ("_identity", "_checkout", "_token", "_payloads", "_view_json", "_state")

    def __repr__(self) -> str:
        return "<PreparedIdentityEdit>"

    @property
    def token(self) -> str:
        return self._token

    @property
    def revision(self) -> str:
        return self._checkout.revision

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)


def _checkout(value: object) -> bool:
    return type(value) is IdentityCheckout and getattr(value, "_identity", None) is value


def _prepared(value: object) -> bool:
    return (type(value) is PreparedIdentityEdit and getattr(value, "_identity", None) is value
            and _checkout(getattr(value, "_checkout", None))
            and getattr(value._checkout, "_prepared", None) is value)


def _lease_matches(native: shared._NativeContract, lease: object) -> bool:
    return type(lease) is native.lease and lease.profile is _PROFILE and not lease._identity_recovery_mode


def capture_project_identity_edit(lease: InitRootLease, selection: IdentitySelection) -> IdentityCheckout:
    native = shared._native_contract()
    if not _lease_matches(native, lease):
        shared._reject("invalid_params")
    try:
        with lease.workspace_scope() as workspace:
            inventory = capture_inventory(workspace)
            captured, total = [], 0
            for path in inventory.paths:
                item = workspace.observe(path, limit=MAX_FILE_BYTES)
                total += len(item.data) if item.data is not None else 0
                if total > MAX_TOTAL_BYTES:
                    from .init_transaction import InitConflict
                    raise InitConflict("The identity source inventory exceeds its byte bound")
                captured.append(item)
            originals = tuple(captured)
            targets = lease.bind_identity_targets(workspace, selection, inventory, originals)
            targets.check_inventory(workspace)
            revision = lease.bind_revision(workspace, originals)
    except BaseException as error:
        raise ConfigEditFailure(shared._settled_failure(native, error)) from None
    if (type(targets) is not IdentityTargets or type(revision) is not native.revision
            or revision.profile is not _PROFILE or revision._identity_targets is not targets):
        raise ConfigEditFailure(shared._uncertain())
    result = object.__new__(IdentityCheckout)
    for name, value in (("_identity", result), ("_lease", lease), ("_revision", revision),
                        ("_revision_token", revision.token), ("_targets", targets), ("_analysis", targets._analysis),
                        ("_files", tuple(shared._snapshot(item, path, MAX_FILE_BYTES)
                                         for item, path in zip(originals, inventory.paths))),
                        ("_state", shared._CAPTURED), ("_prepared", None)):
        object.__setattr__(result, name, value)
    return result


def prepare_project_identity_edit(lease: InitRootLease, checkout: IdentityCheckout, *,
                                  expected_revision: str, desired_identity: str,
                                  intent: str) -> PreparedIdentityEdit:
    if not _checkout(checkout) or checkout._state != shared._CAPTURED:
        shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", shared._PREPARING)
    try:
        native = shared._native_contract()
        if lease is not checkout._lease or not _lease_matches(native, lease):
            shared._reject("invalid_params")
        if type(expected_revision) is not str or expected_revision != checkout.revision:
            shared._reject("stale_revision")
        # Closed identity diagnostics remain available from Analyze. A refused
        # Prepare consumes the review just like all other saved-file domains.
        preparation = prepare_project_identity(checkout._analysis, desired_identity,
            expected_revision=checkout._analysis.revision, intent=intent)
        with lease.workspace_scope(checkout._revision) as workspace:
            checkout._targets._check_workspace(workspace)
            checkout._targets.bind_preparation(preparation)
        token = shared.uuid.uuid4().hex
        if shared._TOKEN.fullmatch(token) is None or token == checkout.revision:
            shared._reject("custody_unknown")
        payloads = dict(preparation._payloads)
        view = preparation.view
        view["revision"] = checkout.revision
        result = object.__new__(PreparedIdentityEdit)
        for name, value in (("_identity", result), ("_checkout", checkout), ("_token", token),
                            ("_payloads", tuple(payloads.get(file.path) for file in checkout._files)),
                            ("_view_json", json.dumps(view, separators=(",", ":")).encode("utf-8")),
                            ("_state", shared._PREPARED)):
            object.__setattr__(result, name, value)
        object.__setattr__(checkout, "_prepared", result)
        object.__setattr__(checkout, "_state", shared._PREPARED)
        return result
    except BaseException as error:
        object.__setattr__(checkout, "_state", shared._RETIRED)
        if isinstance(error, (ConfigEditFailure, IdentityInputError)):
            raise
        raise ConfigEditFailure(shared._settled_failure(shared._native_contract(), error)) from None


def apply_project_identity_edit(lease: InitRootLease, plan: PreparedIdentityEdit) -> CoreEditOutcome:
    if (not _prepared(plan) or plan._state != shared._PREPARED
            or plan._checkout._state != shared._PREPARED):
        return shared._not_started("invalid_params")
    object.__setattr__(plan, "_state", shared._RETIRED)
    checkout = plan._checkout
    object.__setattr__(checkout, "_state", shared._RETIRED)
    native = shared._native_contract()
    if lease is not checkout._lease or not _lease_matches(native, lease):
        return shared._not_started("invalid_params")
    native_result: object = None
    try:
        with lease.workspace_scope(checkout._revision) as workspace:
            changes = [(file.observed(), raw) for file, raw in zip(checkout._files, plan._payloads)]
            native_result = workspace.apply_identity_typed(changes)
    except BaseException as error:
        try:
            provisional = shared._native_outcome(native, native_result)
        except shared._ContractViolation:
            provisional = None
        return shared._settled_failure(native, error, provisional)
    try:
        return shared._native_outcome(native, native_result)
    except shared._ContractViolation:
        return shared._uncertain()


def discard_project_identity_edit(authority: IdentityCheckout | PreparedIdentityEdit) -> None:
    if _checkout(authority):
        checkout = authority
    elif _prepared(authority):
        checkout = authority._checkout
    else:
        shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", shared._RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", shared._RETIRED)


def identity_outcome_invalidates(outcome: CoreEditOutcome) -> bool:
    """Do not leave an older release/credential plan live after uncertain writes.

    The coordinator additionally invalidates read epochs on every save intent.
    Known commit is irreversible even if cleanup/finality is not confirmed.
    """
    return (type(outcome) is not CoreEditOutcome or outcome.effect in {"committed", "unknown"}
            or outcome.resources == "unknown" or outcome.journal in {"unknown", "recovery_required"})
