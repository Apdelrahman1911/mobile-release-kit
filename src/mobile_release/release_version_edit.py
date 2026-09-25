"""Private one-shot saved-version VALUE editing through the original owner.

The saved config and root ignore proof are read-only dependencies. Only the
original lease binds a dynamic descriptor, only its original rooted revision
is rechecked, and only its target files reach the typed transaction facade.
No general paths, recovery commands, new writer or injectable backend exists.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from . import config_edit as _shared
from .api._json import bounded_json_text
from .config_edit import ConfigEditFailure, CoreEditOutcome
from .errors import ConfigurationError
from .init_transaction import TypedEditProfile
from .version_text import (DEPENDENCY_LIMITS, DEPENDENCY_PATHS, MAX_PREPARED_BYTES,
                           MAX_VERSION_BYTES, VersionTextInputError, VersionSelection,
                           admit_baseline, baseline, content_digest, final_newline,
                           line_endings, original_text, prepare_payload)

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease, RootedRevision

_PROFILE = TypedEditProfile.RELEASE_VERSION


class VersionCheckout(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_revision", "_revision_token", "_selection",
                 "_dependencies", "_files", "_baseline_json", "_original_values", "_state", "_prepared")
    _identity: VersionCheckout
    _lease: InitRootLease
    _revision: RootedRevision
    _revision_token: str
    _selection: VersionSelection
    _dependencies: tuple[_shared._FileSnapshot, ...]
    _files: tuple[_shared._FileSnapshot, ...]
    _baseline_json: bytes
    _original_values: tuple[str, str] | None
    _state: str
    _prepared: PreparedVersionEdit | None

    def __repr__(self) -> str:
        return "<VersionCheckout>"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def selection(self) -> VersionSelection:
        return self._selection

    @property
    def values(self) -> dict[str, str] | None:
        if self._original_values is None:
            return None
        return {"name": self._original_values[0], "build": self._original_values[1]}

    @property
    def baseline(self) -> dict[str, Any]:
        # Detached comparisons, never writable authority or a replacement file.
        return cast(dict[str, Any], json.loads(self._baseline_json))


class PreparedVersionEdit(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_checkout", "_token", "_payloads", "_view_json", "_state")
    _identity: PreparedVersionEdit
    _checkout: VersionCheckout
    _token: str
    _payloads: tuple[bytes | None, ...]
    _view_json: bytes
    _state: str

    def __repr__(self) -> str:
        return "<PreparedVersionEdit>"

    @property
    def token(self) -> str:
        return self._token

    @property
    def revision(self) -> str:
        return self._checkout.revision

    @property
    def view(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._view_json))


def _authentic_checkout(value: object) -> bool:
    return type(value) is VersionCheckout and getattr(value, "_identity", None) is value


def _authentic_plan(value: object) -> bool:
    return (type(value) is PreparedVersionEdit and getattr(value, "_identity", None) is value
            and _authentic_checkout(getattr(value, "_checkout", None))
            and getattr(value._checkout, "_prepared", None) is value)


def _lease_matches(native: _shared._NativeContract, lease: object) -> bool:
    return type(lease) is native.lease and getattr(lease, "profile", None) is _PROFILE


def _admit_revision(native: _shared._NativeContract, revision: object,
                    selection: VersionSelection, originals: tuple[_shared._FileSnapshot, ...]) -> None:
    if (type(revision) is not native.revision or revision.profile is not _PROFILE
            or type(revision.token) is not str or _shared._TOKEN.fullmatch(revision.token) is None
            or type(revision.version_selection) is not VersionSelection
            or revision.version_selection != selection
            or type(revision.missing_version_directories) is not tuple):
        raise _shared._ContractViolation()
    absent = revision.missing_version_directories
    if (len(absent) > 11 or any(type(path) is not str for path in absent)
            or absent != selection.directories[len(selection.directories) - len(absent):]
            or any(file.data is not None and any(file.path.startswith(path + "/") for path in absent)
                   for file in originals)):
        raise _shared._ContractViolation()


def _safe_originals(files: tuple[_shared._FileSnapshot, ...],
                    selection: VersionSelection) -> tuple[str, str] | None:
    if len(files) != 1:
        raise _shared._ContractViolation()
    if files[0].data is None:
        return None
    try:
        return original_text(selection, files[0].data).values
    except VersionTextInputError:
        _shared._reject("invalid_params")


def capture_release_version_edit(lease: InitRootLease) -> VersionCheckout:
    try:
        native = _shared._native_contract()
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None
    if not _lease_matches(native, lease):
        _shared._reject("invalid_params")
    try:
        with lease.workspace_scope() as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            dependencies = tuple(workspace.observe(path, limit=limit)
                                 for path, limit in zip(DEPENDENCY_PATHS, DEPENDENCY_LIMITS))
            targets = lease.bind_version_targets(workspace, dependencies)
            originals = tuple(workspace.observe(path, limit=MAX_VERSION_BYTES) for path in targets.paths)
            revision = lease.bind_revision(workspace, (*dependencies, *originals))
    except BaseException as error:
        raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
    try:
        captured_dependencies = tuple(_shared._snapshot(item, path, limit) for item, path, limit in
                                      zip(dependencies, DEPENDENCY_PATHS, DEPENDENCY_LIMITS))
        config = captured_dependencies[0].data
        if config is None or type(revision) is not native.revision:
            raise _shared._ContractViolation()
        # Targets were derived once by this original lease, inside capture.
        # Retain that descriptor's selection; never reparse even the retained
        # config into a replacement target inventory outside its native scope.
        selection = revision.version_selection
        if type(selection) is not VersionSelection:
            raise _shared._ContractViolation()
        files = tuple(_shared._snapshot(item, path, MAX_VERSION_BYTES)
                      for item, path in zip(originals, selection.paths))
        if len(files) != len(selection.paths):
            raise _shared._ContractViolation()
        _admit_revision(native, revision, selection, files)
        original_values = _safe_originals(files, selection)
        baseline_json = bounded_json_text(baseline(config, files[0].data),
                                          max_bytes=8 * 1024, max_nodes=256, max_depth=8).encode("utf-8")
        checkout = object.__new__(VersionCheckout)
        for name, value in (
            ("_identity", checkout), ("_lease", lease), ("_revision", revision), ("_revision_token", revision.token),
            ("_selection", selection), ("_dependencies", captured_dependencies), ("_files", files),
            ("_baseline_json", baseline_json), ("_original_values", original_values), ("_state", _shared._CAPTURED), ("_prepared", None),
        ):
            object.__setattr__(checkout, name, value)
        return checkout
    except ConfigEditFailure:
        raise
    except (AttributeError, _shared._ContractViolation):
        raise ConfigEditFailure(_shared._uncertain()) from None
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None


def _derive(checkout: VersionCheckout, intent: object, supplied_values: object) -> tuple[tuple[bytes | None, ...], bytes]:
    selection, original = checkout._selection, checkout._files[0]
    try:
        payload, raw, values = prepare_payload(selection, original.data, intent, supplied_values)
    except VersionTextInputError:
        _shared._reject("invalid_params")
    before_text = "" if original.data is None else original.data.decode("utf-8")
    after_text = raw.decode("utf-8")
    action = "create" if original.data is None else "preserve" if payload is None else "replace"
    before = {"state": "absent"} if original.data is None else {
        "state": "present", "text": before_text, **content_digest(original.data)}
    mode = 0o644 if original.binding is None else dict(original.binding)["mode"]
    view = {
        "schemaVersion": 1, "source": selection.source, "nameKey": selection.name_key,
        "buildKey": selection.build_key, "iosEnabled": selection.ios_enabled, "intent": intent,
        "values": values,
        "file": {"path": original.path, "action": action, "before": before,
                 "after": {"text": after_text, **content_digest(raw)},
                 "requestedMode": mode, "preserveMode": original.binding is not None},
        "createDirectories": list(checkout._revision.missing_version_directories),
        "lineEndings": {"before": line_endings(before_text), "after": line_endings(after_text),
                        "finalNewlineBefore": final_newline(before_text),
                        "finalNewlineAfter": final_newline(after_text),
                        "preserved": original.data is not None},
        "validation": {"valid": True, "state": "format-valid", "issues": []},
    }
    try:
        encoded = bounded_json_text(view, max_bytes=MAX_PREPARED_BYTES, max_nodes=2048, max_depth=16).encode("utf-8")
    except (ConfigurationError, ValueError, UnicodeError, RecursionError):
        _shared._reject("invalid_params")
    return (payload,), encoded


def prepare_release_version_edit(lease: InitRootLease, checkout: VersionCheckout,
                               expected_revision: str, expected_baseline: object,
                               intent: object, values: object) -> PreparedVersionEdit:
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
            expected = admit_baseline(expected_baseline)
        except VersionTextInputError:
            _shared._reject("invalid_params")
        if expected != checkout.baseline:
            _shared._reject("stale_revision")
        try:
            native = _shared._native_contract()
        except BaseException as error:
            raise ConfigEditFailure(_shared._pure_failure(error)) from None
        if not _lease_matches(native, lease):
            _shared._reject("invalid_params")
        _admit_revision(native, checkout._revision, checkout._selection, checkout._files)
        payloads, view_json = _derive(checkout, intent, values)
        try:
            with lease.workspace_scope(checkout._revision) as workspace:
                if type(workspace) is not native.workspace:
                    raise _shared._ContractViolation()
        except BaseException as error:
            raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
        token = _shared.uuid.uuid4().hex
        if type(token) is not str or _shared._TOKEN.fullmatch(token) is None or token == checkout.revision:
            _shared._reject("custody_unknown")
        plan = object.__new__(PreparedVersionEdit)
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


def apply_release_version_edit(lease: InitRootLease, plan: PreparedVersionEdit) -> CoreEditOutcome:
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
            changes = [(file.observed(), payload) for file, payload in zip(checkout._files, plan._payloads)]
            native_result = workspace.apply_version_typed(changes)
    except BaseException as error:
        try:
            provisional = _shared._native_outcome(native, native_result)
        except _shared._ContractViolation:
            provisional = None
        return _shared._settled_failure(native, error, provisional)
    try:
        provisional = _shared._native_outcome(native, native_result)
    except _shared._ContractViolation:
        return _shared._uncertain()
    if provisional.reason == "none":
        expected = ("unchanged", "not_created") if all(payload is None for payload in plan._payloads) else ("committed", "clean")
        if (provisional.effect, provisional.journal) != expected:
            return _shared._uncertain(provisional)
    return provisional


def discard_release_version_edit(authority: VersionCheckout | PreparedVersionEdit) -> None:
    if _authentic_checkout(authority):
        checkout = authority
    elif _authentic_plan(authority):
        checkout = authority._checkout
    else:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", _shared._RETIRED)
