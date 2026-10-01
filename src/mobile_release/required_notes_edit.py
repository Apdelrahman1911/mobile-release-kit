"""One closed required-note edit through the original metadata transaction.

Only the original lease captures config/ignore/version/counterpart and one note.
Direct private review DATA is separate from routine outcome/finality. No generic
path writer, secondary owner or persisted recovery authority is introduced.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from . import config_edit as _shared
from .api._json import bounded_json_text
from .config_edit import ConfigEditFailure, CoreEditOutcome
from .errors import ConfigurationError
from .init_transaction import TypedEditProfile
from .metadata_text import DEPENDENCY_LIMITS, DEPENDENCY_PATHS
from .required_notes import (RequiredNotesInputError, RequiredNotesSelection,
                             admit_notes_baseline, check_required_note, notes_baseline,
                             notes_context, notes_selection_view, required_note_sensitive,
                             validate_required_note_input)

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease, RootedRevision

_PROFILE = TypedEditProfile.METADATA_TEXT
MAX_PREPARED_BYTES = 896 * 1024


class RequiredNotesCheckout(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_revision", "_revision_token", "_selection", "_selection_json",
                 "_dependencies", "_file", "_baseline_json", "_state", "_prepared")
    _identity: RequiredNotesCheckout
    _lease: InitRootLease
    _revision: RootedRevision
    _revision_token: str
    _selection: RequiredNotesSelection
    _selection_json: bytes
    _dependencies: tuple[_shared._FileSnapshot, ...]
    _file: _shared._FileSnapshot | None
    _baseline_json: bytes
    _state: str
    _prepared: PreparedRequiredNotesEdit | None

    def __repr__(self) -> str:
        return "<RequiredNotesCheckout>"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def baseline(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._baseline_json))

    @property
    def selection(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._selection_json))


class PreparedRequiredNotesEdit(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_checkout", "_token", "_payload", "_view_json", "_state")
    _identity: PreparedRequiredNotesEdit
    _checkout: RequiredNotesCheckout
    _token: str
    _payload: bytes | None
    _view_json: bytes
    _state: str

    def __repr__(self) -> str:
        return "<PreparedRequiredNotesEdit>"

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
    return type(value) is RequiredNotesCheckout and getattr(value, "_identity", None) is value


def _authentic_plan(value: object) -> bool:
    return (type(value) is PreparedRequiredNotesEdit and getattr(value, "_identity", None) is value
            and _authentic_checkout(getattr(value, "_checkout", None))
            and getattr(value._checkout, "_prepared", None) is value)


def _lease_matches(native: _shared._NativeContract, lease: object) -> bool:
    from .init_workspace_custody import _LeasePurpose
    return (type(lease) is native.lease and getattr(lease, "profile", None) is _PROFILE
            and getattr(lease, "_purpose", None) is _LeasePurpose.REQUIRED_NOTES)


def _snapshot(lease: InitRootLease, value: object, path: str, limit: int) -> _shared._FileSnapshot:
    # The concrete original lease, not a renderer identity or a dictionary tag,
    # selects the Notes-only material family. Other editors retain _snapshot.
    family = lease.notes_identity_family
    if family == "posix":
        return _shared._snapshot(value, path, limit)
    if family != "windows-ntfs-v1":
        raise _shared._ContractViolation()
    from ._required_notes_windows_contract import WindowsNotesContractError, material
    from .init_transaction import ObservedFile
    if type(value) is not ObservedFile or type(value.path) is not str or value.path != path:
        raise _shared._ContractViolation()
    if value.before is None:
        if value.data is not None:
            raise _shared._ContractViolation()
        return _shared._FileSnapshot(path, None, None)
    try:
        before = material(value.before, directory=False, limit=limit)
    except WindowsNotesContractError:
        raise _shared._ContractViolation() from None
    data = value.data
    if (type(data) is not bytes or len(data) > limit or before["size"] != str(len(data))
            or before["sha256"] != _shared.hashlib.sha256(data).hexdigest()):
        raise _shared._ContractViolation()
    return _shared._FileSnapshot(path, tuple(sorted(before.items())), data)


def _admit_revision(native: _shared._NativeContract, revision: object,
                    selection: RequiredNotesSelection, original: _shared._FileSnapshot | None) -> None:
    if (type(revision) is not native.revision or revision.profile is not _PROFILE
            or type(revision.token) is not str or _shared._TOKEN.fullmatch(revision.token) is None
            or type(revision.metadata_selection) is not RequiredNotesSelection
            or revision.metadata_selection is not selection
            or original is None or original.path != selection.path
            or type(revision.missing_metadata_directories) is not tuple):
        raise _shared._ContractViolation()
    absent = revision.missing_metadata_directories
    if (len(absent) > 11 or any(type(path) is not str for path in absent)
            or absent != tuple(path for path in selection.directories if path in absent)
            or original.data is not None and any(original.path.startswith(path + "/") for path in absent)):
        raise _shared._ContractViolation()


def _safe_original(raw: bytes | None, selection: RequiredNotesSelection) -> None:
    checked = check_required_note(selection.context.kind, raw)
    if "notes.utf8" in checked.issues or "notes.editor-byte-limit" in checked.issues:
        _shared._reject("invalid_params")
    if raw is not None:
        # Android's first policy failure can precede its secret check. This
        # independent private-disclosure guard must not depend on that ordering.
        if required_note_sensitive(selection.context.kind, raw.decode("utf-8")):
            _shared._reject("invalid_params")


def capture_required_notes_edit(lease: InitRootLease, context: object) -> RequiredNotesCheckout:
    try:
        selected_context = notes_context(context)
    except RequiredNotesInputError:
        _shared._reject("invalid_params")
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
            fixed = tuple(workspace.observe(path, limit=limit)
                          for path, limit in zip(DEPENDENCY_PATHS, DEPENDENCY_LIMITS))
            targets = lease.bind_required_notes_targets(workspace, fixed, selected_context.wire())
            selection = targets.selection
            if (type(selection) is not RequiredNotesSelection or selection.context != selected_context
                    or targets.paths != (selection.path,) or targets.payload_limits != (selection.editor_byte_limit,)):
                raise _shared._ContractViolation()
            dependencies, limits = targets.dependency_observations, targets.dependency_limits
            if (len(dependencies) != len(limits) or tuple(item.path for item in dependencies) != targets.dependency_paths):
                raise _shared._ContractViolation()
            original = workspace.observe(selection.path, limit=selection.editor_byte_limit)
            revision = lease.bind_revision(workspace, (*dependencies, original))
    except BaseException as error:
        raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
    try:
        captured = tuple(_snapshot(lease, item, path, limit)
                         for item, path, limit in zip(dependencies, targets.dependency_paths, limits))
        item = _snapshot(lease, original, selection.path, selection.editor_byte_limit)
        _admit_revision(native, revision, selection, item)
        _safe_original(item.data, selection)
        originals = {row.path: row.data for row in captured}
        config = originals[DEPENDENCY_PATHS[0]]
        if config is None:
            raise _shared._ContractViolation()
        version = None if selection.version_source is None else originals[selection.version_source]
        counterpart = None if selection.counterpart_path is None else originals[selection.counterpart_path]
        baseline_json = bounded_json_text(notes_baseline(config, version, item.data, counterpart),
                                          max_bytes=8 * 1024, max_nodes=256, max_depth=8).encode("utf-8")
        selection_json = bounded_json_text(notes_selection_view(selection, item.data, counterpart),
                                           max_bytes=8 * 1024, max_nodes=256, max_depth=8).encode("utf-8")
        checkout = object.__new__(RequiredNotesCheckout)
        for name, value in (
            ("_identity", checkout), ("_lease", lease), ("_revision", revision), ("_revision_token", revision.token),
            ("_selection", selection), ("_selection_json", selection_json), ("_dependencies", captured), ("_file", item),
            ("_baseline_json", baseline_json), ("_state", _shared._CAPTURED), ("_prepared", None),
        ):
            object.__setattr__(checkout, name, value)
        return checkout
    except ConfigEditFailure:
        raise
    except (AttributeError, KeyError, _shared._ContractViolation):
        raise ConfigEditFailure(_shared._uncertain()) from None
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None


def prepare_required_notes_edit(lease: InitRootLease, checkout: RequiredNotesCheckout,
                                expected_revision: str, context: object,
                                expected_baseline: object, text: object) -> PreparedRequiredNotesEdit:
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
            requested = notes_context(context)
            expected = admit_notes_baseline(requested, expected_baseline)
            validation = validate_required_note_input({"context": context, "text": text})
        except RequiredNotesInputError:
            _shared._reject("invalid_params")
        if requested != checkout._selection.context or expected != checkout.baseline:
            _shared._reject("stale_revision")
        if validation["valid"] is not True:
            _shared._reject("invalid_params")
        try:
            native = _shared._native_contract()
        except BaseException as error:
            raise ConfigEditFailure(_shared._pure_failure(error)) from None
        if not _lease_matches(native, lease):
            _shared._reject("invalid_params")
        _admit_revision(native, checkout._revision, checkout._selection, checkout._file)
        original = checkout._file
        if original is None or type(text) is not str:
            raise _shared._ContractViolation()
        raw = text.encode("utf-8")
        action = "create" if original.data is None else "preserve" if original.data == raw else "replace"
        before = {"state": "absent"} if original.data is None else {"state": "present", "text": original.data.decode("utf-8")}
        view = {"schemaVersion": 1, "selection": checkout.selection, "baseline": checkout.baseline,
                "before": before, "after": text, "action": action,
                "createDirectories": list(checkout._revision.missing_metadata_directories), "validation": validation}
        try:
            view_json = bounded_json_text(view, max_bytes=MAX_PREPARED_BYTES, max_nodes=2048, max_depth=16).encode("utf-8")
        except (ConfigurationError, ValueError, UnicodeError, RecursionError):
            _shared._reject("invalid_params")
        try:
            with lease.workspace_scope(checkout._revision) as workspace:
                if type(workspace) is not native.workspace:
                    raise _shared._ContractViolation()
        except BaseException as error:
            raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
        token = _shared.uuid.uuid4().hex
        if type(token) is not str or _shared._TOKEN.fullmatch(token) is None or token == checkout.revision:
            _shared._reject("custody_unknown")
        plan = object.__new__(PreparedRequiredNotesEdit)
        for name, value in (("_identity", plan), ("_checkout", checkout), ("_token", token),
                            ("_payload", None if action == "preserve" else raw),
                            ("_view_json", view_json), ("_state", _shared._PREPARED)):
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


def apply_required_notes_edit(lease: InitRootLease, plan: PreparedRequiredNotesEdit) -> CoreEditOutcome:
    if (not _authentic_plan(plan) or getattr(plan, "_state", None) != _shared._PREPARED
            or plan._checkout._state != _shared._PREPARED):
        return _shared._not_started("invalid_params")
    object.__setattr__(plan, "_state", _shared._RETIRED)
    checkout = plan._checkout
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if lease is not checkout._lease or checkout._file is None:
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
            native_result = workspace.apply_metadata_text_typed([(checkout._file.observed(), plan._payload)])
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
        expected = ("unchanged", "not_created") if plan._payload is None else ("committed", "clean")
        if (provisional.effect, provisional.journal) != expected:
            return _shared._uncertain(provisional)
    return provisional


def discard_required_notes_edit(authority: RequiredNotesCheckout | PreparedRequiredNotesEdit) -> None:
    if _authentic_checkout(authority):
        checkout = authority
    elif _authentic_plan(authority):
        checkout = authority._checkout
    else:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", _shared._RETIRED)
        object.__setattr__(checkout._prepared, "_payload", None)
        object.__setattr__(checkout._prepared, "_view_json", b"{}")
    # Release adapter-private references at original cleanup. The immutable native
    # lease keeps its own necessary custody until close; this is not secure erasure.
    object.__setattr__(checkout, "_dependencies", ())
    object.__setattr__(checkout, "_file", None)
    object.__setattr__(checkout, "_baseline_json", b"{}")
    object.__setattr__(checkout, "_selection_json", b"{}")
