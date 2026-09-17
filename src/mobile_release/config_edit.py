"""Private, one-shot configuration editing for the dedicated native owner.

This is not a passive API method or a general file-writing service. Only the
concrete original InitRootLease and its settled borrowed InitWorkspace scopes
can supply filesystem authority. Capture/prepare never stage a transaction;
apply delegates the exact two fixed slots to the existing transaction engine.

Native imports are lazy. Importing this module grants no mutation capability,
and does not admit a platform or change desktop production/passive gates.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypedDict, cast

from .api._json import bounded_json_text
from .api._preview import (MAX_DOCUMENT_DEPTH, MAX_DOCUMENT_NODES, MAX_PAIR_BYTES,
                           MAX_PAIR_NODES, MAX_RESULT_BYTES, preview_config)
from .api.contracts import ApiError, PreviewResult
from .config import (MAX_CONFIG_BYTES, configuration_data_equal, parse_config_text,
                     validate_config_data)
from .config_payloads import (MAX_IGNORE_BYTES, append_ignore_lines,
                              prepare_edit_ignore, serialize_config_data)
from .errors import ConfigurationError, ValidationError
from .init_transaction import ObservedFile

if TYPE_CHECKING:
    from .init_transaction import InitApplyOutcome, InitOperationFailure, InitWorkspace
    from .init_workspace_custody import InitRootLease, RootedRevision

CONFIG_PATH = "release/mobile-release.json"
IGNORE_PATH = ".gitignore"
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_KEYS = frozenset({"device", "inode", "mode", "size", "sha256"})

Effect = Literal["not_started", "unchanged", "rolled_back", "committed", "unknown"]
Journal = Literal["not_created", "clean", "recovery_required", "unknown"]
Resources = Literal["settled", "unknown"]
Reason = Literal["none", "invalid_params", "invalid_config", "ignore_conflict",
                 "stale_revision", "pending_state", "busy", "cancelled",
                 "filesystem_error", "custody_unknown", "unsupported_platform"]
_EFFECTS = frozenset({"not_started", "unchanged", "rolled_back", "committed", "unknown"})
_JOURNALS = frozenset({"not_created", "clean", "recovery_required", "unknown"})
_RESOURCES = frozenset({"settled", "unknown"})
_REASONS = frozenset({"none", "invalid_params", "invalid_config", "ignore_conflict",
                     "stale_revision", "pending_state", "busy", "cancelled",
                     "filesystem_error", "custody_unknown", "unsupported_platform"})


@dataclass(frozen=True, slots=True)
class CoreEditOutcome:
    """Provisional transaction facts, not original-child/outer-owner finality."""

    effect: Effect
    journal: Journal
    resources: Resources
    reason: Reason

    def __post_init__(self) -> None:
        for value, allowed in ((self.effect, _EFFECTS), (self.journal, _JOURNALS),
                               (self.resources, _RESOURCES), (self.reason, _REASONS)):
            if type(value) is not str or value not in allowed:
                raise ValueError("invalid configuration edit outcome")
        if (self.effect == "unchanged" and self.journal != "not_created"
                or self.effect in {"committed", "rolled_back"} and self.journal == "not_created"
                or self.reason == "none" and (self.resources != "settled"
                    or self.effect == "unknown" or self.journal in {"unknown", "recovery_required"})):
            raise ValueError("inconsistent configuration edit outcome")


class ConfigEditFailure(ValidationError):
    """A closed, redacted failure; original exception text is never a reason."""

    def __init__(self, outcome: CoreEditOutcome):
        if type(outcome) is not CoreEditOutcome or outcome.reason == "none":
            raise ValueError("invalid configuration edit failure")
        self.outcome = outcome
        super().__init__(f"Configuration edit refused ({outcome.reason}).")


class ConfigFileView(TypedDict):
    path: Literal["release/mobile-release.json"]
    action: Literal["create", "replace", "preserve"]
    beforeBytes: int | None
    afterBytes: int


class IgnoreFileView(TypedDict):
    path: Literal[".gitignore"]
    action: Literal["create", "append", "preserve"]
    beforeBytes: int | None
    afterBytes: int


class PreparedConfigView(TypedDict):
    schemaVersion: Literal[1]
    files: list[ConfigFileView | IgnoreFileView]
    createReleaseDirectory: bool
    rewritesConfigFormatting: bool
    ignoreAdditions: list[str]
    preview: PreviewResult


@dataclass(frozen=True, slots=True, repr=False)
class _FileSnapshot:
    path: str
    binding: tuple[tuple[str, int | str], ...] | None
    data: bytes | None

    def observed(self) -> ObservedFile:
        # The transaction receives a fresh private dict, never retained mutable
        # state. Stable metadata/ancestry still belongs to the exact revision.
        return ObservedFile(self.path, dict(self.binding) if self.binding is not None else None, self.data)


_CAPTURED = "captured"
_PREPARING = "preparing"
_PREPARED = "prepared"
_RETIRED = "retired"


class _PrivateAuthority:
    __slots__ = ()

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        raise TypeError("Configuration edit authority is created only by the native adapter")

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Configuration edit authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Configuration edit authority is immutable")

    def __copy__(self) -> Any:
        raise TypeError("Configuration edit authority cannot be copied or serialized")

    def __deepcopy__(self, memo: dict[int, Any]) -> Any:
        raise TypeError("Configuration edit authority cannot be copied or serialized")

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError("Configuration edit authority cannot be copied or serialized")


class ConfigCheckout(_PrivateAuthority):
    """Original rooted capture; only base/revision are owner-facing data."""

    __slots__ = ("_identity", "_lease", "_revision", "_revision_token", "_files",
                 "_base_json", "_state", "_prepared")
    _identity: ConfigCheckout
    _lease: InitRootLease
    _revision: RootedRevision
    _revision_token: str
    _files: tuple[_FileSnapshot, _FileSnapshot]
    _base_json: bytes
    _state: str
    _prepared: PreparedConfigEdit | None

    def __repr__(self) -> str:
        return "<ConfigCheckout>"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def base(self) -> dict[str, Any] | None:
        return cast(dict[str, Any] | None, json.loads(self._base_json))


class PreparedConfigEdit(_PrivateAuthority):
    """One immutable plan, inseparable from its original checkout and lease."""

    __slots__ = ("_identity", "_checkout", "_token", "_payloads", "_view_json", "_state")
    _identity: PreparedConfigEdit
    _checkout: ConfigCheckout
    _token: str
    _payloads: tuple[bytes | None, bytes | None]
    _view_json: bytes
    _state: str

    def __repr__(self) -> str:
        return "<PreparedConfigEdit>"

    @property
    def token(self) -> str:
        return self._token

    @property
    def revision(self) -> str:
        return self._checkout.revision

    @property
    def view(self) -> PreparedConfigView:
        return cast(PreparedConfigView, json.loads(self._view_json))


@dataclass(frozen=True, slots=True)
class _NativeContract:
    lease: type[InitRootLease]
    revision: type[RootedRevision]
    workspace: type[InitWorkspace]
    outcome: type[InitApplyOutcome]
    failure: type[InitOperationFailure]


class _ContractViolation(Exception):
    """Internal constant-only native seam mismatch; not an alternate backend."""


def _native_contract() -> _NativeContract:
    # No Protocol, duck-typed fallback, callback injection or passive dispatch.
    from .init_transaction import InitApplyOutcome, InitOperationFailure, InitWorkspace
    from .init_workspace_custody import InitRootLease, RootedRevision

    return _NativeContract(InitRootLease, RootedRevision, InitWorkspace,
                           InitApplyOutcome, InitOperationFailure)


def _not_started(reason: Reason) -> CoreEditOutcome:
    # Only used before any short scope has been acquired, or after a scope
    # successfully settled without application. The outer lease is separate.
    return CoreEditOutcome("not_started", "not_created", "settled", reason)


def _pure_failure(error: BaseException) -> CoreEditOutcome:
    # Native exceptions are classified by their concrete carrier elsewhere.
    # A real interruption of bounded in-memory work is not a filesystem error.
    return _not_started("cancelled" if isinstance(error, KeyboardInterrupt) else "custody_unknown")


def _uncertain(previous: CoreEditOutcome | None = None) -> CoreEditOutcome:
    if previous is None:
        return CoreEditOutcome("unknown", "unknown", "unknown", "custody_unknown")
    return CoreEditOutcome(previous.effect, previous.journal, "unknown",
                           previous.reason if previous.reason != "none" else "custody_unknown")


def _reject(reason: Reason) -> None:
    raise ConfigEditFailure(_not_started(reason)) from None


def _native_outcome(native: _NativeContract, value: object) -> CoreEditOutcome:
    if type(value) is not native.outcome:
        raise _ContractViolation()
    try:
        return CoreEditOutcome(value.effect, value.journal, value.resources, value.reason)
    except (AttributeError, TypeError, ValueError):
        raise _ContractViolation() from None


def _settled_failure(native: _NativeContract, failure: BaseException,
                     previous: CoreEditOutcome | None = None) -> CoreEditOutcome:
    if type(failure) is not native.failure:
        return _uncertain(previous)
    try:
        result = _native_outcome(native, failure.outcome)
        if result.reason == "none":
            raise _ContractViolation()
    except (AttributeError, _ContractViolation):
        return _uncertain(previous)
    if previous is not None:
        # An irreversible decision and the first primary reason cannot be
        # erased by a later close failure, even if the seam itself misreports.
        if previous.effect in {"committed", "rolled_back", "unchanged"}:
            if result.effect not in {previous.effect, "unknown"}:
                return _uncertain(previous)
            if previous.effect in {"committed", "rolled_back"} and result.journal == "not_created":
                return _uncertain(previous)
            result = CoreEditOutcome(previous.effect,
                                     "not_created" if previous.effect == "unchanged" else result.journal,
                                     result.resources, result.reason)
        if previous.reason != "none" and result.reason != previous.reason:
            result = CoreEditOutcome(result.effect, result.journal, result.resources, previous.reason)
    return result


def _authentic_checkout(value: object) -> bool:
    return type(value) is ConfigCheckout and getattr(value, "_identity", None) is value


def _authentic_plan(value: object) -> bool:
    return (type(value) is PreparedConfigEdit and getattr(value, "_identity", None) is value
            and _authentic_checkout(value._checkout) and value._checkout._prepared is value)


def _snapshot(value: object, path: str, limit: int) -> _FileSnapshot:
    if type(value) is not ObservedFile or type(value.path) is not str or value.path != path:
        raise _ContractViolation()
    if value.before is None:
        if value.data is not None:
            raise _ContractViolation()
        return _FileSnapshot(path, None, None)
    before, data = value.before, value.data
    if (type(before) is not dict or before.keys() != _IDENTITY_KEYS
            or type(data) is not bytes or len(data) > limit
            or any(type(before[key]) is not int for key in ("device", "inode", "mode", "size"))
            or before["device"] < 0 or before["inode"] <= 0
            or not 0 <= before["mode"] <= 0o777 or before["size"] != len(data)
            or type(before["sha256"]) is not str or _DIGEST.fullmatch(before["sha256"]) is None
            or before["sha256"] != hashlib.sha256(data).hexdigest()):
        raise _ContractViolation()
    return _FileSnapshot(path, tuple(sorted(before.items())), data)


def _admit_revision(native: _NativeContract, revision: object,
                    files: tuple[_FileSnapshot, _FileSnapshot]) -> None:
    if (type(revision) is not native.revision or type(revision.token) is not str
            or _TOKEN.fullmatch(revision.token) is None
            or type(revision.release_directory_absent) is not bool
            or revision.release_directory_absent and files[0].data is not None):
        raise _ContractViolation()


def _base_bytes(files: tuple[_FileSnapshot, _FileSnapshot]) -> bytes:
    raw = files[0].data
    if raw is None:
        base = b"null"
    else:
        try:
            data = parse_config_text(raw.decode("utf-8"))
            base = bounded_json_text(data, max_bytes=MAX_CONFIG_BYTES,
                                     max_nodes=MAX_DOCUMENT_NODES,
                                     max_depth=MAX_DOCUMENT_DEPTH).encode("utf-8")
        except (UnicodeError, ConfigurationError):
            _reject("invalid_config")
    try:
        # Capture admits bytes, not sufficient coverage or guessed overwrite
        # permission. Negation intent is reviewed/refused during Prepare.
        append_ignore_lines(files[1].data if files[1].data is not None else b"", ())
    except ValidationError:
        _reject("ignore_conflict")
    return base


def capture_config_edit(lease: InitRootLease) -> ConfigCheckout:
    """Capture exact original files/ancestors under one settled short scope."""
    try:
        native = _native_contract()
    except BaseException as error:
        raise ConfigEditFailure(_pure_failure(error)) from None
    if type(lease) is not native.lease:
        _reject("invalid_params")
    try:
        with lease.workspace_scope() as workspace:
            if type(workspace) is not native.workspace:
                raise _ContractViolation()
            originals = (workspace.observe(CONFIG_PATH, limit=MAX_CONFIG_BYTES),
                         workspace.observe(IGNORE_PATH, limit=MAX_IGNORE_BYTES))
            revision = lease.bind_revision(workspace, originals)
    except BaseException as error:
        raise ConfigEditFailure(_settled_failure(native, error)) from None
    try:
        files = (_snapshot(originals[0], CONFIG_PATH, MAX_CONFIG_BYTES),
                 _snapshot(originals[1], IGNORE_PATH, MAX_IGNORE_BYTES))
        _admit_revision(native, revision, files)
    except (AttributeError, _ContractViolation):
        raise ConfigEditFailure(_uncertain()) from None
    except BaseException as error:
        raise ConfigEditFailure(_pure_failure(error)) from None
    try:
        base_json = _base_bytes(files)
        checkout = object.__new__(ConfigCheckout)
        for name, value in (("_identity", checkout), ("_lease", lease), ("_revision", revision),
                            ("_revision_token", revision.token), ("_files", files),
                            ("_base_json", base_json), ("_state", _CAPTURED), ("_prepared", None)):
            object.__setattr__(checkout, name, value)
        return checkout
    except ConfigEditFailure:
        raise
    except BaseException as error:
        raise ConfigEditFailure(_pure_failure(error)) from None


def _admit_inputs(expected_base: object, draft: object) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if (expected_base is not None and type(expected_base) is not dict) or type(draft) is not dict:
        _reject("invalid_params")
    try:
        raw = tuple(bounded_json_text(value, max_bytes=MAX_CONFIG_BYTES,
                                      max_nodes=MAX_DOCUMENT_NODES,
                                      max_depth=MAX_DOCUMENT_DEPTH) for value in (expected_base, draft))
        bounded_json_text({"base": expected_base, "draft": draft}, max_bytes=MAX_PAIR_BYTES,
                          max_nodes=MAX_PAIR_NODES, max_depth=MAX_DOCUMENT_DEPTH + 1)
    except ConfigurationError:
        _reject("invalid_params")
    # No caller-owned container is retained, including nested argv/list values.
    return json.loads(raw[0]), json.loads(raw[1])


def _derive(checkout: ConfigCheckout, expected_base: object, draft: object
            ) -> tuple[tuple[bytes | None, bytes | None], bytes]:
    expected, proposed = _admit_inputs(expected_base, draft)
    base = checkout.base
    if not configuration_data_equal(expected, base):
        _reject("stale_revision")
    try:
        validate_config_data(proposed)
    except ConfigurationError:
        _reject("invalid_config")
    config, ignore = checkout._files
    config_payload = None if configuration_data_equal(base, proposed) else serialize_config_data(proposed)
    if config_payload is not None and len(config_payload) > MAX_CONFIG_BYTES:
        _reject("invalid_params")
    try:
        ignored, additions = prepare_edit_ignore(ignore.data if ignore.data is not None else b"")
    except ValidationError:
        _reject("ignore_conflict")
    ignore_payload = None if ignore.data is not None and ignored == ignore.data else ignored
    config_action = "preserve" if config_payload is None else "create" if config.data is None else "replace"
    ignore_action = "preserve" if ignore_payload is None else "create" if ignore.data is None else "append"
    try:
        preview = preview_config(base, proposed)
        if preview["validation"]["valid"] is not True or preview["comparison"]["state"] != "complete":
            raise _ContractViolation()
        view: PreparedConfigView = {
            "schemaVersion": 1,
            "files": [
                {"path": CONFIG_PATH, "action": config_action,
                 "beforeBytes": len(config.data) if config.data is not None else None,
                 "afterBytes": len(config_payload) if config_payload is not None else len(config.data)},
                {"path": IGNORE_PATH, "action": ignore_action,
                 "beforeBytes": len(ignore.data) if ignore.data is not None else None,
                 "afterBytes": len(ignore_payload) if ignore_payload is not None else len(ignore.data)},
            ],
            "createReleaseDirectory": checkout._revision.release_directory_absent and config_action == "create",
            "rewritesConfigFormatting": config_action == "replace",
            "ignoreAdditions": list(additions), "preview": preview,
        }
        view_json = bounded_json_text(view, max_bytes=MAX_RESULT_BYTES,
                                      max_nodes=8_000, max_depth=18).encode("utf-8")
    except (ApiError, ConfigurationError):
        _reject("invalid_params")
    return (config_payload, ignore_payload), view_json


def prepare_config_edit(lease: InitRootLease, checkout: ConfigCheckout,
                        expected_revision: str, expected_base: object,
                        draft: object) -> PreparedConfigEdit:
    """Consume the one prepare attempt; derive bytes, then recheck originals."""
    if not _authentic_checkout(checkout) or checkout._state != _CAPTURED:
        _reject("invalid_params")
    # Even an invalid parameter, intent mismatch or failed acquisition exhausts
    # this checkout. A replacement owner needs genuine prior owner settlement.
    object.__setattr__(checkout, "_state", _PREPARING)
    try:
        if lease is not checkout._lease:
            _reject("invalid_params")
        if type(expected_revision) is not str or _TOKEN.fullmatch(expected_revision) is None:
            _reject("invalid_params")
        if expected_revision != checkout.revision:
            _reject("stale_revision")
        payloads, view_json = _derive(checkout, expected_base, draft)
        try:
            native = _native_contract()
        except BaseException as error:
            raise ConfigEditFailure(_pure_failure(error)) from None
        if type(lease) is not native.lease or type(checkout._revision) is not native.revision:
            _reject("invalid_params")
        try:
            with lease.workspace_scope(checkout._revision) as workspace:
                if type(workspace) is not native.workspace:
                    raise _ContractViolation()
                # The concrete scope rechecks all original raw/root/ancestor
                # bindings before yielding and again as needed on settlement.
                # Do not reobserve, stage, probe or adopt a replacement base.
        except BaseException as error:
            raise ConfigEditFailure(_settled_failure(native, error)) from None
        token = uuid.uuid4().hex
        if type(token) is not str or _TOKEN.fullmatch(token) is None or token == checkout.revision:
            _reject("custody_unknown")
        plan = object.__new__(PreparedConfigEdit)
        for name, value in (("_identity", plan), ("_checkout", checkout), ("_token", token),
                            ("_payloads", payloads), ("_view_json", view_json), ("_state", _PREPARED)):
            object.__setattr__(plan, name, value)
        object.__setattr__(checkout, "_prepared", plan)
        object.__setattr__(checkout, "_state", _PREPARED)
        return plan
    except ConfigEditFailure:
        object.__setattr__(checkout, "_state", _RETIRED)
        raise
    except BaseException as error:
        object.__setattr__(checkout, "_state", _RETIRED)
        raise ConfigEditFailure(_pure_failure(error)) from None


def apply_config_edit(lease: InitRootLease, plan: PreparedConfigEdit) -> CoreEditOutcome:
    """Consume once before acquisition; return only after true short-scope exit."""
    if (not _authentic_plan(plan) or plan._state != _PREPARED
            or plan._checkout._state != _PREPARED):
        return _not_started("invalid_params")
    object.__setattr__(plan, "_state", _RETIRED)
    checkout = plan._checkout
    object.__setattr__(checkout, "_state", _RETIRED)
    if lease is not checkout._lease:
        return _not_started("invalid_params")
    try:
        native = _native_contract()
    except BaseException as error:
        return _pure_failure(error)
    if type(lease) is not native.lease or type(checkout._revision) is not native.revision:
        return _not_started("invalid_params")
    native_result: object = None
    try:
        with lease.workspace_scope(checkout._revision) as workspace:
            if type(workspace) is not native.workspace:
                raise _ContractViolation()
            changes = [(item.observed(), payload) for item, payload in zip(checkout._files, plan._payloads)]
            native_result = workspace.apply_typed(changes)
    except BaseException as error:
        # Copy/merge only outside __exit__. The concrete raw receipt survives
        # a later close failure; it is not itself process/resource finality.
        try:
            provisional = _native_outcome(native, native_result)
        except _ContractViolation:
            provisional = None
        return _settled_failure(native, error, provisional)
    try:
        provisional = _native_outcome(native, native_result)
    except _ContractViolation:
        return _uncertain()
    if provisional.reason == "none":
        expected = ("unchanged", "not_created") if all(item is None for item in plan._payloads) else ("committed", "clean")
        if (provisional.effect, provisional.journal) != expected:
            return _uncertain(provisional)
    return provisional


def discard_config_edit(authority: ConfigCheckout | PreparedConfigEdit) -> None:
    """Idempotently retire authentic in-memory authority; perform no cleanup IO."""
    if _authentic_checkout(authority):
        checkout = authority
    elif _authentic_plan(authority):
        checkout = authority._checkout
    else:
        _reject("invalid_params")
    object.__setattr__(checkout, "_state", _RETIRED)
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", _RETIRED)
