"""Fixed nonsecret environment-variable DATA; no network or consent authority.

The genuine Setup owner must supply the current assigned field/configuration,
pre-admit the bounded representations, and retain its original deadline, loan,
response/capture quotas and cleanup. These objects cannot establish that custody.
No existing Initial/GO dispatcher or live reader factory is extended here.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from . import github_setup_remote as _setup
from ._desktop_github_engine import _check_control, _check_values
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _account, _coordinate, _read, _utc
from .config import ReleaseConfig
from .credential_policy import credential_format_error
from .credential_requirements import ENVIRONMENT_NAMES, requirements
from .github_preflight import HttpRequest, Reader, _DIGEST, _MARKER, _match, _object, _require

API_VERSION = _setup.API_VERSION
MAX_REQUESTS = 8
MAX_VALUE_BYTES = 4096
MAX_REMOTE_VALUE_BYTES = 48 * 1024
MAX_FACTS_BYTES = 2048
MAX_PREPARED_BYTES = 8 * 1024
MAX_BODY_BYTES = 8 * 1024
MAX_RESULT_BYTES = 64 * 1024
# Closed existing record/field mappings, not arbitrary field access or secrets.
VARIABLE_FIELDS = (
    ("MOBILE_RELEASE_ANDROID_KEY_ALIAS", "android-keystore", "keyAlias", "android"),
    ("MOBILE_RELEASE_GOOGLE_WIF_PROVIDER", "google-wif", "provider", "android"),
    ("MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT", "google-wif", "serviceAccount", "android"),
    ("MOBILE_RELEASE_ASC_KEY_ID", "asc-p8", "keyId", "ios"),
    ("MOBILE_RELEASE_ASC_ISSUER_ID", "asc-p8", "issuerId", "ios"),
)
REASONS = _setup.REASONS | frozenset({
    "variable-exists", "variable-missing", "variable-changed", "material-too-large",
    "material-changed", "configuration-changed", "requirement-unsupported", "resources-unavailable",
})
CONFIRMATION = (
    "Send this exact required variable to GitHub? Variables are not secrets and can be read by permitted "
    "GitHub users and workflows. This action uses the selected assigned field. There is no atomic "
    "compare-and-set: another actor can change or delete the variable after these observations. Cancel "
    "does not undo a sent request. Readback confirms the observed value only; it does not prove a build "
    "or release works."
)


class VariableRefused(ValueError):
    def __init__(self, reason: str) -> None:
        _require(type(reason) is str and reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The fixed nonsecret variable observation was refused")


def _same(condition: bool, reason: str) -> None:
    if not condition:
        raise VariableRefused(reason)


def _bounded(value: object, maximum: int) -> bytes:
    # Normalized bounded forms only. The containing owner precharges this
    # representation allowance; this actual encoding also counts JSON escaping.
    _check_values(value, nodes=1024, depth=12)
    raw = _setup._canonical(value)
    _require(len(raw) <= maximum)
    return raw


def _fingerprint(text: str) -> tuple[int, str]:
    raw = text.encode("utf-8", errors="strict")
    return len(raw), hashlib.sha256(raw).hexdigest()


def _desired(name: str, value: object) -> str:
    _require(type(value) is str)
    _same(0 < len(value) <= MAX_VALUE_BYTES, "material-too-large")
    _same(len(value.encode("utf-8", errors="strict")) <= MAX_VALUE_BYTES, "material-too-large")
    _same(credential_format_error(name, value) is None, "requirement-unsupported")
    return value


def _binding(value: object) -> tuple[int, str, int, str]:
    row = _object(value, {"savedConfig", "canonicalConfig"})
    fields: list[Any] = []
    for key in ("savedConfig", "canonicalConfig"):
        leaf = _object(row[key], {"bytes", "sha256"})
        _require(type(leaf["bytes"]) is int and 1 <= leaf["bytes"] <= 524288)
        fields.extend((leaf["bytes"], _match(leaf["sha256"], _DIGEST)))
    return tuple(fields)  # type: ignore[return-value]


def _binding_value(value: tuple[int, str, int, str]) -> dict[str, Any]:
    return {"savedConfig": {"bytes": value[0], "sha256": value[1]},
            "canonicalConfig": {"bytes": value[2], "sha256": value[3]}}


@dataclass(frozen=True, slots=True)
class VariableSelection:
    mode: str
    stage: str
    requirement: str
    record_id: str
    record_revision: int
    context_revision: int

    @classmethod
    def parse(cls, value: object) -> VariableSelection:
        row = _object(value, {"kind", "mode", "stage", "requirement", "source"})
        _require(row["kind"] == "environment_variable" and type(row["mode"]) is str
                 and row["mode"] in {"create", "replace"} and type(row["stage"]) is str
                 and row["stage"] in ENVIRONMENT_NAMES and type(row["requirement"]) is str
                 and row["requirement"] in {r[0] for r in VARIABLE_FIELDS})
        source = _object(row["source"], {"recordId", "recordRevision", "contextRevision"})
        marker = _match(source["recordId"], _MARKER)
        for key in ("recordRevision", "contextRevision"):
            _require(type(source[key]) is int and 0 <= source[key] <= 2**32 - 1)
        return cls(row["mode"], row["stage"], row["requirement"], marker,
                   source["recordRevision"], source["contextRevision"])

    @property
    def mapping(self) -> tuple[str, str, str]:
        return next(row[1:] for row in VARIABLE_FIELDS if row[0] == self.requirement)

    @property
    def environment(self) -> str:
        return ENVIRONMENT_NAMES[self.stage]

    def value(self) -> dict[str, Any]:
        return {"kind": "environment_variable", "mode": self.mode, "stage": self.stage,
                "requirement": self.requirement, "source": {"recordId": self.record_id,
                "recordRevision": self.record_revision, "contextRevision": self.context_revision}}


def require_variable(config: ReleaseConfig, selection: VariableSelection, *, purpose: str) -> None:
    """Shared requiredness policy only; no constructed config/source grants custody."""
    _require(type(config) is ReleaseConfig)
    selected = VariableSelection.parse(selection.value())
    _require(type(purpose) is str and purpose in {"full", "signing", "store"})
    platform = selected.mapping[2]
    matches = [r for r in requirements(config, selected.stage, purpose=purpose, platforms=(platform,))
               if r.kind == "variable" and r.name == selected.requirement
               and r.stage == selected.stage and r.platform == platform]
    _same(len(matches) == 1, "requirement-unsupported")


@dataclass(frozen=True, slots=True)
class VariableTarget:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str
    selection: VariableSelection

    @classmethod
    def parse(cls, value: object) -> VariableTarget:
        row = _object(value, {"projectBinding", "repository", "accountId", "repositoryId", "selection"})
        return cls(_match(row["projectBinding"], _DIGEST), _coordinate(row["repository"]),
                   _setup._environment_id(row["accountId"]), _setup._environment_id(row["repositoryId"]),
                   VariableSelection.parse(row["selection"]))

    def value(self) -> dict[str, Any]:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id,
                "selection": self.selection.value()}


@dataclass(frozen=True, slots=True)
class VariableFacts:
    environment_name: str
    environment_id: str
    name: str
    fingerprint: tuple[int, str] | None
    metadata: tuple[str, str] | None

    @classmethod
    def parse(cls, value: object) -> VariableFacts:
        row = _object(value, {"environmentName", "environmentId", "name", "value", "metadata"})
        _require(type(row["environmentName"]) is str and row["environmentName"] in ENVIRONMENT_NAMES.values()
                 and type(row["name"]) is str and row["name"] in {r[0] for r in VARIABLE_FIELDS})
        identity = _setup._environment_id(row["environmentId"])
        _require((row["value"] is None) == (row["metadata"] is None))
        fingerprint = metadata = None
        if row["value"] is not None:
            v = _object(row["value"], {"bytes", "sha256"})
            _require(type(v["bytes"]) is int and 0 <= v["bytes"] <= MAX_REMOTE_VALUE_BYTES)
            fingerprint = (v["bytes"], _match(v["sha256"], _DIGEST))
            if not v["bytes"]:
                _require(fingerprint == _fingerprint(""))
            m = _object(row["metadata"], {"createdAt", "updatedAt"})
            metadata = (_utc(m["createdAt"]), _utc(m["updatedAt"]))
        result = cls(row["environmentName"], identity, row["name"], fingerprint, metadata)
        _bounded(result.value(), MAX_FACTS_BYTES)
        return result

    @classmethod
    def from_upstream(cls, selected: VariableSelection, environment_id: str,
                      body: object) -> tuple[VariableFacts, str | None]:
        # Raw value is an ephemeral comparison input, never a Facts field.
        fingerprint = metadata = text = None
        if body is not None:
            row = _object(body, {"name", "value", "created_at", "updated_at"})
            _same(type(row["name"]) is str and row["name"] == selected.requirement, "variable-changed")
            _require(type(row["value"]) is str and len(row["value"]) <= MAX_REMOTE_VALUE_BYTES)
            text = row["value"]
            fingerprint = _fingerprint(text)
            _require(fingerprint[0] <= MAX_REMOTE_VALUE_BYTES)
            metadata = (_utc(row["created_at"]), _utc(row["updated_at"]))
        result = cls(selected.environment, environment_id, selected.requirement, fingerprint, metadata)
        return cls.parse(result.value()), text

    def value(self) -> dict[str, Any]:
        return {"environmentName": self.environment_name, "environmentId": self.environment_id, "name": self.name,
                "value": None if self.fingerprint is None else {"bytes": self.fingerprint[0], "sha256": self.fingerprint[1]},
                "metadata": None if self.metadata is None else {"createdAt": self.metadata[0], "updatedAt": self.metadata[1]}}


@dataclass(frozen=True, slots=True, repr=False)
class VariablePrepared:
    target: VariableTarget
    before: VariableFacts
    text: str
    configuration: tuple[int, str, int, str]
    observed_at: str

    @classmethod
    def parse(cls, value: object) -> VariablePrepared:
        row = _object(value, {"target", "before", "after", "configuration", "observedAt", "confirmation"})
        target = VariableTarget.parse(row["target"])
        before = VariableFacts.parse(row["before"])
        selected = target.selection
        _require(before.name == selected.requirement and before.environment_name == selected.environment
                 and (selected.mode == "create") == (before.fingerprint is None))
        after = _object(row["after"], {"name", "value"})
        v = _object(after["value"], {"text", "bytes", "sha256"})
        _require(after["name"] == selected.requirement)
        text = _desired(selected.requirement, v["text"])
        fingerprint = _fingerprint(text)
        _require(type(v["bytes"]) is int and v["bytes"] == fingerprint[0]
                 and _match(v["sha256"], _DIGEST) == fingerprint[1] and before.fingerprint != fingerprint)
        result = cls(target, before, text, _binding(row["configuration"]), _utc(row["observedAt"]))
        _require(row["confirmation"] == CONFIRMATION and row == result.value())
        _bounded(row, MAX_PREPARED_BYTES)
        return result

    def value(self) -> dict[str, Any]:
        size, digest = _fingerprint(self.text)
        return {"target": self.target.value(), "before": self.before.value(),
                "after": {"name": self.target.selection.requirement,
                          "value": {"text": self.text, "bytes": size, "sha256": digest}},
                "configuration": _binding_value(self.configuration), "observedAt": self.observed_at,
                "confirmation": CONFIRMATION}


@dataclass(frozen=True, slots=True, repr=False)
class VariableAction:
    kind: str
    target: VariableTarget
    prepared: VariablePrepared | None = None

    @classmethod
    def parse(cls, value: object) -> VariableAction:
        row = _object(value, {"kind", "target", "prepared"})
        _require(type(row["kind"]) is str and row["kind"] in {"prepare", "apply"})
        target = VariableTarget.parse(row["target"])
        prepared = None if row["prepared"] is None else VariablePrepared.parse(row["prepared"])
        _require((row["kind"] == "prepare") == (prepared is None)
                 and (prepared is None or prepared.target == target))
        return cls(row["kind"], target, prepared)

    def value(self) -> dict[str, Any]:
        return {"kind": self.kind, "target": self.target.value(),
                "prepared": None if self.prepared is None else self.prepared.value()}


def _write_body(selection: VariableSelection, text: str) -> bytes:
    value = {"value": _desired(selection.requirement, text)}
    if selection.mode == "create":
        value["name"] = selection.requirement
    return _bounded(value, MAX_BODY_BYTES)


class VariableSchedule:
    """Fixed DATA cursor, not an HTTP owner. Failed claims never restore steps."""
    def __init__(self, action: VariableAction) -> None:
        self.action = VariableAction.parse(action.value())
        self.steps: list[str] = []

    @property
    def expected(self) -> tuple[str, ...]:
        reads = ("account", "repository-before", "environment-before", "variable-before")
        return reads + (("environment-after", "repository-after") if self.action.kind == "prepare" else
                        ("write", "variable-after", "environment-after", "repository-after"))

    def claim(self, step: str, reference: str | None = None) -> HttpRequest:
        _require(reference is None and len(self.steps) < len(self.expected) <= MAX_REQUESTS
                 and step == self.expected[len(self.steps)])
        self.steps.append(step)
        if step == "account":
            return HttpRequest("GET", "/user", None)
        prefix = "/repos/" + self.action.target.repository
        if step.startswith("repository-"):
            return HttpRequest("GET", prefix, None)
        selected = self.action.target.selection
        prefix += "/environments/" + selected.environment
        if step.startswith("environment-"):
            return HttpRequest("GET", prefix, None)
        prefix += "/variables"
        if step == "write":
            _require(self.action.prepared is not None)
            body = _write_body(selected, self.action.prepared.text)
            if selected.mode == "create":
                return HttpRequest("POST", prefix, body)
            return HttpRequest("PATCH", prefix + "/" + selected.requirement, body)
        return HttpRequest("GET", prefix + "/" + selected.requirement, None)


def execute_variable(action: VariableAction, reader: Reader, *, value: str,
                     configuration: dict[str, Any], observed_at: str) -> dict[str, Any]:
    """Perform only the fixed DATA sequence using an already owned reader.

    No standalone reader is made here. Runtime/source/loan/close failures that
    are not the existing settled ReadFailure or malformed DATA propagate.
    """
    from .github_setup_secret_inputs import SecretConfigurationError
    action = VariableAction.parse(action.value())
    selected = action.target.selection
    text = _desired(selected.requirement, value)
    config = _binding(configuration)
    _utc(observed_at)
    _write_body(selected, text)  # Prospective exact payload before even read #1.
    if action.prepared is not None:
        _same(text == action.prepared.text, "material-changed")
        _same(config == action.prepared.configuration, "configuration-changed")
    result: dict[str, Any] = {"schemaVersion": 1, "action": action.kind, "reason": "none",
        "effect": "not-started", "writeClaimed": False, "writeAcknowledged": False,
        "prepared": None, "observed": None, "control": _control()}

    def take(step: str) -> dict[str, Any] | None:
        if step == "write":
            result["writeClaimed"], result["effect"] = True, "unknown"
        reply = reader.read(step)
        _require(type(reply) is ReadResult)
        result["control"] = dict(_check_control(reply.control))
        if result["control"]["reason"] != "none":
            raise VariableRefused(result["control"]["reason"])
        _check_values(reply.observation, nodes=20_000, depth=24)
        row = _object(reply.observation, {"status", "body", "failure"})
        if step == "write":
            expected = 201 if selected.mode == "create" else 204
            if type(row["status"]) is int and row["status"] == expected:
                _require(row["failure"] == "none")
                if expected == 201:
                    if row["body"] is not None:
                        _object(row["body"], set())
                else:
                    _require(row["body"] is None)
                result["writeAcknowledged"] = True
                return None
        if step == "variable-before" and type(row["status"]) is int and row["status"] == 404:
            _require(row["body"] is None and row["failure"] == "none")
            return None
        body, reason = _read(row)
        if step == "write" or body is None:
            raise VariableRefused(reason if reason != "none" else "response-invalid")
        return body

    def environment(step: str) -> str:
        body = take(step)
        _require(type(body) is dict and type(body.get("id")) is int and type(body.get("name")) is str)
        _same(body["name"] == selected.environment, "target-changed")
        return _setup._environment_id(body["id"], upstream=True)

    try:
        account = take("account")
        _require(account is not None and type(account.get("id")) is int)
        _same(_account(account)["id"] == action.target.account_id, "target-changed")
        _setup._identity(take("repository-before"), action.target)  # type: ignore[arg-type]
        identity = environment("environment-before")
        before, prior = VariableFacts.from_upstream(selected, identity, take("variable-before"))
        if selected.mode == "create":
            _same(prior is None, "variable-exists")
        else:
            _same(prior is not None, "variable-missing")
        same_value = prior == text
        prior = None  # Do not retain raw remote prior text through later calls.
        if action.kind == "prepare":
            _same(environment("environment-after") == identity, "target-changed")
            _setup._identity(take("repository-after"), action.target)  # type: ignore[arg-type]
            if same_value:
                result["reason"] = "no-change"
            else:
                prepared = VariablePrepared(action.target, before, text, config, observed_at)
                result["prepared"] = VariablePrepared.parse(prepared.value()).value()
            result["observed"] = before.value()
        else:
            _require(action.prepared is not None)
            _same(before == action.prepared.before, "variable-changed")
            take("write")
            after, actual = VariableFacts.from_upstream(selected, identity, take("variable-after"))
            _same(actual == text, "variable-changed")
            actual = None
            _same(environment("environment-after") == identity, "target-changed")
            _setup._identity(take("repository-after"), action.target)  # type: ignore[arg-type]
            result["observed"], result["effect"] = after.value(), "readback-confirmed"
    except SecretConfigurationError:
        # The SAME source context must finish its consuming closes and expose
        # cleanup_unknown; an original failure is never malformed HTTP DATA.
        raise
    except (VariableRefused, _setup.Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    return result


def encode_variable_result(action: VariableAction, value: object, *, desired_value: str,
                           configuration: dict[str, Any]) -> bytes:
    """Bind result DATA to the same private inputs, not a new frame/GO route."""
    action = VariableAction.parse(action.value())
    desired = _desired(action.target.selection.requirement, desired_value)
    config = _binding(configuration)
    if action.prepared is not None:
        _require(desired == action.prepared.text and config == action.prepared.configuration)
    row = _object(value, {"schemaVersion", "action", "reason", "effect", "writeClaimed",
                          "writeAcknowledged", "prepared", "observed", "control"})
    _require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
             and row["action"] == action.kind and type(row["reason"]) is str and row["reason"] in REASONS
             and type(row["writeClaimed"]) is bool and type(row["writeAcknowledged"]) is bool)
    control = _check_control(row["control"])
    _require(control["reason"] == "none" or row["reason"] == control["reason"])
    _require(not row["writeAcknowledged"] or row["writeClaimed"])
    observed = None if row["observed"] is None else VariableFacts.parse(row["observed"])
    selected = action.target.selection
    _require(observed is None or observed.name == selected.requirement
             and observed.environment_name == selected.environment)
    if action.kind == "prepare":
        _require(row["effect"] == "not-started" and not row["writeClaimed"] and not row["writeAcknowledged"]
                 and (row["reason"] == "none") == (row["prepared"] is not None)
                 and (row["reason"] in {"none", "no-change"}) == (observed is not None))
        if row["prepared"] is not None:
            prepared = VariablePrepared.parse(row["prepared"])
            _require(prepared.target == action.target and observed == prepared.before
                     and prepared.text == desired and prepared.configuration == config)
        if row["reason"] == "no-change":
            _require(selected.mode == "replace" and observed is not None
                     and observed.fingerprint == _fingerprint(desired))
    else:
        _require(row["prepared"] is None and row["reason"] != "no-change")
        if row["effect"] == "readback-confirmed":
            _require(row["reason"] == "none" and row["writeAcknowledged"] and action.prepared is not None
                     and observed is not None and observed.environment_id == action.prepared.before.environment_id
                     and observed.fingerprint == _fingerprint(action.prepared.text))
        else:
            _require(row["effect"] == ("unknown" if row["writeClaimed"] else "not-started")
                     and row["reason"] != "none" and observed is None)
    return _bounded(row, MAX_RESULT_BYTES)
