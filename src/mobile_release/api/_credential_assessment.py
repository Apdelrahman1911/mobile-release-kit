"""Finite policy over supplied scalars and mechanical file assertions only.

No selected file, credential reader, native parser, keyring, process or service
is used. A fabricated observation cannot establish source custody. The private
Rust adapter must rebuild the result before any future, separately gated route;
document/selection binding and native observation ownership are not implemented
by this pure service. Secret copies are not promised to be erased on return.
"""
from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, NoReturn, cast

from ..config import MAX_CONFIG_BYTES, ReleaseConfig, parse_config_text
from ..credential_policy import (
    CREDENTIAL_POLICY_VERSION, credential_format_error,
    firebase_payload_shape_and_match, material_size_limit,
)
from ..credential_requirements import requirements
from ..errors import ConfigurationError
from ._credential_guide import _KIND_LAYOUT
from ._json import MAX_DEPTH, MAX_NODES, bounded_json_text
from .contracts import ApiError, CredentialAssessmentResult

MAX_PARAMS_BYTES = 1024 * 1024 - 1  # The transport additionally bounds its actual envelope/newline.
MAX_SCALAR_BYTES = 4096
MAX_SCALARS_BYTES = 65536
MAX_OBSERVATION_BYTES = 64 * 1024
MAX_OBSERVATION_NODES = 4096
MAX_OBSERVATION_DEPTH = 8
MAX_CLIENTS = 256
MAX_PROJECTED_STRING_BYTES = 1024
MAX_RESULT_BYTES = 16 * 1024

_ERRORS = {
    "assessment_invalid_request": "The assessment request has an unsupported shape or value type.",
    "assessment_limit": "The assessment request exceeds a supported interface bound.",
    "assessment_version": "This assessment schema version is unavailable.",
    "assessment_policy_stale": "Credential policy changed; prepare the context again.",
    "assessment_context_invalid": "The submitted draft is not valid for assessment.",
    "assessment_unavailable": "Credential assessment is unavailable; no credential was verified.",
}
_POLICY_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,64}\Z", re.ASCII)
_UNAVAILABLE_REASONS = (
    "not-run", "incomplete", "unsupported-format", "unsupported-variant", "material-limit", "parser-limit",
)
_REJECTED_SCOPES = {
    "empty-file": "file-nonempty", "suffix-conflict": "suffix-consistency", "malformed-container": "container-parse",
}
# These are the version-one observation union, not a requiredness/help table.
_FORMATS = {
    "android-keystore": ("jks", "pkcs12"), "android-firebase": ("firebase-json",),
    "apple-p12": ("pkcs12",), "apple-profile": ("cms-signed-data",),
    "asc-p8": ("pkcs8",), "ios-firebase": ("firebase-plist",),
}
_FORMAT_SCOPES = {
    "jks": "jks-header", "pkcs12": "pfx-envelope", "cms-signed-data": "cms-signed-data-envelope",
    "pkcs8": "pkcs8-envelope", "firebase-json": "json-document", "firebase-plist": "plist-document",
}
_FIREBASE_KINDS = ("android-firebase", "ios-firebase")


class _Refusal(Exception):
    """Only an internal constant code; never retains a rejected value/message."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(code: str = "assessment_invalid_request") -> NoReturn:
    raise _Refusal(code)


def _exact(value: object, keys: set[str]) -> dict[str, Any]:
    if (type(value) is not dict or len(value) != len(keys)
            or any(type(key) is not str for key in value) or set(value) != keys):
        _refuse()
    return cast(dict[str, Any], value)


def _enum(value: object, choices: tuple[str, ...]) -> str:
    if type(value) is not str or value not in choices:
        _refuse()
    return cast(str, value)


def _string_size(value: object, maximum: int) -> int:
    if type(value) is not str:
        _refuse()
    if len(value) > maximum:
        _refuse("assessment_limit")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        _refuse()
    if size > maximum:
        _refuse("assessment_limit")
    return size


def _json_text(value: object, *, max_bytes: int, max_nodes: int = MAX_NODES,
               max_depth: int = MAX_DEPTH) -> str:
    # Classify Python-only/non-UTF8/nonfinite values without inspecting a
    # ConfigurationError's potentially reflective message. The shared serializer
    # and final byte check enforce escaping, encoded size, depth and nodes.
    pending = [(value, 0)]
    nodes = 0
    containers = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        kind = type(current)
        if nodes > max_nodes or depth > max_depth or (kind in (dict, list) and depth >= max_depth):
            _refuse("assessment_limit")
        if kind is dict:
            containers += bool(current)
            if nodes + len(pending) + 2 * len(current) > max_nodes:
                _refuse("assessment_limit")
            for key, child in current.items():
                if type(key) is not str:
                    _refuse()
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif kind is list:
            containers += bool(current)
            if nodes + len(pending) + len(current) > max_nodes:
                _refuse("assessment_limit")
            pending.extend((child, depth + 1) for child in current)
        elif kind is str:
            _string_size(current, max_bytes)
        elif kind is float:
            if not math.isfinite(current):
                _refuse()
        elif current is not None and kind not in (int, bool):
            _refuse()
    try:
        # The shared serializer's preliminary counter conservatively reserves
        # one extra separator per nonempty container. Give only that bounded
        # headroom, then enforce the actual inclusive UTF-8 interface limit.
        # This leaves the existing helper/CLI untouched and avoids refusing an
        # otherwise valid exact-limit observation before actual serialization.
        raw = bounded_json_text(value, max_bytes=max_bytes + containers, max_nodes=max_nodes, max_depth=max_depth)
    except ConfigurationError:
        _refuse("assessment_limit")
    if len(raw.encode("utf-8")) > max_bytes:
        _refuse("assessment_limit")
    return raw


def _android_projection(value: object) -> None:
    document = _exact(value, {"root", "clients"})
    root = _enum(document["root"], ("object", "other"))
    clients = document["clients"]
    if root == "other" and clients is not None:
        _refuse()
    if clients is None:
        return
    if type(clients) is not list:
        _refuse()
    if len(clients) > MAX_CLIENTS:
        _refuse("assessment_limit")
    for client in clients:
        if client is None:
            continue
        client_info = _exact(client, {"clientInfo"})["clientInfo"]
        if client_info is None:
            continue
        android_info = _exact(client_info, {"androidClientInfo"})["androidClientInfo"]
        if android_info is None:
            continue
        name = _exact(android_info, {"packageName"})["packageName"]
        if name is not None:
            _string_size(name, MAX_PROJECTED_STRING_BYTES)


def _ios_projection(value: object) -> None:
    document = _exact(value, {"root", "bundleId"})
    root = _enum(document["root"], ("dictionary", "other"))
    name = document["bundleId"]
    if root == "other" and name is not None:
        _refuse()
    if name is not None:
        _string_size(name, MAX_PROJECTED_STRING_BYTES)


def _observation(value: object, kind: str, file_requirement: str | None) -> None:
    if value is None:
        return
    if file_requirement is None or type(value) is not dict:
        _refuse()
    status = _enum(value.get("status"), ("unavailable", "rejected", "observed"))
    if status != "observed":
        observation = _exact(value, {"status", "reason"})
        _enum(observation["reason"], _UNAVAILABLE_REASONS if status == "unavailable" else tuple(_REJECTED_SCOPES))
    else:
        format_name = _enum(value.get("format"), _FORMATS[kind])
        extra_keys = {
            "jks": {"version"}, "pkcs12": {"version", "authSafe"}, "cms-signed-data": {"encoding"},
            "pkcs8": {"encoding", "algorithm", "curve"}, "firebase-json": {"document"},
            "firebase-plist": {"encoding", "document"},
        }[format_name]
        observation = _exact(value, {"status", "byteCount", "format"} | extra_keys)
        count = observation["byteCount"]
        if type(count) is not int or count < 1:
            _refuse()
        if count > material_size_limit(file_requirement):
            _refuse("assessment_limit")
        if format_name in ("jks", "pkcs12"):
            version = observation["version"]
            if type(version) is not int or version not in ((1, 2) if format_name == "jks" else (3,)):
                _refuse()
            if format_name == "pkcs12":
                _enum(observation["authSafe"], ("data", "signed-data"))
        elif format_name == "cms-signed-data":
            _enum(observation["encoding"], ("der",))
        elif format_name == "pkcs8":
            _enum(observation["encoding"], ("pem", "der"))
            algorithm = _enum(observation["algorithm"], ("ec", "rsa", "other"))
            curve = observation["curve"]
            if curve is not None:
                _enum(curve, ("p256", "other"))
            if algorithm != "ec" and curve is not None:
                _refuse()
        elif format_name == "firebase-json":
            _android_projection(observation["document"])
        else:
            _enum(observation["encoding"], ("xml", "binary"))
            _ios_projection(observation["document"])
    _json_text(value, max_bytes=MAX_OBSERVATION_BYTES, max_nodes=MAX_OBSERVATION_NODES,
               max_depth=MAX_OBSERVATION_DEPTH)


def _applicability(config: ReleaseConfig, kind_platform: str, platform: str, stage: str,
                   purpose: str, names: set[str]) -> dict[str, str]:
    if platform != kind_platform:
        reason = "wrong-platform"
    elif platform != "project" and not config.platform_enabled(platform):
        reason = "platform-disabled"
    else:
        selected = {item.name for item in requirements(
            config, stage, purpose=purpose, platforms=() if platform == "project" else (platform,),
        )} & names
        if selected and selected != names:
            _refuse("assessment_unavailable")
        reason = "selected" if selected else "not-required"
    return {"state": "required" if reason == "selected" else "not-applicable", "reason": reason}


def _check(scope: str, outcome: str) -> dict[str, str]:
    return {"scope": scope, "outcome": outcome}


def _scalar_result(value: str | None, name: str, input_kind: str) -> tuple[str, list[str], list[dict[str, str]]]:
    if value is None or value == "":
        return "missing", ["required-missing"], []
    if "\x00" in value:
        return "invalid", ["value-nul"], [_check("value-admission", "failed")]
    checks = [_check("value-admission", "passed")]
    # Only these guide text fields have shared identifier rules. Passwords and
    # the project token receive value admission, never a password/permission test.
    if input_kind == "text":
        valid = credential_format_error(name, value) is None
        checks.append(_check("identifier-format", "passed" if valid else "failed"))
        if not valid:
            return "invalid", ["scalar-format"], checks
    return "configured", [], checks


def _firebase_payload(document: dict[str, Any], kind: str) -> object:
    if document["root"] == "other":
        return None
    if kind == "ios-firebase":
        return {"BUNDLE_ID": document["bundleId"]}
    clients = document["clients"]
    if clients is None:
        return {"client": None}
    result = []
    for client in clients:
        if client is None:
            result.append(None)
            continue
        info = client["clientInfo"]
        android = info["androidClientInfo"] if info is not None else None
        result.append({"client_info": None if info is None else {
            "android_client_info": None if android is None else {"package_name": android["packageName"]},
        }})
    return {"client": result}


def _file_result(observation: dict[str, Any] | None, kind: str, config: ReleaseConfig,
                 platform: str) -> tuple[str, list[str], list[dict[str, str]], str]:
    identity = "not-assessed" if kind in _FIREBASE_KINDS else "not-applicable"
    if observation is None:
        return "missing", ["required-missing"], [], identity
    status = observation["status"]
    if status == "unavailable":
        return "unknown", [observation["reason"]], [], identity
    if status == "rejected":
        reason = observation["reason"]
        return "invalid", [reason], [_check(_REJECTED_SCOPES[reason], "asserted-fail")], identity
    checks = [_check(_FORMAT_SCOPES[observation["format"]], "asserted-pass")]
    if kind == "asc-p8":
        valid = observation["algorithm"] == "ec" and observation["curve"] == "p256"
        checks.append(_check("ec-p256-identifiers", "passed" if valid else "failed"))
        return ("configured" if valid else "invalid"), ([] if valid else ["pkcs8-algorithm"]), checks, identity
    if kind in _FIREBASE_KINDS:
        shape, match = firebase_payload_shape_and_match(
            _firebase_payload(observation["document"], kind), platform=platform,
            expected_identity=config.section(platform).get("applicationId" if platform == "android" else "bundleId"),
        )
        checks.append(_check("firebase-shape", "passed" if shape else "failed"))
        if not shape:
            return "invalid", ["firebase-shape"], checks, "not-assessed"
        checks.append(_check("application-identity", "passed" if match else "failed"))
        return ("format-valid" if match else "invalid"), ([] if match else ["identity-mismatch"]), checks, ("match" if match else "mismatch")
    # File recognition is independent of missing/invalid scalar companions. It
    # does not test a password, key usability, certificate trust or native scope.
    return "configured", [], checks, identity


def _assess(params: object) -> CredentialAssessmentResult:
    request = _exact(params, {"schemaVersion", "policyVersion", "context", "input"})
    policy = request["policyVersion"]
    if type(policy) is not str or _POLICY_TOKEN.fullmatch(policy) is None:
        _refuse()
    if policy != CREDENTIAL_POLICY_VERSION:
        _refuse("assessment_policy_stale")
    version = request["schemaVersion"]
    if type(version) is not int:
        _refuse()
    if version != 1:
        _refuse("assessment_version")
    context = _exact(request["context"], {"draft", "platform", "stage", "purpose"})
    platform = _enum(context["platform"], ("android", "ios", "project"))
    stage = _enum(context["stage"], ("candidate", "external-testing", "production"))
    purpose = _enum(context["purpose"], ("full", "signing", "store"))
    if type(context["draft"]) is not dict:
        _refuse()
    supplied = _exact(request["input"], {"kind", "fields", "observation"})
    kind = _enum(supplied["kind"], tuple(_KIND_LAYOUT))
    kind_platform, layout = _KIND_LAYOUT[kind]
    scalar_fields = _exact(supplied["fields"], {field_id for field_id, _, input_kind, _ in layout if input_kind != "file"})
    scalar_bytes = 0
    for value in scalar_fields.values():
        if value is not None:
            scalar_bytes += _string_size(value, MAX_SCALAR_BYTES)
        if scalar_bytes > MAX_SCALARS_BYTES:
            _refuse("assessment_limit")
    file_name = "MOBILE_RELEASE_" + layout[0][1] if layout[0][2] == "file" else None
    _observation(supplied["observation"], kind, file_name)
    _json_text(params, max_bytes=MAX_PARAMS_BYTES)
    raw_draft = _json_text(context["draft"], max_bytes=MAX_CONFIG_BYTES)
    try:
        data = parse_config_text(raw_draft)
    except ConfigurationError:
        _refuse("assessment_context_invalid")
    # ReleaseConfig is a data wrapper here, as in the passive catalogue. Its
    # project_path/release_version/filesystem methods are never invoked.
    config = ReleaseConfig(path=Path("release/mobile-release.json"), root=Path("."), data=data)
    applicability = _applicability(config, kind_platform, platform, stage, purpose,
                                   {"MOBILE_RELEASE_" + suffix for _, suffix, _, _ in layout})
    identity = "not-assessed" if kind in _FIREBASE_KINDS else "not-applicable"
    fields = []
    for field_id, suffix, input_kind, _ in layout:
        value = supplied["observation"] if input_kind == "file" else scalar_fields[field_id]
        name = "MOBILE_RELEASE_" + suffix
        presence = "missing" if value is None or (input_kind != "file" and value == "") else "supplied"
        if applicability["state"] == "not-applicable":
            state, issues, checks = "not-applicable", [], []
        elif input_kind == "file":
            state, issues, checks, identity = _file_result(value, kind, config, platform)
        else:
            state, issues, checks = _scalar_result(value, name, input_kind)
        fields.append({"id": field_id, "requirement": name, "presence": presence,
                       "state": state, "issues": issues, "checks": checks})
    if applicability["state"] == "not-applicable":
        state = "not-applicable"
    else:
        states = {field["state"] for field in fields}
        state = next((candidate for candidate in ("invalid", "missing", "unknown") if candidate in states),
                     "format-valid" if kind in _FIREBASE_KINDS else "configured")
    result = {
        "schemaVersion": 1, "policyVersion": CREDENTIAL_POLICY_VERSION, "kind": kind,
        "context": {"platform": platform, "stage": stage, "purpose": purpose},
        "applicability": applicability, "state": state, "fields": fields, "identity": identity,
        "assurance": {
            "basis": "supplied-input-only", "scalarValuesProcessed": any(value is not None for value in scalar_fields.values()),
            "fileObservationsProcessed": supplied["observation"] is not None,
            "selectedFilesRead": False, "keyringAccessed": False, "storageWritesPerformed": False,
            "projectCodeExecuted": False, "sourceCustody": "not-established", "nativeValidation": "not-run",
            "serviceValidation": "not-run", "releaseReadiness": "unknown",
        },
    }
    try:
        _json_text(result, max_bytes=MAX_RESULT_BYTES)
    except _Refusal:
        _refuse("assessment_unavailable")
    return cast(CredentialAssessmentResult, result)


def assess_credentials(params: object) -> CredentialAssessmentResult:
    """Admit independently; no reflective validation result or raw exception escapes."""
    try:
        return _assess(params)
    except _Refusal as refusal:
        raise ApiError(refusal.code, _ERRORS[refusal.code]) from None
    except Exception:
        # Unexpected failures follow the engine's constant transport-failure
        # path, not its arbitrary ApiError-message forwarding path. Direct pure
        # callers likewise receive no dependency exception/config/parser detail.
        raise RuntimeError("Unexpected credential assessment failure.") from None
