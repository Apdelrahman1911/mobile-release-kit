"""Closed artifact inspection context/result DATA; no owner or IO activation."""
from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass

from .artifact_inspection import GIB, KIB, MAX_NAMESPACE_ENTRIES, MAX_SELECTED_BYTES


PROTOCOL = "mrk-artifact-inspection/1"
SCOPE = "selected-artifact-bytes-only"
WORK_SECONDS, FINALITY_SECONDS = 900, 910
CONTEXT_LIMIT = 8 * KIB
RESULT_LIMIT = 16 * KIB
TRANSPORT_LIMIT = 64 * KIB
CHECKS = ("byte-identity", "structure", "manifest", "expected-identity", "expected-version",
          "signature", "profile-entitlements", "current-validity", "signer-policy", "archive-pair", "symbols")
LIMITATIONS = ("byte-observation-not-source-provenance", "current-signature-not-store-or-release-authority",
              "saved-inputs-not-unsaved-draft", "no-build-sign-upload-or-store-operation",
              "external-changes-can-make-results-stale")
FAIL_REASONS = {
    "byte-identity": (), "structure": ("unsupported-format", "input-limit", "malformed-structure"),
    "manifest": ("malformed-structure",), "expected-identity": ("identity-mismatch",),
    "expected-version": ("version-mismatch",), "signature": ("signature-invalid",),
    "profile-entitlements": ("profile-invalid",), "current-validity": ("signing-time-invalid",),
    "signer-policy": ("signer-mismatch",), "archive-pair": ("pair-mismatch",), "symbols": ("symbols-mismatch",),
}
UNAVAILABLE_REASONS = {
    "byte-identity": (), "structure": (),
    "manifest": ("tools-unavailable", "prerequisite-not-run"),
    "expected-identity": ("prerequisite-not-run",), "expected-version": ("prerequisite-not-run",),
    "signature": ("tools-unavailable", "prerequisite-not-run"),
    "profile-entitlements": ("tools-unavailable", "prerequisite-not-run"),
    "current-validity": ("tools-unavailable", "prerequisite-not-run"),
    "signer-policy": ("saved-policy-missing", "signer-unobserved", "prerequisite-not-run"),
    "archive-pair": ("archive-not-selected", "prerequisite-not-run"),
    "symbols": ("symbols-not-selected", "prerequisite-not-run"),
}
_IRRELEVANT_AAB = frozenset(("profile-entitlements", "archive-pair", "symbols"))
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PROJECT = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,64}\Z")


class ProtocolError(ValueError):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("artifact inspection protocol refused")


def integer(value: object, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _keys(value: object, expected: tuple[str, ...]) -> dict:
    require(type(value) is dict and len(value) == len(expected)
            and all(key in value for key in expected))
    return value


def _text(value: object, expression: re.Pattern, maximum: int) -> bool:
    return type(value) is str and len(value) <= maximum and expression.fullmatch(value) is not None


def _utf8(value: object, maximum: int, *, ascii_only: bool = False) -> bool:
    if type(value) is not str or not 0 < len(value) <= maximum:
        return False
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        return False
    try:
        return (not ascii_only or value.isascii()) and len(value.encode("utf-8", "strict")) <= maximum
    except UnicodeError:
        return False


def _encoded(value: dict, maximum: int) -> bytes:
    # Called only after the fixed depth/field/list/string validation below.
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    require(len(raw) <= maximum)
    return raw


def content(value: object, maximum: int = 512 * KIB) -> dict:
    value = _keys(value, ("bytes", "sha256"))
    require(integer(value["bytes"], maximum, 1) and _text(value["sha256"], _SHA, 64))
    return dict(value)


def selections(value: object, format: str) -> dict:
    value = _keys(value, ("artifact", "archive", "dsyms"))
    require(type(format) is str and format in ("aab", "ipa") and _text(value["artifact"], _TOKEN, 32))
    selected = [value["artifact"]]
    for role in ("archive", "dsyms"):
        token = value[role]
        require(token is None or _text(token, _TOKEN, 32))
        if token is not None:
            selected.append(token)
    require(len(set(selected)) == len(selected))
    require((format != "aab" or value["archive"] is value["dsyms"] is None)
            and (value["dsyms"] is None or value["archive"] is not None))
    return dict(value)


def context(value: object) -> dict:
    value = _keys(value, ("projectId", "draftRevision", "baselineGeneration", "savedConfig", "format", "selections"))
    require(_text(value["projectId"], _PROJECT, 64)
            and integer(value["draftRevision"], 2**32 - 2)
            and integer(value["baselineGeneration"], 2**32 - 2)
            and type(value["format"]) is str and value["format"] in ("aab", "ipa"))
    result = {**value, "savedConfig": content(value["savedConfig"]),
              "selections": selections(value["selections"], value["format"])}
    _encoded(result, CONTEXT_LIMIT)
    return result


def saved_version(value: object) -> dict:
    value = _keys(value, ("bytes", "sha256", "name", "build"))
    require(_text(value["name"], _VERSION, 64) and integer(value["build"], 2_100_000_000, 1))
    return {**content({"bytes": value["bytes"], "sha256": value["sha256"]}, 64 * KIB),
            "name": value["name"], "build": value["build"]}


def _artifact(value: object, role: str, format: str) -> dict:
    value = _keys(value, ("role", "selectionId", "label", "kind", "bytes", "entries", "identity"))
    require(type(value["role"]) is str and value["role"] == role and _text(value["selectionId"], _TOKEN, 32)
            and _utf8(value["label"], 255) and not any(char in value["label"] for char in "/\\")
            and type(value["kind"]) is str and value["kind"] in ("file", "directory"))
    require(role != "artifact" or value["kind"] == "file")
    maximum = MAX_SELECTED_BYTES if value["kind"] == "directory" else (GIB if format == "aab" else 4 * GIB)
    require(integer(value["bytes"], maximum)
            and integer(value["entries"], MAX_NAMESPACE_ENTRIES, 1)
            and (value["kind"] != "file" or value["entries"] == 1))
    identity = _keys(value["identity"], ("method", "sha256"))
    require(identity["method"] == ("sha256-file" if value["kind"] == "file" else "sha256-tree-v1")
            and _text(identity["sha256"], _SHA, 64))
    return {**value, "identity": dict(identity)}


def _observed(value: object, format: str) -> dict:
    value = _keys(value, ("applicationId", "bundleId", "versionName", "versionBuild", "signerSha256", "teamId"))
    for field, maximum, ascii_only in (("applicationId", 255, False), ("bundleId", 255, False),
                                      ("versionName", 256, False), ("versionBuild", 64, True), ("teamId", 128, True)):
        require(value[field] is None or _utf8(value[field], maximum, ascii_only=ascii_only))
    require(value["signerSha256"] is None or _text(value["signerSha256"], _SHA, 64))
    require(value["bundleId" if format == "aab" else "applicationId"] is None)
    require(format != "aab" or value["teamId"] is None)
    return dict(value)


def _checks(value: object, format: str, roles: tuple[str, ...]) -> list[dict]:
    require(type(value) is list and len(value) == len(CHECKS))
    result = []
    for check, row in zip(CHECKS, value):
        row = _keys(row, ("check", "status", "reason"))
        require(type(row["check"]) is str and row["check"] == check
                and type(row["status"]) is str and len(row["status"]) <= 14
                and type(row["reason"]) is str and len(row["reason"]) <= 32)
        status, reason = row["status"], row["reason"]
        if format == "aab" and check in _IRRELEVANT_AAB:
            require((status, reason) == ("not_applicable", "none"))
        elif format == "aab" and check == "current-validity":
            require((status, reason) == ("unavailable", "prerequisite-not-run"))
        elif format == "ipa" and check == "archive-pair" and "archive" not in roles:
            require((status, reason) == ("unavailable", "archive-not-selected"))
        elif format == "ipa" and check == "symbols" and "dsyms" not in roles:
            require((status, reason) == ("unavailable", "symbols-not-selected"))
        elif status == "pass":
            require(reason == "none")
        elif status == "fail":
            require(reason in FAIL_REASONS[check])
        elif status == "unavailable":
            require(reason in UNAVAILABLE_REASONS[check]
                    and reason not in ("archive-not-selected", "symbols-not-selected"))
        else:
            require(False)
        result.append(dict(row))
    return result


def validate_result(value: object, request_context: object | None = None) -> dict:
    """Validate producer DATA, not physical/signature/expected-policy authority."""
    value = _keys(value, ("schemaVersion", "scope", "format", "usedConfig", "usedVersion", "artifacts",
                         "observed", "checks", "limitations"))
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and type(value["scope"]) is str and value["scope"] == SCOPE
            and type(value["format"]) is str and value["format"] in ("aab", "ipa"))
    require(type(value["artifacts"]) is list and 1 <= len(value["artifacts"]) <= 3)
    format = value["format"]
    require(format != "aab" or len(value["artifacts"]) == 1)
    roles = ("artifact", "archive", "dsyms")[:len(value["artifacts"])]
    artifacts = [_artifact(row, role, format) for row, role in zip(value["artifacts"], roles)]
    require(len({row["selectionId"] for row in artifacts}) == len(artifacts)
            and sum(row["bytes"] for row in artifacts) <= MAX_SELECTED_BYTES)
    require(type(value["limitations"]) is list and len(value["limitations"]) == len(LIMITATIONS)
            and all(type(actual) is str and actual == expected for actual, expected in zip(value["limitations"], LIMITATIONS)))
    result = {"schemaVersion": 1, "scope": SCOPE, "format": format,
              "usedConfig": content(value["usedConfig"]), "usedVersion": saved_version(value["usedVersion"]),
              "artifacts": artifacts, "observed": _observed(value["observed"], format),
              "checks": _checks(value["checks"], format, roles), "limitations": list(LIMITATIONS)}
    require(artifacts[0]["bytes"] != 0 or result["checks"][1]["status"] == "fail")
    if request_context is not None:
        wanted = context(request_context)
        require(wanted["format"] == format and wanted["savedConfig"] == result["usedConfig"])
        selected = {role: None for role in ("artifact", "archive", "dsyms")}
        selected.update((row["role"], row["selectionId"]) for row in artifacts)
        require(selected == wanted["selections"])
    _encoded(result, RESULT_LIMIT)
    return result


# Fixed native-only transport. These are comparison records, never a caller's
# file descriptor, tool permission, effective budget or source observation.
REQUEST_LIMIT = 32 * KIB
RESPONSE_LIMIT = TRANSPORT_LIMIT
PROFILES = frozenset(("macos-arm64", "macos-x86_64"))
OUTCOMES = frozenset(("complete", "refused", "cancelled", "timed-out", "failed", "unknown"))
REASONS = frozenset(("none", "cancelled", "context-changed", "document-lost", "shutdown", "timed-out",
    "protocol-error", "runtime-unavailable", "intent-expired", "stale-intent", "saved-config-missing",
    "saved-config-invalid", "saved-config-changed", "saved-config-sensitive", "saved-config-unsafe",
    "saved-config-too-large", "platform-disabled", "project-admission-refused", "input-limit", "result-limit",
    "command-incomplete", "cleanup-unknown", "saved-version-missing", "saved-version-invalid",
    "saved-version-changed", "saved-version-unsafe", "saved-version-too-large", "selection-missing",
    "selection-changed", "selection-unsafe", "toolchain-unavailable", "toolchain-mismatch", "resources-unavailable"))
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
_SIGNED = re.compile(r"(?:0|-?[1-9][0-9]{0,18})\Z")


def _path(value: object) -> str:
    from ._desktop_preflight_protocol import _path as saved_path
    require(_utf8(value, 4096))
    try:
        return saved_path(value)
    except ValueError:
        raise ProtocolError("artifact inspection path refused") from None


def root_identity(value: object) -> dict:
    value = _keys(value, ("device", "inode", "mode", "uid", "gid"))
    require(all(_text(value[key], _DECIMAL, 20) and int(value[key]) <= 2**64 - 1
                for key in ("device", "inode")) and value["inode"] != "0"
            and all(integer(value[key], 2**32 - 1) for key in ("mode", "uid", "gid"))
            and stat.S_ISDIR(value["mode"]))
    return dict(value)


def original_identity(value: object, kind: str) -> dict:
    value = _keys(value, ("device", "inode", "mode", "uid", "gid", "nlink", "bytes",
                          "mtimeSeconds", "mtimeNanos", "ctimeSeconds", "ctimeNanos", "flags"))
    require(all(_text(value[key], _DECIMAL, 20) and int(value[key]) <= 2**64 - 1
                for key in ("device", "inode", "nlink", "bytes"))
            and value["inode"] != "0" and value["nlink"] != "0")
    require(all(_text(value[key], _SIGNED, 20) and -(2**63) <= int(value[key]) < 2**63
                for key in ("mtimeSeconds", "ctimeSeconds"))
            and all(integer(value[key], 999_999_999) for key in ("mtimeNanos", "ctimeNanos"))
            and all(integer(value[key], 2**32 - 1) for key in ("mode", "uid", "gid", "flags")))
    require((kind == "file" and stat.S_ISREG(value["mode"]) and value["nlink"] == "1")
            or (kind == "directory" and stat.S_ISDIR(value["mode"])))
    return dict(value)


def native(value: object, wanted: dict) -> dict:
    value = _keys(value, ("profile", "projectRoot", "rootIdentity", "cwd", "originals", "tools",
                          "parentDescriptorReservation"))
    require(type(value["profile"]) is str and value["profile"] in PROFILES
            and integer(value["parentDescriptorReservation"], 192)
            and type(value["originals"]) is list and 1 <= len(value["originals"]) <= 3)
    originals = []
    selected = wanted["selections"]
    for role, row in zip(("artifact", "archive", "dsyms"), value["originals"]):
        row = _keys(row, ("selectionId", "role", "path", "kind", "identity"))
        require(type(row["role"]) is str and row["role"] == role
                and _text(row["selectionId"], _TOKEN, 32) and row["selectionId"] == selected[role]
                and type(row["kind"]) is str and row["kind"] in ("file", "directory")
                and (role != "artifact" or row["kind"] == "file"))
        path = _path(row["path"])
        label = path.rsplit("/", 1)[-1]
        require(_utf8(label, 255) and label not in (".", "..") and not any(c in label for c in "/\\"))
        originals.append({**row, "path": path, "identity": original_identity(row["identity"], row["kind"])})
    require(len(originals) == sum(token is not None for token in selected.values()))
    tools = _keys(value["tools"], ("android", "ios"))
    require(tools["ios"] is None or type(tools["ios"]) is str and tools["ios"] == "macos-artifact-ios-system-v1")
    if tools["android"] is not None:
        from .android_build_tools_macos import binding
        try:
            binding(tools["android"])  # Existing full registered Mac binding parser.
        except ValueError:
            raise ProtocolError("artifact inspection tool binding refused") from None
    require((wanted["format"] == "aab" and tools["ios"] is None)
            or (wanted["format"] == "ipa" and tools["android"] is None))
    return {**value, "projectRoot": _path(value["projectRoot"]), "cwd": _path(value["cwd"]),
            "rootIdentity": root_identity(value["rootIdentity"]), "originals": originals, "tools": dict(tools)}


@dataclass(frozen=True)
class ArtifactInspectionRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict


def parse_request(raw: bytes) -> ArtifactInspectionRequest:
    require(type(raw) is bytes and 1 <= len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n")
            and raw.count(b"\n") == 1 and not raw.startswith(b"\xef\xbb\xbf"))
    from ._desktop_preflight_protocol import _pairs, _structure
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: require(False))
        _structure(value)
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("artifact inspection request refused") from None
    value = _keys(value, ("protocol", "operationId", "ownerGeneration", "context", "native"))
    require(type(value["protocol"]) is str and value["protocol"] == PROTOCOL
            and _text(value["operationId"], _TOKEN, 32) and _text(value["ownerGeneration"], _TOKEN, 32))
    wanted = context(value["context"])
    return ArtifactInspectionRequest(value["operationId"], value["ownerGeneration"], wanted,
                                     native(value["native"], wanted))


def validate_terminal(value: object, request: ArtifactInspectionRequest) -> None:
    value = _keys(value, ("schemaVersion", "context", "outcome", "reason", "result", "lifetime"))
    require(type(request) is ArtifactInspectionRequest and type(value["schemaVersion"]) is int
            and value["schemaVersion"] == 1 and context(value["context"]) == request.context
            and type(value["outcome"]) is str and value["outcome"] in OUTCOMES
            and type(value["reason"]) is str and value["reason"] in REASONS)
    life = _keys(value["lifetime"], ("complete", "fatal", "contained", "commandDispatched", "commands", "profileCalls",
                                     "inputClosed", "handlersRestored", "invocationClosed", "stopObserved"))
    require(all(type(life[key]) is bool for key in ("complete", "fatal", "contained", "inputClosed",
                                                  "handlersRestored", "invocationClosed"))
            and (life["commandDispatched"] is None or type(life["commandDispatched"]) is bool)
            and integer(life["commands"], 4096) and integer(life["profileCalls"], 128)
            and type(life["stopObserved"]) is str and life["stopObserved"] in ("none", "cancelled", "timed-out"))
    settled = (life["complete"] and not life["fatal"] and life["contained"] and life["inputClosed"]
               and life["handlersRestored"] and life["invocationClosed"] and life["commandDispatched"] is not None)
    if value["outcome"] == "complete":
        require(settled and life["stopObserved"] == "none" and value["reason"] == "none")
        validate_result(value["result"], request.context)
    else:
        require(value["result"] is None and value["reason"] != "none" and (settled or value["outcome"] == "unknown"))
        if value["outcome"] == "unknown":
            require(value["reason"] == "cleanup-unknown" and not settled)
        if value["outcome"] in ("cancelled", "timed-out"):
            require(value["reason"] == value["outcome"] == life["stopObserved"])


def response(request: ArtifactInspectionRequest, kind: str, payload: dict) -> bytes:
    require(type(request) is ArtifactInspectionRequest and type(kind) is str and kind in ("accepted", "terminal"))
    if kind == "accepted":
        require(type(payload) is dict and type(payload.get("schemaVersion")) is int
                and payload == {"schemaVersion": 1, "context": request.context})
    else:
        validate_terminal(payload, request)
    frame = {"protocol": PROTOCOL, "operationId": request.operation_id, "ownerGeneration": request.owner_generation,
             "sequence": 0 if kind == "accepted" else 1, "kind": kind, "payload": payload}
    raw = _encoded(frame, RESPONSE_LIMIT - 1) + b"\n"
    if kind == "terminal":
        accepted = response(request, "accepted", {"schemaVersion": 1, "context": request.context})
        require(len(accepted) + len(raw) <= RESPONSE_LIMIT)
    return raw
