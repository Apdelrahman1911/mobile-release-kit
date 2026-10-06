"""Closed DATA for owned iOS archive/export/inspection and local recovery.

This wire cannot select a program, upload or grant native custody.
The renderer's comparisons are not file authority; terminal DATA remains
provisional until the original native/document owners have joined.
"""
from __future__ import annotations

import re
import stat
from dataclasses import dataclass

# Reuse the already bounded, no-float DATA codec. Importing these pure helpers
# does not admit an Android operation or lend its runtime/tool/file owners.
from ._desktop_android_build_protocol import (
    ProtocolError, _decode, _encode, _enum, _identity, _keys, _path, _structure,
    _text, _TOKEN, _PROJECT, _DECIMAL, content, integer, saved_version,
)

PROTOCOL = "mrk-ios-archive/1"
CONSENT = "saved-ios-unsigned-archive-v1"
SCOPE = "local-unsigned-ios-archive-observation"
SIGNED_PROTOCOL = "mrk-ios-archive/2"
SIGNED_CONSENT = "saved-ios-signed-export-v2"
SIGNED_SCOPE = "local-signed-ios-artifact-validation"
TOOLCHAIN_PROFILE = "ios-full-xcode-macos-arm64-v1"
X64_TOOLCHAIN_PROFILE = "ios-full-xcode-macos-x86_64-v1"
TOOLCHAIN_PROFILES = {"macos-arm64": TOOLCHAIN_PROFILE, "macos-x86_64": X64_TOOLCHAIN_PROFILE}
PROFILES = {"macos-arm64": ("macos", "arm64"), "macos-x86_64": ("macos", "x86_64")}
RENDERER_REQUEST_LIMIT, REQUEST_LIMIT, RESPONSE_LIMIT = 8 * 1024, 32 * 1024, 64 * 1024
INTENT_SECONDS, WORK_SECONDS, FINALITY_SECONDS = 300, 90 * 60, 90 * 60 + 10
SIGNED_CLEANUP_SECONDS, SIGNED_FINALITY_SECONDS = 5520, 5530
SIGNED_COMMAND_LIMIT, SIGNED_PROFILE_LIMIT = 4096, 1024
STAGES = ("inputs-bound", "checking-xcode", "preparing", "archiving", "inspecting", "disposing-snapshot", "disposing-work")
SIGNED_STAGES = ("inputs-bound", "checking-xcode", "validating-signing", "materializing-signing", "preparing", "archiving",
                 "exporting", "restoring-signing", "inspecting", "disposing-snapshot", "disposing-work")
MAX_FRAMES = len(STAGES) + 2
ROLES = ("xcode-version", "ios-sdk", "prepare", "archive")
SIGNED_ROLES = (*ROLES, "export")
STATUSES = ("PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE")
CHECKS = ("archive-identity", "archive-dsym", "archive-structure", "other-core-finding")
SIGNED_CHECKS = (*CHECKS, "signing-material", "profile-material", "firebase-material", "artifact-correspondence",
                 "ipa-structure", "ipa-profile", "ipa-entitlements", "ipa-signer", "ipa-validation", "symbols-upload")
OUTCOMES = ("complete", "refused", "failed", "cancelled", "timed-out", "unknown")
REASONS = frozenset(("none", "cancelled", "context-changed", "document-lost", "shutdown", "timed-out",
    "protocol-error", "runtime-unavailable", "intent-expired", "stale-intent", "platform-disabled",
    "container-required", "scheme-required", "container-missing", "toolchain-unavailable", "toolchain-mismatch",
    "project-admission-refused", "command-failed", "command-incomplete", "artifact-missing", "artifact-unsafe",
    "artifact-changed", "archive-validation-failed", "input-limit", "result-limit", "work-retained", "cleanup-unknown",
    "signing-policy-required", "signing-input-missing", "signing-input-invalid", "signing-validation-failed",
    "account-admission-refused", "artifact-validation-failed", "symbols-upload-not-requested", "recovery-attention",
    *(f"saved-{kind}-{reason}" for kind in ("config", "version")
      for reason in ("missing", "invalid", "changed", "sensitive", "unsafe", "too-large"))))
LIMITATIONS = ("saved-inputs-not-atomic", "project-build-code-is-trusted", "not-network-isolated",
    "unsigned-archive-not-an-ipa", "signing-and-profile-not-validated", "ipa-correspondence-not-validated",
    "source-provenance-not-authenticated", "store-operation-not-requested", "release-readiness-not-assessed",
    "retained-location-not-current-file-authority", "core-terminal-requires-original-native-finality")
SIGNED_LIMITATIONS = ("saved-inputs-not-atomic", "project-build-code-is-trusted", "not-network-isolated",
    "single-primary-profile", "source-provenance-not-authenticated", "store-operation-not-requested",
    "release-readiness-not-assessed", "retained-location-not-current-file-authority",
    "core-terminal-requires-original-native-finality")
_PREPARE = {"projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion"}
CLOSE_FIELDS = ("inputClosed", "handlersRestored", "invocationClosed", "snapshotClosed", "filesClosed", "namespaceClosed")
SIGNED_CLOSE_FIELDS = (*CLOSE_FIELDS, "signingClosed", "buildInputsClosed", "materialRetired")


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("Invalid saved iOS archive protocol")


def prepare(value: object) -> dict:
    if type(value) is dict and "recovery" in value:
        from ._desktop_ios_recovery_protocol import prepare as recovery_prepare
        return recovery_prepare(value)
    signed = type(value) is dict and "signing" in value
    value = _keys(value, _PREPARE | ({"signing"} if signed else set()))
    require(_text(value["projectId"], _PROJECT) and integer(value["draftRevision"], 2**32 - 2)
            and integer(value["baselineGeneration"], 2**32 - 2))
    result = {**value, "savedConfig": content(value["savedConfig"]), "savedVersion": saved_version(value["savedVersion"])}
    if signed:
        result["signing"] = signing_context(value["signing"])
    require(len(_encode(result)) <= RENDERER_REQUEST_LIMIT)
    return result


def parse_prepare(raw: bytes) -> dict:
    return prepare(_decode(raw, RENDERER_REQUEST_LIMIT, framed=False))


def context(value: object) -> dict:
    if type(value) is dict and "recovery" in value:
        from ._desktop_ios_recovery_protocol import context as recovery_context
        return recovery_context(value)
    signed = type(value) is dict and "signing" in value
    fields = _PREPARE | ({"signing"} if signed else set())
    value = _keys(value, fields | {"platform", "operation"})
    operation = "ios-signed-export" if signed else "ios-unsigned-archive"
    require(value["platform"] == "ios" and value["operation"] == operation)
    return {**prepare({key: value[key] for key in fields}), "platform": "ios", "operation": operation}


def signing_context(value: object) -> dict:
    value = _keys(value, {"teamId", "distributionCertificateSha256", "assignments"})
    require(_text(value["teamId"], re.compile(r"[A-Z0-9]{10}"))
            and _text(value["distributionCertificateSha256"], re.compile(r"[0-9a-f]{64}")))
    rows = value["assignments"]
    require(type(rows) is list and 2 <= len(rows) <= 4)
    kinds = []
    for row in rows:
        _keys(row, {"kind", "recordId", "recordRevision", "contextRevision"})
        require(_text(row["recordId"], _TOKEN) and integer(row["recordRevision"], 2**32 - 2, 1)
                and integer(row["contextRevision"], 2**32 - 2, 1))
        kinds.append(row["kind"])
    require(kinds[:2] == ["apple-p12", "apple-profile"]
            and kinds[2:] in ([], ["ios-firebase"], ["project-read-token"], ["ios-firebase", "project-read-token"])
            and len({row["recordId"] for row in rows}) == len(rows)
            and len({row["contextRevision"] for row in rows}) == 1)
    return {**value, "assignments": [dict(row) for row in rows]}


def is_signed(value: dict) -> bool:
    return value.get("operation") == "ios-signed-export"


def is_recovery(value: dict) -> bool:
    return value.get("operation") == "ios-local-recovery"


def stages(value: dict) -> tuple[str, ...]:
    if is_recovery(value):
        from ._desktop_ios_recovery_protocol import STAGES as recovery_stages
        return recovery_stages
    return SIGNED_STAGES if is_signed(value) else STAGES


def protocol(value: dict) -> str:
    if is_recovery(value):
        from ._desktop_ios_recovery_protocol import PROTOCOL as recovery_protocol
        return recovery_protocol
    return SIGNED_PROTOCOL if is_signed(value) else PROTOCOL


def _tool_identity(value: object) -> dict:
    value = _keys(value, {"device", "inode", "mode", "uid", "gid", "links", "size", "mtimeNs", "ctimeNs"})
    require(all(_text(value[key], _DECIMAL) and int(value[key]) <= 2**64 - 1
                for key in ("device", "inode", "mtimeNs", "ctimeNs")) and value["inode"] != "0"
            and all(integer(value[key], 2**32 - 1) for key in ("mode", "uid", "gid"))
            and stat.S_ISREG(value["mode"]) and value["mode"] & 0o111 != 0
            and integer(value["links"], 1, 1) and integer(value["size"], 64 * 1024 * 1024, 1))
    return dict(value)


def _native(value: object, *, signed: bool = False, recovery: bool = False) -> dict:
    if recovery:
        require(not signed)
        from ._desktop_ios_recovery_protocol import native as recovery_native
        return recovery_native(value)
    value = _keys(value, {"profile", "projectRoot", "rootIdentity", "cwd", "toolchain"} | ({"signingTools", "signingContext"} if signed else set()))
    require(_enum(value["profile"], PROFILES))
    tool = _keys(value["toolchain"], {"schemaVersion", "profile", "developerDir", "developerIdentity",
                                     "xcodebuildIdentity", "sdk", "sdkIdentity"})
    require(type(tool["schemaVersion"]) is int and tool["schemaVersion"] == 1
            and tool["profile"] == TOOLCHAIN_PROFILES[value["profile"]])
    developer, sdk = _path(tool["developerDir"]), _path(tool["sdk"])
    require(developer.endswith(".app/Contents/Developer") and developer.startswith("/Applications/")
            and sdk.startswith(developer + "/Platforms/iPhoneOS.platform/Developer/SDKs/")
            and sdk.endswith(".sdk") and "/" not in sdk.removeprefix(developer + "/Platforms/iPhoneOS.platform/Developer/SDKs/"))
    result = {"profile": value["profile"], "projectRoot": _path(value["projectRoot"]),
            "rootIdentity": _identity(value["rootIdentity"]), "cwd": _path(value["cwd"]),
            "toolchain": {**tool, "developerDir": developer, "developerIdentity": _identity(tool["developerIdentity"]),
                          "sdk": sdk, "sdkIdentity": _identity(tool["sdkIdentity"]),
                          "xcodebuildIdentity": _tool_identity(tool["xcodebuildIdentity"])}}
    if signed:
        tools = _keys(value["signingTools"], {"security", "codesign", "openssl"})
        result["signingTools"] = {name: _tool_identity(identity) for name, identity in tools.items()}
        require(all(identity["uid"] == 0 and identity["mode"] & 0o022 == 0 for identity in result["signingTools"].values()))
        result["signingContext"] = content(value["signingContext"], maximum=512 * 1024)
    return result


@dataclass(frozen=True)
class IOSArchiveRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict


def parse_request(raw: bytes) -> IOSArchiveRequest:
    value = _keys(_decode(raw, REQUEST_LIMIT, framed=True), {"protocol", "operationId", "ownerGeneration", "context", "native"})
    selected = context(value["context"])
    require(value["protocol"] == protocol(selected) and _text(value["operationId"], _TOKEN) and _text(value["ownerGeneration"], _TOKEN))
    return IOSArchiveRequest(value["operationId"], value["ownerGeneration"], selected,
        _native(value["native"], signed=is_signed(selected), recovery=is_recovery(selected)))


def _request_binding(request: IOSArchiveRequest) -> dict:
    require(type(request) is IOSArchiveRequest and _text(request.operation_id, _TOKEN) and _text(request.owner_generation, _TOKEN))
    return {"operationId": request.operation_id, "ownerGeneration": request.owner_generation,
            "context": context(request.context), "native": _native(request.native, signed=is_signed(request.context), recovery=is_recovery(request.context))}


def _selection(value: object) -> dict:
    value = _keys(value, {"containerKind", "container", "scheme", "configuration", "bundleId", "symbolsPolicy", "preparationConfigured"})
    require(_enum(value["containerKind"], ("project", "workspace"))
            and _enum(value["symbolsPolicy"], ("disabled", "retain", "required"))
            and type(value["preparationConfigured"]) is bool)
    for key in ("container", "scheme", "configuration", "bundleId"):
        require(type(value[key]) is str and 1 <= len(value[key].encode("utf-8")) <= 512
                and not any(ord(char) < 32 or ord(char) == 127 for char in value[key]))
    return dict(value)


def activity(value: object, *, signed: bool = False) -> dict:
    value = _keys(value, {"stage", "selection", "commands", "findings"})
    require(_enum(value["stage"], ("accepted", *(SIGNED_STAGES if signed else STAGES))))
    if value["selection"] is not None:
        _selection(value["selection"])
    require(value["stage"] == "accepted" or value["selection"] is not None)
    roles = SIGNED_ROLES if signed else ROLES
    commands = _keys(value["commands"], set(roles))
    for command in commands.values():
        command = _keys(command, {"outcome", "exitCode"})
        require(_enum(command["outcome"], ("not-dispatched", "exited", "unknown", "not-configured"))
                and (integer(command["exitCode"], 2**31 - 1, -(2**31)) if command["outcome"] == "exited"
                     else command["exitCode"] is None))
    require(all(commands[role]["outcome"] != "not-configured" for role in roles if role != "prepare"))
    rows = value["findings"]
    require(type(rows) is list and len(rows) <= 16)
    for row in rows:
        _keys(row, {"check", "status"})
        require(_enum(row["check"], SIGNED_CHECKS if signed else CHECKS) and _enum(row["status"], STATUSES))
    if (rows and not signed) or value["stage"] in {"inspecting", "disposing-snapshot", "disposing-work"}:
        require(commands["archive"] == {"outcome": "exited", "exitCode": 0})
        if signed:
            require(commands["export"] == {"outcome": "exited", "exitCode": 0})
    return value


def validate_terminal(value: object, request: IOSArchiveRequest) -> None:
    _request_binding(request)
    if is_recovery(request.context):
        from ._desktop_ios_recovery_protocol import validate_terminal as recovery_terminal
        return recovery_terminal(value, request)
    _structure(value)
    value = _keys(value, {"schemaVersion", "context", "outcome", "reason", "activity", "disposition", "result", "lifetime"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and context(value["context"]) == request.context and _enum(value["outcome"], OUTCOMES)
            and _enum(value["reason"], REASONS))
    signed = is_signed(request.context)
    closes = SIGNED_CLOSE_FIELDS if signed else CLOSE_FIELDS
    roles = SIGNED_ROLES if signed else ROLES
    observed = activity(value["activity"], signed=signed)
    life = _keys(value["lifetime"], {"complete", "fatal", "contained", "commandDispatched", "commands", "profileCalls", "stopObserved", *closes})
    require(all(type(life[key]) is bool for key in ("complete", "fatal", "contained", *closes))
            and (life["commandDispatched"] is None or type(life["commandDispatched"]) is bool)
            and integer(life["commands"], SIGNED_COMMAND_LIMIT if signed else 4)
            and integer(life["profileCalls"], SIGNED_PROFILE_LIMIT if signed else 0)
            and _enum(life["stopObserved"], ("none", "cancelled", "timed-out")))
    exited = sum(command["outcome"] == "exited" for command in observed["commands"].values())
    require(exited <= life["commands"])
    if life["commandDispatched"] is False:
        require(life["commands"] <= 1 and all(command["outcome"] in {"not-dispatched", "not-configured"}
                for command in observed["commands"].values()))
    elif life["commandDispatched"] is True:
        require(life["commands"] > 0)
    disposition = _keys(value["disposition"], {"snapshot", "work", "output", "relativeDirectory"})
    require(_enum(disposition["snapshot"], ("not-created", "removed", "unknown"))
            and _enum(disposition["work"], ("not-created", "removed", "retained-work", "unknown"))
            and _enum(disposition["output"], ("not-created", "retained-incomplete", "retained-local-result", "unknown")))
    require(disposition["relativeDirectory"] is None if disposition["output"] == "not-created" else
            disposition["relativeDirectory"] == f".mobile-release/desktop-ios-archive/{request.operation_id}")
    settled = (life["complete"] and not life["fatal"] and life["contained"]
               and all(life[key] for key in closes) and life["commandDispatched"] is not None
               and "unknown" not in disposition.values())
    if value["outcome"] == "complete":
        require(settled and value["reason"] == life["stopObserved"] == "none"
                and observed["stage"] == "disposing-work"
                and disposition["snapshot"] == disposition["work"] == "removed"
                and disposition["output"] == "retained-local-result")
        selected = _selection(observed["selection"])
        roles = roles if selected["preparationConfigured"] else tuple(role for role in roles if role != "prepare")
        if not selected["preparationConfigured"]:
            require(observed["commands"]["prepare"] == {"outcome": "not-configured", "exitCode": None})
        require((life["commands"] >= len(roles) if signed else life["commands"] == len(roles))
                and all(observed["commands"][role] == {"outcome": "exited", "exitCode": 0} for role in roles))
        rows = observed["findings"]
        if signed:
            expected_checks = {"signing-material", "profile-material", "artifact-correspondence", "ipa-structure", "ipa-profile", "ipa-entitlements", "ipa-signer"}
            if any(row["kind"] == "ios-firebase" for row in request.context["signing"]["assignments"]):
                expected_checks.add("firebase-material")
            require(len(rows) == len(expected_checks) and {row["check"] for row in rows} == expected_checks
                    and all(row["status"] == "PASS" for row in rows) and selected["symbolsPolicy"] != "required"
                    and life["profileCalls"] >= 3)
        else:
            require(len(rows) == 2 and rows[0] == {"check": "archive-identity", "status": "PASS"}
                    and rows[1]["check"] == "archive-dsym" and rows[1]["status"] in
                    (("PASS", "NOT_APPLICABLE") if selected["symbolsPolicy"] == "disabled" else ("PASS",)))
        result = _keys(value["result"], {"schemaVersion", "scope", "usedConfig", "usedVersion", "archive", "entries", "bytes", "limitations"}
                       | ({"ipa", "ipaBytes", "pairing"} if signed else set()))
        require(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1 and result["scope"] == (SIGNED_SCOPE if signed else SCOPE)
                and content(result["usedConfig"]) == request.context["savedConfig"]
                and saved_version(result["usedVersion"]) == request.context["savedVersion"]
                and result["archive"] == disposition["relativeDirectory"] + "/archive.xcarchive"
                and integer(result["entries"], 100_000, 1) and integer(result["bytes"], 8 * 1024**3, 1)
                and result["limitations"] == list(SIGNED_LIMITATIONS if signed else LIMITATIONS))
        if signed:
            prefix = disposition["relativeDirectory"] + "/export/"
            require(type(result["ipa"]) is str and result["ipa"].startswith(prefix)
                    and result["ipa"].endswith(".ipa") and 0 < len(result["ipa"][len(prefix):].encode("utf-8")) <= 255
                    and not any(ord(char) < 32 or ord(char) == 127 or char in "/\\:" for char in result["ipa"][len(prefix):])
                    and integer(result["ipaBytes"], 4 * 1024**3, 1))
            pair = _keys(result["pairing"], {"nativePaths", "nativeIdentities", "presentSymbolSlices"})
            require(integer(pair["nativePaths"], 100_000, 1) and integer(pair["nativeIdentities"], 100_000, 1)
                    and integer(pair["presentSymbolSlices"], 100_000))
    else:
        require(value["result"] is None and value["reason"] != "none" and disposition["output"] != "retained-local-result")
        require(settled if value["outcome"] != "unknown" else not settled)
        require((value["reason"] == "cleanup-unknown") is (value["outcome"] == "unknown"))
        if value["outcome"] in {"cancelled", "timed-out"}:
            require(value["outcome"] == value["reason"] == life["stopObserved"])
        if value["outcome"] == "refused":
            require(life["commandDispatched"] is False)
    require(len(_encode(value)) <= RESPONSE_LIMIT)


class IOSArchiveFrames:
    """Finite stream DATA; the original engine, not this class, owns the pipes."""

    def __init__(self, request: IOSArchiveRequest) -> None:
        self.request, self.binding = request, _request_binding(request)
        self.frames = self.bytes = 0
        self.stage = -1
        self.terminal = self.failed = False

    def response(self, kind: str, payload: dict) -> bytes:
        try:
            order = stages(self.request.context)
            require(not self.terminal and not self.failed and self.frames < len(order) + 2
                    and _request_binding(self.request) == self.binding)
            require(kind == "accepted" if self.frames == 0 else kind in {"progress", "terminal"})
            stage = self.stage
            if kind == "accepted":
                _keys(payload, {"schemaVersion", "context"})
                require(type(payload["schemaVersion"]) is int and payload["schemaVersion"] == 1
                        and context(payload["context"]) == self.request.context)
            elif kind == "progress":
                _keys(payload, {"schemaVersion", "stage"})
                require(type(payload["schemaVersion"]) is int and payload["schemaVersion"] == 1 and payload["stage"] in order)
                stage = order.index(payload["stage"])
                require(stage > self.stage)
            else:
                validate_terminal(payload, self.request)
                reached = payload["activity"]["stage"]
                require((-1 if reached == "accepted" else order.index(reached)) >= self.stage)
            raw = _encode({"protocol": protocol(self.request.context), "operationId": self.request.operation_id,
                           "ownerGeneration": self.request.owner_generation, "sequence": self.frames,
                           "kind": kind, "payload": payload})
            require(self.bytes + len(raw) <= RESPONSE_LIMIT)
            self.frames += 1
            self.bytes += len(raw)
            self.stage, self.terminal = stage, kind == "terminal"
            return raw
        except (ProtocolError, TypeError, ValueError, IndexError):
            self.failed = True
            raise
