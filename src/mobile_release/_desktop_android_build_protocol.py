"""Closed DATA for saved Android build/post-run AAB inspection, never authority.

No IO, tool invocation, filesystem admission or cleanup occurs here. Original
owners supply actual observations; these parsers/projections cannot manufacture
custody or finality. In particular, a core terminal is provisional until the
original native runtime/process/transport owners and final joins have settled.
"""
from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass
from typing import Any

from .config import ANDROID_ID_RE, MAX_CONFIG_BYTES, MAX_VERSION_BYTES

PROTOCOL = "mrk-android-build/3"
CONSENT = "saved-android-build-inspect-v3"
SCOPE = "local-post-build-artifact-observation"
TOOLCHAIN_PROFILE = "android-local-linux-gnu-x86_64-v1"
# A closed source contract, NOT a runtime/native qualification flag.
PROFILES = {"linux-gnu-x86_64": ("linux", "x86_64")}
RENDERER_REQUEST_LIMIT, REQUEST_LIMIT, RESPONSE_LIMIT = 8 * 1024, 32 * 1024, 64 * 1024
INTENT_SECONDS, WORK_SECONDS, FINALITY_SECONDS = 300, 3000, 3010
MAX_FRAMES, MAX_FINDINGS, MAX_ARTIFACTS = 11, 128, 1
MAX_AAB_BYTES = 1024 * 1024 * 1024
STAGES = ("inputs-bound", "building", "capturing", "inspecting", "disposing-work")
SIGNED_STAGES = ("inputs-bound", "validating-signing", "materializing-signing", "building",
                 "capturing", "signing", "restoring-signing", "inspecting", "disposing-work")
STATUSES = ("PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE")
CHECKS = ("aab-structure", "aab-manifest", "application-id", "build-number", "version-name",
          "release-flags", "signature", "signer", "core-lifecycle", "other-core-finding")
ABIS = ("arm64-v8a", "armeabi", "armeabi-v7a", "mips", "mips64", "x86", "x86_64")
LIMITATIONS = ("saved-inputs-not-atomic", "project-code-effects-possible", "not-network-isolated",
               "post-run-bytes-may-be-incremental-reused-or-stale", "source-binding-not-established",
               "artifact-signer-not-inspected", "toolkit-signing-not-requested", "store-operation-not-requested",
               "release-readiness-not-assessed", "local-output-observation-not-current-file-authority",
               "core-terminal-requires-original-native-finality")
SIGNER_MESSAGE = ("Toolkit signing was not requested; artifact signer was not inspected. "
                  "Project code may have signed this file.")
OUTCOMES = ("complete", "refused", "failed", "cancelled", "timed-out", "unknown")
_SAVED_REASONS = tuple(f"saved-{kind}-{reason}" for kind in ("config", "version")
                       for reason in ("missing", "invalid", "changed", "sensitive", "unsafe", "too-large"))
REASONS = frozenset(("none", "cancelled", "context-changed", "document-lost", "shutdown", "timed-out",
    "protocol-error", "runtime-unavailable", "intent-expired", "stale-intent", *_SAVED_REASONS,
    "platform-disabled", "module-required", "toolchain-unavailable", "toolchain-mismatch",
    "project-admission-refused", "command-failed", "command-incomplete", "artifact-missing",
    "artifact-ambiguous", "artifact-unsafe", "artifact-changed", "input-limit", "result-limit",
    "work-retained", "cleanup-unknown", "signing-inputs-required", "signing-invalid",
    "signing-failed", "signing-incomplete"))
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PROJECT = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
_VERSION_TEXT = re.compile(r"[0-9A-Za-z.+-]{1,64}\Z")
_MODULE_TEXT = re.compile(r":[0-9A-Za-z_.:-]{0,511}\Z")
_VARIANT_TEXT = re.compile(r"[0-9A-Za-z_-]{1,128}\Z")
_TASK_TEXT = re.compile(r":[0-9A-Za-z_.:-]{1,647}\Z")
_PREPARE_FIELDS = {"projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion", "artifactValidation", "signing"}
_FAILURES = frozenset(("FAIL", "MISSING", "BLOCKED", "INVALID"))
_MANIFEST_CHECKS = frozenset(("aab-manifest", "application-id", "build-number", "version-name", "release-flags"))
_CLOSE_FIELDS = ("inputClosed", "handlersRestored", "invocationClosed", "artifactsClosed", "toolsClosed", "namespaceClosed",
                 "signingInputsClosed", "materialRetired")
_INSPECTION_FIELDS = {"findings", "summary"}


class ProtocolError(ValueError):
    """Only a fixed message; rejected values and exception text are private."""


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("Invalid saved Android build protocol")


def integer(value: object, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _enum(value: object, allowed) -> bool:
    return type(value) is str and value in allowed


def _keys(value: object, fields: set[str]) -> dict:
    require(type(value) is dict and all(type(key) is str for key in value) and set(value) == fields)
    return value


def _text(value: object, pattern: re.Pattern) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _pairs(values: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in values:
        require(key not in result)
        result[key] = value
    return result


def _integer_literal(text: str) -> int:
    require(len(text.lstrip("-")) <= 16)
    value = int(text)
    require(abs(value) <= 2**53 - 1)
    return value


def _structure(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    require(count[0] <= 8192 and depth <= 16)
    if type(value) is dict:
        for key, item in value.items():
            require(type(key) is str)
            _structure(key, depth + 1, count)
            _structure(item, depth + 1, count)
    elif type(value) is list:
        for item in value:
            _structure(item, depth + 1, count)
    elif type(value) is str:
        try:
            require(len(value) <= 4096 and len(value.encode("utf-8")) <= 4096)
        except UnicodeError:
            require(False)
    elif type(value) is int:
        require(abs(value) <= 2**53 - 1)
    else:
        require(value is None or type(value) is bool)  # No field needs floating-point DATA.


def _decode(raw: bytes, limit: int, *, framed: bool) -> object:
    require(type(raw) is bytes and 1 <= len(raw) <= limit and not raw.startswith(b"\xef\xbb\xbf"))
    if framed:
        require(raw.endswith(b"\n") and raw.count(b"\n") == 1)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_int=_integer_literal,
                           parse_float=lambda _: require(False), parse_constant=lambda _: require(False))
        _structure(value)
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ProtocolError("Invalid saved Android build protocol") from None


def _encode(value: object) -> bytes:
    _structure(value)
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii") + b"\n"
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ProtocolError("Invalid saved Android build protocol") from None


def content(value: object, *, maximum: int = MAX_CONFIG_BYTES) -> dict:
    value = _keys(value, {"bytes", "sha256"})
    require(integer(value["bytes"], maximum, 1) and _text(value["sha256"], _SHA))
    return dict(value)


def saved_version(value: object) -> dict:
    from .api._release_version import _source_path  # Reuse existing pure public-source admission.
    value = _keys(value, {"source", "bytes", "sha256", "name", "build"})
    require(type(value["source"]) is str and len(value["source"]) <= 512 and _source_path(value["source"])
            and _text(value["name"], _VERSION_TEXT) and integer(value["build"], 2_100_000_000, 1))
    compared = content({"bytes": value["bytes"], "sha256": value["sha256"]}, maximum=MAX_VERSION_BYTES)
    # Wire text checks are not the marketing/iOS policy. The original operation
    # uses the shared parser and compares its one effective ReleaseVersion.
    return {"source": value["source"], **compared, "name": value["name"], "build": value["build"]}


def artifact_validation(value: object) -> dict:
    value = _keys(value, {"mode", "uploadCertificateSha256"})
    require(_enum(value["mode"], ("structure-and-version", "upload-signature")))
    fingerprint = value["uploadCertificateSha256"]
    # Public comparison transport only. Exact saved config policy/normalization
    # remains in core, and equality is checked before Gradle/tool acquisition.
    require(fingerprint is None if value["mode"] == "structure-and-version" else
            type(fingerprint) is str and re.fullmatch(r"[0-9A-Fa-f:]{1,95}", fingerprint) is not None)
    return dict(value)


def signing_context(value: object) -> dict | None:
    if value is None:
        return None
    value = _keys(value, {"source", "contextRevision", "assignments"})
    require(value["source"] == "assigned-session" and integer(value["contextRevision"], 2**32 - 2, 1))
    rows = value["assignments"]
    require(type(rows) is list and 1 <= len(rows) <= 3)
    for row in rows:
        _keys(row, {"kind", "recordId", "recordRevision", "contextRevision"})
        require(_text(row["recordId"], _TOKEN) and integer(row["recordRevision"], 2**32 - 2, 1)
                and integer(row["contextRevision"], 2**32 - 2, 1)
                and row["contextRevision"] == value["contextRevision"])
    kinds = [row["kind"] for row in rows]
    require(kinds[:1] == ["android-keystore"] and kinds[1:] in
            ([], ["android-firebase"], ["project-read-token"], ["android-firebase", "project-read-token"])
            and len({row["recordId"] for row in rows}) == len(rows))
    return {**value, "assignments": [dict(row) for row in rows]}


def is_signed(value: dict) -> bool:
    return value.get("signing") is not None


def stages(value: dict) -> tuple[str, ...]:
    return SIGNED_STAGES if is_signed(value) else STAGES


def frame_limit(value: dict) -> int:
    return 11 if is_signed(value) else 8


def _limitations(validation: dict, signing: dict | None = None) -> list[str]:
    return ["upload-signature-check-not-store-enrollment" if item == "artifact-signer-not-inspected"
            and validation["mode"] == "upload-signature" else
            "toolkit-signing-not-release-readiness" if item == "toolkit-signing-not-requested" and signing is not None
            else item for item in LIMITATIONS]


def prepare(value: object) -> dict:
    value = _keys(value, _PREPARE_FIELDS)
    require(_text(value["projectId"], _PROJECT) and integer(value["draftRevision"], 2**32 - 2)
            and integer(value["baselineGeneration"], 2**32 - 2))
    result = {**value, "savedConfig": content(value["savedConfig"]), "savedVersion": saved_version(value["savedVersion"]),
              "artifactValidation": artifact_validation(value["artifactValidation"]),
              "signing": signing_context(value["signing"])}
    require(result["signing"] is None or result["artifactValidation"]["mode"] == "upload-signature")
    require(len(_encode(result)) <= RENDERER_REQUEST_LIMIT)
    return result


def parse_prepare(raw: bytes) -> dict:
    """Comparison DATA only; this cannot allocate consent or resolve a project."""
    return prepare(_decode(raw, RENDERER_REQUEST_LIMIT, framed=False))


def context(value: object) -> dict:
    value = _keys(value, _PREPARE_FIELDS | {"platform", "operation"})
    require(value["platform"] == "android" and value["operation"] == "android-build-inspect")
    return {**prepare({key: value[key] for key in _PREPARE_FIELDS}),
            "platform": "android", "operation": "android-build-inspect"}


def _path(value: object) -> str:
    require(type(value) is str and len(value) <= 4096 and value.startswith("/"))
    try:
        require(len(value.encode("utf-8")) <= 4096)
        if value != "/":
            parts = value[1:].split("/")
            require(len(parts) <= 128 and all(part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                    and not any(ord(char) < 32 or ord(char) == 127 or char in "\\:" for char in part) for part in parts))
    except UnicodeError:
        require(False)
    return value


def _identity(value: object) -> dict:
    value = _keys(value, {"device", "inode", "mode", "uid", "gid"})
    require(all(_text(value[key], _DECIMAL) and int(value[key]) <= 2**64 - 1 for key in ("device", "inode"))
            and value["inode"] != "0" and all(integer(value[key], 2**32 - 1) for key in ("mode", "uid", "gid"))
            and stat.S_ISDIR(value["mode"]))
    return dict(value)


def _native(value: object, *, signed: bool = False) -> dict:
    value = _keys(value, {"profile", "projectRoot", "rootIdentity", "cwd", "toolchain"}
                  | ({"signingContext"} if signed else set()))
    require(_enum(value["profile"], PROFILES))
    toolchain = _keys(value["toolchain"], {"schemaVersion", "profile", "root", "rootIdentity", "inventorySha256"})
    require(type(toolchain["schemaVersion"]) is int and toolchain["schemaVersion"] == 1
            and toolchain["profile"] == TOOLCHAIN_PROFILE and _text(toolchain["inventorySha256"], _SHA))
    result = {"profile": value["profile"], "projectRoot": _path(value["projectRoot"]),
            "rootIdentity": _identity(value["rootIdentity"]), "cwd": _path(value["cwd"]),
            "toolchain": {**toolchain, "root": _path(toolchain["root"]), "rootIdentity": _identity(toolchain["rootIdentity"])}}
    if signed:
        result["signingContext"] = content(value["signingContext"])
    return result


@dataclass(frozen=True)
class AndroidBuildRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict


def parse_request(raw: bytes) -> AndroidBuildRequest:
    value = _keys(_decode(raw, REQUEST_LIMIT, framed=True), {"protocol", "operationId", "ownerGeneration", "context", "native"})
    require(value["protocol"] == PROTOCOL and _text(value["operationId"], _TOKEN) and _text(value["ownerGeneration"], _TOKEN))
    selected = context(value["context"])
    return AndroidBuildRequest(value["operationId"], value["ownerGeneration"], selected,
                               _native(value["native"], signed=is_signed(selected)))


def _request_binding(request: AndroidBuildRequest) -> dict:
    require(type(request) is AndroidBuildRequest and _text(request.operation_id, _TOKEN) and _text(request.owner_generation, _TOKEN))
    return {"operationId": request.operation_id, "ownerGeneration": request.owner_generation,
            "context": context(request.context), "native": _native(request.native, signed=is_signed(request.context))}


def _selection(value: object) -> dict:
    value = _keys(value, {"module", "variant", "applicationId", "task"})
    require(_text(value["module"], _MODULE_TEXT) and _text(value["variant"], _VARIANT_TEXT)
            and type(value["applicationId"]) is str and len(value["applicationId"]) <= 255
            and ANDROID_ID_RE.fullmatch(value["applicationId"]) is not None and _text(value["task"], _TASK_TEXT))
    # Public labels only. Core configuration/task selection is not duplicated
    # here and these labels must never be converted back into an argv.
    return dict(value)


def _command(value: object) -> dict:
    value = _keys(value, {"outcome", "exitCode"})
    require(_enum(value["outcome"], ("not-dispatched", "exited", "unknown")))
    require(integer(value["exitCode"], 2**31 - 1, -(2**31)) if value["outcome"] == "exited" else value["exitCode"] is None)
    return dict(value)


def project_finding(code: str) -> str:
    return {"android.aab.structure": "aab-structure", "android.aab.manifest": "aab-manifest",
            "android.aab.package": "application-id", "android.aab.versionCode": "build-number",
            "android.aab.versionName": "version-name", "android.aab.release-flags": "release-flags",
            "android.aab.signature": "signature", "android.aab.signer": "signer", "android.build.process-lifetime": "core-lifecycle",
            "android.build.input-ownership": "core-lifecycle"}.get(code, "other-core-finding")


def _inspection(value: object) -> dict:
    value = _keys(value, _INSPECTION_FIELDS)
    require(type(value["findings"]) is list and len(value["findings"]) <= MAX_FINDINGS)
    summary = _keys(value["summary"], {"total", "shown", "omitted", "counts"})
    counts = _keys(summary["counts"], set(STATUSES))
    require(all(integer(summary[key], MAX_FINDINGS) for key in ("total", "shown", "omitted"))
            and summary["total"] == summary["shown"] == len(value["findings"]) and summary["omitted"] == 0
            and all(integer(number, MAX_FINDINGS) for number in counts.values()))
    observed = {status: 0 for status in STATUSES}
    rows = []
    for ordinal, row in enumerate(value["findings"]):
        row = _keys(row, {"ordinal", "check", "status"})
        require(type(row["ordinal"]) is int and row["ordinal"] == ordinal
                and _enum(row["check"], CHECKS) and _enum(row["status"], STATUSES))
        rows.append(dict(row))
        observed[row["status"]] += 1
    require(observed == counts)
    return {"findings": rows, "summary": {**summary, "counts": dict(counts)}}


def _signing_activity(value: object) -> dict | None:
    if value is None:
        return None
    value = _keys(value, {"validationCommand", "validationPassed", "signingCommand", "materialization"})
    validation, signing = _command(value["validationCommand"]), _command(value["signingCommand"])
    require(type(value["validationPassed"]) is bool
            and _enum(value["materialization"], ("not-started", "active", "restored", "unknown")))
    if value["validationPassed"]:
        require(validation == {"outcome": "exited", "exitCode": 0})
    if value["materialization"] != "not-started" or signing["outcome"] != "not-dispatched":
        require(value["validationPassed"])
    if signing["outcome"] != "not-dispatched":
        require(value["materialization"] != "not-started")
    return {**value, "validationCommand": validation, "signingCommand": signing}


def _activity(value: object) -> dict:
    value = _keys(value, {"stage", "selection", "command", "signing", *_INSPECTION_FIELDS})
    signing = _signing_activity(value["signing"])
    allowed = SIGNED_STAGES if signing is not None else STAGES
    require(_enum(value["stage"], ("accepted", *allowed)))
    selected = None if value["selection"] is None else _selection(value["selection"])
    command = _command(value["command"])
    if value["stage"] not in {"accepted", "disposing-work"}:
        require(selected is not None)
    if value["stage"] in {"capturing", "signing", "restoring-signing", "inspecting"}:
        require(command == {"outcome": "exited", "exitCode": 0})
    if command["outcome"] != "not-dispatched":
        require(selected is not None and value["stage"] in
                {"building", "capturing", "signing", "restoring-signing", "inspecting", "disposing-work"})
    if signing is not None:
        if signing["validationCommand"]["outcome"] != "not-dispatched":
            require(selected is not None and value["stage"] not in {"accepted", "inputs-bound"})
        if command["outcome"] != "not-dispatched":
            require(signing["validationPassed"] and signing["materialization"] != "not-started")
        if signing["signingCommand"]["outcome"] != "not-dispatched":
            require(command == {"outcome": "exited", "exitCode": 0}
                    and value["stage"] in {"signing", "restoring-signing", "inspecting", "disposing-work"})
        if value["stage"] in {"inspecting", "disposing-work"}:
            require(signing["signingCommand"] == {"outcome": "exited", "exitCode": 0}
                    and signing["materialization"] == "restored")
    inspection = _inspection({key: value[key] for key in _INSPECTION_FIELDS})
    if any(row["check"] not in {"core-lifecycle", "other-core-finding"} for row in inspection["findings"]):
        # Failed/cancelled command paths cannot scan for a substitute AAB. Keep
        # negative activity useful without claiming an inspection took place.
        require(command == {"outcome": "exited", "exitCode": 0} and value["stage"] in {"inspecting", "disposing-work"})
    return {"stage": value["stage"], "selection": selected, "command": command, "signing": signing,
            **inspection}


def project_activity(report, *, stage: str, selection: dict | None, command: dict,
                     signing: dict | None = None) -> dict:
    from .reporting import Finding, Report, Status
    require(report is None or type(report) is Report and isinstance(report.findings, list) and len(report.findings) <= MAX_FINDINGS)
    rows, counts = [], {status: 0 for status in STATUSES}
    if report is not None:
        for ordinal, finding in enumerate(report.findings):
            require(type(finding) is Finding and type(finding.code) is str and len(finding.code) <= 256 and type(finding.status) is Status)
            check = project_finding(finding.code)
            rows.append({"ordinal": ordinal, "check": check, "status": finding.status.value})
            counts[finding.status.value] += 1
    return _activity({"stage": stage, "selection": selection, "command": command, "signing": signing, "findings": rows,
                      "summary": {"total": len(rows), "shown": len(rows), "omitted": 0, "counts": counts}})


def _artifact(value: object) -> dict:
    value = _keys(value, {"logicalName", "platform", "kind", "fileName", "size", "sha256", "architectures", "unknownAbi", "freshness"})
    require(value["logicalName"] == "android-aab" and value["platform"] == "android" and value["kind"] == "aab"
            and value["fileName"] == "app-release.aab" and integer(value["size"], MAX_AAB_BYTES, 1)
            and _text(value["sha256"], _SHA) and type(value["unknownAbi"]) is bool and value["freshness"] == "not-established"
            and type(value["architectures"]) is list and len(value["architectures"]) <= len(ABIS)
            and all(_enum(abi, ABIS) for abi in value["architectures"]))
    require(value["architectures"] == sorted(set(value["architectures"])))
    return {**value, "architectures": list(value["architectures"])}


def project_artifact(record: object, *, unknown_abi: bool) -> dict:
    record = _keys(record, {"logicalName", "platform", "kind", "fileName", "size", "sha256", "architectures"})
    return _artifact({**record, "unknownAbi": unknown_abi, "freshness": "not-established"})


def _assurances(rows: list[dict], validation: dict, signing: dict | None = None) -> dict:
    structures = [row["status"] for row in rows if row["check"] == "aab-structure"]
    structure = ("passed" if structures == ["PASS"] else "failed" if any(item in _FAILURES for item in structures)
                 else "not-checked")
    manifest = [row for row in rows if row["check"] in _MANIFEST_CHECKS]
    unsupported = any(row["check"] in {"other-core-finding", "core-lifecycle"} for row in rows)
    native = ("passed" if structure == "passed" and not unsupported and len(manifest) == 1
              and manifest[0]["check"] == "aab-manifest" and manifest[0]["status"] == "PASS"
              else "failed" if any(row["status"] in _FAILURES for row in manifest) else "not-checked")
    signatures = [row["status"] for row in rows if row["check"] == "signature"]
    signers = [row["status"] for row in rows if row["check"] == "signer"]
    signature = signer = "not-inspected"
    if validation["mode"] == "upload-signature":
        signature = ("passed" if structure == "passed" and not unsupported and signatures == ["PASS"] else
                     "failed" if any(item in _FAILURES for item in signatures) else "not-checked")
        signer = ("matches-saved-upload-certificate" if signature == "passed" and signers == ["PASS"] else
                  "failed" if any(item in _FAILURES for item in signers) else "not-checked")
    toolkit = ("not-requested" if signing is None else "verified" if
               signing["signingCommand"] == {"outcome": "exited", "exitCode": 0}
               and signature == "passed" and signer == "matches-saved-upload-certificate" else "not-verified")
    return {"structure": structure, "nativeManifest": native,
            "applicationVersion": "native-checked" if native == "passed" else "not-established",
            "signature": signature, "signer": signer, "toolkitSigning": toolkit, "storeOperation": "not-requested",
            "sourceBinding": "not-established", "releaseReadiness": "not-assessed"}


def _inspection_mode(rows: list[dict], validation: dict) -> None:
    signatures = [row["status"] for row in rows if row["check"] == "signature"]
    signers = [row["status"] for row in rows if row["check"] == "signer"]
    if validation["mode"] == "structure-and-version":
        require(not signatures and all(status == "SKIP" for status in signers))
    else:
        require(signatures in ([], ["PASS"], ["FAIL"]))
        require(not signers or signatures == ["PASS"] and
                (signers == ["PASS"] or all(status == "FAIL" for status in signers)))


def _inspection_commands(rows: list[dict], validation: dict) -> int:
    """Exact reachable completed inspection prefixes, not an open call budget.

    One: structure rejection. Two: basic manifest. Three: signature rejection.
    Four: accepted signature followed by leaf inspection (which may fail).
    Manifest failures are nonfatal policy DATA and do not skip signature work.
    """
    _inspection_mode(rows, validation)
    structures = [row["status"] for row in rows if row["check"] == "aab-structure"]
    manifest = [row for row in rows if row["check"] in _MANIFEST_CHECKS]
    signatures = [row["status"] for row in rows if row["check"] == "signature"]
    signers = [row["status"] for row in rows if row["check"] == "signer"]
    if structures == ["FAIL"]:
        require(not manifest and not signatures and not signers)
        return 1
    require(structures == ["PASS"] and bool(manifest))
    if validation["mode"] == "structure-and-version":
        require(signers == ["SKIP"])
        return 2
    if signatures == ["FAIL"]:
        require(not signers)
        return 3
    require(signatures == ["PASS"] and bool(signers))
    return 4


def project_result(activity: object, artifact: object, *, used_config: object,
                   used_version: object, toolchain_profile: str, validation: object) -> dict:
    observed = _activity(activity)
    validation = artifact_validation(validation)
    require(observed["stage"] == "disposing-work")
    result = {"schemaVersion": 1, "scope": SCOPE, "usedConfig": content(used_config),
              "usedVersion": saved_version(used_version), "artifactValidation": validation, "selection": observed["selection"],
              "toolchainProfile": toolchain_profile, "command": observed["command"], "signing": observed["signing"],
              "findings": observed["findings"], "summary": observed["summary"],
              "artifacts": [_artifact(artifact)], "assurances": _assurances(observed["findings"], validation, observed["signing"]),
              "limitations": _limitations(validation, observed["signing"])}
    validate_result(result)
    return result


def validate_result(value: object) -> None:
    _structure(value)
    value = _keys(value, {"schemaVersion", "scope", "usedConfig", "usedVersion", "selection", "toolchainProfile",
                          "command", "signing", "findings", "summary", "artifacts", "assurances", "limitations", "artifactValidation"})
    signing = _signing_activity(value["signing"])
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE
            and value["toolchainProfile"] == TOOLCHAIN_PROFILE and type(value["limitations"]) is list
            and value["limitations"] == _limitations(artifact_validation(value["artifactValidation"]), signing))
    if signing is not None:
        require(value["artifactValidation"]["mode"] == "upload-signature" and signing["validationPassed"]
                and signing["validationCommand"] == signing["signingCommand"] == {"outcome": "exited", "exitCode": 0}
                and signing["materialization"] == "restored")
    content(value["usedConfig"])
    saved_version(value["usedVersion"])
    _selection(value["selection"])
    require(_command(value["command"]) == {"outcome": "exited", "exitCode": 0})
    inspection = _inspection({key: value[key] for key in _INSPECTION_FIELDS})
    require(any(row["check"] == "aab-structure" for row in inspection["findings"])
            and all(row["check"] != "core-lifecycle" for row in inspection["findings"]))
    require(type(value["artifacts"]) is list and len(value["artifacts"]) == MAX_ARTIFACTS)
    _artifact(value["artifacts"][0])
    validation = artifact_validation(value["artifactValidation"])
    _inspection_commands(inspection["findings"], validation)
    assurance = _keys(value["assurances"], set(_assurances(inspection["findings"], validation, signing)))
    require(assurance == _assurances(inspection["findings"], validation, signing) and len(_encode(value)) <= RESPONSE_LIMIT)


def _disposition(value: object) -> dict:
    value = _keys(value, {"work", "artifacts"})
    require(_enum(value["work"], ("not-created", "removed", "retained-work", "unknown"))
            and _enum(value["artifacts"], ("not-created", "removed", "retained-local-result", "retained-incomplete", "unknown")))
    return dict(value)


def _lifetime(value: object) -> dict:
    value = _keys(value, {"complete", "fatal", "contained", "commandDispatched", "commands", "profileCalls", "stopObserved", *_CLOSE_FIELDS})
    require(all(type(value[key]) is bool for key in ("complete", "fatal", "contained", *_CLOSE_FIELDS))
            and (value["commandDispatched"] is None or type(value["commandDispatched"]) is bool)
            and integer(value["commands"], 6) and type(value["profileCalls"]) is int and value["profileCalls"] == 0
            and _enum(value["stopObserved"], ("none", "cancelled", "timed-out")))
    return dict(value)


def _signed_command_prefix(activity: dict, life: dict) -> None:
    """Three fixed pre-inspection roles; a preflight is not a Gradle launch."""
    signing = activity["signing"]
    require(signing is not None)
    validation, command, canonicalization = (signing["validationCommand"], activity["command"],
                                              signing["signingCommand"])
    zero, unused = {"outcome": "exited", "exitCode": 0}, {"outcome": "not-dispatched", "exitCode": None}
    count = life["commands"]
    require(count >= sum(item["outcome"] == "exited" for item in (validation, command, canonicalization)))
    if validation != zero or not signing["validationPassed"]:
        require(command == canonicalization == unused and count <= 1)
    elif command != zero:
        require(canonicalization == unused and count <= 2)
    elif canonicalization != zero:
        require(count <= 3)
    if count > 3:
        require(canonicalization == zero and activity["stage"] in {"inspecting", "disposing-work"}
                and signing["materialization"] == "restored")
    if any(item["outcome"] == "exited" for item in (validation, command, canonicalization)):
        require(life["commandDispatched"] is True)
    if validation == unused:
        require(life["commandDispatched"] is False)


def validate_terminal(value: object, request: AndroidBuildRequest) -> None:
    _request_binding(request)
    _structure(value)
    value = _keys(value, {"schemaVersion", "context", "outcome", "reason", "activity", "disposition", "result", "lifetime"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and context(value["context"]) == request.context and _enum(value["outcome"], OUTCOMES)
            and _enum(value["reason"], REASONS))
    activity, disposition, life = _activity(value["activity"]), _disposition(value["disposition"]), _lifetime(value["lifetime"])
    validation = request.context["artifactValidation"]
    signed = is_signed(request.context)
    require(signed is (activity["signing"] is not None))
    _inspection_mode(activity["findings"], validation)
    require(life["commands"] <= (6 if signed else 4 if validation["mode"] == "upload-signature" else 2))
    if signed:
        _signed_command_prefix(activity, life)
    else:
        require(life["signingInputsClosed"] and life["materialRetired"])
        if activity["command"] != {"outcome": "exited", "exitCode": 0}:
            require(life["commands"] <= 1)
        if life["commands"] > 1:
            require(activity["stage"] in {"inspecting", "disposing-work"})
    if any(row["check"] not in {"core-lifecycle", "other-core-finding"} for row in activity["findings"]):
        require(life["commands"] == _inspection_commands(activity["findings"], validation) + (2 if signed else 0))
    settled = (life["complete"] and not life["fatal"] and life["contained"] and all(life[key] for key in _CLOSE_FIELDS)
               and life["commandDispatched"] is not None and "unknown" not in disposition.values())
    if not signed and activity["command"]["outcome"] == "not-dispatched":
        require(life["commandDispatched"] is False and life["commands"] <= 1)
    elif activity["command"]["outcome"] == "exited":
        require(life["commandDispatched"] is True and life["commands"] >= 1)
    if value["outcome"] == "complete":
        require(settled and life["stopObserved"] == "none" and value["reason"] == "none"
                and activity["stage"] == "disposing-work"
                and disposition == {"work": "removed", "artifacts": "retained-local-result"})
        validate_result(value["result"])
        result = value["result"]
        require(result["usedConfig"] == request.context["savedConfig"] and result["usedVersion"] == request.context["savedVersion"]
                and result["artifactValidation"] == validation
                and result["toolchainProfile"] == request.native["toolchain"]["profile"]
                and all(result[key] == activity[key] for key in ("selection", "command", "signing", "findings", "summary")))
        require(life["commands"] == _inspection_commands(result["findings"], validation) + (2 if signed else 0))
    else:
        require(value["result"] is None and value["reason"] != "none" and disposition["artifacts"] != "retained-local-result")
        require(settled or value["outcome"] == "unknown")
        if value["outcome"] == "unknown":
            require(value["reason"] == "cleanup-unknown" and not settled)
        else:
            require(value["reason"] != "cleanup-unknown")
        if value["outcome"] in {"cancelled", "timed-out"}:
            require(value["outcome"] == value["reason"] == life["stopObserved"])
        if value["outcome"] == "refused":
            require(activity["command"]["outcome"] == "not-dispatched" and life["commandDispatched"] is False)
            if signed:
                require(activity["signing"]["validationCommand"]["outcome"] == "not-dispatched"
                        and activity["signing"]["signingCommand"]["outcome"] == "not-dispatched")
        if value["reason"] == "command-failed":
            require(value["outcome"] == "failed" and activity["command"]["outcome"] == "exited"
                    and activity["command"]["exitCode"] != 0)
        if value["reason"] == "command-incomplete":
            require(value["outcome"] == "failed" and activity["command"]["outcome"] != "exited")
        if value["reason"].startswith("signing-"):
            require(signed)
        if value["reason"] == "signing-invalid":
            require(not activity["signing"]["validationPassed"]
                    and activity["command"]["outcome"] == "not-dispatched")
        if value["reason"] == "signing-failed":
            require(value["outcome"] == "failed" and activity["signing"]["signingCommand"]["outcome"] == "exited"
                    and activity["signing"]["signingCommand"]["exitCode"] != 0)
        if value["reason"] in {"artifact-missing", "artifact-ambiguous", "artifact-unsafe", "artifact-changed"}:
            # This vertical has no pre-build artifact scan. These reasons
            # describe capture/inspection after the original zero return,
            # never an admission refusal or a failed-build substitute.
            require(value["outcome"] == "failed" and activity["selection"] is not None
                    and activity["command"] == {"outcome": "exited", "exitCode": 0}
                    and activity["stage"] in {"capturing", "signing", "restoring-signing", "inspecting", "disposing-work"})
        if value["reason"] in {"cancelled", "context-changed", "document-lost", "shutdown"}:
            require(life["stopObserved"] == "cancelled")
        if value["reason"] == "timed-out":
            require(life["stopObserved"] == "timed-out")
        if value["reason"] == "work-retained":
            require(value["outcome"] == "failed" and disposition["work"] == "retained-work")
    if disposition["work"] == "retained-work":
        require(value["outcome"] in {"failed", "unknown"})
    require(len(_encode(value)) <= RESPONSE_LIMIT)


def response(request: AndroidBuildRequest, kind: str, payload: dict, *, sequence: int) -> bytes:
    """One frame only; the original AndroidBuildFrames enforces stream finality."""
    _request_binding(request)
    require(_enum(kind, ("accepted", "progress", "terminal")) and integer(sequence, frame_limit(request.context) - 1))
    if kind == "accepted":
        _keys(payload, {"schemaVersion", "context"})
        require(sequence == 0 and type(payload["schemaVersion"]) is int and payload["schemaVersion"] == 1
                and context(payload["context"]) == request.context)
    elif kind == "progress":
        _keys(payload, {"schemaVersion", "stage"})
        require(1 <= sequence <= len(stages(request.context)) and type(payload["schemaVersion"]) is int and payload["schemaVersion"] == 1
                and _enum(payload["stage"], stages(request.context)))
    else:
        require(sequence >= 1)
        validate_terminal(payload, request)
    raw = _encode({"protocol": PROTOCOL, "operationId": request.operation_id, "ownerGeneration": request.owner_generation,
                   "sequence": sequence, "kind": kind, "payload": payload})
    require(len(raw) <= RESPONSE_LIMIT)
    return raw


class AndroidBuildFrames:
    """Finite DATA stream state, not an owner of pipes, files, tools or permits."""

    def __init__(self, request: AndroidBuildRequest) -> None:
        self._binding = _request_binding(request)
        self._request = request
        self._frames = self._bytes = 0
        self._stage = -1
        self._terminal = self._failed = False

    def response(self, kind: str, payload: dict) -> bytes:
        try:
            require(not self._failed and not self._terminal and self._frames < frame_limit(self._request.context)
                    and _request_binding(self._request) == self._binding)
            if self._frames == 0:
                require(kind == "accepted")
            else:
                require(_enum(kind, ("progress", "terminal")))
            stage = self._stage
            if kind == "progress":
                _keys(payload, {"schemaVersion", "stage"})
                allowed = stages(self._request.context)
                require(_enum(payload["stage"], allowed))
                stage = allowed.index(payload["stage"])
                require(stage == self._stage + 1 if is_signed(self._request.context) else stage > self._stage)
            raw = response(self._request, kind, payload, sequence=self._frames)
            if kind == "terminal":
                reached = payload["activity"]["stage"]
                require((-1 if reached == "accepted" else stages(self._request.context).index(reached)) >= self._stage)
                if is_signed(self._request.context) and payload["outcome"] == "complete":
                    require(self._stage == len(SIGNED_STAGES) - 1)
            require(self._bytes + len(raw) <= RESPONSE_LIMIT)
            # Commit before handing bytes to the original engine. Partial or
            # failed writes never authorize encoder replay or a second terminal.
            self._frames += 1
            self._bytes += len(raw)
            self._stage = stage
            self._terminal = kind == "terminal"
            return raw
        except ProtocolError:
            self._failed = True
            raise


def reason_guidance(reason: str) -> str:
    require(_enum(reason, REASONS))
    if reason.startswith("saved-config-"):
        return "Correct the saved configuration and refresh its saved input comparison after original cleanup settles; unsaved drafts are not used."
    if reason.startswith("saved-version-"):
        return "Correct the version file selected by the saved configuration, then refresh both saved comparisons after original cleanup settles."
    return {
        "none": "Review the separate inspection findings. Task completion and retained local bytes are not release approval.",
        "cancelled": "Cancellation is not rollback. Check original status and output disposition; start no new run until original cleanup is confirmed.",
        "context-changed": "The reviewed selection changed. Wait for the original run to settle, refresh saved inputs and provide new consent.",
        "document-lost": "The original document is no longer attached. Check original status; do not repeat Start or adopt its files from a new session.",
        "shutdown": "Wait for original shutdown and cleanup. Closing a view does not prove the command or its helpers have stopped.",
        "timed-out": "The original deadline was reached. Check original cleanup and retained output status; a timeout does not identify a private compiler error.",
        "protocol-error": "The original build communication did not match its fixed contract. Check original status and wait for cleanup; do not repeat Start.",
        "runtime-unavailable": "The required Desktop runtime is unavailable. Use a separately qualified runtime; no system-runtime fallback is used.",
        "intent-expired": "The saved-input review expired. After original settlement, refresh the saved comparisons and provide new consent.",
        "stale-intent": "This consent no longer identifies the current original owner. Check original status rather than repeating Start.",
        "platform-disabled": "Enable and save the intended Android configuration before refreshing the saved build selection.",
        "module-required": "Configure android.module as the intended Android application module, save it, then refresh the saved selection.",
        "toolchain-unavailable": "Configure the separately qualified JDK, Android SDK, Gradle and pinned bundletool profile. This action installs no tools and accepts no SDK licenses.",
        "toolchain-mismatch": "Make the project's wrapper and SDK/JDK selection agree with the qualified fixed profile. No alternate wrapper or ambient installation is selected.",
        "project-admission-refused": "Resolve the original project's pending toolkit work or private-directory admission issue before reviewing a new run; do not delete shared caches.",
        "command-failed": "Gradle returned a known nonzero code. Possible causes include project or dependency configuration; inspect private Build Output in Android Studio or the project's normal editor. App-code fixes may require that editor. Refresh and provide new consent only after original cleanup is confirmed.",
        "command-incomplete": "No usable Gradle command outcome was obtained. Check original cleanup status; no exit code or hidden compiler diagnosis is inferred.",
        "signing-inputs-required": "Assign the upload keystore and all signing inputs required by the saved Android configuration in Credentials, then refresh the saved review.",
        "signing-invalid": "The selected Android signing inputs did not pass validation. Check the keystore, alias, both passwords, saved upload certificate and required Firebase file in Credentials; Gradle did not run.",
        "signing-failed": "The signing tool returned a nonzero code. Check the assigned key password and keystore with its authorized owner. The partial output is not a verified signed artifact; wait for original cleanup before a new review.",
        "signing-incomplete": "No usable signing-tool outcome was obtained. Check original cleanup and retained-input status; do not adopt partial output or start another run until settlement is confirmed.",
        "artifact-missing": "The required AAB was not found in the configured module and variant output. Check that project's bundle task before a newly consented run.",
        "artifact-ambiguous": "More than one required AAB candidate was observed. Resolve the configured project's ambiguous output without adopting a substitute file.",
        "artifact-unsafe": "The selected output could not be admitted safely. Correct the project's output layout; no alternate path or arbitrary file picker is used.",
        "artifact-changed": "The original captured output or input changed during observation. Review project changes and refresh only after original cleanup settles.",
        "input-limit": "The saved input or task-owned processing limit was reached. Reduce the applicable input or use a separately supported profile; no limit is raised automatically.",
        "result-limit": "The bounded result could not be represented safely. Check original status and cleanup; raw tool output is not a substitute report.",
        "work-retained": "Original task work is known to remain. Review its disposition; this result offers no automatic rerun, blanket deletion or global daemon stop.",
        "cleanup-unknown": "Original cleanup is unconfirmed and the owner remains retained. Use original Status or Cancel; further execution stays blocked. Do not adopt or delete files from a new session.",
    }[reason]
