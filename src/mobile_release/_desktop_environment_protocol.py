"""Closed diagnostics DATA and parsers; no tool lookup or execution imports.

This is not a passive API method. Native-only paths/profile in a request come
from the original registered document and qualified runtime, never a renderer.
The terminal lifetime fields are core observations, not native finality.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ._desktop_engine import ProtocolError, _check_depth, _check_values, _constant, _pairs
from .toolchain_policy import XCODE_BUILD, XCODE_VERSION

PROTOCOL = "mrk-environment-diagnostics/1"
POLICY = "environment-diagnostics-v1"
REQUEST_LIMIT = 1024 * 1024
DRAFT_LIMIT = 512 * 1024
RESPONSE_LIMIT = 64 * 1024  # Aggregate accepted + terminal, not per frame.
OUTPUT_LIMIT = 16 * 1024  # Aggregate stdout + stderr for each ordinary command.
WORK_SECONDS = 6.0
FINALITY_SECONDS = 10.0
CALL_SECONDS = 3
TOKEN = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)
PROFILES = {
    "linux-gnu-x86_64": ("linux", "x86_64"),
    "linux-gnu-aarch64": ("linux", "aarch64"),
    "macos-x86_64": ("macos", "x86_64"),
    "macos-arm64": ("macos", "arm64"),
}
ROSTERS = {
    ("linux", "android"): ("git", "java", "javac"),
    ("linux", "ios"): ("git", "xcode"),
    ("macos", "android"): ("developer-selection", "git", "java", "javac"),
    ("macos", "ios"): ("developer-selection", "git", "xcode"),
}
NOT_RUN = frozenset({"invalid-draft", "platform-disabled", "host-mismatch", "unsupported-host",
    "missing-in-supported-lookup", "unsupported-installation", "unselected-installation",
    "full-xcode-not-selected", "stopped"})
ATTEMPTED = frozenset({"command-incomplete", "binding-changed", "cancelled", "timed-out"})
COMPLETED = frozenset({"observed", "nonzero-exit", "version-unrecognized", "selection-unrecognized"})
OUTCOMES = frozenset({"complete", "partial", "failed", "cancelled", "timed-out", "unavailable"})
HELP = {
    "developer-selection": "Checks the existing macOS developer selection only. No tool selection, installation, license acceptance or path is exposed. A Command Line Tools selection does not establish the pinned full Xcode baseline.",
    "git": "Checks only the installed Git executable version outside your project. It does not read a repository, configuration, hooks, remotes or authentication. Custom or per-user installations are outside the supported lookup.",
    "java": "Checks the selected system Java runtime version. Java 21 is a workflow reference, not a local compatibility requirement. This does not check Gradle, Android SDK packages, signing tools or whether a complete JDK is usable by your project.",
    "javac": "Checks the compiler version from the same admitted system JDK as Java. No source is compiled. A matching version does not establish project, Gradle, Android SDK or signing compatibility.",
    "xcode": "Checks only the selected full Xcode version and build against the shared release baseline. No project, scheme, SDK inventory, signing identity, license acceptance, build or Store operation is performed.",
}
_VERSION = re.compile(r"[0-9][0-9A-Za-z._+\-]{0,63}\Z", re.ASCII)
_BUILD = re.compile(r"[0-9]{1,3}[A-Z][0-9]{1,6}[a-z]?\Z", re.ASCII)
_GIT = re.compile(rb"git version ([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?(?:[.\-][0-9A-Za-z][0-9A-Za-z.+\-]{0,40})?)(?: \(Apple Git-[0-9]{1,6}\))?\n?\Z")
_JAVA_VERSION = rb"[0-9]{1,3}(?:[._][0-9]{1,6}){0,3}(?:[+\-][0-9A-Za-z][0-9A-Za-z.+_\-]{0,32})?"
_JAVA = re.compile(rb'(?:openjdk|java) version "(' + _JAVA_VERSION + rb')"(?: [0-9]{4}-[0-9]{2}-[0-9]{2})?(?: LTS)?\n'
    rb'(?:OpenJDK Runtime Environment|Java\(TM\) SE Runtime Environment)[ -~]{1,512}\n'
    rb'(?:OpenJDK (?:64-Bit )?Server VM|Java HotSpot\(TM\) (?:64-Bit )?Server VM)[ -~]{1,512}\n?\Z')
_JAVAC = re.compile(rb"javac (" + _JAVA_VERSION + rb")\n?\Z")
_XCODE = re.compile(rb"Xcode ([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?)\nBuild version ([0-9]{1,3}[A-Z][0-9]{1,6}[a-z]?)\n?\Z")
_ROLE_VERSION = {
    "git": re.compile(r"[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?(?:[.\-][0-9A-Za-z][0-9A-Za-z.+\-]{0,40})?\Z", re.ASCII),
    "java": re.compile(_JAVA_VERSION.decode("ascii") + r"\Z", re.ASCII),
    "javac": re.compile(_JAVA_VERSION.decode("ascii") + r"\Z", re.ASCII),
    "xcode": re.compile(r"[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?\Z", re.ASCII),
}


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("Invalid environment diagnostics data")


def integer(value: object, high: int = 2**32 - 2, low: int = 0) -> bool:
    return type(value) is int and low <= value <= high


def absolute_path(value: object) -> str:
    """Validate native DATA without normalizing, resolving or opening a path."""
    require(type(value) is str)
    assert isinstance(value, str)
    try:
        parts = value.split("/")
        valid = (len(value.encode("utf-8")) <= 4096 and value.startswith("/")
                 and (value == "/" or 1 < len(parts) <= 129 and all(
                     part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                     and not any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in part)
                     for part in parts[1:])))
    except UnicodeError:
        valid = False
    require(valid)
    return value


def context_value(value: object) -> dict[str, Any]:
    require(type(value) is dict and set(value) == {
        "projectId", "draftRevision", "baselineGeneration", "platform", "operation"})
    assert isinstance(value, dict)
    require(type(value["projectId"]) is str and ID.fullmatch(value["projectId"]) is not None
        and integer(value["draftRevision"]) and integer(value["baselineGeneration"])
        and type(value["platform"]) is str and value["platform"] in {"android", "ios"}
        and value["operation"] == "build" and type(value["operation"]) is str)
    return dict(value)


def _json_bytes(value: object) -> bytes:
    _check_values(value)
    try:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ProtocolError("Invalid environment diagnostics JSON") from None


@dataclass(frozen=True)
class EnvironmentRequest:
    run_id: str
    owner_generation: str
    context: dict[str, Any]
    draft: dict[str, Any]
    native: dict[str, str]


def parse_request(raw: bytes) -> EnvironmentRequest:
    require(type(raw) is bytes and 2 <= len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n")
        and raw[:1] == b"{" and raw[-2:-1] == b"}" and b"\r" not in raw and b"\n" not in raw[:-1])
    try:
        text = raw[:-1].decode("utf-8", errors="strict")
        _check_depth(text)
        decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)
        value, end = decoder.raw_decode(text)
        require(end == len(text))
        _check_values(value)
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid environment diagnostics JSON") from None
    require(type(value) is dict and set(value) == {
        "protocol", "runId", "ownerGeneration", "context", "draft", "native"})
    require(value["protocol"] == PROTOCOL and type(value["protocol"]) is str)
    for name in ("runId", "ownerGeneration"):
        require(type(value[name]) is str and TOKEN.fullmatch(value[name]) is not None)
    context = context_value(value["context"])
    require(type(value["draft"]) is dict and len(_json_bytes(value["draft"])) <= DRAFT_LIMIT)
    native = value["native"]
    require(type(native) is dict and set(native) == {"profile", "projectRoot", "cwd"}
        and type(native["profile"]) is str and native["profile"] in PROFILES)
    absolute_path(native["projectRoot"])
    absolute_path(native["cwd"])
    return EnvironmentRequest(value["runId"], value["ownerGeneration"], context, value["draft"], dict(native))


def baseline(role: str) -> dict[str, str | None]:
    require(type(role) is str and role in HELP)
    if role in {"java", "javac"}:
        return {"kind": "workflow-reference", "version": "21", "build": None}
    if role == "xcode":
        return {"kind": "exact-pin", "version": XCODE_VERSION, "build": XCODE_BUILD}
    return {"kind": "no-local-policy", "version": None, "build": None}


def row(role: str, state: str = "not-run", reason: str = "stopped", *, version: str | None = None,
        build: str | None = None, returncode: int | None = None) -> dict[str, Any]:
    assessment = "not-assessed"
    if reason == "observed" and role != "developer-selection":
        assessment = ("match" if (version, build) == (XCODE_VERSION, XCODE_BUILD) else "mismatch") if role == "xcode" else "no-local-policy"
    value = {"id": role, "state": state, "reason": reason, "version": version, "build": build,
             "returnCode": returncode, "baseline": baseline(role), "assessment": assessment, "help": HELP[role]}
    validate_row(value)
    return value


def validate_row(value: object) -> None:
    require(type(value) is dict and set(value) == {
        "id", "state", "reason", "version", "build", "returnCode", "baseline", "assessment", "help"})
    assert isinstance(value, dict)
    role = value["id"]
    require(type(role) is str and role in HELP)
    require(type(value["state"]) is str and value["state"] in {"not-run", "attempted", "completed"})
    reasons = {"not-run": NOT_RUN, "attempted": ATTEMPTED, "completed": COMPLETED}
    require(type(value["reason"]) is str and value["reason"] in reasons[value["state"]])
    require(type(value["baseline"]) is dict and value["baseline"] == baseline(role)
        and type(value["help"]) is str and value["help"] == HELP[role])
    version, build = value["version"], value["build"]
    require(version is None or type(version) is str and _VERSION.fullmatch(version) is not None)
    require(build is None or type(build) is str and _BUILD.fullmatch(build) is not None)
    require(type(value["assessment"]) is str
        and value["assessment"] in {"match", "mismatch", "no-local-policy", "not-assessed"})
    if value["state"] != "completed":
        require(version is None and build is None and value["returnCode"] is None and value["assessment"] == "not-assessed")
        require(value["reason"] != "full-xcode-not-selected" or role == "xcode")
        return
    require(integer(value["returnCode"], 2**31 - 1, -(2**31)))
    require((value["reason"] == "nonzero-exit") == (value["returnCode"] != 0))
    if value["reason"] != "observed":
        require(version is None and build is None and value["assessment"] == "not-assessed")
        require((value["reason"] == "selection-unrecognized") == (role == "developer-selection" and value["reason"] != "nonzero-exit"))
    elif role == "developer-selection":
        require(version is None and build is None and value["assessment"] == "not-assessed")
    elif role == "xcode":
        require(version is not None and _ROLE_VERSION[role].fullmatch(version) is not None
            and build is not None and value["assessment"] == (
            "match" if (version, build) == (XCODE_VERSION, XCODE_BUILD) else "mismatch"))
    else:
        require(version is not None and _ROLE_VERSION[role].fullmatch(version) is not None
            and build is None and value["assessment"] == "no-local-policy")


def parse_version(role: str, stdout: bytes, stderr: bytes) -> tuple[str, str | None] | None:
    """Complete bounded bytes only; no stripping, replacement decoding or substring match."""
    require(type(role) is str and role in {"git", "java", "javac", "xcode"})
    require(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= OUTPUT_LIMIT)
    if role in {"java", "javac"}:
        if bool(stdout) == bool(stderr):
            return None
        content = stdout or stderr
    else:
        if stderr:
            return None
        content = stdout
    match = {"git": _GIT, "java": _JAVA, "javac": _JAVAC, "xcode": _XCODE}[role].fullmatch(content)
    if match is None:
        return None
    version = match.group(1).decode("ascii")
    if _VERSION.fullmatch(version) is None:
        return None
    return version, match.group(2).decode("ascii") if role == "xcode" else None


def assurance(attempts: int) -> dict[str, Any]:
    require(integer(attempts, 4))
    return {"basis": "local-tool-observation", "toolsAttempted": attempts > 0,
        "projectCodeExecuted": False, "projectFilesRead": False, "repositoryObserved": False,
        "sdkInspected": False, "credentialsRead": False, "storeContacted": False,
        "dependencyCompleteness": "unknown", "releaseReadiness": "unknown", "toolCacheEffects": "possible"}


def validate_terminal(value: object, request: EnvironmentRequest) -> None:
    require(type(value) is dict and set(value) == {"schemaVersion", "policyVersion", "context", "hostPlatform",
        "outcome", "checks", "commandsAttempted", "lifetime", "assurance"})
    assert isinstance(value, dict)
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
        and type(value["policyVersion"]) is str and value["policyVersion"] == POLICY
        and value["context"] == request.context and context_value(value["context"]) == request.context)
    host = value["hostPlatform"]
    require(type(host) is str and host in {"linux", "macos"})
    require(host == PROFILES[request.native["profile"]][0])
    require(type(value["outcome"]) is str and value["outcome"] in OUTCOMES)
    checks = value["checks"]
    require(type(checks) is list and len(checks) == len(ROSTERS[(host, request.context["platform"])]))
    for expected, check in zip(ROSTERS[(host, request.context["platform"])], checks):
        validate_row(check)
        require(check["id"] == expected)
    attempts = value["commandsAttempted"]
    require(integer(attempts, 4) and attempts == sum(check["state"] != "not-run" for check in checks))
    if host == "linux" and request.context["platform"] == "ios":
        require(attempts == 0 and all(check["state"] == "not-run" for check in checks))
    global_reasons = {"invalid-draft", "platform-disabled", "host-mismatch", "unsupported-host"}
    for check in checks:
        if check["reason"] in global_reasons:
            require(attempts == 0 and all(other["reason"] == check["reason"] for other in checks))
        if check["reason"] == "host-mismatch":
            require(host == "linux" and request.context["platform"] == "ios")
    expected_assurance = assurance(attempts)
    require(value["assurance"] == expected_assurance)
    require(all(type(value["assurance"][key]) is type(expected) for key, expected in expected_assurance.items()))
    lifetime = value["lifetime"]
    bools = {"complete", "fatal", "contained", "inputClosed", "handlersRestored", "toolDescriptorsClosed"}
    require(type(lifetime) is dict and set(lifetime) == bools | {"commandDispatched", "commands", "stopObserved"})
    require(all(type(lifetime[key]) is bool for key in bools)
        and (lifetime["commandDispatched"] is None or type(lifetime["commandDispatched"]) is bool)
        and integer(lifetime["commands"], attempts)
        and type(lifetime["stopObserved"]) is str and lifetime["stopObserved"] in {"none", "cancelled", "timed-out"})
    require(lifetime["fatal"] or lifetime["complete"] and lifetime["contained"]
        and lifetime["commandDispatched"] is not None)
    settled = (lifetime["complete"] and not lifetime["fatal"] and lifetime["contained"]
        and lifetime["commandDispatched"] is not None and lifetime["inputClosed"]
        and lifetime["handlersRestored"] and lifetime["toolDescriptorsClosed"])
    completed = sum(check["state"] == "completed" for check in checks)
    require(completed <= lifetime["commands"] and (not completed or lifetime["commandDispatched"] is True))
    for check in checks:
        if check["state"] == "attempted" and check["reason"] in {"cancelled", "timed-out"}:
            require(check["reason"] == lifetime["stopObserved"])
    outcome = value["outcome"]
    if outcome in {"complete", "unavailable"}:
        require(settled and lifetime["stopObserved"] == "none" and all(
            check["state"] != "attempted" and check["reason"] != "stopped" for check in checks))
        require((outcome == "unavailable") == (attempts == 0))
        require(lifetime["commands"] == attempts and lifetime["commandDispatched"] == (attempts > 0))
    elif outcome in {"partial", "failed"}:
        require((outcome == "partial") == (completed > 0) and lifetime["stopObserved"] == "none")
    else:
        require(lifetime["stopObserved"] == outcome)


def response(request: EnvironmentRequest, kind: str, result: dict[str, Any]) -> bytes:
    require(type(request) is EnvironmentRequest and type(kind) is str and kind in {"accepted", "terminal"})
    if kind == "accepted":
        require(type(result) is dict and set(result) == {"schemaVersion", "context", "hostPlatform"}
            and type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
            and result["context"] == request.context and context_value(result["context"]) == request.context
            and result["hostPlatform"] == PROFILES[request.native["profile"]][0])
    else:
        validate_terminal(result, request)
    raw = _json_bytes({"protocol": PROTOCOL, "runId": request.run_id, "ownerGeneration": request.owner_generation,
        "seq": 0 if kind == "accepted" else 1, "kind": kind, "result": result}) + b"\n"
    require(len(raw) <= RESPONSE_LIMIT)
    return raw
