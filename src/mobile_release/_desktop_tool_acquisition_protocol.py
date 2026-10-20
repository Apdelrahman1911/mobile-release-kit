"""Closed private bootstrap and redacted tool-preparation result DATA.

Only the installed native owner can supply the original request pipe. Parsing
one of these values does not create a native inventory, permit or cache lease.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import re
import stat

from ._tool_acquisition_spec import COMPONENTS, MANIFEST_LIMIT, canonical
from ._tool_requirements_capture import CONFIG, FIXED, module_files

PROTOCOL = "mrk-tool-acquisition/1"
CONSENT = "pinned-public-tool-sources-v1"
REQUEST_LIMIT, RESPONSE_LIMIT = 12 * 1024 * 1024, 64 * 1024
WORK_SECONDS, FINALITY_SECONDS = 1200, 1210
CA_LIMIT = 512 * 1024
CONTROL_LIMIT = 16 * 1024
PROFILES = {"macos-arm64": ("macos", "arm64"), "macos-x86_64": ("macos", "x86_64")}
REASONS = frozenset(("none", "cancelled", "timed-out", "context-changed", "document-lost", "shutdown",
    "runtime-unavailable", "protocol-error", "intent-expired", "stale-intent", "cleanup-unknown", "input-limit", "result-limit",
    "input", "unsupported", "stale", "census-incomplete", "recovery-required", "cache-conflict", "disk-space", "network",
    "redirect", "framing", "archive-digest", "archive-layout", "archive-member", "limit", "already-used", "unknown"))
OUTCOMES = frozenset(("complete", "refused", "failed", "cancelled", "timed-out", "unknown"))
TOKEN = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)
DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z", re.ASCII)
NANOS = re.compile(r"-?(?:0|[1-9][0-9]{0,19})\Z", re.ASCII)


class ProtocolError(ValueError):
    pass


def require(value: bool) -> None:
    if not value:
        raise ProtocolError("Invalid fixed tool-acquisition protocol")


def integer(value, high=2**32 - 2, low=0):
    return type(value) is int and low <= value <= high


def text(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def keys(value, names):
    require(type(value) is dict and set(value) == set(names))
    return value


def choice(value, values):
    return type(value) is str and value in values


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value)
        value[key] = item
    return value


def structure(value, depth=0, count=None):
    count = [0] if count is None else count
    count[0] += 1
    require(depth <= 16 and count[0] <= 8192)
    if type(value) is dict:
        for key, item in value.items():
            require(type(key) is str and len(key) <= 64)
            structure(item, depth + 1, count)
    elif type(value) is list:
        require(len(value) <= 144)
        for item in value:
            structure(item, depth + 1, count)
    elif type(value) is str:
        require(len(value) <= REQUEST_LIMIT)
    elif type(value) is int:
        require(abs(value) <= 2**53 - 1)
    else:
        require(value is None or type(value) is bool)


def path(value):
    require(type(value) is str and 1 <= len(value.encode("utf-8")) <= 4096 and value.startswith("/"))
    if value != "/":
        parts = value[1:].split("/")
        require(len(parts) <= 128 and all(part not in ("", ".", "..") and len(part.encode("utf-8")) <= 255
            and not any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in part) for part in parts))
    return value


def identity(value, *, file=False):
    fields = {"device", "inode", "mode", "uid", "gid"}
    if file:
        fields |= {"links", "bytes", "mtimeNs", "ctimeNs"}
    keys(value, fields)
    require(all(text(value[key], DECIMAL) and int(value[key]) <= 2**64 - 1 for key in ("device", "inode"))
        and value["inode"] != "0" and all(integer(value[key], 2**32 - 1) for key in ("mode", "uid", "gid"))
        and (stat.S_ISREG(value["mode"]) if file else stat.S_ISDIR(value["mode"])))
    if file:
        require(integer(value["links"], 2**32 - 1, 1) and integer(value["bytes"], 512 * 1024)
                and text(value["mtimeNs"], NANOS) and text(value["ctimeNs"], NANOS))
    return value


def content(value):
    keys(value, ("bytes", "sha256"))
    require(integer(value["bytes"], 512 * 1024, 1) and text(value["sha256"], SHA))
    return value


def context(value):
    keys(value, ("projectId", "draftRevision", "baselineGeneration", "savedConfig", "action", "review"))
    require(text(value["projectId"], ID) and integer(value["draftRevision"]) and integer(value["baselineGeneration"])
            and choice(value["action"], ("inspect", "acquire")))
    content(value["savedConfig"])
    if value["action"] == "inspect":
        require(value["review"] is None)
    else:
        keys(value["review"], ("operationId", "ownerGeneration", "requirementsSha256"))
        require(text(value["review"]["operationId"], TOKEN) and text(value["review"]["ownerGeneration"], TOKEN)
                and text(value["review"]["requirementsSha256"], SHA))
    return value


def footprint(value):
    keys(value, ("module", "buildFile", "sourcesSha256", "directories", "missing", "files"))
    try:
        candidates = module_files(value["module"])
    except ValueError:
        raise ProtocolError("Invalid fixed tool-acquisition protocol") from None
    require(choice(value["buildFile"], candidates) and text(value["sourcesSha256"], SHA))
    names = set(FIXED) | set(candidates) | {CONFIG}
    prefixes = {"/".join(name.split("/")[:n]) for name in names for n in range(1, len(name.split("/")))}
    require(type(value["directories"]) is list and len(value["directories"]) <= 132
            and type(value["missing"]) is list and len(value["missing"]) <= 9
            and type(value["files"]) is list and 1 <= len(value["files"]) <= 10)
    dirs, files = [], []
    for row in value["directories"]:
        keys(row, ("relative", "identity"))
        require(choice(row["relative"], prefixes))
        identity(row["identity"])
        dirs.append(row["relative"])
    for row in value["files"]:
        keys(row, ("relative", "identity", "sha256"))
        require(choice(row["relative"], names) and text(row["sha256"], SHA))
        identity(row["identity"], file=True)
        files.append(row["relative"])
    missing = value["missing"]
    require(all(choice(name, names | prefixes) for name in missing))
    for collection in (dirs, files, missing):
        require(collection == sorted(set(collection)))
    require(CONFIG in files and sum(row["identity"]["bytes"] for row in value["files"]) <= 5 * 512 * 1024)
    require(not (set(dirs) & (set(files) | set(missing))) and not (set(files) & set(missing)))
    # Complete fixed negative footprint, not arbitrary path nominations or a
    # missing leaf whose parent was never actually observed.
    for name in names:
        covering = [missing_name for missing_name in missing if name == missing_name or name.startswith(missing_name + "/")]
        require(len(covering) == (0 if name in files else 1))
    for name in dirs + files + missing:
        parts = name.split("/")
        require(all("/".join(parts[:n]) in dirs for n in range(1, len(parts))))
    return value


def decode(value, limit):
    require(type(value) is str and len(value) <= 4 * ((limit + 2) // 3))
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError, binascii.Error):
        raise ProtocolError("Invalid fixed tool-acquisition protocol") from None
    require(0 < len(result) <= limit and base64.b64encode(result).decode("ascii") == value)
    return result


def component_partition(missing, compatible):
    """Canonical DATA only; native source custody is not reconstructed here."""
    require(type(missing) is list and type(compatible) is list and len(missing) + len(compatible) == 4)
    names = [part.value for part in COMPONENTS]
    for parts in (missing, compatible):
        require(all(choice(part, names) for part in parts) and parts == [part for part in names if part in parts])
    require(not set(missing) & set(compatible) and set(missing) | set(compatible) == set(names))
    return (tuple(part for part in COMPONENTS if part.value in missing),
            tuple(part for part in COMPONENTS if part.value in compatible))


def cache(value, *, operation, selected):
    keys(value, ("root", "rootIdentity", "generation", "contextSha256", "referenceSha256", "projectionSha256",
                 "missing", "compatible", "intentBase64", "origins", "footprint"))
    path(value["root"])
    identity(value["rootIdentity"])
    require(value["rootIdentity"]["mode"] == (stat.S_IFDIR | 0o700) and integer(value["generation"], 2**53 - 1, 1)
            and all(text(value[key], SHA) for key in ("contextSha256", "referenceSha256", "projectionSha256")))
    # The SAME native SourceSlots inspection supplies this exact partition.
    # Present wrong/unreadable selections cannot be represented as missing.
    missing, _ = component_partition(value["missing"], value["compatible"])
    require(bool(missing))
    footprint(value["footprint"])
    require(value["footprint"]["sourcesSha256"] == selected["review"]["requirementsSha256"])
    require_saved_config(value["footprint"], selected)
    raw_intent = decode(value["intentBase64"], CONTROL_LIMIT)
    expected = canonical({"schemaVersion": 1, "operationId": operation,
        "contextSha256": value["contextSha256"], "profile": selected["profile"],
        "referenceSha256": value["referenceSha256"], "projectionSha256": value["projectionSha256"],
        "cacheGeneration": value["generation"], "components": value["missing"]})
    require(raw_intent == expected)
    require(type(value["origins"]) is list and len(value["origins"]) <= 31)
    seen = set()
    for row in value["origins"]:
        keys(row, ("operationId", "intentSha256"))
        require(text(row["operationId"], TOKEN) and row["operationId"] != operation and row["operationId"] not in seen
                and text(row["intentSha256"], SHA))
        seen.add(row["operationId"])
    return value


def require_saved_config(observation, selected):
    require(any(row["relative"] == CONFIG and row["identity"]["bytes"] == selected["savedConfig"]["bytes"]
                and row["sha256"] == selected["savedConfig"]["sha256"] for row in observation["files"]))


@dataclass(frozen=True)
class ToolAcquisitionRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict


def parse_request(raw):
    require(type(raw) is bytes and 0 < len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False), parse_float=lambda _: require(False))
        structure(value)
        keys(value, ("protocol", "operationId", "ownerGeneration", "context", "native"))
        require(value["protocol"] == PROTOCOL and text(value["operationId"], TOKEN) and text(value["ownerGeneration"], TOKEN))
        selected = context(value["context"])
        native = keys(value["native"], ("profile", "projectRoot", "rootIdentity", "cwd", "manifestBase64", "caBase64", "cache"))
        require(choice(native["profile"], PROFILES))
        path(native["projectRoot"])
        path(native["cwd"])
        identity(native["rootIdentity"])
        if selected["action"] == "inspect":
            require(native["manifestBase64"] is None and native["caBase64"] is None and native["cache"] is None)
        else:
            cache(native["cache"], operation=value["operationId"], selected={**selected, "profile": native["profile"]})
            manifest = decode(native["manifestBase64"], MANIFEST_LIMIT)
            require(hashlib.sha256(manifest).hexdigest() == native["cache"]["projectionSha256"])
            decode(native["caBase64"], CA_LIMIT)
        return ToolAcquisitionRequest(value["operationId"], value["ownerGeneration"], selected, native)
    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError):
        raise ProtocolError("Invalid fixed tool-acquisition protocol") from None


def requirements(value):
    keys(value, ("schemaVersion", "basis", "sourcesSha256", "complete", "platform", "projectCodeExecuted", "android", "xcode"))
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["basis"] == "unverified-static-source-hints"
            and text(value["sourcesSha256"], SHA) and value["complete"] is True and value["platform"] == "android"
            and value["projectCodeExecuted"] is False)
    keys(value["xcode"], ("version", "build"))
    require(value["xcode"] == {"version": "26.3", "build": "17C529"})
    android = keys(value["android"], ("jdk", "agp", "sdkPlatform", "sdkBuildTools", "gradle"))
    literal = re.compile(r"[A-Za-z0-9_.+-]{1,128}\Z", re.ASCII)
    for field in ("jdk", "agp", "sdkPlatform", "sdkBuildTools"):
        row = keys(android[field], ("state", "value"))
        require((row["state"] == "literal" and text(row["value"], literal))
                or (row["state"] == "unknown" and row["value"] is None)
                or (field in ("jdk", "sdkBuildTools") and row["state"] == "unspecified" and row["value"] is None))
    row = keys(android["gradle"], ("state", "version", "distributionUrl", "sha256"))
    if row["state"] == "unknown":
        require(row["version"] is None and row["distributionUrl"] is None and row["sha256"] is None)
    else:
        require(row["state"] == "literal" and type(row["version"]) is str and len(row["version"]) <= 64
            and re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", row["version"], re.ASCII) is not None
            and choice(row["distributionUrl"], (f"https://services.gradle.org/distributions/gradle-{row['version']}-bin.zip",
                f"https://downloads.gradle.org/distributions/gradle-{row['version']}-bin.zip"))
            and (row["sha256"] is None or text(row["sha256"], SHA)))
    return value


def staged(value, request):
    keys(value, ("schemaVersion", "kind", "operationId", "contextSha256", "referenceSha256", "projectionSha256", "cacheJob",
                 "lookupScope", "reusedArchives", "downloadedArchives", "groups", "assurance"))
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["kind"] == "staged-tool-sources"
            and value["operationId"] == request.operation_id and value["cacheJob"] == "tool-" + request.operation_id
            and value["lookupScope"] == "registered-selected-known")
    require(all(value[key] == request.native["cache"][key] for key in ("contextSha256", "referenceSha256", "projectionSha256")))
    missing, _ = component_partition(request.native["cache"]["missing"], request.native["cache"]["compatible"])
    expected = [part.value for part in missing]
    require(bool(expected))
    all_parts = []
    for field in ("reusedArchives", "downloadedArchives"):
        parts = value[field]
        require(type(parts) is list and all(choice(part, expected) for part in parts)
                and parts == [part for part in expected if part in parts])
        all_parts.extend(parts)
    require(len(all_parts) == len(expected) and set(all_parts) == set(expected))
    groups = value["groups"]
    expected_groups = []
    for group in ("jdk", "sdk", "gradle"):
        components = [part.value for part in missing if part.group == group]
        if components:
            complete = len(components) == sum(part.group == group for part in COMPONENTS)
            expected_groups.append({"group": group, "components": components, "allRequiredComponentsStaged": complete,
                "next": "choose-native-source" if complete else "complete-sdk-manually"})
    require(type(groups) is list and len(groups) == len(expected_groups))
    for row, expected_group in zip(groups, expected_groups):
        keys(row, ("group", "components", "allRequiredComponentsStaged", "next"))
        require(type(row["allRequiredComponentsStaged"]) is bool and row == expected_group)
    assurance = keys(value["assurance"], ("nativeFinality", "registered", "readyToBuild"))
    require(all(item is False for item in assurance.values()))


def validate_terminal(value, request):
    keys(value, ("schemaVersion", "context", "outcome", "reason", "result", "lifetime"))
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and context(value["context"]) == request.context
            and choice(value["outcome"], OUTCOMES) and choice(value["reason"], REASONS))
    life = keys(value["lifetime"], ("complete", "fatal", "contained", "commandDispatched", "commands", "profileCalls",
                                  "inputClosed", "handlersRestored", "resourcesClosed", "stopObserved"))
    require(all(type(life[key]) is bool for key in ("complete", "fatal", "contained", "inputClosed", "handlersRestored", "resourcesClosed"))
            and (life["commandDispatched"] is False or life["commandDispatched"] is None)
            and type(life["commands"]) is int and life["commands"] == 0
            and type(life["profileCalls"]) is int and life["profileCalls"] == 0
            and choice(life["stopObserved"], ("none", "cancelled", "timed-out")))
    settled = (life["complete"] and not life["fatal"] and life["contained"] and life["commandDispatched"] is False
               and life["inputClosed"] and life["handlersRestored"] and life["resourcesClosed"])
    if value["outcome"] == "complete":
        require(settled and value["reason"] == "none" and life["stopObserved"] == "none")
        if request.context["action"] == "inspect":
            result = keys(value["result"], ("kind", "requirements", "footprint"))
            require(result["kind"] == "tool-requirements-observation"
                    and requirements(result["requirements"])["sourcesSha256"] == footprint(result["footprint"])["sourcesSha256"])
            require_saved_config(result["footprint"], request.context)
            require(len(canonical(result["requirements"])) <= CONTROL_LIMIT)
        else:
            staged(value["result"], request)
    else:
        require(value["result"] is None and value["reason"] != "none" and (settled or value["outcome"] == "unknown"))
        if value["outcome"] == "unknown":
            require(value["reason"] == "cleanup-unknown" and not settled)
        if value["outcome"] in ("cancelled", "timed-out"):
            require(value["reason"] == value["outcome"] == life["stopObserved"])


def response(request, kind, payload):
    require(type(request) is ToolAcquisitionRequest and kind in ("accepted", "terminal"))
    if kind == "accepted":
        require(payload == {"schemaVersion": 1, "context": request.context})
    else:
        validate_terminal(payload, request)
    raw = json.dumps({"protocol": PROTOCOL, "operationId": request.operation_id, "ownerGeneration": request.owner_generation,
                      "sequence": 0 if kind == "accepted" else 1,
                      "kind": kind, "payload": payload}, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    require(len(raw) <= RESPONSE_LIMIT)
    return raw
