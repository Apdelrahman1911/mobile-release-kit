"""Closed DATA for the existing iOS owner's check-only material operation.

This is not an account, credential, native-tool or profile authority.  The
original IOSArchive input/worker and its native parent still own all resources.
In particular, a terminal here cannot assign a credential or authorize a build.
"""
from __future__ import annotations

from datetime import datetime
import re

from ._desktop_android_build_protocol import (
    _encode, _enum, _identity, _keys, _path, _structure, _text,
    content, integer, saved_version,
)

PROTOCOL = "mrk-ios-signing-inputs-check/1"
OPERATION = "ios-signing-inputs-check"
ACTION = "check-signing"
CONSENT = "saved-ios-signing-inputs-check-v1"
SCOPE = "local-ios-signing-inputs-validation"
INTENT_SECONDS, WORK_SECONDS, FINALITY_SECONDS = 60, 300, 310
COMMAND_LIMIT, PROFILE_LIMIT = 7, 1
STAGES = ("inputs-bound", "checking-signing-tools", "validating-signing", "checking-inputs")
CHECKS = ("signing-material", "profile-material", "firebase-material", "other-core-finding")
LIMITATIONS = (
    "saved-inputs-not-atomic", "single-primary-profile", "offline-not-live-revocation",
    "no-build-or-installed-signing-session", "no-provider-operation",
    "historical-input-check-not-credential-assignment", "release-readiness-not-assessed",
    "core-terminal-requires-original-native-finality",
)
_PREPARE = {"projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion", "signing", "action"}
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def is_check(value: object) -> bool:
    return type(value) is dict and value.get("operation") == OPERATION


def prepare(value: object) -> dict:
    from . import _desktop_ios_archive_protocol as archive
    value = _keys(value, _PREPARE)
    archive.require(value["action"] == ACTION)
    # Reuse the unchanged signed-input grammar, then narrow its role roster.
    plain = archive.prepare({key: value[key] for key in _PREPARE - {"action"}})
    kinds = [row["kind"] for row in plain["signing"]["assignments"]]
    archive.require(kinds in (["apple-p12", "apple-profile"], ["apple-p12", "apple-profile", "ios-firebase"]))
    result = {**plain, "action": ACTION}
    archive.require(len(_encode(result)) <= archive.RENDERER_REQUEST_LIMIT)
    return result


def context(value: object) -> dict:
    from ._desktop_ios_archive_protocol import require
    value = _keys(value, _PREPARE | {"platform", "operation"})
    require(value["platform"] == "ios" and value["operation"] == OPERATION)
    return {**prepare({key: value[key] for key in _PREPARE}), "platform": "ios", "operation": OPERATION}


def native(value: object) -> dict:
    from ._desktop_ios_archive_protocol import PROFILES, _tool_identity, require
    value = _keys(value, {"profile", "projectRoot", "rootIdentity", "cwd", "openssl", "signingContext"})
    require(_enum(value["profile"], PROFILES))
    tool = _tool_identity(value["openssl"])
    require(tool["uid"] == 0 and tool["mode"] & 0o022 == 0)
    return {"profile": value["profile"], "projectRoot": _path(value["projectRoot"]),
            "rootIdentity": _identity(value["rootIdentity"]), "cwd": _path(value["cwd"]),
            "openssl": tool, "signingContext": content(value["signingContext"], maximum=512 * 1024)}


def findings(value: object) -> list[dict]:
    from ._desktop_ios_archive_protocol import STATUSES, require
    require(type(value) is list and len(value) <= 4)
    for row in value:
        _keys(row, {"check", "status"})
        require(_enum(row["check"], CHECKS) and _enum(row["status"], STATUSES))
    require(len({row["check"] for row in value}) == len(value))
    return value


def expected_checks(selected: dict) -> set[str]:
    result = {"signing-material", "profile-material"}
    if any(row["kind"] == "ios-firebase" for row in selected["signing"]["assignments"]):
        result.add("firebase-material")
    return result


def result_data(value: object, selected: dict) -> dict:
    from ._desktop_ios_archive_protocol import require, signing_context
    selected = context(selected)
    value = _keys(value, {"schemaVersion", "scope", "checkedAt", "usedConfig", "usedVersion",
                          "usedSigning", "checks", "limitations"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE
            and content(value["usedConfig"]) == selected["savedConfig"]
            and saved_version(value["usedVersion"]) == selected["savedVersion"]
            and signing_context(value["usedSigning"]) == selected["signing"]
            and value["limitations"] == list(LIMITATIONS) and _text(value["checkedAt"], _TIME))
    try:
        datetime.strptime(value["checkedAt"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        require(False)
    rows = findings(value["checks"])
    require({row["check"] for row in rows} == expected_checks(selected)
            and all(row["status"] == "PASS" for row in rows))
    return value


def validate_terminal(value: object, request) -> None:
    from . import _desktop_ios_archive_protocol as archive
    archive._request_binding(request)
    selected = context(request.context)
    _structure(value)
    value = _keys(value, {"schemaVersion", "context", "outcome", "reason", "activity", "disposition", "result", "lifetime"})
    archive.require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
        and context(value["context"]) == selected and _enum(value["outcome"], archive.OUTCOMES)
        and _enum(value["reason"], archive.REASONS))
    activity = _keys(value["activity"], {"stage", "findings"})
    archive.require(_enum(activity["stage"], ("accepted", *STAGES)))
    rows = findings(activity["findings"])
    closes = archive.SIGNED_CLOSE_FIELDS
    life = _keys(value["lifetime"], {"complete", "fatal", "contained", "commandDispatched", "commands",
                                   "profileCalls", "stopObserved", *closes})
    archive.require(all(type(life[key]) is bool for key in ("complete", "fatal", "contained", *closes))
        and (life["commandDispatched"] is None or type(life["commandDispatched"]) is bool)
        and integer(life["commands"], COMMAND_LIMIT) and integer(life["profileCalls"], PROFILE_LIMIT)
        and _enum(life["stopObserved"], ("none", "cancelled", "timed-out")))
    if life["commandDispatched"] is False:
        archive.require(life["commands"] <= 1)
    elif life["commandDispatched"] is True:
        archive.require(life["commands"] > 0)
    disposition = _keys(value["disposition"], {"snapshot", "work", "output", "relativeDirectory"})
    # This mode cannot create or retain an archive/work namespace.  Private
    # validation scratch remains covered by the real buildInputsClosed owner.
    archive.require(disposition == {"snapshot": "not-created", "work": "not-created",
                                    "output": "not-created", "relativeDirectory": None})
    settled = (life["complete"] and not life["fatal"] and life["contained"]
               and all(life[key] for key in closes) and life["commandDispatched"] is not None)
    if value["outcome"] == "complete":
        archive.require(settled and value["reason"] == life["stopObserved"] == "none"
                        and activity["stage"] == STAGES[-1] and life["profileCalls"] == 1
                        and life["commandDispatched"] is True and 5 <= life["commands"] <= COMMAND_LIMIT)
        result = result_data(value["result"], selected)
        archive.require(result["checks"] == rows)
    else:
        archive.require(value["result"] is None and value["reason"] != "none"
                        and (settled if value["outcome"] != "unknown" else not settled)
                        and ((value["reason"] == "cleanup-unknown") is (value["outcome"] == "unknown")))
        if value["outcome"] in {"cancelled", "timed-out"}:
            archive.require(value["outcome"] == value["reason"] == life["stopObserved"])
        if value["outcome"] == "refused":
            archive.require(life["commandDispatched"] is False)
    archive.require(len(_encode(value)) <= archive.RESPONSE_LIMIT)
