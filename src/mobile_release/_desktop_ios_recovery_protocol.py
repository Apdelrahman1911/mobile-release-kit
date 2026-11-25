"""Closed recovery DATA for the same iOS owner; no command or path authority."""
from __future__ import annotations

PROTOCOL = "mrk-ios-archive/3"
CONSENT = "local-ios-recovery-v1"
WORK_SECONDS, CLEANUP_SECONDS, FINALITY_SECONDS = 120, 240, 250
COMMAND_LIMIT = 32
STAGES = ("recovering-account", "recovering-project", "disposing-work")
LIMITATIONS = ("local-recovery-only", "manual-recovery-not-supported",
              "user-confirmation-is-not-worker-finality", "no-store-operation")
ACCOUNT_CONFIRMATION = "account-signing-is-idle-and-restore-owned-state"
PROJECT_CONFIRMATION = "project-build-inputs-are-idle-and-restore-owned-state"


def prepare(value: object) -> dict:
    from . import _desktop_ios_archive_protocol as wire
    value = wire._keys(value, {"projectId", "recovery"})
    wire.require(wire._text(value["projectId"], wire._PROJECT))
    choice = value["recovery"]
    wire.require(type(choice) is dict)
    inspect = choice.get("action") == "inspect"
    wire._keys(choice, {"action"} if inspect else {"action", "session"})
    wire.require(choice["action"] in {"inspect", "account", "project"}
                 and (inspect or wire._text(choice["session"], wire._TOKEN)))
    return {"projectId": value["projectId"], "recovery": dict(choice)}


def context(value: object) -> dict:
    from . import _desktop_ios_archive_protocol as wire
    value = wire._keys(value, {"projectId", "recovery", "platform", "operation"})
    wire.require(value["platform"] == "ios" and value["operation"] == "ios-local-recovery")
    return {**prepare({key: value[key] for key in ("projectId", "recovery")}),
            "platform": "ios", "operation": "ios-local-recovery"}


def native(value: object) -> dict:
    from . import _desktop_ios_archive_protocol as wire
    value = wire._keys(value, {"profile", "projectRoot", "rootIdentity", "cwd", "security"})
    wire.require(wire._enum(value["profile"], wire.PROFILES))
    tool = wire._tool_identity(value["security"])
    wire.require(tool["uid"] == 0 and tool["mode"] & 0o022 == 0)
    return {"profile": value["profile"], "projectRoot": wire._path(value["projectRoot"]),
            "rootIdentity": wire._identity(value["rootIdentity"]), "cwd": wire._path(value["cwd"]), "security": tool}


def row(value: object, *, account: bool) -> dict:
    from . import _desktop_ios_archive_protocol as wire
    value = wire._keys(value, {"status", "session", "next"})
    statuses = {"idle", "pending", "busy", "conflict", "manual-required", "recovered", "absent"}
    statuses |= {"recovered-with-conflict"} if account else {"cleanup-only", "not-inspected"}
    state, session, action = value["status"], value["session"], value["next"]
    wire.require(wire._enum(state, statuses) and (session is None or wire._text(session, wire._TOKEN)))
    required = {"pending", "cleanup-only", "manual-required", "recovered", "recovered-with-conflict", "absent"}
    wire.require((state not in required or session is not None)
                 and (state not in {"idle", "not-inspected"} or session is None))
    expected = ({"none"} if state in {"idle", "recovered", "absent"} else {"wait"} if state == "busy"
                else {"manual"} if state == "manual-required" else {"ordinary", "manual"} if state == "pending"
                else {"ordinary"} if state == "cleanup-only" else {"preserve"})
    wire.require(action in expected)
    return dict(value)


def report(value: object, bound: dict) -> dict:
    from . import _desktop_ios_archive_protocol as wire
    value = wire._keys(value, {"schemaVersion", "scope", "account", "project", "limitations"})
    wire.require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                 and value["scope"] == "local-ios-recovery" and value["limitations"] == list(LIMITATIONS))
    action = bound["recovery"]["action"]
    for name in ("account", "project"):
        needed = action in {"inspect", name}
        wire.require(needed == (value[name] is not None))
        if needed:
            checked = row(value[name], account=name == "account")
            if action != "inspect":
                wire.require(checked["session"] == bound["recovery"]["session"]
                             and checked["status"] in {"recovered", "recovered-with-conflict", "absent", "busy", "conflict", "manual-required"})
            else:
                wire.require(checked["status"] not in {"recovered", "recovered-with-conflict", "absent"})
    return value


def validate_terminal(value: object, request) -> None:
    from . import _desktop_ios_archive_protocol as wire
    wire._structure(value)
    value = wire._keys(value, {"schemaVersion", "context", "outcome", "reason", "activity", "report", "lifetime"})
    wire.require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                 and context(value["context"]) == request.context and wire._enum(value["outcome"], wire.OUTCOMES)
                 and wire._enum(value["reason"], wire.REASONS))
    activity = wire._keys(value["activity"], {"stage"})
    wire.require(wire._enum(activity["stage"], ("accepted", *STAGES)))
    life = wire._keys(value["lifetime"], {"complete", "fatal", "contained", "commandDispatched", "commands",
                                        "profileCalls", "stopObserved", *wire.SIGNED_CLOSE_FIELDS})
    wire.require(all(type(life[key]) is bool for key in ("complete", "fatal", "contained", *wire.SIGNED_CLOSE_FIELDS))
                 and (life["commandDispatched"] is None or type(life["commandDispatched"]) is bool)
                 and wire.integer(life["commands"], COMMAND_LIMIT) and wire.integer(life["profileCalls"], 0)
                 and wire._enum(life["stopObserved"], ("none", "cancelled", "timed-out")))
    if life["commandDispatched"] is True:
        wire.require(life["commands"] > 0)
    elif life["commandDispatched"] is False:
        wire.require(life["commands"] <= 1)
    settled = (life["complete"] and not life["fatal"] and life["contained"] and life["commandDispatched"] is not None
               and all(life[key] for key in wire.SIGNED_CLOSE_FIELDS))
    if value["report"] is not None:
        wire.require(settled)
        report(value["report"], request.context)
    if value["outcome"] == "complete":
        wire.require(settled and value["reason"] == life["stopObserved"] == "none"
                     and activity["stage"] == "disposing-work" and value["report"] is not None)
    else:
        wire.require(value["reason"] != "none" and (settled if value["outcome"] != "unknown" else not settled)
                     and (value["reason"] == "cleanup-unknown") is (value["outcome"] == "unknown"))
        if value["outcome"] in {"cancelled", "timed-out"}:
            wire.require(value["outcome"] == value["reason"] == life["stopObserved"])
        if value["outcome"] == "refused":
            wire.require(life["commandDispatched"] is False)
    wire.require(len(wire._encode(value)) <= wire.RESPONSE_LIMIT)
