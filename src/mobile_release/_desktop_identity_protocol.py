"""Closed identity DATA framing; the original typed-edit owner alone owns IO.

This is a private fixed child protocol, not a public CLI or filesystem API.
The native owner supplies continuity and all five registered-root facts; a
renderer target/preview never supplies that authority. No build is evaluated.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ._desktop_engine import ProtocolError, _check_depth, _check_values, _constant, _pairs
from .api._json import bounded_json_text
from .config import ANDROID_ID_RE, IOS_ID_RE
from .config_edit import CoreEditOutcome
from .errors import ConfigurationError, ValidationError
from .project_identity import (CONFIG_PATH, MAX_FILE_BYTES, Diagnostic, IdentityInputError,
                               IdentitySelection, public_path, selection_input)

PROTOCOL = "mrk-project-identity/1"
REQUEST_LIMIT = 16 * 1024
RESPONSE_LIMIT = 128 * 1024
TERMINAL_LIMIT = 16 * 1024
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
NEW_WARNING = ("A different identity is a different app. This cannot update your existing app. "
               "Availability in the stores has not been checked.")
INVALIDATIONS = ["credential-assessments-and-assignments", "prepared-release-plans", "candidate-identity-revision"]
RECOVERY_REASONS = {"none", "incomplete_journal", "foreign_journal", "legacy_journal", "invalid_journal",
                    "unsupported_descriptor", "target_changed", "control_changed", "namespace_changed", "inventory_changed"}


def _need(value: bool) -> None:
    if not value:
        raise ProtocolError("Invalid project identity frame")


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == keys)
    return value


def _token(value: Any) -> bool:
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def _integer(value: Any, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _text(value: Any, maximum: int) -> bool:
    return (type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def identity_value(value: Any, platform: str) -> bool:
    return (type(value) is str and len(value) <= 255
            and (ANDROID_ID_RE if platform == "android" else IOS_ID_RE).fullmatch(value) is not None)


def selection(value: Any) -> IdentitySelection:
    _object(value, {"platform", "target", "project", "continuity"})
    return selection_input(IdentitySelection(value["platform"], value["target"], value["project"], value["continuity"]))


def diagnostic(value: Any) -> None:
    _object(value, {"code", "path", "line", "column", "help"})
    _need(type(value["code"]) is str and public_path(value["path"])
          and _integer(value["line"], MAX_FILE_BYTES, 1) and _integer(value["column"], MAX_FILE_BYTES, 1))
    # Fixed core help, never exception/source text supplied by a parser.
    _need(value == Diagnostic(value["code"], value["path"], value["line"], value["column"]).as_dict())


def _locations(rows: Any, platform: str, *, change: bool = False) -> None:
    _need(type(rows) is list and len(rows) <= 65)
    seen = set()
    for row in rows:
        _object(row, {"path", "line", "column", "role"} | ({"beforeId", "afterId"} if change else set()))
        _need(public_path(row["path"]) and _integer(row["line"], MAX_FILE_BYTES, 1)
              and _integer(row["column"], MAX_FILE_BYTES, 1)
              and row["role"] == ("saved-identity" if row["path"] == CONFIG_PATH else
                    "android-application-id" if platform == "android" else "ios-bundle-id"))
        key = tuple(row[name] for name in ("path", "line", "column", "role"))
        _need(key not in seen)
        seen.add(key)
        if change:
            _need(identity_value(row["beforeId"], platform) and identity_value(row["afterId"], platform)
                  and row["beforeId"] != row["afterId"])


def analysis_view(value: Any) -> None:
    _object(value, {"schemaVersion", "kind", "revision", "selection", "state", "identity", "configuredIdentity",
                    "identityStatus", "configurations", "locations", "diagnostics", "nextStep", "scope", "buildVerificationRequired"})
    chosen = selection(value["selection"])
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["kind"] == "project-identity"
          and _token(value["revision"]) and type(value["state"]) is str and value["state"] in {"supported", "unsupported"}
          and value["scope"] == "recognized-literal-source-only" and value["buildVerificationRequired"] is True
          and _text(value["nextStep"], 1024) and value["identityStatus"] in (None, "unverified", "approved", "blocked"))
    for name in ("identity", "configuredIdentity"):
        _need(value[name] is None or identity_value(value[name], chosen.platform))
    names = value["configurations"]
    _need(type(names) is list and len(names) <= 32 and all(_text(name, 80) for name in names) and len(names) == len(set(names)))
    _locations(value["locations"], chosen.platform)
    _need(type(value["diagnostics"]) is list and len(value["diagnostics"]) <= 1)
    for item in value["diagnostics"]:
        diagnostic(item)
    if value["state"] == "supported":
        _need(value["identity"] is not None and value["identity"] == value["configuredIdentity"]
              and value["identityStatus"] is not None and len(names) > 0 and len(value["locations"]) >= 2
              and sum(row["role"] == "saved-identity" for row in value["locations"]) == 1 and not value["diagnostics"])
    else:
        _need(len(value["diagnostics"]) == 1)


def preview_view(value: Any) -> None:
    _object(value, {"schemaVersion", "kind", "revision", "selection", "intent", "state", "changes", "warnings",
                    "invalidations", "retainVersionReservations", "buildVerificationRequired"})
    chosen = selection(value["selection"])
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["kind"] == "project-identity-preview"
          and _token(value["revision"]) and value["intent"] in ("preserve", "new-application")
          and value["state"] in ("change", "unchanged") and value["retainVersionReservations"] is True
          and value["buildVerificationRequired"] is True)
    _locations(value["changes"], chosen.platform, change=True)
    if value["state"] == "unchanged":
        _need(value["changes"] == value["warnings"] == value["invalidations"] == [])
    else:
        rows = value["changes"]
        _need(chosen.continuity == "unknown" and value["intent"] == "new-application" and len(rows) >= 2
              and sum(row["role"] == "saved-identity" for row in rows) == 1
              and len({row["beforeId"] for row in rows}) == len({row["afterId"] for row in rows}) == 1
              and value["warnings"] == [NEW_WARNING] and value["invalidations"] == INVALIDATIONS)


def recovery_view(value: Any) -> None:
    _object(value, {"schemaVersion", "kind", "state", "reason", "action", "transactionId", "desiredIdentity",
                    "files", "help", "privateCleanup", "retainVersionReservations"})
    cleanup = _object(value["privateCleanup"], {"fileCount", "directoryCount", "scope"})
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["kind"] == "project-identity-recovery"
          and value["state"] in ("idle", "recoverable", "conflict") and type(value["reason"]) is str
          and value["reason"] in RECOVERY_REASONS and value["retainVersionReservations"] is True and _text(value["help"], 1024)
          and type(value["files"]) is list and len(value["files"]) <= 64
          and cleanup["scope"] == "inspected-owned-journal-only" and _integer(cleanup["fileCount"], 1024)
          and _integer(cleanup["directoryCount"], 1025))
    if value["state"] != "recoverable":
        _need(value["action"] is None and value["transactionId"] is None and value["desiredIdentity"] is None
              and not value["files"] and cleanup["fileCount"] == cleanup["directoryCount"] == 0
              and (value["state"] == "idle") == (value["reason"] == "none"))
        return
    _need(value["reason"] == "none" and _token(value["transactionId"]) and value["action"] in
          ("rollback", "preparing_cleanup", "committed_cleanup", "rolled_back_cleanup") and cleanup["directoryCount"] >= 1
          and (identity_value(value["desiredIdentity"], "android") or identity_value(value["desiredIdentity"], "ios")))
    seen = set()
    for row in value["files"]:
        _object(row, {"path", "action", "beforeBytes", "afterBytes"})
        _need(public_path(row["path"]) and row["path"] not in seen and _integer(row["beforeBytes"], MAX_FILE_BYTES)
              and (row["afterBytes"] is None or _integer(row["afterBytes"], MAX_FILE_BYTES))
              and row["action"] == ("restore_original" if value["action"] == "rollback" and row["afterBytes"] is not None else "preserve"))
        seen.add(row["path"])


def parse_request(raw: bytes, *, sequence: int, session: str | None):
    from ._desktop_edit_protocol import EditRequest, registered_identity
    _need(type(sequence) is int and sequence in {0, 1, 2} and type(raw) is bytes and 2 <= len(raw) <= REQUEST_LIMIT
          and raw[:1] == b"{" and raw[-2:] == b"}\n" and b"\r" not in raw and b"\n" not in raw[:-1])
    try:
        text = raw[:-1].decode("utf-8", errors="strict")
        _check_depth(text)
        value, end = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant).raw_decode(text)
        _need(end == len(text))
        _check_values(value)
        _object(value, {"protocol", "session", "seq", "op", "params"})
        _need(value["protocol"] == PROTOCOL and _token(value["session"]) and (session is None or value["session"] == session)
              and type(value["seq"]) is int and value["seq"] == sequence and type(value["op"]) is str and type(value["params"]) is dict)
        op, params = value["op"], value["params"]
        if op == "discard":
            _need(sequence in {1, 2} and not params)
        else:
            intent = params.get("intent")
            _need(type(intent) is str and intent in {"edit", "recover"})
            if sequence == 0:
                _object(params, {"root", "registeredIdentity", "intent"} | ({"selection"} if intent == "edit" else set()))
                _need(op == "open" and _text(params["root"], 4096))
                registered_identity(params["registeredIdentity"])
                if intent == "edit":
                    selection(params["selection"])
            elif sequence == 1:
                _object(params, {"revision", "intent"} | ({"desiredIdentity", "identityIntent"} if intent == "edit" else set()))
                _need(op == "prepare" and _token(params["revision"]))
                if intent == "edit":
                    _need(params["identityIntent"] in ("preserve", "new-application")
                          and (identity_value(params["desiredIdentity"], "android") or identity_value(params["desiredIdentity"], "ios")))
            else:
                _object(params, {"planToken", "intent"})
                _need(op == "apply" and _token(params["planToken"]))
        return EditRequest(value["session"], sequence, op, params, PROTOCOL)
    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError, ConfigurationError):
        raise ProtocolError("Invalid project identity request") from None


def response(request: Any, kind: str, result: dict[str, Any]) -> bytes:
    _need(request.protocol == PROTOCOL and kind in ("opened", "prepared", "terminal"))
    try:
        _need(type(result) is dict and result.get("intent") in ("edit", "recover"))
        if kind == "terminal":
            _object(result, {"intent", "planToken", "effect", "journal", "resources", "reason", "diagnostic"})
            CoreEditOutcome(*(result[key] for key in ("effect", "journal", "resources", "reason")))
            _need(result["planToken"] is None or _token(result["planToken"]))
            if result["diagnostic"] is not None:
                diagnostic(result["diagnostic"])
                _need(result["intent"] == "edit" and result["planToken"] is None and result["reason"] != "none")
        else:
            _object(result, {"intent", "revision", "view", "scopeResources"} | ({"planToken"} if kind == "prepared" else set()))
            _need(_token(result["revision"]) and result["scopeResources"] == "settled")
            if kind == "prepared":
                _need(_token(result["planToken"]) and result["planToken"] != result["revision"])
            if result["intent"] == "recover":
                recovery_view(result["view"])
                _need(kind != "prepared" or result["view"]["state"] == "recoverable")
            else:
                (analysis_view if kind == "opened" else preview_view)(result["view"])
                _need(result["view"]["revision"] == result["revision"])
        value = {"protocol": PROTOCOL, "session": request.session, "seq": request.seq, "kind": kind, "result": result}
        _check_values(value)
        bounded_json_text(value, max_bytes=(TERMINAL_LIMIT if kind == "terminal" else RESPONSE_LIMIT) - 1, max_depth=24, max_nodes=12000)
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError, ValidationError):
        raise ProtocolError("Invalid project identity response") from None
