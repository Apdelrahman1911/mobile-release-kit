"""G1A: credential-free projection of supplied read observations and fixed help.

Only fixed help is exposed through catalog; projection is not an API method.
No HTTP, gh, project reads or native
session/revision/capability/expiry authority. Supplied HTTP outcomes are DATA,
not evidence that a request, TLS verification or original settlement occurred.
"""
from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from importlib.resources import files
from typing import Any, cast

from ..errors import ConfigurationError
from ..workflow_payloads import GITHUB_WORKFLOWS, TOOLING_REPOSITORY_RE
from ._json import bounded_json_text
from .contracts import ApiError

INPUT_IDS = ("repository", "token")
GUIDANCE_IDS = ("authentication", "permissions", "session-memory", "repository-identity",
                "automation-observation", "remote-changes", "revocation")
REASONS = ("none", "unqualified", "runtime-unavailable", "publisher-unconfigured",
           "not-connected", "invalid-input", "busy", "unauthorized", "forbidden",
           "not-found-or-inaccessible", "target-changed", "rate-limited", "network-unavailable",
           "tls-failed", "response-invalid", "response-limit", "expired", "stale", "cancelled",
           "cleanup-unknown")
MAX_RESOURCE_BYTES = 32 * 1024
MAX_RESULT_BYTES = 64 * 1024
_TRANSPORT_FAILURES = {"network-unavailable", "tls-failed", "response-invalid", "response-limit", "rate-limited", "cancelled"}
_HELP_FIELDS = {"id", "label", "what", "why", "where", "format", "failure"}
_INPUT_KEYS = {"repository", "observedAt", "expectedAccountId", "expectedRepositoryId",
               "account", "repositoryBefore", "workflowPages", "repositoryAfter"}


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid closed GitHub observation data")


def _object(value: object, keys: set[str]) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys)
    return cast(dict[str, Any], value)


def _text(value: object, limit: int) -> str:
    _require(type(value) is str and 0 < len(value) <= limit)
    text = cast(str, value)
    _require(bool(text.strip()) and len(text.encode("utf-8")) <= limit)
    _require(not any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in text))
    return text


def _coordinate(value: object) -> str:
    text = _text(value, 140)
    _require(TOOLING_REPOSITORY_RE.fullmatch(text) is not None)
    return text


def _id(value: object, *, upstream: bool = False) -> str:
    # GitHub JSON numeric IDs are parsed exactly by Python, never via a JS float.
    if upstream and type(value) is int:
        _require(0 < value <= 2**64 - 1)
        return str(value)
    _require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None)
    text = cast(str, value)
    _require(int(text) <= 2**64 - 1)
    return text


def _utc(value: object) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is not None)
    text = cast(str, value)
    datetime(int(text[:4]), int(text[5:7]), int(text[8:10]), int(text[11:13]), int(text[14:16]), int(text[17:19]))
    return text  # Display DATA only; no now(), timers or deadline admission.


def _reason(value: object) -> str:
    _require(type(value) is str and value in REASONS)
    return cast(str, value)


def _fact(value: object, time: str | None, reason: str = "none") -> dict[str, Any]:
    return {"state": "observed" if value is not None else "unavailable",
            "value": value, "observedAt": time if value is not None else None, "reason": reason}


def _read(value: object) -> tuple[dict[str, Any] | None, str]:
    row = _object(value, {"status", "body", "failure"})
    code, body, failure = row["status"], row["body"], _reason(row["failure"])
    if code is None:
        _require(body is None and failure in _TRANSPORT_FAILURES)
        return None, failure
    _require(type(code) is int and 100 <= code <= 599 and failure == "none")
    if code != 200:
        _require(body is None)  # Raw upstream error bodies never enter the projector.
        return None, {401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible", 429: "rate-limited"}.get(
            code, "network-unavailable" if code >= 500 else "response-invalid")
    _require(type(body) is dict)
    bounded_json_text(body, max_bytes=256 * 1024, max_nodes=20_000, max_depth=24)
    return cast(dict[str, Any], body), "none"


def _account(body: dict[str, Any]) -> dict[str, Any]:
    return {"id": _id(body.get("id"), upstream=True), "login": _text(body.get("login"), 96)}


def _repository(body: dict[str, Any]) -> dict[str, Any]:
    visibility, archived = body.get("visibility"), body.get("archived")
    _require(visibility in ("public", "private", "internal") and type(archived) is bool)
    reported = body.get("permissions", {})
    _require(type(reported) is dict)
    permissions = {}
    for role in ("pull", "push", "admin"):
        value = reported.get(role)
        _require(value is None or type(value) is bool)
        permissions[role] = "unknown" if value is None else "reported-allowed" if value else "reported-denied"
    return {"id": _id(body.get("id"), upstream=True), "fullName": _coordinate(body.get("full_name")),
            "defaultBranch": _text(body.get("default_branch"), 1024), "visibility": visibility,
            "archived": archived, "permissions": permissions}


def _automation(pages: list[tuple[dict[str, Any] | None, str]], time: str) -> dict[str, Any]:
    if not pages:
        return _fact(None, None, "response-invalid")
    rows: list[tuple[str, str, str]] = []
    totals, counts = [], []
    for body, reason in pages:
        if body is None:
            return _fact(None, None, reason)
        total, workflows = body.get("total_count"), body.get("workflows")
        _require(type(total) is int and 0 <= total <= 2**32 - 1)
        _require(type(workflows) is list and len(workflows) <= 100)
        totals.append(total)
        counts.append(len(workflows))
        for row in workflows:
            _require(type(row) is dict)
            identity, path = _id(row.get("id"), upstream=True), _text(row.get("path"), 1024)
            state = row.get("state")
            _require(type(state) is str and len(state.encode("utf-8")) <= 96)
            rows.append((identity, path, "active" if state == "active" else
                         "disabled" if state in ("disabled_fork", "disabled_inactivity", "disabled_manually") else "unknown"))
    ambiguous = (len(set(totals)) != 1 or len({r[0] for r in rows}) != len(rows)
                 or len({r[1] for r in rows}) != len(rows) or totals[0] < len(rows)
                 or len(pages) == 2 and counts[0] != 100)
    complete = not ambiguous and totals[0] == len(rows)
    by_path = {} if ambiguous else {path: (identity, state) for identity, path, state in rows}
    selected = []
    for identity, path in GITHUB_WORKFLOWS:
        found = by_path.get(path)
        selected.append({"id": identity, "remoteId": found[0] if found else None,
                         "presence": "listed" if found else "not-listed" if complete else "unknown",
                         "state": found[1] if found else "unknown"})
    return _fact({"coverage": "complete" if complete else "limited", "workflows": selected}, time)


def project_github_observations(value: object) -> dict[str, Any]:
    """Project at most five supplied read results, never a token or native status.

    The future trusted owner supplies its original target/expected immutable IDs
    and display timestamp. This pure function does not establish that ownership.
    Unknown upstream success fields are bounded, then discarded by whitelisting.
    """
    try:
        bounded_json_text(value, max_bytes=1024 * 1024, max_nodes=20_000, max_depth=24)
        request = _object(value, _INPUT_KEYS)
        target, time = _coordinate(request["repository"]), _utc(request["observedAt"])
        expected_account, expected_repository = request["expectedAccountId"], request["expectedRepositoryId"]
        if expected_account is not None:
            _id(expected_account)
        if expected_repository is not None:
            _id(expected_repository)
            _require(expected_account is not None)
        raw_pages = request["workflowPages"]
        _require(type(raw_pages) is list and len(raw_pages) <= 2)
        account_body, account_reason = _read(request["account"])
        before, before_reason = _read(request["repositoryBefore"])
        pages = [_read(page) for page in raw_pages]
        after, after_reason = _read(request["repositoryAfter"])
        unavailable = lambda reason: _fact(None, None, reason)
        result = {"schemaVersion": 1, "account": unavailable(account_reason),
                  "repository": unavailable(account_reason), "automation": unavailable(account_reason)}
        if account_body is not None:
            account = _account(account_body)
            if expected_account is not None and account["id"] != expected_account:
                result.update({key: unavailable("target-changed") for key in ("account", "repository", "automation")})
            else:
                result["account"] = _fact(account, time)
                reason = before_reason if before is None else after_reason if after is None else "none"
                if before is not None and after is not None:
                    repository, ending = _repository(before), _repository(after)
                    if (repository["fullName"].lower() != target.lower() or ending["fullName"].lower() != target.lower()
                            or repository["id"] != ending["id"]
                            or expected_repository is not None and repository["id"] != expected_repository):
                        reason = "target-changed"
                    else:
                        # End read brackets identity only, not an atomic settings snapshot.
                        result["repository"] = _fact(repository, time)
                        result["automation"] = _automation(pages, time)
                if reason != "none":
                    result.update({key: unavailable(reason) for key in ("repository", "automation")})
        _projection(result)
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError, ConfigurationError, OverflowError):
        raise ApiError("github_observation_invalid", "Supplied GitHub observations do not satisfy the bounded read-only contract") from None


def _projection(value: object) -> dict[str, Any]:
    bounded_json_text(value, max_bytes=MAX_RESULT_BYTES, max_nodes=2000, max_depth=12)
    result = _object(value, {"schemaVersion", "account", "repository", "automation"})
    _require(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1)
    for name in ("account", "repository", "automation"):
        fact = _object(result[name], {"state", "value", "observedAt", "reason"})
        reason, state, item = _reason(fact["reason"]), fact["state"], fact["value"]
        if state in ("not-observed", "unavailable"):
            _require(item is None and fact["observedAt"] is None and reason != "none")
            _require(state != "not-observed" or reason == "not-connected")
            continue
        _require(state in ("observed", "stale") and (reason == "none") == (state == "observed"))
        _utc(fact["observedAt"])
        if name == "account":
            row = _object(item, {"id", "login"})
            _id(row["id"])
            _text(row["login"], 96)
        elif name == "repository":
            row = _object(item, {"id", "fullName", "defaultBranch", "visibility", "archived", "permissions"})
            _id(row["id"])
            _coordinate(row["fullName"])
            _text(row["defaultBranch"], 1024)
            _require(row["visibility"] in ("public", "private", "internal") and type(row["archived"]) is bool)
            permissions = _object(row["permissions"], {"pull", "push", "admin"})
            _require(all(v in ("reported-allowed", "reported-denied", "unknown") for v in permissions.values()))
        else:
            row = _object(item, {"coverage", "workflows"})
            _require(row["coverage"] in ("complete", "limited") and type(row["workflows"]) is list and len(row["workflows"]) == 4)
            seen = set()
            for workflow, (identity, _) in zip(row["workflows"], GITHUB_WORKFLOWS):
                record = _object(workflow, {"id", "remoteId", "presence", "state"})
                _require(record["id"] == identity and record["presence"] in ("listed", "not-listed", "unknown"))
                _require(record["state"] in ("active", "disabled", "unknown"))
                if record["presence"] == "listed":
                    remote = _id(record["remoteId"])
                    _require(remote not in seen)
                    seen.add(remote)
                else:
                    _require(record["remoteId"] is None and record["state"] == "unknown")
                _require(record["presence"] != ("unknown" if row["coverage"] == "complete" else "not-listed"))
    _require(result["repository"]["value"] is None or result["account"]["value"] is not None)
    _require(result["automation"]["value"] is None or result["repository"]["value"] is not None)
    _require(result["repository"]["state"] != "observed" or result["account"]["state"] == "observed")
    _require(result["automation"]["state"] != "observed" or result["repository"]["state"] == "observed")
    return result


def stale_github_observations(value: object, reason: object = "stale") -> dict[str, Any]:
    """Label retained facts without changing their IDs/times or renewing a session."""
    try:
        result = _projection(value)
        why = _reason(reason)
        _require(why not in ("none", "not-connected"))
        copy = json.loads(bounded_json_text(result, max_bytes=MAX_RESULT_BYTES, max_nodes=2000, max_depth=12))
        for name in ("account", "repository", "automation"):
            if copy[name]["value"] is not None:
                copy[name].update(state="stale", reason=why)
        return copy
    except (ValueError, TypeError, UnicodeError, RecursionError, ConfigurationError, OverflowError):
        raise ApiError("github_observation_invalid", "Retained GitHub observations do not satisfy the closed stale-fact contract") from None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _nonfinite(_text: str) -> None:
    raise ValueError("Non-finite bundled JSON")


def _read_resource_bytes() -> bytes:
    with files("mobile_release.api").joinpath("data", "github-connection-v1.json").open("rb") as source:
        return source.read(MAX_RESOURCE_BYTES + 1)


def github_connection_help() -> dict[str, Any]:
    """Pre-input help for a later catalog seam; no token/transport is involved."""
    try:
        raw = _read_resource_bytes()
        _require(type(raw) is bytes and len(raw) <= MAX_RESOURCE_BYTES)
        result = _object(json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite), {"schemaVersion", "inputs", "guidance"})
        bounded_json_text(result, max_bytes=MAX_RESOURCE_BYTES, max_nodes=2000, max_depth=12)
        _require(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1)
        for name, ids in (("inputs", INPUT_IDS), ("guidance", GUIDANCE_IDS)):
            rows = result[name]
            _require(type(rows) is list and len(rows) == len(ids))
            for raw_row, identity in zip(rows, ids):
                row = _object(raw_row, _HELP_FIELDS | {"requiredness"} if name == "inputs" else _HELP_FIELDS)
                _require(row["id"] == identity)
                _text(row["label"], 96)
                for field in ("what", "why", "where", "format", "failure"):
                    _text(row[field], 1024)
                if name == "inputs":
                    _require(row["requiredness"] == ("required" if identity == "repository" else "conditional"))
        return result
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, ConfigurationError):
        raise ApiError("resource_unavailable", "The bundled GitHub connection help is unavailable or invalid; entry remains disabled") from None
