"""Closed initialization framing, DATA only; the existing owner supplies IO."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ._desktop_engine import ProtocolError, _check_depth, _check_values, _constant, _pairs
from .api._json import bounded_json_text
from .config_edit import CoreEditOutcome
from .errors import ConfigurationError, ValidationError
from .initialization_targets import FIXED_PATHS, INVENTORY_BYTES, VIEW_BYTES, kind as file_kind
from .init_transaction import IGNORE_LINES, MAX_FILE_BYTES, validate_paths
from .workflow_payloads import GITHUB_WORKFLOWS, normalize_tooling_reference, pinned_schema_reference

PROTOCOL = "mrk-project-initialization/1"
REQUEST_LIMIT = RESPONSE_LIMIT = 1024 * 1024
TERMINAL_LIMIT = 16 * 1024
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RECOVERY_REASONS = {"none", "incomplete_journal", "foreign_journal", "legacy_journal", "invalid_journal",
                     "unsupported_descriptor", "resource_changed", "target_changed", "control_changed", "namespace_changed"}


def _need(condition: bool) -> None:
    if not condition:
        raise ProtocolError("Invalid initialization frame")


def _object(value: object, keys: set[str]) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == keys)
    return value


def _integer(value: object, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _token(value: object) -> bool:
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _bounded(value: Any, maximum: int, *, depth: int = 30, nodes: int = 20000) -> None:
    bounded_json_text(value, max_bytes=maximum, max_depth=depth, max_nodes=nodes)


def parse_request(raw: bytes, *, sequence: int, session: str | None):
    from ._desktop_edit_protocol import EditRequest, registered_identity
    _need(type(sequence) is int and sequence in {0, 1, 2} and type(raw) is bytes
          and 2 <= len(raw) <= REQUEST_LIMIT and raw[:1] == b"{" and raw[-2:] == b"}\n"
          and b"\r" not in raw and raw.find(b"\n") == len(raw) - 1)
    try:
        text = raw.decode("utf-8", errors="strict")
        _check_depth(text)
        value, end = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant).raw_decode(text)
        _need(end == len(text) - 1)
        _check_values(value)
        _object(value, {"protocol", "session", "seq", "op", "params"})
        _need(value["protocol"] == PROTOCOL and _token(value["session"])
              and (session is None or value["session"] == session)
              and type(value["seq"]) is int and value["seq"] == sequence
              and type(value["op"]) is str and type(value["params"]) is dict)
        op, params = value["op"], value["params"]
        if sequence == 0:
            intent = params.get("intent")
            _need(type(intent) is str and intent in {"initialize", "recover"})
            _object(params, {"root", "registeredIdentity", "intent"} |
                    ({"draft", "toolingRepository", "toolingSha"} if intent == "initialize" else set()))
            _need(op == "open" and type(params["root"]) is str and len(params["root"].encode("utf-8")) <= 4096)
            registered_identity(params["registeredIdentity"])
            if intent == "initialize":
                _need(type(params["draft"]) is dict and type(params["toolingRepository"]) is str
                      and len(params["toolingRepository"].encode("utf-8")) <= 140
                      and type(params["toolingSha"]) is str and len(params["toolingSha"].encode("utf-8")) <= 40)
                _bounded(params["draft"], 512 * 1024, depth=28, nodes=8000)
        elif op == "discard":
            _need(not params)
        else:
            field = "revision" if sequence == 1 else "planToken"
            _object(params, {field, "intent"})
            _need(op == ("prepare" if sequence == 1 else "apply") and _token(params[field])
                  and type(params["intent"]) is str and params["intent"] in {"initialize", "recover"})
        return EditRequest(value["session"], sequence, op, params, PROTOCOL)
    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError, ConfigurationError):
        raise ProtocolError("Invalid initialization request") from None


def _source(template: Any, tooling: Any) -> None:
    _object(template, {"coreVersion", "resourceVersion", "resourceSha256"})
    _need(type(template["coreVersion"]) is str and len(template["coreVersion"]) <= 32
          and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", template["coreVersion"]) is not None
          and type(template["resourceVersion"]) is int and template["resourceVersion"] == 1
          and _digest(template["resourceSha256"]))
    _object(tooling, {"repository", "sha", "schemaReference", "state"})
    repository, sha = normalize_tooling_reference(tooling["repository"], tooling["sha"])
    _need(tooling == {"repository": repository, "sha": sha,
                    "schemaReference": pinned_schema_reference(repository, sha), "state": "format-only"})


def _paths(rows: Any, *, recovery: bool) -> tuple[str, ...]:
    _need(type(rows) is list and 6 <= len(rows) <= 256)
    paths = []
    for index, row in enumerate(rows):
        keys = {"index", "kind", "path"} | ({"effect", "before", "after"} if recovery else {"action", "beforeBytes", "afterBytes"})
        _object(row, keys)
        _need(type(row["index"]) is int and row["index"] == index and row["kind"] == file_kind(index)
              and type(row["path"]) is str and (index >= 6 or row["path"] == FIXED_PATHS[index]))
        paths.append(row["path"])
    _need(paths[6:] == sorted(paths[6:]))
    validate_paths(paths)  # Safe DATA only; cannot derive writable targets.
    return tuple(paths)


def initialization_view(value: Any) -> None:
    _object(value, {"schemaVersion", "kind", "files", "directoryCount", "createDirectories", "configurationPreview",
                    "workflows", "ignoreAdditions", "templateSet", "tooling"})
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["kind"] == "project-initialization")
    paths = _paths(value["files"], recovery=False)
    parents = {"/".join(path.split("/")[:i]) for path in paths for i in range(1, len(path.split("/")))}
    _need(_integer(value["directoryCount"], 256) and value["directoryCount"] == len(parents))
    created = value["createDirectories"]
    _need(type(created) is list and all(type(path) is str for path in created)
          and len(created) == len(set(created)) and set(created) <= parents
          and created == sorted(created, key=lambda p: (p.count("/"), p)))
    for index, row in enumerate(value["files"]):
        before, after, action = row["beforeBytes"], row["afterBytes"], row["action"]
        maximum = 512 * 1024 if index == 0 else 1024 * 1024 if index < 6 else MAX_FILE_BYTES
        _need((before is None or _integer(before, maximum)) and _integer(after, maximum)
              and type(action) is str and action in {"create", "preserve", "append"})
        _need((action == "create" and before is None) or
              (action == "preserve" and before is not None and before == after) or
              (action == "append" and index == 1 and before is not None and after > before))
        _need(index >= 6 and (action != "create" or after == 0) or index < 6 and after > 0)
        _need(not 2 <= index < 6 or after <= 16 * 1024)
    _source(value["templateSet"], value["tooling"])
    workflows = value["workflows"]
    _need(type(workflows) is list and len(workflows) == 4)
    for index, ((identity, path), row) in enumerate(zip(GITHUB_WORKFLOWS, workflows)):
        _object(row, {"id", "path", "content", "byteLength", "sha256"})
        _need(row["id"] == identity and row["path"] == path and type(row["content"]) is str)
        raw = row["content"].encode("utf-8")
        _need(_integer(row["byteLength"], 16 * 1024, 1) and row["byteLength"] == len(raw)
              and row["sha256"] == hashlib.sha256(raw).hexdigest()
              and value["files"][index + 2]["afterBytes"] == len(raw))
    additions = value["ignoreAdditions"]
    _need(type(additions) is list and all(type(item) is str and item in IGNORE_LINES for item in additions)
          and len(additions) == len(set(additions)) and type(value["configurationPreview"]) is dict)
    _bounded({"files": value["files"], "createDirectories": created}, INVENTORY_BYTES, depth=8, nodes=12000)
    _bounded(value, VIEW_BYTES)


def recovery_view(value: Any) -> None:
    _object(value, {"schemaVersion", "kind", "state", "reason", "action", "transactionId", "context", "files", "privateCleanup"})
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["kind"] == "project-initialization-recovery" and type(value["state"]) is str
          and value["state"] in {"idle", "conflict", "recoverable"}
          and type(value["reason"]) is str and value["reason"] in _RECOVERY_REASONS)
    cleanup = _object(value["privateCleanup"], {"fileCount", "directoryCount", "scope"})
    _need(_integer(cleanup["fileCount"], 1024) and _integer(cleanup["directoryCount"], 257)
          and cleanup["scope"] == "inspected-owned-journal-only")
    if value["state"] != "recoverable":
        _need((value["reason"] == "none") == (value["state"] == "idle")
              and value["action"] is None and value["transactionId"] is None and value["context"] is None
              and value["files"] == [] and cleanup["fileCount"] == cleanup["directoryCount"] == 0)
    else:
        _need(value["reason"] == "none" and _token(value["transactionId"]) and type(value["action"]) is str
              and value["action"] in {"rollback", "preparing_cleanup", "committed_cleanup", "rolled_back_cleanup"})
        context = _object(value["context"], {"configuration", "templateSet", "tooling"})
        config = _object(context["configuration"], {"byteLength", "sha256"})
        _need(_integer(config["byteLength"], 512 * 1024, 1) and _digest(config["sha256"]))
        _source(context["templateSet"], context["tooling"])
        if value["files"] == []:
            _need(value["action"] in {"committed_cleanup", "rolled_back_cleanup"}
                  and cleanup["fileCount"] == 2 and cleanup["directoryCount"] == 1)
        else:
            _paths(value["files"], recovery=True)
            for index, row in enumerate(value["files"]):
                before, after = row["before"], row["after"]
                for item in (before, after):
                    if item is not None:
                        _object(item, {"byteLength", "sha256", "mode"})
                        limit = 512 * 1024 if index == 0 else 1024 * 1024 if index < 6 else MAX_FILE_BYTES
                        _need(_integer(item["byteLength"], limit) and _digest(item["sha256"]) and _integer(item["mode"], 0o777))
                _need(before is not None or after is not None)
                _need(index == 1 or before is None or after is None)
                if after is not None:
                    _need(after["mode"] == (0o644 if before is None else before["mode"]))
                    _need(after["byteLength"] == 0 if index >= 6 else after["byteLength"] > 0)
                    _need(not 2 <= index < 6 or after["byteLength"] <= 16 * 1024)
                expected = ("preserve" if after is None else "keep_committed" if value["action"] == "committed_cleanup" else
                            "preserve" if value["action"] != "rollback" else "remove_new" if before is None else "restore_original")
                _need(row["effect"] == expected)
    _bounded(value["files"], INVENTORY_BYTES, depth=8, nodes=12000)
    _bounded(value, VIEW_BYTES)


def response(request: Any, kind: str, result: dict[str, Any]) -> bytes:
    _need(request.protocol == PROTOCOL and type(kind) is str and kind in {"opened", "prepared", "terminal"})
    try:
        _need(type(result) is dict and type(result.get("intent")) is str and result["intent"] in {"initialize", "recover"})
        intent = result["intent"]
        if kind == "terminal":
            conflict = result.get("kind") == "conflict"
            keys = {"kind", "intent", "effect", "journal", "resources", "reason"} | ({"revision", "conflict"} if conflict else {"planToken"})
            _object(result, keys)
            CoreEditOutcome(*(result[key] for key in ("effect", "journal", "resources", "reason")))
            if conflict:
                _need(intent == "initialize" and _token(result["revision"]) and result["effect"] == "not_started"
                      and result["journal"] == "not_created" and result["resources"] == "settled" and result["reason"] == "none")
                view = _object(result["conflict"], {"schemaVersion", "reason", "files"})
                _need(type(view["schemaVersion"]) is int and view["schemaVersion"] == 1
                      and view["reason"] == "existing_targets_differ" and type(view["files"]) is list and 1 <= len(view["files"]) <= 5)
                order = []
                for row in view["files"]:
                    _object(row, {"kind", "path", "beforeBytes"})
                    _need(type(row["path"]) is str and row["path"] in (FIXED_PATHS[0], *FIXED_PATHS[2:6]))
                    index = FIXED_PATHS.index(row["path"])
                    _need(row["kind"] == file_kind(index) and _integer(row["beforeBytes"], 512 * 1024 if index == 0 else 1024 * 1024))
                    order.append(index)
                _need(order == sorted(set(order)))
            else:
                _need(result["kind"] == "outcome" and (result["planToken"] is None or _token(result["planToken"])))
        else:
            field = "recovery" if intent == "recover" else "observed" if kind == "opened" else "view"
            _object(result, {"intent", "revision", "scopeResources", field} | ({"planToken"} if kind == "prepared" else set()))
            _need(_token(result["revision"]) and result["scopeResources"] == "settled")
            if kind == "prepared":
                _need(_token(result["planToken"]) and result["planToken"] != result["revision"])
            if field == "recovery":
                recovery_view(result[field])
                _need(kind != "prepared" or result[field]["state"] == "recoverable")
            elif field == "view":
                initialization_view(result[field])
            else:
                observed = _object(result[field], {"schemaVersion", "fileCount", "directoryCount"})
                _need(type(observed["schemaVersion"]) is int and observed["schemaVersion"] == 1
                      and _integer(observed["fileCount"], 256, 6) and _integer(observed["directoryCount"], 256))
        value = {"protocol": PROTOCOL, "session": request.session, "seq": request.seq, "kind": kind, "result": result}
        _check_values(value)
        _bounded(value, TERMINAL_LIMIT - 1 if kind == "terminal" else RESPONSE_LIMIT - 1, depth=32)
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
        _need(len(raw) <= (TERMINAL_LIMIT if kind == "terminal" else RESPONSE_LIMIT))
        return raw
    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError, ValidationError):
        raise ProtocolError("Invalid initialization response") from None
