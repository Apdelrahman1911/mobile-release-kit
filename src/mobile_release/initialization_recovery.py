"""Closed initialization checks for the SAME original recovery inspector.

No journal search, alternate rollback or new recovery owner. The existing
workflow/configuration inspector and one-use restoration guard call these
initialization-only DATA/physical checks after acquiring the registered root.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from . import init_transaction as tx
from .config_payloads import prepare_edit_ignore
from .initialization_targets import DOMAIN, DescriptorError, InitializationInput, kind


class InspectionRefusal(tx.InitConflict):
    def __init__(self, reason: str) -> None:
        super().__init__("The initialization journal must be preserved for attention")
        self.reason = reason


def _need(value: bool, reason: str = "invalid_journal") -> None:
    if not value:
        raise InspectionRefusal(reason)


def header_data(raw: bytes | None) -> None:
    if raw is None:
        raise InspectionRefusal("incomplete_journal")
    header = tx._parse(raw)
    if header.get("schemaVersion") == 1 and "domain" not in header:
        raise InspectionRefusal("legacy_journal")
    if header.get("domain") != DOMAIN:
        raise InspectionRefusal("foreign_journal")
    _need(type(header.get("schemaVersion")) is int and header["schemaVersion"] == 2,
          "unsupported_descriptor")


def suffix(workspace: tx.InitWorkspace, state: str, fd: int, private: Any,
           names: set[str], header_fact: Any, header_raw: bytes):
    """Only header + one real terminal marker; never header-only adoption."""
    from .github_workflow_recovery import _Entry, _Inspection, _full9, _observed
    _need(state == tx.CLEANUP and len(names) == 2 and "header.json" in names
          and len(names & {"COMMITTED", "ROLLED_BACK"}) == 1, "incomplete_journal")
    header = workspace._header(fd)  # Original named read + strict source descriptor.
    _need(tx._json(header) == header_raw and header_fact.raw[3] == os.geteuid()
          and header_fact.value()["mode"] == 0o600, "control_changed")
    marker_name = next(iter(names - {"header.json"}))
    fact, raw = _observed(workspace, fd, marker_name, limit=tx.MAX_CONTROL_BYTES)
    _need(fact.binding is not None and fact.raw[3] == os.geteuid() and fact.value()["mode"] == 0o600
          and raw is not None, "control_changed")
    marker = tx._parse(raw)
    _need(set(marker) == {"schemaVersion", "transactionId", "planSha256", "state"}
          and type(marker["schemaVersion"]) is int and marker["schemaVersion"] == 1
          and marker["transactionId"] == header["transactionId"] and marker["state"] == marker_name
          and type(marker["planSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", marker["planSha256"]) is not None
          and tx._json(marker) == raw)
    entries = {"header.json": _Entry(False, header_fact, header_raw), marker_name: _Entry(False, fact, raw)}
    for name, entry in entries.items():
        current, body = _observed(workspace, fd, name, limit=tx.MAX_CONTROL_BYTES)
        _need(current == entry.fact and body == entry.control, "control_changed")
    _need(set(workspace._list(fd)) == names and _full9(os.fstat(fd)) == private.raw, "namespace_changed")
    return _Inspection(tx.TypedEditProfile.PROJECT_INITIALIZATION, state,
                       "committed_cleanup" if marker_name == "COMMITTED" else "rolled_back_cleanup",
                       _full9(os.fstat(workspace.fd)), private, header_raw, b"",
                       tuple(sorted(entries.items())), (), ())


def private_payload(data: InitializationInput, plan: dict[str, Any], name: str, raw: bytes | None) -> None:
    if name.startswith("new-"):
        index = int(name[4:])  # The exact name already belongs to plan's finite allowed map.
        if index != 1:
            _need(raw == data.desired(index), "target_changed")


def _public_bytes(workspace: tx.InitWorkspace, path: str, expected: dict[str, Any], limit: int) -> bytes:
    from .github_workflow_recovery import _observed
    with workspace._parent(path) as parent:
        _need(parent is not None, "target_changed")
        fact, raw = _observed(workspace, parent, path.rsplit("/", 1)[-1], limit=limit)
    _need(fact.value() == expected and raw is not None, "target_changed")
    return raw


def nonterminal_payloads(workspace: tx.InitWorkspace, fd: int, plan: dict[str, Any]) -> None:
    """Full actual before/new payload proof, only before public rollback."""
    from .github_workflow_recovery import _observed
    data = workspace._initialization_input
    _need(type(data) is InitializationInput)
    # .gitignore is the sole replacement. Its actual original bytes must still
    # exist at exactly the current or backup location proved by _locations.
    row = plan["files"][1]
    before, after = row["before"], row["after"]
    if before is None:
        original = b""
    else:
        fact, raw = _observed(workspace, fd, "old-1", limit=data.limits[1])
        if fact.binding is not None:
            _need(after is not None and fact.value() == before and raw is not None, "target_changed")
            original = raw
        else:
            original = _public_bytes(workspace, row["path"], before, data.limits[1])
    desired, _ = prepare_edit_ignore(original)
    if after is None:
        _need(before is not None and desired == original, "invalid_journal")
    else:
        _need((before is None or desired != original) and after["size"] == len(desired)
              and after["sha256"] == hashlib.sha256(desired).hexdigest(), "invalid_journal")
    # Fixed generated files are compared as actual bytes, not only inventory
    # assertions. The existing location graph independently binds their inodes.
    for index in (0, 2, 3, 4, 5):
        row = plan["files"][index]
        staged, raw = _observed(workspace, fd, f"new-{index}", limit=data.limits[index])
        if staged.binding is not None:
            _need(staged.value() == row["after"] and raw == data.desired(index), "target_changed")
        else:
            # Partial preparing cleanup may have already deleted staged NEW;
            # then the corresponding public destination must still be absent.
            current = workspace._current(row["path"])
            if current is None:
                _need(row["before"] is None, "target_changed")
            else:
                _need(current == (row["before"] or row["after"]), "target_changed")
                _need(_public_bytes(workspace, row["path"], current, data.limits[index]) == data.desired(index),
                      "target_changed")


def conflict_reason(error: BaseException) -> str:
    return error.reason if type(error) in (DescriptorError, InspectionRefusal) else "invalid_journal"


def view(captured: Any, conflict: bool | str) -> dict[str, Any]:
    result = {"schemaVersion": 1, "kind": "project-initialization-recovery",
              "state": "conflict" if conflict else "idle", "reason": conflict if type(conflict) is str else "invalid_journal" if conflict else "none",
              "action": None, "transactionId": None, "context": None, "files": [],
              "privateCleanup": {"fileCount": 0, "directoryCount": 0, "scope": "inspected-owned-journal-only"}}
    if captured is None:
        return result
    header = json.loads(captured.header)
    context = header["initialization"]
    raw = context["configurationUtf8"].encode("utf-8")
    from .workflow_payloads import pinned_schema_reference
    result.update(state="recoverable", reason="none", action=captured.action,
                  transactionId=header["transactionId"], context={
                      "configuration": {"byteLength": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                      "templateSet": context["templateSet"], "tooling": {
                          "repository": context["toolingRepository"], "sha": context["toolingSha"],
                          "schemaReference": pinned_schema_reference(context["toolingRepository"], context["toolingSha"]),
                          "state": "format-only"}})
    if captured.plan:
        plan = json.loads(captured.plan)
        def summary(item: dict[str, Any] | None):
            return None if item is None else {"byteLength": item["size"], "sha256": item["sha256"], "mode": item["mode"]}
        result["files"] = [{"index": index, "kind": kind(index), "path": row["path"],
                            "effect": ("preserve" if row["after"] is None else
                                       "keep_committed" if captured.action == "committed_cleanup" else
                                       "preserve" if captured.action != "rollback" else
                                       "remove_new" if row["before"] is None else "restore_original"),
                            "before": summary(row["before"]), "after": summary(row["after"])}
                           for index, row in enumerate(plan["files"])]
    # Include the held private root, not just its staged child directories.
    result["privateCleanup"].update(fileCount=sum(not entry.directory for _, entry in captured.entries),
                                     directoryCount=1 + sum(entry.directory for _, entry in captured.entries))
    return result
