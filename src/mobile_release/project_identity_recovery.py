"""Identity-only qualification for the existing original restoration owner.

No source path in a journal is a write grant: the nonterminal inspector proves
all current/backup originals, rediscovers controls, and rederives the exact
literal-span transformation. A real terminal authorizes private cleanup only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import TYPE_CHECKING, Any

from . import init_transaction as tx
from .config_payloads import sufficient_ignore_rules
from .project_identity import (IGNORE_PATH, MAX_FILE_BYTES, IdentityInputError,
                               analyze_project_identity, prepare_project_identity)
from .project_identity_targets import (DOMAIN, DescriptorError, IdentityDescriptor,
                                       Inventory, recovery_inventory)

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease
    from .github_workflow_recovery import WorkflowRecoveryCheckout, PreparedWorkflowRecovery


class InspectionRefusal(tx.InitConflict):
    def __init__(self, reason: str = "invalid_journal") -> None:
        super().__init__("The identity journal must be preserved for attention")
        self.reason = reason


def _need(value: bool, reason: str = "invalid_journal") -> None:
    if not value:
        raise InspectionRefusal(reason)


def header_data(raw: bytes | None) -> None:
    _need(raw is not None, "incomplete_journal")
    header = tx._parse(raw)
    if header.get("schemaVersion") == 1 and "domain" not in header:
        raise InspectionRefusal("legacy_journal")
    _need(header.get("domain") == DOMAIN, "foreign_journal")
    _need(type(header.get("schemaVersion")) is int and header["schemaVersion"] == 2,
          "unsupported_descriptor")


def suffix(workspace: tx.InitWorkspace, state: str, fd: int, private: Any,
           names: set[str], header_fact: Any, header_raw: bytes):
    """Strict header + actual terminal marker; no header-only adoption."""
    from .github_workflow_recovery import _Entry, _Inspection, _full9, _observed
    _need(state == tx.CLEANUP and len(names) == 2 and "header.json" in names
          and len(names & {"COMMITTED", "ROLLED_BACK"}) == 1, "incomplete_journal")
    header = workspace._header(fd)
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
    return _Inspection(tx.TypedEditProfile.PROJECT_IDENTITY, state,
        "committed_cleanup" if marker_name == "COMMITTED" else "rolled_back_cleanup",
        _full9(os.fstat(workspace.fd)), private, header_raw, b"", tuple(sorted(entries.items())), (), ())


def private_payload(data: IdentityDescriptor, plan: dict[str, Any], name: str, raw: bytes | None) -> None:
    _need(type(data) is IdentityDescriptor)
    if name.startswith("old-"):
        index = int(name[4:])  # Already in the existing inspector's finite allowed map.
        _, size, digest = data.sources[index]
        _need(raw is not None and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
              "target_changed")


def _public_bytes(workspace: tx.InitWorkspace, path: str, expected: dict[str, Any]) -> bytes:
    from .github_workflow_recovery import _observed
    with workspace._parent(path) as parent:
        _need(parent is not None, "target_changed")
        fact, raw = _observed(workspace, parent, path.rsplit("/", 1)[-1], limit=MAX_FILE_BYTES)
    _need(fact.value() == expected and raw is not None, "target_changed")
    return raw


def nonterminal_payloads(workspace: tx.InitWorkspace, fd: int, plan: dict[str, Any]) -> Inventory:
    """Reconstruct originals and prove the exact transform, before rollback."""
    from .github_workflow_recovery import _observed
    data = workspace._identity_input
    _need(type(data) is IdentityDescriptor)
    inventory = recovery_inventory(workspace)
    _need(set(inventory.paths) <= set(data.paths), "inventory_changed")
    sources: dict[str, bytes] = {}
    for index, row in enumerate(plan["files"]):
        before, after = row["before"], row["after"]
        fact, raw = _observed(workspace, fd, f"old-{index}", limit=MAX_FILE_BYTES)
        if fact.binding is not None:
            _need(after is not None and fact.value() == before and raw is not None, "target_changed")
        else:
            raw = _public_bytes(workspace, row["path"], before)
        _, size, digest = data.sources[index]
        _need(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, "target_changed")
        sources[row["path"]] = raw
    _need(sufficient_ignore_rules(sources[IGNORE_PATH]), "invalid_journal")
    try:
        original = analyze_project_identity(sources, data.selection,
                                            directories=inventory.control_directories)
        prepared = prepare_project_identity(original, data.desired_identity,
            expected_revision=original.revision, intent=data.intent)
    except IdentityInputError:
        raise InspectionRefusal("unsupported_descriptor") from None
    _need(prepared.changed)
    desired = dict(prepared._payloads)
    for index, row in enumerate(plan["files"]):
        expected = desired.get(row["path"])
        after = row["after"]
        _need((after is None) is (expected is None), "invalid_journal")
        if after is None:
            continue
        _need(after["size"] == len(expected) and after["sha256"] == hashlib.sha256(expected).hexdigest(),
              "invalid_journal")
        staged, raw = _observed(workspace, fd, f"new-{index}", limit=MAX_FILE_BYTES)
        if staged.binding is not None:
            _need(staged.value() == after and raw == expected, "target_changed")
        else:
            current = workspace._current(row["path"])
            if current == after:
                _need(_public_bytes(workspace, row["path"], after) == expected, "target_changed")
            else:
                # Existing preparation cleanup may have removed staged NEW.
                # Its location graph has already proved the unchanged public OLD.
                _need(current == row["before"], "target_changed")
    _need(recovery_inventory(workspace) == inventory, "inventory_changed")
    return inventory


def check_current_inventory(workspace: tx.InitWorkspace, captured: Inventory,
                            public: dict[str, Any]) -> None:
    """Keep added controls/ownership changes out of the original guard's moves."""
    _need(type(captured) is Inventory)
    current = recovery_inventory(workspace)
    expected_paths = tuple(sorted(path for path, fact in public.items() if fact.binding is not None))
    _need(current.paths == expected_paths and current.control_directories == captured.control_directories
          and current.directories == captured.directories, "inventory_changed")


def conflict_reason(error: BaseException) -> str:
    return error.reason if type(error) in (DescriptorError, InspectionRefusal) else "invalid_journal"


def view(captured: Any, conflict: bool | str) -> dict[str, Any]:
    result = {"schemaVersion": 1, "kind": "project-identity-recovery",
        "state": "conflict" if conflict else "idle",
        "reason": conflict if type(conflict) is str else "invalid_journal" if conflict else "none",
        "action": None, "transactionId": None, "desiredIdentity": None, "files": [],
        "help": ("Preserve the journal and resolve the reported conflict before trying again." if conflict
                 else "No identity recovery is required."),
        "privateCleanup": {"fileCount": 0, "directoryCount": 0, "scope": "inspected-owned-journal-only"},
        "retainVersionReservations": True}
    if captured is None:
        return result
    header = json.loads(captured.header)
    result.update(state="recoverable", action=captured.action, transactionId=header["transactionId"],
        desiredIdentity=header["identity"]["desiredIdentity"],
        help=("Keep the committed identity and finish private journal cleanup."
              if captured.action == "committed_cleanup" else
              "Restore the exact captured original files, then analyze the project again."
              if captured.action == "rollback" else "Finish private journal cleanup without changing project files."))
    if captured.plan:
        plan = json.loads(captured.plan)
        result["files"] = [{"path": row["path"],
            "action": "restore_original" if captured.action == "rollback" and row["after"] is not None else "preserve",
            "beforeBytes": row["before"]["size"],
            "afterBytes": row["after"]["size"] if row["after"] is not None else None}
            for row in plan["files"]]
    result["privateCleanup"].update(fileCount=sum(not entry.directory for _, entry in captured.entries),
        directoryCount=1 + sum(entry.directory for _, entry in captured.entries))
    return result


def capture_project_identity_recovery(lease: InitRootLease) -> WorkflowRecoveryCheckout:
    from .github_workflow_recovery import _capture_recovery
    return _capture_recovery(lease, tx.TypedEditProfile.PROJECT_IDENTITY)


def prepare_project_identity_recovery(lease: InitRootLease, checkout: WorkflowRecoveryCheckout,
                                      expected_revision: str) -> PreparedWorkflowRecovery:
    from .github_workflow_recovery import _prepare_recovery
    return _prepare_recovery(lease, checkout, expected_revision, tx.TypedEditProfile.PROJECT_IDENTITY)


def apply_project_identity_recovery(lease: InitRootLease, plan: PreparedWorkflowRecovery):
    from .github_workflow_recovery import _apply_recovery
    return _apply_recovery(lease, plan, tx.TypedEditProfile.PROJECT_IDENTITY)


def discard_project_identity_recovery(authority: WorkflowRecoveryCheckout | PreparedWorkflowRecovery) -> None:
    from .github_workflow_recovery import _discard_recovery
    _discard_recovery(authority, tx.TypedEditProfile.PROJECT_IDENTITY)
