"""One source-derived initialization inventory, never a caller path grant.

The same closed descriptor is stored in the existing transaction header and
plan. Restart parsing regenerates it through the shared configuration/workflow
policies. Only an original registered lease can bind it to a writable revision.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from . import config_edit as shared
from . import init_transaction as tx
from .api._json import bounded_json_text
from .config import MAX_CONFIG_BYTES, parse_config_text, validate_config_data
from .config_payloads import MAX_IGNORE_BYTES, prepare_edit_ignore, serialize_config_data
from .errors import ConfigurationError, ValidationError
from .github_workflow_edit import _proposal
from .initialization_payloads import metadata_skeleton
from .workflow_payloads import GITHUB_WORKFLOWS, normalize_tooling_reference, pinned_schema_reference

DOMAIN = "project-initialization"
FIXED_PATHS = ("release/mobile-release.json", ".gitignore", *(path for _, path in GITHUB_WORKFLOWS))
VIEW_BYTES = 768 * 1024
INVENTORY_BYTES = 128 * 1024
_CONTROL_HEADROOM = 2 * 1024 * 1024


class DescriptorError(ValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__("Initialization descriptor is not supported by this source")
        self.reason = reason


def _need(condition: bool, reason: str = "unsupported_descriptor") -> None:
    if not condition:
        raise DescriptorError(reason)


class InitializationInput(shared._PrivateAuthority):
    """Frozen generated DATA. This object alone has no filesystem authority."""

    __slots__ = ("_identity", "configuration", "workflows", "paths", "directories",
                 "_context", "_template", "_tooling", "control_quote", "retained_quote")

    def context(self) -> dict[str, Any]:
        return json.loads(self._context)

    def template(self) -> dict[str, Any]:
        return json.loads(self._template)

    def tooling(self) -> dict[str, Any]:
        return json.loads(self._tooling)

    @property
    def limits(self) -> tuple[int, ...]:
        return (MAX_CONFIG_BYTES, MAX_IGNORE_BYTES, *((1024 * 1024,) * 4),
                *((tx.MAX_FILE_BYTES,) * (len(self.paths) - len(FIXED_PATHS))))

    def desired(self, index: int) -> bytes:
        _need(type(index) is int and 0 <= index < len(self.paths) and index != 1)
        return self.configuration if index == 0 else self.workflows[index - 2] if index < 6 else b""

    def remaining_observation(self, observed: int) -> int:
        # Four simultaneous original/read/recheck copies plus all bounded
        # descriptor/control/projection copies. This is a byte-workspace quote,
        # not an assertion about Python's process RSS or a new resource pool.
        _need(type(observed) is int and observed >= 0)
        return max(0, (tx.MAX_TOTAL_BYTES - self.retained_quote) // 4 - observed)

    def check_budget(self, originals: int, payloads: int = 0) -> None:
        _need(type(originals) is int and originals >= 0 and type(payloads) is int and payloads >= 0)
        _need(self.retained_quote + 4 * originals + 2 * payloads <= tx.MAX_TOTAL_BYTES,
              "invalid_journal")


def kind(index: int) -> str:
    return "configuration" if index == 0 else "gitignore" if index == 1 else "workflow" if index < 6 else "metadata"


def _control_quote(context: dict[str, Any], paths: tuple[str, ...], directories: tuple[str, ...]) -> int:
    # The actual format permits at most u64 values; use their longest decimal
    # encodings for both slots before the first private mkdir. No real identity
    # or stage admission is inferred from these deliberately conservative DATA.
    identity = {"device": 2**64 - 1, "inode": 2**64 - 1, "mode": 0o777}
    file = {**identity, "size": tx.MAX_FILE_BYTES, "sha256": "f" * 64}
    header = {"schemaVersion": 2, "domain": DOMAIN, "transactionId": "f" * 32,
              "root": identity, "initialization": context}
    plan = {**header,
            "directories": [{"path": path, "before": identity, "after": identity} for path in directories],
            "files": [{"path": path, "before": file, "after": file} for path in paths]}
    encoded_header, encoded_plan = tx._json(header), tx._json(plan)
    _need(len(encoded_header) <= tx.MAX_CONTROL_BYTES and len(encoded_plan) <= tx.MAX_CONTROL_BYTES)
    return len(encoded_header) + len(encoded_plan)


def prepare_input(draft: object, repository: object, sha: object) -> InitializationInput:
    """Pure shared preparation, once before the complete original capture."""
    try:
        _need(type(draft) is dict)
        frozen = json.loads(bounded_json_text(draft, max_bytes=MAX_CONFIG_BYTES,
                                             max_nodes=8000, max_depth=28))
        repository, sha = normalize_tooling_reference(repository, sha)
        frozen["$schema"] = pinned_schema_reference(repository, sha)
        validate_config_data(frozen)
        _need(bool(frozen.get("android", {}).get("enabled")) or bool(frozen.get("ios", {}).get("enabled")))
        configuration = serialize_config_data(frozen)
        _need(0 < len(configuration) <= MAX_CONFIG_BYTES)
        # Count first in the shared helper, then validate the complete union;
        # metadata paths never come from an Open/Prepare inventory or a journal.
        paths = (*FIXED_PATHS, *metadata_skeleton(frozen, max_paths=tx.MAX_FILES - len(FIXED_PATHS)))
        tx.validate_paths(list(paths))
        directories = tuple(sorted({"/".join(path.split("/")[:i]) for path in paths
                                    for i in range(1, len(path.split("/")))}, key=lambda p: (p.count("/"), p)))
        proposed, _ = _proposal(frozen, repository, sha)
        tooling, template = proposed["tooling"], proposed["templateSet"]
        _need(tooling == {"repository": repository, "sha": sha,
                         "schemaReference": frozen["$schema"], "state": "format-only"})
        rows = proposed["workflows"]
        _need(type(rows) is list and len(rows) == len(GITHUB_WORKFLOWS))
        workflows = []
        for (identity, path), row in zip(GITHUB_WORKFLOWS, rows):
            _need(type(row) is dict and set(row) == {"id", "path", "content", "byteLength", "sha256", "comparison"}
                  and row["id"] == identity and row["path"] == path and row["comparison"] == "not-supplied"
                  and type(row["content"]) is str)
            raw = row["content"].encode("utf-8")
            _need(0 < len(raw) <= 16 * 1024 and type(row["byteLength"]) is int and row["byteLength"] == len(raw)
                  and row["sha256"] == hashlib.sha256(raw).hexdigest())
            workflows.append(raw)
        _need(sum(map(len, workflows)) <= 64 * 1024)
        context = {"schemaVersion": 1, "configurationUtf8": configuration.decode("utf-8"),
                   "toolingRepository": repository, "toolingSha": sha, "templateSet": template}
        control_quote = _control_quote(context, paths, directories)
        context_raw = tx._json(context)
        # Parsed Unicode, canonical header/plan, generated source bytes, both
        # retained views and their escaped serialization are all precharged.
        retained = (4 * len(context_raw) + 4 * control_quote + 4 * len(configuration)
                    + 4 * sum(map(len, workflows)) + 4 * VIEW_BYTES + 4 * INVENTORY_BYTES
                    + _CONTROL_HEADROOM)
        _need(retained < tx.MAX_TOTAL_BYTES)
        value = object.__new__(InitializationInput)
        for name, item in (("_identity", value), ("configuration", configuration), ("workflows", tuple(workflows)),
                           ("paths", paths), ("directories", directories), ("_context", context_raw),
                           ("_tooling", tx._json(tooling)), ("_template", tx._json(template)),
                           ("control_quote", control_quote), ("retained_quote", retained)):
            object.__setattr__(value, name, item)
        return value
    except shared.ConfigEditFailure:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError, ConfigurationError, ValidationError):
        raise DescriptorError("unsupported_descriptor") from None


def from_context(context: object) -> InitializationInput:
    """Strict restart DATA parser; no original revision is manufactured here."""
    try:
        _need(type(context) is dict and set(context) == {"schemaVersion", "configurationUtf8", "toolingRepository", "toolingSha", "templateSet"}
              and type(context["schemaVersion"]) is int and context["schemaVersion"] == 1
              and type(context["configurationUtf8"]) is str)
        raw = context["configurationUtf8"].encode("utf-8")
        _need(0 < len(raw) <= MAX_CONFIG_BYTES)
        data = parse_config_text(context["configurationUtf8"])
        validate_config_data(data)
        _need(serialize_config_data(data) == raw)
        repository, sha = normalize_tooling_reference(context["toolingRepository"], context["toolingSha"])
        _need(repository == context["toolingRepository"] and sha == context["toolingSha"]
              and data.get("$schema") == pinned_schema_reference(repository, sha))
        generated = prepare_input(data, repository, sha)
        _need(context["templateSet"] == generated.template(), "resource_changed")
        _need(generated.configuration == raw and tx._json(context) == generated._context)
        return generated
    except DescriptorError:
        raise
    except (shared.ConfigEditFailure, ValueError, TypeError, UnicodeError, RecursionError, KeyError, ConfigurationError, ValidationError):
        raise DescriptorError("unsupported_descriptor") from None


def plan_shape(data: InitializationInput, plan: dict[str, Any]) -> None:
    """Additional closed-role checks AFTER the transaction's sole plan parser."""
    _need(tuple(row["path"] for row in plan["files"]) == data.paths
          and tuple(row["path"] for row in plan["directories"]) == data.directories, "invalid_journal")
    originals = payloads = 0
    for index, (row, limit) in enumerate(zip(plan["files"], data.limits)):
        before, after = row["before"], row["after"]
        _need(before is None or before["size"] <= limit, "invalid_journal")
        originals += (before or {}).get("size", 0)
        if index != 1:
            _need(before is None or after is None, "invalid_journal")
            if after is not None:
                raw = data.desired(index)
                _need(after["size"] == len(raw) and after["sha256"] == hashlib.sha256(raw).hexdigest()
                      and after["mode"] == 0o644, "invalid_journal")
            elif index < 6:
                raw = data.desired(index)
                _need(before is not None and before["size"] == len(raw)
                      and before["sha256"] == hashlib.sha256(raw).hexdigest(), "invalid_journal")
        else:
            _need(after is None or 0 < after["size"] <= MAX_IGNORE_BYTES, "invalid_journal")
            _need(after is None or before is None and after["mode"] == 0o644
                  or before is not None and after["mode"] == before["mode"]
                  and after["inode"] != before["inode"] and after["size"] > before["size"], "invalid_journal")
        payloads += (after or {}).get("size", 0)
    data.check_budget(originals, payloads)


class InitializationTargets(shared._PrivateAuthority):
    """The original lease's noncopyable configuration/source-bound descriptor."""

    __slots__ = ("_identity", "_lease", "_capture_workspace", "_input")

    @property
    def paths(self) -> tuple[str, ...]:
        return self._input.paths

    @property
    def directories(self) -> tuple[str, ...]:
        return self._input.directories

    @property
    def observation_limits(self) -> tuple[int, ...]:
        return self._input.limits

    def journal_context(self) -> dict[str, Any]:
        return self._input.context()

    def _check_workspace(self, workspace: tx.InitWorkspace) -> None:
        from .init_workspace_custody import LockedInitScope
        _need(type(self) is InitializationTargets and self._identity is self
              and type(workspace) is tx.InitWorkspace and workspace._typed_profile is tx.TypedEditProfile.PROJECT_INITIALIZATION
              and workspace._initialization_targets is self and type(workspace._scope) is LockedInitScope
              and workspace._scope is self._lease._active and workspace._scope.lease is self._lease
              and workspace._scope.workspace is workspace and self._lease._initialization_targets is self)

    def check_changes(self, workspace: tx.InitWorkspace, changes: list[tuple[tx.ObservedFile, bytes | None]]) -> None:
        self._check_workspace(workspace)
        _need(len(changes) == len(self.paths))
        originals = payloads = 0
        for index, ((observed, payload), path) in enumerate(zip(changes, self.paths)):
            _need(observed.path == path and workspace._captured.get(path) is observed)
            before = observed.data
            originals += len(before) if before is not None else 0
            if index == 1:
                wanted, _ = prepare_edit_ignore(before if before is not None else b"")
                expected = None if before == wanted else wanted
            else:
                wanted = self._input.desired(index)
                _need(index >= 6 or before is None or before == wanted)
                expected = wanted if before is None else None
            _need(payload == expected and (payload is None or type(payload) is bytes))
            payloads += len(payload) if payload is not None else 0
        self._input.check_budget(originals, payloads)
        _need(_control_quote(self.journal_context(), self.paths, self.directories) == self._input.control_quote)


def bind_targets(lease: Any, workspace: tx.InitWorkspace, data: InitializationInput) -> InitializationTargets:
    from .init_workspace_custody import InitRootLease
    _need(type(lease) is InitRootLease and lease.profile is tx.TypedEditProfile.PROJECT_INITIALIZATION
          and not lease._workflow_recovery_mode and lease._active is not None
          and lease._active.workspace is workspace and workspace._typed_profile is lease.profile
          and lease._initialization_targets is None and workspace._initialization_targets is None
          and lease._revision is None and not workspace._captured and not workspace.parents
          and type(data) is InitializationInput and data._identity is data)
    lease.check()
    targets = object.__new__(InitializationTargets)
    for name, item in (("_identity", targets), ("_lease", lease), ("_capture_workspace", workspace), ("_input", data)):
        object.__setattr__(targets, name, item)
    lease._initialization_targets = workspace._initialization_targets = targets
    return targets
