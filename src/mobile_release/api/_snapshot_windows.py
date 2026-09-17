"""Finite original-handle Windows collector, behind a closed activation gate.

Names/metadata are observations, not authority to reopen a path. Sharing is not
an attribute/reparse lock. Only the private native adapter acquires handles;
pure parsing, exclusions, inventory/output quotas and DTO assembly remain shared.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator

from . import _snapshot as policy
from . import _snapshot_windows_native as native_api
from .contracts import ApiError, ConfigObservation, SnapshotResult, issue


@dataclass(frozen=True)
class _Frame:
    handle: int
    expected_name: str  # Comparison veto ONLY; never an open argument.
    metadata: native_api.Metadata
    parts: tuple[str, ...]


class _ConfirmedMissing(Exception):
    pass


def validate_root(root: object) -> tuple[str, str, tuple[str, ...]]:
    if type(root) is not str:
        raise ApiError("invalid_params", "root must be an explicitly selected absolute folder path")
    try:
        sized = 1 < len(root.encode("utf-8")) <= policy.MAX_ROOT_BYTES
    except UnicodeError:
        sized = False
    path = root[4:] if root.startswith("\\\\?\\") else root
    parts = path[3:].split("\\")
    if (not sized or re.match(r"^[A-Za-z]:\\", path, re.ASCII) is None
            or not 1 <= len(parts) <= policy.MAX_ROOT_COMPONENTS
            or not all(native_api.valid_component(part) and policy._safe_component(part) for part in parts)):
        raise ApiError("unsafe_path", "root must be a bounded ordinary or verbatim drive path without aliases")
    return root, path[:2].upper(), tuple(parts)


def validate_config_path(value: object) -> str:
    selected = policy.validate_config_path(value)
    if not all(native_api.valid_component(part) for part in selected.split("/")):
        raise ApiError("unsafe_path", "configPath must contain only ordinary Windows path components")
    return selected


def _new_native(inventory: policy._Inventory) -> native_api.Native:
    # Only the internal factory is replaceable in inert tests; never a request
    # argument/environment setting or a public filesystem/callback API.
    return native_api.Native(lambda: _tick(inventory))


def _tick(inventory: policy._Inventory) -> None:
    if not inventory.tick():
        raise policy._ReadProblem("snapshot.scan-stopped", "Static observation was stopped at its scan limit.")


def _inspect(native: native_api.Native, handle: int, expected_name: str, directory: bool,
             volume: int | None, parts: tuple[str, ...], inventory: policy._Inventory,
             entry: native_api.Entry | None = None) -> _Frame:
    _tick(inventory)
    observed = native.metadata(handle)
    _tick(inventory)
    if (observed.directory != directory or observed.delete_pending
            or observed.attributes & (native_api.REPARSE_ATTRIBUTE | native_api.UNSUPPORTED_ATTRIBUTES)
            or observed.reparse_tag is not None
            or bool(observed.attributes & native_api.DIRECTORY_ATTRIBUTE) != directory
            or (directory and observed.case_flags != 0)
            or (not directory and observed.links != 1)):
        raise native_api.NativeError("unsafe")
    if (type(observed.file_id) is not bytes or len(observed.file_id) != 16 or not any(observed.file_id)
            or observed.size < 0 or (volume is not None and observed.volume != volume)):
        raise native_api.NativeError("unsupported")
    if entry is not None and (observed.file_id != entry.file_id or directory != entry.directory):
        raise native_api.NativeError("changed")
    # Exact long-name/case equality can only REFUSE. Original RootDirectory +
    # OBJ_DONT_REPARSE, not this query, supplied acquisition custody.
    actual_name = native.normalized_name(handle)
    _tick(inventory)
    if actual_name != expected_name or policy._excluded(parts):
        raise native_api.NativeError("unsafe")
    return _Frame(handle, expected_name, observed, parts)


def _recheck(native: native_api.Native, frame: _Frame, inventory: policy._Inventory) -> None:
    _tick(inventory)
    ending = _inspect(native, frame.handle, frame.expected_name, frame.metadata.directory,
                      frame.metadata.volume, frame.parts, inventory)
    _tick(inventory)
    if ending.metadata != frame.metadata:
        raise native_api.NativeError("changed")


def _capture_root(native: native_api.Native, drive: str, parts: tuple[str, ...],
                  inventory: policy._Inventory) -> tuple[str, list[_Frame]]:
    _tick(inventory)
    device = native.drive_mapping(drive)
    _tick(inventory)
    handle = native.open_root(device)
    _tick(inventory)
    frames = [_inspect(native, handle, device + "\\", True, None, (), inventory)]
    native.require_ntfs(handle)
    _tick(inventory)
    for part in parts:
        _tick(inventory)
        parent = frames[-1]
        _recheck(native, parent, inventory)
        child = native.open_child(parent.handle, part, True)
        _tick(inventory)
        expected = parent.expected_name.rstrip("\\") + "\\" + part
        frames.append(_inspect(native, child, expected, True, frames[0].metadata.volume, (), inventory))
    return device, frames


def _entries(native: native_api.Native, parent: _Frame, inventory: policy._Inventory) -> Iterator[native_api.Entry]:
    restart = True
    while True:
        _tick(inventory)
        if inventory.counts["entries"] >= policy.MAX_ENTRIES:
            inventory.stopped = True
            raise policy._ReadProblem("snapshot.entry-limit", "Static directory-entry limit reached.")
        raw = native.directory_batch(parent.handle, restart)
        _tick(inventory)
        if raw is None:
            return
        restart = False
        entries = native_api.decode_directory_batch(raw)
        # Every returned record, even ignored records after a lookup match, is
        # charged before publishing the batch. Refuse an over-budget batch;
        # the public counter saturates, and no entry from it is opened.
        remaining = policy.MAX_ENTRIES - inventory.counts["entries"]
        inventory.counts["entries"] += min(len(entries), remaining)
        if len(entries) > remaining:
            inventory.stopped = True
            raise policy._ReadProblem("snapshot.entry-limit", "Static directory-entry limit reached.")
        for entry in entries:
            _tick(inventory)
            yield entry


def _lookup(native: native_api.Native, parent: _Frame, name: str,
            inventory: policy._Inventory) -> native_api.Entry | None:
    """Bounded original-parent observation; absence also needs a failed open."""
    _recheck(native, parent, inventory)
    found = None
    seen: set[str] = set()
    for entry in _entries(native, parent, inventory):
        if entry.name in seen:
            raise native_api.NativeError("changed")
        seen.add(entry.name)
        if entry.name == name:
            found = entry
    _recheck(native, parent, inventory)
    return found


def _open_child(native: native_api.Native, parent: _Frame, name: str, directory: bool,
                parts: tuple[str, ...], inventory: policy._Inventory,
                entry: native_api.Entry | None) -> _Frame:
    if not native_api.valid_component(name) or policy._excluded(parts):
        raise native_api.NativeError("unsafe")
    if entry is not None and (entry.directory != directory or entry.attributes & (
            native_api.REPARSE_ATTRIBUTE | native_api.UNSUPPORTED_ATTRIBUTES)):
        raise native_api.NativeError("unsafe")
    _recheck(native, parent, inventory)
    try:
        handle = native.open_child(parent.handle, name, directory)
    except native_api.NativeError as error:
        if error.category != "missing":
            raise
        _recheck(native, parent, inventory)
        if entry is not None:
            raise policy._ReadProblem("snapshot.changed", "A previously observed project entry disappeared.") from None
        raise _ConfirmedMissing from None
    try:
        _tick(inventory)
        return _inspect(native, handle, parent.expected_name.rstrip("\\") + "\\" + name,
                        directory, parent.metadata.volume, parts, inventory, entry)
    except BaseException:
        native.close(handle)
        raise


def _read_file(native: native_api.Native, parent: _Frame, name: str, parts: tuple[str, ...],
               inventory: policy._Inventory, entry: native_api.Entry | None) -> str:
    _tick(inventory)
    if inventory.counts["sourceFiles"] >= policy.MAX_SOURCE_FILES:
        inventory.stopped = True
        raise policy._ReadProblem("snapshot.file-limit", "Static source-file count limit reached.")
    inventory.counts["sourceFiles"] += 1
    frame = _open_child(native, parent, name, False, parts, inventory, entry)
    try:
        if frame.metadata.size > policy.MAX_SOURCE_BYTES:
            raise policy._ReadProblem("snapshot.file-size", "A static source file exceeds its byte limit.")
        if frame.metadata.size > policy.MAX_TOTAL_BYTES - inventory.counts["sourceBytes"]:
            inventory.stopped = True
            raise policy._ReadProblem("snapshot.byte-limit", "Static aggregate source-byte limit reached.")
        consumed = 0
        chunks: list[bytes] = []
        while True:
            _tick(inventory)
            remaining = policy.MAX_TOTAL_BYTES - inventory.counts["sourceBytes"]
            if remaining <= 0:
                inventory.stopped = True
                raise policy._ReadProblem("snapshot.byte-limit", "Static byte limit reached before EOF was observed.")
            count = min(native_api.BUFFER_BYTES, policy.MAX_SOURCE_BYTES + 1 - consumed, remaining)
            block = native.read(frame.handle, count)
            if type(block) is not bytes or len(block) > count:
                raise native_api.NativeError("unsupported")
            consumed += len(block)
            inventory.counts["sourceBytes"] += len(block)
            _tick(inventory)
            if consumed > policy.MAX_SOURCE_BYTES:
                raise policy._ReadProblem("snapshot.file-size", "A static source file grew beyond its byte limit.")
            if not block:
                break
            chunks.append(block)
        _recheck(native, frame, inventory)
        _recheck(native, parent, inventory)
        if consumed != frame.metadata.size:
            raise policy._ReadProblem("snapshot.changed", "Static source bytes changed during reading.")
        try:
            return b"".join(chunks).decode("utf-8", errors="strict")
        except UnicodeError:
            raise policy._ReadProblem("snapshot.encoding", "A static source file is not UTF-8 text.") from None
    finally:
        native.close(frame.handle)


def _note_native(error: native_api.NativeError, inventory: policy._Inventory) -> tuple[str, str]:
    code = {"unsafe": "snapshot.unsafe-file", "changed": "snapshot.changed",
            "missing": "snapshot.changed", "unsupported": "snapshot.unsupported", "limit": "snapshot.handle-limit"}.get(
                error.category, "snapshot.unreadable")
    message = "A Windows project entry could not be observed safely; no alternate path was used."
    if error.category == "limit":
        inventory.stopped = True
    inventory.note(code, message)
    return code, message


def _configuration(native: native_api.Native, root: _Frame, relative: str,
                   inventory: policy._Inventory) -> ConfigObservation:
    result: ConfigObservation = {"path": relative, "state": "unavailable", "data": None, "issues": []}
    frames: list[_Frame] = []
    parts = tuple(relative.split("/"))
    parent = root
    try:
        for index, name in enumerate(parts[:-1], 1):
            entry = _lookup(native, parent, name, inventory)
            parent = _open_child(native, parent, name, True, parts[:index], inventory, entry)
            frames.append(parent)
        entry = _lookup(native, parent, parts[-1], inventory)
        text = _read_file(native, parent, parts[-1], parts, inventory, entry)
        for frame in frames:
            _recheck(native, frame, inventory)
        try:
            data = policy.parse_config_text(text)
        except policy.ConfigurationError:
            result["state"] = "invalid"
            result["issues"].append(issue("config.invalid", "Selected configuration is not format-valid."))
        else:
            try:
                policy.bounded_json_text(data, max_nodes=policy.MAX_CONFIG_OUTPUT_NODES)
            except policy.ConfigurationError:
                message = "Configuration exceeds the passive snapshot output budget; no configuration data was returned."
                inventory.note("snapshot.config-output-limit", message)
                result["issues"].append(issue("snapshot.config-output-limit", message, partial=True))
            else:
                result["state"], result["data"] = "format-valid", data
    except _ConfirmedMissing:
        result["state"] = "missing"
        result["issues"].append(issue("config.missing", "No configuration was observed at the selected path.", partial=True))
    except policy._ReadProblem as error:
        inventory.note(error.code, error.message)
        result["issues"].append(issue(error.code, error.message, partial=True))
    except native_api.NativeError as error:
        code, message = _note_native(error, inventory)
        result["issues"].append(issue(code, message, partial=True))
    finally:
        # A close failure propagates to the outer owner, which attempts every
        # still-owned independent original handle before failing the request.
        for frame in reversed(frames):
            native.close(frame.handle)
    return result


def _walk(native: native_api.Native, parent: _Frame, inventory: policy._Inventory, config_path: str) -> None:
    if not inventory.tick():
        return
    seen: set[str] = set()
    try:
        _recheck(native, parent, inventory)
        for entry in _entries(native, parent, inventory):
            if entry.name in {".", ".."}:
                continue
            if entry.name in seen:
                raise native_api.NativeError("changed")
            seen.add(entry.name)
            parts = (*parent.parts, entry.name)
            relative = "/".join(parts)
            if (not native_api.valid_component(entry.name) or not policy._safe_component(entry.name)
                    or len(relative.encode("utf-8")) > policy.MAX_RELATIVE_BYTES):
                inventory.counts["excludedEntries"] += 1
                inventory.note("snapshot.path-limit", "An unsafe or oversized project path was excluded.")
                continue
            if policy._excluded(parts):
                inventory.counts["excludedEntries"] += 1
                continue
            if entry.attributes & (native_api.REPARSE_ATTRIBUTE | native_api.UNSUPPORTED_ATTRIBUTES):
                inventory.counts["excludedEntries"] += 1
                inventory.note("snapshot.link-excluded", "A reparse, offline or unsupported project entry was excluded.")
                continue
            try:
                if entry.directory:
                    if len(parts) > policy.MAX_DEPTH:
                        inventory.counts["excludedEntries"] += 1
                        inventory.note("snapshot.depth-limit", "Static directory-depth limit reached.")
                        continue
                    child = _open_child(native, parent, entry.name, True, parts, inventory, entry)
                    try:
                        if relative.endswith((".xcodeproj", ".xcworkspace")):
                            if len(inventory.directories) >= policy.MAX_SOURCE_FILES:
                                inventory.note("snapshot.container-limit", "Static project-container hint limit reached.")
                            else:
                                inventory.directories.add(relative)
                        _walk(native, child, inventory, config_path)
                    finally:
                        native.close(child.handle)
                elif relative != config_path and policy._source_candidate(relative):
                    inventory.sources[relative] = _read_file(native, parent, entry.name, parts, inventory, entry)
            except policy._ReadProblem as error:
                inventory.note(error.code, error.message)
            except native_api.NativeError as error:
                _note_native(error, inventory)
        _recheck(native, parent, inventory)
    except policy._ReadProblem as error:
        inventory.note(error.code, error.message)
    except native_api.NativeError as error:
        _note_native(error, inventory)


def project_snapshot(root: object, config_path: object = "release/mobile-release.json") -> SnapshotResult:
    selected_root, drive, parts = validate_root(root)
    selected_config = validate_config_path(config_path)
    observed_at = datetime.now(timezone.utc).isoformat()
    inventory = policy._Inventory()
    try:
        native = _new_native(inventory)
    except (native_api.NativeUnavailable, native_api.NativeError):
        raise ApiError("platform_unavailable", "The Windows static reader binding/profile is unavailable") from None
    except policy._ReadProblem:
        raise ApiError("snapshot_unavailable", "Windows reader admission exceeded the static scan limit") from None
    try:
        try:
            device, frames = _capture_root(native, drive, parts, inventory)
        except native_api.NativeError as error:
            raise ApiError("unsafe_path" if error.category == "unsafe" else "snapshot_unavailable",
                           "Selected Windows folder could not be admitted safely; no alternate path was used") from None
        except policy._ReadProblem:
            raise ApiError("snapshot_unavailable", "Selected folder admission exceeded the static scan limit") from None
        config = _configuration(native, frames[-1], selected_config, inventory)
        _walk(native, frames[-1], inventory, selected_config)
        if inventory.tick():
            try:
                for frame in frames:
                    _recheck(native, frame, inventory)
                _tick(inventory)
                current = native.drive_mapping(drive)
                _tick(inventory)
                if current != device:
                    raise native_api.NativeError("changed")
            except (native_api.NativeError, policy._ReadProblem):
                message = "Selected folder or an ancestor changed or became unobservable during this non-atomic observation."
                inventory.note("snapshot.changed", message)
                config = {"path": selected_config, "state": "unavailable", "data": None,
                          "issues": [issue("snapshot.changed", message, partial=True)]}
    finally:
        native.close_all()
    return policy._assemble_snapshot(selected_root, observed_at, inventory, config)
