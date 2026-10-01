"""Closed Windows required-note DATA shapes; no filesystem or native authority.

Only the original required-note lease can select this family. Validating a
renderer-supplied dictionary never opens a handle or selects an implementation.
"""
from __future__ import annotations

import re
from typing import Any

PLATFORM = "windows-ntfs-v1"
_ROOT_KEYS = frozenset({"platform", "volumeSerial", "fileId"})
_MATERIAL_KEYS = _ROOT_KEYS | {"kind", "attributes", "securityTransitionKey"}
_FILE_KEYS = _MATERIAL_KEYS | {"size", "sha256"}
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_U64 = re.compile(r"0|[1-9][0-9]{0,19}\Z")
_MAX_U64 = 2**64 - 1


class WindowsNotesContractError(ValueError):
    """A constant-only boundary failure; never native diagnostics or file text."""


def _refuse() -> None:
    raise WindowsNotesContractError("Invalid Windows required-note DATA") from None


def canonical_u64(value: object, *, nonzero: bool = False) -> int:
    if (type(value) is not str or _U64.fullmatch(value) is None
            or int(value) > _MAX_U64 or nonzero and value == "0"):
        _refuse()
    return int(value)


def registered_root(value: object) -> dict[str, str]:
    if (type(value) is not dict or value.keys() != _ROOT_KEYS
            or type(value["platform"]) is not str or value["platform"] != PLATFORM
            or type(value["volumeSerial"]) is not str or _HEX16.fullmatch(value["volumeSerial"]) is None
            or type(value["fileId"]) is not str or _HEX32.fullmatch(value["fileId"]) is None):
        _refuse()
    # This exact copied shape is DATA, not an original root lease.
    return {key: value[key] for key in ("platform", "volumeSerial", "fileId")}


def material(value: object, *, directory: bool, limit: int | None = None) -> dict[str, Any]:
    if type(directory) is not bool or (limit is not None and (type(limit) is not int or limit < 0)):
        _refuse()
    keys = _MATERIAL_KEYS if directory else _FILE_KEYS
    if type(value) is not dict or value.keys() != keys:
        _refuse()
    registered_root({key: value[key] for key in ("platform", "volumeSerial", "fileId")})
    if (type(value["kind"]) is not str or value["kind"] != ("directory" if directory else "file")
            or type(value["attributes"]) is not int or not 0 <= value["attributes"] < 2**32):
        _refuse()
    canonical_u64(value["securityTransitionKey"], nonzero=True)
    if not directory:
        size = canonical_u64(value["size"])
        if (limit is not None and size > limit or type(value["sha256"]) is not str
                or _HEX64.fullmatch(value["sha256"]) is None):
            _refuse()
    return dict(value)


def material_valid(value: object, *, directory: bool = False, limit: int | None = None) -> bool:
    try:
        material(value, directory=directory, limit=limit)
    except WindowsNotesContractError:
        return False
    return True
