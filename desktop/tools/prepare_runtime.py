"""Offline publisher preparation of a desktop core/runtime manifest.

This does not download, install, execute or qualify Python. Supply an independently
verified, platform-correct, redistributable Python payload in runtime-root/python.
All files must already be regular, unlinked files (flatten distributor aliases in
the separately reviewed acquisition step). The output is private build material,
not a signed installer or native verification receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path

TARGETS = frozenset({
    "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
})
# Keep this intersection aligned with src-tauri/src/runtime.rs.  Each manifest
# file costs seven JSON nodes, so 2048 files also fit the protocol parser's
# independent 20,000-node limit without weakening that parser.
MAX_FILES = 2048
MAX_ENTRIES = 8192
MAX_PATH_PARTS = 16
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_CORE_BYTES = 32 * 1024 * 1024
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class PreparationError(ValueError):
    pass


def _safe_name(name: str) -> bool:
    return (re.fullmatch(r"[A-Za-z0-9._+\-]+", name, flags=re.ASCII) is not None
            and name not in {".", ".."} and not name.endswith(".")
            and name.split(".", 1)[0].lower() not in _RESERVED)


def _state(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _ordinary(path: Path, *, directory: bool = False) -> os.stat_result:
    value = path.lstat()
    is_reparse = bool(getattr(value, "st_file_attributes", 0) & 0x400)
    if is_reparse or (not stat.S_ISDIR(value.st_mode) if directory else
                      not stat.S_ISREG(value.st_mode) or value.st_nlink != 1):
        raise PreparationError("Only ordinary directories and single-link files may be packaged")
    return value


def _root(path: Path) -> Path:
    # Explicit publisher inputs only, never automatic HOME/PATH discovery.
    if not path.is_absolute() or ".." in path.parts:
        raise PreparationError("Input and output roots must be explicit absolute paths")
    for ancestor in reversed((path, *path.parents)):
        _ordinary(ancestor, directory=True)
    return path


def files(root: Path, *, reserve_entries: int = 0) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    directories: set[Path] = set()
    pending = [(root, 0)]
    entries = 0
    while pending:
        parent, depth = pending.pop()
        if depth >= MAX_PATH_PARTS:
            raise PreparationError("Payload directory depth exceeded")
        with os.scandir(parent) as children:
            for child in children:
                entries += 1
                if entries + reserve_entries > MAX_ENTRIES or not _safe_name(child.name):
                    raise PreparationError("Payload inventory limit or unsafe name")
                path = parent / child.name
                relative = path.relative_to(root).as_posix()
                if (len(relative) > 512 or len(path.relative_to(root).parts) > MAX_PATH_PARTS
                        or relative.lower() in seen):
                    raise PreparationError("Payload path limit or case collision")
                seen.add(relative.lower())
                value = path.lstat()
                if stat.S_ISDIR(value.st_mode):
                    _ordinary(path, directory=True)
                    directories.add(path)
                    pending.append((path, depth + 1))
                else:
                    _ordinary(path)
                    result.append(path)
                    if len(result) > MAX_FILES:
                        raise PreparationError("Payload file count exceeded")
    # The runtime inventory authorizes only file ancestors, never extra empty
    # directories. Reject rather than silently removing publisher inputs.
    required_directories: set[Path] = set()
    for path in result:
        parent = path.parent
        while parent != root:
            required_directories.add(parent)
            parent = parent.parent
    if directories != required_directories:
        raise PreparationError("Payload contains an empty or uninventoried directory")
    return sorted(result, key=lambda item: item.relative_to(root).as_posix())


def read_checked(path: Path, *, limit: int) -> bytes:
    before = _ordinary(path)
    if before.st_size > limit:
        raise PreparationError("Payload file byte limit exceeded")
    with path.open("rb") as stream:
        if _state(os.fstat(stream.fileno())) != _state(before):
            raise PreparationError("Payload file changed before reading")
        # The ceiling is not the expected allocation. Reading a tiny file with
        # read(512 MiB) can reserve that much memory before seeing EOF. One byte
        # beyond the admitted size still detects growth without that overhead.
        content = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    if len(content) > limit or len(content) != before.st_size or _state(after) != _state(before) or _state(path.lstat()) != _state(before):
        raise PreparationError("Payload file changed during reading")
    return content


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare(source: Path, runtime: Path, target: str) -> dict[str, str]:
    if target not in TARGETS:
        raise PreparationError("Unsupported desktop package target")
    source, runtime = _root(source), _root(runtime)
    # No merging, overwriting or adoption of another preparation's output.
    if set(os.listdir(runtime)) != {"python"}:
        raise PreparationError("Runtime output must contain only its pre-admitted python payload")
    python = runtime / "python"
    _ordinary(python, directory=True)
    executable = python / ("python.exe" if "windows" in target else "bin/python3")
    _ordinary(executable)
    _root(executable.parent)
    # Reserve the two payload files and final manifest before writing output.
    # This is only publisher preparation, not runtime-custody admission.
    if len(files(runtime, reserve_entries=3)) > MAX_FILES - 2:
        raise PreparationError("Python payload leaves no room for core resources")
    package = _root(source / "src/mobile_release")
    candidates = files(package)
    if not candidates or any(path.suffix not in {".py", ".json", ".pem"} for path in candidates):
        raise PreparationError("Core inventory contains unexpected/generated files")
    core: list[tuple[str, bytes]] = []
    size = 0
    for path in candidates:
        content = read_checked(path, limit=MAX_CORE_BYTES - size)
        size += len(content)
        core.append(("mobile_release/" + path.relative_to(package).as_posix(), content))
    source_map = dict(core)
    version = re.search(rb'^__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"$', source_map["mobile_release/__init__.py"], re.M)
    if version is None:
        raise PreparationError("Core version must be an explicit package version")
    bootstrap = read_checked(_root(source / "desktop") / "engine_bootstrap.py", limit=64 * 1024)
    with (runtime / "engine_bootstrap.py").open("xb") as stream:
        stream.write(bootstrap)
    with zipfile.ZipFile(runtime / "core.zip", "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in core:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    inventory = []
    total = 0
    for path in files(runtime, reserve_entries=1):
        content = read_checked(path, limit=min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total))
        total += len(content)
        inventory.append({"path": path.relative_to(runtime).as_posix(), "sha256": digest(content), "size": len(content)})
    manifest = {
        "schemaVersion": 1, "protocol": 1, "coreVersion": version[1].decode("ascii"), "target": target,
        "coreSha256": next(item["sha256"] for item in inventory if item["path"] == "core.zip"),
        "protocolSha256": digest(source_map["mobile_release/_desktop_engine.py"]),
        "inventorySha256": digest(canonical(inventory)), "files": inventory,
    }
    encoded = canonical(manifest) + b"\n"
    if len(encoded) > 1024 * 1024:
        raise PreparationError("Manifest byte limit exceeded")
    with (runtime / "manifest.json").open("xb") as stream:
        stream.write(encoded)
    return {"manifestSha256": digest(encoded), "protocolSha256": manifest["protocolSha256"],
            "qualification": "prepared-not-native-verified"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.source, args.runtime_root, args.target), sort_keys=True))
    except (OSError, ValueError, KeyError, UnicodeError):
        parser.exit(1, "Runtime preparation failed. Existing inputs/partial output were preserved; no native qualification was performed.\n")


if __name__ == "__main__":
    main()
