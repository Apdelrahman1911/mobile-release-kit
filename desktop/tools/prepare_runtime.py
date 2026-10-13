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
MAX_BOOTSTRAP_BYTES = 64 * 1024
BOOTSTRAPS = (
    "engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
    "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py",
)
# Keep the historical supplier preparation exact. Current product callers must
# select this complete roster explicitly; file presence never selects a domain.
CURRENT_BOOTSTRAPS = (
    *BOOTSTRAPS, "project_recovery_bootstrap.py", "github_preflight_bootstrap.py",
    "ios_archive_bootstrap.py", "github_release_bootstrap.py", "artifact_inspection_bootstrap.py", "github_setup_bootstrap.py", "github_history_bootstrap.py",
)
GITHUB_CA_NAME = "github-ca.pem"
MAX_GITHUB_CA_BYTES = 512 * 1024
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class PreparationError(ValueError):
    pass


def _safe_name(name: str) -> bool:
    return (re.fullmatch(r"[A-Za-z0-9._+\-]+", name, flags=re.ASCII) is not None
            and name not in {".", ".."} and not name.endswith(".")
            and name.split(".", 1)[0].lower() not in _RESERVED)


def _windows_identity(value: os.stat_result, mode: int) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, mode, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_birthtime_ns, value.st_file_attributes,
            value.st_reparse_tag)


def _state(value: os.stat_result) -> tuple[int, ...]:
    if os.name == "nt":
        # Same-API snapshots retain raw mode and ctime (descriptor ChangeTime)
        # plus every comparable Windows field. Only cross-API checks differ.
        return _windows_identity(value, value.st_mode) + (value.st_ctime_ns,)
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
        opened = os.fstat(stream.fileno())
        if os.name == "nt":
            # CPython 3.14 Windows pathname stat decorates these suffixes with
            # 0111 and exposes birthtime as ctime; fstat keeps raw mode and
            # ChangeTime. Normalize only the named suffix decoration, compare
            # birthtime across APIs, and retain both raw same-API snapshots.
            named_mode = before.st_mode
            if path.name.lower().endswith((".exe", ".bat", ".cmd", ".com")):
                named_mode &= ~0o111
            matches = (_windows_identity(before, named_mode)
                       == _windows_identity(opened, opened.st_mode))
        else:
            matches = _state(opened) == _state(before)
        if not matches:
            raise PreparationError("Payload file changed before reading")
        # The ceiling is not the expected allocation. Reading a tiny file with
        # read(512 MiB) can reserve that much memory before seeing EOF. One byte
        # beyond the admitted size still detects growth without that overhead.
        content = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    descriptor_before = opened if os.name == "nt" else before
    if (len(content) > limit or len(content) != before.st_size
            or _state(after) != _state(descriptor_before)
            or _state(path.lstat()) != _state(before)):
        raise PreparationError("Payload file changed during reading")
    return content


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare(source: Path, runtime: Path, target: str) -> dict[str, str]:
    """Historical fixed preparation; does not include newer product domains."""
    return _prepare(source, runtime, target, current=False)


def prepare_current(source: Path, runtime: Path, target: str, *, history_provider: bool = False) -> dict[str, str]:
    """Current complete fixed roster, still DATA only and never qualification."""
    return _prepare(source, runtime, target, current=True, history_provider=history_provider)


def _prepare(source: Path, runtime: Path, target: str, *, current: bool,
             history_provider: bool = False) -> dict[str, str]:
    bootstrap_names = CURRENT_BOOTSTRAPS if current else BOOTSTRAPS
    if target not in TARGETS:
        raise PreparationError("Unsupported desktop package target")
    if type(history_provider) is not bool or (history_provider and
            (not current or target not in {"aarch64-apple-darwin", "x86_64-apple-darwin"})):
        raise PreparationError("History provider is a fixed current Mac input only")
    source, runtime = _root(source), _root(runtime)
    provider = None
    provider_paths = None
    provider_state = None
    provider_directory_state = None
    provider_digest = None
    total_limit = MAX_TOTAL_BYTES
    # No merging, overwriting or adoption of another preparation's output.
    if history_provider:
        # The existing incremental inventory bounds every entry before the
        # closed root/one-provider roster is inspected; no new eager listdir.
        provider_paths = files(runtime, reserve_entries=len(bootstrap_names) + 3)
        relative = [path.relative_to(runtime).as_posix() for path in provider_paths]
        if ({name.split("/", 1)[0] for name in relative} != {"python", "tools"}
                or [name for name in relative if not name.startswith("python/")] != ["tools/gh"]):
            raise PreparationError("Current provider input must be exactly tools/gh beside python")
        provider = runtime / "tools/gh"
        provider_directory_state = _state(_ordinary(provider.parent, directory=True))
        value = _ordinary(provider)
        if stat.S_IMODE(value.st_mode) != 0o555 or not 0 < value.st_size <= 128 * 1024 * 1024:
            raise PreparationError("Current provider input mode or byte bound")
        provider_state = _state(value)
        total_limit = min(MAX_TOTAL_BYTES, 512 * 1024 * 1024)
    elif set(os.listdir(runtime)) != {"python"}:
        raise PreparationError("Runtime output must contain only its pre-admitted python payload")
    python = runtime / "python"
    _ordinary(python, directory=True)
    executable = python / ("python.exe" if "windows" in target else "bin/python3")
    _ordinary(executable)
    _root(executable.parent)
    # Every fixed entry point, the core ZIP and the fixed CA are payload. Their
    # presence/digests do not qualify an owner, TLS, or native execution custody.
    generated_payloads = len(bootstrap_names) + 2
    # Reserve every generated payload and the final manifest before any write.
    # This is only publisher preparation, not runtime-custody admission.
    preadmitted = provider_paths if provider_paths is not None else files(runtime, reserve_entries=generated_payloads + 1)
    if len(preadmitted) > MAX_FILES - generated_payloads - (1 if history_provider else 0):
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
    desktop = _root(source / "desktop")
    # Admit every selected fixed entry point and the CA before creating output;
    # an absent source must not leave a deceptively complete passive bundle.
    # CA bytes are opaque publisher input, not an acquired trust store or proof
    # of certificate correctness. Never synthesize a placeholder or use the OS.
    bootstraps = [(name, read_checked(desktop / name, limit=MAX_BOOTSTRAP_BYTES)) for name in bootstrap_names]
    github_ca = read_checked(desktop / GITHUB_CA_NAME, limit=MAX_GITHUB_CA_BYTES)
    if not github_ca:
        raise PreparationError("The fixed GitHub CA payload is empty")
    provider_expected = None
    if provider is not None:
        # Quote actual input lengths and bounded generated resources before
        # reading the large provider or creating any generated payload. The
        # containing stager independently keeps the same512MiB total ceiling.
        quote = (sum(_ordinary(path).st_size for path in preadmitted) + size + MAX_FILES * 2048
                 + sum(len(content) for _, content in bootstraps) + len(github_ca) + 1024 * 1024)
        if quote > total_limit:
            raise PreparationError("Current provider leaves no room for complete runtime resources")
        if (_state(_ordinary(provider)) != provider_state
                or _state(_ordinary(provider.parent, directory=True)) != provider_directory_state):
            raise PreparationError("Current provider original changed before preparation")
        provider_digest = digest(read_checked(provider, limit=128 * 1024 * 1024))
        provider_expected = {path.relative_to(runtime).as_posix() for path in preadmitted}
        provider_expected.update((*bootstrap_names, "core.zip", GITHUB_CA_NAME))
    for name, content in bootstraps:
        with (runtime / name).open("xb") as stream:
            stream.write(content)
    with (runtime / GITHUB_CA_NAME).open("xb") as stream:
        stream.write(github_ca)
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
        relative = path.relative_to(runtime).as_posix()
        if provider_expected is not None and relative not in provider_expected:
            raise PreparationError("Current provider runtime acquired an unexpected payload")
        limit = min(MAX_FILE_BYTES, total_limit - total)
        if path == provider:
            limit = min(limit, 128 * 1024 * 1024)
        content = read_checked(path, limit=limit)
        total += len(content)
        content_digest = digest(content)
        if path == provider and (_state(_ordinary(provider)) != provider_state or content_digest != provider_digest):
            raise PreparationError("Current provider original changed during preparation")
        inventory.append({"path": relative, "sha256": content_digest, "size": len(content)})
    if provider is not None:
        if ({row["path"] for row in inventory} != provider_expected
                or _state(_ordinary(provider)) != provider_state
                or _state(_ordinary(provider.parent, directory=True)) != provider_directory_state):
            raise PreparationError("Current provider runtime original or roster changed")
    manifest = {
        "schemaVersion": 1, "protocol": 1, "coreVersion": version[1].decode("ascii"), "target": target,
        "coreSha256": next(item["sha256"] for item in inventory if item["path"] == "core.zip"),
        "protocolSha256": digest(source_map["mobile_release/_desktop_engine.py"]),
        "inventorySha256": digest(canonical(inventory)), "files": inventory,
    }
    encoded = canonical(manifest) + b"\n"
    if len(encoded) > 1024 * 1024:
        raise PreparationError("Manifest byte limit exceeded")
    if history_provider and total + len(encoded) > total_limit:
        raise PreparationError("Complete current provider runtime exceeds its byte limit")
    with (runtime / "manifest.json").open("xb") as stream:
        stream.write(encoded)
    return {"manifestSha256": digest(encoded), "protocolSha256": manifest["protocolSha256"],
            "qualification": "prepared-not-native-verified"}


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--profile", choices=("historical", "current"), default="historical",
                        help="Explicit current ten-bootstrap product roster, or backward-compatible historical roster")
    args = parser.parse_args(argv)
    try:
        action = prepare_current if args.profile == "current" else prepare
        print(json.dumps(action(args.source, args.runtime_root, args.target), sort_keys=True))
    except (OSError, ValueError, KeyError, UnicodeError):
        parser.exit(1, "Runtime preparation failed. Existing inputs/partial output were preserved; no native qualification was performed.\n")


if __name__ == "__main__":
    main()
