"""Offline publisher preparation of a desktop core/runtime manifest.

This does not download, install, execute or qualify Python. Supply an independently
verified, platform-correct, redistributable Python payload in runtime-root/python.
All files must already be regular, unlinked files (flatten distributor aliases in
the separately reviewed acquisition step). The output is private build material,
not a signed installer or native verification receipt.
"""

from __future__ import annotations

import argparse
import ast
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
MAC_MAX_FILES = 16384
MAC_MAX_ENTRIES = 32768
MAC_MANIFEST_BYTES = 12 * 1024 * 1024
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
    "ios_archive_bootstrap.py", "github_release_bootstrap.py", "artifact_inspection_bootstrap.py", "github_setup_bootstrap.py", "github_history_bootstrap.py", "local_release_history_bootstrap.py",
)
STORE_BOOTSTRAP = "local_store_preflight_bootstrap.py"
GITHUB_CA_NAME = "github-ca.pem"
MAX_GITHUB_CA_BYTES = 512 * 1024
STORE_EXECUTABLES = frozenset({"bin/ruby", "bin/bundle"})
STORE_REQUIRED_FILES = frozenset({
    *STORE_EXECUTABLES, "bin/mrk_bundle_setup.rb", "ca.pem", "lib/ruby/gems/3.3.0/gems/bundler-4.0.16/exe/bundle",
    "bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane.rb",
    "licenses/Ruby-COPYING", "licenses/Ruby-BSDL", "licenses/Ruby-LEGAL",
    "licenses/OpenSSL-LICENSE.txt", "licenses/LibYAML-License", "licenses/locked-gem-licenses.txt",
})
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class PreparationError(ValueError):
    pass


def _safe_name(name: str, *, mac_store: bool = False) -> bool:
    pattern = r"[A-Za-z0-9._+% \-]+" if mac_store else r"[A-Za-z0-9._+\-]+"
    return (re.fullmatch(pattern, name, flags=re.ASCII) is not None
            and name not in {".", ".."} and not name.startswith(" ") and not name.endswith((".", " "))
            and name.split(".", 1)[0].lower() not in _RESERVED)


def _safe_runtime_path(name: str, *, store_prefix: str | None = None) -> bool:
    if type(name) is not str or not name or len(name) > 512 or store_prefix not in (None, "", "store"):
        return False
    parts = name.split("/")
    scoped = store_prefix == "" or store_prefix == "store" and name.startswith("store/")
    prefix_parts = 1 if store_prefix == "store" else 0
    return (len(parts) <= MAX_PATH_PARTS + (prefix_parts if scoped else 0)
            and all(_safe_name(part, mac_store=scoped and index >= prefix_parts)
                    for index, part in enumerate(parts)))


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


def _files(root: Path, *, reserve_entries: int = 0, max_files: int | None = None,
           max_entries: int | None = None, store_prefix: str | None = None,
           supplier_directories: dict | None = None) -> list[Path]:
    max_files = MAX_FILES if max_files is None else max_files
    max_entries = MAX_ENTRIES if max_entries is None else max_entries
    result: list[Path] = []
    seen: set[str] = set()
    directories: set[Path] = set()
    pending = [(root, 0)]
    entries = 0
    while pending:
        parent, depth = pending.pop()
        depth_limit = MAX_PATH_PARTS + (1 if store_prefix == "store" else 0)
        if depth > depth_limit or depth == depth_limit and supplier_directories is None:
            raise PreparationError("Payload directory depth exceeded")
        if supplier_directories is not None:
            supplier_directories[parent] = _state(_ordinary(parent, directory=True))
        with os.scandir(parent) as children:
            for child in children:
                entries += 1
                path = parent / child.name
                relative = path.relative_to(root).as_posix()
                if entries + reserve_entries > max_entries or not _safe_runtime_path(relative, store_prefix=store_prefix):
                    raise PreparationError("Payload inventory limit or unsafe name")
                if relative.lower() in seen:
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
                    if len(result) > max_files:
                        raise PreparationError("Payload file count exceeded")
    # The runtime inventory authorizes only file ancestors, never extra empty
    # directories. Reject rather than silently removing publisher inputs.
    required_directories: set[Path] = set()
    for path in result:
        parent = path.parent
        while parent != root:
            required_directories.add(parent)
            parent = parent.parent
    if supplier_directories is None and directories != required_directories:
        raise PreparationError("Payload contains an empty or uninventoried directory")
    return sorted(result, key=lambda item: item.relative_to(root).as_posix())


def files(root: Path, *, reserve_entries: int = 0, max_files: int | None = None,
          max_entries: int | None = None, mac_store: bool = False) -> list[Path]:
    if type(mac_store) is not bool:
        raise PreparationError("Invalid runtime path profile")
    return _files(root, reserve_entries=reserve_entries, max_files=max_files, max_entries=max_entries,
                  store_prefix="store" if mac_store else None)


def store_component_files(root: Path, *, directories: dict) -> list[Path]:
    """Explicit signed Store supplier input, not a generic output-tree profile.

    Empty supplier directories are observed for POST, never manufactured in the
    final file inventory. Every filename and byte remains in the Store copy.
    """
    if type(directories) is not dict or directories:
        raise PreparationError("Store directory observation must start empty")
    return _files(_root(root), max_files=MAC_MAX_FILES, max_entries=MAC_MAX_ENTRIES,
                  store_prefix="", supplier_directories=directories)


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


def prepare_current(source: Path, runtime: Path, target: str, *, history_provider: bool = False,
                    store_component: Path | None = None) -> dict[str, str]:
    """Current complete fixed roster, still DATA only and never qualification."""
    return _prepare(source, runtime, target, current=True, history_provider=history_provider,
                    store_component=store_component)


def _store_tooling_names(body: bytes) -> tuple[str, ...]:
    """Pure roster for captured selected-core DATA; no imported core or IO."""
    if type(body) is not bytes or not body or len(body)>MAX_CORE_BYTES:
        raise PreparationError("Selected core tooling source is unbounded")
    try:
        assignments = [node.value for node in ast.parse(body).body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "REQUIRED_TOOLING_FILES"
                               for target in node.targets)]
        if len(assignments) != 1:
            raise ValueError("Missing or ambiguous tooling roster")
        names = ast.literal_eval(assignments[0])
    except (SyntaxError, ValueError, TypeError) as error:
        raise PreparationError("Selected core tooling roster must be literal DATA") from error
    if (type(names) is not tuple or not 0 < len(names) <= MAX_FILES
            or any(type(name) is not str or not name or len(name) > 512
                   or not all(_safe_name(part) for part in name.split("/")) for name in names)
            or len({name.lower() for name in names}) != len(names)):
        raise PreparationError("Selected core tooling roster has invalid or duplicate paths")
    return names


def _store_tooling_files(source: Path) -> tuple[tuple[str, ...], bytes]:
    body=read_checked(source / "src/mobile_release/tooling.py",limit=MAX_CORE_BYTES)
    return _store_tooling_names(body),body


def _store_inputs(component: Path, source: Path, runtime: Path):
    """Observe an already authenticated component; never acquire/execute it.

    Native architecture, linkage and signing belong to the component producer
    and final Mac stager. These original-byte checks prevent mixing inputs while
    composing the complete runtime manifest; they are not supplier authority.
    """
    component = _root(component)
    if component == runtime or component in runtime.parents or runtime in component.parents:
        raise PreparationError("Store component and runtime output must not overlap")
    original_directories = {}
    paths = store_component_files(component, directories=original_directories)
    tooling_files, tooling_source = _store_tooling_files(source)
    required = STORE_REQUIRED_FILES
    relative = {path.relative_to(component).as_posix() for path in paths}
    if not required <= relative or "tooling" in relative:
        raise PreparationError("Store component lacks runtime/notices or conflicts with tooling")
    if not {"Gemfile","Gemfile.lock","fastlane/Fastfile","fastlane/run_lane.rb",
            "fastlane/native_process_spawn.rb"} <= set(tooling_files):
        raise PreparationError("Selected core lacks required Store entry tooling")
    rows = []
    total = 0
    for path in paths:
        name = path.relative_to(component).as_posix()
        # The outer manifest adds store/; apply its path/depth bounds here too.
        if not _safe_runtime_path("store/" + name, store_prefix="store"):
            raise PreparationError("Store component cannot fit the runtime path bounds")
        state = _state(_ordinary(path))
        body = read_checked(path, limit=min(MAX_FILE_BYTES, 512 * 1024 * 1024 - total))
        total += len(body)
        if name in required and not body:
            raise PreparationError("A required Store component file is empty")
        if name in STORE_EXECUTABLES and not stat.S_IMODE(state[2]) & 0o111:
            raise PreparationError("Store entry must be an executable component input")
        if name == "bin/bundle" and not body.startswith(b"#!/bin/sh\n"):
            raise PreparationError("Store wrapper requires the fixed system shell, not ambient lookup")
        rows.append((name, state, digest(body), len(body)))
    _store_post(component, rows, original_directories)
    # Dependency artifacts may carry older tooling. Never merge that subtree:
    # the current selected core supplies the entire new tooling namespace.
    tooling_rows=[];tooling_directories={}
    component_digests={name:(sha,size) for name,_,sha,size in rows}
    output_total=sum(size for name,_,_,size in rows if not name.startswith("tooling/"))
    for name in sorted(tooling_files):
        path=source / name
        try:
            _root(path.parent)
            for parent in path.parents:
                if parent==source or source in parent.parents:
                    tooling_directories.setdefault(parent,_state(_ordinary(parent,directory=True)))
            state=_state(_ordinary(path))
            body=read_checked(path,limit=min(MAX_FILE_BYTES,512*1024*1024-output_total))
        except FileNotFoundError as error:
            raise PreparationError("A required selected Store tooling input is missing") from error
        if not body:raise PreparationError("Selected Store tooling is empty")
        sha=digest(body)
        # Installed gems came from these actual dependency inputs, not merely
        # the same Ruby version. Source-only tooling edits can reuse the gemset;
        # changed dependency inputs require reassembly from the native base.
        if (name in {"Gemfile","Gemfile.lock"}
                and component_digests.get("tooling/"+name)!=(sha,len(body))):
            raise PreparationError("Store dependency inputs changed; reassemble the locked gems")
        output_total+=len(body)
        tooling_rows.append(("tooling/"+name,state,sha,len(body)))
    # [0:5] preserve dependency observations; [5:8] are current source originals.
    observed=(component,tuple(rows),original_directories,output_total,tooling_source,
              source,tuple(tooling_rows),tooling_directories)
    _store_tooling_post(observed)
    return observed


def _store_post(component, rows, directories):
    current_directories = {}
    if ([path.relative_to(component).as_posix() for path in store_component_files(component, directories=current_directories)] != [row[0] for row in rows]
            or current_directories != directories
            or any(_state(_ordinary(component / name)) != state for name, state, _, _ in rows)):
        raise PreparationError("Store component original or roster changed")


def _store_copy_rows(observed):
    return tuple(sorted([row for row in observed[1] if not row[0].startswith("tooling/")]
                        +list(observed[6]),key=lambda row:row[0]))


def _store_output_rows(observed):
    """Immutable final (relative name, sha256, size) rows, before any copy."""
    return tuple((name,sha,size) for name,_,sha,size in _store_copy_rows(observed))


def _store_recheck(observed):
    _store_post(observed[0],observed[1],observed[2])
    _store_tooling_post(observed)


def _store_tooling_post(observed):
    source,rows,directories=observed[5:8]
    if any(_state(_ordinary(path,directory=True))!=state for path,state in directories.items()):
        raise PreparationError("Selected Store tooling ancestor changed")
    for name,state,expected,size in rows:
        path=source / name.removeprefix("tooling/")
        if _state(_ordinary(path))!=state or digest(read_checked(path,limit=size))!=expected:
            raise PreparationError("Selected Store tooling original changed")


def _copy_store(observed, runtime):
    component, rows, directories = observed[:3]
    _store_post(component, rows, directories)
    _store_tooling_post(observed)
    output = runtime / "store"
    copies = _store_copy_rows(observed)
    parents = {output}
    for name, _, _, _ in copies:
        parents.update(output / parent for parent in Path(name).parents if parent != Path("."))
    created = []
    for directory in sorted(parents, key=lambda path: (len(path.parts), str(path))):
        # Every directory is exclusive task output. Never normalize an input or
        # adopt an existing directory through mkdir(exist_ok=True).
        directory.mkdir(mode=0o700)
        original = _ordinary(directory, directory=True)
        created.append((directory, (original.st_dev, original.st_ino, original.st_uid, original.st_gid)))
    for name, state, expected, size in copies:
        path = (observed[5] / name.removeprefix("tooling/") if name.startswith("tooling/") else component / name)
        body = read_checked(path, limit=size)
        if _state(_ordinary(path)) != state or digest(body) != expected:
            raise PreparationError("Store component original changed during copying")
        target = output / name
        with target.open("xb") as stream:
            stream.write(body)
            os.fchmod(stream.fileno(), 0o555 if name in STORE_EXECUTABLES else 0o444)
    _store_post(component, rows, directories)
    _store_tooling_post(observed)
    # The containing runtime's root remains private/writable for core.zip and
    # its manifest; all prepared descendants have the stager's read-only mode.
    for directory, identity in reversed(created):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for actual in (os.fstat(fd), _ordinary(directory, directory=True)):
                if (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_gid) != identity or stat.S_IMODE(actual.st_mode) != 0o700:
                    raise PreparationError("Copied Store directory changed before sealing")
            os.fchmod(fd, 0o555)
        finally:
            os.close(fd)


def _prepare(source: Path, runtime: Path, target: str, *, current: bool,
             history_provider: bool = False, store_component: Path | None = None) -> dict[str, str]:
    bootstrap_names = CURRENT_BOOTSTRAPS if current else BOOTSTRAPS
    current_mac = current and target in {"aarch64-apple-darwin", "x86_64-apple-darwin"}
    file_limit = MAC_MAX_FILES if current_mac else MAX_FILES
    entry_limit = MAC_MAX_ENTRIES if current_mac else MAX_ENTRIES
    manifest_limit = MAC_MANIFEST_BYTES if current_mac else 1024 * 1024
    if target not in TARGETS:
        raise PreparationError("Unsupported desktop package target")
    if type(history_provider) is not bool or (history_provider and
            (not current or target not in {"aarch64-apple-darwin", "x86_64-apple-darwin"})):
        raise PreparationError("History provider is a fixed current Mac input only")
    if store_component is not None and (not current or target not in
            {"aarch64-apple-darwin", "x86_64-apple-darwin"} or not isinstance(store_component, Path)):
        raise PreparationError("Store component is an explicit current Mac input only")
    if store_component is not None:
        bootstrap_names = (*bootstrap_names, STORE_BOOTSTRAP)
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
        provider_paths = files(runtime, reserve_entries=len(bootstrap_names) + 3, max_files=file_limit, max_entries=entry_limit)
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
    preadmitted = provider_paths if provider_paths is not None else files(runtime, reserve_entries=generated_payloads + 1, max_files=file_limit, max_entries=entry_limit)
    store = _store_inputs(store_component, source, runtime) if store_component is not None else None
    store_rows = _store_output_rows(store) if store else ()
    store_files = len(store_rows)
    if len(preadmitted) + store_files > file_limit - generated_payloads - (1 if history_provider else 0):
        raise PreparationError("Python payload leaves no room for core resources")
    if store:
        total_limit = min(total_limit, 512 * 1024 * 1024)
        # Count the combined file ancestors, not merely each tree separately.
        names = {path.relative_to(runtime).as_posix() for path in preadmitted}
        names.update("store/" + row[0] for row in store_rows)
        names.update((*bootstrap_names, "core.zip", GITHUB_CA_NAME, "manifest.json"))
        entries = set(names)
        for name in names:
            entries.update(parent.as_posix() for parent in Path(name).parents if parent != Path("."))
        if len(entries) > entry_limit:
            raise PreparationError("Combined Store runtime entry limit exceeded")
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
    if store and source_map.get("mobile_release/tooling.py") != store[4]:
        raise PreparationError("Selected core tooling roster changed before composition")
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
    if provider is not None or store is not None:
        # Quote actual input lengths and bounded generated resources before
        # reading the large provider or creating any generated payload. The
        # containing stager independently keeps the same512MiB total ceiling.
        quote = (sum(_ordinary(path).st_size for path in preadmitted) + size + MAX_FILES * 2048
                 + sum(len(content) for _, content in bootstraps) + len(github_ca) + manifest_limit
                 + (store[3] if store else 0))
        if quote > total_limit:
            raise PreparationError("Current provider leaves no room for complete runtime resources")
    if provider is not None:
        if (_state(_ordinary(provider)) != provider_state
                or _state(_ordinary(provider.parent, directory=True)) != provider_directory_state):
            raise PreparationError("Current provider original changed before preparation")
        provider_digest = digest(read_checked(provider, limit=128 * 1024 * 1024))
        provider_expected = {path.relative_to(runtime).as_posix() for path in preadmitted}
        provider_expected.update((*bootstrap_names, "core.zip", GITHUB_CA_NAME))
        if store:
            provider_expected.update("store/" + row[0] for row in store_rows)
    if store:
        _copy_store(store, runtime)
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
    for path in files(runtime, reserve_entries=1, max_files=file_limit, max_entries=entry_limit,
                      mac_store=current_mac and store is not None):
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
    if store:
        _store_post(store[0], store[1], store[2])
        _store_tooling_post(store)
        expected_store = {"store/" + name: (sha, size) for name, sha, size in store_rows}
        actual_store = {row["path"]: (row["sha256"], row["size"]) for row in inventory
                        if row["path"].startswith("store/")}
        if actual_store != expected_store:
            raise PreparationError("Copied Store runtime differs from the observed component")
    manifest = {
        "schemaVersion": 1, "protocol": 1, "coreVersion": version[1].decode("ascii"), "target": target,
        "coreSha256": next(item["sha256"] for item in inventory if item["path"] == "core.zip"),
        "protocolSha256": digest(source_map["mobile_release/_desktop_engine.py"]),
        "inventorySha256": digest(canonical(inventory)), "files": inventory,
    }
    encoded = canonical(manifest) + b"\n"
    if len(encoded) > manifest_limit:
        raise PreparationError("Manifest byte limit exceeded")
    if (history_provider or store) and total + len(encoded) > total_limit:
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
    parser.add_argument("--store-component", type=Path,
                        help="Already authenticated Mac Store component; current profile only, no native qualification")
    args = parser.parse_args(argv)
    try:
        if args.store_component is not None and args.profile != "current":
            raise PreparationError("Store component requires the current profile")
        result = (prepare_current(args.source, args.runtime_root, args.target, store_component=args.store_component)
                  if args.profile == "current" else prepare(args.source, args.runtime_root, args.target))
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, UnicodeError):
        parser.exit(1, "Runtime preparation failed. Existing inputs/partial output were preserved; no native qualification was performed.\n")


if __name__ == "__main__":
    main()
