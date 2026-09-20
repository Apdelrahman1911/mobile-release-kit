"""Closed input/data helpers for the one proposed Linux CPython source recipe.

A matching sealed lock is input identity, NOT execution or production approval.
There is no acquisition, signature-verification claim, candidate import, package
installation or subprocess launcher in this module. Use only in the separately
reviewed publisher envelope. Every output is private build evidence.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import sys

PROFILE = "cpython-3.14.7-linux-x86_64-static-v1"
TARGET = {"triple": "x86_64-unknown-linux-gnu", "userspace": "ubuntu-24.04",
          "pythonVersion": "3.14.7", "gil": True}
CPYTHON_COMMIT = "823f0323ee6ec1402088b73bce1a38473cac36dc"
CORE_PROFILE_SHA256 = "988c9ba2ca2aa343c9c7f2caae4c92c36e0ca7224f53c519303f5cdeae9e319f"
SOURCE_PINS = {
    "cpython": ("3.14.7", 24053924,
                "3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81",
                "https://www.python.org/ftp/python/3.14.7/Python-3.14.7.tar.xz"),
    "zlib": ("1.3.2", 1502830,
             "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16",
             "https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz"),
    "libffi": ("3.4.8", 1397992,
               "bc9842a18898bfacb0ed1252c4febcc7e78fa139fd27fdc7a3e30d9d9356119b",
               "https://github.com/libffi/libffi/releases/download/v3.4.8/libffi-3.4.8.tar.gz"),
}
STATIC_MODULES = tuple("_bisect _blake2 _ctypes _heapq _hmac _json _md5 _posixsubprocess "
                       "_random _sha1 _sha2 _sha3 _struct binascii fcntl math select unicodedata zlib".split())
BOOTSTRAP_MODULES = tuple("atexit faulthandler posix _signal _tracemalloc _suggestions _datetime "
    "_codecs _collections errno _io itertools _sre _sysconfig _thread time _types _typing "
    "_weakref _abc _functools _locale _opcode _operator _stat _symtable pwd".split())
INTRINSIC_MODULES = tuple("marshal _imp _ast _tokenize builtins sys gc _contextvars _warnings _string".split())
DISABLED_MODULES = tuple("_asyncio _bz2 _codecs_cn _codecs_hk _codecs_iso2022 _codecs_jp "
    "_codecs_kr _codecs_tw _csv _ctypes_test _curses _curses_panel _dbm _decimal "
    "_elementtree _gdbm _hashlib _interpchannels _interpqueues _interpreters _lsprof "
    "_lzma _multibytecodec _multiprocessing _pickle _posixshmem _queue _remote_debugging "
    "_scproxy _socket _sqlite3 _ssl _statistics _testbuffer _testcapi _testclinic "
    "_testclinic_limited _testimportmultiple _testinternalcapi _testlimitedcapi "
    "_testmultiphase _testsinglephase _tkinter _uuid _xxtestfuzz _zoneinfo _zstd array "
    "cmath grp mmap pyexpat readline resource syslog termios xxlimited xxlimited_35 xxsubtype".split())
PYTHON_CONFIGURE = ("--prefix=/opt/mrk-python", "--with-platlibdir=lib", "--disable-shared",
    "--without-mimalloc", "--with-pymalloc", "--with-lto=no", "--disable-optimizations",
    "--disable-test-modules", "--with-ensurepip=no", "--with-pkg-config=no",
    "--with-builtin-hashlib-hashes=md5,sha1,sha2,sha3,blake2")
ZLIB_CONFIGURE = ("--static", "--prefix=/work/deps")
FFI_CONFIGURE = ("--disable-shared", "--enable-static", "--with-pic", "--disable-docs",
                 "--disable-multi-os-directory", "--prefix=/work/deps", "--libdir=/work/deps/lib")
PHASES = ("zlib-configure", "zlib-build", "zlib-install", "libffi-configure", "libffi-build",
          "libffi-install", "python-configure", "hacl-build", "python-build", "python-install")
BUILD_FILES = ("cpython_static_inputs.py", "cpython_static_link.py", "cpython_static_recipe.sh",
               "cpython_static_setup.local")
TOOL_ROLES = frozenset({"cc", "cxx", "cc1", "cc1plus", "collect2", "as", "ld", "ar", "ranlib",
                        "make", "sh", "host_python"})
WORK = Path("/work")
RECEIPTS = WORK / "receipts"
SOURCE_ROOT = WORK / "inputs/sources"
CORE_ROOT = WORK / "inputs/core-source"
# Source DATA may contain ordinary spaces/tilde (for example CPython icons and
# libffi's lt~obsolete.m4). Never shell-expand or rename them. This syntax is
# confined to the four fixed source trees; their pinned inventories authorize
# membership. Core/control/command path syntax remains unchanged.
SOURCE_DATA_PREFIXES = tuple(str(SOURCE_ROOT / name) + "/" for name in
                             ("cpython", "libffi", "openssl", "zlib"))
FIXED_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/work/home", "TMPDIR": "/work/tmp",
    "LC_ALL": "C.UTF-8", "TZ": "UTC", "CONFIG_SITE": "/dev/null", "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONSTRICTEXTENSIONBUILD": "1", "PYTHON_COLORS": "0",
    "CFLAGS": "-O2 -g0 -march=x86-64 -mtune=generic"}
MAX_JSON = 32 * 1024 * 1024
MAX_FILE = 1024 * 1024 * 1024
MAX_INPUT_FILES = 150000
MAX_INPUT_BYTES = 16 * 1024 * 1024 * 1024


class InputError(ValueError):
    """A bounded publisher error; not native cleanup or qualification."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise InputError(message)


def keys(value: object, expected: set[str]) -> dict:
    need(type(value) is dict and set(value) == expected, "Unexpected or missing record fields")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii") + b"\n"


def sha(value: object) -> str:
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "Missing SHA256")
    return value


def absolute(value: object) -> Path:
    need(type(value) is str and (re.fullmatch(r"/[A-Za-z0-9_./+@=,-]+", value) is not None
         or (value.startswith(SOURCE_DATA_PREFIXES)
             and re.fullmatch(r"/[A-Za-z0-9_./+@=,~ -]+", value) is not None)),
         "Explicit bounded absolute publisher path required")
    p = Path(value)
    need(len(value) <= 4096 and str(p) == value and ".." not in p.parts, "Noncanonical publisher path")
    return p


def _state(s: os.stat_result) -> tuple[int, ...]:
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def ordinary_directory(path: Path) -> None:
    if path != Path("/"):
        absolute(str(path))
    for ancestor in reversed((path, *path.parents)):
        need(stat.S_ISDIR(ancestor.lstat().st_mode), "Ordinary publisher path ancestors required")


def read_file(path: Path, limit: int = MAX_FILE, *, single_link: bool = False) -> bytes:
    ordinary_directory(path.parent)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and (not single_link or before.st_nlink == 1),
         "Expected an ordinary input file")
    need(0 <= before.st_size <= limit, "Input file bound exceeded")
    with path.open("rb") as stream:
        need(_state(os.fstat(stream.fileno())) == _state(before), "Input changed before read")
        raw = stream.read(before.st_size + 1)
        need(_state(os.fstat(stream.fileno())) == _state(before), "Input changed during read")
    need(len(raw) == before.st_size and _state(path.lstat()) == _state(before), "Input changed after read")
    return raw


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in items:
        need(name not in result, "Duplicate JSON field")
        result[name] = value
    return result


def decode(raw: bytes, *, canonical_required: bool = True) -> object:
    need(len(raw) <= MAX_JSON, "JSON bound exceeded")
    def nonfinite(_value: str) -> None:
        raise InputError("Nonfinite JSON")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=nonfinite)
        need(not canonical_required or canonical(value) == raw, "Expected canonical JSON with terminal LF")
    except (UnicodeError, ValueError, RecursionError, TypeError):
        raise InputError("Invalid or noncanonical publisher JSON") from None
    return value


def file_shape(item: object, *, extra: set[str] = frozenset()) -> dict:
    item = keys(item, {"path", "size", "sha256"} | set(extra))
    absolute(item["path"])
    need(type(item["size"]) is int and 0 <= item["size"] <= MAX_FILE, "Invalid input size")
    sha(item["sha256"])
    return item


def verify_file(item: dict, *, limit: int = MAX_FILE) -> bytes:
    raw = read_file(absolute(item["path"]), limit)
    need(len(raw) == item["size"] and digest(raw) == item["sha256"], "Input hash or size differs")
    return raw


def inventory_file(item: dict, *, package_ids: set[str] | None = None) -> dict[str, dict]:
    value = keys(decode(verify_file(file_shape(item), limit=MAX_JSON)), {"schemaVersion", "files"})
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and type(value["files"]) is list
         and 0 < len(value["files"]) <= MAX_INPUT_FILES, "Invalid input inventory")
    result = {}
    total = 0
    for entry in value["files"]:
        file_shape(entry, extra={"package"} if package_ids is not None else set())
        if package_ids is not None:
            need(entry["package"] in package_ids, "Unknown sysroot package origin")
        need(entry["path"] not in result, "Duplicate inventory path")
        total += entry["size"]
        need(total <= MAX_INPUT_BYTES, "Input inventory byte bound exceeded")
        result[entry["path"]] = entry
    need(list(result) == sorted(result), "Unsorted input inventory")
    return result


def ordinary_tree(root: Path) -> dict[str, Path]:
    ordinary_directory(root)
    result = {}
    pending = [root]
    count = 0
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            absolute(str(path))
            count += 1
            need(count <= MAX_INPUT_FILES, "Input tree bound exceeded")
            st = path.lstat()
            if stat.S_ISDIR(st.st_mode):
                pending.append(path)
            else:
                need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "Source links/special files refused")
                result[str(path)] = path
    return result


def _https(value: object) -> None:
    need(type(value) is str and value.startswith("https://") and len(value) <= 2048
         and not any(ord(c) < 33 or ord(c) == 127 for c in value), "HTTPS acquisition URL required")


def validate_shape(lock: object) -> dict:
    lock = keys(lock, {"schemaVersion", "state", "target", "builder", "packages", "tools", "sources",
                       "recipeFiles", "coreSourceFiles", "environment", "configuration"})
    need(type(lock["schemaVersion"]) is int and lock["schemaVersion"] == 1
         and lock["state"] == "sealed", "Input lock is UNSEALED")
    need(canonical(lock["target"]) == canonical(TARGET), "Unsupported source-build target")
    env = keys(lock["environment"], set(FIXED_ENV) | {"SOURCE_DATE_EPOCH"})
    need(all(env[k] == v for k, v in FIXED_ENV.items()), "Build environment differs from fixed recipe")
    need(type(env["SOURCE_DATE_EPOCH"]) is str and re.fullmatch(r"[0-9]{1,12}", env["SOURCE_DATE_EPOCH"])
         is not None, "SOURCE_DATE_EPOCH must be selected and sealed")
    conf = keys(lock["configuration"], {"profile", "cpythonCommit", "staticModules", "disabledModules",
        "pythonConfigure", "zlibConfigure", "libffiConfigure", "makePhases", "coreProfile"})
    expected = {"profile": PROFILE, "cpythonCommit": CPYTHON_COMMIT,
        "staticModules": list(STATIC_MODULES), "disabledModules": list(DISABLED_MODULES),
        "pythonConfigure": list(PYTHON_CONFIGURE), "zlibConfigure": list(ZLIB_CONFIGURE),
        "libffiConfigure": list(FFI_CONFIGURE), "makePhases": list(PHASES)}
    need(all(conf[k] == v for k, v in expected.items()), "Configuration differs from reviewed profile")
    need(file_shape(conf["coreProfile"])["sha256"] == CORE_PROFILE_SHA256, "Unreviewed core source profile")
    sources = lock["sources"]
    need(type(sources) is list and len(sources) == 3, "Exactly three source archives required")
    seen = set()
    for entry in sources:
        keys(entry, {"id", "version", "archive", "root", "inventory", "patches"})
        name = entry["id"]
        need(name in SOURCE_PINS and name not in seen, "Unknown or duplicate source")
        seen.add(name)
        version, size, hashed, url = SOURCE_PINS[name]
        acquisition = keys(entry["archive"], {"url", "file", "receipt"})
        record = file_shape(acquisition["file"])
        file_shape(acquisition["receipt"])
        need((entry["version"], record["size"], record["sha256"], acquisition["url"]) ==
             (version, size, hashed, url), "Source archive pin differs")
        need(entry["root"] == str(SOURCE_ROOT / name) and entry["patches"] == [], "Unreviewed source root/patch")
        file_shape(entry["inventory"])
    need([s["id"] for s in sources] == sorted(seen), "Unsorted source inventory")
    return lock


def load_lock(path: Path, expected_sha256: str, *, verify_inputs: bool = True) -> dict:
    """Integrity is not signature verification or authorization to run a build."""
    sha(expected_sha256)
    raw = read_file(absolute(str(path)), MAX_JSON, single_link=True)
    need(digest(raw) == expected_sha256, "Input-lock digest differs from admitted command")
    lock = validate_shape(decode(raw))
    builder = keys(lock["builder"], {"image", "sysroot", "snapshot", "preparationRecipe"})
    image = keys(builder["image"], {"reference", "manifest", "blobs"})
    need(type(image["reference"]) is str and re.fullmatch(
        r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", image["reference"]) is not None, "Mutable builder image refused")
    need(file_shape(image["manifest"])["sha256"] == image["reference"].rsplit(":", 1)[1], "Image digest mismatch")
    need(type(image["blobs"]) is list and 0 < len(image["blobs"]) <= 512, "Retained builder blobs required")
    snapshot = keys(builder["snapshot"], {"id", "url", "metadata", "keyFingerprints", "trustReceipt"})
    _https(snapshot["url"])
    need(type(snapshot["id"]) is str and 0 < len(snapshot["id"]) <= 128, "Fixed repository snapshot required")
    need(type(snapshot["keyFingerprints"]) is list and snapshot["keyFingerprints"] and
         all(type(x) is str and re.fullmatch(r"[0-9A-F]{40,64}", x) for x in snapshot["keyFingerprints"]),
         "Reviewed archive-key identities required")
    need(type(snapshot["metadata"]) is list and 0 < len(snapshot["metadata"]) <= 512,
         "Signed repository metadata required")
    artifacts = [image["manifest"], *image["blobs"], *snapshot["metadata"], snapshot["trustReceipt"],
                 builder["preparationRecipe"], lock["configuration"]["coreProfile"]]
    need(type(lock["packages"]) is list and 0 < len(lock["packages"]) <= 4096, "Exact package closure required")
    package_ids = set()
    for package in lock["packages"]:
        keys(package, {"id", "name", "version", "architecture", "binary", "source"})
        need(all(type(package[k]) is str and 0 < len(package[k]) <= 256 for k in
                 ("id", "name", "version", "architecture")), "Invalid package identity")
        need(package["architecture"] in {"amd64", "all"}, "Unexpected package architecture")
        need(package["id"] not in package_ids, "Duplicate package origin")
        package_ids.add(package["id"])
        source = keys(package["source"], {"name", "version", "artifacts"})
        need(type(source["name"]) is str and source["name"] and type(source["version"]) is str
             and source["version"] and type(source["artifacts"]) is list and source["artifacts"],
             "Exact source package closure required")
        for item in [package["binary"], *source["artifacts"]]:
            keys(item, {"url", "file"})
            _https(item["url"])
            artifacts.append(item["file"])
    need([p["id"] for p in lock["packages"]] == sorted(package_ids), "Unsorted package inventory")
    sysroot = keys(builder["sysroot"], {"inventory", "aliases"})
    origins = inventory_file(sysroot["inventory"], package_ids=package_ids)
    need(type(sysroot["aliases"]) is list and len(sysroot["aliases"]) <= MAX_INPUT_FILES,
         "Exact sysroot aliases required")
    alias_paths = set()
    for alias in sysroot["aliases"]:
        keys(alias, {"path", "target"})
        alias_path = absolute(alias["path"])
        need(type(alias["target"]) is str and 0 < len(alias["target"]) <= 4096
             and re.fullmatch(r"[A-Za-z0-9_./+@=,-]+", alias["target"]) is not None, "Invalid sysroot alias")
        need(alias["path"] not in alias_paths and alias["path"] not in origins, "Duplicate sysroot alias")
        alias_paths.add(alias["path"])
        if verify_inputs:
            need(stat.S_ISLNK(alias_path.lstat().st_mode) and os.readlink(alias_path) == alias["target"],
                 "Sysroot alias changed")
    need([a["path"] for a in sysroot["aliases"]] == sorted(alias_paths), "Unsorted sysroot aliases")
    tools = {}
    need(type(lock["tools"]) is list, "Tool inventory required")
    for tool in lock["tools"]:
        keys(tool, {"role", "file", "package"})
        role = tool["role"]
        need(role in TOOL_ROLES and role not in tools and tool["package"] in package_ids, "Unknown tool origin")
        record = file_shape(tool["file"])
        origin = origins.get(record["path"])
        need(origin is not None and origin == {**record, "package": tool["package"]}, "Tool not bound to sysroot package")
        tools[role] = record["path"]
    need(set(tools) == TOOL_ROLES, "Incomplete toolchain/host Python input roster")
    need(list(tools) == sorted(tools), "Unsorted tool role inventory")
    recipe = {str(Path(__file__).resolve().parent / name) for name in BUILD_FILES}
    need(type(lock["recipeFiles"]) is list and {file_shape(f)["path"] for f in lock["recipeFiles"]} == recipe
         and len(lock["recipeFiles"]) == len(recipe), "Recipe source roster differs")
    need([f["path"] for f in lock["recipeFiles"]] == sorted(recipe), "Unsorted recipe source inventory")
    artifacts.extend(lock["recipeFiles"])
    for source in lock["sources"]:
        artifacts.extend([source["archive"]["file"], source["archive"]["receipt"], source["inventory"]])
        if verify_inputs:
            inventory = inventory_file(source["inventory"])
            need(set(ordinary_tree(absolute(source["root"]))) == set(inventory), "Extracted source roster differs")
            for entry in inventory.values():
                verify_file(entry)
    profile = decode(verify_file(lock["configuration"]["coreProfile"]), canonical_required=False)
    need(type(profile) is dict and type(profile.get("wholeCorePayloadFiles")) is list, "Core profile missing")
    expected_core = {e["path"]: e for e in profile["wholeCorePayloadFiles"]}
    expected_core.update({e["path"]: e for e in profile["selectedScopeAndHandoffFiles"] if e["path"] in
                         {"desktop/engine_bootstrap.py", "desktop/config_edit_bootstrap.py", "desktop/tools/prepare_runtime.py"}})
    core = lock["coreSourceFiles"]
    need(type(core) is list and len(core) == len(expected_core), "Complete core/preparer roster required")
    core_paths = set()
    for entry in core:
        file_shape(entry)
        relative = str(absolute(entry["path"]).relative_to(CORE_ROOT))
        need(relative in expected_core and relative not in core_paths, "Unexpected core source")
        core_paths.add(relative)
        expected = expected_core[relative]
        need((entry["size"], entry["sha256"]) == (expected["size"], expected["sha256"]), "Core source drift")
    need([f["path"] for f in core] == sorted(f["path"] for f in core), "Unsorted core source inventory")
    for record in [*artifacts, *origins.values(), *core]:
        file_shape(record, extra={"package"} if "package" in record else set())
    if verify_inputs:
        for record in [*artifacts, *origins.values(), *core]:
            verify_file(record)
        actual_core = ordinary_tree(CORE_ROOT / "src/mobile_release")
        need(set(actual_core) == {str(CORE_ROOT / e) for e in expected_core if e.startswith("src/mobile_release/")},
             "Uninventoried core source")
    need(os.path.realpath(sys.executable) == tools["host_python"], "Wrong publisher host interpreter")
    # Derived views are not part of the canonical sealed input document.
    return {**lock, "_tools": tools, "_origins": origins, "_digest": expected_sha256}


def write_new(path: Path, data: bytes, mode: int = 0o600) -> dict:
    ordinary_directory(path.parent)
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), mode)
        need(stream.write(data) == len(data), "Short publisher write")
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "size": len(data), "sha256": digest(data)}


def materialize(lock_path: Path, expected: str) -> None:
    lock = load_lock(lock_path, expected)
    # The admitted command starts with env -i plus the lock's exact environment.
    # Refuse rather than silently retain credentials, Python hooks or compiler overrides.
    need(set(os.environ) <= set(lock["environment"]) | {"PWD", "SHLVL", "_"},
         "Inherited environment is not the admitted clean environment")
    need(all(os.environ.get(k) == v for k, v in lock["environment"].items()),
         "Entry environment differs from the sealed environment")
    ordinary_directory(WORK)
    need(stat.S_IMODE(WORK.lstat().st_mode) == 0o700, "Private /work mode must be 0700")
    fresh = [WORK / p for p in ("build", "deps", "stage", "receipts", "capture", "home", "tmp", "build-env.sh")]
    need(all(not p.exists() and not p.is_symlink() for p in fresh), "Fresh workspace required; no reuse/cleanup")
    for path in fresh[:-1]:
        path.mkdir(mode=0o700)
    for name in ("cpython", "libffi", "zlib"):
        (WORK / "build" / name).mkdir(mode=0o700)
    # zlib's ordinary in-source configure, using fresh exact copies, not changes to admitted source.
    source = SOURCE_ROOT / "zlib"
    source_record = next(e for e in lock["sources"] if e["id"] == "zlib")
    source_inventory = inventory_file(source_record["inventory"])
    copies = []
    for path in ordinary_tree(source).values():
        destination = WORK / "build/zlib" / path.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        raw = verify_file(source_inventory[str(path)])
        record = write_new(destination, raw, stat.S_IMODE(path.stat().st_mode) & 0o777)
        copies.append({"source": str(path), "destination": record})
    write_new(RECEIPTS / "source-copies.json", canonical(copies))
    setup = Path(__file__).parent / "cpython_static_setup.local"
    modules = WORK / "build/cpython/Modules"
    modules.mkdir(mode=0o700)
    write_new(modules / "Setup.local", read_file(setup), 0o644)
    tools = lock["_tools"]
    recorder = Path(__file__).parent / "cpython_static_link.py"
    wrapper = ("#!" + tools["sh"] + "\nexec " + shlex.quote(tools["host_python"]) +
               " -I -S -B " + shlex.quote(str(recorder)) + ' "$@"\n').encode("ascii")
    for name in ("ld", "ld.bfd"):
        write_new(WORK / "capture" / name, wrapper, 0o755)
    env = dict(lock["environment"])
    env.update({"MRK_LOCK": str(lock_path), "MRK_LOCK_SHA256": expected,
        "MRK_TOOLS": str(Path(__file__).parent), "CONFIG_SHELL": tools["sh"],
        "CC": tools["cc"] + " -B/work/capture/ -fuse-ld=bfd",
        "CXX": tools["cxx"] + " -B/work/capture/ -fuse-ld=bfd",
        "AR": tools["ar"], "RANLIB": tools["ranlib"], "LD": "/work/capture/ld.bfd",
        "MAKE": tools["make"], "HOST_PYTHON": tools["host_python"]})
    write_new(WORK / "build-env.sh", "".join("export " + k + "=" + shlex.quote(v) + "\n"
                                             for k, v in sorted(env.items())).encode("ascii"))


def _configuration_names(config: bytes, makefile: bytes, modules: tuple[str, ...],
                         disabled: tuple[str, ...]) -> list[str]:
    """Audit generated configuration as data, not a runtime builtin observation."""
    table = re.search(rb"struct _inittab _PyImport_Inittab\[\] = \{(.*?)\n\};", config, re.S)
    need(table is not None, "Generated builtin table missing")
    body = re.sub(rb"/\*.*?\*/", b"", table[1], flags=re.S)
    row = rb'\{\s*"([A-Za-z0-9_]+)"\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\},'
    names = [value.decode("ascii") for value in re.findall(row, body)]
    rest = re.sub(row, b"", body).strip()
    need(re.fullmatch(rb"\{\s*0\s*,\s*0\s*\}", rest) is not None,
         "Unsupported generated builtin table syntax")
    expected = set(BOOTSTRAP_MODULES + INTRINSIC_MODULES + modules)
    need(len(names) == len(expected) and set(names) == expected, "Generated builtin-name roster differs")
    for key, wanted in ((b"MODBUILT_NAMES", set(BOOTSTRAP_MODULES + modules)),
                        (b"MODSHARED_NAMES", set()), (b"MODDISABLED_NAMES", set(disabled))):
        values = re.findall(rb"^" + key + rb"[ \t]*=[ \t]*(.*)$", makefile, re.M)
        need(len(values) == 1, "Generated module Makefile assignment missing or repeated")
        words = values[0].decode("ascii").split()
        need(len(words) == len(wanted) and set(words) == wanted, "Generated Makefile module roster differs")
    return sorted(names)


def configuration_names(config: bytes, makefile: bytes) -> list[str]:
    return _configuration_names(config, makefile, STATIC_MODULES, DISABLED_MODULES)


def phase_record(lock_path: Path, expected: str, name: str, status: int) -> None:
    lock = load_lock(lock_path, expected, verify_inputs=False)
    need(name in PHASES and type(status) is int and 0 <= status <= 255, "Unexpected recipe phase/status")
    log = read_file(RECEIPTS / (name + ".log"), 256 * 1024 * 1024)
    ignored = (b"(ignored)" in log or b"*** Error compiling" in log or b"Can't list " in log)
    children = list(RECEIPTS.iterdir())
    failed_capture = any(path.name == "CAPTURE-FAILED.json" for path in children)
    incomplete = []
    for path in children:
        if re.fullmatch(r"link-[0-9]{6}", path.name):
            try:
                receipt = decode(read_file(path / "receipt.json", 16 * 1024 * 1024))
                need(type(receipt) is dict and receipt.get("inputLockSha256") == expected
                     and receipt.get("linkId") == path.name and receipt.get("kind") in {"query", "linked", "link-failed"},
                     "Original link capture incomplete")
            except (OSError, ValueError, TypeError, RecursionError):
                incomplete.append(path.name)
    failed_capture = failed_capture or bool(incomplete)
    write_new(RECEIPTS / (name + ".json"), canonical({"schemaVersion": 1, "inputLockSha256": expected,
        "phase": name, "originalExitCode": status, "logSha256": digest(log),
        "ignoredInstallError": ignored, "captureFailure": failed_capture, "incompleteLinkCaptures": sorted(incomplete)}))
    need(status == 0 and not ignored and not failed_capture, "Original phase or evidence failed; retain workspace")
    if name in {"python-configure", "python-build", "python-install"}:
        captured = {}
        for relative in ("Modules/config.c", "Makefile", "pyconfig.h", "Modules/Setup.local",
                         "Modules/Setup.bootstrap", "Modules/Setup.stdlib"):
            raw = read_file(WORK / "build/cpython" / relative, MAX_JSON)
            captured[relative] = raw
            write_new(RECEIPTS / (name + "-" + relative.replace("/", "-")), raw)
        names = configuration_names(captured["Modules/config.c"], captured["Makefile"])
        need(captured["Modules/Setup.local"] == read_file(Path(__file__).with_name("cpython_static_setup.local")),
             "Configured Setup.local changed")
        write_new(RECEIPTS / (name + "-configuration.json"), canonical({"schemaVersion": 1,
            "inputLockSha256": expected, "builtinNamesFromGeneratedSource": names,
            "notARuntimeBuiltinObservation": True,
            "files": [{"path": p, "size": len(b), "sha256": digest(b)} for p, b in sorted(captured.items())]}))


# Conventional source origin. None of these selectors inherit legacy/H approval.
SOURCE_PROFILE = "cpython-3.14.7-linux-x86_64-source-v1"
SOURCE_LOCK_SCHEMA = "mrk-cpython-source-lock-1"
SOURCE_PHASE_SCHEMA = "mrk-cpython-source-phase-1"
SOURCE_OUTPUT_SCHEMA = "mrk-cpython-source-output-1"
SOURCE_COMPONENTS_SCHEMA = "mrk-cpython-source-components-1"
SOURCE_EXECUTION_REVIEW_PATH = Path("/work/inputs/source-execution-review.json")
SOURCE_ARCHIVES = {**SOURCE_PINS, "openssl": ("3.5.8", 53213818,
    "a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2",
    "https://www.openssl.org/source/openssl-3.5.8.tar.gz")}
SOURCE_STATIC_MODULES = tuple(sorted((*STATIC_MODULES, "_socket", "_ssl", "pyexpat", "resource")))
SOURCE_DISABLED_MODULES = tuple(n for n in DISABLED_MODULES if n not in {"_socket", "_ssl", "pyexpat", "resource"})
SOURCE_PYTHON_CONFIGURE = (*PYTHON_CONFIGURE, "--with-openssl=/work/deps", "--with-openssl-rpath=no",
                          "--with-ssl-default-suites=python", "--without-system-expat")
SOURCE_OPENSSL_CONFIGURE = ("linux-x86_64", "shared", "no-module", "no-dso", "no-engine",
    "no-autoload-config", "no-legacy", "no-tests", "--prefix=/work/deps", "--libdir=lib",
    "--openssldir=/nonexistent/mobile-release-kit/openssl")
SOURCE_PHASES = (*PHASES[:6], "openssl-configure", "openssl-build", "openssl-install", "openssl-layout",
                 "python-configure", "builtin-archives", "python-build", "python-project")
SOURCE_BUILD_FILES = ("cpython_source_recipe.py", "cpython_source_setup.local", "cpython_static_inputs.py",
    "cpython_static_builder_data.py", "prepare_cpython_static_payload.py", "prepare_cpython_source_payload.py")
SOURCE_CORE_HANDOFFS = frozenset({"desktop/engine_bootstrap.py", "desktop/config_edit_bootstrap.py",
    "desktop/github_connection_bootstrap.py", "desktop/environment_bootstrap.py",
    "desktop/offline_preflight_bootstrap.py", "desktop/android_build_bootstrap.py",
    "desktop/tools/prepare_runtime.py", "desktop/github-ca.pem"})
SOURCE_CA = (240216, "9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f")
SOURCE_TOOLS = {
    "cc": "/usr/bin/x86_64-linux-gnu-gcc-13", "cxx": "/usr/bin/x86_64-linux-gnu-g++-13",
    "ar": "/usr/bin/x86_64-linux-gnu-ar", "ranlib": "/usr/bin/x86_64-linux-gnu-ranlib",
    "ld": "/usr/bin/x86_64-linux-gnu-ld.bfd", "make": "/usr/bin/make",
    "sh": "/usr/bin/dash", "perl": "/usr/bin/perl", "host_python": "/usr/bin/python3.12"}
SOURCE_ENV = {**FIXED_ENV, "SOURCE_DATE_EPOCH": "1785925789", "CONFIG_SHELL": SOURCE_TOOLS["sh"],
    "CC": SOURCE_TOOLS["cc"], "CXX": SOURCE_TOOLS["cxx"], "AR": SOURCE_TOOLS["ar"],
    "RANLIB": SOURCE_TOOLS["ranlib"], "LD": SOURCE_TOOLS["ld"], "MAKE": SOURCE_TOOLS["make"],
    "PERL": SOURCE_TOOLS["perl"]}
SOURCE_PYTHON_ENV = {**SOURCE_ENV, "CPPFLAGS": "-I/work/deps/include", "LDFLAGS": "-L/work/deps/lib",
    "ZLIB_CFLAGS": "-I/work/deps/include", "ZLIB_LIBS": "/work/deps/lib/libz.a",
    "LIBFFI_CFLAGS": "-I/work/deps/include", "LIBFFI_LIBS": "/work/deps/lib/libffi.a"}
# Pinned configure appends these supplied precious variables in this order,
# before its later library probing. In particular LIBFFI_LIBS has no -ldl yet.
SOURCE_PYTHON_PRECIOUS = ("CC", "CFLAGS", "LDFLAGS", "CPPFLAGS", "LIBFFI_CFLAGS", "LIBFFI_LIBS",
                         "ZLIB_CFLAGS", "ZLIB_LIBS")
SOURCE_OPENSSL_LDFLAGS = "LDFLAGS=-Wl,--enable-new-dtags,-z,origin,-rpath,'$$ORIGIN'"
SOURCE_PYTHON_LDFLAGS = "LDFLAGS=-Wl,--enable-new-dtags,-z,origin,-rpath,'$$ORIGIN/../lib'"
SOURCE_PYTHON_MAKE = (SOURCE_PYTHON_LDFLAGS, "PYTHON_FOR_BUILD=./$(BUILDPYTHON) -E -B",
                      "PYTHON_FOR_FREEZE=./_bootstrap_python -B")
SOURCE_ARCHIVE_TARGETS = tuple("Modules/_hacl/" + n for n in (
    "libHacl_Hash_MD5.a", "libHacl_Hash_SHA1.a", "libHacl_Hash_SHA2.a", "libHacl_Hash_SHA3.a",
    "libHacl_Hash_BLAKE2.a", "libHacl_HMAC.a")) + ("Modules/expat/libexpat.a",)
SOURCE_LIBRARIES = ("libcrypto.so.3", "libssl.so.3")
SOURCE_OPENSSL_LAYOUT_DATA = "openssl-layout-data.json"
SOURCE_LAYOUT_ROOTS = ("/work/build/cpython/lib", "/work/build/lib", "/work/stage/python/lib")
SOURCE_GENERATED_NAMES = ("_sysconfigdata__linux_x86_64-linux-gnu.py",
    "_sysconfig_vars__linux_x86_64-linux-gnu.json", "build-details.json")
SOURCE_CONFIG_FILES = ("Makefile", "pyconfig.h", "Modules/config.c", "Modules/Setup.local",
                       "Modules/Setup.bootstrap", "Modules/Setup.stdlib", "config.log")
SOURCE_OPENSSL_FILES = ("Makefile", "configdata.pm", "include/openssl/configuration.h", "include/openssl/opensslv.h")


def _source_admission():
    # A is a constants-only external trust root, not a self-hashed input in L.
    # Final command admission must hash-pin A and all helpers BEFORE any import.
    spec = importlib.util.spec_from_file_location("_mrk_cpython_source_admission",
                                                Path(__file__).with_name("cpython_source_admission.py"))
    admission = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(admission)
    return admission


def require_source_build():
    # First public build operation: no caller path, import of the core, or mkdir before this.
    admission = _source_admission()
    pins = (admission.APPROVED_SOURCE_LOCK_SHA256, admission.APPROVED_SOURCE_EXECUTION_REVIEW_SHA256,
            admission.APPROVED_SOURCE_CORE_INPUTS_SHA256)
    need(all(x is not None for x in pins), "Conventional source build closed: input/core/execution reviews missing")
    for value in pins:
        sha(value)
    return admission


def source_read(path: Path, limit: int = MAX_FILE) -> bytes:
    """Bounded ordinary/no-follow single-link DATA; close failure is a failure."""
    ordinary_directory(path.parent)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "Conventional source input is not bounded ordinary DATA")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(_state(os.fstat(descriptor)) == _state(before), "Source input changed before open")
        blocks, total = [], 0
        while True:
            block = os.read(descriptor, min(1 << 20, before.st_size - total + 1))
            if not block:
                break
            total += len(block)
            need(total <= before.st_size, "Source input grew during read")
            blocks.append(block)
        need(total == before.st_size and _state(os.fstat(descriptor)) == _state(before)
             and _state(path.lstat()) == _state(before), "Source input changed during read")
    finally:
        os.close(descriptor)
    return b"".join(blocks)


def source_bound(record: dict, limit: int = MAX_FILE) -> bytes:
    file_shape(record)
    raw = source_read(absolute(record["path"]), limit)
    need((len(raw), digest(raw)) == (record["size"], record["sha256"]), "Source input hash/size differs")
    return raw


def source_write(path: Path, raw: bytes, mode: int = 0o600) -> dict:
    ordinary_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(descriptor, mode)
        need(os.write(descriptor, raw) == len(raw), "Short conventional source output write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    need(source_read(path, len(raw)) == raw and stat.S_IMODE(path.lstat().st_mode) == mode,
         "Conventional source write/readback differs")
    return {"path": str(path), "size": len(raw), "sha256": digest(raw)}


def source_configuration() -> dict:
    return {"pythonConfigure": list(SOURCE_PYTHON_CONFIGURE), "zlibConfigure": list(ZLIB_CONFIGURE),
        "libffiConfigure": list(FFI_CONFIGURE), "opensslConfigure": list(SOURCE_OPENSSL_CONFIGURE),
        "staticModules": list(SOURCE_STATIC_MODULES), "disabledModules": list(SOURCE_DISABLED_MODULES),
        "phases": list(SOURCE_PHASES), "cpythonCommit": CPYTHON_COMMIT, "bundledExpatVersion": "2.8.2",
        "pythonMakeAssignments": list(SOURCE_PYTHON_MAKE), "opensslMakeAssignment": SOURCE_OPENSSL_LDFLAGS}


def source_lock_shape(value: object) -> dict:
    value = keys(value, {"schema", "profile", "state", "target", "rootfs", "hostInputs",
                         "sources", "coreSourceFiles", "recipeFiles", "environment", "configuration"})
    need(value["schema"] == SOURCE_LOCK_SCHEMA and value["profile"] == SOURCE_PROFILE
         and value["state"] == "sealed-inputs-only" and canonical(value["target"]) == canonical(TARGET),
         "Different conventional source lock")
    need(value["environment"] == SOURCE_ENV and value["configuration"] == source_configuration(),
         "Different conventional recipe configuration")
    for field in ("rootfs", "hostInputs"):
        file_shape(value[field])
    need(type(value["sources"]) is list and [s["id"] for s in value["sources"]] == sorted(SOURCE_ARCHIVES),
         "Exactly four pinned source archives required")
    for source in value["sources"]:
        keys(source, {"id", "version", "archive", "url", "root", "inventory", "patches"})
        pin = SOURCE_ARCHIVES[source["id"]]
        file_shape(source["archive"])
        file_shape(source["inventory"])
        need((source["version"], source["archive"]["size"], source["archive"]["sha256"], source["url"]) == pin
             and source["patches"] == [] and source["root"] == str(SOURCE_ROOT / source["id"]),
             "Unreviewed source bytes, root or patches")
    core = value["coreSourceFiles"]
    need(type(core) is list and 8 < len(core) <= 2048, "Whole core plus eight fixed handoff inputs required")
    names = []
    for record in core:
        file_shape(record)
        name = absolute(record["path"]).relative_to(CORE_ROOT).as_posix()
        need(name in SOURCE_CORE_HANDOFFS or name.startswith("src/mobile_release/"), "Foreign core input")
        names.append(name)
        if name == "desktop/github-ca.pem":
            need((record["size"], record["sha256"]) == SOURCE_CA, "Different public CA")
    need(names == sorted(set(names)) and SOURCE_CORE_HANDOFFS <= set(names), "Core/handoff roster incomplete")
    recipe = value["recipeFiles"]
    need(type(recipe) is list and len(recipe) == len(SOURCE_BUILD_FILES), "Recipe file roster differs")
    for record in recipe:
        file_shape(record)
    expected = sorted(str(Path(__file__).parent / name) for name in SOURCE_BUILD_FILES)
    need([record["path"] for record in recipe] == expected, "Foreign or incomplete recipe source")
    return value


def source_inventory(source: dict) -> dict[str, dict]:
    document = keys(decode(source_bound(source["inventory"], MAX_JSON)), {"files"})
    need(type(document["files"]) is list and 0 < len(document["files"]) <= MAX_INPUT_FILES,
         "Bounded archive-derived source inventory required")
    records, total = {}, 0
    for row in document["files"]:
        file_shape(row, extra={"mode"})
        path = absolute(row["path"])
        need(path.is_relative_to(absolute(source["root"])) and row["mode"] in {0o644, 0o755}
             and path.name not in {".git", "INCOMPLETE"} and row["path"] not in records,
             "Different extracted source member")
        records[row["path"]] = row
        total += row["size"]
    need(list(records) == sorted(records) and total <= MAX_INPUT_BYTES, "Source inventory ordering/bound")
    return records


def source_execution_review(raw: bytes, expected_sha256: str) -> dict:
    """Fixed-path prerequisite E identity, not final-command authorization."""
    need(digest(raw) == sha(expected_sha256) and type(decode(raw)) is dict,
         "Source execution-envelope review binding differs")
    return {"path": str(SOURCE_EXECUTION_REVIEW_PATH), "size": len(raw), "sha256": digest(raw)}


def load_source_lock(path: Path) -> dict:
    admission = require_source_build()
    raw = source_read(absolute(str(path)), MAX_JSON)
    need(digest(raw) == admission.APPROVED_SOURCE_LOCK_SHA256, "Source lock is not the independently admitted lock")
    lock = source_lock_shape(decode(raw))
    need(digest(canonical(lock["coreSourceFiles"])) == admission.APPROVED_SOURCE_CORE_INPUTS_SHA256,
         "Source core review binding differs")
    review = source_execution_review(source_read(SOURCE_EXECUTION_REVIEW_PATH, MAX_JSON),
                                     admission.APPROVED_SOURCE_EXECUTION_REVIEW_SHA256)
    # Root report is input correspondence, not transferable native authority.
    root = decode(source_bound(lock["rootfs"], MAX_JSON))
    need(type(root) is dict and root.get("schema") == "mrk-cpython-source-rootfs-1"
         and root.get("profile") == SOURCE_PROFILE and root.get("nativeQualification") == "not-established",
         "Different source root provenance")
    source_bound(lock["hostInputs"], MAX_JSON)
    for row in (*lock["recipeFiles"], *lock["coreSourceFiles"]):
        source_bound(row)
    actual = ordinary_tree(CORE_ROOT / "src/mobile_release")
    need(set(actual) == {r["path"] for r in lock["coreSourceFiles"] if r["path"].startswith(str(CORE_ROOT / "src/mobile_release") + "/")},
         "Current whole core is not the frozen N+8 input roster")
    for source in lock["sources"]:
        source_bound(source["archive"])
        inventory = source_inventory(source)
        need(set(ordinary_tree(absolute(source["root"]))) == set(inventory), "Extracted source roster differs")
        for row in inventory.values():
            source_bound({k: row[k] for k in ("path", "size", "sha256")})
            need(stat.S_IMODE(Path(row["path"]).lstat().st_mode) == row["mode"], "Source mode differs")
    need(os.path.realpath(sys.executable) == SOURCE_TOOLS["host_python"] and sys.flags.isolated == 1
         and sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1,
         "Use the qualified root's original host Python with -I -S -B")
    return {**lock, "_digest": digest(raw), "_executionReview": review}


def source_workspace(lock: dict) -> None:
    need(dict(os.environ) == SOURCE_ENV, "Entry requires the literal empty-origin source environment")
    ordinary_directory(WORK)
    need(stat.S_IMODE(WORK.lstat().st_mode) == 0o700, "Source /work must be private")
    for name in ("build", "deps", "stage", "receipts", "home", "tmp"):
        (WORK / name).mkdir(mode=0o700)  # No reuse/adoption/retry/cleanup.
    for name in SOURCE_ARCHIVES:
        (WORK / "build" / name).mkdir(mode=0o700)
    copies = []
    for source in lock["sources"]:
        if source["id"] not in {"zlib", "openssl"}:
            continue
        for row in source_inventory(source).values():
            path = Path(row["path"])
            destination = WORK / "build" / source["id"] / path.relative_to(source["root"])
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            record = {k: row[k] for k in ("path", "size", "sha256")}
            copies.append({"original": record, "copy": source_write(destination, source_bound(record), row["mode"])})
    modules = WORK / "build/cpython/Modules"
    modules.mkdir(mode=0o700)
    source_write(modules / "Setup.local", source_read(Path(__file__).with_name("cpython_source_setup.local")), 0o644)
    source_write(RECEIPTS / "source-copies.json", canonical(copies))


def source_configuration_names(config: bytes, makefile: bytes) -> list[str]:
    return _configuration_names(config, makefile, SOURCE_STATIC_MODULES, SOURCE_DISABLED_MODULES)


def _make_value(raw: bytes, name: str) -> str:
    values = re.findall(rb"^" + re.escape(name.encode("ascii")) + rb"[ \t]*=[ \t]*(.*)$", raw, re.M)
    need(len(values) == 1, "Material make assignment missing/repeated")
    return values[0].decode("ascii").strip()


def source_material_configuration(files: dict[str, bytes], setup: bytes, patchlevel: bytes) -> list[str]:
    """Material DATA predicates only; full files remain retained for review."""
    need(files["Modules/Setup.local"] == setup, "Source Setup.local differs")
    names = source_configuration_names(files["Modules/config.c"], files["Makefile"])
    header, make = files["pyconfig.h"], files["Makefile"]
    for name in ("WITH_PYMALLOC", "HAVE_FORK", "HAVE_POSIX_SPAWN", "HAVE_SYS_RESOURCE_H",
                 "HAVE_WAITPID", "HAVE_PIPE2", "HAVE_POLL", "HAVE_SOCKETPAIR"):
        need(re.findall(rb"^#define " + name.encode() + rb"[ \t]+(.*)$", header, re.M) == [b"1"],
             "Required ABI/POSIX configuration missing")
    for name in ("Py_GIL_DISABLED", "Py_DEBUG", "Py_TRACE_REFS", "WITH_MIMALLOC", "Py_ENABLE_SHARED"):
        need(re.search(rb"^#define " + name.encode() + rb"\b", header, re.M) is None,
             "Different GIL/allocator/shared/debug ABI")
    need(re.findall(rb'^#define PY_VERSION[ \t]+"([^"]+)"', patchlevel, re.M) == [b"3.14.7"],
         "Different CPython source version")
    expected = {"VERSION": "3.14", "MACHDEP": "linux", "MULTIARCH": "x86_64-linux-gnu",
        "HOST_GNU_TYPE": "x86_64-pc-linux-gnu", "ABIFLAGS": "", "PY_ENABLE_SHARED": "0",
        "CONFIGURE_CFLAGS": FIXED_ENV["CFLAGS"], "CC": SOURCE_TOOLS["cc"],
        "MODULE_ZLIB_LDFLAGS": "/work/deps/lib/libz.a", "MODULE__CTYPES_LDFLAGS": "/work/deps/lib/libffi.a -ldl",
        "MODULE_PYEXPAT_CFLAGS": "-I$(srcdir)/Modules/expat", "MODULE_PYEXPAT_LDFLAGS": "-lm $(LIBEXPAT_A)",
        "MODULE_PYEXPAT_DEPS": "$(LIBEXPAT_HEADERS) $(LIBEXPAT_A)", "LIBEXPAT_A": "Modules/expat/libexpat.a"}
    for name, wanted in expected.items():
        need(_make_value(make, name) == wanted, "Material Python make configuration differs")
    need(_make_value(make, "MODULE__SSL_CFLAGS").split() == ["-I/work/deps/include"]
         and _make_value(make, "MODULE__SSL_LDFLAGS").split() == ["-L/work/deps/lib", "-lssl", "-lcrypto"],
         "Unselected OpenSSL module headers/link flags")
    original_args = (*SOURCE_PYTHON_CONFIGURE,
                     *(name + "=" + SOURCE_PYTHON_ENV[name] for name in SOURCE_PYTHON_PRECIOUS))
    need(tuple(shlex.split(_make_value(make, "CONFIG_ARGS"))) == original_args,
         "Original Python configure arguments differ")
    for name in ("CONFIGURE_CFLAGS", "CONFIGURE_CFLAGS_NODIST", "CONFIGURE_LDFLAGS", "CONFIGURE_LDFLAGS_NODIST"):
        need(not any(flag in _make_value(make, name) for flag in ("-flto", "-fprofile", "-B/work/capture")),
             "Unselected optimized/instrumented compiler configuration")
    return names


def source_elf(raw: bytes, name: str) -> dict:
    """Finite ELF64 dynamic metadata read; never dlopen or a native query."""
    need(name in {"python", *SOURCE_LIBRARIES} and 64 <= len(raw) <= 64 << 20,
         "Different native output/byte bound")
    need(raw[:7] == b"\x7fELF\x02\x01\x01", "Expected little-endian ELF64")
    kind, machine = struct.unpack_from("<HH", raw, 16)
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    phsize, count = struct.unpack_from("<HH", raw, 54)
    need(kind in {2, 3} and machine == 62 and phsize == 56 and 0 < count <= 128
         and phoff + count * phsize <= len(raw), "ELF program table differs")
    loads, dynamic = [], []
    for index in range(count):
        tag, flags, offset, address, _, size, memsize, align = struct.unpack_from("<IIQQQQQQ", raw, phoff + index * phsize)
        need(offset + size <= len(raw), "ELF segment extent differs")
        if tag == 1:
            loads.append((address, size, offset))
        if tag == 2:
            dynamic.append((offset, size))
    need(len(dynamic) == 1 and dynamic[0][1] % 16 == 0 and dynamic[0][1] <= 64 << 10,
         "ELF dynamic table differs")
    tags, terminated = {}, False
    offset, size = dynamic[0]
    for index in range(offset, offset + size, 16):
        tag, value = struct.unpack_from("<qQ", raw, index)
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    need(terminated and len(tags.get(5, [])) == len(tags.get(10, [])) == 1
         and 15 not in tags and len(tags.get(29, [])) == 1, "ELF needs one RUNPATH and no RPATH")
    address, size = tags[5][0], tags[10][0]
    found = [offset + address - start for start, length, offset in loads if start <= address and address + size <= start + length]
    need(len(found) == 1 and size <= 1 << 20, "ELF string table differs")
    strings = raw[found[0]:found[0] + size]

    def string(index: int) -> str:
        need(index < len(strings), "ELF string index outside table")
        end = strings.find(b"\0", index)
        need(index < end <= index + 4096, "ELF string missing/oversized")
        return strings[index:end].decode("ascii")

    runpath = string(tags[29][0])
    needed = [string(index) for index in tags.get(1, [])]
    allowed = {"libc.so.6", "libm.so.6", "libgcc_s.so.1", "libdl.so.2", "libpthread.so.0"}
    required = {"libc.so.6"}
    if name == "python":
        required |= set(SOURCE_LIBRARIES)
        allowed |= set(SOURCE_LIBRARIES)
    elif name == "libssl.so.3":
        required.add("libcrypto.so.3")
        allowed.add("libcrypto.so.3")
    need(len(needed) == len(set(needed)) and required <= set(needed) <= allowed
         and runpath == ("$ORIGIN/../lib" if name == "python" else "$ORIGIN"),
         "Unselected loader dependencies or RUNPATH")
    if name != "python":
        need(len(tags.get(14, [])) == 1 and string(tags[14][0]) == name, "OpenSSL SONAME differs")
    return {"needed": needed, "runpath": runpath, "notALoaderQualification": True}


def source_openssl_configuration(files: dict[str, bytes], *, headers: bool) -> None:
    """Check generated OpenSSL DATA without evaluating configdata.pm as Perl.

    OpenSSL 3.5.8 deliberately emits no OPENSSL_NO_MODULE/OPENSSL_NO_LEGACY.
    Its sorted dump_data rows and generated Makefile are the relevant controls.
    """
    raw = files["configdata.pm"]
    declarations = re.findall(rb"^[ \t]*our[ \t]+%disabled\b[^\n]*", raw, re.M)
    need(declarations == [b"our %disabled = ("], "OpenSSL disabled table missing/repeated")
    blocks = re.findall(rb"^our %disabled = \(\n(.*?)\n\);$", raw, re.M | re.S)
    need(len(blocks) == 1, "OpenSSL disabled table framing differs")
    keys, disabled = [], {}
    for row in blocks[0].split(b",\n"):
        match = re.fullmatch(rb'    "([a-z0-9_+.-]+)" => "([a-z0-9_+(). -]+)"', row)
        need(match is not None, "OpenSSL disabled table scalar syntax differs")
        keys.append(match[1])
        disabled[match[1]] = match[2]
    need(keys == sorted(set(keys)), "OpenSSL disabled table keys repeated/unsorted")
    for name in ("module", "dso", "engine", "autoload-config", "legacy"):
        need(disabled.get(name.encode()) == b"option", "OpenSSL explicit no-" + name + " control differs")
    for name in ("MODULES", "INSTALL_MODULES"):
        need(_make_value(files["Makefile"], name) == "", "OpenSSL " + name + " must be empty")
    if headers:
        for macro in ("DSO", "ENGINE", "AUTOLOAD_CONFIG"):
            need(re.search(rb"^#[ \t]*define[ \t]+OPENSSL_NO_" + macro.encode() + rb"\b",
                           files["include/openssl/configuration.h"], re.M) is not None,
                 "OpenSSL generated OPENSSL_NO_" + macro + " control missing")
        need(re.search(rb'^#[ \t]*define[ \t]+OPENSSL_VERSION_STR[ \t]+"3\.5\.8"',
                       files["include/openssl/opensslv.h"], re.M) is not None, "OpenSSL version differs")


def source_capture_configuration(phase: str) -> list[dict]:
    if phase in {"python-configure", "python-build"}:
        root, names = WORK / "build/cpython", SOURCE_CONFIG_FILES
    elif phase in {"openssl-build", "openssl-install"}:
        root, names = WORK / "build/openssl", SOURCE_OPENSSL_FILES
    elif phase == "openssl-configure":
        root, names = WORK / "build/openssl", ("Makefile", "configdata.pm")
    elif phase in {"zlib-configure", "libffi-configure"}:
        root, names = WORK / "build" / phase.split("-", 1)[0], ("configure.log",) if phase == "zlib-configure" else ("config.log",)
    else:
        return []
    captured, records = {}, []
    for name in names:
        raw = source_read(root / name, MAX_JSON)
        captured[name] = raw
        records.append(source_write(RECEIPTS / (phase + "-" + name.replace("/", "-")), raw))
    if phase == "python-build":
        raw = source_read(root / "pybuilddir.txt", 4096)
        source_pybuilddir(raw)
        records.append(source_write(RECEIPTS / "python-build-pybuilddir.txt", raw))
    if phase.startswith("python-"):
        source_material_configuration(captured, source_read(Path(__file__).with_name("cpython_source_setup.local")),
            source_read(SOURCE_ROOT / "cpython/Include/patchlevel.h", 1 << 20))
    elif phase.startswith("openssl-"):
        source_openssl_configuration(captured, headers=phase != "openssl-configure")
    return records


def source_openssl_layout() -> dict:
    rows = []
    for name in SOURCE_LIBRARIES:
        path = WORK / "build/openssl" / name
        raw = source_read(path, 64 << 20)
        source_elf(raw, name)
        need(source_read(WORK / "deps/lib" / name, 64 << 20) == raw,
             "OpenSSL install_dev changed the original built bytes")
        original = {"path": str(path), "size": len(raw), "sha256": digest(raw)}
        copies = []
        for prefix in SOURCE_LAYOUT_ROOTS:
            destination = Path(prefix) / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            copies.append(source_write(destination, raw, 0o644))
        rows.append({"original": original, "producerPhase": "openssl-build", "projections": copies})
    return source_write(RECEIPTS / SOURCE_OPENSSL_LAYOUT_DATA, canonical({"profile": SOURCE_PROFILE, "libraries": rows}))


def source_pybuilddir(raw: bytes) -> str:
    # Pinned sysconfig writes the path itself, without a line terminator.
    need(0 < len(raw) <= 4096, "pybuilddir.txt must be bounded relative DATA")
    need(re.fullmatch(rb"build/[A-Za-z0-9._+\-]+", raw) is not None
         and raw not in {b"build/.", b"build/.."},
         "pybuilddir.txt escapes the original build directory")
    return raw.decode("ascii")


def source_stdlib_destination(name: str) -> tuple[str | None, str | None]:
    """Deterministic original-source omission rule, not an upstream installation."""
    parts = name.split("/")
    need(parts and all(p not in {"", ".", ".."} for p in parts) and not name.startswith("/"), "Invalid Lib member")
    leaf = parts[-1]
    need(not (leaf.endswith((".so", ".dll", ".dylib", ".pyd")) or ".so." in leaf),
         "Unexpected native source member; do not prune it into acceptance")
    if "__pycache__" in parts or leaf.endswith((".pyc", ".pyo")):
        return None, "bytecode-or-cache"
    if parts[0] in {"test", "ensurepip", "idlelib", "turtledemo", "venv", "site-packages", "tkinter", "turtle.py"}:
        return None, "excluded-stdlib-subtree"
    if not leaf.endswith(".py"):
        return None, "non-python-stdlib-data"
    need(not leaf.startswith(("_sysconfigdata_", "_sysconfig_vars_")), "Source cannot stand in for generated sysconfig")
    return "python/lib/python3.14/" + name, None


def source_project(lock: dict) -> dict:
    """Byte-preserving DATA projection. Keep all original objects/archives."""
    files, omissions = [], []

    def copy(path: Path, destination: str, producer: str, *, admitted: dict | None = None) -> None:
        raw = source_bound(admitted) if admitted is not None else source_read(path, 512 << 20)
        target = WORK / "stage" / destination
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        mode = 0o755 if destination == "python/bin/python3" else 0o644
        source_write(target, raw, mode)
        files.append({"path": destination, "size": len(raw), "sha256": digest(raw), "mode": mode,
            "origin": {"kind": "source-built" if producer != "authenticated-source" else "source-projected",
                "path": str(path), "producerPhase": producer}})

    original = WORK / "build/cpython"
    build_tree = ordinary_tree(original)
    for path in build_tree.values():
        leaf = path.name
        if leaf.endswith((".so", ".dll", ".dylib", ".pyd")) or ".so." in leaf:
            need(path.parent == original / "lib" and leaf in SOURCE_LIBRARIES,
                 "Unexpected Python shared native output; no pruning into success")
    source_elf(source_read(original / "python", 64 << 20), "python")
    copy(original / "python", "python/bin/python3", "python-build")
    layout = decode(source_read(RECEIPTS / SOURCE_OPENSSL_LAYOUT_DATA, MAX_JSON))
    for row in layout["libraries"]:
        raw = source_bound(row["original"], 64 << 20)
        for projection in row["projections"]:
            need(source_bound(projection, 64 << 20) == raw, "OpenSSL projection changed during Python build")
        name = Path(row["original"]["path"]).name
        source_elf(raw, name)
        files.append({"path": "python/lib/" + name, "size": len(raw), "sha256": digest(raw), "mode": 0o644,
            "origin": {"kind": "source-built", "path": row["original"]["path"], "producerPhase": "openssl-build"}})
    source = next(s for s in lock["sources"] if s["id"] == "cpython")
    inventory = source_inventory(source)
    lib = SOURCE_ROOT / "cpython/Lib"
    for row in inventory.values():
        path = Path(row["path"])
        if not path.is_relative_to(lib):
            continue
        record = {k: row[k] for k in ("path", "size", "sha256")}
        destination, reason = source_stdlib_destination(path.relative_to(lib).as_posix())
        if destination is None:
            omissions.append({**record, "reason": reason})
        else:
            copy(path, destination, "authenticated-source", admitted=record)
    license_path = SOURCE_ROOT / "cpython/LICENSE"
    copy(license_path, "python/LICENSE.txt", "authenticated-source",
         admitted={k: inventory[str(license_path)][k] for k in ("path", "size", "sha256")})
    generated = original / source_pybuilddir(source_read(original / "pybuilddir.txt", 4096))
    ordinary_directory(generated)
    for name in SOURCE_GENERATED_NAMES:
        copy(generated / name, "python/lib/python3.14/" + name, "python-build")
    for destination, raw, rule in (
        ("python/lib/python314.zip", b"PK\x05\x06" + b"\0" * 18, "empty-zip-v1"),
        ("python/lib/python3.14/lib-dynload/README.mrk", b"No shared extension modules are shipped in this profile.\n", "static-module-landmark-v1")):
        path = WORK / "stage" / destination
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        source_write(path, raw, 0o644)
        files.append({"path": destination, "size": len(raw), "sha256": digest(raw), "mode": 0o644,
                      "origin": {"kind": "generated-landmark", "rule": rule}})
    required = {"os.py", "encodings/__init__.py", "ssl.py", "socket.py", "ctypes/__init__.py",
                "xml/__init__.py", "xml/parsers/__init__.py", "xml/parsers/expat.py"}
    need({"python/lib/python3.14/" + name for name in required} <= {r["path"] for r in files},
         "Selected stdlib/API source leaves absent")
    need(set(ordinary_tree(WORK / "stage")) == {str(WORK / "stage" / row["path"]) for row in files},
         "Projection has unexpected files")
    directories = sorted({str(parent.relative_to(WORK / "stage")) for row in files
        for parent in (WORK / "stage" / row["path"]).parents if parent.is_relative_to(WORK / "stage") and parent != WORK / "stage"})
    document = {"profile": SOURCE_PROFILE, "sourcePrefix": "/work/stage", "files": sorted(files, key=lambda r: r["path"]),
                "directories": directories, "omissions": sorted(omissions, key=lambda r: r["path"])}
    return source_write(RECEIPTS / "source-projection.json", canonical(document))


def main() -> None:
    # The shell calls only these two finite data operations. No generic command/approval option.
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "materialize":
            materialize(absolute(sys.argv[2]), sha(sys.argv[3]))
        elif len(sys.argv) == 6 and sys.argv[1] == "phase":
            phase_record(absolute(sys.argv[2]), sha(sys.argv[3]), sys.argv[4], int(sys.argv[5]))
        else:
            raise InputError("Expected materialize LOCK SHA256 or phase LOCK SHA256 NAME STATUS")
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        raise SystemExit("Static publisher input/evidence refused; retain inputs and partial private output") from None


if __name__ == "__main__":
    main()
