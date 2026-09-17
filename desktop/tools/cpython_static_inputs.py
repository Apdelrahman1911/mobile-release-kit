"""Closed input/data helpers for the one proposed Linux CPython source recipe.

A matching sealed lock is input identity, NOT execution or production approval.
There is no acquisition, signature-verification claim, candidate import, package
installation or subprocess launcher in this module. Use only in the separately
reviewed publisher envelope. Every output is private build evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
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
    need(type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./+@=,-]+", value) is not None,
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


def configuration_names(config: bytes, makefile: bytes) -> list[str]:
    """Audit generated configuration as data, not a runtime builtin observation."""
    table = re.search(rb"struct _inittab _PyImport_Inittab\[\] = \{(.*?)\n\};", config, re.S)
    need(table is not None, "Generated builtin table missing")
    body = re.sub(rb"/\*.*?\*/", b"", table[1], flags=re.S)
    row = rb'\{\s*"([A-Za-z0-9_]+)"\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\},'
    names = [value.decode("ascii") for value in re.findall(row, body)]
    rest = re.sub(row, b"", body).strip()
    need(re.fullmatch(rb"\{\s*0\s*,\s*0\s*\}", rest) is not None,
         "Unsupported generated builtin table syntax")
    expected = set(BOOTSTRAP_MODULES + INTRINSIC_MODULES + STATIC_MODULES)
    need(len(names) == len(expected) and set(names) == expected, "Generated builtin-name roster differs")
    for key, wanted in ((b"MODBUILT_NAMES", set(BOOTSTRAP_MODULES + STATIC_MODULES)),
                        (b"MODSHARED_NAMES", set()), (b"MODDISABLED_NAMES", set(DISABLED_MODULES))):
        values = re.findall(rb"^" + key + rb"[ \t]*=[ \t]*(.*)$", makefile, re.M)
        need(len(values) == 1, "Generated module Makefile assignment missing or repeated")
        words = values[0].decode("ascii").split()
        need(len(words) == len(wanted) and set(words) == wanted, "Generated Makefile module roster differs")
    return sorted(names)


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
