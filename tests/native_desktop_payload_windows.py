"""Fixed copied-payload probe, only for the reviewed disposable Windows job.

One -I -S -B invocation, one prepared core.zip argument, one catalog request.
No child, socket, WMI query, installation, file mutation or product opt-in.
Import is inert. Native APIs below inspect only this original process; a probe
response is not its parent's wait/EOF/cleanup receipt or installed qualification.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

SCOPE = "windows-embedded-payload-native-v1"
LIMIT = 65536
PATH_CHARS = 4096
MODULE_LIMIT = 128
IMAGE_BYTES = 32 * 1024 * 1024
TOTAL_IMAGE_BYTES = 128 * 1024 * 1024
STAGE = "entry"

# Exact PE member names from accepted python-3.14.7-embed-amd64.zip input04.
# Hash authority remains the original compile-bound prepared manifest, returned
# here for the Rust caller to compare; a newly observed module never adds a name.
PAYLOAD_IMAGES = frozenset({
    "_asyncio.pyd", "_bz2.pyd", "_ctypes.pyd", "_decimal.pyd", "_elementtree.pyd",
    "_hashlib.pyd", "_lzma.pyd", "_multiprocessing.pyd", "_overlapped.pyd", "_queue.pyd",
    "_remote_debugging.pyd", "_socket.pyd", "_sqlite3.pyd", "_ssl.pyd", "_uuid.pyd", "_wmi.pyd",
    "_zoneinfo.pyd", "_zstd.pyd", "libcrypto-3.dll", "libffi-8.dll", "libssl-3.dll", "libtommath.dll",
    "pyexpat.pyd", "python.exe", "python3.dll", "python314.dll", "pythonw.exe", "select.pyd",
    "sqlite3.dll", "unicodedata.pyd", "vcruntime140.dll", "vcruntime140_1.dll", "winsound.pyd",
})
SUPPLIER_DATA = frozenset({"LICENSE.txt", "python.cat", "python314._pth", "python314.zip"})
ROOT_FILES = frozenset({"engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
    "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py", "core.zip", "github-ca.pem"})
EXTENSIONS = (
    "_bz2", "_ctypes", "_decimal", "_elementtree", "_hashlib", "_lzma", "_socket", "_sqlite3",
    "_ssl", "_uuid", "_zoneinfo", "_zstd", "pyexpat", "select", "unicodedata",
)

# Prospective finite source policy, NOT a measured dynamic-closure claim.
# First group: exact normal imports from the33 supplier PE images. Second:
# core/CRT/API-set hosts, security/Winsock and COM/UI forward/transitive hosts.
# API-set contracts are individually named, never accepted by a prefix pattern.
SYSTEM_IMAGES = frozenset({
    "advapi32.dll", "bcrypt.dll", "crypt32.dll", "iphlpapi.dll", "kernel32.dll", "ole32.dll",
    "oleaut32.dll", "propsys.dll", "rpcrt4.dll", "user32.dll", "version.dll", "winmm.dll", "ws2_32.dll",
    "ntdll.dll", "kernelbase.dll", "ucrtbase.dll", "msvcrt.dll", "sechost.dll", "bcryptprimitives.dll",
    "cryptbase.dll", "msasn1.dll", "nsi.dll", "mswsock.dll", "combase.dll", "gdi32.dll", "gdi32full.dll",
    "win32u.dll", "msvcp_win.dll", "shcore.dll", "shlwapi.dll",
    "api-ms-win-core-path-l1-1-0.dll",
    "api-ms-win-crt-conio-l1-1-0.dll", "api-ms-win-crt-convert-l1-1-0.dll",
    "api-ms-win-crt-environment-l1-1-0.dll", "api-ms-win-crt-filesystem-l1-1-0.dll",
    "api-ms-win-crt-heap-l1-1-0.dll", "api-ms-win-crt-locale-l1-1-0.dll",
    "api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-private-l1-1-0.dll",
    "api-ms-win-crt-process-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll",
    "api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-string-l1-1-0.dll",
    "api-ms-win-crt-time-l1-1-0.dll", "api-ms-win-crt-utility-l1-1-0.dll",
})


class ProbeFailure(ValueError):
    def __init__(self, code: str, module: str | None = None):
        self.code = code
        self.module = module if module is not None and re.fullmatch(r"[a-z0-9_.-]{1,128}", module) else None
        super().__init__(code)


def require(value: bool, code: str, module: str | None = None) -> None:
    if not value:
        raise ProbeFailure(code, module)


def require_dependency_versions(openssl_version, sqlite_version) -> None:
    # CPython retains OpenSSL's legacy major/minor/fix/patch/status layout.
    # OpenSSL 3.5.7 encodes 0x30500070, not a semantic (3, 5, 7) prefix.
    require(type(openssl_version) is tuple and len(openssl_version) == 5
            and all(type(value) is int for value in openssl_version)
            and openssl_version == (3, 5, 0, 7, 0), "native_openssl_version")
    require(type(sqlite_version) is str and len(sqlite_version) <= 32, "native_sqlite_version")


def path_key(value: str) -> str:
    # Equality normalizes case/separators only, not .., short names, device or
    # UNC prefixes, junctions, environment substitutions or a later resolution.
    require(type(value) is str and 3 <= len(value) < PATH_CHARS
            and re.match(r"^[A-Za-z]:[\\/]", value) is not None
            and all(ord(c) >= 32 and ord(c) != 127 and c not in '<>"|?*' for c in value)
            and ":" not in value[2:], "path_form")
    text = value.replace("/", "\\")
    require(all(part and part not in {".", ".."} and not part.endswith((".", " "))
                for part in text[3:].split("\\")), "path_form")
    return text.casefold()


def file_identity(value, mode: int) -> tuple:
    # CPython Windows exposes the same birthtime through both stat APIs, but
    # path ctime is birthtime while descriptor ctime is Windows ChangeTime.
    return (value.st_dev, value.st_ino, mode, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_birthtime_ns, value.st_file_attributes, value.st_reparse_tag)


def state(value) -> tuple:
    # Same-API comparisons retain the complete, unnormalized mode and ctime.
    return file_identity(value, value.st_mode) + (value.st_ctime_ns,)


def same_opened_file(path: Path, named, opened) -> bool:
    named_mode = named.st_mode
    if path.name.lower().endswith((".exe", ".bat", ".cmd", ".com")):
        # Only path stat adds these executable-suffix bits. Descriptor mode
        # and every other named mode bit remain exact; this is not an ACL test.
        named_mode &= ~0o111
    return file_identity(named, named_mode) == file_identity(opened, opened.st_mode)


def file_fact(path: Path, maximum: int, *, single_link: bool = True, retain: bool = False) -> tuple[dict, bytes]:
    path_key(str(path))
    for parent in reversed(path.parents):
        value = parent.lstat()
        require(stat.S_ISDIR(value.st_mode) and not value.st_file_attributes & 0x400, "file_ancestor")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not before.st_file_attributes & 0x400
            and before.st_nlink >= 1 and (not single_link or before.st_nlink == 1)
            and 0 < before.st_size <= maximum, "file_kind_size")
    descriptor = os.open(path, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
    digest, size, chunks = hashlib.sha256(), 0, []
    try:
        opened = os.fstat(descriptor)
        require(same_opened_file(path, before, opened), "file_open_changed")
        while True:
            block = os.read(descriptor, min(65536, before.st_size + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= before.st_size, "file_grew")
            digest.update(block)
            if retain:
                chunks.append(block)
        require(size == before.st_size and state(os.fstat(descriptor)) == state(opened), "file_read_changed")
    finally:
        os.close(descriptor)  # One original close; no retry or adopted handle.
    require(state(path.lstat()) == state(before), "file_name_changed")
    return {"size": size, "sha256": digest.hexdigest()}, b"".join(chunks)


def pairs(items: list) -> dict:
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def manifest_inputs(runtime: Path) -> tuple[dict, str]:
    fact, raw = file_fact(runtime / "manifest.json", 1024 * 1024, retain=True)
    manifest = json.loads(raw, object_pairs_hook=pairs)
    require(type(manifest) is dict and set(manifest) == {"schemaVersion", "protocol", "coreVersion", "target",
            "coreSha256", "protocolSha256", "inventorySha256", "files"}
            and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1
            and type(manifest["protocol"]) is int and manifest["protocol"] == 1
            and manifest["coreVersion"] == "0.3.0" and manifest["target"] == "x86_64-pc-windows-msvc",
            "manifest_contract")
    rows = manifest["files"]
    expected = ROOT_FILES | {"python/" + name for name in PAYLOAD_IMAGES | SUPPLIER_DATA | {"MRK-EMBEDDED-NOTICES.txt"}}
    require(type(rows) is list and len(rows) == len(expected)
            and all(type(row) is dict and set(row) == {"path", "size", "sha256"}
                    and type(row["path"]) is str and row["path"] in expected
                    and type(row["size"]) is int and 0 < row["size"] <= 512 * 1024 * 1024
                    and type(row["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
                    for row in rows)
            and [row["path"] for row in rows] == sorted(expected)
            and hashlib.sha256(canonical(rows)).hexdigest() == manifest["inventorySha256"], "manifest_inventory")
    entries = {row["path"]: {"size": row["size"], "sha256": row["sha256"]} for row in rows}
    require(entries["core.zip"]["sha256"] == manifest["coreSha256"]
            and entries["python/python314.zip"] == {"size": 4138882,
                "sha256": "5a7a66daf1a2c2e3c8d7a4a0d095685ec301efc3ef28cc2419e3041bf5729b65"}, "manifest_core_stdlib")
    return entries, fact["sha256"]


def require_imported_module_origins(modules: dict, core: Path, stdlib: Path, python: Path) -> None:
    require(type(modules) is dict and len(modules) <= 2048, "python_module_bound")
    roots = (path_key(str(core)), path_key(str(stdlib)))
    # CPython's pyexpat creates two support modules without independent specs;
    # xml.parsers.expat registers aliases of those same producer-owned objects.
    # Validate both producers before classifying these four exact registry keys.
    producer, wrapper = modules.get("pyexpat"), modules.get("xml.parsers.expat")
    for name, owner in (("pyexpat", producer), ("xml.parsers.expat", wrapper)):
        require(type(owner) is type(sys), "python_expat_parent_origin", name)
        spec = getattr(owner, "__spec__", None)
        origin = getattr(spec, "origin", None)
        owner_name, spec_name = vars(owner).get("__name__"), getattr(spec, "name", None)
        require(type(owner_name) is str and owner_name == name
                and type(spec_name) is str and spec_name == name
                and type(origin) is str, "python_expat_parent_origin", name)
        key = path_key(origin)
        if name == "pyexpat":
            require(key == path_key(str(python / "pyexpat.pyd")), "python_expat_parent_origin", name)
        else:
            archive = getattr(getattr(spec, "loader", None), "archive", None)
            require(type(archive) is str and path_key(archive) == roots[1]
                    and key.startswith(roots[1] + "\\"), "python_expat_parent_origin", name)

    support = {}
    for suffix in ("errors", "model"):
        canonical, alias = "pyexpat." + suffix, "xml.parsers.expat." + suffix
        module = getattr(producer, suffix, None)
        require(type(module) is type(sys) and modules.get(canonical) is module
                and modules.get(alias) is module and getattr(wrapper, suffix, None) is module,
                "python_expat_support_identity", canonical)
        attributes = vars(module)
        require(type(attributes.get("__name__")) is str and attributes["__name__"] == canonical
                and all(field in attributes and attributes[field] is None
                        for field in ("__spec__", "__loader__", "__package__"))
                and "__file__" not in attributes and "__path__" not in attributes,
                "python_expat_support_metadata", canonical)
        support[canonical] = support[alias] = module

    for name, module in modules.items():
        if module is None or name == "__main__":
            continue  # The Rust selector separately binds this exact probe copy.
        if name in support:
            require(module is support[name], "python_expat_support_identity", name)
            continue
        # New labels are closed benign names only; never reveal an unknown name
        # or origin. Existing extension/image leaf diagnostics are unchanged.
        label = name if name in {"pyexpat", "xml.parsers.expat", *support} else None
        spec = getattr(module, "__spec__", None)
        require(spec is not None, "python_module_spec_missing", label)
        origin = getattr(spec, "origin", None)
        require(origin is not None, "python_module_origin_missing", label)
        require(type(origin) is str, "python_module_origin_type", label)
        if origin in {"built-in", "frozen"}:
            continue
        key = path_key(origin)
        archive = getattr(getattr(spec, "loader", None), "archive", None)
        if type(archive) is str and path_key(archive) in roots:
            require(key.startswith(path_key(archive) + "\\"), "python_zip_origin")
            if name == "mobile_release" or name.startswith("mobile_release."):
                require(path_key(archive) == roots[0], "core_import_origin")
            continue
        leaf = Path(origin).name.casefold()
        require(leaf in PAYLOAD_IMAGES and leaf.endswith(".pyd")
                and key == path_key(str(python / leaf)), "python_extension_origin", leaf)


def imported_origins(core: Path, stdlib: Path, python: Path) -> None:
    require(len(sys.modules) <= 2048, "python_module_bound")
    require_imported_module_origins(dict(sys.modules), core, stdlib, python)


def behavior() -> dict:
    import bz2
    import ctypes
    import decimal
    import lzma
    import sqlite3
    import ssl
    import zlib
    from compression import zstd
    from xml.etree import ElementTree
    from xml.parsers import expat

    class Pair(ctypes.Structure):
        _fields_ = (("first", ctypes.c_uint64), ("second", ctypes.c_uint64))

    pair = Pair(0x123456789ABCDEF0, 7)
    require(ctypes.sizeof(ctypes.c_void_p) == 8 and ctypes.sizeof(Pair) == 16
            and pair.first + pair.second == 0x123456789ABCDEF7, "ctypes_behavior")
    require(hashlib.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            and hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1).hex()
            == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", "hash_behavior")
    sample = b"Mobile Release Kit fixed native payload\n" * 16
    require(zlib.decompress(zlib.compress(sample)) == sample
            and bz2.decompress(bz2.compress(sample)) == sample
            and lzma.decompress(lzma.compress(sample, preset=0)) == sample
            and zstd.decompress(zstd.compress(sample)) == sample, "compression_behavior")
    xml, events = b'<release version="1">ready</release>', []
    parser = expat.ParserCreate()
    parser.StartElementHandler = lambda name, attrs: events.append((name, attrs))
    parser.CharacterDataHandler = lambda text: events.append(text)
    parser.Parse(xml, True)
    require(events == [("release", {"version": "1"}), "ready"]
            and ElementTree.fromstring(xml).text == "ready", "expat_behavior")
    require(decimal.Decimal("0.1") + decimal.Decimal("0.2") == decimal.Decimal("0.3"), "decimal_behavior")
    require_dependency_versions(ssl.OPENSSL_VERSION_INFO, sqlite3.sqlite_version)
    return {"ctypes": True, "hashes": True, "compression": True, "expat": True,
            "decimal": True, "sqlite": sqlite3.sqlite_version, "ssl": ssl.OPENSSL_VERSION}


def loaded_images(python: Path, entries: dict) -> tuple[str, list[dict]]:
    import ctypes as c

    require(c.sizeof(c.c_void_p) == 8 and c.sizeof(c.c_ulong) == 4 and c.sizeof(c.c_wchar) == 2, "windows_abi")
    # Documented restricted loader search. This ONE LoadLibrary reference is
    # owned; the enumerated HMODULEs and current-process pseudo handle are not.
    kernel = c.WinDLL("kernel32.dll", winmode=0x00000800, use_last_error=True)
    owned, release = kernel._handle, None
    try:
        release = kernel.FreeLibrary
        release.argtypes, release.restype = (c.c_void_p,), c.c_int
        current = kernel.GetCurrentProcess
        current.argtypes, current.restype = (), c.c_void_p
        enum = kernel.K32EnumProcessModules
        enum.argtypes, enum.restype = (c.c_void_p, c.POINTER(c.c_void_p), c.c_ulong, c.POINTER(c.c_ulong)), c.c_int
        filename = kernel.GetModuleFileNameW
        filename.argtypes, filename.restype = (c.c_void_p, c.POINTER(c.c_wchar), c.c_ulong), c.c_ulong
        system = kernel.GetSystemDirectoryW
        system.argtypes, system.restype = (c.POINTER(c.c_wchar), c.c_uint), c.c_uint
        process = current()
        require(process == (1 << 64) - 1, "current_process_handle")

        def text(call, *arguments):
            buffer = c.create_unicode_buffer(PATH_CHARS)
            count = call(*arguments, buffer, PATH_CHARS)
            require(0 < count < PATH_CHARS and buffer[count] == "\0"
                    and len(buffer.value.encode("utf-16-le")) // 2 == count, "native_path_truncated")
            path_key(buffer.value)
            return buffer.value

        def snapshot() -> tuple[tuple[int, str], ...]:
            modules, needed = (c.c_void_p * MODULE_LIMIT)(), c.c_ulong()
            require(enum(process, modules, c.sizeof(modules), c.byref(needed)) != 0
                    and 0 < needed.value <= c.sizeof(modules)
                    and needed.value % c.sizeof(c.c_void_p) == 0, "module_enumeration")
            handles = tuple(modules[index] for index in range(needed.value // c.sizeof(c.c_void_p)))
            require(all(handles) and len(set(handles)) == len(handles), "module_handles")
            return tuple(sorted((handle, text(filename, handle)) for handle in handles))

        system_directory = text(system)
        require(Path(system_directory).name.casefold() == "system32", "system_directory")
        before, images, seen, total = snapshot(), [], set(), 0
        for _, path in before:
            leaf = Path(path).name.casefold()
            require(leaf not in seen, "duplicate_module_name", leaf)
            seen.add(leaf)
            if leaf in PAYLOAD_IMAGES:
                require(path_key(path) == path_key(str(python / leaf)), "payload_image_origin", leaf)
                fact, _ = file_fact(Path(path), IMAGE_BYTES)
                require(fact == entries["python/" + leaf], "payload_image_digest", leaf)
                origin = "payload"
            else:
                require(leaf in SYSTEM_IMAGES and path_key(path) == path_key(str(Path(system_directory) / leaf)),
                        "system_image_origin", leaf)
                fact, _ = file_fact(Path(path), IMAGE_BYTES, single_link=False)
                origin = "system32"
            total += fact["size"]
            require(total <= TOTAL_IMAGE_BYTES, "image_byte_bound")
            images.append({"name": leaf, "path": path, "origin": origin, **fact})
        require({"python.exe", "python314.dll", "vcruntime140.dll", "vcruntime140_1.dll", "libffi-8.dll",
                 "libcrypto-3.dll", "libssl-3.dll", "sqlite3.dll", *(name + ".pyd" for name in EXTENSIONS)} <= seen,
                "required_images_missing")
        require(snapshot() == before, "loaded_images_changed")
        return system_directory, sorted(images, key=lambda item: item["name"])
    finally:
        handle, owned = owned, None  # Retire before the sole release attempt.
        require(release is not None and release(handle) != 0, "loader_reference_close")


def main() -> int:
    global STAGE
    require(len(sys.argv) == 2 and os.name == "nt" and sys.platform == "win32"
            and sys.implementation.name == "cpython" and sys.version_info[:3] == (3, 14, 7)
            and sys.maxsize == (1 << 63) - 1 and struct.calcsize("P") == 8
            and sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.flags.no_user_site == 1
            and sys.flags.ignore_environment == 1 and sys.flags.safe_path and sys.dont_write_bytecode
            and sys._is_gil_enabled(), "runtime_flags")
    executable = Path(sys.executable)
    python, core = executable.parent, Path(sys.argv[1])
    runtime, stdlib = python.parent, python / "python314.zip"
    require(executable.name == "python.exe" and path_key(str(core)) == path_key(str(runtime / "core.zip"))
            and all(path_key(value) == path_key(str(python))
                    for value in (sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix))
            and [path_key(value) for value in sys.path] == [path_key(str(stdlib)), path_key(str(python))]
            and "site" not in sys.modules and "sitecustomize" not in sys.modules and "usercustomize" not in sys.modules,
            "runtime_paths")
    # Python's documented Windows os.environ mapping uppercases its keys even
    # when CreateProcess received the conventional mixed-case SystemRoot name.
    original_environment = dict(os.environ)
    require(set(original_environment) == {"LANG", "LC_ALL", "SYSTEMROOT"}
            and original_environment["LANG"] == "C" and original_environment["LC_ALL"] == "C", "clean_environment")
    environment = {"LANG": "C", "LC_ALL": "C", "SystemRoot": original_environment["SYSTEMROOT"]}
    STAGE = "inputs"
    entries, manifest_hash = manifest_inputs(runtime)
    for relative, bound in (("core.zip", 32 * 1024 * 1024), ("python/python314.zip", 8 * 1024 * 1024),
                            ("python/python314._pth", 1024), ("python/python.exe", IMAGE_BYTES)):
        fact, content = file_fact(runtime / relative, bound, retain=relative.endswith(("._pth", ".exe")))
        require(fact == entries[relative], "prepared_input_digest")
        if relative.endswith("._pth"):
            require(fact == {"size": 80, "sha256": "2ed7ccda80e9e28ab5877902a9a325586c8a7b7b3e6731d944565bee082e216c"},
                    "underpth_digest")
        elif relative.endswith(".exe"):
            require(content[:2] == b"MZ" and len(content) >= 64, "python_pe")
            offset = struct.unpack_from("<I", content, 60)[0]
            require(0 <= offset <= len(content) - 26 and content[offset:offset + 4] == b"PE\0\0"
                    and struct.unpack_from("<H", content, offset + 4)[0] == 0x8664
                    and struct.unpack_from("<H", content, offset + 24)[0] == 0x20B, "python_amd64")
    sys.path.insert(0, str(core))
    from mobile_release import _desktop_engine as engine
    import msvcrt

    msvcrt.setmode(0, os.O_BINARY)
    msvcrt.setmode(1, os.O_BINARY)
    request = engine.parse_request(engine._read_request(0))
    require(request.method == "catalog" and request.params == {}, "fixed_catalog_request")
    STAGE = "imports"
    import importlib
    from importlib.resources import files
    from mobile_release.api import execute

    for name in EXTENSIONS:
        importlib.import_module(name)
    catalog = execute("catalog", {})
    resource_hashes = {}
    for name, field in (("project.schema.json", "schemaSha256"), ("field-help.json", "catalogSha256")):
        with files("mobile_release.api").joinpath("data", name).open("rb") as source:
            raw = source.read(256 * 1024 + 1)
        require(0 < len(raw) <= 256 * 1024, "resource_bound")
        resource_hashes[field] = hashlib.sha256(raw).hexdigest()
        require(json.loads(raw) == catalog["schema" if name == "project.schema.json" else "fields"], "catalog_resource")
    STAGE = "behavior"
    behaviors = behavior()
    STAGE = "import-origins"
    imported_origins(core, stdlib, python)
    STAGE = "loaded-images"
    system_directory, images = loaded_images(python, entries)
    require(path_key(environment["SystemRoot"]) == path_key(str(Path(system_directory).parent)), "system_root_binding")
    require([path_key(value) for value in sys.path] == [path_key(str(core)), path_key(str(stdlib)), path_key(str(python))]
            and dict(os.environ) == original_environment
            and "site" not in sys.modules and "sitecustomize" not in sys.modules and "usercustomize" not in sys.modules,
            "ending_import_environment")
    result = {"scope": SCOPE, "pythonVersion": [3, 14, 7], "machine": "AMD64", "gilEnabled": True,
        "flags": {"isolated": 1, "noSite": 1, "noUserSite": 1, "ignoreEnvironment": 1,
                  "dontWriteBytecode": True, "safePath": True},
        "prefix": sys.prefix, "executable": sys.executable, "sysPath": list(sys.path),
        "manifestSha256": manifest_hash, "coreSha256": entries["core.zip"]["sha256"],
        "stdlibSha256": entries["python/python314.zip"]["sha256"], "resources": resource_hashes,
        "imports": list(EXTENSIONS), "behavior": behaviors, "systemDirectory": system_directory,
        "loadedImages": images, "environment": environment}
    response = engine.encode_response(request, result=result)
    require(len(response) <= LIMIT, "response_bound")
    STAGE = "response"
    engine._write_response(1, response)
    return 0


if __name__ == "__main__":
    try:
        status = main()
    except BaseException as error:
        status = 70
        diagnostic = {"scope": SCOPE, "status": "failed", "stage": STAGE,
                      "code": error.code if isinstance(error, ProbeFailure) else "probe_exception",
                      "module": error.module if isinstance(error, ProbeFailure) else None}
        try:
            os.write(2, canonical(diagnostic) + b"\n")
        except BaseException:
            pass
    raise SystemExit(status)
