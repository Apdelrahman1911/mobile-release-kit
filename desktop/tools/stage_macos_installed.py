#!/usr/bin/env python3
"""Reuse-only Mac engineering package DATA staging; never execute the payload.

Every output is fresh. No extraction API, subprocess, chmod of an existing
ancestor, replacement, deletion, network, core import or interpreter rebuild is
present. `describe-runtime` is the separate DATA step that supplies the proposed
successor digest for independent review BEFORE app compilation. Other commands
require an explicit digest, not a discovered adjacent-manifest authority.
Installer-log actions only collect bounded nonroot diagnostics from one fixed
physical log; they never give those bytes installation/readback authority.
"""
from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
import zlib

DESKTOP = Path(__file__).absolute().parents[1]
RELEASE = "macos26-arm64-project-draft-01"
INSTALL_ROOT = Path("/Library/Application Support/MobileReleaseKit")
APP_NAME = "Mobile Release Kit.app"
APP_BINARY = "Contents/MacOS/mobile-release-kit-desktop"
PACKAGE_ID = "dev.mobile-release-kit.desktop.installed"
FIXTURE_PREFIX = "MobileReleaseKit-InstallerFixture-"
FIXTURE_MARKER = b"MRK_MACOS_INSTALLER_FIXTURE_OCCUPANT\n"
# Exact order/expected original outcomes of the separate compile-time package.
# DATA validation does not itself witness any syscall or injected failure.
FIXTURE_CASES = {
    "occupied-app": ("destination-occupied", "not-attempted", "not-attempted", "refused-staging-retained", False, 1),
    "occupied-release": ("destination-occupied", "not-attempted", "not-attempted", "refused-staging-retained", False, 1),
    "runtime-publication-collision": ("exclusive-publication-refused-or-unknown", "occupied-refused", "not-attempted", "refused-staging-retained", True, 1),
    "staging-file-collision": ("open-refused", "not-attempted", "not-attempted", "refused-staging-retained", False, 1),
    "first-publication-second-refusal": ("exclusive-publication-refused-or-unknown", "confirmed", "occupied-refused", "partial-installation-retained", True, 20),
    "prepublication-persistence-report": ("fixture-reported-persistence-failure", "not-attempted", "not-attempted", "refused-staging-retained", False, 1),
    "postruntime-persistence-report": ("fixture-reported-persistence-failure", "confirmed", "not-attempted", "partial-installation-retained", True, 20),
}
PROTOCOL = "860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e"
ZIP_SIZE = 14726344
ZIP_SHA = "42a6abab90f9641ba1b8c4aa9bb4202b153d676cc6d135b8227d8690e18275be"
TAR_SIZE = 24432640
TAR_SHA = "c927caedfc5a40290da443989534e85bfdf192934f4650c3747a70c53f68d35a"
ORIGINAL_MANIFEST = "7e0b042c82ff567ccfa156974118911e2ba159dbe45020344aaf4d71a28acc44"
NOTICES = {
    "21-LLVM-header-license.txt": (15141, "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee"),
    "22-macOS-SDK-libffi-header-notices.txt": (7329, "5ffe9bffec415b13d6de1f98cffe44bd16297bd91b64d3076cc2852b8de83c68"),
}
BOOTSTRAPS = {"engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
              "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py"}
MAX_FILES = 2048
MAX_BYTES = 512 * 1024 * 1024
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
INSTALLER_RESULT_BYTES = 65536
INSTALLER_RESULT_STATE = "pending-original-export-finalization"
_DARWIN_XATTRS = None
INSTALL_LOG = Path("/private/var/log/install.log")
LOG_TAIL_BYTES = 4096
LOG_INTERVAL_BYTES = 1024 * 1024
LOG_LINE_BYTES = 128 * 1024
LOG_SELECTED_BYTES = 256 * 1024
LOG_METADATA_BYTES = 256 * 1024
LOG_AUTHORITY = "project-correlated-diagnostics-not-package-pid-authentication-or-original-fd-custody"
LOG_REFUSALS = frozenset({
    "log-input-binding", "log-file-policy", "log-file-identity", "log-cursor-shape", "log-cursor-binding",
    "log-cursor-offset", "log-anchor-rewritten", "log-truncated", "log-incomplete-boundary",
    "log-interval-bound", "log-line-bound", "log-selected-bound", "log-metadata-bound",
    "log-no-project-lines", "log-read-incomplete", "log-output-readback", "original-close-unknown",
    "ancestor-close-unknown",
})


class Refused(Exception):
    pass


GENERIC_REFUSAL = "Mac package staging/observation refused; preserve original outputs, no automatic cleanup or retry."
PACKAGE_REFUSALS = {
    "compressed-data-bound": "MRK_MACOS_PACKAGE_REFUSED=compressed-data-bound",
    "xar-header-bound": "MRK_MACOS_PACKAGE_REFUSED=xar-header-bound",
    "xar-member-encoding": "MRK_MACOS_PACKAGE_REFUSED=xar-member-encoding",
    "scripts-only-package-no-payload": "MRK_MACOS_PACKAGE_REFUSED=scripts-only-package-no-payload",
    "unsupported-scripts-cpio-format": "MRK_MACOS_PACKAGE_REFUSED=unsupported-scripts-cpio-format",
    "cpio-trailer": "MRK_MACOS_PACKAGE_REFUSED=cpio-trailer",
    "scripts-root-required": "MRK_MACOS_PACKAGE_REFUSED=scripts-root-required",
    "scripts-root-duplicate": "MRK_MACOS_PACKAGE_REFUSED=scripts-root-duplicate",
    "scripts-root-owner-mode": "MRK_MACOS_PACKAGE_REFUSED=scripts-root-owner-mode",
    "scripts-entry-owner": "MRK_MACOS_PACKAGE_REFUSED=scripts-entry-owner",
    "scripts-directory-mode": "MRK_MACOS_PACKAGE_REFUSED=scripts-directory-mode",
    "scripts-file-type-mode": "MRK_MACOS_PACKAGE_REFUSED=scripts-file-type-mode",
    "packager-identity": "MRK_MACOS_PACKAGE_REFUSED=packager-identity",
    "packager-directory-mode-owner": "MRK_MACOS_PACKAGE_REFUSED=packager-directory-mode-owner",
    "packager-file-mode-owner": "MRK_MACOS_PACKAGE_REFUSED=packager-file-mode-owner",
    "original-package-owner": "MRK_MACOS_PACKAGE_REFUSED=original-package-owner",
    "original-package-roster": "MRK_MACOS_PACKAGE_REFUSED=original-package-roster",
    "complete-original-scripts-correspondence": "MRK_MACOS_PACKAGE_REFUSED=complete-original-scripts-correspondence",
    "scripts-package-identity": "MRK_MACOS_PACKAGE_REFUSED=scripts-package-identity",
    "final-package-roster": "MRK_MACOS_PACKAGE_REFUSED=final-package-roster",
    "package-info-bytes-changed": "MRK_MACOS_PACKAGE_REFUSED=package-info-bytes-changed",
    "complete-root-owned-scripts-correspondence": "MRK_MACOS_PACKAGE_REFUSED=complete-root-owned-scripts-correspondence",
}


def package_refusal_message(error):
    # Select only a predeclared literal. Never stringify/reflect an exception.
    if type(error) is Refused and len(error.args) == 1 and type(error.args[0]) is str:
        message = PACKAGE_REFUSALS.get(error.args[0])
        if message is not None:
            return message + "\n" + GENERIC_REFUSAL
    return GENERIC_REFUSAL


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def decode(body):
    need(len(body) <= 1024 * 1024, "json-byte-bound")
    value = json.loads(body, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused("json-constant")))
    todo = [(value, 0)]
    count = 0
    while todo:
        item, depth = todo.pop()
        count += 1
        need(count <= 20000 and depth <= 32, "json-shape-bound")
        if type(item) is dict:
            todo.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            todo.extend((v, depth + 1) for v in item)
        elif type(item) is float:
            need(float("-inf") < item < float("inf"), "json-constant")
    return value


def safe_path(value):
    if type(value) is not str or not value or len(value) > 512 or not value.isascii():
        return False
    parts = value.split("/")
    if len(parts) > 16:
        return False
    for part in parts:
        if not re.fullmatch(r"[A-Za-z0-9._+-]+", part) or part in (".", "..") or part.endswith("."):
            return False
        stem = part.split(".", 1)[0].upper()
        if stem in ("CON", "PRN", "AUX", "NUL") or re.fullmatch(r"(?:COM|LPT)[1-9]", stem):
            return False
    return True


def signature(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def close_once(fd):
    # Never retry an ambiguous close or silently convert it into settlement.
    try:
        os.close(fd)
    except OSError as error:
        raise Refused("original-close-unknown") from error


@contextlib.contextmanager
def parent(path):
    path = Path(path)
    spelling = os.fspath(path)
    need(path.is_absolute() and len(os.fsencode(spelling)) <= 4096, "absolute-path-required")
    parts = spelling.split("/")[1:]
    need(parts and len(parts) <= 40 and all(p and p not in (".", "..") and len(os.fsencode(p)) <= 255 for p in parts), "path-spelling")
    originals = []
    try:
        originals.append(os.open("/", READ_FLAGS | os.O_DIRECTORY))
        for name in parts[:-1]:
            before = os.stat(name, dir_fd=originals[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode), "ancestor-type")
            opened = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=originals[-1])
            originals.append(opened)
            need(signature(os.fstat(opened)) == signature(before), "ancestor-changed")
        yield originals[-1], parts[-1]
    finally:
        unknown = False
        for fd in reversed(originals):
            try:
                close_once(fd)
            except Refused:
                unknown = True
        need(not unknown, "ancestor-close-unknown")


def no_xattrs(fd):
    # CPython's os xattr helpers are not portable to every Darwin build. This
    # fixed read-only system ABI is for the nonroot DATA stager only. The root
    # installer independently checks the actual staged originals in native C.
    global _DARWIN_XATTRS
    if sys.platform == "darwin":
        if _DARWIN_XATTRS is None:
            import ctypes
            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            call = library.flistxattr
            call.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            call.restype = ctypes.c_ssize_t
            _DARWIN_XATTRS = call
        need(_DARWIN_XATTRS(fd, None, 0, 0) == 0, "file-extended-attributes")
    elif sys.platform == "linux":
        need(not os.listxattr(fd), "file-extended-attributes")
    else:
        raise Refused("unsupported-data-host")


def read_at(fd, name, limit):
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit, "ordinary-file-bound")
    original = os.open(name, READ_FLAGS, dir_fd=fd)
    try:
        need(signature(os.fstat(original)) == signature(before), "file-open-changed")
        no_xattrs(original)
        data = bytearray()
        while len(data) <= limit:
            block = os.read(original, min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        need(len(data) == before.st_size and signature(os.fstat(original)) == signature(before)
             and signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == signature(before), "file-read-changed")
        return bytes(data), before
    finally:
        close_once(original)


def read(path, limit=MAX_BYTES):
    with parent(path) as (fd, name):
        return read_at(fd, name, limit)[0]


def directories(files):
    result = set()
    for path in files:
        bits = path.split("/")
        result.update("/".join(bits[:i]) for i in range(1, len(bits)))
    need(len(result) <= 2048, "directory-count")
    folded = set()
    for name in set(files) | result:
        need(safe_path(name) and name.lower() not in folded, "path-alias-or-type-collision")
        folded.add(name.lower())
    need(not (set(files) & result), "file-directory-collision")
    return result


def packager_ids():
    uid, gid = os.getuid(), os.getgid()
    need(uid != 0 and uid == os.geteuid() and gid == os.getegid(), "packager-identity")
    return uid, gid


def tree(path, *, installed=False, packager=False):
    need(not (installed and packager), "conflicting-tree-owner")
    owner = packager_ids() if packager else None
    found = {}
    observed_directories = set()
    count = total = 0

    def visit(fd, prefix, depth):
        nonlocal count, total
        need(depth <= 16, "tree-depth")
        before = os.fstat(fd)
        if installed:
            need(before.st_uid == 0 and before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o555, "installed-directory-mode-owner")
        if owner is not None:
            need((before.st_uid, before.st_gid) == owner and stat.S_IMODE(before.st_mode) == (0o755 if depth == 0 else 0o555),
                 "packager-directory-mode-owner")
        no_xattrs(fd)
        names = sorted(os.listdir(fd))
        need(len(names) <= MAX_FILES, "directory-entry-bound")
        for name in names:
            relative = prefix + name
            count += 1
            need(count <= 4096 and safe_path(relative), "tree-path-bound")
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                observed_directories.add(relative)
                child = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
                try:
                    need(signature(os.fstat(child)) == signature(info), "tree-directory-changed")
                    visit(child, relative + "/", depth + 1)
                    need(signature(os.fstat(child)) == signature(info)
                         and signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == signature(info), "tree-directory-changed")
                finally:
                    close_once(child)
            else:
                body, info = read_at(fd, name, MAX_BYTES - total)
                total += len(body)
                need(len(found) < MAX_FILES and relative not in found, "tree-file-bound")
                if installed:
                    need(info.st_uid == 0 and info.st_gid == 0, "installed-file-owner")
                if owner is not None:
                    need((info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) in (0o444, 0o555), "packager-file-mode-owner")
                found[relative] = (body, stat.S_IMODE(info.st_mode))
        need(signature(os.fstat(fd)) == signature(before), "tree-root-changed")

    with parent(path) as (fd, name):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode), "tree-root-type")
        root = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
        try:
            need(signature(os.fstat(root)) == signature(before), "tree-root-changed")
            visit(root, "", 0)
            need(signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == signature(before), "tree-root-name-changed")
        finally:
            close_once(root)
    need(observed_directories == directories(found), "tree-unlisted-or-empty-directory")
    return found


def write_tree(output, files, *, root_mode=0o555, app_signing=False):
    need(os.getuid() != 0 and os.getuid() == os.geteuid(), "builder-must-be-nonroot")
    need(0 < len(files) <= MAX_FILES and sum(len(v[0]) for v in files.values()) <= MAX_BYTES, "output-bound")
    dirs = directories(files)
    with parent(output) as (outer, name):
        os.mkdir(name, 0o700, dir_fd=outer)  # Exclusive fresh task output; no cleanup on failure.
        root = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
        try:
            for directory in sorted(dirs, key=lambda p: (p.count("/"), p)):
                with parent(Path(output) / directory) as (fd, leaf):
                    os.mkdir(leaf, 0o700, dir_fd=fd)
            for path, (body, mode) in sorted(files.items()):
                need(mode in ((0o644, 0o755) if app_signing else (0o444, 0o555)), "output-mode")
                with parent(Path(output) / path) as (fd, leaf):
                    opened = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=fd)
                    try:
                        view = memoryview(body)
                        while view:
                            count = os.write(opened, view)
                            need(count > 0, "output-write-zero")
                            view = view[count:]
                        os.fchmod(opened, mode)
                        os.fsync(opened)
                    finally:
                        close_once(opened)
                    actual, info = read_at(fd, leaf, len(body))
                    need(actual == body and stat.S_IMODE(info.st_mode) == mode, "output-readback")
            for directory in sorted(dirs, key=lambda p: (p.count("/"), p), reverse=True):
                with parent(Path(output) / directory) as (fd, leaf):
                    opened = os.open(leaf, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
                    try:
                        os.fchmod(opened, 0o755 if app_signing else 0o555)
                        os.fsync(opened)
                    finally:
                        close_once(opened)
            os.fchmod(root, root_mode)
            os.fsync(root)
            os.fsync(outer)
        finally:
            close_once(root)
    need(tree(output) == files, "complete-output-readback")


def manifest_files(body, expected):
    need(sha(expected) and digest(body) == expected, "runtime-manifest-anchor")
    manifest = decode(body)
    need(type(manifest) is dict and set(manifest) == {"schemaVersion", "protocol", "coreVersion", "target", "coreSha256", "protocolSha256", "inventorySha256", "files"}
         and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1
         and type(manifest["protocol"]) is int and manifest["protocol"] == 1
         and manifest["target"] == "aarch64-apple-darwin" and manifest["protocolSha256"] == PROTOCOL,
         "runtime-manifest-shape")
    rows = manifest["files"]
    need(type(rows) is list and 0 < len(rows) <= MAX_FILES and digest(canonical(rows)) == manifest["inventorySha256"], "runtime-inventory-anchor")
    files = {}
    total = 0
    for row in rows:
        need(type(row) is dict and set(row) == {"path", "sha256", "size"}
             and safe_path(row["path"]) and row["path"] != "manifest.json" and row["path"] not in files
             and sha(row["sha256"]) and type(row["size"]) is int and 0 <= row["size"] <= MAX_BYTES, "runtime-inventory-entry")
        files[row["path"]] = row
        total += row["size"]
    need(list(files) == sorted(files) and total <= MAX_BYTES, "runtime-inventory-order-bound")
    need(BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"} <= set(files)
         and manifest["coreSha256"] == files["core.zip"]["sha256"], "runtime-required-members")
    directories(files)
    return manifest, files


def reused_runtime(archive_path):
    packed = read(archive_path, ZIP_SIZE)
    need(len(packed) == ZIP_SIZE and digest(packed) == ZIP_SHA, "accepted-zip-pin")
    with zipfile.ZipFile(io.BytesIO(packed)) as archive:
        rows = archive.infolist()
        need(len(rows) <= 2048 and len({row.filename for row in rows}) == len(rows), "accepted-zip-roster")
        selected = [row for row in rows if row.filename == "payload.tar"]
        need(len(selected) == 1 and selected[0].file_size == TAR_SIZE and not selected[0].flag_bits & 1, "accepted-tar-member")
        tar = archive.read(selected[0])
    need(len(tar) == TAR_SIZE and digest(tar) == TAR_SHA, "accepted-tar-pin")
    payload = {}
    with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as archive:
        total = 0
        for row in archive:
            need(row.isfile() and row.name.startswith("payload/") and row.uid == 0 and row.gid == 0
                 and 0 <= row.size <= MAX_BYTES and len(payload) < MAX_FILES, "accepted-tar-type-bound")
            name = row.name[len("payload/"):]
            need(safe_path(name) and name not in payload, "accepted-tar-path")
            total += row.size
            need(total <= MAX_BYTES, "accepted-tar-total")
            original = archive.extractfile(row)  # Memory stream only, never extract()/extractall().
            need(original is not None, "accepted-tar-stream")
            with original:
                body = original.read(row.size + 1)
            need(len(body) == row.size, "accepted-tar-size")
            payload[name] = body
    need("manifest.json" in payload, "accepted-manifest-missing")
    manifest, original_rows = manifest_files(payload["manifest.json"], ORIGINAL_MANIFEST)
    need(set(payload) == set(original_rows) | {"manifest.json"}, "accepted-tar-complete-roster")
    for name, row in original_rows.items():
        need(len(payload[name]) == row["size"] and digest(payload[name]) == row["sha256"], "accepted-tar-byte-correspondence")
    for name, (size, expected) in NOTICES.items():
        body = read(DESKTOP / "macos-installed-inputs/notices" / name, size)
        target = "python/licenses/" + name
        need(len(body) == size and digest(body) == expected and target not in payload, "notice-source-pin-or-collision")
        payload[target] = body
    successor = dict(manifest)
    successor["files"] = [{"path": name, "sha256": digest(body), "size": len(body)} for name, body in sorted(payload.items()) if name != "manifest.json"]
    successor["inventorySha256"] = digest(canonical(successor["files"]))
    payload["manifest.json"] = canonical(successor) + b"\n"
    result = {"schemaVersion": 1, "release": RELEASE, "acceptedArchiveSha256": ZIP_SHA, "acceptedTarSha256": TAR_SHA,
              "originalManifestSha256": ORIGINAL_MANIFEST, "successorManifestSha256": digest(payload["manifest.json"]),
              "protocolSha256": PROTOCOL, "unchangedOriginalFileCount": len(original_rows), "addedNotices": sorted(NOTICES),
              "qualification": "description-only-not-build-or-install-authority"}
    return payload, result


def runtime_command(args):
    payload, result = reused_runtime(args.archive)
    if args.command == "runtime":
        need(sha(args.expected_manifest) and result["successorManifestSha256"] == args.expected_manifest, "reviewed-successor-manifest-mismatch")
        files = {name: (body, 0o555 if name == "python/bin/python3" else 0o444) for name, body in payload.items()}
        write_tree(args.output, files)
        result["qualification"] = "reused-bytes-staged-no-native-execution"
    return result


def macho(body):
    need(len(body) >= 32, "macho-header")
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from("<8I", body)
    need(magic == 0xFEEDFACF and cpu == 0x0100000C and subtype == 0 and kind == 2 and count <= 128
         and size <= 65536 and 32 + size <= len(body), "macho-target")
    offset = 32
    minimum = []
    for _ in range(count):
        need(offset + 8 <= 32 + size, "macho-command")
        command, length = struct.unpack_from("<II", body, offset)
        need(length >= 8 and length % 8 == 0 and offset + length <= 32 + size, "macho-command-bound")
        if command == 0x32:
            need(length >= 24, "macho-build-version")
            platform, version = struct.unpack_from("<II", body, offset + 8)
            minimum.append((platform, version))
        offset += length
    need(offset == 32 + size and minimum == [(1, 26 << 16)], "macho-minimum-macos26")


def app_command(args):
    body = read(args.binary)
    macho(body)
    info = read(DESKTOP / "macos-installed-inputs/Info.plist", 16384)
    parsed = plistlib.loads(info)
    need(parsed["CFBundleExecutable"] == "mobile-release-kit-desktop" and parsed["LSMinimumSystemVersion"] == "26.0", "app-info-binding")
    files = {APP_BINARY: (body, 0o755), "Contents/Info.plist": (info, 0o644),
             "Contents/PkgInfo": (b"APPL????", 0o644),
             "Contents/Resources/icon.png": (read(DESKTOP / "src-tauri/icons/icon.png", 1024 * 1024), 0o644)}
    # Native codesign is a SEPARATE fixed workflow command after this returned
    # copy. It may modify the app only; the runtime is not nested in the app.
    # Root/Contents must remain writable to that original codesign writer.
    write_tree(args.output, files, root_mode=0o755, app_signing=True)
    return {"schemaVersion": 1, "appBinarySha256BeforeSigning": digest(body), "qualification": "app-copied-not-signed-or-launched"}


def runtime_tree(root, expected):
    files = tree(root)
    need("manifest.json" in files, "runtime-manifest-missing")
    _, rows = manifest_files(files["manifest.json"][0], expected)
    need(set(files) == set(rows) | {"manifest.json"}, "runtime-complete-roster")
    for name, (body, mode) in files.items():
        need(mode == (0o555 if name == "python/bin/python3" else 0o444), "runtime-mode")
        if name != "manifest.json":
            need(len(body) == rows[name]["size"] and digest(body) == rows[name]["sha256"], "runtime-byte-correspondence")
    return files


def input_command(args):
    runtime = runtime_tree(args.runtime, args.expected_manifest)
    app = tree(args.app)
    need(APP_BINARY in app and "Contents/Info.plist" in app and "Contents/_CodeSignature/CodeResources" in app
         and app["Contents/Info.plist"][0] == read(DESKTOP / "macos-installed-inputs/Info.plist", 16384), "signed-app-roster")
    macho(app[APP_BINARY][0])
    files = {}
    for prefix, source in (("runtime/", runtime), ("app/", app)):
        for name, (body, mode) in source.items():
            need(prefix != "app/" or name.startswith("Contents/"), "app-contents-scope")
            expected_mode = 0o555 if prefix + name in ("app/" + APP_BINARY, "runtime/python/bin/python3") else 0o444
            # codesign may have made its newly created CodeResources 0644. The
            # fresh input copy normalizes modes; it never edits that source.
            need(mode & 0o7022 == 0 and bool(mode & 0o111) == (expected_mode == 0o555), "input-executable-scope")
            files[prefix + name] = (body, expected_mode)
    rows = [{"path": path, "sha256": digest(body), "size": len(body), "executable": mode == 0o555} for path, (body, mode) in sorted(files.items())]
    need(len(rows) <= MAX_FILES - 3, "installer-inventory-bound")
    inventory = canonical({"schemaVersion": 1, "release": RELEASE, "runtimeManifestSha256": args.expected_manifest, "files": rows}) + b"\n"
    decode(inventory)  # Same independent size/node bound the root installer uses.
    files["install-inventory.json"] = (inventory, 0o444)
    write_tree(args.output, files)
    return {"schemaVersion": 1, "inventorySha256": digest(inventory), "runtimeManifestSha256": args.expected_manifest,
            "fileCount": len(rows), "qualification": "fresh-install-input-not-installed"}


def scripts_command(args):
    need(type(args.expected_source) is str and re.fullmatch(r"[0-9a-f]{40}", args.expected_source), "installer-source-binding")
    source = tree(args.input)
    need("install-inventory.json" in source and digest(source["install-inventory.json"][0]) == args.expected_inventory, "installer-input-anchor")
    installer = read(args.installer)
    macho(installer)
    scripts = {"input/" + path: value for path, value in source.items()}
    scripts["mrk-macos-install"] = (installer, 0o555)
    scripts["postinstall"] = (read(DESKTOP / "macos-installed-inputs/postinstall", 8192), 0o555)
    write_tree(args.output, scripts, root_mode=0o755)
    return {"schemaVersion": 1, "installerSha256": digest(installer), "inventorySha256": args.expected_inventory,
            "sourceCommit": args.expected_source, "packageIdentifier": PACKAGE_ID + ("-fixture" if args.fixture else ""),
            "qualification": "scripts-only-input-must-pass-package-archive-audit"}


def inflate(body, limit, *, gzip=False):
    stream = zlib.decompressobj(31 if gzip else 15)
    output = stream.decompress(body, limit + 1)
    need(len(output) <= limit and not stream.unconsumed_tail and stream.eof and not stream.unused_data, "compressed-data-bound")
    return output


def xar_members(body):
    need(len(body) >= 28, "xar-header")
    magic, header, version, compressed, expanded, checksum = struct.unpack_from(">IHHQQI", body)
    need(magic == 0x78617221 and header == 28 and version == 1 and compressed <= 1024 * 1024
         and expanded <= 2 * 1024 * 1024 and header + compressed <= len(body), "xar-header-bound")
    toc_bytes = inflate(body[header:header + compressed], expanded)
    need(len(toc_bytes) == expanded, "xar-toc-size")
    toc = ET.fromstring(toc_bytes)
    need(toc.tag == "xar" and len(toc.findall("toc")) == 1, "xar-toc")
    result = {}
    for member in toc.findall("toc/file"):
        name = member.findtext("name")
        need(name in ("Bom", "PackageInfo", "Scripts") and name not in result and member.findtext("type") == "file"
             and not member.findall("file"), "scripts-only-package-no-payload")
        length, offset, size = (member.findtext("data/" + key) for key in ("length", "offset", "size"))
        need(all(v is not None and re.fullmatch(r"[0-9]{1,10}", v) for v in (length, offset, size)), "xar-member-bound")
        length, offset, size = int(length), int(offset), int(size)
        start = header + compressed + offset
        need(length <= MAX_BYTES and size <= MAX_BYTES and start + length <= len(body), "xar-member-bound")
        packed = body[start:start + length]
        encoding = member.find("data/encoding")
        need(encoding is not None and encoding.get("style") in ("application/octet-stream", "application/x-gzip"), "xar-member-encoding")
        unpacked = packed if encoding.get("style") == "application/octet-stream" else inflate(packed, size, gzip=packed[:2] == b"\x1f\x8b")
        need(len(unpacked) == size, "xar-member-size")
        result[name] = unpacked
    need({"PackageInfo", "Scripts"} <= set(result), "scripts-package-required")
    return result


def _cpio_members(body, owner):
    # The only nonzero owner caller is original-package PREPARATION below.
    # Public cpio_members and final package acceptance are always fixed0:0.
    need(len(body) <= MAX_BYTES, "scripts-archive-bound")
    entries = {}
    root_seen = False
    offset = 0
    for _ in range(4098):
        start = offset
        magic = body[start:start + 6]
        if magic == b"070707":
            widths = [6, 6, 6, 6, 6, 6, 6, 11, 6, 11]
            cursor = start + 6
            values = []
            for width in widths:
                raw = body[cursor:cursor + width]
                need(len(raw) == width and re.fullmatch(b"[0-7]+", raw) is not None, "odc-header")
                values.append(int(raw, 8))
                cursor += width
            dev, ino, mode, uid, gid, links, rdev, mtime, namesize, size = values
            name_start = cursor
            align = 1
        elif magic == b"070701":
            need(start + 110 <= len(body), "newc-header")
            raw = body[start + 6:start + 110]
            need(re.fullmatch(b"[0-9a-fA-F]+", raw) is not None, "newc-header")
            values = [int(raw[i:i + 8], 16) for i in range(0, len(raw), 8)]
            ino, mode, uid, gid, links, mtime, size, devmaj, devmin, rdevmaj, rdevmin, namesize, check = values
            name_start = start + 110
            align = 4
        else:
            raise Refused("unsupported-scripts-cpio-format")
        need(1 <= namesize <= 1025 and size <= MAX_BYTES and name_start + namesize <= len(body), "cpio-entry-bound")
        name_bytes = body[name_start:name_start + namesize]
        need(name_bytes[-1:] == b"\0" and b"\0" not in name_bytes[:-1], "cpio-name")
        name = name_bytes[:-1].decode("ascii")
        data_start = (name_start + namesize + align - 1) // align * align
        offset = (data_start + size + align - 1) // align * align
        need(offset <= len(body), "cpio-data-bound")
        if name == "TRAILER!!!":
            need(size == 0 and not any(body[offset:]), "cpio-trailer")
            need(root_seen, "scripts-root-required")
            return entries
        if name in (".", "./"):
            need(not root_seen, "scripts-root-duplicate")
            need(stat.S_ISDIR(mode) and (uid, gid) == owner and stat.S_IMODE(mode) == 0o755 and size == 0, "scripts-root-owner-mode")
            root_seen = True
            continue
        if name.startswith("./"):
            name = name[2:]
        need(safe_path(name) and name not in entries and (uid, gid) == owner, "scripts-entry-owner")
        if stat.S_ISDIR(mode):
            need(size == 0 and stat.S_IMODE(mode) == 0o555, "scripts-directory-mode")
            entries[name] = (None, 0o555)
        else:
            need(stat.S_ISREG(mode) and links == 1 and stat.S_IMODE(mode) in (0o444, 0o555), "scripts-file-type-mode")
            entries[name] = (body[data_start:data_start + size], stat.S_IMODE(mode))
    raise Refused("scripts-entry-count")


def cpio_members(body):
    return _cpio_members(body, (0, 0))


def package_info(body, *, fixture=False):
    need(type(fixture) is bool, "fixed-package-kind")
    identifier = PACKAGE_ID + ("-fixture" if fixture else "")
    info = ET.fromstring(body)
    need(info.tag == "pkg-info" and info.get("identifier") == identifier
         and info.get("version") == "0.1.0" and info.get("install-location") == "/" and info.get("auth") == "root", "scripts-package-identity")
    payload = info.find("payload")
    need(payload is None or payload.get("numberOfFiles") == "0", "installer-must-have-no-payload")
    hooks = info.find("scripts")
    need(hooks is not None and [child.tag for child in hooks] == ["postinstall"], "no-other-package-hooks")
    post = info.findall("scripts/postinstall")
    need(len(post) == 1 and post[0].get("file") in ("./postinstall", "postinstall"), "fixed-postinstall")
    return identifier


def original_package(scripts_path, package_path, *, fixture=False):
    owner = packager_ids()
    scripts = tree(scripts_path, packager=True)
    with parent(package_path) as (fd, name):
        package, info = read_at(fd, name, MAX_BYTES)
        need((info.st_uid, info.st_gid) == owner, "original-package-owner")
    members = xar_members(package)
    need(set(members) == {"PackageInfo", "Scripts"}, "original-package-roster")
    identifier = package_info(members["PackageInfo"], fixture=fixture)
    archive = members["Scripts"]
    if archive[:2] == b"\x1f\x8b":
        archive = inflate(archive, MAX_BYTES, gzip=True)
    actual = _cpio_members(archive, owner)
    expected = {**scripts, **{name: (None, 0o555) for name in directories(scripts)}}
    need(actual == expected, "complete-original-scripts-correspondence")
    return scripts, package, members, identifier, owner


def prepare_package_command(args):
    scripts, package, members, identifier, owner = original_package(args.scripts, args.package, fixture=args.fixture)
    # This is not archive extraction: only validated, unchanged PackageInfo
    # DATA is copied to a fixed literal name in an exclusively-created root.
    write_tree(args.output, {"PackageInfo": (members["PackageInfo"], 0o444)}, root_mode=0o700)
    return {"schemaVersion": 1, "originalPackageSha256": digest(package), "originalPackageSize": len(package),
            "packageInfoSha256": digest(members["PackageInfo"]), "packageIdentifier": identifier,
            "scriptFileCount": len(scripts), "packagerUid": owner[0], "packagerGid": owner[1],
            "qualification": "caller-owned-original-prepared-not-root-audited-or-installed"}


def package_format_input_command(args):
    files = {"input/readonly.txt": (b"MRK_MACOS_PACKAGE_FORMAT_DATA\n", 0o444),
             "postinstall": (b"#!/bin/sh\n# Inert archive-format input; never execute.\nexit 97\n", 0o555)}
    write_tree(args.output, files, root_mode=0o755)
    return {"schemaVersion": 1, "scriptFileCount": len(files), "qualification": "tiny-inert-package-format-input-never-execute"}


def audit_command(args):
    scripts, original, original_members, identifier, _owner = original_package(args.scripts, args.original_package, fixture=args.fixture)
    package = read(args.package)
    members = xar_members(package)
    need(set(members) == {"PackageInfo", "Scripts"}, "final-package-roster")
    need(members["PackageInfo"] == original_members["PackageInfo"], "package-info-bytes-changed")
    package_info(members["PackageInfo"], fixture=args.fixture)
    archive = members["Scripts"]
    if archive[:2] == b"\x1f\x8b":
        archive = inflate(archive, MAX_BYTES, gzip=True)
    actual = cpio_members(archive)
    expected = {**scripts, **{name: (None, 0o555) for name in directories(scripts)}}
    need(actual == expected, "complete-root-owned-scripts-correspondence")
    return {"schemaVersion": 1, "packageSha256": digest(package), "packageSize": len(package),
            "originalPackageSha256": digest(original), "packageInfoSha256": digest(members["PackageInfo"]),
            "packageIdentifier": identifier, "scriptFileCount": len(scripts), "finalDestinationPayloadEntries": 0,
            "qualification": "scripts-only-package-audited-not-installed-or-GUI-qualified"}


def observation_inventory(args):
    body = read(Path(args.input) / "install-inventory.json", 1024 * 1024)
    need(sha(args.expected_inventory) and sha(args.expected_manifest) and digest(body) == args.expected_inventory, "observation-inventory-anchor")
    inventory = decode(body)
    need(type(inventory) is dict and set(inventory) == {"schemaVersion", "release", "runtimeManifestSha256", "files"}
         and type(inventory["schemaVersion"]) is int and inventory["schemaVersion"] == 1
         and inventory["release"] == RELEASE and inventory["runtimeManifestSha256"] == args.expected_manifest
         and type(inventory["files"]) is list and 0 < len(inventory["files"]) <= MAX_FILES, "observation-inventory-shape")
    rows = {}
    for row in inventory["files"]:
        need(type(row) is dict and set(row) == {"path", "sha256", "size", "executable"}
             and safe_path(row["path"]) and row["path"].startswith(("app/Contents/", "runtime/")) and row["path"] not in rows
             and sha(row["sha256"]) and type(row["size"]) is int and 0 <= row["size"] <= MAX_BYTES
             and type(row["executable"]) is bool
             and row["executable"] == (row["path"] in ("app/" + APP_BINARY, "runtime/python/bin/python3")), "observation-inventory-row")
        rows[row["path"]] = row
    need(list(rows) == sorted(rows) and sum(row["size"] for row in rows.values()) <= MAX_BYTES
         and {"app/" + APP_BINARY, "app/Contents/Info.plist", "runtime/python/bin/python3", "runtime/manifest.json"} <= set(rows)
         and rows["runtime/manifest.json"]["sha256"] == args.expected_manifest, "observation-inventory-required")
    directories(rows)
    return rows


def installer_log_binding(args):
    need(type(args.fixture) is bool and type(args.expected_source) is str
         and re.fullmatch(r"[0-9a-f]{40}", args.expected_source)
         and sha(args.expected_inventory) and sha(args.expected_manifest)
         and type(args.run_id) is str and re.fullmatch(r"[1-9][0-9]{0,23}", args.run_id)
         and type(args.run_attempt) is str and re.fullmatch(r"[1-9][0-9]{0,5}", args.run_attempt), "log-input-binding")
    package = os.fspath(args.package)
    basename = "MobileReleaseKit-InstallerFixture.pkg" if args.fixture else "MobileReleaseKit.pkg"
    dirname = "package-fixture-final" if args.fixture else "package-final"
    need(type(package) is str and package.startswith("/") and len(os.fsencode(package)) <= 4096
         and all(ord(c) >= 32 and ord(c) != 127 for c in package)
         and all(part and part not in (".", "..") for part in package.split("/")[1:])
         and package.split("/")[-2:] == [dirname, basename], "log-input-binding")
    return {"packageKind": "fixture" if args.fixture else "ordinary", "packageIdentifier": PACKAGE_ID + ("-fixture" if args.fixture else ""),
            "packagePath": package, "sourceCommit": args.expected_source, "inventorySha256": args.expected_inventory,
            "runtimeManifestSha256": args.expected_manifest, "runId": args.run_id, "runAttempt": args.run_attempt}


def installer_log_identity(info):
    identity = {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
                "uid": info.st_uid, "gid": info.st_gid, "links": info.st_nlink}
    validate_log_identity(identity)
    return identity


def validate_log_identity(identity):
    need(type(identity) is dict and set(identity) == {"device", "inode", "mode", "uid", "gid", "links"}
         and all(type(value) is int and value >= 0 for value in identity.values())
         and identity["inode"] > 0 and stat.S_ISREG(identity["mode"]) and identity["uid"] == 0
         and identity["links"] == 1 and identity["mode"] & 0o022 == 0, "log-file-policy")


@contextlib.contextmanager
def installer_log_file():
    # A fresh nonroot read of the one fixed physical path, not an original FD
    # held across Installer and not permission to inspect rotated/other logs.
    with parent(INSTALL_LOG) as (outer, name):
        named = installer_log_identity(os.stat(name, dir_fd=outer, follow_symlinks=False))
        original = os.open(name, READ_FLAGS, dir_fd=outer)
        try:
            info = os.fstat(original)
            need(installer_log_identity(info) == named, "log-file-identity")
            yield original, outer, name, info
        finally:
            close_once(original)


def positioned_log_read(fd, offset, size):
    need(type(offset) is int and offset >= 0 and type(size) is int and 0 <= size <= LOG_INTERVAL_BYTES, "log-interval-bound")
    body = bytearray()
    while len(body) < size:
        block = os.pread(fd, min(65536, size - len(body)), offset + len(body))
        need(bool(block), "log-read-incomplete")
        body.extend(block)
    return bytes(body)


def log_growth(fd, outer, name, identity, end):
    current = os.fstat(fd)
    named = os.stat(name, dir_fd=outer, follow_symlinks=False)
    need(installer_log_identity(current) == installer_log_identity(named) == identity, "log-file-identity")
    need(current.st_size >= end and named.st_size >= current.st_size, "log-truncated")
    return named.st_size - end


def make_log_cursor(binding, identity, offset, tail, growth):
    need(type(offset) is int and 0 <= offset < 2 ** 63
         and type(tail) is bytes and len(tail) == min(offset, LOG_TAIL_BYTES), "log-cursor-offset")
    need(not offset or tail.endswith(b"\n"), "log-incomplete-boundary")
    cursor = {"schemaVersion": 1, "kind": "installer-log-cursor", "state": "observed", "binding": binding,
              "logPath": str(INSTALL_LOG), "identity": identity, "offsetBytes": offset,
              "precedingTailBytes": len(tail), "precedingTailSha256": digest(tail),
              "growthBeyondSnapshotBytes": growth, "authority": LOG_AUTHORITY}
    validate_log_cursor(cursor, binding)
    return cursor


def validate_log_cursor(cursor, binding):
    need(type(cursor) is dict and set(cursor) == {"schemaVersion", "kind", "state", "binding", "logPath", "identity",
         "offsetBytes", "precedingTailBytes", "precedingTailSha256", "growthBeyondSnapshotBytes", "authority"}
         and type(cursor["schemaVersion"]) is int and cursor["schemaVersion"] == 1
         and cursor["kind"] == "installer-log-cursor" and cursor["state"] == "observed"
         and cursor["logPath"] == str(INSTALL_LOG) and cursor["authority"] == LOG_AUTHORITY, "log-cursor-shape")
    need(cursor["binding"] == binding, "log-cursor-binding")
    validate_log_identity(cursor["identity"])
    offset = cursor["offsetBytes"]
    need(type(offset) is int and 0 <= offset < 2 ** 63 and type(cursor["precedingTailBytes"]) is int
         and cursor["precedingTailBytes"] == min(offset, LOG_TAIL_BYTES) and sha(cursor["precedingTailSha256"])
         and (offset != 0 or cursor["precedingTailSha256"] == digest(b""))
         and type(cursor["growthBeyondSnapshotBytes"]) is int and 0 <= cursor["growthBeyondSnapshotBytes"] < 2 ** 63, "log-cursor-offset")
    return cursor


def validate_log_window(cursor, identity, end, anchor, body):
    need(identity == cursor["identity"], "log-file-identity")
    need(type(end) is int and end >= cursor["offsetBytes"], "log-truncated")
    size = end - cursor["offsetBytes"]
    need(0 <= size <= LOG_INTERVAL_BYTES, "log-interval-bound")
    need(type(anchor) is bytes and len(anchor) == cursor["precedingTailBytes"]
         and digest(anchor) == cursor["precedingTailSha256"], "log-anchor-rewritten")
    need(type(body) is bytes and len(body) == size, "log-read-incomplete")
    need((not anchor or anchor.endswith(b"\n")) and (not body or body.endswith(b"\n")), "log-incomplete-boundary")


def select_installer_log(body, binding):
    # Byte-preserving diagnostic selection only. No PID attribution, JSON result
    # decoding, convenient-record choice, or acceptance/finality implication.
    need(type(body) is bytes and len(body) <= LOG_INTERVAL_BYTES, "log-interval-bound")
    need(not body or body.endswith(b"\n"), "log-incomplete-boundary")
    def token(value, path=False):
        chars = rb"A-Za-z0-9._+~%/-" if path else rb"A-Za-z0-9._+-"
        return re.compile(rb"(?<![" + chars + rb"])" + re.escape(value) + rb"(?![" + chars + rb"])")
    patterns = {
        "package-identifier": token(binding["packageIdentifier"].encode()),
        "package-path": token(binding["packagePath"].encode(), path=True),
        "native-executable": token(b"mrk-macos-install"),
        "fixture-result": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_FIXTURE_RESULT="),
        "ordinary-result": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_RESULT="),
        "postinstall-phase": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_PHASE=(?:entry|target-ok|relative-entry|absolute-entry|cwd-ok|pre-exec)(?![A-Za-z0-9_-])"),
        "postinstall-refusal": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_REFUSED=(?:target|entry|cwd)(?![A-Za-z0-9_-])"),
        "acl-diagnostic": re.compile(
            rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role="
            rb"(?:input-directory|input-inventory|system-root|system-library|system-support|other-protected-object);phase="
            rb"(?:filesec-allocation|fstatx-snapshot|snapshot-owner|snapshot-group|snapshot-mode|acl-presence|acl-conversion|"
            rb"acl-object|acl-validation|acl-first-entry|acl-entry-present|acl-free|ffi-output)"
            rb";result=-?[0-9]{1,10};call=-?[0-9]{1,10};errno=-?[0-9]{1,10};freeCall=-?[0-9]{1,10};freeErrno=-?[0-9]{1,10}(?=\r?\n$)"),
    }
    counts = {key: 0 for key in patterns}
    selected = bytearray()
    rows = []
    offset = 0
    total = 0
    for line in body.splitlines(keepends=True):
        need(line.endswith(b"\n") and len(line) <= LOG_LINE_BYTES, "log-line-bound")
        matches = {key: sum(1 for _ in pattern.finditer(line)) for key, pattern in patterns.items()}
        anchors = [key for key, count in matches.items() if count]
        for key, count in matches.items():
            counts[key] += count
        if anchors:
            need(len(selected) + len(line) <= LOG_SELECTED_BYTES, "log-selected-bound")
            rows.append({"relativeOffsetBytes": offset, "retainedOffsetBytes": len(selected), "bytes": len(line),
                         "sha256": digest(line), "anchors": anchors})
            selected.extend(line)
        offset += len(line)
        total += 1
    need(bool(selected), "log-no-project-lines")
    wanted = "fixture-result" if binding["packageKind"] == "fixture" else "ordinary-result"
    other = "ordinary-result" if wanted == "fixture-result" else "fixture-result"
    state = "mixed" if counts[other] else "duplicate" if counts[wanted] > 1 else "unbound" if counts[wanted] == 1 else "missing"
    return bytes(selected), {"linesObserved": total, "linesUnselected": total - len(rows), "selectedLines": rows,
                             "markerCounts": counts, "resultMarkerState": state}


def write_log_selection(path, body):
    need(type(body) is bytes and 0 < len(body) <= LOG_SELECTED_BYTES, "log-selected-bound")
    with parent(path) as (outer, name):
        original = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=outer)
        try:
            offset = 0
            while offset < len(body):
                written = os.write(original, body[offset:])
                need(written > 0, "log-output-readback")
                offset += written
            os.fsync(original)
            info = os.fstat(original)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(body)
                 and positioned_log_read(original, 0, len(body)) == body
                 and signature(os.fstat(original)) == signature(info)
                 and signature(os.stat(name, dir_fd=outer, follow_symlinks=False)) == signature(info), "log-output-readback")
        finally:
            close_once(original)


def installer_log_diagnostic(args):
    binding = None
    phase = "input"
    planned_selection = None
    try:
        binding = installer_log_binding(args)
        if args.command == "installer-log-cursor":
            with installer_log_file() as (fd, outer, name, info):
                identity = installer_log_identity(info)
                tail_size = min(info.st_size, LOG_TAIL_BYTES)
                tail = positioned_log_read(fd, info.st_size - tail_size, tail_size)
                need(positioned_log_read(fd, info.st_size - tail_size, tail_size) == tail, "log-anchor-rewritten")
                growth = log_growth(fd, outer, name, identity, info.st_size)
                result = make_log_cursor(binding, identity, info.st_size, tail, growth)
            need(len(canonical(result)) <= 16383, "log-metadata-bound")
            return result, 0
        with parent(args.cursor) as (outer, name):
            cursor_bytes, info = read_at(outer, name, 16384)
            need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, "log-cursor-shape")
        cursor = validate_log_cursor(decode(cursor_bytes), binding)
        phase = "capture"
        with installer_log_file() as (fd, outer, name, info):
            identity = installer_log_identity(info)
            need(identity == cursor["identity"], "log-file-identity")
            start, end = cursor["offsetBytes"], info.st_size
            need(end >= start, "log-truncated")
            need(end - start <= LOG_INTERVAL_BYTES, "log-interval-bound")
            anchor = positioned_log_read(fd, start - cursor["precedingTailBytes"], cursor["precedingTailBytes"])
            body = positioned_log_read(fd, start, end - start)
            validate_log_window(cursor, identity, end, anchor, body)
            need(positioned_log_read(fd, start - len(anchor), len(anchor)) == anchor, "log-anchor-rewritten")
            growth = log_growth(fd, outer, name, identity, end)
        selected, selection = select_installer_log(body, binding)
        result = {"schemaVersion": 1, "kind": "installer-log-capture", "state": "observed-project-correlated",
                  "binding": binding, "logPath": str(INSTALL_LOG), "identity": identity, "cursorSha256": digest(cursor_bytes),
                  "startOffsetBytes": start, "endOffsetBytes": end, "growthBeyondSnapshotBytes": growth,
                  "intervalBytes": len(body), "intervalSha256": digest(body), **selection,
                  "selectedData": {"file": Path(args.selected_output).name, "bytes": len(selected), "sha256": digest(selected)},
                  "authority": LOG_AUTHORITY, "scriptOutputFinality": "unestablished"}
        need(len(canonical(result)) < LOG_METADATA_BYTES, "log-metadata-bound")
        phase = "output"
        planned_selection = result["selectedData"]
        write_log_selection(args.selected_output, selected)
        return result, 0
    except (Refused, OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as error:
        reason = "log-output-unavailable" if phase == "output" else "log-input-or-capture-unavailable"
        if type(error) is Refused and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in LOG_REFUSALS:
            reason = error.args[0]
        return {"schemaVersion": 1, "kind": args.command, "state": "unknown", "reason": reason,
                "binding": binding, "authority": LOG_AUTHORITY, "scriptOutputFinality": "unestablished",
                "plannedSelectedData": planned_selection,
                "selectedOutputState": "write-or-close-unknown-preserve-original" if phase == "output" else "not-created"}, 1


def installer_record(log, *, fixture=False):
    marker = b"MRK_MACOS_INSTALL_FIXTURE_RESULT=" if fixture else b"MRK_MACOS_INSTALL_RESULT="
    other = b"MRK_MACOS_INSTALL_RESULT=" if fixture else b"MRK_MACOS_INSTALL_FIXTURE_RESULT="
    need(other not in log, "separate-installer-outcomes-required")
    records = [decode(line.split(marker, 1)[1]) for line in log.splitlines() if marker in line]
    need(len(records) == 1 and type(records[0]) is dict, "original-installer-result-missing-or-duplicate")
    return records[0]


def installer_result_path(source, inventory, manifest, *, fixture=False):
    need(type(fixture) is bool and type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and sha(inventory) and sha(manifest), "installer-export-binding")
    kind = "fixture" if fixture else "ordinary"
    name = "MobileReleaseKit-InstallerResult-v1-" + kind + "-" + source + "-" + inventory + "-" + manifest + ".json"
    need(name.isascii() and len(name) <= 255, "installer-export-name")
    return INSTALL_ROOT.parent / name


def installer_parent_identity(info):
    # Exclude unrelated child timestamps/link counts; preserve original object,
    # protection and named/FD correspondence throughout this one read interval.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


@contextlib.contextmanager
def installer_channel_parent(path, *, private=None):
    """Only the fixed export parent or original task's private status parent."""
    path = Path(path)
    need(path.is_absolute() and len(os.fsencode(path)) <= 4096 and path.parent == (INSTALL_ROOT.parent if private is None else private),
         "installer-channel-path")
    parts = os.fspath(path).split("/")[1:]
    need(1 < len(parts) <= 40 and all(p and p not in (".", "..") and len(os.fsencode(p)) <= 255 for p in parts), "installer-channel-spelling")
    uid, _gid = packager_ids()
    originals = []
    try:
        for index, name in enumerate(("/", *parts[:-1])):
            outer = originals[-1][0] if originals else None
            before = os.stat(name, dir_fd=outer, follow_symlinks=False)
            task_parent = private is not None and index == len(parts) - 1
            need(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o7022
                 and before.st_uid in ((0, uid) if private is not None else (0,))
                 and (not task_parent or before.st_uid == uid and stat.S_IMODE(before.st_mode) == 0o700),
                 "installer-channel-parent-protection")
            original = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
            originals.append((original, outer, name, installer_parent_identity(before)))
            need(installer_parent_identity(os.fstat(original)) == originals[-1][3]
                 and installer_parent_identity(os.stat(name, dir_fd=outer, follow_symlinks=False)) == originals[-1][3],
                 "installer-channel-parent-changed")
        yield originals[-1][0], parts[-1]
        for original, outer, name, identity in originals:
            need(installer_parent_identity(os.fstat(original)) == identity
                 and installer_parent_identity(os.stat(name, dir_fd=outer, follow_symlinks=False)) == identity,
                 "installer-channel-parent-changed")
    finally:
        active = sys.exc_info()[0] is not None
        unknown = False
        for original, _outer, _name, _identity in reversed(originals):
            try:
                close_once(original)
            except Refused:
                unknown = True
        if unknown and not active:
            raise Refused("installer-channel-parent-close-unknown")


def installer_result_absent_command(args):
    path = installer_result_path(args.expected_source, args.expected_inventory, args.expected_manifest, fixture=args.fixture)
    with installer_channel_parent(path) as (fd, name):
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError as error:
            need(error.errno == errno.ENOENT, "installer-export-absence-unknown")
        else:
            raise Refused("installer-export-name-occupied")
    return {"schemaVersion": 1, "kind": "fixture" if args.fixture else "ordinary", "state": "expected-result-name-absent",
            "sourceCommit": args.expected_source, "inventorySha256": args.expected_inventory, "runtimeManifestSha256": args.expected_manifest}


def installer_success_status(args, *, fixture=False):
    work = Path(args.input).parent
    expected = work / ("installer-fixture-output.status" if fixture else "installer-output.status")
    need(Path(args.input) == work / "input" and Path(args.installer_status) == expected, "installer-status-original-path")
    uid, _gid = packager_ids()
    with installer_channel_parent(expected, private=work) as (fd, name):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == 2, "installer-status-private-original")
        body, actual = read_at(fd, name, 2)
        need(signature(actual) == signature(before) and body == b"0\n", "installer-status-not-original-zero")


def installer_result_document(body, source, inventory, manifest, *, fixture=False):
    installer_result_path(source, inventory, manifest, fixture=fixture)  # Validate expected anchors, not document authority.
    need(type(body) is bytes and 0 < len(body) <= INSTALLER_RESULT_BYTES and body.endswith(b"\n"), "installer-export-byte-bound")
    document = decode(body.decode("utf-8"))  # Do not admit json.loads bytes auto-detected UTF-16/32.
    need(type(document) is dict and set(document) == {"schemaVersion", "kind", "sourceCommit", "inventorySha256",
         "runtimeManifestSha256", "transportState", "result"} and type(document["schemaVersion"]) is int and document["schemaVersion"] == 1
         and document["kind"] == ("fixture" if fixture else "ordinary") and document["sourceCommit"] == source
         and document["inventorySha256"] == inventory and document["runtimeManifestSha256"] == manifest
         and document["transportState"] == INSTALLER_RESULT_STATE and type(document["result"]) is dict, "installer-export-closed-binding")
    return document["result"]


def installer_result_readback(args, *, fixture=False):
    # Saved same-run Installer0 is an independent gate, not a durable journal or
    # something the pending export/diagnostic channel can certify about itself.
    installer_success_status(args, fixture=fixture)
    path = installer_result_path(args.expected_source, args.expected_inventory, args.expected_manifest, fixture=fixture)
    with installer_channel_parent(path) as (fd, name):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o444 and 0 < before.st_size <= INSTALLER_RESULT_BYTES, "installer-export-file-policy")
        body, actual = read_at(fd, name, INSTALLER_RESULT_BYTES)
        need(signature(actual) == signature(before), "installer-export-file-changed")
        result = installer_result_document(body, args.expected_source, args.expected_inventory, args.expected_manifest, fixture=fixture)
    # Both the leaf and all parent originals have actually closed before DATA
    # can be returned. No private staging, log, alternate leaf or sudo reader.
    return result, {"bytes": len(body), "sha256": digest(body), "identity": list(signature(actual)),
                    "finalityBasis": "original-successful-Installer-return-and-checked-readback"}


def bound_original_result(result, expected, source, inventory, manifest):
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source) and sha(inventory) and sha(manifest), "original-result-input-binding")
    reason, runtime, app, state, verified, _exit = expected
    need(type(result) is dict and set(result) == {"schemaVersion", "state", "reason", "release", "runtimePublication", "appPublication",
         "staging", "payloadVerified", "payloadWritersSettled", "originalsSettled", "deadlineMetAfterFinalCloses", "createdAncestors",
         "cleanup", "sourceCommit", "inventorySha256", "runtimeManifestSha256"}, "original-result-closed-shape")
    need(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1 and result["release"] == RELEASE
         and result["sourceCommit"] == source and result["inventorySha256"] == inventory and result["runtimeManifestSha256"] == manifest
         and result["state"] == state and result["reason"] == reason and result["runtimePublication"] == runtime and result["appPublication"] == app
         and result["payloadVerified"] is verified and result["payloadWritersSettled"] is True and result["originalsSettled"] is True
         and result["deadlineMetAfterFinalCloses"] is True and result["cleanup"] == "original-closes-only-no-deletion", "original-installer-not-settled-bound-timely")
    stage = result["staging"]
    need(stage is None or type(stage) is str and re.fullmatch(r"\.install-[0-9a-f]{32}", stage), "original-staging-name")
    need(type(result["createdAncestors"]) is list and len(result["createdAncestors"]) <= 4, "original-created-ancestors")
    for row in result["createdAncestors"]:
        need(type(row) is dict and set(row) == {"name", "state", "parentOriginal", "object"} and type(row["name"]) is str
             and (row["name"] in ("MobileReleaseKit", "versions", RELEASE) or row["name"] == stage)
             and row["state"] in ("created", "existing-not-modified") and type(row["parentOriginal"]) is int
             and 0 <= row["parentOriginal"] < 24576 and type(row["object"]) is dict and set(row["object"]) == {"device", "inode"}
             and all(type(value) is int for value in row["object"].values()) and row["object"]["inode"] > 0, "original-created-ancestor")


def byte_correspondence(actual, expected):
    need(set(actual) == set(expected), "installed-complete-roster")
    for name, (body, mode) in actual.items():
        row = expected[name]
        need(len(body) == row["size"] and digest(body) == row["sha256"] and mode == (0o555 if row["executable"] else 0o444), "installed-byte-mode-correspondence")


def observation_command(args):
    expected = observation_inventory(args)
    result, exported = installer_result_readback(args)
    bound_original_result(result, (None, "confirmed", "confirmed", "installed", True, 0),
                          args.expected_source, args.expected_inventory, args.expected_manifest)
    need(result["staging"] is not None, "installed-original-staging-missing")
    app = tree(INSTALL_ROOT / APP_NAME, installed=True)
    runtime = tree(INSTALL_ROOT / "versions" / RELEASE / "runtime", installed=True)
    actual = {"app/" + name: value for name, value in app.items()}
    actual.update({"runtime/" + name: value for name, value in runtime.items()})
    byte_correspondence(actual, expected)
    return {"schemaVersion": 1, "sourceCommit": args.expected_source, "inventorySha256": args.expected_inventory,
            "runtimeManifestSha256": args.expected_manifest, "release": RELEASE, "installerDeadlineMetAfterFinalCloses": True,
            "installerReportedOriginalsSettled": True, "nonrootReadbackFileCount": len(actual),
            "originalInstallerResult": result, "installerResultExport": exported,
            "applicationLaunched": False, "guiSaveQualified": False, "aquaGate": "required-separate-actual-session",
            "qualification": "engineering-install-observed-not-runtime-or-GUI-acceptance"}


def visible_occupant(case):
    if case in ("occupied-app", "first-publication-second-refusal"):
        return APP_NAME + "/occupied.txt"
    if case in ("occupied-release", "runtime-publication-collision"):
        return "versions/" + RELEASE + "/runtime/occupied.txt"
    return None


def fixture_record(log, source, inventory, manifest):
    # Legacy marker parser is diagnostic/test-only, never readback authority.
    return bound_fixture_result(installer_record(log, fixture=True), source, inventory, manifest)


def bound_fixture_result(result, source, inventory, manifest):
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source) and sha(inventory) and sha(manifest), "fixture-input-binding")
    need(type(result) is dict and set(result) == {"schemaVersion", "sourceCommit", "inventorySha256", "runtimeManifestSha256", "fixtureBase", "setupError",
         "setupOriginalsSettled", "setupDeadlineMet", "inertCloseDeadlinePolicyTable", "fixedCasesComplete", "passed", "cases",
         "genuineConcurrentRaceObserved", "nativeCloseFailureInjected", "applicationLaunched", "guiSaveQualified", "qualification"}, "fixture-closed-shape")
    need(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1 and result["sourceCommit"] == source
         and result["inventorySha256"] == inventory and result["runtimeManifestSha256"] == manifest and result["setupError"] is None
         and all(result[key] is True for key in ("setupOriginalsSettled", "setupDeadlineMet", "inertCloseDeadlinePolicyTable", "fixedCasesComplete", "passed"))
         and all(result[key] is False for key in ("genuineConcurrentRaceObserved", "nativeCloseFailureInjected", "applicationLaunched", "guiSaveQualified"))
         and result["qualification"] == "native-installer-collisions-and-injected-policy-only", "fixture-not-complete-or-bound")
    # Never accept a report-supplied arbitrary pathname: fixed protected ancestry,
    # this explicit source prefix, one nonce component, then seven fixed names.
    need(type(result["fixtureBase"]) is str and re.fullmatch(re.escape(FIXTURE_PREFIX + source[:12] + "-") + r"[0-9a-f]{32}", result["fixtureBase"]), "fixture-base-binding")
    need(type(result["cases"]) is list and len(result["cases"]) == len(FIXTURE_CASES), "fixture-exact-seven-cases")
    for row, (name, expected) in zip(result["cases"], FIXTURE_CASES.items()):
        need(type(row) is dict and set(row) == {"case", "passed", "proofError", "originalResult", "originalExit", "occupant",
             "absenceObservedBeforeCollision", "stagingOpenErrno", "persistence"} and row["case"] == name
             and row["passed"] is True and row["proofError"] is None and type(row["originalExit"]) is int and row["originalExit"] == expected[-1], "fixture-case-shape-or-outcome")
        bound_original_result(row["originalResult"], expected, source, inventory, manifest)
        need((row["originalResult"]["staging"] is None) == (name in ("occupied-app", "occupied-release")), "fixture-staging-phase")
        collision = name in ("runtime-publication-collision", "staging-file-collision", "first-publication-second-refusal")
        need(row["absenceObservedBeforeCollision"] is collision, "fixture-absence-observation")
        error = row["stagingOpenErrno"]
        need((type(error) is int and error == 17) if name == "staging-file-collision" else error is None, "fixture-actual-o-excl-eexist")  # Darwin EEXIST.
        point = {"prepublication-persistence-report": "payload-file-before-any-publication",
                 "postruntime-persistence-report": "stage-directory-after-runtime-rename"}.get(name)
        persistence = row["persistence"]
        if point is not None:
            need(type(persistence) is dict and set(persistence) == {"point", "actualNativeSucceeded", "actualNativeErrno", "injectedReportedFailure"}
                 and persistence["point"] == point and persistence["actualNativeSucceeded"] is True and persistence["actualNativeErrno"] is None
                 and persistence["injectedReportedFailure"] is True and row["occupant"] is None, "fixture-reported-not-actual-native-failure")
        else:
            need(persistence is None, "unexpected-fixture-persistence-report")
            witness = row["occupant"]
            need(type(witness) is dict and set(witness) == {"visibleRelativePath", "sha256", "before", "after", "verifiedByOriginalInstaller"}
                 and witness["visibleRelativePath"] == visible_occupant(name) and witness["sha256"] == digest(FIXTURE_MARKER)
                 and witness["verifiedByOriginalInstaller"] is True and witness["before"] == witness["after"], "fixture-occupant-witness")
            identity = witness["before"]
            need(type(identity) is dict and set(identity) == {"device", "inode", "mode", "uid", "gid", "links", "size",
                 "mtimeSeconds", "mtimeNanoseconds", "ctimeSeconds", "ctimeNanoseconds"} and all(type(value) is int for value in identity.values())
                 and type(witness["after"]) is dict and all(type(value) is int for value in witness["after"].values())
                 and identity["inode"] > 0 and identity["mode"] == 0o444 and identity["uid"] == identity["gid"] == 0 and identity["links"] == 1
                 and identity["size"] == len(FIXTURE_MARKER) and 0 <= identity["mtimeNanoseconds"] < 1000000000
                 and 0 <= identity["ctimeNanoseconds"] < 1000000000, "fixture-occupant-identity")
    return result


@contextlib.contextmanager
def fixture_directory(path, names):
    with parent(path) as (outer, name):
        before = os.stat(name, dir_fd=outer, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o755, "fixture-ancestor-protection")
        original = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
        try:
            need(signature(os.fstat(original)) == signature(before), "fixture-directory-changed")
            no_xattrs(original)
            need(set(os.listdir(original)) == names, "fixture-directory-roster")
            yield original
            need(signature(os.fstat(original)) == signature(before)
                 and signature(os.stat(name, dir_fd=outer, follow_symlinks=False)) == signature(before), "fixture-directory-changed")
        finally:
            close_once(original)


def observe_occupant(path, witness):
    with parent(path) as (fd, name):
        before = os.fstat(fd)
        need(before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o555 and set(os.listdir(fd)) == {"occupied.txt"}, "fixture-occupant-directory")
        no_xattrs(fd)
        body, info = read_at(fd, name, len(FIXTURE_MARKER))
        identity = {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                    "links": info.st_nlink, "size": info.st_size, "mtimeSeconds": info.st_mtime_ns // 1000000000,
                    "mtimeNanoseconds": info.st_mtime_ns % 1000000000, "ctimeSeconds": info.st_ctime_ns // 1000000000, "ctimeNanoseconds": info.st_ctime_ns % 1000000000}
        need(body == FIXTURE_MARKER and identity == witness["before"] == witness["after"] and signature(os.fstat(fd)) == signature(before), "fixture-occupant-not-preserved")


def fixture_observation_command(args):
    expected = observation_inventory(args)
    result, exported = installer_result_readback(args, fixture=True)
    bound_fixture_result(result, args.expected_source, args.expected_inventory, args.expected_manifest)
    base = INSTALL_ROOT.parent / result["fixtureBase"]  # Closed source/nonce component validated above.
    published = {name: row for name, row in expected.items() if name.startswith("runtime/")}
    observations = []
    with fixture_directory(base, set(FIXTURE_CASES)):
        for row in result["cases"]:
            name = row["case"]
            root = base / name
            stage = row["originalResult"]["staging"]
            app_occupant = name in ("occupied-app", "first-publication-second-refusal")
            has_versions = name != "occupied-app"
            has_release = name in ("occupied-release", "runtime-publication-collision", "first-publication-second-refusal", "postruntime-persistence-report")
            runtime_published = row["originalResult"]["runtimePublication"] == "confirmed"
            names = ({stage} if stage is not None else set()) | ({APP_NAME} if app_occupant else set()) | ({"versions"} if has_versions else set())
            runtime_files = 0
            with fixture_directory(root, names) as fd:
                if stage is not None:
                    # Metadata only. Never open/chmod the root-owned0700 staging.
                    info = os.stat(stage, dir_fd=fd, follow_symlinks=False)
                    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "fixture-protected-staging")
                if app_occupant:
                    observe_occupant(root / APP_NAME / "occupied.txt", row["occupant"])
                if has_versions:
                    with fixture_directory(root / "versions", {RELEASE} if has_release else set()):
                        if has_release:
                            with fixture_directory(root / "versions" / RELEASE, {"runtime"}):
                                runtime_path = root / "versions" / RELEASE / "runtime"
                                if runtime_published:
                                    files = tree(runtime_path, installed=True)
                                    byte_correspondence({"runtime/" + key: value for key, value in files.items()}, published)
                                    runtime_files = len(files)
                                else:
                                    observe_occupant(runtime_path / "occupied.txt", row["occupant"])
            observations.append({"case": name, "accessibleOccupantChecked": visible_occupant(name) is not None,
                                 "runtimeReadbackFileCount": runtime_files, "protectedStagingOpened": False})
    return {"schemaVersion": 1, "sourceCommit": args.expected_source, "inventorySha256": args.expected_inventory,
            "runtimeManifestSha256": args.expected_manifest, "originalFixtureResult": result, "installerResultExport": exported, "nonrootReadback": observations,
            "applicationLaunched": False, "guiSaveQualified": False, "genuineConcurrentRaceObserved": False,
            "nativeCloseFailureInjected": False, "qualification": "fixed-native-collisions-and-reported-policy-only-not-Aqua-Save-or-power-loss"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("describe-runtime", "runtime"):
        command = commands.add_parser(name)
        command.add_argument("--archive", required=True, type=Path)
        if name == "runtime":
            command.add_argument("--expected-manifest", required=True)
            command.add_argument("--output", required=True, type=Path)
    app = commands.add_parser("app")
    app.add_argument("--binary", required=True, type=Path)
    app.add_argument("--output", required=True, type=Path)
    inputs = commands.add_parser("input")
    inputs.add_argument("--app", required=True, type=Path)
    inputs.add_argument("--runtime", required=True, type=Path)
    inputs.add_argument("--expected-manifest", required=True)
    inputs.add_argument("--output", required=True, type=Path)
    scripts = commands.add_parser("scripts")
    scripts.add_argument("--input", required=True, type=Path)
    scripts.add_argument("--installer", required=True, type=Path)
    scripts.add_argument("--expected-inventory", required=True)
    scripts.add_argument("--expected-source", required=True)
    scripts.add_argument("--fixture", action="store_true")
    scripts.add_argument("--output", required=True, type=Path)
    probe = commands.add_parser("package-format-input")
    probe.add_argument("--output", required=True, type=Path)
    for name in ("prepare-package", "audit-package"):
        package = commands.add_parser(name)
        package.add_argument("--scripts", required=True, type=Path)
        package.add_argument("--package", required=True, type=Path)
        package.add_argument("--fixture", action="store_true")
        if name == "prepare-package":
            package.add_argument("--output", required=True, type=Path)
        else:
            package.add_argument("--original-package", required=True, type=Path)
    for name in ("observe-installation", "observe-installer-fixture"):
        observation = commands.add_parser(name)
        observation.add_argument("--input", required=True, type=Path)
        observation.add_argument("--expected-inventory", required=True)
        observation.add_argument("--expected-manifest", required=True)
        observation.add_argument("--expected-source", required=True)
        observation.add_argument("--installer-status", required=True, type=Path)
    absent = commands.add_parser("check-installer-result-absent")
    absent.add_argument("--fixture", action="store_true")
    absent.add_argument("--expected-source", required=True)
    absent.add_argument("--expected-inventory", required=True)
    absent.add_argument("--expected-manifest", required=True)
    for name in ("installer-log-cursor", "installer-log-capture"):
        diagnostic = commands.add_parser(name)
        diagnostic.add_argument("--fixture", action="store_true")
        diagnostic.add_argument("--package", required=True, type=Path)
        diagnostic.add_argument("--expected-source", required=True)
        diagnostic.add_argument("--expected-inventory", required=True)
        diagnostic.add_argument("--expected-manifest", required=True)
        diagnostic.add_argument("--run-id", required=True)
        diagnostic.add_argument("--run-attempt", required=True)
        if name == "installer-log-capture":
            diagnostic.add_argument("--cursor", required=True, type=Path)
            diagnostic.add_argument("--selected-output", required=True, type=Path)
    args = parser.parse_args(argv)
    need(args.command == "describe-runtime" or os.getuid() != 0 and os.getuid() == os.geteuid(), "only-installer-is-privileged")
    if args.command in ("installer-log-cursor", "installer-log-capture"):
        result, status = installer_log_diagnostic(args)
        print(canonical(result).decode("utf-8"))
        return status
    action = {"describe-runtime": runtime_command, "runtime": runtime_command, "app": app_command,
              "input": input_command, "scripts": scripts_command, "package-format-input": package_format_input_command,
              "prepare-package": prepare_package_command, "audit-package": audit_command,
              "check-installer-result-absent": installer_result_absent_command,
              "observe-installation": observation_command, "observe-installer-fixture": fixture_observation_command}[args.command]
    try:
        result = action(args)
    except Refused as error:
        if args.command in ("package-format-input", "prepare-package", "audit-package"):
            print(package_refusal_message(error), file=sys.stderr)
            raise SystemExit(1)
        raise
    print(canonical(result).decode("utf-8"))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Refused, OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError, zipfile.BadZipFile, tarfile.TarError, ET.ParseError):
        print(GENERIC_REFUSAL, file=sys.stderr)
        raise SystemExit(1)
