"""Prepare one private, authenticated orchestration Python on disposable Macs.

Apple Python >=3.9 runs preparation only, never the MRK native owner. The PSF
package is DATA: no installation or package script runs. This runtime is not a
shipping supplier, and a ready record does not qualify an application release.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import resource
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

MIB = 1024 * 1024
PACKAGE_URL = "https://www.python.org/ftp/python/3.14.7/python-3.14.7-macos11.pkg"
PACKAGE_SHA256 = "70c5239ad2d62925d2947e46921d0ddd3d35be3d2f0a2d50db33da507dbcb419"
PACKAGE_LIMIT = 96 * MIB
FRAMEWORK_ORIGINAL = "/Library/Frameworks/Python.framework"
VERSION_RELATIVE = "Versions/3.14"
ENTRY_RELATIVE = VERSION_RELATIVE + "/Resources/Python.app/Contents/MacOS/Python"
CPUS = {"arm64": 0x0100000C, "x86_64": 0x01000007}
PREP_SECONDS, SETTLE_SECONDS = 600, 60
FILE_LIMIT, SELECTED_LIMIT, EXPANDED_LIMIT = 256 * MIB, 768 * MIB, 2 * 1024 * MIB
LOAD_COMMANDS = {0xC, 0x80000018, 0x8000001F, 0x80000023}
LC_ID_DYLIB, LC_RPATH, LC_LOAD_DYLINKER = 0xD, 0x8000001C, 0xE
_BUILD = None


class PreparationRefused(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise PreparationRefused(code)


def build_data():
    """Load only the existing stdlib-only builder facade, not its native owner."""
    global _BUILD
    if _BUILD is None:
        path = Path(__file__).with_name("macos_cpython_source_build.py")
        spec = importlib.util.spec_from_file_location("_mrk_orchestrator_build_data", path)
        need(spec is not None and spec.loader is not None, "builder-data-loader")
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        _BUILD = value
    return _BUILD


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def relative_name(name):
    need(type(name) is str and 0 < len(name) <= 4096 and not name.startswith("/")
         and "\\" not in name and all(32 <= ord(c) < 127 for c in name)
         and all(part not in {"", ".", ".."} for part in name.split("/")), "relative-name")
    return name


def package_binding(size, sha256):
    need(type(size) is int and 0 < size <= PACKAGE_LIMIT
         and sha256 == PACKAGE_SHA256, "package-byte-authority")


def package_signature_observation(body):
    """Public-package diagnostic fields only; never signature authority.

    The caller has authenticated the fixed public package and retained the
    original pkgutil call. No arbitrary output, paths or other subjects escape.
    """
    result = {"stdoutSize": len(body), "stdoutSha256": hashlib.sha256(body).hexdigest(),
              "utf8": False, "legacyTrustPhrasePresent": None, "psfInstallerSubjectPresent": None,
              "statusShape": "invalid-utf8", "statusText": None,
              "psfSubjectShape": "invalid-utf8", "psfSubject": None}
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeError:
        return result
    subjects = re.findall(r"Developer ID Installer: Python Software Foundation \([A-Z0-9]{10}\)", text)
    statuses = []
    for line in text.split("\n"):
        prefix = re.match(r"[ \t]*Status:", line)
        if prefix is not None:
            statuses.append(line[prefix.end():])
    result.update(utf8=True, legacyTrustPhrasePresent="signed by a certificate trusted by" in text,
                  psfInstallerSubjectPresent=bool(subjects),
                  statusShape="absent" if not statuses else "multiple",
                  psfSubjectShape="absent" if not subjects else "multiple")
    if len(statuses) == 1:
        # Count ALL anchored fields first. Do not strip controls or normalize
        # Unicode into a publishable sentence; only structural ASCII spaces.
        match = re.fullmatch(r" *(?P<value>[A-Za-z][A-Za-z0-9 ()'.,;:_-]{0,199})", statuses[0])
        result["statusShape"] = "single" if match is not None else "unpublishable"
        if match is not None:
            result["statusText"] = match.group("value")
    if len(subjects) == 1:
        result.update(psfSubjectShape="single", psfSubject=subjects[0])
    return result


def framework_component(body):
    """Read authenticated PackageInfo DATA; never select by guessed filename."""
    need(type(body) is bytes and 0 < len(body) <= 65536, "package-info-bound")
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeError:
        raise PreparationRefused("package-info-utf8") from None
    need("\0" not in text and "<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(),
         "package-info-bound")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise PreparationRefused("package-info-xml") from None
    need(root.tag == "pkg-info", "package-info-root")
    name, version, location = (root.get(key, "") for key in ("identifier", "version", "install-location"))
    if not re.fullmatch(r"org\.python\.Python\.PythonFramework-3\.14", name):
        return False
    need(version in {"3.14.7", "3.14.7.0"} and location == FRAMEWORK_ORIGINAL,
         "package-framework-identity")
    return True


def native_slice(body, machine):
    """Extract one exact native 64-bit slice; no code is run or invented."""
    need(type(body) is bytes and 32 <= len(body) <= FILE_LIMIT and machine in CPUS, "macho-input")
    magic = struct.unpack_from(">I", body)[0]
    if magic in {0xCAFEBABE, 0xCAFEBABF}:
        count = struct.unpack_from(">I", body, 4)[0]
        width = 32 if magic == 0xCAFEBABF else 20
        need(1 <= count <= 8 and 8 + count * width <= len(body), "fat-count")
        ranges, cpus, selected = [], set(), None
        for number in range(count):
            start = 8 + number * width
            if width == 20:
                cpu, subtype, offset, size, alignment = struct.unpack_from(">IIIII", body, start)
            else:
                cpu, subtype, offset, size, alignment, reserved = struct.unpack_from(">IIQQII", body, start)
                need(reserved == 0, "fat-reserved")
            need(cpu in CPUS.values() and cpu not in cpus and 0 <= alignment <= 30
                 and offset >= 8 + count * width and size >= 32 and offset + size <= len(body)
                 and offset % (1 << alignment) == 0
                 and all(offset + size <= lo or offset >= hi for lo, hi in ranges), "fat-slice-range")
            cpus.add(cpu)
            ranges.append((offset, offset + size))
            thin = body[offset:offset + size]
            need(thin[:4] == b"\xcf\xfa\xed\xfe"
                 and struct.unpack_from("<II", thin, 4) == (cpu, subtype), "fat-slice-header")
            if cpu == CPUS[machine]:
                selected = thin
        need(selected is not None, "fat-native-missing")
        body = selected
    need(body[:4] == b"\xcf\xfa\xed\xfe" and struct.unpack_from("<I", body, 4)[0] == CPUS[machine],
         "macho-native-header")
    return body


def macho_records(body, machine):
    """Bounded load-command DATA, after native_slice; not supplier admission."""
    need(native_slice(body, machine) == body, "macho-must-be-thin")
    _, cpu, subtype, kind, count, extent, flags, reserved = struct.unpack_from("<8I", body)
    need(kind in {2, 6, 8} and 1 <= count <= 512 and 8 * count <= extent <= len(body) - 32,
         "macho-command-table")
    cursor, result = 32, []
    for _ in range(count):
        need(cursor + 8 <= 32 + extent, "macho-command-header")
        command, size = struct.unpack_from("<II", body, cursor)
        need(size >= 8 and size % 8 == 0 and cursor + size <= 32 + extent, "macho-command-range")
        need(command != 0x27, "macho-dyld-environment")
        row = {"command": command, "offset": cursor, "size": size}
        if command in LOAD_COMMANDS | {LC_ID_DYLIB, LC_RPATH, LC_LOAD_DYLINKER}:
            minimum = 24 if command in LOAD_COMMANDS | {LC_ID_DYLIB} else 12
            need(size >= minimum, "macho-string-command")
            name_offset = struct.unpack_from("<I", body, cursor + 8)[0]
            need(minimum <= name_offset < size, "macho-string-offset")
            raw = body[cursor + name_offset:cursor + size]
            name, separator, padding = raw.partition(b"\0")
            need(separator and name and len(name) <= 4096 and all(32 <= byte < 127 for byte in name)
                 and not any(padding), "macho-string")
            row.update(text=name.decode("ascii"), nameOffset=name_offset)
        result.append(row)
        cursor += size
    need(cursor == 32 + extent, "macho-command-extent")
    return result


def resolve_member(name, rows):
    """Resolve only inventory-owned aliases, with no real filesystem traversal."""
    need(type(name) is str and not name.startswith("/"), "member-relative")
    value = posixpath.normpath(name)
    for _ in range(65):
        if value == ".":
            need(rows.get(".", {}).get("kind") == "directory", "member-root")
            return value
        relative_name(value)
        parts, changed = value.split("/"), False
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            row = rows.get(prefix)
            need(row is not None, "member-missing")
            if row["kind"] == "link":
                target = row["target"]
                need(type(target) is str and target and not target.startswith("/") and "\\" not in target,
                     "member-link-escape")
                value = posixpath.normpath(posixpath.join(posixpath.dirname(prefix), target, *parts[index:]))
                changed = True
                break
            need(index == len(parts) or row["kind"] == "directory", "member-parent-type")
        if not changed:
            return value
    raise PreparationRefused("member-link-cycle")


def relocation_plan(body, machine, name, rows, images):
    """Return fixed install_name_tool arguments and exact expected load names."""
    relative_name(name)
    records = macho_records(body, machine)
    rpaths = [row["text"] for row in records if row["command"] == LC_RPATH]
    need(len(rpaths) == len(set(rpaths)), "duplicate-rpath")
    executable_parent = posixpath.dirname(ENTRY_RELATIVE)

    def local(path):
        if path.startswith(FRAMEWORK_ORIGINAL + "/"):
            return path[len(FRAMEWORK_ORIGINAL) + 1:]
        if path == "@loader_path" or path.startswith("@loader_path/"):
            return posixpath.join(posixpath.dirname(name), path[len("@loader_path"):].lstrip("/"))
        if path == "@executable_path" or path.startswith("@executable_path/"):
            return posixpath.join(executable_parent, path[len("@executable_path"):].lstrip("/"))
        raise PreparationRefused("loader-external-path")

    normalized_rpaths = []
    for raw in rpaths:
        normalized_rpaths.append(resolve_member(local(raw), rows))
    argv, expected, changes = [], [], []
    for row in records:
        command = row["command"]
        if command == LC_RPATH:
            argv.extend(("-delete_rpath", row["text"]))
            continue
        if command not in LOAD_COMMANDS | {LC_ID_DYLIB, LC_LOAD_DYLINKER}:
            continue
        old = row["text"]
        if command == LC_LOAD_DYLINKER:
            need(old == "/usr/lib/dyld", "loader-dyld-path")
            expected.append((command, old))
            continue
        if command == LC_ID_DYLIB:
            target = name
        elif old.startswith(("/usr/lib/", "/System/Library/")):
            need(posixpath.normpath(old) == old and "\\" not in old, "loader-Apple-path")
            expected.append((command, old))
            continue
        elif old.startswith("@rpath/"):
            matches = set()
            for prefix in normalized_rpaths:
                try:
                    resolved = resolve_member(posixpath.join(prefix, old[7:]), rows)
                except PreparationRefused:
                    continue
                if resolved in images:
                    matches.add(resolved)
            need(len(matches) == 1, "loader-rpath-ambiguous-or-missing")
            target = next(iter(matches))
        else:
            target = resolve_member(local(old), rows)
        need(target in images, "loader-private-image-missing")
        new = "@loader_path/" + posixpath.relpath(target, posixpath.dirname(name) or ".")
        need(len(new.encode("ascii")) + 1 <= row["size"] - row["nameOffset"], "loader-command-capacity")
        expected.append((command, new))
        if new != old:
            if command == LC_ID_DYLIB:
                argv.extend(("-id", new))
            else:
                argv.extend(("-change", old, new))
            changes.append({"command": command, "before": old, "after": new})
    return {"arguments": argv, "expected": expected, "changes": changes, "removedRpaths": rpaths}


def macho_content_valid(before, after, machine, *, signing=False):
    """Permit load-name/signature edits, never changed executable/data bytes."""
    old_rows, new_rows = macho_records(before, machine), macho_records(after, machine)
    need(before[:16] == after[:16] and before[24:32] == after[24:32], "macho-header-changed")
    old_end = 32 + struct.unpack_from("<I", before, 20)[0]
    new_end = 32 + struct.unpack_from("<I", after, 20)[0]
    need(new_end <= old_end or not any(before[old_end:new_end]), "macho-command-overwrote-content")

    def content(body, records):
        signature, fixed = None, []
        for row in records:
            command = row["command"]
            raw = body[row["offset"]:row["offset"] + row["size"]]
            if command == 0x1D:  # LC_CODE_SIGNATURE: an explicit last-file blob.
                need(signature is None and len(raw) == 16, "macho-signature-command")
                offset, size = struct.unpack_from("<II", raw, 8)
                need(offset >= 32 + struct.unpack_from("<I", body, 20)[0]
                     and size > 0 and offset + size == len(body), "macho-signature-range")
                signature = offset
            elif "text" not in row:
                # Re-signing may resize only __LINKEDIT's mapped/file extents.
                # Its file offset, protections, section table and all other
                # commands retain their exact original bytes.
                if signing and command == 0x19 and len(raw) >= 72 and raw[8:24].rstrip(b"\0") == b"__LINKEDIT":
                    raw = raw[:32] + b"\0" * 8 + raw[40:48] + b"\0" * 8 + raw[56:]
                fixed.append(raw)
        return signature if signature is not None else len(body), fixed

    old_limit, old_fixed = content(before, old_rows)
    new_limit, new_fixed = content(after, new_rows)
    boundary, end = max(old_end, new_end), min(old_limit, new_limit)
    need(old_fixed == new_fixed and boundary <= end and before[boundary:end] == after[boundary:end],
         "macho-nonsignature-content-changed")
    need(not any(before[end:old_limit]) and not any(after[end:new_limit]), "macho-signature-alignment-changed")
    if signing:
        need([(row["command"], row["text"]) for row in old_rows if "text" in row]
             == [(row["command"], row["text"]) for row in new_rows if "text" in row],
             "macho-signing-loader-changed")
    return True


def orchestration_environment(base, root):
    need(type(base) is dict and all(type(key) is str and type(value) is str for key, value in base.items()),
         "orchestration-environment")
    need(not any(key.startswith(("DYLD_", "PYTHON")) and key != "PYTHONDONTWRITEBYTECODE"
                 for key in base if key not in {"PYTHON_FOR_REGEN", "PYTHON_FOR_BUILD", "PYTHON_FOR_FREEZE"}),
         "orchestration-inherited-loader")
    return {**base, "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": str(root / "empty-providers")}


def runtime_facts_valid(facts, root, machine):
    """Pure validation of real facts collected inside the copied interpreter."""
    prefix = str(root / "Python.framework" / VERSION_RELATIVE)
    entry = str(root / "Python.framework" / ENTRY_RELATIVE)
    need(type(facts) is dict and facts.get("version") == [3, 14, 7] and facts.get("machine") == machine
         and machine in CPUS and facts.get("executable") == entry
         and facts.get("flags") == {"isolated": 1, "noSite": 1, "noBytecode": True}
         and facts.get("prefixes") == [prefix] * 4, "prepared-runtime-identity")
    need(facts.get("openssl") == {"OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": str(root / "empty-providers")},
         "prepared-runtime-config")
    for category in ("sysPath", "modulePaths"):
        values = facts.get(category)
        need(type(values) is list and values and all(type(path) is str and path.startswith(prefix + "/")
             and posixpath.normpath(path) == path for path in values), "prepared-runtime-" + category)
    images = facts.get("images")
    need(type(images) is list and entry in images and any(path == prefix + "/Python" for path in images)
         and all(type(path) is str and posixpath.normpath(path) == path
                 and (path.startswith(prefix + "/") or path.startswith(("/usr/lib/", "/System/Library/")))
                 for path in images), "prepared-runtime-images")
    return True


def scan_tree(root, *, readonly=False, closure=False, deadline=None):
    """Observe a finite owned tree without traversing any directory alias."""
    b = build_data()
    root = Path(root)
    rows, aliases, total, directories, links = {}, set(), 0, 0, 0
    for directory, names, files in b.walk_tree(root):
        if deadline is not None:
            b.remaining(deadline, time.monotonic(), PREP_SECONDS)
        info = directory.lstat()
        name = directory.relative_to(root).as_posix()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "inventory-directory")
        need(not readonly or stat.S_IMODE(info.st_mode) == 0o555, "inventory-directory-mode")
        need(not readonly or not os.listxattr(directory, follow_symlinks=False), "inventory-directory-xattr")
        need(name not in rows, "inventory-directory-duplicate")
        rows[name] = {"kind": "directory", "identity": list(identity(info))}
        directories += 1
        need(directories <= 4096 if closure else directories <= 32768, "inventory-directory-limit")
        for child in names + files:
            relative = relative_name((directory / child).relative_to(root).as_posix())
            need(relative.casefold() not in aliases, "inventory-case-alias")
            aliases.add(relative.casefold())
        for child in files:
            if deadline is not None:
                b.remaining(deadline, time.monotonic(), PREP_SECONDS)
            path = directory / child
            name = relative_name(path.relative_to(root).as_posix())
            info = path.lstat()
            need(info.st_uid == os.getuid(), "inventory-file-owner")
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                need(type(target) is str and 0 < len(target) <= 4096 and "\0" not in target,
                     "inventory-link-bound")
                need(identity(path.lstat()) == identity(info), "inventory-link-post")
                rows[name] = {"kind": "link", "identity": list(identity(info)), "target": target}
                links += 1
                need(links <= 1024, "inventory-link-limit")
            else:
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                     and 0 <= info.st_size <= FILE_LIMIT, "inventory-file-kind-or-size")
                need(not readonly or stat.S_IMODE(info.st_mode) in {0o444, 0o555}, "inventory-file-mode")
                need(not readonly or not os.listxattr(path, follow_symlinks=False), "inventory-file-xattr")
                body = b.read(path, FILE_LIMIT)
                need(identity(path.lstat()) == identity(info), "inventory-file-post")
                rows[name] = {"kind": "file", "identity": list(identity(info)),
                              "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                total += len(body)
            need(len(rows) <= (32768 + 4096 + 1024 if closure else 65536)
                 and total <= (SELECTED_LIMIT if closure else EXPANDED_LIMIT), "inventory-total-limit")
    need("." in rows, "inventory-root")
    for name, row in rows.items():
        if deadline is not None:
            b.remaining(deadline, time.monotonic(), PREP_SECONDS)
        need(list(identity((root / name).lstat())) == row["identity"], "inventory-original-post")
        if closure and row["kind"] == "link":
            resolve_member(name, rows)
    need(b.DATA.known, "inventory-close-finality")
    return dict(sorted(rows.items()))


def copy_framework(source, destination, expected, *, deadline):
    b = build_data()
    need(scan_tree(source, closure=True, deadline=deadline) == expected, "copy-source-pre")
    need(not destination.exists() and not destination.is_symlink(), "copy-destination-collision")
    destination.mkdir(mode=0o700)
    for name, row in sorted(expected.items(), key=lambda pair: (pair[0].count("/"), pair[0])):
        b.remaining(deadline, time.monotonic(), PREP_SECONDS)
        if name == ".":
            continue
        target = destination / name
        if row["kind"] == "directory":
            target.mkdir(mode=0o700)
        elif row["kind"] == "link":
            os.symlink(row["target"], target)
        else:
            body = b.read(source / name, FILE_LIMIT, expected=(row["size"], row["sha256"]))
            b.write(target, body, 0o700 if row["identity"][2] & 0o111 else 0o600)
    need(scan_tree(source, closure=True, deadline=deadline) == expected, "copy-source-post")
    copied = scan_tree(destination, closure=True, deadline=deadline)
    need(set(copied) == set(expected), "copy-complete-inventory")
    for name, original in expected.items():
        row = copied[name]
        need(row["kind"] == original["kind"], "copy-kind")
        if row["kind"] == "file":
            need((row["size"], row["sha256"]) == (original["size"], original["sha256"]), "copy-bytes")
        if row["kind"] == "link":
            need(row["target"] == original["target"], "copy-alias")
    return copied


def retire_tree(root, expected, *, known, deadline):
    """Remove only pre-observed task originals, never an alias's target."""
    b = build_data()
    root = Path(root)
    need(known is True and b.DATA.known and scan_tree(root, deadline=deadline) == expected,
         "retirement-finality-or-correspondence")
    need(expected.get(".", {}).get("kind") == "directory", "retirement-root")
    children = {}
    for name in expected:
        if name != ".":
            children.setdefault(posixpath.dirname(name) or ".", []).append(posixpath.basename(name))

    def consume(parent, entry, relative):
        b.remaining(deadline, time.monotonic(), SETTLE_SECONDS)
        row = expected[relative]
        before = os.stat(entry, dir_fd=parent, follow_symlinks=False)
        need(list(identity(before)) == row["identity"], "retirement-original-entry")
        if row["kind"] != "directory":
            need(row["kind"] in {"file", "link"}, "retirement-entry-kind")
            os.unlink(entry, dir_fd=parent)
            return
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        with b.DATA.acquiring(os.open, os.close, entry, flags, dir_fd=parent) as fd:
            need(identity(os.fstat(fd)) == identity(before), "retirement-open-original")
            os.fchmod(fd, 0o700)
            for child in sorted(children.get(relative, ())):
                child_relative = child if relative == "." else relative + "/" + child
                consume(fd, child, child_relative)
            with b.DATA.acquiring(os.scandir, lambda stream: stream.close(), fd) as iterator:
                need(next(iterator, None) is None, "retirement-directory-not-empty")
            current = os.stat(entry, dir_fd=parent, follow_symlinks=False)
            original = os.fstat(fd)
            need(identity(current) == identity(original) and current.st_dev == before.st_dev
                 and current.st_ino == before.st_ino and current.st_uid == before.st_uid,
                 "retirement-directory-rebound")
        os.rmdir(entry, dir_fd=parent)

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with b.DATA.acquiring(os.open, os.close, root.parent, flags) as parent:
        consume(parent, root.name, ".")
    need(b.DATA.known and not root.exists() and not root.is_symlink(), "retirement-post")


class FixedCalls:
    """Bounded original calls for these Apple tools only; not a project runner."""
    def __init__(self, root, tools, *, data=None, clock=time.monotonic, popen=subprocess.Popen):
        self.root, self.tools, self.clock, self.popen = Path(root), tools, clock, popen
        self.data = data if data is not None else build_data().DATA
        self.deadline, self.known, self.active = clock() + PREP_SECONDS, True, None
        self.records, self.output_bytes = [], 0
        self.cancellation, self.original_tools = None, []

    def policy(self, *, online=False):
        root = str(self.root)
        need(root.startswith("/") and not any(c in root for c in ('"', "\\", "\n", "\0")), "policy-root")
        return ('(version 1)(allow default)(deny process-fork)(deny file-write*)'
                '(allow file-write* (subpath "' + root + '") (literal "/dev/null"))'
                + ('' if online else '(deny network*)'))

    def run(self, role, arguments, *, environment, maximum=120, online=False):
        need(self.known and self.data.known and self.active is None and len(self.records) < 2048,
             "fixed-call-finality")
        need(role in {"download", "package", "relocate", "sign", "probe", "runtime"} and role in self.tools
             and online == (role == "download") and type(arguments) is list
             and all(type(value) is str and "\0" not in value for value in arguments), "fixed-call-role")
        finish = min(self.deadline - SETTLE_SECONDS, self.clock() + maximum)
        need(self.clock() < finish, "preparation-deadline")
        need(self.cancellation is None or not self.cancellation["cancelled"], "preparation-cancelled")
        for original in self.original_tools:
            need(list(identity(Path(original["path"]).lstat())) == original["identity"]
                 and str(Path(original["selectedPath"]).resolve(strict=True)) == original["path"],
                 "preparation-original-tool-changed")
        argv = [self.tools["sandbox"], "-p", self.policy(online=online), self.tools[role], *arguments]
        row = {"role": role, "entered": True, "returned": False, "settled": False}
        self.records.append(row)
        process, streams, selector, failure = None, [], None, None
        selector_pending = stream_collection_pending = False
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        try:
            # Publication uncertainty is absorbing; never recover by PID search.
            self.active = "constructing"
            process = self.popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=str(self.root), env=environment, close_fds=True)
            need(process is not None, "fixed-call-original")
            self.active = process
            stream_collection_pending = True
            for name in ("stdout", "stderr"):
                stream = getattr(process, name)
                if stream is not None:
                    need(all(stream is not original for original in streams), "fixed-call-duplicate-stream")
                    streams.append(stream)
            if len(streams) != 2:
                self.known = False
                self.data.unknown()
                raise PreparationRefused("fixed-call-original-streams")
            stream_collection_pending = False
            selector_pending = True
            selector = selectors.DefaultSelector()
            selector_pending = False
            for name, stream in zip(("stdout", "stderr"), streams):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                need(self.clock() < finish, "fixed-call-deadline")
                need(self.cancellation is None or not self.cancellation["cancelled"], "preparation-cancelled")
                for key, _ in selector.select(min(0.1, max(0.0, finish - self.clock()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        self.output_bytes += len(block)
                        need(len(outputs[key.data]) + len(block) <= MIB and self.output_bytes <= 16 * MIB,
                             "fixed-call-output-bound")
                        outputs[key.data].extend(block)
            returncode = process.wait(timeout=max(0.001, finish - self.clock()))
            row.update(returned=True, returncode=returncode)
            need(returncode == 0, "fixed-" + role + "-exit-" + str(returncode))
            need(self.clock() < finish, "fixed-call-deadline")
            need(self.cancellation is None or not self.cancellation["cancelled"], "preparation-cancelled")
        except BaseException as error:
            failure = error
        finally:
            if selector_pending or stream_collection_pending:
                self.known = False
                self.data.unknown()
            if process is None:
                self.known = False
                self.data.unknown()
            else:
                try:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=max(0.001, self.deadline - self.clock()))
                    row["settled"] = True
                except BaseException:
                    self.known = False
                    self.data.unknown()
                    if failure is None:
                        failure = PreparationRefused("fixed-call-settlement-unknown")
            for closer in ([selector.close] if selector is not None else []) + [stream.close for stream in streams]:
                try:
                    self.data.close(closer)
                except BaseException:
                    self.known = False
                    if failure is None:
                        failure = PreparationRefused("fixed-call-close-unknown")
            self.active = None if self.known and self.data.known else "unknown"
            row.update(stdoutSize=len(outputs["stdout"]), stderrSize=len(outputs["stderr"]),
                       stdoutSha256=hashlib.sha256(outputs["stdout"]).hexdigest(),
                       stderrSha256=hashlib.sha256(outputs["stderr"]).hexdigest())
        if failure is not None:
            raise failure
        result = {name: bytes(body) for name, body in outputs.items()}
        # Known original settlement is not permission to accept late success.
        need(self.clock() < finish, "fixed-call-deadline")
        need(self.cancellation is None or not self.cancellation["cancelled"], "preparation-cancelled")
        return result


def context():
    b = build_data()
    target = b.target_for_route(os.environ.get("GITHUB_WORKFLOW_REF"), os.environ.get("GITHUB_REF"))
    profile = b.target_profile(target)
    source, run, attempt = (os.environ.get(name, "") for name in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    need(sys.platform == "darwin" and sys.version_info >= (3, 9) and sys.flags.isolated
         and sys.flags.no_site and sys.dont_write_bytecode and os.getuid() == os.geteuid() != 0
         and os.getgid() == os.getegid() and os.uname().machine == profile["machine"]
         and platform.mac_ver()[0].startswith("26."), "fixed-preparation-host")
    need(re.fullmatch(r"[0-9a-f]{40}", source) and source != "0" * 40
         and all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt)), "fixed-preparation-run")
    route = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
             "RUNNER_ARCH": profile["runnerArch"], "GITHUB_REPOSITORY": b.REPOSITORY,
             "GITHUB_EVENT_NAME": "push", "GITHUB_REF": profile["reference"], "GITHUB_WORKFLOW_SHA": source,
             "GITHUB_JOB": "producer", "GITHUB_WORKSPACE": str(b.CHECKOUT), "RUNNER_TEMP": str(b.WORK_PARENT),
             "GITHUB_WORKFLOW_REF": b.REPOSITORY + "/" + profile["workflow"] + "@" + profile["reference"]}
    need(all(os.environ.get(key) == value for key, value in route.items()), "fixed-preparation-route")
    need(b.read(b.CHECKOUT / ".git/HEAD", 41) == source.encode() + b"\n", "fixed-preparation-source")
    root = b.WORK_PARENT / (profile["workPrefix"] + "-orchestrator-" + source + "-" + run + "-" + attempt)
    return {"sourceCommit": source, "run": run, "attempt": attempt, "target": target,
            "machine": profile["machine"], "root": root,
            "buildRoot": b.WORK_PARENT / (profile["workPrefix"] + "-" + source + "-" + run + "-" + attempt)}


def identity_fields(ctx):
    return {name: ctx[name] for name in ("sourceCommit", "run", "attempt", "target", "machine")}


def read_record(path, *, maximum=16 * MIB):
    b = build_data()
    row = path.lstat()
    need(stat.S_ISREG(row.st_mode) and stat.S_IMODE(row.st_mode) == 0o444
         and row.st_uid == os.getuid() and row.st_nlink == 1, "preparation-record-mode")
    return b.decode(b.read(path, maximum))


def atomic_record(path, record):
    b = build_data()
    need(not path.exists() and not path.is_symlink(), "preparation-publication-collision")
    temporary = path.with_name(path.name + ".part")
    b.write(temporary, b.canonical(record), 0o444)
    # link is an exclusive publication: unlike rename it cannot replace a leaf.
    os.link(temporary, path, follow_symlinks=False)
    os.unlink(temporary)
    need(path.lstat().st_nlink == 1 and b.DATA.known, "preparation-publication-finality")


def source_post(before, ctx):
    b = build_data()
    need(b.source_snapshot(b.CHECKOUT, ctx["target"]) == before, "preparation-source-post")


def protected_apple(path):
    b = build_data()
    path = Path(path)
    actual = path.resolve(strict=True)
    allowed = ("/usr/", "/bin/", "/sbin/", "/System/", str(b.DEVELOPER) + "/")
    need(path.is_absolute() and str(path).startswith(allowed) and str(actual).startswith(allowed),
         "preparation-Apple-path")
    for selected in (path, actual):
        for parent in (selected.parent, *selected.parent.parents):
            row = parent.lstat()
            need(stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022,
                 "preparation-Apple-parent")
    info = actual.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o111
         and not info.st_mode & 0o022 and info.st_nlink >= 1 and 0 < info.st_size <= FILE_LIMIT,
         "preparation-Apple-tool")
    body = b.read(actual, FILE_LIMIT, expected_links=info.st_nlink)
    return {"selectedPath": str(path), "path": str(actual), "identity": list(identity(info)),
            "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}


def recheck_apple(rows):
    for row in rows:
        need(protected_apple(row["selectedPath"]) == row, "preparation-Apple-tool-changed")


@contextmanager
def cancellation_state():
    """Latch cancellation; do not interrupt original handle publication."""
    state = {"cancelled": False, "restored": False}
    originals = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    changed = []
    def cancel(number, frame):
        state["cancelled"] = True
    try:
        for number in originals:
            signal.signal(number, cancel)
            changed.append(number)
        yield state
    finally:
        errors = []
        for number in reversed(changed):
            try:
                signal.signal(number, originals[number])
            except BaseException as error:
                errors.append(type(error).__name__)
        need(not errors and all(signal.getsignal(number) == value for number, value in originals.items()),
             "preparation-handler-restoration")
        state["restored"] = True


def primitive_probe():
    """Inert negative probe: settle an unexpected positive child before refusal."""
    observed = {}
    for name in ("fork", "posix_spawn"):
        pid = None
        try:
            if name == "fork":
                pid = os.fork()
                if pid == 0:
                    os._exit(0)
            else:
                pid = os.posix_spawn("/usr/bin/true", ["/usr/bin/true"],
                                     {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
        except OSError as error:
            need(error.errno in {1, 13}, "primitive-probe-unexpected-error")
            observed[name] = {"denied": True, "errno": error.errno, "created": False, "joined": False}
        else:
            need(type(pid) is int and pid > 0, "primitive-probe-original")
            waited, status = os.waitpid(pid, 0)
            need(waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                 "primitive-probe-child-finality")
            observed[name] = {"denied": False, "errno": None, "created": True, "joined": True}
    return observed


def runtime_facts(root):
    import ctypes
    b = build_data()
    actual_sources = {str(Path(__file__).resolve()), str(Path(b.__file__).resolve())}
    module_paths = []
    for module in tuple(sys.modules.values()):
        if module is None:
            continue
        spec = getattr(module, "__spec__", None)
        path = getattr(module, "__file__", None)
        if path and str(Path(path).resolve()) not in actual_sources and getattr(spec, "origin", None) not in {"built-in", "frozen"}:
            module_paths.append(str(Path(path).resolve()))
    dyld = ctypes.CDLL(None)
    count, image_name = dyld._dyld_image_count, dyld._dyld_get_image_name
    count.argtypes, count.restype = (), ctypes.c_uint32
    image_name.argtypes, image_name.restype = (ctypes.c_uint32,), ctypes.c_char_p
    length = int(count())
    need(0 < length <= 1024, "prepared-dyld-count")
    images = []
    for number in range(length):
        raw = image_name(number)
        need(raw is not None and 0 < len(raw) <= 4096, "prepared-dyld-image")
        images.append(raw.decode("utf-8", "strict"))
    need(int(count()) == length, "prepared-dyld-stable")
    return {"version": list(sys.version_info[:3]), "machine": os.uname().machine,
            "executable": str(Path(sys.executable).resolve()),
            "prefixes": [str(Path(value).resolve()) for value in
                         (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix)],
            "flags": {"isolated": sys.flags.isolated, "noSite": sys.flags.no_site,
                      "noBytecode": sys.dont_write_bytecode},
            "openssl": {name: os.environ.get(name) for name in ("OPENSSL_CONF", "OPENSSL_MODULES")},
            "sysPath": list(sys.path), "modulePaths": sorted(set(module_paths)), "images": images}


def prepared_record_valid(doc, ctx, *, ready=True):
    """Closed DATA contract; actual original filesystem/runtime checks follow."""
    keys = {"schemaVersion", "state", "identity", "packageSha256", "rootCustody", "framework", "providerIdentity"}
    if ready:
        keys |= {"originalsKnown", "handlersRestored", "intermediatesRetired"}
    need(type(doc) is dict and set(doc) == keys and type(doc["schemaVersion"]) is int
         and doc["schemaVersion"] == 1 and doc["state"] == ("READY" if ready else "PREPARED-NOT-READY")
         and doc["identity"] == identity_fields(ctx) and doc["packageSha256"] == PACKAGE_SHA256,
         "prepared-record-identity")
    for field, count in (("rootCustody", 5), ("providerIdentity", 9)):
        values = doc[field]
        need(type(values) is list and len(values) == count
             and all(type(value) is int and value >= 0 for value in values), "prepared-record-custody")
    rows = doc["framework"]
    need(type(rows) is dict and "." in rows and 1 <= len(rows) <= 32768 + 4096 + 1024,
         "prepared-record-inventory")
    for name, row in rows.items():
        if name != ".":
            relative_name(name)
        need(type(row) is dict and row.get("kind") in {"directory", "file", "link"},
             "prepared-record-row-kind")
        fields = {"kind", "identity"} | ({"target"} if row["kind"] == "link" else
                  {"size", "sha256"} if row["kind"] == "file" else set())
        values = row.get("identity")
        need(set(row) == fields and type(values) is list and len(values) == 9
             and all(type(value) is int and value >= 0 for value in values), "prepared-record-row")
        if row["kind"] == "file":
            need(type(row["size"]) is int and 0 <= row["size"] <= FILE_LIMIT
                 and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
                 "prepared-record-file")
        if row["kind"] == "link":
            need(type(row["target"]) is str and 0 < len(row["target"]) <= 4096, "prepared-record-alias")
    need(rows["."]["kind"] == "directory", "prepared-record-root")
    if ready:
        need(all(doc[name] is True for name in ("originalsKnown", "handlersRestored", "intermediatesRetired")),
             "prepared-original-finality")
    return True


def prepared_layout(ctx, *, ready=True):
    """Also usable by Apple Python *after* the prepared process has exited."""
    b = build_data()
    root = ctx["root"]
    doc = read_record(root / ("ready.json" if ready else "preparing.json"))
    prepared_record_valid(doc, ctx, ready=ready)
    need(list(b.custody(root.lstat())) == doc.get("rootCustody")
         and stat.S_IMODE(root.lstat().st_mode) == 0o700, "prepared-root-custody")
    need(scan_tree(root / "Python.framework", readonly=True, closure=True) == doc.get("framework"),
         "prepared-framework-correspondence")
    provider = root / "empty-providers"
    need(list(identity(provider.lstat())) == doc.get("providerIdentity")
         and stat.S_ISDIR(provider.lstat().st_mode) and stat.S_IMODE(provider.lstat().st_mode) == 0o555
         and not b.directory_entries(provider), "prepared-provider-custody")
    need(b.DATA.known, "prepared-layout-fd-finality")
    return doc


def verify_prepared(ctx, *, ready=True):
    b = build_data()
    doc = prepared_layout(ctx, ready=ready)
    root = ctx["root"]
    facts = runtime_facts(root)
    runtime_facts_valid(facts, root, ctx["machine"])
    need(b.DATA.known, "prepared-runtime-fd-finality")
    return doc, facts


def build_entry_configuration():
    """Called by the actual prepared builder before loading its native owner."""
    ctx = context()
    verify_prepared(ctx)
    return orchestration_environment({}, ctx["root"])


def enter_build(ctx):
    """Verify bytes with Apple Python, then replace this same original process."""
    b = build_data()
    protected_apple(sys.executable)
    before = b.source_snapshot(b.CHECKOUT, ctx["target"])
    prepared_layout(ctx)
    source_post(before, ctx)
    inherited = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "GITHUB_REPOSITORY",
                 "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
                 "GITHUB_WORKSPACE", "RUNNER_TEMP", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    environment = orchestration_environment({
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
        **{name: os.environ[name] for name in inherited}}, ctx["root"])
    executable = str(ctx["root"] / "Python.framework" / ENTRY_RELATIVE)
    need(b.DATA.known, "preexec-original-descriptor-finality")
    os.execve(executable, [executable, "-I", "-S", "-B", str(b.CHECKOUT / "desktop/tools/macos_cpython_source_build.py")],
              environment)
    raise PreparationRefused("prepared-exec-unexpected-return")


def native_image_bytes(path, machine):
    b = build_data()
    data = b.read(path, FILE_LIMIT)
    if data[:4] not in {b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}:
        return None
    return native_slice(data, machine)


def replace_owned_file(path, body):
    """Only replace an already owned private ordinary leaf, never its name."""
    b = build_data()
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1,
         "private-image-original")
    with b.DATA.acquiring(os.open, os.close, path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC) as fd:
        need(identity(os.fstat(fd)) == identity(before), "private-image-open")
        os.fchmod(fd, 0o700)
        os.ftruncate(fd, 0)
        cursor = 0
        while cursor < len(body):
            count = os.write(fd, body[cursor:cursor + 65536])
            need(count > 0, "private-image-write")
            cursor += count
    need(b.read(path, FILE_LIMIT) == body, "private-image-readback")


def seal_framework(root, rows):
    for name, row in rows.items():
        if row["kind"] == "file":
            mode = 0o555 if (root / name).lstat().st_mode & 0o111 else 0o444
            os.chmod(root / name, mode, follow_symlinks=False)
    for name, row in sorted(rows.items(), key=lambda pair: pair[0].count("/"), reverse=True):
        if row["kind"] == "directory":
            os.chmod(root / name, 0o555, follow_symlinks=False)


def select_framework(expanded, inventory):
    b = build_data()
    candidates = []
    for name, row in inventory.items():
        if row["kind"] == "file" and name.endswith("/PackageInfo"):
            path = expanded / name
            if framework_component(b.read(path, 65536)):
                # The normal framework component's Payload is relative to its
                # authenticated install-location, not the machine filesystem.
                candidate = path.parent / "Payload"
                need(candidate.is_dir() and not candidate.is_symlink()
                     and (candidate / ENTRY_RELATIVE).is_file()
                     and (candidate / VERSION_RELATIVE / "lib/python3.14/os.py").is_file(),
                     "package-framework-payload-shape")
                candidates.append(candidate)
    need(len(candidates) == 1, "package-framework-count")
    return candidates[0]


def capture_cleanup(ctx, *, deadline):
    """Record originals only after every entered preparation call has settled."""
    b, root = build_data(), ctx["root"]
    allowed = {"home", "tmp", "empty-providers", "python-3.14.7.pkg", "expanded", "Python.framework",
               "preparing.json", "ready.json"}
    entries = {}
    for item in b.directory_entries(root):
        b.remaining(deadline, time.monotonic(), SETTLE_SECONDS)
        need(item.name in allowed, "cleanup-unexpected-root-entry")
        path = root / item.name
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entries[item.name] = {"kind": "directory", "inventory": scan_tree(path, deadline=deadline)}
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
                 "cleanup-entry-kind")
            body = b.read(path, FILE_LIMIT)
            need(identity(info) == identity(path.lstat()), "cleanup-file-original")
            entries[item.name] = {"kind": "file", "identity": list(identity(info)),
                                  "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    value = {"schemaVersion": 1, "identity": identity_fields(ctx), "rootCustody": list(b.custody(root.lstat())),
             "entries": entries}
    need(len(b.canonical(value)) <= 16 * MIB and b.DATA.known, "cleanup-manifest-bound-or-finality")
    atomic_record(root / "cleanup.json", value)


def completed_build_valid(report, ctx, outcome):
    """A workflow outcome AND the original native owner's closed report agree."""
    need(outcome in {"success", "failure"} and type(report) is dict
         and type(report.get("schemaVersion")) is int and report["schemaVersion"] == 1
         and report.get("sourceCommit") == ctx["sourceCommit"] and report.get("target") == ctx["target"]
         and report.get("runId") == ctx["run"] and report.get("runAttempt") == ctx["attempt"]
         and report.get("lifetime") == {"complete": True, "fatal": False, "contained": True}
         and all(type(report["lifetime"][key]) is bool for key in report["lifetime"])
         and report.get("handlers") == "RESTORED" and report.get("dataFinality") == "KNOWN",
         "retirement-original-build-finality")
    need(report.get("state") == ("qualified-supplier" if outcome == "success" else "failed-no-supplier"),
         "retirement-original-build-state")
    return True


def retire(ctx, preparation_outcome, build_outcome):
    """Apple bootstrap runs this only after the actual workflow step ended.

    Missing/unknown/cancelled original completion preserves the runtime. A
    failed native command is not in itself unknown completion; the original
    owner must nevertheless report all process/FD/handler finality as known.
    """
    b, root = build_data(), ctx["root"]
    need(preparation_outcome in {"success", "failure"} and build_outcome in {"success", "failure", "skipped"},
         "retirement-step-outcome")
    preparation = read_record(root / "public/evidence/prepare-result.json", maximum=2 * MIB)
    need(type(preparation) is dict and preparation.get("identity") == identity_fields(ctx)
         and preparation.get("originalsKnown") is True and preparation.get("handlersRestored") is True
         and preparation.get("cleanupRecorded") is True, "retirement-preparation-finality")
    if preparation_outcome == "success":
        need(preparation.get("prepared") is True, "retirement-ready-outcome")
        prepared_layout(ctx)
        completed_build_valid(read_record(ctx["buildRoot"] / "public/evidence/run-result.json", maximum=MIB),
                              ctx, build_outcome)
    else:
        need(preparation.get("prepared") is False and build_outcome == "skipped", "retirement-failed-preparation")
    cleanup_path = root / "cleanup.json"
    cleanup_original = identity(cleanup_path.lstat())
    cleanup = read_record(cleanup_path)
    need(type(cleanup) is dict and set(cleanup) == {"schemaVersion", "identity", "rootCustody", "entries"}
         and type(cleanup["schemaVersion"]) is int and cleanup["schemaVersion"] == 1
         and cleanup["identity"] == identity_fields(ctx)
         and cleanup["rootCustody"] == list(b.custody(root.lstat()))
         and stat.S_IMODE(root.lstat().st_mode) == 0o700, "retirement-cleanup-identity")
    entries = cleanup["entries"]
    need(type(entries) is dict and set(entries) <= {"home", "tmp", "empty-providers", "python-3.14.7.pkg",
         "expanded", "Python.framework", "preparing.json", "ready.json"}
         and {row.name for row in b.directory_entries(root)} == set(entries) | {"cleanup.json", "public"},
         "retirement-complete-root-roster")
    deadline = time.monotonic() + SETTLE_SECONDS
    # PRE all originals before removing even the first child. No global cache,
    # installed framework or unrelated runner path is ever in this inventory.
    for name, row in entries.items():
        path = root / name
        if row.get("kind") == "directory":
            need(scan_tree(path, deadline=deadline) == row.get("inventory"), "retirement-tree-originals")
        else:
            need(row.get("kind") == "file" and list(identity(path.lstat())) == row.get("identity"),
                 "retirement-file-original")
            b.read(path, FILE_LIMIT, expected=(row["size"], row["sha256"]))
    need(b.DATA.known, "retirement-data-originals")
    for name, row in entries.items():
        path = root / name
        if row["kind"] == "directory":
            retire_tree(path, row["inventory"], known=True, deadline=deadline)
        else:
            need(list(identity(path.lstat())) == row["identity"], "retirement-file-post")
            path.unlink()
    need(identity(cleanup_path.lstat()) == cleanup_original and b.DATA.known,
         "retirement-cleanup-original-post")
    cleanup_sha = hashlib.sha256(b.canonical(cleanup)).hexdigest()
    cleanup_path.unlink()
    need({row.name for row in b.directory_entries(root)} == {"public"}
         and list(b.custody(root.lstat())) == cleanup["rootCustody"] and b.DATA.known,
         "retirement-final-post")
    atomic_record(root / "public/evidence/retirement-result.json", {
        "schemaVersion": 1, "identity": identity_fields(ctx), "orchestratorRetired": True,
        "preparationOutcome": preparation_outcome, "buildOutcome": build_outcome,
        "originalsKnown": True, "cleanupSha256": cleanup_sha, "retiredEntries": len(entries)})


def prepare(ctx):
    b = build_data()
    root = ctx["root"]
    need(not root.exists() and not root.is_symlink(), "preparation-root-collision")
    before = b.source_snapshot(b.CHECKOUT, ctx["target"])
    root.mkdir(mode=0o700)
    (root / "home").mkdir(mode=0o700)
    (root / "tmp").mkdir(mode=0o700)
    provider = root / "empty-providers"
    provider.mkdir(mode=0o700)
    os.chmod(provider, 0o555)
    original_root = list(b.custody(root.lstat()))
    role_paths = {"sandbox": "/usr/bin/sandbox-exec", "download": "/usr/bin/curl",
                  "package": "/usr/sbin/pkgutil", "relocate": str(b.DEVELOPER / "usr/bin/install_name_tool"),
                  "sign": "/usr/bin/codesign", "probe": str(Path(sys.executable).resolve())}
    engine = FixedCalls(root, role_paths)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(root / "home"),
           "TMPDIR": str(root / "tmp") + "/", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
           "DEVELOPER_DIR": str(b.DEVELOPER)}
    route = {key: value for key, value in os.environ.items() if key in {
        "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "GITHUB_REPOSITORY",
        "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
        "GITHUB_WORKSPACE", "RUNNER_TEMP", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"}}
    scoped_env = {**env, **route}
    script = str(b.CHECKOUT / "desktop/tools/macos_cpython_orchestrator.py")
    policy_known, ready, failure, cancellation = False, None, None, None
    package_signature = None
    try:
        with cancellation_state() as cancellation:
            engine.cancellation = cancellation
            originals = [protected_apple(path) for path in role_paths.values()]
            originals.append(protected_apple(sys.executable))
            engine.original_tools = originals
            proof = engine.run("probe", ["-I", "-S", "-B", script, "primitive-probe"],
                               environment=scoped_env, maximum=30)
            observation = b.decode(proof["stdout"])
            need(type(observation) is dict and set(observation) == {"fork", "posix_spawn"}
                 and all(type(row) is dict and set(row) == {"denied", "errno", "created", "joined"}
                         and row["denied"] is True and row["errno"] in {1, 13}
                         and row["created"] is False and row["joined"] is False for row in observation.values()),
                 "native-process-creation-not-denied")
            policy_known = True
            capacity = os.statvfs(root)
            need(capacity.f_bavail * capacity.f_frsize >= 4 * 1024 * MIB, "preparation-disk-reserve")
            package = root / "python-3.14.7.pkg"
            engine.run("download", ["--disable", "--fail", "--proto", "=https", "--tlsv1.2",
                       "--connect-timeout", "15", "--max-time", "120", "--max-filesize", str(PACKAGE_LIMIT),
                       "--output", str(package), PACKAGE_URL], environment=env, online=True)
            package_body = b.read(package, PACKAGE_LIMIT)
            package_binding(len(package_body), hashlib.sha256(package_body).hexdigest())
            del package_body
            signature = engine.run("package", ["--check-signature", str(package)], environment=env)
            package_signature = {"commandIndex": len(engine.records) - 1,
                                 **package_signature_observation(signature["stdout"])}
            text = signature["stdout"].decode("utf-8", "strict")
            need("signed by a certificate trusted by" in text
                 and re.search(r"Developer ID Installer: Python Software Foundation \([A-Z0-9]{10}\)", text),
                 "package-trusted-PSF-signature")
            expanded = root / "expanded"
            engine.run("package", ["--expand-full", str(package), str(expanded)], environment=env)
            inventory = scan_tree(expanded, deadline=engine.deadline - SETTLE_SECONDS)
            selected = select_framework(expanded, inventory)
            original_rows = scan_tree(selected, closure=True, deadline=engine.deadline - SETTLE_SECONDS)
            capacity = os.statvfs(root)
            need(capacity.f_bavail * capacity.f_frsize >= SELECTED_LIMIT + 1024 * MIB, "preparation-copy-reserve")
            framework = root / "Python.framework"
            copied = copy_framework(selected, framework, original_rows, deadline=engine.deadline - SETTLE_SECONDS)
            images, transformations = set(), []
            for name, row in copied.items():
                if row["kind"] != "file":
                    continue
                path = framework / name
                body = native_image_bytes(path, ctx["machine"])
                if body is not None:
                    images.add(name)
                    replace_owned_file(path, body)
            need(ENTRY_RELATIVE in images and VERSION_RELATIVE + "/Python" in images and len(images) <= 1024,
                 "framework-image-roster")
            for name in sorted(images):
                path = framework / name
                body = b.read(path, FILE_LIMIT)
                plan = relocation_plan(body, ctx["machine"], name, copied, images)
                if plan["arguments"]:
                    engine.run("relocate", [*plan["arguments"], str(path)], environment=env)
                changed = b.read(path, FILE_LIMIT)
                records = macho_records(changed, ctx["machine"])
                actual = [(row["command"], row["text"]) for row in records if "text" in row]
                need(actual == plan["expected"], "relocated-load-command-correspondence")
                macho_content_valid(body, changed, ctx["machine"])
                transformations.append({"path": name, "sliceSha256": hashlib.sha256(body).hexdigest(),
                                        "relocatedSha256": hashlib.sha256(changed).hexdigest(), **plan})
            for name in sorted(images, key=lambda value: (-value.count("/"), value)):
                path = framework / name
                old = b.read(path, FILE_LIMIT)
                engine.run("sign", ["--force", "--sign", "-", "--timestamp=none", str(path)], environment=env)
                engine.run("sign", ["--verify", "--strict", str(path)], environment=env)
                macho_content_valid(old, b.read(path, FILE_LIMIT), ctx["machine"], signing=True)
            signed_rows = scan_tree(framework, closure=True, deadline=engine.deadline - SETTLE_SECONDS)
            # Signing each Mach-O path is not bundle signing. It may update
            # that image's signature blob but cannot add unrelated resources,
            # replace aliases, or change any authenticated non-image file.
            need(set(signed_rows) == set(copied), "signing-inventory-changed")
            for name, row in copied.items():
                current = signed_rows[name]
                need(current["kind"] == row["kind"], "signing-entry-kind")
                if row["kind"] == "link":
                    need(current == row, "signing-alias-changed")
                elif row["kind"] == "file" and name not in images:
                    need(current == row, "signing-nonimage-changed")
            seal_framework(framework, signed_rows)
            final_rows = scan_tree(framework, readonly=True, closure=True, deadline=engine.deadline - SETTLE_SECONDS)
            preparing = {"schemaVersion": 1, "state": "PREPARED-NOT-READY", "identity": identity_fields(ctx),
                         "packageSha256": PACKAGE_SHA256, "rootCustody": original_root,
                         "framework": final_rows, "providerIdentity": list(identity(provider.lstat()))}
            atomic_record(root / "preparing.json", preparing)
            engine.tools["runtime"] = str(framework / ENTRY_RELATIVE)
            facts_result = engine.run("runtime", ["-I", "-S", "-B", script, "check-runtime"],
                                      environment=orchestration_environment(scoped_env, root), maximum=30)
            facts = b.decode(facts_result["stdout"])
            runtime_facts_valid(facts, root, ctx["machine"])
            need(scan_tree(framework, readonly=True, closure=True,
                           deadline=engine.deadline - SETTLE_SECONDS) == final_rows, "runtime-check-original-post")
            recheck_apple(originals)
            source_post(before, ctx)
            need(engine.clock() < engine.deadline - SETTLE_SECONDS, "preparation-deadline")
            need(not cancellation["cancelled"] and engine.known and b.DATA.known and engine.active is None,
                 "preparation-original-finality")
            retire_tree(expanded, inventory, known=True, deadline=engine.deadline)
            expected_package = b.read(package, PACKAGE_LIMIT)
            package_binding(len(expected_package), hashlib.sha256(expected_package).hexdigest())
            package.unlink()
            ready = {**preparing, "state": "READY", "originalsKnown": True, "handlersRestored": True,
                     "intermediatesRetired": True}
        need(engine.clock() < engine.deadline, "preparation-deadline")
        need(not cancellation["cancelled"], "preparation-cancelled")
    except BaseException as error:
        failure = error
    known = (policy_known or not engine.records) and engine.known and b.DATA.known and engine.active is None
    known = known and cancellation is not None and cancellation["restored"]
    cleanup_recorded = False
    if known:
        try:
            if failure is None:
                need(ready is not None, "preparation-ready-finality")
                need(engine.clock() < engine.deadline, "preparation-deadline")
                need(not cancellation["cancelled"], "preparation-cancelled")
                atomic_record(root / "ready.json", ready)
                need(engine.clock() < engine.deadline, "preparation-deadline")
                need(not cancellation["cancelled"], "preparation-cancelled")
            capture_cleanup(ctx, deadline=engine.deadline)
            cleanup_recorded = True
            if failure is None:
                need(engine.clock() < engine.deadline, "preparation-deadline")
                need(not cancellation["cancelled"], "preparation-cancelled")
        except BaseException as error:
            if failure is None:
                failure = error
        known = known and b.DATA.known
    # Fixed, bounded public facts only. Raw captured tool output stays private.
    if known:
        public = root / "public"
        public.mkdir(mode=0o700)
        (public / "evidence").mkdir(mode=0o700)
        if failure is None:
            try:
                need(engine.clock() < engine.deadline, "preparation-deadline")
                need(not cancellation["cancelled"], "preparation-cancelled")
            except BaseException as error:
                failure = error
        code = str(failure) if type(failure) is PreparationRefused else "original-preparation-failed"
        need(failure is None or re.fullmatch(r"[a-zA-Z0-9-]{1,160}", code), "preparation-diagnostic-code")
        atomic_record(public / "evidence/prepare-result.json", {
            "schemaVersion": 1, "identity": identity_fields(ctx), "packageSha256": PACKAGE_SHA256,
            "prepared": failure is None, "originalsKnown": known, "handlersRestored": True,
            "cleanupRecorded": cleanup_recorded, "commands": engine.records,
            "packageSignature": package_signature,
            "failure": None if failure is None else {"code": code, "type": type(failure).__name__}})
    if failure is not None:
        raise failure
    need(known and cleanup_recorded and b.DATA.known, "preparation-finality-unknown")
    # Publication is provisional: the original caller must also succeed.
    # A late final write is a failed step; retained DATA cannot admit a build.
    need(engine.clock() < engine.deadline, "preparation-deadline")
    need(not cancellation["cancelled"], "preparation-cancelled")


def main():
    need(len(sys.argv) in {2, 4} and sys.argv[1] in {"prepare", "build", "check-runtime", "retire", "primitive-probe"},
         "preparation-command")
    mode = sys.argv[1]
    need(len(sys.argv) == (4 if mode == "retire" else 2), "preparation-command-arguments")
    ctx = context()
    os.umask(0o077)
    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    need(limits[0] == resource.RLIM_INFINITY or limits[0] > 0, "preparation-descriptor-bound")
    if limits[0] == resource.RLIM_INFINITY or limits[0] > 1024:
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, limits[1]))
    need(0 < resource.getrlimit(resource.RLIMIT_NOFILE)[0] <= 1024
         and resource.getrlimit(resource.RLIMIT_NOFILE)[1] == limits[1], "preparation-descriptor-bound")
    if mode == "primitive-probe":
        result = primitive_probe()
    elif mode == "check-runtime":
        _, result = verify_prepared(ctx, ready=False)
    elif mode == "build":
        enter_build(ctx)
        raise PreparationRefused("prepared-entry-unexpected-return")
    else:
        if mode == "prepare":
            protected_apple(sys.executable)
            prepare(ctx)
        else:
            protected_apple(sys.executable)
            retire(ctx, sys.argv[2], sys.argv[3])
        result = {"operation": mode, "complete": True}
    need(build_data().DATA.known, "preparation-final-descriptor-state")
    print(build_data().canonical(result).decode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        code = str(error) if type(error) is PreparationRefused else "original-preparation-failed"
        if re.fullmatch(r"[a-zA-Z0-9-]{1,160}", code) is None:
            code = "original-preparation-failed"
        print("Protected orchestration preparation refused: " + code, file=sys.stderr)
        raise SystemExit(1) from None
