#!/usr/bin/env python3
"""Bounded metadata observation only; no vendor execution or installation.

Root supplies an explicit fixture roster. This is NOT runtime/tool admission,
complete supplier provenance, full payload hashing or native build evidence.
No environment/PATH discovery, network, subprocess, package install or license
operation occurs. All supplier paths remain private; output uses fixed labels.
"""
from __future__ import annotations
import hashlib
import json
import os
import plistlib
import time
import stat
import struct
import sys

READ_LIMIT = 128 * 1024 * 1024
ENTRY_LIMIT = 32768
OUTPUT_LIMIT = 256 * 1024
COMMAND_LIMIT = 256 * 1024
ROOTS = ("jdkHome", "sdkPlatform", "sdkBuildTools", "gradleRoot")
INPUTS = ROOTS + ("gradleLauncher", "agpAapt2", "bundletool")
# Only public supplier files. No project/HOME traversal or generic glob.
RELATIVE = {
    "jdkHome": ("release", "bin/java", "bin/javac", "bin/jarsigner", "bin/keytool",
                "lib/libjli.dylib", "lib/server/libjvm.dylib"),
    "sdkPlatform": ("source.properties",),
    "sdkBuildTools": ("source.properties", "aapt2", "zipalign", "apksigner", "d8", "r8"),
    "gradleRoot": ("bin/gradle",),
}
def nine(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

class Refused(Exception):
    pass

class Deadline(Refused):
    """Whole-capture refusal; never downgraded to an individual missing role."""
    pass

class Readers:
    def __init__(self):
        self.end = time.monotonic() + 90
        self.deadline_reached = False
        self.active = []
        self.errors = []
        self.read_bytes = 0
        self.entries = 0
        self.stdio = {fd: nine(os.fstat(fd))[:5] for fd in (0, 1, 2)}
    def expired(self):
        self.deadline_reached = self.deadline_reached or time.monotonic() >= self.end
        return self.deadline_reached
    def checkpoint(self):
        if self.expired():
            raise Deadline("wall_bound")
    def open(self, name, parent=None, folder=False, shared=False):
        self.checkpoint()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        if folder:
            flags |= os.O_DIRECTORY
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self.checkpoint()
        fd = os.open(name, flags, dir_fd=parent)
        # Register returned original before any subsequent failure.
        self.active.append((fd, parent, name, nine(before), shared))
        self.checkpoint()
        after = os.fstat(fd)
        if nine(before) != nine(after) or (folder and not stat.S_ISDIR(after.st_mode)):
            raise Refused("changed_original")
        if not folder and (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1):
            raise Refused("not_regular_single_link")
        self.checkpoint()
        return fd
    def path(self, value, folder=False):
        self.checkpoint()
        if not isinstance(value, str) or len(value) > 4096 or not value.startswith("/"):
            raise Refused("invalid_fixture_path")
        parts = value.split("/")[1:]
        if not parts or any(not part or part in (".", "..") for part in parts):
            raise Refused("invalid_fixture_path")
        parent = self.open("/", folder=True, shared=True)
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            parent = self.open(part, parent, folder=not last or folder, shared=not last)
        return parent
    def close_from(self, mark):
        while len(self.active) > mark:
            fd, parent, name, before, shared = self.active.pop()
            try:
                held = nine(os.fstat(fd))
                named = nine(os.stat(name, dir_fd=parent, follow_symlinks=False))
                matches = held[:5] == before[:5] == named[:5] if shared else held == before == named
                if not matches:
                    self.errors.append("post_identity")
            except BaseException:
                self.errors.append("post_identity")
            finally:
                try:
                    os.close(fd)  # One consuming attempt, never a numeric retry.
                except BaseException:
                    self.errors.append("close_unknown")
    def read_at(self, fd, offset, count, size):
        self.checkpoint()
        if count < 0 or offset < 0 or offset + count > size or self.read_bytes + count > READ_LIMIT:
            raise Refused("read_budget")
        self.read_bytes += count
        data = os.pread(fd, count, offset)
        self.checkpoint()
        if len(data) != count:
            raise Refused("short_read")
        return data
    def finish(self):
        self.close_from(0)
        for fd, original in self.stdio.items():
            try:
                if nine(os.fstat(fd))[:5] != original:
                    self.errors.append("stdio_identity")
            except BaseException:
                self.errors.append("stdio_identity")

def safe_load(value):
    # Public relative/system load references are useful; host-private paths are
    # represented only by a category and digest, never copied into output.
    if value in ("/bin/sh", "/bin/bash", "/usr/bin/env sh", "/usr/bin/env bash") or value.startswith(("@loader_path", "@executable_path", "@rpath", "/System/Library/", "/usr/lib/")):
        return {"reference": value}
    return {"reference": "non_system_or_relative", "sha256": hashlib.sha256(value.encode()).hexdigest()}

def macho(reader, fd, size):
    if size < 4:
        return {"kind": "short"}
    magic = reader.read_at(fd, 0, 4, size)
    offsets = [(0, size)]
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        endian = ">" if magic[:1] == b"\xca" else "<"
        wide = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
        count = struct.unpack(endian + "I", reader.read_at(fd, 4, 4, size))[0]
        if not 0 < count <= 16:
            raise Refused("native_header_bounds")
        stride = 32 if wide else 20
        table = reader.read_at(fd, 8, count * stride, size)
        offsets = []
        for index in range(count):
            entry = table[index * stride:(index + 1) * stride]
            offset, length = struct.unpack_from(endian + ("QQ" if wide else "II"), entry, 8)
            if offset + length > size or length < 32:
                raise Refused("native_header_bounds")
            offsets.append((offset, length))
    elif magic not in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return {"kind": "other", "magic": magic.hex()}
    slices = []
    native_text = 0
    native_loads = 0
    for base, length in offsets:
        header = reader.read_at(fd, base, 32, size)
        endian = "<" if header[:4] == b"\xcf\xfa\xed\xfe" else ">" if header[:4] == b"\xfe\xed\xfa\xcf" else None
        if endian is None:
            slices.append({"kind": "unsupported_slice"})
            continue
        cpu, commands, amount = struct.unpack_from(endian + "I8xII", header, 4)
        if commands > 8192 or amount > COMMAND_LIMIT or amount + 32 > length:
            raise Refused("native_header_bounds")
        body = reader.read_at(fd, base + 32, amount, size)
        at = 0
        loads = []
        for _ in range(commands):
            if at + 8 > len(body):
                raise Refused("native_header_bounds")
            command, width = struct.unpack_from(endian + "II", body, at)
            if width < 8 or width % 8 or at + width > len(body):
                raise Refused("native_header_bounds")
            if command in (0xC, 0x80000018, 0x8000001F, 0x80000023, 0x20, 0x8000001C):
                if width < 12:
                    raise Refused("native_header_bounds")
                start = struct.unpack_from(endian + "I", body, at + 8)[0]
                if not 12 <= start < width:
                    raise Refused("native_header_bounds")
                field = body[at + start:at + width]
                if b"\0" not in field:
                    raise Refused("native_header_bounds")
                raw = field.split(b"\0", 1)[0]
                native_text += len(raw) + 64
                native_loads += 1
                if not raw or len(raw) > 4096 or native_text > 8192 or native_loads > 128:
                    raise Refused("native_header_bounds")
                reference = raw.decode("utf-8", errors="strict")
                loads.append({"type": "rpath" if command == 0x8000001C else "load", **safe_load(reference)})
            at += width
        if at != len(body):
            raise Refused("native_header_bounds")
        slices.append({"cpu": cpu, "architecture": {0x0100000C: "arm64", 0x01000007: "x86_64"}.get(cpu, "other"), "loads": loads})
    return {"kind": "macho", "slices": slices}

def fixed_file(reader, label, value):
    reader.checkpoint()
    if value is None:
        return {"role": label, "status": "missing_fixture_input"}
    mark = len(reader.active)
    try:
        fd = reader.path(value)
        info = os.fstat(fd)
        size = info.st_size
        prefix = reader.read_at(fd, 0, min(size, 4096), size)
        result = {"role": label, "status": "observed", "bytes": size,
                  "mode": oct(stat.S_IMODE(info.st_mode)), "contentSha256": None}
        if prefix.startswith(b"#!"):
            line = prefix.split(b"\n", 1)[0]
            if len(line) > 256:
                raise Refused("script_header_bounds")
            result["format"] = {"kind": "script", "shebang": safe_load(line[2:].decode("ascii", errors="strict").strip())}
        else:
            result["format"] = macho(reader, fd, size)
        if label.endswith("/release") or label.endswith("/source.properties"):
            wanted = {"JAVA_VERSION", "IMPLEMENTOR", "OS_ARCH", "Pkg.Revision", "AndroidVersion.ApiLevel"}
            result["versionFields"] = {}
            for line in prefix.decode("utf-8", errors="strict").splitlines():
                key, found, value_text = line.partition("=")
                if found and key.strip() in wanted:
                    result["versionFields"][key.strip()] = value_text.strip()[:128]
        if size <= READ_LIMIT - reader.read_bytes:
            digest = hashlib.sha256()
            for offset in range(0, size, 65536):
                digest.update(reader.read_at(fd, offset, min(65536, size - offset), size))
            result["contentSha256"] = digest.hexdigest()
        else:
            result["contentHashStatus"] = "not_read_budget"
        return result
    except FileNotFoundError:
        return {"role": label, "status": "missing"}
    except Deadline:
        raise
    except Refused as error:
        return {"role": label, "status": "refused_metadata", "reason": str(error)}
    except (OSError, UnicodeError, struct.error):
        return {"role": label, "status": "refused_metadata", "reason": "unreadable_or_unsupported_original"}
    finally:
        reader.close_from(mark)

def metadata_tree(reader, label, value):
    reader.checkpoint()
    if value is None:
        return {"role": label, "status": "missing_fixture_input"}
    mark = len(reader.active)
    totals = {"entries": 0, "files": 0, "bytes": 0, "aliases": 0}
    digest = hashlib.sha256()
    try:
        top = reader.path(value, folder=True)
        def visit(parent, prefix, depth):
            reader.checkpoint()
            if depth > 32:
                raise Refused("metadata_depth")
            names = os.listdir(parent)
            reader.checkpoint()
            if len(names) > ENTRY_LIMIT:
                raise Refused("metadata_entries")
            for name in sorted(names):
                reader.checkpoint()
                relative = prefix + name
                if len(relative.encode("utf-8")) > 2048 or name in (".", ".."):
                    raise Refused("metadata_names")
                reader.entries += 1
                totals["entries"] += 1
                if reader.entries > ENTRY_LIMIT:
                    raise Refused("metadata_entries")
                item = os.stat(name, dir_fd=parent, follow_symlinks=False)
                reader.checkpoint()
                row = [relative, item.st_mode, item.st_size]
                if stat.S_ISDIR(item.st_mode):
                    child_mark = len(reader.active)
                    child = reader.open(name, parent, folder=True)
                    digest.update(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
                    visit(child, relative + "/", depth + 1)
                    reader.close_from(child_mark)
                elif stat.S_ISREG(item.st_mode):
                    if item.st_nlink != 1:
                        raise Refused("metadata_hardlink")
                    totals["files"] += 1
                    totals["bytes"] += item.st_size
                    digest.update(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
                elif stat.S_ISLNK(item.st_mode):
                    target = os.readlink(name, dir_fd=parent)
                    reader.checkpoint()
                    if len(target) > 4096:
                        raise Refused("metadata_alias")
                    totals["aliases"] += 1
                    row.append(hashlib.sha256(target.encode()).hexdigest())
                    digest.update(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
                else:
                    raise Refused("metadata_type")
        visit(top, "", 0)
        return {"role": label, "status": "observed", **totals, "metadataRosterSha256": digest.hexdigest(),
                "completePayloadHashes": False, "consistency": "per_entry_named_snapshots_not_frozen_roster"}
    except FileNotFoundError:
        return {"role": label, "status": "missing"}
    except Deadline:
        raise
    except Refused as error:
        return {"role": label, "status": "refused_metadata", "reason": str(error), **totals, "completePayloadHashes": False}
    except (OSError, UnicodeError):
        return {"role": label, "status": "refused_metadata", "reason": "unreadable_or_unsupported_original", **totals, "completePayloadHashes": False}
    finally:
        reader.close_from(mark)

def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("duplicate_roster_field")
        result[key] = value
    return result

def host_version(reader):
    mark = len(reader.active)
    try:
        fd = reader.path("/System/Library/CoreServices/SystemVersion.plist")
        size = os.fstat(fd).st_size
        if size > 32768:
            raise Refused("host_version_bounds")
        value = plistlib.loads(reader.read_at(fd, 0, size, size))
        selected = {key: value.get(key) for key in ("ProductVersion", "ProductBuildVersion")}
        if any(not isinstance(item, str) or len(item) > 64 for item in selected.values()):
            raise Refused("host_version_schema")
        return selected
    finally:
        reader.close_from(mark)

def main():
    reader = Readers()
    result = {"schemaVersion": 1, "qualification": "metadata_only_not_admission_or_execution"}
    code = 78
    try:
        if (sys.platform != "darwin" or os.uname().machine != "arm64" or len(sys.argv) != 2
                or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
                or sys.version_info < (3, 11)):
            raise Refused("unsupported_probe_host_or_arguments")
        reader.checkpoint()
        mark = len(reader.active)
        fd = reader.path(sys.argv[1])
        size = os.fstat(fd).st_size
        if size > 32768:
            raise Refused("roster_bounds")
        raw = reader.read_at(fd, 0, size, size)
        roster = json.loads(raw, object_pairs_hook=closed_object)
        reader.close_from(mark)
        if not isinstance(roster, dict) or set(roster) != set(INPUTS) or any(
            value is not None and not isinstance(value, str) for value in roster.values()
        ):
            raise Refused("closed_roster")
        result["inputRosterSha256"] = hashlib.sha256(raw).hexdigest()
        result["nativeHost"] = {"system": os.uname().sysname, "release": os.uname().release, "machine": os.uname().machine, **host_version(reader)}
        result["roles"] = []
        for root in ROOTS:
            for relative in RELATIVE[root]:
                value = None if roster[root] is None else roster[root] + "/" + relative
                result["roles"].append(fixed_file(reader, root + "/" + relative, value))
        for key in ("gradleLauncher", "agpAapt2", "bundletool"):
            result["roles"].append(fixed_file(reader, key, roster[key]))
        result["trees"] = [metadata_tree(reader, root, roster[root]) for root in ROOTS]
        reader.checkpoint()
        result["status"] = "captured" if all(item["status"] == "observed" for item in result["roles"] + result["trees"]) else "captured_with_missing_or_refused_inputs"
        code = 0 if result["status"] == "captured" else 2
    except Refused as error:
        result["status"] = "probe_refused"
        result["reason"] = str(error)
        code = 78
    except BaseException:
        result["status"] = "probe_refused"
        result["reason"] = "invalid_or_unavailable_input"
        code = 78
    finally:
        reader.finish()
    if reader.expired():
        result["status"] = "probe_refused"
        result["reason"] = "wall_bound"
        code = 78
    result["readBytes"] = reader.read_bytes
    result["cleanup"] = "known_closed" if not reader.errors else "unknown"
    if reader.errors:
        code = 79
    raw = (json.dumps(result, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > OUTPUT_LIMIT:
        raw = b'{"schemaVersion":1,"status":"output_bound","qualification":"none"}\n'
        code = 78
    sys.stdout.buffer.write(raw)
    return code

if __name__ == "__main__":
    raise SystemExit(main())
