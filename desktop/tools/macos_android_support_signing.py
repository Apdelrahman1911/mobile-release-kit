#!/usr/bin/env python3
"""Fixed, once-signed Android DATA supplier; native work uses existing Operation."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
from pathlib import Path
import stat
import struct
import sys
import time
import zipfile
import zlib

PHASE = "android-support-shipping"
REF = "refs/heads/verify/desktop-macos-android-support-signing"
WORKFLOW = "desktop-macos-android-support-signing.yml"
PREFIX = "mrk-macos-android-support-signing"
WORK_SECONDS, HARD_SECONDS = 960, 1020
ARCHIVE_LIMIT, NATIVE_LIMIT = 48 * 1024 * 1024, 16 * 1024 * 1024
DECODED_LIMIT, ENTRY_LIMIT = 112 * 1024 * 1024, 16000
IDENTIFIERS = {role: "dev.mobile-release-kit.desktop.android-support." + role
               for role in ("bundletool-aapt2", "bundletool-jna", "agp-aapt2")}
SPECS = (
    {"name": "bundletool-all-1.18.3.jar", "size": 32520401,
     "sha256": "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29",
     "url": "https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar",
     "members": (("bundletool-aapt2", "macos/aapt2", 11186368,
                  "995cf1a04fb55045dd22ae3d6248f32d649bac9dfa7bf9357507499794051c6b"),
                 ("bundletool-jna", "com/sun/jna/darwin/libjnidispatch.jnilib", 180932,
                  "e8ad39879b107ed955388d29555ddbcff3ada41598780eef579246752dd96c75"))},
    {"name": "aapt2-8.9.2-12782657-osx.jar", "size": 4339472,
     "sha256": "5d0aec6851fffbc9f6c8a8b50390c0bc976aa0ddf57a8a3a39061ed54b609ad1",
     "url": "https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-osx.jar",
     "members": (("agp-aapt2", "aapt2", 11143368,
                  "213e3d049e2c85daa930ed777bbd5627c1c5479a8d6698029b8f9c0161ad0a7e"),)},
)
MEMBERS = tuple(member for spec in SPECS for member in spec["members"])
ROLES = tuple(role + suffix for role, *_ in MEMBERS for suffix in ("-sign", "-verify")) + tuple(
    role + "-final-verify" for role, *_ in MEMBERS)


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _native_magic(body):
    return (body[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
            or body[:4] == b"\xca\xfe\xba\xbe" and len(body) >= 8 and 1 <= int.from_bytes(body[4:8], "big") <= 8)


def _zip_metadata(entry):
    return [entry.filename, list(entry.date_time), entry.compress_type, entry.create_system,
            entry.create_version, entry.extract_version, entry.internal_attr, entry.external_attr,
            entry.extra.hex(), entry.comment.hex()]


def zip_data(body):
    """Complete bounded ZIP/CRC inventory; returned DATA is not upstream authority."""
    need(type(body) is bytes and 22 <= len(body) <= ARCHIVE_LIMIT, "archive-bound")
    end = body[-22:]
    need(end[:4] == b"PK\x05\x06", "archive-terminal-directory")
    disk, central_disk, disk_count, count, size, offset, comment = struct.unpack_from("<HHHHIIH", end, 4)
    need(disk == central_disk == comment == 0 and disk_count == count and 0 < count <= ENTRY_LIMIT
         and offset + size == len(body) - 22, "archive-directory-bound")
    rows, natives, names, decoded, local_end = [], {}, set(), 0, 0
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        entries = archive.infolist()
        need(len(entries) == count and not archive.comment, "archive-complete-directory")
        for entry in entries:
            name = entry.filename
            need(type(name) is str and 0 < len(name.encode("utf-8")) <= 4096 and name not in names
                 and not name.startswith("/") and "\\" not in name and "\x00" not in name
                 and all(p not in ("", ".", "..") for p in name.rstrip("/").split("/")), "archive-member-name")
            names.add(name)
            mode = entry.external_attr >> 16
            need(entry.flag_bits in (0, 2048) and entry.compress_type in (0, 8) and not entry.extra
                 and stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)
                 and 0 <= entry.file_size <= NATIVE_LIMIT and entry.header_offset == local_end < offset,
                 "archive-member-policy")
            decoded += entry.file_size
            need(decoded <= DECODED_LIMIT, "archive-decoded-bound")
            upper = name.upper()
            leaf = upper.rsplit("/", 1)[-1]
            need(not (upper.startswith("META-INF/") and (leaf.endswith((".SF", ".RSA", ".DSA", ".EC"))
                      or leaf.startswith("SIG-"))), "archive-java-signature")
            # Actual originals have no data descriptors/ZIP64. Admit matching local values.
            header = body[entry.header_offset:entry.header_offset + 30]
            need(len(header) == 30 and header[:4] == b"PK\x03\x04", "archive-local-header")
            flags, compression = struct.unpack_from("<HH", header, 6)
            crc, compressed, length, name_length, extra_length = struct.unpack_from("<IIIHH", header, 14)
            need(flags == entry.flag_bits and compression == entry.compress_type and crc == entry.CRC
                 and compressed == entry.compress_size and length == entry.file_size and extra_length == 0
                 and entry.header_offset + 30 + name_length + compressed <= offset, "archive-local-central-join")
            local_end = entry.header_offset + 30 + name_length + compressed
            with archive.open(entry) as source:
                digest, prefix, total = hashlib.sha256(), b"", 0
                selected = bytearray() if name in {m[1] for m in MEMBERS} or name == "META-INF/MANIFEST.MF" else None
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    need(total <= entry.file_size, "archive-member-growth")
                    digest.update(block)
                    if len(prefix) < 32:
                        prefix += block[:32 - len(prefix)]
                    if selected is not None:
                        selected.extend(block)
                need(total == entry.file_size, "archive-member-truncated")
            need(not prefix.startswith(b"PK\x03\x04"), "archive-nested-zip")
            if _native_magic(prefix):
                need(selected is not None and name != "META-INF/MANIFEST.MF", "archive-unexpected-native")
                natives[name] = bytes(selected)
            if name == "META-INF/MANIFEST.MF":
                need(total <= 65536 and b"-digest" not in bytes(selected).lower(), "archive-manifest-signature")
            rows.append({"metadata": _zip_metadata(entry), "size": total, "sha256": digest.hexdigest()})
    need(local_end == offset, "archive-local-complete")
    return {"rows": rows, "native": natives, "decodedBytes": decoded, "inventorySha256": sha(canonical(rows))}


def repack(original, replacements):
    need(type(replacements) is dict and replacements and all(type(k) is str and type(v) is bytes
         and 0 < len(v) <= NATIVE_LIMIT for k, v in replacements.items()), "replacement-contract")
    before = zip_data(original)
    need(set(replacements) == set(before["native"]), "replacement-exact-native-roster")
    # Fixed no-ZIP64 originals: retain every original metadata byte and all
    # non-native compressed bytes. General ZipFile writers normalize version10
    # to20, which would unnecessarily alter this known upstream metadata.
    central_size, central_offset = struct.unpack_from("<II", original, len(original) - 10)
    directory, records, position = original[central_offset:central_offset + central_size], [], 0
    output, updated = io.BytesIO(), []
    with zipfile.ZipFile(io.BytesIO(original)) as source:
        for entry in source.infolist():
            need(directory[position:position + 4] == b"PK\x01\x02", "repack-central-record")
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", directory, position + 28)
            record_size = 46 + name_len + extra_len + comment_len
            record = bytearray(directory[position:position + record_size])
            need(len(record) == record_size, "repack-central-truncated")
            position += record_size
            local = entry.header_offset
            name_size, local_extra = struct.unpack_from("<HH", original, local + 26)
            header_size = 30 + name_size + local_extra
            header = bytearray(original[local:local + header_size])
            data = replacements.get(entry.filename)
            if data is None:
                compressed = original[local + header_size:local + header_size + entry.compress_size]
            else:
                encoder = zlib.compressobj(wbits=-15)
                compressed = (encoder.compress(data) + encoder.flush()) if entry.compress_type == 8 else data
                crc = zlib.crc32(data) & 0xffffffff
                struct.pack_into("<III", header, 14, crc, len(compressed), len(data))
                struct.pack_into("<III", record, 16, crc, len(compressed), len(data))
            need(output.tell() + len(header) + len(compressed) <= ARCHIVE_LIMIT, "derived-archive-bound")
            struct.pack_into("<I", record, 42, output.tell())
            output.write(header)
            output.write(compressed)
            updated.append(bytes(record))
    need(position == len(directory), "repack-central-complete")
    central = b"".join(updated)
    end = bytearray(original[-22:])
    struct.pack_into("<II", end, 12, len(central), output.tell())
    need(output.tell() + len(central) + 22 <= ARCHIVE_LIMIT, "derived-archive-bound")
    output.write(central)
    output.write(end)
    body = output.getvalue()
    after = zip_data(body)
    need(len(before["rows"]) == len(after["rows"]), "derived-member-count")
    for old, new in zip(before["rows"], after["rows"]):
        name = old["metadata"][0]
        need(old["metadata"] == new["metadata"], "derived-metadata-changed")
        need((new["size"], new["sha256"]) == ((len(replacements[name]), sha(replacements[name]))
             if name in replacements else (old["size"], old["sha256"])), "derived-content-changed")
    need(after["native"] == replacements, "derived-native-readback")
    return body


def macho_slices(body):
    need(type(body) is bytes and 32 <= len(body) <= NATIVE_LIMIT, "macho-bound")
    need(body[:4] == b"\xca\xfe\xba\xbe", "macho-fixed-universal")
    count = struct.unpack_from(">I", body, 4)[0]
    need(count == 2, "macho-fixed-two-slices")
    rows, previous, architectures = [], 48, set()
    for index in range(count):
        cpu, subtype, offset, size, alignment = struct.unpack_from(">iiIII", body, 8 + index * 20)
        need(cpu in (7, 0x1000007, 0x100000c) and cpu not in architectures and 12 <= alignment <= 14
             and offset >= previous and offset % (1 << alignment) == 0 and 32 <= size <= NATIVE_LIMIT
             and offset + size <= len(body) and not any(body[previous:offset]), "macho-fat-table")
        value = body[offset:offset + size]
        need(value[:4] == (b"\xce\xfa\xed\xfe" if cpu == 7 else b"\xcf\xfa\xed\xfe")
             and struct.unpack_from("<ii", value, 4) == (cpu, subtype), "macho-slice-header")
        architectures.add(cpu)
        rows.append((cpu, subtype, value))
        previous = offset + size
    need(previous == len(body) and architectures in ({7, 0x1000007}, {0x1000007, 0x100000c}), "macho-complete-slices")
    return rows


def _commands(body):
    header = 28 if body[:4] == b"\xce\xfa\xed\xfe" else 32
    need(body[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"), "slice-little-endian")
    count, size = struct.unpack_from("<II", body, 16)
    end, position, rows = header + size, header, []
    need(0 < count <= 256 and end <= len(body), "slice-commands-bound")
    for _ in range(count):
        need(position + 8 <= end, "slice-command-header")
        command, length = struct.unpack_from("<II", body, position)
        need(length >= 8 and length % 4 == 0 and position + length <= end, "slice-command-length")
        rows.append((command, body[position:position + length]))
        position += length
    need(position == end, "slice-command-complete")
    return header, end, rows


def _content(body):
    header, end, commands = _commands(body)
    fixed, signature, linkedit_count = [], None, 0
    for command, raw in commands:
        if command == 0x1d:
            need(signature is None and len(raw) == 16, "slice-signature-command")
            offset, length = struct.unpack_from("<II", raw, 8)
            need(offset >= end and length >= 12 and offset + length == len(body), "slice-signature-range")
            signature = offset
        else:
            if command in (1, 0x19) and raw[8:24].rstrip(b"\0") == b"__LINKEDIT":
                linkedit_count += 1
                need(len(raw) == (56 if command == 1 else 72), "slice-linkedit-shape")
                _address, memory, file_offset, file_size = struct.unpack_from("<IIII" if command == 1 else "<QQQQ", raw, 24)
                # The exact source originals end in LINKEDIT; codesign may
                # resize it only to contain the final signature allocation.
                need(file_offset >= end and file_offset + file_size == len(body)
                     and memory in {file_size, (file_size + 4095) // 4096 * 4096,
                                    (file_size + 16383) // 16384 * 16384}, "slice-linkedit-extent")
                if command == 1:
                    need(len(raw) == 56, "slice-linkedit32")
                    raw = raw[:28] + b"\0" * 4 + raw[32:36] + b"\0" * 4 + raw[40:]
                else:
                    need(len(raw) == 72, "slice-linkedit64")
                    raw = raw[:32] + b"\0" * 8 + raw[40:48] + b"\0" * 8 + raw[56:]
            fixed.append(raw)
    need(linkedit_count == 1, "slice-exact-linkedit")
    return header, end, signature if signature is not None else len(body), fixed


def content_unchanged(before, after):
    old, new = macho_slices(before), macho_slices(after)
    need([(r[0], r[1]) for r in old] == [(r[0], r[1]) for r in new], "signed-architecture-change")
    for (_, _, left), (_, _, right) in zip(old, new):
        oh, oe, ol, oc = _content(left)
        nh, ne, nl, nc = _content(right)
        need(oh == nh and left[:16] == right[:16] and left[24:oh] == right[24:nh], "signed-header-change")
        need(ne >= oe and not any(left[oe:ne]), "signed-command-overwrite")
        start, end = max(oe, ne), min(ol, nl)
        need(oc == nc and start <= end and left[start:end] == right[start:end]
             and not any(left[end:ol]) and not any(right[end:nl]), "signed-code-or-loader-change")


def signature_data(body, requires_runtime):
    need(type(requires_runtime) is bool, "runtime-purpose")
    facts = []
    for cpu, subtype, value in macho_slices(body):
        header, end, records = _commands(value)
        signatures = [raw for command, raw in records if command == 0x1d]
        need(len(signatures) == 1 and len(signatures[0]) == 16, "signed-slice-signature")
        offset, size = struct.unpack_from("<II", signatures[0], 8)
        need(offset >= end and 12 <= size <= 1024 * 1024 and offset + size == len(value), "signed-blob-range")
        blob = value[offset:]
        magic, extent, count = struct.unpack_from(">III", blob)
        need(magic == 0xfade0cc0 and 1 <= count <= 32 and 12 + count * 8 <= extent <= size, "signed-superblob")
        intervals, slots, flags, cms = [], set(), [], False
        for index in range(count):
            slot, start = struct.unpack_from(">II", blob, 12 + 8 * index)
            need(slot not in slots and 12 + count * 8 <= start <= extent - 8, "signed-index")
            slots.add(slot)
            kind, length = struct.unpack_from(">II", blob, start)
            stop = start + length
            need(length >= 8 and stop <= extent and all(stop <= a or start >= b for a, b in intervals), "signed-components")
            intervals.append((start, stop))
            if slot == 0 or 0x1000 <= slot < 0x1005:
                need(kind == 0xfade0c02 and length >= 44, "signed-code-directory")
                version, flag = struct.unpack_from(">II", blob, start + 8)
                need(0x20001 <= version <= 0x2f000 and not flag & 2
                     and (not requires_runtime or flag & 0x10000), "signed-code-flags")
                flags.append(flag)
            if slot == 0x10000:
                need(kind == 0xfade0b01 and length > 8, "signed-cms-wrapper")
                cms = True
        need(0 in slots and cms and flags and len(set(flags)) == 1, "signed-crypto-presence")
        facts.append({"cpuType": cpu, "cpuSubtype": subtype, "size": len(value), "sha256": sha(value),
                      "codeDirectoryFlags": flags, "cmsPresent": True})
    return facts


def clock(op, *, work=True):
    state = op.android_support
    now = time.monotonic_ns()
    need(type(now) is int and state["observed"] <= now < state["started"] + (WORK_SECONDS if work else HARD_SECONDS) * 10**9,
         "support-aggregate-deadline")
    state["observed"] = now
    return now, state["started"] + (WORK_SECONDS if work else HARD_SECONDS) * 10**9


def start(op, api, started):
    need(type(started) is int and started > 0 and op.phase == PHASE and op.target == api.ARM_TARGET,
         "support-original-start")
    op.android_support = {"started": started, "observed": started, "api": api, "pending": False,
        "complete": False, "retiring": False, "inputs": [], "sources": [], "outputs": {}, "delivery": {}, "receipt": None}
    clock(op)
    need(re.fullmatch(r"[0-9a-f]{40}", op.environment.get("MRK_ANDROID_SUPPORT_SOURCE_TREE", ""))
         and op.environment["MRK_ANDROID_SUPPORT_SOURCE_TREE"] != "0" * 40, "support-source-tree-observation")
    capacity = os.fstatvfs(op.work_entry["fd"])
    need(capacity.f_frsize > 0 and capacity.f_bavail * capacity.f_frsize >= 384 * 1024 * 1024, "support-disk-reserve")
    op.receipt.update(toolchain=None, helperIdentifier=None)


def known(op):
    return (not op.errors and op.credential_known() and not op.credential_failed and op.credential_active is None
            and not op.android_support["pending"] and not op.signing_mutation_pending
            and op.stager_io_pending is None and all(c.get("returned") is True and c.get("capturesSettled") is True
                and type(c.get("returncode")) is int and 0 <= c["returncode"] <= 255 for c in op.calls))


def dispatch(op, role):
    clock(op)
    need(type(role) is str and role in ROLES, "support-fixed-role")
    state = op.android_support
    final = role.endswith("-final-verify")
    context = op.credential_active
    expected_purpose = role.removesuffix("-final-verify").removesuffix("-verify").removesuffix("-sign")
    need((final and context is None and len(op.credential_contexts) == 3
          or not final and context is not None and context.get("purpose") == expected_purpose
          and context.get("ready") is True and not context.get("retiring")
          and context.get("roles") == (expected_purpose + "-sign", expected_purpose + "-verify")),
         "support-required-credential-context")
    need(not state["retiring"] and not op.errors and op.stager_io_pending is None
         and len(op.calls) < len(ROLES) and role == ROLES[len(op.calls)]
         and all(c.get("returned") is True and c.get("capturesSettled") is True and type(c.get("returncode")) is int
                 and c["returncode"] == 0 for c in op.calls)
         and op.signing_mutation_pending == role.endswith("-sign"), "support-native-dispatch")


def returned(op, role):
    clock(op)
    need(op.calls[-1]["role"] == role and op.calls[-1]["returncode"] == 0, "support-native-return")


def finish_ready(op):
    return known(op) and not op.android_support["pending"]


def success(op):
    api = op.android_support["api"]
    expected_credentials = (api.CREDENTIAL_ROLES[:17] + ("search-final", "default-after")) * 3
    return (op.android_support["complete"] and finish_ready(op)
            and tuple(c.get("role") for c in op.calls) == ROLES
            and all(type(c.get("returncode")) is int and c["returncode"] == 0 for c in op.calls)
            and tuple(c.get("role") for c in op.credential_calls) == expected_credentials
            and all(c.get("entered") is True and c.get("returned") is True and c.get("settled") is True
                    and type(c.get("status")) is int and c["status"] == 0 for c in op.credential_calls)
            and tuple(c.get("purpose") for c in op.credential_contexts) == tuple(r[0] for r in MEMBERS)
            and all(all(c.get(k) is True for k in ("closed", "retired", "searchRestored", "defaultUnchanged"))
                    for c in op.credential_contexts))


def _io(op, label, action):
    clock(op, work=not op.android_support["retiring"])
    need(op.stager_io_pending is None and not op.android_support["pending"], "support-io-overlap")
    op.stager_io_pending = label
    result = action()
    clock(op, work=not op.android_support["retiring"])
    op.stager_io_pending = None
    return result


def _mkdir(op, parent, name):
    _io(op, "support-mkdir", lambda: os.mkdir(name, 0o700, dir_fd=parent["fd"]))
    return op.directory(parent, name, "support-" + name)


def _write(op, parent, name, body, mode):
    api = op.android_support["api"]
    need(type(body) is bytes and 0 < len(body) <= ARCHIVE_LIMIT, "support-file-bound")
    def write():
        op.recheck_directory(parent)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent["fd"])
        entry = op.register(fd, "support-output-" + name, "file", parent["fd"], name)
        entry["parent_entry"] = parent
        offset = 0
        while offset < len(body):
            count = os.write(fd, body[offset:offset + 1024 * 1024])
            need(type(count) is int and count > 0, "support-short-write")
            offset += count
        os.fchmod(fd, mode)
        os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == mode, "support-created-file-policy")
        entry["identity"] = api.signature(info)
        need(op.read(entry) == body, "support-output-readback")
        return entry
    return _io(op, "support-write", write)


def _call(op, role, path, *, sign=False, requires_runtime=False):
    state, api = op.android_support, op.android_support["api"]
    role_name = role.removesuffix("-final-verify").removesuffix("-verify").removesuffix("-sign")
    identifier = IDENTIFIERS[role_name]
    requirement = api.signing_requirement(op.signing, identifier)
    if sign:
        command = ["/usr/bin/codesign", "--force", "--sign", op.signing[1], "--identifier", identifier, "--timestamp"]
        if requires_runtime:
            command += ["--options", "runtime", "--entitlements", str(op.checkout / "desktop/packaging/macos-empty-entitlements.plist")]
    else:
        command = ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "--test-requirement", "=" + requirement]
    now, endpoint = clock(op)
    return op.call(role, command + [str(path)], op.native_environment(), cwd=op.work,
                   timeout=api.package_timeout_data(now, endpoint, 30), limit=65536)


def _source(op, name, maximum):
    entry = op.source_original(name, "support-source-" + name.rsplit("/", 1)[-1], maximum)
    body = op.read(entry)
    op.android_support["sources"].append((entry, body))
    op.package_sources.append((entry, body))
    return body


def _post(op):
    clock(op, work=not op.android_support["retiring"])
    for entry, body in op.package_sources + op.android_support["inputs"]:
        need(op.read(entry) == body, "support-source-input-post")


def prepare(op):
    state, api = op.android_support, op.android_support["api"]
    need(op.signing is not None, "support-configured-identity")
    nomination = _source(op, "desktop/macos-installed-inputs/android-support.json", 16384)
    state["nominationSha256"] = sha(nomination)
    need(sha(nomination) == "3450a83882cecdc9d8e402380ccf21e6dc5cec65382cbc7c18b4e6ff6a9aeb8f", "support-upstream-source")
    empty = _source(op, "desktop/packaging/macos-empty-entitlements.plist", 1024)
    need(sha(empty) == op.stager.SIGNED_ENTITLEMENTS_SHA256, "support-empty-entitlements")
    original_root = op.directory(op.work_entry, "android-support-originals", "support-input-directory")
    need(set(os.listdir(original_root["fd"])) == {s["name"] for s in SPECS}, "support-input-roster")
    state["originalRoot"] = original_root
    originals, audits, signed, native_rows = {}, {}, {}, []
    for spec in SPECS:
        entry = op.original(original_root, spec["name"], "support-original-" + spec["name"], ARCHIVE_LIMIT, (0o400,))
        body = op.read(entry)
        need(len(body) == spec["size"] and sha(body) == spec["sha256"], "support-exact-upstream")
        state["inputs"].append((entry, body))
        audit = _io(op, "support-original-zip", lambda body=body: zip_data(body))
        need(set(audit["native"]) == {m[1] for m in spec["members"]}, "support-exact-native-members")
        originals[spec["name"]], audits[spec["name"]] = body, {key: audit[key] for key in ("native", "inventorySha256")}
        need(sum(len(v) for v in originals.values()) <= 40 * 1024 * 1024, "support-original-aggregate")
        del audit
    for role, member, size, digest in MEMBERS:
        spec = next(s for s in SPECS if any(m[0] == role for m in s["members"]))
        before = audits[spec["name"]]["native"][member]
        need(len(before) == size and sha(before) == digest, "support-native-original")
        _io(op, "support-original-macho", lambda: macho_slices(before))
        slot = _mkdir(op, op.target_entry, role)
        old = _write(op, slot, "native", before, 0o755)
        path = op.work / op.target_name / role / "native"
        with op.credential_scope(role):
            op.signing_mutation_pending = True
            _call(op, role + "-sign", path, sign=True, requires_runtime=role != "bundletool-jna")
            need(set(os.listdir(slot["fd"])) == {"native"}, "support-sign-slot-roster")
            current = op.original(slot, "native", "support-signed-" + role, NATIVE_LIMIT, (0o755,))
            body = op.read(current)
            _io(op, "support-content-comparison", lambda: content_unchanged(before, body))
            facts = _io(op, "support-signature-data", lambda: signature_data(body, role != "bundletool-jna"))
            op.close(old)
            need(old["closed"] and not op.errors, "support-input-slot-close")
            op.signing_mutation_pending = False
            _call(op, role + "-verify", path)
            need(op.read(current) == body, "support-verified-original-post")
        signed[role] = body
        native_rows.append({"role": role, "member": member, "originalBytes": size, "originalSha256": digest,
            "signedBytes": len(body), "signedSha256": sha(body), "slices": facts,
            "identifier": IDENTIFIERS[role], "runtimeRequired": role != "bundletool-jna", "timestampRequested": True})
    derived, archive_rows = {}, []
    for spec in SPECS:
        replacement = {m[1]: signed[m[0]] for m in spec["members"]}
        body = _io(op, "support-repack", lambda: repack(originals[spec["name"]], replacement))
        audit = _io(op, "support-final-zip", lambda: zip_data(body))
        need(sum(len(v) for v in derived.values()) + len(body) <= ARCHIVE_LIMIT, "support-derived-aggregate")
        derived[spec["name"]] = body
        archive_rows.append({"name": spec["name"], "upstreamUrl": spec["url"], "originalBytes": spec["size"],
            "originalSha256": spec["sha256"], "originalInventorySha256": audits[spec["name"]]["inventorySha256"],
            "derivedBytes": len(body), "derivedSha256": sha(body), "derivedInventorySha256": audit["inventorySha256"],
            "nonNativeUnchanged": True})
        # These are the actual final archive extractions, not signing-slot aliases.
        for role, member, *_ in spec["members"]:
            slot = _mkdir(op, op.target_entry, role + "-final")
            entry = _write(op, slot, "native", audit["native"][member], 0o555)
            _call(op, role + "-final-verify", op.work / op.target_name / (role + "-final") / "native")
            need(op.read(entry) == signed[role], "support-final-extraction-post")
    _post(op)
    for name, body in derived.items():
        entry = _write(op, op.work_entry, name, body, 0o444)
        state["delivery"][name] = (entry, sha(body), len(body))
        op.close(entry)
        need(entry["closed"] and not op.errors, "support-delivery-close")
    state["receipt"] = {"schemaVersion": 1, "kind": "macos-android-support-signed-v1", "source": op.environment["GITHUB_SHA"],
        "sourceTree": op.environment["MRK_ANDROID_SUPPORT_SOURCE_TREE"],
        "workflow": op.environment["GITHUB_WORKFLOW_REF"], "runId": op.environment["GITHUB_RUN_ID"],
        "runAttempt": op.environment["GITHUB_RUN_ATTEMPT"], "sourceNominationSha256": state["nominationSha256"],
        "signer": {"teamIdentifier": op.signing[0], "certificateSha1": op.signing[1],
                   "producerProfileSha256": sha(op.producer_profile), "serviceProfileSha256": sha(op.service_profile)},
        "archives": archive_rows, "nativeMembers": native_rows, "notarizationQualified": False,
        "productReady": False, "outerExitRequired": True}
    state["complete"] = True
    op.sha256 = sha(canonical(archive_rows))


def output_record(op, name, entry):
    allowed = {"android-helper-" + role + suffix for role in ROLES for suffix in (".stdout", ".stderr", ".status")}
    need(name in allowed and name not in op.android_support["outputs"]
         and len(op.android_support["outputs"]) < 27, "support-output-collision")
    op.android_support["outputs"][name] = (entry, op.android_support["api"].signature(os.fstat(entry["fd"])))


def retire(op):
    state, api = op.android_support, op.android_support["api"]
    if not finish_ready(op):
        return
    state["retiring"] = True
    _post(op)
    root = state.get("originalRoot")
    if root is not None:
        for entry, body in state["inputs"]:
            need(op.read(entry) == body, "support-retire-input-post")
            op.close(entry)
            need(entry["closed"] and not op.errors and api.signature(os.stat(entry["name"], dir_fd=root["fd"], follow_symlinks=False)) == entry["identity"], "support-retire-input-original")
            _io(op, "support-input-unlink", lambda entry=entry: os.unlink(entry["name"], dir_fd=root["fd"]))
        need(not os.listdir(root["fd"]), "support-input-directory-empty")
        op.close(root)
        need(root["closed"] and not op.errors, "support-input-directory-close")
        need(api.directory_identity(os.stat("android-support-originals", dir_fd=op.work_entry["fd"], follow_symlinks=False)) == root["identity"], "support-input-directory-original")
        _io(op, "support-input-rmdir", lambda: os.rmdir("android-support-originals", dir_fd=op.work_entry["fd"]))
    for name, (entry, identity) in state["outputs"].items():
        need(entry["closed"] and api.signature(os.stat(name, dir_fd=op.work_entry["fd"], follow_symlinks=False)) == identity,
             "support-capture-original")
        _io(op, "support-capture-unlink", lambda name=name: os.unlink(name, dir_fd=op.work_entry["fd"]))
    state["inputsRetired"] = True


def publish_final(op):
    state, api = op.android_support, op.android_support["api"]
    need(op.receipt["passed"] and state["complete"] and state.get("inputsRetired") is True
         and op.receipt["targetRetired"] and op.receipt["originalClosesKnown"], "support-publication-finality")
    clock(op, work=False)
    result = dict(state["receipt"], sourcePost=True, inputPost=True, nonDeliveryScratchRetired=True,
        originalsClosed=True, nativeOriginals=op.calls, credentialOriginalsSha256=sha(canonical(op.credential_calls)),
        credentialOriginalCount=len(op.credential_calls), credentialContexts=op.credential_contexts)
    body = canonical(result) + b"\n"
    need(len(body) <= 16384, "support-receipt-bound")
    # Existing finish consumed the work FD. Re-adopt only that exact original identity.
    fd = os.open(op.work, api.READ_FLAGS | os.O_DIRECTORY)
    try:
        need(api.directory_identity(os.fstat(fd)) == api.directory_identity(op.work.lstat()) == op.work_entry["identity"], "support-final-work-original")
        for name, (entry, digest, size) in state["delivery"].items():
            need(api.signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == entry["identity"], "support-final-delivery-original")
        output = os.open("android-support-signed-receipt.json", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444, dir_fd=fd)
        try:
            position = 0
            while position < len(body):
                count = os.write(output, body[position:])
                need(count > 0, "support-receipt-write")
                position += count
            os.fchmod(output, 0o444)
            os.fsync(output)
            identity = api.signature(os.fstat(output))
            need(identity == api.signature(os.stat("android-support-signed-receipt.json", dir_fd=fd, follow_symlinks=False))
                 and os.pread(output, len(body) + 1, 0) == body, "support-receipt-readback")
        finally:
            os.close(output)
        clock(op, work=False)
    finally:
        os.close(fd)
    clock(op, work=False)


def _download_body(started):
    import urllib.request
    import urllib.parse
    class HttpsRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            target = urllib.parse.urlsplit(newurl)
            need(target.scheme == "https" and target.hostname is not None and target.port in (None, 443)
                 and target.username is None and target.password is None, "download-https-redirect")
            return super().redirect_request(request, fp, code, message, headers, newurl)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HttpsRedirect())
    need(sys.platform == "darwin" and os.getuid() != 0 and os.environ.get("GITHUB_REF") == REF
         and os.environ.get("GITHUB_REPOSITORY") == "Apdelrahman1911/mobile-release-kit"
         and not any(name in os.environ for name in ("MRK_MACOS_DEVELOPER_ID_P12_BASE64", "MRK_MACOS_DEVELOPER_ID_P12_PASSWORD")), "download-fixed-context")
    root = Path(os.environ["MRK_MACOS_WORK"])
    need(root.parent == Path("/Users/runner/work/_temp") and re.fullmatch(re.escape(PREFIX) + r"\.[A-Za-z0-9]{8}", root.name), "download-fixed-work")
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent)
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid()
             and (info.st_dev, info.st_ino) == (root.lstat().st_dev, root.lstat().st_ino), "download-owned-work")
        os.mkdir("android-support-originals", 0o700, dir_fd=parent)
        target = os.open("android-support-originals", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            for spec in SPECS:
                fd = os.open(spec["name"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=target)
                digest, total = hashlib.sha256(), 0
                try:
                    remaining = 150 - (time.monotonic() - started)
                    need(remaining > 0, "download-connect-deadline")
                    with opener.open(spec["url"], timeout=min(60, remaining)) as response:
                        need(time.monotonic() - started < 150, "download-response-deadline")
                        if response.headers.get("Content-Length") is not None:
                            need(int(response.headers["Content-Length"]) == spec["size"], "download-declared-size")
                        while True:
                            need(time.monotonic() - started < 150, "download-whole-deadline")
                            block = response.read(1024 * 1024)
                            need(time.monotonic() - started < 150, "download-read-deadline")
                            if not block:
                                break
                            total += len(block)
                            need(total <= spec["size"], "download-size-bound")
                            digest.update(block)
                            position = 0
                            while position < len(block):
                                count = os.write(fd, block[position:])
                                need(count > 0, "download-short-write")
                                position += count
                    need(total == spec["size"] and digest.hexdigest() == spec["sha256"], "download-source-pin")
                    os.fchmod(fd, 0o400)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            os.close(target)
    finally:
        os.close(parent)
    need(time.monotonic() - started < 150, "download-final-deadline")


def download():
    """A documented Darwin timer bounds this exclusive no-secret DATA CLI."""
    import signal
    import threading
    started = time.monotonic()
    need(threading.current_thread() is threading.main_thread()
         and signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
         and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "download-exclusive-timer")
    original = signal.getsignal(signal.SIGALRM)
    def expired(_number, _frame):
        raise TimeoutError("fixed public download deadline")
    try:
        signal.signal(signal.SIGALRM, expired)
        remaining = 150 - (time.monotonic() - started)
        need(remaining > 0, "download-timer-expired")
        need(signal.setitimer(signal.ITIMER_REAL, remaining) == (0.0, 0.0), "download-timer-collision")
        _download_body(started)
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            signal.signal(signal.SIGALRM, original)
    need(time.monotonic() - started < 150, "download-final-deadline")


if __name__ == "__main__":
    need(sys.argv[1:] == ["download"], "closed-data-command")
    download()
