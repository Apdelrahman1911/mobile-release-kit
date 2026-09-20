"""One reviewed disposable Ubuntu P0/F1 publisher/package lifecycle job.

Nonroot preparation reuses the ordinary owner. A separately pinned, manager-owned
root entry performs the fixed lifecycle; no application or payload is launched.
This is not a product/consumer capability or a general privileged runner.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import math
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import tomllib

SOURCE = Path(__file__).absolute().parents[2]


def local(name):
    spec = importlib.util.spec_from_file_location("_publisher_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = local("conventional_runtime_data")
C = local("ci_foundation")
REF = "refs/heads/verify/desktop-ubuntu-publication"
WORKFLOW = ".github/workflows/desktop-ubuntu-publication.yml"
FEATURES = ["ubuntu-runtime-publisher"]
TARGET = "x86_64-unknown-linux-gnu"
PREFIX = "runtime_publication::tests::"
TESTS = tuple(sorted(PREFIX + name for name in (
    "release_inputs_are_fixed_and_lowercase", "root_status_requires_all_initial_root_ids",
    "complete_membership_requires_exact_manifest_roster",
    "helper_fresh_copy_has_independent_inode_and_bytes", "helper_source_size_digest_and_readback_refuse",
    "helper_noreplace_preserves_existing_names", "helper_lost_close_receipt_blocks_publication",
    "helper_stage_sync_failure_prevents_rename", "helper_parent_sync_failure_preserves_published_name",
    "helper_extra_destination_member_is_rejected", "helper_source_directory_drift_is_rejected",
)))
LOG_LIMIT = 2 << 20
LOG_TOTAL = 64 << 20
MAX_BINARY = 512 << 20
MAX_DEB = 512 << 20
KERNEL_SELECTOR = "installed_runtime::tests::kernel_scope_is_reviewed_ubuntu"
F1_MANIFEST_SHA256 = "3a075688d6bc7f69dbdaa017b5327d8ca892e12b49b0c2012a6cbea1f79a6061"
FIXTURE_SOURCE = b"fn main() { std::process::exit(78); }\n"
NOTICE_INPUTS_SHA256 = "10653f438f9a99f06673e7a6159081cc721de1393aacbeed5ecfa4f3b14f6138"
SONAME_PACKAGES = {name: "libc6:amd64" for name in (
    "libc.so.6", "ld-linux-x86-64.so.2", "libm.so.6", "libmvec.so.1", "libdl.so.2",
    "libpthread.so.0", "librt.so.1", "libutil.so.1")}
SONAME_PACKAGES["libgcc_s.so.1"] = "libgcc-s1:amd64"
COMMON_LICENSE_PATTERN = rb"/usr/share/common-licenses/([A-Za-z0-9][A-Za-z0-9.+_\-]*)"
COMMON_LICENSES = {"GPL", "GPL-1", "GPL-2", "GPL-3", "LGPL", "LGPL-2", "LGPL-2.1", "LGPL-3",
                   "GFDL", "GFDL-1.2", "GFDL-1.3", "Apache-2.0", "Artistic", "BSD", "CC0-1.0", "MPL-1.1", "MPL-2.0"}


def route(env):
    D.need(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
           and env.get("RUNNER_OS") == "Linux" and env.get("RUNNER_ARCH") == "X64"
           and env.get("GITHUB_EVENT_NAME") == "push" and env.get("GITHUB_REF") == REF
           and env.get("MRK_UBUNTU_PUBLICATION_VERIFY") == "1", "Wrong fixed publisher verification route")
    sha = env.get("GITHUB_SHA", "")
    D.need(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40
           and env.get("MRK_PUSH_EVENT_AFTER") == sha, "Publisher event source differs")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        D.need(re.fullmatch(r"[1-9][0-9]{0,19}", env.get(key, "")) is not None, "Invalid original run identity")
    D.need(env.get("GITHUB_REPOSITORY") == "Apdelrahman1911/mobile-release-kit", "Different repository")
    return sha


def compile_argv(cargo, source, target, *, library):
    return [cargo, "test" if library else "build", "--locked", "--offline", "--jobs", "1",
            "--no-default-features", "--features", FEATURES[0], "--target", TARGET,
            "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml"),
            "--target-dir", str(target), *( ["--lib", "--no-run"] if library else ["--release", "--bin", "mrk-runtime-publish"] ),
            "--message-format=json"]


def compiled_artifact(raw, source, target_root, *, library):
    """Select only an original fresh Cargo result for this fixed profile."""
    D.need(type(raw) is bytes and 0 < len(raw) <= LOG_LIMIT, "Compiler message bound")
    executable, finished = None, False
    for line in raw.splitlines():
        D.need(not finished, "Compiler data follows its final result")
        row = C.bounded_json(line, 1 << 20)
        D.need(type(row) is dict and type(row.get("reason")) is str, "Invalid original compiler message")
        if row["reason"] == "compiler-artifact" and row.get("executable") is not None:
            kind, name, filename = (("lib", "mobile_release_desktop", "lib.rs") if library
                                    else ("bin", "mrk-runtime-publish", "bin/runtime_publish.rs"))
            target, profile = row.get("target"), row.get("profile")
            D.need(executable is None and type(target) is dict and target.get("kind") == [kind]
                   and target.get("name") == name and target.get("src_path") == str(source / "desktop/src-tauri/src" / filename)
                   and row.get("manifest_path") == str(source / "desktop/src-tauri/Cargo.toml")
                   and row.get("features") == FEATURES and row.get("fresh") is False
                   and type(profile) is dict and profile.get("test") is library
                   and profile.get("debug_assertions") is library
                   and profile.get("opt_level") == ("0" if library else "3"), "Different publisher compiler profile")
            value = row["executable"]
            if library:
                executable = C.github_executable_path(value, target_root=target_root)
            else:
                D.need(value == str(target_root / TARGET / "release/mrk-runtime-publish"), "Publisher binary path differs")
                executable = Path(value)
        elif row["reason"] == "build-finished":
            D.need(row.get("success") is True, "Original publisher compiler failed")
            finished = True
    D.need(finished and executable is not None, "Compiler did not yield exactly one fresh artifact")
    return executable


def test_result(stdout, stderr):
    D.need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) <= 2 << 20
           and stderr == b"", "Publisher test capture differs")
    lines = [line for line in stdout.decode("ascii").splitlines() if line]
    D.need(len(lines) == len(TESTS) + 2 and lines[0] == f"running {len(TESTS)} tests"
           and lines[1:-1] == [f"test {name} ... ok" for name in TESTS]
           and re.fullmatch(r"test result: ok\. 11 passed; 0 failed; 0 ignored; 0 measured; "
                            r"[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[-1]) is not None,
           "Exact publisher test roster did not pass once")


def exact_test_result(stdout, stderr, name):
    """A settled singleton result, never zero/partial/extra tests-as-success."""
    D.need(type(name) is str and re.fullmatch(r"[a-zA-Z0-9_:]+", name) is not None
           and type(stdout) is bytes and 0 < len(stdout) <= 2 << 20 and stderr == b"",
           "Exact singleton test capture differs")
    lines = [line for line in stdout.decode("ascii").splitlines() if line]
    D.need(len(lines) == 3 and lines[:2] == ["running 1 test", f"test {name} ... ok"]
           and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
                            r"[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[2]) is not None,
           "Exact singleton test did not pass once")


def elf_dependencies(raw):
    """Bounded ELF DATA, including required/exported symbol-version labels.

    No binary, loader, ldd or readelf execution. The caller binds the actual
    source/output and native package files; labels alone never admit a host.
    """
    D.need(type(raw) is bytes and 64 <= len(raw) <= MAX_BINARY, "ELF byte bound")

    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        D.need(type(offset) is int and 0 <= offset <= len(raw) - size, "ELF record extent")
        return struct.unpack_from(fmt, raw, offset)

    ident, kind, machine, version, _, phoff, _, _, ehsize, phsize, phnum, _, _, _ = unpack("<16sHHIQQQIHHHHHH", 0)
    D.need(ident[:7] == b"\x7fELF\x02\x01\x01" and kind in (2, 3) and machine == 62
           and version == 1 and ehsize == 64 and phsize == 56 and 0 < phnum <= 128,
           "Expected bounded ELF64 little-endian x86_64")
    headers = [unpack("<IIQQQQQQ", phoff + i * phsize) for i in range(phnum)]
    for p in headers:
        D.need(p[2] <= len(raw) and p[5] <= len(raw) - p[2]
               and (p[0] != 1 or p[5] <= p[6]), "ELF segment extent")

    def address(value, length):
        candidates = [p[2] + value - p[3] for p in headers if p[0] == 1 and p[3] <= value
                      and length <= p[5] and value - p[3] <= p[5] - length]
        D.need(len(candidates) == 1, "ELF pointer is not uniquely file-backed")
        return candidates[0]

    interpreters, dynamics = [p for p in headers if p[0] == 3], [p for p in headers if p[0] == 2]
    D.need(len(interpreters) <= 1 and len(dynamics) == 1, "ELF interpreter/dynamic count")
    interpreter = None
    if interpreters:
        p = interpreters[0]
        D.need(1 < p[5] <= 4096, "ELF interpreter bound")
        value = raw[p[2]:p[2] + p[5]]
        D.need(value.endswith(b"\0") and b"\0" not in value[:-1], "ELF interpreter termination")
        interpreter = value[:-1].decode("ascii")
        D.need(interpreter == "/lib64/ld-linux-x86-64.so.2", "Unreviewed ELF interpreter")
    dynamic = dynamics[0]
    D.need(0 < dynamic[5] <= 65536 and dynamic[5] % 16 == 0, "ELF dynamic bound")
    tags, finished = {}, False
    for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = unpack("<qQ", offset)
        if tag == 0:
            finished = True
            break
        D.need(tag not in {15, 29, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF},
               "ELF search/audit/filter override refused")
        tags.setdefault(tag, []).append(value)
    D.need(finished, "Unterminated ELF dynamic table")

    def single(tag, optional=False):
        values = tags.get(tag, [])
        D.need(len(values) == 1 or optional and not values, "ELF singleton dynamic tag")
        return values[0] if values else None

    size = single(10)
    D.need(0 < size <= 2 << 20, "ELF string table bound")
    offset = address(single(5), size)
    strings = raw[offset:offset + size]

    def string(index):
        D.need(0 <= index < size, "ELF string index")
        end = strings.find(b"\0", index)
        D.need(index <= end <= index + 4096, "ELF string termination/bound")
        return strings[index:end].decode("ascii")

    needed = [string(value) for value in tags.get(1, [])]
    D.need(len(needed) <= 32 and len(set(needed)) == len(needed)
           and all(name in SONAME_PACKAGES for name in needed), "Unreviewed/duplicate native ELF dependency")
    requirements, definitions = {}, []
    pointer, count = single(0x6FFFFFFE, True), single(0x6FFFFFFF, True)
    D.need((pointer is None) == (count is None), "Incomplete ELF version-needs")
    if pointer is not None:
        D.need(0 < count <= 32, "ELF version-need count")
        seen = set()
        for i in range(count):
            D.need(pointer not in seen, "ELF version-need cycle")
            seen.add(pointer)
            ver, n, fileidx, aux, nxt = unpack("<HHIII", address(pointer, 16))
            name = string(fileidx)
            D.need(ver == 1 and 0 < n <= 512 and aux >= 16 and name in needed and name not in requirements,
                   "ELF version-need record")
            values, at, auxseen = [], pointer + aux, set()
            for j in range(n):
                D.need(at not in auxseen, "ELF version auxiliary cycle")
                auxseen.add(at)
                _, _, _, index, step = unpack("<IHHII", address(at, 16))
                values.append(string(index))
                D.need((step == 0) == (j == n - 1) and (step == 0 or step >= 16), "ELF version auxiliary chain")
                at += step
            requirements[name] = values
            D.need((nxt == 0) == (i == count - 1) and (nxt == 0 or nxt >= 16), "ELF version-need chain")
            pointer += nxt
    pointer, count = single(0x6FFFFFFC, True), single(0x6FFFFFFD, True)
    D.need((pointer is None) == (count is None), "Incomplete ELF version definitions")
    if pointer is not None:
        D.need(0 < count <= 512, "ELF version-definition count")
        seen = set()
        for i in range(count):
            D.need(pointer not in seen, "ELF version-definition cycle")
            seen.add(pointer)
            ver, _, _, n, _, aux, nxt = unpack("<HHHHIII", address(pointer, 20))
            D.need(ver == 1 and 0 < n <= 32 and aux >= 20, "ELF version-definition record")
            at = pointer + aux
            for j in range(n):
                index, step = unpack("<II", address(at, 8))
                value = string(index)
                if j == 0:
                    definitions.append(value)
                D.need((step == 0) == (j == n - 1) and (step == 0 or step >= 8), "ELF definition auxiliary chain")
                at += step
            D.need((nxt == 0) == (i == count - 1) and (nxt == 0 or nxt >= 20), "ELF version-definition chain")
            pointer += nxt
    soname = single(14, True)
    return {"interpreter": interpreter, "needed": needed, "versionNeeds": requirements,
            "versionDefinitions": definitions, "soname": string(soname) if soname is not None else None}


def deb_readback(path, data_rows, control_rows):
    """Exact uncompressed .deb ar/tar DATA readback, never extraction/install."""
    raw = D.read(path, MAX_DEB)
    D.need(raw.startswith(b"!<arch>\n"), "Debian ar signature differs")
    offset, totals = 8, {}
    for wanted, rows in (("debian-binary", None), ("control.tar", control_rows), ("data.tar", data_rows)):
        D.need(offset + 60 <= len(raw), "Truncated Debian ar header")
        header = raw[offset:offset + 60]
        D.need(header[58:] == b"`\n", "Debian ar header terminator")
        name = header[:16].decode("ascii").rstrip(" ").removesuffix("/")
        D.need(name == wanted and re.fullmatch(rb"[0-9]+ *", header[16:28]) is not None
               and header[28:34].strip() == header[34:40].strip() == b"0"
               and header[40:48].strip() == b"100644"
               and re.fullmatch(rb"[0-9]+ *", header[48:58]) is not None, "Debian ar name/owner/mode differs")
        size = int(header[48:58])
        offset += 60
        D.need(0 <= size <= len(raw) - offset, "Debian ar member extent")
        body = raw[offset:offset + size]
        offset += size
        if size & 1:
            D.need(raw[offset:offset + 1] == b"\n", "Debian ar padding differs")
            offset += 1
        if rows is None:
            D.need(body == b"2.0\n", "Debian format version differs")
            continue
        D.need(type(rows) is dict and 0 < len(rows) <= 32768 and len(body) % 512 == 0,
               "Debian expected roster/tar bound")
        seen, end, files, bytes_ = set(), 0, 0, 0
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as archive:
            for member in archive:
                D.need(member.offset == end, "Hidden Debian tar record")
                if member.offset_data != end + 512:
                    # GNU tar needs one long-name DATA header for the fixed
                    # manifest-addressed paths. It is not a filesystem link.
                    # Account for it explicitly; never let tarfile hide PAX,
                    # long-link, sparse or chained extension records.
                    extension = tarfile.TarInfo.frombuf(body[end:end + 512], "ascii", "strict")
                    D.need(extension.type == tarfile.GNUTYPE_LONGNAME and extension.name == "././@LongLink"
                           and extension.uid == extension.gid == 0 and extension.linkname == ""
                           and 101 <= extension.size <= 514, "Unreviewed Debian tar extension")
                    name_end = end + 512 + extension.size
                    header_at = (name_end + 511) // 512 * 512
                    extended_name = body[end + 512:name_end]
                    D.need(len(extended_name) == extension.size and extended_name.endswith(b"\0")
                           and b"\0" not in extended_name[:-1]
                           and extended_name[:-1].decode("ascii").removesuffix("/") == member.name.removesuffix("/")
                           and not body[name_end:header_at].strip(b"\0")
                           and member.offset_data == header_at + 512, "Debian tar long-name body/extent differs")
                D.need(member.name == "." or member.name.startswith("./"), "Noncanonical Debian tar name")
                name = member.name[2:] if member.name.startswith("./") else "."
                name = name.removesuffix("/") or "."
                if name != ".":
                    D.relative(name)
                D.need(name not in seen and name in rows and name != "opt" and not name.startswith("opt/")
                       and member.uid == member.gid == 0 and member.uname in ("", "root")
                       and member.gname in ("", "root") and not member.pax_headers and not member.issparse()
                       and member.linkname == "", "Debian tar member/owner/extension differs")
                row = rows[name]
                D.need(member.mode == row["mode"], "Debian tar mode differs")
                seen.add(name)
                if row["type"] == "directory":
                    D.need(member.type == tarfile.DIRTYPE and member.size == 0, "Debian directory type differs")
                else:
                    D.need(row["type"] == "file" and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                           and member.size == row["size"], "Debian file type/size differs")
                    D.sha(row["sha256"])
                    digest, count = hashlib.sha256(), 0
                    with archive.extractfile(member) as stream:
                        while chunk := stream.read(64 << 10):
                            count += len(chunk)
                            D.need(count <= row["size"], "Debian file grew")
                            digest.update(chunk)
                    D.need(count == row["size"] and digest.hexdigest() == row["sha256"], "Debian file body differs")
                    files += 1
                    bytes_ += count
                member_end = member.offset_data + member.size
                padded = (member_end + 511) // 512 * 512
                D.need(not body[member_end:padded].strip(b"\0"), "Nonzero Debian tar body padding")
                end = max(end, padded)
                D.need(len(seen) <= len(rows), "Debian tar member bound")
        D.need(seen == set(rows) and len(body) - end >= 1024 and not body[end:].strip(b"\0"),
               "Debian tar missing members or hidden/truncated ending")
        totals[wanted] = {"entries": len(seen), "files": files, "bytes": bytes_}
    D.need(offset == len(raw), "Extra Debian ar member/trailing bytes")
    return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), **totals}


def directory_identity(path):
    D.directory(path)
    value = path.lstat()
    D.need(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700, "Private task directory changed")
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def artifact_record(path, *, copy_to=None):
    """Cargo may hardlink its own outputs. This is NOT runtime-file admission.

    Keep the original identity/count stable while reading; an exported copy is
    a fresh single-link file whose bytes are independently read back.
    """
    D.directory(path.parent)
    before = path.lstat()
    D.need(stat.S_ISREG(before.st_mode) and before.st_nlink >= 1 and before.st_uid == os.geteuid()
           and before.st_mode & 0o7022 == 0 and before.st_mode & stat.S_IXUSR
           and 0 < before.st_size <= MAX_BINARY, "Unexpected compiler output identity")
    identity = (*D.state(before), before.st_uid, before.st_gid)
    original = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        stream = os.fdopen(original, "rb")
    except BaseException:
        os.close(original)
        raise
    writer = None
    try:
        with stream as source:
            opened = os.fstat(source.fileno())
            D.need((*D.state(opened), opened.st_uid, opened.st_gid) == identity, "Compiler output changed before read")
            if copy_to is not None:
                writer = copy_to.open("xb")
            digest, size = hashlib.sha256(), 0
            for block in iter(lambda: source.read(64 << 10), b""):
                size += len(block)
                D.need(size <= before.st_size, "Compiler output grew")
                digest.update(block)
                if writer is not None:
                    D.need(writer.write(block) == len(block), "Short compiler output copy")
            D.need(size == before.st_size and D.state(os.fstat(source.fileno())) == D.state(before), "Compiler output changed")
            if writer is not None:
                writer.flush()
                os.fchmod(writer.fileno(), 0o555)
                os.fsync(writer.fileno())
    finally:
        if writer is not None:
            writer.close()
    after = path.lstat()
    D.need((*D.state(after), after.st_uid, after.st_gid) == identity, "Compiler output identity changed after close")
    result = {"path": str(path), "size": size, "sha256": digest.hexdigest(), "identity": list(identity)}
    if copy_to is not None:
        D.bound(copy_to, {"path": copy_to.name, "size": size, "sha256": result["sha256"]})
    return result


class Check:
    def __init__(self, root, owner, *, deadline=None):
        self.root, self.owner = root, owner
        self.end = time.monotonic() + 1200 if deadline is None else deadline
        self.retained = 0
        self.phase = "admission"
        self.commands = []
        self.failed = False

    def command(self, label, argv, env, cwd, *, timeout=600, codes=(0,), limit=LOG_LIMIT):
        D.need(not self.failed, "Prior command failed; no further launch")
        self.phase = label
        self.failed = True
        remaining = min(timeout, int(self.end - time.monotonic()))
        D.need(remaining >= 1, "Common publisher-check endpoint expired")
        print("Publisher check: " + label, flush=True)
        result = self.owner(argv, environ=env, cwd=cwd, timeout=remaining, capture=True, text=False, output_limit=limit)
        D.need(type(result) is subprocess.CompletedProcess and result.args == argv
               and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes,
               "Original command result incomplete")
        size = len(result.stdout) + len(result.stderr)
        D.need(size <= limit and self.retained + size <= LOG_TOTAL, "Original command capture bound")
        self.retained += size
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            D.write(self.root / "public" / (label + "." + suffix), raw)
        self.commands.append({"phase": label, "argv": argv, "exitCode": result.returncode,
                              "timeoutSeconds": remaining, "ordinaryOwnerReturned": True})
        D.need(result.returncode in codes and time.monotonic() < self.end, "Original command failed or finished late: " + label)
        self.failed = False
        return result


def failure_reason(error):
    """Only source-labelled invariant text; never arbitrary exception bodies."""
    if (type(error) in (D.Refused, C.CheckFailure)
            or type(error).__module__.startswith(("_publisher_", "_deb_"))
            and type(error).__name__ in {"Refused", "PreparationError", "SmokeRefused"}):
        reason = str(error)
        if 0 < len(reason) <= 512 and all(32 <= ord(character) < 127 for character in reason):
            return reason
    if isinstance(error, OSError):
        return type(error).__name__ + " errno=" + str(error.errno)
    return type(error).__name__


def retain_failure(root, phase, commands, error):
    # Diagnostic retention must not replace the original failure or launch any
    # follow-up process. Never inspect a possibly-live privileged service tree.
    reason = failure_reason(error)
    print("Publisher check refused in " + phase + ": " + reason, file=sys.stderr, flush=True)
    try:
        directory_identity(root)
        directory_identity(root / "public")
        D.write(root / "public/failure.json", D.canonical({"phase": phase, "reason": reason, "commands": commands,
                "qualified": False, "partialOutputsMayRemain": True, "cleanupEstablished": False}))
    except Exception as diagnostic_error:
        print("Publisher failure evidence could not be retained: " + failure_reason(diagnostic_error), file=sys.stderr, flush=True)


def hosted_paths():
    sha = route(os.environ)
    C.conventional_host(D)
    uids, gids = os.getresuid(), os.getresgid()
    D.need(uids[0] != 0 and gids[0] != 0 and len(set(uids)) == len(set(gids)) == 1,
           "One genuine nonroot runner identity required")
    source, temporary = Path(os.environ["GITHUB_WORKSPACE"]), Path(os.environ["RUNNER_TEMP"])
    for path in (source, temporary):
        D.directory(path)
        D.need(path.resolve(strict=True) == path, "Noncanonical hosted directory")
    D.need(source == SOURCE, "Publisher checkout source differs")
    root = temporary / ("mrk-desktop-ubuntu-publisher-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"])
    return sha, source, temporary, root


def prepare():
    """Create the one private root/endpoint BEFORE the fixed A download action."""
    started = time.monotonic()
    sha, source, _, root = hosted_paths()
    os.umask(0o077)
    root.mkdir(mode=0o700)
    try:
        (root / "public").mkdir(mode=0o700)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("root=" + str(root) + "\n")
        for name in ("work", "cases"):
            (root / name).mkdir(mode=0o700)
        for name in ("home", "tmp", "cargo", "rustup", "target"):
            (root / "work" / name).mkdir(mode=0o700)
        D.write(root / "work/gitconfig-empty", b"")
        deadline = repr(started + 1200)
        row = {"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "source": str(source), "root": str(root), "deadline": deadline,
               "runnerUid": os.getuid(), "runnerGid": os.getgid(),
               "rootIdentity": list(directory_identity(root)), "workIdentity": list(directory_identity(root / "work"))}
        pin = D.write(root / "preparation.json", D.canonical(row))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("preparation_sha256=" + pin["sha256"] + "\ndeadline=" + deadline + "\n")
        return root
    except BaseException as error:
        retain_failure(root, "prepare", [], error)
        raise


def resumed_preparation():
    sha, source, temporary, root = hosted_paths()
    D.need(os.environ.get("MRK_UBUNTU_PUBLICATION_ROOT") == str(root), "Original private root differs")
    raw = D.read(root / "preparation.json", 16384)
    D.need(hashlib.sha256(raw).hexdigest() == D.sha(os.environ.get("MRK_UBUNTU_PUBLICATION_PREPARATION_SHA256")),
           "Original preparation pin differs")
    row = D.decode(raw, 16384)
    expected = {"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                "source": str(source), "root": str(root), "deadline": os.environ.get("MRK_UBUNTU_PUBLICATION_DEADLINE"),
                "runnerUid": os.getuid(), "runnerGid": os.getgid(),
                "rootIdentity": list(directory_identity(root)), "workIdentity": list(directory_identity(root / "work"))}
    D.need(D.same(row, expected) and type(row["deadline"]) is str
           and re.fullmatch(r"[0-9]+\.[0-9]+", row["deadline"]) is not None, "Original preparation binding changed")
    deadline = float(row["deadline"])
    D.need(math.isfinite(deadline) and 0 < deadline - time.monotonic() <= 1200,
           "Original lifecycle endpoint expired/invalid; never renew it")
    return sha, source, temporary, root, deadline


def protected_host_file(path, limit=MAX_BINARY, *, trace=None):
    """Root-owned OS DATA, resolving only protected original link ancestry."""
    path = Path(path)
    D.need(path.is_absolute() and ".." not in path.parts, "Absolute native OS input required")

    def observe_metadata(candidate, info, expected, operation="lstat", target=None):
        if trace is not None:
            trace({"selectedPath": str(path), "candidate": str(candidate), "component": candidate.name or "/",
                   "expectedType": expected, "operation": operation, "uid": info.st_uid, "gid": info.st_gid,
                   "mode": info.st_mode, "fileType": stat.S_IFMT(info.st_mode), "permissions": stat.S_IMODE(info.st_mode),
                   "device": info.st_dev, "inode": info.st_ino, "links": info.st_nlink, "size": info.st_size,
                   "linkTarget": target})

    links, ancestry, pending, resolved = [], {}, list(path.parts[1:]), Path("/")
    root_stat = resolved.lstat()
    observe_metadata(resolved, root_stat, "directory")
    D.need(stat.S_ISDIR(root_stat.st_mode) and root_stat.st_uid == root_stat.st_gid == 0
           and not root_stat.st_mode & 0o7022, "Unprotected native OS root")
    ancestry[str(resolved)] = [root_stat.st_dev, root_stat.st_ino, root_stat.st_mode, root_stat.st_uid, root_stat.st_gid]
    steps = 0
    while pending:
        steps += 1
        D.need(steps <= 256, "Native OS input link/ancestry bound")
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            resolved = resolved.parent
            continue
        candidate = resolved / part
        st = candidate.lstat()
        observe_metadata(candidate, st, "directory" if pending else "file")
        D.need(st.st_uid == st.st_gid == 0, "Native OS input has a nonroot owner")
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(candidate)
            observe_metadata(candidate, st, "directory" if pending else "file", "readlink", target if len(target) <= 4096 else None)
            D.need(len(links) < 40 and 0 < len(target) <= 4096 and D.state(candidate.lstat()) == D.state(st),
                   "Native OS input link changed/exceeded bound")
            links.append([str(candidate), list(D.state(st)), target])
            target = Path(target)
            if target.is_absolute():
                resolved, parts = Path("/"), target.parts[1:]
            else:
                parts = target.parts
            pending = [*parts, *pending]
        else:
            D.need(not st.st_mode & 0o7022 and (stat.S_ISDIR(st.st_mode) if pending else stat.S_ISREG(st.st_mode)),
                   "Native OS input has nonordinary/writable/special ancestry")
            resolved = candidate
            if pending:
                ancestry[str(candidate)] = [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid]
    D.need(path.resolve(strict=True) == resolved, "Resolved native OS input differs")
    st = resolved.lstat()
    D.need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "Native OS input is not an ordinary file")
    row = D.file_record(resolved, limit)
    for name, expected in ancestry.items():
        observed = Path(name).lstat()
        D.need([observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid] == expected,
               "Native OS ancestry changed while reading")
    for name, expected, target in links:
        D.need(list(D.state(Path(name).lstat())) == expected and os.readlink(name) == target,
               "Native OS link changed while reading")
    D.need(D.state(resolved.lstat()) == D.state(st) and path.resolve(strict=True) == resolved,
           "Native OS input binding changed")
    return {**row, "path": str(resolved), "selectedPath": str(path), "identity": list(D.state(st)),
            "links": links, "ancestry": ancestry}


def diagnose_native_notices(root):
    """One fresh-host, nonroot DATA observation; never enter the lifecycle."""
    preparation = D.decode(D.read(root / "preparation.json", 16384), 16384)
    deadline = float(preparation["deadline"])
    D.need(math.isfinite(deadline) and 0 < deadline - time.monotonic() <= 1200,
           "Original notice diagnostic endpoint expired/invalid")
    events, paths, retained_bytes = [], [], 0

    def observe(row):
        nonlocal retained_bytes
        size = len(D.canonical(row))
        D.need(len(events) < 256 and retained_bytes + size <= 96 << 10 and time.monotonic() < deadline,
               "Native notice diagnostic trace/endpoint bound")
        events.append(row)
        retained_bytes += size

    def inspect(path, limit):
        D.need(len(paths) < 32, "Native notice diagnostic path bound")
        row = {"selectedPath": str(path), "checked": False}
        paths.append(row)
        try:
            pinned = protected_host_file(path, limit, trace=observe)
        except (D.Refused, OSError) as error:
            row.update(reason=failure_reason(error), errorType=type(error).__name__,
                       errno=error.errno if isinstance(error, OSError) else None)
            return None
        row.update(checked=True, file={key: pinned[key] for key in ("path", "size", "sha256")})
        return pinned

    # The first selected package is from original run35517013573's retained
    # dpkg owner/version DATA. This observation describes THIS new VM only.
    copyright = inspect(Path("/usr/share/doc/gcc-13-x86-64-linux-gnu/copyright"), 2 << 20)
    references = {"derived": False, "names": [], "reason": "Protected copyright read refused; common-license derivation skipped"}
    if copyright is not None:
        try:
            body = D.read(Path(copyright["path"]), 2 << 20)
            D.need(len(body) == copyright["size"] and hashlib.sha256(body).hexdigest() == copyright["sha256"],
                   "Native notice diagnostic copyright changed before reference read")
            names = list(dict.fromkeys(found.decode("ascii").rstrip(".") for found in re.findall(COMMON_LICENSE_PATTERN, body)))
            D.need(len(names) <= 31 and all(name in COMMON_LICENSES for name in names),
                   "Unreviewed common native license reference")
        except (D.Refused, OSError) as error:
            references["reason"] = failure_reason(error)
        else:
            references = {"derived": True, "names": names}
            for name in names:
                inspect(Path("/usr/share/common-licenses") / name, 256 << 10)
    kernel = os.uname()
    report = {"scope": "native-notice-data-only", "dataOnly": True, "qualified": False,
              "sourceSha": preparation["sourceSha"], "runId": preparation["runId"], "attempt": preparation["attempt"],
              "runnerUid": preparation["runnerUid"], "runnerGid": preparation["runnerGid"],
              "imageOS": os.environ["ImageOS"], "imageVersion": os.environ["ImageVersion"],
              "kernel": {key: getattr(kernel, key) for key in ("sysname", "machine", "release", "version")},
              "originalDeadline": preparation["deadline"], "paths": paths, "references": references, "trace": events,
              "comparisonScope": "Fresh-job metadata; not retained filesystem facts from failed run35517013573",
              "continuation": "No A/toolchain acquisition, compiler, package, native or root lifecycle continuation"}
    raw = D.canonical(report)
    D.need(len(raw) <= 128 << 10 and time.monotonic() < deadline, "Native notice diagnostic report/endpoint bound")
    D.write(root / "public/native-notice-diagnostic.json", raw)
    raise D.Refused("Diagnostic-only native notice observation ended; no lifecycle continuation was requested")


def native_inputs(check, source, work, environment, cargo, rustc, metadata_raw):
    """Standard toolchain/support input provenance, not a linked-object census."""
    notice_source = source / "desktop/packaging/debian/native-notices"
    raw = D.read(notice_source / "inputs.json", 1 << 20)
    D.need(hashlib.sha256(raw).hexdigest() == NOTICE_INPUTS_SHA256, "Native source notice roster differs")
    admitted = D.decode(raw, 1 << 20)
    rows = D.records(admitted["files"])
    C.conventional_files(D, notice_source, sorted([*rows.values(), D.file_record(notice_source / "inputs.json")], key=lambda x: x["path"]))
    notices = work / "native-notices"
    notices.mkdir(mode=0o700)
    for name, row in rows.items():
        destination = notices / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        D.copy(notice_source / name, destination, row, 0o644)
    D.copy(notice_source / "inputs.json", notices / "inputs.json", D.file_record(notice_source / "inputs.json"), 0o644)
    D.bound(source / "LICENSE", rows["notices/mobile-release-kit/LICENSE"])
    metadata = C.bounded_json(metadata_raw, LOG_LIMIT)
    packages = metadata.get("packages")
    D.need(type(packages) is list and len(packages) == 36, "Native Cargo roster differs")
    registry = {(p["name"], p["version"]): p for p in packages if p["source"] is not None}
    expected = {(p["name"], p["version"]): p for p in admitted["crates"]}
    D.need(set(registry) == set(expected) and len([p for p in packages if p["source"] is None]) == 2,
           "Native Cargo source versions differ from original notices")
    locked = tomllib.loads(D.read(source / "desktop/src-tauri/Cargo.lock", 256 << 10).decode("utf-8"))
    lock = {(p["name"], p["version"]): p for p in locked["package"] if "source" in p}
    inputs = []
    for key, row in expected.items():
        D.need(registry[key]["source"] == "registry+https://github.com/rust-lang/crates.io-index"
               and registry[key]["license"] == row["license"] and lock[key]["checksum"] == row["archiveSha256"],
               "Cargo original notice/checksum correspondence differs")
        candidates = list((work / "cargo/registry/cache").glob("*/" + key[0] + "-" + key[1] + ".crate"))
        D.need(len(candidates) == 1, "Native locked crate cache is ambiguous")
        record = D.file_record(candidates[0], 8 << 20)
        D.need(record["sha256"] == row["archiveSha256"], "Actual acquired crate differs from native notices")
        inputs.append({**record, "path": str(candidates[0])})
    toolchain = Path(rustc).parent.parent
    D.need(Path(cargo).parent.parent == toolchain and toolchain.is_relative_to(work / "rustup/toolchains"),
           "Compiler component root differs")
    manifest_path = toolchain / "lib/rustlib/multirust-channel-manifest.toml"
    channel = tomllib.loads(D.read(manifest_path, 2 << 20).decode("utf-8"))
    for pkg, target, key in (("rustc", TARGET, "rustcArchiveSha256"), ("rust-std", TARGET, "stdArchiveSha256"),
                             ("rust-src", "*", "sourceArchiveSha256")):
        D.need(channel["pkg"][pkg]["version"] == "1.98.0 (88d9e12ae 2026-08-18)"
               and channel["pkg"][pkg]["target"][target]["xz_hash"] == admitted["rust"][key],
               "Actual Rust component differs from reviewed original notices")
    for name, row in rows.items():
        prefix = "notices/rust-1.98.0/"
        if name.startswith(prefix) and not name.startswith(prefix + "source-package/"):
            path = toolchain / "share/doc/rust" / name.removeprefix(prefix)
            D.bound(path, row)
            inputs.append({**D.file_record(path, 2 << 20), "path": str(path)})
    # Use the actual standard component manifests, not only the rustc shim or
    # version text. This conservatively binds the compiler backend, bundled
    # GNU-linker entry/rust-lld, and the complete native std support set. No
    # linker wrapper or purported exact linked-object census is introduced.
    component_rosters, component_manifests = {}, []
    for component in ("rustc", "rust-std", "cargo"):
        path = toolchain / "lib/rustlib" / ("manifest-" + component + "-" + TARGET)
        lines = D.read(path, 128 << 10).decode("ascii").splitlines()
        D.need(0 < len(lines) <= 512 and all(line.startswith("file:") for line in lines),
               "Installed Rust component manifest differs")
        names = [D.relative(line.removeprefix("file:")) for line in lines]
        D.need(len(names) == len(set(names)), "Duplicate installed Rust component member")
        component_rosters[component] = set(names)
        component_manifests.append(path)
    support_prefix = "lib/rustlib/" + TARGET + "/lib/"
    std_names = component_rosters["rust-std"]
    D.need(all(name.startswith(support_prefix) and Path(name).suffix in (".rlib", ".rmeta", ".a", ".o", ".so") for name in std_names)
           and any(Path(name).name.startswith("libstd-") and name.endswith(".rlib") for name in std_names)
           and any(Path(name).name.startswith("libcompiler_builtins-") and name.endswith(".rlib") for name in std_names),
           "Rust standard/static support roster differs")
    D.need({str(path.relative_to(toolchain)) for path in (toolchain / support_prefix).iterdir() if not path.is_dir()} == std_names,
           "Actual installed Rust native support files differ from component manifest")
    compiler_names = {"bin/rustc", "lib/rustlib/" + TARGET + "/bin/rust-lld",
                      "lib/rustlib/" + TARGET + "/bin/gcc-ld/ld.lld"}
    compiler_names |= {name for name in component_rosters["rustc"]
                       if name.startswith("lib/libLLVM") or name.startswith("lib/librustc_driver-")}
    D.need(len(compiler_names) >= 5 and compiler_names <= component_rosters["rustc"]
           and "bin/cargo" in component_rosters["cargo"], "Actual standard Rust compiler/linker component missing")
    for path in [manifest_path, *component_manifests, *(toolchain / name for name in sorted(compiler_names | std_names | {"bin/cargo"}))]:
        inputs.append({**D.file_record(path, 512 << 20), "path": str(path)})
    D.need(sum(row["size"] for row in inputs) <= 1 << 30, "Native compiler/component input bound")
    os_files, os_packages, package_files, common_notices = {}, {}, {}, set()
    counter = 0

    def host(path, limit=MAX_BINARY):
        record = protected_host_file(path, limit)
        os_files[record["selectedPath"]] = record
        return record

    def package(name):
        nonlocal counter
        D.need(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?", name) is not None, "Native package name differs")
        if name in os_packages:
            return os_packages[name]
        D.need(len(os_packages) < 20, "Native OS package closure bound")
        counter += 1
        fields = "${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n"
        argv = ["/usr/bin/dpkg-query", "-W", "-f=" + fields, name]
        result = check.command("native-package-" + str(counter), argv, environment, work, timeout=15, limit=64 << 10)
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Native package query capture differs")
        values = result.stdout.decode("ascii").rstrip("\n").split("\t")
        D.need(len(values) == 6 and values[0].split(":")[0] == name.split(":")[0] and values[1] == "installed"
               and values[3] == "amd64" and all(re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", values[i]) for i in (2, 5)),
               "Actual native package/version/architecture differs")
        listing = check.command("native-package-files-" + str(counter), ["/usr/bin/dpkg-query", "-L", name],
                                environment, work, timeout=15, limit=256 << 10)
        D.need(listing.stderr == b"", "Native package file query differs")
        files = listing.stdout.decode("utf-8").splitlines()
        D.need(0 < len(files) <= 8192 and all(p.startswith("/") and ".." not in Path(p).parts for p in files),
               "Native package file roster differs")
        row = {"binaryPackage": values[0], "version": values[2], "architecture": values[3],
               "sourcePackage": values[4], "sourceVersion": values[5], "queryArgv": argv,
               "querySha256": hashlib.sha256(result.stdout).hexdigest()}
        os_packages[name], package_files[name] = row, set(files)
        doc = host(Path("/usr/share/doc") / name.split(":")[0] / "copyright", 2 << 20)
        target = notices / "host" / name.split(":")[0] / "copyright"
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not target.exists():
            D.copy(Path(doc["path"]), target, {key: doc[key] for key in ("path", "size", "sha256")}, 0o644)
        body = D.read(Path(doc["path"]), 2 << 20)
        for found in re.findall(COMMON_LICENSE_PATTERN, body):
            item = found.decode("ascii").rstrip(".")
            D.need(item in COMMON_LICENSES, "Unreviewed common native license reference")
            if item not in common_notices:
                common = host(Path("/usr/share/common-licenses") / item, 256 << 10)
                destination = notices / "host/common" / item
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                D.copy(Path(common["path"]), destination, {k: common[k] for k in ("path", "size", "sha256")}, 0o644)
                common_notices.add(item)
        row["copyright"] = {key: doc[key] for key in ("selectedPath", "path", "size", "sha256")}
        # A package's documentation directory may be a protected link to its
        # compiler/base package. Bind that original owner/version too.
        owner_of(Path(doc["path"]))
        return row

    def owner_of(path):
        nonlocal counter
        counter += 1
        result = check.command("native-file-owner-" + str(counter), ["/usr/bin/dpkg-query", "-S", str(path)],
                               environment, work, timeout=15, limit=64 << 10)
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Native file ownership query differs")
        line = result.stdout.decode("ascii").rstrip("\n")
        suffix = ": " + str(path)
        D.need(line.endswith(suffix), "Native file package ownership differs")
        name = line[:-len(suffix)]
        package(name)
        return name

    cc = shutil.which("cc", path=environment["PATH"])
    D.need(cc is not None and Path(cc).is_absolute(), "Standard GNU compiler driver missing")
    driver = host(Path(cc))
    owner_of(Path(driver["path"]))
    version = check.command("native-gcc-version", [cc, "-dumpfullversion"], environment, work, timeout=15, limit=4096)
    D.need(version.stderr == b"" and re.fullmatch(rb"[0-9]+(?:\.[0-9]+){1,2}\n", version.stdout), "GNU compiler version differs")
    for name in ("collect2", "ld"):
        output = check.command("native-gcc-program-" + name, [cc, "-print-prog-name=" + name],
                               environment, work, timeout=15, limit=4096)
        D.need(output.stderr == b"" and output.stdout.count(b"\n") == 1, "GNU compiler-program query differs")
        selected = output.stdout.decode("ascii").rstrip("\n")
        selected = selected if selected.startswith("/") else shutil.which(selected, path=environment["PATH"])
        D.need(selected is not None and Path(selected).is_absolute(), "GNU standard linker program missing")
        program = host(Path(os.path.abspath(selected)))
        owner_of(Path(program["path"]))
    for index, name in enumerate(("Scrt1.o", "crti.o", "crtn.o", "crtbeginS.o", "crtendS.o",
                                  "libgcc.a", "libgcc_eh.a", "libgcc_s.so", "libc.so", "libc_nonshared.a",
                                  "libutil.a", "librt.a", "libpthread.a", "libm.so", "libdl.a")):
        output = check.command("native-gcc-support-" + str(index), [cc, "-print-file-name=" + name],
                               environment, work, timeout=15, limit=4096)
        D.need(output.stderr == b"" and output.stdout.count(b"\n") == 1, "GNU support-file query differs")
        selected = Path(os.path.abspath(output.stdout.decode("ascii").rstrip("\n")))
        D.need(output.stdout.startswith(b"/"), "GNU compiler support file was not resolved")
        support_row = host(selected)
        owner_of(Path(support_row["path"]))
    # Prebind the finite GNU std support candidates before compilation; actual
    # new-output DT_NEEDED closure is evaluated separately below, never guessed.
    libraries = {}
    for soname, pkg in SONAME_PACKAGES.items():
        package(pkg)
        selected = Path("/usr/lib/x86_64-linux-gnu") / soname
        record = host(selected)
        aliases = {record["path"], record["selectedPath"], record["path"].replace("/usr/lib/", "/lib/", 1)}
        D.need(bool(aliases & package_files[pkg]), "Native shared object is not in its actual installed package")
        elf = elf_dependencies(D.read(Path(record["path"]), MAX_BINARY))
        D.need(elf["soname"] == soname, "Actual native shared-object SONAME differs")
        libraries[soname] = {"file": record, "package": pkg, "elf": elf}
    loader = host(Path("/lib64/ld-linux-x86-64.so.2"))
    D.need(loader["path"] == libraries["ld-linux-x86-64.so.2"]["file"]["path"], "Actual interpreter binding differs")
    return {"notices": notices, "inputs": inputs, "osFiles": os_files, "osPackages": os_packages,
            "libraries": libraries, "rust": {**admitted["rust"], "cargoVersion": channel["pkg"]["cargo"]["version"],
                "cargoArchiveSha256": D.sha(channel["pkg"]["cargo"]["target"][TARGET]["xz_hash"])},
            "gccVersion": version.stdout.decode("ascii").strip()}


def finish_native_inputs(check, work, environment, native, outputs):
    closures = {}
    for label, path in outputs.items():
        raw = D.read(path, MAX_BINARY)
        observed = elf_dependencies(raw)
        D.need(observed["interpreter"] == "/lib64/ld-linux-x86-64.so.2" and observed["soname"] is None
               and observed["needed"], "Compiler output is not the expected native executable")
        # The interpreter is a dependency even if a linker omits a redundant
        # direct DT_NEEDED entry for it.
        pending, visited = [observed, native["libraries"]["ld-linux-x86-64.so.2"]["elf"]], {"ld-linux-x86-64.so.2"}
        while pending:
            current = pending.pop()
            for soname in current["needed"]:
                selected = native["libraries"][soname]
                D.need(set(current["versionNeeds"].get(soname, [])) <= set(selected["elf"]["versionDefinitions"]),
                       "Actual native shared object lacks required symbol versions")
                if soname not in visited:
                    visited.add(soname)
                    pending.append(selected["elf"])
        closures[label] = {"file": {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                           "elf": observed, "objects": sorted(visited),
                           "packages": sorted({native["libraries"][name]["package"] for name in visited})}
    for row in native["inputs"]:
        D.bound(Path(row["path"]), row)
    for selected, row in native["osFiles"].items():
        D.need(D.same(protected_host_file(Path(selected)), row), "Native compiler/support input changed during compilation")
    for index, row in enumerate(native["osPackages"].values()):
        result = check.command("native-package-recheck-" + str(index), row["queryArgv"], environment, work, timeout=15, limit=64 << 10)
        D.need(result.stderr == b"" and hashlib.sha256(result.stdout).hexdigest() == row["querySha256"],
               "Native OS package changed during compilation")
    required = sorted({pkg for label in ("P0", "F1", "fixture") for pkg in closures[label]["packages"]})
    depends = ", ".join(pkg.split(":")[0] + " (= " + native["osPackages"][pkg]["version"] + ")" for pkg in required)
    record = {"rust": native["rust"], "gccVersion": native["gccVersion"], "compilerInputs": native["inputs"],
              "osFiles": list(native["osFiles"].values()), "osPackages": native["osPackages"],
              "sharedObjects": native["libraries"], "outputs": closures,
              "depends": depends, "scope": "Bound standard compiler/components/GCC/CRT/static-support and actual ELF/package/version/notice closure; not an exact linked-object census or product qualification."}
    D.write(native["notices"] / "BUILD-INPUTS.json", D.canonical(record), 0o644)
    P = local("prepare_runtime")
    notices = [{**D.file_record(path, 2 << 20), "path": path.relative_to(native["notices"]).as_posix()}
               for path in P.files(native["notices"])]
    notices.sort(key=lambda row: row["path"])
    D.need(sum(row["size"] for row in notices) <= 64 << 20, "Complete native notice input bound")
    return record, notices, depends


def package_rows(stager, binary_rows, runtime_rows, kit_rows, notice_rows, manifest, version, depends):
    mapping = {}

    def add(name, row, mode):
        D.need(name not in mapping, "Expected package member collision")
        mapping[name] = {"type": "file", "mode": mode, "size": row["size"], "sha256": row["sha256"]}

    for name, destination in stager.BINARIES.items():
        add(destination, binary_rows[name], 0o755)
    prefix = "usr/lib/mobile-release-kit/runtime-input/" + TARGET + "/" + manifest
    for name, row in runtime_rows.items():
        add(prefix + "/" + name, row, 0o555 if name == "python/bin/python3" else 0o444)
    for name, row in kit_rows.items():
        add(stager.DOCS + "/runtime/" + name, row, 0o644)
    for name, row in notice_rows.items():
        add(stager.DOCS + "/desktop/" + name, row, 0o644)
    for name, destination, mode in (("postinst", "DEBIAN/postinst", 0o755), ("prerm", "DEBIAN/prerm", 0o755),
                                   ("postrm", "DEBIAN/postrm", 0o755),
                                   ("mobile-release-kit.desktop", "usr/share/applications/mobile-release-kit.desktop", 0o644),
                                   ("README.md", stager.DOCS + "/INSTALLATION.md", 0o644)):
        add(destination, D.file_record(stager.TEMPLATES / name, 64 << 10), mode)
    installed = (sum(row["size"] for name, row in mapping.items() if not name.startswith("DEBIAN/")) + 1023) // 1024
    control = stager.controls(version, depends, installed)
    add("DEBIAN/control", {"size": len(control), "sha256": hashlib.sha256(control).hexdigest()}, 0o644)
    data_rows, control_rows = {".": {"type": "directory", "mode": 0o755}}, {".": {"type": "directory", "mode": 0o755}}
    for name, row in mapping.items():
        target = control_rows if name.startswith("DEBIAN/") else data_rows
        relative = name.removeprefix("DEBIAN/") if target is control_rows else name
        target[relative] = row
        for parent in Path(relative).parents:
            if str(parent) != ".":
                target[str(parent)] = {"type": "directory", "mode": 0o755}
    return data_rows, control_rows


def package_inputs(source, work):
    """Admit all A bytes and the fixed fresh F1 DATA before compilation."""
    admission = C.CONVENTIONAL_SMOKE_INPUTS
    artifact = work / "admitted-a"
    original = C.conventional_files(D, artifact, admission["preparedArtifact"]["files"])
    D.need(len(original) == 47, "Original A transport roster differs")
    D.unpack(artifact / "prepared-runtime.tar", original["prepared-runtime.tar"], work / "prepared")
    D.need(D.file_record(source / "desktop/tools/stage_ubuntu_deb.py", 64 << 10)["sha256"]
           == "961b95afb5631ec4f7b81b9affa023b2077c0cf50a3752212a1182a6dc39df98", "Accepted stager source differs")
    stager = local("stage_ubuntu_deb")
    p0 = work / "prepared/runtime"
    runtime_rows = stager.runtime_records(p0, admission["manifestSha256"], admission["protocolSha256"])
    D.need(len(runtime_rows) == 607, "Original A runtime roster differs")
    for name, row in runtime_rows.items():
        D.bound(p0 / name, row)
    raw = D.read(p0 / "manifest.json", 1 << 20)
    D.need(len(raw) == 85440 and hashlib.sha256(raw + b"\n").hexdigest() == F1_MANIFEST_SHA256,
           "Fixed F1 trailing-whitespace anchor differs")
    f1 = work / "fixture-runtime"
    f1.mkdir(mode=0o700)
    for name, row in runtime_rows.items():
        if name == "manifest.json":
            continue
        target = f1 / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        D.copy(p0 / name, target, row, stat.S_IMODE((p0 / name).lstat().st_mode))
    D.write(f1 / "manifest.json", raw + b"\n", 0o444)
    f1_rows = stager.runtime_records(f1, F1_MANIFEST_SHA256, admission["protocolSha256"])
    kit = stager.kit_records(artifact, original)
    return stager, artifact, original, p0, runtime_rows, f1, f1_rows, kit


def prepare_packages(check, source, work, public, environment, binaries, native_notices, depends, prepared):
    stager, artifact, original, p0, runtime_rows, f1, f1_rows, kit = prepared
    admission = C.CONVENTIONAL_SMOKE_INPUTS
    prepared_pin = D.write(work / "prepared-files.json", D.canonical(list(original.values())))
    notice_pin = D.write(work / "native-notice-files.json", D.canonical(native_notices))
    notice_rows = D.records(native_notices)
    packages, readbacks = {}, {}
    for label, runtime, rows, manifest, version in (
        ("P0", p0, runtime_rows, admission["manifestSha256"], "0.0.0+mrk.lifecycle.0"),
        ("F1", f1, f1_rows, F1_MANIFEST_SHA256, "0.0.0+mrk.lifecycle.1"),
    ):
        compiled = work / ("compiled-" + label)
        compiled.mkdir(mode=0o700)
        records = []
        for name, input_ in (("mobile-release-kit-desktop", binaries["fixture"]), ("mrk-runtime-publish", binaries[label])):
            row = D.file_record(input_, MAX_BINARY)
            D.copy(input_, compiled / name, row, 0o555)
            records.append({**row, "path": name})
        records.sort(key=lambda row: row["path"])
        compiler_pin = D.write(work / (label + "-compiler-files.json"), D.canonical(records))
        output = work / ("stage-" + label)
        argv = ["/usr/bin/python3.12", "-I", "-S", "-B", str(source / "desktop/tools/stage_ubuntu_deb.py")]
        values = {"compiled": compiled, "compiler-files": work / (label + "-compiler-files.json"),
                  "compiler-files-sha256": compiler_pin["sha256"], "runtime": runtime,
                  "prepared-artifact": artifact, "prepared-files": work / "prepared-files.json",
                  "prepared-files-sha256": prepared_pin["sha256"], "desktop-notices": work / "native-notices",
                  "desktop-notice-files": work / "native-notice-files.json", "desktop-notice-files-sha256": notice_pin["sha256"],
                  "manifest-sha256": manifest, "protocol-sha256": admission["protocolSha256"],
                  "version": version, "depends": depends, "output": output}
        for key, value in values.items():
            argv.extend(["--" + key, str(value)])
        result = check.command("stage-" + label, argv, environment, work, timeout=120)
        staged = C.bounded_json(result.stdout, 16384)
        D.need(result.stderr == b"" and staged.get("runtimeManifestSha256") == manifest
               and staged.get("installed") is False and staged.get("qualified") is False, "Original stager result differs")
        # Only this fresh private stage root, never an existing OS parent.
        D.need(output.lstat().st_uid == os.geteuid() and stat.S_IMODE(output.lstat().st_mode) == 0o700,
               "Fresh staging root changed")
        os.chmod(output, 0o755)
        package_path = public / (label + ".deb")
        check.command("deb-build-" + label, ["/usr/bin/dpkg-deb", "--root-owner-group", "--uniform-compression", "-Znone",
                                            "--build", str(output), str(package_path)], environment, work, timeout=120)
        check.phase = "deb-complete-readback-" + label
        expected_data, expected_control = package_rows(stager, D.records(records), rows, kit, notice_rows, manifest, version, depends)
        readback = deb_readback(package_path, expected_data, expected_control)
        packages[label] = {key: readback[key] for key in ("path", "size", "sha256")}
        packages[label].update(manifestSha256=manifest, version=version)
        readbacks[label] = {**readback, "dataRows": expected_data, "controlRows": expected_control}
    D.write(public / "package-members.txt", D.canonical(readbacks))
    capacity = {"runtimeBytes": sum(row["size"] for row in runtime_rows.values()),
                "installedBytes": {name: row["data.tar"]["bytes"] for name, row in readbacks.items()},
                "installedEntries": {name: row["data.tar"]["entries"] for name, row in readbacks.items()}}
    return packages, capacity


def verify():
    sha, source, temporary, root, deadline = resumed_preparation()
    os.umask(0o077)
    work, public = root / "work", root / "public"
    original_root, original_work = directory_identity(root), directory_identity(work)
    original_public, original_cases = directory_identity(public), directory_identity(root / "cases")
    # Only the accepted ordinary owner is imported nonroot. The root boundary
    # has a separately pinned protected closure and never imports this driver.
    sys.path.insert(0, str(source / "src"))
    from mobile_release.owned_process import run_owned
    check = Check(root, run_owned, deadline=deadline)
    environment = C.clean_environment(work)
    git, rustup = shutil.which("git", path=environment["PATH"]), shutil.which("rustup", path=environment["PATH"])

    def source_check(label):
        check.phase = label + "-source-admission"
        C.conventional_host(D)
        D.need(directory_identity(root) == original_root and directory_identity(work) == original_work
               and directory_identity(public) == original_public and directory_identity(root / "cases") == original_cases,
               "Task root changed")
        C.no_cargo_configuration((work, root, *root.parents, temporary, *temporary.parents,
                                  source / "desktop/src-tauri", source / "desktop", source, *source.parents,
                                  work / "cargo", work / "home"))
        D.need(all(not (work / "cargo" / name).exists() and not (work / "cargo" / name).is_symlink()
                   for name in ("config", "config.toml")), "Unexpected private Cargo configuration")
        head = check.command(label + "-head", [git, "rev-parse", "HEAD"], environment, source, timeout=15)
        D.need(head.stderr == b"" and head.stdout == sha.encode("ascii") + b"\n",
               "Publisher source commit changed")
        status = check.command(label + "-status", [git, "status", "--porcelain=v1", "--untracked-files=all", "--ignored"],
                               environment, source, timeout=15)
        D.need(status.stdout == status.stderr == b"", "Publisher source has modified, untracked or ignored additions")

    try:
        D.need(all(value is not None and Path(value).is_absolute() for value in (git, rustup)), "Hosted compiler/source tools missing")
        source_check("before")
        tree = check.command("source-tree", [git, "rev-parse", "HEAD^{tree}"], environment, source, timeout=15).stdout.strip().decode("ascii")
        D.need(re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "Invalid source tree")
        check.phase = "reviewed-lifecycle-entry"
        entry_sha = D.sha(os.environ.get("MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256"))
        D.need(D.file_record(source / "desktop/tools/ubuntu_publication_lifecycle.py", 1 << 20)["sha256"] == entry_sha,
               "Workflow reviewed lifecycle entry differs")
        kernel = os.uname()
        metadata = {"sourceSha": sha, "sourceTree": tree, "workflow": D.file_record(source / WORKFLOW, 64 << 10),
                    "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                    "imageOS": os.environ["ImageOS"], "imageVersion": os.environ["ImageVersion"],
                    "kernel": {key: getattr(kernel, key) for key in ("sysname", "machine", "release", "version")},
                    "nativeQualification": False, "features": FEATURES, "rust": C.RUST,
                    "lifecycleEntrySha256": entry_sha, "originalDeadline": repr(deadline),
                    "fixtureScope": "P0/F1 nonrelease packages and an unlaunched std-only app fixture; no real desktop build."}
        D.write(public / "source.json", D.canonical(metadata))
        check.phase = "original-a-data"
        prepared = package_inputs(source, work)
        D.write(public / "runtime-inputs.json", D.canonical({"admission": C.CONVENTIONAL_SMOKE_INPUTS,
                "runtimeFiles": 607, "fixtureManifestSha256": F1_MANIFEST_SHA256,
                "fixtureChange": "Exactly one LF appended to the original 85440-byte manifest; all606 payload bodies unchanged."}))
        # Current-job package metadata, not invented historical H evidence.
        check.phase = "kernel-package-metadata"
        D.need(re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,127}", kernel.release) is not None, "Kernel package query name differs")
        try:
            with Path("/proc/version_signature").open("rb") as signature:
                raw = signature.read(4097)
        except (FileNotFoundError, PermissionError) as error:
            D.write(public / "version-signature-unavailable.json", D.canonical({"reason": type(error).__name__}))
        else:
            D.need(0 < len(raw) <= 4096, "Version signature metadata bound")
            D.write(public / "version-signature.txt", raw)
        check.command("kernel-packages", ["/usr/bin/dpkg-query", "-W",
            "-f=${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n",
            "linux-image-" + kernel.release, "linux-image-unsigned-" + kernel.release, "linux-modules-" + kernel.release],
            environment, work, timeout=15, codes=(0, 1), limit=64 << 10)

        check.command("rust-acquire", [rustup, "toolchain", "install", C.RUST, "--profile", "minimal", "--no-self-update"], environment, work)
        selected = {}
        for name in ("cargo", "rustc"):
            result = check.command(name + "-selection", [rustup, "which", "--toolchain", C.RUST, name], environment, work, timeout=15)
            D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Original compiler selection capture differs")
            selected[name] = result.stdout.decode("utf-8").rstrip("\n")
            path = Path(selected[name])
            D.need(path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
                   and path.is_relative_to(work / "rustup/toolchains"), "Selected private compiler missing/different")
        cargo, rustc = selected["cargo"], selected["rustc"]
        result = check.command("rust-version", [rustc, "-vV"], environment, work, timeout=15)
        version = result.stdout.decode("ascii")
        D.need(result.stderr == b"" and f"release: {C.RUST}\n" in version and f"host: {TARGET}\n" in version
               and "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\n" in version,
               "Selected compiler identity differs")
        environment.update(RUSTC=rustc, PATH=str(Path(cargo).parent) + os.pathsep + environment["PATH"])
        metadata_raw = check.command("locked-inputs", [cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
            "--features", FEATURES[0], "--filter-platform", TARGET, "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml")], environment, work).stdout
        source_check("acquired")
        check.phase = "native-input-provenance"
        native = native_inputs(check, source, work, environment, cargo, rustc, metadata_raw)
        environment.update(GITHUB_SHA=sha, MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
                           MRK_BUNDLED_PROTOCOL_SHA256=C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"])
        originals, exports, export_identities = {}, {}, {}

        def export(label, path, leaf):
            destination = public / leaf
            originals[label] = artifact_record(path, copy_to=destination)
            export_identities[label] = artifact_record(destination)
            exports[label] = {key: export_identities[label][key] for key in ("path", "size", "sha256")}
            D.need(all(exports[label][key] == originals[label][key] for key in ("size", "sha256"))
                   and export_identities[label]["identity"][:2] != originals[label]["identity"][:2],
                   "Original compiler output and fresh export differ/alias")
            D.write(public / ("compiler-" + label + ".json"), D.canonical({"original": originals[label], "export": export_identities[label]}))

        def exported_unchanged():
            for label, row in export_identities.items():
                D.need(D.same(artifact_record(Path(row["path"])), row), "Fresh compiler export changed: " + label)

        binary_raw = check.command("publisher-compile", compile_argv(cargo, source, work / "target", library=False), environment, work).stdout
        binary_path = compiled_artifact(binary_raw, source, work / "target", library=False)
        export("P0", binary_path, "mrk-runtime-publish")
        library_raw = check.command("libtest-compile", compile_argv(cargo, source, work / "target", library=True), environment, work).stdout
        library_path = compiled_artifact(library_raw, source, work / "target", library=True)
        export("libtest", library_path, "libtest")
        D.need(D.same(artifact_record(binary_path), originals["P0"])
               and D.same(artifact_record(library_path), originals["libtest"]), "Original P0/libtest output changed before F1")
        exported_unchanged()
        # Cargo reuses unchanged dependencies. Preserve P0 above before this
        # original F1 build can replace its release output; build.rs tracks M.
        f1_environment = {**environment, "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256": F1_MANIFEST_SHA256}
        f1_raw = check.command("publisher-F1-compile", compile_argv(cargo, source, work / "target", library=False), f1_environment, work).stdout
        f1_path = compiled_artifact(f1_raw, source, work / "target", library=False)
        export("F1", f1_path, "mrk-runtime-publish-F1")
        D.need(exports["P0"]["sha256"] != exports["F1"]["sha256"], "Original F1 publisher did not acquire its distinct manifest anchor")
        fixture_source = public / "fixture.rs"
        fixture_pin = D.write(fixture_source, FIXTURE_SOURCE, 0o444)
        fixture_path = work / "fixture-app"
        check.command("fixture-compile", [rustc, "--edition=2021", "--crate-name", "mrk_lifecycle_fixture", "--crate-type", "bin",
            "--target", TARGET, "-C", "opt-level=3", "-C", "debuginfo=0", str(fixture_source), "-o", str(fixture_path)],
            environment, work, timeout=120)
        D.bound(fixture_source, fixture_pin)
        export("fixture", fixture_path, "fixture-app")
        source_check("compiled")
        exported_unchanged()
        test_env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(work / "home"),
                    "TMPDIR": str(root / "cases"), "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        result = check.command("kernel-selector", [exports["libtest"]["path"], KERNEL_SELECTOR, "--exact", "--test-threads=1"],
                               test_env, root / "cases", timeout=120, limit=2 << 20)
        exact_test_result(result.stdout, result.stderr, KERNEL_SELECTOR)
        check.phase = "native-output-closure"
        outputs = {label: Path(row["path"]) for label, row in exports.items()}
        native_record, notice_rows, depends = finish_native_inputs(check, work, environment, native, outputs)
        check.phase = "package-preparation"
        packages, capacity = prepare_packages(check, source, work, public, environment, outputs, notice_rows, depends, prepared)
        exported_unchanged()
        for label in ("libtest", "F1", "fixture"):
            D.need(D.same(artifact_record(Path(originals[label]["path"])), originals[label]), "Original retained compiler output changed")
        source_check("before-root")
        compiler_records = {"sourceSha": sha, "sourceTree": tree,
            "binaries": {label: exports[label] for label in ("P0", "F1", "fixture")}, "library": exports["libtest"],
            "originalArtifacts": originals, "exportedArtifacts": export_identities,
            "P0OriginalCapturedBeforeF1Overwrite": True, "fixtureSource": {**fixture_pin, "path": str(fixture_source)},
            "manifestSha256": C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"], "fixtureManifestSha256": F1_MANIFEST_SHA256,
            "protocolSha256": C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"], "nativeInputs": native_record, "capacity": capacity}
        D.write(public / "compiler.json", D.canonical(compiler_records))
        check.phase = "root-lifecycle-handoff"
        request = {"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "deadline": deadline, "runnerUid": os.getuid(), "runnerGid": os.getgid(), "source": str(source), "taskRoot": str(root),
            "library": exports["libtest"], "packages": packages, "compilerRecords": compiler_records}
        handoff_path = work / "lifecycle-handoff.json"
        handoff_bytes = D.canonical(request)
        D.need(len(handoff_bytes) <= 1 << 20, "Lifecycle handoff byte bound")
        handoff_pin = D.write(handoff_path, handoff_bytes)
        lifecycle = local("ubuntu_publication_lifecycle")
        argv = lifecycle.service_argv(handoff_path, handoff_pin["sha256"], entry_sha)
        client_env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(work / "home")}
        client_result = check.command("root-lifecycle", argv, client_env, work, timeout=1200, limit=2 << 20)
        # Only this original successful client result permits the fixed root
        # verifier to read matching start/StopPost/final records. Failure never
        # triggers a replacement wait, live-root inspection, retry or repair.
        check.phase = "root-lifecycle-original-result"
        lifecycle_result = lifecycle.verify_service_result(handoff_path, handoff_pin["sha256"], entry_sha, client_result, public)
        exported_unchanged()
        source_check("after")
        check.phase = "final-evidence"
        D.need(time.monotonic() < deadline, "Original lifecycle endpoint expired before final evidence")
        D.write(public / "result.json", D.canonical({"sourceSha": sha, "tests": [KERNEL_SELECTOR, lifecycle.ROOT_TEST, lifecycle.USER_TEST],
            "compilations": ["P0", "libtest", "F1", "fixture"], "helper11Rerun": False, "packages": packages,
            "lifecycle": lifecycle_result, "commands": check.commands, "inputsAndOutputsRetained": True,
            "qualified": False, "scope": "fixed-publisher-P0-F1-package-lifecycle-with-unlaunched-std-only-app-fixture"}))
        print("Publisher/package lifecycle checks passed; original evidence retained. No product qualification.", flush=True)
    except BaseException as error:
        # Never turn a failure into a pass or infer disposal from process exit.
        retain_failure(root, check.phase, check.commands, error)
        raise


def main():
    if sys.argv[1:] == ["diagnose-native-notices"]:
        diagnose_native_notices(prepare())
    elif sys.argv[1:] == ["prepare"]:
        prepare()
    else:
        D.need(len(sys.argv) == 1, "Expected prepare, diagnose-native-notices or the no-argument lifecycle verification entry")
        verify()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Publisher check refused: " + failure_reason(error) + ". Preserve original evidence; no qualification.", file=sys.stderr)
        raise SystemExit(1)
