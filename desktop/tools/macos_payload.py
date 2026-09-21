"""One fixed, credential-free macOS ARM64 publisher build/payload smoke job.

Not a desktop runtime constructor, installer, general command runner or sandbox.
All process work uses the existing Darwin ordinary owner. Import is inert so the
small DATA tests can inspect recipes/copy policies on Linux without native work.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import sys
import tarfile
import time
import unicodedata
import zipfile

TARGET = "aarch64-apple-darwin"
PREFIX = Path("/opt/mobile-release-kit-macos-payload/python")
CLT = Path("/Library/Developer/CommandLineTools")
CHUNK = 65536
SOURCE_LIMIT = 1024 * 1024 * 1024
FILE_LIMIT = 512 * 1024 * 1024
ENTRY_LIMIT = 100000
WORK_SECONDS = 1800
FINAL_SECONDS = 30
EVIDENCE_LIMIT = 256 * 1024 * 1024
NOTICE_DATA_LIMIT = 8 * 1024 * 1024
DISPOSABLE_DIRS = ("downloads", "sources", "build", "deps", "package-source", "home", "tmp", "poison")
SYSTEM_DEPS = frozenset({"/usr/lib/libSystem.B.dylib", "/usr/lib/libffi.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"})
DYLIBS = ("libcrypto.3.dylib", "libssl.3.dylib")
TOOL_NAMES = ("clang", "ld", "ar", "ranlib", "make", "otool", "install_name_tool", "codesign")
HACL = ("Hash_MD5", "Hash_SHA1", "Hash_SHA2", "Hash_SHA3", "Hash_BLAKE2", "HMAC")
OMIT = frozenset({"test", "tests", "__pycache__", "ensurepip", "idlelib", "turtledemo",
                  "tkinter", "venv", "site-packages"})
REQUEST_SHIM = 'exec "$1" -I -S -B "$2" "$3" < "$4"'


class Refused(ValueError):
    """Fixed diagnostic only; inputs/exception strings are not printed."""


class NoticeLimit(Refused):
    """Only the optional notice snapshot's own finite DATA budget expired."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def command_timeout(end: float, now: float, cap: int = 720) -> int:
    # Floor, not ceil; keep the ordinary owner's entire immutable 3s tail.
    require(math.isfinite(end) and math.isfinite(now) and 1 <= cap <= 720, "clock")
    remaining = min(cap, math.floor(end - now - 3))
    require(remaining >= 1, "work-deadline")
    return remaining


def state(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_stream(path: Path, limit: int, consume, poll=lambda: None, *, expected_links: int = 1) -> dict:
    """One original descriptor, bounded chunks, and unchanged named input."""
    require(type(expected_links) is int and expected_links >= 1, "input-link-count")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "regular-input-kind")
    require(before.st_nlink == expected_links, "regular-input-links")
    require(0 <= before.st_size <= limit, "regular-input-size")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(state(os.fstat(fd)) == state(before), "input-open-changed")
        count, digest = 0, hashlib.sha256()
        while True:
            poll()
            piece = os.read(fd, min(CHUNK, before.st_size + 1 - count))
            if not piece:
                break
            count += len(piece)
            require(count <= before.st_size, "input-grew")
            digest.update(piece)
            consume(piece)
        require(count == before.st_size and state(os.fstat(fd)) == state(before), "input-read-changed")
    finally:
        # No fdopen construction/ownership handoff and no close retry.
        os.close(fd)
    require(state(path.lstat()) == state(before), "input-name-changed")
    return {"size": count, "sha256": digest.hexdigest()}


def read_file(path: Path, limit: int, poll=lambda: None) -> bytes:
    pieces = []
    read_stream(path, limit, pieces.append, poll)
    return b"".join(pieces)


def file_digest(path: Path, poll=lambda: None) -> dict:
    return read_stream(path, FILE_LIMIT, lambda _: None, poll)


def write_all(fd: int, body: bytes) -> None:
    remaining = memoryview(body)
    while remaining:
        written = os.write(fd, remaining)
        require(written > 0, "short-write")
        remaining = remaining[written:]


def write_file(path: Path, body: bytes, mode: int = 0o600) -> dict:
    require(len(body) <= FILE_LIMIT, "output-file-limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        write_all(fd, body)
    finally:
        os.close(fd)
    return {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def copy_file(source: Path, destination: Path, poll=lambda: None, mode: int = 0o644) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        row = read_stream(source, FILE_LIMIT, lambda piece: write_all(fd, piece), poll)
    finally:
        os.close(fd)
    require(file_digest(destination, poll) == row, "copy-readback")
    return row


def tree(root: Path, poll=lambda: None) -> list[Path]:
    result, pending, seen, count = [], [root], set(), 0
    while pending:
        poll()
        parent = pending.pop()
        require(stat.S_ISDIR(parent.lstat().st_mode), "tree-directory")
        with os.scandir(parent) as children:
            for item in children:
                poll()
                count += 1
                path = Path(item.path)
                relative = path.relative_to(root).as_posix()
                key = unicodedata.normalize("NFD", relative).casefold()
                require(count <= ENTRY_LIMIT and len(relative) <= 1024
                        and len(path.relative_to(root).parts) <= 32 and key not in seen, "tree-bound-or-alias")
                seen.add(key)
                value = path.lstat()
                if stat.S_ISDIR(value.st_mode):
                    pending.append(path)
                else:
                    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1, "tree-special")
                    result.append(path)
    return sorted(result, key=lambda p: p.relative_to(root).as_posix())


def inventory(root: Path, poll=lambda: None) -> list[dict]:
    rows, total = [], 0
    for path in tree(root, poll):
        row = file_digest(path, poll)
        total += row["size"]
        require(total <= SOURCE_LIMIT, "inventory-byte-limit")
        rows.append({"path": path.relative_to(root).as_posix(), **row, "mode": stat.S_IMODE(path.lstat().st_mode)})
    return rows


def extract_source(archive: Path, selection: dict, destination: Path, poll=lambda: None) -> list[dict]:
    require(type(selection["size"]) is int and 0 < selection["size"] <= 64 * 1024 * 1024, "archive-size-bound")
    body = read_file(archive, selection["size"], poll)
    require(len(body) == selection["size"] and hashlib.sha256(body).hexdigest() == selection["sha256"], "archive-pin")
    destination.mkdir()
    seen, rows, total = set(), [], 0
    # Hash-bound, previously inventoried upstream archives, never arbitrary
    # input. Still never extract links/specials, follow names or use extractall.
    # Decode the same admitted bytes, not a pathname reopened after hashing.
    # The largest of these three fixed compressed inputs is 51 MiB.
    with io.BytesIO(body) as original, tarfile.open(fileobj=original, mode="r|*") as source:
        for member in source:
            poll()
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            require(name and not name.startswith("/") and "\\" not in name and "\x00" not in name
                    and "/".join(parts) == name and ".." not in parts and len(parts) <= 32
                    and parts[0] == selection["root"] and len(name) <= 1024, "archive-path")
            key = unicodedata.normalize("NFD", name).casefold()
            require(key not in seen and len(seen) < ENTRY_LIMIT, "archive-alias-bound")
            seen.add(key)
            require(member.isdir() or member.isfile(), "archive-special")
            target = destination.joinpath(*parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            require(len(parts) > 1 and 0 <= member.size <= 64 * 1024 * 1024, "archive-file-bound")
            total += member.size
            require(total <= SOURCE_LIMIT, "archive-total-bound")
            extracted = source.extractfile(member)
            require(extracted is not None, "archive-body")
            with extracted:
                content = extracted.read(member.size + 1)
            require(len(content) == member.size, "archive-size")
            row = write_file(target, content, 0o755 if member.mode & 0o111 else 0o644)
            require(type(member.mtime) in (int, float) and math.isfinite(member.mtime)
                    and 0 <= member.mtime <= 4102444800, "archive-mtime")
            timestamp = int(member.mtime * 1_000_000_000)
            os.utime(target, ns=(timestamp, timestamp), follow_symlinks=False)
            rows.append({"path": "/".join(parts[1:]), "originalMode": member.mode,
                         "originalMtime": member.mtime, **row})
    require(rows, "empty-source")
    return rows


class Deadline:
    """One existing-style main-thread alarm; no renewal or replacement owner."""
    def __init__(self, end: float, guard):
        self.end, self.guard = end, guard
        self.expired = False
        self.phase = "new"
        self.handler = self.expire

    def expire(self, signum, frame):
        self.expired = True
        self.guard.interrupt(signum, frame)

    def check(self):
        self.guard.check()
        require(not self.expired and time.monotonic() < self.end, "work-deadline")

    def install(self):
        require(self.phase == "new" and signal.getsignal(signal.SIGALRM) is signal.SIG_DFL
                and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "alarm-precondition")
        self.phase = "unknown"
        require(signal.signal(signal.SIGALRM, self.handler) is signal.SIG_DFL, "alarm-install")
        require(signal.setitimer(signal.ITIMER_REAL, max(0.000001, self.end - time.monotonic())) == (0.0, 0.0), "alarm-timer")
        self.phase = "active"

    def finish(self):
        require(self.phase == "active" and signal.getsignal(signal.SIGALRM) is self.handler, "alarm-custody")
        self.expired = self.expired or time.monotonic() >= self.end
        self.phase = "unknown"
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        require(signal.signal(signal.SIGALRM, signal.SIG_DFL) is self.handler, "alarm-restore")
        self.phase = "closed"
        self.expired = self.expired or time.monotonic() >= self.end


class Job:
    def __init__(self, source: Path, root: Path, context: dict, started: float):
        self.source, self.root, self.context = source, root, context
        self.end, self.hard = started + WORK_SECONDS, started + WORK_SECONDS + FINAL_SECONDS
        self.records, self.projections, self.phase = [], [], "startup"
        self.failed, self.evidence_bytes = False, 0
        self.root_identity = (root.stat().st_dev, root.stat().st_ino)
        self.disposable_identities = {name: (path.stat().st_dev, path.stat().st_ino)
            for name in DISPOSABLE_DIRS for path in (root / name,)}
        # Source imports occur only after the native/workflow admission in main.
        sys.path.insert(0, str(source / "src"))
        from mobile_release.cancellation import DefaultCancellation, CleanupScope
        from mobile_release.owned_process import ProcessCleanupError, run_owned
        self.run_owned = run_owned
        self.guard = DefaultCancellation(ProcessCleanupError, "macOS payload original cleanup is incomplete")
        self.clock = Deadline(self.end, self.guard)
        self.scope = CleanupScope(self.guard, self.close_clock, owns_cancellation=True, first_primary=True)
        self.environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                            "HOME": str(root / "home"), "TMPDIR": str(root / "tmp")}
        self.build_environment = dict(self.environment, DEVELOPER_DIR=str(CLT), MACOSX_DEPLOYMENT_TARGET="26.0")

    def close_clock(self):
        if self.clock.phase != "new":
            self.clock.finish()

    def run(self, name: str, argv: list[str], cwd: Path | None = None, env: dict | None = None, cap: int = 720) -> bytes:
        require(not self.failed and len(self.records) < 100 and re.fullmatch(r"[a-z0-9-]{1,64}", name)
                and name not in {row["name"] for row in self.records}, "command-admission")
        self.clock.check()
        self.phase = name
        require(shutil.disk_usage(self.root).free >= 2 * 1024**3, "disk-headroom")
        # Reserve both captures as one summed bound before native dispatch.
        require(self.evidence_bytes + 16 * 1024 * 1024 <= EVIDENCE_LIMIT, "evidence-budget")
        timeout = command_timeout(self.end, time.monotonic(), cap)
        row = {"name": name, "argv": argv, "timeoutSeconds": timeout, "status": "attempted"}
        self.records.append(row)
        try:
            result = self.run_owned(argv, cwd=cwd or self.root, environ=env or self.environment,
                timeout=timeout, output_limit=16 * 1024 * 1024, capture=True, text=False, cancellation=self.guard)
            verdict = self.guard.lifetime_ledger.verdict()
            require(verdict.complete and not verdict.fatal and verdict.commands == len(self.records)
                    and verdict.command_contained is True, "command-original-finality")
            row["originalFinality"] = True
            row["returnCode"] = result.returncode
            row["stdout"] = self.retain(f"{name}.stdout", result.stdout)
            row["stderr"] = self.retain(f"{name}.stderr", result.stderr)
            require(result.returncode == 0, "command-return")
            row["status"] = "complete"
            self.clock.check()
            return result.stdout
        except BaseException:
            self.failed = True
            row["status"] = "failed"
            raise

    def retain(self, name: str, body: bytes):
        require(len(body) <= 32 * 1024 * 1024, "record-bound")
        require(self.evidence_bytes + len(body) <= EVIDENCE_LIMIT, "evidence-budget")
        # Charge attempted writes too: a partial/failed original is not reusable
        # capacity. No later command is allowed after such an error.
        self.evidence_bytes += len(body)
        return write_file(self.root / "evidence" / name, body)

    def save(self, name: str, value: object):
        self.clock.check()
        row = self.retain(name, canonical(value))
        self.clock.check()
        return row

    def copy(self, source: Path, destination: Path, mode: int = 0o644):
        if destination.is_relative_to(self.root / "evidence"):
            size = source.lstat().st_size
            require(0 <= size <= EVIDENCE_LIMIT - self.evidence_bytes, "evidence-budget")
            self.evidence_bytes += size
        row = copy_file(source, destination, self.clock.check, mode)
        self.projections.append({"source": str(source), "destination": str(destination.relative_to(self.root)), **row})
        return row


def pairs(items: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in items:
        require(key not in value, "duplicate-input-key")
        value[key] = item
    return value


def load_inputs(source: Path) -> dict:
    inputs = source / "desktop/macos-payload-inputs"
    value = json.loads(read_file(inputs / "sources.json", 65536), object_pairs_hook=pairs)
    require(type(value) is dict and set(value) == {"schemaVersion", "target", "deploymentTarget", "sources", "ca", "notices"}
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["target"] == TARGET and value["deploymentTarget"] == "26.0"
            and type(value["sources"]) is list and len(value["sources"]) == 3, "input-schema")
    selections = (
        ("cpython", "3.14.7", "Python-3.14.7", "https://www.python.org/ftp/python/3.14.7/Python-3.14.7.tar.xz"),
        ("zlib", "1.3.2", "zlib-1.3.2", "https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz"),
        ("openssl", "3.5.8", "openssl-3.5.8", "https://github.com/openssl/openssl/releases/download/openssl-3.5.8/openssl-3.5.8.tar.gz"))
    for row, selection in zip(value["sources"], selections):
        require(type(row) is dict and set(row) == {"id", "version", "root", "size", "sha256", "url", "authority"}
                and tuple(row[k] for k in ("id", "version", "root", "url")) == selection
                and type(row["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
                and type(row["size"]) is int and 0 < row["size"] <= 64 * 1024 * 1024
                and type(row["authority"]) is str and 0 < len(row["authority"]) <= 512, "source-selection")
    ca = read_file(inputs / "github-ca.pem", 512 * 1024)
    require(value["ca"] == {"path": "github-ca.pem", "size": len(ca), "sha256": hashlib.sha256(ca).hexdigest()}, "ca-pin")
    paths = tree(inputs / "notices")
    require(type(value["notices"]) is dict and 0 < len(paths) <= 32
            and {p.name for p in paths} == set(value["notices"])
            and all(p.parent == inputs / "notices" and re.fullmatch(r"[A-Za-z0-9._-]{1,96}", p.name) for p in paths), "notice-roster")
    for path in paths:
        require(hashlib.sha256(read_file(path, 128 * 1024)).hexdigest() == value["notices"][path.name], "notice-pin")
    return value


def protected_nodes(path: Path, poll, observe, *, directory: bool = False) -> tuple:
    selected = path.resolve(strict=True)
    nodes = (selected, *selected.parents)
    require(len(str(path)) <= 1024 and len(nodes) <= 32
            and all(len(str(node)) <= 1024 for node in nodes), "tool-path-bound")
    originals = []
    for node in nodes:
        poll()
        originals.append((node, node.lstat()))
    facts = {"requestedPath": str(path), "resolvedPath": str(selected), "nodes": [
        {"path": str(node), "device": value.st_dev, "inode": value.st_ino,
         "mode": value.st_mode, "uid": value.st_uid, "links": value.st_nlink,
         "size": value.st_size, "mtimeNs": value.st_mtime_ns, "ctimeNs": value.st_ctime_ns,
         "regular": stat.S_ISREG(value.st_mode), "directory": stat.S_ISDIR(value.st_mode)}
        for node, value in originals]}
    require(len(canonical(facts)) <= 65536, "tool-facts-bound")
    # Preserve actual predicate facts before a possible admission/read refusal.
    # These are fixed public system paths, not environment or exception dumps.
    observe(facts)
    for parent, value in originals:
        require(value.st_uid == 0 and not value.st_mode & 0o022
                and (stat.S_ISREG(value.st_mode) if parent == selected and not directory
                     else stat.S_ISDIR(value.st_mode)), "tool-ownership")
    return selected, originals


def protected_file(path: Path, poll=lambda: None, *, observe=lambda _: None) -> dict:
    selected, originals = protected_nodes(path, poll, observe)
    original = originals[0][1]
    require(original.st_nlink >= 1, "tool-link-count")
    # Only this administratively trusted read-only route admits root-managed
    # hard links. Private source/copy/inventory callers retain exact count one.
    row = read_stream(selected, FILE_LIMIT, lambda _: None, poll, expected_links=original.st_nlink)
    require(state(selected.lstat()) == state(original), "tool-input-changed")
    return {"path": str(selected), "linkCount": original.st_nlink, **row}


def inspect_protected(job: Job, role: str, path: Path, *, observe=lambda _: None) -> dict:
    require(re.fullmatch(r"[a-z0-9-]{1,64}", role), "tool-role")
    job.phase = "inspect-" + role

    def record(facts):
        job.save("protected-" + role + ".json", {"role": role, **facts})
        observe(facts)

    return protected_file(path, job.clock.check, observe=record)


def notice_snapshot(job: Job, resource: Path, sdk: Path, selected_inputs: list[dict], selected_facts: list[dict]) -> None:
    """Fixed public text snapshot, not a license decision or an include crawler."""
    end, total, documents = time.monotonic() + 30, 0, 0
    current = CLT
    report = {"clt": str(CLT), "compilerResourceDirectory": str(resource), "sdk": str(sdk),
        "observed": [], "directories": [], "unresolved": [], "snapshotBytes": 0,
        "limits": {"seconds": 30, "dataBytes": NOTICE_DATA_LIMIT, "manifestBytes": 65536,
                   "directoryEntries": 128, "vendorDocuments": 8, "documentBytes": 2 * 1024 * 1024,
                   "ffiDelegates": 4},
        "review": "unfinished-not-an-approval",
        "reason": "Exact selected Apple CLT/SDK/LLVM runtime/header obligations need independent reconciliation."}

    def poll():
        job.clock.check()  # Global deadline/cancellation always wins; never softened.
        if time.monotonic() >= end:
            raise NoticeLimit("snapshot-time-limit")

    def record(group, row):
        report[group].append(row)
        # Leave room for one final bounded local-limit diagnostic.
        if len(canonical(report)) > 65536 - 2048:
            report[group].pop()
            raise NoticeLimit("snapshot-manifest-limit")

    def unresolved(path, reason, **facts):
        record("unresolved", {"source": str(path), "reason": reason, **facts})

    def admit(path, *, directory=False, expected=None, allow_missing=True, parent=None):
        poll()
        try:
            path.lstat()
        except FileNotFoundError:
            if expected is not None or not allow_missing:
                raise Refused("notice-selected-input-missing")
            unresolved(path, "missing")
            return None
        observed = []
        resolved, originals = protected_nodes(path, poll, observed.append, directory=directory)
        facts = observed[0]
        if expected is not None:
            require(facts == expected, "notice-selected-input-changed")
        # Only the one explicitly named receipt may resolve outside CLT.
        receipt = path == Path("/var/db/receipts/com.apple.pkg.CLTools_Executables.plist")
        if not (resolved.is_relative_to(CLT) or receipt and resolved in {
                path, Path("/private/var/db/receipts/com.apple.pkg.CLTools_Executables.plist")}) \
                or parent is not None and resolved.parent != parent:
            unresolved(path, "out-of-scope", resolvedPath=str(resolved))
            return None
        return resolved, originals, facts

    def unchanged(path, resolved, originals):
        for node, original in originals:
            poll()
            after = node.lstat()
            require(state(after) == state(original) and after.st_uid == original.st_uid, "notice-input-changed")
        require(path.resolve(strict=True) == resolved, "notice-route-changed")

    def capture(path, cap, *, index=None, allow_missing=True, parent=None):
        nonlocal total, current
        current, job.phase = path, "vendor-notice-snapshot"
        admitted = admit(path, expected=selected_facts[index] if index is not None else None,
                         allow_missing=allow_missing, parent=parent)
        if admitted is None:
            return None
        resolved, originals, facts = admitted
        original = originals[0][1]
        require(original.st_nlink >= 1, "tool-link-count")
        if original.st_size > cap:
            unresolved(path, "file-size-limit", protected=facts)
            return None
        if total + original.st_size > NOTICE_DATA_LIMIT:
            raise NoticeLimit("snapshot-data-limit")
        pieces = []
        row = read_stream(resolved, cap, pieces.append, poll, expected_links=original.st_nlink)
        unchanged(path, resolved, originals)
        if index is not None:
            require({"path": str(resolved), "linkCount": original.st_nlink, **row} == selected_inputs[index],
                    "notice-selected-input-changed")
        body = b"".join(pieces)
        destination = f"vendor/input-{len(report['observed']):02d}{path.suffix.lower()}"
        item = {"source": str(path), "destination": "evidence/" + destination,
                "protected": facts, "linkCount": original.st_nlink, **row}
        poll()  # Admission and the complete original read precede any output.
        record("observed", item)
        # Once publishing starts, settle its bounded write/readback under the
        # existing global clock; local expiry cannot conceal a partial copy.
        require(job.retain(destination, body) == row, "notice-copy-write")
        require(file_digest(job.root / "evidence" / destination, job.clock.check) == row, "notice-copy-readback")
        job.projections.append({"source": str(path), "resolvedSource": str(resolved),
                                "destination": item["destination"], **row})
        total += row["size"]
        report["snapshotBytes"] = total
        return body

    try:
        wrapper = None
        for path, index in ((resource / "include/stddef.h", 1), (resource / "include/stdarg.h", 2),
                            (resource / "include/stdint.h", 3), (sdk / "usr/include/ffi/ffi.h", 5),
                            (sdk / "usr/include/ffi/ffitarget.h", 6), (sdk / "SDKSettings.json", 4)):
            body = capture(path, 65536 if index == 4 else 128 * 1024, index=index)
            if index == 6:
                wrapper = body
        # Only direct literal declarations in the selected small wrapper.
        # Both architecture notices may be retained; no macros or recursion.
        delegates = set()
        for number, line in enumerate((wrapper or b"").splitlines(), 1):
            poll()
            if not re.match(rb"^[ \t]*#[ \t]*include\b", line):
                continue
            match = re.fullmatch(rb'[ \t]*#[ \t]*include[ \t]*(?:"([^"\r\n]+)"|<([^>\r\n]+)>)[ \t]*(?://.*)?', line)
            name = (match[1] or match[2]) if match else b""
            if name.startswith(b"ffi/"):
                name = name[4:]
            if not re.fullmatch(rb"[A-Za-z0-9_+.-]{1,128}\.h", name):
                unresolved(sdk / "usr/include/ffi/ffitarget.h", "ffi-include-out-of-scope", line=number)
                continue
            if name in {b"ffi.h", b"ffitarget.h"} or name in delegates:
                continue
            current = sdk / "usr/include/ffi" / name.decode("ascii")
            if len(delegates) == 4:
                raise NoticeLimit("ffi-include-limit")
            delegates.add(name)
            capture(sdk / "usr/include/ffi" / name.decode("ascii"), 128 * 1024,
                    parent=sdk / "usr/include/ffi")
        capture(Path("/var/db/receipts/com.apple.pkg.CLTools_Executables.plist"), 65536)
        for directory in (CLT, CLT / "Library/Documentation", CLT / "usr/share",
                          CLT / "usr/share/doc", CLT / "usr/share/clang", resource):
            current = directory
            admitted = admit(directory, directory=True)
            if admitted is None:
                continue
            resolved, originals, facts = admitted
            candidates, names, count = [], set(), 0
            with os.scandir(resolved) as children:
                for item in children:
                    poll()
                    count += 1
                    if count > 128:
                        break
                    name = item.name.lower()
                    names.add(name)
                    if name.endswith((".txt", ".rtf", ".pdf")) and any(word in name for word in (
                            "license", "licence", "copyright", "notice", "acknowledg")):
                        candidates.append(directory / item.name)
            unchanged(directory, resolved, originals)
            record("directories", {"source": str(directory), "protected": facts, "entriesSeen": count,
                                   "complete": count <= 128, "candidateCount": len(candidates)})
            if count > 128:
                unresolved(directory, "directory-entry-limit")
                continue
            former = {CLT: "License.rtf", CLT / "Library/Documentation": "License.rtf",
                      CLT / "usr/share/clang": "LICENSE.txt"}.get(directory)
            if former and former.lower() not in names:
                unresolved(directory / former, "missing")
            for path in sorted(candidates):
                current = path
                if documents == 8:
                    raise NoticeLimit("vendor-document-limit")
                documents += 1
                capture(path, 2 * 1024 * 1024, allow_missing=False)
    except NoticeLimit as error:
        # Only our own local DATA budget is recoverable. Ownership/input drift,
        # original close, global deadline/cancellation and write errors escape.
        report["unresolved"].append({"source": str(current), "reason": error.args[0]})
    require(len(canonical(report)) <= 65536, "notice-manifest-limit")
    job.save("vendor-attribution-inputs.json", report)


def selected_tool(job: Job, name: str, raw: bytes) -> tuple[str, dict]:
    """Keep a fixed tool's invocation role separate from its physical identity."""
    require(name in TOOL_NAMES, "tool-role")
    role = name.replace("_", "-")
    job.phase = "inspect-" + role
    bins = (CLT / "usr/bin", Path("/usr/bin"))
    choices = {str(directory / name).encode("ascii"): directory / name for directory in bins}
    require(type(raw) is bytes and 0 < len(raw) <= 1025
            and raw.removesuffix(b"\n") in choices, "tool-selection")
    invocation = choices[raw.removesuffix(b"\n")]
    current, originals, aliases = invocation, {}, {}

    def save_route(facts: dict | None = None) -> None:
        record = {"role": role, **(facts or {}), "invocationPath": str(invocation), "invocationRoute": [
            {"path": str(node), "device": value.st_dev, "inode": value.st_ino,
             "mode": value.st_mode, "uid": value.st_uid, "links": value.st_nlink,
             "size": value.st_size, "mtimeNs": value.st_mtime_ns, "ctimeNs": value.st_ctime_ns,
             **({"linkTarget": aliases[node]} if node in aliases else {})}
            for node, value in originals.items()]}
        require(len(canonical(record)) <= 65536, "tool-facts-bound")
        job.save("protected-" + role + ".json", record)

    try:
        while True:
            require(current.parent in bins, "tool-origin")
            require(current not in aliases, "tool-alias-cycle")
            for node in (current, *current.parents):
                job.clock.check()
                require(len(str(node)) <= 1024, "tool-path-bound")
                if node not in originals:
                    require(len(originals) < 32, "tool-path-bound")
                    originals[node] = node.lstat()
                value = originals[node]
                is_alias = node == current and stat.S_ISLNK(value.st_mode)
                expected_kind = is_alias or stat.S_ISREG(value.st_mode) if node == current else stat.S_ISDIR(value.st_mode)
                require(value.st_uid == 0 and (is_alias or not value.st_mode & 0o022)
                        and expected_kind, "tool-route-ownership")
            if not stat.S_ISLNK(originals[current].st_mode):
                break
            require(len(aliases) < 8, "tool-alias-limit")
            target = os.readlink(current)
            require(0 < len(target) <= 1024, "tool-alias-target")
            aliases[current] = target
            destination = Path(target)
            require(re.fullmatch(r"[A-Za-z0-9_+.-]{1,255}", destination.name)
                    and destination.name not in {".", ".."}
                    and (destination.is_absolute() and str(destination) == target and destination.parent in bins
                         or not destination.is_absolute() and destination.name == target), "tool-alias-target")
            current = destination if destination.is_absolute() else current.parent / destination
        require(invocation.resolve(strict=True) == current, "tool-alias-resolution")
    except (OSError, Refused):
        save_route()
        raise

    row = protected_file(invocation, job.clock.check, observe=save_route)
    require(row["path"] == str(current), "tool-alias-resolution")
    for node, original in originals.items():
        job.clock.check()
        after = node.lstat()
        require(state(after) == state(original) and after.st_uid == original.st_uid, "tool-route-changed")
        if node in aliases:
            require(os.readlink(node) == aliases[node], "tool-route-changed")
    require(invocation.resolve(strict=True) == current, "tool-alias-resolution")
    # ranlib and libtool may be the same bytes but are not the same invocation.
    return str(invocation), {"invocationPath": str(invocation), **row}


def source_binding(job: Job, git: str) -> None:
    environment = dict(job.environment, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    argv = [git, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"]
    identity = job.run("source-identity", [*argv, "rev-parse", "HEAD", "HEAD^{tree}"], job.source, environment, 15)
    parts = identity.decode("ascii").splitlines()
    require(len(parts) == 2 and parts[0] == job.context["sourceSha"]
            and re.fullmatch(r"[0-9a-f]{40}", parts[1]), "source-identity")
    require(job.run("source-clean", [*argv, "status", "--porcelain=v1", "--untracked-files=all", "--ignored"],
                    job.source, environment, 15) == b"", "source-not-clean")
    job.context["sourceTree"] = parts[1]
    job.save("source-binding.json", {**job.context,
        "driver": file_digest(job.source / "desktop/tools/macos_payload.py", job.clock.check),
        "hostPython": {"path": sys.executable, "version": sys.version,
            **file_digest(Path(sys.executable).resolve(strict=True), job.clock.check)}})


def prepare_tools(job: Job) -> dict:
    require(not os.path.lexists(PREFIX) and CLT.is_dir(), "compiler-prefix-or-clt")
    env = job.build_environment
    tools, identities = {}, {"xcrun": inspect_protected(job, "xcrun", Path("/usr/bin/xcrun"))}
    sdk_raw = job.run("sdk-selection", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], env=env, cap=30)
    sdk = Path(sdk_raw.decode("utf-8").strip()).resolve(strict=True)
    require(sdk.is_relative_to(CLT / "SDKs") and sdk.name.startswith("MacOSX") and sdk.name.endswith(".sdk"), "sdk-selection")
    for name in TOOL_NAMES:
        raw = job.run("select-" + name.replace("_", "-"), ["/usr/bin/xcrun", "--find", name], env=env, cap=30)
        tools[name], identities[name] = selected_tool(job, name, raw)
    for name in ("sh", "perl", "curl", "git"):
        path = Path("/bin/sh") if name == "sh" else Path("/usr/bin") / name
        identities[name] = inspect_protected(job, name, path)
        tools[name] = str(path)
    tools["sdk"] = str(sdk)
    tools["clangVersion"] = job.run("clang-version", [tools["clang"], "--version"], env=env, cap=30).decode("utf-8")
    source_binding(job, tools["git"])
    resource = Path(job.run("clang-resources", [tools["clang"], "-print-resource-dir"], env=env, cap=30).decode("utf-8").strip()).resolve(strict=True)
    require(resource.is_relative_to(CLT / "usr/lib/clang") and resource.is_dir(), "compiler-resource-origin")
    # Actual selected metadata/inputs, not a broad SDK census or a claim that
    # all files in the Apple installation have been independently audited.
    compiler_inputs, compiler_facts = [], []
    for index, path in enumerate((resource / "lib/darwin/libclang_rt.osx.a", resource / "include/stddef.h",
                 resource / "include/stdarg.h", resource / "include/stdint.h", sdk / "SDKSettings.json",
                 sdk / "usr/include/ffi/ffi.h", sdk / "usr/include/ffi/ffitarget.h",
                 sdk / "usr/lib/libSystem.tbd", sdk / "usr/lib/libffi.tbd")):
        job.phase = f"inspect-compiler-input-{index}"
        require(path.resolve(strict=True).is_relative_to(CLT), "compiler-input-origin")
        compiler_inputs.append(inspect_protected(job, f"compiler-input-{index}", path, observe=compiler_facts.append))
    job.build_environment.update(SDKROOT=str(sdk), CC=tools["clang"], AR=tools["ar"], RANLIB=tools["ranlib"],
        LD=tools["ld"], CFLAGS=f"-arch arm64 -O2 -g0 -isysroot {sdk}", CPPFLAGS=f"-isysroot {sdk}",
        LDFLAGS=f"-arch arm64 -isysroot {sdk} -Wl,-headerpad_max_install_names",
        PYTHONSTRICTEXTENSIONBUILD="1")
    job.save("toolchain.json", {"tools": tools, "identities": identities, "compilerResourceDirectory": str(resource),
        "selectedCompilerInputs": compiler_inputs, "environment": job.build_environment,
        "kernel": tuple(os.uname()), "policy": "administratively-trusted-native-Apple-CLT",
        "sourceAttributionReview": "required", "protectedOSDependencies": sorted(SYSTEM_DEPS)})
    notice_snapshot(job, resource, sdk, compiler_inputs, compiler_facts)
    return tools


def acquire_sources(job: Job, inputs: dict, tools: dict):
    root = job.root
    for selection in inputs["sources"]:
        archive = root / "downloads" / (selection["id"] + ".archive")
        job.run("acquire-" + selection["id"], [tools["curl"], "--disable", "--fail", "--silent", "--show-error",
            "--location", "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "3",
            "--connect-timeout", "10", "--max-time", "180", "--max-filesize", str(selection["size"]),
            "--output", str(archive), "--url", selection["url"]], cap=190)
        rows = extract_source(archive, selection, root / "sources" / selection["id"], job.clock.check)
        job.save(selection["id"] + "-source-inventory.json", rows)


def make_value(text: str, key: str) -> str:
    values = re.findall(r"^" + re.escape(key) + r"[ \t]*=[ \t]*(.*)$", text, re.M)
    require(len(values) == 1, "make-assignment")
    return values[0].strip()


def no_bytecode_make(text: str) -> list[str]:
    # Configure.ac173-174's native defaults, kept byte-for-byte. A different
    # hostrunner/cross-build recipe needs review, not shell evaluation/fallback.
    defaults = {"PYTHON_FOR_BUILD": "./$(BUILDPYTHON) -E", "PYTHON_FOR_FREEZE": "./_bootstrap_python"}
    require(all(make_value(text, key) == value for key, value in defaults.items()), "python-build-defaults")
    return [key + "=" + value + " -B" for key, value in defaults.items()]


def build_executable(text: str) -> str:
    # Configure.ac1365-1381 selects .exe on case-insensitive APFS, because the
    # build also contains the Python/ directory. Do not probe/adopt a filename.
    suffix = make_value(text, "BUILDEXE")
    require(suffix in ("", ".exe") and make_value(text, "BUILDPYTHON") == "python$(BUILDEXE)", "python-build-name")
    return "python" + suffix


def builtin_table(text: str) -> set[str]:
    # Same bounded generated-config parser as cpython_static_inputs, without
    # transplanting that Linux profile's expected count or disabled roster.
    table = re.search(r"struct _inittab _PyImport_Inittab\[\] = \{(.*?)\n\};", text, re.S)
    require(table is not None, "builtin-table")
    body = re.sub(r"/\*.*?\*/", "", table[1], flags=re.S)
    row = r'\{\s*"([A-Za-z0-9_]+)"\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\},'
    names = re.findall(row, body)
    require(len(names) == len(set(names)) and re.fullmatch(r"\{\s*0\s*,\s*0\s*\}", re.sub(row, "", body).strip())
            is not None, "builtin-table-shape")
    return set(names)


def setup_names(text: str) -> dict[str, set[str]]:
    result, section = {"static": set(), "disabled": set()}, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line in {"*static*", "*disabled*"}:
            section = line.strip("*")
            continue
        name = line.split()[0]
        require(section is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
                and not any(name in values for values in result.values()), "setup-roster")
        result[section].add(name)
    return result


def generated_configuration(python_build: Path, poll=lambda: None) -> dict[str, Path]:
    # Makefile.pre.in generates all three leaves beneath pybuilddir.txt, not
    # the make working directory. Select once for evidence and payload copies.
    relative = read_file(python_build / "pybuilddir.txt", 4096, poll).decode("ascii").removesuffix("\n")
    parts = PurePosixPath(relative).parts
    require(parts and len(relative) <= 1024 and len(parts) <= 32 and not relative.startswith("/")
            and "/".join(parts) == relative
            and all(part not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts), "pybuilddir")
    generated = python_build
    require(stat.S_ISDIR(generated.lstat().st_mode), "pybuilddir-directory")
    for part in parts:
        poll()
        generated = generated / part
        require(stat.S_ISDIR(generated.lstat().st_mode), "pybuilddir-directory")
    selected = {}
    with os.scandir(generated) as children:
        for count, item in enumerate(children, 1):
            poll()
            require(count <= ENTRY_LIMIT, "sysconfig-roster-bound")
            for prefix, suffix in (("_sysconfigdata_", ".py"), ("_sysconfig_vars_", ".json")):
                if item.name.startswith(prefix) and item.name.endswith(suffix):
                    require(prefix not in selected and re.fullmatch(r"[A-Za-z0-9_.-]+", item.name), "sysconfig-roster")
                    selected[prefix] = Path(item.path)
    require(len(selected) == 2, "sysconfig-roster")
    result = {"build-details.json": generated / "build-details.json",
              **{path.name: path for path in selected.values()}}
    for path in result.values():
        poll()
        value = path.lstat()
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                and 0 <= value.st_size <= FILE_LIMIT, "generated-configuration-file")
    return result


def retain_build_configuration(job: Job) -> None:
    # CPython is built out of tree. Modules/Setup is a source input, unlike
    # the generated/seeded build files; never adopt a same-named build decoy.
    sources = {
        "Makefile": "build/cpython/Makefile",
        "pyconfig.h": "build/cpython/pyconfig.h",
        "Modules/config.c": "build/cpython/Modules/config.c",
        "Modules/Setup": "sources/cpython/Modules/Setup",
        "Modules/Setup.local": "build/cpython/Modules/Setup.local",
        "Modules/Setup.bootstrap": "build/cpython/Modules/Setup.bootstrap",
        "Modules/Setup.stdlib": "build/cpython/Modules/Setup.stdlib",
        "pybuilddir.txt": "build/cpython/pybuilddir.txt",
    }
    for name, source in sources.items():
        job.phase = "configuration-" + name.replace("/", "-")
        job.copy(job.root / source, job.root / "evidence/configuration" / name)


def build(job: Job, tools: dict) -> dict[str, Path]:
    root, env = job.root, job.build_environment
    deps = root / "deps"
    zlib = root / "sources/zlib"
    job.run("zlib-configure", [tools["sh"], str(zlib / "configure"), "--static", f"--prefix={deps}"], zlib, env)
    job.run("zlib-build", [tools["make"], "-j2"], zlib, env)
    job.run("zlib-install", [tools["make"], "-j2", "install"], zlib, env)
    openssl = root / "sources/openssl"
    job.run("openssl-configure", [tools["perl"], str(openssl / "Configure"), "darwin64-arm64-cc", "shared",
        "no-module", "no-dso", "no-engine", "no-autoload-config", "no-legacy", "no-tests",
        f"--prefix={deps}", "--libdir=lib", f"--openssldir={deps}/no-config"], openssl, env)
    job.run("openssl-build", [tools["make"], "-j2", "build_libs"], openssl, env)
    job.run("openssl-install", [tools["make"], "-j2", "install_dev"], openssl, env)
    python = root / "build/cpython"
    (python / "Modules").mkdir(parents=True)
    job.copy(job.source / "desktop/tools/cpython_macos_setup.local", python / "Modules/Setup.local")
    env = dict(env, ZLIB_CFLAGS=f"-I{deps}/include", ZLIB_LIBS=f"{deps}/lib/libz.a")
    options = [f"--prefix={PREFIX}", "--with-platlibdir=lib", "--disable-framework", "--disable-shared",
        "--without-mimalloc", "--with-pymalloc", "--with-lto=no", "--disable-optimizations", "--disable-test-modules",
        "--with-ensurepip=no", "--with-pkg-config=no", "--without-system-expat", f"--with-openssl={deps}", "--with-openssl-rpath=no"]
    job.run("python-configure", [tools["sh"], str(root / "sources/cpython/configure"), *options], python, env)
    configured = read_file(python / "Makefile", 4 * 1024 * 1024, job.clock.check).decode("utf-8")
    job.python_build_name = build_executable(configured)
    make = [tools["make"], "-j2", *no_bytecode_make(configured)]
    job.run("builtin-archives", [*make, *(f"Modules/_hacl/libHacl_{name}.a" for name in HACL), "Modules/expat/libexpat.a"], python, env)
    job.run("python-build", [*make, job.python_build_name, "platform", "checksharedmods", "build-details.json"], python, env)
    # Preserve real generated configuration before classifying it. A roster/
    # native-profile refusal must not require another build just for diagnosis.
    retain_build_configuration(job)
    job.phase = "configuration-openssl-configdata"
    job.copy(openssl / "configdata.pm", root / "evidence/configuration/openssl-configdata.pm")
    job.phase = "configuration-generated-selection"
    generated = generated_configuration(python, job.clock.check)
    job.phase = "configuration-generated-copies"
    for name, path in generated.items():
        job.copy(path, root / "evidence/configuration" / name)
    config = read_file(python / "pyconfig.h", 1024 * 1024, job.clock.check).decode("ascii")
    require("#define Py_GIL_DISABLED 1" not in config and "#define Py_ENABLE_SHARED 1" not in config
            and "#define WITH_PYMALLOC 1" in config, "python-config")
    makefile = read_file(python / "Makefile", 4 * 1024 * 1024, job.clock.check).decode("utf-8")
    require("USING_APPLE_OS_LIBFFI=1" in makefile and "USING_MALLOC_CLOSURE_DOT_C=1" in makefile, "darwin-libffi")
    local = setup_names(read_file(python / "Modules/Setup.local", 65536, job.clock.check).decode("ascii"))
    bootstrap = setup_names(read_file(python / "Modules/Setup.bootstrap", 65536, job.clock.check).decode("ascii"))
    intrinsic = builtin_table(read_file(root / "sources/cpython/Modules/config.c.in", 65536, job.clock.check).decode("ascii"))
    builtins = builtin_table(read_file(python / "Modules/config.c", 65536, job.clock.check).decode("ascii"))
    expected = local["static"] | bootstrap["static"] | intrinsic
    require(builtins == expected and not bootstrap["disabled"], "darwin-builtin-roster")
    for key, wanted in (("MODBUILT_NAMES", local["static"] | bootstrap["static"]),
                        ("MODDISABLED_NAMES", local["disabled"]), ("MODSHARED_NAMES", set())):
        words = make_value(makefile, key).split()
        require(len(words) == len(set(words)) and set(words) == wanted, "make-module-roster")
    job.expected_builtins = sorted(expected)
    job.save("builtin-roster.json", {"generatedConfig": sorted(builtins), "generatedBootstrap": sorted(bootstrap["static"]),
                                   "configuredStatic": sorted(local["static"]), "intrinsic": sorted(intrinsic)})
    return generated


def macho_header(text: str, kind: str) -> int:
    """One thin ordinary ARM64 file, not a substring in a fat/mixed header."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    require(kind in {"EXECUTE", "DYLIB"} and len(lines) == 4 and lines[1] == "Mach header"
            and lines[2].split()[:7] == ["magic", "cputype", "cpusubtype", "caps", "filetype", "ncmds", "sizeofcmds"], "macho-header")
    fields = lines[3].split()
    require(len(fields) >= 8 and fields[:5] == ["MH_MAGIC_64", "ARM64", "ALL", "0x00", kind]
            and fields[5].isdigit() and fields[6].isdigit()
            and 0 < int(fields[5]) <= 128 and 0 < int(fields[6]) <= 1024 * 1024, "macho-architecture")
    return int(fields[5])


def library_commands(text: str, count: int) -> dict:
    """Closed load-path policy over the actual tool's complete command list."""
    require(len(text) <= 1024 * 1024 and 0 < count <= 128, "macho-output")
    blocks = re.split(r"^Load command ([0-9]+)\n", text, flags=re.M)
    require(len(blocks) == count * 2 + 1 and blocks[0].endswith(":\n")
            and len(blocks[0].splitlines()) == 1, "macho-command-count")
    deps, rpaths, ids, linkers, versions = [], [], [], [], []
    path_free = {"LC_SEGMENT_64", "LC_SYMTAB", "LC_DYSYMTAB", "LC_UUID", "LC_SOURCE_VERSION",
                 "LC_MAIN", "LC_FUNCTION_STARTS", "LC_DATA_IN_CODE", "LC_CODE_SIGNATURE",
                 "LC_DYLD_INFO_ONLY", "LC_DYLD_EXPORTS_TRIE", "LC_DYLD_CHAINED_FIXUPS"}
    for index in range(count):
        require(blocks[index * 2 + 1] == str(index), "macho-command-order")
        body = blocks[index * 2 + 2]
        commands = re.findall(r"^\s*cmd ([A-Z0-9_]+)$", body, re.M)
        require(len(commands) == 1, "macho-command")
        command = commands[0]
        if command in {"LC_LOAD_DYLIB", "LC_ID_DYLIB", "LC_LOAD_DYLINKER", "LC_RPATH"}:
            field = "path" if command == "LC_RPATH" else "name"
            values = re.findall(r"^\s*" + field + r" ([ -~]+) \(offset [0-9]+\)$", body, re.M)
            require(len(values) == 1 and len(values[0]) <= 1024, "macho-load-name")
            {"LC_LOAD_DYLIB": deps, "LC_ID_DYLIB": ids, "LC_LOAD_DYLINKER": linkers, "LC_RPATH": rpaths}[command].append(values[0])
        elif command == "LC_BUILD_VERSION":
            platform = re.findall(r"^\s*platform (\S+)$", body, re.M)
            minimum = re.findall(r"^\s*minos (\S+)$", body, re.M)
            require(platform in (["1"], ["MACOS"]) and minimum in (["26.0"], ["26.0.0"]), "macho-deployment")
            versions.append("26.0")
        else:
            # In particular weak/upward/reexport/lazy libraries, environment
            # commands and undeclared load routes do not silently disappear.
            require(command in path_free, "macho-undeclared-command")
    require(len(deps) == len(set(deps)) and len(rpaths) == len(set(rpaths))
            and len(ids) <= 1 and len(linkers) <= 1 and versions == ["26.0"], "macho-load-roster")
    return {"dependencies": deps, "rpaths": rpaths, "id": ids[0] if ids else None,
            "dylinker": linkers[0] if linkers else None, "deploymentTarget": versions[0]}


def relocation(before: dict, index: int, root: Path) -> tuple[dict[str, str], dict]:
    require(index in (0, 1, 2), "macho-role")
    private = set()
    changes = {}
    for dependency in before["dependencies"]:
        if dependency in SYSTEM_DEPS:
            continue
        name = Path(dependency).name
        require(name in DYLIBS and dependency == str(root / "deps/lib" / name), "macho-undeclared-dependency")
        private.add(name)
        changes[dependency] = ("@executable_path/../lib/" if index == 0 else "@loader_path/") + name
    expected_private = ({*DYLIBS}, set(), {"libcrypto.3.dylib"})[index]
    require(private == expected_private and all(p == str(root / "deps/lib") for p in before["rpaths"])
            and before["id"] == (None if index == 0 else str(root / "deps/lib" / DYLIBS[index - 1]))
            and before["dylinker"] == ("/usr/lib/dyld" if index == 0 else None), "macho-original-role")
    after = dict(before, dependencies=[changes.get(d, d) for d in before["dependencies"]], rpaths=[],
                 id=None if index == 0 else "@rpath/" + DYLIBS[index - 1])
    return changes, after


def project(job: Job, tools: dict, generated: dict[str, Path]) -> Path:
    root = job.root
    payload = root / "payload"
    runtime = payload / "python"
    python_build = root / "build/cpython"
    native = [(python_build / job.python_build_name, runtime / "bin/python3")]
    native.extend((root / "sources/openssl" / name, runtime / "lib" / name) for name in DYLIBS)
    for source, destination in native:
        job.copy(source, root / "evidence/original-build" / destination.name)
        job.copy(source, destination, 0o755)
    for path in tree(root / "sources/cpython/Lib", job.clock.check):
        relative = path.relative_to(root / "sources/cpython/Lib")
        if path.suffix == ".py" and not any(p in OMIT for p in relative.parts) and path.name != "turtle.py":
            job.copy(path, runtime / "lib/python3.14" / relative)
    for name, path in generated.items():
        job.copy(path, runtime / "lib/python3.14" / name)
    job.copy(root / "sources/cpython/LICENSE", runtime / "LICENSE.txt")
    write_file(runtime / "lib/python3.14/lib-dynload/README.txt", b"This fixed CPython profile uses builtin extension modules.\n", 0o644)
    with zipfile.ZipFile(runtime / "lib/python314.zip", "x"):
        pass
    correspondence = []
    for index, (source, destination) in enumerate(native):
        kind = "EXECUTE" if index == 0 else "DYLIB"
        original = file_digest(destination, job.clock.check)
        require(original == file_digest(root / "evidence/original-build" / destination.name, job.clock.check), "native-original-copy")
        header = job.run(f"macho-header-{index}", [tools["otool"], "-hv", str(destination)], cap=30).decode("utf-8")
        count = macho_header(header, kind)
        before = job.run(f"macho-before-{index}", [tools["otool"], "-l", str(destination)], cap=30).decode("utf-8")
        loads = library_commands(before, count)
        changes, expected = relocation(loads, index, root)
        if index:
            job.run(f"id-{index}", [tools["install_name_tool"], "-id", expected["id"], str(destination)])
        for number, (dependency, replacement) in enumerate(changes.items()):
            job.run(f"relocate-{index}-{number}", [tools["install_name_tool"], "-change", dependency, replacement, str(destination)])
        for number, rpath in enumerate(loads["rpaths"]):
            job.run(f"remove-rpath-{index}-{number}", [tools["install_name_tool"], "-delete_rpath", rpath, str(destination)])
        relocated = file_digest(destination, job.clock.check)
        job.run(f"adhoc-sign-{index}", [tools["codesign"], "--force", "--sign", "-", str(destination)], cap=60)
        job.run(f"verify-sign-{index}", [tools["codesign"], "--verify", "--strict", str(destination)], cap=30)
        final_header = job.run(f"macho-final-header-{index}", [tools["otool"], "-hv", str(destination)], cap=30).decode("utf-8")
        after = job.run(f"macho-after-{index}", [tools["otool"], "-l", str(destination)], cap=30).decode("utf-8")
        require(library_commands(after, macho_header(final_header, kind)) == expected, "macho-final-load-policy")
        correspondence.append({"source": str(source), "destination": str(destination.relative_to(root)),
            "original": original, "relocated": relocated, "signed": file_digest(destination, job.clock.check),
            "beforeLoadCommands": loads, "afterLoadCommands": expected, "signature": "verified-ad-hoc-not-Developer-ID"})
        job.save(f"native-correspondence-{index}.json", correspondence[-1])
    return payload


def package(job: Job, inputs: dict, payload: Path) -> dict:
    source = job.source
    spec = importlib.util.spec_from_file_location("mrk_payload_preparer", source / "desktop/tools/prepare_runtime.py")
    require(spec is not None and spec.loader is not None, "preparer-source")
    preparer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preparer)
    package_source = job.root / "package-source"
    for path in tree(source / "src/mobile_release", job.clock.check):
        relative = path.relative_to(source / "src/mobile_release")
        job.copy(path, package_source / "src/mobile_release" / relative)
    for name in preparer.BOOTSTRAPS:
        job.copy(source / "desktop" / name, package_source / "desktop" / name)
    job.copy(source / "desktop/macos-payload-inputs/github-ca.pem", package_source / "desktop/github-ca.pem")
    for name in inputs["notices"]:
        job.copy(source / "desktop/macos-payload-inputs/notices" / name, payload / "python/licenses" / name)
    changes = ("Mobile Release Kit native macOS26 ARM64 technical payload.\n"
        "Ordinary GIL/non-framework static CPython; static zlib and builtin modules, private shared OpenSSL.\n"
        "ctypes uses the selected Apple SDK/OS libffi, not separately built libffi3.4.8.\n"
        "Source stdlib is pruned as recorded; native copies have payload-relative load paths and ad-hoc signatures.\n"
        "Apple CLT/SDK/LLVM incorporation/redistribution obligations require independent review.\n"
        "This is not an accepted distribution, installed runtime or notarized application.\n")
    write_file(payload / "python/licenses/PYTHON-CHANGES.txt", changes.encode("ascii"), 0o644)
    job.clock.check()
    result = preparer.prepare(package_source, payload, TARGET)
    job.clock.check()
    job.save("preparation.json", result)
    return result


SMOKE = r'''import ctypes, hashlib, json, os, pathlib, resource, ssl, sys, zlib
from xml.parsers import expat
p = pathlib.Path(sys.argv[1])
assert sys.version_info[:3] == (3, 14, 7) and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
assert pathlib.Path(sys.executable) == p / 'python/bin/python3'
assert sys.prefix == str(p / 'python') and sys.base_prefix == sys.prefix and sys.exec_prefix == sys.prefix
assert sys._is_gil_enabled() and not sys.flags.optimize
assert set(os.environ) == {'PATH', 'LANG', 'LC_ALL', 'TZ', 'HOME', 'TMPDIR'}
assert all(not v or pathlib.Path(v).is_relative_to(p / 'python') for v in sys.path)
assert hashlib.sha256(b'abc').hexdigest() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
assert zlib.decompress(zlib.compress(b'mrk')) == b'mrk' and ssl.OPENSSL_VERSION.startswith('OpenSSL 3.5.8 ')
assert ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(lambda n: n + 1)(4) == 5
assert resource.getrlimit(resource.RLIMIT_NOFILE)[0] > 0
parser = expat.ParserCreate(); parser.Parse(b'<a/>', True)
required = {'_ssl', '_socket', '_ctypes', 'zlib', 'pyexpat', 'resource', '_json', '_sha2', '_hmac'}
assert required <= set(sys.builtin_module_names)
lib = ctypes.CDLL(None)
lib._dyld_image_count.argtypes = []; lib._dyld_image_count.restype = ctypes.c_uint32
lib._dyld_get_image_name.argtypes = [ctypes.c_uint32]; lib._dyld_get_image_name.restype = ctypes.c_char_p
count = lib._dyld_image_count(); assert 0 < count <= 4096
images = [lib._dyld_get_image_name(n).decode('utf-8') for n in range(count)]
assert all(os.path.isabs(v) and len(v) <= 4096 for v in images)
normalized = [os.path.normpath(v) for v in images]
assert all(v.startswith(('/System/Library/', '/usr/lib/', str(p / 'python') + '/')) for v in normalized)
assert str(p / 'python/lib/libssl.3.dylib') in normalized and str(p / 'python/lib/libcrypto.3.dylib') in normalized
print(json.dumps({'builtinModules': sorted(sys.builtin_module_names), 'loadedImages': images, 'prefix': sys.prefix,
                  'imports': 'passed', 'ctypesCallback': 'passed'}, sort_keys=True))
'''


def smoke(job: Job, tools: dict, payload: Path):
    original = inventory(payload, job.clock.check)
    script = job.root / "smoke.py"
    write_file(script, SMOKE.encode("ascii"))
    poison = job.root / "poison"
    for name in ("sitecustomize.py", "usercustomize.py", "json.py"):
        write_file(poison / name, b"raise RuntimeError('unqualified search path consumed')\n")
    write_file(poison / "pyvenv.cfg", b"home = /not-an-admitted-python\n")
    write_file(poison / "unexpected.pth", b"import sitecustomize\n")
    keys = {"PYTHONPATH": str(poison), "PYTHONHOME": str(poison), "PYTHONUSERBASE": str(poison), "VIRTUAL_ENV": str(poison),
            "DYLD_LIBRARY_PATH": str(poison), "DYLD_INSERT_LIBRARIES": str(poison / "not-a-library")}
    previous = {key: os.environ.get(key) for key in keys}
    try:
        os.environ.update(keys)
        output = job.run("payload-imports", [str(payload / "python/bin/python3"), "-I", "-S", "-B", str(script), str(payload)], poison, cap=30)
        result = json.loads(output, object_pairs_hook=pairs)
        require(type(result) is dict and result.get("builtinModules") == job.expected_builtins
                and result.get("imports") == "passed" and result.get("ctypesCallback") == "passed", "native-builtin-correspondence")
        for method in ("capabilities", "catalog"):
            request = job.root / (method + ".request")
            write_file(request, canonical({"protocol": 1, "id": "payload-" + method, "method": method, "params": {}}))
            output = job.run("payload-" + method, [tools["sh"], "-c", REQUEST_SHIM, "mrk-payload-request",
                str(payload / "python/bin/python3"), str(payload / "engine_bootstrap.py"), str(payload / "core.zip"), str(request)], poison, cap=15)
            # Use the actual protocol's strict parser/shape rules; no CLI scraping.
            from mobile_release._desktop_engine import _pairs, _constant, _check_depth, _check_values
            require(output[:1] == b"{" and output[-2:] == b"}\n" and output.count(b"\n") == 1
                    and len(output) <= 4 * 1024 * 1024, "passive-frame-bound")
            text = output.decode("utf-8")
            _check_depth(text)
            response = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
            _check_values(response)
            require(type(response) is dict and set(response) == {"protocol", "id", "ok", "result"}
                    and type(response["protocol"]) is int and response["protocol"] == 1
                    and response["id"] == "payload-" + method and response["ok"] is True
                    and type(response["result"]) is dict, "passive-result")
            value = response["result"]
            if method == "capabilities":
                require(value.get("hostPlatform") == "macos" and value.get("apiVersion") == 1
                        and value.get("mode") == "read-only-foundation", "packaged-capabilities")
            else:
                require(value.get("schemaVersion") == 1 and type(value.get("schema")) is dict
                        and value["schema"].get("$id") == "urn:mobile-release-kit:schema:project:1"
                        and type(value.get("fields")) is list and bool(value["fields"])
                        and all(type(value.get(k)) is dict for k in ("credentialGuide", "githubSetup", "githubConnection", "metadataText")),
                        "packaged-catalog-resources")
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    require(not os.path.lexists(PREFIX) and inventory(payload, job.clock.check) == original, "payload-postcondition")
    job.save("payload-inventory.json", original)


def admission() -> tuple[Path, Path, dict]:
    source = Path(__file__).resolve().parents[2]
    env = os.environ
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and os.geteuid() != 0
            and sys.version_info[:3] == (3, 14, 7) and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode, "native-platform")
    sha, run, attempt = env.get("GITHUB_SHA", ""), env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    ref = "refs/heads/verify/desktop-macos-payload"
    require(env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("RUNNER_OS") == "macOS"
            and env.get("RUNNER_ARCH") == "ARM64" and env.get("ImageOS") in {"macos26", "macos26-arm64"}
            and env.get("GITHUB_REF") == ref and re.fullmatch("[a-f0-9]{40}", sha)
            and re.fullmatch("[1-9][0-9]{0,19}", run) and re.fullmatch("[1-9][0-9]{0,19}", attempt)
            and env.get("GITHUB_WORKFLOW_SHA") == sha
            and env.get("GITHUB_WORKFLOW_REF") == env.get("GITHUB_REPOSITORY", "") + "/.github/workflows/desktop-macos-payload.yml@" + ref
            and Path(env.get("GITHUB_WORKSPACE", "")).resolve() == source, "workflow-source")
    require((env.get("GITHUB_EVENT_NAME") == "push" and env.get("MRK_EVENT_AFTER") == sha)
            or (env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and env.get("MRK_EXPECTED_SHA") == sha), "event-source")
    temporary = Path(env.get("RUNNER_TEMP", ""))
    require(temporary.is_absolute() and temporary.resolve() == temporary and temporary.is_dir()
            and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(temporary)), "task-parent")
    root = temporary / ("mrk-macos-payload-" + run + "-" + attempt)
    require(not os.path.lexists(root) and shutil.disk_usage(temporary).free >= 8 * 1024**3, "task-absence-or-capacity")
    return source, root, {"sourceSha": sha, "runId": run, "attempt": attempt, "target": TARGET, "scope": "macos-payload-smoke-v1"}


def original_settled(job: Job) -> bool:
    verdict = job.guard.lifetime_ledger.verdict()
    return (verdict.complete and not verdict.fatal and verdict.profile_calls == 0
            and verdict.command_contained is True and job.guard.handler_state == "RESTORED"
            and job.clock.phase == "closed" and verdict.commands == len(job.records)
            and all(row.get("originalFinality") is True for row in job.records))


def final_poll(job: Job) -> None:
    require(time.monotonic() < job.hard, "final-deadline")


def remove_disposable(job: Job) -> None:
    require(original_settled(job) and shutil.rmtree.avoids_symlink_attacks, "cleanup-settlement")
    root = job.root
    value = root.lstat()
    require(stat.S_ISDIR(value.st_mode) and (value.st_dev, value.st_ino) == job.root_identity
            and value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700, "cleanup-task-identity")
    for name in DISPOSABLE_DIRS:
        final_poll(job)
        path = root / name
        value = path.lstat()
        require(stat.S_ISDIR(value.st_mode) and (value.st_dev, value.st_ino) == job.disposable_identities[name]
                and value.st_uid == os.geteuid(), "cleanup-root-identity")
        # Python's descriptor-based rmtree does not follow native build aliases
        # into external directories. Only these original task-created roots.
        shutil.rmtree(path)
        final_poll(job)
        require(not os.path.lexists(path), "cleanup-absence")
    for name in ("smoke.py", "capabilities.request", "catalog.request"):
        final_poll(job)
        value = (root / name).lstat()
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.geteuid(), "cleanup-file")
        (root / name).unlink()
    require(set(os.listdir(root)) == {"payload", "evidence"}, "retained-roster")


def archive_payload(job: Job) -> dict:
    # upload-artifact does not preserve executable modes in loose files. One
    # ordinary tar keeps the already-tested payload's modes, not new binaries.
    payload = job.root / "payload"
    rows = inventory(payload, lambda: final_poll(job))
    require(sum(row["size"] + 4096 for row in rows) + 10240 <= FILE_LIMIT, "artifact-archive-bound")
    destination = job.root / "payload.tar"
    with destination.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for row in rows:
                final_poll(job)
                info = tarfile.TarInfo("payload/" + row["path"])
                info.size, info.mode, info.mtime = row["size"], row["mode"], 0
                with (payload / row["path"]).open("rb") as original:
                    before = state(os.fstat(original.fileno()))
                    archive.addfile(info, original)
                    require(state(os.fstat(original.fileno())) == before, "archive-input-changed")
    require(inventory(payload, lambda: final_poll(job)) == rows, "archive-payload-changed")
    return file_digest(destination, lambda: final_poll(job))


def main() -> int:
    started = time.monotonic()
    require(len(sys.argv) == 1, "fixed-entry-only")
    source, root, context = admission()
    inputs = load_inputs(source)
    root.mkdir(mode=0o700)
    for name in (*DISPOSABLE_DIRS, "evidence"):
        (root / name).mkdir(mode=0o700)
    # This GitHub-created task output file is only routing DATA, never admission.
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        stream.write("root=" + str(root) + "\n")
    job = Job(source, root, context, started)
    error = None
    try:
        try:
            with job.scope:
                job.guard.install()
                job.guard.activate()
                job.clock.install()
                job.save("inputs.json", inputs)
                tools = prepare_tools(job)
                acquire_sources(job, inputs, tools)
                generated = build(job, tools)
                payload = project(job, tools, generated)
                package(job, inputs, payload)
                smoke(job, tools, payload)
                job.save("copy-correspondence.json", job.projections)
        finally:
            job.scope.__exit__(*sys.exc_info())
    except BaseException as caught:
        error = caught
    settled = original_settled(job)
    passed = error is None and not job.failed and settled and not job.clock.expired and time.monotonic() < job.hard
    report = {**context, "phase": job.phase, "status": "native-smoke-complete-cleanup-pending" if passed else "failed",
        "originalCommandsSettled": settled, "commands": job.records,
        "errorCode": error.args[0] if type(error) is Refused else "original-operation-failed" if error else None,
        "distributionAccepted": False, "vendorObligationsReview": "required", "installedRuntimeQualified": False,
        "workDeadlineExpired": job.clock.expired, "cleanupEstablished": False, "partialOutputsMayRemain": True}
    # No post-failure native work or output-tree deletion. A failed/unknown
    # owner remains failed; the dedicated VM is its final infrastructure boundary.
    if time.monotonic() < job.hard:
        job.retain("work-result.json", canonical(report))
    if not passed:
        print("macOS payload work failed; original evidence/outputs retained; no qualification.", file=sys.stderr)
        return 1
    # All original producers and local handlers returned before disposable
    # compiler/source/dependency cleanup. Retain actual payload + original native
    # binaries/configuration/receipts for independent review and artifact upload.
    remove_disposable(job)
    archive = archive_payload(job)
    final_poll(job)
    retained = inventory(root, lambda: final_poll(job))
    require(sum(row["size"] for row in retained if row["path"].startswith("evidence/")) == job.evidence_bytes,
            "evidence-accounting")
    # These two final records explicitly exclude themselves, avoiding a circular
    # inventory. The workflow requires original step success AND this result;
    # neither a provisional work-result nor an uploaded partial tree is a pass.
    accounting = job.retain("retained-output-inventory.json", canonical({"files": retained,
        "excludedFinalRecords": ["evidence/retained-output-inventory.json", "evidence/result.json"]}))
    final_poll(job)
    job.retain("result.json", canonical({**report, "status": "native-smoke-passed", "cleanupEstablished": True,
        "partialOutputsMayRemain": False, "nativeSettlementPrecededCleanup": True,
        "retained": ["payload", "payload.tar", "evidence"], "payloadArchive": archive, "retainedInventory": accounting}))
    final_poll(job)
    print("macOS packaged passive smoke passed; retained payload requires independent result and distribution review.")
    return 0 if time.monotonic() < job.hard else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, UnicodeError):
        print("macOS payload preparation/cleanup refused; preserve task outputs and original failure.", file=sys.stderr)
        raise SystemExit(1)
