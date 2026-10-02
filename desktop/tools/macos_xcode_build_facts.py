#!/usr/bin/env python3
"""Small, read-only Xcode infrastructure diagnostic; never product evidence.

The measured limits belong to this shell's child, not necessarily an XPC service.
Crash time/toolchain matches are correlations, not process ownership or finality.
Only the fixed disposable hosted workflow calls main. Tests call the pure parser.
"""
import datetime
import heapq
import json
import math
import os
from pathlib import Path, PurePosixPath
import resource
import stat
import sys
import time

PROCESSES = frozenset(("XCBBuildService", "SWBBuildService", "SwiftBuildService"))
SIGNALS = frozenset(("SIGABRT", "SIGSEGV", "SIGBUS", "SIGILL", "SIGTRAP", "SIGFPE",
                     "SIGKILL", "SIGXCPU", "SIGXFSZ", "SIGTERM"))
EXCEPTIONS = frozenset(("EXC_CRASH", "EXC_BAD_ACCESS", "EXC_BAD_INSTRUCTION",
                        "EXC_BREAKPOINT", "EXC_RESOURCE", "EXC_GUARD"))
NAMESPACES = frozenset(("SIGNAL", "CODESIGNING", "DYLD", "RESOURCE", "GUARD"))
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_REPORTS = 8
MAX_ENTRIES = 8192
SCOPE = "same-XCTRunner-build-infrastructure-only"


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def constant(_):
    raise ValueError("nonfinite JSON value")


def timestamp(value):
    if type(value) is not str or not 1 <= len(value) <= 64:
        raise ValueError("timestamp shape")
    # Apple's IPS examples use a space before the UTC offset.
    parts = value.rsplit(" ", 1)
    if len(parts) == 2 and parts[1].startswith(("+", "-")):
        value = "".join(parts)
    result = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp timezone unavailable")
    result = result.timestamp()
    if not math.isfinite(result) or result < 0:
        raise ValueError("timestamp range")
    return result


def closed_crash_facts(raw, begin, end, contents):
    """Interpret the documented two-JSON-object IPS format without raw output."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_REPORT_BYTES:
        raise ValueError("report size")
    decoder = json.JSONDecoder(object_pairs_hook=pairs, parse_constant=constant)
    text = raw.decode("utf-8").lstrip()
    header, at = decoder.raw_decode(text)
    body, after = decoder.raw_decode(text[at:].lstrip())
    if text[at:].lstrip()[after:].strip() or type(header) is not dict or type(body) is not dict:
        raise ValueError("report framing")
    name = body.get("procName")
    if header.get("bug_type") != "309" or type(name) is not str or name not in PROCESSES or header.get("name") != name:
        raise ValueError("report kind")
    capture, launch = timestamp(body.get("captureTime")), timestamp(body.get("procLaunch"))
    exception, termination = body.get("exception", {}), body.get("termination", {})
    if type(exception) is not dict or type(termination) is not dict:
        raise ValueError("exception shape")
    def closed(value, values):
        return value if type(value) is str and value in values else "unavailable-or-other"
    code = termination.get("code")
    path = body.get("procPath")
    within = False
    if type(path) is str and len(path) <= 4096:
        parts, prefix = PurePosixPath(path).parts, PurePosixPath(contents).parts
        within = ".." not in parts and len(parts) > len(prefix) and parts[:len(prefix)] == prefix
    return {
        "process": name,
        "exception": closed(exception.get("type"), EXCEPTIONS),
        "signal": closed(exception.get("signal"), SIGNALS),
        "terminationNamespace": closed(termination.get("namespace"), NAMESPACES),
        "terminationCode": code if type(code) is int and 0 <= code < 2**63 else None,
        "captureEpochSeconds": capture, "launchEpochSeconds": launch,
        "captureInBuildInterval": begin <= capture <= end,
        "launchInBuildInterval": begin <= launch <= capture <= end,
        "sameToolchainContents": within,
        "processOwnershipEstablished": False, "rawReportRetained": False,
    }


def read_at(directory_fd, name, limit, owners):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in owners or before.st_nlink != 1
                or before.st_mode & 0o022 or not 0 <= before.st_size <= limit):
            raise ValueError("diagnostic input shape")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) != before.st_size or identity(before) != identity(os.fstat(fd)):
            raise ValueError("diagnostic input changed")
        if identity(before) != identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)):
            raise ValueError("diagnostic input replaced")
        return data
    finally:
        os.close(fd)


def derived_sizes(root_fd, file_limit, deadline):
    result = {"entries": 0, "files": 0, "bytes": 0, "atShellFileLimit": 0,
              "largestFiles": [], "complete": True}
    largest = []
    def visit(fd, prefix, depth):
        if depth > 24:
            raise ValueError("tree depth")
        with os.scandir(fd) as entries:
            for entry in entries:
                result["entries"] += 1
                if result["entries"] > MAX_ENTRIES or time.monotonic() >= deadline:
                    raise ValueError("tree bound")
                s = entry.stat(follow_symlinks=False)
                relative = prefix + entry.name
                if s.st_dev != os.fstat(fd).st_dev:
                    raise ValueError("different output volume")
                if stat.S_ISDIR(s.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        visit(child, relative + "/", depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(s.st_mode):
                    result["files"] += 1
                    result["bytes"] += s.st_size
                    result["atShellFileLimit"] += int(file_limit > 0 and s.st_size == file_limit)
                    # This is a fixed, credential-free external XCTest build.
                    label = relative if relative.isascii() and relative.isprintable() and len(relative) <= 256 else "name-unavailable"
                    heapq.heappush(largest, (s.st_size, label))
                    if len(largest) > 12:
                        heapq.heappop(largest)
    try:
        fd = os.open("DerivedData", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        try:
            visit(fd, "", 0)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        result["complete"] = False
    result["largestFiles"] = [{"bytes": size, "relativePath": name} for size, name in sorted(largest, reverse=True)]
    # Enumeration/last-entry handling can finish after the shared endpoint,
    # including an empty directory. Keep partial facts, never claim completeness.
    result["complete"] = result["complete"] and time.monotonic() < deadline
    return result


def crash_snapshot(begin, end, contents, deadline):
    result = {"facts": [], "directoryUnavailable": 0, "reportUnavailable": 0,
              "matchingFiles": 0, "complete": True}
    seen = 0
    for directory in ("/Users/runner/Library/Logs/DiagnosticReports", "/Library/Logs/DiagnosticReports"):
        try:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            result["directoryUnavailable"] += 1
            continue
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    seen += 1
                    if seen > 1024 or time.monotonic() >= deadline:
                        result["complete"] = False
                        break
                    if not entry.name.endswith(".ips") or not any(entry.name.startswith(p + "-") or entry.name.startswith(p + "_") for p in PROCESSES):
                        continue
                    try:
                        s = entry.stat(follow_symlinks=False)
                        if not stat.S_ISREG(s.st_mode) or not begin <= s.st_mtime <= time.time():
                            continue
                        result["matchingFiles"] += 1
                        if result["matchingFiles"] > MAX_REPORTS:
                            result["complete"] = False
                            break
                        data = read_at(fd, entry.name, MAX_REPORT_BYTES, (0, os.getuid()))
                        result["facts"].append(closed_crash_facts(data, begin, end, contents))
                    except (OSError, ValueError, OverflowError, RecursionError):
                        result["reportUnavailable"] += 1
        except OSError:
            result["directoryUnavailable"] += 1
        finally:
            os.close(fd)
    result["complete"] = result["complete"] and time.monotonic() < deadline
    return result


def emit(fd, name, value):
    body = (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode("ascii")
    if len(body) > 65536:
        raise ValueError("diagnostic output bound")
    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    with os.fdopen(output, "wb") as stream:
        stream.write(body)


def main():
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or len(sys.argv) not in (3, 4) or sys.argv[1] not in ("before", "after")):
        raise ValueError("diagnostic scope")
    phase, root = sys.argv[1], Path(sys.argv[2])
    if root.parent != Path("/Users/runner/work/_temp") or not root.name.startswith("mrk-macos-ui-host."):
        raise ValueError("private task root")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        original = os.fstat(root_fd)
        expected = f"{original.st_dev}:{original.st_ino}:{original.st_uid}"
        if original.st_uid != os.getuid() or stat.S_IMODE(original.st_mode) != 0o700:
            raise ValueError("private root ownership")
        if read_at(root_fd, "original-directory.txt", 128, (os.getuid(),)).decode().strip() != expected:
            raise ValueError("original directory mismatch")
        evidence = os.open("evidence", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        try:
            evidence_stat = os.fstat(evidence)
            if (evidence_stat.st_dev != original.st_dev or evidence_stat.st_uid != original.st_uid
                    or stat.S_IMODE(evidence_stat.st_mode) != 0o700):
                raise ValueError("private evidence directory")
            if phase == "before":
                limits = {name: list(resource.getrlimit(getattr(resource, name)))
                          for name in ("RLIMIT_FSIZE", "RLIMIT_AS", "RLIMIT_DATA", "RLIMIT_NOFILE")}
                disk = os.fstatvfs(root_fd)
                try:
                    pages, page_size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
                    memory = pages * page_size if pages > 0 and page_size > 0 else None
                except (OSError, ValueError):
                    memory = None  # This sysconf observation is not available on every Darwin release.
                emit(evidence, "build-infrastructure-before.json", {
                    "schemaVersion": 1, "scope": SCOPE, "originalDirectory": expected,
                    "beginEpochSeconds": time.time(), "shellChildLimits": limits,
                    "serviceLimitsObserved": False, "diskAvailableBytes": disk.f_bavail * disk.f_frsize,
                    "physicalMemoryBytes": memory,
                    "productQualified": False})
            else:
                status = int(sys.argv[3]) if len(sys.argv) == 4 else -1
                before = json.loads(read_at(evidence, "build-infrastructure-before.json", 65536, (os.getuid(),)), object_pairs_hook=pairs)
                if (not 0 <= status <= 255 or before.get("scope") != SCOPE
                        or before.get("schemaVersion") != 1 or before.get("originalDirectory") != expected):
                    raise ValueError("original build observation")
                end, deadline = time.time(), time.monotonic() + 10
                begin = before["beginEpochSeconds"]
                if type(begin) not in (float, int) or not math.isfinite(begin) or not 0 <= end - begin <= 300:
                    raise ValueError("original build interval")
                contents = str(Path(os.environ["DEVELOPER_DIR"]).resolve().parent)
                result = {"schemaVersion": 1, "scope": SCOPE, "originalBuildExit": status,
                          "beginEpochSeconds": begin, "endEpochSeconds": end,
                          "serviceLimitsObserved": False, "productQualified": False,
                          "processOwnershipOrFinalityEstablished": False,
                          "crashes": crash_snapshot(begin, end, contents, deadline),
                          "derivedData": derived_sizes(root_fd, before["shellChildLimits"]["RLIMIT_FSIZE"][0], deadline)}
                emit(evidence, "build-infrastructure-after.json", result)
        finally:
            os.close(evidence)
    finally:
        os.close(root_fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, OverflowError, RecursionError):
        print("Xcode infrastructure diagnostic unavailable; original build result is separate.", file=sys.stderr)
        raise SystemExit(1)
