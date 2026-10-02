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
    flags = {key: body.get(key) for key in ("isNonFatal", "isSimulated")}
    if any(key in body and type(value) is not bool for key, value in flags.items()):
        raise ValueError("nonfatal or simulated report flag shape")
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
        # Missing flags are unknown, not proof of an ordinary fatal crash.
        **flags,
        "processOwnershipEstablished": False, "rawReportRetained": False,
    }


def late_build_inputs(raw, expected_directory, source, tree, run_attempt):
    """Validate retained DATA; never replace the original build end with now."""
    for name, value in (("source-commit.txt", source), ("source-tree.txt", tree)):
        if (type(value) is not str or len(value) != 40
                or any(c not in "0123456789abcdef" for c in value)
                or raw[name] != (value + "\n").encode("ascii")):
            raise ValueError("original source binding")
    parts = run_attempt.split("/")
    if (len(run_attempt) > 64 or len(parts) != 2
            or any(not p.isascii() or not p.isdecimal() or int(p) <= 0 for p in parts)
            or raw["run-attempt.txt"] != (run_attempt + "\n").encode("ascii")):
        raise ValueError("original run binding")
    before = json.loads(raw["build-infrastructure-before.json"], object_pairs_hook=pairs, parse_constant=constant)
    after = json.loads(raw["build-infrastructure-after.json"], object_pairs_hook=pairs, parse_constant=constant)
    for record in (before, after):
        if (type(record) is not dict or record.get("scope") != SCOPE
                or type(record.get("schemaVersion")) is not int or record["schemaVersion"] != 1
                or record.get("productQualified") is not False
                or record.get("serviceLimitsObserved") is not False):
            raise ValueError("original diagnostic contract")
    begin, end, status = before.get("beginEpochSeconds"), after.get("endEpochSeconds"), after.get("originalBuildExit")
    if (before.get("originalDirectory") != expected_directory
            or any(type(t) not in (float, int) or not math.isfinite(t) or t < 0 for t in (begin, end))
            or type(after.get("beginEpochSeconds")) not in (float, int)
            or after["beginEpochSeconds"] != begin or not 0 <= end - begin <= 300
            or after.get("processOwnershipOrFinalityEstablished") is not False
            or type(status) is not int or not 1 <= status <= 255
            or raw["build.status"] != (str(status) + "\n").encode("ascii")):
        raise ValueError("original failed build interval or status")
    return {"schemaVersion": 1, "scope": SCOPE, "originalBuildExit": status,
            "beginEpochSeconds": begin, "endEpochSeconds": end,
            "sourceCommit": source, "sourceTree": tree, "runAttempt": run_attempt,
            "serviceLimitsObserved": False, "productQualified": False,
            "processOwnershipOrFinalityEstablished": False}


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
            or len(sys.argv) < 3 or sys.argv[1] not in ("before", "after", "late")
            or len(sys.argv) != {"before": 3, "after": 4, "late": 6}[sys.argv[1]]):
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
            elif phase == "after":
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
            else:
                # These originals remain inputs only. A delayed report is not a
                # new build, a changed build result, or process-finality evidence.
                raw, originals = {}, {}
                for name, limit in (("source-commit.txt", 41), ("source-tree.txt", 41),
                                    ("run-attempt.txt", 64), ("build.status", 4),
                                    ("build-infrastructure-before.json", 65536),
                                    ("build-infrastructure-after.json", 65536)):
                    originals[name] = identity(os.stat(name, dir_fd=evidence, follow_symlinks=False))
                    raw[name] = read_at(evidence, name, limit, (os.getuid(),))
                    if originals[name] != identity(os.stat(name, dir_fd=evidence, follow_symlinks=False)):
                        raise ValueError("original delayed-observation input changed")
                result = late_build_inputs(raw, expected, *sys.argv[3:])

                def recheck_originals():
                    if (identity(original) != identity(os.fstat(root_fd))
                            or identity(original) != identity(os.stat(root, follow_symlinks=False))
                            or identity(evidence_stat) != identity(os.fstat(evidence))
                            or identity(evidence_stat) != identity(os.stat("evidence", dir_fd=root_fd, follow_symlinks=False))
                            or any(value != identity(os.stat(name, dir_fd=evidence, follow_symlinks=False))
                                   for name, value in originals.items())):
                        raise ValueError("original delayed-observation custody changed")

                # One finite publication opportunity, not an OS completion promise.
                time.sleep(20)
                recheck_originals()
                start, deadline = time.time(), time.monotonic() + 10
                if not math.isfinite(start) or start < result["endEpochSeconds"]:
                    raise ValueError("delayed observation clock")
                contents = str(Path(os.environ["DEVELOPER_DIR"]).resolve().parent)
                crashes = crash_snapshot(result["beginEpochSeconds"], result["endEpochSeconds"], contents, deadline)
                end = time.time()
                if not math.isfinite(end) or end < start:
                    raise ValueError("delayed observation clock")
                recheck_originals()
                crashes["complete"] = crashes["complete"] and time.monotonic() < deadline
                result.update(delaySeconds=20, observationStartEpochSeconds=start,
                              observationEndEpochSeconds=end, crashes=crashes)
                emit(evidence, "build-infrastructure-late.json", result)
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
