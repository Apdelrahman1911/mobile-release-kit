"""Bounded DATA operations for the two closed conventional hosted routes.

No admission, download, command, candidate, manifest generation or cleanup lives
here. Expected records come only from the controller's reviewed source literals
or an already authenticated original inventory. This is not runtime custody.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile

PROFILE = "cpython-3.14.7-linux-x86_64-source-v1"
TARGET = "x86_64-unknown-linux-gnu"
PREPARE_SCOPE = "conventional-runtime-data-preparation-v1"
SMOKE_SCOPE = "conventional-runtime-bootstrap-smoke-v1"
PROBE_SCOPE = "conventional-interpreter-behavior-smoke-v1"
NOT_VERIFIED = ["installed-runtime-custody", "immutable-publication", "tls-handshake",
                "dns-or-github-authentication", "native-close-faults", "gui", "production-enablement"]
MAX_ARCHIVE = 4 << 30
MAX_FILES = 32768
CHUNK = 64 << 10


class Refused(ValueError):
    pass


def need(ok: bool, message: str) -> None:
    if not ok:
        raise Refused(message)


def sha(value: object) -> str:
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "Missing literal byte pin")
    return value


def relative(value: object) -> str:
    need(type(value) is str and 0 < len(value) <= 512
         and re.fullmatch(r"[A-Za-z0-9_./+@=,\-]+", value) is not None
         and all(part not in {"", ".", ".."} for part in value.split("/"))
         and len(value.split("/")) <= 32, "Unsafe DATA member")
    return value


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii") + b"\n"


def decode(raw: bytes, limit: int = 32 << 20) -> object:
    need(type(raw) is bytes and 0 < len(raw) <= limit, "DATA JSON byte bound")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "Duplicate DATA field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite DATA")))
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(depth <= 32 and count <= 1_000_000, "DATA JSON structure bound")
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        else:
            need(type(item) in {str, int, bool, type(None)}, "Unexpected DATA scalar")
    return value


def same(left: object, right: object) -> bool:
    # bool/float must not substitute for integer wait/size/schema fields.
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(same(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def state(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def directory(path: Path) -> None:
    need(path.is_absolute() and ".." not in path.parts, "Absolute DATA root required")
    for parent in (path, *path.parents):
        need(stat.S_ISDIR(parent.lstat().st_mode), "Nonordinary DATA directory")


def _open(path: Path, limit: int):
    directory(path.parent)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "Nonordinary or oversized DATA file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    try:
        need(state(os.fstat(stream.fileno())) == state(before), "DATA changed before read")
    except BaseException:
        stream.close()
        raise
    return stream, before


def file_record(path: Path, limit: int = MAX_ARCHIVE) -> dict:
    stream, before = _open(path, limit)
    hashed, size = hashlib.sha256(), 0
    with stream:
        while block := stream.read(CHUNK):
            size += len(block)
            need(size <= before.st_size, "DATA grew during read")
            hashed.update(block)
        need(size == before.st_size and state(os.fstat(stream.fileno())) == state(before), "DATA read changed")
    need(state(path.lstat()) == state(before), "DATA changed after close")
    return {"path": path.name, "size": size, "sha256": hashed.hexdigest()}


def read(path: Path, limit: int = 32 << 20) -> bytes:
    stream, before = _open(path, limit)
    with stream:
        raw = stream.read(before.st_size + 1)
        need(len(raw) == before.st_size and state(os.fstat(stream.fileno())) == state(before), "DATA read changed")
    need(state(path.lstat()) == state(before), "DATA changed after close")
    return raw


def records(values: object, *, absolute: bool = False) -> dict[str, dict]:
    need(type(values) is list and 0 < len(values) <= MAX_FILES, "Missing admitted DATA roster")
    result, folded, total = {}, set(), 0
    for row in values:
        need(type(row) is dict and set(row) == {"path", "size", "sha256"}, "Different DATA record")
        name = row["path"]
        if absolute:
            need(type(name) is str and name.startswith("/"), "Absolute support record required")
            relative(name[1:])
        else:
            relative(name)
        need(type(row["size"]) is int and 0 <= row["size"] <= MAX_ARCHIVE, "DATA size bound")
        sha(row["sha256"])
        need(name.lower() not in folded, "Duplicate DATA path")
        folded.add(name.lower())
        total += row["size"]
        need(total <= MAX_ARCHIVE, "DATA aggregate bound")
        result[name] = row
    need(list(result) == sorted(result), "DATA roster order differs")
    return result


def bound(path: Path, expected: dict) -> None:
    need(file_record(path, expected["size"]) == {**expected, "path": path.name}, "Admitted DATA bytes differ")


def write(path: Path, raw: bytes, mode: int = 0o600) -> dict:
    directory(path.parent)
    with path.open("xb") as output:
        os.fchmod(output.fileno(), mode)
        need(output.write(raw) == len(raw), "Short DATA write")
        output.flush()
        os.fsync(output.fileno())
    need(read(path, len(raw)) == raw, "Closed DATA write readback differs")
    return file_record(path, len(raw))


def copy(source: Path, target: Path, expected: dict, mode: int = 0o600) -> None:
    bound(source, expected)
    directory(target.parent)
    original, before = _open(source, expected["size"])
    count = 0
    with original, target.open("xb") as output:
        os.fchmod(output.fileno(), mode)
        while block := original.read(CHUNK):
            count += len(block)
            need(count <= expected["size"] and output.write(block) == len(block), "DATA copy short or grew")
        need(count == expected["size"] and state(os.fstat(original.fileno())) == state(before), "DATA copy changed")
        output.flush()
        os.fsync(output.fileno())
    need(state(source.lstat()) == state(before), "DATA copy source changed")
    bound(target, expected)
    need(stat.S_IMODE(target.lstat().st_mode) == mode, "DATA copy mode differs")


def unpack(archive_path: Path, expected: dict, target: Path, *, retained: list[dict] | None = None) -> None:
    """Authenticated ordinary tar only; no extractall, links, aliases or overwrite.

    H uses its existing retained-files rows. The prepared archive is independently
    pinned by B and has only runtime members; its existing manifest is checked by
    the unchanged probe/runtime inspectors, not regenerated by this function.
    """
    bound(archive_path, expected)
    planned = None
    if retained is not None:
        need(type(retained) is list and 0 < len(retained) <= MAX_FILES, "Original H inventory bound")
        planned = {}
        for row in retained:
            need(type(row) is dict and set(row) == {"path", "originalPath", "size", "sha256", "originalMode"},
                 "Original H retention record differs")
            name = relative(row["path"])
            need(name not in planned and type(row["originalMode"]) is int
                 and 0 <= row["originalMode"] <= 0o777, "Original H mode or roster differs")
            planned[name] = row
        records([{key: row[key] for key in ("path", "size", "sha256")} for row in retained])
    directory(target.parent)
    target.mkdir(mode=0o700)
    seen, total = set(), 0
    original, before = _open(archive_path, MAX_ARCHIVE)
    with original, tarfile.open(fileobj=original, mode="r|") as archive:
        for member in archive:
            name = relative(member.name)
            need(member.isreg() and not member.issparse() and member.linkname == ""
                 and not member.mode & ~0o777 and name.lower() not in seen
                 and 0 <= member.size <= 512 << 20, "Nonordinary tar member")
            total += member.size
            seen.add(name.lower())
            need(len(seen) <= (MAX_FILES if planned is not None else 2049) and total <= MAX_ARCHIVE,
                 "Tar member/byte bound")
            row = planned.get(name) if planned is not None else None
            need(planned is None and name.startswith("runtime/") or row is not None
                 and (member.size, member.mode) == (row["size"], row["originalMode"]), "Tar original member differs")
            destination = target / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory(destination.parent)
            hashed, count = hashlib.sha256(), 0
            with archive.extractfile(member) as body, destination.open("xb") as output:
                os.fchmod(output.fileno(), member.mode)
                while block := body.read(CHUNK):
                    count += len(block)
                    need(count <= member.size and output.write(block) == len(block), "Tar member copy failed")
                    hashed.update(block)
                need(count == member.size and (row is None or hashed.hexdigest() == row["sha256"]),
                     "Tar original body differs")
                output.flush()
                os.fsync(output.fileno())
            bound(destination, {"path": name, "size": count, "sha256": hashed.hexdigest()})
            need(stat.S_IMODE(destination.lstat().st_mode) == member.mode, "Tar mode readback differs")
        need(state(os.fstat(original.fileno())) == state(before), "Original tar changed")
    need(state(archive_path.lstat()) == state(before)
         and (planned is None or seen == {name.lower() for name in planned}), "Tar incomplete or changed")
    bound(archive_path, expected)


def pack_runtime(runtime: Path, files: list[dict], destination: Path) -> dict:
    """Preserve modes and read every original member back after archive close."""
    planned = records(files)
    need(len(planned) <= 2049 and "manifest.json" in planned
         and sum(row["size"] for row in planned.values()) <= (1 << 30) + (1 << 20), "Prepared archive inventory differs")
    modes = {}
    for name, row in planned.items():
        bound(runtime / name, row)
        modes[name] = stat.S_IMODE((runtime / name).lstat().st_mode)
        need(modes[name] & ~0o777 == 0, "Prepared mode differs")
    need(modes.get("python/bin/python3", 0) & 0o111 != 0, "Prepared interpreter is not executable")
    with destination.open("xb") as output:
        with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for name, row in planned.items():
                original, before = _open(runtime / name, row["size"])
                with original:
                    header = tarfile.TarInfo("runtime/" + name)
                    header.size, header.mode, header.mtime = row["size"], modes[name], 0
                    archive.addfile(header, original)
                    need(state(os.fstat(original.fileno())) == state(before)
                         and state((runtime / name).lstat()) == state(before), "Prepared archive input changed")
        output.flush()
        os.fsync(output.fileno())
    result = file_record(destination, MAX_ARCHIVE)
    with tarfile.open(destination, mode="r|") as archive:
        rows = iter(planned.items())
        for member in archive:
            expected = next(rows, None)
            need(expected is not None, "Prepared archive extra member")
            name, row = expected
            need(member.name == "runtime/" + name and member.isreg() and not member.issparse()
                 and member.size == row["size"] and member.mode == modes[name], "Prepared archive readback differs")
            hashed, size = hashlib.sha256(), 0
            with archive.extractfile(member) as body:
                while block := body.read(CHUNK):
                    size += len(block)
                    need(size <= row["size"], "Prepared archive readback grew")
                    hashed.update(block)
            need((size, hashed.hexdigest()) == (row["size"], row["sha256"]), "Prepared archive body readback differs")
        need(next(rows, None) is None, "Prepared archive lost member")
    bound(destination, result)
    return result


def outer(value: object, scope: str, producer: dict) -> None:
    need(same(value, {"schemaVersion": 1, "scope": scope, **producer, "originalWait": True,
        "exitCode": 0, "outputWritersClosed": True, "statusWriterCloseGate": "original-step-success-required"}),
        "Original shell wait/close DATA differs")
    # The admitted artifact must additionally come from the actually successful
    # original Actions step. This serialized caveat cannot prove its own close.


def probe_receipt(value: object, prepared: dict, builtin_names: list[str]) -> dict:
    need(type(value) is dict and set(value) == {"schemaVersion", "profile", "scope", "status", "bindings",
         "observed", "notVerified", "outerOriginalWaitRequired"}, "Probe receipt fields differ")
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["profile"] == PROFILE and value["scope"] == PROBE_SCOPE and value["status"] == "passed"
         and same(value["bindings"], prepared) and value["notVerified"] == NOT_VERIFIED
         and value["outerOriginalWaitRequired"] is True, "Probe receipt binding differs")
    observed = value["observed"]
    need(type(observed) is dict and set(observed) == {"pythonVersion", "builtinNames", "expatVersion", "xmlValid",
        "xmlMalformedRefused", "nofile", "opensslVersion", "ignoreUnexpectedEof", "caCertificates",
        "privateMappedLibraries", "coreImportsFromPreparedZip"}, "Probe observations differ")
    need(same(observed["pythonVersion"], [3, 14, 7]) and observed["builtinNames"] == builtin_names
         and observed["expatVersion"] == "expat_2.8.2" and observed["xmlValid"] is True
         and observed["xmlMalformedRefused"] is True and observed["coreImportsFromPreparedZip"] is True
         and observed["privateMappedLibraries"] == ["libcrypto.so.3", "libssl.so.3"]
         and type(observed["opensslVersion"]) is str and observed["opensslVersion"].startswith("OpenSSL 3.5.8 ")
         and 0 < len(observed["opensslVersion"]) <= 128
         and all(" " <= char <= "~" for char in observed["opensslVersion"])
         and type(observed["ignoreUnexpectedEof"]) is int and 0 < observed["ignoreUnexpectedEof"] < 2**64
         and type(observed["caCertificates"]) is int and observed["caCertificates"] > 0
         and type(observed["nofile"]) is list and len(observed["nofile"]) == 2
         and all(type(item) is int for item in observed["nofile"])
         and (observed["nofile"][0] == -1 or observed["nofile"][0] > 0)
         and (observed["nofile"][1] == -1 or 0 < observed["nofile"][0] <= observed["nofile"][1]),
         "Probe observation failed")
    return value


def smoke_receipt(value: object, prepared: dict, source: dict) -> dict:
    need(type(value) is dict and set(value) == {"schemaVersion", "profile", "scope", "status", "allOwnersSettled",
         "failureCode", "bindings", "cases", "notVerified", "outerOriginalWaitRequired"}, "Smoke receipt fields differ")
    bindings = {"source": source, "prepared": {"profile": PROFILE, **prepared,
        "coreSelection": "prepared-zip-only", "checkoutBootstrapEqualsPrepared": True}}
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["profile"] == PROFILE
         and value["scope"] == SMOKE_SCOPE and value["status"] == "passed" and value["allOwnersSettled"] is True
         and value["failureCode"] is None and same(value["bindings"], bindings)
         and value["notVerified"] == NOT_VERIFIED and value["outerOriginalWaitRequired"] is True,
         "Smoke receipt binding/finality differs")
    cases = value["cases"]
    need(type(cases) is list and len(cases) == 2, "Smoke requires exactly two original cases")
    native_flags = {"inspection_joined", "acquisition_joined", "spawned", "waited", "exit_success",
        "writer_joined", "writer_complete", "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined",
        "driver_joined", "watchdog_joined"}
    for row, name in zip(cases, ("core-capabilities", "core-zip-catalog")):
        need(type(row) is dict and set(row) == {"case", "passed", "failureCode", "elapsedMs", "evidenceKind",
             "results", "notes", "owners", "registeredOwners", "disabled"}, "Smoke case fields differ")
        need(row["case"] == name and row["passed"] is True and row["failureCode"] is None
             and type(row["elapsedMs"]) is int and 0 <= row["elapsedMs"] <= 180000
             and row["evidenceKind"] == "actual-passive-child" and same(row["results"], [{"return": "ok"}])
             and row["notes"] == {} and type(row["registeredOwners"]) is int and row["registeredOwners"] == 0
             and row["disabled"] is False and type(row["owners"]) is list and len(row["owners"]) == 1,
             "Smoke case is incomplete or unknown")
        owner = row["owners"][0]
        need(type(owner) is dict and set(owner) == {"id", "terminal", "unknownLatched", "permitRetained", "native"}
             and owner["id"] == "query-1" and owner["terminal"] is True
             and owner["unknownLatched"] is False and owner["permitRetained"] is False, "Smoke owner not settled")
        observed = owner["native"]
        need(type(observed) is dict and set(observed) == native_flags | {"stdout_bytes", "stderr_bytes"}
             and all(observed[field] is True for field in native_flags)
             and type(observed["stdout_bytes"]) is int and 0 < observed["stdout_bytes"] <= 4 << 20
             and type(observed["stderr_bytes"]) is int and 0 <= observed["stderr_bytes"] <= 64 << 10,
             "Smoke original waits/joins/EOF/writer facts incomplete")
    return value
