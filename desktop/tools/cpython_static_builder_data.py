"""Conventional root projection from retained DATA, not package installation.

The base is R, which had no builder DATA helper. Only the bounded forward-tar,
member-path and alias rules of H's helper are reused here. No H module import,
private-W lease, container, package manager, maintainer script or native probe.
Read-only *mounting*, tool execution and hard containment are separate admission.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import posixpath
import stat
import sys
import tarfile

_SPEC = importlib.util.spec_from_file_location("_mrk_source_root_inputs", Path(__file__).with_name("cpython_static_inputs.py"))
I = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(I)

APPROVED_ROOT_REQUEST_SHA256: str | None = "a413726fb84740ab8ba2b6877c598d95bbe91ec6eb477fffa8aa6c5e1e40b4d7"
ROOT_SCHEMA = "mrk-cpython-source-rootfs-1"
MEMBERS_SHA256 = "a9ddc292f72b4ce8a45b944f445b26e7d9cc2de411325ff4d8ba8e99a68d13a9"
PUBLIC_SELECTION_SHA256 = "9166c3b1fe0d00d5ae6c093603d161f6eba1c71fa5f9129966428cb93b883ea4"
PUBLIC_SELECTION_BYTES = 150507
MEMBER_SELECTION_LINEAGE_SHA256 = "ccff4af92ac1d0d2e5a65c34e8508f40007f77c42c8e0c55a4a23a8e9b5714fd"
BASE_MANIFEST_SHA256 = "496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4"
BASE_CONFIG_SHA256 = "6232b38791000e3818b58d8847b5a8f5612d606929e01156dd8febc423e0f2ef"
BASE_LAYER_SHA256 = "edd1ed89f0d443580bd42e5a10cd8736aba5a3438b2a0645c2ebb50119bb0eba"
MAX_ENTRIES, MAX_MEMBER, MAX_RAW, MAX_BODY = 16384, 512 << 20, 2 << 30, 560 << 20
CHUNK = 1 << 20
ROOT_MOUNTPOINTS = ("dev", "proc", "work")
ROOT_CONFIG = {"etc/hosts": b"127.0.0.1 localhost\n::1 localhost\n",
    "etc/resolv.conf": b"# Network is unavailable in the admitted build.\n",
    "etc/nsswitch.conf": b"passwd: files\ngroup: files\nhosts: files\nnetworks: files\n"}


def relative(value: object) -> str:
    I.need(type(value) is str and 0 < len(value) <= 4096 and not value.startswith("/")
           and all(33 <= ord(c) <= 126 and c != "\\" for c in value)
           and all(p not in {"", ".", ".."} for p in value.split("/")), "Invalid conventional root member path")
    return value


def member_name(value: str) -> str:
    while value.startswith("./"):
        value = value[2:]
    return relative(value.rstrip("/"))


def resolve_path(path: str, entries: dict) -> str:
    """H's lexical, bounded alias rule. Never follow a host filesystem alias."""
    pending, result, steps = path.lstrip("/").split("/"), [], 0
    while pending:
        part = pending.pop(0)
        if part in {"", "."}:
            continue
        if part == "..":
            I.need(result, "Alias escapes conventional root")
            result.pop()
            continue
        result.append(part)
        item = entries.get("/".join(result))
        if item and item["type"] in {"symlink", "hardlink"}:
            steps += 1
            I.need(steps <= 32, "Alias cycle/depth ceiling")
            target = item["target"]
            if item["type"] == "hardlink" or target.startswith("/"):
                result = []
            else:
                result.pop()
            pending = target.lstrip("/").split("/") + pending
    return relative("/".join(result))


class ForwardReader:
    """H's bounded r: reader: consumed padding/trailers are hashed as DATA."""
    def __init__(self, stream, limit: int):
        self.stream, self.limit, self.count = stream, limit, 0
        self.hash, self.last = hashlib.sha256(), b""

    def tell(self):
        return self.count

    def seekable(self):
        return False

    def read(self, size: int):
        I.need(type(size) is int and 0 <= size <= CHUNK, "Unbounded archive read refused")
        raw = self.stream.read(min(size, self.limit - self.count + 1))
        self.count += len(raw)
        I.need(self.count <= self.limit, "Archive expanded-byte ceiling")
        self.hash.update(raw)
        self.last = (self.last + raw)[-512:]
        return raw

    def seek(self, offset: int, whence: int = 0):
        I.need(whence == 0 and self.count <= offset <= self.limit, "Nonforward tar seek refused")
        while self.count < offset:
            I.need(self.read(min(CHUNK, offset - self.count)), "Truncated tar padding")
        return self.count


def _fingerprint(record: dict) -> None:
    I.file_shape(record)
    path = I.absolute(record["path"])
    I.ordinary_directory(path.parent)
    before = path.lstat()
    I.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
           and before.st_size == record["size"] <= MAX_RAW, "Different retained decoded stream")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    total, hashed = 0, hashlib.sha256()
    try:
        I.need(I._state(os.fstat(descriptor)) == I._state(before), "Archive changed before reading")
        while block := os.read(descriptor, CHUNK):
            total += len(block)
            I.need(total <= before.st_size, "Archive grew during read")
            hashed.update(block)
        I.need(I._state(os.fstat(descriptor)) == I._state(before) == I._state(path.lstat()), "Archive changed during read")
    finally:
        os.close(descriptor)
    I.need((total, hashed.hexdigest()) == (record["size"], record["sha256"]), "Decoded archive pin differs")


def selection_data(value: object) -> tuple[list[dict], list[dict]]:
    """Existing 151/85/267 join only; do not resolve/reinstall 146 packages."""
    value = I.keys(value, {"addedPackages", "basePackages", "complete", "inputAndHostToolHashes", "lock",
                          "notPerformed", "packages", "requestedRoots", "scope", "sources"})
    I.need(value["addedPackages"] == 59 and value["basePackages"] == 92 and value["complete"] is True
           and value["scope"] == "offline-metadata-resolution-only" and value["lock"] == "UNSEALED"
           and len(value["packages"]) == 151 and len(value["sources"]) == 85, "Different package/source selection")
    sources = []
    for row in value["sources"]:
        I.keys(row, {"name", "version", "artifactsExpected"})
        artifacts = []
        for artifact in row["artifactsExpected"]:
            I.keys(artifact, {"bytes", "sha256", "url"})
            I.sha(artifact["sha256"])
            I.need(type(artifact["bytes"]) is int and 0 < artifact["bytes"] <= MAX_MEMBER
                   and artifact["url"].startswith("https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/"),
                   "Source artifact is outside the fixed snapshot")
            artifacts.append(artifact)
        I.need(artifacts, "Source package has no retained artifact references")
        sources.append({"id": row["name"] + "@" + row["version"], "artifacts": artifacts})
    ids = {row["id"] for row in sources}
    I.need(len(ids) == 85 and sum(len(r["artifacts"]) for r in sources) == 267, "Source artifact closure differs")
    packages = []
    for row in value["packages"]:
        I.keys(row, {"name", "version", "architecture", "relationships", "sourceId", "binaryExpected"})
        I.need(row["sourceId"] in ids and row["architecture"] in {"amd64", "all"}, "Package lacks versioned source")
        packages.append({"id": row["name"] + ":" + row["architecture"] + "=" + row["version"],
                         "sourceId": row["sourceId"], "binaryExpected": row["binaryExpected"]})
    I.need(len({r["id"] for r in packages}) == 151, "Duplicate selected package")
    return sorted(packages, key=lambda r: r["id"]), sorted(sources, key=lambda r: r["id"])


def omitted(name: str) -> str | None:
    if "__pycache__" in name.split("/") or name.endswith((".pyc", ".pyo")):
        return "no-python-cache-reads-or-writes-in-tool-root"
    if name in {"etc/ld.so.cache", "etc/ld.so.preload"}:
        return "no-loader-cache-or-preload"
    if name == "var/lib/dpkg" or name.startswith(("var/lib/dpkg/", "var/cache/apt/", "var/lib/apt/")):
        return "not-an-installed-package-database"
    if name in ROOT_CONFIG:
        return "fixed-root-configuration-replacement"
    return None


def root_plan(members: dict) -> tuple[list[dict], list[dict], list[dict]]:
    I.need(members.get("schema") == "mrk-private-tool-member-plan-1" and members.get("fileCount") == 8758
           and members.get("bodyBytes") == 580511397 and len(members["aliases"]) == 551
           and members["lineage"]["selectionSha256"] == MEMBER_SELECTION_LINEAGE_SHA256,
           "Different retained D4 member correspondence")
    files, omissions, aliases = [], [], []
    for row in members["files"]:
        I.keys(row, {"name", "size", "sha256", "mode", "source", "origins", "alias"})
        name = relative(row["name"])
        I.sha(row["sha256"])
        I.need(type(row["size"]) is int and 0 <= row["size"] <= MAX_MEMBER and row["mode"] in {0o444, 0o555}
               and row["origins"], "Member DATA/mode/origin differs")
        I.keys(row["source"], {"archiveId", "member"})
        relative(row["source"]["member"])
        reason = omitted(name)
        if reason:
            omissions.append({"name": name, "reason": reason, "sha256": row["sha256"]})
        else:
            files.append(row)
    I.need(len({r["name"] for r in files}) == len(files) and sum(r["size"] for r in files) <= MAX_BODY,
           "Conventional body count/byte ceiling")
    ordinary = {r["name"] for r in files}
    directories = {r["name"] for r in members["directories"]}
    for edge in members["aliases"]:
        I.keys(edge, {"name", "target", "targetKind", "origins", "projection"})
        name, target = relative(edge["name"]), relative(edge["target"])
        if edge["projection"] == "fresh-regular-copy":
            I.need(name in ordinary or omitted(name) is not None, "File alias lacks its independent body")
        elif edge["targetKind"] == "directory" and target in directories and omitted(target) is None:
            I.need(name not in ordinary and name not in directories, "Directory alias collides with a body/directory")
            aliases.append({"name": name, "target": target, "origins": edge["origins"]})
        else:
            omissions.append({"name": name, "reason": "unresolved-or-omitted-logical-alias", "target": target})
    entries = {r["name"]: {"type": "symlink", "target": "/" + r["target"]} for r in aliases}
    for row in aliases:
        I.need(resolve_path(row["name"], entries) == row["target"], "Conventional alias target changed")
    return files, aliases, sorted(omissions, key=lambda r: r["name"])


def root_directories(files: list[dict], aliases: list[dict]) -> set[str]:
    paths = [*(r["name"] for r in files), *(r["name"] for r in aliases)]
    I.need(not any(name == point or name.startswith(point + "/") for name in paths for point in ROOT_MOUNTPOINTS),
           "Fixed empty root mountpoint scaffold is occupied")
    directories = {"etc", *ROOT_MOUNTPOINTS}
    for name in [*paths, *(r["target"] + "/_" for r in aliases)]:
        pieces = relative(name).split("/")
        directories.update("/".join(pieces[:index]) for index in range(1, len(pieces)))
    I.need(not any(name.startswith(point + "/") for name in directories for point in ROOT_MOUNTPOINTS),
           "Fixed empty root mountpoint scaffold has a descendant directory")
    return directories


def _selected_body(member, size: int) -> bytes:
    """Finite bounded reads; BufferedReader must not forward a giant raw read."""
    I.need(type(size) is int and 0 <= size <= MAX_MEMBER, "Selected body size ceiling")
    blocks = []
    for offset in range(0, size, CHUNK):
        wanted = min(CHUNK, size - offset)
        block = member.read(wanted)
        I.need(type(block) is bytes and len(block) == wanted, "Short/oversized selected tar body")
        blocks.append(block)
    I.need(member.read(1) == b"", "Selected tar body has trailing bytes")
    return b"".join(blocks)


def _copy_archive(record: dict, archive_id: str, files: list[dict], output: Path) -> None:
    planned = {}
    for row in files:
        if row["source"]["archiveId"] == archive_id:
            planned.setdefault(row["source"]["member"], []).append(row)
    I.need(all(len(rows) <= 32 for rows in planned.values()), "Archive body fanout ceiling")
    path, seen, last_end, count = Path(record["path"]), set(), 0, 0
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        I.need(I._state(os.fstat(descriptor)) == I._state(before), "Archive copy input changed")
        # fdopen does not own the original descriptor; the unconditional close below does.
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            reader = ForwardReader(stream, record["size"])
            with tarfile.open(fileobj=reader, mode="r:") as archive:
                names = set()
                for item in archive:
                    count += 1
                    I.need(count <= MAX_ENTRIES and not item.sparse and item.offset_data + item.size <= record["size"]
                           and 0 <= item.size <= MAX_MEMBER and (not item.pax_headers or set(item.pax_headers) <=
                           {"path", "linkpath", "mtime", "atime", "ctime"}), "Unsupported/oversized tar member")
                    last_end = ((item.offset_data + item.size + 511) // 512) * 512
                    if item.name in {".", "./"}:
                        I.need(item.isdir() and item.size == 0, "Different tar root")
                        continue
                    name = member_name(item.name)
                    I.need(name not in names and not any(p.startswith(".wh.") for p in name.split("/")),
                           "Duplicate/whiteout archive member")
                    names.add(name)
                    I.need(item.isreg() or item.isdir() or item.issym() or item.islnk(), "Special archive member refused")
                    if name not in planned:
                        continue
                    I.need(item.isreg(), "Selected body is not an original regular archive member")
                    member = archive.extractfile(item)
                    I.need(member is not None, "Missing selected tar body")
                    with member:
                        raw = _selected_body(member, item.size)
                    for row in planned[name]:
                        I.need((len(raw), I.digest(raw)) == (row["size"], row["sha256"]), "Selected body differs")
                        I.source_write(output / row["name"], raw, row["mode"])
                    seen.add(name)
            I.need(reader.count == last_end + 512 and reader.last == bytes(512), "Missing first tar end block")
            while block := reader.read(CHUNK):
                I.need(not any(block), "Nonzero tar trailer")
            I.need(reader.count >= last_end + 1024 and reader.count % 512 == 0
                   and (reader.count, reader.hash.hexdigest()) == (record["size"], record["sha256"])
                   and seen == set(planned), "Original archive or selected copy set differs")
        I.need(I._state(os.fstat(descriptor)) == I._state(before) == I._state(path.lstat()), "Archive changed during copy")
    finally:
        os.close(descriptor)


def materialize_source_root(request_path: Path, output: Path, report: Path) -> dict:
    I.need(APPROVED_ROOT_REQUEST_SHA256 is not None, "Conventional root preparation is closed pending DATA/command review")
    raw = I.source_read(I.absolute(str(request_path)), I.MAX_JSON)
    I.need(I.digest(raw) == I.sha(APPROVED_ROOT_REQUEST_SHA256), "Different conventional root request")
    request = I.keys(I.decode(raw), {"schema", "profile", "members", "selection", "streams"})
    I.need(request["schema"] == "mrk-cpython-source-root-request-1" and request["profile"] == I.SOURCE_PROFILE
           and request["members"]["sha256"] == MEMBERS_SHA256
           and (request["selection"]["size"], request["selection"]["sha256"]) ==
               (PUBLIC_SELECTION_BYTES, PUBLIC_SELECTION_SHA256), "Root inputs lack the selected retained correspondence")
    members = I.decode(I.source_bound(request["members"], I.MAX_JSON))
    packages, sources = selection_data(I.decode(I.source_bound(request["selection"], I.MAX_JSON)))
    files, aliases, omissions = root_plan(members)
    expected = {r["id"]: r for r in members["streams"]}
    I.need(len(expected) == 60 and type(request["streams"]) is list and len(request["streams"]) == 60,
           "Use base plus selected59 decoded payloads, not all146 over base")
    streams = {}
    for row in request["streams"]:
        I.keys(row, {"id", "file"})
        I.need(row["id"] in expected and row["id"] not in streams, "Foreign/duplicate decoded stream")
        wanted = expected[row["id"]]
        I.need((row["file"]["size"], row["file"]["sha256"]) == (wanted["size"], wanted["sha256"]),
               "Different original decoded archive")
        streams[row["id"]] = row["file"]
    I.need(list(streams) == sorted(expected) and sum(r["size"] for r in streams.values()) <= MAX_RAW,
           "Decoded stream ordering/aggregate ceiling")
    for record in streams.values():
        _fingerprint(record)  # Every complete source authenticated before any output creation.
    for path in (output, report):
        I.absolute(str(path))
        I.ordinary_directory(path.parent)
        I.need(not path.exists() and not path.is_symlink(), "Root/report must be fresh")
    inputs = [request_path, Path(request["members"]["path"]), Path(request["selection"]["path"]),
              *(Path(r["path"]) for r in streams.values())]
    I.need(output != report and output not in report.parents
           and all(output not in p.parents and report != p for p in inputs), "Root/report overlaps inputs")
    directories = root_directories(files, aliases)
    I.need(len(directories) + len(files) + len(aliases) + len(ROOT_CONFIG) + 2 <= MAX_ENTRIES,
           "Conventional root entry ceiling")
    output.mkdir(mode=0o700)
    I.source_write(output / "INCOMPLETE", b"Root DATA projection incomplete; no native qualification.\n")
    for name in sorted(directories, key=lambda s: (s.count("/"), s)):
        (output / name).mkdir(mode=0o700)
    for archive_id, record in streams.items():
        _copy_archive(record, archive_id, files, output)
    generated = []
    for name, data in ROOT_CONFIG.items():
        row = I.source_write(output / name, data, 0o444)
        generated.append({**row, "path": name, "origin": "fixed-root-configuration-v1"})
    for row in aliases:
        link = posixpath.relpath(row["target"], posixpath.dirname(row["name"]) or ".")
        os.symlink(link, output / row["name"])
        I.need(os.readlink(output / row["name"]) == link, "Root alias readback differs")
    for row in files:
        path = output / row["name"]
        data = I.source_read(path, MAX_MEMBER)
        I.need((len(data), I.digest(data), stat.S_IMODE(path.lstat().st_mode)) ==
               (row["size"], row["sha256"], row["mode"]), "Root body readback differs")
    actual_files, actual_dirs, actual_aliases, pending = set(), set(), set(), [output]
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                path = Path(child.path)
                name = relative(path.relative_to(output).as_posix())
                value = child.stat(follow_symlinks=False)
                if stat.S_ISDIR(value.st_mode):
                    actual_dirs.add(name)
                    pending.append(path)
                elif stat.S_ISLNK(value.st_mode):
                    actual_aliases.add(name)
                else:
                    I.need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1, "Nonordinary root body")
                    actual_files.add(name)
                I.need(len(actual_files) + len(actual_dirs) + len(actual_aliases) <= MAX_ENTRIES, "Root readback entry ceiling")
    I.need(actual_files == {r["name"] for r in files} | set(ROOT_CONFIG) | {"INCOMPLETE"}
           and actual_dirs == directories and actual_aliases == {r["name"] for r in aliases},
           "Conventional root namespace readback differs")
    document = {"schema": ROOT_SCHEMA, "profile": I.SOURCE_PROFILE, "nativeQualification": "not-established",
        "baseManifestSha256": BASE_MANIFEST_SHA256, "baseConfigSha256": BASE_CONFIG_SHA256,
        "baseLayerSha256": BASE_LAYER_SHA256, "memberPlanSha256": MEMBERS_SHA256,
        "selectionSha256": PUBLIC_SELECTION_SHA256, "memberSelectionLineageSha256": MEMBER_SELECTION_LINEAGE_SHA256,
        "requestSha256": I.digest(raw),
        "files": files, "aliases": aliases, "directories": sorted(directories), "generated": generated,
        "generatedDirectories": [{"path": name, "origin": "fixed-empty-mountpoint-scaffold-v1"} for name in ROOT_MOUNTPOINTS],
        "omissions": omissions, "packages": packages, "sources": sources,
        "mountRequirement": "whole-root-read-only-with-only-separately-admitted-work-dev-proc-mounts"}
    data = I.canonical(document)
    I.need(len(data) <= I.MAX_JSON, "Conventional root report ceiling")
    result = I.source_write(report, data)
    (output / "INCOMPLETE").unlink()
    for name in sorted(directories, key=lambda s: (-s.count("/"), s)):
        os.chmod(output / name, 0o555)
        I.need(stat.S_IMODE((output / name).lstat().st_mode) == 0o555, "Root directory mode differs")
    os.chmod(output, 0o555)
    I.need(stat.S_IMODE(output.lstat().st_mode) == 0o555, "Root mode differs")
    return result


def main() -> None:
    I.need(len(sys.argv) == 4, "Expected fixed REQUEST ROOT REPORT paths")
    materialize_source_root(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))


if __name__ == "__main__":
    main()
