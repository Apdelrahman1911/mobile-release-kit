"""One pinned SDK subtree copied to a NEW candidate, through the existing run.

The private binding is comparison DATA from the parent's returned SourceSlots.
This opens NEW originals; it never revives their closed native handles. No SDK
manager, installer, project script, symlink, existing chmod or merge is used.
The same ToolAcquisition cleanup/STOP/deadline owns this finite source book.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import struct
from typing import Iterator

from ._tool_acquisition_spec import (Archive, CHUNK, Component, MEMBER_LIMIT, Member,
    digest, relative, require)
from ._tool_acquisition_files import Files, OutputTree, named
from .build_inputs import _Directory, _FD, _fd_cleanup

FORMAT = "mrk-sdk-copy/1"
SDK = (Component.SDK_PLATFORM, Component.SDK_BUILD_TOOLS)
PREFIX = {Component.SDK_PLATFORM: "platforms/android-35", Component.SDK_BUILD_TOOLS: "build-tools/35.0.0"}
# Same finite ancestry/frontier as the native source observer. This is not a
# larger process/RSS quota or a claim about the still-unqualified native route.
ANCESTORS, LIVE_SOURCE, METADATA_BYTES = 48, 64, 32 * 1024
STAMP = struct.Struct("<iQHIIHqqqqqI")


def stamp(info: os.stat_result) -> bytes:
    """Exact Darwin Identity fields; atime is deliberately not a source pin."""
    try:
        return STAMP.pack(info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns // 10**9, info.st_mtime_ns % 10**9,
            info.st_ctime_ns // 10**9, info.st_ctime_ns % 10**9, getattr(info, "st_flags", 0))
    except (OverflowError, struct.error):
        require(False, "stale")


@dataclass(frozen=True, slots=True, repr=False)
class CopyBinding:
    component: Component
    root: Path
    root_identity: bytes
    observation_sha256: str

    @classmethod
    def parse(cls, value, missing: tuple[Component, ...], compatible: tuple[Component, ...]):
        if value is None:
            return None  # Old private requests/results retain their old meaning.
        require(type(value) is dict and set(value) == {"format", "component", "root", "rootIdentity", "observationSha256"})
        require(value["format"] == FORMAT and type(value["component"]) is str
            and value["component"] in [part.value for part in SDK])
        component = Component(value["component"])
        require(component in compatible and tuple(part for part in SDK if part in compatible) == (component,)
            and tuple(part for part in SDK if part in missing) == tuple(part for part in SDK if part != component), "stale")
        root = value["root"]
        require(type(root) is str and root.startswith("/") and 1 < len(root.encode("utf-8")) <= 4096)
        parts = root[1:].split("/")
        require(len(parts) + 1 <= ANCESTORS and all(part not in ("", ".", "..") and len(part.encode("utf-8")) <= 255
            and not any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in part) for part in parts))
        raw = value["rootIdentity"]
        require(type(raw) is str and len(raw) == 2 * STAMP.size and all(c in "0123456789abcdef" for c in raw)
            and digest(value["observationSha256"]))
        identity = bytes.fromhex(raw)
        fields = STAMP.unpack(identity)
        require(fields[0] >= 0 and fields[1] > 0 and stat.S_ISDIR(fields[2]) and not fields[2] & 0o7022
            and fields[6] >= 0 and 0 <= fields[8] < 10**9 and 0 <= fields[10] < 10**9)
        return cls(component, Path(root), identity, value["observationSha256"])


class _Observation:
    def __init__(self, reference: str, binding: CopyBinding):
        self.hash = hashlib.sha256(b"mrk-sdk-copy-observation/1\0" + bytes.fromhex(reference)
            + bytes([SDK.index(binding.component) + 1]) + binding.root_identity)
        self.count = 0

    def member(self, path: str, directory: bool, identity: bytes):
        raw = path.encode("utf-8")
        require(0 < len(raw) <= 512 and self.count < MEMBER_LIMIT, "limit")
        self.hash.update(b"\1" + struct.pack("<I", len(raw)) + raw + bytes([int(directory)]) + identity)
        self.count += 1

    def finish(self, metadata: tuple[bytes, bytes] | None):
        require(self.count > 0, "archive-layout")
        self.hash.update(bytes([2, int(metadata is not None)]))
        if metadata is not None:
            self.hash.update(metadata[0]); self.hash.update(metadata[1])
        self.hash.update(b"\3" + struct.pack("<I", self.count))
        return self.hash.hexdigest()


class SdkCopy:
    """Retained before any read; one acquisition, copy, POST and close sequence."""
    def __init__(self, binding: CopyBinding, reference: str, archive: Archive, files: Files):
        require(type(binding) is CopyBinding and type(archive) is Archive and archive.component is binding.component)
        require(digest(reference))
        self.binding, self.reference, self.archive, self.files = binding, reference, archive, files
        self.guard = files.guard
        self.root = _Directory(binding.root, self.guard, system_root_aliases=True)
        self.slots: list[_FD] = []
        self.acquired = self.copied = self.close_claimed = self.closed = False
        # Only reference entries, not retained file bytes or 11k open handles.
        self.members: dict[str, Member | None] = {}
        self.children: dict[str, list[str]] = {}
        prefix = PREFIX[binding.component]
        for member in archive.members:
            path = member.source_relative
            if path is None:
                require(member.kind == "directory", "archive-layout")
                continue
            require(path == prefix or path.startswith(prefix + "/"), "archive-layout")
            require(path not in self.members, "archive-layout")
            self.members[path] = member
        for parent in archive.parents:
            path = parent.relative
            if path == prefix or path.startswith(prefix + "/"):
                require(path not in self.members and parent.mode == 0o755, "archive-layout")
                self.members[path] = None
            else:
                require(prefix.startswith(path + "/"), "archive-layout")
        require(0 < len(self.members) <= MEMBER_LIMIT and prefix in self.members, "archive-layout")
        for path, member in self.members.items():
            relative(path)
            directory = member is None or member.kind == "directory"
            if directory:
                self.children[path] = []
        require(prefix in self.children, "archive-layout")
        for path in self.members:
            if path == prefix:
                continue
            parent, _, leaf = path.rpartition("/")
            require(parent in self.children, "archive-layout")
            self.children[parent].append(leaf)
        for names in self.children.values():
            names.sort()  # Same component-wise canonical order as native.

    def check(self):
        self.files.check()
        require(self.acquired and not self.close_claimed, "unknown")
        self.root.check()
        require(stamp(os.fstat(self.root.fd)) == self.binding.root_identity, "stale")

    def acquire(self):
        require(not self.acquired and not self.close_claimed, "already-used")
        self.root.acquire()
        self.acquired = True
        self.check()
        source = os.fstat(self.root.fd); destination = os.fstat(self.files.root.fd)
        source_id = (source.st_dev, source.st_ino); destination_id = (destination.st_dev, destination.st_ino)
        # Physical held-root/ancestry comparisons, not canonicalized path guesses.
        require(source_id not in {(b["device"], b["inode"]) for _, _, b in self.files.root.bindings}
            and destination_id not in {(b["device"], b["inode"]) for _, _, b in self.root.bindings}, "cache-conflict")
        self.check()

    @contextmanager
    def _open(self, parent: int, name: str, directory: bool, *, mode: int | None = None,
              size: int | None = None) -> Iterator[tuple[int, bytes]]:
        self.check()
        before = named(parent, name)
        require(before is not None and (stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode))
            and before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o7022
            and (directory or before.st_nlink == 1) and (mode is None or stat.S_IMODE(before.st_mode) == mode)
            and (size is None or before.st_size == size), "stale")
        require(len(self.root.slots) + len(self.slots) < LIVE_SOURCE, "limit")
        slot = _FD(self.guard)
        self.slots.append(slot)  # BEFORE the original open, including its error.
        with _fd_cleanup(slot):
            slot.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
            expected = stamp(before)
            require(stamp(os.fstat(slot.number)) == expected, "stale")
            yield slot.number, expected
            self.check()
            require(stamp(os.fstat(slot.number)) == expected
                and stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected, "stale")
        require(slot.close_state == "CLOSED", "unknown")
        self.slots.remove(slot)

    def _chunks(self, fd: int, size: int, digest_value: str | None):
        count, hashed = 0, hashlib.sha256()
        while count < size:
            self.check()
            data = os.read(fd, min(CHUNK, size - count))
            require(type(data) is bytes and 0 < len(data) <= min(CHUNK, size - count), "stale")
            count += len(data); hashed.update(data)
            yield data
        self.check()
        require(os.read(fd, 1) == b"" and (digest_value is None or hashed.hexdigest() == digest_value), "stale")

    def _metadata(self, fd: int):
        before = named(fd, "package.xml")
        if before is None:
            return None
        require(stat.S_IMODE(before.st_mode) in (0o444, 0o644) and 0 < before.st_size <= METADATA_BYTES, "stale")
        with self._open(fd, "package.xml", False, mode=stat.S_IMODE(before.st_mode), size=before.st_size) as (opened, identity):
            hashed = hashlib.sha256()
            for data in self._chunks(opened, before.st_size, None): hashed.update(data)
            return identity, hashed.digest()

    def _pass(self, tree: OutputTree | None):
        observed = _Observation(self.reference, self.binding)
        metadata = None
        prefix = PREFIX[self.binding.component]

        def visit(parent: int, path: str):
            nonlocal metadata
            member = self.members[path]
            directory = path in self.children
            mode = 0o755 if member is None else member.source_mode
            with self._open(parent, path.rsplit("/", 1)[-1], directory, mode=mode,
                    size=None if directory else member.size) as (fd, identity):
                observed.member(path, directory, identity)
                if directory:
                    expected = set(self.children[path])
                    if path == prefix:
                        metadata = self._metadata(fd)
                        if metadata is not None: expected.add("package.xml")
                    require(set(self.files.names(fd, MEMBER_LIMIT)) == expected, "stale")
                    if tree is not None:
                        if member is None: tree.directory(self.binding.component.folder + "/" + path)
                        else: tree.member(self.archive, member)
                    for leaf in self.children[path]: visit(fd, path + "/" + leaf)
                    require(set(self.files.names(fd, MEMBER_LIMIT)) == expected, "stale")
                else:
                    chunks = self._chunks(fd, member.size, member.sha256)
                    if tree is None:
                        for _ in chunks: pass
                    else:
                        tree.member(self.archive, member, chunks)

        # Only the chosen required subtree, not the whole SDK/sibling packages.
        parent_name = prefix.split("/")[0]
        with self._open(self.root.fd, parent_name, True) as (parent, _):
            visit(parent, prefix)
        self.check()
        require(observed.finish(metadata) == self.binding.observation_sha256, "stale")

    def copy_to(self, tree: OutputTree):
        require(not self.copied and not self.close_claimed, "already-used")
        self.copied = True
        self.check()
        self._pass(tree)
        # Exact required bytes + full identities again after the copy. Each
        # reader is a NEW original in this SAME finite book; no closed-FD reuse.
        self._pass(None)
        self.check()
        self.close()  # Positive closure is required BEFORE any vendor transfer.
        require(self.closed, "unknown")
        self.files.check()

    def close(self):
        if self.close_claimed:
            require(self.closed, "unknown")
            return
        self.close_claimed = True
        first = None
        # Independent original closes still run after any earlier failure.
        for slot in tuple(reversed(self.slots)):
            try:
                slot.close()
                if slot.close_state == "CLOSED": self.slots.remove(slot)
            except BaseException as error:
                if first is None: first = error
        try:
            self.root.close()
        except BaseException as error:
            if first is None: first = error
        if first is not None:
            self.guard._abort(first)
            raise first
        require(not self.slots and all(slot.close_state == "CLOSED" for slot in self.root.slots), "unknown")
        self.closed = True
