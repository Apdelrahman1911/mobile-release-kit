"""Bounded descriptor-owned cache files and closed-roster extraction.

Only a newly created operation directory is writable. There is no deletion,
overwrite, recursive cleanup, chmod-existing-tool or installation interface.
Original native finality and reuse permission belong to the calling owner.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat
from typing import Callable, Iterator

from ._tool_acquisition_spec import (AcquisitionError, Archive, CHUNK, MANIFEST_LIMIT,
    MEMBER_LIMIT, Member, canonical, name_key, relative, require)
from .build_inputs import _Directory, _FD, _mkdir_private
from .cancellation import DefaultCancellation


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info: os.stat_result) -> tuple[int, ...]:
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(), "cache-conflict")
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def named(parent: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


class _Scan:
    """Original scandir iterator, retained before its internally owned FD opens."""
    def __init__(self, guard: DefaultCancellation):
        self.guard, self.original, self.state = guard, None, "NEW"

    def open(self, parent: int) -> None:
        require(self.state == "NEW", "unknown")
        with self.guard.deferred(check_on_exit=False):
            self.state = "ATTEMPTED"
            try:
                self.original = os.scandir(parent)
                self.state = "OPEN"
            except BaseException as error:
                self.state = "UNKNOWN"
                self.guard._abort(error)
                raise

    def close(self) -> None:
        if self.state == "CLOSED":
            return
        if self.state == "NEW":
            self.state = "CLOSED"
            return
        require(self.state == "OPEN" and self.original is not None, "unknown")
        with self.guard.deferred(check_on_exit=False):
            self.state = "CLOSE_ATTEMPTED"
            try:
                self.original.close()
                self.state = "CLOSED"
            except BaseException as error:
                self.state = "UNKNOWN"
                self.guard._abort(error)
                raise


class Files:
    """Retain before acquisition, reuse existing one-attempt _FD closes."""
    def __init__(self, root: Path, guard: DefaultCancellation, checkpoint: Callable[[], None]):
        self.guard, self.checkpoint = guard, checkpoint
        self.root = _Directory(root, guard, system_root_aliases=True)
        self.slots: list[_FD] = []
        self.scans: list[_Scan] = []
        self.creations: list[dict[str, str]] = []
        self.settled = False
        self.before_write: Callable[[int], None] | None = None

    def acquire(self) -> None:
        self.root.acquire()
        info = os.fstat(self.root.fd)
        directory_identity(info)
        require(stat.S_IMODE(info.st_mode) == 0o700, "cache-conflict")
        self.check()

    def check(self) -> None:
        self.checkpoint()
        self.guard.check()
        self.root.check()

    def open(self, parent: int, name: str, flags: int) -> _FD:
        self.check()
        slot = _FD(self.guard)
        self.slots.append(slot)
        slot.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        return slot

    def close_slot(self, slot: _FD) -> None:
        slot.close()
        if slot.close_state == "CLOSED":
            self.slots.remove(slot)

    @contextmanager
    def directory(self, parent: int, name: str, *, mode: int = 0o700) -> Iterator[int]:
        before = named(parent, name)
        require(before is not None and stat.S_IMODE(before.st_mode) == mode, "cache-conflict")
        expected = directory_identity(before)
        slot = self.open(parent, name, os.O_RDONLY | os.O_DIRECTORY)
        try:
            require(directory_identity(os.fstat(slot.number)) == expected, "cache-conflict")
            yield slot.number
            self.check()
            require(directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected
                    and directory_identity(os.fstat(slot.number)) == expected, "cache-conflict")
        finally:
            self.close_slot(slot)

    def mkdir(self, parent: int, name: str, *, mode: int = 0o700) -> tuple[int, ...]:
        self.check()
        require(named(parent, name) is None, "cache-conflict")
        record = {"state": "NEW"}
        self.creations.append(record)
        _mkdir_private(name, parent, self.guard, record)
        slot = self.open(parent, name, os.O_RDONLY | os.O_DIRECTORY)
        try:
            info = os.fstat(slot.number)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(), "cache-conflict")
            os.fchmod(slot.number, mode)  # Only the exact directory just created.
            result = directory_identity(os.fstat(slot.number))
            require(directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == result, "cache-conflict")
            os.fsync(parent)
            return result
        finally:
            self.close_slot(slot)

    def names(self, parent: int, limit: int) -> tuple[str, ...]:
        self.check()
        names, folded = [], set()
        # Never materialize an unbounded list before applying the entry limit.
        scan = _Scan(self.guard)
        self.scans.append(scan)
        try:
            scan.open(parent)
            for entry in scan.original:
                self.check()
                require(len(names) < limit, "limit")
                key = name_key(entry.name)
                require(key not in folded, "cache-conflict")
                folded.add(key)
                names.append(entry.name)
        finally:
            scan.close()
            if scan.state == "CLOSED":
                self.scans.remove(scan)
        return tuple(sorted(names))

    @contextmanager
    def new_file(self, parent: int, name: str) -> Iterator[int]:
        slot = self.open(parent, name, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        try:
            original = os.fstat(slot.number)
            require(stat.S_ISREG(original.st_mode) and original.st_nlink == 1 and original.st_uid == os.geteuid(), "cache-conflict")
            os.fchmod(slot.number, 0o600)
            yield slot.number
            self.check()
            after = os.fstat(slot.number)
            require((after.st_dev, after.st_ino) == (original.st_dev, original.st_ino)
                    and after.st_nlink == 1 and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(after),
                    "cache-conflict")
            os.fsync(slot.number)
            os.fsync(parent)
        finally:
            self.close_slot(slot)

    @contextmanager
    def reader(self, parent: int, name: str, maximum: int, *, mode: int = 0o600) -> Iterator[Reader]:
        before = named(parent, name)
        require(before is not None and stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode and before.st_size <= maximum,
                "cache-conflict")
        slot = self.open(parent, name, os.O_RDONLY)
        reader = Reader(self, parent, name, slot, identity(before))
        try:
            reader.verify()
            yield reader
            reader.verify()
        finally:
            self.close_slot(slot)

    def write(self, fd: int, value: bytes) -> None:
        require(type(value) is bytes and len(value) <= CHUNK, "limit")
        if self.before_write is not None:
            self.before_write(len(value))
        offset = 0
        while offset < len(value):
            self.check()
            count = os.write(fd, value[offset:])
            require(type(count) is int and 0 < count <= len(value) - offset, "unknown")
            offset += count

    def control(self, parent: int, name: str, value: object) -> None:
        data = canonical(value)
        require(len(data) <= 16 * 1024, "limit")
        with self.new_file(parent, name) as fd:
            self.write(fd, data)

    def close(self) -> None:
        first = None
        for scan in tuple(reversed(self.scans)):
            try:
                scan.close()
                if scan.state == "CLOSED":
                    self.scans.remove(scan)
            except BaseException as error:
                if first is None:
                    first = error
        for slot in tuple(reversed(self.slots)):
            try:
                self.close_slot(slot)
            except BaseException as error:
                if first is None:
                    first = error
        try:
            self.root.close()
        except BaseException as error:
            if first is None:
                first = error
        if first is not None:
            raise first
        require(not self.slots and not self.scans
            and all(record["state"] not in ("ATTEMPTED", "UNKNOWN") for record in self.creations), "unknown")
        self.settled = True


class Reader:
    """A borrowed original descriptor; stdlib parsers never own its close."""
    def __init__(self, files: Files, parent: int, name: str, slot: _FD, stamp: tuple[int, ...]):
        self.files, self.parent, self.name, self.slot, self.stamp = files, parent, name, slot, stamp
        self.size = stamp[6]

    def verify(self) -> None:
        self.files.check()
        require(self.slot.number is not None and identity(os.fstat(self.slot.number)) == self.stamp
                and identity(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)) == self.stamp, "cache-conflict")

    def tell(self) -> int:
        self.files.check()
        return os.lseek(self.slot.number, 0, os.SEEK_CUR)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        require(type(offset) is int and whence in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END), "archive-layout")
        start = 0 if whence == os.SEEK_SET else self.tell() if whence == os.SEEK_CUR else self.size
        require(0 <= start + offset <= self.size, "archive-layout")
        self.files.check()
        return os.lseek(self.slot.number, start + offset, os.SEEK_SET)

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size == -1:
            size = self.size - self.tell()
        require(type(size) is int and 0 <= size <= MANIFEST_LIMIT, "limit")
        self.files.check()
        data = os.read(self.slot.number, size)
        self.files.check()
        return data

    def sha256(self) -> str:
        self.verify()
        self.seek(0)
        value = hashlib.sha256()
        while True:
            data = self.read(CHUNK)
            if not data:
                break
            value.update(data)
        self.verify()
        return value.hexdigest()


class OutputTree:
    def __init__(self, files: Files, root: int, archives: tuple[Archive, ...]):
        self.files, self.root = files, root
        self.directories: dict[str, int] = {}
        self.created: dict[str, tuple[int, ...]] = {}
        self.written: dict[str, tuple[int, ...]] = {}
        self.expected: dict[str, Member] = {}
        folded: dict[str, str] = {}

        def add(path: str, directory: bool, mode: int) -> None:
            relative(path)
            key = name_key(path)
            require(key not in folded or folded[key] == path, "archive-layout")
            folded[key] = path
            require(not directory or path not in self.expected, "archive-layout")
            require(directory or path not in self.directories, "archive-layout")
            if directory:
                require(self.directories.get(path, mode) == mode, "archive-layout")
                self.directories[path] = mode

        for archive in archives:
            prefix = archive.component.folder
            add(prefix, True, 0o755)
            for parent in archive.parents:
                add(prefix + "/" + parent.relative, True, parent.mode)
            for member in archive.members:
                if member.source_relative is None:
                    continue
                path = prefix + "/" + member.source_relative
                add(path, member.kind == "directory", member.source_mode)
                if member.kind == "file":
                    require(path not in self.expected, "archive-layout")
                    self.expected[path] = member
            for path in tuple((*self.directories, *self.expected)):
                parts = path.split("/")
                for index in range(1, len(parts)):
                    add("/".join(parts[:index]), True, 0o755)
        require(len(self.directories) + len(self.expected) <= MEMBER_LIMIT, "limit")
        self.children: dict[str, set[str]] = {path: set() for path in self.directories}
        self.children[""] = set()
        for path in (*self.directories, *self.expected):
            parent, _, name = path.rpartition("/")
            self.children[parent].add(name)

    @contextmanager
    def parent(self, path: str) -> Iterator[tuple[int, str]]:
        parts = relative(path).split("/")
        slots: list[_FD] = []
        parent = self.root
        try:
            for index, part in enumerate(parts[:-1]):
                spelling = "/".join(parts[:index + 1])
                require(spelling in self.directories, "archive-layout")
                if spelling not in self.created:
                    self.created[spelling] = self.files.mkdir(parent, part, mode=self.directories[spelling])
                slot = self.files.open(parent, part, os.O_RDONLY | os.O_DIRECTORY)
                slots.append(slot)
                require(directory_identity(os.fstat(slot.number)) == self.created[spelling]
                        and directory_identity(os.stat(part, dir_fd=parent, follow_symlinks=False)) == self.created[spelling],
                        "cache-conflict")
                parent = slot.number
            yield parent, parts[-1]
        finally:
            first = None
            for slot in reversed(slots):
                try:
                    self.files.close_slot(slot)
                except BaseException as error:
                    if first is None:
                        first = error
            if first is not None:
                raise first

    def directory(self, path: str) -> None:
        require(path in self.directories, "archive-layout")
        with self.parent(path) as (parent, leaf):
            if path not in self.created:
                self.created[path] = self.files.mkdir(parent, leaf, mode=self.directories[path])
            require(directory_identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == self.created[path], "cache-conflict")

    def member(self, archive: Archive, member: Member, chunks: Iterator[bytes] | None = None) -> None:
        if member.source_relative is None:
            require(member.kind == "directory", "archive-member")
            return
        path = archive.component.folder + "/" + member.source_relative
        if member.kind == "directory":
            self.directory(path)
            return
        require(path in self.expected and path not in self.written and chunks is not None, "archive-member")
        with self.parent(path) as (parent, leaf):
            with self.files.new_file(parent, leaf) as fd:
                count = 0
                hashed = hashlib.sha256()
                for data in chunks:
                    require(type(data) is bytes and 0 < len(data) <= CHUNK and count + len(data) <= member.size, "archive-member")
                    self.files.write(fd, data)
                    hashed.update(data)
                    count += len(data)
                require(count == member.size and hashed.hexdigest() == member.sha256, "archive-member")
                os.fchmod(fd, member.source_mode)
                require(os.fstat(fd).st_size == member.size, "archive-member")
                self.written[path] = identity(os.fstat(fd))

    def verify(self) -> None:
        for path in sorted(self.directories, key=lambda value: (value.count("/"), value)):
            self.directory(path)
        require(set(self.written) == set(self.expected), "archive-member")
        for path, member in self.expected.items():
            with self.parent(path) as (parent, leaf):
                with self.files.reader(parent, leaf, member.size, mode=member.source_mode) as reader:
                    require(reader.size == member.size and reader.stamp == self.written[path]
                            and reader.sha256() == member.sha256, "archive-member")
        # Complete exact output census, including empty directories; unknown
        # children cannot become source-picker candidates merely by their name.
        for path in self.directories:
            with self.parent(path + "/placeholder") as (parent, _):
                require(set(self.files.names(parent, MEMBER_LIMIT)) == self.children[path], "cache-conflict")
        require(set(self.files.names(self.root, MEMBER_LIMIT)) == self.children[""], "cache-conflict")


def _chunks(reader, size: int, check: Callable[[], None]) -> Iterator[bytes]:
    count = 0
    while count < size:
        check()
        data = reader.read(min(CHUNK, size - count))
        require(type(data) is bytes and 0 < len(data) <= min(CHUNK, size - count), "archive-member")
        count += len(data)
        yield data
    check()
    require(reader.read(1) == b"", "archive-member")


def extract_zip(reader: Reader, archive: Archive, tree: OutputTree) -> None:
    import zipfile
    from .android_zip import inspect_zip_directory, plan_zip_directory, zip_tail_range
    from .android_zip_integrity import inspect_zip_integrity

    check = reader.files.check
    tail = zip_tail_range(reader.size)
    reader.seek(tail.offset)
    plan = plan_zip_directory(reader.size, reader.read(tail.length))
    reader.seek(plan.central_directory.offset)
    metadata = inspect_zip_directory(plan, reader.read(plan.central_directory.length))
    require(len(metadata.entries) == len(archive.members) and metadata.declared_expanded_bytes == archive.expanded_bytes,
            "archive-layout")
    roster = {member.name: member for member in archive.members}
    seen = set()
    for entry in metadata.entries:
        name = relative(entry.name.removesuffix("/"))
        key = name_key(name)
        require(key not in seen and name in roster, "archive-layout")
        seen.add(key)
        member = roster[name]
        require((entry.name.endswith("/")) == (member.kind == "directory") and entry.file_size == member.size
                and entry.external_attr >> 16 == member.archive_mode, "archive-member")
    # Reuse the existing bounded central/local/CRC/decompression verifier after
    # checking this supplier's stricter exact counts/expansion/roster.
    verified = inspect_zip_integrity(reader, archive_bytes=reader.size, checkpoint=check)
    require(verified.metadata == metadata and verified.expanded_bytes == archive.expanded_bytes, "archive-layout")
    reader.verify()
    with zipfile.ZipFile(reader, "r", allowZip64=False) as zipped:
        infos = zipped.infolist()
        require(len(infos) == len(metadata.entries), "archive-layout")
        for info, entry in zip(infos, metadata.entries):
            check()
            require(info.filename == entry.name and info.file_size == entry.file_size
                    and info.header_offset == entry.local_header_offset and info.CRC == entry.crc32
                    and info.compress_type == entry.compression and info.compress_size == entry.compressed_size
                    and info.external_attr == entry.external_attr and info.flag_bits == entry.flag_bits, "archive-layout")
            member = roster[entry.name.removesuffix("/")]
            if member.kind == "directory":
                tree.member(archive, member)
            else:
                with zipped.open(info, "r") as content:
                    tree.member(archive, member, _chunks(content, member.size, check))
    reader.verify()


class _BoundedGzip:
    """Forward-only tar reader; metadata reads are bounded before allocation.

    Used directly with TarFile's uncompressed mode. Its streaming _Stream
    adapter is intentionally NOT used: that adapter can aggregate an attacker
    sized GNU/PAX metadata read before our per-read limit sees the request.
    """
    def __init__(self, reader: Reader, maximum: int):
        import zlib
        self.reader, self.maximum = reader, maximum
        self.stream = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.pending = b""
        self.total = 0
        self.finished = False

    def tell(self) -> int:
        return self.total

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        require(type(offset) is int and whence in (os.SEEK_SET, os.SEEK_CUR), "archive-layout")
        target = offset if whence == os.SEEK_SET else self.total + offset
        require(self.total <= target <= self.maximum, "archive-layout")
        while self.total < target:
            require(bool(self.read(min(CHUNK, target - self.total))), "archive-layout")
        return self.total

    def read(self, size: int) -> bytes:
        require(type(size) is int and 0 <= size <= CHUNK, "limit")
        if size == 0 or self.finished:
            return b""
        output = bytearray()
        while len(output) < size and not self.finished:
            self.reader.files.check()
            if not self.pending:
                self.pending = self.reader.read(CHUNK)
            allowance = min(size - len(output), self.maximum - self.total + 1)
            require(allowance > 0, "limit")
            previous = len(self.pending)
            data = self.stream.decompress(self.pending, allowance)
            self.pending = self.stream.unconsumed_tail
            require(not self.stream.unused_data, "archive-layout")
            self.total += len(data)
            require(self.total <= self.maximum, "limit")
            output.extend(data)
            if self.stream.eof:
                require(not self.pending and self.reader.read(1) == b"", "archive-layout")
                self.finished = True
            else:
                require(bool(data) or len(self.pending) < previous, "archive-layout")
        return bytes(output)


def extract_tar(reader: Reader, archive: Archive, tree: OutputTree) -> None:
    import tarfile

    reader.seek(0)
    # Exact file expansion plus fixed header/block-padding and bounded metadata.
    maximum = archive.expanded_bytes + len(archive.members) * 1024 + 8 * 1024 * 1024
    stream = _BoundedGzip(reader, maximum)
    roster = {member.name: member for member in archive.members}
    seen = set()
    with tarfile.open(fileobj=stream, mode="r:") as tar:
        for entry in tar:
            reader.files.check()
            name = relative(entry.name.removesuffix("/"))
            key = name_key(name)
            require(len(seen) < len(roster) and key not in seen and name in roster, "archive-layout")
            seen.add(key)
            member = roster[name]
            require(not entry.issparse() and not entry.linkname and (entry.isdir() or entry.isreg()), "archive-member")
            require(entry.isdir() == (member.kind == "directory") and entry.size == member.size, "archive-member")
            mode = entry.mode | (stat.S_IFDIR if entry.isdir() else stat.S_IFREG)
            expected_mode = member.archive_mode | (stat.S_IFDIR if entry.isdir() else stat.S_IFREG)
            require(mode == expected_mode and len(entry.pax_headers) <= 16, "archive-member")
            require(all(key in {"path", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"}
                        and type(value) is str and len(value) <= 512 for key, value in entry.pax_headers.items()), "archive-member")
            if entry.isdir():
                tree.member(archive, member)
            else:
                content = tar.extractfile(entry)  # Reader only; never tar.extract/extractall.
                require(content is not None, "archive-member")
                with content:
                    tree.member(archive, member, _chunks(content, member.size, reader.files.check))
        require(len(seen) == len(roster), "archive-layout")
        while True:
            reader.files.check()
            padding = tar.fileobj.read(CHUNK)
            if not padding:
                break
            require(not any(padding), "archive-layout")
    require(stream.finished, "archive-layout")
    reader.verify()
