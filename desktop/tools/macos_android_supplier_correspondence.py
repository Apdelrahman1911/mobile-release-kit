"""Bounded, offline original-archive correspondence DATA.

No path opening, extraction, network, subprocess, installation, environment
discovery or runtime/tool admission occurs here. A reviewed owner supplies the
SAME already nominated original and its original endpoint; it retains custody
through report publication and performs the actual close/join. A report is
never a reviewed supplier reference, consent, native closure or a pass receipt.
The accepted macos_android_supplier_preparation.py remains independent.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import re
import struct
import zlib
from typing import Callable, Protocol

WINDOW = 65536
ARCHIVE_LIMIT = 256 * 1024 * 1024
ISSUED_READ_LIMIT = 768 * 1024 * 1024
EXPANDED_LIMIT = 1024 * 1024 * 1024
FILE_LIMIT = 512 * 1024 * 1024
FILE_COUNT = 16384
ALIAS_COUNT = 128
ENTRY_LIMIT = 32768
ROSTER_LIMIT = 48 * 1024 * 1024
OUTPUT_LIMIT = 4 * 1024 * 1024
WORKSPACE_LIMIT = 64 * 1024 * 1024
SCRATCH_RESERVATION = 8 * 1024 * 1024
CENTRAL_LIMIT = 16 * 1024 * 1024
TAR_STREAM_LIMIT = EXPANDED_LIMIT + ENTRY_LIMIT * 1024 + 10240
LABELS = ("jdk", "sdk-platform", "sdk-build-tools", "gradle", "bundletool", "aapt2")
ZIP_FLAGS = 0x080E  # UTF-8, optional descriptor, Deflate compression hints.
ZIP_EXTRA = frozenset((0x000A, 0x5455, 0x5855, 0x7875, 0xCAFE))  # Times, uid/gid, JAR marker.
COLUMNS = ("name", "kind", "mode", "size", "sha256", "target",
           "localHeaderOffset", "dataOffset", "compressedSize", "method",
           "flags", "crc32", "creatorSystem", "formatHint")

class Refused(Exception):
    """No partial capture/digest may be promoted after any refusal."""

class Original(Protocol):
    """All methods preserve the owner's unchanged aggregate clock and custody.

    checkpoint MUST raise on any original deadline/failure/finality loss.
    verify_binding MUST check the SAME original identity and named binding.
    read_at MUST use that same retained original, issue only count bytes and
    return bytes (or raise). It must participate in the owner's aggregate
    accounting as well as this module's fixed single-artifact accounting.
    """
    def checkpoint(self) -> None: ...
    def verify_binding(self) -> None: ...
    def read_at(self, offset: int, count: int) -> bytes: ...

@dataclass(frozen=True, slots=True)
class Pin:
    label: str
    size: int
    sha256: str

@dataclass(frozen=True, slots=True)
class OpaqueZipPin:
    """An inert inner ZIP, never a seventh supplier/profile nomination."""
    size: int
    sha256: str

class MemberObserver(Protocol):
    """Bounded synchronous DATA callbacks; no callback grants publication.

    Rows are immutable scalar tuples in COLUMNS order, not mutable Members.
    begin/block/end are called for every file, including empty files. end is
    reached only after the original length/CRC/hash checks. An exception in any
    callback poisons the entire pass, including already-observed members.
    """
    def begin(self, row: tuple) -> None: ...
    def block(self, name: str, offset: int, data: bytes) -> None: ...
    def end(self, row: tuple) -> None: ...

class InspectionWorkspace(Protocol):
    """One inspector's aggregate charges; not interpreter-memory telemetry."""
    def reserve_rows(self, count: int) -> None: ...
    def release_rows(self, count: int) -> None: ...
    def charge_read(self, count: int) -> None: ...
    def charge_expanded(self, count: int) -> None: ...

@dataclass(slots=True)
class Member:
    name: str
    kind: str
    mode: int
    size: int
    sha256: str | None = None
    target: str | None = None
    local: int | None = None
    data: int | None = None
    compressed: int | None = None
    method: int | None = None
    flags: int | None = None
    crc: int | None = None
    creator: int | None = None
    hint: str | None = None
    # Internal raw name is needed only until local/CD agreement is complete.
    raw_name: bytes | None = None
    # Info-ZIP original UNIX common timestamp DATA; never filesystem policy.
    old_unix: bytes | None = None
    def row(self):
        return (self.name, self.kind, self.mode, self.size, self.sha256,
                self.target, self.local, self.data, self.compressed,
                self.method, self.flags, self.crc, self.creator, self.hint)

def _fail(reason):
    raise Refused(reason)

def _integer(value):
    return type(value) is int and value >= 0

def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

def _name(raw: bytes, directory=False):
    # This grammar is archive-only. '$' is ordinary Java class-name DATA.
    # Installed path policy remains unchanged and no name is extracted here.
    if directory and raw.endswith(b"/"):
        raw = raw[:-1]
    if not raw or len(raw) > 512 or any(c > 127 for c in raw):
        _fail("archive_name_bytes")
    parts = raw.split(b"/")
    if len(parts) > 16 or any(not p or len(p) > 255 or p in (b".", b"..")
        or p[-1:] in (b".", b" ") or any(not (48 <= c <= 57 or 65 <= c <= 90
        or 97 <= c <= 122 or c in b"_+@.,= $-") for c in p) for p in parts):
        _fail("archive_name_grammar")
    return raw.decode("ascii")

def _opaque_name(raw: bytes, directory=False):
    # Java resources stay inside the original ZIP as exact case-sensitive DATA.
    # They are never converted to installed/APFS names, normalized or extracted.
    if directory and raw.endswith(b"/"):
        raw = raw[:-1]
    if not raw or len(raw) > 512 or b"\0" in raw or b"\\" in raw:
        _fail("opaque_zip_name_bytes")
    try:
        name = raw.decode("utf-8", "strict")
    except UnicodeError:
        _fail("opaque_zip_name_utf8")
    parts = name.split("/")
    # An opaque directory may have one extra terminal marker (raw ends "//").
    # Validate that component only; preserve name, including its remaining
    # slash, for exact duplicate and non-directory-parent checks. Never rstrip.
    validation_parts = parts[:-1] if directory and parts[-1] == "" else parts
    if len(parts) > 16 or any(not p or p in (".", "..") or
                             len(p.encode("utf-8")) > 255 for p in validation_parts):
        _fail("opaque_zip_name_structure")
    return name

def _target(name: str, raw: bytes):
    if not raw or len(raw) > 512 or raw.startswith(b"/"):
        _fail("archive_alias_target")
    try:
        target = raw.decode("ascii")
    except UnicodeError:
        _fail("archive_alias_target")
    parts = name.split("/")[:-1]
    for component in raw.split(b"/"):
        if component == b"..":
            if not parts:
                _fail("archive_alias_escape")
            parts.pop()
        elif component == b".":
            continue
        else:
            parts.append(_name(component))
    if not parts or parts[0] != name.split("/")[0]:
        _fail("archive_alias_bundle")
    return target, "/".join(parts)

def _hint(prefix: bytes):
    if prefix.startswith(b"#!"):
        return "shell"
    if prefix[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "macho"
    if prefix[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        # Java class files also begin CAFEBABE. A hint is NOT native proof.
        return "fat-macho-or-java-class"
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix.startswith(b"MZ"):
        return "pe"
    if prefix.startswith(b"PK\x03\x04"):
        return "zip"
    if prefix.startswith(b"JM\x01\x00"):
        return "jmod"
    return None

class _Pass:
    def __init__(self, original: Original, pin: Pin | OpaqueZipPin,
                 observer: MemberObserver | None = None,
                 workspace: InspectionWorkspace | None = None):
        self.opaque = type(pin) is OpaqueZipPin
        if (type(pin) is not Pin and not self.opaque) \
            or type(pin) is Pin and pin.label not in LABELS or not _integer(pin.size) \
            or not 0 < pin.size <= (64 * 1024 * 1024 if self.opaque else ARCHIVE_LIMIT) \
            or not _sha(pin.sha256):
            _fail("archive_pin")
        self.original = original
        self.pin = pin
        self.observer = observer
        self.workspace = workspace
        self.issued = 0
        self.roster = 0
        self.expanded = 0
        self.files = 0
        self.aliases = 0
        self.headers = 0
        self.rows: list[Member] = []
        self.names: set[str] = set()
        self.failed = False
    def notify(self, operation, *values):
        if self.observer is None:
            return
        self.check()
        try:
            getattr(self.observer, operation)(*values)
            self.check()
        except BaseException:
            self.failed = True
            raise
    def discard_rows(self):
        # Release only this pass's heap reservation after dropping its row/set
        # references. This does NOT close an original or recover a failed pass.
        self.rows.clear()
        self.names.clear()
        held = self.roster
        self.roster = 0
        if self.workspace is not None:
            self.workspace.release_rows(held)
    def discard_failed_rows(self):
        # Keep the first original failure even if heap-accounting cleanup also
        # refuses. The pass remains irreversibly failed; no report is returned.
        self.failed = True
        try:
            self.discard_rows()
        except BaseException:
            pass
    def check(self):
        if self.failed:
            _fail("capture_already_failed")
        try:
            self.original.checkpoint()
        except BaseException:
            self.failed = True
            raise
    def binding(self):
        self.check()
        try:
            self.original.verify_binding()
        except BaseException:
            self.failed = True
            raise
        self.check()
    def read(self, at: int, count: int):
        self.check()
        if not _integer(at) or not _integer(count) or count > WINDOW \
            or at + count > self.pin.size or self.issued + count > ISSUED_READ_LIMIT:
            self.failed = True
            _fail("issued_read_bound")
        self.issued += count  # Requested bytes are charged BEFORE a possible failure.
        try:
            if self.workspace is not None:
                self.workspace.charge_read(count)
            data = self.original.read_at(at, count)
            self.check()
            if type(data) is not bytes or len(data) != count:
                _fail("short_or_invalid_original_read")
            return data
        except BaseException:
            self.failed = True
            raise
    def region(self, at, count):
        if not _integer(count) or count > WINDOW + 22:
            _fail("header_window_bound")
        out = bytearray()
        while len(out) < count:
            out.extend(self.read(at + len(out), min(WINDOW, count - len(out))))
        return bytes(out)
    def authenticate(self):
        self.binding()
        hash_ = hashlib.sha256()
        for at in range(0, self.pin.size, WINDOW):
            hash_.update(self.read(at, min(WINDOW, self.pin.size - at)))
        if hash_.hexdigest() != self.pin.sha256:
            _fail("original_archive_sha256")
        self.binding()
    def header(self):
        self.check()
        self.headers += 1
        if self.headers > ENTRY_LIMIT:
            _fail("entry_header_bound")
    def name_key(self, name: str):
        # This one sealed JAR stays ONE file. Its Java member names are not
        # projected onto a case-insensitive installed filesystem.
        return name if self.opaque or self.pin.label == "bundletool" else name.lower()
    def member_name(self, raw, directory=False):
        return (_opaque_name if self.opaque else _name)(raw, directory=directory)
    def append(self, member: Member):
        self.check()
        # Charged before set/list/row retention, includes allocator headroom,
        # case key, raw name, sort index and every bounded row object.
        charge = 1536 + 8 * len(member.name) + 8 * len(member.target or "")
        if self.roster + charge > ROSTER_LIMIT or len(self.rows) >= ENTRY_LIMIT:
            _fail("roster_workspace_bound")
        key = self.name_key(member.name)
        if key in self.names:
            _fail("duplicate_or_case_colliding_member")
        if self.workspace is not None:
            self.workspace.reserve_rows(charge)
        self.roster += charge
        self.names.add(key)
        if member.kind == "file":
            self.files += 1
            self.expanded += member.size
            if self.opaque and self.workspace is not None:
                self.workspace.charge_expanded(member.size)
        elif member.kind == "alias":
            self.aliases += 1
        if self.files > FILE_COUNT or self.aliases > ALIAS_COUNT or self.expanded > EXPANDED_LIMIT:
            _fail("expanded_member_bound")
        self.rows.append(member)
    def finish(self):
        self.check()
        # Directory and file/alias namespace may not collide or traverse a file.
        self.rows.sort(key=lambda member: self.name_key(member.name))
        exact = {row.name: row for row in self.rows}
        previous = []
        for row in self.rows:
            self.check()
            if not self.opaque and self.pin.label != "bundletool":
                # Implicit parents need the same spelling too. Equal folded
                # prefixes are contiguous after sorting; adjacent rows witness
                # every spelling change without retaining a directory tree.
                parts = row.name.split("/")
                for before, current in zip(previous, parts):
                    if before.lower() != current.lower():
                        break
                    if before != current:
                        _fail("case_colliding_member_parent")
                previous = parts
            path = row.name
            while "/" in path:
                path = path.rsplit("/", 1)[0]
                if path in exact and exact[path].kind != "directory":
                    _fail("non_directory_member_parent")
                if self.name_key(path) in self.names and path not in exact:
                    _fail("case_colliding_member_parent")
            if row.kind == "alias":
                _, target = _target(row.name, (row.target or "").encode("ascii"))
                if target not in exact or exact[target].kind != "file":
                    _fail("alias_not_same_archive_regular_file")
            row.raw_name = None
            row.old_unix = None
        self.binding()
        return Correspondence(self)

class Correspondence:
    """A live comparison report, NOT a supplier/admission authority.

    publish() performs bounded deterministic publication while the original
    endpoint/binding is still live. The owner must not close it first. Any
    publication failure latches; a failed/partial report cannot be retried as
    success. Actual durable output custody/cleanup remains the sink owner's job.
    """
    def __init__(self, capture: _Pass):
        self._capture = capture
        self._published = False
    def consume_rows(self, sink: Callable[[tuple], None]):
        """One terminal, source-bound DATA visit without a second row book.

        The verified Member book is drained in its original sorted order.
        Heap-reference handoff is not file/original finality; the same binding
        and endpoint remain required through the last callback and POST.
        """
        p = self._capture
        if self._published or p.failed:
            _fail("report_finality")
        # Claim terminal consumption before binding or callback reentry. This
        # flag does not assert successful external publication or authority.
        self._published = True
        originally_failed = False
        try:
            p.binding()
            summary = {"entryHeaders": p.headers, "members": len(p.rows),
                       "files": p.files, "aliases": p.aliases,
                       "expandedBytes": p.expanded, "issuedReadBytes": p.issued,
                       "rosterReservationBytes": p.roster}
            # Complete raw/CD/local, payload and namespace validation already
            # finished. No namespace index or second list is needed to drain.
            p.names.clear()
            p.rows.reverse()
            while p.rows:
                p.check()
                member = p.rows.pop()
                charge = 1536 + 8 * len(member.name) + 8 * len(member.target or "")
                row = member.row()
                del member
                if charge > p.roster:
                    _fail("terminal_row_reservation")
                p.roster -= charge
                if p.workspace is not None:
                    p.workspace.release_rows(charge)
                # Only this one converted tuple and residual container
                # capacity use the existing8MiB scratch allowance here. The
                # sink must charge any retained copy before retaining it.
                sink(row)
                del row
                p.check()
            if p.roster != 0:
                _fail("terminal_row_reservation")
            p.binding()
            return summary
        except BaseException:
            p.failed = True
            originally_failed = True
            raise
        finally:
            if originally_failed:
                p.discard_failed_rows()
            else:
                p.discard_rows()
    def _chunks(self):
        p = self._capture
        encoder = json.JSONEncoder(ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        head = {"schemaVersion": 1, "kind": "offline-opaque-zip-correspondence-data" if p.opaque
                else "offline-official-archive-correspondence-data",
                "label": None if p.opaque else p.pin.label, "archiveBytes": p.pin.size,
                "archiveSha256": p.pin.sha256, "completeMemberHashes": True,
                "supplierAuthority": False, "nativeClosure": False,
                "entryHeaders": p.headers, "members": len(p.rows),
                "files": p.files, "aliases": p.aliases, "expandedBytes": p.expanded,
                "columns": COLUMNS}
        head_json = encoder.encode(head)
        yield head_json[:-1].encode("ascii") + b',"rows":['
        for index, row in enumerate(p.rows):
            p.check()
            if index:
                yield b","
            for fragment in encoder.iterencode(row.row()):
                yield fragment.encode("ascii")
        yield b"]}\n"
    def publish(self, sink: Callable[[bytes], None]):
        p = self._capture
        if self._published or p.failed:
            _fail("report_finality")
        try:
            p.binding()
            count = 0
            expected = hashlib.sha256()
            for chunk in self._chunks():
                count += len(chunk)
                if count > OUTPUT_LIMIT:
                    _fail("output_bound")
                expected.update(chunk)
            if p.roster + 2 * count + SCRATCH_RESERVATION > WORKSPACE_LIMIT:
                _fail("publication_workspace_bound")
            # One exact-size bytearray plus the immutable publication copy are
            # both charged above; no manifest-sized dict/list clone is built.
            output = bytearray(count)
            at = 0
            actual = hashlib.sha256()
            for chunk in self._chunks():
                if at + len(chunk) > count:
                    _fail("output_second_pass_size")
                output[at:at + len(chunk)] = chunk
                at += len(chunk)
                actual.update(chunk)
            if at != count or actual.digest() != expected.digest():
                _fail("output_second_pass_drift")
            p.binding()
            immutable = bytes(output)
            del output
            sink(immutable)
            p.binding()
            self._published = True
            # A DATA publication receipt only. Original close/join is external.
            return {"bytes": count, "sha256": actual.hexdigest(),
                    "issuedReadBytes": p.issued, "rosterReservationBytes": p.roster}
        except BaseException:
            p.failed = True
            raise


def _extra(raw, *, local=False):
    at = 0
    seen = set()
    old_unix = None
    while at < len(raw):
        if at + 4 > len(raw):
            _fail("zip_extra_truncated")
        tag, size = struct.unpack_from("<HH", raw, at)
        at += 4
        if tag not in ZIP_EXTRA or tag in seen or at + size > len(raw):
            _fail("zip_extra_unsupported_or_ambiguous")
        seen.add(tag)
        if tag == 0x5855:
            # Info-ZIP old UNIX: common atime/mtime, local-only uid/gid.
            # Exact structure is DATA; no owner/time/mode is ever applied.
            if size != (12 if local else 8):
                _fail("zip_old_unix_size")
            old_unix = raw[at:at + 8]
        at += size
    return old_unix

def _zip_directory(p: _Pass):
    n = min(p.pin.size, 22 + 65535)
    tail = p.region(p.pin.size - n, n)
    candidates = []
    at = len(tail) - 22
    while at >= 0:
        at = tail.rfind(b"PK\x05\x06", 0, at + 4)
        if at < 0:
            break
        if at + 22 <= len(tail):
            fields = struct.unpack_from("<4s4H2IH", tail, at)
            if at + 22 + fields[-1] == len(tail):
                candidates.append((p.pin.size - n + at, fields))
                if len(candidates) > 1:
                    _fail("zip_ambiguous_end")
        at -= 1
    if len(candidates) != 1:
        _fail("zip_end_record")
    end_at, (_, disk, cd_disk, disk_count, count, cd_size, cd_at, _) = candidates[0]
    if disk != 0 or cd_disk != 0 or count != disk_count or not 0 < count <= ENTRY_LIMIT \
        or count == 65535 or cd_size == 0xFFFFFFFF or cd_at == 0xFFFFFFFF \
        or not 46 * count <= cd_size <= CENTRAL_LIMIT or cd_at + cd_size != end_at:
        _fail("zip_directory_extent_or_multidisk_zip64")
    offset = cd_at
    for _ in range(count):
        p.header()
        fixed = p.read(offset, 46)
        if fixed[:4] != b"PK\x01\x02":
            _fail("zip_central_signature")
        (_, made, needed, flags, method, _time, _date, crc, compressed, size,
         name_len, extra_len, comment_len, member_disk, _internal, external,
         local) = struct.unpack("<4s6H3I5H2I", fixed)
        variable = name_len + extra_len + comment_len
        if needed > 20 or flags & ~ZIP_FLAGS or method not in (0, 8) \
            or method == 0 and flags & 6 or member_disk != 0 \
            or not 0 < name_len <= 513 or 46 + variable > WINDOW \
            or offset + 46 + variable > cd_at + cd_size \
            or size == 0xFFFFFFFF or compressed == 0xFFFFFFFF or local == 0xFFFFFFFF \
            or size > FILE_LIMIT or local + 30 > cd_at \
            or compressed > p.pin.size or method == 0 and compressed != size:
            _fail("zip_central_member_bounds")
        variable_bytes = p.read(offset + 46, variable)
        raw_name = variable_bytes[:name_len]
        old_unix = _extra(variable_bytes[name_len:name_len + extra_len])
        creator = made >> 8
        mode = external >> 16
        if creator not in (0, 3) or mode & ~0o170777:
            _fail("zip_member_mode_or_creator")
        file_type = mode & 0o170000
        directory = raw_name.endswith(b"/")
        if file_type not in (0, 0o040000, 0o100000) \
            or file_type == 0o040000 and not directory \
            or file_type == 0o100000 and directory or external & 0x10 and not directory \
            or directory and size != 0:
            _fail("zip_non_regular_member")
        name = p.member_name(raw_name, directory=directory)
        row = Member(name, "directory" if directory else "file", mode, size,
                     local=local, compressed=compressed, method=method,
                     flags=flags, crc=crc, creator=creator, raw_name=raw_name,
                     old_unix=old_unix)
        p.append(row)
        offset += 46 + variable
    if offset != cd_at + cd_size:
        _fail("zip_central_count_mismatch")
    return cd_at

def _zip_payload(p: _Pass, row: Member):
    if row.data is None or row.compressed is None:
        _fail("zip_internal_extent")
    hash_ = hashlib.sha256()
    crc = 0
    expanded = 0
    prefix = bytearray()
    if row.kind == "file":
        p.notify("begin", row.row())
    def consume(block):
        nonlocal crc, expanded
        if len(block) > WINDOW or expanded + len(block) > row.size:
            _fail("zip_expansion_size")
        start = expanded
        expanded += len(block)
        hash_.update(block)
        crc = zlib.crc32(block, crc)
        if len(prefix) < 16:
            prefix.extend(block[:16 - len(prefix)])
        if row.kind == "file":
            p.notify("block", row.name, start, block)
    if row.method == 0:
        for at in range(0, row.compressed, WINDOW):
            consume(p.read(row.data + at, min(WINDOW, row.compressed - at)))
    else:
        decoder = zlib.decompressobj(-15)
        for at in range(0, row.compressed, WINDOW):
            pending = p.read(row.data + at, min(WINDOW, row.compressed - at))
            read_end = at + len(pending)
            while pending:
                p.check()
                before = len(pending)
                block = decoder.decompress(pending, WINDOW)
                pending = decoder.unconsumed_tail
                consume(block)
                if decoder.unused_data or decoder.eof and (pending or read_end != row.compressed):
                    _fail("zip_deflate_trailing_data")
                if not block and len(pending) == before:
                    _fail("zip_deflate_no_progress")
        # Do not use unbounded flush(): drain only fixed-size internal output.
        while not decoder.eof:
            p.check()
            block = decoder.decompress(b"", WINDOW)
            if not block:
                _fail("zip_deflate_incomplete")
            consume(block)
        if decoder.unused_data or decoder.unconsumed_tail:
            _fail("zip_deflate_extent")
    if expanded != row.size or crc & 0xFFFFFFFF != row.crc:
        _fail("zip_member_crc_or_length")
    if row.kind == "file":
        row.sha256 = hash_.hexdigest()
        row.hint = _hint(prefix)
        p.notify("end", row.row())

def _zip(p: _Pass):
    cd_at = _zip_directory(p)
    # Directory metadata was bounded before list growth. No ZipFile constructor,
    # infolist() allocation, extraction or native execution is used.
    ordered = sorted(p.rows, key=lambda row: row.local)
    expected = 0
    for index, row in enumerate(ordered):
        p.check()
        if row.local != expected:
            _fail("zip_overlap_gap_or_sfx")
        fixed = p.read(row.local, 30)
        if fixed[:4] != b"PK\x03\x04":
            _fail("zip_local_signature")
        (_, needed, flags, method, _time, _date, crc, compressed,
         size, name_len, extra_len) = struct.unpack("<4s5H3I2H", fixed)
        if needed > 20 or flags != row.flags or method != row.method \
            or not 0 < name_len <= 513 or 30 + name_len + extra_len > WINDOW:
            _fail("zip_local_central_disagreement")
        variable = p.read(row.local + 30, name_len + extra_len)
        if variable[:name_len] != row.raw_name:
            _fail("zip_local_name_disagreement")
        if _extra(variable[name_len:], local=True) != row.old_unix:
            _fail("zip_old_unix_local_central_disagreement")
        data = row.local + 30 + name_len + extra_len
        end = data + row.compressed
        next_at = ordered[index + 1].local if index + 1 < len(ordered) else cd_at
        if end > next_at:
            _fail("zip_overlapping_payload")
        if row.flags & 8:
            if (crc, compressed, size) not in ((0, 0, 0), (row.crc, row.compressed, row.size)):
                _fail("zip_descriptor_local_disagreement")
            length = next_at - end
            if length not in (12, 16):
                _fail("zip_descriptor_extent")
            descriptor = p.read(end, length)
            if length == 16:
                if descriptor[:4] != b"PK\x07\x08":
                    _fail("zip_descriptor_signature")
                descriptor = descriptor[4:]
            if struct.unpack("<3I", descriptor) != (row.crc, row.compressed, row.size):
                _fail("zip_descriptor_disagreement")
        elif (crc, compressed, size) != (row.crc, row.compressed, row.size) or end != next_at:
            _fail("zip_local_sizes_or_extent")
        row.data = data
        expected = next_at
    if expected != cd_at:
        _fail("zip_local_directory_extent")
    # Every header/extent has been checked before decoding any member payload.
    for row in ordered:
        _zip_payload(p, row)


def _gzip_header(p: _Pass):
    if p.pin.size < 18:
        _fail("gzip_length")
    header = p.read(0, 10)
    if header[:3] != b"\x1f\x8b\x08" or header[3] & 0xE0:
        _fail("gzip_header")
    flags = header[3]
    at = 10
    if flags & 4:
        size = struct.unpack("<H", p.read(at, 2))[0]
        at += 2
        if size > 4096:
            _fail("gzip_extra_bound")
        p.read(at, size)
        at += size
    for flag in (8, 16):
        if flags & flag:
            # Bounded optional original name/comment; never a filesystem path.
            for _ in range(513):
                value = p.read(at, 1)
                at += 1
                if value == b"\0":
                    break
            else:
                _fail("gzip_text_bound")
    if flags & 2:
        p.read(at, 2)  # zlib's wrapper validates header CRC along with trailer.
        at += 2
    if at + 8 > p.pin.size:
        _fail("gzip_header_extent")

class _Gzip:
    def __init__(self, p: _Pass):
        _gzip_header(p)
        self.p = p
        self.decoder = zlib.decompressobj(31)
        self.at = 0
        self.pending = b""
        self.expanded = 0
        self.done = False
        self.buffer = b""
    def pull(self):
        if self.done:
            return b""
        while True:
            self.p.check()
            if not self.pending and self.at < self.p.pin.size:
                count = min(WINDOW, self.p.pin.size - self.at)
                self.pending = self.p.read(self.at, count)
                self.at += count
            before = len(self.pending)
            block = self.decoder.decompress(self.pending, WINDOW)
            self.pending = self.decoder.unconsumed_tail
            self.expanded += len(block)
            if self.expanded > TAR_STREAM_LIMIT:
                _fail("tar_stream_expansion_bound")
            if self.decoder.unused_data:
                _fail("gzip_concatenation_or_trailing_data")
            if self.decoder.eof:
                if self.pending or self.at != self.p.pin.size:
                    _fail("gzip_extent")
                self.done = True
            if block or self.done:
                return block
            if len(self.pending) == before and (before != 0 or self.at == self.p.pin.size):
                _fail("gzip_incomplete_or_no_progress")
    def take(self, count):
        if not _integer(count) or count > WINDOW:
            _fail("tar_read_window")
        while len(self.buffer) < count:
            block = self.pull()
            if not block:
                _fail("tar_truncated")
            self.buffer += block
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result
    def payload(self, count):
        while count:
            value = self.take(min(WINDOW, count))
            count -= len(value)
            yield value
    def padding(self, size):
        if size % 512 and any(self.take(512 - size % 512)):
            _fail("tar_nonzero_padding")
    def trailer(self):
        # Two all-zero end blocks have already been consumed.
        count = 1024
        while True:
            if self.buffer:
                chunk, self.buffer = self.buffer, b""
            else:
                chunk = self.pull()
            if not chunk:
                break
            count += len(chunk)
            if count > 10240 or any(chunk):
                _fail("tar_trailing_data")
        if count % 512 or not self.done:
            _fail("tar_termination")

def _octal(raw, what):
    if not raw or raw[0] & 0x80:
        _fail("tar_base256_or_sparse_" + what)
    text = raw.strip(b" \0")
    if not text:
        return 0
    if any(c < 48 or c > 55 for c in text):
        _fail("tar_numeric_" + what)
    return int(text, 8)

def _cstring(raw, what):
    name, sep, rest = raw.partition(b"\0")
    if sep and any(rest):
        _fail("tar_nonzero_string_padding_" + what)
    return name

def _pax(raw):
    if not 0 < len(raw) <= WINDOW:
        _fail("pax_bound")
    values = {}
    at = 0
    allowed = (b"path", b"linkpath", b"size", b"mtime", b"atime", b"ctime")
    while at < len(raw):
        space = raw.find(b" ", at, min(len(raw), at + 12))
        if space < 0:
            _fail("pax_record_length")
        length_raw = raw[at:space]
        if not length_raw or length_raw.startswith(b"0") or not length_raw.isdigit():
            _fail("pax_record_length")
        length = int(length_raw)
        if length <= space - at + 3 or at + length > len(raw) or raw[at + length - 1] != 10:
            _fail("pax_record_extent")
        key, sep, value = raw[space + 1:at + length - 1].partition(b"=")
        if not sep or key not in allowed or key in values or b"\0" in value or b"\n" in value:
            _fail("pax_unknown_duplicate_or_invalid_key")
        if key in (b"path", b"linkpath"):
            if not 0 < len(value) <= 512:
                _fail("pax_path_bound")
        elif key == b"size":
            if not value or len(value) > 12 or not value.isdigit() or int(value) > FILE_LIMIT:
                _fail("pax_size_bound")
        elif len(value) > 64 or re.fullmatch(rb"-?[0-9]+(?:\.[0-9]+)?", value) is None:
            _fail("pax_time_value")
        values[key] = value
        at += length
    return values

def _tar(p: _Pass):
    stream = _Gzip(p)
    pax = None
    dialect = None
    while True:
        p.check()
        header = stream.take(512)
        if not any(header):
            if pax is not None or any(stream.take(512)):
                _fail("tar_end_or_orphan_pax")
            stream.trailer()
            break
        p.header()
        expected = _octal(header[148:156], "checksum")
        actual = sum(header[:148]) + 8 * 32 + sum(header[156:])
        magic = header[257:265]
        gnu = magic == b"ustar  \0"
        if actual != expected or magic not in (b"ustar\0" + b"00", b"ustar  \0") \
            or any(header[500:512]):
            _fail("tar_header_checksum_or_ustar")
        if dialect is not None and dialect != magic:
            _fail("tar_mixed_header_dialect")
        dialect = magic
        type_ = header[156:157]
        # The actual JDK has only unextended GNU regular/directory records.
        # GNU bytes345..499 are NOT the POSIX path-prefix field.
        if gnu and (any(header[345:500]) or type_ not in (b"0", b"5")):
            _fail("tar_gnu_extension_or_type")
        name = _cstring(header[:100], "name")
        if not gnu:
            prefix = _cstring(header[345:500], "prefix")
            if prefix:
                name = prefix + b"/" + name
        mode = _octal(header[100:108], "mode")
        uid = _octal(header[108:116], "uid")
        gid = _octal(header[116:124], "gid")
        size = _octal(header[124:136], "size")
        _octal(header[136:148], "mtime")
        archival_sgid_directory = gnu and type_ == b"5" and mode == 0o2755
        if (mode & ~0o777 and not archival_sgid_directory) or uid > 0xFFFFFFFF or gid > 0xFFFFFFFF \
            or size > FILE_LIMIT or _octal(header[329:337], "device") != 0 \
            or _octal(header[337:345], "device") != 0:
            _fail("tar_mode_size_or_device")
        link = _cstring(header[157:257], "link")
        if type_ == b"x":
            if pax is not None or link or not 0 < size <= WINDOW:
                _fail("pax_header_bound")
            # This fixed PAX control label is not an installed member name.
            if name != b"././@PaxHeader":
                _name(name)
            pax = _pax(stream.take(size))
            stream.padding(size)
            continue
        if type_ not in (b"\0", b"0", b"2", b"5"):
            _fail("tar_unsupported_type")
        if pax is not None:
            name = pax.get(b"path", name)
            link = pax.get(b"linkpath", link)
            size = int(pax[b"size"]) if b"size" in pax else size
            pax = None
        kind = "directory" if type_ == b"5" else "alias" if type_ == b"2" else "file"
        name_text = _name(name, directory=kind == "directory")
        if kind != "file" and size != 0 or kind != "alias" and link:
            _fail("tar_type_payload")
        target = None
        if kind == "alias":
            target, _ = _target(name_text, link)
        type_mode = {"directory": 0o040000, "alias": 0o120000, "file": 0o100000}[kind]
        row = Member(name_text, kind, type_mode | mode, size, target=target)
        p.append(row)
        if kind == "file":
            digest = hashlib.sha256()
            prefix = bytearray()
            p.notify("begin", row.row())
            position = 0
            for block in stream.payload(size):
                p.check()
                digest.update(block)
                if len(prefix) < 16:
                    prefix.extend(block[:16 - len(prefix)])
                p.notify("block", row.name, position, block)
                position += len(block)
            row.sha256 = digest.hexdigest()
            row.hint = _hint(prefix)
            p.notify("end", row.row())
        stream.padding(size)
    if not p.rows:
        _fail("empty_tar")

def compile_archive(original: Original, pin: Pin, *,
                    observer: MemberObserver | None = None,
                    workspace: InspectionWorkspace | None = None) -> Correspondence:
    """Compare one complete, already-nominated original, without extracting it.

    The JDK is one gzip/POSIX-USTAR or observed unextended GNU-tar stream.
    GNU special bits remain archive-only directory DATA. Other six-profile
    components are classic nonencrypted Stored/Deflate ZIPs. Unknown encodings
    refuse explicitly rather than being guessed or silently truncated.
    """
    if type(pin) is not Pin:
        _fail("archive_pin")
    p = _Pass(original, pin, observer, workspace)
    try:
        p.authenticate()
        if pin.label == "jdk":
            _tar(p)
        else:
            _zip(p)
        return p.finish()
    except (zlib.error, struct.error) as error:
        p.discard_failed_rows()
        raise Refused("archive_codec_or_structure") from error
    except BaseException:
        p.discard_failed_rows()
        raise

def compile_opaque_zip(original: Original, pin: OpaqueZipPin, *,
                       observer: MemberObserver | None = None,
                       workspace: InspectionWorkspace | None = None) -> Correspondence:
    """Inspect one already-bounded JVM ZIP view as DATA, never a supplier.

    The caller authenticates a JMOD's complete preamble/member and supplies the
    exact ZIP view, if applicable. This parser never searches for a guessed
    prefix or weakens local/central/CRC/Deflate completeness requirements.
    """
    if type(pin) is not OpaqueZipPin:
        _fail("opaque_zip_pin")
    p = _Pass(original, pin, observer, workspace)
    try:
        p.authenticate()
        _zip(p)
        return p.finish()
    except (zlib.error, struct.error) as error:
        p.discard_failed_rows()
        raise Refused("archive_codec_or_structure") from error
    except BaseException:
        p.discard_failed_rows()
        raise
