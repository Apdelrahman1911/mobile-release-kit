"""Bounded Mach-O correspondence, not a code-signature authenticity verifier.

UUIDs are labels. Signable slices additionally bind every byte except a strictly
bounded trailing signature and its bookkeeping. The caller must still verify
the final Apple signature and authenticate the complete artifact's SHA-256.
"""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import uuid
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

from .errors import ValidationError
from .inspection import InspectionDeadline

MAX_BINARY_SIZE = 1024 * 1024 * 1024
MAX_COMMAND_BYTES = 8 * 1024 * 1024
MAX_PADDING = 16 * 1024 * 1024
MAX_SIGNATURE = 16 * 1024 * 1024
MAX_DATA_IN_CODE_RECORDS = 1_000_000
TABLE_CHUNK_BYTES = 64 * 1024
THIN = {b"\xce\xfa\xed\xfe": ("<", False), b"\xfe\xed\xfa\xce": (">", False),
        b"\xcf\xfa\xed\xfe": ("<", True), b"\xfe\xed\xfa\xcf": (">", True)}
FAT = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
       b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}
MACHO_MAGICS = frozenset(THIN) | frozenset(FAT)
LINKEDIT_DATA = {0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x36, 0x37, 0x38, 0x3A, 0x80000033, 0x80000034}
DYLIB_COMMANDS = {0xC, 0xD, 0x20, 0x80000018, 0x8000001F, 0x80000023}
STRING_COMMANDS = {0xE, 0xF, 0x8000001C, 0x39}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(f"Mach-O {message}")


def _aligned(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass(frozen=True)
class MachOSlice:
    cpu: int
    subtype: int
    uuid: str
    file_type: int
    image_sha256: str | None

    @property
    def key(self) -> tuple[int, int, str]:
        return self.cpu, self.subtype, self.uuid


class _Reader:
    def __init__(self, fd: int, base: int, size: int, deadline: InspectionDeadline):
        self.fd, self.base, self.size = fd, base, size
        self.deadline = deadline

    def read(self, offset: int, size: int) -> bytes:
        self.deadline.check()
        _require(0 <= offset <= self.size and 0 <= size <= self.size - offset, "range exceeds its slice")
        _require(size <= MAX_PADDING, "inspection allocation exceeds its bound")
        value = os.pread(self.fd, size, self.base + offset)
        _require(len(value) == size, "file changed or is truncated")
        return value

    def zero(self, begin: int, end: int, *, maximum: int = MAX_PADDING) -> None:
        _require(0 <= end - begin <= maximum, "padding exceeds its bound")
        for offset in range(begin, end, 1024 * 1024):
            _require(not any(self.read(offset, min(1024 * 1024, end - offset))), "contains nonzero unaccounted padding")

    def hash_range(self, digest: object, begin: int, end: int) -> None:
        _require(0 <= begin <= end <= self.size, "hash range exceeds its slice")
        for offset in range(begin, end, 1024 * 1024):
            digest.update(self.read(offset, min(1024 * 1024, end - offset)))


def _name(raw: bytes) -> str:
    value, _, padding = raw.partition(b"\0")
    _require(bool(value) and not any(padding) and all(32 < byte < 127 for byte in value), "segment/section name is invalid")
    return value.decode("ascii")


def _signature(reader: _Reader, offset: int, size: int) -> None:
    _require(12 <= size <= MAX_SIGNATURE, "signature exceeds its structural bound")
    data = reader.read(offset, size)
    magic, length, count = struct.unpack_from(">3I", data)
    _require(magic == 0xFADE0CC0 and 0 < count <= 512 and 12 + count * 8 <= length <= size,
             "signature SuperBlob is malformed")
    seen: set[int] = set()
    spans = []
    directory = False
    for index in range(count):
        reader.deadline.check()
        kind, start = struct.unpack_from(">2I", data, 12 + index * 8)
        _require(kind not in seen and 12 + count * 8 <= start <= length - 8, "signature index is invalid or duplicated")
        seen.add(kind)
        blob_magic, blob_size = struct.unpack_from(">2I", data, start)
        _require(8 <= blob_size <= length - start, "signature blob is out of bounds")
        spans.append((start, start + blob_size))
        if kind == 0 or 0x1000 <= kind < 0x1006:
            _require(blob_magic == 0xFADE0C02 and blob_size >= 44, "CodeDirectory is missing or malformed")
            version, _flags, hash_offset, ident_offset, special, slots, limit = struct.unpack_from(">7I", data, start + 8)
            minimum = next((bound for threshold, bound in ((0x20600, 108), (0x20500, 96), (0x20400, 88), (0x20300, 64), (0x20200, 52), (0x20100, 48)) if version >= threshold), 44)
            _require(0x20000 <= version <= 0x20600 and blob_size >= minimum, "CodeDirectory version/size is unsupported")
            hash_size, hash_type, _platform, page = struct.unpack_from("4B", data, start + 36)
            _require(limit == offset and 0 < hash_size <= 64 and hash_type in {1, 2, 3, 4, 5} and page <= 30,
                     "CodeDirectory does not bind the complete non-signature image")
            expected_slots = (limit + (1 << page) - 1) // (1 << page) if page else 1
            _require(slots == expected_slots and minimum <= ident_offset < blob_size and
                     minimum + special * hash_size <= hash_offset and hash_offset + slots * hash_size <= blob_size,
                     "CodeDirectory hash/string ranges are invalid")
            _require(b"\0" in data[start + ident_offset:start + blob_size], "CodeDirectory identifier is unterminated")
            if version >= 0x20300:
                limit64 = struct.unpack_from(">Q", data, start + 56)[0]
                _require(limit64 in {0, limit}, "CodeDirectory extended limit disagrees")
            directory |= kind == 0
    _require(directory, "signature lacks a primary CodeDirectory")
    cursor = 12 + count * 8
    for begin, end in sorted(spans):
        _require(begin >= cursor and not any(data[cursor:begin]), "signature blobs overlap or hide unindexed data")
        cursor = end
    _require(not any(data[cursor:length]), "signature has nonzero unindexed envelope data")
    # codesign can leave old signature bytes after a shrinking SuperBlob. Only
    # this bounded allocation slack is excluded, not gaps within the envelope.
    # It lies beyond every declared image/data range. Native codesign need not
    # authenticate slack; the intent's exact whole-artifact hash still binds it.


def _thin(reader: _Reader, *, dsym: bool) -> MachOSlice:
    magic = reader.read(0, 4)
    _require(magic in THIN, "slice is not a supported thin image")
    endian, wide = THIN[magic]
    header_size = 32 if wide else 28
    header = list(struct.unpack(endian + ("8I" if wide else "7I"), reader.read(0, header_size)))
    _magic, cpu, subtype, file_type, count, command_size, _flags = header[:7]
    _require(file_type == 10 if dsym else file_type in {2, 6, 8}, "file type is not a dSYM" if dsym else "file type is not a signable executable, dylib or bundle")
    _require(0 < count <= 4096 and count * 8 <= command_size <= MAX_COMMAND_BYTES and
             header_size + command_size <= reader.size, "load-command bounds are invalid")
    commands = reader.read(header_size, command_size)
    position = 0
    normalized = []
    segments = []
    sections = []
    data_ranges = []
    link_ranges = []
    uuids = []
    signature = None
    symtab = None
    dysymtab = None
    data_in_code = None
    entrypoint = None
    singleton: set[int] = set()

    def extent(offset: int, size: int, *, link: bool = False) -> None:
        _require(0 <= offset <= reader.size and 0 <= size <= reader.size - offset, "referenced file data is out of bounds")
        if size:
            _require(offset >= header_size + command_size, "data reference overlaps load commands")
            (link_ranges if link else data_ranges).append((offset, offset + size))

    for _ in range(count):
        reader.deadline.check()
        _require(position + 8 <= len(commands), "load command is truncated")
        cmd, size = struct.unpack_from(endian + "2I", commands, position)
        _require(size >= 8 and size % (8 if wide else 4) == 0 and position + size <= len(commands), "load command size/alignment is invalid")
        body = bytearray(commands[position:position + size])

        def exact(expected: int) -> None:
            _require(size == expected, "load command has an invalid fixed size")

        def unique() -> None:
            _require(cmd not in singleton, "singleton load command is duplicated")
            singleton.add(cmd)

        if cmd in {1, 0x19}:
            _require((cmd == 0x19) == wide, "segment width disagrees with the header")
            base, section_size = (72, 80) if wide else (56, 68)
            _require(size >= base, "segment is truncated")
            values = struct.unpack_from(endian + ("II16sQQQQIIII" if wide else "II16s8I"), body)
            name = _name(values[2])
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = values[3:]
            _require(nsects <= 4096 and size == base + nsects * section_size and
                     fileoff <= reader.size and filesize <= reader.size - fileoff and
                     vmaddr + vmsize < 1 << (64 if wide else 32) and initprot & ~maxprot == 0 and
                     maxprot & ~7 == 0, "segment bounds, sections or protections are invalid")
            segments.append((name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot))
            if name == "__LINKEDIT" and not dsym:
                _require(nsects == 0 and flags == 0, "signable __LINKEDIT must not contain sections or flags")
                struct.pack_into(endian + ("Q" if wide else "I"), body, 32 if wide else 28, 0)
                struct.pack_into(endian + ("Q" if wide else "I"), body, 48 if wide else 36, 0)
            for index in range(nsects):
                if index % 256 == 0:
                    reader.deadline.check()
                part = struct.unpack_from(endian + ("16s16sQQ8I" if wide else "16s16s9I"), body, base + index * section_size)
                section_name, parent = _name(part[0]), _name(part[1])
                address, length, offset, alignment, relocation, relocations, section_flags = part[2:9]
                _require(parent == name and alignment <= 30, "section owner/alignment is invalid")
                # dsymutil preserves original virtual __TEXT/__DATA sections with
                # no backed bytes; only __DWARF/actual file-backed sections count.
                virtual_only = dsym and filesize == 0
                zero_fill = section_flags & 0xFF in {1, 0xC, 0x12}
                if not dsym or not virtual_only:
                    _require(vmaddr <= address <= vmaddr + vmsize and length <= vmaddr + vmsize - address,
                             "section virtual range is outside its segment")
                if length and not zero_fill and not virtual_only:
                    _require(fileoff <= offset <= fileoff + filesize and length <= fileoff + filesize - offset and
                             offset % (1 << alignment) == 0, "section file range is outside its segment")
                    extent(offset, length)
                    sections.append((name, section_name, offset, offset + length))
                extent(relocation, relocations * 8, link=True)
        elif cmd == 0x1B:
            unique(); exact(24)
            value = bytes(body[8:24])
            _require(any(value), "UUID must not be zero")
            uuids.append(str(uuid.UUID(bytes=value)))
        elif cmd == 2:
            unique(); exact(24)
            symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "4I", body, 8)
            extent(symoff, nsyms * (16 if wide else 12), link=True)
            extent(stroff, strsize, link=True)
            symtab = nsyms
        elif cmd == 0xB:
            unique(); exact(80)
            values = struct.unpack_from(endian + "18I", body, 8)
            dysymtab = values[:6]
            for index, unit in ((6, 8), (8, 56 if wide else 52), (10, 4), (12, 4), (14, 8), (16, 8)):
                extent(values[index], values[index + 1] * unit, link=True)
        elif cmd in {0x22, 0x80000022}:
            _require(not ({0x22, 0x80000022} & singleton), "dyld-info command is duplicated")
            unique(); exact(48)
            values = struct.unpack_from(endian + "10I", body, 8)
            for index in range(0, 10, 2):
                extent(values[index], values[index + 1], link=True)
        elif cmd in LINKEDIT_DATA or cmd == 0x1D:
            unique(); exact(16)
            offset, length = struct.unpack_from(endian + "2I", body, 8)
            if cmd == 0x1D:
                _require(not dsym and length > 0, "dSYM must not have a code signature")
                _require(offset <= reader.size and length == reader.size - offset, "signature is not the trailing slice data")
                signature = (offset, length)
            else:
                extent(offset, length, link=True)
                if cmd == 0x29:
                    _require(length % 8 == 0 and length // 8 <= MAX_DATA_IN_CODE_RECORDS,
                             "data-in-code table size/record count exceeds its bound")
                    data_in_code = (offset, length)
        elif cmd in {0x21, 0x2C}:
            unique(); exact(24 if cmd == 0x2C else 20)
            offset, length, encrypted = struct.unpack_from(endian + "3I", body, 8)
            _require(encrypted == 0 and (cmd != 0x2C or struct.unpack_from(endian + "I", body, 20)[0] == 0), "encrypted or malformed pre-Store image is unsupported")
            extent(offset, length)
        elif cmd == 0x80000028:
            unique(); exact(24)
            entrypoint = struct.unpack_from(endian + "Q", body, 8)[0]
        elif cmd == 0x31:
            exact(40)
            offset, length = struct.unpack_from(endian + "2Q", body, 24)
            extent(offset, length)
        elif cmd in DYLIB_COMMANDS or cmd in STRING_COMMANDS:
            minimum = 24 if cmd in DYLIB_COMMANDS else 12
            _require(size >= minimum, "string command is truncated")
            offset = struct.unpack_from(endian + "I", body, 8)[0]
            _require(minimum <= offset < size and b"\0" in body[offset:], "string command lacks a bounded terminator")
        elif cmd in {0x24, 0x25, 0x2F, 0x30, 0x2A}:
            unique(); exact(16)
        elif cmd == 0x32:
            unique()
            _require(size >= 24, "build-version command is truncated")
            tools = struct.unpack_from(endian + "I", body, 20)[0]
            _require(tools <= 64 and size == 24 + tools * 8, "build-version tools are out of bounds")
        elif cmd == 0x2D:
            _require(size >= 12, "linker-option command is truncated")
            strings = struct.unpack_from(endian + "I", body, 8)[0]
            _require(strings <= 1024, "linker-option count is excessive")
            tail = bytes(body[12:])
            for _index in range(strings):
                _require(b"\0" in tail, "linker option is unterminated")
                _value, _separator, tail = tail.partition(b"\0")
            _require(not any(tail), "linker options contain unaccounted data")
        else:
            raise ValidationError(f"Mach-O load command 0x{cmd:x} is unsupported for exact artifact correspondence")
        if cmd != 0x1D:
            normalized.append(bytes(body))
        position += size
    _require(position == command_size and len(uuids) == 1, "commands or UUID inventory are incomplete")
    names = [segment[0] for segment in segments]
    _require(len(names) == len(set(names)), "segment name is duplicated")
    backed = sorted((item[3], item[3] + item[4], item[0]) for item in segments if item[4])
    _require(all(backed[index][1] <= backed[index + 1][0] for index in range(len(backed) - 1)), "file-backed segments overlap")
    virtual = sorted((item[1], item[1] + item[2]) for item in segments if item[2])
    if not dsym:
        _require(all(virtual[index][1] <= virtual[index + 1][0] for index in range(len(virtual) - 1)), "virtual segments overlap")
    ordered_sections = sorted((item[2], item[3]) for item in sections)
    _require(all(ordered_sections[index][1] <= ordered_sections[index + 1][0] for index in range(len(ordered_sections) - 1)), "file-backed sections overlap")
    if dysymtab is not None:
        _require(symtab is not None and all(dysymtab[index] + dysymtab[index + 1] <= symtab for index in (0, 2, 4)), "dynamic symbol indices exceed the symbol table")
    linkedit = next((item for item in segments if item[0] == "__LINKEDIT"), None)
    if link_ranges:
        _require(linkedit is not None and all(linkedit[3] <= begin < end <= linkedit[3] + linkedit[4] for begin, end in link_ranges), "linkedit reference is outside __LINKEDIT")
    if data_in_code:
        # Sections have already been proved non-overlapping. Index them once:
        # attacker-controlled table and section counts must not multiply work.
        code_sections = sorted((start, end) for name, _section, start, end in sections if name == "__TEXT")
        starts = [start for start, _end in code_sections]
        table_end = sum(data_in_code)
        for offset in range(data_in_code[0], table_end, TABLE_CHUNK_BYTES):
            data = reader.read(offset, min(TABLE_CHUNK_BYTES, table_end - offset))
            for begin, length, kind in struct.iter_unpack(endian + "IHH", data):
                index = bisect_right(starts, begin) - 1
                _require(kind in {1, 2, 3, 4, 5} and length > 0 and index >= 0 and
                         begin + length <= code_sections[index][1], "data-in-code entry is outside a code section")
        reader.deadline.check()
    if dsym:
        _require(signature is None and any(name == "__DWARF" and section.startswith("__debug_") for name, section, _start, _end in sections), "dSYM has no backed DWARF sections")
        reader.deadline.check()
        return MachOSlice(cpu, subtype, uuids[0], file_type, None)

    _require(linkedit is not None and linkedit[5:7] == (1, 1), "signable image needs a read-only __LINKEDIT segment")
    _name_value, _vmaddr, vmsize, fileoff, filesize, _maxprot, _initprot = linkedit
    _require(fileoff + filesize == reader.size and vmsize in {filesize, _aligned(filesize, 4096), _aligned(filesize, 16384)}, "__LINKEDIT extent is not the bounded signature-dependent extent")
    other_ends = [item[3] + item[4] for item in segments if item[0] != "__LINKEDIT" and item[4]]
    _require(other_ends and max(other_ends) <= fileoff, "__LINKEDIT overlaps signable file data")
    text = next((item for item in segments if item[0] == "__TEXT"), None)
    _require(text is not None and text[3] == 0 and text[4] >= header_size + command_size and text[6] & 4,
             "signable image lacks a header-owning executable __TEXT segment")
    _require(sections, "signable image lacks file-backed sections")
    content_start = min(item[2] for item in sections)
    _require(header_size + command_size <= content_start <= text[4], "header padding overlaps code data")
    reader.zero(header_size + command_size, content_start)
    content_end = max([fileoff, *other_ends, *(end for _begin, end in data_ranges), *(end for _begin, end in link_ranges)])
    boundary = _aligned(content_end, 16)
    if signature:
        _require(signature[0] == boundary and signature[0] >= fileoff, "signature start is not the bound end of all non-signature data")
        reader.zero(content_end, boundary, maximum=15)
        _signature(reader, *signature)
    else:
        _require(content_end <= reader.size <= boundary, "unsigned image hides unreferenced trailing data")
        reader.zero(content_end, reader.size, maximum=15)
    if entrypoint is not None:
        _require(any(name == "__TEXT" and begin <= entrypoint < end for name, _section, begin, end in sections), "entry point is not inside a __TEXT section")
    header[4], header[5] = len(normalized), sum(map(len, normalized))
    digest = hashlib.sha256(b"mrk-macho-image-v1\0")
    digest.update(struct.pack(endian + ("8I" if wide else "7I"), *header))
    for command in normalized:
        digest.update(command)
    digest.update(struct.pack(">QQ", content_start, boundary))
    reader.hash_range(digest, content_start, content_end)
    digest.update(b"\0" * (boundary - content_end))
    reader.deadline.check()
    return MachOSlice(cpu, subtype, uuids[0], file_type, digest.hexdigest())


def inspect_macho(path: Path, *, dsym: bool = False,
                  deadline: InspectionDeadline | None = None) -> tuple[MachOSlice, ...]:
    """Inspect private immutable snapshot bytes without loading executable code."""
    deadline = deadline if deadline is not None else InspectionDeadline()
    deadline.check()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            attributes = os.fstat(fd)
            _require(stat.S_ISREG(attributes.st_mode) and 0 < attributes.st_size <= MAX_BINARY_SIZE, "input is not a bounded regular file")
            reader = _Reader(fd, 0, attributes.st_size, deadline)
            magic = reader.read(0, 4)
            if magic in THIN:
                return (_thin(reader, dsym=dsym),)
            _require(magic in FAT, "input is not a supported thin/fat image")
            endian, wide = FAT[magic]
            count = struct.unpack(endian + "I", reader.read(4, 4))[0]
            _require(0 < count <= 32, "fat slice count is invalid")
            entry_size = 32 if wide else 20
            entries = []
            cpus: set[tuple[int, int]] = set()
            for index in range(count):
                values = struct.unpack(endian + ("IIQQII" if wide else "5I"), reader.read(8 + index * entry_size, entry_size))
                cpu, subtype, offset, size, alignment = values[:5]
                _require((not wide or values[5] == 0) and (cpu, subtype) not in cpus and alignment <= 24 and
                         offset >= 8 + count * entry_size and offset % (1 << alignment) == 0 and
                         28 <= size <= reader.size - offset, "fat slice declaration is invalid or duplicated")
                cpus.add((cpu, subtype))
                entries.append((offset, size, cpu, subtype))
            cursor = 8 + count * entry_size
            result = []
            for offset, size, cpu, subtype in sorted(entries):
                _require(offset >= cursor, "fat slices overlap")
                reader.zero(cursor, offset)
                value = _thin(_Reader(fd, offset, size, deadline), dsym=dsym)
                _require((value.cpu, value.subtype) == (cpu, subtype), "fat and thin CPU identity disagree")
                result.append(value)
                cursor = offset + size
            reader.zero(cursor, reader.size)
            return tuple(sorted(result, key=lambda item: (item.cpu, item.subtype)))
        finally:
            os.close(fd)
    except (OSError, struct.error, OverflowError) as error:
        raise ValidationError("Mach-O input could not be inspected safely") from error
