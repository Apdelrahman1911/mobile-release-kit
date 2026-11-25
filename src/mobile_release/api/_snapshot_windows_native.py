"""Private, synchronous Windows snapshot adapter; not a general native service.

No ctypes/DLL loading at import. Acquisition is NtCreateFile with one original
RootDirectory and OBJ_DONT_REPARSE, never a full child path or file-ID reopen.
Sharing does NOT exclude attribute-only reparse/case mutation. This source is
not native qualification; the public dispatcher remains disabled.

Constants/declarations cross-checked as data against microsoft/win32metadata
5c5efbc01d4c87f6830ec304d42777991d533154: shared/{ntdef,ntstatus,winerror}.h,
um/{winternl,winnt,minwinbase,WinBase,libloaderapi}.h. See the documented
NtCreateFile, OBJECT_ATTRIBUTES and IO_STATUS_BLOCK contracts on Microsoft Learn.
"""
from __future__ import annotations

import os
import re
import struct
import sys
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Callable, NoReturn

BUFFER_BYTES = 64 * 1024
MAPPING_UNITS = 4096
NAME_UNITS = 8192
MAX_HANDLES = 144
INVALID_HANDLE = (1 << 64) - 1
OBJ_DONT_REPARSE = 0x1000
DIRECTORY_ACCESS = 0x001000A1
FILE_ACCESS = 0x00100081
DIRECTORY_OPTIONS = 0x21
FILE_OPTIONS = 0x60
FILE_OPEN = FILE_OPENED = FILE_SHARE_READ = 1
STATUS_SUCCESS = 0
STATUS_PENDING = 0x103
STATUS_NAME_NOT_FOUND = 0xC0000034
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B
ERROR_IO_PENDING = 997
ERROR_NO_MORE_FILES = 18
DIRECTORY_ATTRIBUTE = 0x10
REPARSE_ATTRIBUTE = 0x400
# Device/virtual/resident-offline/recall entries are outside this profile.
UNSUPPORTED_ATTRIBUTES = 0x40 | 0x10000 | 0x1000 | 0x40000 | 0x400000
_DEVICE = re.compile(r"\\Device\\HarddiskVolume[0-9]{1,10}\Z", re.ASCII)
_RESERVED = frozenset({"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"} | {
    prefix + digit for prefix in ("COM", "LPT") for digit in "123456789¹²³"
})


class NativeUnavailable(RuntimeError):
    """The binding/profile is unavailable before project IO starts."""


class NativeError(OSError):
    """Only a closed internal category, never native error/path text."""

    def __init__(self, category: str = "unavailable"):
        self.category = category
        super().__init__("Windows static observation could not be completed safely")


class NativeCleanupError(RuntimeError):
    """No result is permitted after an unproven original-handle close."""


class _UnsettledNativeCall(BaseException):
    """Only reachable if a substituted nonreturning fail-stop returns."""


def valid_component(name: object) -> bool:
    if type(name) is not str or name in {"", ".", ".."}:
        return False
    try:
        return (len(name.encode("utf-8")) <= 255 and len(name.encode("utf-16-le")) <= 510
                and not any(ord(c) < 32 or ord(c) == 127 or c in '<>:"/\\|?*' for c in name)
                and not name.endswith((".", " "))
                and name.split(".", 1)[0].rstrip(" ").upper() not in _RESERVED)
    except UnicodeError:
        return False


def parse_drive_mapping(raw: bytes) -> str:
    if (type(raw) is not bytes or not 4 <= len(raw) <= 2 * MAPPING_UNITS
            or len(raw) % 2 or not raw.endswith(b"\0\0\0\0")):
        raise NativeError("unsupported")
    try:
        parts = raw.decode("utf-16-le", errors="strict").split("\0")
    except UnicodeError:
        raise NativeError("unsupported") from None
    if len(parts) < 3 or parts[-2:] != ["", ""] or any(not x for x in parts[:-2]):
        raise NativeError("unsupported")
    if _DEVICE.fullmatch(parts[0]) is None:
        raise NativeError("unsupported")
    return parts[0]  # Later MULTI_SZ entries are historical, never another open.


@dataclass(frozen=True)
class OpenSpec:
    parent: int | None
    name: str
    directory: bool
    access: int
    options: int
    attributes: int = OBJ_DONT_REPARSE
    sharing: int = FILE_SHARE_READ
    disposition: int = FILE_OPEN


def open_spec(parent: int | None, name: str, directory: bool) -> OpenSpec:
    if type(directory) is not bool or type(name) is not str:
        raise NativeError("unsafe")
    if parent is None:
        if not directory or not name.endswith("\\") or _DEVICE.fullmatch(name[:-1]) is None:
            raise NativeError("unsafe")
    elif (type(parent) is not int or not 0 < parent < INVALID_HANDLE or not valid_component(name)):
        raise NativeError("unsafe")
    return OpenSpec(parent, name, directory, DIRECTORY_ACCESS if directory else FILE_ACCESS,
                    DIRECTORY_OPTIONS if directory else FILE_OPTIONS)


def _nt_category(status: int) -> str:
    if status == STATUS_NAME_NOT_FOUND:
        return "missing"
    if status in {STATUS_REPARSE_POINT_ENCOUNTERED, 0xC0000103, 0xC00000BA}:
        return "unsafe"
    if status in {0xC000000D, 0xC0000003, 0xC0000010, 0xC00000BB}:
        return "unsupported"
    # PATH_NOT_FOUND, access/share/delete errors, and every other completed
    # error are NOT proof that a configuration is missing.
    return "unavailable"


def _nt_outcome(status: int, handle: int | None, io_status: int, information: int) -> str:
    if type(status) is not int or not -(1 << 31) <= status <= 0xFFFFFFFF:
        return "unknown"
    status &= 0xFFFFFFFF
    if (status == STATUS_SUCCESS and type(io_status) is int and io_status == 0
            and type(information) is int and information == FILE_OPENED
            and type(handle) is int and 0 < handle < INVALID_HANDLE):
        return "opened"
    if status >> 30 == 3 and handle is None:
        return _nt_category(status)  # Non-PENDING return, not stale IOSB, is authoritative.
    return "unknown"  # Never NT_SUCCESS(PENDING), warning, or contradictory output.


@dataclass(frozen=True)
class Metadata:
    attributes: int
    volume: int
    file_id: bytes
    directory: bool
    delete_pending: bool
    links: int
    size: int
    creation: int
    write: int
    change: int
    case_flags: int | None
    reparse_tag: int | None = None


@dataclass(frozen=True)
class Entry:
    name: str
    attributes: int
    file_id: bytes
    reparse_tag: int | None

    @property
    def directory(self) -> bool:
        return bool(self.attributes & DIRECTORY_ATTRIBUTE)


def decode_directory_batch(raw: bytes) -> tuple[Entry, ...]:
    """Validate the whole bounded buffer chain before publishing any entry.

    GetFileInformationByHandleEx supplies no bytes-returned value. Fresh zeroed
    storage and the documented complete record chain are required. FileIndex
    is undefined on NTFS; ReparsePointTag is undefined for ordinary entries.
    """
    if type(raw) is not bytes or not 90 <= len(raw) <= BUFFER_BYTES:
        raise NativeError("unsupported")
    offset = 0
    result: list[Entry] = []
    while True:
        if offset % 8 or offset + 88 > len(raw):
            raise NativeError("unsupported")
        advance = struct.unpack_from("<I", raw, offset)[0]
        attributes, length = struct.unpack_from("<II", raw, offset + 56)
        if not length or length % 2 or length > 510:
            raise NativeError("unsupported")
        end = offset + 88 + length
        if end > len(raw) or (advance and (advance % 8 or advance < 88 + length or offset + advance >= len(raw))):
            raise NativeError("unsupported")
        try:
            name = raw[offset + 88:end].decode("utf-16-le", errors="strict")
        except UnicodeError:
            raise NativeError("unsupported") from None
        if "\0" in name:
            raise NativeError("unsupported")
        tag = struct.unpack_from("<I", raw, offset + 68)[0] if attributes & REPARSE_ATTRIBUTE else None
        result.append(Entry(name, attributes, raw[offset + 72:offset + 88], tag))
        if not advance:
            return tuple(result)
        offset += advance


# Size/alignment and named offsets are checked before any DLL call. This is a
# finite binding contract, not an architecture emulation or ABI qualification.
_ABI = {
    "Unicode": (16, 8, {"Length": 0, "MaximumLength": 2, "Buffer": 8}),
    "Attributes": (48, 8, {"Length": 0, "RootDirectory": 8, "ObjectName": 16,
                           "Attributes": 24, "SecurityDescriptor": 32, "SecurityQualityOfService": 40}),
    "IO": (16, 8, {"Result": 0, "Information": 8}),
    "Result": (8, 8, {"Status": 0, "Pointer": 0}),
    "Basic": (40, 8, {"CreationTime": 0, "LastAccessTime": 8, "LastWriteTime": 16,
                       "ChangeTime": 24, "FileAttributes": 32}),
    "Standard": (24, 8, {"AllocationSize": 0, "EndOfFile": 8, "NumberOfLinks": 16,
                          "DeletePending": 20, "Directory": 21}),
    "Tag": (8, 4, {"FileAttributes": 0, "ReparseTag": 4}),
    "Id": (24, 8, {"VolumeSerialNumber": 0, "FileId": 8}),
    "Case": (4, 4, {"Flags": 0}),
    "Directory": (96, 8, {"NextEntryOffset": 0, "FileIndex": 4, "CreationTime": 8,
                           "LastAccessTime": 16, "LastWriteTime": 24, "ChangeTime": 32,
                           "EndOfFile": 40, "AllocationSize": 48, "FileAttributes": 56,
                           "FileNameLength": 60, "EaSize": 64, "ReparsePointTag": 68,
                           "FileId": 72, "FileName": 88}),
}


def _check_abi(actual: dict) -> None:
    if actual != _ABI:
        raise NativeUnavailable("Windows snapshot ABI is not admitted")


def _load_bindings() -> SimpleNamespace:
    if sys.platform != "win32" or os.name != "nt":
        raise NativeUnavailable("Windows snapshot platform is not admitted")
    try:
        import ctypes as c

        U32, U16, I64, HANDLE = c.c_uint32, c.c_uint16, c.c_int64, c.c_void_p
        if tuple(c.sizeof(t) for t in (HANDLE, c.c_wchar, c.c_int32, I64, U32, U16,
                                       c.c_uint8, c.c_uint64)) != (8, 2, 4, 8, 4, 2, 1, 8):
            raise NativeUnavailable("Windows snapshot scalar ABI is not admitted")
        class Unicode(c.Structure):
            _fields_ = [("Length", U16), ("MaximumLength", U16), ("Buffer", c.c_void_p)]
        class Attributes(c.Structure):
            _fields_ = [("Length", U32), ("RootDirectory", HANDLE), ("ObjectName", c.POINTER(Unicode)),
                        ("Attributes", U32), ("SecurityDescriptor", c.c_void_p), ("SecurityQualityOfService", c.c_void_p)]
        class Result(c.Union):
            _fields_ = [("Status", c.c_int32), ("Pointer", c.c_void_p)]
        class IO(c.Structure):
            _fields_ = [("Result", Result), ("Information", c.c_uint64)]
        class Basic(c.Structure):
            _fields_ = [("CreationTime", I64), ("LastAccessTime", I64), ("LastWriteTime", I64),
                        ("ChangeTime", I64), ("FileAttributes", U32)]
        class Standard(c.Structure):
            _fields_ = [("AllocationSize", I64), ("EndOfFile", I64), ("NumberOfLinks", U32),
                        ("DeletePending", c.c_uint8), ("Directory", c.c_uint8)]
        class Tag(c.Structure):
            _fields_ = [("FileAttributes", U32), ("ReparseTag", U32)]
        class Id(c.Structure):
            _fields_ = [("VolumeSerialNumber", c.c_uint64), ("FileId", c.c_uint8 * 16)]
        class Case(c.Structure):
            _fields_ = [("Flags", U32)]
        class Directory(c.Structure):
            _fields_ = [("NextEntryOffset", U32), ("FileIndex", U32), ("CreationTime", I64),
                        ("LastAccessTime", I64), ("LastWriteTime", I64), ("ChangeTime", I64),
                        ("EndOfFile", I64), ("AllocationSize", I64), ("FileAttributes", U32),
                        ("FileNameLength", U32), ("EaSize", U32), ("ReparsePointTag", U32),
                        ("FileId", c.c_uint8 * 16), ("FileName", c.c_wchar * 1)]
        classes = {item.__name__: item for item in (Unicode, Attributes, IO, Result, Basic, Standard, Tag, Id, Case, Directory)}
        _check_abi({name: (c.sizeof(cls), c.alignment(cls), {field: getattr(cls, field).offset for field in _ABI[name][2]})
                    for name, cls in classes.items()})
        k = c.WinDLL("kernel32.dll", winmode=0x800, use_last_error=True)
        nt = c.WinDLL("ntdll.dll", winmode=0x800, use_last_error=True)
        void, boolean, wchar = c.c_void_p, c.c_int32, c.c_wchar_p
        signatures = {
            "GetCurrentProcess": ([], HANDLE),
            "IsWow64Process2": ([HANDLE, c.POINTER(U16), c.POINTER(U16)], boolean),
            "QueryDosDeviceW": ([wchar, c.POINTER(c.c_wchar), U32], U32),
            "GetHandleInformation": ([HANDLE, c.POINTER(U32)], boolean),
            "GetFileType": ([HANDLE], U32),
            "GetFileInformationByHandleEx": ([HANDLE, c.c_int32, void, U32], boolean),
            "GetVolumeInformationByHandleW": ([HANDLE, c.POINTER(c.c_wchar), U32, c.POINTER(U32),
                                                c.POINTER(U32), c.POINTER(U32), c.POINTER(c.c_wchar), U32], boolean),
            "GetFinalPathNameByHandleW": ([HANDLE, c.POINTER(c.c_wchar), U32, U32], U32),
            "ReadFile": ([HANDLE, void, U32, c.POINTER(U32), void], boolean),
            "CloseHandle": ([HANDLE], boolean),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(k, name)
            function.argtypes, function.restype = arguments, result
        nt.NtCreateFile.argtypes = [c.POINTER(HANDLE), U32, c.POINTER(Attributes), c.POINTER(IO),
                                    c.POINTER(I64), U32, U32, U32, U32, void, U32]
        nt.NtCreateFile.restype = c.c_int32
        return SimpleNamespace(c=c, k=k, nt=nt, U32=U32, U16=U16, HANDLE=HANDLE, **classes)
    except (ImportError, AttributeError, OSError, ValueError):
        raise NativeUnavailable("Windows snapshot binding is unavailable") from None


class _HandleOwner:
    """One request, original numeric handles, sole-close and fail-stop discipline."""

    def __init__(self) -> None:
        self._owned: list[int] = []
        self._cleanup_failed = False
        self._poisoned = False
        self._pinned: object = None
        self._entered: object = None
        self._exit = os._exit

    def _abort(self, arena: object) -> NoReturn:
        self._poisoned = True
        self._pinned = arena
        # No ordinary exception unwind on real pending/unknown completion. The
        # caller frame/arena and original parents stay live until process exit.
        self._exit(70)
        raise _UnsettledNativeCall("Native completion did not settle")

    def _capacity(self) -> None:
        if self._poisoned:
            raise _UnsettledNativeCall("Native completion did not settle")
        if self._entered is not None:
            self._abort(self._entered)
        if len(self._owned) >= MAX_HANDLES:
            raise NativeError("limit")

    def _require_owned(self, handle: int) -> None:
        if self._poisoned:
            raise _UnsettledNativeCall("Native completion did not settle")
        if self._entered is not None:
            self._abort(self._entered)
        if type(handle) is not int or handle not in self._owned:
            raise NativeError("unsafe")

    def _finish_open(self, status: int, handle: int | None, io_status: int,
                     information: int, arena: object) -> int:
        if self._poisoned:
            raise _UnsettledNativeCall("Native completion did not settle")
        if self._entered is not None and self._entered is not arena:
            self._abort(self._entered)
        # _invoke already holds this arena before native entry. Also retain it
        # for the direct inert classifier seam; never replace an entered call.
        self._entered = arena
        try:
            outcome = _nt_outcome(status, handle, io_status, information)
            if outcome == "unknown":
                self._abort(arena)
            if outcome != "opened":
                self._entered = None  # Authoritative completed error, NULL output.
                raise NativeError(outcome)
            if handle in self._owned:
                self._abort(arena)
            self._owned.append(handle)
            self._entered = None  # Completion AND original-handle ownership proven.
        except BaseException:
            if not self._poisoned and self._entered is not None:
                self._abort(self._entered)
            raise
        return handle

    def _raw_close(self, handle: int) -> bool:
        raise NotImplementedError

    def close(self, handle: int) -> None:
        if self._poisoned:
            return  # Only reached by inert substituted fail-stop unwinding.
        if self._entered is not None:
            self._abort(self._entered)  # No cleanup across an unclassified return.
        if type(handle) is not int or handle not in self._owned:
            self._cleanup_failed = True
            raise NativeCleanupError("Windows snapshot handle ownership did not settle")
        self._owned.remove(handle)  # Retire BEFORE the one native close attempt.
        try:
            if not self._raw_close(handle):
                self._cleanup_failed = True
        except BaseException:
            self._cleanup_failed = True
        if self._cleanup_failed:
            raise NativeCleanupError("Windows snapshot handle cleanup did not settle")

    def close_all(self) -> None:
        if self._poisoned:
            return
        if self._entered is not None:
            self._abort(self._entered)
        while self._owned:
            try:
                self.close(self._owned[-1])
            except NativeCleanupError:
                pass
        if self._cleanup_failed:
            raise NativeCleanupError("Windows snapshot handle cleanup did not settle")


class Native(_HandleOwner):
    def __init__(self, check_budget: Callable[[], None]) -> None:
        super().__init__()
        self._check_budget = check_budget  # Private shared inventory, never caller/project input.
        self._check_budget()
        self._b = _load_bindings()
        b = self._b
        process = self._invoke(b.k.GetCurrentProcess, ())
        machine, native = b.U16(0xFFFF), b.U16(0xFFFF)
        self._boolean(b.k.IsWow64Process2, (process, b.c.byref(machine), b.c.byref(native)), (machine, native))
        if machine.value != 0 or native.value != 0x8664:
            raise NativeUnavailable("Windows snapshot architecture is not admitted")

    def _invoke(self, function: object, arguments: tuple, keep: tuple = (), *, completion: str = "scalar") -> object:
        if self._poisoned:
            raise _UnsettledNativeCall("Native completion did not settle")
        if self._entered is not None:
            self._abort(self._entered)
        if completion not in {"scalar", "boolean", "count", "directory", "open"}:
            raise NativeError("unsafe")
        # This may unwind only BEFORE entry. In particular, do not consult a
        # deadline after an entered call until its completion has been classified.
        self._check_budget()
        arena = (self, self._b, tuple(self._owned), arguments, keep, function)
        # Establish the self-held root BEFORE entry. Abort/cleanup after a lost
        # return must not allocate or reconstruct an arena to preserve it.
        self._entered = arena
        try:
            value = function(*arguments)
            error = self._b.c.get_last_error()
            if completion == "open":
                output, io = keep[-2:]
                value = self._finish_open(value, output.value, io.Result.Status, io.Information, arena)
            elif completion != "scalar":
                if not value:
                    if completion == "directory" and error == ERROR_NO_MORE_FILES:
                        value = None  # Only this known completed error is EOF.
                    else:
                        self._win_failure(error, arena)
                elif completion == "directory":
                    value = True
            # Scalar-only APIs are GetCurrentProcess/GetFileType, which expose
            # no asynchronous completion/output ownership. All other families
            # classify under this guard; an open is registered before release.
            self._entered = None
        except BaseException:
            if not self._poisoned and self._entered is not None:
                self._abort(self._entered)
            raise
        return value  # Classified data only; never a raw status/arena handoff.

    def _boolean(self, function: object, arguments: tuple, keep: tuple = ()) -> None:
        self._invoke(function, arguments, keep, completion="boolean")

    def _win_failure(self, error: int, arena: object) -> NoReturn:
        if error == ERROR_IO_PENDING:
            self._abort(arena)
        category = "unsupported" if error in {1, 50, 87, 120, 124} else "unavailable"
        self._entered = None  # Known completed failure; ordinary cleanup is safe.
        raise NativeError(category)

    def drive_mapping(self, drive: str) -> str:
        if re.fullmatch(r"[A-Za-z]:", drive, re.ASCII) is None:
            raise NativeError("unsafe")
        b = self._b
        buffer = b.c.create_unicode_buffer(MAPPING_UNITS)
        count = self._invoke(b.k.QueryDosDeviceW, (drive, buffer, MAPPING_UNITS), (buffer,), completion="count")
        if not 2 <= count <= MAPPING_UNITS:
            raise NativeError("unsupported")
        return parse_drive_mapping(b.c.string_at(b.c.addressof(buffer), count * 2))

    def open_root(self, device: str) -> int:
        return self._open(open_spec(None, device + "\\", True))

    def open_child(self, parent: int, name: str, directory: bool) -> int:
        self._require_owned(parent)
        return self._open(open_spec(parent, name, directory))

    def _open(self, spec: OpenSpec) -> int:
        self._capacity()
        b = self._b
        encoded = spec.name.encode("utf-16-le", errors="strict")
        if len(encoded) > 65532:
            raise NativeError("unsafe")
        name_buffer = (b.U16 * (len(encoded) // 2 + 1)).from_buffer_copy(encoded + b"\0\0")
        name = b.Unicode(len(encoded), len(encoded) + 2, b.c.addressof(name_buffer))
        attributes = b.Attributes(b.c.sizeof(b.Attributes), spec.parent, b.c.pointer(name), spec.attributes, None, None)
        output, io = b.HANDLE(), b.IO()
        io.Result.Status, io.Information = STATUS_PENDING, INVALID_HANDLE
        arguments = (b.c.byref(output), spec.access, b.c.byref(attributes), b.c.byref(io),
                     None, 0, spec.sharing, spec.disposition, spec.options, None, 0)
        handle = self._invoke(b.nt.NtCreateFile, arguments, (spec, name_buffer, name, attributes, output, io),
                              completion="open")
        try:
            flags = b.U32(0xFFFFFFFF)
            self._boolean(b.k.GetHandleInformation, (handle, b.c.byref(flags)), (flags,))
            if flags.value & 1:
                raise NativeError("unsafe")
        except NativeError:
            self.close(handle)
            raise
        return handle

    def _info(self, handle: int, information_class: int, cls: object) -> object:
        self._require_owned(handle)
        b = self._b
        value = cls()
        self._boolean(b.k.GetFileInformationByHandleEx,
                      (handle, information_class, b.c.byref(value), b.c.sizeof(value)), (value,))
        return value

    def metadata(self, handle: int) -> Metadata:
        self._require_owned(handle)
        b = self._b
        file_type = self._invoke(b.k.GetFileType, (handle,))
        if file_type != 1:
            raise NativeError("unsafe")
        basic = self._info(handle, 0, b.Basic)
        standard = self._info(handle, 1, b.Standard)
        tag = self._info(handle, 9, b.Tag)
        identity = self._info(handle, 18, b.Id)
        if (basic.FileAttributes != tag.FileAttributes or standard.Directory not in (0, 1)
                or standard.DeletePending not in (0, 1)
                or bool(standard.Directory) != bool(tag.FileAttributes & DIRECTORY_ATTRIBUTE)):
            raise NativeError("changed")
        case = self._info(handle, 23, b.Case).Flags if standard.Directory else None
        return Metadata(tag.FileAttributes, identity.VolumeSerialNumber, bytes(identity.FileId),
                        bool(standard.Directory), bool(standard.DeletePending), standard.NumberOfLinks,
                        standard.EndOfFile, basic.CreationTime, basic.LastWriteTime, basic.ChangeTime,
                        case, tag.ReparseTag if tag.FileAttributes & REPARSE_ATTRIBUTE else None)

    def require_ntfs(self, handle: int) -> None:
        self._require_owned(handle)
        b = self._b
        name = b.c.create_unicode_buffer(261)
        self._boolean(b.k.GetVolumeInformationByHandleW,
                      (handle, None, 0, None, None, None, name, 261), (name,))
        if name.value != "NTFS":
            raise NativeError("unsupported")

    def normalized_name(self, handle: int) -> str:
        self._require_owned(handle)
        b = self._b
        buffer = b.c.create_unicode_buffer(NAME_UNITS)
        count = self._invoke(b.k.GetFinalPathNameByHandleW, (handle, buffer, NAME_UNITS, 2), (buffer,), completion="count")
        if not 0 < count < NAME_UNITS or buffer[count] != "\0":
            raise NativeError("unsafe")
        try:
            value = b.c.string_at(b.c.addressof(buffer), count * 2).decode("utf-16-le", errors="strict")
        except UnicodeError:
            raise NativeError("unsafe") from None
        if "\0" in value:
            raise NativeError("unsafe")
        return value

    def directory_batch(self, handle: int, restart: bool) -> bytes | None:
        self._require_owned(handle)
        if type(restart) is not bool:
            raise NativeError("unsafe")
        b = self._b
        buffer = b.c.create_string_buffer(BUFFER_BYTES)  # Fresh zeroed storage, never stale records.
        value = self._invoke(b.k.GetFileInformationByHandleEx,
                             (handle, 20 if restart else 19, buffer, BUFFER_BYTES), (buffer,), completion="directory")
        if value is None:
            return None
        return bytes(buffer.raw)

    def read(self, handle: int, count: int) -> bytes:
        self._require_owned(handle)
        if type(count) is not int or not 1 <= count <= BUFFER_BYTES:
            raise NativeError("limit")
        b = self._b
        buffer, consumed = b.c.create_string_buffer(count), b.U32(0xFFFFFFFF)
        self._boolean(b.k.ReadFile, (handle, buffer, count, b.c.byref(consumed), None), (buffer, consumed))
        if consumed.value > count:
            raise NativeError("unsupported")
        return bytes(buffer.raw[:consumed.value])

    def _raw_close(self, handle: int) -> bool:
        # Unlike pending IO, close uncertainty has no caller-owned IO buffer;
        # retirement must still attempt every other independent original close.
        return bool(self._b.k.CloseHandle(handle))
