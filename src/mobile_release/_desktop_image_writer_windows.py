"""Private Windows image stdio and primitive callers; NOT a transaction backend.

The fixed B2 bootstrap roots the one DLL and exact original stdio context.
B1 binds only to that context and the SAME activated EditInput/guard after the
native parent/child handoff. Public Windows image gates and Stage C stay closed.
A pathname or ABI handshake alone grants no installed execution authority.

No ctypes import/load occurs at module import. No destructor, unload, retry,
worker, platform fallback, callbacks into Python from Rust, or new deadline.
The original guard supplies separate producing and STOP-permitted settlement
checks, both preserving the same original custody/hard deadline before entry only.
The module roots the actual DLL and one owner through UNKNOWN. Byte buffers
are separately bounded (512KiB transient/retained adapter byte-buffer budget);
the Rust primitive16MiB and Rust bridge512KiB budgets are separate.
"""
from __future__ import annotations

from dataclasses import dataclass
import ntpath
import os
import struct
import sys
import threading
from typing import Any, Callable

_VERSION = 1
_INPUT_MAX = 65_536
_OUTPUT_MAX = 65_536
_LAYOUT_TAG = 0x49573131
_OK, _EOF, _REFUSED, _FAILED, _UNKNOWN = range(5)
_DLL_LEAF = "mrk_image_writer_native.dll"
# Already-accepted disposition close, ordinary once-close, original retirement.
# Fresh disposition (13) and namespace finalization (15) are NOT settlement.
_SETTLEMENT_OPERATIONS = (14, 16, 17)
_ATTEMPTED = False
_RETAINED_DLL: Any = None
_RETAINED_OWNER: _Bridge | None = None


class BridgeRefused(RuntimeError):
    """No authority or successful native effect is implied."""


class BridgeFailure(RuntimeError):
    """Known primitive failure; original owner/finality remain retained."""


class BridgeUnknown(RuntimeError):
    """Absorbing uncertainty: never unload, close again or create a new owner."""


@dataclass(frozen=True, slots=True, eq=False)
class _Token:
    _owner: _Bridge
    _value: int
    _kind: int
    _index: int


def _integer(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise BridgeRefused("The image primitive argument is outside its closed bounds.")
    return value


def _text(value: Any, maximum: int) -> bytes:
    if type(value) is not str:
        raise BridgeRefused("The image primitive name is not admitted.")
    try:
        data = value.encode("ascii")
    except UnicodeError:
        raise BridgeRefused("The image primitive name is not admitted.") from None
    if not data or len(data) > maximum or b"\0" in data:
        raise BridgeRefused("The image primitive name is not admitted.")
    return struct.pack("<I", len(data)) + data


def _plan_bytes(project: str, children: tuple, moves: tuple, deletes: tuple) -> bytes:
    # Concrete frozen plan rows only; no path/role can be appended after Prepare.
    if (type(children) is not tuple or len(children) > 38
            or type(moves) is not tuple or len(moves) > 16
            or type(deletes) is not tuple or len(deletes) > 38):
        raise BridgeRefused("The image primitive graph is outside its closed bounds.")
    data = bytearray(b"MRKIW1\0\0" + struct.pack("<III", len(children), len(moves), len(deletes)))
    data += _text(project, 32_768)
    for row in children:
        if type(row) is not tuple or len(row) != 3:
            raise BridgeRefused("The image primitive child is not admitted.")
        parent, role, name = row
        _integer(parent, 65535)
        if type(role) is not int or not 1 <= role <= 10:
            raise BridgeRefused("The image primitive role is not admitted.")
        data += struct.pack("<II", parent, role) + _text(name, 255)
    for row in moves:
        if type(row) is not tuple or len(row) != 5:
            raise BridgeRefused("The image primitive move is not admitted.")
        source, old_parent, old_name, new_parent, new_name = row
        data += struct.pack("<II", _integer(source, 65535), _integer(old_parent, 65535))
        data += _text(old_name, 255) + struct.pack("<I", _integer(new_parent, 65535)) + _text(new_name, 255)
    for row in deletes:
        if type(row) is not tuple or len(row) != 3:
            raise BridgeRefused("The image primitive deletion is not admitted.")
        source, parent, name = row
        data += struct.pack("<II", _integer(source, 65535), _integer(parent, 65535)) + _text(name, 255)
    if len(data) > _INPUT_MAX:
        raise BridgeRefused("The image primitive graph exceeds its fixed input buffer.")
    return bytes(data)


def _types(c: Any) -> tuple[type, type, type]:
    class Request(c.Structure):
        _fields_ = [
            ("size", c.c_uint32), ("version", c.c_uint32),
            ("operation", c.c_uint32), ("reserved", c.c_uint32),
            ("owner", c.c_uint64), ("a", c.c_uint64), ("b", c.c_uint64), ("c", c.c_uint64),
            ("number", c.c_uint32), ("count", c.c_uint32),
            ("input_len", c.c_uint32), ("output_capacity", c.c_uint32),
        ]

    class Reply(c.Structure):
        _fields_ = [
            ("size", c.c_uint32), ("version", c.c_uint32),
            ("status", c.c_uint32), ("error", c.c_uint32),
            ("owner", c.c_uint64), ("token", c.c_uint64),
            ("sequence", c.c_uint64), ("epoch", c.c_uint64),
            ("output_len", c.c_uint32), ("count", c.c_uint32),
            ("total", c.c_uint32), ("flags", c.c_uint32),
            ("first_failure", c.c_uint32), ("reserved", c.c_uint32 * 3),
        ]

    class Info(c.Structure):
        _fields_ = [(name, c.c_uint32) for name in (
            "size", "version", "request_size", "reply_size", "request_align", "reply_align",
            "input_max", "output_max", "max_children", "max_moves", "max_deletes",
            "max_passes", "bridge_heap_max", "operations", "layout_tag", "reserved",
        )] + [("request_offsets", c.c_uint32 * 12), ("reply_offsets", c.c_uint32 * 14)]

    if (c.sizeof(Request), c.sizeof(Reply), c.sizeof(Info),
            c.alignment(Request), c.alignment(Reply), c.alignment(Info)) != (64, 80, 168, 8, 8, 4):
        raise BridgeRefused("The image primitive ABI layout is not supported.")
    return Request, Reply, Info


# The same DLL is first loaded by the fixed bootstrap, before engine imports.
# This context and all supplier wrappers remain strongly rooted for process life.
_STDIO_ATTEMPTED = False
_RETAINED_STDIO: _ChildStdio | None = None
_STD_IDLE, _STD_PENDING, _STD_COMPLETE, _STD_EOF, _STD_CANCELLED = range(5)
_STD_REFUSED, _STD_FAILED, _STD_UNKNOWN, _STD_CLOSED = range(5, 9)
_STD_HANDOFF = 96
_STD_CALLS = 131_072
_STD_RESERVE = 1_024


def _stdio_types(c: Any) -> tuple[type, type, type]:
    class Request(c.Structure):
        _fields_ = [
            ("size", c.c_uint32), ("version", c.c_uint32),
            ("operation", c.c_uint32), ("role", c.c_uint32),
            ("generation", c.c_uint64), ("length", c.c_uint32),
            ("capacity", c.c_uint32), ("reserved", c.c_uint32 * 2),
        ]

    class Reply(c.Structure):
        _fields_ = [
            ("size", c.c_uint32), ("version", c.c_uint32),
            ("status", c.c_uint32), ("error", c.c_uint32),
            ("generation", c.c_uint64), ("requested", c.c_uint32),
            ("transferred", c.c_uint32), ("flags", c.c_uint32),
            ("close_mask", c.c_uint32), ("mappings", c.c_uint64 * 3),
            ("output_len", c.c_uint32), ("first_failure", c.c_uint32),
            ("reserved", c.c_uint32 * 2),
        ]

    class Info(c.Structure):
        _fields_ = [("fields", c.c_uint32 * 16), ("request_offsets", c.c_uint32 * 8),
                    ("reply_offsets", c.c_uint32 * 13)]

    if (c.sizeof(Request), c.sizeof(Reply), c.sizeof(Info),
            c.alignment(Request), c.alignment(Reply), c.alignment(Info)) != (40, 80, 148, 8, 8, 4):
        raise BridgeRefused("The original image stdio ABI layout is unavailable.")
    return Request, Reply, Info


def _bootstrap_image_stdio(*, started: float, originals: tuple, mappings: tuple) -> _ChildStdio:
    """Only the isolated, fixed bootstrap supplies the untouched supplier chains.

    Native preflight is read-only. Closing the exact empty closefd=False chains
    precedes ALL native channel claims and protocol IO. This is not an alternate
    CPython supplier/UCRT qualification; unrepresentable originals refuse.
    """
    global _STDIO_ATTEMPTED, _RETAINED_DLL, _RETAINED_STDIO
    if (_STDIO_ATTEMPTED or _RETAINED_DLL is not None or _RETAINED_STDIO is not None
            or sys.platform != "win32" or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or threading.current_thread() is not threading.main_thread()
            or type(started) is not float or not 0.0 < started < float("inf")
            or type(originals) is not tuple or len(originals) != 3
            or type(mappings) is not tuple or len(mappings) != 3
            or any(type(n) is not int or not 0 < n < (1 << 64) for n in mappings)
            or len(set(mappings)) != 3
            or any(getattr(sys, name, None) is not None for name in
                   ("stdin", "stdout", "stderr", "__stdin__", "__stdout__", "__stderr__"))
            or type(sys.executable) is not str or not ntpath.isabs(sys.executable)
            or ntpath.normpath(sys.executable) != sys.executable
            or ntpath.basename(sys.executable) != "python.exe"):
        raise BridgeRefused("The fixed original Windows image bootstrap is not admitted.")
    _STDIO_ATTEMPTED = True
    try:
        import ctypes
        _RETAINED_DLL = ctypes.WinDLL(ntpath.join(ntpath.dirname(sys.executable), _DLL_LEAF), winmode=0x900)
        # Root the Python context BEFORE the first preflight/claim. The DLL roots
        # its own original arena before its first native entry.
        _RETAINED_STDIO = _ChildStdio(ctypes, _RETAINED_DLL, started, originals, mappings)
        _RETAINED_STDIO._admit_supplier()
        return _RETAINED_STDIO
    except BaseException:
        if _RETAINED_STDIO is not None:
            _RETAINED_STDIO._unknown = True
        raise BridgeUnknown("The original image stdio bootstrap did not finish admission.") from None


def _original_image_stdio(value: Any, started: float) -> _ChildStdio:
    if (type(value) is not _ChildStdio or value is not _RETAINED_STDIO
            or value._started != started or not value._supplier_retired
            or value._unknown or value._input is not None):
        raise BridgeRefused("No original image stdio context was handed off.")
    value._context()
    return value


class _ChildStdio:
    """One main-thread transport over native-owned pending buffers.

    The Python byte-buffer budget is 512KiB, separate from the 512KiB native
    arena and B1's budgets. Only one bounded synchronous ABI frame is live at a
    time. Native pending IO NEVER retains a pointer into a ctypes/Python buffer.
    No destructor, detach, raw os.read/write, fallback, worker, retry or reload.
    """
    def __init__(self, c: Any, dll: Any, started: float, originals: tuple, mappings: tuple) -> None:
        self._ctypes, self._dll = c, dll
        self._Request, self._Reply, self._Info = _stdio_types(c)
        self._started, self._startup_end = started, started + 30.0
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._originals, self._mappings = originals, mappings
        self._input: Any = None
        self._supplier_retired = self._handoff_complete = self._unknown = False
        self._custody_unknown = False  # Distinct from a valid, retained native Unknown return.
        self._write_broken = False
        self._claims = [False, False, False]
        self._close_attempted = [False, False, False]
        self._closed = [False, False, False]
        self._generation = [0, 0, 0]
        self._state = [_STD_IDLE, _STD_IDLE, _STD_IDLE]
        self._remaining = [0, 0, 0]
        self._requested = [0, 0, 0]
        self._failure_frame: Any = None
        self._calls = 0
        self._pending: Any = None
        self._info_pending: Any = None
        self._last_reply: Any = None
        self._returned_status: int | None = None
        self._call = dll.mrk_stdio_v1_call
        self._info = dll.mrk_stdio_v1_info
        self._call.argtypes = [c.POINTER(self._Request), c.POINTER(c.c_ubyte),
                              c.POINTER(self._Reply), c.POINTER(c.c_ubyte)]
        self._call.restype = c.c_uint32
        self._info.argtypes = [c.POINTER(self._Info), c.c_uint32]
        self._info.restype = c.c_uint32

    def _context(self) -> None:
        if (self._pid != os.getpid() or self._thread is not threading.current_thread()
                or self._thread is not threading.main_thread()):
            self._custody_unknown = self._unknown = True
            raise BridgeUnknown("Original image stdio changed owner.")

    def _lost_custody(self) -> bool:
        # A validated returned native Unknown is NOT a lost synchronous ABI call.
        # No such failure clears this bit or an unreturned/malformed original frame.
        return self._custody_unknown or self._pending is not None or self._info_pending is not None

    def _boundary(self, *, settlement: bool = False, terminal: bool = False) -> None:
        self._context()
        if self._lost_custody() or self._unknown and not settlement:
            raise BridgeUnknown("Original image stdio custody is unresolved.")
        if self._input is not None:
            self._input._image_native_boundary(settlement=settlement, terminal=terminal)
        else:
            import time
            if time.monotonic() >= self._startup_end:
                raise BridgeRefused("Original image stdio startup expired.")

    def _check_abi(self) -> None:
        self._boundary()
        c = self._ctypes
        value = self._Info()
        self._info_pending = value
        status = self._info(c.byref(value), c.sizeof(value))
        expected = (148, 1, 40, 80, 8, 8, 65_536, 14, 0x49533131,
                    512 * 1024, _STD_CALLS, _STD_RESERVE, _STD_HANDOFF, 3, 0, 0)
        if (status != _STD_IDLE or tuple(value.fields) != expected
                or tuple(value.request_offsets) != tuple(getattr(self._Request, n).offset for n, _ in self._Request._fields_)
                or tuple(value.reply_offsets) != tuple(getattr(self._Reply, n).offset for n, _ in self._Reply._fields_)):
            self._custody_unknown = self._unknown = True
            raise BridgeUnknown("The original image stdio ABI did not match.")
        self._info_pending = None

    def _invoke(self, operation: int, role: int = 0, *, length: int = 0,
                payload: bytes = b"", capacity: int = 0, terminal: bool = False) -> tuple[Any, bytes]:
        native_settlement = operation in (8, 9, 10, 11, 14)
        settlement = native_settlement or terminal
        if self._unknown and not native_settlement:
            raise BridgeUnknown("Unknown image stdio cannot produce another write/read.")
        self._boundary(settlement=settlement, terminal=terminal)
        if (type(operation) is not int or not 1 <= operation <= 14
                or type(role) is not int or role not in (0, 1, 2)
                or type(payload) is not bytes or len(payload) > 65_536
                or type(length) is not int or not 0 <= length <= 65_536
                or type(capacity) is not int or not 0 <= capacity <= 65_536
                or self._calls >= (_STD_CALLS if settlement else _STD_CALLS - _STD_RESERVE)):
            raise BridgeRefused("The original image stdio request exceeded its closed bounds.")
        self._calls += 1
        generation = 0 if operation in (1, 2, 3, 4, 5, 12, 13) else self._generation[role]
        c = self._ctypes
        request = self._Request(40, 1, operation, role, generation, length, capacity)
        source = (c.c_ubyte * len(payload)).from_buffer_copy(payload)
        destination = (c.c_ubyte * capacity)()
        reply = self._Reply()
        self._pending = (request, source, reply, destination)
        try:
            status = self._call(c.byref(request), source, c.byref(reply), destination)
            # Retain the actual returning frame BEFORE any guard/decoder/callback.
            self._returned_status, self._last_reply = status, reply
            if (reply.size != 80 or reply.version != 1 or reply.status != status
                    or status not in range(9) or any(reply.reserved)
                    or reply.flags & ~7 or reply.close_mask & ~7
                    or reply.requested > 65_536 or reply.transferred > reply.requested
                    or reply.output_len > capacity or reply.output_len > reply.transferred and operation != 13
                    or operation != 1 and any(reply.mappings)):
                raise BridgeUnknown("The original image stdio return is inconsistent.")
            expected_requested = None
            if operation in (6, 7):
                if reply.generation == generation + 1:
                    expected_requested = length
                elif status in (_STD_REFUSED, _STD_FAILED, _STD_UNKNOWN) and reply.generation == generation:
                    expected_requested = self._requested[role]
                else:
                    raise BridgeUnknown("The original image operation generation changed.")
            elif operation in (8, 9, 10, 11, 14):
                if reply.generation != generation:
                    raise BridgeUnknown("The original image completion generation changed.")
                expected_requested = self._requested[role]
            if expected_requested is not None and reply.requested != expected_requested:
                raise BridgeUnknown("The original image stdio return is inconsistent.")
            data = c.string_at(c.addressof(destination), reply.output_len) if reply.output_len else b""
            if operation not in (1, 2, 3, 4, 5, 12, 13):
                self._generation[role] = reply.generation
                self._requested[role] = reply.requested
                self._state[role] = status
                if status == _STD_COMPLETE and operation != 10:
                    self._remaining[role] = reply.transferred
            if reply.flags & 1 or status == _STD_UNKNOWN:
                self._unknown = True
                if self._failure_frame is None:
                    self._failure_frame = self._pending  # retain first observed failure frame, separately from a lost return
                self._pending = None
                if not native_settlement or status == _STD_UNKNOWN:
                    raise BridgeUnknown("Original image stdio native custody is unknown.")
            self._pending = None  # Only the native arena can remain an OS destination.
            if status in (_STD_REFUSED, _STD_FAILED):
                raise BridgeFailure("The original image stdio operation failed.")
            return reply, data
        except BaseException:
            if self._pending is not None:
                self._custody_unknown = self._unknown = True  # Lost/invalid return keeps the actual ABI frame.
            raise

    def _admit_supplier(self) -> None:
        import _io
        import msvcrt
        self._check_abi()
        value, _ = self._invoke(1)
        if tuple(value.mappings) != self._mappings:
            self._custody_unknown = self._unknown = True
            raise BridgeUnknown("The supplier and native CRT mappings are not identical.")
        for number, chain in enumerate(self._originals):
            if type(chain) is not tuple or len(chain) != 3:
                raise BridgeRefused("The original supplier chain is not representable.")
            text, buffered, raw = chain
            expected = _io.BufferedReader if number == 0 else _io.BufferedWriter
            if (type(text) is not _io.TextIOWrapper or type(buffered) is not expected or type(raw) is not _io.FileIO
                    or text.buffer is not buffered or buffered.raw is not raw or raw.closefd is not False
                    or text.closed or buffered.closed or raw.closed
                    or text.fileno() != number or buffered.fileno() != number or raw.fileno() != number
                    or msvcrt.get_osfhandle(number) != self._mappings[number]):
                raise BridgeRefused("The untouched supplier standard stream is not admitted.")
        # The fixed bootstrap removed both sys alias sets before importing us and
        # performed no stream IO. No detach/GC or dormant wrapper remains as a
        # potential late flusher/closer. Exact supplier emptiness needs native B3
        # evidence; a different wrapper/supplier refuses above.
        for text, buffered, raw in self._originals:
            text.close()  # Explicitly cascades through the ORIGINAL buffer/raw.
            if not (text.closed and buffered.closed and raw.closed):
                self._custody_unknown = self._unknown = True
                raise BridgeUnknown("Original supplier retirement did not complete.")
        if (tuple(msvcrt.get_osfhandle(n) for n in range(3)) != self._mappings
                or any(getattr(sys, name, None) is not None for name in
                       ("stdin", "stdout", "stderr", "__stdin__", "__stdout__", "__stderr__"))):
            self._custody_unknown = self._unknown = True
            raise BridgeUnknown("Supplier retirement changed original descriptor custody.")
        self._invoke(2)  # Native GetStdHandle/shared-UCRT post-retirement check.
        self._supplier_retired = True
        for number in range(3):
            self._invoke(3 + number)
            self._claims[number] = True

    def _bind_input(self, original: Any) -> None:
        from ._desktop_edit_control import EditInput
        self._context()
        if (type(original) is not EditInput or self._input is not None
                or original._windows_stdio is not self or not self._supplier_retired
                or not all(self._claims) or self._unknown):
            raise BridgeRefused("The original image input binding is invalid.")
        self._input = original

    def _pause(self, *, terminal: bool = False) -> None:
        import time
        self._boundary(settlement=True, terminal=terminal)
        end = self._input._image_endpoint() if self._input is not None else self._startup_end
        time.sleep(min(0.1, max(0.0, end - time.monotonic())))  # Same main thread, no new allowance.

    def read_available(self, length: int) -> bytes | None:
        """None means pending/successful-zero. b'' means native broken-peer EOF ONLY."""
        state = self._state[0]
        if state == _STD_IDLE:
            value, _ = self._invoke(6, length=length)
            state = value.status
        elif state == _STD_PENDING:
            value, _ = self._invoke(8)
            state = value.status
        if state == _STD_PENDING:
            return None
        if state == _STD_EOF:
            return b""
        if state != _STD_COMPLETE:
            raise BridgeFailure("Original image input did not complete.")
        value, data = self._invoke(10, capacity=length)
        self._remaining[0] -= len(data)
        if self._remaining[0] < 0:
            self._custody_unknown = self._unknown = True
            raise BridgeUnknown("Original image input completion changed extent.")
        self._state[0] = _STD_IDLE if self._remaining[0] == 0 else _STD_COMPLETE
        return data if data else None

    def handoff(self) -> None:
        if self._input is None or self._handoff_complete or not all(self._claims):
            raise BridgeRefused("The original image handoff cannot be repeated.")
        prologue = bytearray()
        while len(prologue) < _STD_HANDOFF:
            self._input._image_handoff_check()
            value = self.read_available(_STD_HANDOFF - len(prologue))
            if value is None:
                self._pause()
            elif not value:
                raise BridgeFailure("The original image prologue ended early.")
            else:
                prologue.extend(value)
        self._invoke(12, length=_STD_HANDOFF, payload=bytes(prologue))
        _, ack = self._invoke(13, capacity=_STD_HANDOFF)
        if len(ack) != _STD_HANDOFF:
            self._custody_unknown = self._unknown = True
            raise BridgeUnknown("The original image acknowledgement is incomplete.")
        self._write_bytes(ack, handoff=True)
        value, _ = self._invoke(14, 1)
        if not value.flags & 4:
            self._unknown = True
            raise BridgeUnknown("The original image acknowledgement did not complete.")
        self._handoff_complete = True

    def _settle_pending(self, role: int, *, terminal: bool = False) -> None:
        if self._unknown and self._pending is None:
            self._invoke(14, role, terminal=terminal)  # observe the SAME retained operation, never reissue it
        if self._state[role] != _STD_PENDING:
            return
        self._invoke(9, role, terminal=terminal)  # CancelIoEx success/NOT_FOUND is NOT completion.
        while self._state[role] == _STD_PENDING:
            value, _ = self._invoke(8, role, terminal=terminal)
            if value.status == _STD_PENDING:
                self._pause(terminal=terminal)

    def _write_bytes(self, raw: bytes, *, handoff: bool = False, terminal: bool = False) -> None:
        if self._write_broken or not handoff and not self._handoff_complete:
            raise BridgeRefused("The original image output is unavailable.")
        remaining = memoryview(raw)
        try:
            while remaining:
                if handoff:
                    self._input._image_handoff_check()
                elif not terminal:
                    self._input.before_image_entry()
                else:
                    self._input._image_terminal_check()
                chunk = bytes(remaining[:65_536])
                value, _ = self._invoke(7, 1, length=len(chunk), payload=chunk, terminal=terminal)
                while value.status == _STD_PENDING:
                    if handoff:
                        self._input._image_handoff_check()
                    elif not terminal:
                        self._input.before_image_entry()
                    else:
                        self._input._image_terminal_check()
                    self._pause(terminal=terminal)
                    value, _ = self._invoke(8, 1, terminal=terminal)
                if value.status != _STD_COMPLETE:
                    raise BridgeFailure("Original image output did not complete.")
                value, _ = self._invoke(10, 1, terminal=terminal)
                self._state[1] = _STD_IDLE
                if value.transferred == 0:
                    raise BridgeFailure("Original image output made no progress.")
                remaining = remaining[value.transferred:]
        except BaseException:
            self._write_broken = True  # Never append a terminal frame to a partial prefix.
            if self._input is not None:
                self._input._image_cleanup_started()
            try:
                self._settle_pending(1, terminal=terminal)
            except BaseException:
                self._unknown = True
            raise

    def write_frame(self, raw: bytes, *, terminal: bool = False) -> None:
        if type(raw) is not bytes:
            raise BridgeRefused("Original image output must be a bounded protocol frame.")
        if terminal:
            self._input._image_terminal_started()
        self._write_bytes(raw, terminal=terminal)

    def close_role(self, role: int) -> None:
        self._context()
        if self._closed[role]:
            return
        if self._close_attempted[role] or not self._claims[role]:
            raise BridgeUnknown("Original image descriptor close is not available.")
        self._settle_pending(role, terminal=True)
        self._close_attempted[role] = True
        value, _ = self._invoke(11, role, terminal=True)
        if value.status != _STD_CLOSED or value.close_mask != 7:
            self._unknown = True
            raise BridgeUnknown("Original image descriptor/event/mapping retirement is incomplete.")
        self._closed[role] = True


def _open_for_original_image_child(
    *, domain: str, installed_python: str, before_entry: Callable[[], None],
    before_settlement: Callable[[], None], _stdio_context: Any = None,
) -> _Bridge:
    """Bind B1 to the actual original EditInput AFTER its native handoff.

    The fixed bootstrap has already loaded and rooted the one DLL. A pathname,
    callback, synthetic receipt or separate guard cannot authorize another load
    or owner. B1's unchanged 18 operations retain their producing/settling split.
    """
    from ._desktop_edit_control import EditInput
    global _ATTEMPTED, _RETAINED_OWNER
    original = _stdio_context._input if type(_stdio_context) is _ChildStdio else None
    if (_ATTEMPTED or type(_stdio_context) is not _ChildStdio
            or domain != "metadata_images" or sys.platform != "win32"
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or threading.current_thread() is not threading.main_thread()
            or type(installed_python) is not str or installed_python != sys.executable
            or not ntpath.isabs(installed_python) or ntpath.normpath(installed_python) != installed_python
            or ntpath.basename(installed_python) != "python.exe"
            or _stdio_context is not _RETAINED_STDIO or _RETAINED_DLL is None
            or _stdio_context._dll is not _RETAINED_DLL or not _stdio_context._handoff_complete
            or _stdio_context._unknown or type(original) is not EditInput
            or original._windows_stdio is not _stdio_context
            or getattr(before_entry, "__self__", None) is not original
            or getattr(before_entry, "__func__", None) is not EditInput.before_image_entry
            or getattr(before_settlement, "__self__", None) is not original
            or getattr(before_settlement, "__func__", None) is not EditInput.before_image_settlement):
        raise BridgeRefused("The original Windows image child is not admitted.")
    before_entry()
    _ATTEMPTED = True
    try:
        c = _stdio_context._ctypes
        Request, Reply, Info = _types(c)
        _RETAINED_OWNER = _Bridge(c, _RETAINED_DLL, Request, Reply, Info, before_entry, before_settlement)
        _RETAINED_OWNER._check_abi()
        return _RETAINED_OWNER
    except BaseException:
        if _RETAINED_OWNER is not None:
            _RETAINED_OWNER._unknown = True
        raise BridgeUnknown("The retained image primitive library did not finish admission.") from None

class _Bridge:
    def __init__(self, c: Any, dll: Any, request: type, reply: type, info: type,
                 before_entry: Callable[[], None], before_settlement: Callable[[], None]) -> None:
        self._ctypes, self._dll = c, dll
        self._Request, self._Reply, self._Info = request, reply, info
        self._before_entry, self._before_settlement = before_entry, before_settlement
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._lock = threading.Lock()
        self._owner = 0
        self._prepared = self._prepare_attempted = False
        self._unknown = self._failed = self._retired = False
        self._tokens: dict[int, _Token] = {}
        self._images: tuple[_Token, ...] = ()
        self._moves: tuple[_Token, ...] = ()
        self._deletes: tuple[_Token, ...] = ()
        self._pass_count = 0
        self._pending: Any = None
        self._info_pending: Any = None
        self._observation_pending: Any = None
        self._last_reply: Any = None
        self._last_payload = b""
        self._last_observation: Any = None
        self._returned_status: int | None = None
        self._call = dll.mrk_iw_v1_call
        self._info = dll.mrk_iw_v1_info
        self._call.argtypes = [c.POINTER(request), c.POINTER(c.c_ubyte),
                              c.POINTER(reply), c.POINTER(c.c_ubyte)]
        self._call.restype = c.c_uint32
        self._info.argtypes = [c.POINTER(info), c.c_uint32]
        self._info.restype = c.c_uint32

    def _context(self) -> None:
        if self._pid != os.getpid() or self._thread is not threading.current_thread():
            raise BridgeRefused("The image primitive caller changed context.")

    def _check_abi(self) -> None:
        self._context()
        c = self._ctypes
        result = self._Info()
        self._info_pending = result
        status = self._info(c.byref(result), c.sizeof(result))
        expected = (168, 1, 64, 80, 8, 8, 65_536, 65_536, 38, 16, 38, 32,
                    512 * 1024, 18, _LAYOUT_TAG, 0)
        actual = tuple(getattr(result, name) for name, _ in self._Info._fields_[:16])
        request_offsets = tuple(getattr(self._Request, name).offset for name, _ in self._Request._fields_)
        reply_offsets = tuple(getattr(self._Reply, name).offset for name, _ in self._Reply._fields_)
        if (status != _OK or actual != expected
                or tuple(result.request_offsets) != request_offsets
                or tuple(result.reply_offsets) != reply_offsets):
            self._unknown = True
            raise BridgeUnknown("The image primitive library ABI does not match.")
        self._info_pending = None

    def _token(self, token: _Token, kind: int | tuple[int, ...]) -> int:
        kinds = (kind,) if type(kind) is int else kind
        if (type(token) is not _Token or token._owner is not self
                or token._kind not in kinds or self._tokens.get(token._value) is not token):
            raise BridgeRefused("The image primitive token is not from this original owner.")
        return token._value

    def _capture(self, value: Any, status: int, operation: int) -> None:
        if (value.size != 80 or value.version != 1 or value.status != status
                or status not in (_OK, _EOF, _REFUSED, _FAILED, _UNKNOWN)
                or any(value.reserved) or value.flags & ~127 or value.output_len > _OUTPUT_MAX
                or value.first_failure not in (0, 32, 33, 34, 35, 36)
                or value.error not in (0, 1, 2, 3, 4, 5, 6, 7, 32, 33, 34, 35, 36)):
            raise BridgeUnknown("The image primitive return frame is not admitted.")
        if (status in (_OK, _EOF) and value.error
                or status == _FAILED and value.error not in (32, 33, 34, 35, 36)
                or status == _REFUSED and value.error == 0
                or value.flags & 16 and not value.flags & 8):
            raise BridgeUnknown("The image primitive outcome tags are inconsistent.")
        if operation != 1 and value.owner != self._owner:
            raise BridgeUnknown("The image primitive return changed owner.")
        if status == _EOF and (operation not in (6, 7) or value.output_len or value.count or value.token):
            raise BridgeUnknown("The image primitive EOF frame is not admitted.")
        if status in (_OK, _EOF) and operation != 18 and value.flags & (1 | 32):
            raise BridgeUnknown("The image primitive return has unresolved native custody.")

    def _invoke(self, operation: int, *, a: int = 0, b: int = 0, c_key: int = 0,
                number: int = 0, count: int = 0, payload: bytes = b"",
                decode: Callable[[bytes, Any], Any] | None = None) -> Any:
        self._context()
        if type(operation) is not int or not 1 <= operation <= 18:
            raise BridgeRefused("The image primitive operation is outside its closed set.")
        if operation != 18 and (self._unknown or self._retired
                                or self._failed and operation not in _SETTLEMENT_OPERATIONS):
            raise BridgeUnknown("The original image primitive owner cannot enter again.")
        if operation != 1 and not self._prepared:
            raise BridgeRefused("The image primitive owner was not prepared.")
        if type(payload) is not bytes or len(payload) > _INPUT_MAX:
            raise BridgeRefused("The image primitive buffer is outside its fixed bounds.")
        for value in (a, b, c_key):
            _integer(value, (1 << 64) - 1)
        _integer(number, (1 << 32) - 1)
        _integer(count, 128)
        if not self._lock.acquire(blocking=False):
            raise BridgeRefused("An original image primitive call is already active.")
        entered = False
        observation = operation == 18
        pending_name = "_observation_pending" if observation else "_pending"
        try:
            if getattr(self, pending_name) is not None:
                raise BridgeUnknown("An unresolved original image frame cannot be replaced.")
            self._context()
            if not observation:
                # Closed routing, never an opcode guessed by a caller callback.
                # STOP may permit these original once-closes, not new mutation.
                # Both boundaries retain the SAME original custody/hard deadline.
                if operation in _SETTLEMENT_OPERATIONS:
                    self._before_settlement()
                else:
                    self._before_entry()
                # No guard callback after native return before result retention.
            c = self._ctypes
            r = self._Request(64, 1, operation, 0, self._owner, a, b, c_key,
                              number, count, len(payload), _OUTPUT_MAX)
            source = (c.c_ubyte * len(payload)).from_buffer_copy(payload)
            destination = (c.c_ubyte * _OUTPUT_MAX)()
            result = self._Reply()
            pending = (r, source, result, destination)
            setattr(self, pending_name, pending)  # strong reachable frame BEFORE entry
            entered = True
            status = self._call(c.byref(r), source, c.byref(result), destination)
            self._returned_status = status
            # Capture actual result before callbacks/STOP/decoder allocation. On
            # any interruption the registered original frame is kept, not freed.
            if observation:
                self._last_observation = (result, b"")
            else:
                self._last_reply = result
            self._capture(result, status, operation)
            data = c.string_at(c.addressof(destination), result.output_len) if result.output_len else b""
            if observation:
                self._last_observation = (result, data)
            else:
                self._last_payload = data
            if status == _UNKNOWN:
                self._unknown = True
                raise BridgeUnknown("The image primitive outcome remains unknown.")
            if status in (_REFUSED, _FAILED):
                # A definite returned refusal/failure has no outstanding caller
                # buffer writer. Rust still retains its actual original book.
                if status == _FAILED:
                    self._failed = True
                setattr(self, pending_name, None)
                if status == _FAILED:
                    raise BridgeFailure("The image primitive failed; original finality is separate.")
                raise BridgeRefused("The image primitive request was refused.")
            answer = decode(data, result) if decode is not None else data
            if operation == 17:
                self._retired = True
                if not result.flags & 2:
                    self._unknown = True
                    raise BridgeUnknown("The image primitive originals did not settle.")
            # Successful observation of UNKNOWN facts does not clear UNKNOWN.
            if result.flags & (1 | 32):
                self._unknown = True
            setattr(self, pending_name, None)
            return answer
        except (BridgeFailure, BridgeRefused):
            if entered and getattr(self, pending_name) is not None:
                self._unknown = True
                raise BridgeUnknown("The returned image frame was not completely admitted.") from None
            raise
        except BaseException:
            if entered:
                self._unknown = True
                # Keep the original primary/observation frame and actual DLL.
                raise BridgeUnknown("The image primitive call did not finish positively.") from None
            raise
        finally:
            self._lock.release()

    def prepare(self, project: str, children: tuple = (), moves: tuple = (), deletes: tuple = ()) -> None:
        self._context()
        if self._prepare_attempted:
            raise BridgeRefused("The original image primitive preparation was already attempted.")
        wire = _plan_bytes(project, children, moves, deletes)
        self._prepare_attempted = True

        def decode(data: bytes, result: Any) -> None:
            expected = (len(children) + 1, len(moves), len(deletes))
            if (result.owner != ((self._pid << 32) | 1) or result.sequence != 0 or result.token
                    or result.count != sum(expected) or result.total != result.count
                    or len(data) != result.count * 16):
                raise BridgeUnknown("The image primitive preparation reply is not admitted.")
            self._owner = result.owner
            groups: list[list[_Token]] = [[], [], []]
            for kind, index, value in struct.iter_unpack("<IIQ", data):
                if (kind not in (1, 2, 3) or index != len(groups[kind - 1])
                        or index >= expected[kind - 1] or value == 0 or value in self._tokens):
                    raise BridgeUnknown("The image primitive returned an invalid original token.")
                token = _Token(self, value, kind, index)
                self._tokens[value] = token
                groups[kind - 1].append(token)
            if tuple(map(len, groups)) != expected:
                raise BridgeUnknown("The image primitive token graph is incomplete.")
            self._images, self._moves, self._deletes = map(tuple, groups)
            self._prepared = True

        self._invoke(1, payload=wire, decode=decode)

    def image_key(self, index: int) -> _Token:
        _integer(index, len(self._images) - 1)
        return self._images[index]

    def move_key(self, index: int) -> _Token:
        _integer(index, len(self._moves) - 1)
        return self._moves[index]

    def delete_key(self, index: int) -> _Token:
        _integer(index, len(self._deletes) - 1)
        return self._deletes[index]

    def _unit(self, data: bytes, result: Any) -> None:
        if data or result.token or result.count or result.total:
            raise BridgeUnknown("The image primitive scalar reply is not admitted.")

    def begin(self) -> None:
        self._invoke(2, decode=self._unit)

    def acquire(self, image: _Token) -> None:
        self._invoke(3, a=self._token(image, 1), decode=self._unit)

    def _begin_pass(self, operation: int, image: _Token) -> _Token:
        def decode(data: bytes, result: Any) -> _Token:
            if (data or not result.token or result.token in self._tokens
                    or result.count or self._pass_count >= 32):
                raise BridgeUnknown("The image primitive pass reply is not admitted.")
            token = _Token(self, result.token, 4 if operation == 4 else 5, self._pass_count)
            self._tokens[result.token] = token
            self._pass_count += 1
            return token
        return self._invoke(operation, a=self._token(image, 1), decode=decode)

    def begin_read(self, image: _Token) -> _Token:
        return self._begin_pass(4, image)

    def begin_roster(self, image: _Token) -> _Token:
        return self._begin_pass(5, image)

    def read_next(self, pass_key: _Token) -> bytes | None:
        def decode(data: bytes, result: Any) -> bytes | None:
            if result.token or result.count or (result.status == _OK and not data):
                raise BridgeUnknown("The image primitive read reply is not admitted.")
            return None if result.status == _EOF else data
        return self._invoke(6, a=self._token(pass_key, 4), decode=decode)

    def roster_next(self, pass_key: _Token) -> tuple | None:
        def decode(data: bytes, result: Any) -> tuple | None:
            if result.status == _EOF:
                return None
            if not 0 < result.count <= 128 or result.token:
                raise BridgeUnknown("The image primitive roster reply is not admitted.")
            values = []
            at = 0
            for _ in range(result.count):
                if len(data) - at < 32:
                    raise BridgeUnknown("The image primitive roster is truncated.")
                kind, attributes, size, reserved, file_id = struct.unpack_from("<IIII16s", data, at)
                at += 32
                if kind not in (1, 2) or reserved or not size or size > len(data) - at:
                    raise BridgeUnknown("The image primitive roster row is not admitted.")
                name = data[at:at + size].decode("ascii")
                if "\0" in name:
                    raise BridgeUnknown("The image primitive roster name is not admitted.")
                values.append((kind, attributes, file_id, name))
                at += size
            if at != len(data):
                raise BridgeUnknown("The image primitive roster has trailing bytes.")
            return tuple(values)
        return self._invoke(7, a=self._token(pass_key, 5), decode=decode)

    def write_chunk(self, image: _Token, data: bytes) -> None:
        if not data:
            raise BridgeRefused("An empty image primitive write is not admitted.")
        self._invoke(8, a=self._token(image, 1), payload=data, decode=self._unit)

    def finish_write(self, image: _Token) -> None:
        self._invoke(9, a=self._token(image, 1), decode=self._unit)

    def full_fence(self, image: _Token) -> None:
        self._invoke(10, a=self._token(image, 1), decode=self._unit)

    def rename(self, movement: _Token, destination_pass: _Token) -> None:
        self._invoke(11, a=self._token(movement, 2), b=self._token(destination_pass, 5), decode=self._unit)

    def finish_move(self, movement: _Token, old_pass: _Token, new_pass: _Token) -> tuple:
        def decode(data: bytes, result: Any) -> tuple:
            if len(data) != 56 or result.count or result.token:
                raise BridgeUnknown("The image primitive move receipt is not admitted.")
            value = struct.unpack("<IIQ16sQqq", data)
            if value[1] or value[0] != movement._index:
                raise BridgeUnknown("The image primitive move identity is not admitted.")
            return value
        return self._invoke(12, a=self._token(movement, 2), b=self._token(old_pass, 5),
                            c_key=self._token(new_pass, 5), decode=decode)

    def dispose(self, deletion: _Token, empty_pass: _Token | None = None) -> None:
        self._invoke(13, a=self._token(deletion, 3),
                     b=0 if empty_pass is None else self._token(empty_pass, 5), decode=self._unit)

    def close_disposed(self, deletion: _Token) -> None:
        self._invoke(14, a=self._token(deletion, 3), decode=self._unit)

    def finish_deletion(self, deletion: _Token, parent_pass: _Token) -> tuple:
        def decode(data: bytes, result: Any) -> tuple:
            if len(data) != 40 or result.count or result.token:
                raise BridgeUnknown("The image primitive deletion receipt is not admitted.")
            value = struct.unpack("<IIQ16sQ", data)
            if value[1] or value[0] != deletion._index:
                raise BridgeUnknown("The image primitive deletion identity is not admitted.")
            return value
        return self._invoke(15, a=self._token(deletion, 3), b=self._token(parent_pass, 5), decode=decode)

    def close(self, image: _Token) -> None:
        self._invoke(16, a=self._token(image, 1), decode=self._unit)

    def retire_handles(self) -> None:
        # Explicit one attempt, never __del__ and never a transaction-success result.
        self._invoke(17, decode=self._unit)

    def observe(self, kind: int = 1, *, start: int = 0, count: int = 128,
                image: _Token | None = None) -> tuple:
        """Closed DATA projection: costs/effects/passes/moves/deletions/identity.

        No observation is a permit, join, completed transaction or rollback.
        Fixed records below mirror the Rust encoder, including presence flags.
        """
        if type(kind) is not int or not 1 <= kind <= 6:
            raise BridgeRefused("The image primitive observation kind is not admitted.")
        formats = {1: "<12Q", 2: "<8I4Q", 3: "<IIQ16sQII", 4: "<IIQqq",
                   5: "<IIQQQ", 6: "<Q16s"}
        if kind in (1, 6):
            if start != 0:
                raise BridgeRefused("The image primitive scalar observation has no page.")
            a, requested = (self._token(image, 1), 0) if kind == 6 else (0, 0)
            if kind == 1 and image is not None:
                raise BridgeRefused("The image primitive summary has no image operand.")
        else:
            if image is not None:
                raise BridgeRefused("The image primitive page has no image operand.")
            a, requested = _integer(start, 8192), _integer(count, 128)
            if not requested:
                raise BridgeRefused("The image primitive observation page cannot be empty.")

        def decode(data: bytes, result: Any) -> tuple:
            fmt = formats[kind]
            size = struct.calcsize(fmt)
            rows = 1 if kind in (1, 6) else result.count
            if (result.token or rows > 128 or len(data) != rows * size
                    or kind not in (1, 6) and (result.count > requested or result.total < a + result.count)):
                raise BridgeUnknown("The image primitive observation length is not admitted.")
            values = tuple(struct.iter_unpack(fmt, data))
            for value in values:
                if kind == 2 and (value[0] not in range(1, 11) or value[2] & ~63
                                  or value[3] not in (0, 1, 2) or value[7]
                                  or any(value[9:])):
                    raise BridgeUnknown("The image primitive effect record is not admitted.")
                if kind == 3 and (value[1] not in (1, 2) or value[6]):
                    raise BridgeUnknown("The image primitive pass record is not admitted.")
                if kind == 4 and value[1] & ~63:
                    raise BridgeUnknown("The image primitive move record is not admitted.")
                if kind == 5 and (value[1] & ~127 or value[4]):
                    raise BridgeUnknown("The image primitive deletion record is not admitted.")
            return values

        return self._invoke(18, a=a, number=kind, count=requested, decode=decode)
