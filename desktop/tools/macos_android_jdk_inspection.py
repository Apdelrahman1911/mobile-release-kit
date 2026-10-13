"""Complete, offline Intel JDK/JMOD byte observations, never native authority.

The caller supplies one retained Original and the actual correspondence module.
No file is opened, extracted or executed here. All nested parsers share the
original endpoint and aggregate reservations. Publication still requires the
caller's original POST, consuming closes and real process return afterwards.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct

MIB = 1024 * 1024
ARCHIVE_BYTES = 180578248
ARCHIVE_SHA256 = "c01975da12ed4235250ff891fe8bba73a9e73037d444b269c9d0922b5dbc8e0a"
CORRESPONDENCE_BYTES = 100949
CORRESPONDENCE_SHA256 = "fd4287337be6dc07ebb3576e1790a2c708487899637ed945d60d5197e8d30e46"
JDK_ROOT = "jdk-17.0.20.1+1/"
HOME = JDK_ROOT + "Contents/Home/"
CPU_X64 = 0x01000007
PAYLOAD_LIMIT = 64 * MIB
ROWS_LIMIT = 48 * MIB
WORKSPACE_LIMIT = 128 * MIB
READ_LIMIT = 768 * MIB
EXPANDED_LIMIT = 1024 * MIB
OUTPUT_LIMIT = 8 * MIB
COMMAND_LIMIT = 65536
WINDOW = 65536
FORMAT_NAMES = frozenset(("macho", "java-class-header", "unsupported-native",
                          "ambiguous-native", "foreign-native", "zip", "jmod",
                          "unsupported-jmod", "shell", "opaque"))

# Closed SOURCE nominations, not an arbitrary pin/URL or native admission API.
# (component, whole bytes, whole SHA256, selected outer JARs, required native rows)
NON_JDK_ARCHIVES = (
    ("aapt2", 4339472, "5d0aec6851fffbc9f6c8a8b50390c0bc976aa0ddf57a8a3a39061ed54b609ad1", (), (
        ("aapt2", 11143368, "213e3d049e2c85daa930ed777bbd5627c1c5479a8d6698029b8f9c0161ad0a7e", 0o100755),
    )),
    ("gradle", 138068841, "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854", (
        ("gradle-8.14.5/lib/native-platform-osx-amd64-0.22-milestone-28.jar", 12867,
         "61ab872b419deae8cdf37d1a0d5f6916b170ada1226129741fceb3ebd56b950f"),
        ("gradle-8.14.5/lib/gradle-fileevents-0.2.7.jar", 1433862,
         "9f8d26b0057ed645af68c8d4139988d69ee884ad8d009e98a793c08cbdd3d2f8"),
        ("gradle-8.14.5/lib/jansi-1.18.jar", 287352,
         "109e64fc65767c7a1a3bd654709d76f107b0a3b39db32cbf11139e13a6f5229b"),
    ), ()),
    ("bundletool", 32520401, "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29", (), ()),
)


# Separate complete DATA route. The legacy selected-three route above is not
# silently upgraded and the caller cannot choose arbitrary pins or selections.
COMPLETE_NON_JDK_ARCHIVES = (
    ("gradle", 138068841, "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854"),
    ("sdk-platform", 64273788, "0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0"),
    ("sdk-build-tools", 76857898, "530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48"),
)


class InspectionRefused(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise InspectionRefused(code)


def uint(value):
    return type(value) is int and value >= 0


def sha(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class Arena:
    """Explicit simultaneous allocations, not a claim to measure all Python RAM.

    The independent address-space limit remains required. Reservations include
    live parent buffers, row-object overhead, native snapshots, JSON copies and
    an8MiB scratch allowance. Reads/expansion are cumulative, never refunded.
    """
    def __init__(self, original):
        self.original = original
        self.failed = False
        self.held = {"payload": 0, "rows": 0, "facts": 0, "output": 0, "other": 8 * MIB}
        self.peaks = dict(self.held)
        self.peak = sum(self.held.values())
        self.reads = 0
        self.expanded = 0

    def check(self):
        need(not self.failed, "inspection-already-failed")
        try:
            self.original.checkpoint()
        except BaseException:
            self.failed = True
            raise

    def require(self, condition, code):
        if not condition:
            self.failed = True
            raise InspectionRefused(code)

    def reserve(self, kind, count):
        self.check()
        self.require(kind in self.held and uint(count), "reservation-shape")
        value = self.held[kind] + count
        self.require(kind != "payload" or value <= PAYLOAD_LIMIT, "aggregate-payload-reservation")
        self.require(kind != "rows" or value <= ROWS_LIMIT, "aggregate-row-reservation")
        total = sum(self.held.values()) + count
        self.require(total <= WORKSPACE_LIMIT, "aggregate-workspace-reservation")
        self.held[kind] = value
        self.peaks[kind] = max(self.peaks[kind], value)
        self.peak = max(self.peak, total)

    def release(self, kind, count):
        # Heap disposal may follow a failed pass; it does not clear its latch.
        self.require(kind in self.held and uint(count) and count <= self.held[kind], "reservation-release")
        self.held[kind] -= count

    def reserve_rows(self, count):
        self.reserve("rows", count)

    def release_rows(self, count):
        self.release("rows", count)

    def charge_read(self, count):
        self.check()
        self.require(uint(count) and self.reads + count <= READ_LIMIT, "aggregate-issued-read-bound")
        self.reads += count

    def charge_expanded(self, count):
        self.check()
        self.require(uint(count) and self.expanded + count <= EXPANDED_LIMIT, "aggregate-inner-expansion-bound")
        self.expanded += count

    def facts(self, count):
        self.reserve("facts", count)


def content_kind(prefix, size):
    """Distinguish bounded supported headers; never infer safety from a suffix."""
    need(type(prefix) is bytes and uint(size) and len(prefix) <= size, "format-prefix")
    magic = prefix[:4]
    if magic == b"\xca\xfe\xba\xbe":
        if len(prefix) >= 8 and 1 <= struct.unpack_from(">I", prefix, 4)[0] <= 4:
            return "macho"
        if len(prefix) >= 10:
            minor, major, pool = struct.unpack_from(">HHH", prefix, 4)
            if 45 <= major <= 61 and (minor == 0 or minor == 65535 and major >= 56) and pool >= 1:
                # This label is deliberately HEADER evidence, not verification
                # of bytecode semantics or a negative for arbitrary fat formats.
                return "java-class-header"
        return "ambiguous-native"
    if magic in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbf"):
        return "macho"
    if magic in (b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                 b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        return "unsupported-native"
    if prefix.startswith(b"\x7fELF") or prefix.startswith(b"MZ"):
        return "foreign-native"
    if magic in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if prefix.startswith(b"JM"):
        return "jmod" if magic == b"JM\x01\x00" else "unsupported-jmod"
    return "shell" if prefix.startswith(b"#!") else "opaque"


def selected_slice(prefix, size):
    """Locate only the original x64 slice; Rust still interprets load policy."""
    need(type(prefix) is bytes and uint(size) and 32 <= size and len(prefix) >= 32, "native-prefix-bound")
    if prefix[:4] == b"\xcf\xfa\xed\xfe":
        cpu, subtype = struct.unpack_from("<II", prefix, 4)
        return (0, size, cpu, subtype) if cpu == CPU_X64 else None
    need(prefix[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"), "native-format")
    count = struct.unpack_from(">I", prefix, 4)[0]
    width = 32 if prefix[:4] == b"\xca\xfe\xba\xbf" else 20
    table_end = 8 + count * width
    need(1 <= count <= 4 and table_end <= len(prefix), "native-fat-table")
    cpus, ranges, selected = set(), [], None
    for index in range(count):
        if width == 20:
            cpu, subtype, offset, extent, alignment = struct.unpack_from(">IIIII", prefix, 8 + index * width)
        else:
            cpu, subtype, offset, extent, alignment, reserved = struct.unpack_from(">IIQQII", prefix, 8 + index * width)
            need(reserved == 0, "native-fat-reserved")
        need(cpu not in cpus and alignment <= 20 and offset >= table_end and extent >= 32
             and offset % (1 << alignment) == 0 and offset + extent <= size
             and all(offset + extent <= lo or offset >= hi for lo, hi in ranges), "native-fat-range")
        cpus.add(cpu)
        ranges.append((offset, offset + extent))
        if cpu == CPU_X64:
            selected = (offset, extent, cpu, subtype)
    return selected


class _Window:
    def __init__(self, offset, size, arena):
        arena.reserve("payload", size)
        self.arena, self.offset, self.size, self.used = arena, offset, size, 0
        self.data = bytearray(size)

    def feed(self, offset, block):
        lo = max(offset, self.offset)
        hi = min(offset + len(block), self.offset + self.size)
        if lo < hi:
            need(lo == self.offset + self.used, "snapshot-stream-order")
            self.data[self.used:self.used + hi - lo] = block[lo - offset:hi - offset]
            self.used += hi - lo

    def dispose(self):
        self.data = None
        self.arena.release("payload", self.size)
        self.size = 0


class NativeCapture:
    def __init__(self, size, arena):
        self.size, self.arena = size, arena
        self.prefix = _Window(0, min(4096, size), arena)
        self.header = self.commands = None
        self.selected = None
        self.started = False

    def feed(self, offset, block):
        self.prefix.feed(offset, block)
        if not self.started:
            need(offset == 0, "native-stream-start")
            self.started = True
            self.selected = selected_slice(block, self.size)
            if self.selected is not None:
                self.header = _Window(self.selected[0], 32, self.arena)
        if self.header is not None:
            self.header.feed(offset, block)
            if self.header.used == 32 and self.commands is None:
                magic, cpu, subtype, filetype, count, extent, flags, reserved = struct.unpack("<8I", self.header.data)
                need(magic == 0xFEEDFACF and (cpu, subtype) == self.selected[2:], "native-selected-header")
                need(filetype in (2, 6, 8) and 1 <= count <= 1024 and 8 * count <= extent
                     and 32 + extent <= min(COMMAND_LIMIT, self.selected[1]), "native-command-region")
                self.commands = _Window(self.selected[0] + 32, extent, self.arena)
            if self.commands is not None:
                self.commands.feed(offset, block)

    def finish(self, row):
        need(self.started and self.prefix.used == self.prefix.size, "native-prefix-incomplete")
        if self.selected is None:
            return self._record(row, None)
        need(self.header.used == 32 and self.commands is not None and self.commands.used == self.commands.size,
             "native-snapshot-incomplete")
        temporary = 2 * (32 + self.commands.size + self.prefix.size)
        self.arena.reserve("other", temporary)
        try:
            return self._record(row, bytes(self.header.data) + bytes(self.commands.data))
        finally:
            self.arena.release("other", temporary)

    def _record(self, row, commands):
        prefix = bytes(self.prefix.data)
        encoded = 4 * ((len(prefix) + 2) // 3) + (0 if commands is None else 4 * ((len(commands) + 2) // 3))
        self.arena.facts(4096 + 8 * len(row[0]) + 4 * encoded)
        result = {"name": row[0], "bytes": row[3], "mode": row[2], "sha256": row[4],
                  "format": "macho", "prefixBytes": len(prefix), "prefixSha256": hashlib.sha256(prefix).hexdigest(),
                  "prefixBase64": base64.b64encode(prefix).decode("ascii"), "selectedCpu": None,
                  "sliceOffset": None, "sliceBytes": None, "commandsBytes": 0,
                  "commandsSha256": None, "commandsBase64": None}
        if commands is not None:
            result.update(selectedCpu="x86_64", sliceOffset=self.selected[0], sliceBytes=self.selected[1],
                          commandsBytes=len(commands), commandsSha256=hashlib.sha256(commands).hexdigest(),
                          commandsBase64=base64.b64encode(commands).decode("ascii"))
        return result

    def dispose(self):
        for window in (self.prefix, self.header, self.commands):
            if window is not None:
                window.dispose()


class _View:
    """Private complete buffer, exposed to the parser through readonly windows.

    The collecting writer is finished before constructing this view. No buffer
    reference is handed to observers. No fake file/PID ownership is asserted.
    """
    def __init__(self, body, offset, arena):
        self._body = body
        self._offset = offset
        self._view = memoryview(body)[offset:].toreadonly()
        self._length = len(self._view)
        self.arena = arena

    def checkpoint(self):
        self.arena.check()

    def verify_binding(self):
        self.checkpoint()
        self.arena.original.verify_binding()
        need(self._view.readonly and self._view.obj is self._body and len(self._view) == self._length,
             "inner-buffer-binding")
        self.checkpoint()

    def read_at(self, offset, count):
        self.checkpoint()
        need(uint(offset) and uint(count) and count <= WINDOW and offset + count <= self._length,
             "inner-read-window")
        return bytes(self._view[offset:offset + count])


    def dispose(self):
        self._view.release()
        self._body = None


def _complete_problem(name, mode, kind):
    # These are conservative unresolved DATA labels, never native admission.
    if kind in ("unsupported-native", "ambiguous-native", "unsupported-jmod"):
        return kind
    if ((name.endswith((".jar", ".zip")) and kind != "zip")
            or (name.endswith(".jmod") and kind != "jmod")):
        return "archive-name-format-disagreement"
    if name.endswith(".class") and kind != "java-class-header":
        return "class-name-format-disagreement"
    if name.endswith((".dylib", ".jnilib", ".so", ".dll", ".exe")) and kind not in ("macho", "foreign-native"):
        return "native-name-format-disagreement"
    if kind == "opaque" and mode & 0o111:
        return "executable-opaque"
    return None


def _complete_prefix(row, kind, window, arena):
    size = min(row[3], 4096)
    arena.require((window is None and size == 0)
                  or (window is not None and window.size == size and window.used == size),
                  "complete-prefix-incomplete")
    arena.reserve("other", 2 * size)
    try:
        encoded = 4 * ((size + 2) // 3)
        arena.facts(4096 + 8 * len(row[0]) + 4 * encoded)
        prefix = b"" if window is None else bytes(window.data)
        return {"name": row[0], "bytes": row[3], "mode": row[2], "sha256": row[4],
                "format": kind, "prefixBytes": size,
                "prefixSha256": hashlib.sha256(prefix).hexdigest(),
                "prefixBase64": base64.b64encode(prefix).decode("ascii")}
    finally:
        arena.release("other", 2 * size)


def _complete_census(observer, summary):
    need(observer.complete and observer.current is None and not observer.uninspected
         and summary["aliases"] == 0 and 0 <= summary["files"] <= summary["members"]
         and sum(observer.formats.values()) == summary["files"]
         and len(observer.native) == observer.formats["macho"]
         and len(observer.foreign) == observer.formats["foreign-native"]
         and len(observer.native) + len(observer.foreign) <= 128
         and len(observer.archives) == observer.formats["zip"] + observer.formats["jmod"],
         "complete-observer-census")


class _Observer:
    def __init__(self, parser, arena, *, expected=None, depth=0, nested_count=None, outer_selection=None,
                 complete=False, top_level=False):
        need(type(complete) is bool and type(top_level) is bool
             and (not complete or expected is None and outer_selection is None)
             and (not top_level or complete and depth == 0 and nested_count is None),
             "complete-observer-context")
        self.complete, self.top_level = complete, top_level
        self.parser, self.arena, self.expected = parser, arena, expected
        self.depth = depth
        self.nested_count = [0] if nested_count is None else nested_count
        self.outer_selection = None
        self.selected_seen = set()
        self.uninspected = []
        if outer_selection is not None:
            need(expected is None and depth == 0 and nested_count is None
                 and type(outer_selection) is tuple and len(outer_selection) <= 3
                 and all(type(row) is tuple and len(row) == 3 and type(row[0]) is str
                         and 0 < len(row[0]) <= 512 and uint(row[1]) and 0 < row[1] <= PAYLOAD_LIMIT
                         and sha(row[2]) for row in outer_selection), "outer-selection-shape")
            arena.facts(4096 + sum(2048 + 8 * len(row[0]) for row in outer_selection))
            self.outer_selection = {row[0]: row[1:] for row in outer_selection}
            need(len(self.outer_selection) == len(outer_selection), "outer-selection-duplicate")
        self.current = None
        self.native = []
        self.foreign = [] if complete else None
        self.unknown = []
        self.archives = []
        self.formats = {name: 0 for name in sorted(FORMAT_NAMES)}

    def begin(self, row):
        self.arena.check()
        self.arena.require(self.current is None and row[1] == "file", "observer-file-overlap")
        if self.expected is not None:
            self.arena.require(row[0] in self.expected, "outer-unexpected-member")
        if self.outer_selection is not None and row[0] in self.outer_selection:
            self.arena.require(row[0] not in self.selected_seen
                               and row[3] == self.outer_selection[row[0]][0], "selected-outer-member-size")
        self.current = {"row": row, "offset": 0, "kind": None, "buffer": None,
                        "native": None, "prefix": b"", "probe": bytearray(), "prefix_window": None,
                        "whole_hash": None, "view_hash": None, "buffered": 0}

    def block(self, name, offset, data):
        self.arena.check()
        state = self.current
        self.arena.require(state is not None and name == state["row"][0] and offset == state["offset"]
             and type(data) is bytes and len(data) <= WINDOW and offset + len(data) <= state["row"][3],
             "observer-block-order")
        if state["kind"] is None:
            taken = min(min(160, state["row"][3]) - len(state["probe"]), len(data))
            state["probe"].extend(data[:taken])
            if len(state["probe"]) < min(160, state["row"][3]):
                state["offset"] += len(data)
                return
            probe = bytes(state["probe"])
            kind = content_kind(probe, state["row"][3])
            state["kind"] = kind
            if kind == "macho":
                state["native"] = NativeCapture(state["row"][3], self.arena)
            elif kind in ("jmod", "zip") and (self.outer_selection is None
                                                  or state["row"][0] in self.outer_selection):
                self.arena.reserve("payload", state["row"][3])
                state["buffer"] = bytearray(state["row"][3])
                state["whole_hash"] = hashlib.sha256()
                state["view_hash"] = hashlib.sha256() if kind == "jmod" else state["whole_hash"]
            elif not self.complete and kind in ("unsupported-native", "ambiguous-native", "foreign-native", "unsupported-jmod"):
                state["prefix"] = probe
            if self.complete and (kind == "foreign-native"
                                  or _complete_problem(state["row"][0], state["row"][2], kind) is not None):
                state["prefix_window"] = _Window(0, min(4096, state["row"][3]), self.arena)
            self._feed(state, 0, probe)
            self._feed(state, offset + taken, data[taken:])
            state["probe"] = None
        else:
            self._feed(state, offset, data)
        state["offset"] += len(data)

    def _feed(self, state, offset, data):
        if not data:
            return
        if state["native"] is not None:
            state["native"].feed(offset, data)
        if state["prefix_window"] is not None:
            state["prefix_window"].feed(offset, data)
        if state["buffer"] is not None:
            self.arena.require(offset == state["buffered"]
                               and offset + len(data) <= len(state["buffer"]), "inner-collector-order")
            state["buffer"][offset:offset + len(data)] = data
            # Hash the same ordered immutable bytes as the existing copy, not
            # a second traversal of the completed private buffer. The parser
            # will still independently authenticate that copied buffer.
            state["whole_hash"].update(data)
            if state["kind"] == "jmod":
                state["view_hash"].update(data[max(0, 4 - offset):])
            state["buffered"] += len(data)

    def end(self, row):
        self.arena.check()
        state = self.current
        self.arena.require(state is not None and state["row"][0] == row[0] and state["offset"] == row[3]
             and sha(row[4]), "observer-file-completion")
        if self.expected is not None:
            self.arena.require(tuple(row) == self.expected[row[0]], "outer-member-correspondence")
        kind = state["kind"] or "opaque"
        if self.top_level and row[0].endswith((".jar", ".jmod")):
            self.arena.require(kind == ("jmod" if row[0].endswith(".jmod") else "zip"),
                               "complete-outer-archive-format")
        selected = self.outer_selection is not None and row[0] in self.outer_selection
        if selected:
            self.arena.require(kind == "zip" and (row[3], row[4]) == self.outer_selection[row[0]],
                               "selected-outer-member-pin")
        self.formats[kind] += 1
        if state["native"] is not None:
            need(len(self.native) + (len(self.foreign) if self.complete else 0) < 128, "native-member-count")
            self.native.append(state["native"].finish(row))
        elif state["buffer"] is not None:
            self.arena.require(state["buffered"] == row[3]
                               and state["whole_hash"].hexdigest() == row[4], "inner-whole-member-sha")
            outer = self.expected is not None or self.outer_selection is not None or self.top_level
            if not outer:
                self.nested_count[0] += 1
                need(self.depth < 2 and self.nested_count[0] <= 3, "nested-archive-count-or-depth")
            self.archives.append(inspect_inner(self.parser, self.arena, state["buffer"], row,
                                              zip_sha256=state["view_hash"].hexdigest(),
                                              depth=self.depth if outer else self.depth + 1,
                                              nested_count=None if outer else self.nested_count,
                                              complete=self.complete))
        elif self.outer_selection is not None and kind in ("zip", "jmod"):
            self.arena.facts(4096 + 8 * len(row[0]))
            self.uninspected.append({"name": row[0], "bytes": row[3], "mode": row[2], "sha256": row[4],
                                     "format": kind, "completeMemberHash": True, "interiorInspected": False})
        elif state["prefix"]:
            self.arena.facts(4096 + 8 * len(row[0]) + 8 * len(state["prefix"]))
            self.unknown.append({"name": row[0], "bytes": row[3], "mode": row[2], "sha256": row[4],
                                  "format": kind, "prefixBase64": base64.b64encode(state["prefix"]).decode("ascii")})
        if self.complete:
            if kind == "foreign-native":
                need(len(self.native) + len(self.foreign) < 128, "native-member-count")
                prefix = state["prefix_window"]
                self.arena.require(prefix is not None, "foreign-prefix-required")
                observed_format = "ELF" if prefix.data[:4] == b"\x7fELF" else "PE"
                self.foreign.append(_complete_prefix(row, observed_format, prefix, self.arena))
            problem = _complete_problem(row[0], row[2], kind)
            if problem is not None:
                fact = _complete_prefix(row, kind, state["prefix_window"], self.arena)
                fact["reason"] = problem
                self.unknown.append(fact)
        if selected:
            self.selected_seen.add(row[0])
        self.dispose_current()

    def dispose_current(self):
        state, self.current = self.current, None
        if state is not None:
            if state["native"] is not None:
                state["native"].dispose()
            if state["prefix_window"] is not None:
                state["prefix_window"].dispose()
            if state["buffer"] is not None:
                size = len(state["buffer"])
                state["buffer"] = None
                self.arena.release("payload", size)


def inspect_inner(parser, arena, body, row, *, zip_sha256, depth=0, nested_count=None, complete=False):
    """Inspect a completed collector, with independent authentication of its copy.

    zip_sha256 is captured from the same ordered stream as the complete buffer;
    _Observer.end first binds its whole-stream hash to the completed member row.
    The unchanged parser still rehashes the entire copied ZIP view before use.
    Every inner entry is decoded/hashed, including non-native resources.
    """
    arena.check()
    arena.require(type(body) is bytearray and len(body) == row[3] and len(body) <= PAYLOAD_LIMIT, "inner-body-bound")
    arena.require(sha(zip_sha256), "inner-zip-view-sha")
    jmod = body[:4] == b"JM\x01\x00"
    arena.require(jmod or body[:4] in (b"PK\x03\x04", b"PK\x05\x06"), "inner-format")
    view = _View(body, 4 if jmod else 0, arena)
    observer = _Observer(parser, arena, depth=depth, nested_count=nested_count, complete=complete)
    enumeration = hashlib.sha256()
    try:
        pin = parser.OpaqueZipPin(view._length, zip_sha256)
        if complete:
            report = parser.compile_opaque_zip(view, pin, observer=observer, workspace=arena, compact=True)
        else:
            report = parser.compile_opaque_zip(view, pin, observer=observer, workspace=arena)
        def consume(item):
            arena.check()
            fragment = json.dumps(item, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
            need(len(fragment) <= 16384, "inner-enumeration-row")
            enumeration.update(fragment)
            enumeration.update(b"\n")
        summary = report.consume_rows(consume)
        need(observer.current is None and summary["aliases"] == 0, "inner-observer-finality")
        arena.facts(8192 + 8 * len(row[0]))
        result = {"name": row[0], "bytes": row[3], "sha256": row[4], "mode": row[2],
                "format": "jmod" if jmod else "zip", "zipViewOffset": 4 if jmod else 0,
                "centralMembers": summary["members"],
                "inspectedMembers": summary["members"], "files": summary["files"],
                "completeMemberHashes": True, "expandedInspectedBytes": summary["expandedBytes"],
                "enumerationSha256": enumeration.hexdigest(), "formatCounts": observer.formats,
                "nativeMembers": sorted(observer.native, key=lambda item: item["name"]),
                "unknownMembers": sorted(observer.unknown, key=lambda item: item["name"]),
                "nestedArchives": sorted(observer.archives, key=lambda item: item["name"]),
                "innerBookReservationBytes": summary["rosterReservationBytes"],
                "issuedReadBytes": summary["issuedReadBytes"],
                "nativeExecuted": False, "supplierAuthority": False}
        if complete:
            _complete_census(observer, summary)
            arena.facts(4096)
            result["directoryMembers"] = summary["members"] - summary["files"]
            result["foreignNativeMembers"] = sorted(observer.foreign, key=lambda item: item["name"])
            result["negativeEvidence"] = None
            if (not observer.native and not observer.foreign and not observer.unknown and not observer.archives
                    and all(count == 0 for kind, count in observer.formats.items()
                            if kind not in ("java-class-header", "opaque"))):
                result["negativeEvidence"] = {
                    "kind": "complete-recognized-format-negative",
                    "centralMembers": summary["members"], "inspectedMembers": summary["members"],
                    "files": summary["files"], "completeMemberHashes": True,
                    "expandedInspectedBytes": summary["expandedBytes"],
                    "enumerationSha256": enumeration.hexdigest(), "nativeMembers": [], "nestedArchives": [],
                    "nativeExecution": False, "supplierAuthority": False}
        return result
    except BaseException as error:
        arena.failed = True
        # Detached failure-only context. The caller completed and hashed this
        # parent member BEFORE constructing this authenticated ZIP/JMOD view.
        # Never discover locals or read another byte to explain a refusal.
        if (type(error) is parser.Refused and len(error.args) == 1
                and error.args[0] in ("expanded_member_bound", "zip_member_mode_or_creator")):
            try:
                detail = getattr(error, "_fixed_zip_diagnostic", None)
                if type(detail) is dict and detail.get("contextsComplete") is True:
                    detail["contextsComplete"] = False
                    contexts = detail.get("containers")
                    name_bytes = row[0].encode("utf-8")
                    if type(contexts) is list and len(contexts) < 3 and 0 < len(name_bytes) <= 512:
                        context = {"nameBytes": len(name_bytes), "nameHex": name_bytes.hex(),
                            "bytes": row[3], "sha256": row[4], "mode": row[2],
                            "zipViewOffset": 4 if jmod else 0, "zipViewBytes": view._length,
                            "zipViewSha256": zip_sha256}
                        if context not in contexts:  # Full fixed row, not only its name.
                            contexts.append(context)
                            detail["contextsComplete"] = True
            except BaseException:
                try:
                    error._fixed_zip_diagnostic = None
                except BaseException:
                    pass
        raise  # Same exception object/args, disposal and no fallback.
    finally:
        observer.dispose_current()
        view.dispose()


def counterpart_facts(native, archives, arena):
    direct = {row["name"]: row for row in native}
    keys = ("bytes", "sha256", "prefixBytes", "prefixSha256", "prefixBase64", "selectedCpu",
            "sliceOffset", "sliceBytes", "commandsBytes", "commandsSha256", "commandsBase64")
    for archive in archives:
        if archive["format"] != "jmod":
            continue
        for row in archive["nativeMembers"]:
            name = row["name"]
            candidate = HOME + name if name.startswith(("bin/", "lib/")) else None
            other = direct.get(candidate)
            exact = other is not None and all(row[key] == other[key] for key in keys)
            template = (archive["name"] == HOME + "jmods/jdk.jpackage.jmod" and
                        name == "classes/jdk/jpackage/internal/resources/jpackageapplauncher")
            arena.facts(2048 + 8 * len(candidate or ""))
            row["counterpart"] = {"candidate": candidate, "matched": exact,
                                  "status": "exact-byte-and-snapshot-match" if exact else
                                  "different-bytes-or-snapshot" if other is not None else
                                  "embedded-jpackage-template-observed" if template else "unmatched"}


class Inspection:
    def __init__(self, arena, document):
        self.arena, self.document, self.published = arena, document, False

    def publish(self, sink):
        arena = self.arena
        need(not self.published, "inspection-publication-finality")
        try:
            arena.check()
            arena.original.verify_binding()
            encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            count, expected = 0, hashlib.sha256()
            for fragment in encoder.iterencode(self.document):
                arena.check()
                body = fragment.encode("ascii")
                count += len(body)
                need(count <= OUTPUT_LIMIT, "inspection-output-bound")
                expected.update(body)
            arena.reserve("output", 2 * count)
            try:
                output, cursor, actual = bytearray(count), 0, hashlib.sha256()
                for fragment in encoder.iterencode(self.document):
                    arena.check()
                    body = fragment.encode("ascii")
                    need(cursor + len(body) <= count, "inspection-output-drift")
                    output[cursor:cursor + len(body)] = body
                    cursor += len(body)
                    actual.update(body)
                need(cursor == count and actual.digest() == expected.digest(), "inspection-output-drift")
                arena.original.verify_binding()
                arena.check()
                immutable = bytes(output)
                del output
                sink(immutable)
                arena.original.verify_binding()
                arena.check()
                self.published = True
                return {"bytes": count, "sha256": actual.hexdigest(), "nativeExecuted": False,
                        "supplierAuthority": False, "peakReservedBytes": arena.peak,
                        "peakReservations": dict(arena.peaks)}
            finally:
                arena.release("output", 2 * count)
        except BaseException:
            arena.failed = True
            raise


def _correspondence_rows(rows):
    """Retain the canonical root directory and every authenticated descendant."""
    code = "original-correspondence-roster"
    need(type(rows) is list and len(rows) == 549
         and all(type(row) is list and len(row) == 14 and type(row[0]) is str for row in rows), code)
    expected = {row[0]: tuple(row) for row in rows}
    root = JDK_ROOT[:-1]
    root_row = expected.get(root)
    need(len(expected) == 549 and root_row is not None
         and type(root_row[1]) is str and root_row[1] == "directory"
         and type(root_row[2]) is int and root_row[2] == 17901
         and type(root_row[3]) is int and root_row[3] == 0
         and all(value is None for value in root_row[4:])
         and all(name == root or name.startswith(JDK_ROOT) for name in expected), code)
    return expected


def inspect_jdk(original, previous, parser):
    """Compile the exact genuine retained Intel acquisition; no arbitrary pins."""
    arena = Arena(original)
    observer = None
    try:
        arena.check()
        need(type(previous) is bytes and len(previous) == CORRESPONDENCE_BYTES
             and hashlib.sha256(previous).hexdigest() == CORRESPONDENCE_SHA256, "original-correspondence-pin")
        arena.reserve("other", 4 * MIB)
        document = json.loads(previous)
        need(document["kind"] == "offline-official-archive-correspondence-data" and document["label"] == "jdk"
             and document["archiveBytes"] == ARCHIVE_BYTES and document["archiveSha256"] == ARCHIVE_SHA256
             and document["completeMemberHashes"] is True and document["supplierAuthority"] is False
             and document["nativeClosure"] is False and document["columns"] == list(parser.COLUMNS)
             and document["members"] == 549 and document["files"] == 457 and document["aliases"] == 0
             and document["expandedBytes"] == 299747655, "original-correspondence-shape")
        expected = _correspondence_rows(document["rows"])
        observer = _Observer(parser, arena, expected=expected)
        report = parser.compile_archive(original, parser.Pin("jdk", ARCHIVE_BYTES, ARCHIVE_SHA256),
                                        observer=observer, workspace=arena)
        visited = 0
        def compare(row):
            nonlocal visited
            need(row[0] in expected and tuple(row) == expected[row[0]], "original-correspondence-drift")
            visited += 1
        summary = report.consume_rows(compare)
        need(visited == 549 and observer.current is None and summary["members"] == 549
             and summary["files"] == 457 and summary["expandedBytes"] == 299747655
             and summary["entryHeaders"] == document["entryHeaders"], "complete-outer-correspondence")
        need(len(observer.native) == 71 and len(observer.archives) == 74
             and sum(row["format"] == "jmod" for row in observer.archives) == 70, "genuine-selected-roster")
        counterpart_facts(observer.native, observer.archives, arena)
        original.verify_binding()
        arena.check()
        result = {"schemaVersion": 1, "kind": "mrk-intel-jdk-native-jvm-data-v1", "target": "x86_64-apple-darwin",
                  "archiveBytes": ARCHIVE_BYTES, "archiveSha256": ARCHIVE_SHA256,
                  "correspondenceSha256": CORRESPONDENCE_SHA256, "outer": summary,
                  "formatCounts": observer.formats,
                  "nativeMembers": sorted(observer.native, key=lambda item: item["name"]),
                  "unknownMembers": sorted(observer.unknown, key=lambda item: item["name"]),
                  "jvmMembers": sorted(observer.archives, key=lambda item: item["name"]),
                  "issuedReadBytes": arena.reads, "innerExpandedBytes": arena.expanded,
                  "prepublicationPeakReservedBytes": arena.peak,
                  "prepublicationPeakReservations": dict(arena.peaks),
                  "reservationMeaning": "explicit-owned-allocation-budget-not-total-interpreter-memory",
                  "nativeExecuted": False, "nativeClosure": False, "supplierAuthority": False}
        return Inspection(arena, result)
    except BaseException:
        arena.failed = True
        raise
    finally:
        if observer is not None:
            observer.dispose_current()


def _inspect_non_jdk(original, parser, specification):
    """Same algorithm for explicit tiny DATA fixtures; not a command pin API."""
    need(type(specification) is tuple and len(specification) == 5, "non-jdk-data-specification")
    component, size, digest, selected, required = specification
    need(type(component) is str and component in ("aapt2", "gradle", "bundletool")
         and uint(size) and 0 < size <= 256 * MIB and sha(digest)
         and type(selected) is tuple and type(required) is tuple and len(required) <= 1
         and all(type(row) is tuple and len(row) == 4 and type(row[0]) is str
                 and 0 < len(row[0]) <= 512 and uint(row[1]) and row[1] > 0 and sha(row[2])
                 and uint(row[3]) for row in required), "non-jdk-data-specification")
    arena = Arena(original)
    observer = None
    rows, retained_rows = [], 0
    try:
        arena.check()
        observer = _Observer(parser, arena, outer_selection=selected)
        # The original complete archive hash is verified by this parser BEFORE
        # any member callback. Each selected JAR's completed row and collector
        # hash are checked again before its copied ZIP view is independently read.
        report = parser.compile_archive(original, parser.Pin(component, size, digest),
                                        observer=observer, workspace=arena)
        def retain(row):
            nonlocal retained_rows
            arena.check()
            charge = 1536 + 8 * len(row[0]) + 8 * len(row[5] or "")
            arena.reserve_rows(charge)  # Coexists with the parser's OWN row book.
            retained_rows += charge
            rows.append(row)
        summary = report.consume_rows(retain)
        need(observer.current is None and summary["members"] == len(rows)
             and observer.selected_seen == set(observer.outer_selection), "non-jdk-complete-outer")
        for name, extent, whole_sha, mode in required:
            member = next((row for row in rows if row[0] == name), None)
            native = next((row for row in observer.native if row["name"] == name), None)
            need(member is not None and member[1:5] == ("file", mode, extent, whole_sha)
                 and native is not None and (native["bytes"], native["sha256"], native["mode"])
                 == (extent, whole_sha, mode), "non-jdk-required-native-row")
        original.verify_binding()
        arena.check()
        document = {"schemaVersion": 1, "kind": "mrk-intel-non-jdk-observation-data-v1",
                    "target": "x86_64-apple-darwin", "component": component,
                    "archiveBytes": size, "archiveSha256": digest,
                    "columns": list(parser.COLUMNS), "outer": summary, "rows": rows,
                    "completeOuterMemberHashes": True, "formatCounts": observer.formats,
                    "nativeMembers": sorted(observer.native, key=lambda item: item["name"]),
                    "unknownMembers": sorted(observer.unknown, key=lambda item: item["name"]),
                    "selectedInnerArchives": sorted(observer.archives, key=lambda item: item["name"]),
                    "uninspectedInnerArchives": sorted(observer.uninspected, key=lambda item: item["name"]),
                    "uninspectedInnerArchiveCount": len(observer.uninspected),
                    "innerInspectionScope": "fixed-selected-outer-jars-only",
                    "issuedReadBytes": arena.reads, "innerExpandedBytes": arena.expanded,
                    "prepublicationPeakReservedBytes": arena.peak,
                    "prepublicationPeakReservations": dict(arena.peaks),
                    "reservationMeaning": "explicit-owned-allocation-budget-not-total-interpreter-memory",
                    "remainingObligations": ["kotlin-shaded-jansi", "sdk-platform", "sdk-build-tools",
                                             "installed-loader-provider-custody", "native-Mac-qualification"],
                    "nativeExecuted": False, "nativeClosure": False, "supplierAuthority": False}
        return Inspection(arena, document)
    except BaseException:
        arena.failed = True
        rows.clear()
        # Preserve the original refusal if heap-accounting disposal also refuses.
        try:
            arena.release_rows(retained_rows)
        except BaseException:
            pass
        raise
    finally:
        if observer is not None:
            observer.dispose_current()


def inspect_non_jdk(original, component, parser):
    """Observe one of three fixed SOURCE archives; never native permission."""
    need(type(component) is str and component in ("aapt2", "gradle", "bundletool"),
         "non-jdk-component")  # Before touching the supplied original.
    specification = next(row for row in NON_JDK_ARCHIVES if row[0] == component)
    return _inspect_non_jdk(original, parser, specification)


def _complete_outer_inverse(rows, observer, arena):
    # Reserve both temporary maps/tuples before construction. All source rows
    # remain retained; no filtered list replaces the original outer inventory.
    charge = 8192 + sum(4096 + 16 * len(row[0]) for row in rows
                        if row[1] == "file" and row[-1] in ("zip", "jmod"))
    arena.reserve("other", charge)
    try:
        expected = {row[0]: (row[3], row[2], row[4], row[-1]) for row in rows
                    if row[1] == "file" and row[-1] in ("zip", "jmod")}
        actual = {item["name"]: (item["bytes"], item["mode"], item["sha256"], item["format"])
                  for item in observer.archives}
        arena.require(len(actual) == len(observer.archives) and actual == expected,
                      "complete-outer-inner-inverse")
    finally:
        arena.release("other", charge)


def _inspect_complete_non_jdk(original, parser, specification):
    # Private real-byte fixture seam, never a caller-controlled production pin.
    need(type(specification) is tuple and len(specification) == 3, "complete-non-jdk-specification")
    component, size, digest = specification
    need(type(component) is str and component in ("gradle", "sdk-platform", "sdk-build-tools")
         and uint(size) and 0 < size <= 256 * MIB and sha(digest), "complete-non-jdk-specification")
    arena = Arena(original)
    observer = None
    rows, retained_rows = [], 0
    try:
        arena.check()
        observer = _Observer(parser, arena, complete=True, top_level=True)
        report = parser.compile_archive(original, parser.Pin(component, size, digest),
                                        observer=observer, workspace=arena)
        def retain(row):
            nonlocal retained_rows
            arena.check()
            charge = 1536 + 8 * len(row[0]) + 8 * len(row[5] or "")
            arena.reserve_rows(charge)
            retained_rows += charge
            rows.append(row)
        summary = report.consume_rows(retain)
        arena.require(summary["members"] == len(rows), "complete-outer-row-count")
        _complete_census(observer, summary)
        _complete_outer_inverse(rows, observer, arena)
        original.verify_binding()
        arena.check()
        arena.facts(8192)
        document = {"schemaVersion": 1, "kind": "mrk-intel-complete-non-jdk-observation-data-v1",
                    "target": "x86_64-apple-darwin", "component": component,
                    "archiveBytes": size, "archiveSha256": digest,
                    "columns": list(parser.COLUMNS), "outer": summary, "rows": rows,
                    "completeOuterMemberHashes": True, "completeInnerCoverage": True,
                    "directoryMembers": summary["members"] - summary["files"],
                    "formatCounts": observer.formats,
                    "nativeMembers": sorted(observer.native, key=lambda item: item["name"]),
                    "foreignNativeMembers": sorted(observer.foreign, key=lambda item: item["name"]),
                    "unknownMembers": sorted(observer.unknown, key=lambda item: item["name"]),
                    "innerArchives": sorted(observer.archives, key=lambda item: item["name"]),
                    "uninspectedInnerArchives": sorted(observer.uninspected, key=lambda item: item["name"]),
                    "uninspectedInnerArchiveCount": len(observer.uninspected),
                    "innerInspectionScope": "all-complete-outer-zip-or-jmod",
                    "issuedReadBytes": arena.reads, "innerExpandedBytes": arena.expanded,
                    "prepublicationPeakReservedBytes": arena.peak,
                    "prepublicationPeakReservations": dict(arena.peaks),
                    "reservationMeaning": "explicit-owned-allocation-budget-not-total-interpreter-memory",
                    "remainingObligations": ["fresh-complete-target-reference", "target-native-role-review",
                                             "installed-loader-provider-custody", "native-Mac-qualification"],
                    "nativeExecuted": False, "nativeClosure": False, "supplierAuthority": False}
        return Inspection(arena, document)
    except BaseException:
        arena.failed = True
        rows.clear()
        try:
            arena.release_rows(retained_rows)
        except BaseException:
            pass
        raise
    finally:
        if observer is not None:
            observer.dispose_current()


def inspect_complete_non_jdk(original, component, parser):
    """Fully observe one fixed public Gradle/SDK archive; never native permission."""
    need(type(component) is str and component in ("gradle", "sdk-platform", "sdk-build-tools"),
         "complete-non-jdk-component")
    specification = next(row for row in COMPLETE_NON_JDK_ARCHIVES if row[0] == component)
    return _inspect_complete_non_jdk(original, parser, specification)
