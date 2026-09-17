"""Inert Windows reader contracts, not Windows qualification.

Only dictionaries, synthetic handle numbers and bounded byte buffers are used.
Native calls/exit are substituted or refused before entry; no DLL is loaded. Fake
relative opens/mutations prove call ordering, not NTFS, ABI, ACL or reparse
semantics. A substituted fail-stop proves retained references, not process/IO
finality or successful native CloseHandle receipts. No filesystem fixtures.
Focused leaves read bound fixture source and select named pure reducers. The
ACL ordering leaf also selects two original methods with exclusively fake
capabilities; no fixture module, native observer or constructor is imported/run.
"""
from __future__ import annotations

import ast
import copy
import importlib
import json
import os
import struct
import sys
import unittest
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import api
from mobile_release.api import _snapshot as policy
from mobile_release.api import _snapshot_windows as windows
from mobile_release.api import _snapshot_windows_native as native
from mobile_release.api.contracts import ApiError

DEVICE = r"\Device\HarddiskVolume7"
CONFIG = "release/mobile-release.json"
GRADLE = b'plugins { id("com.android.application") }\napplicationId = "org.fixture.app"\n'


def _draft() -> dict:
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def _batch(entries: list[native.Entry]) -> bytes:
    """Encode actual FILE_ID_EXTD_DIR_INFO offsets, without ctypes."""
    if not entries:
        raise ValueError("An empty directory is EOF, not a success buffer")
    records = []
    for index, entry in enumerate(entries):
        name = entry.name.encode("utf-16-le")
        length = (88 + len(name) + 7) & ~7
        record = bytearray(length)
        struct.pack_into("<I", record, 0, length if index + 1 < len(entries) else 0)
        struct.pack_into("<II", record, 56, entry.attributes, len(name))
        # Deliberately nonzero garbage for undefined ordinary-entry tag.
        struct.pack_into("<I", record, 68, entry.reparse_tag if entry.reparse_tag is not None else 0xDEADBEEF)
        record[72:88] = entry.file_id
        record[88:88 + len(name)] = name
        records.append(bytes(record))
    return b"".join(records)


@dataclass
class _Node:
    path: str
    data: bytes | None
    meta: native.Metadata
    children: dict[str, "_Node"] = field(default_factory=dict)
    normalized: str | None = None
    batches: list[bytes | None | Exception] | None = None
    chunks: list[bytes] | None = None

    def entry(self, name: str) -> native.Entry:
        return native.Entry(name, self.meta.attributes, self.meta.file_id, self.meta.reparse_tag)


class _FakeExit(BaseException):
    pass


class _Fake(native._HandleOwner):
    """Finite in-memory adapter; the production owner still controls closing."""

    def __init__(self, root_parts=("selected",)):
        super().__init__()
        self._exit = self._failstop  # Never retain os._exit as a usable test seam.
        self._check_budget = lambda: None
        self.root_parts = tuple(root_parts)
        self.root = "C:\\" + "\\".join(root_parts)
        self.serial = 0
        self.volume = self._node(DEVICE + "\\", None)
        self.project = self.volume
        for part in self.root_parts:
            child = self._node(self.project.path.rstrip("\\") + "\\" + part, None)
            self.project.children[part] = child
            self.project = child
        self.handles: dict[int, _Node] = {}
        self.next_handle = 100
        self.trace: list[tuple] = []
        self.specs: list[native.OpenSpec] = []
        self.open_lifetimes: list[tuple[int, ...]] = []
        self.aliases: dict[tuple[str, str], _Node] = {}
        self.open_errors: dict[str, str] = {}
        self.close_results: dict[int, object] = {}
        self.mapping_targets = [DEVICE]
        self.mapping_calls = 0
        self.filesystem = "NTFS"
        self.reparse_parent = "refuse"
        self.before_open = lambda parent, name, directory: None
        self.before_metadata = lambda handle: None
        self.before_read = lambda handle, count: None
        self._enumerations: dict[int, list] = {}
        self._positions: dict[int, int] = {}
        self._chunks: dict[int, list[bytes]] = {}

    def _node(self, path: str, data: bytes | None) -> _Node:
        self.serial += 1
        directory = data is None
        return _Node(path, data, native.Metadata(
            0x10 if directory else 0x20, 17, self.serial.to_bytes(16, "little"),
            directory, False, 1, 0 if directory else len(data), 101, 202, 303,
            0 if directory else None,
        ))

    def add(self, relative: str, data: bytes | None = None) -> _Node:
        parent = self.project
        parts = relative.split("/")
        for index, name in enumerate(parts):
            if name not in parent.children:
                child_data = data if index == len(parts) - 1 else None
                parent.children[name] = self._node(parent.path.rstrip("\\") + "\\" + name, child_data)
            parent = parent.children[name]
        return parent

    def config(self, data: bytes | None = None) -> _Node:
        return self.add(CONFIG, json.dumps(_draft()).encode() if data is None else data)

    def _step(self, *event) -> None:
        self._check_budget()
        self.trace.append(event)

    def _failstop(self, code: int) -> None:
        self.trace.append(("failstop", code, tuple(self._owned)))
        raise _FakeExit

    def drive_mapping(self, drive: str) -> str:
        self._step("mapping", drive)
        target = self.mapping_targets[min(self.mapping_calls, len(self.mapping_targets) - 1)]
        self.mapping_calls += 1
        return native.parse_drive_mapping((target + "\0\0").encode("utf-16-le"))

    def open_root(self, device: str) -> int:
        return self._open(native.open_spec(None, device + "\\", True))

    def open_child(self, parent: int, name: str, directory: bool) -> int:
        self._require_owned(parent)
        return self._open(native.open_spec(parent, name, directory))

    def _open(self, spec: native.OpenSpec) -> int:
        self._capacity()
        self._step("open", spec.parent, spec.name, spec.directory)
        self.specs.append(spec)
        self.open_lifetimes.append(tuple(self._owned))
        self.before_open(spec.parent, spec.name, spec.directory)
        if spec.parent is None:
            if spec.name != DEVICE + "\\":
                raise native.NativeError("unsupported")
            node = self.volume
        else:
            parent = self.handles[spec.parent]
            if parent.meta.attributes & native.REPARSE_ATTRIBUTE and self.reparse_parent == "refuse":
                raise native.NativeError("unsafe")
            path = parent.path.rstrip("\\") + "\\" + spec.name
            if path in self.open_errors:
                raise native.NativeError(self.open_errors[path])
            # Always the original parent dictionary, never a reconstructed path
            # or a mutable ancestor's alternative subtree.
            node = parent.children.get(spec.name) or self.aliases.get((parent.path, spec.name))
            if node is None:
                raise native.NativeError("missing")
        if (node.data is None) != spec.directory:
            raise native.NativeError("unsafe")
        handle = self.next_handle
        self.next_handle += 4
        self._finish_open(0, handle, 0, 1, (spec, node))
        self.handles[handle] = node
        self._positions[handle] = 0
        if node.chunks is not None:
            self._chunks[handle] = list(node.chunks)
        return handle

    def metadata(self, handle: int) -> native.Metadata:
        self._require_owned(handle)
        self._step("metadata", handle)
        self.before_metadata(handle)
        return self.handles[handle].meta

    def normalized_name(self, handle: int) -> str:
        self._require_owned(handle)
        self._step("name", handle)
        node = self.handles[handle]
        return node.path if node.normalized is None else node.normalized

    def require_ntfs(self, handle: int) -> None:
        self._require_owned(handle)
        self._step("volume", handle)
        if self.filesystem != "NTFS":
            raise native.NativeError("unsupported")

    def directory_batch(self, handle: int, restart: bool) -> bytes | None:
        self._require_owned(handle)
        self._step("directory", handle, restart)
        node = self.handles[handle]
        if restart:
            entries = [child.entry(name) for name, child in node.children.items()]
            self._enumerations[handle] = (list(node.batches) if node.batches is not None
                                          else [_batch(entries)] if entries else [])
        batches = self._enumerations[handle]
        value = batches.pop(0) if batches else None
        if isinstance(value, Exception):
            raise value
        return value

    def read(self, handle: int, count: int) -> bytes:
        self._require_owned(handle)
        self._step("read", handle, count)
        self.before_read(handle, count)
        if handle in self._chunks:
            return self._chunks[handle].pop(0) if self._chunks[handle] else b""
        node = self.handles[handle]
        start = self._positions[handle]
        block = node.data[start:start + count]
        self._positions[handle] += len(block)
        return block

    def _raw_close(self, handle: int) -> bool:
        self.trace.append(("close", handle, tuple(self._owned)))
        if handle in self._owned:
            raise AssertionError("A close slot was not retired first")
        result = self.close_results.get(handle, True)
        if isinstance(result, BaseException):
            raise result
        return result


class _Buffer:
    def __init__(self, count: int):
        self.raw = b"\0" * count


def _shim(error: int = 0, **functions) -> native.Native:
    """Python-only call/arena seam: no ctypes and no claim to emulate its ABI."""
    owner = native.Native.__new__(native.Native)
    native._HandleOwner.__init__(owner)

    def stop(code):
        raise _FakeExit(code)

    owner._exit = stop
    owner._check_budget = lambda: None
    owner._owned = [101, 202]
    owner._b = SimpleNamespace(
        c=SimpleNamespace(create_string_buffer=_Buffer, byref=lambda value: value,
                          get_last_error=lambda: error),
        U32=lambda value: SimpleNamespace(value=value),
        k=SimpleNamespace(CloseHandle=lambda handle: True, **functions),
    )
    return owner


class WindowsSnapshotPureTests(unittest.TestCase):
    def _dacl_reducers(self):
        signatures = {"_dacl_policy": ("data",), "_dacl_comparison": ("saved", "observed", "role"),
                      "_dacl_comparison_valid": ("value",), "_installed_deny_data_dacl": ("data",),
                      "_failure_diagnostic": ("case", "nonce", "stage", "reason", "fixture_state",
                                              "reader_state", "output_state", "comparison")}
        source = (Path(__file__).resolve().parents[1] / "native_desktop_snapshot_windows.py").read_bytes()
        self.assertLessEqual(len(source), 128 * 1024)
        parsed = ast.parse(source, filename="reviewed-dacl-restoration-source")
        selected = [node for node in parsed.body if getattr(node, "name", None) in signatures]
        self.assertCountEqual([node.name for node in selected], signatures)
        safe = {"type": type, "str": str, "dict": dict, "tuple": tuple, "bytes": bytes, "bool": bool,
                "int": int, "len": len, "range": range, "any": any}
        nodes = (ast.FunctionDef, ast.arguments, ast.arg, ast.Expr, ast.Constant, ast.Name, ast.Load, ast.Store,
                 ast.Assign, ast.AugAssign, ast.For, ast.If, ast.IfExp, ast.Return, ast.Call, ast.Attribute,
                 ast.Tuple, ast.List, ast.Dict, ast.Subscript, ast.Slice, ast.BoolOp, ast.BinOp, ast.UnaryOp,
                 ast.Compare, ast.operator, ast.unaryop, ast.boolop, ast.cmpop)
        for definition in selected:
            self.assertIs(type(definition), ast.FunctionDef)
            self.assertFalse(definition.decorator_list or definition.returns or definition.type_comment
                             or getattr(definition, "type_params", []))
            args = definition.args
            self.assertEqual(tuple(arg.arg for arg in args.args), signatures[definition.name])
            self.assertFalse(args.posonlyargs or args.vararg or args.kwonlyargs or args.kwarg or args.kw_defaults)
            self.assertTrue(all(arg.annotation is None and arg.type_comment is None for arg in args.args))
            self.assertEqual([ast.literal_eval(value) for value in args.defaults],
                             [None] if definition.name == "_failure_diagnostic" else [])
            self.assertEqual(sum(isinstance(node, ast.FunctionDef) for node in ast.walk(definition)), 1)
            for node in ast.walk(definition):
                self.assertIsInstance(node, nodes)
                if isinstance(node, ast.Name):
                    self.assertFalse(node.id.startswith("__"))
                if isinstance(node, ast.Attribute):
                    self.assertIn(node.attr, ("from_bytes", "append", "encode"))
                    if node.attr != "encode":
                        self.assertIsInstance(node.value, ast.Name)
                        self.assertEqual((node.value.id, node.attr),
                                         ("int", "from_bytes") if node.attr == "from_bytes" else ("aces", "append"))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertIn(node.func.id, {*safe, *signatures})
        namespace = {"__builtins__": safe}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "reviewed-dacl-pure-reducers", "exec",
                     dont_inherit=True), namespace)
        self.assertEqual(set(namespace), {"__builtins__", *signatures})
        return namespace, parsed

    def _dacl_bytes(self, *, aces=None, control=0x9004, revision=2, offset=20, capacity=None, tail=b""):
        world = bytes.fromhex("010100000000000100000000")
        if aces is None:
            aces = (struct.pack("<BBHI", 1, 0, 20, 1) + world,
                    struct.pack("<BBHI", 0, 0, 20, 0x1F01FF) + world)
        header = struct.pack("<BBHIIII", 1, 0, control, 0, 0, 0, offset)
        if not offset:
            return header + tail
        used = 8 + sum(map(len, aces))
        capacity = used if capacity is None else capacity
        return (header + b"\xa5" * (offset - 20) + struct.pack("<BBHHH", revision, 0, capacity, len(aces), 0)
                + b"".join(aces) + b"\x5a" * (capacity - used) + tail)

    def test_dacl_restoration_compares_complete_policy_not_placement(self):
        reducers, _ = self._dacl_reducers()
        parse, compare, scalar = (reducers[name] for name in ("_dacl_policy", "_dacl_comparison", "_dacl_comparison_valid"))
        original = self._dacl_bytes()
        policy = parse(original)
        self.assertEqual(policy[:4], (0x9004, True, False, 2))
        self.assertEqual(tuple(map(len, policy[4])), (20, 20))
        for variant in (original, self._dacl_bytes(offset=24), self._dacl_bytes(offset=64, capacity=256),
                        self._dacl_bytes(capacity=256, tail=b"unused capacity")):
            facts, equal = compare(original, variant, "denied-directory")
            self.assertIs(equal, True)
            self.assertTrue(scalar(facts))
            self.assertEqual(facts["lengthEqual"], len(original) == len(variant))
            self.assertEqual(facts["bytesEqual"], original == variant)
            self.assertTrue(all(value is True for key, value in facts.items()
                                if key not in ("role", "lengthEqual", "bytesEqual")))
        placed = self._dacl_bytes(offset=24)
        alternate_gap = placed[:20] + b"\x11" * 4 + placed[24:]
        facts, equal = compare(placed, alternate_gap, "denied-file")
        self.assertTrue(equal and facts["lengthEqual"] and not facts["bytesEqual"])
        for bit, field in ((0x1000, "protectedEqual"), (8, "defaultedEqual"),
                           (0x100, "autoInheritanceEqual"), (0x400, "autoInheritanceEqual")):
            facts, equal = compare(original, self._dacl_bytes(control=0x9004 ^ bit), "denied-file")
            self.assertFalse(equal)
            self.assertTrue(scalar(facts))
            self.assertIs(facts["controlEqual"], False)
            self.assertIs(facts[field], False)  # Including resulting 0x0400, never masked.
        aces = policy[4]
        variants = [(aces[::-1], "orderedAcesEqual"), (aces[:1], "orderedAcesEqual"),
                    (aces + aces[:1], "orderedAcesEqual")]
        for offset in (0, 1, 4, 10, 15, 16, 19):
            changed = bytearray(aces[0]); changed[offset] ^= 1
            variants.append(((bytes(changed), aces[1]), "orderedAcesEqual"))
        for changed, field in variants:
            facts, equal = compare(original, self._dacl_bytes(aces=changed), "denied-file")
            self.assertFalse(equal)
            self.assertTrue(facts["savedShapeValid"] and facts["observedShapeValid"] and scalar(facts))
            self.assertIs(facts[field], False)
        for flags in (1, 2, 4, 8, 16, 31):
            changed = aces[0][:1] + bytes([flags]) + aces[0][2:]
            facts, equal = compare(original, self._dacl_bytes(aces=(changed, aces[1])), "denied-file")
            self.assertFalse(equal)
            self.assertIs(facts["orderedAcesEqual"], False)
        for count in (2, 15):
            sid = bytes([1, count]) + b"\0\0\0\0\0\x05" + struct.pack("<" + "I" * count, *range(count))
            ace = struct.pack("<BBHI", 0, 0, 8 + len(sid), 0x1F01FF) + sid
            descriptor = self._dacl_bytes(aces=(ace,))
            self.assertEqual(parse(descriptor)[4], (ace,))
            self.assertTrue(compare(descriptor, self._dacl_bytes(aces=(ace,), offset=24, capacity=256), "denied-file")[1])
        facts, equal = compare(original, self._dacl_bytes(revision=4), "denied-file")
        self.assertFalse(equal)
        self.assertIs(facts["aclRevisionEqual"], False)
        self.assertIs(facts["orderedAcesEqual"], True)
        states = [self._dacl_bytes(control=0x8000, offset=0), self._dacl_bytes(offset=0),
                  self._dacl_bytes(aces=()), original]
        for index, left in enumerate(states):
            self.assertIsNotNone(parse(left))
            for other, right in enumerate(states):
                facts, equal = compare(left, right, "denied-file")
                self.assertEqual(equal, index == other)
                self.assertTrue(scalar(facts))
        # Counted ACEs, not allocated bytes: lowering AceCount is a policy change,
        # even when the former next ACE is now valid unused ACL capacity.
        changed = bytearray(original); struct.pack_into("<H", changed, 24, 1)
        self.assertIsNotNone(parse(bytes(changed)))
        self.assertFalse(compare(original, bytes(changed), "denied-file")[1])

    def test_dacl_restoration_rejects_malformed_and_unsupported_layouts(self):
        reducers, _ = self._dacl_reducers()
        parse, compare = reducers["_dacl_policy"], reducers["_dacl_comparison"]
        original = self._dacl_bytes()

        def changed(offset, replacement):
            return original[:offset] + replacement + original[offset + len(replacement):]

        invalid = [None, True, 1, "descriptor", bytearray(original), memoryview(original), original + bytes(16385),
                   changed(0, b"\x02"), changed(1, b"\x01"), changed(21, b"\x01"), changed(26, b"\x01\x00")]
        for control in (0, 0x1004, 0x9000, 0x8004 | 1, 0x8004 | 2, 0x8004 | 0x10,
                        0x8004 | 0x20, 0x8004 | 0x40, 0x8004 | 0x80, 0x8004 | 0x200,
                        0x8004 | 0x800, 0x8004 | 0x2000, 0x8004 | 0x4000):
            invalid.append(changed(2, struct.pack("<H", control)))
        for field in (4, 8, 12):  # No owner/group/SACL projection or hidden overlap.
            for offset in (1, 4, 16, 20, 28, 0xFFFFFFFC):
                invalid.append(changed(field, struct.pack("<I", offset)))
        for offset in (4, 16, 21, 64, 0xFFFFFFFC):
            invalid.append(changed(16, struct.pack("<I", offset)))
        for revision in (0, 1, 3, 5, 255):
            invalid.append(changed(20, bytes([revision])))
        for size in (0, 4, 8, 28, 47, 49, 52, 65532):
            invalid.append(changed(22, struct.pack("<H", size)))
        for count in (3, 65535):
            invalid.append(changed(24, struct.pack("<H", count)))
        for offset in (28, 48):
            for flag in (0x20, 0x40, 0x80, 0xFF):
                invalid.append(changed(offset + 1, bytes([flag])))
            for length in (0, 4, 16, 19, 21, 24, 65532):
                invalid.append(changed(offset + 2, struct.pack("<H", length)))
            for revision in (0, 2):
                invalid.append(changed(offset + 8, bytes([revision])))
            for count in (0, 2, 16, 255):
                invalid.append(changed(offset + 9, bytes([count])))
        sid = original[36:48]
        for ace_type in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 17, 18, 19, 20, 21, 255):
            # Even a bounded, aligned body is not an opaque supported ACE.
            body = (struct.pack("<I", 3) + b"g" * 32 + sid if ace_type in (5, 6)
                    else sid + b"artx\0\0\0\0" if ace_type in (9, 10, 11, 12) else sid)
            ace = struct.pack("<BBHI", ace_type, 0, 8 + len(body), 1) + body
            invalid.append(self._dacl_bytes(aces=(ace,)))
        padded = bytearray(original[28:48] + b"\0" * 4); struct.pack_into("<H", padded, 2, 24)
        invalid.append(self._dacl_bytes(aces=(bytes(padded),)))  # In-ACE surplus cannot be normalized.
        invalid.extend(original[:end] for end in range(len(original)))
        for value in invalid:
            with self.subTest(kind=type(value).__name__, size=len(value) if isinstance(value, (bytes, bytearray)) else None):
                self.assertIsNone(parse(value))
                facts, equal = compare(original, value, "denied-file")
                self.assertFalse(equal)
                self.assertIs(facts["savedShapeValid"], True)
                self.assertIs(facts["observedShapeValid"], False)
                self.assertTrue(reducers["_dacl_comparison_valid"](facts))
                self.assertTrue(all(facts[key] is None for key in ("presenceEqual", "nullEqual", "controlEqual",
                    "protectedEqual", "defaultedEqual", "autoInheritanceEqual", "aclRevisionEqual", "orderedAcesEqual")))

    def test_dacl_pair_admission_precedes_mutation_and_original_restore_counts(self):
        reducers, parsed = self._dacl_reducers()
        fixture = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "Fixture")
        selected = [node for node in fixture.body if isinstance(node, ast.FunctionDef)
                    and node.name in ("deny_data", "restore")]
        self.assertEqual([node.name for node in selected], ["deny_data", "restore"])
        # Execute original control flow ONLY with the sealed fake capabilities
        # below. No fixture module/constructor, ctypes, native binding or path IO.
        class Refused(Exception):
            pass

        def require(value, code):
            if not value:
                raise Refused(code)

        safe = {"len": len, "str": str, "bytes": bytes, "bool": bool, "reversed": reversed}
        namespace = {"__builtins__": safe, "require": require, "FixtureFailure": Refused,
                     **{key: reducers[key] for key in ("_dacl_policy", "_dacl_comparison", "_installed_deny_data_dacl")}}
        for definition in selected:
            self.assertFalse(definition.decorator_list or definition.args.defaults or definition.args.kw_defaults)
            self.assertEqual([arg.arg for arg in definition.args.args], ["self"])
            self.assertIsNone(definition.returns.value)
            self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom, ast.ClassDef, ast.Global, ast.Nonlocal))
                                 for node in ast.walk(definition)))
            for call in (node for node in ast.walk(definition) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                self.assertIn(call.func.id, {*safe, *namespace})
        exec(compile(ast.Module(body=selected, type_ignores=[]), "reviewed-dacl-flow-with-fake-capabilities", "exec",
                     dont_inherit=True), namespace)

        class Buffer:
            def __init__(self, size):
                self.raw = bytes(size)
            def __len__(self):
                return len(self.raw)
            def __getitem__(self, item):
                return self.raw[item]

        scalar = lambda value=0: SimpleNamespace(value=value)
        test = self

        class Project:
            def __truediv__(self, relative):
                test.assertIn(relative, ("read-denied/build.gradle", "list-denied"))
                return relative  # A string label, not a filesystem-capable Path.

        class Native:
            def __init__(self, baselines, readbacks=None, failed_setter=None, failed_close=None, reported=None):
                self.c = SimpleNamespace(create_string_buffer=Buffer, byref=lambda value: value,
                                         c_int32=scalar, c_void_p=scalar)
                self.U32 = self.U16 = scalar
                self.a = SimpleNamespace(**{name: name for name in ("GetKernelObjectSecurity", "GetSecurityDescriptorControl",
                    "CreateWellKnownSid", "InitializeAcl", "AddAccessDeniedAceEx", "AddAccessAllowedAceEx",
                    "SetSecurityInfo", "GetSecurityDescriptorDacl")})
                self.baselines = dict(zip((101, 102), baselines))
                self.current = dict(self.baselines)
                self.readbacks = readbacks or dict(self.baselines)
                self.failed_setter, self.failed_close, self.reported = failed_setter, failed_close, reported or {}
                self.held, self.retained_arenas, self.events, self.restore_calls = [], {}, [], set()
            def open(self, path, access):
                test.assertEqual(access, 0x60080)
                handle = 101 + len(self.held)
                self.held.append(handle); self.events.append(("open", handle))
                return handle
            def retain(self, label, items):
                test.assertNotIn(label, self.retained_arenas)
                self.retained_arenas[label] = items
            def identity(self, handle):
                test.assertIn(handle, self.held)
                return (17, handle.to_bytes(16, "little"))
            def call(self, function, args, keep=(), *, kind="boolean"):
                if function == "GetKernelObjectSecurity":
                    handle, flags, buffer, limit, needed = args
                    test.assertEqual((flags, limit), (4, 16384))
                    data = self.current[handle]
                    buffer.raw = data[:limit] + bytes(max(0, limit - len(data)))
                    needed.value = self.reported.get(handle, len(data)) if handle in self.restore_calls else len(data)
                    self.events.append(("get", handle))
                elif function == "GetSecurityDescriptorControl":
                    saved, control, revision = args
                    control.value, revision.value = int.from_bytes(saved.raw[2:4], "little"), saved.raw[0]
                    self.events.append(("control", control.value))
                elif function == "GetSecurityDescriptorDacl":
                    saved, present, pointer, defaulted = args
                    present.value, defaulted.value, pointer.value = 1, 0, saved
                elif function == "CreateWellKnownSid":
                    args[3].value = 12
                elif function == "SetSecurityInfo":
                    handle, object_type, security, owner, group, acl, sacl = args
                    test.assertEqual((object_type, owner, group, sacl, kind), (1, None, None, None, "zero"))
                    if isinstance(acl, SimpleNamespace):
                        test.assertTrue(any(acl.value is items[0] for items in self.retained_arenas.values()))
                        self.events.append(("restore", handle, security))
                        if handle == self.failed_setter:
                            raise Refused("mock_returned_setter_error")
                        self.restore_calls.add(handle)
                        self.current[handle] = self.readbacks[handle]
                    else:
                        self.events.append(("deny", handle, security))
                        test.assertEqual(security, 4 | 0x80000000)
                        self.current[handle] = test._dacl_bytes()
                else:
                    test.assertIn(function, ("InitializeAcl", "AddAccessDeniedAceEx", "AddAccessAllowedAceEx"))
                return 0 if kind == "zero" else 1
            def close(self, handle):
                self.events.append(("close", handle))
                if handle == self.failed_close:
                    raise Refused("mock_consuming_close_unknown")
                test.assertIn(handle, self.held)
                self.held.remove(handle)
            def close_all(self):
                test.assertEqual(self.held, [])
                self.events.append(("all-closed",))

        def make(baselines, **options):
            return SimpleNamespace(native=Native(baselines, **options), project=Project(), journal=[],
                thread=None, alias=None, case="acl-type", restored=False, dacl_comparison=None,
                checks={key: None for key in ("fileAccessDenied", "directoryAccessDenied", "accessibleSiblingRead",
                                             "configDirectoryRefused", "daclRestored")})

        for controls in ((0x8004, 0x9404), (0x9004, 0x8404), (0x8404, 0x8004), (0x9404, 0x9004)):
            baselines = tuple(self._dacl_bytes(control=control) for control in controls)
            readbacks = {handle: self._dacl_bytes(control=control, offset=24, capacity=256)
                         for handle, control in zip((101, 102), controls)}
            owner = make(baselines, readbacks=readbacks)
            namespace["deny_data"](owner)
            originals = tuple(record["baseline"] for record in owner.journal)
            self.assertEqual(originals, baselines)
            self.assertTrue(all(type(value) is bytes for value in originals))
            events = owner.native.events
            first_mutation = next(index for index, event in enumerate(events) if event[0] == "deny")
            self.assertEqual([event for event in events[:first_mutation] if event[0] == "get"], [("get", 101), ("get", 102)])
            self.assertEqual(len([event for event in events[:first_mutation] if event[0] == "control"]), 2)
            self.assertEqual([record["changed"] for record in owner.journal], [True, True])
            namespace["restore"](owner)
            security = [4 | (0x80000000 if control & 0x1000 else 0x20000000) for control in controls]
            self.assertEqual([event for event in events if event[0] == "restore"], [("restore", 102, security[1]), ("restore", 101, security[0])])
            self.assertEqual([event for event in events if event[0] == "close"], [("close", 102), ("close", 101)])
            self.assertEqual(owner.checks["daclRestored"], 2)
            self.assertIs(type(owner.checks["daclRestored"]), int)
            self.assertEqual((owner.journal, owner.native.held, owner.native.retained_arenas), ([], [], {}))
            self.assertTrue(owner.restored)
            self.assertIsNone(owner.dacl_comparison)
            self.assertTrue(all(owner.checks[key] is None for key in owner.checks if key != "daclRestored"))

        original = self._dacl_bytes(control=0x8404)
        unsupported = [self._dacl_bytes(control=0x8000, offset=0), self._dacl_bytes(control=0x8404, offset=0), b"malformed"]
        unsupported.extend(self._dacl_bytes(control=0x8404 | bit) for bit in (8, 0x100, 1, 2, 0x200, 0x4000))
        for bad in unsupported:
            for baselines in ((bad, original), (original, bad)):
                owner = make(baselines)
                with self.assertRaises(Refused):
                    namespace["deny_data"](owner)
                self.assertFalse(any(event[0] in ("deny", "restore") for event in owner.native.events))
                self.assertFalse(owner.restored)
                self.assertIsNone(owner.checks["daclRestored"])
                self.assertTrue(all(record["changed"] is False for record in owner.journal))
                if baselines[0] == original:
                    self.assertEqual(owner.journal[0]["baseline"], original)
                    self.assertEqual(owner.native.held, [101, 102])
        owner = make((original, original))
        namespace["deny_data"](owner)
        owner.journal[1]["saved"].raw = self._dacl_bytes(control=0x8004) + bytes(16384 - len(original))
        with self.assertRaisesRegex(Refused, "^saved_dacl_unsupported$"):
            namespace["restore"](owner)
        self.assertEqual(tuple(record["baseline"] for record in owner.journal), (original, original))
        self.assertFalse(any(event[0] == "restore" for event in owner.native.events))
        self.assertIsNone(owner.checks["daclRestored"])
        for handle, role in ((101, "denied-file"), (102, "denied-directory")):
            readbacks = {101: original, 102: original}
            readbacks[handle] = self._dacl_bytes(control=0x8004)  # Only resulting auto-inherited differs.
            owner = make((original, original), readbacks=readbacks)
            namespace["deny_data"](owner)
            with self.assertRaisesRegex(Refused, "^dacl_restoration_not_confirmed$"):
                namespace["restore"](owner)
            self.assertEqual(owner.dacl_comparison["role"], role)
            self.assertIs(owner.dacl_comparison["autoInheritanceEqual"], False)
            self.assertEqual(tuple(record["baseline"] for record in owner.journal), (original, original))
            self.assertIsNone(owner.checks["daclRestored"])
            self.assertFalse(owner.restored)
            self.assertIn(handle, owner.native.held)
        for options in ({"failed_setter": 102}, {"failed_close": 101}, {"reported": {102: 16385}}):
            owner = make((original, original), **options)
            namespace["deny_data"](owner)
            with self.assertRaises(Refused):
                namespace["restore"](owner)
            self.assertIsNone(owner.checks["daclRestored"])
            self.assertFalse(owner.restored)
            self.assertTrue(owner.journal and owner.native.retained_arenas)
            if "reported" in options:
                self.assertIs(owner.dacl_comparison["observedShapeValid"], False)
                self.assertIsNone(owner.dacl_comparison["lengthEqual"])
                self.assertIsNone(owner.dacl_comparison["bytesEqual"])

    def test_dacl_comparison_diagnostic_schema_and_budgets(self):
        reducers, _ = self._dacl_reducers()
        compare, scalar, reduce = (reducers[name] for name in ("_dacl_comparison", "_dacl_comparison_valid", "_failure_diagnostic"))
        original = self._dacl_bytes(control=0x8404)
        mismatch = self._dacl_bytes(control=0x8004)
        facts, equal = compare(original, mismatch, "denied-directory")
        self.assertFalse(equal)
        arguments = {"case": "acl-type", "nonce": "a" * 64, "stage": "restoration",
            "reason": "dacl_restoration_not_confirmed", "fixture_state": (True, True, True, True, True, False, True, False),
            "reader_state": (1, True, True, False, True), "output_state": (False, 0, 0), "comparison": facts}
        prefix = b"MRK_WINDOWS_SNAPSHOT_FAILURE_V1 "
        raw = reduce(**arguments)
        self.assertLessEqual(len(raw), 1024)
        parsed = json.loads(raw[len(prefix):-1])
        self.assertEqual(parsed["comparison"], facts)
        self.assertEqual(set(parsed), {"schemaVersion", "scope", "id", "nonce", "stage", "code", "comparison"})
        self.assertEqual(set(facts), {"role", "savedShapeValid", "observedShapeValid", "lengthEqual", "bytesEqual",
            "presenceEqual", "nullEqual", "controlEqual", "protectedEqual", "defaultedEqual", "autoInheritanceEqual",
            "aclRevisionEqual", "orderedAcesEqual"})
        policy = tuple(key for key in facts if key not in ("role", "savedShapeValid", "observedShapeValid", "lengthEqual", "bytesEqual"))
        for observed in (b"", b"invalid", bytes([2]) + original[1:], None, original + bytes(16385)):
            unknown, equal = compare(original, observed, "denied-file")
            self.assertFalse(equal)
            self.assertTrue(scalar(unknown))
            self.assertTrue(all(unknown[key] is None for key in policy))
            frame = reduce(**{**arguments, "comparison": unknown})
            self.assertEqual(json.loads(frame[len(prefix):-1])["comparison"], unknown)
            for key in policy:
                self.assertIsNone(reduce(**{**arguments, "comparison": {**unknown, key: True}}))
        for saved, observed in ((b"", b""), (b"invalid", b"invalid"), (b"invalid", None), (b"", original)):
            unknown, equal = compare(saved, observed, "denied-file")
            self.assertFalse(equal)
            self.assertTrue(scalar(unknown))
            self.assertEqual(json.loads(reduce(**{**arguments, "comparison": unknown})[len(prefix):-1])["comparison"], unknown)
        bad_objects = [None, [], True, {}, {**facts, "extra": "private-canary"}, {**facts, "role": "private-canary"}]
        for key in facts:
            bad_objects.append({name: value for name, value in facts.items() if name != key})
            for value in (0, 1, 0.0, "true", [], {}, "private-canary"):
                bad_objects.append({**facts, key: value})
        bad_objects.extend(({**facts, "lengthEqual": None}, {**facts, "bytesEqual": True},
                            {**facts, "savedShapeValid": False}, {**facts, "controlEqual": True}))
        for malformed in bad_objects:
            self.assertFalse(scalar(malformed))
            if malformed is not None:  # None omits the optional object, never encodes JSON null.
                self.assertIsNone(reduce(**{**arguments, "comparison": malformed}))
        for key, value in (("case", "short-alias"), ("stage", "setup"), ("reason", "fixture_dacl_not_effective")):
            self.assertIsNone(reduce(**{**arguments, key: value}))
        for index in range(8):
            changed = list(arguments["fixture_state"]); changed[index] = not changed[index]
            self.assertIsNone(reduce(**{**arguments, "fixture_state": tuple(changed)}))
        for reader in ((1, False, None, None, None), (1, True, False, False, True),
                       (1, True, True, True, True), (1, True, True, False, False)):
            self.assertIsNone(reduce(**{**arguments, "reader_state": reader}))
        engine_error = b"Mobile Release Kit desktop engine rejected the request or transport.\n"
        available = 65536 - len(raw) - len(engine_error)
        self.assertEqual(reduce(**{**arguments, "output_state": (False, 3, available)}), raw)
        self.assertIsNone(reduce(**{**arguments, "output_state": (False, 3, available + 1)}))
        self.assertIsNone(reduce(**{**arguments, "output_state": (True, 0, 0)}))
        # Literal maximum-width DATA, not the Rust reducer or any native process.
        widest = {key: ("denied-directory" if key == "role" else False) for key in facts}
        widest["savedShapeValid"] = widest["observedShapeValid"] = True
        self.assertTrue(scalar(widest))
        marker = reduce(**{**arguments, "comparison": widest})
        self.assertLessEqual(len(marker), 1024)
        summary = {"schemaVersion": 1, "scope": "windows-static-snapshot-native-v1", "id": "acl-type",
            "exitCode": -2147483648, "ownerErrorCode": "snapshot_unavailable",
            "fixtureFailure": {"status": "valid", "stage": "restoration", "code": "dacl_restoration_not_confirmed",
                               "comparison": widest}}
        outer = b"MRK_WINDOWS_SNAPSHOT_EXIT_DIAGNOSTIC_V1 " + json.dumps(summary, separators=(",", ":")).encode("ascii") + b"\n"
        self.assertLessEqual(len(outer), 1024)
        self.assertNotIn(b"private-canary", marker + outer)

    def _run(self, fake: _Fake, config_path=CONFIG, clock=None) -> dict:
        def factory(inventory):
            fake.inventory = inventory
            fake._check_budget = lambda: windows._tick(inventory)
            return fake

        with patch.object(windows, "_new_native", side_effect=factory), \
             patch.object(native, "_load_bindings", side_effect=AssertionError("real DLL loading")), \
             patch.object(os, "_exit", side_effect=AssertionError("real process exit")), \
             patch.object(os, "open", side_effect=AssertionError("POSIX/full-path fallback")), \
             patch.object(policy.time, "monotonic", side_effect=clock or (lambda: 0.0)):
            result = windows.project_snapshot(fake.root, config_path)
        self.assertEqual(fake._owned, [])
        return result

    def _read(self, fake: _Fake, relative="build.gradle") -> tuple[str, policy._Inventory]:
        with patch.object(policy.time, "monotonic", return_value=0.0):
            inventory = policy._Inventory()
            fake.inventory = inventory
            fake._check_budget = lambda: windows._tick(inventory)
            try:
                _, frames = windows._capture_root(fake, "C:", fake.root_parts, inventory)
                node = fake.project.children[relative]
                text = windows._read_file(fake, frames[-1], relative, (relative,), inventory, node.entry(relative))
                return text, inventory
            finally:
                fake.close_all()

    def test_windows_root_and_component_grammar(self):
        for root in (r"C:\selected", r"\\?\C:\selected", "c:\\資料\\😀"):
            admitted, drive, parts = windows.validate_root(root)
            self.assertEqual(admitted, root)
            self.assertEqual(drive, "C:")
            self.assertTrue(parts)
        for root in (None, 1, "", "C:", "C:\\", "C:relative", r"\selected", r"\\server\share",
                     r"\\?\UNC\server\share", r"\\.\C:\selected", r"\\?\GLOBALROOT\Device\HarddiskVolume7\a",
                     r"C:\a/child", "C:\\a\\", r"C:\a\\b", r"C:\a\..\b", r"C:\a\.\b",
                     "C:\\\ud800", "C:\\" + "\\".join(["a"] * 129), "C:\\" + "\\".join(["x" * 255] * 17)):
            with self.subTest(root=repr(root)), self.assertRaises(ApiError):
                windows.validate_root(root)
        self.assertEqual(len(windows.validate_root("C:\\" + "\\".join(["a"] * 128))[2]), 128)
        for name in ("app", "資料", "😀", "x" * 255, "COM10"):
            self.assertTrue(native.valid_component(name), name)
        for name in ("", ".", "..", "a/b", "a\\b", "a:b", "a?", "a*", "a.", "a ", "a\x00", "a\x7f",
                     "\ud800", "x" * 256, "😀" * 64, "CON", "con.txt", "NUL .txt", "COM1.ini",
                     "LPT9", "COM¹.txt", "LPT²", "CONIN$", "CONOUT$.txt", "CLOCK$", None, True):
            self.assertFalse(native.valid_component(name), repr(name))
        self.assertEqual(windows.validate_config_path("資料/mobile-release.json"), "資料/mobile-release.json")
        for path in ("release\\mobile-release.json", "NUL/mobile-release.json", "release./mobile-release.json",
                     "../mobile-release.json", "private/mobile-release.json", "release/PRIVATE/mobile-release.json",
                     "release/other.json", "release/mobile-release.json:stream"):
            with self.subTest(path=path), self.assertRaises(ApiError):
                windows.validate_config_path(path)

    def test_drive_capture_never_redirects_children(self):
        raw = (DEVICE + "\0" + r"\??\C:\historical" + "\0\0").encode("utf-16-le")
        self.assertEqual(native.parse_drive_mapping(raw), DEVICE)
        for target in (r"\??\C:\subst", r"\Device\Mup\server", r"\Device\LanmanRedirector", DEVICE + r"\suffix",
                       r"\Device\HarddiskVolume", r"\Device\HarddiskVolume12345678901"):
            with self.assertRaises(native.NativeError):
                native.parse_drive_mapping((target + "\0\0").encode("utf-16-le"))
        for malformed in (b"", b"\0\0", raw[:-1], raw[:-2], b"\0\0\0\0", (DEVICE + "\0\0extra\0\0").encode("utf-16-le")):
            with self.assertRaises(native.NativeError):
                native.parse_drive_mapping(malformed)
        fake = _Fake()
        fake.config()
        fake.add("build.gradle", GRADLE)
        fake.mapping_targets = [DEVICE, r"\Device\HarddiskVolume8"]
        result = self._run(fake)
        absolute = [spec for spec in fake.specs if spec.parent is None]
        self.assertEqual([spec.name for spec in absolute], [DEVICE + "\\"])
        self.assertEqual(fake.mapping_calls, 2)
        self.assertFalse(any("HarddiskVolume8" in spec.name for spec in fake.specs))
        self.assertEqual(result["config"]["state"], "unavailable")
        self.assertIsNone(result["config"]["data"])
        self.assertTrue(result["discovery"]["partial"])

    def test_nt_abi_arguments_and_original_parent_chain(self):
        expected = {
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
        native._check_abi(expected)
        broken = copy.deepcopy(expected)
        broken["Attributes"][2]["RootDirectory"] = 4
        with self.assertRaises(native.NativeUnavailable):
            native._check_abi(broken)
        for directory, access, options in ((True, 0x001000A1, 0x21), (False, 0x00100081, 0x60)):
            spec = native.open_spec(101, "child", directory)
            self.assertEqual((spec.parent, spec.name, spec.access, spec.options, spec.attributes,
                              spec.sharing, spec.disposition), (101, "child", access, options, 0x1000, 1, 1))
            self.assertFalse(spec.attributes & 0x2)  # No OBJ_INHERIT; live inherit query needs W1.
            self.assertFalse(spec.options & 0x00200000)  # No FILE_OPEN_REPARSE_POINT.
        for args in ((101, r"a\b", True), (101, r"C:\a", True), (0, "a", True), (True, "a", True),
                     (native.INVALID_HANDLE, "a", False), (None, DEVICE + "\\", False), (None, "C:\\", True)):
            with self.assertRaises(native.NativeError):
                native.open_spec(*args)
        fake = _Fake(("parent", "selected"))
        fake.config()
        fake.add("src/build.gradle", GRADLE)
        self._run(fake)
        self.assertEqual(sum(spec.parent is None for spec in fake.specs), 1)
        for spec, live in zip(fake.specs[1:], fake.open_lifetimes[1:]):
            self.assertIn(spec.parent, live)
            self.assertNotIn("\\", spec.name)
            self.assertNotIn("/", spec.name)
            self.assertEqual(spec.attributes, 0x1000)
        closed = [event[1] for event in fake.trace if event[0] == "close"]
        self.assertCountEqual(closed, fake.handles)
        self.assertEqual(len(closed), len(set(closed)))
        with self.assertRaises(native.NativeError):
            fake.open_child(100, "replacement", True)  # Retired original, no reacquisition.

    def test_admission_survives_attribute_only_mutation_without_following(self):
        for mutation, response in (({"attributes": 0x410}, "refuse"), ({"attributes": 0x410}, "original"),
                                   ({"case_flags": 1}, "original")):
            fake = _Fake()
            source = fake.add("src/build.gradle", GRADLE)
            fake.reparse_parent = response
            mutations = []

            def mutate(parent, name, directory):
                if name == "src":
                    self.assertIs(fake.handles[parent], fake.project)
                    self.assertIn(parent, fake._owned)
                    fake.project.meta = replace(fake.project.meta, **mutation)
                    mutations.append((parent, name))

            fake.before_open = mutate  # After the collector's last pre-open recheck.
            result = self._run(fake)
            self.assertEqual(len(mutations), 1)
            self.assertTrue(result["discovery"]["partial"])
            read_nodes = [fake.handles[event[1]] for event in fake.trace if event[0] == "read"]
            self.assertTrue(all(node is source for node in read_nodes))
            if response == "refuse":
                self.assertEqual(read_nodes, [])
            self.assertEqual(sum(spec.parent is None for spec in fake.specs), 1)
        changes = (
            {"attributes": 0x420, "reparse_tag": 0xA0000003}, {"attributes": 0x1020},
            {"attributes": 0x40020}, {"attributes": 0x400020}, {"attributes": 0x60},
            {"delete_pending": True}, {"links": 2}, {"volume": 18},
            {"file_id": b"\0" * 16}, {"size": -1}, {"directory": True},
        )
        for change in changes:
            fake = _Fake()
            node = fake.add("build.gradle", GRADLE)
            node.meta = replace(node.meta, **change)
            result = self._run(fake)
            self.assertTrue(result["discovery"]["partial"], change)
            self.assertFalse(any(event[0] == "read" for event in fake.trace), change)
        fake = _Fake()
        node = fake.add("src")
        fake.add("src/build.gradle", GRADLE)
        node.meta = replace(node.meta, case_flags=1)
        self.assertTrue(self._run(fake)["discovery"]["partial"])
        self.assertFalse(any(event[0] == "directory" and fake.handles[event[1]] is node for event in fake.trace))
        fake = _Fake()
        node = fake.add("build.gradle", GRADLE)

        def replace_after_enumeration(parent, name, directory):
            if name == "build.gradle":
                node.meta = replace(node.meta, file_id=b"z" * 16)

        fake.before_open = replace_after_enumeration
        result = self._run(fake)
        self.assertIn("snapshot.changed", {issue["code"] for issue in result["issues"]})
        self.assertFalse(any(event[0] == "read" for event in fake.trace))

    def test_reparse_witnesses_require_fixed_identity_and_original_refusal(self):
        # Only these unannotated/default-free definitions enter the inert
        # namespace. No fixture module, require(), constructor or native seam.
        signatures = {
            "_reparse_witness_state": ("expected",),
            "_reparse_witness_entry": ("state", "relative", "parent", "name", "file_id", "directory", "attributes", "tag"),
            "_reparse_witness_refusal": ("state", "relative", "name", "directory", "entered_parent", "completed_parent",
                                         "owned", "classified", "status", "category"),
        }
        source = (Path(__file__).resolve().parents[1] / "native_desktop_snapshot_windows.py").read_bytes()
        self.assertLessEqual(len(source), 128 * 1024)
        parsed = ast.parse(source, filename="reviewed-reparse-fixture-source")
        selected = [node for node in parsed.body if getattr(node, "name", None) in signatures]
        self.assertCountEqual([node.name for node in selected], signatures)
        safe = {"ValueError": ValueError, "type": type, "dict": dict, "tuple": tuple, "bytes": bytes,
                "bool": bool, "int": int, "len": len, "set": set, "any": any}
        methods = {"get", "items", "rsplit", "pop", "discard", "add"}
        nodes = (ast.FunctionDef, ast.arguments, ast.arg, ast.Expr, ast.Constant, ast.Name, ast.Load, ast.Store,
                 ast.Assign, ast.For, ast.If, ast.IfExp, ast.Return, ast.Raise, ast.Call, ast.Attribute, ast.Tuple,
                 ast.Set, ast.Dict, ast.Subscript, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare,
                 ast.operator, ast.unaryop, ast.boolop, ast.cmpop)
        for definition in selected:
            self.assertIs(type(definition), ast.FunctionDef)
            self.assertFalse(definition.decorator_list or definition.returns or definition.type_comment
                             or getattr(definition, "type_params", []))
            args = definition.args
            self.assertEqual(tuple(arg.arg for arg in args.args), signatures[definition.name])
            self.assertFalse(args.posonlyargs or args.vararg or args.kwonlyargs or args.kwarg
                             or args.defaults or args.kw_defaults)
            self.assertTrue(all(arg.annotation is None and arg.type_comment is None for arg in args.args))
            self.assertEqual(sum(isinstance(node, ast.FunctionDef) for node in ast.walk(definition)), 1)
            for node in ast.walk(definition):
                self.assertIsInstance(node, nodes)
                if isinstance(node, ast.Name):
                    self.assertFalse(node.id.startswith("__"))
                if isinstance(node, ast.Attribute):
                    self.assertIn(node.attr, methods)
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        self.assertIn(node.func.id, safe)
                    else:
                        self.assertIsInstance(node.func, ast.Attribute)
                        self.assertIn(node.func.attr, methods)
        namespace = {"__builtins__": safe}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "reviewed-reparse-reducers", "exec",
                     dont_inherit=True), namespace)
        self.assertEqual(set(namespace), {"__builtins__", *signatures})
        make = namespace["_reparse_witness_state"]
        observe = namespace["_reparse_witness_entry"]
        refuse = namespace["_reparse_witness_refusal"]
        expected = {
            "linked-file/build.gradle": ((17, b"f" * 16), False, 0xA000000C),
            "linked-dir": ((17, b"d" * 16), True, 0xA000000C),
            "junction-dir": ((17, b"j" * 16), True, 0xA0000003),
        }
        parent = (100, 1, (17, b"p" * 16))
        file_parent = (104, 2, (17, b"q" * 16))

        def entry_args(role, advertised=True):
            identity, directory, tag = expected[role]
            return {"relative": role, "parent": file_parent if role.startswith("linked-file/") else parent,
                    "name": role.rsplit("/", 1)[-1], "file_id": identity[1], "directory": directory,
                    "attributes": (0x10 if directory else 0x20) | (0x400 if advertised else 0),
                    "tag": tag if advertised else None}

        def refusal_args(role):
            entry = entry_args(role, False)
            return {"relative": role, "name": entry["name"], "directory": entry["directory"],
                    "entered_parent": entry["parent"], "completed_parent": entry["parent"],
                    "owned": True, "classified": True, "status": 0xC000050B, "category": "unsafe"}

        state = make(expected)
        self.assertEqual((state["entries"], state["credited"], state["invalid"]), ({}, set(), set()))
        for role in expected:
            self.assertTrue(observe(state, **entry_args(role)))
            self.assertTrue(observe(state, **entry_args(role)))
        self.assertEqual(state["credited"], set(expected))
        for refused_role in expected:
            state = make(expected)
            for role in expected:
                self.assertEqual(observe(state, **entry_args(role, role != refused_role)), role != refused_role)
            self.assertEqual(len(state["credited"]), 2)
            self.assertTrue(refuse(state, **refusal_args(refused_role)))
            self.assertTrue(refuse(state, **refusal_args(refused_role)))
            self.assertEqual(state["credited"], set(expected))  # Three identities, not three events.
        state = make(expected)
        for unrelated in ("other-link", "hardlinked/build.gradle", "@root"):
            self.assertFalse(observe(state, **{**entry_args("linked-dir"), "relative": unrelated}))
            self.assertFalse(refuse(state, **{**refusal_args("linked-dir"), "relative": unrelated}))
        self.assertEqual((state["entries"], state["credited"]), ({}, set()))

        bad_setups = [{key: value for key, value in expected.items() if key != "junction-dir"},
                      {**expected, "other": expected["linked-dir"]}]
        for identity, directory, tag in (((0, b"f" * 16), False, 0xA000000C),
                ((17, b"\0" * 16), False, 0xA000000C), ((17, b"f"), False, 0xA000000C),
                ((17, b"d" * 16), False, 0xA000000C), ((17, b"f" * 16), True, 0xA000000C),
                ((17, b"f" * 16), False, 0xA0000003)):
            bad_setups.append({**expected, "linked-file/build.gradle": (identity, directory, tag)})
        for malformed in bad_setups:
            with self.assertRaises(ValueError):
                make(malformed)

        bad_entries = ({"file_id": b"x" * 16}, {"directory": True}, {"name": "BUILD.GRADLE"},
                       {"tag": 0xA0000003}, {"attributes": True}, {"attributes": 0x20},
                       {"attributes": 0x20, "tag": None},
                       {"parent": None}, {"parent": (0, 2, (17, b"q" * 16))},
                       {"parent": (104, 0, (17, b"q" * 16))},
                       {"parent": (104, 2, (18, b"q" * 16))},
                       {"parent": (104, 2, (17, b"\0" * 16))},
                       {"parent": (104, 3, (17, b"q" * 16))},
                       {"parent": (104, 2, (17, b"r" * 16))})
        role = "linked-file/build.gradle"
        for changed in bad_entries:
            state = make(expected)
            observe(state, **entry_args(role))
            with self.assertRaises(ValueError):
                observe(state, **{**entry_args(role), **changed})
            self.assertNotIn(role, state["entries"])
            self.assertNotIn(role, state["credited"])
            self.assertIn(role, state["invalid"])
            with self.assertRaises(ValueError):
                observe(state, **entry_args(role))  # A matching later sample cannot revive a conflict.
            with self.assertRaises(ValueError):
                refuse(state, **refusal_args(role))
        bad_refusals = ({"status": 0}, {"status": 0x103}, {"status": 0xC0000034}, {"status": 0xC0000022},
                        {"category": "unavailable"}, {"name": "other.gradle"}, {"directory": True},
                        {"owned": False}, {"classified": False}, {"entered_parent": None},
                        {"completed_parent": None}, {"entered_parent": parent},
                        {"completed_parent": (104, 3, (17, b"q" * 16))},
                        {"entered_parent": (104, 3, (17, b"q" * 16)),
                         "completed_parent": (104, 3, (17, b"q" * 16))})
        for changed in bad_refusals:
            state = make(expected)
            observe(state, **entry_args(role, False))
            with self.assertRaises(ValueError):
                refuse(state, **{**refusal_args(role), **changed})
            self.assertNotIn(role, state["entries"])
            self.assertNotIn(role, state["credited"])
            with self.assertRaises(ValueError):
                refuse(state, **refusal_args(role))
        for advertised in (None, True):
            state = make(expected)
            if advertised is not None:
                observe(state, **entry_args(role))
            with self.assertRaises(ValueError):
                refuse(state, **refusal_args(role))  # Missing/advertised is not an unflagged candidate.
            self.assertFalse(state["credited"])

        # Actual shared collector, only existing in-memory adapters. These two
        # routes model ordering, not measured NTFS statuses or the failed run.
        for advertised in (True, False):
            fake = _Fake()
            fake.config()
            blocked = []
            for relative, (_identity, directory, tag) in expected.items():
                node = fake.add(relative, None if directory else b"unread-link-canary")
                blocked.append(node)
                if directory:
                    fake.add(relative + "/build.gradle", b"unread-outside-canary")
                if advertised:
                    node.meta = replace(node.meta, attributes=node.meta.attributes | 0x400, reparse_tag=tag)
                else:
                    fake.open_errors[node.path] = "unsafe"
            sibling = fake.add("sibling/build.gradle", GRADLE)
            result = self._run(fake)
            self.assertTrue(result["discovery"]["partial"])
            required = "snapshot.link-excluded" if advertised else "snapshot.unsafe-file"
            self.assertIn(required, {item["code"] for item in result["issues"]})
            reads = [fake.handles[event[1]] for event in fake.trace if event[0] == "read"]
            self.assertTrue(any(node is sibling for node in reads))
            self.assertFalse(any(node.data in (b"unread-link-canary", b"unread-outside-canary") for node in reads))
            self.assertFalse(any(node is blocked_node for node in fake.handles.values() for blocked_node in blocked))
            attempts = []
            for spec, owned in zip(fake.specs, fake.open_lifetimes):
                if spec.parent is None:
                    continue
                path = fake.handles[spec.parent].path.rstrip("\\") + "\\" + spec.name
                if path in {node.path for node in blocked}:
                    attempts.append(path)
                    self.assertIn(spec.parent, owned)
                    self.assertEqual(spec.attributes, 0x1000)
                    self.assertNotIn("\\", spec.name)
                    self.assertNotIn("/", spec.name)
            self.assertCountEqual(attempts, [] if advertised else [node.path for node in blocked])
            closed = [event[1] for event in fake.trace if event[0] == "close"]
            self.assertCountEqual(closed, fake.handles)
            self.assertEqual(len(closed), len(set(closed)))
            self.assertEqual(fake._owned, [])

    def test_short_alias_selection_and_returned_failure_classification(self):
        # Only these two reviewed scalar definitions execute. Neither the
        # fixture module nor its DLL/handle/setter/restore code is imported.
        source = (Path(__file__).resolve().parents[1] / "native_desktop_snapshot_windows.py").read_bytes()
        self.assertLessEqual(len(source), 128 * 1024)
        parsed = ast.parse(source, filename="reviewed-short-alias-fixture-source")
        signatures = {"_short_alias_selection": ("exact_name", "observed_name"),
                      "_short_alias_error_reason": ("api", "code")}
        selected = [node for node in parsed.body if getattr(node, "name", None) in signatures]
        self.assertEqual(len(selected), 2)
        safe = {"type": type, "str": str, "int": int, "len": len}
        nodes = (ast.FunctionDef, ast.arguments, ast.arg, ast.Expr, ast.Constant, ast.Name, ast.Load, ast.Store,
                 ast.Assign, ast.For, ast.If, ast.Return, ast.Call, ast.Attribute, ast.Tuple, ast.Dict,
                 ast.Subscript, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare,
                 ast.operator, ast.unaryop, ast.boolop, ast.cmpop)
        for definition in selected:
            self.assertIs(type(definition), ast.FunctionDef)
            self.assertFalse(definition.decorator_list or definition.returns or definition.type_comment
                             or getattr(definition, "type_params", []))
            args = definition.args
            self.assertEqual(tuple(arg.arg for arg in args.args), signatures[definition.name])
            self.assertFalse(args.posonlyargs or args.vararg or args.kwonlyargs or args.kwarg or args.defaults or args.kw_defaults)
            self.assertTrue(all(arg.annotation is None and arg.type_comment is None for arg in args.args))
            self.assertEqual(sum(isinstance(node, ast.FunctionDef) for node in ast.walk(definition)), 1)
            for node in ast.walk(definition):
                self.assertIsInstance(node, nodes)
                if isinstance(node, ast.Name):
                    self.assertFalse(node.id.startswith("__"))
                if isinstance(node, ast.Attribute):
                    self.assertIsInstance(node.value, ast.Name)
                    self.assertIn((node.value.id, node.attr), {("observed_name", "split"), ("reasons", "get")})
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertIn(node.func.id, safe)
        namespace = {"__builtins__": safe}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "reviewed-short-alias-reducers", "exec",
                     dont_inherit=True), namespace)
        self.assertEqual(set(namespace), {"__builtins__", *signatures})
        select, classify = (namespace[name] for name in signatures)
        exact = "LongSnapshotDirectory"
        self.assertEqual(select(exact, exact), "absent")
        for name in ("LONGSN~1", "MRKSNP~1", "FOO.BAR", "a"):
            self.assertEqual(select(exact, name), "existing")
        for name in (None, 1, b"MRKSNP~1", "", ".", "..", "A.", ".A", "A.B.C", "NINECHARS",
                     "A.LONG", "A/B", "A\\B", "A:B", "A B", "\u00e9", exact.lower(), "A" * 8192):
            self.assertIsNone(select(exact, name))
        self.assertIsNone(select("DifferentDirectory", "MRKSNP~1"))
        expected = {5: "short_alias_access_denied", 32: "short_alias_sharing_violation",
                    50: "short_alias_not_supported", 87: "short_alias_invalid_parameter",
                    183: "short_alias_name_collision", 305: "short_alias_volume_disabled",
                    1314: "short_alias_privilege_unavailable"}
        for api_name in ("CreateFileW", "GetHandleInformation", "GetFileInformationByHandleEx",
                         "GetShortPathNameW", "SetFileShortNameW"):
            for code, reason in expected.items():
                self.assertEqual(classify(api_name, code), reason)
            self.assertEqual(classify(api_name, 123), "short_alias_other_refused")
            self.assertIsNone(classify(api_name, 997))
        self.assertEqual(classify("ReadFile", 5), "fixture_native_unavailable")
        for code in (None, True, "5", 5.0, -1, 1 << 32):
            self.assertIsNone(classify("SetFileShortNameW", code))
        for api_name in (None, 1, b"SetFileShortNameW"):
            self.assertIsNone(classify(api_name, 5))

    def test_installed_dacl_policy_requires_exact_protected_world_aces(self):
        # Execute only the scalar bytes predicate, never the fixture's native
        # module/constructor/open/setter/readback or restoration code.
        name = "_installed_deny_data_dacl"
        source = (Path(__file__).resolve().parents[1] / "native_desktop_snapshot_windows.py").read_bytes()
        self.assertLessEqual(len(source), 128 * 1024)
        parsed = ast.parse(source, filename="reviewed-dacl-fixture-source")
        selected = [node for node in parsed.body if getattr(node, "name", None) == name]
        self.assertEqual(len(selected), 1)
        definition = selected[0]
        self.assertIs(type(definition), ast.FunctionDef)
        self.assertFalse(definition.decorator_list or definition.returns or definition.type_comment
                         or getattr(definition, "type_params", []))
        args = definition.args
        self.assertEqual(tuple(arg.arg for arg in args.args), ("data",))
        self.assertFalse(args.posonlyargs or args.vararg or args.kwonlyargs or args.kwarg or args.defaults or args.kw_defaults)
        self.assertIsNone(args.args[0].annotation)
        self.assertEqual(sum(isinstance(node, ast.FunctionDef) for node in ast.walk(definition)), 1)
        safe = {"type": type, "bytes": bytes, "int": int, "len": len}
        nodes = (ast.FunctionDef, ast.arguments, ast.arg, ast.Expr, ast.Constant, ast.Name, ast.Load, ast.Store,
                 ast.Assign, ast.AugAssign, ast.For, ast.If, ast.Return, ast.Call, ast.Attribute, ast.Tuple,
                 ast.Subscript, ast.Slice, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare,
                 ast.operator, ast.unaryop, ast.boolop, ast.cmpop)
        for node in ast.walk(definition):
            self.assertIsInstance(node, nodes)
            if isinstance(node, ast.Name):
                self.assertFalse(node.id.startswith("__"))
            if isinstance(node, ast.Attribute):
                self.assertIsInstance(node.value, ast.Name)
                self.assertEqual((node.value.id, node.attr), ("int", "from_bytes"))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertIn(node.func.id, safe)
        namespace = {"__builtins__": safe}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "reviewed-dacl-policy-predicate", "exec",
                     dont_inherit=True), namespace)
        self.assertEqual(set(namespace), {"__builtins__", name})
        check = namespace[name]
        world = bytes.fromhex("010100000000000100000000")
        deny = struct.pack("<BBHI", 1, 0, 20, 1) + world
        allow = struct.pack("<BBHI", 0, 0, 20, 0x1F01FF) + world

        def descriptor(*, offset=20, capacity=48):
            return (struct.pack("<BBHIIII", 1, 0, 0x9004, 0, 0, 0, offset) + bytes(offset - 20)
                    + struct.pack("<BBHHH", 2, 0, capacity, 2, 0) + deny + allow
                    + b"\xa5" * (capacity - 48))

        valid = descriptor()
        for data in (valid, descriptor(offset=24), descriptor(capacity=256)):
            self.assertIs(check(data), True)

        def changed(offset, replacement):
            return valid[:offset] + replacement + valid[offset + len(replacement):]

        malformed = [changed(0, b"\x02"), changed(20, b"\x04"),
                     valid[:28] + allow + deny, valid[:28] + deny + allow[:-1]]
        for control in (0, 0x8004, 0x9000, 0x1004):
            malformed.append(changed(2, struct.pack("<H", control)))
        for offset in (0, 4, 16, 21, 64, 0xFFFFFFFC):
            malformed.append(changed(16, struct.pack("<I", offset)))
        for size in (0, 4, 8, 28, 47, 49, 52, 65532):
            malformed.append(changed(22, struct.pack("<H", size)))
        for count in (0, 1, 3, 65535):
            malformed.append(changed(24, struct.pack("<H", count)))
        for offset in (28, 48):
            malformed.extend((changed(offset, b"\x05"), changed(offset + 1, b"\x10"),
                              changed(offset + 2, struct.pack("<H", 24)),
                              changed(offset + 4, struct.pack("<I", 2)),
                              changed(offset + 8, b"\x02"), changed(offset + 9, b"\x02"),
                              changed(offset + 15, b"\x05"), changed(offset + 16, b"\x01")))
        malformed.append(changed(22, struct.pack("<HH", 68, 3)) + allow)
        for data in malformed:
            with self.subTest(data=data.hex()):
                self.assertIs(check(data), False)
        for end in range(len(valid)):
            self.assertIs(check(valid[:end]), False)
        for data in (None, True, 1, "descriptor", bytearray(valid), memoryview(valid), valid + bytes(16384)):
            self.assertIs(check(data), False)

    def test_failure_diagnostic_is_closed_bounded_and_unknown_silent(self):
        # Only reviewed scalar definitions execute, never fixture/emitter/observer.
        name = "_failure_diagnostic"
        namespace, parsed = self._dacl_reducers()
        reduce = namespace[name]
        fixture_state = (True, True, True, True, True, False, True, False)
        reader_state = (0, False, None, None, None)
        arguments = {"case": "short-alias", "nonce": "a" * 64, "stage": "setup",
                     "reason": "real_short_alias_unavailable", "fixture_state": fixture_state,
                     "reader_state": reader_state, "output_state": (False, 0, 0)}
        prefix = b"MRK_WINDOWS_SNAPSHOT_FAILURE_V1 "
        raw = reduce(**arguments)
        self.assertTrue(raw.startswith(prefix) and raw.endswith(b"\n") and raw.isascii())
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertLessEqual(len(raw), 1024)
        expected = {"schemaVersion": 1, "scope": "windows-static-snapshot-native-v1", "id": "short-alias",
                    "nonce": "a" * 64, "stage": "setup", "code": "real_short_alias_unavailable"}
        self.assertEqual(json.loads(raw[len(prefix):-1]), expected)
        reasons = ("short_alias_bound", "real_short_alias_unavailable", "real_alias_required",
                   "normalized_alias_veto_required", "fixture_native_unavailable", "fixture_failure",
                   "short_alias_access_denied", "short_alias_sharing_violation", "short_alias_not_supported",
                   "short_alias_invalid_parameter", "short_alias_name_collision", "short_alias_volume_disabled",
                   "short_alias_privilege_unavailable", "short_alias_other_refused",
                   "saved_dacl_bound", "saved_dacl_unsupported", "world_sid_bound", "fixture_dacl_denial_required", "fixture_dacl_not_effective",
                   "dacl_restore_original_object", "saved_dacl_present", "dacl_restoration_not_confirmed",
                   "fixture_restoration_bound", "fixture_retained_arena_bound", "fixture_arena_bound",
                   "fixture_path_bound", "fixture_inherited_handle", "fixture_zero_file_id")
        for stage in ("setup", "reader", "reduction", "restoration"):
            for reason in reasons:
                marker = reduce(**{**arguments, "stage": stage, "reason": reason})
                self.assertEqual(json.loads(marker[len(prefix):-1]), {**expected, "stage": stage, "code": reason})
        for stage, reason in (("setup", "fixture_dacl_not_effective"),
                              ("restoration", "dacl_restoration_not_confirmed")):
            marker = reduce(**{**arguments, "case": "acl-type", "stage": stage, "reason": reason})
            self.assertEqual(json.loads(marker[len(prefix):-1]),
                             {**expected, "id": "acl-type", "stage": stage, "code": reason})
        # Literal-only roster extraction, not module execution or a native fixture.
        groups = [node for node in parsed.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "GROUPS" for target in node.targets)]
        self.assertEqual(len(groups), 1)
        cases = tuple(case for _group, cases in ast.literal_eval(groups[0].value) for case in cases)
        self.assertEqual(len(cases), 31)
        for case in cases:
            marker = reduce(**{**arguments, "case": case})
            self.assertEqual(json.loads(marker[len(prefix):-1]), {**expected, "id": case})

        class Unrenderable:
            def __str__(self):
                raise AssertionError("must not render a diagnostic argument")
            __repr__ = __str__
            def __eq__(self, other):
                raise AssertionError("must not compare an unknown diagnostic argument")

        class NonExactString(str):
            def __eq__(self, other):
                raise AssertionError("must require exact strings before comparison")

        poison = Unrenderable()
        for reason in (None, "private-canary/path\nsecret", b"private-canary", poison,
                       NonExactString("short_alias_bound"), ["short_alias_bound"]):
            marker = reduce(**{**arguments, "reason": reason})
            self.assertEqual(json.loads(marker[len(prefix):-1]), {**expected, "code": "fixture_failure"})
            self.assertNotIn(b"private-canary", marker)
        for key, values in (
                ("case", (None, "private-canary", "short-alias\n", NonExactString("short-alias"), poison)),
                ("nonce", (None, "A" * 64, "a" * 63, "a" * 65, "g" * 64, "\u00e9" * 64, poison)),
                ("stage", (None, "admission", "complete", "setup\n", NonExactString("setup"), poison))):
            for value in values:
                self.assertIsNone(reduce(**{**arguments, key: value}))
        for index in range(8):
            for value in (not fixture_state[index], None, 0, 1, "clear", poison):
                changed = list(fixture_state); changed[index] = value
                self.assertIsNone(reduce(**{**arguments, "fixture_state": tuple(changed)}))
        for state in (None, [], {}, fixture_state[:-1], (*fixture_state, True)):
            self.assertIsNone(reduce(**{**arguments, "fixture_state": state}))
        attached = (1, True, True, False, True)
        for state in (reader_state, attached):
            self.assertEqual(reduce(**{**arguments, "reader_state": state}), raw)
        for state in (None, [], (0, False), (True, False, None, None, None),
                      (1, False, None, None, None), (2, False, None, None, None),
                      (0, False, True, None, None), (0, False, None, False, None), (0, False, None, None, True),
                      (0, True, True, False, True), (1, 1, True, False, True), (2, True, True, False, True),
                      (1, True, False, False, True), (1, True, None, False, True), (1, True, 1, False, True),
                      (1, True, True, True, True), (1, True, True, None, True), (1, True, True, 0, True),
                      (1, True, True, False, False), (1, True, True, False, None), (1, True, True, False, 1)):
            self.assertIsNone(reduce(**{**arguments, "reader_state": state}))
        # Already classified pending completion / already joined observer only;
        # the helper never performs completion or a join to reach these tuples.
        for state in ((True, True, True, True, False, True, True, False),
                      (True, True, True, True, False, True, False, True)):
            self.assertEqual(reduce(**{**arguments, "fixture_state": state, "reader_state": attached}), raw)
        for state in (None, [], (False, 0), (True, 0, 0), (None, 0, 0), (0, 0, 0),
                      (False, -1, 0), (False, 4, 0), (False, True, 0), (False, 1.0, 0),
                      (False, 0, -1), (False, 0, 65537), (False, 0, False), (False, 0, 0.0)):
            self.assertIsNone(reduce(**{**arguments, "output_state": state}))
        engine_error = b"Mobile Release Kit desktop engine rejected the request or transport.\n"
        available = 65536 - len(raw) - len(engine_error)
        self.assertEqual(reduce(**{**arguments, "output_state": (False, 3, available)}), raw)
        self.assertIsNone(reduce(**{**arguments, "output_state": (False, 3, available + 1)}))

        # Inspect, but NEVER compile/execute, the effectful diagnostic seam.
        fixture = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "Fixture")
        methods = {node.name: node for node in fixture.body if isinstance(node, ast.FunctionDef)}
        emitter = methods["diagnose_failure"]
        self.assertFalse(any(isinstance(node, (ast.With, ast.For, ast.While, ast.Await)) for node in ast.walk(emitter)))
        attribute_calls = [node.func for node in ast.walk(emitter)
                           if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        self.assertEqual([(call.value.id, call.attr) for call in attribute_calls], [("os", "write")])
        write = next(node for node in ast.walk(emitter) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr == "write")
        self.assertEqual(write.args[0].value, 2)
        self.assertEqual(write.args[1].id, "raw")
        for call in (node for node in ast.walk(emitter) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            self.assertIn(call.func.id, {"type", "len", name, "_short_alias_error_reason"})
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in ("snapshot", "join", "restore")
                             for node in ast.walk(emitter)))
        native_labels = [node for node in ast.walk(emitter) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Name) and node.func.id == "_short_alias_error_reason"]
        self.assertEqual(len(native_labels), 1)
        self.assertEqual([(arg.value.id, arg.attr) for arg in native_labels[0].args], [("error", "api"), ("error", "code")])
        guarded = next(node for node in emitter.body if isinstance(node, ast.Try))
        self.assertEqual(guarded.body[1].targets[0].attr, "diagnostic_attempted")
        self.assertIs(guarded.body[1].value.value, True)
        self.assertEqual(guarded.handlers[0].type.id, "BaseException")
        self.assertIsInstance(guarded.handlers[0].body[0], ast.Return)
        self.assertEqual(methods["__init__"].body[-2].targets[0].attr, "diagnostic_ready")
        self.assertIs(methods["__init__"].body[-2].value.value, True)
        self.assertEqual(methods["__init__"].body[-1].targets[0].attr, "diagnostic_attempted")
        self.assertIs(methods["__init__"].body[-1].value.value, False)
        for method, stage in (("finish", "reduction"), ("_finish", "restoration")):
            calls = [node for node in ast.walk(methods[method]) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr == "diagnose_failure"]
            self.assertEqual([call.args[0].value for call in calls], [stage])
        main = next(node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        dispatch = next(node for node in ast.walk(main) if isinstance(node, ast.FunctionDef) and node.name == "dispatch")
        refusals = [node for node in ast.walk(dispatch) if isinstance(node, ast.ExceptHandler)
                    and isinstance(node.type, ast.Attribute) and node.type.attr == "ApiError"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0].body[-3].value.func.attr, "finish")
        self.assertEqual(refusals[0].body[-2].targets[0].id, "validated_refusal")
        self.assertEqual(refusals[0].body[-2].value.id, "error")
        self.assertIsInstance(refusals[0].body[-1], ast.Raise)
        self.assertIsNone(refusals[0].body[-1].exc)
        guarded_refusals = [node for node in ast.walk(dispatch) if isinstance(node, ast.If)
                            and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
                            and node.test.left.id == "error"]
        self.assertEqual(len(guarded_refusals), 1)
        self.assertIsInstance(guarded_refusals[0].test.ops[0], ast.IsNot)
        self.assertEqual(guarded_refusals[0].test.comparators[0].id, "validated_refusal")
        self.assertEqual(guarded_refusals[0].body[0].value.func.attr, "diagnose_failure")
        self.assertEqual(guarded_refusals[0].body[0].value.args[0].value, "reader")

    def test_normalized_name_and_case_are_only_vetoes(self):
        for spelling in ("Build.Gradle", "BUILD~1.GRA", r"\Device\HarddiskVolume8\build.gradle", ""):
            fake = _Fake()
            node = fake.add("build.gradle", GRADLE)
            node.normalized = spelling
            result = self._run(fake)
            self.assertTrue(result["discovery"]["partial"])
            self.assertFalse(any(event[0] == "read" for event in fake.trace))
            self.assertFalse(any(spec.name == spelling for spec in fake.specs if spelling != ""))
        for alias, actual in (("RELEAS~1", "release"), ("Release", "release"), ("PUBLIC~1", "private")):
            fake = _Fake()
            target = fake.add(actual)
            fake.add(actual + "/mobile-release.json", json.dumps(_draft()).encode())
            fake.aliases[(fake.project.path, alias)] = target
            result = self._run(fake, alias + "/mobile-release.json")
            self.assertEqual(result["config"]["state"], "unavailable")
            alias_handles = [handle for handle, node in fake.handles.items() if node is target]
            # Alias identification can acquire a metadata handle, but cannot
            # enumerate/read through that alias before the long-name veto.
            first_alias = next(event for event in fake.trace if event[:3] == ("open", 104, alias))
            self.assertIsNotNone(first_alias)
            if actual == "private":
                self.assertFalse(any(event[0] in {"directory", "read"} and event[1] in alias_handles
                                     for event in fake.trace))
            self.assertFalse(any(spec.name == target.path for spec in fake.specs))
        fake = _Fake()
        fake.volume.normalized = DEVICE.lower() + "\\"
        with self.assertRaises(ApiError):
            self._run(fake)
        self.assertEqual(fake._owned, [])

    def test_directory_chain_bounds_and_conditional_fields(self):
        first = native.Entry("資料", 0x20, b"a" * 16, None)
        second = native.Entry("child", 0x10, b"b" * 16, None)
        raw = _batch([first, second])
        self.assertEqual(native.decode_directory_batch(raw), (first, second))
        self.assertIsNone(native.decode_directory_batch(raw)[0].reparse_tag)
        reparse = native.Entry("link", 0x420, b"c" * 16, 0xA000000C)
        self.assertEqual(native.decode_directory_batch(_batch([reparse]))[0].reparse_tag, 0xA000000C)
        malformed = [b"\0" * 89, b"\0" * (native.BUFFER_BYTES + 1)]
        for offset, value in ((0, 8), (0, 95), (0, len(raw)), (60, 0), (60, 3), (60, 512)):
            changed = bytearray(raw)
            struct.pack_into("<I", changed, offset, value)
            malformed.append(bytes(changed))
        for name_bytes in (b"\0\0", b"\0\xd8"):
            changed = bytearray(_batch([native.Entry("a", 0x20, b"a" * 16, None)]))
            changed[88:90] = name_bytes
            malformed.append(bytes(changed))
        changed = bytearray(raw)
        second_offset = struct.unpack_from("<I", raw)[0]
        struct.pack_into("<I", changed, second_offset + 60, 1)
        malformed.append(bytes(changed))  # Even a valid first record cannot escape this bad batch.
        for data in malformed:
            with self.assertRaises(native.NativeError):
                native.decode_directory_batch(data)
        fake = _Fake()
        node = fake.add("build.gradle", GRADLE)
        bad_tail = bytearray(_batch([node.entry("build.gradle"), second]))
        struct.pack_into("<I", bad_tail, struct.unpack_from("<I", bad_tail)[0] + 60, 1)
        fake.project.batches = [bytes(bad_tail)]
        self.assertTrue(self._run(fake)["discovery"]["partial"])
        self.assertFalse(any(spec.name == "build.gradle" for spec in fake.specs))
        calls = []

        def enumerate_call(handle, info_class, buffer, size):
            self.assertEqual(buffer.raw, b"\0" * native.BUFFER_BYTES)
            calls.append((handle, info_class, buffer, size))
            buffer.raw = raw + b"\0" * (size - len(raw))
            return len(calls) == 1

        owner = _shim(native.ERROR_NO_MORE_FILES, GetFileInformationByHandleEx=enumerate_call)
        self.assertEqual(native.decode_directory_batch(owner.directory_batch(101, True)), (first, second))
        self.assertIsNone(owner.directory_batch(101, False))
        self.assertEqual([call[1] for call in calls], [20, 19])
        self.assertIsNot(calls[0][2], calls[1][2])
        owner.close_all()
        owner = _shim(5, GetFileInformationByHandleEx=lambda *args: False)
        with self.assertRaises(native.NativeError):
            owner.directory_batch(101, True)
        owner.close_all()

    def test_shared_pruning_candidates_and_parsers(self):
        fake = _Fake()
        fake.config()
        sources = {
            "app/build.gradle.kts": GRADLE.decode(),
            "release/version.properties": "VERSION_NAME=9.9.9\nBUILD_NUMBER=42\n",
            "App.xcodeproj/project.pbxproj": "PRODUCT_BUNDLE_IDENTIFIER = org.fixture.ios;\n",
            "App.xcodeproj/xcshareddata/xcschemes/App.xcscheme": "",
        }
        for relative, text in sources.items():
            fake.add(relative, text.encode())
        fake.add("App.xcworkspace")
        for relative in ("README.txt", "gradlew", "local.properties"):
            fake.add(relative, b"noncandidate-canary")
        for relative in (".git", "node_modules", "build", "private", "secrets", "credentials", "release/private",
                         ".mobile-release", ".venv", "Pods"):
            fake.add(relative + "/build.gradle", b"private-canary")
        with patch.object(policy, "parse_project_sources", wraps=policy.parse_project_sources) as parser:
            result = self._run(fake)
        parser.assert_called_once()
        self.assertEqual(parser.call_args.args[0], sources)
        self.assertEqual(parser.call_args.args[1], {"App.xcodeproj", "App.xcworkspace"})
        self.assertEqual(result["discovery"]["hints"]["android"], {
            "module": ":app", "buildFile": "app/build.gradle.kts", "applicationId": "org.fixture.app",
        })
        self.assertEqual(result["discovery"]["hints"]["ios"]["bundleId"], "org.fixture.ios")
        self.assertEqual(result["config"]["state"], "format-valid")
        opened = {spec.name for spec in fake.specs}
        self.assertFalse(opened & {".git", "node_modules", "build", "private", "secrets", "credentials", ".venv", "Pods"})
        self.assertFalse(opened & {"README.txt", "gradlew", "local.properties"})
        self.assertNotIn("private-canary", json.dumps(result))
        self.assertNotIn("9.9.9", json.dumps(result["discovery"]))
        self.assertFalse(result["discovery"]["partial"])

        # The public DTO omits absent optional hints; it must not omit an
        # actually observed value. This is the same shared sanitizer exercised
        # by the genuine hosted source/ZIP fixtures, not a native qualification.
        explicit = _Fake()
        explicit.config()
        explicit.add("app/build.gradle.kts", GRADLE + b'namespace = "org.fixture.code"\napplicationIdSuffix = ".debug"\n')
        self.assertEqual(self._run(explicit)["discovery"]["hints"]["android"], {
            "module": ":app", "buildFile": "app/build.gradle.kts", "applicationId": "org.fixture.app",
            "namespace": "org.fixture.code", "debugApplicationIdSuffix": ".debug",
        })

    def test_original_reads_require_bounds_and_eof(self):
        fake = _Fake()
        node = fake.add("build.gradle", b"ab")
        node.chunks = [b"a", b"b", b""]
        text, inventory = self._read(fake)
        self.assertEqual((text, inventory.counts["sourceBytes"]), ("ab", 2))
        reads = [event for event in fake.trace if event[0] == "read"]
        self.assertEqual(len({event[1] for event in reads}), 1)
        self.assertTrue(all(0 < event[2] <= native.BUFFER_BYTES for event in reads))
        for data, chunks, code, count in (
            (b"ab", [b"a", b""], "snapshot.changed", 1),
            (b"ab", [b"abc", b""], "snapshot.changed", 3),
            (b"\xff", None, "snapshot.encoding", 1),
        ):
            fake = _Fake()
            fake.add("build.gradle", data).chunks = chunks
            with self.assertRaises(policy._ReadProblem) as caught:
                self._read(fake)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(fake.inventory.counts["sourceBytes"], count)
            self.assertEqual(fake._owned, [])
        with patch.object(policy, "MAX_SOURCE_BYTES", 4):
            fake = _Fake()
            fake.add("build.gradle", b"abcd")
            self.assertEqual(self._read(fake)[0], "abcd")  # A separate genuine EOF is observed.
            fake = _Fake()
            fake.add("build.gradle", b"abcd").chunks = [b"abcd", b"x"]
            with self.assertRaises(policy._ReadProblem) as caught:
                self._read(fake)
            self.assertEqual(caught.exception.code, "snapshot.file-size")
            self.assertEqual(fake.inventory.counts["sourceBytes"], 5)  # Discarded excess still charged.
            fake = _Fake()
            fake.add("build.gradle", b"abcde")
            with self.assertRaises(policy._ReadProblem):
                self._read(fake)
            self.assertFalse(any(event[0] == "read" for event in fake.trace))
        with patch.object(policy, "MAX_TOTAL_BYTES", 4):
            fake = _Fake()
            fake.add("build.gradle", b"abcd")
            with self.assertRaises(policy._ReadProblem) as caught:
                self._read(fake)
            self.assertEqual(caught.exception.code, "snapshot.byte-limit")
            self.assertEqual(len([event for event in fake.trace if event[0] == "read"]), 1)
        fake = _Fake()
        node = fake.add("build.gradle", b"ab")

        def changed_on_eof(handle, count):
            if fake._positions[handle] == 2:
                node.meta = replace(node.meta, write=node.meta.write + 1)

        fake.before_read = changed_on_eof
        with self.assertRaises(native.NativeError):
            self._read(fake)
        self.assertEqual(fake.inventory.counts["sourceBytes"], 2)

        def invalid_count(handle, buffer, count, consumed, overlapped):
            self.assertIsNone(overlapped)
            consumed.value = count + 1
            return True

        owner = _shim(ReadFile=invalid_count)
        with self.assertRaises(native.NativeError):
            owner.read(101, 4)
        owner.close_all()

    def test_config_missing_invalid_unavailable_changed(self):
        self.assertEqual(self._run(_Fake())["config"]["state"], "missing")
        fake = _Fake()
        fake.config(b'{"untrusted-canary":')
        result = self._run(fake)
        self.assertEqual(result["config"]["state"], "invalid")
        self.assertNotIn("untrusted-canary", json.dumps(result))
        categories = {
            0xC0000034: "missing", 0xC000003A: "unavailable", 0xC0000022: "unavailable",
            0xC0000043: "unavailable", 0xC0000056: "unavailable", 0xC000050B: "unsafe",
            0xC0000103: "unsafe", 0xC00000BA: "unsafe", 0xC000000D: "unsupported",
            0xC0000003: "unsupported", 0xC0000010: "unsupported", 0xC00000BB: "unsupported",
            0xC1234567: "unavailable",
        }
        for status, category in categories.items():
            self.assertEqual(native._nt_outcome(status, None, native.STATUS_PENDING, native.INVALID_HANDLE), category)
        for category in ("unavailable", "unsafe", "unsupported"):
            fake = _Fake()
            fake.open_errors[fake.project.path + "\\release"] = category
            result = self._run(fake)
            self.assertEqual(result["config"]["state"], "unavailable")
            self.assertTrue(result["discovery"]["partial"])
        fake = _Fake()
        node = fake.config()
        release = fake.project.children["release"]

        def disappear(parent, name, directory):
            if name == "mobile-release.json":
                self.assertIs(fake.handles[parent], release)
                del release.children[name]  # Prior enumeration presence must not become "missing".

        fake.before_open = disappear
        result = self._run(fake)
        self.assertEqual(result["config"]["state"], "unavailable")
        self.assertIn("snapshot.changed", {issue["code"] for issue in result["config"]["issues"]})
        self.assertFalse(any(event[0] == "read" and fake.handles[event[1]] is node for event in fake.trace))
        fake = _Fake()

        def change_missing_parent(parent, name, directory):
            if name == "release":
                fake.project.meta = replace(fake.project.meta, change=404)

        fake.before_open = change_missing_parent
        self.assertEqual(self._run(fake)["config"]["state"], "unavailable")
        fake = _Fake()
        fake.config(b"\xff")
        self.assertEqual(self._run(fake)["config"]["state"], "unavailable")
        fake = _Fake()
        fake.config()
        with patch.object(policy, "MAX_CONFIG_OUTPUT_NODES", 1):
            result = self._run(fake)
        self.assertEqual(result["config"]["state"], "unavailable")
        self.assertIsNone(result["config"]["data"])
        self.assertTrue(result["discovery"]["partial"])

    def test_shared_inventory_hint_and_output_limits(self):
        self.assertEqual((policy.MAX_DEPTH, policy.MAX_ENTRIES, policy.MAX_SOURCE_FILES, policy.MAX_SOURCE_BYTES,
                          policy.MAX_TOTAL_BYTES, policy.MAX_ROOT_BYTES, policy.MAX_RELATIVE_BYTES,
                          policy.MAX_ROOT_COMPONENTS, policy.MAX_ISSUES, policy.MAX_HINT_NODES,
                          policy.MAX_HINT_STRING, policy.MAX_HINT_ITEMS, policy.MAX_CONFIG_OUTPUT_NODES),
                         (12, 10000, 128, 512 * 1024, 8 * 1024 * 1024, 4096, 512, 128, 64, 4096, 512, 128, 8000))
        self.assertEqual((native.MAX_HANDLES, native.BUFFER_BYTES, native.MAPPING_UNITS, native.NAME_UNITS),
                         (144, 65536, 4096, 8192))
        fake = _Fake()
        for index in range(5):
            fake.add(f"ignored-{index}", b"")
        with patch.object(policy, "MAX_ENTRIES", 2):
            result = self._run(fake)
        self.assertEqual(result["discovery"]["scan"]["entries"], 2)
        self.assertTrue(result["discovery"]["partial"])
        self.assertEqual(len(fake.specs), 2)  # Whole over-budget batch refused before any child admission.
        fake = _Fake()
        fake.config()
        fake.add("build.gradle", GRADLE)
        with patch.object(policy, "MAX_SOURCE_FILES", 1):
            result = self._run(fake)
        self.assertEqual(result["discovery"]["scan"]["sourceFiles"], 1)  # Configuration consumes the same quota.
        self.assertFalse(any(spec.name == "build.gradle" for spec in fake.specs))
        self.assertTrue(result["discovery"]["partial"])
        fake = _Fake()
        fake.add("a/b/build.gradle", GRADLE)
        with patch.object(policy, "MAX_DEPTH", 1):
            result = self._run(fake, "mobile-release.json")
        self.assertFalse(any(spec.name == "b" for spec in fake.specs))
        self.assertIn("snapshot.depth-limit", {issue["code"] for issue in result["issues"]})
        fake = _Fake()
        fake.add("abcdefghij/klmnopqrst/build.gradle", GRADLE)
        with patch.object(policy, "MAX_RELATIVE_BYTES", 20):
            result = self._run(fake, "mobile-release.json")
        self.assertIn("snapshot.path-limit", {issue["code"] for issue in result["issues"]})
        fake = _Fake()
        fake.add("build.gradle", b"abcd")
        with patch.object(policy, "MAX_TOTAL_BYTES", 3):
            result = self._run(fake)
        self.assertEqual(result["discovery"]["scan"]["sourceBytes"], 0)
        self.assertTrue(result["discovery"]["partial"])
        fake = _Fake()
        for index in range(5):
            fake.add(f"bad:{index}", b"")
        with patch.object(policy, "MAX_ISSUES", 2):
            result = self._run(fake)
        self.assertEqual(len(result["issues"]), 2)
        self.assertEqual(result["discovery"]["scan"]["excludedEntries"], 5)
        for name, value, hint, expected in (
            ("MAX_HINT_STRING", 4, {"keep": "ok", "drop": "12345"}, {"keep": "ok"}),
            ("MAX_HINT_ITEMS", 1, {"items": ["a", "b"]}, {"items": ["a"]}),
            ("MAX_HINT_NODES", 2, {"first": "ok", "second": "gone"}, {"first": "ok"}),
        ):
            inventory = policy._Inventory()
            with patch.object(policy, name, value):
                self.assertEqual(policy._bound_hints(hint, inventory), expected)
            self.assertTrue(inventory.partial)
        fake = _Fake()
        with patch.object(native, "MAX_HANDLES", 2):
            result = self._run(fake)
        self.assertIn("snapshot.handle-limit", {issue["code"] for issue in result["issues"]})
        fake = _Fake()
        fake.add("One.xcodeproj")
        fake.add("Two.xcodeproj")
        with patch.object(policy, "MAX_SOURCE_FILES", 1), \
             patch.object(policy, "parse_project_sources", wraps=policy.parse_project_sources) as parser:
            result = self._run(fake)
        self.assertEqual(len(parser.call_args.args[1]), 1)
        self.assertIn("snapshot.container-limit", {issue["code"] for issue in result["issues"]})

    def test_single_deadline_does_not_claim_cancellation(self):
        now = [100.0]
        fake = _Fake()
        fake.add("build.gradle", GRADLE)

        def expire(handle, count):
            now[0] = 106.0

        fake.before_read = expire
        result = self._run(fake, clock=lambda: now[0])
        self.assertEqual(fake.inventory.deadline, 105.0)
        self.assertTrue(fake.inventory.stopped)
        self.assertTrue(result["discovery"]["partial"])
        self.assertIn("snapshot.deadline", {issue["code"] for issue in result["issues"]})
        read_index = next(index for index, event in enumerate(fake.trace) if event[0] == "read")
        self.assertTrue(all(event[0] == "close" for event in fake.trace[read_index + 1:]))
        self.assertEqual(fake.inventory.counts["sourceBytes"], len(GRADLE))
        self.assertEqual(fake.mapping_calls, 1)
        owner = _shim()
        call = Mock()
        owner._check_budget = Mock(side_effect=policy._ReadProblem("snapshot.deadline", "expired"))
        with self.assertRaises(policy._ReadProblem):
            owner._invoke(call, ())
        call.assert_not_called()  # Before-entry expiry is ordinary cleanup, not fake cancellation.
        self.assertFalse(owner._poisoned)
        owner.close_all()

    def test_close_once_all_independent_unknown_fatal(self):
        for failure in (False, None, OSError("lost return"), _FakeExit("interrupted close")):
            fake = _Fake()
            fake._owned = [101, 202, 303]
            fake.close_results[303] = failure
            with self.assertRaises(native.NativeCleanupError) as caught:
                fake.close_all()
            self.assertNotIsInstance(caught.exception, OSError)
            self.assertEqual(fake._owned, [])
            closes = [event for event in fake.trace if event[0] == "close"]
            self.assertEqual([event[1] for event in closes], [303, 202, 101])
            self.assertTrue(all(event[1] not in event[2] for event in closes))
            with self.assertRaises(native.NativeCleanupError):
                fake.close_all()
            self.assertEqual(len(fake.trace), 3)  # Sticky uncertainty is not a numeric retry.
        fake = _Fake()
        fake.config()
        fake.close_results[100] = False
        with self.assertRaises(native.NativeCleanupError):
            self._run(fake)
        self.assertEqual(fake._owned, [])
        closed = [event[1] for event in fake.trace if event[0] == "close"]
        self.assertEqual(len(closed), len(set(closed)))
        self.assertCountEqual(closed, fake.handles)
        with self.assertRaises(native.NativeCleanupError):
            fake.close(100)
        self.assertEqual(len([event for event in fake.trace if event[0] == "close"]), len(closed))

    def test_unknown_completion_pins_arena_until_failstop(self):
        cases = (
            (0x103, None, 0x103, 0), (1, 303, 0, 1), (0x104, None, 0, 1),
            (0x80000005, None, 0, 1), (0, None, 0, 1), (0, native.INVALID_HANDLE, 0, 1),
            (0, 303, 0x103, 1), (0, 303, 0, 0), (0xC0000022, 303, 0, 1),
            (True, 303, 0, 1), (0, 303, False, 1), (0, 303, 0, True), (1 << 32, 303, 0, 1),
        )
        for values in cases:
            fake = _Fake()
            fake._owned = [101, 202]
            arena = {"buffers": bytearray(b"still-live"), "parents": (101, 202)}
            with self.subTest(values=values), self.assertRaises(_FakeExit):
                fake._finish_open(*values, arena)
            self.assertIs(fake._pinned, arena)
            self.assertEqual(fake._owned, [101, 202])
            self.assertEqual(fake.trace, [("failstop", 70, (101, 202))])
            fake.close_all()  # Only the inert substitute unwinds; no close is invented.
            self.assertEqual(fake._owned, [101, 202])
        owner = _shim()
        keep = _Buffer(4)

        def entered_call(*args):
            raise OSError("return/completion lost")

        with self.assertRaises(_FakeExit):
            owner._invoke(entered_call, (101,), (keep,))
        self.assertEqual(owner._pinned[2], (101, 202))
        self.assertIs(owner._pinned[4][0], keep)
        owner.close_all()
        self.assertEqual(owner._owned, [101, 202])
        for method, functions in (
            ("read", {"ReadFile": lambda *args: False}),
            ("directory", {"GetFileInformationByHandleEx": lambda *args: False}),
        ):
            owner = _shim(native.ERROR_IO_PENDING, **functions)
            with self.assertRaises(_FakeExit):
                owner.read(101, 4) if method == "read" else owner.directory_batch(101, True)
            self.assertTrue(owner._poisoned)
            self.assertEqual(owner._owned, [101, 202])
            self.assertIsInstance(owner._pinned[4][0], _Buffer)
            owner.close_all()
            self.assertEqual(owner._owned, [101, 202])
        fake = _Fake()
        with self.assertRaises(native.NativeError) as caught:
            fake._finish_open(0xC0000034, None, 0x103, native.INVALID_HANDLE, object())
        self.assertEqual(caught.exception.category, "missing")
        self.assertFalse(fake._poisoned)
        self.assertEqual(fake._finish_open(0, 303, 0, 1, object()), 303)
        self.assertEqual(fake._owned, [303])
        fake.close_all()

        def unknown(owner, operation, expected=(101, 202)):
            close = Mock(return_value=True)
            owner._b.k.CloseHandle = close
            with self.assertRaises(_FakeExit) as stopped:
                operation()
            self.assertEqual(stopped.exception.args, (70,))
            self.assertTrue(owner._poisoned)
            self.assertIsNotNone(owner._entered)
            self.assertIs(owner._pinned, owner._entered)
            self.assertEqual(tuple(owner._owned), expected)
            owner.close_all()
            owner.close(101)
            close.assert_not_called()  # No ordinary cleanup across a lost result.

        class LostTruth:
            def __bool__(self):
                raise MemoryError("inert post-return classification loss")

        # A loss AFTER the substituted native function returned, not merely an
        # exception inside it. These reached unguarded BOOL/count classification
        # in the old source. No real BOOL object/ABI behavior is claimed here.
        for operation in ("read", "directory", "mapping", "name"):
            owner = _shim(native.ERROR_IO_PENDING)
            entered = []

            def returned(*arguments):
                entered.append(owner._entered)
                return LostTruth()

            owner._b.c.create_unicode_buffer = _Buffer
            owner._b.k.ReadFile = returned
            owner._b.k.GetFileInformationByHandleEx = returned
            owner._b.k.QueryDosDeviceW = returned
            owner._b.k.GetFinalPathNameByHandleW = returned
            invoke = {
                "read": lambda: owner.read(101, 4),
                "directory": lambda: owner.directory_batch(101, True),
                "mapping": lambda: owner.drive_mapping("C:"),
                "name": lambda: owner.normalized_name(101),
            }[operation]
            with self.subTest(post_return=operation):
                unknown(owner, invoke)
            self.assertEqual(len(entered), 1)
            self.assertIs(entered[0], owner._pinned)  # Self-held BEFORE call entry.
            self.assertEqual(owner._pinned[2], (101, 202))
            self.assertIsInstance(owner._pinned[4][0], _Buffer)

        class LostErrorComparison:
            def __eq__(self, other):
                raise MemoryError("inert EOF/pending comparison loss")

        owner = _shim(LostErrorComparison(), GetFileInformationByHandleEx=lambda *args: False)
        unknown(owner, lambda: owner.directory_batch(101, True))
        owner = _shim()
        returned = Mock(return_value=17)
        owner._b.c.get_last_error = Mock(side_effect=MemoryError("inert last-error return loss"))
        unknown(owner, lambda: owner._invoke(returned, (101,), (_Buffer(4),)))
        returned.assert_called_once_with(101)

        class LostOutput:
            @property
            def value(self):
                raise MemoryError("inert output handoff loss")

        class LostOutcome:
            def __eq__(self, other):
                raise MemoryError("inert classifier-to-registration loss")

        class LostRegistration(list):
            def __init__(self, after):
                super().__init__((101, 202))
                self.after = after

            def append(self, handle):
                if self.after:
                    super().append(handle)
                raise MemoryError("inert ownership registration loss")

        # The same actual production invocation/classifier path, with Python-
        # only output objects. Guard output unpack, classifier handoff/return,
        # and successful-open ownership transfer, including append then loss.
        for stage in ("output", "classifier-entry", "classifier-handoff", "classifier-return",
                      "register-before", "register-after"):
            owner = _shim()
            buffer = _Buffer(4)
            output = LostOutput() if stage == "output" else SimpleNamespace(value=303)
            io = SimpleNamespace(Result=SimpleNamespace(Status=0), Information=1)
            entered = []

            def opened():
                entered.append(owner._entered)
                return 0

            injection = nullcontext()
            if stage == "classifier-entry":
                injection = patch.object(native, "_nt_outcome", side_effect=MemoryError("inert classifier entry loss"))
            elif stage == "classifier-handoff":
                injection = patch.object(owner, "_finish_open", side_effect=MemoryError("inert handoff loss"))
            elif stage == "classifier-return":
                injection = patch.object(native, "_nt_outcome", return_value=LostOutcome())
            elif stage.startswith("register-"):
                owner._owned = LostRegistration(stage == "register-after")
            expected = (101, 202, 303) if stage == "register-after" else (101, 202)
            with self.subTest(open_loss=stage), injection:
                unknown(owner, lambda: owner._invoke(opened, (), (buffer, output, io), completion="open"), expected)
            self.assertEqual(len(entered), 1)
            self.assertIs(entered[0], owner._pinned)
            self.assertEqual(owner._pinned[2], (101, 202))
            self.assertIs(owner._pinned[4][0], buffer)
            self.assertIs(owner._pinned[4][-2], output)
            self.assertIs(owner._pinned[4][-1], io)

        # Defense at every cleanup/new-entry boundary even if a future caller
        # loses control outside _invoke's guard. Never reconstruct the arena.
        for boundary in ("close", "close-all", "capacity", "owned", "invoke"):
            owner = _shim()
            call = Mock()
            arena = (owner, owner._b, (101, 202), (101,), (_Buffer(4),), call)
            owner._entered = arena
            action = {
                "close": lambda: owner.close(101),
                "close-all": owner.close_all,
                "capacity": owner._capacity,
                "owned": lambda: owner._require_owned(101),
                "invoke": lambda: owner._invoke(call, ()),
            }[boundary]
            with self.subTest(unclassified_boundary=boundary):
                unknown(owner, action)
            self.assertIs(owner._pinned, arena)
            call.assert_not_called()

        # Positive controls: authoritative completion releases the guard. Known
        # errors/EOF may clean up; only classified data crosses _invoke's return.
        for completion, value, error, expected in (
            ("scalar", 17, 0, 17), ("boolean", True, 0, True), ("count", 7, 0, 7),
            ("directory", False, native.ERROR_NO_MORE_FILES, None), ("directory", True, 0, True),
        ):
            owner = _shim(error)
            with self.subTest(completed=completion, value=value):
                self.assertEqual(owner._invoke(lambda: value, (), (_Buffer(4),), completion=completion), expected)
            self.assertIsNone(owner._entered)
            self.assertIsNone(owner._pinned)
            self.assertFalse(owner._poisoned)
            close = Mock(return_value=True)
            owner._b.k.CloseHandle = close
            owner.close_all()
            self.assertEqual([call.args[0] for call in close.call_args_list], [202, 101])
        for completion, error, category in (("boolean", 5, "unavailable"), ("count", 50, "unsupported"),
                                            ("directory", 5, "unavailable")):
            owner = _shim(error)
            with self.subTest(completed_error=completion), self.assertRaises(native.NativeError) as caught:
                owner._invoke(lambda: False, (), (_Buffer(4),), completion=completion)
            self.assertEqual(caught.exception.category, category)
            self.assertIsNone(owner._entered)
            self.assertFalse(owner._poisoned)
            owner.close_all()
            self.assertEqual(owner._owned, [])
        owner = _shim()
        output = SimpleNamespace(value=None)
        io = SimpleNamespace(Result=SimpleNamespace(Status=native.STATUS_PENDING), Information=native.INVALID_HANDLE)
        with self.assertRaises(native.NativeError) as caught:
            owner._invoke(lambda: 0xC0000034, (), (output, io), completion="open")
        self.assertEqual(caught.exception.category, "missing")
        self.assertIsNone(owner._entered)
        self.assertFalse(owner._poisoned)
        owner.close_all()
        self.assertEqual(owner._owned, [])

        # A loss after the CLASSIFIED open return is now safe ordinary cleanup:
        # the handle is already registered, not stranded in a raw return tuple.
        owner = _shim()
        output = SimpleNamespace(value=303)
        io = SimpleNamespace(Result=SimpleNamespace(Status=0), Information=1)

        def classified_handoff_loss():
            self.assertEqual(owner._invoke(lambda: 0, (), (output, io), completion="open"), 303)
            raise MemoryError("inert loss after known completion and registration")

        with self.assertRaises(MemoryError):
            classified_handoff_loss()
        self.assertEqual(owner._owned, [101, 202, 303])
        self.assertIsNone(owner._entered)
        self.assertIsNone(owner._pinned)
        self.assertFalse(owner._poisoned)
        close = Mock(return_value=True)
        owner._b.k.CloseHandle = close
        owner.close_all()
        self.assertEqual([call.args[0] for call in close.call_args_list], [303, 202, 101])

    def test_unchanged_result_and_false_assurance(self):
        fake = _Fake()
        fake.config()
        fake.add("build.gradle", GRADLE)
        result = self._run(fake)
        self.assertEqual(set(result), {"root", "observedAt", "observationScope", "config", "discovery", "assurance", "issues"})
        self.assertEqual(result["root"], fake.root)
        self.assertEqual(datetime.fromisoformat(result["observedAt"]).utcoffset(), timezone.utc.utcoffset(None))
        self.assertEqual(result["observationScope"], "single-request-non-atomic")
        self.assertEqual(set(result["config"]), {"path", "state", "data", "issues"})
        self.assertEqual(result["config"]["data"], _draft())
        self.assertEqual(result["discovery"]["state"], "unverified")
        self.assertFalse(result["discovery"]["partial"])
        self.assertEqual(result["discovery"]["limits"], policy.LIMITS)
        self.assertEqual(set(result["discovery"]["scan"]), {"entries", "sourceFiles", "sourceBytes", "excludedEntries"})
        self.assertEqual(result["assurance"], {
            "basis": "static-text", "projectCodeExecuted": False, "toolsProbed": False,
            "credentialsRead": False, "gitObserved": False, "storeContacted": False,
            "writesPerformed": False, "releaseReadiness": "unknown",
        })
        encoded = json.dumps(result)
        for private in (DEVICE, "file_id", "RootDirectory", "reparse_tag", '"handle"', '"volume"', "authorityToken"):
            self.assertNotIn(private, encoded)
        fake = _Fake()
        fake.add("build.gradle", b"\xff")
        partial = self._run(fake)
        self.assertTrue(partial["discovery"]["partial"])
        self.assertEqual(partial["assurance"], result["assurance"])
        self.assertEqual(set(partial), set(result))

    def test_portable_posix_imports_never_load_native(self):
        forbidden = {"ctypes", "_ctypes", "mobile_release.api._snapshot_windows",
                     "mobile_release.api._snapshot_windows_native", "mobile_release.owned_process"}

        class Guard:
            def find_spec(self, fullname, path=None, target=None):
                if fullname in forbidden:
                    raise AssertionError("forbidden native import: " + fullname)
                return None

        with patch.dict(sys.modules):
            for name in tuple(sys.modules):
                if name == "mobile_release" or name.startswith("mobile_release.") or name in forbidden:
                    del sys.modules[name]
            with patch.object(sys, "meta_path", [Guard(), *sys.meta_path]), \
                 patch.object(os, "open", side_effect=AssertionError("filesystem fallback")), \
                 patch.object(os, "_exit", side_effect=AssertionError("real exit")):
                fresh = importlib.import_module("mobile_release.api")
                fresh.execute("catalog", {})
                fresh.execute("capabilities", {})
                self.assertTrue(fresh.execute("config.validate", {"draft": _draft()})["valid"])
                fresh.execute("config.suggest", {"hints": {}})
                fresh.execute("config.preview", {"base": None, "draft": _draft()})
                posix = importlib.import_module("mobile_release.api._snapshot")
                config = {"path": CONFIG, "state": "missing", "data": None, "issues": []}
                with patch.object(posix, "posix_snapshot_available", return_value=True), \
                     patch.object(posix, "_root_handles", return_value=nullcontext(707)), \
                     patch.object(posix, "_config", return_value=config), \
                     patch.object(posix, "_walk", return_value=None):
                    result = fresh.execute("project.snapshot", {"root": "/selected"})
                self.assertEqual(result["root"], "/selected")
                self.assertFalse(forbidden & set(sys.modules))
                for name in ("ctypes", "mobile_release.api._snapshot_windows_native"):
                    with self.assertRaisesRegex(AssertionError, "forbidden native import"):
                        importlib.import_module(name)  # Negative controls cannot load a real DLL.

    def test_profile_dispatch_and_binding_failure_never_fallback(self):
        self.assertIs(policy._WINDOWS_SNAPSHOT_QUALIFIED, False)
        with patch.object(sys, "platform", "win32"), patch.object(os, "name", "nt"), \
             patch.object(os, "open", side_effect=AssertionError("fallback filesystem open")), \
             patch.object(windows, "_new_native", side_effect=AssertionError("closed gate loaded native")):
            self.assertFalse(policy.posix_snapshot_available())
            self.assertFalse(policy.snapshot_available())
            with self.assertRaises(ApiError) as caught:
                policy.project_snapshot(r"C:\selected")
            self.assertEqual(caught.exception.code, "platform_unavailable")
            caps = api.capabilities()
            self.assertFalse(next(item for item in caps["methods"] if item["method"] == "project.snapshot")["available"])
            self.assertTrue(all(not item["available"] for item in caps["actions"]))
            marker = {"inert-admitted-route": True}
            with patch.object(policy, "_WINDOWS_SNAPSHOT_QUALIFIED", True), \
                 patch.object(windows, "project_snapshot", return_value=marker) as route:
                self.assertTrue(policy.snapshot_available())
                self.assertIs(policy.project_snapshot(r"C:\selected", CONFIG), marker)
                route.assert_called_once_with(r"C:\selected", CONFIG)
        with patch.object(native, "_load_bindings", side_effect=native.NativeUnavailable("pre-call refusal")), \
             patch.object(os, "open", side_effect=AssertionError("binding fallback")):
            with self.assertRaises(ApiError) as caught:
                windows.project_snapshot(r"C:\selected")
            self.assertEqual(caught.exception.code, "platform_unavailable")
        with patch.object(sys, "platform", "linux"), patch.object(os, "name", "posix"):
            with self.assertRaises(native.NativeUnavailable):
                native._load_bindings()  # Refuses before its function-local ctypes import.
        fake = _Fake()
        fake.filesystem = "ReFS"
        with self.assertRaises(ApiError) as caught:
            self._run(fake)
        self.assertEqual(caught.exception.code, "snapshot_unavailable")
        self.assertEqual(fake._owned, [])
        self.assertEqual(len(fake.specs), 1)
