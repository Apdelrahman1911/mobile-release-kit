"""Sixteen inert Windows reader contracts, not Windows qualification.

Only dictionaries, synthetic handle numbers and bounded byte buffers are used.
Native calls/exit are substituted or refused before entry; no DLL is loaded. Fake
relative opens/mutations prove call ordering, not NTFS, ABI, ACL or reparse
semantics. A substituted fail-stop proves retained references, not process/IO
finality or successful native CloseHandle receipts. No filesystem fixtures.
"""
from __future__ import annotations

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
        self.assertEqual(result["discovery"]["hints"]["android"]["applicationId"], "org.fixture.app")
        self.assertEqual(result["discovery"]["hints"]["ios"]["bundleId"], "org.fixture.ios")
        self.assertEqual(result["config"]["state"], "format-valid")
        opened = {spec.name for spec in fake.specs}
        self.assertFalse(opened & {".git", "node_modules", "build", "private", "secrets", "credentials", ".venv", "Pods"})
        self.assertFalse(opened & {"README.txt", "gradlew", "local.properties"})
        self.assertNotIn("private-canary", json.dumps(result))
        self.assertNotIn("9.9.9", json.dumps(result["discovery"]))
        self.assertFalse(result["discovery"]["partial"])

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
