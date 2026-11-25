"""Explicitly selected, inert publisher tests; no candidate runtime is executed.

Only standard-library data codecs and ordinary, owned temporary files are used.
Archive link/special entries are in-memory headers, never host filesystem links,
FIFOs, device nodes, installed runtimes, subprocesses, or imported payload code.
Select CPythonPayloadTests explicitly after independent source/check review.
"""

from __future__ import annotations

from contextlib import nullcontext
import gzip
import hashlib
import importlib.util
import inspect
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

_SOURCE = Path(__file__).resolve().parents[2]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, _SOURCE / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


payload = _load("desktop_cpython_payload", "desktop/tools/prepare_cpython_payload.py")
preparation = _load("desktop_runtime_preparation_for_payload", "desktop/tools/prepare_runtime.py")

_BASE = {
    "python/bin/python3.14": b"INERT text, not a Python executable.\n",
    "python/lib/libpython3.14.so.1.0": b"INERT text, not a shared library.\n",
    "python/LICENSE.txt": b"INERT original-license fixture, not an actual notice.\n",
    "python/lib/python3.14/os.py": b"# inert os fixture; never imported\n",
    "python/lib/python3.14/encodings/__init__.py": b"# inert encoding fixture; never imported\n",
    "python/lib/python3.14/json/__init__.py": b"# retained inert stdlib fixture; never imported\n",
}
_NOTICES = {
    "LICENSE.fixture.txt": b"INERT notice fixture only; no redistribution approval.\n",
    "PYTHON-CHANGES.txt": b"INERT fixture for a shipped PBS/pruning/mapping/landmark change summary.\n",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(name: str, content: bytes = b"inert\n", kind: bytes = tarfile.REGTYPE, link: str = ""):
    return name, content, kind, link


def _members():
    return [_entry(name, content) for name, content in _BASE.items()]


def _tar(members, *, format: int = tarfile.PAX_FORMAT, metadata: int = 0) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=format) as archive:
        for name, content, kind, link in members:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kind, link
            info.uid, info.gid, info.mtime = metadata, metadata, metadata
            info.mode = 0o777 if metadata else 0o600
            info.size = len(content) if kind in {tarfile.REGTYPE, tarfile.AREGTYPE} else 0
            archive.addfile(info, io.BytesIO(content) if info.size else None)
    return stream.getvalue()


def _record(name: str, content: bytes = b"", *, kind: bytes = tarfile.REGTYPE,
            declared_size: int | None = None) -> bytes:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(content) if declared_size is None else declared_size
    header = info.tobuf(format=tarfile.USTAR_FORMAT)
    return header + content + b"\0" * (-len(content) % 512)


def _pax(key: bytes, value: bytes) -> bytes:
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while length != len(str(length)) + 1 + len(body):
        length = len(str(length)) + 1 + len(body)
    return str(length).encode("ascii") + b" " + body


def _inventory(notices: dict[str, bytes]) -> bytes:
    return payload._canonical({
        "schemaVersion": 1, "pythonChangeSummary": "PYTHON-CHANGES.txt",
        "files": [{"path": name, "size": len(content), "sha256": _sha(content)}
                  for name, content in sorted(notices.items())],
    }) + b"\n"


def _fixture(base: Path, *, members=None, raw: bytes | None = None,
             notices: dict[str, bytes] | None = None, inventory: bytes | None = None):
    base.mkdir(parents=True, exist_ok=True)
    members = _members() if members is None else members
    raw = _tar(members) if raw is None else raw
    compressed = gzip.compress(raw, mtime=0)
    notices = dict(_NOTICES if notices is None else notices)
    inventory = _inventory(notices) if inventory is None else inventory
    provenance = b'{"complete":true,"kind":"inert-fixture-NOT-production-provenance"}\n'
    archive_path = base / "candidate.tar.gz"
    notice_root = base / "notices"
    inventory_path = base / "notice-inventory.json"
    provenance_path = base / "static-link-provenance.json"
    archive_path.write_bytes(compressed)
    notice_root.mkdir()
    for name, content in notices.items():
        path = notice_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    inventory_path.write_bytes(inventory)
    provenance_path.write_bytes(provenance)
    required = tuple((name, len(_BASE[name]), _sha(_BASE[name])) for name, _, _ in payload._REQUIRED)
    policy = payload._Policy(len(compressed), _sha(compressed), required, _sha(inventory), _sha(provenance))
    return SimpleNamespace(base=base, archive=archive_path, notices=notice_root,
                           inventory=inventory_path, provenance=provenance_path,
                           output=base / "output", report=base / "mapping.json",
                           raw=raw, compressed=compressed, policy=policy)


def _run(fixture, *, output: Path | None = None, report: Path | None = None):
    return payload._prepare_with_policy(fixture.archive, fixture.notices, fixture.inventory,
                                        fixture.provenance, output or fixture.output,
                                        report or fixture.report, fixture.policy)


def _snapshot(root: Path) -> dict[str, bytes]:
    # Fixtures contain only owned ordinary files/directories. This helper is not
    # an alternate production inventory or a hostile-filesystem safety claim.
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*")) if path.is_file()}


def _selected(fixture):
    items, omissions = payload._archive_items(fixture.raw, fixture.policy)
    items.extend(payload._notice_items(fixture.notices, fixture.inventory.read_bytes(),
                                       fixture.policy.notice_inventory_sha256))
    items.extend(payload._Item(name, data, {"kind": "generated", "recipe": recipe})
                 for name, data, recipe in payload._GENERATED)
    return items, omissions


class CPythonPayloadTests(unittest.TestCase):
    def assert_refused_before_output(self, fixture):
        before = _snapshot(fixture.base)
        with self.assertRaises(payload.PayloadError):
            _run(fixture)
        self.assertFalse(fixture.output.exists())
        self.assertFalse(fixture.report.exists())
        self.assertEqual(_snapshot(fixture.base), before)

    def test_limits_and_both_bootstrap_reservations_match_existing_preparer(self):
        for name in ("MAX_FILES", "MAX_ENTRIES", "MAX_PATH_PARTS", "MAX_FILE_BYTES", "MAX_TOTAL_BYTES"):
            self.assertEqual(getattr(payload, name), getattr(preparation, name), name)
        self.assertEqual(set(payload.RESERVED_PAYLOAD_FILES),
                         {"core.zip", preparation.GITHUB_CA_NAME, *preparation.BOOTSTRAPS})
        self.assertEqual(len(payload.RESERVED_PAYLOAD_FILES), 8)
        self.assertEqual(payload.RESERVED_ENTRIES, 9)
        self.assertEqual(payload.RESOURCE_BYTE_HEADROOM, 64 * 1024 * 1024)
        self.assertGreater(payload.RESOURCE_BYTE_HEADROOM,
                           preparation.MAX_CORE_BYTES + len(preparation.BOOTSTRAPS) * preparation.MAX_BOOTSTRAP_BYTES
                           + preparation.MAX_GITHUB_CA_BYTES + payload.MAX_MANIFEST_BYTES)
        self.assertEqual(payload.MAX_MANIFEST_BYTES, 1024 * 1024)
        self.assertEqual(payload.MAX_MANIFEST_NODES, 20_000)
        for name in ("libpython3.14.so.1.0", "a+b.py", "engine_bootstrap.py", "A-1"):
            self.assertEqual(payload._safe_name(name), preparation._safe_name(name))
        for name in ("", ".", "..", "NUL.txt", "COM1", "x.", "a/b", "a\\b", "é", "a:b"):
            self.assertFalse(payload._safe_name(name))
            self.assertEqual(payload._safe_name(name), preparation._safe_name(name))

    def test_production_anchors_are_closed_before_any_read_parse_or_write(self):
        self.assertIsNone(payload.APPROVED_NOTICE_INVENTORY_SHA256)
        self.assertIsNone(payload.APPROVED_STATIC_LINK_PROVENANCE_SHA256)
        self.assertEqual(tuple(inspect.signature(payload.prepare).parameters),
                         ("archive", "notices", "notice_inventory", "static_link_provenance", "output", "report"))
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))  # Includes caller `complete: true`.
            args = (fixture.archive, fixture.notices, fixture.inventory, fixture.provenance,
                    fixture.output, fixture.report)
            with patch.object(payload, "_read_checked") as read, \
                    patch.object(payload, "_decode_gzip") as decode, \
                    patch.object(payload, "_write_payload") as write:
                with self.assertRaises(payload.PayloadError):
                    payload.prepare(*args)
                read.assert_not_called()
                decode.assert_not_called()
                write.assert_not_called()
            for field in ("notice_inventory_sha256", "provenance_sha256"):
                policy = fixture.policy._replace(**{field: None})
                with self.assertRaises(payload.PayloadError):
                    payload._prepare_with_policy(*args, policy)
            # A copied policy cannot label even a report as the production one.
            copy = payload._Policy(*payload._PRODUCTION_POLICY)
            mapping = json.loads(payload._report(copy, [], []))
            self.assertEqual(mapping["profile"]["kind"], "inert-test-fixture")
            self.assertNotEqual(mapping["profile"]["id"], payload.PROFILE)
            self.assertFalse(fixture.output.exists())

    def test_archive_size_and_hash_fail_before_decoder_or_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            original = fixture.policy
            for policy in (original._replace(archive_size=original.archive_size + 1),
                           original._replace(archive_size=original.archive_size - 1),
                           original._replace(archive_sha256="0" * 64)):
                with self.subTest(policy=policy):
                    fixture.policy = policy
                    with patch.object(payload, "_decode_gzip") as decode, \
                            patch.object(payload, "_write_payload") as write:
                        self.assert_refused_before_output(fixture)
                        decode.assert_not_called()
                        write.assert_not_called()

    def test_complete_gzip_crc_eof_and_decompressed_bound(self):
        raw = _tar(_members())
        compressed = gzip.compress(raw, mtime=0)
        self.assertEqual(payload._decode_gzip(compressed), raw)
        corrupted = bytearray(compressed)
        corrupted[-8] ^= 1  # CRC trailer, not a tar header.
        for invalid in (compressed[:-1], bytes(corrupted), compressed + b"\0",
                        compressed + gzip.compress(b"second stream", mtime=0), b"not gzip"):
            with self.subTest(size=len(invalid)), self.assertRaises(payload.PayloadError):
                payload._decode_gzip(invalid)
        with patch.object(payload, "MAX_TAR_BYTES", len(raw) - 1):
            with self.assertRaises(payload.PayloadError):
                payload._decode_gzip(compressed)

    def test_tar_requires_real_aligned_eof_and_rejects_second_archive(self):
        raw = _tar(_members())
        bare = raw[:len(_BASE) * 1024]  # All six inert file bodies are <512 bytes.
        broken = bytearray(raw)
        broken[1024] ^= 1  # Later invalid header, which tarfile can stop at.
        cases = (raw[:-1], bare, bare + b"\0" * 512, bare + b"\0" * 1024 + b"x" * 512,
                 raw + raw, bytes(broken), b"\0" * 512)
        with tempfile.TemporaryDirectory() as temporary:
            for index, invalid in enumerate(cases):
                with self.subTest(index=index):
                    self.assert_refused_before_output(_fixture(Path(temporary) / str(index), raw=invalid))

    def test_raw_header_metadata_count_and_recursion_caps_precede_stdlib_open(self):
        metadata = _record("pax", _pax(b"mtime", b"0"), kind=tarfile.XHDTYPE)
        large = _record("pax", kind=tarfile.XHDTYPE, declared_size=payload.MAX_METADATA_BYTES + 1)
        cases = (
            (large + b"\0" * 1024, {}),
            (metadata * 2 + _record("python/a", b"x") + b"\0" * 1024,
             {"MAX_TOTAL_METADATA_BYTES": len(_pax(b"mtime", b"0")) * 2 - 1}),
            (metadata * (payload.MAX_METADATA_CHAIN + 1) + _record("python/a", b"x") + b"\0" * 1024, {}),
            (_tar(_members()), {"MAX_TAR_HEADERS": len(_BASE) - 1}),
        )
        for raw, limits in cases:
            limit_patch = patch.multiple(payload, **limits) if limits else nullcontext()
            with self.subTest(limits=limits), limit_patch:
                with patch.object(payload.tarfile, "open", side_effect=AssertionError("stdlib must not parse")):
                    with self.assertRaises(payload.PayloadError):
                        payload._archive_items(raw, payload._PRODUCTION_POLICY)

    def test_bounded_pax_and_gnu_long_names_are_data_only(self):
        name = "python/lib/python3.14/package/" + "a" * 90 + ".py"
        for format in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
            with self.subTest(format=format), tempfile.TemporaryDirectory() as temporary:
                fixture = _fixture(Path(temporary), raw=_tar(_members() + [_entry(name, b"long inert name")], format=format))
                _run(fixture)
                self.assertEqual((fixture.output / name).read_bytes(), b"long inert name")

    def test_hard_sparse_special_unknown_and_oversized_members_refuse(self):
        cases = [_record("python/share/unsafe", kind=kind) + b"\0" * 1024
                 for kind in (tarfile.LNKTYPE, tarfile.GNUTYPE_SPARSE, tarfile.FIFOTYPE,
                              tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.CONTTYPE, b"Z")]
        cases.extend([
            _record("python/big", declared_size=payload.MAX_FILE_BYTES + 1) + b"\0" * 1024,
            _record("python/truncated", declared_size=8192) + b"\0" * 1024,
            _record("python/directory", b"body", kind=tarfile.DIRTYPE) + b"\0" * 1024,
            _record("pax", _pax(b"GNU.sparse.map", b"0,1"), kind=tarfile.XHDTYPE) + b"\0" * 1024,
            _record("pax", _pax(b"size", b"99999999999"), kind=tarfile.XHDTYPE) + b"\0" * 1024,
            _record("pax", _pax(b"size", b"2"), kind=tarfile.XHDTYPE)
            + _record("python/lib/python3.14/data", b"x") + b"\0" * 1024,
        ])
        with tempfile.TemporaryDirectory() as temporary:
            for index, raw in enumerate(cases):
                with self.subTest(index=index):
                    self.assert_refused_before_output(_fixture(Path(temporary) / str(index), raw=raw))

    def test_source_paths_are_portable_not_normalized_or_traversed(self):
        prefix = "python/lib/python3.14/"
        names = ("/python/absolute", "../python/outside", "python/../outside", "python/./dot",
                 "python//empty", "Python/not-literal-root", "python\\windows", "python/C:drive",
                 "python/NUL.txt", "python/com1", "python/LPT9.log", "python/trailing.",
                 "python/new\nline", "python/tab\tname", prefix + "é.py", prefix + "hidden\0suffix.py",
                 "python/" + "/".join(["d"] * 16), prefix + "a" * 513)
        with tempfile.TemporaryDirectory() as temporary:
            for index, name in enumerate(names):
                with self.subTest(name=repr(name)):
                    fixture = _fixture(Path(temporary) / str(index), members=_members() + [_entry(name)])
                    self.assert_refused_before_output(fixture)
            bad_directory = _fixture(Path(temporary) / "directory",
                                     members=_members() + [_entry("python/dir//", b"", tarfile.DIRTYPE)])
            self.assert_refused_before_output(bad_directory)

    def test_duplicate_source_paths_refuse_even_when_omitted(self):
        extras = (
            [_entry("python/lib/python3.14/os.py", _BASE["python/lib/python3.14/os.py"])],
            [_entry("python/share/terminfo/a"), _entry("python/share/terminfo/a")],
            [_entry("python/bin/python3", b"", tarfile.SYMTYPE, "python3.14")] * 2,
            [_entry("python/lib/python3.14/os.py", b"", tarfile.DIRTYPE)],
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, extra in enumerate(extras):
                with self.subTest(index=index):
                    self.assert_refused_before_output(_fixture(Path(temporary) / str(index), members=_members() + extra))

    def test_retained_ancestor_file_rename_notice_and_landmark_collisions_refuse(self):
        pairs = (
            ("python/lib/Foo/a", "python/lib/foo/b"),
            ("python/lib/file", "python/lib/file/child"),
            ("python/lib/name", "python/lib/NAME"),
            ("python/bin/python3", "python/bin/python3"),
            ("python/licenses/NOTICE.txt", "python/licenses/notice.txt"),
            (payload._GENERATED[0][0], payload._GENERATED[0][0]),
            (payload._GENERATED[1][0], payload._GENERATED[1][0]),
        )
        for first, second in pairs:
            with self.subTest(paths=(first, second)), self.assertRaises(payload.PayloadError):
                payload._preflight_items([payload._Item(first, b"a", {}), payload._Item(second, b"b", {})])
        with tempfile.TemporaryDirectory() as temporary:
            for index, name in enumerate((payload._EXEC_DESTINATION, *(entry[0] for entry in payload._GENERATED),
                                          "python/lib/python3.14/lib-dynload/unexpected.so")):
                self.assert_refused_before_output(_fixture(Path(temporary) / str(index), members=_members() + [_entry(name)]))

    def test_omitted_terminfo_aliases_and_links_never_resolve_or_materialize(self):
        extras = [_entry("python/share/terminfo/a/Alias"), _entry("python/share/terminfo/a/alias"),
                  _entry("python/bin/python3", b"", tarfile.SYMTYPE, "../../outside"),
                  _entry("python/lib/python3.14/external.py", b"", tarfile.SYMTYPE, "/not/read/by/this/test")]
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary), members=_members() + extras)
            with patch.object(tarfile.TarFile, "extract", side_effect=AssertionError("no extraction")), \
                    patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("no extraction")), \
                    patch.object(tarfile.TarFile, "extractfile", side_effect=AssertionError("no target resolution")):
                _run(fixture)
            self.assertEqual((fixture.output / payload._EXEC_DESTINATION).read_bytes(), _BASE[payload._EXEC_SOURCE])
            self.assertFalse((fixture.output / "python/share").exists())
            self.assertFalse((fixture.output / "python/lib/python3.14/external.py").exists())
            mapping = json.loads(fixture.report.read_bytes())
            self.assertEqual(len(mapping["omissions"]), len(extras))
            self.assertEqual({item["reason"] for item in mapping["omissions"]}, {"symbolic-link", "terminfo"})
            self.assertNotIn(b"/not/read/by/this/test", fixture.report.read_bytes())

    def test_pruning_is_explicit_and_unrelated_stdlib_and_regular_libpython_remain(self):
        drop = (
            "python/bin/pip3", "python/include/python3.14/Python.h", "python/share/man/python.1",
            "python/share/terminfo/a/ansi", "python/lib/pkgconfig/python.pc",
            "python/lib/libtcl8.6.so", "python/lib/libtk8.6.so", "python/lib/tcl8.6/init.tcl",
            "python/lib/tk8.6/data.tcl", "python/lib/itcl4.3/data", "python/lib/thread2.8/data",
            "python/lib/libpython3.14.a",
            *("python/lib/python3.14/" + tail for tail in (
                "site-packages/pip/__init__.py", "ensurepip/_bundled/pip.whl", "tkinter/__init__.py",
                "idlelib/main.py", "turtledemo/demo.py", "turtle.py", "config-3.14-x86_64-linux-gnu/Makefile",
                "__pycache__/os.cpython-314.pyc", "json/__pycache__/x.pyc", "old.pyo",
                "lib-dynload/_dbm.cpython-314-x86_64-linux-gnu.so",
                "lib-dynload/_tkinter.cpython-314-x86_64-linux-gnu.so")),
        )
        keep = ("python/lib/libpython3.so", "python/lib/libpython3.14.so",
                "python/lib/python3.14/ssl.py", "python/lib/python3.14/sqlite3/__init__.py",
                "python/lib/python3.14/dbm/__init__.py", "python/lib/python3.14/importlib/__init__.py")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary), members=_members() + [_entry(name) for name in (*drop, *keep)])
            _run(fixture)
            for name in drop:
                self.assertFalse((fixture.output / name).exists(), name)
            for name in keep:
                self.assertEqual((fixture.output / name).read_bytes(), b"inert\n", name)
            for name, data, _ in payload._GENERATED:
                self.assertEqual((fixture.output / name).read_bytes(), data)
            with zipfile.ZipFile(fixture.output / "python/lib/python314.zip") as archive:
                self.assertEqual(archive.namelist(), [])
            mapping = json.loads(fixture.report.read_bytes())
            self.assertEqual([entry["path"] for entry in mapping["omissions"]], sorted(drop))
            source = next(entry for entry in mapping["files"] if entry["path"] == payload._EXEC_DESTINATION)
            self.assertEqual(source["origin"]["member"], payload._EXEC_SOURCE)
            self.assertEqual(source["sha256"], _sha(_BASE[payload._EXEC_SOURCE]))

    def test_required_original_members_hashes_and_stdlib_landmarks_cannot_be_replaced(self):
        required = [name for name, _, _ in payload._REQUIRED] + sorted(payload._REQUIRED_STDLIB)
        cases = [[entry for entry in _members() if entry[0] != name] for name in required]
        for name, _, _ in payload._REQUIRED:
            cases.append([_entry(path, b"changed" if path == name else content) for path, content in _BASE.items()])
        cases.append([entry for entry in _members() if entry[0] != payload._EXEC_SOURCE]
                     + [_entry(payload._EXEC_SOURCE, b"", tarfile.SYMTYPE, "/external")])
        cases.append(_members() + [_entry("python/lib/unknown-native.so")])
        with tempfile.TemporaryDirectory() as temporary:
            for index, members in enumerate(cases):
                with self.subTest(index=index):
                    self.assert_refused_before_output(_fixture(Path(temporary) / str(index), members=members))

    def test_notice_inventory_is_hash_bound_and_requires_shipped_change_summary(self):
        original = json.loads(_inventory(_NOTICES))
        cases = []
        for key, value in (("pythonChangeSummary", "absent.txt"), ("schemaVersion", True), ("complete", True)):
            document = json.loads(json.dumps(original))
            document[key] = value
            cases.append(payload._canonical(document))
        for key, value in (("path", "../outside"), ("size", True), ("sha256", "F" * 64)):
            document = json.loads(json.dumps(original))
            document["files"][0][key] = value
            cases.append(payload._canonical(document))
        document = json.loads(json.dumps(original))
        document["files"].append(document["files"][0])
        cases.extend((payload._canonical(document), b'{"schemaVersion":1,"schemaVersion":1}',
                      b"[]", b"not JSON", b"[" * 2000 + b"]" * 2000))
        with tempfile.TemporaryDirectory() as temporary:
            for index, inventory in enumerate(cases):
                with self.subTest(index=index):
                    self.assert_refused_before_output(_fixture(Path(temporary) / str(index), inventory=inventory))
            fixture = _fixture(Path(temporary) / "hash")
            for field in ("notice_inventory_sha256", "provenance_sha256"):
                original_policy = fixture.policy
                fixture.policy = original_policy._replace(**{field: "0" * 64})
                with patch.object(payload, "_decode_gzip") as decode:
                    self.assert_refused_before_output(fixture)
                    decode.assert_not_called()
                fixture.policy = original_policy

    def test_notice_extra_missing_drift_empty_directories_and_ancestor_aliases_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            extra = _fixture(base / "extra")
            (extra.notices / "extra.txt").write_bytes(b"not allowlisted")
            missing = _fixture(base / "missing")
            (missing.notices / "LICENSE.fixture.txt").unlink()
            drift = _fixture(base / "drift")
            (drift.notices / "LICENSE.fixture.txt").write_bytes(b"changed")
            empty = _fixture(base / "empty")
            (empty.notices / "empty").mkdir()
            alias = _fixture(base / "alias", notices={**_NOTICES, "Group/a.txt": b"a", "group/b.txt": b"b"})
            for fixture in (extra, missing, drift, empty, alias):
                with self.subTest(path=fixture.base.name):
                    self.assert_refused_before_output(fixture)

    def test_combined_payload_file_entry_byte_and_manifest_headroom(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            items, _ = _selected(fixture)
            self.assertEqual(len(items), len(_BASE) + len(_NOTICES) + len(payload._GENERATED))
            directories = {parent.as_posix() for item in items for parent in Path(item.path).parents
                           if parent != Path(".")}
            inventory = payload._inventory(items) + [
                {"path": name, "size": payload.RESOURCE_BYTE_HEADROOM, "sha256": "0" * 64}
                for name in payload.RESERVED_PAYLOAD_FILES]
            limits = {
                "MAX_FILES": len(items) + len(payload.RESERVED_PAYLOAD_FILES),
                "MAX_ENTRIES": len(items) + len(directories) + payload.RESERVED_ENTRIES,
                "MAX_TOTAL_BYTES": sum(len(item.content) for item in items) + payload.RESOURCE_BYTE_HEADROOM,
                "MAX_FILE_BYTES": max(len(item.content) for item in items),
                "MAX_MANIFEST_BYTES": len(payload._canonical(inventory)) + payload.MANIFEST_METADATA_HEADROOM,
                "MAX_MANIFEST_NODES": 7 * len(inventory) + 32,
            }
            for name, exact in limits.items():
                with self.subTest(bound=name):
                    with patch.object(payload, name, exact):
                        self.assertEqual(payload._preflight_items(items), directories)
                    with patch.object(payload, name, exact - 1):
                        with self.assertRaises(payload.PayloadError):
                            payload._preflight_items(items)
            with patch.object(payload, "MAX_FILES", len(items) + len(payload.RESERVED_PAYLOAD_FILES) - 1), \
                    patch.object(payload, "_write_payload") as write:
                self.assert_refused_before_output(fixture)
                write.assert_not_called()

    def test_notice_and_report_independent_bounds_refuse_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            items, omissions = _selected(fixture)
            limits = {
                "MAX_NOTICE_FILES": len(_NOTICES) - 1,
                "MAX_NOTICE_ENTRIES": len(_NOTICES) - 1,
                "MAX_NOTICE_BYTES": sum(len(data) for data in _NOTICES.values()) - 1,
                "MAX_NOTICE_INVENTORY_BYTES": len(fixture.inventory.read_bytes()) - 1,
                "MAX_PROVENANCE_BYTES": len(fixture.provenance.read_bytes()) - 1,
                "MAX_REPORT_BYTES": len(payload._report(fixture.policy, items, omissions)) - 1,
            }
            for name, limit in limits.items():
                with self.subTest(bound=name), patch.object(payload, name, limit), \
                        patch.object(payload, "_write_payload") as write:
                    self.assert_refused_before_output(fixture)
                    write.assert_not_called()

    def test_identical_inputs_produce_identical_bytes_inventory_and_descriptive_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            first = _run(fixture)
            second_output, second_report = fixture.base / "second", fixture.base / "second.json"
            second = _run(fixture, output=second_output, report=second_report)
            self.assertEqual(first, second)
            self.assertEqual(_snapshot(fixture.output), _snapshot(second_output))
            self.assertEqual(fixture.report.read_bytes(), second_report.read_bytes())
            self.assertEqual({entry.name for entry in fixture.output.iterdir()}, {"python"})
            mapping = json.loads(fixture.report.read_bytes())
            self.assertEqual(mapping["profile"]["kind"], "inert-test-fixture")
            self.assertTrue(mapping["notACompletionOrHandoffReceipt"])
            self.assertEqual(mapping["evidenceKind"], "descriptive-transform-mapping")
            self.assertEqual(mapping["qualification"], "no-native-supply-or-legal-qualification")
            self.assertEqual(first["reportSha256"], _sha(fixture.report.read_bytes()))
            for entry in mapping["files"]:
                content = (fixture.output / entry["path"]).read_bytes()
                self.assertEqual((entry["size"], entry["sha256"]), (len(content), _sha(content)))
                mode = stat.S_IMODE((fixture.output / entry["path"]).stat().st_mode)
                self.assertEqual(mode, 0o755 if entry["path"] == payload._EXEC_DESTINATION else 0o644)

    def test_tar_order_owners_modes_times_do_not_change_selected_bytes_but_digest_is_honest(self):
        members = _members() + [_entry("python/share/terminfo/z/ignored")]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first = _fixture(base / "first", raw=_tar(members))
            second = _fixture(base / "second", raw=_tar(list(reversed(members)), metadata=321))
            _run(first)
            _run(second)
            self.assertEqual(_snapshot(first.output), _snapshot(second.output))
            left, right = json.loads(first.report.read_bytes()), json.loads(second.report.read_bytes())
            self.assertNotEqual(left["archive"]["sha256"], right["archive"]["sha256"])
            self.assertEqual(left.pop("archive")["sha256"], _sha(first.compressed))
            self.assertEqual(right.pop("archive")["sha256"], _sha(second.compressed))
            self.assertEqual(left, right)

    def test_existing_output_report_and_report_inside_output_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            empty = _fixture(base / "empty")
            empty.output.mkdir()
            occupied = _fixture(base / "occupied")
            occupied.output.mkdir()
            (occupied.output / "keep").write_bytes(b"existing output")
            report = _fixture(base / "report")
            report.report.write_bytes(b"existing report")
            for fixture in (empty, occupied, report):
                before = _snapshot(fixture.base)
                with self.assertRaises(payload.PayloadError):
                    _run(fixture)
                self.assertEqual(_snapshot(fixture.base), before)
            inside = _fixture(base / "inside")
            with self.assertRaises(payload.PayloadError):
                _run(inside, report=inside.output / "report.json")
            self.assertFalse(inside.output.exists())
            with self.assertRaises(payload.PayloadError):
                _run(inside, output=inside.notices / "output")
            with self.assertRaises(payload.PayloadError):
                _run(inside, report=inside.notices / "report.json")
            with self.assertRaises(payload.PayloadError):
                _run(inside, output=Path("relative-output"))

    def test_checked_input_identity_and_ordinary_file_failures_are_inert(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ordinary"
            path.write_bytes(b"inert")
            original = path.stat()
            changed = SimpleNamespace(**{name: getattr(original, name) for name in
                                         ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                                          "st_mtime_ns", "st_ctime_ns")})
            changed.st_size += 1
            for values in ([changed], [original, changed]):
                with patch.object(payload.os, "fstat", side_effect=values):
                    with self.assertRaises(payload.PayloadError):
                        payload._read_checked(path, limit=100)
            for mode, links, attributes in ((stat.S_IFLNK, 1, 0), (stat.S_IFIFO, 1, 0),
                                            (stat.S_IFREG, 2, 0), (stat.S_IFREG, 1, 0x400)):
                # Only mocked stat metadata, not a host symlink/hardlink/FIFO.
                value = SimpleNamespace(st_mode=mode, st_nlink=links, st_file_attributes=attributes)
                with patch.object(Path, "lstat", return_value=value):
                    with self.assertRaises(payload.PayloadError):
                        payload._ordinary(path)
            self.assertEqual(path.read_bytes(), b"inert")

    def test_read_failure_leaves_no_output_and_partial_write_remains_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            before = _snapshot(fixture.base)
            with patch.object(payload, "_read_checked", side_effect=OSError("inert injected read failure")):
                with self.assertRaises(OSError):
                    _run(fixture)
            self.assertEqual(_snapshot(fixture.base), before)
            original = payload._write_file

            def partial(path, content, mode):
                if path == fixture.output / payload._EXEC_DESTINATION:
                    with path.open("xb") as stream:
                        stream.write(b"inert partial bytes")
                    raise OSError("inert injected write failure")
                original(path, content, mode)

            with patch.object(payload, "_write_file", side_effect=partial):
                with self.assertRaises(OSError):
                    _run(fixture)
            self.assertTrue((fixture.output / "INCOMPLETE").is_file())
            self.assertEqual((fixture.output / payload._EXEC_DESTINATION).read_bytes(), b"inert partial bytes")
            self.assertFalse(fixture.report.exists())
            for name, content in before.items():
                self.assertEqual((fixture.base / name).read_bytes(), content)
            source = fixture.base / "empty-source"
            source.mkdir()
            with self.assertRaises(preparation.PreparationError):
                preparation.prepare(source, fixture.output, payload.TARGET)
            self.assertFalse((fixture.output / "manifest.json").exists())
            for name in payload.RESERVED_PAYLOAD_FILES:
                self.assertFalse((fixture.output / name).exists())

    def test_output_recheck_detects_extra_empty_changed_and_wrong_mode_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            for index, mutation in enumerate(("extra", "empty", "bytes", "mode")):
                fixture = _fixture(Path(temporary) / str(index))
                original = payload._verify_output

                def altered(root, items, directories):
                    executable = root / payload._EXEC_DESTINATION
                    if mutation == "extra":
                        (root / "extra.txt").write_bytes(b"unexpected")
                    elif mutation == "empty":
                        (root / "empty").mkdir()
                    elif mutation == "bytes":
                        executable.write_bytes(b"changed inert output")
                    else:
                        executable.chmod(0o644)
                    original(root, items, directories)

                with self.subTest(mutation=mutation), patch.object(payload, "_verify_output", side_effect=altered):
                    with self.assertRaises(payload.PayloadError):
                        _run(fixture)
                self.assertTrue((fixture.output / "INCOMPLETE").is_file())
                self.assertFalse(fixture.report.exists())

    def test_recheck_report_and_final_sentinel_failures_never_publish_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            recheck = _fixture(base / "recheck")
            with patch.object(payload, "_verify_output", side_effect=payload.PayloadError("inert recheck failure")):
                with self.assertRaises(payload.PayloadError):
                    _run(recheck)
            self.assertTrue((recheck.output / "INCOMPLETE").exists())
            self.assertFalse(recheck.report.exists())
            for stage in ("report-write", "report-read", "sentinel"):
                fixture = _fixture(base / stage)
                write, read, unlink = payload._write_file, payload._read_checked, Path.unlink

                def failed_write(path, data, mode):
                    write(path, data, mode)
                    if path == fixture.report:
                        raise OSError("inert post-report write failure")

                def failed_read(path, *, limit):
                    if path == fixture.report:
                        raise OSError("inert report recheck failure")
                    return read(path, limit=limit)

                def failed_unlink(path, *args, **kwargs):
                    if path == fixture.output / "INCOMPLETE":
                        raise OSError("inert sentinel removal failure")
                    return unlink(path, *args, **kwargs)

                replacement = {"report-write": patch.object(payload, "_write_file", side_effect=failed_write),
                               "report-read": patch.object(payload, "_read_checked", side_effect=failed_read),
                               "sentinel": patch.object(Path, "unlink", failed_unlink)}[stage]
                with self.subTest(stage=stage), replacement:
                    with self.assertRaises(OSError):
                        _run(fixture)
                self.assertTrue((fixture.output / "INCOMPLETE").is_file())
                mapping = json.loads(fixture.report.read_bytes())
                self.assertTrue(mapping["notACompletionOrHandoffReceipt"])
                self.assertEqual(mapping["evidenceKind"], "descriptive-transform-mapping")
                self.assertEqual(mapping["profile"]["kind"], "inert-test-fixture")

    def test_inert_python_only_handoff_to_existing_preparer_includes_both_bootstraps(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            _run(fixture)
            source = fixture.base / "source"
            package = source / "src/mobile_release"
            package.mkdir(parents=True)
            (package / "__init__.py").write_bytes(b'__version__ = "0.3.0"\n')
            (package / "_desktop_engine.py").write_bytes(b"# inert source, never imported\n")
            (source / "desktop").mkdir()
            for bootstrap in preparation.BOOTSTRAPS:
                (source / "desktop" / bootstrap).write_bytes(b"# inert bootstrap, never executed\n")
            # Opaque inventory data only: not a certificate or trust-store fixture.
            (source / "desktop" / preparation.GITHUB_CA_NAME).write_bytes(b"INERT CA INVENTORY DATA ONLY\n")
            self.assertEqual({path.name for path in fixture.output.iterdir()}, {"python"})
            result = preparation.prepare(source, fixture.output, payload.TARGET)
            manifest = json.loads((fixture.output / "manifest.json").read_bytes())
            paths = {entry["path"] for entry in manifest["files"]}
            self.assertTrue(set(payload.RESERVED_PAYLOAD_FILES) <= paths)
            self.assertIn("python/licenses/PYTHON-CHANGES.txt", paths)
            self.assertTrue({entry[0] for entry in payload._GENERATED} <= paths)
            self.assertIn(payload._EXEC_DESTINATION, paths)
            self.assertNotIn(payload._EXEC_SOURCE, paths)
            self.assertEqual(len(paths), len(_BASE) + len(_NOTICES) + len(payload._GENERATED)
                             + len(payload.RESERVED_PAYLOAD_FILES))
            self.assertEqual(result["qualification"], "prepared-not-native-verified")
            self.assertIsNone(payload.APPROVED_NOTICE_INVENTORY_SHA256)
            self.assertIsNone(payload.APPROVED_STATIC_LINK_PROVENANCE_SHA256)


if __name__ == "__main__":
    unittest.main()
