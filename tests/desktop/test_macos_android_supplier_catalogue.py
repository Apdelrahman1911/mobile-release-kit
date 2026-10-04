"""Focused pure catalogue projection regressions; no real supplier evidence.

Tiny synthetic dictionaries/snapshots below exercise rejection and literal
rendering only. They cannot pass generate()'s genuine complete-input gate,
are never compiled/installed, and do not claim native/owner finality or fit.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

_SOURCE = Path(__file__).resolve().parents[2] / "desktop/tools/macos_android_supplier_catalogue.py"
_NAME = "mrk_macos_supplier_catalogue_data_tests"
_SPEC = importlib.util.spec_from_file_location(_NAME, _SOURCE)
M = importlib.util.module_from_spec(_SPEC)
if _NAME in sys.modules:
    raise RuntimeError("unexpected catalogue test module collision")
sys.modules[_NAME] = M
_SPEC.loader.exec_module(M)
HASH = "a" * 64


def member(name, *, label="jdk", kind="file", mode=0o100644, size=1, hint=None, target=None):
    if kind != "file":
        size = 0
    zip_fields = (0, 40, max(1, size), 0 if size else 8, 0, 0, 3) if label != "jdk" else (None,) * 7
    return M.Member(name, kind, mode, size, HASH if kind == "file" else None, target, *zip_fields, hint)


def outer_document(label, rows):
    rows = sorted(rows, key=lambda row: row.name if label == "bundletool" else row.name.lower())
    return {"schemaVersion": 1, "kind": "offline-official-archive-correspondence-data", "label": label,
            "archiveBytes": M.ARCHIVES[label][0], "archiveSha256": M.ARCHIVES[label][1],
            "completeMemberHashes": True, "supplierAuthority": False, "nativeClosure": False,
            "entryHeaders": len(rows), "members": len(rows), "files": sum(row.kind == "file" for row in rows),
            "aliases": sum(row.kind == "alias" for row in rows), "expandedBytes": sum(row.size for row in rows),
            "columns": list(M.COLUMNS), "rows": [[getattr(row, name) for name in M.Member.__dataclass_fields__] for row in rows]}


def outer(label, rows):
    return M.Outer(label, outer_document(label, rows))


def snapshot(raw=b"x" * 64):
    # Deliberately NOT a Mach-O parser fixture: only encoded length/hash joins.
    encoded = base64.b64encode(raw).decode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    return {"format": "MachO", "prefixBytes": len(raw), "prefixSha256": digest, "prefixBase64": encoded,
            "selectedCpu": M.ARM64, "sliceOffset": 0, "sliceBytes": len(raw),
            "commandsBytes": len(raw), "commandsSha256": digest, "commandsBase64": encoded}


def empty_jvm(row):
    return {"name": row.name, "bytes": row.size, "sha256": row.sha256, "formatHint": row.hint,
            "centralMembers": 1, "inspectedMembers": 1, "files": 1, "completeMemberHashes": True,
            "expandedInspectedBytes": 1, "snapshotReinspectedBytes": 0, "enumerationSha256": HASH,
            "formatCounts": {key: int(key == "Data") for key in M.FORMATS}, "nativeMembers": [],
            "nestedArchives": [], "nestedArchiveHashes": [], "innerBookReservationBytes": 4096,
            "nativeExecuted": False, "supplierAuthority": False}


class CatalogueProjectionDataTests(unittest.TestCase):
    def test_strict_json_types_duplicate_keys_and_allocation_bounds(self):
        self.assertEqual(M.decode(b'{"count":12,"data":false}'), {"count": 12, "data": False})
        for raw in (b'{"count":1,"count":1}', b'{"n":1.0}', b'{"n":NaN}', b'{"n":-1}',
                    b'{"n":18446744073709551616}', b'[' * 17 + b']' * 17, b'"' + b'x' * 131073 + b'"'):
            with self.subTest(raw=raw[:64]), self.assertRaises(M.Refused):
                M.decode(raw)
        for value in (False, True, -1, 1.0, "1"):
            with self.subTest(value=value), self.assertRaises(M.Refused):
                M.integer(value)

    def test_snapshot_requires_full_canonical_bytes_not_hash_scalars(self):
        good = snapshot()
        self.assertEqual(M.header(good, 64), (b"x" * 64, b"x" * 64, M.ARM64))
        changes = ({"prefixBase64": good["prefixBase64"] + "\n"}, {"commandsSha256": HASH},
                   {"prefixBytes": True}, {"sliceOffset": 1}, {"commandsBytes": 31},
                   {"selectedCpu": False}, {"prefixBase64": "!" * len(good["prefixBase64"])})
        for edit in changes:
            with self.subTest(edit=edit), self.assertRaises(M.Refused):
                M.header({**good, **edit}, 64)
        # Noncanonical pad bits may decode to identical bytes; re-encoding is
        # still required. These are DATA bytes, not a selected release fixture.
        with self.assertRaises(M.Refused):
            M.base64_bytes("eB==", 1, hashlib.sha256(b"x").hexdigest(), 1)

    def test_outer_completeness_case_parent_and_archive_only_sgid(self):
        root = member(M.JDK_ROOT, kind="directory", mode=0o042755)
        leaf = member(M.JDK_ROOT + "/Contents/Home/data")
        good = outer_document("jdk", [root, leaf])
        accepted = M.Outer("jdk", good)
        self.assertEqual(accepted.members[0].mode, 0o042755)
        changes = ({"members": 3}, {"entryHeaders": True}, {"expandedBytes": 2}, {"completeMemberHashes": False},
                   {"archiveSha256": HASH}, {"columns": list(reversed(M.COLUMNS))})
        for edit in changes:
            with self.subTest(edit=edit), self.assertRaises(M.Refused):
                M.Outer("jdk", {**good, **edit})
        for rows in ([leaf, member(M.JDK_ROOT + "/contents/Home/other")],
                     [leaf, member(M.JDK_ROOT + "/Contents")],
                     [leaf, member(leaf.name)], [member(M.JDK_ROOT + "/bad", mode=0o102644)]):
            with self.subTest(rows=rows), self.assertRaises(M.Refused):
                M.Outer("jdk", outer_document("jdk", rows))
        # Case-sensitive sealed classes are not projected to filesystem paths.
        classes = [member("pkg/A.class", label="bundletool"), member("pkg/a.class", label="bundletool")]
        self.assertEqual(len(outer("bundletool", classes).members), 2)
        with self.assertRaises(M.Refused):
            M.source_relative("pkg/A$Inner.class")
        self.assertEqual(M.relative("pkg/A$Inner.class"), "pkg/A$Inner.class")

    def test_source_parent_derivation_preserves_real_headers_and_alias_custody(self):
        root = member(M.JDK_ROOT, kind="directory", mode=0o042755)
        real = member(M.JDK_ROOT + "/Contents", kind="directory", mode=0o042755)
        file = member(M.JDK_ROOT + "/Contents/Home/lib/value")
        alias = member(M.JDK_ROOT + "/Contents/Home/bin/link", kind="alias", mode=0o120777, target="../lib/value")
        outers = {label: SimpleNamespace(members=[]) for label in M.LABELS}
        outers["jdk"] = outer("jdk", [root, real, file, alias])
        sources = M.collect_sources(outers)
        by_name = {row.relative: row for row in sources}
        self.assertEqual(by_name["Contents"].mode, 0o755)
        self.assertIsNotNone(by_name["Contents"].member)
        self.assertIsNone(by_name["Contents/Home"].member)
        self.assertEqual(by_name["Contents/Home"].prefix, M.JDK_ROOT + "/Contents/Home")
        self.assertEqual(by_name["Contents/Home/bin/link"].canonical, "Contents/Home/lib/value")
        self.assertNotIn(M.JDK_ROOT, by_name)
        for target in ("../../../../outside", "/elsewhere", "../missing", "../bin/link"):
            changed = member(alias.name, kind="alias", mode=0o120777, target=target)
            outers["jdk"] = outer("jdk", [root, real, file, changed])
            with self.subTest(target=target), self.assertRaises(M.Refused):
                M.collect_sources(outers)
        with self.assertRaises(M.Refused):
            M.resolve_alias("Contents/value", "../../Contents/value")

    def test_jvm_empty_is_explicit_and_complete_counts_are_required(self):
        row = member("gradle-8.14.5/lib/empty.jar", label="gradle", hint="zip")
        good = empty_jvm(row)
        self.assertIs(M.jvm(good, row), good)
        for edit in ({"nativeMembers": [{}]}, {"inspectedMembers": 0}, {"completeMemberHashes": False},
                     {"files": True}, {"nativeExecuted": 0}, {"name": "other.jar"},
                     {"nestedArchives": [{"member": "child.jar", "bytes": 1, "mode": 0}]}):
            with self.subTest(edit=edit), self.assertRaises(M.Refused):
                M.jvm({**good, **edit}, row)
        modified = copy.deepcopy(good)
        modified["formatCounts"]["Data"] = 0
        with self.assertRaises(M.Refused):
            M.jvm(modified, row)

    def test_finite_foreign_resource_never_uses_basename_or_generic_data(self):
        path = "gradle/lib/native-platform-windows-amd64-0.22-milestone-28.jar"
        pin = M.NATIVE_PINS[path]
        name, size, digest, mode, kind = pin[2][0]
        row = {"name": name, "bytes": size, "sha256": digest, "mode": mode, "format": "PE",
               "prefixBytes": 4096, "prefixSha256": HASH}
        self.assertEqual(M.finite_native(path, pin[:2], [row])[0][1], kind)
        for candidate, archive, rows in (("unlisted.jar", pin[:2], [row]), (path, (pin[0] + 1, pin[1]), [row]),
                                         (path, pin[:2], []), (path, pin[:2], [{**row, "mode": mode ^ 1}]),
                                         (path, pin[:2], [{**row, "name": name.rsplit("/", 1)[-1]}])):
            with self.subTest(candidate=candidate, rows=rows), self.assertRaises(M.Refused):
                M.finite_native(candidate, archive, rows)
        proofs = SimpleNamespace(negatives={}, jvms={}, direct={})
        for item in (member("gradle-8.14.5/unknown", mode=0o100755),
                     member("gradle-8.14.5/unknown", hint="shell"),
                     member("gradle-8.14.5/unknown.jar", hint="zip"),
                     member("gradle-8.14.5/unknown.so", hint="elf")):
            with self.subTest(item=item), self.assertRaises(M.Refused):
                M.classify(item, "gradle", "gradle/unknown", proofs)

    def test_input_mapping_indexes_bind_every_record_and_never_resolve_paths(self):
        retained = b'{"inert":"unit fixture"}\n'
        one = b'{"kind":"inert-unit-record"}\n'
        pins = {"fixture-retained.json": (len(retained), hashlib.sha256(retained).hexdigest())}
        def index(labels, path):
            return M.canonical({"schemaVersion": 1, "kind": "complete-catalogue-observation-index-data", "labels": labels,
                "records": [{"path": path, "bytes": len(one), "sha256": hashlib.sha256(one).hexdigest()}],
                "nativeExecuted": False, "nativeClosure": False, "supplierAuthority": False})
        documents = {"fixture-retained.json": retained, "evidence/jdk-record.json": one, "evidence/other-record.json": one,
                     "evidence/jdk-completion.json": index(["jdk"], "evidence/jdk-record.json"),
                     "evidence/other-completion.json": index(list(M.LABELS[1:]), "evidence/other-record.json")}
        # Test only the finite mapping/index helper, never generate() and never
        # any catalogue with substituted official pins.
        with mock.patch.object(M, "RETAINED", pins):
            parsed = M.Inputs(documents)
            with self.assertRaises(M.Refused):
                parsed.finish()
            parsed.document("evidence/jdk-record.json")
            parsed.document("evidence/other-record.json")
            parsed.finish()
            with self.assertRaises(M.Refused):
                parsed.group("evidence/jdk-record.json", "sdk-platform")
            for edit in ({"evidence/jdk-record.json": one + b" "}, {"unused": b"x"},
                         {"fixture-retained.json": retained + b" "}):
                with self.subTest(edit=list(edit)), self.assertRaises(M.Refused):
                    changed = M.Inputs({**documents, **edit})
                    changed.document("evidence/jdk-record.json")
                    changed.document("evidence/other-record.json")
                    changed.finish()
        emitted = []
        with self.assertRaises(M.Refused):
            M.generate({}, emitted.append)
        self.assertEqual(emitted, [])

    def test_same_original_zip_offset_binding_and_no_supplied_rust_expressions(self):
        row = member("aapt2", label="aapt2", mode=0o100755, size=64)
        self.assertIn("ZipMethod::Stored", M.zip_literal(row))
        for changes in ({"flags": 0x8000}, {"data": 12}, {"compressed": 65}, {"data": M.ARCHIVES["aapt2"][0]}):
            values = {name: getattr(row, name) for name in M.Member.__dataclass_fields__}
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(M.Refused):
                M.zip_literal(M.Member(**values))
        value = '\"); unreachable!(); ("'
        self.assertEqual(json.loads(M.rust_string(value)), value)
        for value in ("bad\nline", "nonascii-\u00e9", "\0"):
            with self.subTest(value=value), self.assertRaises(M.Refused):
                M.rust_string(value)

    def test_streamed_emission_is_bounded_deterministic_and_sink_failure_is_not_success(self):
        # Tiny formatter-only projection; its Reference is deliberately invalid
        # as a real supplier. No compiled include or native receipt is created.
        path = M.INSTALLED_JDK + "Contents/data"
        src = M.Source("Jdk", "Contents/data", "file", 0o644, 1, HASH, None, None, 0, 0, M.JDK_ROOT + "/Contents/data")
        projection = SimpleNamespace(
            payload=[M.Payload(path, 1, HASH, 0o444, ("Picked", "Jdk", "Contents/data"), ("Data",))],
            sources=[src], aliases=[], directories=["jdk", "jdk/temurin-17.jdk", "jdk/temurin-17.jdk/Contents"],
            outers={label: SimpleNamespace(members=[]) for label in M.LABELS}, vendor_ids={(0, 0): 0},
            payload_ids={("Jdk", "Contents/data"): 0}, alias_ids={},
            aapt=member("aapt2", label="aapt2", mode=0o100755, size=64), vendor="inert-test", version="0")
        projection.outers["jdk"].members = [member(src.prefix)]
        first, second = [], []
        receipt = M.render(projection, first.append)
        self.assertEqual(receipt, M.render(projection, second.append))
        self.assertEqual(first, second)
        raw = b"".join(first)
        self.assertEqual(receipt, {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertTrue(all(len(chunk) <= 65536 for chunk in first))
        self.assertIn(b"SourceDisposition::Payload(0)", raw)
        self.assertIn(b"Component::Aapt2", raw)
        self.assertLess(raw.index(b"Component::Aapt2"), raw.index(b"Component::Bundletool"))
        self.assertNotIn(b"reference_digest", raw)
        with mock.patch.object(M, "OUTPUT_LIMIT", 8), self.assertRaises(M.Refused):
            M.render(projection, lambda _: None)
        class SinkFailure(Exception):
            pass
        def reject(_):
            raise SinkFailure()
        with self.assertRaises(SinkFailure):
            M.render(projection, reject)


if __name__ == "__main__":
    unittest.main()
