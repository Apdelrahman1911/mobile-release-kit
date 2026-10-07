"""Focused pure catalogue projection regressions; no real supplier evidence.

Tiny synthetic dictionaries/snapshots and explicit fixed public DATA excerpts
below exercise rejection and literal rendering only. They cannot pass generate()'s genuine complete-input gate,
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


# Exact public DATA excerpts, not a fabricated complete supplier or native proof.
# The SDK wrapper has ONE synthetic outer row; the real operation's whole report
# remains separate evidence. No archive or runtime is opened by these tests.
_G2_JDK_RELEASE = b'IMPLEMENTOR="Eclipse Adoptium"\nIMPLEMENTOR_VERSION="Temurin-17.0.20.1+1"\nJAVA_RUNTIME_VERSION="17.0.20.1+1"\nJAVA_VERSION="17.0.20.1"\nJAVA_VERSION_DATE="2026-08-18"\nLIBC="default"\nMODULES="java.base java.compiler java.datatransfer java.xml java.prefs java.desktop java.instrument java.logging java.management java.security.sasl java.naming java.rmi java.management.rmi java.net.http java.scripting java.security.jgss java.transaction.xa java.sql java.sql.rowset java.xml.crypto java.se java.smartcardio jdk.accessibility jdk.internal.jvmstat jdk.attach jdk.charsets jdk.compiler jdk.crypto.ec jdk.crypto.cryptoki jdk.dynalink jdk.internal.ed jdk.editpad jdk.hotspot.agent jdk.httpserver jdk.incubator.foreign jdk.incubator.vector jdk.internal.le jdk.internal.opt jdk.internal.vm.ci jdk.internal.vm.compiler jdk.internal.vm.compiler.management jdk.jartool jdk.javadoc jdk.jcmd jdk.management jdk.management.agent jdk.jconsole jdk.jdeps jdk.jdwp.agent jdk.jdi jdk.jfr jdk.jlink jdk.jpackage jdk.jshell jdk.jsobject jdk.jstatd jdk.localedata jdk.management.jfr jdk.naming.dns jdk.naming.rmi jdk.net jdk.nio.mapmode jdk.random jdk.sctp jdk.security.auth jdk.security.jgss jdk.unsupported jdk.unsupported.desktop jdk.xml.dom jdk.zipfs"\nOS_ARCH="x86_64"\nOS_NAME="Darwin"\nSOURCE=".:git:79597447bd94"\nBUILD_SOURCE="git:e6ba7dec3d07654074559310376a3ae89da5f4ac"\nBUILD_SOURCE_REPO="https://github.com/adoptium/temurin-build.git"\nSOURCE_REPO="https://github.com/adoptium/jdk17u.git"\nFULL_VERSION="17.0.20.1+1"\nSEMANTIC_VERSION="17.0.20.1+1"\nBUILD_INFO="OS: macOS Version: 14.1 23B74"\nJVM_VARIANT="Hotspot"\nJVM_VERSION="17.0.20.1+1"\nIMAGE_TYPE="JDK"\n'
_G2_JDK_CFG = b'-server KNOWN\n-client IGNORE\n'
_G2_MANIFEST_BYTES = b"Manifest-Version: 1.0\nCreated-By: soong_zip\n\n"


def fresh_sdk_manifest():
    """Independent exact observed tuple and tiny synthetic containing census."""
    row = ['android-15/renderscript/lib/androidx-rs.jar',
     'file',
     33188,
     155117,
     '174eb53df52a9cca7bf9c396ba93bf4ac0262a48f2a1375f626efddf405d4666',
     None,
     71506503,
     71506592,
     143766,
     8,
     8,
     4195204064,
     3,
     'zip']
    inner = {'bytes': 155117,
     'centralMembers': 87,
     'completeMemberHashes': True,
     'directoryMembers': 3,
     'enumerationSha256': '841abae6dabfdc606b1188d54e0a1e7d7ae2875380ccc5b95ec2a9de44c3efee',
     'expandedInspectedBytes': 338616,
     'files': 84,
     'foreignNativeMembers': [],
     'format': 'zip',
     'formatCounts': {'ambiguous-native': 0,
                      'foreign-native': 0,
                      'java-class-header': 83,
                      'jmod': 0,
                      'macho': 0,
                      'opaque': 1,
                      'shell': 0,
                      'unsupported-jmod': 0,
                      'unsupported-native': 0,
                      'zip': 0},
     'innerBookReservationBytes': 162552,
     'inspectedMembers': 87,
     'issuedReadBytes': 375769,
     'mode': 33188,
     'name': 'android-15/renderscript/lib/androidx-rs.jar',
     'nativeExecuted': False,
     'nativeMembers': [],
     'negativeEvidence': None,
     'nestedArchives': [],
     'sha256': '174eb53df52a9cca7bf9c396ba93bf4ac0262a48f2a1375f626efddf405d4666',
     'supplierAuthority': False,
     'unknownMembers': [{'bytes': 45,
                         'format': 'opaque',
                         'mode': 33216,
                         'name': 'META-INF/MANIFEST.MF',
                         'prefixBase64': 'TWFuaWZlc3QtVmVyc2lvbjogMS4wCkNyZWF0ZWQtQnk6IHNvb25nX3ppcAoK',
                         'prefixBytes': 45,
                         'prefixSha256': '5b85b9d62b7ac535a1d6d3c4801a50d63a08bc1cc31d55ca1396c34c8be6d332',
                         'reason': 'executable-opaque',
                         'sha256': '5b85b9d62b7ac535a1d6d3c4801a50d63a08bc1cc31d55ca1396c34c8be6d332'}],
     'zipViewOffset': 0}
    summary = {"entryHeaders": 1, "members": 1, "files": 1, "aliases": 0,
               "expandedBytes": row[3], "issuedReadBytes": 76857898,
               "rosterReservationBytes": 1536 + 8 * len(row[0])}
    origin = M._fresh_outer("sdk-build-tools", summary, [row])
    return origin, inner, row, summary


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

        # A tiny inert header tests the new producer's ORIGINAL representation;
        # neither these bytes nor a successful validator confer loader policy.
        def fresh_native(name="bin/java", cpu=0x01000007):
            words = (0xFEEDFACF, cpu, 3, 2, 1, 8, 0, 0, 1, 8)
            raw = b"".join(word.to_bytes(4, "little") for word in words)
            digest = hashlib.sha256(raw).hexdigest()
            value = {"name": name, "bytes": len(raw), "mode": 0o100755, "sha256": digest, "format": "macho",
                     "prefixBytes": len(raw), "prefixSha256": digest, "prefixBase64": base64.b64encode(raw).decode("ascii"),
                     "selectedCpu": "x86_64", "sliceOffset": 0, "sliceBytes": len(raw), "commandsBytes": len(raw),
                     "commandsSha256": digest, "commandsBase64": base64.b64encode(raw).decode("ascii")}
            return value, raw
        current, body = fresh_native()
        self.assertEqual(M._fresh_native(current), (body, body))
        for edit in ({"selectedCpu": M.ARM64}, {"sliceBytes": True}, {"sliceOffset": 1},
                     {"commandsSha256": HASH}, {"prefixBase64": current["prefixBase64"] + "\n"},
                     {"mode": 0o102755}, {"bytes": True}, {"format": "MachO"}, {"unrecognized": 1}):
            with self.subTest(edit=edit), self.assertRaises(M.Refused):
                M._fresh_native({**current, **edit})
        nonhost, nonhost_body = fresh_native(cpu=M.ARM64)
        nonhost.update(selectedCpu=None, sliceOffset=None, sliceBytes=None, commandsBytes=0,
                       commandsSha256=None, commandsBase64=None)
        self.assertEqual(M._fresh_native(nonhost), (nonhost_body, None))
        fat = bytearray(256)
        fat[:8] = b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big")
        for at, cpu, offset in ((8, M.ARM64, 64), (28, 0x01000007, 128)):
            fat[at:at + 20] = b"".join(n.to_bytes(4, "big") for n in (cpu, 3, offset, 64, 6))
        fat[128:128 + len(body)] = body
        fat = bytes(fat)
        def fat_row(raw):
            digest = hashlib.sha256(raw).hexdigest()
            return {**current, "bytes": len(raw), "sha256": digest, "prefixBytes": len(raw), "prefixSha256": digest,
                    "prefixBase64": base64.b64encode(raw).decode("ascii"), "sliceOffset": 128, "sliceBytes": 64}
        self.assertEqual(M._fresh_native(fat_row(fat)), (fat, body))
        for at, changed_word in ((4, 5), (28, M.ARM64), (36, 64), (44, 21)):
            changed_fat = fat[:at] + changed_word.to_bytes(4, "big") + fat[at + 4:]
            with self.subTest(fat_field=at), self.assertRaises(M.Refused):
                M._fresh_native(fat_row(changed_fat))
        wrong_nonhost = {**current, **{key: nonhost[key] for key in
                        ("selectedCpu", "sliceOffset", "sliceBytes", "commandsBytes", "commandsSha256", "commandsBase64")}}
        with self.assertRaises(M.Refused):
            M._fresh_native(wrong_nonhost)
        # Distinct prefix/commands commitments must also agree on their actual
        # overlapping bytes, not merely have individually valid SHA scalars.
        changed = body[:12] + (6).to_bytes(4, "little") + body[16:]
        with self.assertRaises(M.Refused):
            M._fresh_native({**current, "commandsBase64": base64.b64encode(changed).decode("ascii"),
                             "commandsSha256": hashlib.sha256(changed).hexdigest()})
        direct = {**current, "name": M.JDK_ROOT + "/Contents/Home/bin/java"}
        embedded = {**current, "counterpart": {"candidate": direct["name"], "matched": True,
                                               "status": "exact-byte-and-snapshot-match"}}
        self.assertEqual(M._fresh_native(embedded, counterpart=True), (body, body))
        archive = {"name": M.JDK_ROOT + "/Contents/Home/jmods/java.base.jmod", "format": "jmod", "nativeMembers": [embedded]}
        M._fresh_jdk_counterparts([direct], [archive])
        for edit in ({"candidate": "elsewhere/bin/java"}, {"matched": 1}, {"status": "unmatched"}):
            wrong = copy.deepcopy(archive)
            wrong["nativeMembers"][0]["counterpart"].update(edit)
            with self.subTest(edit=edit), self.assertRaises(M.Refused):
                M._fresh_jdk_counterparts([direct], [wrong])
        with self.assertRaises(M.Refused):
            M._fresh_jdk_counterparts([{**direct, "sha256": HASH}], [archive])
        foreign_raw = b"\x7fELF" + b"unit-data" * 2
        foreign = {"name": "native/linux.so", "bytes": len(foreign_raw), "mode": 0o100644,
                   "sha256": hashlib.sha256(foreign_raw).hexdigest(), "format": "foreign-native",
                   "prefixBase64": base64.b64encode(foreign_raw).decode("ascii")}
        self.assertEqual(M._fresh_foreign(foreign, complete=False), "ELF")
        complete = {**foreign, "format": "ELF", "prefixBytes": len(foreign_raw), "prefixSha256": foreign["sha256"]}
        self.assertEqual(M._fresh_foreign(complete, complete=True), "ELF")
        for value, complete_mode in (({**complete, "format": "PE"}, True), (foreign, True), (complete, False),
                                     ({**foreign, "format": "unsupported-native"}, False)):
            with self.subTest(complete=complete_mode), self.assertRaises(M.Refused):
                M._fresh_foreign(value, complete=complete_mode)

        # The inert exception needs every observed byte, not just a trusted-looking SHA.
        origin, manifest_jar, _, _ = fresh_sdk_manifest()
        containing = origin.by_name[manifest_jar["name"]]
        special = manifest_jar["unknownMembers"][0]
        self.assertEqual(M.base64_bytes(special["prefixBase64"], special["prefixBytes"],
                                       special["prefixSha256"], 45), _G2_MANIFEST_BYTES)
        self.assertEqual(hashlib.sha256(_G2_MANIFEST_BYTES).hexdigest(), special["sha256"])
        self.assertEqual(M._fresh_inner(manifest_jar, containing, complete=True, container=origin), (338616, 375769))
        for edit in ({"prefixBase64": special["prefixBase64"] + "\n"}, {"prefixBytes": True},
                     {"prefixBytes": 44}, {"prefixSha256": HASH},
                     {"prefixBase64": base64.b64encode(b"X" + _G2_MANIFEST_BYTES[1:]).decode("ascii")},
                     {"prefixBase64": base64.b64encode(_G2_MANIFEST_BYTES[:-1]).decode("ascii")},
                     {"prefixBase64": special["prefixBase64"] + "="}):
            wrong = copy.deepcopy(manifest_jar)
            wrong["unknownMembers"][0].update(edit)
            with self.subTest(inert_prefix=edit), self.assertRaises(M.Refused):
                M._fresh_inner(wrong, containing, complete=True, container=origin)

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

        def fresh_report(label):
            file = member("NOTICE", label=label)
            old = outer_document(label, [file])
            roster = 1536 + 8 * len(file.name)
            summary = {key: old[key] for key in ("entryHeaders", "members", "files", "aliases", "expandedBytes")}
            summary.update(issuedReadBytes=M.ARCHIVES[label][0], rosterReservationBytes=roster)
            complete = label in ("gradle", "sdk-platform", "sdk-build-tools")
            doc = {"schemaVersion": 1, "kind": "mrk-intel-complete-non-jdk-observation-data-v1" if complete
                    else "mrk-intel-non-jdk-observation-data-v1", "target": "x86_64-apple-darwin", "component": label,
                   "archiveBytes": M.ARCHIVES[label][0], "archiveSha256": M.ARCHIVES[label][1],
                   "columns": list(M.COLUMNS), "outer": summary, "rows": old["rows"], "completeOuterMemberHashes": True,
                   "formatCounts": {key: int(key == "opaque") for key in M._FRESH_FORMATS},
                   "nativeMembers": [], "unknownMembers": [], "uninspectedInnerArchives": [], "uninspectedInnerArchiveCount": 0,
                   "innerInspectionScope": "all-complete-outer-zip-or-jmod" if complete else "fixed-selected-outer-jars-only",
                   "remainingObligations": list(M._FRESH_COMPLETE_OBLIGATIONS if complete else M._FRESH_SELECTED_OBLIGATIONS),
                   "issuedReadBytes": M.ARCHIVES[label][0], "innerExpandedBytes": 0,
                   "prepublicationPeakReservedBytes": 8 * 1024 * 1024 + roster,
                   "prepublicationPeakReservations": {"payload": 0, "rows": roster, "facts": 0, "output": 0, "other": 8 * 1024 * 1024},
                   "reservationMeaning": "explicit-owned-allocation-budget-not-total-interpreter-memory",
                   "nativeExecuted": False, "nativeClosure": False, "supplierAuthority": False}
            if complete:
                doc.update(completeInnerCoverage=True, directoryMembers=0, foreignNativeMembers=[], innerArchives=[])
            else:
                doc["selectedInnerArchives"] = []
            return doc
        for label in M.LABELS[1:]:
            report = fresh_report(label)
            parsed = M._fresh_non_jdk(label, report)
            self.assertEqual(parsed.members[0], member("NOTICE", label=label))
            for edit in ({"target": "aarch64-apple-darwin"}, {"archiveSha256": HASH}, {"completeOuterMemberHashes": False},
                         {"nativeExecuted": 0}, {"supplierAuthority": True}, {"component": "jdk"},
                         {"columns": list(reversed(M.COLUMNS))}, {"uninspectedInnerArchiveCount": True},
                         {"issuedReadBytes": report["issuedReadBytes"] + 1}, {"innerExpandedBytes": 1},
                         {"remainingObligations": []}, {"innerInspectionScope": "unrestricted"}):
                with self.subTest(label=label, edit=edit), self.assertRaises(M.Refused):
                    M._fresh_non_jdk(label, {**report, **edit})
            wrong = copy.deepcopy(report)
            wrong["outer"]["files"] = 0
            with self.assertRaises(M.Refused):
                M._fresh_non_jdk(label, wrong)
            wrong = copy.deepcopy(report)
            wrong["rows"][0][2] = 0o102644
            with self.assertRaises(M.Refused):
                M._fresh_non_jdk(label, wrong)
        selected_only = fresh_report("aapt2")
        with self.assertRaises(M.Refused):
            M._fresh_non_jdk("gradle", selected_only)
        complete = fresh_report("gradle")
        for edit in ({"completeInnerCoverage": False}, {"directoryMembers": 1}, {"negativeEvidence": {}},
                     {"unknownMembers": [{"name": "unknown"}]}, {"selectedInnerArchives": []}):
            with self.subTest(edit=edit), self.assertRaises(M.Refused):
                M._fresh_non_jdk("gradle", {**complete, **edit})
        # A complete-looking file list without its actual archive interior is
        # still incomplete. Likewise a suffix cannot hide an opaque executable.
        for name, hint, mode in (("needed.jar", "zip", 0o100644), ("hidden.jar", None, 0o100644),
                                 ("unknown.bin", None, 0o100755)):
            wrong = copy.deepcopy(complete)
            wrong["rows"][0][0], wrong["rows"][0][2], wrong["rows"][0][-1] = name, mode, hint
            wrong["outer"]["rosterReservationBytes"] = 1536 + 8 * len(name)
            if hint == "zip":
                wrong["formatCounts"]["opaque"], wrong["formatCounts"]["zip"] = 0, 1
            with self.subTest(name=name), self.assertRaises(M.Refused):
                M._fresh_non_jdk("gradle", wrong)
        self.assertEqual(M._fresh_pin("jdk"), (180578248, "c01975da12ed4235250ff891fe8bba73a9e73037d444b269c9d0922b5dbc8e0a"))
        self.assertNotEqual(M._fresh_pin("jdk"), M.ARCHIVES["jdk"][:2])
        self.assertEqual(M.Outer("jdk", good).members, accepted.members)

        # Only the admitted SDK origin plus its ORIGINAL containing row permits the
        # exact inert special. This remains a synthetic one-row aggregate DATA fixture.
        origin, manifest_jar, manifest_row, summary = fresh_sdk_manifest()
        report = fresh_report("sdk-build-tools")
        report.update(rows=[manifest_row], outer=summary, innerArchives=[manifest_jar],
                      innerExpandedBytes=338616, issuedReadBytes=76857898 + 375769)
        report["formatCounts"]["opaque"], report["formatCounts"]["zip"] = 0, 1
        report["prepublicationPeakReservations"]["rows"] = summary["rosterReservationBytes"]
        report["prepublicationPeakReservedBytes"] = 8 * 1024 * 1024 + summary["rosterReservationBytes"]
        unchanged = copy.deepcopy(report)
        accepted = M._fresh_non_jdk("sdk-build-tools", report)
        self.assertEqual(accepted.by_name[manifest_jar["name"]].tuple(), origin.by_name[manifest_jar["name"]].tuple())
        self.assertEqual(report, unchanged)
        for edit in ({"archiveBytes": 76857899}, {"archiveSha256": HASH}, {"target": "aarch64-apple-darwin"}):
            with self.subTest(inert_archive=edit), self.assertRaises(M.Refused):
                M._fresh_non_jdk("sdk-build-tools", {**report, **edit})
        wrong_component = copy.deepcopy(report)
        wrong_component.update(component="gradle", archiveBytes=M.ARCHIVES["gradle"][0],
                               archiveSha256=M.ARCHIVES["gradle"][1])
        wrong_component["outer"]["issuedReadBytes"] = M.ARCHIVES["gradle"][0]
        wrong_component["issuedReadBytes"] = M.ARCHIVES["gradle"][0] + 375769
        with self.assertRaises(M.Refused):
            M._fresh_non_jdk("gradle", wrong_component)
        for field, value in (("name", "elsewhere/renderscript/lib/androidx-rs.jar"),
                             ("mode", 0o100444), ("bytes", 155118), ("sha256", HASH)):
            wrong = copy.deepcopy(report)
            index = {"name": 0, "mode": 2, "bytes": 3, "sha256": 4}[field]
            wrong["rows"][0][index] = value
            wrong["innerArchives"][0][field] = value
            wrong["outer"]["expandedBytes"] = wrong["rows"][0][3]
            roster = 1536 + 8 * len(wrong["rows"][0][0])
            wrong["outer"]["rosterReservationBytes"] = roster
            wrong["prepublicationPeakReservations"]["rows"] = roster
            wrong["prepublicationPeakReservedBytes"] = 8 * 1024 * 1024 + roster
            with self.subTest(inert_jar=field), self.assertRaises(M.Refused):
                M._fresh_non_jdk("sdk-build-tools", wrong)
        containing = origin.by_name[manifest_jar["name"]]
        equal_but_unbound = copy.copy(containing)
        self.assertEqual(equal_but_unbound, containing)
        self.assertIsNot(equal_but_unbound, containing)
        with self.assertRaises(M.Refused):
            M._fresh_inner(manifest_jar, equal_but_unbound, complete=True, container=origin)

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

        def fresh_inner(name="unit.jar", *, complete=True):
            result = {"name": name, "bytes": 100, "sha256": HASH, "mode": 0o100644, "format": "zip", "zipViewOffset": 0,
                      "centralMembers": 2, "inspectedMembers": 2, "files": 1, "completeMemberHashes": True,
                      "expandedInspectedBytes": 1, "enumerationSha256": HASH,
                      "formatCounts": {key: int(key == "opaque") for key in M._FRESH_FORMATS},
                      "nativeMembers": [], "unknownMembers": [], "nestedArchives": [],
                      "innerBookReservationBytes": 4096, "issuedReadBytes": 100,
                      "nativeExecuted": False, "supplierAuthority": False}
            if complete:
                negative = {key: result[key] for key in ("centralMembers", "inspectedMembers", "files", "completeMemberHashes",
                            "expandedInspectedBytes", "enumerationSha256")}
                negative.update(kind="complete-recognized-format-negative", nativeMembers=[], nestedArchives=[],
                                nativeExecution=False, supplierAuthority=False)
                result.update(directoryMembers=1, foreignNativeMembers=[], negativeEvidence=negative)
            return result
        fresh = fresh_inner()
        self.assertEqual(M._fresh_inner(fresh, complete=True), (1, 100))
        # The new report's counts cover FILES (1), not directories+files (2).
        self.assertEqual(M._fresh_inner(fresh_inner(complete=False), complete=False), (1, 100))
        for edit in ({"inspectedMembers": 1}, {"completeMemberHashes": False}, {"directoryMembers": 0},
                     {"files": True}, {"nativeExecuted": 0}, {"zipViewOffset": 4}, {"negativeEvidence": None},
                     {"unknownMembers": [{"reason": "executable-opaque"}]}, {"mode": 0o177777},
                     {"issuedReadBytes": 99}, {"extra": 1}):
            with self.subTest(edit=edit), self.assertRaises(M.Refused):
                M._fresh_inner({**fresh, **edit}, complete=True)
        wrong = copy.deepcopy(fresh)
        wrong["formatCounts"]["opaque"] = 2
        with self.assertRaises(M.Refused):
            M._fresh_inner(wrong, complete=True)
        wrong = copy.deepcopy(fresh)
        wrong["negativeEvidence"]["enumerationSha256"] = "b" * 64
        with self.assertRaises(M.Refused):
            M._fresh_inner(wrong, complete=True)
        for complete in (True, False):
            with self.subTest(schema=complete), self.assertRaises(M.Refused):
                M._fresh_inner(fresh_inner(complete=not complete), complete=complete)
        containing = member("unit.jar", label="gradle", hint="zip", size=100)
        self.assertEqual(M._fresh_inner(fresh, containing, complete=True), (1, 100))
        with self.assertRaises(M.Refused):
            M._fresh_inner(fresh, member("other.jar", label="gradle", hint="zip", size=100), complete=True)
        parent = fresh_inner("parent.jar")
        parent.update(centralMembers=3, inspectedMembers=3, files=2, expandedInspectedBytes=101,
                      nestedArchives=[fresh_inner("child.jar")], negativeEvidence=None)
        parent["formatCounts"]["zip"] = 1
        self.assertEqual(M._fresh_inner(parent, complete=True), (102, 200))
        for mutation in ("duplicate", "mode", "format-count", "own-bytes", "depth"):
            wrong = copy.deepcopy(parent)
            if mutation == "duplicate":
                wrong["nestedArchives"].append(copy.deepcopy(wrong["nestedArchives"][0]))
                wrong["formatCounts"]["zip"] = 2
                wrong.update(centralMembers=4, inspectedMembers=4, files=3, expandedInspectedBytes=201)
            elif mutation == "mode":
                wrong["nestedArchives"][0]["mode"] = 0o102644
            elif mutation == "format-count":
                wrong["formatCounts"]["zip"], wrong["formatCounts"]["jmod"] = 0, 1
            elif mutation == "own-bytes":
                wrong["expandedInspectedBytes"] = 1
            else:
                deep = copy.deepcopy(parent)
                deeper = copy.deepcopy(parent)
                deeper["nestedArchives"] = [deep]
                wrong["nestedArchives"] = [deeper]
            with self.subTest(mutation=mutation), self.assertRaises(M.Refused):
                M._fresh_inner(wrong, complete=True)
        # Old ARM JVM validation still includes its original central-member
        # census and schema. No fresh report is forged into that old format.
        self.assertIs(M.jvm(good, row), good)
        with self.assertRaises(M.Refused):
            M.jvm(fresh, row)

        # An admitted inert special stays named/raw and prevents a fabricated negative.
        origin, manifest_jar, _, _ = fresh_sdk_manifest()
        containing = origin.by_name[manifest_jar["name"]]
        unchanged = copy.deepcopy(manifest_jar)
        self.assertEqual(M._fresh_inner(manifest_jar, containing, complete=True, container=origin), (338616, 375769))
        self.assertEqual(M._fresh_specials(manifest_jar, manifest_jar["formatCounts"], complete=True,
                                          container=origin, containing=containing), {"META-INF/MANIFEST.MF"})
        self.assertEqual(manifest_jar, unchanged)
        self.assertIsNone(manifest_jar["negativeEvidence"])
        self.assertEqual(manifest_jar["unknownMembers"][0]["mode"], 0o100700)
        for edit in ({"name": "manifest.MF"}, {"name": "meta-inf/MANIFEST.MF"}, {"mode": 0o100644},
                     {"mode": True}, {"bytes": True}, {"bytes": 44}, {"sha256": HASH},
                     {"format": "shell"}, {"format": "macho"}, {"reason": "unsupported-native"}, {"extra": 1}):
            wrong = copy.deepcopy(manifest_jar)
            wrong["unknownMembers"][0].update(edit)
            with self.subTest(inert_member=edit), self.assertRaises(M.Refused):
                M._fresh_inner(wrong, containing, complete=True, container=origin)
        for field, value in (("enumerationSha256", HASH), ("expandedInspectedBytes", 338615),
                             ("centralMembers", 88), ("inspectedMembers", 86), ("directoryMembers", True)):
            wrong = {**manifest_jar, field: value}
            with self.subTest(inert_census=field), self.assertRaises(M.Refused):
                M._fresh_inner(wrong, containing, complete=True, container=origin)
        for extra in (copy.deepcopy(manifest_jar["unknownMembers"][0]),
                      {**manifest_jar["unknownMembers"][0], "name": "other.txt"}):
            wrong = copy.deepcopy(manifest_jar)
            wrong["unknownMembers"].append(extra)
            with self.subTest(extra_unknown=extra["name"]), self.assertRaises(M.Refused):
                M._fresh_inner(wrong, containing, complete=True, container=origin)
        fake_negative = {key: manifest_jar[key] for key in ("centralMembers", "inspectedMembers", "files",
                         "completeMemberHashes", "expandedInspectedBytes", "enumerationSha256")}
        fake_negative.update(kind="complete-recognized-format-negative", nativeMembers=[], nestedArchives=[],
                             nativeExecution=False, supplierAuthority=False)
        with self.assertRaises(M.Refused):
            M._fresh_inner({**manifest_jar, "negativeEvidence": fake_negative}, containing, complete=True, container=origin)
        with self.assertRaises(M.Refused):
            M._fresh_inner(manifest_jar, containing, complete=True)
        with self.assertRaises(M.Refused):
            M._fresh_inner(manifest_jar, containing, complete=True, container=origin, depth=1)
        nested_parent = fresh_inner("parent.jar")
        nested_parent.update(centralMembers=3, inspectedMembers=3, files=2, expandedInspectedBytes=155118,
                             nestedArchives=[copy.deepcopy(manifest_jar)], negativeEvidence=None)
        nested_parent["formatCounts"]["zip"] = 1
        with self.assertRaises(M.Refused):
            M._fresh_inner(nested_parent, complete=True, container=origin)
        legacy = copy.deepcopy(manifest_jar)
        for key in ("directoryMembers", "foreignNativeMembers", "negativeEvidence"):
            del legacy[key]
        with self.assertRaises(M.Refused):
            M._fresh_inner(legacy, containing, complete=False, container=origin)

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

        # Fresh inputs are a distinct closed mapping. These inert bytes exercise
        # bookkeeping only, NEVER a fabricated complete supplier/reference.
        fresh = {name: b'{"inert":"fresh-unit-record"}\n' for name in M._FRESH_INTEL_ROLES}
        originals = dict(fresh)
        parsed = M._FreshIntelInputs(fresh)
        fresh["jdk-inspection.json"] = b"changed caller mapping"
        with self.assertRaises(M.Refused):
            parsed.finish()
        for name in M._FRESH_INTEL_ROLES:
            self.assertIs(parsed.raw(name), originals[name])
            with self.assertRaises(M.Refused):
                parsed.raw(name)
        self.assertEqual(parsed.finish(), tuple((name, len(originals[name]), hashlib.sha256(originals[name]).hexdigest())
                                               for name in M._FRESH_INTEL_ROLES))
        with self.assertRaises(M.Refused):
            parsed.finish()
        for changed in ({k: v for k, v in originals.items() if k != "jdk-release.bytes"},
                        {**originals, "elsewhere/report.json": b"x"},
                        {**originals, "jdk-release.bytes": bytearray(b"x")},
                        {**originals, "jdk-release.bytes": b""}):
            with self.subTest(keys=list(changed)), self.assertRaises(M.Refused):
                M._FreshIntelInputs(changed)
        with mock.patch.object(M, "INPUT_LIMIT", 1), self.assertRaises(M.Refused):
            M._FreshIntelInputs(originals)
        with mock.patch.object(M, "DOCUMENT_LIMIT", 1), self.assertRaises(M.Refused):
            M._FreshIntelInputs(originals)
        duplicate = M._FreshIntelInputs({**originals, "jdk-inspection.json": b'{"same":1,"same":1}'})
        with self.assertRaises(M.Refused):
            duplicate.document("jdk-inspection.json")
        with self.assertRaises(M.Refused):
            M._FreshIntelInputs(originals).document("jdk-release.bytes")
        # A plausible report field cannot substitute for the actual selected
        # release/cfg originals, or for the exact whole correspondence bytes.
        for changed in ({}, originals, {**originals, "gradle-inspection.json": b'{"completeInnerCoverage":false}'}):
            with self.subTest(keys=list(changed)), self.assertRaises(M.Refused):
                M._fresh_intel_data(changed)
        with self.assertRaises(M.Refused):
            M._fresh_jdk(b"not the pinned correspondence", {})
        selected = M._FRESH_INTEL_SELECTED[0]
        selected_member = M.Member(selected[1], "file", 0o100644, selected[2], selected[3], None, *(None,) * 7, None)
        with self.assertRaises(M.Refused):
            M._fresh_selected_bytes(M._FreshIntelInputs(originals), SimpleNamespace(by_name={selected[1]: selected_member}))
        with self.assertRaises(M.Refused):
            M.generate(originals, emitted.append)
        self.assertEqual(emitted, [])
        self.assertFalse(hasattr(M, "generate_intel"))
        self.assertEqual(M.ARCHIVES["jdk"][0], 185851019)  # ARM default untouched.

        # Genuine public selected JDK byte excerpts exercise the ORIGINAL existing
        # admission; other seven inert records cannot become a whole supplier bundle.
        documents = dict(originals, **{"jdk-release.bytes": _G2_JDK_RELEASE, "jdk-jvm-cfg.bytes": _G2_JDK_CFG})
        selected_rows = {}
        for role, name, size, digest in M._FRESH_INTEL_SELECTED:
            self.assertEqual((len(documents[role]), hashlib.sha256(documents[role]).hexdigest()), (size, digest))
            selected_rows[name] = M.Member(name, "file", 0o100644, size, digest, None, *(None,) * 7, None)
        selected_outer = M._FreshOuter("jdk", list(selected_rows.values()), selected_rows)
        parsed = M._FreshIntelInputs(documents)
        selected_result = M._fresh_selected_bytes(parsed, selected_outer)
        self.assertEqual(tuple(name for name, _ in selected_result), tuple(selected_rows))
        for (role, name, _, _), (actual_name, raw) in zip(M._FRESH_INTEL_SELECTED, selected_result):
            self.assertEqual(actual_name, name)
            self.assertIs(raw, documents[role])
        self.assertEqual(parsed.used, {"jdk-release.bytes", "jdk-jvm-cfg.bytes"})
        with self.assertRaises(M.Refused):
            parsed.finish()
        with self.assertRaises(M.Refused):
            M._fresh_selected_bytes(parsed, selected_outer)
        for edit in ({"jdk-release.bytes": _G2_JDK_CFG, "jdk-jvm-cfg.bytes": _G2_JDK_RELEASE},
                     {"jdk-release.bytes": _G2_JDK_RELEASE[:-1]}, {"jdk-release.bytes": b"X" + _G2_JDK_RELEASE[1:]},
                     {"jdk-jvm-cfg.bytes": _G2_JDK_CFG + b"\n"}, {"jdk-jvm-cfg.bytes": bytearray(_G2_JDK_CFG)}):
            with self.subTest(selected_bytes=list(edit)), self.assertRaises(M.Refused):
                M._fresh_selected_bytes(M._FreshIntelInputs({**documents, **edit}), selected_outer)
        for role, name, _, _ in M._FRESH_INTEL_SELECTED:
            for edit in ({"kind": "directory"}, {"mode": 0o100444}, {"sha256": HASH}, {"size": 1}):
                row = selected_rows[name]
                values = {key: getattr(row, key) for key in M.Member.__dataclass_fields__}
                values.update(edit)
                changed_rows = {**selected_rows, name: M.Member(**values)}
                wrong_outer = M._FreshOuter("jdk", list(changed_rows.values()), changed_rows)
                with self.subTest(selected_role=role, row=edit), self.assertRaises(M.Refused):
                    M._fresh_selected_bytes(M._FreshIntelInputs(documents), wrong_outer)
            with self.subTest(absent=role), self.assertRaises(M.Refused):
                M._fresh_selected_bytes(M._FreshIntelInputs(documents),
                                       M._FreshOuter("jdk", [], {k: v for k, v in selected_rows.items() if k != name}))
        with self.assertRaises(M.Refused):
            M._fresh_intel_data(documents)
        with self.assertRaises(M.Refused):
            M.generate(documents, emitted.append)
        self.assertEqual(emitted, [])
        self.assertFalse(hasattr(M, "generate_intel"))

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
        # Preserve distinct wrapper-selection and acquisition-provenance roles.
        self.assertIn(
            b'gradle_distribution_url: "https://services.gradle.org/distributions/gradle-8.14.5-bin.zip", '
            b'gradle_distribution_sha256: "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854"', raw)
        self.assertIn(
            b'OfficialArchive { component: Component::Gradle, official_source: '
            b'"https://github.com/gradle/gradle-distributions/releases/download/v8.14.5/gradle-8.14.5-bin.zip"', raw)
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
