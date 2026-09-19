"""Inert, task-owned evidence fixtures; no release, artifact or native proof.

The positive fixtures exercise the real pure provenance validators. Fixture
resealing is independently constructed JSON, not a production publisher call.
Filesystem changes below affect only disposable test-owned ordinary objects.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import provenance
from mobile_release.api import ApiError, execute
from mobile_release.api import _candidate_evidence as evidence
from mobile_release.api import _snapshot as snapshot
from mobile_release.config import ReleaseConfig
from mobile_release.errors import ValidationError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NAMES = ("candidate-manifest.json", "candidate-receipt.json", "operation/candidate-operation-intent.json")
KINDS = ("manifest", "receipt", "intent")
ASSURANCE = {
    "level": "local-document-consistency", "documentsOnly": True,
    "artifactBytesVerified": False, "workflowAuthenticated": False,
    "storeStateObserved": False, "comparedWithSourceProject": False,
    "releaseReady": False, "recoveryAuthorized": False,
}


def fixture_seal(document: dict) -> dict:
    document.pop("integrity", None)
    raw = json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    document["integrity"] = {"algorithm": "sha256", "sha256": hashlib.sha256(raw).hexdigest()}
    return document


def fixture_rebind(documents: list[dict]) -> list[dict]:
    manifest, receipt, intent = documents
    fixture_seal(intent)
    manifest["operationIntentSha256"] = intent["integrity"]["sha256"]
    fixture_seal(manifest)
    receipt["operationIntentSha256"] = intent["integrity"]["sha256"]
    receipt["candidateManifestSha256"] = manifest["integrity"]["sha256"]
    fixture_seal(receipt)
    return documents


def fixture_documents(platform: str = "android") -> list[dict]:
    documents = [json.loads((FIXTURES / name).read_text(encoding="utf-8"))
                 for name in ("candidate-valid.json", "receipt-candidate-valid.json", "intent-candidate-valid.json")]
    if platform == "android":
        return documents
    manifest, receipt, intent = documents
    artifacts = [
        {"logicalName": name, "platform": "ios", "kind": kind,
         "fileName": filename, "size": size, "sha256": digest * 64, "architectures": ["arm64"]}
        for name, kind, filename, size, digest in (
            ("ios-ipa", "ipa", "reader.ipa", 12345678, "6"),
            ("ios-archive", "xcarchive", "reader.xcarchive.zip", 23456789, "8"),
            ("ios-dsyms", "dsym", "reader.dSYM.zip", 345678, "9"),
        )
    ] + copy.deepcopy(manifest["artifacts"][1:])
    signing = [{"platform": "ios", "kind": "apple-distribution", "certificateSha256": "a" * 64,
                "teamId": "ABCDE12345", "profileUuid": "11111111-2222-3333-4444-555555555555",
                "profileExpiresAt": "2027-01-01T00:00:00Z"}]
    manifest["platforms"] = {"ios": {"applicationId": "com.example.reader", "storeAppId": "1234567890"}}
    manifest["artifacts"], manifest["signing"] = artifacts, signing
    manifest["storeReceipts"][0].update(provider="app-store-connect", channel="testflight-internal",
                                         state="processed", storeBuildId="build-resource-id", autoNotifyEnabled=False)
    intent.update(platform="ios", confirmation="candidate:ios:1.2.3:42",
                  application={"id": "com.example.reader", "storeAppId": "1234567890"},
                  destination={"channel": "testflight-internal"},
                  artifacts=copy.deepcopy(artifacts), signing=copy.deepcopy(signing))
    intent["storePrecondition"] = {
        "schemaVersion": 1, "documentType": "store-precondition", "operation": "ios_testflight_internal",
        "platform": "ios", "appIdentity": "com.example.reader", "marketingVersion": "1.2.3",
        "buildNumber": 42, "observedAt": "2026-01-01T00:00:00Z",
        "snapshot": {"canonicalization": "mrk-apple-operation-v1", "appStoreAppId": "1234567890",
                     "serverObservedAt": "2026-01-01T00:00:00Z", "build": None},
    }
    receipt.update(platform="ios", provider="app-store-connect", storeBuildId="build-resource-id",
                   destination={"channel": "testflight-internal"},
                   readback={"state": "processed", "observedAt": "2026-01-01T00:00:00Z", "autoNotifyEnabled": False})
    receipt.pop("storeState")
    return fixture_rebind(documents)


def put(root: Path, name: str, value: object) -> None:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        target.write_bytes(value)
    else:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        target.write_text(text, encoding="utf-8")


def populate(root: Path, documents: list[dict]) -> None:
    for name, document in zip(NAMES, documents):
        put(root, name, document)


def parameters(root: Path) -> dict:
    observed = root.stat()
    return {"root": str(root), "expectedRoot": {"device": str(observed.st_dev), "inode": str(observed.st_ino),
                                               "mode": observed.st_mode, "uid": observed.st_uid, "gid": observed.st_gid}}


def expected_result(documents: list[dict]) -> dict:
    """Exact fixture contract; no production projection helper is used."""
    manifest = documents[0]
    platform = next(iter(manifest["platforms"]))
    return {
        "schemaVersion": 1, "outcome": "consistent",
        "documents": [{"kind": kind, "state": "valid"} for kind in KINDS],
        "summary": {
            "platform": platform, "applicationId": manifest["platforms"][platform]["applicationId"],
            "version": dict(manifest["version"]),
            "source": {key: manifest["source"][key] for key in ("commit", "tree")},
            "artifacts": [{"logicalName": artifact["logicalName"], "declaredBytes": str(artifact["size"]),
                           "sha256": artifact["sha256"]} for artifact in manifest["artifacts"]],
            "recordedRuns": {role: {"runId": manifest[role]["runId"], "attempt": str(manifest[role]["attempt"])}
                             for role in ("authorizedBy", "executedBy", "producedBy")},
            "documentPayloadSha256": {kind: document["integrity"]["sha256"] for kind, document in zip(KINDS, documents)},
        },
        "assurance": dict(ASSURANCE),
    }


class CandidateEvidenceAdmissionTests(unittest.TestCase):
    def test_exact_private_identity_params_precede_filesystem_admission(self):
        valid = {"root": "/selected/evidence", "expectedRoot": {"device": "1", "inode": "2", "mode": 0o40700, "uid": 0, "gid": 0}}
        bad = [None, [], {}, {**valid, "path": "PRIVATE"}, {"root": valid["root"]},
               {**valid, "root": 1}, {**valid, "expectedRoot": []}]
        for key, values in {"device": [1, True, "01", "-1", "１", "9" * 21, str(1 << 64)],
                            "inode": [False, "", "1.0", "1e2", "1\n"],
                            "mode": [True, -1, 1 << 32], "uid": [False, -1], "gid": [0.0, "0"]}.items():
            for value in values:
                bad.append({**valid, "expectedRoot": {**valid["expectedRoot"], key: value}})
        bad.append({**valid, "expectedRoot": {**valid["expectedRoot"], "PRIVATE": "do not reflect"}})
        with patch.object(os, "open", side_effect=AssertionError("filesystem admission")):
            for params in bad:
                with self.subTest(params=params), self.assertRaises(ApiError) as refused:
                    execute("artifacts.candidate.observe", params)
                self.assertEqual(refused.exception.code, "invalid_params")
                self.assertEqual(str(refused.exception), evidence._ERRORS["invalid_params"])

    def test_unsupported_profiles_are_closed_without_io(self):
        params = {"root": "/selected/evidence", "expectedRoot": {"device": "1", "inode": "2", "mode": 0o40700, "uid": 0, "gid": 0}}
        for platform in ("darwin", "win32", "freebsd"):
            with self.subTest(platform=platform), patch.object(sys, "platform", platform), \
                 patch.object(os, "open", side_effect=AssertionError("filesystem admission")):
                self.assertFalse(evidence.candidate_evidence_observation_available())
                with self.assertRaises(ApiError) as refused:
                    execute("artifacts.candidate.observe", params)
                self.assertEqual(refused.exception.code, "artifacts_unavailable")


@unittest.skipUnless(evidence.candidate_evidence_observation_available(), "Linux descriptor reader required")
class CandidateEvidenceObservationTests(unittest.TestCase):
    def assert_error(self, root: Path, code: str, *, params: dict | None = None) -> None:
        with self.assertRaises(ApiError) as refused:
            execute("artifacts.candidate.observe", parameters(root) if params is None else params)
        self.assertEqual(refused.exception.code, code)
        self.assertEqual(refused.exception.message, evidence._ERRORS[code])

    def test_android_and_ios_use_real_validators_and_exact_redacted_contract(self):
        for platform in ("android", "ios"):
            documents = fixture_documents(platform)
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                populate(root, documents)
                with patch.object(evidence, "validate_evidence_document", wraps=provenance.validate_evidence_document) as document_check, \
                     patch.object(evidence, "validate_operation_intent", wraps=provenance.validate_operation_intent) as intent_check, \
                     patch.object(evidence, "verify_sealed", wraps=provenance.verify_sealed) as digest_check, \
                     patch.object(evidence, "validate_receipt_chain", wraps=provenance.validate_receipt_chain) as chain_check:
                    result = execute("artifacts.candidate.observe", parameters(root))
                self.assertEqual(result, expected_result(documents))
                self.assertEqual((document_check.call_count, intent_check.call_count, digest_check.call_count, chain_check.call_count), (2, 1, 2, 1))
                self.assertEqual(set(chain_check.call_args.kwargs), {"candidate_manifest", "candidate_receipt", "candidate_intent", "platform", "config"})
                self.assertIsNone(chain_check.call_args.kwargs["config"])
                self.assertEqual(chain_check.call_args.kwargs["platform"], platform)
                encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()
                self.assertLessEqual(len(encoded), 64 * 1024)
                for hidden in (str(root), "storePrecondition", "privateStateCommitments", "signing", "configuration",
                               "confirmation", "fileName", "architectures", "storeReceipts", "sourceRef", ".github/workflows", "example/mobile-app"):
                    self.assertNotIn(hidden, encoded.decode())
                self.assertNotEqual(hashlib.sha256((root / NAMES[0]).read_bytes()).hexdigest(), result["summary"]["documentPayloadSha256"]["manifest"])

    def test_declared_decimal_precision_and_distinct_manifest_run_roles(self):
        documents = fixture_documents()
        for document in documents[:2]:
            for role, run, attempt in (("authorizedBy", "9" * 64, 10 ** 63),
                                       ("executedBy", "9" * 64, 10 ** 63 + 1),
                                       ("producedBy", "8" * 64, 10 ** 63 + 2)):
                document[role].update(runId=run, attempt=attempt)
        documents[2]["authorizedBy"] = copy.deepcopy(documents[0]["authorizedBy"])
        documents[0]["artifacts"][0]["size"] = 10 ** 63 + 123
        documents[2]["artifacts"] = copy.deepcopy(documents[0]["artifacts"])
        fixture_rebind(documents)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, documents)
            result = execute("artifacts.candidate.observe", parameters(root))
            self.assertEqual(result, expected_result(documents))
            summary = result["summary"]
            self.assertEqual(summary["artifacts"][0]["declaredBytes"], str(10 ** 63 + 123))
            self.assertEqual(len({tuple(value.items()) for value in summary["recordedRuns"].values()}), 3)
            self.assertEqual(summary["recordedRuns"]["producedBy"]["attempt"], str(10 ** 63 + 2))

    def test_forged_self_consistency_never_claims_provenance_or_artifact_authority(self):
        documents = fixture_documents()
        for document in documents[:2]:
            document["source"]["tree"] = "B" * 40
        for key in ("candidateSource", "operationSource"):
            documents[2][key]["tree"] = "B" * 40
        fixture_rebind(documents)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, documents)
            result = execute("artifacts.candidate.observe", parameters(root))
            self.assertEqual(result["outcome"], "consistent")
            self.assertEqual(result["summary"]["source"]["tree"], "B" * 40)
            self.assertEqual(result["assurance"], ASSURANCE)
            self.assertFalse(any(result["assurance"][key] for key in ASSURANCE if key not in {"level", "documentsOnly"}))

    def test_artifact_projection_has_stable_role_order_not_document_order(self):
        documents = fixture_documents()
        artifacts = documents[0]["artifacts"]
        artifacts.extend([
            {"logicalName": "android-mapping", "platform": "android", "kind": "r8-mapping",
             "fileName": "mapping.txt", "size": 7, "sha256": "8" * 64, "architectures": []},
            {"logicalName": "android-native-symbols", "platform": "android", "kind": "native-symbols",
             "fileName": "symbols.zip", "size": 8, "sha256": "9" * 64, "architectures": ["arm64-v8a"]},
        ])
        artifacts.reverse()
        documents[2]["artifacts"] = copy.deepcopy(artifacts)
        fixture_rebind(documents)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, documents)
            result = execute("artifacts.candidate.observe", parameters(root))
            self.assertEqual(result["outcome"], "consistent")
            self.assertEqual([row["logicalName"] for row in result["summary"]["artifacts"]],
                             ["android-aab", "android-mapping", "android-native-symbols", "store-metadata", "validation-report"])

    def test_only_three_fixed_documents_are_opened_no_publishers_or_payloads(self):
        documents = fixture_documents()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, documents)
            for name in ("reader-1.2.3-42.aab", "release/mobile-release.json", "release/version.properties", "private.json"):
                put(root, name, "PRIVATE_SENTINEL")
            params = parameters(root)
            real_open = os.open
            opened_leaves = []

            def readonly_open(path, flags, *args, **kwargs):
                self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
                if not flags & os.O_DIRECTORY:
                    self.assertIn(path, [Path(name).name for name in NAMES])
                    opened_leaves.append(path)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(evidence, "candidate_evidence_observation_available", return_value=True), \
                 patch.object(os, "open", side_effect=readonly_open), \
                 patch.object(Path, "open", side_effect=AssertionError("document-directed path open")), \
                 patch.object(provenance, "sha256_file", side_effect=AssertionError("payload hashing")), \
                 patch.object(provenance, "seal", side_effect=AssertionError("publisher")), \
                 patch.object(provenance, "timestamp", side_effect=AssertionError("ambient time")), \
                 patch.object(ReleaseConfig, "release_version", side_effect=AssertionError("configuration source")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
                 patch.object(os, "system", side_effect=AssertionError("shell")), \
                 patch.object(socket, "socket", side_effect=AssertionError("network")):
                self.assertEqual(execute("artifacts.candidate.observe", params), expected_result(documents))
            self.assertEqual(opened_leaves, [Path(name).name for name in NAMES])

    def test_missing_is_incomplete_and_present_invalid_dominates_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = execute("artifacts.candidate.observe", parameters(root))
            self.assertEqual(result, {"schemaVersion": 1, "outcome": "incomplete", "summary": None,
                                      "documents": [{"kind": kind, "state": "missing"} for kind in KINDS], "assurance": ASSURANCE})
            put(root, NAMES[0], "{}")
            result = execute("artifacts.candidate.observe", parameters(root))
            self.assertEqual((result["outcome"], result["summary"]), ("invalid", None))
            self.assertEqual([row["state"] for row in result["documents"]], ["invalid", "missing", "missing"])
            self.assertEqual(result["assurance"], ASSURANCE)
        for index in range(3):
            with self.subTest(missing=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                documents = fixture_documents()
                for offset, (name, document) in enumerate(zip(NAMES, documents)):
                    if offset != index:
                        put(root, name, document)
                result = execute("artifacts.candidate.observe", parameters(root))
                self.assertEqual((result["outcome"], result["summary"]), ("incomplete", None))
                self.assertEqual([row["state"] for row in result["documents"]],
                                 ["missing" if offset == index else "valid" for offset in range(3)])

    def test_malformed_json_duplicates_floats_nonfinite_and_schema_stage_self_digest(self):
        values = ["{", "[]", '{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1.0}', '{"x":1e999}', '{"x":"\\ud800"}']
        baseline = fixture_documents()
        for field, value in (("schemaVersion", True), ("schemaVersion", 1), ("documentType", "store-receipt"),
                             ("version", {"marketing": "1.2.3", "build": True})):
            document = copy.deepcopy(baseline[0])
            document[field] = value
            values.append(fixture_seal(document))
        tampered = copy.deepcopy(baseline[0])
        tampered["version"]["build"] = 43
        values.append(tampered)
        for value in values:
            with self.subTest(value=str(value)[:80]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                put(root, NAMES[0], value)
                result = execute("artifacts.candidate.observe", parameters(root))
                self.assertEqual((result["outcome"], result["summary"]), ("invalid", None))
        for index in (1, 2):
            with self.subTest(stage=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                document = copy.deepcopy(baseline[index])
                document["stage"] = "external-testing"
                put(root, NAMES[index], fixture_seal(document))
                result = execute("artifacts.candidate.observe", parameters(root))
                self.assertEqual(result["documents"][index]["state"], "invalid")
                self.assertEqual(result["outcome"], "invalid")

    def test_actual_candidate_intent_receipt_cross_bindings_not_only_self_digests(self):
        for index, field in ((0, "operationIntentSha256"), (1, "candidateManifestSha256"), (1, "operationIntentSha256")):
            with self.subTest(document=index, field=field), tempfile.TemporaryDirectory() as temporary:
                documents = fixture_documents()
                documents[index][field] = "0" * 64
                fixture_seal(documents[index])
                root = Path(temporary)
                populate(root, documents)
                result = execute("artifacts.candidate.observe", parameters(root))
                self.assertEqual(result, {"schemaVersion": 1, "outcome": "inconsistent", "summary": None,
                                          "documents": [{"kind": kind, "state": "valid"} for kind in KINDS], "assurance": ASSURANCE})

    def test_private_or_legacy_validator_messages_are_never_forwarded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, fixture_documents())
            with patch.object(evidence, "validate_evidence_document", side_effect=ValidationError("authenticated operation intent PRIVATE_SENTINEL")):
                result = execute("artifacts.candidate.observe", parameters(root))
            self.assertEqual(result["outcome"], "invalid")
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))
            self.assertNotIn("authenticated", json.dumps(result))
            with patch.object(evidence, "validate_evidence_document", side_effect=RuntimeError("PRIVATE_SENTINEL")):
                self.assert_error(root, "artifacts_unavailable")

    def test_byte_integer_node_depth_and_projection_limits_are_not_policy_invalid(self):
        values = [b" " * (2 * 1024 * 1024 + 1), "9" * 65, "-" + "9" * 65,
                  "[" * 33 + "0" + "]" * 33, json.dumps([0] * 20_000)]
        for value in values:
            with self.subTest(size=len(value)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                put(root, NAMES[0], value)
                self.assert_error(root, "artifacts_limit")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, fixture_documents())
            with patch.object(evidence, "MAX_RESULT_BYTES", 1):
                self.assert_error(root, "artifacts_limit")
            with patch.object(evidence, "MAX_RESULT_NODES", 1):
                self.assert_error(root, "artifacts_limit")
            with patch.object(evidence, "MAX_TOTAL_NODES", 1):
                self.assert_error(root, "artifacts_limit")
            with patch.object(snapshot, "MAX_ENTRIES", 0):
                self.assert_error(root, "artifacts_limit")

    def test_exact_two_mib_each_and_six_mib_total_are_admitted_without_extra_files(self):
        documents = fixture_documents()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, document in zip(NAMES, documents):
                text = json.dumps(document, separators=(",", ":")).encode()
                put(root, name, text + b" " * (2 * 1024 * 1024 - len(text)))
            self.assertEqual(execute("artifacts.candidate.observe", parameters(root)), expected_result(documents))

    def test_unrepresentable_valid_identifiers_and_large_run_text_are_limits(self):
        for value in ("com.example.\u202ereader", "com.example.\u0085reader"):
            documents = fixture_documents()
            documents[0]["platforms"]["android"]["applicationId"] = value
            documents[0]["storeReceipts"][0]["applicationId"] = value
            documents[1]["applicationId"] = value
            documents[2]["application"]["id"] = value
            documents[2]["storePrecondition"]["appIdentity"] = value
            fixture_rebind(documents)
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                populate(root, documents)
                self.assert_error(root, "artifacts_limit")
        documents = fixture_documents()
        for document in documents[:2]:
            for role in ("authorizedBy", "executedBy", "producedBy"):
                document[role]["runId"] = "9" * 65
        documents[2]["authorizedBy"]["runId"] = "9" * 65
        fixture_rebind(documents)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, documents)
            self.assert_error(root, "artifacts_limit")

    def test_utf8_and_unsafe_root_refusals_are_constant(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            put(root, NAMES[0], b"\xffPRIVATE_SENTINEL")
            self.assert_error(root, "artifacts_encoding")
            for value in (str(root) + "/../alias", "/" + "x" * 4096, "/" + "/".join(["x"] * 129)):
                params = {**parameters(root), "root": value}
                self.assert_error(root, "artifacts_unsafe", params=params)

    def test_read_io_refusal_does_not_reflect_path_or_native_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, fixture_documents())
            params = parameters(root)
            original_open = os.open

            def refuse_leaf(path, flags, *args, **kwargs):
                if not flags & os.O_DIRECTORY:
                    raise PermissionError("PRIVATE_SENTINEL " + str(root))
                return original_open(path, flags, *args, **kwargs)

            with patch.object(evidence, "candidate_evidence_observation_available", return_value=True), \
                 patch.object(os, "open", side_effect=refuse_leaf):
                self.assert_error(root, "artifacts_unreadable", params=params)

    def test_original_root_identity_is_checked_before_any_document_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, fixture_documents())
            for key in ("device", "inode", "mode", "uid", "gid"):
                params = parameters(root)
                old = params["expectedRoot"][key]
                params["expectedRoot"][key] = str(int(old) + 1) if isinstance(old, str) else old + 1
                with self.subTest(key=key), patch.object(snapshot._NamedTextReads, "read", side_effect=AssertionError("document read")):
                    self.assert_error(root, "artifacts_changed", params=params)

    def test_root_parent_leaf_links_and_portable_aliases_are_not_followed(self):
        for case in ("root", "parent", "symlink", "hardlink", "alias"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / "evidence"
                root.mkdir()
                populate(root, fixture_documents())
                if case == "root":
                    selected = base / "alias"
                    selected.symlink_to(root, target_is_directory=True)
                    self.assert_error(selected, "artifacts_unsafe")
                    continue
                if case == "parent":
                    (root / "operation").rename(base / "original-operation")
                    (root / "operation").symlink_to(base / "original-operation", target_is_directory=True)
                elif case == "symlink":
                    (root / NAMES[0]).rename(base / "original-manifest")
                    (root / NAMES[0]).symlink_to(base / "original-manifest")
                elif case == "hardlink":
                    os.link(root / NAMES[0], base / "linked-manifest")
                else:
                    put(root, "Candidate-Manifest.json", "{}")
                self.assert_error(root, "artifacts_unsafe")

    def test_special_foreign_owner_and_foreign_device_refuse_before_leaf_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, fixture_documents())
            params = parameters(root)
            original_stat, original_open = os.stat, os.open
            for changed in ("type", "owner", "device"):
                def forged_stat(path, *args, **kwargs):
                    value = original_stat(path, *args, **kwargs)
                    if path == NAMES[0]:
                        return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600 if changed == "type" else value.st_mode,
                                               st_nlink=value.st_nlink, st_uid=value.st_uid + int(changed == "owner"),
                                               st_dev=value.st_dev + int(changed == "device"))
                    return value

                def no_leaf(path, flags, *args, **kwargs):
                    self.assertTrue(flags & os.O_DIRECTORY)
                    return original_open(path, flags, *args, **kwargs)

                with self.subTest(changed=changed), patch.object(evidence, "candidate_evidence_observation_available", return_value=True), \
                     patch.object(os, "stat", side_effect=forged_stat), patch.object(os, "open", side_effect=no_leaf):
                    self.assert_error(root, "artifacts_unsafe", params=params)

    def test_changed_leaf_absence_and_ancestor_veto_even_nonconsistent_results(self):
        original_check = snapshot._NamedTextReads.check
        for case in ("leaf", "absence", "ancestor"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / "evidence"
                root.mkdir()
                if case != "absence":
                    populate(root, fixture_documents())
                params = parameters(root)

                def changed(reader):
                    if case == "leaf":
                        with (root / NAMES[0]).open("ab") as stream:
                            stream.write(b" ")
                    elif case == "absence":
                        put(root, NAMES[0], "{}")
                    else:
                        root.rename(base / "original-evidence")
                        root.mkdir()
                    original_check(reader)

                with patch.object(snapshot._NamedTextReads, "check", changed):
                    self.assert_error(root, "artifacts_changed", params=params)

    def test_one_cooperative_deadline_includes_pure_validation_and_final_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, fixture_documents())
            clock = [0.0]
            original = evidence.validate_evidence_document

            def finish_after_deadline(document):
                original(document)
                clock[0] = 6.0

            with patch.object(snapshot.time, "monotonic", side_effect=lambda: clock[0]), \
                 patch.object(evidence, "validate_evidence_document", side_effect=finish_after_deadline), \
                 patch.object(snapshot, "_Inventory", wraps=snapshot._Inventory) as inventory:
                self.assert_error(root, "artifacts_deadline")
            self.assertEqual(inventory.call_count, 1)

    def test_descriptor_close_uncertainty_attempts_all_original_closes_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, fixture_documents())
            params = parameters(root)
            original_open, original_close = os.open, os.close
            active, closed = set(), []

            def opened(*args, **kwargs):
                descriptor = original_open(*args, **kwargs)
                active.add(descriptor)
                self.assertLessEqual(len(active), 132)
                return descriptor

            def ambiguous_close(descriptor):
                self.assertIn(descriptor, active)
                active.remove(descriptor)
                original_close(descriptor)
                closed.append(descriptor)
                if len(closed) == 1:
                    raise OSError("PRIVATE_SENTINEL ambiguous close")

            with patch.object(evidence, "candidate_evidence_observation_available", return_value=True), \
                 patch.object(os, "open", side_effect=opened), patch.object(os, "close", side_effect=ambiguous_close):
                self.assert_error(root, "artifacts_cleanup_unknown", params=params)
            self.assertFalse(active)
            self.assertEqual(len(closed), len(set(closed)))
            self.assertGreater(len(closed), 1)

    def test_original_iterator_close_uncertainty_is_not_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            put(root, "unrelated", "not opened")
            params = parameters(root)
            original_scandir = os.scandir
            closes = []

            class AmbiguousIterator:
                def __init__(self, descriptor):
                    self.original = original_scandir(descriptor)

                def __iter__(self):
                    return iter(self.original)

                def close(self):
                    closes.append(self)
                    self.original.close()
                    raise OSError("PRIVATE_SENTINEL iterator close")

            with patch.object(evidence, "candidate_evidence_observation_available", return_value=True), \
                 patch.object(os, "scandir", side_effect=AmbiguousIterator):
                self.assert_error(root, "artifacts_cleanup_unknown", params=params)
            self.assertEqual(len(closes), 1)


if __name__ == "__main__":
    unittest.main()
