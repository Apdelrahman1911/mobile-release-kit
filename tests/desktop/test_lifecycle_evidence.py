"""Local, disposable metadata fixtures; no Store, workflow or recovery authority."""
from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release.api import ApiError, execute
from mobile_release.api import _candidate_evidence as candidate, _lifecycle_evidence as lifecycle, _snapshot
from mobile_release.evidence_layout import evidence_document_paths, evidence_layout
from mobile_release.workflow import WorkflowError, _layout
from unit.evidence_helpers import fixture_chain, ios_precondition, raw_receipt, workflow_environment
from mobile_release.provenance import build_receipt, external_production_blocker, verify_sealed
from test_candidate_evidence import ASSURANCE, fixture_documents, fixture_seal, parameters, put


def bundle(stage: str, docs: dict | None = None) -> dict:
    docs = fixture_chain() if docs is None else docs
    if stage == "candidate":
        return {"candidate-receipt.json": docs["candidate_receipt"], "candidate-manifest.json": docs["candidate"],
                "operation/candidate-operation-intent.json": docs["candidate_intent"]}
    name = "external" if stage == "external-testing" else "production"
    result = {stage + "-receipt.json": docs[name + "_receipt"],
              "operation/" + stage + "-operation-intent.json": docs[name + "_intent"]}
    result.update({"operation/candidate/" + path: document for path, document in bundle("candidate", docs).items()})
    if stage == "production-submit":
        result.update({"operation/external/" + path: document for path, document in bundle("external-testing", docs).items()})
    return result


def populate(root: Path, stage: str, docs: dict | None = None) -> dict:
    values = bundle(stage, docs)
    for path, value in values.items():
        put(root, path, value)
    return values


def observe(root: Path, stage: str) -> dict:
    return execute("release.evidence.observe", {**parameters(root), "stage": stage})


def fixture_variants() -> dict[str, tuple[str, dict]]:
    """Deterministic local documents, not signed artifacts or live service IO."""
    variants = {name: (stage, fixture_chain()) for name, stage in (
        ("androidCandidate", "candidate"), ("androidExternal", "external-testing"), ("androidProduction", "production-submit"))}
    for name, result in (("androidObservedExternal", "already_present"), ("androidReconciledExternal", "reconciled")):
        docs = fixture_chain()
        intent = verify_sealed(docs["external_intent"])
        if result == "already_present":
            snapshot = intent["storePrecondition"]["snapshot"]
            snapshot["destinationState"] = copy.deepcopy(snapshot["destinationTargetState"])
            snapshot["targetPresent"] = True
        docs["external_intent"] = fixture_seal(intent)
        with patch.dict(os.environ, workflow_environment("external-testing")):
            docs["external_receipt"] = build_receipt(stage="external-testing", platform="android", candidate_manifest=docs["candidate"],
                previous_receipt=docs["candidate_receipt"], operation_intent=docs["external_intent"], store_receipt=raw_receipt(docs["external_intent"], result=result))
        variants[name] = ("external-testing", docs)
    manifest, receipt, candidate_intent = fixture_documents("ios")
    docs = {"candidate": manifest, "candidate_receipt": receipt, "candidate_intent": candidate_intent}
    for stage, key in (("external-testing", "external"), ("production-submit", "production")):
        intent = verify_sealed(fixture_chain()[key + "_intent"])
        intent.update(platform="ios", application=copy.deepcopy(candidate_intent["application"]),
                      confirmation=f"{stage}:ios:1.2.3:42", artifacts=copy.deepcopy(manifest["artifacts"]), signing=copy.deepcopy(manifest["signing"]))
        intent["destination"] = {"channel": "testflight-external"} if key == "external" else {"channel": "app-store-review", "automaticRelease": False}
        intent["storePrecondition"] = ios_precondition(None, stage=stage)
        intent["privateStateCommitments"] = copy.deepcopy(intent["storePrecondition"]["snapshot"].get("privateStateCommitments", {}))
        intent["predecessors"].update(candidateManifestSha256=manifest["integrity"]["sha256"], candidateReceiptSha256=receipt["integrity"]["sha256"])
        if key == "production":
            intent["predecessors"]["externalReceiptSha256"] = docs["external_receipt"]["integrity"]["sha256"]
        docs[key + "_intent"] = fixture_seal(intent)
        with patch.dict(os.environ, workflow_environment(stage)):
            docs[key + "_receipt"] = build_receipt(stage=stage, platform="ios", candidate_manifest=manifest,
                previous_receipt=receipt if key == "external" else docs["external_receipt"], operation_intent=docs[key + "_intent"], store_receipt=raw_receipt(docs[key + "_intent"]))
    variants["iosAvailableExternal"] = ("external-testing", copy.deepcopy(docs))
    variants["iosProduction"] = ("production-submit", copy.deepcopy(docs))
    docs["external_receipt"]["readback"]["state"] = "approved"
    fixture_seal(docs["external_receipt"])
    variants["iosPendingExternal"] = ("external-testing", copy.deepcopy(docs))
    for name, outcome in (("iosRecordedReconciliation", "operator-authorized-reconciliation"), ("iosRecordedRetry", "operator-authorized-retry")):
        changed = copy.deepcopy(docs)
        changed["candidate_receipt"]["outcome"] = outcome
        changed["candidate_receipt"]["executedBy"]["runId"] = "9007199254740993"
        changed["candidate_receipt"]["producedBy"].update(runId="9007199254740993", attempt=2)
        fixture_seal(changed["candidate_receipt"])
        variants[name] = ("candidate", changed)
    return variants


class LifecycleLayoutTests(unittest.TestCase):
    def test_exact_existing_layout_and_workflow_error_boundary(self):
        for stage, count in (("candidate", 3), ("external-testing", 5), ("production-submit", 10)):
            self.assertEqual(evidence_document_paths(stage), tuple(bundle(stage)))
            self.assertEqual(len(evidence_document_paths(stage)), count)
            for phase in ("intent", "final"):
                self.assertEqual(_layout(stage, phase), evidence_layout(stage, phase))
                self.assertEqual(_layout(stage, phase, "prefix/"), evidence_layout(stage, phase, "prefix/"))
        for stage, phase in (("unknown", "final"), ("candidate", "unknown"), ("production", "intent")):
            with self.assertRaisesRegex(WorkflowError, "^invalid evidence layout$"):
                _layout(stage, phase)

    def test_closed_params_and_platform_before_io(self):
        valid = {"root": "/inert/not-opened", "expectedRoot": {"device": "1", "inode": "2", "mode": 0o40700, "uid": 0, "gid": 0}, "stage": "candidate"}
        for value in (None, {}, {**valid, "stage": []}, {**valid, "stage": "production"}, {**valid, "path": "private"}):
            with self.subTest(value=value), patch.object(os, "open", side_effect=AssertionError("unexpected IO")):
                with self.assertRaises(ApiError) as refused:
                    execute("release.evidence.observe", value)
                self.assertEqual(refused.exception.code, "invalid_params")
        for host in ("darwin", "win32", "freebsd"):
            with patch.object(sys, "platform", host), patch.object(os, "open", side_effect=AssertionError("unexpected IO")):
                with self.assertRaises(ApiError) as refused:
                    execute("release.evidence.observe", valid)
                self.assertEqual(refused.exception.code, "artifacts_unavailable")
                self.assertFalse(next(row for row in execute("capabilities", {})["methods"] if row["method"] == "release.evidence.observe")["available"])


@unittest.skipUnless(candidate.candidate_evidence_observation_available(), "Linux descriptor reader required")
class LifecycleEvidenceTests(unittest.TestCase):
    def assert_limit(self, root: Path, stage: str):
        with self.assertRaises(ApiError) as refused:
            observe(root, stage)
        self.assertEqual(refused.exception.code, "artifacts_limit")

    def test_three_real_layouts_reuse_policy_and_never_upgrade_authority(self):
        docs = fixture_chain()
        for stage, count in (("candidate", 1), ("external-testing", 2), ("production-submit", 3)):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                values = populate(root, stage)
                with patch.object(lifecycle, "validate_receipt_chain", wraps=lifecycle.validate_receipt_chain) as validate:
                    result = observe(root, stage)
                self.assertEqual(result["outcome"], "consistent")
                self.assertEqual(result["assurance"], ASSURANCE)
                self.assertEqual(result["stage"], stage)
                self.assertEqual(result["documents"], [{"path": path, "state": "valid"} for path in values])
                self.assertEqual([row["stage"] for row in result["history"]], list(("candidate", "external-testing", "production-submit")[:count]))
                self.assertEqual(result["history"][0]["previousReceiptSha256"], None)
                for previous, current in zip(result["history"], result["history"][1:]):
                    self.assertEqual(current["previousReceiptSha256"], previous["receiptSha256"])
                self.assertEqual(result["summary"]["applicationId"], "com.example.reader")
                self.assertEqual(result["summary"]["documentPayloadSha256"]["manifest"], docs["candidate"]["integrity"]["sha256"])
                self.assertEqual(validate.call_count, 1)
                self.assertIsNone(validate.call_args.kwargs["config"])

    def test_shared_fixtures_and_core_blocker_parity(self):
        expected = json.loads((Path(__file__).resolve().parents[2] / "desktop/tests/fixtures/lifecycle-evidence.json").read_text())
        for name, (stage, docs) in fixture_variants().items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                populate(root, stage, docs)
                result = observe(root, stage)
                self.assertEqual(result, expected[name])
                self.assertEqual(result["outcome"], "consistent")
                self.assertEqual(result["assurance"], ASSURANCE)
                if stage == "external-testing":
                    blocker = external_production_blocker(docs["external_receipt"], platform=result["summary"]["platform"])
                    if blocker:
                        self.assertEqual(result["guidance"], {"code": blocker[0], "message": blocker[1]})
                    else:
                        self.assertEqual(result["guidance"]["code"], "recorded-external-gate")
        self.assertEqual(expected["iosRecordedRetry"]["history"][0]["recordedRuns"]["executedBy"]["runId"], "9007199254740993")
        self.assertNotEqual(expected["iosRecordedRetry"]["history"][0]["recordedRuns"], expected["iosRecordedRetry"]["summary"]["recordedRuns"])

    def test_platform_stage_intent_and_predecessor_disagreement_export_no_partial_history(self):
        for key in ("platform", "stage", "operationIntentSha256", "previousReceiptSha256"):
            docs = fixture_chain()
            receipt = docs["external_receipt"]
            receipt[key] = "ios" if key == "platform" else "candidate" if key == "stage" else "f" * 64
            fixture_seal(receipt)
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                populate(root, "external-testing", docs)
                result = observe(root, "external-testing")
                self.assertIn(result["outcome"], ("invalid", "inconsistent"))
                self.assertEqual(result["history"], [])
                self.assertIsNone(result["summary"])

    def test_missing_invalid_and_inconsistent_never_export_history(self):
        for state in ("incomplete", "invalid", "inconsistent"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                values = populate(root, "external-testing")
                path = "external-testing-receipt.json"
                if state == "incomplete":
                    (root / path).unlink()
                elif state == "invalid":
                    put(root, path, '{"PRIVATE_CANARY": 1, "PRIVATE_CANARY": 2}')
                else:
                    receipt = copy.deepcopy(values[path])
                    receipt["previousReceiptSha256"] = "f" * 64
                    put(root, path, fixture_seal(receipt))
                result = observe(root, "external-testing")
                self.assertEqual(result["outcome"], state)
                self.assertEqual(result["history"], [])
                self.assertIsNone(result["summary"])
                self.assertEqual(result["guidance"]["code"], "evidence-" + state)
                self.assertNotIn("PRIVATE_CANARY", json.dumps(result))

    def test_repeated_candidate_bytes_must_match_without_claiming_bundle_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, "production-submit")
            path = root / "operation/external/operation/candidate/candidate-manifest.json"
            path.write_text(path.read_text() + "\n")  # Same sealed value, different selected bytes.
            result = observe(root, "production-submit")
            self.assertEqual(result["outcome"], "inconsistent")
            self.assertIsNone(result["summary"])

    def test_exact_document_and_aggregate_limits_require_real_eof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = populate(root, "candidate")
            for path, document in values.items():
                raw = json.dumps(document).encode()
                put(root, path, raw + b" " * (lifecycle.MAX_DOCUMENT_BYTES - len(raw)))
            result = observe(root, "candidate")
            self.assertEqual(result["outcome"], "consistent")  # Exact6MiB, all real EOFs.
            path = root / "candidate-manifest.json"
            path.write_bytes(path.read_bytes() + b" ")
            self.assert_limit(root, "candidate")

    def test_zero_remaining_refuses_next_nonempty_file_even_after_invalid_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = list(populate(root, "production-submit"))
            for path in paths[:3]:
                put(root, path, b"null" + b" " * (lifecycle.MAX_DOCUMENT_BYTES - 4))
            self.assert_limit(root, "production-submit")

    def test_rejected_arrays_are_charged_before_top_level_kind_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in bundle("production-submit"):
                put(root, path, [0] * 14999)  # Exactly15,000 nodes; fifth decoded copy exceeds60k.
            with patch.object(candidate, "_decoded_document", wraps=candidate._decoded_document) as decode:
                self.assert_limit(root, "production-submit")
            self.assertEqual(decode.call_count, 5)

    def test_symlink_changed_and_original_cleanup_failures_withhold_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, "candidate")
            path = root / "candidate-manifest.json"
            path.rename(root / "other.json")
            path.symlink_to("other.json")
            with self.assertRaises(ApiError) as refused:
                observe(root, "candidate")
            self.assertEqual(refused.exception.code, "artifacts_unsafe")
            path.unlink()
            (root / "other.json").rename(path)
            with patch.object(_snapshot._NamedTextReads, "check", side_effect=_snapshot._ReadProblem("snapshot.changed", "PRIVATE")):
                with self.assertRaises(ApiError) as refused:
                    observe(root, "candidate")
            self.assertEqual(refused.exception.code, "artifacts_changed")
            close = _snapshot._close_handles
            def closed_then_failed(handles, **kwargs):
                close(handles, **kwargs)
                raise _snapshot._DescriptorCleanupError("PRIVATE")
            with patch.object(_snapshot, "_close_handles", side_effect=closed_then_failed):
                with self.assertRaises(ApiError) as refused:
                    observe(root, "candidate")
            self.assertEqual(refused.exception.code, "artifacts_cleanup_unknown")
            self.assertNotIn("PRIVATE", str(refused.exception))

    def test_observation_does_not_write_launch_or_contact_services(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            populate(root, "production-submit")
            with patch.object(os, "mkdir", side_effect=AssertionError("write")), \
                 patch.object(os, "write", side_effect=AssertionError("write")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("launch")), \
                 patch.object(socket, "socket", side_effect=AssertionError("network")):
                self.assertEqual(observe(root, "production-submit")["outcome"], "consistent")


if __name__ == "__main__":
    unittest.main()
