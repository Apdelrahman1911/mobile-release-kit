from __future__ import annotations

import base64
import copy
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import ReleaseVersion, load_config
from mobile_release.errors import ValidationError
from mobile_release.provenance import (
    build_candidate_manifest, build_operation_intent, build_receipt, canonical_json_bytes,
    commitment_key_from_base64, load_candidate_manifest, load_operation_intent,
    load_release_receipt, load_store_receipt, private_state_commitment,
    seal, validate_evidence_document, validate_operation_intent,
    validate_operation_intent_context, validate_receipt_raw_binding,
    validate_store_receipt, verify_sealed, workflow_authority,
)

from .apple_contract_helpers import wrap_apple_contracts
from .evidence_helpers import (
    STAGES, build_lifecycle, git_identity, raw_receipt, workflow_environment,
)
from .helpers import android_config, ios_config, write_project


def replace_path(document: object, path: tuple, replacement: object) -> dict:
    result = copy.deepcopy(document)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return result


def value_paths(value: object, path: tuple = ()):
    if isinstance(value, dict):
        iterator = value.items()
    elif isinstance(value, list):
        iterator = enumerate(value)
    else:
        return
    for key, child in iterator:
        yield path + (key,), child
        yield from value_paths(child, path + (key,))


class OperationIntentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.contexts = {}
        for platform in ("android", "ios"):
            root = Path(cls.temporary.name) / platform
            config = load_config(write_project(root, android_config() if platform == "android" else ios_config(), platform=platform))
            with patch.dict(os.environ, {}, clear=True):
                cls.contexts[platform] = config, build_lifecycle(config, platform=platform)

    def context(self, platform="android", stage="candidate") -> tuple[dict, dict]:
        config, docs = self.contexts[platform]
        intent = docs[{"candidate": "candidate_intent", "external-testing": "external_intent", "production-submit": "production_intent"}[stage]]
        args = {"config": config, "release": config.release_version(), "git": git_identity(), "stage": stage, "platform": platform, "confirmation": f"{stage}:{platform}:1.2.3:42", "metadata_sha256": docs["metadata_sha256"], "artifacts": docs["records"], "signing_evidence": docs["signing"], "candidate_manifest": docs["candidate"], "candidate_receipt": docs["candidate_receipt"], "external_receipt": docs["external_receipt"]}
        return intent, args

    def test_external_intent_creation_and_context_preserve_configured_locale_scope(self) -> None:
        original, args = self.context("ios", "external-testing")
        payload = verify_sealed(copy.deepcopy(original))
        external = payload["storePrecondition"]["snapshot"]["external"]
        unconfigured = "  Unconfigured 日本語 <keep> 🧪\n\n"
        external["localizations"].append({"id": "unconfigured-ja", "locale": "ja", "whatsNew": unconfigured})
        external["targetLocalizations"].append({"locale": "ja", "whatsNew": unconfigured})
        with patch.dict(os.environ, workflow_environment("external-testing"), clear=True):
            built = build_operation_intent(**args, store_precondition=payload["storePrecondition"], private_state_commitments=payload["privateStateCommitments"])
            validate_operation_intent_context(built, **args)
            for change in ("overwrite-unconfigured", "create-unconfigured", "omit-configured"):
                broken = copy.deepcopy(payload)
                targets = broken["storePrecondition"]["snapshot"]["external"]["targetLocalizations"]
                if change == "overwrite-unconfigured":
                    targets[-1]["whatsNew"] = "Wrong replacement"
                elif change == "create-unconfigured":
                    targets.append({"locale": "zz", "whatsNew": "Unconfigured new locale"})
                else:
                    targets[:] = [item for item in targets if item["locale"] != "en-US"]
                document = seal(broken)
                # Historical shape remains valid. Context-aware authorization
                # is the guard, not a stale seal or an arbitrary shape ban.
                validate_operation_intent(document)
                with self.subTest(change=change):
                    with self.assertRaisesRegex(ValidationError, "configured locale scope"):
                        build_operation_intent(**args, store_precondition=broken["storePrecondition"], private_state_commitments=broken["privateStateCommitments"])
                    with self.assertRaisesRegex(ValidationError, "configured locale scope"):
                        validate_operation_intent_context(document, **args)

    def test_all_platform_stage_intents_bind_context_and_allow_later_original_attempt(self) -> None:
        for platform in self.contexts:
            for stage in STAGES:
                intent, args = self.context(platform, stage)
                for attempt in (1, 2, 10):
                    with self.subTest(platform=platform, stage=stage, attempt=attempt), patch.dict(os.environ, workflow_environment(stage, attempt=attempt), clear=True):
                        self.assertEqual(validate_operation_intent_context(intent, **args), verify_sealed(intent))

    def test_candidate_context_rejects_every_application_source_and_artifact_binding(self) -> None:
        for platform in self.contexts:
            intent, original = self.context(platform)
            changes = {
                "stage": "external-testing", "platform": "ios" if platform == "android" else "android",
                "confirmation": original["confirmation"] + " ",
                "release": ReleaseVersion(name="1.2.4", build=43),
                "metadata_sha256": "f" * 64,
                "artifacts": copy.deepcopy(original["artifacts"]),
            }
            changes["artifacts"][0]["sha256"] = "e" * 64
            if platform == "ios":
                changes["signing_evidence"] = {**original["signing_evidence"], "profileUuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
            for field, value in changes.items():
                with self.subTest(platform=platform, field=field), patch.dict(os.environ, workflow_environment(), clear=True), self.assertRaises(ValidationError):
                    validate_operation_intent_context(intent, **{**original, field: value})
            for field, value in (("commit", "c" * 40), ("tree", "d" * 40), ("ref", "refs/heads/not-main"), ("repository", "other/app"), ("repository_id", "99")):
                with self.subTest(platform=platform, git=field), patch.dict(os.environ, workflow_environment(), clear=True), self.assertRaises(ValidationError):
                    validate_operation_intent_context(intent, **{**original, "git": replace(original["git"], **{field: value})})
            for field, value in (("MOBILE_RELEASE_TOOLING_SHA", "e" * 40), ("MOBILE_RELEASE_REUSABLE_WORKFLOW_REPOSITORY", "other/toolkit"), ("GITHUB_WORKFLOW", "Impostor workflow"), ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/heads/other"), ("GITHUB_SHA", "d" * 40), ("MOBILE_RELEASE_REUSABLE_WORKFLOW_PATH", ".github/workflows/reusable-production-submit.yml")):
                with self.subTest(platform=platform, workflow=field), patch.dict(os.environ, {**workflow_environment(), field: value}, clear=True), self.assertRaises(ValidationError):
                    validate_operation_intent_context(intent, **original)

    def test_committed_configuration_and_predecessor_hashes_cannot_be_substituted(self) -> None:
        intent, args = self.context()
        config = args["config"]
        original_bytes = config.path.read_bytes()
        try:
            config.path.write_bytes(original_bytes + b"\n")
            with patch.dict(os.environ, workflow_environment(), clear=True), self.assertRaisesRegex(ValidationError, "configuration"):
                validate_operation_intent_context(intent, **args)
        finally:
            config.path.write_bytes(original_bytes)
        for stage in ("external-testing", "production-submit"):
            intent, args = self.context(stage=stage)
            for field in intent["predecessors"]:
                changed = verify_sealed(copy.deepcopy(intent))
                changed["predecessors"][field] = "f" * 64
                with self.subTest(stage=stage, predecessor=field), patch.dict(os.environ, workflow_environment(stage), clear=True), self.assertRaisesRegex(ValidationError, "predecessor"):
                    validate_operation_intent_context(seal(changed), **args)
            for field, bad in (("candidateSource", {**intent["candidateSource"], "tree": "e" * 40}), ("artifacts", list(reversed(intent["artifacts"]))), ("signing", [{**intent["signing"][0], "certificateSha256": "c" * 64}])):
                changed = verify_sealed(copy.deepcopy(intent))
                changed[field] = bad
                with self.subTest(stage=stage, field=field), patch.dict(os.environ, workflow_environment(stage), clear=True), self.assertRaises(ValidationError):
                    validate_operation_intent_context(seal(changed), **args)

    def test_recovery_uses_original_checked_out_source_but_records_actual_dispatch_identity(self) -> None:
        intent, args = self.context()
        recovery_env = workflow_environment(run_id="9000000000", head="e" * 40)
        raw = raw_receipt(intent)
        with patch.dict(os.environ, recovery_env, clear=True):
            with self.assertRaisesRegex(ValidationError, "explicit recovery_run_id"):
                validate_operation_intent_context(intent, **args)
            validate_operation_intent_context(intent, **args, recovery_run_id=intent["authorizedBy"]["runId"])
            with self.assertRaisesRegex(ValidationError, "source"):
                validate_operation_intent_context(intent, **{**args, "git": replace(args["git"], commit="e" * 40)}, recovery_run_id=intent["authorizedBy"]["runId"])
            validate_store_receipt(raw, config=args["config"], release=args["release"], stage="candidate", platform="android", operation_intent=intent, recovery_run_id=intent["authorizedBy"]["runId"])
            manifest = build_candidate_manifest(config=args["config"], release=args["release"], git=args["git"], platform="android", artifacts=args["artifacts"], store_receipt=raw, metadata_sha256=args["metadata_sha256"], operation_intent=intent)
            receipt = build_receipt(stage="candidate", platform="android", candidate_manifest=manifest, store_receipt=raw, operation_intent=intent)
        self.assertEqual(manifest["source"]["commit"], "2" * 40)
        self.assertEqual(manifest["authorizedBy"], intent["authorizedBy"])
        self.assertEqual(manifest["executedBy"], intent["authorizedBy"])
        self.assertEqual(manifest["producedBy"]["headSha"], "e" * 40)
        self.assertEqual(manifest["producedBy"]["runId"], "9000000000")
        with patch.dict(os.environ, {}, clear=True):
            validate_receipt_raw_binding(receipt, store_receipt=raw, operation_intent=intent, candidate_manifest=manifest)

    def test_external_intent_cannot_relabel_another_source_as_the_candidate(self) -> None:
        for platform in self.contexts:
            intent, _args = self.context(platform, "external-testing")
            for field in ("commit", "tree"):
                changed = verify_sealed(copy.deepcopy(intent))
                changed["operationSource"][field] = "e" * 40
                if field == "commit":
                    changed["authorizedBy"]["headSha"] = "e" * 40
                with self.subTest(platform=platform, field=field), self.assertRaisesRegex(ValidationError, "exact candidate source"):
                    validate_operation_intent(seal(changed))

    def test_raw_reuse_retains_real_executor_not_latest_attempt_or_unrelated_recovery(self) -> None:
        intent, args = self.context()
        raw = raw_receipt(intent)
        kwargs = {"config": args["config"], "release": args["release"], "stage": "candidate", "platform": "android", "operation_intent": intent}
        with patch.dict(os.environ, workflow_environment(attempt=3), clear=True):
            self.assertEqual(validate_store_receipt(raw, **kwargs)["executedBy"]["attempt"], 1)
            future = copy.deepcopy(raw)
            future["executedBy"]["attempt"] = 4
            with self.assertRaisesRegex(ValidationError, "future"):
                validate_store_receipt(future, **kwargs)
            with self.assertRaises(ValidationError):
                validate_store_receipt(raw, **kwargs, recovery_run_id=intent["authorizedBy"]["runId"])
        with patch.dict(os.environ, workflow_environment(run_id="900"), clear=True):
            with self.assertRaises(ValidationError):
                validate_store_receipt(raw, **kwargs)
            changed = copy.deepcopy(raw)
            changed["executedBy"]["runId"] = "901"
            with self.assertRaisesRegex(ValidationError, "unauthorized"):
                validate_store_receipt(changed, **kwargs, recovery_run_id=intent["authorizedBy"]["runId"])
            changed["executedBy"] = workflow_authority("candidate")
            with self.assertRaises(ValidationError):
                validate_store_receipt(changed, **kwargs)  # current executor is not original authority
            validate_store_receipt(changed, **kwargs, recovery_run_id=intent["authorizedBy"]["runId"])

    def test_raw_receipt_version_bump_cannot_accept_or_silently_upgrade_legacy_evidence(self) -> None:
        for platform, (config, docs) in self.contexts.items():
            for stage, intent_name, receipt_name in (
                ("candidate", "candidate_intent", "candidate_receipt"),
                ("external-testing", "external_intent", "external_receipt"),
                ("production-submit", "production_intent", "production_receipt"),
            ):
                intent = docs[intent_name]
                raw = raw_receipt(intent)
                self.assertEqual(raw["schemaVersion"], 3)
                original = copy.deepcopy(raw)
                with patch.dict(os.environ, workflow_environment(stage), clear=True):
                    validate_store_receipt(raw, config=config, release=config.release_version(), stage=stage, platform=platform, operation_intent=intent)
                    for version in (1, 2, 4, 3.0, "3", True):
                        incompatible = {**raw, "schemaVersion": version}
                        message = "floating-point values are forbidden" if type(version) is float else "schemaVersion must be 3"
                        with self.subTest(platform=platform, stage=stage, version=version):
                            with self.assertRaisesRegex(ValidationError, message):
                                validate_store_receipt(incompatible, config=config, release=config.release_version(), stage=stage, platform=platform, operation_intent=intent)
                            with self.assertRaisesRegex(ValidationError, message):
                                validate_receipt_raw_binding(docs[receipt_name], store_receipt=incompatible, operation_intent=intent, candidate_manifest=docs["candidate"])
                        self.assertEqual(incompatible["schemaVersion"], version)
                self.assertEqual(raw, original)

    def test_ios_candidate_automatic_reconciliation_and_explicit_retry_are_distinct(self) -> None:
        intent, args = self.context("ios")
        kwargs = {"config": args["config"], "release": args["release"], "stage": "candidate", "platform": "ios", "operation_intent": intent}
        with patch.dict(os.environ, workflow_environment(), clear=True):
            validate_store_receipt(raw_receipt(intent, result="reconciled"), **kwargs)
        with patch.dict(os.environ, workflow_environment(attempt=2), clear=True):
            later = raw_receipt(intent, result="reconciled", executed_by=workflow_authority("candidate"))
            with self.assertRaisesRegex(ValidationError, "operator"):
                validate_store_receipt(later, **kwargs)
        for attempt in (1, 2):
            with patch.dict(os.environ, workflow_environment(run_id="900", attempt=attempt), clear=True):
                raw = raw_receipt(intent, result="operator_authorized_reconciliation", executed_by=workflow_authority("candidate"))
                validate_store_receipt(raw, **kwargs, recovery_run_id=intent["authorizedBy"]["runId"])
                raw["result"] = "operator_authorized_retry"
                if attempt == 1:
                    validate_store_receipt(raw, **kwargs, recovery_run_id=intent["authorizedBy"]["runId"])
                else:
                    with self.assertRaisesRegex(ValidationError, "rerun"):
                        validate_store_receipt(raw, **kwargs, recovery_run_id=intent["authorizedBy"]["runId"])

    def test_pure_final_readback_validation_needs_no_environment_but_rejects_relabeling(self) -> None:
        for platform, (_config, docs) in self.contexts.items():
            for stage, intent_name, receipt_name in (("candidate", "candidate_intent", "candidate_receipt"), ("external-testing", "external_intent", "external_receipt"), ("production-submit", "production_intent", "production_receipt")):
                intent, receipt = docs[intent_name], docs[receipt_name]
                raw = raw_receipt(intent)
                kwargs = {"operation_intent": intent, "candidate_manifest": docs["candidate"]}
                with self.subTest(platform=platform, stage=stage), patch.dict(os.environ, {}, clear=True):
                    validate_receipt_raw_binding(receipt, store_receipt=raw, **kwargs)
                    for field, bad in (("observedAt", "2026-01-02T00:00:00Z"), ("result", "reconciled"), ("appIdentity", "other.application"), ("operationIntentSha256", "f" * 64), ("buildNumber", 43), ("unexpected", "data"), ("state", "UNKNOWN")):
                        with self.subTest(field=field), self.assertRaises(ValidationError):
                            validate_receipt_raw_binding(receipt, store_receipt={**raw, field: bad}, **kwargs)
                    for role in ("authorizedBy", "executedBy"):
                        changed = copy.deepcopy(raw)
                        changed[role]["runId"] = "99"
                        with self.subTest(role=role), self.assertRaises(ValidationError):
                            validate_receipt_raw_binding(receipt, store_receipt=changed, **kwargs)

    def test_typed_loaders_cannot_confuse_an_intent_with_candidate_or_receipt(self) -> None:
        _, docs = self.contexts["android"]
        loaders = {"candidate": load_candidate_manifest, "candidate_intent": load_operation_intent, "candidate_receipt": load_release_receipt}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            for name, correct in loaders.items():
                path.write_text(json.dumps(docs[name]))
                self.assertEqual(correct(path), docs[name])
                for other in set(loaders.values()) - {correct}:
                    with self.assertRaises(ValidationError):
                        other(path)
            for data in (b'{"schemaVersion":1,"schemaVersion":1}', b'[]', b'null', b'"' + b'\xff' + b'"', b'[' * 2000 + b'0' + b']' * 2000, b' ' * (2 * 1024 * 1024 + 1)):
                path.write_bytes(data)
                for loader in (*loaders.values(), load_store_receipt):
                    with self.subTest(loader=loader.__name__, size=len(data)), self.assertRaises(ValidationError):
                        loader(path)

    def test_public_serializer_rejects_sensitive_fields_values_invalid_unicode_and_depth(self) -> None:
        for value in ({"password": "synthetic"}, {"items": ["-----BEGIN PRIVATE KEY-----"]}, {"items": ["-----BEGIN CERTIFICATE-----"]}, {"number": 0.5}, {"number": float("nan")}, {"text": "\ud800"}, {"\ud800": "value"}, {1: "non-string key"}):
            with self.subTest(value=repr(value)), self.assertRaises(ValidationError):
                canonical_json_bytes(value)
        value = {}
        for _ in range(66):
            value = {"child": value}
        with self.assertRaisesRegex(ValidationError, "nesting"):
            canonical_json_bytes(value)

    def test_private_commitment_matches_ruby_without_relaxing_public_evidence(self) -> None:
        # Exact fictional target used by test_apple_production_lane.rb. The
        # expected digest is emitted by real Ruby HMAC canonicalization, not
        # computed here by the function under test.
        value = {"contactFirstName": "LanePrivateFirst", "contactLastName": "LanePrivateLast", "contactEmail": "lane-review@example.test", "contactPhone": "+12025550124", "demoAccountRequired": True, "demoAccountName": "lane-private-demo", "demoAccountPassword": "lane-private-password", "notes": "Lane private review instructions"}
        expected = "86c70fb50993ed9821ba6d3e636103dffe2d914bc6c81280115ef8b26ba3dedc"
        self.assertEqual(private_state_commitment(domain="app-review", value=value, key=b"k" * 32), expected)
        self.assertNotEqual(private_state_commitment(domain="beta-review", value=value, key=b"k" * 32), expected)
        self.assertNotEqual(private_state_commitment(domain="app-review", value=value, key=b"j" * 32), expected)
        with self.assertRaises(ValidationError):
            canonical_json_bytes(value)
        for bad in (b"k" * 31, b"k" * 33, "k" * 32, None):
            with self.assertRaises(ValidationError):
                private_state_commitment(domain="app-review", value=value, key=bad)
        for bad in (0.5, "\ud800", {"secret-input": object()}):
            with self.assertRaises(ValidationError) as error:
                private_state_commitment(domain="app-review", value={"private-name": bad}, key=b"k" * 32)
            self.assertNotIn("private-name", str(error.exception))
            self.assertNotIn("secret-input", str(error.exception))
        encoded = base64.b64encode(b"k" * 32).decode()
        self.assertEqual(commitment_key_from_base64(encoded), b"k" * 32)
        for bad in (encoded + "\n", "not-base64", base64.b64encode(b"k" * 31).decode()):
            with self.assertRaises(ValidationError):
                commitment_key_from_base64(bad)

    def test_malformed_container_corpus_raises_validation_errors_not_python_exceptions(self) -> None:
        corpus = []
        for platform, (_, docs) in self.contexts.items():
            corpus.extend((f"{platform}/{name}", docs[name]) for name in ("candidate", "candidate_intent", "external_intent", "production_intent", "candidate_receipt", "external_receipt", "production_receipt"))
        with tempfile.TemporaryDirectory() as temporary:
            _, apple = wrap_apple_contracts(Path(temporary))
            corpus.extend((f"apple/{name}/{field}", docs[field]) for name, docs in apple.items() for field in ("intent", "receipt"))
        checked = 0
        for name, sealed in corpus:
            document = verify_sealed(sealed)
            for path, original in value_paths(document):
                for bad in ({}, []):
                    if original == bad:
                        continue  # legitimate already-empty fields are not malformed
                    changed = replace_path(document, path, bad)
                    try:
                        validate_evidence_document(seal(changed))
                    except ValidationError:
                        pass
                    except Exception as error:
                        self.fail(f"{name} {path}: {type(error).__name__}: {error}")
                    checked += 1
        self.assertGreater(checked, 4000)

    def test_wrong_nested_json_types_are_rejected_not_coerced(self) -> None:
        corpus = []
        for platform, (_config, docs) in self.contexts.items():
            corpus.extend((f"{platform}/{name}", docs[name]) for name in ("candidate", "candidate_intent", "external_intent", "production_intent", "candidate_receipt", "external_receipt", "production_receipt"))
        with tempfile.TemporaryDirectory() as temporary:
            _, apple = wrap_apple_contracts(Path(temporary))
            corpus.extend((f"apple/{name}/{field}", docs[field]) for name, docs in apple.items() for field in ("intent", "receipt"))
        checked = 0
        for name, sealed in corpus:
            document = verify_sealed(sealed)
            for path, original in value_paths(document):
                # {} may be a legitimate empty object and [] a legitimate empty
                # collection; replace with a different JSON type, not emptiness.
                bad = {} if isinstance(original, list) or original is None else []
                changed = replace_path(document, path, bad)
                with self.subTest(document=name, path=path), self.assertRaises(ValidationError):
                    validate_evidence_document(seal(changed))
                checked += 1
        self.assertGreater(checked, 4000)

    def test_raw_store_document_nested_type_corpus_fails_closed(self) -> None:
        checked = 0
        for platform, (_config, docs) in self.contexts.items():
            for stage, intent_name, receipt_name in (("candidate", "candidate_intent", "candidate_receipt"), ("external-testing", "external_intent", "external_receipt"), ("production-submit", "production_intent", "production_receipt")):
                intent = docs[intent_name]
                raw = raw_receipt(intent)
                for path, original in value_paths(raw):
                    bad = {} if isinstance(original, list) or original is None else []
                    changed = replace_path(raw, path, bad)
                    with self.subTest(platform=platform, stage=stage, path=path), patch.dict(os.environ, {}, clear=True), self.assertRaises(ValidationError):
                        validate_receipt_raw_binding(docs[receipt_name], store_receipt=changed, operation_intent=intent, candidate_manifest=docs["candidate"])
                    checked += 1
        self.assertGreater(checked, 200)

    def test_numeric_team_ids_are_not_silently_coerced_into_valid_signers(self) -> None:
        _config, docs = self.contexts["ios"]
        for name in ("candidate", "candidate_intent", "external_intent", "production_intent"):
            changed = verify_sealed(copy.deepcopy(docs[name]))
            changed["signing"][0]["teamId"] = 1234567890
            with self.subTest(document=name), self.assertRaisesRegex(ValidationError, "signing/profile"):
                validate_evidence_document(seal(changed))


if __name__ == "__main__":
    unittest.main()
