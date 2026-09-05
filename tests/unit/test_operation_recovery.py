from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import ExitStack, contextmanager, redirect_stdout
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mobile_release import cli, ios_artifacts
from mobile_release.cli import _ci, _status, build_parser
from mobile_release.config import load_config
from mobile_release.errors import StoreOperationError, ValidationError
from mobile_release.ios import SigningValidityInterval
from mobile_release.inspection import MAX_INSPECTION_SECONDS
from mobile_release.reporting import Finding, Status
from mobile_release.provenance import (
    copy_immutable_file,
    load_operation_intent,
    load_release_receipt,
    validate_receipt_raw_binding,
    write_evidence,
)

from .evidence_helpers import android_precondition, build_lifecycle, git_identity, ios_precondition, raw_receipt, workflow_environment
from .helpers import android_config, ios_config, write_project
from .ios_artifact_helpers import native_image
from .ios_entitlement_helpers import NativeProfileSeam, binary_dictionary, modernize_ipa_fixture, rewrite_zip_members, signed_entitlements


def directory_snapshot(directory: Path) -> dict[Path, tuple[str, bytes | None]]:
    return {
        path.relative_to(directory): ("directory", None) if path.is_dir() else ("file", path.read_bytes())
        for path in directory.rglob("*")
    }


class StoreWireFixture:
    """Fake only Store transport; exercise real CLI/adapter/persistence validators.

    These files are not signed AABs. The native artifact validator is stubbed at
    the test boundary; release reconciliation itself is also covered against
    the pinned Publisher/Spaceship clients by the Ruby lane tests.
    """

    def __init__(self, root: Path):
        self.root = root
        self.config = load_config(write_project(root, android_config()))
        self.binary = root / "app.aab"
        with zipfile.ZipFile(self.binary, "w") as archive:
            archive.writestr("base/lib/arm64-v8a/libfixture.so", b"non-executable fixture")
            archive.writestr("base/manifest/AndroidManifest.xml", b"synthetic native-parser seam")
            archive.writestr("base/dex/classes.dex", b"non-executable fixture")
            archive.writestr("BundleConfig.pb", b"synthetic native-parser seam")
        self.report = root / "validation-report.json"
        self.report.write_text('{"fixture":true}\n')
        self.mutations: list[str] = []
        self.calls: list[tuple[str, str]] = []
        self.store_complete: set[str] = set()
        self.raise_after_mutation = False
        self.preconditions: list[Path] = []
        self.outputs = {stage: root / ".mobile-release" / stage for stage in ("candidate", "external-testing", "production-submit")}

    def command(self, stage: str, mode: str, *, output: Path | None = None, intent: Path | None = None) -> list[str]:
        argv = ["ci", stage, "--config", str(self.config.path), "--platform", "android", "--confirm", f"{stage}:android:1.2.3:42", "--output-dir", str(output or self.outputs[stage]), f"--{mode}"]
        if intent is not None:
            argv += ["--operation-intent", str(intent)]
        if stage == "candidate":
            argv += ["--artifact", f"android-aab={self.binary}", "--artifact", f"validation-report={self.report}"]
        else:
            argv += ["--candidate-manifest", str(self.outputs["candidate"] / "candidate-manifest.json")]
            if stage == "production-submit":
                argv += ["--external-receipt", str(self.outputs["external-testing"] / "external-testing-receipt.json")]
        return argv

    def wire(self, command: list[str], **kwargs):
        env = kwargs["env"]
        stage = {"android_internal_upload": "candidate", "android_external_promote": "external-testing", "android_production_draft": "production-submit"}[command[-1]]
        mode = env["MOBILE_RELEASE_STORE_MODE"]
        self.calls.append((stage, mode))
        path = Path(env["MOBILE_RELEASE_STORE_RECEIPT_PATH"])
        if mode == "prepare":
            records = []
            if stage != "candidate":
                candidate = json.loads((self.outputs["candidate"] / "candidate-manifest.json").read_text())
                records = candidate["artifacts"]
            value = android_precondition(self.config, stage=stage, artifacts=records)
            self.preconditions.append(path)
        else:
            intent = load_operation_intent(Path(env["MOBILE_RELEASE_OPERATION_INTENT_PATH"]))
            result = "reconciled" if stage in self.store_complete else "accepted"
            if stage not in self.store_complete:
                self.mutations.append(stage)
                self.store_complete.add(stage)
            if self.raise_after_mutation:
                raise subprocess.TimeoutExpired(command, 3600)
            value = raw_receipt(intent, result=result, executed_by=json.loads(env["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"]))
        path.write_text(json.dumps(value) + "\n")
        return subprocess.CompletedProcess(command, 0)

    def invoke(self, stage: str, mode: str, *, attempt: int = 1, output: Path | None = None, intent: Path | None = None) -> int:
        with patch.dict(os.environ, workflow_environment(stage, attempt=attempt), clear=True), redirect_stdout(io.StringIO()):
            return _ci(build_parser().parse_args(self.command(stage, mode, output=output, intent=intent)))


class OperationRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = StoreWireFixture(Path(self.temporary.name))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("mobile_release.cli.git_context", return_value=git_identity()))
        self.stack.enter_context(patch("mobile_release.discovery.git_context", return_value=git_identity()))
        self.stack.enter_context(patch("mobile_release.preflight.git_context", return_value=git_identity()))
        self.stack.enter_context(patch("mobile_release.cli.validate_aab", return_value=[]))
        # GitHub authority is exercised independently by workflow tests. This
        # fixture covers native/history, Store transport and persistence only.
        self.authentication = self.stack.enter_context(patch(
            "mobile_release.cli.authenticate_operation_intent",
            side_effect=lambda path, **_: load_operation_intent(path),
        ))
        self.stack.enter_context(patch("mobile_release.stores._require_fastlane_bundle"))
        self.stack.enter_context(patch("mobile_release.stores.resolve_tooling_root", return_value=Path(__file__).resolve().parents[2]))
        self.stack.enter_context(patch("mobile_release.stores.subprocess.run", side_effect=self.fixture.wire))

    def candidate(self) -> Path:
        self.fixture.invoke("candidate", "prepare-operation")
        self.fixture.invoke("candidate", "execute-store")
        return self.fixture.outputs["candidate"]

    def native_android_policy(self):
        from mobile_release.android import validate_aab
        from .test_android_upload_validation import jarsigner_output

        state = {"warning": "", "calls": []}
        def command(argv, **kwargs):
            if argv[0] in {"jarsigner", "keytool"}:
                state["calls"].append(argv[0])
                if argv[0] == "jarsigner":
                    return subprocess.CompletedProcess(argv, 4, jarsigner_output(warning=state["warning"]), "")
                return subprocess.CompletedProcess(argv, 0, "Signer #1:\n\nCertificate #1:\nSHA256: " + ":".join(["AA"] * 32) + "\n", "")
            return self.fixture.wire(argv, **kwargs)
        self.stack.enter_context(patch("mobile_release.cli.validate_aab", new=validate_aab))
        self.stack.enter_context(patch("mobile_release.android._bundletool_manifest", return_value='<manifest package="com.example.reader" android:versionCode="42" android:versionName="1.2.3" />'))
        self.stack.enter_context(patch("mobile_release.android.subprocess.run", side_effect=command))
        return state

    def test_android_raw_completion_after_signer_warning_threshold_retains_original_evidence(self) -> None:
        state = self.native_android_policy()
        self.fixture.invoke("candidate", "prepare-operation")
        with patch("mobile_release.cli.build_candidate_manifest", side_effect=RuntimeError("manifest persistence failed")), self.assertRaises(RuntimeError):
            self.fixture.invoke("candidate", "execute-store")
        output = self.fixture.outputs["candidate"]
        raw = (output / "raw-store-receipt.json").read_bytes()
        calls = list(self.fixture.calls)
        # An initially eligible signer with 208 days left crosses JDK21's
        # 180-day warning window 31 days later, within 90-day retention.
        state["warning"] = "This jar contains entries whose signer certificate will expire within six months. \n"
        self.assertEqual(self.fixture.invoke("candidate", "execute-store", attempt=2), 0)
        self.assertEqual(state["calls"], ["jarsigner", "keytool"])
        self.assertEqual(self.fixture.calls, calls)
        self.assertEqual(self.fixture.mutations, ["candidate"])
        self.assertEqual((output / "raw-store-receipt.json").read_bytes(), raw)
        self.assertEqual(load_release_receipt(output / "candidate-receipt.json")["executedBy"]["attempt"], 1)
        self.assertEqual(load_release_receipt(output / "candidate-receipt.json")["producedBy"]["attempt"], 2)

    def test_android_accepted_bundle_can_reconcile_after_warning_without_a_new_upload(self) -> None:
        state = self.native_android_policy()
        self.fixture.invoke("candidate", "prepare-operation")
        self.fixture.raise_after_mutation = True
        with self.assertRaises(StoreOperationError):
            self.fixture.invoke("candidate", "execute-store")
        output = self.fixture.outputs["candidate"]
        self.assertFalse((output / "raw-store-receipt.json").exists())
        calls = list(self.fixture.calls)
        self.fixture.raise_after_mutation = False
        state["warning"] = "This jar contains entries whose signer certificate will expire within six months. \n"
        self.assertEqual(self.fixture.invoke("candidate", "execute-store", attempt=2), 0)
        self.assertEqual(state["calls"], ["jarsigner", "keytool"])
        self.assertEqual(self.fixture.calls, calls + [("candidate", "execute")])
        self.assertEqual(self.fixture.mutations, ["candidate"])
        self.assertEqual(load_release_receipt(output / "candidate-receipt.json")["outcome"], "reconciled")

    def test_android_historical_validation_requires_authenticity_before_artifacts_or_store(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        calls = list(self.fixture.calls)
        self.authentication.side_effect = ValidationError("original authenticated artifact is unavailable")
        with patch("mobile_release.cli.validate_aab_structure", side_effect=AssertionError("history consumed before authentication")), self.assertRaisesRegex(ValidationError, "authenticated artifact"):
            self.fixture.invoke("candidate", "execute-store", attempt=2)
        self.assertEqual(self.fixture.calls, calls)
        self.assertEqual(self.fixture.mutations, [])

    def test_android_authenticated_history_retains_structure_and_exact_all_artifact_binding(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        calls = list(self.fixture.calls)
        original = self.fixture.binary.read_bytes()
        for change in ("invalid-layout", "changed-original-bytes"):
            with self.subTest(change=change):
                self.fixture.binary.write_bytes(original)
                if change == "invalid-layout":
                    with zipfile.ZipFile(self.fixture.binary, "w") as archive:
                        archive.writestr("unrelated", b"no Android bundle structure")
                else:
                    with zipfile.ZipFile(self.fixture.binary, "a") as archive:
                        archive.writestr("base/assets/foreign", b"changed")
                with self.assertRaises(ValidationError):
                    self.fixture.invoke("candidate", "execute-store", attempt=2)
                self.assertEqual(self.fixture.calls, calls)
                self.assertEqual(self.fixture.mutations, [])
        self.fixture.binary.write_bytes(original)
        config_bytes = self.fixture.config.path.read_bytes()
        value = json.loads(config_bytes)
        value["android"]["uploadCertificateSha256"] = "b" * 64
        self.fixture.config.path.write_text(json.dumps(value))
        with self.assertRaises(ValidationError):
            self.fixture.invoke("candidate", "execute-store", attempt=2)
        self.assertEqual(self.fixture.calls, calls)

    def test_android_fresh_preparation_still_rejects_current_signature_warning(self) -> None:
        state = self.native_android_policy()
        state["warning"] = "This jar contains entries whose signer certificate will expire within six months. \n"
        with self.assertRaisesRegex(ValidationError, "android.aab.signature"):
            self.fixture.invoke("candidate", "prepare-operation")
        self.assertEqual(self.fixture.calls, [])
        self.authentication.assert_not_called()

    def test_manifest_failure_after_store_success_reuses_original_raw_on_later_attempt(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        output = self.fixture.outputs["candidate"]
        with patch("mobile_release.cli.build_candidate_manifest", side_effect=RuntimeError("injected manifest failure")):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.fixture.invoke("candidate", "execute-store")
        self.assertEqual(self.fixture.mutations, ["candidate"])
        self.assertFalse((output / "candidate-manifest.json").exists())
        self.assertFalse((output / "candidate-receipt.json").exists())
        original_raw = (output / "raw-store-receipt.json").read_bytes()
        calls = list(self.fixture.calls)
        self.assertEqual(self.fixture.invoke("candidate", "execute-store", attempt=2), 0)
        self.assertEqual(self.fixture.calls, calls)
        self.assertEqual((output / "raw-store-receipt.json").read_bytes(), original_raw)
        manifest = json.loads((output / "candidate-manifest.json").read_text())
        receipt = load_release_receipt(output / "candidate-receipt.json")
        self.assertEqual(manifest["authorizedBy"]["attempt"], 1)
        self.assertEqual(manifest["executedBy"]["attempt"], 1)
        self.assertEqual(manifest["producedBy"]["attempt"], 2)
        validate_receipt_raw_binding(receipt, store_receipt=json.loads(original_raw), operation_intent=load_operation_intent(output / "candidate-operation-intent.json"), candidate_manifest=manifest)

    def test_partial_manifest_completes_only_with_same_producer_and_original_raw(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        output = self.fixture.outputs["candidate"]
        original_write = write_evidence

        def fail_receipt(path, value):
            if path.name == "candidate-receipt.json":
                raise OSError("injected persistence failure")
            return original_write(path, value)

        with patch("mobile_release.cli.write_evidence", side_effect=fail_receipt):
            with self.assertRaisesRegex(OSError, "injected"):
                self.fixture.invoke("candidate", "execute-store")
        original_manifest = (output / "candidate-manifest.json").read_bytes()
        calls = list(self.fixture.calls)
        self.assertEqual(self.fixture.invoke("candidate", "execute-store"), 0)
        self.assertEqual((output / "candidate-manifest.json").read_bytes(), original_manifest)
        self.assertEqual(self.fixture.calls, calls)

    def test_partial_manifest_from_previous_attempt_requires_fresh_staging_not_rebuild(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        output = self.fixture.outputs["candidate"]
        original_write = write_evidence

        def fail_receipt(path, value):
            if path.name == "candidate-receipt.json":
                raise OSError("injected persistence failure")
            original_write(path, value)

        with patch("mobile_release.cli.write_evidence", side_effect=fail_receipt), self.assertRaises(OSError):
            self.fixture.invoke("candidate", "execute-store")
        saved = {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()}
        calls = list(self.fixture.calls)
        with self.assertRaisesRegex(ValidationError, "new empty --output-dir.*SAME"):
            self.fixture.invoke("candidate", "execute-store", attempt=2)
        self.assertEqual(self.fixture.calls, calls)
        fresh = output.with_name("candidate-recovery")
        self.assertEqual(self.fixture.invoke("candidate", "execute-store", attempt=2, output=fresh, intent=output / "candidate-operation-intent.json"), 0)
        self.assertEqual(self.fixture.mutations, ["candidate"])
        self.assertEqual(load_release_receipt(fresh / "candidate-receipt.json")["outcome"], "reconciled")
        self.assertEqual(saved, {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()})

    def test_partial_manifest_rejects_missing_or_substituted_original_raw_before_store(self) -> None:
        output = self.candidate()
        (output / "candidate-receipt.json").unlink()
        raw_path = output / "raw-store-receipt.json"
        original = raw_path.read_text()
        calls = list(self.fixture.calls)
        for replacement in (None, "{}", "not-json", json.dumps({**json.loads(original), "observedAt": "2026-01-01T00:00:01Z"})):
            with self.subTest(replacement=replacement):
                if replacement is None:
                    raw_path.unlink()
                else:
                    raw_path.write_text(replacement)
                with self.assertRaisesRegex(ValidationError, "new empty --output-dir"):
                    self.fixture.invoke("candidate", "execute-store")
                self.assertEqual(self.fixture.calls, calls)
                self.assertFalse((output / "candidate-receipt.json").exists())

    def test_rejected_partial_manifest_preserves_whole_directory_before_copies(self) -> None:
        output = self.candidate()
        (output / "candidate-receipt.json").unlink()
        (output / "store-metadata.zip").unlink()
        raw_path = output / "raw-store-receipt.json"
        original_raw = raw_path.read_bytes()
        original_manifest = (output / "candidate-manifest.json").read_bytes()
        calls = list(self.fixture.calls)
        for raw, attempt in ((None, 1), (b"{}", 1), (original_raw, 2)):
            with self.subTest(raw=raw is None, attempt=attempt):
                raw_path.unlink(missing_ok=True)
                if raw is not None:
                    raw_path.write_bytes(raw)
                before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
                directories = {path.relative_to(output) for path in output.rglob("*") if path.is_dir()}
                with self.assertRaisesRegex(ValidationError, "new empty --output-dir"):
                    self.fixture.invoke("candidate", "execute-store", attempt=attempt)
                self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})
                self.assertEqual(directories, {path.relative_to(output) for path in output.rglob("*") if path.is_dir()})
                self.assertEqual(original_manifest, (output / "candidate-manifest.json").read_bytes())
                self.assertEqual(calls, self.fixture.calls)

    def test_complete_evidence_requires_matching_raw_and_never_falls_back_to_store(self) -> None:
        for stage in ("candidate", "external-testing", "production-submit"):
            self.fixture.invoke(stage, "prepare-operation")
            self.fixture.invoke(stage, "execute-store")
            output = self.fixture.outputs[stage]
            raw_path = output / "raw-store-receipt.json"
            original_raw = raw_path.read_bytes()
            changed = json.loads(original_raw)
            changed["observedAt"] = "2026-01-01T00:00:01Z"
            calls = list(self.fixture.calls)
            for replacement in (None, b"{}", json.dumps(changed).encode()):
                with self.subTest(stage=stage, missing=replacement is None):
                    raw_path.unlink(missing_ok=True)
                    if replacement is not None:
                        raw_path.write_bytes(replacement)
                    with self.assertRaises(ValidationError):
                        self.fixture.invoke(stage, "execute-store", attempt=2)
                    self.assertEqual(calls, self.fixture.calls)
            raw_path.write_bytes(original_raw)

    def test_incompatible_complete_evidence_preserves_whole_output_before_any_artifact_check(self) -> None:
        for stage in ("candidate", "external-testing", "production-submit"):
            self.fixture.invoke(stage, "prepare-operation")
            self.fixture.invoke(stage, "execute-store")
            output = self.fixture.outputs[stage]
            if stage == "candidate":
                # The old path recreated this missing file before noticing the
                # raw readback was absent, corrupt or from another observation.
                (output / "store-metadata.zip").unlink()
            (output / "preserve" / "nested").mkdir(parents=True)
            (output / "preserve" / "user-note.txt").write_bytes(b"preserve this diagnostic")
            raw_path = output / "raw-store-receipt.json"
            original_raw = raw_path.read_bytes()
            changed = json.loads(original_raw)
            changed["observedAt"] = "2026-01-01T00:00:01Z"
            calls = list(self.fixture.calls)
            for replacement in (None, b"{}", json.dumps(changed).encode()):
                with self.subTest(stage=stage, missing=replacement is None):
                    raw_path.unlink(missing_ok=True)
                    if replacement is not None:
                        raw_path.write_bytes(replacement)
                    before = directory_snapshot(output)
                    with patch("mobile_release.cli.validate_aab", side_effect=AssertionError("artifact validation ran before final guard")), self.assertRaisesRegex(ValidationError, "existing final evidence"):
                        self.fixture.invoke(stage, "execute-store", attempt=2)
                    self.assertEqual(before, directory_snapshot(output))
                    self.assertEqual(calls, self.fixture.calls)
            raw_path.write_bytes(original_raw)

    def test_complete_candidate_does_not_recreate_a_missing_local_metadata_copy(self) -> None:
        output = self.candidate()
        (output / "store-metadata.zip").unlink()
        before = directory_snapshot(output)
        calls = list(self.fixture.calls)
        self.assertEqual(self.fixture.invoke("candidate", "execute-store", attempt=2), 0)
        self.assertEqual(before, directory_snapshot(output))
        self.assertEqual(calls, self.fixture.calls)

    def test_context_drift_rejected_before_staging_metadata_or_new_intent_copy(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        original = self.fixture.outputs["candidate"]
        original_intent = original / "candidate-operation-intent.json"
        recovery = original.with_name("empty-recovery")
        recovery.mkdir()
        self.fixture.report.write_text('{"changed":true}\n')
        before = directory_snapshot(recovery)
        calls = list(self.fixture.calls)
        with self.assertRaisesRegex(ValidationError, "artifacts do not match"):
            self.fixture.invoke("candidate", "execute-store", attempt=2, output=recovery, intent=original_intent)
        self.assertEqual(before, directory_snapshot(recovery))
        self.assertEqual(calls, self.fixture.calls)

    def test_conflicting_staged_intent_cannot_leave_a_new_metadata_copy(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        original = self.fixture.outputs["candidate"]
        recovery = original.with_name("conflicting-staging")
        recovery.mkdir()
        (recovery / "candidate-operation-intent.json").write_bytes(b"different immutable document")
        before = directory_snapshot(recovery)
        calls = list(self.fixture.calls)
        with self.assertRaisesRegex(ValidationError, "conflicts"):
            self.fixture.invoke("candidate", "execute-store", attempt=2, output=recovery, intent=original / "candidate-operation-intent.json")
        self.assertEqual(before, directory_snapshot(recovery))
        self.assertEqual(calls, self.fixture.calls)

    def test_prepare_cannot_replace_a_missing_intent_after_raw_evidence_exists(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        with patch("mobile_release.cli.build_candidate_manifest", side_effect=RuntimeError("lost manifest")), self.assertRaises(RuntimeError):
            self.fixture.invoke("candidate", "execute-store")
        output = self.fixture.outputs["candidate"]
        (output / "candidate-operation-intent.json").unlink()
        (output / "store-metadata.zip").unlink()
        before = directory_snapshot(output)
        calls = list(self.fixture.calls)
        with self.assertRaisesRegex(ValidationError, "original operation intent"):
            self.fixture.invoke("candidate", "prepare-operation", attempt=2)
        self.assertEqual(before, directory_snapshot(output))
        self.assertEqual(calls, self.fixture.calls)

    def test_all_stages_can_reconcile_timeout_without_raw_or_second_mutation(self) -> None:
        for stage in ("candidate", "external-testing", "production-submit"):
            with self.subTest(stage=stage):
                self.fixture.invoke(stage, "prepare-operation")
                self.fixture.raise_after_mutation = True
                with self.assertRaises(StoreOperationError):
                    self.fixture.invoke(stage, "execute-store")
                output = self.fixture.outputs[stage]
                self.assertFalse((output / "raw-store-receipt.json").exists())
                self.fixture.raise_after_mutation = False
                self.assertEqual(self.fixture.invoke(stage, "execute-store", attempt=2), 0)
                receipt = load_release_receipt(output / f"{stage}-receipt.json")
                self.assertEqual(receipt["outcome"], "reconciled")
                self.assertEqual(self.fixture.mutations.count(stage), 1)

    def test_promotion_receipt_write_failure_reuses_original_raw_and_preserves_predecessors(self) -> None:
        candidate_dir = self.candidate()
        candidate_bytes = (candidate_dir / "candidate-manifest.json").read_bytes()
        for stage in ("external-testing", "production-submit"):
            with self.subTest(stage=stage):
                self.fixture.invoke(stage, "prepare-operation")
                with patch("mobile_release.cli.write_evidence", side_effect=OSError("injected final write failure")), self.assertRaises(OSError):
                    self.fixture.invoke(stage, "execute-store")
                output = self.fixture.outputs[stage]
                raw_bytes = (output / "raw-store-receipt.json").read_bytes()
                calls = list(self.fixture.calls)
                self.assertEqual(self.fixture.invoke(stage, "execute-store", attempt=2), 0)
                self.assertEqual(self.fixture.calls, calls)
                self.assertEqual(raw_bytes, (output / "raw-store-receipt.json").read_bytes())
        self.assertEqual(candidate_bytes, (candidate_dir / "candidate-manifest.json").read_bytes())

    def test_complete_final_evidence_reuse_does_not_mutate_or_retimestamp(self) -> None:
        output = self.candidate()
        original = {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()}
        calls = list(self.fixture.calls)
        self.assertEqual(self.fixture.invoke("candidate", "execute-store", attempt=7), 0)
        self.assertEqual(self.fixture.calls, calls)
        self.assertEqual(original, {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()})

    def test_prepare_rerun_reuses_sealed_intent_without_store_read_and_rejects_drift(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        calls = list(self.fixture.calls)
        self.assertEqual(self.fixture.invoke("candidate", "prepare-operation", attempt=2), 0)
        self.assertEqual(self.fixture.calls, calls)
        self.fixture.report.write_text('{"changed":true}\n')
        with self.assertRaisesRegex(ValidationError, "artifacts do not match"):
            self.fixture.invoke("candidate", "prepare-operation", attempt=2)
        self.assertEqual(self.fixture.calls, calls)

    def test_external_source_must_be_the_exact_candidate_before_preparation_or_reuse(self) -> None:
        self.candidate()
        for mode in ("prepare-operation", "execute-store"):
            if mode == "execute-store":
                self.fixture.invoke("external-testing", "prepare-operation")
            output = self.fixture.outputs["external-testing"]
            for changed in (replace(git_identity(), commit="e" * 40), replace(git_identity(), tree="e" * 40)):
                with self.subTest(mode=mode, source=changed):
                    before = directory_snapshot(output)
                    existed = output.exists()
                    calls = list(self.fixture.calls)
                    env = workflow_environment("external-testing", head=changed.commit)
                    with patch.dict(os.environ, env, clear=True), patch("mobile_release.cli.git_context", return_value=changed), self.assertRaisesRegex(ValidationError, "exact candidate source"):
                        _ci(build_parser().parse_args(self.fixture.command("external-testing", mode)))
                    self.assertEqual(before, directory_snapshot(output))
                    self.assertEqual(existed, output.exists())
                    self.assertEqual(calls, self.fixture.calls)

    def test_external_recovery_uses_original_source_not_new_dispatch_head(self) -> None:
        self.candidate()
        self.fixture.invoke("external-testing", "prepare-operation")
        intent = load_operation_intent(self.fixture.outputs["external-testing"] / "external-testing-operation-intent.json")
        args = build_parser().parse_args(self.fixture.command("external-testing", "execute-store"))
        args.recovery_run_id = intent["authorizedBy"]["runId"]
        env = workflow_environment("external-testing", run_id="900", head="e" * 40)
        with patch.dict(os.environ, env, clear=True), redirect_stdout(io.StringIO()):
            self.assertEqual(_ci(args), 0)
        receipt = load_release_receipt(self.fixture.outputs["external-testing"] / "external-testing-receipt.json")
        self.assertEqual(receipt["source"]["commit"], git_identity().commit)
        self.assertEqual(receipt["producedBy"]["headSha"], "e" * 40)

    def test_unsealed_precondition_is_preserved_but_recaptured_after_intent_write_failure(self) -> None:
        with patch("mobile_release.cli.write_evidence", side_effect=OSError("intent disk failure")), self.assertRaises(OSError):
            self.fixture.invoke("candidate", "prepare-operation")
        first = self.fixture.preconditions[0]
        original = first.read_bytes()
        self.assertEqual(self.fixture.mutations, [])
        self.assertEqual(self.fixture.invoke("candidate", "prepare-operation", attempt=2), 0)
        self.assertEqual(len(self.fixture.preconditions), 2)
        self.assertNotEqual(first, self.fixture.preconditions[-1])
        self.assertEqual(first.read_bytes(), original)
        self.assertEqual(self.fixture.mutations, [])

    def test_missing_or_wrong_document_intent_cannot_start_store_execution(self) -> None:
        with self.assertRaisesRegex(ValidationError, "authenticated --operation-intent"):
            self.fixture.invoke("candidate", "execute-store")
        self.assertEqual(self.fixture.calls, [])
        output = self.candidate()
        (output / "candidate-operation-intent.json").write_bytes((output / "candidate-manifest.json").read_bytes())
        calls = list(self.fixture.calls)
        with self.assertRaises(ValidationError):
            self.fixture.invoke("candidate", "execute-store", attempt=2)
        self.assertEqual(self.fixture.calls, calls)

    def test_malformed_existing_raw_never_triggers_a_replacement_mutation(self) -> None:
        self.fixture.invoke("candidate", "prepare-operation")
        output = self.fixture.outputs["candidate"]
        (output / "store-metadata.zip").unlink()
        path = output / "raw-store-receipt.json"
        for contents in ("{", "{}", '{"schemaVersion":2,"schemaVersion":2}'):
            with self.subTest(contents=contents):
                path.write_text(contents)
                calls = list(self.fixture.calls)
                before = directory_snapshot(output)
                with self.assertRaises(ValidationError):
                    self.fixture.invoke("candidate", "execute-store")
                self.assertEqual(self.fixture.calls, calls)
                self.assertEqual(path.read_text(), contents)
                self.assertEqual(before, directory_snapshot(output))
        self.assertEqual(self.fixture.mutations, [])

    def test_metadata_copy_interruption_leaves_no_final_path_and_retry_is_exact(self) -> None:
        source = self.fixture.root / "metadata-source.zip"
        destination = self.fixture.root / "copied.zip"
        source.write_bytes(b"original metadata" * 200)

        def interrupted(_source, target, **_kwargs):
            target.write(b"partial")
            raise KeyboardInterrupt()

        with patch("mobile_release.provenance.shutil.copyfileobj", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            copy_immutable_file(source, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(list(destination.parent.glob(f".{destination.name}.*")), [])
        copy_immutable_file(source, destination)
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        original = destination.read_bytes()
        source.write_bytes(b"different metadata")
        with self.assertRaisesRegex(ValidationError, "conflicts"):
            copy_immutable_file(source, destination)
        self.assertEqual(destination.read_bytes(), original)

    def test_status_supports_packaged_intent_but_rejects_ambiguous_alternatives(self) -> None:
        output = self.candidate()
        adjacent = output / "candidate-operation-intent.json"
        packaged = output / "operation" / adjacent.name
        packaged.parent.mkdir()
        original = adjacent.read_bytes()
        adjacent.rename(packaged)
        args = build_parser().parse_args(["status", "--config", str(self.fixture.config.path), "--candidate-manifest", str(output / "candidate-manifest.json"), "--receipt", str(output / "candidate-receipt.json"), "--format", "json"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(_status(args), 0)
        adjacent.write_bytes(original)
        with redirect_stdout(io.StringIO()) as text:
            self.assertNotEqual(_status(args), 0)
        self.assertIn("ambiguous", text.getvalue())


class IosOperationRecoveryTests(unittest.TestCase):
    """Exercise CLI ordering with explicit authentication/native boundary seams.

    Cryptographic and GitHub verification are tested in their own executable
    boundary suites; these fixtures never pretend their IPA is Apple signed.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = load_config(write_project(self.root, ios_config(), platform="ios"))
        self.documents = build_lifecycle(self.config, platform="ios")
        self.output = self.root / ".mobile-release" / "candidate"
        self.intent_path = self.output / "candidate-operation-intent.json"
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("mobile_release.cli.git_context", "mobile_release.discovery.git_context", "mobile_release.preflight.git_context"):
            self.stack.enter_context(patch(name, return_value=git_identity()))
        self.stack.enter_context(patch(
            "mobile_release.preflight._xcode_toolchain_finding",
            return_value=Finding("ios.xcode-toolchain", Status.PASS, "Synthetic toolchain seam, not an Xcode verification"),
        ))

    def invoke(self, mode: str, *, attempt: int = 1) -> int:
        argv = ["ci", "candidate", "--config", str(self.config.path), "--platform", "ios", "--confirm", "candidate:ios:1.2.3:42", "--output-dir", str(self.output), f"--{mode}", "--artifact", f"ios-ipa={self.root / 'app.ipa'}", "--artifact", f"validation-report={self.root / 'validation-report.json'}"]
        argv.extend(["--artifact", f"ios-archive={self.root / 'archive.zip'}", "--artifact", f"ios-dsyms={self.root / 'dsyms.zip'}"])
        with patch.dict(os.environ, workflow_environment(attempt=attempt), clear=True), redirect_stdout(io.StringIO()):
            return _ci(build_parser().parse_args(argv))

    def test_recovery_requires_actual_intent_authentication_before_using_historical_signing(self) -> None:
        write_evidence(self.intent_path, self.documents["candidate_intent"])
        before = directory_snapshot(self.output)
        with patch("mobile_release.cli.authenticate_operation_intent", side_effect=ValidationError("missing original authenticated artifact")) as authenticate, patch("mobile_release.cli.validate_ipa_current_signing", side_effect=AssertionError("native validation cannot replace intent authenticity")), patch("mobile_release.cli.ipa_signing_evidence", side_effect=AssertionError("historical evidence was read before authentication")), patch("mobile_release.cli.execute_store_operation") as store:
            with self.assertRaisesRegex(ValidationError, "authenticated artifact"):
                self.invoke("execute-store", attempt=2)
        authenticate.assert_called_once_with(self.intent_path.resolve(), stage="candidate", platform="ios")
        store.assert_not_called()
        self.assertEqual(before, directory_snapshot(self.output))

    def test_real_ungranted_entitlement_stops_fresh_intent_before_store_read_or_mutation(self) -> None:
        modernize_ipa_fixture(self.root / "app.ipa")
        native = NativeProfileSeam()
        native.claims["Reader.app"] = {**signed_entitlements(), "com.apple.developer.associated-domains": ["applinks:fictional.example"]}
        with patch("mobile_release.ios.sys.platform", "darwin"), patch("mobile_release.ios.shutil.which", return_value="/fictional/tool"), patch("mobile_release.ios.subprocess.run", side_effect=native), patch("mobile_release.cli.prepare_store_operation") as prepare, patch("mobile_release.cli.execute_store_operation") as mutate:
            with self.assertRaisesRegex(ValidationError, "final candidate artifact validation failed"):
                self.invoke("prepare-operation")
        prepare.assert_not_called()
        mutate.assert_not_called()
        self.assertFalse(self.intent_path.exists())
        self.assertTrue(any("--entitlements" in argv for argv, _ in native.calls))

    def test_malformed_generic_resource_plist_stops_fresh_intent_before_signing_or_store(self) -> None:
        resource = "Resources/Extra/Info.plist"
        for archive, ipa in ((b'<plist><dict><key>discarded</key><string>archive-only</string></dict><dict/></plist>',
                              b'<plist><dict/></plist>'),
                             (b'<plist><dict><key>x</key><data>Y&#81;==</data></dict></plist>',
                              b'<plist><dict><key>x</key><data>YQ==</data></dict></plist>'),
                             (binary_dictionary(b"\x5f\x00\x01A"),
                              b'<plist><dict><key>x</key><string>A</string></dict></plist>')):
            rewrite_zip_members(self.root / "app.ipa", {f"Payload/Reader.app/{resource}": ipa})
            rewrite_zip_members(self.root / "archive.zip", {
                f"archive.xcarchive/Products/Applications/Reader.app/{resource}": archive,
            })
            with patch("mobile_release.cli.validate_ipa_current_signing", side_effect=AssertionError("correspondence must reject first")), patch("mobile_release.cli.prepare_store_operation") as prepare, patch("mobile_release.cli.execute_store_operation") as mutate:
                with self.assertRaisesRegex(ValidationError, "plist"):
                    self.invoke("prepare-operation")
            prepare.assert_not_called()
            mutate.assert_not_called()
            self.assertFalse(self.intent_path.exists())

    def test_authenticated_original_validation_allows_raw_completion_after_profile_expiry(self) -> None:
        intent = self.documents["candidate_intent"]
        write_evidence(self.intent_path, intent)
        original_raw = raw_receipt(intent)
        raw_path = self.output / "raw-store-receipt.json"
        raw_path.write_text(json.dumps(original_raw))
        original_bytes = raw_path.read_bytes()
        with patch("mobile_release.cli.authenticate_operation_intent", return_value=intent) as authenticate, patch("mobile_release.cli.validate_ipa_current_signing", side_effect=AssertionError("raw completion must not reinterpret expired signing")), patch("mobile_release.cli.ipa_signing_evidence", side_effect=AssertionError("raw completion must reuse original signer evidence")), patch("mobile_release.ios._utc_now", return_value=datetime(2030, 1, 1, tzinfo=timezone.utc)), patch("mobile_release.stores._run_store_lane", side_effect=AssertionError("raw completion must be Store-free")):
            self.assertEqual(self.invoke("execute-store", attempt=2), 0)
        authenticate.assert_called_once()
        manifest = json.loads((self.output / "candidate-manifest.json").read_text())
        self.assertEqual(manifest["signing"], intent["signing"])
        self.assertEqual(manifest["artifacts"], intent["artifacts"])
        self.assertEqual(manifest["producedBy"]["attempt"], 2)
        self.assertEqual(manifest["executedBy"]["attempt"], 1)
        self.assertEqual(raw_path.read_bytes(), original_bytes)

    def test_authenticated_signing_proof_cannot_authorize_changed_original_bytes(self) -> None:
        intent = self.documents["candidate_intent"]
        write_evidence(self.intent_path, intent)
        before = directory_snapshot(self.output)
        with zipfile.ZipFile(self.root / "app.ipa", "a") as archive:
            archive.writestr("Payload/Reader.app/substituted.txt", b"changed original IPA")
        with patch("mobile_release.cli.authenticate_operation_intent", return_value=intent), patch("mobile_release.cli.validate_ipa_current_signing", side_effect=AssertionError("must use the original, not bless a replacement")), patch("mobile_release.cli.execute_store_operation") as store, self.assertRaisesRegex(ValidationError, "artifacts do not match"):
            self.invoke("execute-store", attempt=2)
        store.assert_not_called()
        self.assertEqual(before, directory_snapshot(self.output))

    def test_fresh_preparation_server_time_must_be_inside_the_full_validated_interval(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        interval = SigningValidityInterval(start, start + timedelta(seconds=1))
        for observation in ("2025-12-31T23:59:59Z", "2026-01-01T00:00:01Z"):
            with self.subTest(observation=observation):
                precondition = ios_precondition(self.config)
                precondition["snapshot"]["serverObservedAt"] = observation
                with patch("mobile_release.cli.validate_ipa_current_signing", return_value=([], interval)), patch("mobile_release.cli.ipa_signing_evidence", return_value=self.documents["signing"]), patch("mobile_release.cli.prepare_store_operation", return_value=precondition), patch("mobile_release.cli.execute_store_operation") as store, self.assertRaises(ValidationError):
                    self.invoke("prepare-operation")
                store.assert_not_called()
                self.assertFalse(self.intent_path.exists())
        with patch("mobile_release.cli.validate_ipa_current_signing", return_value=([], interval)), patch("mobile_release.cli.ipa_signing_evidence", return_value=self.documents["signing"]), patch("mobile_release.cli.prepare_store_operation", return_value=ios_precondition(self.config)), patch("mobile_release.cli.authenticate_operation_intent", side_effect=AssertionError("fresh preparation does not consume historical validation")):
            self.assertEqual(self.invoke("prepare-operation"), 0)
        self.assertEqual(load_operation_intent(self.intent_path)["storePrecondition"]["snapshot"]["serverObservedAt"], "2026-01-01T00:00:00Z")

    @staticmethod
    def replace_member(path, name, contents):
        with zipfile.ZipFile(path) as archive:
            entries = {item.filename: archive.read(item) for item in archive.infolist()}
        entries[name] = contents
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in entries.items():
                archive.writestr(member, data)

    def test_fresh_preparation_rejects_each_substituted_artifact_before_store_or_native_signing(self):
        cases = (
            ("app.ipa", "Payload/Reader.app/Reader", native_image(code=b"substituted same UUID")),
            ("archive.zip", "archive.xcarchive/Products/Applications/Reader.app/Reader", native_image("unrelated")),
            ("dsyms.zip", "dsyms/Reader.dSYM/Contents/Resources/DWARF/Reader", native_image("unrelated", dsym=True)),
        )
        for filename, name, contents in cases:
            path = self.root / filename
            original = path.read_bytes()
            self.replace_member(path, name, contents)
            with self.subTest(filename=filename), patch("mobile_release.cli.prepare_store_operation") as prepare, patch("mobile_release.cli.execute_store_operation") as execute, patch("mobile_release.cli.validate_ipa_current_signing") as native:
                with self.assertRaises(ValidationError):
                    self.invoke("prepare-operation")
                prepare.assert_not_called()
                execute.assert_not_called()
                native.assert_not_called()
                self.assertFalse(self.intent_path.exists())
            path.write_bytes(original)

    def test_fresh_preparation_aba_never_validates_b_then_seals_a(self):
        ipa = self.root / "app.ipa"
        original = ipa.read_bytes()
        alternate = b"otherwise acceptable synthetic signature B"
        observed = []
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        interval = SigningValidityInterval(start, start + timedelta(days=1))

        def native(path, **_kwargs):
            ipa.write_bytes(alternate)
            try:
                observed.append(path.read_bytes())
                if observed[-1] == alternate:
                    return [], interval
                return [Finding("synthetic-signature-A", Status.FAIL, "A is not signed by the synthetic authorized signer")], None
            finally:
                ipa.write_bytes(original)

        with patch("mobile_release.cli.validate_ipa_current_signing", side_effect=native), patch("mobile_release.cli.ipa_signing_evidence", return_value=self.documents["signing"]), patch("mobile_release.cli.prepare_store_operation", return_value=ios_precondition(self.config)) as store:
            with self.assertRaisesRegex(ValidationError, "synthetic-signature-A"):
                self.invoke("prepare-operation")
        self.assertEqual(observed, [original])
        self.assertEqual(ipa.read_bytes(), original)
        store.assert_not_called()
        self.assertFalse(self.intent_path.exists())

    def test_mutation_during_preparation_read_cannot_be_sealed(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        interval = SigningValidityInterval(start, start + timedelta(days=1))

        def prepare(**_kwargs):
            path = self.root / "archive.zip"
            path.write_bytes(path.read_bytes() + b"changed during Store read")
            return ios_precondition(self.config)

        with patch("mobile_release.cli.validate_ipa_current_signing", return_value=([], interval)), patch("mobile_release.cli.ipa_signing_evidence", return_value=self.documents["signing"]), patch("mobile_release.cli.prepare_store_operation", side_effect=prepare), patch("mobile_release.cli.execute_store_operation") as execute:
            with self.assertRaisesRegex(ValidationError, "changed after snapshotting"):
                self.invoke("prepare-operation")
        self.assertFalse(self.intent_path.exists())
        execute.assert_not_called()

    def test_shared_deadline_prevents_next_authorization_boundary_and_cleans_snapshots(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        interval = SigningValidityInterval(start, start + timedelta(days=1))
        originals = {path: path.read_bytes() for path in self.root.glob("*.zip")}
        originals[self.root / "app.ipa"] = (self.root / "app.ipa").read_bytes()
        # Expire at actual work boundaries, not after a fragile count of clock reads.
        for phase in ("paired-inspection", "evidence-context", "intent-construction"):
            snapshots = []

            @contextmanager
            def capture_snapshot(paths):
                with ios_artifacts.snapshot_ios_artifacts(paths) as snapshot:
                    snapshots.append(snapshot)
                    yield snapshot

            with self.subTest(phase=phase), ExitStack() as stack:
                clock = stack.enter_context(patch("mobile_release.inspection.time.monotonic", return_value=0))
                stack.enter_context(patch("mobile_release.cli.snapshot_ios_artifacts", side_effect=capture_snapshot))
                native = stack.enter_context(patch("mobile_release.cli.validate_ipa_current_signing", return_value=([], interval)))
                stack.enter_context(patch("mobile_release.cli.ipa_signing_evidence", return_value=self.documents["signing"]))
                prepare = stack.enter_context(patch("mobile_release.cli.prepare_store_operation", return_value=ios_precondition(self.config)))
                execute = stack.enter_context(patch("mobile_release.cli.execute_store_operation"))
                publish = stack.enter_context(patch("mobile_release.cli.write_evidence", wraps=write_evidence))
                seam, real = {
                    "paired-inspection": ("mobile_release.ios_artifacts.inspect_macho", ios_artifacts.inspect_macho),
                    "evidence-context": ("mobile_release.cli.validate_evidence_context", cli.validate_evidence_context),
                    "intent-construction": ("mobile_release.cli.build_operation_intent", cli.build_operation_intent),
                }[phase]

                def expire(*args, **kwargs):
                    result = real(*args, **kwargs)
                    clock.return_value = MAX_INSPECTION_SECONDS
                    return result

                stack.enter_context(patch(seam, side_effect=expire))
                with self.assertRaisesRegex(ValidationError, "shared time bound"):
                    self.invoke("prepare-operation")
                if phase == "paired-inspection":
                    native.assert_not_called()
                else:
                    self.assertIs(native.call_args.kwargs["deadline"], snapshots[0].deadline)
                self.assertEqual(prepare.call_count, int(phase == "intent-construction"))
                execute.assert_not_called()
                publish.assert_not_called()
                self.assertFalse(self.intent_path.exists())
                self.assertEqual(len(snapshots), 1)
                self.assertFalse(snapshots[0].temporary.exists())
                self.assertEqual(originals, {path: path.read_bytes() for path in originals})

    def test_deadline_after_readback_preserves_precondition_and_retry_recaptures_same_candidate(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        interval = SigningValidityInterval(start, start + timedelta(days=3))
        paths, modes, sent_artifacts, snapshots = [], [], [], []
        real_intent = cli.build_operation_intent
        before = {path: path.read_bytes() for path in self.root.glob("*.zip")}
        before[self.root / "app.ipa"] = (self.root / "app.ipa").read_bytes()

        @contextmanager
        def capture_snapshot(inputs):
            with ios_artifacts.snapshot_ios_artifacts(inputs) as snapshot:
                snapshots.append(snapshot)
                yield snapshot

        def wire(command, **kwargs):
            environment = kwargs["env"]
            modes.append(environment["MOBILE_RELEASE_STORE_MODE"])
            self.assertEqual(modes[-1], "prepare", "a retry must not mutate the Store")
            path = Path(environment["MOBILE_RELEASE_STORE_RECEIPT_PATH"])
            paths.append(path)
            precondition = ios_precondition(self.config)
            precondition["snapshot"]["serverObservedAt"] = f"2026-01-0{len(paths)}T00:00:00Z"
            path.write_text(json.dumps(precondition))
            return subprocess.CompletedProcess(command, 0)

        with ExitStack() as stack:
            clock = stack.enter_context(patch("mobile_release.inspection.time.monotonic", return_value=0))
            stack.enter_context(patch("mobile_release.cli.snapshot_ios_artifacts", side_effect=capture_snapshot))
            stack.enter_context(patch("mobile_release.cli.validate_ipa_current_signing", return_value=([], interval)))
            stack.enter_context(patch("mobile_release.cli.ipa_signing_evidence", return_value=self.documents["signing"]))
            stack.enter_context(patch("mobile_release.stores._require_fastlane_bundle"))
            stack.enter_context(patch("mobile_release.stores.resolve_tooling_root", return_value=Path(__file__).resolve().parents[2]))
            stack.enter_context(patch("mobile_release.stores.subprocess.run", side_effect=wire))

            def expire_after_intent(**kwargs):
                intent = real_intent(**kwargs)
                sent_artifacts.append(intent["artifacts"])
                clock.return_value = MAX_INSPECTION_SECONDS
                return intent

            with patch("mobile_release.cli.build_operation_intent", side_effect=expire_after_intent), self.assertRaisesRegex(ValidationError, "shared time bound"):
                self.invoke("prepare-operation")
            self.assertFalse(self.intent_path.exists())
            self.assertEqual(len(paths), 1)
            first_readback = paths[0].read_bytes()
            # A new preparation owns a new budget but must read new Store state;
            # surviving unsealed readback is diagnostic, never authorization.
            self.assertEqual(self.invoke("prepare-operation", attempt=2), 0)
        intent = load_operation_intent(self.intent_path)
        self.assertEqual(intent["artifacts"], sent_artifacts[0])
        self.assertEqual(intent["storePrecondition"]["snapshot"]["serverObservedAt"], "2026-01-02T00:00:00Z")
        self.assertEqual(modes, ["prepare", "prepare"])
        self.assertNotEqual(paths[0], paths[1])
        self.assertEqual(paths[0].read_bytes(), first_readback)
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        self.assertEqual(len(snapshots), 2)
        self.assertIsNot(snapshots[0].deadline, snapshots[1].deadline)
        self.assertTrue(all(not snapshot.temporary.exists() for snapshot in snapshots))

    def test_accepted_signature_slack_cannot_change_after_authenticated_intent_sealing(self):
        import struct
        from mobile_release.macho import inspect_macho

        write_evidence(self.intent_path, self.documents["candidate_intent"])
        with zipfile.ZipFile(self.root / "app.ipa") as archive:
            binary = bytearray(archive.read("Payload/Reader.app/Reader"))
        image = self.root / "synthetic-native"
        image.write_bytes(binary)
        before = inspect_macho(image)
        position = 32
        for _ in range(struct.unpack_from("<I", binary, 16)[0]):
            command, size = struct.unpack_from("<II", binary, position)
            if command == 0x1D:
                offset, allocation = struct.unpack_from("<II", binary, position + 8)
            position += size
        envelope = struct.unpack_from(">I", binary, offset + 4)[0]
        self.assertLess(envelope, allocation)
        binary[offset + allocation - 1] = 1
        image.write_bytes(binary)
        self.assertEqual(before, inspect_macho(image))  # Signature-neutral equality is not artifact authenticity.
        self.replace_member(self.root / "app.ipa", "Payload/Reader.app/Reader", binary)
        with patch("mobile_release.cli.authenticate_operation_intent", return_value=self.documents["candidate_intent"]), patch("mobile_release.cli.execute_store_operation") as execute:
            with self.assertRaisesRegex(ValidationError, "artifacts do not match"):
                self.invoke("execute-store", attempt=2)
        execute.assert_not_called()

    def test_historical_recovery_checks_original_archive_and_detached_hashes(self):
        write_evidence(self.intent_path, self.documents["candidate_intent"])
        for name in ("archive.zip", "dsyms.zip"):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"replacement")
            with self.subTest(name=name), patch("mobile_release.cli.authenticate_operation_intent", return_value=self.documents["candidate_intent"]), patch("mobile_release.cli.validate_ipa_current_signing", side_effect=AssertionError("historical recovery must not reinterpret expiry")), patch("mobile_release.cli.execute_store_operation") as execute:
                with self.assertRaisesRegex(ValidationError, "artifacts do not match"):
                    self.invoke("execute-store", attempt=2)
                execute.assert_not_called()
            path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
