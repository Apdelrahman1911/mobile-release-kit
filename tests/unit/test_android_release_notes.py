from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release.cli import _ci, _require_ci_policy, build_parser
from mobile_release.config import load_config
from mobile_release.errors import MobileReleaseError, ValidationError
from mobile_release.metadata import android_release_notes, metadata_findings, validate_android_release_note
from mobile_release.provenance import (
    build_operation_intent, canonical_json_bytes, seal, validate_operation_intent,
    validate_operation_intent_context, verify_sealed,
)
from mobile_release.reporting import FAILING_STATUSES

from .evidence_helpers import build_lifecycle, fixture_chain, git_identity, workflow_environment
from .helpers import android_config, ios_config, write_project

ROOT = Path(__file__).resolve().parents[2]
CORPUS = json.loads((ROOT / "tests/fixtures/android-release-notes-corpus.json").read_text())

try:
    import jsonschema
except ImportError:  # pragma: no cover - repository test extra installs the schema checker
    jsonschema = None


class AndroidReleaseNotesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-notes-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.config = load_config(write_project(self.root, android_config()))
        self.directory = self.root / "release/store/android/en-US/changelogs"
        self.default = self.directory / "default.txt"

    def assert_metadata_failure(self) -> None:
        findings = metadata_findings(self.config, platforms=("android",))
        self.assertTrue(any(item.status in FAILING_STATUSES for item in findings), findings)
        self.assertFalse(any(item.code == "metadata.valid" for item in findings))

    def test_shared_corpus_checks_text_reader_and_preflight_without_normalization(self) -> None:
        for group in ("valid", "invalid"):
            for case in CORPUS[group]:
                with self.subTest(group=group, case=case["name"]):
                    text = case["text"] * case.get("repeat", 1) + case.get("suffix", "")
                    self.default.write_bytes(text.encode("utf-8"))
                    if group == "valid":
                        self.assertEqual(text, validate_android_release_note(text))
                        self.assertEqual([{"language": "en-US", "text": text}], android_release_notes(self.config))
                        self.assertFalse(any(item.status in FAILING_STATUSES for item in metadata_findings(self.config)))
                    else:
                        with self.assertRaises(ValidationError):
                            validate_android_release_note(text)
                        with self.assertRaises(ValidationError):
                            android_release_notes(self.config)
                        self.assert_metadata_failure()
        for case in CORPUS["invalidUtf8"]:
            with self.subTest(case=case["name"]):
                self.default.write_bytes(bytes.fromhex(case["hex"]))
                with self.assertRaises(ValidationError):
                    android_release_notes(self.config)
                self.assert_metadata_failure()

    def test_missing_notes_fail_all_ci_stages_before_any_store_or_source_operation(self) -> None:
        self.default.unlink()
        self.assert_metadata_failure()
        for stage in ("candidate", "external-testing", "production-submit"):
            with self.subTest(stage=stage):
                with self.assertRaisesRegex(ValidationError, "metadata.android.*release-notes"):
                    _require_ci_policy(self.config, "android", stage)
                for mode in ("prepare-operation", "execute-store", "validate-operation-intent"):
                    args = build_parser().parse_args([
                        "ci", stage, "--config", str(self.config.path), "--platform", "android",
                        "--output-dir", str(self.root / ".mobile-release/output"),
                        "--confirm", f"{stage}:android:1.2.3:42", f"--{mode}",
                    ])
                    with patch("mobile_release.cli.git_context") as source, patch("mobile_release.cli.execute_store_operation") as store:
                        with self.assertRaisesRegex(ValidationError, "metadata.android.*release-notes"):
                            _ci(args)
                        source.assert_not_called()
                        store.assert_not_called()

    def test_exact_precedence_fallback_and_authoritative_build(self) -> None:
        exact = self.directory / "42.txt"
        exact.write_bytes(b"Exact copy\r\n")
        self.assertEqual("Exact copy\r\n", android_release_notes(self.config)[0]["text"])
        for text in ("", "TODO", "x" * 501):
            exact.write_text(text)
            with self.assertRaises(ValidationError):
                android_release_notes(self.config)
        exact.unlink()
        self.assertEqual("Reliability improvements.\n", android_release_notes(self.config)[0]["text"])
        (self.directory / "41.txt").write_text("Earlier build only")
        self.default.unlink()
        with self.assertRaises(ValidationError):
            android_release_notes(self.config)
        (self.root / "release/version.properties").write_text("VERSION_NAME=1.2.3\nBUILD_NUMBER=41\n")
        self.assertEqual("Earlier build only", android_release_notes(self.config)[0]["text"])

    def test_unused_stub_or_historical_invalid_notes_are_not_excused_by_valid_exact(self) -> None:
        (self.directory / "42.txt").write_text("Reviewed exact copy")
        self.default.write_text("")
        self.assertEqual("Reviewed exact copy", android_release_notes(self.config)[0]["text"])
        self.assert_metadata_failure()
        self.default.unlink()
        self.assertFalse(any(item.status in FAILING_STATUSES for item in metadata_findings(self.config)))
        (self.directory / "41.txt").write_text("x" * 501)
        self.assert_metadata_failure()

    def test_all_configured_locales_are_required_and_disabled_android_is_unaffected(self) -> None:
        locale = self.root / "release/store/android/fr-FR"
        shutil.copytree(self.directory.parent, locale)
        value = self.config.data
        value["metadata"]["androidLocales"].append("fr-FR")
        self.config.path.write_text(json.dumps(value))
        self.config = load_config(self.config.path)
        self.assertEqual(["en-US", "fr-FR"], [note["language"] for note in android_release_notes(self.config)])
        (locale / "changelogs/default.txt").unlink()
        with self.assertRaises(ValidationError):
            android_release_notes(self.config)
        self.assert_metadata_failure()
        with tempfile.TemporaryDirectory() as temporary:
            ios = load_config(write_project(Path(temporary), ios_config(), platform="ios"))
            self.assertFalse(any(item.status in FAILING_STATUSES for item in metadata_findings(ios)))

    def test_exact_symlink_directory_and_fifo_never_fall_back(self) -> None:
        exact = self.directory / "42.txt"
        for kind in ("in-root-link", "broken-link", "directory", "fifo"):
            with self.subTest(kind=kind):
                if kind == "in-root-link":
                    exact.symlink_to(self.default)
                elif kind == "broken-link":
                    exact.symlink_to(self.root / "absent.txt")
                elif kind == "directory":
                    exact.mkdir()
                else:
                    os.mkfifo(exact)
                try:
                    with self.assertRaises(MobileReleaseError):
                        android_release_notes(self.config)
                    self.assert_metadata_failure()
                finally:
                    exact.rmdir() if exact.is_dir() and not exact.is_symlink() else exact.unlink()

    def test_parent_symlinks_missing_version_and_read_failure_are_reported(self) -> None:
        moved = self.root / "saved-notes"
        self.directory.rename(moved)
        self.directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(MobileReleaseError):
            android_release_notes(self.config)
        self.assert_metadata_failure()
        self.directory.unlink()
        moved.rename(self.directory)
        with patch("mobile_release.metadata.os.open", side_effect=PermissionError("synthetic private error detail")):
            with self.assertRaises(ValidationError) as caught:
                android_release_notes(self.config)
            self.assertNotIn("private error detail", str(caught.exception))
        (self.root / "release/version.properties").unlink()
        findings = metadata_findings(self.config)
        self.assertTrue(any(item.code == "metadata.android.release-notes.version" for item in findings))

    def test_production_intent_creation_and_consumption_bind_locale_and_raw_copy(self) -> None:
        documents = build_lifecycle(self.config)
        original = documents["production_intent"]
        arguments = dict(
            config=self.config, release=self.config.release_version(), git=git_identity(),
            stage="production-submit", platform="android", confirmation="production-submit:android:1.2.3:42",
            metadata_sha256=documents["metadata_sha256"], candidate_manifest=documents["candidate"],
            candidate_receipt=documents["candidate_receipt"], external_receipt=documents["external_receipt"],
        )
        with patch.dict(os.environ, workflow_environment("production-submit"), clear=True):
            validate_operation_intent_context(original, **arguments)
            for notes in (
                [{"language": "fr-FR", "text": "Reliability improvements.\n"}],
                [{"language": "en-US", "text": "Different reviewed copy"}],
                [{"language": "en-US", "text": "Reliability improvements.\r\n"}],
            ):
                with self.subTest(notes=notes):
                    value = verify_sealed(copy.deepcopy(original))
                    snapshot = value["storePrecondition"]["snapshot"]
                    snapshot["targetRelease"]["releaseNotes"] = notes
                    snapshot["destinationTargetState"]["releases"][0]["releaseNotes"] = notes
                    changed = seal(value)
                    validate_operation_intent(changed)  # Structurally valid, wrong context.
                    with self.assertRaisesRegex(ValidationError, "configured locales/committed-build"):
                        validate_operation_intent_context(changed, **arguments)
                    with self.assertRaisesRegex(ValidationError, "configured locales/committed-build"):
                        build_operation_intent(store_precondition=value["storePrecondition"], **arguments)

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_new_production_target_rejects_bad_notes_but_accepts_unchanged_historical_notes(self) -> None:
        schema = json.loads((ROOT / "schemas/store-operation-intent.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema)
        original = fixture_chain()["production_intent"]
        for notes in (None, [], [{"language": "en-US", "text": ""}], [{"language": "en-US", "text": "\u0085\u001c"}], [{"language": "en-US", "text": "x" * 501}]):
            with self.subTest(notes=notes):
                changed = verify_sealed(copy.deepcopy(original))
                for release in (changed["storePrecondition"]["snapshot"]["targetRelease"], changed["storePrecondition"]["snapshot"]["destinationTargetState"]["releases"][0]):
                    if notes is None:
                        release.pop("releaseNotes")
                    else:
                        release["releaseNotes"] = notes
                changed = seal(changed)
                self.assertFalse(validator.is_valid(changed))
                with self.assertRaises(ValidationError):
                    validate_operation_intent(changed)
        changed = verify_sealed(copy.deepcopy(original))
        snapshot = changed["storePrecondition"]["snapshot"]
        history = [
            {"versionCodes": [str(code)], "status": "draft", "releaseNotes": [{"language": "en-US", "text": text}]}
            for code, text in ((40, ""), (41, "x" * 600))
        ]
        for state in (snapshot["destinationState"], snapshot["destinationTargetState"]):
            state["releases"] = sorted(state["releases"] + history, key=canonical_json_bytes)
        changed = seal(changed)
        validator.validate(changed)
        validate_operation_intent(changed)
