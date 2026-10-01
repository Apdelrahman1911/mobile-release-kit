"""Pure required-notes regression SOURCE; no file/process/native qualification.

All inputs are synthetic DATA. Execution is a separate Root-owned safe gate.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from mobile_release import metadata
from mobile_release import required_notes as notes
from mobile_release.required_notes_contract import required_notes_routine_status
from mobile_release.errors import ValidationError


def config(root="release/store"):
    return {"schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified"},
        "metadata": {"root": root, "androidLocales": ["en-US", "fr-FR"], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []}}


def routine():
    return {"schemaVersion": 1, "domain": "required_notes", "projectId": "fixture-project",
        "windowGeneration": "a" * 32, "ownerGeneration": "b" * 32, "sessionId": "c" * 32,
        "planToken": "d" * 32, "revision": "e" * 32, "context": {"kind": "ios-beta-review"},
        "draftRevision": 1, "statusRevision": 3, "phase": "reviewing", "applySubmitted": False,
        "coreOutcome": None, "nativeReason": "none", "nativeFinality": "pending", "lateSettled": False}


class RequiredNotesSelectionTests(unittest.TestCase):
    def test_closed_kind_shape_never_accepts_paths_build_or_hidden_locale(self):
        for value in ({"kind": "ios-beta-review", "locale": "en-US"},
                      {"kind": "android-build", "locale": "en-US", "build": 88},
                      {"kind": "ios-app-review", "path": "other/private.txt"},
                      {"kind": "android-default", "locale": "../review"},
                      {"kind": "release_notes.txt"}):
            with self.subTest(value=value), self.assertRaises(notes.RequiredNotesInputError):
                notes.notes_context(value)

    def test_exact_build_and_default_derive_from_saved_version_bytes(self):
        version = b"VERSION_NAME=2.4.0\nBUILD_NUMBER=42\nUNRELATED=keep\n"
        for kind in ("android-build", "android-default"):
            configured = notes.notes_configuration(json.dumps(config()), {"kind": kind, "locale": "fr-FR"})
            selected = notes.required_note_selection(configured, version)
            self.assertEqual(selected.build, 42)
            self.assertEqual(selected.version_source, "release/version.properties")
            leaf = "42" if kind == "android-build" else "default"
            other = "default" if kind == "android-build" else "42"
            self.assertEqual(selected.paths, (f"release/store/android/fr-FR/changelogs/{leaf}.txt",))
            self.assertEqual(selected.counterpart_path, f"release/store/android/fr-FR/changelogs/{other}.txt")
            self.assertEqual(selected.editor_byte_limit, 2000)
            with self.assertRaises(notes.RequiredNotesInputError):
                notes.required_note_selection(configured, 42)

    def test_fixed_apple_destinations_do_not_need_a_fake_locale(self):
        for kind, relative in notes.IOS_PATHS.items():
            with self.subTest(kind=kind):
                selections = []
                for global_locale in ("en-US", "fr-FR"):
                    cfg = config()
                    cfg["metadata"]["iosLocales"] = [global_locale]
                    selected = notes.required_note_selection(
                        notes.notes_configuration(json.dumps(cfg), {"kind": kind}))
                    self.assertIsNone(selected.context.locale)
                    self.assertEqual(selected.path, "release/store/" + relative)
                    self.assertIsNone(selected.build)
                    self.assertIsNone(selected.counterpart_path)
                    self.assertIsNone(selected.version_source)
                    selections.append(selected)
                self.assertEqual(selections[0], selections[1])

    def test_disabled_unconfigured_private_roots_and_source_aliases_are_refused(self):
        for mutate, context in (
            (lambda c: c["ios"].update(enabled=False), {"kind": "ios-beta-review"}),
            (lambda c: None, {"kind": "android-build", "locale": "de-DE"}),
            (lambda c: c["metadata"].update(root="private/store"), {"kind": "ios-app-review"}),
            (lambda c: c["metadata"].update(root="review/store"), {"kind": "ios-app-review"}),
        ):
            cfg = config(); mutate(cfg)
            with self.assertRaises(notes.RequiredNotesInputError):
                notes.notes_configuration(json.dumps(cfg), context)
        cfg = config()
        cfg["metadata"]["iosLocales"] = []
        with self.assertRaises(notes.RequiredNotesInputError) as raised:
            notes.notes_configuration(json.dumps(cfg), {"kind": "ios-beta-review"})
        self.assertEqual(raised.exception.reason, "config_invalid")
        cfg = config()
        cfg["version"]["source"] = "release/store/android/en-US/changelogs/42.txt"
        prepared = notes.notes_configuration(json.dumps(cfg), {"kind": "android-build", "locale": "en-US"})
        with self.assertRaises(notes.RequiredNotesInputError):
            notes.required_note_selection(prepared, b"VERSION_NAME=2.4\nBUILD_NUMBER=42\n")
        self.assertNotIn("changelogs", metadata.REQUIRED_LOCALE_TEXT["android"])
        self.assertNotIn("ios-beta-notes.txt", metadata.REQUIRED_LOCALE_TEXT["ios"])

    def test_bad_saved_version_errors_do_not_echo_private_parser_input(self):
        selected = notes.notes_configuration(json.dumps(config()), {"kind": "android-build", "locale": "en-US"})
        marker = "internal-note-marker-not-for-diagnostics"
        with self.assertRaises(notes.RequiredNotesInputError) as raised:
            notes.required_note_selection(selected, f"VERSION_NAME={marker}\nBUILD_NUMBER=42\n".encode())
        self.assertNotIn(marker, str(raised.exception))
        self.assertEqual(raised.exception.reason, "version_invalid")


class RequiredNotesPolicyTests(unittest.TestCase):
    def test_android_policy_uses_existing_authority_and_keeps_raw_whitespace(self):
        cases = ["a" * 500, "a" * 501, "😀" * 500, "😀" * 501, "a" * 498 + "\r\n",
                 "a" * 499 + "\r\n", " \t\n", "Release\x00note", "TODO details", "password=abcdefgh"]
        for text in cases:
            with self.subTest(length=len(text)):
                try:
                    accepted = metadata.validate_android_release_note(text)
                    expected = True
                    self.assertEqual(accepted, text)
                except ValidationError:
                    expected = False
                raw = text.encode("utf-8")
                with patch.object(notes, "validate_android_release_note", wraps=metadata.validate_android_release_note) as authority:
                    checked = notes.check_required_note("android-build", raw)
                    self.assertEqual(checked.valid, expected)
                    self.assertEqual(checked.character_limit, 500)
                    if len(raw) <= 2000:
                        authority.assert_called_once_with(text)
                self.assertEqual(raw, text.encode("utf-8"))

    def test_presence_alone_selects_exact_even_empty_invalid_utf8_or_placeholder(self):
        for exact in (b"", b"\xff", b"TODO", b"a" * 501):
            effective = notes.effective_android_note(exact, b"Reviewed fallback.")
            self.assertEqual(effective.source, "exact")
            self.assertFalse(effective.check.valid)
        self.assertEqual(notes.effective_android_note(None, b"Reviewed fallback.").source, "default")
        self.assertFalse(notes.effective_android_note(None, None).check.valid)
        # A nonregular/read-error sentinel cannot be converted to absence.
        with self.assertRaises(notes.RequiredNotesInputError):
            notes.effective_android_note(object(), b"Reviewed fallback.")

    def test_review_cap_is_not_an_invented_provider_character_limit(self):
        for kind in ("ios-beta-review", "ios-app-review"):
            result = notes.check_required_note(kind, b"a" * 32768)
            self.assertTrue(result.valid)
            self.assertIsNone(result.character_limit)
            self.assertEqual(result.editor_byte_limit, 32768)
            self.assertEqual(notes.check_required_note(kind, b"a" * 32769).issues, ("notes.editor-byte-limit",))

    def test_testflight_matches_both_current_preflight_and_raw_fastlane_bounds(self):
        self.assertTrue(notes.check_required_note("testflight-what-to-test", b"a" * 4000).valid)
        over = notes.check_required_note("testflight-what-to-test", b"a" * 4001)
        self.assertIn("metadata.length", over.issues)
        self.assertIn("notes.testflight-length", over.issues)
        # Generic preflight removes trailing newline characters for its count;
        # Fastlane hashes the entire bounded original. Never truncate on Save.
        maximum = b"a" * 4000 + b"\n" * (65536 - 4000)
        accepted = notes.check_required_note("testflight-what-to-test", maximum)
        self.assertTrue(accepted.valid)
        self.assertEqual(accepted.raw_byte_count, 65536)
        self.assertEqual(accepted.outbound_character_count, 4000)
        self.assertEqual(notes.check_required_note("testflight-what-to-test", maximum + b"\n").issues, ("notes.editor-byte-limit",))

    def test_ruby_strip_is_not_python_unicode_strip_and_bytes_are_not_returned(self):
        text = "\u0085" + "a" * 3999
        result = notes.check_required_note("testflight-what-to-test", text.encode("utf-8"))
        self.assertTrue(result.valid)
        self.assertEqual(len(text.strip()), 3999)
        self.assertEqual(result.outbound_character_count, 4000)
        private_text = b"Use the synthetic fixture screen before completing review."
        wire = notes.check_required_note("ios-beta-review", private_text).wire()
        self.assertNotIn(private_text.decode(), json.dumps(wire))
        self.assertNotIn("sha256", wire)

    def test_direct_validator_rejects_unknown_shape_and_preserves_closed_diagnostics(self):
        for extra in ("path", "root", "build"):
            with self.assertRaises(notes.RequiredNotesInputError):
                notes.validate_required_note_input({"context": {"kind": "ios-beta-review"}, "text": "Instructions", extra: "untrusted"})
        result = notes.validate_required_note_input({"context": {"kind": "ios-beta-review"}, "text": "password=abcdefgh"})
        self.assertFalse(result["valid"])
        self.assertIn("metadata.secret-pattern", [row["code"] for row in result["issues"]])
        self.assertNotIn("abcdefgh", json.dumps(result))
        # Raw CRLF keeps an eight-character quoted value that the generic
        # normalized view reduces below its detector threshold. Import admission
        # must refuse it even when a length/NUL/placeholder policy failure wins.
        threshold = '{"client_secret":"abc\r\ndef"}'
        self.assertFalse(any(code == "metadata.secret-pattern" for code, _ in
                             notes.check_metadata_text("required-note", threshold).issues))
        for kind in notes.KINDS:
            context = {"kind": kind}
            if kind.startswith("android-"):
                context["locale"] = "en-US"
            over_editor_cap = "x" * (notes.editor_byte_limit(kind) + 1 - len(threshold)) + threshold
            for text in (threshold, "x" * 501 + threshold, "\x00" + threshold,
                         "TODO " + threshold, over_editor_cap, "password=abcdefgh"):
                with self.subTest(kind=kind, size=len(text)):
                    policy = notes.check_required_note(kind, text.encode()).wire()
                    expected = dict(policy, valid=False, state="invalid")
                    expected["issues"] = list(policy["issues"])
                    if not any(row["code"] == "metadata.secret-pattern" for row in expected["issues"]):
                        expected["issues"].append({
                            "code": "metadata.secret-pattern",
                            "message": notes.ISSUE_MESSAGES["metadata.secret-pattern"]})
                    checked = notes.validate_required_note_input({"context": context, "text": text})
                    self.assertEqual(checked, expected)  # Includes all original counts/limits and issue ordering.
                    self.assertEqual(sum(row["code"] == "metadata.secret-pattern" for row in checked["issues"]), 1)
                    self.assertNotIn("client_secret", json.dumps(checked))
                    self.assertNotIn("abcdefgh", json.dumps(checked))
            benign = {"context": context, "text": "Reviewed release instructions.\r\n"}
            unchanged = notes.check_required_note(kind, benign["text"].encode()).wire()
            self.assertTrue(unchanged["valid"])
            self.assertEqual(notes.validate_required_note_input(benign), unchanged)
            self.assertEqual(benign["text"], "Reviewed release instructions.\r\n")


class RequiredNotesRoutinePrivacyTests(unittest.TestCase):
    def test_pre_emission_routine_contract_rejects_private_views_text_and_digests(self):
        original = routine()
        accepted = required_notes_routine_status(original)
        self.assertEqual(accepted, original)
        self.assertIsNot(accepted, original)
        for field in ("text", "baseline", "before", "after", "prepared", "sha256", "validation", "path"):
            value = routine(); value[field] = "synthetic-private-marker"
            with self.subTest(field=field), self.assertRaises(notes.RequiredNotesInputError):
                required_notes_routine_status(value)
        accepted["context"]["kind"] = "ios-app-review"
        self.assertEqual(original["context"]["kind"], "ios-beta-review")

    def test_bool_fake_enums_and_early_finality_cannot_escape_closed_contract(self):
        class EqualToEverything:
            def __eq__(self, _other):
                return True
        for key, value in (("schemaVersion", True), ("nativeFinality", EqualToEverything()),
                           ("phase", "final"), ("draftRevision", True)):
            candidate = routine(); candidate[key] = value
            with self.assertRaises(notes.RequiredNotesInputError):
                required_notes_routine_status(candidate)
        candidate = routine()
        candidate.update(phase="final", nativeFinality="settled", applySubmitted=True,
            coreOutcome={"effect": "committed", "journal": "clean", "resources": "settled", "reason": "none"})
        self.assertEqual(required_notes_routine_status(candidate)["coreOutcome"]["effect"], "committed")
        candidate["coreOutcome"]["reason"] = "synthetic-private-marker"
        with self.assertRaises(notes.RequiredNotesInputError):
            required_notes_routine_status(candidate)


if __name__ == "__main__":
    unittest.main()
