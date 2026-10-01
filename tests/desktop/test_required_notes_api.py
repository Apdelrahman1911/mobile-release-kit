"""Focused passive required-note contracts; no native/filesystem qualification.

All selected reads/resources are inert sentinels under IO traps. The one shipped
help check reads fixed package DATA only. No project, process or Store is used.
"""
from __future__ import annotations

import builtins
import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from mobile_release import _desktop_engine as engine
from mobile_release import required_notes as notes
from mobile_release.api import METHODS, ApiError, execute
from mobile_release.api import _required_notes as api
from mobile_release.api import _snapshot as snapshot
from mobile_release.config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES


def forbidden(*_args, **_kwargs):
    raise AssertionError("No selected-project, process or network IO is admitted")


@contextmanager
def no_io():
    with ExitStack() as stack:
        stack.enter_context(patch.object(builtins, "open", side_effect=forbidden))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "scandir", "listdir",
                     "mkdir", "rename", "replace", "unlink", "rmdir", "fsync", "system", "register_at_fork",
                     "pipe", "pipe2", "dup", "dup2", "fork", "posix_spawn", "execve", "waitpid", "kill"):
            stack.enter_context(patch.object(os, name, create=True, side_effect=forbidden))
        for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
            stack.enter_context(patch.object(Path, name, side_effect=forbidden))
        stack.enter_context(patch.object(subprocess, "Popen", side_effect=forbidden))
        stack.enter_context(patch.object(socket, "socket", side_effect=forbidden))
        yield


def config():
    return {
        "$schema": "https://never-contact.invalid/schema.json", "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified"},
        "metadata": {"root": "public/store", "androidLocales": ["en-US"], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [["./must-not-run"]], "androidArtifact": [], "iosArtifact": []},
    }


_PATHS = {
    "android-build": "public/store/android/en-US/changelogs/42.txt",
    "android-default": "public/store/android/en-US/changelogs/default.txt",
    "ios-beta-review": "public/store/review/ios-beta-notes.txt",
    "ios-app-review": "public/store/review/ios-notes.txt",
    "testflight-what-to-test": "public/store/testflight/what-to-test.txt",
}
_NORMAL_EVENTS = ["root-enter", "named-enter", "named-recheck", "named-close", "root-recheck", "root-close"]


def inputs(kind="android-build", *, note=b"Reviewed release notes\r\n", counterpart=None):
    context = {"kind": kind, "locale": "en-US"} if kind.startswith("android-") else {"kind": kind}
    values = {api.CONFIG_PATH: (json.dumps(config(), ensure_ascii=False, indent=2) + "\r\n").encode("utf-8"),
              _PATHS[kind]: note}
    if kind.startswith("android-"):
        values["release/version.properties"] = b"VERSION_NAME = '1.2.3'\r\nBUILD_NUMBER = 42\r\n# untouched comment\r\n"
        values[_PATHS["android-default" if kind == "android-build" else "android-build"]] = counterpart
    return values, {"root": "/inert-project", "context": context}


def digest(raw):
    return {"byteLength": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class Reads:
    def __init__(self, values):
        self.values, self.calls, self.events = values, [], []

    def read(self, path, *, limit, binary=False):
        self.calls.append((path, limit, binary))
        if binary is not True or path not in self.values:
            raise AssertionError("Only the exact selected binary reads are permitted")
        value = self.values[path]
        if isinstance(value, BaseException):
            raise value
        if value is not None and len(value) > limit:
            raise snapshot._ReadProblem("snapshot.file-size", "private-error-marker")
        return value


@contextmanager
def observation(values, *, named_error=None, root_note=None, named_close=False,
                root_close=False, root_settled=True):
    reader = Reads(values)

    @contextmanager
    def root_scope(_root, inventory):
        reader.events.append("root-enter")
        try:
            yield 400
            reader.events.append("root-recheck")
            if root_note is not None:
                inventory.note(root_note, "private-error-marker")
        finally:
            reader.events.append("root-close")
            if root_close:
                raise snapshot._DescriptorCleanupError("private-error-marker")
        inventory.root_settled = root_settled and root_note != "snapshot.changed"

    @contextmanager
    def named_scope(_descriptor, _inventory):
        reader.events.append("named-enter")
        try:
            yield reader
            reader.events.append("named-recheck")
            if named_error is not None:
                raise named_error
        finally:
            reader.events.append("named-close")
            if named_close:
                raise snapshot._DescriptorCleanupError("private-error-marker")

    with no_io(), patch.object(api, "required_notes_observation_available", return_value=True), \
            patch.object(snapshot, "_root_handles", side_effect=root_scope), \
            patch.object(snapshot, "_named_text_reads", side_effect=named_scope):
        yield reader


class RequiredNotesApiTests(unittest.TestCase):
    def refused(self, params, reason):
        with self.assertRaises(ApiError) as caught:
            execute("required.notes.observe", params)
        self.assertEqual(caught.exception.code, "required_notes_" + reason)
        self.assertEqual(caught.exception.message, api._ERRORS[reason])
        self.assertNotIn("private-error-marker", str(caught.exception))

    def test_pure_validation_reuses_all_five_policies_without_io_or_input_mutation(self):
        with no_io():
            for kind in notes.KINDS:
                context = {"kind": kind, "locale": "en-US"} if kind.startswith("android-") else {"kind": kind}
                supplied = {"context": context, "text": "Reviewed instructions\r\n"}
                before = copy.deepcopy(supplied)
                result = execute("required.notes.validate", supplied)
                self.assertEqual(result, notes.check_required_note(kind, supplied["text"].encode("utf-8")).wire())
                self.assertEqual(supplied, before)
                self.assertTrue(result["valid"])
            invalid = execute("required.notes.validate", {"context": {"kind": "android-build", "locale": "en-US"},
                                                         "text": "x" * 501})
            self.assertEqual(invalid["issues"][0]["code"], "notes.android-length")
            self.assertNotIn("text", invalid)

    def test_closed_params_and_platform_gate_precede_all_reads(self):
        _, good = inputs()
        invalid = [None, [], {}, {"root": None, "context": good["context"]},
                   {**good, "context": {"kind": "android-build"}},
                   {**good, "context": {"kind": "ios-app-review", "locale": "en-US"}},
                   {**good, "context": {"kind": "other"}}, {**good, "root": "\ud800"},
                   {**good, "root": "/" + "x" * api.MAX_OBSERVE_PARAMS_BYTES}]
        invalid += [{**good, key: None} for key in
                    ("path", "metadataRoot", "configPath", "build", "version", "baseline", "text", "includePrivate", "save")]
        with no_io(), patch.object(snapshot, "_root_handles", side_effect=forbidden):
            for params in invalid:
                self.refused(params, "invalid_params")
            for params in [None, {"context": good["context"]}, {"context": good["context"], "text": None},
                           {"context": good["context"], "text": "\ud800"},
                           {"context": good["context"], "text": "x" * 65538},
                           {"context": good["context"], "text": "valid", "root": "/inert-project"}]:
                with self.assertRaises(ApiError) as caught:
                    execute("required.notes.validate", params)
                self.assertEqual(caught.exception.code, "required_notes_invalid_params")
            with patch.object(sys, "platform", "win32"), patch.object(snapshot, "_WINDOWS_SNAPSHOT_QUALIFIED", True):
                self.refused(good, "unavailable")
                caps = {row["method"]: row["available"] for row in execute("capabilities", {})["methods"]}
                self.assertFalse(caps["required.notes.observe"])
                self.assertTrue(caps["required.notes.validate"])

    def test_all_fixed_routes_binary_baselines_and_private_original_preserve_bytes(self):
        raw = "Reviewed café\r\ninstructions🦊\r".encode("utf-8")
        for kind in notes.KINDS:
            values, params = inputs(kind, note=raw, counterpart=b"Counterpart never returned")
            with self.subTest(kind=kind), observation(values) as reader:
                result = execute("required.notes.observe", params)
                self.assertEqual(reader.events, _NORMAL_EVENTS)
            is_android = kind.startswith("android-")
            expected_calls = [(api.CONFIG_PATH, MAX_CONFIG_BYTES, True)]
            if is_android:
                expected_calls.append(("release/version.properties", MAX_VERSION_BYTES, True))
            expected_calls.append((_PATHS[kind], notes.editor_byte_limit(kind), True))
            if is_android:
                other = _PATHS["android-default" if kind == "android-build" else "android-build"]
                expected_calls.append((other, 2000, True))
            self.assertEqual(reader.calls, expected_calls)
            self.assertEqual(set(result), {"schemaVersion", "selection", "baseline", "original", "validation"})
            self.assertEqual(result["selection"], {
                "context": params["context"], "metadataRoot": "public/store", "destination": _PATHS[kind],
                "savedBuild": 42 if is_android else None,
                "effective": {"source": "exact", "valid": True} if is_android else None,
            })
            self.assertEqual(result["baseline"], {
                "config": digest(values[api.CONFIG_PATH]),
                "version": digest(values["release/version.properties"]) if is_android else None,
                "note": {"state": "present", **digest(raw)},
                "counterpart": {"state": "present", **digest(b"Counterpart never returned")} if is_android else None,
            })
            self.assertEqual(result["original"], {"state": "present", "text": raw.decode("utf-8")})
            self.assertTrue(result["validation"]["valid"])
            self.assertNotIn("Counterpart never returned", json.dumps(result))
            self.assertNotIn("untouched comment", json.dumps(result))
            self.assertNotIn("ownerGeneration", result)
            self.assertNotIn("projectId", result)

    def test_absence_is_not_invalid_or_unreadable_and_exact_presence_wins(self):
        cases = [
            ("android-build", None, b"Fallback", "default", True, False),
            ("android-build", b"", b"Fallback", "exact", False, False),
            ("android-default", b"Fallback", b"x" * 501, "exact", False, True),
            ("android-default", None, b"\xff", "exact", False, False),
            ("android-build", None, None, "missing", False, False),
        ]
        for kind, note, counterpart, source, valid, selected_valid in cases:
            values, params = inputs(kind, note=note, counterpart=counterpart)
            with self.subTest(kind=kind, source=source), observation(values):
                result = execute("required.notes.observe", params)
            self.assertEqual(result["selection"]["effective"], {"source": source, "valid": valid})
            self.assertEqual(result["validation"]["valid"], selected_valid)
            self.assertEqual(result["original"], {"state": "absent"} if note is None
                             else {"state": "present", "text": note.decode("utf-8")})
            self.assertEqual(result["baseline"]["note"]["state"], "absent" if note is None else "present")
        values, params = inputs(counterpart=OSError("private-error-marker"))
        with observation(values):
            self.refused(params, "unreadable")

    def test_ordinary_invalid_text_can_be_repaired_but_encoding_and_secret_are_never_returned(self):
        for note, code in [(b"x" * 501, "notes.android-length"), (b"TODO", "metadata.placeholder"), (b"\0", "notes.android-content")]:
            values, params = inputs(note=note)
            with observation(values):
                result = execute("required.notes.observe", params)
            self.assertEqual(result["original"]["text"], note.decode("utf-8"))
            self.assertEqual(result["validation"]["issues"][0]["code"], code)
        # Android reports length/NUL first: disclosure still runs the independent secret guard.
        for note, reason in [(b"private-error-marker\xff", "encoding"),
                             (b"x" * 501 + b" password=private-error-marker", "sensitive"),
                             (b"\0 password=private-error-marker", "sensitive"),
                             (b"x" * 2001, "limit")]:
            values, params = inputs(note=note)
            with observation(values) as reader:
                self.refused(params, reason)
            self.assertEqual(reader.events.count("named-close"), 1)
            self.assertEqual(reader.events.count("root-close"), 1)
            if reason != "limit":
                self.assertEqual(reader.events, _NORMAL_EVENTS)

        # A quoted raw value can meet the existing 8-character secret threshold
        # but fall below it after CRLF normalization. Earlier policy errors must
        # not hide that raw match for any kind; still finish both final rechecks.
        raw_secret = b'{"client_secret":"abc\r\ndef"}'
        for kind in notes.KINDS:
            for prefix in (b"", b"\0", b"x" * 501, b"TODO\n"):
                values, params = inputs(kind, note=prefix + raw_secret)
                with self.subTest(kind=kind, prefix=prefix[:8]), observation(values) as reader:
                    self.refused(params, "sensitive")
                self.assertEqual(reader.events, _NORMAL_EVENTS)

    def test_configuration_version_policy_refusals_finish_both_normal_rechecks(self):
        values, params = inputs()
        bad_config = config()
        bad_config["metadata"]["root"] = "release/private"
        disabled = config()
        disabled["android"] = {"enabled": False}
        cases = [
            ({api.CONFIG_PATH: None}, "config_missing"),
            ({api.CONFIG_PATH: b'{"private-error-marker":1}'}, "config_invalid"),
            ({api.CONFIG_PATH: b"\xff"}, "encoding"),
            ({api.CONFIG_PATH: b"password=private-error-marker"}, "sensitive"),
            ({api.CONFIG_PATH: json.dumps(bad_config).encode()}, "unsafe"),
            ({api.CONFIG_PATH: json.dumps(disabled).encode()}, "not_configured"),
            ({**values, "release/version.properties": None}, "version_missing"),
            ({**values, "release/version.properties": b"BUILD_NUMBER=0"}, "version_invalid"),
            ({**values, "release/version.properties": b"\xff"}, "encoding"),
            ({**values, "release/version.properties": b"password=private-error-marker"}, "sensitive"),
        ]
        for supplied, reason in cases:
            with self.subTest(reason=reason), observation(supplied) as reader:
                self.refused(params, reason)
            self.assertEqual(reader.events, _NORMAL_EVENTS)

    def test_final_recheck_and_close_failures_override_success_and_policy_refusal(self):
        valid, params = inputs()
        sensitive, _ = inputs(note=b'{"client_secret":"abc\r\ndef"}')
        for supplied in [valid, sensitive, {api.CONFIG_PATH: None}, {api.CONFIG_PATH: b"invalid"}]:
            for options, reason in [
                ({"root_note": "snapshot.changed"}, "changed"),
                ({"root_note": "snapshot.deadline"}, "limit"),
                ({"root_settled": False}, "changed"),
                ({"named_error": snapshot._ReadProblem("snapshot.changed", "private-error-marker")}, "changed"),
                ({"named_close": True}, "cleanup_unknown"),
                ({"root_close": True}, "cleanup_unknown"),
                ({"named_close": True, "root_close": True}, "cleanup_unknown"),
                ({"named_error": snapshot._ReadProblem("snapshot.changed", "private-error-marker"), "root_close": True}, "cleanup_unknown"),
            ]:
                with self.subTest(options=options), observation(supplied, **options) as reader:
                    self.refused(params, reason)
                self.assertEqual(reader.events.count("named-close"), 1)
                self.assertEqual(reader.events.count("root-close"), 1)

    def test_reader_failures_never_become_absence_or_reflect_details(self):
        failures = [(snapshot._ReadProblem(code, "private-error-marker"), reason) for code, reason in api._READ_REASONS.items()]
        failures += [(OSError("private-error-marker"), "unreadable"),
                     (ApiError("required_notes_unsafe", "private-error-marker"), "unsafe"),
                     (ApiError("required_notes_invented", "private-error-marker"), "unreadable")]
        for failure, reason in failures:
            values, params = inputs(counterpart=failure)
            with observation(values) as reader:
                self.refused(params, reason)
            self.assertEqual(reader.events.count("named-close"), 1)
            self.assertEqual(reader.events.count("root-close"), 1)

    def test_maximum_escaped_note_fits_unchanged_passive_transport_without_truncation(self):
        text = "\x01" * 65536
        values, params = inputs("testflight-what-to-test", note=text.encode())
        with observation(values):
            result = execute("required.notes.observe", params)
        self.assertEqual(result["original"]["text"], text)
        self.assertFalse(result["validation"]["valid"])
        raw = json.dumps({"protocol": 1, "id": "required-notes", "method": "required.notes.validate",
                          "params": {"context": params["context"], "text": text}}, separators=(",", ":")).encode() + b"\n"
        with no_io():
            request = engine.parse_request(raw)
            validation = execute(request.method, request.params)
            self.assertEqual(validation, result["validation"])
            response = engine.encode_response(engine.Request("required-notes", "required.notes.observe", params), result=result)
            self.assertLessEqual(len(response), api.MAX_RESULT_BYTES + 128)
            self.assertEqual(json.loads(response)["result"], result)
            self.assertEqual((engine.MAX_REQUEST_BYTES, engine.MAX_RESPONSE_BYTES), (1024 * 1024, 4 * 1024 * 1024))

    def test_passive_roster_does_not_enable_prepare_apply_import_or_native_routes(self):
        with no_io():
            self.assertEqual(engine.METHODS, frozenset(METHODS))
            for method in ("required.notes.observe", "required.notes.validate"):
                request = engine.parse_request((json.dumps({"protocol": 1, "id": "notes", "method": method,
                                                            "params": {}}) + "\n").encode())
                self.assertEqual(request.method, method)
            for method in ("required.notes.prepare", "required.notes.apply", "required.notes.save",
                           "required.notes.import", "required.notes.status", "required.notes.discard", "read_file"):
                self.assertNotIn(method, engine.METHODS)
                with self.assertRaises(ApiError):
                    execute(method, {})


class RequiredNotesHelpTests(unittest.TestCase):
    def test_shipped_closed_guide_and_catalogue_degrade_without_hiding_other_help(self):
        guide = api.required_notes_help()  # Fixed package DATA; no selected files.
        self.assertEqual(set(guide), {"schemaVersion", "fields", "actions"})
        self.assertEqual([row["id"] for row in guide["fields"]], list(notes.KINDS))
        self.assertEqual([row["audience"] for row in guide["fields"]],
                         ["public-play", "public-play", "apple-review", "apple-review", "testflight-testers"])
        self.assertEqual([row["id"] for row in guide["actions"]], ["load", "validate", "review", "save", "import", "discard"])
        self.assertEqual(execute("catalog", {})["requiredNotes"], guide)
        with patch.object(api, "required_notes_help", side_effect=ApiError("resource_unavailable", "fixed")):
            result = execute("catalog", {})
        self.assertIsNone(result["requiredNotes"])
        self.assertIsNotNone(result["metadataText"])
        self.assertTrue(result["fields"])
        for mutate in [lambda value: value.update(limits={}), lambda value: value["fields"].reverse(),
                       lambda value: value["actions"].reverse(), lambda value: value["fields"][0].update(audience="apple-review"),
                       lambda value: value["fields"][0].update(requiredness="optional"),
                       lambda value: value["actions"][0].update(label="x" * 2049),
                       lambda value: value["actions"][0].update(why="line\nbreak")]:
            changed = copy.deepcopy(guide)
            mutate(changed)
            with self.assertRaises(ValueError):
                api._guide(changed)

    def test_guide_parser_rejects_duplicates_bad_utf8_and_oversize_without_fallback(self):
        for raw in (b'{"schemaVersion":1,"schemaVersion":1,"fields":[],"actions":[]}',
                    b"\xff", b"x" * (64 * 1024 + 1), b"{}", b"[" * 2000):
            class Resource:
                def joinpath(self, *parts):
                    self.parts = parts
                    return self

                def open(self, mode):
                    if self.parts != ("data", "required-notes-help-v1.json") or mode != "rb":
                        raise AssertionError("Unexpected alternate guide read")
                    return io.BytesIO(raw)
            with no_io(), patch.object(api, "files", return_value=Resource()) as bundled:
                with self.assertRaises(ApiError) as caught:
                    api.required_notes_help()
                self.assertEqual(caught.exception.code, "resource_unavailable")
                self.assertEqual(caught.exception.message, api._GUIDE_ERROR)
                bundled.assert_called_once_with("mobile_release.api")


if __name__ == "__main__":
    unittest.main()
