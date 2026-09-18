"""Finite pure/reader-seam SOURCE checks; not native filesystem qualification.

No selected project is opened. Reader descriptors/stat facts are inert sentinels
under OS traps. The one shipped guide check reads trusted package JSON only.
Execution and its exact command admission are separate from authoring this file.
"""
from __future__ import annotations

import builtins
import copy
import hashlib
import json
import os
import stat
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import _desktop_engine as engine
from mobile_release import metadata
from mobile_release import metadata_text as text
from mobile_release.api import ApiError, execute
from mobile_release.api import _metadata_text as api
from mobile_release.api import _snapshot as snapshot
from mobile_release.errors import ValidationError


def config(root="public/store"):
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified"},
        "metadata": {"root": root, "androidLocales": ["en-US", "fr-FR"], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def fields(platform="android", value="Approved public copy"):
    return [{"id": identity, "text": "https://public.invalid/policy" if identity.endswith("_url.txt") else value}
            for identity in metadata.REQUIRED_LOCALE_TEXT[platform]]


def forbidden(*_args, **_kwargs):
    raise AssertionError("no selected-project or native IO is admitted")


@contextmanager
def no_io():
    with ExitStack() as stack:
        stack.enter_context(patch.object(builtins, "open", side_effect=forbidden))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "listdir", "scandir", "fsync",
                     "mkdir", "rename", "replace", "unlink", "rmdir", "system", "urandom", "register_at_fork",
                     "pipe", "pipe2", "dup", "dup2", "fork", "posix_spawn", "execve", "waitpid", "kill"):
            stack.enter_context(patch.object(os, name, create=True, side_effect=forbidden))
        for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
            stack.enter_context(patch.object(Path, name, side_effect=forbidden))
        yield


class InertReads:
    def __init__(self, values, *, failure=None):
        self.values, self.failure = values, failure
        self.calls = []
        self.closed = 0

    def read(self, path, *, limit):
        self.calls.append((path, limit))
        if path not in self.values:
            raise AssertionError("not in the explicit public named-file fixture")
        result = self.values[path]
        if isinstance(result, BaseException):
            raise result
        return result

    @contextmanager
    def scope(self, *_args):
        try:
            yield self
            if self.failure is not None:
                raise self.failure
        finally:
            self.closed += 1


@contextmanager
def inert_observation(values, *, reader_failure=None, root_changed=False):
    reader = InertReads(values, failure=reader_failure)

    @contextmanager
    def root_scope(_root, inventory):
        yield 400
        if root_changed:
            inventory.note("snapshot.changed", "inert changed original ancestor")

    with no_io(), patch.object(api, "metadata_text_observation_available", return_value=True), \
            patch.object(snapshot, "_root_handles", side_effect=root_scope), \
            patch.object(snapshot, "_named_text_reads", side_effect=reader.scope):
        yield reader


def observation_values(platform="android"):
    raw = json.dumps(config(), ensure_ascii=False)
    selection = text.public_text_selection(raw, platform, "en-US")
    return {text.CONFIG_PATH: raw, **{path: None for path in selection.paths}}, selection


def stat_value(size=0, *, inode=10, directory=False, links=1, device=9, uid=1001, gid=1002):
    return SimpleNamespace(st_dev=device, st_ino=inode, st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | 0o644,
                           st_nlink=links, st_size=size, st_mtime_ns=100, st_ctime_ns=101, st_uid=uid, st_gid=gid)


class InertEntries:
    def __init__(self, names, *, close_error=False):
        self.names, self.close_error, self.closes = names, close_error, 0

    def __iter__(self):
        return iter(SimpleNamespace(name=name) for name in self.names)

    def close(self):
        self.closes += 1
        if self.close_error:
            raise OSError("inert close uncertainty")


class MetadataTextPolicyTests(unittest.TestCase):
    def test_unicode_generic_count_newline_view_and_exact_input_preservation(self):
        with no_io():
            for raw, count in [("a\r\nb\r", 3), ("x\n\n", 1), ("x\n ", 3), ("🦊", 1), ("e\u0301", 2)]:
                supplied = fields(value=raw)
                before = copy.deepcopy(supplied)
                result = execute("metadata.text.validate", {"platform": "android", "fields": supplied})
                self.assertTrue(result["valid"])
                self.assertEqual([row["characterCount"] for row in result["fields"]], [count] * 3)
                self.assertEqual(supplied, before)
            self.assertEqual(metadata.check_metadata_text("title.txt", "a" * 30 + "\r\n").issues, ())
            with self.assertRaises(ValidationError):
                metadata.validate_android_release_note("a" * 499 + "\r\n")
            original = "A reviewed note\r\n"
            self.assertEqual(metadata.validate_android_release_note(original), original)

    def test_limits_and_fixed_issue_triples_order_are_core_owned(self):
        with no_io():
            for platform in ("android", "ios"):
                for row in fields(platform):
                    identity = row["id"]
                    expected = metadata.MAX_STORE_URL_LENGTH if identity.endswith("_url.txt") else metadata.TEXT_LIMITS[identity]
                    result = api.validate_metadata_text({"platform": platform, "fields": fields(platform)})
                    self.assertEqual(next(item["limit"] for item in result["fields"] if item["id"] == identity), expected)
                    if not identity.endswith("_url.txt"):
                        self.assertFalse(metadata.check_metadata_text(identity, "é" * expected).issues)
                        self.assertEqual(metadata.check_metadata_text(identity, "é" * (expected + 1)).issues,
                                         (("metadata.length", metadata.Status.FAIL),))
            supplied = fields("ios")
            supplied[2]["text"] = "\x00 TODO password=private-fixture-marker " + "x" * 2048
            result = api.validate_metadata_text({"platform": "ios", "fields": supplied})
            self.assertFalse(result["valid"])
            self.assertEqual(result["state"], "invalid")
            issues = result["fields"][2]["issues"]
            self.assertEqual([item["code"] for item in issues],
                             ["metadata.nul", "metadata.placeholder", "metadata.secret-pattern", "metadata.url"])
            self.assertEqual([item["status"] for item in issues], ["INVALID", "FAIL", "FAIL", "INVALID"])
            self.assertEqual([item["message"] for item in issues], [api._MESSAGES[item["code"]] for item in issues])
            self.assertNotIn("private-fixture-marker", json.dumps(result))
            empty = api.validate_metadata_text({"platform": "android", "fields": fields(value=" \r\n")})
            self.assertEqual(empty["fields"][0]["issues"], [{"code": "metadata.empty-text", "status": "INVALID",
                                                          "message": api._MESSAGES["metadata.empty-text"]}])

    def test_url_rules_match_existing_policy_without_network_or_whitespace_repair(self):
        with no_io():
            for raw in ["https://public.invalid/support\r\n", "https://public.invalid:443/path"]:
                self.assertFalse(metadata.check_metadata_text("support_url.txt", raw).issues)
            for raw in ["http://public.invalid", " https://public.invalid", "https://public.invalid ",
                        "https://u:p@public.invalid", "https://public.invalid?q=x", "https://public.invalid/#x",
                        "https://public.invalid:bad", "https://public.invalid/\t", "https://[broken"]:
                with self.subTest(raw=raw):
                    self.assertIn(("metadata.url", metadata.Status.INVALID), metadata.check_metadata_text("support_url.txt", raw).issues)

    def test_closed_bundle_baseline_shape_byte_limits_and_non_disclosure(self):
        valid = fields()
        malformed = [None, {}, valid[:-1], list(reversed(valid)), valid + [valid[0]],
                     [{**valid[0], "path": "private"}, *valid[1:]],
                     [{"id": "title.txt", "text": "\ud800"}, *valid[1:]],
                     [{"id": "title.txt", "text": "🦊" * 8193}, *valid[1:]],
                     [{"id": "title.txt", "text": "x" * (text.MAX_TEXT_BYTES + 1)}, *valid[1:]]]
        with no_io():
            for value in malformed:
                with self.subTest(kind=type(value).__name__), self.assertRaises(ApiError) as caught:
                    execute("metadata.text.validate", {"platform": "android", "fields": value})
                self.assertEqual(caught.exception.code, "metadata_text_invalid_params")
                self.assertEqual(caught.exception.message, api._ERRORS["invalid_params"])
            for value in [{"platform": "android", "fields": valid, "root": "/not-input"},
                          {"platform": "other", "fields": valid}, {"platform": "android"}, []]:
                with self.assertRaises(ApiError):
                    execute("metadata.text.validate", value)
            checked = api.validate_metadata_text({"platform": "android", "fields": fields(value="x" * text.MAX_TEXT_BYTES)})
            self.assertFalse(checked["valid"])  # Maximum admitted bytes, not Store-valid length.
            baseline = text.baseline(b"{}", metadata.REQUIRED_LOCALE_TEXT["android"], (None, b"a", b""))
            self.assertEqual(text.admit_baseline("android", baseline), baseline)
            for alter in [lambda value: value["config"].update(byteLength=True),
                          lambda value: value["fields"][0].update(sha256="0" * 64),
                          lambda value: value["fields"][1].update(byteLength=text.MAX_TEXT_BYTES + 1),
                          lambda value: value["fields"][1].update(sha256="A" * 64),
                          lambda value: value["fields"].reverse()]:
                changed = copy.deepcopy(baseline)
                alter(changed)
                with self.assertRaises(text.MetadataTextInputError):
                    text.admit_baseline("android", changed)

    def test_original_cli_codes_status_messages_and_json_position_stay_unchanged(self):
        root = Path("/inert/store")
        selected = SimpleNamespace(section=lambda _name: {"root": "store"}, project_path=lambda _value: root,
                                   enabled_platforms=(), platform_enabled=lambda _platform: False)
        path = root / "broken.json"
        with no_io(), patch.object(Path, "is_dir", return_value=True), \
                patch.object(Path, "read_text", return_value="TODO\x00 password=private-fixture-marker"), \
                patch.object(metadata, "_safe_platform_files", return_value=[path]):
            results = metadata.metadata_findings(selected, platforms=())
        self.assertEqual([item.code for item in results],
                         ["metadata.nul", "metadata.placeholder", "metadata.secret-pattern", "metadata.json"])
        self.assertEqual([item.status for item in results[:3]], [metadata.Status.INVALID, metadata.Status.FAIL, metadata.Status.FAIL])
        self.assertEqual([item.message for item in results[:3]],
                         ["Metadata file contains NUL bytes: broken.json", "Unresolved placeholder in broken.json",
                          "Possible secret material in broken.json"])
        self.assertEqual(results[2].remediation, "Remove private credentials and rotate them if they were committed.")

    def test_target_selection_is_saved_config_bound_and_rejects_private_portable_paths(self):
        with no_io():
            selected = text.public_text_selection(json.dumps(config()), "android", "fr-FR")
            self.assertEqual(selected.paths, tuple(f"public/store/android/fr-FR/{identity}" for identity in selected.ids))
            for root in ["release/private", "secrets", "review", "testflight", ".git", "release/.hidden", "a/../b",
                         "public/con.txt", "public/COM0", "public/lpt9", "public/a*b", "public/a?b", "public/a|b",
                         "public/a\"b", "public/a<b", "public/e\u0301", "public/trailing.",
                         ".mobile-release-metadata-text-prepare", "release/mobile-release.json", "/".join(["a"] * 10)]:
                with self.subTest(root=root), self.assertRaises(text.MetadataTextInputError):
                    text.public_text_selection(json.dumps(config(root)), "android", "en-US")
            for platform, locale in [("android", "de-DE"), ("ios", "fr-FR"), ("review", "en-US"), ("android", "EN_us")]:
                with self.assertRaises(text.MetadataTextInputError):
                    text.public_text_selection(json.dumps(config()), platform, locale)


class MetadataTextObservationTests(unittest.TestCase):
    def test_observation_returns_only_selected_names_raw_bytes_and_detached_baseline(self):
        values, selection = observation_values()
        raw = "Approved\r\npublic🦊\r"
        values[selection.paths[0]] = raw
        with inert_observation(values) as reader:
            result = execute("metadata.text.observe", {"root": "/inert-project", "platform": "android", "locale": "en-US"})
        self.assertEqual(reader.calls, [(text.CONFIG_PATH, 512 * 1024), *[(path, text.MAX_TEXT_BYTES) for path in selection.paths]])
        self.assertEqual(reader.closed, 1)
        self.assertEqual(result["fields"][0]["text"], raw)
        self.assertEqual(result["fields"][0]["sha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(result["fields"][1], {"id": selection.ids[1], "path": selection.paths[1], "state": "absent"})
        self.assertEqual(result["baseline"], text.baseline(values[text.CONFIG_PATH].encode(), selection.ids,
                                                        (raw.encode(), None, None)))
        self.assertEqual(result["observationScope"], "single-request-non-atomic")
        self.assertNotIn("/inert-project", json.dumps(result))
        self.assertEqual(result["assurance"]["basis"], "static-text")
        self.assertFalse(result["assurance"]["credentialsRead"])
        self.assertFalse(result["assurance"]["writesPerformed"])

    def test_observation_is_all_or_error_after_read_failure_secret_or_changed_parent(self):
        for problem, reason in [(snapshot._ReadProblem("snapshot.encoding", "private-error-marker"), "encoding"),
                                (snapshot._ReadProblem("snapshot.file-size", "private-error-marker"), "limit"),
                                (snapshot._ReadProblem("snapshot.unsafe-file", "private-error-marker"), "unsafe"),
                                (snapshot._ReadProblem("snapshot.changed", "private-error-marker"), "changed"),
                                (OSError("private-error-marker"), "unreadable"),
                                ("password=private-error-marker", "sensitive")]:
            values, selection = observation_values()
            values[selection.paths[0]], values[selection.paths[-1]] = "public", problem
            with self.subTest(reason=reason), inert_observation(values) as reader:
                with self.assertRaises(ApiError) as caught:
                    api.observe_metadata_text({"root": "/inert-project", "platform": "android", "locale": "en-US"})
                self.assertEqual(caught.exception.code, "metadata_text_" + reason)
                self.assertEqual(caught.exception.message, api._ERRORS[reason])
                self.assertNotIn("private-error-marker", str(caught.exception))
                self.assertEqual(reader.closed, 1)
        for options, reason in [({"root_changed": True}, "changed"),
                                ({"reader_failure": snapshot._DescriptorCleanupError("private-error-marker")}, "cleanup_unknown")]:
            values, _ = observation_values()
            with inert_observation(values, **options), self.assertRaises(ApiError) as caught:
                api.observe_metadata_text({"root": "/inert-project", "platform": "android", "locale": "en-US"})
            self.assertEqual(caught.exception.code, "metadata_text_" + reason)

    def test_config_failures_no_raw_reflection_and_windows_no_fallback(self):
        for raw, reason in [(None, "config_missing"), ('{"private-error-marker":1}', "config_invalid"),
                            (json.dumps(config("release/private")), "unsafe")]:
            with inert_observation({text.CONFIG_PATH: raw}), self.assertRaises(ApiError) as caught:
                api.observe_metadata_text({"root": "/inert-project", "platform": "android", "locale": "en-US"})
            self.assertEqual(caught.exception.code, "metadata_text_" + reason)
            self.assertNotIn("private-error-marker", str(caught.exception))
        with no_io(), patch.object(api, "metadata_text_observation_available", return_value=False), \
                patch.object(snapshot, "_root_handles", side_effect=forbidden):
            with self.assertRaises(ApiError) as caught:
                api.observe_metadata_text({"root": "/inert-project", "platform": "android", "locale": "en-US"})
            self.assertEqual(caught.exception.code, "metadata_text_unavailable")
        for extra in ["metadataRoot", "path", "configPath", "fields", "revision", "includePrivate", "save"]:
            with no_io(), self.assertRaises(ApiError) as caught:
                api.observe_metadata_text({"root": "/inert-project", "platform": "android", "locale": "en-US", extra: None})
            self.assertEqual(caught.exception.code, "metadata_text_invalid_params")

    def test_named_read_bound_receipt_and_cleanup_are_original_not_reopened(self):
        raw = b"public\r\ntext"
        facts = stat_value(len(raw))
        receipts = []
        with no_io(), patch.object(os, "stat", return_value=facts), patch.object(os, "fstat", return_value=facts), \
                patch.object(os, "open", return_value=500) as opened, \
                patch.object(os, "read", side_effect=[raw, b""]) as read, patch.object(os, "close") as close:
            observed = snapshot._read_file(400, "title.txt", "public/title.txt", snapshot._Inventory(),
                                           limit=text.MAX_TEXT_BYTES, receipts=receipts)
            self.assertEqual(observed, raw.decode())
            self.assertEqual(receipts, [(400, "title.txt", snapshot._named_identity(facts))])
            opened.assert_called_once()
            self.assertEqual(read.call_args_list[0].args, (500, text.MAX_TEXT_BYTES + 1))
            close.assert_called_once_with(500)
        for bad in [stat_value(text.MAX_TEXT_BYTES + 1), stat_value(10, links=2), stat_value(10, directory=True)]:
            with no_io(), patch.object(os, "stat", return_value=bad), self.assertRaises(snapshot._ReadProblem):
                snapshot._read_file(400, "title.txt", "public/title.txt", snapshot._Inventory(), limit=text.MAX_TEXT_BYTES)

    def test_named_reader_retains_config_parent_and_absence_until_final_check(self):
        root, parent, file = stat_value(directory=True), stat_value(inode=20, directory=True), stat_value(2, inode=30)
        current_parent = parent
        current_file = file

        def named(name, **kwargs):
            if name == "release":
                return current_parent
            if current_file is None:
                raise FileNotFoundError()
            return current_file

        def read(parent_fd, name, relative, inventory, *, limit, receipts):
            receipts.append((parent_fd, name, snapshot._named_identity(file)))
            return "{}"

        with no_io(), patch.object(os, "fstat", side_effect=lambda fd: root if fd == 400 else parent), \
                patch.object(os, "stat", side_effect=named), patch.object(os, "open", return_value=500), \
                patch.object(os, "close") as close, patch.object(snapshot._NamedTextReads, "_alias"), \
                patch.object(snapshot, "_read_file", side_effect=read):
            with self.assertRaises(snapshot._ReadProblem):
                with snapshot._named_text_reads(400, snapshot._Inventory()) as reader:
                    self.assertEqual(reader.read(text.CONFIG_PATH, limit=512 * 1024), "{}")
                    current_parent = stat_value(inode=21, directory=True)
            close.assert_called_once_with(500)
            current_parent, current_file = parent, None
            reader = snapshot._NamedTextReads(400, snapshot._Inventory())
            self.assertIsNone(reader.read("title.txt", limit=text.MAX_TEXT_BYTES))
            current_file = file
            with self.assertRaises(snapshot._ReadProblem):
                reader.check()

    def test_named_reader_refuses_foreign_device_owner_special_mode_and_changed_group(self):
        root = stat_value(directory=True)
        for value in [stat_value(device=10), stat_value(uid=1002), stat_value(links=2),
                      stat_value(directory=True)]:
            with no_io(), patch.object(os, "fstat", return_value=root), patch.object(os, "stat", return_value=value), \
                    patch.object(snapshot._NamedTextReads, "_alias"), self.assertRaises(snapshot._ReadProblem) as caught:
                snapshot._NamedTextReads(400, snapshot._Inventory()).read("title.txt", limit=text.MAX_TEXT_BYTES)
            self.assertEqual(caught.exception.code, "snapshot.unsafe-file")
        special = stat_value()
        special.st_mode |= stat.S_ISUID
        with no_io(), patch.object(os, "fstat", return_value=root), patch.object(os, "stat", return_value=special), \
                patch.object(snapshot._NamedTextReads, "_alias"), self.assertRaises(snapshot._ReadProblem):
            snapshot._NamedTextReads(400, snapshot._Inventory()).read("title.txt", limit=text.MAX_TEXT_BYTES)
        with no_io(), patch.object(os, "fstat", return_value=root), \
                patch.object(os, "stat", return_value=stat_value(gid=1003)), patch.object(snapshot._NamedTextReads, "_alias"):
            reader = snapshot._NamedTextReads(400, snapshot._Inventory())
            reader.leaves.append((400, "title.txt", snapshot._named_identity(stat_value())))
            with self.assertRaises(snapshot._ReadProblem) as caught: reader.check()
            self.assertEqual(caught.exception.code, "snapshot.changed")

    def test_alias_inspection_is_bounded_and_never_reads_sibling_contents(self):
        with no_io(), patch.object(os, "fstat", return_value=stat_value(directory=True)), \
                patch.object(os, "scandir", return_value=InertEntries(["TITLE.txt"])):
            reader = snapshot._NamedTextReads(400, snapshot._Inventory())
            with self.assertRaises(snapshot._ReadProblem) as caught:
                reader._alias(400, "title.txt")
            self.assertEqual(caught.exception.code, "snapshot.unsafe-file")
        with no_io(), patch.object(os, "fstat", return_value=stat_value(directory=True)), \
                patch.object(os, "scandir", return_value=InertEntries(["unrelated"])):
            inventory = snapshot._Inventory()
            inventory.counts["entries"] = snapshot.MAX_ENTRIES
            with self.assertRaises(snapshot._ReadProblem) as caught:
                snapshot._NamedTextReads(400, inventory)._alias(400, "title.txt")
            self.assertEqual(caught.exception.code, "snapshot.entry-limit")
        entries = InertEntries([], close_error=True)
        with no_io(), patch.object(os, "fstat", return_value=stat_value(directory=True)), \
                patch.object(os, "scandir", return_value=entries):
            with self.assertRaises(snapshot._DescriptorCleanupError):
                snapshot._NamedTextReads(400, snapshot._Inventory())._alias(400, "title.txt")
        self.assertEqual(entries.closes, 1)


class MetadataTextGuideTests(unittest.TestCase):
    def test_shipped_guide_closed_layout_and_additive_catalogue(self):
        guide = api.metadata_text_help()  # Fixed trusted package JSON, not selected project IO.
        self.assertEqual(guide["limits"], {"maxTextBytes": 32768, "maxCachedLocales": 32, "maxCachedTextBytes": 8388608})
        self.assertEqual([(row["platform"], row["id"]) for row in guide["fields"]],
                         [(platform, identity) for platform, ids in metadata.REQUIRED_LOCALE_TEXT.items() for identity in ids])
        self.assertEqual([row["id"] for row in guide["actions"]], ["load", "validate", "review", "save", "discard"])
        self.assertEqual(execute("catalog", {})["metadataText"], guide)
        with patch.object(api, "metadata_text_help", side_effect=ApiError("resource_unavailable", "fixed")):
            result = execute("catalog", {})
        self.assertIsNone(result["metadataText"])
        self.assertEqual(result["metadata"]["requiredLocaleText"]["android"], list(metadata.REQUIRED_LOCALE_TEXT["android"]))
        for mutate in [lambda value: value.update(extra=True), lambda value: value["actions"].reverse(),
                       lambda value: value["fields"][0].update(requiredness="optional"),
                       lambda value: value["fields"][0].update(label="x" * 2049),
                       lambda value: value["limits"].update(maxTextBytes=True)]:
            changed = copy.deepcopy(guide)
            mutate(changed)
            with self.assertRaises(ValueError):
                api._guide(changed)

    def test_passive_engine_additions_do_not_admit_edit_or_native_routes(self):
        with no_io():
            self.assertIn("metadata.text.observe", engine.METHODS)
            self.assertIn("metadata.text.validate", engine.METHODS)
            for method in ["metadata.text.apply", "metadata.text.prepare", "metadata.text.save", "metadata.edit", "read_file"]:
                self.assertNotIn(method, engine.METHODS)
                with self.assertRaises(ApiError):
                    execute(method, {})


if __name__ == "__main__":
    unittest.main()
