"""Focused pure/reader-seam checks, not native or Store qualification.

All selected-project reads below are inert maps or descriptor sentinels under IO
traps. Only the shipped image-policy DATA is loaded outside those traps. Root
runs these tests separately; authoring this source does not execute them.
"""
from __future__ import annotations
import builtins
import copy
import hashlib
import json
import os
import stat
import struct
import unittest
import zlib
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from mobile_release import metadata, metadata_images as images
from mobile_release.api import ApiError, execute
from mobile_release.api import _metadata_validation as api, _snapshot as snapshot


def config(root="public/store"):
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified"},
        "metadata": {"root": root, "androidLocales": ["fr-FR", "en-US"], "iosLocales": ["en-US", "fr-FR"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def forbidden(*_args, **_kwargs):
    raise AssertionError("No real selected-project IO or execution admitted")


@contextmanager
def no_io():
    with ExitStack() as stack:
        stack.enter_context(patch.object(builtins, "open", side_effect=forbidden))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "listdir", "scandir", "fsync",
                     "mkdir", "rename", "replace", "unlink", "rmdir", "system", "urandom", "pipe", "dup", "fork",
                     "posix_spawn", "execve", "waitpid", "kill"):
            stack.enter_context(patch.object(os, name, create=True, side_effect=forbidden))
        for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
            stack.enter_context(patch.object(Path, name, side_effect=forbidden))
        yield


def fixture(platform="android", data=None, policy=()):
    data = copy.deepcopy(data or config())
    root = data["metadata"]["root"]
    values = {api.CONFIG_PATH: json.dumps(data, ensure_ascii=False).encode()}
    names = {}
    if platform == "android":
        values["release/version.properties"] = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=42\n"
    for locale in data["metadata"][platform + "Locales"]:
        folder = f"{root}/{platform}/{locale}"
        names[folder] = (*metadata.REQUIRED_LOCALE_TEXT[platform], "unrelated", ".private", "ignored.bin")
        for identity in metadata.REQUIRED_LOCALE_TEXT[platform]:
            values[f"{folder}/{identity}"] = b"https://public.invalid/policy" if identity.endswith("_url.txt") else b"Saved public copy"
        if platform == "android":
            values[f"{folder}/changelogs/42.txt"] = b"Improved local editing.\n"
            values[f"{folder}/changelogs/default.txt"] = b"Fallback note.\n"
        for kind in policy:
            if kind.platform != platform:
                continue
            folder = (f"{root}/android/{locale}/images" + ("" if kind.singleton else "/" + kind.identity)
                      if platform == "android" else f"{root}/ios/screenshots/{locale}/{kind.identity}")
            names[folder] = None
    if platform == "ios":
        for name in api.IOS_NOTES:
            values[f"{root}/{name}"] = b"Inert fixed note."
    return values, names


class Reads:
    def __init__(self, values, names):
        self.values, self.names = values, names
        self.calls, self.directories = [], []
        self.post = self.closed = self.root_post = 0
        self.inventory = None

    def read(self, path, *, limit, binary=False):
        assert binary is True
        assert path in self.values, "Attempt outside the explicit selected file roster"
        self.calls.append((path, limit))
        value = self.values[path]
        if isinstance(value, BaseException):
            raise value
        if value is not None and len(value) > limit:
            raise snapshot._ReadProblem("snapshot.file-size", "inert-private-error")
        return value

    def metadata_names(self, path):
        assert path in self.names, "Attempt outside canonical selected directories"
        self.directories.append(path)
        return self.names[path]


@contextmanager
def observation(values, names, policy, *, post_error=None, root_changed=False):
    reader = Reads(values, names)

    @contextmanager
    def root_scope(_root, inventory):
        yield 400
        reader.root_post += 1
        if root_changed:
            inventory.note("snapshot.changed", "inert-private-error")
        else:
            inventory.root_settled = True

    @contextmanager
    def named_scope(_root, inventory):
        reader.inventory = inventory
        try:
            yield reader
            reader.post += 1
            if post_error:
                raise post_error
        finally:
            reader.closed += 1

    with no_io(), patch.object(api, "metadata_validation_available", return_value=True), \
            patch.object(snapshot, "_root_handles", side_effect=root_scope), \
            patch.object(snapshot, "_named_text_reads", side_effect=named_scope), \
            patch.object(api, "_types", return_value=policy), patch.object(images, "_types", return_value=policy):
        yield reader


def png_header(width=32, height=32):
    # Deliberately only an IHDR, not a decoded/complete PNG fixture.
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))


class SavedMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = images._types()  # trusted packaged DATA only

    def run_report(self, values, names, platform="android", **options):
        with observation(values, names, self.policy, **options) as reader:
            result = execute("metadata.validate", {"root": "/inert-project", "platform": platform})
        self.assertEqual((reader.post, reader.root_post, reader.closed), (1, 1, 1))
        return result, reader

    def test_every_locale_missing_one_is_not_green_and_other_trees_untouched(self):
        values, names = fixture(policy=self.policy)
        result, reader = self.run_report(values, names)
        self.assertTrue(result["valid"])
        self.assertEqual(result["locales"], ["en-US", "fr-FR"])
        self.assertEqual(len(result["files"]), 8)
        self.assertEqual(result["imageSets"], [])  # missing image slots are optional
        self.assertTrue(all("/android/" in path or path in (api.CONFIG_PATH, "release/version.properties") for path, _ in reader.calls))
        self.assertFalse(any("unrelated" in path or ".private" in path for path in reader.directories))
        values["public/store/android/fr-FR/full_description.txt"] = None
        result, _ = self.run_report(values, names)
        self.assertFalse(result["valid"])
        self.assertEqual(result["state"], "issues")
        missing = [row for row in result["files"] if row["state"] == "missing"]
        self.assertEqual([(row["locale"], row["id"], row["issues"]) for row in missing],
                         [("fr-FR", "full_description.txt", ["metadata.missing"])])

    def test_core_text_url_utf8_json_and_secret_rules_without_values(self):
        values, names = fixture("ios", policy=self.policy)
        values["public/store/ios/en-US/support_url.txt"] = b"https://public.invalid/support?private=x"
        values["public/store/ios/en-US/description.txt"] = b"TODO password=inert-private-marker"
        values["public/store/ios/fr-FR/keywords.txt"] = b"\xff"
        folder = "public/store/ios/fr-FR"
        names[folder] = (*names[folder], "extra.json")
        values[folder + "/extra.json"] = b'{"duplicate":1,"duplicate":2}'
        result, _ = self.run_report(values, names, "ios")
        by_path = {row["path"]: row for row in result["files"]}
        self.assertIn("metadata.url", by_path["public/store/ios/en-US/support_url.txt"]["issues"])
        self.assertIn("metadata.placeholder", by_path["public/store/ios/en-US/description.txt"]["issues"])
        self.assertIn("metadata.secret-pattern", by_path["public/store/ios/en-US/description.txt"]["issues"])
        self.assertEqual(by_path["public/store/ios/fr-FR/keywords.txt"]["issues"], ["metadata.utf8"])
        self.assertIn("metadata.json", by_path[folder + "/extra.json"]["issues"])
        self.assertFalse(by_path[folder + "/extra.json"]["required"])
        self.assertNotIn("inert-private-marker", json.dumps(result))
        self.assertNotIn("private=x", json.dumps(result))

    def test_fixed_ios_notes_have_no_text_hash_length_or_summary_and_no_private_siblings(self):
        values, names = fixture("ios", policy=self.policy)
        private = b"password=inert-private-marker"
        values["public/store/" + api.IOS_NOTES[0]] = private
        result, reader = self.run_report(values, names, "ios")
        notes = [row for row in result["files"] if row["kind"] == "ios-note"]
        self.assertEqual({row["path"] for row in notes}, {"public/store/" + name for name in api.IOS_NOTES})
        self.assertTrue(all(set(row) == {"kind", "id", "path", "locale", "required", "state", "issues"} for row in notes))
        self.assertEqual(notes[0]["issues"], ["metadata.secret-pattern"])
        self.assertNotIn(private.decode(), json.dumps(result))
        self.assertNotIn(hashlib.sha256(private).hexdigest(), json.dumps(result))
        self.assertIsNone(result["androidBuild"])
        self.assertNotIn("release/version.properties", [path for path, _ in reader.calls])
        self.assertTrue(all(not path.endswith(("contact.json", "demo-password.txt", "auth-key.p8")) for path, _ in reader.calls))

    def test_android_exact_build_invalid_never_falls_back_and_missing_version_is_explicit(self):
        values, names = fixture(policy=self.policy)
        exact = "public/store/android/en-US/changelogs/42.txt"
        default = "public/store/android/en-US/changelogs/default.txt"
        values[exact] = b"TODO"
        result, reader = self.run_report(values, names)
        note = next(row for row in result["files"] if row["path"] == exact)
        self.assertEqual(note["issues"], ["metadata.android-note"])
        self.assertNotIn(default, [path for path, _ in reader.calls])
        values[exact] = None
        result, reader = self.run_report(values, names)
        self.assertTrue(result["valid"])
        self.assertIn(default, [path for path, _ in reader.calls])
        values["release/version.properties"] = None
        result, reader = self.run_report(values, names)
        self.assertIsNone(result["androidBuild"])
        notes = [row for row in result["files"] if row["kind"] == "android-note"]
        self.assertEqual(len(notes), 2)
        self.assertTrue(all(row["path"] is None and row["issues"] == ["metadata.android-version"] for row in notes))
        self.assertFalse(any("/changelogs/" in path for path, _ in reader.calls))

    def test_android_changelog_admits_exact_and_fallback_bounds_before_any_read(self):
        # Nine metadata-root components fit ordinary text but not changelogs.
        # The second root leaves exact bytes in range but default.txt too long.
        roots = ["/".join(["segment"] * 9), "a" * 239 + "/" + "b" * 239]
        for root in roots:
            with self.subTest(rootComponents=len(root.split("/"))), no_io():
                reader = SimpleNamespace(read=forbidden)
                with self.assertRaises(api.MetadataTextInputError) as caught:
                    api._android_note(reader, root, "en-US", 42)
                self.assertEqual(caught.exception.reason, "unsafe")

    def test_images_use_complete_read_contract_header_not_pixels_and_core_counts(self):
        values, names = fixture(policy=self.policy)
        folder = "public/store/android/en-US/images/phoneScreenshots"
        names[folder] = tuple(f"shot{i}.png" for i in range(9))
        for index, name in enumerate(names[folder]):
            values[folder + "/" + name] = png_header(32 + index)
        result, reader = self.run_report(values, names)
        group = result["imageSets"][0]
        self.assertEqual(group["count"], 9)
        self.assertEqual(group["issues"], ["image.count"])
        image_rows = [row for row in result["files"] if row["kind"] == "image"]
        self.assertTrue(all(row["state"] == "checked" for row in image_rows))
        self.assertTrue(all(limit == images.MAX_IMAGE_BYTES for path, limit in reader.calls if path.endswith(".png")))
        values[folder + "/shot1.png"] = values[folder + "/shot0.png"]
        result, _ = self.run_report(values, names)
        self.assertIn("image.duplicate", result["imageSets"][0]["issues"])
        self.assertFalse(result["valid"])
        self.assertEqual(result["assurance"]["releaseReadiness"], "unknown")
        self.assertFalse(any(result["assurance"][key] for key in ("writesPerformed", "storeContacted", "projectCodeExecuted", "credentialsRead")))

    def test_singletons_request_each_canonical_spelling_and_ignore_other_type_siblings(self):
        values, names = fixture(policy=self.policy)
        folder = "public/store/android/en-US/images"
        names[folder] = ("icon.png", "unsafe-unrelated", "screenshots", ".private")
        for kind in ("icon", "featureGraphic", "tvBanner"):
            for ext in ("png", "jpg", "jpeg"):
                values[folder + "/" + kind + "." + ext] = png_header() if (kind, ext) == ("icon", "png") else None
        result, reader = self.run_report(values, names)
        self.assertTrue(result["valid"])
        self.assertEqual([(row["id"], row["count"]) for row in result["imageSets"]], [("icon", 1)])
        self.assertNotIn(folder + "/unsafe-unrelated", [path for path, _ in reader.calls])

    def test_closed_errors_limits_and_negative_outcomes_still_take_normal_post(self):
        for code, reason in [("snapshot.file-limit", "limit"), ("snapshot.byte-limit", "limit"), ("snapshot.entry-limit", "limit"),
                             ("snapshot.deadline", "limit"), ("snapshot.unsafe-file", "unsafe"), ("snapshot.changed", "changed")]:
            values, names = fixture(policy=self.policy)
            values["public/store/android/fr-FR/title.txt"] = snapshot._ReadProblem(code, "inert-private-error")
            with observation(values, names, self.policy) as reader, self.assertRaises(ApiError) as caught:
                api.validate_saved_metadata({"root": "/inert-project", "platform": "android"})
            self.assertEqual(caught.exception.code, "metadata_validation_" + reason)
            self.assertEqual(caught.exception.message, api._ERRORS[reason])
            self.assertEqual((reader.post, reader.root_post, reader.closed), (1, 1, 1))
        for knob in ("MAX_ROWS", "MAX_RESULT_BYTES"):
            values, names = fixture(policy=self.policy)
            with observation(values, names, self.policy) as reader, patch.object(api, knob, 1), self.assertRaises(ApiError) as caught:
                api.validate_saved_metadata({"root": "/inert-project", "platform": "android"})
            self.assertEqual(caught.exception.code, "metadata_validation_limit")
            self.assertEqual(reader.post, 1)
        for options, reason in [({"root_changed": True}, "changed"),
                                ({"post_error": snapshot._DescriptorCleanupError("inert-private-error")}, "cleanup_unknown")]:
            values, names = fixture(policy=self.policy)
            with observation(values, names, self.policy, **options), self.assertRaises(ApiError) as caught:
                api.validate_saved_metadata({"root": "/inert-project", "platform": "android"})
            self.assertEqual(caught.exception.code, "metadata_validation_" + reason)
            self.assertNotIn("inert-private-error", str(caught.exception))

    def test_configuration_and_platform_refusal_do_not_echo_or_fallback(self):
        for raw, reason in [(None, "config_missing"), (b'{"unexpected":1}', "config_invalid"),
                            (b"\xff", "encoding"), (b'{"note":"password=inert-private-marker"}', "sensitive")]:
            with observation({api.CONFIG_PATH: raw}, {}, self.policy) as reader, self.assertRaises(ApiError) as caught:
                api.validate_saved_metadata({"root": "/inert-project", "platform": "android"})
            self.assertEqual(caught.exception.code, "metadata_validation_" + reason)
            self.assertEqual(reader.post, 1)
        with no_io(), patch.object(snapshot, "posix_snapshot_available", return_value=False), \
                patch.object(snapshot, "windows_snapshot_available", return_value=True), self.assertRaises(ApiError) as caught:
            api.validate_saved_metadata({"root": "/inert-project", "platform": "android"})
        self.assertEqual(caught.exception.code, "metadata_validation_unavailable")
        for name in ("locale", "draft", "path", "metadataRoot", "includePrivate", "policy"):
            with no_io(), self.assertRaises(ApiError) as caught:
                api.validate_saved_metadata({"root": "/inert-project", "platform": "android", name: None})
            self.assertEqual(caught.exception.code, "metadata_validation_invalid_params")


def facts(*, inode=10, mode=stat.S_IFDIR | 0o700, links=1, size=0):
    return SimpleNamespace(st_dev=9, st_ino=inode, st_mode=mode, st_uid=1001, st_gid=1002,
                           st_nlink=links, st_size=size, st_mtime_ns=100, st_ctime_ns=101)


class Entries:
    def __init__(self, names, fail=False):
        self.names, self.fail, self.closed = names, fail, 0
    def __iter__(self):
        return iter(SimpleNamespace(name=name) for name in self.names)
    def close(self):
        self.closed += 1
        if self.fail:
            raise OSError("inert-private-close")


class MetadataDirectorySeamTests(unittest.TestCase):
    def test_names_never_stat_siblings_and_roster_change_refuses(self):
        root, child = facts(), facts(inode=11)
        roster = ["title.txt", "unrelated-private-dir", "ignored.bin"]
        opened, iterators = [], []
        def scan(_fd):
            value = Entries(list(roster)); iterators.append(value); return value
        with no_io(), patch.object(os, "fstat", side_effect=lambda fd: root if fd == 400 else child), \
                patch.object(os, "stat", return_value=child) as named, patch.object(os, "open", side_effect=lambda *_a, **_kw: opened.append(500) or 500), \
                patch.object(os, "close") as closed, patch.object(os, "scandir", side_effect=scan), \
                patch.object(snapshot._NamedTextReads, "_alias"), patch.object(snapshot, "_directory_flags", return_value=0):
            with self.assertRaises(snapshot._ReadProblem) as caught:
                with snapshot._named_text_reads(400, snapshot._Inventory()) as reader:
                    self.assertEqual(reader.metadata_names("public"), tuple(sorted(roster)))
                    self.assertEqual(reader.metadata_names("public"), tuple(sorted(roster)))
                    self.assertEqual(opened, [500])  # cached original, no second owner
                    roster.append("late.txt")
            self.assertEqual(caught.exception.code, "snapshot.changed")
            self.assertTrue(all(call.args == ("public",) and call.kwargs["follow_symlinks"] is False for call in named.call_args_list))
            closed.assert_called_once_with(500)
        self.assertTrue(all(iterator.closed == 1 for iterator in iterators))

    def test_alias_symlink_absence_and_replacement_are_not_reported_as_complete(self):
        with no_io(), patch.object(os, "fstat", return_value=facts()), patch.object(os, "scandir", return_value=Entries(["PUBLIC"])):
            with self.assertRaises(snapshot._ReadProblem) as caught:
                snapshot._NamedTextReads(400, snapshot._Inventory()).metadata_names("public")
            self.assertEqual(caught.exception.code, "snapshot.unsafe-file")
        for bad in (facts(mode=stat.S_IFLNK | 0o777), facts(mode=stat.S_IFREG | 0o600, links=2)):
            with no_io(), patch.object(os, "fstat", return_value=facts()), patch.object(os, "stat", return_value=bad), \
                    patch.object(snapshot._NamedTextReads, "_alias"), self.assertRaises(snapshot._ReadProblem):
                snapshot._NamedTextReads(400, snapshot._Inventory()).metadata_names("public")
        current = None
        def named(*_args, **_kwargs):
            if current is None:
                raise FileNotFoundError()
            return current
        with no_io(), patch.object(os, "fstat", return_value=facts()), patch.object(os, "stat", side_effect=named), \
                patch.object(snapshot._NamedTextReads, "_alias"):
            reader = snapshot._NamedTextReads(400, snapshot._Inventory())
            self.assertIsNone(reader.metadata_names("public"))
            current = facts(inode=99)
            with self.assertRaises(snapshot._ReadProblem):
                reader.check()

    def test_original_named_reader_refuses_file_hardlinks_before_open(self):
        linked = facts(mode=stat.S_IFREG | 0o600, links=2, size=10)
        with no_io(), patch.object(os, "fstat", return_value=facts()), \
                patch.object(os, "stat", return_value=linked), patch.object(snapshot._NamedTextReads, "_alias"):
            with self.assertRaises(snapshot._ReadProblem) as caught:
                snapshot._NamedTextReads(400, snapshot._Inventory()).read(
                    "title.txt", limit=api.MAX_TEXT_BYTES, binary=True)
            self.assertEqual(caught.exception.code, "snapshot.unsafe-file")

    def test_original_binary_reader_preserves_file_byte_and_per_file_bounds(self):
        for exhausted, expected in [("files", "snapshot.file-limit"), ("bytes", "snapshot.byte-limit"),
                                    ("size", "snapshot.file-size")]:
            inventory = snapshot._Inventory()
            if exhausted == "files":
                inventory.counts["sourceFiles"] = snapshot.MAX_SOURCE_FILES
            if exhausted == "bytes":
                inventory.counts["sourceBytes"] = snapshot.MAX_TOTAL_BYTES
            value = facts(mode=stat.S_IFREG | 0o600, size=api.MAX_TEXT_BYTES + 1 if exhausted == "size" else 10)
            with no_io(), patch.object(os, "stat", return_value=value), self.assertRaises(snapshot._ReadProblem) as caught:
                snapshot._read_file(400, "title.txt", "public/title.txt", inventory, limit=api.MAX_TEXT_BYTES, binary=True)
            self.assertEqual(caught.exception.code, expected)

    def test_entry_deadline_and_consuming_close_failures_are_bounded(self):
        for exhausted in ("entries", "deadline", "close"):
            iterator = Entries(["unrelated"], fail=exhausted == "close")
            with no_io(), patch.object(os, "fstat", return_value=facts()), patch.object(os, "scandir", return_value=iterator):
                inventory = snapshot._Inventory()
                if exhausted == "entries":
                    inventory.counts["entries"] = snapshot.MAX_ENTRIES
                reader = snapshot._NamedTextReads(400, inventory)
                with patch.object(inventory, "tick", return_value=exhausted != "deadline"):
                    with self.assertRaises(snapshot._DescriptorCleanupError if exhausted == "close" else snapshot._ReadProblem):
                        reader._metadata_entries(400)
            self.assertEqual(iterator.closed, 1)
