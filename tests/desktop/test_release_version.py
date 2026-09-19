"""Inert saved-version policy/reader contracts, not OS or runtime qualification.

No selected project, child, native tool or network is admitted. Original reader
control flow is exercised with descriptor/stat sentinels under IO traps.
"""
from __future__ import annotations

import builtins
import json
import os
import socket
import stat
import subprocess
import sys
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _desktop_engine as engine
from mobile_release.api import METHODS, ApiError, execute
from mobile_release.api import _release_version as api
from mobile_release.api import _snapshot as snapshot
from mobile_release.config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseConfig


def config(*, source="release/version.properties", ios=False):
    return {
        "$schema": "https://never-contact.invalid/schema.json", "schemaVersion": 1,
        "version": {"source": source, "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified"} if ios else {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": ["en-US"] if ios else []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [["./must-not-run"]], "androidArtifact": [], "iosArtifact": []},
    }


def values(raw="VERSION_NAME='1.2.3'\r\nBUILD_NUMBER=42\nOTHER=unselected-fixture\n", *, data=None):
    data = config() if data is None else data
    return {api.CONFIG_PATH: json.dumps(data), data["version"]["source"]: raw}


def forbidden(*_args, **_kwargs):
    raise AssertionError("No project/native/process/network IO is admitted")


@contextmanager
def no_io():
    with ExitStack() as stack:
        stack.enter_context(patch.object(builtins, "open", side_effect=forbidden))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "listdir", "scandir", "fsync",
                     "mkdir", "rename", "replace", "unlink", "rmdir", "system", "register_at_fork",
                     "pipe", "pipe2", "dup", "dup2", "fork", "posix_spawn", "execve", "waitpid", "kill"):
            stack.enter_context(patch.object(os, name, create=True, side_effect=forbidden))
        for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
            stack.enter_context(patch.object(Path, name, side_effect=forbidden))
        stack.enter_context(patch.object(subprocess, "Popen", side_effect=forbidden))
        stack.enter_context(patch.object(socket, "socket", side_effect=forbidden))
        stack.enter_context(patch.object(ReleaseConfig, "project_path", side_effect=forbidden))
        stack.enter_context(patch.object(ReleaseConfig, "release_version", side_effect=forbidden))
        stack.enter_context(patch("mobile_release.config.parse_key_value_file", side_effect=forbidden))
        yield


class Reads:
    def __init__(self, supplied):
        self.values, self.calls, self.events = supplied, [], []

    def read(self, path, *, limit):
        self.calls.append((path, limit))
        if path not in self.values:
            raise AssertionError("Read outside the saved-config-derived fixture")
        value = self.values[path]
        if isinstance(value, BaseException):
            raise value
        return value


@contextmanager
def inert_observation(supplied, *, named_error=None, root_note=None, named_close=False, root_close=False):
    reader = Reads(supplied)

    @contextmanager
    def root_scope(_root, inventory):
        reader.events.append("root-enter")
        try:
            yield 400
            reader.events.append("root-recheck")
            if root_note:
                inventory.note(root_note, "private-error-marker")
        finally:
            reader.events.append("root-close")
            if root_close:
                raise snapshot._DescriptorCleanupError("private-error-marker")

    @contextmanager
    def named_scope(_descriptor, _inventory):
        reader.events.append("named-enter")
        try:
            yield reader
            reader.events.append("named-recheck")
            if named_error:
                raise named_error
        finally:
            reader.events.append("named-close")
            if named_close:
                raise snapshot._DescriptorCleanupError("private-error-marker")

    with no_io(), patch.object(api, "release_version_observation_available", return_value=True), \
            patch.object(snapshot, "_root_handles", side_effect=root_scope), \
            patch.object(snapshot, "_named_text_reads", side_effect=named_scope):
        yield reader


def facts(inode, *, directory=False, size=0):
    return SimpleNamespace(st_dev=9, st_ino=inode, st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | 0o700,
                           st_nlink=1, st_size=size, st_mtime_ns=100, st_ctime_ns=101, st_uid=1001, st_gid=1002)


class ReleaseVersionTests(unittest.TestCase):
    def refused(self, reason):
        with self.assertRaises(ApiError) as caught:
            execute("release.version.observe", {"root": "/inert-project"})
        self.assertEqual(caught.exception.code, "release_version_" + reason)
        self.assertEqual(caught.exception.message, api._ERRORS[reason])
        self.assertNotIn("private-error-marker", str(caught.exception))

    def test_request_is_exact_bounded_and_has_no_alternate_path_or_draft(self):
        bad = [None, [], {}, {"root": None}, {"root": True}, {"root": "\ud800"},
               {"root": "/" + "x" * api.MAX_PARAMS_BYTES}]
        bad += [{"root": "/inert-project", key: None} for key in
                ("path", "source", "configPath", "platform", "nameKey", "buildKey", "draft", "force")]
        with no_io(), patch.object(snapshot, "_root_handles", side_effect=forbidden):
            for supplied in bad:
                with self.subTest(kind=type(supplied).__name__), self.assertRaises(ApiError) as caught:
                    execute("release.version.observe", supplied)
                self.assertEqual(caught.exception.code, "release_version_invalid_params")
            with patch.object(api, "release_version_observation_available", return_value=True):
                for root in ("relative", "/a/../b", "//a", "/a/", "/a\\b", "/"):
                    with self.subTest(root=root), self.assertRaises(ApiError) as caught:
                        execute("release.version.observe", {"root": root})
                    self.assertEqual(caught.exception.code, "release_version_unsafe")

    def test_windows_and_installed_capability_claims_do_not_enable_observation(self):
        with no_io(), patch.object(sys, "platform", "win32"), \
                patch.object(snapshot, "_WINDOWS_SNAPSHOT_QUALIFIED", True), \
                patch.object(snapshot, "_root_handles", side_effect=forbidden):
            self.refused("unavailable")
            caps = execute("capabilities", {})
            self.assertFalse(next(row for row in caps["methods"] if row["method"] == "release.version.observe")["available"])
            self.assertTrue(all(not row["available"] for row in caps["actions"]))

    def test_only_saved_source_and_selected_normalized_values_are_returned(self):
        with inert_observation(values()) as reader:
            result = execute("release.version.observe", {"root": "/inert-project"})
        self.assertEqual(reader.calls, [(api.CONFIG_PATH, MAX_CONFIG_BYTES), ("release/version.properties", MAX_VERSION_BYTES)])
        self.assertEqual(reader.events, ["root-enter", "named-enter", "named-recheck", "named-close", "root-recheck", "root-close"])
        self.assertEqual(result, {"schemaVersion": 1, "source": "release/version.properties", "version": {"name": "1.2.3", "build": 42},
                                 "observationScope": "single-request-non-atomic", "assurance": {
                                     "basis": "static-text", "projectCodeExecuted": False, "toolsProbed": False,
                                     "credentialsRead": False, "gitObserved": False, "storeContacted": False,
                                     "writesPerformed": False, "releaseReadiness": "unknown"}})
        self.assertNotIn("unselected-fixture", json.dumps(result))
        data = config(source="public/app-version.env")
        data["version"].update(nameKey="MARKETING", buildKey="BUILD")
        with inert_observation(values("MARKETING=2.4\nBUILD=7\nVERSION_NAME=ignored", data=data)):
            self.assertEqual(execute("release.version.observe", {"root": "/inert-project"})["version"], {"name": "2.4", "build": 7})

    def test_shared_policy_handles_enabled_ios_suffixes_keys_and_build_limits(self):
        for ios, name, build, valid in [(False, "1.2.3.4-beta.5", "42", True), (False, "1.2.3.4+5", "42", True),
                                        (False, "1.2.3.4-beta+5", "42", False), (True, "1.2.3-beta", "42", False),
                                        (True, "1.2.3.4", "42", False), (True, "1.2", "1", True),
                                        (True, "1.2.3", "2100000000", True), (False, "1", "42", False),
                                        (False, "1.2", "042", False), (False, "1.2", "+42", False),
                                        (False, "1.2", "0", False), (False, "1.2", "2100000001", False),
                                        (False, "1.2", "9" * 10_000, False)]:
            with self.subTest(ios=ios, name=name, build_size=len(build)), \
                    inert_observation(values(f"VERSION_NAME={name}\nBUILD_NUMBER={build}", data=config(ios=ios))):
                if valid:
                    self.assertEqual(execute("release.version.observe", {"root": "/inert-project"})["version"], {"name": name, "build": int(build)})
                else:
                    self.refused("source_invalid")
        for raw in ("VERSION_NAME=1.2", "BUILD_NUMBER=42", "VERSION_NAME=1.2\nVERSION_NAME=1.3\nBUILD_NUMBER=42",
                    "VERSION_NAME=${X}\nBUILD_NUMBER=42", 'VERSION_NAME="1.2\nBUILD_NUMBER=42'):
            with inert_observation(values(raw)):
                self.refused("source_invalid")

    def test_ordinary_refusals_leave_original_contexts_normally(self):
        cases = [({api.CONFIG_PATH: None}, "config_missing"), ({api.CONFIG_PATH: '{"private-error-marker":1}'}, "config_invalid"),
                 (values(None), "source_missing"), (values("VERSION_NAME=private-error-marker\nBUILD_NUMBER=42"), "source_invalid"),
                 (values(data=config(source="release/private/version.env")), "unsafe"),
                 (values("VERSION_NAME=1.2\nBUILD_NUMBER=42\npassword=private-error-marker"), "sensitive")]
        for supplied, reason in cases:
            with self.subTest(reason=reason), inert_observation(supplied) as reader:
                self.refused(reason)
            self.assertEqual(reader.events, ["root-enter", "named-enter", "named-recheck", "named-close", "root-recheck", "root-close"])
            if reason in {"config_missing", "config_invalid", "unsafe"}:
                self.assertEqual(reader.calls, [(api.CONFIG_PATH, MAX_CONFIG_BYTES)])

    def test_changed_and_limit_rechecks_supersede_ordinary_outcomes(self):
        for supplied in ({api.CONFIG_PATH: None}, {api.CONFIG_PATH: "invalid"}, values(None), values("invalid")):
            for options, reason in [({"root_note": "snapshot.changed"}, "changed"),
                                    ({"root_note": "snapshot.deadline"}, "limit"),
                                    ({"named_error": snapshot._ReadProblem("snapshot.changed", "private-error-marker")}, "changed")]:
                with self.subTest(options=list(options)), inert_observation(supplied, **options) as reader:
                    self.refused(reason)
                self.assertIn("named-recheck", reader.events)
                self.assertEqual(reader.events.count("named-close"), 1)
                self.assertEqual(reader.events.count("root-close"), 1)

    def test_original_close_uncertainty_has_precedence_and_is_not_retried(self):
        for supplied in ({api.CONFIG_PATH: None}, {api.CONFIG_PATH: "invalid"}, values(None), values("invalid"), values()):
            for options in ({"named_close": True}, {"root_close": True},
                            {"named_close": True, "root_close": True},
                            {"named_error": snapshot._ReadProblem("snapshot.changed", "private-error-marker"), "named_close": True},
                            {"root_note": "snapshot.deadline", "root_close": True}):
                with self.subTest(options=options), inert_observation(supplied, **options) as reader:
                    self.refused("cleanup_unknown")
                self.assertEqual(reader.events.count("named-close"), 1)
                self.assertEqual(reader.events.count("root-close"), 1)

    def test_source_path_admission_precedes_any_selected_version_read(self):
        unsafe = [".env", "release/.hidden", "private/version", "release/secrets/version", "review/version", "testflight/version",
                  "build/version", "node_modules/version", "release/COM1.env", "release/file.", "release/file ",
                  "release/a?b", "release/a:b", "release/e\u0301.env", "/absolute", "../escape", "a//b",
                  "a/" * 12 + "v", "é" * 256, "a/" + "x" * 256, "release/credentials/version"]
        with no_io():
            for path in unsafe:
                self.assertFalse(api._source_path(path), path)
            for path in ("release/version.properties", "public/é.env", "a/" * 11 + "v"):
                self.assertTrue(api._source_path(path), path)
        for path in unsafe:
            with self.subTest(path=path), inert_observation(values(data=config(source=path))) as reader:
                with self.assertRaises(ApiError) as caught:
                    execute("release.version.observe", {"root": "/inert-project"})
                self.assertIn(caught.exception.code, {"release_version_config_invalid", "release_version_unsafe"})
            self.assertEqual(reader.calls, [(api.CONFIG_PATH, MAX_CONFIG_BYTES)])

    def test_mechanical_failures_and_known_codes_never_reflect_messages(self):
        failures = [(snapshot._ReadProblem(code, "private-error-marker"), reason) for code, reason in api._READ_REASONS.items()]
        failures += [(OSError("private-error-marker"), "unreadable"),
                     (ApiError("release_version_source_invalid", "private-error-marker"), "source_invalid"),
                     (ApiError("release_version_invented", "private-error-marker"), "unreadable")]
        for failure, reason in failures:
            with self.subTest(reason=reason), inert_observation(values(failure)) as reader:
                self.refused(reason)
            self.assertEqual(reader.events.count("named-close"), 1)
            self.assertEqual(reader.events.count("root-close"), 1)

    def test_actual_named_absence_and_root_rechecks_survive_policy_refusal(self):
        # Real original context managers, with only stat/open/read/close facts
        # supplied as inert sentinels. No root or descriptor is actually opened.
        for case, expected in [("config-appears", "changed"), ("source-appears", "changed"),
                               ("invalid-config-root-changes", "changed"), ("invalid-source-root-changes", "changed"),
                               ("config-appears-close-fails", "cleanup_unknown"), ("missing-source-close-fails", "cleanup_unknown")]:
            root_fact, selected_fact, release_fact, file_fact = facts(1, directory=True), facts(2, directory=True), facts(3, directory=True), facts(4)
            current, opened, closed = {"changed": False}, [], []
            missing = "mobile-release.json" if case.startswith("config-appears") else "version.properties" if case in {"source-appears", "missing-source-close-fails"} else None

            def open_fake(name, _flags, *, dir_fd=None):
                descriptor = 10 if name == "/" else 20 if name == "selected" else 30 + sum(item == "release" for item in opened)
                opened.append(name)
                return descriptor

            def stat_fake(name, *, dir_fd=None, follow_symlinks=False):
                if name == "selected":
                    return facts(22, directory=True) if current["changed"] and "root-changes" in case else selected_fact
                if name == "release":
                    return release_fact
                if name == missing and (not current["changed"] or case == "missing-source-close-fails"):
                    raise FileNotFoundError()
                return file_fact

            def read_fake(parent, name, relative, inventory, *, limit, receipts):
                receipts.append((parent, name, snapshot._named_identity(file_fact)))
                if name == "mobile-release.json":
                    return "invalid" if case == "invalid-config-root-changes" else json.dumps(config())
                return "invalid" if case == "invalid-source-root-changes" else "VERSION_NAME=1.2\nBUILD_NUMBER=42"

            original_check = snapshot._NamedTextReads.check

            def check(reader):
                current["changed"] = True
                return original_check(reader)

            def close(descriptor):
                closed.append(descriptor)
                if "close-fails" in case and descriptor >= 30:
                    raise OSError("private-error-marker")

            with self.subTest(case=case), no_io(), patch.object(api, "release_version_observation_available", return_value=True), \
                    patch.object(os, "open", side_effect=open_fake), patch.object(os, "stat", side_effect=stat_fake), \
                    patch.object(os, "fstat", side_effect=lambda fd: root_fact if fd == 10 else selected_fact if fd == 20 else release_fact), \
                    patch.object(os, "close", side_effect=close), patch.object(snapshot._NamedTextReads, "_alias"), \
                    patch.object(snapshot._NamedTextReads, "check", check), patch.object(snapshot, "_read_file", side_effect=read_fake):
                with self.assertRaises(ApiError) as caught:
                    execute("release.version.observe", {"root": "/selected"})
                self.assertEqual(caught.exception.code, "release_version_" + expected)
            self.assertEqual(closed[-2:], [20, 10])
            self.assertEqual(len(closed), len(set(closed)))

    def test_dto_and_passive_frame_are_separately_bounded(self):
        with inert_observation(values()):
            result = execute("release.version.observe", {"root": "/inert-project"})
        raw = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertLessEqual(len(raw), api.MAX_RESULT_BYTES)
        request = engine.Request("q" * 64, "release.version.observe", {"root": "/inert-project"})
        frame = engine.encode_response(request, result=result)
        self.assertGreater(len(frame), len(raw))
        self.assertLessEqual(len(frame), engine.MAX_RESPONSE_BYTES)
        self.assertIn("release.version.observe", engine.METHODS)
        self.assertEqual(engine.METHODS, frozenset(METHODS))
        self.assertNotIn("preflight.offline", engine.METHODS)
        self.assertNotIn("artifacts.verify", engine.METHODS)
