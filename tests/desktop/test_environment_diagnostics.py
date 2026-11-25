"""Focused inert diagnostics contracts, not native process/host qualification.

Metadata, descriptors, tool returns and clocks below are synthetic DATA or
patched fixed seams. No real file descriptor, signal handler, tool, project,
subprocess, helper, framework or network service is acquired by these tests.
Only the lead may execute this separately reviewed selection.
"""
from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import types
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from mobile_release import _desktop_environment_control as control
from mobile_release import _desktop_environment_engine as engine
from mobile_release import _desktop_environment_protocol as wire
from mobile_release import environment_diagnostics as diagnostics
from mobile_release import environment_diagnostics_tools as tools
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError, ProcessError


def draft() -> dict:
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.inert.diagnostics", "identityStatus": "unverified"},
        "ios": {"enabled": True, "bundleId": "org.inert.diagnostics", "identityStatus": "unverified"},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def request_data(platform="android", profile="linux-gnu-x86_64") -> dict:
    return {"protocol": wire.PROTOCOL, "runId": "a" * 32, "ownerGeneration": "b" * 32,
        "context": {"projectId": "opaque_project", "draftRevision": 2, "baselineGeneration": 3,
                    "platform": platform, "operation": "build"},
        "draft": draft(), "native": {"profile": profile, "projectRoot": "/inert/project", "cwd": "/inert/runtime"}}


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"


def request(platform="android", profile="linux-gnu-x86_64"):
    return wire.parse_request(encoded(request_data(platform, profile)))


def terminal_fixture(req=None) -> dict:
    req = request() if req is None else req
    host = wire.PROFILES[req.native["profile"]][0]
    return {"schemaVersion": 1, "policyVersion": wire.POLICY, "context": dict(req.context), "hostPlatform": host,
        "outcome": "unavailable", "checks": [wire.row(role, reason="platform-disabled")
            for role in wire.ROSTERS[(host, req.context["platform"])]], "commandsAttempted": 0,
        "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": False,
            "commands": 0, "inputClosed": True, "handlersRestored": True, "toolDescriptorsClosed": True, "stopObserved": "none"},
        "assurance": wire.assurance(0)}


def metadata(mode=stat.S_IFDIR | 0o755, *, uid=0, gid=0, inode=1, links=1, size=4096):
    return types.SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid,
                                st_nlink=links, st_size=size, st_mtime_ns=100, st_ctime_ns=100)


def metadata_table(files=(), links=()) -> dict:
    """Only finite fixed-path DATA for the lookup-policy cases below."""
    table = {"/": metadata()}
    for path in (*files, *links):
        parts = path.split("/")[1:]
        for length in range(1, len(parts)):
            name = "/" + "/".join(parts[:length])
            table.setdefault(name, metadata(inode=len(table) + 1))
        table[path] = metadata((stat.S_IFLNK | 0o777) if path in links else (stat.S_IFREG | 0o755), inode=len(table) + 1)
    return table


def guard():
    # Construction only: install/activate is never called in this inert suite.
    return DefaultCancellation(wire.ProtocolError, "inert diagnostics ownership")


def elf(architecture="x86_64") -> bytes:
    value = bytearray(64)
    value[:7] = b"\x7fELF\x02\x01\x01"
    value[16:18] = (3).to_bytes(2, "little")
    value[18:20] = (62 if architecture == "x86_64" else 183).to_bytes(2, "little")
    value[20:24] = (1).to_bytes(4, "little")
    value[52:54] = (64).to_bytes(2, "little")
    return bytes(value)


class EnvironmentDiagnosticsProtocolTests(unittest.TestCase):
    def test_selection_detail_is_optional_closed_and_only_for_original_negative_selection(self):
        original = wire.row("developer-selection", "completed", "selection-unrecognized", returncode=0)
        for detail in (None, {"stage": "application", "reason": "directory-owner"},
                       {"stage": "alias", "reason": "target-shape"}):
            value = {**original, "selectionDiagnostic": detail}
            wire.validate_row(value)
            self.assertEqual(json.loads(encoded(value)), value)
        wire.validate_row(original)
        self.assertNotIn("selectionDiagnostic", original)
        wire.validate_row({**wire.row("git"), "selectionDiagnostic": None})
        for bad in ({}, {"stage": "application", "reason": "target-shape"},
                    {"stage": "alias", "reason": "directory-owner"},
                    {"stage": "PRIVATE_PATH", "reason": "directory-owner"},
                    {"stage": "application", "reason": "directory-owner", "path": "PRIVATE_PATH"}):
            with self.subTest(detail=bad), self.assertRaises(wire.ProtocolError):
                wire.validate_row({**original, "selectionDiagnostic": bad})
        detail = {"stage": "application", "reason": "directory-owner"}
        for key in original:
            bad = {**original, "selectionDiagnostic": detail}
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(wire.ProtocolError): wire.validate_row(bad)
        for value in (wire.row("git"), wire.row("developer-selection"),
                      wire.row("developer-selection", "completed", "observed", returncode=0),
                      wire.row("developer-selection", "completed", "nonzero-exit", returncode=1)):
            with self.subTest(row=value["reason"]), self.assertRaises(wire.ProtocolError):
                wire.validate_row({**value, "selectionDiagnostic": detail})
        constructed = wire.row("developer-selection", "completed", "selection-unrecognized", returncode=0, selection_diagnostic=detail)
        detail["reason"] = "PRIVATE_SENTINEL"
        self.assertEqual(constructed["selectionDiagnostic"]["reason"], "directory-owner")

    def test_closed_request_context_native_data_and_finite_two_frame_contract(self):
        req = request()
        self.assertEqual(req.native, request_data()["native"])
        self.assertNotIn("root", req.context)
        accepted = wire.response(req, "accepted", {"schemaVersion": 1, "context": req.context, "hostPlatform": "linux"})
        terminal = wire.response(req, "terminal", terminal_fixture(req))
        self.assertEqual([json.loads(raw)["seq"] for raw in (accepted, terminal)], [0, 1])
        self.assertLess(len(accepted) + len(terminal), wire.RESPONSE_LIMIT)
        self.assertNotIn(b"/inert/", accepted + terminal)
        self.assertNotIn(b"org.inert.diagnostics", accepted + terminal)
        self.assertEqual(wire.OUTPUT_LIMIT, 16_384)
        for key in request_data():
            with self.subTest(missing=key), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded({name: value for name, value in request_data().items() if name != key}))
        for key in ("executable", "argv", "environment", "timeout", "approval", "executionScope"):
            with self.subTest(extra=key), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded({**request_data(), key: "PRIVATE_INPUT_SENTINEL"}))

    def test_duplicate_utf8_counter_depth_and_path_refusals_are_fixed_errors(self):
        raw = encoded(request_data())
        bad = [raw.replace(b'"protocol":', b'"protocol":"duplicate","protocol":', 1),
               raw[:-1], raw + b"{}\n", raw.replace(b"opaque_project", b"\xff"), b"[1]\n"]
        for value in bad:
            with self.subTest(raw_length=len(value)), self.assertRaises(wire.ProtocolError):
                wire.parse_request(value)
        for section, key, value in [("context", "draftRevision", True), ("context", "baselineGeneration", 2**32 - 1),
            ("context", "platform", "windows"), ("context", "operation", "artifact-validation"),
            ("native", "profile", "linux"), ("native", "cwd", "/inert/../project"),
            ("native", "projectRoot", "/inert//project"), ("native", "cwd", "~/runtime")]:
            data = request_data()
            data[section][key] = value
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError) as caught:
                wire.parse_request(encoded(data))
            self.assertNotIn(str(value), str(caught.exception))
        nested = {}
        node = nested
        for _ in range(34):
            node["x"] = {}
            node = node["x"]
        for value in (nested, {"large": "x" * wire.DRAFT_LIMIT}):
            data = request_data()
            data["draft"] = value
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded(data))

    def test_complete_version_bytes_and_xcode_baseline_no_substring_or_raw_output(self):
        java = (b'openjdk version "21.0.8" 2025-07-15 LTS\n'
                b'OpenJDK Runtime Environment Temurin-21.0.8+9 (build 21.0.8+9-LTS)\n'
                b'OpenJDK 64-Bit Server VM (build 21.0.8+9-LTS, mixed mode, sharing)\n')
        good = [("git", b"git version 2.43.0\n", b"", ("2.43.0", None)),
                ("git", b"git version 2.50.1 (Apple Git-155)\n", b"", ("2.50.1", None)),
                ("java", b"", java, ("21.0.8", None)),
                ("javac", b"javac 21.0.8\n", b"", ("21.0.8", None)),
                ("xcode", b"Xcode 26.3\nBuild version 17C529\n", b"", ("26.3", "17C529"))]
        for role, stdout, stderr, expected in good:
            with self.subTest(role=role):
                self.assertEqual(wire.parse_version(role, stdout, stderr), expected)
        for role, stdout, stderr in [("git", b"prefix git version 2.43.0\n", b""),
            ("java", java, b"PRIVATE_OUTPUT_SENTINEL"), ("java", b"", java.split(b"\n")[0] + b"\n"),
            ("javac", b"javac 21.0.8\r\n", b""), ("xcode", b"Xcode 26.3\nBuild version 17C529\nextra", b""),
            ("xcode", b"Xcode 26.3\nBuild version 17C529\n", b"warning"), ("git", b"\xff", b"")]:
            with self.subTest(role=role, malformed=True):
                self.assertIsNone(wire.parse_version(role, stdout, stderr))
        self.assertEqual(wire.row("xcode", "completed", "observed", version="26.3", build="17C529", returncode=0)["assessment"], "match")
        self.assertEqual(wire.row("xcode", "completed", "observed", version="26.2", build="17B111", returncode=0)["assessment"], "mismatch")
        self.assertEqual(wire.row("java", "completed", "observed", version="17.0.1", returncode=0)["assessment"], "no-local-policy")
        with self.assertRaises(wire.ProtocolError):
            wire.parse_version("java", b"x" * 9000, b"y" * 9000)  # Aggregate, not per-stream.

    def test_result_roster_reason_and_scope_joins_reject_forged_linux_xcode(self):
        for context in wire.ROSTERS:
            host, platform = context
            req = request(platform, "macos-arm64" if host == "macos" else "linux-gnu-x86_64")
            value = terminal_fixture(req)
            wire.validate_terminal(value, req)
            for mutation in ("duplicate", "counter", "extra", "readiness", "lifetime"):
                bad = copy.deepcopy(value)
                if mutation == "duplicate": bad["checks"][1] = bad["checks"][0]
                if mutation == "counter": bad["commandsAttempted"] = True
                if mutation == "extra": bad["lifetime"]["nativeFinality"] = "settled"
                if mutation == "readiness": bad["assurance"]["releaseReadiness"] = "ready"
                if mutation == "lifetime": bad["lifetime"]["contained"] = False
                with self.subTest(context=context, mutation=mutation), self.assertRaises(wire.ProtocolError):
                    wire.validate_terminal(bad, req)
        req = request("ios")
        value = terminal_fixture(req)
        value["checks"] = [wire.row("git", reason="unsupported-installation"),
            wire.row("xcode", "completed", "observed", version="26.3", build="17C529", returncode=0)]
        value.update(outcome="complete", commandsAttempted=1, assurance=wire.assurance(1))
        value["lifetime"].update(commands=1, commandDispatched=True)
        with self.assertRaises(wire.ProtocolError): wire.validate_terminal(value, req)
        value = terminal_fixture()
        value["checks"][0] = wire.row("git", reason="unsupported-installation")
        with self.assertRaises(wire.ProtocolError): wire.validate_terminal(value, request())

    def test_unknown_cannot_be_complete_and_cancel_requires_original_stop_fact(self):
        req = request()
        value = terminal_fixture(req)
        value["checks"] = [wire.row(role, reason="stopped") for role in ("git", "java", "javac")]
        value["outcome"] = "failed"
        value["lifetime"].update(fatal=True, complete=False, contained=False, commandDispatched=None)
        wire.validate_terminal(value, req)
        for outcome in ("complete", "unavailable", "cancelled", "timed-out", "partial"):
            bad = copy.deepcopy(value)
            bad["outcome"] = outcome
            with self.subTest(outcome=outcome), self.assertRaises(wire.ProtocolError): wire.validate_terminal(bad, req)
        value["outcome"] = value["lifetime"]["stopObserved"] = "cancelled"
        wire.validate_terminal(value, req)
        self.assertNotIn("writesPerformed", value["assurance"])
        self.assertEqual(value["assurance"]["toolCacheEffects"], "possible")
        for reason in ("cancelled", "timed-out"):
            bad = terminal_fixture(req)
            bad.update(outcome="failed", checks=[wire.row("git", "attempted", reason), wire.row("java"), wire.row("javac")],
                       commandsAttempted=1, assurance=wire.assurance(1))
            with self.subTest(unobserved_stop=reason), self.assertRaises(wire.ProtocolError): wire.validate_terminal(bad, req)
        for commands, dispatched in ((0, False), (1, False), (1, None)):
            bad = terminal_fixture(req)
            bad.update(outcome="partial", checks=[wire.row("git", "completed", "observed", version="2.43.0", returncode=0),
                wire.row("java"), wire.row("javac")], commandsAttempted=1, assurance=wire.assurance(1))
            bad["lifetime"].update(commands=commands, commandDispatched=dispatched, fatal=dispatched is None)
            with self.subTest(unsupported_completed=(commands, dispatched)), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(bad, req)


class EnvironmentDiagnosticsLookupTests(unittest.TestCase):
    def test_directory_file_owner_write_link_and_script_policy(self):
        for profile in wire.PROFILES:
            with self.subTest(profile=profile):
                self.assertTrue(tools.directory_allowed(metadata(), profile))
                self.assertFalse(tools.directory_allowed(metadata(uid=1000), profile))
                self.assertFalse(tools.directory_allowed(metadata(stat.S_IFDIR | 0o777), profile))
                self.assertFalse(tools.directory_allowed(metadata(stat.S_IFDIR | 0o775, gid=1000), profile))
                self.assertEqual(tools.directory_allowed(metadata(stat.S_IFDIR | 0o775, gid=80), profile), profile.startswith("macos"))
        self.assertTrue(tools.executable_allowed(metadata(stat.S_IFREG | 0o755)))
        for value in (metadata(stat.S_IFREG | 0o775), metadata(stat.S_IFREG | 0o6755),
                      metadata(stat.S_IFREG | 0o644), metadata(stat.S_IFREG | 0o755, links=2),
                      metadata(stat.S_IFLNK | 0o777), metadata(stat.S_IFREG | 0o755, uid=1000)):
            self.assertFalse(tools.executable_allowed(value))
        self.assertTrue(tools.binary_header_allowed(elf(), "linux-gnu-x86_64", 4096))
        self.assertFalse(tools.binary_header_allowed(elf(), "linux-gnu-aarch64", 4096))
        self.assertTrue(tools.binary_header_allowed(elf("aarch64"), "linux-gnu-aarch64", 4096))
        for content in (b"#!/bin/sh\n", b"MZ" + b"\0" * 100, b"\x7fELF\x01" + b"\0" * 100, b""):
            self.assertFalse(tools.binary_header_allowed(content, "linux-gnu-x86_64", 4096))

    def test_macho_native_and_bounded_universal_architecture_headers(self):
        thin = bytearray(32)
        thin[:4] = b"\xcf\xfa\xed\xfe"
        thin[4:8] = (0x0100000C).to_bytes(4, "little")
        thin[12:16] = (2).to_bytes(4, "little")
        self.assertTrue(tools.binary_header_allowed(bytes(thin), "macos-arm64", 4096))
        self.assertFalse(tools.binary_header_allowed(bytes(thin), "macos-x86_64", 4096))
        fat = bytearray(28)
        fat[:8] = b"\xca\xfe\xba\xbe" + (1).to_bytes(4, "big")
        fat[8:12] = (0x01000007).to_bytes(4, "big")
        fat[16:20], fat[20:24] = (256).to_bytes(4, "big"), (32).to_bytes(4, "big")
        self.assertTrue(tools.binary_header_allowed(bytes(fat), "macos-x86_64", 4096))
        self.assertFalse(tools.binary_header_allowed(bytes(fat), "macos-arm64", 4096))
        fat[4:8] = (9).to_bytes(4, "big")
        self.assertFalse(tools.binary_header_allowed(bytes(fat), "macos-x86_64", 4096))

    def test_empty_origin_environments_exclude_ambient_options_and_stub_roles(self):
        inherited = {"HOME": "PRIVATE_HOME", "JAVA_HOME": "PRIVATE_JDK", "JAVA_TOOL_OPTIONS": "PRIVATE_OPTION",
                     "DEVELOPER_DIR": "PRIVATE_XCODE", "GIT_CONFIG_COUNT": "1", "HTTPS_PROXY": "PRIVATE_PROXY"}
        with patch.dict(os.environ, inherited):
            self.assertEqual(tools.tool_environment("linux-gnu-x86_64", "java"), {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
            self.assertEqual(tools.tool_environment("macos-arm64", "git"), {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
            root = "/Applications/Xcode_26.3.app/Contents/Developer"
            value = tools.tool_environment("macos-arm64", "xcode", root)
            self.assertEqual(value["DEVELOPER_DIR"], root)
            self.assertEqual(set(value), {"LANG", "LC_ALL", "PATH", "DEVELOPER_DIR"})
            self.assertNotIn("PRIVATE_", json.dumps(value))
        for profile, role, root in [("linux-gnu-x86_64", "xcode", None), ("linux-gnu-x86_64", "developer-selection", None),
            ("macos-arm64", "xcode", "/Library/Developer/CommandLineTools"), ("macos-arm64", "xcode", "/private/custom")]:
            with self.assertRaises(wire.ProtocolError): tools.tool_environment(profile, role, root)

    def test_linux_exact_two_links_same_jdk_no_path_search_or_mixed_pair(self):
        originals = ("/usr/bin/java", "/etc/alternatives/java", "/usr/bin/javac", "/etc/alternatives/javac")
        finals = ("/usr/lib/jvm/jdk-21/bin/java", "/usr/lib/jvm/jdk-21/bin/javac")
        table = metadata_table(finals, originals)
        targets = dict(zip(originals, (b"/etc/alternatives/java", finals[0].encode(), b"/etc/alternatives/javac", finals[1].encode())))
        owner = guard()
        lookup = tools.ToolLookup("linux-gnu-x86_64", "/inert/project", owner)
        with patch.object(owner, "check"), patch.object(lookup, "_stat", side_effect=table.__getitem__), \
             patch.object(lookup, "_readlink", side_effect=targets.__getitem__), patch.object(lookup, "_header") as header:
            java, javac = lookup.linux_jdk()
            self.assertEqual((java.path, javac.path), finals)
            self.assertEqual(header.call_count, 2)
            self.assertEqual([node.path for node in java.nodes if node.kind == "link"], list(originals[:2]))
            targets["/etc/alternatives/javac"] = b"/usr/lib/jvm/jdk-17/bin/javac"
            with self.assertRaises(tools.ToolUnavailable): lookup.linux_jdk()
            self.assertEqual(header.call_count, 2)  # No mixed-JDK probe or fallback.
            targets["/usr/bin/java"] = b"../lib/jvm/jdk-21/bin/java"
            with self.assertRaises(tools.ToolUnavailable): lookup.linux_jdk()

    def test_mac_selection_single_supported_alias_no_install_launcher_fallback(self):
        selected = "/Applications/Xcode_26.3.app/Contents/Developer"
        table = metadata_table((selected + "/usr/bin/git",), ("/Applications/Xcode.app",))
        owner = guard()
        lookup = tools.ToolLookup("macos-arm64", "/inert/project", owner)
        with patch.object(owner, "check"), patch.object(lookup, "_stat", side_effect=lambda path, **_options: table[path]), \
             patch.object(lookup, "_readlink", return_value=b"Xcode_26.3.app") as link:
            result = lookup.mac_developer(b"/Applications/Xcode.app/Contents/Developer\n")
            self.assertEqual(result.path, selected)
            self.assertEqual([node.path for node in result.nodes if node.kind == "link"], ["/Applications/Xcode.app"])
            link.return_value = b"../PRIVATE_XCODE"
            with self.assertRaises(tools.ToolUnavailable): lookup.mac_developer(b"/Applications/Xcode.app/Contents/Developer\n")
        for output in (b"/private/custom\n", b"/Applications/Xcode.app/Contents/Developer\n\n", b"/usr/bin/git", b"\xff"):
            with self.assertRaises(tools.ToolUnavailable): lookup.mac_developer(output)

    def test_mac_selection_reports_first_original_predicate_without_extra_observation(self):
        selected = "/Applications/Xcode_26.3.app/Contents/Developer"
        app, contents = "/Applications/Xcode_26.3.app", "/Applications/Xcode_26.3.app/Contents"
        prefix = ["/", "/Applications", app]
        cases = [("/", metadata(uid=1000), "root", "directory-owner", ["/"]),
                 ("/Applications", metadata(stat.S_IFDIR | 0o777), "applications", "directory-world-write", prefix[:2]),
                 (app, metadata(uid=1000), "application", "directory-owner", prefix),
                 (app, metadata(stat.S_IFDIR | 0o775, gid=1000), "application", "directory-group-write", prefix),
                 (contents, metadata(stat.S_IFLNK | 0o777), "contents", "directory-kind", prefix + prefix + [contents])]
        for path, facts, stage, reason, names in cases:
            with self.subTest(stage=stage, reason=reason):
                table = metadata_table((selected + "/usr/bin/git",))
                table[path] = facts
                lookup = tools.ToolLookup("macos-arm64", "/inert/project", guard())
                with patch.object(lookup, "_stat", side_effect=lambda name, **_options: table[name]) as observed, \
                     patch.object(lookup, "_readlink", side_effect=AssertionError("no alias probe")), \
                     patch.object(lookup, "_header", side_effect=AssertionError("no executable header")):
                    with self.assertRaises(tools.ToolUnavailable) as caught: lookup.mac_developer(selected.encode() + b"\n")
                self.assertEqual(caught.exception.selection_diagnostic, {"stage": stage, "reason": reason})
                self.assertEqual([call.args[0] for call in observed.call_args_list], names)
        lookup = tools.ToolLookup("macos-arm64", "/inert/project", guard())
        for raw, reason in ((b"", "byte-shape"), (b"\n", "line-shape"), (b"\xff", "utf8-invalid"),
                (b"/PRIVATE_PATH\n", "path-shape"), (b"/Applications/PRIVATE.app/Contents/Developer\n", "app-name")):
            with self.subTest(reason=reason), patch.object(lookup, "_stat", side_effect=AssertionError("no namespace probe")):
                with self.assertRaises(tools.ToolUnavailable) as caught: lookup.mac_developer(raw)
                self.assertEqual(caught.exception.selection_diagnostic, {"stage": "selector-output", "reason": reason})
                self.assertNotIn("PRIVATE", json.dumps(caught.exception.selection_diagnostic))

    def test_mac_selection_namespace_alias_and_legacy_errors_keep_original_custody(self):
        owner = guard()
        lookup = tools.ToolLookup("macos-arm64", "/inert/project", owner)
        for failure, reason in ((FileNotFoundError("PRIVATE_PATH"), "namespace-missing"),
                                (PermissionError("PRIVATE_PATH"), "namespace-inaccessible")):
            with patch.object(lookup, "_origin"), patch.object(owner, "check"), patch.object(os, "lstat", side_effect=failure) as observed:
                with self.assertRaises(tools.ToolUnavailable) as caught:
                    lookup.mac_developer(b"/Library/Developer/CommandLineTools\n")
            self.assertEqual(observed.call_count, 1)
            self.assertEqual(caught.exception.selection_diagnostic, {"stage": "root", "reason": reason})
            self.assertNotIn("PRIVATE", str(caught.exception))
        legacy = tools.ToolUnavailable("missing-in-supported-lookup")
        with patch.object(lookup, "_stat", side_effect=legacy):
            with self.assertRaises(tools.ToolUnavailable) as caught: lookup.mac_developer(b"/Library/Developer/CommandLineTools\n")
        self.assertIs(caught.exception, legacy)
        self.assertIsNone(caught.exception.selection_diagnostic)
        selected = "/Applications/Xcode_26.3.app/Contents/Developer"
        table = metadata_table((selected + "/usr/bin/git", "/Library/Developer/CommandLineTools/usr/bin/git"), ("/Applications/Xcode.app",))
        with patch.object(owner, "check"), patch.object(lookup, "_stat", side_effect=lambda name, **_options: table[name]), \
             patch.object(os, "readlink", return_value=b"../PRIVATE_TARGET") as link:
            with self.assertRaises(tools.ToolUnavailable) as caught: lookup.mac_developer(b"/Applications/Xcode.app/Contents/Developer\n")
            self.assertEqual(caught.exception.selection_diagnostic, {"stage": "alias", "reason": "target-shape"})
            self.assertEqual(link.call_count, 1)
            link.return_value = b"\xff"
            with self.assertRaises(tools.ToolUnavailable) as caught: lookup.mac_developer(b"/Applications/Xcode.app/Contents/Developer\n")
            self.assertEqual(caught.exception.selection_diagnostic, {"stage": "alias", "reason": "target-encoding"})
            link.return_value = b"Xcode_26.3.app"
            self.assertEqual(lookup.mac_developer(b"/Applications/Xcode.app/Contents/Developer\n").path, selected)
            self.assertEqual(lookup.mac_developer(b"/Library/Developer/CommandLineTools\n").path, "/Library/Developer/CommandLineTools")

    def test_mac_alias_first_readlink_or_identity_failure_has_no_later_probe(self):
        alias = "/Applications/Xcode.app"
        table = metadata_table(links=(alias,))
        original_facts = tools._file_facts
        for kind, reason in (("missing", "namespace-missing"), ("bytes", "target-bytes"), ("changed", "identity-changed")):
            with self.subTest(kind=kind):
                owner = guard()
                lookup = tools.ToolLookup("macos-arm64", "/inert/project", owner)
                events = []
                def observed(path, **_options):
                    events.append(("stat", path))
                    if kind == "changed" and events.count(("stat", alias)) == 3:
                        return metadata(stat.S_IFLNK | 0o777, inode=999)
                    return table[path]
                def link(path):
                    self.assertEqual(path, alias.encode())
                    events.append(("readlink", alias))
                    if kind == "missing": raise FileNotFoundError("PRIVATE_TARGET")
                    return b"" if kind == "bytes" else b"Xcode_26.3.app"
                def facts(value):
                    events.append(("facts", "changed" if value.st_ino == 999 else "original"))
                    return original_facts(value)
                with patch.object(owner, "check"), patch.object(lookup, "_stat", side_effect=observed), \
                     patch.object(os, "readlink", side_effect=link), patch.object(tools, "_file_facts", side_effect=facts):
                    with self.assertRaises(tools.ToolUnavailable) as caught:
                        lookup.mac_developer((alias + "/Contents/Developer\n").encode())
                expected = [("stat", path) for path in ("/", "/Applications", alias, "/", "/Applications", alias)]
                expected.append(("readlink", alias))
                if kind == "changed": expected.extend((("facts", "original"), ("stat", alias), ("facts", "changed")))
                self.assertEqual(events, expected)
                self.assertEqual(caught.exception.selection_diagnostic, {"stage": "alias", "reason": reason})
                self.assertEqual(caught.exception.inaccessible, kind == "missing")
                self.assertEqual(lookup.headers, [])

    def test_mac_jdk_unique_census_rejects_multiple_or_inaccessible_candidate(self):
        root = "/Library/Java/JavaVirtualMachines"
        files = tuple(root + "/" + name + "/Contents/Home/bin/" + role
                      for name in ("one.jdk", "two.jdk") for role in ("java", "javac"))
        table = metadata_table(files)
        owner = guard()
        lookup = tools.ToolLookup("macos-arm64", "/inert/project", owner)
        with patch.object(owner, "check"), patch.object(lookup, "_stat", side_effect=table.__getitem__) as observed, \
             patch.object(lookup, "_names", return_value=("one.jdk",)) as names, patch.object(lookup, "_header"):
            self.assertEqual(lookup.mac_jdk()[0].path, files[0])
            names.return_value = ("one.jdk", "two.jdk")
            with self.assertRaises(tools.ToolUnavailable) as caught: lookup.mac_jdk()
            self.assertEqual(caught.exception.reason, "unselected-installation")
            def inaccessible(path):
                if path == files[2]: raise tools.ToolUnavailable(inaccessible=True)
                return table[path]
            observed.side_effect = inaccessible
            with self.assertRaises(tools.ToolUnavailable) as caught: lookup.mac_jdk()
            self.assertEqual(caught.exception.reason, "unselected-installation")

    def test_observed_identity_change_stops_and_project_overlap_never_opens_project(self):
        owner = guard()
        lookup = tools.ToolLookup("linux-gnu-x86_64", "/usr/bin", owner)
        with patch.object(owner, "check"), patch.object(os, "lstat", side_effect=AssertionError("project access")):
            with self.assertRaises(tools.ToolUnavailable): lookup.linux_git()
        lookup = tools.ToolLookup("linux-gnu-x86_64", "/inert/project", owner)
        original = metadata(stat.S_IFREG | 0o755)
        binding = tools.ToolBinding("/usr/bin/git", (tools._Node("/usr/bin/git", "file", tools._file_facts(original)),))
        with patch.object(owner, "check"), patch.object(lookup, "_stat", return_value=metadata(stat.S_IFREG | 0o755, inode=2)):
            with self.assertRaises(tools.BindingChanged): lookup.recheck(binding)

    def test_header_registered_before_open_and_single_close_after_stable_bytes(self):
        owner = guard()
        lookup = tools.ToolLookup("linux-gnu-x86_64", "/inert/project", owner)
        value = metadata(stat.S_IFREG | 0o755)
        binding = tools.ToolBinding("/usr/bin/git", (tools._Node("/usr/bin/git", "file", tools._file_facts(value)),))
        def opened(path, flags):
            self.assertEqual((path, lookup.headers[0].state), ("/usr/bin/git", "ACQUIRING"))
            self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            return 123456  # Synthetic: every descriptor operation is patched.
        def closed(number):
            self.assertEqual((number, lookup.headers[0].state, lookup.headers[0].fd), (123456, "CLOSING", None))
        with patch.object(owner, "check"), patch.object(lookup, "recheck"), patch.object(os, "open", side_effect=opened), \
             patch.object(os, "fstat", return_value=value), patch.object(os, "read", return_value=elf()) as read, \
             patch.object(os, "close", side_effect=closed) as close:
            lookup._header(binding)
            lookup.close()
            self.assertEqual(close.call_count, 1)
            self.assertEqual(read.call_args.args, (123456, 264))
            self.assertTrue(lookup.closed)
            self.assertFalse(owner.lifetime_ledger.fatal)

    def test_header_open_return_loss_and_close_error_never_retry_numeric_custody(self):
        for phase in ("open", "close"):
            owner = guard()
            lookup = tools.ToolLookup("linux-gnu-x86_64", "/inert/project", owner)
            value = metadata(stat.S_IFREG | 0o755)
            binding = tools.ToolBinding("/usr/bin/git", (tools._Node("/usr/bin/git", "file", tools._file_facts(value)),))
            with patch.object(owner, "check"), patch.object(lookup, "recheck"), \
                 patch.object(os, "open", side_effect=OSError("opaque open loss") if phase == "open" else None, return_value=123456), \
                 patch.object(os, "fstat", return_value=value), patch.object(os, "read", return_value=elf()), \
                 patch.object(os, "close", side_effect=OSError("opaque close loss")) as close:
                with self.assertRaises(ProcessCleanupError): lookup._header(binding)
                with self.assertRaises(ProcessCleanupError): lookup.close()
                self.assertEqual(close.call_count, 0 if phase == "open" else 1)
                self.assertTrue(owner.lifetime_ledger.fatal)
                self.assertFalse(owner.cancelled)  # Custody failure is not an observed STOP.
                self.assertFalse(lookup.closed)
                self.assertEqual(lookup.headers[0].state, "UNKNOWN")

    def test_bounded_directory_iterator_is_original_retained_and_closed_once(self):
        class InertScan:
            def __init__(self, count, fail=False): self.values, self.closes, self.fail = iter(range(count)), 0, fail
            def __next__(self): return types.SimpleNamespace(name=f"jdk{next(self.values)}.jdk")
            def close(self):
                self.closes += 1
                if self.fail: raise OSError("opaque iterator close")
        for count, fail in ((33, False), (1, True)):
            owner = guard()
            lookup = tools.ToolLookup("macos-arm64", "/inert/project", owner)
            scan = InertScan(count, fail)
            with patch.object(owner, "check"), patch.object(os, "scandir", return_value=scan):
                with self.assertRaises(ProcessCleanupError if fail else tools.ToolUnavailable):
                    lookup._names("/Library/Java/JavaVirtualMachines")
                if fail:
                    with self.assertRaises(ProcessCleanupError): lookup.close()
                    self.assertIs(lookup.scans[0].iterator, scan)
                    self.assertTrue(owner.lifetime_ledger.fatal)
                else:
                    lookup.close()
                    self.assertTrue(lookup.closed)
                self.assertEqual(scan.closes, 1)


class InertLookup:
    """Narrow policy seam, not a real resolver, descriptor or native capability."""
    closed = True
    def __init__(self): self.rechecks = []
    def recheck(self, binding): self.rechecks.append(binding.path)
    def close(self): pass
    def linux_git(self): return tools.ToolBinding("/usr/bin/git", ())
    def linux_jdk(self): return tuple(tools.ToolBinding("/usr/lib/jvm/jdk-21/bin/" + role, ()) for role in ("java", "javac"))
    def mac_selector(self): return tools.ToolBinding("/usr/bin/xcode-select", ())
    def mac_developer(self, _raw): return tools.ToolBinding("/Applications/Xcode.app/Contents/Developer", ())
    def mac_developer_tool(self, developer, role): return tools.ToolBinding(developer.path + "/usr/bin/" + ("xcodebuild" if role == "xcode" else role), ())
    def mac_jdk(self): return tuple(tools.ToolBinding("/Library/Java/JavaVirtualMachines/jdk.jdk/Contents/Home/bin/" + role, ()) for role in ("java", "javac"))


class EnvironmentDiagnosticsServiceTests(unittest.TestCase):
    def service(self, *, platform="android", profile="linux-gnu-x86_64", data=None):
        stack = ExitStack()
        self.addCleanup(stack.close)
        owner, source = guard(), control.EnvironmentInput(100.0)
        source.acquired = True  # Inert admission DATA, no fd0 acquisition.
        owner._install_environment_source(source)
        lookup = InertLookup()
        stack.enter_context(patch.object(diagnostics, "ToolLookup", return_value=lookup))
        stack.enter_context(patch.object(diagnostics.time, "monotonic", return_value=100.0))
        stack.enter_context(patch.object(owner, "check", side_effect=lambda: (_ for _ in ()).throw(KeyboardInterrupt()) if owner.cancelled else None))
        stack.enter_context(patch.object(diagnostics.sys, "platform", "darwin" if profile.startswith("macos") else "linux"))
        stack.enter_context(patch.object(os, "uname", return_value=types.SimpleNamespace(machine=wire.PROFILES[profile][1])))
        stack.enter_context(patch.object(os, "getcwd", return_value="/inert/runtime"))
        req = request(platform, profile) if data is None else wire.parse_request(encoded(data))
        return diagnostics.DiagnosticsRun(req, owner, source), lookup

    @staticmethod
    def result(argv, **_kwargs):
        role = argv[0].rsplit("/", 1)[-1]
        output = {"git": b"git version 2.43.0\n", "javac": b"javac 21.0.8\n",
            "xcode-select": b"/Applications/Xcode.app/Contents/Developer\n",
            "xcodebuild": b"Xcode 26.2\nBuild version 17B111\n"}
        java = (b'openjdk version "21.0.8" 2025-07-15 LTS\nOpenJDK Runtime Environment (build 21.0.8+9-LTS)\n'
                b'OpenJDK 64-Bit Server VM (build 21.0.8+9-LTS, mixed mode, sharing)\n')
        return subprocess.CompletedProcess(argv, 0, b"" if role == "java" else output[role], java if role == "java" else b"")

    def test_real_service_routes_only_fixed_ordinary_seam_with_same_guard_and_bytes(self):
        service, _lookup = self.service()
        with patch.object(diagnostics, "run_owned", side_effect=self.result) as called:
            service.run()
        self.assertEqual(called.call_count, 3)
        self.assertTrue(service.roster_finished)
        self.assertEqual([row["reason"] for row in service.checks.values()], ["observed"] * 3)
        for call, argument in zip(called.call_args_list, ("--version", "-version", "-version")):
            self.assertEqual(call.args[0][1:], (argument,))
            self.assertEqual(set(call.kwargs), {"environ", "cwd", "timeout", "capture", "text", "output_limit", "cancellation"})
            self.assertEqual((call.kwargs["timeout"], call.kwargs["output_limit"], call.kwargs["capture"], call.kwargs["text"]), (3, 16_384, True, False))
            self.assertIs(call.kwargs["cancellation"], service.guard)
            self.assertEqual(str(call.kwargs["cwd"]), "/inert/runtime")
        # Mocked CompletedProcess cannot mint actual owner/handler settlement.
        self.assertEqual(service.terminal()["outcome"], "partial")
        self.assertFalse(service.terminal()["lifetime"]["handlersRestored"])

    def test_ios_linux_disabled_and_invalid_draft_do_not_lookup_or_run_tools(self):
        cases = [(request_data("ios"), "host-mismatch")]
        disabled = request_data()
        disabled["draft"]["android"] = {"enabled": False}
        invalid = request_data()
        invalid["draft"] = {"PRIVATE_DRAFT_SENTINEL": True}
        cases.extend(((disabled, "platform-disabled"), (invalid, "invalid-draft")))
        for data, reason in cases:
            service, lookup = self.service(data=data)
            with patch.object(diagnostics, "run_owned", side_effect=AssertionError("tool execution")), \
                 patch.object(lookup, "linux_git", side_effect=AssertionError("tool lookup")), \
                 patch.object(os, "lstat", side_effect=AssertionError("project or tool read")):
                service.run()
            self.assertEqual(service.commands_attempted, 0)
            self.assertEqual({row["reason"] for row in service.checks.values()}, {reason})
            self.assertNotIn("PRIVATE_DRAFT_SENTINEL", json.dumps(list(service.checks.values())))

    def test_mac_xcode_mismatch_is_completed_negative_not_owner_failure(self):
        service, _lookup = self.service(platform="ios", profile="macos-arm64")
        with patch.object(diagnostics, "run_owned", side_effect=self.result) as called:
            service.run()
        self.assertEqual(called.call_count, 3)
        self.assertEqual(service.checks["xcode"]["assessment"], "mismatch")
        self.assertEqual(service.checks["xcode"]["state"], "completed")
        self.assertIsNone(service.primary)
        xcode = called.call_args_list[-1]
        self.assertEqual(xcode.kwargs["environ"]["DEVELOPER_DIR"], "/Applications/Xcode.app/Contents/Developer")
        self.assertIsNone(service.checks["developer-selection"]["version"])

    def test_mac_selection_detail_uses_original_negative_call_not_raw_data_or_new_git(self):
        service, lookup = self.service(platform="ios", profile="macos-arm64")
        with patch.object(diagnostics, "run_owned", return_value=subprocess.CompletedProcess(
                ("/usr/bin/xcode-select", "-p"), 0, b"PRIVATE_PATH", b"PRIVATE_DIAGNOSTIC")) as call, \
             patch.object(lookup, "mac_developer", side_effect=AssertionError("stderr refused before path lookup")), \
             patch.object(lookup, "mac_developer_tool", side_effect=AssertionError("no Git or Xcode")):
            service.run()
        self.assertEqual(call.call_count, 1)
        check = service.checks["developer-selection"]
        self.assertEqual((check["state"], check["reason"], check["returnCode"]), ("completed", "selection-unrecognized", 0))
        self.assertEqual(check["selectionDiagnostic"], {"stage": "selector-output", "reason": "stderr-present"})
        self.assertNotIn("PRIVATE", json.dumps(service.checks))
        self.assertEqual(service.commands_attempted, 1)
        legacy = tools.ToolUnavailable()
        # A fresh in-memory service, not another call on the completed run.
        fresh, other = self.service(platform="ios", profile="macos-arm64")
        with patch.object(diagnostics, "run_owned", side_effect=self.result), patch.object(other, "mac_developer", side_effect=legacy):
            fresh.run()
        self.assertNotIn("selectionDiagnostic", fresh.checks["developer-selection"])

    def test_mac_developer_recheck_binding_changed_is_not_a_completed_selection_detail(self):
        service, lookup = self.service(platform="ios", profile="macos-arm64")
        original = tools.BindingChanged("PRIVATE_PATH")
        def recheck(binding):
            if binding.path.endswith("/Developer"): raise original
        with patch.object(diagnostics, "run_owned", side_effect=self.result) as call, patch.object(lookup, "recheck", side_effect=recheck):
            with self.assertRaises(tools.BindingChanged) as caught: service.run()
        self.assertIs(caught.exception, original)
        service.remember(original)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(service.checks["developer-selection"]["reason"], "binding-changed")
        self.assertNotIn("selectionDiagnostic", service.checks["developer-selection"])

    def test_opaque_process_error_retains_original_facts_and_stops_without_new_probe(self):
        service, lookup = self.service()
        original = ProcessError("PRIVATE_ERROR: timed out or output cap", dispatched=True)
        def failure(argv, **kwargs):
            if argv[0].endswith("/java"): raise original
            return self.result(argv, **kwargs)
        with patch.object(diagnostics, "run_owned", side_effect=failure) as called:
            with self.assertRaises(ProcessError) as caught: service.run()
            self.assertIs(caught.exception, original)
            service.remember(caught.exception)
        self.assertEqual(called.call_count, 2)
        self.assertEqual(len(lookup.rechecks), 3)  # Git pre/post; Java pre; never post-error.
        self.assertEqual(service.checks["java"]["reason"], "command-incomplete")
        self.assertEqual(service.checks["javac"]["reason"], "stopped")
        self.assertIs(service.primary, original)
        self.assertEqual((original.dispatched, original.contained, original.cleanup_complete), (True, True, True))
        self.assertEqual(service.source.stop_reason, "none")
        self.assertNotIn("PRIVATE_ERROR", json.dumps(service.terminal()))

    def test_fatal_nested_lifetime_or_close_failure_without_stop_stays_failed_unknown(self):
        for primary in (ProcessError("opaque fatal", dispatched=True, contained=False), ProcessCleanupError("opaque close")):
            service, _lookup = self.service()
            later = OSError("opaque later cleanup")
            later.__context__ = primary
            service.remember(later)
            service.close()
            result = service.terminal()
            self.assertTrue(result["lifetime"]["fatal"])
            self.assertEqual(result["lifetime"]["stopObserved"], "none")
            self.assertEqual(result["outcome"], "failed")
            self.assertTrue(primary.dispatched or isinstance(primary, ProcessCleanupError))

    def test_complete_nonzero_and_unrecognized_output_do_not_leak_or_stop_roster(self):
        service, _lookup = self.service()
        def returned(argv, **kwargs):
            if argv[0].endswith("/git"): return subprocess.CompletedProcess(argv, 7, b"PRIVATE_OUTPUT_SENTINEL", b"PRIVATE_STDERR")
            if argv[0].endswith("/java"): return subprocess.CompletedProcess(argv, 0, b"", b"PRIVATE_UNPARSEABLE_VERSION")
            return self.result(argv, **kwargs)
        with patch.object(diagnostics, "run_owned", side_effect=returned) as called: service.run()
        self.assertEqual(called.call_count, 3)
        self.assertEqual(service.checks["git"]["reason"], "nonzero-exit")
        self.assertEqual(service.checks["git"]["returnCode"], 7)
        self.assertEqual(service.checks["java"]["reason"], "version-unrecognized")
        self.assertTrue(service.roster_finished)
        self.assertNotIn("PRIVATE_", json.dumps(list(service.checks.values())))

    def test_shared_child_deadline_integer_margin_and_no_subsecond_call(self):
        service, lookup = self.service()
        with patch.object(diagnostics.time, "monotonic", return_value=104.2), \
             patch.object(diagnostics, "run_owned", side_effect=self.result) as called:
            service._version("git", lookup.linux_git())
        self.assertEqual(called.call_args.kwargs["timeout"], 1)
        with patch.object(diagnostics.time, "monotonic", return_value=105.1), \
             patch.object(diagnostics, "run_owned", side_effect=AssertionError("late command")) as called:
            with self.assertRaises(KeyboardInterrupt): service._call("java", lookup.linux_jdk()[0])
        self.assertEqual(called.call_count, 0)
        self.assertEqual((service.commands_attempted, service.source.work_end, service.source.stop_reason), (1, 106.0, "timed-out"))


class EnvironmentDiagnosticsControlTests(unittest.TestCase):
    def input(self):
        owner, source = guard(), control.EnvironmentInput(100.0)
        source.fd, source.acquired, source.identity = 0, True, (1, 2, stat.S_IFIFO | 0o600)
        owner._install_environment_source(source)
        return owner, source

    def test_single_request_then_eof_or_any_extra_byte_is_stop_not_another_request(self):
        for suffix in (b"", b"NEXT_FRAME"):
            owner, source = self.input()
            source.buffer.extend(encoded(request_data()) + suffix)
            with patch.object(control.time, "monotonic", return_value=100.0), \
                 patch.object(os, "fstat", return_value=metadata(stat.S_IFIFO | 0o600, inode=2)), \
                 patch.object(os, "read", side_effect=BlockingIOError):
                if suffix:
                    with self.assertRaises(KeyboardInterrupt): source.request()
                    self.assertFalse(source.request_returned)
                else:
                    self.assertEqual(source.request().run_id, "a" * 32)
                    with self.assertRaises(wire.ProtocolError): source.request()
            self.assertEqual(source.stop_reason, "cancelled" if suffix else "none")
        for returned in (b"", b"x"):
            owner, source = self.input()
            source.active = True
            with patch.object(control.time, "monotonic", return_value=100.0), \
                 patch.object(os, "fstat", return_value=metadata(stat.S_IFIFO | 0o600, inode=2)), patch.object(os, "read", return_value=returned):
                owner._poll_edit_stop()
            self.assertTrue(owner.cancelled)
            self.assertEqual(source.stop_reason, "cancelled")

    def test_cutoff_is_original_and_identity_loss_is_sticky_not_successful_eof(self):
        owner, source = self.input()
        with patch.object(control.time, "monotonic", return_value=106.0), patch.object(os, "read", side_effect=AssertionError("late read")):
            owner._poll_edit_stop()
        self.assertEqual(source.stop_reason, "timed-out")
        self.assertEqual(source.work_end, 106.0)
        owner, source = self.input()
        with patch.object(control.time, "monotonic", return_value=100.0), \
             patch.object(os, "fstat", return_value=metadata(stat.S_IFIFO | 0o600, inode=3)), patch.object(os, "close") as close:
            owner._poll_edit_stop()
            with self.assertRaises(wire.ProtocolError): source.close()
            with self.assertRaises(wire.ProtocolError): source.close()
            close.assert_not_called()
        self.assertTrue(owner.lifetime_ledger.fatal)
        self.assertFalse(source.closed)

    def test_sealed_sources_are_mutually_exclusive_and_cannot_rebind_after_close(self):
        from mobile_release._desktop_edit_control import EditInput
        owner, source = self.input()
        with self.assertRaises(wire.ProtocolError): owner._install_environment_source(object())
        edit = EditInput(100.0)
        edit.acquired = True
        with self.assertRaises(wire.ProtocolError): owner._install_edit_source(edit)
        with patch.object(os, "fstat", return_value=metadata(stat.S_IFIFO | 0o600, inode=2)), patch.object(os, "close") as close:
            source.close()
            source.close()
            close.assert_called_once_with(0)
        with self.assertRaises(wire.ProtocolError): owner._install_edit_source(edit)
        with self.assertRaises(wire.ProtocolError): owner._install_environment_source(source)

    def test_engine_attempts_both_original_cleanups_after_first_failure(self):
        original = engine._Engine(100.0)  # Constructor only, no install/IO.
        failure = ProcessCleanupError("original lookup cleanup")
        service = types.SimpleNamespace(close=Mock(side_effect=failure))
        original.service = service
        with patch.object(original.input, "close", side_effect=OSError("input close")) as close:
            with self.assertRaises(ProcessCleanupError) as caught: original.cleanup()
        self.assertIs(caught.exception, failure)
        service.close.assert_called_once_with()
        close.assert_called_once_with()
        self.assertTrue(original.guard.lifetime_ledger.fatal)

    def test_engine_aggregate_frames_and_absolute_terminal_cutoff_do_not_renew(self):
        original = engine._Engine(100.0)
        original.output.owned, original.output.identity = True, (1, 2, stat.S_IFIFO | 0o600)
        with patch.object(original.guard, "check"), patch.object(engine.time, "monotonic", return_value=101.0), \
             patch.object(os, "fstat", return_value=metadata(stat.S_IFIFO | 0o600, inode=2)), patch.object(os, "write", side_effect=lambda _fd, raw: len(raw)):
            original.write(b"accepted\n")
            with self.assertRaises(wire.ProtocolError): original.write(b"second accepted\n")
            with self.assertRaises(wire.ProtocolError): original.write(b"x" * wire.RESPONSE_LIMIT, terminal=True)
        with patch.object(engine.time, "monotonic", return_value=110.0), patch.object(os, "write") as called:
            with self.assertRaises(wire.ProtocolError): original.write(b"terminal\n", terminal=True)
            called.assert_not_called()
        self.assertEqual((wire.WORK_SECONDS, wire.FINALITY_SECONDS, wire.CALL_SECONDS), (6.0, 10.0, 3))
        for hidden_failure in (100.0, 100.001, 105.999, 109.0):
            self.assertLessEqual(100.0 + wire.FINALITY_SECONDS, hidden_failure + 10.0)


if __name__ == "__main__":
    unittest.main()
