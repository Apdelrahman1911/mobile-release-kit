"""Artifact DATA tests; no native/tool/original cleanup qualification."""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import unittest

from unittest.mock import patch
from mobile_release import darwin_memory
from mobile_release import artifact_inspection as data
from mobile_release import _desktop_artifact_inspection_protocol as wire
from mobile_release.errors import ValidationError


def context_data(format="ipa", count=1):
    roles = ("artifact", "archive", "dsyms")
    return {"projectId": "project-1", "draftRevision": 3, "baselineGeneration": 2,
            "savedConfig": {"bytes": 41, "sha256": "1" * 64}, "format": format,
            "selections": {role: str(index + 1) * 32 if index < count else None
                           for index, role in enumerate(roles)}}


def result_data(format="ipa", count=1):
    selected = context_data(format, count)
    artifacts = []
    for role, token in selected["selections"].items():
        if token is None:
            continue
        kind = "file" if role == "artifact" else "directory"
        artifacts.append({"role": role, "selectionId": token, "label": role,
                          "kind": kind, "bytes": 7 if role == "artifact" else 0, "entries": 1,
                          "identity": {"method": "sha256-file" if kind == "file" else "sha256-tree-v1",
                                       "sha256": "3" * 64}})
    checks = [{"check": check, "status": "pass", "reason": "none"} for check in wire.CHECKS]
    for row in checks:
        if format == "aab" and row["check"] in ("profile-entitlements", "archive-pair", "symbols"):
            row.update(status="not_applicable")
        elif format == "aab" and row["check"] == "current-validity":
            row.update(status="unavailable", reason="prerequisite-not-run")
        elif format == "ipa" and row["check"] == "archive-pair" and count < 2:
            row.update(status="unavailable", reason="archive-not-selected")
        elif format == "ipa" and row["check"] == "symbols" and count < 3:
            row.update(status="unavailable", reason="symbols-not-selected")
    return {"schemaVersion": 1, "scope": wire.SCOPE, "format": format,
            "usedConfig": selected["savedConfig"],
            "usedVersion": {"bytes": 8, "sha256": "2" * 64, "name": "1.2.3", "build": 7},
            "artifacts": artifacts,
            "observed": {"applicationId": "com.example.reader" if format == "aab" else None,
                         "bundleId": "com.example.reader" if format == "ipa" else None,
                         "versionName": "1.2.3", "versionBuild": "7", "signerSha256": None, "teamId": None},
            "checks": checks, "limitations": list(wire.LIMITATIONS)}


class ArtifactInspectionDataTests(unittest.TestCase):
    def test_canonical_tree_encoding_binds_root_empty_directories_names_sizes_and_hashes(self):
        empty_sha, body_sha = hashlib.sha256(b"").hexdigest(), hashlib.sha256(b"abc").hexdigest()
        root = data.TreeEntryData("directory", "", 0, None)
        rows = (root, data.TreeEntryData("file", "empty", 0, empty_sha),
                data.TreeEntryData("directory", "folder", 0, None),
                data.TreeEntryData("file", "folder/x", 3, body_sha))
        expected = (b"mrk-artifact-tree-v1\0" + struct.pack(">Q", 4)
                    + b"D" + struct.pack(">I", 0)
                    + b"F" + struct.pack(">I", 5) + b"empty" + struct.pack(">Q", 0) + bytes.fromhex(empty_sha)
                    + b"D" + struct.pack(">I", 6) + b"folder"
                    + b"F" + struct.pack(">I", 8) + b"folder/x" + struct.pack(">Q", 3) + bytes.fromhex(body_sha))
        digest, entries, size = data.tree_identity_data(rows)
        self.assertEqual((digest, entries, size), (hashlib.sha256(expected).hexdigest(), 4, 3))
        self.assertEqual(data.tree_identity_data((root,)),
                         (hashlib.sha256(b"mrk-artifact-tree-v1\0" + struct.pack(">Q", 1) + b"D\0\0\0\0").hexdigest(), 1, 0))
        for changed in (
            rows[:-1], rows[:2] + (data.TreeEntryData("directory", "g", 0, None),),
            rows[:-1] + (data.TreeEntryData("file", "folder/x", 4, body_sha),),
            rows[:-1] + (data.TreeEntryData("file", "folder/x", 3, empty_sha),),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(data.tree_identity_data(changed)[0], digest)
        invalid = (
            (), list(rows), rows[1:], (root, rows[2], rows[1], rows[3]),
            (root, rows[1], rows[1]), (root, rows[3]),
            (root, data.TreeEntryData("directory", "Folder", 0, None),
             data.TreeEntryData("directory", "folder", 0, None)),
            (root, data.TreeEntryData("directory", "e\u0301", 0, None),
             data.TreeEntryData("directory", "\u00e9", 0, None)),
            (root, data.TreeEntryData("directory", "bad", 1, None)),
            (root, data.TreeEntryData("file", "x", True, body_sha)),
            (root, data.TreeEntryData("file", "x", -1, body_sha)),
            (root, data.TreeEntryData("file", "x", 4 * data.GIB + 1, body_sha)),
            (root, data.TreeEntryData("file", "x", 1, body_sha.upper())),
            (root, data.TreeEntryData("file", "../x", 1, body_sha)),
            (root, data.TreeEntryData("file", "a\\x", 1, body_sha)),
        )
        for rows_bad in invalid:
            with self.subTest(invalid=rows_bad), self.assertRaises((data.ArtifactInspectionLimitError, ValidationError)):
                data.tree_identity_data(rows_bad)

    def test_fixed_prospective_limits_include_raw_unicode_profiles_and_combined_descriptors(self):
        data.aab_directory_data(32768, 8 * data.MIB, data.GIB, 2 * data.GIB)
        data.namespace_data(8192, 2 * data.MIB, 2 * data.MIB)
        for bad in ((32769, 1, 1, 1), (1, 8 * data.MIB + 1, 1, 1), (1, 1, data.GIB + 1, 1), (True, 1, 1, 1)):
            with self.subTest(aab=bad), self.assertRaises(data.ArtifactInspectionLimitError):
                data.aab_directory_data(*bad)
        for bad in ((8193, 0, 0), (1, 2 * data.MIB + 1, 0), (1, 0, 2 * data.MIB + 1), (0, 0, 0)):
            with self.subTest(namespace=bad), self.assertRaises(data.ArtifactInspectionLimitError):
                data.namespace_data(*bad)
        self.assertEqual(data.decode_budget_data(127, 4 * data.MIB - 1, 1), (128, 4 * data.MIB))
        for args in ((128, 0, 1), (0, 4 * data.MIB, 1), (0, 0, 256 * data.KIB + 1), (False, 0, 1)):
            with self.subTest(decode=args), self.assertRaises(data.ArtifactInspectionLimitError):
                data.decode_budget_data(*args)
        self.assertEqual(data.slice_budget_data(8160, 32), 8192)
        for args in ((8192, 1), (0, 33), (0, True)):
            with self.subTest(slices=args), self.assertRaises(data.ArtifactInspectionLimitError):
                data.slice_budget_data(*args)
        maximum = dict(decode_calls=128, decode_raw=4 * data.MIB, capture_raw=32 * data.MIB,
                       max_capture_cap=8 * data.MIB, profile_loads=1)
        # Raw captured bytes AND their four-byte Unicode form, plus active join.
        self.assertEqual(data.control_quote_data(**maximum), 992 * data.MIB)
        with self.assertRaises(data.ArtifactInspectionLimitError):
            data.control_quote_data(**{**maximum, "profile_loads": 2})
        for field in maximum:
            with self.subTest(field=field), self.assertRaises(data.ArtifactInspectionLimitError):
                data.control_quote_data(**{**maximum, field: True})
        self.assertEqual(data.descriptor_quote_data(16, 112, 64), 192)
        with self.assertRaises(data.ArtifactInspectionLimitError):
            data.descriptor_quote_data(16, 113, 64)
        quote = data.profile_quote_data(profile_loads=0, call_units=4088, decode_calls=0,
                                       decode_raw=0, capture_raw=0, max_capture_cap=0,
                                       parent_reserved=16, core_live=112)
        self.assertEqual((quote.profile_loads, quote.call_units, quote.live_descriptors, quote.private_disk_bytes),
                         (1, 4096, 192, 40 * data.MIB))
        self.assertEqual(quote.control_bytes, 608 * data.MIB + data.PROFILE_CAPTURE * 4)
        with self.assertRaises(data.ArtifactInspectionLimitError):
            data.profile_quote_data(profile_loads=0, call_units=4089, decode_calls=0,
                                    decode_raw=0, capture_raw=0, max_capture_cap=0,
                                    parent_reserved=16, core_live=112)
        self.assertEqual(data.capture_quote_data(30 * data.MIB, "aab"), 2 * data.MIB)
        with self.assertRaises(data.ArtifactInspectionLimitError):
            data.capture_quote_data(30 * data.MIB + 1, "aab")
        self.assertEqual(data.capture_quote_data(0, "ipa"), 8 * data.MIB)
        self.assertEqual(data.capture_quote_data(0, "profile"), data.PROFILE_CAPTURE)
        self.assertEqual(data.captured_bytes_data(30 * data.MIB, 17, 2 * data.MIB), 30 * data.MIB + 17)
        # Unknown consumption is conservatively the WHOLE already reserved cap,
        # not a fabricated zero-output/known-return observation.
        self.assertEqual(data.captured_bytes_data(30 * data.MIB, 2 * data.MIB, 2 * data.MIB), 32 * data.MIB)
        with self.assertRaises(data.ArtifactInspectionLimitError):
            data.captured_bytes_data(0, 2 * data.MIB + 1, 2 * data.MIB)


        # Actual Darwin probe control body; no libSystem load, port, IO or native claim.
        def probe_case(*, page=4096, free=11, speculative=3, count=24,
                       page_result=0, stats_result=0, close_result=0,
                       acquire_error=None, read_error=None, close_error=None, stop=None):
            calls = []
            clock_error = ValidationError("inert same-owner clock")
            ticks = 0

            def check():
                nonlocal ticks
                ticks += 1
                calls.append(("check", ticks))
                if ticks == stop:
                    raise clock_error

            def acquire():
                calls.append(("acquire",))
                if acquire_error is not None:
                    raise acquire_error
                return 41

            def read_page(host, output):
                self.assertEqual(host, 41)
                calls.append(("page",))
                if read_error is not None:
                    raise read_error
                output._obj.value = page
                return page_result

            def read_stats(host, flavor, output, words):
                self.assertEqual((host, flavor, words._obj.value), (41, 4, 24))
                calls.append(("statistics",))
                value = darwin_memory.ctypes.cast(
                    output, darwin_memory.ctypes.POINTER(darwin_memory._VMStatistics64Rev0)).contents
                value.free_count, value.speculative_count = free, speculative
                value.inactive_count, value.purgeable_count = 9999, 8888
                words._obj.value = count
                return stats_result

            def retire(task, host):
                self.assertEqual((task, host), (7, 41))
                calls.append(("retire",))
                if close_error is not None:
                    raise close_error
                return close_result

            def run():
                with patch.object(darwin_memory.sys, "platform", "darwin"), patch.object(
                        darwin_memory, "_bindings", return_value=(acquire, read_page, read_stats, retire, 7)):
                    return darwin_memory.sampled_free_bytes(check=check)
            return run, calls, clock_error

        for page, free, speculative in ((4096, 11, 3), (16384, 11, 3), (4096, 0, 0),
                                        (16384, 0xffffffff, 0xffffffff)):
            run, calls, _ = probe_case(page=page, free=free, speculative=speculative)
            self.assertEqual(run(), page * free)  # Speculative already included; no inactive/purgeable credit.
            self.assertEqual([row[0] for row in calls if row[0] != "check"],
                             ["acquire", "page", "statistics", "retire"])
            self.assertEqual(calls[-1], ("check", 6))
        for invalid in ({"page": 0}, {"page": 8192}, {"count": 23}, {"count": 25},
                        {"speculative": 12}, {"page_result": 5}, {"stats_result": 5}):
            run, calls, _ = probe_case(**invalid)
            with self.assertRaises(darwin_memory.DarwinMemoryUnavailable):
                run()
            self.assertEqual(calls.count(("retire",)), 1)
        for stop in range(1, 7):
            run, calls, error = probe_case(stop=stop)
            with self.assertRaises(ValidationError) as caught:
                run()
            self.assertIs(caught.exception, error)
            self.assertEqual(calls.count(("retire",)), int(stop >= 3))
        for error in (OSError("inert acquisition"), KeyboardInterrupt(), SystemExit(7)):
            run, calls, _ = probe_case(acquire_error=error)
            with self.assertRaises(darwin_memory.DarwinMemoryCleanupUnknown) as caught:
                run()
            self.assertIs(caught.exception.__cause__, error)
            self.assertEqual(calls.count(("acquire",)), 1)
            self.assertNotIn(("retire",), calls)
        for error in (OSError("inert close"), KeyboardInterrupt(), SystemExit(8)):
            for primary in (None, ValidationError("inert first read failure")):
                run, calls, _ = probe_case(read_error=primary, close_error=error)
                with self.assertRaises(darwin_memory.DarwinMemoryCleanupUnknown) as caught:
                    run()
                self.assertIs(caught.exception.__cause__, primary if primary is not None else error)
                self.assertEqual(calls.count(("retire",)), 1)
        run, calls, _ = probe_case(close_result=5)
        with self.assertRaises(darwin_memory.DarwinMemoryCleanupUnknown):
            run()
        self.assertEqual(calls.count(("retire",)), 1)
        primary = ValidationError("inert read with known retirement")
        run, calls, _ = probe_case(read_error=primary)
        with self.assertRaises(ValidationError) as caught:
            run()
        self.assertIs(caught.exception, primary)
        self.assertEqual(calls.count(("retire",)), 1)
        with patch.object(darwin_memory.sys, "platform", "linux"), patch.object(
                darwin_memory, "_bindings", side_effect=AssertionError("must not load native library")):
            with self.assertRaises(darwin_memory.DarwinMemoryUnavailable):
                darwin_memory.sampled_free_bytes(check=lambda: None)

        # The actual shared Android _point/_charge path must enter the same
        # operation clock before any work debit. These guard/source/clock ports
        # are inert DATA, not an admitted picker, tool, process or native owner.
        import os
        import threading
        from types import SimpleNamespace
        from mobile_release import desktop_artifact_inspection as service
        from mobile_release.android_build_tools import AndroidValidationTools

        cases = (
            ("work", 0, False, False, 95.0, None, False, "ok"),
            ("work-stop", 0, False, False, 95.0, None, True, "stop"),
            ("work-expired", 0, False, False, 100.0, None, False, "stop"),
            ("guarded-original", 1, False, False, 105.0, None, True, "ok"),
            ("guarded-original-expired", 1, False, False, 110.0, None, True, "cleanup"),
            ("closing", 0, True, True, 105.0, None, True, "ok"),
            ("closing-expired", 0, True, True, 110.0, None, True, "cleanup"),
            ("guarded-first-failure", 1, False, False, 54.0, 45.0, True, "ok"),
            ("guarded-first-failure-expired", 1, False, False, 55.0, 45.0, True, "cleanup"),
        )
        for name, depth, closing, tool_cleanup, now, first_failure, stopped, expected in cases:
            with self.subTest(shared_point=name):
                events, remembered, aborted = [], [], []
                stopped_error = ValidationError("inert original stop")
                prior = ValidationError("inert first original failure") if first_failure is not None else None
                state = {"stopped": stopped}

                def check():
                    events.append("work-check")
                    if state["stopped"]:
                        raise stopped_error

                def stop(reason):
                    events.append(("stop", reason))
                    state["stopped"] = True

                def failure_observed():
                    events.append("failure-observed")
                    if source.first_failure is None:
                        source.first_failure = now

                guard = SimpleNamespace(depth=depth, check=check,
                                        lifetime_ledger=SimpleNamespace(_remember=remembered.append),
                                        _abort=aborted.append)
                source = SimpleNamespace(guard=guard, work_end=100.0,
                                         first_failure=first_failure, stop=stop,
                                         failure_observed=failure_observed)
                operation = object.__new__(service.ArtifactInspectionOperation)
                operation.pid, operation.thread = os.getpid(), threading.current_thread()
                operation.guard, operation.source = guard, source
                source.operation = operation
                operation.close_claimed, operation.unknown = closing, False
                operation.primary, operation.counters = prior, {"tool-checkpoints": 7}
                tools = SimpleNamespace(operation=operation, guard=guard,
                                        _cleanup_mode=tool_cleanup, _close_claimed=tool_cleanup,
                                        _owner=lambda *, active: events.append(("tool-owner", active)))
                tools._point = lambda: AndroidValidationTools._point(tools)
                before = dict(operation.counters)
                caught = None
                with patch.object(service.time, "monotonic", return_value=now):
                    try:
                        AndroidValidationTools._charge(tools, "walk", 2, 10)
                    except BaseException as error:
                        caught = error
                self.assertEqual(events[0], ("tool-owner", not tool_cleanup))
                self.assertEqual(source.work_end, 100.0)
                if expected == "ok":
                    self.assertIsNone(caught)
                    self.assertEqual(operation.counters,
                                     {"tool-checkpoints": 8 if name == "work" else 7, "walk": 2})
                    self.assertEqual(events.count("work-check"), 2 if name == "work" else 0)
                    self.assertIs(operation.primary, prior)
                    self.assertEqual(source.first_failure, first_failure)
                    self.assertFalse(remembered)
                    self.assertFalse(aborted)
                    self.assertFalse(operation.unknown)
                else:
                    self.assertEqual(operation.counters, before)
                    if expected == "stop":
                        self.assertIs(caught, stopped_error)
                        self.assertEqual(events.count("work-check"), 2 if name == "work-expired" else 1)
                        self.assertEqual(("stop", "timed-out") in events, name == "work-expired")
                        self.assertIs(operation.primary, prior)
                        self.assertEqual(source.first_failure, first_failure)
                        self.assertFalse(remembered)
                        self.assertFalse(aborted)
                        self.assertFalse(operation.unknown)
                    else:
                        self.assertIsInstance(caught, service.ArtifactInspectionRefused)
                        self.assertEqual(caught.reason, "cleanup-unknown")
                        self.assertNotIn("work-check", events)
                        self.assertEqual(len(remembered), 1)
                        self.assertEqual(remembered[0].reason, "cleanup-unknown")
                        self.assertEqual(aborted, remembered)
                        self.assertIs(operation.primary, prior if prior is not None else remembered[0])
                        self.assertEqual(source.first_failure, first_failure if first_failure is not None else now)
                        self.assertTrue(operation.unknown)
                # A guarded original publication/POST uses the established
                # settlement bound; depth is not a completed-cleanup receipt.
                self.assertEqual(guard.depth, depth)

    def test_context_and_result_are_closed_correlated_and_do_not_upgrade_unavailable_checks(self):
        for format, count in (("aab", 1), ("ipa", 1), ("ipa", 2), ("ipa", 3)):
            with self.subTest(format=format, count=count):
                wanted, result = context_data(format, count), result_data(format, count)
                self.assertEqual(wire.context(wanted), wanted)
                self.assertEqual(wire.validate_result(result, wanted), result)
                encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                self.assertLessEqual(len(encoded), wire.RESULT_LIMIT)
        wanted = context_data("ipa", 3)
        for key, value in (("native", {}), ("path", "/not-a-renderer-source"), ("deadline", 900), ("expectedSigner", "0" * 64)):
            with self.subTest(extra=key), self.assertRaises(wire.ProtocolError):
                wire.context({**wanted, key: value})
        for changed in (
            {**wanted, "draftRevision": True}, {**wanted, "savedConfig": {"bytes": 0, "sha256": "1" * 64}},
            {**wanted, "selections": {"artifact": "1" * 32, "archive": None, "dsyms": "3" * 32}},
            {**wanted, "selections": {"artifact": "1" * 32, "archive": "1" * 32, "dsyms": None}},
            {**wanted, "format": "aab"},
        ):
            with self.subTest(context=changed), self.assertRaises(wire.ProtocolError):
                wire.context(changed)
        base = result_data("ipa", 3)
        mutations = []
        def mutate(action):
            value = copy.deepcopy(base)
            action(value)
            mutations.append(value)
        mutate(lambda value: value.update(rawNativeOutput="never exported"))
        mutate(lambda value: value["usedVersion"].update(build="7"))
        mutate(lambda value: value["usedVersion"].update(build=True))
        mutate(lambda value: value["usedVersion"].update(name="x" * 65))
        mutate(lambda value: value["usedConfig"].update(sha256="4" * 64))
        mutate(lambda value: value["artifacts"][0].update(selectionId="4" * 32))
        mutate(lambda value: value["artifacts"][0].update(entries=2))
        mutate(lambda value: value["artifacts"][0].update(label="artifact\u0085label"))
        mutate(lambda value: value["artifacts"][1].update(entries=0))
        mutate(lambda value: value["artifacts"][1].update(bytes=16 * data.GIB))
        mutate(lambda value: value["artifacts"][1]["identity"].update(method="sha256-file"))
        mutate(lambda value: value["observed"].pop("teamId"))
        mutate(lambda value: value["observed"].update(applicationId="wrong-platform"))
        mutate(lambda value: value["checks"].pop())
        mutate(lambda value: value["checks"].reverse())
        mutate(lambda value: value["checks"][5].update(status="unavailable", reason="none"))
        mutate(lambda value: value["checks"][8].update(status="pass", reason="saved-policy-missing"))
        mutate(lambda value: value["checks"][9].update(status="unavailable", reason="archive-not-selected"))
        mutate(lambda value: value["limitations"].pop())
        for index, value in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(wire.ProtocolError):
                wire.validate_result(value, wanted)
        known_negative = copy.deepcopy(base)
        known_negative["checks"][8].update(status="unavailable", reason="saved-policy-missing")
        known_negative["checks"][9].update(status="fail", reason="pair-mismatch")
        self.assertEqual(wire.validate_result(known_negative, wanted), known_negative)
        aab = result_data("aab")
        aab["checks"][7].update(status="pass", reason="none")
        with self.assertRaises(wire.ProtocolError):
            wire.validate_result(aab, context_data("aab"))
        empty = result_data("ipa")
        empty["artifacts"][0]["bytes"] = 0
        with self.assertRaises(wire.ProtocolError):
            wire.validate_result(empty, context_data("ipa"))
        empty["checks"][1].update(status="fail", reason="malformed-structure")
        self.assertEqual(wire.validate_result(empty, context_data("ipa")), empty)

        # Private transport DATA remains closed; these records confer no native
        # picker, descriptor, tool or process-return authority.
        identity = {"device": "1", "inode": "2", "mode": 0o100600, "uid": 1000, "gid": 1000,
                    "nlink": "1", "bytes": "7", "mtimeSeconds": "-1", "mtimeNanos": 2,
                    "ctimeSeconds": "3", "ctimeNanos": 4, "flags": 0}
        request_value = {"protocol": wire.PROTOCOL, "operationId": "4" * 32, "ownerGeneration": "5" * 32,
            "context": context_data("aab"), "native": {"profile": "macos-arm64", "projectRoot": "/project",
            "rootIdentity": {"device": "1", "inode": "9", "mode": 0o40700, "uid": 1000, "gid": 1000},
            "cwd": "/runtime", "parentDescriptorReservation": 8,
            "originals": [{"selectionId": "1" * 32, "role": "artifact", "path": "/chosen/app.aab",
                           "kind": "file", "identity": identity}], "tools": {"android": None, "ios": None}}}
        def encoded_request(value):
            return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        request = wire.parse_request(encoded_request(request_value))
        self.assertEqual(request.context, context_data("aab"))
        self.assertEqual(request.native, request_value["native"])
        request_mutations = (
            lambda v: v.update(extra=True),
            lambda v: v.update(protocol="mrk-ios-archive/1"),
            lambda v: v["native"].update(parentDescriptorReservation=True),
            lambda v: v["native"].update(parentDescriptorReservation=193),
            lambda v: v["native"].update(profile="linux-x86_64"),
            lambda v: v["native"].update(tools={"android": None}),
            lambda v: v["native"]["tools"].update(ios="macos-artifact-ios-system-v1"),
            lambda v: v["native"]["originals"][0].update(selectionId="3" * 32),
            lambda v: v["native"]["originals"][0].update(path="/chosen/a\u0085.aab"),
            lambda v: v["native"]["originals"][0].update(kind="directory"),
            lambda v: v["native"]["originals"][0]["identity"].update(nlink="2"),
            lambda v: v["native"]["originals"][0]["identity"].update(bytes="01"),
            lambda v: v["native"]["originals"][0]["identity"].update(mtimeSeconds="-0"),
            lambda v: v["native"]["originals"][0]["identity"].update(mtimeNanos=1_000_000_000),
        )
        for index, change in enumerate(request_mutations):
            value = copy.deepcopy(request_value)
            change(value)
            with self.subTest(request=index), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded_request(value))
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(encoded_request(request_value) + b"\n")
        terminal = {"schemaVersion": 1, "context": request.context, "outcome": "complete", "reason": "none",
            "result": result_data("aab"), "lifetime": {"complete": True, "fatal": False, "contained": True,
            "commandDispatched": False, "commands": 0, "profileCalls": 2, "inputClosed": True,
            "handlersRestored": True, "invocationClosed": True, "stopObserved": "none"}}
        wire.validate_terminal(terminal, request)
        accepted = wire.response(request, "accepted", {"schemaVersion": 1, "context": request.context})
        returned = wire.response(request, "terminal", terminal)
        self.assertEqual((json.loads(accepted)["sequence"], json.loads(returned)["sequence"]), (0, 1))
        self.assertLessEqual(len(accepted) + len(returned), wire.RESPONSE_LIMIT)
        for field, value in (("complete", False), ("fatal", True), ("contained", False),
                             ("inputClosed", False), ("handlersRestored", False), ("invocationClosed", False),
                             ("commandDispatched", None), ("commands", True), ("profileCalls", 129)):
            changed = copy.deepcopy(terminal)
            changed["lifetime"][field] = value
            with self.subTest(lifetime=field), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(changed, request)
        unknown = copy.deepcopy(terminal)
        unknown.update(outcome="unknown", reason="cleanup-unknown", result=None)
        unknown["lifetime"]["contained"] = False
        wire.validate_terminal(unknown, request)
        unknown["lifetime"]["contained"] = True
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(unknown, request)
        with self.assertRaises(wire.ProtocolError):
            wire.response(request, "accepted", {"schemaVersion": True, "context": request.context})


    def test_actual_snapshot_reader_separates_parser_negative_from_original_io_failure(self):
        """Actual reader/FD IO with a finite receiver, not a production owner admission."""
        import errno
        import os
        import tempfile
        import types
        from contextlib import contextmanager, nullcontext
        from pathlib import Path
        from mobile_release.android_zip import AndroidZipError
        from mobile_release import _desktop_artifact_inspection_selection as selected
        from mobile_release.desktop_artifact_inspection import ArtifactInspectionOperation

        class Receiver:
            # Only the already documented receiver ports are supplied here.
            # Source/native/quit authority and real Operation construction are NOT mocked into qualification.
            def __init__(receiver, path, root_fd):
                receiver.path, receiver.root_fd = path, root_fd
                receiver.expected = selected._identity(os.fstat(root_fd))
                receiver.primary, receiver.errors = None, []
                receiver.counters, receiver.live, receiver.closed = {}, set(), []
                receiver.close_claimed = False
                receiver.guard = types.SimpleNamespace(depth=0, deferred=lambda **kw: nullcontext())
                receiver.snapshot = types.SimpleNamespace(_owner=object())
                receiver.snapshot_binding = types.SimpleNamespace(origin=receiver.origin)
                receiver.inspection_deadline = types.SimpleNamespace(descriptor=receiver.descriptor, check=receiver.checkpoint)
                receiver._artifact = None

            def owner(receiver):
                self.assertIs(type(receiver), Receiver)

            def origin(receiver, owner, guard):
                self.assertIs(owner, receiver.snapshot._owner)
                self.assertIs(guard, receiver.guard)

            def named(receiver):
                if (selected._identity(os.fstat(receiver.root_fd)) != receiver.expected
                        or selected._identity(os.stat(receiver.path, follow_symlinks=False)) != receiver.expected):
                    raise selected.ArtifactInspectionRefused("selection-changed")

            def checkpoint(receiver):
                receiver.owner()

            cleanup_checkpoint = checkpoint

            def inspection_checkpoint(receiver):
                receiver.named()

            def dependents_settled(receiver):
                return not receiver.live

            def remember(receiver, error, **kwargs):
                receiver.errors.append(error)
                if receiver.primary is None:
                    receiver.primary = error

            def fail(receiver, reason):
                error = selected.ArtifactInspectionRefused(reason)
                receiver.remember(error)
                raise error

            def charge(receiver, *args):
                return ArtifactInspectionOperation.charge(receiver, *args)

            def check_private_file(receiver, *args, **kwargs):
                return ArtifactInspectionOperation.check_private_file(receiver, *args, **kwargs)

            @contextmanager
            def descriptor(receiver, path):
                self.assertEqual(path, receiver.path)
                receiver.named()
                number = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                receiver.live.add(number)
                first = None
                try:
                    self.assertEqual(selected._identity(os.fstat(number)), receiver.expected)
                    yield number
                except BaseException as error:
                    first = error
                    raise
                finally:
                    post_error = None
                    try:
                        receiver.named()
                        if selected._identity(os.fstat(number)) != receiver.expected:
                            raise selected.ArtifactInspectionRefused("selection-changed")
                    except BaseException as error:
                        receiver.remember(error)
                        post_error = error
                    finally:
                        os.close(number)  # Actual consuming close, never simulated success.
                        receiver.live.remove(number)
                        receiver.closed.append(number)
                    if first is None and post_error is not None:
                        raise post_error

        for mode in ("success", "validation", "zip", "read", "named", "parser-and-named", "stat"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="artifact-reader-") as temporary:
                path = Path(temporary) / "snapshot.aab"
                payload = b"held actual bytes"
                path.write_bytes(payload)
                path.chmod(0o400)
                original = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    receiver = Receiver(path, original)
                    files = object.__new__(selected.ArtifactInspectionFiles)
                    files.operation, files.guard, files.close_claimed = receiver, receiver.guard, False
                    files.artifact = None
                    files.selected = [types.SimpleNamespace(check=receiver.named)]
                    artifact = selected.ArtifactInspectionArtifact(files, path, len(payload), hashlib.sha256(payload).hexdigest())
                    files.artifact = receiver._artifact = artifact
                    artifact.verify_bytes()  # Real content hash plus original metadata/close.
                    self.assertFalse(receiver.errors)
                    parser_error = AndroidZipError("end") if mode == "zip" else ValidationError("known parser refusal")
                    read_error = OSError(errno.EIO, "injected read failure")
                    stat_error = OSError(errno.EIO, "injected fstat failure")
                    caught, reader = None, None
                    try:
                        with artifact.reader() as reader:
                            self.assertIs(type(reader), selected._ArtifactReader)
                            self.assertEqual(reader.read(4), payload[:4])
                            self.assertEqual(reader.tell(), 4)
                            self.assertEqual(reader.seek(-2, 2), len(payload) - 2)
                            self.assertEqual(reader.read(), payload[-2:])
                            reader.seek(0)
                            if mode in {"validation", "zip"}:
                                raise parser_error
                            if mode == "read":
                                original_read = os.read
                                def fail_read(number, amount):
                                    if number == reader.number:
                                        raise read_error
                                    return original_read(number, amount)
                                with patch.object(selected.os, "read", side_effect=fail_read):
                                    reader.read(1)
                            elif mode == "stat":
                                original_fstat = os.fstat
                                def fail_stat(number):
                                    if number == original:
                                        raise stat_error
                                    return original_fstat(number)
                                with patch.object(selected.os, "fstat", side_effect=fail_stat):
                                    reader.tell()
                            elif mode in {"named", "parser-and-named"}:
                                # Identical bytes/size/protection are NOT the same original inode.
                                path.rename(Path(temporary) / "preserved-original")
                                path.write_bytes(payload)
                                path.chmod(0o400)
                                if mode == "parser-and-named":
                                    raise parser_error
                            else:
                                self.assertEqual(reader.read(), payload)
                    except BaseException as error:
                        caught = error
                    self.assertIsNotNone(reader)
                    self.assertTrue(reader.closed)
                    self.assertIsNone(artifact._reader)
                    self.assertFalse(receiver.live)
                    self.assertGreater(len(receiver.closed), 0)
                    self.assertEqual(receiver.counters["artifact-reader-borrows"], 1)
                    if mode in {"success", "validation", "zip"}:
                        self.assertIs(caught, None if mode == "success" else parser_error)
                        self.assertIsNone(receiver.primary)
                        self.assertFalse(receiver.errors)
                        # Actual production negative-result gate, not a fixture's permissive predicate.
                        if mode == "zip":
                            # Raw ZIP policy is ValueError, not yet the adapter's closed ValidationError.
                            # The reader must not latch it; the genuine Android adapter supplies this exact wrapper.
                            from mobile_release.android import _OwnedAabStructureError
                            with self.assertRaises(wire.ProtocolError):
                                ArtifactInspectionOperation.data_refusal(receiver, parser_error)
                            ArtifactInspectionOperation.data_refusal(receiver, _OwnedAabStructureError(str(parser_error)))
                        else:
                            ArtifactInspectionOperation.data_refusal(receiver, parser_error)
                    else:
                        self.assertIsNotNone(caught)
                        self.assertIsNotNone(receiver.primary)
                        self.assertTrue(receiver.errors)
                        if mode in {"read", "stat"}:
                            self.assertIs(caught, read_error if mode == "read" else stat_error)
                            self.assertIs(receiver.primary, caught)
                        elif mode == "named":
                            self.assertIs(type(caught), selected.ArtifactInspectionRefused)
                            self.assertEqual(caught.reason, "selection-changed")
                        elif mode == "parser-and-named":
                            self.assertIs(caught, parser_error)  # First body exception preserved, IO latch NOT erased.
                            self.assertIsNot(receiver.primary, parser_error)
                        with self.assertRaises(wire.ProtocolError):
                            ArtifactInspectionOperation.data_refusal(receiver, parser_error)
                finally:
                    os.close(original)

    def test_artifact_projection_keeps_saved_policy_observation_and_missing_prerequisites_separate(self):
        """Pure real typed DATA only: no production operation/source admission."""
        from dataclasses import replace
        from pathlib import Path
        from types import SimpleNamespace
        from mobile_release.android import ArtifactAabObservation
        from mobile_release.android_manifest import AndroidManifest
        from mobile_release.config import ReleaseConfig, ReleaseVersion
        from mobile_release.ios import ArtifactIPAObservation
        from mobile_release.desktop_artifact_inspection import ArtifactInspectionOperation, _project_artifact_result
        from mobile_release._desktop_artifact_inspection_selection import ArtifactInspectionInputs

        fingerprint = "a1" * 32
        def fixture(format, count=1):
            config = ReleaseConfig(Path("/inert/config.json"), Path("/inert"), {
                "android": {"enabled": True, "applicationId": "com.example.reader",
                            "uploadCertificateSha256": ":".join(["A1"] * 32)},
                "ios": {"enabled": True, "bundleId": "com.example.reader", "teamId": "ABCDE12345",
                        "distributionCertificateSha256": fingerprint},
            })
            inputs = ArtifactInspectionInputs(config, ReleaseVersion("1.2.3", 7),
                                              b"inert captured config", b"inert captured version", "version.txt")
            # Exact class, no constructor/FD/source/guard/native capability.
            operation = object.__new__(ArtifactInspectionOperation)
            operation.inputs, operation.primary, operation.unknown = inputs, None, False
            context = context_data(format, count)
            context["savedConfig"] = inputs.used_config()
            operation.request = SimpleNamespace(context=context)
            operation._artifact_rows = result_data(format, count)["artifacts"]
            return operation

        def checks(result):
            return {row["check"]: (row["status"], row["reason"]) for row in result["checks"]}

        manifest = AndroidManifest("com.example.reader", "7", "1.2.3", False, False)
        aab = ArtifactAabObservation(True, manifest, True, fingerprint)
        op = fixture("aab")
        retained = copy.deepcopy((op.inputs.config.data, op._artifact_rows, op.request.context))
        result = _project_artifact_result(op, aab=aab, structure_ok=True)
        values = checks(result)
        for name in ("byte-identity", "structure", "manifest", "expected-identity", "expected-version",
                     "signature", "signer-policy"):
            self.assertEqual(values[name], ("pass", "none"))
        self.assertEqual(values["current-validity"], ("unavailable", "prerequisite-not-run"))
        self.assertEqual(values["profile-entitlements"], ("not_applicable", "none"))
        self.assertIsNone(result["observed"]["bundleId"])
        self.assertIsNone(result["observed"]["teamId"])
        self.assertEqual(result["usedVersion"], op.inputs.used_version())
        result["artifacts"][0]["identity"]["sha256"] = "0" * 64
        result["observed"]["applicationId"] = "changed.only.output"
        self.assertEqual((op.inputs.config.data, op._artifact_rows, op.request.context), retained)
        for changed_manifest in (replace(manifest, debuggable=True), replace(manifest, test_only=True)):
            values = checks(_project_artifact_result(op, aab=replace(aab, manifest=changed_manifest), structure_ok=True))
            self.assertEqual(values["manifest"], ("fail", "malformed-structure"))
            self.assertEqual(values["expected-identity"], ("pass", "none"))
        changed = replace(aab, manifest=replace(manifest, package="com.other.app", version_code="07"))
        values = checks(_project_artifact_result(op, aab=changed, structure_ok=True))
        self.assertEqual(values["expected-identity"], ("fail", "identity-mismatch"))
        self.assertEqual(values["expected-version"], ("fail", "version-mismatch"))
        for missing in (ArtifactAabObservation(True), replace(aab, manifest=None, manifest_unavailable=True)):
            values = checks(_project_artifact_result(op, aab=missing, structure_ok=True))
            self.assertEqual(values["manifest"], ("unavailable", "tools-unavailable"))
            self.assertEqual(values["expected-version"], ("unavailable", "prerequisite-not-run"))
        values = checks(_project_artifact_result(op, aab=replace(aab, manifest=None, manifest_failed=True), structure_ok=True))
        self.assertEqual(values["manifest"], ("fail", "malformed-structure"))
        no_signature = replace(aab, signature_ok=False, signature_failed=True, signer_sha256=None)
        values = checks(_project_artifact_result(op, aab=no_signature, structure_ok=True))
        self.assertEqual(values["signature"], ("fail", "signature-invalid"))
        self.assertEqual(values["signer-policy"], ("unavailable", "signer-unobserved"))
        del op.inputs.config.data["android"]["uploadCertificateSha256"]
        values = checks(_project_artifact_result(op, aab=aab, structure_ok=True))
        self.assertEqual(values["signature"], ("pass", "none"))
        self.assertEqual(values["signer-policy"], ("unavailable", "saved-policy-missing"))

        ipa = ArtifactIPAObservation(True, "com.example.reader", "1.2.3", "7", fingerprint, "ABCDE12345",
                                     True, True, True, "none", "none", "none")
        op = fixture("ipa", 3)
        values = checks(_project_artifact_result(op, ipa=ipa, structure_ok=True, pair_ok=True, symbols_ok=False))
        self.assertEqual(values["archive-pair"], ("pass", "none"))
        self.assertEqual(values["symbols"], ("fail", "symbols-mismatch"))
        self.assertEqual(values["signer-policy"], ("pass", "none"))
        changed = replace(ipa, current_validity_ok=False, current_validity_reason="signing-time-invalid")
        values = checks(_project_artifact_result(op, ipa=changed, structure_ok=True))
        self.assertEqual(values["signature"], ("pass", "none"))
        self.assertEqual(values["current-validity"], ("fail", "signing-time-invalid"))
        self.assertEqual(values["archive-pair"], ("unavailable", "prerequisite-not-run"))
        for field, value in (("distributionCertificateSha256", "b2" * 32), ("teamId", "ZZZZZ12345")):
            other = fixture("ipa")
            other.inputs.config.data["ios"][field] = value
            values = checks(_project_artifact_result(other, ipa=ipa, structure_ok=True))
            self.assertEqual(values["signer-policy"], ("fail", "signer-mismatch"))
            self.assertEqual(values["signature"], ("pass", "none"))
            self.assertEqual(values["expected-identity"], ("pass", "none"))
        no_tools = replace(ipa, signer_sha256=None, team_id=None, signature_ok=None, profile_ok=None,
                           current_validity_ok=None, signature_reason="tools-unavailable",
                           profile_reason="tools-unavailable", current_validity_reason="tools-unavailable")
        values = checks(_project_artifact_result(fixture("ipa"), ipa=no_tools, structure_ok=True))
        self.assertEqual(values["signature"], ("unavailable", "tools-unavailable"))
        self.assertEqual(values["signer-policy"], ("unavailable", "signer-unobserved"))
        self.assertEqual(values["archive-pair"], ("unavailable", "archive-not-selected"))
        self.assertEqual(values["symbols"], ("unavailable", "symbols-not-selected"))
        for format in ("aab", "ipa"):
            empty = fixture(format)
            empty._artifact_rows[0]["bytes"] = 0
            values = checks(_project_artifact_result(empty, structure_ok=False))
            self.assertEqual(values["byte-identity"], ("pass", "none"))
            self.assertEqual(values["structure"], ("fail", "malformed-structure"))
            self.assertEqual(values["expected-identity"], ("unavailable", "prerequisite-not-run"))
            self.assertEqual(values["signature"], ("unavailable", "prerequisite-not-run"))
        for bad in ({"structure_ok": 1, "ipa": ipa}, {"structure_ok": True, "aab": aab},
                    {"structure_ok": True, "ipa": replace(ipa, signature_ok=1)},
                    {"structure_ok": True, "ipa": replace(ipa, profile_reason="profile-invalid")},
                    {"structure_ok": False, "ipa": ipa},
                    {"structure_ok": True, "ipa": ipa, "pair_ok": True},
                    {"structure_ok": True, "ipa": ipa, "symbols_ok": 0}):
            with self.subTest(bad=bad), self.assertRaises(wire.ProtocolError):
                _project_artifact_result(fixture("ipa"), **bad)
        failed = fixture("ipa")
        failure = ValidationError("original failure")
        failed.primary = failure
        with self.assertRaises(wire.ProtocolError):
            _project_artifact_result(failed, ipa=ipa, structure_ok=True)
        self.assertIs(failed.primary, failure)


    def test_fixed_ios_tool_originals_refuse_partial_open_post_swap_and_unknown_close(self):
        """Actual class/caller control flow with inert ports, not native/FD authority."""
        import errno
        import os
        import stat
        import types
        from contextlib import contextmanager, nullcontext
        from pathlib import Path
        from mobile_release import desktop_artifact_inspection as subject, ios, ios_artifacts
        from mobile_release.owned_process import ProcessCleanupError

        for mode in ("success", "partial", "post-swap", "close-unknown", "partial-and-close"):
            with self.subTest(mode=mode):
                events, slots, values = [], [], {}
                open_error = OSError(errno.EACCES, "inert original open refused")
                close_error = OSError(errno.EIO, "inert consuming close unknown")
                cleanup_error = ProcessCleanupError("inert original custody unknown")
                operation = object.__new__(subject.ArtifactInspectionOperation)
                # Deliberately no Operation constructor/request/native/runtime admission.
                # Every resource and owner port below is finite DATA and replaced.
                operation.primary, operation.unknown = None, False
                operation.ios_tools, operation.close_claimed = None, False
                operation.source = object()
                operation.guard = types.SimpleNamespace(_artifact_inspection_source=operation.source,
                    deferred=lambda **kwargs: nullcontext())
                operation.owner = lambda: self.assertIs(type(operation), subject.ArtifactInspectionOperation)
                operation.files = types.SimpleNamespace(operation=operation,
                    point=lambda: events.append(("point", None)))
                operation.inspection_checkpoint = lambda: events.append(("checkpoint", None))
                operation.dependents_settled = lambda: not operation.unknown
                operation.request = types.SimpleNamespace(native={"tools": {"ios": None}})
                operation.inspection_deadline = object()
                app = Path("/inert-snapshot/Payload/Reader.app")
                operation._ipa_layout = (app, types.SimpleNamespace(all_inventory={}))
                operation.snapshot = types.SimpleNamespace(_owner=types.SimpleNamespace(
                    audit=lambda: events.append(("audit", None))))

                def remember(error, *, fatal=False):
                    if operation.primary is None:
                        operation.primary = error
                    operation.unknown |= fatal
                    events.append(("remember", error))
                operation.remember = remember

                def attributes(inode, *, directory=False):
                    return types.SimpleNamespace(st_dev=7, st_ino=inode,
                        st_mode=(stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o755),
                        st_uid=0, st_gid=0, st_nlink=2 if directory else 1,
                        st_size=4096 if directory else 128, st_mtime_ns=1_000_000_000,
                        st_ctime_ns=2_000_000_000, st_flags=0)
                names = {name: attributes(30 + index) for index, name in
                         enumerate(("codesign", "security", "openssl"))}

                class Slot:
                    def __init__(slot, guard):
                        self.assertIs(guard, operation.guard)
                        slot.guard, slot.number = guard, None
                        slot.name, slot.open_state, slot.close_state = "unopened", "NEW", "NOT_ATTEMPTED"
                        slot.close_calls = 0
                        slots.append(slot)

                    def open(slot, name, flags, *, dir_fd):
                        self.assertEqual(dir_fd, 103)
                        self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        self.assertEqual((slot.number, slot.open_state), (None, "NEW"))
                        slot.name, slot.open_state = name, "ATTEMPTED"
                        events.append(("open", name))
                        if name == "security" and mode in {"partial", "partial-and-close"}:
                            slot.open_state = "NO_EFFECT"
                            raise open_error
                        slot.number, slot.open_state = 200 + len(values), "OPEN"
                        values[slot.number] = names[name]
                        return slot.number

                    def close(slot):
                        if slot.close_state == "CLOSED":
                            return
                        self.assertEqual(slot.close_state, "NOT_ATTEMPTED")
                        slot.close_calls += 1
                        events.append(("close", slot.name))
                        slot.number, slot.close_state = None, "ATTEMPTED"
                        if ((mode == "close-unknown" and slot.name == "security")
                                or (mode == "partial-and-close" and slot.name == "codesign")):
                            slot.close_state = "UNKNOWN"
                            raise close_error
                        slot.close_state = "CLOSED"

                class Directory:
                    def __init__(directory, path, guard, *, edit_checkpoints):
                        self.assertEqual(path, Path("/usr/bin"))
                        self.assertIs(guard, operation.guard)
                        self.assertIs(edit_checkpoints, True)
                        directory.path, directory.guard = path, guard
                        directory.slots = [Slot(guard) for _ in range(3)]

                    @property
                    def fd(directory):
                        return directory.slots[-1].number

                    def acquire(directory):
                        for index, slot in enumerate(directory.slots):
                            slot.name, slot.number, slot.open_state = ("/", "usr", "bin")[index], 101 + index, "OPEN"
                            values[slot.number] = attributes(10 + index, directory=True)

                    def check(directory):
                        self.assertTrue(all(slot.number is not None for slot in directory.slots))
                        events.append(("parent-post", None))

                def named(name, *, dir_fd, follow_symlinks):
                    self.assertEqual(dir_fd, 103)
                    self.assertIs(follow_symlinks, False)
                    events.append(("named", name))
                    return names[name]

                def held(number):
                    events.append(("held", number))
                    return values[number]

                @contextmanager
                def descriptor(path, flags):
                    self.assertEqual(path, app)
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    events.append(("descriptor-enter", None))
                    try:
                        yield 999  # Inert loan; never a real descriptor or child result.
                    finally:
                        events.append(("descriptor-close", None))
                operation.descriptor = descriptor
                fake_os = types.SimpleNamespace(stat=named, fstat=held,
                    O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW,
                    O_NONBLOCK=os.O_NONBLOCK, O_DIRECTORY=os.O_DIRECTORY)
                with patch.object(subject, "_Directory", Directory), patch.object(subject, "_FD", Slot), \
                     patch.object(subject, "os", fake_os), \
                     patch.object(subject, "_cleanup_failure", side_effect=lambda guard, error: cleanup_error), \
                     patch.object(subject, "run_owned", side_effect=AssertionError("no native entry in DATA group")), \
                     patch.object(ios, "_artifact_operation", return_value=operation):
                    self.assertIsNone(ios._artifact_tool("codesign", operation.inspection_deadline))
                    operation.request.native["tools"]["ios"] = "macos-artifact-ios-system-v1"
                    with self.assertRaises(ValidationError):
                        ios._artifact_tool("codesign", operation.inspection_deadline)
                    tools = subject.ArtifactInspectionIOSTools(operation)
                    self.assertIs(operation.ios_tools, tools)
                    if mode in {"partial", "partial-and-close"}:
                        with self.assertRaises(OSError) as raised:
                            tools.acquire()
                        self.assertIs(raised.exception, open_error)
                        self.assertIs(operation.primary, open_error)
                        self.assertFalse(tools.acquired)
                        self.assertEqual(tuple(tools.slots), ("codesign", "security"))
                    else:
                        tools.acquire()
                        self.assertTrue(tools.acquired)
                        self.assertEqual(ios._artifact_tool("codesign", operation.inspection_deadline), "/usr/bin/codesign")
                        operation.request.native["tools"]["ios"] = None
                        with self.assertRaises(ValidationError):
                            ios._artifact_tool("codesign", operation.inspection_deadline)
                        operation.request.native["tools"]["ios"] = "macos-artifact-ios-system-v1"
                        command, actual_path = operation._ios_command(["codesign", "-d", "--verbose=4", str(app)])
                        self.assertEqual(command, ["/usr/bin/codesign", "-d", "--verbose=4", str(app)])
                        self.assertEqual(actual_path, app)
                        with self.assertRaises(wire.ProtocolError):
                            operation._ios_command(["codesign", "--force", "--sign", "-", str(app)])
                        # The same caller wraps a hypothetical body in actual
                        # PRE/POST/known-loan-close control, without a native call.
                        before = len(events)
                        with patch.object(Path, "is_dir", return_value=True), \
                             patch.object(ios_artifacts, "_input", return_value={"same": "snapshot-data"}) as original:
                            with operation._ios_native_input(app):
                                events.append(("body", None))
                            self.assertEqual(original.call_count, 2)
                        window = [kind for kind, _ in events[before:]]
                        self.assertLess(window.index("descriptor-enter"), window.index("body"))
                        self.assertLess(window.index("body"), window.index("audit"))
                        self.assertEqual(window[-1], "descriptor-close")
                        if mode == "post-swap":
                            names["codesign"] = attributes(999)  # Same bytes/mode/size, different named original.
                            with self.assertRaises(wire.ProtocolError) as raised:
                                tools.check()
                            self.assertIs(operation.primary, raised.exception)
                    first = operation.primary
                    if mode in {"close-unknown", "partial-and-close"}:
                        with self.assertRaises(ProcessCleanupError) as raised:
                            tools.close()
                        self.assertIs(raised.exception, cleanup_error)
                        self.assertIs(operation.primary, close_error if first is None else first)
                        self.assertTrue(operation.unknown)
                        self.assertFalse(tools.close_complete)
                        counts = tuple(slot.close_calls for slot in slots)
                        with self.assertRaises(wire.ProtocolError):
                            tools.close()
                        self.assertEqual(tuple(slot.close_calls for slot in slots), counts)  # Never retry a retired number.
                    else:
                        if mode == "post-swap":
                            with self.assertRaises(wire.ProtocolError):
                                tools.close()
                        else:
                            tools.close()
                        self.assertTrue(tools.close_complete)
                        self.assertFalse(operation.unknown)
                        self.assertIs(operation.primary, first)
                        counts = tuple(slot.close_calls for slot in slots)
                        tools.close()
                        self.assertEqual(tuple(slot.close_calls for slot in slots), counts)
                    self.assertTrue(tools.close_claimed)
                    self.assertTrue(all(slot.close_calls == 1 and slot.number is None for slot in slots))
                    self.assertEqual([name for kind, name in events if kind == "open"],
                        ["codesign", "security"] if mode.startswith("partial") else ["codesign", "security", "openssl"])

    def test_actual_aab_service_retains_originals_and_refuses_named_source_swap(self):
        # Linux private-filesystem integration, NOT Mac/native admission. Only
        # platform/free-resource samples and the native-provided pipe identity
        # are fixture DATA. The service, saved inputs, snapshots and every
        # project/source/read/POST/close operation below remain production code.
        import io
        import os
        import signal
        import stat
        import subprocess
        import tempfile
        import time
        import zipfile
        from contextlib import ExitStack
        from pathlib import Path
        from types import SimpleNamespace
        from mobile_release import android, ios, build_inputs
        from mobile_release import desktop_artifact_inspection as service_module
        from mobile_release import _desktop_artifact_inspection_selection as selected
        from mobile_release._desktop_artifact_inspection_control import ArtifactInspectionInput
        from mobile_release.cancellation import DefaultCancellation

        config_value = {"schemaVersion": 1,
            "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
            "source": {"candidateBranch": "main", "productionBranch": "main"},
            "android": {"enabled": True, "applicationId": "com.example.reader", "identityStatus": "unverified"},
            "ios": {"enabled": False},
            "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
            "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
            "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []}}
        config_raw = json.dumps(config_value, separators=(",", ":")).encode()
        version_raw = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
        encoded_zip = io.BytesIO()
        with zipfile.ZipFile(encoded_zip, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in ("BundleConfig.pb", "base/manifest/AndroidManifest.xml", "base/dex/classes.dex"):
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, b"inert structure bytes; not protobuf, DEX or signature proof")
        artifact_raw = encoded_zip.getvalue()
        encoded_zip.close()
        native_forbidden = AssertionError("no native/tool/process operation in the filesystem service test")
        real_aab = service_module.ArtifactInspectionRun._aab
        handlers = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM)}
        environment_before, cwd_before = dict(os.environ), os.getcwd()

        for swap in (False, True):
            with self.subTest(named_source_swap=swap), tempfile.TemporaryDirectory(prefix="artifact-service-") as directory:
                base = Path(directory)
                root, scratch, chosen = (base / name for name in ("project", "scratch", "chosen"))
                for path in (root, scratch, chosen):
                    path.mkdir(mode=0o700)
                (root / "release").mkdir(mode=0o700)
                config_path, version_path = root / "release/mobile-release.json", root / "release/version.properties"
                config_path.write_bytes(config_raw)
                version_path.write_bytes(version_raw)
                source_path = chosen / "selected.aab"
                source_path.write_bytes(artifact_raw)
                source_path.chmod(0o600)
                before = selected._identity(source_path.stat())
                project_stat = root.stat()
                context = context_data("aab")
                context["savedConfig"] = {"bytes": len(config_raw), "sha256": hashlib.sha256(config_raw).hexdigest()}
                request_value = {"protocol": wire.PROTOCOL, "operationId": "4" * 32, "ownerGeneration": "5" * 32,
                    "context": context, "native": {"profile": "macos-x86_64", "projectRoot": str(root),
                    "rootIdentity": {"device": str(project_stat.st_dev), "inode": str(project_stat.st_ino),
                                     "mode": project_stat.st_mode, "uid": project_stat.st_uid, "gid": project_stat.st_gid},
                    "cwd": os.getcwd(), "parentDescriptorReservation": 8,
                    "originals": [{"selectionId": "1" * 32, "role": "artifact", "path": str(source_path),
                                   "kind": "file", "identity": before}], "tools": {"android": None, "ios": None}}}
                request_raw = json.dumps(request_value, separators=(",", ":")).encode() + b"\n"
                # Keep the actual writer open until source.close: EOF is a real
                # stop, never a shortcut for absence of cancellation.
                read_fd, write_fd = os.pipe()
                source = ArtifactInspectionInput(time.monotonic())
                guard = DefaultCancellation(ValidationError, "service fixture cancellation restoration failed")
                run = None
                samples, observed, original_failures = [], [], []
                class PlatformResourceData:
                    def __getattr__(self, name):
                        return getattr(os, name)
                    def uname(self):
                        return SimpleNamespace(machine="x86_64")
                    def fstatvfs(self, number):
                        # Actual original must exist on the private scratch FS;
                        # only free capacity is DATA (the test never claims 4GiB).
                        self_stat = os.fstat(number)
                        self_actual = os.fstatvfs(number)
                        self_outer.assertTrue(stat.S_ISDIR(self_stat.st_mode))
                        self_outer.assertGreater(self_actual.f_frsize, 0)
                        samples.append("disk-data")
                        return SimpleNamespace(f_bavail=8 * 1024 * 1024, f_frsize=4096)
                self_outer = self
                def memory_data(*, check):
                    check()
                    samples.append("memory-data")
                    return 8 * data.GIB
                def observed_then_swap(owner):
                    provisional = real_aab(owner)
                    self.assertIs(owner, run)
                    self.assertIs(owner.operation.snapshot._owner, owner.operation.snapshot_binding.owner)
                    observed.append(copy.deepcopy(provisional))
                    if swap:
                        replacement = chosen / "replacement.aab"
                        replacement.write_bytes(artifact_raw)
                        replacement.chmod(0o600)
                        self.assertNotEqual(replacement.stat().st_ino, int(before["inode"]))
                        os.replace(replacement, source_path)
                        self.assertEqual(source_path.read_bytes(), artifact_raw)
                        # This is the real held/named original comparison, not a
                        # mocked error or replacement snapshot permission.
                        try:
                            owner.operation.files.selected[0].check()
                        except selected.ArtifactInspectionRefused as error:
                            original_failures.append(error)
                            raise
                        self.fail("same-byte new inode must not preserve original identity")
                    return provisional
                try:
                    self.assertLess(len(request_raw), 4096)
                    self.assertEqual(os.write(write_fd, request_raw), len(request_raw))
                    pipe_stat = os.fstat(read_fd)
                    self.assertTrue(stat.S_ISFIFO(pipe_stat.st_mode))
                    os.set_blocking(read_fd, False)
                    source.fd = read_fd
                    source.identity = (pipe_stat.st_dev, pipe_stat.st_ino, pipe_stat.st_mode)
                    source.acquired = True  # Fixture-only native input admission; never production fd0.
                    guard.install()
                    guard._install_artifact_inspection_source(source)
                    guard.activate()
                    request = source.request()
                    self.assertEqual(request.native, request_value["native"])
                    with ExitStack() as scope:
                        scope.enter_context(patch.dict(os.environ, {"TMPDIR": str(scratch)}))
                        scope.enter_context(patch.object(service_module, "sys", SimpleNamespace(platform="darwin")))
                        scope.enter_context(patch.object(service_module, "os", PlatformResourceData()))
                        scope.enter_context(patch.object(darwin_memory, "sampled_free_bytes", side_effect=memory_data))
                        scope.enter_context(patch.object(darwin_memory, "_bindings", side_effect=native_forbidden))
                        scope.enter_context(patch.object(android, "run_owned", side_effect=native_forbidden))
                        scope.enter_context(patch.object(ios, "_run_native", side_effect=native_forbidden))
                        scope.enter_context(patch.object(subprocess, "Popen", side_effect=native_forbidden))
                        scope.enter_context(patch.object(service_module.ArtifactInspectionRun, "_aab", observed_then_swap))
                        run = service_module.ArtifactInspectionRun(request, guard, source)
                        if swap:
                            with self.assertRaises(selected.ArtifactInspectionRefused) as caught:
                                run.run()
                            self.assertEqual(caught.exception.reason, "selection-changed")
                            self.assertEqual(len(original_failures), 1)
                            self.assertIs(run.operation.primary, original_failures[0])
                            self.assertIsNone(run.result)
                            first_failure = source.first_failure
                            self.assertIsNotNone(first_failure)
                        else:
                            run.run()
                            self.assertIsNone(run.operation.primary)
                            self.assertIsNone(source.first_failure)
                        run.close()  # Real known idempotent closure, not a forged receipt.
                    source.close()
                    read_fd = None  # Sole close consumed by the real input source.
                    guard.restore()
                    terminal = run.terminal()
                    wire.validate_terminal(terminal, request)
                    self.assertEqual(terminal["outcome"], "refused" if swap else "complete")
                    self.assertEqual(terminal["reason"], "selection-changed" if swap else "none")
                    self.assertEqual(terminal["result"], None if swap else observed[0])
                    life = terminal["lifetime"]
                    for name in ("complete", "contained", "inputClosed", "handlersRestored", "invocationClosed"):
                        self.assertIs(life[name], True)
                    self.assertIs(life["fatal"], False)
                    self.assertIs(life["commandDispatched"], False)
                    self.assertEqual((life["commands"], life["profileCalls"], life["stopObserved"]), (0, 0, "none"))
                    self.assertEqual(samples, ["memory-data", "disk-data"])
                    self.assertEqual(len(observed), 1)
                    result = observed[0]
                    self.assertEqual(result["usedConfig"], context["savedConfig"])
                    self.assertEqual(result["usedVersion"], {"bytes": len(version_raw), "sha256": hashlib.sha256(version_raw).hexdigest(), "name": "1.2.3", "build": 7})
                    self.assertEqual(result["artifacts"][0]["identity"], {"method": "sha256-file", "sha256": hashlib.sha256(artifact_raw).hexdigest()})
                    checks = {item["check"]: item for item in result["checks"]}
                    self.assertEqual(tuple(checks), wire.CHECKS)
                    for name in ("byte-identity", "structure"):
                        self.assertEqual(checks[name]["status"], "pass")
                    self.assertEqual(checks["signature"], {"check": "signature", "status": "unavailable", "reason": "tools-unavailable"})
                    self.assertTrue(all(value is None for value in result["observed"].values()))
                    self.assertIsNone(run.operation.tools)
                    self.assertIsNone(run.operation.ios_tools)
                    self.assertTrue(run.operation.closed())
                    self.assertTrue(run.operation.invocation._artifact_inspection_closed(run.operation))
                    self.assertFalse(run.operation.live_slots)
                    self.assertFalse(run.operation.files.iterators)
                    self.assertFalse(run.operation._scratch)
                    self.assertFalse(list(scratch.iterdir()))
                    self.assertEqual(config_path.read_bytes(), config_raw)
                    self.assertEqual(version_path.read_bytes(), version_raw)
                    self.assertEqual(source_path.read_bytes(), artifact_raw)
                    self.assertIsNone(build_inputs._ENV_OWNER)
                    self.assertFalse(build_inputs._ENV_TAINTED)
                    if swap:
                        self.assertEqual(source.first_failure, first_failure)
                finally:
                    # Preserve the actual cleanup methods even if an assertion
                    # fails; never clear an unknown latch or rewrite a verdict.
                    try:
                        if run is not None and not run.operation.close_claimed:
                            run.close()
                    finally:
                        try:
                            if not source.close_claimed and source.acquired:
                                source.close()
                                read_fd = None
                            elif not source.acquired and read_fd is not None:
                                os.close(read_fd)
                                read_fd = None
                        finally:
                            try:
                                os.close(write_fd)
                            finally:
                                if guard.handler_state != "RESTORED":
                                    guard.restore()
                self.assertEqual({n: signal.getsignal(n) for n in handlers}, handlers)
        self.assertEqual(os.getcwd(), cwd_before)
        self.assertEqual(dict(os.environ), environment_before)


if __name__ == "__main__":
    unittest.main()
