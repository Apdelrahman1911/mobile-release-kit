"""History grammar/resource DATA only: supplied projections are not live proof."""
from __future__ import annotations

import copy
import json
import hashlib
import io
import os
import stat
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path
import unittest
from unittest.mock import patch

from mobile_release import github_history as history
from mobile_release.errors import ValidationError
from mobile_release import _desktop_github_history_protocol as wire
from mobile_release._desktop_github_history_control import HistoryInput
from mobile_release.cancellation import DefaultCancellation
from mobile_release.desktop_github_history import HistoryOperation, HistoryRefused, _wire_identity
from mobile_release.owned_process import ProcessCleanupError
from mobile_release.provenance import WORKFLOW_PATHS


def context(platform="android", stage="candidate"):
    return history.HistoryContext.parse({"schemaVersion": 1, "projectBinding": "1" * 64,
        "configSha256": "2" * 64, "repository": "owner/repo", "repositoryId": "123",
        "accountId": "456", "toolingRepository": history.TOOLING_REPOSITORY,
        "toolingSha": "3" * 40,
        "selection": {"runId": "789", "attempt": 2, "stage": stage, "platform": platform}})


def result(selected):
    stage = selected.selection.stage
    caller, reusable = WORKFLOW_PATHS[stage]
    authority = {"workflow": "Protected release", "callerPath": ".github/workflows/" + caller,
        "reusableRepository": history.TOOLING_REPOSITORY,
        "reusablePath": ".github/workflows/" + reusable, "reusableCommit": selected.tooling_sha,
        "runId": selected.selection.run_id, "attempt": selected.selection.attempt,
        "headSha": "4" * 40, "ref": "refs/heads/main", "event": "workflow_dispatch"}
    evidence = {"artifactId": "555", "artifactSha256": "5" * 64,
        "artifactName": history.artifact_name(stage, selected.selection.platform, "evidence"),
        "producerJobId": "666", "producedBy": authority,
        "authorizedBy": dict(authority, runId="700", attempt=1),
        "candidateSource": {"commit": "4" * 40, "tree": "6" * 40},
        "operationSource": {"commit": "4" * 40, "tree": "6" * 40},
        "version": {"name": "1.2.3", "build": 42}, "applicationId": "org.example.app",
        "outcome": "reconciled", "candidateManifestSha256": "7" * 64,
        "operationIntentSha256": "8" * 64, "receiptSha256": "9" * 64, "provenanceSha256": "a" * 64}
    return {"schemaVersion": 1, "context": selected.value(), "observedAt": "2026-10-09T12:34:56Z",
        "verification": "verified", "reason": "none", "evidence": evidence, "assurance": history.ASSURANCE}


def private_request(root="/project", work="/private/tmp/history", *, initial_context=None):
    directory = {"device": "1", "inode": "2", "mode": stat.S_IFDIR | 0o700, "uid": os.getuid(), "gid": os.getgid()}
    regular = {"device": "1", "inode": "3", "mode": stat.S_IFREG | 0o600, "uid": os.getuid(), "gid": os.getgid(),
        "nlink": "1", "bytes": "2", "mtimeSeconds": "1", "mtimeNanos": 0,
        "ctimeSeconds": "1", "ctimeNanos": 0, "flags": 0}
    return {"protocol": wire.PROTOCOL, "id": "request-1", "ownerGeneration": "owner-1",
        "context": (initial_context or context()).value(),
        "native": {"profile": "macos-arm64", "projectRoot": root, "rootIdentity": directory,
            "configIdentity": regular, "workRoot": work, "workIdentity": dict(directory, inode="4"),
            "provider": {"relativePath": "tools/gh", "version": "2.88.1", "target": "aarch64-apple-darwin",
                "sourceManifestSha256": "a" * 64, "sha256": "b" * 64,
                "identity": dict(regular, inode="5", mode=stat.S_IFREG | 0o555, uid=0, gid=0)},
            "parentDescriptorReservation": 56, "clock": {"name": "CLOCK_UPTIME_RAW",
                "workEndNs": "900000000000", "hardEndNs": "910000000000"}}}


@contextmanager
def owned_files_fixture():
    """Real tiny file/pipe originals; deliberately NOT native admission/GO proof.

    The fake native-facing request and Linux monotonic clock are test DATA only.
    No provider is admitted, credential read, process spawned or Mac clock used.
    Actual production directory/FD/reader/retirement methods run unchanged.
    """
    with tempfile.TemporaryDirectory(prefix="history-owned-files-") as temporary:
        base = Path(temporary)
        root, work = base / "project", base / "work"
        root.mkdir(mode=0o700); work.mkdir(mode=0o700)
        source = HistoryInput(time.monotonic())
        source.raw_clock = time.CLOCK_MONOTONIC
        source.raw_work_end = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + 30_000_000_000
        source.raw_hard_end = source.raw_work_end + 10_000_000_000
        source.work_end = time.monotonic() + 30
        source.hard_end = source.work_end + 10
        request_data = private_request(str(root), str(work))
        request_data["native"]["rootIdentity"] = _wire_identity(root.stat(), True)
        request_data["native"]["workIdentity"] = _wire_identity(work.stat(), True)
        request = wire.parse_request(wire.canonical(request_data, wire.REQUEST_LIMIT), source.budget)
        source.initial, source.request_returned = request, True
        reader, writer = os.pipe()
        os.set_blocking(reader, False)
        seen = os.fstat(reader)
        source.fd, source.identity, source.acquired = reader, (seen.st_dev, seen.st_ino, seen.st_mode), True
        guard = DefaultCancellation(ProcessCleanupError, "test original cleanup")
        guard._install_github_history_source(source)
        operation = HistoryOperation(request, source, guard, str(base))
        try:
            # Actual retained work original only; not full native admission.
            operation._directory(work, retain=True)
            yield operation
        finally:
            try:
                if not operation.closed:
                    try:
                        operation.cleanup()
                    except ValidationError:
                        if not operation.unknown:
                            raise
            finally:
                try:
                    source.close()
                finally:
                    os.close(writer)


class GitHubHistoryDataTests(unittest.TestCase):
    def test_context_is_closed_immutable_and_never_synthesizes_current_job_authority(self):
        for platform in history.PLATFORMS:
            for stage in history.STAGES:
                selected = context(platform, stage)
                self.assertEqual(history.HistoryContext.parse(selected.value()), selected)
                view = selected.verifier_context()
                self.assertEqual(dict(view.repository), {"id": "123", "fullName": "owner/repo"})
                self.assertEqual(view.trusted_tooling_commit, selected.tooling_sha)
                self.assertFalse(hasattr(view, "authority"))
                self.assertFalse(hasattr(view, "current_job"))
                self.assertFalse(view.is_current_job(result(selected)["evidence"]["producedBy"], platform))
                detached = selected.value()
                detached["selection"]["runId"] = "999"
                self.assertEqual(selected.selection.run_id, "789")
        original = context().value()
        for key, bad in (("schemaVersion", True), ("accountId", 456), ("repositoryId", "01"),
                         ("repositoryId", "18446744073709551616"), ("toolingRepository", "attacker/tools"),
                         ("toolingSha", "A" * 40), ("repository", "owner/repo\x85"),
                         ("repository", "owner/repo\n"), ("projectBinding", "f" * 63)):
            with self.subTest(key=key, bad=bad), self.assertRaises(ValidationError):
                history.HistoryContext.parse(dict(original, **{key: bad}))
        for extra in ("authority", "currentJob", "token", "path"):
            with self.subTest(extra=extra), self.assertRaises(ValidationError):
                history.HistoryContext.parse(dict(original, **{extra: None}))
        selection = original["selection"]
        for key, bad in (("runId", "0"), ("runId", True), ("runId", "18446744073709551616"),
                         ("attempt", True), ("attempt", 0), ("attempt", 101), ("stage", "latest"),
                         ("platform", "apk"), ("stage", [])):
            with self.subTest(key=key, bad=bad), self.assertRaises(ValidationError):
                history.Selection.parse(dict(selection, **{key: bad}))
        maximum = history.Selection.parse(dict(selection, runId="18446744073709551615", attempt=100))
        self.assertEqual(maximum.attempt, 100)

    def test_prospective_budget_and_json_preflight_bound_before_allocation_and_latch_failure(self):
        budget = history.HistoryBudget()
        budget.check_descriptors(56, 127, 1)  # 56 + eight worker ends + 128 = 192.
        for _ in range(128):
            budget.claim_call()
            budget.claim_decode(0)
        for _ in range(4):
            budget.claim_auth_read()
            budget.claim_download(history.GIB)
        for _ in range(32):
            budget.claim_capture(history.MIB, history.MIB)
        budget.claim_originals(32768)
        self.assertEqual((budget._calls, budget._decodes, budget._downloads, budget._auth), (128, 128, 4, 4))
        with self.assertRaises(ValidationError):
            budget.claim_call()
        self.assertEqual(budget._calls, 128)
        with self.assertRaises(ValidationError):
            budget.claim_originals(0)  # No spending/reset after the failed claim.
        for operation in (
            lambda b: b.claim_decode(history.MIB + 1), lambda b: b.claim_decode(True),
            lambda b: b.claim_download(history.GIB + 1), lambda b: b.claim_originals(-1),
            lambda b: b.claim_originals(32769), lambda b: b.claim_capture(2, 1),
            lambda b: b.check_descriptors(57, 127, 1), lambda b: b.check_descriptors(0, 128, 1),
            lambda b: b.check_descriptors(True, 0, 0), lambda b: b.claim_capture(0, history.MIB + 1)):
            fresh = history.HistoryBudget()
            with self.assertRaises(ValidationError):
                operation(fresh)
            self.assertTrue(fresh._failed)
            self.assertEqual((fresh._download_raw, fresh._decode_raw, fresh._capture_raw, fresh._originals), (0, 0, 0, 0))
        for method, count, args in (("claim_auth_read", 4, ()), ("claim_download", 4, (history.GIB,)),
                                   ("claim_decode", 8, (history.MIB,)), ("claim_capture", 32, (history.MIB, history.MIB))):
            fresh = history.HistoryBudget()
            for _ in range(count):
                getattr(fresh, method)(*args)
            before = (fresh._auth, fresh._downloads, fresh._decode_raw, fresh._capture_raw)
            with self.assertRaises(ValidationError):
                getattr(fresh, method)(*args)
            self.assertEqual((fresh._auth, fresh._downloads, fresh._decode_raw, fresh._capture_raw), before)
        literal = {"text": 'quotes " and \\ and [not containers] {x}', "value": [True, None, -2]}
        self.assertEqual(history._decode_json(json.dumps(literal).encode(), history.HistoryBudget()), literal)
        nested = 0
        for _ in range(32):
            nested = [nested]
        self.assertEqual(history._decode_json(b"[" * 32 + b"0" + b"]" * 32, history.HistoryBudget()), nested)
        exact_nodes = b"[" + b",".join([b"0"] * 4095) + b"]"
        self.assertEqual(len(history._decode_json(exact_nodes, history.HistoryBudget())), 4095)
        # Over-limit structure never enters even the actual stdlib JSON allocator.
        for raw in (b"[" * 33 + b"0" + b"]" * 33, b"[" + b",".join([b"0"] * 4096) + b"]",
                    b" " * history.MIB + b"0"):
            fresh = history.HistoryBudget()
            with patch.object(history.json, "loads", side_effect=AssertionError("decoder entered")):
                with self.assertRaises(ValidationError):
                    history._decode_json(raw, fresh)
            self.assertTrue(fresh._failed)
        self.assertEqual(history._decode_json(b"1e308", history.HistoryBudget()), 1e308)
        self.assertEqual(history._decode_json(b'{"n":[-1e308,1.25e-3]}', history.HistoryBudget()),
                         {"n": [-1e308, 1.25e-3]})
        for raw in (b"1e309", b"-1e309", b'{"n":[1e309]}', b'{"n":-1e309}',
                    b'{"a":1,"a":2}', b"NaN", b'"unterminated', b"[}", b"\xff", b'"\\uZZZZ"'):
            fresh = history.HistoryBudget()
            with self.subTest(raw=raw), self.assertRaises(ValidationError):
                history._decode_json(raw, fresh)
            self.assertTrue(fresh._failed)

        # The private19 ceiling is a subset of the SAME global128 attempts.
        for stage, total in (("candidate", 3), ("external-testing", 8), ("production-submit", 19)):
            fresh = history.HistoryBudget()
            fresh.reserve_verifiers()
            for _ in range(total):
                fresh.claim_verifier()
            self.assertEqual((fresh._verifiers, fresh._calls), (total, total), stage)
        with self.assertRaises(ValidationError):
            fresh.claim_verifier()
        self.assertEqual((fresh._verifiers, fresh._calls), (19, 19))
        mixed = history.HistoryBudget(); mixed.reserve_verifiers()
        for _ in range(128):
            mixed.claim_call()
        with self.assertRaises(ValidationError):
            mixed.claim_verifier()
        self.assertEqual((mixed._verifiers, mixed._calls), (0, 128))
        with self.assertRaises(ValidationError):
            history.HistoryBudget().claim_verifier()  # No prospective reservation.
        reserved = history.HistoryBudget()
        reserved.reserve_decode(2)
        self.assertEqual(reserved.decode_reserved(b"{}"), {})
        self.assertEqual((reserved._decodes, reserved._decode_raw, reserved._pending_decode), (1, 2, None))
        with self.assertRaises(ValidationError):
            reserved.decode_reserved(b"{}")

    def test_results_preserve_authentication_distinctions_exact_version_and_selected_producer(self):
        for platform in history.PLATFORMS:
            for stage in history.STAGES:
                selected = context(platform, stage)
                fixture = result(selected)
                self.assertEqual(history.parse_result(fixture, selected), fixture)
                for category, reasons in (("unavailable", history.UNAVAILABLE), ("refused", history.REFUSED)):
                    for reason in reasons:
                        negative = dict(fixture, verification=category, reason=reason, evidence=None)
                        self.assertEqual(history.parse_result(negative, selected), negative)
                        wrong = dict(negative, verification="refused" if category == "unavailable" else "unavailable")
                        with self.assertRaises(ValidationError):
                            history.parse_result(wrong, selected)
                high = copy.deepcopy(fixture)
                high["evidence"]["version"]["build"] = 2_100_000_000
                self.assertEqual(history.parse_result(high, selected)["evidence"]["version"]["build"], 2_100_000_000)
                for name in ("1", "v1.2", "1.2\x85", "1" * 65 + ".2"):
                    bad = copy.deepcopy(fixture)
                    bad["evidence"]["version"]["name"] = name
                    with self.assertRaises(ValidationError):
                        history.parse_result(bad, selected)
                tagged = copy.deepcopy(fixture)
                tagged["evidence"]["version"]["name"] = "1.2.3-rc.1"
                if platform == "ios":
                    with self.assertRaises(ValidationError):
                        history.parse_result(tagged, selected)
                else:
                    self.assertEqual(history.parse_result(tagged, selected), tagged)
        selected = context()
        good = result(selected)
        bads = [dict(good, schemaVersion=True), dict(good, verification="verified", reason="artifact-missing"),
                dict(good, evidence=None), dict(good, assurance="current-store-state"),
                dict(good, observedAt="2026-02-30T12:34:56Z"), dict(good, observedAt="2026-10-09T12:34:56+00:00"),
                dict(good, extra=None)]
        for reason in ("busy", "not-connected", "cancelled", "expired", "cleanup-unknown", "future-reason", "none"):
            bads.append(dict(good, verification="unavailable", reason=reason, evidence=None))
        for field, replacement in (("producedBy", {**good["evidence"]["producedBy"], "runId": "999"}),
                                  ("producedBy", {**good["evidence"]["producedBy"], "attempt": True}),
                                  ("authorizedBy", {**good["evidence"]["authorizedBy"], "reusableCommit": "f" * 40}),
                                  ("artifactName", "mobile-release-candidate-intent-android"),
                                  ("version", {"name": "1.2", "build": 2_100_000_001}),
                                  ("version", {"name": "1.2", "build": True}),
                                  ("version", {"marketing": "1.2", "build": 1}),
                                  ("receiptSha256", "G" * 64), ("applicationId", "org.example\napp")):
            bad = copy.deepcopy(good)
            bad["evidence"][field] = replacement
            bads.append(bad)
        mismatched = copy.deepcopy(good)
        mismatched["context"]["configSha256"] = "f" * 64
        bads.append(mismatched)
        for bad in bads:
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                history.parse_result(bad, selected)
        parsed = history.parse_result(good, selected)
        good["evidence"]["version"]["name"] = "9.9"
        self.assertEqual(parsed["evidence"]["version"]["name"], "1.2.3")


    def test_private_frames_bind_actual_nomination_clock_ready_go_and_terminal_without_authority(self):
        data = private_request()
        raw = wire.canonical(data, wire.REQUEST_LIMIT)
        selected = wire.parse_request(raw, history.HistoryBudget())
        self.assertEqual(selected.digest, hashlib.sha256(raw).hexdigest())
        self.assertEqual(json.loads(wire.ready_frame(selected))["ready"], {"requestSha256": selected.digest})
        go = {"protocol": wire.PROTOCOL, "id": selected.id,
              "go": {"requestSha256": selected.digest, "token": "inert-test-only"}}
        self.assertEqual(wire.parse_go(wire.canonical(go, wire.GO_LIMIT), selected, history.HistoryBudget()), "inert-test-only")
        self.assertNotIn(b"token", wire.ready_frame(selected))
        for change in (
            lambda x: x["native"].update(parentDescriptorReservation=True),
            lambda x: x["native"]["clock"].update(name="monotonic"),
            lambda x: x["native"]["clock"].update(hardEndNs="910000000001"),
            lambda x: x["native"]["provider"].update(relativePath="/usr/bin/gh"),
            lambda x: x["native"]["provider"]["identity"].update(mode=stat.S_IFREG | 0o755),
            lambda x: x["native"]["provider"].update(target="x86_64-apple-darwin"),
            lambda x: x["native"]["configIdentity"].update(bytes=str(512 * 1024 + 1)),
            lambda x: x["native"].update(workRoot=x["native"]["projectRoot"] + "/private"),
            lambda x: x.update(token="never-in-initial")):
            bad = copy.deepcopy(data); change(bad)
            with self.assertRaises(ValidationError):
                wire.parse_request(wire.canonical(bad, wire.REQUEST_LIMIT), history.HistoryBudget())
        for bad in (dict(go, id="other"), dict(go, go=dict(go["go"], token="bad token")),
                    dict(go, go=dict(go["go"], requestSha256="c" * 64))):
            with self.assertRaises(ValidationError):
                wire.parse_go(wire.canonical(bad, wire.GO_LIMIT), selected, history.HistoryBudget())
        life = {"complete": True, "fatal": False, "contained": True, "commandDispatched": True,
                "commands": 25, "verifierCalls": 19, "inputClosed": True, "handlersRestored": True,
                "invocationClosed": True, "stopObserved": False}
        positive = result(selected.context)
        self.assertEqual(json.loads(wire.terminal_frame(selected, positive, "none", life))["result"], positive)
        for bad in (dict(life, commands=True), dict(life, commands=18), dict(life, inputClosed=False),
                    dict(life, commandDispatched=None), dict(life, fatal=True), dict(life, stopObserved=True)):
            with self.assertRaises(ValidationError):
                wire.terminal_frame(selected, positive, "none", bad)
        failed = dict(life, commandDispatched=False, commands=1, verifierCalls=0)
        self.assertIsNone(json.loads(wire.terminal_frame(selected, None, "response-invalid", failed))["result"])

    def test_owned_files_reader_decode_zip_and_exact_retirement_preserve_originals(self):
        from mobile_release import workflow
        from mobile_release.workflow import _extract_zip
        with owned_files_fixture() as operation:
            retained = set(operation.live)
            operation.ensure_directory(operation.work / "data")
            path = operation.work / "data" / "value.json"
            operation.write_file(path, iter((b'{"n":1}',)))
            self.assertEqual(operation.read_json(path), {"n": 1})
            self.assertEqual(operation.read_json(path), {"n": 1})
            self.assertEqual(operation.budget._decodes, 3)  # Initial +two actual reads.
            self.assertEqual(operation.file_sha(path), hashlib.sha256(b'{"n":1}').hexdigest())
            # A parser-body refusal still proves actual source POST/one close.
            with self.assertRaisesRegex(ValidationError, "parser-only"):
                with operation.reader(path) as reader:
                    self.assertEqual(reader.read(3), b'{"n')
                    raise ValidationError("parser-only")
            self.assertFalse(operation.unknown)
            self.assertEqual(operation.live, retained)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipper:
                zipper.writestr("nested/value.txt", b"actual tiny bytes")
            zip_path = operation.work / "tiny.zip"
            operation.write_file(zip_path, iter((archive.getvalue(),)))
            destination = operation.work / "expanded"
            operation.ensure_directory(destination)
            original_gate, original_zip = workflow._validate_zip_source, zipfile.ZipFile
            gate_originals, decoder_originals = [], []
            def checked_gate(source):
                gate_originals.append(source.fileno())
                return original_gate(source)
            def checked_zip(source):
                decoder_originals.append(source.fileno())
                return original_zip(source)
            with patch.object(workflow, "_validate_zip_source", side_effect=checked_gate), \
                    patch.object(zipfile, "ZipFile", side_effect=checked_zip):
                _extract_zip(zip_path, destination, history.GIB, cancellation=operation.guard, history=operation)
            self.assertEqual(len(gate_originals), 1)
            self.assertEqual(gate_originals, decoder_originals)  # One actual held ZIP original.
            files, directories = operation.files(destination, history.GIB)
            self.assertEqual(set(files), {"nested/value.txt"})
            self.assertEqual(directories, {"nested"})
            with operation.reader(files["nested/value.txt"]) as reader:
                self.assertEqual(reader.read(), b"actual tiny bytes")
            operation.cleanup()
            self.assertTrue(operation.closed)
            self.assertEqual(list(operation.work.iterdir()), [])
            self.assertTrue(all(slot.close_state == "CLOSED" for slot in operation.slots))

        # A second pass cannot admit a new inode or substitute a directory
        # then restore the old namespace before final source/retirement POST.
        for replace_parent in (False, True):
            with self.subTest(replace_parent=replace_parent), owned_files_fixture() as operation:
                directory = operation.work / "data"
                operation.ensure_directory(directory)
                path = directory / "value.json"
                operation.write_file(path, iter((b'{"n":1}',)))
                before = _wire_identity(path.stat())
                self.assertEqual(operation.file_sha(path), hashlib.sha256(b'{"n":1}').hexdigest())
                original = directory if replace_parent else path
                parked = operation.work.parent / "retained-original"
                original.rename(parked)
                if replace_parent:
                    directory.mkdir(mode=0o700)
                path.write_bytes(b'{"n":2}')
                try:
                    with patch.object(operation, "decode", side_effect=AssertionError("replacement reached decoder")):
                        with self.assertRaises(ValidationError):
                            operation.read_json(path)
                    self.assertTrue(operation.unknown)
                finally:
                    path.unlink()
                    if replace_parent:
                        directory.rmdir()
                    parked.rename(original)
                self.assertEqual(path.read_bytes(), b'{"n":1}')
                if replace_parent:
                    self.assertEqual(_wire_identity(path.stat()), before)  # Original file never changed.

        # The config hash and later decode are bound to the retained source FD,
        # not two independently self-consistent fresh file observations.
        from mobile_release.build_inputs import _FD
        with owned_files_fixture() as operation:
            directory = operation.root / "release"
            directory.mkdir(mode=0o700)
            path = directory / "mobile-release.json"
            path.write_bytes(b'{"n":1}')
            parent = operation._directory(directory, retain=True)
            slot = _FD(operation.guard)
            identity = _wire_identity(path.stat())
            operation.sources.append((parent, path.name, slot, identity))
            slot.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent.fd)
            self.assertEqual(operation.file_sha(path), hashlib.sha256(b'{"n":1}').hexdigest())
            parked = operation.root / "retained-release"
            directory.rename(parked)
            directory.mkdir(mode=0o700)
            path.write_bytes(b'{"n":2}')
            try:
                with patch.object(operation, "decode", side_effect=AssertionError("replacement config decoded")):
                    with self.assertRaises(ValidationError):
                        operation.read_json(path)
                self.assertTrue(operation.unknown)
            finally:
                path.unlink(); directory.rmdir(); parked.rename(directory)
            self.assertEqual(_wire_identity(path.stat()), identity)

        # Mutation at the exact gate/ZipFile seam cannot select another ZIP
        # or reach ZipInfo allocation before the same original is rechecked.
        with owned_files_fixture() as operation:
            directory = operation.work / "archives"
            operation.ensure_directory(directory)
            path = directory / "tiny.zip"
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as zipper:
                zipper.writestr("value.txt", b"original")
            operation.write_file(path, iter((archive.getvalue(),)))
            before = _wire_identity(path.stat())
            destination = operation.work / "expanded"
            operation.ensure_directory(destination)
            parked = operation.work.parent / "retained-archive"
            original_gate = workflow._validate_zip_source
            def replace_after_gate(source):
                count = original_gate(source)
                directory.rename(parked)
                directory.mkdir(mode=0o700)
                path.write_bytes(b"unadmitted replacement ZIP")
                return count
            try:
                with patch.object(workflow, "_validate_zip_source", side_effect=replace_after_gate), \
                        patch.object(zipfile, "ZipFile", side_effect=AssertionError("unbound ZipInfo allocation")) as decoder:
                    with self.assertRaises(ValidationError):
                        _extract_zip(path, destination, history.GIB, cancellation=operation.guard, history=operation)
                    decoder.assert_not_called()
                self.assertTrue(operation.unknown)
                self.assertEqual(list(destination.iterdir()), [])
            finally:
                path.unlink(); directory.rmdir(); parked.rename(directory)
            self.assertEqual(_wire_identity(path.stat()), before)

    def test_owned_source_mutation_is_unknown_but_cancelled_known_files_still_retire(self):
        with owned_files_fixture() as operation:
            path = operation.work / "retained"
            operation.write_file(path, iter((b"before",)))
            with self.assertRaises(ValidationError):
                with operation.reader(path) as reader:
                    self.assertEqual(reader.read(), b"before")
                    # Actual same-name mutation, not a supplied failure boolean.
                    path.write_bytes(b"changed source")
            self.assertTrue(operation.unknown)
            self.assertEqual(operation.live, {slot for directory in operation.directories for slot in directory.slots})
            with self.assertRaises(ValidationError):
                operation.cleanup()
            self.assertTrue(path.exists())  # No guessed deletion after lost binding.
            self.assertTrue(all(slot.close_state == "CLOSED" for slot in operation.slots))
        with owned_files_fixture() as operation:
            operation.write_file(operation.work / "cancelled", iter((b"partial",)))
            operation.source.stop()
            with self.assertRaises(KeyboardInterrupt):
                operation.checkpoint()
            operation.cleanup()
            self.assertTrue(operation.closed)
            self.assertEqual(list(operation.work.iterdir()), [])

    def test_original_provider_reservation_uses_same_deadline_and_no_spawn_is_not_zero_attempts(self):
        from mobile_release.workflow import _TransportProcess
        with owned_files_fixture() as operation:
            operation.source.go_returned = True
            operation.token, operation.config = "inert-test-only", object()
            operation.budget.reserve_verifiers()
            args = ["gh", "api", "--hostname", "github.com", "--method", "GET", "user"]
            actual, env, maximum, timeout = operation.command(args, None, history.MIB, 120)
            self.assertEqual(actual[0], str(operation.provider))
            self.assertEqual(actual[1:], args[1:])
            self.assertEqual(env["GH_TOKEN"], "inert-test-only")
            self.assertFalse(set(env) & {"PATH", "HTTPS_PROXY", "SSL_CERT_FILE", "GH_DEBUG", "GIT_CONFIG"})
            self.assertEqual(maximum, history.MIB)
            self.assertLessEqual(timeout, 30)
            # Exercise SAME original object's known NEW retirement; no Popen,
            # fake wait result or native execution is supplied by this test.
            child = _TransportProcess(operation.guard, history=operation)
            operation.bind_child(child)
            child.cleanup(); child.release_settled(); operation.finish_child(child)
            self.assertEqual(operation.budget._calls, 1)
            self.assertFalse(operation.dispatched)
            self.assertIsNone(operation.current_child)
            operation.source.work_end = time.monotonic() - 1
            with self.assertRaises(KeyboardInterrupt):
                operation.command(args, None, history.MIB, 120)
            self.assertEqual(operation.budget._calls, 1)
        # Inert HTTP port, actual fixed identity parser/call ordering: a
        # delivered known negative still has all four identity observations.
        from mobile_release.workflow import Transport
        for failure, expected in ((HistoryRefused("artifact-missing"), ["user", "repos/owner/repo", "repos/owner/repo", "user"]),
                                  (ValidationError("unknown parser failure"), ["user", "repos/owner/repo"])):
            with owned_files_fixture() as operation:
                operation.source.go_returned = True
                observed = []
                def response(arguments, **keywords):
                    observed.append(arguments[-1])
                    value = {"id": 456} if arguments[-1] == "user" else {"id": 123, "full_name": "owner/repo"}
                    return json.dumps(value).encode()
                with patch.object(Transport, "run", side_effect=response), patch.object(HistoryOperation, "_observe", side_effect=failure):
                    with self.assertRaises(type(failure)):
                        operation.run("inert-test-only")
                self.assertEqual(observed, expected)
                self.assertEqual(operation.budget._auth, len(expected))
                self.assertEqual(operation.identity_complete, isinstance(failure, HistoryRefused))
