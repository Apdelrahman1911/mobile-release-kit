"""Inert provider transcripts + real tiny owned files; NOT native/gh proof.

Reuse the existing strict lifecycle fixture and HistoryOperation. No subprocess,
socket, Git, Store, Mac admission, native rename or positive native receipt is
executed. Supplied signature JSON is test DATA, never cryptographic evidence.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import stat
import tempfile
import time
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from mobile_release import github_candidate_download as download
from mobile_release import github_history as history
from mobile_release import _desktop_github_history_protocol as wire
from mobile_release._desktop_github_history_control import HistoryInput
from mobile_release.build_inputs import _FD
from mobile_release.cancellation import DefaultCancellation
from mobile_release.desktop_github_history import HistoryOperation, HistoryRefused, _wire_identity
from mobile_release.errors import ValidationError
from mobile_release.owned_process import ProcessCleanupError
from mobile_release import workflow
from desktop.test_github_history import private_request, context, result
from workflow import test_workflow_recovery as recovery
from unit import evidence_helpers


@contextmanager
def original(selected=None, *, enabled=True):
    """Same real file/guard ledger recipe as History's owned_files_fixture.

    Initial pins/raw clock/GO are deliberately fixture DATA. The producer and
    every destination descriptor are actual originals, but no native owner is
    minted or settled by these tests. Native publication remains UNRUN.
    """
    selected = selected or context()
    with tempfile.TemporaryDirectory(prefix="candidate-owned-") as temporary:
        base = Path(temporary)
        root, work = base / "project", base / "work"
        root.mkdir(mode=0o700); work.mkdir(mode=0o700)
        release = root / "release"; release.mkdir(mode=0o700)
        config = release / "mobile-release.json"; config.write_bytes(b"{}")
        config.chmod(0o600)
        parent = release / "downloads"; parent.mkdir(mode=0o700)
        final, pending, primary = download.names(selected.selection)
        stage = parent / pending; stage.mkdir(mode=0o700)
        for name in (primary, download.RECEIPT):
            fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        source = HistoryInput(time.monotonic())
        source.raw_clock = time.CLOCK_MONOTONIC
        source.raw_work_end = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + 30_000_000_000
        source.raw_hard_end = source.raw_work_end + 10_000_000_000
        source.work_end = time.monotonic() + 30; source.hard_end = source.work_end + 10
        data = private_request(str(root), str(work), initial_context=selected)
        data["native"].update(rootIdentity=_wire_identity(root.stat(), True),
                              workIdentity=_wire_identity(work.stat(), True), configIdentity=_wire_identity(config.stat()))
        if enabled:
            data["native"]["download"] = {"consentVersion": download.CONSENT,
                "parentIdentity": _wire_identity(parent.stat(), True), "stagingIdentity": _wire_identity(stage.stat(), True),
                "primaryIdentity": _wire_identity((stage / primary).stat()), "receiptIdentity": _wire_identity((stage / download.RECEIPT).stat())}
        request = wire.parse_request(wire.canonical(data, wire.REQUEST_LIMIT), source.budget)
        source.initial, source.request_returned = request, True
        reader, writer = os.pipe(); os.set_blocking(reader, False)
        seen = os.fstat(reader)
        source.fd, source.identity, source.acquired = reader, (seen.st_dev, seen.st_ino, seen.st_mode), True
        guard = DefaultCancellation(ProcessCleanupError, "test original cleanup")
        guard._install_github_history_source(source)
        op = HistoryOperation(request, source, guard, str(base))
        try:
            op._directory(work, retain=True)
            held = op._directory(release, retain=True)
            slot = _FD(guard)
            op.sources.append((held, config.name, slot, _wire_identity(config.stat())))
            slot.open(config.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=held.fd)
            op.budget.reserve_verifiers()
            # Contained test DATA, not a free-disk/native-admission claim: this
            # host may have <6GiB free; every actual fixture is only kilobytes.
            class Space:
                f_frsize = 1
                f_bavail = 7 * history.GIB
            with patch.object(download.os, "fstatvfs", return_value=Space()):
                yield op, stage, parent / final
        finally:
            try:
                if not op.closed:
                    try: op.cleanup()
                    except ValidationError:
                        if not op.unknown: raise
            finally:
                try: source.close()
                finally: os.close(writer)


class Transcript(workflow.Transport):
    """Only the provider boundary is inert; parsers/verifier/ZIP/writes are real."""
    def __init__(self, api, operation):
        self.api, self.operation = api, operation
        self.entered = []
        self.account = 456
    def run(self, arguments, *, history=None, output=None, maximum=1024*1024, timeout=120, cancellation=None):
        op = self.operation
        assert history is op and cancellation is op.guard
        op.require_owner(cancellation); op.checkpoint()
        self.entered.append(list(arguments))
        if arguments[:3] == ["gh", "attestation", "verify"]:
            op.budget.claim_verifier()
        else:
            op.budget.claim_call()
            assert arguments[:6] == ["gh", "api", "--hostname", "github.com", "--method", "GET"]
        endpoint = arguments[-1]
        if output is not None:
            assert output == op.work / "download.zip" and endpoint.endswith("/zip")
            raw = self.api.zips[int(endpoint.split("/")[-2])]
            assert len(raw) <= maximum
            op.write_file(output, (raw,))
            return b""
        if endpoint == "user": return json.dumps({"id": self.account}).encode()
        if endpoint == "repos/example/mobile-app": return b'{"id":100000000,"full_name":"example/mobile-app"}'
        return self.api.run(arguments, maximum=maximum, timeout=timeout, cancellation=cancellation)


@contextmanager
def lifecycle(platform="android"):
    # The preexisting fixture defaults to a different tooling repo; nominate
    # the fixed History repository in fixture construction, not product policy.
    old = evidence_helpers.workflow_environment
    def environment(*args, **kw):
        return dict(old(*args, **kw), MOBILE_RELEASE_REUSABLE_WORKFLOW_REPOSITORY=history.TOOLING_REPOSITORY)
    with tempfile.TemporaryDirectory(prefix="candidate-proof-data-") as temporary, \
            patch.object(evidence_helpers, "workflow_environment", environment), \
            patch.object(recovery, "workflow_environment", environment):
        api = recovery.FakeGitHub()
        life = recovery.Lifecycle(Path(temporary), api, platform)
        life.create("candidate")
        selected = life.contexts["candidate"]
        api.upload(selected, life.handoff, "handoff")
        c = history.HistoryContext.parse(dict(context(platform).value(),
            repository="example/mobile-app", repositoryId="100000000", toolingSha=selected.trusted_tooling_commit,
            selection={"runId": selected.authority["runId"], "attempt": selected.authority["attempt"], "stage":"candidate", "platform":platform}))
        api.requests.clear()
        yield api, life, c


def observe(op, api):
    transport = Transcript(api, op)
    client = workflow.GitHub(op.request.context.verifier_context(), transport, history=op, cancellation=op.guard)
    op.candidate_download.admit()
    op._observe(client)
    return client, transport


class CandidateDownloadTests(unittest.TestCase):
    def test_both_platforms_use_actual_verifier_handoff_attestation_and_two_original_outputs(self):
        for platform in ("android", "ios"):
            with self.subTest(platform=platform), lifecycle(platform) as (api, life, c), original(c) as (op, stage, final):
                client, transport = observe(op, api)
                facet = op.candidate_download
                self.assertTrue(facet.finished)
                self.assertEqual({p.name for p in stage.iterdir()}, {facet.primary, download.RECEIPT})
                self.assertEqual((stage / facet.primary).read_bytes(), (life.handoff / facet.primary).read_bytes())
                receipt = json.loads((stage / download.RECEIPT).read_bytes())
                self.assertEqual(receipt["authorizedBy"], life.intents["candidate"]["authorizedBy"])
                self.assertEqual(receipt["context"], c.value())
                self.assertEqual(receipt["primary"]["sha256"], facet.result["primarySha256"])
                self.assertEqual(receipt["artifactSha256"], facet.handoff["digest"][7:])
                self.assertEqual(op.budget._verifiers, 4)
                self.assertEqual(op.budget._downloads, 3)
                self.assertLess(op.budget._calls, 128)
                self.assertTrue(all(path.is_relative_to(op.work) for path in (r["path"] for r in op.created)))
                self.assertFalse(final.exists())  # Python never publishes.
                slots = tuple(slot for _, slot, _ in facet.files)
                op.cleanup()
                self.assertTrue(op.closed and all(slot.close_state == "CLOSED" for slot in slots))
                self.assertTrue((stage / facet.primary).exists())
                self.assertEqual(list(op.work.iterdir()), [])
                self.assertFalse(final.exists())
                with self.assertRaises(ValidationError): facet.allow_handoff(client, facet.handoff, facet.handoff_path)

    def test_fresh_final_verification_not_displayed_result_is_required(self):
        with original() as (op, _, _):
            facet = op.candidate_download; facet.admit()
            client = workflow.GitHub(op.request.context.verifier_context(), history=op, cancellation=op.guard)
            with self.assertRaises(ValidationError): facet.prepare(client, op.work, result(op.request.context))
            self.assertFalse(facet.entered)

    def test_handoff_identity_head_expiry_and_ambiguity_refuse_before_primary_write(self):
        for field in ("head", "expired", "duplicate", "missing"):
            with self.subTest(field=field), lifecycle() as (api, life, c), original(c) as (op, stage, final):
                rows = api.artifacts[c.selection.run_id]
                item = next(v for v in rows if v["name"].endswith("handoff-android"))
                if field == "head": item["workflow_run"]["head_sha"] = "f" * 40
                elif field == "expired": item["expired"] = True
                elif field == "duplicate": rows.append(dict(item, id=item["id"]+1))
                else: rows.remove(item)
                with self.assertRaises(ValidationError): observe(op, api)
                self.assertEqual((stage / op.candidate_download.primary).stat().st_size, 0)
                self.assertFalse(final.exists())

    def test_wrong_primary_attestation_retains_empty_candidates_without_fallback(self):
        with lifecycle() as (api, life, c), original(c) as (op, stage, final):
            digest = hashlib.sha256((life.handoff / "app-release.aab").read_bytes()).hexdigest()
            api.signatures[digest][0]["verificationResult"]["signature"]["certificate"]["buildSignerDigest"] = "f" * 40
            with self.assertRaises(ValidationError): observe(op, api)
            self.assertEqual((stage / "app-release.aab").stat().st_size, 0)
            self.assertFalse(final.exists() or op.candidate_download.finished)

    def test_full_handoff_layout_checksums_and_no_nested_extraction(self):
        for bad in ("checksum", "unexpected", "traversal", "case-duplicate", "symlink"):
            with self.subTest(bad=bad), lifecycle() as (api, life, c), original(c) as (op, stage, final):
                row = next(v for v in api.artifacts[c.selection.run_id] if "handoff" in v["name"])
                with zipfile.ZipFile(io.BytesIO(api.zips[row["id"]])) as archive:
                    members = [(v.filename, archive.read(v)) for v in archive.infolist()]
                if bad == "checksum": members = [(n, b"changed" if n == "app-release.aab" else v) for n, v in members]
                elif bad == "unexpected": members.append(("not-canonical.txt", b"inert"))
                elif bad == "traversal": members.append(("../outside", b"inert"))
                elif bad == "case-duplicate": members.append(("APP-RELEASE.AAB", b"inert"))
                else:
                    info = zipfile.ZipInfo("link"); info.create_system = 3; info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    members.append((info, b"app-release.aab"))
                data = io.BytesIO()
                with zipfile.ZipFile(data, "w") as archive:
                    for name, value in members: archive.writestr(name, value)
                raw = data.getvalue(); api.zips[row["id"]] = raw
                row.update(size_in_bytes=len(raw), digest="sha256:"+hashlib.sha256(raw).hexdigest())
                with self.assertRaises(ValidationError): observe(op, api)
                self.assertEqual((stage / "app-release.aab").stat().st_size, 0)
                self.assertFalse(final.exists() or (op.work / "outside").exists())

    def test_private_consent_pins_are_closed_and_old_request_digest_is_unchanged(self):
        raw = private_request()
        old = wire.parse_request(wire.canonical(raw, wire.REQUEST_LIMIT), history.HistoryBudget())
        self.assertEqual(old.digest, hashlib.sha256(wire.canonical(raw, wire.REQUEST_LIMIT)).hexdigest())
        with original() as (op, _, _):
            pins = copy.deepcopy(op.request.native["download"])
            for mutate in (lambda p: p.update(consentVersion="read"), lambda p: p.update(path="elsewhere"),
                           lambda p: p["primaryIdentity"].update(bytes="1"),
                           lambda p: p.update(receiptIdentity=copy.deepcopy(p["primaryIdentity"]))):
                value = copy.deepcopy(pins); mutate(value)
                with self.assertRaises(ValidationError): download.native(value, op.request.context)
            with self.assertRaises(ValidationError): download.native(pins, context(stage="external-testing"))
            self.assertNotIn("download", old.native)

    def test_existing_parent_and_candidate_replacement_never_get_adopted(self):
        for replace_parent in (False, True):
            with self.subTest(parent=replace_parent), original() as (op, stage, _):
                target = stage.parent if replace_parent else stage / "app-release.aab"
                moved = target.with_name(target.name + "-displaced")
                target.rename(moved)
                if replace_parent: target.mkdir(mode=0o700)
                else: target.write_bytes(b""); target.chmod(0o600)
                with self.assertRaises(ValidationError): op.candidate_download.admit()
                self.assertTrue(moved.exists())

    def test_actual_short_writes_complete_but_sync_failure_never_finishes(self):
        with original() as (op, stage, _):
            facet = op.candidate_download; facet.admit()
            raw = b"tiny original bytes"; digest = hashlib.sha256(raw).hexdigest(); real = os.write
            with patch.object(download.os, "write", side_effect=lambda fd, value: real(fd, value[:2])):
                facet._write(0, (raw,), digest, len(raw))
            self.assertEqual((stage / facet.primary).read_bytes(), raw)
            with self.assertRaises(ValidationError): facet._write(0, (raw,), digest, len(raw))
            with patch.object(download.os, "fsync", side_effect=OSError("inert sync failure")), self.assertRaises(OSError):
                facet._write(1, (raw,), digest, len(raw))
            self.assertFalse(facet.finished)

    def test_same_filesystem_disk_check_is_sum_not_max_and_precedes_writes(self):
        class Space:
            f_frsize = 1
            f_bavail = 5 * history.GIB
        with original() as (op, stage, _), patch.object(download.os, "fstatvfs", return_value=Space()):
            with self.assertRaises(ValidationError): op.candidate_download.admit()
            self.assertEqual((stage / "app-release.aab").stat().st_size, 0)

    def test_original_work_expiry_stops_candidate_writes_without_new_clock(self):
        with original() as (op, stage, _):
            facet = op.candidate_download; facet.admit()
            op.source.work_end = time.monotonic() - 1
            raw = b"must not write"
            with self.assertRaises(KeyboardInterrupt): facet._write(0, (raw,), hashlib.sha256(raw).hexdigest(), len(raw))
            self.assertEqual((stage / facet.primary).stat().st_size, 0)
            self.assertFalse(facet.finished)

    def test_ordinary_history_still_refuses_handoff_and_download_is_once_original_bound(self):
        with original(enabled=False) as (op, _, _):
            client = workflow.GitHub(op.request.context.verifier_context(), history=op, cancellation=op.guard)
            with self.assertRaises(ValidationError): client.download({}, op.work / "handoff", handoff=True)
        with original() as (op, _, _):
            facet = op.candidate_download; facet.admit(); facet.entered = True
            facet.handoff, facet.handoff_path = {"inert":"original"}, op.work / "handoff"
            client = workflow.GitHub(op.request.context.verifier_context(), history=op, cancellation=op.guard)
            with self.assertRaises(ValidationError): facet.allow_handoff(client, dict(facet.handoff), facet.handoff_path)
            facet.allow_handoff(client, facet.handoff, facet.handoff_path)
            with self.assertRaises(ValidationError): facet.allow_handoff(client, facet.handoff, facet.handoff_path)

    def test_actual_run_requires_same_account_and_repository_after_candidate_writes(self):
        # Only the provider response is replaced; run/identity/POST/one-use
        # sequencing are the actual HistoryOperation, not a fabricated result.
        for drift in ("none", "account-before", "account-after", "repository-after"):
            with self.subTest(drift=drift), lifecycle() as (api, life, c), original(c) as (op, stage, final):
                class IdentityTranscript(Transcript):
                    def __init__(self, api, op):
                        super().__init__(api, op)
                        self.identities = []
                    def run(self, arguments, **kwargs):
                        endpoint = arguments[-1]
                        if endpoint in ("user", "repos/example/mobile-app"):
                            self.identities.append(endpoint)
                            if endpoint == "user":
                                self.account = 789 if drift == "account-before" or drift == "account-after" and len(self.identities) == 4 else 456
                        raw = super().run(arguments, **kwargs)
                        if endpoint == "repos/example/mobile-app" and drift == "repository-after" and len(self.identities) == 3:
                            return b'{"id":100000001,"full_name":"example/mobile-app"}'
                        return raw
                transcript = IdentityTranscript(api, op)
                op.candidate_download.admit()
                op.source.go_returned = True  # Inert initial/GO DATA, never native authority.
                with patch.object(workflow, "Transport", return_value=transcript):
                    if drift == "none":
                        self.assertIs(op.run("inert-no-credential"), op.final_observation)
                        self.assertTrue(op.identity_complete)
                        self.assertEqual(transcript.identities, ["user", "repos/example/mobile-app", "repos/example/mobile-app", "user"])
                    else:
                        with self.assertRaises(HistoryRefused):
                            op.run("inert-no-credential")
                        self.assertFalse(op.identity_complete)
                if drift == "account-before":
                    self.assertEqual(len(transcript.entered), 1)
                    self.assertEqual((stage / op.candidate_download.primary).stat().st_size, 0)
                else:
                    self.assertTrue(op.candidate_download.finished)
                self.assertFalse(final.exists())

    def test_private_terminal_requires_download_and_actual_lifetime_fields_without_changing_old_frames(self):
        # Grammar DATA only, not a genuine close/wait acknowledgement.
        life = {"complete": True, "fatal": False, "contained": True, "commandDispatched": True,
                "commands": 25, "verifierCalls": 4, "inputClosed": True, "handlersRestored": True,
                "invocationClosed": True, "stopObserved": False}
        with original() as (op, _, _):
            candidate = {"primarySha256": "1"*64, "primaryBytes": 3, "receiptSha256": "2"*64, "receiptBytes": 3}
            positive = result(op.request.context)
            frame = json.loads(wire.terminal_frame(op.request, positive, "none", life, download=candidate))
            self.assertEqual(frame["download"], candidate)
            for changed in (None, dict(candidate, receiptBytes=4097), dict(candidate, path="somewhere")):
                with self.assertRaises(ValidationError):
                    wire.terminal_frame(op.request, positive, "none", life, download=changed)
            for changed in (dict(life, inputClosed=False), dict(life, fatal=True), dict(life, stopObserved=True)):
                with self.assertRaises(ValidationError):
                    wire.terminal_frame(op.request, positive, "none", changed, download=candidate)
            failed = json.loads(wire.terminal_frame(op.request, None, "response-invalid", life))
            self.assertIn("download", failed); self.assertIsNone(failed["download"])
        with original(enabled=False) as (op, _, _):
            old = wire.terminal_frame(op.request, result(op.request.context), "none", life)
            self.assertNotIn("download", json.loads(old))
            with self.assertRaises(ValidationError):
                wire.terminal_frame(op.request, result(op.request.context), "none", life, download=candidate)
