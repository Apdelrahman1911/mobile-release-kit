"""Actual closed worker/ACK/source code with INERT Git/C-A-W outcomes.

Existing BranchTests forbids Popen. Modeled native mkdir/ACK is expressly DATA;
it neither exercises nor qualifies native SourceBook, Store, consent or joins.
"""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_local_protocol as wire
from mobile_release import _desktop_git_read_protocol as fields
from mobile_release import git_repository_upstream as upstream
from mobile_release import git_repository_upstream_transaction as tx
from mobile_release import git_repository_upstream_wire as codec
from mobile_release import git_service as core
from mobile_release.desktop_git_local import GitLocalOperation, _Engine
import test_desktop_git_local_protocol as old_wire
import test_git_repository_upstream as fixture
import test_git_repository_local as old


def row(phase="prepare"):
    v = old_wire.fixture(phase=phase)
    v["action"] = {"kind": "set-upstream", "expectedRevision": "a" * 64,
        "expectedReferenceRevision": "c" * 64, "branch": "refs/heads/main", "head": "1" * 40,
        "remote": "origin", "repository": "example/project", "identity": None}
    paths = upstream.parent_paths("refs/remotes/origin/main")
    present = (".", "logs", "refs", "logs/refs")
    names = {".": ["HEAD", "config", "index", "logs", "objects", "refs"],
             "logs": ["refs"], "refs": ["heads"], "logs/refs": ["heads"]}
    v["upstream"] = {"parents": [{"name": n,
        "identity": [1, i + 2, stat.S_IFDIR | 0o700, 1001, 1001, 1, 32, 123, 456],
        "names": names[n]} for i, n in enumerate(present)],
        "missing": [n for n in paths if n not in present], "reference": None, "log": None}
    return v


class UpstreamWireTests(unittest.TestCase):
    def setUp(self):
        stop = patch("subprocess.Popen", side_effect=AssertionError("No process in Upstream DATA tests"))
        stop.start(); self.addCleanup(stop.stop)

    def test_exact_local_action_needs_original_parent_projection_on_both_phases(self):
        for phase in ("prepare", "apply"):
            request = wire.parse_request(old_wire.frame(row(phase)))
            self.assertIs(type(request.action), codec.Action)
            self.assertIs(type(request.upstream_sources), codec.Sources)
        for change in (lambda v: v.pop("upstream"), lambda v: v.update(upstream=None),
                       lambda v: v["action"].update(url="https://github.com/example/project.git"),
                       lambda v: v["action"].update(token="not-a-token"),
                       lambda v: v["action"].update(targetOid="1" * 40),
                       lambda v: v["action"].update(identity={"name": "Only name"}),
                       lambda v: v["action"].update(branch="refs/remotes/origin/main"),
                       lambda v: v["native"]["files"].update(index=None)):
            v = row(); change(v)
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(v))
        for kind in ("stage", "unstage", "commit"):
            v = old_wire.fixture(kind)
            self.assertIsNone(wire.parse_request(old_wire.frame(v)).upstream_sources)
            v["upstream"] = row()["upstream"]
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(v))

    def test_absence_is_exact_parent_names_not_a_missing_or_partial_dto(self):
        for change in (lambda v: v["upstream"]["parents"][0]["identity"].__setitem__(3, 0),
                       lambda v: v["upstream"]["parents"][2]["names"].append("remotes"),
                       lambda v: v["upstream"]["parents"][2]["names"].append("Remotes"),
                       lambda v: v["upstream"]["missing"].pop(),
                       lambda v: v["upstream"]["missing"].append("../escape"),
                       lambda v: v["upstream"]["parents"].reverse()):
            v = row(); change(v)
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(v))
        v = row(); source = v["upstream"]
        # All parent paths now exist, but a reference snapshot cannot substitute
        # for absence/presence in that exact original parent's named entries.
        for i, name in enumerate(source["missing"]):
            names = [Path(p).name for p in source["missing"] if str(Path(p).parent) == name]
            source["parents"].append({"name": name,
                "identity": [1, 20 + i, stat.S_IFDIR | 0o700, 1001, 1001, 1, 32, 123, 456],
                "names": sorted(names)})
        source["parents"][2]["names"].append("remotes")
        source["parents"][3]["names"].append("remotes")
        source["missing"] = []
        wire.parse_request(old_wire.frame(v))
        leaf = next(p for p in source["parents"] if p["name"] == "refs/remotes/origin")
        for name in ("main", "MAIN"):
            leaf["names"] = [name]
            with self.assertRaises(wire.ProtocolError): wire.parse_request(old_wire.frame(v))

    def test_family_reasons_and_publication_paths_do_not_expand_old_actions(self):
        request = wire.parse_request(old_wire.frame(row()))
        old_request = wire.parse_request(old_wire.frame(old_wire.fixture()))
        for reason in upstream.REASONS:
            wire.terminal(request, "refused", reason=reason, first_failure_ns=request.work_end_ns,
                          cleanup_end_ns=request.hard_end_ns)
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(old_request, "refused", reason=reason, first_failure_ns=old_request.work_end_ns,
                              cleanup_end_ns=old_request.hard_end_ns)
        for path in ("/private/key", ".git/HEAD", ".git/refs/heads/main", ".git/mrk-git-x/../index"):
            self.assertFalse(codec.Progress("directories-returned", (path,)).valid(
                "upstream-directories-returned", request.action))


class UpstreamWorkerTests(unittest.TestCase):
    setUp = fixture.UpstreamTests.setUp
    write = fixture.UpstreamTests.write
    prepared = fixture.UpstreamTests.prepared
    release_fixture_descriptors = fixture.UpstreamTests.release_fixture_descriptors

    @contextmanager
    def operation(self, phase="apply"):
        _, review, _ = self.prepared()
        value = row(phase)
        value["action"] = codec.Action(review.plan._snapshot.public.revision, review.plan.reference_revision,
            old.BRANCH, old.HEAD, "origin", "example/project", None).as_dict()
        if phase == "apply": value["reviewDigest"] = review.digest
        tool = self.base / "inert-tool"; tool.write_bytes(b"synthetic DATA, not an executable")
        def snapshot(path):
            return fields.FileSnapshot(path, fields.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        controls = review.plan._controls
        native = codec.Sources(controls.parents, controls.missing, None, None)
        # Only synthetic native DTO replacement; the actual native reader would
        # refuse this provider. The unchanged worker below owns its real FDs.
        request = replace(wire.parse_request(old_wire.frame(value)), uid=os.getuid(), gid=os.getgid(), root=self.root,
            directories=tuple((p, fields.directory_identity(p.stat())) for p in
                              (self.root, self.root / ".git", self.root / ".git/objects")),
            tool=snapshot(tool), files=tuple(snapshot(self.root / ".git" / n) for n in ("HEAD", "config", "index")),
            upstream_sources=native)
        engine = _Engine(time.monotonic()); source, guard = engine.input, engine.guard
        engine.request = source.initial = request; source.request_returned = source.acquired = True
        guard._install_saved_command_source(source)
        operation = engine.operation = GitLocalOperation(request, source, guard, engine)
        source.ready_sent = source.go_returned = source.active = True
        def returned(argv, **options):
            command = object(); guard.lifetime_ledger._bind_command(command)
            result = self.fake(argv, **options)
            guard.lifetime_ledger._finish_command(command, dispatched=True, contained=True, cleanup_complete=True)
            return result
        try:
            with patch.object(guard, "check", return_value=None), \
                    patch("mobile_release._command_process.run_command", side_effect=returned) as calls:
                yield operation, calls
        finally:
            if operation.repository is not None: self.repositories.append(operation.repository)
            operation.cleanup(); source.close()

    def modeled_ack(self, operation, mutate=None):
        """DATA-only model of native's exact post-CAS parent creation."""
        t = operation.repository._transaction
        for name in t.intent.missing_directories:
            (self.root / ".git" / name).mkdir(mode=0o700)
        if mutate: mutate(t)
        parents = tuple(upstream.Parent(n, upstream.directory(self.root / ".git" / n),
            tuple(t.session.names(self.root / ".git" / n))) for n in upstream.parent_paths("refs/remotes/origin/main"))
        digest = tx.directory_digest(t.intent, t.plan._controls.parents, parents)
        return (b"MRK-GIT-UPSTREAM-ACK/1 " + operation.request.digest.encode() + b" "
                + operation.source.candidate.digest.encode() + b" 5 " + digest.encode() + b"\n")

    def test_original_prepare_is_read_only_and_has_no_candidate_or_configuration_command(self):
        with self.operation("prepare") as (op, calls):
            op.admit(); op.run()
            self.assertTrue(op.returned); self.assertIs(type(op.review), upstream.UpstreamReview)
            self.assertIsNone(op.diff); self.assertIsNone(op.result)
            self.assertFalse(op.source.candidate_claimed); self.assertEqual(self.fake.added, [])
            self.assertFalse((self.root / ".git/refs/remotes").exists())
            value = wire.terminal(op.request, "ok", reason=None, review=op.review,
                first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(value)["result"], {"review": op.review.as_dict()})
            self.assertEqual(calls.call_count, op.calls)

    def test_actual_config_return_keeps_old_fd_and_unchanged_originals_until_sole_close(self):
        with self.operation() as (op, calls):
            op.admit()
            originals = [(o, o.fd) for o in op.originals]
            old_config = op.upstream_state.old
            before = (self.root / ".git/config").read_bytes()
            with patch.object(op.engine, "write") as output, patch.object(op.source, "_frame", side_effect=lambda _: self.modeled_ack(op)):
                op.run()
            self.assertTrue(op.returned and op.source.candidate_returned)
            self.assertEqual(op.result.state, "succeeded"); self.assertEqual(op.publication(), "upstream-config-returned")
            self.assertEqual(op.upstream_state.progress, codec.Progress("config-returned", ()))
            self.assertTrue((self.root / ".git/config").read_bytes().startswith(before))
            self.assertFalse((self.root / ".git/refs/remotes/origin/main").exists())
            self.assertEqual(len(self.fake.added), 4); output.assert_called_once()
            for original, fd in originals:
                self.assertEqual(original.fd, fd)
                if original.sha256 is not None:
                    self.assertEqual(os.fstat(fd).st_nlink, 0 if original is old_config else 1)
            self.assertNotEqual(op.upstream_state.successor.identity[:2], old_config.identity[:2])
            self.assertEqual(calls.call_count, op.calls)
            encoded = wire.terminal(op.request, "ok", reason=None, result=op.result, publication=op.publication(),
                progress=op.upstream_state.progress, first_failure_ns=None, cleanup_end_ns=op.request.hard_end_ns)
            self.assertEqual(json.loads(encoded)["result"]["effectPhase"], "config-returned")
            op.cleanup(); self.assertTrue(op.closed)
            self.assertTrue(all(o.closed for o, _ in originals)); self.assertTrue(op.upstream_state.successor.closed)

    def test_missing_parent_drift_refuses_before_any_command_or_candidate(self):
        with self.operation() as (op, calls):
            op.admit()
            (self.root / ".git/refs/remotes").mkdir(mode=0o700)
            with self.assertRaises((wire.ProtocolError, core.GitError)): op.run()
            self.assertEqual(calls.call_count, 0); self.assertFalse(op.source.candidate_claimed)
            self.assertTrue((self.root / ".git/refs/remotes").is_dir())

    def test_lost_directory_ack_never_replays_or_claims_config_success(self):
        with self.operation() as (op, _):
            op.admit(); before = (self.root / ".git/config").read_bytes()
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=KeyboardInterrupt("inert ACK loss")):
                with self.assertRaises(KeyboardInterrupt): op.run()
            self.assertTrue(op.source.candidate_claimed); self.assertFalse(op.source.candidate_returned)
            self.assertIsNone(op.repository._transaction.config_returned)
            self.assertEqual((self.root / ".git/config").read_bytes(), before)
            with self.assertRaises(wire.ProtocolError): op.source.handoff(op.source.candidate)
            op.cleanup(); self.assertFalse(op.closed); self.assertTrue(op.unknown)

    def test_foreign_entry_is_not_native_ack_authority_even_when_digest_agrees(self):
        with self.operation() as (op, _):
            op.admit(); before = (self.root / ".git/config").read_bytes()
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lambda _: self.modeled_ack(op,
                lambda t: (self.root / ".git/refs/remotes/origin/foreign").write_bytes(b"unrelated"))):
                with self.assertRaises((wire.ProtocolError, core.GitError)): op.run()
            self.assertFalse(op.source.candidate_returned); self.assertIsNone(op.repository._transaction.config_returned)
            self.assertEqual((self.root / ".git/config").read_bytes(), before)
            self.assertEqual((self.root / ".git/refs/remotes/origin/foreign").read_bytes(), b"unrelated")

    def test_ack_parser_binds_original_request_candidate_revision_and_full_digest(self):
        with self.operation() as (op, _):
            op.admit()
            def ack(_):
                raw = self.modeled_ack(op)
                sent = op.source.candidate
                revision, digest = wire.upstream_acknowledged(op.request, sent, raw)
                self.assertEqual(revision, 5); self.assertEqual(len(digest), 64)
                with self.assertRaises(wire.ProtocolError): wire.upstream_acknowledged(replace(op.request), sent, raw)
                with self.assertRaises(wire.ProtocolError): wire.acknowledged(op.request, sent, raw)
                for bad in (raw + b"\n", raw + raw, raw.replace(b" 5 ", b" 4 "), raw.replace(b" 5 ", b" 05 "),
                            raw.replace(sent.digest.encode(), b"f" * 64), raw.replace(b"UPSTREAM", b"LOCAL")):
                    with self.assertRaises(wire.ProtocolError): wire.upstream_acknowledged(op.request, sent, bad)
                return raw
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=ack): op.run()
            self.assertTrue(op.source.candidate_returned); self.assertEqual(op.result.state, "succeeded")

    def test_injected_post_replace_fsync_loss_retains_originals_and_never_calls_it_success(self):
        with self.operation() as (op, _):
            op.admit(); old_config = op.upstream_state.old; fd = old_config.fd
            fsync = os.fsync; replaced = []
            def fail_directory(number):
                t = op.repository._transaction if op.repository else None
                current = os.fstat(number)
                if t and t.config_attempted and stat.S_ISDIR(current.st_mode):
                    replaced.append(current.st_ino)
                    raise OSError("inert missing post-replace fsync receipt")
                return fsync(number)
            with patch.object(op.engine, "write"), patch.object(op.source, "_frame", side_effect=lambda _: self.modeled_ack(op)), \
                    patch.object(tx.os, "fsync", side_effect=fail_directory):
                with self.assertRaises((wire.ProtocolError, core.GitError)): op.run()
            self.assertEqual(len(replaced), 1); self.assertEqual(os.fstat(fd).st_nlink, 0)
            self.assertIs(old_config, op.upstream_state.old); self.assertIsNone(op.upstream_state.successor)
            self.assertTrue(op.repository._unknown and op.repository._transaction.retained)
            self.assertNotEqual(op.result.state if op.result else None, "succeeded")
            self.assertTrue((self.root / ".git/refs/remotes/origin").is_dir())
            with self.assertRaises(wire.ProtocolError): op.source.handoff(op.source.candidate)
            op.cleanup(); self.assertFalse(op.closed)

    def test_unjoined_command_cannot_grant_directory_or_config_publication(self):
        with self.operation() as (op, _):
            op.admit()
            with patch("mobile_release._command_process.run_command", side_effect=self.fake):
                with self.assertRaises(wire.ProtocolError): op.run()
            self.assertFalse(op.source.candidate_claimed); self.assertIsNone(op.upstream_state.successor)
            self.assertEqual(self.fake.added, [])


if __name__ == "__main__":
    unittest.main()
