"""Passive actual-control/worker composition, never Git/native/Store execution.

Run with the exact Root-only Python hooks applied or projected into a private
source copy. Popen is forbidden. Synthetic source files and explicitly FAKE
C/A/W ledger returns exercise control semantics only, not installed admission.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_local_protocol as wire
from mobile_release import _desktop_git_read_protocol as fields
from mobile_release import git_repository_local as local
from mobile_release import git_service as core
from mobile_release._desktop_git_local_control import GitLocalInput
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain
from mobile_release.desktop_git_local import GitLocalOperation, _Engine
from mobile_release.owned_process import run_owned
from test_desktop_git_local_protocol import fixture, frame
import test_git_repository_local as core_fixture
from test_git_repository_local import FakeGit, projected_hook, HEAD, OLD_INDEX, CANDIDATE_INDEX


@contextmanager
def synthetic_operation(kind="stage", *, phase="apply"):
    with tempfile.TemporaryDirectory(prefix="mrk-git-local-worker-data-") as name, projected_hook():
        base=Path(name);root=base/"project"
        for relative in ("", ".git", ".git/objects", ".git/objects/info", ".git/objects/pack", ".git/refs", ".git/refs/heads"):
            (root/relative).mkdir(mode=0o700)
        for name,body in {".git/HEAD":b"ref: refs/heads/main\n", ".git/config":b"[core]\nbare=false\nrepositoryformatversion=0\n",
                ".git/refs/heads/main":(HEAD+"\n").encode(),".git/index":OLD_INDEX,"a.txt":b"edited a\n","b.txt":b"unrelated staged\n"}.items():
            (root/name).write_bytes(body)
        tool=base/"inert-tool";tool.write_bytes(b"never executable, fixture DATA")
        fake=FakeGit(root)
        if kind=="commit":fake.status=b"M  a.txt\0M  b.txt\0"
        engine=_Engine(time.monotonic());source,guard=engine.input,engine.guard
        mkdtemp=tempfile.mkdtemp
        def scratch(**kwargs):
            if "dir" not in kwargs:kwargs["dir"]=base
            assert Path(kwargs["dir"]).is_relative_to(base)
            return mkdtemp(**kwargs)
        with patch.object(guard,"check",return_value=None), \
                patch("subprocess.Popen",side_effect=AssertionError("NO process in GitLocal DATA tests")), \
                patch.object(core.tempfile,"mkdtemp",side_effect=scratch):
            seed=local.GitLocalRepository(root,git_executable=wire.TOOL_PATH,work_end=source.work_end,_run=fake)
            observed=seed.observe();row=fixture(kind,phase=phase);row["action"]["expectedRevision"]=observed.revision
            selected=wire.action(row["action"])
            prepared=seed.prepare_local(kind,expected_revision=observed.revision,paths=selected.paths,
                                       message=selected.message,identity=selected.identity)
            if phase=="apply":row["reviewDigest"]=prepared.digest
            def snapshot(path):
                return fields.FileSnapshot(path,fields.identity(path.stat()),hashlib.sha256(path.read_bytes()).hexdigest())
            # Explicit DATA override: production parser correctly rejects
            # uid0/non-CLT provider. No actual source capability is created.
            request=replace(wire.parse_request(frame(row)),uid=os.getuid(),gid=os.getgid(),root=root,
                directories=tuple((p,fields.directory_identity(p.stat())) for p in (root,root/".git",root/".git/objects")),
                tool=snapshot(tool),files=tuple(snapshot(root/".git"/n) for n in ("HEAD","config","index")))
            engine.request=source.initial=request;source.request_returned=source.acquired=True
            guard._install_saved_command_source(source) # Type/binding check, no FD0/signals acquired.
            operation=engine.operation=GitLocalOperation(request,source,guard,engine)
            source.ready_sent=source.go_returned=source.active=True
            def ledger_return(argv,**options):
                ledger,record=guard.lifetime_ledger,object()
                ledger._bind_command(record) # FAKE C/A/W receipt, explicitly not native proof.
                result=fake(argv,**options)
                ledger._finish_command(record,dispatched=True,contained=True,cleanup_complete=True)
                return result
            try:
                with patch("mobile_release._command_process.run_command",side_effect=ledger_return) as calls:
                    yield operation,fake,calls
            finally:
                operation.cleanup();source.close()
                # Test teardown ONLY, for deliberately simulated unknowns.
                # No real producer exists and no result is reclassified.
                if operation.repository is not None:
                    holder=type("InertFixture",(),{"repositories":[operation.repository]})()
                    core_fixture.LocalFacetTests.release_fixture_descriptors(holder)


class ControlTests(unittest.TestCase):
    def test_exact_original_domain_not_subclass_or_read_alias(self):
        source=GitLocalInput(time.monotonic())
        self.assertIs(source_domain(source),SavedCommandDomain.GitLocal)
        class Lookalike(GitLocalInput):pass
        with self.assertRaises(ValueError):source_domain(Lookalike(time.monotonic()))
        source._domain=SavedCommandDomain.GitRead
        with self.assertRaises(ValueError):source_domain(source)

    def test_candidate_handshake_is_one_attempt_and_exact_ack(self):
        with synthetic_operation() as (op,_,__):
            op.admit();op.entered=True
            seed=local.GitLocalRepository(op.request.root,git_executable=wire.TOOL_PATH,work_end=op.source.work_end,_run=FakeGit(op.request.root))
            op.review=seed.prepare_local("stage",expected_revision=op.request.action.expected_revision,paths=op.request.action.paths)
            intent=core.PublicationIntent("stage",op.review.plan._snapshot.public.revision,"refs/heads/main",HEAD,
                op.review.plan._snapshot.index_stamp.digest,"3"*64,None)
            sent=wire.candidate(op.request,op.review,intent)
            ack=b"MRK-GIT-LOCAL-ACK/1 "+op.request.digest.encode()+b" "+sent.digest.encode()+b" 5\n"
            with patch.object(op,"write_candidate") as write,patch.object(op.source,"_frame",return_value=ack):
                op.source.handoff(sent)
                self.assertTrue(op.source.candidate_returned)
                self.assertEqual(op.source.ack_revision,5)
                with self.assertRaises(wire.ProtocolError):op.source.handoff(sent)
                write.assert_called_once_with(sent)

    def test_lost_ack_claim_stays_latched_no_publication_or_retry(self):
        with synthetic_operation() as (op,_,__):
            op.admit()
            lost=KeyboardInterrupt("synthetic missing ACK")
            with patch.object(op.engine,"write") as write,patch.object(op.source,"_frame",side_effect=lost):
                with self.assertRaises(KeyboardInterrupt) as error:op.run()
                self.assertIs(error.exception,lost)
            self.assertTrue(op.source.candidate_claimed)
            self.assertFalse(op.source.candidate_returned)
            self.assertEqual((op.request.root/".git/index").read_bytes(),OLD_INDEX)
            self.assertIsNone(op.repository._transaction.index_publication)
            self.assertEqual(write.call_count,1)
            with self.assertRaises(wire.ProtocolError):op.source.handoff(op.source.candidate)

    def test_first_failure_latched_before_clock_return_and_never_renews(self):
        source=GitLocalInput(50);source.initial=wire.parse_request(frame(fixture()))
        with patch.object(time,"CLOCK_UPTIME_RAW",1,create=True),patch.object(time,"clock_gettime_ns",return_value=90_000_000_000) as clock, \
                patch.object(time,"monotonic",side_effect=[80.,80.001]):
            source.failure_observed();source.failure_observed()
            self.assertEqual(source.first_failure,80.)
            self.assertEqual(source.hard_end,90.)
            self.assertLessEqual(source.first_failure_ns,89_999_000_001);clock.assert_called_once()
        source=GitLocalInput(50);lost=KeyboardInterrupt()
        with patch.object(time,"CLOCK_UPTIME_RAW",1,create=True),patch.object(time,"clock_gettime_ns",side_effect=lost) as clock:
            with self.assertRaises(KeyboardInterrupt) as error:source.failure_observed()
            self.assertIs(error.exception,lost);source.failure_observed();clock.assert_called_once()


class OperationTests(unittest.TestCase):
    @staticmethod
    def ack(source):
        return b"MRK-GIT-LOCAL-ACK/1 "+source.initial.digest.encode()+b" "+source.candidate.digest.encode()+b" 5\n"

    def test_stage_positive_receipt_retains_old_index_fd_until_sole_close(self):
        with synthetic_operation() as (op,_,calls):
            op.admit();old=op.index_original;fd=old.fd
            with patch.object(op.engine,"write") as write,patch.object(op.source,"_frame",side_effect=lambda _:self.ack(op.source)):
                op.run()
            self.assertTrue(op.returned and op.source.candidate_returned)
            self.assertEqual(op.result.state,"succeeded");self.assertEqual(write.call_count,1)
            self.assertIs(op.index_original,old);self.assertEqual(old.fd,fd)
            self.assertEqual(os.fstat(fd).st_nlink,0)
            self.assertIsNotNone(op.index_successor)
            self.assertNotEqual(os.fstat(fd).st_ino,os.fstat(op.index_successor.fd).st_ino)
            self.assertEqual((op.request.root/".git/index").read_bytes(),CANDIDATE_INDEX)
            self.assertEqual(op.publication(),"index-returned")
            self.assertEqual(calls.call_count,op.calls)
            op.cleanup();self.assertTrue(old.closed and op.index_successor.closed)
            with self.assertRaises(OSError):os.fstat(fd)

    def test_prepare_result_has_actual_full_index_review_without_candidate_frame(self):
        with synthetic_operation("commit",phase="prepare") as (op,_,__):
            op.admit()
            with patch.object(op.engine,"write") as write:op.run()
            self.assertTrue(op.returned);self.assertEqual(op.review.plan.paths,("a.txt","b.txt"))
            self.assertTrue(op.diff.staged);write.assert_not_called()
            self.assertIsNone(op.result);self.assertFalse(op.source.candidate_claimed)

    def test_original_runner_rejects_unbound_or_foreign_command_before_fake_caw(self):
        with synthetic_operation() as (op,_,calls):
            op.admit();op.entered=True
            with self.assertRaises(wire.ProtocolError):
                run_owned(["/bin/sh","-c","false"],cwd=op.request.root,environ={},timeout=1,capture=True,text=False,
                          output_limit=1024,cancellation=op.guard)
            calls.assert_not_called()

    def test_unpublished_fake_process_receipt_cannot_claim_success(self):
        with synthetic_operation(phase="prepare") as (op,fake,__):
            op.admit()
            with patch("mobile_release._command_process.run_command",side_effect=fake) as calls:
                with self.assertRaises(wire.ProtocolError):op.run()
                self.assertEqual(calls.call_count,1)
            self.assertFalse(op.returned)

    def test_foreign_index_replacement_without_actual_publication_receipt_refuses(self):
        with synthetic_operation() as (op,_,__):
            op.admit();old=op.index_original;replacement=op.request.root/".git/foreign-index"
            replacement.write_bytes(CANDIDATE_INDEX);os.replace(replacement,old.path)
            with self.assertRaises(fields.ProtocolError):op.source_post(hash_files=True)
            self.assertIsNone(op.index_successor);self.assertFalse(old.closed)
            self.assertEqual(old.fd,op.index_original.fd)
