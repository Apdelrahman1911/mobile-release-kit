"""Same worker/channel/core fixture, explicitly fake C/A/W and durable ACK.

Real private source/transaction files and engine phase methods are exercised.
No native issuer/join, Git child, HTTP, credential or provider is constructed.
"""
import os
import unittest

from mobile_release import git_push_new_branch as first
from mobile_release import git_repository_push_new_branch as repository
from mobile_release import _git_push_private_protocol as private
from mobile_release import _desktop_git_push_protocol as protocol
from mobile_release import git_service as core
from mobile_release.owned_process import ProcessCleanupError
import test_desktop_git_push as worker
import test_git_repository_push_new_branch as fixture


class FirstPublicationWorkerTests(unittest.TestCase):
    def test_original_review_engine_uses_full_history_and_closed_hook_without_candidate(self):
        with worker.original(phase="prepare", first_publication=True) as (op, _, __, seen, remote, sends):
            op.admit()
            op.run()
            self.assertIs(type(op.repository), repository.GitPushNewBranchRepository)
            self.assertEqual(op.review.plan.action, first.KIND)
            self.assertEqual(op.review.plan.commits, (fixture.ANCESTOR, fixture.HEAD))
            self.assertTrue(op.core_returned and op.returned and op.source.channel.closed)
            self.assertEqual((len(remote), sends, op.calls), (1, [], len(seen)))
            self.assertIn("--dry-run", remote[0])
            self.assertFalse(op.source.candidate_claimed)
            self.assertIsNone(op.repository._transaction.intent)
            self.assertIsNone(op.repository._transaction.view.body_initial)
            challenge = private._decode(op.source.channel.binding.challenge())
            self.assertEqual(challenge["target"]["kind"], first.KIND)
            self.assertIsNone(challenge["remote"])

    def test_original_apply_engine_keeps_zero_old_candidate_send_return_and_every_source(self):
        with worker.original(first_publication=True) as (op, world, __, seen, remote, sends):
            names = (".git/HEAD", ".git/config", ".git/index", ".git/refs/heads/main", "a.txt", "b.txt")
            before = {name: (world.root / name).read_bytes() for name in names}
            op.admit()
            fds = tuple(row.fd for row in op.originals)
            op.run()
            self.assertEqual((op.result.action, op.result.state, op.result.settlement),
                             (first.KIND, "succeeded", "settled"))
            self.assertIs(type(op.result.intent), repository.PushNewBranchIntent)
            self.assertEqual(op.result.intent.old_oid, first.ZERO)
            self.assertIsNone(op.result.intent.remote)
            self.assertEqual((len(remote), len(sends), op.calls), (1, 1, len(seen)))
            channel = op.source.channel
            self.assertTrue(channel.return_checked and channel.eof and channel.closed and op.returned)
            self.assertEqual((channel.client.calls, channel.peer.calls), (1, 1))
            self.assertIs(op.transmission(), op.repository._transaction.receipt)
            for name, content in before.items():
                self.assertEqual((world.root / name).read_bytes(), content)
            op.cleanup()
            self.assertTrue(op.closed)
            for fd in fds:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_lost_create_candidate_ack_or_stop_keeps_original_and_never_sends(self):
        for stopped in (False, True):
            with self.subTest(stopped=stopped), worker.original(first_publication=True) as (op, _, mode, __, remote, sends):
                mode.ack_stop = stopped
                if not stopped:
                    mode.ack_error = OSError("inert lost first-publication ACK")
                op.admit()
                try:
                    op.run()
                except BaseException as error:
                    self.assertIsInstance(error, (OSError, KeyboardInterrupt, ProcessCleanupError,
                                                  core.GitError, protocol.ProtocolError, ValueError))
                self.assertTrue(op.source.candidate_claimed)
                self.assertFalse(op.source.candidate_returned)
                self.assertEqual((len(remote), sends), (1, []))
                self.assertEqual(op.repository._transaction.intent.action, first.KIND)
                self.assertFalse(op.repository._transaction.send_entered)
                with self.assertRaises(Exception):
                    op.source.handoff(op.source.candidate)


if __name__ == "__main__":
    unittest.main()
