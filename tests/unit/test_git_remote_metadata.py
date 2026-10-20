"""New metadata-only helper cases; entirely fake IO/HTTP, no native entry."""
from dataclasses import replace
import unittest

from mobile_release import git_remote_transport as transport
from mobile_release.git_remote_wire import Selection
import test_git_remote_helper as helper_fixture
from test_git_remote_transport import FakeExchange, TARGET, ACCOUNT, REPOSITORY, LS_REQUEST, LS_RESPONSE
from test_git_remote_wire import OID, REF, offered, fetch


class MetadataTests(unittest.TestCase):
    def helper(self, *, bodies=None, extra=b""):
        original = FakeExchange(target=replace(TARGET, selected=Selection(REF, None)),
            bodies=bodies or [ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE, ACCOUNT, REPOSITORY])
        return helper_fixture.GitRemoteHelperTests.helper(self, helper_fixture.PREFIX + LS_REQUEST + extra, original)

    def test_metadata_posts_identity_before_only_response_end_and_no_fetch_body(self):
        body, original, out, events = self.helper()
        self.assertEqual(body.run().oid, OID)
        self.assertEqual(len(original.calls), 6)
        self.assertEqual([event[2] for event in events if event[:2] == ("write", b"0002")], [6])
        self.assertNotIn(transport.FETCH, [call[3] for call in original.calls])
        self.assertTrue(body.finished)
        with self.assertRaises(transport.RemoteError):
            body.run()
        self.assertEqual(len(original.calls), 6)

    def test_metadata_changed_account_never_emits_a_finished_metadata_response(self):
        body, original, out, _ = self.helper(bodies=[ACCOUNT, REPOSITORY, offered().raw, LS_RESPONSE,
                                                   {**ACCOUNT, "id": 12}, REPOSITORY])
        with self.assertRaises(transport.RemoteError):
            body.run()
        self.assertNotIn(b"0002", out)
        self.assertEqual(len(original.calls), 5)

    def test_metadata_cannot_be_upgraded_to_fetch_by_a_later_git_request(self):
        body, original, out, _ = self.helper(extra=fetch())
        with self.assertRaises(transport.RemoteError):
            body.run()
        self.assertEqual(len(original.calls), 6)
        self.assertFalse(body.finished)
        self.assertNotIn(transport.FETCH, [call[3] for call in original.calls])


if __name__ == "__main__":
    unittest.main()
