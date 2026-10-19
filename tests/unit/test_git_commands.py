"""Only closed adapter policy; no repository, native process or credentials."""
from __future__ import annotations

import unittest
from unittest.mock import Mock

from mobile_release.git_commands import GitCommands
from mobile_release.git_service import GitError


class GitCommandTests(unittest.TestCase):
    def setUp(self):
        self.repository = Mock()
        self.adapter = GitCommands(self.repository)

    def test_arbitrary_command_paths_options_and_credentials_are_not_a_route(self):
        for name, params in (("exec", {"argv": ["git", "push"]}), ("git_push", {}),
            ("git_observe", {"root": "/caller/path"}), ("git_diff", {"paths": [], "token": "INERT"}),
            ("git_stage_prepare", {"paths": ["a"], "expectedRevision": "0" * 64, "force": True})):
            with self.assertRaises(GitError) as failure:
                self.adapter.invoke(name, params)
            self.assertEqual(failure.exception.reason, "invalid-input")
        self.assertEqual(self.repository.mock_calls, [])

    def test_public_prepare_assertions_cannot_reconstruct_private_apply_plan(self):
        for params in ({"planId": "git-plan-" + "0" * 32}, {"planId": "missing", "paths": ["a"]},
                       {"planId": "missing", "expectedRevision": "0" * 64}):
            with self.assertRaises(GitError):
                self.adapter.invoke("git_stage_apply", params, owner=Mock())
        self.assertEqual(self.repository.mock_calls, [])

    def test_apply_requires_actual_owner_and_matching_action(self):
        plan = Mock(action="stage", _used=False)
        plan.as_dict.return_value = {"action": "stage", "expectedRevision": "0" * 64, "paths": ["a"]}
        public = self.adapter._retain(plan)
        with self.assertRaises(GitError) as failure:
            self.adapter.invoke("git_stage_apply", {"planId": public["planId"]})
        self.assertEqual(failure.exception.reason, "authorization")
        with self.assertRaises(GitError):
            self.adapter.invoke("git_commit_apply", {"planId": public["planId"]}, owner=Mock())
        self.assertEqual(self.repository.mock_calls, [])

    def test_discard_does_not_apply_or_touch_git(self):
        plan = Mock(action="stage", _used=False)
        plan.as_dict.return_value = {"action": "stage"}
        public = self.adapter._retain(plan)
        self.assertEqual(self.adapter.invoke("git_plan_discard", {"planId": public["planId"]}), {"discarded": True})
        self.assertEqual(self.repository.mock_calls, [])
