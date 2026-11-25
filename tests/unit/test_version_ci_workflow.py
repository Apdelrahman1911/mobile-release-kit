"""Fixed workflow integration DATA; no Git/gh child, network or Store.

The real consumer, ledger, GitHub JSON adapter and command dispatcher run.
Only original process boundaries and unrelated old seal fixtures are inert.
"""
from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from mobile_release import version_ci as ci
from mobile_release import workflow
from test_version_ci import Fixture


class WorkflowCI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mrk-ci-workflow-data-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_actual_gh_json_adapter_forwards_every_fixed_limit_and_ignores_cached_trees(self):
        f = Fixture(self.root)
        calls = []

        class Transport:
            def run(self, args, **kwargs):
                calls.append((args, kwargs))
                self.assertion = args[:6] == ["gh", "api", "--hostname", "github.com", "--method", "GET"]
                assert self.assertion
                value = f.json(SimpleNamespace(cancellation=kwargs["cancellation"]), args[-1],
                               maximum=kwargs["maximum"], timeout=kwargs["timeout"])
                return json.dumps(value).encode()

        github = workflow.GitHub(f.context, Transport())
        github._trees.update({f.before_commit: "0" * 40, f.final: "0" * 40})
        github._comparisons[(f.anchor.commit, f.ledger_commit)] = {"status": "behind"}
        with patch.dict(os.environ, {ci.AUTHORITY_ENV: f.settings}), patch.object(ci, "run_owned", f.git), \
             patch.object(ci.time, "monotonic", lambda: f.clock):
            checked = workflow.verify_version_reservation(self.root, f.context, github)
        self.assertEqual(checked.candidate_id, f.request.candidate_id)
        self.assertEqual(len(calls), 8)
        self.assertTrue(all(k["maximum"] == ci.HTTP_LIMIT and k["timeout"] == 10 for _, k in calls))
        self.assertEqual(len({id(k["cancellation"]) for _, k in calls}), 1)
        self.assertEqual(github._trees[f.final], "0" * 40)  # No cached replacement/substitution.

    def test_default_json_calls_keep_old_limits_and_invalid_new_bounds_never_reach_transport(self):
        f = Fixture(self.root)
        transport = Mock(spec=workflow.Transport)
        transport.run.return_value = b'{"ok":true}'
        github = workflow.GitHub(f.context, transport)
        endpoint = "repos/" + f.context.repository["fullName"]
        self.assertEqual(github.json(endpoint + "/git/commits/" + f.final), {"ok": True})
        self.assertNotIn("maximum", transport.run.call_args.kwargs)
        self.assertNotIn("timeout", transport.run.call_args.kwargs)
        for kwargs in ({"maximum": 0}, {"maximum": True}, {"maximum": workflow.MAX_JSON + 1},
                       {"timeout": 0}, {"timeout": 121}, {"timeout": True}):
            with self.assertRaises(workflow.WorkflowError):
                github.json(endpoint, **kwargs)
        with self.assertRaises(workflow.WorkflowError):
            github.json("repos/other/application", maximum=1, timeout=1)
        self.assertEqual(transport.run.call_count, 1)

    def test_fixed_command_reports_unconfigured_or_existing_only_and_failure_cannot_choose_manual(self):
        f = Fixture(self.root)
        args = ["verify-version-reservation", "--stage", "candidate", "--platform", "android",
                "--app-root", str(self.root)]
        checked = ci.Checked(f.request.candidate_id, f.row.sha256, f.final, f.after_tree, "1.2.3", 8)
        for result, message in ((None, "unconfigured"), (checked, "no number was allocated")):
            output = io.StringIO()
            with patch.object(workflow.Context, "current", return_value=f.context), \
                 patch.object(ci, "verify_reserved_source", return_value=result) as call, \
                 patch.object(workflow.Resolver, "resolve", side_effect=AssertionError("not resolution")), \
                 redirect_stdout(output):
                self.assertEqual(workflow.main(args), 0)
                self.assertIs(call.call_args.args[1], f.context)
            self.assertIn(message, output.getvalue())
        output, error = io.StringIO(), io.StringIO()
        with patch.object(workflow.Context, "current", return_value=f.context), \
             patch.object(ci, "verify_reserved_source", side_effect=ci.Refused("authority")), \
             redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(workflow.main(args), 2)
        self.assertFalse(output.getvalue())
        self.assertIn("does not create, reset or allocate", error.getvalue())

    def test_fresh_seal_checks_exact_operation_source_before_proof_and_promotion_does_not_use_gate(self):
        # Only tests placement/association inside the existing seal. These old
        # namespace/artifact owners are not native or filesystem proof here.
        f = Fixture(self.root)
        checked = ci.Checked(f.request.candidate_id, f.row.sha256, f.final, f.after_tree, "1.2.3", 8)
        source = {"commit": f.final, "tree": f.after_tree, "ref": f.context.authority["ref"]}
        owner = SimpleNamespace(path=self.root / ".mobile-release", cancellation=object(), check=lambda: None)

        @contextmanager
        def namespace(*args, **kwargs):
            yield owner

        intent = {"authorizedBy": f.context.authority, "repository": f.context.repository,
                  "stage": "candidate", "platform": f.context.platform,
                  "candidateSource": source.copy(), "operationSource": source.copy()}
        client = Mock()
        client.with_cancellation.return_value = client
        client.tree.return_value = f.after_tree
        replacements = {"app_private_namespace": namespace, "_app_private_directory": namespace,
                        "_validate_handoff": lambda *a: None, "_metadata_binding": lambda *a: None,
                        "copy_immutable_file": lambda *a, **k: None, "_copy_tree": lambda *a, **k: None}
        from contextlib import ExitStack
        with ExitStack() as stack:
            for name, value in replacements.items():
                stack.enter_context(patch.object(workflow, name, value))
            stack.enter_context(patch.object(workflow, "load_operation_intent", return_value=intent))
            stack.enter_context(patch.object(workflow, "Verifier"))
            proof = stack.enter_context(patch.object(workflow, "_create_proof"))
            gate = stack.enter_context(patch.object(workflow, "verify_version_reservation", return_value=checked))
            workflow.seal_intent(self.root, f.context, client)
            self.assertIs(gate.call_args.kwargs["cancellation"], owner.cancellation)
            self.assertEqual(proof.call_count, 1)
            intent["operationSource"] = dict(source, ref="refs/heads/elsewhere")
            with self.assertRaises(workflow.WorkflowError):
                workflow.seal_intent(self.root, f.context, client)
            self.assertEqual(proof.call_count, 1)
            intent["operationSource"] = source.copy()
            gate.side_effect = workflow.WorkflowError("fixed gate refusal")
            with self.assertRaises(workflow.WorkflowError):
                workflow.seal_intent(self.root, f.context, client)
            self.assertEqual(proof.call_count, 1)
            count = gate.call_count
            intent["stage"] = "external-testing"
            workflow.seal_intent(self.root, replace(f.context, stage="external-testing"), client)
            self.assertEqual(gate.call_count, count)
            self.assertEqual(proof.call_count, 2)

    def test_only_failed_fresh_gate_and_explicit_skipped_execution_permit_original_resolution(self):
        f = Fixture(self.root)
        context = replace(f.context, authority=dict(f.context.authority, attempt=2))
        failed = {"number": 6, "name": "Verify the existing version reservation before new work",
                  "status": "completed", "conclusion": "failure"}
        skipped = {"number": 12, "name": "Execute or reconcile the exact authorized Store operation",
                   "status": "completed", "conclusion": "skipped"}
        client = workflow.GitHub(context)
        client.job = Mock()  # Exact upstream job DATA only; no gh process.
        resolver = workflow.Resolver(context, client)
        client.job.return_value = {"status": "completed", "conclusion": "failure", "steps": [failed, skipped]}
        resolver._prove_no_prior_execution()
        for gate, execution in ((dict(failed, conclusion="skipped"), skipped),
                                (dict(failed, name="Unrelated application failure"), skipped),
                                (dict(failed, number=13), skipped),
                                (failed, dict(skipped, conclusion="success")),
                                (failed, dict(skipped, conclusion="cancelled"))):
            client.job.return_value = {"status": "completed", "conclusion": "failure", "steps": [gate, execution]}
            with self.assertRaises(workflow.WorkflowError):
                resolver._prove_no_prior_execution()


if __name__ == "__main__":
    unittest.main()
