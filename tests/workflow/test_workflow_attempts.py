"""Mixed-attempt promotion through real resolution, packaging and parsers.

GitHub responses, Store readbacks and clocks are synthetic. Attempt-2 finals
must pass the real resume or proven pre-mutation prepare path first. API job
windows and witness/service timestamps are independently fixed, not inferred
from the producer claim being checked. No fixture can perform a Store mutation.
"""
from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from itertools import product
from pathlib import Path
from unittest.mock import patch

from mobile_release import workflow
from mobile_release.errors import ValidationError
from mobile_release.provenance import seal, sha256_file, validate_evidence_document, verify_sealed

from . import test_workflow_recovery as fixture


PLATFORMS = ("android", "ios")
STAGES = ("candidate", "external-testing")
EPOCH = datetime(2026, 1, 2, tzinfo=timezone.utc)


@contextmanager
def producer_clock(stage: str, attempt: int):
    instant = EPOCH + timedelta(hours=10 * STAGES.index(stage) + attempt)

    def timestamp(delta=0):
        return (instant + timedelta(seconds=delta)).isoformat().replace("+00:00", "Z")

    with patch.object(fixture, "utc", timestamp), patch.object(workflow, "_now", timestamp):
        yield


class WorkflowAttemptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-attempts-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.api = fixture.FakeGitHub()

    def lifecycle(self, platform: str, root: Path | None = None):
        root = (root or self.root) / platform
        root.mkdir(parents=True)
        return fixture.Lifecycle(root, self.api, platform)

    def resolve(self, selected, destination, **options):
        return workflow.Resolver(selected, self.api.client(selected)).resolve(destination, **options)

    def finish_on_attempt(self, lifecycle, stage: str, attempt: int):
        self.assertIn(attempt, (1, 2))
        # A same-run iOS retry cannot attribute an earlier ambiguous upload.
        # Instead exercise the real, positive proof of no prior execution that
        # permits original preparation after a failed pre-authorization gate.
        later_preparation = stage == "candidate" and lifecycle.platform == "ios" and attempt == 2
        authorized_attempt = 2 if later_preparation else 1
        if later_preparation:
            with producer_clock(stage, 1):
                earlier = fixture.context(stage, lifecycle.platform)
                build = self.api.register(earlier, key="ios_build", conclusion="success")
                build.update(started_at=fixture.utc(-600), completed_at=fixture.utc(-60))
                old_store = self.api.register(earlier, conclusion="failure")
                old_store.update(started_at=fixture.utc(-30), completed_at=fixture.utc(300))
                old_store["steps"] = [
                    {"name": "Prepare immutable Store operation without mutation", "number": 1, "status": "completed", "conclusion": "failure"},
                    {"name": "Execute or reconcile the exact authorized Store operation", "number": 2, "status": "completed", "conclusion": "skipped"},
                ]
                handoff = self.api.upload(earlier, lifecycle.handoff, "handoff")
                handoff["created_at"] = fixture.utc(-120)
            with producer_clock(stage, 2):
                current = fixture.context(stage, lifecycle.platform, attempt=2)
                self.api.register(current, active=True)
                destination = lifecycle.root / "candidate-proven-unexecuted"
                result = self.resolve(current, destination, handoff_digest=handoff["digest"][7:])
                self.assertEqual(result["mode"], "prepare")
                for file in lifecycle.handoff.iterdir():
                    self.assertEqual((destination / "artifacts/ios" / file.name).read_bytes(), file.read_bytes())
        with producer_clock(stage, authorized_attempt):
            original, app, intent = lifecycle.prepare(stage, attempt=authorized_attempt)
            if stage == "candidate" and not later_preparation:
                self.api.upload(original, lifecycle.handoff, "handoff")
            if attempt == authorized_attempt:
                package = lifecycle.finish(stage, original, app, intent)
            else:
                self.api.register(original, conclusion="cancelled")
        if attempt != authorized_attempt:
            with producer_clock(stage, 2):
                current = fixture.context(stage, lifecycle.platform, attempt=2)
                self.api.register(current, active=True)
                destination = lifecycle.root / (stage + "-resumed")
                result = self.resolve(current, destination)
                self.assertEqual(result["mode"], "resume")
                self.assertEqual(result["source"], intent["operationSource"])
                recovered_app = lifecycle.root / (stage + "-recovered-app")
                shutil.copytree(destination / "operation", recovered_app / ".mobile-release/operation")
                self.assertEqual(
                    (destination / "operation" / f"{stage}-operation-intent.json").read_bytes(),
                    (app / ".mobile-release/operation" / f"{stage}-operation-intent.json").read_bytes(),
                )
                package = lifecycle.finish(stage, current, recovered_app, intent, executor=dict(current.authority), result="reconciled")
        proof = json.loads((package / "workflow-provenance.json").read_bytes())
        original_proof = json.loads((package / "operation/intent-provenance.json").read_bytes())
        receipt = json.loads((package / f"{stage}-receipt.json").read_bytes())
        self.assertEqual(original_proof["producer"]["attempt"], authorized_attempt)
        self.assertEqual(proof["producer"]["attempt"], attempt)
        self.assertEqual(receipt["authorizedBy"]["attempt"], authorized_attempt)
        self.assertEqual(receipt["executedBy"]["attempt"], attempt)
        self.assertEqual(receipt["producedBy"]["attempt"], attempt)
        jobs = self.api.jobs[(original.authority["runId"], attempt)]
        expected_job = next(job for job in jobs if job["name"].endswith(" / " + workflow.job_key(stage, lifecycle.platform)))
        self.assertEqual(proof["jobId"], str(expected_job["id"]))
        return package

    def add_later_successful_attempt(self, stage: str, platform: str):
        with producer_clock(stage, 3):
            latest = fixture.context(stage, platform, attempt=3)
            self.api.register(latest, conclusion="success")
        return latest

    def assert_read_only(self):
        self.assertTrue(self.api.requests)
        for command in self.api.requests:
            if command[:2] == ["gh", "api"]:
                self.assertEqual(command[command.index("--method") + 1], "GET")
                self.assertNotRegex(command[-1], r"actions/runs/[0-9]+$")
            else:
                self.assertEqual(command[:3], ["gh", "attestation", "verify"])

    def test_all_sixteen_mixed_candidate_external_producer_attempt_combinations(self):
        for combination in product((1, 2), repeat=4):
            with self.subTest(candidate_android=combination[0], candidate_ios=combination[1], external_android=combination[2], external_ios=combination[3]):
                self.api = fixture.FakeGitHub()
                root = self.root / "".join(map(str, combination))
                lifecycles = {platform: self.lifecycle(platform, root) for platform in PLATFORMS}
                for stage_index, stage in enumerate(STAGES):
                    for index, platform in enumerate(PLATFORMS):
                        lifecycle = lifecycles[platform]
                        if stage == "external-testing":
                            # Authenticate the candidate before preparing external
                            # authority. Same run IDs do not imply same attempts.
                            selected = fixture.context(stage, platform, selected_platform="both", confirmation="external-testing:both:1.2.3:42")
                            with producer_clock(stage, 1):
                                self.api.register(selected, active=True)
                                prepared = self.resolve(selected, root / (platform + "-external-input"), candidate_run_id="1000000000")
                            self.assertEqual(prepared["mode"], "prepare")
                        self.finish_on_attempt(lifecycle, stage, combination[2 * stage_index + index])
                    for attempt in (1, 2):
                        # A sibling/post-upload failure must not erase complete
                        # authenticated evidence. Keep the latest run successful.
                        pair = str(1000000000 + stage_index), attempt
                        if pair in self.api.attempts:
                            self.api.attempts[pair]["conclusion"] = "failure" if attempt == 1 else "cancelled"
                    for platform in PLATFORMS:
                        self.add_later_successful_attempt(stage, platform)

                original_artifacts = copy.deepcopy(self.api.artifacts)
                original_zips = dict(self.api.zips)
                self.api.requests.clear()
                for index, platform in enumerate(PLATFORMS):
                    lifecycle = lifecycles[platform]
                    current = fixture.context("production-submit", platform, run_id="2000000000")
                    self.api.register(current)
                    destination = root / (platform + "-production")
                    result = self.resolve(current, destination, candidate_run_id="1000000000", external_run_id="1000000001")
                    self.assertEqual(result["mode"], "prepare")
                    for stage_index, stage in enumerate(STAGES):
                        source = lifecycle.packages[stage]
                        staged = destination / "input" / ("candidate" if stage == "candidate" else "external")
                        for file in source.rglob("*"):
                            if file.is_file():
                                self.assertEqual((staged / file.relative_to(source)).read_bytes(), file.read_bytes())
                        expected_attempt = combination[2 * stage_index + index]
                        proof = json.loads((staged / "workflow-provenance.json").read_bytes())
                        self.assertEqual(proof["producer"]["attempt"], expected_attempt)
                        run_id = str(1000000000 + stage_index)
                        original_final = next(item for item in self.api.artifacts[run_id] if item["name"] == workflow.artifact_name(stage, platform, "evidence"))
                        reused = self.resolve(fixture.context(stage, platform, attempt=3), root / (platform + stage + "-reused"))
                        self.assertEqual(reused["mode"], "complete")
                        self.assertEqual(reused["evidenceRunId"], run_id)
                        self.assertEqual(reused["evidenceArtifactId"], str(original_final["id"]))
                        self.assertEqual(reused["files"], [])
                        requests = [command[-1] for command in self.api.requests if command[:2] == ["gh", "api"]]
                        authorized_attempt = json.loads((staged / "operation/intent-provenance.json").read_bytes())["producer"]["attempt"]
                        for required_attempt in {authorized_attempt, expected_attempt}:
                            self.assertIn(f"repos/example/mobile-app/actions/runs/{run_id}/attempts/{required_attempt}/jobs?per_page=100&page=1", requests)
                self.assertEqual(self.api.artifacts, original_artifacts)
                self.assertEqual(self.api.zips, original_zips)
                self.assert_read_only()

    def test_one_claim_substitution_cannot_use_a_successful_latest_job_as_authority(self):
        cases = ("certificate-attempt", "predicate-attempt", "job-id", "job-attempt", "old-job-missing", "artifact-run", "artifact-source", "artifact-latest-interval")
        for stage, platform, variant in product(STAGES, PLATFORMS, cases):
            with self.subTest(stage=stage, platform=platform, variant=variant):
                self.api = fixture.FakeGitHub()
                root = self.root / f"{stage}-{platform}-{variant}"
                lifecycle = self.lifecycle(platform, root)
                candidate = self.finish_on_attempt(lifecycle, "candidate", 1)
                target = candidate if stage == "candidate" else self.finish_on_attempt(lifecycle, stage, 1)
                selected = self.add_later_successful_attempt(stage, platform)
                self.assertEqual(self.resolve(selected, root / "valid-baseline")["mode"], "complete")
                run_id = selected.authority["runId"]
                job = self.api.jobs[(run_id, 1)][0]
                artifact = next(item for item in self.api.artifacts[run_id] if item["name"] == workflow.artifact_name(stage, platform, "evidence"))
                signature = self.api.signatures[sha256_file(target / "workflow-provenance.json")][0]["verificationResult"]
                expected_error = "attestation" if variant.endswith("attempt") and variant != "job-attempt" else "job" if variant in {"job-id", "job-attempt", "old-job-missing"} else "artifact"
                if variant == "certificate-attempt":
                    signature["signature"]["certificate"]["runInvocationURI"] = f"https://github.com/example/mobile-app/actions/runs/{run_id}/attempts/3"
                elif variant == "predicate-attempt":
                    signature["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = f"https://github.com/example/mobile-app/actions/runs/{run_id}/attempts/3"
                elif variant == "job-id":
                    job["id"] = self.api.jobs[(run_id, 3)][0]["id"]
                elif variant == "job-attempt":
                    job["run_attempt"] = 3
                elif variant == "old-job-missing":
                    self.api.jobs[(run_id, 1)] = []
                elif variant == "artifact-run":
                    artifact["workflow_run"]["id"] += 1
                elif variant == "artifact-source":
                    artifact["workflow_run"]["head_sha"] = "4" * 40
                else:
                    # ZIP/hash unchanged: only service creation time is moved
                    # into the independently registered latest job's interval.
                    artifact["created_at"] = self.api.jobs[(run_id, 3)][0]["started_at"]
                rejected = root / "must-not-authorize"
                with self.assertRaisesRegex(workflow.WorkflowError, expected_error):
                    self.resolve(selected, rejected)
                self.assertFalse((rejected / "resolution.json").exists())
                self.assert_read_only()

    def test_later_same_run_ios_upload_cannot_claim_recovery_without_authority(self):
        lifecycle = self.lifecycle("ios")
        package = self.finish_on_attempt(lifecycle, "candidate", 1)
        receipt = json.loads((package / "candidate-receipt.json").read_bytes())
        validate_evidence_document(receipt)
        for outcome in ("mutated", "reconciled", "operator-authorized-reconciliation", "operator-authorized-retry"):
            with self.subTest(outcome=outcome):
                forged = verify_sealed(receipt)
                forged["executedBy"] = dict(fixture.context("candidate", "ios", attempt=2).authority)
                forged["producedBy"] = dict(forged["executedBy"])
                forged["outcome"] = outcome
                with self.assertRaisesRegex(ValidationError, "(later iOS candidate|different protected iOS dispatch)"):
                    validate_evidence_document(seal(forged))


if __name__ == "__main__":
    unittest.main()
