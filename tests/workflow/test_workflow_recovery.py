"""Execute recovery policy at the GitHub/gh transport boundary, never at a Store.

The fake returns GitHub REST and ``gh attestation verify --format json`` shapes,
not pre-approved booleans. Production parsers, layout checks, evidence builders,
receipt normalization, predecessor validation, and resolver decisions all run.
The certificate JSON shape was checked against a cryptographically verified
public cli/cli reusable-workflow test bundle with gh 2.88.1 and its default TUF
trust. Predicate layout was compared with @actions/attest 3.2.0 from the pinned
action's lockfile. Production does NOT accept this synthetic signature authority.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import load_config
from mobile_release.errors import ValidationError
from mobile_release.provenance import (
    build_receipt,
    canonical_json_bytes,
    seal,
    sha256_file,
    validate_evidence_document,
    verify_sealed,
)
from mobile_release.workflow import (
    Context,
    GitHub,
    MAX_EVIDENCE,
    Resolver,
    Transport,
    Verifier,
    WorkflowError,
    _extract_zip,
    _files,
    _inventory,
    _layout,
    _metadata_binding,
    _outputs,
    _verify_checkout,
    artifact_name,
    authenticate_operation_intent,
    job_key,
    main,
    package_final,
    seal_intent,
    stage_resolution,
)
from unit.evidence_helpers import build_lifecycle, raw_receipt, workflow_environment
from unit.helpers import android_config, ios_config, write_project


def json_file(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def utc(delta: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def context(stage: str = "candidate", platform: str = "android", *, run_id: str | None = None, attempt: int = 1, head: str = "2" * 40, key: str | None = None, confirmation: str | None = None, selected_platform: str | None = None) -> Context:
    env = workflow_environment(stage, run_id=run_id, attempt=attempt, head=head)
    env["GITHUB_JOB"] = key or job_key(stage, platform)
    env["MOBILE_RELEASE_CONFIRMATION"] = confirmation if confirmation is not None else f"{stage}:{platform}:1.2.3:42"
    env["MOBILE_RELEASE_SELECTED_PLATFORM"] = selected_platform if selected_platform is not None else platform
    with patch.dict(os.environ, env, clear=True):
        return Context.current(stage, platform)


class FakeGitHub(Transport):
    """Independent API records and accepted verifier outputs, with request log."""

    def __init__(self):
        self.attempts: dict[tuple[str, int], dict] = {}
        self.jobs: dict[tuple[str, int], list[dict]] = {}
        self.artifacts: dict[str, list[dict]] = {}
        self.zips: dict[int, bytes] = {}
        self.signatures: dict[str, list[dict]] = {}
        self.trees = {"2" * 40: "3" * 40, "4" * 40: "5" * 40}
        self.comparisons: dict[tuple[str, str], dict | None] = {}
        self.requests: list[list[str]] = []
        self.fail: str | None = None
        self.next_id = 10000

    def client(self, selected: Context) -> GitHub:
        return GitHub(selected, self)

    def register(self, selected: Context, *, active: bool = False, conclusion: str = "failure", key: str | None = None) -> dict:
        authority = selected.authority
        pair = authority["runId"], authority["attempt"]
        repo = {"id": int(selected.repository["id"]), "full_name": selected.repository["fullName"]}
        self.attempts[pair] = {"id": int(pair[0]), "run_attempt": pair[1], "head_sha": authority["headSha"], "head_branch": authority["ref"][11:], "event": "workflow_dispatch", "path": authority["callerPath"], "name": authority["workflow"], "repository": repo, "head_repository": copy.deepcopy(repo), "status": "completed", "conclusion": conclusion}
        key = key or selected.current_job
        existing = [job for job in self.jobs.get(pair, []) if job["name"].split(" / ")[-1] == key]
        if existing:
            job = existing[0]
        else:
            self.next_id += 1
            job = {"id": self.next_id, "run_id": int(pair[0]), "run_attempt": pair[1], "name": f"{selected.stage} / {key}", "head_sha": authority["headSha"], "steps": []}
            self.jobs.setdefault(pair, []).append(job)
        job.update(status="in_progress" if active else "completed", conclusion=None if active else conclusion, started_at=utc(-600), completed_at=None if active else utc(600))
        return job

    def proof_signature(self, path: Path, proof: dict) -> dict:
        producer, repo = proof["producer"], proof["repository"]
        uri = "https://github.com/" + repo["fullName"]
        signer = "https://github.com/" + producer["reusableRepository"] + "/" + producer["reusablePath"] + "@" + producer["reusableCommit"]
        invocation = uri + f"/actions/runs/{producer['runId']}/attempts/{producer['attempt']}"
        certificate = {"issuer": "https://token.actions.githubusercontent.com", "subjectAlternativeName": signer, "buildSignerURI": signer, "buildSignerDigest": producer["reusableCommit"], "runnerEnvironment": "github-hosted", "sourceRepositoryURI": uri, "sourceRepositoryIdentifier": repo["id"], "sourceRepositoryDigest": producer["headSha"], "sourceRepositoryRef": producer["ref"], "buildConfigURI": uri + "/" + producer["callerPath"] + "@" + producer["ref"], "buildConfigDigest": producer["headSha"], "buildTrigger": "workflow_dispatch", "runInvocationURI": invocation}
        statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": path.name, "digest": {"sha256": sha256_file(path)}}], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1", "externalParameters": {"workflow": {"ref": producer["ref"], "repository": uri, "path": producer["callerPath"]}}, "internalParameters": {"github": {"event_name": "workflow_dispatch", "repository_id": repo["id"], "repository_owner_id": "123", "runner_environment": "github-hosted"}}, "resolvedDependencies": [{"uri": "git+" + uri + "@" + producer["ref"], "digest": {"gitCommit": producer["headSha"]}}]}, "runDetails": {"builder": {"id": signer}, "metadata": {"invocationId": invocation}}}}
        return {"attestation": {"bundle": "opaque; a real gh process verifies this at the boundary"}, "verificationResult": {"mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1", "signature": {"certificate": certificate}, "statement": statement, "verifiedTimestamps": [{"type": "Tlog", "uri": "https://rekor.sigstore.dev", "timestamp": utc()}]}}

    def sign(self, path: Path, proof: dict | None = None) -> dict:
        proof = proof or json.loads(path.read_bytes())
        signature = self.proof_signature(path, proof)
        self.signatures.setdefault(sha256_file(path), []).append(signature)
        return signature

    def upload(self, selected: Context, root: Path, kind: str, *, members: list[tuple[str | zipfile.ZipInfo, bytes]] | None = None, expired: bool = False) -> dict:
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as stream:
            if members is None:
                for file in sorted(root.rglob("*")):
                    if file.is_file():
                        stream.writestr(file.relative_to(root).as_posix(), file.read_bytes())
            else:
                for name, body in members:
                    stream.writestr(name, body)
        raw = data.getvalue()
        self.next_id += 1
        artifact = {"id": self.next_id, "name": artifact_name(selected.stage, selected.platform, kind), "size_in_bytes": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "expired": expired, "created_at": utc(), "workflow_run": {"id": int(selected.authority["runId"]), "repository_id": int(selected.repository["id"]), "head_repository_id": int(selected.repository["id"]), "head_sha": selected.authority["headSha"]}}
        self.zips[artifact["id"]] = raw
        self.artifacts.setdefault(selected.authority["runId"], []).append(artifact)
        return artifact

    def run(self, arguments, *, maximum=16 * 1024 * 1024, timeout=120, output=None):
        self.requests.append(list(arguments))
        if self.fail and self.fail in " ".join(arguments):
            raise WorkflowError("injected GitHub read/verification failure")
        if arguments[:3] == ["gh", "attestation", "verify"]:
            for flag in ("--repo", "--signer-workflow", "--signer-digest", "--source-digest", "--source-ref", "--deny-self-hosted-runners", "--format"):
                if flag not in arguments:
                    raise AssertionError("missing cryptographic verifier policy flag")
            if "--custom-trusted-root" in arguments:
                raise AssertionError("production verifier accepted a custom root")
            digest = sha256_file(Path(arguments[3]))
            if digest not in self.signatures:
                raise WorkflowError("no authenticated signature for synthetic subject")
            return canonical_json_bytes(self.signatures[digest])
        if arguments[:2] != ["gh", "api"] or arguments[arguments.index("--method") + 1] != "GET":
            raise AssertionError("forbidden Store/build/auth/upload/delete command")
        endpoint = arguments[-1]
        if not endpoint.startswith("repos/example/mobile-app/"):
            raise AssertionError("request escaped fixed GitHub repository")
        resource = endpoint.removeprefix("repos/example/mobile-app/")
        if resource.startswith("git/commits/"):
            commit = resource.removeprefix("git/commits/")
            result = {"sha": commit, "tree": {"sha": self.trees[commit]}}
        elif resource.startswith("compare/"):
            pair = tuple(resource.removeprefix("compare/").split("..."))
            result = self.comparisons[pair]
            if result is None:
                raise WorkflowError("GitHub source commits have no common history")
        elif resource.startswith("actions/artifacts/") and resource.endswith("/zip"):
            body = self.zips[int(resource.split("/")[2])]
            if len(body) > maximum or output is None:
                raise WorkflowError("oversized fixture download")
            Path(output).write_bytes(body)
            os.chmod(output, 0o600)
            return b""
        elif "/attempts/" in resource:
            parts = resource.split("?")[0].split("/")
            pair = parts[2], int(parts[4])
            if len(parts) == 5:
                result = self.attempts[pair]
            else:
                rows = self.jobs.get(pair, [])
                page = int(resource.rsplit("page=", 1)[1])
                result = {"total_count": len(rows), "jobs": rows[(page - 1) * 100:page * 100]}
        elif "/artifacts?" in resource:
            run = resource.split("/")[2]
            rows = self.artifacts.get(run, [])
            page = int(resource.rsplit("page=", 1)[1])
            result = {"total_count": len(rows), "artifacts": rows[(page - 1) * 100:page * 100]}
        else:
            # A latest-run request is explicitly forbidden. The fixtures can
            # retain attempt 1 while a later attempt is the API's latest.
            raise AssertionError("unexpected or mutable-latest-run API request: " + resource)
        return canonical_json_bytes(result)


class Lifecycle:
    """Build real strict documents and package them using the real helper."""

    def __init__(self, root: Path, api: FakeGitHub, platform: str = "android"):
        self.root, self.api, self.platform = root, api, platform
        self.config = load_config(write_project(root / "source", android_config() if platform == "android" else ios_config(), platform=platform))
        self.documents = build_lifecycle(self.config, platform=platform)
        self.candidate: dict | None = None
        self.receipts: dict[str, dict] = {}
        self.packages: dict[str, Path] = {}
        self.intents: dict[str, dict] = {}
        self.contexts: dict[str, Context] = {}
        self.handoff = root / "handoff"
        self.handoff.mkdir()
        primary = "app-release.aab" if platform == "android" else "app.ipa"
        shutil.copyfile(self.config.root / ("app.aab" if platform == "android" else "app.ipa"), self.handoff / primary)
        shutil.copyfile(self.config.root / "validation-report.json", self.handoff / "validation-report.json")
        self.records = copy.deepcopy(self.documents["records"])
        for record in self.records:
            if record["logicalName"] in {"android-aab", "ios-ipa"}:
                record["fileName"] = primary
        if platform == "ios":
            # The resolver authenticates but must never extract nested archives.
            with zipfile.ZipFile(self.handoff / "archive.zip", "w") as archive:
                archive.writestr("../opaque-retained-archive-not-extracted-here", "fixture")
            record = next(item for item in self.records if item["logicalName"] == "ios-archive")
            record.update(size=(self.handoff / "archive.zip").stat().st_size, sha256=sha256_file(self.handoff / "archive.zip"))
            shutil.copyfile(self.config.root / "dsyms.zip", self.handoff / "dsyms.zip")
        self.records.sort(key=lambda item: item["logicalName"])
        (self.handoff / "SHA256SUMS").write_text("".join(f"{sha256_file(file)}  {file.name}\n" for file in sorted(self.handoff.iterdir())))

    def prepare(self, stage: str, *, run_id: str | None = None, attempt: int = 1) -> tuple[Context, Path, dict]:
        selected = context(stage, self.platform, run_id=run_id, attempt=attempt)
        self.contexts[stage] = selected
        self.api.register(selected, active=True)
        app = self.root / (stage + "-app")
        operation = app / ".mobile-release" / "operation"
        operation.mkdir(parents=True)
        source_key = {"candidate": "candidate_intent", "external-testing": "external_intent", "production-submit": "production_intent"}[stage]
        intent = verify_sealed(self.documents[source_key])
        intent["authorizedBy"] = dict(selected.authority)
        intent["artifacts"] = copy.deepcopy(self.records)
        if stage != "candidate":
            assert self.candidate is not None
            intent["predecessors"] = {"candidateManifestSha256": self.candidate["integrity"]["sha256"], "candidateReceiptSha256": self.receipts["candidate"]["integrity"]["sha256"]}
            shutil.copytree(self.packages["candidate"], app / ".mobile-release" / "input" / "candidate")
        if stage == "production-submit":
            intent["predecessors"]["externalReceiptSha256"] = self.receipts["external-testing"]["integrity"]["sha256"]
            shutil.copytree(self.packages["external-testing"], app / ".mobile-release" / "input" / "external")
        intent = seal(intent)
        json_file(operation / f"{stage}-operation-intent.json", intent)
        self.intents[stage] = intent
        if stage == "candidate":
            shutil.copytree(self.handoff, app / ".mobile-release" / "artifacts" / self.platform)
            metadata = app / ".mobile-release" / "staging" / "candidate" / self.platform / "store-metadata.zip"
            metadata.parent.mkdir(parents=True)
            shutil.copyfile(self.config.root / "store-metadata.zip", metadata)
        seal_intent(app, selected, self.api.client(selected))
        proof = json.loads((operation / "intent-provenance.json").read_bytes())
        self.api.sign(operation / "intent-provenance.json")
        if stage == "candidate":
            self.api.sign(self.handoff / ("app-release.aab" if self.platform == "android" else "app.ipa"), proof)
        self.api.upload(selected, operation, "intent")
        return selected, app, intent

    def finish(self, stage: str, selected: Context, app: Path, intent: dict, *, conclusion: str = "success", executor: dict | None = None, result: str = "accepted") -> Path:
        raw = raw_receipt(intent, executed_by=executor, result=result)
        evidence = app / ".mobile-release" / "staging" / stage / self.platform
        evidence.mkdir(parents=True, exist_ok=True)
        if stage == "candidate":
            candidate = verify_sealed(self.documents["candidate"])
            candidate.update(artifacts=copy.deepcopy(self.records), operationIntentSha256=intent["integrity"]["sha256"], authorizedBy=intent["authorizedBy"], executedBy=raw["executedBy"], producedBy=dict(selected.authority))
            self.candidate = seal(candidate)
            validate_evidence_document(self.candidate)
            json_file(evidence / "candidate-manifest.json", self.candidate)
        assert self.candidate is not None
        env = workflow_environment(stage, run_id=selected.authority["runId"], attempt=selected.authority["attempt"], head=selected.authority["headSha"])
        with patch.dict(os.environ, env):
            receipt = build_receipt(stage=stage, platform=self.platform, candidate_manifest=self.candidate, store_receipt=raw, operation_intent=intent, previous_receipt=self.receipts.get("candidate" if stage == "external-testing" else "external-testing"))
        self.receipts[stage] = receipt
        json_file(evidence / f"{stage}-receipt.json", receipt)
        json_file(app / ".mobile-release" / "store" / "readback.json", raw)
        package = self.root / (stage + "-final")
        package_final(app, evidence, app / ".mobile-release" / "store" / "readback.json", package, selected, self.api.client(selected))
        self.api.sign(package / "workflow-provenance.json")
        self.api.upload(selected, package, "evidence")
        self.api.register(selected, conclusion=conclusion)
        self.packages[stage] = package
        return package

    def create(self, stage: str, *, run_id: str | None = None, conclusion: str = "success") -> Path:
        return self.finish(stage, *self.prepare(stage, run_id=run_id), conclusion=conclusion)


class WorkflowRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-workflow-recovery-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.api = FakeGitHub()

    def lifecycle(self, platform="android"):
        root = self.root / (platform + "-lifecycle")
        root.mkdir()
        return Lifecycle(root, self.api, platform)

    def resolve(self, selected: Context, name="resolution", **options):
        self.api.register(selected)
        return Resolver(selected, self.api.client(selected)).resolve(self.root / name, **options)

    def assert_read_only(self):
        self.assertTrue(self.api.requests)
        for command in self.api.requests:
            self.assertTrue(command[:3] == ["gh", "attestation", "verify"] or command[:2] == ["gh", "api"])
            if command[:2] == ["gh", "api"]:
                self.assertEqual(command[command.index("--method") + 1], "GET")
            self.assertNotIn("--custom-trusted-root", command)
            self.assertFalse(set(command) & {"gradle", "xcodebuild", "fastlane", "upload", "DELETE", "POST", "PATCH"})

    def test_complete_final_reuses_original_without_handoff_standalone_intent_or_store(self):
        lifecycle = self.lifecycle()
        package = lifecycle.create("candidate", conclusion="cancelled")
        original = lifecycle.contexts["candidate"]
        originals = self.api.artifacts[original.authority["runId"]]
        final = next(item for item in originals if "evidence" in item["name"])
        self.api.artifacts[original.authority["runId"]] = [final]
        shutil.rmtree(lifecycle.handoff)
        self.api.requests.clear()
        current = context(run_id="2000000000", head="4" * 40)
        result = self.resolve(current, recovery_run_id=original.authority["runId"])
        self.assertEqual(result["mode"], "complete")
        self.assertEqual(result["source"]["commit"], "2" * 40)
        self.assertEqual(result["dispatch"]["headSha"], "4" * 40)
        self.assertEqual(result["evidenceRunId"], original.authority["runId"])
        self.assertEqual(result["evidenceArtifactId"], str(final["id"]))
        self.assertEqual(result["files"], [])
        self.assertEqual([p.name for p in (self.root / "resolution").iterdir()], ["resolution.json"])
        self.assertTrue((package / "candidate-manifest.json").is_file())
        self.assert_read_only()

    def test_latest_attempt_mismatch_and_failed_other_platform_do_not_erase_final(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate", conclusion="failure")
        # Exact attempt 1 remains queryable; any mutable latest-run query is a
        # fake boundary assertion failure, not an accidental passing fixture.
        selected = context(attempt=4)
        result = self.resolve(selected)
        self.assertEqual(result["mode"], "complete")
        attempts = [cmd[-1] for cmd in self.api.requests if cmd[:2] == ["gh", "api"] and "/attempts/" in cmd[-1]]
        self.assertTrue(any("/attempts/1" in path for path in attempts))
        self.assertTrue(any("/attempts/4" in path for path in attempts))

    def test_candidate_intent_resumes_original_bytes_and_source_across_dispatches(self):
        lifecycle = self.lifecycle("ios")
        old, app, intent = lifecycle.prepare("candidate")
        self.api.register(old, conclusion="cancelled")
        self.api.upload(old, lifecycle.handoff, "handoff")
        current = context(platform="ios", run_id="2000000000", head="4" * 40)
        result = self.resolve(current, recovery_run_id=old.authority["runId"])
        self.assertEqual(result["mode"], "resume")
        self.assertEqual(result["source"], intent["operationSource"])
        staged = self.root / "resolution"
        self.assertEqual((staged / "operation" / "candidate-operation-intent.json").read_bytes(), (app / ".mobile-release" / "operation" / "candidate-operation-intent.json").read_bytes())
        for binary in lifecycle.handoff.iterdir():
            self.assertEqual((staged / "artifacts" / "ios" / binary.name).read_bytes(), binary.read_bytes())
        self.assertFalse((self.root / "opaque-retained-archive-not-extracted-here").exists())
        self.assert_read_only()

    def test_prepare_and_final_may_have_different_actual_attempts(self):
        lifecycle = self.lifecycle()
        old, app, intent = lifecycle.prepare("candidate")
        self.api.register(old, conclusion="failure")
        current = context(attempt=2)
        self.api.register(current, active=True)
        lifecycle.finish("candidate", current, app, intent, executor=dict(current.authority))
        result = self.resolve(context(attempt=3))
        self.assertEqual(result["mode"], "complete")
        package = lifecycle.packages["candidate"]
        self.assertEqual(json.loads((package / "workflow-provenance.json").read_bytes())["producer"]["attempt"], 2)
        self.assertEqual(json.loads((package / "operation" / "intent-provenance.json").read_bytes())["producer"]["attempt"], 1)

    def test_candidate_first_resolver_is_fresh_but_store_without_handoff_is_not(self):
        selected = context(key="android_resolve")
        self.assertEqual(self.resolve(selected)["mode"], "fresh")
        with self.assertRaisesRegex(ValidationError, "handoff"):
            self.resolve(context(), name="store-no-handoff")
        with self.assertRaisesRegex(ValidationError, "absence"):
            self.resolve(context(attempt=2, key="android_resolve"), name="later-empty")
        with self.assertRaisesRegex(ValidationError, "missing"):
            self.resolve(context(run_id="2000000000"), name="missing-original", recovery_run_id="1000000000")

    def test_inapplicable_selectors_and_wrong_platform_resolver_do_not_authorize_fresh_work(self):
        cases = (
            (context(key="android_resolve"), {"candidate_run_id": "123"}),
            (context(key="android_resolve"), {"external_run_id": "123"}),
            (context("external-testing"), {"external_run_id": "123"}),
            (context("production-submit"), {"handoff_digest": "a" * 64}),
            (context(key="ios_resolve"), {}),
        )
        for index, (selected, options) in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValidationError):
                self.resolve(selected, name=f"invalid-selector-{index}", **options)

    def test_invalid_run_selectors_and_same_run_recovery_fail_before_network_or_writes(self):
        selected = context(key="android_resolve")
        for value in ("", "0", "-1", "01", "1/attempts/1", "1\nmode=fresh", "9" * 21, selected.authority["runId"]):
            destination = self.root / "must-not-exist"
            with self.subTest(value=value), self.assertRaises(ValidationError):
                Resolver(selected, self.api.client(selected)).resolve(destination, recovery_run_id=value)
            self.assertFalse(destination.exists())
        self.assertEqual(self.api.requests, [])

    def test_handoff_only_requires_trusted_needs_digest_and_actual_build_job(self):
        lifecycle = self.lifecycle()
        current = context()
        self.api.register(current)
        self.api.register(current, key="android_build", conclusion="success")
        artifact = self.api.upload(current, lifecycle.handoff, "handoff")
        digest = artifact["digest"][7:]
        with self.assertRaisesRegex(ValidationError, "trusted build"):
            self.resolve(context(key="android_resolve"), name="resolver")
        with self.assertRaisesRegex(ValidationError, "differs"):
            self.resolve(current, name="wrong", handoff_digest="f" * 64)
        result = self.resolve(current, name="trusted", handoff_digest=digest)
        self.assertEqual(result["mode"], "prepare")
        self.assert_read_only()

    def prior_skipped(self, selected: Context, *, attempted=False, cancelled=False, missing=False):
        job = self.api.register(selected, conclusion="cancelled" if cancelled else "failure")
        job["steps"] = [
            {"name": "Prepare immutable Store operation without mutation", "number": 1, "status": "completed", "conclusion": "failure"},
            {"name": "Execute or reconcile the exact authorized Store operation", "number": 2, "status": "completed", "conclusion": "failure" if attempted else "skipped"},
        ]
        if missing:
            job["steps"].pop()
        return job

    def test_later_handoff_only_requires_positive_nonexecution_in_every_attempt(self):
        lifecycle = self.lifecycle()
        original = context()
        self.api.register(original, key="android_build", conclusion="success")
        self.prior_skipped(original)
        artifact = self.api.upload(original, lifecycle.handoff, "handoff")
        digest = artifact["digest"][7:]
        self.assertEqual(self.resolve(context(attempt=2), name="safe", handoff_digest=digest)["mode"], "prepare")
        cases = [("executed", True, False, False), ("cancelled", False, True, False), ("missing-step", False, False, True)]
        for name, attempted, cancelled, missing in cases:
            self.prior_skipped(original, attempted=attempted, cancelled=cancelled, missing=missing)
            with self.subTest(name=name), self.assertRaises(ValidationError):
                self.resolve(context(attempt=2), name=name, handoff_digest=digest)
        # Checking only attempt 2 would falsely forget the Store call in 1.
        self.prior_skipped(original, attempted=True)
        self.prior_skipped(context(attempt=2))
        with self.assertRaisesRegex(ValidationError, "execution"):
            self.resolve(context(attempt=3), name="forgotten-execute", handoff_digest=digest)

    def test_deleted_intent_after_ambiguous_store_result_cannot_be_prepared_again(self):
        lifecycle = self.lifecycle()
        original, _, _ = lifecycle.prepare("candidate")
        self.api.artifacts[original.authority["runId"]] = []
        self.prior_skipped(original, attempted=True)
        self.api.register(original, key="android_build", conclusion="success")
        artifact = self.api.upload(original, lifecycle.handoff, "handoff")
        with self.assertRaisesRegex(ValidationError, "execution"):
            self.resolve(context(attempt=2), handoff_digest=artifact["digest"][7:])
        self.assert_read_only()

    def test_missing_jobs_and_ambiguous_names_are_not_nonexecution_proof(self):
        lifecycle = self.lifecycle()
        old = context()
        self.api.register(old, key="android_build", conclusion="success")
        artifact = self.api.upload(old, lifecycle.handoff, "handoff")
        for variant in ("missing", "duplicate", "suffix"):
            self.api.jobs[(old.authority["runId"], 1)] = [job for job in self.api.jobs[(old.authority["runId"], 1)] if job["name"].endswith("android_build")]
            if variant != "missing":
                job = self.prior_skipped(old)
                if variant == "duplicate":
                    other = copy.deepcopy(job)
                    other["id"] += 100000
                    self.api.jobs[(old.authority["runId"], 1)].append(other)
                else:
                    job["name"] = "attacker_android_store"
            with self.subTest(variant=variant), self.assertRaises(ValidationError):
                self.resolve(context(attempt=2), name=variant, handoff_digest=artifact["digest"][7:])

    def test_artifact_expiry_inaccessibility_duplicate_or_digest_drift_never_falls_back(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate")
        run_id = lifecycle.contexts["candidate"].authority["runId"]
        original = copy.deepcopy(self.api.artifacts[run_id])
        for variant in ("expired", "duplicate", "digest", "wrong-repository", "api-error"):
            self.api.artifacts[run_id] = copy.deepcopy(original)
            final = next(item for item in self.api.artifacts[run_id] if "evidence" in item["name"])
            if variant == "expired":
                final["expired"] = True
            elif variant == "duplicate":
                duplicate = dict(final, id=final["id"] + 1)
                self.api.artifacts[run_id].append(duplicate)
            elif variant == "digest":
                final["digest"] = "sha256:" + "f" * 64
            elif variant == "wrong-repository":
                final["workflow_run"]["repository_id"] += 1
            else:
                self.api.fail = "/artifacts?"
            with self.subTest(variant=variant), self.assertRaises(ValidationError):
                self.resolve(context(attempt=2), name=variant)
            self.api.fail = None

    def test_required_intent_and_handoff_expiry_fail_but_redundant_intent_can_expire(self):
        lifecycle = self.lifecycle()
        old, app, intent = lifecycle.prepare("candidate")
        self.api.register(old, conclusion="failure")
        handoff = self.api.upload(old, lifecycle.handoff, "handoff", expired=True)
        with self.assertRaisesRegex(ValidationError, "expired"):
            self.resolve(context(attempt=2), name="expired-handoff")
        handoff["expired"] = False
        self.api.register(old, active=True)
        lifecycle.finish("candidate", old, app, intent)
        next(item for item in self.api.artifacts[old.authority["runId"]] if "intent" in item["name"])["expired"] = True
        self.assertEqual(self.resolve(context(attempt=2), name="complete")["mode"], "complete")

    def test_invalid_certified_claim_cannot_be_repaired_by_a_plausible_predicate(self):
        lifecycle = self.lifecycle()
        package = lifecycle.create("candidate")
        proof = package / "workflow-provenance.json"
        digest = sha256_file(proof)
        original = copy.deepcopy(self.api.signatures[digest])
        for claim, changed in {
            "runInvocationURI": "https://github.com/example/mobile-app/actions/runs/1000000000/attempts/9",
            "sourceRepositoryIdentifier": "999",
            "sourceRepositoryURI": "https://github.com/evil/mobile-app",
            "sourceRepositoryDigest": "4" * 40,
            "buildSignerDigest": "a" * 40,
            "buildSignerURI": "https://github.com/evil/tool/.github/workflows/reusable-candidate.yml@" + "1" * 40,
            "buildConfigURI": "https://github.com/example/mobile-app/.github/workflows/evil.yml@refs/heads/main",
            "runnerEnvironment": "self-hosted",
            "buildTrigger": "pull_request",
            "issuer": "https://attacker.invalid",
        }.items():
            self.api.signatures[digest] = copy.deepcopy(original)
            self.api.signatures[digest][0]["verificationResult"]["signature"]["certificate"][claim] = changed
            with self.subTest(claim=claim), self.assertRaisesRegex(ValidationError, "attestation"):
                self.resolve(context(attempt=2), name=claim)
        self.assert_read_only()

    def test_predicate_invocation_source_builder_and_subject_are_checked_separately(self):
        lifecycle = self.lifecycle()
        package = lifecycle.create("candidate")
        digest = sha256_file(package / "workflow-provenance.json")
        original = copy.deepcopy(self.api.signatures[digest])
        for variant in ("invocation", "source", "builder", "subject-name", "subject-digest", "timestamp", "predicate-version"):
            self.api.signatures[digest] = copy.deepcopy(original)
            result = self.api.signatures[digest][0]["verificationResult"]
            statement = result["statement"]
            if variant == "invocation":
                statement["predicate"]["runDetails"]["metadata"]["invocationId"] += "0"
            elif variant == "source":
                statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = "4" * 40
            elif variant == "builder":
                statement["predicate"]["runDetails"]["builder"]["id"] = "https://github.com/actions/runner/github-hosted"
            elif variant == "subject-name":
                statement["subject"][0]["name"] = "other.json"
            elif variant == "subject-digest":
                statement["subject"][0]["digest"]["sha256"] = "f" * 64
            elif variant == "timestamp":
                result["verifiedTimestamps"][0]["timestamp"] = "2000-01-01T00:00:00Z"
            else:
                statement["predicateType"] = "https://invalid.example/provenance"
            with self.subTest(variant=variant), self.assertRaisesRegex(ValidationError, "attestation"):
                self.resolve(context(attempt=2), name=variant)

    def test_wrong_job_id_or_artifact_timing_fails_even_when_run_succeeded(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate")
        original = lifecycle.contexts["candidate"]
        pair = original.authority["runId"], 1
        job = self.api.jobs[pair][0]
        job_id = job["id"]
        job["id"] += 1
        with self.assertRaisesRegex(ValidationError, "job ID"):
            self.resolve(context(attempt=2), name="job")
        job["id"] = job_id
        artifact = next(item for item in self.api.artifacts[pair[0]] if "evidence" in item["name"])
        artifact["created_at"] = "2000-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValidationError, "interval"):
            self.resolve(context(attempt=2), name="timing")

    def replace_final(self, lifecycle: Lifecycle, mutate, *, resign: bool = False):
        package = lifecycle.packages["candidate"]
        mutate(package)
        if resign:
            proof_path = package / "workflow-provenance.json"
            proof = json.loads(proof_path.read_bytes())
            proof_path.unlink()
            proof["files"] = _inventory(package, _layout("candidate", "final"), omitted="workflow-provenance.json")
            json_file(proof_path, proof)
            self.api.sign(proof_path)
        selected = lifecycle.contexts["candidate"]
        self.api.artifacts[selected.authority["runId"]] = [artifact for artifact in self.api.artifacts[selected.authority["runId"]] if "evidence" not in artifact["name"]]
        return self.api.upload(selected, package, "evidence")

    def test_raw_byte_substitution_is_rejected_by_signed_complete_inventory(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate")
        def change(package):
            path = package / "store-receipt.json"
            value = json.loads(path.read_bytes())
            value["state"] = "draft"
            json_file(path, value)
        self.replace_final(lifecycle, change)
        with self.assertRaisesRegex(ValidationError, "inventory"):
            self.resolve(context(attempt=2))

    def test_even_authenticated_raw_must_match_normalized_final_receipt(self):
        for field, changed in (("observedAt", "2026-01-01T00:00:01Z"), ("result", "reconciled"), ("versionCode", 43), ("executedBy", {"wrong": "job"})):
            with self.subTest(field=field):
                nested = self.root / field
                nested.mkdir()
                lifecycle = Lifecycle(nested, self.api)
                lifecycle.create("candidate", run_id=str(1100000000 + len(self.api.artifacts)))
                def change(package):
                    path = package / "store-receipt.json"
                    raw = json.loads(path.read_bytes())
                    raw[field] = changed
                    json_file(path, raw)
                self.replace_final(lifecycle, change, resign=True)
                original = lifecycle.contexts["candidate"].authority["runId"]
                with self.assertRaises(ValidationError):
                    self.resolve(context(run_id=str(int(original) + 1000000000)), name=field + "-resolution", recovery_run_id=original)

    def test_complete_inventory_cannot_drop_original_intent_proof_or_add_hidden_file(self):
        for variant in ("drop-proof", "extra-file", "extra-directory"):
            with self.subTest(variant=variant):
                nested = self.root / variant
                nested.mkdir()
                lifecycle = Lifecycle(nested, self.api)
                lifecycle.create("candidate", run_id=str(1200000000 + len(self.api.artifacts)))
                def change(package):
                    if variant == "drop-proof":
                        (package / "operation" / "intent-provenance.json").unlink()
                    elif variant == "extra-file":
                        (package / ".private-key").write_text("not an allowed report")
                    else:
                        (package / "extra").mkdir()
                        (package / "extra" / "unexpected.json").write_text("{}")
                self.replace_final(lifecycle, change)
                original = lifecycle.contexts["candidate"].authority["runId"]
                with self.assertRaises(ValidationError):
                    self.resolve(context(run_id=str(int(original) + 1000000000)), name=variant + "-resolution", recovery_run_id=original)

    def test_sidecar_checksum_without_authenticated_signature_is_rejected(self):
        lifecycle = self.lifecycle()
        package = lifecycle.create("candidate")
        del self.api.signatures[sha256_file(package / "workflow-provenance.json")]
        with self.assertRaisesRegex(ValidationError, "signature"):
            self.resolve(context(attempt=2))

    def test_retry_may_have_multiple_attestations_but_cannot_mix_claims(self):
        lifecycle = self.lifecycle()
        package = lifecycle.create("candidate")
        digest = sha256_file(package / "workflow-provenance.json")
        real = copy.deepcopy(self.api.signatures[digest][0])
        bad_identity = copy.deepcopy(real)
        bad_identity["verificationResult"]["signature"]["certificate"]["runInvocationURI"] += "0"
        bad_subject = copy.deepcopy(real)
        bad_subject["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "f" * 64
        self.api.signatures[digest] = [bad_identity, bad_subject]
        with self.assertRaisesRegex(ValidationError, "attestation"):
            self.resolve(context(attempt=2), name="mixed")
        self.api.signatures[digest].append(real)
        self.assertEqual(self.resolve(context(attempt=2), name="valid-retry")["mode"], "complete")

    def test_predecessor_retention_survives_parent_artifact_expiry(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate")
        lifecycle.create("external-testing")
        current, _, intent = lifecycle.prepare("production-submit")
        self.api.register(current, conclusion="failure")
        # All candidate/external ZIPs expire. The newer operation embeds their
        # exact documents AND original signed proofs, so no parent ZIP is needed.
        for run_id, artifacts in self.api.artifacts.items():
            if run_id != current.authority["runId"]:
                for artifact in artifacts:
                    artifact["expired"] = True
        result = self.resolve(context("production-submit", attempt=2), name="production-recovery")
        self.assertEqual(result["mode"], "resume")
        copied = json.loads((self.root / "production-recovery" / "operation" / "production-submit-operation-intent.json").read_bytes())
        self.assertEqual(copied, intent)
        self.assertEqual(json.loads((self.root / "production-recovery" / "input" / "candidate" / "candidate-manifest.json").read_bytes()), lifecycle.candidate)

    def test_full_android_and_ios_candidate_external_production_chains_reuse_originals(self):
        for platform in ("android", "ios"):
            lifecycle = self.lifecycle(platform)
            for index, stage in enumerate(("candidate", "external-testing", "production-submit")):
                with self.subTest(platform=platform, stage=stage):
                    run_id = str(1300000000 + index * 100 + (platform == "ios"))
                    lifecycle.create(stage, run_id=run_id)
                    current = context(stage, platform, run_id=str(int(run_id) + 1000000000), head="4" * 40)
                    result = self.resolve(current, name=platform + stage, recovery_run_id=run_id)
                    self.assertEqual(result["mode"], "complete")
                    self.assertEqual(result["evidenceRunId"], run_id)
        self.assert_read_only()

    def test_mixed_origin_platforms_use_explicit_independent_candidate_and_external_runs(self):
        for index, platform in enumerate(("android", "ios")):
            lifecycle = self.lifecycle(platform)
            candidate_run, external_run = str(1400000000 + index), str(1500000000 + index)
            lifecycle.create("candidate", run_id=candidate_run)
            lifecycle.create("external-testing", run_id=external_run)
            selected = context("production-submit", platform, run_id=str(1600000000 + index))
            result = self.resolve(selected, name=platform, candidate_run_id=candidate_run, external_run_id=external_run)
            self.assertEqual(result["mode"], "prepare")
            staged = self.root / platform / "input"
            self.assertEqual(json.loads((staged / "candidate" / "candidate-manifest.json").read_bytes())["producedBy"]["runId"], candidate_run)
            self.assertEqual(json.loads((staged / "external" / "external-testing-receipt.json").read_bytes())["producedBy"]["runId"], external_run)

    def test_completed_cross_run_recovery_can_be_selected_by_actual_final_producer_all_six_paths(self):
        self.api.trees["6" * 40] = "7" * 40
        for platform_index, platform in enumerate(("android", "ios")):
            lifecycle = self.lifecycle(platform)
            for index, stage in enumerate(("candidate", "external-testing", "production-submit")):
                label = platform + stage
                original_id = str(2100000000 + 10 * platform_index + index)
                recovery_id, reuse_id = str(int(original_id) + 100), str(int(original_id) + 200)
                with self.subTest(platform=platform, stage=stage):
                    original, app, intent = lifecycle.prepare(stage, run_id=original_id)
                    self.api.register(original, conclusion="cancelled")
                    if stage == "candidate":
                        self.api.upload(original, lifecycle.handoff, "handoff")
                    recovery = context(stage, platform, run_id=recovery_id, head="4" * 40)
                    resumed = self.resolve(recovery, label + "-resume", recovery_run_id=original_id)
                    self.assertEqual(resumed["mode"], "resume")
                    self.assertEqual(resumed["source"], intent["operationSource"])
                    # An unfinished recovery has no implicit alias to the
                    # original intent; callers must still select original A.
                    reuse = context(stage, platform, run_id=reuse_id, head="6" * 40)
                    with self.assertRaisesRegex(WorkflowError, "original authenticated operation intent is missing"):
                        self.resolve(reuse, label + "-incomplete-alias", recovery_run_id=recovery_id)
                    recovered_app = self.root / (label + "-recovered-app")
                    shutil.copytree(self.root / (label + "-resume") / "operation", recovered_app / ".mobile-release" / "operation")
                    self.api.register(recovery, active=True)
                    outcome = "operator_authorized_reconciliation" if platform == "ios" and stage == "candidate" else "reconciled"
                    package = lifecycle.finish(stage, recovery, recovered_app, intent, executor=dict(recovery.authority), result=outcome)
                    before = {path.relative_to(package): path.read_bytes() for path in package.rglob("*") if path.is_file()}
                    final_artifact = self.api.artifacts[recovery_id][0]
                    before_zip = self.api.zips[final_artifact["id"]]
                    # Completed B retains A proof/predecessors; neither A's
                    # redundant standalone intent nor original binaries are
                    # prerequisites for reference-only reuse of B.
                    self.api.artifacts[original_id] = []
                    for selected, selector, suffix in (
                        (reuse, recovery_id, "new-dispatch"),
                        (context(stage, platform, run_id=recovery_id, attempt=2, head="4" * 40), original_id, "rerun-recovery"),
                    ):
                        result = self.resolve(selected, label + suffix, recovery_run_id=selector)
                        self.assertEqual(result["mode"], "complete")
                        self.assertEqual(result["authorizationRunId"], original_id)
                        self.assertEqual(result["evidenceRunId"], recovery_id)
                        self.assertEqual(result["evidenceArtifactId"], str(final_artifact["id"]))
                        self.assertEqual(result["source"], intent["operationSource"])
                        self.assertEqual(result["files"], [])
                        self.assertEqual(list((self.root / (label + suffix)).iterdir()), [self.root / (label + suffix) / "resolution.json"])
                    self.assertEqual(self.api.zips[final_artifact["id"]], before_zip)
                    self.assertEqual({path.relative_to(package): path.read_bytes() for path in package.rglob("*") if path.is_file()}, before)
                    self.assertEqual(len(self.api.artifacts[recovery_id]), 1)
        self.assert_read_only()

    def test_complete_recovery_requires_exact_confirmation_at_real_main_entrypoint_all_six_paths(self):
        for platform_index, platform in enumerate(("android", "ios")):
            lifecycle = self.lifecycle(platform)
            for index, stage in enumerate(("candidate", "external-testing", "production-submit")):
                lifecycle.create(stage)
                original = lifecycle.contexts[stage]
                run_id = str(2500000000 + 10 * platform_index + index)
                selected = context(stage, platform, run_id=run_id)
                self.api.register(selected)
                expected = f"{stage}:{platform}:1.2.3:42"
                variants = (None, "", expected + " ", expected.replace(":42", ":43"), expected.replace("1.2.3", "1.2.4"), expected.replace(stage, "wrong-stage"), expected)
                for case, confirmation in enumerate(variants):
                    env = workflow_environment(stage, run_id=run_id)
                    env.update(GITHUB_JOB=job_key(stage, platform), MOBILE_RELEASE_SELECTED_PLATFORM=platform)
                    if confirmation is not None:
                        env["MOBILE_RELEASE_CONFIRMATION"] = confirmation
                    destination = self.root / f"main-{platform}-{stage}-{case}"
                    with self.subTest(platform=platform, stage=stage, confirmation=confirmation), patch.dict(os.environ, env, clear=True), patch("mobile_release.workflow.Transport.run", side_effect=self.api.run), patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO) as errors:
                        code = main(["resolve", "--stage", stage, "--platform", platform, "--destination", str(destination), "--recovery-run-id", original.authority["runId"]])
                        self.assertEqual(code, 0 if confirmation == expected else 2, errors.getvalue())
                        self.assertFalse((destination / "artifacts").exists())

    def test_resolver_confirmation_both_is_only_normalized_for_matching_multiplatform_selection(self):
        lifecycle = self.lifecycle()
        for index, stage in enumerate(("candidate", "external-testing", "production-submit")):
            lifecycle.create(stage)
            original_id = lifecycle.contexts[stage].authority["runId"]
            both = f"{stage}:both:1.2.3:42"
            for selection in ("android", "ios", "both", ""):
                selected = context(stage, run_id=str(2600000000 + index), confirmation=both, selected_platform=selection)
                name = stage + "-both-" + (selection or "missing")
                with self.subTest(stage=stage, selection=selection):
                    if stage != "production-submit" and selection == "both":
                        self.assertEqual(self.resolve(selected, name, recovery_run_id=original_id)["mode"], "complete")
                    else:
                        with self.assertRaisesRegex(WorkflowError, "confirmation|platform selection"):
                            self.resolve(selected, name, recovery_run_id=original_id)

    def test_known_intent_wrong_confirmation_stops_before_handoff_download(self):
        lifecycle = self.lifecycle()
        original, _app, _intent = lifecycle.prepare("candidate")
        self.api.register(original)
        handoff = self.api.upload(original, lifecycle.handoff, "handoff")
        selected = context(run_id="2700000000", confirmation="candidate:android:1.2.3:43")
        with self.assertRaisesRegex(WorkflowError, "confirmation"):
            self.resolve(selected, recovery_run_id=original.authority["runId"])
        self.assertFalse(any(command[-1].endswith(f"artifacts/{handoff['id']}/zip") for command in self.api.requests))
        self.assertFalse((self.root / "resolution" / "operation").exists())

    def test_complete_recovery_preserves_scope_and_actual_producer_attempt(self):
        lifecycle = self.lifecycle()
        original, app, intent = lifecycle.prepare("candidate")
        self.api.register(original)
        producer = context(run_id="2800000000", attempt=2, head="4" * 40)
        self.api.register(producer, active=True)
        lifecycle.finish("candidate", producer, app, intent, executor=dict(producer.authority), result="reconciled")
        for field, value in (("ref", "refs/heads/other"), ("workflow", "Wrong workflow"), ("reusableCommit", "9" * 40), ("reusableRepository", "different/toolkit")):
            selected = context(run_id="2800000001")
            selected = replace(selected, authority={**selected.authority, field: value})
            with self.subTest(field=field), self.assertRaises(WorkflowError):
                self.resolve(selected, "scope-" + field, recovery_run_id=producer.authority["runId"])
        with self.assertRaisesRegex(WorkflowError, "producer|dispatch"):
            self.resolve(context(run_id=producer.authority["runId"], attempt=1, head="4" * 40), "before-producer", recovery_run_id=original.authority["runId"])

    def test_fresh_production_rejects_authentic_pending_testflight_before_authorizing_prepare(self):
        lifecycle = self.lifecycle("ios")
        lifecycle.create("candidate")
        original = raw_receipt
        def pending(intent, **options):
            value = original(intent, **options)
            value.update(state="submitted-for-review", betaReviewState="WAITING_FOR_REVIEW")
            return value
        with patch(__name__ + ".raw_receipt", side_effect=pending):
            lifecycle.create("external-testing")
        # This is valid final evidence: the external dispatch may legitimately
        # finish before Beta Review. It is immutable, but NOT production proof.
        external = lifecycle.contexts["external-testing"]
        self.assertEqual(self.resolve(context("external-testing", "ios", attempt=2), name="reuse-pending")["mode"], "complete")
        selected = context("production-submit", "ios")
        with self.assertRaisesRegex(ValidationError, "available-to-testers"):
            self.resolve(selected, name="pending-is-not-production", candidate_run_id=lifecycle.contexts["candidate"].authority["runId"], external_run_id=external.authority["runId"])
        self.assertFalse((self.root / "pending-is-not-production" / "resolution.json").exists())
        self.assert_read_only()

    def test_existing_operation_does_not_replace_its_predecessor_from_new_run_input(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate")
        old, _, _ = lifecycle.prepare("external-testing")
        self.api.register(old, conclusion="failure")
        with self.assertRaisesRegex(ValidationError, "selector conflicts"):
            self.resolve(context("external-testing", attempt=2), candidate_run_id="999999999")
        with self.assertRaisesRegex(ValidationError, "durable intent"):
            self.resolve(context("production-submit", attempt=2), name="no-promotion-intent", candidate_run_id="1000000000", external_run_id=old.authority["runId"])

    def test_conflicting_standalone_intent_is_rejected_even_when_final_contains_old_proof(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate")
        selected = lifecycle.contexts["candidate"]
        original = next(item for item in self.api.artifacts[selected.authority["runId"]] if "intent" in item["name"])
        # Even a malformed redundant artifact is not silently treated as absent.
        original["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValidationError, "service receipt"):
            self.resolve(context(attempt=2))

    def test_temporary_final_upload_error_cannot_authorize_overwrite_or_reissue(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate", conclusion="failure")
        old = lifecycle.contexts["candidate"].authority["runId"]
        result = self.resolve(context(run_id="2000000000"), recovery_run_id=old)
        self.assertEqual(result["mode"], "complete")
        self.assertEqual(result["evidenceRunId"], old)
        self.assert_read_only()
        with self.assertRaisesRegex(ValidationError, "reference-only"):
            stage_resolution(self.root / "resolution", self.root / "must-not-stage", context(run_id="2000000000"))

    def test_cli_original_intent_authentication_does_not_accept_local_seal(self):
        lifecycle = self.lifecycle("ios")
        selected, app, intent = lifecycle.prepare("candidate")
        path = app / ".mobile-release" / "operation" / "candidate-operation-intent.json"
        verified = authenticate_operation_intent(path, stage="candidate", platform="ios", github=self.api.client(selected))
        self.assertEqual(verified, intent)
        self.api.artifacts[selected.authority["runId"]] = []
        with self.assertRaisesRegex(ValidationError, "durable authenticated"):
            authenticate_operation_intent(path, stage="candidate", platform="ios", github=self.api.client(selected))
        self.assert_read_only()

    def test_cli_authentication_rejects_tampered_local_intent_ancestor_and_wrong_store_job(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate")
        selected, app, _ = lifecycle.prepare("external-testing")
        operation = app / ".mobile-release" / "operation"
        path = operation / "external-testing-operation-intent.json"
        (operation / "candidate" / "store-receipt.json").write_text("{}")
        with self.assertRaisesRegex(ValidationError, "local intent"):
            authenticate_operation_intent(path, stage="external-testing", platform="android", github=self.api.client(selected))
        resolver_context = context("external-testing", key="android_resolve")
        with self.assertRaisesRegex(ValidationError, "protected Store job"):
            authenticate_operation_intent(path, stage="external-testing", platform="android", github=self.api.client(resolver_context))

    def test_safe_zip_rejects_duplicate_case_collision_traversal_symlink_and_special_file(self):
        cases = {
            "traversal": [("../escape.json", b"bad")],
            "absolute": [("/absolute.json", b"bad")],
            "backslash": [("operation\\intent.json", b"bad")],
            "double-slash": [("operation//intent.json", b"bad")],
            "case": [("Intent.json", b"one"), ("intent.json", b"two")],
            "duplicate": [("intent.json", b"one"), ("intent.json", b"two")],
        }
        symlink = zipfile.ZipInfo("intent.json")
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        device = zipfile.ZipInfo("device")
        device.external_attr = (stat.S_IFCHR | 0o600) << 16
        cases.update(symlink=[(symlink, b"/outside")], device=[(device, b"fixture")])
        for name, members in cases.items():
            archive = self.root / (name + ".zip")
            with zipfile.ZipFile(archive, "w") as stream:
                for path, body in members:
                    with __import__("warnings").catch_warnings():
                        __import__("warnings").simplefilter("ignore", UserWarning)
                        stream.writestr(path, body)
            output = self.root / name
            output.mkdir()
            with self.subTest(name=name), self.assertRaises(ValidationError):
                _extract_zip(archive, output, 1024)
        self.assertFalse((self.root.parent / "escape.json").exists())

    def test_zip_expansion_limit_is_checked_before_extracting_any_member(self):
        archive = self.root / "bomb.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
            stream.writestr("first.json", b"1")
            stream.writestr("huge.json", b"x" * 10000)
        output = self.root / "extract"
        output.mkdir()
        with self.assertRaisesRegex(ValidationError, "expanded size"):
            _extract_zip(archive, output, 100)
        self.assertEqual(list(output.iterdir()), [])

    def test_evidence_retains_full_250_mib_metadata_archive_without_decoding_nested_zip(self):
        # A real streamed 250 MiB payload, not a patched lower size bound. The
        # inner path is intentionally unsafe: only the candidate's upstream
        # metadata validator may interpret it; this boundary retains opaque
        # authorized bytes and must NOT extract any nested archive.
        metadata = self.root / "store-metadata.zip"
        block = b"\0" * (1024 * 1024)
        with zipfile.ZipFile(metadata, "w", compression=zipfile.ZIP_STORED) as archive:
            with archive.open("../never-decode-this-nested-member", "w") as output:
                for _ in range(250):
                    output.write(block)
        expected_size, expected_digest = metadata.stat().st_size, sha256_file(metadata)
        self.assertGreater(expected_size, 250 * 1024 * 1024)  # ZIP header overhead.
        outer = self.root / "service.zip"
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(metadata, arcname="store-metadata.zip")
        destination = self.root / "large-extracted"
        destination.mkdir()
        _extract_zip(outer, destination, MAX_EVIDENCE)
        retained = destination / "store-metadata.zip"
        _metadata_binding(retained, {"artifacts": [{"logicalName": "store-metadata", "fileName": retained.name, "size": expected_size, "sha256": expected_digest}], "configuration": {"metadataSha256": expected_digest}})
        self.assertEqual(retained.stat().st_size, expected_size)
        self.assertEqual(sha256_file(retained), expected_digest)
        self.assertEqual(set(_files(destination)), {"store-metadata.zip"})
        self.assertFalse((self.root / "never-decode-this-nested-member").exists())

    def test_recursive_evidence_files_have_a_real_one_gib_aggregate_bound(self):
        directory = self.root / "recursive-evidence"
        directory.mkdir()
        for relative in ("operation/candidate/operation/store-metadata.zip", "operation/external/operation/candidate/operation/store-metadata.zip"):
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("wb") as stream:
                stream.truncate(512 * 1024 * 1024)
        self.assertEqual(sum(path.stat().st_size for path in _files(directory).values()), 1024 * 1024 * 1024)
        (directory / "one-more-byte.json").write_bytes(b"0")
        with self.assertRaisesRegex(ValidationError, "bounded size"):
            _files(directory)

    def test_zip_implicit_directory_case_collisions_and_file_directory_conflicts_fail_before_writes(self):
        cases = (
            [("Operation/a.json", b"one"), ("operation/b.json", b"two")],
            [("operation", b"file"), ("operation/a.json", b"nested")],
            [("operation/", b""), ("operation", b"file")],
        )
        for index, members in enumerate(cases):
            archive = self.root / f"collision-{index}.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                for name, body in members:
                    stream.writestr(name, body)
            destination = self.root / f"collision-{index}"
            destination.mkdir()
            with self.subTest(index=index), self.assertRaises(ValidationError):
                _extract_zip(archive, destination, 1024)
            self.assertEqual(list(destination.iterdir()), [])

    def test_authenticated_intent_recovery_rejects_substituted_handoff_even_with_new_zip_digest(self):
        lifecycle = self.lifecycle("ios")
        old, _, _ = lifecycle.prepare("candidate")
        self.api.register(old, conclusion="failure")
        (lifecycle.handoff / "archive.zip").write_bytes(b"different retained archive")
        (lifecycle.handoff / "SHA256SUMS").write_text("".join(f"{sha256_file(file)}  {file.name}\n" for file in sorted(lifecycle.handoff.iterdir()) if file.name != "SHA256SUMS"))
        self.api.upload(old, lifecycle.handoff, "handoff")
        with self.assertRaisesRegex(ValidationError, "intent-authorized"):
            self.resolve(context(platform="ios", attempt=2))
        self.assert_read_only()

    def test_pagination_truncation_duplicates_and_unbounded_lists_fail(self):
        selected = context()
        self.api.register(selected)
        client = self.api.client(selected)
        for response in ({"total_count": 2, "jobs": [{"id": 1}]}, {"total_count": 2, "jobs": [{"id": 1}, {"id": 1}]}, {"total_count": 10001, "jobs": []}, {"total_count": True, "jobs": []}):
            with self.subTest(response=response), patch.object(self.api, "run", return_value=canonical_json_bytes(response)), self.assertRaises(ValidationError):
                client.pages("actions/runs/1000000000/attempts/1/jobs", "jobs")

    def test_rest_attempt_job_and_artifact_ids_require_integers_not_equal_bool_or_float(self):
        selected = context()
        job = self.api.register(selected)
        pair = selected.authority["runId"], 1
        attempt = self.api.attempts[pair]
        for field, value in (("run_attempt", True), ("run_attempt", 1.0), ("id", float(attempt["id"]))):
            old = attempt[field]
            attempt[field] = value
            with self.subTest(kind="attempt", field=field, value=value), self.assertRaises(ValidationError):
                self.api.client(selected).attempt(selected.authority, "candidate")
            attempt[field] = old
        for field, value in (("run_attempt", True), ("run_attempt", 1.0), ("id", float(job["id"])), ("run_id", float(job["run_id"]))):
            old = job[field]
            job[field] = value
            with self.subTest(kind="job", field=field, value=value), self.assertRaises(ValidationError):
                self.api.client(selected).job(selected.authority, "candidate", "android_store")
            job[field] = old
        lifecycle = self.lifecycle()
        artifact = self.api.upload(selected, lifecycle.handoff, "handoff")
        artifact["workflow_run"]["id"] = float(artifact["workflow_run"]["id"])
        with self.assertRaises(ValidationError):
            self.api.client(selected).artifact(selected.authority["runId"], artifact["name"])

    def test_attempt_requires_exact_dispatch_fork_ref_and_caller_identity(self):
        selected = context()
        self.api.register(selected)
        pair = selected.authority["runId"], 1
        original = copy.deepcopy(self.api.attempts[pair])
        mutations = {
            "fork": lambda item: item["head_repository"].update(id=999, full_name="evil/mobile-app"),
            "repository": lambda item: item["repository"].update(id=999),
            "event": lambda item: item.update(event="pull_request"),
            "ref": lambda item: item.update(head_branch="untrusted"),
            "head": lambda item: item.update(head_sha="4" * 40),
            "caller": lambda item: item.update(path=".github/workflows/other.yml"),
            "workflow": lambda item: item.update(name="Other workflow"),
        }
        for name, mutate in mutations.items():
            self.api.attempts[pair] = copy.deepcopy(original)
            mutate(self.api.attempts[pair])
            with self.subTest(name=name), self.assertRaises(ValidationError):
                self.api.client(selected).attempt(selected.authority, "candidate")

    def test_pagination_requires_stable_complete_snapshot_not_disappearing_records(self):
        selected = context()
        first = {"total_count": 101, "jobs": [{"id": index + 1} for index in range(100)]}
        cases = (
            {"total_count": 100, "jobs": []},
            {"total_count": 101, "jobs": []},
            {"total_count": 101, "jobs": [{"id": 1}]},
        )
        for response in cases:
            with self.subTest(response=response), patch.object(self.api, "run", side_effect=[canonical_json_bytes(first), canonical_json_bytes(response)]), self.assertRaises(ValidationError):
                self.api.client(selected).pages("actions/runs/1000000000/attempts/1/jobs", "jobs")

    def test_active_original_producer_polls_only_read_only_until_exact_job_finishes(self):
        selected = context()
        job = self.api.register(selected, active=True)
        client = self.api.client(selected)
        original = copy.deepcopy(job)
        completed = dict(original, status="completed", conclusion="cancelled", completed_at=utc())
        with patch.object(client, "jobs", side_effect=[[original], [completed]]) as lookup, patch("mobile_release.workflow.time.sleep") as sleep:
            self.assertEqual(client.job(selected.authority, "candidate", "android_store"), completed)
        self.assertEqual(lookup.call_count, 2)
        sleep.assert_called_once_with(2)
        with patch.object(client, "jobs", return_value=[original]), patch("mobile_release.workflow.time.monotonic", side_effect=[0, 61]), self.assertRaisesRegex(ValidationError, "no completed interval"):
            client.job(selected.authority, "candidate", "android_store")

    def test_two_page_job_lookup_finds_exact_id_without_taking_first_suffix_match(self):
        selected = context()
        real = self.api.register(selected)
        key = selected.authority["runId"], 1
        self.api.jobs[key] = [{"id": 100000 + index, "name": "unrelated"} for index in range(100)] + [real]
        found = self.api.client(selected).job(selected.authority, "candidate", "android_store", str(real["id"]))
        self.assertEqual(found, real)
        self.assertTrue(any("page=2" in command[-1] for command in self.api.requests))

    def git_checkout(self, directory: str = "checkout") -> tuple[Path, dict]:
        root = self.root / directory
        root.mkdir()
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        subprocess.run(["git", "init", "-q", str(root)], env=env, check=True, stdout=subprocess.DEVNULL)
        (root / "tracked.txt").write_text("source fixture\n")
        subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], env=env, check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Fixture"], env=env, check=True)
        commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], env=env).decode().strip()
        tree = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], env=env).decode().strip()
        return root, {"commit": commit, "tree": tree, "ref": "refs/heads/main"}

    def source_graph(self):
        """REST comparisons derived from real independent Git topology.

        Git is only a test oracle. The production resolver issues bounded GETs
        against full immutable IDs and never executes application-owned Git
        hooks, build tools, comparison scripts, or private credential helpers.
        """
        root, base = self.git_checkout("source-graph")
        env = {"PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_AUTHOR_NAME": "Fixture", "GIT_COMMITTER_NAME": "Fixture",
               "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}

        def git(*arguments):
            return subprocess.check_output(["git", "-C", str(root), *arguments], env=env).decode().strip()

        def create(message, contents, *parents):
            (root / "tracked.txt").write_text(contents)
            git("add", "tracked.txt")
            tree = git("write-tree")
            arguments = ["commit-tree", tree, "-m", message]
            for parent in parents:
                arguments.extend(("-p", parent["commit"]))
            return {"commit": git(*arguments), "tree": tree, "ref": "refs/heads/main"}

        candidate = create("Reviewed candidate", "candidate bytes\n", base)
        descendant = create("Authorized descendant", "later reviewed metadata\n", candidate)
        rebased = create("Protected equal-tree rebase", "candidate bytes\n", base)
        divergent = create("Different sibling tree", "unreviewed different tree\n", base)
        unrelated = create("Copied tree without common history", "candidate bytes\n")
        same_tree_child = create("Same-tree related child", "candidate bytes\n", candidate)
        sources = (candidate, descendant, rebased, divergent, unrelated, same_tree_child)
        for source in (base, *sources):
            self.api.trees[source["commit"]] = source["tree"]
        for left, right in ((candidate, source) for source in sources if source != candidate):
            result = subprocess.run(["git", "-C", str(root), "merge-base", left["commit"], right["commit"]], env=env, capture_output=True, text=True)
            pair = left["commit"], right["commit"]
            if result.returncode == 1:
                self.api.comparisons[pair] = None
                continue
            self.assertEqual(result.returncode, 0, result.stderr)
            behind, ahead = map(int, git("rev-list", "--left-right", "--count", "...".join(pair)).split())
            self.api.comparisons[pair] = {"base_commit": {"sha": pair[0]}, "merge_base_commit": {"sha": result.stdout.strip()}, "status": "diverged" if behind and ahead else "ahead" if ahead else "behind", "ahead_by": ahead, "behind_by": behind}
        return candidate, descendant, rebased, divergent, unrelated, same_tree_child

    def test_production_source_preserves_real_ancestry_or_common_exact_tree_policy(self):
        candidate, descendant, rebased, divergent, unrelated, same_tree_child = self.source_graph()
        client = self.api.client(context("production-submit"))
        for source in (candidate, descendant, rebased, same_tree_child):
            with self.subTest(accepted=source["commit"]):
                client.source_policy("production-submit", candidate, source)
        for source in (divergent, unrelated):
            with self.subTest(rejected=source["commit"]), self.assertRaises(ValidationError):
                client.source_policy("production-submit", candidate, source)
        self.assertEqual(candidate["tree"], unrelated["tree"])
        comparisons = [command[-1] for command in self.api.requests if "/compare/" in command[-1]]
        self.assertTrue(comparisons)
        for endpoint in comparisons:
            self.assertRegex(endpoint, r"/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}$")
        self.assert_read_only()

    def test_external_source_requires_exact_commit_even_with_equal_related_tree(self):
        candidate, descendant, rebased, _, unrelated, _ = self.source_graph()
        client = self.api.client(context("external-testing"))
        client.source_policy("external-testing", candidate, candidate)
        for source in (descendant, rebased, unrelated):
            with self.subTest(source=source["commit"]), self.assertRaisesRegex(ValidationError, "exact original"):
                client.source_policy("external-testing", candidate, source)
        self.assertFalse(any("/compare/" in command[-1] for command in self.api.requests))

    def test_source_policy_refuses_false_tree_missing_mergebase_and_inconsistent_compare(self):
        candidate, descendant, _, _, _, _ = self.source_graph()
        selected = context("production-submit")
        with self.assertRaisesRegex(ValidationError, "tree differs"):
            self.api.client(selected).source_policy("production-submit", candidate, dict(descendant, tree=candidate["tree"]))
        pair = candidate["commit"], descendant["commit"]
        original = copy.deepcopy(self.api.comparisons[pair])
        mutations = {
            "missing-common": lambda response: response.update(merge_base_commit=None),
            "different-base": lambda response: response["base_commit"].update(sha="a" * 40),
            "fake-status": lambda response: response.update(status="identical"),
            "negative-count": lambda response: response.update(ahead_by=-1),
            "bool-count": lambda response: response.update(ahead_by=True),
            "counter-conflict": lambda response: response.update(behind_by=1),
        }
        for name, mutate in mutations.items():
            self.api.comparisons[pair] = copy.deepcopy(original)
            mutate(self.api.comparisons[pair])
            with self.subTest(name=name), self.assertRaises(ValidationError):
                self.api.client(selected).source_policy("production-submit", candidate, descendant)

    def test_new_external_dispatch_cannot_promote_changed_source_but_recovery_uses_original(self):
        lifecycle = self.lifecycle()
        lifecycle.create("candidate")
        candidate_run = lifecycle.contexts["candidate"].authority["runId"]
        selected = context("external-testing", run_id="2100000000", head="4" * 40)
        with self.assertRaisesRegex(ValidationError, "exact original"):
            self.resolve(selected, name="changed-external-source", candidate_run_id=candidate_run)
        old, _, intent = lifecycle.prepare("external-testing")
        self.api.register(old, conclusion="cancelled")
        result = self.resolve(selected, name="original-external-source", recovery_run_id=old.authority["runId"])
        self.assertEqual(result["mode"], "resume")
        self.assertEqual(result["source"], intent["operationSource"])
        self.assertNotEqual(result["source"]["commit"], result["dispatch"]["headSha"])

    def test_stage_checks_real_checkout_context_paths_and_inventory_before_writing(self):
        app, source = self.git_checkout()
        current = context(key="android_resolve", head=source["commit"])
        self.api.trees[source["commit"]] = source["tree"]
        self.resolve(current)
        stage_resolution(self.root / "resolution", app, current)
        self.assertTrue((app / ".mobile-release" / "operation").is_dir())
        with self.assertRaisesRegex(ValidationError, "empty"):
            stage_resolution(self.root / "resolution", app, current)
        with self.assertRaisesRegex(ValidationError, "another workflow"):
            stage_resolution(self.root / "resolution", app, context(key="ios_resolve", head=source["commit"]))
        other, _ = self.git_checkout("other")
        changed = dict(source, tree="f" * 40)
        with self.assertRaisesRegex(ValidationError, "HEAD/tree"):
            _verify_checkout(other, changed)

    def test_stage_rejects_symlink_parent_changed_payload_and_nonprivate_resolution(self):
        selected = context(key="android_resolve")
        self.resolve(selected)
        resolution = self.root / "resolution"
        (resolution / "unexpected.json").write_text("{}")
        with self.assertRaisesRegex(ValidationError, "changed"):
            stage_resolution(resolution, self.root / "app", selected)
        (resolution / "unexpected.json").unlink()
        resolution.chmod(0o755)
        with self.assertRaisesRegex(ValidationError, "private"):
            stage_resolution(resolution, self.root / "app", selected)
        resolution.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(resolution, target_is_directory=True)
        with self.assertRaisesRegex(ValidationError, "symbolic"):
            stage_resolution(alias, self.root / "app", selected)

    def test_output_values_are_single_line_and_retain_per_platform_original_refs(self):
        output = self.root / "github-output"
        output.touch()
        result = {"mode": "complete", "source": {"commit": "2" * 40, "tree": "3" * 40, "ref": "refs/heads/main"}, "authorizationRunId": "1000000000", "evidenceRunId": "2000000000", "evidenceArtifactId": "3333"}
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), patch("sys.stdout", new=io.StringIO()):
            _outputs(result)
        self.assertIn("evidence_run_id=2000000000\n", output.read_text())
        result["source"]["ref"] = "refs/heads/main\nmode=prepare"
        with self.assertRaises(ValidationError):
            _outputs(result)

    def test_main_does_not_print_untrusted_json_exception_key_or_secret(self):
        selected = context(key="android_resolve")
        env = workflow_environment()
        env.update(GITHUB_JOB=selected.current_job, MOBILE_RELEASE_CONFIRMATION="candidate:android:1.2.3:42", MOBILE_RELEASE_SELECTED_PLATFORM="android")
        stream = io.StringIO()
        with patch.dict(os.environ, env), patch.object(Transport, "run", return_value=b'{"PRIVATE_ghp_example_secret":1,"PRIVATE_ghp_example_secret":2}') as transport, patch("sys.stderr", stream):
            self.assertEqual(main(["resolve", "--stage", "candidate", "--platform", "android", "--destination", str(self.root / "bad")]), 2)
            transport.assert_called_once()
        self.assertIn("release evidence failed strict validation", stream.getvalue())
        self.assertNotIn("PRIVATE_ghp_example_secret", stream.getvalue())
        self.assertNotIn("Traceback", stream.getvalue())

    def test_transport_scrubs_store_authority_limits_bytes_and_hides_stderr(self):
        gh = self.root / "gh"
        gh.write_text(f"#!{sys.executable}\nimport os,sys\nassert 'MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64' not in os.environ\nassert 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' not in os.environ\nassert 'GOOGLE_APPLICATION_CREDENTIALS' not in os.environ\nsys.stderr.write('bearer-like-secret-url')\nsys.stdout.write('x'*4096)\n")
        gh.chmod(0o700)
        env = {"PATH": str(self.root) + os.pathsep + os.environ["PATH"], "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": "secret", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc", "GOOGLE_APPLICATION_CREDENTIALS": "adc"}
        with patch.dict(os.environ, env), self.assertRaisesRegex(ValidationError, "size limit") as raised:
            Transport().run(["gh", "api", "--method", "GET", "fixed"], maximum=128)
        self.assertNotIn("bearer-like", str(raised.exception))

    def test_transport_times_out_and_terminates_child_without_exposing_error(self):
        gh = self.root / "gh"
        gh.write_text(f"#!{sys.executable}\nimport time,sys\nsys.stderr.write('secret')\ntime.sleep(60)\n")
        gh.chmod(0o700)
        with patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]}), self.assertRaisesRegex(ValidationError, "timed out"):
            Transport().run(["gh", "api", "--method", "GET", "fixed"], timeout=1)

    def test_transport_timeout_kills_descendant_pipes_even_after_gh_root_exits(self):
        from workflow.process_fixture import run_case

        result = run_case(self.root, "timeout")
        self.assertEqual(result["result"], "timeout")
        self.assertGreater(result["selectorWaitsAfterLeaderExit"], 0)
        self.assertTrue(result["deadBeforeFallback"])

    def test_transport_descendant_timeout_is_independent_of_fixture_startup(self):
        from workflow.process_fixture import run_case

        # Delay longer than the unchanged one-second Transport test deadline.
        # The test clock advances only after a real orphaned-pipe selector wait.
        result = run_case(self.root, "timeout", delay=1.2)
        self.assertGreaterEqual(result["realSeconds"], 1.2)
        self.assertEqual(result["result"], "timeout")
        self.assertGreater(result["selectorWaitsAfterLeaderExit"], 0)

    def test_transport_fixture_startup_failure_cleans_up_before_own_pid_marker(self):
        from workflow.process_fixture import run_case

        result = run_case(self.root, "unready")
        self.assertEqual(result["result"], "readiness-failure")
        self.assertTrue((self.root / "launcher.pid").is_file())
        self.assertFalse((self.root / "gh.pid").exists())
        self.assertFalse((self.root / "child.pid").exists())
        self.assertTrue(result["deadBeforeFallback"])

    def test_transport_sigterm_cleans_detached_process_tree_and_reraises_cancellation(self):
        from workflow.process_fixture import run_case

        result = run_case(self.root, "cancel")
        self.assertEqual(result["result"], "cancelled")
        self.assertTrue(result["ready"] and result["deadBeforeFallback"])

    def test_transport_cancellation_during_popen_cannot_lose_child_handle(self):
        from workflow.process_fixture import run_case

        result = run_case(self.root, "popen-cancel")
        self.assertEqual(result["result"], "cancelled")
        self.assertTrue(result["ready"] and result["deadBeforeFallback"])

    def test_transport_fixture_does_not_relax_gh_only_public_boundary(self):
        with patch("mobile_release.workflow.subprocess.Popen") as spawn:
            with self.assertRaisesRegex(ValidationError, "only permits the GitHub CLI"):
                Transport().run([sys.executable, "-c", "print('not gh')"])
        spawn.assert_not_called()

    def test_transport_restores_default_handlers_and_respects_custom_handlers_and_threads(self):
        gh = self.root / "gh"
        gh.write_text(f"#!{sys.executable}\nprint('verified')\n")
        gh.chmod(0o700)
        env = {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]}
        before = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        with patch.dict(os.environ, env):
            self.assertEqual(Transport().run(["gh", "api"]), b"verified\n")
            self.assertEqual({signum: signal.getsignal(signum) for signum in before}, before)
            def custom(signum, frame):
                raise AssertionError("unexpected external signal")
            signal.signal(signal.SIGTERM, custom)
            self.addCleanup(signal.signal, signal.SIGTERM, before[signal.SIGTERM])
            real_spawn = subprocess.Popen
            def spawn(*arguments, **options):
                self.assertIs(signal.getsignal(signal.SIGTERM), custom)
                return real_spawn(*arguments, **options)
            with patch("mobile_release.workflow.subprocess.Popen", side_effect=spawn):
                self.assertEqual(Transport().run(["gh", "api"]), b"verified\n")
            self.assertIs(signal.getsignal(signal.SIGTERM), custom)
            results = []
            def worker():
                try:
                    results.append(Transport().run(["gh", "api"]))
                except BaseException as error:
                    results.append(error)
            thread = threading.Thread(target=worker)
            with patch("mobile_release.workflow.signal.signal", side_effect=AssertionError("worker must not change process signal handlers")):
                thread.start()
                thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(results, [b"verified\n"])

    def test_transport_partial_output_is_not_silently_replaced_on_failure_or_retry(self):
        gh = self.root / "gh"
        gh.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write('partial payload')\nsys.exit(1)\n")
        gh.chmod(0o700)
        destination = self.root / "immutable-download"
        with patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]}):
            with self.assertRaises(ValidationError):
                Transport().run(["gh", "api"], output=destination)
            self.assertEqual(destination.read_bytes(), b"partial payload")
            with self.assertRaises(ValidationError):
                Transport().run(["gh", "api"], output=destination)
            self.assertEqual(destination.read_bytes(), b"partial payload")

    def test_recovery_helper_import_and_help_work_outside_repository_without_dependencies(self):
        source = Path(__file__).resolve().parents[2] / "src"
        # Wheel integration is run by CI/root; this separately proves the module
        # needs neither repository cwd nor installed Ruby/Store libraries.
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": str(source), "PYTHONSAFEPATH": "1"}
        result = subprocess.run([sys.executable, "-P", "-m", "mobile_release.workflow", "--help"], cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("package-final", result.stdout)


if __name__ == "__main__":
    unittest.main()
