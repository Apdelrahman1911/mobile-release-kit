"""Inert release policy, frame and finite transport contracts only.

No native path, journal, process, tool, HTTP/TLS/socket or Store operation is
admitted. Readers and original-helper IO use supplied DATA doubles; these tests
cannot qualify a native runtime, GitHub permissions or successful releases.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import github_preflight as preflight
from mobile_release import github_release as policy
from mobile_release import _desktop_github_preflight_engine as engine
from mobile_release import _github_connection_transport as transport
from mobile_release import _github_preflight_journal as journal
from mobile_release._github_action_family import Family, journal_suffix, policy_for

TIME = "2026-09-26T18:00:00Z"
SOURCE = "a" * 40
TREE = "e" * 40
ORIGINAL = "f" * 40
RUN = "18446744073709551615"
SENTINEL = "INERT_NOT_A_CREDENTIAL"
APPLE_INTENT = "1a" * 32
APPLE_ADOPTION = "recover-ios-candidate:" + APPLE_INTENT + ":Build_7.-"
APPLE_UPLOAD = "retry-ios-candidate-upload:" + APPLE_INTENT + ":" + "2b" * 32
APPLE_CREATES = "retry-ios-operation-creates:" + APPLE_INTENT + ":" + "3c" * 32
APPLE_MAX_ADOPTION = "recover-ios-candidate:" + APPLE_INTENT + ":" + "B" * 255


def configuration(source="release/version.properties"):
    return {"schemaVersion": 1,
        "version": {"source": source, "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified",
                    "externalTrack": {"name": "beta", "kind": "closed"}},
        "ios": {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified",
                "externalTestFlightGroup": "External fixtures", "review": {"usesNonExemptEncryption": False, "demoAccountRequired": True}},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [["./must-not-run"]], "androidArtifact": [], "iosArtifact": []}}


def target(stage="candidate", platform="android", recovery=False):
    original = stage != "candidate" or recovery
    return policy.Target.parse({"projectBinding": "b" * 64, "repository": "owner/app", "accountId": "11", "repositoryId": "22",
        "branch": "production" if stage == "production-submit" else "main", "toolingRepository": policy.TOOLING_REPOSITORY,
        "toolingSha": "c" * 40, "platform": platform, "marker": "d" * 32,
        "selection": {"stage": stage, "candidateRunId": "101" if stage != "candidate" and not recovery else None,
            "externalRunId": "102" if stage == "production-submit" and not recovery else None,
            "recoveryRunId": "103" if recovery else None, "originalSourceSha": ORIGINAL if original else None,
            "originalVersion": {"name": "1.2.3", "build": 42} if original else None}})


def apple_target(stage="candidate", grant=APPLE_ADOPTION):
    value = target(stage, "ios", True).value()
    value["selection"]["recoveryConfirmation"] = grant
    return policy.Target.parse(value)


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()


def contents(path, raw):
    return {"type": "file", "path": path, "encoding": "base64", "size": len(raw), "sha": blob(raw),
            "content": base64.b64encode(raw).decode()}


def repository():
    return {"id": 22, "full_name": "owner/app", "default_branch": "main", "visibility": "private",
            "archived": False, "permissions": {"pull": True}, "ignored": SENTINEL}


def bodies(selected=None, config=None):
    selected = selected or target()
    config = configuration() if config is None else config
    files = {selected.workflow_path: policy.canonical_caller(selected), policy.CONFIG_PATH: policy._canonical(config),
             config["version"]["source"]: b"VERSION_NAME=2.0.0\nBUILD_NUMBER=99\n"}
    directories = set()
    for path in files:
        parts = path.split("/")
        directories.update("/".join(parts[:n]) for n in range(1, len(parts)))
    rows = [{"path": path, "mode": "040000", "type": "tree", "sha": "0" * 40,
             "url": "https://api.github.com/repos/owner/app/git/trees/" + "0" * 40} for path in sorted(directories)]
    rows += [{"path": path, "mode": "100644", "type": "blob", "sha": blob(raw), "size": len(raw),
              "url": "https://api.github.com/repos/owner/app/git/blobs/" + blob(raw)} for path, raw in files.items()]
    branch = {"name": selected.branch, "commit": {"sha": SOURCE, "commit": {"tree": {
        "sha": TREE, "url": "https://api.github.com/repos/owner/app/git/trees/" + TREE}}}}
    run = {"id": int(RUN), "run_attempt": 1, "workflow_id": 33, "path": selected.workflow_path,
        "name": selected.workflow_name, "head_sha": SOURCE, "head_branch": selected.branch, "event": "workflow_dispatch",
        "display_title": selected.display_title, "repository": {"id": 22, "full_name": "owner/app"},
        "head_repository": {"id": 22, "full_name": "owner/app"}, "actor": {"id": 11}, "triggering_actor": {"id": 11},
        "status": "queued", "conclusion": None, "html_url": "https://github.com/owner/app/actions/runs/" + RUN}
    return {"account": {"id": 11, "login": "owner", "ignored": SENTINEL}, "repository-before": repository(),
        "repository-after": repository(), "branch-before": branch, "branch-after": copy.deepcopy(branch),
        "workflow": {"id": 33, "path": selected.workflow_path, "state": "active", "name": selected.workflow_name},
        "caller": contents(selected.workflow_path, files[selected.workflow_path]),
        "config": contents(policy.CONFIG_PATH, files[policy.CONFIG_PATH]),
        "source-tree": {"sha": TREE, "url": "https://api.github.com/repos/owner/app/git/trees/" + TREE, "truncated": False, "tree": rows},
        "version": contents(config["version"]["source"], files[config["version"]["source"]]),
        "dispatch": {"workflow_run_id": int(RUN), "run_url": "https://api.github.com/repos/owner/app/actions/runs/" + RUN,
                     "html_url": "https://github.com/owner/app/actions/runs/" + RUN},
        "attempt": run, "runs": {"total_count": 1, "workflow_runs": [run]}, "jobs": {"total_count": 0, "jobs": []}}


class Reader:
    def __init__(self, action, values):
        self.schedule, self.values, self.calls = policy.Schedule(action), values, []

    def read(self, step, reference=None):
        self.calls.append(self.schedule.claim(step, reference))
        value = self.values[step]
        if isinstance(value, Exception):
            raise value
        return value if isinstance(value, transport.ReadResult) else transport.ReadResult(
            {"status": 200, "body": value, "failure": "none"}, transport._control())


def execute(kind="prepare", selected=None, values=None):
    selected = selected or target()
    prior = None if kind == "prepare" else prepared(selected)
    action = policy.Action.parse({"kind": kind, "target": selected.value(), "prepared": None if prior is None else prior.value(),
                                  "runId": RUN if kind == "track" else None})
    reader = Reader(action, bodies(selected) if values is None else values)
    result = policy.execute(action, reader, observed_at=TIME)
    assert SENTINEL not in json.dumps(result)
    return result, reader


def prepared(selected=None):
    result, _ = execute(selected=selected)
    if result["reason"] != "none":
        raise AssertionError("Inert fixture prepare failed: " + result["reason"])
    return policy.Prepared.parse(result["prepared"])


def frame(value):
    return journal.canonical(value) + b"\n"


def initial(kind="dispatch", selected=None):
    selected = selected or target()
    return {"protocol": policy.PROTOCOL, "id": "github-release-1",
        "action": policy.Action(kind, selected, None if kind == "prepare" else prepared(selected), RUN if kind == "track" else None).value(),
        "pendingScope": None, "home": None if kind == "prepare" else "/home/mrk"}


def wire(raw, framing):
    if framing == "length":
        return b"HTTP/1.1 200 Inert\r\nContent-Type: application/json\r\nContent-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw
    if framing == "chunked":
        return b"HTTP/1.1 200 Inert\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" + format(len(raw), "x").encode() + b"\r\n" + raw + b"\r\n0\r\n\r\n"
    return b"HTTP/1.0 200 Inert\r\nContent-Type: application/json\r\n\r\n" + raw


def response(raw, framing="length", role=transport._ResponseRole.STANDARD, profile=transport._ExchangeProfile.STANDARD, budget=None):
    budget = budget or transport._Budget(100.0, monotonic=lambda: 100.0, _profile=profile)
    body = transport._ResponseBody(io.BytesIO(wire(raw, framing)), budget, _role=role)
    return transport._response_result(body, budget)


class GitHubReleasePolicyTests(unittest.TestCase):
    def test_all_six_stage_platform_reviews_use_ten_reads_and_real_root_tree(self):
        for stage in ("candidate", "external-testing", "production-submit"):
            for platform in ("android", "ios"):
                with self.subTest(stage=stage, platform=platform):
                    selected = target(stage, platform)
                    result, reader = execute(selected=selected)
                    self.assertEqual(result["reason"], "none")
                    review = policy.Prepared.parse(result["prepared"])
                    self.assertEqual(len(reader.calls), 10)
                    self.assertEqual({call.method for call in reader.calls}, {"GET"})
                    self.assertEqual(reader.calls[2].path, "/repos/owner/app/branches/" + selected.branch)
                    self.assertEqual(reader.calls[6].path, "/repos/owner/app/git/trees/" + TREE + "?recursive=1")
                    self.assertNotEqual(TREE, SOURCE)
                    self.assertEqual(review.source_tree, TREE)
                    self.assertEqual(review.current_version.name, "2.0.0")
                    self.assertEqual(review.confirmation, f"{stage}:{platform}:" + ("2.0.0:99" if stage == "candidate" else "1.2.3:42"))
                    self.assertEqual(review.value()["originalAssurance"], policy.ORIGINAL_ASSURANCE)
                    self.assertEqual(review.destination["assurance"], "current-dispatch-config-not-authenticated-original-destination")
                    self.assertLessEqual(len(policy._canonical(review.value())), policy.MAX_PREPARED_BYTES)

    def test_selection_is_closed_original_data_never_current_version_substitution(self):
        for stage in ("candidate", "external-testing", "production-submit"):
            selected = target(stage, recovery=True)
            self.assertEqual(prepared(selected).confirmation, stage + ":android:1.2.3:42")
            body = json.loads(policy.dispatch_body(prepared(selected)))
            self.assertEqual(body["inputs"]["recovery_run_id"], "103")
            self.assertEqual(body["inputs"]["recovery_confirmation"], "")
            self.assertNotIn("original_source_sha", body["inputs"])
        for change in ({"originalVersion": None}, {"originalSourceSha": None}, {"candidateRunId": None},
                       {"externalRunId": None}, {"originalVersion": {"name": "1.0", "build": True}},
                       {"candidateRunId": "latest"}, {"recovery_confirmation": "invented"}):
            raw = target("production-submit").value()
            raw["selection"].update(change)
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                policy.Target.parse(raw)
        raw = target().value(); raw["platform"] = "both"
        with self.assertRaises(ValueError): policy.Target.parse(raw)

    def test_apple_recovery_confirmation_exact_forms_and_applicability(self):
        valid = (("candidate", APPLE_ADOPTION), ("candidate", APPLE_UPLOAD),
                 ("external-testing", APPLE_CREATES), ("production-submit", APPLE_CREATES),
                 ("candidate", "recover-ios-candidate:" + APPLE_INTENT + ":B"),
                 ("candidate", APPLE_MAX_ADOPTION))
        self.assertEqual((len(APPLE_MAX_ADOPTION), len(APPLE_UPLOAD), len(APPLE_CREATES)), (342, 156, 157))
        for stage, grant in valid:
            with self.subTest(stage=stage, grant=grant):
                selected = apple_target(stage, grant)
                self.assertEqual(selected.selection.recovery_confirmation, grant)
                self.assertEqual(policy.Target.parse(selected.value()), selected)
                self.assertEqual(set(selected.selection.value()), {"stage", "candidateRunId", "externalRunId",
                    "recoveryRunId", "originalSourceSha", "originalVersion", "recoveryConfirmation"})
                # Producer identity remains a declaration; it is not parsed from the token.
                another_producer = selected.value(); another_producer["selection"]["recoveryRunId"] = "9001"
                self.assertEqual(policy.Target.parse(another_producer).selection.recovery_run_id, "9001")
                for platform, recovery in (("android", True), ("ios", False)):
                    wrong = target(stage, platform, recovery).value()
                    wrong["selection"]["recoveryConfirmation"] = grant
                    with self.assertRaises((ValueError, TypeError)): policy.Target.parse(wrong)
                for key, value in (("recoveryRunId", "latest"), ("recoveryRunId", None), ("force", True),
                                   ("recovery_confirmation", grant)):
                    wrong = selected.value(); wrong["selection"][key] = value
                    with self.assertRaises((ValueError, TypeError)): policy.Target.parse(wrong)
        for stage in ("candidate", "external-testing", "production-submit"):
            for grant in (APPLE_ADOPTION, APPLE_UPLOAD, APPLE_CREATES):
                allowed = (stage == "candidate") == (grant != APPLE_CREATES)
                if allowed:
                    self.assertEqual(apple_target(stage, grant).selection.recovery_confirmation, grant)
                else:
                    with self.assertRaises(ValueError): apple_target(stage, grant)
        malformed = [None, "", 0, True, [], {}, " " + APPLE_ADOPTION, APPLE_ADOPTION + " ",
            APPLE_ADOPTION + "\n", APPLE_ADOPTION + "\r\n", APPLE_ADOPTION + "\t", APPLE_ADOPTION + "\0",
            APPLE_ADOPTION + "\u00a0", APPLE_ADOPTION + "\u2028", APPLE_ADOPTION + "\u200b",
            APPLE_ADOPTION.replace(APPLE_INTENT, APPLE_INTENT.upper()),
            APPLE_ADOPTION.replace("recover-ios", "Recover-ios"), APPLE_ADOPTION.replace(":", ":\n", 1),
            "recover-ios-candidate:" + APPLE_INTENT[:-1] + ":B",
            "recover-ios-candidate:" + APPLE_INTENT + "0:B", "recover-ios-candidate:" + APPLE_INTENT + ":",
            APPLE_MAX_ADOPTION + "B", APPLE_UPLOAD[:-1], APPLE_UPLOAD + "0",
            APPLE_UPLOAD.replace("2b", "2B")]
        malformed += ["recover-ios-candidate:" + APPLE_INTENT + ":" + detail for detail in ("B/7", "B+7", "B:7", "B\\7", "é")]
        for grant in malformed:
            with self.subTest(malformed=grant), self.assertRaises((ValueError, TypeError)):
                apple_target(grant=grant)
        for grant in (APPLE_CREATES[:-1], APPLE_CREATES + "0", APPLE_CREATES + "\n", APPLE_CREATES.replace("3c", "3C")):
            with self.subTest(malformed=grant), self.assertRaises(ValueError):
                apple_target("external-testing", grant)

    def test_apple_recovery_dispatch_uses_captured_text_and_unchanged_schedules(self):
        for stage, grant in (("candidate", APPLE_ADOPTION), ("candidate", APPLE_UPLOAD),
                             ("external-testing", APPLE_CREATES), ("production-submit", APPLE_CREATES)):
            with self.subTest(stage=stage, grant=grant):
                draft = apple_target(stage, grant).value()
                selected = policy.Target.parse(draft)
                result, prepare_reader = execute(selected=selected)
                captured = policy.Prepared.parse(result["prepared"])
                self.assertEqual([row.method for row in prepare_reader.calls], ["GET"] * 10)
                replacement = APPLE_UPLOAD if grant == APPLE_ADOPTION else APPLE_ADOPTION if stage == "candidate" else APPLE_CREATES.replace("3c", "4d")
                draft["selection"]["recoveryConfirmation"] = replacement
                action = policy.Action.parse({"kind": "dispatch", "target": captured.target.value(), "prepared": captured.value(), "runId": None})
                reader = Reader(action, bodies(selected))
                result = policy.execute(action, reader, observed_at=TIME)
                self.assertEqual((result["effect"], result["runId"]), ("accepted", RUN))
                self.assertEqual([row.method for row in reader.calls], ["GET"] * 4 + ["POST"])
                inputs = json.loads(reader.calls[-1].body)["inputs"]
                self.assertEqual(inputs["recovery_confirmation"], grant)
                self.assertEqual(inputs["recovery_run_id"], "103")
                self.assertEqual(inputs["confirmation"], stage + ":ios:1.2.3:42")
                self.assertEqual(inputs["desktop_source_sha"], SOURCE)
                self.assertEqual(inputs["desktop_expected_ref"], "refs/heads/" + selected.branch)
                self.assertNotIn("original_source_sha", inputs)
                self.assertEqual(captured.target.selection.recovery_confirmation, grant)
                with self.assertRaises(ValueError): reader.read("dispatch")
                swapped = action.value(); swapped["target"]["selection"]["recoveryConfirmation"] = replacement
                with self.assertRaises(ValueError): policy.Action.parse(swapped)
                late = action.value(); late["recoveryConfirmation"] = replacement
                with self.assertRaises(ValueError): policy.Action.parse(late)
                unknown = bodies(selected); unknown["dispatch"] = transport.ReadFailure("network-unavailable")
                unknown_reader = Reader(action, unknown)
                result = policy.execute(action, unknown_reader, observed_at=TIME)
                self.assertEqual((result["effect"], result["reason"]), ("potentially-applied", "network-unavailable"))
                self.assertEqual([row.method for row in unknown_reader.calls], ["GET"] * 4 + ["POST"])
                self.assertEqual(unknown_reader.calls[-1].body, reader.calls[-1].body)
                with self.assertRaises(ValueError): unknown_reader.read("dispatch")
                for kind, reads in (("track", 5), ("reconcile", 6)):
                    result, observer = execute(kind, selected)
                    self.assertEqual(result["reason"], "none")
                    self.assertEqual([row.method for row in observer.calls], ["GET"] * reads)
                    self.assertEqual(observer.schedule.action.prepared.target.selection.recovery_confirmation, grant)

    def test_selected_symlink_submodule_ancestor_and_incomplete_tree_refuse_before_version(self):
        for selected_path in (policy.CONFIG_PATH, target().workflow_path, "release/version.properties", "release"):
            for mode, kind in (("120000", "blob"), ("160000", "commit")):
                values = bodies(); row = next(row for row in values["source-tree"]["tree"] if row["path"] == selected_path)
                row.update(mode=mode, type=kind, sha="0" * 40)
                row["url"] = "https://api.github.com/repos/owner/app/git/" + ("blobs/" if kind == "blob" else "commits/") + "0" * 40
                if kind == "blob": row["size"] = 10
                else: row.pop("size", None)
                result, reader = execute(values=values)
                self.assertEqual(result["reason"], "source-tree-unavailable")
                self.assertNotIn("version", reader.schedule.steps)
        for change in ({"truncated": True}, {"truncated": 0}, {"sha": SOURCE}, {"tree": []},
                       {"tree": bodies()["source-tree"]["tree"] * 200}):
            values = bodies(); values["source-tree"].update(change)
            result, reader = execute(values=values)
            self.assertEqual(result["reason"], "source-tree-unavailable")
            self.assertNotIn("version", reader.schedule.steps)
        values = bodies(); values["source-tree"]["tree"].append({"path": "unrelated-link", "mode": "120000", "type": "blob", "sha": "0" * 40,
            "size": 10, "url": "https://api.github.com/repos/owner/app/git/blobs/" + "0" * 40})
        self.assertEqual(execute(values=values)[0]["reason"], "none")

    def test_blob_content_branch_and_identity_drift_never_create_a_review(self):
        cases = [("branch-after", lambda value: value["commit"].update(sha=ORIGINAL), "source-changed"),
                 ("repository-after", lambda value: value.update(id=23), "target-changed"),
                 ("version", lambda value: value.update(sha="0" * 40), "version-invalid"),
                 ("caller", lambda value: value.update(type="symlink"), "caller-mismatch"),
                 ("config", lambda value: value.update(submodule_git_url="https://not-used.invalid"), "config-invalid"),
                 ("source-tree", lambda value: next(row for row in value["tree"] if row["path"] == policy.CONFIG_PATH).update(size=1), "source-tree-unavailable")]
        for step, change, expected in cases:
            values = bodies(); change(values[step]); result, reader = execute(values=values)
            self.assertEqual(result["reason"], expected); self.assertIsNone(result["prepared"])
            self.assertTrue(all(row.method == "GET" for row in reader.calls))
        cfg = configuration(); cfg["source"]["candidateBranch"] = "different"
        self.assertEqual(execute(values=bodies(config=cfg))[0]["reason"], "branch-mismatch")
        cfg = configuration(); cfg["android"] = {"enabled": False}
        self.assertEqual(execute(values=bodies(config=cfg))[0]["reason"], "platform-disabled")

    def test_long_utf8_selected_version_path_and_config_decoded_ceiling(self):
        source = "release/" + ("é" * 110) + "/" + ("é" * 100) + ".properties"
        result, reader = execute(values=bodies(config=configuration(source)))
        self.assertEqual(result["reason"], "none")
        path = reader.calls[7].path
        self.assertGreater(len(path), 1024); self.assertLessEqual(len(path), 2048)
        self.assertIn("%C3%A9", path)
        self.assertEqual(transport._request_limits(transport._ExchangeProfile.RELEASE_PREPARE, transport._ResponseRole.RELEASE_VERSION, "GET", path), (256 * 1024, 2048))
        values = bodies(); values["config"] = contents(policy.CONFIG_PATH, b" " * (policy.MAX_CONFIG_BYTES + 1))
        self.assertEqual(execute(values=values)[0]["reason"], "config-invalid")
        raw = policy._canonical(configuration())
        raw += b" " * (policy.MAX_CONFIG_BYTES - len(raw))
        values = bodies(); values["config"] = contents(policy.CONFIG_PATH, raw)
        row = next(row for row in values["source-tree"]["tree"] if row["path"] == policy.CONFIG_PATH)
        row.update(sha=blob(raw), size=len(raw), url="https://api.github.com/repos/owner/app/git/blobs/" + blob(raw))
        self.assertEqual(execute(values=values)[0]["reason"], "none")

    def test_single_dispatch_latches_uncertainty_and_refuses_replacement_source(self):
        for stage in ("candidate", "external-testing", "production-submit"):
            selected = target(stage); result, reader = execute("dispatch", selected)
            self.assertEqual([row.method for row in reader.calls], ["GET"] * 4 + ["POST"])
            self.assertEqual((result["effect"], result["runId"], result["run"]), ("accepted", RUN, None))
            body = json.loads(reader.calls[-1].body)
            self.assertEqual(body["inputs"]["desktop_source_sha"], SOURCE)
            self.assertEqual(body["inputs"]["desktop_expected_ref"], "refs/heads/" + selected.branch)
            with self.assertRaises(ValueError): reader.read("dispatch")
        values = bodies(); values["dispatch"] = transport.ReadFailure("network-unavailable")
        result, reader = execute("dispatch", values=values)
        self.assertEqual((result["effect"], result["reason"]), ("potentially-applied", "network-unavailable"))
        self.assertEqual(sum(row.method == "POST" for row in reader.calls), 1)
        values = bodies(); values["branch-before"]["commit"]["commit"]["tree"]["sha"] = SOURCE
        result, reader = execute("dispatch", values=values)
        self.assertEqual(result["effect"], "not-sent"); self.assertNotIn("dispatch", reader.schedule.steps)

    def test_original_attempt_observation_requires_stage_jobs_not_build_repetition(self):
        for stage in ("candidate", "external-testing", "production-submit"):
            selected = target(stage); values = bodies(selected); values["attempt"].update(status="completed", conclusion="success")
            required = ["validate-platform", "android_resolve", "android_store"] if stage == "candidate" else ["validate-platform", "android"]
            values["jobs"] = {"total_count": len(required), "jobs": [{"id": 100 + i, "name": stage + " / " + name, "run_id": int(RUN),
                "run_attempt": 1, "head_sha": SOURCE, "status": "completed", "conclusion": "success"} for i, name in enumerate(required)]}
            result, reader = execute("track", selected, values)
            self.assertEqual(result["reason"], "none"); self.assertEqual(result["run"]["assurance"], policy.ASSURANCE)
            self.assertIn("/attempts/1", reader.calls[2].path)
            values["jobs"]["jobs"][-1]["conclusion"] = "skipped"
            self.assertEqual(execute("track", selected, values)[0]["reason"], "jobs-incomplete")
        values = bodies(); values["attempt"]["run_attempt"] = 2
        self.assertEqual(execute("track", values=values)[0]["reason"], "run-changed")
        values = bodies(); values["runs"]["workflow_runs"].append(copy.deepcopy(values["attempt"])); values["runs"]["total_count"] = 2
        self.assertEqual(execute("reconcile", values=values)[0]["reason"], "ambiguous-run")


class GitHubReleaseFrameTests(unittest.TestCase):
    def test_full64_maximum_retained_records_fit_the_private_result_without_truncation(self):
        for grant in (None, APPLE_MAX_ADOPTION):
            value = prepared(target(recovery=True) if grant is None else apple_target(grant=grant)).value()
            selected = value["target"]
            selected.update(repository="a" * 39 + "/" + "b" * 100, branch="b" * 200, accountId=RUN, repositoryId=RUN)
            version = {"name": "1.0+" + "v" * 60 if grant is None else "1.2.3", "build": 2_100_000_000}
            selected["selection"].update(recoveryRunId=RUN, originalVersion=version)
            value.update(workflowId=RUN, currentVersion=version, expectedRef="refs/heads/" + selected["branch"],
                         confirmation="candidate:" + selected["platform"] + ":" + version["name"] + ":2100000000",
                         versionSource="a" * 248 + "/" + "é" * 124 + "/" + "v" * 14)
            value["destination"].update(applicationId='"\\é' * 40, destination='"\\é' * 40)
            value["checklist"] = []
            size = lambda: len(policy._canonical(value))
            for i in range(16):
                value["checklist"].append({"name": f"MOBILE_RELEASE_FIXTURE_{i}", "kind": "secret", "reason": "r" * 192})
                if size() > policy.MAX_PREPARED_BYTES:
                    value["checklist"].pop()
                    break
            for field, maximum in (("destination", 256), ("applicationId", 255)):
                while size() < policy.MAX_PREPARED_BYTES and len(value["destination"][field].encode()) < maximum:
                    value["destination"][field] += "x"
            while size() < policy.MAX_PREPARED_BYTES:
                self.assertLess(len(value["checklist"][-1]["name"]) - len("MOBILE_RELEASE_"), 96)
                value["checklist"][-1]["name"] += "X"
            self.assertEqual(size(), 3900)
            policy.Prepared.parse(value)
            rows = []
            for i in range(64):
                row = copy.deepcopy(value); row["target"]["marker"] = format(i, "032x")
                row["displayTitle"] = "MRK Desktop candidate [" + row["target"]["marker"] + "]"
                # Round-trip the real immutable intent serializer/parser, without
                # opening a journal or touching any filesystem/account resource.
                prior = policy.Prepared.parse(row)
                self.assertEqual(journal.parse_intent(journal.intent_bytes(prior, family=Family.RELEASE), family=Family.RELEASE), prior)
                rows.append({"prepared": row, "runId": str(int(RUN) - i)})
            request = engine.parse_initial(frame({"protocol": policy.PROTOCOL, "id": "release-full64", "action": None,
                "pendingScope": {key: selected[key] for key in ("projectBinding", "repository", "accountId", "repositoryId")},
                "home": "/home/mrk"}), family=Family.RELEASE)
            raw = engine.encode_result(request, None, rows)
            self.assertLessEqual(len(raw), engine.MAX_RESULT_BYTES)
            self.assertEqual(json.loads(raw)["pending"], rows)
            with self.assertRaises(ValueError): engine.encode_result(request, None, rows + [rows[0]])
            retained = copy.deepcopy(rows)
            mixed = copy.deepcopy(rows); mixed[1]["prepared"]["target"]["selection"].pop("recoveryConfirmation", None)
            self.assertEqual(json.loads(engine.encode_result(request, None, mixed))["pending"], mixed)
            unsupported = copy.deepcopy(rows); unsupported[1]["prepared"]["target"]["selection"]["recoveryConfirmation"] = None
            with self.assertRaises(ValueError): engine.encode_result(request, None, unsupported)
            over = copy.deepcopy(value)
            self.assertLess(len(over["checklist"]), 16)
            over["checklist"].append({"name": "MOBILE_RELEASE_OVERFLOW", "kind": "manual", "reason": "x"})
            with self.assertRaises(ValueError): policy.Prepared.parse(over)
            self.assertEqual(rows, retained)  # Refusal does not truncate or rewrite any original record.
            value["checklist"][-1]["reason"] += "x"
            with self.assertRaises(ValueError): policy.Prepared.parse(value)

    def test_optional_apple_recovery_preserves_legacy_bytes_and_exact_new_journals(self):
        legacy_keys = {"stage", "candidateRunId", "externalRunId", "recoveryRunId", "originalSourceSha", "originalVersion"}
        for stage in ("candidate", "external-testing", "production-submit"):
            for platform in ("android", "ios"):
                for recovery in (False, True):
                    with self.subTest(stage=stage, platform=platform, recovery=recovery):
                        selected = target(stage, platform, recovery); prior = prepared(selected)
                        self.assertIsNone(selected.selection.recovery_confirmation)
                        self.assertEqual(set(selected.selection.value()), legacy_keys)
                        legacy = prior.value()
                        legacy["target"]["selection"] = {key: legacy["target"]["selection"][key] for key in legacy_keys}
                        # Independently serialize the original six-key schema/envelope, not a migration.
                        expected = json.dumps({"schemaVersion": 1, "protocol": "mrk-github-release/1", "prepared": legacy},
                            ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                        actual = journal.intent_bytes(prior, family=Family.RELEASE)
                        self.assertEqual(actual, expected)
                        self.assertEqual(journal.parse_intent(expected, family=Family.RELEASE), prior)
                        digest = hashlib.sha256(expected).hexdigest()
                        self.assertEqual(hashlib.sha256(actual).hexdigest(), digest)
                        self.assertEqual(journal.parse_run(journal.run_bytes(digest, RUN), hashlib.sha256(actual).hexdigest()), RUN)
                        inputs = {"platform": platform, "confirmation": prior.confirmation,
                            "recovery_run_id": "103" if recovery else "", "recovery_confirmation": "",
                            "desktop_request": "d" * 32, "desktop_source_sha": SOURCE, "desktop_expected_ref": "refs/heads/" + selected.branch}
                        if stage != "candidate": inputs["candidate_run_id"] = "" if recovery else "101"
                        if stage == "production-submit": inputs["external_run_id"] = "" if recovery else "102"
                        expected_body = json.dumps({"ref": selected.branch, "return_run_details": True, "inputs": inputs},
                            ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
                        self.assertEqual(policy.dispatch_body(prior), expected_body)
        for stage, grant in (("candidate", APPLE_ADOPTION), ("candidate", APPLE_UPLOAD),
                             ("external-testing", APPLE_CREATES), ("production-submit", APPLE_CREATES)):
            prior = prepared(apple_target(stage, grant))
            raw = journal.intent_bytes(prior, family=Family.RELEASE)
            restored = journal.parse_intent(raw, family=Family.RELEASE)
            self.assertEqual(restored, prior)
            self.assertEqual(restored.target.selection.recovery_confirmation, grant)
            self.assertEqual(journal.intent_bytes(restored, family=Family.RELEASE), raw)
            # A legacy closed Selection reader must refuse a new grant, not drop it.
            with self.assertRaises(ValueError): preflight._object(restored.target.selection.value(), legacy_keys)
            for change in ({"recoveryConfirmation": None}, {"recoveryConfirmation": ""}, {"recovery_confirmation": grant}):
                bad = json.loads(raw); bad["prepared"]["target"]["selection"].update(change)
                with self.assertRaises(ValueError): journal.parse_intent(frame(bad), family=Family.RELEASE)
            bad = json.loads(raw); bad["schemaVersion"] = 2
            with self.assertRaises(ValueError): journal.parse_intent(frame(bad), family=Family.RELEASE)
            with self.assertRaises(ValueError): journal.parse_intent(b" " + raw, family=Family.RELEASE)

    def test_protocol_journal_and_go_cannot_cross_preflight_family(self):
        raw = journal.intent_bytes(prepared(), family=Family.RELEASE)
        self.assertEqual(journal.parse_intent(raw, family=Family.RELEASE), prepared())
        self.assertEqual(journal_suffix(Family.RELEASE)[-1], "github-release")
        self.assertNotEqual(journal_suffix(Family.RELEASE), journal_suffix(Family.PREFLIGHT))
        with self.assertRaises(ValueError): journal.parse_intent(raw)
        with self.assertRaises(ValueError): journal.intent_bytes(prepared())
        with self.assertRaises(ValueError): policy_for("release")
        request = engine.parse_initial(frame(initial()), family=Family.RELEASE)
        with self.assertRaises(ValueError): engine.parse_initial(frame(initial()))
        ready = json.loads(engine.ready_frame(request))
        self.assertEqual(ready["protocol"], policy.PROTOCOL)
        self.assertEqual(ready["ready"]["journal"], "durable-intent")
        go = {"protocol": policy.PROTOCOL, "id": request.id, "go": {"requestSha256": request.digest, "token": SENTINEL}}
        self.assertEqual(engine.parse_go(frame(go), request), SENTINEL)
        for changed in ({**go, "protocol": preflight.PROTOCOL}, {**go, "go": {"requestSha256": "0" * 64, "token": SENTINEL}}):
            with self.assertRaises(ValueError): engine.parse_go(frame(changed), request)
        result, _ = execute("dispatch")
        self.assertEqual(json.loads(engine.encode_result(request, result))["result"]["effect"], "accepted")

    def test_original_helper_waits_for_durable_intent_and_closes_before_final(self):
        request = engine.parse_initial(frame(initial()), family=Family.RELEASE)
        sequence, frames = [], []
        values = bodies()
        class InertJournal:
            closed = False
            def __init__(self, _home, *, end, family):
                self.assertions = (end, family)
                if self.assertions != (10.0, Family.RELEASE): raise AssertionError("wrong original family/clock")
            def open(self): sequence.append("open")
            def create_intent(self, _prepared): sequence.append("intent")
            def bind_run(self, _prepared, run):
                if run != RUN: raise AssertionError("wrong original run")
                sequence.append("run")
            def close(self): sequence.append("journal-close"); self.closed = True
        def write(_fd, raw):
            frames.append(json.loads(raw)); sequence.append("ready" if "ready" in frames[-1] else "result")
        def reader(action, token, *, started, runtime_dir):
            self.assertEqual(sequence, ["open", "intent", "ready"])
            self.assertEqual(token, SENTINEL); self.assertEqual(started, 0.0)
            sequence.append("go"); return Reader(action, values)
        with patch.object(engine, "Journal", InertJournal), patch.object(engine, "_read_initial", return_value=frame(initial())), \
             patch.object(engine, "_read_request", return_value=frame({"protocol": policy.PROTOCOL, "id": request.id, "go": {"requestSha256": request.digest, "token": SENTINEL}})), \
             patch.object(policy, "_make_live_reader", side_effect=reader), patch.object(engine, "_write_response", side_effect=write), \
             patch.object(engine.time, "monotonic", return_value=0.0), patch.object(engine.os, "dup", side_effect=(10, 11)), \
             patch.object(engine.os, "open", return_value=12), patch.object(engine.os, "set_inheritable"), patch.object(engine.os, "dup2"), patch.object(engine.os, "close"):
            self.assertEqual(engine.main(started=0.0, runtime_dir="/inert", family=Family.RELEASE), 0)
        self.assertEqual(sequence, ["open", "intent", "ready", "go", "run", "journal-close", "result"])
        self.assertNotIn(SENTINEL, json.dumps(frames))


class GitHubReleaseTransportTests(unittest.TestCase):
    def test_only_release_config_role_can_read_base64_overhead_in_all_framing_modes(self):
        raw = policy._canonical({"content": "x" * (300 * 1024)})
        for framing in ("length", "chunked", "eof"):
            self.assertEqual(response(raw, framing).control["reason"], "response-limit")
            self.assertEqual(response(raw, framing, profile=transport._ExchangeProfile.RELEASE_PREPARE).control["reason"], "response-limit")
            value = response(raw, framing, role=transport._ResponseRole.RELEASE_CONFIG, profile=transport._ExchangeProfile.RELEASE_PREPARE)
            self.assertEqual(value.control["reason"], "none")
            self.assertEqual(len(value.observation["body"]["content"]), 300 * 1024)
        with self.assertRaises(ValueError): response(raw, role=transport._ResponseRole.RELEASE_CONFIG)
        profile, role = transport._ExchangeProfile.RELEASE_PREPARE, transport._ResponseRole.RELEASE_CONFIG
        config_path = "/repos/owner/app/contents/release/mobile-release.json?ref=" + SOURCE
        self.assertEqual(transport._request_limits(profile, role, "GET", config_path), (768 * 1024, 1024))
        for method, path in (("POST", config_path), ("GET", "/user"), ("GET", config_path.replace("mobile-release.json", "other.json")), ("GET", config_path + "&extra=1")):
            with self.assertRaises(ValueError): transport._request_limits(profile, role, method, path)
        for framing in ("length", "chunked", "eof"):
            self.assertEqual(response(b" " * (768 * 1024 + 1), framing, role, profile).control["reason"], "response-limit")

    def test_release_aggregate_and_original_deadline_are_never_renewed(self):
        now = [100.0]
        budget = transport._Budget(100.0, monotonic=lambda: now[0], _profile=transport._ExchangeProfile.RELEASE_PREPARE)
        raw = policy._canonical({"x": "v" * (700 * 1024)})
        for _ in range(2):
            self.assertEqual(response(raw, role=transport._ResponseRole.RELEASE_CONFIG, budget=budget).control["reason"], "none")
        self.assertEqual(response(raw, role=transport._ResponseRole.RELEASE_CONFIG, budget=budget).control["reason"], "response-limit")
        self.assertEqual(budget.end, 110.0)
        now[0] = 110.0
        with self.assertRaises(transport.ReadFailure): budget.remaining()
        self.assertEqual(transport.MAX_BODY_BYTES, 256 * 1024)
        self.assertEqual(transport.MAX_BODY_TOTAL, 1024 * 1024)



class GitHubReleaseBootstrapTests(unittest.TestCase):
    """Fixed bootstrap SOURCE plus recording DATA; no runtime or network call."""

    @staticmethod
    def _bootstrap():
        path = Path(__file__).resolve().parents[2] / "desktop" / "github_release_bootstrap.py"
        spec = importlib.util.spec_from_file_location("_mrk_release_bootstrap_contract", path)
        if spec is None or spec.loader is None:
            raise AssertionError("fixed bootstrap SOURCE is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _system(**changes):
        values = dict(argv=["fixed-bootstrap", "/inert/core.zip"],
                      flags=SimpleNamespace(isolated=True, no_site=True),
                      dont_write_bytecode=True, version_info=(3, 11),
                      platform="darwin", path=[])
        values.update(changes)
        return SimpleNamespace(**values)

    @staticmethod
    def _run(module, system, *, source="/inert/runtime/github_release_bootstrap.py"):
        # Replacing this module's references never edits the process sys.path or
        # clock. The already imported fixed engine entry is a recording double.
        with patch.object(module, "sys", system), patch.object(module, "__file__", source), \
             patch.object(module, "time", SimpleNamespace(monotonic=lambda: 11.0)), \
             patch.object(engine, "main", return_value=17) as entry:
            code = module.main()
        return code, entry

    def test_exact_linux_and_darwin_admit_only_the_fixed_engine_family(self):
        module = self._bootstrap()
        for platform in ("linux", "darwin"):
            system = self._system(platform=platform)
            with self.subTest(platform=platform):
                code, entry = self._run(module, system)
                self.assertEqual(code, 17)
                entry.assert_called_once_with(started=11.0, runtime_dir="/inert/runtime", family=Family.RELEASE)
                self.assertEqual(system.path, ["/inert/core.zip"])

    def test_other_platforms_flags_and_unbound_paths_refuse_before_engine_entry(self):
        module = self._bootstrap()
        cases = [dict(platform=value) for value in ("linux2", "Darwin", "win32", "freebsd", "")]
        cases += [dict(argv=value) for value in ([], ["fixed-bootstrap"],
                  ["fixed-bootstrap", "/inert/core.zip", "extra"], ["fixed-bootstrap", "relative.zip"])]
        cases += [dict(flags=SimpleNamespace(isolated=False, no_site=True)),
                  dict(flags=SimpleNamespace(isolated=True, no_site=False)),
                  dict(dont_write_bytecode=False), dict(version_info=(3, 10))]
        for changes in cases:
            system = self._system(**changes)
            with self.subTest(changes=changes):
                code, entry = self._run(module, system)
                self.assertEqual(code, 78)
                entry.assert_not_called()
                self.assertEqual(system.path, [])
        for source in ("github_release_bootstrap.py", ""):
            system = self._system()
            with self.subTest(source=source):
                code, entry = self._run(module, system, source=source)
                self.assertEqual(code, 78)
                entry.assert_not_called()
                self.assertEqual(system.path, [])


if __name__ == "__main__":
    unittest.main()
