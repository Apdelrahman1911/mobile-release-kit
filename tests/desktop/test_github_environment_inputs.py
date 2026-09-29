"""Synthetic P2 policy data, not live credentials/TLS/journal qualification."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

from mobile_release import github_environment_inputs as policy
from mobile_release import _github_connection_transport as transport
from mobile_release._github_action_family import Family, policy_for, journal_suffix
from mobile_release.errors import CredentialError
from test_github_release import configuration, contents, repository

TIME = "2026-09-28T20:00:00Z"
LATER = "2026-09-28T20:00:01Z"
SOURCE = "a" * 40
PRIVATE = "INERT_UNSELECTED_REMOTE_VALUE"


def target(stage="candidate", platform="android", kind=None, purpose="full", config=None):
    data = configuration() if config is None else config
    return policy.Target.parse({"projectBinding": "b" * 64, "repository": "owner/app",
        "accountId": "11", "repositoryId": "22", "branch": "production" if stage == "production" else "main",
        "toolingRepository": policy.TOOLING_REPOSITORY, "toolingSha": "c" * 40,
        "scope": {"platform": platform, "stage": stage, "purpose": purpose},
        "kind": kind or ("google-wif" if platform == "android" else "asc-p8"), "marker": "d" * 32,
        "nativeConfigSha256": hashlib.sha256(policy.canonical(data)).hexdigest()})


def bodies(selected=None, config=None):
    selected = selected or target()
    source = {"ref": "refs/heads/" + selected.branch, "object": {"type": "commit", "sha": SOURCE}}
    environment = {"id": 33, "name": selected.environment, "can_admins_bypass": False,
        "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
        "protection_rules": [{"id": 44, "type": "required_reviewers", "prevent_self_review": True,
            "reviewers": [{"type": "Team", "reviewer": {"id": 55, "ignored": PRIVATE}}]}]}
    return {"account": {"id": 11, "login": "owner", "ignored": PRIVATE},
        "repository-before": repository(), "repository-after": repository(),
        "source-before": source, "source-after": copy.deepcopy(source),
        "caller": contents(selected.caller_path, policy.canonical_caller(selected)),
        "config": contents(policy.CONFIG_PATH, policy.canonical(configuration() if config is None else config)),
        "environment": environment,
        "public-key": {"key_id": "fixture-key_1", "key": base64.b64encode(bytes(range(32))).decode()},
        "metadata": {"name": selected.secret_name, "created_at": TIME, "updated_at": TIME, "ignored": PRIVATE}}


class Reader:
    def __init__(self, action, values):
        self.schedule = policy.Schedule(action)
        self.values = values
        self.calls = []

    def read(self, step, reference=None):
        self.calls.append(self.schedule.claim(step, reference))
        value = self.values[step]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value) if type(value) is transport.ReadResult else transport.ReadResult(
            {"status": 200, "body": copy.deepcopy(value), "failure": "none"}, transport._control())


def prepared(selected=None, values=None):
    selected = selected or target()
    action = policy.Action("prepare", selected)
    result = policy.observe_reads(action, Reader(action, bodies(selected) if values is None else values), observed_at=TIME)
    if result["reason"] != "none":
        raise AssertionError("Synthetic input-group fixture did not prepare: " + result["reason"])
    return policy.Prepared.parse(result["prepared"])


def action(kind="apply", selected=None):
    selected = selected or target()
    return policy.Action(kind, selected, None if kind == "prepare" else prepared(selected))


def sealed_body(key_id="fixture-key_1", size=80):
    return json.dumps({"encrypted_value": base64.b64encode(b"x" * size).decode(), "key_id": key_id},
                      separators=(",", ":")).encode()


class GitHubEnvironmentInputPolicyTests(unittest.TestCase):
    def test_prepare_uses_ten_fixed_settled_reads_for_each_stage_and_platform(self):
        for stage in ("candidate", "external-testing", "production"):
            for platform in ("android", "ios"):
                selected = target(stage, platform)
                chosen = policy.Action("prepare", selected)
                reader = Reader(chosen, bodies(selected))
                result = policy.observe_reads(chosen, reader, observed_at=TIME)
                with self.subTest(stage=stage, platform=platform):
                    self.assertEqual(result["reason"], "none")
                    review = policy.Prepared.parse(result["prepared"])
                    self.assertEqual(reader.schedule.steps, list(policy._READ_STEPS))
                    self.assertEqual([row.method for row in reader.calls], ["GET"] * 10)
                    self.assertEqual(reader.calls[2].path, "/repos/owner/app/git/ref/heads/" + selected.branch)
                    self.assertTrue(reader.calls[3].path.endswith("?ref=" + SOURCE))
                    self.assertEqual(reader.calls[6].path, "/repos/owner/app/environments/" + selected.environment + "/secrets/public-key")
                    self.assertEqual(review.public_target()["secretName"], selected.secret_name)
                    self.assertNotIn(PRIVATE, json.dumps(result))
                    self.assertNotIn("canWrite", json.dumps(result))
                    self.assertEqual(result["networkCleanup"], "confirmed")
                    policy.validate_result(chosen, result)

    def test_each_original_binding_change_refuses_before_a_put(self):
        prior = prepared()
        for step, change, reason in (
            ("account", {"id": 12}, "target-changed"),
            ("repository-before", {"id": 23}, "target-changed"),
            ("source-before", {"ref": "refs/tags/main"}, "source-changed"),
            ("environment", {"id": 34}, "environment-unready"),
            ("environment", {"can_admins_bypass": True}, "environment-unready"),
            ("public-key", {"key_id": "different-key"}, "target-changed"),
            ("public-key", {"key": base64.b64encode(b"z" * 32).decode()}, "target-changed"),
            ("metadata", {"updated_at": LATER}, "metadata-changed"),
            ("source-after", {"object": {"type": "commit", "sha": "e" * 40}}, "source-changed"),
            ("repository-after", {"id": 24}, "target-changed"),
        ):
            values = bodies(); values[step].update(change)
            chosen = policy.Action("apply", prior.target, prior)
            reader = Reader(chosen, values)
            result = policy.observe_reads(chosen, reader, observed_at=LATER)
            with self.subTest(step=step, change=change):
                self.assertEqual(result["reason"], reason)
                self.assertIsNone(result["prepared"])
                self.assertFalse(reader.schedule.write_claimed)
                self.assertTrue(all(row.method == "GET" for row in reader.calls))
        for step, raw, reason in (("caller", b"not the pinned caller", "caller-incompatible"),
            ("config", policy.canonical({**configuration(), "services": {"androidFirebase": "required", "iosFirebase": "disabled"}}),
             "config-mismatch")):
            values = bodies()
            values[step] = contents(prior.target.caller_path if step == "caller" else policy.CONFIG_PATH, raw)
            chosen = policy.Action("apply", prior.target, prior); reader = Reader(chosen, values)
            self.assertEqual(policy.observe_reads(chosen, reader, observed_at=LATER)["reason"], reason)
            self.assertLessEqual(len(reader.calls), 5)

    def test_core_applicability_is_whole_group_and_candidate_inputs_do_not_promote(self):
        selections = [target("production", kind="android-keystore"),
            target("external-testing", "ios", "apple-p12"),
            target(kind="android-keystore", purpose="store"),
            target(kind="android-firebase"), target("candidate", "ios", "apple-review-contact")]
        for selected in selections:
            chosen = policy.Action("prepare", selected); reader = Reader(chosen, bodies(selected))
            result = policy.observe_reads(chosen, reader, observed_at=TIME)
            self.assertEqual(result["reason"], "input-invalid")
            self.assertEqual(len(reader.calls), 5)
        selected = target(kind="android-keystore", purpose="signing")
        self.assertEqual(prepared(selected).target.kind, "android-keystore")
        with self.assertRaises(CredentialError):
            policy.Target.parse({**target().value(), "kind": "review-notes"})

    def test_404_is_upsert_ambiguity_and_reconcile_never_confirms_a_secret_value(self):
        values = bodies()
        values["metadata"] = transport.ReadResult({"status": 404, "body": None, "failure": "none"},
                                                  transport._control("not-found-or-inaccessible"))
        original = prepared(values=values)
        self.assertEqual(original.metadata.state, "missing-or-inaccessible")
        chosen = policy.Action("reconcile", original.target, original)
        values["environment"]["protection_rules"] = [{"type": "unknown-new-policy"}]
        reader = Reader(chosen, values)
        result = policy.observe_reads(chosen, reader, observed_at=LATER)
        self.assertEqual(result["reason"], "none")
        self.assertEqual(reader.schedule.steps, list(policy._RECONCILE_STEPS))
        self.assertEqual(len(reader.calls), 5)
        self.assertEqual(result["observation"]["assurance"], policy.ASSURANCE)
        self.assertEqual(result["observation"]["metadata"]["state"], "missing-or-inaccessible")
        self.assertIsNone(result["record"])
        self.assertIsNone(result["prepared"])

    def test_remote_get_close_failure_never_exposes_writable_snapshot(self):
        for step in policy._READ_STEPS:
            chosen = action(); values = bodies()
            values[step] = transport._CloseFailure("synthetic original close")
            reader = Reader(chosen, values)
            result = policy.observe_reads(chosen, reader, observed_at=LATER)
            self.assertEqual(result["reason"], "network-unavailable")
            self.assertEqual(result["networkCleanup"], "unknown")
            self.assertIsNone(result["prepared"])
            self.assertEqual(len(reader.calls), policy._READ_STEPS.index(step) + 1)
        chosen = action(); values = bodies()
        values["metadata"] = transport.ReadResult({"status": 404, "body": None, "failure": "none"},
                                                  transport._control("response-invalid", 60))
        result = policy.observe_reads(chosen, Reader(chosen, values), observed_at=LATER)
        self.assertEqual(result["reason"], "response-invalid")
        self.assertEqual(result["control"]["cooldownSeconds"], 60)

    def test_one_final_write_claim_uses_original_compact_bytes_and_never_retries(self):
        chosen = action(); schedule = policy.Schedule(chosen)
        body = sealed_body()
        with self.assertRaises(ValueError):
            schedule.claim_write(body)
        for step in policy._READ_STEPS:
            schedule.claim(step, SOURCE if step == "caller" else None)
        with self.assertRaises(ValueError):
            schedule.claim("put")
        sent = schedule.claim_write(body)
        self.assertEqual(sent.method, "PUT")
        self.assertIs(sent.body, body)
        with self.assertRaises(ValueError):
            schedule.claim_write(body)
        for invalid in (b" " + body, body.replace(b'"key_id":', b'"extra":1,"key_id":'),
                        sealed_body("different"), sealed_body(size=48),
                        sealed_body(size=policy.MAX_CIPHERTEXT_BYTES + 1)):
            with self.assertRaises(ValueError):
                policy.validate_put_body(invalid, "fixture-key_1")
        maximum = sealed_body("k" * 128, policy.MAX_CIPHERTEXT_BYTES)
        self.assertLessEqual(len(maximum), policy.MAX_PUT_BODY)
        self.assertIs(policy.validate_put_body(maximum, "k" * 128), maximum)

    def test_fresh_timestamps_are_not_replacement_target_or_metadata_authority(self):
        original = prepared()
        value = original.value()
        value["observedAt"] = value["metadata"]["observedAt"] = LATER
        fresh = policy.Prepared.parse(value)
        policy.compare_prepared(original, fresh)
        value["metadata"]["updatedAt"] = LATER
        with self.assertRaises(policy.Refused):
            policy.compare_prepared(original, policy.Prepared.parse(value))
        # Frozen immutable internals do not alias decoded input mappings.
        value = original.value(); copy_of = policy.Prepared.parse(value)
        value["environmentPolicy"]["canAdminsBypass"] = True
        value["target"]["branch"] = "other"
        self.assertEqual(copy_of, original)

    def test_canonical_domain_is_shared_integer_only_utf8_not_the_old_raw_hash(self):
        corpus = Path(__file__).resolve().parents[1] / "fixtures/desktop/github_input_group_canonical.json"
        rows = json.loads(corpus.read_text(encoding="utf-8"))
        self.assertEqual(rows["schemaVersion"], 1)
        for case in rows["accepted"]:
            self.assertEqual(policy.canonical(json.loads(case["input"])), case["canonical"].encode("utf-8"))
        for raw in rows["rejected"]:
            with self.assertRaises((ValueError, UnicodeError)):
                policy.canonical(json.loads(raw))
        data = configuration()
        pretty = json.dumps(data, indent=2).encode()
        compact = policy.canonical(data)
        self.assertNotEqual(hashlib.sha256(pretty).digest(), hashlib.sha256(compact).digest())
        self.assertEqual(policy._configuration(pretty, target()), hashlib.sha256(pretty).hexdigest())

    def test_private_family_role_and_records_do_not_become_workflow_runs(self):
        self.assertIs(policy_for(Family.INPUT_GROUP), policy)
        self.assertEqual(journal_suffix(Family.INPUT_GROUP)[-1], "github-input-group")
        original = prepared()
        value = action().value(); value["runId"] = "123"
        with self.assertRaises(ValueError):
            policy.Action.parse(value)
        for write in ({"state": "acknowledged-created", "statusCode": 204},
                      {"state": "acknowledged-updated", "statusCode": True},
                      {"state": "explicitly-rejected", "reason": "none"},
                      {"state": "attempted-outcome-unknown", "token": PRIVATE}):
            with self.assertRaises(ValueError):
                policy.record_value(original, write, policy.intent_digest(original))
        record = policy.record_value(original, {"state": "attempted-outcome-unknown"}, policy.intent_digest(original))
        self.assertLessEqual(len(policy.canonical(record)), policy.MAX_RECORD_BYTES)
        self.assertNotIn("runId", record)
        self.assertNotIn("cleanup", record)
        self.assertNotIn("finality", record)


if __name__ == "__main__":
    unittest.main()
