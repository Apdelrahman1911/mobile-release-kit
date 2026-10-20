"""Synthetic Git object/HTTP DATA; no child, network, Store or native authority.

Only an empty task-owned temporary root is real. The existing ledger and exact
version renderer run normally; both process/HTTP boundaries are replaced before
invocation. Passing these tests does not qualify GitHub Actions or a native app.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from mobile_release import version_ci as ci
from mobile_release import version_allocation as allocation
from mobile_release import version_policy as policy
from mobile_release import version_text
from mobile_release import ios_store_versions as ios
from mobile_release import android_store_versions as android
from mobile_release import paired_store_versions as paired
from mobile_release import workflow
from mobile_release.config import default_config_data, ReleaseVersion

PROJECT = "00000000-0000-4000-8000-000000000001"
LEDGER = "00000000-0000-4000-8000-000000000003"
REPOSITORY, REPOSITORY_ID = "fixture/ci-reservation", "123"
BRANCH, NOW, CONTEXT = "refs/heads/main", 10_000, "9" * 64


def oid(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def commit(tree, message, parents=()):
    return ("tree " + tree + "\n" + "".join("parent " + p + "\n" for p in parents)
            + "author Fixture <fixture@example.invalid> 10000 +0000\n"
            + "committer Fixture <fixture@example.invalid> 10000 +0000\n\n").encode() + message


class Fixture:
    def __init__(self, root, schema=4, *, ledger=None):
        self.root = root
        (root / ".git").mkdir(exist_ok=True)
        self.platforms = {1: ("android",), 2: ("ios",), 3: ("android",), 4: ("android", "ios")}[schema]
        self.config = default_config_data({p: {"bundleId" if p == "ios" else "applicationId": "com.example.inert"}
                                          for p in self.platforms})
        self.config_raw = json.dumps(self.config, sort_keys=True).encode()
        self.before = b"# Exact comments\r\nVERSION_NAME = '1.2.3'\r\nBUILD_NUMBER = 7"
        self.before_tree, self.after_tree = "b" * 40, "f" * 40
        self.before_commit_raw = commit(self.before_tree, b"Commit setup before reserving.\n")
        self.before_commit = oid("commit", self.before_commit_raw)
        identity = hashlib.sha256(self.config_raw).hexdigest()
        source = policy.SourceBinding(self.before_commit, self.before_tree, BRANCH, identity,
                                      hashlib.sha256(self.before).hexdigest())
        scope = {1: "require-fresh-complete", 2: ios.POLICY_SCOPE, 3: android.POLICY_SCOPE,
                 4: paired.POLICY_SCOPE}[schema]
        if schema == 1:
            settings = policy.VersionPolicy("automatic", (policy.RefRule(BRANCH, "build"),))
        else:
            settings = policy.VersionPolicy("automatic", (policy.RefRule(BRANCH, "build"),), store_scope=scope)
        self.request = allocation.AllocationRequest(PROJECT,
            f"00000000-0000-4000-8000-{schema:012d}", identity, source, ReleaseVersion("1.2.3", 7),
            self.platforms, settings, None if schema == 1 else CONTEXT)
        if ledger is None:
            ledger = allocation.Ledger(allocation.Genesis(PROJECT, REPOSITORY_ID, LEDGER, ReleaseVersion("1.2.3", 7)))
        self.authority = allocation.AuthorityRegistration(PROJECT, REPOSITORY, REPOSITORY_ID, LEDGER,
                                                         ledger.genesis.sha256, True)
        if schema == 1:
            observations = (policy.StoreObservation("android", identity, "a" * 64, NOW, 7, "1.2.3"),)
        else:
            observations = tuple(android.CurrentInventory(identity, CONTEXT, "a" * 64, NOW, 7, (0, 0, 0, 0, 1))
                if p == "android" else ios.CurrentInventory(identity, CONTEXT, "c" * 64, NOW, 7, "1.2.3", (1, 0, 0))
                for p in self.platforms)
        self.ledger = ledger.append(self.request, observations, now=NOW)
        self.row = self.ledger.reservations[-1]
        self.ledger_commit = "c" * 40
        self.anchor = allocation.Checkpoint(len(self.ledger.reservations), self.ledger.head_sha256, self.ledger_commit)
        self.settings = json.dumps({"schemaVersion": 1, "authority": self.authority.value(), "checkpoint": self.anchor.value()})
        self.message = (f"Save reserved version\n\n{ci.TRAILER}: {self.request.candidate_id} {self.row.sha256}\n").encode()
        self.final_raw = commit(self.after_tree, self.message, (self.before_commit,))
        self.final = oid("commit", self.final_raw)
        selection = version_text.public_version_selection(self.config_raw.decode())
        self.after = version_text.prepare_payload(selection, self.before, "edit",
            {"name": self.row.version.name, "build": str(self.row.version.build)})[1]
        self.config_oid, self.before_oid, self.after_oid = (oid("blob", b) for b in (self.config_raw, self.before, self.after))
        self.entry = f"100644 blob {self.config_oid}\trelease/mobile-release.json\0".encode()
        self.delta = f":100644 100644 {self.before_oid} {self.after_oid} M\0{selection.source}\0".encode()
        self.blobs = {self.config_oid: self.config_raw, self.before_oid: self.before, self.after_oid: self.after}
        self.commits = {self.before_commit: self.before_commit_raw, self.final: self.final_raw}
        self.context = workflow.Context("candidate", self.platforms[0], {"fullName": REPOSITORY, "id": REPOSITORY_ID},
            {"headSha": self.final, "ref": BRANCH}, self.platforms[0] + "_build",
            selected_platform="both" if len(self.platforms) == 2 else self.platforms[0])
        self.git_calls, self.http_calls = [], []
        self.probe = b"\n"
        self.after_git = self.after_http = None
        self.http_override = {}
        self.clock = 100.0

    def git(self, argv, **kwargs):
        args = argv[argv.index("-C") + 2:]
        self.git_calls.append((list(args), kwargs))
        assert kwargs["cancellation"] is not None and kwargs["text"] is False
        assert 1 <= kwargs["timeout"] <= 10
        assert not any(k in kwargs["environ"] for k in ("GH_TOKEN", "HOME", "GOOGLE_APPLICATION_CREDENTIALS", "GIT_CONFIG_COUNT"))
        assert kwargs["environ"]["GIT_NO_LAZY_FETCH"] == "1"
        assert "protocol.allow=never" in argv and "--no-replace-objects" in argv
        if args[0] == "show":
            result = self.probe
        elif args == ["rev-parse", "--verify", "HEAD"]:
            result = (self.context.authority["headSha"] + "\n").encode()
        elif args == ["rev-parse", "--verify", "HEAD^{tree}"]:
            result = (self.after_tree + "\n").encode()
        elif args[:2] == ["cat-file", "commit"]:
            result = self.commits[args[2]]
        elif args[:2] == ["cat-file", "blob"]:
            result = self.blobs[args[2]]
        elif args[0] == "ls-tree":
            self.assert_equal(args[-2:], ["--", version_text.CONFIG_PATH])
            result = self.entry
        else:
            self.assert_equal(args[:3], ["diff-tree", "--no-abbrev", "--raw"])
            self.assert_equal(args[-3:], [self.before_commit, self.final, "--"])
            result = self.delta
        if self.after_git:
            self.after_git(len(self.git_calls), kwargs)
        return subprocess.CompletedProcess(argv, 0, result, b"PRIVATE STDERR MUST NOT APPEAR")

    @staticmethod
    def assert_equal(a, b):
        assert a == b, (a, b)

    def json(self, receiver, endpoint, *, maximum, timeout):
        self.http_calls.append((endpoint, maximum, timeout))
        assert receiver.cancellation is not None
        assert maximum == ci.HTTP_LIMIT and 1 <= timeout <= 10
        prefix = "repos/" + REPOSITORY + "/"
        assert endpoint == prefix[:-1] or endpoint.startswith(prefix)
        path = endpoint[len(prefix):] if endpoint != prefix[:-1] else ""
        if path in self.http_override:
            response = copy.deepcopy(self.http_override[path])
        elif path == "":
            response = {"id": int(REPOSITORY_ID), "full_name": REPOSITORY, "archived": False,
                        "visibility": "private", "default_branch": "main"}
        elif path.startswith("git/ref/heads/"):
            assert path == "git/ref/heads/" + allocation.LEDGER_BRANCH
            response = {"ref": "refs/heads/" + allocation.LEDGER_BRANCH,
                        "object": {"type": "commit", "sha": self.ledger_commit}}
        elif path.startswith("compare/"):
            assert path == "compare/" + self.anchor.commit + "..." + self.ledger_commit
            response = {"status": "identical" if self.anchor.commit == self.ledger_commit else "ahead",
                        "base_commit": {"sha": self.anchor.commit}, "merge_base_commit": {"sha": self.anchor.commit}}
        elif path.startswith("contents/"):
            assert path == "contents/" + allocation.LEDGER_PATH + "?ref=" + self.ledger_commit
            raw = self.ledger.to_bytes()
            response = {"type": "file", "path": allocation.LEDGER_PATH, "encoding": "base64", "size": len(raw),
                        "sha": allocation.blob_sha(raw), "content": base64.b64encode(raw).decode() + "\n"}
        else:
            assert path in ("git/commits/" + self.before_commit, "git/commits/" + self.final)
            before = path.endswith(self.before_commit)
            response = {"sha": self.before_commit if before else self.final,
                        "tree": {"sha": self.before_tree if before else self.after_tree}}
        if self.after_http:
            self.after_http(len(self.http_calls), receiver)
        return response

    def run(self, settings=True):
        actual = self
        def read(receiver, *args, **kwargs):
            return actual.json(receiver, *args, **kwargs)
        with patch.dict(os.environ, {ci.AUTHORITY_ENV: self.settings if settings else "", "GH_TOKEN": "INERT-not-forwarded"}), \
             patch.object(ci, "run_owned", self.git), patch.object(workflow.GitHub, "json", read), \
             patch.object(allocation, "allocate_version", side_effect=AssertionError("CI must not allocate")), \
             patch.object(ci.time, "monotonic", lambda: self.clock):
            return ci.verify_reserved_source(self.root, self.context)

    def final_message(self, message, *, parents=None):
        self.message = message
        self.final_raw = commit(self.after_tree, message, (self.before_commit,) if parents is None else parents)
        self.final = oid("commit", self.final_raw)
        self.commits[self.final] = self.final_raw
        self.context.authority["headSha"] = self.final


class VersionCI(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mrk-version-ci-data-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def refused(self, f, reason=None, **kwargs):
        with self.assertRaises(ci.Refused) as found:
            f.run(**kwargs)
        if reason:
            self.assertEqual(found.exception.reason, reason)
        self.assertNotIn("PRIVATE", str(found.exception))

    def test_same_ledger_versions_one_to_four_and_repeated_consume_never_allocate(self):
        ledger = None
        for schema in (1, 2, 3, 4):
            with self.subTest(schema=schema):
                f = Fixture(self.root, schema, ledger=ledger)
                old = [r.value() for r in f.ledger.reservations[:-1]]
                first = f.run()
                f.git_calls.clear(); f.http_calls.clear()
                second = f.run()
                self.assertEqual(first, second)
                self.assertEqual(first.candidate_id, f.request.candidate_id)
                self.assertEqual(first.row_sha256, f.row.sha256)
                self.assertEqual(first.version_build, 7 + schema)
                self.assertEqual(old, [r.value() for r in f.ledger.reservations[:-1]])
                self.assertLessEqual(len(f.git_calls), 12)
                self.assertEqual(len(f.http_calls), 8)
                ledger = f.ledger

    def test_manual_unconfigured_is_one_owned_probe_no_remote_or_allocation(self):
        f = Fixture(self.root)
        self.assertIsNone(f.run(settings=False))
        self.assertEqual(len(f.git_calls), 1)
        self.assertFalse(f.http_calls)

    def test_opt_in_stripped_trailer_and_trailer_without_settings_do_not_fall_back(self):
        f = Fixture(self.root)
        f.final_message(b"A manual-looking commit with no trailer.\n")
        self.refused(f, "trailer")
        self.assertFalse(f.http_calls)
        f = Fixture(self.root); f.probe = b"MRK-Version-Reservation: not-valid\n"
        self.refused(f, "settings", settings=False)
        self.assertFalse(f.http_calls)

    def test_settings_invalid_duplicate_fields_bounds_and_untrusted_protection_refuse_before_reads(self):
        for change in (lambda s: "{", lambda s: s + " " * ci.SETTINGS_LIMIT,
                       lambda s: s.replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1'),
                       lambda s: s.replace('"protectedBranch": true', '"protectedBranch": false')):
            f = Fixture(self.root); f.settings = change(f.settings)
            self.refused(f, "settings")
            self.assertFalse(f.git_calls or f.http_calls)

    def test_repository_project_genesis_checkpoint_and_rewind_never_select_a_new_counter(self):
        for field, value in (("repositoryId", "124"), ("repository", "another/repository"),
                             ("projectId", "a" * 32), ("genesisSha256", "e" * 64)):
            f = Fixture(self.root); settings = json.loads(f.settings)
            settings["authority"][field] = value; f.settings = json.dumps(settings)
            self.refused(f, "authority")
        f = Fixture(self.root); settings = json.loads(f.settings)
        settings["checkpoint"]["headSha256"] = "e" * 64; f.settings = json.dumps(settings)
        self.refused(f, "authority")
        f = Fixture(self.root)
        path = "compare/" + f.anchor.commit + "..." + f.ledger_commit
        f.http_override[path] = {"status": "behind", "base_commit": {"sha": f.anchor.commit},
                                 "merge_base_commit": {"sha": f.anchor.commit}}
        self.refused(f, "authority")

    def test_missing_candidate_or_changed_same_candidate_hash_is_not_a_retry_allocation(self):
        for candidate, row_hash in (("00000000-0000-4000-8000-000000000099", None), (None, "e" * 64)):
            f = Fixture(self.root)
            f.final_message(f"Save\n\n{ci.TRAILER}: {candidate or f.request.candidate_id} {row_hash or f.row.sha256}\n".encode())
            self.refused(f, "candidate")

    def test_real_repository_identity_is_rechecked_before_and_after_the_ledger_read(self):
        for at_end in (False, True):
            f = Fixture(self.root)
            wrong = {"id": 124, "full_name": REPOSITORY, "archived": False,
                     "visibility": "private", "default_branch": "main"}
            if at_end:
                def substitute_after_pinned_ref(n, _):
                    if n == 7:
                        f.http_override[""] = wrong
                f.after_http = substitute_after_pinned_ref
            else:
                f.http_override[""] = wrong
            self.refused(f, "authority")
            self.assertEqual(len(f.http_calls), 8 if at_end else 1)
            self.assertEqual(f.http_calls[-1][0], "repos/" + REPOSITORY)

    def test_duplicate_misplaced_alternate_case_or_continued_trailer_refuses(self):
        f = Fixture(self.root); good = f.message
        variants = (good + good, good.replace(b"\n\n", b"\n"), good.replace(b"MRK-", b"mrk-"),
                    good + b" continuation\n", good + b"\nNot a trailer\n")
        for message in variants:
            with self.subTest(message=message):
                f = Fixture(self.root); f.final_message(message)
                self.refused(f, "trailer")

    def test_platform_and_full_branch_ref_must_match_reserved_request(self):
        for platform, reference in (("ios", BRANCH), ("both", "refs/heads/other")):
            f = Fixture(self.root)
            f.context = replace(f.context, selected_platform=platform,
                                platform="ios", authority={"headSha": f.final, "ref": reference})
            self.refused(f, "candidate")

    def test_one_parent_only_and_local_original_commit_hash_and_tree_are_bound(self):
        for parents in ((), ("e" * 40,), ("e" * 40, "d" * 40)):
            f = Fixture(self.root); f.final_message(f.message, parents=parents)
            self.refused(f, "source")
        f = Fixture(self.root)
        f.commits[f.before_commit] = f.before_commit_raw.replace(b"tree b", b"tree a", 1)
        self.refused(f, "source")
        f = Fixture(self.root)
        f.http_override["git/commits/" + f.before_commit] = {"sha": f.before_commit, "tree": {"sha": "a" * 40}}
        self.refused(f, "source")

    def test_full_diff_not_a_version_path_filter_rejects_any_additional_or_mode_change(self):
        for change in (lambda d: d + b":100644 100644 " + b"a" * 40 + b" " + b"b" * 40 + b" M\0other.txt\0",
                       lambda d: d.replace(b"100644 100644", b"100644 100755"),
                       lambda d: d.replace(b"100644 100644", b"120000 120000"),
                       lambda d: d.replace(b"100644 100644", b"160000 160000"),
                       lambda d: d[:-1], lambda d: b"", lambda d: d.replace(b" M\0", b" R100\0")):
            f = Fixture(self.root); f.delta = change(f.delta)
            self.refused(f, "source")

    def test_unchanged_outside_symlink_gitlink_modes_are_not_opened_or_rejected(self):
        f = Fixture(self.root)
        # An unfiltered diff contains no record for equal outside entries. The
        # fake command refuses every attempted unrelated path/object lookup.
        self.assertIsNotNone(f.run())
        diff = next(args for args, _ in f.git_calls if args[0] == "diff-tree")
        self.assertEqual(diff[-1], "--")
        self.assertIn("--no-abbrev", diff)
        self.assertFalse(any("--recursive" in args for args, _ in f.git_calls))
        self.assertEqual([args[-1] for args, _ in f.git_calls if args[0] == "ls-tree"], [version_text.CONFIG_PATH])

    def test_config_version_blob_hash_and_exact_comment_crlf_renderer_remain_required(self):
        f = Fixture(self.root)
        self.assertIsNotNone(f.run())
        self.assertTrue(f.after.startswith(b"# Exact comments\r\n"))
        self.assertFalse(f.after.endswith(b"\n"))
        for blob in ("config_oid", "before_oid", "after_oid"):
            f = Fixture(self.root); key = getattr(f, blob)
            f.blobs[key] += b"\n"
            self.refused(f, "source")

    def test_unsafe_or_ambiguous_selected_config_entry_refuses(self):
        for entry in (b"", b"120000 blob " + b"a" * 40 + b"\trelease/mobile-release.json\0",
                      b"100644 blob " + b"a" * 40 + b"\trelease/mobile-release.json\0extra\0"):
            f = Fixture(self.root); f.entry = entry
            self.refused(f, "source")

    def test_original_clock_is_not_renewed_between_commands_or_gh_reads(self):
        for boundary in ("after_git", "after_http"):
            f = Fixture(self.root)
            setattr(f, boundary, lambda n, _: setattr(f, "clock", 160.0))
            self.refused(f, "deadline")
        f = Fixture(self.root); f.after_http = lambda n, _: setattr(f, "clock", 99.0)
        self.refused(f, "deadline")

    def test_cancel_after_original_read_return_stops_without_later_remote_calls(self):
        f = Fixture(self.root)
        def stop(n, receiver):
            receiver.cancellation.cancelled = True
        f.after_http = stop
        with self.assertRaises(KeyboardInterrupt):
            f.run()
        self.assertEqual(len(f.http_calls), 1)

    def test_all_new_remote_reads_are_fresh_bounded_and_ref_change_at_end_refuses(self):
        f = Fixture(self.root)
        def changed(n, _):
            if n == 6:
                f.http_override["git/ref/heads/" + allocation.LEDGER_BRANCH] = {
                    "ref": "refs/heads/" + allocation.LEDGER_BRANCH, "object": {"type": "commit", "sha": "d" * 40}}
        f.after_http = changed
        self.refused(f, "authority")
        self.assertEqual(len(f.http_calls), 7)
        self.assertEqual(f.http_calls[1][0], f.http_calls[-1][0])

    def test_public_remote_error_and_oversize_git_result_never_echo_raw_contents(self):
        f = Fixture(self.root)
        def invalid(n, _):
            if n == 1:
                f.http_override["compare/" + f.anchor.commit + "..." + f.ledger_commit] = {"private": "PRIVATE"}
        f.after_http = invalid
        self.refused(f, "authority")
        f = Fixture(self.root); f.delta = b"PRIVATE" * ci.DIFF_LIMIT
        self.refused(f, "read")


if __name__ == "__main__":
    unittest.main()
