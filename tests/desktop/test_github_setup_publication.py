"""Actual inert five-file policy/journal behavior; no native or network authority."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import github_setup_publication as p
from mobile_release._github_setup_publication_journal import Journal, summary
from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
from test_github_setup import draft

BASE = "a" * 40
COMMIT = "b" * 40
PRIVATE = "MUST_NOT_ESCAPE_UPSTREAM_ERROR_BODY"


def target():
    return p.Target.parse({"projectBinding": "c" * 64, "repository": "owner/app", "accountId": "11",
        "repositoryId": "22", "base": "release/candidate", "toolingRepository": p.TOOLING_REPOSITORY,
        "toolingSha": "d" * 40, "marker": "e" * 32})


def source():
    return p.Source.from_saved(json.dumps(draft()).encode(), target())


def tree(files):
    entries = {path: ("100644", p.git_hash("blob", raw)) for path, raw in files.items()}
    for path in files:
        parts = path.split("/")
        for count in range(1, len(parts)):
            entries.setdefault("/".join(parts[:count]), ("040000", "0" * 40))
    for path in sorted(entries, key=lambda name: name.count("/"), reverse=True):
        if entries[path][0] == "040000":
            descendants = {name[len(path)+1:]: value for name, value in entries.items() if name.startswith(path + "/")}
            entries[path] = ("040000", p.tree_hash(descendants))
    return entries


def repository():
    return {"id": 22, "full_name": "owner/app", "default_branch": "main", "visibility": "private",
            "archived": False, "permissions": {"pull": True}}


class Reader:
    def __init__(self, files=None):
        self.files = {"README.md": b"Do not replace", "app.js": b"original code"} if files is None else files
        self.tree = tree(self.files)
        self.base_tree = p.tree_hash(self.tree)
        self.calls = []
        self.head = None
        self.pull = None
        self.fail_phase = None
        self.fail_status = None
        self.bad_identity = False
        self.changed_base = False
        self.malformed_tree = None
        self.after = None

    @property
    def desired_tree(self):
        return p.tree_hash(p._replace_tree(self.tree, source()))

    def commit(self):
        return {"sha": COMMIT, "message": target().title,
                "tree": {"sha": self.desired_tree}, "parents": [{"sha": BASE}]}

    def pull_value(self):
        return {"number": 7, "title": target().title, "draft": True, "state": "open", "merged_at": None,
            "user": {"id": 11}, "html_url": "https://github.com/owner/app/pull/7",
            "head": {"ref": target().head, "sha": COMMIT, "repo": {"id": 22, "full_name": "owner/app"}},
            "base": {"ref": target().base, "sha": BASE, "repo": {"id": 22, "full_name": "owner/app"}}}

    def __call__(self, request):
        self.calls.append(request)
        path = request.path.removeprefix("/repos/owner/app")
        code = 200
        if request.method == "POST":
            code = 201
            phase = {"/git/trees": "tree", "/git/commits": "commit", "/git/refs": "branch", "/pulls": "pull"}[path]
            if phase == "tree":
                value = {"sha": self.desired_tree}
            elif phase == "commit":
                value = self.commit()
            elif phase == "branch":
                self.head = COMMIT
                value = {"ref": "refs/heads/" + target().head, "object": {"type": "commit", "sha": COMMIT}}
            else:
                self.pull = self.pull_value()
                value = copy.deepcopy(self.pull)
            if self.after:
                self.after(phase, value)
            if phase == self.fail_phase:
                if self.fail_status is not None:
                    return ReadResult({"status": self.fail_status, "body": None, "failure": "none"}, _control())
                raise ReadFailure("network-unavailable")
        elif path == "/user":
            value = {"id": 12 if self.bad_identity else 11, "login": "owner"}
        elif path == "":
            value = repository()
        elif path.startswith("/git/ref/heads/"):
            name = path.removeprefix("/git/ref/heads/")
            if name == p._quote(target().head):
                sha = self.head
            else:
                sha = "f" * 40 if self.changed_base else BASE
            if sha is None:
                return ReadResult({"status": 404, "body": None, "failure": "none"}, _control())
            value = {"ref": "refs/heads/" + (target().head if name == p._quote(target().head) else target().base),
                     "object": {"type": "commit", "sha": sha}}
        elif path == "/git/commits/" + BASE:
            value = {"sha": BASE, "tree": {"sha": self.base_tree}}
        elif path == "/git/commits/" + COMMIT:
            value = self.commit()
        elif path.startswith("/git/trees/"):
            requested = path.removeprefix("/git/trees/")
            assert "?" not in requested, "Only nonrecursive directory reads are supported"
            parent = "" if requested == self.base_tree else next(
                name for name, (mode, sha) in self.tree.items() if mode == "040000" and sha == requested)
            value = {"sha": requested, "truncated": False, "tree": [
                {"path": name.rpartition("/")[2], "mode": mode, "sha": sha,
                 "type": "tree" if mode == "040000" else "commit" if mode == "160000" else "blob"}
                for name, (mode, sha) in self.tree.items() if name.rpartition("/")[0] == parent]}
            if self.malformed_tree:
                self.malformed_tree(value)
        elif path.startswith("/git/blobs/"):
            sha = path.removeprefix("/git/blobs/")
            raw = next(raw for raw in self.files.values() if p.git_hash("blob", raw) == sha)
            value = {"sha": sha, "size": len(raw), "encoding": "base64", "content": base64.b64encode(raw).decode()}
        elif path.startswith("/pulls?"):
            value = [] if self.pull is None else [copy.deepcopy(self.pull)]
        else:
            raise AssertionError(request)
        return ReadResult({"status": code, "body": value, "failure": "none"}, _control())


class MemoryJournal:
    def __init__(self):
        self.original = None
        self.claimed = []
        self.confirmed = {}

    def create_intent(self, value):
        if self.original is not None:
            raise ValueError("Used")
        self.original = summary(value)

    def claim_write(self, phase):
        if phase != p.PHASES[len(self.claimed)] or len(self.claimed) != len(self.confirmed):
            raise ValueError("Used")
        self.claimed.append(phase)

    def record(self, phase, identity):
        self.confirmed[phase] = identity


class SetupPublicationTests(unittest.TestCase):
    def prepared(self, reader=None):
        reader = Reader() if reader is None else reader
        return p.prepare(target(), source(), reader), reader

    def test_prepare_reads_exact_base_and_five_file_review_without_writes(self):
        prepared, reader = self.prepared()
        self.assertTrue(all(call.method == "GET" for call in reader.calls))
        self.assertEqual([row["path"] for row in prepared.view()["files"]], list(p.PATHS))
        self.assertEqual(prepared.base_commit, BASE)
        self.assertEqual(prepared.base_tree, reader.base_tree)
        self.assertTrue(reader.calls[4].path.endswith("/git/trees/" + reader.base_tree))
        self.assertIn("Version, metadata and application source", prepared.view()["confirmation"])
        self.assertIn("existing CI", prepared.view()["confirmation"])
        self.assertNotIn("original code", json.dumps(prepared.view()))
        self.assertNotIn("content", json.dumps(prepared.summary()))

    def test_complete_tree_identity_duplicates_truncation_and_modes_refuse(self):
        for change in (lambda body: body.update(truncated=True),
                       lambda body: body["tree"].append(body["tree"][0]),
                       lambda body: body["tree"][0].update(sha="1" * 40),
                       lambda body: body["tree"][0].update(path="../outside")):
            with self.subTest(change=change):
                reader = Reader(); reader.malformed_tree = change
                with self.assertRaises((p.Refused, ValueError)):
                    self.prepared(reader)
                self.assertTrue(all(call.method == "GET" for call in reader.calls))
        reader = Reader({".github": b"a symlink target is not a directory"})
        with self.assertRaises(p.Refused):
            self.prepared(reader)

    def test_large_application_subtrees_stay_opaque_and_every_setup_sibling_is_preserved(self):
        # A normal source tree may exceed the per-directory HTTP bound overall.
        # None of this application content needs downloading for setup editing.
        files = {f"app/source-{index}.txt": b"unchanged" for index in range(1200)}
        files.update({".github/actions/custom/action.yml": b"unchanged action",
                      ".github/workflows/custom.yml": b"unchanged workflow",
                      "release/notes/history.txt": b"unchanged notes"})
        prepared, reader = self.prepared(Reader(files))
        self.assertEqual(prepared.desired_tree, reader.desired_tree)
        tree_gets = [call.path for call in reader.calls if "/git/trees/" in call.path]
        self.assertEqual(set(tree_gets), {"/repos/owner/app/git/trees/" + sha for sha in
            (reader.base_tree, *(reader.tree[path][1] for path in (".github", ".github/workflows", "release")))})
        self.assertEqual(len(tree_gets), 4)
        self.assertFalse(any("/git/blobs/" in call.path for call in reader.calls))
        self.assertLessEqual(len(reader.calls), p.MAX_REQUESTS)
        result = p.publish(prepared, source(), reader, MemoryJournal())
        self.assertEqual(result["effect"], "draft-pr-observed")

    def test_sparse_and_full_git_trees_have_the_same_identity_without_trusting_changed_parents(self):
        entries = tree({"app/nested/file": b"untouched", "release/notes.txt": b"notes"})
        opaque = {name: value for name, value in entries.items() if not name.startswith("app/")}
        self.assertEqual(p.tree_hash(opaque, verify_subtrees=True), p.tree_hash(entries, verify_subtrees=True))
        opaque["app"] = ("040000", "a" * 40)
        self.assertNotEqual(p.tree_hash(opaque), p.tree_hash(entries))
        body = {"sha": p.tree_hash(entries), "truncated": False, "tree": [
            {"path": "app/nested", "mode": "040000", "type": "tree", "sha": entries["app/nested"][1]}]}
        with self.assertRaises(p.Refused): p._tree(body, body["sha"])

    def test_custom_workflow_refuses_and_canonical_before_is_fully_reviewed(self):
        path = p.PATHS[1]
        with self.assertRaises(p.Refused) as refused:
            self.prepared(Reader({path: b"name: custom workflow\n"}))
        self.assertEqual(refused.exception.reason, "caller-mismatch")
        old = p.render_workflow_caller(source().templates[0], p.TOOLING_REPOSITORY, "1" * 40)
        prepared, _ = self.prepared(Reader({path: old}))
        self.assertEqual(prepared.view()["files"][1]["before"], old.decode())

    def test_previous_candidate_review_and_publication_keep_exact_before_and_current_after(self):
        from mobile_release.github_workflow_candidate_compat import _PREVIOUS_CANDIDATE
        path = p.PATHS[2]
        old = p.render_workflow_caller(_PREVIOUS_CANDIDATE, "Previous/toolkit", "1" * 40)
        for stale in (False, True):
            with self.subTest(stale=stale):
                reader = Reader({path: old, "README.md": b"unchanged application", ".github/workflows/custom.yml": b"# user workflow\n"})
                prepared, _ = self.prepared(reader)
                view = prepared.view()
                self.assertEqual(view["files"][2]["before"].encode(), old)
                self.assertEqual(view["files"][2]["after"].encode(), source().files[2])
                self.assertIn("recover-play-edit", view["files"][2]["after"])
                self.assertEqual(p.Prepared.parse(view), prepared)
                self.assertTrue(all(call.method == "GET" for call in reader.calls))
                reader.calls.clear(); reader.changed_base = stale
                result = p.publish(prepared, source(), reader, MemoryJournal())
                posts = [call for call in reader.calls if call.method == "POST"]
                if stale:
                    self.assertEqual(result["reason"], "source-changed")
                    self.assertEqual(posts, [])
                else:
                    self.assertEqual(result["effect"], "draft-pr-observed")
                    self.assertEqual(json.loads(posts[0].body)["base_tree"], reader.base_tree)
                    self.assertEqual([item["path"] for item in json.loads(posts[0].body)["tree"]], list(p.PATHS))
                    self.assertEqual(json.loads(posts[0].body)["tree"][2]["content"].encode(), source().files[2])
                    self.assertEqual(json.loads(posts[2].body), {"ref": "refs/heads/" + target().head, "sha": COMMIT})
                self.assertFalse(any(call.method in {"PUT", "PATCH", "DELETE"} or "dispatch" in call.path for call in reader.calls))

        for changed in (old + b"# user edit\n", old.replace(b"\n", b"\r\n"),
                        old.replace(b"1" * 40, b"2" * 40, 1)):
            reader = Reader({path: changed})
            with self.assertRaises(p.Refused): self.prepared(reader)
            self.assertTrue(all(call.method == "GET" for call in reader.calls))
            invalid = copy.deepcopy(view); invalid["files"][2]["before"] = changed.decode()
            with self.assertRaises(ValueError): p.Prepared.parse(invalid)
        invalid = copy.deepcopy(view); invalid["files"][2]["after"] = old.decode()
        with self.assertRaises(ValueError): p.Prepared.parse(invalid)  # No legacy AFTER grant.

    def test_actual_publication_sequence_preserves_siblings_and_never_updates_refs(self):
        prepared, reader = self.prepared()
        reader.calls.clear(); journal = MemoryJournal()
        result = p.publish(prepared, source(), reader, journal)
        self.assertEqual((result["reason"], result["effect"]), ("none", "draft-pr-observed"))
        posts = [row for row in reader.calls if row.method == "POST"]
        self.assertEqual([row.path for row in posts], ["/repos/owner/app" + path
            for path in ("/git/trees", "/git/commits", "/git/refs", "/pulls")])
        body = json.loads(posts[0].body)
        self.assertEqual(body["base_tree"], reader.base_tree)
        self.assertEqual([row["path"] for row in body["tree"]], list(p.PATHS))
        self.assertEqual(json.loads(posts[1].body)["parents"], [BASE])
        self.assertEqual(json.loads(posts[2].body), {"ref": "refs/heads/" + target().head, "sha": COMMIT})
        self.assertTrue(json.loads(posts[3].body)["draft"])
        self.assertEqual(journal.claimed, list(p.PHASES))
        self.assertEqual(result["pull"]["url"], "https://github.com/owner/app/pull/7")
        self.assertFalse(any(row.method in {"PATCH", "PUT", "DELETE"} or "dispatch" in row.path for row in reader.calls))

    def test_changed_account_base_source_or_existing_head_never_writes(self):
        for field, value in (("bad_identity", True), ("changed_base", True), ("head", COMMIT)):
            prepared, reader = self.prepared(); reader.calls.clear(); setattr(reader, field, value)
            result = p.publish(prepared, source(), reader, MemoryJournal())
            self.assertNotEqual(result["reason"], "none")
            self.assertFalse(any(row.method == "POST" for row in reader.calls))
        prepared, reader = self.prepared(); reader.calls.clear()
        changed = json.loads(source().files[0]); changed["source"]["candidateBranch"] = "other"
        with self.assertRaises(p.Refused):
            p.publish(prepared, p.Source.from_saved(json.dumps(changed).encode(), target()), reader, MemoryJournal())
        self.assertEqual(reader.calls, [])

    def test_lost_reply_and_cancel_at_every_write_preserve_unknown_without_retry(self):
        for index, phase in enumerate(p.PHASES):
            for cancelled in (False, True):
                prepared, reader = self.prepared(); reader.calls.clear(); journal = MemoryJournal()
                if cancelled:
                    def after(current, _body):
                        if current == phase:
                            raise ReadFailure("cancelled")
                    reader.after = after
                else:
                    reader.fail_phase = phase
                result = p.publish(prepared, source(), reader, journal)
                self.assertEqual(result["effect"], "potentially-applied")
                self.assertEqual(result["reason"], "cancelled" if cancelled else "network-unavailable")
                self.assertEqual(journal.claimed, list(p.PHASES[:index + 1]))
                self.assertEqual(list(journal.confirmed), list(p.PHASES[:index]))
                self.assertEqual(sum(row.method == "POST" for row in reader.calls), index + 1)
                self.assertIsNone(result["pull"])

    def test_branch_or_pr_lost_reply_reconciles_readonly_without_adoption(self):
        for phase in ("branch", "pull"):
            prepared, reader = self.prepared(); journal = MemoryJournal(); reader.fail_phase = phase
            p.publish(prepared, source(), reader, journal)
            reader.calls.clear()
            result = p.reconcile(journal.original, journal.confirmed, tuple(journal.claimed), reader)
            self.assertEqual(result["effect"], "branch-observed" if phase == "branch" else "draft-pr-observed")
            self.assertTrue(all(row.method == "GET" for row in reader.calls))
            reader.head = "9" * 40
            result = p.reconcile(journal.original, journal.confirmed, tuple(journal.claimed), reader)
            self.assertEqual(result["effect"], "unresolved")
        reader.calls.clear()
        result = p.reconcile(journal.original, {"tree": reader.desired_tree}, ("tree", "commit"), reader)
        self.assertEqual((result["effect"], reader.calls), ("unresolved", []))

    def test_wrong_pr_actor_target_duplicate_and_permission_failure_never_pass(self):
        prepared, reader = self.prepared(); journal = MemoryJournal(); reader.fail_phase = "pull"
        p.publish(prepared, source(), reader, journal)
        original = copy.deepcopy(reader.pull)
        for mutate in (lambda row: row["user"].update(id=12), lambda row: row["head"].update(sha="9" * 40),
                       lambda row: row["base"]["repo"].update(id=99), lambda row: row.update(draft=False)):
            reader.pull = copy.deepcopy(original); mutate(reader.pull)
            result = p.reconcile(journal.original, journal.confirmed, tuple(journal.claimed), reader)
            self.assertNotEqual(result["effect"], "draft-pr-observed")
        reader.pull = original
        def duplicated(request):
            value = reader(request)
            if request.path.startswith("/repos/owner/app/pulls?"):
                value.observation["body"] *= 2
            return value
        self.assertEqual(p.reconcile(journal.original, journal.confirmed, tuple(journal.claimed), duplicated)["reason"], "ambiguous")
        prepared, reader = self.prepared(); reader.fail_phase = "tree"; reader.fail_status = 403
        result = p.publish(prepared, source(), reader, MemoryJournal())
        self.assertEqual((result["reason"], result["effect"]), ("forbidden", "potentially-applied"))
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_summary_and_source_refuse_unknown_paths_types_or_raw_extra_fields(self):
        prepared, _ = self.prepared()
        for modify in (lambda row: row.update(rawConfig="private"),
                       lambda row: row["files"][0].update(path="other.json"),
                       lambda row: row["files"][0]["after"].update(bytes=True),
                       lambda row: row["files"].append(copy.deepcopy(row["files"][0]))):
            value = prepared.summary(); modify(value)
            with self.assertRaises(ValueError):
                summary(value)
        for raw in (b'{"schemaVersion":1,"schemaVersion":1}', b"x" * (p.MAX_CONFIG_BYTES + 1)):
            with self.assertRaises(p.Refused):
                p.Source.from_saved(raw, target())

    def test_real_createonly_journal_reopen_preserves_phase_and_never_restores_write(self):
        prepared, _ = self.prepared()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            journal = Journal(str(path), end=time.monotonic() + 20).open()
            journal.create_intent(prepared.summary())
            journal.claim_write("tree"); journal.record("tree", prepared.desired_tree)
            journal.claim_write("commit")
            with self.assertRaises(ValueError):
                journal.claim_write("branch")
            journal.close()
            journal = Journal(str(path), end=time.monotonic() + 20).open()
            scope = {key: target().value()[key] for key in ("projectBinding", "accountId", "repositoryId", "repository")}
            row, = journal.pending(scope)
            self.assertEqual(row["claimed"], ["tree", "commit"])
            self.assertEqual(row["confirmed"], {"tree": prepared.desired_tree})
            with self.assertRaises(ValueError):
                journal.record("commit", COMMIT)
            with self.assertRaises(ValueError):
                journal.create_intent(prepared.summary())
            leaves = list((path / ".local/share/mobile-release-kit/github-setup-publication").iterdir())
            self.assertEqual(len(leaves), 4)
            self.assertTrue(all(item.stat().st_mode & 0o777 == 0o400 for item in leaves))
            self.assertNotIn(source().files[0].decode(), "".join(item.read_text() for item in leaves))
            journal.close()

    def test_existing_preflight_journal_record_bounds_remain_unchanged(self):
        from mobile_release._github_preflight_journal import Journal as Existing, MAX_ENTRIES, MAX_TOTAL_BYTES
        from test_github_preflight import prepared as preflight_prepared
        with tempfile.TemporaryDirectory() as directory:
            existing = Existing(directory, end=time.monotonic() + 20).open()
            expected = preflight_prepared()
            existing.create_intent(expected); existing.bind_run(expected, "123")
            self.assertEqual(existing._max_entries, MAX_ENTRIES)
            self.assertEqual(existing._max_total_bytes, MAX_TOTAL_BYTES)
            self.assertEqual(existing.match_intent(expected, "123"), existing.records[expected.target.marker][2])
            existing.close()
            reopened = Existing(directory, end=time.monotonic() + 20).open()
            self.assertEqual(reopened.records[expected.target.marker][1], "123")
            reopened.close()
