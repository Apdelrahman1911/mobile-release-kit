"""Actual killed config/workflow/initialization writers and fresh recovery.

Only newly created public-data projects are used. The real edit engine, input
parser, rooted lease, transaction, cleanup and original process owner run.
The input feeder supplies a fixed reviewed intent; checkpoint wrappers kill
only their own writer PID after the stated transaction operation. No installed
GUI, helper, Store, release workflow or production qualification is claimed.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--crash-child":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from mobile_release import github_workflow_edit as workflow
from mobile_release import init_transaction as tx

SESSION = "0123456789abcdef0123456789abcdef"
REPOSITORY, PIN = "example/mobile-release-kit", "a" * 40
CASES = ("configuration", "github_workflows", "project_initialization")
POINTS = ("preparing", "replacement", "committed", "cleanup")


def _draft():
    return {"schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.changed", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []}}


def _facts(path):
    s = path.lstat()
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _fixture(root, case):
    root.mkdir(mode=0o700)
    before = {".gitignore": b"# Keep this unrelated comment\n.gradle/\n",
              "unrelated.txt": b"Keep the original bytes, inode and metadata.\n"}
    if case == "configuration":
        old = _draft(); old["android"]["applicationId"] = "org.fixture.original"
        before["release/mobile-release.json"] = json.dumps(old).encode()
    elif case == "github_workflows":
        # Actual shipped templates with a prior format-only pin. These files
        # exist solely inside the disposable project and are never executed.
        proposed, _ = workflow._proposal(_draft(), REPOSITORY, "b" * 40)
        before.update({r["path"]: r["content"].encode() for r in proposed["workflows"]})
    else:
        assert case == "project_initialization"
    for rel, body in before.items():
        p = root / rel; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body); p.chmod(0o640)
    return before


def _child(root, case, mode):
    from mobile_release import _desktop_edit_engine as engine
    from mobile_release._desktop_edit_control import EditInput
    from mobile_release.cancellation import CleanupScope

    assert os.geteuid() != 0 and root.is_absolute() and case in CASES
    assert root.resolve() == root and root.parent.name.startswith("mrk-config-crash-")
    assert root.name in {case + "-" + point for point in POINTS}
    assert mode in {"crash-" + p for p in POINTS} | {"recover"}
    recovering = mode == "recover"
    child = engine._Engine(time.monotonic(), domain=case)
    reader, writer = os.pipe(); os.dup2(reader, 0); os.close(reader)
    original_request = EditInput.request
    move, state_move, unlink = tx.InitWorkspace._move, tx.InitWorkspace._state_move, tx.InitWorkspace._unlink

    def feed(control, sequence, session):
        assert control is child.input and session in (None, SESSION)
        intent = "recover" if recovering else "initialize" if case == "project_initialization" else "edit"
        if sequence == 0:
            params = {"root": str(root)}
            if recovering or case != "configuration":
                s = root.stat()
                params["registeredIdentity"] = {"device": str(s.st_dev), "inode": str(s.st_ino),
                    "mode": s.st_mode, "uid": s.st_uid, "gid": s.st_gid}
                if recovering or case == "project_initialization": params["intent"] = intent
            if case == "project_initialization" and not recovering:
                params.update(draft=_draft(), toolingRepository=REPOSITORY, toolingSha=PIN)
            op = "open"
        elif sequence == 1:
            params = {"revision": child.authority.revision}
            if recovering or case == "project_initialization": params["intent"] = intent
            if not recovering and case != "project_initialization":
                params["draft"] = _draft()
                if case == "configuration": params["expectedBase"] = child.authority.base
                else: params.update(toolingRepository=REPOSITORY, toolingSha=PIN)
            op = "prepare"
        else:
            assert sequence == 2
            params = {"planToken": child.authority.token}
            if recovering or case == "project_initialization": params["intent"] = intent
            if not recovering:
                # Preserve the exact approved plan before any project mutation.
                # This sidecar is outside the project and carries only this
                # fixture's public bytes; it is not filesystem authority.
                plan = child.authority
                paths = (plan._checkout._targets.paths if case == "project_initialization"
                         else child.lease.profile.paths)
                review = {p: None if b is None else base64.b64encode(b).decode("ascii")
                          for p, b in zip(paths, plan._payloads, strict=True)}
                sidecar = root.parent / (root.name + "-review.json")
                with sidecar.open("x") as f:
                    json.dump(review, f); f.flush(); os.fsync(f.fileno())
            op = "apply"
        raw = json.dumps({"protocol": child.input.protocol, "session": SESSION,
                          "seq": sequence, "op": op, "params": params}, separators=(",", ":")).encode() + b"\n"
        assert len(raw) < 4096 and os.write(writer, raw) == len(raw)
        return original_request(control, sequence, session)

    def moved(w, source_fd, source, destination_fd, destination, expected, **kwargs):
        value = move(w, source_fd, source, destination_fd, destination, expected, **kwargs)
        if not recovering and (mode == "crash-replacement" and source.startswith("new-")
                               or mode == "crash-committed" and destination == "COMMITTED"):
            os.kill(os.getpid(), signal.SIGKILL)
        return value

    def state_moved(w, old, new):
        if not recovering and mode == "crash-preparing" and (old, new) == w._state_names[:2]:
            os.kill(os.getpid(), signal.SIGKILL)
        return state_move(w, old, new)

    def unlinked(w, name, **kwargs):
        value = unlink(w, name, **kwargs)
        if not recovering and mode == "crash-cleanup" and name.startswith("old-"):
            os.kill(os.getpid(), signal.SIGKILL)
        return value

    scope = CleanupScope(child.guard, child.cleanup, owns_cancellation=True, first_primary=True)
    try:
        with patch.object(EditInput, "request", feed), patch.object(tx.InitWorkspace, "_move", moved), \
             patch.object(tx.InitWorkspace, "_state_move", state_moved), patch.object(tx.InitWorkspace, "_unlink", unlinked):
            try:
                try:
                    with scope: child.run()
                finally:
                    scope.__exit__(*sys.exc_info())
            except BaseException as error:
                child._remember(error)
            child.terminal()
        assert recovering, "writer did not reach its required actual crash boundary"
        assert child.input.closed and child.lease.closed and child.guard.handler_state == "RESTORED"
        assert not child.guard.lifetime_ledger.fatal
        return 0
    finally:
        os.close(writer); child.close_output()


class ConfigurationCrashRecoveryTests(unittest.TestCase):
    def test_all_three_write_domains_recover_after_real_writer_death(self):
        from mobile_release import owned_process as owned
        from tests.unit.test_owned_process import original_command_outcomes, all_original_commands_final

        self.assertNotEqual(os.geteuid(), 0)
        fixture = Path(tempfile.mkdtemp(prefix="mrk-config-crash-")).resolve()
        outcomes, safe, passed = [], True, False
        suite_result = self._outcome.result
        initial_failures = (len(suite_result.failures), len(suite_result.errors))
        try:
            with original_command_outcomes() as outcomes:
                for case in CASES:
                    for point in POINTS:
                        with self.subTest(case=case, point=point):
                            root = fixture / (case + "-" + point)
                            before = _fixture(root, case)
                            originals = {p: (_facts(root / p), b) for p, b in before.items()}
                            old_dirs = {str(p.relative_to(root)): _facts(p)[:5]
                                        for p in root.rglob("*") if stat.S_ISDIR(p.lstat().st_mode)}
                            committed = point in ("committed", "cleanup")
                            for action, code in (("crash-" + point, -signal.SIGKILL), ("recover", 0)):
                                self.assertTrue(not outcomes or all_original_commands_final(outcomes))
                                ordinal, safe = len(outcomes), False
                                result = owned.run_owned([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                                    "--crash-child", str(root), case, action], cwd=root,
                                    environ={"PATH": "/usr/bin:/bin", "HOME": str(fixture), "TMPDIR": str(fixture),
                                             "LC_ALL": "C", "LANG": "C"}, timeout=25, output_limit=1024 * 1024)
                                self.assertEqual(len(outcomes), ordinal + 1)
                                self.assertIsNotNone(outcomes[ordinal].original_finality)
                                self.assertTrue(all_original_commands_final(outcomes))
                                safe = True
                                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                                raw = json.loads((root.parent / (root.name + "-review.json")).read_bytes())
                                replacements = {p: base64.b64decode(b, validate=True) for p, b in raw.items() if b is not None}
                                for rel, new in replacements.items():
                                    p = root / rel
                                    try:
                                        self.assertTrue(stat.S_ISREG(p.lstat().st_mode))
                                        body = p.read_bytes()
                                    except FileNotFoundError:
                                        body = None
                                    if action != "recover": self.assertIn(body, (before.get(rel), new))
                                    else: self.assertEqual(body, new if committed else before.get(rel))
                                if action == "recover":
                                    frames = [json.loads(line) for line in result.stdout.splitlines()]
                                    terminal = frames[-1]["result"]
                                    self.assertEqual((terminal["effect"], terminal["journal"], terminal["resources"], terminal["reason"]),
                                                     ("committed" if committed else "not_started" if point == "preparing" else "rolled_back",
                                                      "clean", "settled", "none"))
                            for rel, original in originals.items():
                                if rel not in replacements:
                                    self.assertEqual((_facts(root / rel), (root / rel).read_bytes()), original)
                            self.assertFalse(any((root / name).exists() for name in tx.ALL_STATE_NAMES))
                            census = {str(p.relative_to(root)): p.lstat() for p in root.rglob("*")}
                            self.assertTrue(all(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode) for s in census.values()))
                            actual = {p for p, s in census.items() if stat.S_ISREG(s.st_mode)}
                            self.assertEqual(actual, set(before) | (set(replacements) if committed else set()))
                            directories = {p for p, s in census.items() if stat.S_ISDIR(s.st_mode)}
                            expected_dirs = set(old_dirs)
                            if committed:
                                for rel in replacements:
                                    expected_dirs.update(str(p) for p in Path(rel).parents if p != Path("."))
                            self.assertEqual(directories, expected_dirs)
                            for rel, original in old_dirs.items():
                                self.assertEqual(_facts(root / rel)[:5], original)
                self.assertEqual(len(outcomes), 24)
                passed = (len(suite_result.failures), len(suite_result.errors)) == initial_failures
        finally:
            if not safe or not all_original_commands_final(outcomes) or not passed:
                self.fail("Crash/recovery evidence preserved in the private test fixture")
            shutil.rmtree(fixture)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--crash-child":
        raise SystemExit(_child(Path(sys.argv[2]), sys.argv[3], sys.argv[4]))
    unittest.main()
