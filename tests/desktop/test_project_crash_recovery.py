"""Real killed writers and fresh recovery on disposable public-data projects.

Run in the reviewed nonroot macOS/Linux test boundary. Signals target only
the writer's own PID, after the original transaction primitive returns. The
original process owner must settle before another writer or fixture cleanup.
This exercises the core pipeline, not installed-app/helper qualification.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--crash-child":
    _repository = Path(__file__).absolute().parents[2]
    sys.path[:0] = [str(_repository / "src"), str(_repository), str(Path(__file__).absolute().parent)]

from mobile_release import init_transaction as tx
from mobile_release import project_identity as identity
from test_metadata_images import native_row
from test_metadata_images_recovery import FOLDER, KEPT, NEW as IMAGE_NEW, OLD as IMAGE_OLD, SIBLING
from test_metadata_text import config
from tests.unit.test_project_identity import ANDROID, IOS, NEW, OLD, PBX, android, ios

SESSION = "0123456789abcdef0123456789abcdef"
POINTS = ("preparing", "replacement", "committed", "cleanup")


def _facts(path):
    v = path.lstat()
    return (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_gid, v.st_nlink,
            v.st_size, v.st_mtime_ns, v.st_ctime_ns)


def _fixture(root, case):
    if case == "images":
        before = {"release/mobile-release.json": json.dumps(config()).encode(),
                  FOLDER + "/01.png": IMAGE_OLD, FOLDER + "/03.png": KEPT,
                  FOLDER + "/04.png": SIBLING}
        expected = {FOLDER + "/01.png": IMAGE_NEW[0], FOLDER + "/02.png": IMAGE_NEW[1]}
        before[FOLDER + "/02.png"] = None
        source = root.parent / (root.name + "-sources")
        source.mkdir()
        for i, data in enumerate(IMAGE_NEW):
            (source / f"{i}.png").write_bytes(data)
    else:
        before = android() if case == "android" else ios()
        targets = (identity.CONFIG_PATH, "app/build.gradle.kts" if case == "android" else PBX)
        expected = {p: before[p].replace(OLD.encode(), NEW.encode()) for p in targets}
    before[".gitignore"] = ("\n".join(tx.IGNORE_LINES) + "\n").encode()
    before["unrelated.txt"] = b"Do not replace, remove or rewrite this original.\n"
    for path, data in before.items():
        if data is None:
            continue
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o640)
    return before, expected


def _child(root, case, mode):
    from mobile_release import _desktop_edit_engine as engine
    from mobile_release._desktop_edit_control import EditInput
    from mobile_release.cancellation import CleanupScope

    assert case in {"images", "android", "ios"}
    assert mode in {"crash-" + p for p in POINTS} | {"recover-old", "recover-new", "recover-preparing"}
    assert root.is_absolute() and os.geteuid() != 0
    recovering = mode.startswith("recover-")
    child = engine._Engine(time.monotonic(), domain="metadata_images" if case == "images" else "project_identity")
    reader, writer = os.pipe()
    os.dup2(reader, 0)
    os.close(reader)
    request, move = EditInput.request, tx.InitWorkspace._move
    state_move, unlink = tx.InitWorkspace._state_move, tx.InitWorkspace._unlink

    def feed(control, sequence, session):
        assert control is child.input and session in {None, SESSION}
        if sequence == 0:
            v = root.stat()
            params = {"root": str(root), "registeredIdentity": {"device": str(v.st_dev), "inode": str(v.st_ino),
                "mode": v.st_mode, "uid": v.st_uid, "gid": v.st_gid},
                "intent": "recover" if recovering else "import" if case == "images" else "edit"}
            if not recovering:
                if case == "images":
                    rows, originals = [], []
                    for i in range(3):
                        source = root.parent / (root.name + "-sources") / f"{i}.png"
                        v = source.stat()
                        rows.append(native_row(source.read_bytes(), identity=f"{i + 1:032x}", name=f"{i + 1:02}.png"))
                        originals.append({"device": str(v.st_dev), "inode": str(v.st_ino)})
                    params.update(platform="android", locale="en-US", assetType="phoneScreenshots",
                                  images=rows, protectedSources=[], protectedObjects=originals)
                else:
                    params["selection"] = (ANDROID if case == "android" else IOS).as_dict()
            op = "open"
        elif sequence == 1:
            checkout = child.authority
            params = {"revision": checkout.revision}
            if case == "images":
                params.update(expectedBaseline=checkout.baseline, choices=[] if recovering else
                    [{"itemId": f"{i + 1:032x}", "replaceExisting": i == 0} for i in range(3)])
            else:
                params["intent"] = "recover" if recovering else "edit"
                if not recovering:
                    params.update(desiredIdentity=NEW, identityIntent="new-application")
            op = "prepare"
        else:
            assert sequence == 2
            params = {"planToken": child.authority.token}
            if case != "images":
                params["intent"] = "recover" if recovering else "edit"
            op = "apply"
        raw = json.dumps({"protocol": child.input.protocol, "session": SESSION, "seq": sequence,
                          "op": op, "params": params}, separators=(",", ":")).encode() + b"\n"
        assert len(raw) < 4096 and os.write(writer, raw) == len(raw)
        return request(control, sequence, session)

    def moved(w, source_fd, source, destination_fd, destination, expected, **kwargs):
        value = move(w, source_fd, source, destination_fd, destination, expected, **kwargs)
        if not recovering and (mode == "crash-replacement" and source.startswith("new-") or
                               mode == "crash-committed" and destination == "COMMITTED"):
            os.kill(os.getpid(), signal.SIGKILL)
        return value

    def state_moved(w, old, new):
        if mode == "crash-preparing" and (old, new) == w._state_names[:2]:
            os.kill(os.getpid(), signal.SIGKILL)
        return state_move(w, old, new)

    def unlinked(w, name, **kwargs):
        value = unlink(w, name, **kwargs)
        if mode == "crash-cleanup" and name.startswith("old-"):
            os.kill(os.getpid(), signal.SIGKILL)
        return value

    scope = CleanupScope(child.guard, child.cleanup, owns_cancellation=True, first_primary=True)
    try:
        with patch.object(EditInput, "request", feed), patch.object(tx.InitWorkspace, "_move", moved), \
             patch.object(tx.InitWorkspace, "_state_move", state_moved), patch.object(tx.InitWorkspace, "_unlink", unlinked):
            try:
                try:
                    with scope:
                        child.run()
                finally:
                    scope.__exit__(*sys.exc_info())
            except BaseException as error:
                child._remember(error)
            child.terminal()
        assert recovering, "writer never reached the original crash boundary"
        assert child.input.closed and child.lease.closed and child.guard.handler_state == "RESTORED"
        assert not child.guard.lifetime_ledger.fatal
        return 0
    finally:
        os.close(writer)
        child.close_output()


class ProjectCrashRecoveryTests(unittest.TestCase):
    def test_images_android_and_ios_identity_recover_after_actual_writer_death(self):
        from mobile_release import owned_process as owned
        from tests.unit.test_owned_process import original_command_outcomes, all_original_commands_final

        self.assertNotEqual(os.geteuid(), 0)
        fixture = Path(tempfile.mkdtemp(prefix="mrk-project-crash-"))
        outcomes, safe = [], True
        try:
            with original_command_outcomes() as outcomes:
                for case in ("images", "android", "ios"):
                    for point in POINTS:
                        with self.subTest(case=case, point=point):
                            root = fixture / (case + "-" + point)
                            before, replacements = _fixture(root, case)
                            committed = point in {"committed", "cleanup"}
                            mode = "recover-new" if committed else "recover-preparing" if point == "preparing" else "recover-old"
                            unrelated = {p: (_facts(root / p), data) for p, data in before.items()
                                         if p not in replacements and data is not None}
                            for action, expected_return in (("crash-" + point, -signal.SIGKILL), (mode, 0)):
                                self.assertTrue(not outcomes or all_original_commands_final(outcomes))
                                ordinal, safe = len(outcomes), False
                                result = owned.run_owned([sys.executable, "-I", "-S", "-B", str(Path(__file__).absolute()),
                                    "--crash-child", str(root), case, action], cwd=root,
                                    environ={"PATH": "/usr/bin:/bin", "HOME": str(fixture), "TMPDIR": str(fixture),
                                             "LC_ALL": "C", "LANG": "C"}, timeout=20, output_limit=65536)
                                self.assertEqual(len(outcomes), ordinal + 1)
                                original = outcomes[ordinal]
                                self.assertIsNotNone(original.original_finality)
                                safe = True
                                self.assertEqual(original.result_integrity, "complete")
                                self.assertTrue(original.create_w.retired and original.run_tool.retired)
                                self.assertEqual((original.returncode, result.returncode), (expected_return, expected_return), result.stdout)
                                self.assertEqual(result.stderr, "")
                                frames = [json.loads(line) for line in result.stdout.splitlines()]
                                self.assertEqual([f["kind"] for f in frames], ["opened", "prepared"] if action.startswith("crash-") else
                                                 ["opened", "prepared", "terminal"])
                                if not action.startswith("crash-"):
                                    terminal = frames[2]["result"]
                                    self.assertEqual((terminal["effect"], terminal["journal"], terminal["resources"], terminal["reason"]),
                                                     ("committed" if committed else "not_started" if point == "preparing" else "rolled_back",
                                                      "clean", "settled", "none"))
                                for path, new in replacements.items():
                                    target = root / path
                                    if target.exists():
                                        self.assertIn(target.read_bytes(), (before[path], new))
                            for path, new in replacements.items():
                                expected = new if committed else before[path]
                                self.assertEqual((root / path).read_bytes() if (root / path).exists() else None, expected)
                            for path, (facts, data) in unrelated.items():
                                self.assertEqual((_facts(root / path), (root / path).read_bytes()), (facts, data))
                            self.assertFalse(any((root / name).exists() for name in tx.ALL_STATE_NAMES))
                self.assertEqual(len(outcomes), 24)
        finally:
            if not safe or not all_original_commands_final(outcomes):
                self.fail("writer lifetime unknown; preserve private fixture")
            shutil.rmtree(fixture)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--crash-child":
        raise SystemExit(_child(Path(sys.argv[2]), sys.argv[3], sys.argv[4]))
    unittest.main()
