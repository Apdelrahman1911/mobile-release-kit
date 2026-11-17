"""Real edit-pipe loss around COMMITTED, on disposable source fixtures (#65).

The existing observation shim pauses the genuine main-thread engine before or
after its commit. This parent closes the actual stdin pipe, then reads the
original cancellation/settlement records and checks the project independently.
No installed GUI, Rust channel, helper or production qualification is claimed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from mobile_release import init_transaction as tx
from mobile_release._desktop_edit_protocol import PROTOCOL
from tests.desktop.test_configuration_crash_recovery import _draft, _facts, _fixture

REPO = Path(__file__).resolve().parents[2]
SESSION = "0123456789abcdef0123456789abcdef"


@unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"),
                     "local atomic-rename filesystem required")
class ConfigurationTransportInterruptionTests(unittest.TestCase):
    def exercise(self, case):
        fixture = Path(tempfile.mkdtemp(prefix="mrk-config-eof-")).resolve()
        root = fixture / "project"
        before = _fixture(root, "configuration")
        untouched = {p: (_facts(root / p), b) for p, b in before.items()
                     if p not in {"release/mobile-release.json", ".gitignore"}}
        original_targets = {p: _facts(root / p) for p in ("release/mobile-release.json", ".gitignore")}
        process = None
        passed = False
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", str(REPO / "tests/native_desktop_config_eof.py"),
                 str(REPO / "src"), case],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=root, env={"PATH": "/usr/bin:/bin", "HOME": str(fixture),
                               "TMPDIR": str(fixture), "LC_ALL": "C", "LANG": "C"},
                start_new_session=True,
            )
            frames, records = [], []
            disconnected = False
            approved_ignore = None
            seen = {"stdout": 0, "stderr": 0}
            end = time.monotonic() + 25

            def send(sequence, operation, params):
                request = {"protocol": PROTOCOL, "session": SESSION, "seq": sequence,
                           "op": operation, "params": params}
                process.stdin.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
                process.stdin.flush()

            send(0, "open", {"root": str(root)})
            with selectors.DefaultSelector() as selector:
                pending = {"stdout": bytearray(), "stderr": bytearray()}
                for name in pending:
                    stream = getattr(process, name)
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    self.assertLess(time.monotonic(), end, "original edit did not settle within 25s")
                    for key, _ in selector.select(min(0.1, max(0.0, end - time.monotonic()))):
                        name = key.data
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            self.assertFalse(pending[name], "partial original response at EOF")
                            continue
                        seen[name] += len(chunk)
                        self.assertLessEqual(seen[name], 1024 * 1024)
                        pending[name].extend(chunk)
                        while b"\n" in pending[name]:
                            line, _, tail = pending[name].partition(b"\n")
                            pending[name] = bytearray(tail)
                            if name == "stderr":
                                text = line.decode("ascii")
                                records.append(text)
                                if " boundary=" in text:
                                    self.assertFalse(disconnected)
                                    process.stdin.close()  # Actual owner pipe EOF, not a cancellation flag.
                                    disconnected = True
                                continue
                            frame = json.loads(line)
                            self.assertEqual((frame["protocol"], frame["session"]), (PROTOCOL, SESSION))
                            frames.append(frame)
                            if len(frames) == 1:
                                result = frame["result"]
                                send(1, "prepare", {"revision": result["revision"],
                                     "expectedBase": result["base"], "draft": _draft()})
                            elif len(frames) == 2:
                                additions = frame["result"]["view"]["ignoreAdditions"]
                                approved_ignore = before[".gitignore"] + b"".join(
                                    line.encode("utf-8") + b"\n" for line in additions)
                                send(2, "apply", {"planToken": frame["result"]["planToken"]})
            self.assertEqual(process.wait(timeout=max(0.01, end - time.monotonic())), 0)
            self.assertTrue(disconnected)
            self.assertEqual(len(frames), 3)
            self.assertEqual([f["seq"] for f in frames], [0, 1, 2])
            self.assertEqual([f["kind"] for f in frames], ["opened", "prepared", "terminal"])
            result = frames[-1]["result"]
            committed = case == "postcommit-eof"
            self.assertEqual((result["effect"], result["journal"], result["resources"], result["reason"]),
                             ("committed" if committed else "rolled_back", "clean", "settled", "cancelled"))
            self.assertEqual(result["planToken"], frames[1]["result"]["planToken"])
            self.assertEqual(len(records), 2)
            prefix = "MRK_CONFIG_EOF_V1 " + case
            self.assertEqual(records[0], prefix + " boundary=" +
                             ("after-durable-COMMITTED" if committed else "before-COMMITTED"))
            fields = dict(item.split("=", 1) for item in records[1][len(prefix) + 1:].split())
            self.assertEqual(fields, {
                "eof": "1", "nonempty": "0", "readErrors": "0",
                "checkpoint": "descriptor-close" if committed else "publisher-entry",
                "applied": "1", "committed": "1" if committed else "0",
                "rolledBack": "0" if committed else "1",
                "terminal": "COMMITTED" if committed else "ROLLED_BACK",
                "durable": "1", "recovery": "1",
                "clean": "1", "settled": "1", "cancelled": "1",
            })
            actual = (root / "release/mobile-release.json").read_bytes()
            if committed:
                self.assertEqual(json.loads(actual), _draft())
            else:
                self.assertEqual(actual, before["release/mobile-release.json"])
            self.assertIsNotNone(approved_ignore)
            self.assertEqual((root / ".gitignore").read_bytes(),
                             approved_ignore if committed else before[".gitignore"])
            for rel, original in original_targets.items():
                current = _facts(root / rel)
                self.assertEqual(current[2:6], original[2:6])  # Type/mode, owner, link count.
                if not committed:
                    self.assertEqual(current[:8], original[:8])  # Rename may advance ctime.
            for rel, original in untouched.items():
                self.assertEqual((_facts(root / rel), (root / rel).read_bytes()), original)
            self.assertFalse(any((root / name).exists() for name in tx.ALL_STATE_NAMES))
            self.assertEqual({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}, set(before))
            passed = True
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()  # Only this test's own child; retain fixture on failure.
                    process.wait(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            if passed:
                shutil.rmtree(fixture)
            else:
                print("Retained disposable EOF fixture: " + str(fixture), file=sys.stderr)

    def test_pipe_loss_before_commit_rolls_back_and_settles_original_resources(self):
        self.exercise("precommit-eof")

    def test_pipe_loss_after_commit_preserves_new_bytes_and_settles_original_resources(self):
        self.exercise("postcommit-eof")


if __name__ == "__main__":
    unittest.main()
