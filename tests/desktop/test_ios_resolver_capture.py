"""Real, host-safe CI capture children; no Xcode, signing, Store or network."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).absolute().parents[2]
SPEC = importlib.util.spec_from_file_location("ci_bounded_output", ROOT / "desktop/tools/ci_bounded_output.py")
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class IOSResolverCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.children = []
        self.popen = subprocess.Popen
        self.environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.root), "LANG": "C"}

    def run_child(self, code, *, name="output.log", timeout=3, limit=256 * 1024):
        def record(*args, **kwargs):
            child = self.popen(*args, **kwargs)
            self.children.append(child)
            return child
        with mock.patch.object(capture.subprocess, "Popen", side_effect=record):
            return capture.run_bounded([sys.executable, "-I", "-S", "-c", code],
                                       capture_path=self.root / name, cwd=self.root,
                                       env=self.environment, timeout=timeout, limit=limit)

    def assert_joined(self):
        self.assertTrue(self.children)
        for child in self.children:
            self.assertIsNotNone(child.returncode)
            self.assertEqual(child.wait(timeout=0), child.returncode)
            self.assertTrue(child.stdout.closed)

    def test_private_file_is_not_the_output_capture(self):
        write = "from pathlib import Path; Path('private-file').write_bytes(b'x' * (512 * 1024)); print('done')"
        # The former workflow limit is inherited by the real child. It limits
        # every private file, not merely the selected stdout capture.
        old = "import resource; resource.setrlimit(resource.RLIMIT_FSIZE, (262144, 262144)); " + write
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_child(old, name="old.log")
        self.assertLessEqual((self.root / "private-file").stat().st_size, 262144)
        self.assertEqual(self.run_child(write), 0)
        self.assertEqual((self.root / "private-file").stat().st_size, 512 * 1024)
        self.assertEqual((self.root / "output.log").read_bytes(), b"done\n")
        self.assert_joined()

    def test_output_overflow_keeps_capped_prefix_and_reaps_original(self):
        with self.assertRaisesRegex(ValueError, "capture-output-bound"):
            self.run_child("import os,time; os.write(1,b'x' * (512 * 1024)); time.sleep(10)")
        self.assertEqual((self.root / "output.log").read_bytes(), b"x" * (256 * 1024))
        self.assert_joined()

    def test_timeout_keeps_prefix_and_reaps_original(self):
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_child("import os,time; os.write(1,b'before-timeout'); time.sleep(10)", timeout=.3)
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual((self.root / "output.log").read_bytes(), b"before-timeout")
        self.assert_joined()

    def test_eof_is_not_child_completion(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_child("import os,time; os.close(1); os.close(2); time.sleep(10)", timeout=.3)
        self.assertEqual((self.root / "output.log").read_bytes(), b"")
        self.assert_joined()

    def test_nonzero_and_capture_collision_preserve_original_facts(self):
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            self.run_child("import os; os.write(2,b'original-error'); raise SystemExit(7)")
        self.assertEqual(caught.exception.returncode, 7)
        self.assertEqual((self.root / "output.log").read_bytes(), b"original-error")
        with self.assertRaises(FileExistsError):
            self.run_child("raise SystemExit(0)")
        self.assertEqual(len(self.children), 1)
        self.assertEqual((self.root / "output.log").read_bytes(), b"original-error")
        self.assert_joined()

    def test_child_exit_does_not_settle_a_retained_pipe(self):
        # An independently held writer models the real exit-before-EOF case
        # without starting an unowned descendant or inventing child finality.
        read_fd, write_fd = os.pipe()
        def record(*args, **kwargs):
            self.assertIs(kwargs["stdout"], subprocess.PIPE)
            kwargs["stdout"] = write_fd
            child = self.popen(*args, **kwargs)
            child.stdout = os.fdopen(read_fd, "rb")
            self.children.append(child)
            return child
        try:
            with mock.patch.object(capture.subprocess, "Popen", side_effect=record):
                with self.assertRaises(subprocess.TimeoutExpired):
                    capture.run_bounded([sys.executable, "-I", "-S", "-c", "print('finished')"],
                                        capture_path=self.root / "output.log", cwd=self.root,
                                        env=self.environment, timeout=.3, limit=256 * 1024)
        finally:
            os.close(write_fd)
            if not self.children:
                os.close(read_fd)
        self.assertEqual(self.children[0].returncode, 0)
        self.assertEqual((self.root / "output.log").read_bytes(), b"finished\n")
        self.assert_joined()

    def test_cleanup_error_never_replaces_primary_or_passes(self):
        original_waits = []
        def record(*args, **kwargs):
            child = self.popen(*args, **kwargs)
            self.children.append(child)
            wait = child.wait
            original_waits.append(wait)
            def lost_return(*args, **kwargs):
                wait(*args, **kwargs)  # Actual original kill/wait, not fake exit.
                raise OSError("synthetic-lost-wait-return")
            child.wait = lost_return
            return child
        try:
            with mock.patch.object(capture.subprocess, "Popen", side_effect=record):
                with self.assertRaisesRegex(ValueError, "capture-output-bound") as caught:
                    capture.run_bounded([sys.executable, "-I", "-S", "-c",
                                         "import os,time; os.write(1,b'x'*4096); time.sleep(10)"],
                                        capture_path=self.root / "output.log", cwd=self.root,
                                        env=self.environment, timeout=3, limit=32)
        finally:
            for child, wait in zip(self.children, original_waits):
                child.wait = wait
        self.assertIn("capture-cleanup:OSError", caught.exception.__notes__)
        self.assertEqual((self.root / "output.log").read_bytes(), b"x" * 32)
        self.assert_joined()



if __name__ == "__main__":
    unittest.main()
