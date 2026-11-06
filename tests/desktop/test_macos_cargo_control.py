"""Focused diagnostic sink/status DATA checks; never invoke a product/compiler."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "desktop/tools/macos_cargo_control.py"
DRIVER = ROOT / "desktop/tools/macos_cargo_control.sh"
spec = importlib.util.spec_from_file_location("cargo_control_data", SOURCE)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class CargoControlDataTests(unittest.TestCase):
    def test_complete_and_overflow_drain_preserve_distinction(self):
        for body, limit in ((b"abc", 4), (b"abcdef", 4), (b"abcd", 4)):
            source, output = io.BytesIO(body), io.BytesIO()
            result = control.consume(source, output, limit)
            self.assertEqual(source.tell(), len(body))
            self.assertEqual(output.getvalue(), body[:limit])
            self.assertEqual(result["totalBytes"], len(body))
            self.assertTrue(result["eof"])
            self.assertIsNone(result["captureError"])
            self.assertEqual(result["complete"], len(body) <= limit)
            self.assertEqual(result["truncated"], len(body) > limit)

    def test_write_failure_and_short_write_still_drain(self):
        class Broken:
            def write(self, _):
                raise OSError("fixture")
        class Short:
            def write(self, body):
                return len(body) - 1
        for writer, reason in ((Broken(), "output-write-failed"), (Short(), "output-short-write")):
            source = io.BytesIO(b"x" * 150000)
            result = control.consume(source, writer, 100000)
            self.assertEqual(source.tell(), 150000)
            self.assertTrue(result["eof"])
            self.assertFalse(result["complete"])
            self.assertEqual(result["captureError"], reason)

    def test_read_failure_does_not_claim_eof(self):
        class Broken:
            def read(self, _):
                raise OSError("fixture")
        result = control.consume(Broken(), io.BytesIO(), 4)
        self.assertFalse(result["eof"])
        self.assertFalse(result["complete"])
        self.assertIsNone(result["completeStreamSha256"])

    def test_small_live_pipe_prefix_is_retained_before_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "live.log"
            observed = []
            with subprocess.Popen(["/bin/sh", "-c", "printf small; /bin/sleep 1.5"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                with log.open("wb", buffering=0) as output:
                    worker = threading.Thread(target=lambda: observed.append(control.consume(child.stdout, output)))
                    worker.start()
                    deadline = time.monotonic() + 1.0
                    while log.stat().st_size < 5 and time.monotonic() < deadline:
                        time.sleep(0.01)
                    prefix_before_eof = log.read_bytes()
                    producer_still_running = child.poll() is None
                    child.wait(timeout=3)
                    worker.join(timeout=3)
                    self.assertFalse(worker.is_alive())
                self.assertEqual(child.stderr.read(), b"")
            self.assertEqual(prefix_before_eof, b"small")
            self.assertTrue(producer_still_running)
            self.assertTrue(observed[0]["complete"])

    def test_collector_retains_log_with_torn_sidecars(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "evidence").mkdir()
            (work / "evidence/merged.log").write_bytes(b"")
            (work / "resident-image-build.log").write_bytes(b"resident done")
            (work / "shipping-image-build-started.json").write_bytes(b'{"role":')
            (work / "shipping-image-build.log").write_bytes(b"real partial shipping progress")
            (work / "shipping-image-build-original.json").write_bytes(b'{')
            result = control.collect_data(work, {})
            self.assertEqual((work / "evidence/merged.log").read_bytes(), b"real partial shipping progress")
            self.assertEqual(result["selectedLogRole"], "shipping-image-build")
            self.assertFalse(result["allDirectCommandsReturnedZeroWithCompleteCaptures"])
            self.assertLessEqual(len(control.canonical(result)), control.META_LIMIT)

    def test_collector_nonfinite_and_deep_sidecars_stay_unknown(self):
        bodies = (b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e999}',
                  b'{"value":' + b'[' * 33 + b'0' + b']' * 33 + b'}',
                  b'{"value":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sidecar.json"
            for body in bodies:
                path.write_bytes(body)
                observation = control.optional_data(path)
                self.assertIsNone(observation["value"])
                self.assertEqual(observation["state"], "partial-or-unreadable")

    def test_collector_missing_latest_log_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "evidence").mkdir()
            (work / "evidence/merged.log").write_bytes(b"")
            (work / "resident-image-build.log").write_bytes(b"resident evidence")
            (work / "shipping-image-build-started.json").write_bytes(b'{')
            result = control.collect_data(work, {})
            self.assertEqual(result["lastStartedRole"], "shipping-image-build")
            self.assertEqual(result["selectedLogRole"], "resident-image-build")
            self.assertFalse(result["allDirectCommandsReturnedZeroWithCompleteCaptures"])

    def pipeline(self, command_status, sink_status):
        # The actual checked-in Bash driver runs only /bin/sh printf/exit.
        # Fixed fixture handlers replace hosted source guards and metadata IO;
        # record uses the real draining sink DATA function.
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            fixture = """import importlib.util,json,pathlib,sys
source=pathlib.Path(SOURCE_LITERAL)
spec=importlib.util.spec_from_file_location('sink',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
action,root,role,*args=sys.argv[1:];root=pathlib.Path(root)
if action=='begin':
    (root/(role+'-command.sh')).write_text(COMMAND_LITERAL)
elif action=='returned':
    (root/'original.json').write_text(json.dumps({'status':int(args[0])}))
elif action=='record':
    with (root/'log').open('wb',buffering=0) as output: result=module.consume(sys.stdin.buffer,output,4)
    (root/'sink.json').write_text(json.dumps(result));sys.exit(SINK_STATUS)
elif action=='end':
    result=[int(v) for v in args];(root/'pipeline.json').write_text(json.dumps(result))
    sys.exit(0 if result==[0,0] else 1)
"""
            command = "command=(/bin/sh -c 'printf abcdef; exit COMMAND_STATUS')\ncommand_environment=(PATH=/usr/bin:/bin)\ncommand_cwd=/\n"
            command = command.replace("COMMAND_STATUS", str(command_status))
            fixture = fixture.replace("SOURCE_LITERAL", repr(str(SOURCE))).replace("COMMAND_LITERAL", repr(command))
            fixture = fixture.replace("SINK_STATUS", str(sink_status))
            (work / "macos_cargo_control.py").write_text(fixture)
            result = subprocess.run(["/bin/bash", str(DRIVER), "shipping-image-build", str(work), sys.executable],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(json.loads((work / "original.json").read_text())["status"], command_status)
            self.assertEqual(json.loads((work / "pipeline.json").read_text()), [command_status, sink_status])
            sink = json.loads((work / "sink.json").read_text())
            self.assertTrue(sink["eof"])
            self.assertTrue(sink["truncated"])
            self.assertEqual((work / "log").read_bytes(), b"abcd")
            self.assertEqual(result.returncode, 0 if command_status == sink_status == 0 else 1)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")

    def test_real_pipeline_preserves_original_nonzero(self):
        self.pipeline(7, 0)

    def test_real_pipeline_preserves_sink_nonzero(self):
        self.pipeline(0, 3)

    def test_real_pipeline_overflow_does_not_signal_command(self):
        self.pipeline(0, 0)


if __name__ == "__main__":
    unittest.main()
