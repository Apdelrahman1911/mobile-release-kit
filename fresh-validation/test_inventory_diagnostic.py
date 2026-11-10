"""Diagnostic DATA contracts; no root paths, app execution or Installer calls."""
import importlib.util
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("inventory_diagnostic_runner", HERE / "fresh_hosted_runner.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class DiagnosticContracts(unittest.TestCase):
    def test_completed_input_request_is_a_literal_not_shell_input(self):
        scripts = {"diagnostic-recovery-postinstall": (HERE / "scripts/diagnostic-recovery-postinstall").read_bytes()}
        request = "1234567890abcdef" * 2
        body = r.control_script(scripts, "recovery", request)
        self.assertIn(("MobileReleaseKit-Request-" + request + ".pkg").encode(), body)
        self.assertNotIn(b"@REQUEST@", body)
        parsed = subprocess.run(["/bin/sh", "-n"], input=body, capture_output=True, timeout=5)
        self.assertEqual((parsed.returncode, parsed.stdout, parsed.stderr), (0, b"", b""))
        for wrong in (None, True, "", "0" * 32, "A" * 32, "a" * 31, "a" * 33,
                      "$(touch /tmp/unwanted)", "a" * 31 + "\n", "../Install.pkg"):
            with self.subTest(wrong=wrong), self.assertRaises(r.Refused):
                r.control_script(scripts, "recovery", wrong)
        with self.assertRaises(r.Refused):
            r.control_script({"diagnostic-recovery-postinstall": b"@REQUEST@@REQUEST@"}, "recovery", request)

    def test_capacity_charges_the_diagnostic_package_on_the_actual_carrier(self):
        bind = dict(job="write-diagnostic", inputPath=Path("/private/diagnostic/input"),
                    packageBody=b"p" * 100, producerBody=b"d", signatureBody=b"s",
                    inputFiles={"a": (b"i" * 100, 0o444)},
                    controlBodies={"census": b"c", "write": b"w", "recovery": b"r"})
        labels = dict(cut="write", frontier="frontier", completed="completed", recovery="recovery")
        packages = {role: dict(path=str(bind["inputPath"].parent / ("Fresh-" + label + ".pkg")),
                              bytes=size, sha256="a" * 64)
                    for (role, label), size in zip(labels.items(), (100, 200, 300, 400))}
        quote = r.route_resource_quote(bind, packages)
        self.assertEqual(quote["carrierBytes"], dict(cut=202, frontier=302, completed=402, ordinary=502))
        self.assertEqual(quote["installerCalls"], 4)
        self.assertEqual(quote["postCutPackageBuilds"], 0)
        self.assertFalse(quote["capacityIsReservation"])
        for missing in packages:
            with self.subTest(missing=missing), self.assertRaises(r.Refused):
                r.route_resource_quote(bind, {k: v for k, v in packages.items() if k != missing})
        oversized = {k: dict(v, bytes=512 * 1024 * 1024) for k, v in packages.items()}
        with self.assertRaises(r.Refused):
            r.route_resource_quote(bind, oversized)
        for job in ("write-recovery", "torn-refusal"):
            with self.assertRaises(r.Refused):
                r.route_resource_quote(dict(bind, job=job), packages)


class DiagnosticCollectorContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("actual_signed_product_stager", HERE.parent / "desktop/tools/stage_macos_installed.py")
        cls.stager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.stager)

    def fixture(self):
        from types import SimpleNamespace
        binding = dict(job="write-diagnostic", runId="123", runAttempt="1", package={"sha256": "a" * 64})
        correlation = r.diagnostic_recovery_correlation(binding, Path("/Volumes/MRK-Install-123/Fresh-recovery.pkg"), {"sha256": "b" * 64})
        native = b'2026-11-10 package_script_service: ./postinstall: MRK_RECOVERY_DIAGNOSTIC={"schemaVersion":1,"reason":"original-correspondence","check":null,"comparison":null}\n'
        refused = b'2026-11-10 package_script_service: ./postinstall: MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=' + b'a' * 64 + b';exit=1;originals=1;native=1;timely=1;unknown=0\n'
        body = b'unrelated system message\n' + native + refused
        published = {}
        def publish(path, data):
            self.assertNotIn(path.name, published)
            published[path.name] = data
        op = SimpleNamespace(work=Path("/private/diagnostic-DATA"), outputs=SimpleNamespace(publish=publish))
        return correlation, native + refused, body, op, published

    def test_actual_parser_accepts_production_binding_and_retains_native_failure(self):
        correlation, native, body, op, published = self.fixture()
        r.publish_diagnostic_log(op, self.stager, body, correlation, {"fixture": "DATA"}, 0)
        self.assertEqual(published["diagnostic-recovery-native-context.log"], native)
        self.assertNotIn(b'unrelated system message', published["diagnostic-recovery-selected-packagekit.log"])
        self.assertIn(b'MRK_MACOS_INSTALL_COMPLETED_REFUSED=', published["diagnostic-recovery-selected-packagekit.log"])
        self.assertEqual(correlation["packageKind"], "ordinary")
        facts = r.document(published["diagnostic-recovery-window-facts.json"])
        self.assertEqual((facts["nativeBytes"], facts["nativeSha256"]), (len(native), r.sha(native)))
        self.assertTrue(facts["diagnosticOnly"])

    def test_real_missing_field_failure_preserves_bytes_before_parser_raises(self):
        correlation, native, body, op, published = self.fixture()
        del correlation["packageKind"]
        with self.assertRaisesRegex(KeyError, "packageKind"):
            r.publish_diagnostic_log(op, self.stager, body, correlation, {"fixture": "DATA"}, 0)
        self.assertEqual(published["diagnostic-recovery-native-context.log"], native)
        self.assertIn("diagnostic-recovery-window-facts.json", published)
        self.assertNotIn("diagnostic-recovery-selected-packagekit.log", published)
        with self.assertRaises(r.Refused):
            r.diagnostic_native_lines(self.stager, body[:-1])
        with self.assertRaises(r.Refused):
            r.diagnostic_native_lines(self.stager, native * 3)


if __name__ == "__main__":
    unittest.main()
