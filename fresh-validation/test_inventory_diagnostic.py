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


if __name__ == "__main__":
    unittest.main()
