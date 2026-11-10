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


class MemoryLifetimeContracts(unittest.TestCase):
    def binding(self):
        return dict(job="write-diagnostic", inputPath=Path("/private/memory-DATA/input"),
            packageBody=b"p"*100, producerBody=b"d", signatureBody=b"s", sourceBytes=1000,
            inputFiles={"a": (b"input", 0o444)}, controlBodies={"census":b"c", "write":b"w", "recovery":b"r"})

    def packages(self, sizes):
        labels = dict(cut="write", frontier="frontier", completed="completed", recovery="recovery")
        return {role: dict(path="/private/memory-DATA/Fresh-"+label+".pkg", bytes=size, sha256="a"*64)
                for (role,label),size in zip(labels.items(), sizes)}

    def test_disk_package_growth_does_not_accumulate_live_memory(self):
        first=self.binding();second=dict(first,builtPackageBytes={"write":10000000,"frontier":20000000})
        self.assertEqual(r.control_build_fixed_bytes(first),r.control_build_fixed_bytes(second))
        small=r.route_resource_quote(first,self.packages((10,20,30,400)))
        large=r.route_resource_quote(first,self.packages((100,200,300,400)))
        self.assertEqual(small["memoryBytes"],large["memoryBytes"])
        self.assertGreater(large["diskBytes"],small["diskBytes"])
        self.assertEqual(large["installerCalls"],4)
        with self.assertRaises(r.Refused):
            r.route_resource_quote(dict(first,sourceBytes=3*1024**3),self.packages((10,20,30,400)))

    def test_memory_boundary_still_refuses_insufficient_actual_capacity(self):
        spec=importlib.util.spec_from_file_location("actual_resource_guard",HERE.parent/"desktop/tools/macos_fixed_carrier_resume.py")
        resource=importlib.util.module_from_spec(spec);spec.loader.exec_module(resource)
        required=r.route_resource_quote(self.binding(),self.packages((10,20,30,400)))["memoryBytes"]
        self.assertFalse(resource.resource_admission_data(required-1,required,100,100)["memorySufficient"])
        self.assertTrue(resource.resource_admission_data(required,required,100,100)["memorySufficient"])
        self.assertFalse(resource.resource_admission_data(required,required,99,100)["diskSufficient"])

    def test_carrier_body_is_released_only_after_known_detach(self):
        from types import SimpleNamespace
        from unittest import mock
        import time
        for succeeds in (True,False):
            with self.subTest(succeeds=succeeds):
                carrier=object.__new__(r.Carrier)
                carrier.members={"fixture.pkg":b"retained DATA"}
                carrier.detached=False;carrier.cleanup_grace_entered=False;carrier.label="cut";carrier.device="DATA-only"
                carrier.op=SimpleNamespace(fresh_deadline=time.monotonic_ns()+300*10**9,
                    work=Path("/private/memory-DATA"),outputs=SimpleNamespace(publish=lambda *args:None))
                carrier.book=SimpleNamespace(finish=lambda:True)
                carrier.mount=SimpleNamespace(exists=lambda:False,is_symlink=lambda:False)
                carrier.post=lambda:self.assertTrue(carrier.members)
                def detach(*args):
                    self.assertTrue(carrier.members)
                    if not succeeds:raise r.Refused("original-nonzero")
                carrier.call=detach
                with mock.patch.object(r.time,"sleep",lambda _:None):
                    if succeeds:carrier.detach()
                    else:
                        with self.assertRaises(r.Refused):carrier.detach()
                self.assertEqual(carrier.detached,succeeds)
                self.assertEqual(bool(carrier.members),not succeeds)


if __name__ == "__main__":
    unittest.main()
