"""Read-only pin preflight regressions; no service, core or package execution."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import re
import unittest
from unittest.mock import call, patch


SOURCE = Path(__file__).absolute().parents[2]
ENTRY = SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py"
spec = importlib.util.spec_from_file_location("lifecycle_source_pins", ENTRY)
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)


class LifecycleSourcePinTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNone(L._D)
        self.assertIsNone(L._OWNER)
        self.forbidden = []
        for target, name in (
            (L, "_context"), (L, "_modules"), (L, "copy_pinned"),
            (L.subprocess, "Popen"),
        ):
            guard = patch.object(target, name, side_effect=AssertionError("Not an inert source check"))
            self.forbidden.append(guard.start())
            self.addCleanup(guard.stop)

    def tearDown(self):
        for guard in self.forbidden:
            guard.assert_not_called()
        self.assertIsNone(L._D)
        self.assertIsNone(L._OWNER)

    def test_current_nine_pins_use_bounded_original_reads(self):
        expected = {"src/mobile_release/" + name: pin for name, pin in L.CORE_PINS.items()}
        expected["desktop/tools/conventional_runtime_data.py"] = L.DATA_PIN
        self.assertEqual(len(expected), 9)
        with patch.object(L, "record", wraps=L.record) as reads:
            self.assertIsNone(L.check_source_pins(SOURCE))
        self.assertEqual(reads.call_args_list, [
            call(SOURCE / name, size) for name, (size, _) in expected.items()
        ])

    def test_historical_stale_size_refuses_before_owner_initialization(self):
        old = (169926, "075fa6e9838017feb6a1716ab3a75074e3a65dffe8b217613aff7e87c0201f68")
        with patch.dict(L.CORE_PINS, {"_command_process.py": old}):
            with self.assertRaises(L.Refused) as error:
                L.check_source_pins(SOURCE)
        self.assertEqual(str(error.exception), "Lifecycle source pin differs: src/mobile_release/_command_process.py")

    def test_same_size_wrong_digest_refuses_core_and_data(self):
        for relative, context in (
            ("src/mobile_release/_command_process.py",
             patch.dict(L.CORE_PINS, {"_command_process.py": (L.CORE_PINS["_command_process.py"][0], "0" * 64)})),
            ("desktop/tools/conventional_runtime_data.py", patch.object(L, "DATA_PIN", (L.DATA_PIN[0], "0" * 64))),
        ):
            with self.subTest(relative=relative), context:
                with self.assertRaises(L.Refused) as error:
                    L.check_source_pins(SOURCE)
                self.assertEqual(str(error.exception), "Lifecycle source pin differs: " + relative)

    def test_read_error_reports_only_fixed_source_name(self):
        with patch.object(L, "record", side_effect=OSError("private host detail")):
            with self.assertRaises(L.Refused) as error:
                L.check_source_pins(SOURCE)
        self.assertEqual(str(error.exception), "Lifecycle source pin differs: src/mobile_release/__init__.py")
        self.assertTrue(error.exception.__suppress_context__)

    def test_all_four_entrypoints_fail_fast_and_producer_pin_matches(self):
        text = (SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text()
        driver = ast.parse(text)
        first_admission = {
            "verify_installed_shell_compile": "package_inputs",
            "verify": "package_inputs",
            "verify_installed": "installed_u_inputs",
            "verify_installed_shell": "installed_u_inputs",
        }
        for name, next_call in first_admission.items():
            with self.subTest(entrypoint=name):
                function = next(node for node in driver.body if isinstance(node, ast.FunctionDef) and node.name == name)
                checks = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Attribute) and node.func.attr == "check_source_pins"]
                self.assertEqual(len(checks), 1)
                check = checks[0]
                self.assertEqual(ast.unparse(check), 'local(\'ubuntu_publication_lifecycle\').check_source_pins(source)')
                enclosing = next(node.body for node in ast.walk(function) if isinstance(node, ast.Try)
                                 and any(isinstance(item, ast.Expr) and item.value is check for item in node.body))
                index = next(i for i, node in enumerate(enclosing) if isinstance(node, ast.Expr) and node.value is check)
                previous = ast.get_source_segment(text, enclosing[index - 1])
                self.assertIn('D.need(D.file_record(source / "desktop/tools/ubuntu_publication_lifecycle.py"', previous)
                self.assertIn('["sha256"] == entry_sha', previous)
                admissions = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                              and isinstance(node.func, ast.Name) and node.func.id == next_call]
                self.assertEqual(len(admissions), 1)
                self.assertLess(check.lineno, admissions[0].lineno)
        workflow = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        branches = re.findall(r"^    branches: \[([^\n]*)\]$", workflow, re.MULTILINE)
        self.assertEqual(len(branches), 1)
        profiles = {
            "verify/desktop-ubuntu-publication": ("  publisher-helpers:", 1),
            "verify/desktop-installed-shell, verify/desktop-shell-host-metadata": ("  compile:", 2),
        }
        self.assertIn(branches[0], profiles, "Unknown or mixed publication route")
        job_header, pin_count = profiles[branches[0]]
        jobs = workflow.split("\njobs:\n")
        self.assertEqual(len(jobs), 2)
        self.assertEqual(re.findall(r"^  \S.*$", jobs[1], re.MULTILINE), [job_header])
        pins = re.findall(r"^[ \t]+MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256:[ \t]*(.*)$", workflow, re.MULTILINE)
        self.assertEqual(pins, ["'" + hashlib.sha256(ENTRY.read_bytes()).hexdigest() + "'"] * pin_count)


if __name__ == "__main__":
    unittest.main()
