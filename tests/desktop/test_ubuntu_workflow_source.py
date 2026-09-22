"""Pure source contracts: never import or execute hosted DATA provisioning."""

import ast
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[2]
WORKFLOW = SOURCE / ".github/workflows/desktop-ubuntu-publication.yml"
DRIVER = SOURCE / "desktop/tools/ci_ubuntu_publication.py"
PROVISIONER = "desktop/tools/prepare_hosted_ubuntu_data.py"


class HostedWorkflowSource(unittest.TestCase):
    def test_workflow_fits_its_actual_original_source_record_bound(self):
        module = ast.parse(DRIVER.read_text())
        for name, kib in (("verify_installed_shell_compile", 128), ("verify", 64)):
            with self.subTest(consumer=name):
                original = next(node for node in module.body
                                if isinstance(node, ast.FunctionDef) and node.name == name)
                calls = [node for node in ast.walk(original)
                         if isinstance(node, ast.Call)
                         and ast.unparse(node.func) == "D.file_record"
                         and len(node.args) == 2
                         and ast.unparse(node.args[0]) == "source / WORKFLOW"]
                self.assertEqual(len(calls), 1)
                self.assertEqual(ast.unparse(calls[0].args[1]), f"{kib} << 10")
                # Check each actual consumer, not a larger test-only cap.
                self.assertLessEqual(len(WORKFLOW.read_bytes()), kib << 10)

    def test_both_original_jobs_share_the_fixed_source_bound_data_script(self):
        workflow = WORKFLOW.read_text()
        heading = "      - name: Prepare only fixed disposable Ubuntu DATA modes\n"
        parts = workflow.split(heading)
        self.assertEqual(len(parts), 3)
        expected = (
            "        timeout-minutes: 1\n"
            "        shell: bash\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "
            "TZ=UTC HOME=/nonexistent /usr/bin/python3.12 -I -S -B "
            + PROVISIONER + " </dev/null\n"
        )
        for section in parts[1:]:
            self.assertEqual(section.split("      - name:", 1)[0], expected)
        compile_job, native_job = workflow.split("\n  native:\n", 1)
        for job in (compile_job, native_job):
            self.assertEqual(job.count(heading), 1)
            self.assertLess(job.index("Prepare shared Ubuntu shell inputs"), job.index(heading))
            self.assertLess(job.index(heading), job.index("Observe only the hosted Python body"))
            self.assertLess(job.index("Observe only the hosted Python body"),
                            job.index("Prepare a fresh bounded"))
        # Parse only: executing this privileged workflow-only script is forbidden
        # in these local checks. Its original globals must remain module globals.
        ast.parse((SOURCE / PROVISIONER).read_text())
        driver = ast.parse(DRIVER.read_text())
        manifest = next(node for node in driver.body
                        if isinstance(node, ast.FunctionDef) and node.name == "shell_source_manifest")
        assignments = [node for node in manifest.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "paths"
                               for target in node.targets)]
        self.assertEqual(len(assignments), 1)
        paths = ast.literal_eval(assignments[0].value)
        self.assertEqual(paths.count(PROVISIONER), 1)


if __name__ == "__main__":
    unittest.main()
