"""Pure source contracts: never import or execute hosted DATA provisioning."""

import ast
import hashlib
from pathlib import Path
import re
import unittest


SOURCE = Path(__file__).resolve().parents[2]
WORKFLOW = SOURCE / ".github/workflows/desktop-ubuntu-publication.yml"
DRIVER = SOURCE / "desktop/tools/ci_ubuntu_publication.py"
PROVISIONER = "desktop/tools/prepare_hosted_ubuntu_data.py"


class HostedWorkflowSource(unittest.TestCase):
    def test_fixed_jdk_preparation_is_conditional_paired_and_retains_original_failure_data(self):
        workflow = WORKFLOW.read_text()
        sections = re.split(r"^      - name: ", workflow, flags=re.MULTILINE)[1:]
        heading = "Prepare the fixed JDK17 pair only on this disposable shell runner"
        selected = [section for section in sections if section.splitlines()[0] == heading]
        self.assertEqual(len(selected), 1); step = selected[0]
        self.assertIn("        if: github.ref == 'refs/heads/verify/desktop-installed-shell'\n", step)
        self.assertIn("        timeout-minutes: 8\n", step)
        self.assertIn('[[ "$RUNNER_ENVIRONMENT" == github-hosted && "$GITHUB_REF" == refs/heads/verify/desktop-installed-shell ]]', step)
        self.assertIn('root="$RUNNER_TEMP/mrk-desktop-tools-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', step)
        self.assertIn('mkdir -m 700 -- "$root"', step)
        self.assertIn("          umask 077\n", step)
        self.assertLess(step.index("trap finish_tools_inputs EXIT"), step.index("query_packages before"))
        self.assertIn('pair=$(/usr/bin/python3.12 -I -S -B desktop/tools/ci_ubuntu_publication.py installed-shell-tools-before)', step)
        install = step.split('case "$pair" in\n', 1)[1].split('          esac\n', 1)[0]
        self.assertEqual(install.count("/usr/bin/apt-get"), 1)
        self.assertIn("            absent)\n", install)
        self.assertIn("            present) ;;\n            *) exit 1 ;;\n", install)
        self.assertIn("--no-install-recommends --no-remove", install)
        self.assertIn('install openjdk-17-jdk-headless > "$root/install.stdout" 2> "$root/install.stderr"', install)
        for name in ("java", "javac"):
            self.assertIn('sudo /usr/bin/update-alternatives --set ' + name + ' /usr/lib/jvm/java-17-openjdk-amd64/bin/' + name
                          + ' > "$root/' + name + '.stdout" 2> "$root/' + name + '.stderr"', step)
        finish = step.split("finish_tools_inputs() {\n", 1)[1].split("          }\n", 1)[0]
        self.assertLess(finish.index("original=$?"), finish.index("set +e"))
        self.assertIn("trap - EXIT", finish)
        self.assertLess(finish.index("query_packages after"), finish.index("installed-shell-tools-after"))
        self.assertIn('MRK_SHELL_TOOLS_PREPARATION_EXIT="$original" /usr/bin/python3.12 -I -S -B', finish)
        self.assertIn('snapshot=$?\n            if [[ "$original" != 0 ]]; then exit "$original"; fi\n            exit "$snapshot"', finish)
        for forbidden in ("apt-get update", "apt-get upgrade", "dist-upgrade", "--reinstall", "continue-on-error", "rm -", "pkill", "systemd-run", "java -version"):
            self.assertNotIn(forbidden, step)
        self.assertIn('git python3.12 openjdk-17-jdk-headless openjdk-17-jre-headless > "$root/$1-packages.tsv"', step)
        upload = next(section for section in sections if section.startswith("Retain original Tools prerequisite DATA including failures\n"))
        self.assertIn("        if: always() && steps.tools_inputs.outputs.root != ''\n", upload)
        self.assertIn("          path: ${{ steps.tools_inputs.outputs.root }}\n", upload)
        self.assertIn("          if-no-files-found: error\n", upload)
        self.assertLess(workflow.index("Prepare shared Ubuntu shell inputs"), workflow.index(heading))
        self.assertLess(workflow.index(heading), workflow.index("Establish only the reviewed forward glibc tuple set"))
        self.assertLess(workflow.index(heading), workflow.index("Prepare a fresh bounded compiler owner"))
        lifecycle = (SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_bytes()
        self.assertEqual(re.findall(r"MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256: '([0-9a-f]{64})'", workflow),
                         [hashlib.sha256(lifecycle).hexdigest()] * 2)

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

    def test_same_job_compiler_and_native_share_the_fixed_source_bound_data_script(self):
        workflow = WORKFLOW.read_text()
        heading = "      - name: Prepare only fixed disposable Ubuntu DATA modes\n"
        parts = workflow.split(heading)
        self.assertEqual(len(parts), 2)
        expected = (
            "        timeout-minutes: 1\n"
            "        shell: bash\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "
            "TZ=UTC HOME=/nonexistent /usr/bin/python3.12 -I -S -B "
            + PROVISIONER + " </dev/null\n"
        )
        self.assertEqual(parts[1].split("      - name:", 1)[0], expected)
        job = workflow.split("\njobs:\n", 1)[1]
        self.assertEqual(re.findall(r"^  ([a-z][a-z0-9_-]*):$", job, re.MULTILINE), ["compile"])
        self.assertNotIn("needs: compile", job)
        self.assertNotIn("needs.compile", job)
        self.assertLess(job.index("Prepare shared Ubuntu shell inputs"), job.index(heading))
        self.assertLess(job.index("Establish only the reviewed forward glibc tuple set"), job.index(heading))
        self.assertLess(job.index(heading), job.index("Observe only the hosted Python body"))
        self.assertLess(job.index("Observe only the hosted Python body"), job.index("Prepare a fresh bounded compiler owner"))
        sections = re.split(r"^      - name: ", job, flags=re.MULTILINE)[1:]

        def step(name):
            found = [section for section in sections if section.splitlines()[0] == name]
            self.assertEqual(len(found), 1, name)
            return found[0]

        compiler = step("Compile the normal shell and separate observer once without executing either")
        upload = step("Retain original compiler evidence and shell outputs")
        route = step("Require the fixed disposable native route")
        native_owner = step("Prepare a fresh bounded native owner")
        download = step("Download this run's exact original compiled shell outputs")
        consumer = step("Observe only the fixed installed shell route with original finality")
        sequence = (compiler, upload, route, native_owner, download, consumer)
        self.assertEqual([sections.index(section) for section in sequence],
                         sorted(sections.index(section) for section in sequence))
        self.assertIn("        id: compile\n", compiler)
        self.assertIn("        id: upload\n", upload)
        self.assertIn("        id: prepare_native\n", native_owner)
        gate = ("        if: github.ref == 'refs/heads/verify/desktop-installed-shell'"
                " && steps.compile.outcome == 'success' && steps.upload.outcome == 'success'\n")
        for section in (route, native_owner, download, consumer):
            self.assertIn(gate, section)
        bindings = (
            "MRK_INSTALLED_SHELL_ARTIFACT_ID: ${{ steps.upload.outputs.artifact-id }}",
            "MRK_INSTALLED_SHELL_ROSTER_SHA256: ${{ steps.compile.outputs.shell_roster_sha256 }}",
            "MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT: ${{ steps.compile.outputs.shell_producer_attempt }}",
        )
        for section in (route, consumer):
            for binding in bindings:
                self.assertIn(binding, section)
        self.assertIn('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ && "$MRK_PUSH_EVENT_AFTER" == "$GITHUB_SHA" ]]', route)
        self.assertIn("re.fullmatch(r'[1-9][0-9]{0,19}', value)", route)
        self.assertIn("if int(values[1]) > int(values[2]) or not re.fullmatch(r'[0-9a-f]{64}'", route)
        self.assertIn("          run-id: ${{ github.run_id }}\n", download)
        self.assertIn("          artifact-ids: ${{ steps.upload.outputs.artifact-id }}\n", download)
        self.assertIn("          path: ${{ steps.prepare_native.outputs.root }}/work/admitted-shell\n", download)
        for field in ("root", "preparation_sha256", "deadline"):
            self.assertIn("${{ steps.prepare_native.outputs." + field + " }}", consumer)
        checkout = step("Check out exact reviewed source without credentials")
        self.assertIn("          ref: ${{ github.sha }}\n", checkout)
        self.assertIn("          persist-credentials: false\n", checkout)
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
