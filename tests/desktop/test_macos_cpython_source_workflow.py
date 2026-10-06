"""Source contracts for the two fixed fresh macOS CPython workflows.

Only the two YAML files are read. No producer import, shell, Git, network, build,
macOS process or Actions invocation occurs. This intentionally checks a small
fixed workflow layout, not arbitrary YAML or Bash. Native owner finality and
supplier correctness require the separate real Mac run.
"""
from pathlib import Path
import re
import shlex
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/desktop-macos-cpython-source-build.yml"
INTEL_WORKFLOW = ROOT / ".github/workflows/desktop-macos-cpython-source-build-intel.yml"


class MacCPythonSourceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = WORKFLOW.read_text(encoding="utf-8")
        cls.intel = INTEL_WORKFLOW.read_text(encoding="utf-8")
        starts = list(re.finditer(r"^      - id: ([a-z_]+)$", cls.raw, re.MULTILINE))
        cls.ids = [match[1] for match in starts]
        cls.steps = {match[1]: cls.raw[match.start():
                     starts[index + 1].start() if index + 1 < len(starts) else len(cls.raw)]
                     for index, match in enumerate(starts)}

    def test_fixed_hosted_source_route_and_pinned_actions(self):
        self.assertEqual(self.ids, ["admission", "checkout", "prepare", "build", "retire",
                                   "source_post", "preparation_evidence", "evidence", "supplier"])
        # The runner context is valid at step env, not at job env.
        self.assertNotIn("${{ runner.", self.raw.split("    steps:", 1)[0])
        self.assertEqual(self.raw.count("RUNNER_ENVIRONMENT: ${{ runner.environment }}"), 4)
        for step in ("admission", "prepare", "build", "retire"):
            self.assertIn("\n        env:\n          RUNNER_ENVIRONMENT: ${{ runner.environment }}\n",
                          self.steps[step])
        jobs = self.raw.split("jobs:\n", 1)[1]
        self.assertEqual(re.findall(r"^  ([a-z_]+):$", jobs, re.MULTILINE), ["producer"])
        for required in (
            "on:\n  push:\n    branches: [verify/desktop-macos-cpython-source-build]\n",
            "permissions:\n  contents: read\n",
            "env:\n  BASH_ENV: ''\n  ENV: ''\n",
            "group: desktop-macos-cpython-source-build-${{ github.ref }}",
            "cancel-in-progress: false", "runs-on: macos-26", "timeout-minutes: 65",
            "github.repository == 'Apdelrahman1911/mobile-release-kit'",
            "github.event_name == 'push'", "github.sha == github.workflow_sha",
        ):
            self.assertIn(required, self.raw)
        self.assertEqual(re.findall(r"^        uses: ([^ #\n]+)", self.raw, re.MULTILINE), [
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ])
        self.assertIn("ref: ${{ github.sha }}", self.steps["checkout"])
        self.assertIn("persist-credentials: false", self.steps["checkout"])
        self.assertIn("macos_cpython_orchestrator.py prepare", self.steps["prepare"])
        admission = self.steps["admission"]
        for guard in (
            '"$RUNNER_ENVIRONMENT" == github-hosted',
            '"$RUNNER_OS" == macOS && "$RUNNER_ARCH" == ARM64 && "$GITHUB_JOB" == producer',
            '"$GITHUB_REPOSITORY" == Apdelrahman1911/mobile-release-kit',
            '"$GITHUB_EVENT_NAME" == push && "$GITHUB_REF" == refs/heads/verify/desktop-macos-cpython-source-build',
            '"$GITHUB_SHA" == "$GITHUB_WORKFLOW_SHA" && "$GITHUB_SHA" == "$MRK_PUSH_EVENT_AFTER"',
            '"$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/.github/workflows/desktop-macos-cpython-source-build.yml@$GITHUB_REF"',
            '"$(/usr/bin/uname -m)" == arm64 && "$(/usr/bin/sw_vers -productVersion)" == 26.*',
            '"$(/usr/bin/id -u)" =~ ^[1-9][0-9]*$',
        ):
            self.assertIn(guard, admission)
        for forbidden in ("workflow_dispatch:", "workflow_call:", "pull_request:", "matrix:",
                          "secrets.", "id-token:", "contents: write", "continue-on-error:",
                          "actions/download-artifact@", "actions/cache@", "actions/setup-python@", "sudo ", "gh release"):
            self.assertNotIn(forbidden, self.raw)
        assertions = [line.strip() for line in self.raw.splitlines() if line.strip().startswith("[[ ")]
        self.assertTrue(assertions)
        self.assertTrue(all(line.endswith("]] || exit 1") for line in assertions))
        # All guards, clean environment, publication and original status checks
        # below cover both lanes: Intel differs only by this closed nomination.
        derivative = self.raw
        for old, new, count in (
            ("name: Desktop macOS fresh CPython source supplier", "name: Desktop macOS Intel fresh CPython source supplier", 1),
            ("desktop-macos-cpython-source-build", "desktop-macos-cpython-source-build-intel", 5),
            ("runs-on: macos-26\n", "runs-on: macos-26-intel\n", 1),
            ("fixed disposable hosted ARM source-build route", "fixed disposable hosted Intel source-build route", 1),
            ('"$RUNNER_ARCH" == ARM64', '"$RUNNER_ARCH" == X64', 1),
            ('"$(/usr/bin/uname -m)" == arm64', '"$(/usr/bin/uname -m)" == x86_64', 1),
            ("mrk-macos-cpython-orchestrator-$GITHUB_SHA", "mrk-macos-cpython-intel-orchestrator-$GITHUB_SHA", 1),
            ("mrk-macos-cpython-$GITHUB_SHA", "mrk-macos-cpython-intel-$GITHUB_SHA", 1),
            ("name: desktop-macos-cpython-preparation-evidence-", "name: desktop-macos-cpython-intel-preparation-evidence-", 1),
            ("name: desktop-macos-cpython-evidence-", "name: desktop-macos-cpython-intel-evidence-", 1),
            ("name: desktop-macos-cpython-supplier-", "name: desktop-macos-cpython-intel-supplier-", 1),
        ):
            self.assertEqual(derivative.count(old), count)
            self.assertNotIn(new, derivative)
            derivative = derivative.replace(old, new)
        self.assertEqual(self.intel, derivative)

    def test_entry_uses_exact_clean_environment_and_preserves_original_status(self):
        build, prepare, retire = (self.steps[name] for name in ("build", "prepare", "retire"))
        self.assertNotIn("MRK_PYTHON", self.raw)
        self.assertIn('root="$RUNNER_TEMP/mrk-macos-cpython-$GITHUB_SHA-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', build)
        self.assertIn('root="$RUNNER_TEMP/mrk-macos-cpython-orchestrator-$GITHUB_SHA-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', prepare)
        for step in (prepare, build):
            self.assertIn('[[ ! -e "$root" && ! -L "$root" ]] || exit 1', step)
            self.assertIn("printf 'root=%s\\n' \"$root\" >> \"$GITHUB_OUTPUT\"", step)
        inherited = (
            "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH",
            "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA",
            "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF", "GITHUB_WORKSPACE",
            "RUNNER_TEMP", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        )
        for mode, step, arguments in (("prepare", prepare, []), ("build", build, []),
                                      ("retire", retire, ["$PREPARATION_OUTCOME", "$BUILD_OUTCOME"])):
            # Final exec cannot hide the entry status; the fixed build mode
            # performs byte PRE then replaces itself, never wrapping a child.
            command_source = step.split("          exec ", 1)[1].replace("\\" + "\n", "")
            command = shlex.split(command_source)
            self.assertEqual(command, [
                "/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/Users/runner",
                "LANG=C", "LC_ALL=C", "TZ=UTC", "DEVELOPER_DIR=/Library/Developer/CommandLineTools",
                *[name + "=$" + name for name in inherited], "/usr/bin/python3", "-I", "-S", "-B",
                "desktop/tools/macos_cpython_orchestrator.py", mode, *arguments,
            ])
            self.assertNotRegex(step, r"(?m)^\s*(?:mkdir|rm|chmod|curl|wget|pip|brew|sudo)\b")
        self.assertIn("if: always() && steps.prepare.outputs.root != ''", retire)
        self.assertIn("PREPARATION_OUTCOME: ${{ steps.prepare.outcome }}", retire)
        self.assertIn("BUILD_OUTCOME: ${{ steps.build.outcome }}", retire)
        self.assertNotIn("|| true", self.raw)
        self.assertNotIn("set +e", self.raw)
        git_line = ('git_env=(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin '
                    'GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git '
                    '--no-optional-locks -c core.fsmonitor=false -C "$GITHUB_WORKSPACE")')
        for step in (prepare, build, self.steps["source_post"]):
            self.assertIn(git_line, step)
            self.assertIn('rev-parse --verify HEAD)', step)
            self.assertIn('status --porcelain=v1 --untracked-files=all --ignored)', step)
            self.assertIn('[[ "$observed_head" == "$GITHUB_SHA" && -z "$observed_status" ]] || exit 1', step)
        for step in (prepare, build):
            self.assertLess(step.index('[[ "$observed_head"'), step.index("          exec "))
        self.assertIn("if: always() && steps.checkout.outcome == 'success'", self.steps["source_post"])

    def test_only_closed_evidence_and_successful_tar_receipt_are_uploaded(self):
        evidence, preparation, supplier = (self.steps[name] for name in ("evidence", "preparation_evidence", "supplier"))
        for step, owner in ((evidence, "build"), (preparation, "prepare")):
            self.assertIn("if: always() && steps." + owner + ".outputs.root != ''", step)
            self.assertIn("path: ${{ steps." + owner + ".outputs.root }}/public/evidence/\n", step)
            self.assertIn("if-no-files-found: ${{ steps." + owner + ".outcome == 'success' && 'error' || 'warn' }}", step)
        self.assertIn("if: success() && steps.prepare.outcome == 'success' && steps.build.outcome == 'success' && "
                      "steps.retire.outcome == 'success' && steps.source_post.outcome == 'success' && "
                      "steps.preparation_evidence.outcome == 'success' && steps.evidence.outcome == 'success'", supplier)
        self.assertIn("path: |\n            ${{ steps.build.outputs.root }}/public/supplier.tar\n"
                      "            ${{ steps.build.outputs.root }}/public/supplier-receipt.json\n", supplier)
        self.assertIn("if-no-files-found: error", supplier)
        self.assertEqual(re.findall(r"^\s+(?:path: )?(\$\{\{ steps\.(?:build|prepare)\.outputs\.root \}\}[^\n]+)$",
                                    self.raw, re.MULTILINE), [
            "${{ steps.prepare.outputs.root }}/public/evidence/",
            "${{ steps.build.outputs.root }}/public/evidence/",
            "${{ steps.build.outputs.root }}/public/supplier.tar",
            "${{ steps.build.outputs.root }}/public/supplier-receipt.json",
        ])
        for step, kind in ((preparation, "preparation-evidence"), (evidence, "evidence"), (supplier, "supplier")):
            self.assertIn("name: desktop-macos-cpython-" + kind +
                          "-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}", step)
            for required in ("compression-level: 0", "include-hidden-files: false",
                             "overwrite: false", "retention-days: 14"):
                self.assertIn(required, step)
        self.assertNotIn("/public/supplier/", self.raw)
        self.assertNotIn("/scratch/", self.raw)
        self.assertNotIn("prepare_runtime.py", self.raw)
        self.assertNotIn("stage_macos_installed.py", self.raw)


if __name__ == "__main__":
    unittest.main()
