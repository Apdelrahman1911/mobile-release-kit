"""Source contracts for the one fresh macOS CPython workflow.

Only this YAML file is read. No producer import, shell, Git, network, build,
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


class MacCPythonSourceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = WORKFLOW.read_text(encoding="utf-8")
        starts = list(re.finditer(r"^      - id: ([a-z_]+)$", cls.raw, re.MULTILINE))
        cls.ids = [match[1] for match in starts]
        cls.steps = {match[1]: cls.raw[match.start():
                     starts[index + 1].start() if index + 1 < len(starts) else len(cls.raw)]
                     for index, match in enumerate(starts)}

    def test_fixed_hosted_source_route_and_pinned_actions(self):
        self.assertEqual(self.ids, ["admission", "checkout", "python", "build",
                                   "source_post", "evidence", "supplier"])
        jobs = self.raw.split("jobs:\n", 1)[1]
        self.assertEqual(re.findall(r"^  ([a-z_]+):$", jobs, re.MULTILINE), ["producer"])
        for required in (
            "on:\n  push:\n    branches: [verify/desktop-macos-cpython-source-build]\n",
            "permissions:\n  contents: read\n",
            "env:\n  BASH_ENV: ''\n  ENV: ''\n",
            "group: desktop-macos-cpython-source-build-${{ github.ref }}",
            "cancel-in-progress: false", "runs-on: macos-26", "timeout-minutes: 55",
            "github.repository == 'Apdelrahman1911/mobile-release-kit'",
            "github.event_name == 'push'", "github.sha == github.workflow_sha",
        ):
            self.assertIn(required, self.raw)
        self.assertEqual(re.findall(r"^        uses: ([^ #\n]+)", self.raw, re.MULTILINE), [
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ])
        self.assertIn("ref: ${{ github.sha }}", self.steps["checkout"])
        self.assertIn("persist-credentials: false", self.steps["checkout"])
        self.assertIn("python-version: '3.14.7'\n          architecture: arm64", self.steps["python"])
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
                          "actions/download-artifact@", "actions/cache@", "sudo ", "gh release"):
            self.assertNotIn(forbidden, self.raw)
        assertions = [line.strip() for line in self.raw.splitlines() if line.strip().startswith("[[ ")]
        self.assertTrue(assertions)
        self.assertTrue(all(line.endswith("]] || exit 1") for line in assertions))

    def test_entry_uses_exact_clean_environment_and_preserves_original_status(self):
        build = self.steps["build"]
        self.assertIn("MRK_PYTHON: ${{ steps.python.outputs.python-path }}", build)
        self.assertIn('[[ "$MRK_PYTHON" == /* && -x "$MRK_PYTHON" ]] || exit 1', build)
        self.assertIn('root="$RUNNER_TEMP/mrk-macos-cpython-$GITHUB_SHA-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', build)
        self.assertIn('[[ ! -e "$root" && ! -L "$root" ]] || exit 1', build)
        self.assertIn("printf 'root=%s\\n' \"$root\" >> \"$GITHUB_OUTPUT\"", build)
        # exec is the final shell command: no tee, later successful assertion,
        # synthetic result, wrapper retry or cleanup can replace the entry code.
        # shlex alone does not remove Bash backslash-newline continuations.
        command_source = build.split("          exec ", 1)[1].replace("\\" + "\n", "")
        command = shlex.split(command_source)
        inherited = (
            "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH",
            "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA",
            "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF", "GITHUB_WORKSPACE",
            "RUNNER_TEMP", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        )
        self.assertEqual(command, [
            "/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/Users/runner",
            "LANG=C", "LC_ALL=C", "TZ=UTC", *[name + "=$" + name for name in inherited],
            "$MRK_PYTHON", "-I", "-S", "-B", "desktop/tools/macos_cpython_source_build.py",
        ])
        self.assertNotRegex(build, r"(?m)^\s*(?:mkdir|rm|curl|wget|pip|sudo)\b")
        self.assertNotIn("|| true", self.raw)
        self.assertNotIn("set +e", self.raw)
        git_line = ('git_env=(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin '
                    'GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git '
                    '--no-optional-locks -c core.fsmonitor=false -C "$GITHUB_WORKSPACE")')
        for step in (build, self.steps["source_post"]):
            self.assertIn(git_line, step)
            self.assertIn('rev-parse --verify HEAD)', step)
            self.assertIn('status --porcelain=v1 --untracked-files=all --ignored)', step)
            self.assertIn('[[ "$observed_head" == "$GITHUB_SHA" && -z "$observed_status" ]] || exit 1', step)
        self.assertLess(build.index('[[ "$observed_head"'), build.index("          exec "))
        self.assertIn("if: always() && steps.checkout.outcome == 'success'", self.steps["source_post"])

    def test_only_closed_evidence_and_successful_tar_receipt_are_uploaded(self):
        evidence, supplier = self.steps["evidence"], self.steps["supplier"]
        self.assertIn("if: always() && steps.build.outputs.root != ''", evidence)
        self.assertIn("path: ${{ steps.build.outputs.root }}/public/evidence/\n", evidence)
        self.assertIn("if-no-files-found: ${{ steps.build.outcome == 'success' && 'error' || 'warn' }}", evidence)
        self.assertIn("if: success() && steps.build.outcome == 'success' && steps.source_post.outcome == 'success' && steps.evidence.outcome == 'success'", supplier)
        self.assertIn("path: |\n            ${{ steps.build.outputs.root }}/public/supplier.tar\n"
                      "            ${{ steps.build.outputs.root }}/public/supplier-receipt.json\n", supplier)
        self.assertIn("if-no-files-found: error", supplier)
        self.assertEqual(re.findall(r"^\s+(?:path: )?(\$\{\{ steps.build.outputs.root \}\}[^\n]+)$",
                                    self.raw, re.MULTILINE), [
            "${{ steps.build.outputs.root }}/public/evidence/",
            "${{ steps.build.outputs.root }}/public/supplier.tar",
            "${{ steps.build.outputs.root }}/public/supplier-receipt.json",
        ])
        for step, kind in ((evidence, "evidence"), (supplier, "supplier")):
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
