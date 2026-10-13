"""Closed Intel external-XCTest build routing SOURCE, never native acceptance."""
import ast
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/desktop-macos-normal-ui-build-intel.yml"
DONOR = ".github/workflows/desktop-macos-installed.yml"
BUILD = "Build only the external normal-app XCTest runner, not an instrumented app"
INVENTORY = "Bind the complete reviewed first-party checkout before compilation"
BODY_PINS = {'Build only the external normal-app XCTest runner, not an instrumented app': {'bytes': 5726, 'sha256': '777945a2aabc8b1b91e9c8cd31ce25851a2cc15de3df4701bd28321b3bb8689f'}, 'Bind the complete reviewed first-party checkout before compilation': {'bytes': 3604, 'sha256': '1f7161ab0444ce4897baf6d560bff424d983d12091708fb81799fbb41ce37a63'}}
NAMES = (
    "Admit only the fixed credential-free Intel build diagnostic",
    "Check out exact reviewed source without retained credentials",
    "Select DATA stager Python, not the packaged interpreter",
    "Reserve one fresh fixed-shape work root and current source context",
    INVENTORY, BUILD,
    "Project only closed current build failure facts without raw captures",
    "Preserve only the closed public Intel build diagnostic",
)


def steps(source):
    matches = list(re.finditer(r"^      - name: (.+)\n", source, re.M))
    result = {}
    for index, match in enumerate(matches):
        name = match.group(1)
        if name in result: raise AssertionError("duplicate step")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        result[name] = source[match.end():end]
    return result


def body(block):
    lines = block.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.startswith("        run:")]
    if len(starts) != 1: raise AssertionError("one literal run body required")
    return "".join(lines[starts[0] + 1:])


def clone_contract(candidate, donor, name):
    actual = body(steps(candidate)[name]).encode()
    previous = body(steps(donor)[name]).encode()
    if actual != previous or {"bytes": len(actual), "sha256": hashlib.sha256(actual).hexdigest()} != BODY_PINS[name]:
        raise AssertionError("exact original owner/source body differs")


class IntelNormalUIBuildSource(unittest.TestCase):
    def sources(self):
        current = (ROOT / WORKFLOW).read_text()
        donor = (ROOT / DONOR).read_text()
        self.assertLessEqual(len(current.encode()), 32768)
        self.assertLessEqual(len(donor.encode()), 512 * 1024)
        return current, donor

    def test_fixed_credential_free_route_and_eight_finite_steps(self):
        current, _ = self.sources()
        selected = steps(current)
        self.assertEqual(tuple(selected), NAMES)
        self.assertEqual(re.findall(r"^  ([a-z][a-z0-9-]+):$", current.split("jobs:\n", 1)[1], re.M), ["normal-ui-build-intel"])
        self.assertIn("    runs-on: macos-26-intel\n", current)
        self.assertEqual(re.findall(r"^        timeout-minutes: ([0-9]+)$", current, re.M), ["1", "2", "2", "1", "3", "9", "1", "2"])
        self.assertIn("    timeout-minutes: 25\n", current)
        self.assertEqual(sum(int(value) for value in re.findall(r"^        timeout-minutes: ([0-9]+)$", current, re.M)), 21)
        self.assertIn("permissions:\n  contents: read\n", current)
        self.assertIn("  cancel-in-progress: false\n", current)
        self.assertIn("    if: github.event_name == 'push' && github.ref == 'refs/heads/verify/desktop-macos-normal-ui-build-intel'\n", current)
        self.assertIn("      - verify/desktop-macos-normal-ui-build-intel\n", current)
        for forbidden in ("workflow_dispatch:", "pull_request:", "workflow_call:", "schedule:", "matrix:", "environment:",
                          "secrets.", "continue-on-error:", "actions/download-artifact", "setup-node", "cargo ", "npm ",
                          "curl ", "wget ", "notarytool", "security import", "sudo ", "test-without-building"):
            self.assertNotIn(forbidden, current)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", selected[NAMES[1]])
        self.assertIn("          persist-credentials: false\n", selected[NAMES[1]])
        self.assertIn("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97", selected[NAMES[2]])
        self.assertIn("          python-version: '3.14.7'\n", selected[NAMES[2]])
        admission = selected[NAMES[0]]
        for token in ('"$GITHUB_SHA" == "$GITHUB_WORKFLOW_SHA"', '"$MRK_EXPECTED_SHA" == "$GITHUB_SHA"',
                      '"$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"', '"$RUNNER_ENVIRONMENT" == github-hosted',
                      '"$RUNNER_ARCH" == X64', '"$MRK_MACOS_TARGET" == x86_64-apple-darwin',
                      '"$MRK_MACOS_HOSTED_JOB" == github-hosted-macos26-x86_64',
                      '"$GITHUB_REPOSITORY/.github/workflows/desktop-macos-normal-ui-build-intel.yml@$GITHUB_REF"',
                      ' /dev/console)" == runner'):
            self.assertIn(token, admission)
        work = selected[NAMES[3]]
        self.assertIn('mktemp -d "$RUNNER_TEMP/mrk-macos-installed.XXXXXXXX"', work)
        self.assertIn('sys.version_info[:3] != (3, 14, 7)', work)
        self.assertIn('stat.S_IMODE(info.st_mode) != 0o700', work)
        self.assertIn('"applicationLaunched": False, "nativeSuccessInferred": False, "productReady": False', work)

    def test_actual_build_and_inventory_bodies_are_exact_unchanged_owners(self):
        current, donor = self.sources()
        for name in (BUILD, INVENTORY):
            clone_contract(current, donor, name)
        build = steps(current)[BUILD]
        self.assertNotIn("        if:", build)
        self.assertIn("        timeout-minutes: 9\n", build)
        self.assertIn('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" --normal-build', build)
        self.assertIn('> "$MRK_MACOS_WORK/normal-ui/build.log" 2>&1', build)
        self.assertIn('exit "$build_status"', build)
        runner = (ROOT / "desktop/tools/macos_normal_ui_runner.py").read_text()
        parsed = ast.parse(runner)
        functions = {node.name: ast.get_source_segment(runner, node) for node in parsed.body if isinstance(node, ast.FunctionDef)}
        self.assertIn('if arguments == ["--normal-build"]:', functions["normal_request"])
        self.assertIn('timeout=240, phaseSeconds=450', functions["normal_request"])
        self.assertIn('"build-for-testing"', functions["normal_build_arguments"])
        self.assertIn('"-jobs", "2", "-disableAutomaticPackageResolution"', functions["normal_build_arguments"])
        self.assertIn('["ARCHS=x86_64"] if target == INTEL_TARGET else []', functions["normal_build_arguments"])
        ordinary = functions["normal_context"].split('    if request.get("androidPositive") is True:', 1)[0]
        self.assertNotIn("GITHUB_REF", ordinary)
        self.assertNotIn("runtime-result.json", functions["execute_normal_phase"].split('    elif mode == "summary":', 1)[0])
        self.assertIn('need(not os.path.lexists(derived), "fresh-derived-data-required")', functions["execute_normal_phase"])

    def test_copy_contract_rejects_mutated_or_duplicate_originals(self):
        current, donor = self.sources()
        run = body(steps(current)[BUILD])
        self.assertEqual(current.count(run), 1)
        for changed in (run.replace('--normal-build', '--normal-summary', 1), run + run,
                        run.replace('exit "$build_status"', 'exit 0', 1),
                        run.replace('> "$MRK_MACOS_WORK/normal-ui/build.log" 2>&1', '| tee /dev/stderr', 1)):
            self.assertNotEqual(run, changed)
            with self.assertRaises(AssertionError):
                clone_contract(current.replace(run, changed, 1), donor, BUILD)

    def test_only_closed_failure_data_is_uploaded_without_cleanup_authority(self):
        current, _ = self.sources()
        selected = steps(current)
        projector, upload = selected[NAMES[6]], selected[NAMES[7]]
        self.assertIn("        if: always() && steps.work.outcome == 'success' && steps.source.outcome == 'success'\n", projector)
        self.assertIn('/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC', projector)
        self.assertIn('--profile installed --work "$MRK_MACOS_WORK" --target "$MRK_MACOS_TARGET"', projector)
        self.assertIn('--source "$GITHUB_SHA" --workflow-source "$GITHUB_WORKFLOW_SHA"', projector)
        self.assertIn('--run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"', projector)
        self.assertIn("        if: always() && steps.public_evidence.outcome == 'success'\n", upload)
        self.assertEqual([line for line in current.splitlines() if line.startswith("          path:")],
                         ["          path: ${{ steps.work.outputs.root }}/public-verification-evidence.json"])
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", upload)
        self.assertIn("          retention-days: 7\n", upload)
        self.assertIn("          if-no-files-found: error\n", upload)
        for forbidden in ("build.log", "source-binding.json", "source-inventory.json", "DerivedData", "xcresult", "          path: |"):
            self.assertNotIn(forbidden, upload)
        for forbidden in ("rm -", "rmtree", "kill ", "pkill ", "xcodebuild ", "xcrun "):
            self.assertNotIn(forbidden, current)


if __name__ == "__main__":
    unittest.main()
