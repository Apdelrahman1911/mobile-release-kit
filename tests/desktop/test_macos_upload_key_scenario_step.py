"""Execute ONLY the selected workflow shell against a fixed inert interpreter.

No Mac driver, observer, key, Store, provider, build or signing call is run.
The strict command roster is checked before execution; the temporary fake
interpreter only appends bounded public argv/PID DATA and returns a chosen code.
This proves dispatch/errexit/exec, NOT native completion, runtime admission or
ColdA's private first-process handoff (covered by its separate owner tests).
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/desktop-macos-installed.yml"
DRIVER = "desktop/tools/macos_identity_current_runtime.py"
TARGET = "aarch64-apple-darwin"
SCOPES = (
    "upload-key-roundtrip",
    "upload-key-stop-before-go",
    "upload-key-stop-after-new",
    "upload-key-cold-restart",
    "upload-key-backup-roundtrip",
)
CALL = '"$MRK_PYTHON" -I -S -B ' + DRIVER + ' --target "$MRK_MACOS_TARGET" --scope '
GUARD = ("github.ref == 'refs/heads/verify/desktop-macos-candidate'"
         " && env.MRK_MACOS_NATIVE_SCOPE == 'tool-setup'"
         " && env.MRK_MACOS_PACKAGE_ROLE == 'installed-shell-observation'"
         " && steps.tool_native.outcome == 'success'")


def selected_step():
    """Same named-step selection style as existing installed-workflow tests."""
    lines = WORKFLOW.read_text().splitlines(keepends=True)
    found = [i for i, line in enumerate(lines) if line == "        id: upload_key_native\n"]
    if len(found) != 1:
        raise AssertionError("one existing upload step required")
    index = found[0]
    start = next(i for i in range(index, -1, -1) if lines[i].startswith("      - name: "))
    end = next(i for i in range(index + 1, len(lines)) if lines[i].startswith("      - name: "))
    block = "".join(lines[start:end])
    if block.count("        run: |\n") != 1:
        raise AssertionError("one literal shell body required")
    metadata, raw = block.split("        run: |\n")
    if any(line.strip() and not line.startswith("          ") for line in raw.splitlines()):
        raise AssertionError("unexpected selected-step shell indentation")
    script = "\n".join(line[10:] if line else "" for line in raw.splitlines()) + "\n"
    commands = [line.strip() for line in script.splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
    expected = ["set -euo pipefail", "umask 077", "ulimit -c 0"] + [
        ("exec " if i == len(SCOPES) - 1 else "") + CALL + scope
        for i, scope in enumerate(SCOPES)
    ]
    if commands != expected:
        # Never execute altered source commands, shell substitutions, retries,
        # loops, signing or a genuine runtime just to diagnose a failing test.
        raise AssertionError("selected shell must use only the fixed inert-callable roster")
    return metadata, script


@unittest.skipUnless(sys.platform in ("linux", "darwin"), "existing Bash workflow test")
class UploadKeyScenarioStepTests(unittest.TestCase):
    def invoke_inert(self, fail_scope="", code=0):
        _, script = selected_step()  # Validate the exact source BEFORE exec.
        with tempfile.TemporaryDirectory(prefix="mrk-upload-scenarios-inert-") as directory:
            root = Path(directory)
            interpreter = Path(sys.executable).resolve()
            self.assertTrue(interpreter.is_absolute())
            self.assertFalse(any(char in str(interpreter) for char in " \t\r\n"))
            fake = root / "inert interpreter with spaces"
            rows = root / "public-argv.jsonl"
            fd = os.open(rows, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            body = f"#!{interpreter}\n" + '''import json, os, sys
args = sys.argv[1:]
prefix = ["-I", "-S", "-B", "desktop/tools/macos_identity_current_runtime.py",
          "--target", "aarch64-apple-darwin", "--scope"]
allowed = ("upload-key-roundtrip", "upload-key-stop-before-go", "upload-key-stop-after-new",
           "upload-key-cold-restart", "upload-key-backup-roundtrip")
if len(args) != 8 or args[:7] != prefix or args[7] not in allowed:
    raise SystemExit(99)
row = {"argv": args, "pid": os.getpid(), "shell": int(os.environ["MRK_INERT_SHELL_PID"])}
encoded = (json.dumps(row, separators=(",", ":")) + "\\n").encode("ascii")
if len(encoded) > 512:
    raise SystemExit(98)
fd = os.open(os.environ["MRK_INERT_ROWS"], os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    if os.write(fd, encoded) != len(encoded):
        raise SystemExit(97)
finally:
    os.close(fd)
print("INERT " + args[7])
raise SystemExit(int(os.environ["MRK_INERT_CODE"]) if args[7] == os.environ["MRK_INERT_FAIL"] else 0)
'''
            fake.write_text(body)
            fake.chmod(0o700)
            # No source tree or actual driver exists in this private cwd.
            # Only the fixed Python fake can be reached by any selected line.
            self.assertFalse((root / "desktop").exists())
            environment = {
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC",
                "MRK_PYTHON": str(fake), "MRK_MACOS_TARGET": TARGET,
                "MRK_INERT_ROWS": str(rows), "MRK_INERT_FAIL": fail_scope,
                "MRK_INERT_CODE": str(code),
            }
            # The prefix records this test shell's PID only. The actual
            # workflow body is otherwise executed byte-for-byte, including
            # final exec, under Bash's real errexit semantics.
            result = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-c",
                 "export MRK_INERT_SHELL_PID=$$\n" + script],
                cwd=root, env=environment, capture_output=True, text=True,
                timeout=5, check=False,
            )
            self.assertEqual(result.stderr, "")
            self.assertLessEqual(len(result.stdout), 512)
            observed = [json.loads(line) for line in rows.read_text().splitlines()]
            self.assertLessEqual(len(observed), len(SCOPES))
            return result, observed

    def test_one_existing_step_keeps_original_current_route_and_containing_budget(self):
        metadata, _ = selected_step()
        self.assertEqual(metadata,
            "      - name: Verify upload-key reuse, cancellation, cold restart and backend backup\n"
            "        id: upload_key_native\n"
            f"        if: {GUARD}\n"
            "        timeout-minutes: 60\n"
            "        shell: bash\n"
            "        env:\n"
            "          RUNNER_ENVIRONMENT: ${{ runner.environment }}\n")
        # Five wrapper invocations, but ColdA owns TWO genuine caller slots.
        # This is scheduling DATA, not authority to renew any native deadline.
        self.assertEqual(sum((1, 1, 1, 2, 1)) * 495, 2970)
        self.assertLess(2970, 60 * 60)

    def test_actual_shell_dispatches_old_three_then_cold_then_backup_once_and_execs_last(self):
        result, observed = self.invoke_inert()
        self.assertEqual(result.returncode, 0)
        self.assertEqual([row["argv"] for row in observed], [
            ["-I", "-S", "-B", DRIVER, "--target", TARGET, "--scope", scope]
            for scope in SCOPES
        ])
        self.assertEqual(result.stdout.splitlines(), ["INERT " + scope for scope in SCOPES])
        self.assertTrue(all(row["pid"] != row["shell"] for row in observed[:-1]))
        self.assertEqual(observed[-1]["pid"], observed[-1]["shell"])

    def test_actual_error_or_unexecuted_78_at_any_boundary_stops_all_later_scopes(self):
        for index, scope in enumerate(SCOPES):
            for code in (1, 78):
                with self.subTest(scope=scope, code=code):
                    result, observed = self.invoke_inert(scope, code)
                    expected = SCOPES[:index + 1]
                    self.assertEqual(result.returncode, code)
                    self.assertEqual([row["argv"][-1] for row in observed], list(expected))
                    self.assertEqual(result.stdout.splitlines(), ["INERT " + item for item in expected])
                    self.assertEqual(len(observed), len({row["argv"][-1] for row in observed}))


if __name__ == "__main__":
    unittest.main()
