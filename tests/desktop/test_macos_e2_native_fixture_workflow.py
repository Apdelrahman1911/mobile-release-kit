"""Fixed E2 source contracts and pure diagnostic DATA; never workflow/native execution."""
import ast
from pathlib import Path
import re
import textwrap
import unittest

ROOT = Path(__file__).absolute().parents[2]
WORKFLOW = ROOT / ".github/workflows/desktop-macos-maintenance-fixture.yml"
OWNER = ROOT / "desktop/tools/macos_e2_native_fixture.py"
STEP_NAMES = (
    "Admit only this fixed fresh hosted route",
    "Check out the exact reviewed source without retained credentials",
    "Select fixed isolated preparation Python",
    "Prepare only the locked fixture graphs through the original command owner",
    "Run the one reviewed fixture owner and its three native cases",
    "Publish only the closed source-bound fixture summary",
    "Preserve only the bounded reviewed summary",
    "Require actual complete acceptance",
)
# Frozen active source, not values derived from the subject during a test.
EXPECTED_HEADER = "name: Desktop macOS fixed maintenance fixture\n\non:\n  push:\n    branches:\n      - verify/desktop-macos-maintenance-fixture\n\npermissions:\n  contents: read\n\nconcurrency:\n  group: desktop-macos-maintenance-fixture-${{ github.ref }}\n  cancel-in-progress: false\n\njobs:\n  e2_fixture:\n    if: github.repository == 'Apdelrahman1911/mobile-release-kit' && github.event_name == 'push' && github.ref == 'refs/heads/verify/desktop-macos-maintenance-fixture'\n    runs-on: macos-26\n    timeout-minutes: 75\n    env:\n      # No shell startup file, inherited compiler switch or credential reaches\n      # a preparation/native child. Child environments below are reconstructed.\n      BASH_ENV: ''\n      ENV: ''\n"
EXPECTED_NATIVE = "        id: native\n        timeout-minutes: 55\n        shell: /usr/bin/env -i /bin/bash --noprofile --norc -e -o pipefail {0}\n        run: |\n          set -euo pipefail\n          umask 077\n          ulimit -n 1024\n          cd /Users/runner/work/mobile-release-kit/mobile-release-kit\n          # This original owner alone compiles/signs/installs/observes the fixed\n          # fixture. Its 990s/993s native call covers ALL THREE cases, with one\n          # distinct aggregate 60s auxiliary ledger. Step timeout is no receipt.\n          exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/Users/runner LANG=C LC_ALL=C TZ=UTC \\\n            GITHUB_ACTIONS=true RUNNER_ENVIRONMENT='${{ runner.environment }}' RUNNER_OS='${{ runner.os }}' RUNNER_ARCH='${{ runner.arch }}' \\\n            GITHUB_REPOSITORY='${{ github.repository }}' GITHUB_EVENT_NAME='${{ github.event_name }}' GITHUB_REF='${{ github.ref }}' \\\n            GITHUB_SHA='${{ github.sha }}' GITHUB_WORKFLOW_SHA='${{ github.workflow_sha }}' GITHUB_WORKFLOW_REF='${{ github.workflow_ref }}' \\\n            GITHUB_WORKSPACE='${{ github.workspace }}' RUNNER_TEMP='${{ runner.temp }}' GITHUB_JOB=e2_fixture \\\n            GITHUB_RUN_ID='${{ github.run_id }}' GITHUB_RUN_ATTEMPT='${{ github.run_attempt }}' \\\n            MRK_EXPECTED_SHA='${{ github.sha }}' MRK_MACOS_INSTALL_SOURCE_COMMIT='${{ github.sha }}' \\\n            MRK_MACOS_WORK='${{ steps.prepare.outputs.root }}' RUSTUP_TOOLCHAIN=1.98.1 \\\n            RUSTUP_HOME=/Users/runner/.rustup CARGO_HOME=/Users/runner/.cargo \\\n            DEVELOPER_DIR=/Library/Developer/CommandLineTools MACOSX_DEPLOYMENT_TARGET=26.0 \\\n            '${{ steps.python.outputs.python-path }}' -I -S -B \\\n            /Users/runner/work/mobile-release-kit/mobile-release-kit/desktop/tools/macos_e2_native_fixture.py\n\n"
EXPECTED_IF_LINES = (
    "    if: github.repository == 'Apdelrahman1911/mobile-release-kit' && github.event_name == 'push' && github.ref == 'refs/heads/verify/desktop-macos-maintenance-fixture'",
    "        if: always() && !cancelled() && steps.prepare.outcome == 'success'",
    "        if: always() && steps.publication.outcome == 'success'",
    "        if: always() && !cancelled()",
)



def active(text):
    return "\n".join(line.rstrip() for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))


def flat(text):
    return " ".join(active(text).split())


def section(text, start, end):
    """Only unique literal boundaries in this fixed reviewed source shape."""
    if text.count(start) != 1:
        raise AssertionError("fixed source start must be unique: " + start)
    rest = text.split(start, 1)[1]
    if end not in rest:
        raise AssertionError("fixed source end missing: " + end)
    return start + rest.split(end, 1)[0]


def references_github_secrets(text):
    """Inspect fixed-source Actions expressions, not Python entropy calls."""
    cursor = 0
    while True:
        start = text.find("${{", cursor)
        if start < 0:
            return False
        cursor, quoted, code = start + 3, False, []
        while cursor < len(text):
            if quoted and text.startswith("''", cursor):
                cursor += 2
                continue
            char = text[cursor]
            if char == "'":
                quoted = not quoted
                code.append(" ")
            elif not quoted and text.startswith("}}", cursor):
                cursor += 2
                break
            elif not quoted:
                code.append(char)
            cursor += 1
        else:
            raise AssertionError("unterminated GitHub expression in fixed source")
        if re.search(r"\bsecrets\b", "".join(code), re.IGNORECASE):
            return True


class MacE2FixtureWorkflowSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.owner = OWNER.read_text(encoding="utf-8")
        chunks = cls.workflow.split("    steps:\n")
        if len(chunks) != 2:
            raise AssertionError("exactly one fixed steps block is required")
        cls.header, body = chunks
        chunks = body.split("      - name: ")
        if chunks[0]:
            raise AssertionError("unexpected source before first fixed step")
        cls.steps = {}
        for chunk in chunks[1:]:
            name, newline, content = chunk.partition("\n")
            if not newline or name in cls.steps:
                raise AssertionError("missing or duplicate named step")
            cls.steps[name] = content

    def test_fixed_hosted_source_route_and_readonly_actions(self):
        self.assertEqual(active(self.header), active(EXPECTED_HEADER))
        self.assertEqual(tuple(self.steps), STEP_NAMES)
        actions = [line.strip().split(" #", 1)[0]
                   for line in self.workflow.splitlines()
                   if line.startswith("        uses: ")]
        self.assertEqual(actions, [
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ])
        admit, checkout, python = (self.steps[name] for name in STEP_NAMES[:3])
        for required in (
            'set -euo pipefail',
            '[[ "$RUNNER_ENVIRONMENT" == github-hosted && "$RUNNER_OS" == macOS && "$RUNNER_ARCH" == ARM64 ]]',
            '[[ "$GITHUB_REPOSITORY" == Apdelrahman1911/mobile-release-kit && "$GITHUB_EVENT_NAME" == push ]]',
            '[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-maintenance-fixture && "$GITHUB_JOB" == e2_fixture ]]',
            '[[ "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]',
            '[[ "$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/.github/workflows/desktop-macos-maintenance-fixture.yml@$GITHUB_REF" ]]',
        ):
            with self.subTest(admission=required):
                self.assertIn(required, active(admit))
        self.assertIn("ref: ${{ github.sha }}", active(checkout))
        self.assertIn("persist-credentials: false", active(checkout))
        self.assertIn("python-version: '3.14.7'", active(python))
        # Only GitHub expressions consume credential contexts. Python's secrets
        # module remains the unchanged cryptographic work-name entropy source.
        for allowed in (
            "import secrets\nwork = secrets.token_hex(4)",
            "${{ github.sha }} ${{ steps.prepare.outputs.root }}",
            "${{ format('secrets. and }} are text; it''s literal', github.sha) }}",
        ):
            self.assertFalse(references_github_secrets(allowed))
        for forbidden_expression in (
            "${{ secrets.EXAMPLE }}",
            "${{SECRETS['EXAMPLE']}}",
            "${{ SeCrEtS \n . EXAMPLE }}",
            "${{ secrets }}",
            "${{ toJSON(secrets) }}",
            "${{ secrets.* }}",
            "${{ github.sha || secrets['EXAMPLE'] }}",
            "${{ format('}} and it''s quoted {0}', secrets['EXAMPLE']) }}",
        ):
            self.assertTrue(references_github_secrets(forbidden_expression))
        for unfinished in ("${{ github.sha", "${{ format('unfinished }}"):
            with self.assertRaisesRegex(AssertionError, "unterminated GitHub expression"):
                references_github_secrets(unfinished)
        self.assertFalse(references_github_secrets(self.workflow))
        # Actions also evaluates unwrapped if predicates. Freeze the complete
        # occurrence roster: additions, quoted keys, multiline or moved forms fail.
        self.assertEqual(
            tuple(line for line in self.workflow.splitlines()
                  if re.match(r"""^\s*(?:if|['"]if['"])\s*:""", line)),
            EXPECTED_IF_LINES,
        )
        for forbidden in ("contents: write", "id-token:", "pull_request_target:",
                          "workflow_dispatch:", "repository_dispatch:", "matrix:", "services:"):
            with self.subTest(expanded_authority=forbidden):
                self.assertNotIn(forbidden, active(self.workflow))

    def test_reviewed_original_owner_is_the_only_native_route(self):
        prepare, native = (self.steps[name] for name in STEP_NAMES[3:5])
        # Exact active entry prevents an extra native command or inherited env.
        self.assertEqual(active(native), active(EXPECTED_NATIVE))
        self.assertEqual(active(native).count("exec /usr/bin/env -i"), 1)
        self.assertIn("owner = qualification.load_owner(CHECKOUT)", active(prepare))
        self.assertEqual(active(prepare).count("owner.run_owned("), 1)
        for required in (
            "result = owner.run_owned(argv, environ=environment, cwd=cwd, timeout=timeout, capture=True, text=False, output_limit=limit)",
            "fixture.completed(result, argv, limit)",
            'need(result.returncode == 0, "preparation-original-command-failed")',
            'manifests = ("desktop/native/macos-installed-native", "desktop/helpers/macos-android-register")',
            'call("fetch-" + str(index), [str(bin_directory / "cargo"), "fetch", "--manifest-path", str(CHECKOUT / directory / "Cargo.toml"), "--locked", "--target", TARGET], fetch_environment, 240, 262144)',
            "fixture.source_names(by_name)",
            "fixture.binding_data(os.environ, binding, inventory, rust, sig(work_info))",
            'for source_ordinal, row in enumerate(rows, 1): source_file(row["path"], row)',
            'book.publish(work / name, body, 0o600)',
        ):
            with self.subTest(preparation=required):
                self.assertIn(flat(required), flat(prepare))
        self.assertIn('CARGO_NET_OFFLINE="true"', active(self.owner))
        build = section(self.owner, "    def build_images(self):", "    def write_payload(")
        self.assertIn('"--locked", "--offline", "--release", "--jobs", "1", "--target", TARGET', flat(build))
        self.assertIn('result = self.command(role + "-build", argv, environment, cwd=CHECKOUT, timeout=480, limit=4 * 1024 * 1024)', flat(build))
        for raw_path in ("subprocess.", "os.system(", "os.posix_spawn(", "os.fork(",
                         "/usr/sbin/installer", "/bin/launchctl"):
            with self.subTest(unowned_workflow_path=raw_path):
                self.assertNotIn(raw_path, active(self.workflow))

    def preparation_diagnostic(self):
        """Extract literal tables and ONE pure function, not the preparation program."""
        prepare = self.steps[STEP_NAMES[3]]
        body = textwrap.dedent(section(prepare, "          import hashlib", "          PY_PREPARE"))
        tree = ast.parse(body)
        names = {"PREPARATION_COMMANDS", "PREPARATION_PHASES", "PREPARATION_REFUSALS"}
        namespace = {}
        functions = []
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name in names:
                    self.assertNotIn(name, namespace)
                    value = ast.literal_eval(node.value)
                    self.assertIs(type(value), tuple)
                    self.assertTrue(value and all(type(item) is str for item in value))
                    self.assertEqual(len(value), len(set(value)))
                    namespace[name] = value
            elif isinstance(node, ast.FunctionDef) and node.name == "preparation_failure_data":
                self.assertEqual(node.decorator_list, [])
                self.assertEqual(node.args.defaults, [])
                functions.append(node)
        self.assertEqual(set(namespace), names)
        self.assertEqual(len(functions), 1)
        # No imports, assignments from the program, calls, try/finally, or native
        # entry is evaluated. This function uses only its four DATA arguments,
        # the three literal tables and ordinary builtins.
        exec(compile(ast.Module(body=functions, type_ignores=[]), "<fixed-preparation-diagnostic>", "exec"), namespace)
        return namespace["preparation_failure_data"], namespace, tree

    def test_preparation_diagnostic_reports_only_closed_bounded_data(self):
        report, tables, _tree = self.preparation_diagnostic()
        calls = [{"role": "git-tree", "returned": True}, {"role": "git-roster", "returned": True}]
        value = report(ValueError("file-original-policy"), "source-file-inventory", 17, calls)
        self.assertEqual(value, {
            "schemaVersion": 1, "diagnosticOnly": True, "phase": "source-file-inventory",
            "reason": "file-original-policy", "exceptionKind": "value-error", "errno": None,
            "sourceOrdinal": 17, "originalCalls": calls,
        })
        self.assertIsNot(value["originalCalls"], calls)
        self.assertIsNot(value["originalCalls"][0], calls[0])
        class FixtureRefused(ValueError):
            pass
        self.assertEqual(report(FixtureRefused("directory-owner-mode"), "cargo-home-admission", 0, calls)["reason"],
                         "directory-owner-mode")
        marker = "synthetic-private-message-never-published"
        for error in (ValueError(marker), KeyError(marker), RuntimeError(marker),
                      ValueError({"private": marker}), OSError(13, marker, "/synthetic/private-input"),
                      UnicodeDecodeError("utf8", b"\xff", 0, 1, marker), SystemExit(marker), None):
            with self.subTest(category=type(error).__name__):
                result = report(error, "cargo-home-admission", 1, calls)
                self.assertNotIn(marker, repr(result))
                self.assertNotIn("/synthetic/private-input", repr(result))
                self.assertEqual(result["reason"], "unknown")
                self.assertIsNone(result["sourceOrdinal"])
        for number in (True, -1, 0, 256, "13", None):
            self.assertIsNone(report(OSError(number, marker), "cargo-home-admission", 0, calls)["errno"])
        self.assertEqual(report(OSError(13, marker), "cargo-home-admission", 0, calls)["errno"], 13)
        for ordinal in (True, -1, 0, 4097, "17", None):
            self.assertIsNone(report(ValueError(marker), "source-file-inventory", ordinal, calls)["sourceOrdinal"])
        self.assertEqual(report(ValueError(marker), "source-recheck", 4096, calls)["sourceOrdinal"], 4096)
        for stage in (marker, "git-roster " , None, True):
            result = report(ValueError(marker), stage, 17, calls)
            self.assertEqual(result["phase"], "unknown")
            self.assertIsNone(result["sourceOrdinal"])
        bad_calls = (None, tuple(calls), [{"role": marker, "returned": True}],
                     [{"role": "git-tree", "returned": 1}],
                     [{"role": "git-tree", "returned": True, "private": marker}],
                     [calls[1], calls[0]], calls * 4)
        for malformed in bad_calls:
            self.assertIsNone(report(ValueError(marker), "route", 0, malformed)["originalCalls"])
        self.assertEqual(report(ValueError(marker), "route", 0, [dict(calls[0], returned=False)])["originalCalls"],
                         [{"role": "git-tree", "returned": False}])
        self.assertEqual(tables["PREPARATION_COMMANDS"],
                         ("git-tree", "git-roster", "rustc-version", "cargo-version", "fetch-0", "fetch-1"))

    def test_preparation_diagnostic_stages_do_not_change_original_failure_or_cleanup(self):
        _report, tables, tree = self.preparation_diagnostic()
        prepare = self.steps[STEP_NAMES[3]]
        self.assertIn('SOURCE], git_env, 15, 2097152)\n              phase = "source-roster-decode"', prepare)
        for phase, operation in (
            ("source-roster-decode", 'raw_rows = roster.split(b"\\0")'),
            ("source-roster-entry", 'header, encoded = raw.split(b"\\t", 1)'),
            ("source-file-inventory", 'row, _content = source_file(name)'),
            ("source-required-roster", 'by_name = {row["path"]: row for row in rows}'),
            ("cargo-home-admission", 'book.directory(cargo_home)'),
            ("locked-manifests", 'for directory in manifests:'),
            ("repository-toolchain", '_row, toolchain_bytes = source_file('),
            ("rust-tool-admission", 'bin_directory = rustup_home / "toolchains" / "stable-aarch64-apple-darwin" / "bin"'),
        ):
            with self.subTest(phase=phase):
                self.assertIn(phase, tables["PREPARATION_PHASES"])
                self.assertRegex(prepare, 'phase = "' + phase + '"\n +'+re.escape(operation))
        labels = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "need":
                self.assertEqual(len(node.args), 2)
                self.assertIsInstance(node.args[1], ast.Constant)
                labels.append(node.args[1].value)
        self.assertTrue(set(labels) <= set(tables["PREPARATION_REFUSALS"]))
        catcher = section(prepare, "          except BaseException as error:", "          finally:\n              closes_known")
        self.assertEqual(flat(catcher), flat('''
          except BaseException as error:
              failure = True
              try:
                  diagnostic = preparation_failure_data(error, phase, source_ordinal, entered_calls)
                  print("E2 preparation refused in " + diagnostic["phase"] + "; native fixture was not entered.", file=sys.stderr)
                  print("E2 preparation diagnostic " + json.dumps(diagnostic, sort_keys=True, separators=(",", ":")), file=sys.stderr)
              except BaseException:
                  pass
        '''))
        finality = section(prepare, "          finally:\n              closes_known", "          if failure:")
        for required in (
            "closes_known = book is None or book.finish()",
            'all_returned = all(record["returned"] for record in entered_calls)',
            "if scratch is not None and scratch_identity is not None and closes_known and all_returned:",
            'need(sig(os.stat(scratch.name, dir_fd=parent["fd"], follow_symlinks=False))[:5] == scratch_identity and shutil.rmtree.avoids_symlink_attacks, "preparation-scratch-original")',
            "if not cleanup.finish(): failure = True",
        ):
            self.assertIn(flat(required), flat(finality))
        self.assertIn("          if failure:\n              raise SystemExit(1)", prepare)

    def test_direct_image_tools_keep_exact_versions_and_only_locked_fetch_network(self):
        report, tables, _tree = self.preparation_diagnostic()
        prepare = self.steps[STEP_NAMES[3]]
        compiler = section(self.owner, "    def compiler_environment(self, target):", "    def begin(self):")
        assignment = 'bin_directory = rustup_home / "toolchains" / "stable-aarch64-apple-darwin" / "bin"'
        self.assertEqual(prepare.count(assignment), 1)
        self.assertEqual(compiler.count(assignment), 1)
        for source in (prepare, compiler):
            for forbidden in ('(TOOLCHAIN + "-" + TARGET)', 'call("rustup"', '"bin/rustup"',
                              "RUSTUP_DIST_SERVER", "RUSTUP_UPDATE_ROOT",
                              ".resolve(", "os.readlink(", "os.symlink("):
                with self.subTest(forbidden=forbidden):
                    self.assertNotIn(forbidden, active(source))
            self.assertIn('RUSTUP_TOOLCHAIN=TOOLCHAIN, RUSTUP_AUTO_INSTALL="0"', flat(source))
        self.assertNotIn("rustup-admission", tables["PREPARATION_PHASES"])
        self.assertNotIn("rustup", tables["PREPARATION_PHASES"])
        self.assertNotIn("hosted-rustup-tool", tables["PREPARATION_REFUSALS"])
        old_calls = [{"role": role, "returned": True} for role in ("git-tree", "git-roster", "rustup")]
        self.assertIsNone(report(ValueError("unused"), "route", 0, old_calls)["originalCalls"])
        self.assertIn('book.directory(bin_directory)', prepare)
        self.assertIn('info = os.stat(executable, follow_symlinks=False)', prepare)
        self.assertIn(flat('need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()) '
                           'and not info.st_mode & 0o022 and info.st_mode & 0o111, "prepared-rust-tool")'), flat(prepare))
        self.assertIn('self.outputs.directory(bin_directory)', compiler)
        self.assertIn('tool_environment["RUSTC"] = str(bin_directory / "rustc")', prepare)
        self.assertIn('RUSTC=str(rustc)', compiler)
        self.assertIn(flat('raw = call(tool + "-version", [str(executable), "--version", "--verbose"], '
                           'tool_environment, 15, 4096, cwd=CHECKOUT / "desktop/src-tauri")'), flat(prepare))
        self.assertIn(flat('else: need("release: 1.98.1" in text.splitlines(), "effective-cargo-clock-binding") '
                           'tools[tool] = {"command": [tool, "--version", "--verbose"], "output": text}'), flat(prepare))
        self.assertIn(flat('need("release: 1.98.1" in text.splitlines() and '
                           '"commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985" in text.splitlines(), '
                           '"effective-rust-clock-binding")'), flat(prepare))
        self.assertIn('CARGO_NET_OFFLINE="false"', prepare)
        self.assertIn('for index, directory in enumerate(manifests):', prepare)
        self.assertIn(flat('call("fetch-" + str(index), [str(bin_directory / "cargo"), "fetch", "--manifest-path", '
                           'str(CHECKOUT / directory / "Cargo.toml"), "--locked", "--target", TARGET], '
                           'fetch_environment, 240, 262144)'), flat(prepare))
        self.assertIn('CARGO_NET_OFFLINE="true"', compiler)
        self.assertEqual(active(self.steps[STEP_NAMES[4]]), active(EXPECTED_NATIVE))

    def native_owner_diagnostic(self):
        """Extract literal tables and ONE pure function, not publication/owner code."""
        publish = self.steps[STEP_NAMES[5]]
        body = textwrap.dedent(section(publish, "          import hashlib", "          PY_PUBLISH"))
        tree = ast.parse(body)
        names = {"OWNER_DIAGNOSTIC_PHASES", "OWNER_DIAGNOSTIC_REFUSALS", "OWNER_DIAGNOSTIC_ROLES"}
        namespace, functions = {}, []
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name in names:
                    self.assertNotIn(name, namespace)
                    value = ast.literal_eval(node.value)
                    self.assertIs(type(value), tuple)
                    self.assertTrue(value and all(type(item) is str for item in value))
                    self.assertEqual(len(value), len(set(value)))
                    namespace[name] = value
            elif isinstance(node, ast.FunctionDef) and node.name == "native_owner_failure_data":
                self.assertEqual(node.decorator_list, [])
                self.assertEqual(node.args.defaults, [])
                functions.append(node)
        self.assertEqual(set(namespace), names)
        self.assertEqual(len(functions), 1)
        # No publication imports/top-level statements or native program run.
        exec(compile(ast.Module(body=functions, type_ignores=[]), "<fixed-native-owner-diagnostic>", "exec"), namespace)
        return namespace["native_owner_failure_data"], namespace


    def test_acceptance_requires_actual_outcome_and_bounded_closed_summary(self):
        publish, upload, final = (self.steps[name] for name in STEP_NAMES[5:])
        self.assertIn("MRK_NATIVE_STEP_OUTCOME: ${{ steps.native.outcome }}", active(publish))
        self.assertIn('outcome = os.environ["MRK_NATIVE_STEP_OUTCOME"]', active(publish))
        gates = section(publish, "              known_pass = (", "              summary.update(")
        self.assertEqual(flat(gates), flat("""known_pass = (
            outcome == "success" and result["passed"] is True and result["outcome"] == "passed"
            and result["failure"] is None and all(result[key] for key in flags)
            and result["cleanupErrors"] == [] and calls
            and all(call["returned"] and call["returncode"] == 0 for call in calls)
            and native_rust_tests is not None
            and installer_context is not None and installer_context["completed"]
            and native is not None and native["outcome"] == "passed" and native["nativeFinalityKnown"] is True
        )"""))
        flags = section(publish, "              flags = (", "              fixture.need(all(type(result[key])")
        self.assertEqual(flat(flags), flat("""flags = ("installerEntered", "installationReturnedSuccess", "nativeEntered", "nativeOwnerReturned",
            "sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown", "scratchRetired",
            "protectedRetentionRequired")"""))
        self.assertIn('accepted=bool(known_pass)', active(publish))
        units = section(publish, "              native_rust_tests = None", "              native = None")
        self.assertEqual(flat(units), flat("""native_rust_tests = None
            if result["nativeRustTests"] is not None:
                unit_calls = [call for call in calls if call["role"] == "native-rust-tests"]
                fixture.need(len(unit_calls) == 1 and unit_calls[0]["returned"]
                             and unit_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release,
                             "summary-native-rust-tests-call")
                unit_record = fixture.native_rust_tests_data(result["nativeRustTests"])
                if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                        and all(call["returned"] for call in calls)):
                    native_rust_tests = unit_record"""))
        context = section(publish, "              installer_context = None", "              native_rust_tests = None")
        self.assertIn('context_record = fixture.installer_context_data(result["installerContext"], source)', context)
        for required in (
            'context_record["observerSourceSha256"] == rows[fixture.CONTEXT_SOURCE]["sha256"]',
            'for case in context_record["cases"]:',
            'for suffix in ("installer", "receipt-query"):',
            'len(context_calls) == 1 and context_calls[0]["returned"] and context_calls[0]["returncode"] == 0',
            'for case in context_record["enteredCases"]:',
            'fixture.need(len(context_calls) == 1, "summary-context-entered-call")',
            'if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown")) and all(call["returned"] for call in calls)): installer_context = context_record',
        ):
            self.assertIn(flat(required), flat(context))
        self.assertGreater(publish.index(context), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(context), publish.index(units))
        self.assertIn('"installerContext": None,', publish)
        self.assertIn('installerContext=installer_context,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["installerContext"] =' in line], ['summary["installerContext"] = None'] * 2)
        for refused in ('except BaseException: summary["accepted"] = False summary["nativeRustTests"] = None summary["installerContext"] = None',
                        'if not book.finish(): summary["accepted"] = False summary["nativeRustTests"] = None summary["installerContext"] = None'):
            self.assertIn(refused, flat(publish))
        self.assertGreater(publish.index(units), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(units), publish.index("              known_pass = ("))
        self.assertIn('receiptOriginals native nativeRustTests', active(publish))
        self.assertIn('"nativeRustTests": None,', publish)
        self.assertIn('nativeRustTests=native_rust_tests,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["nativeRustTests"] =' in line], ['summary["nativeRustTests"] = None'] * 2)
        for refused in ('except BaseException: summary["accepted"] = False summary["nativeRustTests"] = None',
                        'if not book.finish(): summary["accepted"] = False summary["nativeRustTests"] = None'):
            self.assertIn(refused, flat(publish))
        report, tables = self.native_owner_diagnostic()
        call = {"role": "initial-receipt-query", "entered": True, "returned": True,
                "returncode": 1, "stdoutSha256": "0" * 64, "stderrSha256": "1" * 64}
        diagnostic = report("initial-receipt-query", "original-command-failed", [call])
        self.assertEqual(diagnostic, {
            "diagnosticOnly": True, "phase": "initial-receipt-query", "failure": "original-command-failed",
            "lastOriginalCall": {"role": "initial-receipt-query", "returned": True, "returncode": 1},
        })
        self.assertIsNot(diagnostic["lastOriginalCall"], call)
        successful = dict(call, returncode=0)
        diagnostic = report("client-build", "ambient-cargo-configuration", [successful])
        self.assertEqual(diagnostic["phase"], "client-build")
        self.assertEqual(diagnostic["lastOriginalCall"]["returncode"], 0)
        unit_diagnostic = report("native-rust-tests", "native-rust-test-roster", [dict(successful, role="native-rust-tests")])
        self.assertEqual(unit_diagnostic, {
            "diagnosticOnly": True, "phase": "native-rust-tests", "failure": "native-rust-test-roster",
            "lastOriginalCall": {"role": "native-rust-tests", "returned": True, "returncode": 0}})
        self.assertIsNone(report("prepare", None, [])["failure"])
        self.assertIsNone(report("prepare", None, [])["lastOriginalCall"])
        self.assertEqual(report("native-run", None, [dict(call, role="native-run", returned=False)])["lastOriginalCall"],
                         {"role": "native-run", "returned": False, "returncode": None})
        marker = "synthetic-private-message-never-published"
        for phase, failure in ((marker, marker), (True, True), (None, 0), ([], {})):
            value = report(phase, failure, [dict(call, role=marker, stderr=marker, environment=marker)])
            self.assertEqual(value["phase"], "unknown")
            self.assertEqual(value["failure"], "unknown")
            self.assertEqual(value["lastOriginalCall"]["role"], "unknown")
            self.assertNotIn(marker, repr(value))
            self.assertNotIn("stdoutSha256", value["lastOriginalCall"])
            self.assertNotIn("stderrSha256", value["lastOriginalCall"])
            self.assertLess(len(repr(value)), 512)
        malformed = (None, (), {}, [None], [dict(call, role=None)], [dict(call, entered=1)],
                     [dict(call, returned=1)], [dict(call, returncode=True)],
                     [dict(call, returncode=-1)], [dict(call, returncode=256)],
                     [dict(call, returncode="0")], [dict(call, returncode=None)], [call] * 65)
        for calls in malformed:
            self.assertIsNone(report("initial-receipt-query", "original-command-failed", calls)["lastOriginalCall"])
        self.assertEqual(report("native-run", "new-unlisted-reason", [dict(call, returncode=255)])["lastOriginalCall"]["returncode"], 255)
        # The fixed allowlist covers actual source refusal labels, not error text.
        labels = {"original-operation-refused-or-unknown"}
        for node in ast.walk(ast.parse(self.owner)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in {"need", "Refused"} and node.args
                    and isinstance(node.args[-1], ast.Constant) and type(node.args[-1].value) is str):
                labels.add(node.args[-1].value)
        self.assertEqual(labels, set(tables["OWNER_DIAGNOSTIC_REFUSALS"]))
        self.assertTrue(set(tables["OWNER_DIAGNOSTIC_ROLES"]) <= set(tables["OWNER_DIAGNOSTIC_PHASES"]))
        self.assertIn('"ownerDiagnostic": None,', publish)
        self.assertIn('ownerDiagnostic=native_owner_failure_data(result["phase"], result["failure"], calls),', publish)
        projection = publish.index('ownerDiagnostic=native_owner_failure_data(')
        self.assertGreater(projection, publish.index('"summary-owner-binding"'))
        self.assertGreater(projection, publish.index('"summary-returned-call"'))
        self.assertGreater(projection, publish.index('              known_pass = ('))
        self.assertLess(projection, publish.index('              book.check()', projection))
        acceptance_assignments = [line.strip() for line in active(publish).splitlines()
                                  if 'summary["accepted"] =' in line]
        self.assertEqual(acceptance_assignments, [
            'summary["accepted"] = False', 'summary["accepted"] = False'])
        for required in (
            'if not book.finish(): summary["accepted"] = False',
            'fixture.need(len(body) <= 49152, "summary-output-bound")',
            'publisher.publish(work / "e2-workflow-result.json", body, 0o600)',
            'fixture.need(publisher.finish(), "summary-output-close")',
            '"syntheticIdentity": True, "productionIdentityQualified": False',
            '"actualAppIntegrationQualified": False, "distributionQualified": False',
            '"rawOutputIncluded": False, "environmentValuesIncluded": False',
        ):
            with self.subTest(publication=required):
                self.assertIn(flat(required), flat(publish))
        self.assertEqual([line.strip() for line in upload.splitlines() if line.strip().startswith("path:")],
                         ["path: ${{ steps.prepare.outputs.root }}/e2-workflow-result.json"])
        self.assertIn("if-no-files-found: error", active(upload))
        self.assertNotIn("*", active(upload))
        for required in (
            "ACCEPTED: ${{ steps.publication.outputs.accepted }}",
            "PREPARATION_OUTCOME: ${{ steps.prepare.outcome }}",
            "NATIVE_OUTCOME: ${{ steps.native.outcome }}",
            "PUBLICATION_OUTCOME: ${{ steps.publication.outcome }}",
            'set -euo pipefail',
            '[[ "$PREPARATION_OUTCOME" == success && "$NATIVE_OUTCOME" == success && "$PUBLICATION_OUTCOME" == success && "$ACCEPTED" == true ]]',
        ):
            with self.subTest(finality=required):
                self.assertIn(required, active(final))


if __name__ == "__main__":
    unittest.main()
