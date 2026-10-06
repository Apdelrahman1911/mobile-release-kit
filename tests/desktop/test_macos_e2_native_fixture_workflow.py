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
    "Prepare only Context source and existing tool-version bindings",
    "Observe scripts-only Context receipt facts without native qualification",
    "Publish only the closed source-bound fixture summary",
    "Preserve only the bounded reviewed summary",
    "Require completed diagnostics without native acceptance",
)
# Frozen active source, not values derived from the subject during a test.
EXPECTED_HEADER = "name: Desktop macOS fixed maintenance fixture\n\non:\n  push:\n    branches:\n      - verify/desktop-macos-maintenance-fixture\n\npermissions:\n  contents: read\n\nconcurrency:\n  group: desktop-macos-maintenance-fixture-${{ github.ref }}\n  cancel-in-progress: false\n\njobs:\n  e2_fixture:\n    if: github.repository == 'Apdelrahman1911/mobile-release-kit' && github.event_name == 'push' && github.ref == 'refs/heads/verify/desktop-macos-maintenance-fixture'\n    runs-on: macos-26\n    timeout-minutes: 100\n    env:\n      # No shell startup file, inherited compiler switch or credential reaches\n      # a preparation/native child. Child environments below are reconstructed.\n      BASH_ENV: ''\n      ENV: ''\n"
EXPECTED_NATIVE = "        id: native\n        timeout-minutes: 70\n        shell: /usr/bin/env -i /bin/bash --noprofile --norc -e -o pipefail {0}\n        run: |\n          set -euo pipefail\n          umask 077\n          ulimit -n 1024\n          cd /Users/runner/work/mobile-release-kit/mobile-release-kit\n          # The same owner observes only Context under its unchanged 120s endpoint.\n          # No Rust build/test, image, signing or service/native lifecycle route.\n          # Zero here means safely captured diagnostics, not native acceptance.\n          exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/Users/runner LANG=C LC_ALL=C TZ=UTC \\\n            GITHUB_ACTIONS=true RUNNER_ENVIRONMENT='${{ runner.environment }}' RUNNER_OS='${{ runner.os }}' RUNNER_ARCH='${{ runner.arch }}' \\\n            GITHUB_REPOSITORY='${{ github.repository }}' GITHUB_EVENT_NAME='${{ github.event_name }}' GITHUB_REF='${{ github.ref }}' \\\n            GITHUB_SHA='${{ github.sha }}' GITHUB_WORKFLOW_SHA='${{ github.workflow_sha }}' GITHUB_WORKFLOW_REF='${{ github.workflow_ref }}' \\\n            GITHUB_WORKSPACE='${{ github.workspace }}' RUNNER_TEMP='${{ runner.temp }}' GITHUB_JOB=e2_fixture \\\n            GITHUB_RUN_ID='${{ github.run_id }}' GITHUB_RUN_ATTEMPT='${{ github.run_attempt }}' \\\n            MRK_EXPECTED_SHA='${{ github.sha }}' MRK_MACOS_INSTALL_SOURCE_COMMIT='${{ github.sha }}' \\\n            MRK_MACOS_WORK='${{ steps.prepare.outputs.root }}' RUSTUP_TOOLCHAIN=1.98.1 \\\n            RUSTUP_HOME=/Users/runner/.rustup CARGO_HOME=/Users/runner/.cargo \\\n            DEVELOPER_DIR=/Library/Developer/CommandLineTools MACOSX_DEPLOYMENT_TARGET=26.0 \\\n            '${{ steps.python.outputs.python-path }}' -I -S -B \\\n            /Users/runner/work/mobile-release-kit/mobile-release-kit/desktop/tools/macos_e2_native_fixture.py --observe-context-receipts\n\n"
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
        self.assertEqual(active(native).count(" --observe-service-layout"), 0)
        self.assertEqual(active(native).count(" --observe-context-receipts"), 1)
        self.assertIn("owner = qualification.load_owner(CHECKOUT)", active(prepare))
        self.assertEqual(active(prepare).count("owner.run_owned("), 1)
        for required in (
            "result = owner.run_owned(argv, environ=environment, cwd=cwd, timeout=timeout, capture=True, text=False, output_limit=limit)",
            "fixture.completed(result, argv, limit)",
            'need(result.returncode == 0, "preparation-original-command-failed")',
            'manifests = ("desktop/native/macos-installed-native", "desktop/helpers/macos-android-register", "desktop/src-tauri")',
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
        worker = section(self.owner, "    def build_installer_worker_tests(self):", "    def build_images(self):")
        for required in (
            'origin = time.clock_gettime_ns(time.CLOCK_MONOTONIC)',
            'deadline, last = origin + WORK_SECONDS * 1_000_000_000, origin',
            'need(type(now) is int and last <= now < deadline, "mac8-group-clock")',
            'seconds = (deadline - now) // 1_000_000_000',
            'return min(480, seconds)',
            '("installer-worker", INSTALLER, ("--features", "macos-installed-installer", "--bin", "mrk-macos-install"), INSTALLER_WORKER_RUST_TESTS, installer_worker_rust_tests_result, "installer_worker_rust_tests")',
            '("installed-reader", INSTALLER, ("--lib",), INSTALLED_READER_RUST_TESTS, installed_reader_rust_tests_result, "installed_reader_rust_tests")',
            '("producer-signing", NATIVE, ("--features", "package-producer-signing", "--lib"), PRODUCER_SIGNING_RUST_TESTS, producer_signing_rust_tests_result, "producer_signing_rust_tests")',
            '("package-producer", INSTALLER, ("--features", "macos-package-producer", "--example", "macos_package_producer"), PACKAGE_PRODUCER_RUST_TESTS, package_producer_rust_tests_result, "package_producer_rust_tests")',
            'target = self.scratch / (role + "-target")',
            'self.scratch_origins[target] = entry["identity"]',
            '"--manifest-path", str(CHECKOUT / directory / "Cargo.toml")',
            '"--locked", "--offline", "--jobs", "1", "--target", TARGET',
            '"--no-default-features", *flags, "--message-format=short", "--color", "never"',
            '"--exact", "--test-threads=1", "--format", "pretty", "--color", "never", *names',
            'result = self.command(role + "-rust-tests", argv, environment, cwd=CHECKOUT, timeout=remaining(), limit=4 * 1024 * 1024)',
            'finally: if all(call["returned"] for call in self.calls): self.retire_target(target)',
            'setattr(self, field, record)',
        ):
            self.assertIn(flat(required), flat(worker))
        self.assertEqual(worker.count('deadline, last ='), 1)
        self.assertEqual(worker.count('result = self.command('), 1)  # One literal loop over four SOURCE rows, not a new owner.
        self.assertLess(worker.index('self.retire_target(target)'), worker.index('setattr(self, field, record)'))
        self.assertNotIn('"--release"', worker)
        self.assertNotIn('e2-native-fixture', worker)
        execute = section(self.owner, "    def execute(self):", "\ndef canonical(")
        route = section(execute, '            if self.context_receipts_selected:', '        except BaseException as error:')
        diagnostic, ordinary = route.split('            else:\n', 1)
        self.assertEqual(flat(diagnostic), 'if self.context_receipts_selected: self.observe_installer_context()')
        self.assertIn(flat('if not self.service_layout["selected"]: self.build_installer_worker_tests()'), flat(ordinary))
        self.assertLess(ordinary.index('self.build_installer_worker_tests()'), ordinary.index('self.build_images()'))
        self.assertLess(ordinary.index('self.build_images()'), ordinary.index('self.observe_installer_context()'))
        self.assertLess(ordinary.index('self.observe_installer_context()'), ordinary.index('self.compile_metadata_observer()'))
        self.assertIn(flat('if self.service_layout["selected"]: self.build_images()'), flat(ordinary))
        self.assertIn(flat('if not self.context_receipts_selected: self.observe_btm_logs()'), flat(execute))
        self.assertIn('sys.argv[1:] in ([], [LAYOUT_ARGUMENT], [CONTEXT_RECEIPT_ARGUMENT])', self.owner)
        self.assertIn('context_receipts=sys.argv[1:] == [CONTEXT_RECEIPT_ARGUMENT]', self.owner)
        receipt_capture = section(self.owner, '    def observe_missing_context_receipt(', '    def context_audit(')
        self.assertEqual(receipt_capture.count('self.context_command('), 2)
        self.assertIn('["/usr/sbin/pkgutil", "--pkg-info-plist", identifier], 15)', flat(receipt_capture))
        self.assertIn('["/usr/sbin/pkgutil", "--volume", "/", "--pkgs-plist"], 15,', flat(receipt_capture))
        for required in ('self.source.book.check()', 'self.protected.check()', 'self.outputs.check()',
                         'context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), CONTEXT_SECONDS)',
                         'signature(after) == entry["identity"]', 'digest(self.outputs.read(entry)) == packages[label]["sha256"]'):
            self.assertIn(required, receipt_capture)
        context_observer = section(self.owner, '    def observe_installer_context(self):', '    def compiler_environment(')
        # Initial SAME-slot observations choose one variant. A later original
        # error is preserved; the old missing-plist diagnostic is never retried.
        receipts = section(self.owner, '    def context_receipts(', '    def complete_installer_context(')
        slots = section(self.owner, '    def context_receipt_slots(', '    def context_receipts(')
        complete = section(self.owner, '    def complete_installer_context(', '    def observe_missing_context_receipt(')
        self.assertIn('self.protected.directory(Path("/private/var/db/receipts"))', slots)
        self.assertIn('os.stat(identifier + "." + suffix, dir_fd=parent["fd"], follow_symlinks=False)', slots)
        self.assertIn(flat('except FileNotFoundError: slots.append(None)'), flat(slots))
        self.assertIn('self.protected.check()', slots)
        self.assertEqual(slots.count('context_timeout('), 2)
        for required in (
            'self.phase == "context-" + case + "-record"',
            'observed["outputOriginalClosed"] is observed["installerReturnedZero"] is True',
            'self.calls[-1]["entered"] is self.calls[-1]["returned"] is True',
            'type(self.calls[-1]["returncode"]) is int and self.calls[-1]["returncode"] == 0',
            'packages_post() parent, slots = self.context_receipt_slots(case)',
            'need(slots[0] is not None or slots[1] is None, "context-receipt-mixed-slots")',
            'entry["identity"] == original and entry["identity"][4] == 0 and body',
            'receipt.get("pkg-version") == "1"',
            'after_parent is parent and after == slots',
            'packages_post() return rows, observation',
        ):
            self.assertIn(flat(required), flat(receipts))
        present, absent = receipts.split('        if slots[0] is not None:', 1)[1].split('        else:\n', 1)
        self.assertIn('["/usr/sbin/pkgutil", "--pkg-info-plist", identifier], 15)', present)
        self.assertIn('observation = {"kind": "present"}', present)
        self.assertNotIn('CONTEXT_POST_CENSUS_ROLES', present)
        self.assertIn('self.context_command(CONTEXT_POST_CENSUS_ROLES[index]', absent)
        self.assertIn('["/usr/sbin/pkgutil", "--volume", "/", "--pkgs-plist"], 15,', absent)
        self.assertIn('receipt_census_absent(result.stdout, result.stderr)', absent)
        self.assertIn('need(identifier not in identifiers, "context-receipt-census-listed")', absent)
        self.assertIn('"kind": "absent-no-payload"', absent)
        self.assertNotIn('receipt-query', absent)
        for forbidden in ('except ', 'context-receipt-missing', 'observe_missing_context_receipt('):
            self.assertNotIn(forbidden, active(receipts))
            self.assertNotIn(forbidden, active(context_observer))
        self.assertLess(context_observer.index('observed = self.context_read_output('),
                        context_observer.index('self.context_receipts('))
        self.assertIn(flat('self.context_receipts( case, CONTEXT_IDENTIFIERS[index], observed, package_entries, packages)'),
                      flat(context_observer))
        self.assertIn('observed["receiptOriginals"], observed["receiptObservation"]', context_observer)
        self.assertLess(context_observer.index('self.installer_context["cases"].append(observed)'),
                        context_observer.index('self.complete_installer_context(package_entries, packages)'))
        self.assertIn('installer_context_calls(candidate, self.environment["GITHUB_SHA"], self.calls)', complete)
        self.assertIn('if row["receiptObservation"]["kind"] == "absent-no-payload":', complete)
        self.assertIn('need(slots == [None, None], "context-receipt-slots-changed")', complete)
        for required in ('self.source.book.check()', 'self.outputs.check()', 'self.protected.check()',
                         'context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), CONTEXT_SECONDS)'):
            self.assertIn(required, receipts)
            self.assertLess(complete.index(required), complete.index('self.installer_context["completed"] = True'))
        self.assertNotIn('call("fetch-"', prepare)
        sources = section(self.owner, "def source_names(rows):", "\nclass SourceInputs:")
        for required in ('"desktop/src-tauri/"', '"desktop/macos-installed-inputs/"',
                         '"desktop/tools/macos_android_sdk_metadata.py"',
                         '"src/mobile_release/api/data/metadata-images-v1.json"',
                         '"src/mobile_release/api/data/metadata-image-help-v1.json"'):
            self.assertIn(required, sources)
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
                         ("git-tree", "git-roster", "rustc-version", "cargo-version", "fetch-0", "fetch-1", "fetch-2"))

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
        self.assertEqual(tables["PREPARATION_COMMANDS"],
                         ("git-tree", "git-roster", "rustc-version", "cargo-version", "fetch-0", "fetch-1", "fetch-2"))
        self.assertIn("fetch-2", tables["PREPARATION_PHASES"])
        last_fetch = [{"role": role, "returned": True} for role in tables["PREPARATION_COMMANDS"]]
        self.assertEqual(report(ValueError("preparation-original-command-failed"), "fetch-2", 0, last_fetch)["originalCalls"], last_fetch)
        self.assertIn('manifests = ("desktop/native/macos-installed-native", "desktop/helpers/macos-android-register", "desktop/src-tauri")', flat(prepare))
        self.assertIn('CHECKOUT / INSTALLER', compiler)
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
        # This explicit diagnostic route keeps only actual version bindings;
        # the retained normal compiler method still requires locked offline work.
        self.assertNotIn('CARGO_NET_OFFLINE="false"', prepare)
        self.assertNotIn('for index, directory in enumerate(manifests):', prepare)
        self.assertNotIn('call("fetch-"', prepare)
        self.assertNotIn('fetch_environment', prepare)
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
            and native_rust_tests is not None and installer_worker_rust_tests is not None
            and installed_reader_rust_tests is not None and producer_signing_rust_tests is not None
            and package_producer_rust_tests is not None
            and installer_context is not None and installer_context["completed"]
            and native is not None and native["outcome"] == "passed" and native["nativeFinalityKnown"] is True
        )"""))
        flags = section(publish, "              flags = (", "              fixture.need(all(type(result[key])")
        self.assertEqual(flat(flags), flat("""flags = ("installerEntered", "installationReturnedSuccess", "nativeEntered", "nativeOwnerReturned",
            "sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown", "scratchRetired",
            "protectedRetentionRequired")"""))
        self.assertIn('accepted=bool(known_pass)', active(publish))
        diagnostic = section(publish, '              # This committed workflow selects only the receipt diagnostic route.',
                             '              known_pass = (')
        self.assertIn('fixture.need(result["passed"] is False', diagnostic)
        self.assertIn('result["installerEntered"] is result["nativeEntered"] is False', diagnostic)
        self.assertIn('context_receipt_diagnostic = fixture.context_receipt_diagnostic_result(result, source)', diagnostic)
        self.assertIn('diagnostic_captured = outcome == "success" and context_receipt_diagnostic is not None', diagnostic)
        self.assertIn('contextReceiptDiagnostic=context_receipt_diagnostic, diagnosticCaptured=bool(diagnostic_captured)', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines() if 'summary["diagnosticCaptured"] =' in line],
                         ['summary["diagnosticCaptured"] = False'] * 2)
        self.assertEqual([line.strip() for line in active(publish).splitlines() if 'summary["contextReceiptDiagnostic"] =' in line],
                         ['summary["contextReceiptDiagnostic"] = None'] * 2)
        self.assertIn('b"diagnostic_captured=true\\n" if summary["diagnosticCaptured"] else b"diagnostic_captured=false\\n"', publish)
        self.assertIn('context_observation = fixture.context_observation_result(result, source)', diagnostic)
        self.assertIn('context_completed = outcome == "success" and context_observation is not None', diagnostic)
        self.assertIn('"contextObservationCompleted": False,', publish)
        self.assertIn('contextObservationCompleted=bool(context_completed),', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines() if 'summary["contextObservationCompleted"] =' in line],
                         ['summary["contextObservationCompleted"] = False'] * 2)
        self.assertIn('b"context_observation_completed=true\\n" if summary["contextObservationCompleted"] else b"context_observation_completed=false\\n"', publish)
        self.assertNotIn('context_completed', gates)
        main = section(self.owner, '\ndef main():', '\nif __name__ == "__main__":')
        self.assertLess(main.index('context_observation = context_observation_result('), main.index('body = canonical(value)'))
        self.assertIn('context_completed = operation.context_receipts_selected and context_observation is not None', main)
        self.assertIn(flat('except BaseException: context_observation = None'), flat(main))
        self.assertLess(main.index('need(report.finish(),'), main.index('need(os.write(1, summary)'))
        self.assertLess(main.index('need(os.write(1, summary)'), main.index('context_timeout(decimal(context_observation["deadlineNs"])'))
        self.assertIn('return 0 if value["passed"] or context_completed else', main)
        self.assertNotIn('context_receipt_diagnostic_result(', main)
        units = section(publish, "              native_rust_tests = None", "              installer_worker_rust_tests = None")
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
        worker_units = section(publish, "              installer_worker_rust_tests = None", "              installed_reader_rust_tests = None")
        self.assertEqual(flat(worker_units), flat("""installer_worker_rust_tests = None
            if result["installerWorkerRustTests"] is not None:
                worker_calls = [call for call in calls if call["role"] == "installer-worker-rust-tests"]
                fixture.need(len(worker_calls) == 1 and worker_calls[0]["returned"]
                             and worker_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release
                             and type(worker_calls[0].get("workTimeoutSeconds")) is int
                             and 0 < worker_calls[0]["workTimeoutSeconds"] <= 480
                             and type(worker_calls[0].get("outputLimitBytes")) is int
                             and worker_calls[0]["outputLimitBytes"] == 4 * 1024 * 1024,
                             "summary-installer-worker-rust-tests-call")
                worker_record = fixture.installer_worker_rust_tests_data(result["installerWorkerRustTests"])
                if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                        and all(call["returned"] for call in calls)):
                    installer_worker_rust_tests = worker_record"""))
        self.assertGreater(publish.index(worker_units), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(worker_units), publish.index("              known_pass = ("))
        self.assertIn('native nativeRustTests installerWorkerRustTests installedReaderRustTests producerSigningRustTests packageProducerRustTests installerContext', publish)
        self.assertIn('"installerWorkerRustTests": None,', publish)
        self.assertIn('installerWorkerRustTests=installer_worker_rust_tests,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["installerWorkerRustTests"] =' in line],
                         ['summary["installerWorkerRustTests"] = None'] * 2)
        record = section(self.owner, "def installer_worker_rust_test_record():", "\ndef _rust_tests_data(")
        self.assertIn('"cargoProfile": "test"', record)
        self.assertNotIn('"release"', record)
        receipt = section(self.owner, "    def receipt(self, failure):", "    def execute(self):")
        self.assertIn('and unit_passed and installer_unit_passed and mac8_passed and self.installer_context["completed"]', flat(receipt))
        self.assertIn('"installerWorkerRustTests": self.installer_worker_rust_tests', receipt)
        selected_units = section(publish, "              installed_reader_rust_tests = None", "              producer_signing_rust_tests = None")
        self.assertEqual(flat(selected_units), flat('installed_reader_rust_tests = None\nif result["installedReaderRustTests"] is not None:\n    selected_calls = [call for call in calls if call["role"] == "installed-reader-rust-tests"]\n    fixture.need(len(selected_calls) == 1 and selected_calls[0]["returned"]\n                 and selected_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release\n                 and type(selected_calls[0].get("workTimeoutSeconds")) is int\n                 and 0 < selected_calls[0]["workTimeoutSeconds"] <= 480\n                 and type(selected_calls[0].get("outputLimitBytes")) is int\n                 and selected_calls[0]["outputLimitBytes"] == 4 * 1024 * 1024,\n                 "summary-installed-reader-rust-tests-call")\n    selected_record = fixture.installed_reader_rust_tests_data(result["installedReaderRustTests"])\n    if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))\n            and all(call["returned"] for call in calls)):\n        installed_reader_rust_tests = selected_record'))
        self.assertGreater(publish.index(selected_units), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(selected_units), publish.index("              known_pass = ("))
        self.assertIn('"installedReaderRustTests": None,', publish)
        self.assertIn('installedReaderRustTests=installed_reader_rust_tests,', publish)
        self.assertIn('"installedReaderRustTests": self.installed_reader_rust_tests', receipt)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["installedReaderRustTests"] =' in line], ['summary["installedReaderRustTests"] = None'] * 2)
        selected_units = section(publish, "              producer_signing_rust_tests = None", "              package_producer_rust_tests = None")
        self.assertEqual(flat(selected_units), flat('producer_signing_rust_tests = None\nif result["producerSigningRustTests"] is not None:\n    selected_calls = [call for call in calls if call["role"] == "producer-signing-rust-tests"]\n    fixture.need(len(selected_calls) == 1 and selected_calls[0]["returned"]\n                 and selected_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release\n                 and type(selected_calls[0].get("workTimeoutSeconds")) is int\n                 and 0 < selected_calls[0]["workTimeoutSeconds"] <= 480\n                 and type(selected_calls[0].get("outputLimitBytes")) is int\n                 and selected_calls[0]["outputLimitBytes"] == 4 * 1024 * 1024,\n                 "summary-producer-signing-rust-tests-call")\n    selected_record = fixture.producer_signing_rust_tests_data(result["producerSigningRustTests"])\n    if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))\n            and all(call["returned"] for call in calls)):\n        producer_signing_rust_tests = selected_record'))
        self.assertGreater(publish.index(selected_units), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(selected_units), publish.index("              known_pass = ("))
        self.assertIn('"producerSigningRustTests": None,', publish)
        self.assertIn('producerSigningRustTests=producer_signing_rust_tests,', publish)
        self.assertIn('"producerSigningRustTests": self.producer_signing_rust_tests', receipt)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["producerSigningRustTests"] =' in line], ['summary["producerSigningRustTests"] = None'] * 2)
        selected_units = section(publish, "              package_producer_rust_tests = None", "              installer_worker_diagnostic = None")
        self.assertEqual(flat(selected_units), flat('package_producer_rust_tests = None\nif result["packageProducerRustTests"] is not None:\n    selected_calls = [call for call in calls if call["role"] == "package-producer-rust-tests"]\n    fixture.need(len(selected_calls) == 1 and selected_calls[0]["returned"]\n                 and selected_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release\n                 and type(selected_calls[0].get("workTimeoutSeconds")) is int\n                 and 0 < selected_calls[0]["workTimeoutSeconds"] <= 480\n                 and type(selected_calls[0].get("outputLimitBytes")) is int\n                 and selected_calls[0]["outputLimitBytes"] == 4 * 1024 * 1024,\n                 "summary-package-producer-rust-tests-call")\n    selected_record = fixture.package_producer_rust_tests_data(result["packageProducerRustTests"])\n    if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))\n            and all(call["returned"] for call in calls)):\n        package_producer_rust_tests = selected_record'))
        self.assertGreater(publish.index(selected_units), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(selected_units), publish.index("              known_pass = ("))
        self.assertIn('"packageProducerRustTests": None,', publish)
        self.assertIn('packageProducerRustTests=package_producer_rust_tests,', publish)
        self.assertIn('"packageProducerRustTests": self.package_producer_rust_tests', receipt)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["packageProducerRustTests"] =' in line], ['summary["packageProducerRustTests"] = None'] * 2)
        context = section(publish, "              installer_context = None", "              native_rust_tests = None")
        self.assertIn('context_record = fixture.installer_context_data(result["installerContext"], source)', context)
        for required in (
            'context_record["observerSourceSha256"] == rows[fixture.CONTEXT_SOURCE]["sha256"]',
            'fixture.installer_context_calls(context_record, source, calls)',
            'if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown")) and all(call["returned"] for call in calls)): installer_context = context_record',
        ):
            self.assertIn(flat(required), flat(context))
        self.assertGreater(publish.index(context), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(context), publish.index(units))
        layout = section(publish, "              service_layout = None", "              native_rust_tests = None")
        self.assertEqual(flat(layout), flat("""service_layout = None
            layout_record = fixture.service_layout_data(result["serviceLayoutObservation"], source)
            fixture.need(not layout_record["selected"]
                         and all(not call["role"].startswith("service-layout-") for call in calls),
                         "summary-layout-route")
            if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                    and all(call["returned"] for call in calls)):
                service_layout = layout_record"""))
        self.assertNotIn('context_record["started"]', layout)  # Early bin refusal remains reportable.
        self.assertLess(publish.index('"summary-returned-call"'), publish.index(layout))
        self.assertLess(publish.index(layout), publish.index('              known_pass = ('))
        self.assertIn('serviceLayoutObservation=service_layout,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["serviceLayoutObservation"] =' in line],
                         ['summary["serviceLayoutObservation"] = None'] * 2)
        metadata_diagnostic = section(publish, "              context_metadata_diagnostic = None", "              context_package_diagnostic = None")
        self.assertEqual(flat(active(metadata_diagnostic)), flat("""context_metadata_diagnostic = None
            metadata_candidate = fixture.context_metadata_diagnostic_data(
                result["artifacts"].get(fixture.CONTEXT_METADATA_ARTIFACT) if type(result["artifacts"]) is dict else None,
                result["phase"], result["failure"], calls)
            if (metadata_candidate is not None
                    and all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                    and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
                context_metadata_diagnostic = metadata_candidate"""))
        self.assertLess(publish.index('"summary-returned-call"'), publish.index(metadata_diagnostic))
        self.assertLess(publish.index(metadata_diagnostic), publish.index('              known_pass = ('))
        self.assertIn('"contextMetadataDiagnostic": None,', publish)
        self.assertIn('contextMetadataDiagnostic=context_metadata_diagnostic,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["contextMetadataDiagnostic"] =' in line],
                         ['summary["contextMetadataDiagnostic"] = None'] * 2)
        package_diagnostic = section(publish, "              context_package_diagnostic = None", "              context_distribution_diagnostic = None")
        self.assertEqual(flat(active(package_diagnostic)), flat("""context_package_diagnostic = None
            package_candidate = fixture.context_package_info_diagnostic_data(
                result["artifacts"].get(fixture.CONTEXT_PACKAGE_INFO_ARTIFACT) if type(result["artifacts"]) is dict else None,
                result["phase"], result["failure"], calls)
            if (package_candidate is not None
                    and all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                    and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
                context_package_diagnostic = package_candidate"""))
        self.assertLess(publish.index('"summary-returned-call"'), publish.index(package_diagnostic))
        self.assertLess(publish.index(package_diagnostic), publish.index('              known_pass = ('))
        self.assertNotIn('context_package_diagnostic', gates)
        self.assertIn('"contextPackageInfoDiagnostic": None,', publish)
        self.assertIn('contextPackageInfoDiagnostic=context_package_diagnostic,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["contextPackageInfoDiagnostic"] =' in line],
                         ['summary["contextPackageInfoDiagnostic"] = None'] * 2)
        distribution_diagnostic = section(publish, "              context_distribution_diagnostic = None", "              btm_log = None")
        self.assertEqual(flat(active(distribution_diagnostic)), flat("""context_distribution_diagnostic = None
            distribution_candidate = fixture.context_distribution_diagnostic_data(
                result["artifacts"].get(fixture.CONTEXT_DISTRIBUTION_ARTIFACT) if type(result["artifacts"]) is dict else None,
                result["phase"], result["failure"], calls)
            if (distribution_candidate is not None
                    and all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                    and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
                context_distribution_diagnostic = distribution_candidate"""))
        self.assertLess(publish.index('"summary-returned-call"'), publish.index(distribution_diagnostic))
        self.assertLess(publish.index(distribution_diagnostic), publish.index('              known_pass = ('))
        self.assertNotIn('context_distribution_diagnostic', gates)
        self.assertIn('"contextDistributionDiagnostic": None,', publish)
        self.assertIn('contextDistributionDiagnostic=context_distribution_diagnostic,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["contextDistributionDiagnostic"] =' in line],
                         ['summary["contextDistributionDiagnostic"] = None'] * 2)
        audit = section(self.owner, "    def context_audit(", "    def observe_installer_context(")
        self.assertIn('members = context_xar(body)', audit)
        self.assertIn('return context_product(body, *component)', audit)
        self.assertIn('self._context_audit_refusal = error', audit)
        self.assertIn('any(entry is original for original in self.outputs.entries)', audit)
        self.assertIn('admitted = context_audit_call_data(package, self.phase, call_index, self.calls)', audit)
        self.assertIn('if admitted and diagnostic_known:', audit)
        self.assertLess(audit.index('members = context_xar(body)'), audit.index('context_package_info(members["PackageInfo"], identifier)'))
        self.assertLess(audit.index('context_package_info(members["PackageInfo"], identifier)'), audit.index('self.stager._cpio_members('))
        self.assertNotIn('self.context_command(', audit)
        self.assertNotIn('self.outputs.file(', audit)
        self.assertNotIn('self.context_pure_audit_refused = True', audit)
        execute = section(self.owner, "    def execute(self):", "\ndef canonical(")
        self.assertIn('type(error) is Refused and error is self._context_audit_refusal', execute)
        self.assertIn('except BaseException as error: self.context_pure_audit_refused = False', flat(execute))
        operation = section(self.owner, "class Operation:", "\ndef canonical(")
        finish = section(operation, "    def finish(self):", "    def receipt(self, failure):")
        for token in ('self.context_pure_audit_refused is True', 'self.installer_context["enteredCases"] == []',
                      'self.installer_context["cases"] == []', 'not self.installer_entered and not self.native_entered',
                      '"context-component-installer", "context-product-installer"',
                      'all(record["returned"] for record in self.calls)',
                      'and self.outputs_closed and self.protected_closed and native_finality and context_finality',
                      'and layout_finality and not self.cleanup_errors'):
            self.assertIn(token, finish)
        btm = section(publish, "              btm_log = None", "              # This committed workflow selects only the receipt diagnostic route.")
        self.assertEqual(flat(active(btm)), flat("""btm_log = None
            btm_record = fixture.btm_log_data(result["btmLogObservation"], source, calls)
            if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                    and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
                btm_log = btm_record"""))
        self.assertGreater(publish.index(btm), publish.index('"summary-owner-binding"'))
        self.assertGreater(publish.index(btm), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(btm), publish.index("              known_pass = ("))
        self.assertIn("installerContext contextReceiptDiagnostic serviceLayoutObservation btmLogObservation", publish)
        self.assertIn('"btmLogObservation": None,', publish)
        self.assertIn('btmLogObservation=btm_log,', publish)

        diagnostic = section(publish, "              installer_worker_diagnostic = None", "              native = None")
        for required in (
            'diagnostic_calls = [call for call in calls if "installerWorkerDiagnostic" in call]',
            'len(diagnostic_calls) == 1 and len([call for call in calls if call["role"] == "installer-worker-rust-tests"]) == 1',
            'fixture.installer_worker_diagnostic_data( diagnostic_calls[0]["installerWorkerDiagnostic"], diagnostic_calls[0], rows)',
            'candidate_diagnostic is not None',
            'all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))',
            'all(call["returned"] for call in calls) and not result["cleanupErrors"]',
            'installer_worker_diagnostic = candidate_diagnostic',
        ):
            self.assertIn(flat(required), flat(diagnostic))
        self.assertLess(publish.index('"summary-returned-call"'), publish.index(diagnostic))
        self.assertLess(publish.index(diagnostic), publish.index('              known_pass = ('))
        self.assertIn('"installerWorkerDiagnostic": None,', publish)
        self.assertIn('installerWorkerDiagnostic=installer_worker_diagnostic,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["installerWorkerDiagnostic"] =' in line],
                         ['summary["installerWorkerDiagnostic"] = None'] * 2)
        known_pass = section(publish, "              known_pass = (", "              summary.update(")
        self.assertNotIn("installer_worker_diagnostic", known_pass)
        self.assertNotIn("context_metadata_diagnostic", known_pass)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["btmLogObservation"] =' in line],
                         ['summary["btmLogObservation"] = None'] * 2)
        self.assertNotIn("btm", gates.lower())
        self.assertIn('"installerContext": None,', publish)
        self.assertIn('installerContext=installer_context,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["installerContext"] =' in line], ['summary["installerContext"] = None'] * 2)
        for refused in ('except BaseException: summary["accepted"] = False summary["nativeRustTests"] = None summary["installerWorkerRustTests"] = None summary["installedReaderRustTests"] = None summary["producerSigningRustTests"] = None summary["packageProducerRustTests"] = None summary["installerContext"] = None',
                        'if not book.finish(): summary["accepted"] = False summary["nativeRustTests"] = None summary["installerWorkerRustTests"] = None summary["installedReaderRustTests"] = None summary["producerSigningRustTests"] = None summary["packageProducerRustTests"] = None summary["installerContext"] = None'):
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
        worker_diagnostic = report("installer-worker-rust-tests", "installer-worker-rust-test-roster",
                                   [dict(successful, role="installer-worker-rust-tests")])
        self.assertEqual(worker_diagnostic, {
            "diagnosticOnly": True, "phase": "installer-worker-rust-tests", "failure": "installer-worker-rust-test-roster",
            "lastOriginalCall": {"role": "installer-worker-rust-tests", "returned": True, "returncode": 0}})
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
        owner_tree = ast.parse(self.owner)
        for node in ast.walk(owner_tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in {"need", "Refused"} and node.args
                    and isinstance(node.args[-1], ast.Constant) and type(node.args[-1].value) is str):
                labels.add(node.args[-1].value)
        # The fixed wrappers share only strict parsing, not record identity.
        # Derive their finite prefix/suffix products from SOURCE, never runtime DATA.
        suffixes = {"_rust_tests_data": {"-record"},
                    "_rust_test_output": {"-bound", "-framing", "-roster", "-result"}}
        for helper, expected_suffixes in suffixes.items():
            definitions = [node for node in owner_tree.body if isinstance(node, ast.FunctionDef) and node.name == helper]
            self.assertEqual(len(definitions), 1)
            actual_suffixes = set()
            for node in ast.walk(definitions[0]):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "need":
                    label = node.args[-1]
                    self.assertIsInstance(label, ast.BinOp)
                    self.assertIsInstance(label.op, ast.Add)
                    self.assertIsInstance(label.left, ast.Name)
                    self.assertEqual(label.left.id, "label")
                    self.assertIsInstance(label.right, ast.Constant)
                    actual_suffixes.add(label.right.value)
            self.assertEqual(actual_suffixes, expected_suffixes)
            prefixes = []
            for node in ast.walk(owner_tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == helper:
                    self.assertEqual(len(node.args), 3)
                    self.assertEqual(node.keywords, [])
                    self.assertIsInstance(node.args[-1], ast.Constant)
                    prefixes.append(node.args[-1].value)
            self.assertEqual(sorted(prefixes), ["installed-reader-rust-test", "installer-worker-rust-test", "native-rust-test", "package-producer-rust-test", "producer-signing-rust-test"])
            labels.update(prefix + suffix for prefix in prefixes for suffix in actual_suffixes)
        self.assertEqual(labels, set(tables["OWNER_DIAGNOSTIC_REFUSALS"]))
        # Owner output is sanitized before this workflow sees it. A listed
        # label must survive that exact grammar, not silently become generic.
        owner_grammar = r"[a-z][a-z0-9-]{0,95}"
        self.assertIn('re.fullmatch(r"' + owner_grammar + '", error.args[0])', self.owner)
        for label in labels:
            with self.subTest(owner_refusal=label):
                self.assertIsNotNone(re.fullmatch(owner_grammar, label))
                self.assertEqual(report("context-component-audit", label, [successful])["failure"], label)
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
            "DIAGNOSTIC_CAPTURED: ${{ steps.publication.outputs.diagnostic_captured }}",
            "CONTEXT_OBSERVATION_COMPLETED: ${{ steps.publication.outputs.context_observation_completed }}",
            '[[ "$PREPARATION_OUTCOME" == success && "$NATIVE_OUTCOME" == success && "$PUBLICATION_OUTCOME" == success && "$ACCEPTED" == false && "$DIAGNOSTIC_CAPTURED" == false && "$CONTEXT_OBSERVATION_COMPLETED" == true ]]',
        ):
            with self.subTest(finality=required):
                self.assertIn(required, active(final))


if __name__ == "__main__":
    unittest.main()
