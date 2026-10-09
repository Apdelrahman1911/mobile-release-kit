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
    "Compile linked admission and classify linked crash cuts through the original owner",
    "Publish only the closed source-bound fixture summary",
    "Preserve only the bounded reviewed summary",
    "Require closed scoped qualification without full E2 acceptance",
)
# Frozen active source, not values derived from the subject during a test.
EXPECTED_HEADER = "name: Desktop macOS fixed maintenance fixture\n\non:\n  push:\n    branches:\n      - verify/desktop-macos-maintenance-fixture\n\npermissions:\n  contents: read\n\nconcurrency:\n  group: desktop-macos-maintenance-fixture-${{ github.ref }}\n  cancel-in-progress: false\n\njobs:\n  e2_fixture:\n    if: github.repository == 'Apdelrahman1911/mobile-release-kit' && github.event_name == 'push' && github.ref == 'refs/heads/verify/desktop-macos-maintenance-fixture'\n    runs-on: macos-26\n    timeout-minutes: 100\n    env:\n      # No shell startup file, inherited compiler switch or credential reaches\n      # a preparation/native child. Child environments below are reconstructed.\n      BASH_ENV: ''\n      ENV: ''\n"
EXPECTED_NATIVE = "        id: native\n        timeout-minutes: 70\n        shell: /usr/bin/env -i /bin/bash --noprofile --norc -e -o pipefail {0}\n        run: |\n          set -euo pipefail\n          umask 077\n          ulimit -n 1024\n          cd /Users/runner/work/mobile-release-kit/mobile-release-kit\n          # Same990s owner: two original graphs, linked-admission Parent2 and linked-crash Record1.\n          # Compiled DATA only; no Installer, live removal, signing, SM, Keychain or app launch.\n          exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/Users/runner LANG=C LC_ALL=C TZ=UTC \\\n            GITHUB_ACTIONS=true RUNNER_ENVIRONMENT='${{ runner.environment }}' RUNNER_OS='${{ runner.os }}' RUNNER_ARCH='${{ runner.arch }}' \\\n            GITHUB_REPOSITORY='${{ github.repository }}' GITHUB_EVENT_NAME='${{ github.event_name }}' GITHUB_REF='${{ github.ref }}' \\\n            GITHUB_SHA='${{ github.sha }}' GITHUB_WORKFLOW_SHA='${{ github.workflow_sha }}' GITHUB_WORKFLOW_REF='${{ github.workflow_ref }}' \\\n            GITHUB_WORKSPACE='${{ github.workspace }}' RUNNER_TEMP='${{ runner.temp }}' GITHUB_JOB=e2_fixture \\\n            GITHUB_RUN_ID='${{ github.run_id }}' GITHUB_RUN_ATTEMPT='${{ github.run_attempt }}' \\\n            MRK_EXPECTED_SHA='${{ github.sha }}' MRK_MACOS_INSTALL_SOURCE_COMMIT='${{ github.sha }}' \\\n            MRK_MACOS_WORK='${{ steps.prepare.outputs.root }}' RUSTUP_TOOLCHAIN=1.98.1 \\\n            RUSTUP_HOME=/Users/runner/.rustup CARGO_HOME=/Users/runner/.cargo \\\n            DEVELOPER_DIR=/Library/Developer/CommandLineTools MACOSX_DEPLOYMENT_TARGET=26.0 \\\n            '${{ steps.python.outputs.python-path }}' -I -S -B \\\n            /Users/runner/work/mobile-release-kit/mobile-release-kit/desktop/tools/macos_e2_native_fixture.py --qualify-removal-parent-data\n\n"
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
        for name, relative, attribute in (
                (STEP_NAMES[3], "desktop/tools/macos_maintenance_fixture_prepare.sh", "preparation_source"),
                (STEP_NAMES[5], "desktop/tools/macos_maintenance_fixture_publish.sh", "publication_source")):
            step = cls.steps[name]
            key = "        run: |\n"
            if step.count(key) != 1 or step.split(key, 1)[1].rstrip("\n") != "          builtin source ./" + relative:
                raise AssertionError("fixed maintenance same-shell caller")
            body = (ROOT / relative).read_text(encoding="utf-8")
            setattr(cls, attribute, textwrap.indent(body, "          "))
        cls.actual_source = cls.workflow + cls.preparation_source + cls.publication_source

    def test_fixed_hosted_source_route_and_readonly_actions(self):
        self.assertEqual(active(self.header), active(EXPECTED_HEADER))
        self.assertEqual(tuple(self.steps), STEP_NAMES)
        for raw in self.steps.values():
            if "        run: |\n" in raw:
                decoded = textwrap.dedent(raw.split("        run: |\n", 1)[1]).rstrip("\n") + "\n"
                self.assertLessEqual(len(decoded), 21000)
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
        self.assertFalse(references_github_secrets(self.actual_source))
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
                self.assertNotIn(forbidden, active(self.actual_source))

    def test_reviewed_original_owner_is_the_only_native_route(self):
        prepare, native = self.preparation_source, self.steps[STEP_NAMES[4]]
        # Exact active entry prevents an extra native command or inherited env.
        self.assertEqual(active(native), active(EXPECTED_NATIVE))
        self.assertEqual(active(native).count("exec /usr/bin/env -i"), 1)
        self.assertEqual(active(native).count(" --observe-service-layout"), 0)
        self.assertEqual(active(native).count(" --observe-service-cocoa-startup"), 0)
        self.assertEqual(active(native).count(" --qualify-removal-parent-data"), 1)
        self.assertEqual(active(native).count(" --qualify-removal-recovery-data"), 0)
        self.assertEqual(active(native).count(" --observe-context-receipts"), 0)
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
        self.assertIn('sys.argv[1:] in ([], [LAYOUT_ARGUMENT], [CONTEXT_RECEIPT_ARGUMENT], [COCOA_ARGUMENT], [REGISTRATION_ARGUMENT], [REMOVAL_ARGUMENT], [INTEGRATION_ARGUMENT], [PARENT_ARGUMENT], [CHANGES_ARGUMENT], [RECOVERY_ARGUMENT])', self.owner)
        self.assertIn('service_cocoa=sys.argv[1:] == [COCOA_ARGUMENT]', self.owner)
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
        self.assertIn('call("fetch-"', prepare)
        sources = section(self.owner, "def source_names(rows):", "\nclass SourceInputs:")
        for required in ('"desktop/src-tauri/"', '"desktop/macos-installed-inputs/"',
                         '"desktop/tools/macos_android_sdk_metadata.py"',
                         '"src/mobile_release/api/data/metadata-images-v1.json"',
                         '"src/mobile_release/api/data/metadata-image-help-v1.json"'):
            self.assertIn(required, sources)
        for raw_path in ("subprocess.", "os.system(", "os.posix_spawn(", "os.fork(",
                         "/usr/sbin/installer", "/bin/launchctl"):
            with self.subTest(unowned_workflow_path=raw_path):
                self.assertNotIn(raw_path, active(self.actual_source))


        # Actual selected control flow with inert command/filesystem adapters.
        # This is DATA coverage, not a substitute for the fixed native fixture.
        import hashlib, json
        from types import SimpleNamespace
        owner_tree = ast.parse(self.owner)
        names = {"need", "identity", "decimal", "decode", "pairs", "constant", "canonical", "digest",
                 "registration_fixture_result", "registration_fixture_failure", "registration_rust_test_record",
                 "registration_rust_tests_result", "installer_worker_rust_test_record", "installed_reader_rust_test_record",
                 "installer_worker_rust_tests_result", "installed_reader_rust_tests_result", "_rust_test_output",
                 "registration_clock_data", "registration_publication_tick", "registration_reservation_result",
                 "_rust_tests_data", "installer_worker_rust_tests_data", "installed_reader_rust_tests_data",
                 "registration_app_rust_test_record", "registration_app_rust_tests_result",
                 "removal_native_rust_test_record", "removal_native_rust_tests_result", "removal_app_rust_test_record",
                 "removal_app_rust_tests_result", "removal_data_result", "installer_worker_diagnostic_sources",
                 "installer_worker_diagnostic_result", "installer_worker_diagnostic_data",
                 "integration_native_rust_test_record", "integration_native_rust_tests_result",
                 "integration_app_rust_test_record", "integration_app_rust_tests_result",
                 "integration_parent_rust_test_record", "integration_parent_rust_tests_result", "removal_integration_data_result",
                 "parent_rust_test_record", "parent_rust_tests_result", "record_rust_test_record", "record_rust_tests_result", "removal_parent_data_result",
                 "changes_rust_test_record", "changes_rust_tests_result", "removal_changes_data_result",
                 "recovery_rust_test_record", "recovery_rust_tests_result", "removal_recovery_data_result"}
        available = {node.name: node for node in owner_tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        # Decode's exact small standard-library helpers are selected from SOURCE, never import main.
        functions = [available[name] for name in names if name in available]
        selected = next(node for node in owner_tree.body if isinstance(node, ast.ClassDef) and node.name == "Operation")
        methods = [node for node in selected.body if isinstance(node, ast.FunctionDef)
                   and node.name in {"execute_registration", "execute_removal_data", "registration_tick"}]
        self.assertEqual({node.name for node in methods}, {"execute_registration", "execute_removal_data", "registration_tick"})
        ns = {"re": re, "json": json, "hashlib": hashlib, "Path": Path}
        for node in owner_tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in {"TARGET", "NATIVE", "INSTALLER", "REGISTRATION_SOURCE", "REGISTRATION_ROLES",
                    "REGISTRATION_FACTS", "REGISTRATION_FAILURES", "REGISTRATION_RUST_TESTS", "INSTALLER_WORKER_RUST_TESTS",
                    "INSTALLED_READER_RUST_TESTS", "REGISTRATION_APP_RUST_TESTS", "REMOVAL_ROLES", "REMOVAL_SOURCES",
                    "REMOVAL_NATIVE_RUST_TESTS", "REMOVAL_APP_RUST_TESTS", "HELPER", "INTEGRATION_ROLES",
                    "INTEGRATION_NATIVE_RUST_TESTS", "INTEGRATION_APP_RUST_TESTS", "INTEGRATION_PARENT_RUST_TESTS", "INTEGRATION_SOURCES",
                    "PARENT_ROLES", "PARENT_RUST_TESTS", "RECORD_RUST_TESTS", "CHANGES_ROLES", "CHANGES_RUST_TESTS", "CHANGES_SOURCES", "RECOVERY_ROLES", "RECOVERY_NATIVE_RUST_TESTS"}:
                    ns[node.targets[0].id] = ast.literal_eval(node.value)
        parent_sources = next(node.value for node in owner_tree.body if isinstance(node, ast.Assign)
                              and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                              and node.targets[0].id == "PARENT_SOURCES")
        expected_parent_sources = ast.parse("CHANGES_SOURCES + ('desktop/src-tauri/src/macos_install_maintenance.rs',)", mode="eval").body
        self.assertEqual(ast.dump(parent_sources), ast.dump(expected_parent_sources))
        ns["PARENT_SOURCES"] = ns["CHANGES_SOURCES"] + ast.literal_eval(parent_sources.right)
        core_source = "desktop/src-tauri/src/macos_install_maintenance.rs"
        self.assertNotIn(core_source, ns["CHANGES_SOURCES"])
        self.assertEqual(len(ns["PARENT_SOURCES"]), 40)
        self.assertEqual(set(ns["PARENT_SOURCES"]), set(ns["CHANGES_SOURCES"]) | {core_source})
        ns["RECOVERY_SOURCES"] = ns["CHANGES_SOURCES"]
        ns["RECOVERY_RUST_TESTS"] = (ns["PARENT_RUST_TESTS"], ns["RECOVERY_NATIVE_RUST_TESTS"])
        ns.update(WORK_SECONDS=990, MAX_RAW=(1 << 61)-1, CHECKOUT=Path("/fixed-source"),
                  WORKFLOW="Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-maintenance-fixture.yml@refs/heads/verify/desktop-macos-maintenance-fixture")
        ref = available["Refused"]
        body = [ref, *functions, ast.ClassDef(name="Selected", bases=[], keywords=[], body=methods, decorator_list=[])]
        exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), "<registration-selected-data>", "exec"), ns)
        # Fixed expected header/roles independently assert the nomination, not just a caller echo.
        self.assertEqual(ns["REGISTRATION_ROLES"], ("reservation-rust-tests", "installer-worker-rust-tests", "installed-reader-rust-tests",
                          "registration-entry-build", "registration-fixture-build", "registration-fixture-run"))
        self.assertEqual(ns["REGISTRATION_RUST_TESTS"], (
            "android_service_management::tests::native_report_cannot_fabricate_authority_or_inconsistent_phase_success",
            "android_service_management::tests::actual_native_failure_precedes_return_callback_and_all_cleanup_gates"))
        native = {"type": "mrk-macos-registration-reservation-fixture-v1", "schemaVersion": 1,
                  "target": "aarch64-apple-darwin", "sourceCommit": "a"*40, "outcome": "passed", "failure": None,
                  "workTimeoutSeconds": 20, "hardTimeoutSeconds": 22,
                  "facts": {name: True for name in ns["REGISTRATION_FACTS"]},
                  "originals": {"opened": 61, "closedKnown": 61, "closeUnknown": False, "liveAtReturn": 0},
                  "rootCreated": True, "rootRetired": True, "internalAcquirePostCovered": False,
                  "serviceApiEntered": False, "unknownNativeFaultInjected": False, "productionIdentityQualified": False}
        def pretty(names):
            count = len(names)
            return ("\nrunning " + str(count) + (" test\n" if count == 1 else " tests\n")
                    + "".join("test " + name + " ... ok\n" for name in names)
                    + "\ntest result: ok. " + str(count) + " passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\n").encode()
        self.assertEqual(ns["REGISTRATION_APP_RUST_TESTS"], ('installed_runtime::installation_observation::installation_roster_uses_fixed_app_name_and_global_inventory_bound', 'saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::callback_stamp_needs_exclusive_capture_return_then_original_owner_finality', 'saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::maintenance_preserves_observed_not_registered_after_later_cleanup_unknown', 'saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::register_observation_failure_is_at_real_return_and_stop_keeps_original_deadlines', 'saved_command_owner::android_registration::maintenance::selected::tests::prepared_requires_all_original_facts_and_partial_unregister_never_reopens'))
        app_stdout = pretty(ns["REGISTRATION_APP_RUST_TESTS"])
        app_record = ns["registration_app_rust_tests_result"](app_stdout)
        self.assertEqual(app_record["passed"], 5)
        for malformed in (
            pretty(ns["REGISTRATION_APP_RUST_TESTS"][:-1]),
            pretty((*ns["REGISTRATION_APP_RUST_TESTS"][:-1], "other::test")),
            pretty((*ns["REGISTRATION_APP_RUST_TESTS"], "other::extra")),
            pretty((*ns["REGISTRATION_APP_RUST_TESTS"][:-1], ns["REGISTRATION_APP_RUST_TESTS"][0])),
            app_stdout.replace(b"... ok", b"... ignored", 1),
            app_stdout.replace(b"... ok", b"... FAILED", 1),
        ):
            with self.assertRaises(ns["Refused"]):
                ns["registration_app_rust_tests_result"](malformed)
        for fault in (None, "native-nonzero", "native-malformed", "native-unknown", "late-close", "late-publication", "image-post"):
            with self.subTest(registration=fault):
                clock = SimpleNamespace(now=1000000000, CLOCK_MONOTONIC=1)
                clock.clock_gettime_ns = lambda _kind: clock.now
                ns["time"] = clock
                op = ns["Selected"]()
                op.calls, op.cleanup_errors, op.scratch_origins, op.artifacts = [], [], {}, {}
                op.scratch = Path("/fixed-work/e2-native-fixture")
                op.environment = {"GITHUB_SHA": "a"*40, "DEVELOPER_DIR": "/fixed-developer"}
                op.registration_clock_failed = False
                op.installer_worker_rust_tests = op.installed_reader_rust_tests = None
                op.release = "fixed-release"
                events = []
                def check(): events.append("source-post")
                source_names = (ns["REGISTRATION_SOURCE"], "desktop/native/macos-installed-entry/entry.c",
                    "desktop/native/macos-installed-entry/gate.c", "desktop/native/macos-installed-entry/gate.h",
                    "desktop/native/macos-installed-entry/fixed_paths.h", ns["NATIVE"] + "/src/native.m")
                op.source = SimpleNamespace(read=lambda name: name.encode(), book=SimpleNamespace(check=check),
                    rows={name: {"sha256": hashlib.sha256(name.encode()).hexdigest()} for name in source_names})
                def read(entry):
                    if fault == "image-post" and len(op.calls) == 6:
                        return b"changed"
                    return entry["body"]
                op.outputs = SimpleNamespace(check=lambda: events.append("output-post"),
                    file=lambda path, limit, modes: ({"body": path.name.encode()}, path.name.encode()), read=read)
                op.stager = SimpleNamespace(entry_macho=lambda body: events.append("macho"))
                op.begin = lambda: events.append("begin")
                op.mkdir = lambda path: {"identity": (1,2,3,4,5)}
                op.compiler_environment = lambda target: ("/fixed-cargo", {})
                op.native_environment = lambda: {"PATH": "/usr/bin:/bin"}
                def retire(target): events.append("retire:" + target.name)
                op.retire_target = retire
                def call(role, argv, environment, *, cwd, timeout, limit=65536):
                    events.append(role)
                    op.phase = role
                    index = ns["REGISTRATION_ROLES"].index(role)
                    if index < 3:
                        expected = (ns["REGISTRATION_RUST_TESTS"], ns["INSTALLER_WORKER_RUST_TESTS"], ns["REGISTRATION_APP_RUST_TESTS"])[index]
                        self.assertEqual(argv[-len(expected):], list(expected))
                        self.assertIn("--offline", argv)
                        stdout = pretty(expected)
                    elif index == 5:
                        self.assertEqual(argv, ["/usr/bin/sudo", "-n", "--", str(op.scratch / "registration-facade-target/fixture")])
                        self.assertEqual(cwd, op.scratch / "cwd")
                        stdout = ns["canonical"](native)
                    else:
                        self.assertEqual(argv[:5], ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x"])
                        stdout = b""
                    record = {"role": role, "entered": True, "returned": True, "returncode": 0,
                              "workTimeoutSeconds": timeout, "outputLimitBytes": limit,
                              "stdoutSha256": hashlib.sha256(stdout).hexdigest(), "stderrSha256": hashlib.sha256(b"").hexdigest()}
                    op.calls.append(record)
                    if index == 5 and fault == "native-unknown":
                        record["returned"] = False
                        raise KeyboardInterrupt()
                    code = 65 if index == 5 and fault == "native-nonzero" else 0
                    record["returncode"] = code
                    if index == 5 and fault == "native-malformed": stdout = b"{}\n"
                    return SimpleNamespace(returncode=code, stdout=stdout, stderr=b"")
                op.command = op.call = call
                def finish():
                    events.append("finish")
                    op.sources_closed = op.outputs_closed = op.protected_closed = True
                    op.scratch_retired = not op.cleanup_errors
                    if fault == "late-close": clock.now += 991000000000
                op.finish = finish
                def receipt(failure):
                    value = {"failure": failure, "artifacts": op.artifacts, "source": "a"*40,
                             "workflowSource": "a"*40, "workflow": ns["WORKFLOW"], "phase": op.phase,
                             "sourceClosesKnown": op.sources_closed, "outputClosesKnown": op.outputs_closed,
                             "protectedClosesKnown": op.protected_closed, "scratchRetired": op.scratch_retired,
                             "cleanupErrors": op.cleanup_errors, "installedArtifactRoster": None,
                             "receiptOriginals": [], "protectedMetadataObservations": [],
                             "installerContext": {"started": False, "completed": False},
                             "serviceLayoutObservation": {"selected": False, "started": False},
                             "installerWorkerRustTests": op.installer_worker_rust_tests,
                             "installedReaderRustTests": op.installed_reader_rust_tests, "originalCalls": op.calls}
                    value.update({key: False for key in ("installerEntered", "installationReturnedSuccess", "nativeEntered",
                        "nativeOwnerReturned", "protectedRetentionRequired", "exactReceiptRetired", "productionIdentityQualified",
                        "actualAppIntegrationQualified", "distributionQualified")})
                    value.update({key: None for key in ("native", "nativeRustTests", "package", "producerSigningRustTests",
                        "packageProducerRustTests", "contextReceiptDiagnostic")})
                    return value
                op.receipt = receipt
                result = op.execute_registration()
                self.assertEqual([row["role"] for row in op.calls], list(ns["REGISTRATION_ROLES"]))
                self.assertEqual(events.count("finish"), 1)
                if fault in (None, "late-publication"):
                    self.assertTrue(result["passed"])
                    self.assertIsNone(result["failure"])
                    self.assertIn("retire:registration-facade-target", events)
                    record = result["artifacts"]["registration-reservation"]
                    previous = int(record["clock"]["lastNs"])
                    if fault == "late-publication":
                        clock.now += 991000000000
                        with self.assertRaisesRegex(ns["Refused"], "^registration-publication-clock$"):
                            ns["registration_publication_tick"](record, previous)
                    else:
                        self.assertEqual(ns["registration_publication_tick"](record, previous), clock.now)
                        projected = ns["registration_reservation_result"](result, "a"*40, op.source.rows)
                        self.assertFalse(projected["fullE2Qualified"])
                        self.assertTrue(projected["native"]["facts"]["laterMetadataRefused"])
                        for mutation in ("role", "cap", "limit", "close", "source", "native", "clock", "legacy"):
                            changed = json.loads(json.dumps(result))
                            if mutation == "role": changed["originalCalls"][0]["role"] = "native-run"
                            elif mutation == "cap": changed["originalCalls"][-1]["workTimeoutSeconds"] = 26
                            elif mutation == "limit": changed["originalCalls"][-1]["outputLimitBytes"] = 8193
                            elif mutation == "close": changed["sourceClosesKnown"] = False
                            elif mutation == "source": changed["artifacts"]["registration-reservation"]["sourceHashes"][source_names[0]] = "0"*64
                            elif mutation == "native": changed["artifacts"]["registration-reservation"]["native"]["originals"]["closedKnown"] = 60
                            elif mutation == "legacy": changed["installedReaderRustTests"] = ns["installed_reader_rust_test_record"]()
                            else: changed["artifacts"]["registration-reservation"]["clock"]["closed"] = False
                            with self.subTest(registration_mutation=mutation), self.assertRaises(ns["Refused"]):
                                ns["registration_reservation_result"](changed, "a"*40, op.source.rows)
                        failed = json.loads(json.dumps(native))
                        failed.update(outcome="failed", failure="later-post")
                        self.assertEqual(ns["registration_fixture_failure"](ns["canonical"](failed), 65, "a"*40), failed)
                        with self.assertRaises(ns["Refused"]):
                            ns["registration_fixture_result"](ns["canonical"](failed), 65, "a"*40)
                        failed["failure"] = "/private/unknown-name"
                        with self.assertRaises(ns["Refused"]):
                            ns["registration_fixture_failure"](ns["canonical"](failed), 65, "a"*40)
                else:
                    self.assertFalse(result["passed"])
                    wanted = {"native-nonzero": "original-command-failed", "native-malformed": "registration-fixture-shape",
                              "native-unknown": "registration-original-refused-or-unknown", "late-close": "registration-phase-clock",
                              "image-post": "registration-image-post"}[fault]
                    self.assertEqual(result["failure"], wanted)
                    if fault != "late-close": self.assertNotIn("retire:registration-facade-target", events)
                self.assertFalse(any(name in events for name in ("sign", "package", "installer", "btm", "context")))

        # Both fixed selectors run the actual original-owner method with inert adapters.
        # No Cargo, native, filesystem, clock or public publication is executed here.
        self.assertEqual(ns["REMOVAL_ROLES"], ("removal-native-rust-tests", "removal-app-rust-tests"))
        self.assertEqual((len(ns["REMOVAL_NATIVE_RUST_TESTS"]), len(ns["REMOVAL_APP_RUST_TESTS"])), (4, 10))
        self.assertEqual(ns["REMOVAL_NATIVE_RUST_TESTS"][-1],
                         "removal_coordinator::tests::cutoff_preserves_same_original_not_equal_data_and_fixed_endpoints")
        self.assertEqual(tuple(sum(name.startswith(prefix) for name in ns["REMOVAL_APP_RUST_TESTS"])
                         for prefix in ("macos_remove_producer::", "macos_remove_record::", "macos_remove_protocol::")), (2, 3, 5))
        self.assertEqual(ns['INTEGRATION_ROLES'], (
            'removal-integration-native-rust-tests',
            'removal-integration-app-rust-tests',
            'removal-integration-parent-rust-tests',
        ))
        self.assertEqual(ns['INTEGRATION_NATIVE_RUST_TESTS'], (
            'android_registration::tests::removal_cutoff_contracts_same_signal_without_rearming_or_widening_wire',
            'removal_coordinator::tests::cutoff_preserves_same_original_not_equal_data_and_fixed_endpoints',
            'removal_coordinator::peer::tests::peer_binding_and_actual_verifier_roles_are_closed_data',
            'removal_coordinator::peer::tests::peer_phase_ledger_rejects_cross_slot_replay_and_false_consumption',
            'removal_coordinator::peer::tests::peer_actual_challenge_copy_and_post_precede_single_cutoff_factory',
            'removal_coordinator::peer::tests::peer_consuming_original_is_recorded_before_late_post_and_never_retried',
        ))
        self.assertEqual(ns['INTEGRATION_APP_RUST_TESTS'], (
            'saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::removal_raw_clock_expiry_precedes_projection_and_hard_never_renews',
            'edit_owner::installed_configuration_data_tests::installed_configuration_owner_contract_is_inert',
            'installed_runtime::installation_observation::installation_roster_uses_fixed_app_name_and_global_inventory_bound',
            'macos_install_record::tests::android_service_inventory_pair_and_executable_scope',
            'macos_remove_protocol::tests::four_frames_bind_both_targets_roles_and_preparation_labels_as_data_only',
            'macos_remove_protocol::tests::closed_json_types_duplicates_and_exact_framing_refuse_without_a_second_message',
            'macos_remove_protocol::tests::current_binding_direction_order_and_fresh_nonce_data_cannot_be_replayed',
            'macos_remove_protocol::tests::original_raw_endpoints_equality_regression_and_first_refusal_never_renew',
            'macos_remove_protocol::tests::fixed_encoding_capacity_and_retained_storage_count_real_copies',
        ))
        self.assertEqual(ns['INTEGRATION_PARENT_RUST_TESTS'], (
            'installer::worker::tests::same_absolute_endpoint_reserves_settlement_and_rejects_backwards_or_overflow',
            'installer::worker::tests::private_frames_require_fixed_binding_shapes_bounds_and_no_future_finality',
        ))
        self.assertEqual(len(ns["INTEGRATION_SOURCES"]), 30)
        self.assertEqual(ns["PARENT_ROLES"], ("removal-parent-rust-tests", "removal-record-rust-tests"))
        self.assertEqual(ns["RECORD_RUST_TESTS"], ("macos_remove_record::tests::fresh_removal_and_reinstall_table_never_upgrades_old_failure",))
        self.assertIn("desktop/src-tauri/src/macos_install_record.rs", ns["PARENT_SOURCES"])
        self.assertIn("desktop/src-tauri/src/macos_remove_record.rs", ns["PARENT_SOURCES"])
        self.assertEqual(ns["PARENT_RUST_TESTS"], (
            "installer::worker::tests::private_frames_require_fixed_binding_shapes_bounds_and_no_future_finality",
            "installer::worker::tests::original_join_requires_eof_closes_matching_return_and_timely_sources"))
        self.assertEqual(len(ns["CHANGES_SOURCES"]), 39)
        self.assertIn("desktop/src-tauri/src/android_build_owner.rs", ns["CHANGES_SOURCES"])
        self.assertIn("desktop/src-tauri/src/macos_remove_record.rs", ns["CHANGES_SOURCES"])
        self.assertEqual(ns["CHANGES_ROLES"], ('removal-changes-parent-rust-tests', 'removal-changes-app-rust-tests', 'removal-changes-native-rust-tests', 'removal-changes-emitter-rust-tests'))
        self.assertEqual(ns["CHANGES_RUST_TESTS"], (('installer::worker::tests::private_frames_require_fixed_binding_shapes_bounds_and_no_future_finality', 'installer::worker::tests::original_join_requires_eof_closes_matching_return_and_timely_sources'), ('asset_session::macos_removal::tests::fixed_ingress_and_private_completion_never_replace_originals', 'asset_session::macos_maintenance::tests::new_work_closure_is_not_stop_and_preserves_lock_and_quit_routes', 'asset_session::installation_memory::known::tests::fixed_session_partition_and_overflow_refuse_without_credit', 'edit_owner::installed_configuration_data_tests::installed_configuration_owner_contract_is_inert', 'installed_runtime::installation_observation::installation_roster_uses_fixed_app_name_and_global_inventory_bound', 'macos_remove_record::tests::removal_record_closed_schema_and_bindings_are_data_only', 'macos_remove_record::tests::removal_prefix_failure_and_new_attempt_never_rewrite_history'), ('removal_coordinator::tests::cutoff_preserves_same_original_not_equal_data_and_fixed_endpoints',), ('emitter::tests::fixed_remove_inputs_rosters_and_original_finality_refuse_install_or_partial_routes',)))
        self.assertEqual(ns["CHANGES_RUST_TESTS"][0], ns["PARENT_RUST_TESTS"])
        self.assertEqual(ns["RECOVERY_ROLES"], ('removal-recovery-parent-rust-tests', 'removal-recovery-native-rust-tests'))
        self.assertEqual(ns["RECOVERY_NATIVE_RUST_TESTS"], ('install_producer::tests::report_decoder_binds_slots_error_outputs_and_consuming_returns', 'install_producer::tests::signature_result_requires_same_owner_finality_and_late_gate_refuses', 'install_producer::tests::unknown_native_or_gate_custody_never_releases_or_publishes_success', 'removal_coordinator::peer::tests::peer_binding_and_actual_verifier_roles_are_closed_data'))
        self.assertEqual(ns["RECOVERY_SOURCES"], ns["CHANGES_SOURCES"])
        self.assertEqual(ns["RECOVERY_RUST_TESTS"][0], ns["PARENT_RUST_TESTS"])
        for profile in (False, True, "parent", "changes", "recovery"):
            changes = profile == "changes"
            recovery = profile == "recovery"
            changed_parser = ns["recovery_rust_tests_result" if recovery else "changes_rust_tests_result"]
            changed_record = ns["recovery_rust_test_record" if recovery else "changes_rust_test_record"]
            parent_only = profile == "parent"
            integration = profile is True
            roles = ns["INTEGRATION_ROLES" if integration else "REMOVAL_ROLES"]
            sources = ns["INTEGRATION_SOURCES" if integration else "REMOVAL_SOURCES"]
            native_names = ns["INTEGRATION_NATIVE_RUST_TESTS" if integration else "REMOVAL_NATIVE_RUST_TESTS"]
            app_names = ns["INTEGRATION_APP_RUST_TESTS" if integration else "REMOVAL_APP_RUST_TESTS"]
            parser_prefix = "integration_" if integration else "removal_"
            projection_parser = ns["removal_integration_data_result" if integration else "removal_data_result"]
            artifact = "removal-integration-data" if integration else "removal-data"
            selected_batches = (("native", native_names), ("app", app_names))
            if integration:
                selected_batches += (("parent", ns["INTEGRATION_PARENT_RUST_TESTS"]),)
            if parent_only:
                roles, sources = ns["PARENT_ROLES"], ns["PARENT_SOURCES"]
                projection_parser = ns["removal_parent_data_result"]
                artifact, parser_prefix = "removal-parent-data", ""
                selected_batches = (("parent", ns["PARENT_RUST_TESTS"]), ("record", ns["RECORD_RUST_TESTS"]))
            if changes:
                roles, sources = ns["CHANGES_ROLES"], ns["CHANGES_SOURCES"]
                projection_parser = ns["removal_changes_data_result"]
                artifact = "removal-changes-data"
                selected_batches = tuple(zip(("parent", "app", "native", "emitter"), ns["CHANGES_RUST_TESTS"]))
            if recovery:
                roles, sources = ns["RECOVERY_ROLES"], ns["RECOVERY_SOURCES"]
                projection_parser = ns["removal_recovery_data_result"]
                artifact = "removal-recovery-data"
                selected_batches = tuple(zip(("parent", "native"), ns["RECOVERY_RUST_TESTS"]))
            for index, (suffix, expected) in enumerate(selected_batches):
                parser = ((lambda raw, role=roles[index]: changed_parser(raw, role)) if changes or recovery
                          else ns[parser_prefix + suffix + "_rust_tests_result"])
                raw = pretty(expected)
                self.assertEqual(parser(raw)["passed"], len(expected))
                for bad in (pretty(()), pretty(expected[:-1]), pretty(expected + (expected[0],)),
                            raw.replace(expected[0].encode(), b"unknown_test"), raw.replace(b" ... ok", b" ... FAILED", 1),
                            raw.replace(b"0 ignored", b"1 ignored"), raw + b"test unlisted ... ok\n"):
                    with self.subTest(removal_parser=suffix), self.assertRaises(ns["Refused"]): parser(bad)
            faults = (None, "nonzero", "optional-interrupt", "unknown", "malformed", "source-post", "late-close", "close-throw", "late-publication")
            if integration:
                faults += ("parent-nonzero", "parent-unknown", "parent-malformed")
            if changes or recovery or parent_only:
                faults += tuple("changed-" + str(index) + "-" + kind for index in range(1, len(roles))
                                for kind in ("nonzero", "unknown", "malformed"))
            for fault in faults:
                changed_fault = fault.split("-") if fault and fault.startswith("changed-") else None
                with self.subTest(removal=fault, profile=profile):
                    clock = SimpleNamespace(now=1000000000, CLOCK_MONOTONIC=1)
                    clock.clock_gettime_ns = lambda _kind: clock.now
                    ns["time"] = clock
                    op = ns["Selected"]()
                    op.calls, op.cleanup_errors, op.scratch_origins, op.artifacts = [], [], {}, {}
                    op.scratch = Path("/fixed-work/e2-native-fixture")
                    op.environment = {"GITHUB_SHA": "a" * 40}
                    op.registration_clock_failed = False
                    op.phase = "prepare"
                    op.removal_integration_selected = integration
                    op.removal_parent_selected = parent_only
                    op.removal_changes_selected = changes
                    op.removal_recovery_selected = recovery
                    events = []
                    op.source = SimpleNamespace(read=lambda name: name.encode(),
                        rows={name: {"sha256": hashlib.sha256(name.encode()).hexdigest()} for name in sources})
                    op.begin = lambda: events.append("begin")
                    op.mkdir = lambda path: {"identity": (1, 2, 3, 4, 5)}
                    op.compiler_environment = lambda target: ("/fixed-cargo", {})
                    def retire(target):
                        events.append("retire:" + target.name)
                        if fault == "source-post": raise ns["Refused"]("changed-source")
                    op.retire_target = retire
                    def call(role, argv, environment, *, cwd, timeout, limit):
                        events.append(role); op.phase = role
                        index = roles.index(role)
                        expected = selected_batches[index][1]
                        flags = ["--features", "package-producer-signing", "--lib"] if index == 0 and not integration else ["--lib"]
                        if parent_only and index == 0 or integration and index == 2:
                            flags = ["--features", "macos-installed-remover", "--bin", "mrk-macos-remove"]
                        directory = ns["NATIVE"] if index == 0 and not parent_only else ns["INSTALLER"]
                        if changes:
                            flags = (["--features", "macos-installed-remover", "--bin", "mrk-macos-remove"],
                                     ["--lib"], ["--features", "package-producer-signing", "--lib"],
                                     ["--features", "macos-remove-producer", "--example", "macos_remove_producer"])[index]
                            directory = ns["NATIVE"] if index == 2 else ns["INSTALLER"]
                        if recovery:
                            flags = (["--features", "macos-installed-remover", "--bin", "mrk-macos-remove"],
                                     ["--features", "package-producer-signing", "--lib"])[index]
                            directory = ns["INSTALLER"] if index == 0 else ns["NATIVE"]
                        self.assertEqual(argv, ["/fixed-cargo", "test", "--manifest-path", str(ns["CHECKOUT"] / directory / "Cargo.toml"),
                            "--locked", "--offline", "--jobs", "1", "--target", ns["TARGET"], "--no-default-features", *flags,
                            "--message-format=short", "--color", "never", "--", "--exact", "--test-threads=1", "--format", "pretty", "--color", "never", *expected])
                        self.assertEqual((cwd, timeout, limit), (ns["CHECKOUT"], 480, 4194304))
                        raw = pretty(expected)
                        failed_here = index == (int(changed_fault[1]) if changed_fault else 2 if fault in ("parent-nonzero", "parent-unknown", "parent-malformed") else 0)
                        code = 65 if failed_here and fault in ("nonzero", "optional-interrupt", "parent-nonzero") else 0
                        if changed_fault and failed_here:
                            code = 65 if changed_fault[2] == "nonzero" else 0
                        if failed_here and (fault in ("malformed", "parent-malformed") or changed_fault and changed_fault[2] == "malformed"):
                            raw = pretty(expected[:-1])
                        record = {"role": role, "entered": True, "returned": True, "returncode": code,
                                  "workTimeoutSeconds": timeout, "outputLimitBytes": limit,
                                  "stdoutSha256": hashlib.sha256(raw).hexdigest(), "stderrSha256": hashlib.sha256(b"").hexdigest()}
                        op.calls.append(record)
                        if failed_here and (fault in ("unknown", "parent-unknown") or changed_fault and changed_fault[2] == "unknown"):
                            record["returned"] = False
                            raise KeyboardInterrupt()
                        return SimpleNamespace(returncode=code, stdout=raw, stderr=b"")
                    op.call = call
                    def finish():
                        events.append("finish")
                        if fault == "close-throw": raise KeyboardInterrupt()
                        op.sources_closed = op.outputs_closed = op.protected_closed = True
                        op.scratch_retired = not op.cleanup_errors and all(row["returned"] for row in op.calls)
                        if fault == "late-close": clock.now += 991000000000
                    op.finish = finish
                    def receipt(failure):
                        value = {"failure": failure, "artifacts": op.artifacts, "source": "a" * 40,
                            "workflowSource": "a" * 40, "workflow": ns["WORKFLOW"], "phase": op.phase,
                            "sourceClosesKnown": op.sources_closed, "outputClosesKnown": op.outputs_closed,
                            "protectedClosesKnown": op.protected_closed, "scratchRetired": op.scratch_retired,
                            "cleanupErrors": op.cleanup_errors, "installedArtifactRoster": None,
                            "receiptOriginals": [], "protectedMetadataObservations": [],
                            "installerContext": {"started": False, "completed": False},
                            "serviceLayoutObservation": {"selected": False, "started": False},
                            "btmLogObservation": {"state": "not-requested"}, "originalCalls": op.calls}
                        value.update({key: False for key in ("installerEntered", "installationReturnedSuccess", "nativeEntered",
                            "nativeOwnerReturned", "protectedRetentionRequired", "exactReceiptRetired", "protectedRootRetired",
                            "productionIdentityQualified", "actualAppIntegrationQualified", "distributionQualified")})
                        value.update({key: None for key in ("native", "nativeRustTests", "package", "producerSigningRustTests",
                            "packageProducerRustTests", "contextReceiptDiagnostic", "installedReaderRustTests", "installerWorkerRustTests")})
                        return value
                    op.receipt = receipt
                    original_diagnostic = ns["installer_worker_diagnostic_result"]
                    def interrupted(*_args, **_kwargs): raise KeyboardInterrupt()
                    if fault == "optional-interrupt": ns["installer_worker_diagnostic_result"] = interrupted
                    try:
                        result = op.execute_removal_data()
                    finally:
                        ns["installer_worker_diagnostic_result"] = original_diagnostic
                    self.assertEqual(events.count("finish"), 1)
                    count = len(roles) if fault in (None, "late-close", "close-throw", "late-publication", "parent-nonzero", "parent-unknown", "parent-malformed") else 1
                    if changed_fault: count = int(changed_fault[1]) + 1
                    self.assertEqual([row["role"] for row in op.calls], list(roles[:count]))
                    if fault in (None, "late-publication"):
                        self.assertTrue(result["passed"])
                        projection = projection_parser(result, "a" * 40, op.source.rows)
                        self.assertEqual(projection["scope"], "removal-recovery-compiled-data-only" if recovery else "removal-changes-compiled-data-only" if changes else "removal-parent-record-compiled-data-only" if parent_only else "removal-integration-compiled-data-only" if integration else "removal-compiled-data-only")
                        opposite = ns["removal_data_result" if integration else "removal_integration_data_result"]
                        with self.assertRaises(ns["Refused"]): opposite(result, "a" * 40, op.source.rows)
                        self.assertFalse(projection["liveRemovalQualified"] or projection["fullE2Qualified"])
                        if changes or recovery:
                            keys = ("parentRustTests", "nativeRustTests") if recovery else ("parentRustTests", "appRustTests", "nativeRustTests", "emitterRustTests")
                            self.assertEqual(set(result["artifacts"][artifact]), {"clock", "sourceHashes", *keys})
                            self.assertEqual(len(projection["originalCalls"]), len(roles))
                            for index, key in enumerate(keys):
                                self.assertEqual(projection[key], changed_record(roles[index]))
                                for problem in ("missing", "cross", "ignored", "extra-call", "missing-call"):
                                    altered = json.loads(json.dumps(result))
                                    if problem == "missing": del altered["artifacts"][artifact][key]
                                    elif problem == "cross": altered["artifacts"][artifact][key] = projection[keys[(index+1)%len(keys)]]
                                    elif problem == "ignored": altered["artifacts"][artifact][key]["ignored"] = 1
                                    elif problem == "extra-call": altered["originalCalls"].append(dict(altered["originalCalls"][-1]))
                                    else: altered["originalCalls"].pop(index)
                                    with self.subTest(changes_record=key, problem=problem), self.assertRaises(ns["Refused"]):
                                        projection_parser(altered, "a" * 40, op.source.rows)
                            with self.assertRaises(ns["Refused"]): ns["removal_parent_data_result"](result, "a" * 40, op.source.rows)
                            if recovery:
                                with self.assertRaises(ns["Refused"]): ns["removal_changes_data_result"](result, "a" * 40, op.source.rows)
                                for extra in ("appRustTests", "emitterRustTests"):
                                    altered = json.loads(json.dumps(result)); altered["artifacts"][artifact][extra] = None
                                    with self.assertRaises(ns["Refused"]): projection_parser(altered, "a" * 40, op.source.rows)
                        if parent_only:
                            self.assertEqual(set(result["artifacts"][artifact]), {"clock", "parentRustTests", "recordRustTests", "sourceHashes"})
                            self.assertEqual(projection["parentRustTests"], ns["parent_rust_test_record"]())
                            self.assertEqual(projection["recordRustTests"], ns["record_rust_test_record"]())
                            self.assertEqual(len(projection["originalCalls"]), 2)
                            self.assertEqual(set(projection["sourceHashes"]), set(ns["PARENT_SOURCES"]))
                            for source_problem in ("missing-core", "mismatched-core"):
                                changed = json.loads(json.dumps(result))
                                hashes = changed["artifacts"][artifact]["sourceHashes"]
                                if source_problem == "missing-core": del hashes[core_source]
                                else:
                                    hashes[core_source] = "e" * 64
                                    self.assertNotEqual(hashes[core_source], op.source.rows[core_source]["sha256"])
                                with self.subTest(parent_source=source_problem), self.assertRaisesRegex(ns["Refused"], "^removal-source-binding$"):
                                    projection_parser(changed, "a" * 40, op.source.rows)
                            for problem in ("missing-record", "cross-record", "ignored", "one-call", "extra-call", "old-phase"):
                                changed = json.loads(json.dumps(result))
                                data = changed["artifacts"][artifact]
                                if problem == "missing-record": del data["recordRustTests"]
                                elif problem == "cross-record": data["recordRustTests"] = data["parentRustTests"]
                                elif problem == "ignored": data["recordRustTests"]["ignored"] = 1
                                elif problem == "one-call": changed["originalCalls"].pop()
                                elif problem == "extra-call": changed["originalCalls"].append(dict(changed["originalCalls"][-1]))
                                else: changed["phase"] = roles[0]
                                with self.subTest(parent_record=problem), self.assertRaises(ns["Refused"]):
                                    projection_parser(changed, "a" * 40, op.source.rows)
                            for key in ("nativeRustTests", "appRustTests"):
                                changed = json.loads(json.dumps(result))
                                changed["artifacts"][artifact][key] = None
                                with self.subTest(parent_extra=key), self.assertRaises(ns["Refused"]):
                                    projection_parser(changed, "a" * 40, op.source.rows)
                        if integration:
                            self.assertEqual(projection["parentRustTests"], ns["integration_parent_rust_test_record"]())
                            for parent_fault in ("missing", "legacy", "cross", "extra-call", "missing-call"):
                                changed = json.loads(json.dumps(result))
                                if parent_fault == "missing": del changed["artifacts"][artifact]["parentRustTests"]
                                elif parent_fault == "legacy": changed["installerWorkerRustTests"] = projection["parentRustTests"]
                                elif parent_fault == "cross": changed["artifacts"][artifact]["parentRustTests"] = projection["nativeRustTests"]
                                elif parent_fault == "extra-call": changed["originalCalls"].append(dict(changed["originalCalls"][-1]))
                                else: changed["originalCalls"].pop()
                                with self.subTest(parent_fault=parent_fault), self.assertRaises(ns["Refused"]):
                                    projection_parser(changed, "a" * 40, op.source.rows)
                        for mutation in ("role", "cap", "limit", "close", "source", "legacy", "clock", "extra", "btm"):
                            changed = json.loads(json.dumps(result))
                            if mutation == "role": changed["originalCalls"][0]["role"] = "native-run"
                            elif mutation == "cap": changed["originalCalls"][0]["workTimeoutSeconds"] = 481
                            elif mutation == "limit": changed["originalCalls"][0]["outputLimitBytes"] += 1
                            elif mutation == "close": changed["outputClosesKnown"] = False
                            elif mutation == "source": changed["artifacts"][artifact]["sourceHashes"][sources[0]] = "0" * 64
                            elif mutation == "legacy": changed["installedReaderRustTests"] = {}
                            elif mutation == "clock": changed["artifacts"][artifact]["clock"]["closed"] = False
                            elif mutation == "extra": changed["artifacts"]["registration-reservation"] = {}
                            else: changed["btmLogObservation"]["state"] = "observed"
                            with self.subTest(removal_mutation=mutation), self.assertRaises(ns["Refused"]):
                                projection_parser(changed, "a" * 40, op.source.rows)
                        if fault == "late-publication":
                            clock.now += 991000000000
                            with self.assertRaisesRegex(ns["Refused"], "^registration-publication-clock$"):
                                ns["registration_publication_tick"](projection, int(projection["clock"]["lastNs"]))
                    else:
                        self.assertFalse(result["passed"])
                        expected_reason = {"nonzero": "original-command-failed", "optional-interrupt": "original-command-failed",
                            "unknown": "removal-original-refused-or-unknown", "malformed": "removal-native-rust-test-framing",
                            "source-post": "changed-source", "late-close": "registration-phase-clock", "close-throw": "removal-finalization-unknown",
                            "parent-nonzero": "original-command-failed", "parent-unknown": "removal-original-refused-or-unknown",
                            "parent-malformed": "installer-worker-rust-test-framing"}.get(fault)
                        if changed_fault:
                            expected_reason = {"nonzero": "original-command-failed", "unknown": "removal-original-refused-or-unknown",
                                               "malformed": "removal-changes-rust-test-framing"}[changed_fault[2]]
                        if changes and fault == "malformed": expected_reason = "removal-changes-rust-test-framing"
                        if recovery and (fault == "malformed" or changed_fault and changed_fault[2] == "malformed"):
                            expected_reason = "removal-recovery-rust-test-framing"
                        if parent_only and fault == "malformed": expected_reason = "installer-worker-rust-test-framing"
                        if parent_only and changed_fault and changed_fault[2] == "malformed":
                            expected_reason = "removal-record-rust-test-framing"
                        self.assertEqual(result["failure"], expected_reason)
                        self.assertFalse(result["artifacts"][artifact]["clock"]["closed"])
                        if fault == "unknown": self.assertFalse(any(event.startswith("retire:") for event in events))
                        if changed_fault and changed_fault[2] == "unknown":
                            self.assertNotIn("retire:" + roles[int(changed_fault[1])] + "-target", events)
                            self.assertEqual(sum(event.startswith("retire:") for event in events), int(changed_fault[1]))
                        if fault == "parent-unknown":
                            self.assertNotIn("retire:" + roles[2] + "-target", events)
                            self.assertEqual(sum(event.startswith("retire:") for event in events), 2)
        quartet = ns["recovery_rust_test_record"](ns["RECOVERY_ROLES"][1])
        self.assertEqual(ns["_rust_tests_data"](quartet, quartet, "removal-recovery-rust-test"), quartet)
        for size in (3, 5):
            bad = json.loads(json.dumps(quartet)); bad["passed"] = size
            bad["tests"] = (bad["tests"] + ["foreign_test"])[:size]
            with self.assertRaises(ns["Refused"]):
                ns["_rust_tests_data"](bad, quartet, "removal-recovery-rust-test")
        # Same parser retains current old contract and has no arbitrary test/path expansion.
        rows = {ns["REMOVAL_SOURCES"][-1]: {"sha256": "f" * 64}}
        for role, expected in ((ns["REMOVAL_ROLES"][0], ns["REMOVAL_NATIVE_RUST_TESTS"]),
                               (ns["REMOVAL_ROLES"][1], ns["REMOVAL_APP_RUST_TESTS"]),
                               (ns["INTEGRATION_ROLES"][0], ns["INTEGRATION_NATIVE_RUST_TESTS"]),
                               (ns["INTEGRATION_ROLES"][1], ns["INTEGRATION_APP_RUST_TESTS"]),
                               (ns["INTEGRATION_ROLES"][2], ns["INTEGRATION_PARENT_RUST_TESTS"]),
                               (ns["PARENT_ROLES"][0], ns["PARENT_RUST_TESTS"]),
                               (ns["PARENT_ROLES"][1], ns["RECORD_RUST_TESTS"]),
                               *zip(ns["CHANGES_ROLES"], ns["CHANGES_RUST_TESTS"]),
                               *zip(ns["RECOVERY_ROLES"], ns["RECOVERY_RUST_TESTS"]),
                               (None, ns["INSTALLER_WORKER_RUST_TESTS"])):
            raw = ("test " + expected[-1] + " ... FAILED\nthread '" + expected[-1]
                   + "' panicked at src/macos_remove_protocol.rs:12:3:\nprivate-value-must-not-escape\n").encode()
            diag = ns["installer_worker_diagnostic_result"](raw, b"", rows, removal_role=role)
            self.assertEqual(diag["failedTests"], [expected[-1]])
            self.assertNotIn("private-value", repr(diag))
            original = {"role": role or "installer-worker-rust-tests", "entered": True, "returned": True,
                        "returncode": 101, "workTimeoutSeconds": 479 if role else 480, "outputLimitBytes": 4194304,
                        "stdoutSha256": hashlib.sha256(raw).hexdigest(), "stderrSha256": hashlib.sha256(b"").hexdigest()}
            self.assertEqual(ns["installer_worker_diagnostic_data"](diag, original, rows, removal_role=role), diag)
            for change in ({"returncode": 0}, {"returned": False}, {"role": "native-run"}, {"workTimeoutSeconds": 481}, {"stderrSha256": "0" * 64}):
                self.assertIsNone(ns["installer_worker_diagnostic_data"](diag, dict(original, **change), rows, removal_role=role))
            if role is None:
                self.assertIsNone(ns["installer_worker_diagnostic_data"](diag, dict(original, workTimeoutSeconds=479), rows))
        # Actual parser: repeated E0425 must not hide first E0308/E0609 sites.
        def compiler_lines(codes):
            return b"".join(("src/macos_remove_protocol.rs:%d:3: error[%s]: private-text\n" % (i + 1, code)).encode()
                            for i, code in enumerate(codes))
        def projected(codes):
            raw = compiler_lines(codes)
            value = ns["installer_worker_diagnostic_result"](raw, b"", rows, removal_role=ns["PARENT_ROLES"][0])
            original = {"role": ns["PARENT_ROLES"][0], "entered": True, "returned": True, "returncode": 101,
                        "workTimeoutSeconds": 479, "outputLimitBytes": 4194304,
                        "stdoutSha256": hashlib.sha256(raw).hexdigest(), "stderrSha256": hashlib.sha256(b"").hexdigest()}
            self.assertEqual(ns["installer_worker_diagnostic_data"](value, original, rows,
                             removal_role=ns["PARENT_ROLES"][0]), value)
            self.assertNotIn("private-text", repr(value))
            return value
        exact = projected(["E0425"] * 12)
        self.assertEqual(len(exact["errorLocations"]), 12)
        self.assertFalse(exact["truncated"])
        repeated = projected(["E0425"] * 13)
        self.assertEqual(repeated["errorLocations"], exact["errorLocations"])
        self.assertTrue(repeated["truncated"])
        diverse = projected(["E0425"] * 13 + ["E0308", "E0609", "E0308"])
        self.assertEqual(diverse["errorCodes"], ["E0425", "E0308", "E0609"])
        self.assertEqual(len(diverse["errorLocations"]), 12)
        self.assertTrue(diverse["truncated"])
        self.assertEqual([(row["code"], row["line"]) for row in diverse["errorLocations"][-2:]],
                         [("E0609", 15), ("E0308", 14)])
        unique = ["E%04d" % i for i in range(12)]
        full = projected(unique + ["E0609"])
        self.assertEqual([row["code"] for row in full["errorLocations"]], unique)
        self.assertTrue(full["truncated"])  # No sole representative is ever evicted.
        capped = projected(["E%04d" % i for i in range(33)])
        self.assertEqual(len(capped["errorCodes"]), 32)
        self.assertEqual(len(capped["errorLocations"]), 12)
        self.assertTrue(capped["truncated"])
        selected_source = ast.get_source_segment(self.owner, next(node for node in selected.body
            if isinstance(node, ast.FunctionDef) and node.name == "execute_removal_data"))
        for excluded in ("sudo", "observe_btm_logs", "compile_facades", "run_native", "observe_installer_context", "sign("):
            self.assertNotIn(excluded, selected_source)
        self.assertIn('or getattr(self, "removal_selected", False)', self.owner)


    def preparation_diagnostic(self):
        """Extract literal tables and ONE pure function, not the preparation program."""
        prepare = self.preparation_source
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
        prepare = self.preparation_source
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
        prepare = self.preparation_source
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
        self.assertIn('CARGO_NET_OFFLINE="false"', prepare)
        self.assertIn('for index, directory in enumerate(manifests):', prepare)
        self.assertIn(flat('call("fetch-" + str(index), [str(bin_directory / "cargo"), "fetch", "--manifest-path", '
                           'str(CHECKOUT / directory / "Cargo.toml"), "--locked", "--target", TARGET], '
                           'fetch_environment, 240, 262144)'), flat(prepare))
        self.assertIn('CARGO_NET_OFFLINE="true"', compiler)
        self.assertEqual(active(self.steps[STEP_NAMES[4]]), active(EXPECTED_NATIVE))

    def native_owner_diagnostic(self):
        """Extract literal tables and ONE pure function, not publication/owner code."""
        publish = self.publication_source
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
        publish = self.publication_source
        upload, final = (self.steps[name] for name in STEP_NAMES[6:])
        source_loop = section(publish, "              for relative in (", "                  row = rows[relative]")
        self.assertEqual(flat(source_loop), flat(
            'for relative in ("desktop/tools/macos_e2_native_fixture.py", '
            '".github/workflows/desktop-macos-maintenance-fixture.yml", '
            '"desktop/tools/macos_maintenance_fixture_prepare.sh", '
            '"desktop/tools/macos_maintenance_fixture_publish.sh", '
            '"desktop/macos-installed-inputs/build-release.json", fixture.CONTEXT_SOURCE, fixture.LAYOUT_SOURCE, '
            '*((fixture.CONTEXT_DISTRIBUTION_SOURCE, fixture.CONTEXT_README_SOURCE) '
            'if CONTEXT_PRODUCT_SELECTED else ())):'))
        self.assertLess(publish.index('"summary-source-correspondence"'), publish.index('_entry, result_body ='))
        self.assertIn("MRK_NATIVE_STEP_OUTCOME: ${{ steps.native.outcome }}", active(self.steps[STEP_NAMES[5]]))
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
        self.assertIn('registrationReservation=registration, registrationReservationQualified=registration_qualified', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
            if 'summary["registrationReservationQualified"] =' in line], ['summary["registrationReservationQualified"] = False'] * 2)
        self.assertIn('b"registration_qualified=true\\n" if summary["registrationReservationQualified"] else b"registration_qualified=false\\n"', publish)
        self.assertEqual(publish.count('fixture.registration_publication_tick('), 24)
        self.assertGreater(publish.rindex('fixture.registration_publication_tick('), publish.index('os.close(fd)'))
        route = section(publish, '              # This committed workflow selects only the fixed public product Context.',
                        '              known_pass = (')
        self.assertIn('fixture.need(result["contextReceiptDiagnostic"] is None, "summary-context-receipt-route")', route)
        self.assertIn('context_receipt_diagnostic = None', route)
        self.assertIn('diagnostic_captured = False', route)
        self.assertNotIn('context_receipt_diagnostic_result(', route)
        self.assertIn('complete_context = fixture.context_observation_result(result, source)', route)
        self.assertIn('contextReceiptDiagnostic=context_receipt_diagnostic, diagnosticCaptured=bool(diagnostic_captured)', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines() if 'summary["diagnosticCaptured"] =' in line],
                         ['summary["diagnosticCaptured"] = False'] * 2)
        self.assertEqual([line.strip() for line in active(publish).splitlines() if 'summary["contextReceiptDiagnostic"] =' in line],
                         ['summary["contextReceiptDiagnostic"] = None'] * 2)
        self.assertIn('b"diagnostic_captured=true\\n" if summary["diagnosticCaptured"] else b"diagnostic_captured=false\\n"', publish)
        self.assertIn('context_completed = installer_context is not None and installer_context["completed"]', route)
        self.assertGreater(publish.index(route), publish.index('fixture.installer_context_calls(context_record, source, calls)'))
        self.assertIn('and native_rust_tests is not None and installer_worker_rust_tests is not None', gates)
        self.assertIn('and installed_reader_rust_tests is not None and producer_signing_rust_tests is not None', gates)
        self.assertIn('and package_producer_rust_tests is not None', gates)
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
        self.assertIn('return 0 if value["passed"] or context_completed or cocoa_completed else', main)
        self.assertNotIn('context_receipt_diagnostic_result(', main)
        self.assertLess(main.index('service_cocoa_result(value,'), main.index('body = canonical(value)'))
        self.assertLess(main.index('need(os.write(1, summary)'), main.index('return 0 if value["passed"]'))
        self.assertIn('registration = fixture.registration_reservation_result(result, source, rows)', route)
        self.assertIn('registration_last = fixture.registration_publication_tick(', route)
        self.assertIn('registration_qualified = registration is not None', route)
        self.assertIn('REMOVAL_DATA_SELECTED = False', publish)
        self.assertIn('REMOVAL_INTEGRATION_SELECTED = False', publish)
        self.assertIn('REMOVAL_PARENT_SELECTED = True', publish)
        self.assertIn('CONTEXT_PRODUCT_SELECTED = False', publish)
        self.assertIn('REMOVAL_CHANGES_SELECTED = False', publish)
        self.assertIn('REMOVAL_RECOVERY_SELECTED = False', publish)
        self.assertIn('if outcome == "success" and not CONTEXT_PRODUCT_SELECTED and not REMOVAL_DATA_SELECTED and not REMOVAL_INTEGRATION_SELECTED and not REMOVAL_PARENT_SELECTED and not REMOVAL_CHANGES_SELECTED and not REMOVAL_RECOVERY_SELECTED:', route)
        self.assertIn('if outcome == "success" and REMOVAL_DATA_SELECTED:', route)
        self.assertIn('removal_data = fixture.removal_data_result(result, source, rows)', route)
        self.assertIn('removalData=removal_data, removalDataQualified=removal_qualified, removalDataDiagnostic=removal_diagnostic,', publish)
        for field in ("removalData", "removalDataQualified", "removalDataDiagnostic",
                      "removalIntegrationData", "removalIntegrationDataQualified", "removalIntegrationDataDiagnostic",
                      "removalParentData", "removalParentDataQualified", "removalParentDataDiagnostic",
                      "removalChangesData", "removalChangesDataQualified", "removalChangesDataDiagnostic",
                      "removalRecoveryData", "removalRecoveryDataQualified", "removalRecoveryDataDiagnostic"):
            self.assertEqual(sum("summary[" + repr(field) + "] = " in line for line in active(publish).splitlines()), 2)
        self.assertGreater(publish.rindex('fixture.registration_publication_tick(summary["removalData"], removal_last)'), publish.index('os.close(fd)'))
        self.assertNotIn('removal_data', gates)
        self.assertNotIn('integration_data', gates)
        self.assertNotIn('parent_data', gates)
        self.assertNotIn('changes_data', gates)
        self.assertNotIn('recovery_data', gates)
        self.assertIn('recovery_data = fixture.removal_recovery_data_result(result, source, rows)', route)
        self.assertIn('if outcome == "success" and REMOVAL_RECOVERY_SELECTED:', route)
        self.assertGreater(publish.rindex('fixture.registration_publication_tick(summary["removalRecoveryData"], recovery_last)'), publish.index('os.close(fd)'))
        self.assertIn('removalRecoveryData=recovery_data, removalRecoveryDataQualified=recovery_qualified, removalRecoveryDataDiagnostic=recovery_diagnostic,', publish)
        self.assertIn('removal_recovery_data_result(value, os.environ["GITHUB_SHA"], source.rows)', main)
        self.assertIn('changes_data = fixture.removal_changes_data_result(result, source, rows)', route)
        self.assertIn('if outcome == "success" and REMOVAL_CHANGES_SELECTED:', route)
        self.assertGreater(publish.rindex('fixture.registration_publication_tick(summary["removalChangesData"], changes_last)'), publish.index('os.close(fd)'))
        self.assertIn('removalChangesData=changes_data, removalChangesDataQualified=changes_qualified, removalChangesDataDiagnostic=changes_diagnostic,', publish)
        self.assertIn('removal_changes_data_result(value, os.environ["GITHUB_SHA"], source.rows)', main)
        self.assertIn('parent_data = fixture.removal_parent_data_result(result, source, rows)', route)
        self.assertIn('if outcome == "success" and REMOVAL_PARENT_SELECTED:', route)
        self.assertGreater(publish.rindex('fixture.registration_publication_tick(summary["removalParentData"], parent_last)'), publish.index('os.close(fd)'))
        self.assertIn('removalParentData=parent_data, removalParentDataQualified=parent_qualified, removalParentDataDiagnostic=parent_diagnostic,', publish)
        self.assertIn('removal_parent_data_result(value, os.environ["GITHUB_SHA"], source.rows)', main)
        self.assertIn('integration_data = fixture.removal_integration_data_result(result, source, rows)', route)
        self.assertIn('if outcome == "success" and REMOVAL_INTEGRATION_SELECTED:', route)
        self.assertGreater(publish.rindex('fixture.registration_publication_tick(summary["removalIntegrationData"], integration_last)'), publish.index('os.close(fd)'))
        self.assertIn('removalIntegrationData=integration_data, removalIntegrationDataQualified=integration_qualified, removalIntegrationDataDiagnostic=integration_diagnostic,', publish)
        self.assertIn('removal_integration_data_result(value, os.environ["GITHUB_SHA"], source.rows)', main)


        self.assertNotIn('fixture.service_cocoa_result(', route)
        self.assertIn('except BaseException:', route)
        self.assertNotIn('diagnostic_captured', gates)
        self.assertNotIn('cocoa_completed', gates)
        self.assertIn('passed = (not self.service_layout["selected"] and failure is None', self.owner)
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
            selected_roles = (fixture.CONTEXT_ROLES if CONTEXT_PRODUCT_SELECTED else
                              fixture.RECOVERY_ROLES if REMOVAL_RECOVERY_SELECTED else fixture.CHANGES_ROLES if REMOVAL_CHANGES_SELECTED else
                              fixture.PARENT_ROLES if REMOVAL_PARENT_SELECTED else
                              fixture.INTEGRATION_ROLES if REMOVAL_INTEGRATION_SELECTED else
                              fixture.REMOVAL_ROLES if REMOVAL_DATA_SELECTED else fixture.REGISTRATION_ROLES)
            layout_record = fixture.service_layout_data(result["serviceLayoutObservation"], source)
            fixture.need(layout_record["selected"] is False and layout_record["started"] is False
                         and all(call["role"] in selected_roles for call in calls)
                         and (CONTEXT_PRODUCT_SELECTED
                              or [call["role"] for call in calls] == list(selected_roles[:len(calls)])),
                         "summary-registration-route")
            if layout_record["observerSourceSha256"] is not None:
                fixture.need(layout_record["observerSourceSha256"] == rows[fixture.LAYOUT_SOURCE]["sha256"],
                             "summary-cocoa-source")
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
        self.assertIn('return context_product(body, *component, presentation=presentation)', audit)
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
        btm = section(publish, "              btm_log = None", "              # This committed workflow selects only the fixed public product Context.")
        self.assertEqual(flat(active(btm)), flat("""btm_log = None
            btm_record = fixture.btm_log_data(result["btmLogObservation"], source, calls)
            fixture.need(type(btm_record["schemaVersion"]) is int and btm_record["schemaVersion"] == 3
                         and btm_record["type"] == "mrk-e2-fixture-btm-log-observation-v3", "summary-btm-version")
            if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                    and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
                btm_log = btm_record"""))
        self.assertGreater(publish.index(btm), publish.index('"summary-owner-binding"'))
        self.assertGreater(publish.index(btm), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(btm), publish.index("              known_pass = ("))
        self.assertIn("installerContext contextReceiptDiagnostic serviceLayoutObservation btmLogObservation", publish)
        self.assertIn('"btmLogObservation": None,', publish)
        self.assertIn('btmLogObservation=btm_log,', publish)
        # Execute only this pure projection block, with an already-validated
        # record seam. The real parser/schema mutations run in the BTM group.
        # No publication imports, originals, files or native entry are executed.
        class ValidatedBTM:
            def btm_log_data(_self, value, source, calls):
                self.assertEqual(source, "a" * 40)
                self.assertIs(value, original_record)
                self.assertIs(calls, original_calls)
                validations.append(value)
                return value
            @staticmethod
            def need(value, label):
                if not value:
                    raise ValueError(label)
        projection = compile(ast.parse(textwrap.dedent(btm)), "<fixed-btm-projection>", "exec")
        original_record = {"schemaVersion": 3, "type": "mrk-e2-fixture-btm-log-observation-v3",
                           "ownEventDetails": [{"ordinal": 1, "messageSha256": "c" * 64,
                                                "pathMask": 1, "markerMask": 3, "codeMask": 0,
                                                "trace": {'characters': 269, 'knownTokens': 4, 'unknownRuns': 0, 'tokens': [[0, 42, 10], [43, 8, 13], [52, 5, 27], [59, 209, 0]]}}],
                           "ownEventDetailsOmitted": 0}
        for refused in (None, "sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown", "returned", "cleanup"):
            validations = []
            original_calls = [{"returned": refused != "returned"}]
            original = {"btmLogObservation": original_record, "cleanupErrors": ["close-unknown"] if refused == "cleanup" else [],
                        **{key: key != refused for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown")}}
            namespace = {"fixture": ValidatedBTM(), "result": original, "source": "a" * 40,
                         "calls": original_calls, "accepted": False}
            exec(projection, namespace)
            self.assertEqual(validations, [original_record])
            self.assertIs(namespace["btm_log"], original_record if refused is None else None)
            self.assertFalse(namespace["accepted"])
        for mutation in ({"schemaVersion": 1}, {"schemaVersion": 2}, {"schemaVersion": True},
                         {"type": "mrk-e2-fixture-btm-log-observation-v1"}, {"type": "mrk-e2-fixture-btm-log-observation-v2"}):
            good_record = original_record
            original_record = dict(good_record, **mutation)
            original_calls, validations = [{"returned": True}], []
            namespace = {"fixture": ValidatedBTM(), "source": "a" * 40, "calls": original_calls,
                         "result": {"btmLogObservation": original_record}, "accepted": False}
            with self.assertRaisesRegex(ValueError, "^summary-btm-version$"):
                exec(projection, namespace)
            self.assertIsNone(namespace["btm_log"])
            self.assertFalse(namespace["accepted"])
            original_record = good_record

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
        for refused in ('except BaseException: summary["accepted"] = False summary["registrationReservation"] = None summary["registrationReservationQualified"] = False summary["registrationFailure"] = None summary[\'removalData\'] = None summary[\'removalDataQualified\'] = False summary[\'removalDataDiagnostic\'] = None summary[\'removalIntegrationData\'] = None summary[\'removalIntegrationDataQualified\'] = False summary[\'removalIntegrationDataDiagnostic\'] = None summary[\'removalParentData\'] = None summary[\'removalParentDataQualified\'] = False summary[\'removalParentDataDiagnostic\'] = None summary[\'removalChangesData\'] = None summary[\'removalChangesDataQualified\'] = False summary[\'removalChangesDataDiagnostic\'] = None summary[\'removalRecoveryData\'] = None summary[\'removalRecoveryDataQualified\'] = False summary[\'removalRecoveryDataDiagnostic\'] = None summary["nativeRustTests"] = None summary["installerWorkerRustTests"] = None summary["installedReaderRustTests"] = None summary["producerSigningRustTests"] = None summary["packageProducerRustTests"] = None summary["installerContext"] = None',
                        'if not book.finish(): summary["accepted"] = False summary["registrationReservation"] = None summary["registrationReservationQualified"] = False summary["registrationFailure"] = None summary[\'removalData\'] = None summary[\'removalDataQualified\'] = False summary[\'removalDataDiagnostic\'] = None summary[\'removalIntegrationData\'] = None summary[\'removalIntegrationDataQualified\'] = False summary[\'removalIntegrationDataDiagnostic\'] = None summary[\'removalParentData\'] = None summary[\'removalParentDataQualified\'] = False summary[\'removalParentDataDiagnostic\'] = None summary[\'removalChangesData\'] = None summary[\'removalChangesDataQualified\'] = False summary[\'removalChangesDataDiagnostic\'] = None summary[\'removalRecoveryData\'] = None summary[\'removalRecoveryDataQualified\'] = False summary[\'removalRecoveryDataDiagnostic\'] = None summary["nativeRustTests"] = None summary["installerWorkerRustTests"] = None summary["installedReaderRustTests"] = None summary["producerSigningRustTests"] = None summary["packageProducerRustTests"] = None summary["installerContext"] = None'):
            self.assertIn(refused, flat(publish))
        self.assertGreater(publish.index(units), publish.index('"summary-returned-call"'))
        self.assertLess(publish.index(units), publish.index("              known_pass = ("))
        self.assertIn('receiptOriginals native nativeRustTests', active(publish))
        self.assertIn('"nativeRustTests": None,', publish)
        self.assertIn('nativeRustTests=native_rust_tests,', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
                          if 'summary["nativeRustTests"] =' in line], ['summary["nativeRustTests"] = None'] * 2)
        for refused in ('except BaseException: summary["accepted"] = False summary["registrationReservation"] = None summary["registrationReservationQualified"] = False summary["registrationFailure"] = None summary[\'removalData\'] = None summary[\'removalDataQualified\'] = False summary[\'removalDataDiagnostic\'] = None summary[\'removalIntegrationData\'] = None summary[\'removalIntegrationDataQualified\'] = False summary[\'removalIntegrationDataDiagnostic\'] = None summary[\'removalParentData\'] = None summary[\'removalParentDataQualified\'] = False summary[\'removalParentDataDiagnostic\'] = None summary[\'removalChangesData\'] = None summary[\'removalChangesDataQualified\'] = False summary[\'removalChangesDataDiagnostic\'] = None summary[\'removalRecoveryData\'] = None summary[\'removalRecoveryDataQualified\'] = False summary[\'removalRecoveryDataDiagnostic\'] = None summary["nativeRustTests"] = None',
                        'if not book.finish(): summary["accepted"] = False summary["registrationReservation"] = None summary["registrationReservationQualified"] = False summary["registrationFailure"] = None summary[\'removalData\'] = None summary[\'removalDataQualified\'] = False summary[\'removalDataDiagnostic\'] = None summary[\'removalIntegrationData\'] = None summary[\'removalIntegrationDataQualified\'] = False summary[\'removalIntegrationDataDiagnostic\'] = None summary[\'removalParentData\'] = None summary[\'removalParentDataQualified\'] = False summary[\'removalParentDataDiagnostic\'] = None summary[\'removalChangesData\'] = None summary[\'removalChangesDataQualified\'] = False summary[\'removalChangesDataDiagnostic\'] = None summary[\'removalRecoveryData\'] = None summary[\'removalRecoveryDataQualified\'] = False summary[\'removalRecoveryDataDiagnostic\'] = None summary["nativeRustTests"] = None'):
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
        for suffix in ("bound", "framing", "record", "result", "roster"):
            reason = "removal-record-rust-test-" + suffix
            observed = report("removal-record-rust-tests", reason,
                              [dict(successful, role="removal-record-rust-tests")])
            self.assertEqual(observed, {"diagnosticOnly": True, "phase": "removal-record-rust-tests", "failure": reason,
                "lastOriginalCall": {"role": "removal-record-rust-tests", "returned": True, "returncode": 0}})
        for code, reason in ((78, "cocoa-graphic-session-unavailable"), (79, "cocoa-security-session-query-failed")):
            observed = report("service-cocoa-startup", reason,
                              [dict(call, role="service-cocoa-startup", returncode=code)])
            self.assertEqual(observed, {"diagnosticOnly": True, "phase": "service-cocoa-startup", "failure": reason,
                                       "lastOriginalCall": {"role": "service-cocoa-startup", "returned": True, "returncode": code}})
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
            self.assertEqual(sorted(prefixes), ["installed-reader-rust-test", "installer-worker-rust-test", "installer-worker-rust-test", "installer-worker-rust-test", "native-rust-test", "package-producer-rust-test", "producer-signing-rust-test", "registration-app-rust-test", "registration-rust-test", "removal-app-rust-test", "removal-app-rust-test", "removal-changes-rust-test", "removal-native-rust-test", "removal-native-rust-test", "removal-record-rust-test", "removal-recovery-rust-test"])
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
            "CONTEXT_COMPLETED: ${{ steps.publication.outputs.context_observation_completed }}",
            "PRODUCT_ARGUMENT_OBSERVED: ${{ steps.publication.outputs.installer_product_argument_observed }}",
            "REGISTRATION_QUALIFIED: ${{ steps.publication.outputs.registration_qualified }}",
            "REMOVAL_DATA_QUALIFIED: ${{ steps.publication.outputs.removal_data_qualified }}",
            "REMOVAL_INTEGRATION_DATA_QUALIFIED: ${{ steps.publication.outputs.removal_integration_data_qualified }}",
            "REMOVAL_PARENT_DATA_QUALIFIED: ${{ steps.publication.outputs.removal_parent_data_qualified }}",
            "REMOVAL_CHANGES_DATA_QUALIFIED: ${{ steps.publication.outputs.removal_changes_data_qualified }}",
            "REMOVAL_RECOVERY_DATA_QUALIFIED: ${{ steps.publication.outputs.removal_recovery_data_qualified }}",
            "PREPARATION_OUTCOME: ${{ steps.prepare.outcome }}",
            "NATIVE_OUTCOME: ${{ steps.native.outcome }}",
            "PUBLICATION_OUTCOME: ${{ steps.publication.outcome }}",
            'set -euo pipefail',
            '[[ "$PREPARATION_OUTCOME" == success && "$NATIVE_OUTCOME" == success && "$PUBLICATION_OUTCOME" == success && "$CONTEXT_COMPLETED" == false && "$PRODUCT_ARGUMENT_OBSERVED" == false && "$REMOVAL_RECOVERY_DATA_QUALIFIED" == false && "$REMOVAL_CHANGES_DATA_QUALIFIED" == false && "$REMOVAL_PARENT_DATA_QUALIFIED" == true && "$REMOVAL_INTEGRATION_DATA_QUALIFIED" == false && "$REMOVAL_DATA_QUALIFIED" == false && "$REGISTRATION_QUALIFIED" == false && "$ACCEPTED" == false ]]',
        ):
            with self.subTest(finality=required):
                self.assertIn(required, active(final))

        self.assertIn('"installerProductArgumentObserved": False,', publish)
        self.assertIn('installerProductArgumentObserved=bool(product_argument_observed),', publish)
        self.assertEqual([line.strip() for line in active(publish).splitlines()
            if 'summary["installerProductArgumentObserved"] =' in line],
            ['summary["installerProductArgumentObserved"] = False'] * 2)
        self.assertIn('b"installer_product_argument_observed=true\\n" if summary["installerProductArgumentObserved"] else b"installer_product_argument_observed=false\\n"', publish)
        self.assertEqual(publish.count('fixture.context_publication_tick('), 4)
        self.assertGreater(publish.rindex('fixture.context_publication_tick('), publish.index('os.close(fd)'))
        self.assertLess(publish.index('"summary-context-presentation-source"'), publish.index('_entry, result_body ='))
        self.assertNotIn('installerProductArgumentObserved', gates)
        promotion = textwrap.dedent(section(publish,
            '              context_completed = installer_context is not None and installer_context["completed"]',
            '              known_pass = ('))
        # Only the existing pure route block, not imports/files/publication or
        # native. Actual full owner-result mutation tests live in ContextTests.
        observed = {"completed": True, "deadlineNs": "200000000000"}
        class ValidatedContext:
            CONTEXT_SECONDS = 120
            decimal = staticmethod(int)
            def context_observation_result(_self, report, source):
                self.assertIs(report, marker); self.assertEqual(source, "a" * 40)
                calls.append("observation")
                return observed
            def context_publication_tick(_self, value, previous):
                self.assertIs(value, observed); self.assertEqual(previous, 80_000_000_000)
                calls.append("clock")
                if failure: raise ValueError("same-original clock refused")
                return 150_000_000_000
            def context_product_argument_observed(_self, report, source):
                self.assertIs(report, marker); calls.append("argument")
                return argument
        marker = object()
        for outcome, argument, failure in (("success", True, False), ("success", False, False),
                                           ("success", True, True), ("failure", True, False)):
            calls = []
            ns = {"installer_context": observed, "CONTEXT_PRODUCT_SELECTED": True,
                  "outcome": outcome, "fixture": ValidatedContext(), "result": marker, "source": "a" * 40}
            exec(compile(promotion, "<fixed-context-publication-route>", "exec"), ns)
            self.assertEqual(ns["context_completed"], outcome == "success" and not failure)
            self.assertEqual(ns["product_argument_observed"], outcome == "success" and argument and not failure)
            self.assertEqual(calls, [] if outcome != "success" else ["observation", "clock"] if failure
                             else ["observation", "clock", "argument"])


if __name__ == "__main__":
    unittest.main()
