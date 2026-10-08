set -euo pipefail
umask 077
ulimit -n 1024
cd /Users/runner/work/mobile-release-kit/mobile-release-kit
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/Users/runner LANG=C LC_ALL=C TZ=UTC \
  MRK_MACOS_WORK="$MRK_MACOS_WORK" MRK_NATIVE_STEP_OUTCOME="$MRK_NATIVE_STEP_OUTCOME" \
  GITHUB_SHA="$GITHUB_SHA" GITHUB_WORKFLOW_SHA="$GITHUB_WORKFLOW_SHA" \
  GITHUB_RUN_ID="$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" GITHUB_OUTPUT="$GITHUB_OUTPUT" \
  "$MRK_PYTHON" -I -S -B - <<'PY_PUBLISH'
import hashlib, importlib.util, json, os, re, stat, sys
from pathlib import Path

CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
work = Path(os.environ["MRK_MACOS_WORK"])
source = os.environ["GITHUB_SHA"]
outcome = os.environ["MRK_NATIVE_STEP_OUTCOME"]
if (Path.cwd() != CHECKOUT or work.parent != WORK_PARENT
        or re.fullmatch(r"mrk-macos-maintenance-fixture\.[A-Za-z0-9]{8}", work.name) is None
        or re.fullmatch(r"[0-9a-f]{40}", source) is None or source == "0" * 40
        or os.environ["GITHUB_WORKFLOW_SHA"] != source
        or outcome not in ("success", "failure", "cancelled", "skipped")):
    raise SystemExit("E2 summary route refused.")
# Same reviewed DATA-only module, from the successfully prepared exact
# checkout. No owner.main(), process query, signal or native action.
module_path = CHECKOUT / "desktop/tools/macos_e2_native_fixture.py"
module_fd = None
bootstrap_ok = False
try:
    module_fd = os.open(module_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    before = os.fstat(module_fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in (0o444, 0o644) or not 0 < before.st_size <= 1048576):
        raise ValueError("summary-bootstrap-source")
    module_bytes, offset = bytearray(), 0
    while offset < before.st_size:
        part = os.pread(module_fd, min(65536, before.st_size - offset), offset)
        if not part:
            raise ValueError("summary-bootstrap-short")
        module_bytes.extend(part)
        offset += len(part)
    if os.pread(module_fd, 1, offset) != b"":
        raise ValueError("summary-bootstrap-grew")
    attributes = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    expected = tuple(getattr(before, name) for name in attributes)
    held, named = os.fstat(module_fd), os.stat(module_path, follow_symlinks=False)
    if (tuple(getattr(held, name) for name in attributes) != expected
            or tuple(getattr(named, name) for name in attributes) != expected):
        raise ValueError("summary-bootstrap-original")
    spec = importlib.util.spec_from_file_location("_mrk_e2_publication_data", module_path)
    if spec is None or spec.loader is None:
        raise ValueError("summary-bootstrap-loader")
    fixture = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fixture
    spec.loader.exec_module(fixture)
    fixture.need(fixture.signature(os.fstat(module_fd)) == fixture.signature(before)
                 and fixture.signature(os.stat(module_path, follow_symlinks=False)) == fixture.signature(before),
                 "summary-bootstrap-changed")
    bootstrap_ok = True
except BaseException:
    bootstrap_ok = False
finally:
    if module_fd is not None:
        try:
            os.close(module_fd)
        except OSError:
            bootstrap_ok = False
if not bootstrap_ok:
    raise SystemExit("E2 summary DATA source admission refused.")
REMOVAL_DATA_SELECTED = False  # Historical two-graph4/10 DATA selection.
REMOVAL_INTEGRATION_SELECTED = False  # Historical fixed17 scope remains independently validated.
REMOVAL_PARENT_SELECTED = False  # Historical one-original Parent2 scope remains closed.
REMOVAL_CHANGES_SELECTED = False  # Historical changed11 scope remains independently validated.
REMOVAL_RECOVERY_SELECTED = True  # Two originals: Parent2/native4 comparison DATA only.
OWNER_DIAGNOSTIC_ROLES = (
    "removal-native-rust-tests", "removal-app-rust-tests",
    "removal-integration-native-rust-tests", "removal-integration-app-rust-tests", "removal-integration-parent-rust-tests", "removal-parent-rust-tests", "removal-changes-parent-rust-tests", "removal-changes-app-rust-tests", "removal-changes-native-rust-tests", "removal-changes-emitter-rust-tests", "removal-recovery-parent-rust-tests", "removal-recovery-native-rust-tests",
    "reservation-rust-tests", "registration-entry-build", "registration-fixture-build", "registration-fixture-run",
    'fixture-btm-log',
    'service-layout-build', 'service-layout-single', 'service-layout-nested',
    'service-cocoa-startup',
    'sign-5', 'sign-6', 'sign-7', 'sign-8', 'sign-9',
    'verify-sign-5', 'verify-sign-6', 'verify-sign-7', 'verify-sign-8', 'verify-sign-9',
    'installed-signature-5', 'installed-signature-6', 'installed-signature-7',
    'installed-signature-8', 'installed-signature-9',
    'context-helper-build', 'context-component-build', 'context-product-component-build',
    'context-product-build', 'context-component-empty-bom', 'context-product-empty-bom',
    'context-component-receipt-census', 'context-product-receipt-census', 'context-component-installer',
    'context-product-installer', 'context-component-receipt-query', 'context-product-receipt-query',
    'context-component-receipt-diagnostic-query', 'context-component-receipt-diagnostic-census',
    "metadata-observer-build", "metadata-initial", "initial-receipt-query", "native-rust-tests", "installer-worker-rust-tests", "installed-reader-rust-tests", "producer-signing-rust-tests", "package-producer-rust-tests", "client-build",
    "resident-build", "entry-build", "client-facade-build", "resident-facade-build", "sign-0",
    "sign-1", "sign-2", "sign-3", "sign-4", "verify-sign-0", "verify-sign-1", "verify-sign-2",
    "verify-sign-3", "verify-sign-4", "package-analyze", "package-build", "metadata-before-install",
    "before-install-receipt-query", "standard-installer", "metadata-installed", "installed-receipt",
    "installed-signature-0", "installed-signature-1", "installed-signature-2",
    "installed-signature-3", "installed-signature-4", "native-run", "metadata-after-native",
    "context-component-receipt-post-census",
    "context-product-receipt-post-census",
)

OWNER_DIAGNOSTIC_PHASES = (
    "removal-native-rust-tests", "removal-app-rust-tests",
    "removal-integration-native-rust-tests", "removal-integration-app-rust-tests", "removal-integration-parent-rust-tests", "removal-parent-rust-tests", "removal-changes-parent-rust-tests", "removal-changes-app-rust-tests", "removal-changes-native-rust-tests", "removal-changes-emitter-rust-tests", "removal-recovery-parent-rust-tests", "removal-recovery-native-rust-tests",
    "reservation-rust-tests", "registration-entry-build", "registration-fixture-build", "registration-fixture-run",
    'fixture-btm-log',
    'service-layout-build', 'service-layout-single', 'service-layout-nested',
    'service-cocoa-startup',
    'sign-5', 'sign-6', 'sign-7', 'sign-8', 'sign-9',
    'verify-sign-5', 'verify-sign-6', 'verify-sign-7', 'verify-sign-8', 'verify-sign-9',
    'installed-signature-5', 'installed-signature-6', 'installed-signature-7',
    'installed-signature-8', 'installed-signature-9',
    'context-lsbom-original', 'context-productbuild-original',
    'context-helper-build', 'context-component-build', 'context-product-component-build',
    'context-product-build', 'context-component-empty-bom', 'context-product-empty-bom',
    'context-component-receipt-census', 'context-product-receipt-census', 'context-component-installer',
    'context-product-installer', 'context-component-receipt-query', 'context-product-receipt-query',
    'context-component-receipt-diagnostic-query', 'context-component-receipt-diagnostic-census',
    'context-prepare', 'context-component-audit', 'context-product-audit',
    'context-component-record', 'context-product-record',
    "prepare", "bundle-staging", "package-components", "metadata-observer-build", "metadata-initial",
    "initial-receipt-query", "native-rust-tests", "installer-worker-rust-tests", "installed-reader-rust-tests", "producer-signing-rust-tests", "package-producer-rust-tests", "client-build", "resident-build", "entry-build", "client-facade-build",
    "resident-facade-build", "sign-0", "sign-1", "sign-2", "sign-3", "sign-4", "verify-sign-0",
    "verify-sign-1", "verify-sign-2", "verify-sign-3", "verify-sign-4", "package-analyze",
    "package-build", "metadata-before-install", "before-install-receipt-query", "standard-installer",
    "metadata-installed", "installed-receipt", "installed-signature-0", "installed-signature-1",
    "installed-signature-2", "installed-signature-3", "installed-signature-4", "native-run",
    "metadata-after-native",
    "context-component-receipt-post-census",
    "context-product-receipt-post-census",
)

OWNER_DIAGNOSTIC_REFUSALS = (
    'removal-app-rust-test-bound',
    'removal-app-rust-test-framing',
    'removal-app-rust-test-record',
    'removal-app-rust-test-result',
    'removal-app-rust-test-roster',
    'removal-artifacts',
    'removal-call-finality',
    'removal-call-roster',
    'removal-changes-role',
    'removal-changes-rust-test-bound',
    'removal-changes-rust-test-framing',
    'removal-changes-rust-test-record',
    'removal-changes-rust-test-result',
    'removal-changes-rust-test-roster',
    'removal-recovery-role',
    'removal-recovery-rust-test-bound',
    'removal-recovery-rust-test-framing',
    'removal-recovery-rust-test-record',
    'removal-recovery-rust-test-result',
    'removal-recovery-rust-test-roster',
    'removal-native-rust-test-bound',
    'removal-native-rust-test-framing',
    'removal-native-rust-test-record',
    'removal-native-rust-test-result',
    'removal-native-rust-test-roster',
    'removal-owner-finality',
    'removal-owner-result',
    'removal-owner-scope',
    'removal-record',
    'removal-source-binding',

    'registration-app-rust-test-record',
    'registration-app-rust-test-bound',
    'registration-app-rust-test-framing',
    'registration-app-rust-test-roster',
    'registration-app-rust-test-result',
    'registration-failure-frame',
    'registration-failure-shape',
    'registration-failure-facts',
    'registration-failure-originals',
    'registration-artifacts',
    'registration-call-finality',
    'registration-call-roster',
    'registration-clock-record',
    'registration-clock-shape',
    'registration-compiled',
    'registration-fixture-fact',
    'registration-fixture-facts',
    'registration-fixture-frame',
    'registration-fixture-shape',
    'registration-fixture-type',
    'registration-image-post',
    'registration-native-stderr',
    'registration-native-streams',
    'registration-owner-finality',
    'registration-owner-result',
    'registration-owner-scope',
    'registration-phase-clock',
    'registration-phase-deadline',
    'registration-phase-origin',
    'registration-publication-clock',
    'registration-record',
    'registration-rust-test-bound',
    'registration-rust-test-framing',
    'registration-rust-test-record',
    'registration-rust-test-result',
    'registration-rust-test-roster',
    'registration-source-binding',
    'cocoa-admission-prerequisites',
    'cocoa-code-selector',
    'cocoa-completion-call-binding',
    'cocoa-completion-no-context',
    'cocoa-completion-only-route',
    'cocoa-completion-originals',
    'cocoa-completion-owner',
    'cocoa-completion-required',
    'cocoa-empty-cwd',
    'cocoa-files-selector',
    'cocoa-graphic-session-unavailable',
    'cocoa-image-selector',
    'cocoa-original-call-entry',
    'cocoa-original-clock-correspondence',
    'cocoa-original-result',
    'cocoa-output-correspondence',
    'cocoa-phase-clock',
    'cocoa-public-binding',
    'cocoa-public-case',
    'cocoa-public-completion',
    'cocoa-public-order',
    'cocoa-public-shape',
    'cocoa-public-started',
    'cocoa-public-unentered',
    'cocoa-record-binding',
    'cocoa-record-deadline',
    'cocoa-record-finality',
    'cocoa-record-observation',
    'cocoa-record-observations',
    'cocoa-record-sequence',
    'cocoa-record-shape',
    'cocoa-security-session-query-failed',
    "context-receipt-diagnostic-bound",
    "context-receipt-diagnostic-calls",
    "context-receipt-diagnostic-census",
    "context-receipt-diagnostic-command",
    "context-receipt-diagnostic-finality",
    "context-receipt-diagnostic-observer",
    "context-receipt-diagnostic-original",
    "context-receipt-diagnostic-packages",
    "context-receipt-diagnostic-query",
    "context-receipt-diagnostic-route",
    "context-receipt-diagnostic-shape",
    "context-receipt-diagnostic-slot-changed",
    "context-receipt-diagnostic-slots",
    "context-receipt-diagnostic-trigger",
    "mac8-group-clock",
    "mac8-group-deadline",
    "installed-reader-rust-test-record",
    "installed-reader-rust-test-bound",
    "installed-reader-rust-test-framing",
    "installed-reader-rust-test-roster",
    "installed-reader-rust-test-result",
    "producer-signing-rust-test-record",
    "producer-signing-rust-test-bound",
    "producer-signing-rust-test-framing",
    "producer-signing-rust-test-roster",
    "producer-signing-rust-test-result",
    "package-producer-rust-test-record",
    "package-producer-rust-test-bound",
    "package-producer-rust-test-framing",
    "package-producer-rust-test-roster",
    "package-producer-rust-test-result",
    "installer-worker-rust-test-record", "installer-worker-rust-test-bound",
    "installer-worker-rust-test-framing", "installer-worker-rust-test-roster",
    "installer-worker-rust-test-result",
    'btm-log-window', 'btm-log-data', 'btm-log-original', 'btm-log-tool',
    'layout-original-result', 'layout-record-shape', 'layout-record-binding',
    'layout-record-finality', 'layout-record-deadline', 'layout-public-shape',
    'layout-public-binding', 'layout-public-order', 'layout-public-unselected',
    'layout-public-unentered', 'layout-public-started', 'layout-public-case',
    'layout-public-sequence', 'layout-public-completion', 'layout-paired-inputs',
    'layout-image-flags', 'layout-image-command', 'layout-image-load-offset',
    'layout-image-load-padding', 'layout-image-segment', 'layout-image-sections',
    'layout-image-initializer', 'layout-image-main', 'layout-image-system-closure',
    'layout-package-selector', 'layout-operation-selector', 'layout-build-route',
    'layout-compiler-source-changed', 'layout-plist-original', 'layout-package-components',
    'layout-installed-originals', 'layout-installed-bytes', 'layout-admission-prerequisites',
    'layout-phase-clock', 'layout-empty-cwd', 'layout-output-correspondence',
    'layout-original-clock-correspondence', 'layout-original-call-entry',
    'context-original-call-entry',
    'context-command-role', 'context-component-roster', 'context-compressed-bound',
    'context-deadline', 'context-distribution-changed', 'context-empty-output',
    'context-distribution-observation',
    'context-helper-source-changed', 'context-nonempty-bom', 'context-observation-shape',
    'context-output-bound', 'context-output-close-unknown', 'context-output-not-empty-original',
    'context-output-original', 'context-output-readback', 'context-package-empty-action',
    'context-package-hook', 'context-package-identifier', 'context-package-identity',
    'context-package-no-payload', 'context-package-original', 'context-packages-changed',
    'context-product-component', 'context-product-distribution', 'context-product-roster',
    'context-public-binding', 'context-public-case', 'context-public-completion',
    'context-public-observation', 'context-public-order', 'context-public-receipts',
    'context-public-started', 'context-public-unentered', 'context-receipt-binding',
    'context-receipt-collision', 'context-receipt-owner',
    'context-receipt-query', 'context-record-binding', 'context-script-arguments',
    'context-scripts-changed', 'context-scripts-correspondence', 'context-scripts-original',
    'context-single-entry', 'context-unopened-facts', 'context-xar-bound',
    'context-xar-checksum', 'context-xar-count', 'context-xar-data',
    'context-xar-directory', 'context-xar-encoding', 'context-xar-expanded',
    'context-xar-file', 'context-xar-header', 'context-xar-member-bound',
    'context-xar-member-checksum', 'context-xar-member-duplicate', 'context-xar-member-id',
    'context-xar-member-metadata', 'context-xar-member-name', 'context-xar-member-required',
    'context-xar-member-size', 'context-xar-member-tags',
    'context-xar-member-tags-acl',
    'context-xar-member-tags-flags',
    'context-xar-member-tags-ea',
    'context-xar-member-tags-device',
    'context-xar-member-tags-link',
    'context-xar-range', 'context-xar-roster', 'context-xar-toc',
    'context-xar-unaccounted', 'context-xml-bound', 'context-xml-shape',
    "aggregate-auxiliary-budget", "ambient-cargo-configuration", "cargo-artifact-shape",
    "cargo-bound", "cargo-finish", "cargo-finished", "cargo-lines", "cargo-order",
    "compiler-alias-original", "compiler-alias-roster", "compiler-copy-changed",
    "compiler-one-alias", "detached-checkout", "directory-owner-mode", "directory-spelling",
    "duplicate-json-key", "effective-cargo-clock-version", "effective-rust-binding",
    "effective-rust-clock-version", "effective-rust-tool", "empty-fixture-entitlements",
    "facade-copy-changed", "file-original-policy", "fixture-administrative-domain",
    "fixture-cargo-binding", "fixture-cargo-target", "fixture-cpio-bound", "fixture-cpio-complete",
    "fixture-cpio-count", "fixture-cpio-data-bound", "fixture-cpio-directory",
    "fixture-cpio-entry-bound", "fixture-cpio-file-correspondence", "fixture-cpio-format",
    "fixture-cpio-name", "fixture-cpio-root", "fixture-cpio-roster-owner",
    "fixture-cpio-special-entry", "fixture-directory-policy", "fixture-exact-roster",
    "fixture-flat-package", "fixture-gate-bytes", "fixture-image-bound", "fixture-image-command",
    "fixture-image-command-span", "fixture-image-platform-minimum", "fixture-image-role-identity",
    "fixture-image-system-closure", "fixture-image-header", "fixture-image-library",
    "fixture-image-library-offset", "fixture-image-library-padding",
    "fixture-image-library-termination", "fixture-image-loader-command", "fixture-image-sections",
    "fixture-image-segment", "fixture-image-version", "fixture-newc-header", "fixture-odc-header",
    "fixture-package-bound", "fixture-package-bundle-reference", "fixture-package-bundle-route",
    "fixture-package-inflate", "fixture-package-info", "fixture-package-info-xml",
    "fixture-package-relocation", "fixture-receipt-collision", "fixture-receipt-query-inconclusive",
    "fixture-release-profile", "fixture-root-collision", "fixture-system-dependency",
    "fixture-total-bytes", "fixture-xar-encoding", "fixture-xar-header", "fixture-xar-member-bound",
    "fixture-xar-member-range", "fixture-xar-roster", "fixture-xar-size", "fixture-xar-toc",
    "fixture-xar-xml", "fresh-case-incarnation", "fresh-sealing-original", "genuine-no-f-tail",
    "genuine-unregister-contract", "hosted-source-route", "image-release-size", "installed-group",
    "installed-originals-changed", "installed-payload-correspondence", "installed-receipt-binding",
    "installed-receipt-owner", "installed-receipt-query", "json-byte-bound", "json-constant",
    "json-shape", "json-shape-bound", "local-f-admission-contract", "metadata-absent-fixture",
    "metadata-fixture-collision", "metadata-full9", "metadata-observer-original",
    "metadata-original-correspondence", "metadata-original-policy", "metadata-original-result",
    "metadata-required-directory-absent", "metadata-result-binding", "metadata-row-shape",
    "metadata-same-original-policy", "missing-b-refusal-contract", "native-admission-prerequisites",
    "native-aggregate-outcome", "native-case-count", "native-case-identities", "native-case-order",
    "native-case-shape", "native-empty-cwd", "native-entry-route", "native-filesystem-postcondition",
    "native-platform-account", "native-resource-finality", "native-resource-states",
    "native-result-binding", "native-result-scope", "native-return-finality", "native-role-features",
    "native-rust-test-bound", "native-rust-test-framing", "native-rust-test-record",
    "native-rust-test-result", "native-rust-test-roster",
    "observer-source-changed", "observer-source-original", "one-fixture-image",
    "one-native-result-line", "one-native-role-library", "original-changed",
    "original-command-failed", "original-grew", "original-handle-bound",
    "original-operation-refused-or-unknown", "original-owner-return", "original-short-read",
    "original-unbound", "output-bound", "output-close-unknown", "output-readback",
    "output-short-write", "owner-result-bound", "owner-result-original-close", "owner-summary-write",
    "package-component-children", "package-component-path", "package-component-root",
    "package-component-shape", "package-components", "package-inputs-changed",
    "package-original-changed", "passed-native-originals", "prepared-tool-home-route",
    "private-original-work", "protected-write-forbidden", "required-source-roster",
    "result-expected-binding", "run-shape", "scratch-directory-original-after-mode",
    "scratch-directory-original-before-mode", "scratch-directory-requested-mode",
    "scratch-original-before-retirement", "scratch-retirement-incomplete", "sealing-close-unknown",
    "separate-fixture-image-graph", "source-bytes", "source-executable-mode",
    "source-inventory-binding", "source-inventory-row", "source-module-already-loaded",
    "source-module-loader", "source-original-descriptor-capacity", "source-original-roster-bound",
    "source-run-binding", "source-shape", "tail-binding", "tail-finality-contract", "tail-header",
    "tail-shape", "target-original-before-retirement", "target-original-closes",
    "target-owner-finality", "target-retirement-incomplete", "timestamp-canonical",
    "timestamp-range", "unexecuted-case-facts", "unlisted-source", "watch-without-registration",
    "work-route",
    "context-observation-calls",
    "context-observation-finality",
    "context-public-calls",
    "context-receipt-census-listed",
    "context-receipt-mixed-slots",
    "context-receipt-observation-route",
    "context-receipt-packages",
    "context-receipt-slots-changed",
    "context-receipt-variant",
)

def native_owner_failure_data(phase, failure, calls):
    """Closed diagnostic DATA; never a successful wait or acceptance receipt."""
    safe_phase = phase if type(phase) is str and phase in OWNER_DIAGNOSTIC_PHASES else "unknown"
    safe_failure = (None if failure is None else failure
                    if type(failure) is str and failure in OWNER_DIAGNOSTIC_REFUSALS else "unknown")
    last = None
    if type(calls) is list and 0 < len(calls) <= 64:
        row = calls[-1]
        if (type(row) is dict and row.get("entered") is True
                and type(row.get("role")) is str and type(row.get("returned")) is bool):
            role = row["role"] if row["role"] in OWNER_DIAGNOSTIC_ROLES else "unknown"
            returned, code = row["returned"], row.get("returncode")
            if not returned:
                last = {"role": role, "returned": False, "returncode": None}
            elif type(code) is int and 0 <= code <= 255:
                last = {"role": role, "returned": True, "returncode": code}
    return {"diagnosticOnly": True, "phase": safe_phase, "failure": safe_failure,
            "lastOriginalCall": last}


module_hash = hashlib.sha256(module_bytes).hexdigest()
book = fixture.Originals()
summary = {
    "schemaVersion": 1, "type": "mrk-macos-e2-native-fixture-workflow-v1",
    "source": source, "workflowSource": source, "workflow": fixture.WORKFLOW,
    "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
    "platform": "macos-26-arm64", "toolchain": "1.98.1",
    "nativeStepOutcome": outcome, "ownerOriginalCallerSucceeded": outcome == "success",
    "ownerResultAdmitted": False, "ownerResultSha256": None, "tree": None,
    "bindingSha256": None, "sourceInventorySha256": None, "sourceReleaseId": None,
    "ownerOutcome": None, "originalCallCount": 0, "ownerFinality": None, "native": None,
    "ownerDiagnostic": None, "nativeRustTests": None, "installerWorkerRustTests": None,
    "installedReaderRustTests": None,
    "producerSigningRustTests": None,
    "packageProducerRustTests": None,
    "installerContext": None,
    "serviceLayoutObservation": None,
    "btmLogObservation": None, "installerWorkerDiagnostic": None,
    "contextMetadataDiagnostic": None,
    "contextPackageInfoDiagnostic": None,
    "contextDistributionDiagnostic": None,
    "contextReceiptDiagnostic": None, "diagnosticCaptured": False,
    "contextObservationCompleted": False,
    "registrationReservation": None, "registrationReservationQualified": False, "registrationFailure": None,
    "removalData": None, "removalDataQualified": False, "removalDataDiagnostic": None,
    "removalIntegrationData": None, "removalIntegrationDataQualified": False, "removalIntegrationDataDiagnostic": None,
    "removalParentData": None, "removalParentDataQualified": False, "removalParentDataDiagnostic": None,
    "removalChangesData": None, "removalChangesDataQualified": False, "removalChangesDataDiagnostic": None,
    "removalRecoveryData": None, "removalRecoveryDataQualified": False, "removalRecoveryDataDiagnostic": None,
    "failure": "owner-result-missing-or-refused", "accepted": False,
    "syntheticIdentity": True, "productionIdentityQualified": False,
    "actualAppIntegrationQualified": False, "distributionQualified": False,
    "overlapQualified": False, "protectedRootRetired": False, "exactReceiptRetired": False,
    "rawOutputIncluded": False, "environmentValuesIncluded": False,
}
try:
    work_entry = book.directory(work)
    work_info = os.fstat(work_entry["fd"])
    fixture.need(work_info.st_uid == os.getuid() and stat.S_IMODE(work_info.st_mode) == 0o700,
                 "summary-work-original")
    _entry, binding_body = book.file(work / "source-binding.json", 65536, modes=(0o600,))
    _entry, inventory_body = book.file(work / "source-inventory.json", 2097152, modes=(0o600,))
    _entry, rust_body = book.file(work / "effective-rust-toolchain.json", 16384, modes=(0o600,))
    binding = fixture.decode(binding_body, 65536)
    inventory = fixture.decode(inventory_body, 2097152)
    rust = fixture.decode(rust_body, 16384)
    rows = fixture.binding_data(os.environ, binding, inventory, rust, fixture.signature(work_info))
    fixture.fixture_domain(binding)
    fixture.need(rows["desktop/tools/macos_e2_native_fixture.py"]["sha256"] == module_hash,
                 "summary-bootstrap-inventory")
    for relative in ("desktop/tools/macos_e2_native_fixture.py",
                     ".github/workflows/desktop-macos-maintenance-fixture.yml",
                     "desktop/tools/macos_maintenance_fixture_prepare.sh",
                     "desktop/tools/macos_maintenance_fixture_publish.sh",
                     "desktop/macos-installed-inputs/build-release.json", fixture.CONTEXT_SOURCE,
                     fixture.LAYOUT_SOURCE):
        row = rows[relative]
        _entry, content = book.file(CHECKOUT / relative, 1048576, modes=(0o444, 0o644))
        fixture.need(len(content) == row["size"] and fixture.digest(content) == row["sha256"]
                     and hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest() == row["blob"],
                     "summary-source-correspondence")
        if relative.endswith("/build-release.json"):
            release_data = fixture.decode(content, 65536)
            release = release_data["release"]
            fixture.need(type(release) is str and re.fullmatch(r"[a-z0-9_.-]{1,63}", release),
                         "summary-release-source")
    _entry, result_body = book.file(work / "e2-native-result.json", 65536, modes=(0o600,))
    result = fixture.decode(result_body, 65536)
    expected_keys = set("""schemaVersion type source tree workflowSource workflow runId runAttempt platform toolchain
        sourceInventorySha256 sourceOriginalHandleCount sourceOriginalHandleReserve bindingSha256 sourceReleaseId
        outcome failure phase originalCalls workTimeoutSeconds hardTimeoutSeconds auxiliaryBudgetNanoseconds
        artifacts protectedMetadataObservations package installedArtifactRoster receiptOriginals native nativeRustTests installerWorkerRustTests installedReaderRustTests producerSigningRustTests packageProducerRustTests installerContext contextReceiptDiagnostic serviceLayoutObservation btmLogObservation
        installerEntered installationReturnedSuccess nativeEntered nativeOwnerReturned sourceClosesKnown
        protectedClosesKnown outputClosesKnown cleanupErrors scratchRetired protectedRootRetired exactReceiptRetired
        protectedRetentionRequired administrativeDomain arbitraryConcurrentPrivilegedWriterResistance flatPayloadAtomicNoReplace
        syntheticIdentity productionIdentityQualified actualAppIntegrationQualified distributionQualified
        rawOutputIncluded environmentValuesIncluded outerReceiptWriteCloseAndOriginalCallerExitRequired passed""".split())
    fixture.need(type(result) is dict and set(result) == expected_keys
                 and type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
                 and result["type"] == "mrk-macos-e2-native-fixture-owner-v1"
                 and result["source"] == result["workflowSource"] == source
                 and result["tree"] == binding["tree"] and result["workflow"] == fixture.WORKFLOW
                 and result["runId"] == summary["runId"] and result["runAttempt"] == summary["runAttempt"]
                 and result["platform"] == "macos-26-arm64" and result["toolchain"] == "1.98.1"
                 and result["bindingSha256"] == fixture.digest(binding_body)
                 and result["sourceInventorySha256"] == fixture.digest(inventory_body),
                 "summary-owner-binding")
    fixture.need(type(result["passed"]) is bool and result["outcome"] in ("passed", "failed", "unavailable")
                 and (result["sourceReleaseId"] is None or result["sourceReleaseId"] == release)
                 and result["workTimeoutSeconds"] == 990 and result["hardTimeoutSeconds"] == 993
                 and result["auxiliaryBudgetNanoseconds"] == "60000000000"
                 and result["administrativeDomain"] == "reviewed-fresh-single-hosted-job-sole-fixture-writer"
                 and result["syntheticIdentity"] is True
                 and result["outerReceiptWriteCloseAndOriginalCallerExitRequired"] is True
                 and all(result[key] is False for key in (
                     "productionIdentityQualified", "actualAppIntegrationQualified", "distributionQualified",
                     "arbitraryConcurrentPrivilegedWriterResistance", "flatPayloadAtomicNoReplace",
                     "rawOutputIncluded", "environmentValuesIncluded", "exactReceiptRetired"))
                 and type(result["protectedRootRetired"]) is bool,
                 "summary-owner-scope")
    flags = ("installerEntered", "installationReturnedSuccess", "nativeEntered", "nativeOwnerReturned",
             "sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown", "scratchRetired", "protectedRetentionRequired")
    fixture.need(all(type(result[key]) is bool for key in flags)
                 and type(result["cleanupErrors"]) is list and len(result["cleanupErrors"]) <= 64
                 and all(type(label) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", label)
                         for label in result["cleanupErrors"])
                 and type(result["originalCalls"]) is list and 0 <= len(result["originalCalls"]) <= 64,
                 "summary-owner-finality-shape")
    calls = result["originalCalls"]
    for call in calls:
        fixture.need(type(call) is dict and type(call.get("role")) is str
                     and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", call["role"])
                     and call.get("entered") is True and type(call.get("returned")) is bool,
                     "summary-original-call")
        if call["returned"]:
            fixture.need(type(call.get("returncode")) is int and 0 <= call["returncode"] <= 255
                         and fixture.identity(call.get("stdoutSha256"), 64)
                         and fixture.identity(call.get("stderrSha256"), 64), "summary-returned-call")
    installer_context = None
    context_record = fixture.installer_context_data(result["installerContext"], source)
    if context_record["observerSourceSha256"] is not None:
        fixture.need(context_record["observerSourceSha256"] == rows[fixture.CONTEXT_SOURCE]["sha256"],
                     "summary-context-source")
    fixture.installer_context_calls(context_record, source, calls)
    if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
            and all(call["returned"] for call in calls)):
        # A closed observation (including absent context) is not B admission.
        # An unfinished/unknown phase can never qualify native acceptance.
        installer_context = context_record
    service_layout = None
    selected_roles = (fixture.RECOVERY_ROLES if REMOVAL_RECOVERY_SELECTED else fixture.CHANGES_ROLES if REMOVAL_CHANGES_SELECTED else
                      fixture.PARENT_ROLES if REMOVAL_PARENT_SELECTED else
                      fixture.INTEGRATION_ROLES if REMOVAL_INTEGRATION_SELECTED else
                      fixture.REMOVAL_ROLES if REMOVAL_DATA_SELECTED else fixture.REGISTRATION_ROLES)
    layout_record = fixture.service_layout_data(result["serviceLayoutObservation"], source)
    fixture.need(layout_record["selected"] is False and layout_record["started"] is False
                 and all(call["role"] in selected_roles for call in calls)
                 and [call["role"] for call in calls] == list(selected_roles[:len(calls)]),
                 "summary-registration-route")
    if layout_record["observerSourceSha256"] is not None:
        fixture.need(layout_record["observerSourceSha256"] == rows[fixture.LAYOUT_SOURCE]["sha256"],
                     "summary-cocoa-source")
    if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
            and all(call["returned"] for call in calls)):
        # Incomplete status DATA remains diagnostic only; no missing original is repaired.
        service_layout = layout_record
    native_rust_tests = None
    if result["nativeRustTests"] is not None:
        unit_calls = [call for call in calls if call["role"] == "native-rust-tests"]
        fixture.need(len(unit_calls) == 1 and unit_calls[0]["returned"]
                     and unit_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release,
                     "summary-native-rust-tests-call")
        unit_record = fixture.native_rust_tests_data(result["nativeRustTests"])
        if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                and all(call["returned"] for call in calls)):
            native_rust_tests = unit_record
    installer_worker_rust_tests = None
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
            # Actual Mac test-profile compilation, not a shipping-release build.
            installer_worker_rust_tests = worker_record
    installed_reader_rust_tests = None
    if result["installedReaderRustTests"] is not None:
        selected_calls = [call for call in calls if call["role"] == "installed-reader-rust-tests"]
        fixture.need(len(selected_calls) == 1 and selected_calls[0]["returned"]
                     and selected_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release
                     and type(selected_calls[0].get("workTimeoutSeconds")) is int
                     and 0 < selected_calls[0]["workTimeoutSeconds"] <= 480
                     and type(selected_calls[0].get("outputLimitBytes")) is int
                     and selected_calls[0]["outputLimitBytes"] == 4 * 1024 * 1024,
                     "summary-installed-reader-rust-tests-call")
        selected_record = fixture.installed_reader_rust_tests_data(result["installedReaderRustTests"])
        if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                and all(call["returned"] for call in calls)):
            installed_reader_rust_tests = selected_record
    producer_signing_rust_tests = None
    if result["producerSigningRustTests"] is not None:
        selected_calls = [call for call in calls if call["role"] == "producer-signing-rust-tests"]
        fixture.need(len(selected_calls) == 1 and selected_calls[0]["returned"]
                     and selected_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release
                     and type(selected_calls[0].get("workTimeoutSeconds")) is int
                     and 0 < selected_calls[0]["workTimeoutSeconds"] <= 480
                     and type(selected_calls[0].get("outputLimitBytes")) is int
                     and selected_calls[0]["outputLimitBytes"] == 4 * 1024 * 1024,
                     "summary-producer-signing-rust-tests-call")
        selected_record = fixture.producer_signing_rust_tests_data(result["producerSigningRustTests"])
        if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                and all(call["returned"] for call in calls)):
            producer_signing_rust_tests = selected_record
    package_producer_rust_tests = None
    if result["packageProducerRustTests"] is not None:
        selected_calls = [call for call in calls if call["role"] == "package-producer-rust-tests"]
        fixture.need(len(selected_calls) == 1 and selected_calls[0]["returned"]
                     and selected_calls[0]["returncode"] == 0 and result["sourceReleaseId"] == release
                     and type(selected_calls[0].get("workTimeoutSeconds")) is int
                     and 0 < selected_calls[0]["workTimeoutSeconds"] <= 480
                     and type(selected_calls[0].get("outputLimitBytes")) is int
                     and selected_calls[0]["outputLimitBytes"] == 4 * 1024 * 1024,
                     "summary-package-producer-rust-tests-call")
        selected_record = fixture.package_producer_rust_tests_data(result["packageProducerRustTests"])
        if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                and all(call["returned"] for call in calls)):
            package_producer_rust_tests = selected_record
    installer_worker_diagnostic = None
    diagnostic_calls = [call for call in calls if "installerWorkerDiagnostic" in call]
    if (len(diagnostic_calls) == 1 and len([call for call in calls
            if call["role"] == "installer-worker-rust-tests"]) == 1):
        candidate_diagnostic = fixture.installer_worker_diagnostic_data(
            diagnostic_calls[0]["installerWorkerDiagnostic"], diagnostic_calls[0], rows)
        if (candidate_diagnostic is not None
                and all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
                and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
            # Nonzero original only: this projection cannot establish any pass.
            installer_worker_diagnostic = candidate_diagnostic
    native = None
    if result["native"] is not None:
        native_calls = [call for call in calls if call["role"] == "native-run"]
        fixture.need(len(native_calls) == 1 and native_calls[0]["returned"]
                     and result["nativeOwnerReturned"] and result["nativeEntered"]
                     and result["sourceReleaseId"] == release, "summary-native-call")
        native = fixture.native_result(fixture.canonical(result["native"]),
                                        native_calls[0]["returncode"], source, release)
    context_metadata_diagnostic = None
    metadata_candidate = fixture.context_metadata_diagnostic_data(
        result["artifacts"].get(fixture.CONTEXT_METADATA_ARTIFACT) if type(result["artifacts"]) is dict else None,
        result["phase"], result["failure"], calls)
    if (metadata_candidate is not None
            and all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
            and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
        # Pure failure observations, never metadata acceptance or Context completion.
        context_metadata_diagnostic = metadata_candidate
    context_package_diagnostic = None
    package_candidate = fixture.context_package_info_diagnostic_data(
        result["artifacts"].get(fixture.CONTEXT_PACKAGE_INFO_ARTIFACT) if type(result["artifacts"]) is dict else None,
        result["phase"], result["failure"], calls)
    if (package_candidate is not None
            and all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
            and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
        # Failure observations only: no acceptance, package trust or Context completion.
        context_package_diagnostic = package_candidate
    context_distribution_diagnostic = None
    distribution_candidate = fixture.context_distribution_diagnostic_data(
        result["artifacts"].get(fixture.CONTEXT_DISTRIBUTION_ARTIFACT) if type(result["artifacts"]) is dict else None,
        result["phase"], result["failure"], calls)
    if (distribution_candidate is not None
            and all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
            and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
        # Same-original failure DATA; never product acceptance or Context completion.
        context_distribution_diagnostic = distribution_candidate
    btm_log = None
    btm_record = fixture.btm_log_data(result["btmLogObservation"], source, calls)
    fixture.need(type(btm_record["schemaVersion"]) is int and btm_record["schemaVersion"] == 3
                 and btm_record["type"] == "mrk-e2-fixture-btm-log-observation-v3", "summary-btm-version")
    if (all(result[key] for key in ("sourceClosesKnown", "protectedClosesKnown", "outputClosesKnown"))
            and all(call["returned"] for call in calls) and not result["cleanupErrors"]):
        # Exact own-event masks/hashes are mentions, not path lookups,
        # causal findings, native finality or service authority.
        btm_log = btm_record
    # This committed workflow selects only fixed registration primitive qualification.
    # Full E2/Cocoa/Context helper paths are unchanged but are not selected here.
    fixture.need(result["contextReceiptDiagnostic"] is None, "summary-context-receipt-route")
    context_receipt_diagnostic = None
    diagnostic_captured = False
    registration = None
    registration_last = None
    if outcome == "success" and not REMOVAL_DATA_SELECTED and not REMOVAL_INTEGRATION_SELECTED and not REMOVAL_PARENT_SELECTED and not REMOVAL_CHANGES_SELECTED and not REMOVAL_RECOVERY_SELECTED:
        try:
            registration = fixture.registration_reservation_result(result, source, rows)
            registration_last = fixture.registration_publication_tick(
                registration, fixture.decimal(registration["clock"]["lastNs"]))
        except BaseException:
            registration = None  # Original/source/clock failure never becomes positive.
    registration_qualified = registration is not None
    registration_failure = None
    if (len(calls) == 6 and calls[-1]["role"] == fixture.REGISTRATION_ROLES[-1]
            and calls[-1]["returned"] and calls[-1]["returncode"] != 0
            and all(call["returned"] for call in calls)
            and all(result[key] for key in ("sourceClosesKnown", "outputClosesKnown", "protectedClosesKnown"))):
        try:
            failed = result["artifacts"]["registration-reservation"]["nativeFailure"]
            registration_failure = fixture.registration_fixture_failure(
                fixture.canonical(failed), calls[-1]["returncode"], source)
        except BaseException:
            pass  # Failed/missing diagnostic is not a success or a second native call.
    removal_data = None
    removal_last = None
    if outcome == "success" and REMOVAL_DATA_SELECTED:
        try:
            removal_data = fixture.removal_data_result(result, source, rows)
            removal_last = fixture.registration_publication_tick(
                removal_data, fixture.decimal(removal_data["clock"]["lastNs"]))
        except BaseException:
            removal_data = None
    removal_qualified = removal_data is not None
    removal_diagnostic = None
    failed_graphs = [call for call in calls if "removalDataDiagnostic" in call]
    if (REMOVAL_DATA_SELECTED and len(failed_graphs) == 1 and failed_graphs[0] is calls[-1]
            and all(call["returned"] for call in calls)
            and all(result[key] for key in ("sourceClosesKnown", "outputClosesKnown", "protectedClosesKnown"))
            and not result["cleanupErrors"]):
        removal_diagnostic = fixture.installer_worker_diagnostic_data(
            failed_graphs[0]["removalDataDiagnostic"], failed_graphs[0], rows, removal_role=failed_graphs[0]["role"])
    integration_data = None
    integration_last = None
    if outcome == "success" and REMOVAL_INTEGRATION_SELECTED:
        try:
            integration_data = fixture.removal_integration_data_result(result, source, rows)
            integration_last = fixture.registration_publication_tick(
                integration_data, fixture.decimal(integration_data["clock"]["lastNs"]))
        except BaseException:
            integration_data = None
    integration_qualified = integration_data is not None
    integration_diagnostic = None
    if (REMOVAL_INTEGRATION_SELECTED and len(failed_graphs) == 1 and failed_graphs[0] is calls[-1]
            and all(call["returned"] for call in calls)
            and all(result[key] for key in ("sourceClosesKnown", "outputClosesKnown", "protectedClosesKnown"))
            and not result["cleanupErrors"]):
        integration_diagnostic = fixture.installer_worker_diagnostic_data(
            failed_graphs[0]["removalDataDiagnostic"], failed_graphs[0], rows, removal_role=failed_graphs[0]["role"])
    parent_data = None
    parent_last = None
    if outcome == "success" and REMOVAL_PARENT_SELECTED:
        try:
            parent_data = fixture.removal_parent_data_result(result, source, rows)
            parent_last = fixture.registration_publication_tick(
                parent_data, fixture.decimal(parent_data["clock"]["lastNs"]))
        except BaseException:
            parent_data = None
    parent_qualified = parent_data is not None
    parent_diagnostic = None
    if (REMOVAL_PARENT_SELECTED and len(failed_graphs) == 1 and failed_graphs[0] is calls[-1]
            and all(call["returned"] for call in calls)
            and all(result[key] for key in ("sourceClosesKnown", "outputClosesKnown", "protectedClosesKnown"))
            and not result["cleanupErrors"]):
        parent_diagnostic = fixture.installer_worker_diagnostic_data(
            failed_graphs[0]["removalDataDiagnostic"], failed_graphs[0], rows, removal_role=failed_graphs[0]["role"])
    changes_data = None
    changes_last = None
    if outcome == "success" and REMOVAL_CHANGES_SELECTED:
        try:
            changes_data = fixture.removal_changes_data_result(result, source, rows)
            changes_last = fixture.registration_publication_tick(
                changes_data, fixture.decimal(changes_data["clock"]["lastNs"]))
        except BaseException:
            changes_data = None
    changes_qualified = changes_data is not None
    changes_diagnostic = None
    if (REMOVAL_CHANGES_SELECTED and len(failed_graphs) == 1 and failed_graphs[0] is calls[-1]
            and all(call["returned"] for call in calls)
            and all(result[key] for key in ("sourceClosesKnown", "outputClosesKnown", "protectedClosesKnown"))
            and not result["cleanupErrors"]):
        changes_diagnostic = fixture.installer_worker_diagnostic_data(
            failed_graphs[0]["removalDataDiagnostic"], failed_graphs[0], rows, removal_role=failed_graphs[0]["role"])
    recovery_data = None
    recovery_last = None
    if outcome == "success" and REMOVAL_RECOVERY_SELECTED:
        try:
            recovery_data = fixture.removal_recovery_data_result(result, source, rows)
            recovery_last = fixture.registration_publication_tick(
                recovery_data, fixture.decimal(recovery_data["clock"]["lastNs"]))
        except BaseException:
            recovery_data = None
    recovery_qualified = recovery_data is not None
    recovery_diagnostic = None
    if (REMOVAL_RECOVERY_SELECTED and len(failed_graphs) == 1 and failed_graphs[0] is calls[-1]
            and all(call["returned"] for call in calls)
            and all(result[key] for key in ("sourceClosesKnown", "outputClosesKnown", "protectedClosesKnown"))
            and not result["cleanupErrors"]):
        recovery_diagnostic = fixture.installer_worker_diagnostic_data(
            failed_graphs[0]["removalDataDiagnostic"], failed_graphs[0], rows, removal_role=failed_graphs[0]["role"])
    context_completed = installer_context is not None and installer_context["completed"]
    known_pass = (
        outcome == "success" and result["passed"] is True and result["outcome"] == "passed"
        and result["failure"] is None and all(result[key] for key in flags)
        and result["cleanupErrors"] == [] and calls
        and all(call["returned"] and call["returncode"] == 0 for call in calls)
        and native_rust_tests is not None and installer_worker_rust_tests is not None
        and installed_reader_rust_tests is not None and producer_signing_rust_tests is not None
        and package_producer_rust_tests is not None
        and installer_context is not None and installer_context["completed"]
        and native is not None and native["outcome"] == "passed" and native["nativeFinalityKnown"] is True
    )
    # Only fixed diagnostic labels and returned call facts are added;
    # never compiler captures, environment, package bytes or arbitrary keys.
    summary.update(
        ownerResultAdmitted=True, ownerResultSha256=fixture.digest(result_body), tree=binding["tree"],
        bindingSha256=fixture.digest(binding_body), sourceInventorySha256=fixture.digest(inventory_body),
        sourceReleaseId=release, ownerOutcome=result["outcome"], originalCallCount=len(calls),
        ownerFinality={key: result[key] for key in flags}, native=native, accepted=bool(known_pass),
        nativeRustTests=native_rust_tests, installerWorkerRustTests=installer_worker_rust_tests,
        installedReaderRustTests=installed_reader_rust_tests,
        producerSigningRustTests=producer_signing_rust_tests,
        packageProducerRustTests=package_producer_rust_tests,
        installerContext=installer_context,
        serviceLayoutObservation=service_layout,
        btmLogObservation=btm_log, installerWorkerDiagnostic=installer_worker_diagnostic,
        contextMetadataDiagnostic=context_metadata_diagnostic,
        contextPackageInfoDiagnostic=context_package_diagnostic,
        contextDistributionDiagnostic=context_distribution_diagnostic,
        contextReceiptDiagnostic=context_receipt_diagnostic, diagnosticCaptured=bool(diagnostic_captured),
        contextObservationCompleted=bool(context_completed),
        registrationReservation=registration, registrationReservationQualified=registration_qualified, registrationFailure=registration_failure,
        removalData=removal_data, removalDataQualified=removal_qualified, removalDataDiagnostic=removal_diagnostic,
        removalIntegrationData=integration_data, removalIntegrationDataQualified=integration_qualified, removalIntegrationDataDiagnostic=integration_diagnostic,
        removalParentData=parent_data, removalParentDataQualified=parent_qualified, removalParentDataDiagnostic=parent_diagnostic,
        removalChangesData=changes_data, removalChangesDataQualified=changes_qualified, removalChangesDataDiagnostic=changes_diagnostic,
        removalRecoveryData=recovery_data, removalRecoveryDataQualified=recovery_qualified, removalRecoveryDataDiagnostic=recovery_diagnostic,
        ownerDiagnostic=native_owner_failure_data(result["phase"], result["failure"], calls),
        failure=None if (recovery_qualified if REMOVAL_RECOVERY_SELECTED else changes_qualified if REMOVAL_CHANGES_SELECTED else parent_qualified if REMOVAL_PARENT_SELECTED else integration_qualified if REMOVAL_INTEGRATION_SELECTED else removal_qualified if REMOVAL_DATA_SELECTED else registration_qualified) else "native-step-or-owner-did-not-establish-acceptance")
    book.check()
except BaseException:
    summary["accepted"] = False
    summary["registrationReservation"] = None
    summary["registrationReservationQualified"] = False
    summary["registrationFailure"] = None
    summary['removalData'] = None
    summary['removalDataQualified'] = False
    summary['removalDataDiagnostic'] = None
    summary['removalIntegrationData'] = None
    summary['removalIntegrationDataQualified'] = False
    summary['removalIntegrationDataDiagnostic'] = None
    summary['removalParentData'] = None
    summary['removalParentDataQualified'] = False
    summary['removalParentDataDiagnostic'] = None
    summary['removalChangesData'] = None
    summary['removalChangesDataQualified'] = False
    summary['removalChangesDataDiagnostic'] = None
    summary['removalRecoveryData'] = None
    summary['removalRecoveryDataQualified'] = False
    summary['removalRecoveryDataDiagnostic'] = None
    summary["nativeRustTests"] = None
    summary["installerWorkerRustTests"] = None
    summary["installedReaderRustTests"] = None
    summary["producerSigningRustTests"] = None
    summary["packageProducerRustTests"] = None
    summary["installerContext"] = None
    summary["serviceLayoutObservation"] = None
    summary["btmLogObservation"] = None
    summary["installerWorkerDiagnostic"] = None
    summary["contextMetadataDiagnostic"] = None
    summary["contextPackageInfoDiagnostic"] = None
    summary["contextDistributionDiagnostic"] = None
    summary["contextReceiptDiagnostic"] = None
    summary["diagnosticCaptured"] = False
    summary["contextObservationCompleted"] = False
    summary["failure"] = "owner-result-missing-or-refused"
finally:
    if not book.finish():
        summary["accepted"] = False
        summary["registrationReservation"] = None
        summary["registrationReservationQualified"] = False
        summary["registrationFailure"] = None
        summary['removalData'] = None
        summary['removalDataQualified'] = False
        summary['removalDataDiagnostic'] = None
        summary['removalIntegrationData'] = None
        summary['removalIntegrationDataQualified'] = False
        summary['removalIntegrationDataDiagnostic'] = None
        summary['removalParentData'] = None
        summary['removalParentDataQualified'] = False
        summary['removalParentDataDiagnostic'] = None
        summary['removalChangesData'] = None
        summary['removalChangesDataQualified'] = False
        summary['removalChangesDataDiagnostic'] = None
        summary['removalRecoveryData'] = None
        summary['removalRecoveryDataQualified'] = False
        summary['removalRecoveryDataDiagnostic'] = None
        summary["nativeRustTests"] = None
        summary["installerWorkerRustTests"] = None
        summary["installedReaderRustTests"] = None
        summary["producerSigningRustTests"] = None
        summary["packageProducerRustTests"] = None
        summary["installerContext"] = None
        summary["serviceLayoutObservation"] = None
        summary["btmLogObservation"] = None
        summary["installerWorkerDiagnostic"] = None
        summary["contextMetadataDiagnostic"] = None
        summary["contextPackageInfoDiagnostic"] = None
        summary["contextDistributionDiagnostic"] = None
        summary["contextReceiptDiagnostic"] = None
        summary["diagnosticCaptured"] = False
        summary["contextObservationCompleted"] = False
        summary["failure"] = "summary-input-close-unknown"
publisher = fixture.Originals()
try:
    if summary["registrationReservationQualified"]:
        registration_last = fixture.registration_publication_tick(summary["registrationReservation"], registration_last)
    if summary["removalDataQualified"]:
        removal_last = fixture.registration_publication_tick(summary["removalData"], removal_last)
    if summary["removalIntegrationDataQualified"]:
        integration_last = fixture.registration_publication_tick(summary["removalIntegrationData"], integration_last)
    if summary["removalParentDataQualified"]:
        parent_last = fixture.registration_publication_tick(summary["removalParentData"], parent_last)
    if summary["removalChangesDataQualified"]:
        changes_last = fixture.registration_publication_tick(summary["removalChangesData"], changes_last)
    if summary["removalRecoveryDataQualified"]:
        recovery_last = fixture.registration_publication_tick(summary["removalRecoveryData"], recovery_last)
    body = fixture.canonical(summary)
    fixture.need(len(body) <= 49152, "summary-output-bound")
    publisher.publish(work / "e2-workflow-result.json", body, 0o600)
    fixture.need(publisher.finish(), "summary-output-close")
    if summary["registrationReservationQualified"]:
        registration_last = fixture.registration_publication_tick(summary["registrationReservation"], registration_last)
    if summary["removalDataQualified"]:
        removal_last = fixture.registration_publication_tick(summary["removalData"], removal_last)
    if summary["removalIntegrationDataQualified"]:
        integration_last = fixture.registration_publication_tick(summary["removalIntegrationData"], integration_last)
    if summary["removalParentDataQualified"]:
        parent_last = fixture.registration_publication_tick(summary["removalParentData"], parent_last)
    if summary["removalChangesDataQualified"]:
        changes_last = fixture.registration_publication_tick(summary["removalChangesData"], changes_last)
    if summary["removalRecoveryDataQualified"]:
        recovery_last = fixture.registration_publication_tick(summary["removalRecoveryData"], recovery_last)
    output_path = Path(os.environ["GITHUB_OUTPUT"])
    fixture.need(output_path.parent == WORK_PARENT / "_runner_file_commands"
                 and re.fullmatch(r"set_output_[A-Za-z0-9-]+", output_path.name), "summary-step-output-route")
    fd = os.open(output_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        fixture.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                     and before.st_nlink == 1, "summary-step-output-original")
        line = ((b"accepted=true\n" if summary["accepted"] else b"accepted=false\n")
                + (b"diagnostic_captured=true\n" if summary["diagnosticCaptured"] else b"diagnostic_captured=false\n")
                + (b"context_observation_completed=true\n" if summary["contextObservationCompleted"] else b"context_observation_completed=false\n")
                + (b"registration_qualified=true\n" if summary["registrationReservationQualified"] else b"registration_qualified=false\n")
                + (b"removal_data_qualified=true\n" if summary["removalDataQualified"] else b"removal_data_qualified=false\n")
                + (b"removal_integration_data_qualified=true\n" if summary["removalIntegrationDataQualified"] else b"removal_integration_data_qualified=false\n")
                + (b"removal_parent_data_qualified=true\n" if summary["removalParentDataQualified"] else b"removal_parent_data_qualified=false\n")
                + (b"removal_changes_data_qualified=true\n" if summary["removalChangesDataQualified"] else b"removal_changes_data_qualified=false\n")
                + (b"removal_recovery_data_qualified=true\n" if summary["removalRecoveryDataQualified"] else b"removal_recovery_data_qualified=false\n"))
        fixture.need(os.write(fd, line) == len(line), "summary-step-output-write")
        os.fsync(fd)
        fixture.need(fixture.signature(os.fstat(fd)) == fixture.signature(os.stat(output_path, follow_symlinks=False)),
                     "summary-step-output-changed")
    finally:
        os.close(fd)
    if summary["registrationReservationQualified"]:
        registration_last = fixture.registration_publication_tick(summary["registrationReservation"], registration_last)
    if summary["removalDataQualified"]:
        removal_last = fixture.registration_publication_tick(summary["removalData"], removal_last)
    if summary["removalIntegrationDataQualified"]:
        integration_last = fixture.registration_publication_tick(summary["removalIntegrationData"], integration_last)
    if summary["removalParentDataQualified"]:
        parent_last = fixture.registration_publication_tick(summary["removalParentData"], parent_last)
    if summary["removalChangesDataQualified"]:
        changes_last = fixture.registration_publication_tick(summary["removalChangesData"], changes_last)
    if summary["removalRecoveryDataQualified"]:
        recovery_last = fixture.registration_publication_tick(summary["removalRecoveryData"], recovery_last)
except BaseException:
    publisher.finish()
    raise SystemExit("E2 bounded summary publication refused; no acceptance is established.")
print("Recovery DATA compiled and six selected groups completed; live recovery and shipping-image qualification remain pending."
      if summary["removalRecoveryDataQualified"] else "Recovery DATA failed; retained summary is failure evidence only.")
PY_PUBLISH
