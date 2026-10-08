set -euo pipefail
umask 077
[[ -d "$DEVELOPER_DIR" ]] || exit 1
# Existing pinned loader + run_owned, no new executor or fixture CLI.
# Cargo/rustc cwd remains below desktop/rust-toolchain.toml.
# Select the native package as root; its standalone Cargo.lock is the
# unchanged four-package application-lock closure, not a re-resolution.
"$MRK_PYTHON" -I -S -B - <<'PY_WRAPPING'
import ctypes, hashlib, importlib.util, json, math, os, pathlib, re, stat, struct, subprocess, sys, threading, time
work = pathlib.Path(os.environ["MRK_MACOS_WORK"])
checkout = pathlib.Path(os.environ["GITHUB_WORKSPACE"])
native = checkout / "desktop/native/macos-installed-native"
app = checkout / "desktop/src-tauri"
codec_library = "mobile_release_desktop"
codec_names = (
    "vault_crypto::tests::published_xchacha_vector_matches_selected_detached_api",
    "vault_crypto::tests::header_requires_the_exact_identity_key_nonce_and_tag",
    "vault_crypto::tests::listing_checks_only_descriptor_and_full_open_checks_every_section",
    "vault_crypto::tests::authenticated_payload_uses_exact_shared_scalar_and_file_semantics",
    "vault_crypto::tests::asc_authenticated_round_trip_retains_original_bytes_and_requires_fresh_observation",
    "vault_crypto::tests::asc_payload_refuses_wrong_kind_presence_duplicate_companions_and_over_cap_before_entropy",
    "vault_crypto::tests::random_refusal_collision_and_capacity_never_return_an_output",
    "vault_crypto::tests::intent_authenticates_exact_candidate_revisions_and_operation_without_replay",
    "vault_crypto::tests::section_aad_is_domain_full_prefix_and_role_not_an_ambiguous_concatenation",
    "vault_format::tests::identity_header_and_namespace_are_closed_but_not_authentication",
    "vault_format::tests::backend_identity_is_compile_target_bound_without_changing_other_wire_bytes",
    "vault_format::tests::record_lengths_sections_revisions_and_nonce_roles_are_exact",
    "vault_format::tests::descriptor_requires_every_exact_typed_key_and_current_kind_presence",
    "vault_format::tests::asc_descriptor_has_exact_two_presence_cells_and_no_persisted_approval",
    "vault_format::tests::mutation_fence_has_exact_new_replace_delete_and_zero_absence_rules",
)
policy_names = (
    "wrapping_keychain::policy_contract_tests::policy_failure_preserves_effect_and_blocks_known_candidate",
    "wrapping_keychain::policy_contract_tests::cleanup_uses_original_endpoint_and_spends_only_two_slots",
    "wrapping_keychain::policy_contract_tests::cleanup_bridge_does_not_reenter_or_drop_poisoned_forward_callback",
    "wrapping_keychain::policy_contract_tests::application_entries_do_not_invoke_provider_or_admission",
)
role_names = ("qualification_libtest_role::refuses_process_role",)
artifact_roles = ("codec-binary", "normal-archive", "normal-binary", "observer-archive",
                  "observer-binary", "qualification-archive", "qualification-binary",
                  "reader-compiler-original", "reader-binary", "cohort-compiler-original", "cohort-binary")
name = "common"
creator_entry = "creator-pair"
library = "mrk_macos_installed_native"
package = "path+" + native.as_uri() + "#mrk-macos-installed-native@0.1.0"
fixture_symbols = {
    "_mrk_wrapping_fixture_frame_bytes", "_mrk_wrapping_fixture_abi",
    "_mrk_wrapping_fixture_new", "_mrk_wrapping_fixture_run",
    "_mrk_wrapping_fixture_material", "_mrk_wrapping_fixture_binding", "_mrk_wrapping_fixture_free",
}
pair_symbols = {"_mrk_wrapping_pair_abi", "_mrk_wrapping_pair_frame_bytes", "_mrk_wrapping_pair_acl_frame_bytes",
                "_mrk_wrapping_pair_new", "_mrk_wrapping_pair_step", "_mrk_wrapping_pair_free"}
fixture_symbols |= pair_symbols
reader_phase_symbols = {"_mrk_wrapping_reader_phase_account", "_mrk_wrapping_reader_phase_open",
                        "_mrk_wrapping_reader_phase_write", "_mrk_wrapping_reader_phase_close"}
creator_identifier = "dev.mobile-release-kit.qualification.wrapping.creator"
reader_identifier = "dev.mobile-release-kit.qualification.wrapping.reader"
case_names = ("Selector", "HelperShapes", "AddBaseline", "LookupBaseline", "DuplicateBaseline", "MissingOther",
              "DenyDeleteAndReadonlyAllow", "ForeignUserMutationAllow", "ForeignGroupInheritOnlyMutationAllow",
              "PosixForeignWrite", "SymlinkLeaf", "PostAddNamespaceRefusal", "LockedPrivateFixture", "StopAfterAdd")
native_cohorts = (
    (name, "wrapping-private-common-cohort", "StopAfterAdd", "wrapping-native"),
    ("stop-before-add", "wrapping-private-stop-before-add", "StopBeforeAdd", "wrapping-before-add"),
    ("stop-before-lookup", "wrapping-private-stop-before-lookup", "StopBeforeLookup", "wrapping-before-lookup"),
)
def cohort_profile(entry):
    for profile in native_cohorts + ((creator_entry, "wrapping-private-creator-pair", "StopAfterAdd", "wrapping-creator"),):
        if entry == profile[0]: return profile
    raise ValueError("wrapping-unknown-native-entry")
spec = importlib.util.spec_from_file_location("_mrk_wrapping_existing_owner", checkout / "desktop/tools/macos_aqua_qualification.py")
qualification = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = qualification
spec.loader.exec_module(qualification)
owner = qualification.load_owner(checkout)
# Build environment only; never forwarded to the native cohort.
# No Cargo/Rust wrapper, encoded flags or ambient target override.
build_env = {key: os.environ[key] for key in ("DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET")}
build_env.update(PATH="/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", CARGO_HOME="/Users/runner/.cargo", RUSTUP_HOME="/Users/runner/.rustup", RUSTC="/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc", RUSTUP_AUTO_INSTALL="0")
build_env.update(LANG="C", LC_ALL="C", TZ="UTC", CARGO_INCREMENTAL="0", RUSTUP_TOOLCHAIN="1.98.1")
# Deliberately no HOME/TMPDIR override and no fixture/password/token
# input. The native selector obtains the real ordinary account.
native_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
              "__CF_USER_TEXT_ENCODING": f"0x{os.getuid():X}:0:0"}
receipt = {"schemaVersion": 2, "scope": "wrapping-private-terminal-cohorts",
           "source": os.environ["GITHUB_SHA"], "workflowSource": os.environ["GITHUB_WORKFLOW_SHA"],
           "workflow": os.environ["GITHUB_WORKFLOW_REF"], "runId": os.environ["GITHUB_RUN_ID"],
           "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "nativeEntry": name,
           "innerCutoffSeconds": 45, "outerTimeoutSeconds": 90, "calls": [], "variants": [],
           "nativeOriginalReturned": False, "nativeReportAdmitted": False, "passed": False,
           "receiptProvisionalUntilStepExitZero": True, "shippingBinaryQualified": False,
           "distributionQualified": False, "perQueryUIFailQualified": False, "processNonInteractionQualified": False,
           "fixtureCleanupOnUncertainty": False,
           "nativeCohorts": [{"entry": entry, "scope": scope, "terminalCase": terminal,
               "reportPrefix": prefix, "entered": False, "returned": False, "reportAdmitted": False}
               for entry, scope, terminal, prefix in native_cohorts]}
originals, files, errors = [], [], []
codec = {"compilerAdmitted": False, "testsPassed": False, "artifactHashRechecked": False,
         "syntheticDirectoriesRetired": False}
receipt["policyData"] = {"selectedTests": 4,
    "selectionSha256": hashlib.sha256(("\n".join(policy_names) + "\n").encode("ascii")).hexdigest(),
    "testsPassed": False, "artifactHashRechecked": False, "syntheticDirectoriesRetired": False}
receipt["libtestRoleData"] = {"testsPassed": False, "artifactHashRechecked": False,
    "syntheticDirectoriesRetired": False}
stage = "source-owner"
def pairs(items):
    value = {}
    for key, item in items:
        if key in value: raise ValueError("duplicate-json")
        value[key] = item
    return value
def parse(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite-json")))
def sig(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def pair_directory_same(a, b):
    # A DIRECTORY-only custody key. Preserve sig/full stat snapshots,
    # including nlink observations; regular files and ACKs still use sig.
    return (stat.S_ISDIR(a.st_mode) and stat.S_ISDIR(b.st_mode)
            and (a.st_dev, a.st_ino, a.st_mode, a.st_uid, a.st_gid)
            == (b.st_dev, b.st_ino, b.st_mode, b.st_uid, b.st_gid))
def pair_prelaunch_mark(data, predicate, phase=None):
    phases = ("setup", "sdk-binding", "parent-open", "root-create", "root-open", "root-admission",
              "request-encode", "request-write", "request-read", "request-readback", "binary-admission", "worker-prepare", "launch")
    predicates = ("sdk-load", "sdk-symbol", "sdk-signature", "deadline", "control-registration", "control-open", "control-close",
                  "root-mkdir", "root-held-stat", "root-named-stat", "root-held-binding", "root-named-binding", "root-mode",
                  "ordinary-account", "nonce", "request-encoding", "record-format", "file-held-stat", "file-named-stat",
                  "file-held-binding", "file-named-binding", "file-shape", "file-write", "file-write-length", "file-sync",
                  "file-read", "file-read-length", "file-eof", "file-eof-length", "readback", "binary-digest", "worker-create", "worker-start")
    if predicate not in predicates or phase is not None and phase not in phases: raise ValueError("pair-prelaunch-diagnostic-label")
    if not data["returned"] and data["firstFailure"] is None:
        if phase is not None: data["phase"] = phase
        data["predicate"] = predicate
def pair_prelaunch_failure(data):
    # Later independent join/close errors remain in their original
    # ledgers; they can never replace the first prelaunch predicate.
    if not data["returned"] and data["firstFailure"] is None:
        data["firstFailure"] = {"phase": data["phase"], "predicate": data["predicate"]}
def publish(leaf, data):
    if len(data) > 4 * 1024 * 1024: raise ValueError("wrapping-public-output-bound")
    fd = os.open(work / leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
def invoke(role, argv, *, environ, cwd, timeout, limit):
    # Thin recording at the EXISTING owner call, not a second owner.
    # The actual CompletedProcess/error enters this original first.
    global stage
    stage = role
    row = {"role": role, "argv": argv, "timeoutSeconds": timeout, "outputBound": limit,
           "entered": True, "returned": False}
    receipt["calls"].append(row)
    original = {"record": row, "result": None, "error": None}
    originals.append(original)
    try:
        original["result"] = owner.run_owned(argv, environ=environ, cwd=cwd, timeout=timeout,
                                            capture=True, text=False, output_limit=limit)
    except BaseException as error:
        original["error"] = error
        row["errorType"] = type(error).__name__
        if isinstance(error, (owner.ProcessError, owner.ProcessInterrupted)):
            row.update(dispatched=error.dispatched, contained=error.contained)
            if isinstance(error, owner.ProcessError): row["cleanupComplete"] = error.cleanup_complete
        raise
    result = original["result"]
    row["returned"] = True
    if (type(result) is not subprocess.CompletedProcess or type(result.returncode) is not int
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or len(result.stdout) + len(result.stderr) > limit):
        raise ValueError("wrapping-original-return-contract")
    row.update(returncode=result.returncode, stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr),
               stdoutSha256=hashlib.sha256(result.stdout).hexdigest(),
               stderrSha256=hashlib.sha256(result.stderr).hexdigest())
    return result, row
def admit_file(path, role, executable=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    cell = {"fd": fd, "path": path, "role": role, "closed": False, "unchanged": False}
    files.append(cell)
    before = os.fstat(fd)
    cell["before"] = before
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid()
            or before.st_mode & 0o022 or not 0 < before.st_size <= 1024 * 1024 * 1024
            or executable and not before.st_mode & 0o111):
        raise ValueError("wrapping-original-artifact-shape")
    cell["sha256"] = file_digest(cell)
    return cell
def file_digest(cell):
    fd, path, before = cell["fd"], cell["path"], cell["before"]
    if sig(before) != sig(os.fstat(fd)) or sig(before) != sig(path.lstat()):
        raise ValueError("wrapping-original-artifact-changed")
    digest, offset = hashlib.sha256(), 0
    while offset < before.st_size:
        block = os.pread(fd, min(before.st_size - offset, 1024 * 1024), offset)
        if not block: raise ValueError("wrapping-original-artifact-short")
        digest.update(block)
        offset += len(block)
    if os.pread(fd, 1, before.st_size) or sig(before) != sig(os.fstat(fd)) or sig(before) != sig(path.lstat()):
        raise ValueError("wrapping-original-artifact-changed")
    return digest.hexdigest()
def admit_codec_compiler(result):
    if (type(result) is not subprocess.CompletedProcess or type(result.returncode) is not int
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or len(result.stdout) + len(result.stderr) > 4 * 1024 * 1024 or result.returncode != 0):
        raise ValueError("wrapping-codec-compiler-failed")
    rows = [parse(line) for line in result.stdout.splitlines()]
    if any(type(row) is not dict for row in rows): raise ValueError("wrapping-codec-compiler-json-shape")
    finishes = [row for row in rows if row.get("reason") == "build-finished"]
    if len(finishes) != 1 or finishes[0].get("success") is not True:
        raise ValueError("wrapping-codec-original-compiler-finish")
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable") is not None]
    if len(artifacts) != 1: raise ValueError("wrapping-codec-one-app-artifact")
    artifact = artifacts[0]
    target, profile = artifact.get("target"), artifact.get("profile")
    package_id = "path+" + app.as_uri() + "#mobile-release-kit-desktop@0.1.1"
    if (type(target) is not dict or type(profile) is not dict
            or artifact.get("package_id") != package_id or artifact.get("manifest_path") != str(app / "Cargo.toml")
            or artifact.get("features") != [] or target.get("name") != codec_library
            or target.get("kind") != ["lib"] or target.get("crate_types") != ["lib"]
            or target.get("src_path") != str(app / "src/lib.rs") or profile.get("test") is not True
            or profile.get("debug_assertions") is not True or profile.get("overflow_checks") is not True
            or profile.get("opt_level") != "0" or type(artifact.get("executable")) is not str):
        raise ValueError("wrapping-codec-app-no-features-debug-libtest")
    binary = pathlib.Path(artifact["executable"])
    if (binary.parent != work / "wrapping-codec-target/aarch64-apple-darwin/debug/deps"
            or re.fullmatch(codec_library + r"-[0-9a-f]+", binary.name) is None
            or artifact.get("filenames") != [str(binary)]):
        raise ValueError("wrapping-codec-exact-artifact-location")
    return binary
def admit_fixed_data_results(result, names, count):
    # Every caller supplies source-fixed exact DATA selections. No CLI
    # filter or generic/native fixture roster is admitted here.
    if (type(result) is not subprocess.CompletedProcess or type(result.returncode) is not int
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or len(result.stdout) + len(result.stderr) > 64 * 1024
            or result.returncode != 0 or result.stderr):
        raise ValueError("wrapping-fixed-data-tests-returned-failure")
    lines = [line for line in result.stdout.decode("utf-8", "strict").splitlines() if line]
    expected_rows = {"test " + name + " ... ok" for name in names}
    if (len(names) != count or len(expected_rows) != count or len(lines) != count + 2
            or lines[0] != f"running {count} test" + ("" if count == 1 else "s") or len(set(lines[1:-1])) != count
            or set(lines[1:-1]) != expected_rows):
        raise ValueError("wrapping-fixed-data-exact-named-results")
    summary = re.fullmatch(rf"test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; ([0-9]+) filtered out; finished in [0-9]+\.[0-9]+s", lines[-1])
    if summary is None: raise ValueError("wrapping-fixed-data-exact-test-summary")
    return {"testsPassed": True, "tests": count, "failed": 0, "ignored": 0, "measured": 0, "filtered": int(summary[1])}
def admit_codec_results(result):
    return admit_fixed_data_results(result, codec_names, 15)
def admit_policy_results(result):
    return admit_fixed_data_results(result, policy_names, 4)
def fixed_test_original_settled(calls, role):
    calls = [row for row in calls if row.get("role") == role]
    if not calls: return True  # No original test dispatch yet.
    if len(calls) != 1: return False
    row = calls[0]
    return ((row.get("returned") is True and type(row.get("returncode")) is int)
            or row.get("dispatched") is False
            or (row.get("contained") is True and row.get("cleanupComplete") is True))
def codec_original_settled(calls):
    return fixed_test_original_settled(calls, "codec-tests")
def policy_original_settled(calls):
    return fixed_test_original_settled(calls, "normal-policy-tests")
def originals_succeeded(calls, roles):
    for role in roles:
        matches = [row for row in calls if row.get("role") == role]
        if len(matches) != 1: return False
        row = matches[0]
        # invoke installs returncode only AFTER admitting the actual
        # CompletedProcess, integer status and bounded byte streams.
        # No-dispatch/contained failure permits a close, never pass.
        if row.get("returned") is not True or type(row.get("returncode")) is not int or row["returncode"] != 0:
            return False
    return True
def codec_originals_succeeded(calls):
    return originals_succeeded(calls, ("codec-build", "codec-tests"))
def private_batch_finality(receipt, codec, files, errors, close_errors):
    roles = [cell.get("role") for cell in files]
    policy = receipt.get("policyData", {})
    refusal = receipt.get("libtestRoleData", {})
    return (not errors and not close_errors and len(roles) == len(artifact_roles) == 11
            and len(set(roles)) == 11 and set(roles) == set(artifact_roles)
            and all(cell.get("unchanged") is True and cell.get("closed") is True for cell in files)
            and codec.get("compilerAdmitted") is True and codec.get("testsPassed") is True
            and codec.get("artifactHashRechecked") is True and codec.get("syntheticDirectoriesRetired") is True
            and codec_originals_succeeded(receipt["calls"])
            and policy.get("testsPassed") is True and policy.get("artifactHashRechecked") is True
            and policy.get("syntheticDirectoriesRetired") is True
            and originals_succeeded(receipt["calls"], ("normal-build", "normal-list", "normal-policy-tests"))
            and refusal.get("testsPassed") is True and refusal.get("artifactHashRechecked") is True
            and refusal.get("syntheticDirectoriesRetired") is True
            and originals_succeeded(receipt["calls"], ("qualification-build", "qualification-list", "qualification-role-tests"))
            and receipt["nativeOriginalReturned"] is True and receipt["nativeReportAdmitted"] is True
            and receipt.get("pair", {}).get("passed") is True and receipt.get("pairNativeObservationsAdmitted") is True)
def public_codec_receipt(receipt, codec, files, errors, close_errors):
    # A closed scalar-only DTO: no argv, path, native output, result
    # object, exception text, private fixture or recursive serialization.
    public = {"schemaVersion": 1, "scope": "wrapping-private-app-codec-fifteen",
              "source": receipt["source"], "workflowSource": receipt["workflowSource"],
              "workflow": receipt["workflow"], "runId": receipt["runId"], "runAttempt": receipt["runAttempt"],
              "selectionSha256": hashlib.sha256(("\n".join(codec_names) + "\n").encode("ascii")).hexdigest(),
              "selectedTests": 15, "artifactSha256": codec.get("artifactSha256"), "artifactBytes": codec.get("artifactBytes"),
              "compilerAdmitted": codec["compilerAdmitted"], "testsPassed": codec["testsPassed"],
              "artifactHashRechecked": codec["artifactHashRechecked"],
              "syntheticDirectoriesRetired": codec["syntheticDirectoriesRetired"],
              "errorCount": len(errors), "closeErrorCount": len(close_errors), "passed": receipt["passed"],
              "receiptProvisionalUntilSourcePostAndStepExitZero": True,
              "shippingBinaryQualified": False, "distributionQualified": False}
    for key in ("tests", "failed", "ignored", "measured", "filtered"):
        public[key] = codec.get(key)
    cells = [cell for cell in files if cell["role"] == "codec-binary"]
    for key in ("unchanged", "closed"):
        public["artifactOriginal" + key.title()] = len(cells) == 1 and cells[0][key] is True
    for prefix, role in (("compiler", "codec-build"), ("test", "codec-tests")):
        calls = [row for row in receipt["calls"] if row["role"] == role]
        if len(calls) > 1: raise ValueError("wrapping-codec-public-one-original-per-role")
        call = calls[0] if calls else {}
        public[prefix + "OriginalReturned"] = call.get("returned") is True
        for key in ("returncode", "stdoutBytes", "stderrBytes", "stdoutSha256", "stderrSha256"):
            public[prefix + key[0].upper() + key[1:]] = call.get(key)
    return public
def exact_keys(value, keys):
    if type(value) is not dict or set(value) != set(keys.split()): raise ValueError("wrapping-report-keys")
def ints(value, length):
    if type(value) is not list or len(value) != length or any(type(n) is not int or not -(1 << 63) <= n < (1 << 63) for n in value):
        raise ValueError("wrapping-report-scalars")
    return value
def settled_policy(value, kind=1, role=1, namespace_child=False):
    exact_keys(value, "header calls")
    h = ints(value["header"], 18)
    if type(value["calls"]) is not list or len(value["calls"]) != 5:
        raise ValueError("wrapping-policy-call-bound")
    calls = [ints(call, 7) for call in value["calls"]]
    if kind == 0:  # Explicit namespace resource book: no policy authority.
        if h != [0] * 18 or calls != [[0] * 7 for _ in range(5)]:
            raise ValueError("wrapping-namespace-no-policy-authority")
        return
    if kind == 3:  # The one registered nested filesystem-only action13.
        if role != 1 or h != [1, 3, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1] or calls != [[0] * 7 for _ in range(5)]:
            raise ValueError("wrapping-namespace-child-policy")
        return
    original = h[6]
    child = 1 if namespace_child else 0
    if kind not in (1, 2) or role not in (1, 2) or kind == 2 and role != 1 or original not in (0, 1):
        raise ValueError("wrapping-policy-role-original")
    if h != [1, kind, role, 1, 1, 1, original, 1, 1, 1, 0, 0, 1, 0, 0, child, child, child]:
        raise ValueError("wrapping-policy-originals-unsettled")
    values = (original, 0, 0, original, original)
    if calls != [[1, 1, 0, 0, 0, value, 1] for value in values]:
        raise ValueError("wrapping-policy-return-restoration-required")

def settled_raw(raw, role=1, namespace=False, namespace_child=False):
    exact_keys(raw, "header references calls descriptors acl native policy")
    h = ints(raw["header"], 18)
    if h[0] != 3 or h[6] & 3 != 1 or h[9] != len(raw["references"]) or h[10] != len(raw["calls"]) or h[14] != len(raw["descriptors"]):
        raise ValueError("wrapping-settled-header")
    if not 0 <= h[9] <= 24 or not 0 <= h[10] <= 12 or not 0 <= h[14] <= 72:
        raise ValueError("wrapping-raw-bounds")
    for ref in raw["references"]:
        r = ints(ref, 6)
        if r[0] != 1 or any(n not in (0, 1) for n in r) or r[1] != r[2] or r[3] != r[5] or r[4] != r[5]:
            raise ValueError("wrapping-cf-original-unsettled")
    for call in raw["calls"]:
        c = ints(call, 4)
        if c[1:3] != [1, 1]: raise ValueError("wrapping-security-return-unobserved")
    for descriptor in raw["descriptors"]:
        d = ints(descriptor, 10)
        if (d[0] != 1 or d[1] != d[2] or d[3] != d[7] or d[5] != d[6]
                or d[7] and (d[5:8] != [1, 1, 1] or d[8] != 0)):
            raise ValueError("wrapping-descriptor-original-unsettled")
    a = ints(raw["acl"], 21)
    n = ints(raw["native"], 9)
    if (a[0] != a[1] or a[4] != a[5] or not a[6] == a[7] == a[8]
            or a[9] != a[10] or not a[11] == a[12] == a[13] == a[14]
            or a[15] != a[16] or not a[17] == a[18] == a[19] == a[20] or n[0] != n[1]):
        raise ValueError("wrapping-acl-original-unsettled")
    settled_policy(raw["policy"], 0 if namespace else 1, role, namespace_child)
    if namespace and (h[1] != 2 or h[12] != 0): raise ValueError("wrapping-namespace-is-not-operation")
    return h
def admit_before_item_terminal(case, action, caller):
    # Pure receipt checks. They cannot create native observations or
    # supply the outer original's exit/cleanup/finality.
    terminal = case["case"]
    if terminal not in ("StopBeforeAdd", "StopBeforeLookup"):
        raise ValueError("wrapping-before-item-case")
    phase, operation = (10, 1) if terminal == "StopBeforeAdd" else (11, 2)
    h = settled_raw(case["raw"])
    if (ints(action, 9) != [1, 1, 1, 1, 0, phase, 0, 0, 0]
            or h[1:7] != [operation, 14, 0, 16, phase, 229]
            or h[7] != 0 or h[8] & 1 != 1 or h[11:13] != [0, 1] or h[15:18] != [3, 3, 3]
            or any(row[0] in (10, 11) for row in case["raw"]["calls"])
            or case["selection"] != [1, 1, 1, 1, 0, 1]
            or case["acknowledged"] is not False or case["scopedValuePresent"] is not False
            or case["comparison"] is not None or case["comparisonRefused"] is not False
            or case["frameRetired"] is not True or case["retainedNativeBytes"] != 0
            or any(case[key] is not True for key in ("expected", "nativeReturned", "verified", "settled"))
            or caller["terminalHarnessHalted"] is not True or type(caller["terminalHarnessInvocations"]) is not int
            or caller["terminalHarnessInvocations"] != 14
            or caller["retirementAdmitted"] is not True or caller["stopRequested"] is not True):
        raise ValueError("wrapping-before-item-original-not-settled")
def public_report(result, entry=name):
    _, scope, _, _ = cohort_profile(entry)
    # Partial failure receipts are useful too, but only a bounded
    # closed scalar alphabet may leave the original native stdout.
    marker = b"MRK_WRAPPING_PRIVATE_RESULT="
    if result.stdout.count(marker) != 1: raise ValueError("wrapping-one-public-report")
    line, newline, rest = result.stdout.split(marker)[1].partition(b"\n")
    if not newline or len(line) > 128 * 1024: raise ValueError("wrapping-public-report-bound")
    value = parse(line)
    keys = set(("schemaVersion scope provisional outerFinalityRequired shippingBinaryQualified distributionQualified "
        "perQueryUIFailQualified processNonInteractionQualified cutoffSeconds adapterInvocationBound fixtureActionBound caller originalActions fixtureReturns "
        "fixture cases owed atomicProviderFdAttestation reportUnavailable runEntered runReturned completed originalSlotRetained "
        "registered chargedBytes chargeLimit nativeAbi fixtureFrameBytes adapterFrameBytes retirementAdmitted stopRequested "
        "deadlineObserved poisoned stage callbackOrCallerPanic clockChecks forwardAdmissions retirementAdmissions harnessRefused "
        "materialWiped materialGetter bindingGetter fixtureAllocation postAdd terminalStop terminalHarnessHalted terminalHarnessInvocations verified header actions calls "
        "references selections namespace descriptors acl native policy policies ordinal case evidence expected acknowledged nativeReturned "
        "settled retainedNativeBytes frameRetired scopedValuePresent comparisonRefused selection helperCounts comparison raw "
        "pair positiveAccepted barrierCompleted totalAdapterCalls waits controls positive role bookBytes aclFrameBytes "
        "blocked uncertain complete retained callbackPanic allocation free steps fds io roster").split())
    labels = set(case_names) | {"StopBeforeAdd", "StopBeforeLookup", "wrapping-private-creator-pair", "wrapping-private-stop-before-add", "wrapping-private-stop-before-lookup",
        "wrapping-private-common-cohort", "production-selector-only", "helper-shape-only",
        "synthetic-provider-only", "native-exception", "returned-failed-close", "incomplete-acl",
        "unforced-native-bounds", "before-item-stop", "second-executable-creator", "uifail-no-prompt-denial"}
    def checked(node, depth=0):
        if depth > 8: raise ValueError("wrapping-public-report-depth")
        if type(node) is dict:
            if len(node) > 64 or any(key not in keys for key in node): raise ValueError("wrapping-public-report-key")
            for item in node.values(): checked(item, depth + 1)
        elif type(node) is list:
            if len(node) > 1024: raise ValueError("wrapping-public-report-list")
            for item in node: checked(item, depth + 1)
        elif type(node) is str:
            if node not in labels: raise ValueError("wrapping-public-report-label")
        elif type(node) is int:
            if not -(1 << 63) <= node < (1 << 63): raise ValueError("wrapping-public-report-scalar")
        elif node is not None and type(node) is not bool:
            raise ValueError("wrapping-public-report-type")
    checked(value)
    if type(value) is not dict or value.get("scope") != scope or value.get("provisional") is not True:
        raise ValueError("wrapping-public-report-scope")
    return value
def admit_native_report(result, entry=name):
    _, scope, terminal, _ = cohort_profile(entry)
    selected_cases = case_names[:-1] + (terminal,)
    is_pair = entry == creator_entry
    if (type(result) is not subprocess.CompletedProcess or type(result.returncode) is not int or result.returncode != 0
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes or result.stderr or len(result.stdout) > 128 * 1024):
        raise ValueError("wrapping-native-not-successful")
    marker = b"MRK_WRAPPING_PRIVATE_RESULT="
    # Fixed helper stdout has exactly one bare report, never libtest
    # framing or a fabricated test summary.
    if result.stdout.count(marker) != 1: raise ValueError("wrapping-one-native-report")
    before, after = result.stdout.split(marker)
    line, newline, rest = after.partition(b"\n")
    if before or rest or not newline or len(line) > 128 * 1024:
        raise ValueError("wrapping-exact-helper-return")
    value = parse(line)
    exact_keys(value, "schemaVersion scope provisional outerFinalityRequired shippingBinaryQualified distributionQualified perQueryUIFailQualified processNonInteractionQualified cutoffSeconds adapterInvocationBound fixtureActionBound caller originalActions fixtureReturns fixture cases owed atomicProviderFdAttestation" + (" pair" if is_pair else ""))
    if (type(value["schemaVersion"]) is not int or value["schemaVersion"] != 2 or value["scope"] != scope
            or value["provisional"] is not True or value["outerFinalityRequired"] is not True
            or value["cutoffSeconds"] != 45 or value["adapterInvocationBound"] != (15 if is_pair else 14) or value["fixtureActionBound"] != 17
            or any(value[key] is not False for key in ("shippingBinaryQualified", "distributionQualified", "perQueryUIFailQualified", "processNonInteractionQualified", "atomicProviderFdAttestation"))):
        raise ValueError("wrapping-native-scope")
    c = value["caller"]
    caller_keys = "runEntered runReturned completed originalSlotRetained registered chargedBytes chargeLimit nativeAbi fixtureFrameBytes adapterFrameBytes retirementAdmitted stopRequested deadlineObserved poisoned stage callbackOrCallerPanic clockChecks forwardAdmissions retirementAdmissions harnessRefused materialWiped materialGetter bindingGetter fixtureAllocation"
    if terminal != "StopAfterAdd" or is_pair: caller_keys += " terminalHarnessHalted terminalHarnessInvocations"
    exact_keys(c, caller_keys)
    if (any(c[key] is not True for key in ("runEntered", "runReturned", "completed", "originalSlotRetained", "registered", "retirementAdmitted", "stopRequested", "materialWiped"))
            or any(c[key] is not False for key in ("deadlineObserved", "poisoned", "callbackOrCallerPanic", "harnessRefused"))
            or c["nativeAbi"] != 0x51460201 or c["stage"] != 300 or c["chargeLimit"] != 2 * 1024 * 1024
            or not 0 < c["chargedBytes"] <= c["chargeLimit"] or not 0 < c["fixtureFrameBytes"] <= 196608
            or not 0 < c["adapterFrameBytes"] <= 65536
            or ints(c["materialGetter"], 3) != [1, 1, 1] or ints(c["bindingGetter"], 3) != [1, 1, 1]
            or ints(c["fixtureAllocation"], 6) != [1, 1, 1, 1, 1, 1]):
        raise ValueError("wrapping-original-caller-not-complete")
    exact_keys(value["originalActions"], "postAdd terminalStop")
    if ints(value["originalActions"]["postAdd"], 9) != [1, 1, 1, 1, 1, 10, 1, 0, 1]:
        raise ValueError("wrapping-original-action-missing")
    if terminal == "StopAfterAdd" and ints(value["originalActions"]["terminalStop"], 9) != [1, 1, 1, 1, 1, 10, 1, 0, 1]:
        raise ValueError("wrapping-original-action-missing")
    if len(value["fixtureReturns"]) != 17: raise ValueError("wrapping-fixture-return-roster")
    for i, row in enumerate(value["fixtureReturns"]):
        if ints(row, 8) != [i + 1, 1, 1, 1, 0, 0, 0, 0]: raise ValueError("wrapping-fixture-action-unsettled")
    f = value["fixture"]
    exact_keys(f, "verified header actions calls references selections namespace policies")
    h = ints(f["header"], 20)
    if (f["verified"] is not True or h[:3] != [2, 33200, 17] or h[4:] != [10, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0]
            or not 0 < h[3] <= 1024 or h[3] != len(f["calls"]) or len(f["actions"]) != 17
            or len(f["references"]) != 10 or len(f["selections"]) != 4):
        raise ValueError("wrapping-fixture-finalized-without-facts")
    end = 0
    for i, action in enumerate(f["actions"]):
        a = ints(action, 6)
        if a[:4] != [i + 1, 1, 1, 1] or a[4] != end or not end <= a[5] <= h[3]: raise ValueError("wrapping-fixture-actual-call-roster")
        end = a[5]
    if end != h[3]: raise ValueError("wrapping-fixture-call-coverage")
    for call in f["calls"]:
        a = ints(call, 5)
        if not 1 <= a[0] <= 47 or a[1:3] != [1, 1]: raise ValueError("wrapping-fixture-call-not-returned")
    for ref in f["references"]:
        a = ints(ref, 6)
        if a[0:3] != [1, 1, 1] or a[3] not in (0, 1) or not a[3] == a[4] == a[5]: raise ValueError("wrapping-fixture-cf-not-settled")
    for i, selection in enumerate(f["selections"]):
        s = ints(selection, 15)
        paths = s[4] + (s[3] == 2)
        if (s[:3] != [1, 1, 1] or s[3] not in (1, 2) or not 0 <= s[4] <= 64
                or s[5:8] != [s[4]] * 3 or s[8:11] != [paths] * 3 or s[11] != s[12]
                or s[13] != (0 if i == 0 else 1) or s[14] != 1):
            raise ValueError("wrapping-readonly-selections-not-admitted")
    settled_raw(f["namespace"], namespace=True)
    if type(f["policies"]) is not list or len(f["policies"]) != 17: raise ValueError("wrapping-fixture-policy-roster")
    for i, policy in enumerate(f["policies"]): settled_policy(policy, 3 if i == 12 else 2)
    if len(value["cases"]) != 14: raise ValueError("wrapping-fourteen-original-cases")
    outcomes = (0, 12, 1, 2, 4, 3, 2, 10, 10, 10, 10, 10, 5, 14)
    effects = (0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1 if terminal == "StopAfterAdd" else 0)
    for i, case in enumerate(value["cases"]):
        exact_keys(case, "ordinal case evidence expected acknowledged nativeReturned verified settled retainedNativeBytes frameRetired scopedValuePresent comparisonRefused selection helperCounts comparison raw")
        evidence = "production-selector-only" if i == 0 else "helper-shape-only" if i == 1 else "synthetic-provider-only"
        if (case["ordinal"] != i + 1 or case["case"] != selected_cases[i] or case["evidence"] != evidence
                or any(case[key] is not True for key in ("expected", "nativeReturned", "verified", "settled"))
                or case["acknowledged"] is not (i != 13) or case["retainedNativeBytes"] != 0 or case["comparisonRefused"] is not False):
            raise ValueError("wrapping-original-adapter-case-not-complete")
        h = settled_raw(case["raw"], namespace_child=i == 11)
        if h[2] != outcomes[i] or h[3] != effects[i] or h[12] != 1 or h[4] != 16:
            raise ValueError("wrapping-actual-adapter-outcome")
        if i in (3, 6):
            if ints(case["comparison"], 5) != [1, 1, 1, c["adapterFrameBytes"], 1]: raise ValueError("wrapping-candidate-not-consumed")
        elif case["comparison"] is not None or case["frameRetired"] is not True:
            raise ValueError("wrapping-adapter-frame-not-retired")
    if is_pair:
        pair = value["pair"]
        exact_keys(pair, "positiveAccepted comparisonRefused barrierCompleted totalAdapterCalls waits controls positive")
        if (pair["positiveAccepted"] is not True or pair["comparisonRefused"] is not False
                or pair["barrierCompleted"] is not True or type(pair["totalAdapterCalls"]) is not int or pair["totalAdapterCalls"] != 15
                or type(pair["waits"]) is not int or not 0 <= pair["waits"] < 128
                or c["terminalHarnessHalted"] is not True or type(c["terminalHarnessInvocations"]) is not int
                or c["terminalHarnessInvocations"] != 14):
            raise ValueError("wrapping-creator-positive-barrier-missing")
        admit_peer_case(pair["positive"], False, c["adapterFrameBytes"])
        admit_controls(pair["controls"], 1)
    if terminal != "StopAfterAdd":
        admit_before_item_terminal(value["cases"][13], value["originalActions"]["terminalStop"], c)
    if value["cases"][1]["helperCounts"] != [20, 20, 20]: raise ValueError("wrapping-helper-shape-observations")
    if value["owed"] != ["native-exception", "returned-failed-close", "incomplete-acl", "unforced-native-bounds", "before-item-stop", "second-executable-creator", "uifail-no-prompt-denial"]:
        raise ValueError("wrapping-unexecuted-obligations-not-passes")
    # Validate the entire export's value alphabet too: even a field
    # not used for a positive decision cannot smuggle private text.
    public_labels = set(selected_cases) | set(value["owed"]) | {
        scope, "production-selector-only", "helper-shape-only", "synthetic-provider-only"}
    def public_values(node, depth=0):
        if depth > 8: raise ValueError("wrapping-public-report-depth")
        if type(node) is dict:
            for item in node.values(): public_values(item, depth + 1)
        elif type(node) is list:
            for item in node: public_values(item, depth + 1)
        elif type(node) is str:
            if node not in public_labels: raise ValueError("wrapping-nonpublic-report-label")
        elif type(node) is int:
            if not -(1 << 63) <= node < (1 << 63): raise ValueError("wrapping-public-scalar-bound")
        elif node is not None and type(node) is not bool:
            raise ValueError("wrapping-public-report-type")
    public_values(value)
    for key in ("chargedBytes", "chargeLimit", "nativeAbi", "fixtureFrameBytes", "adapterFrameBytes",
                "stage", "clockChecks", "forwardAdmissions", "retirementAdmissions"):
        if type(c[key]) is not int or c[key] <= 0: raise ValueError("wrapping-caller-scalar-type")
    # Only this closed public report is exported. Raw native stderr or
    # other SDK/libtest text is never uploaded on failure.
    return value

def record_bytes(data, kind, nonce=None, root=None):
    # Pure fixed wire validation; never a process/native receipt or grant.
    specs = {"request": (b"MRKQPR01", 64, 2), "ready": (b"MRKQPD01", 128, 1), "reader-settled": (b"MRKQPA01", 48, 2)}
    if kind not in specs or type(data) is not bytes: raise ValueError("pair-record-kind")
    magic, length, role = specs[kind]
    if (len(data) != length or data[:8] != magic or struct.unpack_from("<HH", data, 8) != (1, role)
            or data[12:16] != b"\0" * 4 or data[16:32] == b"\0" * 16
            or nonce is not None and data[16:32] != nonce):
        raise ValueError("pair-record-envelope")
    if kind == "request":
        device, inode, uid, gid = struct.unpack_from("<QQII", data, 32)
        if device > 0xffffffff or inode == 0 or uid == 0 or data[56:] != b"\0" * 8 or root != (device, inode, uid, gid):
            raise ValueError("pair-request-binding")
    elif kind == "ready":
        version, count, device, inode, mode, uid, gid, reserved = struct.unpack_from("<IIQQIIII", data, 32)
        if (version != 1 or count != 56 or device > 0xffffffff or inode == 0 or mode != 0o040700
                or uid == 0 or root is None or (uid, gid) != root[2:] or reserved != 0 or data[72:88] == b"\0" * 16
                or data[88:104] == b"\0" * 16 or data[104:120] == b"\0" * 16 or data[88:104] == data[104:120]
                or data[120:] != b"\0" * 8): raise ValueError("pair-ready-binding")
    elif struct.unpack_from("<I", data, 32)[0] != 1 or data[36:] != b"\0" * 12:
        raise ValueError("pair-settled-disposition")
    return data

def reader_owner_failure_facts(error, owner):
    # Closed diagnostic DATA only; never dispatch, cleanup, or ACK authority.
    facts = {"dispatched": None, "contained": None, "cleanupComplete": None,
             "ownerFailureCategory": "owner-failure-unknown"}
    if not isinstance(error, (owner.ProcessError, owner.ProcessInterrupted)): return facts
    for key, attribute in (("dispatched", "dispatched"), ("contained", "contained")):
        value = getattr(error, attribute, None)
        if type(value) is bool: facts[key] = value
    if isinstance(error, owner.ProcessInterrupted):
        facts["ownerFailureCategory"] = "interrupted"
    else:
        value = getattr(error, "cleanup_complete", None)
        if type(value) is bool: facts["cleanupComplete"] = value
        arguments = error.args
        if type(arguments) is tuple and len(arguments) == 1 and type(arguments[0]) is str:
            facts["ownerFailureCategory"] = {
                "owned command executable could not be started": "exec-not-started",
                "owned command was stopped before execution": "stopped-before-exec",
                "owned command produced incomplete output": "incomplete-output",
                "owned command output exceeds its bound": "output-bound",
                "owned command cleanup could not be confirmed": "cleanup-unconfirmed",
                "owned command exceeded its original deadline": "owner-deadline",
                "owned command protocol or original ownership is incomplete": "owner-protocol-incomplete",
                "owned command failed, timed out, or produced incomplete output": "owner-failure-unknown",
            }.get(arguments[0], "owner-failure-unknown")
    return facts

def reader_owner_elapsed(started, ended):
    # Reuse the budgeted sample; elapsed does not classify timeout or renew it.
    if (type(started) is not float or type(ended) is not float
            or not math.isfinite(started) or not math.isfinite(ended)): return None
    elapsed = ended - started
    return elapsed if math.isfinite(elapsed) and elapsed >= 0 else None

def owner_budget(now, endpoint, maximum):
    if not math.isfinite(now) or not math.isfinite(endpoint): raise ValueError("pair-invalid-clock")
    remaining = min(maximum, math.floor(endpoint - now - 3))
    if remaining <= 0: raise ValueError("pair-owner-budget-spent")
    return remaining

def launch_admitted(aborted, now, launch_end, drain_end):
    if aborted or now >= launch_end: raise ValueError("pair-creator-launch-refused")
    return owner_budget(now, drain_end, 90)

def acknowledge_admitted(pair, now, forward_end):
    if (not math.isfinite(now) or not math.isfinite(forward_end) or now >= forward_end
            or pair["aborted"] is not False or pair["readerOwnerReturned"] is not True
            or pair["readerNativeAdmitted"] is not True or pair["ackEntered"] is not False):
        raise ValueError("pair-ack-before-reader-finality-or-late")

def reader_phase_registration():
    # Registered before preparation/GO; raw header/FDs/errors never enter receipts.
    row = {key: False for key in ("openEntered", "openReturned", "acquired", "writeEntered", "writeReturned",
        "syncEntered", "syncReturned", "initialized", "finishEntered", "writerSettled", "readEntered", "readReturned",
        "removeEntered", "removeReturned", "absenceObserved", "closeEntered", "closeReturned", "closed", "retired")}
    row.update(role="reader-phase", fileBytes=2176, writtenBytes=0,
               projection={"state": "unavailable", "events": [], "elapsedMilliseconds": [],
                   "elapsedRounding": "floor", "clockOrigin": "reader-entry",
                   "clockSample": "pre-diagnostic-write-admission", "historyOnly": True, "currentCallKnown": False})
    return {"fd": None, "pin": None, "parentPin": None, "header": None, "record": row, "errors": []}

def reader_phase_identity(value):
    return (value.st_dev & 0xffffffff, value.st_ino, value.st_mode, value.st_uid, value.st_gid)

def reader_phase_header(root, parent, original):
    identities = [reader_phase_identity(value) for value in (root, parent, original)]
    for i, identity in enumerate(identities):
        if (any(type(v) is not int or not 0 <= v < 1 << 64 for v in identity)
                or identity[1] == 0 or identity[2] != (0o100600 if i == 2 else 0o040700)
                or not 0 < identity[3] < 1 << 32 or not 0 <= identity[4] < 1 << 32
                or identity[3:] != identities[0][3:]):
            raise ValueError("pair-reader-phase-header-binding")
    return b"MRKQDG02" + b"".join(struct.pack("<5Q", *identity) for identity in identities)

def reader_phase_bound(cell, parent_fd):
    if cell["fd"] is None or cell["pin"] is None or cell["parentPin"] is None:
        raise ValueError("pair-reader-phase-original-unbound")
    if not pair_directory_same(os.fstat(parent_fd), cell["parentPin"]):
        raise ValueError("pair-reader-phase-parent-changed")
    actual = os.fstat(cell["fd"])
    named = os.stat("wrapping-reader-phase.bin", dir_fd=parent_fd, follow_symlinks=False)
    if (sig(actual) != sig(named) or sig(actual)[:6] != sig(cell["pin"])[:6]
            or actual.st_mode != 0o100600 or actual.st_nlink != 1 or not 0 <= actual.st_size <= 2176):
        raise ValueError("pair-reader-phase-original-changed")
    return actual

def reader_phase_prepare(cell, parent_fd, root_pin, check_time):
    row = cell["record"]
    if row["openEntered"]: raise ValueError("pair-reader-phase-single-preparation")
    check_time()
    cell["parentPin"] = os.fstat(parent_fd)
    row["openEntered"] = True
    try:
        cell["fd"] = os.open("wrapping-reader-phase.bin",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    except OSError:
        # A returned OS refusal acquired no FD. An interruption remains Unknown.
        row["openReturned"] = True
        raise
    row["openReturned"] = True; row["acquired"] = True
    cell["pin"] = os.fstat(cell["fd"])
    pin = reader_phase_bound(cell, parent_fd)
    if (pin.st_size != 0 or (pin.st_uid, pin.st_gid) != (os.getuid(), os.getgid())
            or os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid()):
        raise ValueError("pair-reader-phase-ordinary-original")
    header = reader_phase_header(root_pin, cell["parentPin"], pin); cell["header"] = header
    data = header + bytes(2048)
    check_time(); row["writeEntered"] = True
    written = os.write(cell["fd"], data); row["writeReturned"] = True; row["writtenBytes"] = written
    if written != 2176: raise ValueError("pair-reader-phase-initial-write")
    check_time(); row["syncEntered"] = True
    os.fsync(cell["fd"]); row["syncReturned"] = True
    before = reader_phase_bound(cell, parent_fd)
    check_time()
    readback = os.pread(cell["fd"], 2176, 0)
    check_time()
    eof = os.pread(cell["fd"], 1, 2176)
    if readback != data or eof or sig(reader_phase_bound(cell, parent_fd)) != sig(before):
        raise ValueError("pair-reader-phase-initial-readback")
    check_time(); row["initialized"] = True

def reader_phase_projection(data, header):
    if type(data) is not bytes or len(data) != 2176 or type(header) is not bytes or len(header) != 128 or header[:8] != b"MRKQDG02" or data[:128] != header:
        raise ValueError("pair-reader-phase-snapshot-shape")
    coarse = ("diagnostic-opened", "control-reserve-before", "control-reserve-returned", "control-initialize-before",
        "control-initialize-returned", "ready-read-before", "ready-read-returned", "peer-construct-before",
        "peer-construct-returned", "peer-run-before", "peer-run-returned", "control-finish-before",
        "control-finish-returned", "report-build-before", "report-build-returned", "stdout-lock-before",
        "stdout-lock-returned", "stdout-write-before", "stdout-write-returned", "stdout-flush-before",
        "stdout-flush-returned", "reader-run-returned", "panic-observed", "diagnostic-close-before")
    phases = ("entry", "account", "path", "open", "get-path", "get-status", "query", "trusted", "access",
        "add", "lookup", "parent", "validate", "release", "delivery", "return", "namespace", "filesystem", "acl", "uuid", "fd-release")
    checkpoints = ("before-call", "after-call", "before-release", "before-delivery")
    # Floored original-entry PRE-WRITE admission samples, never API/current-call timestamps.
    events, elapsed_milliseconds, seen = [], [], set()
    state = "empty"
    for slot in range(128):
        at = 128 + slot * 16; record = data[at:at + 16]
        if record == bytes(16):
            if any(data[at:]): state = "partial"
            break
        magic, sequence, payload, guard = struct.unpack("<4I", record)
        event, elapsed_ms = payload & 0xff, payload >> 8
        if (magic != 0x32514744 or sequence != slot + 1 or guard != (0x4d524b32 ^ sequence ^ payload)
                or event in seen or not (1 <= event <= 24 or 65 <= event <= 148)
                or not 0 <= elapsed_ms < 10000
                or (elapsed_milliseconds and elapsed_ms < elapsed_milliseconds[-1])):
            state = "partial"; break
        seen.add(event)
        elapsed_milliseconds.append(elapsed_ms)
        events.append(coarse[event - 1] if event <= 24
                      else "native:" + phases[(event - 65) // 4] + ":" + checkpoints[(event - 65) % 4])
        state = "prefix"
    return {"state": state, "events": events, "elapsedMilliseconds": elapsed_milliseconds,
            "elapsedRounding": "floor", "clockOrigin": "reader-entry",
            "clockSample": "pre-diagnostic-write-admission", "historyOnly": True, "currentCallKnown": False}

def reader_phase_writer_settled(original):
    row, result, error = original["record"], original["result"], original["error"]
    if row["entered"] is False:
        return row["returned"] is False and result is None and error is None
    if row["entered"] is not True: return False
    if error is None:
        return (row["returned"] is True and type(result) is subprocess.CompletedProcess
                and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
                and len(result.stdout) + len(result.stderr) <= 256 * 1024)
    if row["returned"] is not False or result is not None or not isinstance(error, owner.ProcessError): return False
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen: continue
        if len(seen) >= 64: return False
        seen.add(id(current))
        if isinstance(current, owner.ProcessInterrupted): return False
        if isinstance(current, owner.ProcessError):
            if getattr(current, "contained", None) is not True or getattr(current, "cleanup_complete", None) is not True:
                return False
        for cause in (current.__context__, current.__cause__):
            if cause is not None: pending.append(cause)
    return True

def reader_phase_collect(cell, parent_fd, original, check_time):
    row, errors = cell["record"], cell["errors"]
    if row["finishEntered"]: return errors
    row["finishEntered"] = True
    row["writerSettled"] = reader_phase_writer_settled(original)
    if not row["writerSettled"]: return errors  # No snapshot, unlink or close while writer custody is uncertain.
    if cell["fd"] is None:
        row["retired"] = not row["openEntered"] or row["openReturned"] and not row["acquired"]
        return errors
    try:
        check_time()  # Original drain endpoint, independent of the already-latched owner failure.
        before = reader_phase_bound(cell, parent_fd)
        if row["initialized"]:
            check_time()
            row["readEntered"] = True
            data = os.pread(cell["fd"], 2176, 0)
            eof = os.pread(cell["fd"], 1, 2176)
            row["readReturned"] = True
            if eof or sig(reader_phase_bound(cell, parent_fd)) != sig(before):
                raise ValueError("pair-reader-phase-snapshot-changed")
            check_time()
            row["projection"] = reader_phase_projection(data, cell["header"])
            if row["projection"]["state"] == "partial":
                errors.append(ValueError("pair-reader-phase-incomplete-history"))
        elif original["record"]["entered"] is not False:
            raise ValueError("pair-reader-phase-uninitialized-writer")
        # Partial parent initialization still owns this exact bounded sibling.
        # Header/read failures above preserve the name; independent close still runs.
        if sig(reader_phase_bound(cell, parent_fd)) != sig(before):
            raise ValueError("pair-reader-phase-preremoval-changed")
        check_time()
        row["removeEntered"] = True
        os.unlink("wrapping-reader-phase.bin", dir_fd=parent_fd); row["removeReturned"] = True
        try: os.stat("wrapping-reader-phase.bin", dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError: row["absenceObserved"] = True
        else: raise ValueError("pair-reader-phase-name-still-present")
        check_time()
    except BaseException as error:
        errors.append(error)
    finally:
        if not row["closeEntered"]:
            fd, cell["fd"] = cell["fd"], None
            cell["consumedFd"] = fd; row["closeEntered"] = True
            try:
                os.close(fd); row["closeReturned"] = True; row["closed"] = True
            except BaseException as error: errors.append(error)
    # Close is unconditional once admitted above; a late close is still failure,
    # never permission to retry that original or renew the aggregate endpoint.
    try: check_time()
    except BaseException as error: errors.append(error)
    row["retired"] = row["removeReturned"] and row["absenceObserved"] and row["closed"]
    return errors


def pair_finality(pair):
    return (pair["aborted"] is False and not pair["errors"] and pair.get("ackResult") == 0 and type(pair.get("ackResult")) is int
        and pair.get("ackErrno") == 0 and type(pair.get("ackErrno")) is int
        and all(pair.get(key) is True for key in ("startAttempted", "startReturned", "joinAttempted", "joinReturned", "joined", "joinedBeforeDrain",
            "readyAdmitted", "readerOwnerReturned", "readerNativeAdmitted", "creatorNativeAdmitted", "ackEntered", "ackReturned",
            "ackMayHavePublished", "ackPublished", "controlRetired", "controlOriginalsClosed", "readerPhaseRetired")))

def admit_peer_case(value, reader, frame_bytes):
    exact_keys(value, "nativeReturned verified retainedNativeBytes frameRetired scopedValuePresent selection comparison raw")
    h = settled_raw(value["raw"], role=2 if reader else 1)
    if (value["nativeReturned"] is not True or value["verified"] is not True or value["retainedNativeBytes"] != 0
            or type(value["retainedNativeBytes"]) is not int or value["scopedValuePresent"] is not False
            or ints(value["selection"], 6) != [1, 1, 1, 1, 0, 1] or h[1] != 2 or h[3] != 0 or h[4] != 16
            or h[7] != 0 or h[8] & 1 != 1 or h[12] != 1 or h[15:18] != [5, 5, 5]):
        raise ValueError("pair-lookup-original")
    raw = value["raw"]
    expected_calls = [[4, 1, 1, 0], [5, 1, 1, 0], [6, 1, 1, 0], [11, 1, 1, -25308 if reader else 0]]
    if not reader: expected_calls.append([12, 1, 1, 0])
    expected_refs = [[1, 1, 1, 1, 1, 1]] * (5 if reader else 7)
    if reader: expected_refs.append([1, 1, 1, 0, 0, 0])
    snapshots = 6 * h[13] + 5
    if (not 1 <= h[13] <= 64 or h[14] != h[13] + 5 or raw["calls"] != expected_calls or raw["references"] != expected_refs
            or any(row != [1, 1, 1, 1, 0, 1, 1, 1, 0, 0] for row in raw["descriptors"])
            or raw["acl"][:3] != [snapshots] * 3 or raw["native"][6:] != [0, 0, 0]
            or not 0 < raw["native"][0] == raw["native"][1] <= 300000):
        raise ValueError("pair-full-native-namespace-custody")
    item = [row for row in value["raw"]["calls"] if row[0] in (10, 11)]
    if reader:
        if (h[2] != 6 or h[5] != 11 or h[6] != 1249 or h[11] != 0 or item != [[11, 1, 1, -25308]]
                or value["frameRetired"] is not True or value["comparison"] is not None):
            raise ValueError("pair-reader-unlocked-returned-uifail-required")
    elif (h[2] != 2 or h[5] != 0 or h[6] != 1145 or h[11] != 32 or item != [[11, 1, 1, 0]]
            or value["frameRetired"] is not False or ints(value["comparison"], 5) != [1, 1, 1, frame_bytes, 1]):
        raise ValueError("pair-creator-contemporaneous-comparison-required")

def admit_controls(value, role):
    exact_keys(value, "role bookBytes aclFrameBytes blocked uncertain complete retained callbackPanic allocation free steps header fds acl native io roster")
    if (type(value["role"]) is not int or value["role"] != role or type(value["bookBytes"]) is not int or not 0 < value["bookBytes"] <= 4096
            or type(value["aclFrameBytes"]) is not int or not 0 < value["aclFrameBytes"] <= 65536
            or value["blocked"] is not False or value["uncertain"] is not False or value["complete"] is not True or value["retained"] is not False or value["callbackPanic"] is not False
            or ints(value["allocation"], 3) != [1, 1, 1] or ints(value["free"], 3) != [1, 1, 1]):
        raise ValueError("pair-control-original-not-retired")
    h, a, n, io, d = (ints(value[key], length) for key, length in (("header", 32), ("acl", 21), ("native", 9), ("io", 9), ("roster", 12)))
    if (h[:10] != [1, 1912, role, 4, 0, 0, 0, 0, 1, 1] or h[13] != 1 or h[25:] != [value["aclFrameBytes"], 1, 1, 1, 0, 0, 0]
            or not 0 < h[20] <= 136 or not 0 <= h[21] <= 128 or h[22] != h[21]
            or not 0 < a[0] == a[1] == a[2] <= 400 or not 0 <= a[3] <= 128 * a[0]
            or a[4] != a[5] or not a[6] == a[7] == a[8] or a[9] != a[10] or not a[11] == a[12] == a[13] == a[14]
            or a[15] != a[16] or not a[17] == a[18] == a[19] == a[20] or any(v < 0 for v in a)
            or not 0 < n[0] == n[1] <= 300000 or n[3] != 1 or n[6:] != [0, 0, 0]
            or not 0 < io[0] == io[1] <= 8192 or io[3] != 1 or io[6:] != [0, 0, 0]
            or d[:5] != [1, 1, 1, 0, 1] or d[5:7] != [h[20], h[20]] or d[9:] != [h[20], 0, 0]
            or not h[20] <= d[7] == d[8] <= 7 * h[20]):
        raise ValueError("pair-control-custody")
    if type(value["fds"]) is not list or len(value["fds"]) != 6: raise ValueError("pair-control-fd-roster")
    for i, actual in enumerate(value["fds"]):
        expected = [0] * 26
        if role == 1 or i not in (2, 4):
            expected[:4], expected[17:20] = [1] * 4, [1] * 3
            if i in (1, 3, 4): expected[5:8], expected[22:24] = [1, 1, {1:64, 3:128, 4:48}[i]], [1, 1]
            if i == 2: expected[9:17] = [1, 1, 128, 0, 1, 1, 0, 0]
        if ints(actual, 26) != expected: raise ValueError("pair-control-fd-actual-return")
    steps = value["steps"]
    if type(steps) is not list or len(steps) > 132: raise ValueError("pair-control-step-bound")
    if role == 1:
        if not 1 <= h[21] <= 128 or h[10:13] != [1, 0, 1] or h[14:20] != [1, 1, 1, 1, 0, 0] or h[23:25] != [0, 0]:
            raise ValueError("pair-control-original-grant")
        expected_steps = [[1,1,1,1,1], [2,1,1,1,1]] + [[4,1,1,2,1]] * (h[21] - 1) + [[4,1,1,1,1], [5,1,1,1,1]]
    else:
        if h[10:13] != [0, 1, 0] or h[14:20] != [0] * 6 or h[21:25] != [0] * 4: raise ValueError("pair-reader-no-grant")
        expected_steps = [[1,1,1,1,1], [3,1,1,1,1], [5,1,1,1,1]]
    if [ints(row, 5) for row in steps] != expected_steps: raise ValueError("pair-control-fixed-lifecycle")

def public_reader_report(result):
    marker = b"MRK_WRAPPING_PEER_RESULT="
    if type(result.stdout) is not bytes or result.stdout.count(marker) != 1: raise ValueError("pair-reader-public-marker")
    line, newline, rest = result.stdout.split(marker)[1].partition(b"\n")
    if not newline or len(line) > 128 * 1024: raise ValueError("pair-reader-public-bound")
    value = parse(line)
    keys = set(("schemaVersion scope provisional outerFinalityRequired reportUnavailable cutoffSeconds adapterInvocationBound runEntered runReturned completed originalSlotRetained registered chargedBytes chargeLimit adapterFrameBytes deadlineObserved poisoned clockChecks callbackOrCallerPanic lookupStarted lookupRefused denialAccepted controls lookup globalWindowSurveillance shippingIdentityQualified perQueryUIFailQualified processNonInteractionQualified "
        "role bookBytes aclFrameBytes blocked uncertain complete retained callbackPanic allocation free steps header fds acl native io roster nativeReturned verified retainedNativeBytes frameRetired scopedValuePresent selection comparison raw references calls descriptors policy").split())
    def checked(node, depth=0):
        if depth > 8: raise ValueError("pair-reader-public-depth")
        if type(node) is dict:
            if len(node) > 64 or any(key not in keys for key in node): raise ValueError("pair-reader-public-key")
            for item in node.values(): checked(item, depth + 1)
        elif type(node) is list:
            if len(node) > 132: raise ValueError("pair-reader-public-list")
            for item in node: checked(item, depth + 1)
        elif type(node) is str:
            if node != "wrapping-other-executable-reader": raise ValueError("pair-reader-public-label")
        elif type(node) is int:
            if not -(1 << 63) <= node < (1 << 63): raise ValueError("pair-reader-public-integer")
        elif node is not None and type(node) is not bool: raise ValueError("pair-reader-public-value")
    checked(value)
    if type(value) is not dict or value.get("scope") != "wrapping-other-executable-reader" or value.get("provisional") is not True:
        raise ValueError("pair-reader-public-scope")
    return value

def admit_reader_report(result):
    if (type(result) is not subprocess.CompletedProcess or type(result.returncode) is not int or result.returncode != 0
            or type(result.stdout) is not bytes or result.stderr != b"" or len(result.stdout) > 128 * 1024):
        raise ValueError("pair-reader-original-return")
    marker = b"MRK_WRAPPING_PEER_RESULT="
    if not result.stdout.startswith(marker) or result.stdout.count(marker) != 1 or result.stdout.count(b"\n") != 1 or not result.stdout.endswith(b"\n"):
        raise ValueError("pair-reader-exact-report")
    value = public_reader_report(result)
    exact_keys(value, "schemaVersion scope provisional outerFinalityRequired cutoffSeconds adapterInvocationBound runEntered runReturned completed originalSlotRetained registered chargedBytes chargeLimit adapterFrameBytes deadlineObserved poisoned clockChecks callbackOrCallerPanic lookupStarted lookupRefused denialAccepted controls lookup globalWindowSurveillance shippingIdentityQualified perQueryUIFailQualified processNonInteractionQualified")
    if (any(type(value[key]) is not int for key in ("schemaVersion", "cutoffSeconds", "adapterInvocationBound", "chargeLimit"))
            or value["schemaVersion"] != 2 or value["scope"] != "wrapping-other-executable-reader" or value["cutoffSeconds"] != 10
            or value["adapterInvocationBound"] != 1 or value["chargeLimit"] != 512 * 1024
            or any(value[key] is not True for key in ("provisional", "outerFinalityRequired", "runEntered", "runReturned", "completed", "originalSlotRetained", "registered", "lookupStarted", "denialAccepted"))
            or any(value[key] is not False for key in ("deadlineObserved", "poisoned", "callbackOrCallerPanic", "lookupRefused", "globalWindowSurveillance", "shippingIdentityQualified", "perQueryUIFailQualified", "processNonInteractionQualified"))
            or type(value["chargedBytes"]) is not int or not 0 < value["chargedBytes"] <= value["chargeLimit"]
            or type(value["adapterFrameBytes"]) is not int or not 0 < value["adapterFrameBytes"] <= 65536
            or type(value["clockChecks"]) is not int or value["clockChecks"] <= 0): raise ValueError("pair-reader-native-not-complete")
    admit_controls(value["controls"], 2); admit_peer_case(value["lookup"], True, value["adapterFrameBytes"])
    return value

def copy_reader_compiler_original(source, role="reader"):
    if role not in ("reader", "cohort"): raise ValueError("pair-fixed-helper-copy-role")
    # Cargo may hard-link its named example to its own hashed build output.
    # Never sign/modify that alias. Copy each separately compiled helper's bytes
    # from one retained, unchanged regular-file original into one exclusive
    # task-owned nlink1 signing target. One helper is never copied from the other.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    cell = {"fd": fd, "path": source, "role": role + "-compiler-original", "closed": False, "unchanged": False}
    files.append(cell); before = os.fstat(fd); cell["before"] = before
    if (not stat.S_ISREG(before.st_mode) or not 1 <= before.st_nlink <= 2 or before.st_uid != os.getuid()
            or before.st_mode & 0o022 or not before.st_mode & 0o111 or not 0 < before.st_size <= 1024 * 1024 * 1024):
        raise ValueError("pair-reader-compiler-original-shape")
    cell["sha256"] = file_digest(cell)
    target = work / {"reader": "wrapping-peer-reader", "cohort": "wrapping-private-cohort"}[role]
    row = {"sourceSha256": cell["sha256"], "sourceLinks": before.st_nlink, "bytes": before.st_size,
           "openEntered": False, "openReturned": False, "writtenBytes": 0, "syncEntered": False,
           "syncReturned": False, "closeEntered": False, "closeReturned": False, "closed": False}
    receipt[role + "Copy"] = row
    copy_original = {"record": row, "fd": None, "error": None}; originals.append(copy_original)
    row["openEntered"] = True
    copy_original["fd"] = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o700)
    row["openReturned"] = True
    try:
        digest, offset = hashlib.sha256(), 0
        while offset < before.st_size:
            length = min(1024 * 1024, before.st_size - offset)
            block = os.pread(fd, length, offset)
            if len(block) != length: raise ValueError("pair-reader-copy-short-read")
            actual = os.write(copy_original["fd"], block); row["writtenBytes"] += actual
            if actual != length: raise ValueError("pair-reader-copy-short-write")
            digest.update(block); offset += length
        if (os.pread(fd, 1, before.st_size) or sig(os.fstat(fd)) != sig(before) or sig(source.lstat()) != sig(before)
                or digest.hexdigest() != cell["sha256"]): raise ValueError("pair-reader-copy-source-changed")
        row["syncEntered"] = True; os.fsync(copy_original["fd"]); row["syncReturned"] = True
        created = os.fstat(copy_original["fd"])
        if (sig(created) != sig(target.lstat()) or created.st_mode != 0o100700 or created.st_nlink != 1
                or created.st_uid != os.getuid() or created.st_size != before.st_size): raise ValueError("pair-reader-copy-target-shape")
        observed_copy = file_digest({"fd": copy_original["fd"], "path": target, "before": created})
        if observed_copy != cell["sha256"]: raise ValueError("pair-reader-copy-readback")
        row["unsignedCopySha256"] = observed_copy
    except BaseException as error:
        copy_original["error"] = error; raise
    finally:
        descriptor, copy_original["fd"] = copy_original["fd"], None
        copy_original["consumedFd"] = descriptor; row["closeEntered"] = True
        os.close(descriptor); row["closeReturned"] = True; row["closed"] = True
    return target

def signature_identity(display, identifier, facts):
    # Only closed scalar diagnostics survive refusal; never display text,
    # arbitrary exception values, paths or requirement contents.
    facts.update({"reason": "original", "originalAdmitted": False, "asciiDecoded": False,
                  "identifierCount": 0, "identifierMatches": False,
                  "cdhashCount": 0, "cdhashValid": False,
                  "explicitRequirementCount": 0, "implicitRequirementCount": 0,
                  "requirementCount": 0, "requirementSingleton": False, "requirementBodyValid": False,
                  "signatureCount": 0, "adHocSignatureCount": 0, "signatureSingletonAdHoc": False,
                  "admitted": False})
    if (type(display) is not subprocess.CompletedProcess or type(display.returncode) is not int
            or display.returncode != 0 or type(display.stdout) is not bytes or type(display.stderr) is not bytes
            or len(display.stdout) + len(display.stderr) > 16384): raise ValueError("pair-code-display-original")
    facts["originalAdmitted"] = True
    facts["reason"] = "ascii"
    try:
        # Split only actual LF delimiters: CR/control bytes inside a
        # requirement must not disappear through splitlines normalization.
        lines = (display.stdout + b"\n" + display.stderr).decode("ascii", "strict").split("\n")
    except UnicodeDecodeError:
        raise ValueError("pair-code-display-ascii") from None
    facts["asciiDecoded"] = True
    identifiers = [line[11:] for line in lines if line.startswith("Identifier=")]
    hashes = [line[7:] for line in lines if line.startswith("CDHash=")]
    # codesign annotates an implicit default requirement with exactly
    # '# '. It is the same requirement body, not an arbitrary comment.
    explicit = [line[len("designated => "):] for line in lines if line.startswith("designated => ")]
    implicit = [line[len("# designated => "):] for line in lines if line.startswith("# designated => ")]
    requirements = explicit + implicit
    signatures = [line[10:] for line in lines if line.startswith("Signature=")]
    facts.update({"identifierCount": len(identifiers), "identifierMatches": identifiers == [identifier],
                  "cdhashCount": len(hashes), "cdhashValid": len(hashes) == 1 and re.fullmatch(r"[0-9a-f]{40}", hashes[0]) is not None,
                  "explicitRequirementCount": len(explicit), "implicitRequirementCount": len(implicit),
                  "requirementCount": len(requirements), "requirementSingleton": len(requirements) == 1,
                  "requirementBodyValid": len(requirements) == 1 and 0 < len(requirements[0]) <= 2048
                      and all(32 <= ord(c) <= 126 for c in requirements[0]),
                  "signatureCount": len(signatures), "adHocSignatureCount": signatures.count("adhoc"),
                  "signatureSingletonAdHoc": signatures == ["adhoc"]})
    for reason, key in (("identifier", "identifierMatches"), ("cdhash", "cdhashValid"),
                        ("requirement-count", "requirementSingleton"), ("requirement-body", "requirementBodyValid"),
                        ("signature", "signatureSingletonAdHoc")):
        facts["reason"] = reason
        if facts[key] is not True: raise ValueError("pair-actual-ad-hoc-code-identity")
    identity = {"identifier": identifier, "cdhash": hashes[0],
                "requirementSha256": hashlib.sha256(requirements[0].encode("ascii")).hexdigest()}
    facts.update(reason="accepted", admitted=True)
    return identity

def distinct_code_identities(creator, reader):
    for value in (creator, reader):
        exact_keys(value, "identifier cdhash requirementSha256 fileSha256")
        if (type(value["identifier"]) is not str or type(value["cdhash"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", value["cdhash"]) is None
                or any(type(value[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None for key in ("requirementSha256", "fileSha256"))):
            raise ValueError("pair-code-identity-shape")
    if (creator["identifier"] != creator_identifier or reader["identifier"] != reader_identifier
            or any(creator[key] == reader[key] for key in ("identifier", "cdhash", "requirementSha256", "fileSha256"))):
        raise ValueError("pair-distinct-executable-code-identity-required")

def creator_worker(holder, lock, abort, argv, cwd, launch_end, drain_end):
    guard, original_errors = None, []
    holder["bodyEntered"] = True
    try:
        guard = owner.DefaultCancellation(owner.ProcessCleanupError, "private creator cancellation restoration unproven")
        guard.install(); holder["guardInstalled"] = True
        guard.activate(); holder["guardActivated"] = True
        # thread.start is NOT native admission. Original endpoints and the
        # absorbing latch are rechecked AFTER this worker's own activation.
        with lock:
            timeout = launch_admitted(abort.is_set(), time.monotonic(), launch_end, drain_end)
            holder["timeoutSeconds"] = timeout
            holder["ownerEntered"] = True
        holder["result"] = owner.run_owned(argv, environ=native_env, cwd=cwd, timeout=timeout,
            capture=True, text=False, output_limit=256 * 1024, cancellation=guard)
        holder["ownerReturned"] = True
    except BaseException as error:
        original_errors.append(error)
        with lock: abort.set()
    finally:
        if guard is not None:
            for key, operation in (("guardRestored", guard.restore), ("guardChecked", guard.check)):
                try: operation(); holder[key] = True
                except BaseException as error:
                    original_errors.append(error)
                    with lock: abort.set()
            try: holder["guardState"] = guard.handler_state
            except BaseException as error:
                original_errors.append(error)
                with lock: abort.set()
        holder["errors"] = original_errors
        holder["bodyReturned"] = True

def run_creator_reader(creator, reader):
    # One aggregate clock BEFORE any control preparation, start attempt, or GO.
    started = time.monotonic()
    launch_end, ready_end, forward_end, drain_end = started + 5, started + 20, started + 35, started + 100
    lock, abort = threading.Lock(), threading.Event()
    pair = {"registeredOriginals": 2, "launchSeconds": 5, "readySeconds": 20, "forwardSeconds": 35, "drainSeconds": 100,
            "startAttempted": False, "startReturned": False, "joinAttempted": False, "joinReturned": False, "joined": False,
            "readyAdmitted": False, "readerOwnerReturned": False, "readerNativeAdmitted": False, "creatorNativeAdmitted": False,
            "ackEntered": False, "ackReturned": False, "ackMayHavePublished": False, "ackPublished": False,
            "controlRetired": False, "readerPhaseRetired": False, "aborted": False, "passed": False, "errors": [], "controlCalls": [],
            "prelaunch": {"phase": "setup", "predicate": None, "returned": False, "firstFailure": None},
            "directoryLinks": {"initial": None, "held": None, "named": None}}
    receipt["pair"] = pair
    holder = {"bodyEntered": False, "bodyReturned": False, "ownerEntered": False, "ownerReturned": False,
              "guardInstalled": False, "guardActivated": False, "guardRestored": False, "guardChecked": False,
              "guardState": "NOT_INSTALLED", "result": None, "errors": []}
    control = work / "wrapping-pair-control"
    original_errors, worker = [], None
    # Original control slots and BOTH owner-call slots exist before preparation
    # and GO; later calls can only spend these closed source-fixed registrations.
    resources = [{"fd": None, "record": {"role": role, "openEntered": False, "openReturned": False,
        "acquired": False, "closeEntered": False, "closeReturned": False, "closed": False}}
        for role in ("parent", "root", "request-write", "request", "ready", "reader-settled.next", "reader-settled")]
    pair["controlCalls"] = [cell["record"] for cell in resources]
    phase_original = reader_phase_registration()
    pair["readerPhase"] = phase_original["record"]
    reader_record = {"role": "wrapping-peer-reader", "argv": [str(reader["path"])], "timeoutSeconds": None,
                     "outputBound": 256 * 1024, "entered": False, "returned": False, "ownerCallPhase": "registered",
                     "dispatched": None, "contained": None, "cleanupComplete": None,
                     "ownerFailureCategory": None, "ownerAttemptElapsedSeconds": None}
    reader_original = {"record": reader_record, "result": None, "error": None}
    receipt["calls"].append(reader_record)
    pair_original = {"pairWorker": holder, "pairReader": reader_original, "pairResources": resources, "readerPhase": phase_original, "pairErrors": original_errors, "thread": None}
    originals.append(pair_original)
    parent_fd, root_fd, root_pin, nonce, root_identity = None, None, None, None, None
    cells = {}
    def mark(predicate, phase=None):
        pair_prelaunch_mark(pair["prelaunch"], predicate, phase)
    def fail(error):
        pair_prelaunch_failure(pair["prelaunch"])
        with lock: abort.set()
        original_errors.append(error)
    def check_time(endpoint):
        mark("deadline")
        if abort.is_set() or time.monotonic() >= endpoint: raise ValueError("pair-forward-admission-spent")
    def reader_phase_check_time():
        # Failure is already latched; only the original drain endpoint gates diagnostics.
        if time.monotonic() >= drain_end: raise ValueError("pair-reader-phase-drain-spent")
    def resource(role, acquire):
        mark("control-registration")
        matching = [cell for cell in resources if cell["record"]["role"] == role]
        if len(matching) != 1 or matching[0]["record"]["openEntered"]: raise ValueError("pair-unregistered-control-open")
        cell = matching[0]; row = cell["record"]; row["openEntered"] = True
        mark("control-open")
        cell["fd"] = acquire(); row["openReturned"] = True; row["acquired"] = True
        return cell
    def close(cell):
        row = cell["record"]
        if cell["fd"] is None or row["closeEntered"]: return
        fd, cell["fd"] = cell["fd"], None; cell["consumedFd"] = fd; row["closeEntered"] = True
        mark("control-close")
        try: os.close(fd); row["closeReturned"] = True; row["closed"] = True
        except BaseException as error:
            row["closeError"] = type(error).__name__; raise # No invented physical return from a Python exception.
    def root_check():
        mark("root-held-stat")
        actual = os.fstat(root_fd); pair["directoryLinks"]["held"] = actual.st_nlink
        mark("root-named-stat")
        named = os.stat("wrapping-pair-control", dir_fd=parent_fd, follow_symlinks=False)
        pair["directoryLinks"]["named"] = named.st_nlink
        mark("root-held-binding")
        if not pair_directory_same(actual, root_pin): raise ValueError("pair-control-root-changed")
        mark("root-named-binding")
        if not pair_directory_same(named, root_pin): raise ValueError("pair-control-root-changed")
        mark("root-mode")
        if actual.st_mode != 0o040700: raise ValueError("pair-control-root-changed")
    def file_check(cell, leaf):
        root_check()
        mark("file-held-stat")
        held = os.fstat(cell["fd"])
        mark("file-named-stat")
        named = os.stat(leaf, dir_fd=root_fd, follow_symlinks=False)
        mark("file-held-binding")
        if sig(held) != sig(cell["pin"]): raise ValueError("pair-control-file-changed")
        mark("file-named-binding")
        if sig(named) != sig(held): raise ValueError("pair-control-file-changed")
    def read_record(leaf, length):
        root_check()
        cell = resource(leaf, lambda: os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_fd))
        cells[leaf] = cell; mark("file-held-stat"); cell["pin"] = os.fstat(cell["fd"])
        pin = cell["pin"]
        mark("file-shape")
        if (pin.st_mode != 0o100600 or pin.st_nlink != 1 or (pin.st_uid, pin.st_gid) != root_identity[2:]
                or pin.st_size != length): raise ValueError("pair-control-file-shape")
        file_check(cell, leaf)
        row = cell["record"]; row["readEntered"] = True; mark("file-read")
        data = os.pread(cell["fd"], length, 0); row["readReturned"] = True; row["readBytes"] = len(data)
        mark("file-read-length")
        if len(data) != length: raise ValueError("pair-control-short-read")
        row["eofEntered"] = True; mark("file-eof")
        extra = os.pread(cell["fd"], 1, length); row["eofReturned"] = True; row["eofBytes"] = len(extra)
        mark("file-eof-length")
        if extra: raise ValueError("pair-control-extra-data")
        file_check(cell, leaf)
        return cell, data
    def write_record(leaf, data):
        root_check()
        cell = resource("request-write" if leaf == "request" else leaf, lambda: os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=root_fd))
        cells[leaf] = cell
        row = cell["record"]; row["writeEntered"] = True; mark("file-write")
        written = os.write(cell["fd"], data); row["writeReturned"] = True; row["writeBytes"] = written
        mark("file-write-length")
        if written != len(data): raise ValueError("pair-control-short-write")
        row["syncEntered"] = True; mark("file-sync"); os.fsync(cell["fd"]); row["syncReturned"] = True
        mark("file-held-stat"); cell["pin"] = os.fstat(cell["fd"])
        pin = cell["pin"]; mark("file-shape")
        if pin.st_mode != 0o100600 or pin.st_nlink != 1 or (pin.st_uid, pin.st_gid) != root_identity[2:] or pin.st_size != len(data):
            raise ValueError("pair-control-created-shape")
        file_check(cell, leaf); close(cell)
        return cell
    try:
        # Fixed SDK binding; never search/fallback to an overwrite rename.
        mark("sdk-load", "sdk-binding")
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        mark("sdk-symbol"); exclusive_rename = libc.renameatx_np
        mark("sdk-signature")
        exclusive_rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        exclusive_rename.restype = ctypes.c_int
        mark("deadline", "parent-open"); check_time(launch_end)
        parent = resource("parent", lambda: os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC))
        parent_fd = parent["fd"]
        mark("root-mkdir", "root-create"); pair["mkdirEntered"] = True
        os.mkdir("wrapping-pair-control", mode=0o700, dir_fd=parent_fd); pair["mkdirReturned"] = True
        mark("control-open", "root-open")
        root = resource("root", lambda: os.open("wrapping-pair-control", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd))
        root_fd = root["fd"]; mark("root-held-stat"); root_pin = os.fstat(root_fd)
        root["pin"] = root_pin; pair["directoryLinks"]["initial"] = root_pin.st_nlink
        mark("ordinary-account", "root-admission")
        if root_pin.st_uid != os.getuid() or root_pin.st_gid != os.getgid() or os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
            raise ValueError("pair-control-ordinary-account")
        root_identity = (root_pin.st_dev & 0xffffffff, root_pin.st_ino, root_pin.st_uid, root_pin.st_gid)
        root_check(); mark("nonce", "request-encode"); nonce = os.urandom(16)
        mark("request-encoding")
        request = b"MRKQPR01" + struct.pack("<HHI", 1, 2, 0) + nonce + struct.pack("<QQII", *root_identity) + b"\0" * 8
        mark("record-format"); record_bytes(request, "request", nonce, root_identity)
        mark("root-held-stat", "request-write"); request_written = write_record("request", request)
        mark("root-held-stat", "request-read"); request_cell, readback = read_record("request", 64)
        mark("readback", "request-readback")
        if sig(request_cell["pin"]) != sig(request_written["pin"]) or readback != request: raise ValueError("pair-request-readback")
        mark("binary-digest", "binary-admission")
        for original in (creator, reader):
            if file_digest(original) != original["sha256"]: raise ValueError("pair-prelaunch-binary-changed")
        # One registered fixed sibling, outside the exact control namespace.
        reader_phase_prepare(phase_original, parent_fd, root_pin, lambda: check_time(launch_end))
        check_time(launch_end)
        mark("worker-create", "worker-prepare")
        argv = [str(creator["path"]), creator_entry]
        worker = threading.Thread(target=creator_worker, args=(holder, lock, abort, argv, control, launch_end, drain_end), daemon=False)
        pair_original["thread"] = worker
        mark("deadline", "launch"); pair["startAttempted"] = True; check_time(launch_end)
        mark("worker-start"); worker.start(); pair["startReturned"] = True
        pair["prelaunch"]["returned"] = True
        for attempt in range(80):
            check_time(ready_end); root_check()
            pair["readyPolls"] = attempt + 1
            try: os.stat("ready", dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                if holder["bodyReturned"]: raise ValueError("pair-creator-ended-before-ready")
                time.sleep(min(0.25, max(0, ready_end - time.monotonic())))
                continue
            ready_cell, ready = read_record("ready", 128)
            record_bytes(ready, "ready", nonce, root_identity)
            file_check(request_cell, "request"); check_time(ready_end)
            pair["readyAdmitted"] = True
            break
        if not pair["readyAdmitted"]: raise ValueError("pair-ready-not-admitted")
        file_check(ready_cell, "ready"); check_time(forward_end)
        if holder["ownerReturned"] or holder["bodyReturned"]: raise ValueError("pair-creator-not-live-at-reader-admission")
        reader_started = time.monotonic()
        timeout = owner_budget(reader_started, forward_end, 15)
        # Main owns this separate synchronous reader; worker never touches it.
        reader_record["timeoutSeconds"] = timeout; reader_record["entered"] = True
        reader_record["ownerCallPhase"] = "calling"
        try:
            reader_original["result"] = owner.run_owned(reader_record["argv"], environ=native_env, cwd=control,
                timeout=timeout, capture=True, text=False, output_limit=256 * 1024)
        except BaseException as error:
            reader_original["error"] = error; reader_record["errorType"] = type(error).__name__
            reader_record["ownerCallPhase"] = "raised"
            # Optional diagnostics must not mask the original owner's bare raise.
            try: reader_record.update(reader_owner_failure_facts(error, owner))
            except BaseException: pass
            try: reader_record["ownerAttemptElapsedSeconds"] = reader_owner_elapsed(reader_started, time.monotonic())
            except BaseException: pass
            raise
        reader_record["returned"] = True; pair["readerOwnerReturned"] = True
        reader_record["ownerCallPhase"] = "returned"
        try: reader_record["ownerAttemptElapsedSeconds"] = reader_owner_elapsed(reader_started, time.monotonic())
        except BaseException: pass
        result = reader_original["result"]
        if (type(result) is not subprocess.CompletedProcess or type(result.returncode) is not int or type(result.stdout) is not bytes
                or type(result.stderr) is not bytes or len(result.stdout) + len(result.stderr) > 256 * 1024):
            raise ValueError("pair-reader-owner-contract")
        reader_record.update(returncode=result.returncode, stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr),
            stdoutSha256=hashlib.sha256(result.stdout).hexdigest(), stderrSha256=hashlib.sha256(result.stderr).hexdigest())
        public_reader = public_reader_report(result)
        publish("wrapping-reader.report.json", (json.dumps(public_reader, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
        admitted_reader = admit_reader_report(result); pair["readerNativeAdmitted"] = True
        for original in (creator, reader):
            if file_digest(original) != original["sha256"]: raise ValueError("pair-prerelease-binary-changed")
        file_check(request_cell, "request"); file_check(ready_cell, "ready"); check_time(forward_end)
        ack = b"MRKQPA01" + struct.pack("<HHI", 1, 2, 0) + nonce + struct.pack("<I", 1) + b"\0" * 12
        record_bytes(ack, "reader-settled", nonce, root_identity)
        staging = write_record("reader-settled.next", ack)
        root_check()
        if sig(os.stat("reader-settled.next", dir_fd=root_fd, follow_symlinks=False)) != sig(staging["pin"]):
            raise ValueError("pair-ack-staging-changed")
        try: os.stat("reader-settled", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise ValueError("pair-ack-collision")
        check_time(forward_end)
        pair["aborted"] = abort.is_set()
        acknowledge_admitted(pair, time.monotonic(), forward_end)
        # Reader original/native/FD/guard finality is established BEFORE entry.
        # Any exception/nonzero return leaves possible-publication latched.
        ctypes.set_errno(0); pair["ackEntered"] = True; pair["ackMayHavePublished"] = True
        rc = exclusive_rename(root_fd, b"reader-settled.next", root_fd, b"reader-settled", 0x00000004)
        actual_errno = ctypes.get_errno(); pair["ackReturned"] = True; pair["ackResult"] = rc; pair["ackErrno"] = actual_errno
        if rc != 0: raise ValueError("pair-ack-publication-uncertain")
        pair["ackPublished"] = True
        ack_cell, readback = read_record("reader-settled", 48)
        if readback != ack or sig(ack_cell["pin"])[:7] != sig(staging["pin"])[:7]: raise ValueError("pair-ack-readback")
        record_bytes(readback, "reader-settled", nonce, root_identity); check_time(forward_end)
    except BaseException as error:
        fail(error)
    finally:
        # Same-original, unconditional join even after start/ready/reader/ack
        # failure. No cross-thread guard calls, PID scan, kill, watchdog or retry.
        if worker is not None and pair["startAttempted"]:
            pair["joinAttempted"] = True
            try:
                worker.join(max(0, drain_end - time.monotonic())); pair["joinReturned"] = True
                pair["joined"] = not worker.is_alive()
                pair["joinedBeforeDrain"] = pair["joined"] and time.monotonic() < drain_end
                if not pair["joinedBeforeDrain"]: raise ValueError("pair-original-join-unconfirmed-or-late")
            except BaseException as error: fail(error)
        if pair["joined"]:
            original_errors.extend(holder["errors"])
            if holder["errors"]:
                with lock: abort.set()
            try:
                if (not all(holder[key] for key in ("bodyEntered", "bodyReturned", "ownerEntered", "ownerReturned", "guardInstalled", "guardActivated", "guardRestored", "guardChecked"))
                        or holder["guardState"] != "RESTORED" or type(holder["result"]) is not subprocess.CompletedProcess):
                    raise ValueError("pair-creator-original-not-settled")
                result = holder["result"]
                if type(result.stdout) is not bytes or type(result.stderr) is not bytes or len(result.stdout) + len(result.stderr) > 256 * 1024:
                    raise ValueError("pair-creator-output-bound")
                report = public_report(result, creator_entry)
                publish("wrapping-creator.report.json", (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
                admit_native_report(result, creator_entry); pair["creatorNativeAdmitted"] = True
            except BaseException as error: fail(error)
        # Read only after this original reader writer is proved settled.
        # Collect failures without replacing its owner exception or calls.
        try:
            for error in reader_phase_collect(phase_original, parent_fd, reader_original, reader_phase_check_time): fail(error)
        except BaseException as error: fail(error)
        pair["readerPhaseRetired"] = phase_original["record"]["retired"]
        try:
            if (not original_errors and not abort.is_set() and pair["joined"] and pair["readerNativeAdmitted"]
                    and pair["creatorNativeAdmitted"] and pair["ackPublished"]):
                for original in (creator, reader):
                    if file_digest(original) != original["sha256"]: raise ValueError("pair-returned-binary-changed")
                root_check()
                if set(os.listdir(root_fd)) != {"request", "ready", "reader-settled"}: raise ValueError("pair-control-final-roster")
                for leaf in ("request", "ready", "reader-settled"): file_check(cells[leaf], leaf)
                for leaf in ("request", "ready", "reader-settled"):
                    file_check(cells[leaf], leaf); cells[leaf]["record"]["removeEntered"] = True
                    os.unlink(leaf, dir_fd=root_fd); cells[leaf]["record"]["removeReturned"] = True
                    cells[leaf]["record"]["removed"] = True
                root_check()
                if os.listdir(root_fd): raise ValueError("pair-control-not-empty")
                pair["rmdirEntered"] = True
                os.rmdir("wrapping-pair-control", dir_fd=parent_fd); pair["rmdirReturned"] = True; pair["controlRetired"] = True
        except BaseException as error: fail(error)
        # Close only caller-owned originals, once. Retain them if worker custody
        # is uncertain. No recursive removal, Keychain cleanup or shared output.
        if worker is None or pair["joined"] or not pair["startAttempted"]:
            for cell in reversed(resources):
                try: close(cell)
                except BaseException as error: fail(error)
        pair["controlOriginalsClosed"] = all(not cell["record"]["openEntered"] or
            cell["record"]["openReturned"] and cell["record"]["acquired"] and cell["record"]["closed"] for cell in resources)
        pair["worker"] = {key: holder[key] for key in ("bodyEntered", "bodyReturned", "ownerEntered", "ownerReturned", "guardInstalled", "guardActivated", "guardRestored", "guardChecked", "guardState")}
        pair["worker"]["timeoutSeconds"] = holder.get("timeoutSeconds")
        # The old retirement/close tail cannot turn late completion into pair success.
        try: reader_phase_check_time()
        except BaseException as error: fail(error)
        pair["aborted"] = abort.is_set()
        pair["errors"] = [type(error).__name__ for error in original_errors]
        pair["passed"] = pair_finality(pair)
        # Retain originals/errors including unknown FD numbers; export no raw
        # controls, fixture names, account IDs, native streams or exception text.
        # pair_original was retained before preparation; no late re-registration.
        publish("wrapping-pair.receipt.json", (json.dumps(pair, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    if not pair["passed"]: raise ValueError("pair-originals-not-complete")

try:
    # Version queries bind actual tools under the checked desktop
    # toolchain selection; no frontend/Tauri/installer/supplier work.
    for role, argv in (
        ("rustc-version", ["/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc", "--version", "--verbose"]),
        ("cargo-version", ["/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo", "--version", "--verbose"]),
        ("sdk-version", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"]),
        ("compiler-version", ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "--version"]),
    ):
        result, row = invoke(role, argv, environ=build_env, cwd=checkout / "desktop", timeout=30, limit=16384)
        if result.returncode != 0 or not result.stdout: raise ValueError("wrapping-tool-binding-refused")
        row["toolOutput"] = result.stdout.decode("ascii", "strict")
    # One app build and one exact15 DATA invocation under the existing
    # owner, before ANY private native profile/fixture is dispatched.
    stage = "codec-target-preparation"
    codec_target = work / "wrapping-codec-target"
    codec_target.mkdir(mode=0o700)
    codec_environment = dict(build_env, CARGO_TARGET_DIR=str(codec_target), RUSTFLAGS="")
    codec_command = ["/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo", "test", "--locked", "--no-default-features", "--jobs", "2",
                     "--target", "aarch64-apple-darwin", "--package", "mobile-release-kit-desktop",
                     "--manifest-path", str(app / "Cargo.toml"), "--lib", "--no-run", "--message-format=json"]
    result, build = invoke("codec-build", codec_command, environ=codec_environment, cwd=app,
                           timeout=600, limit=4 * 1024 * 1024)
    # Preserve the actual bounded compiler return before admission.
    publish("wrapping-codec-build.jsonl", result.stdout)
    publish("wrapping-codec-build.stderr", result.stderr)
    publish("wrapping-codec-build.status", (str(result.returncode) + "\n").encode("ascii"))
    codec_path = admit_codec_compiler(result)
    codec["compilerAdmitted"] = True
    codec_binary = admit_file(codec_path, "codec-binary", executable=True)
    codec.update(artifactSha256=codec_binary["sha256"], artifactBytes=codec_binary["before"].st_size)
    stage = "codec-test-directory-preparation"
    codec_home, codec_tmp = work / "wrapping-codec-home", work / "wrapping-codec-tmp"
    codec_home.mkdir(mode=0o700)
    codec_tmp.mkdir(mode=0o700)
    if file_digest(codec_binary) != codec_binary["sha256"]: raise ValueError("wrapping-codec-pre-test-artifact-changed")
    result, row = invoke("codec-tests", [str(codec_path), "--exact", "--test-threads=1", "--color=never", "--format=pretty", *codec_names],
                         environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(codec_home), "TMPDIR": str(codec_tmp),
                                  "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                         cwd=work, timeout=30, limit=64 * 1024)
    # invoke already retains the real CompletedProcess and its hashes;
    # test stdout/stderr never become a published/raw artifact.
    if file_digest(codec_binary) != codec_binary["sha256"]: raise ValueError("wrapping-codec-returned-artifact-changed")
    codec["artifactHashRechecked"] = True
    stage = "codec-empty-test-directory-retirement"
    codec_home.rmdir()
    codec_tmp.rmdir()  # Empty synthetic directories only; no error-path sweep.
    codec["syntheticDirectoriesRetired"] = True
    stage = "codec-exact-fifteen-result"
    codec.update(admit_codec_results(result))
    qualification_binary, reader_binary, cohort_binary = None, None, None
    for role, features, flags in (("normal", [], ""), ("observer", ["installed-observation"], ""),
                                  ("qualification", ["installed-observation"], "--cfg mrk_wrapping_keychain_qualification")):
        target = work / ("wrapping-" + role + "-target")
        environment = dict(build_env, CARGO_TARGET_DIR=str(target), RUSTFLAGS=flags)
        argv = ["/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo", "test", "--locked", "--no-default-features", "--jobs", "2",
                "--target", "aarch64-apple-darwin", "--package", "mrk-macos-installed-native",
                "--manifest-path", str(native / "Cargo.toml"),
                "--lib", "--no-run", "--message-format=json"]
        if features: argv += ["--features", ",".join(features)]
        result, build = invoke(role + "-build", argv, environ=environment, cwd=native,
                               timeout=600, limit=4 * 1024 * 1024)
        # Actual complete compiler returns only; preserve bounded
        # compiler originals locally, never a live/tail success guess.
        publish("wrapping-" + role + "-build.jsonl", result.stdout)
        publish("wrapping-" + role + "-build.stderr", result.stderr)
        publish("wrapping-" + role + "-build.status", (str(result.returncode) + "\n").encode("ascii"))
        if result.returncode != 0: raise ValueError("wrapping-native-compiler-failed")
        rows = [parse(line) for line in result.stdout.splitlines()]
        if any(type(row) is not dict for row in rows): raise ValueError("wrapping-compiler-json-shape")
        if [row.get("success") for row in rows if row.get("reason") == "build-finished"] != [True]:
            raise ValueError("wrapping-compiler-original-finish")
        artifacts = [row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable") is not None]
        scripts = [row for row in rows if row.get("reason") == "build-script-executed" and row.get("package_id") == package]
        if len(artifacts) != 1 or len(scripts) != 1: raise ValueError("wrapping-fixed-native-build-target")
        artifact = artifacts[0]
        if (artifact.get("package_id") != package or artifact.get("manifest_path") != str(native / "Cargo.toml")
                or artifact.get("features") != features or artifact.get("target", {}).get("name") != library
                or artifact["target"].get("kind") != ["lib"] or artifact["target"].get("crate_types") != ["lib"]
                or artifact["target"].get("src_path") != str(native / "src/lib.rs")
                or artifact.get("profile", {}).get("test") is not True
                or artifact["profile"].get("debug_assertions") is not True):
            raise ValueError("wrapping-native-feature-profile-binding")
        binary = pathlib.Path(artifact["executable"])
        out = pathlib.Path(scripts[0]["out_dir"])
        if (binary.parent != target / "aarch64-apple-darwin/debug/deps"
                or re.fullmatch(library + r"-[0-9a-f]+", binary.name) is None
                or out.name != "out" or out.parent.parent != target / "aarch64-apple-darwin/debug/build"
                or re.fullmatch(r"mrk-macos-installed-native-[0-9a-f]+", out.parent.name) is None):
            raise ValueError("wrapping-native-artifact-location")
        if role == "qualification":
            # Finish both builds before signing/admitting final original FDs.
            # Cargo may refresh its one native archive during this example build.
            reader_argv = ["/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo", "build", "--locked", "--no-default-features", "--jobs", "2",
                "--target", "aarch64-apple-darwin", "--package", "mrk-macos-installed-native",
                "--manifest-path", str(native / "Cargo.toml"), "--example", "wrapping_peer_reader", "--example", "wrapping_private_cohort",
                "--features", "installed-observation", "--message-format=json"]
            result, reader_build = invoke("reader-build", reader_argv, environ=environment, cwd=native, timeout=600, limit=4 * 1024 * 1024)
            publish("wrapping-reader-build.jsonl", result.stdout); publish("wrapping-reader-build.stderr", result.stderr)
            publish("wrapping-reader-build.status", (str(result.returncode) + "\n").encode("ascii"))
            if result.returncode != 0: raise ValueError("pair-reader-compiler-failed")
            reader_rows = [parse(line) for line in result.stdout.splitlines()]
            if any(type(row) is not dict for row in reader_rows) or [row.get("success") for row in reader_rows if row.get("reason") == "build-finished"] != [True]:
                raise ValueError("pair-reader-build-original-finish")
            reader_artifacts = [row for row in reader_rows if row.get("reason") == "compiler-artifact" and row.get("executable") is not None]
            if len(reader_artifacts) != 2: raise ValueError("pair-two-fixed-helper-build-targets")
            helper_artifacts = {}
            for helper in reader_artifacts:
                helper_name = helper.get("target", {}).get("name")
                if (helper_name not in ("wrapping_peer_reader", "wrapping_private_cohort") or helper_name in helper_artifacts
                        or helper.get("package_id") != package or helper.get("manifest_path") != str(native / "Cargo.toml")
                        or helper.get("features") != ["installed-observation"]
                        or helper["target"].get("kind") != ["example"] or helper["target"].get("crate_types") != ["bin"]
                        or helper["target"].get("src_path") != str(native / ("examples/" + helper_name + ".rs"))
                        or helper.get("profile", {}).get("test") is not False or helper["profile"].get("debug_assertions") is not True
                        or pathlib.Path(helper["executable"]) != target / ("aarch64-apple-darwin/debug/examples/" + helper_name)):
                    raise ValueError("pair-helper-source-profile-binding")
                helper_artifacts[helper_name] = helper
            reader_artifact = helper_artifacts["wrapping_peer_reader"]
            cohort_artifact = helper_artifacts["wrapping_private_cohort"]
            reader_path = copy_reader_compiler_original(pathlib.Path(reader_artifact["executable"]))
            cohort_path = copy_reader_compiler_original(pathlib.Path(cohort_artifact["executable"]), "cohort")
            identities = []
            for code_role, path, identifier in (("creator", cohort_path, creator_identifier), ("reader", reader_path, reader_identifier)):
                st = path.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid() or st.st_mode & 0o022 or not st.st_mode & 0o111:
                    raise ValueError("pair-only-task-code-signing")
                result, row = invoke(code_role + "-adhoc-sign", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", identifier, str(path)],
                    environ=native_env, cwd=work, timeout=30, limit=16384)
                if result.returncode != 0: raise ValueError("pair-adhoc-signing-failed")
                result, row = invoke(code_role + "-signature-verify", ["/usr/bin/codesign", "--verify", "--strict", str(path)],
                    environ=native_env, cwd=work, timeout=30, limit=16384)
                if result.returncode != 0: raise ValueError("pair-code-verification-failed")
                result, row = invoke(code_role + "-signature-display", ["/usr/bin/codesign", "--display", "--verbose=4", "-r-", str(path)],
                    environ=native_env, cwd=work, timeout=30, limit=16384)
                identity_facts = {}
                row["identityAdmission"] = identity_facts
                identities.append(signature_identity(result, identifier, identity_facts))
            receipt["codeIdentities"] = identities
        cells = [admit_file(out / "libmrk_macos_installed_native.a", role + "-archive"),
                 admit_file(binary, role + "-binary", executable=True)]
        variant = {"role": role, "features": features, "rustFlags": flags, "profile": artifact["profile"],
                   "compilerCall": build["role"], "artifacts": [], "fixtureSymbols": [], "listAdmitted": False}
        receipt["variants"].append(variant)
        for cell in cells:
            if file_digest(cell) != cell["sha256"]: raise ValueError("wrapping-pre-symbol-artifact-changed")
            result, row = invoke(cell["role"] + "-symbols", ["/usr/bin/nm", "-gU", str(cell["path"])],
                                 environ=native_env, cwd=work, timeout=30, limit=2 * 1024 * 1024)
            if result.returncode != 0 or result.stderr: raise ValueError("wrapping-native-symbol-original")
            symbols = {line.split()[-1] for line in result.stdout.decode("ascii", "strict").splitlines() if line.split()}
            observed = symbols & fixture_symbols
            if ((role != "qualification" and observed) or
                    (cell["role"] == "qualification-archive" and observed != fixture_symbols)):
                raise ValueError("wrapping-native-cfg-exclusion")
            # Constant refusal is defined only by qualification libtest. The
            # native archive/ordinary profiles still cannot supply an active role.
            if ("_mrk_wrapping_private_process_role" in symbols) != (cell["role"] == "qualification-binary"):
                raise ValueError("wrapping-libtest-role-definition-profile")
            # Get/Set must be absent from ordinary/observer link inputs.
            result, imports_row = invoke(cell["role"] + "-policy-imports", ["/usr/bin/nm", "-u", str(cell["path"])],
                environ=native_env, cwd=work, timeout=30, limit=2 * 1024 * 1024)
            if result.returncode != 0 or result.stderr: raise ValueError("wrapping-policy-import-original")
            imported = {line.split()[-1] for line in result.stdout.decode("ascii", "strict").splitlines() if line.split()}
            policy_imports = {"_SecKeychainGetUserInteractionAllowed", "_SecKeychainSetUserInteractionAllowed"}
            if ((role != "qualification" and imported & policy_imports)
                    or (cell["role"] == "qualification-archive" and not policy_imports <= imported)):
                raise ValueError("wrapping-policy-import-profile")
            observed_phase = symbols & reader_phase_symbols
            # Reader-only functions may be dead-stripped from the qualification test binary.
            # They must exist in its native archive and never in ordinary profiles.
            if ((role != "qualification" and observed_phase)
                    or (cell["role"] == "qualification-archive" and observed_phase != reader_phase_symbols)):
                raise ValueError("pair-reader-phase-symbol-profile")
            if file_digest(cell) != cell["sha256"]: raise ValueError("wrapping-post-symbol-artifact-changed")
            variant["fixtureSymbols"].append(sorted(observed))
            variant["artifacts"].append({"role": cell["role"], "path": str(cell["path"].relative_to(work)),
                                         "sha256": cell["sha256"], "identity": sig(cell["before"])})
        result, row = invoke(role + "-list", [str(binary), "--list", "--format=terse"],
                             environ=native_env, cwd=work, timeout=30, limit=256 * 1024)
        if result.returncode != 0 or result.stderr: raise ValueError("wrapping-list-original-return")
        lines = result.stdout.decode("ascii", "strict").splitlines()
        private = [line for line in lines if "wrapping_keychain::private_fixture::" in line]
        if private:
            raise ValueError("wrapping-rust-cfg-exclusion")
        if any(file_digest(cell) != cell["sha256"] for cell in cells): raise ValueError("wrapping-list-artifact-changed")
        variant["listAdmitted"] = True
        if role == "normal":
            # One exact DATA invocation reuses the already-built,
            # admitted ordinary libtest. It has no process activation
            # symbol or provider path; listing alone is not a test.
            stage = "normal-policy-data-directory-preparation"
            policy_home, policy_tmp = work / "wrapping-policy-home", work / "wrapping-policy-tmp"
            policy_home.mkdir(mode=0o700)
            policy_tmp.mkdir(mode=0o700)
            policy = receipt["policyData"]
            policy.update(artifactSha256=cells[1]["sha256"], artifactBytes=cells[1]["before"].st_size)
            if file_digest(cells[1]) != cells[1]["sha256"]: raise ValueError("wrapping-policy-pre-test-artifact-changed")
            result, row = invoke("normal-policy-tests", [str(binary), "--exact", "--test-threads=1", "--color=never", "--format=pretty", *policy_names],
                environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(policy_home), "TMPDIR": str(policy_tmp),
                         "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                cwd=work, timeout=30, limit=64 * 1024)
            if file_digest(cells[1]) != cells[1]["sha256"]: raise ValueError("wrapping-policy-returned-artifact-changed")
            policy["artifactHashRechecked"] = True
            stage = "normal-policy-empty-directory-retirement"
            policy_home.rmdir()
            policy_tmp.rmdir()  # Never sweep unknown/nonempty DATA outputs.
            policy["syntheticDirectoriesRetired"] = True
            stage = "normal-policy-exact-four-result"
            policy.update(admit_policy_results(result))
        if role == "qualification":
            stage = "qualification-role-data-directory-preparation"
            role_home, role_tmp = work / "wrapping-role-home", work / "wrapping-role-tmp"
            role_home.mkdir(mode=0o700)
            role_tmp.mkdir(mode=0o700)
            refusal = receipt["libtestRoleData"]
            if file_digest(cells[1]) != cells[1]["sha256"]: raise ValueError("wrapping-role-pre-test-artifact-changed")
            result, row = invoke("qualification-role-tests", [str(binary), "--exact", "--test-threads=1", "--color=never", "--format=pretty", *role_names],
                environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(role_home), "TMPDIR": str(role_tmp),
                         "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                cwd=work, timeout=30, limit=64 * 1024)
            if file_digest(cells[1]) != cells[1]["sha256"]: raise ValueError("wrapping-role-returned-artifact-changed")
            refusal["artifactHashRechecked"] = True
            stage = "qualification-role-empty-directory-retirement"
            role_home.rmdir()
            role_tmp.rmdir()
            refusal["syntheticDirectoriesRetired"] = True
            stage = "qualification-role-exact-one-result"
            refusal.update(admit_fixed_data_results(result, role_names, 1))
            qualification_binary = cells[1]
            reader_binary = admit_file(reader_path, "reader-binary", executable=True)
            cohort_binary = admit_file(cohort_path, "cohort-binary", executable=True)
            for helper_cell, required in ((reader_binary, pair_symbols | reader_phase_symbols), (cohort_binary, fixture_symbols)):
                result, row = invoke(helper_cell["role"] + "-symbols", ["/usr/bin/nm", "-gU", str(helper_cell["path"])],
                    environ=native_env, cwd=work, timeout=30, limit=2 * 1024 * 1024)
                if result.returncode != 0 or result.stderr: raise ValueError("pair-helper-symbol-original")
                symbols = {line.split()[-1] for line in result.stdout.decode("ascii", "strict").splitlines() if line.split()}
                if not (required | {"_mrk_wrapping_private_process_role"}) <= symbols or file_digest(helper_cell) != helper_cell["sha256"]:
                    raise ValueError("pair-helper-private-symbol-binding")
            identities = [sig(cell["before"])[:2] for cell in (qualification_binary, reader_binary, cohort_binary)]
            if len(set(identities)) != 3: raise ValueError("pair-distinct-file-originals")
            for identity, cell in zip(receipt["codeIdentities"], (cohort_binary, reader_binary)):
                identity["fileSha256"] = cell["sha256"]
            distinct_code_identities(*receipt["codeIdentities"])
            receipt["readerArtifact"] = {"sha256": reader_binary["sha256"], "identity": sig(reader_binary["before"]), "profile": reader_artifact["profile"], "pairSymbols": sorted(pair_symbols), "readerPhaseSymbols": sorted(reader_phase_symbols)}
            receipt["cohortArtifact"] = {"sha256": cohort_binary["sha256"], "identity": sig(cohort_binary["before"]), "profile": cohort_artifact["profile"], "fixtureSymbols": sorted(fixture_symbols)}
    if qualification_binary is None or reader_binary is None or cohort_binary is None or len(receipt["variants"]) != 3: raise ValueError("wrapping-no-admitted-binary")
    # Exactly three predeclared originals share ONE compiled binary.
    # Each entry starts its own original45s cutoff; each90s enclosure
    # belongs to that entry. Never reset/reuse a stopped Harness.
    # Any refused/unknown original stops dispatch; no automatic retry.
    for cohort in receipt["nativeCohorts"]:
        entry = cohort["entry"]
        if file_digest(cohort_binary) != cohort_binary["sha256"]: raise ValueError("wrapping-cohort-original-changed")
        cohort["entered"] = True
        result, row = invoke(cohort["reportPrefix"], [str(cohort_binary["path"]), entry],
                             environ=native_env, cwd=work, timeout=90, limit=256 * 1024)
        cohort["returned"] = True
        report = public_report(result, entry)
        publish(cohort["reportPrefix"] + ".report.json", (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
        cohort["publicReportPreserved"] = True  # Partial is never pass.
        admit_native_report(result, entry)
        if file_digest(cohort_binary) != cohort_binary["sha256"]: raise ValueError("wrapping-returned-original-changed")
        cohort["reportAdmitted"] = True
    receipt["nativeOriginalReturned"] = all(row["returned"] for row in receipt["nativeCohorts"])
    receipt["nativeReportAdmitted"] = all(row["reportAdmitted"] for row in receipt["nativeCohorts"])
    stage = "wrapping-creator-reader"
    run_creator_reader(cohort_binary, reader_binary)
    # This is only the reviewed PRIVATE process-noninteraction scope, not a
    # per-query, global-window or shipping claim. Both originals are now settled.
    receipt["pairNativeObservationsAdmitted"] = True
except BaseException as error:
    errors.append(error)  # Retain the real error, never serialize its private text.
    receipt["failure"] = {"stage": stage, "type": type(error).__name__}
finally:
    close_errors = []
    for cell in files:
        if cell["role"] == "codec-binary" and not codec_original_settled(receipt["calls"]):
            close_errors.append({"role": cell["role"], "retainedForUnsettledCodecOriginal": True})
            continue
        if cell["role"] == "normal-binary" and not policy_original_settled(receipt["calls"]):
            close_errors.append({"role": cell["role"], "retainedForUnsettledPolicyOriginal": True})
            continue
        if cell["role"] == "qualification-binary" and not fixed_test_original_settled(receipt["calls"], "qualification-role-tests"):
            close_errors.append({"role": cell["role"], "retainedForUnsettledRoleOriginal": True})
            continue
        if receipt.get("pair", {}).get("startAttempted") and not receipt["pair"]["joined"]:
            close_errors.append({"role": cell["role"], "retainedForUnjoinedOriginal": True})
            continue
        descriptor, cell["fd"] = cell["fd"], None
        try:
            # Fresh held/named admission and digest before the one
            # consuming close, never a historical-directory equality.
            cell["fd"] = descriptor
            cell["unchanged"] = file_digest(cell) == cell["sha256"]
            if not cell["unchanged"]: raise ValueError("wrapping-consuming-artifact-changed")
        except BaseException as error:
            errors.append(error)
            close_errors.append({"role": cell["role"], "admission": False, "type": type(error).__name__})
        finally:
            cell["fd"] = None
        try:
            os.close(descriptor)  # Spend once; failed/unknown close is never retried.
            cell["closed"] = True
        except BaseException as error:
            errors.append(error)
            close_errors.append({"role": cell["role"], "close": False, "type": type(error).__name__})
    receipt["artifactOriginals"] = [{"role": cell["role"], "unchanged": cell["unchanged"], "closed": cell["closed"]} for cell in files]
    receipt["closeErrors"] = close_errors
    receipt["expectedArtifactRoles"] = artifact_roles
    receipt["passed"] = private_batch_finality(receipt, codec, files, errors, close_errors)
    receipt["perQueryUIFailQualified"] = False
    receipt["processNonInteractionQualified"] = receipt["passed"]
    # NO fixture path admission/deletion from Python, even on timeout,
    # failed SDK call, parser refusal, close failure or process exit.
    publish("wrapping-native.receipt.json", (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    codec_public = public_codec_receipt(receipt, codec, files, errors, close_errors)
    codec_data = (json.dumps(codec_public, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(codec_data) > 16384: raise ValueError("wrapping-codec-closed-receipt-bound")
    publish("wrapping-codec.receipt.json", codec_data)
if not receipt["passed"]: raise SystemExit("private wrapping cohort incomplete; originals retained")
PY_WRAPPING
