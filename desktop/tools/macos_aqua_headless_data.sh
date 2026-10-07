set -euo pipefail
set -o noclobber
umask 077
# Cargo must see desktop/rust-toolchain.toml, not the host default.
cd desktop/src-tauri
# Existing unrelated scopes retain their compiler graph. The fixed
# shipping DATA/control graph uses the same original compiler owner
# as Android lifecycle; no raw test execution or helper-role union.
if [[ "$MRK_MACOS_AQUA_SCOPE" != android-registration-lifecycle && "$MRK_MACOS_AQUA_SCOPE" != vault-helper-shipping && "$MRK_MACOS_AQUA_SCOPE" != vault-helper-shipping-installation-inspection ]]; then
  set +e
  # The same locked graph builds both existing native DATA regressions.
  PATH="/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/rustc" RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup "/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" test --locked --no-default-features --jobs 2 --target "$MRK_MACOS_TARGET" \
    --package mobile-release-kit-desktop --package mrk-macos-installed-native \
    --lib --no-run --message-format=json \
    > "$MRK_MACOS_WORK/headless-build.jsonl" 2> "$MRK_MACOS_WORK/headless-build.stderr"
  status=$?
  set -e
  printf '%s\n' "$status" > "$MRK_MACOS_WORK/headless-build.status"
  [[ $status == 0 ]] || exit "$status"
fi
"$MRK_PYTHON" -I -S -B - <<'PY_HEADLESS'
import hashlib, importlib.util, json, os, pathlib, re, shutil, stat, subprocess, sys, time
build_target = os.environ["MRK_MACOS_TARGET"]
if build_target not in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
    raise ValueError("headless-fixed-build-target")
rust_bin = "/Users/runner/.rustup/toolchains/stable-" + build_target + "/bin"
work = pathlib.Path(os.environ["MRK_MACOS_WORK"])
checkout = pathlib.Path(os.environ["GITHUB_WORKSPACE"])
android_lifecycle = os.environ["MRK_MACOS_AQUA_SCOPE"] == "android-registration-lifecycle"
shipping_gate = os.environ["MRK_MACOS_AQUA_SCOPE"] in ("vault-helper-shipping", "vault-helper-shipping-installation-inspection")
owned_headless = android_lifecycle or shipping_gate
catalogue_gate = os.environ["MRK_MACOS_AQUA_SCOPE"] == "project-fields"
# BEGIN_CATALOGUE_HEADLESS_CONTROL
CATALOGUE_ROUNDTRIP_TEST = "android_supplier_macos::tests::compiled_six_component_catalogue_roundtrips_and_rejects_mismatches"
CATALOGUE_BUDGET_TEST = "saved_command_owner::android_registration::catalogue_budget_tests::genuine_catalogue_fits_fresh_inspect_retained_review_and_register"
CATALOGUE_DOCUMENT_KEYS = ("document_cells", "saved_fields", "records", "assignments",
    "context", "slot_projection", "picker_originals", "other_registries")
CATALOGUE_COMMON_KEYS = ("document", "owner_cells", "runtime_heap", "sources_heap",
    "catalog_heap", "service_heap", "dispatcher", "observation_identity")
CATALOGUE_SOURCE_KEYS = ("inspection", "proposal_work", "reproof", "reproof_work",
    "old_source", "old_operation", "source_review", "proposal_heap", "old_review",
    "source_task", "coordinator", "inspection_tasks")
CATALOGUE_REGISTER_KEYS = ("client", "preparation", "settled", "phase", "tasks", "task_reserved")
CATALOGUE_CASE_KEYS = ("previous", "control_slot", "checked", "retained_review",
    "phase", "new_owner", "final_tasks", "total", "limit", "headroom", "over")
CATALOGUE_CASE_NAMES = ("fresh_inspect", "inspect_retained_review", "register_retained_review")
CATALOGUE_U64 = (1 << 64) - 1

def catalogue_u64_sum(*values):
    total = 0
    for value in values:
        if type(value) is not int or not 0 <= value <= CATALOGUE_U64 or total > CATALOGUE_U64 - value:
            raise ValueError("headless-catalogue-u64-sum")
        total += value
    return total

def parse_catalogue_budget(raw):
    # Exactly67 canonical usize64 tokens, seven LF rows, at most2405B.
    # A panic trailer remains raw failure evidence, never a good-prefix parse.
    if type(raw) is not bytes or not 0 < len(raw) <= 2405 or not raw.endswith(b"\n"):
        raise ValueError("headless-catalogue-closed-output-bound")
    lines = raw[:-1].decode("ascii", "strict").split("\n")
    if len(lines) != 7:
        raise ValueError("headless-catalogue-seven-rows")
    number = r"(0|[1-9][0-9]{0,19})"
    def matched(pattern, line, keys):
        match = re.fullmatch(pattern, line)
        if match is None or len(match.groups()) != len(keys):
            raise ValueError("headless-catalogue-closed-row")
        values = [catalogue_u64_sum(int(value)) for value in match.groups()]
        return dict(zip(keys, values))
    document_pattern = re.escape("catalogue_budget document_rows=[") + ", ".join(
        re.escape('("' + key + '", ') + number + re.escape(")") for key in CATALOGUE_DOCUMENT_KEYS) + re.escape("]")
    document = matched(document_pattern, lines[0], CATALOGUE_DOCUMENT_KEYS)
    def fields(line, prefix, keys):
        return matched(re.escape(prefix) + " ".join(re.escape(key) + "=" + number for key in keys), line, keys)
    return {"schemaVersion": 1, "documentRows": document,
        "common": fields(lines[1], "catalogue_budget common ", CATALOGUE_COMMON_KEYS),
        "source": fields(lines[2], "catalogue_budget source ", CATALOGUE_SOURCE_KEYS),
        "register": fields(lines[3], "catalogue_budget register ", CATALOGUE_REGISTER_KEYS),
        "cases": [{"name": name, **fields(line, "catalogue_budget case=" + name + " ", CATALOGUE_CASE_KEYS)}
                  for name, line in zip(CATALOGUE_CASE_NAMES, lines[4:])]}

def check_catalogue_budget(value):
    document, common = value["documentRows"], value["common"]
    source, register = value["source"], value["register"]
    fresh, inspect, registration = value["cases"]
    if (common["document"] != catalogue_u64_sum(*document.values())
            or any(document[key] <= 0 for key in CATALOGUE_DOCUMENT_KEYS[:7])):
        raise ValueError("headless-catalogue-document-census")
    previous_common = catalogue_u64_sum(*common.values())
    for case in value["cases"]:
        if (case["previous"] != catalogue_u64_sum(previous_common, case["control_slot"], case["checked"], case["retained_review"])
                or case["total"] != catalogue_u64_sum(case["previous"], case["new_owner"], case["phase"], case["final_tasks"])
                or case["limit"] != 64 * 1024 * 1024):
            raise ValueError("headless-catalogue-case-arithmetic")
        headroom = case["limit"] - case["total"] if case["total"] <= case["limit"] else 0
        over = case["total"] - case["limit"] if case["total"] >= case["limit"] else 0
        if case["headroom"] != headroom or case["over"] != over:
            raise ValueError("headless-catalogue-headroom")
    inspection = catalogue_u64_sum(source["inspection"], source["proposal_work"])
    reproof = catalogue_u64_sum(source["reproof"], source["reproof_work"])
    if (fresh["retained_review"] != 0
            or inspect["retained_review"] != source["old_review"]
            or registration["retained_review"] != source["old_review"]
            or any(fresh[key] != inspect[key] for key in ("checked", "new_owner", "phase", "final_tasks"))
            or inspect["control_slot"] != registration["control_slot"]
            or fresh["phase"] != inspection
            or source["inspection"] != source["reproof"]
            or catalogue_u64_sum(source["old_source"], source["source_review"]) > inspection):
        raise ValueError("headless-catalogue-inspection-overlap")
    phase = catalogue_u64_sum(max(catalogue_u64_sum(reproof, register["settled"]), register["preparation"]), register["client"])
    if (register["phase"] != phase or registration["phase"] != phase
            or fresh["final_tasks"] != source["inspection_tasks"]
            or registration["final_tasks"] != 0 or register["tasks"] > register["task_reserved"]):
        raise ValueError("headless-catalogue-register-phase")
    if any(case["total"] > case["limit"] or case["over"] != 0 for case in value["cases"]):
        raise ValueError("headless-catalogue-unchanged-whole-owner-cap")

def exact_headless_result(stdout, returncode, test_names):
    if (type(test_names) is not tuple or len(test_names) not in (1, 26)
            or any(type(name) is not str for name in test_names)):
        raise ValueError("headless-catalogue-fixed-invocation-count")
    if type(stdout) is not bytes or type(returncode) is not int or returncode != 0:
        raise ValueError("headless-tests-returned-failure")
    count = len(test_names)
    lines = [line for line in stdout.decode("utf-8", "strict").splitlines() if line]
    expected_rows = {"test " + name + " ... ok" for name in test_names}
    heading = f"running {count} " + ("test" if count == 1 else "tests")
    if (len(expected_rows) != count or len(lines) != count + 2 or lines[0] != heading
            or len(set(lines[1:-1])) != count or set(lines[1:-1]) != expected_rows):
        raise ValueError("headless-exact-named-results-required")
    summary = re.fullmatch(rf"test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; ([0-9]+) filtered out; finished in [0-9]+\.[0-9]+s", lines[-1])
    if summary is None:
        raise ValueError("headless-exact-test-summary")
    return int(summary[1])

def run_catalogue_batch(owner, binary, test_names, count, prefix, record, original,
                        original_digest, digest, home, tmp, *, clock=None):
    # Existing original owner/FD only. Tests may supply inert callables/clock;
    # the sole live callsite supplies the admitted owner and its actual FD.
    global calls_entered, calls_returned, stage
    if clock is None:
        clock = time.monotonic_ns
    invocations = [
        {"names": test_names[:-1], "outputPrefix": prefix, "libtestCapture": True,
         "originalReturned": False, "testsPassed": False},
        {"names": (CATALOGUE_BUDGET_TEST,), "outputPrefix": prefix + "-catalogue", "libtestCapture": False,
         "originalReturned": False, "testsPassed": False},
    ]
    record.update(invocations=invocations, ownerCallsEntered=0, ownerCallsReturned=0,
        batchOutputBytes=0, finalElapsedNanoseconds=None, deadlineMetAfterFinalCloses=False,
        homeOriginalRetired=False, tmpOriginalRetired=False, artifactCloseAttempts=0,
        headlessCustodyRetained=False)
    batch_errors, start, end, last_clock, clock_unconfirmed = [], None, None, None, False
    def observe_clock():
        nonlocal last_clock, clock_unconfirmed
        try:
            now = clock()
            if type(now) is not int or now < 0 or last_clock is not None and now < last_clock:
                raise ValueError("headless-catalogue-original-clock")
            last_clock = now
            return now
        except BaseException:
            clock_unconfirmed = True
            raise
    def timely(now):
        if end is None or now >= end:
            raise ValueError("headless-catalogue-original-deadline")
    try:
        stage = prefix + "-catalogue-batch-admission"
        if (prefix != "headless" or count != 27 or type(test_names) is not tuple or len(test_names) != 27
                or test_names[-2:] != (CATALOGUE_ROUNDTRIP_TEST, CATALOGUE_BUDGET_TEST)
                or any(type(name) is not str for name in test_names) or len(set(test_names)) != 27
                or record["role"] != "main" or record["names"] != test_names
                or original["record"] is not record or type(original["fd"]) is not int
                or calls_entered != 0 or calls_returned != 0):
            raise ValueError("headless-catalogue-fixed-main-batch")
        if original_digest() != digest:
            raise ValueError("headless-original-artifact-hash")
        # One origin: neither the second call nor cleanup can renew it.
        start = observe_clock()
        end = start + 30_000_000_000
        remaining = 64 * 1024
        for index, invocation in enumerate(invocations):
            if index:
                timely(observe_clock())
                if original_digest() != digest:
                    raise ValueError("headless-original-artifact-hash")
            now = start if index == 0 else observe_clock()
            timely(now)
            timeout = min(30, (end - now) // 1_000_000_000)
            if not 1 <= timeout <= 30 or not 0 < remaining <= 64 * 1024:
                raise ValueError("headless-catalogue-remaining-allowance")
            argv = [str(binary), "--exact", "--test-threads=1", "--color=never", "--format=pretty"]
            if not invocation["libtestCapture"]:
                argv.append("--nocapture")
            argv.extend(invocation["names"])
            expected_argv = tuple(argv)
            invocation.update(timeoutSeconds=timeout, outputLimitBytes=remaining)
            stage = invocation["outputPrefix"] + "-original-test-invocation"
            calls_entered += 1
            record["ownerCallsEntered"] += 1
            result = owner.run_owned(argv,
                environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "TMPDIR": str(tmp),
                         "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                cwd=work, timeout=timeout, capture=True, text=False, output_limit=remaining)
            if (type(result) is not subprocess.CompletedProcess or type(result.returncode) is not int
                    or type(result.args) is not list or any(type(arg) is not str for arg in result.args)
                    or result.args != list(expected_argv) or argv != list(expected_argv)
                    or type(result.stdout) is not bytes or type(result.stderr) is not bytes
                    or len(result.stdout) + len(result.stderr) > remaining):
                raise ValueError("headless-original-return-contract")
            calls_returned += 1
            record["ownerCallsReturned"] += 1
            charged = len(result.stdout) + len(result.stderr)
            remaining -= charged
            record["batchOutputBytes"] += charged
            invocation.update(originalReturned=True, returncode=result.returncode,
                stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr),
                stdoutSha256=hashlib.sha256(result.stdout).hexdigest(),
                stderrSha256=hashlib.sha256(result.stderr).hexdigest())
            record["originalReturned"] = all(row["originalReturned"] for row in invocations)
            # Preserve THIS actual return, not a synthetic merged result.
            publish(invocation["outputPrefix"] + "-tests.stdout", result.stdout)
            publish(invocation["outputPrefix"] + "-tests.stderr", result.stderr)
            publish(invocation["outputPrefix"] + "-tests.status", (str(result.returncode) + "\n").encode("ascii"))
            if original_digest() != digest:
                raise ValueError("headless-original-artifact-hash")
            timely(observe_clock())
            stage = invocation["outputPrefix"] + "-exact-test-result"
            if invocation["libtestCapture"]:
                if result.stderr:
                    raise ValueError("headless-tests-returned-failure")
                filtered = exact_headless_result(result.stdout, result.returncode, invocation["names"])
            else:
                # Retain all three typed totals before any cap pass decision.
                stage = invocation["outputPrefix"] + "-closed-numeric-output"
                invocation["catalogueBudget"] = parse_catalogue_budget(result.stderr)
                filtered = exact_headless_result(result.stdout, result.returncode, invocation["names"])
                check_catalogue_budget(invocation["catalogueBudget"])
            timely(observe_clock())
            invocation.update(testsPassed=True, tests=len(invocation["names"]),
                failed=0, ignored=0, measured=0, filtered=filtered)
        record["artifactOriginalUnchanged"] = True
        stage = prefix + "-catalogue-batch-finality"
    finally:
        if record["ownerCallsEntered"] == record["ownerCallsReturned"]:
            # Independent known cleanup still runs after a nonzero/late/malformed
            # test result. Unknown owner return cannot authorize even one close.
            try:
                if original_digest() != digest:
                    raise ValueError("headless-original-artifact-hash")
            except BaseException as error:
                record["artifactOriginalUnchanged"] = False
                batch_errors.append({"stage": "main-final-artifact-hash", "type": type(error).__name__})
            for field, directory in (("homeOriginalRetired", home), ("tmpOriginalRetired", tmp)):
                try:
                    directory.rmdir()
                    record[field] = True
                except BaseException as error:
                    batch_errors.append({"stage": field, "type": type(error).__name__})
            descriptor, original["fd"] = original["fd"], None
            record["artifactCloseAttempts"] += 1
            try:
                os.close(descriptor)  # One consuming attempt; outer finally skips None.
                record["artifactOriginalClosed"] = True
            except BaseException as error:
                batch_errors.append({"stage": "main-original-close", "type": type(error).__name__})
            if end is not None:
                try:
                    final = observe_clock()
                    record["finalElapsedNanoseconds"] = str(final - start)
                    timely(final)
                    record["deadlineMetAfterFinalCloses"] = (not clock_unconfirmed
                        and record["artifactOriginalClosed"] and record["homeOriginalRetired"] and record["tmpOriginalRetired"])
                except BaseException as error:
                    batch_errors.append({"stage": "main-after-final-closes-clock", "type": type(error).__name__})
        else:
            record["headlessCustodyRetained"] = True
        if batch_errors:
            record["cleanupErrors"] = batch_errors
    if (batch_errors or record["ownerCallsEntered"] != 2 or record["ownerCallsReturned"] != 2
            or not record["originalReturned"] or not record["artifactOriginalUnchanged"]
            or not record["artifactOriginalClosed"] or record["artifactCloseAttempts"] != 1
            or not record["deadlineMetAfterFinalCloses"] or record["headlessCustodyRetained"]
            or not all(row["testsPassed"] for row in invocations)):
        raise ValueError("headless-catalogue-main-finality-unconfirmed")
    record.update(testsPassed=True, tests=27, failed=0, ignored=0, measured=0)
# END_CATALOGUE_HEADLESS_CONTROL
names = (
    "asset_source::macos::tests::private_asset_suffixes_admit_android_without_broadening_apple_formats",
    "asset_source::macos::tests::root_aliases_are_exact_and_physical_protection_is_not_path_text",
    "asset_source::macos::tests::entered_native_checks_remain_uncertain_after_descriptor_book_retirement",
    "asset_source::macos::tests::protected_objects_are_recognized_even_from_another_firmlink_parent_role",
    "asset_source::macos::tests::complete_alias_rosters_are_bounded_before_any_native_acquisition",
    "asset_source::macos::tests::project_fields_are_strict_descendant_data_not_credential_capture",
    "asset_source::macos::tests::project_spellings_are_bounded_without_canonicalization",
    "asset_source::macos::tests::only_local_ownership_aware_apfs_is_admitted",
    "ios_toolchain::tests::fixed_alias_is_only_one_sibling_not_a_path_traversal_or_second_lookup",
    "asset_session::tests::macos_input_context_matrix_keeps_platform_kinds_and_ios_signing_separate",
    "asset_session::tests::macos_cached_record_preview_publication_and_old_context_cannot_bypass_kind_gate",
    "asset_session::vault::tests::explicit_vault_loans_supply_two_signing_inputs_and_preserve_actual_borrowed_backing_on_lock",
    "asset_session::vault::tests::bound_loan_publication_refuses_changed_lineage_or_unsettled_original_without_taking_payload",
    "asset_session::vault::tests::loan_currentness_rejects_equal_counter_replacement_new_context_registry_and_reassignment",
    "asset_session::vault::tests::reassigned_loan_census_is_not_refunded_before_off_lock_retirement_and_restore_preserves_it",
    "asset_session::vault::tests::schema_three_advertises_storage_modes_without_opening_or_probing_a_vault",
    "asset_session::vault::tests::encrypted_projection_redacts_locked_read_only_and_mutating_authority",
    "runtime::persistence_selection_keeps_original_document_and_fixed_helper_pin_bounds",
    "asset_session::vault::tests::boxed_loan_cells_are_charged_once_each_while_arc_backing_deduplicates",
    "asset_session::vault::tests::prospective_loan_pointee_preserves_resident_boundary_and_checked_overlap",
    "asset_session::vault::tests::refused_new_or_replacement_loan_keeps_loaded_and_original_box_unchanged",
    "asset_session::images::persistent_memory::tests::image_fixed_partition_boundary_overflow_and_incomplete_heap_refuse",
    "asset_session::images::persistent_memory::tests::image_identity_set_keeps_distinct_allocations_and_refuses_the_148th",
    "asset_session::images::persistent_memory::tests::image_record_assignment_payload_and_context_capacities_share_one_census",
    "asset_session::images::persistent_memory::tests::image_stored_heap_charges_spare_capacity_not_its_inline_cell_twice",
)
native_names = (
    "tests::bulk_directory_records_preserve_full_ids_and_refuse_malformed_batches",
    "tests::only_explicit_user_appkit_responses_can_be_accept_or_decline",
)
main_count, native_count = 25, 2
scope = "twenty-five-main-and-two-native-macos-headless-data-regressions"
if android_lifecycle:
    # Fixed production-cut regressions only. These never enter
    # a Dispatcher, ServiceManager, real peer or supplier transfer.
    names = (
        "saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::callback_stamp_needs_exclusive_capture_return_then_original_owner_finality",
        "saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::deferred_reuses_only_same_private_owner_action_serial_and_unadmitted_cell",
        "saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::main_gate_only_defers_at_admission_and_preserves_actual_f_on_short_lock_contention",
        "saved_command_owner::android_registration::service_setup::callback_lifecycle_tests::register_observation_failure_is_at_real_return_and_stop_keeps_original_deadlines",
        "saved_command_owner::android_registration::client::tests::enqueued_busy_and_processed_are_distinct_and_finish_never_precedes_its_ack",
        "saved_command_owner::android_registration::client::tests::ack_rejects_wrong_account_nonce_sequence_payload_and_earlier_failure",
        "saved_command_owner::android_registration::client::tests::same_original_ready_reproof_and_current_gates_precede_transfer",
        "saved_command_owner::android_registration::client::tests::mismatched_reproof_lost_go_and_earlier_failure_close_original_barriers",
        "saved_command_owner::android_registration::client::tests::finish_requires_the_actual_source_handle_consumption_not_worker_return",
        "saved_command_owner::android_registration::client::tests::go_loss_and_peer_failure_still_run_preparation_and_independent_native_release",
        "saved_command_owner::android_registration::client::tests::native_clock_preserves_bidirectional_earliest_f_without_echo_or_renewal",
    )
    native_names = (
        "android_registration::tests::never_started_client_retires_its_actual_signal_without_arming_or_native_entry",
    )
    main_count, native_count = 11, 1
    scope = "eleven-main-and-one-native-macos-android-lifecycle-regressions"
if shipping_gate:
    # DATA13 only. The separately ignored real installed control is
    # selected later, after Installer readback and before app entry.
    names = (
        "vault_keyring_macos::tests::a_known_native_failure_projection_does_not_invent_cleanup_uncertainty",
        "vault_keyring_macos::tests::participant_never_uses_terminal_or_missing_child_as_exit_finality",
        "vault_keyring_macos::tests::failed_pipe_close_publishes_first_before_the_next_original_consume",
        "vault_keyring_macos::tests::refusal_never_fabricates_driver_return_join_native_cleanup_or_refund",
        "vault_keyring_macos::tests::cleanup_projection_observes_a_stop_arriving_during_original_settlement",
        "vault_keyring_macos::tests::an_unknown_original_projection_cannot_reopen_cleanup_on_a_later_callback",
    )
    native_names = (
        "vault_helper_filesystem::tests::prearm_and_pre_go_stop_have_no_native_allocation",
        "vault_helper_filesystem::tests::parent_pre_stop_retires_only_an_inert_gate_and_cannot_reenter",
        "vault_helper_filesystem::tests::prepare_and_spawn_are_distinct_one_shot_state_claims",
        "vault_helper_filesystem::tests::code_settlement_never_implies_gate_postcheck_or_unknown_close_finality",
        "vault_helper_filesystem::tests::even_a_closed_spawned_gate_requires_its_actual_postcheck",
        "vault_helper_filesystem::tests::cleanup_gate_correspondence_does_not_erase_a_previous_failure",
        "vault_helper_filesystem::tests::an_entered_unreturned_native_arm_is_never_empty_or_settled",
    )
    main_count, native_count = 6, 7
    scope = "six-main-and-seven-native-macos-shipping-gate-data-regressions"
if catalogue_gate:
    names += (CATALOGUE_ROUNDTRIP_TEST, CATALOGUE_BUDGET_TEST)
    main_count = 27
    scope = "twenty-seven-main-and-two-native-macos-headless-catalogue-data-regressions"
libraries = (
    ("main", "desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", [], names, main_count, "headless"),
    ("native", "desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native",
     ["default", "installed-observation"] if shipping_gate else ["default"], native_names, native_count, "headless-native"),
)
receipt = {"schemaVersion": 1, "scope": scope,
           "source": os.environ["GITHUB_SHA"], "workflowSource": os.environ["GITHUB_WORKFLOW_SHA"],
           "workflow": os.environ["GITHUB_WORKFLOW_REF"], "runId": os.environ["GITHUB_RUN_ID"],
           "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "names": names + native_names, "targets": [],
           "originalReturned": False, "artifactOriginalUnchanged": False, "artifactOriginalClosed": False,
           "passed": False,
           "shippingBinaryQualified": False, "distributionQualified": False}
def sig(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def regular(s, limit):
    if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid()
            or s.st_mode & 0o022 or not 0 <= s.st_size <= limit):
        raise ValueError("headless-original-file-shape")
def read_bound(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        regular(before, limit)
        data = os.pread(fd, before.st_size, 0)
        if len(data) != before.st_size or sig(before) != sig(os.fstat(fd)) or sig(before) != sig(path.lstat()):
            raise ValueError("headless-original-file-changed")
        return data
    finally: os.close(fd)
def publish(name, data):
    fd = os.open(work / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
def directory_identity(s):
    if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_gid != os.getgid()
            or stat.S_IMODE(s.st_mode) != 0o700):
        raise ValueError("headless-owned-directory-shape")
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
def load_original_owner():
    spec = importlib.util.spec_from_file_location("_mrk_macos_headless_owner", checkout / "desktop/tools/macos_aqua_qualification.py")
    qualification = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = qualification
    spec.loader.exec_module(qualification)
    return qualification.load_owner(checkout)
originals = []
owner = None
work_fd = target_fd = None
work_original = target_original = None
calls_entered = calls_returned = 0
cleanup_errors = []
if owned_headless:
    receipt.update(compilerOriginalReturned=False, cargoTargetRetired=False,
                   cargoTargetOriginalClosed=False, workOriginalClosed=False,
                   genuineServiceQualified=False, protectedCopyQualified=False)
if catalogue_gate:
    receipt.update(ownerCallsEntered=0, ownerCallsReturned=0, genuineServiceQualified=False,
                   protectedCopyQualified=False, androidLifecycleQualified=False)
stage = "original-compiler"
try:
    if owned_headless:
        if (work.parent != pathlib.Path("/Users/runner/work/_temp")
                or re.fullmatch(r"mrk-macos-aqua\.[A-Za-z0-9]{8}", work.name) is None
                or pathlib.Path(os.environ["CARGO_TARGET_DIR"]) != work / "cargo-target"
                or not shutil.rmtree.avoids_symlink_attacks):
            raise ValueError("headless-fixed-owned-target-route")
        # Retain actual original directory custody before any compiler.
        work_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        work_original = directory_identity(os.fstat(work_fd))
        if directory_identity(work.lstat()) != work_original:
            raise ValueError("headless-work-original-changed")
        os.mkdir("cargo-target", 0o700, dir_fd=work_fd)  # Exclusive; never reuse a target.
        target_fd = os.open("cargo-target", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=work_fd)
        target_original = directory_identity(os.fstat(target_fd))
        if directory_identity(os.stat("cargo-target", dir_fd=work_fd, follow_symlinks=False)) != target_original:
            raise ValueError("headless-target-original-changed")
        receipt["cargoTargetOriginal"] = [str(value) for value in target_original] if shipping_gate else target_original
        if shipping_gate:
            receipt["workOriginal"] = [str(value) for value in work_original]
        owner = load_original_owner()
        # Exact compiler environment, not test/app/service authority.
        # No ambient wrapper/flags, packaged-runtime or tool selection.
        build_env = {key: os.environ[key] for key in ("DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET")}
        build_env.update(PATH=rust_bin + ":/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", CARGO_HOME="/Users/runner/.cargo", RUSTUP_HOME="/Users/runner/.rustup", RUSTC=rust_bin + "/rustc", RUSTUP_AUTO_INSTALL="0")
        build_env.update(LANG="C", LC_ALL="C", TZ="UTC", RUSTUP_TOOLCHAIN=os.environ["RUSTUP_TOOLCHAIN"],
                         CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(work / "cargo-target"),
                         MRK_MACOS_INSTALL_SOURCE_COMMIT=os.environ["GITHUB_SHA"])
        compiler_argv = [rust_bin + "/cargo", "test", "--locked", "--no-default-features", "--jobs", "1",
            "--target", build_target, "--package", "mobile-release-kit-desktop",
            "--package", "mrk-macos-installed-native", "--lib", "--no-run", "--message-format=json"]
        if shipping_gate:
            compiler_argv += ["--features", "mrk-macos-installed-native/installed-observation"]
            receipt["compilerArgv"] = compiler_argv
        calls_entered += 1
        compiler = owner.run_owned(
            compiler_argv,
            environ=build_env, cwd=checkout / "desktop/src-tauri", timeout=480,
            capture=True, text=False, output_limit=4 * 1024 * 1024,
        )
        if (type(compiler) is not subprocess.CompletedProcess or type(compiler.returncode) is not int
                or type(compiler.args) is not list or compiler.args != compiler_argv
                or type(compiler.stdout) is not bytes or type(compiler.stderr) is not bytes
                or len(compiler.stdout) + len(compiler.stderr) > 4 * 1024 * 1024):
            raise ValueError("headless-original-compiler-return-contract")
        calls_returned += 1
        receipt["compilerOriginalReturned"] = True
        publish("headless-build.jsonl", compiler.stdout)
        publish("headless-build.stderr", compiler.stderr)
        publish("headless-build.status", (str(compiler.returncode) + "\n").encode("ascii"))
    if read_bound(work / "headless-build.status", 4) != b"0\n":
        raise ValueError("headless-original-compiler-status")
    raw = read_bound(work / "headless-build.jsonl", 4 * 1024 * 1024)
    def compiler_pairs(items):
        value = {}
        for key, item in items:
            if key in value: raise ValueError("headless-duplicate-compiler-key")
            value[key] = item
        return value
    rows = [json.loads(line, object_pairs_hook=compiler_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("headless-compiler-constant")))
            for line in raw.splitlines()]
    if any(type(row) is not dict for row in rows): raise ValueError("headless-compiler-json-shape")
    finished = [r.get("success") for r in rows if r.get("reason") == "build-finished"]
    if len(finished) != 1 or finished[0] is not True:
        raise ValueError("headless-original-compiler-finish")
    targets = [r for r in rows if r.get("reason") == "compiler-artifact" and r.get("executable") is not None]
    if len(targets) != 2: raise ValueError("headless-two-original-artifacts")
    receipt["compilerJsonSha256"] = hashlib.sha256(raw).hexdigest()
    admitted = []
    # Admit both fixed compiler targets before invoking either one.
    # Only the fixed shipping graph opts into installed-observation;
    # neither library graph can admit a separate helper role.
    for role, directory, package, library, features, test_names, count, prefix in libraries:
        matches = [r for r in targets if r.get("target", {}).get("name") == library]
        if len(matches) != 1: raise ValueError("headless-one-original-per-library")
        target = matches[0]
        package_id = "path+" + (checkout / directory).as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0")
        if (target.get("package_id") != package_id
                or target.get("manifest_path") != str(checkout / directory / "Cargo.toml")
                or target["target"].get("kind") != ["lib"]
                or target["target"].get("crate_types") != ["lib"]
                or target["target"].get("src_path") != str(checkout / directory / "src/lib.rs")
                or target.get("profile", {}).get("test") is not True or target.get("features") != features):
            raise ValueError("headless-fixed-non-observer-library")
        binary = pathlib.Path(target["executable"])
        expected = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / build_target / "debug/deps"
        if binary.parent != expected or not re.fullmatch(re.escape(library) + r"-[0-9a-f]+", binary.name):
            raise ValueError("headless-original-artifact-path")
        record = {"role": role, "packageId": package_id, "features": features, "names": test_names,
                  "originalReturned": False, "artifactOriginalUnchanged": False,
                  "artifactOriginalClosed": False, "testsPassed": False}
        receipt["targets"].append(record)
        admitted.append((binary, test_names, count, prefix, record))
    stage = "owner-admission"
    if owner is None: owner = load_original_owner()
    for binary, test_names, count, prefix, record in admitted:
        stage = prefix + "-original-artifact"
        binary_fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        original = {"fd": binary_fd, "record": record}
        originals.append(original)  # Custody precedes every fallible observation.
        before = os.fstat(binary_fd)
        regular(before, 1024 * 1024 * 1024)
        if not before.st_mode & 0o111: raise ValueError("headless-original-not-executable")
        def original_digest():
            if sig(before) != sig(os.fstat(binary_fd)) or sig(before) != sig(binary.lstat()):
                raise ValueError("headless-original-artifact-changed")
            digest, offset = hashlib.sha256(), 0
            while offset < before.st_size:
                block = os.pread(binary_fd, min(before.st_size - offset, 1024 * 1024), offset)
                if not block: raise ValueError("headless-original-artifact-short")
                digest.update(block)
                offset += len(block)
            if os.pread(binary_fd, 1, before.st_size): raise ValueError("headless-original-artifact-grew")
            if sig(before) != sig(os.fstat(binary_fd)) or sig(before) != sig(binary.lstat()):
                raise ValueError("headless-original-artifact-changed")
            return digest.hexdigest()
        digest = original_digest()
        record["artifact"] = {"path": str(binary), "sha256": digest, "identity": sig(before)}
        if shipping_gate:
            # Named standard order, not the legacy identity tuple.
            record["artifact"]["full9"] = [str(value) for value in (
                before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid,
                before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns)]
        home, tmp = work / (prefix + "-home"), work / (prefix + "-tmp")
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        if original_digest() != digest: raise ValueError("headless-original-artifact-hash")
        if catalogue_gate and prefix == "headless":
            run_catalogue_batch(owner, binary, test_names, count, prefix, record, original,
                                original_digest, digest, home, tmp)
            continue  # Same main FD is already consumed before the independent native leg.
        stage = prefix + "-original-test-invocation"
        calls_entered += 1
        result = owner.run_owned(
            [str(binary), "--exact", "--test-threads=1", "--color=never", "--format=pretty", *test_names],
            environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "TMPDIR": str(tmp),
                     "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            cwd=work, timeout=30, capture=True, text=False, output_limit=64 * 1024,
        )
        if (type(result) is not subprocess.CompletedProcess or type(result.returncode) is not int
                or (shipping_gate or catalogue_gate) and (type(result.args) is not list or result.args !=
                    [str(binary), "--exact", "--test-threads=1", "--color=never", "--format=pretty", *test_names])
                or type(result.stdout) is not bytes or type(result.stderr) is not bytes
                or len(result.stdout) + len(result.stderr) > 64 * 1024):
            raise ValueError("headless-original-return-contract")
        calls_returned += 1
        record.update(originalReturned=True, returncode=result.returncode,
                      stdoutSha256=hashlib.sha256(result.stdout).hexdigest(),
                      stderrSha256=hashlib.sha256(result.stderr).hexdigest())
        # Preserve each original return before testing its status/content.
        publish(prefix + "-tests.stdout", result.stdout)
        publish(prefix + "-tests.stderr", result.stderr)
        publish(prefix + "-tests.status", (str(result.returncode) + "\n").encode("ascii"))
        if original_digest() != digest: raise ValueError("headless-original-artifact-hash")
        record["artifactOriginalUnchanged"] = True
        stage = prefix + "-empty-test-directory-retirement"
        home.rmdir()
        tmp.rmdir()
        stage = prefix + "-exact-test-result"
        if result.returncode != 0 or result.stderr: raise ValueError("headless-tests-returned-failure")
        lines = [line for line in result.stdout.decode("utf-8", "strict").splitlines() if line]
        expected_rows = {"test " + name + " ... ok" for name in test_names}
        heading = f"running {count} " + ("test" if count == 1 else "tests")
        if (len(test_names) != count or len(expected_rows) != count or len(lines) != count + 2
                or lines[0] != heading or len(set(lines[1:-1])) != count or set(lines[1:-1]) != expected_rows):
            raise ValueError("headless-exact-named-results-required")
        summary = re.fullmatch(rf"test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; ([0-9]+) filtered out; finished in [0-9]+\.[0-9]+s", lines[-1])
        if summary is None: raise ValueError("headless-exact-test-summary")
        record.update(testsPassed=True, tests=count, failed=0, ignored=0, measured=0, filtered=int(summary[1]))
except BaseException as error:
    receipt["failure"] = {"stage": stage, "type": type(error).__name__}
    raise
finally:
    close_errors = []
    for original in originals:
        if original["fd"] is None:
            continue  # The catalogue main batch already consumed its one original FD.
        if (shipping_gate or catalogue_gate) and calls_entered != calls_returned:
            continue  # Unknown original owner cannot authorize any close.
        descriptor, original["fd"] = original["fd"], None
        try:
            os.close(descriptor)  # Exactly one close attempt; unknown is not retried.
            original["record"]["artifactOriginalClosed"] = True
        except BaseException as error:
            close_errors.append({"role": original["record"]["role"], "type": type(error).__name__})
    if android_lifecycle:
        receipt.update(ownerCallsEntered=calls_entered, ownerCallsReturned=calls_returned)
        if target_original is not None and calls_entered == calls_returned and not close_errors:
            try:
                # Delete only the originally created target, after all
                # actual owner returns and artifact descriptor closes.
                if (directory_identity(os.fstat(work_fd)) != work_original
                        or directory_identity(work.lstat()) != work_original
                        or directory_identity(os.fstat(target_fd)) != target_original
                        or directory_identity(os.stat("cargo-target", dir_fd=work_fd, follow_symlinks=False)) != target_original):
                    raise ValueError("headless-target-retirement-original-changed")
                shutil.rmtree("cargo-target", dir_fd=work_fd)
                try: os.stat("cargo-target", dir_fd=work_fd, follow_symlinks=False)
                except FileNotFoundError: pass
                else: raise ValueError("headless-target-retirement-incomplete")
                receipt["cargoTargetRetired"] = True
            except BaseException as error:
                cleanup_errors.append({"stage": "cargo-target-retirement", "type": type(error).__name__})
        else:
            receipt["cargoTargetRetentionReason"] = "original-custody-or-owner-finality-unconfirmed"
        directories = (("cargoTargetOriginalClosed", target_fd), ("workOriginalClosed", work_fd))
        target_fd = work_fd = None
        for field, directory_fd in directories:
            if directory_fd is None: continue
            try:
                os.close(directory_fd)  # One attempt, including failed-retirement paths.
                receipt[field] = True
            except BaseException as error:
                cleanup_errors.append({"stage": field, "type": type(error).__name__})
        if cleanup_errors: receipt["cleanupErrors"] = cleanup_errors
    if shipping_gate:
        receipt.update(ownerCallsEntered=calls_entered, ownerCallsReturned=calls_returned,
                       headlessCustodyRetained=calls_entered != calls_returned)
        if calls_entered == calls_returned:
            try:
                if (work_original is None or target_original is None
                        or directory_identity(os.fstat(work_fd)) != work_original
                        or directory_identity(work.lstat()) != work_original
                        or directory_identity(os.fstat(target_fd)) != target_original
                        or directory_identity(os.stat("cargo-target", dir_fd=work_fd, follow_symlinks=False)) != target_original):
                    raise ValueError("headless-target-retention-original-changed")
                # Still required by the existing observer/Installer
                # compiles and the later exact ignored native control.
                receipt["cargoTargetRetentionReason"] = "required-follow-on-build-and-gate-control"
            except BaseException as error:
                cleanup_errors.append({"stage": "cargo-target-retention", "type": type(error).__name__})
            directories = (("cargoTargetOriginalClosed", target_fd), ("workOriginalClosed", work_fd))
            target_fd = work_fd = None
            for field, directory_fd in directories:
                if directory_fd is None: continue
                try:
                    os.close(directory_fd)  # One consuming close, never a target deletion.
                    receipt[field] = True
                except BaseException as error:
                    cleanup_errors.append({"stage": field, "type": type(error).__name__})
        else:
            receipt["cargoTargetRetentionReason"] = "original-custody-or-owner-finality-unconfirmed"
        if cleanup_errors: receipt["cleanupErrors"] = cleanup_errors
    if close_errors: receipt["closeErrors"] = close_errors
    for key in ("originalReturned", "artifactOriginalUnchanged", "artifactOriginalClosed"):
        receipt[key] = len(receipt["targets"]) == 2 and all(row[key] for row in receipt["targets"])
    receipt["passed"] = ("failure" not in receipt and not close_errors
        and receipt["originalReturned"] and receipt["artifactOriginalUnchanged"] and receipt["artifactOriginalClosed"]
        and all(row["testsPassed"] for row in receipt["targets"]))
    if android_lifecycle:
        receipt["passed"] = (receipt["passed"] and not cleanup_errors
            and receipt["compilerOriginalReturned"] and calls_entered == calls_returned == 3
            and receipt["cargoTargetRetired"] and receipt["cargoTargetOriginalClosed"] and receipt["workOriginalClosed"])
    if shipping_gate:
        receipt["passed"] = (receipt["passed"] and not cleanup_errors
            and receipt["compilerOriginalReturned"] and calls_entered == calls_returned == 3
            and not receipt["headlessCustodyRetained"] and not receipt["cargoTargetRetired"]
            and receipt["cargoTargetOriginalClosed"] and receipt["workOriginalClosed"]
            and receipt.get("cargoTargetRetentionReason") == "required-follow-on-build-and-gate-control")
    if catalogue_gate:
        receipt.update(ownerCallsEntered=calls_entered, ownerCallsReturned=calls_returned)
        main_rows = [row for row in receipt["targets"] if row["role"] == "main"]
        receipt["passed"] = (receipt["passed"] and calls_entered == calls_returned == 3
            and len(main_rows) == 1 and main_rows[0].get("ownerCallsEntered") == 2
            and main_rows[0].get("ownerCallsReturned") == 2
            and main_rows[0].get("artifactCloseAttempts") == 1
            and main_rows[0].get("deadlineMetAfterFinalCloses") is True
            and main_rows[0].get("headlessCustodyRetained") is False)
    if receipt["passed"]: receipt.update(tests=len(names) + len(native_names), failed=0, ignored=0, measured=0)
    # Unknown owner/close finality retains original target output.
    data = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(data) > 16384: raise ValueError("headless-receipt-bound")
    publish("headless-tests.receipt.json", data)
    if close_errors and "failure" not in receipt: raise ValueError("headless-original-close-unconfirmed")
    if cleanup_errors and "failure" not in receipt: raise ValueError("headless-original-target-cleanup-unconfirmed")
    if android_lifecycle and not receipt["passed"] and "failure" not in receipt:
        raise ValueError("headless-android-lifecycle-finality-unconfirmed")
    if shipping_gate and not receipt["passed"] and "failure" not in receipt:
        raise ValueError("headless-shipping-gate-finality-unconfirmed")
    if catalogue_gate and not receipt["passed"] and "failure" not in receipt:
        raise ValueError("headless-catalogue-finality-unconfirmed")
PY_HEADLESS
