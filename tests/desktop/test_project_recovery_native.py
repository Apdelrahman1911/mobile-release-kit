"""Closed Recovery Q contracts and failure injection; no process/GUI/filesystem fixture.

All receipts below are invented in-memory parser inputs, never native evidence.
The genuine fixture producer and original native owners are verified separately.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[2]
def module(name):
    spec = importlib.util.spec_from_file_location("recovery_native_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
L = module("ubuntu_publication_lifecycle")
S = module("ci_ubuntu_publication")
SHA = "a" * 40


def selection(negative=False):
    return {"sourceSha": SHA, "runId": "10", "attempt": "2", "runnerUid": 1001, "runnerGid": 1001,
            "deadline": 1000, "shell": {"projectRecovery": L.shell_recovery_selection(
                L.SHELL_RECOVERY_NEGATIVE_PROFILE if negative else L.SHELL_RECOVERY_PROFILE)}}


def receipt(case):
    negative, cancel, cleanup = case == L.SHELL_RECOVERY_PARTIAL, case == "project-recovery-cancel", case == "project-recovery-cleanup-only"
    inspection = {"status": "cleanup-only" if cleanup else "pending", "session": "5" * 32,
                  "roles": [] if cleanup else ["android-services", "ios-services"], "quiescence": "original"}
    counts = [1, 1, 1, 1, int(negative or cancel), int(negative)]
    result = {"schemaVersion": 1, "scope": "project-build-input-recovery-native-observation-v1", "case": case,
              "sourceCommit": SHA, "testOnlyQualification": True, "applicationFinal": not negative,
              "bootstrapReturned": True, "projectSelectionObserved": True, "originals": [], "requests": counts,
              "replies": list(counts), "freshUncheckedReview": True, "explicitAcknowledgement": True,
              "heldSettlementObserved": cancel, "peerAdmissionRefused": negative or cancel,
              "originalStatusReturned": negative, "originalCancelReturned": negative or cancel,
              "partialWarningVisible": negative, "finalVisible": not negative, "commandDispatches": 0,
              "profileCalls": 0, "ordinaryActivation": False}
    for index in range(2):
        failed = negative and index == 1
        identifier, generation = str(index + 1) * 32, str(index + 3) * 32
        facts = {key: True for key in ("inspectionJoined", "acquisitionJoined", "attempted", "childWaitedSuccess",
            "stdinClosed", "stdoutEofClosed", "stderrEofClosed", "ioJoined")}
        facts.update({key: not failed for key in ("coreLifetimeSettled", "runtimeLedgerSettled", "runtimeSettlementJoined",
            "driverJoined", "managerJoined", "observerJoined", "watchdogJoined", "retiredBeforeCutoff")})
        facts.update(domain="project-recovery", id=identifier, generation=generation, noChild=False,
                     activeRetained=failed, resourceUnknown=failed)
        context = {"projectId": "project1", "draftRevision": 0, "baselineGeneration": 1,
                   "action": "inspect" if index == 0 else "recover", "review": None if index == 0 else deepcopy(inspection)}
        outcome = "unknown" if failed else "cancelled" if index == 1 and cancel else "complete"
        data = None if outcome != "complete" else {"schemaVersion": 1, "scope": "project-build-inputs-only",
            "action": context["action"], "observation": deepcopy(inspection) if index == 0 else None,
            "recoveredSession": None if index == 0 else inspection["session"], "limitations": [
                "build-inputs-only-not-store-or-account-recovery", "recorded-quiescence-not-new-worker-proof",
                "foreign-changes-preserved", "cancellation-does-not-undo-completed-cleanup", "project-and-release-readiness-not-assessed"]}
        projection = {"operationId": identifier, "ownerGeneration": generation, "context": context,
            "phase": "unknown" if failed else "terminal", "intentUsable": False, "outcome": outcome,
            "reason": "cleanup-unknown" if failed else "cancelled" if outcome == "cancelled" else "none",
            "result": data, "effect": None if data is None else "inspection" if index == 0 else "recovery-attempted"}
        result["originals"].append({"facts": facts, "projection": projection, "accepted": True, "coreTerminal": True,
                                    "coreFatal": failed, "reviewMinted": index == 0})
    return result


def owner_failure():
    raw = L.canonical(receipt(L.SHELL_RECOVERY_PARTIAL))
    return {"schemaVersion": 1, "scope": "original-recovery-negative-owner-v1", "case": L.SHELL_RECOVERY_PARTIAL,
        "sourceSha": SHA, "phase": "shell-" + L.SHELL_RECOVERY_PARTIAL, "classificationEligible": True,
        "applicationFinal": False, "originalOwnerFinal": True, "error": {"type": "ProcessError", "origin": "owner",
            "message": "owned command exceeded its original deadline", "originalProcessFacts": {
                "dispatched": True, "contained": True, "cleanup_complete": True}},
        "ownerCall": {"timeoutSeconds": 30, "ownerReturned": False, "startMonotonic": 100.0,
                      "endMonotonic": 131.0, "ownerElapsedSeconds": 31.0}, "labelsBytes": 0,
        "observation": {"path": "project-recovery-negative.observation", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        "failureSinkClosed": True, "observationSinkClosed": True}


def interval_documents():
    """Invented interval DATA; common loader/native qualification is separate."""
    value = selection(True)
    start = {"sourceSha": SHA, "entrySha256": "c" * 64, "handoffSha256": "d" * 64,
             "invocationId": "b" * 32, "deadline": value["deadline"],
             "namespaces": {"user": [1, 2], "pid": [1, 3], "mnt": [1, 4]}}
    published = L.canonical({"P0": {"core.zip": {"identity": [1, 20, stat.S_IFREG | 0o444, 0, 0, 1, 3, 1, 1],
                                               "size": 3, "sha256": "f" * 64}}})
    publication = {"path": "published-before-upgrade.txt", "size": len(published), "sha256": hashlib.sha256(published).hexdigest()}
    binding = {key: start[key] for key in ("sourceSha", "entrySha256", "handoffSha256", "invocationId", "deadline")}
    before = {"schemaVersion": 1, "scope": "project-recovery-negative-loader-before-v1", **binding,
        "publication": publication, "loader": {"payloadAdmitted": True, "runtimeDataRechecked": False,
            "namespaces": deepcopy(start["namespaces"]), "bindings": {"/inert-never-opened/python": {"sha256": "a" * 64}},
            "runtimeData": {"records": [{"path": "shell-root-data-0.json", "size": 1, "sha256": "b" * 64}]}}}
    before_raw = L.canonical(before)
    interval = {"schemaVersion": 1, "scope": "project-recovery-negative-final-interval-v1", **binding,
        "before": {"path": L.SHELL_RECOVERY_LOADER_BEFORE, "size": len(before_raw), "sha256": hashlib.sha256(before_raw).hexdigest()},
        "publication": deepcopy(publication), "loader": {**deepcopy(before["loader"]), "runtimeDataRechecked": True},
        "publicationUnchanged": True}
    interval_raw = L.canonical(interval)
    stop = {"interval": {"path": L.SHELL_RECOVERY_INTERVAL, "size": len(interval_raw), "sha256": hashlib.sha256(interval_raw).hexdigest()}}
    return value, start, stop, {L.SHELL_RECOVERY_LOADER_BEFORE: before_raw, L.SHELL_RECOVERY_INTERVAL: interval_raw,
                               "published-before-upgrade.txt": published}


def inventory_documents(case):
    """Invented bounded parser DATA, not a journal or actual fixture generator."""
    value = selection(case == L.SHELL_RECOVERY_PARTIAL)
    namespace = {"root": str(L.shell_fixture_root(value)), "identity": [1, 5, stat.S_IFDIR | 0o755, 0, 0, 3, 4096, 1, 1],
        "children": list(L.shell_fixture_children(value)),
        "control": {"path": str(L.root_path(value)), "identity": [1, 4, stat.S_IFDIR | 0o711, 0, 0]},
        "ancestors": [{"path": path, "identity": [1, index, stat.S_IFDIR | 0o755, 0, 0]}
                      for index, path in enumerate(("/", "/var", "/var/lib"), 1)]}
    def row(path, inode, content=None):
        raw = L.SHELL_RECOVERY_BYTES.get(content, b"invented parser DATA")
        return {"path": path, "identity": [1, inode, (stat.S_IFDIR | 0o700) if content is None else (stat.S_IFREG | 0o600),
                    1001, 1001, 2 if content is None else 1, 4096 if content is None else len(raw), 1, 1],
                "sha256": None if content is None else hashlib.sha256(raw).hexdigest()}
    android, ios, private = "project/google-services.json", "project/GoogleService-Info.plist", "project/.mobile-release"
    pending = private + "/build-inputs"
    initial = {name: row(name, index, content) for index, (name, content) in enumerate((
        (".", None), ("project", None), ("project/.gitignore", "ignore"), ("project/unrelated.txt", "unrelated"),
        (android, "android-original"), (ios, "ios-original")), 10)}
    generated = deepcopy(initial)
    generated.update({name: row(name, index, content) for index, (name, content) in enumerate((
        (private, None), (pending, None), (pending + "/header.json", "control"), (pending + "/intent.json", "control"),
        (pending + "/checkpoint-000.json", "control"), (pending + "/checkpoint-001.json", "control")), 20)})
    def moved(rows, old, new):
        item = rows.pop(old); item["path"] = new; item["identity"][8] += 1; rows[new] = item
    if case == "project-recovery-cleanup-only":
        name = private + "/build-inputs-complete.json"; generated[name] = row(name, 30, "control")
    else:
        moved(generated, ios, pending + "/backup-1"); generated[ios] = row(ios, 30, "ios-foreign")
        if case == L.SHELL_RECOVERY_PARTIAL:
            moved(generated, android, pending + "/backup-0"); generated[android] = row(android, 31, "android-foreign")
    before = deepcopy(generated)
    if case == "project-recovery-cleanup-only":
        before[android] = row(android, initial[android]["identity"][1], "later-edit")
        before[android]["identity"][7:] = [2, 2]
    else:
        moved(before, android if case == L.SHELL_RECOVERY_PARTIAL else ios,
              "project/saved-foreign-android" if case == L.SHELL_RECOVERY_PARTIAL else "project/saved-foreign-ios")
    after = deepcopy(before)
    if case == L.SHELL_RECOVERY_PARTIAL:
        moved(after, pending + "/backup-0", android)
        name = pending + "/checkpoint-002.json"; after[name] = row(name, 40, "control")
    else:
        if case != "project-recovery-cleanup-only": moved(after, pending + "/backup-1", ios)
        after = {name: item for name, item in after.items() if not name.startswith(pending)}
    return value, [{"schemaVersion": 1, "fixture": "real-core-project-recovery-v1", "sourceSha": SHA,
        "case": case, "stage": stage, "namespace": deepcopy(namespace), "entries": list(rows.values())}
        for stage, rows in zip(("initial", "generated", "before", "after"), (initial, generated, before, after))]


class ProjectRecoveryNativeContracts(unittest.TestCase):
    def test_real_core_producer_contract_never_labels_failed_cleanup_as_success(self):
        for case in L.SHELL_RECOVERY_ALL_CASES:
            good = {"schemaVersion": 1, "scope": "real-core-project-recovery-fixture-v1", "case": case,
                "materializationOutcome": "expected-cleanup-failure", "coreFatal": True, "commands": 0, "profileCalls": 0,
                "attemptedDescriptors": 30, "neverOpenedDescriptors": 1, "attemptedDescriptorsClosed": True,
                "handlersRestored": True, "invocationReleased": True, "originalQuiescenceRecorded": True,
                "retirementInterceptions": int(case == "project-recovery-cleanup-only"), "observersRestored": True,
                "restored": {"android-services": case != L.SHELL_RECOVERY_PARTIAL,
                             "ios-services": case == "project-recovery-cleanup-only"}, "followupCoreOrFilesystemOperation": False}
            self.assertEqual(L.shell_recovery_producer_result(L.canonical(good), b"", case, 0), good)
            for field, replacement in (("materializationOutcome", "success"), ("coreFatal", False), ("commands", 1),
                    ("attemptedDescriptors", 0), ("neverOpenedDescriptors", 2048), ("attemptedDescriptorsClosed", False),
                    ("handlersRestored", False), ("invocationReleased", False), ("originalQuiescenceRecorded", False),
                    ("observersRestored", False), ("followupCoreOrFilesystemOperation", True)):
                with self.subTest(case=case, field=field), self.assertRaises(L.Refused):
                    L.shell_recovery_producer_result(L.canonical({**good, field: replacement}), b"", case, 0)
            for code, stderr in ((1, b""), (0, b"unrelated error")):
                with self.assertRaises(L.Refused): L.shell_recovery_producer_result(L.canonical(good), stderr, case, code)

    def test_fixture_correspondence_preserves_originals_foreign_files_and_later_edits(self):
        for case in L.SHELL_RECOVERY_ALL_CASES:
            value, documents = inventory_documents(case)
            def check(docs):
                return L.shell_recovery_fixture(value, case, *(L.canonical(doc) for doc in docs))
            result = check(documents)
            self.assertEqual(result["partialEffectsObserved"], case == L.SHELL_RECOVERY_PARTIAL)
            self.assertEqual(result["laterEditPreserved"], case == "project-recovery-cleanup-only")
            self.assertFalse(result["privateContentsExported"])
            for target, field in (("project/unrelated.txt", 8), ("project/google-services.json", 1)):
                changed = deepcopy(documents)
                item = next(row for row in changed[3]["entries"] if row["path"] == target)
                item["identity"][field] += 100
                with self.subTest(case=case, target=target), self.assertRaises(L.Refused): check(changed)
            changed = deepcopy(documents)
            item = next(row for row in changed[3]["entries"] if row["path"] == "project/google-services.json")
            item["sha256"] = "b" * 64
            with self.subTest(case=case, risk="changed-target"), self.assertRaises(L.Refused): check(changed)
        value, documents = inventory_documents(L.SHELL_RECOVERY_PARTIAL)
        for risk in ("extra-retired", "pending-replaced", "old-control-changed", "checkpoint-gap", "alias", "wrong-mode"):
            changed = deepcopy(documents); rows = changed[3]["entries"]
            control = next(row for row in rows if row["path"].endswith("/checkpoint-000.json"))
            if risk == "extra-retired":
                extra = deepcopy(control); extra["path"] = "project/.mobile-release/build-inputs/retired-0"
                extra["identity"][1] = 200; rows.append(extra)
            elif risk == "pending-replaced": next(row for row in rows if row["path"] == "project/.mobile-release/build-inputs")["identity"][1] = 201
            elif risk == "old-control-changed": control["sha256"] = "f" * 64
            elif risk == "checkpoint-gap": control["path"] = control["path"].replace("000", "003")
            elif risk == "alias": control["identity"] = deepcopy(next(row for row in rows if row["path"].endswith("/header.json"))["identity"])
            else: control["identity"][2] = stat.S_IFLNK | 0o600
            with self.subTest(risk=risk), self.assertRaises(L.Refused):
                L.shell_recovery_fixture(value, L.SHELL_RECOVERY_PARTIAL, *(L.canonical(doc) for doc in changed))

    def test_workflow_reuses_original_compiler_on_a_distinct_failed_unit_vm(self):
        workflow = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        prefix, negative = workflow.split("\n  recovery-negative:\n", 1)
        self.assertEqual(re.findall(r"^  ([a-z][a-z-]*):$", workflow.split("jobs:\n", 1)[1], re.MULTILINE), ["compile", "recovery-negative"])
        self.assertIn("    needs: compile\n", negative)
        self.assertIn("if: always() && github.ref == 'refs/heads/verify/desktop-project-recovery'", negative)
        self.assertIn("needs.compile.outputs.compiled_success == 'success'", negative)
        self.assertIn("compiled_success: ${{ steps.compile.outcome }}", prefix)
        self.assertIn('if [[ "$MRK_INSTALLED_SHELL_CASE" == compile ]]; then', prefix)
        self.assertIn("printf 'native=true\\n' >> \"$GITHUB_OUTPUT\"", prefix)
        self.assertIn("if: steps.route.outputs.native == 'true'", prefix)
        self.assertIn("refs/heads/verify/desktop-project-recovery:compile|refs/heads/verify/desktop-installed-shell:compile|", prefix)
        self.assertIn("            *) exit 70 ;;", prefix)
        self.assertLessEqual(len(workflow.encode()), S.SHELL_TOOLS_NAMESPACE_SOURCES[".github/workflows/desktop-ubuntu-publication.yml"])
        self.assertIn("shell_artifact_id: ${{ steps.upload.outputs.artifact-id }}", prefix)
        self.assertIn("artifact-ids: ${{ needs.compile.outputs.shell_artifact_id }}", negative)
        self.assertIn("run-id: ${{ github.run_id }}", negative)
        self.assertIn("MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT: ${{ needs.compile.outputs.shell_producer_attempt }}", negative)
        self.assertIn("MRK_INSTALLED_SHELL_ROSTER_SHA256: ${{ needs.compile.outputs.shell_roster_sha256 }}", negative)
        self.assertIn("MRK_INSTALLED_SHELL_SCOPE: project-recovery-unknown1-v1", negative)
        self.assertIn("MRK_INSTALLED_SHELL_TRANSPORT: actions-artifact-v1", negative)
        self.assertIn("    runs-on: ubuntu-24.04\n", negative)
        self.assertLess(negative.index("installed-shell-source-admission"), negative.index("sudo apt-get"))
        self.assertNotIn(" installed-shell-compile", negative)
        self.assertNotIn("actions/setup-node", negative)
        self.assertNotIn("continue-on-error", negative)
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertIn("persist-credentials: false", negative)
        # Normal success gates retain their exact entry contract. Negative code1
        # is passed solely to the distinct collector after original client return.
        consumer = (SOURCE / "desktop/tools/ci_ubuntu_publication.py").read_text()
        self.assertIn("codes=(1,) if recovery and recovery_scope[\"expectedRetainedUnknown\"] else (0,)", consumer)
        self.assertIn("lifecycle.verify_project_recovery_negative_service_result", consumer)

    def test_fixed_scopes_never_expand_ordinary_or_admit_partial_as_success(self):
        for negative in (False, True):
            value = selection(negative)
            self.assertFalse(L.shell_android(value)); self.assertFalse(L.shell_ordinary(value))
            self.assertEqual(L.shell_cases(value), (L.SHELL_RECOVERY_PARTIAL,) if negative else L.SHELL_RECOVERY_CASES)
            self.assertLessEqual(len(L.public_files(value)), L.shell_public_limit(value))
            self.assertEqual(L.service_task_limit(value), "256")
            self.assertFalse(set(L.shell_cases(value)) & set(L.SHELL_CASES))
            for key in ("ordinary21", "githubReadOnly", "androidPublication", "localTransport"):
                changed = deepcopy(value); changed["shell"][key] = {}
                with self.subTest(negative=negative, field=key), self.assertRaises(L.Refused): L.shell_cases(changed)
        negative = L.public_files(selection(True))
        self.assertIn("unit-start-error.json", negative); self.assertIn("project-recovery-negative-stop.json", negative)
        self.assertIn(L.SHELL_RECOVERY_LOADER_BEFORE, negative); self.assertIn(L.SHELL_RECOVERY_INTERVAL, negative)
        self.assertNotIn("unit-result.json", negative); self.assertNotIn("loader-final.json", negative)
        self.assertNotIn("shell-project-recovery-partial-after.json", negative)  # Only original post-client collector may read this.
        with self.assertRaises(L.Refused): L.shell_result(b"", b"", L.SHELL_RECOVERY_PARTIAL, 0, {})

    def test_common_q4_compiler_is_bound_to_two_distinct_fixed_consumer_jobs(self):
        common = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
            "GITHUB_EVENT_NAME": "push", "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": SHA, "MRK_PUSH_EVENT_AFTER": SHA,
            "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
            "GITHUB_REF": L.SHELL_RECOVERY_REF, "MRK_INSTALLED_SHELL_TRANSPORT": "actions-artifact-v1"}
        scopes = []
        for job, case, profile in (("compile", "compile", L.SHELL_RECOVERY_PROFILE), ("compile", "observe", L.SHELL_RECOVERY_PROFILE),
                                   ("recovery-negative", "observe", L.SHELL_RECOVERY_NEGATIVE_PROFILE)):
            env = {**common, "GITHUB_JOB": job, "MRK_INSTALLED_SHELL_CASE": case, "MRK_INSTALLED_SHELL_SCOPE": profile}
            self.assertEqual(S.route(env), SHA)
            with patch.dict(S.os.environ, env, clear=True): scopes.append(S.installed_shell_scope(L))
            for bad in ({"GITHUB_JOB": "other"}, {"MRK_INSTALLED_SHELL_SCOPE": ""}, {"MRK_INSTALLED_SHELL_CASE": "arbitrary"},
                        {"GITHUB_REF": "refs/heads/main"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"}):
                with self.subTest(job=job, change=bad), self.assertRaises(S.D.Refused): S.route({**env, **bad})
        self.assertTrue(all(scope == L.shell_recovery_compile_selection() for scope in scopes))
        source = {"projectRecovery": scopes[0], "androidBuildMaterials": None, "androidBuildBindings": {}, "androidBuildPublication": None}
        S.installed_shell_scope_record(source, L, scopes[0], android_contract=True)
        for mutation in ({"ordinary21": L.shell_ordinary_selection()}, {"projectRecovery": L.shell_recovery_selection(L.SHELL_RECOVERY_PROFILE)},
                         {"androidBuildBindings": {"unexpected": "value"}}, {"remainingRequiredCases": []}):
            with self.subTest(mutation=mutation), self.assertRaises(S.D.Refused):
                S.installed_shell_scope_record({**source, **mutation}, L, scopes[0], android_contract=True)

    def test_original_two_operation_linkage_and_joins_are_required(self):
        for case in L.SHELL_RECOVERY_ALL_CASES:
            good = receipt(case)
            self.assertEqual(L.shell_recovery_receipt(L.canonical(good), case, source=SHA), good)
            for path, value in ((["sourceCommit"], "b" * 40), (["bootstrapReturned"], False), (["ordinaryActivation"], True),
                    (["requests"], [1, 1, 1, 1, 1, 1, 1]), (["originals", 0, "reviewMinted"], False),
                    (["originals", 0, "facts", "ioJoined"], False), (["originals", 0, "facts", "watchdogJoined"], False),
                    (["originals", 1, "projection", "context", "review", "session"], "f" * 32),
                    (["originals", 1, "projection", "operationId"], "1" * 32)):
                changed = deepcopy(good); item = changed
                for key in path[:-1]: item = item[key]
                item[path[-1]] = value
                with self.subTest(case=case, path=path), self.assertRaises(L.Refused):
                    L.shell_recovery_receipt(L.canonical(changed), case, source=SHA)
            for raw in (L.canonical(good)[:-1], L.canonical(good) + b"\n", b"{}\n", b"x" * 8193):
                with self.assertRaises((L.Refused, ValueError)): L.shell_recovery_receipt(raw, case, source=SHA)

    def test_retained_unknown_cannot_borrow_positive_finality_or_effect_claims(self):
        case = L.SHELL_RECOVERY_PARTIAL
        for path, value in ((["applicationFinal"], True), (["partialWarningVisible"], False), (["originalStatusReturned"], False),
                (["originalCancelReturned"], False), (["peerAdmissionRefused"], False), (["originals", 1, "coreFatal"], False),
                (["originals", 1, "facts", "runtimeLedgerSettled"], True), (["originals", 1, "facts", "activeRetained"], False),
                (["originals", 1, "facts", "resourceUnknown"], False), (["originals", 1, "projection", "effect"], "none")):
            changed = receipt(case); item = changed
            for key in path[:-1]: item = item[key]
            item[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(L.Refused): L.shell_recovery_receipt(L.canonical(changed), case)
        for case in L.SHELL_RECOVERY_CASES:
            raw = (b"MRK_DESKTOP_CAPABILITIES=available\nMRK_DESKTOP_CATALOGUE=returned\n"
                b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n" + L.SHELL_RECOVERY_MARKER
                + L.canonical(receipt(case)) + b"MRK_INSTALLED_SHELL_OBSERVATION=" + case.encode() + b"-verified\n")
            self.assertEqual(L.shell_recovery_result(raw, b"", case, 0)["case"], case)
            with self.assertRaises(L.Refused): L.shell_recovery_result(raw, b"", case, 1)
            with self.assertRaises(L.Refused): L.shell_recovery_result(raw, b"MRK_fake\n", case, 0)

    def test_negative_owner_requires_original_error_clock_and_both_closed_reads(self):
        good = owner_failure(); self.assertEqual(L.shell_recovery_negative_owner_data(selection(True), good), good)
        for path, value in ((["classificationEligible"], False), (["originalOwnerFinal"], False), (["failureSinkClosed"], False),
                (["observationSinkClosed"], False), (["labelsBytes"], 1), (["error", "type"], "ProcessCleanupError"),
                (["error", "originalProcessFacts", "contained"], False), (["error", "originalProcessFacts", "cleanup_complete"], False),
                (["error", "originalProcessFacts", "dispatched"], 1), (["ownerCall", "timeoutSeconds"], 29),
                (["ownerCall", "ownerReturned"], True), (["ownerCall", "ownerElapsedSeconds"], 5), (["sourceSha"], "b" * 40)):
            changed = deepcopy(good); item = changed
            for key in path[:-1]: item = item[key]
            item[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(L.Refused): L.shell_recovery_negative_owner_data(selection(True), changed)

    def test_sink_is_unread_before_exact_original_owner_finality(self):
        class OriginalError(Exception):
            def __init__(self):
                super().__init__("owned command exceeded its original deadline")
                self.dispatched = self.contained = self.cleanup_complete = True
        for wrong in ("dispatched", "contained", "cleanup_complete", "wrong-type", "wrong-message"):
            error = OriginalError()
            if wrong == "wrong-type": error = ValueError(*error.args)
            elif wrong == "wrong-message": error.args = ("unrelated timeout",)
            else: setattr(error, wrong, False)
            with ExitStack() as stack:
                stack.enter_context(patch.object(L, "_OWNER", SimpleNamespace(ProcessError=OriginalError)))
                stack.enter_context(patch.object(L, "_FAILED", True)); stack.enter_context(patch.object(L, "_RECOVERY_NEGATIVE", {}))
                labels = stack.enter_context(patch.object(L, "_shell_labels_read", side_effect=AssertionError("premature read")))
                read = stack.enter_context(patch.object(L.os, "read", side_effect=AssertionError("premature read")))
                with self.subTest(wrong=wrong), self.assertRaises(L.Refused):
                    L._shell_recovery_owner_failure(selection(True), error, (10, ()), (11, ()), {"timeoutSeconds": 30})
                labels.assert_not_called(); read.assert_not_called()

    def test_failed_command_keeps_primary_and_attempts_both_original_closes(self):
        class OriginalError(Exception): pass
        for failed_close in (None, 12, 13):
            value = selection(True); original = OriginalError("owned command exceeded its original deadline")
            closed = []
            def close(fd):
                closed.append(fd)
                if fd == failed_close: raise OSError("synthetic close failure")
            with ExitStack() as stack:
                for name, item in {"_FAILED": False, "_RECOVERY_NEGATIVE": None, "_END": 1e12, "_PHASE": "entry",
                                   "_GITHUB_BOUNDARY_COMMAND_FINAL": True,
                                   "_OWNER": SimpleNamespace(run_owned=Mock(side_effect=original))}.items():
                    stack.enter_context(patch.object(L, name, item))
                stack.enter_context(patch.object(L, "_root_ids"))
                stack.enter_context(patch.object(L, "_shell_labels_prepare", return_value=(12, ())))
                stack.enter_context(patch.object(L, "_shell_recovery_negative_prepare", return_value=(13, ())))
                stack.enter_context(patch.object(L, "_shell_recovery_owner_failure"))
                stack.enter_context(patch.object(L.os, "close", side_effect=close))
                with self.assertRaises(OriginalError) as caught:
                    L.command("shell-" + L.SHELL_RECOVERY_PARTIAL, L.shell_argv(value, L.SHELL_RECOVERY_PARTIAL),
                        maximum=30, env=L.shell_environment(value, L.SHELL_RECOVERY_PARTIAL), shell_log=(value, L.SHELL_RECOVERY_PARTIAL, None))
                self.assertIs(caught.exception, original); self.assertTrue(L._FAILED); self.assertEqual(closed, [12, 13])
                self.assertFalse(L._GITHUB_BOUNDARY_COMMAND_FINAL)
                self.assertEqual(L._RECOVERY_NEGATIVE["failureSinkClosed"], failed_close != 12)
                self.assertEqual(L._RECOVERY_NEGATIVE["observationSinkClosed"], failed_close != 13)
                self.assertFalse(L._RECOVERY_NEGATIVE["classificationEligible"])

    def test_failed_stop_correspondence_does_not_fabricate_a_joined_client(self):
        value = selection(True); invocation = "b" * 32
        unit = {"Id": L.root_path(value).name + ".service", "InvocationID": invocation,
                "Result": "success", "ControlGroup": "/system.slice/" + L.root_path(value).name + ".service"}
        start = {"sourceSha": SHA, "entrySha256": "c" * 64, "handoffSha256": "d" * 64, "invocationId": invocation,
            "deadline": value["deadline"], "namespaces": {"user": [1, 2], "pid": [1, 3], "mnt": [1, 4]}, "effective": {"pids.max": "256"},
            "runnerUid": 1001, "runnerGid": 1001, "unit": unit,
            "events": {"memory.events": {"max": 0, "oom": 0, "oom_kill": 0}, "pids.events": {"max": 0}}}
        error = {"phase": "shell-" + L.SHELL_RECOVERY_PARTIAL, "errorType": "ProcessError",
            "reason": "owned command exceeded its original deadline", "laterLaunchesClosed": True, "cleanupProven": False,
            "completion": None, "normalBoundaryDisposition": None, "normalBoundaryCleanupErrors": [], "androidPublication": None,
            "projectRecoveryNegative": owner_failure(), "commands": [{"phase": phase} for phase in L.root_phases(value)[:-1]]}
        stop = {**deepcopy(start), "unit": {**unit, "Result": "exit-code"},
            "completion": {"SERVICE_RESULT": "exit-code", "EXIT_CODE": "exited", "EXIT_STATUS": "1"},
            "applicationFinal": False, "experimentClientJoined": False,
            "stopBoundary": {"activeState": "deactivating", "subState": "stop-post", "controlPid": 100, "mainPid": 0},
            "commands": [{"phase": "stop-unit-show", "exitCode": 0}]}
        self.assertIsNone(L.shell_recovery_negative_finality(value, start, error, stop, 1, "c" * 64, "d" * 64))
        for path, replacement in ((["invocationId"], "e" * 32), (["unit", "Result"], "success"),
                (["completion", "EXIT_STATUS"], "0"), (["stopBoundary", "mainPid"], 101),
                (["events", "pids.events", "max"], 1), (["applicationFinal"], True), (["experimentClientJoined"], True)):
            changed = deepcopy(stop); current = changed
            for key in path[:-1]: current = current[key]
            current[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(L.Refused):
                L.shell_recovery_negative_finality(value, start, error, changed, 1, "c" * 64, "d" * 64)
        with self.assertRaises(L.Refused): L.shell_recovery_negative_finality(value, start, error, stop, 0, "c" * 64, "d" * 64)
        # The ordinary gate is unchanged and must refuse this expected failed unit.
        with self.assertRaises(L.Refused): L.verify_finality(start, stop, 1)

    def test_distinct_negative_interval_requires_all_original_pins_and_actual_recheck_flags(self):
        value, start, stop, raw = interval_documents()
        final = L.decode(raw[L.SHELL_RECOVERY_INTERVAL])["loader"]
        # This focused parser contract intercepts only the existing common
        # loader proof consumer. It is not full loader or native evidence.
        with patch.object(L, "shell_closed_loader") as loader:
            self.assertIsNone(L.shell_recovery_negative_interval_data(value, start, stop, raw))
            loader.assert_called_once_with(value, raw, negative_interval=final)
        for which, path, replacement in (
                ("before", ["scope"], "loader-final"), ("before", ["loader", "payloadAdmitted"], False),
                ("before", ["loader", "runtimeDataRechecked"], True), ("before", ["loader", "namespaces", "mnt"], [1, 9]),
                ("before", ["publication", "sha256"], "0" * 64), ("before", ["deadline"], 1001),
                ("interval", ["schemaVersion"], True), ("interval", ["scope"], "normal-success"),
                ("interval", ["sourceSha"], "e" * 40), ("interval", ["entrySha256"], "e" * 64),
                ("interval", ["handoffSha256"], "e" * 64), ("interval", ["invocationId"], "e" * 32),
                ("interval", ["deadline"], 1001), ("interval", ["publicationUnchanged"], 1),
                ("interval", ["before", "sha256"], "0" * 64), ("interval", ["publication", "size"], 0),
                ("interval", ["loader", "runtimeDataRechecked"], False),
                ("interval", ["loader", "runtimeDataRechecked"], 1),
                ("interval", ["loader", "payloadAdmitted"], False),
                ("interval", ["loader", "bindings", "/inert-never-opened/python", "sha256"], "e" * 64),
                ("interval", ["loader", "runtimeData", "records", 0, "sha256"], "e" * 64)):
            changed = deepcopy(raw); leaf = L.SHELL_RECOVERY_LOADER_BEFORE if which == "before" else L.SHELL_RECOVERY_INTERVAL
            document = L.decode(changed[leaf]); target = document
            for key in path[:-1]: target = target[key]
            target[path[-1]] = replacement; changed[leaf] = L.canonical(document)
            # Re-pin the edited outer bytes, so internal original correspondence
            # (not merely a stale file digest) must reject the mutation.
            altered_stop = {"interval": {"path": L.SHELL_RECOVERY_INTERVAL, "size": len(changed[L.SHELL_RECOVERY_INTERVAL]),
                "sha256": hashlib.sha256(changed[L.SHELL_RECOVERY_INTERVAL]).hexdigest()}}
            with self.subTest(which=which, path=path), patch.object(L, "shell_closed_loader") as loader:
                with self.assertRaises(L.Refused): L.shell_recovery_negative_interval_data(value, start, altered_stop, changed)
                loader.assert_not_called()
        for leaf in (L.SHELL_RECOVERY_LOADER_BEFORE, L.SHELL_RECOVERY_INTERVAL, "published-before-upgrade.txt"):
            changed = dict(raw); del changed[leaf]
            with self.subTest(missing=leaf), self.assertRaises(L.Refused): L.shell_recovery_negative_interval_data(value, start, stop, changed)
        for pin in (None, {**stop["interval"], "sha256": "0" * 64}, {**stop["interval"], "path": "loader-final.json"}):
            with self.subTest(pin=pin), self.assertRaises(L.Refused):
                L.shell_recovery_negative_interval_data(value, start, {"interval": pin}, raw)
        with patch.object(L, "shell_closed_loader", side_effect=L.Refused("synthetic common-loader mismatch")):
            with self.assertRaises(L.Refused): L.shell_recovery_negative_interval_data(value, start, stop, raw)
        with self.assertRaises(L.Refused): L.shell_closed_loader(selection(False), {}, negative_interval={})

    def test_prelaunch_snapshot_retains_the_passed_actual_admitted_proof(self):
        value, start, _, raw = interval_documents(); before = L.decode(raw[L.SHELL_RECOVERY_LOADER_BEFORE])
        original = L.decode(raw["published-before-upgrade.txt"])["P0"]
        for failed in (False, True):
            with ExitStack() as stack:
                stack.enter_context(patch.object(L, "_FAILED", failed)); stack.enter_context(patch.object(L, "_END", 200))
                stack.enter_context(patch.object(L.time, "monotonic", return_value=100))
                source = stack.enter_context(patch.object(L, "_shell_recovery_negative_public", return_value=(
                    raw["published-before-upgrade.txt"], before["publication"])))
                retained = stack.enter_context(patch.object(L, "_retain"))
                if failed:
                    with self.assertRaises(L.Refused):
                        L._shell_recovery_negative_loader_before(value, start, start["handoffSha256"], before["loader"], original)
                    source.assert_not_called(); retained.assert_not_called()
                else:
                    L._shell_recovery_negative_loader_before(value, start, start["handoffSha256"], before["loader"], original)
                    source.assert_called_once_with("published-before-upgrade.txt")
                    retained.assert_called_once_with(L.SHELL_RECOVERY_LOADER_BEFORE, raw[L.SHELL_RECOVERY_LOADER_BEFORE])

    def test_original_stop_interval_refuses_every_recheck_failure_before_retention(self):
        value, start, _, raw = interval_documents(); original = L.decode(raw["published-before-upgrade.txt"])["P0"]
        for failed in (None, "tree", "data", "loader", "denials", "late"):
            calls, files, clock = [], [], [132.0]
            def public(name):
                calls.append(name)
                return raw[name], {"path": name, "size": len(raw[name]), "sha256": hashlib.sha256(raw[name]).hexdigest()}
            def check(phase):
                calls.append(phase)
                if phase == failed: raise L.Refused("synthetic " + phase + " interval failure")
            def tree(*args, **kwargs): check("tree"); return deepcopy(original)
            def data(proof): check("data"); proof["runtimeDataRechecked"] = True
            def loader(proof):
                check("loader")
                if failed == "late": clock[0] = 141.0
            def denials(domain): check("denials")
            def retain(name, payload):
                calls.append("retain"); files.append({"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
            domain = {"original": "inert-test-data"}
            with ExitStack() as stack:
                for name, replacement in {"_FAILED": False, "_END": 140.0, "_FILES": files}.items():
                    stack.enter_context(patch.object(L, name, replacement))
                stack.enter_context(patch.object(L.time, "monotonic", side_effect=lambda: clock[0]))
                stack.enter_context(patch.object(L, "_shell_recovery_negative_public", side_effect=public))
                stack.enter_context(patch.object(L, "_tree", side_effect=tree))
                stack.enter_context(patch.object(L, "_shell_data_check", side_effect=data))
                stack.enter_context(patch.object(L, "_installed_loader_check", side_effect=loader))
                stack.enter_context(patch.object(L, "_domain_events", return_value=domain))
                stack.enter_context(patch.object(L, "_no_denials", side_effect=denials))
                retained = stack.enter_context(patch.object(L, "_retain", side_effect=retain))
                if failed is None:
                    actual_domain, pin = L._shell_recovery_negative_interval(value, start, start["handoffSha256"], domain)
                    self.assertIs(actual_domain, domain); self.assertEqual(pin, files[0])
                    self.assertEqual(pin["path"], L.SHELL_RECOVERY_INTERVAL)
                    self.assertEqual(calls, [L.SHELL_RECOVERY_LOADER_BEFORE, "published-before-upgrade.txt", "tree", "data", "loader", "denials", "retain"])
                else:
                    with self.subTest(failure=failed), self.assertRaises(L.Refused):
                        L._shell_recovery_negative_interval(value, start, start["handoffSha256"], domain)
                    retained.assert_not_called(); self.assertEqual(files, [])

    def test_negative_interval_is_between_authentic_failed_owner_and_post_client_fixture(self):
        source = (SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_text()
        start = source.split("def unit_start():", 1)[1].split("def lifecycle_states(", 1)[0]
        self.assertLess(start.index("expected = _installed_payload(value, loader, original)"),
                        start.index("_shell_recovery_negative_loader_before(value, start, request_sha, loader, original)"))
        self.assertLess(start.index("_shell_recovery_negative_loader_before(value, start, request_sha, loader, original)"),
                        start.index("namespace = _shell_fixtures_prepare(value)"))
        stop = source.split("def _shell_recovery_negative_stop(", 1)[1].split("def shell_recovery_negative_finality(", 1)[0]
        self.assertLess(stop.index("_domain_admission(value, observed.stdout, stop_boundary=True)"), stop.index("_no_denials(domain)"))
        self.assertLess(stop.index("shell_recovery_negative_finality(value, start, error, stop"),
                        stop.index("_shell_recovery_negative_interval(value, start, request_sha, domain)"))
        self.assertLess(stop.index("_shell_recovery_negative_interval(value, start, request_sha, domain)"),
                        stop.index('_retain("project-recovery-negative-stop.json"'))
        self.assertIn('_END == min(value["deadline"], stop_end)', stop)
        self.assertIn('"experimentClientJoined": False', stop)
        unit_stop = source.split("def unit_stop():", 1)[1].split("def installed_closed_result(", 1)[0]
        self.assertIn('_END = min(value["deadline"], stop_end)', unit_stop)
        collector = source.split("def verify_project_recovery_negative_service_result(", 1)[1].split("def main():", 1)[0]
        self.assertLess(collector.index("client_result.returncode == 1"), collector.index("shell_recovery_negative_interval_data(value, start, stop, raw_files)"))
        self.assertLess(collector.index("shell_recovery_negative_interval_data(value, start, stop, raw_files)"),
                        collector.index("_shell_recovery_inventory(value,"))
        self.assertIn('"loaderFinalIntervalQualified": True', collector)
        self.assertNotIn("verify_service_result(", collector)


if __name__ == "__main__":
    unittest.main()
