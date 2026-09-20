"""Focused inert route contracts. Never main, tools, candidates, network or builds.

Filesystem/native seams are mocks. These tests do not admit any actual H,
review kit, hosted interpreter, prepared archive, M/Q or original execution.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

SOURCE = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location("_inert_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load("ci_foundation")
data = load("conventional_runtime_data")


def record(name, byte="a"):
    return {"path": name, "size": 5, "sha256": byte * 64}


def artifact(names):
    return {"repository": "inert/repository", "sourceSha": "b" * 40, "runId": "1", "attempt": 1,
            "artifactId": "2", "files": [record(name) for name in sorted(names)]}


SOURCE_KIT = ("hosted-evidence.tar", "hosted-summary.json", "retained-files.json")
REVIEW_NAMES = ("components.json", "notice-inventory.json", "notices/NOTICE.txt",
                "reviews/configuration-review.txt", "reviews/obligation-review.txt")
PREPARE = {"sourceArtifact": artifact(SOURCE_KIT),
           "reviewFiles": [record(name) for name in REVIEW_NAMES], "outputInventorySha256": "a" * 64}
SMOKE = {"preparedArtifact": artifact((*REVIEW_NAMES, *("source-kit/" + name for name in SOURCE_KIT),
                                     "prepared-runtime.tar", "preparation.json", "copy-result.json",
                                     "copy-report.json", "source-bindings.json", "outer.json")),
         "manifestSha256": "c" * 64, "protocolSha256": "d" * 64}
HOST = {"trustModel": "github-hosted-platform-tcb-v1", "imageOS": "ubuntu24", "imageVersion": "20260907.300.1",
        "python": record("/usr/bin/python3.12")}
CONTEXT = {"source": "/inert-source", "root": "/inert-root", "sourceSha": "b" * 40, "sourceTree": "e" * 40,
           "repository": "inert/repository", "runId": "1", "attempt": 1, "platform": "linux"}


def prepared():
    return {"manifestSha256": SMOKE["manifestSha256"], "protocolSha256": SMOKE["protocolSha256"],
            "files": [record(name) for name in ("core.zip", "engine_bootstrap.py", "github-ca.pem",
                      "python/bin/python3", "python/lib/libcrypto.so.3", "python/lib/libssl.so.3")]}


def probe_value():
    return {"schemaVersion": 1, "profile": data.PROFILE, "scope": data.PROBE_SCOPE, "status": "passed",
        "bindings": prepared(), "notVerified": data.NOT_VERIFIED, "outerOriginalWaitRequired": True,
        "observed": {"pythonVersion": [3, 14, 7], "builtinNames": ["inert"], "expatVersion": "expat_2.8.2",
            "xmlValid": True, "xmlMalformedRefused": True, "nofile": [128, 128], "opensslVersion": "OpenSSL 3.5.8 inert",
            "ignoreUnexpectedEof": 128, "caCertificates": 1, "privateMappedLibraries": ["libcrypto.so.3", "libssl.so.3"],
            "coreImportsFromPreparedZip": True}}


def smoke_value():
    source = {"sourceSha": "b" * 40, "host": "linux", "target": data.TARGET, "runtimeMode": "trusted-development-only",
        "coreZipSha256": "a" * 64, "engineSha256": "d" * 64, "bootstrapSha256": "a" * 64,
        "cargoLockSha256": "a" * 64, "fixtureSha256": "a" * 64}
    flags = ("inspection_joined", "acquisition_joined", "spawned", "waited", "exit_success", "writer_joined",
             "writer_complete", "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined", "driver_joined", "watchdog_joined")
    cases = [{"case": name, "passed": True, "failureCode": None, "elapsedMs": 10,
              "evidenceKind": "actual-passive-child", "results": [{"return": "ok"}], "notes": {},
              "registeredOwners": 0, "disabled": False,
              "owners": [{"id": "query-1", "terminal": True, "unknownLatched": False, "permitRetained": False,
                          "native": {**dict.fromkeys(flags, True), "stdout_bytes": 123, "stderr_bytes": 0}}]}
             for name in ("core-capabilities", "core-zip-catalog")]
    return {"schemaVersion": 1, "profile": data.PROFILE, "scope": data.SMOKE_SCOPE, "status": "passed",
            "allOwnersSettled": True, "failureCode": None, "notVerified": data.NOT_VERIFIED,
            "outerOriginalWaitRequired": True, "cases": cases,
            "bindings": {"source": source, "prepared": {"profile": data.PROFILE, **prepared(),
                "coreSelection": "prepared-zip-only", "checkoutBootstrapEqualsPrepared": True}}}


class AdmissionContracts(unittest.TestCase):
    def test_missing_admissions_refuse_before_helper_import_paths_or_output(self):
        for scope in helper.CONVENTIONAL_SCOPES:
            with self.subTest(scope=scope), patch.object(helper, "conventional_module") as modules, \
                    patch.object(helper, "conventional_context") as context, self.assertRaises(helper.CheckFailure):
                helper.conventional_phase("conventional-admit", scope)
            modules.assert_not_called()
            context.assert_not_called()
        self.assertIsNone(helper.CONVENTIONAL_PREPARE_INPUTS)
        self.assertIsNone(helper.CONVENTIONAL_SMOKE_INPUTS)
        self.assertIsNone(helper.CONVENTIONAL_HOSTED_PYTHON)

    def test_caller_environment_is_not_artifact_or_mq_authority(self):
        with patch.dict(helper.os.environ, {"MRK_BUNDLED_RUNTIME_MANIFEST_SHA256": "c" * 64,
                "MRK_BUNDLED_PROTOCOL_SHA256": "d" * 64, "MRK_DESKTOP_EXPECTED_SHA": "b" * 40,
                "CONVENTIONAL_PREPARE_INPUTS": json.dumps(PREPARE)}, clear=True), self.assertRaises(helper.CheckFailure):
            helper.conventional_admission(helper.CONVENTIONAL_SMOKE_SCOPE)

    def test_literal_contract_and_copier_or_probe_pins_are_separate(self):
        copier = SimpleNamespace(APPROVED_SOURCE_OUTPUT_SHA256="a" * 64, APPROVED_SOURCE_COMPONENTS_SHA256="a" * 64,
            APPROVED_SOURCE_NOTICES_SHA256="a" * 64, APPROVED_SOURCE_COPIER_PYTHON_SHA256="a" * 64)
        probe = SimpleNamespace(APPROVED_PREPARED_MANIFEST_SHA256="c" * 64, APPROVED_PROTOCOL_SHA256="d" * 64)
        modules = {"conventional_runtime_data": data, "prepare_cpython_source_payload": SimpleNamespace(P=copier),
                   "probe_cpython_source_runtime": probe}
        with patch.object(helper, "CONVENTIONAL_PREPARE_INPUTS", PREPARE), patch.object(helper, "CONVENTIONAL_SMOKE_INPUTS", SMOKE), \
                patch.object(helper, "CONVENTIONAL_HOSTED_PYTHON", HOST), patch.object(helper, "conventional_module", side_effect=modules.__getitem__):
            self.assertIs(helper.conventional_admission(helper.CONVENTIONAL_PREPARE_SCOPE)[1], PREPARE)
            self.assertIs(helper.conventional_admission(helper.CONVENTIONAL_SMOKE_SCOPE)[1], SMOKE)
            bad_hosts = [{"python": HOST["python"], "supportFiles": []},
                         {"python": HOST["python"], "supportFiles": [record("/usr/lib/inert-support")]},
                         {**HOST, "supportFiles": []}, {**HOST, "trustModel": "complete-interpreter-closure"},
                         {**HOST, "imageOS": "ubuntu22"}, {**HOST, "imageVersion": ""}, {**HOST, "imageVersion": True},
                         {**HOST, "python": record("/usr/local/bin/python3.12")},
                         {**HOST, "python": {**HOST["python"], "size": 0}}]
            for host in bad_hosts:
                for scope in helper.CONVENTIONAL_SCOPES:
                    with self.subTest(host=host, scope=scope), patch.object(helper, "CONVENTIONAL_HOSTED_PYTHON", host), \
                            self.assertRaises((helper.CheckFailure, data.Refused)):
                        helper.conventional_admission(scope)
            bad_reviews = [[], artifact(REVIEW_NAMES), list(reversed(PREPARE["reviewFiles"])),
                           sorted([*PREPARE["reviewFiles"], record("source-kit.tar")], key=lambda row: row["path"]),
                           [*PREPARE["reviewFiles"], PREPARE["reviewFiles"][-1]]]
            bad_reviews += [[row for row in PREPARE["reviewFiles"] if row["path"] != name] for name in REVIEW_NAMES]
            bad_reviews += [[{**row, "sha256": "f" * 64} if row["path"] == name else row
                             for row in PREPARE["reviewFiles"]] for name in ("components.json", "notice-inventory.json")]
            for rows in bad_reviews:
                with self.subTest(review=rows), patch.object(helper, "CONVENTIONAL_PREPARE_INPUTS", {**PREPARE, "reviewFiles": rows}), \
                        self.assertRaises((helper.CheckFailure, data.Refused)):
                    helper.conventional_admission(helper.CONVENTIONAL_PREPARE_SCOPE)
            old = {key: value for key, value in PREPARE.items() if key != "reviewFiles"}
            with patch.object(helper, "CONVENTIONAL_PREPARE_INPUTS", {**old, "reviewArtifact": artifact(REVIEW_NAMES)}), \
                    self.assertRaises(helper.CheckFailure):
                helper.conventional_admission(helper.CONVENTIONAL_PREPARE_SCOPE)
            for leaf in SOURCE_KIT:
                bad = deepcopy(SMOKE)
                bad["preparedArtifact"]["files"] = [row for row in bad["preparedArtifact"]["files"]
                                                    if row["path"] != "source-kit/" + leaf]
                with self.subTest(missing=leaf), patch.object(helper, "CONVENTIONAL_SMOKE_INPUTS", bad), \
                        self.assertRaises(helper.CheckFailure):
                    helper.conventional_admission(helper.CONVENTIONAL_SMOKE_SCOPE)
            copier.APPROVED_SOURCE_COPIER_PYTHON_SHA256 = None
            with self.assertRaises(helper.CheckFailure):
                helper.conventional_admission(helper.CONVENTIONAL_PREPARE_SCOPE)
            # A's missing copier admission does not silently authorize/close B.
            self.assertIs(helper.conventional_admission(helper.CONVENTIONAL_SMOKE_SCOPE)[1], SMOKE)
            probe.APPROVED_PROTOCOL_SHA256 = "e" * 64
            with self.assertRaises(helper.CheckFailure):
                helper.conventional_admission(helper.CONVENTIONAL_SMOKE_SCOPE)

    def test_scopes_cannot_cross_old_jobs_or_each_other(self):
        for scope, phase in ((helper.CONVENTIONAL_PREPARE_SCOPE, "conventional-smoke"),
                             (helper.CONVENTIONAL_SMOKE_SCOPE, "conventional-prepare"),
                             (helper.BOUNDARY_SCOPE, "conventional-admit"),
                             (helper.CONVENTIONAL_PREPARE_SCOPE, "native")):
            with self.subTest(scope=scope, phase=phase), patch.object(helper, "conventional_admission") as admit, \
                    self.assertRaises(helper.CheckFailure):
                helper.conventional_phase(phase, scope)
            admit.assert_not_called()

    def test_fixed_refs_and_event_specific_pins_refuse_before_paths(self):
        for scope, route in ((helper.CONVENTIONAL_PREPARE_SCOPE, "conventional-prepare"),
                             (helper.CONVENTIONAL_SMOKE_SCOPE, "conventional-smoke")):
            ref = "refs/heads/verify/desktop-" + route
            base = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                    "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": HOST["imageVersion"],
                    "MRK_DESKTOP_HOSTED_CHECKS": scope,
                    "GITHUB_SHA": CONTEXT["sourceSha"], "GITHUB_REPOSITORY": CONTEXT["repository"],
                    "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW_SHA": CONTEXT["sourceSha"],
                    "GITHUB_REF": ref, "GITHUB_WORKFLOW_REF": f"{CONTEXT['repository']}/.github/workflows/desktop-foundation.yml@{ref}",
                    "GITHUB_WORKSPACE": str(SOURCE), "RUNNER_TEMP": "/inert-temp",
                    "MRK_DESKTOP_EXPECTED_SHA": CONTEXT["sourceSha"], "MRK_DESKTOP_DISPATCH_SCOPE": route,
                    "MRK_PUSH_EVENT_AFTER": CONTEXT["sourceSha"]}
            for event in ("push", "workflow_dispatch"):
                wrong_refs = ("refs/heads/feature/desktop-application", "refs/heads/verify/desktop-windows-snapshot",
                              "refs/heads/verify/desktop-" + ("conventional-smoke" if route == "conventional-prepare" else "conventional-prepare"),
                              "refs/tags/verify/desktop-" + route)
                changes = [{}, *({"GITHUB_REF": other, "GITHUB_WORKFLOW_REF":
                                f"{CONTEXT['repository']}/.github/workflows/desktop-foundation.yml@{other}"} for other in wrong_refs),
                           {"GITHUB_WORKFLOW_REF": "inert/other/.github/workflows/desktop-foundation.yml@" + ref},
                           {"GITHUB_WORKFLOW_SHA": "f" * 40}, {"GITHUB_RUN_ATTEMPT": "2"},
                           {"GITHUB_EVENT_NAME": "pull_request"}]
                changes += ([{"MRK_PUSH_EVENT_AFTER": ""}, {"MRK_PUSH_EVENT_AFTER": "f" * 40}] if event == "push"
                            else [{"MRK_DESKTOP_EXPECTED_SHA": ""}, {"MRK_DESKTOP_EXPECTED_SHA": "f" * 40},
                                  {"MRK_DESKTOP_DISPATCH_SCOPE": "foundation"}, {"MRK_DESKTOP_DISPATCH_SCOPE": ""}])
                for change in changes:
                    inert = SimpleNamespace(directory=Mock())
                    with self.subTest(route=route, event=event, change=change), \
                            patch.dict(helper.os.environ, {**base, "GITHUB_EVENT_NAME": event, **change}, clear=True), \
                            patch.object(helper, "conventional_host"), patch.object(Path, "resolve", lambda path, **kwargs: path), \
                            patch.object(helper.shutil, "which", return_value="/inert-git"), \
                            patch.object(helper, "source_unchanged") as source, patch.object(helper, "clean_environment", return_value={}), \
                            patch.object(helper, "run", return_value="e" * 40) as run:
                        if change:
                            with self.assertRaises(helper.CheckFailure):
                                helper.conventional_context(scope, inert)
                            inert.directory.assert_not_called()
                            source.assert_not_called()
                            run.assert_not_called()
                        else:
                            context = helper.conventional_context(scope, inert)
                            self.assertEqual(context["root"], "/inert-temp/mrk-desktop-" + route + "-1-1")
                            self.assertEqual(context["executionScope"], scope)
                            source.assert_called_once()


class DataContracts(unittest.TestCase):
    def test_only_logical_ca_uses_fixed_checkout_controls_path(self):
        bootstraps = ("engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
                      "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py")
        preparer = SimpleNamespace(BOOTSTRAPS=bootstraps, GITHUB_CA_NAME="github-ca.pem",
                                  files=lambda root: [root / "__init__.py"])
        names = sorted([*("desktop/" + name for name in (*bootstraps, "github-ca.pem")),
                        "desktop/tools/prepare_runtime.py", "src/mobile_release/__init__.py"])
        rows = [record("/work/inputs/core-source/" + name) for name in names]
        inert = SimpleNamespace(decode=data.decode, records=data.records, bound=Mock())
        with patch.object(helper, "conventional_module", return_value=preparer):
            helper.conventional_core(inert, Path("/inert-checkout"), data.canonical(rows),
                                     retained_source=Path("/inert-h/inputs/core-source"))
        checked = [call.args[0] for call in inert.bound.call_args_list]
        self.assertIn(Path("/inert-checkout/desktop/cpython-source-inputs/github-ca.pem"), checked)
        self.assertNotIn(Path("/inert-checkout/desktop/github-ca.pem"), checked)
        self.assertIn(Path("/inert-h/inputs/core-source/desktop/github-ca.pem"), checked)

    def test_changed_artifact_and_unsafe_or_duplicate_records_refuse(self):
        with patch.object(data, "file_record", return_value=record("x", "b")), self.assertRaises(data.Refused):
            data.bound(Path("/inert/x"), record("x"))
        kit = Path("/inert-source/desktop/cpython-source-inputs/conventional-review")
        for change in ("none", "missing", "extra", *REVIEW_NAMES):
            names = list(REVIEW_NAMES)
            if change == "missing": names.pop()
            if change == "extra": names.append("notices/unreviewed.txt")
            preparer = SimpleNamespace(files=Mock(return_value=[kit / name for name in names]))
            with self.subTest(review=change), patch.object(helper, "conventional_module", return_value=preparer), \
                    patch.object(data, "file_record", side_effect=lambda path, limit:
                                 record(path.name, "b" if path == kit / change else "a")) as reads:
                if change == "none":
                    self.assertEqual(helper.conventional_files(data, kit, PREPARE["reviewFiles"]), data.records(PREPARE["reviewFiles"]))
                    self.assertEqual(reads.call_count, len(REVIEW_NAMES))
                else:
                    with self.assertRaises((helper.CheckFailure, data.Refused)):
                        helper.conventional_files(data, kit, PREPARE["reviewFiles"])
                    if change in {"missing", "extra"}: reads.assert_not_called()
        for values in ([record("../escape")], [record("x"), record("x")], [record("x"), record("X")],
                       [{**record("x"), "size": True}], [{**record("x"), "sha256": "A" * 64}]):
            with self.subTest(values=values), self.assertRaises(data.Refused):
                data.records(values)

    def test_archive_close_flush_and_readback_errors_never_return_publishable_record(self):
        # All path/stream operations are inert; do not create even a test tar.
        rows = [record("manifest.json"), record("python/bin/python3")]
        for failure in ("archive-close", "flush", "fsync", "readback"):
            output, original, writer, reader = (MagicMock() for _ in range(4))
            output.__enter__.return_value = output
            original.__enter__.return_value = original
            writer.__enter__.return_value = writer
            reader.__enter__.return_value = reader
            reader.__iter__.return_value = iter([])  # Missing original members.
            if failure == "archive-close": writer.__exit__.side_effect = OSError("inert close")
            if failure == "flush": output.flush.side_effect = OSError("inert flush")
            with self.subTest(failure=failure), patch.object(data, "bound"), \
                    patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o100755)), \
                    patch.object(Path, "open", return_value=output), patch.object(data, "_open", return_value=(original, None)), \
                    patch.object(data, "state", return_value=(1,)), patch.object(data.os, "fstat"), \
                    patch.object(data.os, "fsync", side_effect=OSError("inert fsync") if failure == "fsync" else None), \
                    patch.object(data.tarfile, "open", side_effect=[writer, reader]), \
                    patch.object(data, "file_record", return_value=record("prepared-runtime.tar")), \
                    self.assertRaises((OSError, data.Refused)):
                data.pack_runtime(Path("/inert/runtime"), rows, Path("/inert/prepared-runtime.tar"))

    def test_outer_original_wait_and_zero_are_not_a_serialized_caveat(self):
        producer = helper.conventional_producer(CONTEXT)
        value = {"schemaVersion": 1, "scope": data.PREPARE_SCOPE, **producer, "originalWait": True,
                 "exitCode": 0, "outputWritersClosed": True, "statusWriterCloseGate": "original-step-success-required"}
        data.outer(value, data.PREPARE_SCOPE, producer)
        for key, wrong in (("originalWait", False), ("exitCode", True), ("exitCode", 1), ("outputWritersClosed", False),
                           ("attempt", True), ("scope", data.SMOKE_SCOPE)):
            with self.subTest(key=key, wrong=wrong), self.assertRaises(data.Refused):
                data.outer({**value, key: wrong}, data.PREPARE_SCOPE, producer)

    def test_probe_scope_exact_bindings_and_success_observations(self):
        self.assertEqual(data.probe_receipt(probe_value(), prepared(), ["inert"])["scope"], data.PROBE_SCOPE)
        for change in (lambda x: x.update(scope=data.SMOKE_SCOPE),
                       lambda x: x["bindings"].update(manifestSha256="f" * 64),
                       lambda x: x["bindings"]["files"].pop(),
                       lambda x: x["observed"].update(xmlMalformedRefused=False),
                       lambda x: x["observed"].update(expatVersion="expat_2.7.4"),
                       lambda x: x.update(schemaVersion=True)):
            value = probe_value(); change(value)
            with self.assertRaises(data.Refused):
                data.probe_receipt(value, prepared(), ["inert"])
        with self.assertRaises(ValueError): data.decode(b'{"status":"passed","status":"failed"}')

    def test_smoke_requires_exact_two_zip_cases_and_every_serialized_native_fact(self):
        value = smoke_value()
        data.smoke_receipt(value, prepared(), value["bindings"]["source"])
        mutations = [lambda x: x["cases"].pop(), lambda x: x["cases"].reverse(),
            lambda x: x.update(scope="passive-hosted-v2"), lambda x: x.update(allOwnersSettled=False),
            lambda x: x["bindings"]["source"].update(engineSha256="e" * 64),
            lambda x: x["bindings"]["prepared"]["files"].pop(),
            lambda x: x["cases"][0].update(disabled=True), lambda x: x["cases"][0].update(registeredOwners=True),
            lambda x: x["cases"][0]["owners"][0].update(permitRetained=True),
            lambda x: x["cases"][0]["owners"][0].update(unknownLatched=True),
            lambda x: x["cases"][0]["owners"][0]["native"].update(observer_joined=True)]
        mutations += [lambda x, field=field: x["cases"][0]["owners"][0]["native"].update({field: False})
                      for field in value["cases"][0]["owners"][0]["native"] if field not in {"stdout_bytes", "stderr_bytes"}]
        for mutate in mutations:
            candidate = deepcopy(value); mutate(candidate)
            with self.assertRaises(data.Refused):
                data.smoke_receipt(candidate, prepared(), value["bindings"]["source"])


class ProgressionContracts(unittest.TestCase):
    def test_committed_review_rechecks_gate_copy_and_original_h_delivery(self):
        root = Path(CONTEXT["root"])
        kit = Path(CONTEXT["source"]) / "desktop/cpython-source-inputs/conventional-review"
        h = PREPARE["sourceArtifact"]
        h_rows = data.records(h["files"])
        receipts = [record("work/receipts/result.json"), record("work/receipts/source-output.json")]
        manifest = {"protocolSha256": "d" * 64, "files": [record("core.zip")]}
        manifest_raw = data.canonical(manifest)
        result = {"manifestSha256": hashlib.sha256(manifest_raw).hexdigest(), "protocolSha256": "d" * 64,
                  "qualification": "prepared-not-native-verified"}
        copied = {"operation": "source-publisher-copy-completed", "reportSha256": "a" * 64}
        summary = {"schema": "mrk-cpython-source-hosted-result-1", "profile": data.PROFILE,
                   "state": "original-source-build-evidence-retained", **{key: h[key] for key in ("sourceSha", "runId", "attempt")},
                   "originalClientExitCode": 0, "originalUserdelExitCode": 0,
                   "nativeQualification": "not-established", "supplyAcceptance": "not-established",
                   "retained": {field: {**h_rows[leaf], "path": "/var/tmp/mrk-cpython-source-public-v1/" + leaf}
                                for field, leaf in (("archive", "hosted-evidence.tar"), ("inventory", "retained-files.json"))}}
        bodies = {"hosted-summary.json": data.canonical(summary), "manifest.json": manifest_raw,
                  "core-source-files.json": b"[]\n", "retained-files.json": data.canonical({
                      "schema": "mrk-cpython-source-retention-1", "profile": data.PROFILE,
                      "coverage": "conservative-component-review-required", "files": receipts})}
        for failure in ("before", "after", None):
            checked = []
            def inventory(_data, path, files):
                checked.append(path)
                if path == kit and checked.count(kit) == (1 if failure == "before" else 2) and failure:
                    raise helper.CheckFailure("inert changed committed review")
                return data.records(files)
            copier = SimpleNamespace(prepare_source=Mock(return_value=copied))
            preparer = SimpleNamespace(prepare=Mock(return_value=result), files=Mock(return_value=[
                root / "runtime/core.zip", root / "runtime/manifest.json"]))
            modules = {"prepare_cpython_source_payload": SimpleNamespace(P=copier), "prepare_runtime": preparer}
            inert = SimpleNamespace(canonical=data.canonical, decode=data.decode, same=data.same,
                PROFILE=data.PROFILE, NOT_VERIFIED=data.NOT_VERIFIED,
                read=Mock(side_effect=lambda path, limit=0: bodies[path.name]), write=Mock(), copy=Mock(), unpack=Mock(),
                file_record=Mock(side_effect=lambda path, limit=0: {"path": path.name, "size": len(manifest_raw),
                    "sha256": result["manifestSha256"]} if path.name == "manifest.json" else record(path.name)),
                pack_runtime=Mock(return_value=record("prepared-runtime.tar")))
            with self.subTest(failure=failure), patch.object(helper, "conventional_files", side_effect=inventory) as inputs, \
                    patch.object(helper, "conventional_module", side_effect=modules.__getitem__), \
                    patch.object(helper, "conventional_core"), patch.object(helper, "conventional_recheck"), \
                    patch.object(helper, "fixed_file_inventory", return_value=[record("inert-helper")]), patch.object(Path, "mkdir"):
                if failure:
                    with self.assertRaises(helper.CheckFailure):
                        helper.conventional_prepare(CONTEXT, inert, PREPARE)
                else:
                    helper.conventional_prepare(CONTEXT, inert, PREPARE)
            self.assertEqual(inputs.call_args_list[1].args, (inert, kit, PREPARE["reviewFiles"]))
            if failure == "before":
                copier.prepare_source.assert_not_called()
                preparer.prepare.assert_not_called()
            else:
                copier.prepare_source.assert_called_once()
                self.assertEqual(copier.prepare_source.call_args.args[2:6],
                                 (root / "evidence", kit / "components.json", kit / "notices", kit / "notice-inventory.json"))
                self.assertEqual(checked, [root / "source-artifact", kit, root / "source-artifact", kit])
            if failure:
                inert.pack_runtime.assert_not_called()
                self.assertFalse(any(call.args[0].name == "preparation.json" for call in inert.write.call_args_list))
            else:
                inert.pack_runtime.assert_called_once()
                self.assertEqual(inert.pack_runtime.call_args.args[2], root / "public/prepared-runtime.tar")
                kit_copies = [call.args for call in inert.copy.call_args_list if call.args[1].parent == root / "public/source-kit"]
                self.assertEqual(kit_copies, [(root / "source-artifact" / leaf, root / "public/source-kit" / leaf, h_rows[leaf])
                                              for leaf in SOURCE_KIT])
                evidence = [call.args for call in inert.copy.call_args_list if call.args[1].parent == root / "evidence"]
                self.assertEqual(evidence, [(root / "h" / row["path"], root / "evidence" / Path(row["path"]).name, row)
                                             for row in receipts] + [(kit / row["path"], root / "evidence" / Path(row["path"]).name, row)
                                             for row in PREPARE["reviewFiles"] if row["path"].startswith("reviews/")])
                publication = data.decode(next(call.args[1] for call in inert.write.call_args_list
                                              if call.args[0].name == "preparation.json"))
                self.assertTrue(data.same(publication["sourceKit"], h["files"]))

    def test_exact_original_h_triple_join_precedes_unpack_and_probe(self):
        rows = data.records(SMOKE["preparedArtifact"]["files"])
        producer = {key: SMOKE["preparedArtifact"][key] for key in ("repository", "sourceSha", "runId", "attempt")}
        copied = {"operation": "source-publisher-copy-completed", "evidenceKind": "descriptive-source-copy-mapping",
                  "qualification": "no-native-supply-or-legal-qualification", "reportSha256": rows["copy-report.json"]["sha256"]}
        shared = [record("inert-helper")]
        value = {"manifestSha256": SMOKE["manifestSha256"], "protocolSha256": SMOKE["protocolSha256"],
                 "qualification": "prepared-not-native-verified", "scope": data.PREPARE_SCOPE, "producer": producer,
                 "archive": rows["prepared-runtime.tar"], "sourceArtifact": {key: PREPARE["sourceArtifact"][key]
                     for key in ("repository", "sourceSha", "runId", "attempt", "artifactId")},
                 "helperFiles": shared, "copyResult": copied, "sourceKit": PREPARE["sourceArtifact"]["files"],
                 "notVerified": data.NOT_VERIFIED}
        original = value["sourceKit"]
        candidates = [original, original[:-1], list(reversed(original)), [*original, original[-1]],
                      [*original, record("source-kit.tar")], original[0]]
        candidates += [[{**row, key: wrong} if index == 0 else row for index, row in enumerate(original)]
                       for key, wrong in (("path", "source-kit/hosted-evidence.tar"), ("size", True), ("sha256", "f" * 64))]
        for index, candidate in enumerate(candidates):
            bodies = {"preparation.json": {**value, "sourceKit": candidate}, "copy-result.json": copied, "source-bindings.json": [],
                      "outer.json": {"schemaVersion": 1, "scope": data.PREPARE_SCOPE, **producer, "originalWait": True,
                          "exitCode": 0, "outputWritersClosed": True, "statusWriterCloseGate": "original-step-success-required"}}
            inert = SimpleNamespace(read=Mock(side_effect=lambda path, limit=0: data.canonical(bodies[path.name])),
                                    NOT_VERIFIED=data.NOT_VERIFIED,
                                    decode=data.decode, same=data.same, outer=data.outer, unpack=Mock())
            probe = SimpleNamespace(inspect_prepared=Mock(return_value=prepared()))
            with self.subTest(sourceKit=candidate), patch.object(helper, "conventional_files", return_value=rows), \
                    patch.object(helper, "fixed_file_inventory", return_value=shared), \
                    patch.object(helper, "conventional_core") as core, patch.object(helper, "conventional_module", return_value=probe) as modules:
                if index:
                    with self.assertRaises(helper.CheckFailure):
                        helper.conventional_prepared(CONTEXT, inert, SMOKE, unpack=True)
                    inert.unpack.assert_not_called()
                    core.assert_not_called()
                    modules.assert_not_called()
                    probe.inspect_prepared.assert_not_called()
                else:
                    self.assertEqual(helper.conventional_prepared(CONTEXT, inert, SMOKE, unpack=True)[1], prepared())
                    inert.unpack.assert_called_once()
                    probe.inspect_prepared.assert_called_once()

    def test_host_or_source_drift_stops_the_next_phase(self):
        for failure in ("host", "source"):
            with self.subTest(failure=failure), patch.object(helper, "conventional_host",
                    side_effect=helper.CheckFailure("inert host drift") if failure == "host" else None), \
                    patch.object(helper, "source_unchanged", side_effect=helper.CheckFailure("inert source drift")) as source, \
                    self.assertRaises(helper.CheckFailure):
                helper.conventional_recheck(CONTEXT, data)
            if failure == "host": source.assert_not_called()
        metadata = {"st_mode": 0o100755, "st_uid": 0, "st_gid": 0, "st_nlink": 1, "st_size": 5,
                    "st_dev": 1, "st_ino": 2, "st_mtime_ns": 1, "st_ctime_ns": 1}
        for failure in (None, "image-os", "image-version", "image-missing", "root", "architecture", "executable", "flags",
                        "mode", "symlink", "uid", "gid", "nlink", "bytes", "drift"):
            fields = dict(metadata)
            for label, key, wrong in (("mode", "st_mode", 0o100775), ("symlink", "st_mode", 0o120755),
                                      ("uid", "st_uid", 1001), ("gid", "st_gid", 1001), ("nlink", "st_nlink", 2)):
                if failure == label: fields[key] = wrong
            before = SimpleNamespace(**fields)
            after = SimpleNamespace(**{**fields, "st_ctime_ns": 2}) if failure == "drift" else before
            environment = {"ImageOS": "ubuntu22" if failure == "image-os" else HOST["imageOS"],
                           "ImageVersion": "20260908.1.1" if failure == "image-version" else HOST["imageVersion"]}
            if failure == "image-missing": environment.pop("ImageVersion")
            flags = SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=0 if failure == "flags" else 1)
            host_sys = SimpleNamespace(platform="linux", version_info=(3, 12, 0), flags=flags, executable="/usr/bin/python3.12")
            with self.subTest(failure=failure), patch.object(helper, "CONVENTIONAL_HOSTED_PYTHON", HOST), \
                    patch.dict(helper.os.environ, environment, clear=True), patch.object(helper, "sys", host_sys), \
                    patch.object(helper.os, "geteuid", return_value=0 if failure == "root" else 1001), \
                    patch.object(helper.os, "uname", return_value=SimpleNamespace(machine="arm64" if failure == "architecture" else "x86_64")), \
                    patch.object(helper.os.path, "realpath", return_value="/inert/python" if failure == "executable" else "/usr/bin/python3.12"), \
                    patch.object(Path, "lstat", side_effect=[before, after]), \
                    patch.object(data, "file_record", return_value=record("python3.12", "b" if failure == "bytes" else "a")) as body:
                if failure:
                    with self.assertRaises((helper.CheckFailure, data.Refused)):
                        helper.conventional_host(data)
                    if failure not in {"bytes", "drift"}: body.assert_not_called()
                else:
                    helper.conventional_host(data)
                    body.assert_called_once_with(Path("/usr/bin/python3.12"), HOST["python"]["size"])

    def test_probe_errors_or_changed_inputs_cannot_launch_libtest(self):
        messages = b"inert-cargo-messages"
        compiled = {"path": "/inert/libtest", "messagesSha256": hashlib.sha256(messages).hexdigest()}
        checks = {"producer": helper.conventional_producer(CONTEXT), "scope": helper.CONVENTIONAL_SMOKE_SCOPE,
                  "manifestSha256": SMOKE["manifestSha256"], "protocolSha256": SMOKE["protocolSha256"], "compiledTest": compiled}
        for reason in ("nonzero", "timeout", "unknown", "capture", "close", "malformed", "source-change", "artifact-change"):
            owner = Mock(return_value=subprocess.CompletedProcess(["inert"], 0, data.canonical(probe_value()), b""))
            if reason == "nonzero": owner.return_value.returncode = 1
            if reason == "timeout": owner.side_effect = subprocess.TimeoutExpired(["inert"], 30)
            if reason == "unknown": owner.side_effect = RuntimeError("inert unknown original owner")
            if reason == "capture": owner.return_value.stdout = "not-byte-capture"
            if reason == "malformed": owner.return_value.stdout = b"not-json"
            def write(path, raw):
                if reason == "close" and path.name == "probe.stdout": raise OSError("inert original output close")
                return record(path.name)
            inert = SimpleNamespace(write=Mock(side_effect=write), canonical=data.canonical, decode=data.decode, same=data.same,
                read=Mock(side_effect=lambda path, limit: data.canonical(checks) if path.name == "compile-checks.json" else messages),
                probe_receipt=data.probe_receipt)
            current = (Path("/inert-root/prepared/runtime"), prepared(), SimpleNamespace(EXPECTED_BUILTINS=["inert"]))
            with self.subTest(reason=reason), patch.object(helper, "github_original_artifact", return_value=compiled), \
                    patch.object(helper, "github_compiled_test", return_value=Path(compiled["path"])), \
                    patch.object(helper, "conventional_prepared", side_effect=[current, helper.CheckFailure("inert artifact drift")]
                                 if reason == "artifact-change" else None, return_value=current), \
                    patch.object(helper, "conventional_recheck", side_effect=[None, helper.CheckFailure("inert source drift")]
                                 if reason == "source-change" else None), \
                    patch.object(helper, "conventional_owner", return_value=owner), patch.object(Path, "mkdir") as mkdir, \
                    self.assertRaises((ValueError, OSError, RuntimeError, subprocess.TimeoutExpired)):
                helper.conventional_smoke(CONTEXT, inert, SMOKE)
            self.assertEqual(owner.call_count, 1)
            mkdir.assert_not_called()
            self.assertFalse(any(call.args[0].name == "smoke-checks.json" for call in inert.write.call_args_list))

    def test_one_original_cargo_selector_and_fixed_no_run_flags(self):
        argv = helper.conventional_compile_argv("/inert/cargo", CONTEXT)
        self.assertEqual(argv[:8], ["/inert/cargo", "test", "--locked", "--offline", "--jobs", "1", "--no-default-features", "--features"])
        self.assertEqual(argv[-3:], ["--lib", "--no-run", "--message-format=json"])
        source, target = Path(CONTEXT["source"]), Path("/inert-target")
        executable = target / data.TARGET / "debug/deps/mobile_release_desktop-0123456789abcdef"
        row = {"reason": "compiler-artifact", "executable": str(executable), "fresh": False, "features": ["development-runtime"],
               "target": {"kind": ["lib"], "name": "mobile_release_desktop", "src_path": str(source / "desktop/src-tauri/src/lib.rs")},
               "manifest_path": str(source / "desktop/src-tauri/Cargo.toml"), "profile": {"test": True, "debug_assertions": True}}
        final = {"reason": "build-finished", "success": True}
        self.assertEqual(helper.github_compiled_test(data.canonical(row) + data.canonical(final), source=source, target_root=target), executable)
        for rows in ([{**row, "fresh": True}, final], [row, row, final], [row, {**final, "success": False}],
                     [{**row, "features": ["desktop-shell", "development-runtime"]}, final]):
            with self.assertRaises(helper.CheckFailure):
                helper.github_compiled_test(b"".join(data.canonical(item) for item in rows), source=source, target_root=target)

    def test_source_has_only_fixed_ordinary_owner_calls_and_route_local_mq(self):
        tree = ast.parse((SOURCE / "desktop/tools/ci_foundation.py").read_text())
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        ordinary = [node for node in ast.walk(functions["conventional_smoke"]) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "run_owned"]
        self.assertEqual(len(ordinary), 2)
        self.assertEqual([next(key.value.value for key in call.keywords if key.arg == "timeout") for call in ordinary], [30, 180])
        for call in ordinary:
            self.assertIs(next(key.value.value for key in call.keywords if key.arg == "text"), False)
            self.assertNotIn("_evidence", [key.arg for key in call.keywords])
        self.assertNotIn("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", ast.unparse(functions["clean_environment"]))
        self.assertIn("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", ast.unparse(functions["conventional_compile"]))
        producer = ast.unparse(functions["conventional_prepare"])
        self.assertIn("copier.prepare_source", producer)
        self.assertIn("preparer.prepare", producer)
        self.assertNotIn("run_owned", producer)
        self.assertNotIn("github_compiled_test", producer)
        self.assertIn("desktop/cpython-source-inputs/conventional-review", producer)
        self.assertNotIn("reviewArtifact", producer)
        self.assertNotIn("source-kit.tar", producer)
        self.assertNotIn("supportFiles", ast.unparse(functions["conventional_admission"]))
        self.assertNotIn("supportFiles", ast.unparse(functions["conventional_host"]))
        self.assertLess(producer.index("data.pack_runtime"), producer.index("public / 'preparation.json'"))

    def test_workflow_fixed_refs_step_context_download_token_and_success_only_publish(self):
        workflow = (SOURCE / ".github/workflows/desktop-foundation.yml").read_text()
        old, routes = workflow.split("\n  conventional-prepare:\n", 1)
        preparation, smoke = routes.split("\n  conventional-smoke:\n", 1)
        self.assertIn("    branches: [feature/desktop-application, verify/desktop-windows-snapshot, "
                      "verify/desktop-conventional-prepare, verify/desktop-conventional-smoke]\n", old)
        foundation, windows = old.split("\n  passive-native:\n", 1)[1].split("\n  windows-snapshot:\n", 1)
        for section, scope, push in ((foundation, "foundation", "feature/desktop-application"),
                                     (windows, "windows-snapshot", "verify/desktop-windows-snapshot")):
            self.assertIn("    if: >-\n"
                f"      (github.event_name == 'push' && github.ref == 'refs/heads/{push}') ||\n"
                f"      (github.event_name == 'workflow_dispatch' && inputs.scope == '{scope}' &&\n"
                "       github.ref != 'refs/heads/verify/desktop-conventional-prepare' &&\n"
                "       github.ref != 'refs/heads/verify/desktop-conventional-smoke')\n", section)
        for section, route, count in ((preparation, "conventional-prepare", 2), (smoke, "conventional-smoke", 3)):
            header, steps = section.split("    steps:\n", 1)
            self.assertIn("    if: >-\n"
                f"      github.ref == 'refs/heads/verify/desktop-{route}' &&\n"
                "      (github.event_name == 'push' ||\n"
                f"       (github.event_name == 'workflow_dispatch' && inputs.scope == '{route}'))\n", header)
            self.assertNotIn("${{ runner.", header)
            self.assertIn("      MRK_PUSH_EVENT_AFTER: ${{ github.event.after }}\n", header)
            self.assertEqual(section.count("RUNNER_ENVIRONMENT: ${{ runner.environment }}"), count)
            self.assertEqual(section.count("uses: actions/download-artifact@"), 1)
            self.assertNotIn("    needs:", section)
            self.assertNotIn("setup-python@", section)
            self.assertNotIn("setup-node@", section)
            self.assertNotIn("persist-credentials: true", section)
            self.assertIn("if: success() && steps.", section)
            self.assertIn("result=$?", section)
            self.assertIn("exec 4>&- 5>&- || exit 125", section)
            self.assertIn("exec 3>&- || exit 125", section)
            entries = 0
            for step in steps.split("      - name:")[1:]:
                if "ci_foundation.py conventional-" in step:
                    entries += 1
                    self.assertIn("        env:\n", step)
                    self.assertIn("          RUNNER_ENVIRONMENT: ${{ runner.environment }}\n", step)
                if "github-token:" in step:
                    self.assertIn("uses: actions/download-artifact@", step)
                    self.assertIn("digest-mismatch: error", step)
                    self.assertIn("merge-multiple: true", step)
            self.assertEqual(entries, count)
        self.assertNotIn("review-artifact", routes)
        self.assertNotIn("review-repository", routes)
        self.assertNotIn("source-kit.tar", routes)
        for leaf in SOURCE_KIT:
            self.assertIn("${{ steps.admit.outputs.root }}/prepared-artifact/source-kit/" + leaf, smoke)
        self.assertNotIn("ci_foundation.py conventional-smoke", preparation)
        self.assertNotIn("ci_foundation.py conventional-prepare", smoke)


if __name__ == "__main__":
    unittest.main()
