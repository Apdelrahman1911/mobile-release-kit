"""Pure DATA verification. Never opens installed paths or runs product images."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).absolute().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


r = module("fresh_hosted_runner")
b = module("fresh_snapshot_bounds")
s = module("read_torn_tree")
boot = module("fresh_hosted_bootstrap")
host_pre = module("fresh_host_prerequisite")


def binding():
    return dict(productSource=r.PRODUCT["source"], productTree=r.PRODUCT["tree"],
        controlSourceSha256="1" * 64, controlManifestSha256="2" * 64,
        controls={name: {"sha256": char * 64} for name, char in (("write", "3"), ("torn", "4"), ("census", "5"))},
        package={"sha256": "6" * 64}, producer={"sha256": "7" * 64}, signature={"sha256": "8" * 64},
        inventorySha256="9" * 64, runtimeManifestSha256="a" * 64)


def base(role):
    bind = binding()
    return dict(schemaVersion=1, target=r.TARGET, productSource=bind["productSource"],
        controlSourceSha256=bind["controlSourceSha256"], controlManifestSha256=bind["controlManifestSha256"],
        controlImageSha256=bind["controls"][role]["sha256"], packageSha256=bind["package"]["sha256"],
        producerDescriptorSha256=bind["producer"]["sha256"], producerSignatureSha256=bind["signature"]["sha256"],
        transportState="pending-original-process-exit", installationQualified=False)


def cut(role="write"):
    return dict(base(role), kind="mrk-disposable-fresh-cut-v1", role=r.CUT_ROLES[role][0],
        originalFailure="worker-result-incomplete", originalChildExit=r.CUT_ROLES[role][1],
        invocation="b" * 32, terminationAttempted=False, **{k: True for k in (
        "outputEof", "outputClose", "commandClose", "parentOriginalsSettled", "nativeSettled",
        "timely", "sourcePost", "controlledInterruptionWitnessed")})


def frontier():
    observed = dict(kind="mrk-fresh-frontier-observed-v1", invocation="b" * 32,
        frontier="copying", payloadBytes=1, oldOriginalReturnReconstructed=False,
        preservationPerformed=False, requestId="c" * 32, root={"fixture": "DATA"},
        **{k: "d" * 64 for k in ("intentSha256", "originSha256", "enrollmentSha256",
            "enrollmentHeadSha256", "physicalCommitmentSha256", "selectionSha256")})
    return dict(base("census"), kind="mrk-disposable-fresh-census-v1", scope="fresh-frontier",
        recoveryExecuted=False, observation=observed)


class Controls(unittest.TestCase):
    def test_cut_requires_actual_nonzero_and_all_native_finality(self):
        for role in ("write", "torn"):
            value = cut(role)
            self.assertEqual(r.cut_data(r.canonical(value), binding(), role, 1), value)
            for code in (0, True, -9, 256, None):
                with self.assertRaises(r.Refused): r.cut_data(r.canonical(value), binding(), role, code)
            for key in ("outputEof", "outputClose", "commandClose", "parentOriginalsSettled",
                        "nativeSettled", "timely", "sourcePost", "controlledInterruptionWitnessed"):
                bad = dict(value, **{key: False})
                with self.subTest(role=role, key=key), self.assertRaises(r.Refused):
                    r.cut_data(r.canonical(bad), binding(), role, 1)

    def test_cut_rejects_other_exit_and_old_product_image_or_pair(self):
        value = cut()
        for key, wrong in (("originalChildExit", 88), ("terminationAttempted", True),
            ("originalFailure", "other"), ("productSource", "e" * 40),
            ("controlImageSha256", "e" * 64), ("controlSourceSha256", "e" * 64),
            ("controlManifestSha256", "e" * 64), ("packageSha256", "e" * 64),
            ("producerDescriptorSha256", "e" * 64), ("producerSignatureSha256", "e" * 64),
            ("invocation", "0" * 32), ("schemaVersion", True)):
            with self.subTest(key=key), self.assertRaises(r.Refused):
                r.cut_data(r.canonical(dict(value, **{key: wrong})), binding(), "write", 1)

    def test_parser_rejects_duplicate_truncated_nonfinite_and_oversize(self):
        for raw in (b'{"a":1,"a":2}\n', b'{}', b'{"x":NaN}\n', b'{}\n' + b' ' * r.RECORD_LIMIT):
            with self.subTest(raw=raw[:20]), self.assertRaises((r.Refused, ValueError)):
                r.document(raw)

    def test_frontier_requires_genuine_copying_and_old_invocation(self):
        value = frontier()
        self.assertEqual(r.frontier_data(r.canonical(value), binding(), "b" * 32, 0), value)
        for key, bad in (("payloadBytes", 0), ("payloadBytes", True), ("frontier", "complete"),
                         ("preservationPerformed", True), ("invocation", "f" * 32)):
            changed = copy.deepcopy(value); changed["observation"][key] = bad
            with self.subTest(key=key), self.assertRaises(r.Refused):
                r.frontier_data(r.canonical(changed), binding(), "b" * 32, 0)

    def test_completed_matches_unique_original_and_distinguishes_clean(self):
        old = frontier(); bind = binding(); ref = dict(invocation="b" * 32, receiptSha256="e" * 64)
        observed = dict(kind="mrk-fresh-conservation-observed-v1", root=old["observation"]["root"],
            selectionSha256="d" * 64, reference=ref, attempts=[{k: old["observation"][k]
                for k in ("invocation", "requestId", "intentSha256")}])
        value = dict(base("census"), kind="mrk-disposable-fresh-census-v1",
            scope="completed-conservation", recoveryExecuted=False, observation=observed)
        installation = dict(sourceCommit=bind["productSource"], completedPackageSha256=bind["package"]["sha256"],
            inventorySha256=bind["inventorySha256"], runtimeManifestSha256=bind["runtimeManifestSha256"],
            originalInstallerReturnedZero=True, originalWriterJoined=True,
            originalInstallerResult={"action": "fresh-install"}, invocation="f" * 32,
            freshConservation={"reference": ref})
        outcome = r.completed_data(r.canonical(value), bind, old, installation, 0)
        self.assertFalse(outcome["cleanFreshQualified"])
        self.assertFalse(outcome["literalCrossOutputPhysicalDigestEqualityClaimed"])
        for changed in (dict(installation, invocation="b" * 32),
                        dict(installation, originalWriterJoined=False),
                        dict(installation, freshConservation={"reference": dict(ref, receiptSha256="a" * 64)})):
            with self.assertRaises(r.Refused): r.completed_data(r.canonical(value), bind, old, changed, 0)
        value["observation"]["attempts"] *= 2
        with self.assertRaises(r.Refused): r.completed_data(r.canonical(value), bind, old, installation, 0)


class SourcePreparation(unittest.TestCase):
    def test_hydration_uses_admitted_product_and_preserves_actual_workflow(self):
        actual = dict(GITHUB_SHA="a" * 40, GITHUB_WORKFLOW_SHA="a" * 40,
            GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="write-recovery",
            GITHUB_EVENT_NAME="push", MRK_MACOS_INSTALL_SOURCE_COMMIT="a" * 40)
        original = dict(actual)
        bind = dict(productSource="b" * 40, inventorySha256="c" * 64, runtimeManifestSha256="d" * 64)
        prepared = SimpleNamespace(source=bind["productSource"], manifest={
            "inventorySha256": bind["inventorySha256"], "runtimeManifestSha256": bind["runtimeManifestSha256"]})
        derived = boot.hydration_environment(actual, prepared, bind)
        self.assertEqual(actual, original)
        self.assertEqual({k: v for k, v in derived.items() if k.startswith("GITHUB_")},
                         {k: v for k, v in original.items() if k.startswith("GITHUB_")})
        self.assertEqual(derived["MRK_MACOS_INSTALL_SOURCE_COMMIT"], bind["productSource"])
        self.assertEqual(derived["MRK_MACOS_INSTALL_INVENTORY_SHA256"], bind["inventorySha256"])
        self.assertEqual(derived["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"], bind["runtimeManifestSha256"])
        for key, size in (("productSource", 40), ("inventorySha256", 64), ("runtimeManifestSha256", 64)):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "prepared-hydration-anchors"):
                boot.hydration_environment(actual, prepared, dict(bind, **{key: "e" * size}))

    def test_fixed_host_prerequisite_honest_fresh_push_context(self):
        work = "/Users/runner/work/_temp/mrk-macos-fresh-host.1234abcd"
        source = "a" * 40
        env = dict(PATH=host_pre.SAFE_PATH, HOME=work, LANG="C", LC_ALL="C", TZ="UTC",
            RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="macOS", RUNNER_ARCH="ARM64", RUNNER_TEMP=host_pre.RUNNER_TEMP,
            GITHUB_REPOSITORY=host_pre.REPOSITORY, GITHUB_EVENT_NAME="push", GITHUB_REF=host_pre.REF,
            GITHUB_SHA=source, GITHUB_WORKFLOW_SHA=source, GITHUB_WORKFLOW_REF=host_pre.REPOSITORY + "/" + host_pre.WORKFLOW + "@" + host_pre.REF,
            GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="write-recovery", GITHUB_WORKSPACE=host_pre.WORKSPACE,
            MRK_EXPECTED_SHA=source, MRK_MACOS_INSTALL_SOURCE_COMMIT=source, MRK_MACOS_WORK=work,
            __CF_USER_TEXT_ENCODING="0x1F5:0:0")
        def check(values):
            return host_pre._validate_context(values, (501, 501, 20, 20), ("Darwin", "arm64"), (3, 14, 7), (1, 1, 1))
        for job in ("write-recovery", "torn-refusal"):
            self.assertEqual(check(dict(env, GITHUB_JOB=job))["jobKey"], job)
        for key, wrong in (("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_JOB", "aqua"),
            ("GITHUB_REF", "refs/heads/verify/desktop-macos-aqua"), ("GITHUB_WORKFLOW_SHA", "b" * 40),
            ("MRK_MACOS_WORK", work.replace("fresh-host", "aqua")), ("RUNNER_ENVIRONMENT", "self-hosted")):
            with self.subTest(key=key), self.assertRaises(host_pre.Refused): check(dict(env, **{key: wrong}))
        with mock.patch.object(host_pre, "Deadline", side_effect=AssertionError("probe")):
            with self.assertRaisesRegex(host_pre.Refused, "final-signed-input-binding-absent"): host_pre.main()
        self.assertEqual(host_pre.COMMAND, ("/usr/bin/sudo", "-n", "--", "/bin/chmod", "-h", "0755", "/Applications"))
        self.assertEqual(host_pre._application_mode([1, 2, stat.S_IFDIR | 0o775, 0, 80, 1, 0, 1, 1]), "chmod")
        self.assertEqual(host_pre._application_mode([1, 2, stat.S_IFDIR | 0o755, 0, 80, 1, 0, 1, 1]), "noop")

    def test_disabled_bootstrap_before_any_native_probe(self):
        with mock.patch.object(boot.platform, "machine", side_effect=AssertionError("probe")), \
             mock.patch.object(boot.os, "open", side_effect=AssertionError("read")):
            with self.assertRaisesRegex(ValueError, "final-signed-input-binding-absent"): boot.main()

    def test_snapshot_binder_only_two_reviewed_literals(self):
        template = (HERE / "read_torn_tree.py").read_bytes()
        run = {"GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit", "GITHUB_SHA": "a" * 40,
               "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "torn-refusal"}
        bounds = b.quote_for_depth(2, 9695)
        actual = boot.bind_snapshot(template, run, bounds)
        parsed = ast.parse(actual)
        values = {n.targets[0].id: ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
                  and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ("EXECUTION_BINDING", "SNAPSHOT_BOUNDS")}
        self.assertEqual(values, {"EXECUTION_BINDING": run, "SNAPSHOT_BOUNDS": bounds})
        normalized = actual.decode().replace("EXECUTION_BINDING = " + repr(run) + "\n", "EXECUTION_BINDING = None\n")
        normalized = normalized.replace("SNAPSHOT_BOUNDS = " + repr(bounds) + "\n", "SNAPSHOT_BOUNDS = None\n")
        self.assertEqual(normalized.encode(), template)
        with self.assertRaises(ValueError): boot.bind_snapshot(template + b"EXECUTION_BINDING = None\n", run, bounds)

    def test_host_context_preserves_actual_runner_not_product(self):
        bind = dict(executionApproved=True, runnerSourceCommit="a" * 40, runnerBranch="codex/macos-fresh-validation",
                    productSource="b" * 40)
        env = dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="macOS", RUNNER_ARCH="ARM64",
            GITHUB_REPOSITORY=boot.REPOSITORY, GITHUB_EVENT_NAME="push", GITHUB_WORKSPACE=str(boot.ROOT),
            GITHUB_SHA=bind["runnerSourceCommit"], GITHUB_WORKFLOW_SHA=bind["runnerSourceCommit"],
            GITHUB_REF="refs/heads/" + bind["runnerBranch"], GITHUB_WORKFLOW_REF=boot.REPOSITORY + "/" + boot.WORKFLOW + "@refs/heads/" + bind["runnerBranch"],
            RUNNER_TEMP="/Users/runner/work/_temp", GITHUB_JOB="write-recovery", GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
            MRK_MACOS_WORK="/Users/runner/work/_temp/mrk-macos-installed.1234abcd")
        args = dict(machine="arm64", version="26.1", identity=(501, 501, 20, 20), flags=(True, True, True),
                    script=boot.HERE / "fresh_hosted_bootstrap.py")
        self.assertEqual(boot.host_data(bind, env, **args)[1], "write-recovery")
        for key, value in (("GITHUB_SHA", "b" * 40), ("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_JOB", "aqua"),
                           ("GITHUB_WORKFLOW_SHA", "c" * 40), ("GITHUB_RUN_ID", "0")):
            with self.subTest(key=key), self.assertRaises(ValueError): boot.host_data(bind, dict(env, **{key: value}), **args)

    def test_failure_receipt_keeps_original_failure_and_cleanup_unknown(self):
        class Book:
            published = []
            def __init__(self, known=True): self.known = known; self.finished = 0
            def finish(self): self.finished += 1; return self.known
            def publish(self, path, body): self.published.append((path, body))
        outputs, protected, sources = Book(), Book(False), Book()
        op = type("Op", (), {})()
        op.outputs, op.protected, op.source = outputs, protected, type("Source", (), {"book": sources})()
        op.calls, op.fresh_carriers, op.work = [], [], Path("/DATA")
        with mock.patch.object(r, "execute_job", side_effect=r.Refused("first-cut-source-refusal")):
            receipt = r.settle_job(op, None, None, {"job": "write-recovery"})
        self.assertFalse(receipt["passed"])
        self.assertEqual(receipt["firstFailureReason"], "first-cut-source-refusal")
        self.assertEqual(receipt["cleanupErrors"], ["owned-original-close-unknown"])
        self.assertEqual(sources.finished, 1)
        self.assertEqual(outputs.finished, 1)
        self.assertEqual(receipt["transportState"], "pending-original-process-exit")

    def test_disabled_runner_before_effects(self):
        with mock.patch.object(r.sys, "argv", ["fresh_hosted_runner.py"]), \
             mock.patch.object(r, "execute_job", side_effect=AssertionError("effect")):
            with self.assertRaisesRegex(r.Refused, "source-preparation-only"): r.main()

    def test_disabled_snapshot_before_probes(self):
        with mock.patch.object(s.os, "getuid", side_effect=AssertionError("probe")), \
             mock.patch.object(s.os, "open", side_effect=AssertionError("protected open")):
            with self.assertRaisesRegex(s.Refused, "source-preparation-only"): s.main()

    def test_exact_seven_steps_and_existing_status_path(self):
        self.assertEqual(sum(map(len, r.JOB_STEPS.values())), 7)
        tree = ast.parse((HERE / "fresh_hosted_runner.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == "publish_installation_observation")
        literals = {n.value for n in ast.walk(function) if isinstance(n, ast.Constant) and type(n.value) is str}
        self.assertIn("installer-output.status", literals)
        self.assertIn("installation-observation.json", literals)
        self.assertIsNone(r.EXECUTION_BINDING); self.assertIsNone(s.EXECUTION_BINDING)
        self.assertIsNone(s.SNAPSHOT_BOUNDS)

    def test_fixed_frontier_filename_nomination_before_product_execution(self):
        scripts = {p.name: p.read_bytes() for p in (HERE / "scripts").iterdir()}
        self.assertEqual(r.control_script(scripts, "write"), scripts["cut-postinstall"])
        self.assertEqual(r.control_script(scripts, "torn"), scripts["cut-postinstall"])
        actual = r.control_script(scripts, "frontier")
        self.assertEqual(actual, scripts["frontier-postinstall"])
        self.assertNotIn(b"@ACTUAL_INVOCATION@", actual)
        with self.assertRaises(r.Refused): r.frontier_name("0" * 32)
        with self.assertRaises(r.Refused): r.control_script(scripts, "frontier", "a" * 32)
        # Execute only the builtins nomination prefix, before cd/exec/image code.
        prefix = actual.split(b'case "$0" in\n', 1)[0] + b'printf "%s\\n" "$invocation"\n'
        for nomination in ("a" * 32, "1234567890abcdef" * 2):
            result = subprocess.run(["/bin/sh", "-c", prefix.decode(), "DATA", "/Volumes/DATA/" + r.frontier_name(nomination), "ignored", "/"],
                capture_output=True, check=False, timeout=2)
            self.assertEqual(result.returncode, 0); self.assertEqual(result.stdout, (nomination + "\n").encode())
        for name in ("Fresh-frontier-" + "0" * 32 + ".pkg", "Fresh-frontier-" + "A" * 32 + ".pkg",
                     "Fresh-frontier-" + "1" * 31 + ".pkg", "Fresh-frontier-" + "1" * 33 + ".pkg",
                     "Other-" + "1" * 32 + ".pkg", "Fresh-frontier-" + "1" * 32 + ".pkg.extra"):
            result = subprocess.run(["/bin/sh", "-c", prefix.decode(), "DATA", "/Volumes/DATA/" + name, "ignored", "/"],
                capture_output=True, check=False, timeout=2)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(result.stdout, b"")

    def test_package_info_closed_profile(self):
        identity = r.CONTROL_IDS["write"]
        raw = ('<pkg-info format-version="2" identifier="' + identity + '" version="1" '
               'install-location="/" auth="root"><payload numberOfFiles="0" installKBytes="0"/>'
               '<scripts><postinstall file="./postinstall"/></scripts></pkg-info>').encode()
        r.package_info(raw, identity)
        for changed in (raw.replace(b'numberOfFiles="0"', b'numberOfFiles="1"'),
                        raw.replace(b'auth="root"', b'auth="none"'),
                        raw.replace(b'<scripts>', b'<scripts arbitrary="1">'),
                        b'<!DOCTYPE bad>' + raw):
            with self.assertRaises(r.Refused): r.package_info(changed, identity)

    def test_inventory_quote_source_shape_and_limits(self):
        raw = r.canonical({"files": [{"path": "app/Contents/CodeResources"},
            {"path": "app/Contents/Info.plist"}, {"path": "runtime/a"}]})
        quote = b.derive_inventory(raw, 9695)
        self.assertEqual(quote["firstPayloadPath"], "app/Contents/CodeResources")
        self.assertEqual(quote["privateFiles"], 7)
        self.assertEqual(quote["bounds"]["maxNodes"], 12)
        self.assertLess(b.quote_for_depth(16, 9695)["maxOutputBytes"], r.OUTPUT_LIMIT)
        for depth in (True, 1, 17):
            with self.assertRaises(ValueError): b.quote_for_depth(depth, 9695)

    def test_origin_intent_correlation_without_journal_parse(self):
        intent = r.canonical({"invocation": "b" * 32, "requestId": "c" * 32})
        origin = dict(schemaVersion=1, kind="mrk-macos-fresh-output-origin-v1", target=r.TARGET,
            invocation="b" * 32, requestId="c" * 32, intentSha256=r.sha(intent))
        value = s.control_projection(r.canonical(origin), intent)
        self.assertFalse(value["journalSemanticsAccepted"])
        for key, wrong in (("invocation", "a" * 32), ("requestId", "a" * 32), ("intentSha256", "a" * 64)):
            with self.subTest(key=key), self.assertRaises(s.Refused):
                s.control_projection(r.canonical(dict(origin, **{key: wrong})), intent)
        with self.assertRaises(s.Refused): s.control_projection(r.canonical(origin), b'{"x":1,"x":1}')

    def test_prebuilt_resource_quote_and_per_carrier_roster(self):
        bind = dict(job="write-recovery", packageBody=b"p" * 100, producerBody=b"d", signatureBody=b"s",
                    inputFiles={"a": (b"i" * 100, 0o444)}, controlBodies={"census": b"c" * 100})
        packages = dict(cut=b"c" * 100, frontier=b"f" * 100, completed=b"d" * 100)
        quote = r.route_resource_quote(bind, packages)
        self.assertEqual(quote["carrierBytes"], {"cut": 202, "frontier": 202, "completed": 202, "ordinary": 102})
        self.assertEqual(quote["postCutPackageBuilds"], 0)
        self.assertEqual(quote["installerCalls"], 4)
        self.assertFalse(quote["capacityIsReservation"])
        with self.assertRaises(r.Refused): r.route_resource_quote(dict(bind, job="torn-refusal"), packages)
        tree = ast.parse((HERE / "fresh_hosted_runner.py").read_text())
        func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "execute_job")
        builds = [n.lineno for n in ast.walk(func) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "build_control"]
        captures = [n.lineno for n in ast.walk(func) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "captured_control"]
        self.assertLess(max(builds), min(captures))

    def test_torn_snapshot_exact_inventory_rows_and_preservation(self):
        bind = binding()
        bind["snapshotQuote"] = b.derive_inventory(r.canonical({"files": [{"path": "app/Contents/CodeResources"},
            {"path": "app/Contents/Info.plist"}, {"path": "runtime/a"}]}), 9695)
        bind["snapshotBinding"] = {"job": "torn-refusal"}
        stage = ".install-" + "b" * 32
        paths = {"": True, "versions": True, stage: True, stage + "/app": True, stage + "/app/Contents": True,
            "registration-reservation-v1": False, "maintenance-gate-v1": False,
            ".maintenance-" + "b" * 32 + ".intent.json": False,
            **{stage + "/" + name: False for name in ("fresh-output-origin-v1.json", "fresh-output-enrollment-v1",
               "staging-created.json", "app/Contents/CodeResources")}}
        rows = {}
        native = {"birthNs": 1, "aclEmpty": True, "xattrNames": [], "flags": 0}
        for i, (path, directory) in enumerate(paths.items()):
            size = 0 if directory or path.endswith("CodeResources") else 1
            identity = [1, i + 1, (stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o600), 0, 0, 1, size, 1, 1, 0]
            row = {"kind": "directory" if directory else "file", "identity": identity, "native": native}
            if directory:
                row["names"] = sorted(p.rsplit("/", 1)[-1] for p in paths if p and (p.rsplit("/", 1)[0] if "/" in p else "") == path)
            else:
                row.update(bytes=size, sha256=r.sha(b"x" * size))
            rows[path] = row
        export = dict(kind="file", identity=[1, 55, stat.S_IFREG | 0o600, 0, 0, 1, 0, 1, 1, 0],
                      bytes=0, sha256=r.sha(b""), native=native)
        value = dict(kind="mrk-fixed-torn-physical-snapshot-v1", root=s.ROOT, originalClosesKnown=True,
            launcherAbsent=True, semanticJournalAccepted=False, mutationPerformed=False,
            transportState="pending-original-process-exit", installationQualified=False, recoveryQualified=False,
            binding=bind["snapshotBinding"], resourceBounds=bind["snapshotQuote"]["bounds"], rows=rows,
            originIntentCorrelation=dict(invocation="b" * 32, requestId="c" * 32, intentSha256=r.sha(b"x"),
                originSha256=r.sha(b"x"), journalSemanticsAccepted=False),
            requestExports={"MobileReleaseKit-InstallerResult-v2-" + "c" * 32 + ".json": export})
        raw = r.canonical(value)
        self.assertTrue(r.compare_torn(raw, raw, bind, cut("torn"))["rootBytesAndIdentitiesPreserved"])
        for field in ("bytes", "sha256"):
            changed = copy.deepcopy(value)
            changed["rows"][stage + "/app/Contents/CodeResources"][field] = 1 if field == "bytes" else "f" * 64
            with self.assertRaises(r.Refused): r.compare_torn(raw, r.canonical(changed), bind, cut("torn"))
        changed = copy.deepcopy(value); changed["rows"]["versions"]["names"] = ["unexpected"]
        with self.assertRaises(r.Refused): r.compare_torn(raw, r.canonical(changed), bind, cut("torn"))


if __name__ == "__main__":
    unittest.main()
