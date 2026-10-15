"""Offline admission/failure DATA. Never downloads, mounts, installs or launches."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def inert_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ADAPTER = inert_module("fixed_carrier_resume_data", "desktop/tools/macos_fixed_carrier_resume.py")
RUNNER = inert_module("fixed_carrier_resume_ui_data", "desktop/tools/macos_normal_ui_runner.py")


class FixedCarrierResumeData(unittest.TestCase):
    def metadata(self):
        m, row = ADAPTER, ADAPTER.ORIGIN
        run = dict(id=int(row["runId"]), run_attempt=1, head_sha=row["source"],
                   head_branch="verify/desktop-macos-installed", path=m.WORKFLOW,
                   workflow_id=m.WORKFLOW_ID, status="completed", conclusion="cancelled",
                   repository={"full_name": m.REPOSITORY})
        names = {51: "Standard Installer only is privileged; never execute the app or Python as root",
                 52: "Notarize, staple and verify only the final user image",
                 53: "Stage only the finalized ordinary image as an unqualified P0 carrier input",
                 54: "Retain one finalized DMG and its finite descriptor for later independent P0 qualification"}
        job = dict(id=int(row["jobId"]), run_id=run["id"], head_sha=row["source"],
                   status="completed", conclusion="failure", steps=[
                       dict(number=n, name=names.get(n, "unselected-test-fixture"),
                            status="completed", conclusion="failure" if n == 59 else "success")
                       for n in range(1, 60)])
        artifact = dict(id=int(row["artifactId"]), expired=False,
                        size_in_bytes=row["artifactBytes"], digest="sha256:" + row["artifactSha256"],
                        name="mobile-release-kit-macos26-" + m.TARGETS[0] + "-p0-carrier-input-" +
                             row["source"] + "-" + row["runId"] + "-" + row["runAttempt"],
                        workflow_run={"id": run["id"], "head_sha": row["source"],
                                      "head_branch": run["head_branch"]})
        return run, job, artifact

    def test_fixed_origin_stage_and_artifact_admission_preserves_failed_job(self):
        m = ADAPTER
        original = self.metadata()
        self.assertIs(m.metadata_data(*original, m.ORIGIN, "carrier", m.TARGETS[0]), m.ORIGIN)
        mutations = ((0, "head_sha", "a" * 40), (0, "conclusion", "success"),
                     (1, "conclusion", "success"), (2, "expired", True),
                     (2, "id", int(m.ORIGIN["artifactId"]) + 1),
                     (2, "digest", "sha256:" + "a" * 64))
        for index, key, value in mutations:
            changed = copy.deepcopy(original)
            changed[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(m.Refused):
                m.metadata_data(*changed, m.ORIGIN, "carrier", m.TARGETS[0])
        for number in range(51, 55):
            changed = copy.deepcopy(original)
            changed[1]["steps"][number - 1]["conclusion"] = "skipped"
            with self.subTest(stage=number), self.assertRaises(m.Refused):
                m.metadata_data(*changed, m.ORIGIN, "carrier", m.TARGETS[0])
        for role, target in (("qualification", m.TARGETS[0]), ("carrier", "x86_64-apple-darwin")):
            with self.assertRaises(m.Refused):
                m.metadata_data(*original, m.ORIGIN, role, target)

    def test_actual_public_origin_and_unknown_finality_refusal(self):
        m = ADAPTER
        body = (ROOT / "desktop/macos-installed-inputs/fixed-arm-carrier-origin-public.json").read_bytes()
        value = m.origin_public_data(body)
        self.assertFalse(value["productReady"])
        with self.assertRaises(m.Refused):
            m.origin_public_data(body + b"\n")
        for phase in ("finalize-package", "package-install", "finalize-image"):
            for key in ("originalClosesKnown", "targetRetired", "recordedPassed"):
                changed = copy.deepcopy(value)
                changed["phases"][phase][key] = None
                candidate = m.canonical(changed)
                self.assertLessEqual(len(candidate), len(body))
                candidate += b" " * (len(body) - len(candidate))
                # Synthetic nomination only: prove semantic refusal independently
                # of the immutable real-origin hash admission, never new evidence.
                with mock.patch.dict(m.ORIGIN, qualificationEvidenceSha256=m.sha(candidate)):
                    with self.subTest(phase=phase, key=key), self.assertRaises(m.Refused):
                        m.origin_public_data(candidate)

    def preview(self):
        m, row = ADAPTER, ADAPTER.ORIGIN
        value = dict(schemaVersion=2, sourceCommit=row["source"], sourceTree=row["tree"],
                     runId=row["runId"], runAttempt=row["runAttempt"], platform="macOS26-arm64",
                     workflow=m.WORKFLOW, scope="normal-macos-early-preview", packageRole="ordinary-image",
                     instrumented=False, packageSha256=row["package"]["sha256"], packageSize=row["package"]["bytes"],
                     distributionSha256=row["imageSha256"], distributionBytes=row["imageBytes"],
                     descriptorSha256=row["descriptor"]["sha256"], signatureSha256=row["signature"]["sha256"],
                     runtimeManifestSha256="a" * 64, installerInventorySha256="b" * 64,
                     automaticWindowOpen="unexecuted", normalQuit="unexecuted")
        value.update({key: "passed" for key in ("normalBuild", "packageAudit", "installationReadback")})
        value.update({key: True for key in ("originalInstallerReturnedZero", "originalPackageGroupReturnedZero",
            "originalObservationMountDetached", "originalImageFinalizationReturnedZero", "originalFinalImageMountDetached",
            "finalImageScopedNotarizationObserved")})
        value.update({key: False for key in ("fullM2Qualified", "maintenanceQualified", "fullUIQualified",
                                             "distributionQualified", "productReady")})
        return value

    def test_preview_does_not_relabel_old_build_or_infer_product_qualification(self):
        m = ADAPTER
        stager = SimpleNamespace(maintenance_hex=lambda value, length:
            type(value) is str and m.re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None)
        original = self.preview()
        self.assertEqual(m.preview_data(m.canonical(original), stager), original)
        for key, value in (("sourceCommit", "a" * 40), ("sourceTree", "b" * 40),
                           ("productReady", True), ("fullUIQualified", True),
                           ("originalObservationMountDetached", None), ("runtimeManifestSha256", "")):
            with self.subTest(key=key), self.assertRaises(m.Refused):
                m.preview_data(m.canonical({**original, key: value}), stager)

    def test_original_owner_failure_and_capture_uncertainty_are_not_success(self):
        m = ADAPTER
        session = object.__new__(m.Resume)
        session.work, session.environment = Path("/inert-owned-fixture"), {"PATH": "/usr/bin:/bin"}
        session.clock = SimpleNamespace(finality=False, seconds=lambda maximum: maximum)
        session.point = mock.Mock()
        argv = ["/inert-no-native-executable"]
        with mock.patch.dict(m.STATE):
            for code in (0, 65):
                session.calls = []
                session.owner = SimpleNamespace(run_owned=mock.Mock(return_value=SimpleNamespace(
                    args=argv, returncode=code, stdout=b"", stderr=b"")))
                result = session.command("installer", argv, 123)
                self.assertEqual(result.returncode, code)
                self.assertEqual(session.calls[0]["returncode"], code)
                self.assertTrue(session.calls[0]["returned"])
                self.assertEqual(session.owner.run_owned.call_args.kwargs["output_limit"], 256 * 1024)
            for role, stdout, stderr, refused in (("installer", b"x" * 65537, b"", False),
                 ("memory", b"x" * 65537, b"", True), ("installer", b"x" * 150000, b"y" * 150000, True)):
                session.calls = []
                session.owner = SimpleNamespace(run_owned=mock.Mock(return_value=SimpleNamespace(
                    args=argv, returncode=0, stdout=stdout, stderr=stderr)))
                if refused:
                    with self.assertRaises(m.Refused):
                        session.command(role, argv, 123)
                    self.assertFalse(session.calls[0]["returned"])
                else:
                    session.command(role, argv, 123)
            failure = RuntimeError("inert-original-failure")
            failure.contained, failure.cleanup_complete = True, False
            session.calls = []
            session.owner = SimpleNamespace(run_owned=mock.Mock(side_effect=failure))
            with self.assertRaises(RuntimeError) as caught:
                session.command("installer", argv, 123)
            self.assertIs(caught.exception, failure)
            self.assertFalse(session.calls[0]["returned"])
            self.assertFalse(session.calls[0]["capturesSettled"])
            self.assertIs(session.calls[0]["cleanupComplete"], False)
            session.calls = []
            session.owner = SimpleNamespace(run_owned=mock.Mock(return_value=SimpleNamespace(
                args=argv, returncode=0, stdout="not-raw-bytes", stderr=b"")))
            with self.assertRaises(m.Refused):
                session.command("installer", argv, 123)
            self.assertFalse(session.calls[0]["returned"])
            self.assertFalse(session.calls[0]["capturesSettled"])

    def test_quota_failed_allocation_is_not_refunded_and_precedes_next_call(self):
        m = ADAPTER
        failure = RuntimeError("inert-file-allocation-failure")
        book = SimpleNamespace(directories={Path("/"): None, Path("/inert"): None}, entries=[],
                               file=mock.Mock(side_effect=failure))
        quota = m.OriginalQuota()
        quota.books.append(book)
        with self.assertRaises(RuntimeError) as caught:
            quota.call(book, "file", Path("/inert/file"), 1)
        self.assertIs(caught.exception, failure)
        self.assertEqual(quota.reserved, 1)
        quota.reserve(m.MAX_ORIGINALS - 1)
        with self.assertRaises(m.Refused):
            quota.call(book, "file", Path("/inert/second"), 1)
        self.assertEqual(book.file.call_count, 1)

    def test_failure_projection_preserves_first_phase_and_filters_private_or_unknown_values(self):
        m = ADAPTER
        statuses = dict(installer=None, harness=0, ios=65, summary=None, result=None)
        native = dict(schemaVersion=1, scope=m.SCOPE, accepted=False, phase="detach-finality",
                      firstFailurePhase="readback", originalClosesKnown=None, workloadsKnownSettled=False,
                      privateOutputsRetired=None, rawText="private-data-fixture-do-not-export")
        ui = dict(scope="normal-macos-ui-failure-diagnostic-only", phase="test",
                  selection="ios-unsigned-archive-test.xcresult", rawText=native["rawText"],
                  iosUnsignedStages=dict(state="refused", events=[{"stage": "ios-unsigned-project", "result": "failed"}]))
        result = m.finite_failure_data(native, statuses, ui)
        self.assertEqual(result["native"]["phase"], "readback")
        self.assertIsNone(result["native"]["originalClosesKnown"])
        self.assertIs(result["native"]["workloadsKnownSettled"], False)
        self.assertEqual(result["callerStatuses"]["ios"]["returncode"], 65)
        self.assertIs(result["successInferred"], False)
        self.assertNotIn(native["rawText"].encode(), m.canonical(result))
        changed = copy.deepcopy(ui)
        changed["iosUnsignedStages"]["events"][0]["stage"] = native["rawText"]
        self.assertEqual(m.finite_failure_data(native, statuses, changed)["iosUnsignedStages"],
                         {"state": "unavailable", "events": []})
        with self.assertRaises(m.Refused):
            m.finite_failure_data(native, {**statuses, "ios": True}, ui)

        # No tool can silently lose its original admission during call-site split.
        import ast
        body = ast.parse((ROOT / 'desktop/tools/macos_fixed_carrier_resume.py').read_bytes())
        main = next(node for node in body.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'admit_tool']
        self.assertEqual([ast.unparse(node.args[0]) for node in calls],
                         ['session.python', "'/usr/bin/hdiutil'", "'/usr/bin/vm_stat'", "'/usr/bin/openssl'",
                          "'/usr/bin/codesign'", "'/usr/sbin/installer'"])
        self.assertTrue(all(len(node.args) == 1 and not node.keywords for node in calls))
        # Real Python traceback objects, synthetic exception only: no native work.
        secret = 'private-error-value-never-export'
        namespace = {}
        exec(compile("def fault():\n    raise ValueError('" + secret + "')\n",
                     str(ROOT / 'desktop/tools/macos_fixed_carrier_resume.py'), 'exec'), namespace)
        try: namespace['fault']()
        except ValueError as error:
            primary = error
            location = m.failure_location(error)
            self.assertIs(error, primary)
            self.assertEqual(error.args, (secret,))
        self.assertEqual(location['state'], 'observed')
        self.assertEqual(location['exceptionClass'], 'ValueError')
        self.assertEqual(location['frames'], [{'source': 'desktop/tools/macos_fixed_carrier_resume.py', 'line': 2}])
        self.assertTrue(location['foreignFramesExcluded'])
        self.assertFalse(location['truncated'])
        native['failureLocation'] = location
        projected = m.finite_failure_data(native, statuses, ui)
        self.assertEqual(projected['native']['failureLocation'], location)
        self.assertNotIn(secret.encode(), m.canonical(projected))
        self.assertNotIn(str(ROOT).encode(), m.canonical(projected))
        for key, value in (('exceptionClass', secret), ('truncated', 1), ('frames', [{'source': secret, 'line': 2}]),
                           ('frames', [{'source': 'desktop/tools/macos_fixed_carrier_resume.py', 'line': True}]),
                           ('frames', [{'source': 'desktop/tools/macos_fixed_carrier_resume.py', 'line': 100000}])):
            with self.subTest(location_key=key):
                changed = dict(location); changed[key] = value
                self.assertEqual(m.location_data(changed), m.unavailable_location())
        nested = {}; path = str(ROOT / 'desktop/tools/macos_fixed_carrier_resume.py')
        exec(compile("def recurse(n):\n    if n: return recurse(n-1)\n    raise RuntimeError('" + secret + "')\n", path, 'exec'), nested)
        for depth in (10, 70):
            try: nested['recurse'](depth)
            except RuntimeError as error: bounded = m.failure_location(error)
            self.assertEqual(len(bounded['frames']), 8)
            self.assertTrue(bounded['truncated'])
            self.assertNotIn(secret.encode(), m.canonical(bounded))
        # Mixed actual SOURCE filenames: preserve caller routing as well as
        # the latest visited refusal frames, never an unscanned deepest claim.
        routed = {}
        caller_path = str(ROOT / 'desktop/tools/macos_fixed_carrier_resume.py')
        refusal_path = str(ROOT / 'desktop/tools/macos_e2_native_fixture.py')
        exec(compile("def refusal(n):\n    if n: return refusal(n-1)\n    raise RuntimeError('" + secret + "')\n",
                     refusal_path, 'exec'), routed)
        exec(compile("\n" * 10 + "def caller(depth):\n    return refusal(depth)\n", caller_path, 'exec'), routed)
        for depth in (10, 70):
            try: routed['caller'](depth)
            except RuntimeError as error:
                retained = m.failure_location(error)
                self.assertEqual(error.args, (secret,))
            self.assertEqual(len(retained['frames']), 8)
            self.assertTrue(retained['truncated'])
            self.assertEqual(retained['frames'][0],
                             {'source': 'desktop/tools/macos_fixed_carrier_resume.py', 'line': 12})
            self.assertEqual(retained['frames'][-1],
                             {'source': 'desktop/tools/macos_e2_native_fixture.py', 'line': 3 if depth == 10 else 2})
            self.assertNotIn(secret.encode(), m.canonical(retained))
            self.assertNotIn(str(ROOT).encode(), m.canonical(retained))
        with mock.patch.object(m, 'Path', side_effect=RuntimeError(secret)):
            self.assertEqual(m.failure_location(primary), m.unavailable_location())

    def test_fixed_sudo_originals_preserve_quota_snapshot_and_finality(self):
        # Synthetic protocol only: no Darwin syscall, descriptor or command.
        m = ADAPTER
        marker = RuntimeError('inert-primary-acquire-failure')

        def fixture():
            quota = m.OriginalQuota()
            clock = SimpleNamespace(check=mock.Mock())
            api, events = object(), []

            class Book:
                def __init__(self, actual_api, context, actual_clock):
                    self.api, self.context, self.clock = actual_api, context, actual_clock
                    self.nodes, self.errors = {}, []
                    self.budget = {'live': 0, 'uncertain': False}
                    self.result_fd = None
                    self.fail_at = self.close_error_at = None
                    self.change = self.snapshot_error = self.raise_close = False
                    self.close_calls = 0

                def open(self, parent, name, kind, policy, role):
                    self_test.assertIn(wrapper, quota.books)
                    self_test.assertEqual(quota.reserved, 4)
                    path = '/' if parent is None else parent.path.rstrip('/') + '/' + name
                    pre = {'inertGeneration': len(self.nodes), 'inertSnapshotBasis': 'not-native-evidence'}
                    node = SimpleNamespace(path=path, parent=parent, name=name, kind=kind, policy=policy, role=role,
                                           fd=None, close_state='not-opened', pre=None, expected=None)
                    self.nodes[path] = node
                    events.append(('open', path, kind, policy, role))
                    if len(self.nodes) == self.fail_at: raise marker
                    node.fd = 100 + len(self.nodes)  # Never passed to an OS API.
                    node.close_state, node.pre, node.expected = 'owned', pre, pre
                    self.budget['live'] += 1
                    return node

                def snapshot(self, node, phase):
                    events.append(('snapshot', node.path, phase))
                    if self.snapshot_error: self.errors.append('inert-native-ACL-or-snapshot-refusal')
                    return {**node.expected, 'inertGeneration': -1} if self.change else dict(node.expected)

                def close_all(self):
                    self.close_calls += 1
                    if self.raise_close: raise RuntimeError('inert-close-api-failure')
                    errors = []
                    for index, node in enumerate(reversed(list(self.nodes.values()))):
                        if node.fd is None: continue
                        node.fd = None  # Consume before reporting close outcome.
                        events.append(('close', node.path))
                        unknown = index == self.close_error_at
                        node.close_state = 'unknown' if unknown else 'closed'
                        if unknown:
                            errors.append('inert-close-unknown'); self.budget['uncertain'] = True
                        else: self.budget['live'] -= 1
                    return errors

            self_test = self
            module = SimpleNamespace(Originals=Book, _same_snapshot=lambda before, after: before == after)
            wrapper = quota.book(lambda: m.FixedSudoOriginals(module, api, clock, 123))
            self.assertEqual(events, [])  # Inert constructor and registration.
            self.assertIs(wrapper.book.api, api); self.assertIs(wrapper.book.clock, clock)
            self.assertEqual(wrapper.book.context, {'uid': 123})
            return quota, wrapper, events

        quota, wrapper, events = fixture()
        wrapper.acquire(quota)
        self.assertEqual([event[1:] for event in events if event[0] == 'open'], [
            ('/', 'directory', 'native', 'os-provisioner-root'),
            ('/usr', 'directory', 'native', 'os-provisioner-usr'),
            ('/usr/bin', 'directory', 'native', 'os-provisioner-bin'),
            ('/usr/bin/sudo', 'file', 'sudo', 'os-provisioner-sudo')])
        self.assertEqual(len(wrapper.entries), 4)
        self.assertEqual(wrapper.entries[-1]['kind'], 'file')
        quota.check()
        self.assertTrue(quota.finish()); self.assertTrue(quota.finish())
        self.assertEqual(wrapper.book.close_calls, 1)
        self.assertTrue(all(entry['fd'] is None for entry in wrapper.entries))
        self.assertEqual(quota.reserved, 4)
        with self.assertRaises(m.Refused): wrapper.check()

        quota, wrapper, events = fixture()
        quota.reserve(m.MAX_ORIGINALS - 3)
        with self.assertRaises(m.Refused): wrapper.acquire(quota)
        self.assertEqual(events, []); self.assertEqual(quota.reserved, m.MAX_ORIGINALS - 3)
        self.assertTrue(quota.finish())

        quota, wrapper, events = fixture()
        wrapper.book.fail_at = 3
        try:
            wrapper.acquire(quota)
        except RuntimeError as primary:
            self.assertIs(primary, marker)
            self.assertTrue(quota.finish())
        else: self.fail('partial acquisition unexpectedly succeeded')
        self.assertEqual([event[1] for event in events if event[0] == 'close'], ['/usr', '/'])
        self.assertEqual(quota.reserved, 4)

        for fault in ('change', 'snapshot_error', 'missing_fd'):
            with self.subTest(snapshot_fault=fault):
                quota, wrapper, events = fixture(); wrapper.acquire(quota)
                if fault == 'missing_fd':
                    # The view must reflect the actual node; never a cached FD.
                    wrapper.entries[-1].node.fd = None
                    self.assertIsNone(wrapper.entries[-1]['fd'])
                else: setattr(wrapper.book, fault, True)
                with self.assertRaises(m.Refused): quota.check()
                wrapper.book.change = wrapper.book.snapshot_error = False
                with self.assertRaises(m.Refused): quota.check()  # Refusal remains latched.
                quota.finish()

        for fault in ('close_error_at', 'raise_close'):
            with self.subTest(close_fault=fault):
                quota, wrapper, events = fixture(); wrapper.acquire(quota)
                setattr(wrapper.book, fault, 0 if fault == 'close_error_at' else True)
                other = SimpleNamespace(finish=mock.Mock(return_value=True))
                quota.books.insert(0, other)
                self.assertFalse(quota.finish()); other.finish.assert_called_once()
                self.assertFalse(quota.finish()); self.assertEqual(wrapper.book.close_calls, 1)
                if fault == 'close_error_at':
                    self.assertEqual(len([event for event in events if event[0] == 'close']), 4)
                    self.assertTrue(all(entry['fd'] is None for entry in wrapper.entries))
                self.assertEqual(quota.reserved, 4)

        import ast
        body = ast.parse((ROOT / 'desktop/tools/macos_fixed_carrier_resume.py').read_bytes())
        main = next(node for node in body.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        protected = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == 'FixedSudoOriginals']
        self.assertEqual(len(protected), 1)
        retire = next(node for node in ast.walk(body) if isinstance(node, ast.FunctionDef) and node.name == 'retire')
        skips = [node for node in ast.walk(retire) if isinstance(node, ast.If)
                 and ast.unparse(node.test) == 'isinstance(book, FixedSudoOriginals)']
        self.assertEqual(len(skips), 1)
        self.assertEqual(len(skips[0].body), 1); self.assertIsInstance(skips[0].body[0], ast.Continue)

    def test_cleanup_retires_only_owned_outputs_and_refuses_symlink_before_deletion(self):
        m = ADAPTER
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                normal = work / "normal-ui"
                normal.mkdir(mode=0o700)
                outside = work / "unrelated-output"
                outside.mkdir(mode=0o700)
                sentinel = outside / "keep.txt"
                sentinel.write_bytes(b"unrelated-owned-test-sentinel")
                keep = normal / "keep.txt"
                keep.write_bytes(b"unrelated-normal-output")
                for name in ("DerivedData", "ios-unsigned-archive-test.xcresult", "tmp"):
                    if symlink and name == "DerivedData":
                        (normal / name).symlink_to(outside, target_is_directory=True)
                    else:
                        (normal / name).mkdir(mode=0o700)
                        (normal / name / "disposable.txt").write_bytes(b"synthetic-disposable-output")
                for name in ("build.log", "build.stderr", "ios-unsigned-archive-test.log", "ios-unsigned-archive-test.stderr",
                             "ios-unsigned-archive-summary.json", "ios-unsigned-archive-summary.stderr"):
                    (normal / name).write_bytes(b"synthetic-disposable-capture")
                binding = dict(source="a" * 40, runId="2", runAttempt="1",
                               workIdentity=list(m.identity(work.stat())[:5]),
                               normalIdentity=list(m.identity(normal.stat())[:5]))
                path = normal / "consumer-work-binding.json"
                path.write_bytes(m.canonical(binding))
                path.chmod(0o600)
                env = dict(MRK_FIXED_RESULT_OUTCOME="success", MRK_FIXED_UPLOAD_OUTCOME="success",
                           MRK_MACOS_WORK=str(work), GITHUB_SHA="a" * 40, GITHUB_RUN_ID="2", GITHUB_RUN_ATTEMPT="1")
                # The actual joined receipt contract is independently covered
                # above; isolate only its destructive filesystem postconditions.
                with mock.patch.dict(m.os.environ, env, clear=True), mock.patch.object(m, "project_main", return_value={}):
                    if symlink:
                        with self.assertRaises(m.Refused):
                            m.cleanup_main()
                        self.assertTrue((normal / "ios-unsigned-archive-test.xcresult").is_dir())
                        self.assertTrue((normal / "build.log").exists())
                    else:
                        result = m.cleanup_main()
                        self.assertIs(result["taskHarnessOutputsRetired"], True)
                        self.assertIs(result["installedAppRetained"], True)
                        self.assertFalse((normal / "DerivedData").exists())
                        self.assertFalse((normal / "build.log").exists())
                self.assertEqual(sentinel.read_bytes(), b"unrelated-owned-test-sentinel")
                self.assertEqual(keep.read_bytes(), b"unrelated-normal-output")

    def receipt(self, source, run, attempt):
        m, row = RUNNER, ADAPTER.ORIGIN
        value = dict(schemaVersion=1, scope=m.FIXED_RESUME_SCOPE, producerSource=row["source"],
                     producerTree=row["tree"], producerRunId=row["runId"], producerRunAttempt=row["runAttempt"],
                     producerJobId=row["jobId"], artifactId=row["artifactId"], artifactSha256=row["artifactSha256"],
                     consumerSource=source, consumerRunId=run, consumerRunAttempt=attempt, target=m.ARM_TARGET,
                     receiptAuthority="same-consumer-owned-installer-and-readback-not-old-status",
                     productReady=False, p0Qualified=False, intelQualified=False)
        value.update({key: True for key in ("originalInstallerReturnedZero", "sameRequestReadback",
            "originalMountDetached", "originalClosesKnown", "workloadsKnownSettled", "privateOutputsRetired")})
        return value

    def test_success_projection_requires_all_selected_originals_not_job_or_product_success(self):
        m, source = ADAPTER, "a" * 40
        install = self.receipt(source, "2", "1")
        counts = dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0)
        facts = dict(sourceCommit=source, scope="one-ordinary-local-unsigned-ios-archive",
                     nativeResultDisplayed=True, outputPostMatched=True, originalsClosed=True,
                     normalQuitObserved=True, successBeforeCutoff=True, signed=False,
                     ipaExported=False, releaseQualified=False)
        rows = []
        for phase, seconds in (("build", 450), ("test", 1245), ("summary", 90)):
            row = dict(sourceCommit=source, target=m.TARGETS[0], fixedCarrierResumeScope=m.SCOPE,
                       applicationSourceCommit=m.ORIGIN["source"], currentProductQualified=False,
                       p0Qualified=False, intelQualified=False, sourcePrePostMatched=True,
                       originalCommandReturned=True, sourceRosterSha256="b" * 64,
                       receiptPolicy="exclusive0600-readback-consuming-close", commands=[{"returncode": 0}],
                       phaseClock=dict(startNs="1", deadlineNs=str(1 + seconds * 1_000_000_000),
                                       beforePublicationNs="2", postCloseDeadlineRequired=True))
            if phase == "test":
                row.update(normalPhase=phase, originalTestReturncode=0,
                           resultBundle="ios-unsigned-archive-test.xcresult", originalClosesCompleted=True,
                           originalProductsPrePostMatched=True, strictCodesignOriginalZero=True,
                           iosUnsignedObservation=facts)
            else:
                row.update(phase=phase, originalReturncode=0,
                           resultBundle=None if phase == "build" else "ios-unsigned-archive-test.xcresult")
                if phase == "summary":
                    row["iosUnsignedTestCounts"] = counts
            rows.append(row)
        original = (install, *rows, counts, facts)
        result = m.projection_data(*original, source, "2", "1")
        self.assertEqual(result["producerSource"], m.ORIGIN["source"])
        self.assertEqual(result["harnessSource"], source)
        for key in ("currentProductQualified", "p0Qualified", "intelQualified", "signedIOSExportQualified"):
            self.assertIs(result[key], False)
        for index, key, value in ((0, "originalClosesKnown", None), (0, "consumerRunId", "1"),
                                   (1, "sourceCommit", m.ORIGIN["source"]), (2, "originalTestReturncode", 65),
                                   (2, "sourceRosterSha256", "c" * 64), (4, "skippedTests", 1)):
            changed = copy.deepcopy(original)
            changed[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(m.Refused):
                m.projection_data(*changed, source, "2", "1")

    def test_two_source_receipt_is_current_original_only_and_consumes_close(self):
        # Actual private host DATA/guards and source-pin closure; no venv/native execution.
        import ast, stat
        adapter = ADAPTER
        root = Path('/Users/runner/work/_temp/mrk-macos-installed.TEST1234/host-python')
        uid, gid = adapter.os.getuid(), adapter.os.getgid()
        base_path = '/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
        base = dict(launcherPath=base_path, executable=base_path, copyPath=base_path,
                    copyExecutable=base_path, prefix=str(Path(base_path).parent.parent),
                    identity=[1, 2, stat.S_IFREG | 0o775, 0, 0, 1, 3, 4, 5], sha256=adapter.sha(b'exe'))
        cfg = ('home = ' + str(Path(base_path).parent) + '\ninclude-system-site-packages = false\nversion = 3.14.7\nexecutable = ' + base_path +
               '\ncommand = ' + base_path + ' -m venv --copies --without-pip --without-scm-ignore-files ' + str(root) + '\n').encode()
        roster = adapter.HOST_FILES + (adapter.HOST_OPTIONAL,)
        dir_names = {'.': ['bin', 'include', 'lib', 'pyvenv.cfg'], 'bin': [Path(p).name for p in roster if p.startswith('bin/')],
                     'include': [], 'lib': ['python3.14'], 'lib/python3.14': ['site-packages'], 'lib/python3.14/site-packages': []}
        bodies = {p: (cfg if p == 'pyvenv.cfg' else b'exe' if p in ('bin/python', 'bin/python3', 'bin/python3.14', adapter.HOST_OPTIONAL) else b'data') for p in roster}
        def directory(path):
            relative = '.' if path == root else path.relative_to(root).as_posix()
            return (1, adapter.HOST_DIRS.index(relative) + 10, stat.S_IFDIR | 0o700, uid, gid), dir_names[relative]
        def read_file(path, limit):
            relative = path.relative_to(root).as_posix(); body = bodies[relative]
            mode = 0o755 if body == b'exe' else 0o600
            return (1, roster.index(relative) + 20, stat.S_IFREG | mode, uid, gid, 1, len(body), 4, 5), body
        snapshot, actual_cfg = adapter.host_snapshot(root, directory, read_file)
        context = dict(executable=str(root/'bin/python3'), prefix=str(root), basePrefix=base['prefix'], baseExecutable=base_path)
        binding = dict(schemaVersion=1, source='a'*40, runId='2', runAttempt='1', base=base, prefix=str(root),
                       basePrefix=base['prefix'], baseExecutable=base_path, **snapshot, retainedUntilHostedTeardown=True)
        self.assertEqual(adapter.host_selection_data(binding, snapshot, actual_cfg, root, context, 'a'*40, '2', '1'), sum(map(len, bodies.values())))
        for key, value in (('executable', str(root/'bin/python')), ('prefix', str(root.parent)),
                           ('basePrefix', str(root)), ('baseExecutable', '/unrelated/python3')):
            with self.subTest(hostContext=key), self.assertRaises(adapter.Refused):
                adapter.host_selection_data(binding, snapshot, cfg, root, {**context, key: value}, 'a'*40, '2', '1')
        for key, value in (('source', 'b'*40), ('runId', '1'), ('totalBytes', snapshot['totalBytes']+1), ('retainedUntilHostedTeardown', False)):
            with self.subTest(hostBinding=key), self.assertRaises(adapter.Refused):
                adapter.host_selection_data({**binding, key: value}, snapshot, cfg, root, context, 'a'*40, '2', '1')
        for old, new in ((b'version = 3.14.7', b'version = 3.12.0'), (b'include-system-site-packages = false', b'include-system-site-packages = true'),
                         (b'--copies', b'--symlinks'), (b'home = ', b'home = /unrelated/')):
            with self.subTest(hostConfig=new), self.assertRaises(adapter.Refused):
                adapter.host_config_data(cfg.replace(old,new), base, root)
        with self.assertRaises(adapter.Refused): adapter.host_config_data(cfg+b'version = 3.14.7\n',base,root)
        changed_snapshot = copy.deepcopy(snapshot); changed_snapshot['files'][1]['sha256'] = 'b'*64
        with self.assertRaises(adapter.Refused):
            adapter.host_selection_data({**binding, **changed_snapshot}, changed_snapshot, cfg, root, context, 'a'*40, '2', '1')
        for change in ('extra', 'symlink-directory', 'writable-directory', 'hardlink', 'writable-file', 'symlink-file'):
            def bad_directory(path):
                original, names = directory(path)
                if change == 'extra' and path == root: names = names + ['unexpected-output']
                if path == root/'bin' and change in ('symlink-directory', 'writable-directory'):
                    original = (*original[:2], stat.S_IFLNK|0o700 if change=='symlink-directory' else stat.S_IFDIR|0o722, *original[3:])
                return original,names
            def bad_file(path, limit):
                original, body = read_file(path,limit)
                if path == root/'bin/python3':
                    original = list(original)
                    if change=='hardlink': original[5]=2
                    elif change=='writable-file': original[2]|=0o022
                    elif change=='symlink-file': original[2]=stat.S_IFLNK|0o755
                return original,body
            with self.subTest(hostRoster=change), self.assertRaises(adapter.Refused):
                adapter.host_snapshot(root,bad_directory,bad_file)
        # Real host_read implementation with synthetic syscall observations;
        # verify first error is preserved and the one original is consumed once.
        fields = dict(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o755,st_uid=uid,st_gid=gid,st_nlink=1,st_size=3,st_mtime_ns=4,st_ctime_ns=5)
        original = SimpleNamespace(**fields)
        with mock.patch.object(adapter.os,'open',return_value=101), mock.patch.object(adapter.os,'fstat',return_value=original), \
             mock.patch.object(adapter.os,'stat',return_value=original), mock.patch.object(adapter.os,'pread',side_effect=lambda fd,n,off:b'exe' if off==0 else b''), \
             mock.patch.object(adapter.os,'close') as closed:
            self.assertEqual(adapter.host_read(root/'bin/python3',64), (adapter.identity(original),b'exe'))
            self.assertEqual(closed.call_args_list,[mock.call(101)])
            for key,value in (('st_mode',stat.S_IFREG|0o777), ('st_mode',stat.S_IFLNK|0o755), ('st_nlink',2), ('st_size',65)):
                closed.reset_mock()
                with mock.patch.object(adapter.os,'fstat',return_value=SimpleNamespace(**{**fields,key:value})), self.assertRaises(adapter.Refused):
                    adapter.host_read(root/'bin/python3',64)
                self.assertEqual(closed.call_args_list,[mock.call(101)])
            for short,eof,changed in ((b'ex',b'',False),(b'exe',b'x',False),(b'exe',b'',True)):
                closed.reset_mock()
                with mock.patch.object(adapter.os,'pread',side_effect=lambda fd,n,off:short if off==0 else eof), \
                     mock.patch.object(adapter.os,'stat',return_value=SimpleNamespace(**{**fields,'st_ino':3}) if changed else original), self.assertRaises(adapter.Refused):
                    adapter.host_read(root/'bin/python3',64)
                self.assertEqual(closed.call_args_list,[mock.call(101)])
            closed.reset_mock();closed.side_effect=OSError('synthetic-close-unknown')
            with self.assertRaisesRegex(ValueError,'resume-host-file-close'):adapter.host_read(root/'bin/python3',64)
            self.assertEqual(closed.call_args_list,[mock.call(101)])
            closed.reset_mock()
            first = RuntimeError('synthetic-original-read-failure')
            with mock.patch.object(adapter.os,'pread',side_effect=first), self.assertRaises(RuntimeError) as caught:
                adapter.host_read(root/'bin/python3',64)
            self.assertIs(caught.exception,first);self.assertEqual(closed.call_args_list,[mock.call(101)])
            self.assertIn('resume-host-file-close',first.__notes__)
        workflow = (ROOT/adapter.RESUME_WORKFLOW).read_bytes()
        helper = (ROOT/'desktop/tools/macos_fixed_carrier_resume.py').read_bytes()
        self.assertEqual(len(workflow),adapter.RESUME_WORKFLOW_BYTES)
        self.assertIn(('MRK_FIXED_RESUME_BYTES: "'+str(len(helper))+'"').encode(),workflow)
        self.assertIn(('MRK_FIXED_RESUME_SHA256: "'+adapter.sha(helper)+'"').encode(),workflow)
        self.assertIn(b'-m venv --copies --without-pip --without-scm-ignore-files "$work/host-python"',workflow)
        self.assertIn(b'"$work/host-python/bin/python3" -I -S -B -',workflow)
        # Actual inline private admission functions must be byte-logic identical.
        text = workflow.decode();block=text.split("<<'PY_RESUME_PYTHON'\n",1)[1].split('\n          PY_RESUME_PYTHON',1)[0]
        import textwrap
        inline_ast = ast.parse(textwrap.dedent(block));helper_ast=ast.parse(helper)
        for name in ('host_read','host_directory','host_config_data','host_snapshot','host_selection_data'):
            left=next(n for n in inline_ast.body if isinstance(n,ast.FunctionDef) and n.name==name)
            right=next(n for n in helper_ast.body if isinstance(n,ast.FunctionDef) and n.name==name)
            self.assertEqual(ast.dump(left,include_attributes=False),ast.dump(right,include_attributes=False))
        m, source = RUNNER, "a" * 40
        env = dict(TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=m.FIXED_RESUME_SOURCE,
                   GITHUB_REPOSITORY="Apdelrahman1911/mobile-release-kit", GITHUB_EVENT_NAME="push",
                   GITHUB_REF="refs/heads/verify/desktop-macos-installed", GITHUB_SHA=source,
                   GITHUB_WORKFLOW_SHA=source, GITHUB_RUN_ID="2", GITHUB_RUN_ATTEMPT="1",
                   GITHUB_WORKFLOW_REF="Apdelrahman1911/mobile-release-kit/" + m.FIXED_RESUME_WORKFLOW +
                                       "@refs/heads/verify/desktop-macos-installed",
                   RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="macOS", RUNNER_ARCH="ARM64")
        env[m.FIXED_RESUME_ENV] = m.FIXED_RESUME_SCOPE
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixed-carrier-install.json"
            request = dict(target=m.ARM_TARGET, phase="test", iosUnsigned=True, derived=Path(temporary) / "DerivedData")
            original = self.receipt(source, "2", "1")
            def write(value):
                body = m.encoded(value) + b"\n"
                path.write_bytes(body)
                path.chmod(0o600)
                return m.sha(body)
            env["MRK_FIXED_RESUME_RECEIPT_SHA256"] = write(original)
            # Passive Linux DATA fixture: emulate the required native interpreter only here.
            with mock.patch.dict(m.os.environ, env, clear=True), mock.patch.object(m.sys, "version_info", (3, 14, 7)):
                self.assertEqual(m.fixed_resume_context(request, source), {m.FIXED_RESUME_ENV: m.FIXED_RESUME_SCOPE})
                with mock.patch.object(m.sys, "version_info", (3, 12, 0)), self.assertRaises(m.Refused):
                    m.fixed_resume_context(request, source)
                for key, value in (("consumerRunId", "1"), ("producerSource", source),
                                   ("originalClosesKnown", None), ("sameRequestReadback", False),
                                   ("productReady", True), ("intelQualified", True)):
                    m.os.environ["MRK_FIXED_RESUME_RECEIPT_SHA256"] = write({**original, key: value})
                    with self.subTest(key=key), self.assertRaises(m.Refused):
                        m.fixed_resume_context(request, source)
                m.os.environ["MRK_FIXED_RESUME_RECEIPT_SHA256"] = write(original)
                for changed in ({**request, "target": m.INTEL_TARGET}, {**request, "iosUnsigned": False},
                                {**request, "androidPositive": True}):
                    with self.assertRaises(m.Refused):
                        m.fixed_resume_context(changed, source)
                real_close = m.os.close
                closed = []
                def failed_close(fd):
                    real_close(fd)
                    closed.append(fd)
                    raise OSError("inert-close-result-unknown")
                with mock.patch.object(m.os, "close", side_effect=failed_close), self.assertRaises(m.Refused):
                    m.fixed_resume_context(request, source)
                self.assertEqual(len(closed), 1)
                m.os.environ["MRK_FIXED_RESUME_RECEIPT_SHA256"] = write({**original, "consumerRunId": "1"})
                with mock.patch.object(m.os, "close", side_effect=failed_close), self.assertRaises(m.Refused) as caught:
                    m.fixed_resume_context(request, source)
                self.assertEqual(caught.exception.args, ("fixed-resume-native-receipt-join",))

    def test_dormant_p1_hybrids_and_original_release_readback_remain_closed(self):
        # Passive actual SOURCE units + ordinary API ports only. No native
        # signature/Installer/Keychain/Xcode operation or qualification here.
        import ast
        from collections import namedtuple
        import contextlib
        import hashlib
        import os
        import platform
        import pwd
        import re
        import resource
        import stat
        import types
        m, r = ADAPTER, RUNNER
        path = ROOT / "desktop/tools/stage_macos_installed.py"
        tree = ast.parse(path.read_bytes())
        wanted = {"Refused", "need", "sha", "digest", "canonical", "pairs", "decode", "mac_target", "command_target",
                  "source_build_selection", "selected_build", "build_release_data", "safe_path", "directories",
                  "maintenance_hex", "maintenance_map", "maintenance_json", "maintenance_release_data",
                  "maintenance_producer_data", "observation_inventory_bytes", "original_release_readback_selection",
                  "original_release_readback_members", "observation_command"}
        definitions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in wanted]
        self.assertEqual({n.name for n in definitions}, wanted)
        assignments = {t.id: n for n in tree.body if isinstance(n, ast.Assign)
                       for t in n.targets if isinstance(t, ast.Name)}
        constants = {n.id for definition in definitions for n in ast.walk(definition)
                     if isinstance(n, ast.Name) and n.id.isupper()} - {"PACKAGE_VERSION", "RELEASE"}
        constants.update({"APP_BINARY", "ARM_TARGET", "BUNDLE_ID", "CURRENT_PROTOCOL", "ENTRY_BINARY",
                          "INSTALLATION_INVENTORY_NAME", "INTEL_TARGET", "PACKAGE_ID", "PAYLOAD_INFO", "VAULT_HELPER"})
        constants.add("BuildSelection")
        pending = list(constants)
        while pending:
            name = pending.pop()
            if name not in assignments:
                continue
            for node in ast.walk(assignments[name].value):
                if isinstance(node, ast.Call):
                    self.assertIsInstance(node.func, ast.Name)
                    self.assertIn(node.func.id, {"Path", "namedtuple"})
                if isinstance(node, ast.Name) and node.id.isupper() and node.id not in constants:
                    constants.add(node.id); pending.append(node.id)
        namespace = dict(__file__=str(path), __name__="stagea_actual_readback_data", Path=Path, namedtuple=namedtuple,
                         hashlib=hashlib, json=json, re=re, os=os, stat=stat)
        selected = [n for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id in constants for t in n.targets)] + definitions
        exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), str(path), "exec"), namespace)
        stage = types.SimpleNamespace(**namespace)
        current = stage.build_release_data((ROOT / "desktop/macos-installed-inputs/build-release.json").read_bytes())
        namespace.update(PACKAGE_VERSION=current["packageVersion"], RELEASE=current["release"])
        self.assertEqual(stage.source_build_selection().package_version, "0.1.2")
        manifest = "a" * 64
        paths = {"app/" + stage.ENTRY_BINARY, "app/" + stage.APP_BINARY, "app/" + stage.VAULT_HELPER,
                 "app/Contents/Info.plist", "app/" + stage.PAYLOAD_INFO, "runtime/python/bin/python3", "runtime/manifest.json"}
        executable = {"app/" + stage.ENTRY_BINARY, "app/" + stage.APP_BINARY, "app/" + stage.VAULT_HELPER,
                      "runtime/python/bin/python3"}
        inventory = stage.canonical(dict(schemaVersion=1, release=m.ORIGIN["release"], runtimeManifestSha256=manifest,
            files=[dict(path=p, sha256=manifest if p == "runtime/manifest.json" else "b" * 64,
                        size=1, executable=p in executable) for p in sorted(paths)]))
        policy = dict(schemaVersion=1, kind="mrk-macos-developer-id-code-policy-v1", teamIdentifier="ABCDE12345",
                      leafCertificateSha1="c" * 40, leafCertificateSha256="d" * 64, hardenedRuntime=True, entitlements="empty")
        policy_sha = m.sha(json.dumps(policy, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii"))
        release = dict(profile="fixed-macos26-arm64-maintenance-v2", packageIdentifier=stage.PACKAGE_ID,
                       bundleIdentifier=stage.BUNDLE_ID, packageVersion=m.ORIGIN["packageVersion"], release=m.ORIGIN["release"],
                       sourceCommit=m.ORIGIN["source"], protocolSha256=stage.CURRENT_PROTOCOL,
                       runtimeManifestSha256=manifest, inventorySha256=m.sha(inventory), signingPolicySha256=policy_sha,
                       packageSha256=m.ORIGIN["package"]["sha256"])
        descriptor = stage.canonical(dict(schemaVersion=2, kind="mrk-macos-install-producer-v2",
            domain="MobileReleaseKit-package-producer-v2", target=stage.ARM_TARGET,
            releaseSet=dict(schemaVersion=2, current=release, acceptedPredecessors=[]),
            signingPolicies=[dict(sha256=policy_sha, policy=policy)]))
        producer = stage.maintenance_producer_data(descriptor, target=stage.ARM_TARGET)
        signed = b"synthetic-signature-not-native-evidence"
        mounted = {k: copy.deepcopy(m.ORIGIN[k]) for k in ("source", "tree", "runId", "runAttempt", "jobId", "artifactId",
                                                         "artifactSha256", "package", "descriptor", "signature")}
        mounted.update(target=stage.ARM_TARGET, release=release,
                       inventory=dict(name=stage.INSTALLATION_INVENTORY_NAME, bytes=len(inventory), sha256=m.sha(inventory)),
                       signingPolicy=dict(sha256=policy_sha, policy=policy))
        # Explicit synthetic nomination for member bytes only. Fixed artifact
        # metadata remains real SOURCE; this does not claim a native signature.
        with mock.patch.dict(m.ORIGIN, descriptor=dict(name="producer.json", bytes=len(descriptor), sha256=m.sha(descriptor)),
                             signature=dict(name="producer.sig", bytes=len(signed), sha256=m.sha(signed))):
            mounted["descriptor"] = copy.deepcopy(m.ORIGIN["descriptor"])
            mounted["signature"] = copy.deepcopy(m.ORIGIN["signature"])
            record = m.original_release_readback_data(mounted, inventory, target=stage.ARM_TARGET)
            for key in ("source", "artifactId", "artifactSha256"):
                changed = copy.deepcopy(mounted); changed[key] = "e" * 40
                with self.subTest(provenance=key), self.assertRaises(m.Refused):
                    m.original_release_readback_data(changed, inventory, target=stage.ARM_TARGET)
        self.assertEqual(set(record), {"schemaVersion", "purpose", "target", "release", "descriptor", "signature", "inventory"})
        args = SimpleNamespace(target=stage.ARM_TARGET, expected_source=release["sourceCommit"],
                               expected_inventory=release["inventorySha256"], expected_manifest=manifest,
                               expected_package=release["packageSha256"], input=Path("/synthetic-readback-input"), request_id="f" * 32)
        selection = stage.original_release_readback_selection(args, record)
        self.assertEqual(selection.package_version, "0.1.1")
        self.assertEqual(stage.source_build_selection().package_version, "0.1.2")
        self.assertEqual(len(stage.observation_inventory_bytes(inventory, args.expected_inventory, manifest, selection=selection)), len(paths))
        with self.assertRaises(stage.Refused):
            stage.observation_inventory_bytes(inventory, args.expected_inventory, manifest)
        stage.original_release_readback_members(record, producer, descriptor, signed, inventory)
        for key, value in (("schemaVersion", True), ("purpose", "other"), ("target", stage.INTEL_TARGET), ("extra", False)):
            changed = copy.deepcopy(record); changed[key] = value
            with self.subTest(record=key), self.assertRaises(stage.Refused):
                stage.original_release_readback_selection(args, changed)
        for key in ("descriptor", "signature", "inventory"):
            for field, value in (("bytes", True), ("bytes", 0), ("sha256", "0" * 63), ("extra", False)):
                changed = copy.deepcopy(record); changed[key][field] = value
                with self.subTest(member=key, field=field), self.assertRaises(stage.Refused):
                    stage.original_release_readback_selection(args, changed)
        for key in ("descriptor", "signature", "inventory"):
            changed = copy.deepcopy(record); changed[key]["sha256"] = "0" * 64
            with self.subTest(member_digest=key), self.assertRaises(stage.Refused):
                stage.original_release_readback_members(changed, producer, descriptor, signed, inventory)
        changed = copy.deepcopy(record); changed["release"]["packageVersion"] = "bad-version"
        with self.assertRaises(stage.Refused): stage.original_release_readback_selection(args, changed)
        for field in ("expected_source", "expected_inventory", "expected_manifest", "expected_package"):
            altered = copy.copy(args); setattr(altered, field, "e" * (40 if field == "expected_source" else 64))
            with self.subTest(argument=field), self.assertRaises(stage.Refused):
                stage.original_release_readback_selection(altered, record)
        for bodies in ((descriptor + b"x", signed, inventory), (descriptor, signed + b"x", inventory),
                       (descriptor, signed, inventory + b"x")):
            with self.assertRaises(stage.Refused): stage.original_release_readback_members(record, producer, *bodies)
        changed = copy.deepcopy(producer); changed["releaseSet"]["current"]["packageVersion"] = "0.1.2"
        with self.assertRaises(stage.Refused): stage.original_release_readback_members(record, changed, descriptor, signed, inventory)
        events = []
        class ReachedFreshGate(Exception): pass
        result = dict(invocation="1" * 32, requestId=args.request_id, action="fresh-install")
        state = dict(invocation=result["invocation"], requestId=args.request_id, intendedAction="fresh-install", retained=[], previousEvidence=[])
        @contextlib.contextmanager
        def parent_port(_):
            events.append("parent"); yield 90, "fixture"
        @contextlib.contextmanager
        def directory_port(*_):
            yield 91, dict(device=1)
        def roster_port(*_):
            events.append("fresh-gate"); raise ReachedFreshGate()
        def producer_port(*_):
            events.append("producer"); return producer, descriptor, signed
        def result_port(*_):
            events.append("installer-result"); return result, {}
        def read_port(*_):
            events.append("inventory"); return inventory
        ports = dict(installer_result_readback=result_port, maintenance_producer_inputs=producer_port, read=read_port,
                     installer_channel_parent=parent_port, maintenance_directory=directory_port,
                     maintenance_metadata_leaf=lambda *_: b"synthetic-already-parsed-state",
                     maintenance_state_data=lambda *_: state, maintenance_history_data=lambda *_: (state, {result["invocation"]: {}}),
                     maintenance_roster_data=roster_port)
        with mock.patch.dict(namespace, ports):
            with self.assertRaises(ReachedFreshGate): stage.observation_command(args, original_release_readback=record)
            self.assertEqual(events, ["installer-result", "producer", "inventory", "parent", "fresh-gate"])
            for keyword, value in (("expected_previous", dict(invocation="2" * 32, sha256="c" * 64)),
                                   ("expected_restore_previous", dict(invocation="2" * 32, sha256="c" * 64)),
                                   ("nominated_update_predecessor", {}), ("expected_update_previous", {}), ("update_facts", {})):
                events.clear()
                with self.subTest(purpose=keyword), self.assertRaises(stage.Refused):
                    stage.observation_command(args, original_release_readback=record, **{keyword: value})
                self.assertEqual(events, [])
            for key, value in (("action", "update"),):
                with mock.patch.dict(result, {key: value}), self.assertRaises(stage.Refused):
                    stage.observation_command(args, original_release_readback=record)
            for key, value in (("intendedAction", "update"), ("retained", [{}]), ("previousEvidence", [dict(invocation="2" * 32)])):
                with mock.patch.dict(state, {key: value}), self.assertRaises(stage.Refused):
                    stage.observation_command(args, original_release_readback=record)
        # Actual two runner hybrids; native/platform/owner checks use ordinary
        # synthetic API ports and are fully restored before filesystem cleanup.
        source = "3" * 40
        root = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
        derived = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH/normal-ui/DerivedData")
        env = dict(PATH="/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", USER="runner", LOGNAME="runner",
                   TMPDIR=str(derived.parent / "tmp") + "/", LANG="en_US.UTF-8", LC_ALL="en_US.UTF-8", TZ="UTC",
                   DEVELOPER_DIR=r.DEVELOPER, TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=r.normal_target_data(r.ARM_TARGET)[1],
                   TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=source, TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=source,
                   GITHUB_SHA=source, GITHUB_WORKFLOW_SHA=source, GITHUB_REPOSITORY="Apdelrahman1911/mobile-release-kit",
                   GITHUB_EVENT_NAME="push", RUNNER_ENVIRONMENT="github-hosted", GITHUB_WORKSPACE=str(root),
                   RUNNER_OS="macOS", RUNNER_ARCH="ARM64", GITHUB_RUN_ID="1", GITHUB_RUN_ATTEMPT="1")
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, env, clear=True))
            stack.enter_context(mock.patch.object(r, "__file__", str(root / "desktop/tools/macos_normal_ui_runner.py")))
            stack.enter_context(mock.patch.object(Path, "cwd", return_value=root))
            stack.enter_context(mock.patch.object(r.sys, "platform", "darwin"))
            stack.enter_context(mock.patch.object(platform, "machine", return_value="arm64"))
            stack.enter_context(mock.patch.object(platform, "mac_ver", return_value=("26.1", (), "arm64")))
            stack.enter_context(mock.patch.object(r.sys, "version_info", (3, 14, 7)))
            stack.enter_context(mock.patch.object(r.sys, "flags", SimpleNamespace(isolated=1, no_site=1)))
            stack.enter_context(mock.patch.object(r.sys, "dont_write_bytecode", True))
            for name, value in (("getuid", 501), ("geteuid", 501), ("getgid", 20), ("getegid", 20)):
                stack.enter_context(mock.patch.object(os, name, return_value=value))
            stack.enter_context(mock.patch.object(pwd, "getpwuid", return_value=SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="runner", pw_dir="/Users/runner")))
            stack.enter_context(mock.patch.object(os, "stat", return_value=SimpleNamespace(st_uid=501)))
            stack.enter_context(mock.patch.object(r, "normal_file_limit", return_value=(1, 1)))
            fixed = stack.enter_context(mock.patch.object(r, "fixed_resume_context", return_value={r.FIXED_RESUME_ENV: r.FIXED_RESUME_SCOPE}))
            request = dict(target=r.ARM_TARGET, phase="build", derived=derived)
            self.assertEqual(r.normal_context(request)[1], source)
            fixed.assert_not_called()
            with mock.patch.dict(os.environ, TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=m.ORIGIN["source"]):
                with self.assertRaises(r.Refused): r.normal_context(request)
            with mock.patch.dict(os.environ, {r.FIXED_RESUME_ENV: r.FIXED_RESUME_SCOPE,
                                             "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": m.ORIGIN["source"],
                                             "GITHUB_REF": "refs/heads/verify/desktop-macos-installed"}):
                self.assertEqual(r.normal_context(request)[2][r.FIXED_RESUME_ENV], r.FIXED_RESUME_SCOPE)
                mixed = dict(request, credentialUpdate="p0-bootstrap")
                with self.assertRaises(r.Refused): r.normal_context(mixed)
            with mock.patch.dict(os.environ, GITHUB_REF=r.CREDENTIAL_UPDATE_REF,
                                 GITHUB_WORKFLOW_REF="Apdelrahman1911/mobile-release-kit/" + r.CREDENTIAL_UPDATE_WORKFLOW + "@" + r.CREDENTIAL_UPDATE_REF):
                update = dict(request, credentialUpdate="p0-bootstrap")
                self.assertEqual(r.normal_context(update)[1], source)
                self.assertEqual(update["credentialContext"]["source"], source)
                with mock.patch.dict(os.environ, GITHUB_REF="refs/heads/verify/desktop-macos-installed"):
                    with self.assertRaises(r.Refused): r.normal_context(dict(request, credentialUpdate="p1-resume"))
        token = object()
        with mock.patch.object(r, "execute_credential_update_phase", return_value=token) as delegated:
            req = dict(credentialUpdate="p0-bootstrap")
            self.assertIs(r.execute_normal_phase(None, req, source, (1, 1)), token)
            delegated.assert_called_once_with(None, req, source, (1, 1))
        with tempfile.TemporaryDirectory() as temporary:
            result_dir = Path(temporary) / "test.xcresult"; result_dir.mkdir(mode=0o700)
            original = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            phase = SimpleNamespace(environment={r.FIXED_RESUME_ENV: r.FIXED_RESUME_SCOPE}, records=[],
                                    call=mock.Mock(return_value=original),
                                    clock=SimpleNamespace(before_publication=lambda: {}, check=mock.Mock()))
            request = dict(target=r.ARM_TARGET, phase="summary", derived=Path(temporary) / "DerivedData", result=result_dir)
            with mock.patch.object(r, "normal_source_state", return_value={"source": source}), mock.patch.object(r, "exclusive_output") as output:
                self.assertIs(r.execute_normal_phase(phase, request, source, (1, 1)), original)
                facts = json.loads(output.call_args.args[1])
                self.assertEqual(facts["applicationSourceCommit"], m.ORIGIN["source"])
                self.assertTrue(facts["sourcePrePostMatched"])
                self.assertFalse(facts["currentProductQualified"])
                self.assertFalse(facts["p0Qualified"])
                self.assertFalse(facts["intelQualified"])
                phase.call.assert_called_once()
                phase.clock.check.assert_called_once()
            with mock.patch.object(r, "normal_source_state", side_effect=[{}, {"changed": True}]), mock.patch.object(r, "exclusive_output") as output:
                with self.assertRaises(r.Refused): r.execute_normal_phase(phase, request, source, (1, 1))
                output.assert_not_called()
        swift = (ROOT / "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        self.assertEqual(swift.count("private enum SourceProfile { case sameBuild, packagedEntry, fixedCarrierResume, updateP0Bootstrap }"), 1)
        self.assertEqual(swift.count("case .fixedCarrierResume:"), 1)
        self.assertEqual(swift.count("case .updateP0Bootstrap:"), 1)
        picker = swift[swift.index("private func goToFolder("):swift.index("@MainActor private func nativeOpen(")]
        self.assertEqual(picker.count('sheet.buttons.matching(identifier: "Cancel")'), 1)
        self.assertNotIn("cancel.click()", picker)
        self.assertLess(picker.index("path.hasPrefix"), picker.index('identifier: "Cancel"'))
        self.assertLess(picker.index("cancel.isHittable"), picker.index('sheet.typeKey("g"'))
        self.assertIn("pathField.value as? String == path", picker)
        self.assertIn("owned", picker)
        workflow = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text()
        ordinary_if = workflow.splitlines()[23]
        self.assertNotIn("github.ref == 'refs/heads/verify/desktop-macos-installed'", ordinary_if)
        self.assertIn("github.ref == 'refs/heads/verify/desktop-macos-positive-update'", ordinary_if)
        fixed_workflow = (ROOT / ".github/workflows/desktop-macos-fixed-carrier-resume.yml").read_text()
        self.assertIn(m.sha((ROOT / "desktop/tools/macos_fixed_carrier_resume.py").read_bytes()), fixed_workflow)
        pins = next(ast.literal_eval(n.value) for n in ast.parse((ROOT / "desktop/tools/macos_android_dependency_preparation.py").read_bytes()).body
                    if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PINS" for t in n.targets))
        body = (ROOT / "desktop/tools/macos_normal_ui_runner.py").read_bytes()
        self.assertEqual(pins["desktop/tools/macos_normal_ui_runner.py"], [len(body), m.sha(body)])
        self.assertEqual(m.SOURCE_PINS["desktop/tools/stage_macos_installed.py"], (path.stat().st_size, m.sha(path.read_bytes())))



if __name__ == "__main__":
    unittest.main()
