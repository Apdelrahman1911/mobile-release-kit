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


        # Normal local batches retain an earlier independently joined pass;
        # later failure/absence cannot manufacture or erase that observation.
        batch = "launch-project"
        families = [r[0] for r in m.NORMAL_FAMILIES[batch]]
        normal_statuses = {families[0]: dict(test=0, summary=0, result=0),
                           families[1]: dict(test=65, summary=None, result=None)}
        normal_native = {**native, "scope": m.NORMAL_SCOPE, "normalBatch": batch}
        retained = m.normal_failure_data(normal_native, batch, normal_statuses, {families[0]}, 0)
        self.assertEqual([(r["family"], r["state"]) for r in retained["families"]],
                         [(families[0], "passed"), (families[1], "failed")])
        self.assertEqual(retained["native"]["phase"], "readback")
        self.assertIsNone(retained["native"]["originalClosesKnown"])
        self.assertIs(retained["native"]["workloadsKnownSettled"], False)
        self.assertIs(retained["successInferred"], False)
        self.assertNotIn(native["rawText"].encode(), m.canonical(retained))
        for key, value in (("test", 65), ("summary", None), ("result", True)):
            bad_statuses = copy.deepcopy(normal_statuses)
            bad_statuses[families[0]][key] = value
            with self.subTest(normalPassedStatus=key), self.assertRaises(m.Refused):
                m.normal_failure_data(normal_native, batch, bad_statuses, {families[0]}, 0)
        missing = {family: dict(test=None, summary=None, result=None) for family in families}
        unavailable = m.normal_failure_data(None, batch, missing, set(), None)
        self.assertEqual([r["state"] for r in unavailable["families"]], ["not-run", "not-run"])
        self.assertEqual(unavailable["native"]["state"], "unavailable")
        self.assertIsNone(unavailable["harnessReturncode"])
        zeros_without_original = {family: dict(test=0, summary=0, result=0) for family in families}
        unknown = m.normal_failure_data(None, batch, zeros_without_original, set(), 0)
        self.assertEqual([r["state"] for r in unknown["families"]], ["unknown", "unknown"])
        with self.assertRaises(m.Refused):
            m.normal_failure_data(normal_native, batch, missing, {"foreign.xcresult"}, 0)
        for wrong in (None, True, "foreign-batch"):
            with self.subTest(normalBatch=wrong), self.assertRaises(m.Refused):
                m.normal_batch_data({m.NORMAL_BATCH_ENV: wrong})

        # Original resource numbers distinguish memory and disk without changing
        # either admission floor or exposing host/environment/private strings.
        for memory_ok, disk_ok in ((False, False), (False, True), (True, False), (True, True)):
            observation = m.resource_admission_data(100 if memory_ok else 99, 100, 200 if disk_ok else 199, 200)
            self.assertEqual((observation["memorySufficient"], observation["diskSufficient"]), (memory_ok, disk_ok))
            self.assertFalse(observation["osMemoryReservation"])
            self.assertFalse(observation["peakRssQualified"])
            self.assertEqual(m.resource_projection_data(observation), observation)
            observed = m.finite_failure_data({**native, "resourceAdmission": observation}, statuses, ui)
            self.assertEqual(observed["native"]["resourceAdmission"], observation)
            normal_observed = m.normal_failure_data({**normal_native, "resourceAdmission": observation}, batch, normal_statuses, {families[0]}, 0)
            self.assertEqual(normal_observed["native"]["resourceAdmission"], observation)
            for key, value in (("availableMemoryEstimateBytes", True), ("requiredMemoryBytes", 0),
                               ("availableDiskBytes", -1), ("requiredDiskBytes", 1 << 53),
                               ("memorySufficient", not memory_ok), ("diskSufficient", not disk_ok),
                               ("osMemoryReservation", True), ("peakRssQualified", True),
                               ("availableMemoryEstimateBytes", secret)):
                with self.subTest(resourceKey=key, memory=memory_ok, disk=disk_ok):
                    changed = {**observation, key: value}
                    self.assertIsNone(m.resource_projection_data(changed))
                    filtered = m.finite_failure_data({**native, "resourceAdmission": changed}, statuses, ui)
                    self.assertIsNone(filtered["native"]["resourceAdmission"])
                    self.assertNotIn(secret.encode(), m.canonical(filtered))
            self.assertIsNone(m.resource_projection_data({**observation, "unrelated": secret}))
        for values in ((True, 100, 200, 200), (100, 0, 200, 200), (100, 100, -1, 200), (100, 100, 200, 1 << 53)):
            with self.subTest(resourceValues=values), self.assertRaises(m.Refused):
                m.resource_admission_data(*values)
        self.assertIsNone(m.resource_projection_data(None))

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


        # Real normal sibling cleanup uses the same fd-based symlink-safe
        # primitive, narrowed to this batch's exact settled result roster.
        for batch in m.NORMAL_FAMILIES:
            for symlink in ((False, True) if batch == "launch-project" else (False,)):
                with self.subTest(normalBatch=batch, symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                    work = Path(temporary)
                    normal = work / "normal-ui"; normal.mkdir(mode=0o700)
                    outside = work / "unrelated-output"; outside.mkdir(mode=0o700)
                    sentinel = outside / "keep.txt"; sentinel.write_bytes(b"unrelated-owned-test-sentinel")
                    host = work / "host-python"; host.mkdir(mode=0o700)
                    (host / "keep.txt").write_bytes(b"retained-private-host-original")
                    keep = normal / "keep.txt"; keep.write_bytes(b"unrelated-normal-output")
                    unselected = normal / "unselected-result.xcresult"; unselected.mkdir(mode=0o700)
                    (unselected / "keep.txt").write_bytes(b"unselected-original")
                    roots = ["DerivedData", *[r[0] for r in m.NORMAL_FAMILIES[batch]], "tmp"]
                    for name in roots:
                        if symlink and name == "DerivedData":
                            (normal / name).symlink_to(outside, target_is_directory=True)
                        else:
                            (normal / name).mkdir(mode=0o700)
                            (normal / name / "disposable.txt").write_bytes(b"synthetic-disposable-output")
                    disposable = ["build.log", "build.stderr"]
                    retained_files = ["fixed-carrier-install.json", "fixed-normal-batch.json", "fixed-normal-diagnostic.json"]
                    for _, test_stem, summary_stem, _, _ in m.NORMAL_FAMILIES[batch]:
                        disposable.extend((test_stem + ".log", test_stem + ".stderr", summary_stem + ".json", summary_stem + ".stderr"))
                        retained_files.extend((test_stem + ".status", summary_stem + ".status", "fixed-normal-" + test_stem + ".json"))
                    for name in disposable: (normal / name).write_bytes(b"synthetic-disposable-capture")
                    for name in retained_files: (normal / name).write_bytes(b"retained-finite-original")
                    binding = dict(source="a" * 40, runId="2", runAttempt="1",
                        workIdentity=list(m.identity(work.stat())[:5]), normalIdentity=list(m.identity(normal.stat())[:5]))
                    binding_path = normal / "consumer-work-binding.json"
                    binding_path.write_bytes(m.canonical(binding)); binding_path.chmod(0o600)
                    env = dict(MRK_FIXED_RESULT_OUTCOME="success", MRK_FIXED_UPLOAD_OUTCOME="success",
                               GITHUB_SHA="a" * 40, GITHUB_RUN_ID="2", GITHUB_RUN_ATTEMPT="1")
                    # Joined family/batch authority is covered by the actual
                    # reducer and readback cases below; isolate filesystem effects.
                    with mock.patch.dict(m.os.environ, env, clear=True), \
                         mock.patch.object(m, "normal_batch_project_main", return_value={}), \
                         mock.patch.object(m, "normal_projection_context", return_value=(env, batch, normal)):
                        if symlink:
                            with self.assertRaises(m.Refused): m.normal_cleanup_main()
                            self.assertTrue(all((normal / r[0]).is_dir() for r in m.NORMAL_FAMILIES[batch]))
                            self.assertTrue((normal / "build.log").exists())
                        else:
                            retired = m.normal_cleanup_main()
                            self.assertIs(retired["taskHarnessOutputsRetired"], True)
                            self.assertIs(retired["installedAppRetained"], True)
                            self.assertIs(retired["separateSyntheticFixtureRetired"], False)
                            self.assertFalse(any((normal / name).exists() for name in roots + disposable))
                    self.assertEqual(sentinel.read_bytes(), b"unrelated-owned-test-sentinel")
                    self.assertEqual(keep.read_bytes(), b"unrelated-normal-output")
                    self.assertEqual((host / "keep.txt").read_bytes(), b"retained-private-host-original")
                    self.assertEqual((unselected / "keep.txt").read_bytes(), b"unselected-original")
                    self.assertTrue(all((normal / name).exists() for name in retained_files))
        # Failed or unknown publication has no normal cleanup authority.
        for bad in ({"MRK_FIXED_RESULT_OUTCOME": "failure"}, {"MRK_FIXED_UPLOAD_OUTCOME": "skipped"}):
            with mock.patch.dict(m.os.environ, {"MRK_FIXED_RESULT_OUTCOME": "success", "MRK_FIXED_UPLOAD_OUTCOME": "success", **bad}, clear=True), \
                 mock.patch.object(m, "normal_batch_project_main") as no_read, self.assertRaises(m.Refused):
                m.normal_cleanup_main()
            no_read.assert_not_called()

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


        # Genuine finite normal reducer inputs for all four closed batches and
        # all seven result families. No native status or signature is fabricated.
        def command(role, cap, limit, output=b""):
            return dict(role=role, returncode=0, timeoutSeconds=cap, roleCapSeconds=cap,
                        outputLimitBytes=limit, argvSha256="d" * 64, stdoutBytes=len(output),
                        stdoutSha256=m.sha(output), stderrBytes=0, stderrSha256=m.sha(b""))
        def normal_row(batch, phase, seconds, bundle, summary_body):
            source_role = ("normal-ui-source-roster", 15, 1048576)
            roles = ([source_role, *[("normal-toolchain-" + k, 15, 4096) for k in ("xcode", "sdkPath", "sdkVersion", "sdkBuild")],
                      ("normal-ui-build", 240, 1048576), source_role] if phase == "build" else
                     [source_role, ("verify-generated-runner", 30, 1048576), ("generated-runner-entitlements", 30, 1048576),
                      ("one-admitted-ui-test", {345: 180, 585: 420, 885: 720}[seconds], 1048576), source_role] if phase == "test" else
                     [source_role, ("normal-ui-summary", 30, 262144), source_role])
            commands = [command(role, cap, limit, b"source-roster" if role == source_role[0] else
                                summary_body if role == "normal-ui-summary" else b"") for role, cap, limit in roles]
            row = dict(sourceCommit=source, target=m.TARGETS[0], fixedCarrierResumeScope=m.NORMAL_SCOPE,
                fixedNormalBatch=batch, applicationSourceCommit=m.ORIGIN["source"], currentProductQualified=False,
                p0Qualified=False, intelQualified=False, sourcePrePostMatched=True, originalCommandReturned=True,
                sourceRosterSha256="b" * 64, receiptPolicy="exclusive0600-readback-consuming-close", commands=commands,
                phaseClock=dict(startNs="1", deadlineNs=str(1 + seconds * 1_000_000_000), beforePublicationNs="2", postCloseDeadlineRequired=True),
                resultBundle=bundle)
            if phase == "test":
                row.update(normalPhase="test", originalTestReturncode=0, originalClosesCompleted=True,
                    originalProductsPrePostMatched=True, strictCodesignOriginalZero=True, reSignedOrRepaired=False,
                    projectFieldAndEditMarkersObserved=True, androidToolSourceBrowseMarkerObserved=True,
                    managedWorkflowRefusalMarkerObserved=True, savedReleaseEvidenceMarkerObserved=True)
            else: row.update(phase=phase, originalReturncode=0)
            return row
        self.assertEqual({batch: tuple(row[0] for row in families) for batch, families in m.NORMAL_FAMILIES.items() if batch != "saved-version-recovery"}, {batch:rows for batch,rows in RUNNER.FIXED_NORMAL_BATCHES.items() if batch != "saved-version-recovery"})
        self.assertEqual(len(m.NORMAL_FAMILIES), 5)
        self.assertEqual(sum(len(families) for families in m.NORMAL_FAMILIES.values()), 8)
        fixtures = {}
        for batch, families in m.NORMAL_FAMILIES.items():
            if batch == "saved-version-recovery": continue  # Separate genuine prefix/witness case below.
            self.assertEqual(m.normal_batch_data({m.NORMAL_BATCH_ENV: batch}), batch)
            normal_install = {**self.receipt(source, "2", "1"), "scope": m.NORMAL_SCOPE, "normalBatch": batch}
            fixtures[batch] = []
            for bundle, test_stem, summary_stem, count, seconds in families:
                summary_body = m.canonical(dict(totalTestCount=count, passedTests=count, failedTests=0, skippedTests=0, expectedFailures=0))
                normal_rows = [normal_row(batch, phase, budget, result, summary_body)
                    for phase, budget, result in (("build", 450, None), ("test", seconds, bundle), ("summary", 90, bundle))]
                inputs = (normal_install, *normal_rows, summary_body)
                with self.subTest(normalBatch=batch, family=bundle):
                    projected = m.normal_family_projection_data(*inputs, batch, bundle, source, "2", "1")
                    self.assertEqual(projected["testCounts"]["passedTests"], count)
                    self.assertEqual(projected["producerSource"], m.ORIGIN["source"])
                    self.assertEqual(projected["harnessSource"], source)
                    self.assertEqual(projected["familyResult"], "passed")
                    self.assertTrue(all(projected[k] is False for k in ("rawTextExported", "currentProductQualified", "p0Qualified", "intelQualified", "productReady")))
                fixtures[batch].append((bundle, test_stem, summary_stem, inputs, projected))
        batch = "launch-project"
        bundle, test_stem, summary_stem, inputs, expected = fixtures[batch][0]
        for index, key, value in ((0, "producerSource", source), (0, "consumerRunId", "1"),
                                 (0, "originalClosesKnown", None), (0, "productReady", True),
                                 (1, "sourceCommit", m.ORIGIN["source"]), (2, "sourceRosterSha256", "c" * 64),
                                 (2, "originalClosesCompleted", None), (2, "strictCodesignOriginalZero", False),
                                 (2, "reSignedOrRepaired", True)):
            changed = copy.deepcopy(inputs); changed[index][key] = value
            with self.subTest(normalOriginal=key), self.assertRaises(m.Refused):
                m.normal_family_projection_data(*changed, batch, bundle, source, "2", "1")
        for mutation in ("role", "count", "clock", "source-output", "summary-digest", "test-counts"):
            changed = list(copy.deepcopy(inputs))
            if mutation == "role": changed[2]["commands"][3]["role"] = "foreign-native-role"
            elif mutation == "count": changed[1]["commands"].pop()
            elif mutation == "clock": changed[2]["phaseClock"]["deadlineNs"] = "3"
            elif mutation == "source-output": changed[1]["commands"][-1]["stdoutSha256"] = "c" * 64
            elif mutation == "summary-digest": changed[3]["commands"][1]["stdoutSha256"] = "c" * 64
            else:
                wrong_counts = json.loads(changed[4]); wrong_counts["skippedTests"] = 1
                changed[4] = m.canonical(wrong_counts)
            with self.subTest(normalMutation=mutation), self.assertRaises(m.Refused):
                m.normal_family_projection_data(*changed, batch, bundle, source, "2", "1")
        with self.assertRaises(m.Refused):
            m.normal_family_projection_data(*inputs, batch, "diagnostics-test.xcresult", source, "2", "1")
        # Actual per-family and batch projectors consume genuine tiny regular
        # source receipts; only the already-reviewed host context is a DATA port.
        with tempfile.TemporaryDirectory() as temporary:
            normal = Path(temporary)
            env = dict(GITHUB_SHA=source, GITHUB_RUN_ID="2", GITHUB_RUN_ATTEMPT="1")
            def put(name, value):
                body = value if type(value) is bytes else m.canonical(value) + b"\n"
                path = normal / name; path.write_bytes(body); path.chmod(0o600)
            for current_bundle, stem, summary_name, current_inputs, projected in fixtures[batch]:
                put("build.status", b"0\n"); put(stem + ".status", b"0\n"); put(summary_name + ".status", b"0\n")
                for name, row in zip(("fixed-carrier-install.json", "build.command-admission.json",
                                     stem + ".runner-admission.json", summary_name + ".command-admission.json"), current_inputs[:4]): put(name, row)
                put(summary_name + ".json", current_inputs[4])
                put("fixed-normal-" + stem + ".json", projected)
            with mock.patch.object(m, "normal_projection_context", return_value=(env, batch, normal)):
                self.assertEqual(m.normal_project_main(bundle), expected)
                joined = m.normal_batch_project_main()
                self.assertEqual([r["family"] for r in joined["families"]], [r[0] for r in m.NORMAL_FAMILIES[batch]])
                self.assertEqual(joined["batchResult"], "passed")
                self.assertIs(joined["productReady"], False)
                wrong = normal / ("fixed-normal-" + fixtures[batch][1][1] + ".json")
                original_publication = wrong.read_bytes(); wrong.write_bytes(original_publication + b" ")
                with self.assertRaises(m.Refused): m.normal_batch_project_main()
                wrong.write_bytes(original_publication)
                real_close = m.os.close; closed = []
                def consumed_unknown(fd):
                    real_close(fd); closed.append(fd)
                    if len(closed) == 1: raise OSError("synthetic-consuming-close-unknown")
                with mock.patch.object(m.os, "close", side_effect=consumed_unknown), self.assertRaisesRegex(m.Refused, "resume-normal-projection-close"):
                    m.normal_project_main(bundle)
                self.assertEqual(len(closed), 8)
                closed.clear(); put(test_stem + ".status", b"65\n")
                with mock.patch.object(m.os, "close", side_effect=consumed_unknown), self.assertRaises(m.Refused) as caught:
                    m.normal_project_main(bundle)
                self.assertEqual(caught.exception.args, ("resume-normal-caller-zero",))
                self.assertIn("resume-normal-projection-close", caught.exception.__notes__)
                self.assertEqual(len(closed), 2)

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


        # Actual closed normal request/context, with explicit original-file DATA ports.
        # These observations do not execute a host tool, Installer, XCTest or app.
        from contextlib import ExitStack
        import re
        normal_root = Path("/inert-owned-normal-data/normal-ui")
        temporary = str(normal_root / "tmp") + "/"
        expected_batches = {
            "launch-project": ("test.xcresult", "project-test.xcresult"),
            "doctor-saved-checks": ("diagnostics-test.xcresult", "saved-checks-test.xcresult"),
            "local-github-evidence": ("workflow-refusal-test.xcresult", "release-evidence-test.xcresult"),
            "persistence": ("persistence-test.xcresult",),
            "saved-version-recovery": ("saved-version-recovery-test.xcresult",),
        }
        self.assertEqual(m.FIXED_NORMAL_BATCHES, expected_batches)
        self.assertEqual(m.FIXED_NORMAL_SCOPE, "fixed-ce644-arm-carrier-normal-local-batch-v1")
        self.assertEqual(m.FIXED_NORMAL_BATCH_ENV, "TEST_RUNNER_MRK_NORMAL_UI_FIXED_NORMAL_BATCH")
        self.assertEqual(expected_batches["saved-version-recovery"], (m.SAVED_VERSION_RESULT,))
        def parsed(result, phase):
            if phase == "build":
                arguments = ["--normal-build"]
            elif phase == "summary":
                arguments = ["--normal-summary", result]
            else:
                methods, allowance, _ = m.NORMAL_SELECTIONS[result]
                arguments = ["test-without-building", "-project", m.PROJECT, "-scheme", "MRKNormalAppUI",
                    "-configuration", "Debug", "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15",
                    "-derivedDataPath", str(normal_root / "DerivedData"), "-resultBundlePath", str(normal_root / result),
                    *["-only-testing:" + m.CLASS + name for name in methods], "-parallel-testing-enabled", "NO",
                    "-test-timeouts-enabled", "YES", "-default-test-execution-time-allowance", str(allowance),
                    "-maximum-test-execution-time-allowance", str(allowance), "-disableAutomaticPackageResolution"]
            return m.normal_request(arguments, temporary)
        observation = {}
        fd = 501
        uid, gid = m.os.getuid(), m.os.getgid()
        def file_state():
            return SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
                st_uid=uid, st_gid=gid, st_nlink=1, st_size=len(observation["body"]), st_mtime_ns=4, st_ctime_ns=5)
        def held(value):
            self.assertEqual(value, fd)
            return file_state()
        def named(path, *, follow_symlinks):
            self.assertEqual(path, normal_root / "fixed-carrier-install.json")
            self.assertIs(follow_symlinks, False)
            return file_state()
        def pread(value, maximum, offset):
            self.assertEqual(value, fd)
            return observation["body"][offset:offset + maximum]
        normal_env = {**env, m.FIXED_RESUME_ENV: m.FIXED_NORMAL_SCOPE,
                      "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": m.normal_target_data(m.ARM_TARGET)[1]}
        with ExitStack() as ports:
            opened = ports.enter_context(mock.patch.object(m.os, "open", return_value=fd))
            fstat_port = ports.enter_context(mock.patch.object(m.os, "fstat", side_effect=held))
            stat_port = ports.enter_context(mock.patch.object(m.os, "stat", side_effect=named))
            read_port = ports.enter_context(mock.patch.object(m.os, "pread", side_effect=pread))
            closed = ports.enter_context(mock.patch.object(m.os, "close"))
            ports.enter_context(mock.patch.object(m.sys, "version_info", (3, 14, 7)))
            ports.enter_context(mock.patch.object(m.sys, "flags", SimpleNamespace(isolated=True, no_site=True)))
            ports.enter_context(mock.patch.object(m.sys, "dont_write_bytecode", True))
            def nominate(row):
                observation["body"] = m.encoded(row) + b"\n"
                for port in (opened, fstat_port, stat_port, read_port, closed): port.reset_mock()
                normal_env["MRK_FIXED_RESUME_RECEIPT_SHA256"] = m.sha(observation["body"])
            for batch, results in expected_batches.items():
                normal_env[m.FIXED_NORMAL_BATCH_ENV] = batch
                normal_receipt = {**self.receipt(source, "2", "1"), "scope": m.FIXED_NORMAL_SCOPE, "normalBatch": batch}
                if batch == "saved-version-recovery":
                    normal_receipt["savedVersionRuntimeOrigin"] = dict(scope=m.SAVED_VERSION_RUNTIME_SCOPE,
                        sourceCommit=m.FIXED_RESUME_SOURCE, release=m.SAVED_VERSION_ORIGINAL_RELEASE,
                        runtimeManifestSha256="a"*64, installationInventorySha256="b"*64)
                cases = [(None, "build"), *[(r, p) for r in results for p in ("test", "summary")]]
                for result, phase in cases:
                    request = parsed(result, phase)
                    nominate(normal_receipt)
                    with self.subTest(normalBatch=batch, phase=phase, result=result), mock.patch.dict(m.os.environ, normal_env, clear=True):
                        self.assertEqual(m.fixed_normal_context(request, source),
                            {m.FIXED_RESUME_ENV: m.FIXED_NORMAL_SCOPE, m.FIXED_NORMAL_BATCH_ENV: batch})
                    opened.assert_called_once_with(normal_root / "fixed-carrier-install.json",
                        m.os.O_RDONLY | m.os.O_NOFOLLOW | m.os.O_NONBLOCK | m.os.O_CLOEXEC)
                    self.assertEqual(closed.call_args_list, [mock.call(fd)])
                    self.assertEqual((fstat_port.call_count, stat_port.call_count, read_port.call_count), (3, 2, 2))
            batch = "launch-project"
            normal_env[m.FIXED_NORMAL_BATCH_ENV] = batch
            normal_receipt = {**self.receipt(source, "2", "1"), "scope": m.FIXED_NORMAL_SCOPE, "normalBatch": batch}
            request = parsed("test.xcresult", "test")
            for changed in ({**request, "methods": ()}, {**request, "allowance": 300},
                            {**request, "result": normal_root / "diagnostics-test.xcresult"},
                            {**request, "target": m.INTEL_TARGET}, {**request, "iosUnsigned": True}):
                nominate(normal_receipt)
                with self.subTest(normalRequest=changed), mock.patch.dict(m.os.environ, normal_env, clear=True), self.assertRaises(m.Refused):
                    m.fixed_normal_context(changed, source)
                opened.assert_not_called(); closed.assert_not_called()
            for changes in ({m.FIXED_RESUME_ENV: m.FIXED_RESUME_SCOPE}, {m.FIXED_RESUME_ENV: "foreign-scope"},
                            {m.FIXED_NORMAL_BATCH_ENV: "foreign-batch"}, {"GITHUB_SHA": "b" * 40}):
                nominate(normal_receipt)
                with self.subTest(normalContext=changes), mock.patch.dict(m.os.environ, {**normal_env, **changes}, clear=True), self.assertRaises(m.Refused):
                    m.fixed_normal_context(request, source)
                opened.assert_not_called(); closed.assert_not_called()
            nominate(normal_receipt)
            without_batch = {k: v for k, v in normal_env.items() if k != m.FIXED_NORMAL_BATCH_ENV}
            with mock.patch.dict(m.os.environ, without_batch, clear=True), self.assertRaises(m.Refused):
                m.fixed_normal_context(request, source)
            opened.assert_not_called()
            # The actual dispatch rejects the opposite partial marker before native host admission.
            partial = {k: v for k, v in normal_env.items() if k != m.FIXED_RESUME_ENV}
            partial["TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE"] = source
            partial["TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE"] = source
            with mock.patch.dict(m.os.environ, partial, clear=True), self.assertRaisesRegex(m.Refused, "fixed-normal-marker-pair"):
                m.normal_context(request)
            opened.assert_not_called()
            for key, value in (("normalBatch", "persistence"), ("scope", m.FIXED_RESUME_SCOPE),
                               ("producerSource", source), ("consumerRunId", "1"),
                               ("sameRequestReadback", False), ("originalClosesKnown", None), ("productReady", True)):
                nominate({**normal_receipt, key: value})
                with self.subTest(normalReceipt=key), mock.patch.dict(m.os.environ, normal_env, clear=True), self.assertRaises(m.Refused):
                    m.fixed_normal_context(request, source)
                self.assertEqual(closed.call_args_list, [mock.call(fd)])
            nominate(normal_receipt)
            with mock.patch.dict(m.os.environ, normal_env, clear=True), mock.patch.object(m.os, "close", side_effect=OSError("synthetic-close-unknown")) as once:
                with self.assertRaisesRegex(m.Refused, "fixed-resume-native-receipt-close"):
                    m.fixed_normal_context(request, source)
                self.assertEqual(once.call_args_list, [mock.call(fd)])
            nominate({**normal_receipt, "sameRequestReadback": False})
            with mock.patch.dict(m.os.environ, normal_env, clear=True), mock.patch.object(m.os, "close", side_effect=OSError("synthetic-close-unknown")) as once:
                with self.assertRaises(m.Refused) as caught:
                    m.fixed_normal_context(request, source)
                self.assertEqual(caught.exception.args, ("fixed-resume-native-receipt-join",))
                self.assertIn("fixed-resume-native-receipt-close", caught.exception.__notes__)
                self.assertEqual(once.call_args_list, [mock.call(fd)])
            nominate(normal_receipt)
            first = RuntimeError("synthetic-normal-original-read-failure")
            with mock.patch.dict(m.os.environ, normal_env, clear=True), mock.patch.object(m.os, "pread", side_effect=first), \
                 mock.patch.object(m.os, "close", side_effect=OSError("synthetic-close-unknown")) as once:
                with self.assertRaises(RuntimeError) as caught:
                    m.fixed_normal_context(request, source)
                self.assertIs(caught.exception, first)
                self.assertIn("fixed-resume-native-receipt-close", first.__notes__)
                self.assertEqual(once.call_args_list, [mock.call(fd)])
        # Actual Swift SOURCE: closed result-to-profile calls remain after each original clock.
        swift = (ROOT / "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift").read_text()
        self.assertIn('private func launchForJourney(profile: SourceProfile = .sameBuild)', swift)
        self.assertIn('case .sameBuild:\n            try require(applicationSource == harnessSource,', swift)
        self.assertIn('context["MRK_NORMAL_UI_FIXED_CARRIER_RESUME"] == "fixed-ce644-arm-carrier-ios-unsigned-only"', swift)
        self.assertIn('scope == "fixed-ce644-arm-carrier-normal-local-batch-v1" && results.contains(result)', swift)
        selected_sources = {
            "launchCancelAndQuit": ("test.xcresult", 1),
            "syntheticProjectJourney": ("project-test.xcresult", 1),
            "testSyntheticProjectPathFields": ("project-test.xcresult", 1),
            "testSyntheticPersistentCredentials": ("persistence-test.xcresult", 3),
            "testSyntheticProjectBuildToolDiagnostics": ("diagnostics-test.xcresult", 1),
            "testSyntheticProjectSavedOfflineChecks": ("saved-checks-test.xcresult", 1),
            "testSyntheticProjectEmptyBuildInputInspection": ("saved-checks-test.xcresult", 1),
            "testSyntheticProjectManagedWorkflowRefusal": ("workflow-refusal-test.xcresult", 1),
            "testSyntheticProjectSavedReleaseEvidence": ("release-evidence-test.xcresult", 1),
        }
        for name, (result, count) in selected_sources.items():
            start = re.search(r'^    (?:@MainActor )?(?:private )?func ' + name + r'\(', swift, re.M)
            self.assertIsNotNone(start)
            rest = swift[start.end():]
            next_member = re.search(r'^    (?:@MainActor\b|(?:private )?(?:static )?func\b|private (?:final )?class\b)', rest, re.M)
            block = rest[:next_member.start()] if next_member else rest
            literal = 'normalJourneyProfile(for: "' + result + '")'
            with self.subTest(swiftMethod=name):
                self.assertEqual(block.count(literal), count)
                self.assertLess(block.index('try beginCase('), block.index(literal))
        local = swift.split('private func syntheticProjectJourney(includeImages: Bool) throws {', 1)[1]
        self.assertIn('if includeImages {\n                profile = try normalJourneyProfile(for: "project-test.xcresult")\n            } else {\n                profile = .sameBuild', local)


        # Saved-only original-runtime witness. Tiny DATA nominations exercise the
        # actual SOURCE-selected parsers, not the restart producer/app/runtime.
        import io, zipfile, hashlib, types
        from collections import namedtuple
        runner, adapter = RUNNER, ADAPTER
        stage_path = ROOT / runner.SAVED_VERSION_STAGER
        stage_tree = ast.parse(stage_path.read_bytes())
        wanted = {"Refused", "need", "sha", "digest", "canonical", "pairs", "decode", "mac_target",
                  "source_build_selection", "selected_build", "build_release_data", "safe_path", "directories",
                  "observation_inventory_bytes", "manifest_files", "current_core_matches"}
        definitions = [n for n in stage_tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in wanted]
        self.assertEqual({n.name for n in definitions}, wanted)
        assignments = {t.id:n for n in stage_tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t,ast.Name)}
        constants = {n.id for definition in definitions for n in ast.walk(definition) if isinstance(n,ast.Name) and n.id.isupper()} - {"PACKAGE_VERSION","RELEASE"}
        constants.add("BuildSelection")
        pending = list(constants)
        while pending:
            name = pending.pop()
            if name not in assignments: continue
            for item in ast.walk(assignments[name].value):
                if isinstance(item,ast.Call):
                    self.assertIsInstance(item.func, ast.Name); self.assertIn(item.func.id, {"Path","namedtuple"})
                if isinstance(item,ast.Name) and item.id.isupper() and item.id not in constants:
                    constants.add(item.id); pending.append(item.id)
        selected = [n for n in stage_tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in constants for t in n.targets)] + definitions
        namespace = dict(__file__=str(stage_path), __name__="saved_original_runtime_data", Path=Path, namedtuple=namedtuple,
                         hashlib=hashlib, json=json, re=re, os=adapter.os, stat=stat, io=io, zipfile=zipfile)
        exec(compile(ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[])),str(stage_path),"exec"), namespace)
        stage = types.SimpleNamespace(**namespace)
        namespace.update(PACKAGE_VERSION="0.1.2", RELEASE="macos26-arm64-desktop-02")
        fixed = {"desktop/"+name for name in runner.SAVED_VERSION_BOOTSTRAPS}
        fixed.update(("desktop/cpython-source-inputs/github-ca.pem","desktop/tools/prepare_runtime.py","desktop/packaging/macos-history-provider.profile"))
        source_bytes = {name:b"tiny-SOURCE-data" for name in fixed}
        for index in range(178-len(fixed)-1): source_bytes["src/mobile_release/unit%03d.py"%index] = b"tiny-core-SOURCE\n"
        source_bytes["src/mobile_release/__init__.py"] = b'__version__ = "0.3.0"\n'
        synthetic_s = runner.sha(runner.encoded([dict(path=n,size=len(source_bytes[n]),sha256=runner.sha(source_bytes[n])) for n in sorted(source_bytes)]))
        out = io.BytesIO()
        with zipfile.ZipFile(out,"w",compression=zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(n for n in source_bytes if n.startswith("src/mobile_release/")):
                info=zipfile.ZipInfo(name[len("src/"):],date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
                info.create_system=3;info.external_attr=(stat.S_IFREG|0o644)<<16
                archive.writestr(info,source_bytes[name])
        core_body=out.getvalue()
        bootstraps={name:source_bytes["desktop/"+name] for name in runner.SAVED_VERSION_BOOTSTRAPS}
        bootstraps["github-ca.pem"]=source_bytes["desktop/cpython-source-inputs/github-ca.pem"]
        runtime_bodies={"core.zip":core_body,**bootstraps,"python/bin/python3":b"not-an-executed-interpreter"}
        rows=[dict(path=n,size=len(b),sha256=adapter.sha(b)) for n,b in sorted(runtime_bodies.items())]
        manifest_body=stage.canonical(dict(schemaVersion=1,protocol=1,coreVersion="0.3.0",target=stage.ARM_TARGET,
                          coreSha256=adapter.sha(core_body),protocolSha256=stage.CURRENT_PROTOCOL,
                          inventorySha256=adapter.sha(stage.canonical(rows)),files=rows))
        inv={"runtime/"+n:dict(path="runtime/"+n,size=len(b),sha256=adapter.sha(b),executable=n=="python/bin/python3") for n,b in runtime_bodies.items()}
        inv["runtime/manifest.json"]=dict(path="runtime/manifest.json",size=len(manifest_body),sha256=adapter.sha(manifest_body),executable=False)
        for name in {"app/"+stage.ENTRY_BINARY,"app/"+stage.APP_BINARY,"app/"+stage.VAULT_HELPER,"app/Contents/Info.plist","app/"+stage.PAYLOAD_INFO}:
            inv[name]=dict(path=name,size=1,sha256=adapter.sha(b"a"),executable=name in {"app/"+stage.ENTRY_BINARY,"app/"+stage.APP_BINARY,"app/"+stage.VAULT_HELPER})
        inventory=stage.canonical(dict(schemaVersion=1,release=runner.SAVED_VERSION_ORIGINAL_RELEASE,runtimeManifestSha256=adapter.sha(manifest_body),files=[inv[n] for n in sorted(inv)]))
        origin=dict(scope=runner.SAVED_VERSION_RUNTIME_SCOPE,sourceCommit=runner.FIXED_RESUME_SOURCE,release=runner.SAVED_VERSION_ORIGINAL_RELEASE,
                    runtimeManifestSha256=adapter.sha(manifest_body),installationInventorySha256=adapter.sha(inventory))
        with mock.patch.object(runner,"SAVED_VERSION_SOURCE",synthetic_s):
            witness=runner.saved_version_runtime_data(stage,origin,inventory,manifest_body,core_body,bootstraps,source_bytes,runner.ARM_TARGET)
            self.assertEqual(witness["coreVersion"],"0.3.0");self.assertIs(witness["runtimeOriginalsMatched"],True)
            self.assertNotIn("qualification",witness)
            for field,value in (("scope","current-runtime"),("sourceCommit","f"*40),("release","macos26-arm64-desktop-02"),("runtimeManifestSha256",True),("extra",False)):
                changed={**origin,field:value}
                with self.subTest(runtimeOrigin=field),self.assertRaises(runner.Refused):
                    runner.saved_version_runtime_data(stage,changed,inventory,manifest_body,core_body,bootstraps,source_bytes,runner.ARM_TARGET)
            for index,args in enumerate(((inventory+b" ",manifest_body,core_body,bootstraps,source_bytes),
                        (inventory,manifest_body+b" ",core_body,bootstraps,source_bytes),
                        (inventory,manifest_body,core_body+b"foreign",bootstraps,source_bytes),
                        (inventory,manifest_body,core_body,{**bootstraps,"engine_bootstrap.py":b"foreign"},source_bytes),
                        (inventory,manifest_body,core_body,bootstraps,{**source_bytes,"src/mobile_release/extra.py":b"foreign"}))):
                with self.subTest(runtimeBytes=index),self.assertRaises((runner.Refused,stage.Refused,zipfile.BadZipFile)):
                    runner.saved_version_runtime_data(stage,origin,*args,runner.ARM_TARGET)
        with self.assertRaises(stage.Refused): stage.observation_inventory_bytes(inventory,origin["installationInventorySha256"],origin["runtimeManifestSha256"])
        fixture=runner.SavedVersionFixture.__new__(runner.SavedVersionFixture)
        fixture.fds=[31,32];fixture.runtime_stack=None;fixture.runtime_stager=None
        first=OSError("synthetic-consuming-close")
        with mock.patch.object(runner.os,"close",side_effect=[first,None]) as consuming,self.assertRaises(OSError) as caught:
            fixture.close()
        self.assertIs(caught.exception,first);self.assertEqual(consuming.call_args_list,[mock.call(32),mock.call(31)])
        self.assertIn('module.installation_metadata_directory(module.INSTALL_ROOT, names, selection=selection)', (ROOT/'desktop/tools/macos_normal_ui_runner.py').read_text())
        self.assertIn('"runtime-result.json", 65536', (ROOT/'desktop/tools/macos_normal_ui_runner.py').read_text())
        self.assertIn('launchForJourney(profile: try normalJourneyProfile(for: "saved-version-recovery-test.xcresult"))',swift)
        self.assertIn('origin["coreVersion"] as? String == "0.3.0"',swift)
        # Exact saved prefix census: owned SOURCE query0 then actual interrupt86.
        row=dict(sourceCommit=source,target=adapter.TARGETS[0],fixedCarrierResumeScope=adapter.NORMAL_SCOPE,fixedNormalBatch="saved-version-recovery",
                 applicationSourceCommit=adapter.ORIGIN["source"],currentProductQualified=False,p0Qualified=False,intelQualified=False,
                 sourcePrePostMatched=True,originalCommandReturned=True,normalPhase="test",resultBundle=runner.SAVED_VERSION_RESULT,
                 originalTestReturncode=0,receiptPolicy="exclusive0600-readback-consuming-close",sourceRosterSha256="a"*64,
                 phaseClock=dict(startNs="1",deadlineNs=str(1+585*10**9),beforePublicationNs="2",postCloseDeadlineRequired=True))
        roles=[("normal-ui-source-roster",15,1048576,0),("saved-version-source-roster",15,65536,0),("saved-version-core-interrupt",20,65536,86),
               ("verify-generated-runner",30,1048576,0),("generated-runner-entitlements",30,1048576,0),("one-admitted-ui-test",420,1048576,0),("normal-ui-source-roster",15,1048576,0)]
        row["commands"]=[dict(role=role,returncode=code,timeoutSeconds=cap,roleCapSeconds=cap,outputLimitBytes=limit,argvSha256="a"*64,
                               stdoutBytes=1,stdoutSha256="b"*64,stderrBytes=0,stderrSha256="c"*64) for role,cap,limit,code in roles]
        self.assertEqual(adapter.normal_original_projection_data(row,"saved-version-recovery",source,"test",585,runner.SAVED_VERSION_RESULT),"a"*64)
        for index,field,value in ((2,"returncode",0),(2,"returncode",True),(1,"role","foreign-source-query"),(2,"stderrBytes",1)):
            changed=copy.deepcopy(row);changed["commands"][index][field]=value
            with self.subTest(savedCensus=(index,field)),self.assertRaises(adapter.Refused):
                adapter.normal_original_projection_data(changed,"saved-version-recovery",source,"test",585,runner.SAVED_VERSION_RESULT)


        # Complete saved-family reducer joins the actual private native receipt
        # bytes/hash, producer stdout digest, runtime witness and recovery facts.
        install={**self.receipt(source,"2","1"),"scope":adapter.NORMAL_SCOPE,"normalBatch":"saved-version-recovery",
                 "savedVersionRuntimeOrigin":origin}
        row.update(originalClosesCompleted=True,originalProductsPrePostMatched=True,strictCodesignOriginalZero=True,reSignedOrRepaired=False)
        row["savedVersionRecovery"]=dict(originalRuntimeWitness={**origin,"coreVersion":"0.3.0","sourceInputsSha256":runner.SAVED_VERSION_SOURCE,"runtimeOriginalsMatched":True},
            runtimeManifestSha256=origin["runtimeManifestSha256"],sourceInputsSha256=runner.SAVED_VERSION_SOURCE,
            producerReturncode=86,publicOriginalCount=13,readyJournalFileCount=6,originalFixtureRestored=True,unrelatedOriginalsUnchanged=True,
            readyJournalRemoved=True,sourcePrePostMatched=True,uiOriginalMarkersObserved=True,originalClosesCompleted=True,
            interruptedGuiSaveObserved=False,currentRuntimeQualified=False,producerFramesSha256=row["commands"][2]["stdoutSha256"],
            originalRuntimeReceiptSha256=adapter.sha(adapter.canonical(install)+b"\n"))
        def ordinary_row(phase,seconds,roles):
            value={k:v for k,v in row.items() if k not in {"commands","savedVersionRecovery","normalPhase","originalTestReturncode"}}
            value.update(phase=phase,originalReturncode=0,resultBundle=None if phase=="build" else runner.SAVED_VERSION_RESULT,
                         phaseClock=dict(startNs="1",deadlineNs=str(1+seconds*10**9),beforePublicationNs="2",postCloseDeadlineRequired=True))
            value["commands"]=[dict(role=role,returncode=0,timeoutSeconds=cap,roleCapSeconds=cap,outputLimitBytes=limit,argvSha256="a"*64,
                                 stdoutBytes=1,stdoutSha256="b"*64,stderrBytes=0,stderrSha256="c"*64) for role,cap,limit in roles]
            return value
        build=ordinary_row("build",450,[("normal-ui-source-roster",15,1048576),*[('normal-toolchain-'+k,15,4096) for k in ('xcode','sdkPath','sdkVersion','sdkBuild')],
                      ("normal-ui-build",240,1048576),("normal-ui-source-roster",15,1048576)])
        summary=ordinary_row("summary",90,[("normal-ui-source-roster",15,1048576),("normal-ui-summary",30,262144),("normal-ui-source-roster",15,1048576)])
        summary_body=adapter.canonical(dict(totalTestCount=1,passedTests=1,failedTests=0,skippedTests=0,expectedFailures=0))
        summary["commands"][1].update(stdoutBytes=len(summary_body),stdoutSha256=adapter.sha(summary_body))
        args=(install,build,row,summary,summary_body,"saved-version-recovery",runner.SAVED_VERSION_RESULT,source,"2","1")
        self.assertEqual(adapter.normal_family_projection_data(*args)["familyResult"],"passed")
        changed=copy.deepcopy(row);changed["savedVersionRecovery"]["originalRuntimeWitness"]["runtimeOriginalsMatched"]=1
        with self.assertRaises(adapter.Refused):
            adapter.normal_family_projection_data(install,build,changed,summary,summary_body,"saved-version-recovery",runner.SAVED_VERSION_RESULT,source,"2","1")
        for field,value in (("producerReturncode",True),("currentRuntimeQualified",True),("originalClosesCompleted",False),
                            ("producerFramesSha256","f"*64),("originalRuntimeReceiptSha256","f"*64),("runtimeResultSha256","f"*64)):
            changed=copy.deepcopy(row);changed["savedVersionRecovery"][field]=value
            with self.subTest(savedFamily=field),self.assertRaises(adapter.Refused):
                adapter.normal_family_projection_data(install,build,changed,summary,summary_body,"saved-version-recovery",runner.SAVED_VERSION_RESULT,source,"2","1")

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
        self.assertEqual(swift.count("private enum SourceProfile { case sameBuild, packagedEntry, fixedCarrierResume, fixedNormalBatch, updateP0Bootstrap }"), 1)
        self.assertEqual(swift.count("case .fixedCarrierResume:"), 1)
        self.assertEqual(swift.count("case .fixedNormalBatch:"), 1)
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



    def test_phase_budget_accounts_live_codecs_and_funds_cpio_only_once(self):
        m = ADAPTER
        tool = inert_module('phase_budget_stager_data', 'desktop/tools/stage_macos_installed.py')
        base = m.acquisition_memory_requirement(123)
        self.assertEqual(base, 6 * (m.ORIGIN['artifactBytes'] + m.ORIGIN['imageBytes'])
                         + (16 << 20) + 123 + (512 << 20) + (1 << 30))
        self.assertLess(base, 3190128640)
        self.assertEqual(m.allocation_memory_requirement(base, 10, 20, 30),
                         base + 10 + 60 + 62 + (16 << 20))
        for args in ((True, 0, 0, 0), (base, -1, 0, 0), (base, 0, True, 0),
                     (base, 0, 0, m.LIMIT + 1), (base, 8 * m.LIMIT + 1, 0, 0)):
            with self.subTest(args=args), self.assertRaises(m.Refused):
                m.allocation_memory_requirement(*args)

        # Tiny genuine XAR and CPIO decoders; no extraction or native command.
        def odc(name, mode, data=b''):
            name = name.encode() + b'\0'
            values = ((0, 6), (1, 6), (mode, 6), (0, 6), (0, 6), (1, 6),
                      (0, 6), (0, 11), (len(name), 6), (len(data), 11))
            return b'070707' + ''.join(format(v, '0%do' % width) for v, width in values).encode() + name + data
        archive = odc('.', m.stat.S_IFDIR | 0o755)
        for index in range(178):
            archive += odc('f%d' % index, m.stat.S_IFREG | 0o444, b'DATA')
        archive += odc('TRAILER!!!', 0)
        cpio_rows = []
        expected = tool.cpio_members(archive)
        self.assertEqual(tool.cpio_members(archive, allocation_budget=lambda *args: cpio_rows.append(args)), expected)
        self.assertEqual(cpio_rows[0], ('cpio-window', 2 * len(archive), 0, 0))
        self.assertEqual(len(cpio_rows), 179)
        self.assertEqual(cpio_rows[-1], ('cpio-slice', len(archive) + 178 * 4, 0, 0))
        def refused(*args):
            raise m.Refused('test-allocation-refused')
        with self.assertRaisesRegex(m.Refused, 'test-allocation-refused'):
            tool.cpio_members(archive, allocation_budget=refused)

        values = [('PackageInfo', b'INFO'), ('Scripts', archive)]
        heap = b''; nodes = []
        for name, body in values:
            packed = m.zlib.compress(body)
            nodes.append('<file><name>%s</name><type>file</type><data><length>%d</length>'
                '<offset>%d</offset><size>%d</size><encoding style="application/x-gzip"/></data></file>'
                % (name, len(packed), len(heap), len(body)))
            heap += packed
        toc = ('<xar><toc>' + ''.join(nodes) + '</toc></xar>').encode()
        packed_toc = m.zlib.compress(toc)
        inner = m.struct.pack('>IHHQQI', 0x78617221, 28, 1, len(packed_toc), len(toc), 0) + packed_toc + heap
        seen = []
        self.assertEqual(tool.xar_members(inner, allocation_budget=lambda *args: seen.append(args)), dict(values))
        self.assertEqual(tool.xar_members(inner), dict(values))
        self.assertEqual([row[0] for row in seen], ['xar-toc', 'xar-member', 'xar-member'])
        self.assertEqual(seen[2][1], len(inner) + 4 * len(toc) + 2 * len(values[0][1])
                         + len(m.zlib.compress(values[0][1])))
        with mock.patch.object(tool, 'inflate', wraps=tool.inflate) as inflate:
            with self.assertRaisesRegex(m.Refused, 'test-allocation-refused'):
                tool.xar_members(inner, allocation_budget=lambda phase, *args:
                    None if phase == 'xar-toc' else refused())
            self.assertEqual(inflate.call_count, 1)  # Refused before the member codec.

        # Closed outer product layout, including the live prior packed/decoded
        # member references. Signature authority is not simulated by this DATA.
        outer_values = [('Distribution', b'XML'), ('Resources/InstallerReadMe.html', b'HTML'),
                        (tool.INSTALL_COMPONENT, inner)]
        heap = b''; outer_nodes = []
        for index, (name, body) in enumerate(outer_values):
            packed = m.zlib.compress(body)
            data = ('<data><length>%d</length><offset>%d</offset><size>%d</size>'
                    '<encoding style="application/x-gzip"/></data>') % (len(packed), 20 + len(heap), len(body))
            if name.startswith('Resources/'):
                node = ('<file id="2"><name>Resources</name><type>directory</type><file id="3">'
                        '<name>InstallerReadMe.html</name><type>file</type>%s</file></file>') % data
            else:
                node = '<file id="%d"><name>%s</name><type>file</type>%s</file>' % (1 if index == 0 else 4, name, data)
            outer_nodes.append(node); heap += packed
        outer_toc = ('<xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum>'
                     + ''.join(outer_nodes) + '</toc></xar>').encode()
        outer_packed = m.zlib.compress(outer_toc)
        outer = (m.struct.pack('>IHHQQI', 0x78617221, 28, 1, len(outer_packed), len(outer_toc), 1)
                 + outer_packed + m.hashlib.sha1(outer_packed).digest() + heap)
        seen = []
        self.assertEqual(tool.install_product_members(outer), dict(outer_values))
        self.assertEqual(tool.install_product_members(outer, allocation_budget=lambda *args: seen.append(args)), dict(outer_values))
        self.assertEqual([row[0] for row in seen], ['install-product-toc'] + ['install-product-member'] * 3)
        # Breadth-first traversal visits Distribution, component, then ReadMe.
        self.assertEqual(seen[2][1], len(outer) + 2 * len(outer_packed) + 4 * len(outer_toc)
                         + 2 * len(b'XML') + len(m.zlib.compress(b'XML')))
        with mock.patch.object(tool, 'inflate', wraps=tool.inflate) as inflate:
            with self.assertRaisesRegex(m.Refused, 'test-allocation-refused'):
                tool.install_product_members(outer, allocation_budget=lambda phase, *args:
                    None if phase == 'install-product-toc' else refused())
            self.assertEqual(inflate.call_count, 1)

        # ISIZE is an enforced cap, not a trustworthy memory/provenance claim.
        compressor = m.zlib.compressobj(wbits=31)
        gzip = compressor.compress(archive) + compressor.flush()
        seen = []
        self.assertEqual(m.scripts_archive_data(gzip, tool, 55, lambda *args: seen.append(args)), archive)
        self.assertEqual(seen, [('scripts', 55, len(gzip), len(archive))])
        self.assertEqual(m.scripts_archive_data(gzip, tool, 55), archive)
        for damaged in (gzip[:-4] + m.struct.pack('<I', 1), gzip + gzip, gzip + b'tail',
                        gzip[:-4] + m.struct.pack('<I', m.LIMIT + 1)):
            with self.subTest(bytes=len(damaged)), self.assertRaises((m.Refused, tool.Refused, m.zlib.error)):
                m.scripts_archive_data(damaged, tool, 55, lambda *args: None)
        with mock.patch.object(tool, 'inflate', wraps=tool.inflate) as inflate:
            with self.assertRaisesRegex(m.Refused, 'test-allocation-refused'):
                m.scripts_archive_data(gzip, tool, 55, refused)
            inflate.assert_not_called()

        # The genuine owner method is exercised with synthetic read-only DATA
        # ports. Linux does not certify Darwin vm_stat or an OS reservation.
        session = m.Resume.__new__(m.Resume)
        session.memory_base, session.required_disk = base, 1234
        session.allocation_samples, session.cpio_window = 0, None
        session.clock = SimpleNamespace(check=lambda: 1)
        session.host = object(); session.parent = {'fd': 987}
        calls = []
        session.command = lambda *args: calls.append(args) or SimpleNamespace(stdout=b'', stderr=b'', returncode=0)
        enough = m.allocation_memory_requirement(base, 100, 0, 0)
        with (mock.patch.object(m, 'host_memory_data', return_value=(4096, 1 << 36)),
              mock.patch.object(m, 'memory_data', return_value={'availableEstimateBytes': enough}),
              mock.patch.object(m.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=1234, f_frsize=1)),
              mock.patch.dict(m.STATE, phase='attach', resourceAdmission=None)):
            session.allocation_budget('cpio-window', 100, 0, 0)
            with self.assertRaisesRegex(m.Refused, 'resume-cpio-window-once'):
                session.allocation_budget('cpio-window', 100, 0, 0)
            self.assertEqual(len(calls), 1)  # Duplicate funding refuses before another command.
            for live in range(101):
                session.allocation_budget('cpio-slice', live, 0, 0)
            self.assertEqual(len(calls), 1)
            self.assertEqual(m.STATE['phase'], 'attach')
            self.assertFalse(m.STATE['resourceAdmission']['osMemoryReservation'])
            with self.assertRaisesRegex(m.Refused, 'resume-cpio-allocation-window'):
                session.allocation_budget('cpio-slice', 101, 0, 0)
            session.cpio_window = None; calls.clear()
            for index in range(12):
                session.allocation_budget('xar-member', 100, 0, 0)
            self.assertEqual(session.allocation_samples, 13)
            with self.assertRaisesRegex(m.Refused, 'resume-allocation-sample-bound'):
                session.allocation_budget('xar-member', 100, 0, 0)
            self.assertEqual(len(calls), 12)
            session.allocation_samples = 0
            with mock.patch.object(m, 'memory_data', return_value={'availableEstimateBytes': enough - 1}):
                with self.assertRaisesRegex(m.Refused, 'resume-resource-memory-admission'):
                    session.allocation_budget('xar-member', 100, 0, 0)
            self.assertEqual(m.STATE['phase'], 'resource-admission')
            self.assertFalse(m.STATE['resourceAdmission']['memorySufficient'])

        # The initial DMG readback binding is dead after equality; the held
        # original and fresh POST stay live. Tiny genuine FD DATA only.
        import ast
        donor_source = (ROOT / 'desktop/tools/macos_e2_native_fixture.py').read_bytes()
        self.assertEqual((len(donor_source), m.sha(donor_source)), m.SOURCE_PINS['desktop/tools/macos_e2_native_fixture.py'])
        donor_tree = ast.parse(donor_source)
        names = {'Originals', 'Refused', 'need', 'signature'}
        selected = [n for n in donor_tree.body
                    if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names
                    or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'READ_FLAGS' for t in n.targets)]
        self.assertEqual({n.name if hasattr(n, 'name') else 'READ_FLAGS' for n in selected}, names | {'READ_FLAGS'})
        donor = {'__name__': 'tiny_original_file_data', 'os': m.os, 'stat': m.stat, 'Path': Path}
        exec(compile(ast.Module(body=selected, type_ignores=[]), 'tiny_original_file_data', 'exec'), donor)
        class BeforePlaceholder(Exception):
            pass
        image = b'PUBLIC-TINY-IMAGE-DATA\n' * 64
        # Existing quick owner supplies private0700 TMPDIR=/scratch. Never
        # change the donor's safe ancestor/mode policy to admit /tmp.
        with tempfile.TemporaryDirectory(dir=m.os.environ['TMPDIR']) as folder:
            work = Path(folder).resolve()
            image_path = work / 'arm64.dmg'
            image_path.write_bytes(image)
            image_path.chmod(0o444)
            quota = m.OriginalQuota()
            book = quota.book(donor['Originals'])
            parent = quota.call(book, 'directory', work)
            probe_entry, probe_copy = quota.call(book, 'file', image_path, len(image), modes=(0o444,))
            self.assertEqual(probe_copy, image)
            self.assertIsNot(probe_copy, image)
            self.assertTrue(all(not any(isinstance(v, (bytes, bytearray, memoryview)) for v in entry.values()) for entry in book.entries))
            del probe_copy
            observed = {}
            def published(path, body):
                self.assertEqual(path, image_path)
                self.assertIs(body, image)
            session = SimpleNamespace(work=work, quota=quota, outer=book, parent=parent,
                                      private={}, publish_image=published)
            def stop(name, mode, *, dir_fd):
                frame = m.sys._getframe(1)
                self.assertIs(frame.f_code, m.Resume.install_image.__code__)
                self.assertNotIn('original', frame.f_locals)
                self.assertIs(frame.f_locals['image'], image)
                held = frame.f_locals['image_entry']
                self.assertTrue(any(held is entry for entry in book.entries))
                self.assertEqual(session.private['arm64.dmg'], held['identity'])
                self.assertEqual((name, mode, dir_fd), ('arm64-mount', 0o700, parent['fd']))
                self.assertEqual(book.read(held), image)
                observed['held'] = held
                raise BeforePlaceholder()
            with mock.patch.object(m.os, 'mkdir', new=stop):
                with self.assertRaises(BeforePlaceholder):
                    m.Resume.install_image(session, image, {})
            self.assertIn('held', observed)
            # No native/mount call was reached; held/named mutation still
            # refuses before fresh reads, then consuming closes happen once.
            image_path.chmod(0o600)
            image_path.write_bytes(b'X' * len(image))
            image_path.chmod(0o444)
            with self.assertRaises(donor['Refused']):
                book.read(observed['held'])
            close_calls = []
            actual_close = m.os.close
            def consume(fd):
                close_calls.append(fd)
                actual_close(fd)
            with mock.patch.object(m.os, 'close', side_effect=consume):
                self.assertTrue(quota.finish())
                first = list(close_calls)
                self.assertTrue(quota.finish())
                self.assertEqual(close_calls, first)
            self.assertEqual(len(first), len(book.entries))
            self.assertTrue(all(entry['fd'] is None and entry['closed'] for entry in book.entries))
            # A genuine differently read image fails the original equality
            # before the deletion/private/mkdir boundary; no guard relaxed.
            other_quota = m.OriginalQuota()
            other_book = other_quota.book(donor['Originals'])
            other_parent = other_quota.call(other_book, 'directory', work)
            failed = SimpleNamespace(work=work, quota=other_quota, outer=other_book,
                                     parent=other_parent, private={}, publish_image=published)
            try:
                with mock.patch.object(m.os, 'mkdir', side_effect=AssertionError('unexpected-placeholder')):
                    with self.assertRaisesRegex(m.Refused, '^resume-image-copy-original$'):
                        m.Resume.install_image(failed, image, {})
                self.assertEqual(failed.private, {})
            finally:
                self.assertTrue(other_quota.finish())

        # Actual mounted_data boundary: nested and direct public XAR parsers
        # release only the dead outer dict; direct component aliases stay live.
        manifest_digest = 'a' * 64
        required_paths = {'app/' + tool.ENTRY_BINARY, 'app/' + tool.APP_BINARY,
                          'app/' + tool.VAULT_HELPER, 'app/Contents/Info.plist',
                          'app/' + tool.PAYLOAD_INFO, 'runtime/python/bin/python3', 'runtime/manifest.json'}
        executables = {'app/' + tool.ENTRY_BINARY, 'app/' + tool.APP_BINARY,
                       'app/' + tool.VAULT_HELPER, 'runtime/python/bin/python3'}
        actual_inventory = tool.canonical(dict(schemaVersion=1, release=m.ORIGIN['release'],
            runtimeManifestSha256=manifest_digest,
            files=[dict(path=p, sha256=manifest_digest if p == 'runtime/manifest.json' else 'b' * 64,
                        size=1, executable=p in executables) for p in sorted(required_paths)]))
        small_archive = (odc('.', m.stat.S_IFDIR | 0o755)
                         + odc('input', m.stat.S_IFDIR | 0o555)
                         + odc('input/' + tool.INSTALLATION_INVENTORY_NAME,
                               m.stat.S_IFREG | 0o444, actual_inventory)
                         + odc('TRAILER!!!', 0))
        gzip_writer = m.zlib.compressobj(wbits=31)
        small_gzip = gzip_writer.compress(small_archive) + gzip_writer.flush()
        info = ('<pkg-info identifier="%s" version="%s" install-location="/" auth="root">'
                '<scripts><postinstall file="./postinstall"/></scripts></pkg-info>'
                % (tool.PACKAGE_ID, m.ORIGIN['packageVersion'])).encode()
        synthetic_policy = dict(schemaVersion=1, kind='mrk-macos-developer-id-code-policy-v1',
            teamIdentifier='ABCDE12345', leafCertificateSha1='c' * 40,
            leafCertificateSha256='d' * 64, hardenedRuntime=True, entitlements='empty')
        policy_digest = m.sha(json.dumps(synthetic_policy, ensure_ascii=True,
            separators=(',', ':'), allow_nan=False).encode('ascii'))

        def inner_fixture(script_bytes, *, extra=False):
            parts = [('PackageInfo', info), ('Scripts', script_bytes)]
            if extra:
                parts.append(('Bom', b'PUBLIC-EXTRA-ROSTER'))
            content = b''; nodes = []
            for name, value in parts:
                nodes.append('<file><name>%s</name><type>file</type><data><length>%d</length>'
                    '<offset>%d</offset><size>%d</size><encoding style="application/octet-stream"/></data></file>'
                    % (name, len(value), len(content), len(value)))
                content += value
            xml = ('<xar><toc>' + ''.join(nodes) + '</toc></xar>').encode()
            compressed = m.zlib.compress(xml)
            return m.struct.pack('>IHHQQI', 0x78617221, 28, 1, len(compressed), len(xml), 0) + compressed + content

        def product_fixture(script_bytes, direct, *, extra=False):
            content = b''
            def file_node(identifier, name, value):
                nonlocal content
                text = ('<file id="%d"><name>%s</name><type>file</type><data><length>%d</length>'
                        '<offset>%d</offset><size>%d</size><encoding style="application/octet-stream"/></data></file>'
                        % (identifier, name, len(value), 20 + len(content), len(value)))
                content += value
                return text
            nodes = [file_node(1, 'Distribution', b'PUBLIC-XML')]
            nodes.append('<file id="2"><name>Resources</name><type>directory</type>'
                         + file_node(3, 'InstallerReadMe.html', b'PUBLIC-HTML') + '</file>')
            if direct:
                nodes.append('<file id="4"><name>' + tool.INSTALL_COMPONENT + '</name><type>directory</type>'
                             + file_node(5, 'PackageInfo', info) + file_node(6, 'Scripts', script_bytes) + '</file>')
            else:
                nodes.append(file_node(4, tool.INSTALL_COMPONENT, inner_fixture(script_bytes, extra=extra)))
            xml = ('<xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum>'
                   + ''.join(nodes) + '</toc></xar>').encode()
            compressed = m.zlib.compress(xml)
            package = (m.struct.pack('>IHHQQI', 0x78617221, 28, 1, len(compressed), len(xml), 1)
                       + compressed + m.hashlib.sha1(compressed).digest() + content)
            release = dict(profile='fixed-macos26-arm64-maintenance-v2', packageIdentifier=tool.PACKAGE_ID,
                bundleIdentifier=tool.BUNDLE_ID, packageVersion=m.ORIGIN['packageVersion'], release=m.ORIGIN['release'],
                sourceCommit=m.ORIGIN['source'], protocolSha256=tool.CURRENT_PROTOCOL,
                runtimeManifestSha256=manifest_digest, inventorySha256=m.sha(actual_inventory),
                signingPolicySha256=policy_digest, packageSha256=m.sha(package))
            producer = tool.canonical(dict(schemaVersion=2, kind='mrk-macos-install-producer-v2',
                domain='MobileReleaseKit-package-producer-v2', target=tool.ARM_TARGET,
                releaseSet=dict(schemaVersion=2, current=release, acceptedPredecessors=[]),
                signingPolicies=[dict(sha256=policy_digest, policy=synthetic_policy)]))
            signature = b'PUBLIC-SYNTHETIC-SIGNATURE-NOT-NATIVE-EVIDENCE'
            originals = {'Install.pkg': (package, 0o444), 'producer.json': (producer, 0o444),
                         'producer.sig': (signature, 0o444)}
            row = dict(m.ORIGIN, members=[], inventorySha256=m.sha(actual_inventory),
                       runtimeManifestSha256=manifest_digest, signingIdentity={key: synthetic_policy[key]
                       for key in ('teamIdentifier', 'leafCertificateSha1', 'leafCertificateSha256')})
            for key, name in (('package', 'Install.pkg'), ('descriptor', 'producer.json'), ('signature', 'producer.sig')):
                value = originals[name][0]
                row[key] = dict(name=name, bytes=len(value), sha256=m.sha(value))
            return originals, row

        actual_outer_parser = tool.install_product_members
        # Observers retain only scalar charges/identities, never returned buffers
        # or frames. new= functions avoid unittest.mock's extra sideeffect stack.
        for direct in (False, True):
            for is_gzip in (False, True):
                originals, row = product_fixture(small_gzip if is_gzip else small_archive, direct)
                scalar = {}; phases = []
                def observe_outer(*args, **kwargs):
                    parsed = actual_outer_parser(*args, **kwargs)
                    scalar['outerBytes'] = sum(map(len, parsed.values()))
                    scalar['innerBytes'] = 0 if direct else len(parsed[tool.INSTALL_COMPONENT])
                    scalar['directScriptId'] = id(parsed[tool.INSTALL_COMPONENT + '/Scripts']) if direct else 0
                    return parsed
                def observe_budget(phase, live, packed_bytes, output):
                    phases.append((phase, live, packed_bytes, output))
                    # Never materialize cached f_locals while members is live:
                    # a test observer must not manufacture a retained dict root.
                    if phase in ('install-product-toc', 'install-product-member'):
                        return
                    if phase in ('xar-toc', 'xar-member'):
                        retained = scalar['outerBytes'] + scalar['innerBytes']
                        if phase == 'xar-toc':
                            self.assertEqual(live, retained)
                        else:
                            self.assertGreaterEqual(live, retained)
                        return
                    self.assertIn(phase, ('scripts', 'cpio-window', 'cpio-slice'))
                    frame = m.sys._getframe()
                    local = None
                    try:
                        for _ in range(8):
                            frame = frame.f_back
                            if frame is None:
                                break
                            if frame.f_code is m.mounted_data.__code__:
                                break
                        self.assertIsNotNone(frame)
                        self.assertIs(frame.f_code, m.mounted_data.__code__)
                        local = frame.f_locals
                        if phase in ('scripts', 'cpio-window', 'cpio-slice'):
                            self.assertNotIn('members', local)
                            self.assertEqual(local['outer_retained'], 0)
                            self.assertEqual(set(local['component']), {'PackageInfo', 'Scripts'})
                            component_bytes = sum(map(len, local['component'].values()))
                            self.assertEqual(local['component_retained'], component_bytes)
                            self.assertIs(local['bodies']['Install.pkg'], originals['Install.pkg'][0])
                            self.assertIs(local['bodies']['producer.json'], originals['producer.json'][0])
                            self.assertIs(local['bodies']['producer.sig'], originals['producer.sig'][0])
                            self.assertIs(local['packed'], local['component']['Scripts'])
                            if direct:
                                self.assertEqual(id(local['component']['Scripts']), scalar['directScriptId'])
                            if phase == 'scripts':
                                self.assertEqual((live, packed_bytes, output),
                                    (component_bytes, len(local['packed']), len(small_archive)))
                            elif phase == 'cpio-window':
                                self.assertEqual((live, packed_bytes, output),
                                    (component_bytes + 2 * len(local['archive']), 0, 0))
                                if not is_gzip:
                                    self.assertIs(local['archive'], local['packed'])
                            else:
                                self.assertEqual((live, packed_bytes, output),
                                    (component_bytes + len(local['archive']) + len(actual_inventory), 0, 0))
                            scalar['postOuterReleased'] = 1
                    finally:
                        del local, frame
                with mock.patch.object(tool, 'install_product_members', new=observe_outer):
                    expected = m.mounted_data(originals, row, tool.ARM_TARGET, tool)
                    result = m.mounted_data(originals, row, tool.ARM_TARGET, tool, allocation_budget=observe_budget)
                self.assertEqual(result, expected)
                self.assertEqual(result[1], actual_inventory)
                self.assertEqual(result[0]['inventoryPayloadBytes'], len(required_paths))
                self.assertFalse(result[0]['nativeQualificationInferred'])
                self.assertEqual(scalar['postOuterReleased'], 1)
                self.assertEqual(sum(p[0] == 'scripts' for p in phases), int(is_gzip))
                self.assertEqual(sum(p[0] == 'cpio-window' for p in phases), 1)
                self.assertEqual(sum(p[0] == 'xar-toc' for p in phases), int(not direct))

        invalid, invalid_row = product_fixture(small_gzip, False, extra=True)
        refused_phases = []
        with self.assertRaisesRegex(m.Refused, '^enrollment-product-component$'):
            m.mounted_data(invalid, invalid_row, tool.ARM_TARGET, tool,
                allocation_budget=lambda phase, *args: refused_phases.append(phase))
        self.assertNotIn('scripts', refused_phases)
        # Actual Scripts codec remains unentered when its allocation refuses;
        # prior outer/inner codecs are real and the first exception is unchanged.
        originals, row = product_fixture(small_gzip, False)
        first = m.Refused('outer-lifetime-allocation-stop')
        scalar = {}
        with mock.patch.object(tool, 'inflate', wraps=tool.inflate) as decoder:
            def refuse_scripts(phase, *args):
                if phase == 'scripts':
                    scalar['priorInflateCalls'] = decoder.call_count
                    raise first
            with self.assertRaises(m.Refused) as caught:
                m.mounted_data(originals, row, tool.ARM_TARGET, tool, allocation_budget=refuse_scripts)
            self.assertIs(caught.exception, first)
            self.assertEqual(decoder.call_count, scalar['priorInflateCalls'])
            self.assertGreater(scalar['priorInflateCalls'], 0)

    def test_pinned_tls_roots_require_source_authentication_and_strict_tls(self):
        m = ADAPTER
        pem = (ROOT / m.TLS_CA_PATH).read_bytes()
        self.assertEqual((len(pem), m.sha(pem)), (m.TLS_CA_BYTES, m.TLS_CA_SHA256))
        class DataQuota:
            def __init__(self, body=pem, failure=None):
                self.body, self.failure, self.calls = body, failure, []
            def call(self, book, role, path, limit, **kwargs):
                self.calls.append((book, role, path, limit, kwargs))
                if self.failure is not None:
                    raise self.failure
                return {"path": path}, self.body  # Explicit DATA port, not native custody.
        def session(body=pem, failure=None):
            value = m.Resume.__new__(m.Resume)
            value.root, value.outer, value.quota = ROOT, object(), DataQuota(body, failure)
            value.sources, value.ca_path, value.ca_sha = [], None, None
            return value
        with mock.patch.object(m.ssl, "get_default_verify_paths", side_effect=AssertionError("no shared CA fallback")):
            value = session()
            body = m.admit_pinned_tls_roots(value)  # Calls the actual Resume.source digest guard.
            self.assertIs(body, pem)
            self.assertEqual(value.ca_path, str(ROOT / m.TLS_CA_PATH))
            self.assertEqual(value.ca_sha, m.TLS_CA_SHA256)
            self.assertEqual(value.quota.calls, [(value.outer, "file", ROOT / m.TLS_CA_PATH,
                                                 m.TLS_CA_BYTES, {"uid": m.os.getuid()})])
            self.assertEqual(len(value.sources), 1)
            context = m.tls_context(body)  # Real local SSL constructor, no socket/network.
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, m.ssl.CERT_REQUIRED)
            self.assertGreaterEqual(context.minimum_version, m.ssl.TLSVersion.TLSv1_2)
            self.assertGreater(context.cert_store_stats()["x509_ca"], 0)
            self.assertIsNone(context.keylog_filename)
            for bad in (pem[:-1], bytes([pem[0] ^ 1]) + pem[1:]):
                value = session(bad)
                with self.subTest(kind="changed-or-short"), self.assertRaises(m.Refused):
                    m.admit_pinned_tls_roots(value)
                self.assertEqual((value.ca_path, value.ca_sha, value.sources), (None, None, []))
            value = session(failure=m.Refused("original-read-unknown"))
            with self.assertRaises(m.Refused):
                m.admit_pinned_tls_roots(value)
            self.assertEqual((value.ca_path, value.ca_sha, value.sources), (None, None, []))
        good = {"caPath": str(ROOT / m.TLS_CA_PATH), "caSha256": m.TLS_CA_SHA256}
        m.pinned_ca_request_data(good, ROOT)
        for key, bad in (("caPath", "/shared/default-ca.pem"), ("caPath", None), ("caSha256", "0" * 64)):
            changed = dict(good, **{key: bad})
            with self.subTest(key=key), self.assertRaises(m.Refused):
                m.pinned_ca_request_data(changed, ROOT)



if __name__ == "__main__":
    unittest.main()
