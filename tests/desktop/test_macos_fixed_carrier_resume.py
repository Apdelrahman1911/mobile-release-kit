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


if __name__ == "__main__":
    unittest.main()
