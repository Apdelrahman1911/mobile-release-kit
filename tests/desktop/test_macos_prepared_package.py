"""Inert prepared-package correspondence; no signing, native or network calls."""
import copy
import contextlib
import importlib.util
import os
import stat
import subprocess
import textwrap
import sys
import tempfile
from types import SimpleNamespace, ModuleType
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('prepared_package_data', ROOT / 'desktop/tools/macos_prepared_package.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def fixture(target='aarch64-apple-darwin'):
    origin = dict(source='1'*40, tree='2'*40, target=target, runId='41', runAttempt='1', jobId='42')
    values = {'MobileReleaseKit.pkg': b'inert finalized package', 'MobileReleaseKit-original.pkg': b'inert original package',
              'android-helper-finalize-package.json': b'{"inert":true}\n', 'package-finalization.status': b'0\n'}
    manifest = dict(schemaVersion=1, scope=P.SCOPE, origin=origin, packageRole='ordinary-image',
        packageVersion='0.2.0', release='macos26-test', packagerUid=501, packagerGid=20,
        inventorySha256='3'*64, runtimeManifestSha256='4'*64,
        members=[dict(name=n, bytes=len(values[n]), sha256=P.sha(values[n])) for n in sorted(values)],
        originalFinalizationReturnedZero=True, originalClosesKnown=True, installed=False, productReady=False,
        normalBuild=dict(appBinarySha256BeforeSigning='a'*64,desktopImageSha256BeforeSigning='b'*64))
    values['PREPARED.json'] = P.canonical(manifest)
    service = dict(run=dict(id=41, run_attempt=1, head_sha=origin['source'], head_branch=P.BRANCH,
        event='push', path=P.WORKFLOW, workflow_id=363563168, repository={'full_name':P.REPOSITORY}, conclusion='failure'),
        job=dict(id=42, run_id=41, run_attempt=1, head_sha=origin['source'], name='normal-installed-'+target,
            steps=[dict(name=name, number=i+1, status='completed', conclusion='success') for i,name in enumerate(P.PRODUCER_STEPS)]),
        artifact=dict(id=43, name=P.artifact_name(origin), expired=False, size_in_bytes=1000, digest='sha256:'+'5'*64,
                      workflow_run=dict(id=41, head_sha=origin['source'], head_branch=P.BRANCH)))
    consumer = dict(source='1'*40, tree='2'*40, target=target, runId='41', runAttempt='2')
    return values, manifest, service, consumer


def real_modules():
    base=Path(os.environ.get('MRK_TEST_REPO', ROOT))
    sys.path.insert(0,str(base/'tests/desktop'))
    import test_macos_installed_staging as T
    result=[]
    for filename in ('stage_macos_installed.py', 'macos_android_helper_package.py'):
        name='prepared_test_'+filename[:-3]
        module=ModuleType(name); module.__file__=str(base/'desktop/tools'/filename)
        sys.modules[name]=module
        exec(compile((ROOT/'desktop/tools'/filename).read_bytes(),module.__file__,'exec'),module.__dict__)
        result.append(module)
    return T,*result


class PreparedPackageData(unittest.TestCase):
    def test_exact_cohort_and_real_producer_attempt_are_distinct_from_new_consumer(self):
        for target in P.TARGETS:
            values, manifest, service, consumer = fixture(target)
            binding = P.admit_data(values, service, consumer)
            current = dict(GITHUB_SHA=consumer['source'], GITHUB_RUN_ID='41', GITHUB_RUN_ATTEMPT='2')
            old = binding.finalization_environment(current)
            self.assertEqual((old['GITHUB_RUN_ID'],old['GITHUB_RUN_ATTEMPT']),('41','1'))
            self.assertEqual(current['GITHUB_RUN_ATTEMPT'],'2')
            self.assertTrue(binding.same_source)
            self.assertEqual(binding.manifest,manifest)
            current['GITHUB_RUN_ATTEMPT']='3'
            with self.assertRaisesRegex(ValueError,'prepared-current-consumer'):
                binding.finalization_environment(current)

    def test_new_harness_never_relabels_built_source(self):
        values, manifest, service, consumer = fixture()
        consumer.update(source='6'*40,tree='7'*40)
        binding=P.admit_data(values,service,consumer)
        self.assertFalse(binding.same_source)
        self.assertEqual(binding.source,'1'*40)
        with self.assertRaisesRegex(ValueError,'prepared-binding-constructor'):
            P.PreparedBinding(object(),manifest,consumer,{})

    def test_omission_extra_changed_status_duplicate_json_and_bad_manifest_refuse(self):
        values, manifest, service, consumer=fixture()
        for name in P.NAMES:
            wrong=dict(values);wrong.pop(name)
            with self.subTest(name=name),self.assertRaises(ValueError): P.admit_data(wrong,service,consumer)
        for name in P.FILES:
            wrong=dict(values);wrong[name]+=b'changed'
            with self.subTest(changed=name),self.assertRaises(ValueError): P.admit_data(wrong,service,consumer)
        wrong=dict(values, private=b'no raw logs')
        with self.assertRaises(ValueError): P.admit_data(wrong,service,consumer)
        with self.assertRaisesRegex(ValueError,'prepared-json-duplicate'): P.decode(b'{"a":1,"a":1}',100)
        for key,val in (('runtimeManifestSha256','0'*64),('installed',True),('originalClosesKnown',False),('packagerUid',0)):
            wrong=copy.deepcopy(manifest);wrong[key]=val
            with self.subTest(key=key),self.assertRaises(ValueError): P.manifest_data(wrong)

    def test_closed_cut_not_whole_job_or_artifact_name_is_required(self):
        values,manifest,service,consumer=fixture()
        for index in range(3):
            for mutation in ('missing','duplicate','failure','in_progress'):
                changed=copy.deepcopy(service)
                if mutation=='missing': changed['job']['steps'].pop(index)
                elif mutation=='duplicate': changed['job']['steps'].append(dict(changed['job']['steps'][index],number=10))
                elif mutation=='failure': changed['job']['steps'][index]['conclusion']='failure'
                else: changed['job']['steps'][index]['status']='in_progress'
                with self.subTest(index=index,mutation=mutation),self.assertRaises(ValueError): P.admit_data(values,changed,consumer)
        for which,key,val in (('artifact','expired',True),('artifact','size_in_bytes',True),('run','run_attempt',2),
                              ('job','id',True),('job','name','normal-installed-other'),('run','event','pull_request')):
            changed=copy.deepcopy(service);changed[which][key]=val
            with self.subTest(key=key),self.assertRaises(ValueError): P.admit_data(values,changed,consumer)

    def test_actual_allocation_quote_counts_overlapping_vectors(self):
        quote=P.quote_data(10,20,30,40)
        self.assertEqual(quote['memoryBytes'],3*30+4*30+2*40+32*P.MIB)
        self.assertEqual(quote['diskBytes'],2*30+30+40+32*P.MIB)
        for args in ((True,20,30,40),(10,20,0,40),(10,20,30,12*P.MIB+1)):
            with self.assertRaises(ValueError): P.quote_data(*args)

    def test_hydration_retires_vectors_after_readback_and_keeps_full_admission(self):
        for failure in (None, 'write', 'reread', 'source-reread', 'transport'):
            with self.subTest(failure=failure):
                values, manifest, service, consumer = fixture()
                binding = P.admit_data(values, service, consumer)
                final = values['MobileReleaseKit.pkg']
                original = values['MobileReleaseKit-original.pkg']
                checks, events, published = [], [], {}
                expected_quote = P.quote_data(len(final), len(original), 33, 12 * P.MIB)
                audit = dict(packageSha256=P.sha(final), packageSize=len(final),
                             originalPackageSha256=P.sha(original), packageInfoSha256='a'*64, scriptFileCount=1)

                def check(quote):
                    checks.append(dict(quote))
                    if len(checks) == 2:
                        self.assertNotIn('MobileReleaseKit.pkg', values)
                        self.assertNotIn('MobileReleaseKit-original.pkg', values)
                    elif len(checks) == 3:
                        self.assertNotIn('MobileReleaseKit.pkg', values)
                        self.assertNotIn('MobileReleaseKit-original.pkg', values)

                def write(parent, name, body):
                    events.append(('write', name))
                    if name == 'MobileReleaseKit.pkg':
                        self.assertEqual(body, final)
                        self.assertIn(name, values)
                        if failure == 'write':
                            raise ValueError('known-output-readback-refusal')
                    published[name] = body

                def scripts(*args, **kwargs):
                    self.assertNotIn('MobileReleaseKit.pkg', values)
                    self.assertNotIn('MobileReleaseKit-original.pkg', values)
                    self.assertEqual(args[1], original)
                    return {'input/inventory': (b'inert inventory', 0o444)}

                def independent_audit(*args):
                    self.assertNotIn('MobileReleaseKit.pkg', values)
                    self.assertNotIn('MobileReleaseKit-original.pkg', values)
                    self.assertEqual(checks[-1], expected_quote)
                    events.append(('audit', 'entered'))
                    return audit

                def read(entry):
                    if entry['name'] == 'MobileReleaseKit-original.pkg':
                        return b'tampered' if failure == 'source-reread' else original
                    return b'tampered' if failure == 'reread' else published['MobileReleaseKit.pkg']

                op = SimpleNamespace(prepared_binding=binding, work=Path('/inert'), target=consumer['target'],
                    work_entry='work', stager=SimpleNamespace(INSTALLATION_INVENTORY_NAME='inventory', write_tree=lambda *a, **k: None),
                    package_directory=lambda name: name, package_file=write, package_clock=lambda: None,
                    directory=lambda *a: {'fd': -1}, package_outputs=[], package_roots=[],
                    publish=lambda name, body: published.__setitem__(name, body),
                    original=lambda parent, name, *a: dict(name=name, identity=(0,0,0,0,0,0,len(original) if name=='MobileReleaseKit-original.pkg' else len(final))), read=read,
                    package_finalization_input=lambda *a: audit, package_stager_io=independent_audit, package_post=lambda: None)
                guard = SimpleNamespace(check=check, allocation=lambda *a: None)
                with mock.patch.object(P, 'initialize_staging'), mock.patch.object(P, 'ResourceGuard', return_value=guard), \
                        mock.patch.object(P.os, 'listdir', return_value=list(P.NAMES) + (['extra'] if failure == 'transport' else [])), \
                        mock.patch.object(P, 'original_expansion_bytes', return_value=33), \
                        mock.patch.object(P, 'original_scripts_data', side_effect=scripts), \
                        mock.patch.object(P, 'finish_staging') as finish:
                    if failure:
                        reason = ('known-output-readback-refusal' if failure == 'write' else
                                  'prepared-transport-original-roster' if failure == 'transport' else 'prepared-hydrated-audit')
                        with self.assertRaisesRegex(ValueError, reason):
                            P.hydrate_checkpoint(op, values, binding)
                        self.assertIsNotNone(finish.call_args.args[1])
                        self.assertNotIn(('audit', 'entered'), events)
                        if failure == 'write':
                            self.assertIn('MobileReleaseKit.pkg', values)
                            self.assertIn('MobileReleaseKit-original.pkg', values)
                    else:
                        self.assertIs(P.hydrate_checkpoint(op, values, binding), binding)
                        self.assertEqual(checks, [P.quote_data(len(final), len(original), 1, 1), expected_quote, expected_quote])
                        self.assertEqual(events[-1], ('audit', 'entered'))
                        self.assertIsNone(finish.call_args.args[1])
                    finish.assert_called_once()

    @unittest.skipUnless(sys.platform == 'darwin', 'actual Darwin temporary-copy FD policy')
    def test_prepared_copy_cache_control_keeps_actual_original_and_refuses_error(self):
        import fcntl
        from desktop.tools import macos_android_helper_package as H
        for prepared, refused in ((True, False), (False, False), (True, True)):
            with self.subTest(prepared=prepared, refused=refused), tempfile.TemporaryDirectory() as directory:
                root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                entries, outputs, controls = [], [], []
                body = b'inert prepared copy\n' * 500
                def register(fd, role, kind, parent, name):
                    entry = dict(fd=fd, role=role, kind=kind, parent=parent, name=name)
                    entries.append(entry)
                    return entry
                def read(entry):
                    self.assertEqual(os.fstat(entry['fd']), os.stat(entry['name'], dir_fd=entry['parent'], follow_symlinks=False))
                    return os.pread(entry['fd'], len(body), 0)
                native = fcntl.fcntl
                def control(fd, command, value):
                    self.assertEqual(len(entries), 1)
                    self.assertEqual(entries[0]['fd'], fd)
                    self.assertEqual(os.fstat(fd).st_size, 0)
                    controls.append((command, value))
                    if refused:
                        raise OSError('actual original policy call refused')
                    return native(fd, command, value)
                op = SimpleNamespace(prepared_staging=prepared, phase='package-install', package_clock=lambda: None,
                    stager=SimpleNamespace(MAX_BYTES=P.PACKAGE_LIMIT), recheck_directory=lambda _: None,
                    register=register, read=read, package_outputs=outputs)
                op.prepared_file_post = lambda entry, **kw: H.Operation.prepared_file_post(op, entry, **kw)
                try:
                    with mock.patch.object(fcntl, 'fcntl', side_effect=control):
                        if refused:
                            with self.assertRaisesRegex(OSError, 'original policy call refused'):
                                H.Operation.package_file(op, {'fd': root}, 'copy.pkg', body)
                            self.assertEqual(os.fstat(entries[0]['fd']).st_size, 0)
                            self.assertFalse(outputs)
                        else:
                            entry = H.Operation.package_file(op, {'fd': root}, 'copy.pkg', body)
                            self.assertEqual(read(entry), body)
                            self.assertEqual(stat.S_IMODE(os.fstat(entry['fd']).st_mode), 0o444)
                            self.assertEqual(outputs, [(entry, P.sha(body))])
                        self.assertEqual(controls, [(fcntl.F_NOCACHE, 1)] if prepared else [])
                finally:
                    for entry in entries:
                        os.close(entry['fd'])
                    os.close(root)

    @unittest.skipUnless(sys.platform == 'darwin', 'actual Darwin source FD policy')
    def test_prepared_input_cache_control_uses_same_readonly_original(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source'
            body = b'inert original package bytes\n'
            path.write_bytes(body)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            entry = {'fd': fd}
            reads, controls = [], []
            native = fcntl.fcntl
            def read(actual):
                self.assertIs(actual, entry)
                self.assertEqual(os.fstat(fd), path.stat())
                reads.append(actual)
                return os.pread(fd, len(body), 0)
            def control(actual, command, value):
                self.assertEqual((actual, command, value), (fd, fcntl.F_NOCACHE, 1))
                controls.append(actual)
                return native(actual, command, value)
            try:
                with mock.patch.object(fcntl, 'fcntl', side_effect=control):
                    self.assertEqual(P.read_prepared_member(SimpleNamespace(read=read), 'MobileReleaseKit.pkg', entry), body)
                    self.assertEqual(P.read_prepared_member(SimpleNamespace(read=read), 'package-finalization.status', entry), body)
                self.assertEqual(controls, [fd])
                self.assertEqual(len(reads), 2)
                with mock.patch.object(fcntl, 'fcntl', side_effect=OSError('source cache-control refused')):
                    with self.assertRaisesRegex(OSError, 'source cache-control refused'):
                        P.read_prepared_member(SimpleNamespace(read=read), 'MobileReleaseKit-original.pkg', entry)
                self.assertEqual(len(reads), 2)
                self.assertEqual(os.fstat(fd), path.stat())
            finally:
                os.close(fd)

    def test_prepared_bounded_post_rematches_all_bytes_and_original_namespace(self):
        from desktop.tools import macos_android_helper_package as H
        for failure in (None, 'bytes', 'short', 'extra', 'name'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'input.pkg'
                body = b'original chunk\n' * 15000
                path.write_bytes(body)
                root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                fd = os.open('input.pkg', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root)
                entry = dict(fd=fd, parent=root, parent_entry={'fd': root}, name='input.pkg',
                             identity=H.signature(os.fstat(fd)))
                reads, clocks = [], []
                op = SimpleNamespace(prepared_staging=True, phase='package-install',
                    stager=SimpleNamespace(MAX_BYTES=P.PACKAGE_LIMIT),
                    package_clock=lambda: clocks.append(True), recheck_directory=lambda _: None)
                native = os.pread
                def read(actual, size, offset):
                    self.assertEqual(actual, fd)
                    self.assertLessEqual(size, 65536)
                    reads.append((size, offset))
                    chunk = native(actual, size, offset)
                    if offset == 65536:
                        if failure == 'bytes': return bytes([chunk[0] ^ 1]) + chunk[1:]
                        if failure == 'short': return chunk[:-1]
                        if failure == 'name':
                            path.rename(path.with_suffix('.retired'))
                            path.write_bytes(body)
                    if offset == len(body) and failure == 'extra': return b'!'
                    return chunk
                try:
                    with mock.patch.object(H.os, 'pread', side_effect=read):
                        if failure:
                            reason = 'package-output-readback' if failure == 'bytes' else 'file-original-read-changed'
                            with self.assertRaisesRegex(ValueError, reason):
                                H.Operation.prepared_file_post(op, entry, body=body)
                        else:
                            self.assertEqual(H.Operation.prepared_file_post(op, entry, body=body), P.sha(body))
                            self.assertEqual(H.Operation.prepared_file_post(op, entry), P.sha(body))
                            self.assertEqual(reads[-1], (1, len(body)))
                            self.assertEqual(native(fd, len(body), 0), body)
                            self.assertGreater(len(clocks), len(reads))
                    op.prepared_staging = False
                    with self.assertRaisesRegex(ValueError, 'prepared-staging-owner'):
                        H.Operation.prepared_file_post(op, entry)
                finally:
                    os.close(fd)
                    os.close(root)

    def test_real_original_cpio_materialization_and_final_product_audit_both_targets(self):
        base=Path(os.environ.get('MRK_TEST_REPO',ROOT))
        sys.path.insert(0,str(base/'tests/desktop'))
        import test_macos_installed_staging as T
        tool=T.TOOL
        fixture_owner=T.MacAndroidHelperPackagingData()
        for target in P.TARGETS:
            selection=tool.source_build_selection(target)
            names=('app/'+tool.ENTRY_BINARY,'app/'+tool.APP_BINARY,'app/'+tool.VAULT_HELPER,
                   'app/Contents/Info.plist','app/'+tool.PAYLOAD_INFO,'runtime/python/bin/python3','runtime/manifest.json')
            executables={names[0],names[1],names[2],names[-2]}
            payload={name:(('INERT '+name+'\n').encode(),0o555 if name in executables else 0o444) for name in names}
            manifest_sha=P.sha(payload['runtime/manifest.json'][0])
            inventory=P.canonical(dict(schemaVersion=1,release=selection.release,runtimeManifestSha256=manifest_sha,
                files=[dict(path=name,size=len(body),sha256=P.sha(body),executable=mode==0o555)
                       for name,(body,mode) in sorted(payload.items())]))
            scripts={'input/'+name:row for name,row in payload.items()}
            scripts.update({'input/install-inventory.json':(inventory,0o444),'postinstall':(b'exit 97\n',0o555),
                            'mrk-macos-install':(b'INERT NEVER EXECUTED\n',0o555)})
            info=T.package_data(selection=selection)[1]['PackageInfo']
            def archive(uid,gid):
                body=T.odc('.',stat.S_IFDIR|0o755,uid=uid,gid=gid)
                for name in sorted(tool.directories(scripts)):
                    body+=T.odc('./'+name,stat.S_IFDIR|0o555,uid=uid,gid=gid)
                for name,(contents,mode) in sorted(scripts.items()):
                    body+=T.odc('./'+name,stat.S_IFREG|mode,contents,uid=uid,gid=gid)
                return body+T.odc('TRAILER!!!',0)
            original=fixture_owner.final_package_xar({'PackageInfo':info,'Scripts':archive(os.getuid(),os.getgid())})
            component=fixture_owner.final_package_xar({'PackageInfo':info,'Scripts':archive(0,0)})
            definition,readme=tool.install_product_sources(selection)
            package=fixture_owner.final_package_xar({'Distribution':definition,'Resources/InstallerReadMe.html':readme,
                tool.INSTALL_COMPONENT:component},signed=True,product=True)
            values,manifest,_,_=fixture(target)
            values.update({'MobileReleaseKit.pkg':package,'MobileReleaseKit-original.pkg':original})
            manifest.update(packageVersion=selection.package_version,release=selection.release,
                packagerUid=os.getuid(),packagerGid=os.getgid(),inventorySha256=P.sha(inventory),runtimeManifestSha256=manifest_sha,
                members=[dict(name=name,bytes=len(values[name]),sha256=P.sha(values[name])) for name in sorted(P.FILES)])
            values['PREPARED.json']=P.canonical(manifest)
            self.assertEqual(P.cohort_data(values),manifest)
            parsed=P.original_scripts_data(tool,original,manifest)
            self.assertEqual(parsed,scripts)
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                (root/'original.pkg').write_bytes(original);(root/'original.pkg').chmod(0o600)
                (root/'final.pkg').write_bytes(package);(root/'final.pkg').chmod(0o444)
                tool.write_tree(root/'scripts',parsed,root_mode=0o755,mac_store_prefix='input/runtime/store')
                result=tool.audit_install_product_command(SimpleNamespace(target=target,fixture=False,store_runtime=True,
                    scripts=root/'scripts',original_package=root/'original.pkg',package=root/'final.pkg'))
                self.assertEqual(result['packageSha256'],P.sha(package))
                self.assertEqual(result['scriptFileCount'],len(scripts))
                (root/'scripts/postinstall').chmod(0o755)
                with self.assertRaises(tool.Refused):
                    tool.audit_install_product_command(SimpleNamespace(target=target,fixture=False,store_runtime=True,
                        scripts=root/'scripts',original_package=root/'original.pkg',package=root/'final.pkg'))
            wrong=dict(manifest,packagerUid=os.getuid()+1)
            with self.assertRaisesRegex(ValueError,'prepared-packager-identity'):
                P.original_scripts_data(tool,original,wrong)

    def test_export_passes_held_version_to_actual_build_parser_before_publication(self):
        T, tool, _helper = real_modules()
        for target in P.TARGETS:
            for version, stale in (('0.1.2', False), ('0.1.3', False), ('0.1.3', True)):
                with self.subTest(target=target, version=version, stale=stale):
                    origin = dict(source='1'*40, tree='2'*40, target=target, runId='41', runAttempt='1', jobId='42')
                    work = Path('/inert/prepared-version')
                    directory, binary, rows, image = T.normal_cargo_fixture(work/'cargo-target', build_target=target)
                    if not stale:
                        rows[1]['package_id'] = rows[1]['package_id'].replace('@0.1.2', '@'+version)
                    build = dict(schemaVersion=1, packageVersion=version,
                        release=('macos26-arm64-' if target == tool.ARM_TARGET else 'macos26-x86_64-')+'desktop-03')
                    final, original = b'INERT final package', b'INERT original package'
                    facade = T.entry_macho_fixture(target=target)
                    # Actual original-build parser plus actual manifest reducer;
                    # package/native/original ownership ports are explicitly inert.
                    source = P.canonical(dict(source=origin['source'], tree=origin['tree']))
                    bound = P.canonical(dict(source=origin['source'], tree=origin['tree'], workflowSource=origin['source'],
                        runId='41', runAttempt='1', scope='current-macos-candidate', instrumented=False, packageRole='ordinary-image'))
                    compiled = tool.image_cargo_artifact(T.cargo_lines(*rows, {'reason':'build-finished','success':True}),
                        binary, directory, image, 'desktop', target=target, package_version='0.1.2' if stale else version)
                    app = dict(packageRole='ordinary-image', desktopImageCargoArtifact=compiled,
                        desktopImageSha256BeforeSigning=P.sha(image), appBinarySha256BeforeSigning=P.sha(facade))
                    bodies = {'package-final/MobileReleaseKit.pkg': final, 'MobileReleaseKit-original.pkg':original,
                        'android-helper-finalize-package.json': b'{}\n', 'package-finalization.status':b'0\n',
                        'release':P.canonical(build), 'normal-build.status':b'0\n', 'source-inventory.json':source,
                        'source-binding.json':bound, 'normal-build.jsonl':T.cargo_lines(*rows, {'reason':'build-finished','success':True}),
                        str(binary.relative_to(work)):image, 'mobile-release-kit-desktop':facade,
                        'app-result.json':P.canonical(app)}
                    published = {}
                    def original_file(parent, name, *args):
                        path = str(Path(parent)/name) if parent else name
                        return {'path':path, 'identity':(0,0,0,0,0,0,len(bodies[path]))}
                    audit = dict(packageSha256=P.sha(final), packageSize=len(final),
                        originalPackageSha256=P.sha(original), packageInfoSha256='a'*64, scriptFileCount=3)
                    op = SimpleNamespace(prepared_binding=None, target=target, work=work, stager=tool,
                        work_entry='', release_entry={'path':'release'}, package_outputs=[], package_roots=[],
                        environment={'GITHUB_SHA':origin['source'], 'GITHUB_RUN_ID':'41', 'GITHUB_RUN_ATTEMPT':'1',
                            'MRK_MACOS_INSTALL_INVENTORY_SHA256':'3'*64, 'MRK_BUNDLED_RUNTIME_MANIFEST_SHA256':'4'*64},
                        directory=lambda parent,name,*args: str(Path(parent)/name), original=original_file,
                        descend=lambda parent,parts: str(Path(parent).joinpath(*parts)) if parts else parent,
                        read=lambda entry:bodies[entry['path']], package_finalization_input=lambda *_:audit,
                        package_stager_io=lambda *_:audit, package_directory=lambda name:name,
                        package_file=lambda root,name,body:published.__setitem__(name,body), package_post=lambda:None)
                    with mock.patch.object(P, 'initialize_staging'), mock.patch.object(P, 'ResourceGuard'), \
                            mock.patch.object(P, 'original_scripts_data'), mock.patch.object(P, 'finish_staging') as finish:
                        if stale:
                            with self.assertRaises(tool.Refused): P.export_checkpoint(op, origin)
                            self.assertFalse(published)
                            self.assertIsNotNone(finish.call_args.args[1])
                        else:
                            result = P.export_checkpoint(op, origin)
                            self.assertEqual(result['packageVersion'], version)
                            self.assertEqual(result['normalBuild'], {'appBinarySha256BeforeSigning':P.sha(facade),
                                'desktopImageSha256BeforeSigning':P.sha(image)})
                            self.assertEqual(P.decode(published['PREPARED.json'], P.RECEIPT_LIMIT), result)
                            self.assertEqual(len(published),5)
                            self.assertIsNone(finish.call_args.args[1])
                        finish.assert_called_once()

    def test_actual_prepared_preview_keeps_current_closures_and_refuses_cross_source(self):
        T, tool, helper=real_modules()
        with mock.patch.object(T,'TOOL',tool), mock.patch.dict(sys.modules,{'desktop.tools.macos_prepared_package':P}):
            for target in P.TARGETS:
                work, values, docs, expected, selection=T.MacNormalPreviewData().preview_fixture(target)
                _,manifest,service,consumer=fixture(target)
                origin=manifest['origin']; origin.update(source='a'*40,tree='b'*40,runId='123')
                consumer.update(source='a'*40,tree='b'*40,runId='123',runAttempt='1')
                manifest.update(runtimeManifestSha256='c'*64, inventorySha256='d'*64,
                    normalBuild={k:docs['app-result.json'][k] for k in ('appBinarySha256BeforeSigning','desktopImageSha256BeforeSigning')})
                binding=P.PreparedBinding(P._SEAL,manifest,consumer,{})  # Explicit synthetic provenance DATA only.
                docs['android-helper-package-install.json'].update(runId='123',runAttempt='1',directStagerIOPending=None)
                final=docs['android-helper-finalize-image.json']
                final['workflow']=tool._CANDIDATE_FINAL_IMAGE_WORKFLOW
                final['finalImage']['packageInstallReceiptSha256']=tool.digest(tool.canonical(docs['android-helper-package-install.json']))
                for name in ('android-helper-package-install.json','android-helper-finalize-image.json'):
                    values[work/name]=tool.canonical(docs[name])
                values[work/'input/install-inventory.json']=b'INERT inventory boundary'
                # All OLD worktree build controls removed. Actual common preview
                # still validates current16 calls/readback/producer/final13 calls.
                for name in ('source-binding.json','source-inventory.json','normal-build.status','normal-build.jsonl','app-result.json','mobile-release-kit-desktop'):
                    values.pop(work/name,None)
                environment=dict(GITHUB_REPOSITORY=P.REPOSITORY,GITHUB_EVENT_NAME='push',GITHUB_REF='refs/heads/'+P.BRANCH,
                    GITHUB_WORKFLOW_REF=tool._CANDIDATE_FINAL_IMAGE_WORKFLOW,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,
                    GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
                args=SimpleNamespace(target=target,work=work,output=work/'candidate',expected_source='a'*40,candidate_carrier=True,installed_passive_carrier=False)
                with mock.patch.dict(os.environ,environment,clear=True), mock.patch.object(tool,'source_build_selection',return_value=selection), mock.patch.object(tool,'read',side_effect=lambda path,*_:values[Path(path)]), \
                     mock.patch.object(tool,'observation_inventory_bytes',return_value=expected), \
                     mock.patch.object(tool,'observation_inventory',return_value=expected), mock.patch.object(tool,'write_tree') as output:
                    tool.preview_command(args,prepared=binding)
                    summary=tool.decode(output.call_args.args[1]['PREVIEW.json'][0])
                    self.assertEqual(summary['preparedProducer'],origin)
                    self.assertFalse(summary['productReady']);self.assertEqual(summary['normalBuild'],'passed')
                    output.reset_mock()
                    values[work/'package-install.status']=b'1\n'
                    with self.assertRaises(tool.Refused):tool.preview_command(args,prepared=binding)
                    output.assert_not_called()
                    values[work/'package-install.status']=b'0\n'
                    cross=P.PreparedBinding(P._SEAL,manifest,dict(consumer,source='e'*40),{})
                    with self.assertRaises(ValueError):tool.preview_command(args,prepared=cross)
                    output.assert_not_called()

    def test_exact_job_and_artifact_selection_never_last_matrix_row_or_truncated_page(self):
        values,manifest,service,consumer=fixture()
        job=dict(service['job'],status='completed',conclusion='success')
        opposite=dict(job,name='normal-installed-'+P.TARGETS[1],id=99)
        body=P.canonical(dict(total_count=2,jobs=[opposite,job]))
        self.assertEqual(P.selected_job_data(body,'1'*40,'41',P.TARGETS[0],completed=True),job)
        for rows,total in (([job,job],2),([job],2),([dict(job,run_attempt=True)],1)):
            with self.assertRaises(ValueError):P.selected_job_data(P.canonical(dict(total_count=total,jobs=rows)),'1'*40,'41',P.TARGETS[0],completed=True)
        body=P.canonical(dict(total_count=1,artifacts=[service['artifact']]))
        self.assertEqual(P.selected_artifact_data(body,manifest['origin']),service['artifact'])
        with self.assertRaises(ValueError):P.selected_artifact_data(P.canonical(dict(total_count=2,artifacts=[service['artifact']]*2)),manifest['origin'])

    def test_failed_prepared_source_admission_is_inside_actual_execute_cleanup(self):
        T,tool,helper=real_modules()
        values,manifest,service,consumer=fixture()
        binding=P.admit_data(values,service,consumer)
        environment=dict(GITHUB_SHA=consumer['source'],GITHUB_WORKFLOW_SHA=consumer['source'],GITHUB_RUN_ID='41',
            GITHUB_RUN_ATTEMPT='2',GITHUB_WORKFLOW_REF=P.REPOSITORY+'/'+P.WORKFLOW+'@refs/heads/'+P.BRANCH,
            MRK_MACOS_PACKAGE_ROLE='ordinary-image')
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(sys.modules,{'desktop.tools.macos_prepared_package':P}):
            root=Path(directory); checkout=root/'source';work=root/'work';checkout.mkdir();work.mkdir(mode=0o700)
            (checkout/'.git').mkdir();(checkout/'.git/HEAD').write_bytes(b'wrong original HEAD\n');(checkout/'.git/HEAD').chmod(0o644)
            native=mock.Mock(side_effect=AssertionError('native must not enter'))
            operation=helper.Operation(SimpleNamespace(run_owned=native),checkout,work,'package-install',environment,tool,prepared=binding)
            with self.assertRaises(helper.Refused):operation.execute()
            native.assert_not_called()
            self.assertTrue(operation.receipt['originalClosesKnown'] and operation.receipt['targetRetired'])
            self.assertTrue(all(row['closed'] and row['fd'] is None for row in operation.entries))
            self.assertFalse(operation.receipt['passed'])
            self.assertFalse((work/operation.target_name).exists())

    def test_actual_retention_gate_requires_one_successful_upload_before_service_cut(self):
        workflow = (ROOT / P.WORKFLOW).read_text()
        marker = '      - name: ' + P.PRODUCER_STEPS[-1] + '\n'
        self.assertEqual(workflow.count(marker), 1)
        gate = workflow.split(marker, 1)[1].split('\n      - name:', 1)[0]
        script = textwrap.dedent(gate.split('        run: |\n', 1)[1])
        _, _, service, _ = fixture()
        outcomes = ('success', 'failure', 'skipped', 'cancelled', '')
        for first in outcomes:
            for retry in outcomes:
                with self.subTest(first=first, retry=retry):
                    result = subprocess.run(['/bin/bash', '-c', script],
                        env={'PATH': '/usr/bin:/bin', 'FIRST_OUTCOME': first, 'RETRY_OUTCOME': retry},
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
                    accepted = (first, retry) in (('success', 'skipped'), ('failure', 'success'))
                    self.assertEqual(result.returncode, 0 if accepted else 1)
                    self.assertEqual(result.stderr, '')
                    self.assertEqual(result.stdout,
                        'Prepared upload original outcomes: first=%s retry=%s\n' % (first, retry))
                    # GitHub normalizes continue-on-error conclusions. These
                    # cannot establish the cut when the real outcome gate fails.
                    steps = copy.deepcopy(service['job']['steps'][:2])
                    steps.extend(dict(name=name, number=index, status='completed', conclusion='success')
                        for index, name in enumerate(('First upload attempt', 'Retry upload attempt'), 3))
                    steps.append(dict(name=P.PRODUCER_STEPS[-1], number=5, status='completed',
                        conclusion='success' if result.returncode == 0 else 'failure'))
                    job = dict(service['job'], status='completed', conclusion='success', steps=steps)
                    body = P.canonical(dict(total_count=1, jobs=[job]))
                    if accepted:
                        self.assertEqual(P.selected_job_data(body, '1'*40, '41', P.TARGETS[0], completed=True), job)
                    else:
                        with self.assertRaisesRegex(ValueError, 'prepared-service-cut'):
                            P.producer_steps_data(job)
                        with self.assertRaisesRegex(ValueError, 'prepared-one-target-job'):
                            P.selected_job_data(body, '1'*40, '41', P.TARGETS[0], completed=True)

    def test_all_attempt_selection_keeps_the_unique_successful_old_producer(self):
        values,manifest,service,consumer=fixture()
        # All three authenticated checkpoint steps closed successfully. An
        # unrelated later cleanup failure cannot revoke their uploaded bytes.
        old=dict(service['job'],status='completed',conclusion='failure', steps=[
            *service['job']['steps'], dict(name='Retire disposable compiler outputs', number=4,
                                        status='completed', conclusion='failure')])
        install=dict(old,id=99,run_attempt=2,name='prepared-installed-'+P.TARGETS[0],conclusion='failure')
        failed_steps=copy.deepcopy(old['steps'])
        failed_steps[1]['conclusion']='failure'
        failed_build=dict(old,id=101,run_attempt=2,steps=failed_steps)
        latest=P.canonical(dict(total_count=2,jobs=[install,failed_build]))
        with self.assertRaises(ValueError):P.selected_job_data(latest,'1'*40,'41',P.TARGETS[0],completed=True)
        all_attempts=P.canonical(dict(total_count=3,jobs=[install,old,failed_build]))
        selected=P.selected_job_data(all_attempts,'1'*40,'41',P.TARGETS[0],completed=True)
        self.assertEqual(selected,old)
        self.assertEqual(selected['run_attempt'],1)
        # Whole-job success is neither necessary nor sufficient for the cut.
        succeeded=dict(old,conclusion='success')
        self.assertEqual(P.selected_job_data(P.canonical(dict(total_count=1,jobs=[succeeded])),
            '1'*40,'41',P.TARGETS[0],completed=True),succeeded)
        for wrong in (dict(failed_build,conclusion='success'), dict(old,status='in_progress'),
                      dict(old,head_sha='6'*40), dict(old,run_id=42)):
            with self.subTest(job=wrong['id'], status=wrong['status']),self.assertRaises(ValueError):
                P.selected_job_data(P.canonical(dict(total_count=1,jobs=[wrong])),
                    '1'*40,'41',P.TARGETS[0],completed=True)
        with self.assertRaises(ValueError):
            P.selected_job_data(P.canonical(dict(total_count=2,jobs=[old,dict(old,id=103,run_attempt=3)])),
                '1'*40,'41',P.TARGETS[0],completed=True)
        for key,value in (('size_in_bytes',P.ARTIFACT_LIMIT+1),('size_in_bytes',True),('digest','sha256:'+'0'*64)):
            artifact=dict(service['artifact'],**{key:value})
            with self.assertRaises(ValueError):P.selected_artifact_data(P.canonical(dict(total_count=1,artifacts=[artifact])),manifest['origin'])

    def test_actual_original_receipt_consumer_keeps_producer_and_new_attempt_separate(self):
        T,tool,helper=real_modules()
        fixture_owner=T.MacAndroidHelperPackagingData()
        with mock.patch.object(T,'TOOL',tool), mock.patch.object(T,'ANDROID_HELPER',helper), \
             mock.patch.dict(sys.modules,{'desktop.tools.macos_prepared_package':P}):
            for target in P.TARGETS:
                with tempfile.TemporaryDirectory() as directory:
                    state=fixture_owner.final_package_fixture(Path(directory),target=target)
                    state.environment.update(GITHUB_REF='refs/heads/'+P.BRANCH,GITHUB_WORKFLOW_REF=P.REPOSITORY+'/'+P.WORKFLOW+'@refs/heads/'+P.BRANCH)
                    state.operation.receipt['workflow']=state.environment['GITHUB_WORKFLOW_REF']
                    with fixture_owner.final_package_fixture_call(state):state.operation.execute()
                    record=state.operation.receipt['finalPackage']
                    status=state.work/'package-finalization.status';status.write_bytes(b'0\n');status.chmod(0o600)
                    _,manifest,_,_=fixture(target)
                    manifest['origin'].update(source=state.environment['GITHUB_SHA'],runId=state.environment['GITHUB_RUN_ID'],runAttempt=state.environment['GITHUB_RUN_ATTEMPT'])
                    for harness in (state.environment['GITHUB_SHA'],'6'*40):
                        consumer=dict(source=harness,tree='2'*40,target=target,runId=state.environment['GITHUB_RUN_ID'],runAttempt='2')
                        binding=P.PreparedBinding(P._SEAL,manifest,consumer,{})
                        current=dict(state.environment,GITHUB_SHA=harness,GITHUB_WORKFLOW_SHA=harness,GITHUB_RUN_ATTEMPT='2')
                        for prepared in (None,binding):
                            env=dict(current,MRK_MACOS_INSTALL_SOURCE_COMMIT=harness if prepared is None else binding.source)
                            later=helper.Operation(SimpleNamespace(run_owned=mock.Mock(side_effect=AssertionError('no native handoff call'))),
                                state.checkout,state.work,'package-install',env,tool,target=target,prepared=prepared)
                            later.package_started=later.package_observed=state.clock[0]
                            later.package_endpoint=state.clock[0]+990_000_000_000
                            later.signing=state.operation.signing
                            with fixture_owner.credential_fixture_call(later,state.credentials):
                                try:
                                    later.open();later.image_binding()
                                    parent=later.directory(later.work_entry,'package-final','prepared-test-final')
                                    original=later.original(parent,'MobileReleaseKit.pkg','prepared-test-package',tool.MAX_BYTES,(0o444,))
                                    if prepared is None:
                                        with self.assertRaises(helper.Refused):later.package_finalization_input(original,later.read(original))
                                    else:
                                        self.assertEqual(later.package_finalization_input(original,later.read(original)),record)
                                        self.assertEqual(later.image_source,binding.source)
                                        self.assertEqual(later.receipt['source'],harness)
                                        later.package_post()
                                    self.assertEqual(later.calls,[])
                                    self.assertEqual(env['GITHUB_RUN_ATTEMPT'],'2')
                                finally:later.finish()
                            self.assertTrue(later.receipt['originalClosesKnown'] and later.receipt['targetRetired'])
                            self.assertFalse(later.receipt['passed'])


    @contextlib.contextmanager
    def current_readback_fixture(self, target=P.TARGETS[0]):
        import time
        T, tool, helper = real_modules()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            built, current, work = root/'built', root/'current', root/'work'
            built.mkdir(); current.mkdir(); work.mkdir(mode=0o700)
            def put(relative, body):
                path = current/relative; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body); path.chmod(0o644); return path
            program = put('desktop/tools/stage_macos_installed.py', (ROOT/'desktop/tools/stage_macos_installed.py').read_bytes())
            put('.git/HEAD', b'6'*40+b'\n')
            for name in ('build-release.json', 'build-release-intel.json'):
                put('desktop/macos-installed-inputs/'+name, (tool.DESKTOP/'macos-installed-inputs'/name).read_bytes())
            values, manifest, service, consumer = fixture(target)
            selection = tool.source_build_selection(target)
            manifest.update(packageVersion=selection.package_version, release=selection.release)
            values['PREPARED.json'] = P.canonical(manifest)
            consumer.update(source='6'*40, tree='7'*40)
            binding = P.admit_data(values, service, consumer)
            env = dict(GITHUB_SHA=consumer['source'], GITHUB_WORKFLOW_SHA=consumer['source'], GITHUB_RUN_ID='41',
                GITHUB_RUN_ATTEMPT='2', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF=helper.CANDIDATE_REF,
                GITHUB_WORKFLOW_REF=P.REPOSITORY+'/'+P.WORKFLOW+'@refs/heads/'+P.BRANCH,
                MRK_MACOS_PACKAGE_ROLE='ordinary-image')
            owner = SimpleNamespace(run_owned=mock.Mock(side_effect=AssertionError('no native call in source readback test')))
            with mock.patch.dict(sys.modules, {'desktop.tools.macos_prepared_package': P}), mock.patch.object(helper, 'CHECKOUT', current):
                op = helper.Operation(owner, built, work, 'package-install', env, tool, target=target, prepared=binding)
                op.open()
                op.package_started = op.package_observed = time.monotonic_ns()
                op.package_endpoint = op.package_started + 990_000_000_000
                op.image_source, op.image_release = binding.source, selection.release
                # Explicit inert previous-Installer boundary; no native execution claimed.
                op.installer_zero = True
                args = SimpleNamespace(target=target, expected_source=binding.source,
                    expected_inventory=manifest['inventorySha256'], expected_manifest=manifest['runtimeManifestSha256'],
                    expected_package=P.sha(values['MobileReleaseKit.pkg']))
                try:
                    yield SimpleNamespace(T=T, tool=tool, helper=helper, op=op, args=args, current=current, program=program,
                                          binding=binding, environment=env, owner=owner)
                finally:
                    op.finish()
                    owner.run_owned.assert_not_called()
                    self.assertTrue(all(e['closed'] and e['fd'] is None for e in op.entries))
                    self.assertFalse(op.receipt['passed'])  # No package/GUI/native authority from this fixture.

    def test_current_readback_original_source_and_built_readers_stay_separate(self):
        for target in P.TARGETS:
            with self.subTest(target=target), self.current_readback_fixture(target) as f:
                current = f.op.package_stager_io('readback-admission', None)
                self.assertIsNot(current, f.tool)
                self.assertIs(f.op.stager, f.tool)
                self.assertNotEqual(type(current.source_build_selection(target)), type(f.tool.source_build_selection(target)))
                self.assertEqual(tuple(current.source_build_selection(target)), tuple(f.tool.source_build_selection(target)))
                names = {e['name'] for e in f.op.entries if e['role'].startswith('readback-source-')}
                self.assertEqual(names, {'build-release.json'} | ({'build-release-intel.json'} if target == P.TARGETS[1] else set()))
                self.assertEqual(f.op.read(f.op.diagnostic_program_entry), f.program.read_bytes())
                producer, records, result = f.T.maintenance_documents(('fresh-install', 'same-package-noop'), launcher=True, target=target)
                def readback(args):
                    self.assertIs(args, f.args)
                    # Actual current capsule/history parser; only OS observation port is inert.
                    return current.maintenance_history_data(result, records, producer)[0]
                with mock.patch.object(current, 'observation_command', side_effect=readback) as fresh, \
                     mock.patch.object(f.tool, 'observation_command', side_effect=AssertionError('built readback not selected')) as old, \
                     mock.patch.object(f.tool, 'audit_install_product_command', return_value='built audit') as audit, \
                     mock.patch.object(f.tool, 'installer_result_absent_command', return_value='built absence') as absent:
                    self.assertEqual(f.op.package_stager_io('final-audit', f.args), 'built audit')
                    self.assertEqual(f.op.package_stager_io('result-absence', f.args), 'built absence')
                    self.assertEqual(f.op.package_stager_io('v2-readback', f.args)['invocation'], result['invocation'])
                    fresh.assert_called_once_with(f.args); old.assert_not_called()
                    audit.assert_called_once_with(f.args); absent.assert_called_once_with(f.args)
                self.assertIsNone(f.op.stager_io_pending)
                self.assertIs(f.op.current_readback_module, current)
                self.assertIs(f.op.stager_failure_module, f.tool)
                self.assertEqual(f.op.image_source, '1'*40)
                self.assertEqual(f.op.environment['GITHUB_SHA'], '6'*40)
                f.op.package_post()
            self.assertTrue(f.op.receipt['targetRetired'])

    def test_current_readback_refuses_wrong_scope_selection_and_original_arguments(self):
        with self.current_readback_fixture() as f:
            for key, value in (('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REF', 'refs/heads/other')):
                with mock.patch.dict(f.environment, {key: value}), self.assertRaisesRegex(f.helper.Refused, 'prepared-readback-purpose'):
                    f.op.package_readback_module()
            with mock.patch.object(f.op, 'phase', 'finalize-image'), self.assertRaisesRegex(f.helper.Refused, 'prepared-readback-purpose'):
                f.op.package_readback_module()
            self.assertIsNone(f.op.current_readback_module)
            for binding in (None, P.PreparedBinding(P._SEAL, f.binding.manifest,
                    dict(f.binding.consumer, source=f.binding.source), {})):
                with mock.patch.object(f.op, 'prepared_binding', binding):
                    self.assertIs(f.op.package_readback_module(f.args), f.tool)
            with mock.patch.object(f.op, 'image_release', 'wrong'), self.assertRaisesRegex(f.helper.Refused, 'prepared-readback-built-selection'):
                f.op.package_readback_module()
            current = f.op.package_readback_module()
            original = current.source_build_selection()
            with mock.patch.object(current, 'source_build_selection', return_value=original._replace(package_version='99.0.0')), \
                 self.assertRaisesRegex(f.helper.Refused, 'prepared-readback-current-selection'):
                f.op.package_readback_module()
            with mock.patch.object(current, 'CURRENT_PROTOCOL', '0'*64), self.assertRaisesRegex(f.helper.Refused, 'prepared-readback-current-selection'):
                f.op.package_readback_module()
            for key in vars(f.args):
                wrong = SimpleNamespace(**vars(f.args)); setattr(wrong, key, 'wrong')
                with self.subTest(key=key), self.assertRaisesRegex(f.helper.Refused, 'prepared-readback-original-bindings'):
                    f.op.package_readback_module(wrong)
            with mock.patch.object(f.op, 'installer_zero', False), self.assertRaisesRegex(f.helper.Refused, 'prepared-readback-installer-not-zero'):
                f.op.package_readback_module(f.args)
            f.op.package_post()
            # The actual install method reaches compatibility before signing or any Installer effect.
            f.op.release_entry = next(e for e in f.op.entries if e['role'] == 'readback-source-build-release.json')
            f.environment.update(MRK_MACOS_INSTALL_INVENTORY_SHA256=f.args.expected_inventory,
                                 MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=f.args.expected_manifest)
            refusal = f.helper.Refused('prepared-readback-current-selection')
            with mock.patch.object(f.op, 'package_readback_module', side_effect=refusal) as preflight, \
                 mock.patch.object(f.tool, 'packaging_signing_data', side_effect=AssertionError('signing must remain unentered')) as signing:
                with self.assertRaises(f.helper.Refused) as caught:
                    f.op.package_install()
                self.assertIs(caught.exception, refusal); preflight.assert_called_once_with(); signing.assert_not_called()
                self.assertEqual(f.op.stager_io_pending, 'readback-admission')
                self.assertEqual(f.op.errors[-1], dict(stage='package-stager-io', operation='readback-admission', type='CompletionUnknown'))

    def test_current_readback_source_post_and_unknown_original_cannot_pass(self):
        for mutation in ('program', 'release', 'unknown'):
            with self.subTest(mutation=mutation), self.current_readback_fixture(P.TARGETS[1]) as f:
                current = f.op.package_stager_io('readback-admission', None)
                def readback(_):
                    path = f.program if mutation == 'program' else f.current/'desktop/macos-installed-inputs/build-release-intel.json'
                    path.write_bytes(path.read_bytes()+b' ')
                    return {'not': 'accepted after source drift'}
                with mock.patch.object(current, 'observation_command', side_effect=readback) as observed:
                    if mutation == 'unknown':
                        f.op.calls.append(dict(role='installer', returned=True, capturesSettled=False))
                    with self.assertRaises(f.helper.Refused):
                        f.op.package_stager_io('v2-readback', f.args)
                    if mutation == 'unknown':
                        observed.assert_not_called(); self.assertIsNone(f.op.stager_io_pending)
                    else:
                        observed.assert_called_once_with(f.args)
                        self.assertEqual(f.op.stager_io_pending, 'v2-readback')
                        self.assertEqual(f.op.errors[-1]['type'], 'CompletionUnknown')
                    self.assertFalse(f.op.installation_readback)
            self.assertFalse(f.op.receipt['targetRetired'])

    def test_current_readback_failure_uses_actual_module_line_and_same_pending_tail(self):
        for point in ('readback', 'preflight-import', 'preflight-selection'):
            target = P.TARGETS[1] if point == 'preflight-selection' else P.TARGETS[0]
            with self.subTest(point=point), self.current_readback_fixture(target) as f:
                current = (None if point == 'preflight-import' else
                           f.op.package_stager_io('readback-admission', None))
                producer, _records, _result = f.T.maintenance_documents()
                failure = []
                def readback(_):
                    return current.maintenance_capsule_data(b'{}\n', producer, current=True)
                pending = 'v2-readback' if point == 'readback' else 'readback-admission'
                if point != 'readback':
                    # Actual imported/selected source JSON parser fails after its original read.
                    name = 'build-release-intel.json' if point == 'preflight-selection' else 'build-release.json'
                    (f.current/'desktop/macos-installed-inputs'/name).write_bytes(b'{}\n')
                def boundary():
                    try:
                        return f.op.package_stager_io(pending, f.args if point == 'readback' else None)
                    except BaseException as error:
                        failure.append(error); raise
                patch = (mock.patch.object(current, 'observation_command', side_effect=readback)
                         if point == 'readback' else contextlib.nullcontext())
                with patch, mock.patch.object(f.op, 'open', side_effect=boundary):
                    # Exercise the real execute catch/finish/finite receipt, not a copied classifier.
                    with self.assertRaisesRegex(f.helper.Refused, 'helper-package-incomplete'):
                        f.op.execute()
                current = f.op.stager_failure_module
                self.assertEqual(len(failure), 1)
                self.assertIs(type(failure[0]), current.Refused)
                self.assertEqual(f.op.diagnostic_failure['type'], 'stager-refused')
                self.assertEqual(f.op.stager_failure_line, f.helper.failure_stager_line(failure[0], current))
                self.assertIsInstance(f.op.stager_failure_line, int)
                self.assertIsNone(f.helper.failure_stager_line(failure[0], f.tool))
                self.assertEqual(f.op.stager_io_pending, pending)
                self.assertFalse(f.op.receipt['passed'])
                self.assertFalse(f.op.receipt['targetRetired'])
                self.assertFalse(f.op.receipt['originalClosesKnown'])  # Pending observer is not whole-operation finality.
                self.assertTrue(all(e['closed'] and e['fd'] is None for e in f.op.entries))
                self.assertIs(f.op.stager, f.tool)
                if point == 'preflight-import': self.assertIsNone(f.op.current_readback_module)

    def resource_original(self, helper, tool, root, target=P.TARGETS[0]):
        import subprocess
        import time
        work=root/'work';work.mkdir(mode=0o700,exist_ok=True)
        checkout=root/'source';checkout.mkdir(exist_ok=True)
        environment=dict(GITHUB_SHA='1'*40,GITHUB_WORKFLOW_SHA='1'*40,GITHUB_RUN_ID='41',
            GITHUB_RUN_ATTEMPT='2',GITHUB_WORKFLOW_REF=P.REPOSITORY+'/'+P.WORKFLOW+'@refs/heads/'+P.BRANCH,
            MRK_MACOS_PACKAGE_ROLE='ordinary-image')
        body=(b'Mach Virtual Memory Statistics: (page size of 4096 bytes)\n'
              b'Pages free: 1000000.\nPages inactive: 1.\nPages speculative: 1.\n')
        def native(argv, **kwargs):
            self.assertEqual(argv,['/usr/bin/vm_stat'])
            self.assertEqual(kwargs['timeout'],10)
            return subprocess.CompletedProcess(argv,0,body,b'')
        dispatch=mock.Mock(side_effect=native)
        op=helper.Operation(SimpleNamespace(run_owned=dispatch),checkout,work,'package-install',environment,tool,target=target)
        op.prepared_staging=True
        op.open()
        op.package_started=op.package_observed=time.monotonic_ns()
        op.package_endpoint=op.package_started+180_000_000_000
        op.mount_api=object()
        # Only native Darwin host admission/counters are inert. The ResourceGuard,
        # VM-output parser, dispatch ledger, publisher/readback/closes are real.
        with mock.patch.object(op,'normal_mount_host'):
            guard=P.ResourceGuard(op)
        return op,guard,dispatch,body

    def test_resource_samples_and_next_prepared_owner_use_original_target_captures(self):
        _,tool,helper=real_modules()
        for target in P.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                for owner_number,samples in ((1,16),(2,2)):
                    op,guard,dispatch,body=self.resource_original(helper,tool,root,target)
                    try:
                        with mock.patch.object(guard.data,'host_memory_data',return_value=(4096,16<<30)):
                            for _ in range(samples):guard.check(dict(memoryBytes=1,diskBytes=1))
                            if owner_number==1:
                                with self.assertRaisesRegex(ValueError,'prepared-resource-sample-bound'):
                                    guard.check(dict(memoryBytes=1,diskBytes=1))
                        self.assertEqual(dispatch.call_count,samples)
                        for index in range(1,samples+1):
                            prefix=op.work/op.target_name/('android-helper-prepared-resource-memory-%02d'%index)
                            for suffix,expected in (('.stdout',body),('.stderr',b''),('.status',b'0\n')):
                                self.assertEqual(Path(str(prefix)+suffix).read_bytes(),expected)
                        self.assertTrue(all(row['returned'] and row['capturesSettled'] for row in op.calls))
                    finally:P.finish_staging(op,sys.exception())
                    self.assertTrue(op.receipt['targetRetired'] and op.receipt['originalClosesKnown'])
                    self.assertTrue(all(row['closed'] and row['fd'] is None for row in op.entries))
                    self.assertFalse((op.work/op.target_name).exists())
                    # Existing work-root captures from an earlier version are
                    # neither deleted nor overwritten by the next owner.
                    for suffix in ('.stdout','.stderr','.status'):
                        previous=op.work/('android-helper-prepared-resource-memory'+suffix)
                        if owner_number==1:previous.write_bytes(b'prior original')
                        self.assertEqual(previous.read_bytes(),b'prior original')

    def test_occupied_resource_capture_refuses_and_never_reuses_failed_slot(self):
        _,tool,helper=real_modules()
        with tempfile.TemporaryDirectory() as directory:
            op,guard,dispatch,_=self.resource_original(helper,tool,Path(directory))
            occupied=op.work/op.target_name/'android-helper-prepared-resource-memory-01.stdout'
            occupied.write_bytes(b'preserved original');occupied.chmod(0o600)
            failure=None
            try:
                with mock.patch.object(guard.data,'host_memory_data',return_value=(4096,16<<30)):
                    with self.assertRaises(FileExistsError) as raised:guard.check(dict(memoryBytes=1,diskBytes=1))
                    failure=raised.exception
                    with self.assertRaises(helper.Refused):guard.check(dict(memoryBytes=1,diskBytes=1))
                self.assertEqual(dispatch.call_count,1)
                self.assertEqual(len(op.calls),1)
                self.assertTrue(op.calls[0]['returned']);self.assertFalse(op.calls[0]['capturesSettled'])
                with self.assertRaises(helper.Refused):op.publish('unexpected.stdout',b'not allowed',parent=op.target_entry)
                self.assertEqual(occupied.read_bytes(),b'preserved original')
            finally:P.finish_staging(op,failure)
            self.assertFalse(op.receipt['targetRetired'])
            self.assertTrue(op.receipt['originalClosesKnown'])
            self.assertEqual(occupied.read_bytes(),b'preserved original')
            self.assertIn('prepared-staging-original-closes',failure.__notes__)

    def test_nonstaging_call_keeps_existing_capture_scope(self):
        _,tool,helper=real_modules()
        with tempfile.TemporaryDirectory() as directory:
            op,_,dispatch,body=self.resource_original(helper,tool,Path(directory))
            op.prepared_staging=False
            try:
                op.call('prepared-resource-memory',['/usr/bin/vm_stat'],op.native_environment(),
                        cwd=op.work,timeout=10,limit=65536)
                self.assertEqual((op.work/'android-helper-prepared-resource-memory.stdout').read_bytes(),body)
                self.assertEqual(sorted(p.name for p in (op.work/op.target_name).iterdir()),['tmp'])
                with self.assertRaises(helper.Refused):
                    op.publish('android-helper-prepared-resource-memory-01.stdout',b'not allowed',parent=op.target_entry)
            finally:op.finish()
            self.assertEqual(dispatch.call_count,1)
            self.assertTrue(op.receipt['targetRetired'] and op.receipt['originalClosesKnown'])

    def test_failed_consuming_close_preserves_original_exception(self):
        class Op:
            def finish(self): raise KeyboardInterrupt('inert close')
        error=ValueError('inert primary')
        P.finish_staging(Op(),error)
        self.assertEqual(error.__notes__,['prepared-staging-original-closes'])
        with self.assertRaises(KeyboardInterrupt): P.finish_staging(Op())


class PackageRoleWorkflowData(unittest.TestCase):
    """Actual shell path selection and helper input opens; no Mac tools or signing."""

    def package_segment(self):
        workflow = (ROOT / P.WORKFLOW).read_text()
        marker = '      - name: Build the fixed one-shot root Installer and scripts-only package\n'
        self.assertEqual(workflow.count(marker), 1)
        step = workflow.split(marker, 1)[1].split('\n      - name:', 1)[0]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        start = '# xar is not a streaming/O_EXCL tool: reserve its private output parent.\n'
        end = 'unset MRK_MACOS_DEVELOPER_ID_P12_BASE64 MRK_MACOS_DEVELOPER_ID_P12_PASSWORD'
        self.assertEqual(script.count(start), 1)
        self.assertEqual(script.count(end), 1)
        script = start + script.split(start, 1)[1].split(end, 1)[0]
        native = '/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC COPYFILE_DISABLE=1 \\\n    /usr/bin/xar'
        self.assertEqual(script.count(native), 1)
        # Intercept only XAR. Real fixed mkdir/no-clobber/cwd/status logic runs.
        return '''set -euo pipefail
set -o noclobber
umask 077
inert_xar() {
  [[ $# == 6 && "$1" == -c && "$2" == -f && "$4" == --compression=none && "$5" == PackageInfo && "$6" == Scripts ]] || exit 97
  printf 'INERT XAR input, never installed\\n' > "$3"
  printf '%s\\n' "$3"
}
''' + script.replace(native, 'inert_xar', 1)

    def produce(self, work, role):
        (work / 'package-parts').mkdir(mode=0o700)
        environment = dict(PATH='/usr/bin:/bin', LC_ALL='C', TZ='UTC', MRK_MACOS_WORK=str(work))
        if role is not None:
            environment['MRK_MACOS_PACKAGE_ROLE'] = role
        return subprocess.run(['/bin/bash', '-c', self.package_segment()], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)

    def consume_input(self, helper, tool, work, role):
        # Stub only earlier source/audit/clock prerequisites. Exercise actual
        # role dispatch, directory/original opens and held input-byte reads,
        # stopping BEFORE productbuild, signing or any native command.
        environment = dict(GITHUB_SHA='1'*40, GITHUB_WORKFLOW_SHA='1'*40,
            GITHUB_WORKFLOW_REF='inert/source@'+'1'*40, GITHUB_RUN_ID='1',
            GITHUB_RUN_ATTEMPT='1', MRK_MACOS_PACKAGE_ROLE=role)
        native = mock.Mock(side_effect=AssertionError('no native call is permitted'))
        operation = helper.Operation(SimpleNamespace(run_owned=native), work / 'unused-source',
            work, 'finalize-package', environment, tool)
        self.assertEqual(operation.install_product, role == 'ordinary-image')
        operation.signing = object()
        operation.install_presentation_sources = [None, None]
        (work / 'scripts').mkdir(mode=0o700)
        original = work / operation.packager_filename
        original.write_bytes(b'INERT original package\n'); original.chmod(0o600)
        operation.work_entry = operation.register(os.open(work, helper.READ_FLAGS | os.O_DIRECTORY), 'work', 'directory')
        operation.work_entry['identity'] = helper.directory_identity(os.fstat(operation.work_entry['fd']))
        captured = []
        class InputRead(Exception): pass
        def audit(entry, path):
            captured.append(entry)
            raise InputRead()
        def component_audit(label, *args):
            self.assertEqual(label, 'install-product-component-audit')
            captured.append(operation.install_component_inputs[1])
            raise InputRead()
        try:
            with contextlib.ExitStack() as stack:
                for name in ('notary_space', 'installer_sources', 'notary_clock', 'selected_package_store', 'notary_snapshot'):
                    stack.enter_context(mock.patch.object(operation, name, return_value=None))
                stack.enter_context(mock.patch.object(operation, 'source_original', return_value=None))
                stack.enter_context(mock.patch.object(operation, 'read', return_value=b'inert source'))
                stack.enter_context(mock.patch.object(helper, 'notary_service', return_value=None))
                stack.enter_context(mock.patch.object(operation, 'final_package_audit', side_effect=audit))
                stack.enter_context(mock.patch.object(operation, 'final_package_io', side_effect=component_audit))
                with self.assertRaises(InputRead):
                    operation.finalize_package()
            self.assertEqual(len(captured), 1)
            self.assertEqual(os.pread(captured[0]['fd'], 128, 0), b'INERT XAR input, never installed\n')
            self.assertEqual(captured[0]['role'], 'install-product-component' if operation.install_product else 'final-package-unsigned-original')
            native.assert_not_called()
            self.assertEqual((operation.calls, operation.credential_calls, operation.credential_contexts), ([], [], []))
            self.assertFalse(operation.final_package_complete or operation.receipt['passed'])
        finally:
            for entry in reversed(operation.entries):
                operation.close(entry)
        self.assertEqual(operation.errors, [])
        self.assertTrue(all(entry['closed'] and entry['fd'] is None for entry in operation.entries))

    def test_workflow_package_input_matches_both_actual_helper_roles(self):
        _, tool, helper = real_modules()
        for role, directory in (('ordinary-image', 'package-component'), ('installed-shell-observation', 'package-unsigned')):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                result = self.produce(work, role)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.consume_input(helper, tool, work, role)
                self.assertEqual(result.stdout, str(work / directory / 'MobileReleaseKit.pkg') + '\n')
                self.assertEqual((work / 'package-xar.status').read_bytes(), b'0\n')
                self.assertEqual(stat.S_IMODE((work / directory).stat().st_mode), 0o700)
                self.assertFalse((work / ('package-unsigned' if directory == 'package-component' else 'package-component')).exists())

    def test_workflow_unknown_or_missing_role_refuses_before_create_or_xar(self):
        for role in (None, '', 'other', 'ordinary-image/../package-unsigned'):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                result = self.produce(work, role)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(sorted(path.name for path in work.iterdir()), ['package-parts'])

    def test_workflow_existing_package_parent_or_output_is_never_replaced(self):
        for role, directory in (('ordinary-image', 'package-component'), ('installed-shell-observation', 'package-unsigned')):
            for occupied in ('directory', 'output', 'symlink'):
                with self.subTest(role=role, occupied=occupied), tempfile.TemporaryDirectory() as temporary:
                    work = Path(temporary); parent = work / directory
                    if occupied == 'symlink':
                        parent.symlink_to('missing-owned-test-target', target_is_directory=True)
                    else:
                        parent.mkdir(mode=0o700)
                        if occupied == 'output':
                            (parent / 'MobileReleaseKit.pkg').write_bytes(b'preserve existing package')
                    before = parent.lstat()
                    result = self.produce(work, role)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, '')
                    self.assertFalse((work / 'package-xar.status').exists())
                    after = parent.lstat()
                    self.assertEqual((before.st_ino, before.st_mode), (after.st_ino, after.st_mode))
                    if occupied == 'output':
                        self.assertEqual((parent / 'MobileReleaseKit.pkg').read_bytes(), b'preserve existing package')
                    elif occupied == 'symlink':
                        self.assertEqual(os.readlink(parent), 'missing-owned-test-target')


if __name__=='__main__': unittest.main()
