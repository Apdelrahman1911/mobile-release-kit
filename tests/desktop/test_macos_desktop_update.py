"""Ordinary update composition/provenance DATA, never native installation proof."""
import copy
import json
import os
import plistlib
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from desktop.tools import macos_candidate_parts as P
from desktop.tools import macos_candidate_part_transport as T
from desktop.tools import macos_prepared_package as B
from desktop.tools import macos_desktop_update as U
from tests.desktop.test_macos_candidate_parts import fixture as native_fixture
from tests.desktop.test_macos_prepared_package import fixture as prepared_fixture
from tests.desktop import test_macos_prepared_package as prepared_tests
from tests.desktop.test_macos_candidate_parts_workflow import yaml


def ordinary_fixture(part='image'):
    manifest, run, job, artifact = native_fixture('prepare')
    origin = manifest['origin']; origin.update(nativeScope='disabled', hostProfile='macos-26')
    manifest['part'] = part
    manifest['dependencies'] = [dict(part=n, origin=dict(origin, jobId=str(100+i)), artifactId=str(200+i),
        artifactSha256='a'*64, manifestSha256='b'*64) for i, n in enumerate(P.ancestors(part, origin))]
    job.update(name=P.job_name(part, origin), steps=[dict(name=n, status='completed', conclusion='success')
        for n in (*P.cuts(part, origin), *P.EXTRA_STEPS.get(part, ()),
                  'Verify and freeze completed part originals', 'Upload immutable completed part')])
    artifact['name'] = P.artifact_name(part, origin)
    return manifest, run, job, artifact


def inventory_fixture():
    S = U.S
    names = {'app/Contents/Helpers/MobileReleaseKitLauncher.app/Contents/' + n for n in
             ('MacOS/mrk-macos-launcher', 'Info.plist', 'Resources/icon.png', '_CodeSignature/CodeResources')}
    names |= {'app/' + n for n in (S.LAUNCHER_TICKET, S.ENTRY_BINARY, S.APP_BINARY,
                                  S.DESKTOP_IMAGE, S.RESIDENT_IMAGE, 'Contents/MacOS/mrk', S.VAULT_HELPER,
                                  S.REMOVER, S.ANDROID_HELPER, S.ANDROID_SERVICE_PLIST)}
    return dict(files=[dict(path=n, size=32, sha256='1'*64,
                           executable=n == 'app/' + S.LAUNCHER_EXECUTABLE) for n in sorted(names)])


class OrdinaryDesktopUpdateTests(unittest.TestCase):
    def test_maintenance_payload_floor_keeps_each_generation_bounded(self):
        inventories = [dict(files=[dict(size=n)]) for n in (283_826_469,331_920_402)]
        proof = U.maintenance_payload_floor_data(inventories)
        self.assertEqual(proof['payloadBytesLowerBound'],615_746_871)
        self.assertFalse(proof['fullNativeBudgetAdmitted'])
        self.assertFalse(proof['metadataAndLauncherCopiesIncluded'])
        maximum = [dict(files=[dict(size=U.S.MAX_BYTES)])] * U.MAINTENANCE_GENERATION_LIMIT
        self.assertEqual(U.maintenance_payload_floor_data(maximum)['payloadBytesLowerBound'],
                         U.MAINTENANCE_GENERATION_LIMIT * U.S.MAX_BYTES)
        for inventories in ([], maximum+[maximum[0]], [dict(files=[])],
                            [dict(files=[dict(size=True)])], [dict(files=[dict(size=-1)])],
                            [dict(files=[dict(size=U.S.MAX_BYTES+1)])],
                            [dict(files=[dict(size=U.S.MAX_BYTES),dict(size=1)])]):
            with self.subTest(inventories=repr(inventories)[:100]), self.assertRaises(U.S.Refused):
                U.maintenance_payload_floor_data(inventories)
        root=Path(__file__).resolve().parents[2]/'desktop/src-tauri/src'
        maintenance=(root/'macos_install_maintenance.rs').read_text()
        self.assertIn('pub const PREDECESSOR_LIMIT: usize = '+str(U.MAINTENANCE_GENERATION_LIMIT-1)+';',maintenance)
        record=(root/'macos_install_record.rs').read_text()
        self.assertIn('pub const PAYLOAD_LIMIT: u64 = 512 * 1024 * 1024;',record)
        self.assertIn('pub const CONTROL_LIMIT: usize = 128 * 1024 * 1024;',record)
        transaction=(root/'macos_install_transaction.rs').read_text()
        self.assertIn('(PREDECESSOR_LIMIT as u64 + 1) * PAYLOAD_LIMIT + CONTROL_LIMIT as u64;',transaction)

    def test_scripts_package_exports_the_recipe_component_for_the_final_product(self):
        recipe = yaml('.github/actions/macos-candidate-recipes/'
                      'build-the-fixed-one-shot-root-installer-and-scripts-/action.yml')
        command = recipe['runs']['steps'][0]['run']
        # Exercise the source recipe's closed role selection, without pkgbuild,
        # signing, credentials, or native installation.
        selection = command[command.index('case "${MRK_MACOS_PACKAGE_ROLE-}" in'):
                            command.index('/bin/mkdir -m 700 "$package_output"')]
        import subprocess
        for ordinary in (True, False):
            manifest = ordinary_fixture('scripts-package')[0] if ordinary else native_fixture('scripts-package')[0]
            origin = manifest['origin']
            role = 'ordinary-image' if ordinary else 'installed-shell-observation'
            output = 'package-component' if ordinary else 'package-unsigned'
            other = 'package-unsigned' if ordinary else 'package-component'
            with self.subTest(role=role), tempfile.TemporaryDirectory(
                    dir=Path(os.environ['MRK_PART_TEST_ROOT']).resolve(strict=True)) as temporary:
                root = Path(temporary)
                work = root / manifest['workName']; work.mkdir(mode=0o700)
                workspace = root / 'source'; workspace.mkdir(mode=0o700)
                selected = subprocess.run(['/bin/bash', '-c', selection + 'printf "%s" "$package_output"'],
                    env=dict(PATH='/usr/bin:/bin', MRK_MACOS_WORK=str(work), MRK_MACOS_PACKAGE_ROLE=role),
                    check=True, capture_output=True, timeout=5)
                self.assertEqual(selected.stdout, str(work / output).encode())
                self.assertEqual(selected.stderr, b'')
                expected = tuple('work/' + output if n == 'work/package-unsigned' else n
                                 for n in T.ROSTER['scripts-package'])
                # The real held-file/roster/archive/project readers execute.
                # Only the attribute port is inert DATA, never qualification.
                with patch.object(T.S, 'no_xattrs', return_value=None):
                    for name in expected:
                        path = T.destination(name, work, workspace)
                        if name in ('work/scripts', 'work/package-parts', 'work/' + output):
                            path.mkdir(mode=0o700)
                            T.write(path / ('MobileReleaseKit.pkg' if name == 'work/' + output else 'inert'), b'inert\n')
                        else:
                            T.write(path, b'inert\n')
                    files, directories = T.selected_files('scripts-package', work, workspace, origin)
                    self.assertIn('work/' + output + '/MobileReleaseKit.pkg', files)
                    self.assertNotIn('work/' + other, directories)
                    self.assertFalse(T.permitted('scripts-package', 'work/' + other + '/MobileReleaseKit.pkg', origin=origin))
                    manifest['members'] = [files[n] for n in sorted(files)]
                    manifest['directories'] = [dict(path=n, mode=m) for n, m in sorted(directories.items())]
                    archive = root / 'scripts-part.zip'
                    T.encode_archive(archive, manifest, files, work, workspace)
                    self.assertEqual(T.archive_manifest(archive), manifest)
                    fresh = root / 'fresh'; fresh.mkdir(mode=0o700)
                    T.project_archive(archive, manifest, fresh, workspace, {n: 'scripts-package' for n in files})
                    self.assertEqual(T.read(fresh / output / 'MobileReleaseKit.pkg', 16), b'inert\n')
                    self.assertEqual(T.selected_files('scripts-package', fresh, workspace, origin), (files, directories))
                    (fresh / output / 'MobileReleaseKit.pkg').unlink()
                    (fresh / output).rmdir()
                    with self.assertRaises(FileNotFoundError):
                        T.selected_files('scripts-package', fresh, workspace, origin)

    def test_actual_desktop_size_traverses_original_signer_and_retains_strict_refusals(self):
        # The pre-compilation DATA job must exercise the actual fixed signer,
        # not merely verify that the ordinary inventory contains the dylib.
        # All credential/signature returns are inert fixtures, never native.
        from tests.desktop.test_macos_installed_staging import MacAndroidHelperPackagingData, TOOL
        # The attribute port, like the credential/native-return ports, is
        # inert DATA here. This is size/signing custody coverage, never proof
        # that a local checkout or package passes the actual attribute gate.
        # GitHub's default macOS temp path traverses /var -> /private/var.
        # The production held-directory reader must keep refusing symlinks.
        # Place only these inert fixtures in the caller's real owned directory.
        fixture_root = Path(os.environ['MRK_PART_TEST_ROOT']).resolve(strict=True)
        with patch.object(tempfile, 'tempdir', str(fixture_root)), \
                patch.object(TOOL, 'no_xattrs', return_value=None):
            MacAndroidHelperPackagingData().test_fixed_workflow_signing_roles_use_original_inputs_and_identity()

    def test_signer_fixture_resolves_owned_temp_alias_and_restores_default(self):
        with tempfile.TemporaryDirectory(dir=os.environ['MRK_PART_TEST_ROOT']) as temporary:
            root = Path(temporary)
            real = root / 'real'; real.mkdir()
            alias = root / 'alias'; alias.symlink_to(real, target_is_directory=True)
            with patch.dict(os.environ, {'MRK_PART_TEST_ROOT': str(alias)}), \
                    patch.object(tempfile, 'tempdir', str(alias)):
                self.test_actual_desktop_size_traverses_original_signer_and_retains_strict_refusals()
                self.assertEqual(tempfile.tempdir, str(alias))

    def test_current_launcher_versions_match_real_application_and_package(self):
        # Run 41291931705 refused assembly before Swift compilation because
        # the launcher still said 0.1.2 while the application/package was 0.1.3.
        # This module is also run by the original DATA job before native builds.
        root = Path(__file__).resolve().parents[2]
        desktop = root / 'desktop'
        application = json.loads((desktop / 'src-tauri/tauri.conf.json').read_bytes())['version']
        package = json.loads((desktop / 'macos-installed-inputs/build-release.json').read_bytes())['packageVersion']
        launcher = plistlib.loads((desktop / 'native/macos-applications-launcher/Info.plist').read_bytes())
        self.assertEqual(application, package)
        for key in ('CFBundleShortVersionString', 'CFBundleVersion'):
            with self.subTest(key=key):
                self.assertEqual(launcher[key], application)

    def test_matrix_job_names_match_strict_current_job_selector(self):
        # Actual run 41291021077/job 124802333160 added this suffix to the
        # original static name. Keep the selector strict; name jobs explicitly.
        observed = ('Desktop update / macOS part (Desktop26 / prepare) '
                    '(disabled, aarch64-apple-darwin, macos-26, arm64, github-hosted-...')
        workflow = yaml('.github/workflows/desktop-macos-update-parts.yml')['jobs']
        for part in P.ORDINARY_PARTS:
            origin = ordinary_fixture(part)[0]['origin']
            job = workflow['desktop26-' + part]
            expression = re.fullmatch(
                r"\$\{\{ matrix\.native_scope == 'disabled' && '([^']+)' "
                r"\|\| 'Invalid Desktop update scope' \}\}", job['name'])
            self.assertIsNotNone(expression, 'a static matrix name acquires a GitHub suffix')
            self.assertEqual(P.ORDINARY_CALLER + ' / ' + expression[1], P.job_name(part, origin))
            correct = dict(id=123, name=P.job_name(part, origin), status='in_progress',
                           head_sha=origin['source'])
            env = dict(GITHUB_SHA=origin['source'], GITHUB_RUN_ID=origin['runId'],
                       GITHUB_RUN_ATTEMPT=origin['runAttempt'], MRK_MACOS_NATIVE_SCOPE='disabled',
                       MRK_MACOS_RUNNER='macos-26')
            with patch.dict(os.environ, env), patch.object(T, 'read', return_value=json.dumps(
                    dict(tree=origin['tree'])).encode()):
                with patch.object(T, 'listing', return_value=[correct]):
                    self.assertEqual(T.current(part, Path('/inert')), dict(origin, jobId='123'))
                for rows in ([dict(correct, name=observed)], [correct, correct],
                             [dict(correct, head_sha='f'*40)], [dict(correct, status='completed')]):
                    with patch.object(T, 'listing', return_value=rows), self.assertRaisesRegex(
                            ValueError, 'part-current-actual-job'):
                        T.current(part, Path('/inert'))
        self.assertIn("matrix.native_scope == 'disabled'", workflow['desktop26-carrier']['name'])

    def test_complete_update_requires_five_launcher_components_and_real_desktop(self):
        value = inventory_fixture()
        result = U.contents_data(value, 'ordinary-image')
        self.assertEqual(result['launcherComponents'], 5)
        self.assertFalse(result['installed'] or result['productReady'])
        for i in range(len(value['files'])):
            bad = copy.deepcopy(value); bad['files'].pop(i)
            with self.subTest(missing=value['files'][i]['path']), self.assertRaises(U.S.Refused):
                U.contents_data(bad, 'ordinary-image')
        for role in ('installed-shell-observation', 'tool-setup', 'git-native', None):
            with self.assertRaises(U.S.Refused): U.contents_data(value, role)
        for name in ('unexpected', 'Contents/Extra'):
            bad = copy.deepcopy(value)
            bad['files'].append(dict(path='app/'+U.S.LAUNCHER_BUNDLE+'/'+name,size=1,sha256='1'*64,executable=False))
            with self.assertRaises(U.S.Refused): U.contents_data(bad, 'ordinary-image')

    def test_launcher_metadata_duplicates_and_wrong_executable_are_rejected(self):
        value = inventory_fixture()
        for change in ('duplicate', 'boolean-size', 'wrong-mode', 'invalid-digest'):
            bad = copy.deepcopy(value)
            leaf = next(r for r in bad['files'] if r['path'] == 'app/'+U.S.LAUNCHER_EXECUTABLE)
            if change == 'duplicate': bad['files'].append(dict(leaf))
            if change == 'boolean-size': leaf['size'] = True
            if change == 'wrong-mode': leaf['executable'] = False
            if change == 'invalid-digest': leaf['sha256'] = '0'*64
            with self.subTest(change=change), self.assertRaises(U.S.Refused): U.contents_data(bad, 'ordinary-image')

    def test_ordinary_parts_admit_exact_completed_jobs_and_keep_observers_separate(self):
        for part in P.ORDINARY_PARTS:
            m, r, j, a = ordinary_fixture(part)
            self.assertEqual(P.metadata_data(r, j, a, m)['origin'], m['origin'])
            for bad_name in ('macOS part (Desktop26 / '+part+')', 'Build signed candidate (Tool26)'):
                bad = dict(j, name=bad_name)
                with self.assertRaises(ValueError): P.metadata_data(r, bad, a, m)
        m, _, _, _ = ordinary_fixture()
        with self.assertRaises(ValueError): P.artifact_name('observer', m['origin'])
        n, _, _, _ = native_fixture()
        with self.assertRaises(ValueError): P.artifact_name('image', n['origin'])
        bad = dict(m['origin'], hostProfile='xcode-27')
        with self.assertRaises(ValueError): P.origin_data(bad)

    def test_failed_ordinary_signing_does_not_recompile_the_desktop(self):
        states = dict.fromkeys(P.ORDINARY_PARTS, 'success')
        for n in ('assemble', 'notarize-payload', 'installer', 'scripts-package', 'final-package'): states[n] = 'skipped'
        states['sign-cli'] = 'failure'
        self.assertEqual(P.ready_parts(states), ('sign-cli',))
        states['sign-cli'] = 'running'; self.assertEqual(P.ready_parts(states), ())
        states['sign-cli'] = 'success'; self.assertEqual(P.ready_parts(states), ('assemble',))
        self.assertEqual(states['image'], 'success')

    def test_prepared_ordinary_split_requires_actual_original_image_job(self):
        values, manifest, service, consumer = prepared_fixture()
        m, run, job, artifact = ordinary_fixture()
        service['job'].update(name=B.ORDINARY_SPLIT_JOB, labels=['macos-26'], steps=[
            dict(name=n, number=i+1, status='completed', conclusion='success') for i,n in enumerate(B.ORDINARY_SPLIT_STEPS)])
        with self.assertRaises(ValueError): B.admit_data(values, service, consumer)
        service['compiledImage'] = dict(run=run, job=job, artifact=artifact)
        self.assertIsNotNone(B.admit_data(values, service, consumer))
        for k,v in (('labels',['xcode-27']),('conclusion','failure'),('name','macOS part (Desktop26 / image)')):
            bad = copy.deepcopy(service); bad['compiledImage']['job'][k] = v
            with self.assertRaises(ValueError): B.admit_data(values, bad, consumer)
        bad = copy.deepcopy(service); bad['compiledImage']['artifact']['digest'] = 'bad'
        with self.assertRaises(ValueError): B.admit_data(values, bad, consumer)
        # The exact original attempt has an artifact; a copied rerun does not.
        jobs = dict(jobs=[job, dict(job, id=88, run_attempt=2)], total_count=2)
        selected = B.selected_compiled_image_data(B.canonical(dict(artifacts=[artifact],total_count=1)),
            B.canonical(jobs), B.canonical(run), manifest['origin'])
        self.assertEqual(selected['job']['id'],job['id'])

    def test_ordinary_carrier_cannot_accept_tool_observer_role_or_missing_original_return(self):
        values, consumer, _, _ = prepared_tests.PreparedPackageData().local_carrier_fixture()
        with self.assertRaises(ValueError): B.ordinary_local_carrier_transport_data(values, consumer)
        manifest = B.decode(values['prepared-input/PREPARED.json'], B.MANIFEST_LIMIT)
        manifest.update(schemaVersion=1,packageRole='ordinary-image',normalBuild=dict(
            appBinarySha256BeforeSigning='a'*64,desktopImageSha256BeforeSigning='b'*64))
        manifest.pop('observerBuild');manifest['origin'].pop('nativeScope');manifest['origin'].pop('hostProfile')
        consumer.pop('nativeScope');consumer.pop('hostProfile')
        values['prepared-input/PREPARED.json'] = B.canonical(manifest)
        receipt = B.decode(values['android-helper-package-install.json'],4*B.MIB)
        receipt['packageRole']='ordinary-image';values['android-helper-package-install.json']=B.canonical(receipt)
        self.assertFalse(B.ordinary_local_carrier_transport_data(values,consumer)['localInstallationQualified'])
        with self.assertRaises(ValueError): B.local_carrier_transport_data(values,consumer)
        values['package-install.status']=b'1\n'
        with self.assertRaises(ValueError): B.ordinary_local_carrier_transport_data(values,consumer)

    def test_workflow_runs_only_ordinary_stages_and_carrier_never_runs_git_cases(self):
        parent = yaml(P.WORKFLOW)['jobs']
        self.assertIn('[macos-desktop-update]',parent['candidate-desktop-update']['if'])
        self.assertIn('[macos-builds-only]',parent['candidate-desktop-update']['if'])
        workflow = yaml('.github/workflows/desktop-macos-update-parts.yml')['jobs']
        origin = ordinary_fixture()[0]['origin']
        for part in P.ORDINARY_PARTS:
            j = workflow['desktop26-'+part]
            self.assertEqual(j['strategy']['matrix']['include'][0]['native_scope'],'disabled')
            self.assertEqual(j['env']['MRK_MACOS_PACKAGE_ROLE'],'ordinary-image')
            self.assertIn('[macos-desktop-update]',j['if'])
            self.assertEqual(j.get('needs',[]),['desktop26-'+n for n in P.ancestors(part,origin)])
            names = [s['name'] for s in j['steps']]
            for name in P.cuts(part,origin):self.assertIn(name,names)
            for s in j['steps']:
                if s.get('uses','').startswith('./.github/actions/macos-candidate-recipes/'):
                    action = yaml(s['uses'][2:]+'/action.yml')
                    self.assertEqual(set(s.get('with',{})),set(action.get('inputs',{})))
            for scope,(profile,_) in P.PROFILES.items():
                self.assertIn("!contains(github.event.head_commit.message, '[macos-desktop-update]')",
                              parent['candidate-'+profile.lower()+'-'+('observer' if part=='image' else part)]['if'])
        carrier = workflow['desktop26-carrier']
        self.assertIn('local-desktop-carrier',carrier['if'])
        self.assertEqual(carrier['env']['MRK_MACOS_PACKAGE_ROLE'],'ordinary-image')
        body=json.dumps(carrier['steps'])
        self.assertNotIn('GitCli',body)
        self.assertNotIn('macos_installed_app_build.sh',body)
        self.assertNotIn('tool_service',body)
        self.assertIn('image-attempt',body)


class OrdinaryImageTransportDataTests(unittest.TestCase):
    def test_signed_desktop_and_launcher_bindings_survive_archive_and_fresh_projection(self):
        with tempfile.TemporaryDirectory(dir=os.environ['MRK_PART_TEST_ROOT']) as temporary:
            root=Path(temporary);work=root/'mrk-macos-installed.ABC123de';work.mkdir(mode=0o700)
            workspace=root/'source';workspace.mkdir(mode=0o700)
            m=ordinary_fixture('assemble')[0];origin=m['origin']
            bindings={'MRK_MACOS_SIGNED_ENTRY_SHA256':(T.S.ENTRY_BINARY,'sign-root-app'),
                      'MRK_MACOS_SIGNED_PAYLOAD_SHA256':(T.S.APP_BINARY,'sign-desktop-payload'),
                      'MRK_MACOS_SIGNED_DESKTOP_IMAGE_SHA256':(T.S.DESKTOP_IMAGE,'sign-desktop-image'),
                      'MRK_MACOS_APPLICATIONS_LAUNCHER_SHA256':(T.S.LAUNCHER_EXECUTABLE,'sign-applications-launcher')}
            bodies={leaf:('inert '+leaf+'\n').encode() for leaf,_ in bindings.values()}
            with patch.object(T.S,'no_xattrs',return_value=None):
                (work/'app').mkdir(mode=0o700)
                T.S.write_tree(work/'app'/T.S.APP_NAME,{n:(b,0o555 if n==T.S.LAUNCHER_EXECUTABLE else 0o755) for n,b in bodies.items()},
                               root_mode=0o755,app_signing=True)
                T.write(work/'app-result.json',b'{}\n')
                for phase in (*T.RECEIPTS['assemble'],'sign-applications-launcher','sign-desktop-image'):
                    row=dict(phase=phase,source=origin['source'],workflowSource=origin['source'],
                             runId=origin['runId'],runAttempt=origin['runAttempt'],target=P.TARGET,
                             passed=True,targetRetired=True,originalClosesKnown=True)
                    leaf=next((n for n,p in bindings.values() if p==phase),None)
                    if leaf is not None:row['signedBytesSha256']=P.sha(bodies[leaf])
                    T.write(work/('android-helper-'+phase+'.json'),P.canonical(row),0o444)
                expected={v:P.sha(bodies[n]) for v,(n,_) in bindings.items()}
                self.assertEqual(T.signed_app_bindings(work,origin),expected)
                files,dirs=T.selected_files('assemble',work,workspace,origin)
                m['members']=[files[n] for n in sorted(files)];m['directories']=[dict(path=n,mode=d) for n,d in sorted(dirs.items())]
                archive=root/'signed-ordinary.zip';T.encode_archive(archive,m,files,work,workspace)
                self.assertEqual(T.archive_manifest(archive),m)
                fresh=root/'fresh';fresh.mkdir(mode=0o700)
                T.project_archive(archive,m,fresh,workspace,{n:'assemble' for n in files})
                self.assertEqual(T.signed_app_bindings(fresh,origin),expected)
                target=fresh/'app'/T.S.APP_NAME/T.S.DESKTOP_IMAGE
                target.write_bytes(b'tampered DATA\n')
                with self.assertRaises(ValueError):T.signed_app_bindings(fresh,origin)

    def test_image_transport_keeps_only_exact_original_cdylib_and_known_cargo_alias(self):
        with tempfile.TemporaryDirectory(dir=os.environ['MRK_PART_TEST_ROOT']) as temporary:
            root=Path(temporary);work=root/'mrk-macos-installed.ABC123de';work.mkdir(mode=0o700)
            workspace=root/'source';workspace.mkdir(mode=0o700)
            image=work/'cargo-target'/P.TARGET/'release/libmrk_desktop_image.dylib'
            image.parent.mkdir(mode=0o700,parents=True)
            image.write_bytes(b'inert cdylib DATA\n');image.chmod(0o755)
            deps=image.parent/'deps';deps.mkdir(mode=0o700);os.link(image,deps/image.name)
            (work/'normal-build.jsonl').write_bytes(b'{"reason":"build-finished","success":true}\n')
            (work/'normal-build.status').write_bytes(b'0\n')
            origin=ordinary_fixture()[0]['origin']
            # Inert attribute port: no Mach-O, signature or native transport qualification.
            with patch.object(T.S,'no_xattrs',return_value=None):
                files,dirs=T.selected_files('image',work,workspace,origin)
                self.assertEqual(set(files),set(T.ROSTER['image']))
                m=ordinary_fixture()[0];m['members']=[files[n] for n in sorted(files)];m['directories']=[]
                path=root/'image.zip';T.encode_archive(path,m,files,work,workspace)
                self.assertEqual(T.archive_manifest(path),m)
                (deps/image.name).unlink();os.link(image,root/'foreign-alias')
                with self.assertRaises(ValueError):T.selected_files('image',work,workspace,origin)
            self.assertFalse(T.permitted('image','work/cargo-target/'+P.TARGET+'/release/foreign.dylib',origin=origin))


if __name__ == '__main__':
    unittest.main()
