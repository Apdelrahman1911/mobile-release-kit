"""SOURCE selection/one-pass composition DATA; no native or network execution."""
import copy
import contextlib
import io
import json
from pathlib import Path
import shutil
import tarfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_macos_launcher_staging import TOOL
from test_macos_store_composition import fixture, args


def selection():
    return {'schemaVersion': 1, 'state': 'configured', 'source': 'a' * 40,
            'runId': '11', 'runAttempt': '2', 'artifacts': {TOOL.ARM_TARGET: '31', TOOL.INTEL_TARGET: '32'}}


def python_selection():
    return {'state': 'configured', 'signingSourceCommit': 'b' * 40, 'signingRunId': '12',
            'signingRunAttempt': '1', 'signingArtifactId': '33',
            **{key: str(i) * 64 for i, key in enumerate(('signedPythonSha256', 'signingReceiptSha256',
                'producerProfileSha256', 'serviceProfileSha256', 'sourceInputsSha256', 'runtimeManifestSha256'), 1)}}


def binding():
    python = python_selection()
    store = TOOL.signed_store_selection_data(TOOL.canonical(selection()))
    value = {'schemaVersion': 1, 'kind': 'current-signed-store-runtime', 'target': TOOL.ARM_TARGET,
             'sourceInputsSha256': '7' * 64, 'runtimeManifestSha256': '8' * 64,
             'python': {k: v for k, v in python.items() if k not in ('state', 'sourceInputsSha256', 'runtimeManifestSha256')},
             'store': {**store, 'receiptSha256': '9' * 64, 'archiveSha256': 'a' * 64, 'artifactDigest': 'sha256:' + 'b' * 64}}
    return python, store, value


class StoreConsumerData(unittest.TestCase):
    def test_preparation_diagnostic_preserves_failure_without_private_details(self):
        secret = 'private-input-must-not-be-logged'
        try:
            TOOL.need(False, secret)
        except TOOL.Refused as error:
            original = error
        for command in ('compose-store-runtime', 'app'):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                TOOL.runtime_refusal_annotation(command, original)
            self.assertRegex(stderr.getvalue(), r'^MRK_RUNTIME_PREPARATION_REFUSED=refused;sites=stager:[0-9]+\n$')
            self.assertNotIn(secret, stderr.getvalue())
            self.assertNotIn(str(TOOL.DESKTOP), stderr.getvalue())
        # Foreign stack filenames, exception chains and arbitrary class names
        # are not diagnostics. Only literal known kinds and own code sites are.
        class PrivateNamedError(Exception):
            pass
        try:
            exec(compile('raise failure', '/private/' + secret, 'exec'),
                 {'failure': PrivateNamedError(secret)})
        except PrivateNamedError as foreign:
            foreign.__cause__ = original
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                TOOL.runtime_refusal_annotation('compose-store-runtime', foreign)
            self.assertEqual(stderr.getvalue(), 'MRK_RUNTIME_PREPARATION_REFUSED=unknown;sites=unavailable\n')
        # Real parser/handler retains the exact refusal even if stderr fails.
        for fail_sink in (False, True):
            sink = mock.Mock()
            if fail_sink:
                sink.write.side_effect = OSError(secret)
            with (mock.patch.object(TOOL, 'finalize_runtime_binding_command', side_effect=original),
                  mock.patch.object(TOOL.os, 'getuid', return_value=501),
                  mock.patch.object(TOOL.os, 'geteuid', return_value=501),
                  mock.patch.object(TOOL.sys, 'stderr', sink), self.assertRaises(TOOL.Refused) as caught):
                TOOL.main(['finalize-runtime-binding', '--target', TOOL.ARM_TARGET, '--work-root', '/inert'])
            self.assertIs(caught.exception, original)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            TOOL.runtime_refusal_annotation('preview', original)
        self.assertEqual(stderr.getvalue(), '')

    def test_source_selection_is_closed_per_arch_and_never_falls_back(self):
        original = selection()
        self.assertEqual(TOOL.signed_store_selection_data(TOOL.canonical(original))['artifactId'], '31')
        self.assertEqual(TOOL.signed_store_selection_data(TOOL.canonical(original), target=TOOL.INTEL_TARGET)['artifactId'], '32')
        for bad in ({'schemaVersion': 1, 'state': 'unconfigured'}, {}, {**original, 'runAttempt': 2},
                    {**original, 'source': '0' * 40}, {**original, 'artifacts': {TOOL.ARM_TARGET: '31', TOOL.INTEL_TARGET: '31'}},
                    {**original, 'latest': True}):
            with self.subTest(bad=bad), self.assertRaises(TOOL.Refused):
                TOOL.signed_store_selection_data(TOOL.canonical(bad))
        with self.assertRaises(TOOL.Refused):
            TOOL.signed_store_selection_data(b'{"schemaVersion":1,"schemaVersion":1,"state":"unconfigured"}')

    def test_computed_binding_preserves_capsule_and_selected_store_not_legacy_manifest(self):
        python, store, value = binding()
        selected, actual = TOOL.composed_runtime_binding_data(TOOL.canonical(value), python, store)
        self.assertEqual(selected['signedPythonSha256'], python['signedPythonSha256'])
        self.assertEqual(selected['runtimeManifestSha256'], '8' * 64)
        self.assertNotEqual(selected['runtimeManifestSha256'], python['runtimeManifestSha256'])
        for section, key, replacement in (('python', 'signingRunId', '14'), ('store', 'runAttempt', '3'),
                ('store', 'artifactId', '32'), ('store', 'archiveSha256', '0' * 64),
                ('store', 'selectionSha256', 'c' * 64)):
            bad = copy.deepcopy(value); bad[section][key] = replacement
            with self.subTest(key=key), self.assertRaises(TOOL.Refused):
                TOOL.composed_runtime_binding_data(TOOL.canonical(bad), python, store)
        with self.assertRaises(TOOL.Refused):
            TOOL.composed_runtime_binding_data(TOOL.canonical(value), python, store, target=TOOL.INTEL_TARGET)

    def test_notary_requires_exact_same_invocation_computed_source_and_manifest(self):
        _python, _store, composed = binding()
        body = TOOL.canonical(composed)
        environment = {'GITHUB_SHA': 'c' * 40, 'GITHUB_WORKFLOW_SHA': 'c' * 40,
            'GITHUB_RUN_ID': '41', 'GITHUB_RUN_ATTEMPT': '1',
            'MRK_MACOS_RUNTIME_BINDING_SHA256': TOOL.digest(body),
            'MRK_BUNDLED_RUNTIME_MANIFEST_SHA256': composed['runtimeManifestSha256'],
            'MRK_BUNDLED_RUNTIME_SOURCE_SHA256': composed['sourceInputsSha256']}
        source = {'runtimeBindingSha256': TOOL.digest(body), 'target': TOOL.ARM_TARGET,
            'runtimeManifestSha256': composed['runtimeManifestSha256'],
            'runtimeSourceInputsSha256': composed['sourceInputsSha256'], 'signedStoreDerivation': composed['store'],
            'workDirectory': [1, 2, 1000], 'source': 'c' * 40, 'workflowSource': 'c' * 40, 'runId': '41', 'runAttempt': '1'}
        self.assertEqual(TOOL.composed_source_binding_data(TOOL.canonical(source), body, composed, environment, (1, 2, 1000)), source)
        for key, changed in (('runAttempt', '2'), ('source', 'd' * 40), ('workDirectory', [1, 3, 1000]),
                             ('runtimeManifestSha256', '1' * 64), ('runtimeBindingSha256', '2' * 64)):
            with self.subTest(key=key), self.assertRaises(TOOL.Refused):
                TOOL.composed_source_binding_data(TOOL.canonical({**source, key: changed}), body, composed, environment, (1, 2, 1000))
        with self.assertRaises(TOOL.Refused):
            TOOL.composed_source_binding_data(TOOL.canonical(source), body, composed,
                {**environment, 'MRK_BUNDLED_RUNTIME_MANIFEST_SHA256': '6' * 64}, (1, 2, 1000))

    def test_configured_compose_requires_original_python_pins_but_no_cli_manifest(self):
        chosen = python_selection()
        namespace = SimpleNamespace(command='compose-store-runtime', python_root=Path('/supplier'), signed_python=Path('/signed/python'),
            signing_receipt=Path('/signed/receipt'), expected_signed_python=chosen['signedPythonSha256'],
            expected_signing_receipt=chosen['signingReceiptSha256'], expected_signing_source=chosen['signingSourceCommit'],
            expected_signing_run=chosen['signingRunId'], expected_signing_attempt=chosen['signingRunAttempt'],
            expected_supplier=TOOL.SIGNED_ORIGINAL_SUPPLIERS[TOOL.ARM_TARGET]['receiptSha256'])
        with mock.patch.object(TOOL, 'signed_runtime_inputs', return_value=(chosen, ())):
            self.assertEqual(TOOL.configured_current_binding(namespace, TOOL.ARM_TARGET), (chosen, ()))
            namespace.command = 'current-runtime'
            with self.assertRaises(TOOL.Refused): TOOL.configured_current_binding(namespace, TOOL.ARM_TARGET)
            namespace.command = 'compose-store-runtime'; namespace.expected_signing_run = '99'
            with self.assertRaises(TOOL.Refused): TOOL.configured_current_binding(namespace, TOOL.ARM_TARGET)


class StoreConsumerFilesystem(unittest.TestCase):
    def test_one_composition_latches_new_manifest_and_refuses_republication(self):
        for target in TOOL.MAC_TARGETS:
            with self.subTest(target=target):
                self.check_composition(target)

    def check_composition(self, target):
        # Fresh supplier/capsule/service authentication boundaries are inert;
        # real CLI, provider custody, preparation, TAR correspondence and latching run.
        from test_macos_installed_staging import history_provider_macho_fixture
        with fixture(target=target) as f:
            chosen = python_selection()
            chosen['signedPythonSha256'] = TOOL.digest(f.supplier['python/bin/python3'][0])
            selected = TOOL.signed_store_selection_data(TOOL.canonical(selection()), target=target)
            source_snapshot = (TOOL.canonical(selection()), ('inert-source-original',))
            python_snapshot = ((b'inert Python SOURCE nomination',),)
            provider_body = history_provider_macho_fixture(target=target)
            provider = f.root / 'gh'; provider.write_bytes(provider_body); provider.chmod(0o555)
            profile = {'schemaVersion': 1, 'version': TOOL.HISTORY_PROVIDER_VERSION,
                'sourceManifestSha256': '1' * 64,
                'targets': {name: TOOL.digest(history_provider_macho_fixture(target=name)) for name in TOOL.MAC_TARGETS}}
            (f.checkout / TOOL.HISTORY_PROVIDER_PROFILE).write_bytes(TOOL.canonical(profile))
            root = f.root / 'signed-store-component'; root.mkdir(mode=0o700)
            runtime = root / 'extracted/runtime'
            shutil.copytree(f.component, runtime)
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w:gz') as contents:
                for path in sorted(runtime.rglob('*')):
                    if path.is_file():
                        data = path.read_bytes(); row = tarfile.TarInfo('runtime/' + path.relative_to(runtime).as_posix())
                        row.size = len(data); row.mode = path.stat().st_mode & 0o777
                        contents.addfile(row, io.BytesIO(data))
            archive_body = archive.getvalue()
            receipt = {'kind': 'macos-store-signed-v1', 'target': target,
                **{key: selected[key] for key in ('source', 'runId', 'runAttempt')},
                'signedArchiveSha256': TOOL.digest(archive_body), 'signedArchiveBytes': len(archive_body),
                **{key: True for key in ('originalsClosed', 'sourcePost', 'inputPost', 'nonNativeUnchanged')}}
            receipt_body = TOOL.canonical(receipt)
            origin = {'schema': 1, 'source': selected['source'], 'target': target,
                **{key: int(selected[key]) for key in ('runId', 'runAttempt', 'artifactId')},
                'receiptSha256': TOOL.digest(receipt_body), 'archiveSha256': TOOL.digest(archive_body),
                'artifactDigest': 'sha256:' + 'c' * 64}
            (root / 'signed-origin.json').write_bytes(TOOL.canonical(origin))
            (root / 'store-signed-receipt.json').write_bytes(receipt_body)
            (root / 'store-signed.tar.gz').write_bytes(archive_body)
            a = args(f, 'compose'); a.command = 'compose-store-runtime'; a.store_component = None
            a.target = target; a.history_provider = provider
            a.signed_store_root = root; a.binding_output = f.root / 'runtime-binding.json'
            a.expected_source = a.expected_manifest = None
            a.output = f.root / 'runtime'
            a.signed_python = f.python_root / 'python3'; a.signing_receipt = f.receipt
            for option, key in (('expected_signed_python', 'signedPythonSha256'), ('expected_signing_receipt', 'signingReceiptSha256'),
                    ('expected_signing_source', 'signingSourceCommit'), ('expected_signing_run', 'signingRunId'), ('expected_signing_attempt', 'signingRunAttempt')):
                setattr(a, option, chosen[key])
            a.expected_supplier = TOOL.SIGNED_ORIGINAL_SUPPLIERS[target]['receiptSha256']
            options = {name: value for name, value in vars(a).items() if name != 'command' and value is not None}
            def command_argv(command, options):
                return [command] + [part for name, value in options.items()
                                    for part in ('--' + name.replace('_', '-'), str(value))]
            fresh = (f.supplier, {'supplierOrigin': 'fresh-public-source'}, None, b'inert original receipt')
            with (mock.patch.object(TOOL, 'signed_runtime_inputs', return_value=(chosen, python_snapshot)),
                  mock.patch.object(TOOL, 'signed_store_selection', return_value=(selected, source_snapshot)),
                  mock.patch.object(TOOL, 'fresh_supplier', return_value=fresh) as supplier_reader,
                  mock.patch.object(TOOL, 'read_signed_python', return_value=((f.supplier['python/bin/python3'][0],), {}))):
                no_python = {name: value for name, value in options.items() if name not in TOOL.SIGNED_OPTIONS}
                missing_pin = {name: value for name, value in options.items() if name != 'expected_signing_receipt'}
                no_provider = {name: value for name, value in options.items() if name != 'history_provider'}
                unconfigured = {name: value for name, value in options.items()
                                if name not in ('signed_store_root', 'binding_output')}
                unconfigured.update(expected_source=chosen['sourceInputsSha256'],
                                    expected_manifest=chosen['runtimeManifestSha256'])
                cases = [('compose-store-runtime', no_python, 'configured-signing-required'),
                         ('compose-store-runtime', missing_pin, 'signed-python-options'),
                         ('compose-store-runtime', {**options, 'expected_signed_python': 'invalid'}, 'signed-python-options'),
                         ('compose-store-runtime', {**options, 'expected_signing_run': '99'}, 'configured-signing-source-arguments'),
                         ('compose-store-runtime', no_provider, 'history-provider-configured-input-required'),
                         ('current-runtime', unconfigured, 'history-provider-configured-final-required')]
                for command, rejected, reason in cases:
                    with self.subTest(command=command, reason=reason), self.assertRaisesRegex(TOOL.Refused, reason):
                        TOOL.main(command_argv(command, rejected))
                    self.assertFalse(a.work.exists())
                    self.assertFalse(a.output.exists())
                    self.assertFalse(a.binding_output.exists())
                    supplier_reader.assert_not_called()
                stdout = io.StringIO()
                with (contextlib.redirect_stdout(stdout),
                      mock.patch.object(TOOL, 'current_runtime_command', wraps=TOOL.current_runtime_command) as dispatch):
                    TOOL.main(command_argv('compose-store-runtime', options))
                dispatch.assert_called_once()
                a = dispatch.call_args.args[0]
                self.assertFalse(hasattr(a, 'configured_signing'))
                result = json.loads(stdout.getvalue())
                nomination, _snapshot = TOOL.history_provider_selection(a, 'fresh-public-source', target=target)
                self.assertEqual(nomination['sha256'], TOOL.digest(provider_body))
                self.assertEqual(result['historyProvider']['sha256'], nomination['sha256'])
                self.assertFalse(result['historyProvider']['nativeAuthority'])
                for supplied in (a, SimpleNamespace(**{**vars(a), 'history_provider': None})):
                    with self.assertRaisesRegex(TOOL.Refused, 'history-provider-fresh-only'):
                        TOOL.history_provider_selection(supplied, 'historical', target=target)
                output = TOOL.tree(a.output, current_root_mode=0o555, mac_store_prefix='store')
                self.assertEqual(output[TOOL.HISTORY_PROVIDER_PATH], (provider_body, 0o555))
                manifest = json.loads(output['manifest.json'][0])
                self.assertEqual(manifest['target'], target)
                self.assertEqual(next(row['sha256'] for row in manifest['files']
                                      if row['path'] == TOOL.HISTORY_PROVIDER_PATH), nomination['sha256'])
                self.assertEqual(result['qualification'], 'current-source-staged-no-native-execution')
                self.assertEqual(result['runtimeBindingSha256'], TOOL.digest(a.binding_output.read_bytes()))
                self.assertNotEqual(result['successorManifestSha256'], chosen['runtimeManifestSha256'])
                self.assertFalse((f.root / 'source-binding.json').exists())
                info = f.root.stat()
                admission = {'target': target, 'runtimeCompositionPending': True,
                    'workDirectory': [info.st_dev, info.st_ino, info.st_uid], 'signedPythonDerivation': {
                        'nominationSha256': TOOL.digest(python_snapshot[0][0]),
                        **{key: chosen[key] for key in ('signedPythonSha256', 'signingReceiptSha256', 'signingSourceCommit', 'producerProfileSha256', 'serviceProfileSha256')},
                        **{key: chosen[source] for key, source in (('runId', 'signingRunId'), ('runAttempt', 'signingRunAttempt'), ('artifactId', 'signingArtifactId'))}}}
                (f.root / 'source-admission.json').write_bytes(TOOL.canonical(admission))
                final = TOOL.finalize_runtime_binding_command(SimpleNamespace(target=target, work_root=f.root))
                self.assertEqual(final['runtimeManifestSha256'], result['successorManifestSha256'])
                source = json.loads((f.root / 'source-binding.json').read_bytes())
                self.assertEqual(source['runtimeBindingSha256'], result['runtimeBindingSha256'])
                self.assertEqual(source['signedStoreDerivation'], result['storeComponent'])
                with self.assertRaises(TOOL.Refused):
                    TOOL.finalize_runtime_binding_command(SimpleNamespace(target=target, work_root=f.root))
                (runtime / 'bin/ruby').chmod(0o600)
                (runtime / 'bin/ruby').write_bytes(b'not the authenticated archive')
                (runtime / 'bin/ruby').chmod(0o555)
                retry = copy.copy(a); retry.work = f.root / 'bad-work'; retry.output = f.root / 'bad-runtime'
                retry.binding_output = f.root / 'bad-binding.json'
                with self.assertRaisesRegex(TOOL.Refused, 'composed-store-archive-correspondence'):
                    TOOL.current_runtime_command(retry)
                self.assertFalse(retry.output.exists())


class StoreConsumerNotary(unittest.TestCase):
    def test_actual_notary_owner_admits_same_composition_and_refuses_foreign_binding(self):
        # Reuse the existing inert native/key boundary, not a mock Operation or
        # notary method. Source originals, full runtime parser/copies, POST,
        # original call records and credential-file retirement are real.
        import os
        import tempfile
        from test_macos_installed_staging import MacAndroidHelperPackagingData, TOOL as stager, ANDROID_HELPER as api
        from test_macos_store_staging import StoreStaging
        helper = MacAndroidHelperPackagingData()
        for failure in (None, 'invocation', 'selection', 'binding-digest'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='mrk-store-notary-data-') as temporary:
                state = helper.notary_fixture(Path(temporary))
                op = state.operation
                original_nomination = (op.checkout / 'desktop' / stager.SIGNED_RUNTIME_BINDING).read_bytes()
                legacy = json.loads(original_nomination)['targets'][stager.ARM_TARGET]
                # Populate a complete synthetic Store runtime; these Mach-O
                # bytes are never executed and are not cryptographic evidence.
                store_files = StoreStaging().fixture(stager.ARM_TARGET)
                from test_macos_store_paths import STORE_NAMES
                store_files.update({"store/" + name: (b"inert retained template/notice", 0o444) for name in STORE_NAMES})
                for name, (body, mode) in store_files.items():
                    path = op.work / 'runtime' / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body); path.chmod(mode)
                    state.runtime[name] = body
                manifest = json.loads(state.runtime['manifest.json'])
                rows = [{'path': name, 'size': len(body), 'sha256': stager.digest(body)}
                        for name, body in sorted(state.runtime.items()) if name != 'manifest.json']
                manifest.update(files=rows, inventorySha256=stager.digest(stager.canonical(rows)))
                manifest_body = stager.canonical(manifest) + b'\n'
                (op.work / 'runtime/manifest.json').chmod(0o600)
                (op.work / 'runtime/manifest.json').write_bytes(manifest_body)
                (op.work / 'runtime/manifest.json').chmod(0o444)
                state.runtime['manifest.json'] = manifest_body
                actual_m = stager.digest(manifest_body)
                self.assertNotEqual(actual_m, legacy['runtimeManifestSha256'])
                selected_store = stager.signed_store_selection_data(stager.canonical(selection()))
                composed = {'schemaVersion': 1, 'kind': 'current-signed-store-runtime', 'target': stager.ARM_TARGET,
                    'sourceInputsSha256': '7' * 64, 'runtimeManifestSha256': actual_m,
                    'python': {k: v for k, v in legacy.items() if k not in ('state', 'sourceInputsSha256', 'runtimeManifestSha256')},
                    'store': {**selected_store, 'archiveSha256': '8' * 64, 'receiptSha256': '9' * 64,
                              'artifactDigest': 'sha256:' + 'a' * 64}}
                composed_body = stager.canonical(composed) + b'\n'
                info = op.work.stat()
                source = {'runtimeBindingSha256': stager.digest(composed_body), 'target': stager.ARM_TARGET,
                    'runtimeManifestSha256': actual_m, 'runtimeSourceInputsSha256': '7' * 64,
                    'signedStoreDerivation': composed['store'], 'workDirectory': [info.st_dev, info.st_ino, info.st_uid],
                    **{key: op.environment[env] for key, env in (('source', 'GITHUB_SHA'), ('workflowSource', 'GITHUB_WORKFLOW_SHA'),
                        ('runId', 'GITHUB_RUN_ID'), ('runAttempt', 'GITHUB_RUN_ATTEMPT'))}}
                source_store = selection()
                if failure == 'invocation': source['runAttempt'] = '99'
                if failure == 'selection': source_store['source'] = 'd' * 40
                for path, body, mode in ((op.checkout / 'desktop' / stager.SIGNED_STORE_SELECTION, stager.canonical(source_store), 0o644),
                        (op.work / 'runtime-binding.json', composed_body, 0o444),
                        (op.work / 'source-binding.json', stager.canonical(source), 0o444)):
                    path.write_bytes(body); path.chmod(mode)
                op.environment.update(MRK_MACOS_STORE_RUNTIME='signed-component',
                    MRK_MACOS_RUNTIME_BINDING_SHA256='b' * 64 if failure == 'binding-digest' else stager.digest(composed_body),
                    MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=actual_m, MRK_BUNDLED_RUNTIME_SOURCE_SHA256='7' * 64)
                with helper.notary_fixture_call(state):
                    if failure is None:
                        try:
                            op.execute()
                        except api.Refused:
                            self.fail(str(op.receipt.get('failure')))
                        self.assertTrue(op.composed_runtime)
                        self.assertTrue(op.receipt['passed'] and op.receipt['originalClosesKnown'] and op.receipt['targetRetired'])
                        self.assertEqual(len(op.calls), 13)
                        self.assertEqual(op.receipt['payloadNotarization']['runtimeManifestSha256'], actual_m)
                        self.assertEqual((op.work / 'input/runtime/manifest.json').read_bytes(), manifest_body)
                        self.assertEqual(op.receipt['notaryAuthentication'], {'created': True, 'closed': True, 'retired': True})
                    else:
                        with self.assertRaises(api.Refused): op.execute()
                        self.assertFalse(op.receipt['passed'])
                        self.assertEqual(state.observations, [])
                        self.assertIsNone(op.notary_key)
                self.assertEqual((op.checkout / 'desktop' / stager.SIGNED_RUNTIME_BINDING).read_bytes(), original_nomination)

    def test_final_package_selected_scope_and_receipt_count_keep_legacy_bound(self):
        import tempfile
        import test_macos_installed_staging as staging
        helper, api, stager = staging.MacAndroidHelperPackagingData(), staging.ANDROID_HELPER, staging.TOOL
        with tempfile.TemporaryDirectory(prefix="mrk-store-final-package-data-") as temporary:
            f = helper.final_package_fixture(Path(temporary))
            op = f.operation
            source = op.checkout / "desktop" / stager.SIGNED_STORE_SELECTION
            source.write_bytes(stager.canonical(selection())); source.chmod(0o644)
            op.environment["MRK_MACOS_STORE_RUNTIME"] = "signed-component"
            with helper.final_package_fixture_call(f):
                try:
                    op.execute()
                except api.Refused:
                    self.fail(str(op.receipt.get("failure")))
            self.assertTrue(op.package_store_runtime and op.receipt["passed"] and op.receipt["originalClosesKnown"])
            self.assertTrue(any(entry["role"] == "source-package-store-selection" and entry["closed"] for entry in op.entries))
            final = op.work / "package-final/MobileReleaseKit.pkg"
            body = final.read_bytes()
            release = (op.checkout / op.release_input).read_bytes()
            arguments = (op.environment, op.target, f.credentials.installer,
                api.digest((op.checkout / api.INSTALLER_PROFILE).read_bytes()),
                api.digest((op.checkout / api.NOTARY_PROFILE).read_bytes()), len(body), api.digest(body),
                stager.build_release_data(release, target=op.target)["release"], api.digest(release))
            for count in (4097, stager.MAX_FILES):
                row = copy.deepcopy(op.receipt)
                row["finalPackage"]["scriptFileCount"] = count
                raw = stager.canonical(row)
                self.assertEqual(api.final_package_receipt(raw, *arguments, runtime_stager=stager)["scriptFileCount"], count)
                with self.assertRaises(api.Refused): api.final_package_receipt(raw, *arguments)
            row["finalPackage"]["scriptFileCount"] = stager.MAX_FILES + 1
            with self.assertRaises(api.Refused):
                api.final_package_receipt(stager.canonical(row), *arguments, runtime_stager=stager)
