"""Actual Darwin xcrun/checked-reader cut; native Document grant is modeled.

Only the resolver crosses the real existing owned-process boundary. No ASC,
Keychain, signing, build, IPA validation, upload or additional tool is invoked.
The separate Rust Book test owns native selection qualification; this fixture's
nomination is test DATA and does not claim that Book lives across this child.
"""
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

from mobile_release import _command_process as process
from mobile_release import local_store_execute as execute
from mobile_release import _desktop_store_execute_protocol as wire
from mobile_release.ios_current_tools_macos import tool_data
from test_local_ios_store_prepare import IOSStorePrepareTests
from test_local_store_prepare import OP


@unittest.skipUnless(sys.platform == 'darwin', 'actual macOS resolver qualification only')
class IOSStoreResolverMacTests(unittest.TestCase):
    def test_original_xcrun_resolution_post_and_close_before_pending_or_asc(self):
        self.assertNotEqual(os.geteuid(), 0)
        fixture = IOSStorePrepareTests(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        terminal, engine, _, _, _ = fixture.run_original()
        self.assertEqual(terminal['outcome'], 'complete', type(engine.primary).__name__)
        prepared = fixture.root / '.mobile-release/store/local' / OP.replace('-', '')
        intent = json.loads((prepared / 'operation-intent.json').read_bytes())
        before = {path: path.read_bytes() for path in prepared.iterdir()}

        alias = Path('/Applications/Xcode.app')
        original_alias = alias.lstat()
        app = alias
        link = None
        if stat.S_ISLNK(original_alias.st_mode):
            self.assertIn(original_alias.st_uid, (0, os.getuid()))
            link = os.readlink(alias)
            name = link.removeprefix('/Applications/')
            self.assertNotEqual(name, 'Xcode.app')
            self.assertLessEqual(len(name.encode()), 255)
            self.assertRegex(name, r'\AXcode[A-Za-z0-9_.+-]*\.app\Z')
            app = alias.parent / name
        else:
            self.assertTrue(stat.S_ISDIR(original_alias.st_mode))
        developer = app / 'Contents/Developer'
        selection = dict(schemaVersion=1, developerDirectory=str(developer),
            appIdentity=execute.LocalStoreExecuteRun._root_data(app.lstat()),
            developerIdentity=execute.LocalStoreExecuteRun._root_data(developer.lstat()),
            xcrun=tool_data(Path('/usr/bin/xcrun').lstat()))
        wire.upload_selection(selection)
        fixture.value['protocol'] = wire.PROTOCOL
        fixture.value['context'].update(operation='local-store-execute', intentSha256=intent['integrity']['sha256'])
        fixture.value['native'].update(uploadSelection=selection,
            signingTools={name: tool_data((Path('/usr/bin') / name).lstat()) for name in ('security', 'codesign', 'openssl')})

        actual_command = process.run_command
        returned = []
        post = []
        original_upload = execute.LocalStoreExecuteRun._upload_tools
        class BeforePending(wire.ProtocolError):
            pass
        refusal = BeforePending()

        def resolve(argv, kwargs, actual_engine, fault):
            self.assertIsNone(fault)
            self.assertEqual(tuple(argv), ('/usr/bin/xcrun', '--no-cache', '--find', 'altool'))
            self.assertIs(kwargs['cancellation'], actual_engine.guard)
            self.assertEqual(kwargs['environ'], dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C',
                DEVELOPER_DIR=str(developer)))
            self.assertTrue(kwargs['capture'])
            self.assertFalse(kwargs['text'])
            self.assertEqual(kwargs['output_limit'], 4097)
            self.assertLessEqual(kwargs['timeout'], 10)
            self.assertFalse(actual_engine.input._material_read)
            # Uses original C/A/W command owner and ledger. Never synthesize
            # its return/join/clock or increment the ledger as inert rows do.
            result = actual_command(argv, **kwargs)
            # This fixed nonpublishing command has no credentials and already
            # captures <=4097 bytes. Keep its actual error, not just exit72.
            self.assertEqual(result.returncode, 0,
                'original xcrun resolver returned nonzero: ' + repr(result.stderr[:1024]))
            returned.append(result.returncode)
            return result

        def tools(owner):
            original_upload(owner)
            self.assertEqual(returned, [0])
            self.assertEqual(owner.observation.calls, 6)
            self.assertEqual(len(owner._runtime_rows), 1)
            self.assertIsNone(owner.pending_head)
            self.assertIsNone(owner.material_original)
            self.assertIsNotNone(owner.tool_manifest)
            self.assertLessEqual(len(owner.tool_reader.descriptors), execute.UPLOAD_TOOL_SLOTS)
            owner._upload_post(resolved=True)
            self.assertEqual(owner.transport_tools['selection'], selection)
            self.assertTrue(Path(owner.transport_tools['altoolPath']).is_relative_to(app / 'Contents'))
            post.append(owner)
            raise refusal  # Deliberate known refusal, never pending/ASC/Store.

        fixture.resolve_tool = resolve
        def no_lane(*_):
            self.fail('Store lane must not be reached by resolver qualification')
        fixture.execution_receipt = no_lane
        with patch.object(execute.LocalStoreExecuteRun, '_upload_tools', tools):
            terminal, engine, events, calls, high = fixture.run_original(_execute=True)
        if engine.primary is not refusal:
            raise AssertionError('original resolver did not reach the expected pre-pending cut') from engine.primary
        self.assertEqual(returned, [0])
        self.assertEqual(post, [engine.service])
        self.assertIs(engine.primary, refusal)
        self.assertNotEqual(terminal['outcome'], 'complete')
        self.assertNotEqual(terminal['outcome'], 'unknown')
        self.assertIsNone(terminal['result'])
        self.assertEqual(events, ['lease-ready'])
        self.assertEqual(len(calls), 7)
        self.assertEqual(terminal['lifetime']['commands'], 7)
        self.assertEqual(fixture.current_phase(), 'prepared')
        self.assertFalse(engine.input._material_read)
        self.assertTrue(engine.input.material_closed())
        self.assertFalse(engine.service.store_completed)
        engine.service.tool_reader.assert_closed()
        self.assertTrue(engine.service.closed())
        self.assertLessEqual(high, 256)
        self.assertEqual(before, {path: path.read_bytes() for path in prepared.iterdir()})
        final_alias = alias.lstat()
        self.assertEqual((original_alias.st_dev, original_alias.st_ino, original_alias.st_mode, original_alias.st_uid,
            original_alias.st_gid, original_alias.st_mtime_ns, original_alias.st_ctime_ns),
            (final_alias.st_dev, final_alias.st_ino, final_alias.st_mode, final_alias.st_uid,
             final_alias.st_gid, final_alias.st_mtime_ns, final_alias.st_ctime_ns))
        if link is not None:
            self.assertEqual(os.readlink(alias), link)
