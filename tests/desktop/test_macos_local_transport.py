"""Opt-in macOS transport smoke; tiny fixtures, no Installer/signing/credentials."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid


@unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('MRK_RUN_LOCAL_MAC_SMOKE') == '1',
                     'explicit macOS smoke selection required')
class LocalTransport(unittest.TestCase):
    def test_readonly_input_and_nonforce_ejection_lifetime(self):
        work = Path(tempfile.mkdtemp(prefix='mrk-local-transport-')).resolve()
        mount = Path('/Volumes') / ('MRK-LocalSmoke-' + uuid.uuid4().hex)
        original = b'xar!Harmless source-reader fixture, not an installable package.\n'
        device = None
        known = True
        reader = None
        delayed_reader = None
        observations = []
        deadline = time.monotonic() + 180

        def run(*args, eject_tool='hdiutil'):
            nonlocal known
            try:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0)
                command = (['/usr/sbin/diskutil', 'eject', *args[1:]]
                           if args[0] == 'detach' and eject_tool == 'diskutil' else ['/usr/bin/hdiutil', *args])
                result = subprocess.run(command, cwd=work,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(45, remaining), check=False)
            except BaseException:
                known = False
                raise
            self.assertLess(len(result.stdout) + len(result.stderr), 65536)
            return result

        try:
            source = work / 'source'; source.mkdir(mode=0o700)
            package = source / 'Install.pkg'; package.write_bytes(original)
            (source / 'producer.json').write_bytes(b'{}\n')
            (source / 'producer.sig').write_bytes(b'inert signature\n')
            image = work / 'fixture.dmg'
            self.assertEqual(run('create', '-size', '8m', '-fs', 'HFS+', '-volname', 'MRKLocalSmoke',
                '-srcfolder', str(source), '-format', 'UDZO', str(image)).returncode, 0)
            native_reader = os.environ.get('MRK_LOCAL_INSTALLER_TEST_BIN')
            for eject_tool in ('hdiutil', 'diskutil', 'diskutil-grace'):
                delayed = eject_tool == 'diskutil-grace'
                if delayed: eject_tool = 'diskutil'
                self.assertFalse(mount.exists())
                attached = run('attach', str(image), '-readonly', '-nobrowse', '-noautoopen',
                               '-mountpoint', str(mount), '-plist')
                self.assertEqual(attached.returncode, 0)
                # A failed/ambiguous parse keeps the image for inspection.
                known = False
                entities = plistlib.loads(attached.stdout)['system-entities']
                devices = [row['dev-entry'] for row in entities if row.get('mount-point') == str(mount)]
                self.assertEqual(len(devices), 1)
                device = devices[0]; known = True
                mounted = mount / 'Install.pkg'
                self.assertEqual(hashlib.sha256(mounted.read_bytes()).digest(), hashlib.sha256(original).digest())
                if native_reader:
                    env = dict(os.environ, MRK_LOCAL_MOUNTED_PACKAGE=str(mounted), MRK_LOCAL_HOST_PACKAGE=str(package))
                    checked = subprocess.run([native_reader, '--exact',
                        'installer::completed_package::local_readonly_source_policy', '--ignored', '--nocapture'],
                        env=env, cwd=work, capture_output=True, timeout=15, check=False)
                    self.assertEqual(checked.returncode, 0, checked.stdout.decode(errors='replace') + checked.stderr.decode(errors='replace'))
                    self.assertIn(b'1 passed', checked.stdout)
                reader = os.open(mounted, os.O_RDONLY | os.O_NOFOLLOW)
                if delayed:
                    # Model a separate asynchronous source reader. This is not
                    # an Installer service or evidence of its actual lifetime.
                    fd, reader = reader, None
                    released = threading.Event()
                    def release_source():
                        time.sleep(2)
                        os.close(fd)
                        released.set()
                    delayed_reader = threading.Thread(target=release_source)
                    delayed_reader.start()
                    self.assertEqual(os.pread(fd, len(original), 0), original)
                    time.sleep(60)
                    delayed_reader.join(timeout=1)
                    self.assertTrue(released.is_set())
                    self.assertFalse(delayed_reader.is_alive())
                    delayed_reader = None
                    result = run('detach', device, eject_tool=eject_tool)
                    observations.append({'tool': eject_tool, 'cleanupGraceSeconds': 60,
                                         'firstEjectionReturncode': result.returncode})
                    self.assertEqual(result.returncode, 0)
                    device = None
                    self.assertFalse(mount.exists())
                    continue
                result = run('detach', device, eject_tool=eject_tool)
                observations.append({'tool': eject_tool, 'openFileEjectionReturncode': result.returncode})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(os.pread(reader, len(original), 0), original)
                os.close(reader); reader = None
                self.assertEqual(run('detach', device, eject_tool=eject_tool).returncode, 0)
                device = None
                self.assertFalse(mount.exists())
            print(json.dumps({'scope': 'local-dmg-source-lifetime', 'observations': observations,
                              'installedAnything': False, 'nativeInputPolicyTested': bool(native_reader), 'passed': True}))
        finally:
            if delayed_reader is not None:
                delayed_reader.join(timeout=3)
                if delayed_reader.is_alive(): known = False
            if reader is not None:
                os.close(reader)
            # Never force-detach or delete through a mount/uncertain operation.
            if known and device is None and not mount.exists():
                shutil.rmtree(work)
            else:
                print(json.dumps({'scope': 'local-dmg-source-lifetime', 'fixturePreserved': True}))
