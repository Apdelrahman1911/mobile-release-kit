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
import time
import unittest
import uuid


@unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('MRK_RUN_LOCAL_MAC_SMOKE') == '1',
                     'explicit macOS smoke selection required')
class LocalTransport(unittest.TestCase):
    def test_verified_host_copy_does_not_pin_distribution(self):
        work = Path(tempfile.mkdtemp(prefix='mrk-local-transport-')).resolve()
        mount = Path('/Volumes') / ('MRK-LocalSmoke-' + uuid.uuid4().hex)
        original = b'Harmless installer-source lifetime fixture.\n'
        device = None
        known = True
        reader = None
        observations = []
        deadline = time.monotonic() + 90

        def run(*args):
            nonlocal known
            try:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0)
                result = subprocess.run(['/usr/bin/hdiutil', *args], cwd=work,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(45, remaining), check=False)
            except BaseException:
                known = False
                raise
            self.assertLess(len(result.stdout) + len(result.stderr), 65536)
            return result

        try:
            source = work / 'source'; source.mkdir(mode=0o700)
            package = source / 'fixture.pkg'; package.write_bytes(original)
            image = work / 'fixture.dmg'
            self.assertEqual(run('create', '-size', '8m', '-fs', 'HFS+', '-volname', 'MRKLocalSmoke',
                '-srcfolder', str(source), '-format', 'UDZO', str(image)).returncode, 0)
            for use_host_copy in (False, True):
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
                mounted = mount / 'fixture.pkg'
                self.assertEqual(hashlib.sha256(mounted.read_bytes()).digest(), hashlib.sha256(original).digest())
                reader = os.open(package if use_host_copy else mounted, os.O_RDONLY | os.O_NOFOLLOW)
                result = run('detach', device)
                observations.append({'source': 'host-copy' if use_host_copy else 'mounted-copy',
                                     'detachReturncode': result.returncode})
                self.assertEqual(result.returncode, 0 if use_host_copy else 16)
                self.assertEqual(os.pread(reader, len(original), 0), original)
                os.close(reader); reader = None
                if not use_host_copy:
                    self.assertEqual(run('detach', device).returncode, 0)
                device = None
                self.assertFalse(mount.exists())
            print(json.dumps({'scope': 'local-dmg-source-lifetime', 'observations': observations,
                              'installedAnything': False, 'passed': True}))
        finally:
            if reader is not None:
                os.close(reader)
            # Never force-detach or delete through a mount/uncertain operation.
            if known and device is None and not mount.exists():
                shutil.rmtree(work)
            else:
                print(json.dumps({'scope': 'local-dmg-source-lifetime', 'fixturePreserved': True}))
