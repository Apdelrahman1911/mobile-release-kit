"""Real Tauri command dispatch with a DATA Document port; no native app launch."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'tests/desktop/fixtures/tauri_preparation_dispatch'
ORIGINAL_RESULTS = []


def function(source, name, *, command=False):
    match = re.search(r'(?m)^(?:pub\(crate\) )?(?:async )?fn ' + re.escape(name) + r"(?:\([^\n]*|<'[^\n]*)", source)
    if match is None:
        raise AssertionError(f'missing original function: {name}')
    first = match.start()
    if command:
        annotation = '#[tauri::command]\n'
        if source[first - len(annotation):first] != annotation:
            raise AssertionError(f'changed dispatch annotation: {name}')
        first -= len(annotation)
    last = source.index('\n}', match.end()) + 2
    return source[first:last]


class TauriPreparationDispatchTests(unittest.TestCase):
    def test_current_tauri_dispatch_and_original_request_gates(self):
        shell = (ROOT / 'desktop/src-tauri/src/shell.rs').read_text()
        wire = (ROOT / 'desktop/src-tauri/src/installation.rs').read_text()
        command = function(shell, 'prepare_installation_quit', command=True)
        # Deliberately keep the old synchronous form as a negative control. The
        # changed current command itself is copied verbatim, never reconstructed.
        legacy = command.replace('async fn prepare_installation_quit(', 'fn legacy_prepare_installation_quit(')
        self.assertNotEqual(legacy, command, 'the production command must dispatch asynchronously')
        confirmation = re.search(r'pub\(crate\) const PREPARE_QUIT_CONFIRMATION: &str =\n\s*"[^"\n]+";', wire).group()
        replacements = {
            'ORIGINAL_PREPARATION_COMMAND': command,
            'LEGACY_SYNCHRONOUS_COMMAND': legacy,
            'ORIGINAL_WINDOW_AND_BODY_GATES': function(shell, 'edit_window') + '\n' + function(shell, 'request_body'),
            'ORIGINAL_CONFIRMATION_AND_REQUEST': confirmation + '\n' + function(wire, 'preparation_request'),
        }
        source = (FIXTURE / 'dispatch.rs').read_text()
        for name, value in replacements.items():
            self.assertEqual(source.count(f'/* {name} */'), 1)
            source = source.replace(f'/* {name} */', value)
        cargo = shutil.which('cargo')
        self.assertIsNotNone(cargo, 'Use installed Cargo and cached dependencies')
        scratch = os.environ.get('MRK_PART_TEST_ROOT')
        with tempfile.TemporaryDirectory(prefix='tauri-preparation-dispatch-', dir=scratch) as directory:
            work = Path(directory)
            (work / 'src').mkdir()
            (work / 'src/lib.rs').write_text(source)
            shutil.copyfile(FIXTURE / 'Cargo.toml', work / 'Cargo.toml')
            # Freeze resolution to the app's current dependency versions. Cargo
            # may prune unused packages only inside this disposable fixture.
            shutil.copyfile(ROOT / 'desktop/src-tauri/Cargo.lock', work / 'Cargo.lock')
            env = dict(os.environ)
            env['CARGO_TARGET_DIR'] = str(ROOT / 'desktop/src-tauri/target')
            command = [cargo, 'test', '--offline', '--manifest-path', str(work / 'Cargo.toml'), '--lib', '--', '--test-threads=1']
            result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
            ORIGINAL_RESULTS.append({'command': command, 'returncode': result.returncode,
                                     'stdout': result.stdout, 'stderr': result.stderr})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('5 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
