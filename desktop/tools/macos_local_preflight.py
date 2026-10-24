#!/usr/bin/env python3
"""Fast macOS checks using disposable files; never install or access credentials.

Run with Python >=3.11. --transport also mounts two tiny read-only fixtures.
The real accessibility smoke is opt-in because it needs a local OS permission.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transport', action='store_true')
    parser.add_argument('--dialog', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'darwin' or sys.version_info < (3, 11) or os.getuid() == 0:
        parser.error('requires ordinary-user macOS and Python >=3.11')
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    output = args.output.resolve(strict=True)
    temporary = output / 'tmp'; temporary.mkdir(mode=0o700)
    env = dict(os.environ, TMPDIR=str(temporary))
    results = []

    def run(name, command, *, timeout=60):
        with (output / (name + '.log')).open('xb') as log:
            result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
        results.append({'check': name, 'returncode': result.returncode})
        (output / 'results.json').write_text(json.dumps({'checks': results}, indent=2) + '\n')
        if result.returncode:
            print(f'{name} failed; see {output / (name + ".log")}', file=sys.stderr)
            raise SystemExit(result.returncode)

    run('installer-data', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/desktop',
                          '-p', 'test_macos_distribution_detach.py'])
    executable = output / 'macos-dialog-smoke'
    run('native-dialog-compile', ['/usr/bin/xcrun', 'clang', '-fno-objc-arc', '-fblocks',
        '-framework', 'AppKit', '-framework', 'ApplicationServices',
        'tests/desktop/macos_dialog_smoke.m', '-o', str(executable)])
    run('native-dialog-allowances', [str(executable), '--allowance-contract'])
    if args.transport:
        env['MRK_RUN_LOCAL_MAC_SMOKE'] = '1'
        run('native-transport', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/desktop',
                                '-p', 'test_macos_local_transport.py'], timeout=110)
    if args.dialog:
        # The fixture's own watchdog bounds its entire UI lifetime to ten seconds.
        run('native-dialog', [str(executable), str(temporary)], timeout=15)
        run('native-open-project', [str(executable), '--open-project', str(temporary)], timeout=15)
    print(json.dumps({'checks': results, 'installedAnything': False,
                      'dialogTested': args.dialog, 'passed': True}))


if __name__ == '__main__':
    main()
