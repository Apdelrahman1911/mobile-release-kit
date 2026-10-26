#!/usr/bin/env python3
"""Fast macOS checks using disposable files; never install or access credentials.

Run with Python >=3.11. --transport also mounts two tiny read-only fixtures.
The real accessibility smoke is opt-in because it needs a local OS permission.
--git-test-bin runs real Git source custody against a locally compiled Rust test
binary, using Apple's CLT Git and a disposable repository.
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
    parser.add_argument('--git-test-bin', type=Path)
    parser.add_argument('--observer-test-bin', type=Path,
                        help='compiled observer with recorded runtime inputs; runs DATA contracts only')
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

    def run(name, command, *, timeout=60, expected_output=None):
        with (output / (name + '.log')).open('xb') as log:
            result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
        matched = expected_output is None or expected_output in (output / (name + '.log')).read_bytes()
        results.append({'check': name, 'returncode': result.returncode, 'expectedOutputMatched': matched})
        (output / 'results.json').write_text(json.dumps({'checks': results}, indent=2) + '\n')
        if result.returncode or not matched:
            print(f'{name} failed; see {output / (name + ".log")}', file=sys.stderr)
            raise SystemExit(result.returncode or 1)

    run('installer-data', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/desktop',
                          '-p', 'test_macos_distribution_detach.py'])
    run('retained-source-bounds', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/desktop',
        '-p', 'test_macos_candidate_bootstrap.py', '-k',
        'test_retained_workflow_adds_only_closed_git_operation_and_preserves_original_handoff_and_clocks'])
    run('candidate-checkpoints', [sys.executable, '-m', 'unittest',
        'tests.desktop.test_macos_candidate_stages'])
    for profile, defines in (('ordinary', []), ('observed', ['-DMRK_INSTALLED_OBSERVATION'])):
        service = output / ('macos-service-phases-' + profile)
        run('native-service-compile-' + profile, ['/usr/bin/xcrun', 'clang', '-fno-objc-arc', *defines,
            '-framework', 'Foundation', '-framework', 'ServiceManagement', '-framework', 'Security',
            'tests/desktop/macos_service_phase_smoke.m', '-o', str(service)])
        run('native-service-phases-' + profile, [str(service)],
            expected_output=b'16 actual Objective-C phase cases passed; service and gate edges inert')
    executable = output / 'macos-dialog-smoke'
    run('native-dialog-compile', ['/usr/bin/xcrun', 'clang', '-fno-objc-arc', '-fblocks',
        '-framework', 'AppKit', '-framework', 'ApplicationServices',
        'tests/desktop/macos_dialog_smoke.m', '-o', str(executable)])
    run('native-dialog-allowances', [str(executable), '--allowance-contract'])
    if args.observer_test_bin:
        run('observer-data-contracts', [str(args.observer_test_bin.resolve(strict=True)), 'data-contracts'],
            expected_output=b'MRK_MACOS_DATA_CONTRACTS=passed')
    if args.git_test_bin:
        test_bin = args.git_test_bin.resolve(strict=True)
        env['RUST_MIN_STACK'] = '16777216'
        run('native-git-sources', [str(test_bin), 'git_sources_native_tests', '--ignored', '--test-threads=1'],
            expected_output=b'2 passed; 0 failed')
        # Match Finder's hidden Library ancestor without changing the owner's
        # Library or any installation. Only this new disposable directory gets
        # the harmless presentation flag; real source/ACL checks still run.
        hidden = temporary / 'hidden-library'; hidden.mkdir(mode=0o700)
        os.chflags(hidden, 0x00008000)
        env['TMPDIR'] = str(hidden)
        try:
            run('native-git-hidden-ancestor', [str(test_bin), 'git_sources_native_tests', '--ignored', '--test-threads=1'],
                expected_output=b'2 passed; 0 failed')
        finally:
            env['TMPDIR'] = str(temporary)
        run('git-source-flags', [str(test_bin), 'git_source_flags::tests', '--test-threads=1'],
            expected_output=b'4 passed; 0 failed')
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
