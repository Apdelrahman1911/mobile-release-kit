"""Same-candidate installed UI handoff; detached, not activated.

Only existing Applications, project edits, synthetic-vault restart and saved-check journeys are selected.
Candidate source remains the real canonical checkout; helper identity is separate.
No historical fixed-carrier profile, Store operation or application build is used.
"""
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_candidate_consumer as consumer
from desktop.tools import macos_fixed_carrier_resume as resume

PHASES = ('build', 'applications-test', 'applications-summary', 'project-test', 'project-summary',
          'persistence-test', 'persistence-summary', 'saved-checks-test', 'saved-checks-summary')
RUNNER = 'desktop/tools/macos_normal_ui_runner.py'
STAGE = 'admission'
NATIVE_STATUS = None
NATIVE_DIAGNOSTIC = None
CLOSES_KNOWN = None
# Parent-held source/host/result original cells only. Independent loader and
# owned-process native ledgers keep their existing limits; this is NOT an
# aggregate descriptor count across the inner XCTest process tree.
PERSISTENCE_MARKER = ('MRK_MACOS_NORMAL_PERSISTENCE_UI='
    'initialize-save-assess-bind-context-lock-reopen-rebind-replace-delete-restart-unlock-reassess-rebind;'
    'appRestart=passed;ordinaryLifetimes=2;cleanExitStatus=unavailable;allWorkerFinality=unavailable;'
    'fixtures=retained-for-disposable-job-retirement')
LIFETIME_SUFFIX = (';outerRequest=1;completion=1;body=1;handoff=1;payloadIdentity=1;'
    'originalTerminated=1;gateFree=1;gateClosed=1;failureCleanup=0;caseDeadlineMet=1')


def install_admission_data(value, selected, context):
    """Same-job completed owner receipt, not independent installation authority.

    The workflow may enter only after the real acquire/install invocation returned
    zero. A JSON document cannot synthesize its native owner or qualify UI.
    """
    selected = consumer.candidate.candidate_selection_data(selected)
    expected = {'scope': 'candidate-fresh-installer-observation', 'target': selected['target'],
        'producerSource': selected['source'], 'producerTree': selected['tree'],
        'artifactId': selected['artifactId'], 'artifactSha256': selected['artifactSha256'],
        'producerRunId': selected['runId'], 'producerRunAttempt': selected['runAttempt'],
        'producerJobId': selected['jobId'], 'helperSource': context['helperSource'],
        'consumerRunId': context['runId'], 'consumerRunAttempt': context['runAttempt'],
        'originalInstallerReturnedZero': True, 'sameRequestReadback': True,
        'originalMountDetached': True, 'originalClosesKnown': True,
        'workloadsKnownSettled': True, 'privateOutputsRetired': True,
        'productReady': False, 'uiQualified': False, 'p0Qualified': False}
    resume.need(type(value) is dict and set(value) == set(expected) | {'helperTree'}
        and all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items())
        and selected['target'] == context['target'] and type(value['helperTree']) is str
        and re.fullmatch(r'[0-9a-f]{40}', value['helperTree']) and value['helperTree'] != '0' * 40,
        'candidate-ui-install-handoff')
    return dict(value)


def phase_request(normal, name, target, work):
    resume.need(type(name) is str and name in PHASES, 'candidate-ui-phase')
    machine, _ = normal.normal_target_data(target)
    root = work / 'normal-ui'
    if name == 'build':
        arguments = ['--normal-build']
    elif name.endswith('-summary'):
        arguments = ['--normal-summary', name.replace('-summary', '-test') + '.xcresult']
    else:
        methods, allowance, _ = normal.NORMAL_SELECTIONS[name + '.xcresult']
        arguments = ['test-without-building', '-project', normal.PROJECT, '-scheme', 'MRKNormalAppUI',
            '-configuration', 'Debug', '-destination', 'platform=macOS,arch=' + machine,
            '-destination-timeout', '15', '-derivedDataPath', str(root / 'DerivedData'),
            '-resultBundlePath', str(root / (name + '.xcresult')),
            *['-only-testing:' + normal.CLASS + method for method in methods],
            '-parallel-testing-enabled', 'NO', '-test-timeouts-enabled', 'YES',
            '-default-test-execution-time-allowance', str(allowance),
            '-maximum-test-execution-time-allowance', str(allowance), '-disableAutomaticPackageResolution']
    argv = ['--target', target, *arguments]
    request = normal.normal_request(argv, str(root / 'tmp') + '/')
    resume.need(request['phase'] == ('build' if name == 'build' else 'summary' if name.endswith('-summary') else 'test')
                and request['target'] == target, 'candidate-ui-existing-request')
    return argv, request


def clean_environment(normal, selected, work):
    _, hosted = normal.normal_target_data(selected['target'])
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/runner', 'USER': 'runner',
        'LOGNAME': 'runner', 'TMPDIR': str(work / 'normal-ui/tmp') + '/', 'LANG': 'en_US.UTF-8',
        'LC_ALL': 'en_US.UTF-8', 'TZ': 'UTC', 'DEVELOPER_DIR': normal.DEVELOPER,
        'TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB': hosted,
        'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE': selected['source'],
        'TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE': selected['source']}


def persistence_markers(body):
    resume.need(type(body) is bytes and 0 < len(body) <= 1 << 20 and body.endswith(b'\n'),
                'candidate-ui-persistence-output')
    text = body.decode('utf-8', 'strict'); lines = text.splitlines()
    phases = ['MRK_MACOS_PERSISTENCE_LIFETIME=phase=' + str(n) + LIFETIME_SUFFIX for n in (1, 2)]
    prefix = 'MRK_MACOS_PERSISTENCE_LIFETIME='
    resume.need(lines.count(PERSISTENCE_MARKER) == 1 and all(lines.count(v) == 1 for v in phases)
                and sum(line.startswith(prefix) for line in lines) == 2
                and sum(line.startswith('MRK_MACOS_NORMAL_PERSISTENCE_UI=') for line in lines) == 1
                and lines.index(phases[0]) < lines.index(phases[1]) < lines.index(PERSISTENCE_MARKER)
                and 'MRK_MACOS_UI_FAILURE_CLEANUP=' not in text, 'candidate-ui-persistence-lifetimes')
    method = '-[MRKNormalAppUITests.NormalAppUITests testSyntheticPersistentCredentials]'
    attempts = [line for line in lines if line.startswith('Test Case ')]
    resume.need(len(attempts) == 2 and attempts[0] == "Test Case '" + method + "' started."
                and re.fullmatch("Test Case '" + re.escape(method) + r"' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", attempts[1]),
                'candidate-ui-persistence-one-attempt')
    return True


STORE_ENTRY_MARKER = ('MRK_MACOS_NORMAL_STORE_ENTRY_UI=same-build-navigation-help-and-no-credential-refusal;'
    'storeActions=not-run;historyVerification=not-run;liveLifecycle=not-established')
RECOVERY_IDLE_MARKER = ('MRK_MACOS_NORMAL_RECOVERY_IDLE_UI='
    'ordinary-ui-observed-empty-build-input-inspection-and-settled-projection;'
    'mutationRecovery=not-run;projectCleanliness=not-established;'
    'cleanExitStatus=unavailable;allWorkerFinality=unavailable')


def saved_checks_markers(body):
    """Exact original two-test observations; not Store or history authority."""
    resume.need(type(body) is bytes and 0 < len(body) <= 1 << 20 and body.endswith(b'\n'),
                'candidate-ui-saved-checks-output')
    text = body.decode('utf-8', 'strict'); lines = text.splitlines()
    normal_marker = 'MRK_MACOS_UI_ORIGINAL=' + LIFETIME_SUFFIX[1:]
    prefix = 'MRK_MACOS_NORMAL_OFFLINE_UI='
    offline = [line for line in lines if line.startswith(prefix)]
    resume.need(len(offline) == 1, 'candidate-ui-saved-checks-markers')
    match = re.fullmatch(re.escape(prefix) +
        r'ordinary-ui-observed-saved-offline-report-and-settled-projection;missing=([1-9][0-9]{0,2});'
        r'skipped=([1-9][0-9]{0,2});releaseReadiness=not-assessed;'
        r'cleanExitStatus=unavailable;allWorkerFinality=unavailable', offline[0])
    resume.need(match is not None and 2 <= int(match[1]) <= 128 and 1 <= int(match[2]) <= 128
        and lines.count(normal_marker) == 2
        and sum(line.startswith('MRK_MACOS_UI_ORIGINAL=') for line in lines) == 2
        and lines.count(RECOVERY_IDLE_MARKER) == lines.count(STORE_ENTRY_MARKER) == 1
        and sum(line.startswith('MRK_MACOS_NORMAL_RECOVERY_IDLE_UI=') for line in lines) == 1
        and sum(line.startswith('MRK_MACOS_NORMAL_STORE_ENTRY_UI=') for line in lines) == 1
        and 'MRK_MACOS_UI_FAILURE_CLEANUP=' not in text, 'candidate-ui-saved-checks-markers')
    attempts = [(index, line) for index, line in enumerate(lines) if line.startswith('Test Case ')]
    resume.need(len(attempts) == 4, 'candidate-ui-saved-checks-attempts')
    methods = {'testSyntheticProjectSavedOfflineChecks': (offline[0],),
               'testSyntheticProjectEmptyBuildInputInspection': (RECOVERY_IDLE_MARKER, STORE_ENTRY_MARKER)}
    # XCTest may order methods differently from the request; each distinct
    # method must still have its own non-overlapping original start/pass pair.
    for offset in (0, 2):
        start, first = attempts[offset]; end, last = attempts[offset + 1]
        method = next((name for name in methods if first ==
            "Test Case '-[MRKNormalAppUITests.NormalAppUITests " + name + "]' started."), None)
        resume.need(method is not None and re.fullmatch(
            r"Test Case '-\[MRKNormalAppUITests\.NormalAppUITests " + re.escape(method) +
            r"\]' passed \([0-9]+(?:\.[0-9]+)? seconds\)\.", last), 'candidate-ui-saved-checks-attempts')
        originals = [index for index in range(start + 1, end) if lines[index] == normal_marker]
        resume.need(len(originals) == 1 and all(originals[0] < lines.index(marker) < end
            for marker in methods.pop(method)), 'candidate-ui-saved-checks-attempts')
    resume.need(not methods, 'candidate-ui-saved-checks-attempts')
    return True


def phase_admission_data(row, request, source, stdout, stderr):
    """Current normal runner's original receipt, without fixed P0 decoration."""
    mode = request['phase']; target = request['target']
    result = None if request['result'] is None else request['result'].name
    resume.need(type(row) is dict and row.get('sourceCommit') == source and row.get('target') == target
        and row.get('sourcePrePostMatched') is True and row.get('originalCommandReturned') is True
        and row.get('normalPhase' if mode == 'test' else 'phase') == mode and row.get('resultBundle') == result
        and type(row.get('originalTestReturncode' if mode == 'test' else 'originalReturncode')) is int
        and row['originalTestReturncode' if mode == 'test' else 'originalReturncode'] == 0
        and row.get('scope') == ('actual-generated-xctrunner-admission-only' if mode == 'test'
                                else 'normal-ui-original-command-admission-only')
        and row.get('receiptPolicy') == 'exclusive0600-readback-consuming-close'
        and not any(k in row for k in ('fixedCarrierResumeScope', 'fixedNormalBatch', 'applicationSourceCommit',
                                      'currentProductQualified', 'p0Qualified', 'intelQualified')),
        'candidate-ui-original-receipt')
    normal_limit = 32 << 30 if mode == 'build' else 1 << 30
    resume.need(row.get('fileLimitBytes') == [normal_limit, normal_limit], 'candidate-ui-original-file-limit')
    roster = row.get('sourceRosterSha256')
    resume.need(type(roster) is str and re.fullmatch(r'[0-9a-f]{64}', roster), 'candidate-ui-source-roster')
    clock = row.get('phaseClock')
    resume.need(type(clock) is dict and set(clock) == {'startNs', 'deadlineNs', 'beforePublicationNs', 'postCloseDeadlineRequired'}
        and clock['postCloseDeadlineRequired'] is True
        and all(type(clock[k]) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}', clock[k])
                for k in ('startNs', 'deadlineNs', 'beforePublicationNs')), 'candidate-ui-original-clock')
    start, end, before = (int(clock[k]) for k in ('startNs', 'deadlineNs', 'beforePublicationNs'))
    resume.need(end - start == request['phaseSeconds'] * 1_000_000_000 and start <= before < end,
                'candidate-ui-original-clock')
    src = ('normal-ui-source-roster', 15, 1048576)
    roles = ([src, *[('normal-toolchain-' + k, 15, 4096) for k in ('xcode', 'sdkPath', 'sdkVersion', 'sdkBuild')],
              ('normal-ui-build', 240, 1048576), src] if mode == 'build' else
             [src, ('verify-generated-runner', 30, 1048576), ('generated-runner-entitlements', 30, 1048576),
              ('one-admitted-ui-test', request['timeout'], 1048576), src] if mode == 'test' else
             [src, ('normal-ui-summary', 30, 262144), src])
    commands = row.get('commands')
    keys = {'role', 'returncode', 'timeoutSeconds', 'roleCapSeconds', 'outputLimitBytes', 'argvSha256',
            'stdoutBytes', 'stdoutSha256', 'stderrBytes', 'stderrSha256'}
    resume.need(type(commands) is list and len(commands) == len(roles), 'candidate-ui-original-commands')
    for command, (role, cap, limit) in zip(commands, roles):
        resume.need(type(command) is dict and set(command) == keys and command['role'] == role
            and type(command['returncode']) is int and command['returncode'] == 0
            and all(type(command[k]) is int for k in ('timeoutSeconds', 'roleCapSeconds', 'outputLimitBytes', 'stdoutBytes', 'stderrBytes'))
            and 1 <= command['timeoutSeconds'] <= command['roleCapSeconds'] == cap
            and command['outputLimitBytes'] == limit and 0 <= command['stdoutBytes'] <= limit
            and 0 <= command['stderrBytes'] <= limit - command['stdoutBytes']
            and all(type(command[k]) is str and re.fullmatch(r'[0-9a-f]{64}', command[k])
                    for k in ('argvSha256', 'stdoutSha256', 'stderrSha256')), 'candidate-ui-original-command')
    resume.need(commands[0]['stdoutSha256'] == commands[-1]['stdoutSha256']
                and commands[0]['stdoutBytes'] == commands[-1]['stdoutBytes'], 'candidate-ui-source-query-post')
    original = commands[-2] if mode != 'summary' else commands[1]
    resume.need(type(stdout) is bytes and type(stderr) is bytes
                and original['stdoutBytes'] == len(stdout) and original['stdoutSha256'] == resume.sha(stdout)
                and original['stderrBytes'] == len(stderr) and original['stderrSha256'] == resume.sha(stderr),
                'candidate-ui-original-output-binding')
    if mode == 'test':
        resume.need(all(row.get(k) is True for k in ('originalClosesCompleted', 'originalProductsPrePostMatched', 'strictCodesignOriginalZero'))
                    and row.get('reSignedOrRepaired') is False, 'candidate-ui-runner-finality')
        if result == 'project-test.xcresult':
            resume.need(row.get('projectFieldAndEditMarkersObserved') is True
                        and row.get('androidToolSourceBrowseMarkerObserved') is True, 'candidate-ui-project-markers')
        elif result == 'applications-test.xcresult':
            resume.need(row.get('applicationsLaunchObservationMarker') is True, 'candidate-ui-applications-marker')
        elif result == 'saved-checks-test.xcresult':
            resume.need(saved_checks_markers(stdout),
                'candidate-ui-saved-checks-markers')
        else:
            resume.need(result == 'persistence-test.xcresult' and persistence_markers(stdout), 'candidate-ui-restart-selection')
    if mode == 'summary':
        count = 2 if result in ('project-test.xcresult', 'saved-checks-test.xcresult') else 1
        counts = resume.decode(stdout, allow_finite_floats=True)
        wanted = {'totalTestCount': count, 'passedTests': count, 'failedTests': 0, 'skippedTests': 0, 'expectedFailures': 0}
        resume.need(type(counts) is dict and all(type(counts.get(k)) is int and counts[k] == v for k, v in wanted.items()),
                    'candidate-ui-exact-test-counts')
    return roster


def admission_name(name):
    return ('build.command-admission.json' if name == 'build' else
            name + '.command-admission.json' if name.endswith('-summary') else name + '.runner-admission.json')


def read_phase(read, normal, name, selected, work):
    _, request = phase_request(normal, name, selected['target'], work)
    root = work / 'normal-ui'
    resume.need(read(root / (name + '.status'), 16) == b'0\n', 'candidate-ui-prior-caller-zero')
    row = resume.decode(read(root / admission_name(name), 32768))
    stdout = read(root / (name + '.stdout'), 1 << 20)
    stderr = read(root / (name + '.stderr'), 1 << 20)
    return phase_admission_data(row, request, selected['source'], stdout, stderr)


def run_phase(normal, owner, book, quota, context, selected, name, clock, verify_sources):
    """One fixed existing CLI under the existing owned-process API.

    Outer success requires inner zero, its exact original native records, POST,
    and all consuming input closes. Outer failure/timeout cannot certify inner
    worker finality and never authorizes another phase or deleting outputs.
    """
    global STAGE, NATIVE_STATUS, NATIVE_DIAGNOSTIC
    work = context['work'].parent; directory = work / 'normal-ui'
    args, request = phase_request(normal, name, selected['target'], work)
    env = clean_environment(normal, selected, work)
    argv = [str(work / 'host-python/bin/python3'), '-I', '-S', '-B', str(consumer.CANDIDATE_ROOT / RUNNER), *args]
    quota.check(); verify_sources()
    # Inner original phase budget is unchanged. The outer endpoint was created
    # before admission, and funds PRE/POST queries and native cleanup separately.
    timeout = request['phaseSeconds'] + 15
    resume.need(clock.allowance(timeout) == timeout, 'candidate-ui-original-wrapper-reserve')
    STAGE = 'native'
    original = owner.run_owned(argv, environ=env, cwd=consumer.CANDIDATE_ROOT, timeout=timeout,
                               capture=True, text=False, output_limit=(1 << 20) + 4096)
    normal.original_command(original, argv, (1 << 20) + 4096)
    NATIVE_STATUS = original.returncode
    STAGE = 'native-post'
    clock.check(); quota.check()
    # Originals remain private. Even a known native refusal cannot publish a
    # success/status marker, and failure leaves all possibly useful output data.
    quota.call(book, 'publish', directory / (name + '.stdout'), original.stdout)
    quota.call(book, 'publish', directory / (name + '.stderr'), original.stderr)
    if original.returncode != 0:
        # Classify only a whole closed exception record using the existing
        # normal runner's sanitizer. Never echo stderr or replace its failure.
        try:
            diagnosis = normal.classify_normal_admission_failure(original.stderr)
            NATIVE_DIAGNOSTIC = {key: diagnosis[key] for key in
                ('status', 'stage', 'exceptionClass', 'sourceFrames', 'ownerFailure', 'ownerDiagnostic')
                if key in diagnosis}
        except BaseException:
            pass
    resume.need(original.returncode == 0, 'candidate-ui-original-cli-nonzero')
    row_entry, body = quota.call(book, 'file', directory / admission_name(name), 32768, modes=(0o600,))
    row = resume.decode(body)
    roster = phase_admission_data(row, request, selected['source'], original.stdout, original.stderr)
    verify_sources(); quota.check(); clock.check()
    return roster


def main():
    global STAGE, NATIVE_STATUS, NATIVE_DIAGNOSTIC, CLOSES_KNOWN
    STAGE, NATIVE_STATUS, NATIVE_DIAGNOSTIC, CLOSES_KNOWN = 'admission', None, None, None
    name = sys.argv[1] if len(sys.argv) == 2 else None
    resume.need(name in (*PHASES, 'result', 'cleanup'), 'candidate-ui-fixed-command')
    context = consumer.entry_context((name,))
    resume.need(ROOT == consumer.HELPER_ROOT and Path.cwd() == consumer.CANDIDATE_ROOT,
                'candidate-ui-real-source-roots')
    import resource
    file_limit = (32 << 30) if name == 'build' else (1 << 30)
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    work = context['work'].parent; directory = work / 'normal-ui'
    quota = resume.OriginalQuota(); primary = None; clock = None
    try:
        quota.reserve(1)  # Existing bootstrap source's consuming FD.
        book = quota.book(resume.bootstrap_originals(consumer.HELPER_ROOT))
        sources = {}
        def read(path, limit, *, source=False, mode=0o600):
            entry, body = quota.call(book, 'file', path, limit, modes=(mode,))
            if source: sources[path] = body
            return body
        selected = consumer.selection_data(read(consumer.HELPER_ROOT / consumer.SELECTION_PATH, 8192,
                                                  source=True, mode=0o644), context['target'])
        install = install_admission_data(resume.decode(read(work / 'consumer-result.json', 16384)), selected, context)
        paths = tuple(dict.fromkeys((*consumer.HELPER_SOURCE_INPUTS, consumer.CONSUMER_PATH,
            consumer.LEGACY_PATH, consumer.PARSER_PATH, RUNNER, 'desktop/tools/macos_candidate_ui.py')))
        for path in paths:
            limit = resume.SOURCE_LIMIT if path == consumer.LEGACY_PATH else resume.SOURCE_MODULE_LIMIT
            read(consumer.HELPER_ROOT / path, limit, source=True, mode=0o644)
        # Genuine candidate path is retained; module execution never impersonates
        # helper SOURCE or rewrites __file__/the live checkout/GitHub identity.
        runner_body = read(consumer.CANDIDATE_ROOT / RUNNER, 1 << 20, source=True, mode=0o644)
        normal = resume.load_module('_mrk_candidate_ui_owner', consumer.HELPER_ROOT / RUNNER,
                                    sources[consumer.HELPER_ROOT / RUNNER])
        _, request = phase_request(normal, name if name in PHASES else 'persistence-summary', selected['target'], work)
        # Exact existing inner budget plus bounded admission/source/final closes;
        # never restarted on cancellation, a late result or another native call.
        clock = normal.PhaseClock(request['phaseSeconds'] + 180, started=consumer.STARTED_NS)
        owner = normal.load_normal_owner(consumer.HELPER_ROOT)
        environment = clean_environment(normal, selected, work)
        git_env = dict(environment, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                       GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
        source_phase = normal.NormalPhase(owner, git_env, consumer.CANDIDATE_ROOT, clock)
        tool_uid = os.stat('/usr/bin/git', follow_symlinks=False).st_uid
        resume.need(tool_uid in (0, os.getuid()), 'candidate-ui-git-owner')
        quota.call(book, 'file', Path('/usr/bin/git'), 64 << 20, uid=tool_uid, modes=(0o555, 0o755))
        def verify_sources():
            quota.check(); clock.check()
            for root, source, tree in ((consumer.HELPER_ROOT, context['helperSource'], install['helperTree']),
                                       (consumer.CANDIDATE_ROOT, selected['source'], selected['tree'])):
                prefix = ['/usr/bin/git', '-C', str(root), '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                          '--no-optional-locks', '--literal-pathspecs']
                result = source_phase.call('candidate-ui-source-identity', prefix + ['rev-parse', 'HEAD', 'HEAD^{tree}'], 15, 8192)
                resume.need(result.returncode == 0 and result.stderr == b''
                            and result.stdout == (source + '\n' + tree + '\n').encode('ascii'), 'candidate-ui-checkout-identity')
                expected = {str(path.relative_to(root)): body for path, body in sources.items()
                            if path.is_relative_to(root) and not (root == consumer.CANDIDATE_ROOT
                                                                 and path.is_relative_to(consumer.HELPER_ROOT))}
                result = source_phase.call('candidate-ui-source-blobs', prefix + ['ls-tree', '-z', '--full-tree', source,
                                                                                '--', *sorted(expected)], 15, 8192)
                resume.need(result.returncode == 0 and result.stderr == b'', 'candidate-ui-source-query')
                consumer.source_rows_data(result.stdout, expected)
            quota.check(); clock.check()
        STAGE = 'source'
        verify_sources()
        STAGE = 'host'
        # Existing native normal context/source parser below remains authoritative
        # for target/account/console/Xcode and exact candidate harness inputs.
        host = work / 'host-python'
        host_body = read(host / 'host-binding.json', 32768)
        binding = resume.decode(host_body)
        def directory_read(path):
            entry = quota.call(book, 'directory', path)
            return entry['identity'], os.listdir(entry['fd'])
        def host_read(path, limit):
            entry, body = quota.call(book, 'file', path, limit)
            return entry['identity'], body
        snapshot, cfg = resume.host_snapshot(host, directory_read, host_read, sidecar=True)
        actual_host = {'executable': str(Path(sys.executable).resolve()), 'prefix': sys.prefix,
            'basePrefix': sys.base_prefix, 'baseExecutable': str(Path(sys._base_executable).resolve())}
        resume.host_selection_data(binding, snapshot, cfg, host, actual_host,
                                   context['helperSource'], context['runId'], context['runAttempt'])
        if name == 'build':
            os.mkdir(directory, 0o700); os.mkdir(directory / 'tmp', 0o700)
        held_directory = quota.call(book, 'directory', directory)
        resume.need(held_directory['identity'][2:] == (0o40700, os.getuid(), os.getgid()), 'candidate-ui-private-root')
        STAGE = 'predecessors'
        previous = PHASES if name in ('result', 'cleanup') else PHASES[:PHASES.index(name)]
        rosters = [read_phase(lambda p, n: read(p, n), normal, phase, selected, work) for phase in previous]
        resume.need(not rosters or len(set(rosters)) == 1, 'candidate-ui-same-harness-roster')
        if name in PHASES:
            # All sources/host/prior result originals have been quoted before the
            # new native entry. Remaining cells: two captures, one admission,
            # No in-process success status: only the enclosing workflow may record
            # its actual returned caller status after this final close/clock.
            resume.need(quota.reserved + 3 <= resume.MAX_ORIGINALS, 'candidate-ui-original-capacity')
            roster = run_phase(normal, owner, book, quota, context, selected, name, clock, verify_sources)
            resume.need(not rosters or roster == rosters[0], 'candidate-ui-same-harness-roster')
        else:
            verify_sources(); quota.check(); clock.check()
        # Consume inputs before publishing any success indicator. A late close
        # failure leaves the phase unconfirmed even if XCTest happened to pass.
        STAGE = 'final-closes'
        CLOSES_KNOWN = quota.finish()
        resume.need(CLOSES_KNOWN, 'candidate-ui-original-final-closes')
        clock.check()
        value = {'scope': 'candidate-existing-local-ui-observation', 'phase': name,
            'target': selected['target'], 'applicationSource': selected['source'], 'harnessSource': selected['source'],
            'helperSource': context['helperSource'], 'helperTree': install['helperTree'],
            'consumerRunId': context['runId'], 'consumerRunAttempt': context['runAttempt'],
            'artifactId': selected['artifactId'], 'artifactSha256': selected['artifactSha256'],
            'originalClosesKnown': True, 'productReady': False, 'allApplicationWorkerFinality': 'unavailable',
            'applicationsEntryQualified': False, 'p0Qualified': False}
        if name in ('result', 'cleanup'):
            value.update(applicationsLaunchObservations=1, projectEditingTests=2, syntheticPersistenceRestartTests=1,
                         savedOfflineChecksTests=1, emptyBuildInputInspectionTests=1, storeEntryRefusalObserved=True,
                         totalTests=6, failedTests=0, skippedTests=0, sameInstalledApplication=True,
                         sourceRosterSha256=rosters[0])
        if name == 'cleanup':
            STAGE = 'cleanup'
            cleanup_outputs(directory, held_directory['identity'], clock)
            value.update(taskHarnessOutputsRetired=True, installedApplicationRetained=True,
                         syntheticPrivateFixturesRetainedForHostedTeardown=True)
        clock.finish()
        STAGE = 'complete'
        return value
    except BaseException as error:
        primary = error
        raise
    finally:
        settled = False
        try: settled = quota.finish()
        except BaseException:
            if primary is None: raise
            BaseException.add_note(primary, 'candidate-ui-original-final-closes')
        CLOSES_KNOWN = settled
        if not settled:
            if primary is None: raise resume.Refused('candidate-ui-original-final-closes')
            BaseException.add_note(primary, 'candidate-ui-original-final-closes')


def cleanup_outputs(directory, expected, clock):
    """Only known settled harness outputs; no app/vault/shared services removed."""
    import shutil
    import stat
    resume.need(shutil.rmtree.avoids_symlink_attacks, 'candidate-ui-cleanup-primitive')
    fd = None
    primary = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        def post():
            clock.check()
            resume.need(resume.identity(os.fstat(fd))[:5] == expected
                == resume.identity(os.stat(directory, follow_symlinks=False))[:5]
                and expected[2:] == (stat.S_IFDIR | 0o700, os.getuid(), os.getgid()),
                'candidate-ui-cleanup-root')
        post()
        for name in ('DerivedData', 'tmp', 'applications-test.xcresult', 'project-test.xcresult', 'persistence-test.xcresult',
                     'saved-checks-test.xcresult'):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            resume.need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_dev == expected[0],
                        'candidate-ui-cleanup-directory')
            post(); shutil.rmtree(name, dir_fd=fd); post()
        for phase in PHASES:
            for suffix in ('.stdout', '.stderr'):
                name = phase + suffix
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                resume.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                            and info.st_dev == expected[0], 'candidate-ui-cleanup-file')
                post(); os.unlink(name, dir_fd=fd); post()
    except BaseException as error:
        primary = error
        raise
    finally:
        if fd is not None:
            original, fd = fd, None
            try: os.close(original)
            except BaseException:
                if primary is None: raise resume.Refused('candidate-ui-cleanup-close-unknown') from None
                BaseException.add_note(primary, 'candidate-ui-cleanup-close-unknown')


PUBLIC_REASONS = frozenset((
    'candidate-ui-install-handoff', 'candidate-ui-phase', 'candidate-ui-existing-request',
    'candidate-ui-persistence-output', 'candidate-ui-persistence-lifetimes', 'candidate-ui-persistence-one-attempt',
    'candidate-ui-original-receipt', 'candidate-ui-original-file-limit', 'candidate-ui-source-roster',
    'candidate-ui-original-clock', 'candidate-ui-original-commands', 'candidate-ui-original-command',
    'candidate-ui-source-query-post', 'candidate-ui-original-output-binding', 'candidate-ui-runner-finality',
    'candidate-ui-project-markers', 'candidate-ui-applications-marker', 'candidate-ui-restart-selection',
    'candidate-ui-exact-test-counts', 'candidate-ui-prior-caller-zero', 'candidate-ui-original-wrapper-reserve',
    'candidate-ui-original-cli-nonzero', 'candidate-ui-fixed-command', 'candidate-ui-real-source-roots',
    'candidate-ui-git-owner', 'candidate-ui-checkout-identity', 'candidate-ui-source-query',
    'candidate-ui-private-root', 'candidate-ui-same-harness-roster', 'candidate-ui-original-capacity',
    'candidate-ui-saved-checks-output', 'candidate-ui-saved-checks-markers', 'candidate-ui-saved-checks-attempts',
    'candidate-ui-original-final-closes', 'candidate-ui-cleanup-primitive', 'candidate-ui-cleanup-root',
    'candidate-ui-cleanup-directory', 'candidate-ui-cleanup-file', 'candidate-ui-cleanup-close-unknown',
))


def failure_data(error, phase):
    args = BaseException.args.__get__(error)
    reason = args[0] if len(args) == 1 and type(args[0]) is str and args[0] in PUBLIC_REASONS else None
    classes = (resume.Refused, OSError, FileNotFoundError, PermissionError, ValueError, TypeError, RuntimeError,
               KeyError, AttributeError, ImportError, KeyboardInterrupt, SystemExit)
    return {'scope': 'candidate-ui-failure-only', 'phase': phase if phase in (*PHASES, 'result', 'cleanup') else None,
            'stage': STAGE if STAGE in ('admission', 'source', 'host', 'predecessors', 'native', 'native-post',
                                        'final-closes', 'cleanup', 'complete') else None,
            'exceptionClass': type(error).__name__ if type(error) in classes else 'other',
            'reason': reason, 'nativeReturncode': NATIVE_STATUS if type(NATIVE_STATUS) is int and 0 <= NATIVE_STATUS <= 255 else None,
            'inputOriginalClosesKnown': CLOSES_KNOWN if type(CLOSES_KNOWN) is bool else None,
            'nativeDiagnostic': NATIVE_DIAGNOSTIC,
            'rawOutputExported': False, 'cleanupAuthorized': False}


if __name__ == '__main__':
    try:
        result = main()
    except BaseException as error:
        sys.stderr.buffer.write(resume.canonical(failure_data(error, sys.argv[1] if len(sys.argv) == 2 else None)) + b'\n')
        raise SystemExit(1) from None
    sys.stdout.buffer.write(resume.canonical(result) + b'\n')
