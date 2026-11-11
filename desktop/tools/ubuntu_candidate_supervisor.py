"""Bounded original process-group owner; caller holds the compiler lock."""
from pathlib import Path
import hashlib, json, os, platform, selectors, signal, subprocess, time
CAP=4*1024**2
RSS_LIMIT=3*1024**3
FREE_FLOOR=2*1024**3
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
HOSTED_SHELL_RSS_LIMIT=5*1024**3
HOSTED_TOTAL_FLOOR=7*1024**3
HOSTED_START_FREE=6*1024**3
HOSTED_FREE_RESERVE=1024**3

def memory_facts(body):
    facts={}
    for line in body.splitlines():
        fields=line.split()
        if fields and fields[0] in ('MemTotal:', 'MemAvailable:'):
            assert len(fields)==3 and fields[1].isdigit() and fields[2]=='kB'
            name=fields[0][:-1]; assert name not in facts
            facts[name]=int(fields[1])*1024
    assert set(facts)=={'MemTotal','MemAvailable'} and 0 < facts['MemAvailable'] <= facts['MemTotal']
    return facts

def shell_memory_admitted(facts):
    return facts['MemTotal'] >= HOSTED_TOTAL_FLOOR and facts['MemAvailable'] >= HOSTED_START_FREE

def hosted_shell_memory(E):
    # Source-selected CI control only. No environment value supplies a limit.
    assert platform.system()=='Linux' and platform.machine()=='x86_64'
    assert os.getuid()==os.geteuid()!=0
    assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
    body=Path('/proc/meminfo').read_text(); assert len(body)<=65536
    facts=memory_facts(body)
    receipt=dict(rawMeminfo=body, **facts, admitted=shell_memory_admitted(facts),
        groupRssLimitBytes=HOSTED_SHELL_RSS_LIMIT, minTotalBytes=HOSTED_TOTAL_FLOOR,
        minInitialAvailableBytes=HOSTED_START_FREE, minActiveAvailableBytes=HOSTED_FREE_RESERVE,
        githubRunId=os.environ.get('GITHUB_RUN_ID'), githubSha=os.environ.get('GITHUB_SHA'))
    (E/'hosted-shell-memory.json').write_text(json.dumps(receipt,indent=2)+'\n')
    assert receipt['admitted'], 'hosted shell memory/headroom refused; original native facts retained'
    return HOSTED_SHELL_RSS_LIMIT

def run(commands,D,E,env,*,hosted_shell=False):
    rss_limit=RSS_LIMIT
    if hosted_shell:
        assert len(commands)==1 and commands[0][0]=='shell-build'
        argv=commands[0][1]
        assert argv[1]=='build' and argv[-2:]==['--bin','mobile-release-kit-desktop']
        assert '--release' in argv and 'desktop-shell,custom-protocol' in argv
        assert '--jobs' in argv and argv[argv.index('--jobs')+1]=='1'
        rss_limit=hosted_shell_memory(E)
    def clean(): pass
    def free():
        s=os.statvfs(E); return s.f_bavail*s.f_frsize
    assert free() > FREE_FLOOR + 512 * 1024**2
    results = []
    for role, argv, timeout in commands:
        clean()
        part = E / role
        part.mkdir(mode=0o700)
        streams = {name: (part / (name + '.log')).open('xb', buffering=0) for name in ('stdout', 'stderr')}
        written = dict(stdout=0, stderr=0)
        selector = selectors.DefaultSelector()
        child = None
        failure = code = None
        started = time.monotonic()
        last = peak = 0
        observations = []
        try:
            child = subprocess.Popen(argv, cwd=D, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            for stream, name in ((child.stdout, 'stdout'), (child.stderr, 'stderr')):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map() or child.poll() is None:
                now = time.monotonic()
                if now - started > timeout or free() < FREE_FLOOR:
                    failure = 'original-deadline' if now - started > timeout else 'free-disk-floor'
                    break
                if now - last >= 0.1:
                    last = now
                    probe = subprocess.run(['/bin/ps', '-eo', 'pid=,ppid=,pgid=,rss='],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
                    assert len(probe.stdout) <= 4 * 1024**2 and len(probe.stderr) <= 4096
                    rows = []
                    for line in probe.stdout.splitlines():
                        fields = line.split()
                        assert len(fields) == 4 and all(n.isdigit() for n in fields)
                        row = list(map(int, fields))
                        if row[2] != child.pid: continue
                        rows.append(row)
                    assert probe.returncode in (0, 1) and not (probe.returncode == 1 and rows)
                    rss = sum(row[3] * 1024 for row in rows)
                    peak = max(peak, rss)
                    available=None
                    if hosted_shell:
                        available=memory_facts(Path('/proc/meminfo').read_text())['MemAvailable']
                    observations.append(dict(elapsedSeconds=now-started, processes=rows, groupRssBytes=rss, freeDiskBytes=free(),
                        availableMemoryBytes=available))
                    if available is not None and available < HOSTED_FREE_RESERVE:
                        failure='hosted-memory-headroom-floor'
                        break
                    if rss > rss_limit:
                        failure = 'compiler-group-rss-limit'
                        break
                for key, _ in selector.select(0.1):
                    body = os.read(key.fd, min(65536, CAP - sum(written.values()) + 1))
                    if not body:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    keep = body[:CAP - sum(written.values())]
                    if keep:
                        count = streams[key.data].write(keep)
                        written[key.data] += count
                        assert count == len(keep)
                    if len(body) > len(keep):
                        failure = 'combined-output-overflow'
                        break
                if failure:
                    break
        except BaseException as error:
            failure = 'capture-or-resource-error:' + type(error).__name__ + ':' + str(error)
        finally:
            if child is not None:
                if failure:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    code = child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    failure = failure or 'original-child-close-timeout'
                    os.killpg(child.pid, signal.SIGKILL)
                    code = child.wait()
            for key in list(selector.get_map().values()):
                key.fileobj.close()
            selector.close()
            for stream in streams.values():
                stream.close()
            result = dict(role=role, argv=argv, timeoutSeconds=timeout, groupRssLimitBytes=rss_limit, originalReturn=code, captureFailure=failure,
                capturedBytes=written, elapsedSeconds=time.monotonic()-started, peakObservedGroupRssBytes=peak,
                finalFreeDiskBytes=free(), stdoutSha256=sha(part / 'stdout.log'), stderrSha256=sha(part / 'stderr.log'))
            results.append(result)
            (part / 'original-return.json').write_text(json.dumps(result, indent=2) + '\n')
            (part / 'resource-observations.json').write_text(json.dumps(observations, indent=2) + '\n')
            print(json.dumps(result), flush=True)
        if failure or code != 0:
            raise SystemExit(1)
