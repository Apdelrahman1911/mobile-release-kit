"""Bounded original process-group owner; caller holds the compiler lock."""
from pathlib import Path
import hashlib, json, os, selectors, signal, subprocess, time
CAP=4*1024**2
RSS_LIMIT=3*1024**3
FREE_FLOOR=2*1024**3
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def run(commands,D,E,env):
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
                    observations.append(dict(elapsedSeconds=now-started, processes=rows, groupRssBytes=rss, freeDiskBytes=free()))
                    if rss > RSS_LIMIT:
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
            result = dict(role=role, argv=argv, timeoutSeconds=timeout, originalReturn=code, captureFailure=failure,
                capturedBytes=written, elapsedSeconds=time.monotonic()-started, peakObservedGroupRssBytes=peak,
                finalFreeDiskBytes=free(), stdoutSha256=sha(part / 'stdout.log'), stderrSha256=sha(part / 'stderr.log'))
            results.append(result)
            (part / 'original-return.json').write_text(json.dumps(result, indent=2) + '\n')
            (part / 'resource-observations.json').write_text(json.dumps(observations, indent=2) + '\n')
            print(json.dumps(result), flush=True)
        if failure or code != 0:
            raise SystemExit(1)
