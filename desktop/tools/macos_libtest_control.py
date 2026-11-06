"""Fixed exact-product libtest preparation and two bounded stream recorders.

The shell invokes Cargo and waits each original recorder once. GitHub owns
step deadlines. No tests, shipping role, application launch or signing occur.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time

PRODUCT = "239d2df45c41f880063ed0bec583edc8a49c148b"
TREE = "9045790f52172218d5b0befb6e1f451b35afc105"
INVENTORY = "5e30e90394d276b4b1d7d7ec232ac1748c768249116044fb8503403fb10831cc"
BRANCH = "refs/heads/codex/macos-libtest-control"
WORKFLOW = ".github/workflows/desktop-macos-libtest-control.yml"
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
RUST_BIN = Path("/Users/runner/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin")
TARGET = "aarch64-apple-darwin"
LIMIT = 4 * 1024 * 1024
META_LIMIT = 65536
ROLES = ("npm-ci", "frontend-build", "locked-dependency-fetch", "application-libtest-build")
STREAMS = ("stdout", "stderr")
CONTROL_FILES = ("macos_libtest_control.py", "macos_libtest_control.sh", "macos_libtest_artifact.py")
RUST_COMMIT = "48a229ceaefd4985c50990b14116b6d856af0985"
FIXTURES = (
    ('MRK_OUTPUT_DATA_CORPUS', 'corpus.json', 679465, 'a2b4132dd4d7a5d9ba4c824d731e4587fcd6825f5f498931d2b8b782ae0631b2'),
    ('MRK_OUTPUT_DATA_INVENTORY', 'inventory.json', 1402721, 'beb7a406091cef70e0e7799450bab1cd90a969436d7c1ae231b3c49b133a350a'),
    ('MRK_OUTPUT_DATA_PATH_QUOTES', 'path-quotes.json', 1067553, '3bbd9b6c157b1d251429bd5d9fbd04025ab24b247786ece4328c1531694d1321'),
)



def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def save(path, value):
    body = canonical(value)
    need(len(body) <= META_LIMIT, "control-metadata-bound")
    with path.open("xb", buffering=0) as output:
        need(output.write(body) == len(body), "control-metadata-short-write")
        os.fsync(output.fileno())


def data(path):
    with path.open("rb") as stream: body=stream.read(META_LIMIT+1)
    need(0 < len(body) <= META_LIMIT, "control-metadata-bound")
    return json.loads(body)


def git(*args):
    # Existing source inventory's ordinary read-only Git primitive.
    result = subprocess.run(["/usr/bin/git", "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null", *args], cwd=CHECKOUT,
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    need(len(result.stdout) <= 2 * 1024 * 1024 and len(result.stderr) <= 65536, "control-git-bound")
    return result.stdout


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_hash(path, maximum):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "control-file-type-bound")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        need(identity(before) == identity(os.fstat(stream.fileno())), "control-file-open")
        count=0
        while count<before.st_size:
            block=stream.read(min(65536,before.st_size-count));need(bool(block),'control-file-short')
            h.update(block);count+=len(block)
        need(not stream.read(1),'control-file-growth')
        need(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()), "control-file-post")
    return {"bytes": before.st_size, "sha256": h.hexdigest()}


def inventory(output=None):
    # Same tracked-blob/size/mode rule as the reviewed source recipe. Untracked
    # generated frontend files are not substituted for any tracked product input.
    rows = git("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0")
    need(rows[-1] == b"" and len(rows) <= 4096, "control-source-count")
    files = []
    for row in rows[:-1]:
        header, raw_name = row.split(b"\t", 1)
        mode, kind, blob = header.split(b" ")
        name = raw_name.decode("utf-8", "strict")
        need(kind == b"blob" and mode in (b"100644", b"100755")
             and not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/")), "control-source-path")
        path = CHECKOUT / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size <= 32 * 1024 * 1024, "control-source-file")
            digest = hashlib.sha256()
            blob_digest = hashlib.sha1(b"blob " + str(before.st_size).encode() + b"\0")
            size = 0
            while block := os.read(fd, 65536):
                size += len(block)
                need(size <= before.st_size, "control-source-growth")
                digest.update(block)
                blob_digest.update(block)
            need(size == before.st_size and identity(before) == identity(os.fstat(fd))
                 == identity(path.lstat()) and blob_digest.hexdigest() == blob.decode()
                 and bool(before.st_mode & 0o111) == (mode == b"100755"), "control-source-post")
        finally:
            os.close(fd)
        files.append({"path": name, "gitMode": mode.decode(), "blob": blob.decode(),
                      "size": size, "sha256": digest.hexdigest()})
    raw = canonical({"source": PRODUCT, "tree": TREE, "files": files})
    need(len(raw) <= 2 * 1024 * 1024, "control-source-inventory-bound")
    need(len(files)==3943 and hashlib.sha256(raw).hexdigest()==INVENTORY,"exact-frozen-product-inventory")
    if output is not None:
        write_bytes(output,raw,2*1024*1024)
    return {"files": len(files), "bytes": sum(row["size"] for row in files),
            "inventorySha256": hashlib.sha256(raw).hexdigest()}


def context(work):
    need(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0
         and os.getuid() == os.geteuid() and sys.version_info[:3] == (3, 14, 7)
         and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, "control-host")
    expected = {"GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit", "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": BRANCH, "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                "RUNNER_ARCH": "ARM64", "GITHUB_WORKSPACE": str(CHECKOUT)}
    need(all(os.environ.get(k) == v for k, v in expected.items()), "control-route")
    need(re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", ""))
         and os.environ.get("GITHUB_WORKFLOW_SHA") == os.environ["GITHUB_SHA"]
         and os.environ.get("GITHUB_WORKFLOW_REF") == "Apdelrahman1911/mobile-release-kit/" + WORKFLOW + "@" + BRANCH,
         "control-workflow-source")
    need(re.fullmatch(r"/Users/runner/work/_temp/mrk-macos-libtest-control\.[A-Za-z0-9_]+", str(work))
         and work.is_dir() and not work.is_symlink() and stat.S_IMODE(work.stat().st_mode) == 0o700, "control-work")
    return {"controlSource": os.environ["GITHUB_SHA"], "productSource": PRODUCT, "productTree": TREE,
            "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"]}


def commands(node, npm, work):
    cargo = str(RUST_BIN / "cargo")
    return {
        "npm-ci": [str(node), str(npm), "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(work / "npm-cache")],
        "frontend-build": [str(node), str(npm), "run", "build"],
        "locked-dependency-fetch": [cargo, "fetch", "--locked", "--target", TARGET, "--manifest-path", "Cargo.toml"],
        "application-libtest-build": [cargo, "test", "--locked", "--jobs", "1", "--target", TARGET,
            "--message-format=json-render-diagnostics", "--offline", "--release", "--no-default-features",
            "--config", "profile.release.package.mobile-release-kit-desktop.opt-level=1", "--lib", "--no-run"],
    }


def environment(node, work, release, npm=False):
    base = dict(PATH=str(RUST_BIN) + ":" + str(node.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        HOME="/Users/runner", CARGO_HOME="/Users/runner/.cargo", RUSTUP_HOME="/Users/runner/.rustup",
        RUSTC=str(RUST_BIN / "rustc"), RUSTUP_TOOLCHAIN="1.98.1", RUSTUP_AUTO_INSTALL="0", CARGO_INCREMENTAL="0",
        CARGO_TARGET_DIR=str(work / "cargo-target"), TMPDIR=str(work / "compile-tmp"), LANG="C", LC_ALL="C", TZ="UTC",
        CI="true", DEVELOPER_DIR="/Library/Developer/CommandLineTools", MACOSX_DEPLOYMENT_TARGET="26.0",
        MRK_MACOS_INSTALL_SOURCE_COMMIT=PRODUCT, MRK_IMAGE_RELEASE_ID=release)
    if npm:
        base.update(HOME=str(work / "compile-home"), npm_config_userconfig=str(work / "compile-user.npmrc"),
            npm_config_globalconfig=str(work / "compile-global.npmrc"), npm_config_registry="https://registry.npmjs.org/",
            npm_config_cache=str(work / "npm-cache"), npm_config_update_notifier="false")
    return base


def consume(stream, output, limit=LIMIT):
    """Bounded prefix recorder only. Overflow and write errors still drain input."""
    total = kept = 0
    complete_hash, prefix_hash = hashlib.sha256(), hashlib.sha256()
    error = None
    eof = False
    # read1 performs one underlying pipe read, retaining short live bursts
    # immediately instead of waiting to fill a 64KiB buffered read.
    read = getattr(stream, "read1", stream.read)
    while True:
        try:
            block = read(65536)
        except Exception:
            error = error or "input-read-failed"
            break
        if type(block) is not bytes:
            error = error or "input-read-type"
            break
        if not block:
            eof = True
            break
        total += len(block)
        complete_hash.update(block)
        piece = block[:max(0, limit - kept)] if error is None else b""
        if piece:
            try:
                count = output.write(piece)
                if type(count) is not int or not 0 <= count <= len(piece):
                    error = "output-write-count"
                else:
                    prefix_hash.update(piece[:count])
                    kept += count
                    if count != len(piece):
                        error = "output-short-write"
            except Exception:
                error = "output-write-failed"
    return dict(totalBytes=total, retainedBytes=kept, truncated=total > kept, eof=eof,
        captureError=error, complete=eof and error is None and total == kept,
        retainedSha256=prefix_hash.hexdigest(), completeStreamSha256=complete_hash.hexdigest() if eof else None)


def optional_data(path):
    """Interrupted sidecars are observations of unknown state, never fatal to collection."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            return {"value": None, "state": "oversized"}
        value = json.loads(raw)
        # Enforce an explicit DATA depth bound across Python versions; parser
        # recursion limits do not consistently reject deeply nested JSON.
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            need(depth <= 32, "control-sidecar-depth")
            if type(item) is dict:
                pending.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, depth + 1) for child in item)
        # Includes exponent overflow (1e999) and JSON NaN/Infinity extensions.
        canonical(value)
        if type(value) is not dict:
            return {"value": None, "state": "wrong-shape"}
        return {"value": value, "state": "read", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    except FileNotFoundError:
        return {"value": None, "state": "missing"}
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {"value": None, "state": "partial-or-unreadable"}


def write_bytes(path,raw,limit,mode=0o600):
    need(type(raw) is bytes and len(raw)<=limit,'retained-output-bound')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        view=memoryview(raw)
        while view:
            n=os.write(fd,view);need(0<n<=len(view),'retained-output-short-write');view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)


def role_result(work,role):
    started=data(work/(role+'-started.json'))
    original=data(work/(role+'-original.json'))
    readers=data(work/(role+'-readers.json'))
    streams={name:data(work/(role+'-'+name+'-sink.json')) for name in STREAMS}
    need(started['role']==original['role']==role and type(original['originalReturn']) is int
         and original['originalReturn']==0 and readers['original']==original
         and readers['components']==[0,0] and all(type(n) is int for n in readers['components'])
         and readers['streams']==streams,'original-command-or-reader-return')
    for name,sink in streams.items():
        need(sink['complete'] is True and sink['eof'] is True and sink['captureError'] is None
             and sink['truncated'] is False and sink['inputCloseReturned'] is True
             and sink['outputCloseReturned'] is True and sink['totalBytes']==sink['retainedBytes']
             and sink['completeStreamSha256']==sink['retainedSha256'],'complete-original-stream')
        need(file_hash(work/(role+'.'+name),LIMIT)=={'bytes':sink['retainedBytes'],'sha256':sink['retainedSha256']},'original-stream-file-changed')
    need(sum(sink['totalBytes'] for sink in streams.values())<=LIMIT,'combined-command-capture-bound')
    return dict(role=role,start=started,original=original,readerReturns=readers['components'],streams=streams)


def collect_data(work,bound):
    rows=[]
    for role in ROLES:
        observations={name:optional_data(work/(role+suffix)) for name,suffix in
            (('start','-started.json'),('original','-original.json'),('readers','-readers.json'),
             ('stdout','-stdout-sink.json'),('stderr','-stderr-sink.json'))}
        rows.append({'role':role,'observations':observations})
    return dict(bound,kind='mrk-libtest-only-command-observations-v1',commands=rows,
        originalResultMissingMeansUnknown=True,partialTimeoutLogNeverQualifies=True,
        streamLimitBytes=LIMIT,qualificationCombinedCommandLimitBytes=LIMIT,
        temporaryAggregateStreamLimitBytes=8*LIMIT,testsExecuted=False,signed=False,installed=False,
        fullUnsignedSequenceQualified=False,shippingQualified=False)


def fixtures():
    rows=[]
    for key,name,size,digest in FIXTURES:
        path=CHECKOUT/'.github/fixtures/macos-output-data'/name
        need(file_hash(path,size)=={'bytes':size,'sha256':digest},'public-fixture-binding')
        rows.append(dict(environment=key,path='.github/fixtures/macos-output-data/'+name,bytes=size,sha256=digest))
    return rows


def tool_post(work):
    selected=data(work/'tool-binding.json')
    for name,expected in selected['tools'].items():
        need(file_hash(Path(name),128*1024*1024)==expected,'control-tool-changed')
    return selected


def retain_executable(original,retained):
    # Same original copy/hash/post/independent-close rules as existing libtest retention.
    source_fd=target_fd=None
    first=None;result=None
    try:
        source_fd=os.open(original,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        info=os.fstat(source_fd);before=identity(info)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
             and info.st_mode&0o111 and not info.st_mode&0o022 and 0<info.st_size<=512*1024*1024
             and before==identity(original.lstat()),'original-libtest-file')
        target_fd=os.open(retained,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o700)
        h=hashlib.sha256();count=0;header=b''
        while count<info.st_size:
            block=os.read(source_fd,min(65536,info.st_size-count));need(bool(block),'original-libtest-short')
            if not header:header=block[:16]
            h.update(block);count+=len(block);view=memoryview(block)
            while view:
                n=os.write(target_fd,view);need(0<n<=len(view),'retained-libtest-short');view=view[n:]
        need(not os.read(source_fd,1) and before==identity(os.fstat(source_fd))==identity(original.lstat()),'original-libtest-post')
        need(len(header)==16 and header[:4]==bytes.fromhex('cffaedfe')
             and int.from_bytes(header[4:8],'little')==0x0100000c
             and int.from_bytes(header[12:16],'little')==2,'actual-arm64-executable-header')
        os.fsync(target_fd)
        result={'bytes':count,'sha256':h.hexdigest(),'originalIdentity':list(before),'machO':'arm64-MH_EXECUTE'}
    except BaseException as error:first=error
    finally:
        for fd in (target_fd,source_fd):
            if fd is not None:
                try:os.close(fd)
                except BaseException as error:
                    if first is None:first=error
    if first is not None:raise first
    need(file_hash(retained,512*1024*1024)=={'bytes':result['bytes'],'sha256':result['sha256']},'retained-libtest-post')
    return result


def qualify(work,bound):
    need(git("rev-parse","HEAD").decode().strip()==PRODUCT and git("rev-parse","HEAD^{tree}").decode().strip()==TREE,"exact-product-final-head")
    commands_done=[role_result(work,role) for role in ROLES]
    source_post=inventory();need(source_post==data(work/'product-before.json'),'product-source-post')
    tools=tool_post(work);fixture_rows=fixtures()
    frontend=data(work/'frontend-original.json')
    need(frontend==file_hash(CHECKOUT/'desktop/dist/index.html',1024*1024) and frontend['bytes']>0,'genuine-frontend-post')
    build=commands_done[-1]
    with (work/'application-libtest-build.stdout').open('rb') as stream:raw=stream.read(LIMIT+1)
    need(len(raw)<=LIMIT,'cargo-stdout-bound')
    spec=importlib.util.spec_from_file_location('exact_libtest_artifact',work/'macos_libtest_artifact.py')
    parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
    original,artifact=parser.remaining_artifact_data(raw,CHECKOUT,work,'application-libtest-build')
    fact=retain_executable(original,work/'bundle/application-libtest');artifact.update(fact)
    write_bytes(work/'bundle/application-libtest-build.stdout',raw,LIMIT)
    need(inventory()==source_post,'product-source-final-post');tool_post(work);fixtures()
    need(file_hash(CHECKOUT/'desktop/dist/index.html',1024*1024)==frontend,'frontend-final-post')
    provenance=dict(schemaVersion=1,kind='unsigned-app-libtest-only-for-local-exact-data-v1',
        source=PRODUCT,sourceTree=TREE,workflowSource=bound['controlSource'],**bound,target=TARGET,
        rustRelease='1.98.1',rustCommit=RUST_COMMIT,release=tools['release'],artifact=artifact,
        compilerCommand=build,compilerEnvironment=build['start']['environment'],
        sourceInventorySha256=source_post['inventorySha256'],fixtures=fixture_rows,
        sourcePost=True,toolsPost=True,frontendGenerated=True,frontendPost=frontend,
        originalPending=False,testsExecuted=False,signed=False,installed=False,shippingQualified=False,
        stderrRetention=dict(artifactPrefix='macos-libtest-only-diagnostics',file='application-libtest-build.stderr',
                             **build['streams']['stderr']))
    save(work/'bundle/application-libtest-provenance.json',provenance)
    receipt=dict(schemaVersion=1,kind='mrk-libtest-only-compile-receipt-v1',scope='fixed-arm-application-libtest-only',
        source=PRODUCT,sourceTree=TREE,workflowSource=bound['controlSource'],**bound,target=TARGET,
        commands=commands_done,sourceInventorySha256=source_post['inventorySha256'],sourcePost=True,toolsPost=True,
        frontendGenerated=True,frontendPost=frontend,fixtures=fixture_rows,tools=tools,artifact=artifact,
        libtestRetained=True,libtestCompiled=True,originalPending=False,testsExecuted=False,
        shippingQualified=False,fullUnsignedSequenceQualified=False,signed=False,installed=False)
    save(work/'bundle/compile-receipt.json',receipt)
    # This last marker follows every artifact/source/tool check and original file close.
    save(work/'bundle-qualified.json',dict(bound,members=['application-libtest','application-libtest-provenance.json',
        'application-libtest-build.stdout','source-inventory.json','compile-receipt.json'],libtestCompiled=True))


def record_stream(work,role,stream_name):
    need(stream_name in STREAMS,'fixed-stream')
    inp=output=None;error=None;result=None;closed={'inputCloseReturned':False,'outputCloseReturned':False}
    try:
        inp=(work/(role+'-'+stream_name+'.fifo')).open('rb')
        try:output=(work/(role+'.'+stream_name)).open('r+b',buffering=0)
        except BaseException:error='stream-output-open-failed'
        class Discard:
            def write(self,block):raise OSError('output unavailable')
        result=consume(inp,output if output is not None else Discard())
        if output is not None:os.fsync(output.fileno())
    except BaseException:error='stream-open-or-sync-failed'
    finally:
        for name,original in (('outputCloseReturned',output),('inputCloseReturned',inp)):
            if original is not None:
                try:original.close();closed[name]=True
                except BaseException:error=error or 'stream-close-failed'
    if result is None:
        result=dict(totalBytes=0,retainedBytes=0,truncated=False,eof=False,captureError=error,
            complete=False,retainedSha256=hashlib.sha256(b'').hexdigest(),completeStreamSha256=None)
    result.update(closed)
    if error or not all(closed.values()):result.update(captureError=error or 'stream-close-unknown',complete=False)
    save(work/(role+'-'+stream_name+'-sink.json'),result)
    return 0 if result['complete'] else 1


def main():
    action, work_text, *args = sys.argv[1:]
    work = Path(work_text)
    bound = context(work)
    if action == "bootstrap":
        need(git("rev-parse", "HEAD").decode().strip() == bound["controlSource"], "control-checkout")
        expected = {}
        for name in CONTROL_FILES:
            original = CHECKOUT / "desktop/tools" / name
            expected[name] = file_hash(original, 65536)
            need(file_hash(work / name, 65536) == expected[name], "control-copy")
        save(work / "control-binding.json", dict(bound, controls=expected,
            workflow=file_hash(CHECKOUT / WORKFLOW, 65536),libtestOnly=True))
        (work / "evidence").mkdir(mode=0o700)
        (work / "bundle").mkdir(mode=0o700)
        return
    binding = data(work / "control-binding.json")
    need(all(binding[k] == v for k, v in bound.items()), "control-binding")
    for name, expected in binding["controls"].items():
        need(file_hash(work / name, 65536) == expected, "control-script-changed")
    if action == "prepare":
        need(git("rev-parse", "HEAD").decode().strip() == PRODUCT
             and git("rev-parse", "HEAD^{tree}").decode().strip() == TREE
             and not git("status", "--porcelain=v1", "--untracked-files=all"), "control-product-checkout")
        for path in (CHECKOUT / "desktop/node_modules", CHECKOUT / "desktop/dist"):
            need(not path.exists() and not path.is_symlink(), "control-fresh-frontend")
        for parent in (CHECKOUT / "desktop", *(CHECKOUT / "desktop").parents):
            need(not (parent / ".npmrc").exists() and not (parent / ".npmrc").is_symlink(), "control-npm-config")
        for name in ("npm-cache", "compile-home", "compile-tmp", "cargo-target"):
            (work / name).mkdir(mode=0o700)
        for name in ("compile-user.npmrc", "compile-global.npmrc"):
            (work / name).touch(mode=0o600, exist_ok=False)
        save(work / "product-before.json", inventory(work/"bundle/source-inventory.json"))
        return
    if action == "bind-tools":
        node, npm = Path(shutil.which("node")).resolve(strict=True), Path(shutil.which("npm")).resolve(strict=True)
        need(npm == node.parent.parent / "lib/node_modules/npm/bin/npm-cli.js", "control-npm-distribution")
        release = json.loads((CHECKOUT / "desktop/macos-installed-inputs/build-release.json").read_bytes())["release"]
        need(re.fullmatch(r"[a-z0-9_.-]{1,63}", release), "control-release")
        version = subprocess.run([str(node), "--version"], check=True, capture_output=True, timeout=15,
            env=environment(node, work, release), cwd=CHECKOUT / "desktop")
        need(version.stdout == b"v24.20.0\n" and version.stderr == b"", "control-node-version")
        npm_version = subprocess.run([str(node), str(npm), "--version"], check=True, capture_output=True, timeout=15,
            env=environment(node, work, release, npm=True), cwd=CHECKOUT / "desktop")
        need(len(npm_version.stdout) <= 4096 and not npm_version.stderr
             and re.fullmatch(rb"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\n", npm_version.stdout), "control-npm-version")
        tools = {str(p): file_hash(p, 128 * 1024 * 1024) for p in (node, npm, RUST_BIN / "cargo", RUST_BIN / "rustc", Path(sys.executable).resolve(strict=True))}
        for tool in ('rustc','cargo'):
            observed=subprocess.run([str(RUST_BIN/tool),'--version','--verbose'],check=True,capture_output=True,timeout=15,
                env=environment(node,work,release),cwd=CHECKOUT/'desktop/src-tauri')
            need(len(observed.stdout)<=65536 and not observed.stderr,'direct-rust-version-output')
            need(('release: 1.98.1\n' in observed.stdout.decode()) if tool=='rustc' else observed.stdout.startswith(b'cargo 1.98.1 '),'pinned-rust-release')
            if tool=='rustc':need(('commit-hash: '+RUST_COMMIT+'\n').encode() in observed.stdout,'pinned-rust-commit')
        save(work / "tool-binding.json", {"tools": tools, "python": str(Path(sys.executable).resolve(strict=True)), "node": str(node), "npm": str(npm), "release": release,
            "nodeVersion": version.stdout.decode().strip(), "npmVersion": npm_version.stdout.decode().strip()})
        return
    if action == "collect":
        save(work / "evidence/control.json", collect_data(work, bound))
        return
    selected_python=data(work/"tool-binding.json")["python"]
    need(str(Path(sys.executable).resolve(strict=True))==selected_python,"actual-python-selection")
    role = args[0] if args else None
    if action in ("begin", "returned", "record", "end"):
        need(role in ROLES, "control-role")
    if action == "record":
        raise SystemExit(record_stream(work,role,args[1]))
    if action == "returned":
        status = int(args[1])
        need(0 <= status <= 255, "control-original-status")
        save(work / (role + "-original.json"), {"role": role, "originalReturn": status,
            "returnedMonotonicNs": time.monotonic_ns(), "elapsedShellSeconds": int(args[2]),
            "elapsedPrecision": "whole Bash SECONDS; excludes later recorder drain",
            "origin": "shell-direct-command-question-mark"})
        return
    if action == "end":
        components=[int(n) for n in args[1:]]
        need(len(components)==2 and all(0<=n<=255 for n in components),'original-reader-status')
        original=data(work/(role+'-original.json'))
        streams={name:data(work/(role+'-'+name+'-sink.json')) for name in STREAMS}
        save(work/(role+'-readers.json'),dict(components=components,original=original,streams=streams))
        role_result(work,role)
        if role=='frontend-build':save(work/'frontend-original.json',file_hash(CHECKOUT/'desktop/dist/index.html',1024*1024))
        return
    if action == "begin":
        for previous in ROLES[:ROLES.index(role)]:role_result(work,previous)
        need(inventory() == data(work / "product-before.json"), "control-product-changed")
        selected = data(work / "tool-binding.json")
        for name, expected in selected["tools"].items():
            need(file_hash(Path(name), 128 * 1024 * 1024) == expected, "control-tool-changed")
        node, npm = Path(selected["node"]), Path(selected["npm"])
        argv = commands(node, npm, work)[role]
        env = environment(node, work, selected["release"], role in ROLES[:2])
        if role=='application-libtest-build':
            fixtures()
            for key,name,_,_ in FIXTURES:env[key]=str(CHECKOUT/'.github/fixtures/macos-output-data'/name)
            env.pop('MRK_IMAGE_RELEASE_ID',None)
        cwd = CHECKOUT / ("desktop" if role in ROLES[:2] else "desktop/src-tauri")
        save(work / (role + "-started.json"), dict(bound, role=role, argv=argv, environment=env,
            cwd=str(cwd), startedMonotonicNs=time.monotonic_ns(), supervision="github-step-only",
            outputMode="separate-original-stdout-stderr", logLimitBytes=LIMIT))
        for name in STREAMS:
            (work/(role+'.'+name)).touch(mode=0o600,exist_ok=False)
            os.mkfifo(work/(role+'-'+name+'.fifo'),0o600)
        text = "command=(" + " ".join(shlex.quote(v) for v in argv) + ")\n"
        text += "command_environment=(" + " ".join(shlex.quote(k + "=" + v) for k, v in env.items()) + ")\n"
        text += "command_cwd=" + shlex.quote(str(cwd)) + "\n"
        with (work / (role + "-command.sh")).open("x") as out:
            out.write(text)
        return
    if action == "qualify":
        qualify(work,bound)
        return
    raise ValueError("control-action")


if __name__ == "__main__":
    main()
