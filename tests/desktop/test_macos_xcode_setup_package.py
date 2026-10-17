"""One explicitly selected hosted PackageKit probe; never native setup authority.

Ordinary discovery skips this method. The fixed synthetic package has no Xcode,
A helper, credential or project input. A client timeout preserves the fixture:
joining/killing that client is not PackageKit service finality.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import resource
import shutil
import stat
import subprocess
import sys
import time
import tempfile
import unittest


PROBE_ID = "dev.mobile-release-kit.desktop.xcode-setup.probe"
PROBE_BUNDLE = "MobileReleaseKitXcodeSetupProbe.bundle"
CALLBACK = b"MRK_XCODE_COMPONENT_CALLBACK=once\n"

def _command_failure(work, repo, argv, sequence, *, returncode=None, timed_out=False):
    """Only this probe's fixed public commands; never environment/host-log capture."""
    def excerpt(suffix):
        try:
            fd = os.open(work / (str(sequence) + suffix), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 1024 * 1024:
                    return "capture-unavailable"
                os.lseek(fd, max(0, info.st_size - 4096), os.SEEK_SET)
                text = os.read(fd, 4096).decode("utf-8", "replace")
            finally:
                os.close(fd)
        except OSError:
            return "capture-unavailable"
        for path, label in sorted(((work, "<task>"), (repo, "<checkout>")), key=lambda row: len(str(row[0])), reverse=True):
            text = text.replace(str(path), label)
        text = "".join(char if 32 <= ord(char) < 127 else "\\u%04x" % ord(char) for char in text)
        return text[-2048:]

    executable = argv[2] if argv[:2] == ["/usr/bin/sudo", "-n"] else argv[0]
    value = {"tool": Path(executable).name, "sequence": sequence,
             "outcome": "timeout" if timed_out else "exit", "returncode": returncode,
             "stdout": excerpt(".stdout"), "stderr": excerpt(".stderr")}
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    # One failed command ends this test; never replace somebody else's record.
    with (work / "Failure.json").open("xb") as output:
        output.write(body)
    return value


class XcodeSetupProbeDiagnostics(unittest.TestCase):
    def test_setup_hook_diagnostics_preserve_refusal_and_helper_exit(self):
        # Ordinary shell with a task-local inert helper, never PackageKit/root.
        source = Path(__file__).resolve().parents[2] / "desktop/macos-xcode-setup-inputs"
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp)
            (scripts / "setup").mkdir()
            helper = scripts / "setup/mrk-macos-xcode-setup"
            helper.write_text("#!/bin/sh\nprintf 'synthetic-helper\\n'\nexit 23\n")
            helper.chmod(0o700)
            for hook, relative in (("preinstall", "preinstall"), ("postinstall", "setup/postinstall")):
                body = (source / relative).read_bytes()
                (scripts / relative).write_bytes(body)
                prefix = ("MRK_XCODE_HOOK=hook=" + hook + ";stage=").encode()
                for target, code, marker in (("/", 23, b"pre-exec"), ("/unrelated", 1, b"target-refused")):
                    with self.subTest(hook=hook, target=target):
                        result = subprocess.run(["/bin/sh", "./" + relative, "synthetic.pkg", "/", target],
                            cwd=scripts, env={"PATH": "/usr/bin:/bin"}, capture_output=True, timeout=5)
                        self.assertEqual(result.returncode, code)
                        self.assertEqual(result.stderr.splitlines(), [prefix + b"entry", prefix + marker])
                        self.assertEqual(result.stdout, b"synthetic-helper\n" if target == "/" else b"")
                # An unrecognized callback path still refuses before helper entry.
                result = subprocess.run(["/bin/sh", "-c", body.decode(), "unrecognized",
                    "synthetic.pkg", "/", "/"], cwd=scripts, env={"PATH": "/usr/bin:/bin"},
                    capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr.splitlines(), [prefix + b"entry", prefix + b"path-refused"])
                self.assertEqual(result.stdout, b"")

    def test_failed_and_timed_out_commands_keep_bounded_public_diagnostics(self):
        # Real task-file IO and exact helper used by run(); no native/process call.
        for timed_out in (False, True):
            with self.subTest(timeout=timed_out), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                repo = work / "checkout"
                (work / "3.stdout").write_bytes((str(work)+" output\x1b\n").encode())
                (work / "3.stderr").write_bytes(("\u2603" * 5000 + str(repo) + " failure").encode())
                actual = _command_failure(work, repo, ["/usr/bin/sudo", "-n", "/usr/sbin/installer"], 3,
                                          returncode=None if timed_out else 75, timed_out=timed_out)
                raw = (work / "Failure.json").read_bytes()
                self.assertEqual(actual["tool"], "installer")
                self.assertEqual(actual["sequence"], 3)
                self.assertEqual(actual["outcome"], "timeout" if timed_out else "exit")
                self.assertEqual(actual["returncode"], None if timed_out else 75)
                self.assertEqual(json.loads(raw), actual)
                self.assertLessEqual(len(actual["stdout"])+len(actual["stderr"]), 4096)
                self.assertLess(len(raw), 8192)
                self.assertTrue(raw.isascii())
                self.assertNotIn(str(work), raw.decode())
                self.assertNotIn("\x1b", raw.decode())
                self.assertIn("<task>", actual["stdout"])
                self.assertIn("<checkout> failure", actual["stderr"])
                with self.assertRaises(FileExistsError):
                    _command_failure(work, repo, ["/usr/bin/pkgbuild"], 3, returncode=1)
                self.assertEqual((work / "Failure.json").read_bytes(), raw)


    def test_library_acl_wiring_uses_full_original_snapshot_and_preserves_absence_kind(self):
        # Reuse the actual filesec implementation and existing inert ABI library;
        # real held local FD conversion only, not a Darwin/native observation.
        from types import SimpleNamespace
        path = Path(__file__).resolve().with_name("test_macos_xcode_host_preparation.py")
        spec = importlib.util.spec_from_file_location("probe_existing_acl_fixture", path)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        host = fixture.M
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o755)
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                results = []
                for options in ({}, {"present": 32}, {"changed_snapshot": True}, {"present": 32, "free_result": -1}):
                    with self.subTest(options=options):
                        library = fixture.ACLLibraryData(**options)
                        library.expected = host.full9(os.fstat(fd))
                        checks = []
                        api = SimpleNamespace(library=library, deadline=SimpleNamespace(check=lambda: checks.append(True)))
                        scope = {"api": api, "host": host, "os": os, "stat": stat}
                        exec(_LIBRARY_FACTS, scope)
                        if "changed_snapshot" in options or "free_result" in options:
                            with self.assertRaises(AssertionError):
                                scope["library_facts"](fd)
                        else:
                            result = scope["library_facts"](fd)
                            self.assertEqual(result["inode"], os.fstat(fd).st_ino)
                            self.assertEqual(result["acl"], {"kind": "empty-valid-acl" if options else "absent",
                                                            "present": 32 if options else 0})
                            self.assertEqual(checks, [True, True])
                            results.append(result)
                        self.assertIn(("fstatx_np", fd, 0x1000), library.calls)
                        self.assertEqual(library.calls.count(("filesec_free", 0x1000)), 1)
                self.assertNotEqual(results[0], results[1])  # Empty is not rewritten as absent.
            finally:
                os.close(fd)


# The same short function is exercised by the inert wiring test and root observer.
_LIBRARY_FACTS = r'''
def library_facts(fd):
    api.deadline.check()
    info=os.fstat(fd)
    assert stat.S_IMODE(info.st_mode)==0o755
    # A NULL acl_get_fd_np/ENOENT is not proof of absence. Reuse the complete
    # same-FD filesec snapshot/property/presence and consuming-free checks.
    acl=host._acl_snapshot(api.library,fd,host.full9(info))
    assert acl['empty'] and acl['filesecFreeReturned'], ('library-acl-snapshot',acl['phase'],acl['kind'])
    assert acl['kind'] in ('absent','empty-valid-acl')
    assert host.full9(os.fstat(fd))==host.full9(info)
    api.deadline.check()
    return {'device':info.st_dev,'inode':info.st_ino,'mode':stat.S_IMODE(info.st_mode),
            'uid':info.st_uid,'gid':info.st_gid,'acl':{'kind':acl['kind'],'present':acl['present']}}
'''


# Fixed observer only, used on the disposable hosted machine. No source/dest
# path parameter, root recursive deletion, or production preflight dispatch.
_OBSERVER = r'''
import base64,hashlib,importlib.util,json,os,plistlib,stat,sys,time
assert os.getuid()==os.geteuid()==0
assert len(sys.argv)==2 and sys.argv[1] in ('absent','inspect','remove-marker','finish')
# Fixed checked source, never the preparation main/permission-changing route.
spec=importlib.util.spec_from_file_location('probe_filesec',ACL_SOURCE)
host=importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
class OriginalDeadline:
    def check(self):
        assert time.monotonic()<DEADLINE, 'original probe deadline'
api=host.DarwinAPI(OriginalDeadline(),TARGET)
flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
held=[]
def identity(info):
    return tuple(getattr(info,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def stable_directory(info):
    return (info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode),stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid)
def directory(parent,name,mode=None):
    fd=os.open(name,flags|os.O_DIRECTORY,dir_fd=parent);held.append(fd)
    info=os.fstat(fd)
    assert stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and not info.st_mode&0o022
    if mode is not None: assert stat.S_IMODE(info.st_mode)==mode
    named=os.stat(name,dir_fd=parent,follow_symlinks=False)
    assert identity(info)==identity(named)
    return fd,info
''' + _LIBRARY_FACTS + r'''

def absent(parent,name):
    try: os.stat(name,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError: return
    raise AssertionError('preexisting fixed probe state')
def read(parent,name,limit,mode=None,gid=0):
    fd=os.open(name,flags,dir_fd=parent)
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1
        if gid is not None:assert before.st_gid==gid
        assert not before.st_mode&0o022 and 0<before.st_size<=limit
        if mode is not None: assert stat.S_IMODE(before.st_mode)==mode
        chunks=[];size=0
        while size<before.st_size:
            block=os.read(fd,min(4096,before.st_size-size));assert block
            chunks.append(block);size+=len(block)
        assert os.read(fd,1)==b''
        after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
        assert identity(before)==identity(after)==identity(named)
        return b''.join(chunks),before
    finally: os.close(fd)
def unlink(parent,name,original):
    assert identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==identity(original)
    os.unlink(name,dir_fd=parent)
try:
    root,_=directory(None,'/')
    library,_=directory(root,'Library')
    private,_=directory(root,'private')
    var,_=directory(private,'var')
    db,_=directory(var,'db')
    receipts,_=directory(db,'receipts')
    original_library=library_facts(library)
    action=sys.argv[1]
    if action=='absent':
        absent(library,BUNDLE)
        absent(receipts,ID+'.plist');absent(receipts,ID+'.bom')
        result={'state':'absent'}
    else:
        bundle,bundle_identity=directory(library,BUNDLE,0o555)
        contents,contents_identity=directory(bundle,'Contents',0o555)
        assert os.listdir(bundle)==['Contents']
        assert set(os.listdir(contents))=={'Info.plist','Callback.txt'}
        info,info_identity=read(contents,'Info.plist',8192,0o444)
        marker,marker_identity=read(contents,'Callback.txt',128,0o444)
        assert info==INFO and marker==MARKER
        receipt,receipt_identity=read(receipts,ID+'.plist',32768,gid=None)
        bom,bom_identity=read(receipts,ID+'.bom',65536,gid=None)
        parsed=plistlib.loads(receipt)
        assert type(parsed) is dict and len(parsed)<=64
        assert all(type(key) is str and len(key)<=256 for key in parsed)
        readable=plistlib.dumps(parsed,fmt=plistlib.FMT_XML,sort_keys=True)
        assert len(readable)<=49152
        result={'state':'observed','receiptPlist':base64.b64encode(readable).decode(),
                'receiptRaw':base64.b64encode(receipt).decode(),
                'receiptPrefix8Hex':receipt[:8].hex(),
                'receiptMode':stat.S_IMODE(receipt_identity.st_mode),'receiptUid':receipt_identity.st_uid,'receiptGid':receipt_identity.st_gid,
                'receiptFieldTypes':{key:type(value).__name__ for key,value in parsed.items()},
                'receiptBom':base64.b64encode(bom).decode(),'receiptBomSha256':hashlib.sha256(bom).hexdigest()}
        if action in ('remove-marker','finish'):
            unlink(contents,'Callback.txt',marker_identity)
        if action=='finish':
            unlink(contents,'Info.plist',info_identity)
            assert not os.listdir(contents)
            assert stable_directory(os.stat('Contents',dir_fd=bundle,follow_symlinks=False))==stable_directory(contents_identity)
            assert stable_directory(os.fstat(contents))==stable_directory(contents_identity)
            os.rmdir('Contents',dir_fd=bundle)
            assert not os.listdir(bundle)
            assert stable_directory(os.stat(BUNDLE,dir_fd=library,follow_symlinks=False))==stable_directory(bundle_identity)
            assert stable_directory(os.fstat(bundle))==stable_directory(bundle_identity)
            os.rmdir(BUNDLE,dir_fd=library)
        # Receipt deletion is ONLY the later fixed pkgutil --forget command,
        # after this original-observed carrier cleanup completed positively.
    assert library_facts(library)==original_library
    result['library']=original_library
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
finally:
    first=None
    for fd in reversed(held):
        try: os.close(fd)
        except OSError as error:
            if first is None:first=error
    if first is not None:raise first
'''


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("MRK_XCODE_SETUP_PACKAGE_PROBE") == "1",
                     "explicit hosted synthetic PackageKit probe only")
class XcodeSetupPackageNative(unittest.TestCase):
    def test_component_callback_once_reinstall_and_documented_timeout(self):
        self.assertNotEqual(os.geteuid(), 0)
        for key, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                           "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
                           "RUNNER_TEMP": "/Users/runner/work/_temp"}.items():
            self.assertEqual(os.environ.get(key), value)
        repo = Path(__file__).absolute().parents[2]
        target = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}[platform.machine()]
        source = os.environ["GITHUB_SHA"]
        self.assertRegex(source, r"^[0-9a-f]{40}$")
        self.assertEqual(source, os.environ.get("GITHUB_WORKFLOW_SHA"))
        spec = importlib.util.spec_from_file_location("xcode_setup_probe_stager", repo / "desktop/tools/stage_macos_installed.py")
        stager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(stager)
        selection = stager.source_build_selection(target)
        sources = stager.xcode_setup_sources(selection)
        work = Path(os.environ["RUNNER_TEMP"]) / "mrk-xcode-package-probe"
        work.mkdir(mode=0o700)  # No reuse or cleanup of somebody else's output.
        started = time.monotonic()
        deadline = started + 300
        counter = 0
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "LANG": "C", "LC_ALL": "C"}
        previous_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        resource.setrlimit(resource.RLIMIT_FSIZE, (min(1024 * 1024, previous_limit[0]) if previous_limit[0] >= 0 else 1024 * 1024,
                                                previous_limit[1]))
        def bounded(path, limit):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                self.assertTrue(stat.S_ISREG(before.st_mode))
                self.assertEqual(before.st_uid, os.getuid())
                self.assertLessEqual(before.st_size, limit)
                body = bytearray()
                while len(body) < before.st_size:
                    part = os.read(fd, min(4096, before.st_size - len(body)))
                    self.assertTrue(part)
                    body.extend(part)
                self.assertEqual(os.read(fd, 1), b"")
                after = os.fstat(fd)
                named = os.stat(path, follow_symlinks=False)
                fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                identity = lambda item: tuple(getattr(item, field) for field in fields)
                self.assertEqual(identity(before), identity(after))
                self.assertEqual(identity(before), identity(named))
                return bytes(body)
            finally:
                os.close(fd)

        def run(argv, *, seconds=60):
            nonlocal counter
            remaining = deadline-time.monotonic()
            self.assertGreater(remaining, 0)
            counter += 1
            out_path, err_path = (work / (str(counter) + suffix) for suffix in (".stdout", ".stderr"))
            try:
                with out_path.open("xb") as out, err_path.open("xb") as err:
                    # Standard original-client API only; TimeoutExpired kills/joins
                    # that issuer, not PackageKit. There is deliberately NO root
                    # fixture cleanup in a failure/finally branch.
                    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                            env=env, timeout=min(seconds, remaining), check=False)
                    self.assertLess(time.monotonic(), deadline, "original probe deadline after command return")
            except subprocess.TimeoutExpired:
                _command_failure(work, repo, argv, counter, timed_out=True)
                raise TimeoutError(f"fixed probe command {counter} timed out; see bounded Failure.json; preserve root fixture") from None
            if result.returncode != 0:
                _command_failure(work, repo, argv, counter, returncode=result.returncode)
            self.assertEqual(result.returncode, 0, f"fixed probe command {counter} failed; see bounded Failure.json; preserve root fixture")
            self.assertLessEqual(out_path.stat().st_size, 256 * 1024)
            self.assertLessEqual(err_path.stat().st_size, 256 * 1024)
            return bounded(out_path, 256 * 1024)
        info = plistlib.dumps({"CFBundleIdentifier": PROBE_ID, "CFBundleName": "MRK Package Callback Probe",
                               "CFBundlePackageType": "BNDL", "CFBundleVersion": selection.package_version},
                              fmt=plistlib.FMT_XML, sort_keys=True)
        observer = ("ID="+repr(PROBE_ID)+"\nBUNDLE="+repr(PROBE_BUNDLE)+"\nINFO="+repr(info)+"\nMARKER="+repr(CALLBACK)
                    +"\nACL_SOURCE="+repr(str(repo / "desktop/tools/macos_xcode_host_preparation.py"))
                    +"\nTARGET="+repr(target)+"\nDEADLINE="+repr(deadline)+"\n"+_OBSERVER)
        def observe(action):
            return json.loads(run(["/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c", observer, action], seconds=20))
        try:
            self.assertEqual(run(["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip(), source)
            run(["/usr/bin/git", "-C", str(repo), "diff", "--exit-code", "HEAD", "--",
                 "desktop/macos-xcode-setup-inputs", "desktop/tools/stage_macos_installed.py",
                 "desktop/tools/macos_xcode_host_preparation.py", str(Path(__file__).relative_to(repo))])
            initial = observe("absent")
            self.assertEqual(initial["state"], "absent")
            payload, scripts = work / "payload", work / "Scripts"
            stager.write_tree(payload, {PROBE_BUNDLE+"/Contents/Info.plist": (info, 0o444)}, root_mode=0o755)
            # Inert script fixture, not the A binary or a signing/admission stand-in.
            helper = ("#!/bin/sh\nset -eu\numask 077\n[ \"$#\" -eq 0 ] || exit 1\nset -C\n"
                      "printf '%s\\n' 'MRK_XCODE_COMPONENT_CALLBACK=once' > '/Library/"+PROBE_BUNDLE+"/Contents/Callback.txt'\n"
                      "/bin/chmod 0444 '/Library/"+PROBE_BUNDLE+"/Contents/Callback.txt'\n").encode()
            stager.write_tree(scripts, {"setup/postinstall": (sources["setup/postinstall"], 0o555),
                                       stager.XCODE_SETUP_PROGRAM: (helper, 0o555)}, root_mode=0o755)
            component = plistlib.loads(sources["Component.plist"])
            component[0]["RootRelativeBundlePath"] = PROBE_BUNDLE
            component_path = work / "Component.plist"
            component_path.write_bytes(plistlib.dumps(component, fmt=plistlib.FMT_XML))
            package, expanded = work / "Probe.pkg", work / "expanded"
            run(["/usr/bin/pkgbuild", "--root", str(payload), "--component-plist", str(component_path),
                 "--scripts", str(scripts), "--identifier", PROBE_ID, "--version", selection.package_version,
                 "--install-location", "/Library", "--ownership", "recommended", "--compression", "legacy",
                 "--min-os-version", "26.0", str(package)])
            run(["/usr/sbin/pkgutil", "--expand", str(package), str(expanded)])
            xml = bounded(expanded / "PackageInfo", 16384)
            self.assertLessEqual(len(xml), 16384)
            (work / "PackageInfo.xml").write_bytes(xml)
            bom = run(["/usr/bin/lsbom", "-p", "fmugs", str(expanded / "Bom")])
            self.assertLessEqual(len(bom), 8192)
            original_bom = bounded(expanded / "Bom", 65536)
            self.assertLessEqual(len(original_bom), 65536)
            (work / "BOM.txt").write_bytes(bom)
            (work / "Original.bom").write_bytes(original_bom)
            # Same tiny component, unsigned outer grammar observation only.
            # Reuse the source presentation, changing only its fixed package ID
            # and component filename; this product is never installed here.
            definition = sources["Distribution.xml"]
            self.assertEqual(definition.count(stager.XCODE_SETUP_ID.encode()), 2)
            self.assertEqual(definition.count(stager.XCODE_SETUP_COMPONENT.encode()), 1)
            definition = definition.replace(stager.XCODE_SETUP_ID.encode(), PROBE_ID.encode())
            definition = definition.replace(stager.XCODE_SETUP_COMPONENT.encode(), package.name.encode())
            presentation, product = work / "product-input", work / "Product.pkg"
            stager.write_tree(presentation, {"Distribution": (definition, 0o444),
                "resources/InstallerReadMe.html": (sources["InstallerReadMe.html"], 0o444)}, root_mode=0o700)
            component_sha = hashlib.sha256(bounded(package, 1024 * 1024)).hexdigest()
            run(["/usr/bin/productbuild", "--distribution", str(presentation / "Distribution"),
                 "--package-path", str(work), "--resources", str(presentation / "resources"), str(product)], seconds=30)
            self.assertEqual(hashlib.sha256(bounded(package, 1024 * 1024)).hexdigest(), component_sha)
            # Existing XAR fixed header/inflate DATA API, not another native
            # command or a relaxed shipping member parser. Retain <=64KiB TOC.
            outer = bounded(product, 1024 * 1024)
            self.assertGreaterEqual(len(outer), 28)
            magic, header, version, packed, unpacked, checksum = stager.struct.unpack_from(">IHHQQI", outer)
            self.assertEqual((magic, header, version), (0x78617221, 28, 1))
            self.assertIn(checksum, (1, 3, 4))
            self.assertTrue(0 < packed <= 65536 and 0 < unpacked <= 65536 and header + packed <= len(outer))
            toc = stager.inflate(outer[header:header + packed], unpacked)
            self.assertEqual(len(toc), unpacked)
            (work / "ProductTOC.xml").write_bytes(toc)
            tree = stager.ET.fromstring(xml)
            self.assertEqual(tree.get("identifier"), PROBE_ID)
            hooks = tree.findall(".//postinstall")
            self.assertEqual(len(hooks), 1)
            self.assertEqual(hooks[0].get("timeout"), "3800")
            self.assertIn(hooks[0].get("file"), ("setup/postinstall", "./setup/postinstall"))
            self.assertFalse(tree.findall(".//preinstall"))
            package_sha = hashlib.sha256(bounded(package, 1024 * 1024)).hexdigest()
            for iteration in (1, 2):
                self.assertEqual(hashlib.sha256(bounded(package, 1024 * 1024)).hexdigest(), package_sha)
                run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/"], seconds=90)
                observed = observe("inspect")
                self.assertEqual(observed["state"], "observed")
                self.assertEqual(observed["library"], initial["library"])
                receipt_raw = base64.b64decode(observed["receiptRaw"], validate=True)
                self.assertLessEqual(len(receipt_raw), 32768)
                self.assertEqual(receipt_raw[:8].hex(), observed["receiptPrefix8Hex"])
                (work / f"Receipt-{iteration}.plist.raw").write_bytes(receipt_raw)
                (work / f"Receipt-{iteration}.facts.json").write_text(json.dumps({
                    "prefix8Hex": observed["receiptPrefix8Hex"], "fieldTypes": observed["receiptFieldTypes"],
                    "mode": observed["receiptMode"], "uid": observed["receiptUid"], "gid": observed["receiptGid"],
                    "bytes": len(receipt_raw), "sha256": hashlib.sha256(receipt_raw).hexdigest()}, sort_keys=True)+"\n")
                receipt = base64.b64decode(observed["receiptPlist"], validate=True)
                receipt_bom = base64.b64decode(observed["receiptBom"], validate=True)
                self.assertLessEqual(len(receipt), 49152)
                self.assertLessEqual(len(receipt_bom), 65536)
                (work / f"Receipt-{iteration}.plist.xml").write_bytes(receipt)
                (work / f"Receipt-{iteration}.bom").write_bytes(receipt_bom)
                self.assertEqual(hashlib.sha256(receipt_bom).hexdigest(), observed["receiptBomSha256"])
                self.assertEqual(receipt_bom, original_bom)
                if iteration == 1:
                    observe("remove-marker")  # Never credit upgrade deleting it.
            observe("finish")
            run(["/usr/bin/sudo", "-n", "/usr/sbin/pkgutil", "--forget", PROBE_ID], seconds=20)
            self.assertEqual(observe("absent"), initial)
            result = {"sourceCommit": source, "target": target, "callbacks": 2, "installations": 2,
                      "encodedScriptTimeoutSeconds": 3800, "longRuntimeProved": False,
                      "nativeSetupQualified": False, "rootFixtureRemoved": True,
                      "libraryUnchanged": initial["library"],
                      "originalBomSha256": hashlib.sha256(original_bom).hexdigest()}
            (work / "RESULT.json").write_text(json.dumps(result, sort_keys=True)+"\n")
            # All clients returned; only this new task's build inputs can retire.
            for path in (payload, scripts, expanded, presentation):
                # Only fresh nonroot task trees; no root fixture or receipt here.
                for directory, child_dirs, files in os.walk(path, followlinks=False):
                    current = Path(directory)
                    original = current.lstat()
                    self.assertTrue(stat.S_ISDIR(original.st_mode))
                    self.assertEqual(original.st_uid, os.getuid())
                    for name in child_dirs + files:
                        node = (current / name).lstat()
                        self.assertEqual(node.st_uid, os.getuid())
                        self.assertFalse(stat.S_ISLNK(node.st_mode))
                    current.chmod(0o700)
                shutil.rmtree(path)
            package.unlink()
            product.unlink()
            component_path.unlink()
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, previous_limit)
        print("Synthetic component callback twice/receipt/BOM/encoded3800 observed; no long-runtime or native setup claim.")


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("MRK_XCODE_PRODUCT_METADATA_PROBE") == "1",
                     "explicit hosted unsigned product metadata probe only")
class XcodeSetupProductMetadataNative(unittest.TestCase):
    def test_unsigned_product_original_metadata_matches_production_parsers(self):
        self.assertNotEqual(os.geteuid(), 0)
        for key, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                           "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
                           "RUNNER_TEMP": "/Users/runner/work/_temp"}.items():
            self.assertEqual(os.environ.get(key), value)
        repo = Path(__file__).absolute().parents[2]
        source = os.environ["GITHUB_SHA"]
        self.assertRegex(source, r"^[0-9a-f]{40}$")
        self.assertEqual(source, os.environ.get("GITHUB_WORKFLOW_SHA"))
        target = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}[platform.machine()]
        spec = importlib.util.spec_from_file_location("unsigned_product_probe_stager", repo / "desktop/tools/stage_macos_installed.py")
        stager = importlib.util.module_from_spec(spec); spec.loader.exec_module(stager)
        selected = stager.source_build_selection(target)
        sources = stager.xcode_setup_sources(selected)
        work = Path(os.environ["RUNNER_TEMP"]) / "mrk-xcode-product-metadata"
        work.mkdir(mode=0o700)  # Only a new nonroot task tree; never reuse.
        deadline, counter = time.monotonic() + 300, 0
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "LANG": "C", "LC_ALL": "C"}
        previous_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        resource.setrlimit(resource.RLIMIT_FSIZE, (min(1024 * 1024, previous_limit[0]) if previous_limit[0] >= 0 else 1024 * 1024,
                                                previous_limit[1]))
        def bounded(path, limit):
            self.assertLess(time.monotonic(), deadline)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                self.assertTrue(stat.S_ISREG(before.st_mode))
                self.assertEqual((before.st_uid, before.st_nlink), (os.getuid(), 1))
                self.assertTrue(0 < before.st_size <= limit)
                value = bytearray()
                while len(value) < before.st_size:
                    part = os.read(fd, min(4096, before.st_size-len(value))); self.assertTrue(part); value.extend(part)
                self.assertEqual(os.read(fd, 1), b"")
                fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                identity = lambda info: tuple(getattr(info, name) for name in fields)
                self.assertEqual(identity(before), identity(os.fstat(fd)))
                self.assertEqual(identity(before), identity(path.lstat()))
                self.assertLess(time.monotonic(), deadline)
                return bytes(value)
            finally:
                os.close(fd)
        def run(argv, seconds, *, cwd=work, archive=False):
            nonlocal counter
            remaining = deadline-time.monotonic(); self.assertGreater(remaining, 0); counter += 1
            stdout, stderr = (work / (str(counter)+suffix) for suffix in (".stdout", ".stderr"))
            environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "COPYFILE_DISABLE": "1"} if archive else env
            try:
                with stdout.open("xb") as out, stderr.open("xb") as err:
                    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, cwd=cwd,
                                            env=environment, timeout=min(seconds, remaining), check=False)
                self.assertLess(time.monotonic(), deadline, "original metadata probe deadline after command")
            except subprocess.TimeoutExpired:
                _command_failure(work, repo, argv, counter, timed_out=True)
                raise TimeoutError("unsigned metadata command timed out; preserve task") from None
            if result.returncode != 0:
                _command_failure(work, repo, argv, counter, returncode=result.returncode)
            self.assertEqual(result.returncode, 0, "unsigned metadata command failed; see Failure.json")
            self.assertLessEqual(stdout.stat().st_size, 256*1024); self.assertLessEqual(stderr.stat().st_size, 256*1024)
            return b"" if stdout.stat().st_size == 0 else bounded(stdout, 256*1024)
        def metadata(package, member):
            # Observation-only extraction of TWO fixed public XML members. Save
            # the actual TOC before any member/production-parser assertion. This
            # neither relaxes the shipping parser nor grants package authority.
            self.assertIn(member, ("PackageInfo", "Distribution"))
            body = bounded(package, 1024*1024)
            self.assertGreaterEqual(len(body), 28)
            magic, header, version, packed, unpacked, checksum = stager.struct.unpack_from(">IHHQQI", body)
            self.assertEqual((magic, header, version), (0x78617221, 28, 1))
            self.assertIn(checksum, (1, 3, 4))
            self.assertTrue(0 < packed <= 65536 and 0 < unpacked <= 65536 and header+packed <= len(body))
            toc = stager.inflate(body[header:header+packed], unpacked); self.assertEqual(len(toc), unpacked)
            (work / ("ComponentTOC.xml" if member == "PackageInfo" else "ProductTOC.xml")).write_bytes(toc)
            tree = stager.ET.fromstring(toc)
            rows = [row for row in tree.findall("./toc/file") if row.findtext("name") == member]
            self.assertEqual(len(rows), 1); row = rows[0]
            self.assertEqual(row.findtext("type"), "file"); self.assertFalse(row.findall("file"))
            self.assertEqual(len(row.findall("data")), 1); data = row.find("data")
            numbers = []
            for key in ("length", "offset", "size"):
                self.assertEqual(len(data.findall(key)), 1)
                text = data.findtext(key); self.assertRegex(text, r"^(0|[1-9][0-9]{0,9})$"); numbers.append(int(text))
            length, offset, size = numbers
            limit = 16384 if member == "PackageInfo" else 32768
            self.assertTrue(0 < length <= 65536 and 0 < size <= limit and offset >= {1:20, 3:32, 4:64}[checksum])
            start = header+packed+offset; self.assertLessEqual(start+length, len(body))
            self.assertEqual(len(data.findall("encoding")), 1); encoding = data.find("encoding").get("style")
            self.assertIn(encoding, ("application/octet-stream", "application/x-gzip"))
            value = body[start:start+length]
            value = value if encoding == "application/octet-stream" else stager.inflate(value, size, gzip=value[:2] == b"\x1f\x8b")
            self.assertEqual(len(value), size)
            (work / (member+".xml")).write_bytes(value)
            return body, value
        try:
            self.assertEqual(run(["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"], 10).decode().strip(), source)
            run(["/usr/bin/git", "-C", str(repo), "diff", "--exit-code", "HEAD", "--",
                 "desktop/macos-xcode-setup-inputs", "desktop/tools/stage_macos_installed.py",
                 str(Path(__file__).relative_to(repo))], 10)
            payload, scripts, parts = work/"carrier", work/"scripts-original", work/"parts"
            stager.write_tree(payload, {stager.XCODE_SETUP_CARRIER+"/Contents/Info.plist": (sources["CarrierInfo.plist"], 0o444)}, root_mode=0o755)
            # Deliberately NOT Mach-O or a signing/admission stand-in. Packaging
            # tools only read these bytes; no script/helper/Installer is executed.
            files = {"preinstall": (sources["preinstall"], 0o555), "setup/postinstall": (sources["setup/postinstall"], 0o555),
                     stager.XCODE_SETUP_PROGRAM: (b"INERT UNSIGNED PACKAGE METADATA PROBE; NEVER EXECUTE\n", 0o555)}
            stager.write_tree(scripts, files, root_mode=0o755)
            component_plist = work/"Component.plist"; component_plist.write_bytes(sources["Component.plist"])
            original = work/"original.pkg"
            run(["/usr/bin/pkgbuild", "--root", str(payload), "--scripts", str(scripts), "--component-plist", str(component_plist),
                 "--identifier", stager.XCODE_SETUP_ID, "--version", selected.package_version, "--install-location", "/Library",
                 "--ownership", "recommended", "--compression", "legacy", "--min-os-version", "26.0", str(original)], 60)
            original_body, package_info = metadata(original, "PackageInfo")
            members = stager.xar_members(original_body, xcode_setup=True)
            self.assertEqual(members["PackageInfo"], package_info)
            stager.xcode_setup_package_info(package_info, selected)
            stager._xcode_setup_payload(members["Payload"], sources["CarrierInfo.plist"])
            self.assertTrue(0 < len(members["Bom"]) <= 65536)
            stager.write_tree(parts, {name: (members[name], 0o444) for name in ("PackageInfo", "Payload", "Bom")}, root_mode=0o700)
            bom = run(["/usr/bin/lsbom", "-p", "fmugs", str(parts/"Bom")], 10)
            self.assertLessEqual(len(bom), 8192); (work/"BOM.txt").write_bytes(bom)
            stager.xcode_setup_bom_data(bom, sources["CarrierInfo.plist"])
            scripts_final = work/"scripts-final"
            stager.write_tree(scripts_final, dict(files, **{"setup/carrier.bom": (members["Bom"], 0o444)}), root_mode=0o755)
            run(["/usr/bin/bsdtar", "-c", "-z", "-f", str(parts/"Scripts"), "--format=odc", "--uid=0", "--gid=0",
                 "--no-acls", "--no-xattrs", "--no-fflags", "--no-mac-metadata", "."], 30, cwd=scripts_final, archive=True)
            script_body = bounded(parts/"Scripts", 1024*1024)
            self.assertEqual(stager.cpio_members(stager.inflate(script_body, 1024*1024, gzip=True)),
                             dict(files, **{"setup": (None, 0o555), "setup/carrier.bom": (members["Bom"], 0o444)}))
            component_dir = work/"component"; component_dir.mkdir(mode=0o700)
            component = component_dir/stager.XCODE_SETUP_COMPONENT
            run(["/usr/bin/xar", "-c", "-f", str(component), "--compression=none", "PackageInfo", "Scripts", "Bom", "Payload"],
                30, cwd=parts, archive=True)
            component_body = bounded(component, 1024*1024)
            component_members = stager.xar_members(component_body, xcode_setup=True)
            self.assertEqual(component_members, dict(members, Scripts=script_body))
            presentation = work/"presentation"
            stager.write_tree(presentation, {"Distribution": (sources["Distribution.xml"], 0o444),
                "resources/InstallerReadMe.html": (sources["InstallerReadMe.html"], 0o444)}, root_mode=0o700)
            product = work/"Product.pkg"
            run(["/usr/bin/productbuild", "--distribution", str(presentation/"Distribution"), "--package-path", str(component_dir),
                 "--resources", str(presentation/"resources"), str(product)], 30)
            outer, distribution = metadata(product, "Distribution")
            self.assertEqual(bounded(component, 1024*1024), component_body)
            actual = stager.install_product_members(outer, xcode_setup=True)
            self.assertEqual(actual["Distribution"], distribution)
            stager.install_product_distribution(distribution, sources["Distribution.xml"], xcode_setup=True)
            self.assertEqual(actual["Resources/InstallerReadMe.html"], sources["InstallerReadMe.html"])
            observed_component = (stager.xar_members(actual[stager.XCODE_SETUP_COMPONENT], xcode_setup=True)
                if stager.XCODE_SETUP_COMPONENT in actual else
                {name: actual[stager.XCODE_SETUP_COMPONENT+"/"+name] for name in stager.XCODE_SETUP_COMPONENT_MEMBERS})
            self.assertEqual(observed_component, component_members)
            self.assertEqual(counter, 7)  # Two fixed Git checks + five packaging commands.
            self.assertLess(time.monotonic(), deadline)
            (work/"RESULT.json").write_text(json.dumps({"sourceCommit":source, "target":target, "packagingCommands":5,
                "productionMetadataParsersPassed":True, "unsignedOnly":True, "installerExecuted":False,
                "nativeSetupQualified":False, "signingQualified":False}, sort_keys=True)+"\n")
            # No service/root state exists. Retire only own successfully joined
            # nonroot inputs; on failure preserve bounded metadata for diagnosis.
            for path in (payload, scripts, scripts_final, parts, component_dir, presentation):
                for directory, child_dirs, names in os.walk(path, followlinks=False):
                    node = Path(directory); self.assertTrue(stat.S_ISDIR(node.lstat().st_mode))
                    self.assertEqual(node.lstat().st_uid, os.getuid())
                    for name in child_dirs+names:
                        info = (node/name).lstat(); self.assertEqual(info.st_uid, os.getuid()); self.assertFalse(stat.S_ISLNK(info.st_mode))
                    node.chmod(0o700)
                shutil.rmtree(path)
            original.unlink(); product.unlink(); component_plist.unlink()
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, previous_limit)
        print("Unsigned five-command product metadata passed; no Installer, signing or native setup qualification.")


if __name__ == "__main__":
    unittest.main()
