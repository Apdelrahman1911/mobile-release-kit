"""Fixed local current-IPA originals; existing snapshot/profile/command owners.

The native Store Session retains the original system-tool Book. This nominated
DATA/child comparison never grants Store access, signing or a build operation.
"""
from __future__ import annotations
import json
import math
import os
import re
import stat
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from .build_inputs import _Directory, _FD, finite_scratch
from .cancellation import CleanupScope
from .errors import ValidationError
from .owned_process import ProcessCleanupError, run_owned

LIMIT = 16 * 1024
MAX_CALLS = 4096
OUTPUT_LIMIT = 8 * 1024**2
SYSTEM = Path('/usr/bin')
NAMES = ('security', 'codesign', 'openssl')
FAILURE = 'Current local IPA originals or lifetime could not be confirmed'


def need(value):
    if not value: raise ValidationError(FAILURE)


def tool_data(st):
    return dict(device=str(st.st_dev), inode=str(st.st_ino), mode=st.st_mode,
        uid=st.st_uid, gid=st.st_gid, links=st.st_nlink, size=st.st_size,
        mtimeNs=str(st.st_mtime_ns), ctimeNs=str(st.st_ctime_ns))


def bindings(value):
    need(type(value) is dict and set(value) == set(NAMES))
    from ._desktop_ios_archive_protocol import _tool_identity
    for item in value.values():
        try: _tool_identity(item)
        except Exception:
            raise ValidationError(FAILURE) from None
        need(item['uid'] == 0 and not item['mode'] & 0o7022)
    return value


def request_data(raw):
    need(type(raw) is str and 0 < len(raw.encode()) <= LIMIT)
    def pairs(rows):
        result = {}
        for k,v in rows:
            need(k not in result); result[k]=v
        return result
    try: value=json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, RecursionError): raise ValidationError(FAILURE) from None
    need(type(value) is dict and set(value) == {'schemaVersion','signingTools','runDeadlineNs','hardDeadlineNs'}
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 1)
    tools=bindings(value['signingTools']); ends=[]
    for name in ('runDeadlineNs','hardDeadlineNs'):
        v=value[name];need(type(v) is str and re.fullmatch(r'[1-9][0-9]{0,18}',v) is not None);ends.append(int(v))
    run,hard=ends;now=time.monotonic_ns()
    need(now < run <= now+3600*10**9 and hard-run == 5*10**9 and hard <= 2**63-1)
    return tools,run,hard


class _CurrentIPADeadline:
    def __init__(self, owner): self.owner=owner
    @property
    def expires_at(self):
        self.owner.origin()
        # Existing profile owner floors a float endpoint; never round UP.
        value=self.owner.run_end/10**9
        if value.as_integer_ratio()[0]*10**9 > self.owner.run_end*value.as_integer_ratio()[1]:
            value=math.nextafter(value, -math.inf)
        return value
    def check(self): self.owner.point(cleanup=self.owner.guard.depth > 0)


def operation_for(deadline):
    if type(deadline) is not _CurrentIPADeadline: return None
    owner=deadline.owner
    need(type(owner) is CurrentIPATools and owner.deadline is deadline)
    owner.origin(); return owner


class CurrentIPASnapshotBinding:
    """Exact consumer edge into the existing finite snapshot, not a runner."""
    def __init__(self, operation):
        need(type(operation) is CurrentIPATools)
        self.operation=operation;self.guard=operation.guard;self.owner=None
        self.active=self.entered=self.returned=self.finish_claimed=self.finished=False
    def origin(self, owner, guard):
        self.operation.origin();need(self.operation.snapshot_binding is self and owner is self.owner and guard is self.guard)
    def bind_owner(self, owner):
        from .ios_artifacts import _IOSSnapshotOwner
        self.origin(None,self.guard)
        need(type(owner) is _IOSSnapshotOwner and owner._desktop_binding is self
            and owner._lane_binding is None and owner.deadline is self.operation.deadline and not self.finish_claimed)
        self.owner=owner
    def producer(self, owner, guard):
        self.origin(owner,guard);self.operation.point()
        need(self.active and not self.finish_claimed and self.operation.idle())
    @contextmanager
    def consumer(self):
        self.origin(self.owner,self.guard);need(not self.entered and not self.finish_claimed)
        self.entered=self.active=True
        try: yield
        finally: self.active=False;self.returned=True
    def finish_consumers(self, *, cancellation, primary=None):
        self.origin(self.owner,cancellation)
        if self.finish_claimed: need(self.finished);return
        self.finish_claimed=True
        need(not self.active and (not self.entered or self.returned) and self.operation.idle() and not self.operation.iterators)
        if self.owner is not None:
            need(not self.owner._accounting_pending and not self.owner._accounting_failed
                and self.owner._reserved == self.owner._retired and all(v is None for v in self.owner._leases))
        self.finished=True
    def dependents_settled_for(self, *, owner, cancellation):
        self.origin(owner,cancellation)
        return self.finished and self.finish_claimed and not self.active and self.operation.idle()


class CurrentIPATools:
    def __init__(self, raw, scratch):
        self.expected,self.run_end,self.hard_end=request_data(raw)
        self.scratch,self.guard=scratch,scratch.cancellation
        self.pid,self.thread=os.getpid(),threading.current_thread()
        need(getattr(self.guard,'_current_ipa_tools',None) is None)
        self.guard._current_ipa_tools=self
        from .checked_files import _Reader
        self.inputs = _Reader(self.guard); self.input_nodes = []; self.input_paths = (); self.input_quote = 0
        self.parent=None;self.tools={};self.flags={};self.commands=[];self.pending=None
        self.failed=self.closed=self.close_claimed=False
        self.snapshot=None;self.signing=None;self.view=None;self.policy_source=None;self.policy_prelude=False
        self.deadline=_CurrentIPADeadline(self);self.inspection_deadline=self.deadline
        self.snapshot_binding=CurrentIPASnapshotBinding(self)
        self.scratches=[];self.prefixes=set();self.iterators=[];self.scans=0
    def origin(self):
        need(type(self) is CurrentIPATools and self.pid == os.getpid() and self.thread is threading.current_thread()
            and getattr(self.guard,'_current_ipa_tools',None) is self and not self.closed)
    def point(self, *, cleanup=False):
        self.origin();need(time.monotonic_ns() < (self.hard_end if cleanup else self.run_end))
        if not cleanup: need(not self.failed and not self.close_claimed)
        self.guard.check();self.scratch._check()
    def idle(self):
        facts=self.guard.lifetime_ledger.verdict()
        return self.pending is None and facts.contained and facts.complete and not facts.fatal and not self.guard.lifetime_ledger.fatal
    @staticmethod
    def protected(st, directory=False):
        need((stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)) and st.st_uid == 0
            and not st.st_mode & 0o7022
            and (directory or st.st_nlink == 1 and st.st_size > 0 and st.st_mode & 0o111 != 0))
    def acquire(self):
        self.point();need(sys.platform == 'darwin' and self.parent is None)
        # Six system originals + existing142 snapshot pool + bounded input/
        # scratch ancestors +64 profile/command transient envelope <=256.
        self.parent=_Directory(SYSTEM,self.guard,edit_checkpoints=True);self.parent.acquire()
        for slot in self.parent.slots:
            observed=os.fstat(slot.number);self.protected(observed,True)
            self.flags[id(slot)]=getattr(observed,'st_flags',0)
        for name in NAMES:
            slot=_FD(self.guard);self.tools[name]=slot
            number=slot.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.parent.fd)
            observed=os.fstat(number);self.protected(observed)
            self.flags[id(slot)]=getattr(observed,'st_flags',0)
            need(tool_data(observed) == self.expected[name])
        self.post()
    def post(self):
        self.point(cleanup=True);need(self.parent is not None and set(self.tools) == set(NAMES))
        self.parent.check()
        for slot in self.parent.slots:
            observed=os.fstat(slot.number);self.protected(observed,True)
            need(getattr(observed,'st_flags',0)==self.flags[id(slot)])
        for name,slot in self.tools.items():
            need(slot.number is not None)
            value=os.fstat(slot.number);self.protected(value);need(getattr(value,'st_flags',0)==self.flags[id(slot)])
            need(tool_data(value)==self.expected[name] and tool_data(os.stat(name,dir_fd=self.parent.fd,follow_symlinks=False))==self.expected[name])
        self.point(cleanup=True)
    @contextmanager
    def entries(self, number, owner):
        self.point(cleanup=True)
        need(owner is self.snapshot_binding.owner and owner._desktop_binding is self.snapshot_binding)
        need(number == owner.slot.number or any(lease is not None and lease.slot.number == number for lease in owner._leases))
        need(self.scans < 65536 and not self.iterators)
        self.scans += 1
        row=[None,'OPENING']; self.iterators.append(row)
        try:
            row[0]=os.scandir(number);row[1]='OPEN'
            yield row[0]
        finally:
            if row[1]=='OPEN':
                row[1]='CLOSING'
                try: need(row[0].close() is None)
                except BaseException as error:
                    row[1]='UNKNOWN';self.guard._abort(error);raise
                row[1]='CLOSED';self.iterators.remove(row)
            else:
                error=ProcessCleanupError(FAILURE);self.guard._abort(error);raise error
    def _shared_input(self, path, maximum):
        from .checked_files import (_Alias, _Node, _Policy, _alias_parts, _protect_directory,
                                    _directory_identity, _file_identity)
        reader=self.inputs
        if not reader.nodes:
            return reader.acquire(path,_Policy(False,1,maximum),None)
        self.inputs_post()
        need(reader.root is not None)
        parent=reader.root;canonical=physical=Path('/')
        parts=path.parts[1:-1]
        if parts:
            first=reader._stat(parent,parts[0])
            if stat.S_ISLNK(first.st_mode):
                target=os.readlink(parts[0],dir_fd=reader._number(parent))
                replacement=_alias_parts(parts[0],first,target)
                reader.aliases.append(_Alias(parts[0],first,target))
                parts=(*replacement,*parts[1:])
        for name in parts:
            canonical /= name
            observed=reader._stat(parent,name)
            role=reader._physical_role(parent,physical,observed)
            _protect_directory(role,observed)
            # A matching spelling selects an ALREADY HELD candidate only; the
            # actual parent, held identity and named identity must all match.
            node=next((n for n in reader.nodes if n.directory and n.parent is parent and n.name==name),None)
            if node is None:
                slot=reader._open(name,parent=parent,directory=True)
                node=_Node(slot,parent,name,canonical,observed,True);reader.nodes.append(node)
                if role is not None and name!=role.name:
                    reader.nodes.append(_Node(slot,parent,role.name,role,observed,True))
            need(_directory_identity(os.fstat(reader._number(node.slot))) == _directory_identity(node.observed)
                 == _directory_identity(observed) == _directory_identity(reader._stat(parent,name)))
            parent,physical=node.slot,role
        observed=reader._stat(parent,path.name)
        need(stat.S_ISREG(observed.st_mode) and 1<=observed.st_size<=maximum)
        slot=reader._open(path.name,parent=parent,directory=False)
        need(_file_identity(os.fstat(reader._number(slot))) == _file_identity(observed)
             == _file_identity(reader._stat(parent,path.name)))
        node=_Node(slot,parent,path.name,canonical/path.name,observed,False);reader.nodes.append(node)
        return node
    def bind_inputs(self, config, intent, ipa):
        from .checked_files import _absolute
        self.point(); need(not self.input_nodes)
        paths=tuple(_absolute(Path(path),private=True) for path in (config,intent,ipa))
        need(len(set(paths))==3)
        ancestors={Path('/')}
        for path in paths:
            ancestors.update(path.parents)
            # Quote both literal and supported physical alias spellings before
            # reading either. Alias validation still occurs on original root.
            if len(path.parts)>1 and path.parts[1] in ('var','tmp'):
                ancestors.update((Path('/private')/Path(*path.parts[1:])).parents)
        quote=len(ancestors)+3
        fixed=6+142+64+2*(len(self.scratch.parent.path.parts)+1)+4
        need(quote+fixed<=256)
        self.input_quote=quote;self.input_paths=paths
        for path,maximum in zip(paths,(1024**2,2*1024**2,4*1024**3)):
            self.point();self.input_nodes.append(self._shared_input(path,maximum))
            need(len(self.inputs.descriptors)<=self.input_quote)
        self.inputs_post()
        from .ios_artifacts import _zip_directory_bound
        _zip_directory_bound(paths[2],deadline=self.deadline)
        self.inputs_post()
    @contextmanager
    def input_file(self, path):
        import io
        self.inputs_post()
        node = next((node for original,node in zip(self.input_paths,self.input_nodes) if path in (original,node.canonical)), None)
        need(node is not None)
        number = self.inputs._number(node.slot)
        os.lseek(number, 0, os.SEEK_SET)
        try:
            with io.FileIO(number, 'rb', closefd=False) as source: yield source
        finally: self.inputs_post()
    def zip_directory(self, path, raw, entries, central):
        # Same existing ZIP prelude runs BEFORE ZipInfo allocation. Conservative
        # representation quote covers two namespace graphs, central parse/string
        # copies, full profile/plist/native buffers and retained call records.
        self.point()
        need(path in (self.input_paths[2], self.input_nodes[2].canonical) or self.snapshot is not None
             and path == self.snapshot.paths['ios-ipa'])
        need(raw <= 4*1024**3 and entries <= 8192 and central <= 8*1024**2)
        need(192*1024**2 + entries*8192 + central*8 <= 384*1024**2)
    def intent_bytes(self):
        self.inputs_post(); need(len(self.input_nodes)==3)
        return self.inputs.read(self.input_nodes[1])
    def inputs_post(self):
        self.point(cleanup=True)
        if self.inputs.nodes: self.inputs.terminal()
    def input_raw(self,index):
        self.inputs_post(); return self.inputs.read(self.input_nodes[index])
    def begin_inspection(self, artifacts, cancellation):
        self.point();need(cancellation is self.guard and self.snapshot is None and set(artifacts)=={'ios-ipa'})
        return self.deadline
    def bind_snapshot(self, snapshot):
        self.point();need(self.snapshot is None and snapshot._owner is self.snapshot_binding.owner)
        self.snapshot=snapshot
    @contextmanager
    def policy_archive(self):
        import io
        from .ios_artifacts import _zip_directory_bound
        self.point();need(self.snapshot is not None and self.policy_source is None)
        path=self.snapshot.paths['ios-ipa']; owner=self.snapshot._owner
        with owner.descriptor(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK) as number:
            with io.FileIO(number,'rb',closefd=False) as source:
                self.policy_source=source
                try:
                    self.policy_prelude=True
                    try: _zip_directory_bound(path,deadline=self.deadline,owner=owner)
                    finally: self.policy_prelude=False
                    source.seek(0)
                    yield
                finally: self.policy_source=None
        self.snapshot.assert_unchanged()
    @contextmanager
    def validation_view(self, path):
        self.point();need(self.snapshot is not None and self.snapshot.paths['ios-ipa']==path and self.view is None)
        self.view=self.snapshot.unpack('ios-ipa');self.snapshot.assert_unchanged()
        try: yield self.view,self.guard
        finally:
            with self.guard.deferred(check_on_exit=False):
                need(self.idle());self.snapshot.assert_unchanged();self.post()
    def validated(self,path,guard,deadline,facts):
        self.point();need(self.signing is None and self.snapshot is not None and path==self.snapshot.paths['ios-ipa']
            and guard is self.guard and deadline is self.deadline and self.view is not None)
        self.post();self.signing=dict(facts)
    def scratch_parent(self,prefix,directory):
        self.point();need(prefix=='mobile-release-leaf-' and self.view is not None and directory==self.view)
        return self.scratch._path
    def register_scratch(self,record):
        self.point();need(len(self.scratches)<513 and record[1] is self.guard and record not in self.scratches)
        self.scratches.append(record)
    def has_scratch(self,record): return any(v is record for v in self.scratches)
    def scratch_acquired(self,record):
        need(self.has_scratch(record) and record[2]['acquired']);self.scratch_before_cleanup(record)
    def scratch_before_cleanup(self,record):
        self.point(cleanup=True);need(self.has_scratch(record) and self.idle())
        path=Path(record[0].name);need(path.parent==self.scratch._path and not path.is_symlink())
        need(record[0].state['identity'] is not None)
    def scratch_removed(self,record):
        need(self.has_scratch(record) and record[2]['removed']);self.scratches.remove(record)
    def _argv(self,argv):
        need(type(argv) is list and 2<=len(argv)<=12 and all(type(a) is str and 0<len(a.encode())<=4096 and '\0' not in a for a in argv))
        name=argv[0].removeprefix('/usr/bin/');need(name in ('codesign','openssl') and argv[0] in (name,'/usr/bin/'+name))
        if name=='openssl':
            need(len(argv)==10 and argv[1:5]==['x509','-inform','DER','-in'] and argv[6:]==['-noout','-fingerprint','-sha256','-dates'])
            path=Path(argv[5]);need(any(path==p.parent/(p.name+'0') for p in self.prefixes))
            need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=1024**2)
        else:
            path=Path(argv[-1]);need(self.view is not None and path.is_relative_to(self.view) and not path.is_symlink())
            options=argv[1:-1]
            if options and options[0]=='--verify':
                need(options in (['--verify','--all-architectures','--deep','--strict','--verbose=2'],
                    ['--verify','--all-architectures','--strict','--verbose=2','--test-requirement','=designated']))
            else:
                need(options and options[0]=='-d');options=options[1:]
                if options and options[0]=='--architecture':
                    need(len(options)>=3 and re.fullmatch(r'[0-9]{1,10},[0-9]{1,10}',options[1]));options=options[2:]
                if options and options[0]=='--extract-certificates':
                    need(len(options)==2);prefix=Path(options[1])
                    need(any(record[2]['acquired'] and prefix.parent==Path(record[0].name) for record in self.scratches)
                        and re.fullmatch(r'slice-(?:[0-9]|[12][0-9]|3[01])-',prefix.name) and prefix not in self.prefixes and len(self.prefixes)<MAX_CALLS)
                    self.prefixes.add(prefix)
                else: need(options in (['--verbose=4'],['--entitlements','-','--der'],['--entitlements','-','--xml']))
        return (str(SYSTEM/name),*argv[1:])
    def _command_seal(self,evidence,role):
        self.point();need(self.pending is not None and self.pending[0] is evidence and self.pending[1]==role)
        return self.pending[2],self.scratch._path,self.pending[3],self.pending[4],self.pending[5]
    def _command_timing(self,evidence):
        self.point();need(self.pending is not None and self.pending[0] is evidence);return self.pending[4]
    def native_call(self,argv,*,timeout,text,cancellation):
        self.point();need(cancellation is self.guard and timeout in (30,60) and type(text) is bool and self.pending is None and len(self.commands)<MAX_CALLS)
        self.post();command=self._argv(argv)
        from .credentials import artifact_validation_environment
        from ._command_process import CommandCallEvidence,CLEANUP_NS
        from ._store_lane_contract import Timing,clock_label
        environment=artifact_validation_environment({'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(self.scratch._path),'TMPDIR':str(self.scratch._path),'LANG':'C','LC_ALL':'C'})
        run=min(self.run_end-CLEANUP_NS,time.monotonic_ns()+timeout*10**9);need(time.monotonic_ns()<run)
        timing=Timing(clock_label(),run,run+CLEANUP_NS);evidence=CommandCallEvidence(self.guard)
        role='ios-'+str(len(self.commands))+'-'+Path(command[0]).name
        self.commands.append(evidence);self.pending=(evidence,role,command,environment,timing,timeout)
        try:
            evidence._reserve_current_ios(self,role)
            return run_owned(command,cwd=self.scratch._path,environ=environment,capture=True,text=text,
                timeout=timeout,output_limit=OUTPUT_LIMIT,cancellation=self.guard,_evidence=evidence)
        except BaseException:
            self.failed=True;raise
        finally:
            self.pending=None
            with self.guard.deferred(check_on_exit=False):
                try: self.post()
                except BaseException: self.failed=True;raise
    def close(self):
        if self.close_claimed: need(self.closed);return
        self.close_claimed=True;first=None
        with self.guard.deferred(check_on_exit=False):
            try:
                need(self.idle() and not self.scratches and not self.iterators)
                if len(self.tools)==3: self.post()
                self.inputs_post()
            except BaseException as error: first=error
            for slot in list(self.tools.values())+[self.parent]:
                if slot is None: continue
                try: slot.close()
                except BaseException as error:
                    self.guard._abort(error);first=first or error
            try:
                self.inputs.close(); self.inputs.assert_closed()
            except BaseException as error:
                self.guard._abort(error); first=first or error
            known=all(s.state in ('UNACQUIRED','CLOSED') for s in self.inputs.descriptors) and all(s.close_state=='CLOSED' or s.open_state=='NEW' for s in self.tools.values())
            if self.parent is not None: known=known and all(s.number is None and s.close_state=='CLOSED' for s in self.parent.slots)
            if known: self.closed=True;self.guard._current_ipa_tools=None
            else: raise ProcessCleanupError(FAILURE) from None
        if first is not None: raise first


@contextmanager
def current_ipa_tools(raw):
    request_data(raw)
    with finite_scratch(layout='online-runner') as scratch:
        owner=CurrentIPATools(raw,scratch)
        scope=CleanupScope(owner.guard,owner.close,owns_cancellation=False,first_primary=True)
        try:
            with scope:
                owner.acquire();yield owner;owner.point();need(not owner.failed and owner.signing is not None)
        finally: scope.__exit__(*sys.exc_info())
        need(owner.closed)
