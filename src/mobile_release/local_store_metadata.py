"""Fixed private metadata tree consuming the same authenticated ZIP bytes.

Input custody only. It neither grants a Store Invocation nor extracts arbitrary
archives. New files live under the original store-metadata scratch and can be
removed only by this original, after the same scratch's consumers have settled.
"""
import hashlib
import io
import os
from pathlib import PurePosixPath
import stat
import struct
import zipfile

from .build_inputs import (FiniteScratch, _FD, _fd_cleanup, _mkdir_private, _check_creation,
    _directory, _file, _name_key, _consumer_idle, _attempt_all, _read_file)
from .local_release_journal import canonical, _need
from .metadata import MAX_ARCHIVE_SIZE, MAX_FILE_SIZE, MAX_FILE_COUNT, PLATFORM_METADATA_ROOTS, ALLOWED_SUFFIXES

MAX_DIRECTORIES = 96
MAX_ROWS_BYTES = 2 << 20
_DOMAIN = b'mrk-local-store-metadata-tree/1\0'


class StoreMetadataTree:
    def __init__(self, scratch, *, platform):
        _need(type(scratch) is FiniteScratch and scratch.layout == 'store-metadata'
              and platform in ('android','ios') and scratch._store_metadata_tree is None)
        scratch._owner()
        self.scratch, self.guard, self.platform = scratch, scratch.cancellation, platform
        self.directories = {}; self.files = {}; self.slots = []; self.writer_slots = []
        self.iterator = None; self.scan_state = 'new'; self.planned = None
        self.started = self.ready = self.failed = self.claimed = self.closed = self.retired = False
        self.snapshot = None; self.total = 0; self.passes = 0
        scratch._store_metadata_tree = self  # Original receiver before mkdir/open.

    @property
    def path(self): return self.scratch._path / 'metadata-tree'

    def _point(self):
        self.scratch._owner(cleanup=self.claimed)
        self.guard._check_owner(); self.scratch._check()
        if not self.claimed: self.guard.check()
        for name, entry in self.directories.items():
            if entry['retired']: continue
            slot, parent, leaf = entry['slot'], entry['parent'], entry['name']
            _need(entry['identity'] is not None and slot.number is not None
                  and _directory(os.fstat(slot.number)) == entry['identity']
                  and _directory(os.stat(leaf, dir_fd=parent.number, follow_symlinks=False)) == entry['identity'])

    def _plan(self, names):
        _need(not self.started and not self.claimed and type(names) is tuple and len(names) <= MAX_FILE_COUNT)
        paths, aliases, directories = [], set(), {''}; row_bytes = 0
        previous = None
        for name in names:
            _need(type(name) is str and name and not any(ord(c)<32 or ord(c)==127 for c in name)
                  and '\\' not in name and '\x00' not in name)
            path = PurePosixPath(name); encoded = name.encode('utf-8')
            _need(path.as_posix() == name and not path.is_absolute() and 2 <= len(path.parts) <= 32
                  and all(p not in ('','.','..') and not p.startswith('.') and len(p.encode('utf-8')) <= 255 for p in path.parts)
                  and path.parts[0] in PLATFORM_METADATA_ROOTS[self.platform] and path.suffix.lower() in ALLOWED_SUFFIXES
                  and (previous is None or previous < encoded))
            key = tuple(_name_key(p) for p in path.parts)
            _need(key not in aliases); aliases.add(key); previous = encoded
            row_bytes += 4*len(encoded)+512; _need(row_bytes <= MAX_ROWS_BYTES)
            paths.append(name)
            for parent in path.parents:
                if parent == PurePosixPath('.'): continue
                directories.add(parent.as_posix()); _need(len(directories)<=MAX_DIRECTORIES)
        # Reject file/directory and Unicode/case aliases across the whole roster.
        keys = {}
        for name in (*directories,*paths):
            key = tuple(_name_key(p) for p in PurePosixPath(name).parts)
            _need(key not in keys); keys[key] = name
        self.planned = (tuple(paths),tuple(sorted(directories,key=lambda p:(p.count('/')+(p!=''),p.encode('utf-8')))))
        # Caller additionally quotes the complete remaining Store phase. This
        # local floor counts actual scratch originals + fixed native reserve.
        _need(len(self.scratch.parent.slots)+1+len(directories)+2+128 <= 256)
        source=getattr(self.guard,'_local_store_source',None)
        if source is not None:
            from .local_store_execute import LocalStoreExecuteRun
            owner=source.require_operation()
            from .local_store_reconcile import LocalStoreReconcileRun
            if (type(owner) is LocalStoreExecuteRun or type(owner) is LocalStoreReconcileRun and owner.readiness) and owner.later_stage:
                from .local_store_stage import execute_tree_quote
                execute_tree_quote(owner,self,len(directories)+2)
        return len(directories)+2

    def _mkdir(self, name):
        parent_name, _, leaf = name.rpartition('/')
        parent = self.scratch.slot if name == '' else self.directories[parent_name]['slot']
        leaf = 'metadata-tree' if name == '' else leaf
        slot = _FD(self.guard); self.slots.append(slot)
        entry = dict(slot=slot,parent=parent,name=leaf,identity=None,creation={'state':'NEW'},retired=False)
        self.directories[name] = entry
        _mkdir_private(leaf,parent.number,self.guard,entry['creation'])
        number = slot.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent.number)
        entry['identity'] = _directory(os.fstat(number))
        _need(entry['identity']['uid']==os.geteuid() and entry['identity']['mode']==0o700)
        self._point()

    def begin(self, names):
        self._plan(names); self.started = True
        try:
            self.scratch._check()
            for name in self.planned[1]: self._mkdir(name)
        except BaseException:
            self.failed=True; raise

    def write(self, name, data):
        _need(self.started and not self.ready and not self.failed and not self.claimed
              and name in self.planned[0] and name not in self.files
              and type(data) is bytes and len(data)<=MAX_FILE_SIZE
              and self.total+len(data)<=MAX_ARCHIVE_SIZE)
        self._point(); parent_name,_,leaf=name.rpartition('/'); parent=self.directories[parent_name]['slot']
        slot=_FD(self.guard); self.writer_slots.append(slot)
        entry=dict(parent=parent,name=leaf,binding=None,created=None);self.files[name]=entry
        try:
            with _fd_cleanup(slot):
                number=slot.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,dir_fd=parent.number)
                initial=_file(os.fstat(number));entry['created']=initial
                _need(initial['mode']==0o600 and initial['uid']==os.geteuid() and initial['links']==1)
                view=memoryview(data)
                while view:
                    self.guard.check();n=os.write(number,view);_need(n>0);view=view[n:]
                os.fsync(number);os.fchmod(number,0o444)
                binding=_file(os.fstat(number))
                _need(binding['size']==len(data) and binding['mode']==0o444 and binding['links']==1
                      and all(binding[k]==initial[k] for k in ('device','inode','uid','gid')))
                entry['binding']={**binding,'sha256':hashlib.sha256(data).hexdigest()}
            self.total+=len(data);self._point()
        except BaseException:
            self.failed=True;raise

    def seal(self, snapshot):
        _need(not self.ready and not self.failed and set(self.files)==set(self.planned[0]))
        self.scratch.require(snapshot);self.snapshot=snapshot;self.ready=True;self.post()

    def from_snapshot(self, snapshot):
        """Read only this original scratch's already-authenticated input token."""
        self.scratch.require(snapshot)
        # Bound before BytesIO/copy/central-directory decoder allocation. ZIP
        # is the existing <=250MiB logical metadata + bounded directory overhead.
        _need(snapshot.size <= MAX_ARCHIVE_SIZE + 4*MAX_ROWS_BYTES + 512*MAX_FILE_COUNT + 65536)
        found=_read_file(self.scratch.slot.number,'store-metadata.zip',self.guard,snapshot.size,private=True)
        _need(found is not None and found[0]['sha256']==snapshot.sha256)
        raw=found[1];_need(len(raw)>=22 and raw[-22:-18]==b'PK\x05\x06')
        end=struct.unpack('<4s4H2IH',raw[-22:])
        _need(end[1:3]==(0,0) and end[3]==end[4] and end[4]<=MAX_FILE_COUNT and end[7]==0
              and end[5]+end[6]==len(raw)-22)
        # stdlib consumes central-directory length, not the advertised count.
        # Count actual fixed headers BEFORE it allocates any ZipInfo objects.
        cursor=end[6]; count=row_bytes=0
        while cursor < len(raw)-22:
            _need(cursor+46<=len(raw)-22 and raw[cursor:cursor+4]==b'PK\x01\x02')
            head=struct.unpack_from('<4s6H3I5H2I',raw,cursor)
            name_len,extra_len,comment_len=head[10:13]
            count+=1;row_bytes+=4*name_len+512
            _need(count<=end[4] and row_bytes<=MAX_ROWS_BYTES and 0<name_len<=4096
                  and extra_len==0 and comment_len==0 and cursor+46+name_len<=len(raw)-22)
            cursor+=46+name_len
        _need(cursor==len(raw)-22 and count==end[4])
        with zipfile.ZipFile(io.BytesIO(raw),'r') as archive:
            rows=archive.infolist();_need(len(rows)==end[4] and not archive.comment)
            names=tuple(row.filename for row in rows);self.begin(names)
            offset=0
            for row in rows:
                _need(row.header_offset==offset and row.compress_type==zipfile.ZIP_STORED
                      and row.file_size==row.compress_size and row.file_size<=MAX_FILE_SIZE
                      and row.external_attr==0o100644<<16 and not row.extra and not row.comment
                      and row.flag_bits in (0,0x800) and row.date_time==(1980,1,1,0,0,0))
                header=struct.unpack('<4s5H3I2H',raw[offset:offset+30])
                _need(header[0]==b'PK\x03\x04' and header[2]==row.flag_bits and header[3]==0
                      and header[7]==row.compress_size and header[8]==row.file_size and header[10]==0)
                name_bytes=row.filename.encode('utf-8' if row.flag_bits&0x800 else 'ascii')
                _need(header[9]==len(name_bytes) and raw[offset+30:offset+30+len(name_bytes)]==name_bytes)
                self.write(row.filename,archive.read(row))
                offset+=30+len(name_bytes)+row.file_size
            _need(offset==end[6])
        self.scratch.require(snapshot);self.seal(snapshot)

    def _names(self,name):
        self._point();entry=self.directories[name]
        expected={n.rpartition('/')[2] for n in self.planned[0] if n.rpartition('/')[0]==name}
        expected|={n.rpartition('/')[2] for n in self.planned[1] if n and n.rpartition('/')[0]==name}
        _need(self.iterator is None and self.scan_state in ('new','closed'));self.scan_state='acquiring'
        try:
            self.iterator=os.scandir(entry['slot'].number);self.scan_state='open';seen=set()
            for item in self.iterator:
                self._point();_need(item.name in expected and item.name not in seen);seen.add(item.name)
            _need(seen==expected)
        finally:
            original,self.iterator=self.iterator,None
            if original is not None:
                self.scan_state='closing'
                try:original.close()
                except BaseException as error:self.scan_state='unknown';self.guard._abort(error);raise
                self.scan_state='closed'
            elif self.scan_state=='acquiring':
                self.scan_state='unknown';self.guard._abort(ValueError('Metadata tree scan did not settle'))

    def post(self):
        _need(self.ready and not self.failed and not self.claimed and self.passes<4)
        self.passes+=1
        try:
            self._point();self.scratch.require(self.snapshot)
            for name in self.planned[1]:self._names(name)
            for entry in self.files.values():
                found=_read_file(entry['parent'].number,entry['name'],self.guard,MAX_FILE_SIZE,binding_only=True)
                _need(found==(entry['binding'],b''))
            self._point()
        except BaseException:self.failed=True;raise

    def binding_data(self):
        _need(self.ready and not self.failed and not self.claimed);self._point()
        rows=[dict(path=n,kind='directory') for n in self.planned[1] if n]
        rows.extend(dict(path=n,kind='file',bytes=e['binding']['size'],sha256=e['binding']['sha256']) for n,e in self.files.items())
        rows.sort(key=lambda r:r['path'].encode('utf-8'))
        _need(len(canonical(rows))<=4*MAX_ROWS_BYTES)
        root=os.fstat(self.directories['']['slot'].number)
        return dict(schemaVersion=1,root=str(self.path),rootIdentity=dict(device=str(root.st_dev),inode=str(root.st_ino),mode=root.st_mode,uid=root.st_uid,gid=root.st_gid),
            metadataSha256=self.snapshot.sha256,rosterSha256=hashlib.sha256(_DOMAIN+canonical(rows)+b'\n').hexdigest())

    def fork_close(self):
        # Child copies only, no unlink or parent settlement credit.
        if self.iterator is not None:
            from .cancellation import _mark_fork_unsafe
            _mark_fork_unsafe()
        for slot in reversed(self.writer_slots+self.slots): slot.close()

    def cleanup(self):
        if self.claimed:return
        self.claimed=True;error=None
        try:
            _need(self.guard.lifetime_ledger.verdict().complete and not self.guard.lifetime_ledger.verdict().fatal)
            _need(_consumer_idle(self.guard,lane_binding=self.scratch._lane_binding,desktop_binding=self.scratch._desktop_binding,owner=self.scratch))
            self._point()
            # Refuse to remove any unbound/foreign/unknown row, independently
            # consume original descriptors even if a partial writer is unknown.
            for name,entry in reversed(tuple(self.files.items())):
                found=_read_file(entry['parent'].number,entry['name'],self.guard,MAX_FILE_SIZE,binding_only=True)
                _need(entry['binding'] is not None and found==(entry['binding'],b''))
                self._point();os.unlink(entry['name'],dir_fd=entry['parent'].number)
            for name,entry in reversed(tuple(self.directories.items())):
                _check_creation(entry['creation'],entry['identity'])
                _need(entry['identity'] is not None);self._point()
                # rmdir refuses unrecognized content rather than recursively deleting.
                os.rmdir(entry['name'],dir_fd=entry['parent'].number)
                entry['retired']=True;entry['creation']['state']='RETIRED'
            self.retired=True
        except BaseException as caught:self.failed=True;error=caught
        finally:
            try:_attempt_all(self.guard,[s.close for s in reversed(self.writer_slots+self.slots)])
            except BaseException as caught:
                self.failed=True
                if error is None:error=caught
            self.closed=self.iterator is None and self.scan_state in ('new','closed') and all(s.number is None and s.close_state=='CLOSED' for s in self.slots+self.writer_slots)
        if error is not None:raise error
        _need(self.closed)
