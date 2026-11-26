"""Fixed readonly source/dependency checks and private offline Cargo layout."""
import hashlib,json,os,stat,sys
from pathlib import Path
assert (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
        and type(sys.pycache_prefix) is str and sys.pycache_prefix == '/run/mrk-gnome-python-empty-pycache-v1')
assert len(sys.argv)==2 and sys.argv[1] in ('prepare','post')
x=json.loads(Path('/inputs.json').read_bytes())
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
for row in x['checkedFiles']:
 p=Path(row['path']);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes']<=32<<20
  assert stat.S_IMODE(before.st_mode)==int(row['mode'],8)
  h=hashlib.sha256();count=0
  while True:
   part=os.read(fd,65536)
   if not part:break
   h.update(part);count+=len(part)
  assert count==row['bytes'] and h.hexdigest()==row['sha256'],row['path']
  assert identity(before)==row['identity']==identity(os.fstat(fd))==identity(p.lstat()),row['path']
 finally:os.close(fd)
for row in x['registryDirectories']+x['sourceDirectories']:
 p=Path(row['path']);s=p.lstat();assert stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==int(row['mode'],8)
 assert [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns]==row['identity'],row['path']
 assert sorted(os.listdir(p))==row['entries'],row['path']
print('VAULT_FINALITY_'+sys.argv[1].upper()+'_MATCHED='+str(len(x['checkedFiles'])),flush=True)
if sys.argv[1]=='post':raise SystemExit(0)
reg='index.crates.io-1949cf8c6b5b557f';base=Path('/tmp/cargo/registry');index=base/'index'/reg
(index/'.cache').mkdir(parents=True,mode=0o700);(index/'config.json').symlink_to(x['indexConfig']['path'])
for row in x['indexes']:
 dest=index/'.cache'/row['relative'];dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);dest.symlink_to(row['path'])
src=base/'src'/reg;src.mkdir(parents=True,mode=0o700)
for row in x['registrySources']:(src/row['name']).symlink_to(row['path'])
cache=base/'cache'/reg;cache.mkdir(parents=True,mode=0o700)
for row in x['archives']:(cache/row['filename']).symlink_to(row['path'])
for name in ('home','work','rustup','neutral'):Path('/tmp',name).mkdir(mode=0o700)
