//! DATA predicate only: no native Account/Book, descriptor, file or clock.
//! Positive comparison below is not a publication or close/finality witness.
use super::*;
fn original()->FileIdentity {FileIdentity {common:DirectoryIdentity {dev:1,ino:2,mode:0o100600,uid:1001,gid:1001},
    nlink:1,size:20,mtime:(1,2),ctime:(3,4)}}
#[test]
fn exact_own_unlink_allows_ctime_only_without_replacing_old_identity() {
    let old=original();let mut current=old;current.nlink=0;current.ctime=(9,10);
    let mut successor=old;successor.common.ino=3;
    assert!(unlinked_original(current,old,successor,0));
    assert!(old.nlink==1 && old.ctime==(3,4));
    assert!(!unlinked_original(current,old,current,0));
}
#[test]
fn foreign_index_metadata_never_uses_unlink_exception() {
    let old=original();let mut current=old;current.nlink=0;let mut successor=old;successor.common.ino=3;
    for mutate in [
        (|v:&mut FileIdentity|v.common.dev+=1) as fn(&mut FileIdentity),|v|v.common.ino+=1,
        |v|v.common.mode=0o100644,|v|v.common.uid+=1,|v|v.common.gid+=1,
        |v|v.nlink=1,|v|v.size+=1,|v|v.mtime.0+=1,
    ] {let mut changed=current;mutate(&mut changed);assert!(!unlinked_original(changed,old,successor,0));}
    assert!(!unlinked_original(current,old,successor,1));
}
