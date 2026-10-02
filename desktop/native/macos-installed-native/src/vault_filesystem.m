// Retained, same-descriptor storage ACL snapshot. No Keychain or process API.
// Each exported step enters at most one allocating/freeing API. The Rust owner
// observes a refusal BEFORE scheduling cleanup under its original endpoint.
#include <sys/acl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <uuid/uuid.h>

#define MRK_VAULT_ACL_MAGIC UINT64_C(0x4d524b5641434c31)
enum { ABSENT=0, ENTERED=1, OWNED=2, FREE_ENTERED=3, SETTLED=4, UNKNOWN=5 };
enum { RUNNING=0, ALLOWED=1, REFUSED=2, NATIVE=3, BOUNDS=4 };
enum { FSEC=0, ACL=1, QUALIFIER=2 };
typedef struct {
    uint64_t device, inode;
    uint32_t mode, owner, group, flags;
} mrk_vault_acl_expected;
typedef struct {
    uint32_t version, phase, outcome, resource[3], entries, qualifiers, qualifiers_closed;
    uint32_t first_phase;
    int32_t first_return, first_errno;
} mrk_vault_acl_facts;
typedef struct {
    uint64_t magic;
    mrk_vault_acl_facts facts;
    mrk_vault_acl_expected expected;
    filesec_t fsec;
    acl_t acl;
    void *qualifier;
    acl_entry_t entry;
    struct stat snapshot;
    acl_tag_t tag;
    uint32_t empty_policy;
} mrk_vault_acl_frame;

static int valid(mrk_vault_acl_frame *f) { return f && f->magic == MRK_VAULT_ACL_MAGIC; }
static int resources_settled(mrk_vault_acl_frame *f) {
    for (int i=0; i<3; ++i) if (f->facts.resource[i] != ABSENT && f->facts.resource[i] != SETTLED) return 0;
    return 1;
}
static void failure(mrk_vault_acl_frame *f, uint32_t kind, uint32_t at, int rc, int error) {
    if (!f->facts.first_phase) {
        f->facts.first_phase=at; f->facts.first_return=rc; f->facts.first_errno=error >= 0 ? error : EIO;
        f->facts.outcome=kind;
    }
}
static int snapshot_matches(mrk_vault_acl_frame *f) {
    struct stat *s=&f->snapshot; mrk_vault_acl_expected *e=&f->expected;
    return s->st_dev >= 0 && (uint64_t)s->st_dev == e->device && s->st_ino == e->inode
        && (uint32_t)s->st_mode == e->mode && s->st_uid == e->owner
        && s->st_gid == e->group && s->st_flags == e->flags;
}
// Inheritance flags never relax this policy: even an inherit-only ALLOW write
// is refused. DENY entries confer no authority. Unknown tags/rights are refused.
static int entry_policy(acl_tag_t tag, acl_permset_mask_t rights) {
    const acl_permset_mask_t read = ACL_READ_DATA | ACL_EXECUTE | ACL_READ_ATTRIBUTES
        | ACL_READ_EXTATTRIBUTES | ACL_READ_SECURITY | ACL_SYNCHRONIZE;
    const acl_permset_mask_t mutation = ACL_WRITE_DATA | ACL_APPEND_DATA | ACL_DELETE
        | ACL_DELETE_CHILD | ACL_WRITE_ATTRIBUTES | ACL_WRITE_EXTATTRIBUTES
        | ACL_WRITE_SECURITY | ACL_CHANGE_OWNER;
    return (tag == ACL_EXTENDED_ALLOW || tag == ACL_EXTENDED_DENY)
        && !(rights & ~(read | mutation)) && (tag == ACL_EXTENDED_DENY || !(rights & mutation));
}
size_t mrk_vault_acl_frame_bytes(void) { return sizeof(mrk_vault_acl_frame); }
void *mrk_vault_acl_frame_new(void) {
    mrk_vault_acl_frame *f=calloc(1, sizeof(*f));
    if (f) { f->magic=MRK_VAULT_ACL_MAGIC; f->facts.version=1; }
    return f;
}
int mrk_vault_acl_facts_read(void *raw, mrk_vault_acl_facts *out) {
    mrk_vault_acl_frame *f=raw; if (!valid(f) || !out) return 0;
    *out=f->facts; return 1;
}
int mrk_vault_acl_begin(void *raw, const mrk_vault_acl_expected *expected, uint32_t empty) {
    mrk_vault_acl_frame *f=raw;
    if (!valid(f) || !expected || empty > 1 || !resources_settled(f) || f->facts.first_phase
        || !((f->facts.phase == 0 && f->facts.outcome == RUNNING) || f->facts.outcome == ALLOWED)) return 0;
    memset(&f->facts, 0, sizeof(f->facts)); memset(&f->snapshot, 0, sizeof(f->snapshot));
    f->fsec=NULL; f->acl=NULL; f->qualifier=NULL; f->entry=NULL;
    f->facts.version=1; f->facts.phase=1; f->expected=*expected; f->empty_policy=empty;
    return 1;
}
static void entry_next(mrk_vault_acl_frame *f, int which) {
    errno=0; f->entry=NULL;
    int rc=acl_get_entry(f->acl, which, &f->entry), error=errno;
    if (rc == -1 && error == EINVAL) { f->facts.phase=15; f->facts.outcome=ALLOWED; return; }
    if (rc != 0 || !f->entry) { failure(f, NATIVE, f->facts.phase, rc, error); return; }
    if (++f->facts.entries > 128) { failure(f, BOUNDS, f->facts.phase, 0, 0); return; }
    f->facts.phase=10;
}
static void free_qualifier(mrk_vault_acl_frame *f, uint32_t phase) {
    f->facts.resource[QUALIFIER]=FREE_ENTERED;
    errno=0; int rc=acl_free(f->qualifier), error=errno;
    if (rc) { f->facts.resource[QUALIFIER]=UNKNOWN; failure(f, NATIVE, phase, rc, error); }
    else { f->qualifier=NULL; f->facts.resource[QUALIFIER]=SETTLED; ++f->facts.qualifiers_closed; }
}
int mrk_vault_acl_step(void *raw, int fd) {
    mrk_vault_acl_frame *f=raw;
    if (!valid(f) || fd < 0 || f->facts.outcome != RUNNING || f->facts.phase < 1 || f->facts.phase > 14) return 0;
    int rc=0, error=0;
    switch (f->facts.phase) {
    case 1:
        f->facts.resource[FSEC]=ENTERED; errno=0; f->fsec=filesec_init(); error=errno;
        f->facts.resource[FSEC]=f->fsec ? OWNED : SETTLED;
        if (!f->fsec) failure(f,NATIVE,1,0,error); else f->facts.phase=2;
        break;
    case 2:
        errno=0; rc=fstatx_np(fd,&f->snapshot,f->fsec); error=errno;
        if (rc) failure(f,NATIVE,2,rc,error);
        else if (!snapshot_matches(f)) failure(f,REFUSED,2,0,0);
        else f->facts.phase=3;
        break;
    case 3: {
        uid_t owner=0; errno=0; rc=filesec_get_property(f->fsec,FILESEC_OWNER,&owner); error=errno;
        if (rc) failure(f,NATIVE,3,rc,error);
        else if (owner != f->snapshot.st_uid) failure(f,REFUSED,3,0,0);
        else f->facts.phase=4; break;
    }
    case 4: {
        gid_t group=0; errno=0; rc=filesec_get_property(f->fsec,FILESEC_GROUP,&group); error=errno;
        if (rc) failure(f,NATIVE,4,rc,error);
        else if (group != f->snapshot.st_gid) failure(f,REFUSED,4,0,0);
        else f->facts.phase=5; break;
    }
    case 5: {
        mode_t mode=0; errno=0; rc=filesec_get_property(f->fsec,FILESEC_MODE,&mode); error=errno;
        if (rc) failure(f,NATIVE,5,rc,error);
        else if (mode != f->snapshot.st_mode) failure(f,REFUSED,5,0,0);
        else f->facts.phase=6; break;
    }
    case 6: {
        int present=0; errno=0; rc=filesec_query_property(f->fsec,FILESEC_ACL,&present); error=errno;
        if (rc) failure(f,NATIVE,6,rc,error);
        else if (!present) { f->facts.phase=15; f->facts.outcome=ALLOWED; }
        else f->facts.phase=7; break;
    }
    case 7:
        f->facts.resource[ACL]=ENTERED; f->acl=NULL;
        errno=0; rc=filesec_get_property(f->fsec,FILESEC_ACL,&f->acl); error=errno;
        if (f->acl && (void *)f->acl != _FILESEC_REMOVE_ACL && (void *)f->acl != _FILESEC_UNSET_PROPERTY)
            f->facts.resource[ACL]=OWNED;
        else { f->acl=NULL; f->facts.resource[ACL]=SETTLED; }
        if (rc) failure(f,NATIVE,7,rc,error);
        else if (f->facts.resource[ACL] != OWNED) failure(f,REFUSED,7,0,0);
        else f->facts.phase=8;
        break;
    case 8:
        errno=0; rc=acl_valid(f->acl); error=errno;
        if (rc) failure(f,NATIVE,8,rc,error); else f->facts.phase=9;
        break;
    case 9: entry_next(f,ACL_FIRST_ENTRY); break;
    case 10:
        errno=0; rc=acl_get_tag_type(f->entry,&f->tag); error=errno;
        if (rc) failure(f,NATIVE,10,rc,error);
        else if (f->empty_policy || (f->tag != ACL_EXTENDED_ALLOW && f->tag != ACL_EXTENDED_DENY))
            failure(f,REFUSED,10,0,0);
        else f->facts.phase=11;
        break;
    case 11: {
        acl_permset_mask_t rights=0; errno=0; rc=acl_get_permset_mask_np(f->entry,&rights); error=errno;
        if (rc) failure(f,NATIVE,11,rc,error);
        else if (!entry_policy(f->tag,rights)) failure(f,REFUSED,11,0,0);
        else f->facts.phase=12; break;
    }
    case 12: {
        f->facts.resource[QUALIFIER]=ENTERED; errno=0; f->qualifier=acl_get_qualifier(f->entry); error=errno;
        f->facts.resource[QUALIFIER]=f->qualifier ? OWNED : SETTLED;
        if (!f->qualifier) { failure(f,NATIVE,12,0,error); break; }
        ++f->facts.qualifiers;
        uint8_t uuid[sizeof(uuid_t)]; memcpy(uuid,f->qualifier,sizeof(uuid)); uint8_t any=0;
        for (size_t i=0; i<sizeof(uuid); ++i) any |= uuid[i];
        if (!any) failure(f,REFUSED,12,0,0); else f->facts.phase=13;
        break;
    }
    case 13:
        free_qualifier(f,13);
        if (f->facts.outcome == RUNNING) f->facts.phase=14;
        break;
    case 14: entry_next(f,ACL_NEXT_ENTRY); break;
    default: return 0;
    }
    return 1;
}
int mrk_vault_acl_cleanup_step(void *raw) {
    mrk_vault_acl_frame *f=raw; if (!valid(f)) return 0;
    // Consume each original once. Unknown free outcomes are retained and never
    // retried; other positively owned independent references may still retire.
    if (f->facts.resource[QUALIFIER] == OWNED) { free_qualifier(f,16); return 1; }
    if (f->facts.resource[ACL] == OWNED) {
        f->facts.resource[ACL]=FREE_ENTERED; errno=0; int rc=acl_free(f->acl), error=errno;
        if (rc) { f->facts.resource[ACL]=UNKNOWN; failure(f,NATIVE,17,rc,error); }
        else { f->acl=NULL; f->entry=NULL; f->facts.resource[ACL]=SETTLED; }
        return 1;
    }
    if (f->facts.resource[FSEC] == OWNED) {
        f->facts.resource[FSEC]=FREE_ENTERED;
        filesec_free(f->fsec); // Void API: positive settlement requires actual return.
        f->fsec=NULL; f->facts.resource[FSEC]=SETTLED; return 1;
    }
    return 0;
}
int mrk_vault_acl_frame_retire(void *raw) {
    mrk_vault_acl_frame *f=raw;
    if (!valid(f) || !resources_settled(f)) return 0;
    f->magic=0; free(f); return 1;
}
// Same policy used above, with no filesystem/provider effect. Rust cfg(test)
// exposes this only to the native crate's inert policy regression tests.
uint32_t mrk_vault_acl_policy_data_contract(void) {
    const acl_permset_mask_t reads[] = { ACL_READ_DATA, ACL_EXECUTE, ACL_READ_ATTRIBUTES,
        ACL_READ_EXTATTRIBUTES, ACL_READ_SECURITY, ACL_SYNCHRONIZE };
    const acl_permset_mask_t writes[] = { ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE,
        ACL_DELETE_CHILD, ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER };
    for (size_t i=0; i<sizeof(reads)/sizeof(reads[0]); ++i)
        if (!entry_policy(ACL_EXTENDED_ALLOW,reads[i]) || !entry_policy(ACL_EXTENDED_DENY,reads[i])) return 0;
    for (size_t i=0; i<sizeof(writes)/sizeof(writes[0]); ++i)
        if (entry_policy(ACL_EXTENDED_ALLOW,writes[i]) || !entry_policy(ACL_EXTENDED_DENY,writes[i])) return 0;
    if (entry_policy(ACL_UNDEFINED_TAG,ACL_READ_DATA)
        || entry_policy(ACL_EXTENDED_ALLOW,UINT64_MAX) || entry_policy(ACL_EXTENDED_DENY,UINT64_MAX)) return 0;
    return 15;
}
