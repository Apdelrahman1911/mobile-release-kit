// Retained, same-descriptor storage ACL snapshot. No Keychain or process API.
// Each exported step enters at most one allocating/freeing API. The Rust owner
// observes a refusal BEFORE scheduling cleanup under its original endpoint.
#include <sys/acl.h>
#include "vault_helper_control.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <membership.h>

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
    uint32_t lease_uid;
    uuid_t lease_principal, native_principal;
    struct kauth_filesec lease_export;
} mrk_vault_acl_frame;
_Static_assert(sizeof(mrk_vault_acl_frame)<=1024, "snapshot supplied frame exceeds Rust precharge");

static int valid(mrk_vault_acl_frame *f) { return f && f->magic == MRK_VAULT_ACL_MAGIC; }
static int resources_settled(mrk_vault_acl_frame *f) {
    for (int i=0; i<3; ++i) if (f->facts.resource[i] != ABSENT && f->facts.resource[i] != SETTLED) return 0;
    return 1;
}
static void failure(mrk_vault_acl_frame *f, uint32_t kind, uint32_t at, int rc, int error) {
    mrk_vault_control_failure(); // Fixed helper stamp; ordinary app build is a no-op.
    if (!f->facts.first_phase) {
        f->facts.first_phase=at; f->facts.first_return=rc; f->facts.first_errno=error >= 0 ? error : EIO;
        f->facts.outcome=kind;
    }
}
static int snapshot_matches(mrk_vault_acl_frame *f) {
    struct stat *s=&f->snapshot; mrk_vault_acl_expected *e=&f->expected;
    return s->st_dev >= 0 && (uint64_t)s->st_dev == e->device && s->st_ino == e->inode
        && (uint32_t)s->st_mode == e->mode && s->st_uid == e->owner
        && s->st_gid == e->group && s->st_flags == e->flags
        && (f->empty_policy != 2 || s->st_nlink == 1);
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
// Closed, separate lease policy. acl_valid() does not validate all flag bits;
// the documented native external form preserves the FULL public flags/rights.
// No opaque ACL layout, new native allocation or relaxed payload policy is used.
_Static_assert(sizeof(guid_t) == sizeof(uuid_t), "native principal width");
_Static_assert(sizeof(struct kauth_filesec) == KAUTH_FILESEC_SIZE(1), "one-ACE external width");
static int lease_principal_policy(const uint8_t *principal) {
    const uint8_t synthesized_user[12]={0xff,0xff,0xee,0xee,0xdd,0xdd,0xcc,0xcc,0xbb,0xbb,0xaa,0xaa};
    const uint8_t synthesized_group[12]={0xaa,0xaa,0xbb,0xbb,0xcc,0xcc,0xdd,0xdd,0xee,0xee,0xff,0xff};
    uint8_t any=0;
    for (size_t i=0; i<sizeof(uuid_t); ++i) any |= principal[i];
    // Libinfo documents these fallback UUIDs as UID/GID-derived, not stable
    // account identity. A successful membership roundtrip alone is insufficient.
    return any && memcmp(principal,synthesized_user,sizeof(synthesized_user))
        && memcmp(principal,synthesized_group,sizeof(synthesized_group));
}
static int lease_export_policy(const struct kauth_filesec *ext, const uint8_t *principal) {
    const acl_permset_mask_t read = ACL_READ_DATA | ACL_READ_ATTRIBUTES
        | ACL_READ_EXTATTRIBUTES | ACL_READ_SECURITY;
    return lease_principal_policy(principal)
        && ext->fsec_magic == KAUTH_FILESEC_MAGIC && ext->fsec_entrycount == 1
        && ext->fsec_flags == 0
        && ext->fsec_ace[0].ace_flags == KAUTH_ACE_PERMIT
        && ext->fsec_ace[0].ace_rights == read
        && memcmp(&ext->fsec_ace[0].ace_applicable,principal,sizeof(uuid_t)) == 0;
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
    f->lease_uid=0; memset(f->lease_principal,0,sizeof(uuid_t));
    memset(f->native_principal,0,sizeof(uuid_t)); memset(&f->lease_export,0,sizeof(f->lease_export));
    f->facts.version=1; f->facts.phase=1; f->expected=*expected; f->empty_policy=empty;
    return 1;
}
int mrk_vault_acl_begin_lease_user(void *raw, const mrk_vault_acl_expected *expected,
    uint32_t uid, const uint8_t *principal) {
    if (!principal || !mrk_vault_acl_begin(raw,expected,0)) return 0;
    mrk_vault_acl_frame *f=raw;
    f->expected=*expected; f->empty_policy=2;
    if (uid == 0 || uid == UINT32_MAX || !lease_principal_policy(principal)
        || expected->owner != 0 || expected->group != 0 || expected->flags != 0
        || expected->mode != (S_IFREG | 0400)) {
        failure(f,REFUSED,1,0,0); return 1;
    }
    f->lease_uid=uid; memcpy(f->lease_principal,principal,sizeof(uuid_t));
    return 1;
}
static void entry_next(mrk_vault_acl_frame *f, int which) {
    errno=0; f->entry=NULL;
    int rc=acl_get_entry(f->acl, which, &f->entry), error=errno;
    if (rc == -1 && error == EINVAL) {
        if (f->empty_policy == 2 && f->facts.entries != 1) failure(f,REFUSED,f->facts.phase,0,0);
        else { f->facts.phase=15; f->facts.outcome=ALLOWED; }
        return;
    }
    if (rc != 0 || !f->entry) { failure(f, NATIVE, f->facts.phase, rc, error); return; }
    if (++f->facts.entries > 128) { failure(f, BOUNDS, f->facts.phase, 0, 0); return; }
    if (f->empty_policy == 2 && f->facts.entries != 1) { failure(f,REFUSED,f->facts.phase,0,0); return; }
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
    if (!valid(f) || fd < 0 || f->facts.outcome != RUNNING
        || !((f->facts.phase >= 1 && f->facts.phase <= 14) || (f->facts.phase >= 19 && f->facts.phase <= 23))) return 0;
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
        else if (!present && f->empty_policy == 2) failure(f,REFUSED,6,0,0);
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
        if (rc) failure(f,NATIVE,8,rc,error); else f->facts.phase=f->empty_policy == 2 ? 19 : 9;
        break;
    case 9: entry_next(f,ACL_FIRST_ENTRY); break;
    case 10:
        errno=0; rc=acl_get_tag_type(f->entry,&f->tag); error=errno;
        if (rc) failure(f,NATIVE,10,rc,error);
        else if (f->empty_policy == 1 || (f->tag != ACL_EXTENDED_ALLOW && f->tag != ACL_EXTENDED_DENY))
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
    case 19: {
        errno=0; ssize_t amount=acl_size(f->acl); error=errno;
        if (amount < 0) failure(f,NATIVE,19,-1,error);
        else if (amount != (ssize_t)sizeof(f->lease_export)) failure(f,REFUSED,19,0,0);
        else f->facts.phase=20;
        break;
    }
    case 20: {
        // Fixed preallocated frame storage; this API creates no caller-owned
        // allocation. The header/ACE fields below are public SDK structures.
        errno=0; ssize_t amount=acl_copy_ext_native(&f->lease_export,f->acl,sizeof(f->lease_export)); error=errno;
        if (amount < 0) failure(f,NATIVE,20,-1,error);
        else if (amount != (ssize_t)sizeof(f->lease_export)) failure(f,NATIVE,20,0,EIO);
        else f->facts.phase=21;
        break;
    }
    case 21:
        if (!lease_export_policy(&f->lease_export,f->lease_principal)) failure(f,REFUSED,21,0,0);
        else f->facts.phase=22;
        break;
    case 22:
        rc=mbr_uid_to_uuid((uid_t)f->lease_uid,f->native_principal);
        if (rc) failure(f,NATIVE,22,rc,rc);
        else if (!lease_principal_policy(f->native_principal)
            || memcmp(f->native_principal,f->lease_principal,sizeof(uuid_t))) failure(f,REFUSED,22,0,0);
        else f->facts.phase=23;
        break;
    case 23: {
        id_t mapped=0; int kind=-1;
        rc=mbr_uuid_to_id(f->native_principal,&mapped,&kind);
        if (rc) failure(f,NATIVE,23,rc,rc);
        else if (kind != ID_TYPE_UID || mapped != (id_t)f->lease_uid) failure(f,REFUSED,23,0,0);
        else f->facts.phase=9;
        break;
    }
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
// DATA only: exercise the same full-width lease predicate without filesystem,
// membership, allocation, privileged publication or user-account effects.
uint32_t mrk_vault_acl_lease_policy_data_contract(void) {
    struct kauth_filesec good; memset(&good,0,sizeof(good));
    uuid_t principal={0x12,0x34,0x56,0x78,0x9a,0xbc,0x4d,0xef,0x81,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    good.fsec_magic=KAUTH_FILESEC_MAGIC; good.fsec_entrycount=1;
    good.fsec_ace[0].ace_flags=KAUTH_ACE_PERMIT;
    good.fsec_ace[0].ace_rights=ACL_READ_DATA|ACL_READ_ATTRIBUTES|ACL_READ_EXTATTRIBUTES|ACL_READ_SECURITY;
    memcpy(&good.fsec_ace[0].ace_applicable,principal,sizeof(principal));
    if (!lease_export_policy(&good,principal)) return 0;
    for (uint32_t bit=0; bit<32; ++bit) {
        struct kauth_filesec changed=good; changed.fsec_flags=UINT32_C(1)<<bit;
        if (lease_export_policy(&changed,principal)) return 0;
        changed=good; changed.fsec_ace[0].ace_flags ^= UINT32_C(1)<<bit;
        if (lease_export_policy(&changed,principal)) return 0;
        changed=good; changed.fsec_ace[0].ace_rights ^= UINT32_C(1)<<bit;
        if (lease_export_policy(&changed,principal)) return 0;
    }
    struct kauth_filesec changed=good; changed.fsec_entrycount=0;
    if (lease_export_policy(&changed,principal)) return 0;
    changed=good; changed.fsec_entrycount=2;
    if (lease_export_policy(&changed,principal)) return 0;
    changed=good; changed.fsec_magic ^= 1;
    if (lease_export_policy(&changed,principal)) return 0;
    changed=good; ((uint8_t *)&changed.fsec_ace[0].ace_applicable)[0] ^= 1;
    if (lease_export_policy(&changed,principal)) return 0;
    uuid_t invalid={0};
    if (lease_principal_policy(invalid)) return 0;
    const uint8_t fallback[2][12]={
        {0xff,0xff,0xee,0xee,0xdd,0xdd,0xcc,0xcc,0xbb,0xbb,0xaa,0xaa},
        {0xaa,0xaa,0xbb,0xbb,0xcc,0xcc,0xdd,0xdd,0xee,0xee,0xff,0xff}};
    for (size_t i=0; i<2; ++i) {
        memcpy(invalid,fallback[i],12); invalid[15]=1;
        if (lease_principal_policy(invalid)) return 0;
    }
    return 31;
}



// Fixed original-new-lease ACL writer. This is NOT the snapshot observer and
// never changes its Empty/Ancestors policies. The containing helper must own the
// new parent-relative exclusive0600 file and original EX lease BEFORE entry.
// Only the exact selected-account read ACE is constructed; no caller ACL bytes,
// path, chmod/chown, lock, fd acquisition, unlock, close or retry is accepted.
#define MRK_ANDROID_LEASE_ACL_WRITE_MAGIC UINT64_C(0x4d524b414c575231)
enum { EFFECT_ABSENT=0, EFFECT_ENTERED=1, EFFECT_APPLIED=2, EFFECT_UNKNOWN=3 };
typedef struct {
    mrk_vault_acl_expected identity;
    uint64_t links, bytes;
    int64_t modified_seconds, modified_nanoseconds, changed_seconds, changed_nanoseconds;
} mrk_android_lease_acl_write_expected;
typedef struct {
    uint32_t version, phase, outcome, resource, effect, post_observed;
    uint32_t first_phase;
    int32_t first_return, first_errno, free_return, free_errno;
    int64_t changed_seconds, changed_nanoseconds;
} mrk_android_lease_acl_write_facts;
typedef struct {
    uint64_t magic;
    mrk_android_lease_acl_write_facts facts;
    mrk_android_lease_acl_write_expected expected;
    int descriptor;
    uint32_t uid;
    uuid_t principal, native_principal;
    struct kauth_filesec external, readback;
    struct stat snapshot;
    acl_t acl;
} mrk_android_lease_acl_write_frame;
_Static_assert(sizeof(mrk_android_lease_acl_write_frame)<=1024, "lease supplied frame exceeds Rust precharge");

static int lease_write_valid(mrk_android_lease_acl_write_frame *f) {
    return f && f->magic == MRK_ANDROID_LEASE_ACL_WRITE_MAGIC;
}
static void lease_write_failure(mrk_android_lease_acl_write_frame *f, uint32_t kind,
    uint32_t phase, int rc, int error) {
    if (!f->facts.first_phase) {
        f->facts.first_phase=phase; f->facts.first_return=rc;
        f->facts.first_errno=error >= 0 ? error : EIO; f->facts.outcome=kind;
    }
}
static int lease_write_shape(const mrk_android_lease_acl_write_expected *e) {
    return e->identity.device && e->identity.inode
        && e->identity.mode == (S_IFREG | 0600) && e->identity.owner == 0
        && e->identity.group == 0 && e->identity.flags == 0
        && e->links == 1 && e->bytes == 60
        && e->modified_nanoseconds >= 0 && e->modified_nanoseconds < INT64_C(1000000000)
        && e->changed_nanoseconds >= 0 && e->changed_nanoseconds < INT64_C(1000000000);
}
static int lease_write_matches(mrk_android_lease_acl_write_frame *f, int after_mutation) {
    const struct stat *s=&f->snapshot;
    const mrk_android_lease_acl_write_expected *e=&f->expected;
    return lease_write_shape(e) && s->st_dev >= 0
        && (uint64_t)s->st_dev == e->identity.device && s->st_ino == e->identity.inode
        && s->st_mode == e->identity.mode && s->st_uid == e->identity.owner
        && s->st_gid == e->identity.group && s->st_flags == e->identity.flags
        && s->st_nlink == 1 && s->st_size == 60
        && s->st_mtimespec.tv_sec == e->modified_seconds
        && s->st_mtimespec.tv_nsec == e->modified_nanoseconds
        && s->st_ctimespec.tv_nsec >= 0 && s->st_ctimespec.tv_nsec < 1000000000
        && (after_mutation || (s->st_ctimespec.tv_sec == e->changed_seconds
            && s->st_ctimespec.tv_nsec == e->changed_nanoseconds));
}
static int lease_write_external(struct kauth_filesec *out, const uint8_t *principal) {
    if (!out || !principal || !lease_principal_policy(principal)) return 0;
    memset(out,0,sizeof(*out)); out->fsec_magic=KAUTH_FILESEC_MAGIC; out->fsec_entrycount=1;
    out->fsec_ace[0].ace_flags=KAUTH_ACE_PERMIT;
    out->fsec_ace[0].ace_rights=ACL_READ_DATA | ACL_READ_ATTRIBUTES
        | ACL_READ_EXTATTRIBUTES | ACL_READ_SECURITY;
    memcpy(&out->fsec_ace[0].ace_applicable,principal,sizeof(uuid_t));
    return lease_export_policy(out,principal);
}
size_t mrk_android_lease_acl_write_frame_bytes(void) { return sizeof(mrk_android_lease_acl_write_frame); }
void *mrk_android_lease_acl_write_frame_new(void) {
    mrk_android_lease_acl_write_frame *f=calloc(1,sizeof(*f));
    if (f) { f->magic=MRK_ANDROID_LEASE_ACL_WRITE_MAGIC; f->facts.version=1; f->descriptor=-1; }
    return f;
}
int mrk_android_lease_acl_write_facts_read(void *raw, mrk_android_lease_acl_write_facts *out) {
    mrk_android_lease_acl_write_frame *f=raw;
    if (!lease_write_valid(f) || !out) return 0;
    *out=f->facts; return 1;
}
int mrk_android_lease_acl_write_begin(void *raw, int fd,
    const mrk_android_lease_acl_write_expected *expected, uint32_t uid, const uint8_t *principal) {
    mrk_android_lease_acl_write_frame *f=raw;
    if (!lease_write_valid(f) || !expected || !principal || f->facts.phase
        || f->facts.resource != ABSENT || f->facts.effect != EFFECT_ABSENT) return 0;
    f->facts.phase=1;
    if (fd < 0 || uid == 0 || uid == UINT32_MAX || !lease_write_shape(expected)
        || !lease_principal_policy(principal) || !lease_write_external(&f->external,principal)) {
        lease_write_failure(f,REFUSED,1,0,0); return 1;
    }
    f->descriptor=fd; f->uid=uid; f->expected=*expected;
    memcpy(f->principal,principal,sizeof(uuid_t));
    return 1;
}
int mrk_android_lease_acl_write_step(void *raw, int fd) {
    mrk_android_lease_acl_write_frame *f=raw;
    if (!lease_write_valid(f) || fd < 0 || fd != f->descriptor || f->facts.outcome != RUNNING
        || f->facts.phase < 1 || f->facts.phase > 10) return 0;
    int rc=0,error=0;
    switch (f->facts.phase) {
    case 1:
        rc=mbr_uid_to_uuid((uid_t)f->uid,f->native_principal);
        if (rc) lease_write_failure(f,NATIVE,1,rc,rc);
        else if (!lease_principal_policy(f->native_principal)
            || memcmp(f->native_principal,f->principal,sizeof(uuid_t))) lease_write_failure(f,REFUSED,1,0,0);
        else f->facts.phase=2;
        break;
    case 2: {
        id_t mapped=0; int kind=-1;
        rc=mbr_uuid_to_id(f->native_principal,&mapped,&kind);
        if (rc) lease_write_failure(f,NATIVE,2,rc,rc);
        else if (kind != ID_TYPE_UID || mapped != (id_t)f->uid) lease_write_failure(f,REFUSED,2,0,0);
        else f->facts.phase=3;
        break;
    }
    case 3:
        errno=0; rc=fstat(fd,&f->snapshot); error=errno;
        if (rc) lease_write_failure(f,NATIVE,3,rc,error);
        else if (!lease_write_matches(f,0)) lease_write_failure(f,REFUSED,3,0,0);
        else f->facts.phase=4;
        break;
    case 4:
        // Native external-form conversion owns one returned ACL allocation.
        // No opaque libc layout, text parser, caller flags or reallocating
        // create-entry series is used.
        f->facts.resource=ENTERED; errno=0; f->acl=acl_copy_int_native(&f->external); error=errno;
        f->facts.resource=f->acl ? OWNED : SETTLED;
        if (!f->acl) lease_write_failure(f,NATIVE,4,0,error); else f->facts.phase=5;
        break;
    case 5:
        errno=0; rc=acl_valid(f->acl); error=errno;
        if (rc) lease_write_failure(f,NATIVE,5,rc,error); else f->facts.phase=6;
        break;
    case 6: {
        errno=0; ssize_t amount=acl_size(f->acl); error=errno;
        if (amount < 0) lease_write_failure(f,NATIVE,6,-1,error);
        else if (amount != (ssize_t)sizeof(f->readback)) lease_write_failure(f,REFUSED,6,0,0);
        else f->facts.phase=7;
        break;
    }
    case 7: {
        errno=0; ssize_t amount=acl_copy_ext_native(&f->readback,f->acl,sizeof(f->readback)); error=errno;
        if (amount < 0) lease_write_failure(f,NATIVE,7,-1,error);
        else if (amount != (ssize_t)sizeof(f->readback)) lease_write_failure(f,NATIVE,7,0,EIO);
        else if (!lease_export_policy(&f->readback,f->principal)) lease_write_failure(f,REFUSED,7,0,0);
        else f->facts.phase=8;
        break;
    }
    case 8:
        // Recheck the unchanged original immediately before the ONLY mutation.
        errno=0; rc=fstat(fd,&f->snapshot); error=errno;
        if (rc) lease_write_failure(f,NATIVE,8,rc,error);
        else if (!lease_write_matches(f,0)) lease_write_failure(f,REFUSED,8,0,0);
        else f->facts.phase=9;
        break;
    case 9:
        f->facts.effect=EFFECT_ENTERED;
        errno=0; rc=acl_set_fd_np(fd,f->acl,ACL_TYPE_EXTENDED); error=errno;
        if (rc) {
            // A failed setter cannot prove there was no metadata effect.
            f->facts.effect=EFFECT_UNKNOWN; lease_write_failure(f,NATIVE,9,rc,error);
        } else { f->facts.effect=EFFECT_APPLIED; f->facts.phase=10; }
        break;
    case 10:
        errno=0; rc=fstat(fd,&f->snapshot); error=errno;
        if (rc) lease_write_failure(f,NATIVE,10,rc,error);
        else if (!lease_write_matches(f,1)) lease_write_failure(f,REFUSED,10,0,0);
        else {
            f->facts.changed_seconds=f->snapshot.st_ctimespec.tv_sec;
            f->facts.changed_nanoseconds=f->snapshot.st_ctimespec.tv_nsec;
            f->facts.post_observed=1; f->facts.phase=11; f->facts.outcome=ALLOWED;
        }
        break;
    default: return 0;
    }
    return 1;
}
int mrk_android_lease_acl_write_cleanup(void *raw) {
    mrk_android_lease_acl_write_frame *f=raw;
    if (!lease_write_valid(f) || f->facts.resource != OWNED) return 0;
    f->facts.resource=FREE_ENTERED; errno=0; int rc=acl_free(f->acl),error=errno;
    f->facts.free_return=rc; f->facts.free_errno=error;
    if (rc) { f->facts.resource=UNKNOWN; lease_write_failure(f,NATIVE,12,rc,error); }
    else { f->acl=NULL; f->facts.resource=SETTLED; }
    return 1;
}
int mrk_android_lease_acl_write_retire(void *raw) {
    mrk_android_lease_acl_write_frame *f=raw;
    if (!lease_write_valid(f) || (f->facts.resource != ABSENT && f->facts.resource != SETTLED)) return 0;
    f->magic=0; free(f); return 1;
}
// Pure DATA only. Uses the SAME shape and exact one-ACE construction/predicate,
// not a fixture implementation and never an ACL allocation/setter.
uint32_t mrk_android_lease_acl_writer_data_contract(void) {
    const uint8_t principal[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    struct kauth_filesec ext;
    if (!lease_write_external(&ext,principal) || !lease_export_policy(&ext,principal)) return 0;
    uint8_t invalid[16]={0};
    if (lease_write_external(&ext,invalid)) return 0;
    mrk_android_lease_acl_write_frame f; memset(&f,0,sizeof(f));
    f.expected=(mrk_android_lease_acl_write_expected){
        .identity={.device=7,.inode=42,.mode=S_IFREG|0600,.owner=0,.group=0,.flags=0},
        .links=1,.bytes=60,.modified_seconds=1,.modified_nanoseconds=2,.changed_seconds=3,.changed_nanoseconds=4};
    f.snapshot.st_dev=7; f.snapshot.st_ino=42; f.snapshot.st_mode=S_IFREG|0600; f.snapshot.st_nlink=1;
    f.snapshot.st_size=60; f.snapshot.st_mtimespec.tv_sec=1; f.snapshot.st_mtimespec.tv_nsec=2;
    f.snapshot.st_ctimespec.tv_sec=3; f.snapshot.st_ctimespec.tv_nsec=4;
    if (!lease_write_matches(&f,0) || !lease_write_matches(&f,1)) return 0;
    f.snapshot.st_ctimespec.tv_nsec=5;
    if (lease_write_matches(&f,0) || !lease_write_matches(&f,1)) return 0;
    f.snapshot.st_mtimespec.tv_nsec=3;
    if (lease_write_matches(&f,1)) return 0;
    for (int which=0; which<8; ++which) {
        mrk_android_lease_acl_write_expected e=f.expected;
        switch (which) {
        case 0:e.identity.mode=S_IFREG|0400;break;
        case 1:e.identity.owner=501;break;
        case 2:e.identity.group=80;break;
        case 3:e.identity.flags=1;break;
        case 4:e.links=2;break;
        case 5:e.bytes=59;break;
        case 6:e.modified_nanoseconds=INT64_C(1000000000);break;
        default:e.changed_nanoseconds=-1;break;
        }
        if (lease_write_shape(&e)) return 0;
    }
    return 31;
}


// Native UID→UUID→UID DATA for the already authenticated connecting account.
// Never called from an XPC callback; the original payload worker supplies uid.
int mrk_android_lease_principal(uint32_t uid, uint8_t *out) {
    if (!out || uid==0 || uid==UINT32_MAX || getuid()!=0 || geteuid()!=0) return 0;
    uuid_t original; id_t mapped=0; int kind=-1;
    int result=mbr_uid_to_uuid((uid_t)uid,original);
    if (result || !lease_principal_policy(original)) return 0;
    result=mbr_uuid_to_id(original,&mapped,&kind);
    if (result || kind!=ID_TYPE_UID || mapped!=(id_t)uid) return 0;
    memcpy(out,original,sizeof(uuid_t)); return 1;
}
