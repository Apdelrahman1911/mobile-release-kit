// Synthetic fixed identity for the nonshipping E2 transport fixture.
// Actual Security/file originals, not a production profile or publisher claim.
#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "vault_helper_control.h"
#include "e2_native_fixture_fixed.h"
#include "e2_native_fixture_identity.h"

enum { ID_NONE=0,ID_ENTERED=1,ID_OWNED=2,ID_CLOSE_ENTERED=3,ID_SETTLED=4,ID_UNKNOWN=5 };
enum { ID_MAIN=1,ID_CLIENT=2,ID_RESIDENT=3,ID_CALL_LIMIT=131072 };
#define ID_MAGIC UINT64_C(0x4d524b4532494431)
#define ID_MAX_RAW ((UINT64_C(1)<<61)-1)
#define ID_FILE_MAX (UINT64_C(1024)*1024)
#define ID_IMAGE_MAX (UINT64_C(32)*1024*1024)
#define ID_TOTAL_MAX (UINT64_C(80)*1024*1024)
typedef struct { int parent;const char *name;uint32_t mode;uint64_t limit; } source_spec;
static const source_spec source_specs[MRK_E2_IDENTITY_FDS]={
    {-1,"/",0,0},{0,"Library",0,0},{1,"Application Support",0,0},
    {2,MRK_E2_FIXTURE_ROOT_LEAF,0755,0},{3,"MRK E2 Native Fixture.app",0755,0},
    {4,"Contents",0755,0},{5,"MacOS",0755,0},{5,"Helpers",0755,0},{5,"_CodeSignature",0755,0},
    {7,"MRK E2 Native Client.app",0755,0},{9,"Contents",0755,0},
    {10,"MacOS",0755,0},{10,"Helpers",0755,0},{10,"Frameworks",0755,0},
    {10,"Library",0755,0},{14,"LaunchDaemons",0755,0},{10,"_CodeSignature",0755,0},
    {3,"maintenance-gate-v1",0444,ID_FILE_MAX},{5,"Info.plist",0444,ID_FILE_MAX},
    {6,"mrk-e2-native-entry",0555,ID_IMAGE_MAX},{8,"CodeResources",0444,ID_FILE_MAX},
    {10,"Info.plist",0444,ID_FILE_MAX},{11,"mrk-e2-native-client",0555,ID_IMAGE_MAX},
    {12,"mrk-e2-native-resident",0555,ID_IMAGE_MAX},
    {13,"libmrk_e2_native_client.dylib",0555,ID_IMAGE_MAX},
    {13,"libmrk_e2_native_resident.dylib",0555,ID_IMAGE_MAX},
    {15,MRK_E2_FIXTURE_PLIST,0444,ID_FILE_MAX},{16,"CodeResources",0444,ID_FILE_MAX}
};
/* Existing empty-policy ACL ABI. It distinguishes absent FILESEC_ACL from
 * failed snapshots and Darwin's actual validated empty-list exhaustion. */
typedef struct { uint64_t device,inode;uint32_t mode,owner,group,flags; } acl_expected;
typedef struct {
    uint32_t version,phase,outcome,resource[3],entries,qualifiers,qualifiers_closed,first_phase;
    int32_t first_return,first_errno;
} acl_facts;
_Static_assert(sizeof(acl_expected)==32 && sizeof(acl_facts)==48,"existing ACL DATA ABI");
extern size_t mrk_vault_acl_frame_bytes(void);
extern void *mrk_vault_acl_frame_new(void);
extern int mrk_vault_acl_begin(void *,const acl_expected *,uint32_t);
extern int mrk_vault_acl_step(void *,int);
extern int mrk_vault_acl_facts_read(void *,acl_facts *);
extern int mrk_vault_acl_cleanup_step(void *);
extern int mrk_vault_acl_frame_retire(void *);
extern int mrk_no_xattrs(int);
typedef struct {
    int fd;struct stat original;fsid_t fsid;uint64_t mount_flags;uint8_t hash[CC_SHA256_DIGEST_LENGTH];
} source_original;
typedef struct {
    uint64_t magic;pid_t process;pthread_t thread;_Atomic uint32_t active;
    mrk_e2_fixture_identity_facts facts;
    source_original source[MRK_E2_IDENTITY_FDS];
    CFTypeRef values[MRK_E2_IDENTITY_CFS];
    void *acl;acl_facts acl_report;
    NSAutoreleasePool *pool;
    uint32_t prepared;uint64_t total;
    uint8_t hashes[2][20];char requirements[2][192];
    CC_SHA256_CTX hash_context;
    union { uint8_t bytes[8192];struct stat info;struct statfs filesystem; } scratch;
} identity_original;
/* All explicit C caller backing below is fixed. Framework-private heaps are
 * not these project bytes and are never represented as zero. */
typedef struct {
    struct stat named;acl_expected expected;uint8_t digest[32];uint8_t actual[20];
    CFTypeRef acquired;OSStatus status;uint64_t offset;size_t count;
    mrk_e2_fixture_identity_facts returned;mrk_e2_fixture_checkpoint_api callback;
    /* Main lookup adds only bounded local DATA and borrowed Foundation values. */
    struct stat lookup_stat;mrk_e2_fixture_bundle_lookup lookup_data;
    NSBundle *lookup_bundle;NSString *lookup_values[3];
} identity_local_bound;
_Static_assert(sizeof(identity_original)+1024u+sizeof(identity_local_bound)<=MRK_E2_IDENTITY_PROJECT_MAX,
    "complete fixed provider + ACL frame + supplied local/callback backing");
static uint64_t now_ns(void) { uint64_t n=0;return mrk_vault_uptime(&n)?n:0; }
static int api_valid(const mrk_e2_fixture_checkpoint_api *api) {
    return api && api->context && api->point;
}
static int role_allowed(uint32_t role,int preparing) {
    if (getuid()!=geteuid() || getgid()!=getegid()) return 0;
    if (role==ID_MAIN) return getuid()!=0 && pthread_main_np()==1;
    if (role==ID_CLIENT) return getuid()!=0 && pthread_main_np()==0;
    return role==ID_RESIDENT && getuid()==0 && (!preparing || pthread_main_np()==1);
}
static int valid(identity_original *p) {
    return p && p->magic==ID_MAGIC && p->process==getpid() && role_allowed(p->facts.role,0)
        && (p->facts.role==ID_RESIDENT || pthread_equal(p->thread,pthread_self()));
}
static void failed(mrk_e2_fixture_identity_facts *f,uint64_t at,uint32_t unknown) {
    f->failed=1;f->ready=0;
    if (!at || at>ID_MAX_RAW || unknown) f->unknown=1;
    if (at && at<=ID_MAX_RAW) {
        if (!f->first_ns || at<f->first_ns) f->first_ns=at;
        if (at>f->last_ns) f->last_ns=at;
    }
}
static int before_data(mrk_e2_fixture_identity_facts *f,const mrk_e2_fixture_checkpoint_api *api,
    uint32_t phase,uint32_t cleanup) {
    if (!api_valid(api) || cleanup>1 || f->in_call || f->calls>=ID_CALL_LIMIT
        || (!cleanup && (f->failed || f->unknown))) return 0;
    const uint64_t now=now_ns();
    const uint32_t gate=api->point(api->context,phase,0,cleanup,now,0);
    if (!now || now>ID_MAX_RAW || now<f->last_ns || gate!=1) {
        failed(f,now,gate>1 || !now || now>ID_MAX_RAW || now<f->last_ns);return 0;
    }
    f->last_ns=now;f->phase=phase;f->calls++;f->in_call=1;return 1;
}
static int returned_data(mrk_e2_fixture_identity_facts *f,const mrk_e2_fixture_checkpoint_api *api,
    uint32_t cleanup,uint32_t outcome) {
    const uint64_t now=now_ns();
    if (!f->in_call || f->returns>=f->calls) { failed(f,now,1);return 0; }
    f->in_call=0;f->returns++;
    if (!now || now>ID_MAX_RAW || now<f->last_ns) outcome=2;
    if (outcome) failed(f,now,outcome==2);
    if (now>=f->last_ns && now<=ID_MAX_RAW) f->last_ns=now;
    const uint32_t gate=api->point(api->context,f->phase,1,cleanup,now,outcome);
    if (gate!=1) failed(f,now,gate>1);
    return outcome==0 && gate==1;
}
static int before(identity_original *p,const mrk_e2_fixture_checkpoint_api *api,uint32_t phase,uint32_t cleanup) {
    return valid(p) && before_data(&p->facts,api,phase,cleanup);
}
static int returned(identity_original *p,const mrk_e2_fixture_checkpoint_api *api,uint32_t cleanup,uint32_t outcome) {
    return returned_data(&p->facts,api,cleanup,outcome);
}
static int acquire_active(identity_original *p,int preparing) {
    uint32_t idle=0;
    return valid(p) && (!preparing || (pthread_equal(p->thread,pthread_self()) && role_allowed(p->facts.role,1)))
        && atomic_compare_exchange_strong(&p->active,&idle,1);
}
static int finish(identity_original *p,mrk_e2_fixture_identity_facts *out,int result) {
    *out=p->facts;atomic_store(&p->active,0);return result;
}
size_t mrk_e2_fixture_identity_project_bytes(void) {
    return sizeof(identity_original)+1024u+sizeof(identity_local_bound);
}
static void *new_original(uint32_t role,const mrk_e2_fixture_checkpoint_api *api,mrk_e2_fixture_identity_facts *out) {
    if (!out) return NULL;
    memset(out,0,sizeof(*out));out->version=1;out->bytes=sizeof(*out);out->role=role;
    if (!api_valid(api) || !role_allowed(role,1)) return NULL;
    if (!before_data(out,api,MRK_E2_ID_ALLOCATE,0)) return NULL;
    out->allocation_entered=1;
    identity_original *p=calloc(1,sizeof(*p));
    out->allocation_returned=1;
    if (p) {
        out->allocated=1;p->magic=ID_MAGIC;p->process=getpid();p->thread=pthread_self();atomic_init(&p->active,0);
        for (unsigned i=0;i<MRK_E2_IDENTITY_FDS;i++) p->source[i].fd=-1;
        p->facts=*out;returned(p,api,0,0);*out=p->facts;
    } else returned_data(out,api,0,1);
    return p; // Acquired pointer is retained even if its returned gate refused.
}
void *mrk_e2_fixture_main_identity_new(const mrk_e2_fixture_checkpoint_api *api,mrk_e2_fixture_identity_facts *out) {
    return new_original(ID_MAIN,api,out);
}
void *mrk_e2_fixture_client_identity_new(const mrk_e2_fixture_checkpoint_api *api,mrk_e2_fixture_identity_facts *out) {
    return new_original(ID_CLIENT,api,out);
}
void *mrk_e2_fixture_resident_identity_new(const mrk_e2_fixture_checkpoint_api *api,mrk_e2_fixture_identity_facts *out) {
    return new_original(ID_RESIDENT,api,out);
}
static int same(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_mode==b->st_mode
        && a->st_uid==b->st_uid && a->st_gid==b->st_gid && a->st_nlink==b->st_nlink
        && a->st_size==b->st_size && a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec
        && a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec
        && a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec
        && a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec && a->st_flags==b->st_flags;
}
static int source_policy(unsigned i,const struct stat *s) {
    const source_spec *spec=&source_specs[i];
    if (s->st_uid!=0 || s->st_dev<0 || !s->st_ino || !s->st_nlink || s->st_size<0) return 0;
    if (!spec->limit && !S_ISDIR(s->st_mode)) return 0;
    if (i<3) return !(s->st_mode&07022);
    if (s->st_gid!=0 || s->st_flags!=0 || (s->st_mode&07777)!=spec->mode) return 0;
    return !spec->limit || (S_ISREG(s->st_mode) && s->st_nlink==1 && s->st_size>0
        && (uint64_t)s->st_size<=spec->limit);
}
static int filesystem_policy(const struct statfs *s) {
    return !strcmp(s->f_fstypename,"apfs") && (s->f_flags&MNT_LOCAL)
        && !(s->f_flags&(MNT_UNION|MNT_AUTOMOUNTED|MNT_IGNORE_OWNERSHIP));
}
static int named(identity_original *p,unsigned i,struct stat *out) {
    return i==0?lstat("/",out):fstatat(p->source[source_specs[i].parent].fd,source_specs[i].name,out,AT_SYMLINK_NOFOLLOW);
}
static int source_check(identity_original *p,unsigned i,const mrk_e2_fixture_checkpoint_api *api,uint32_t cleanup) {
    if (p->facts.fds[i]!=ID_OWNED || p->source[i].fd<0) return 0;
    if (!before(p,api,MRK_E2_ID_SOURCE_CHECK,cleanup)) return 0;
    int rc=fstat(p->source[i].fd,&p->scratch.info);
    int ok=rc==0 && source_policy(i,&p->scratch.info) && same(&p->source[i].original,&p->scratch.info);
    if (!returned(p,api,cleanup,ok?0:1)) return 0;
    if (!before(p,api,MRK_E2_ID_SOURCE_CHECK,cleanup)) return 0;
    rc=named(p,i,&p->scratch.info);
    ok=rc==0 && same(&p->source[i].original,&p->scratch.info);
    if (!returned(p,api,cleanup,ok?0:1)) return 0;
    if (!before(p,api,MRK_E2_ID_SOURCE_CHECK,cleanup)) return 0;
    rc=fstatfs(p->source[i].fd,&p->scratch.filesystem);
    ok=rc==0 && filesystem_policy(&p->scratch.filesystem)
        && p->source[i].mount_flags==p->scratch.filesystem.f_flags
        && !memcmp(&p->source[i].fsid,&p->scratch.filesystem.f_fsid,sizeof(fsid_t));
    return returned(p,api,cleanup,ok?0:1);
}
static int acl_read(identity_original *p) {
    acl_facts next={0};
    if (!p->acl || mrk_vault_acl_facts_read(p->acl,&next)!=1 || next.version!=1
        || next.phase>23 || next.outcome>4 || next.entries>128 || next.qualifiers_closed>next.qualifiers
        || next.resource[0]>ID_UNKNOWN || next.resource[1]>ID_UNKNOWN || next.resource[2]>ID_UNKNOWN) {
        failed(&p->facts,now_ns(),1);return 0;
    }
    p->acl_report=next;
    for (unsigned i=0;i<3;i++) p->facts.acl_resources[i]=next.resource[i];
    return 1;
}
static int acl_cleanup(identity_original *p,const mrk_e2_fixture_checkpoint_api *api) {
    if (!p->acl) return p->facts.acl_frame==ID_NONE;
    if (!acl_read(p)) return 0;
    for (unsigned count=0;count<3;count++) {
        int owned=0;for (unsigned i=0;i<3;i++) owned|=p->facts.acl_resources[i]==ID_OWNED;
        if (!owned) break;
        if (!before(p,api,MRK_E2_ID_ACL_RELEASE,1)) return 0;
        int rc=mrk_vault_acl_cleanup_step(p->acl);
        int known=acl_read(p);
        int no_unknown=1;for (unsigned i=0;i<3;i++) no_unknown&=p->facts.acl_resources[i]!=ID_UNKNOWN;
        if (!returned(p,api,1,known && rc==1 && no_unknown?0:2)) {
            /* Independent positively-owned ACL resources can still settle. */
            if (!known) return 0;
        }
    }
    for (unsigned i=0;i<3;i++) if (p->facts.acl_resources[i]!=ID_NONE && p->facts.acl_resources[i]!=ID_SETTLED) return 0;
    return 1;
}
static int acl_check(identity_original *p,unsigned index,const mrk_e2_fixture_checkpoint_api *api) {
    const struct stat *s=&p->source[index].original;
    acl_expected expected={(uint64_t)s->st_dev,(uint64_t)s->st_ino,(uint32_t)s->st_mode,s->st_uid,s->st_gid,s->st_flags};
    if (p->facts.acl_generation>=MRK_E2_IDENTITY_FDS || !before(p,api,MRK_E2_ID_ACL,0)) return 0;
    const int begun=mrk_vault_acl_begin(p->acl,&expected,1);
    if (begun==1) p->facts.acl_generation++;
    if (!returned(p,api,0,begun==1?0:1)) return 0;
    for (unsigned step=0;step<16;step++) {
        if (!acl_read(p)) return 0;
        if (p->acl_report.outcome!=0) break;
        if (!before(p,api,MRK_E2_ID_ACL,0)) return 0;
        int rc=mrk_vault_acl_step(p->acl,p->source[index].fd);
        int known=acl_read(p);
        uint32_t result=!known || rc!=1?2:p->acl_report.outcome>1?1:0;
        if (!returned(p,api,0,result)) return 0;
    }
    if (p->acl_report.outcome!=1) { failed(&p->facts,now_ns(),1);return 0; }
    return acl_cleanup(p,api);
}
static int read_hash(identity_original *p,unsigned i,const mrk_e2_fixture_checkpoint_api *api,int compare) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];uint64_t offset=0;
    if (!before(p,api,MRK_E2_ID_SOURCE_READ,0)) return 0;
    int digest_ok=CC_SHA256_Init(&p->hash_context)==1;
    if (!returned(p,api,0,digest_ok?0:2)) return 0;
    const uint64_t size=(uint64_t)p->source[i].original.st_size;
    while (offset<size) {
        size_t count=(size-offset)<sizeof(p->scratch.bytes)?(size_t)(size-offset):sizeof(p->scratch.bytes);
        if (!before(p,api,MRK_E2_ID_SOURCE_READ,0)) return 0;
        ssize_t got=pread(p->source[i].fd,p->scratch.bytes,count,(off_t)offset);
        if (!returned(p,api,0,got>0 && (size_t)got<=count?0:1)) return 0;
        if (!before(p,api,MRK_E2_ID_SOURCE_READ,0)) return 0;
        digest_ok=CC_SHA256_Update(&p->hash_context,p->scratch.bytes,(CC_LONG)got)==1;
        if (!returned(p,api,0,digest_ok?0:2)) return 0;
        offset+=(uint64_t)got;
    }
    if (!before(p,api,MRK_E2_ID_SOURCE_READ,0)) return 0;
    const ssize_t eof=pread(p->source[i].fd,p->scratch.bytes,1,(off_t)size);
    if (!returned(p,api,0,eof==0?0:1) || !before(p,api,MRK_E2_ID_SOURCE_READ,0)) return 0;
    digest_ok=CC_SHA256_Final(digest,&p->hash_context)==1;
    if (!returned(p,api,0,!digest_ok?2:compare && memcmp(digest,p->source[i].hash,sizeof(digest))?1:0)) return 0;
    if (!compare) memcpy(p->source[i].hash,digest,sizeof(digest));
    return source_check(p,i,api,0);
}
static int open_source(identity_original *p,unsigned i,const mrk_e2_fixture_checkpoint_api *api) {
    struct stat prior;
    if (!before(p,api,MRK_E2_ID_SOURCE_CHECK,0)) return 0;
    int rc=named(p,i,&prior);
    if (!returned(p,api,0,rc==0 && source_policy(i,&prior)?0:1)) return 0;
    if (!before(p,api,MRK_E2_ID_SOURCE_OPEN,0)) return 0;
    p->facts.fds[i]=ID_ENTERED;
    int flags=O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK;
    if (!source_specs[i].limit) flags|=O_DIRECTORY;
    p->source[i].fd=i==0?open("/",flags):openat(p->source[source_specs[i].parent].fd,source_specs[i].name,flags);
    p->facts.fds[i]=p->source[i].fd>=0?ID_OWNED:ID_SETTLED;
    if (!returned(p,api,0,p->source[i].fd>=0?0:1)) return 0;
    if (!before(p,api,MRK_E2_ID_SOURCE_CHECK,0)) return 0;
    rc=fstat(p->source[i].fd,&p->scratch.info);
    int ok=rc==0 && source_policy(i,&p->scratch.info) && same(&prior,&p->scratch.info);
    if (ok) p->source[i].original=p->scratch.info;
    if (!returned(p,api,0,ok?0:1)) return 0;
    if (!before(p,api,MRK_E2_ID_SOURCE_CHECK,0)) return 0;
    rc=fstatfs(p->source[i].fd,&p->scratch.filesystem);
    ok=rc==0 && filesystem_policy(&p->scratch.filesystem);
    if (ok) { p->source[i].mount_flags=p->scratch.filesystem.f_flags;p->source[i].fsid=p->scratch.filesystem.f_fsid; }
    if (!returned(p,api,0,ok?0:1) || !acl_check(p,i,api)) return 0;
    if (i>=3) {
        if (!before(p,api,MRK_E2_ID_SOURCE_CHECK,0)) return 0;
        rc=mrk_no_xattrs(p->source[i].fd);
        if (!returned(p,api,0,rc==0?0:1)) return 0;
    }
    if (!source_check(p,i,api,0)) return 0;
    if (!source_specs[i].limit) return 1;
    if (!before(p,api,MRK_E2_ID_SOURCE_CHECK,0)) return 0;
    const int capacity=p->total<=ID_TOTAL_MAX && (uint64_t)prior.st_size<=ID_TOTAL_MAX-p->total;
    if (capacity) p->total+=(uint64_t)prior.st_size;
    if (!returned(p,api,0,capacity?0:1)) return 0;
    return read_hash(p,i,api,0);
}
static int number(CFDictionaryRef info,CFStringRef key,uint32_t *out) {
    CFTypeRef value=CFDictionaryGetValue(info,key);int64_t n=0;
    if (!value || CFGetTypeID(value)!=CFNumberGetTypeID() || CFNumberIsFloatType((CFNumberRef)value)
        || !CFNumberGetValue((CFNumberRef)value,kCFNumberSInt64Type,&n) || n<0 || n>UINT32_MAX) return 0;
    *out=(uint32_t)n;return 1;
}
static int signing_info(CFDictionaryRef info,unsigned role,int dynamic,uint8_t hash[20]) {
    if (!info || CFGetTypeID(info)!=CFDictionaryGetTypeID() || CFDictionaryGetCount(info)>128) return 0;
    CFStringRef identifier=role==0?CFSTR(MRK_E2_FIXTURE_CLIENT_ID):CFSTR(MRK_E2_FIXTURE_RESIDENT_ID);
    CFTypeRef actual=CFDictionaryGetValue(info,kSecCodeInfoIdentifier);
    uint32_t flags=0,status=0;
    if (!actual || CFGetTypeID(actual)!=CFStringGetTypeID() || !CFEqual(actual,identifier)
        || !number(info,kSecCodeInfoFlags,&flags)
        || (flags&(kSecCodeSignatureAdhoc|kSecCodeSignatureRuntime))!=(kSecCodeSignatureAdhoc|kSecCodeSignatureRuntime)) return 0;
    CFTypeRef ent=CFDictionaryGetValue(info,kSecCodeInfoEntitlementsDict);
    CFTypeRef raw=CFDictionaryGetValue(info,kSecCodeInfoEntitlements);
    if (ent && (CFGetTypeID(ent)!=CFDictionaryGetTypeID() || CFDictionaryGetCount((CFDictionaryRef)ent)!=0)) return 0;
    if ((!ent && raw) || (raw && (CFGetTypeID(raw)!=CFDataGetTypeID() || CFDataGetLength((CFDataRef)raw)>4096))) return 0;
    CFTypeRef unique=CFDictionaryGetValue(info,kSecCodeInfoUnique);
    if (!unique || CFGetTypeID(unique)!=CFDataGetTypeID() || CFDataGetLength((CFDataRef)unique)!=20) return 0;
    if (dynamic && (!number(info,kSecCodeInfoStatus,&status) || !(status&kSecCodeStatusValid)
        || (status&kSecCodeStatusDebugged))) return 0;
    CFDataGetBytes((CFDataRef)unique,CFRangeMake(0,20),hash);return 1;
}
static const SecCSFlags check_flags=kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode|kSecCSNoNetworkAccess;
/* Separate actual acquisition/returned custody from the success decision. */
#define ID_CF_ACQUIRE(slot,expression) do { \
    if (!before(p,api,MRK_E2_ID_SECURITY,0)) return 0; \
    p->facts.cf[(slot)]=ID_ENTERED;CFTypeRef value=NULL;OSStatus status=errSecSuccess;uint32_t outcome=0; \
    @try { expression;p->values[(slot)]=value;p->facts.cf[(slot)]=value?ID_OWNED:ID_SETTLED; \
        if (!value || status!=errSecSuccess) outcome=1; } \
    @catch (...) { p->facts.cf[(slot)]=ID_UNKNOWN;outcome=2; } \
    if (!returned(p,api,0,outcome)) return 0; \
} while (0)
#define ID_SECURITY_CHECK(expression) do { \
    if (!before(p,api,MRK_E2_ID_SECURITY,0)) return 0;uint32_t outcome=0; \
    @try { if (!(expression)) outcome=1; } @catch (...) { outcome=2; } \
    if (!returned(p,api,0,outcome)) return 0; \
} while (0)
static int static_identity(identity_original *p,unsigned role,const mrk_e2_fixture_checkpoint_api *api) {
    const unsigned base=role*5;
    const char *path=role==0?MRK_E2_FIXTURE_CLIENT_APP:MRK_E2_FIXTURE_RESIDENT;
    const char *identifier=role==0?MRK_E2_FIXTURE_CLIENT_ID:MRK_E2_FIXTURE_RESIDENT_ID;
    ID_CF_ACQUIRE(base,value=CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,(const UInt8 *)path,(CFIndex)strlen(path),role==0));
    ID_CF_ACQUIRE(base+1,SecStaticCodeRef code=NULL;status=SecStaticCodeCreateWithPath((CFURLRef)p->values[base],kSecCSDefaultFlags,&code);value=code);
    ID_SECURITY_CHECK(SecStaticCodeCheckValidity((SecStaticCodeRef)p->values[base+1],check_flags,NULL)==errSecSuccess);
    ID_CF_ACQUIRE(base+2,CFDictionaryRef info=NULL;status=SecCodeCopySigningInformation((SecStaticCodeRef)p->values[base+1],kSecCSSigningInformation,&info);value=info);
    ID_SECURITY_CHECK(signing_info((CFDictionaryRef)p->values[base+2],role,0,p->hashes[role]));
    char hex[41];static const char digits[]="0123456789abcdef";
    for (unsigned i=0;i<20;i++) { hex[2*i]=digits[p->hashes[role][i]>>4];hex[2*i+1]=digits[p->hashes[role][i]&15]; }hex[40]=0;
    if (!before(p,api,MRK_E2_ID_SECURITY,0)) return 0;
    int length=snprintf(p->requirements[role],sizeof(p->requirements[role]),"identifier \"%s\" and cdhash H\"%s\"",identifier,hex);
    if (!returned(p,api,0,length>0 && (size_t)length<sizeof(p->requirements[role])?0:2)) return 0;
    ID_CF_ACQUIRE(base+3,value=CFStringCreateWithBytes(kCFAllocatorDefault,(const UInt8 *)p->requirements[role],length,kCFStringEncodingASCII,false));
    ID_CF_ACQUIRE(base+4,SecRequirementRef requirement=NULL;status=SecRequirementCreateWithString((CFStringRef)p->values[base+3],kSecCSDefaultFlags,&requirement);value=requirement);
    ID_SECURITY_CHECK(SecStaticCodeCheckValidity((SecStaticCodeRef)p->values[base+1],check_flags,(SecRequirementRef)p->values[base+4])==errSecSuccess);
    return 1;
}
static int dynamic_identity(identity_original *p,const mrk_e2_fixture_checkpoint_api *api) {
    const unsigned role=p->facts.role==ID_RESIDENT?1:0;uint8_t actual[20];
    ID_CF_ACQUIRE(10,SecCodeRef code=NULL;status=SecCodeCopySelf(kSecCSDefaultFlags,&code);value=code);
    ID_SECURITY_CHECK(SecCodeCheckValidity((SecCodeRef)p->values[10],kSecCSNoNetworkAccess,(SecRequirementRef)p->values[role*5+4])==errSecSuccess);
    ID_CF_ACQUIRE(11,CFDictionaryRef info=NULL;status=SecCodeCopySigningInformation((SecStaticCodeRef)p->values[10],kSecCSSigningInformation|kSecCSDynamicInformation,&info);value=info);
    ID_SECURITY_CHECK(signing_info((CFDictionaryRef)p->values[11],role,1,actual) && !memcmp(actual,p->hashes[role],sizeof(actual)));
    return 1;
}
static int prepare_body(identity_original *p,const mrk_e2_fixture_checkpoint_api *api) {
    if (p->facts.role==ID_MAIN) {
        if (!before(p,api,MRK_E2_ID_POOL_ALLOCATE,0)) return 0;
        p->facts.pool=1;uint32_t outcome=0;
        @try { p->pool=[NSAutoreleasePool alloc];p->facts.pool=p->pool?2:6;if (!p->pool) outcome=1; }
        @catch (...) { p->facts.pool=7;outcome=2; }
        if (!returned(p,api,0,outcome)) return 0;
        if (!before(p,api,MRK_E2_ID_POOL_INIT,0)) return 0;
        p->facts.pool=3;outcome=0;
        @try { p->pool=[p->pool init];p->facts.pool=p->pool?4:7;if (!p->pool) outcome=2; }
        @catch (...) { p->facts.pool=7;outcome=2; }
        if (!returned(p,api,0,outcome)) return 0;
    }
    if (!before(p,api,MRK_E2_ID_ACL,0)) return 0;
    const size_t acl_bytes=mrk_vault_acl_frame_bytes();
    if (!returned(p,api,0,acl_bytes>0 && acl_bytes<=1024u?0:1)
        || !before(p,api,MRK_E2_ID_ACL,0)) return 0;
    p->facts.acl_frame=ID_ENTERED;p->acl=mrk_vault_acl_frame_new();
    p->facts.acl_frame=p->acl?ID_OWNED:ID_SETTLED;
    if (!returned(p,api,0,p->acl?0:1)) return 0;
    for (unsigned i=0;i<MRK_E2_IDENTITY_FDS;i++) if (!open_source(p,i,api)) return 0;
    for (unsigned i=0;i<MRK_E2_IDENTITY_FDS;i++) if (!source_check(p,i,api,0)) return 0;
    if (!static_identity(p,0,api) || !static_identity(p,1,api) || !dynamic_identity(p,api)) return 0;
    for (unsigned i=0;i<MRK_E2_IDENTITY_FDS;i++) {
        if (source_specs[i].limit && !read_hash(p,i,api,1)) return 0;
        if (!source_check(p,i,api,0)) return 0;
    }
    const unsigned role=p->facts.role==ID_RESIDENT?1:0;
    ID_SECURITY_CHECK(SecCodeCheckValidity((SecCodeRef)p->values[10],kSecCSNoNetworkAccess,(SecRequirementRef)p->values[role*5+4])==errSecSuccess);
    for (unsigned i=0;i<MRK_E2_IDENTITY_FDS;i++) if (!source_check(p,i,api,0)) return 0;
    /* Preparation validates identity but mints no manager-action epoch. */
    p->facts.recheck_epoch=0;p->facts.ready=1;return 1;
}
int mrk_e2_fixture_identity_prepare(void *raw,const mrk_e2_fixture_checkpoint_api *api,mrk_e2_fixture_identity_facts *out) {
    identity_original *p=raw;
    if (!out || !api_valid(api) || !acquire_active(p,1)) return 0;
    if (p->prepared || p->facts.failed || p->facts.unknown) return finish(p,out,0);
    p->prepared=1;return finish(p,out,prepare_body(p,api));
}
int mrk_e2_fixture_identity_recheck(void *raw,uint32_t cleanup,const mrk_e2_fixture_checkpoint_api *api,mrk_e2_fixture_identity_facts *out) {
    identity_original *p=raw;
    if (!out || cleanup>1 || !api_valid(api) || !acquire_active(p,0)) return 0;
    if (!p->facts.ready || p->facts.failed || p->facts.unknown || p->facts.borrow_count
        || p->facts.recheck_epoch==UINT32_MAX) return finish(p,out,0);
    int ok=1;for (unsigned i=0;i<MRK_E2_IDENTITY_FDS && ok;i++) ok=source_check(p,i,api,cleanup);
    if (ok) p->facts.recheck_epoch++;
    return finish(p,out,ok);
}
int mrk_e2_fixture_identity_facts_read(void *raw,mrk_e2_fixture_identity_facts *out) {
    identity_original *p=raw;
    if (!out || !valid(p) || atomic_load(&p->active) || p->facts.in_call) return 0;
    *out=p->facts;return 1;
}
static CFStringRef requirement(identity_original *p,unsigned role) {
    if (!valid(p) || atomic_load(&p->active) || p->facts.in_call || !p->facts.ready
        || p->facts.failed || p->facts.unknown || p->facts.cf[role*5+3]!=ID_OWNED) return NULL;
    return (CFStringRef)p->values[role*5+3];
}
CFStringRef mrk_e2_fixture_client_requirement(void *raw) { return requirement(raw,0); }
CFStringRef mrk_e2_fixture_resident_requirement(void *raw) { return requirement(raw,1); }
/* Pure DATA predicate, shared with the fixture regression. It neither
 * acquires a borrow nor validates preparation/custody by itself. */
int mrk_e2_fixture_main_epoch_admits(uint32_t rechecked,uint32_t spent) {
    return rechecked>spent;
}
int mrk_e2_fixture_main_borrow(void *raw) {
    identity_original *p=raw;
    if (!valid(p) || p->facts.role!=ID_MAIN || atomic_load(&p->active) || p->facts.in_call
        || !p->facts.ready || p->facts.failed || p->facts.unknown || p->facts.pool!=4
        || p->facts.borrow_count || !mrk_e2_fixture_main_epoch_admits(p->facts.recheck_epoch,p->facts.spent_epoch)) return 0;
    p->facts.spent_epoch=p->facts.recheck_epoch;p->facts.borrow_count=1;return 1;
}
int mrk_e2_fixture_main_borrow_return(void *raw) {
    identity_original *p=raw;
    if (!valid(p) || p->facts.role!=ID_MAIN || atomic_load(&p->active) || p->facts.in_call
        || p->facts.borrow_count!=1) {
        if (valid(p)) failed(&p->facts,now_ns(),1);return 0;
    }
    p->facts.borrow_count=0;return 1;
}
/* These getters may use the already-owned pool. No +1 reference, FD, path
 * selection or service operation escapes; the caller catches exceptions into
 * its ORIGINAL unknown-custody path after the actual service status return. */
static uint32_t fixture_lookup_string(NSString *value,NSString *client,NSString *outer) {
    if (!value) return 4;
    if (![value isKindOfClass:[NSString class]] || [value length]>4096u) return 3;
    if ([value isEqualToString:client]) return 1;
    if ([value isEqualToString:outer]) return 2;
    return 3;
}
/* Only the existing fixed parent chain. 1=original matches,0=mismatch,-1=a
 * returned lookup failure. No new descriptor, adoption, symlink traversal or
 * interpretation of a failed syscall as absence. This is not source authority. */
static int fixture_lookup_original(identity_original *p,unsigned selected) {
    struct stat observed;
    for (unsigned count=0;count<MRK_E2_IDENTITY_FDS;count++) {
        if (selected>=MRK_E2_IDENTITY_FDS || p->facts.fds[selected]!=ID_OWNED
            || p->source[selected].fd<0) return 0;
        const int parent=source_specs[selected].parent;
        if (parent>=0 && ((unsigned)parent>=MRK_E2_IDENTITY_FDS
            || p->facts.fds[parent]!=ID_OWNED || p->source[parent].fd<0)) return 0;
        if (fstat(p->source[selected].fd,&observed)) return -1;
        if (!source_policy(selected,&observed) || !same(&p->source[selected].original,&observed)) return 0;
        if (named(p,selected,&observed)) return -1;
        if (!same(&p->source[selected].original,&observed)) return 0;
        if (fstat(p->source[selected].fd,&observed)) return -1;
        if (!same(&p->source[selected].original,&observed)) return 0;
        if (parent<0) return 1;
        selected=(unsigned)parent;
    }
    return 0;
}
int mrk_e2_fixture_main_bundle_lookup(void *raw,mrk_e2_fixture_bundle_lookup *out) {
    identity_original *p=raw;
    if (!out || !valid(p) || p->facts.role!=ID_MAIN || atomic_load(&p->active)
        || p->facts.in_call || !p->facts.ready || p->facts.failed || p->facts.unknown
        || p->facts.pool!=4 || !p->pool || p->facts.borrow_count!=1) return 0;
    NSBundle *bundle=[NSBundle mainBundle];
    mrk_e2_fixture_bundle_lookup next={0};
    next.bundle=fixture_lookup_string([bundle bundlePath],@MRK_E2_FIXTURE_CLIENT_APP,@MRK_E2_FIXTURE_APP);
    next.executable=fixture_lookup_string([bundle executablePath],@MRK_E2_FIXTURE_CLIENT,@MRK_E2_FIXTURE_ENTRY);
    next.identifier=fixture_lookup_string([bundle bundleIdentifier],@MRK_E2_FIXTURE_CLIENT_ID,@MRK_E2_FIXTURE_APP_ID);
    if (next.bundle==1) {
        const int original=fixture_lookup_original(p,26);
        next.plist=original==1?1:original==0?2:6;
    } else if (next.bundle==2) {
        next.plist=6;
        if (fixture_lookup_original(p,5)==1) {
            const int rc=fstatat(p->source[5].fd,"Library",&p->scratch.info,AT_SYMLINK_NOFOLLOW);
            const int returned_errno=rc<0?errno:0;
            const int post=fixture_lookup_original(p,5);
            if (post==1) next.plist=rc==0?4:returned_errno==ENOENT?3:6;
        }
    } else next.plist=next.bundle==3?5:6;
    *out=next;return 1;
}
int mrk_e2_fixture_identity_close(void **original,const mrk_e2_fixture_checkpoint_api *api,mrk_e2_fixture_identity_facts *out) {
    if (!original || !out || !api_valid(api)) return 0;
    identity_original *p=*original;
    if (!acquire_active(p,1)) return 0;
    if (p->facts.borrow_count || p->facts.in_call) return finish(p,out,0);
    p->facts.ready=0;
    for (unsigned i=MRK_E2_IDENTITY_CFS;i>0;i--) {
        const unsigned index=i-1;
        if (p->facts.cf[index]!=ID_OWNED) continue;
        if (!before(p,api,MRK_E2_ID_CF_RELEASE,1)) continue;
        p->facts.cf[index]=ID_CLOSE_ENTERED;uint32_t outcome=0;
        @try { CFRelease(p->values[index]);p->values[index]=NULL;p->facts.cf[index]=ID_SETTLED; }
        @catch (...) { p->facts.cf[index]=ID_UNKNOWN;outcome=2; }
        returned(p,api,1,outcome);
    }
    if (p->acl && acl_cleanup(p,api) && before(p,api,MRK_E2_ID_ACL_RELEASE,1)) {
        p->facts.acl_frame=ID_CLOSE_ENTERED;
        int rc=mrk_vault_acl_frame_retire(p->acl);
        if (rc==1) { p->acl=NULL;p->facts.acl_frame=ID_SETTLED; }
        else p->facts.acl_frame=ID_UNKNOWN;
        returned(p,api,1,rc==1?0:2);
    }
    for (unsigned i=MRK_E2_IDENTITY_FDS;i>0;i--) {
        const unsigned index=i-1;
        if (p->facts.fds[index]!=ID_OWNED) continue;
        if (!before(p,api,MRK_E2_ID_SOURCE_CLOSE,1)) continue;
        p->facts.fds[index]=ID_CLOSE_ENTERED;const int fd=p->source[index].fd;p->source[index].fd=-1;
        const int rc=close(fd);
        p->facts.fds[index]=rc==0?ID_SETTLED:ID_UNKNOWN;
        returned(p,api,1,rc==0?0:2); // no EINTR retry, probe or replacement FD
    }
    int slots_known=1;
    for (unsigned i=0;i<MRK_E2_IDENTITY_FDS;i++) slots_known&=p->facts.fds[i]==ID_NONE || p->facts.fds[i]==ID_SETTLED;
    for (unsigned i=0;i<MRK_E2_IDENTITY_CFS;i++) slots_known&=p->facts.cf[i]==ID_NONE || p->facts.cf[i]==ID_SETTLED;
    slots_known&=!p->acl && (p->facts.acl_frame==ID_NONE || p->facts.acl_frame==ID_SETTLED);
    if (slots_known && p->facts.pool==4 && before(p,api,MRK_E2_ID_POOL_DRAIN,1)) {
        p->facts.pool=5;uint32_t outcome=0;
        @try { [p->pool drain];p->pool=nil;p->facts.pool=6; }
        @catch (...) { p->facts.pool=7;outcome=2; }
        returned(p,api,1,outcome);
    }
    /* An alloc-only or partial-init autorelease pool is retained. No undocumented
     * release/drain of an uninitialized pool is used to manufacture finality. */
    if (!slots_known || p->pool || (p->facts.pool!=0 && p->facts.pool!=6) || p->facts.unknown
        || p->facts.in_call || p->facts.calls!=p->facts.returns || !before(p,api,MRK_E2_ID_RETIRE,1))
        return finish(p,out,0);
    *out=p->facts;p->magic=0;*original=NULL;free(p);
    out->consumed=1;
    return returned_data(out,api,1,0); // caller-owned DATA only after consumption
}
#undef ID_CF_ACQUIRE
#undef ID_SECURITY_CHECK
