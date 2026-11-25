// Fixed setup executable static/dynamic signature only. No execution, network, copy or publication.
// The enclosing copier owns full ancestry/census and original absolute W/F/H.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

// This macro is generated ONLY by the isolated setup build from the existing
// reviewed Developer ID profile parser, including exact team/cert/issuer+leaf OIDs.
// A missing binding never builds a wildcard or an unavailable-signature fallback.
#ifndef MRK_XCODE_SETUP_REQUIREMENT
#error fixed reviewed setup Developer ID requirement is required
#endif
_Static_assert(sizeof(MRK_XCODE_SETUP_REQUIREMENT) > 1 && sizeof(MRK_XCODE_SETUP_REQUIREMENT) <= 2048,
    "bounded complete SOURCE requirement");
#define SELF_CELL_MAGIC UINT64_C(0x58434f444553454c)
#define SELF_CELL_BYTES 12288u
#define SELF_PATH_BYTES 4097u
#define SELF_REFS 10u
// states:0 absent,2 owned,3 release-entered/unknown,4 positively released.
typedef struct {
    uint32_t phase, unknown, verified;
    int32_t status;
    uint32_t states[SELF_REFS];
} self_report;
typedef struct {
    uint64_t magic;
    pid_t pid;
    pthread_t thread;
    int parent, bundle;
    struct stat parent_before, bundle_before;
    char path[SELF_PATH_BYTES], parent_path[SELF_PATH_BYTES], leaf[256];
    CFTypeRef values[SELF_REFS];
    self_report report;
} self_cell;
_Static_assert(sizeof(self_cell) <= SELF_CELL_BYTES, "bounded supplied SELF cell");
_Static_assert(_Alignof(self_cell) <= _Alignof(uint64_t), "Rust u64 storage alignment");
_Static_assert(sizeof(self_report) == 56u, "Rust/C report ABI");

static int owner(self_cell *cell) {
    return cell && cell->magic == SELF_CELL_MAGIC && cell->pid == getpid()
        && pthread_equal(cell->thread, pthread_self());
}
static int self_path(const char *path, size_t length) {
    const char suffix[]="/setup/mrk-macos-xcode-setup";
    if (!path || length<=sizeof(suffix)-1 || length>=SELF_PATH_BYTES || path[0]!='/'
        || memchr(path,0,length) || memcmp(path+length-(sizeof(suffix)-1),suffix,sizeof(suffix)-1)) return 0;
    size_t start=1; unsigned parts=0;
    for (size_t i=1; i<=length; ++i) {
        if (i!=length && path[i]!='/') {
            unsigned char c=(unsigned char)path[i];
            if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')
                || c=='.'||c=='_'||c=='-'||c=='+'||c==' ')) return 0;
            continue;
        }
        size_t n=i-start;
        if (!n || n>255 || (n==1&&path[start]=='.') || (n==2&&!memcmp(path+start,"..",2))) return 0;
        if (++parts>10) return 0;
        start=i+1;
    }
    return parts>=3;
}
// Ignore access time; validation itself may read directory metadata. Do not
// memcmp stat padding or claim this detects hostile mutate-and-swap-back.
static int same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode
        && a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink
        && a->st_size == b->st_size && a->st_flags == b->st_flags && a->st_gen == b->st_gen
        && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec
        && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec
        && a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec
        && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static int originals(self_cell *cell, int first) {
    struct stat parent, bundle, named_parent, named_bundle, relative;
    if (fstat(cell->parent, &parent) || fstat(cell->bundle, &bundle)
        || lstat(cell->parent_path, &named_parent) || lstat(cell->path, &named_bundle)
        || fstatat(cell->parent, cell->leaf, &relative, AT_SYMLINK_NOFOLLOW)
        || !S_ISDIR(parent.st_mode) || !S_ISREG(bundle.st_mode)
        || !same(&parent, &named_parent) || !same(&bundle, &named_bundle)
        || !same(&bundle, &relative)) return 0;
    if (first) { cell->parent_before=parent; cell->bundle_before=bundle; return 1; }
    return same(&parent, &cell->parent_before) && same(&bundle, &cell->bundle_before);
}
int mrk_xcode_self_begin(void *storage, size_t bytes,
    const uint8_t *path, size_t length, int parent, int bundle, self_report *out) {
    if (!storage || bytes != SELF_CELL_BYTES || !out || parent < 0 || bundle < 0
        || parent == bundle || !self_path((const char *)path, length)) return 0;
    self_cell *cell=storage;
    if (cell->magic) return -1; // a live/unknown original is never overwritten
    memset(cell, 0, sizeof(*cell)); cell->magic=SELF_CELL_MAGIC;
    cell->pid=getpid(); cell->thread=pthread_self();
    if (getuid()!=0 || geteuid()!=0) { *out=cell->report; return 0; }
    cell->parent=parent; cell->bundle=bundle;
    memcpy(cell->path, path, length);
    const char *slash=strrchr(cell->path, '/');
    size_t parent_length=(size_t)(slash-cell->path);
    memcpy(cell->parent_path, cell->path, parent_length);
    memcpy(cell->leaf, slash+1, length-parent_length);
    int result=originals(cell, 1); *out=cell->report;
    return result;
}
static int number(CFDictionaryRef info,CFStringRef key,uint32_t *out) {
    CFTypeRef value=CFDictionaryGetValue(info,key); int64_t n=0;
    if (!value || CFGetTypeID(value)!=CFNumberGetTypeID() || CFNumberIsFloatType((CFNumberRef)value)
        || !CFNumberGetValue((CFNumberRef)value,kCFNumberSInt64Type,&n) || n<0 || n>UINT32_MAX) return 0;
    *out=(uint32_t)n; return 1;
}
static int information(CFDictionaryRef info,int dynamic,const char *path) {
    if (!info || CFGetTypeID(info)!=CFDictionaryGetTypeID() || CFDictionaryGetCount(info)>128) return 0;
    uint32_t flags=0,status=0;
    if (!number(info,kSecCodeInfoFlags,&flags) || !(flags&kSecCodeSignatureRuntime)) return 0;
    CFTypeRef identifier=CFDictionaryGetValue(info,kSecCodeInfoIdentifier);
    if (!identifier || CFGetTypeID(identifier)!=CFStringGetTypeID()
        || !CFEqual(identifier,CFSTR("dev.mobile-release-kit.desktop.xcode-setup"))) return 0;
    CFTypeRef ent=CFDictionaryGetValue(info,kSecCodeInfoEntitlementsDict);
    CFTypeRef raw=CFDictionaryGetValue(info,kSecCodeInfoEntitlements);
    if (ent && (CFGetTypeID(ent)!=CFDictionaryGetTypeID() || CFDictionaryGetCount((CFDictionaryRef)ent)!=0)) return 0;
    if ((!ent&&raw) || (raw && (CFGetTypeID(raw)!=CFDataGetTypeID() || CFDataGetLength((CFDataRef)raw)>4096))) return 0;
    CFTypeRef executable=CFDictionaryGetValue(info,kSecCodeInfoMainExecutable);
    char actual[SELF_PATH_BYTES]={0};
    if (!executable || CFGetTypeID(executable)!=CFURLGetTypeID()
        || !CFURLGetFileSystemRepresentation((CFURLRef)executable,false,(UInt8 *)actual,sizeof(actual))
        || !memchr(actual,0,sizeof(actual)) || strcmp(actual,path)) return 0;
    return !dynamic || (number(info,kSecCodeInfoStatus,&status)
        && (status&kSecCodeStatusValid) && !(status&kSecCodeStatusDebugged));
}
static int same_code(CFDictionaryRef disk,CFDictionaryRef executing) {
    CFTypeRef left=CFDictionaryGetValue(disk,kSecCodeInfoUnique),right=CFDictionaryGetValue(executing,kSecCodeInfoUnique);
    // Whole current supported 20-byte unique CodeDirectory identity, not a
    // prefix comparison or substitute for static/dynamic validity/path custody.
    return left && right && CFGetTypeID(left)==CFDataGetTypeID() && CFGetTypeID(right)==CFDataGetTypeID()
        && CFDataGetLength((CFDataRef)left)==20 && CFDataGetLength((CFDataRef)right)==20 && CFEqual(left,right);
}
int mrk_xcode_self_step(void *storage, uint32_t phase, self_report *out) {
    self_cell *cell=storage;
    if (!owner(cell) || !out || cell->report.unknown || phase != cell->report.phase+1
        || phase < 1 || phase > 11) return -1;
    cell->report.phase=phase; int result=1; OSStatus status=errSecSuccess;
    @try {
        switch (phase) {
            case 1:
                cell->values[0]=CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
                    (const UInt8 *)cell->path,(CFIndex)strlen(cell->path),false);
                result=cell->values[0]!=NULL; break;
            case 2: {
                SecStaticCodeRef code=NULL;
                status=SecStaticCodeCreateWithPath((CFURLRef)cell->values[0],kSecCSDefaultFlags,&code);
                cell->values[1]=code; result=status==errSecSuccess&&code; break;
            }
            case 3:
                cell->values[2]=CFStringCreateWithCString(kCFAllocatorDefault,
                    MRK_XCODE_SETUP_REQUIREMENT,kCFStringEncodingASCII);
                result=cell->values[2]!=NULL; break;
            case 4: {
                SecRequirementRef requirement=NULL;
                status=SecRequirementCreateWithString((CFStringRef)cell->values[2],kSecCSDefaultFlags,&requirement);
                cell->values[3]=requirement; result=status==errSecSuccess&&requirement; break;
            }
            case 5: {
                CFErrorRef error=NULL;
                status=SecStaticCodeCheckValidityWithErrors((SecStaticCodeRef)cell->values[1],
                    kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode|kSecCSNoNetworkAccess,
                    (SecRequirementRef)cell->values[3],&error);
                cell->values[4]=error; result=status==errSecSuccess&&!error; break;
            }
            case 6:case 9: {
                CFDictionaryRef info=NULL; int dynamic=phase==9;
                status=SecCodeCopySigningInformation((SecStaticCodeRef)cell->values[dynamic?6:1],
                    kSecCSSigningInformation|(dynamic?kSecCSDynamicInformation:0),&info);
                cell->values[dynamic?8:5]=info;
                result=status==errSecSuccess && information(info,dynamic,cell->path);
                if (result&&dynamic) result=same_code((CFDictionaryRef)cell->values[5],info);
                break;
            }
            case 7: {
                SecCodeRef code=NULL; status=SecCodeCopySelf(kSecCSDefaultFlags,&code);
                cell->values[6]=code; result=status==errSecSuccess&&code; break;
            }
            case 8:case 10: {
                CFErrorRef error=NULL;
                status=SecCodeCheckValidityWithErrors((SecCodeRef)cell->values[6],kSecCSNoNetworkAccess,
                    (SecRequirementRef)cell->values[3],&error);
                cell->values[phase==8?7:9]=error; result=status==errSecSuccess&&!error;
                if (phase==10) cell->report.verified=(uint32_t)result;
                break;
            }
            case 11: result=originals(cell,0); break;
        }
    } @catch (...) { cell->report.unknown=1; result=-1; }
    for (unsigned i=0;i<SELF_REFS;++i) if (cell->values[i]&&cell->report.states[i]==0) cell->report.states[i]=2;
    if (phase==2 || phase==4 || (phase>=5&&phase<=10)) cell->report.status=status;
    *out=cell->report; return result;
}
int mrk_xcode_self_release(void *storage, uint32_t slot, self_report *out) {
    self_cell *cell=storage;
    if (!owner(cell) || !out || slot>=SELF_REFS || cell->report.states[slot]!=2 || !cell->values[slot]) return -1;
    // A throwing/nonreturning release cannot be retried. Other independent
    // known references remain eligible for their own original cleanup calls.
    cell->report.states[slot]=3;
    @try { CFRelease(cell->values[slot]); cell->values[slot]=NULL; cell->report.states[slot]=4; }
    @catch (...) { cell->report.unknown=1; *out=cell->report; return -1; }
    *out=cell->report; return 1;
}
int mrk_xcode_self_retire(void *storage) {
    self_cell *cell=storage;
    if (!owner(cell) || cell->report.unknown) return 0;
    for (unsigned i=0; i<SELF_REFS; ++i)
        if (cell->values[i] || (cell->report.states[i]!=0 && cell->report.states[i]!=4)) return 0;
    memset(cell, 0, sizeof(*cell)); return 1;
}
