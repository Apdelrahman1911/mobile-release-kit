// Fixed Xcode static signature only. No execution, network, copy or publication.
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

#define APPLE_CELL_MAGIC UINT64_C(0x58434f4445415050)
#define APPLE_CELL_BYTES 4096u
#define APPLE_PATH_BYTES 320u
#define APPLE_REFS 5u
// states:0 absent,2 owned,3 release-entered/unknown,4 positively released.
typedef struct {
    uint32_t phase, unknown, verified;
    int32_t status;
    uint32_t states[APPLE_REFS];
} apple_report;
typedef struct {
    uint64_t magic;
    pid_t pid;
    pthread_t thread;
    int parent, bundle;
    uint32_t role;
    struct stat parent_before, bundle_before;
    char path[APPLE_PATH_BYTES], parent_path[APPLE_PATH_BYTES], leaf[256];
    CFTypeRef values[APPLE_REFS];
    apple_report report;
} apple_cell;
_Static_assert(sizeof(apple_cell) <= APPLE_CELL_BYTES, "bounded supplied Apple cell");
_Static_assert(_Alignof(apple_cell) <= _Alignof(uint64_t), "Rust u64 storage alignment");
_Static_assert(sizeof(apple_report) == 36u, "Rust/C report ABI");

static int owner(apple_cell *cell) {
    return cell && cell->magic == APPLE_CELL_MAGIC && cell->pid == getpid()
        && pthread_equal(cell->thread, pthread_self());
}
static int ascii_name(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '+' || c == '-';
}
static int role_path(uint32_t role, const char *path, size_t length) {
    if (!path || !length || length >= APPLE_PATH_BYTES || memchr(path, 0, length)) return 0;
    if (role == 1) {
        const char prefix[] = "/Applications/";
        size_t prefix_size = sizeof(prefix)-1;
        if (length < prefix_size + 9 || memcmp(path, prefix, prefix_size)) return 0;
        const char *name = path + prefix_size; size_t n = length - prefix_size;
        if (n > 255 || memcmp(name, "Xcode", 5) || memcmp(name+n-4, ".app", 4)) return 0;
        for (size_t i=0; i<n; ++i) if (!ascii_name((unsigned char)name[i])) return 0;
        return 1;
    }
    const char *fixed = role == 2 ? "/Library/MobileReleaseKitDeveloper/.pending/Xcode.app"
        : role == 3 ? "/Library/MobileReleaseKitDeveloper/Xcode.app" : NULL;
    return fixed && strlen(fixed) == length && !memcmp(path, fixed, length);
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
static int originals(apple_cell *cell, int first) {
    struct stat parent, bundle, named_parent, named_bundle, relative;
    if (fstat(cell->parent, &parent) || fstat(cell->bundle, &bundle)
        || lstat(cell->parent_path, &named_parent) || lstat(cell->path, &named_bundle)
        || fstatat(cell->parent, cell->leaf, &relative, AT_SYMLINK_NOFOLLOW)
        || !S_ISDIR(parent.st_mode) || !S_ISDIR(bundle.st_mode)
        || !same(&parent, &named_parent) || !same(&bundle, &named_bundle)
        || !same(&bundle, &relative)) return 0;
    if (first) { cell->parent_before=parent; cell->bundle_before=bundle; return 1; }
    return same(&parent, &cell->parent_before) && same(&bundle, &cell->bundle_before);
}
int mrk_xcode_apple_begin(void *storage, size_t bytes, uint32_t role,
    const uint8_t *path, size_t length, int parent, int bundle, apple_report *out) {
    if (!storage || bytes != APPLE_CELL_BYTES || !out || parent < 0 || bundle < 0
        || parent == bundle || !role_path(role, (const char *)path, length)) return 0;
    apple_cell *cell=storage;
    if (cell->magic) return -1; // a live/unknown original is never overwritten
    memset(cell, 0, sizeof(*cell)); cell->magic=APPLE_CELL_MAGIC;
    cell->pid=getpid(); cell->thread=pthread_self(); cell->role=role;
    cell->parent=parent; cell->bundle=bundle;
    memcpy(cell->path, path, length);
    const char *slash=strrchr(cell->path, '/');
    size_t parent_length=(size_t)(slash-cell->path);
    memcpy(cell->parent_path, cell->path, parent_length);
    memcpy(cell->leaf, slash+1, length-parent_length);
    int result=originals(cell, 1); *out=cell->report;
    return result;
}
int mrk_xcode_apple_step(void *storage, uint32_t phase, apple_report *out) {
    apple_cell *cell=storage;
    if (!owner(cell) || !out || cell->report.unknown || phase != cell->report.phase+1
        || phase < 1 || phase > 6) return -1;
    cell->report.phase=phase; int result=1; OSStatus status=errSecSuccess;
    @try {
        switch (phase) {
            case 1:
                cell->values[0]=CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
                    (const UInt8 *)cell->path, (CFIndex)strlen(cell->path), true);
                result=cell->values[0] != NULL; break;
            case 2: {
                SecStaticCodeRef code=NULL;
                status=SecStaticCodeCreateWithPath((CFURLRef)cell->values[0], kSecCSDefaultFlags, &code);
                cell->values[1]=code; result=status==errSecSuccess && code; break;
            }
            case 3:
                cell->values[2]=CFStringCreateWithCString(kCFAllocatorDefault,
                    "identifier \"com.apple.dt.Xcode\" and anchor apple", kCFStringEncodingUTF8);
                result=cell->values[2] != NULL; break;
            case 4: {
                SecRequirementRef requirement=NULL;
                status=SecRequirementCreateWithString((CFStringRef)cell->values[2], kSecCSDefaultFlags, &requirement);
                cell->values[3]=requirement; result=status==errSecSuccess && requirement; break;
            }
            case 5: {
                CFErrorRef error=NULL;
                status=SecStaticCodeCheckValidityWithErrors((SecStaticCodeRef)cell->values[1],
                    kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode
                    | kSecCSNoNetworkAccess, (SecRequirementRef)cell->values[3], &error);
                cell->values[4]=error;
                result=status==errSecSuccess && !error;
                cell->report.verified=(uint32_t)result; break;
            }
            case 6: result=originals(cell, 0); break;
        }
    } @catch (...) { cell->report.unknown=1; result=-1; }
    for (unsigned i=0; i<APPLE_REFS; ++i) if (cell->values[i] && cell->report.states[i]==0) cell->report.states[i]=2;
    if (phase == 2 || phase == 4 || phase == 5) cell->report.status=status;
    *out=cell->report; return result;
}
int mrk_xcode_apple_release(void *storage, uint32_t slot, apple_report *out) {
    apple_cell *cell=storage;
    if (!owner(cell) || !out || slot>=APPLE_REFS || cell->report.states[slot]!=2 || !cell->values[slot]) return -1;
    // A throwing/nonreturning release cannot be retried. Other independent
    // known references remain eligible for their own original cleanup calls.
    cell->report.states[slot]=3;
    @try { CFRelease(cell->values[slot]); cell->values[slot]=NULL; cell->report.states[slot]=4; }
    @catch (...) { cell->report.unknown=1; *out=cell->report; return -1; }
    *out=cell->report; return 1;
}
int mrk_xcode_apple_retire(void *storage) {
    apple_cell *cell=storage;
    if (!owner(cell) || cell->report.unknown) return 0;
    for (unsigned i=0; i<APPLE_REFS; ++i)
        if (cell->values[i] || (cell->report.states[i]!=0 && cell->report.states[i]!=4)) return 0;
    memset(cell, 0, sizeof(*cell)); return 1;
}
