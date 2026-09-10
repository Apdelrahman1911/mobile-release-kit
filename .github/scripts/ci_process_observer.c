/* Fixed, unentitled BSD metadata reader for admitted macOS test fixtures.
 * Build with the actual selected SDK.  Never execute this helper as root.
 * Output is a versioned BSD record, not a substitute ps/Mach-thread state.
 */
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <unistd.h>
#include <libproc.h>

/* Compile-time evidence for the original parent's fixed libproc byte buffers.
 * These assertions use the selected SDK; ctypes self-layout is not evidence.
 * They add no observer mode, output, root execution or runtime operation.
 */
_Static_assert(CHAR_BIT == 8 && sizeof(void *) == 8 && sizeof(int) == 4
               && INT_MAX == 2147483647 && INT_MIN == (-2147483647 - 1),
               "native-parent libproc requires the 64-bit, 32-bit-int ABI");
_Static_assert(sizeof(uint32_t) == 4 && sizeof(uint64_t) == 8,
               "native-parent libproc integer widths differ");
_Static_assert(_Generic((uid_t)0, uint32_t: 1, default: 0)
               && _Generic((gid_t)0, uint32_t: 1, default: 0)
               && _Generic((pid_t)0, int32_t: 1, default: 0),
               "native-parent libproc credential/PID types differ");
_Static_assert(_Generic(&proc_pidinfo,
                       int (*)(int, int, uint64_t, void *, int): 1, default: 0),
               "native-parent proc_pidinfo signature differs");
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__)
#error "native-parent libproc target byte order is unavailable"
#else
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "native-parent libproc requires little-endian buffers");
#endif

#define MRK_NATIVE_ABI_FIELD(record, field, offset, type) \
    _Static_assert(offsetof(struct record, field) == (offset) \
                   && sizeof(((struct record *)0)->field) == sizeof(type) \
                   && _Generic(((struct record *)0)->field, type: 1, default: 0), \
                   "native-parent libproc ABI differs: " #record "." #field)

_Static_assert(sizeof(struct proc_bsdinfo) == 136,
               "native-parent proc_bsdinfo buffer size differs");
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_flags, 0, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_status, 4, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_xstatus, 8, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_pid, 12, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_ppid, 16, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_uid, 20, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_gid, 24, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_ruid, 28, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_rgid, 32, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_svuid, 36, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_bsdinfo, pbi_svgid, 40, uint32_t);
_Static_assert(offsetof(struct proc_bsdinfo, pbi_comm) == 48
               && sizeof(((struct proc_bsdinfo *)0)->pbi_comm) == 16,
               "native-parent proc_bsdinfo command-name ABI differs");
_Static_assert(offsetof(struct proc_bsdinfo, pbi_name) == 64
               && sizeof(((struct proc_bsdinfo *)0)->pbi_name) == 32,
               "native-parent proc_bsdinfo reported-name ABI differs");

_Static_assert(sizeof(struct proc_exitreasonbasicinfo) == 24,
               "native-parent BASIC buffer size differs");
MRK_NATIVE_ABI_FIELD(proc_exitreasonbasicinfo, beri_namespace, 0, uint32_t);
MRK_NATIVE_ABI_FIELD(proc_exitreasonbasicinfo, beri_code, 4, uint64_t);
MRK_NATIVE_ABI_FIELD(proc_exitreasonbasicinfo, beri_flags, 12, uint64_t);
MRK_NATIVE_ABI_FIELD(proc_exitreasonbasicinfo, beri_reason_buf_size, 20, uint32_t);
#undef MRK_NATIVE_ABI_FIELD

_Static_assert(PROC_PIDTBSDINFO == 3 && PROC_PIDTBSDINFO_SIZE == 136,
               "native-parent BSD selector/size differs");
_Static_assert(SIDL == 1 && SRUN == 2 && SSLEEP == 3 && SSTOP == 4 && SZOMB == 5,
               "native-parent BSD status constants differ");
_Static_assert(PROC_FLAG_TRACED == 2 && PROC_FLAG_INEXIT == 4
               && PROC_FLAG_LP64 == 0x10 && PROC_FLAG_PSUGID == 0x2000,
               "native-parent BSD flag constants differ");
/* BASIC25 is private XNU12377.1.9-family source provenance, not an SDK-
 * measured selector when the SDK does not expose its definition. Never
 * include private headers or invent a definition to make this check pass.
 */
#ifdef PROC_PIDEXITREASONBASICINFO
_Static_assert(PROC_PIDEXITREASONBASICINFO == 25,
               "native-parent private BASIC selector differs");
#endif

enum { OUTPUT_LIMIT = 512, GROUP_LIMIT = 256 };

/* A partial write or failed close cannot publish a successful observation.
 * No close retry: an interrupted close does not establish FD custody.
 */
static int emit(int status, const char *format, ...)
{
    char line[OUTPUT_LIMIT];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    bool failed = length < 1 || (size_t)length >= sizeof(line);
    if (!failed && write(STDOUT_FILENO, line, (size_t)length) != length)
        failed = true;
    if (close(STDOUT_FILENO) != 0)
        failed = true;
    return failed ? 3 : status;
}

static int failure(const char *code)
{
    return emit(3, "MRK_PROCESS_V1 error %s\n", code);
}

static bool canonical_pid(const char *text, int *pid)
{
    if (text == NULL || text[0] < '1' || text[0] > '9')
        return false;
    unsigned int value = 0;
    size_t index = 0;
    for (; text[index] != '\0'; ++index) {
        if (index >= 10 || text[index] < '0' || text[index] > '9')
            return false;
        unsigned int digit = (unsigned int)(text[index] - '0');
        if (value > ((unsigned int)INT_MAX - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    if (value < 2)
        return false;
    *pid = (int)value;
    return true;
}

/* The modern SDK getgroups declaration can select Darwin's NSS alias.
 * Select only the fixed unversioned libSystem function, with actual SDK gid_t.
 */
static bool kernel_groups(gid_t expected, char *diagnostic, size_t capacity)
{
    void *library = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        (void)dlerror();
        (void)snprintf(diagnostic, capacity, "GROUP_LIBRARY");
        return false;
    }
    const char *problem = NULL;
    int error_number = 0;
    (void)dlerror();
    void *symbol = dlsym(library, "getgroups");
    const char *lookup_error = dlerror();
    if (symbol == NULL || lookup_error != NULL) {
        problem = "GROUP_SYMBOL";
    } else {
        typedef int (*getgroups_function)(int, gid_t *);
        getgroups_function operation = (getgroups_function)symbol;
        errno = 0;
        int count = operation(0, NULL);
        int count_error = errno;
        if (count < 0) {
            problem = "GROUP_COUNT";
            error_number = count_error;
        } else if (count < 1 || count > GROUP_LIMIT) {
            problem = "GROUP_BOUND";
        } else {
            gid_t groups[GROUP_LIMIT] = {0};
            errno = 0;
            int filled = operation(count, groups);
            int fill_error = errno;
            if (filled < 0) {
                problem = "GROUP_READ";
                error_number = fill_error;
            } else if (filled != count) {
                problem = "GROUP_CHANGED";
            } else if (count != 1 || groups[0] != expected) {
                problem = "GROUP_IDENTITY";
            }
        }
    }
    bool close_failed = dlclose(library) != 0;
    if (problem == NULL && !close_failed)
        return true;
    /* Preserve a primary observation failure AND independent library close. */
    (void)snprintf(diagnostic, capacity, "%s_%d%s",
                   problem == NULL ? "GROUP_CLOSE" : problem, error_number,
                   problem != NULL && close_failed ? "_AND_CLOSE" : "");
    return false;
}

static int query(int pid, struct proc_bsdinfo *info, int *error_number)
{
    memset(info, 0, sizeof(*info));
    errno = 0;
    /* A zero arg omits still-existing zombies on Darwin. */
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, UINT64_C(1), info,
                            (int)sizeof(*info));
    *error_number = errno;
    return size;
}

static bool same_identity(const struct proc_bsdinfo *info, uid_t uid, gid_t gid)
{
    return info->pbi_ruid == uid && info->pbi_uid == uid && info->pbi_svuid == uid
        && info->pbi_rgid == gid && info->pbi_gid == gid && info->pbi_svgid == gid
        && !(info->pbi_flags & PROC_FLAG_PSUGID);
}

int main(int argc, char **argv)
{
    int pid = 0;
    if (argc != 2 || !canonical_pid(argv[1], &pid))
        return failure("INPUT");
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (uid == 0 || geteuid() != uid || getegid() != gid)
        return failure("CALLER_IDENTITY");

    struct proc_bsdinfo self;
    int error_number = 0;
    int self_pid = (int)getpid();
    int size = query(self_pid, &self, &error_number);
    if (size != (int)sizeof(self))
        return failure("SELF_QUERY");
    if (self.pbi_pid != (uint32_t)self_pid || !same_identity(&self, uid, gid))
        return failure("SELF_IDENTITY");
    char group_error[96];
    if (!kernel_groups(gid, group_error, sizeof(group_error)))
        return failure(group_error);

    struct proc_bsdinfo info;
    size = query(pid, &info, &error_number);
    if (size == 0 && error_number == ESRCH)
        return emit(0, "MRK_PROCESS_V1 absent %d\n", pid);
    if (size == 0 && (error_number == EPERM || error_number == EACCES))
        return emit(2, "MRK_PROCESS_V1 denied %d kernel %d\n", pid, error_number);
    if (size != (int)sizeof(info))
        return failure(size == 0 ? "QUERY" : "SIZE");
    if (info.pbi_pid != (uint32_t)pid || info.pbi_pgid < 2
        || info.pbi_pgid > (uint32_t)INT_MAX || !same_identity(&info, uid, gid))
        return emit(2, "MRK_PROCESS_V1 denied %d identity 0\n", pid);

    unsigned int exiting = (info.pbi_flags & PROC_FLAG_INEXIT) ? 1U : 0U;
    const char *state = "indeterminate";
    if (info.pbi_status == SZOMB)
        state = "zombie"; /* A real zombie may retain INEXIT; SZOMB wins. */
    else if (!exiting && (info.pbi_status == SRUN || info.pbi_status == SSLEEP
                          || info.pbi_status == SSTOP))
        state = "live"; /* BSD non-exited presence, not a Mach-thread claim. */
    return emit(0, "MRK_PROCESS_V1 present %" PRIu32 " %" PRIu32
                " %" PRIu32 " %" PRIu32 " %" PRIu32
                " %" PRIu32 " %" PRIu32 " %" PRIu32
                " %" PRIu32 " %u %s\n",
                info.pbi_pid, info.pbi_pgid,
                (uint32_t)info.pbi_ruid, (uint32_t)info.pbi_uid, (uint32_t)info.pbi_svuid,
                (uint32_t)info.pbi_rgid, (uint32_t)info.pbi_gid, (uint32_t)info.pbi_svgid,
                info.pbi_status, exiting, state);
}
