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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <unistd.h>
#include <libproc.h>

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
