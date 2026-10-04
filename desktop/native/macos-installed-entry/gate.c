/* C/libSystem-only installed gate admission. The same source is linked into
 * the entry, payload and fixed vault helper. No destructor or unlock.
 * Pure metadata primitives are shared with native.m's metadata-only build. */
#include "gate.h"
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

_Static_assert(sizeof(MRK_MAINTENANCE_GATE_BYTES) == 31, "fixed30B permanent gate required");
_Static_assert(sizeof(mrk_entry_book) <= 1024, "bounded fixed gate startup book");

static const char *const ancestors[MRK_ENTRY_ANCESTORS] = {
    "/", "Library", "Application Support", "MobileReleaseKit"
};
static int fail(mrk_entry_book *book) { book->failed = 1; return 0; }
static int identity(const struct stat *a, const struct stat *b, int leaf) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino
        && a->st_mode == b->st_mode && a->st_uid == b->st_uid
        && a->st_gid == b->st_gid && a->st_flags == b->st_flags
        && (!leaf || (a->st_nlink == b->st_nlink && a->st_size == b->st_size
            && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec
            && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec
            && a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec
            && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec));
}
static int protected_fd(int fd, const struct stat *s, int leaf, int product) {
    struct statfs fs;
    int phase = 0, returned = 0, error = 0, freed = 0, free_error = 0;
    if ((s->st_mode & S_IFMT) != (leaf ? S_IFREG : S_IFDIR)
        || s->st_uid != 0 || (s->st_mode & 07022)
        || ((leaf || product) && (s->st_gid != 0
            || (s->st_mode & 07777) != (leaf ? 0444 : 0755)))
        || (leaf && (s->st_nlink != 1 || s->st_flags != 0
            || s->st_size != (off_t)(sizeof(MRK_MAINTENANCE_GATE_BYTES) - 1)))
        || fstatfs(fd, &fs) || strcmp(fs.f_fstypename, "apfs")
        || !(fs.f_flags & MNT_LOCAL)
        || (fs.f_flags & (MNT_UNION | MNT_AUTOMOUNTED | MNT_IGNORE_OWNERSHIP))) return 0;
    if (mrk_acl_empty(fd, &phase, &returned, &error, &freed, &free_error)) return 0;
    return (!leaf && !product) || mrk_no_xattrs(fd) == 0;
}
void mrk_entry_init(mrk_entry_book *book) {
    memset(book, 0, sizeof(*book));
    for (unsigned i = 0; i < MRK_ENTRY_ANCESTORS; ++i) book->ancestors[i] = -1;
    book->gate = -1;
}
int mrk_entry_root(mrk_entry_book *book) {
    if (book->failed || book->ancestors[0] >= 0) return fail(book);
    for (unsigned i = 0; i < MRK_ENTRY_ANCESTORS; ++i) {
        struct stat named, actual, after;
        int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
        if (i ? fstatat(book->ancestors[i-1], ancestors[i], &named, AT_SYMLINK_NOFOLLOW)
              : lstat("/", &named)) return fail(book);
        if (!S_ISDIR(named.st_mode)) return fail(book);
        book->ancestors[i] = i ? openat(book->ancestors[i-1], ancestors[i], flags) : open("/", flags);
        if (book->ancestors[i] < 0 || fstat(book->ancestors[i], &actual)
            || !identity(&named, &actual, 0)
            || !protected_fd(book->ancestors[i], &actual, 0, i == MRK_ENTRY_ANCESTORS - 1)) return fail(book);
        if (i ? fstatat(book->ancestors[i-1], ancestors[i], &after, AT_SYMLINK_NOFOLLOW)
              : lstat("/", &after)) return fail(book);
        if (!identity(&actual, &after, 0)) return fail(book);
        book->identities[i] = actual;
    }
    return 1;
}
int mrk_entry_gate_matches(mrk_entry_book *book, int flags) {
    struct stat named, actual;
    char data[sizeof(MRK_MAINTENANCE_GATE_BYTES) - 1], extra;
    if (book->failed || book->gate < 3 || fcntl(book->gate, F_GETFD) != flags) return fail(book);
    for (unsigned i = 0; i < MRK_ENTRY_ANCESTORS; ++i) {
        if (book->ancestors[i] < 0 || fstat(book->ancestors[i], &actual)
            || !identity(&actual, &book->identities[i], 0)) return fail(book);
        if (i ? fstatat(book->ancestors[i-1], ancestors[i], &named, AT_SYMLINK_NOFOLLOW)
              : lstat("/", &named)) return fail(book);
        if (!identity(&actual, &named, 0)) return fail(book);
    }
    int parent = book->ancestors[MRK_ENTRY_ANCESTORS - 1];
    if (fstatat(parent, MRK_MAINTENANCE_GATE_NAME, &named, AT_SYMLINK_NOFOLLOW)
        || fstat(book->gate, &actual) || !identity(&named, &actual, 1)
        || !protected_fd(book->gate, &actual, 1, 0)
        || pread(book->gate, data, sizeof(data), 0) != (ssize_t)sizeof(data)
        || memcmp(data, MRK_MAINTENANCE_GATE_BYTES, sizeof(data))
        || pread(book->gate, &extra, 1, sizeof(data)) != 0) return fail(book);
    if (book->gate_identity.st_ino && !identity(&actual, &book->gate_identity, 1)) return fail(book);
    struct stat after;
    if (fstat(book->gate, &after) || !identity(&actual, &after, 1)
        || fstatat(parent, MRK_MAINTENANCE_GATE_NAME, &after, AT_SYMLINK_NOFOLLOW)
        || !identity(&actual, &after, 1)) return fail(book);
    book->gate_identity = actual;
    return 1;
}
int mrk_entry_open_gate(mrk_entry_book *book) {
    if (book->failed || book->gate != -1 || book->ancestors[MRK_ENTRY_ANCESTORS-1] < 0) return fail(book);
    book->gate = openat(book->ancestors[MRK_ENTRY_ANCESTORS-1], MRK_MAINTENANCE_GATE_NAME,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    return book->gate >= 0 && mrk_entry_gate_matches(book, FD_CLOEXEC);
}
int mrk_entry_close_ancestors(mrk_entry_book *book) {
    int closed = 1;
    for (unsigned i = MRK_ENTRY_ANCESTORS; i > 0; --i) {
        int fd = book->ancestors[i-1];
        book->ancestors[i-1] = -1; /* Spend the original before the one close. */
        if (fd >= 0 && close(fd)) { closed = 0; book->failed = 1; }
    }
    return closed;
}

/* These are process-lifetime originals, not a success/maintenance flag. */
static int original_gate = -1;
static pid_t original_process = 0;
static unsigned admission_entered = 0;
int mrk_installed_entry_admit(int descriptor, int32_t entry_pid) {
    uint32_t uid = 0;
    if (pthread_main_np() != 1 || admission_entered || original_gate >= 0) return EPERM;
    admission_entered = 1;
    if (mrk_user(&uid) || descriptor < 3 || entry_pid <= 1 || getpid() != entry_pid) return EPERM;
    mrk_entry_book book; mrk_entry_init(&book);
    book.gate = descriptor; /* Borrowed until exact admission; never close it here. */
    int accepted = mrk_entry_root(&book) && mrk_entry_gate_matches(&book, 0);
    if (accepted) accepted = fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0
        && mrk_entry_gate_matches(&book, FD_CLOEXEC);
    int closed = mrk_entry_close_ancestors(&book);
    if (!accepted || !closed) return EPERM;
    original_gate = descriptor; original_process = getpid();
    return 0;
    /* No flock/reacquisition, LOCK_UN, descriptor clone or release. The
     * entry's same original remains held until this kernel process exits. */
}
int mrk_installed_entry_retained(void) {
    return pthread_main_np() == 1 && original_gate >= 3 && original_process == getpid();
}

/* This callback is reachable only through the private, fixed Rust command.
 * Descriptor flags are private to the child after fork; flock state is not.
 * No lock/unlock, allocation, log, environment, pathname or cleanup here. */
int mrk_vault_gate_child_inherit(int descriptor, int32_t parent_pid) {
    if (descriptor < 3 || parent_pid <= 1 || getpid() == parent_pid || getppid() != parent_pid) return EPERM;
    int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0) return errno ? errno : EIO;
    if (flags != FD_CLOEXEC) return EPERM;
    if (fcntl(descriptor, F_SETFD, 0)) return errno ? errno : EIO;
    flags = fcntl(descriptor, F_GETFD);
    if (flags < 0) return errno ? errno : EIO;
    return flags == 0 ? 0 : EPERM;
}

static int vault_original_gate = -1;
static pid_t vault_original_process = 0;
static unsigned vault_admission_entered = 0;
int mrk_vault_helper_gate_admit(int descriptor, int32_t parent_pid) {
    uint32_t uid = 0;
    if (pthread_main_np() != 1 || vault_admission_entered || vault_original_gate >= 0) return EPERM;
    vault_admission_entered = 1;
    if (mrk_user(&uid) || descriptor < 3 || parent_pid <= 1 || getppid() != parent_pid) return EPERM;
    mrk_entry_book book; mrk_entry_init(&book);
    book.gate = descriptor; /* Borrowed until admitted; never close argv's FD. */
    int accepted = mrk_entry_root(&book) && mrk_entry_gate_matches(&book, 0);
    if (accepted) {
        int flags = fcntl(descriptor, F_GETFL);
        accepted = flags >= 0 && (flags & O_ACCMODE) == O_RDONLY && (flags & O_NONBLOCK)
            && !(flags & (O_APPEND | O_ASYNC));
    }
    if (accepted) accepted = fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0
        && mrk_entry_gate_matches(&book, FD_CLOEXEC) && getppid() == parent_pid;
    int closed = mrk_entry_close_ancestors(&book);
    if (!accepted || !closed) return EPERM;
    vault_original_gate = descriptor; vault_original_process = getpid();
    return vault_original_gate >= 3 && vault_original_process == getpid() ? 0 : EPERM;
    /* No LOCK_UN, close, dup, lock reacquisition or destructor. Kernel exit is
     * the lifetime boundary; GO and authenticated parent checks are separate. */
}
