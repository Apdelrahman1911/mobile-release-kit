/* Ordinary installed entry. One fixed exec after SH, no Cocoa or Rust startup.
 * This binary has no fixture/scenario/configuration or maintenance action. */
#include "gate.h"
#include <sys/file.h>
#include <sys/mount.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

static int account_text(const char *value, const char *storage, size_t length, size_t maximum) {
    if (!value) return 0;
    uintptr_t start = (uintptr_t)storage, address = (uintptr_t)value;
    if (address < start || address - start >= length) return 0;
    size_t available = length - (size_t)(address - start);
    const char *end = memchr(value, 0, available);
    return end && end > value && (size_t)(end - value) <= maximum;
}
static int environment(char home[PATH_MAX+6], char user[262], char logname[265], char temporary[PATH_MAX+8]) {
    struct passwd account, *found = NULL;
    char storage[16384], selected[PATH_MAX], resolved[PATH_MAX];
    if (getpwuid_r(getuid(), &account, storage, sizeof(storage), &found)
        || found != &account || account.pw_uid != getuid() || account.pw_gid != getgid()
        || !account_text(account.pw_name, storage, sizeof(storage), 255)
        || !account_text(account.pw_dir, storage, sizeof(storage), PATH_MAX - 1)
        || account.pw_dir[0] != '/') return 0;
    size_t count = confstr(_CS_DARWIN_USER_TEMP_DIR, selected, sizeof(selected));
    if (!count || count > sizeof(selected) || !realpath(selected, resolved)
        || strncmp(resolved, "/private/var/folders/", 21)) return 0;
    int fd = open(resolved, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat before, named, after; struct statfs fs;
    int valid = !fstat(fd, &before) && S_ISDIR(before.st_mode) && before.st_uid == getuid()
        && (before.st_mode & 07777) == 0700 && !lstat(resolved, &named)
        && named.st_dev == before.st_dev && named.st_ino == before.st_ino && named.st_mode == before.st_mode
        && named.st_uid == before.st_uid && named.st_gid == before.st_gid
        && !fstatfs(fd, &fs) && !strcmp(fs.f_fstypename, "apfs") && (fs.f_flags & MNT_LOCAL)
        && !(fs.f_flags & (MNT_UNION | MNT_AUTOMOUNTED | MNT_IGNORE_OWNERSHIP))
        && !fstat(fd, &after) && after.st_dev == before.st_dev && after.st_ino == before.st_ino
        && after.st_mode == before.st_mode && after.st_uid == before.st_uid && after.st_gid == before.st_gid;
    int close_result = close(fd); /* Always one consuming close; never retry. */
    if (!valid || close_result) return 0;
    int a = snprintf(home, PATH_MAX+6, "HOME=%s", account.pw_dir);
    int b = snprintf(user, 262, "USER=%s", account.pw_name);
    int c = snprintf(logname, 265, "LOGNAME=%s", account.pw_name);
    int d = snprintf(temporary, PATH_MAX+8, "TMPDIR=%s/", resolved);
    return a > 5 && a < PATH_MAX+6 && b > 5 && b < 262 && c > 8 && c < 265 && d > 8 && d < PATH_MAX+8;
}
int main(int argc, char **argv) {
    (void)argv;
    uint32_t uid = 0;
    char own[PATH_MAX]; uint32_t own_size = sizeof(own);
    if (argc != 1 || mrk_user(&uid) || _NSGetExecutablePath(own, &own_size)
        || strcmp(own, MRK_ENTRY_EXECUTABLE)) return 64;
    mrk_entry_book reservation; mrk_entry_init(&reservation);
    if (!mrk_entry_root(&reservation) || !mrk_entry_open_registration(&reservation)
        || mrk_registration_acquire_shared(&reservation) != 1) _exit(75);
    mrk_entry_book book; mrk_entry_init(&book);
    if (!mrk_entry_root(&book) || !mrk_entry_open_gate(&book)) _exit(65);
    if (flock(book.gate, LOCK_SH | LOCK_NB)) _exit(errno == EWOULDBLOCK ? 75 : 66);
    if (!mrk_entry_gate_matches(&book, FD_CLOEXEC)) _exit(67);
    /* Overlap R SH with the actual lifetime M SH. R never crosses exec. */
    if (!mrk_registration_retire(&reservation)) _exit(67);
    char home[PATH_MAX+6], user[262], logname[265], temporary[PATH_MAX+8];
    if (!environment(home, user, logname, temporary)) _exit(68);
    char *const clean[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", home, user, logname,
        temporary, "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8", "TZ=UTC", NULL};
    if (fcntl(book.gate, F_SETFD, 0) || !mrk_entry_gate_matches(&book, 0)) _exit(69);
    char descriptor[16], process[16];
    int a = snprintf(descriptor, sizeof(descriptor), "%d", book.gate);
    int b = snprintf(process, sizeof(process), "%d", getpid());
    if (a < 1 || (size_t)a >= sizeof(descriptor) || b < 1 || (size_t)b >= sizeof(process)) _exit(70);
    if (!mrk_entry_close_ancestors(&book)) _exit(71);
    char *const next[] = {MRK_PAYLOAD_EXECUTABLE, MRK_INSTALLED_ENTRY_ARGUMENT, descriptor, process, NULL};
    execve(MRK_PAYLOAD_EXECUTABLE, next, clean);
    const int returned_errno = errno; /* Latch actual return before anything else. */
    _exit(returned_errno == ENOENT ? 76 : 72);
    /* Even on failure, no early close/unlock of the original SH. Kernel exit
     * releases it. This does not claim any child/service lifetime closure. */
}
