/* Private synthetic fixture only. No installed-product ABI or path selector. */
#ifndef MRK_M2_FIXTURE_H
#define MRK_M2_FIXTURE_H
#include "fixture_config.h" /* Created once in the fresh, admitted build root. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MRK_ENTRY_APP MRK_ROOT "/Launch Mobile Release Kit.app"
#define MRK_PAYLOAD_APP MRK_ROOT "/Mobile Release Kit.app"
#define MRK_PAYLOAD_EXE MRK_PAYLOAD_APP "/Contents/MacOS/payload"
#define MRK_GATE "maintenance-use.lock"

static inline int mrk_close(int *original) {
    int fd = *original; *original = -1;
    return fd >= 0 && close(fd) == 0; /* Never retry a consumed number. */
}
static inline int mrk_account(void) {
    return getuid() == MRK_UID && getgid() == MRK_GID && getuid() != 0
        && getuid() == geteuid() && getgid() == getegid();
}
static inline int mrk_root(void) {
    struct stat a, b;
    int fd = open(MRK_ROOT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &a) || lstat(MRK_ROOT, &b) || !S_ISDIR(a.st_mode)
        || a.st_dev != b.st_dev || a.st_ino != b.st_ino
        || a.st_uid != MRK_UID || a.st_gid != MRK_GID || (a.st_mode & 07777) != 0700) {
        (void)mrk_close(&fd); return -1;
    }
    return fd;
}
static inline int mrk_gate_matches(int root, int fd) {
    struct stat a, b;
    return fd >= 3 && !fstat(fd, &a) && !fstatat(root, MRK_GATE, &b, AT_SYMLINK_NOFOLLOW)
        && S_ISREG(a.st_mode) && (a.st_mode & 07777) == 0444 && a.st_nlink == 1
        && a.st_uid == MRK_UID && a.st_gid == MRK_GID && a.st_size == 0
        && (uint64_t)a.st_dev == MRK_GATE_DEVICE && (uint64_t)a.st_ino == MRK_GATE_INODE
        && a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size;
}
static inline int mrk_open_gate(int root) {
    int fd = openat(root, MRK_GATE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    if (!mrk_gate_matches(root, fd)) { (void)mrk_close(&fd); return -1; }
    return fd;
}
/* A DIFFERENT open description, never an unlock/conversion of the bridge. */
static inline int mrk_exclusive_probe(int root) {
    int fd = mrk_open_gate(root), answer = -1;
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) answer = 1;
    else if (errno == EWOULDBLOCK) answer = 0;
    if (!mrk_close(&fd)) return -1;
    return answer;
}
static inline int mrk_decimal(const char *text, int minimum, int *value) {
    if (!text || !*text || strlen(text) > 10) return 0;
    for (const char *p = text; *p; ++p) if (*p < '0' || *p > '9') return 0;
    errno = 0; char *end = NULL; long number = strtol(text, &end, 10);
    if (errno || !end || *end || number < minimum || number > INT_MAX) return 0;
    char canonical[16]; int count = snprintf(canonical, sizeof(canonical), "%ld", number);
    if (count < 1 || (size_t)count >= sizeof(canonical) || strcmp(canonical, text)) return 0;
    *value = (int)number; return 1;
}
/* Four fixed public diagnostic records; exclusive publication, no repair. */
static inline int mrk_record(int root, const char *name, const char *body) {
    size_t size = strlen(body), offset = 0;
    char staging[80];
    int count = snprintf(staging, sizeof(staging), ".%s.inflight", name);
    if (!size || size > 4096 || count < 1 || (size_t)count >= sizeof(staging)) return 0;
    int fd = openat(root, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    int ok = 1;
    while (offset < size) {
        ssize_t written = write(fd, body + offset, size - offset);
        if (written <= 0) { ok = 0; break; }
        offset += (size_t)written;
    }
    /* Initial sealing of this newly created output, never permission repair. */
    if (ok && (fchmod(fd, 0400) || fsync(fd))) ok = 0;
    if (!mrk_close(&fd)) ok = 0;
    if (!ok || renameatx_np(root, staging, root, name, RENAME_EXCL)) return 0;
    return fsync(root) == 0;
}
static inline double mrk_now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}
static inline int mrk_before(double deadline) {
    double now = mrk_now();
    return now >= 0 && now < deadline;
}
#endif
