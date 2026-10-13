/* Nonshipping, scripts-only Installer context observation. No App/runtime writes.
 * The generated header nominates only this owner's original packages/output.
 * It is compiled after both empty output originals have been acquired. */
#define _DARWIN_C_SOURCE 1
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef MRK_CONTEXT_SOURCE_COMMIT
#error fixed source commitment is required
#endif
#ifndef MRK_CONTEXT_OBSERVER_SHA256
#error fixed observer source digest is required
#endif

struct context_case {
    const char *name, *parent, *output;
    uint64_t parent_dev, parent_ino, parent_mode, parent_uid, parent_gid;
    uint64_t output_dev, output_ino, output_mode, output_uid, output_gid;
};
#include "mrk-context-inputs.h"

enum { PACKAGE_LIMIT = 8 * 1024 * 1024, RECORD_LIMIT = 4096 };
struct observation {
    const char *kind, *match;
    bool opened, closed;
    struct stat original;
    unsigned char sha256[CC_SHA256_DIGEST_LENGTH];
};

static bool timely(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0
        || value.tv_nsec < 0 || value.tv_nsec >= 1000000000L
        || (uint64_t)value.tv_sec > (UINT64_MAX - (uint64_t)value.tv_nsec) / UINT64_C(1000000000)) return false;
    uint64_t now = (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
    return now < MRK_CONTEXT_DEADLINE_NS;
}

static bool close_original(int *fd) {
    int original = *fd;
    *fd = -1; /* Consuming close, including an ambiguous result: never retry. */
    return original >= 0 && close(original) == 0;
}

static bool structural(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino
        && a->st_mode == b->st_mode && a->st_uid == b->st_uid
        && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink;
}

static bool complete(const struct stat *a, const struct stat *b) {
    return structural(a, b) && a->st_size == b->st_size
        && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec
        && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec
        && a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec
        && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}

/* A fixed generated path only; never any Installer argument or environment. */
static int directory_original(const char *path) {
    char spelling[PATH_MAX + 1];
    size_t length = strnlen(path, sizeof(spelling));
    if (!timely() || length < 1 || length >= sizeof(spelling) || path[0] != '/') return -1;
    memcpy(spelling, path, length + 1);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t offset = 1;
    unsigned count = 0;
    while (offset < length) {
        char *name = spelling + offset;
        char *slash = strchr(name, '/');
        if (slash != NULL) *slash = '\0';
        if (!timely() || ++count > 32 || name[0] == '\0'
            || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            (void)close_original(&fd); return -1;
        }
        struct stat parent, before, held, after;
        if (fstat(fd, &parent) != 0 || !S_ISDIR(parent.st_mode)
            || (parent.st_uid != 0 && parent.st_uid != MRK_CONTEXT_UID)
            || (parent.st_mode & 0022) != 0
            || fstatat(fd, name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
            (void)close_original(&fd); return -1;
        }
        int next = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        bool valid = next >= 0 && fstat(next, &held) == 0
            && fstatat(fd, name, &after, AT_SYMLINK_NOFOLLOW) == 0
            && structural(&before, &held) && structural(&held, &after)
            && S_ISDIR(held.st_mode) && (held.st_uid == 0 || held.st_uid == MRK_CONTEXT_UID)
            && (held.st_mode & 0022) == 0;
        bool previous_closed = close_original(&fd);
        if (!valid || !previous_closed) {
            if (next >= 0) (void)close_original(&next);
            return -1;
        }
        fd = next;
        if (slash == NULL) return fd;
        offset = (size_t)(slash - spelling) + 1;
    }
    return fd;
}

static bool observed_package(const char *path, struct observation *row) {
    size_t nomination = 3;
    for (size_t index = 0; index < 3; index++)
        if (strcmp(path, MRK_CONTEXT_PACKAGES[index]) == 0) nomination = index;
    if (nomination == 3) { row->kind = "other"; return true; }
    /* Read only a fixed task package. No fallback open of an unrelated path. */
    char parent_path[PATH_MAX + 1];
    size_t length = strlen(MRK_CONTEXT_PACKAGES[nomination]);
    if (length >= sizeof(parent_path)) return false;
    memcpy(parent_path, MRK_CONTEXT_PACKAGES[nomination], length + 1);
    char *name = strrchr(parent_path, '/');
    if (name == NULL || name == parent_path) return false;
    *name++ = '\0';
    int parent = directory_original(parent_path), fd = -1;
    struct stat before, after, named;
    bool good = parent >= 0 && timely()
        && fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0;
    if (good) fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    good = good && fd >= 0 && fstat(fd, &before) == 0 && complete(&before, &named)
        && S_ISREG(before.st_mode) && before.st_uid == MRK_CONTEXT_UID
        && before.st_nlink == 1 && (before.st_mode & 0022) == 0
        && before.st_size > 0 && before.st_size <= PACKAGE_LIMIT;
    if (fd >= 0) row->opened = true;
    CC_SHA256_CTX context;
    unsigned char bytes[65536];
    off_t offset = 0;
    if (good) good = CC_SHA256_Init(&context) == 1;
    while (good && offset < before.st_size) {
        size_t size = (size_t)(before.st_size - offset);
        if (size > sizeof(bytes)) size = sizeof(bytes);
        ssize_t count = timely() ? pread(fd, bytes, size, offset) : -1;
        good = count == (ssize_t)size && CC_SHA256_Update(&context, bytes, (CC_LONG)size) == 1;
        if (good) offset += (off_t)size;
    }
    if (good) good = timely() && pread(fd, bytes, 1, offset) == 0
        && fstat(fd, &after) == 0 && fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0
        && complete(&before, &after) && complete(&after, &named)
        && CC_SHA256_Final(row->sha256, &context) == 1;
    bool file_closed = fd >= 0 && close_original(&fd);
    bool parent_closed = parent >= 0 && close_original(&parent);
    if (!good || !file_closed || !parent_closed || !timely()) return false;
    row->kind = "nominated"; row->match = MRK_CONTEXT_PACKAGE_LABELS[nomination];
    row->closed = true; row->original = before;
    return true;
}

static bool observe(const char *path, bool present, struct observation *row) {
    memset(row, 0, sizeof(*row));
    if (!present) { row->kind = "missing"; return timely(); }
    if (path[0] == '\0') { row->kind = "empty"; return timely(); }
    if (strnlen(path, PATH_MAX + 1) > PATH_MAX) { row->kind = "other"; return timely(); }
    return timely() && observed_package(path, row);
}

static bool observation_json(char *buffer, size_t capacity, const struct observation *row) {
    if (!row->opened) {
        int count = snprintf(buffer, capacity,
            "{\"kind\":\"%s\",\"match\":null,\"opened\":false,\"closed\":null,\"original\":null,\"sha256\":null}",
            row->kind);
        return count > 0 && (size_t)count < capacity;
    }
    if (!row->closed || row->match == NULL || row->original.st_mtimespec.tv_sec < 0
        || row->original.st_ctimespec.tv_sec < 0) return false;
    const struct stat *s = &row->original;
    char hash[65];
    for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; index++)
        (void)snprintf(hash + index * 2, 3, "%02x", row->sha256[index]);
    uint64_t mtime = (uint64_t)s->st_mtimespec.tv_sec * UINT64_C(1000000000) + (uint64_t)s->st_mtimespec.tv_nsec;
    uint64_t ctime = (uint64_t)s->st_ctimespec.tv_sec * UINT64_C(1000000000) + (uint64_t)s->st_ctimespec.tv_nsec;
    int count = snprintf(buffer, capacity,
        "{\"kind\":\"nominated\",\"match\":\"%s\",\"opened\":true,\"closed\":true,"
        "\"original\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],\"sha256\":\"%s\"}",
        row->match, (uint64_t)s->st_dev, (uint64_t)s->st_ino, (uint64_t)s->st_mode,
        (uint64_t)s->st_uid, (uint64_t)s->st_gid, (uint64_t)s->st_nlink,
        (uint64_t)s->st_size, mtime, ctime, hash);
    return count > 0 && (size_t)count < capacity;
}

int main(int argc, char **argv) {
    /* argv1 is the exact fixed script case; argv2/3 transport PACKAGE_PATH;
     * remaining arguments are the unmodified original Installer script argv. */
    if (getuid() != 0 || geteuid() != 0 || argc < 4 || argc > 20 || !timely()
        || (strcmp(argv[2], "x") != 0 && argv[2][0] != '\0')) return 1;
    const struct context_case *selected = NULL;
    for (size_t index = 0; index < 2; index++)
        if (strcmp(argv[1], MRK_CONTEXT_CASES[index].name) == 0) selected = &MRK_CONTEXT_CASES[index];
    if (selected == NULL) return 1;
    int parent = directory_original(selected->parent), output = -1;
    struct stat parent_info, original, named, final;
    bool good = parent >= 0 && fstat(parent, &parent_info) == 0
        && (uint64_t)parent_info.st_dev == selected->parent_dev
        && (uint64_t)parent_info.st_ino == selected->parent_ino
        && (uint64_t)parent_info.st_mode == selected->parent_mode
        && (uint64_t)parent_info.st_uid == selected->parent_uid
        && (uint64_t)parent_info.st_gid == selected->parent_gid
        && timely() && fstatat(parent, selected->output, &named, AT_SYMLINK_NOFOLLOW) == 0;
    if (good) output = openat(parent, selected->output, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    good = good && output >= 0 && fstat(output, &original) == 0 && complete(&original, &named)
        && S_ISREG(original.st_mode) && original.st_size == 0 && original.st_nlink == 1
        && (uint64_t)original.st_dev == selected->output_dev
        && (uint64_t)original.st_ino == selected->output_ino
        && (uint64_t)original.st_mode == selected->output_mode
        && (uint64_t)original.st_uid == selected->output_uid
        && (uint64_t)original.st_gid == selected->output_gid;
    struct observation argument, package;
    if (good) good = observe(argc > 4 ? argv[4] : "", argc > 4, &argument)
        && observe(argv[3], strcmp(argv[2], "x") == 0, &package);
    char first[1024], second[1024], record[RECORD_LIMIT], readback[RECORD_LIMIT];
    if (good) good = observation_json(first, sizeof(first), &argument)
        && observation_json(second, sizeof(second), &package);
    int count = -1;
    if (good) count = snprintf(record, sizeof(record),
        "{\"schemaVersion\":1,\"type\":\"mrk-e2-installer-context-v1\","
        "\"sourceCommit\":\"%s\",\"observerSourceSha256\":\"%s\",\"case\":\"%s\","
        "\"clock\":\"CLOCK_MONOTONIC\",\"deadlineNs\":\"%" PRIu64 "\","
        "\"scriptArgumentCount\":%d,\"secondArgumentIsRoot\":%s,\"thirdArgumentIsRoot\":%s,"
        "\"outputOriginal\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",1],"
        "\"argumentOne\":%s,\"packagePath\":%s}\n",
        MRK_CONTEXT_SOURCE_COMMIT, MRK_CONTEXT_OBSERVER_SHA256, selected->name,
        MRK_CONTEXT_DEADLINE_NS, argc - 4,
        argc > 5 && strcmp(argv[5], "/") == 0 ? "true" : "false",
        argc > 6 && strcmp(argv[6], "/") == 0 ? "true" : "false",
        (uint64_t)original.st_dev, (uint64_t)original.st_ino, (uint64_t)original.st_mode,
        (uint64_t)original.st_uid, (uint64_t)original.st_gid, first, second);
    good = good && count > 0 && (size_t)count < sizeof(record) && timely();
    if (good) good = write(output, record, (size_t)count) == count && fsync(output) == 0
        && timely() && pread(output, readback, (size_t)count + 1, 0) == count
        && memcmp(record, readback, (size_t)count) == 0 && fstat(output, &final) == 0
        && fstatat(parent, selected->output, &named, AT_SYMLINK_NOFOLLOW) == 0
        && structural(&original, &final) && complete(&final, &named) && final.st_size == count;
    bool output_closed = output >= 0 && close_original(&output);
    bool parent_closed = parent >= 0 && close_original(&parent);
    /* The record does not claim these future closes. Only actual exec/Installer
     * success AND the parent's original output checks can establish them. */
    return good && output_closed && parent_closed && timely() ? 0 : 1;
}
