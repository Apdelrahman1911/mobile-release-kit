/* Fixed, nonshipping Darwin regression. No service/API/registration action.
 * Compile only through the admitted E2 owner; no argv/environment path or mode.
 * The real metadata fault below is AFTER acquire_shared returned success. */
#include "gate.h"
#include <sys/file.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if !defined(MRK_E2_NATIVE_FIXTURE) || MRK_E2_NATIVE_FIXTURE != 1 || !defined(MRK_ENTRY_METADATA_ONLY)
#error fixed metadata-only E2 fixture compilation required
#endif
#if !defined(__APPLE__) || !defined(__arm64__) || defined(__x86_64__)
#error this fixed qualification is native Darwin ARM64 only
#endif
#ifndef MRK_IMAGE_SOURCE_COMMIT
#error admitted source commit required
#endif
_Static_assert(sizeof(MRK_IMAGE_SOURCE_COMMIT) == 41, "fixed source width");
_Static_assert(sizeof(MRK_MAINTENANCE_GATE_BYTES) == 31, "fixed M bytes");
_Static_assert(sizeof(MRK_REGISTRATION_GATE_BYTES) == 39, "fixed R bytes");

enum { PARENTS = 3, SLOTS = 3, ORIGINALS = 5, EXPECTED_OPENS = 61, FACTS = 11 };
enum phase { ENTRY, PARENT, ROOT_CREATE, ROOT_ADMIT, LEAF_CREATE, LEAF_ADMIT,
    SHARED_PAIR, SHARED_CONTENTION, SHARED_RETIRE, EXCLUSIVE_ACQUIRE,
    EXCLUSIVE_REFUSAL, EXCLUSIVE_RETIRE, M_DOMAIN, LATER_POST, LATER_RETIRE,
    ROOT_POST, CLEANUP, CLOCK, OUTPUT, PHASE_COUNT };
static const char *const phases[PHASE_COUNT] = {
    "entry", "parent", "root-create", "root-admit", "leaf-create", "leaf-admit",
    "shared-pair", "shared-contention", "shared-retire", "exclusive-acquire",
    "exclusive-refusal", "exclusive-retire", "m-domain", "later-post", "later-retire",
    "root-post", "cleanup", "clock", "output"
};
static const char *const parents[PARENTS] = { "/", "Library", "Application Support" };
static const char *const leaf_names[2] = { MRK_MAINTENANCE_GATE_NAME, MRK_REGISTRATION_GATE_NAME };
static const char *const leaf_bytes[2] = { MRK_MAINTENANCE_GATE_BYTES, MRK_REGISTRATION_GATE_BYTES };
static const size_t leaf_lengths[2] = { sizeof(MRK_MAINTENANCE_GATE_BYTES)-1, sizeof(MRK_REGISTRATION_GATE_BYTES)-1 };
static const char *const fact_names[FACTS] = {
    "sharedPairAcquired", "exclusiveBlockedBySharedPair", "exclusiveBlockedByRemainingShared",
    "exclusiveAfterSharedRetirement", "sharedRefusedByExclusive", "sharedAfterExclusiveRetirement",
    "separateMExclusiveWhileRShared", "laterMetadataRefused", "failedReservationRetainedKnown",
    "failedReservationRetiredKnown", "exclusiveAfterFailedRetirement"
};
struct participant { mrk_entry_book book; int originals[ORIGINALS]; int unknown; };
struct fixture {
    int parent[PARENTS], root, leaf[2];
    struct stat parent_stat[PARENTS], root_stat, leaf_stat[2];
    struct participant slots[SLOTS];
    uint64_t last, work_end, hard_end, first_time, cleanup_end;
    int clock_known, cleanup, phase, failure, close_unknown, uncertain;
    unsigned opened, closed, root_created, root_retired, leaf_created[2], facts[FACTS];
};
_Static_assert(sizeof(struct fixture) <= 8192, "fixed bounded stack fixture");

static int fail_at(struct fixture *f, int phase, uint64_t at) {
    if (!f->failure) { f->failure = phase + 1; f->first_time = at; }
    return 0;
}
static int require(struct fixture *f, int okay) {
    return okay ? 1 : fail_at(f, f->phase, f->last);
}
static int tick(struct fixture *f) {
    struct timespec t;
    if (!f->clock_known || clock_gettime(CLOCK_MONOTONIC, &t) != 0 || t.tv_sec < 0
        || t.tv_nsec < 0 || t.tv_nsec >= 1000000000
        || (uint64_t)t.tv_sec > (UINT64_MAX-999999999u)/1000000000u) {
        f->clock_known = 0; return fail_at(f, CLOCK, f->last);
    }
    uint64_t now = (uint64_t)t.tv_sec*1000000000u + (uint64_t)t.tv_nsec;
    if (!f->last) {
        if (!now || now > UINT64_MAX-22000000000ull) {
            f->clock_known = 0; return fail_at(f, CLOCK, now);
        }
        f->work_end = now+20000000000ull; f->hard_end = now+22000000000ull;
    } else if (now < f->last) {
        f->clock_known = 0; return fail_at(f, CLOCK, f->last);
    }
    f->last = now;
    uint64_t end = f->cleanup ? f->cleanup_end : f->work_end;
    return now < end ? 1 : fail_at(f, CLOCK, end);
}
#define STEP(f, condition) (tick(f) && require((f), (condition)) && tick(f))

static int same(const struct stat *a, const struct stat *b, int leaf) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode
        && a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_flags == b->st_flags
        && (!leaf || (a->st_nlink == b->st_nlink && a->st_size == b->st_size
            && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec
            && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec
            && a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec
            && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec));
}
static int transition(const struct stat *before, const struct stat *after, mode_t mode, gid_t gid) {
    /* ONLY this fixture's own explicit chmod/chown can change these two fields
     * and ctime. Nothing rebaselines a failed production participant. */
    struct stat expected = *before;
    expected.st_mode = (expected.st_mode & S_IFMT) | mode; expected.st_gid = gid;
    expected.st_ctimespec = after->st_ctimespec;
    return same(&expected, after, 1)
        && (after->st_ctimespec.tv_sec > before->st_ctimespec.tv_sec
            || (after->st_ctimespec.tv_sec == before->st_ctimespec.tv_sec
                && after->st_ctimespec.tv_nsec >= before->st_ctimespec.tv_nsec));
}
static int local_directory(struct fixture *f, int fd, const struct stat *s) {
    struct statfs fs;
    int phase = 0, returned = 0, error = 0, freed = 0, free_error = 0;
    return STEP(f, S_ISDIR(s->st_mode) && s->st_uid == 0 && !(s->st_mode & 07022))
        && STEP(f, fstatfs(fd, &fs) == 0)
        && STEP(f, !strcmp(fs.f_fstypename, "apfs") && (fs.f_flags & MNT_LOCAL)
            && !(fs.f_flags & (MNT_UNION | MNT_AUTOMOUNTED | MNT_IGNORE_OWNERSHIP)))
        && STEP(f, mrk_acl_empty(fd, &phase, &returned, &error, &freed, &free_error) == 0
            && !phase && !returned && !error && !freed && !free_error);
}
static int retain(struct fixture *f, int *slot, int fd) {
    *slot = fd; /* Record even when the following deadline or admission fails. */
    if (fd >= 0) ++f->opened;
    return require(f, fd >= 3) && tick(f);
}
static int consume(struct fixture *f, int *slot) {
    if (*slot < 0) return 1;
    if (!tick(f)) return 0;
    int original = *slot; *slot = -1;
    int returned = close(original);
    if (returned != 0) { f->close_unknown = f->uncertain = 1; return require(f, 0); }
    ++f->closed;
    return tick(f);
}
static int named_leaf(struct fixture *f, int i, struct stat *out) {
    struct stat named;
    char body[38], extra;
    return STEP(f, fstat(f->leaf[i], out) == 0)
        && STEP(f, fstatat(f->root, leaf_names[i], &named, AT_SYMLINK_NOFOLLOW) == 0)
        && STEP(f, same(out, &named, 1) && S_ISREG(out->st_mode) && out->st_uid == 0
            && out->st_gid == 0 && out->st_nlink == 1 && !out->st_flags
            && out->st_size == (off_t)leaf_lengths[i])
        && STEP(f, pread(f->leaf[i], body, leaf_lengths[i], 0) == (ssize_t)leaf_lengths[i])
        && STEP(f, !memcmp(body, leaf_bytes[i], leaf_lengths[i]))
        && STEP(f, pread(f->leaf[i], &extra, 1, (off_t)leaf_lengths[i]) == 0)
        && STEP(f, mrk_no_xattrs(f->leaf[i]) == 0);
}
static int root_named(struct fixture *f, struct stat *out) {
    struct stat named;
    return STEP(f, fstat(f->root, out) == 0)
        && STEP(f, fstatat(f->parent[2], MRK_INSTALLED_ROOT_LEAF, &named, AT_SYMLINK_NOFOLLOW) == 0)
        && STEP(f, same(out, &named, 1) && S_ISDIR(out->st_mode) && out->st_uid == 0 && !out->st_flags);
}
static int setup(struct fixture *f) {
    f->phase = PARENT;
    for (unsigned i = 0; i < PARENTS; ++i) {
        struct stat named, actual, after;
        if (!STEP(f, (i ? fstatat(f->parent[i-1], parents[i], &named, AT_SYMLINK_NOFOLLOW)
                        : lstat("/", &named)) == 0) || !tick(f)) return 0;
        int fd = i ? openat(f->parent[i-1], parents[i], O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
                   : open("/", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if (!retain(f, &f->parent[i], fd) || !STEP(f, fstat(fd, &actual) == 0)
            || !STEP(f, same(&named, &actual, 0)) || !local_directory(f, fd, &actual)
            || !STEP(f, (i ? fstatat(f->parent[i-1], parents[i], &after, AT_SYMLINK_NOFOLLOW)
                            : lstat("/", &after)) == 0)
            || !STEP(f, same(&actual, &after, 0))) return 0;
        f->parent_stat[i] = actual;
    }
    f->phase = ROOT_CREATE;
    struct stat missing;
    if (!tick(f)) return 0;
    errno = 0;
    int absent = fstatat(f->parent[2], MRK_INSTALLED_ROOT_LEAF, &missing, AT_SYMLINK_NOFOLLOW);
    int error = errno;
    if (!require(f, absent == -1 && error == ENOENT) || !tick(f)) return 0;
    if (!tick(f)) return 0;
    int made = mkdirat(f->parent[2], MRK_INSTALLED_ROOT_LEAF, 0700);
    if (made == 0) f->root_created = 1;
    if (!require(f, made == 0) || !tick(f)) return 0;
    if (!retain(f, &f->root, openat(f->parent[2], MRK_INSTALLED_ROOT_LEAF,
            O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC))) return 0;
    f->phase = ROOT_ADMIT;
    struct stat before, after;
    if (!root_named(f, &before) || !STEP(f, (before.st_mode & 07777) == 0700)
        || !local_directory(f, f->root, &before) || !STEP(f, mrk_no_xattrs(f->root) == 0)) return 0;
    if (before.st_gid != 0) {
        if (!STEP(f, fchown(f->root, (uid_t)-1, (gid_t)0) == 0) || !root_named(f, &after)
            || !STEP(f, transition(&before, &after, 0700, 0))) return 0;
        before = after;
    }
    if (!STEP(f, fchmod(f->root, 0755) == 0) || !root_named(f, &after)
        || !STEP(f, transition(&before, &after, 0755, 0))) return 0;
    f->root_stat = after;
    for (int i = 0; i < 2; ++i) {
        f->phase = LEAF_CREATE;
        if (!tick(f)) return 0;
        int fd = openat(f->root, leaf_names[i], O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC, 0600);
        if (fd >= 0) f->leaf_created[i] = 1;
        if (!retain(f, &f->leaf[i], fd) || !STEP(f, fstat(fd, &before) == 0)
            || !STEP(f, S_ISREG(before.st_mode) && (before.st_mode & 07777) == 0600
                && before.st_uid == 0 && before.st_gid == 0 && before.st_nlink == 1
                && before.st_size == 0 && !before.st_flags)
            || !STEP(f, pwrite(fd, leaf_bytes[i], leaf_lengths[i], 0) == (ssize_t)leaf_lengths[i])
            || !STEP(f, fstat(fd, &before) == 0) || !STEP(f, fchmod(fd, 0444) == 0)) return 0;
        f->phase = LEAF_ADMIT;
        if (!named_leaf(f, i, &after) || !STEP(f, transition(&before, &after, 0444, 0))) return 0;
        f->leaf_stat[i] = after;
    }
    return 1;
}
static void collect(struct fixture *f, struct participant *p) {
    for (unsigned i = 0; i < ORIGINALS; ++i) {
        int fd = i < MRK_ENTRY_ANCESTORS ? p->book.ancestors[i] : p->book.gate;
        if (fd >= 0 && p->originals[i] < 0) { p->originals[i] = fd; ++f->opened; }
    }
}
static int open_book(struct fixture *f, unsigned slot, int registration) {
    struct participant *p = &f->slots[slot];
    for (unsigned i = 0; i < ORIGINALS; ++i) if (!require(f, p->originals[i] < 0)) return 0;
    if (!require(f, !p->unknown) || !tick(f)) return 0;
    mrk_entry_init(&p->book);
    int returned = mrk_entry_root(&p->book); collect(f, p);
    if (!require(f, returned == 1) || !tick(f)) return 0;
    returned = registration ? mrk_entry_open_registration(&p->book) : mrk_entry_open_gate(&p->book);
    collect(f, p);
    return require(f, returned == 1) && tick(f)
        && STEP(f, same(&p->book.gate_identity, &f->leaf_stat[registration ? 1 : 0], 1));
}
static int shared(struct fixture *f, unsigned slot, int wanted) {
    struct participant *p = &f->slots[slot];
    if (!tick(f)) return 0;
    int returned = mrk_registration_acquire_shared(&p->book);
    if (returned < 0 || p->book.registration_unknown) { p->unknown = 1; f->uncertain = 1; }
    return require(f, returned == wanted && p->book.registration_attempted
        && p->book.registration_held == (unsigned)wanted && !p->book.registration_unknown
        && !p->book.registration_retired && p->book.failed == !wanted) && tick(f);
}
static int exclusive(struct fixture *f, unsigned slot, int wanted) {
    struct participant *p = &f->slots[slot];
    if (!STEP(f, mrk_entry_gate_matches(&p->book, FD_CLOEXEC) == 1)) return 0;
    errno = 0;
    int returned = flock(p->book.gate, LOCK_EX|LOCK_NB);
    int error = returned == -1 ? errno : 0;
    if (returned != 0 && !(returned == -1 && error == EWOULDBLOCK)) {
        p->unknown = 1; f->uncertain = 1;
    }
    return require(f, wanted ? returned == 0 : returned == -1 && error == EWOULDBLOCK)
        && tick(f) && STEP(f, mrk_entry_gate_matches(&p->book, FD_CLOEXEC) == 1);
}
static int retire_book(struct fixture *f, unsigned slot, int registration) {
    struct participant *p = &f->slots[slot];
    unsigned count = 0;
    for (unsigned i = 0; i < ORIGINALS; ++i) if (p->originals[i] >= 0) ++count;
    if (!count) return 1;
    if (p->unknown || p->book.registration_unknown) { f->uncertain = 1; return require(f, 0); }
    if (!tick(f)) return 0;
    int known;
    if (registration && p->book.gate_role == 1) {
        known = mrk_registration_retire(&p->book);
    } else {
        known = p->book.gate < 0 || mrk_entry_gate_matches(&p->book, FD_CLOEXEC) == 1;
        if (!mrk_entry_close_ancestors(&p->book)) known = 0;
        if (known && p->book.gate >= 0) {
            int original = p->book.gate; p->book.gate = -1;
            known = close(original) == 0;
        }
    }
    if (!known) { p->unknown = 1; f->uncertain = f->close_unknown = 1; return require(f, 0); }
    /* No opens/threads occur between the consuming returns and these checks.
     * Never close these saved integers again, even if a check is inconclusive. */
    for (unsigned i = 0; i < ORIGINALS; ++i) {
        int original = p->originals[i];
        if (original < 0) continue;
        p->originals[i] = -1;
        errno = 0;
        int flags = fcntl(original, F_GETFD); int error = errno;
        if (flags != -1 || error != EBADF) { f->uncertain = 1; return require(f, 0); }
        ++f->closed;
    }
    return tick(f);
}
static int controls(struct fixture *f) {
    f->phase = SHARED_PAIR;
    if (!open_book(f, 0, 1) || !shared(f, 0, 1) || !open_book(f, 1, 1) || !shared(f, 1, 1)) return 0;
    f->facts[0] = 1;
    f->phase = SHARED_CONTENTION;
    if (!open_book(f, 2, 1) || !exclusive(f, 2, 0) || !retire_book(f, 2, 0)) return 0;
    f->facts[1] = 1;
    f->phase = SHARED_RETIRE;
    if (!retire_book(f, 0, 1) || !open_book(f, 2, 1) || !exclusive(f, 2, 0)
        || !retire_book(f, 2, 0)) return 0;
    f->facts[2] = 1;
    if (!retire_book(f, 1, 1) || !open_book(f, 2, 1) || !exclusive(f, 2, 1)
        || !retire_book(f, 2, 0)) return 0;
    f->facts[3] = 1;
    f->phase = EXCLUSIVE_ACQUIRE;
    if (!open_book(f, 0, 1) || !exclusive(f, 0, 1)) return 0;
    f->phase = EXCLUSIVE_REFUSAL;
    if (!open_book(f, 1, 1) || !shared(f, 1, 0) || !retire_book(f, 1, 1)) return 0;
    f->facts[4] = 1;
    f->phase = EXCLUSIVE_RETIRE;
    if (!retire_book(f, 0, 0) || !open_book(f, 0, 1) || !shared(f, 0, 1)) return 0;
    f->facts[5] = 1;
    f->phase = M_DOMAIN;
    if (!open_book(f, 1, 0) || !exclusive(f, 1, 1) || !retire_book(f, 1, 0)
        || !retire_book(f, 0, 1)) return 0;
    f->facts[6] = 1;
    f->phase = LATER_POST;
    if (!open_book(f, 0, 1) || !shared(f, 0, 1)) return 0;
    struct participant *p = &f->slots[0];
    struct stat before, changed, restored, held;
    if (!named_leaf(f, 1, &before) || !STEP(f, same(&before, &p->book.gate_identity, 1))
        || !STEP(f, fstat(p->book.gate, &held) == 0) || !STEP(f, same(&held, &before, 1))
        || !STEP(f, fchmod(p->book.gate, 0400) == 0) || !named_leaf(f, 1, &changed)
        || !STEP(f, transition(&before, &changed, 0400, 0))) return 0;
    /* Deliberately LATER than acquire_shared's successful return, not an
     * injection into its internal PRE/flock/POST sequence. */
    if (!STEP(f, mrk_entry_gate_matches(&p->book, FD_CLOEXEC) == 0)) return 0;
    f->facts[7] = 1;
    if (!STEP(f, p->book.failed == 1 && p->book.registration_held == 1
        && p->book.registration_unknown == 0 && p->book.registration_retired == 0
        && p->book.gate == p->originals[4] && fcntl(p->book.gate, F_GETFD) == FD_CLOEXEC)) return 0;
    f->facts[8] = 1;
    if (!STEP(f, fstat(p->book.gate, &held) == 0) || !STEP(f, same(&held, &changed, 1))
        || !STEP(f, fchmod(p->book.gate, 0444) == 0) || !named_leaf(f, 1, &restored)
        || !STEP(f, transition(&changed, &restored, 0444, 0))) return 0;
    f->leaf_stat[1] = restored; /* Creator fact ONLY; failed participant stays failed. */
    f->phase = LATER_RETIRE;
    if (!retire_book(f, 0, 1)) return 0;
    f->facts[9] = 1;
    if (!open_book(f, 0, 1) || !exclusive(f, 0, 1) || !retire_book(f, 0, 0)) return 0;
    f->facts[10] = 1;
    return 1;
}
static int parent_post(struct fixture *f) {
    for (unsigned i = 0; i < PARENTS; ++i) {
        struct stat actual, named;
        if (!STEP(f, fstat(f->parent[i], &actual) == 0)
            || !STEP(f, (i ? fstatat(f->parent[i-1], parents[i], &named, AT_SYMLINK_NOFOLLOW)
                            : lstat("/", &named)) == 0)
            || !STEP(f, same(&actual, &f->parent_stat[i], 0) && same(&actual, &named, 0))) return 0;
    }
    return 1;
}
static void finish(struct fixture *f) {
    /* A prior failure's settlement window never resets at cleanup entry. */
    uint64_t origin = f->failure ? f->first_time : f->last;
    f->cleanup_end = origin <= UINT64_MAX-2000000000ull ? origin+2000000000ull : f->hard_end;
    if (f->cleanup_end > f->hard_end) f->cleanup_end = f->hard_end;
    f->cleanup = 1; f->phase = CLEANUP;
    for (unsigned i = 0; i < SLOTS; ++i) {
        int r = f->slots[i].book.registration_attempted != 0;
        if (!retire_book(f, i, r)) f->uncertain = 1;
    }
    /* Only the complete, confirmed fixture can be removed. Partial creation,
     * mutation, unknown close or named replacement retains it for its owner. */
    if (!f->failure && !f->uncertain && f->root_created) {
        f->phase = ROOT_POST;
        struct stat actual;
        int okay = parent_post(f) && root_named(f, &actual)
            && STEP(f, same(&actual, &f->root_stat, 0));
        for (int i = 0; i < 2 && okay; ++i)
            okay = named_leaf(f, i, &actual) && STEP(f, same(&actual, &f->leaf_stat[i], 1));
        f->phase = CLEANUP;
        for (int i = 0; i < 2 && okay; ++i) {
            okay = consume(f, &f->leaf[i]);
            if (okay) okay = STEP(f, fstatat(f->root, leaf_names[i], &actual, AT_SYMLINK_NOFOLLOW) == 0)
                && STEP(f, same(&actual, &f->leaf_stat[i], 1))
                && STEP(f, unlinkat(f->root, leaf_names[i], 0) == 0);
        }
        if (okay) okay = root_named(f, &actual) && STEP(f, same(&actual, &f->root_stat, 0));
        if (okay) okay = consume(f, &f->root);
        if (okay) okay = STEP(f, fstatat(f->parent[2], MRK_INSTALLED_ROOT_LEAF, &actual, AT_SYMLINK_NOFOLLOW) == 0)
            && STEP(f, same(&actual, &f->root_stat, 0))
            && STEP(f, unlinkat(f->parent[2], MRK_INSTALLED_ROOT_LEAF, AT_REMOVEDIR) == 0);
        if (okay && tick(f)) {
            errno = 0;
            int absent = fstatat(f->parent[2], MRK_INSTALLED_ROOT_LEAF, &actual, AT_SYMLINK_NOFOLLOW);
            int error = errno;
            if (require(f, absent == -1 && error == ENOENT) && tick(f)) f->root_retired = 1;
        }
    }
    /* Close remaining KNOWN creator originals, never an unknown participant.
     * A failure does not license unlinking even when these closes succeed. */
    for (int i = 1; i >= 0; --i) (void)consume(f, &f->leaf[i]);
    (void)consume(f, &f->root);
    for (int i = PARENTS-1; i >= 0; --i) (void)consume(f, &f->parent[i]);
}
static int emit(struct fixture *f) {
    char output[4096], live[32]; size_t used = 0;
    f->phase = OUTPUT;
    (void)tick(f);
    int passed = !f->failure && !f->close_unknown && !f->uncertain && f->root_retired
        && f->opened == EXPECTED_OPENS && f->closed == EXPECTED_OPENS;
    for (unsigned i = 0; i < FACTS; ++i) passed &= f->facts[i] == 1;
    if (!passed && !f->failure) fail_at(f, OUTPUT, f->last);
    if (f->uncertain) strcpy(live, "null");
    else (void)snprintf(live, sizeof(live), "%u", f->opened-f->closed);
#define APPEND(...) do { int n = snprintf(output+used, sizeof(output)-used, __VA_ARGS__); \
    if (n < 0 || (size_t)n >= sizeof(output)-used) { return 1; } used += (size_t)n; } while (0)
    APPEND("{\"schemaVersion\":1,\"type\":\"mrk-macos-registration-reservation-fixture-v1\","
        "\"sourceCommit\":\"%s\",\"target\":\"aarch64-apple-darwin\",\"outcome\":\"%s\",\"failure\":",
        MRK_IMAGE_SOURCE_COMMIT, passed ? "passed" : "failed");
    if (f->failure) APPEND("\"%s\"", phases[f->failure-1]); else APPEND("null");
    APPEND(",\"workTimeoutSeconds\":20,\"hardTimeoutSeconds\":22,\"facts\":{");
    for (unsigned i = 0; i < FACTS; ++i) APPEND("%s\"%s\":%s", i ? "," : "", fact_names[i], f->facts[i] ? "true" : "false");
    APPEND("},\"originals\":{\"opened\":%u,\"closedKnown\":%u,\"closeUnknown\":%s,\"liveAtReturn\":%s},"
        "\"rootCreated\":%s,\"rootRetired\":%s,\"internalAcquirePostCovered\":false,"
        "\"serviceApiEntered\":false,\"unknownNativeFaultInjected\":false,\"productionIdentityQualified\":false}\n",
        f->opened, f->closed, f->close_unknown ? "true" : "false", live,
        f->root_created ? "true" : "false", f->root_retired ? "true" : "false");
#undef APPEND
    /* The outer owner owns stdout/stderr; this original emits one bounded line
     * and never closes caller descriptors or retries a partial publication. */
    int written = write(STDOUT_FILENO, output, used) == (ssize_t)used;
    return tick(f) && written && passed ? 0 : 1;
}
int main(int argc, char **argv) {
    (void)argv;
    struct fixture f; memset(&f, 0, sizeof(f));
    f.root = -1; f.leaf[0] = f.leaf[1] = -1; f.clock_known = 1; f.phase = ENTRY;
    for (unsigned i = 0; i < PARENTS; ++i) f.parent[i] = -1;
    for (unsigned i = 0; i < SLOTS; ++i) {
        mrk_entry_init(&f.slots[i].book);
        for (unsigned j = 0; j < ORIGINALS; ++j) f.slots[i].originals[j] = -1;
    }
    if (STEP(&f, argc == 1 && getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0)
        && STEP(&f, mrk_platform() == 0) && setup(&f)) (void)controls(&f);
    finish(&f);
    return emit(&f);
}
