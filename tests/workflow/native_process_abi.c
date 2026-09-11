/*
 * Test-only public-header/API reference for the reviewed disposable CI owner.
 * Never compile at library import/runtime or ship this as an extension.  This
 * program creates no child, waits for nobody, changes no signal disposition,
 * and only closes descriptors returned by its own successful acquisitions.
 * File actions are constructed and destroyed, NEVER executed.
 *
 * The single bounded JSON line is a header observation, not a wait/EOF/domain
 * receipt or proof that either language's FFI call is correct.  Those require
 * separate completed owner captures and actual no-child language API controls.
 */
#if defined(__linux__)
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1
# endif
#elif defined(__APPLE__) && defined(__MACH__)
# ifndef _DARWIN_C_SOURCE
#  define _DARWIN_C_SOURCE 1
# endif
#else
# error "unsupported native-process ABI platform"
#endif

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
# if !defined(__GLIBC__)
#  error "native-process ABI requires public glibc interfaces on Linux"
# elif !__GLIBC_PREREQ(2, 34)
#  error "native-process ABI requires glibc closefrom file actions"
# endif
# define ABI_FAMILY "linux-glibc"
#else
# define ABI_FAMILY "darwin"
_Static_assert(_Generic((posix_spawn_file_actions_t)0, void *: 1, default: 0),
               "Darwin file actions must be a public pointer slot");
_Static_assert(_Generic((posix_spawnattr_t)0, void *: 1, default: 0),
               "Darwin attributes must be a public pointer slot");
#endif

#if defined(__x86_64__)
# define ABI_ARCHITECTURE "x86_64"
#elif defined(__aarch64__) || defined(__arm64__)
# define ABI_ARCHITECTURE "arm64"
#else
# error "unsupported native-process ABI architecture"
#endif

_Static_assert(CHAR_BIT == 8, "native-process ABI requires eight-bit bytes");
_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8,
               "native-process ABI requires LP64");
_Static_assert(sizeof(int) == 4 && sizeof(short) == 2,
               "unsupported native-process integer widths");
_Static_assert(sizeof(pid_t) == 4 && (pid_t)-1 < (pid_t)0,
               "native-process ABI requires signed four-byte pid_t");

/* Only the hosted FIFO-delay fixtures bind addopen/addclose.  Match their
 * unsigned fixed mode argument, without adding production ABI JSON fields. */
#if defined(__linux__)
_Static_assert(sizeof(mode_t) == 4 && _Generic((mode_t)0, unsigned int: 1, default: 0),
               "FIFO fixture requires Linux unsigned-int mode_t");
#else
_Static_assert(sizeof(mode_t) == 2 && _Generic((mode_t)0, unsigned short: 1, default: 0),
               "FIFO fixture requires Darwin unsigned-short mode_t");
#endif

/* These checks have no calls, including the posix_spawn check.  In particular,
 * fcntl is the true variadic prototype, NOT a three-fixed-int approximation. */
typedef int (*fcntl_signature)(int, int, ...);
typedef int (*close_signature)(int);
typedef int (*sigaction_signature)(int, const struct sigaction *, struct sigaction *);
typedef int (*spawn_signature)(pid_t *, const char *,
                               const posix_spawn_file_actions_t *,
                               const posix_spawnattr_t *, char *const *, char *const *);
typedef int (*actions_signature)(posix_spawn_file_actions_t *);
typedef int (*dup2_signature)(posix_spawn_file_actions_t *, int, int);
typedef int (*addopen_signature)(posix_spawn_file_actions_t *, int, const char *, int, mode_t);
typedef int (*addclose_signature)(posix_spawn_file_actions_t *, int);
#define CHECK_SIGNATURE(name, signature) \
    _Static_assert(_Generic(&(name), signature: 1, default: 0), \
                   "unsupported public " #name " prototype")
CHECK_SIGNATURE(fcntl, fcntl_signature);
CHECK_SIGNATURE(close, close_signature);
CHECK_SIGNATURE(sigaction, sigaction_signature);
CHECK_SIGNATURE(posix_spawn, spawn_signature);
CHECK_SIGNATURE(posix_spawn_file_actions_init, actions_signature);
CHECK_SIGNATURE(posix_spawn_file_actions_destroy, actions_signature);
CHECK_SIGNATURE(posix_spawn_file_actions_adddup2, dup2_signature);
CHECK_SIGNATURE(posix_spawn_file_actions_addopen, addopen_signature);
CHECK_SIGNATURE(posix_spawn_file_actions_addclose, addclose_signature);
#if defined(__linux__)
typedef int (*closefrom_signature)(posix_spawn_file_actions_t *, int);
CHECK_SIGNATURE(posix_spawn_file_actions_addclosefrom_np, closefrom_signature);
#else
typedef int (*attributes_signature)(posix_spawnattr_t *);
typedef int (*setflags_signature)(posix_spawnattr_t *, short);
typedef int (*getflags_signature)(const posix_spawnattr_t *, short *);
CHECK_SIGNATURE(posix_spawnattr_init, attributes_signature);
CHECK_SIGNATURE(posix_spawnattr_destroy, attributes_signature);
CHECK_SIGNATURE(posix_spawnattr_setflags, setflags_signature);
CHECK_SIGNATURE(posix_spawnattr_getflags, getflags_signature);
#endif

static int close_once(int *slot)
{
    int descriptor = *slot;
    *slot = -1;                 /* Retire before the one potentially closing call. */
    return descriptor < 0 ? 0 : close(descriptor);
}

static int public_api_control(void)
{
    /* Keep the real public spawn symbol referenced without invoking it. */
    spawn_signature volatile spawn_symbol = &posix_spawn;
    struct sigaction before, after;
    posix_spawn_file_actions_t actions;
    int descriptors[6] = {-1, -1, -1, -1, -1, -1};
    int source_flags[3], source_status[3];
    const int modes[3] = {O_RDONLY, O_WRONLY, O_RDWR};
    int pair[2], actions_initialized = 0, failed = 1;
#if !defined(__linux__)
    posix_spawnattr_t attributes = NULL;
    int attributes_initialized = 0;
    short flags = 0;
#endif

    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    memset(&actions, 0, sizeof(actions));
    if (spawn_symbol == NULL || sigaction(SIGCHLD, NULL, &before) != 0 ||
        before.sa_handler == SIG_IGN || (before.sa_flags & SA_NOCLDWAIT) != 0)
        return 1;

    /* A pipe supplies different source modes and initially non-CLOEXEC flags.
     * There are no other threads or descendants in this reference program. */
    if (pipe(pair) != 0)
        goto cleanup;
    descriptors[0] = pair[0];
    descriptors[1] = pair[1];
    descriptors[2] = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (descriptors[2] < 0)
        goto cleanup;

    for (int index = 0; index < 3; ++index) {
        source_flags[index] = fcntl(descriptors[index], F_GETFD);
        source_status[index] = fcntl(descriptors[index], F_GETFL);
        if (source_flags[index] < 0 || source_status[index] < 0 ||
            (source_status[index] & O_ACCMODE) != modes[index])
            goto cleanup;
        /* The third argument is a promoted C int through the public varargs ABI. */
        int duplicate = fcntl(descriptors[index], F_DUPFD_CLOEXEC, 8);
        if (duplicate < 8)
            goto cleanup;
        for (int owned = 0; owned < 6; ++owned) {
            if (duplicate == descriptors[owned])
                goto cleanup; /* Never close an unproved/aliased returned number. */
        }
        descriptors[index + 3] = duplicate;
        int duplicate_flags = fcntl(duplicate, F_GETFD);
        int duplicate_status = fcntl(duplicate, F_GETFL);
        if (duplicate_flags < 0 || duplicate_status < 0 ||
            (duplicate_flags & FD_CLOEXEC) != FD_CLOEXEC ||
            (duplicate_status & O_ACCMODE) != modes[index])
            goto cleanup;
    }

    /* POSIX spawn action/attribute APIs return an error number, not errno. */
    if (posix_spawn_file_actions_init(&actions) != 0)
        goto cleanup;
    actions_initialized = 1;
    for (int index = 0; index < 3; ++index) {
        if (posix_spawn_file_actions_adddup2(&actions, descriptors[index + 3], index) != 0)
            goto cleanup;
    }
#if defined(__linux__)
    if (posix_spawn_file_actions_addclosefrom_np(&actions, 8) != 0)
        goto cleanup;
#else
    if (posix_spawnattr_init(&attributes) != 0)
        goto cleanup;
    attributes_initialized = 1;
    if (posix_spawnattr_setflags(&attributes, (short)POSIX_SPAWN_CLOEXEC_DEFAULT) != 0 ||
        posix_spawnattr_getflags(&attributes, &flags) != 0 ||
        flags != (short)POSIX_SPAWN_CLOEXEC_DEFAULT)
        goto cleanup;
#endif
    for (int index = 0; index < 3; ++index) {
        if (fcntl(descriptors[index], F_GETFD) != source_flags[index] ||
            fcntl(descriptors[index], F_GETFL) != source_status[index])
            goto cleanup;
    }
    failed = 0;

cleanup:
#if !defined(__linux__)
    if (attributes_initialized) {
        attributes_initialized = 0;
        if (posix_spawnattr_destroy(&attributes) != 0)
            failed = 1;
    }
#endif
    if (actions_initialized) {
        actions_initialized = 0;
        if (posix_spawn_file_actions_destroy(&actions) != 0)
            failed = 1;
    }
    for (int index = 5; index >= 0; --index) {
        if (close_once(&descriptors[index]) != 0)
            failed = 1;        /* No EINTR retry against a possibly reused FD. */
    }
    if (failed || sigaction(SIGCHLD, NULL, &after) != 0 ||
        before.sa_handler != after.sa_handler || before.sa_flags != after.sa_flags)
        return 1;
    /* Compare public signal membership, not uninitialized sigset padding. */
    for (int number = 1; number < NSIG; ++number) {
        int old_member = sigismember(&before.sa_mask, number);
        int new_member = sigismember(&after.sa_mask, number);
        if (old_member < 0 || new_member < 0 || old_member != new_member)
            return 1;
    }
    return 0;
}

struct record {
    char bytes[8193];           /* Maximum 8192 output bytes, including final LF. */
    size_t used;
    int failed;
};

static void append(struct record *, const char *, ...) __attribute__((format(printf, 2, 3)));
static void append(struct record *record, const char *format, ...)
{
    if (record->failed)
        return;
    va_list arguments;
    va_start(arguments, format);
    size_t remaining = sizeof(record->bytes) - record->used;
    int length = vsnprintf(record->bytes + record->used, remaining, format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= remaining) {
        record->failed = 1;
        return;
    }
    record->used += (size_t)length;
}

#define SIZE_ALIGN(type) sizeof(type), _Alignof(type)
#define FIELD(type, member) offsetof(type, member), sizeof(((type *)0)->member)

static int report_headers(void)
{
    struct record record = {{0}, 0, 0};
    append(&record, "{\"schema\":\"mrk-native-process-abi-v1\",\"family\":\"%s\","
           "\"architecture\":\"%s\",\"byteorder\":\"little\",\"scalars\":{"
           "\"pointer\":{\"size\":%zu,\"align\":%zu},"
           "\"int\":{\"size\":%zu,\"align\":%zu},"
           "\"short\":{\"size\":%zu,\"align\":%zu},"
           "\"long\":{\"size\":%zu,\"align\":%zu},"
           "\"pid_t\":{\"size\":%zu,\"align\":%zu,\"signed\":%s}},",
           ABI_FAMILY, ABI_ARCHITECTURE, SIZE_ALIGN(void *), SIZE_ALIGN(int),
           SIZE_ALIGN(short), SIZE_ALIGN(long), SIZE_ALIGN(pid_t),
           (pid_t)-1 < (pid_t)0 ? "true" : "false");
    append(&record, "\"sigaction\":{\"size\":%zu,\"align\":%zu,\"fields\":{"
           "\"handler\":{\"offset\":%zu,\"size\":%zu},"
           "\"mask\":{\"offset\":%zu,\"size\":%zu},"
           "\"flags\":{\"offset\":%zu,\"size\":%zu},\"restorer\":",
           SIZE_ALIGN(struct sigaction), FIELD(struct sigaction, sa_handler),
           FIELD(struct sigaction, sa_mask), FIELD(struct sigaction, sa_flags));
#if defined(__linux__)
    append(&record, "{\"offset\":%zu,\"size\":%zu}}},"
           "\"file_actions\":{\"kind\":\"struct\",\"size\":%zu,\"align\":%zu,\"fields\":{"
           "\"allocated\":{\"offset\":%zu,\"size\":%zu},"
           "\"used\":{\"offset\":%zu,\"size\":%zu},"
           "\"actions\":{\"offset\":%zu,\"size\":%zu},"
           "\"pad\":{\"offset\":%zu,\"size\":%zu}}},\"spawn_attributes\":null,",
           FIELD(struct sigaction, sa_restorer), SIZE_ALIGN(posix_spawn_file_actions_t),
           FIELD(posix_spawn_file_actions_t, __allocated),
           FIELD(posix_spawn_file_actions_t, __used),
           FIELD(posix_spawn_file_actions_t, __actions),
           FIELD(posix_spawn_file_actions_t, __pad));
#else
    append(&record, "null}},\"file_actions\":{\"kind\":\"pointer_slot\","
           "\"size\":%zu,\"align\":%zu,\"fields\":{}},"
           "\"spawn_attributes\":{\"kind\":\"pointer_slot\","
           "\"size\":%zu,\"align\":%zu,\"fields\":{}},",
           SIZE_ALIGN(posix_spawn_file_actions_t), SIZE_ALIGN(posix_spawnattr_t));
#endif
    append(&record, "\"constants\":{\"SIG_IGN\":%" PRIuPTR ",\"SA_NOCLDWAIT\":%d,"
           "\"SIGCHLD\":%d,\"NSIG\":%d,\"F_DUPFD_CLOEXEC\":%d,\"F_GETFD\":%d,"
           "\"F_GETFL\":%d,\"FD_CLOEXEC\":%d,\"O_RDONLY\":%d,\"O_WRONLY\":%d,"
           "\"O_RDWR\":%d,\"O_ACCMODE\":%d,\"POSIX_SPAWN_CLOEXEC_DEFAULT\":",
           (uintptr_t)SIG_IGN, (int)SA_NOCLDWAIT, (int)SIGCHLD, (int)NSIG,
           (int)F_DUPFD_CLOEXEC, (int)F_GETFD, (int)F_GETFL, (int)FD_CLOEXEC,
           (int)O_RDONLY, (int)O_WRONLY, (int)O_RDWR, (int)O_ACCMODE);
#if defined(__linux__)
    append(&record, "null},");
#else
    append(&record, "%d},", (int)POSIX_SPAWN_CLOEXEC_DEFAULT);
#endif
    /* Signature strings describe the independently checked public prototypes.
     * Python/Ruby exports must describe their actual FFI declaration sources. */
    append(&record, "\"functions\":{"
           "\"fcntl\":{\"return\":\"int\",\"args\":[\"int\",\"int\"],\"variadic\":true},"
           "\"close\":{\"return\":\"int\",\"args\":[\"int\"],\"variadic\":false},"
           "\"sigaction\":{\"return\":\"int\",\"args\":[\"int\",\"pointer\",\"pointer\"],\"variadic\":false},"
           "\"posix_spawn\":{\"return\":\"int\",\"args\":[\"pointer\",\"pointer\",\"pointer\","
           "\"pointer\",\"pointer\",\"pointer\"],\"variadic\":false},"
           "\"posix_spawn_file_actions_init\":{\"return\":\"int\",\"args\":[\"pointer\"],\"variadic\":false},"
           "\"posix_spawn_file_actions_destroy\":{\"return\":\"int\",\"args\":[\"pointer\"],\"variadic\":false},"
           "\"posix_spawn_file_actions_adddup2\":{\"return\":\"int\",\"args\":[\"pointer\",\"int\",\"int\"],\"variadic\":false},"
           "\"posix_spawn_file_actions_addclosefrom_np\":");
#if defined(__linux__)
    append(&record, "{\"return\":\"int\",\"args\":[\"pointer\",\"int\"],\"variadic\":false},"
           "\"posix_spawnattr_init\":null,\"posix_spawnattr_destroy\":null,"
           "\"posix_spawnattr_setflags\":null,\"posix_spawnattr_getflags\":null");
#else
    append(&record, "null,"
           "\"posix_spawnattr_init\":{\"return\":\"int\",\"args\":[\"pointer\"],\"variadic\":false},"
           "\"posix_spawnattr_destroy\":{\"return\":\"int\",\"args\":[\"pointer\"],\"variadic\":false},"
           "\"posix_spawnattr_setflags\":{\"return\":\"int\",\"args\":[\"pointer\",\"short\"],\"variadic\":false},"
           "\"posix_spawnattr_getflags\":{\"return\":\"int\",\"args\":[\"pointer\",\"pointer\"],\"variadic\":false}");
#endif
    append(&record, "}}\n");
    if (record.failed)
        return 1;
    int failed = fwrite(record.bytes, 1, record.used, stdout) != record.used;
    if (fclose(stdout) != 0)
        failed = 1;
    return failed;
}

int main(void)
{
    const uint16_t endian = 1;
    if (*(const unsigned char *)&endian != 1 || public_api_control() != 0)
        return 1;
    return report_headers();
}
