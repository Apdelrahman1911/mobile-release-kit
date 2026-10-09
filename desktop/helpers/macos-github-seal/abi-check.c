/* Compile ONLY against the same target SDK and admitted official 1.0.22
 * headers. Do not link this translation unit into the helper or run it. */
#include <limits.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sodium.h>

#if !defined(__APPLE__) || !defined(__MACH__) || !defined(__LP64__) || \
    !(defined(__aarch64__) || defined(__x86_64__))
#error "Only reviewed 64-bit Apple Darwin ABIs are supported"
#endif
#if SODIUM_LIBRARY_VERSION_MAJOR != 26 || SODIUM_LIBRARY_VERSION_MINOR != 4
#error "The admitted libsodium 1.0.22 ABI headers are required"
#endif
_Static_assert(CHAR_BIT == 8, "byte width");
_Static_assert(sizeof(int) == 4, "C int width");
_Static_assert(sizeof(unsigned long long) == 8, "C unsigned long long width");
_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8, "Darwin64 size/pointer width");
_Static_assert(crypto_box_PUBLICKEYBYTES == 32 && crypto_box_SEALBYTES == 48, "sealed box sizes");
_Static_assert(sizeof(rlim_t) == 8 && (rlim_t)-1 > 0, "Darwin unsigned rlim_t");
_Static_assert(sizeof(struct rlimit) == 16 && _Alignof(struct rlimit) == 8, "Darwin rlimit layout");
_Static_assert(offsetof(struct rlimit, rlim_cur) == 0 && offsetof(struct rlimit, rlim_max) == 8, "Darwin rlimit fields");
_Static_assert(RLIMIT_CPU == 0 && RLIMIT_FSIZE == 1 && RLIMIT_CORE == 4 && RLIMIT_NOFILE == 8, "Darwin resource selectors");
_Static_assert(F_GETFD == 1, "Darwin descriptor query");

static void __attribute__((unused)) mrk_fixed_abi_declarations(void)
{
    int (*init)(void) = sodium_init;
    int (*seal)(unsigned char *, const unsigned char *, unsigned long long, const unsigned char *) = crypto_box_seal;
    void (*wipe)(void *, size_t) = sodium_memzero;
    int (*random_close)(void) = randombytes_close;
    int (*get_limit)(int, struct rlimit *) = getrlimit;
    int (*set_limit)(int, const struct rlimit *) = setrlimit;
    int (*descriptor_flags)(int, int, ...) = fcntl;
    int (*consume_close)(int) = close;
    (void)init; (void)seal; (void)wipe; (void)random_close;
    (void)get_limit; (void)set_limit; (void)descriptor_flags; (void)consume_close;
}
