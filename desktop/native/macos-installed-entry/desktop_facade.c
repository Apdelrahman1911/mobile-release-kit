/* Ordinary installed process: C/libSystem only until its OWN actual SH.
 * entry.c still owns the inherited SH. Both originals remain until kernel exit.
 * No new app lifecycle, maintenance permission or returning observer loop. */
#include "gate.h"
#include "image_abi.h"
#include <sys/file.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <limits.h>

enum { PRODUCT_NOT_ENTERED = 0, PRODUCT_LOAD_ENTERED = 1 };
static atomic_uint product_stage = ATOMIC_VAR_INIT(PRODUCT_NOT_ENTERED);
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "fixed lock-free startup latch");

static _Noreturn void retain_unknown(void) {
    /* No dlclose, signal, gate close/unlock or hidden forced-exit deadline. */
    for (;;) {
        const struct timespec interval = {1, 0};
        (void)nanosleep(&interval, NULL);
    }
}
static int canonical_positive(const char *text, int minimum, int *out) {
    if (!text || !out || text[0] < '1' || text[0] > '9') return 0;
    unsigned value = 0;
    for (unsigned index = 0; index < 10; ++index) {
        const unsigned char byte = (unsigned char)text[index];
        if (!byte) {
            if (value < (unsigned)minimum) return 0;
            *out = (int)value; return 1;
        }
        if (byte < '0' || byte > '9' || value > ((unsigned)INT_MAX - (byte - '0')) / 10) return 0;
        value = value * 10 + (byte - '0');
    }
    if (text[10] || value < (unsigned)minimum) return 0;
    *out = (int)value; return 1;
}
int main(int argc, char **argv) {
    uint32_t uid = 0; int inherited = -1, process = 0;
    char own[PATH_MAX]; uint32_t own_size = sizeof(own);
    if (pthread_main_np() != 1 || argc != 4 || !argv || !argv[1] || !argv[2] || !argv[3]
        || mrk_user(&uid) || _NSGetExecutablePath(own, &own_size)
        || strcmp(own, MRK_PAYLOAD_EXECUTABLE)
        || strcmp(argv[1], MRK_INSTALLED_ENTRY_ARGUMENT)
        || !canonical_positive(argv[2], 3, &inherited)
        || !canonical_positive(argv[3], 2, &process)
        || mrk_installed_entry_admit(inherited, process)) _exit(64);
    /* The inherited metadata admission is deliberately NOT flock proof.
     * Obtain a distinct validated original and perform the actual SH here. */
    mrk_entry_book gate; mrk_entry_init(&gate);
    if (!mrk_entry_root(&gate) || !mrk_entry_open_gate(&gate)) _exit(65);
    if (flock(gate.gate, LOCK_SH | LOCK_NB)) _exit(66);
    if (!mrk_entry_gate_matches(&gate, FD_CLOEXEC)
        || !mrk_entry_close_ancestors(&gate)) _exit(67);

    /* A returned NULL may follow partial initializer entry. Latch BEFORE load;
     * every following failure retains possible product custody and both SHs. */
    atomic_store_explicit(&product_stage, PRODUCT_LOAD_ENTERED, memory_order_release);
    void *const image = dlopen(MRK_DESKTOP_IMAGE, RTLD_NOW | RTLD_LOCAL);
    if (!image) retain_unknown();
    void *const symbol = dlsym(image, "mrk_desktop_image_entry_v1");
    if (!symbol) retain_unknown();
    mrk_desktop_image_entry_v1_fn entry = NULL;
    memcpy(&entry, &symbol, sizeof(entry));
    if (!entry) retain_unknown();
    (void)entry();
    /* Normal App::run performs its existing owned shutdown/exit. An unexpected
     * return or initialization failure is NOT a new quiescence/exit permit. */
    retain_unknown();
}
