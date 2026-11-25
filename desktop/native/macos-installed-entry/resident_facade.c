/* Fixed privileged resident facade. libSystem-only initial loader closure.
 * Own SH and tail pipe precede product dlopen/threads. Product image return
 * requires the REAL private R reclamation path, never an exit/status shortcut.
 * The resident image target/transport remain inactive until later integration. */
#include "gate.h"
#include "image_abi.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <errno.h>

enum { TRANSFER_FRESH = 0, TRANSFER_ENTERED = 1, TRANSFERRED = 2, TRANSFER_UNKNOWN = 3 };
enum { PRODUCT_NOT_ENTERED = 0, PRODUCT_LOAD_ENTERED = 1, PRODUCT_RETURNED_QUIESCED = 2 };
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "fixed lock-free one-shot custody");
_Static_assert(sizeof(int) == sizeof(int32_t), "fixed Darwin original descriptor width");

static struct {
    mrk_entry_book gate;
    mrk_resident_host_v1 host;
    mrk_maintenance_binding_v1 binding;
    int read_original;
    int writer_original;
    struct stat read_identity;
    struct stat writer_identity;
    uint64_t transfer_entered_at;
    unsigned write_state;
    ssize_t write_returned;
    int write_error;
    uint64_t write_returned_at;
} original;
_Static_assert(sizeof(original) <= 4096, "one bounded original facade book");
static atomic_uint transfer_state = ATOMIC_VAR_INIT(TRANSFER_FRESH);
static atomic_uint product_stage = ATOMIC_VAR_INIT(PRODUCT_NOT_ENTERED);

static _Noreturn void retain_unknown(void) {
    for (;;) {
        const struct timespec interval = {1, 0};
        (void)nanosleep(&interval, NULL);
    }
}
static uint64_t raw_now(void) {
    const uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    return now && now <= MRK_IMAGE_MAX_RAW ? now : 0;
}
static int nonzero(const uint8_t *bytes, size_t count) {
    unsigned combined = 0;
    for (size_t index = 0; index < count; ++index) combined |= bytes[index];
    return combined != 0;
}
static int all_zero(const uint8_t *bytes, size_t count) {
    return !nonzero(bytes, count);
}
static void put32(uint8_t *out, size_t at, uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) out[at + index] = (uint8_t)(value >> (24 - index * 8));
}
static void put64(uint8_t *out, size_t at, uint64_t value) {
    for (unsigned index = 0; index < 8; ++index) out[at + index] = (uint8_t)(value >> (56 - index * 8));
}
static uint64_t minimum(uint64_t left, uint64_t right) { return left < right ? left : right; }
static int fixed_identity(void) {
    static const char source[] = MRK_IMAGE_SOURCE_COMMIT;
    static const char release[] = MRK_IMAGE_RELEASE_ID;
    static const char target[] = MRK_IMAGE_TARGET;
    unsigned source_nonzero = 0;
    for (size_t index = 0; index < sizeof(source) - 1; ++index) {
        const unsigned char byte = (unsigned char)source[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) return 0;
        source_nonzero |= byte != '0';
    }
    for (size_t index = 0; index < sizeof(release) - 1; ++index) {
        const unsigned char byte = (unsigned char)release[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z')
            || (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.')) return 0;
    }
    if (!source_nonzero || sizeof(target) > sizeof(original.host.target)) return 0;
    original.host.version = MRK_IMAGE_ABI_VERSION;
    original.host.bytes = sizeof(original.host);
    original.host.role = MRK_IMAGE_RESIDENT_ROLE;
    memcpy(original.host.source, source, sizeof(source) - 1);
    memcpy(original.host.release, release, sizeof(release) - 1);
    memcpy(original.host.target, target, sizeof(target) - 1);
    arc4random_buf(original.host.instance, sizeof(original.host.instance));
    return nonzero(original.host.instance, sizeof(original.host.instance));
}
static int pipe_original_valid(int fd, int access, const struct stat *identity) {
    if (fd < 3 || !identity) return 0;
    struct stat status;
    const int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) == access && (flags & O_NONBLOCK)
        && !(flags & (O_APPEND | O_ASYNC)) && fcntl(fd, F_GETFD) == FD_CLOEXEC
        && !fstat(fd, &status) && S_ISFIFO(status.st_mode)
        && status.st_dev == identity->st_dev && status.st_ino == identity->st_ino
        && status.st_mode == identity->st_mode && status.st_uid == identity->st_uid
        && status.st_gid == identity->st_gid && status.st_nlink == identity->st_nlink
        && status.st_flags == identity->st_flags;
}
static int prepare_pipe(void) {
    int created[2] = {-1, -1};
    if (pipe(created)) return 0;
    original.read_original = created[0]; original.writer_original = created[1];
    if (created[0] < 3 || created[1] < 3 || created[0] == created[1]
        || created[0] == original.gate.gate || created[1] == original.gate.gate) return 0;
    /* This is before ANY product load/thread: pipe()+fcntl has no concurrent
     * local fork/exec inheritance window here. No Darwin pipe2 assumption. */
    for (unsigned index = 0; index < 2; ++index) {
        const int flags = fcntl(created[index], F_GETFL);
        if (flags < 0 || fcntl(created[index], F_SETFL, flags | O_NONBLOCK)
            || fcntl(created[index], F_SETFD, FD_CLOEXEC)) return 0;
    }
    if (fstat(created[0], &original.read_identity) || fstat(created[1], &original.writer_identity)) return 0;
    return pipe_original_valid(created[0], O_RDONLY, &original.read_identity)
        && pipe_original_valid(created[1], O_WRONLY, &original.writer_identity);
}
static int binding_valid(const mrk_maintenance_binding_v1 *binding, uint64_t now) {
    uint8_t nonce[16] = {0}; memcpy(nonce, "MRKACTX1", 8);
    put64(nonce, 8, binding->context_number);
    return binding->version == MRK_IMAGE_ABI_VERSION && binding->bytes == sizeof(*binding)
        && binding->context_number && binding->context_slot < 8
        && binding->account && binding->account != UINT32_MAX
        && !memcmp(binding->context_nonce, nonce, sizeof(nonce))
        && nonzero(binding->operation, sizeof(binding->operation))
        && !memcmp(binding->instance, original.host.instance, sizeof(binding->instance))
        && !memcmp(binding->source, original.host.source, sizeof(binding->source))
        && !memcmp(binding->release, original.host.release, sizeof(binding->release))
        && !memcmp(binding->target, original.host.target, sizeof(binding->target))
        && all_zero(binding->reserved, sizeof(binding->reserved))
        && binding->acceptance && binding->origin && binding->hard <= MRK_IMAGE_MAX_RAW
        && binding->origin <= MRK_IMAGE_MAX_RAW - MRK_IMAGE_HARD_NS
        && binding->work == binding->origin + MRK_IMAGE_WORK_NS
        && binding->hard == binding->origin + MRK_IMAGE_HARD_NS
        && binding->cut >= binding->acceptance && binding->cut >= binding->origin
        && binding->cut < binding->work && binding->cut < binding->cutoff
        && binding->cutoff <= binding->hard
        && binding->cutoff <= binding->cut + MRK_IMAGE_CLEANUP_NS
        && now >= binding->cut && now < binding->cutoff;
}
static int32_t take_tail_read(const mrk_maintenance_binding_v1 *binding, int32_t *out) {
    unsigned expected = TRANSFER_FRESH;
    if (!atomic_compare_exchange_strong_explicit(&transfer_state, &expected, TRANSFER_ENTERED,
            memory_order_acq_rel, memory_order_acquire)) {
        atomic_store_explicit(&transfer_state, TRANSFER_UNKNOWN, memory_order_release);
        return -1;
    }
    /* No stable NSXPC server pthread is invented. This sole fixed private
     * caller supplies disjoint LIVE POD/output storage and accounts actual
     * invocation return. Duplicates never touch that storage or a spent FD. */
    const uint64_t now = raw_now();
    if (atomic_load_explicit(&product_stage, memory_order_acquire) != PRODUCT_LOAD_ENTERED
        || !binding || !out || *out != -1 || !now || !binding_valid(binding, now)
        || !pipe_original_valid(original.read_original, O_RDONLY, &original.read_identity)) {
        atomic_store_explicit(&transfer_state, TRANSFER_UNKNOWN, memory_order_release);
        return -1;
    }
    original.binding = *binding;
    original.transfer_entered_at = now;
    const int delivered = original.read_original;
    original.read_original = -1; /* Spend BEFORE this exact private handoff. */
    *out = delivered;
    expected = TRANSFER_ENTERED;
    if (!atomic_compare_exchange_strong_explicit(&transfer_state, &expected, TRANSFERRED,
            memory_order_release, memory_order_relaxed)) {
        /* The caller must retain the possibly delivered original on failure.
         * Never close, reacquire, duplicate or retry this uncertain transfer. */
        return -1;
    }
    return 0;
}
static int return_valid(const mrk_resident_return_v1 *returned) {
    if (returned->version != MRK_IMAGE_ABI_VERSION || returned->bytes != sizeof(*returned)
        || returned->kind != MRK_IMAGE_PRODUCT_QUIESCED || returned->reserved
        || memcmp(&returned->binding, &original.binding, sizeof(original.binding))
        || returned->ceiling != original.binding.hard
        || returned->retirement != original.binding.cut
        || returned->returned_at > MRK_IMAGE_MAX_RAW
        || returned->returned_at < original.transfer_entered_at
        || returned->last < original.binding.cut || returned->last > returned->returned_at
        || (returned->first && (returned->first < original.binding.acceptance
            || returned->first > returned->returned_at))) return 0;
    uint64_t cutoff = minimum(returned->ceiling, returned->retirement + MRK_IMAGE_CLEANUP_NS);
    if (returned->first) cutoff = minimum(cutoff, returned->first + MRK_IMAGE_CLEANUP_NS);
    return cutoff == returned->cutoff && cutoff <= original.binding.cutoff
        && returned->returned_at < cutoff;
}
static void encode_tail(uint8_t frame[MRK_MAINTENANCE_FRAME_BYTES],
    const mrk_resident_return_v1 *returned, uint64_t write_entered_at) {
    const mrk_maintenance_binding_v1 *binding = &returned->binding;
    memset(frame, 0, MRK_MAINTENANCE_FRAME_BYTES);
    memcpy(frame, MRK_MAINTENANCE_WIRE_MAGIC, 8);
    put32(frame, 8, MRK_IMAGE_ABI_VERSION);
    put32(frame, 12, MRK_MAINTENANCE_KIND_TAIL);
    put32(frame, 16, MRK_MAINTENANCE_FRAME_BYTES);
    /* Explicit canonical BE fields, never memcpy of a native C struct. */
    put32(frame, 24, binding->version); put32(frame, 28, binding->bytes);
    memcpy(frame + 32, binding->instance, 16);
    memcpy(frame + 48, binding->operation, 16);
    memcpy(frame + 64, binding->context_nonce, 16);
    put64(frame, 80, binding->context_number);
    put32(frame, 88, binding->account); put32(frame, 92, binding->context_slot);
    put64(frame, 96, binding->acceptance); put64(frame, 104, binding->origin);
    put64(frame, 112, binding->work); put64(frame, 120, binding->hard);
    put64(frame, 128, binding->cut); put64(frame, 136, binding->cutoff);
    memcpy(frame + 144, binding->source, 40);
    memcpy(frame + 184, binding->release, 64);
    memcpy(frame + 248, binding->target, 24);
    put64(frame, 280, returned->ceiling); put64(frame, 288, returned->retirement);
    put64(frame, 296, returned->first); put64(frame, 304, returned->cutoff);
    put64(frame, 312, returned->returned_at); put64(frame, 320, returned->last);
    put64(frame, 328, write_entered_at);
    /* 20..24, 272..280 and 336..384 remain zero. The observed write ENTRY time
     * is not a claim that write already returned or that the process exited. */
}
static _Noreturn void park_settled_until_cutoff(uint64_t cutoff, uint64_t last) {
    /* Entered ONLY after actual private product return and validated owning
     * output. Deadline cannot be used to end unknown product originals. */
    for (;;) {
        const uint64_t now = raw_now();
        if (!now || now < last) retain_unknown();
        if (now >= cutoff) _exit(74); /* Failure endpoint, not a success receipt. */
        last = now;
        const struct timespec interval = {0, 2000000};
        (void)nanosleep(&interval, NULL);
    }
}
int main(int argc, char **argv) {
    (void)argv;
    original.read_original = -1; original.writer_original = -1;
    char own[PATH_MAX]; uint32_t own_size = sizeof(own);
    if (argc != 1 || pthread_main_np() != 1 || getpid() <= 1
        || getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0 || issetugid()
        || mrk_platform() || _NSGetExecutablePath(own, &own_size)
        || strcmp(own, MRK_RESIDENT_EXECUTABLE)) _exit(64);
    mrk_entry_init(&original.gate);
    if (!mrk_entry_root(&original.gate) || !mrk_entry_open_gate(&original.gate)) _exit(65);
    if (flock(original.gate.gate, LOCK_SH | LOCK_NB)) _exit(66);
    if (!mrk_entry_gate_matches(&original.gate, FD_CLOEXEC)
        || !mrk_entry_close_ancestors(&original.gate)) _exit(67);
    if (!fixed_identity() || !prepare_pipe()) _exit(68);
    original.host.take_tail_read = take_tail_read;
    atomic_store_explicit(&product_stage, PRODUCT_LOAD_ENTERED, memory_order_release);
    void *const image = dlopen(MRK_RESIDENT_IMAGE, RTLD_NOW | RTLD_LOCAL);
    if (!image) retain_unknown(); /* Possible initializer entry even on NULL. */
    void *const symbol = dlsym(image, "mrk_resident_image_entry_v1");
    if (!symbol) retain_unknown();
    mrk_resident_image_entry_v1_fn entry = NULL;
    memcpy(&entry, &symbol, sizeof(entry));
    if (!entry) retain_unknown();
    mrk_resident_return_v1 returned = {0};
    const int32_t result = entry(&original.host, &returned);
    /* Only the accepted R adapter may export this after real native/capture
     * returns, sender-read close, original joins and exact Registry reclamation.
     * Acquire is memory visibility, not a replacement for that owning return. */
    if (result != 0 || atomic_load_explicit(&transfer_state, memory_order_acquire) != TRANSFERRED
        || original.read_original != -1 || !return_valid(&returned)) retain_unknown();
    atomic_store_explicit(&product_stage, PRODUCT_RETURNED_QUIESCED, memory_order_release);
    const uint64_t now = raw_now();
    if (!now || now < returned.returned_at) retain_unknown();
    if (now >= returned.cutoff) park_settled_until_cutoff(returned.cutoff, now);
    sigset_t blocked;
    if (sigemptyset(&blocked) || sigaddset(&blocked, SIGPIPE)
        || pthread_sigmask(SIG_BLOCK, &blocked, NULL)
        || !pipe_original_valid(original.writer_original, O_WRONLY, &original.writer_identity))
        park_settled_until_cutoff(returned.cutoff, now);
    const uint64_t write_entered = raw_now();
    if (!write_entered || write_entered < now) retain_unknown();
    if (write_entered >= returned.cutoff) park_settled_until_cutoff(returned.cutoff, write_entered);
    uint8_t frame[MRK_MAINTENANCE_FRAME_BYTES];
    encode_tail(frame, &returned, write_entered);
    original.write_state = 1; errno = 0;
    const ssize_t written = write(original.writer_original, frame, sizeof(frame));
    const int actual_errno = errno;
    original.write_returned = written;
    original.write_error = written < 0 ? actual_errno : 0;
    original.write_returned_at = raw_now();
    /* Exactly one nonblocking atomic-size attempt; no partial/EINTR retry.
     * The client requires its complete bound frame and later original EOF/exit.
     * A short/error return is FAILED, not an implicit successful frame. */
    if (!original.write_returned_at || original.write_returned_at < write_entered) retain_unknown();
    original.write_state = written == (ssize_t)sizeof(frame) && original.write_returned_at < returned.cutoff ? 2 : 3;
    /* Both complete and failed attempts keep SH/writer until kernel exit. */
    park_settled_until_cutoff(returned.cutoff, original.write_returned_at);
}
