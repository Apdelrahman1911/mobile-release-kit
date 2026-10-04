/* Fixed PRIVATE product-image ABI, not a serialized native capability.
 * The stager must bind both compile-time projections to the same SOURCE/release.
 * No caller/argv/environment value selects an image, entrypoint or command. */
#ifndef MRK_INSTALLED_IMAGE_ABI_H
#define MRK_INSTALLED_IMAGE_ABI_H
#include <stdint.h>
#include <stddef.h>

#if !defined(__APPLE__) || !defined(__arm64__) || !defined(__LP64__)
#error "the installed image ABI requires native macOS ARM64 LP64"
#endif
#ifndef MRK_IMAGE_SOURCE_COMMIT
#error "the admitted image build must supply the exact SOURCE commit projection"
#endif
#ifndef MRK_IMAGE_RELEASE_ID
#error "the admitted image build must supply the fixed build-release projection"
#endif

enum {
    MRK_IMAGE_ABI_VERSION = 1,
    MRK_IMAGE_RESIDENT_ROLE = 2,
    MRK_IMAGE_INSTANCE_BYTES = 16,
    MRK_IMAGE_SOURCE_BYTES = 40,
    MRK_IMAGE_RELEASE_BYTES = 64,
    MRK_IMAGE_TARGET_BYTES = 24,
    MRK_IMAGE_BINDING_BYTES = 256,
    MRK_IMAGE_HOST_BYTES = 168,
    MRK_IMAGE_RETURN_BYTES = 320,
    MRK_MAINTENANCE_FRAME_BYTES = 384,
    MRK_MAINTENANCE_KIND_TAIL = 8,
    MRK_IMAGE_PRODUCT_QUIESCED = 1,
};
#define MRK_IMAGE_TARGET "aarch64-apple-darwin"
#define MRK_MAINTENANCE_WIRE_MAGIC "MRKMNT01"
#define MRK_IMAGE_WORK_NS UINT64_C(300000000000)
#define MRK_IMAGE_HARD_NS UINT64_C(310000000000)
#define MRK_IMAGE_CLEANUP_NS UINT64_C(10000000000)
#define MRK_IMAGE_MAX_RAW ((UINT64_C(1) << 61) - UINT64_C(1))

/* Contains DATA only. A copy is not BeginDrain, close, ACK or quiescence proof.
 * The private callback accepts it only from the reviewed Started native path.
 * Scalar members are native ABI values; the tail encoder is explicitly BE. */
typedef struct {
    uint32_t version;
    uint32_t bytes;
    uint8_t instance[MRK_IMAGE_INSTANCE_BYTES];
    uint8_t operation[16];
    uint8_t context_nonce[16];
    uint64_t context_number;
    uint32_t account;
    uint32_t context_slot;
    uint64_t acceptance;
    uint64_t origin;
    uint64_t work;
    uint64_t hard;
    uint64_t cut;
    uint64_t cutoff;
    uint8_t source[MRK_IMAGE_SOURCE_BYTES];
    uint8_t release[MRK_IMAGE_RELEASE_BYTES];
    uint8_t target[MRK_IMAGE_TARGET_BYTES];
    uint8_t reserved[8];
} mrk_maintenance_binding_v1;

/* Output is initialized to -1 by the live private native caller. On a possibly
 * entered/failed call it must retain any delivered original; failure NEVER
 * licenses retry, guessed close or reconstruction of the C read original.
 * C's sole callback and the later native caller both account actual returns. */
typedef int32_t (*mrk_take_tail_read_v1)(
    const mrk_maintenance_binding_v1 *binding, int32_t *read_original);

typedef struct {
    uint32_t version;
    uint32_t bytes;
    uint32_t role;
    uint32_t reserved;
    uint8_t instance[MRK_IMAGE_INSTANCE_BYTES];
    uint8_t source[MRK_IMAGE_SOURCE_BYTES];
    uint8_t release[MRK_IMAGE_RELEASE_BYTES];
    uint8_t target[MRK_IMAGE_TARGET_BYTES];
    mrk_take_tail_read_v1 take_tail_read;
} mrk_resident_host_v1;

/* Produced ONLY by consuming the real private R ProductQuiesced. The adapter
 * must include actual endpoint-receipt/close/capture/native return and Registry
 * reclamation; a boolean/frame/constructor cannot produce this owning return.
 * first==0 means no first failure; all other times are original raw uptime.
 * No Rust-owned memory, native object, FD, address or process control crosses. */
typedef struct {
    uint32_t version;
    uint32_t bytes;
    uint32_t kind;
    uint32_t reserved;
    mrk_maintenance_binding_v1 binding;
    uint64_t ceiling;
    uint64_t retirement;
    uint64_t first;
    uint64_t cutoff;
    uint64_t returned_at;
    uint64_t last;
} mrk_resident_return_v1;

typedef int32_t (*mrk_desktop_image_entry_v1_fn)(void);
typedef int32_t (*mrk_resident_image_entry_v1_fn)(
    const mrk_resident_host_v1 *, mrk_resident_return_v1 *);

_Static_assert(sizeof(MRK_IMAGE_SOURCE_COMMIT) == MRK_IMAGE_SOURCE_BYTES + 1,
    "complete literal SOURCE commit projection");
_Static_assert(sizeof(MRK_IMAGE_RELEASE_ID) > 1 && sizeof(MRK_IMAGE_RELEASE_ID) <= MRK_IMAGE_RELEASE_BYTES,
    "complete bounded literal release projection");
_Static_assert(sizeof(mrk_maintenance_binding_v1) == MRK_IMAGE_BINDING_BYTES,
    "fixed bounded binding ABI");
_Static_assert(offsetof(mrk_maintenance_binding_v1, context_number) == 56
    && offsetof(mrk_maintenance_binding_v1, acceptance) == 72
    && offsetof(mrk_maintenance_binding_v1, source) == 120
    && offsetof(mrk_maintenance_binding_v1, reserved) == 248,
    "binding ABI has no unspecified padding");
_Static_assert(sizeof(mrk_resident_host_v1) == MRK_IMAGE_HOST_BYTES
    && offsetof(mrk_resident_host_v1, take_tail_read) == 160,
    "one fixed private host callback");
_Static_assert(sizeof(mrk_resident_return_v1) == MRK_IMAGE_RETURN_BYTES
    && offsetof(mrk_resident_return_v1, binding) == 16
    && offsetof(mrk_resident_return_v1, ceiling) == 272,
    "fixed product-return ABI");
_Static_assert(sizeof(mrk_desktop_image_entry_v1_fn) == sizeof(void *)
    && sizeof(mrk_resident_image_entry_v1_fn) == sizeof(void *),
    "fixed Darwin function-pointer representation");
_Static_assert(MRK_MAINTENANCE_FRAME_BYTES <= 512, "one atomic bounded pipe write");
#endif
