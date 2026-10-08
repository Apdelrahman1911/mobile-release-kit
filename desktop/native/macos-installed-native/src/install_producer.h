#ifndef MRK_INSTALL_PRODUCER_H
#define MRK_INSTALL_PRODUCER_H
#include <stddef.h>
#include <stdint.h>

#ifndef MRK_INSTALL_PRODUCER_SIGNING
#define MRK_INSTALL_PRODUCER_SIGNING 0
#endif
#if MRK_INSTALL_PRODUCER_SIGNING != 0 && MRK_INSTALL_PRODUCER_SIGNING != 1
#error package signing is a closed nonshipping build selection
#endif

enum { MRK_INSTALL_PRODUCER_SLOTS=26, MRK_INSTALL_PRODUCER_STEPS=29,
    MRK_INSTALL_PRODUCER_RELEASE=64, MRK_INSTALL_PRODUCER_DESCRIPTOR_MAX=65536,
    MRK_INSTALL_PRODUCER_CERTIFICATE_MAX=16384, MRK_INSTALL_PRODUCER_CELL_MAX=131072,
    MRK_INSTALL_PRODUCER_PATH_MAX=1024, MRK_INSTALL_PRODUCER_CODE_STEPS=8,
    MRK_INSTALL_PRODUCER_CODE_SLOTS=6, MRK_INSTALL_PRODUCER_CODE_STACK_MAX=8192,
    MRK_INSTALL_PRODUCER_SIGN_STEPS=12, MRK_INSTALL_PRODUCER_SIGN_SLOTS=14,
    MRK_REMOVE_PRODUCER_DESCRIPTOR_MAX=16384 };
typedef struct {
    uint32_t version,phase,calls,returned,matched,failed,unknown,reserved;
    uint32_t states[MRK_INSTALL_PRODUCER_SLOTS];
} mrk_install_producer_report;
typedef struct {
    uint32_t version,rsa_bits;
    uint8_t team[10],leaf_sha1[20],leaf_sha256[32],public_key_pkcs1_sha256[32];
} mrk_install_producer_signer;

// SOURCE selection only. This is neither certificate-purpose authentication nor
// permission to consume descriptor releases. No runtime path/key is accepted.
int mrk_install_producer_source(mrk_install_producer_signer *out);
int mrk_install_producer_source_leaf_matches(const uint8_t *der,size_t size);
void *mrk_install_producer_new(const uint8_t *descriptor,size_t descriptor_size,
    const uint8_t *signature,size_t signature_size);
// role is fixed 1(entry App) or 2(payload App), not a runtime policy/identifier.
// Borrowed original directory descriptors are never opened/duped/closed here.
void *mrk_install_producer_code_new(uint32_t role,int outer,int code,
    const uint8_t *outer_path,size_t path_size);
// Separate fixed Remove-v1 constructors; no caller-selected domain/identifier.
void *mrk_remove_producer_new(const uint8_t *descriptor,size_t size,const uint8_t *signature,size_t signature_size);
// Borrowed source-owned directory and regular mrk-macos-remove, not App roles.
void *mrk_remove_producer_code_new(int directory,int program,const uint8_t *path,size_t size);
int mrk_install_producer_step(void *raw,uint32_t phase,mrk_install_producer_report *out);
int mrk_install_producer_release(void *raw,uint32_t slot,mrk_install_producer_report *out);
int mrk_install_producer_retire(void *raw);
#if MRK_INSTALL_PRODUCER_SIGNING
// Explicit packaging example only; no private key or arbitrary identity input.
void *mrk_install_producer_sign_new(const uint8_t *descriptor,size_t size);
void *mrk_remove_producer_sign_new(const uint8_t *descriptor,size_t size);
int mrk_install_producer_sign_copy(void *raw,uint8_t *out,size_t capacity,size_t *size);
#endif
#endif
