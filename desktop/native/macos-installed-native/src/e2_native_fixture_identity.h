/* Nonshipping E2 fixture only. No runtime path, requirement or identity fallback. */
#ifndef MRK_E2_NATIVE_FIXTURE_IDENTITY_H
#define MRK_E2_NATIVE_FIXTURE_IDENTITY_H
#if !defined(MRK_E2_NATIVE_FIXTURE) || MRK_E2_NATIVE_FIXTURE != 1
#error explicit nonshipping E2 fixture graph required
#endif
#include <stdint.h>
#include <stddef.h>
#include <CoreFoundation/CoreFoundation.h>
#define MRK_E2_IDENTITY_PROJECT_MAX 24576u
#define MRK_E2_IDENTITY_FDS 28u
#define MRK_E2_IDENTITY_CFS 12u
/* Callback context is borrowed for this one synchronous C call only.
 * edge: before0/actual-return1; outcome: success0/failure1/unknown2.
 * return: stop0/proceed1/unknown2. No callback/context is retained. */
typedef uint32_t (*mrk_e2_fixture_point)(void *,uint32_t,uint32_t,uint32_t,uint64_t,uint32_t);
typedef struct { void *context;mrk_e2_fixture_point point; } mrk_e2_fixture_checkpoint_api;
typedef struct {
    uint32_t version,bytes,role,allocated,allocation_entered,allocation_returned,consumed;
    uint32_t ready,failed,unknown,in_call,calls,returns,phase,borrow_count;
    uint32_t pool,acl_frame,acl_generation,acl_resources[3];
    uint32_t fds[MRK_E2_IDENTITY_FDS],cf[MRK_E2_IDENTITY_CFS];
    uint32_t recheck_epoch,spent_epoch,reserved;
    uint64_t last_ns,first_ns;
} mrk_e2_fixture_identity_facts;
_Static_assert(sizeof(mrk_e2_fixture_identity_facts)==272u,"fixed E2 identity DATA ABI");
enum {
    MRK_E2_ID_ALLOCATE=1,MRK_E2_ID_POOL_ALLOCATE=2,MRK_E2_ID_POOL_INIT=3,
    MRK_E2_ID_SOURCE_OPEN=4,MRK_E2_ID_SOURCE_READ=5,MRK_E2_ID_SOURCE_CHECK=6,
    MRK_E2_ID_ACL=7,MRK_E2_ID_SECURITY=8,MRK_E2_ID_CF_RELEASE=9,
    MRK_E2_ID_ACL_RELEASE=10,MRK_E2_ID_SOURCE_CLOSE=11,MRK_E2_ID_POOL_DRAIN=12,
    MRK_E2_ID_RETIRE=13
};
size_t mrk_e2_fixture_identity_project_bytes(void);
void *mrk_e2_fixture_main_identity_new(const mrk_e2_fixture_checkpoint_api *,mrk_e2_fixture_identity_facts *);
void *mrk_e2_fixture_client_identity_new(const mrk_e2_fixture_checkpoint_api *,mrk_e2_fixture_identity_facts *);
void *mrk_e2_fixture_resident_identity_new(const mrk_e2_fixture_checkpoint_api *,mrk_e2_fixture_identity_facts *);
int mrk_e2_fixture_identity_prepare(void *,const mrk_e2_fixture_checkpoint_api *,mrk_e2_fixture_identity_facts *);
int mrk_e2_fixture_identity_recheck(void *,uint32_t,const mrk_e2_fixture_checkpoint_api *,mrk_e2_fixture_identity_facts *);
int mrk_e2_fixture_identity_facts_read(void *,mrk_e2_fixture_identity_facts *);
int mrk_e2_fixture_identity_close(void **,const mrk_e2_fixture_checkpoint_api *,mrk_e2_fixture_identity_facts *);
CFStringRef mrk_e2_fixture_client_requirement(void *);
CFStringRef mrk_e2_fixture_resident_requirement(void *);
/* Pure epoch DATA only; the real borrow still checks every original state. */
int mrk_e2_fixture_main_epoch_admits(uint32_t,uint32_t);
int mrk_e2_fixture_main_borrow(void *);
int mrk_e2_fixture_main_borrow_return(void *);
#endif
