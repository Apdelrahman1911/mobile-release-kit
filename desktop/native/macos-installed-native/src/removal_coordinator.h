#ifndef MRK_REMOVAL_COORDINATOR_H
#define MRK_REMOVAL_COORDINATOR_H
#include <stddef.h>
#include <stdint.h>

// Fixed main-window removal sheet. No renderer text, path, privilege command,
// general dialog or synchronous runModal entry is accepted by this ABI.
size_t mrk_removal_confirmation_bytes(void);
void *mrk_removal_confirmation_reserve(uint64_t start, uint64_t work, uint64_t hard);
int mrk_removal_confirmation_start(void *original);
// 0 pending, 1 accepted, 2 declined, 3 closed, -2 known work refusal, -1 unknown.
int mrk_removal_confirmation_poll(void *original);
int mrk_removal_confirmation_close(void *original);
// 1 consumes original and writes accepted 0/1 plus its original nonce. Failure
// retains the original, including every entered/unknown reference.
int mrk_removal_confirmation_retire(void *original, uint32_t *accepted, uint8_t nonce[16]);
// Actual Parent clock, NOT CLOCK_UPTIME_RAW used by Android Signal/Instant.
int mrk_removal_monotonic(uint64_t *now);

// Separate fixed peer original. These are private ABI DATA, never a way for a
// renderer or a parsed descriptor to claim a live peer or completed removal.
enum { MRK_REMOVE_PEER_VERSION=1, MRK_REMOVE_PEER_BORROWED=20,
    MRK_REMOVE_PEER_FDS=3, MRK_REMOVE_PEER_CFS=24,
    MRK_REMOVE_PEER_FRAME=4100, MRK_REMOVE_PEER_JSON=32768 };
enum { MRK_REMOVE_PARENT=1, MRK_REMOVE_APP=2 };
enum { MRK_REMOVE_SOURCE=1, MRK_REMOVE_OPEN=2, MRK_REMOVE_CONNECT=3,
    MRK_REMOVE_AUTHENTICATE=4, MRK_REMOVE_FRAME_BEGIN=5,
    MRK_REMOVE_FRAME_POLL=6, MRK_REMOVE_RECHECK=7,
    MRK_REMOVE_EXIT=8, MRK_REMOVE_CLOSE=9 };
enum { MRK_RP_SOURCE=1, MRK_RP_STATIC_URL=2, MRK_RP_STATIC_CODE=3,
    MRK_RP_REQUIREMENT_TEXT=4, MRK_RP_REQUIREMENT=5,
    MRK_RP_STATIC_VALIDITY=6, MRK_RP_STATIC_INFO=7,
    MRK_RP_CERTIFICATE=8, MRK_RP_SELF=9,
    MRK_RP_DYNAMIC_VALIDITY=10, MRK_RP_DYNAMIC_INFO=11,
    MRK_RP_SOCKET=12, MRK_RP_SOCKET_FLAGS=13,
    MRK_RP_BIND=14, MRK_RP_SOCKET_MODE=15, MRK_RP_LISTEN=16,
    MRK_RP_CONNECT=17, MRK_RP_CONNECT_STATUS=18,
    MRK_RP_ACCEPT=19, MRK_RP_TOKEN=20,
    MRK_RP_AUDIT_DATA=21, MRK_RP_AUDIT_ATTRIBUTES=22,
    MRK_RP_GUEST=23, MRK_RP_KQUEUE=24, MRK_RP_WATCH_FLAGS=25,
    MRK_RP_WATCH_REGISTER=26, MRK_RP_WATCH_POLL=27,
    MRK_RP_SEND=28, MRK_RP_RECEIVE=29,
    MRK_RP_RELEASE=30, MRK_RP_CLOSE=31, MRK_RP_RETIRE=32,
    MRK_RP_BOUNDARY=33 };
typedef struct {
    uint64_t device,inode,links,size;
    int64_t modified_seconds,changed_seconds;
    uint32_t mode,uid,gid,flags,modified_nanoseconds,changed_nanoseconds;
} mrk_removal_stat_data;
typedef struct {
    uint32_t version,role,operation,failed,unknown,calls,returned;
    uint32_t stage,frame_index,frame_started,frame_size,frame_offset;
    uint32_t token_ready,watch_ready,exit_observed,eof,closed,bind_returned;
    uint32_t fd_states[MRK_REMOVE_PEER_FDS],cf_states[MRK_REMOVE_PEER_CFS];
    uint32_t peer_pid,peer_uid,peer_gid,first_code;
    uint64_t last,first_failure;
    mrk_removal_stat_data request_directory,socket_name;
} mrk_removal_peer_report;
typedef struct {
    uint32_t version,role;
    uint64_t start,work,hard;
    uint8_t request_id[16],code_sha256[3][32];
    uint8_t installed_sha256[32],remove_sha256[32],request_sha256[32];
    int32_t borrowed[MRK_REMOVE_PEER_BORROWED];
    const uint8_t *installed,*installed_signature,*remove,*remove_signature;
    size_t installed_size,installed_signature_size,remove_size,remove_signature_size;
} mrk_removal_peer_inputs;
// Called synchronously only, never retained by a native asynchronous object.
// before=1 precedes the original; before=0 observes its actual returned facts.
// 1 admits,0 stops,-1 retains Unknown. No callback can manufacture native facts.
typedef int (*mrk_removal_peer_gate)(void *context,uint32_t before,uint32_t phase,
    uint32_t slot,uint32_t cleanup,const mrk_removal_peer_report *facts);
size_t mrk_removal_peer_bytes(void);
void *mrk_removal_peer_new(const mrk_removal_peer_inputs *inputs);
// 1 ready,0 pending,-2 known refusal,-1 unknown. Output always describes the
// actual original when its same-process/thread identity is still available.
int mrk_removal_peer_run(void *original,uint32_t operation,const uint8_t *frame,
    size_t size,mrk_removal_peer_gate gate,void *context,mrk_removal_peer_report *out);
// Copy only one actually completed inbound frame, not a caller-supplied frame.
int mrk_removal_peer_copy(void *original,uint8_t out[MRK_REMOVE_PEER_FRAME],size_t *size);
// 1 is actual sole consumption. Unknown/entered/owned references retain cell.
// Rust records consumption BEFORE the independent owner/clock POST gate.
int mrk_removal_peer_retire(void *original,mrk_removal_peer_report *out);
// Private pure DATA predicate, shared with the exact final-Ack send POST.
// 0 requires ordinary live POST; 1 permits terminal POST; -1 refuses its watch
// result. This does not observe an original, call a clock/watch or grant proof.
int mrk_removal_peer_ack_post_data(uint32_t role,uint32_t index,uint32_t direction,
    uint32_t expected,uint32_t before,int64_t returned,int32_t watch_result);
#endif
