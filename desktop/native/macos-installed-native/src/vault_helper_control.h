// One fixed helper-main clock/control cell. Not a process runner or timeout owner.
#ifndef MRK_VAULT_HELPER_CONTROL_H
#define MRK_VAULT_HELPER_CONTROL_H
#include <stdint.h>
int mrk_vault_uptime(uint64_t *out);
#if defined(MRK_WRAPPING_VAULT_HELPER)
int mrk_vault_control_begin(const uint8_t nonce[16], uint64_t work, uint64_t cleanup);
uint32_t mrk_vault_control_admit(uint32_t cleanup);
void mrk_vault_control_failure(void);
void mrk_vault_control_failure_at(uint64_t first);
void mrk_vault_control_effect(uint32_t effect);
int mrk_vault_control_snapshot(uint64_t *first, uint64_t *cleanup, uint32_t *effect, uint32_t *valid);
int mrk_vault_control_input_retiring(void);
int mrk_vault_control_input_closed(void);
int mrk_vault_control_terminal_start(void);
#else
static inline void mrk_vault_control_failure(void) {}
static inline void mrk_vault_control_effect(uint32_t effect) { (void)effect; }
#endif
#endif
