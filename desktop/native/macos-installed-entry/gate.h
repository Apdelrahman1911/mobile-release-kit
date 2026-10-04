/* One fixed original gate, not a process runner or a maintenance permission. */
#ifndef MRK_INSTALLED_ENTRY_GATE_H
#define MRK_INSTALLED_ENTRY_GATE_H
#include <sys/stat.h>
#include <stdint.h>
#include "fixed_paths.h"
enum { MRK_ENTRY_ANCESTORS = 4 };
typedef struct {
    int ancestors[MRK_ENTRY_ANCESTORS];
    struct stat identities[MRK_ENTRY_ANCESTORS];
    int gate;
    struct stat gate_identity;
    int failed;
} mrk_entry_book;
void mrk_entry_init(mrk_entry_book *book);
int mrk_entry_root(mrk_entry_book *book);
int mrk_entry_open_gate(mrk_entry_book *book);
int mrk_entry_gate_matches(mrk_entry_book *book, int flags);
int mrk_entry_close_ancestors(mrk_entry_book *book);
/* Private vault role: child-only transfer and process-lifetime admission. */
int mrk_vault_gate_child_inherit(int descriptor, int32_t parent_pid);
int mrk_vault_helper_gate_admit(int descriptor, int32_t parent_pid);
int mrk_user(uint32_t *uid);
int mrk_no_xattrs(int fd);
int mrk_acl_empty(int fd, int *phase, int *returned, int *error,
                  int *free_returned, int *free_error);
#endif
