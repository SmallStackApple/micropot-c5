#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Fake filesystem primitives (brand-agnostic).
 *
 * A persona file tree is a static table of nodes; helpers resolve paths
 * (cwd + . + ..), look up files and enumerate direct children. The SPIFFS
 * partition stays reserved for a phase-2 writable overlay (attacker
 * uploads, malware persistence); the read-only tree always comes from
 * brand data.
 * ---------------------------------------------------------------------- */

typedef enum {
    MPFS_DIR = 0,
    MPFS_FILE,
} mpfs_type_t;

typedef struct {
    const char *path;     /* absolute, e.g. "/etc/passwd"; dirs without "/" */
    mpfs_type_t type;
    const char *content;  /* file body (NUL-terminated); NULL for dirs */
    const char *mode;     /* ls -l mode string, e.g. "-rw-r--r--" */
    const char *owner;
    const char *group;
    uint32_t    size;     /* 0 => strlen(content); dirs default 4096 */
    const char *date;     /* ls -l date, e.g. "Oct  1 09:00" */
} mpfs_node_t;

/** Exact lookup by absolute path. NULL when absent. */
const mpfs_node_t *mpfs_lookup(const mpfs_node_t *tree, size_t n,
                               const char *path);

/** Enumerate direct children of @p dir (absolute). @return count. */
size_t mpfs_children(const mpfs_node_t *tree, size_t n, const char *dir,
                     const mpfs_node_t **out, size_t max);

/**
 * Resolve @p arg against @p cwd into an absolute, canonical path
 * (".", "..", duplicate slashes handled). @return false on overflow.
 */
bool mpfs_normalize(const char *cwd, const char *arg, char *out, size_t len);

/** Basename after the last '/'; "/" itself yields "/". */
const char *mpfs_basename(const char *path);

#ifdef __cplusplus
}
#endif
