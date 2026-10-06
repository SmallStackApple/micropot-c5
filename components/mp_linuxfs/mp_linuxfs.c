#include <stdio.h>
#include <string.h>

#include "mp_linuxfs.h"

const mpfs_node_t *mpfs_lookup(const mpfs_node_t *tree, size_t n,
                               const char *path)
{
    if (!tree || !path) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        if (strcmp(tree[i].path, path) == 0) {
            return &tree[i];
        }
    }
    return NULL;
}

size_t mpfs_children(const mpfs_node_t *tree, size_t n, const char *dir,
                     const mpfs_node_t **out, size_t max)
{
    size_t dir_len = strlen(dir);
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        const char *p = tree[i].path;
        if (strcmp(p, dir) == 0) {
            continue; /* the directory itself is not its child */
        }
        if (dir_len == 1) { /* root: children start right after "/" */
            if (p[0] != '/') {
                continue;
            }
            p++;
        } else {
            if (strncmp(p, dir, dir_len) != 0 || p[dir_len] != '/') {
                continue;
            }
            p += dir_len + 1;
        }
        if (!*p || strchr(p, '/')) {
            continue; /* deeper than one level */
        }
        if (out && count < max) {
            out[count] = &tree[i];
        }
        count++;
    }
    return count;
}

bool mpfs_normalize(const char *cwd, const char *arg, char *out, size_t len)
{
    if (!len) {
        return false;
    }
    /* joined path: arg absolute wins, else cwd + "/" + arg */
    char joined[256];
    if (arg[0] == '/') {
        snprintf(joined, sizeof(joined), "%s", arg);
    } else if (strcmp(cwd, "/") == 0) {
        snprintf(joined, sizeof(joined), "/%s", arg);
    } else {
        snprintf(joined, sizeof(joined), "%s/%s", cwd, arg);
    }

    size_t olen = 0;
    out[olen++] = '/';
    out[olen] = '\0';

    char *save = NULL;
    for (char *tok = strtok_r(joined, "/", &save); tok;
         tok = strtok_r(NULL, "/", &save)) {
        if (strcmp(tok, ".") == 0 || !*tok) {
            continue;
        }
        if (strcmp(tok, "..") == 0) {
            if (olen > 1) {
                /* drop the last component */
                olen--;
                while (olen > 1 && out[olen - 1] != '/') {
                    olen--;
                }
                if (olen > 1) {
                    olen--; /* keep a single leading slash */
                }
                out[olen] = '\0';
                if (olen == 0) {
                    out[olen++] = '/';
                    out[olen] = '\0';
                }
            }
            continue;
        }
        size_t need = olen + strlen(tok) + 2;
        if (need >= len) {
            return false;
        }
        if (olen > 1) {
            out[olen++] = '/';
        }
        strcpy(out + olen, tok);
        olen += strlen(tok);
    }
    return true;
}

const char *mpfs_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* -------------------------------------------------------- writable overlay
 * Phase-1 stubs. The interface is fixed so services can adopt it now; the
 * phase-2 LittleFS-backed overlay fills these in (see mp_linuxfs.h and
 * docs/ROADMAP.md). */
esp_err_t mpfs_overlay_init(void)
{
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t mpfs_write(const char *path, const void *data, size_t len)
{
    (void)path;
    (void)data;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t mpfs_remove(const char *path)
{
    (void)path;
    return ESP_ERR_NOT_SUPPORTED;
}
