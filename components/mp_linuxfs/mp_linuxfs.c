#include <stdio.h>
#include <string.h>

#include "mp_linuxfs.h"

static const mp_lfs_t *s_fs;

const mp_lfs_t *mp_lfs_active(void)
{
    return s_fs;
}

void mp_lfs_use(const mp_lfs_t *fs)
{
    s_fs = fs;
}

/* -------------------------------------------------------- path handling */

/* Normalise an absolute path: collapse //, ., .., trailing /. */
void mp_lfs_join(const char *cwd, const char *arg, char *out, size_t cap)
{
    char raw[512];
    if (!arg || arg[0] == '\0') {
        snprintf(raw, sizeof(raw), "%s", cwd ? cwd : "/");
    } else if (arg[0] == '~') {
        snprintf(raw, sizeof(raw), "/root%s", arg + 1);
    } else if (arg[0] == '/') {
        snprintf(raw, sizeof(raw), "%s", arg);
    } else {
        snprintf(raw, sizeof(raw), "%s/%s", cwd && cwd[0] ? cwd : "/", arg);
    }

    /* walk segments, handling "." and ".." */
    char *segs[64];
    size_t nseg = 0;
    char *p = raw;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        char *start = p;
        while (*p && *p != '/') p++;
        if (*p) *p++ = '\0';
        if (strcmp(start, ".") == 0) {
            continue;
        }
        if (strcmp(start, "..") == 0) {
            if (nseg) nseg--;
            continue;
        }
        if (nseg < 64) segs[nseg++] = start;
    }

    size_t len = 0;
    out[0] = '\0';
    if (cap < 2) {
        return;
    }
    out[len++] = '/';
    out[len] = '\0';
    for (size_t i = 0; i < nseg; i++) {
        size_t n = strlen(segs[i]);
        if (len + n + 2 >= cap) break;
        if (len > 1) out[len++] = '/';
        memcpy(out + len, segs[i], n);
        len += n;
        out[len] = '\0';
    }
}

/* ------------------------------------------------------------- lookup */

const mp_lfs_node_t *mp_lfs_lookup(const char *abspath)
{
    if (!s_fs || !abspath) {
        return NULL;
    }
    for (size_t i = 0; i < s_fs->n; i++) {
        if (s_fs->nodes[i].path && strcmp(s_fs->nodes[i].path, abspath) == 0) {
            return &s_fs->nodes[i];
        }
    }
    return NULL;
}

bool mp_lfs_is_dir(const char *abspath)
{
    const mp_lfs_node_t *n = mp_lfs_lookup(abspath);
    return n && n->kind == MP_LFS_DIR;
}

const char *mp_lfs_read(const char *abspath, size_t *out_len)
{
    const mp_lfs_node_t *n = mp_lfs_lookup(abspath);
    if (!n || n->kind != MP_LFS_FILE || !n->content) {
        return NULL;
    }
    if (out_len) {
        *out_len = strlen(n->content);
    }
    return n->content;
}

/* --------------------------------------------------------------- list */

static bool parent_is(const char *path, const char *dir)
{
    size_t dlen = strlen(dir);
    if (dlen == 1 && dir[0] == '/') {
        return path[0] == '/' && strchr(path + 1, '/') == NULL;
    }
    if (strncmp(path, dir, dlen) != 0 || path[dlen] != '/') {
        return false;
    }
    return strchr(path + dlen + 1, '/') == NULL;
}

int mp_lfs_list(const char *absdir, mp_lfs_list_cb cb, void *arg)
{
    if (!s_fs) {
        return 0;
    }
    int count = 0;
    for (size_t i = 0; i < s_fs->n; i++) {
        const mp_lfs_node_t *n = &s_fs->nodes[i];
        if (!n->path || strcmp(n->path, absdir) == 0) {
            continue;
        }
        if (parent_is(n->path, absdir)) {
            const char *name = strrchr(n->path, '/');
            name = name ? name + 1 : n->path;
            if (cb) {
                cb(name, n, arg);
            }
            count++;
        }
    }
    return count;
}

void mp_lfs_size_str(uint32_t bytes, char *out, size_t cap)
{
    if (bytes < 1024) {
        snprintf(out, cap, "%u", (unsigned)bytes);
    } else if (bytes < 1024u * 1024u) {
        snprintf(out, cap, "%.1fK", bytes / 1024.0);
    } else {
        snprintf(out, cap, "%.1fM", bytes / (1024.0 * 1024.0));
    }
}
