/*
 * Filesystem commands for the bash-flavoured shell: pwd/cd/ls/cat/grep/echo.
 * All answers come from the brand's static mpfs tree plus the session cwd.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mp_linuxfs.h"
#include "mp_linekit.h"
#include "mp_linuxsh_internal.h"

#define CAT_IDLE_MS 10000

int sh_cmd_pwd(sh_t *sh)
{
    return sh_outf(sh, "%s\r\n", sh->cwd);
}

int sh_cmd_cd(sh_t *sh, int argc, char **argv)
{
    const char *target = (argc < 2 || strcmp(argv[1], "~") == 0) ? "/root"
                                                                 : argv[1];
    char path[128];
    if (!sh_resolve(sh, target, path, sizeof(path))) {
        return 0;
    }
    const mpfs_node_t *node = mpfs_lookup(sh->cfg->fs, sh->cfg->fs_n, path);
    if (!node) {
        return sh_outf(sh, "bash: cd: %s: No such file or directory\r\n",
                       target);
    }
    if (node->type != MPFS_DIR) {
        return sh_outf(sh, "bash: cd: %s: Not a directory\r\n", target);
    }
    snprintf(sh->cwd, sizeof(sh->cwd), "%s", path);
    return 0;
}

static void ls_long_line(sh_t *sh, const mpfs_node_t *node, const char *name)
{
    uint32_t size = node->size;
    if (!size) {
        size = node->type == MPFS_DIR ? 4096
                                      : (uint32_t)strlen(node->content);
    }
    sh_outf(sh, "%s 1 %s %s %6u %s %s\r\n",
            node->mode ? node->mode
                       : (node->type == MPFS_DIR ? "drwxr-xr-x"
                                                 : "-rw-r--r--"),
            node->owner ? node->owner : "root",
            node->group ? node->group : "root",
            (unsigned)size,
            node->date ? node->date : "Oct  1 09:00",
            name);
}

int sh_cmd_ls(sh_t *sh, int argc, char **argv)
{
    bool long_fmt = false, show_all = false;
    const char *target = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strchr(argv[i], 'l')) {
                long_fmt = true;
            }
            if (strchr(argv[i], 'a')) {
                show_all = true;
            }
        } else {
            target = argv[i];
        }
    }

    char path[128];
    if (!sh_resolve(sh, target ? target : ".", path, sizeof(path))) {
        return 0;
    }
    const mpfs_node_t *node = mpfs_lookup(sh->cfg->fs, sh->cfg->fs_n, path);
    if (!node) {
        return sh_outf(sh,
                       "ls: cannot access '%s': No such file or directory\r\n",
                       target ? target : path);
    }
    if (node->type == MPFS_FILE) {
        if (long_fmt) {
            ls_long_line(sh, node, target ? target : mpfs_basename(path));
        } else {
            sh_outf(sh, "%s\r\n", target ? target : mpfs_basename(path));
        }
        return 0;
    }

    const mpfs_node_t *kids[64];
    size_t n = mpfs_children(sh->cfg->fs, sh->cfg->fs_n, path, kids, 64);
    if (long_fmt) {
        if (show_all) {
            sh_out(sh, "total 8\r\n");
            const mpfs_node_t *self = node;
            ls_long_line(sh, self, ".");
            static const mpfs_node_t parent = {
                "", MPFS_DIR, NULL, "drwxr-xr-x", "root", "root", 4096, NULL
            };
            ls_long_line(sh, &parent, "..");
        } else {
            sh_out(sh, "total 4\r\n");
        }
        for (size_t i = 0; i < n; i++) {
            ls_long_line(sh, kids[i], mpfs_basename(kids[i]->path));
        }
    } else {
        for (size_t i = 0; i < n; i++) {
            sh_out(sh, mpfs_basename(kids[i]->path));
            sh_out(sh, (i + 1 < n) ? "  " : "\r\n");
        }
        if (!n) {
            sh_out(sh, "\r\n");
        }
    }
    return 0;
}

static int cat_file(sh_t *sh, const char *path, const char *shown)
{
    const mpfs_node_t *node = mpfs_lookup(sh->cfg->fs, sh->cfg->fs_n, path);
    if (!node) {
        return sh_outf(sh, "cat: %s: No such file or directory\r\n", shown);
    }
    if (node->type == MPFS_DIR) {
        return sh_outf(sh, "cat: %s: Is a directory\r\n", shown);
    }
    /* file bodies use \n; the terminal wants \r\n */
    for (const char *p = node->content; *p;) {
        const char *nl = strchr(p, '\n');
        if (nl) {
            mp_conn_send(sh->conn, p, (size_t)(nl - p));
            sh_out(sh, "\r\n");
            p = nl + 1;
        } else {
            sh_out(sh, p);
            sh_out(sh, "\r\n");
            break;
        }
    }
    return 0;
}

int sh_cmd_cat(sh_t *sh, int argc, char **argv)
{
    if (argc < 2) {
        /* bare cat reads stdin: echo lines back until the peer goes quiet */
        char line[256];
        for (;;) {
            int n = mp_line_read(sh->conn, line, sizeof(line), CAT_IDLE_MS,
                                 false, MP_LINE_ECHO_ON);
            if (n < 0) {
                break;
            }
            sh_out(sh, line);
            sh_out(sh, "\r\n");
        }
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        char path[128];
        if (sh_resolve(sh, argv[i], path, sizeof(path))) {
            cat_file(sh, path, argv[i]);
        }
    }
    return 0;
}

int sh_cmd_grep(sh_t *sh, int argc, char **argv)
{
    if (argc < 3) {
        return sh_out(sh, "Usage: grep [OPTION]... PATTERNS [FILE]...\r\n");
    }
    const char *pat = argv[1];
    char path[128];
    if (!sh_resolve(sh, argv[2], path, sizeof(path))) {
        return 0;
    }
    const mpfs_node_t *node = mpfs_lookup(sh->cfg->fs, sh->cfg->fs_n, path);
    if (!node || node->type == MPFS_DIR) {
        return sh_outf(sh, "grep: %s: No such file or directory\r\n", argv[2]);
    }
    /* fixed-string, line oriented: enough for "grep root /etc/passwd" */
    char *copy = strdup(node->content);
    if (!copy) {
        return -1;
    }
    for (char *line = strtok(copy, "\n"); line; line = strtok(NULL, "\n")) {
        if (strstr(line, pat)) {
            sh_out(sh, line);
            sh_out(sh, "\r\n");
        }
    }
    free(copy);
    return 0;
}

int sh_cmd_echo(sh_t *sh, int argc, char **argv)
{
    int i = 1;
    bool newline = true;
    if (i < argc && strcmp(argv[i], "-n") == 0) {
        newline = false;
        i++;
    }
    for (; i < argc; i++) {
        sh_out(sh, argv[i]);
        sh_out(sh, (i + 1 < argc) ? " " : (newline ? "\r\n" : ""));
    }
    if (argc <= 1 && newline) {
        sh_out(sh, "\r\n");
    }
    return 0;
}
