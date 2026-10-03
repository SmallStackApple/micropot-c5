#include <string.h>

#include "mp_form.h"

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void mp_form_url_decode(char *s)
{
    char *d = s;
    for (; *s; s++) {
        if (*s == '+') {
            *d++ = ' ';
        } else if (*s == '%' && hexval(s[1]) >= 0 && hexval(s[2]) >= 0) {
            *d++ = (char)((hexval(s[1]) << 4) | hexval(s[2]));
            s += 2;
        } else {
            *d++ = *s;
        }
    }
    *d = '\0';
}

bool mp_form_get(const char *body, const char *key, char *out, size_t out_len)
{
    const size_t klen = strlen(key);
    const char  *p = body;
    for (;;) {
        p = strstr(p, key);
        if (!p) {
            return false;
        }
        if ((p == body || p[-1] == '&') && p[klen] == '=') {
            break;
        }
        p += klen;
    }
    p += klen + 1;
    const char *end = strchr(p, '&');
    size_t      len = end ? (size_t)(end - p) : strlen(p);
    if (len >= out_len) {
        len = out_len - 1;
    }
    memcpy(out, p, len);
    out[len] = '\0';
    mp_form_url_decode(out);
    return true;
}
