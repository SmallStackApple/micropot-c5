#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * application/x-www-form-urlencoded helpers.
 *
 * Pure string code (no ESP dependencies) so it can be unit-tested on the
 * host (test/host). Internal to mp_http.
 * ---------------------------------------------------------------------- */

/** In-place URL decoding: %XX unescaped, '+' becomes space. */
void mp_form_url_decode(char *s);

/**
 * Extract a form field. The key is only matched at the start of the body
 * or right after '&' (so "xusername=" cannot spoof "username=").
 * The value is URL-decoded in place.
 *
 * @return true when the key was found (value may be empty).
 */
bool mp_form_get(const char *body, const char *key, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif
