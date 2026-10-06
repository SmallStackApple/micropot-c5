#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** sha512crypt ($6$) per Ulrich Drepper's specification. @p out receives
 *  the full "$6$salt$hash" string. Salt is capped at 16 chars (any extra
 *  is ignored, like glibc). Returns false on bad args. */
bool mp_crypt_sha512(const char *pass, const char *salt, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
