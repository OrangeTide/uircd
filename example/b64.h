/* b64.h : minimal base64 encode/decode */

#ifndef B64_H
#define B64_H

#include <stddef.h>

/* Encode len bytes into dst (NUL-terminated). dst must hold at least
 * 4*((len+2)/3)+1 bytes. Returns the string length written. */
size_t b64_encode(char *dst, size_t dstsz, const unsigned char *src,
                  size_t len);

/* Decode a base64 string into dst. Returns the number of bytes written, or
 * (size_t)-1 on malformed input or insufficient space. */
size_t b64_decode(unsigned char *dst, size_t dstsz, const char *src);

#endif /* B64_H */
