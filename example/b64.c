/* b64.c : minimal base64 encode/decode */

#include "b64.h"

static const char enc_tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t
b64_encode(char *dst, size_t dstsz, const unsigned char *src, size_t len)
{
    size_t i, o = 0;

    for (i = 0; i + 2 < len; i += 3) {
        unsigned v = (unsigned)src[i] << 16 | (unsigned)src[i + 1] << 8 |
                     src[i + 2];
        if (o + 4 >= dstsz)
            break;
        dst[o++] = enc_tab[(v >> 18) & 0x3f];
        dst[o++] = enc_tab[(v >> 12) & 0x3f];
        dst[o++] = enc_tab[(v >> 6) & 0x3f];
        dst[o++] = enc_tab[v & 0x3f];
    }
    if (i < len && o + 4 < dstsz) {
        unsigned v = (unsigned)src[i] << 16;
        int rem = (int)(len - i);
        if (rem == 2)
            v |= (unsigned)src[i + 1] << 8;
        dst[o++] = enc_tab[(v >> 18) & 0x3f];
        dst[o++] = enc_tab[(v >> 12) & 0x3f];
        dst[o++] = rem == 2 ? enc_tab[(v >> 6) & 0x3f] : '=';
        dst[o++] = '=';
    }
    if (o < dstsz)
        dst[o] = '\0';
    return o;
}

static int
dec_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t
b64_decode(unsigned char *dst, size_t dstsz, const char *src)
{
    size_t o = 0;
    int quad[4], qn = 0;

    for (; *src; src++) {
        int v;
        if (*src == '=' || *src == '\n' || *src == '\r')
            break;
        v = dec_val((unsigned char)*src);
        if (v < 0)
            return (size_t)-1;
        quad[qn++] = v;
        if (qn == 4) {
            if (o + 3 > dstsz)
                return (size_t)-1;
            dst[o++] = (unsigned char)(quad[0] << 2 | quad[1] >> 4);
            dst[o++] = (unsigned char)(quad[1] << 4 | quad[2] >> 2);
            dst[o++] = (unsigned char)(quad[2] << 6 | quad[3]);
            qn = 0;
        }
    }
    if (qn == 2) {
        if (o + 1 > dstsz)
            return (size_t)-1;
        dst[o++] = (unsigned char)(quad[0] << 2 | quad[1] >> 4);
    } else if (qn == 3) {
        if (o + 2 > dstsz)
            return (size_t)-1;
        dst[o++] = (unsigned char)(quad[0] << 2 | quad[1] >> 4);
        dst[o++] = (unsigned char)(quad[1] << 4 | quad[2] >> 2);
    } else if (qn != 0) {
        return (size_t)-1;
    }
    return o;
}
