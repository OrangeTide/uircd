/* uircdpasswd.c : generate a scrypt passwd line for miniircd */

#include "b64.h"
#include "crypto_scrypt.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sys/random.h>

#define SCRYPT_N  16384
#define SCRYPT_R  8
#define SCRYPT_P  1
#define SALT_LEN  16
#define HASH_LEN  32

static int
read_password(char *buf, size_t sz)
{
    struct termios old, raw;
    int have_tty = isatty(STDIN_FILENO);
    size_t len;

    if (have_tty) {
        fprintf(stderr, "Password: ");
        fflush(stderr);
        if (tcgetattr(STDIN_FILENO, &old) == 0) {
            raw = old;
            raw.c_lflag &= ~(tcflag_t)ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        }
    }
    if (!fgets(buf, (int)sz, stdin)) {
        if (have_tty)
            tcsetattr(STDIN_FILENO, TCSANOW, &old);
        return -1;
    }
    if (have_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        fprintf(stderr, "\n");
    }
    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return 0;
}

int
main(int argc, char **argv)
{
    const char *name, *flags;
    char pass[256];
    unsigned char salt[SALT_LEN], hash[HASH_LEN];
    char saltb64[64], hashb64[64];

    if (argc < 3 || argc > 4) {
        fprintf(stderr,
                "usage: %s <name> <flags> [password]\n"
                "  name   account name, or \"*\" for a shared PASS\n"
                "  flags  any of: c (may connect), o (may OPER)\n"
                "password is read from the terminal if omitted.\n",
                argv[0]);
        return 2;
    }
    name = argv[1];
    flags = argv[2];

    if (argc == 4) {
        if (strlen(argv[3]) >= sizeof(pass)) {
            fprintf(stderr, "password too long\n");
            return 1;
        }
        strcpy(pass, argv[3]);
    } else if (read_password(pass, sizeof(pass)) != 0) {
        fprintf(stderr, "could not read password\n");
        return 1;
    }

    if (getrandom(salt, sizeof(salt), 0) != (ssize_t)sizeof(salt)) {
        fprintf(stderr, "getrandom failed\n");
        return 1;
    }
    if (crypto_scrypt((const uint8_t *)pass, strlen(pass), salt, sizeof(salt),
                      SCRYPT_N, SCRYPT_R, SCRYPT_P, hash, sizeof(hash)) != 0) {
        fprintf(stderr, "scrypt failed\n");
        return 1;
    }

    b64_encode(saltb64, sizeof(saltb64), salt, sizeof(salt));
    b64_encode(hashb64, sizeof(hashb64), hash, sizeof(hash));

    printf("%s:scrypt:%d:%d:%d:%s:%s:%s\n",
           name, SCRYPT_N, SCRYPT_R, SCRYPT_P, saltb64, hashb64, flags);

    /* wipe sensitive material; explicit_bzero is not elided at -O2 */
    explicit_bzero(pass, sizeof(pass));
    explicit_bzero(hash, sizeof(hash));
    return 0;
}
