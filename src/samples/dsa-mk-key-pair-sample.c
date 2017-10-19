/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>

static int is_valid_number(const char *number, const size_t number_size);

int main(int argc, char **argv) {
    int exit_code = 0;
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size, k_priv_size;

    if (argc >= 3) {
        if (!is_valid_number(argv[1], strlen(argv[1])) ||
            !is_valid_number(argv[2], strlen(argv[2]))) {
            exit_code = 1;
            goto usage;
        }

        if (kryptos_dsa_mk_key_pair(atoi(argv[1]), atoi(argv[2]),
                                    &k_pub, &k_pub_size,
                                    &k_priv, &k_priv_size) != kKryptosSuccess) {
            exit_code = 1;
            printf("ERROR: while generating key pair.\n");
        } else {
            printf("*** PUBLIC KEY:\n\n%s\n", k_pub);
            printf("*** PRIVATE KEY:\n\n%s\n", k_priv);
        }
    } else {
usage:
        printf("use: %s <p size in bits> <q size in bits>\n", argv[0]);
    }

epilogue:

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub);
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv);
    }

    return exit_code;
}

static int is_valid_number(const char *number, const size_t number_size) {
    const char *np, *np_end;

    if (number == NULL || number_size == 0) {
        return 0;
    }

    np = number;
    np_end = np + number_size;

    while (np != np_end) {
        if (!isdigit(*np)) {
            return 0;
        }

        np++;
    }

    return 1;
}
