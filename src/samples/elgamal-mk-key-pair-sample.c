/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static int is_valid_number(const char *number, const size_t number_size);

int main(int argc, char **argv) {
    size_t p_bits, q_bits;
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size, k_priv_size;
    int exit_code = 0;

    if (argc > 2) {
        if (!is_valid_number(argv[1], strlen(argv[1])) ||
            !is_valid_number(argv[2], strlen(argv[2]))) {
            goto usage;
        }

        if (kryptos_elgamal_mk_key_pair(atoi(argv[1]), atoi(argv[2]),
                                        &k_pub, &k_pub_size,
                                        &k_priv, &k_priv_size) == kKryptosSuccess) {
            printf("Public key:\n");
            printf("\n%s\n", k_pub);
            printf("Private key:\n");
            printf("\n%s\n", k_priv);
        } else {
            printf("ERROR: while making the key pair.\n");
            exit_code = 1;
        }
    } else {
usage:
        printf("use: %s <p size in bits> <q size in bits>\n", argv[0]);
        exit_code = 1;
    }

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
