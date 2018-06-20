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
    kryptos_u8_t *k_priv = NULL, *k_pub = NULL;
    size_t k_priv_size = 0, k_pub_size = 0;
    int exit_code = 0;

    if (argc > 1 && is_valid_number(argv[1], strlen(argv[1]))) {
        if (kryptos_rsa_mk_key_pair(atoi(argv[1]),
                                    &k_pub, &k_pub_size,
                                    &k_priv, &k_priv_size) == kKryptosSuccess) {
            // INFO(Rafael): This is just for demo issues, the best here would be
            //               save the k_pub and k_priv buffers to separated files
            //               for a later usage. Duh! :)
            printf("*** Public key:\n\n");
            printf("%s\n", k_pub);
            printf("*** Private key:\n\n");
            printf("%s\n", k_priv);
        } else {
            printf("ERROR: while generating the key pair.\n");
            exit_code = 1;
        }
    } else {
        printf("use: %s <key size in bits>\n", argv[0]);
        exit_code = 1;
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv, k_priv_size);
    }

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub, k_pub_size);
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
