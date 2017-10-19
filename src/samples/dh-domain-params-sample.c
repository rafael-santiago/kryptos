/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int is_valid_number(const char *number, const size_t number_size);

int main(int argc, char **argv) {
    kryptos_u8_t *params = NULL;
    size_t params_size = 0, p_bits = 0, q_bits = 0;

    if (argc > 2) {
        if (!is_valid_number(argv[1], strlen(argv[1])) ||
            !is_valid_number(argv[2], strlen(argv[2]))) {
            goto usage;
        }

        p_bits = atoi(argv[1]);
        q_bits = atoi(argv[2]);

        if (p_bits < q_bits) {
            printf("ERROR: the size of p must be greater than the size of q.\n");
            return 1;
        }

        if (kryptos_dh_mk_domain_params(p_bits, q_bits, &params, &params_size) != kKryptosSuccess) {
            printf("ERROR: while generating the domain parameters.\n");
            return 1;
        }

        fwrite(params, params_size, 1, stdout);

        kryptos_freeseg(params);
    } else {
usage:
        printf("use: %s <p size in bits> <q size in bits>\n", argv[0]);
        return 1;
    }

    return 0;
}

static int is_valid_number(const char *number, const size_t number_size) {
    const char *np, *np_end;

    if (number == NULL || number_size == 0) {
        return 0;
    }

    np = number;
    np_end = np + number_size;

    if (np == np_end) {
        return 0;
    }

    while (np != np_end) {
        if (!isdigit(*np)) {
            return 0;
        }
        np++;
    }

    return 1;
}
