/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

#define SIPHASH_SAMPLE_KEY "Lazy-people-that-dislike-reading: it-s-not-crypto-hash. Be careful!!!"

int main(int argc, char **argv) {
    int exit_code = EXIT_FAILURE;
    if (argc == 1) {
        printf("use: %s <data>\n", argv[0]);
    } else {
        printf("%llx\n", kryptos_siphash_sum((kryptos_u8_t *)argv[1], strlen(argv[1]),
                                             (kryptos_u8_t *)SIPHASH_SAMPLE_KEY, strlen(SIPHASH_SAMPLE_KEY), 4, 2));
        exit_code = EXIT_SUCCESS;
    }
    return exit_code;
}

#undef SIPHASH_SAMPLE_KEY
