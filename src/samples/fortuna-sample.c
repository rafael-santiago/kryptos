/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>

int main(int argc, char **argv) {
    struct kryptos_fortuna_ctx *fortuna;
    kryptos_u8_t *block, *bp, *bp_end;
    size_t block_size;
    int error = 0;

    // INFO(Rafael): When passing 1 it signales kryptos to alloc a new context,
    //               instead of using a static one.
    fortuna = kryptos_fortuna_init(1);

    if (fortuna != NULL) {

        if (kryptos_fortuna_reseed(fortuna, (kryptos_u8_t *)"fortes fortuna adiuvat", 22)) {
            block_size = 16;
            block = kryptos_fortuna_get_random_block(fortuna, block_size);
            if (block != NULL) {
                bp = block;
                bp_end = bp + block_size;

                printf("Random 128-bit block from external generator: ");

                while (bp != bp_end) {
                    printf("%c", isprint(*bp) ? *bp : '.');
                    bp++;
                }

                printf("\n");

                kryptos_freeseg(block, block_size);

                // INFO(Rafael): You should save it somewhere, if you want to restore
                //               the CSPRNG state later.

                printf("Current seed from external generator: 0x");
                bp = fortuna->seed;
                bp_end = bp + fortuna->seed_size;

                while (bp != bp_end) {
                    printf("%.2X", *bp);
                    bp++;
                }

                printf("\n");

                // INFO(Rafael): Now let's switch the internal kryptos CSPRNG to Fortuna.

                if (kryptos_set_csprng(kKryptosCSPRNGFortuna)) {

                    // INFO(Rafael): Notice that we call 'kryptos_get_random_block' instead of
                    //               'kryptos_fortuna_get_random_block'.
                    block = kryptos_get_random_block(block_size);
                    if (block != NULL) {
                        bp = block;
                        bp_end = bp + block_size;

                        printf("Random 128-bit block from internal generator: ");

                        while (bp != bp_end) {
                            printf("%c", isprint(*bp) ? *bp : '.');
                            bp++;
                        }

                        printf("\n");

                        kryptos_freeseg(block, block_size);
                    } else {
                        error = 1;
                        printf("ERROR: Unable to get a random block.\n");
                    }
                } else {
                    error = 1;
                    printf("ERROR: Unable to set the internal kryptos CSPRNG to Fortuna.\n");
                }

            } else {
                error = 1;
                printf("ERROR: Unable to get a random block.\n");
            }
        } else {
            error = 1;
            printf("ERROR: Unable to reseed Fortuna.\n");
        }

        kryptos_fortuna_fini(fortuna);
    } else {
        error = 1;
        printf("ERROR: Unable to initialize Fortuna.\n");
    }

    return error;
}
