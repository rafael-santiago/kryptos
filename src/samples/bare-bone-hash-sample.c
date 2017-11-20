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

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    size_t o;

    // INFO(Rafael): Defining the input that must be "hashed".

    t.in = (kryptos_u8_t *)"abc";
    t.in_size = 3;

    printf("Hashed data: %s\n", t.in);

    // INFO(Rafael): Executing the hash algorithm over the input.
    //               The second parameter when 0 requests a raw byte output.

    kryptos_sha1_hash(&ktask, 0);

    if (ktask->out != NULL) {
        printf("Raw output: ");
        for (o = 0; o < ktask->out_size; o++) {
            printf("%c", isprint(ktask->out[o]) ? ktask->out[o] : '.');
        }
        printf("\n");

        // INFO(Rafael): Freeing the output buffer.

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    } else {
        printf("ERROR: when executing the hash with raw byte output.\n");
        return 1;
    }

    // INFO(Rafael): Executing again the hash algorithm over the previously defined input.
    //               The second parameter when 1 requests a hexadecimal output.

    kryptos_sha1_hash(&ktask, 1);

    if (ktask->out != NULL) {
        printf("Hex output: %s\n", ktask->out);

        // INFO(Rafael): Freeing the output buffer.

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    } else {
        printf("ERROR: when executing the hash with hexdecimal output.\n");
        return 1;
    }

    return 0;
}
