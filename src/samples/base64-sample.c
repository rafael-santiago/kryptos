/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    int exit_code = 0;

    // INFO(Rafael): Indicating which encoder use.

    t.encoder = kKryptosEncodingBASE64;

    t.in = (kryptos_u8_t *)"Hey Beavis, I will become a encoded string Huh!";
    t.in_size = strlen((char *)t.in);

    printf("Original text: '%s'\n", t.in);

    // INFO(Rafael): Once the encoder indicated we need to inform our encode intentions
    //               and then call the encoding processor.

    kryptos_task_set_encode_action(ktask);
    kryptos_base64_processor(&ktask);

    if (!kryptos_last_task_succeed(ktask)) {
        t.in = NULL;
        t.in_size = 0;
        printf("Error during encoding task.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Encoded text: '%s'\n", t.out);

    t.in = t.out;
    t.in_size = t.out_size;

    t.out = NULL;
    t.out_size = 0;

    // INFO(Rafael): Once the encoder indicated we need to inform our decode intentions
    //               and then call the encoding processor again.


    kryptos_task_set_decode_action(ktask);
    kryptos_base64_processor(&ktask);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("Error during decoding task.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Decoded text: '");
    fwrite(t.out, t.out_size, 1, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return exit_code;
}
