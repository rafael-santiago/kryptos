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
#ifndef __cplusplus
    char *data = "Hey Beavis, I will become a encoded string Huh!";
#else
    char *data = (char *)"Hey Beavis, I will become a encoded string Huh!";
#endif

    printf("Original text: '%s'\n", data);

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(base64, ktask, (kryptos_u8_t *)data, strlen(data));

    if (!kryptos_last_task_succeed(ktask)) {
        t.in = NULL;
        t.in_size = 0;
        printf("Error during encoding task.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Encoded text: '%s'\n", ktask->out);

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(base64, ktask, ktask->out, ktask->out_size);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("Error during decoding task.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Decoded text: '");
    fwrite(ktask->out, ktask->out_size, 1, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return exit_code;
}
