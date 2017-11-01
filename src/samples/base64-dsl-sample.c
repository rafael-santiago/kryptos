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
    char *data = "Hey Beavis, I will become a encoded string Huh!";

    printf("Original text: '%s'\n", data);

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(base64, ktask, data, strlen(data));

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

    printf("Decoded text: '%s'\n", ktask->out);

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return exit_code;
}
