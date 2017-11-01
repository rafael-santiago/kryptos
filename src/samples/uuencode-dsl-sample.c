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
    int exit_code = 0;
    kryptos_task_ctx t, *ktask = &t;
    char *data = "Angel of Harlem";

    kryptos_task_init_as_null(ktask);

    printf("Original data: '%s'\n", data);

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(uuencode, ktask, data, strlen(data));

    if (!kryptos_last_task_succeed(ktask)) {
        exit_code = 1;
        printf("Encoding error!\n");
        ktask->in = NULL;
        goto epilogue;
    }

    printf("Encoded data: '%s'\n", ktask->out);

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(uuencode, ktask, ktask->out, ktask->out_size);

    if (!kryptos_last_task_succeed(ktask)) {
        exit_code = 1;
        printf("Decoding error!\n");
        goto epilogue;
    }

    printf("Decoded data: '");
    fwrite(ktask->out, 1, ktask->out_size, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return exit_code;
}
