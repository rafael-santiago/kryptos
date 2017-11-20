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
    kryptos_u8_t *data = (kryptos_u8_t *)"Empty arms";
    size_t data_size = 10;

    kryptos_task_init_as_null(ktask);

    kryptos_hash(sha512, ktask, data, data_size, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        exit_code = 1;
        printf("Error while computing the message hash.\n");
        goto epilogue;
    }

    printf("Message hash: %s\n", ktask->out);

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return exit_code;
}
