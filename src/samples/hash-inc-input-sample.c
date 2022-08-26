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

int main(void) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *alpha = (kryptos_u8_t *)"abcdefghijklmnopqrstuvwxyz";
    kryptos_hash_init(sha3_512, ktask);
    while (*alpha != 0) {
        kryptos_hash_update(ktask, alpha, 2);
        alpha += 2;
    }
    kryptos_hash_finalize(ktask, 1);
    printf("SHA3-512 hex result = %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    return EXIT_SUCCESS;
}
