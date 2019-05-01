/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *bp, *bp_end;

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): You can call blake2bN and blake2sN through the kryptos_hash macro.
    //               You must specify the hash size (in bytes) by using the out_size field from kryptos_task_ctx.

    ktask->out_size = 28;
    kryptos_hash(blake2sN, ktask, "Lenny", 5, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: when trying to compute blake2s224.\n");
        goto epilogue;
    }

    printf("Blake2s224: %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->out_size = 48;
    kryptos_hash(blake2bN, ktask, "Lenny", 5, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: when trying to compute blake2b384.\n");
        goto epilogue;
    }

    printf("Blake2b384: %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Keyed hash are the same of implementations of blake with fixed output size.

    ktask->key = "Blake2s";
    ktask->key_size = 7;
    ktask->out_size = 28;
    kryptos_hash(blake2sN, ktask, "Lenny", 5, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: when trying to compute blake2s224.\n");
        goto epilogue;
    }

    printf("Blake2s224 (Keyed): %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->key = "Blake2b";
    ktask->key_size = 7;
    ktask->out_size = 48;
    kryptos_hash(blake2bN, ktask, "Lenny", 5, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: when trying to compute blake2b384.\n");
        goto epilogue;
    }

    printf("Blake2b384 (Keyed): %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return 0;
}
