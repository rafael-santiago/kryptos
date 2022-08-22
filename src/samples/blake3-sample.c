/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TEST_STR "Entre os animais ferozes, o de mais perigosa mordedura eh o delator;"\
                 "entre os animais domesticos, o adulador."

#define KEY_STR "DiogenesDeSinopeDiogenesDeSinope"

int main(void) {
    kryptos_task_ctx t, *ktask = &t;
    int err = EXIT_SUCCESS;
    kryptos_u8_t *derived_key = NULL;
    size_t derived_key_size = 0;
    kryptos_u8_t *d = NULL, *d_end = NULL;

    kryptos_task_init_as_null(ktask);

    kryptos_hash(blake3, ktask, (kryptos_u8_t *)TEST_STR, strlen(TEST_STR), 1);

    if (!kryptos_last_task_succeed(ktask)) {
        err = EXIT_FAILURE;
        fprintf(stderr, "error: while computing hash : detail : '%s'\n",
            (ktask->result_verbose != NULL) ? ktask->result_verbose : "no details.");
        goto epilogue;
    }

    fprintf(stdout, "BLAKE3 on hash mode = %s\n", ktask->out);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->key = (kryptos_u8_t *)KEY_STR;
    ktask->key_size = 32;

    kryptos_hash(blake3, ktask, (kryptos_u8_t *)TEST_STR, strlen(TEST_STR), 1);

    if (!kryptos_last_task_succeed(ktask)) {
        err = EXIT_FAILURE;
        fprintf(stderr, "error: while computing hash : detail : '%s'\n",
            (ktask->result_verbose != NULL) ? ktask->result_verbose : "no details.");
        goto epilogue;
    }

    fprintf(stdout, "BLAKE3 on keyed-hash mode = %s\n", ktask->out);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    derived_key_size = 32;
    derived_key = kryptos_blake3(TEST_STR, strlen(TEST_STR), KEY_STR, 32, derived_key_size);

    if (derived_key == NULL) {
        err = EXIT_FAILURE;
        fprintf(stderr, "error: while deriving key.\n");
        goto epilogue;
    }

    fprintf(stdout, "BLAKE3 as a general KDF (on derive-key mode) = ");

    d = derived_key;
    d_end = d + derived_key_size;
    while (d != d_end) {
        fprintf(stdout, "%.2X", *d);
        d++;
    }
    fprintf(stdout, "\n");
    d = d_end = NULL;

epilogue:

    if (derived_key != NULL) {
        kryptos_freeseg(derived_key, derived_key_size);
    }

    derived_key_size = 0;

    kryptos_task_init_as_null(ktask);

    return err;
}
