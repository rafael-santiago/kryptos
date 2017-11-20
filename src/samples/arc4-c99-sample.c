/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    unsigned char *data = (unsigned char *)"hello world!";
    kryptos_task_ctx task, *ktask = &task;
    int exit_code = 0;

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Defining the input data information for the desired task.

    kryptos_task_set_in(ktask, data, 12);

    printf("In: %s\n", ktask->in);

    // INFO(Rafael): Running the ARC4 cipher over the input (plaintext).

    kryptos_run_cipher(arc4, ktask, (kryptos_u8_t *)"1234", 4);

    if (kryptos_last_task_succeed(ktask)) {
        printf("Encrypted... now decrypting...\n");

        // INFO(Rafael): Moving the output (ciphertext) to the input.

        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);

        // INFO(Rafael): Running the ARC4 cipher over the input (ciphertext).

        kryptos_run_cipher(arc4, ktask, (kryptos_u8_t *)"1234", 4);

        if (kryptos_last_task_succeed(ktask)) {
            printf("Out: ");
            fwrite(ktask->out, ktask->out_size, 1, stdout);
            printf("\n");
        } else {
            printf("Error during decryption.\n");
            exit_code = 1;
        }

        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    } else {
        printf("Error during encryption.\n");
        exit_code = 1;
    }
    return exit_code;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
