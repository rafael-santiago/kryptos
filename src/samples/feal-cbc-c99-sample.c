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
    kryptos_task_ctx task, *ktask = &task;
    kryptos_u8_t *key = "foo";
    kryptos_u8_t *data = "plaintext";
    size_t data_size = 9;
    int rounds = 80; /* Let's use FEAL with 80 rounds */
    int exit_code = 0;

    printf("Original data: %s\n", data);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Encrypting.
    kryptos_task_set_in(ktask, data, data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(feal, ktask, key, strlen(key), kKryptosCBC, &rounds);

    if (kryptos_last_task_succeed(ktask)) {
        printf("Encryption success!\n");
        // INFO(Rafael): Decrypting.
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(feal, ktask, key, strlen(key), kKryptosCBC, &rounds);
        printf("Plaintext: ");
        fwrite(ktask->out, ktask->out_size, 1, stdout);
        printf("\n");
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    } else {
        printf("Encryption error!\n");
        exit_code = 1;
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }

    return exit_code;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
