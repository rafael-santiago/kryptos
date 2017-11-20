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
    kryptos_task_ctx task, *ktask = &task;
    kryptos_u8_t *key = (kryptos_u8_t *)"foo";
    kryptos_u8_t *data = (kryptos_u8_t *)"plaintext";
    size_t data_size = 9;

    printf("Original data: %s\n", data);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Loading the basic information about the task involving the chosen cipher.
    kryptos_blowfish_setup(ktask, key, strlen((char *)key), kKryptosECB);

    // INFO(Rafael): Since we need to encrypt, we need to inform it.
    kryptos_task_set_encrypt_action(ktask);

    // INFO(Rafael): Setting up the input information for the desired task.
    ktask->in = data;
    ktask->in_size = data_size;

    // INFO(Rafael): Encrypting.
    kryptos_blowfish_cipher(&ktask);

    if (ktask->result == kKryptosSuccess) {
        printf("Data encrypted!\n");

        kryptos_task_set_decrypt_action(ktask);

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;
        ktask->out = NULL;

        // INFO(Rafael): Decrypting.
        kryptos_blowfish_cipher(&ktask);

        if (ktask->result == kKryptosSuccess) {
            printf("Data decrypted: ");
            fwrite(ktask->out, ktask->out_size, 1, stdout);
            printf("\n");
        } else {
            printf("ERROR: during decryption.\n");
        }

        // INFO(Rafael): Freeing input and output.
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    } else {
        printf("ERROR: during encryption.\n");
    }

    return 0;
}
