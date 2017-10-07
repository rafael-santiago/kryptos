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
    kryptos_task_ctx m;
    int exit_code = 1;

    // INFO(Rafael): Always set everything to null is a good practice.

    kryptos_task_init_as_null(&m);

    // INFO(Rafael): Setting the plaintext.

    kryptos_task_set_in(&m, "As I was saying...", 18);

    printf("Data: %s\n", m.in);

    // INFO(Rafael): Encrypting with CAST5-CBC and generating our MAC based on SHA-512.

    kryptos_task_set_encrypt_action(&m);
    kryptos_run_cipher_hmac(cast5, sha512, &m, "silent passenger", 16, kKryptosCBC);

    if (kryptos_last_task_succeed(&m)) {
        printf("Data successfully encrypted... Now we will intentionally corrupt it.\n");
        // INFO(Rafael): Let us corrupt the cryptogram on purpose of seeing the decryption fail.
        //               Do not do it at home! ;)

        kryptos_task_set_in(&m, m.out, m.out_size);

        m.in[m.in_size >> 1] = ~m.in[m.in_size >> 1];

        // INFO(Rafael): Now trying to decrypt.

        kryptos_task_set_decrypt_action(&m);
        kryptos_run_cipher_hmac(cast5, sha512, &m, "silent passenger", 16, kKryptosCBC);

        if (!kryptos_last_task_succeed(&m) && m.result == kKryptosHMACError) {
            printf("Nice! The cryptogram corruption was detected. Do not consider this, "
                   "ask for a retransmission... ;)\n");
            // INFO(Rafael): Note that we do not need to free the output, because a corruption was detected
            //               and due to it the decryption process was not performed, since we would not
            //               have a valid plaintext. On normal conditions, with valid plaintexts you should
            //               also combine the bitmask KRYPTOS_TASK_OUT in kryptos_task_free() call.
            //
            //               The bitmask KRYPTOS_TASK_IV is being passed because the used block cipher was
            //               CAST5 in CBC with a null IV. CBC requested with a null iv internally asks
            //               kryptos to generate a pseudo-random IV and this action allocates memory.
            //
            kryptos_task_free(&m, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
            exit_code = 0;
        } else {
            // INFO(Rafael): It should never happen.
            printf("Rascals! We were fooled!!\n");
            exit_code = 1;
        }
    } else {
        // INFO(Rafael): It should never happen.
        printf("ERROR: Hmmmm it should be at least encrypted.\n");
        exit_code = 1;
    }

    // INFO(Rafael): Housekeeping.

    kryptos_task_init_as_null(&m);

    return exit_code;
}
