/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <kryptos.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *plaintext = "Do not tamper with me!";
    kryptos_u8_t *key = "the worst and common way of using a user key.";
    kryptos_u8_t *p, *p_end;
    int exit_code = 0;

    printf("plaintext: '%s'\n", plaintext);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): You can set the additional authenticated data via kryptos_task_set_gcm_aad():
    //
    //                  kryptos_task_set_gcm_aad(ktask, aad_buf, aad_buf_size)
    //
    //               You can set the counter via kryptos_task_set_gcm_ctr():
    //
    //                  kryptos_task_set_gcm_ctr(ktask, &ctr_var)
    //
    //               You can set counter and add via kryptos_task_set_gcm_mode():
    //
    //                  kryptos_task_set_gcm_mode(ktask, &ctr_var, aad_buf, aad_buf_size)
    //

    kryptos_task_set_in(ktask, plaintext, strlen(plaintext));
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(aes256, ktask, key, strlen(key), kKryptosGCM);

    ktask->in = NULL;
    ktask->in_size = 0;

    if (!kryptos_last_task_succeed(ktask)) {
        if (ktask->result_verbose != NULL) {
            printf("ERROR: %s\n", ktask->result_verbose);
        } else {
            printf("ERROR: What?!\n");
        }
        exit_code = 1;
    } else {
        printf("ciphertext: '");

        p = ktask->out;
        p_end = p + ktask->out_size;

        while (p != p_end) {
            printf("%c", isprint(*p) ? *p : '.');
            p++;
        }

        printf("'\n");

        kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));
        ktask->out = NULL;
        ktask->out_size = 0;

        // TIP(Rafael): Try to tamper with ktask->in just by uncommenting the following line.
        //ktask->in[ktask->in_size >> 1] = ~ktask->in[ktask->in_size >> 1];

        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(aes256, ktask, key, strlen(key), kKryptosGCM);

        if (kryptos_last_task_succeed(ktask)) {
            printf("decrypted data: '");
            fwrite(ktask->out, 1, ktask->out_size, stdout);
            printf("'\n");
        } else {
            if (ktask->result_verbose != NULL) {
                printf("ERROR: %s\n", ktask->result_verbose);
            } else {
                printf("ERROR: What?\n");
            }
            exit_code = 1;
        }
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);

    return exit_code;
}
