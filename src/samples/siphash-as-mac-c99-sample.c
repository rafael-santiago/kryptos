/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MESSAGE "Two headed dog, two headed dog, I've been working in the Kremlin with two-headed dog."

int main(int argc, char **argv) {
    int exit_code = EXIT_FAILURE;
#if defined(KRYPTOS_C99)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *bad_hardcoded_key = (kryptos_u8_t *)"Red Temple Prayer";
    size_t bad_hardcoded_key_size = strlen((char *)bad_hardcoded_key);
    kryptos_u8_t *p = NULL, *p_end = NULL;

    kryptos_task_init_as_null(ktask);
    kryptos_task_set_in(ktask, (kryptos_u8_t *)MESSAGE, strlen(MESSAGE));
    printf("Message to authenticate and send: '%s'\n", ktask->in);

    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher_siphash(aes256, 8, 4, ktask, bad_hardcoded_key, bad_hardcoded_key_size, kKryptosOFB);

    if (kryptos_last_task_succeed(ktask)) {
        p = ktask->out;
        p_end = p + ktask->out_size;
        printf("Message with authentication code: ");
        while (p != p_end) {
            printf("%c", isprint(*p) ? *p : '.');
            p++;
        }
        printf("\n");
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        ktask->out = NULL;
        ktask->out_size = 0;
        kryptos_task_set_decrypt_action(ktask);
        // INFO(Rafael): Try to comment one of the following lines or even both.
        // bad_hardcoded_key_size <<= 1;
        // ktask->in[ktask->in_size >> 1] += 1;
        kryptos_run_cipher_siphash(aes256, 8, 4, ktask, bad_hardcoded_key, bad_hardcoded_key_size, kKryptosOFB);
        if (kryptos_last_task_succeed(ktask)) {
            p = ktask->out;
            p_end = p + ktask->out_size;
            printf("Authenticated plaintext: ");
            while (p != p_end) {
                printf("%c", isprint(*p) ? *p : '.');
                p++;
            }
            printf("\n");
        } else {
            printf("error: '%s'\n", (ktask->result_verbose != NULL) ? ktask->result_verbose : "Unexpected.");
        }
    } else {
        kryptos_task_set_in(ktask, NULL, 0);
        printf("error: '%s'\n", (ktask->result_verbose != NULL) ? ktask->result_verbose : "Unexpected.");
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
#else
    printf("warning: libkryptos was compiled without c99 support.");
#endif
    return exit_code;
}

#undef MESSAGE

