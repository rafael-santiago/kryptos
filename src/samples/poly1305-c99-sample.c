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
#include <stdio.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"Nao e possivel ser bom pela metade (Liev Tolstoi)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_u8_t *weak_key = (kryptos_u8_t *)"1234n41v3";
    size_t weak_key_size = strlen((char *)weak_key);
    kryptos_u8_t *p, *p_end;

    printf("Plaintext: '%s'\n", plaintext);

    kryptos_task_init_as_null(ktask);
    kryptos_task_set_in(ktask, plaintext, plaintext_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher_poly1305(aes128, ktask, weak_key, weak_key_size, kKryptosCBC);

    if (kryptos_last_task_succeed(ktask)) {
        p = ktask->out;
        p_end = p + ktask->out_size;
        printf("Authenticated ciphertext: ");
        while (p != p_end) {
            printf("%c", isprint(*p) ? *p : '.');
            p++;
        }
        printf("\n");
        // INFO(Rafael): Try to uncomment the following line.
        //ktask->out[ktask->out_size >> 1] += 1;
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        // INFO(Rafael): Try to uncomment the following line and comment the next one.
        //kryptos_run_cipher_poly1305(aes128, ktask, (kryptos_u8_t *)"wr0ngk3y", strlen("wr0ngk3y"), kKryptosCBC);
        kryptos_run_cipher_poly1305(aes128, ktask, weak_key, weak_key_size, kKryptosCBC);
        if (kryptos_last_task_succeed(ktask)) {
            printf("Decrypted authenticated data: '");
            fwrite(ktask->out, 1, ktask->out_size, stdout);
            printf("'\n");
            kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        } else {
            printf("Decryption error: %s\n", ktask->result_verbose);
        }
    }
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return EXIT_FAILURE;
#endif
}
