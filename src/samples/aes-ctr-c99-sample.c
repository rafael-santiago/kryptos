/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    int error = 0;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u32_t ctr = 9;
    kryptos_u8_t *plain = (kryptos_u8_t *)"But why don't you take him with you into the light? "
                          "He does not deserve the light, he deserves peace.";
    kryptos_u8_t *p, *p_end;
    size_t plain_size = strlen((char *)plain);
    kryptos_u8_t *key = (kryptos_u8_t *)"Fly Me To The Moon";
    size_t key_size = strlen((char *)key);

    kryptos_task_init_as_null(ktask);

    kryptos_task_set_in(ktask, plain, plain_size);
    kryptos_task_set_ctr_mode(ktask, &ctr);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, key, key_size, kKryptosCTR);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: %s\n", ktask->result_verbose);
        error = 1;
        goto epilogue;
    }

    p = ktask->out;
    p_end = p + ktask->out_size;

    printf("CRYPTOGRAM: ");

    while (p != p_end) {
        printf("%c", isprint(*p) ? *p : '.');
        p++;
    }

    printf("\n");

    printf("NEXT COUNTER VALUE: %d\n", ctr);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, key, key_size, kKryptosCTR);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: %s\n", ktask->result_verbose);
        error = 1;
        goto epilogue;
    }

    printf("PLAINTEXT: ");
    fwrite(ktask->out, ktask->out_size, 1, stdout);
    printf("\n");

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IV | KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return error;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
