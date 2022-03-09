/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_u8_t *message = (kryptos_u8_t *)"\"I don't know why people are so keen to put the details of "
                            "their private life in public; they forget that invisibility "
                            "is a superpower.\" (Banksy)", *mp, *mp_end;
    size_t message_size = strlen((char *)message);
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = (kryptos_u8_t *)"123mudar*";

    kryptos_task_init_as_null(ktask);

    ktask->key = key;
    ktask->key_size = strlen((char *)key);

    printf("Original message: %s\n\n", message);

    ktask->out = (kryptos_u8_t *)kryptos_newseg(message_size);
    if (ktask->out == NULL) {
        printf("Error: Not enough memory.\n");
        return 1;
    }

    memcpy(ktask->out, message, message_size);
    ktask->out_size = message_size;
    kryptos_task_set_encrypt_action(ktask);

    kryptos_poly1305(&ktask);

    if (kryptos_last_task_succeed(ktask)) {
        mp = ktask->out;
        mp_end = mp + ktask->out_size;
        printf("MAC + nonce + message: ");
        while (mp != mp_end) {
            printf("%c", isprint(*mp) ? *mp : '.');
            mp++;
        }
        printf("\n\n");

        // INFO(Rafael): Wrong key will not authenticate.
        //ktask->key = "321mudei*";
        //ktask->key_size = strlen(ktask->key);

        // INFO(Rafael): Incomplete key will not authenticate.
        //ktask->key_size -= 1;

        kryptos_task_set_decrypt_action(ktask);
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        ktask->out = NULL;
        ktask->out_size = 0;

        // INFO(Rafael): Corrupted mac will not authenticate.
        //ktask->in[0] += 1;

        // INFO(Rafael): Corrupted message will not authenticate.
        //ktask->in[ktask->in_size >> 1] += 1;

        // INFO(Rafael): Incomplete message will not authenticate.
        //ktask->in_size -= 1;

        kryptos_poly1305(&ktask);

        if (kryptos_last_task_succeed(ktask)) {
            printf("Authenticated message: ");
            fwrite(ktask->in, 1, ktask->in_size, stdout);
            printf("\n");
        } else {
            printf("Error: %s\n", ktask->result_verbose);
        }
    } else {
        printf("Unexpected error: '%s'\n", ktask->result_verbose);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    return 0;
}
