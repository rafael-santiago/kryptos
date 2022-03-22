/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *write_in_c = (kryptos_u8_t *)"When I find my code in tons of trouble,\n"
                               "Friends and colleagues come to me,\n"
                               "Speaking words of wisdom:\n"
                               "Write in C.\n\n"
                               " -- Write in C(\"Let it Be\")\n";

    kryptos_task_init_as_null(ktask);

    kryptos_hash(blake2b512, ktask, write_in_c, strlen((char *)write_in_c), 1);

    printf("Unkeyed hash: %s\n", ktask->out);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->key = (kryptos_u8_t *)"John Paul Ritchie";
    ktask->key_size = strlen((char *)ktask->key);

    kryptos_hash(blake2b512, ktask, write_in_c, strlen((char *)write_in_c), 1);

    printf("Keyed hash:   %s\n", ktask->out);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return 0;
}
