/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_u8_t *tag[3] = { NULL, NULL, NULL }, *p, *p_end;
    // INFO(Rafael): You should never use parallelism greater than 1 because kryptos does not support multi-threading
    //               and due to it timing attacks can be done when using parallelism greater than 1.
    kryptos_u32_t parallelism = 1, tag_size = 32, memory_size_kb = 512, iterations = 50;
    int exit_code = 0;
    kryptos_u8_t *variant[3] = { "argon2d", "argon2i", "argon2id" };
    size_t i;

    tag[0] = kryptos_argon2d("Tales of Brave Ulysses", 22,
                             "salt", 4,
                             parallelism, tag_size, memory_size_kb, iterations,
                             "key", 3,
                             "associated data", 15);

    if (tag[0] == NULL) {
        printf("ERROR: when trying to expand the key by using argon2d.\n");
        exit_code = 1;
        goto epilogue;
    }

    tag[1] = kryptos_argon2i("Tales of Brave Ulysses", 11,
                             "salt", 4,
                             parallelism, tag_size, memory_size_kb, iterations,
                             "key", 3,
                             "associated data", 15);

    if (tag[1] == NULL) {
        printf("ERROR: when trying to expand the key by using argon2i.\n");
        exit_code = 1;
        goto epilogue;
    }

    tag[2] = kryptos_argon2id("Tales of Brave Ulysses", 11,
                              "salt", 4,
                              parallelism, tag_size, memory_size_kb, iterations,
                              "key", 3,
                              "associated data", 15);

    if (tag[2] == NULL) {
        printf("ERROR: when trying to expand the key by using argon2id.\n");
        exit_code = 1;
        goto epilogue;
    }

    for (i = 0; i < sizeof(variant) / sizeof(variant[0]); i++) {
        printf("%s resulting tag: ", variant[i]);
        p = tag[i];
        p_end = p + tag_size;
        while (p != p_end) {
            printf("%.2X", *p);
            p++;
        }
        printf("\n");
        kryptos_freeseg(tag[i], tag_size);
    }

epilogue:

    return exit_code;
}
