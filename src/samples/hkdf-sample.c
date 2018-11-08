/*
 *                                Copyright (C) 2018 by Rafael Santiago
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
    kryptos_u8_t temp[4096];
    kryptos_u8_t *key = NULL, *kp, *kp_end;
    size_t temp_size;

    printf("User key: ");

    fgets(temp, sizeof(temp) - 1, stdin);

    if ((temp_size = strlen(temp)) > 0) {
        temp[temp_size--] = 0;
    }

    key = kryptos_hkdf(temp, temp_size, sha3_256, "", 0, "", 0, 16);

    if (key != NULL) {
        kp = key;
        kp_end = kp + 16;

        printf("Effective key: ");

        while (kp != kp_end) {
            printf("%c", isprint(*kp) ? *kp : '.');
            kp++;
        }

        printf("\n");
        kryptos_freeseg(key, 16);
    }

    return 0;
}
