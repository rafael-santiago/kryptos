/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

#define PBKDF2_COUNT 20
#define PBKDF2_DK_SIZE 16

int main(int argc, char **argv) {
    char password[4096];
    kryptos_u8_t *dk, *d, *d_end;
    size_t dk_size, password_size;

    printf("Password: ");
    fgets(password, sizeof(password) - 1, stdin);

    if ((password_size = strlen(password)) > 0) {
        password[password_size--] = 0;
    }

    dk = kryptos_pbkdf2(password, password_size, whirlpool, "Salt", 4, PBKDF2_COUNT, PBKDF2_DK_SIZE);

    if (dk == NULL) {
        printf("ERROR: Unable to derive the user password.\n");
        return 1;
    }

    d = dk;
    d_end = d + 16;

    printf("Derived key: ");

    while (d != d_end) {
        printf("%c", isprint(*d) ? *d : '.');
        d++;
    }

    printf("\n");

    kryptos_freeseg(dk, 16);

    return 0;
}
