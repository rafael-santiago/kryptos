/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_u8_t *password = (kryptos_u8_t *)"1234";
    size_t password_size = 4;
    kryptos_u8_t *hash;
    size_t hash_size;
    kryptos_u8_t *salt;

    if ((salt = kryptos_get_random_block(16)) == NULL) {
        printf("Unable to generate a valid 16-byte salt.\n");
        return 1;
    }

    hash = kryptos_bcrypt(4, salt, 16, password, password_size, &hash_size);
    kryptos_freeseg(salt, 16);

    if (hash == NULL) {
        printf("Error!\n");
        return 1;
    } else {
        printf("Hashed password: ");
        fwrite(hash, 1, hash_size, stdout);
        printf("\n");
        if (kryptos_bcrypt_verify(password, password_size, hash, hash_size)) {
            printf("Valid password.\n");
        } else {
            printf("Invalid password.\n");
        }
    }

    return 0;
}
