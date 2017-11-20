/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <kryptos_mp.h>
#include <stdio.h>

#define PRIME "PRIME"

int main(int argc, char **argv) {
    int exit_code = 0;
    kryptos_u8_t *pem_buffer = (kryptos_u8_t *)"-----BEGIN PRIME-----\n"
                                               "+TyfXiVPtBkAIRwp5ZDMN"
                                               "NOvx36w9DG0kQVWmbaeIm"
                                               "9VJanCQb+pTfbDTnCnnyZ"
                                               "10h4bibG6CKJFk75bYgL6"
                                               "QzveLHdQO2WIPhXLtv0U0"
                                               "8c0DRNdjZu9aRvvHj2RXi"
                                               "umUz5pVCbhQoeAv9YI1yx"
                                               "Ya+I4J+FNyMnwC6LKtRQG"
                                               "KAM=\n"
                                               "-----END PRIME-----\n";

    kryptos_mp_value_t *prime = NULL;
    int is_prime;

    if (kryptos_pem_get_mp_data(PRIME, pem_buffer, strlen((char *)pem_buffer), &prime) != kKryptosSuccess) {
        printf("Error while getting the prime number from buffer.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Number successfully loaded from the PEM buffer.\n");

    printf("By the way, this is the exact number loaded (in hexadecimal format) "); kryptos_print_mp(prime);

    printf("Now I am testing the primality of it, please wait...\n");

    is_prime = kryptos_mp_is_prime(prime);

    if (is_prime) {
        printf("The number is prime.\n");
    } else {
        printf("The number is not prime as expected.\n");
        exit_code = 1;
    }

epilogue:

    if (prime != NULL) {
        kryptos_del_mp_value(prime);
    }

    return exit_code;
}
