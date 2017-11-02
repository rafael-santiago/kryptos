/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

#define SECOND_NAME "SECOND"

#define FIRST_NAME "FIRST"

int main(int argc, char **argv) {
    int exit_code = 0;
    kryptos_u8_t *pem_buffer = "-----BEGIN SECOND-----\n"
                               "Qm9uZA==\n"
                               "-----END SECOND-----\n"
                               "-----BEGIN FIRST-----\n"
                               "SmFtZXM=\n"
                               "-----END FIRST-----\n";

    kryptos_u8_t *first = NULL, *second = NULL;
    size_t first_size, second_size, pem_buffer_size = strlen(pem_buffer);

    second = kryptos_pem_get_data(SECOND_NAME, pem_buffer, pem_buffer_size, &second_size);

    if (second == NULL) {
        printf("Error while getting data labeled as %s from buffer.\n", SECOND_NAME);
        exit_code = 1;
        goto epilogue;
    }

    first = kryptos_pem_get_data(FIRST_NAME, pem_buffer, pem_buffer_size, &first_size);

    if (first == NULL) {
        printf("Error while getting data labeled as %s from buffer.\n", FIRST_NAME);
        exit_code = 1;
        goto epilogue;
    }

    printf("My name is ");

    fwrite(second, second_size, 1, stdout);

    printf(", ");

    fwrite(first, first_size, 1, stdout);

    printf(" ");

    fwrite(second, second_size, 1, stdout);

    printf(".\n");

epilogue:

    if (second != NULL) {
        kryptos_freeseg(second);
    }

    if (first != NULL) {
        kryptos_freeseg(first);
    }

    return exit_code;
}
