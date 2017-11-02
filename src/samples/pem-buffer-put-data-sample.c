/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

#define FIRST_NAME "FIRST"

#define SECOND_NAME "SECOND"

int main(int argc, char **argv) {
    kryptos_u8_t *pem_buffer = NULL;
    size_t pem_buffer_size;
    int exit_code = 0;

    if (kryptos_pem_put_data(&pem_buffer, &pem_buffer_size, SECOND_NAME,
                             "Bond", 4) != kKryptosSuccess) {
        printf("Error while putting data labeled as %s into buffer.\n", SECOND_NAME);
        exit_code = 1;
        goto epilogue;
    }

    printf("PEM:\n\n%s\n", pem_buffer);

    if (kryptos_pem_put_data(&pem_buffer, &pem_buffer_size, FIRST_NAME,
                             "James", 5) != kKryptosSuccess) {
        printf("Error while putting data labeled as %s into buffer.\n", FIRST_NAME);
    }

    printf("PEM:\n\n%s\n", pem_buffer);

epilogue:

    if (pem_buffer != NULL) {
        kryptos_freeseg(pem_buffer);
    }

    return exit_code;
}
