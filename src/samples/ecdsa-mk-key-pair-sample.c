/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size, k_priv_size;
    kryptos_curve_ctx *curve = NULL;
    int exit_code = 0;

    if ((curve = kryptos_new_standard_curve(kBrainPoolP160R1)) == NULL) {
        printf("ERROR: on curve data loading.\n");
        exit_code = 1;
        goto epilogue;
    }

    if (kryptos_ecdsa_mk_key_pair(curve, &k_pub, &k_pub_size, &k_priv, &k_priv_size) != kKryptosSuccess) {
        printf("ERROR: on key pair calculation.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** PUBLIC KEY:\n\n%s\n*** PRIVATE KEY:\n\n%s\n", k_pub, k_priv);

epilogue:

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub, k_pub_size);
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv, k_priv_size);
    }

    if (curve != NULL) {
        kryptos_del_curve_ctx(curve);
    }

    return exit_code;
}

