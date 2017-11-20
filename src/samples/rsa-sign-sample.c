/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *message = (kryptos_u8_t *)"The Lost Art of Keeping a Secret";
    size_t message_size = 32;
    kryptos_u8_t *k_pub_alice =  (kryptos_u8_t *)"-----BEGIN RSA PARAM N-----\n"
                                                 "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                                                 "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                                                 "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                                                 "8otBSRve8Px5q3woN79T41r1Al9Pv"
                                                 "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                                                 "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                                                 "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                                                 "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                                                 "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                                                 "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                                                 "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                                                 "mjHRIDrsDl+415Rbc+upTDw==\n"
                                                 "-----END RSA PARAM N-----\n"
                                                 "-----BEGIN RSA PARAM E-----\n"
                                                 "b5ZwnpaLpdIdqDv3OLKfKSmGYm1YN"
                                                 "woU+4wsNZaSATDs7HcsH9gUEKykux"
                                                 "Me7aypsuNuzyxNaM+jOGRfMcC5W+7"
                                                 "YQJolurDZw9UV1WFdH0RtstcQpZDp"
                                                 "/x0/ZcXCDBOK0qjoalL43C2+Hpcw6"
                                                 "iaRjrtPGWksWAk6feWe/fAjdZaxA6"
                                                 "+jUjHdcMP064dpDhv188WfjkvXkvZ"
                                                 "kM5A/aUm+sQsc0QDzPeKI37TNrVL2"
                                                 "RfoJadeTxyoOERy8DX973UevG8oFp"
                                                 "tfJbTE5QSWn+gln6LA/cCaW07TGQp"
                                                 "eZ917BibntPDDrenOw+Ox8wN1yTCV"
                                                 "x3+tYL4amoEjaxvevM+SgBQ==\n"
                                                 "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = (kryptos_u8_t *)"-----BEGIN RSA PARAM N-----\n"
                                                 "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                                                 "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                                                 "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                                                 "8otBSRve8Px5q3woN79T41r1Al9Pv"
                                                 "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                                                 "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                                                 "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                                                 "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                                                 "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                                                 "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                                                 "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                                                 "mjHRIDrsDl+415Rbc+upTDw==\n"
                                                 "-----END RSA PARAM N-----\n"
                                                 "-----BEGIN RSA PARAM D-----\n"
                                                 "DxId/jUln36fB1XhFEtLf8d30+A6S"
                                                 "znf9rU923pkUqK7h34TuyuwmKHumO"
                                                 "lLXCGwGpzldMu2J+t6gP3WmTjuKNI"
                                                 "Hfq/BBd6G6Qh2aDeh4hdg+Iz0Y377"
                                                 "NV6mXqDhXELrs0oGBfsn0rARQV5rb"
                                                 "ugY2MqAttYhYf3hBDbTjkv20K4kqb"
                                                 "1uKS++/M3UlE/n3pbs5O50SLV0uCg"
                                                 "wzkmVZ3ii4k316hXc1wua9NnvVgAL"
                                                 "l1vXdVkpJo7mqQaBrSDKhgvovKWnp"
                                                 "t4NjIJRXkX1IgF0n1lUp1ph1A5Mm8"
                                                 "NJMiCwNn/LiIuw3nhUDOxD4U3U5Ra"
                                                 "j6lsWHu5edzYetSfSrSwHDw==\n"
                                                 "-----END RSA PARAM D-----\n";

    int exit_code = 0;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("*** MESSAGE: '");
    fwrite(message, message_size, 1, stdout);
    printf("'\n");

    alice->cipher = kKryptosCipherRSA;

    alice->in = message;
    alice->in_size = message_size;
    alice->key = k_priv_alice;
    alice->key_size = strlen((char *)k_priv_alice);

    kryptos_rsa_sign(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while signing the message.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** SIGNED OUTPUT:\n\n%s\n", alice->out);

    bob->cipher = kKryptosCipherRSA;
    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen((char *)k_pub_alice);

    kryptos_rsa_verify(&bob);

    if (!kryptos_last_task_succeed(bob)) {
        if (bob->result != kKryptosInvalidSignature) {
            printf("ERROR: invalid signature.\n");
        } else {
            printf("ERROR: while verifying the signature.\n");
        }
        exit_code = 1;
        goto epilogue;
    }

    printf("*** AUTHENTICATED OUTPUT: '");
    fwrite(bob->out, bob->out_size, 1, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
}
