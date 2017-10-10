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
#if defined(KRYPTOS_C99)
    kryptos_u8_t *k_pub_bob = "-----BEGIN RSA PARAM N-----\n"
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

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
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

    kryptos_u8_t *message = "This is shorter but still weak!\x00";
    size_t message_size = 32;
    kryptos_task_ctx a, b, *alice = &a, *bob = &b;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("Message: %s\n\n", message);

    kryptos_task_set_in(alice, message, message_size);
    kryptos_task_set_encrypt_action(alice);
    kryptos_run_cipher(rsa, alice, k_pub_bob, strlen(k_pub_bob));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while encrypting!\n");
        exit(1);
    }

    printf("Ciphertext:\n\n%s\n", alice->out);

    kryptos_task_set_in(bob, alice->out, alice->out_size);
    kryptos_task_set_decrypt_action(bob);
    kryptos_run_cipher(rsa, bob, k_priv_bob, strlen(k_priv_bob));

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: while decrypting!\n");
        exit(1);
    }

    printf("Plaintext: %s\n", bob->out);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return 0;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
