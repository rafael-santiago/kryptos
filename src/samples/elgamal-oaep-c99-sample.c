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
    int exit_code = 0;
    kryptos_u8_t *k_pub = "-----BEGIN ELGAMAL PARAM P-----\n"
                          "VRdEtMLDjy6jSMKvM83QDgAR1Y/2ZI9"
                          "rDvT4nmFFBoV9/0q5HA+29b3V54aBOv"
                          "G2Z31lqsfTWldx8AEnfs7N6gOlNmHC4"
                          "xoST0rv/80gjdb+Kc+LWQAjmsSpdWBJ"
                          "ZiAeBX7nZ4yyDFbFTTFiLvYwRj48YSr"
                          "KWnA7aJQwwcSLtQQ=\n"
                          "-----END ELGAMAL PARAM P-----\n"
                          "-----BEGIN ELGAMAL PARAM Q-----\n"
                          "SXShpt+AsZ2nSsm6W+sxh3wVqFY=\n"
                          "-----END ELGAMAL PARAM Q-----\n"
                          "-----BEGIN ELGAMAL PARAM G-----\n"
                          "RiMRb7ClUb6s0ibMlVIlpHA6uXTyZ4J"
                          "xwzKsNKpMNibCWurQMiW728/mh9krRL"
                          "1a1rxt0G0ZQJWKBbFbZxGoDOZQW1ltO"
                          "sJaibQBZ1WELtnN8HI581nJ3Np0sGXn"
                          "1CvsWm9CuCBroLCpFAVKDJFIwcdSZmD"
                          "KHPd/aworRwZANAQ=\n"
                          "-----END ELGAMAL PARAM G-----\n"
                          "-----BEGIN ELGAMAL PARAM B-----\n"
                          "mdIQuCFoT4nscK6AcpfkY0cCWmrVHGm"
                          "UTM3SDL3K0+0mFG6JkhhM0BcI3C7leH"
                          "UdMW6RD8vYq7qjcsGil6rNu1Ur4MQtw"
                          "0jtZhxYT8CQAJ0oH8XnwSCGWpgQedb4"
                          "ViGbiqtR0ZN7o3ScmSbd4o8EIzaVleW"
                          "BSy5Eb4B1aE2fwQE=\n"
                          "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *k_priv = "-----BEGIN ELGAMAL PARAM P-----\n"
                           "VRdEtMLDjy6jSMKvM83QDgAR1Y/2ZI9"
                           "rDvT4nmFFBoV9/0q5HA+29b3V54aBOv"
                           "G2Z31lqsfTWldx8AEnfs7N6gOlNmHC4"
                           "xoST0rv/80gjdb+Kc+LWQAjmsSpdWBJ"
                           "ZiAeBX7nZ4yyDFbFTTFiLvYwRj48YSr"
                           "KWnA7aJQwwcSLtQQ=\n"
                           "-----END ELGAMAL PARAM P-----\n"
                           "-----BEGIN ELGAMAL PARAM D-----\n"
                           "onkj9oCz4yimIihUZWsEoEVtl0M=\n"
                           "-----END ELGAMAL PARAM D-----\n";

    kryptos_u8_t *message = "The Man With The Dogs";
    size_t message_size = 21;
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *label = NULL;

    printf("*** ORIGINAL MESSAGE: '%s'\n", message);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    kryptos_task_set_in(alice, message, message_size);
    kryptos_task_set_encrypt_action(alice);
    kryptos_run_cipher(elgamal_oaep, alice, k_pub, strlen(k_pub),
                       label, NULL, kryptos_oaep_hash(sha384));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while encrypting. %s\n", alice->result_verbose);
        exit_code = 1;
        goto epilogue;
    }

    printf("*** CIPHERTEXT:\n\n%s\n", alice->out);

    kryptos_task_set_in(bob, alice->out, alice->out_size);
    kryptos_task_set_decrypt_action(bob);
    kryptos_run_cipher(elgamal_oaep, bob, k_priv, strlen(k_priv),
                       label, NULL, kryptos_oaep_hash(sha384));

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: while decrypting.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** PLAINTEXT: '%s'\n", bob->out);

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
}
