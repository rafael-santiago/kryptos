/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(void) {
    int exit_code = 0;
    kryptos_u8_t *k_pub = "-----BEGIN ECDSA P-----\n"
                          "D2IVlRPYs5Wtx99g3Flwc19KXuk=\n"
                          "-----END ECDSA P-----\n"
                          "-----BEGIN ECDSA A-----\n"
                          "AMP36JdddNq6Yb7idOuAouJ7DjQ=\n"
                          "-----END ECDSA A-----\n"
                          "-----BEGIN ECDSA B-----\n"
                          "WF5n2MiV7L0tqk8TEjRClYWaWB4=\n"
                          "-----END ECDSA B-----\n"
                          "-----BEGIN ECDSA Q-----\n"
                          "CfxgnkApUNSRWd9g3Flwc19KXuk=\n"
                          "-----END ECDSA Q-----\n"
                          "-----BEGIN ECDSA A X-----\n"
                          "w9u8vfda6zFGjJNiT2o/6hav1b4=\n"
                          "-----END ECDSA A X-----\n"
                          "-----BEGIN ECDSA A Y-----\n"
                          "IWPaFmOXnGZBR/k4w44aekfLZxY=\n"
                          "-----END ECDSA A Y-----\n"
                          "-----BEGIN ECDSA B X-----\n"
                          "C9yDV1KdKboG3FLz2hkjuxc6eHk=\n"
                          "-----END ECDSA B X-----\n"
                          "-----BEGIN ECDSA B Y-----\n"
                          "o2LrZwgxAjDmOYoV6d+BotCbuuE=\n"
                          "-----END ECDSA B Y-----\n";
    kryptos_u8_t *k_priv = "-----BEGIN ECDSA D-----\n"
                           "7DukDiEY0PFh2MuVORfJkudyJqE=\n"
                           "-----END ECDSA D-----\n"
                           "-----BEGIN ECDSA P-----\n"
                           "D2IVlRPYs5Wtx99g3Flwc19KXuk=\n"
                           "-----END ECDSA P-----\n"
                           "-----BEGIN ECDSA A-----\n"
                           "AMP36JdddNq6Yb7idOuAouJ7DjQ=\n"
                           "-----END ECDSA A-----\n"
                           "-----BEGIN ECDSA B-----\n"
                           "WF5n2MiV7L0tqk8TEjRClYWaWB4=\n"
                           "-----END ECDSA B-----\n"
                           "-----BEGIN ECDSA Q-----\n"
                           "CfxgnkApUNSRWd9g3Flwc19KXuk=\n"
                           "-----END ECDSA Q-----\n"
                           "-----BEGIN ECDSA A X-----\n"
                           "w9u8vfda6zFGjJNiT2o/6hav1b4=\n"
                           "-----END ECDSA A X-----\n"
                           "-----BEGIN ECDSA A Y-----\n"
                           "IWPaFmOXnGZBR/k4w44aekfLZxY=\n"
                           "-----END ECDSA A Y-----\n";
    kryptos_task_ctx a_ctx, b_ctx, *alice = &a_ctx, *bob = &b_ctx;
    kryptos_u8_t *message = "Never ever hardcode keys Bob!";

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("ORIGINAL MESSAGE:\n\n'%s'\n\n", message);

    // INFO(Rafael): Alice signs the message and sends it to Bob...

    kryptos_sign(ecdsa, alice, message, strlen(message), k_priv, strlen(k_priv), kryptos_ecdsa_hash(sha3_512));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: when signing the input.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("SIGNED MESSAGE:\n\n%s\n\n", alice->out);

    // INFO(Rafael): ... Now Bob verifies the authenticity of it...

    kryptos_verify(ecdsa, bob, alice->out, alice->out_size, k_pub, strlen(k_pub), kryptos_ecdsa_hash(sha3_512));

    if (!kryptos_last_task_succeed(bob)) {
        if (bob->result == kKryptosInvalidSignature) {
            // INFO(Rafael): Try to corrupt some parameter in the alice->out PEM buffer and you
            //               will fall into this branch.
            printf("SIGNATURE ERROR: %s\n", bob->result_verbose);
        } else {
            printf("GENERAL ERROR: when verifying signature.\n");
        }
    }

    printf("AUTHENTICATED MESSAGE:\n\n'");
    fwrite(bob->out, 1, bob->out_size, stdout);
    printf("'\n\n");

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
}
