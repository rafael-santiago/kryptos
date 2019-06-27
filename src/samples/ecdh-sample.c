/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    // WARN: Never send out the exchange parameters without signing the data.
    //       This is just a simplified sample.
    struct kryptos_ecdh_xchg_ctx alice_ctx, bob_ctx, *alice = &alice_ctx, *bob = &bob_ctx;
    int exit_code = 0;

    kryptos_ecdh_init_xchg_ctx(alice);
    kryptos_ecdh_init_xchg_ctx(bob);

    alice->curve = kryptos_new_standard_curve(kBrainPoolP160R1);

    if (alice->curve == NULL) {
        printf("ERROR: when trying to load BrainpoolP160R1 curve.\n");
        exit_code = 1;
        goto epilogue;
    }

    // INFO: Alice's first step.

    kryptos_ecdh_process_xchg(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: during ECDH processing (Alice's side).\n");
        exit_code = 1;
        goto epilogue;
    }

    // WARN: Again, it would be signed before has sent.

    bob->in = alice->out;
    bob->in_size = alice->out_size;

    alice->out = NULL;

    // INFO: Bob's only step.

    kryptos_ecdh_process_xchg(&bob);

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: during ECDH processing (Bob's side).\n");
        exit_code = 1;
        goto epilogue;
    }

    // WARN: Again, it would be signed before has sent.

    alice->in = bob->out;
    alice->in_size = bob->out_size;

    bob->out = NULL;

    // INFO: Alice's final step.

    kryptos_ecdh_process_xchg(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: during ECDH processing (Alice's side, last step).\n");
        exit_code = 1;
        goto epilogue;
    }

    if (kryptos_mp_eq(alice->k, bob->k)) {
        printf("INFO: Alice and Bob have agreed a session key.\n");
        printf("      Key from Alice's context = "); kryptos_print_mp(alice->k);
        printf("      Key from Bob's context   = "); kryptos_print_mp(bob->k);
    } else {
        printf("ERROR: key agreement has failed.\n");
        exit_code = 1;
    }

epilogue:

    kryptos_clear_ecdh_xchg_ctx(alice);
    kryptos_clear_ecdh_xchg_ctx(bob);

    return exit_code;
}
