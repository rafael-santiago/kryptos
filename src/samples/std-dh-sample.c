/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    struct kryptos_dh_xchg_ctx alice_data, bob_data, *alice = &alice_data, *bob = &bob_data;
    int exit_code = 1;

    // INFO(Rafael): The actors should initialize their data contexts.

    kryptos_dh_init_xchg_ctx(alice);
    kryptos_dh_init_xchg_ctx(bob);

    // INFO(Rafael): Inside the kryptos_dh_xchg_ctx there are two meaningful fields called 'p' and 'g'.
    //               You can generate your own primes if you want to. However, kryptos has built-in
    //               standarnized primes and generators based on RFC-3526, and in this sample we will
    //               use them.

    if (kryptos_dh_get_modp(kKryptosDHGroup1536, &alice->p, &alice->g) != kKryptosSuccess) {
        printf("ERROR: Unexpected error during prime and generator loading.\n");
        return 1;
    }

    // INFO(Rafael): Alice defines the size in bits of her secret random number.
    alice->s_bits = 160;

    // INFO(Rafael): Now Alice processes the setup data.

    printf("INFO: Alice is processing...\n");

    kryptos_dh_process_stdxchg(&alice);

    if (!kryptos_last_task_succeed(alice) || alice->s == NULL || alice->out == NULL) {
        printf("ERROR: Error during exchange process. (1)\n");
        kryptos_clear_dh_xchg_ctx(alice);
        goto main_epilogue;
    }

    // INFO(Rafael): The s field inside 'alice' context is [S]ecret, the out field should be sent to bob.
    //               This data is automatically generated as PEM format.
    //               Bob receives in his input the Alice's output.

    printf("INFO: Alice -> Bob\n");

    bob->in = alice->out;
    bob->in_size = alice->out_size;

    // INFO(Rafael): Bob also defines the size in bits of his secret random number.
    bob->s_bits = 160;

    // INFO(Rafael): Now Bob passes to kryptos_dh_process_stdxchg() "oracle" his input

    printf("INFO: Bob is processing...\n");

    kryptos_dh_process_stdxchg(&bob);

    if (!kryptos_last_task_succeed(bob) || bob->s == NULL || bob->out == NULL || bob->k == NULL) {
        printf("ERROR: Error during exchange process. (2)\n");
        kryptos_clear_dh_xchg_ctx(alice);
        kryptos_clear_dh_xchg_ctx(bob);
        goto main_epilogue;
    }

    // INFO(Rafael): Now Bob should send back his output to Alice.
    //               Bob already got k, Alice will get it soon.

    printf("INFO: Bob got a k value.\n");
    printf("INFO: Bob -> Alice\n");

    alice->in = bob->out;
    alice->in_size = bob->out_size;

    // INFO(Rafael): Now Alice passes to "oracle" the output received from bob in her input.

    printf("INFO: Alice is processing...\n");

    kryptos_dh_process_stdxchg(&alice);

    printf("INFO: Alice got a k value.\n");

    if (!kryptos_last_task_succeed(alice) || alice->k == NULL) {
        printf("ERROR: Error during exchange process. (3)\n");
        kryptos_clear_dh_xchg_ctx(alice);
        kryptos_clear_dh_xchg_ctx(bob);
        return exit_code;
    }

    if (alice->k->data_size == bob->k->data_size &&
        memcmp(alice->k->data, bob->k->data, alice->k->data_size) == 0) {
        alice->in = NULL;
        bob->in = NULL;
        printf("SUCCESS: Alice and Bob have agreed about a session key.\n");
    } else {
        printf("ERROR: The k values between Alice and Bob are not the same.\n");
    }

    exit_code = 0;

main_epilogue:

    kryptos_clear_dh_xchg_ctx(alice);
    kryptos_clear_dh_xchg_ctx(bob);


    return exit_code;
}
