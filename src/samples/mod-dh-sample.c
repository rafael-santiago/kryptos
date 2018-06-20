/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    struct kryptos_dh_xchg_ctx alice_data, bob_data, *alice = &alice_data, *bob = &bob_data;
    kryptos_u8_t *k_pub_bob = NULL, *k_priv_bob = NULL;
    size_t k_pub_bob_size = 0, k_priv_bob_size = 0;
    int exit_code = 0;

    // INFO(Rafael): Always initializing the dh_xchg_ctx is a best practice.

    kryptos_dh_init_xchg_ctx(bob);
    kryptos_dh_init_xchg_ctx(alice);

    // INFO(Rafael): Let's use some standarnized prime and generator again in this sample.

    if (kryptos_dh_get_modp(kKryptosDHGroup1536, &bob->p, &bob->g) != kKryptosSuccess) {
        exit_code = 1;
        printf("ERROR: while getting P and G parameters.\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Bob defines the size in bits of his random secret value and then he makes a key pair
    //               based on p, g and s.
    //
    //               Actually it will generate a fourth value t what should be published by him.

    bob->s_bits = 160;

    kryptos_dh_mk_key_pair(&k_pub_bob, &k_pub_bob_size, &k_priv_bob, &k_priv_bob_size, &bob);

    if (!kryptos_last_task_succeed(bob)) {
        exit_code = 1;
        printf("ERROR: while generating the key pair.\n");
        goto main_epilogue;
    }

    kryptos_clear_dh_xchg_ctx(bob);

    // INFO(Rafael): Bob should make public the data in k_pub_bob and save safely the data in k_priv_bob.

    // INFO(Rafael): Now let's suppose that Alice wants to communicate with Bob. She must put the public key
    //               info from Bob in her input task buffer and also picks a size in bits for her [s]ecret s
    //               value.

    alice->in = k_pub_bob;
    alice->in_size = k_pub_bob_size;
    alice->s_bits = 160;

    // INFO(Rafael): Notice that she needs to call kryptos_dh_process_modxchg() instead of
    //               kryptos_dh_process_stdxchg().

    kryptos_dh_process_modxchg(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        exit_code = 1;
        printf("ERROR: while modified dh was processing [Alice's side].\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Alice has already the session key but she must send to Bob her produced output. Thus,
    //               Bob will also got the same session key.

    // INFO(Rafael): By his side, Bob must append the received data from Alice with his private key data.
    //               This involves mere pointer math loved by any true C programmer ;)

    bob->in_size = alice->out_size + k_priv_bob_size;
    bob->in = (kryptos_u8_t *) kryptos_newseg(bob->in_size);

    if (bob->in == NULL) {
        exit_code = 1;
        printf("ERROR: no memory to produce the input.\n");
        goto main_epilogue;
    }

    if (memcpy(bob->in, alice->out, alice->out_size) != bob->in) {
        exit_code = 1;
        printf("ERROR: during input copy.\n");
        goto main_epilogue;
    }

    if (memcpy(bob->in + alice->out_size, k_priv_bob, k_priv_bob_size) != (bob->in + alice->out_size)) {
        exit_code = 1;
        printf("ERROR: during input copy.\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Bob picks again a size in bits for his [s]ecret s value.

    bob->s_bits = 160;

    // INFO(Rafael): Having defined the data from Alice appended with his private key information and also
    //               the size in bits of his s, all that Bob should do is call kryptos_dh_process_modxchg().

    kryptos_dh_process_modxchg(&bob);

    if (!kryptos_last_task_succeed(bob)) {
        exit_code = 1;
        printf("ERROR: while modified dh was processing [Bob's side].\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Now all indicate that Alice and Bob have agreed about k and this value can be accessed
    //               by them into their task contexts by the field 'k'.

    if (alice->k->data_size == bob->k->data_size &&
        memcmp(alice->k->data, bob->k->data, alice->k->data_size) == 0) {
        alice->in = NULL;
        bob->in = NULL;
        printf("SUCCESS: Alice and Bob have agreed about a session key.\n");
    } else {
        printf("ERROR: The k values between Alice and Bob are not the same.\n");
    }

main_epilogue:

    kryptos_clear_dh_xchg_ctx(bob);
    kryptos_clear_dh_xchg_ctx(alice);

    if (k_pub_bob != NULL) {
        kryptos_freeseg(k_pub_bob, k_pub_bob_size);
    }

    if (k_priv_bob != NULL) {
        kryptos_freeseg(k_priv_bob, k_priv_bob_size);
    }

    k_priv_bob_size = k_pub_bob_size = 0;

    return exit_code;
}
