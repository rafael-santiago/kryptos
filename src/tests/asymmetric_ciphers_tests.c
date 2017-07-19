/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "asymmetric_ciphers_tests.h"
#include <kryptos.h>
#include <kryptos_pem.h>
#include <string.h>

CUTE_TEST_CASE(kryptos_dh_get_modp_tests)
    struct modp_test_ctx {
        kryptos_dh_modp_group_bits_t bits;
        size_t expected_bitsize;
    };
    struct modp_test_ctx test_vector[] = {
            { kKryptosDHGroup1536, 1536 },
            { kKryptosDHGroup2048, 2048 },
            { kKryptosDHGroup3072, 3072 },
            { kKryptosDHGroup4096, 4096 },
            { kKryptosDHGroup6144, 6144 },
            { kKryptosDHGroup8192, 8192 }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    size_t t;
    kryptos_mp_value_t *p = NULL, *g = NULL;

    CUTE_ASSERT(kryptos_dh_get_modp(-1, &p, &g) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_dh_get_modp(kKryptosDHGroup1536, &p, NULL) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_dh_get_modp(kKryptosDHGroup1536, NULL, &g) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_dh_get_modp(kKryptosDHGroup1536, NULL, NULL) == kKryptosInvalidParams);

    for (t = 0; t < test_vector_nr; t++) {
        CUTE_ASSERT(kryptos_dh_get_modp(test_vector[t].bits, &p, &g) == kKryptosSuccess);
        CUTE_ASSERT(p != NULL);
        CUTE_ASSERT(g != NULL);
        CUTE_ASSERT(p->data_size == kryptos_mp_bit2byte(test_vector[t].expected_bitsize));
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(g);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_get_random_s_tests)
    kryptos_dh_modp_group_bits_t bits[] = {
        kKryptosDHGroup1536, kKryptosDHGroup3072, kKryptosDHGroup4096, kKryptosDHGroup6144, kKryptosDHGroup8192
    };
    size_t bits_nr = sizeof(bits) / sizeof(bits[0]), b;
    kryptos_mp_value_t *p = NULL, *g = NULL, *s = NULL;

    CUTE_ASSERT(kryptos_dh_get_random_s(NULL, NULL, 0) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_get_random_s(&s, NULL, 0) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_get_random_s(NULL, (kryptos_mp_value_t *)&b, 0) == kKryptosInvalidParams);

    for (b = 0; b < bits_nr; b++) {
        CUTE_ASSERT(kryptos_dh_get_modp(bits[b], &p, &g) == kKryptosSuccess);
        CUTE_ASSERT(kryptos_dh_get_random_s(&s, p, 0) == kKryptosSuccess);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(g);
        kryptos_del_mp_value(s);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_eval_t_tests)
    kryptos_dh_modp_group_bits_t bits[] = {
        kKryptosDHGroup1536, kKryptosDHGroup3072, kKryptosDHGroup4096, kKryptosDHGroup6144, kKryptosDHGroup8192
    };
    size_t bits_nr = sizeof(bits) / sizeof(bits[0]), b;
    kryptos_mp_value_t *p = NULL, *g = NULL, *s = NULL, *t = NULL;
    size_t bit_size = 256;

    CUTE_ASSERT(kryptos_dh_eval_t(NULL, NULL, NULL, NULL) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_eval_t(&t, NULL, NULL, NULL) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_eval_t(&t, NULL, (kryptos_mp_value_t *)&b, (kryptos_mp_value_t *)&b) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_eval_t(&t, (kryptos_mp_value_t *)&b, NULL, (kryptos_mp_value_t *)&b) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_eval_t(&t, (kryptos_mp_value_t *)&b, (kryptos_mp_value_t *)&b, NULL) == kKryptosInvalidParams);

    for (b = 0; b < bits_nr; b++) {
        CUTE_ASSERT(kryptos_dh_get_modp(bits[b], &p, &g) == kKryptosSuccess);
        if (CUTE_GET_OPTION("quick-dh-tests") != NULL) {
            // INFO(Rafael): Unrealistic bit size. However, faster for tests.
            bit_size = 8;
        }
        CUTE_ASSERT(kryptos_dh_get_random_s(&s, p, bit_size) == kKryptosSuccess);
        CUTE_ASSERT(kryptos_dh_eval_t(&t, g, s, p) == kKryptosSuccess);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(g);
        kryptos_del_mp_value(s);
        kryptos_del_mp_value(t);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_standard_key_exchange_bare_bone_tests)
    // INFO(Rafael): Here only the standard exchange implementation is simulated.
    kryptos_mp_value_t *g = NULL, *p = NULL;
    kryptos_mp_value_t *s_alice = NULL, *s_bob = NULL;
    kryptos_mp_value_t *t_alice = NULL, *t_bob = NULL;
    kryptos_mp_value_t *kab_alice = NULL, *kab_bob = NULL;

    // INFO(Rafael): Alice and Bob agree about a p and g.
    CUTE_ASSERT(kryptos_dh_get_modp(kKryptosDHGroup1536, &p, &g) == kKryptosSuccess);

    CUTE_ASSERT(p != NULL);
    CUTE_ASSERT(g != NULL);

    // INFO(Rafael): Alice picks one random value sa 1 <= sa <= p - 2.
    s_alice = kryptos_hex_value_as_mp("AA", 2); // WARN(Rafael): The Eve's dream.
    CUTE_ASSERT(s_alice != NULL);

    // INFO(Rafael): Bob picks one random value sb 1 <= sb <= p - 2.
    s_bob = kryptos_hex_value_as_mp("BB", 2); // WARN(Rafael): The Eve's dream.
    CUTE_ASSERT(s_bob != NULL);

    // INFO(Rafael): Alice calculates ta = g^sa mod p and she also sends her result to Bob.
    CUTE_ASSERT(kryptos_dh_eval_t(&t_alice, g, s_alice, p) == kKryptosSuccess);
    CUTE_ASSERT(t_alice != NULL);

    // INFO(Rafael): Bob calculates tb = g^sb mod p and he also sends his result to Alice.
    CUTE_ASSERT(kryptos_dh_eval_t(&t_bob, g, s_bob, p) == kKryptosSuccess);
    CUTE_ASSERT(t_bob != NULL);

    // INFO(Rafael): Alice calculates kab = tb^sa mod p.
    CUTE_ASSERT(kryptos_dh_eval_t(&kab_alice, t_bob, s_alice, p) == kKryptosSuccess);
    CUTE_ASSERT(kab_alice != NULL);

    // INFO(Rafael): Bob calculates kab = ta^sb mod p.
    CUTE_ASSERT(kryptos_dh_eval_t(&kab_bob, t_alice, s_bob, p) == kKryptosSuccess);
    CUTE_ASSERT(kab_bob != NULL);

    printf(" *** Alice KAB = "); kryptos_print_mp(kab_alice);
    printf(" *** Bob KAB   = "); kryptos_print_mp(kab_bob);

    CUTE_ASSERT(kryptos_mp_eq(kab_alice, kab_bob) == 1);

    kryptos_del_mp_value(g);
    kryptos_del_mp_value(p);
    kryptos_del_mp_value(s_alice);
    kryptos_del_mp_value(s_bob);
    kryptos_del_mp_value(t_alice);
    kryptos_del_mp_value(t_bob);
    kryptos_del_mp_value(kab_alice);
    kryptos_del_mp_value(kab_bob);

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_process_stdxchg_tests)
    // INFO(Rafael): Here we will test the "oracle" mode of the exchange process.
    struct kryptos_dh_xchg_ctx alice_stuff, bob_stuff, *alice = &alice_stuff, *bob = &bob_stuff;

    kryptos_dh_init_xchg_ctx(alice);
    kryptos_dh_init_xchg_ctx(bob);

    // INFO(Rafael): Alice will start the protocol. So she picks a pre-computed DH group.
    CUTE_ASSERT(kryptos_dh_get_modp(kKryptosDHGroup1536, &alice->p, &alice->g) == kKryptosSuccess);

    // INFO(Rafael): Mas... Alice é vida loka...
    alice->s_bits = 8;

    kryptos_dh_process_stdxchg(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->s != NULL);
    CUTE_ASSERT(alice->out != NULL);

    // INFO(Rafael): Now Alice got PEM data that she must send to Bob.
    bob->in = alice->out;
    bob->in_size = alice->out_size;

    // INFO(Rafael): Feito Alice, Bob é também um vida loka!!!
    bob->s_bits = 8;

    // INFO(Rafael): Once the PEM data received Bob process it.
    kryptos_dh_process_stdxchg(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->s != NULL);
    CUTE_ASSERT(bob->out != NULL);
    CUTE_ASSERT(bob->k != NULL);

    // INFO(Rafael): Now Bob got the value of t encoded as a PEM, so he sends it to Alice.
    alice->in = bob->out;
    alice->in_size = bob->out_size;

    // INFO(Rafael): Alice process the PEM data received from Bob.
    kryptos_dh_process_stdxchg(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->k != NULL);

    printf(" *** Alice KAB = "); kryptos_print_mp(alice->k);
    printf(" *** Bob   KAB = "); kryptos_print_mp(bob->k);

    CUTE_ASSERT(kryptos_mp_eq(alice->k, bob->k) == 1);

    alice->in = NULL;
    bob->in = NULL;

    kryptos_clear_dh_xchg_ctx(alice);
    kryptos_clear_dh_xchg_ctx(bob);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_mk_key_pair_tests)
    struct kryptos_dh_xchg_ctx key_ctx, *kp = &key_ctx;
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size, k_priv_size;
    kryptos_u8_t *pem_data;
    size_t pem_data_size;

    kryptos_dh_mk_key_pair(NULL, &k_pub_size, &k_priv, &k_priv_size, &kp);
    CUTE_ASSERT(kryptos_last_task_succeed(kp) != 1);

    kryptos_dh_mk_key_pair(&k_pub, NULL, &k_priv, &k_priv_size, &kp);
    CUTE_ASSERT(kryptos_last_task_succeed(kp) != 1);

    kryptos_dh_mk_key_pair(&k_pub, &k_pub_size, NULL, &k_priv_size, &kp);
    CUTE_ASSERT(kryptos_last_task_succeed(kp) != 1);

    kryptos_dh_mk_key_pair(&k_pub, &k_pub_size, &k_priv, NULL, &kp);
    CUTE_ASSERT(kryptos_last_task_succeed(kp) != 1);

    kryptos_dh_mk_key_pair(&k_pub, &k_pub_size, &k_priv, &k_priv_size, NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(kp) != 1);

    // INFO(Rafael): Preparing our context.
    kryptos_dh_init_xchg_ctx(kp);
    CUTE_ASSERT(kryptos_dh_get_modp(kKryptosDHGroup1536, &kp->p, &kp->g) == kKryptosSuccess);
    kp->s_bits = 8;

    kryptos_dh_mk_key_pair(&k_pub, &k_pub_size, &k_priv, &k_priv_size, &kp);

    CUTE_ASSERT(kryptos_last_task_succeed(kp) == 1);
    CUTE_ASSERT(k_pub != NULL);
    CUTE_ASSERT(k_pub_size != 0);
    CUTE_ASSERT(k_priv != NULL);
    CUTE_ASSERT(k_priv_size != 0);

    // INFO(Rafael): Verifying the public buffer, this must include: P, G and T but never S.

    pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_P, k_pub, k_pub_size, &pem_data_size);
    CUTE_ASSERT(pem_data != NULL && pem_data_size != 0);
    kryptos_freeseg(pem_data);

    pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_G, k_pub, k_pub_size, &pem_data_size);
    CUTE_ASSERT(pem_data != NULL && pem_data_size != 0);
    kryptos_freeseg(pem_data);

    pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_T, k_pub, k_pub_size, &pem_data_size);
    CUTE_ASSERT(pem_data != NULL && pem_data_size != 0);
    kryptos_freeseg(pem_data);

    pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_S, k_pub, k_pub_size, &pem_data_size);
    CUTE_ASSERT(pem_data == NULL);

    // INFO(Rafael): Verifying the private buffer, this must include S and also P.

    pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_S, k_priv, k_priv_size, &pem_data_size);
    CUTE_ASSERT(pem_data != NULL && pem_data_size != 0);
    kryptos_freeseg(pem_data);

    pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_P, k_priv, k_priv_size, &pem_data_size);
    CUTE_ASSERT(pem_data != NULL && pem_data_size != 0);
    kryptos_freeseg(pem_data);

    kryptos_clear_dh_xchg_ctx(kp);
    kryptos_freeseg(k_pub);
    kryptos_freeseg(k_priv);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_process_modxchg_tests)
    struct kryptos_dh_xchg_ctx alice_ctx, *alice = &alice_ctx, bob_ctx, *bob = &bob_ctx;
    kryptos_u8_t *k_pub_bob = NULL, *k_priv_bob = NULL;
    size_t k_pub_bob_size, k_priv_bob_size;

    // INFO(Rafael): Bob generates his key pair and send his public key to Alice. This must be done only once.

    kryptos_dh_init_xchg_ctx(bob);
    CUTE_ASSERT(kryptos_dh_get_modp(kKryptosDHGroup1536, &bob->p, &bob->g) == kKryptosSuccess);
    bob->s_bits = 8;

    kryptos_dh_mk_key_pair(&k_pub_bob, &k_pub_bob_size, &k_priv_bob, &k_priv_bob_size, &bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(k_pub_bob != NULL);
    CUTE_ASSERT(k_pub_bob_size != 0);
    CUTE_ASSERT(k_priv_bob != NULL);
    CUTE_ASSERT(k_priv_bob_size != 0);

    kryptos_clear_dh_xchg_ctx(bob);

    // INFO(Rafael): Now, Alice wants to communicate with Bob...

    kryptos_dh_init_xchg_ctx(alice);

    alice->in = k_pub_bob;
    alice->in_size = k_pub_bob_size;
    alice->s_bits = 8;

    kryptos_dh_process_modxchg(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->out != NULL && alice->out_size != 0);
    CUTE_ASSERT(alice->k != NULL);

    // INFO(Rafael): Alice gets the private key session K and also the public value U. She sends U to Bob.
    //               In order to successfully calculate the session K He also includes in his input his private key info.

    bob->in_size = alice->out_size + k_priv_bob_size;
    bob->in = (kryptos_u8_t *) kryptos_newseg(bob->in_size);
    CUTE_ASSERT(bob->in != NULL);
    memcpy(bob->in, alice->out, alice->out_size);
    memcpy(bob->in + alice->out_size, k_priv_bob, k_priv_bob_size);

    bob->s_bits = 8;

    kryptos_dh_process_modxchg(&bob);
    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->out == NULL && bob->out_size == 0); // INFO(Rafael): Bob does not need to send any data to Alice.
    CUTE_ASSERT(bob->k != NULL);

    // INFO(Rafael): Alice and Bob must agree each other about K.

    CUTE_ASSERT(kryptos_mp_eq(alice->k, bob->k) == 1);

    alice->in = NULL;

    kryptos_clear_dh_xchg_ctx(alice);
    kryptos_clear_dh_xchg_ctx(bob);
    kryptos_freeseg(k_pub_bob);
    kryptos_freeseg(k_priv_bob);

CUTE_TEST_CASE_END
