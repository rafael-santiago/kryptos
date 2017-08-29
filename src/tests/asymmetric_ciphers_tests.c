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
#include <kryptos_padding.h>
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
    printf(" *** Bob   KAB = "); kryptos_print_mp(kab_bob);

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

    printf(" *** Alice KAB = "); kryptos_print_mp(alice->k);
    printf(" *** Bob   KAB = "); kryptos_print_mp(bob->k);

    // INFO(Rafael): Alice and Bob must agree each other about K.

    CUTE_ASSERT(kryptos_mp_eq(alice->k, bob->k) == 1);

    alice->in = NULL;

    kryptos_clear_dh_xchg_ctx(alice);
    kryptos_clear_dh_xchg_ctx(bob);
    kryptos_freeseg(k_pub_bob);
    kryptos_freeseg(k_priv_bob);

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_mk_key_pair_tests)
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size, k_priv_size;
    kryptos_rsa_mk_key_pair(80, &k_pub, &k_pub_size, &k_priv, &k_priv_size);
    CUTE_ASSERT(k_pub != NULL && k_priv != NULL);
    printf(" *** RSA PUBLIC KEY:\n\n");
    printf("%s", k_pub);
    printf("\n *** RSA PRIVATE KEY:\n\n");
    printf("%s", k_priv);
    kryptos_freeseg(k_pub);
    kryptos_freeseg(k_priv);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_cipher_tests)
    kryptos_u8_t *k_pub_bob = "-----BEGIN RSA PARAM N-----\n"
                              "1fqzrUbRB0Y1e0/4Mhxk5RaD0EFJs8JpEY6cwh2RQguccjk9yxeT4vF353cMUQQ17/GWGpz8glbKdCBI1j1SGw==\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "vyc/zlnghHEj1seRh3gDaY6NMRvenL3STs7DGOVcOqUHUt9K27WV0mzX3D7/D0+4lDarkXCpFWBSUCVjiBD7Cw==\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
                               "1fqzrUbRB0Y1e0/4Mhxk5RaD0EFJs8JpEY6cwh2RQguccjk9yxeT4vF353cMUQQ17/GWGpz8glbKdCBI1j1SGw==\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "31VGxn2s64+kcfyrAP6xeqr3ak9C72nGXf+NALlQnYOpVHH7V3agnX3U05xsc3DLReFS0Giz0N/736IUGqonCA==\n"
                               "-----END RSA PARAM D-----\n";

    kryptos_task_ctx a_kt, *a_ktask = &a_kt;
    kryptos_task_ctx b_kt, *b_ktask = &b_kt;
    kryptos_u8_t *m = "Hello Bob!\x00\x00\x00\x00\x00\x00";
    size_t m_size = 16;

    kryptos_task_init_as_null(a_ktask);
    kryptos_task_init_as_null(b_ktask);

    // INFO(Rafael): Alice sends a new message to Bob, so she picks Bob's public key.

    a_ktask->key = k_pub_bob;
    a_ktask->key_size = strlen(k_pub_bob);
    a_ktask->in = m;
    a_ktask->in_size = m_size;

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    a_ktask->cipher = kKryptosCipherRSA;
    kryptos_task_set_encrypt_action(a_ktask);
    kryptos_rsa_cipher(&a_ktask);

    CUTE_ASSERT(kryptos_last_task_succeed(a_ktask) == 1);

    printf(" *** CIPHERTEXT:\n\n%s\n\n", a_ktask->out);

    // INFO(Rafael): Now Alice sends the encrypted buffer to Bob.

    b_ktask->in = a_ktask->out;
    b_ktask->in_size = a_ktask->out_size;

    // INFO(Rafael): Bob uses his private key to get the original message.

    b_ktask->key = k_priv_bob;
    b_ktask->key_size = strlen(k_priv_bob);

    b_ktask->cipher = kKryptosCipherRSA;
    kryptos_task_set_decrypt_action(b_ktask);
    kryptos_rsa_cipher(&b_ktask);

    CUTE_ASSERT(kryptos_last_task_succeed(b_ktask) == 1);

    CUTE_ASSERT(b_ktask->out != NULL);

    printf(" *** PLAINTEXT:\n\n'%s'\n\n", b_ktask->out);

    CUTE_ASSERT(b_ktask->out_size == m_size);
    CUTE_ASSERT(memcmp(b_ktask->out, m, m_size) == 0);

    kryptos_task_free(a_ktask, KRYPTOS_TASK_OUT);
    kryptos_task_free(b_ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_cipher_c99_tests)
#ifdef KRYPTOS_C99
    kryptos_u8_t *k_pub_alice = "-----BEGIN RSA PARAM N-----\n"
                                "q/agiHElaTH+B056kexqvlrlHcbr4c8lF2lvFdH6VnrdyZCRYxYVJS1wixnxrUeMpJ7l2g+hEHYlgRxM3xrGaA==\n"
                                "-----END RSA PARAM N-----\n"
                                "-----BEGIN RSA PARAM E-----\n"
                                "Q9mxxs0+nosV5jzwUs1UmYEhXLrYAszE9q0S3hljhpXD9ANvkzCUC5nM8FZ3+44V1IrPhIYZYDwfSrGlhwG4Aw==\n"
                                "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN RSA PARAM N-----\n"
                                 "q/agiHElaTH+B056kexqvlrlHcbr4c8lF2lvFdH6VnrdyZCRYxYVJS1wixnxrUeMpJ7l2g+hEHYlgRxM3xrGaA==\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM D-----\n"
                                 "K04+KEU3GyG2ABjJu+sTqV5yH8mgO8aIPdygWvBq9GzJfTmLt18cck2pc7y6lmYLsl+NxgFo7KTliwXAjU3eGg==\n"
                                 "-----END RSA PARAM D-----\n";

    kryptos_task_ctx a_kt, *a_ktask = &a_kt;
    kryptos_task_ctx b_kt, *b_ktask = &b_kt;
    kryptos_u8_t *m = "Hello Alice!\x00\x00\x00\x00";
    size_t m_size = 16;

    kryptos_task_init_as_null(a_ktask);
    kryptos_task_init_as_null(b_ktask);

    // INFO(Rafael): Bob sends a new message to Alice, so he picks Alice's public key.

    kryptos_task_set_in(b_ktask, m, m_size);
    kryptos_task_set_encrypt_action(b_ktask);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_run_cipher(rsa, b_ktask, k_pub_alice, strlen(k_pub_alice));

    CUTE_ASSERT(kryptos_last_task_succeed(b_ktask) == 1);

    printf(" *** CIPHERTEXT:\n\n%s\n\n", b_ktask->out);

    // INFO(Rafael): Now Bob sends the encrypted buffer to Alice.

    kryptos_task_set_in(a_ktask, b_ktask->out, b_ktask->out_size);

    // INFO(Rafael): Alice uses her private key to get the original message.

    kryptos_task_set_decrypt_action(a_ktask);
    kryptos_run_cipher(rsa, a_ktask, k_priv_alice, strlen(k_priv_alice));

    CUTE_ASSERT(kryptos_last_task_succeed(a_ktask) == 1);

    CUTE_ASSERT(a_ktask->out != NULL);

    printf(" *** PLAINTEXT:\n\n'%s'\n\n", a_ktask->out);

    CUTE_ASSERT(a_ktask->out_size == m_size);
    CUTE_ASSERT(memcmp(a_ktask->out, m, m_size) == 0);

    kryptos_task_free(a_ktask, KRYPTOS_TASK_OUT);
    kryptos_task_free(b_ktask, KRYPTOS_TASK_OUT);
#else
    printf("WARN: No c99 support, this test was skipped.\n");
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_oaep_mgf_tests)
    // WARN(Rafael): Assuming that SHA-1/256 implementation are working well.
    struct oaep_mgf_tests {
        const kryptos_u8_t *seed;
        const size_t seed_size;
        const size_t len;
        kryptos_hash_func hash_func;
        const kryptos_u8_t *expected_out;
    };
    struct oaep_mgf_tests test_vector[] = {
        { "foo", 3,  3,   kryptos_sha1_hash, "\x1A\xC9\x07"          },
        { "foo", 3,  5,   kryptos_sha1_hash, "\x1A\xC9\x07\x5C\xD4"  },
        { "bar", 3,  5,   kryptos_sha1_hash, "\xBC\x0C\x65\x5E\x01"  },
        { "bar", 3, 50,   kryptos_sha1_hash, "\xBC\x0C\x65\x5E\x01"
                                             "\x6B\xC2\x93\x1D\x85"
                                             "\xA2\xE6\x75\x18\x1A"
                                             "\xDC\xEF\x7F\x58\x1F"
                                             "\x76\xDF\x27\x39\xDA"
                                             "\x74\xFA\xAC\x41\x62"
                                             "\x7B\xE2\xF7\xF4\x15"
                                             "\xC8\x9E\x98\x3F\xD0"
                                             "\xCE\x80\xCE\xD9\x87"
                                             "\x86\x41\xCB\x48\x76" },
        { "bar", 3, 50, kryptos_sha256_hash, "\x38\x25\x76\xA7\x84"
                                             "\x10\x21\xCC\x28\xFC"
                                             "\x4C\x09\x48\x75\x3F"
                                             "\xB8\x31\x20\x90\xCE"
                                             "\xA9\x42\xEA\x4C\x4E"
                                             "\x73\x5D\x10\xDC\x72"
                                             "\x4B\x15\x5F\x9F\x60"
                                             "\x69\xF2\x89\xD6\x1D"
                                             "\xAC\xA0\xCB\x81\x45"
                                             "\x02\xEF\x04\xEA\xE1" }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_u8_t *out;
    size_t out_size;

    for (t = 0; t < test_vector_nr; t++) {
        out = kryptos_oaep_mgf(test_vector[t].seed, test_vector[t].seed_size,
                               test_vector[t].len,
                               test_vector[t].hash_func,
                               &out_size);
        CUTE_ASSERT(out != NULL);
        CUTE_ASSERT(out_size == test_vector[t].len);
        CUTE_ASSERT(memcmp(out, test_vector[t].expected_out, out_size) == 0);
        kryptos_freeseg(out);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_oaep_padding_tests)
    struct oaep_padding_tests {
        kryptos_u8_t *buffer;
        size_t buffer_size;
        size_t k;
        kryptos_u8_t *l;
        size_t l_size;
        kryptos_hash_func hash;
        kryptos_hash_size_func hash_size;
        int corrupt_it;
    };
    struct oaep_padding_tests test_vector[] = {
        { "(null)", 6, 128, NULL, 0, kryptos_sha1_hash, kryptos_sha1_hash_size, 0 },
        { "(null)", 6, 128, NULL, 0, NULL, NULL, 0 },
        { "foobar", 6, 128, "", 0, kryptos_sha1_hash, kryptos_sha1_hash_size, 0 },
        { "alabaster", 9,  96, "L", 1, kryptos_sha224_hash, kryptos_sha224_hash_size, 0 },
        { "you got a killer scene there, man...", 36, 256, "QoTSA", 5, kryptos_sha256_hash, kryptos_sha256_hash_size, 0 },
        { "Givin'Up Food For Funk", 22, 512, "TheJ.B.'s", 9, kryptos_sha384_hash, kryptos_sha384_hash_size, 0 },
        { "stray Cat strut", 15, 1024, "meow!", 5, kryptos_sha512_hash, kryptos_sha512_hash_size, 0 },
        { "stones in my passway", 20, 128, "RJ", 2, kryptos_md4_hash, kryptos_md4_hash_size, 0 },
        { "Get Back", 8, 512, "jojo", 4, kryptos_md5_hash, kryptos_md5_hash_size, 0 },
        { "I Put A Spell On You", 20, 80, "Nina", 4, kryptos_ripemd128_hash, kryptos_ripemd128_hash_size, 0 },
        { "Space Cadet", 11, 1024, "TheCoyoteWhoSpokeInTongues", 26, kryptos_ripemd160_hash, kryptos_ripemd160_hash_size, 0 },
        { "Funky President (People It's Bad)", 33, 128, "Mr.Dynamite", 11, kryptos_sha1_hash, kryptos_sha1_hash_size, 1 },
        { "Boom Boom", 9, 256, "HowHowHowHow", 12, kryptos_sha224_hash, kryptos_sha224_hash_size, 1 },
        { "First Day Of My Life", 20, 96, "", 0, kryptos_sha256_hash, kryptos_sha256_hash_size, 1 },
        { "Come On, Let's Go", 17, 1024, "LittleDarling", 13, kryptos_sha384_hash, kryptos_sha384_hash_size, 1 },
        { "Sexual Healing", 14, 512, "Babe", 4, kryptos_sha512_hash, kryptos_sha512_hash_size, 1 },
        { "First It Giveth", 15, 128, "...ThanITakeItAway", 18, kryptos_md4_hash, kryptos_md4_hash_size, 1 },
        { "Easy as It Seems", 16, 2048, "Mavericks", 9, kryptos_md5_hash, kryptos_md5_hash_size, 1 },
        { "Have You Ever Seen The Rain", 27, 128, "", 0, kryptos_ripemd128_hash, kryptos_ripemd128_hash_size, 1 },
        { "I Know You Got Soul", 19, 256, "L", 1, kryptos_ripemd160_hash, kryptos_ripemd160_hash_size, 1 },
        { "(null)", 6, 128, NULL, 0, kryptos_sha1_hash, kryptos_sha1_hash_size, 1 },
        { "(null)", 6, 128, NULL, 0, NULL, NULL, 1 }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_u8_t *padded_message = NULL, *message = NULL;
    size_t padded_message_size = 0, message_size = 0;

    for (t = 0; t < test_vector_nr; t++) {
        padded_message_size = test_vector[t].buffer_size;
        padded_message = kryptos_apply_oaep_padding(test_vector[t].buffer,
                                                    &padded_message_size,
                                                    test_vector[t].k,
                                                    test_vector[t].l,
                                                    test_vector[t].l_size,
                                                    test_vector[t].hash,
                                                    test_vector[t].hash_size);
        CUTE_ASSERT(padded_message != NULL);

        if (test_vector[t].corrupt_it) {
            padded_message[padded_message_size >> 1] = ~padded_message[padded_message_size >> 1];
        }

        message = kryptos_drop_oaep_padding(padded_message,
                                            &padded_message_size,
                                            test_vector[t].k,
                                            test_vector[t].l,
                                            test_vector[t].l_size,
                                            test_vector[t].hash,
                                            test_vector[t].hash_size);

        if (test_vector[t].corrupt_it) {
            CUTE_ASSERT(message == NULL);
        } else {
            CUTE_ASSERT(message != NULL);
            CUTE_ASSERT(padded_message_size == test_vector[t].buffer_size);
            CUTE_ASSERT(memcmp(message, test_vector[t].buffer, padded_message_size) == 0);
            kryptos_freeseg(message);
        }

        kryptos_freeseg(padded_message);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_oaep_cipher_tests)
    kryptos_u8_t *k_pub_bob = "-----BEGIN RSA PARAM N-----\n"
                              "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoVg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "o13jdPAiis0sJZeh0OL9jL8Tib/EgoVNLqNXCM966j1qD4yq5KcXgrDezI48lxWDn66cZnppeXGfK8d0ym8U85JsXVgV2ao45ESDnBQFoRSoeQ3p3QVqDzfgViMeHIinMzFxx/OYpSgxpuQq4em4CwrBkqn1DxlRCzNCrdAqiwo=\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
                               "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoVg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "D3fMDiyVdMeojcOJuo4rB8CdgjNrxS2M9eORsLeiI6t+AiQpsE9LDlk62xHRAKfvX42RDkrlnr1g6PY3shIuPKcSfqLcl+Sdvt3NHzRLM8CEgJSWrUu919xo/IUKhFyFdN5ClYwpvaXaK/MVM1AV8gihLHpEsQT9gNfTgwDrVxU=\n"
                               "-----END RSA PARAM D-----\n";

    kryptos_task_ctx a_kt, *a_ktask = &a_kt;
    kryptos_task_ctx b_kt, *b_ktask = &b_kt;
    kryptos_u8_t *m = "Hello Bob!";
    size_t m_size = 10;
    kryptos_u8_t *l = "L";
    size_t l_size = 1;

    // INFO(Rafael): Case without corrupting data.

    kryptos_task_init_as_null(a_ktask);
    kryptos_task_init_as_null(b_ktask);

    // INFO(Rafael): Alice sends a new message to Bob, so she picks Bob's public key.

    a_ktask->key = k_pub_bob;
    a_ktask->key_size = strlen(k_pub_bob);
    a_ktask->arg[0] = l;
    a_ktask->arg[1] = &l_size;
    a_ktask->arg[2] = kryptos_sha1_hash;
    a_ktask->arg[3] = kryptos_sha1_hash_size;
    a_ktask->in = m;
    a_ktask->in_size = m_size;

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    a_ktask->cipher = kKryptosCipherRSAOAEP;
    kryptos_task_set_encrypt_action(a_ktask);
    kryptos_rsa_oaep_cipher(&a_ktask);

    CUTE_ASSERT(kryptos_last_task_succeed(a_ktask) == 1);

    printf(" *** CIPHERTEXT:\n\n%s\n\n", a_ktask->out);

    // INFO(Rafael): Now Alice sends the encrypted buffer to Bob.

    b_ktask->in = a_ktask->out;
    b_ktask->in_size = a_ktask->out_size;

    // INFO(Rafael): Bob uses his private key to get the original message.

    b_ktask->key = k_priv_bob;
    b_ktask->key_size = strlen(k_priv_bob);
    b_ktask->arg[0] = l;
    b_ktask->arg[1] = &l_size;
    b_ktask->arg[2] = kryptos_sha1_hash;
    b_ktask->arg[3] = kryptos_sha1_hash_size;

    b_ktask->cipher = kKryptosCipherRSAOAEP;
    kryptos_task_set_decrypt_action(b_ktask);
    kryptos_rsa_oaep_cipher(&b_ktask);

    CUTE_ASSERT(kryptos_last_task_succeed(b_ktask) == 1);

    CUTE_ASSERT(b_ktask->out != NULL);

    printf(" *** PLAINTEXT:\n\n'%s'\n\n", b_ktask->out);

    CUTE_ASSERT(b_ktask->out_size == m_size);
    CUTE_ASSERT(memcmp(b_ktask->out, m, m_size) == 0);

    kryptos_task_free(a_ktask, KRYPTOS_TASK_OUT);
    kryptos_task_free(b_ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Case with corrupted data.

    kryptos_task_init_as_null(a_ktask);
    kryptos_task_init_as_null(b_ktask);

    // INFO(Rafael): Alice sends a new message to Bob, so she picks Bob's public key.

    a_ktask->key = k_pub_bob;
    a_ktask->key_size = strlen(k_pub_bob);
    a_ktask->arg[0] = l;
    a_ktask->arg[1] = &l_size;
    a_ktask->arg[2] = kryptos_sha1_hash;
    a_ktask->arg[3] = kryptos_sha1_hash_size;
    a_ktask->in = m;
    a_ktask->in_size = m_size;

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    a_ktask->cipher = kKryptosCipherRSAOAEP;
    kryptos_task_set_encrypt_action(a_ktask);
    kryptos_rsa_oaep_cipher(&a_ktask);

    CUTE_ASSERT(kryptos_last_task_succeed(a_ktask) == 1);

    printf(" *** CIPHERTEXT:\n\n%s\n\n", a_ktask->out);

    // INFO(Rafael): For some reason during the transfer the cryptogram becomes corrupted.
    a_ktask->out[a_ktask->out_size >> 1] = ~a_ktask->out[a_ktask->out_size >> 1];
    printf(" ( the cryptogram was intentionally corrupted )\n\n");

    // INFO(Rafael): Now Alice sends the encrypted buffer to Bob.

    b_ktask->in = a_ktask->out;
    b_ktask->in_size = a_ktask->out_size;

    // INFO(Rafael): Bob uses his private key to get the original message.

    b_ktask->key = k_priv_bob;
    b_ktask->key_size = strlen(k_priv_bob);
    b_ktask->arg[0] = l;
    b_ktask->arg[1] = &l_size;
    b_ktask->arg[2] = kryptos_sha1_hash;
    b_ktask->arg[3] = kryptos_sha1_hash_size;

    b_ktask->cipher = kKryptosCipherRSAOAEP;
    kryptos_task_set_decrypt_action(b_ktask);
    kryptos_rsa_oaep_cipher(&b_ktask);

    CUTE_ASSERT(kryptos_last_task_succeed(b_ktask) == 0);

    CUTE_ASSERT(b_ktask->out == NULL);
    CUTE_ASSERT(b_ktask->out_size == 0);

    printf(" *** PLAINTEXT:\n\n (null)\n\n");

    printf(" *** Nice, the unexpected cryptogram was successfully detected => '%s'.\n", b_ktask->result_verbose);

    kryptos_task_free(a_ktask, KRYPTOS_TASK_OUT);
    kryptos_task_free(b_ktask, KRYPTOS_TASK_OUT);

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_oaep_cipher_c99_tests)
#ifdef KRYPTOS_C99
    kryptos_u8_t *k_pub_alice = "-----BEGIN RSA PARAM N-----\n"
                                "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoVg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                                "-----END RSA PARAM N-----\n"
                                "-----BEGIN RSA PARAM E-----\n"
                                "o13jdPAiis0sJZeh0OL9jL8Tib/EgoVNLqNXCM966j1qD4yq5KcXgrDezI48lxWDn66cZnppeXGfK8d0ym8U85JsXVgV2ao45ESDnBQFoRSoeQ3p3QVqDzfgViMeHIinMzFxx/OYpSgxpuQq4em4CwrBkqn1DxlRCzNCrdAqiwo=\n"
                                "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN RSA PARAM N-----\n"
                                 "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoVg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM D-----\n"
                                 "D3fMDiyVdMeojcOJuo4rB8CdgjNrxS2M9eORsLeiI6t+AiQpsE9LDlk62xHRAKfvX42RDkrlnr1g6PY3shIuPKcSfqLcl+Sdvt3NHzRLM8CEgJSWrUu919xo/IUKhFyFdN5ClYwpvaXaK/MVM1AV8gihLHpEsQT9gNfTgwDrVxU=\n"
                                 "-----END RSA PARAM D-----\n";

    kryptos_task_ctx a_kt, *a_ktask = &a_kt;
    kryptos_task_ctx b_kt, *b_ktask = &b_kt;
    kryptos_u8_t *m = "Hello Alice!";
    size_t m_size = 12;
    kryptos_u8_t *l = "L";
    size_t l_size = 1;

    // INFO(Rafael): Case without corrupting data.

    kryptos_task_init_as_null(a_ktask);
    kryptos_task_init_as_null(b_ktask);

    // INFO(Rafael): Bob sends a new message to Alice, so he picks Alice's public key.

    kryptos_task_set_in(b_ktask, m, m_size);
    kryptos_task_set_encrypt_action(b_ktask);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_run_cipher(rsa_oaep, b_ktask, k_pub_alice, strlen(k_pub_alice), l, &l_size,
                       kryptos_sha1_hash, kryptos_sha1_hash_size);

    CUTE_ASSERT(kryptos_last_task_succeed(b_ktask) == 1);

    printf(" *** CIPHERTEXT:\n\n%s\n\n", b_ktask->out);

    // INFO(Rafael): Now Bob sends the encrypted buffer to Alice.

    kryptos_task_set_in(a_ktask, b_ktask->out, b_ktask->out_size);

    // INFO(Rafael): Alice uses her private key to get the original message.

    kryptos_task_set_decrypt_action(a_ktask);
    kryptos_run_cipher(rsa_oaep, a_ktask, k_priv_alice, strlen(k_priv_alice), l, &l_size,
                       kryptos_sha1_hash, kryptos_sha1_hash_size);

    CUTE_ASSERT(kryptos_last_task_succeed(a_ktask) == 1);

    CUTE_ASSERT(a_ktask->out != NULL);

    printf(" *** PLAINTEXT:\n\n'%s'\n\n", a_ktask->out);

    CUTE_ASSERT(a_ktask->out_size == m_size);
    CUTE_ASSERT(memcmp(a_ktask->out, m, m_size) == 0);

    kryptos_task_free(a_ktask, KRYPTOS_TASK_OUT);
    kryptos_task_free(b_ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Case with corrupted data.

    kryptos_task_init_as_null(a_ktask);
    kryptos_task_init_as_null(b_ktask);

    // INFO(Rafael): Bob sends a new message to Alice, so he picks Alice's public key.

    kryptos_task_set_in(b_ktask, m, m_size);
    kryptos_task_set_encrypt_action(b_ktask);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_run_cipher(rsa_oaep, b_ktask, k_pub_alice, strlen(k_pub_alice), l, &l_size,
                       kryptos_sha1_hash, kryptos_sha1_hash_size);

    CUTE_ASSERT(kryptos_last_task_succeed(b_ktask) == 1);

    printf(" *** CIPHERTEXT:\n\n%s\n\n", b_ktask->out);

    // INFO(Rafael): For some reason during the transfer the cryptogram becomes corrupted.
    b_ktask->out[b_ktask->out_size >> 1] = ~b_ktask->out[b_ktask->out_size >> 1];
    printf(" ( the cryptogram was intentionally corrupted )\n\n");

    // INFO(Rafael): Now Bob sends the encrypted buffer to Alice.

    kryptos_task_set_in(a_ktask, b_ktask->out, b_ktask->out_size);

    // INFO(Rafael): Alice uses her private key to get the original message.

    kryptos_task_set_decrypt_action(a_ktask);
    kryptos_run_cipher(rsa_oaep, a_ktask, k_priv_alice, strlen(k_priv_alice), l, &l_size,
                       kryptos_sha1_hash, kryptos_sha1_hash_size);

    CUTE_ASSERT(kryptos_last_task_succeed(a_ktask) == 0);

    CUTE_ASSERT(a_ktask->out == NULL);
    CUTE_ASSERT(a_ktask->out_size == 0);

    printf(" *** PLAINTEXT:\n\n (null)\n\n");

    printf(" *** Nice, the unexpected cryptogram was successfully detected => '%s'.\n", a_ktask->result_verbose);

    kryptos_task_free(a_ktask, KRYPTOS_TASK_OUT);
    kryptos_task_free(b_ktask, KRYPTOS_TASK_OUT);

#else
    printf("WARN: No c99 support, this test was skipped.\n");
#endif
CUTE_TEST_CASE_END
