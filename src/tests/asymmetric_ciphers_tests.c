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

static int corrupt_pem_data(const kryptos_u8_t *hdr, kryptos_u8_t *pem_data, const size_t pem_data_size);

static int corrupt_pem_data(const kryptos_u8_t *hdr, kryptos_u8_t *pem_data, const size_t pem_data_size) {
    kryptos_u8_t *data = NULL;
    size_t data_size;
    kryptos_u8_t *dp, *dp_end, swp = 0, *temp;
    const kryptos_u8_t *hp, *hp_end;
    int found = 0;

    dp = pem_data;
    dp_end = pem_data + pem_data_size;

    hp_end = hdr + strlen(hdr);

    while (dp != dp_end && !found) {
        found = 1;
        temp = dp + 1;

        hp = hdr;

        while (found && hp != hp_end && dp != dp_end) {
            found = (*dp == *hp);
            dp++;
            hp++;
        }

        if (!found) {
            dp = temp;
        }
    }

    if (!found) {
        return 0;
    }

    while (*dp != '\n' && dp != dp_end) {
        dp++;
    }

    if (dp == dp_end) {
        return 0;
    }

    dp++;

    temp = dp;
    while (*temp != '\n' && temp != dp_end) {
        temp++;
    }

    if (temp == dp_end) {
        return 0;
    }

    dp_end = dp + ((temp - dp) >> 1);

    while (dp < dp_end) {
        swp = *dp;
        *dp = *(dp + 1);
        *(dp + 1) = swp;
        dp += 2;
    }

    return 1;
}

CUTE_TEST_CASE(kryptos_verify_dl_params_tests)
    kryptos_mp_value_t *p = NULL, *q = NULL, *g = NULL;

    // INFO(Rafael): It should pass.

    g = kryptos_hex_value_as_mp("3C", 2);
    q = kryptos_hex_value_as_mp("2F", 2);
    p = kryptos_hex_value_as_mp("11B", 3);

    CUTE_ASSERT(p != NULL && q != NULL && g != NULL);

    CUTE_ASSERT(kryptos_verify_dl_params(p, q, g) == kKryptosSuccess);

    // INFO(Rafael): It should fail due to g's nullity.

    CUTE_ASSERT(kryptos_verify_dl_params(p, q, NULL) == kKryptosInvalidParams);

    // INFO(Rafael): It should fail due to q's nullity.

    CUTE_ASSERT(kryptos_verify_dl_params(p, NULL, g) == kKryptosInvalidParams);

    // INFO(Rafael): It should fail due to p's nullity.

    CUTE_ASSERT(kryptos_verify_dl_params(NULL, q, g) == kKryptosInvalidParams);

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(g);

    // INFO(Rafael): It should fail due to g.

    g = kryptos_hex_value_as_mp("0", 1);
    q = kryptos_hex_value_as_mp("2F", 2);
    p = kryptos_hex_value_as_mp("11B", 3);

    CUTE_ASSERT(p != NULL && q != NULL && g != NULL);

    CUTE_ASSERT(kryptos_verify_dl_params(p, q, g) == kKryptosInvalidParams);

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(g);

    // INFO(Rafael): It should fail due to g.

    g = kryptos_hex_value_as_mp("11C", 3);
    q = kryptos_hex_value_as_mp("2F", 2);
    p = kryptos_hex_value_as_mp("11B", 3);

    CUTE_ASSERT(p != NULL && q != NULL && g != NULL);

    CUTE_ASSERT(kryptos_verify_dl_params(p, q, g) == kKryptosInvalidParams);

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(g);

    // INFO(Rafael): It should fail due to q.

    g = kryptos_hex_value_as_mp("3C", 2);
    q = kryptos_hex_value_as_mp("2A", 2);
    p = kryptos_hex_value_as_mp("11B", 3);

    CUTE_ASSERT(p != NULL && q != NULL && g != NULL);

    CUTE_ASSERT(kryptos_verify_dl_params(p, q, g) == kKryptosInvalidParams);

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(g);

    // INFO(Rafael): It should fail due to p.

    g = kryptos_hex_value_as_mp("3C", 2);
    q = kryptos_hex_value_as_mp("2F", 2);
    p = kryptos_hex_value_as_mp("11A", 3);

    CUTE_ASSERT(p != NULL && q != NULL && g != NULL);

    CUTE_ASSERT(kryptos_verify_dl_params(p, q, g) == kKryptosInvalidParams);

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(g);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_generate_dl_params_tests)
    // WARN(Rafael): If the kryptos_verify_dl_params() is broken: "you shall not pass".
    kryptos_mp_value_t *p = NULL, *q = NULL, *g = NULL;

    CUTE_ASSERT(kryptos_generate_dl_params(80, 40, &p, &q, NULL) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_generate_dl_params(80, 40, &p, NULL, &g) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_generate_dl_params(80, 40, NULL, &q, &g) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_generate_dl_params(64, 32, &p, &q, &g) == kKryptosSuccess);

    printf(" P = "); kryptos_print_mp(p);
    printf(" Q = "); kryptos_print_mp(q);
    printf(" G = "); kryptos_print_mp(g);

    CUTE_ASSERT(p != NULL);
    CUTE_ASSERT(q != NULL);
    CUTE_ASSERT(g != NULL);

    // INFO(Rafael): Internally it was checked but let's make sure here too.
    CUTE_ASSERT(kryptos_verify_dl_params(p, q, g) == kKryptosSuccess);

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(g);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_mk_domain_params_tests)
    kryptos_u8_t *params = NULL;
    size_t params_size = 0;
    kryptos_u8_t *data = NULL;
    size_t data_size = 0;

    CUTE_ASSERT(kryptos_dh_mk_domain_params(0, 32, &params, &params_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_mk_domain_params(64, 0, &params, &params_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_mk_domain_params(64, 32, NULL, &params_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_mk_domain_params(64, 32, &params, NULL) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_dh_mk_domain_params(64, 32, &params, &params_size) == kKryptosSuccess);

    CUTE_ASSERT(params != NULL);
    CUTE_ASSERT(params_size > 0);

    printf(" *** DH DOMAIN PARAMETERS:\n\n%s", params);

    data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_P, params, params_size, &data_size);

    CUTE_ASSERT(data != NULL);

    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_Q, params, params_size, &data_size);

    CUTE_ASSERT(data != NULL);

    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_G, params, params_size, &data_size);

    CUTE_ASSERT(data != NULL);

    kryptos_freeseg(data);

    kryptos_freeseg(params);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_verify_domain_params_tests)
    kryptos_u8_t *valid_params = "-----BEGIN DH PARAM P-----\n"
                                 "r0JMxbGO+Cg=\n"
                                 "-----END DH PARAM P-----\n"
                                 "-----BEGIN DH PARAM Q-----\n"
                                 "O/IVlg==\n"
                                 "-----END DH PARAM Q-----\n"
                                 "-----BEGIN DH PARAM G-----\n"
                                 "gEAAVxKjmgI=\n"
                                 "-----END DH PARAM G-----\n";

    kryptos_u8_t *invalid_params = "-----BEGIN DH PARAM P-----\n"
                                   "Ko87iBqGQEI=\n"
                                   "-----END DH PARAM P-----\n"
                                   "-----BEGIN DH PARAM Q-----\n"
                                   "Y/hBcA==\n"
                                   "-----END DH PARAM Q-----\n"
                                   "-----BEGIN DH PARAM G-----\n"
                                   "tOOCDE3FHCU=\n"
                                   "-----END DH PARAM G-----\n";

    CUTE_ASSERT(kryptos_dh_verify_domain_params(valid_params, 0) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_verify_domain_params(NULL, 1) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_dh_verify_domain_params(valid_params, strlen(valid_params)) == kKryptosSuccess);

    CUTE_ASSERT(kryptos_dh_verify_domain_params(invalid_params, strlen(invalid_params)) == kKryptosInvalidParams);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dh_get_modp_from_params_buf_tests)
    kryptos_u8_t *valid_params = "-----BEGIN DH PARAM P-----\n"
                                 "r0JMxbGO+Cg=\n"
                                 "-----END DH PARAM P-----\n"
                                 "-----BEGIN DH PARAM Q-----\n"
                                 "O/IVlg==\n"
                                 "-----END DH PARAM Q-----\n"
                                 "-----BEGIN DH PARAM G-----\n"
                                 "gEAAVxKjmgI=\n"
                                 "-----END DH PARAM G-----\n";

    kryptos_u8_t *no_p_param = "-----BEGIN DH PARAM Q-----\n"
                               "O/IVlg==\n"
                               "-----END DH PARAM Q-----\n"
                               "-----BEGIN DH PARAM G-----\n"
                               "gEAAVxKjmgI=\n"
                               "-----END DH PARAM G-----\n";

    kryptos_u8_t *no_g_param = "-----BEGIN DH PARAM P-----\n"
                               "r0JMxbGO+Cg=\n"
                               "-----END DH PARAM P-----\n"
                               "-----BEGIN DH PARAM Q-----\n"
                               "O/IVlg==\n"
                               "-----END DH PARAM Q-----\n";

    // CLUE(Rafael): It was intentional.
    kryptos_mp_value_t *p = (kryptos_mp_value_t *)valid_params,
                       *q = (kryptos_mp_value_t *)valid_params,
                       *g = (kryptos_mp_value_t *)valid_params;

    CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(NULL, 1, &p, NULL, &g) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(no_p_param, 0, &p, NULL, &g) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(no_p_param, 1, NULL, NULL, &g) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(no_p_param, 1, &p, &q, NULL) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(no_p_param, strlen(no_p_param), &p, NULL, &g) != kKryptosSuccess);
    CUTE_ASSERT(p == NULL && g == NULL);

    CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(no_g_param, strlen(no_g_param), &p, &q, &g) != kKryptosSuccess);
    CUTE_ASSERT(p == NULL && g == NULL && q == NULL);

    CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(valid_params, strlen(valid_params), &p, &q, &g) == kKryptosSuccess);
    CUTE_ASSERT(p != NULL && g != NULL && q != NULL);

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(g);

    p = g = NULL;

    CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(valid_params, strlen(valid_params), &p, NULL, &g) == kKryptosSuccess);
    CUTE_ASSERT(p != NULL && g != NULL);

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(g);
CUTE_TEST_CASE_END

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
    kryptos_mp_value_t *g = NULL, *p = NULL, *q = NULL;
    kryptos_mp_value_t *s_alice = NULL, *s_bob = NULL;
    kryptos_mp_value_t *t_alice = NULL, *t_bob = NULL;
    kryptos_mp_value_t *kab_alice = NULL, *kab_bob = NULL;
    kryptos_u8_t *domain_parameters = "-----BEGIN DH PARAM P-----\n"
                                      "VSsW7ufPMgFn+MceQyQHgBtpq/q/"
                                      "xLAZ00q/hRh8Of7Wvto1lsS6iBWs"
                                      "mz4mYiSiOiPZkv6asUoBF8JhxMs4"
                                      "LHEGaTV0uiRzIPxOABkXDGUnXjwd"
                                      "EfpwkG3H+EuZK9fINggkkS+cxJ+P"
                                      "DwkaoMgpwZEZj+ieeeOSnZgKuvaN"
                                      "pVQ=\n"
                                      "-----END DH PARAM P-----\n"
                                      "-----BEGIN DH PARAM Q-----\n"
                                      "Xdy01wlOrsxucvEv7bz+7VBT9X0=\n"
                                      "-----END DH PARAM Q-----\n"
                                      "-----BEGIN DH PARAM G-----\n"
                                      "PdxLwCCBNeXR4EnVZb30SOHClBpr"
                                      "bfJkZs3WHyct4mbI71Yo6tqFLXZZ"
                                      "ozZCnP9ijWpsfz9qsfrcifcixEb0"
                                      "Ewd+Xf3ne3sHVrFwC/VLCAAi1Ccc"
                                      "a4GqzyO5juyIdjn2Bx8hWvV4E0G0"
                                      "jgP58tlcjSNYP2lJj7TGafmyom44"
                                      "Zxg=\n"
                                      "-----END DH PARAM G-----\n";
    kryptos_mp_value_t *_2 = NULL, *q_2 = NULL;


    printf("*** Using MODP from RFC-3526.\n\n");

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

    // INFO(Rafael): Now using the "homemade" domain parameters. They were well generated (strong primes) so let's
    //               assume that Alice and Bob verified those parameters.

    printf("\n*** Using pre-computed domain parameters.\n\n");

    p = g = s_alice = s_bob = NULL;

    // INFO(Rafael): Alice picks one random value sa.
    if (CUTE_GET_OPTION("dh-use-q-size") != NULL) {
        CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(domain_parameters,
                                                        strlen(domain_parameters), &p, &q, &g) == kKryptosSuccess);



        CUTE_ASSERT(p != NULL);
        CUTE_ASSERT(q != NULL);
        CUTE_ASSERT(g != NULL);

        _2 = kryptos_hex_value_as_mp("2", 1);
        CUTE_ASSERT(_2 != NULL);

        q_2 = kryptos_assign_mp_value(&q_2, q);
        CUTE_ASSERT(q_2 != NULL);

        q_2 = kryptos_mp_sub(&q_2, _2);
        CUTE_ASSERT(q_2 != NULL);

        do {
            if (s_alice != NULL) {
                kryptos_del_mp_value(s_alice);
            }

            // INFO(Rafael): Let's use the recommended random value size. This is linked to q size i.e. 160 bits -> [2, q-2].
            //               This is a bare-bone test so we will explicitly generate a 160-bit random value.
            s_alice = kryptos_mp_rand(160);

            CUTE_ASSERT(s_alice != NULL);
        } while (kryptos_mp_lt(s_alice, _2) || kryptos_mp_gt(s_alice, q_2));
    } else {
        CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(domain_parameters,
                                                        strlen(domain_parameters), &p, NULL, &g) == kKryptosSuccess);

        CUTE_ASSERT(p != NULL);
        CUTE_ASSERT(g != NULL);

        s_alice = kryptos_hex_value_as_mp("AA", 2); // WARN(Rafael): The Eve's dream.
        CUTE_ASSERT(s_alice != NULL);
    }

    // INFO(Rafael): Bob picks one random value sb.
    if (CUTE_GET_OPTION("dh-use-q-size") != NULL) {
        do {
            if (s_bob != NULL) {
                kryptos_del_mp_value(s_bob);
            }

            // INFO(Rafael): Let's use the recommended random value size. This is linked to q size i.e. 160 bits -> [2, q-2].
            //               This is a bare-bone test so we will explicitly generate a 160-bit random value.
            s_bob = kryptos_mp_rand(160);

            CUTE_ASSERT(s_bob != NULL);
        } while (kryptos_mp_lt(s_bob, _2) || kryptos_mp_gt(s_bob, q_2));

        kryptos_del_mp_value(_2);
        kryptos_del_mp_value(q_2);

        q_2 = _2 = NULL;
    } else {
        s_bob = kryptos_hex_value_as_mp("BB", 2); // WARN(Rafael): The Eve's dream.
        CUTE_ASSERT(s_bob != NULL);
    }

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
    if (CUTE_GET_OPTION("dh-use-q-size") != NULL) {
        kryptos_del_mp_value(q);
    }
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
    kryptos_u8_t *domain_parameters = "-----BEGIN DH PARAM P-----\n"
                                      "q/1geMTHBhklSLEP9NVV3Z3KH54E"
                                      "hi8L4/ImBDydLH+WtLacIcNy5bzW"
                                      "ZYyFbfIKgD+mzbTWYLMkv8MR54O4"
                                      "5qTMKGCAk/CifUw351HC/UNnBWi+"
                                      "ZajlIJ1vjegceCWynu9wsoO/9wH1"
                                      "sCtFJifH0zfMG8i53PB9kUeXa/bo"
                                      "T5E=\n"
                                      "-----END DH PARAM P-----\n"
                                      "-----BEGIN DH PARAM Q-----\n"
                                      "tx047pscx/Il1QIIVVnlwXD66bI=\n"
                                      "-----END DH PARAM Q-----\n"
                                      "-----BEGIN DH PARAM G-----\n"
                                      "kxvfCyqImE9Gr1F4dhZtPqGOAyjd"
                                      "wsObgGUueIrI6Pz71dCOyE1Jtmgh"
                                      "Knl8ygGDb9Xj3MjglpijVi+2th4W"
                                      "UZrE5BbJlBTza1rPjnvHjODGgy0Y"
                                      "GzviMegv6kI986kndWqJRfwQ7REi"
                                      "uTNjasdut36Ejvpj/r98zDZA5gg+"
                                      "gE0=\n"
                                      "-----END DH PARAM G-----\n";

    kryptos_dh_init_xchg_ctx(alice);
    kryptos_dh_init_xchg_ctx(bob);

    printf("*** Using MODP from RFC-3526.\n\n");

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

    printf("\n*** Using the pre-computed domain parameters.\n\n");

    kryptos_dh_init_xchg_ctx(alice);
    kryptos_dh_init_xchg_ctx(bob);

    // INFO(Rafael): Alice will start the protocol. So she picks a pre-computed DH group.
    if (CUTE_GET_OPTION("dh-use-q-size") == NULL) {
        CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(domain_parameters,
                                                        strlen(domain_parameters),
                                                        &alice->p, NULL, &alice->g) == kKryptosSuccess);
    } else {
        CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(domain_parameters,
                                                        strlen(domain_parameters),
                                                        &alice->p, &alice->q, &alice->g) == kKryptosSuccess);
    }

    CUTE_ASSERT(alice->p != NULL);
    if (CUTE_GET_OPTION("dh-use-q-size") != NULL) {
        // INFO(Rafael): This options states that Alice will use a value between [2, q-2], a 160-bit value.
        CUTE_ASSERT(alice->q != NULL);
    }
    CUTE_ASSERT(alice->g != NULL);

    if (CUTE_GET_OPTION("dh-use-q-size") == NULL) {
        // INFO(Rafael): Mas... Alice é vida loka...
        alice->s_bits = 8;
    }

    kryptos_dh_process_stdxchg(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->s != NULL);
    CUTE_ASSERT(alice->out != NULL);

    // INFO(Rafael): Now Alice got PEM data that she must send to Bob.
    bob->in = alice->out;
    bob->in_size = alice->out_size;

    if (CUTE_GET_OPTION("dh-use-q-size") == NULL) {
        // INFO(Rafael): Feito Alice, Bob é também um vida loka!!!
        bob->s_bits = 8;
    }

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
    kryptos_u8_t *domain_parameters = "-----BEGIN DH PARAM P-----\n"
                                      "VSsW7ufPMgFn+MceQyQHgBtpq/q/"
                                      "xLAZ00q/hRh8Of7Wvto1lsS6iBWs"
                                      "mz4mYiSiOiPZkv6asUoBF8JhxMs4"
                                      "LHEGaTV0uiRzIPxOABkXDGUnXjwd"
                                      "EfpwkG3H+EuZK9fINggkkS+cxJ+P"
                                      "DwkaoMgpwZEZj+ieeeOSnZgKuvaN"
                                      "pVQ=\n"
                                      "-----END DH PARAM P-----\n"
                                      "-----BEGIN DH PARAM Q-----\n"
                                      "Xdy01wlOrsxucvEv7bz+7VBT9X0=\n"
                                      "-----END DH PARAM Q-----\n"
                                      "-----BEGIN DH PARAM G-----\n"
                                      "PdxLwCCBNeXR4EnVZb30SOHClBpr"
                                      "bfJkZs3WHyct4mbI71Yo6tqFLXZZ"
                                      "ozZCnP9ijWpsfz9qsfrcifcixEb0"
                                      "Ewd+Xf3ne3sHVrFwC/VLCAAi1Ccc"
                                      "a4GqzyO5juyIdjn2Bx8hWvV4E0G0"
                                      "jgP58tlcjSNYP2lJj7TGafmyom44"
                                      "Zxg=\n"
                                      "-----END DH PARAM G-----\n";

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

    // INFO(Rafael): The following test is based on MODP from RFC-3526. No Q value is expected.

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

    // INFO(Rafael): Now we will use domain parameters pre-computed including a q parameter (when --dh-use-q-size is present).

    k_pub = k_priv = NULL;

    // INFO(Rafael): Preparing our context.
    kryptos_dh_init_xchg_ctx(kp);

    if (CUTE_GET_OPTION("dh-use-q-size") == NULL) {
        CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(domain_parameters,
                                                        strlen(domain_parameters),
                                                        &kp->p, NULL, &kp->g) == kKryptosSuccess);
        kp->s_bits = 8;
    } else {
        CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(domain_parameters,
                                                        strlen(domain_parameters),
                                                        &kp->p, &kp->q, &kp->g) == kKryptosSuccess);
    }

    kryptos_dh_mk_key_pair(&k_pub, &k_pub_size, &k_priv, &k_priv_size, &kp);

    CUTE_ASSERT(kryptos_last_task_succeed(kp) == 1);
    CUTE_ASSERT(k_pub != NULL);
    CUTE_ASSERT(k_pub_size != 0);
    CUTE_ASSERT(k_priv != NULL);
    CUTE_ASSERT(k_priv_size != 0);

    // INFO(Rafael): Verifying the public buffer, this must include: P, G and T also maybe Q but never S.

    pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_P, k_pub, k_pub_size, &pem_data_size);
    CUTE_ASSERT(pem_data != NULL && pem_data_size != 0);
    kryptos_freeseg(pem_data);

    if (CUTE_GET_OPTION("dh-use-q-size") != NULL) {
        pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_Q, k_pub, k_pub_size, &pem_data_size);
        CUTE_ASSERT(pem_data != NULL && pem_data_size != 0);
        kryptos_freeseg(pem_data);
    } else {
        pem_data = kryptos_pem_get_data(KRYPTOS_DH_PEM_HDR_PARAM_Q, k_pub, k_pub_size, &pem_data_size);
        CUTE_ASSERT(pem_data == NULL);
    }

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
    kryptos_u8_t *domain_parameters = "-----BEGIN DH PARAM P-----\n"
                                      "q/1geMTHBhklSLEP9NVV3Z3KH54E"
                                      "hi8L4/ImBDydLH+WtLacIcNy5bzW"
                                      "ZYyFbfIKgD+mzbTWYLMkv8MR54O4"
                                      "5qTMKGCAk/CifUw351HC/UNnBWi+"
                                      "ZajlIJ1vjegceCWynu9wsoO/9wH1"
                                      "sCtFJifH0zfMG8i53PB9kUeXa/bo"
                                      "T5E=\n"
                                      "-----END DH PARAM P-----\n"
                                      "-----BEGIN DH PARAM Q-----\n"
                                      "tx047pscx/Il1QIIVVnlwXD66bI=\n"
                                      "-----END DH PARAM Q-----\n"
                                      "-----BEGIN DH PARAM G-----\n"
                                      "kxvfCyqImE9Gr1F4dhZtPqGOAyjd"
                                      "wsObgGUueIrI6Pz71dCOyE1Jtmgh"
                                      "Knl8ygGDb9Xj3MjglpijVi+2th4W"
                                      "UZrE5BbJlBTza1rPjnvHjODGgy0Y"
                                      "GzviMegv6kI986kndWqJRfwQ7REi"
                                      "uTNjasdut36Ejvpj/r98zDZA5gg+"
                                      "gE0=\n"
                                      "-----END DH PARAM G-----\n";

    // INFO(Rafael): Using MODP defined in RFC-3526.

    printf("*** Using MODP from RFC-3526.\n\n");

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

    // INFO(Rafael): Using the pre-computed parameters and q (when --dh-use-q-size is present).

    printf("\n*** Using the pre-computed domain parameters.\n\n");

    k_pub_bob = k_priv_bob = NULL;

    kryptos_dh_init_xchg_ctx(bob);

    if (CUTE_GET_OPTION("dh-use-q-size") == NULL) {
        CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(domain_parameters,
                                                        strlen(domain_parameters),
                                                        &bob->p, NULL, &bob->g) == kKryptosSuccess);
        bob->s_bits = 8;
    } else {
        CUTE_ASSERT(kryptos_dh_get_modp_from_params_buf(domain_parameters,
                                                        strlen(domain_parameters),
                                                        &bob->p, &bob->q, &bob->g) == kKryptosSuccess);
    }

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

    if (CUTE_GET_OPTION("dh-use-q-size") == NULL) {
        alice->s_bits = 8;
    }

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

    // INFO(Rafael): At Bob's size s_bits does not mind because S will be loaded from the private key.

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

    printf(" *** CIPHERTEXT:\n\n%s\n", a_ktask->out);

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

    printf(" *** PLAINTEXT:\n\n'%s'\n", b_ktask->out);

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

    printf(" *** CIPHERTEXT:\n\n%s\n", b_ktask->out);

    // INFO(Rafael): Now Bob sends the encrypted buffer to Alice.

    kryptos_task_set_in(a_ktask, b_ktask->out, b_ktask->out_size);

    // INFO(Rafael): Alice uses her private key to get the original message.

    kryptos_task_set_decrypt_action(a_ktask);
    kryptos_run_cipher(rsa, a_ktask, k_priv_alice, strlen(k_priv_alice));

    CUTE_ASSERT(kryptos_last_task_succeed(a_ktask) == 1);

    CUTE_ASSERT(a_ktask->out != NULL);

    printf(" *** PLAINTEXT:\n\n'%s'\n", a_ktask->out);

    CUTE_ASSERT(a_ktask->out_size == m_size);
    CUTE_ASSERT(memcmp(a_ktask->out, m, m_size) == 0);

    kryptos_task_free(a_ktask, KRYPTOS_TASK_OUT);
    kryptos_task_free(b_ktask, KRYPTOS_TASK_OUT);
#else
    printf("WARN: No c99 support, this test was skipped.\n");
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_padding_mgf_tests)
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
        out = kryptos_padding_mgf(test_vector[t].seed, test_vector[t].seed_size,
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
                              "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoVg"
                              "7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "o13jdPAiis0sJZeh0OL9jL8Tib/EgoVNLqNXCM966j1qD4yq5KcXgrDezI48lxWDn66cZnppeXGfK8d0ym8U85JsXVgV2ao4"
                              "5ESDnBQFoRSoeQ3p3QVqDzfgViMeHIinMzFxx/OYpSgxpuQq4em4CwrBkqn1DxlRCzNCrdAqiwo=\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
                               "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoV"
                               "g7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "D3fMDiyVdMeojcOJuo4rB8CdgjNrxS2M9eORsLeiI6t+AiQpsE9LDlk62xHRAKfvX42RDkrlnr1g6PY3shIuPKcSfqLcl+S"
                               "dvt3NHzRLM8CEgJSWrUu919xo/IUKhFyFdN5ClYwpvaXaK/MVM1AV8gihLHpEsQT9gNfTgwDrVxU=\n"
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

    printf(" *** CIPHERTEXT:\n\n%s\n", a_ktask->out);

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

    printf(" *** CIPHERTEXT:\n\n%s\n", a_ktask->out);

    // INFO(Rafael): For some reason during the transfer the cryptogram becomes corrupted.

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_C, a_ktask->out, a_ktask->out_size) == 1);

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
                                "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNo"
                                "Vg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                                "-----END RSA PARAM N-----\n"
                                "-----BEGIN RSA PARAM E-----\n"
                                "o13jdPAiis0sJZeh0OL9jL8Tib/EgoVNLqNXCM966j1qD4yq5KcXgrDezI48lxWDn66cZnppeXGfK8d0ym8U85JsXVgV2a"
                                "o45ESDnBQFoRSoeQ3p3QVqDzfgViMeHIinMzFxx/OYpSgxpuQq4em4CwrBkqn1DxlRCzNCrdAqiwo=\n"
                                "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN RSA PARAM N-----\n"
                                 "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjN"
                                 "oVg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM D-----\n"
                                 "D3fMDiyVdMeojcOJuo4rB8CdgjNrxS2M9eORsLeiI6t+AiQpsE9LDlk62xHRAKfvX42RDkrlnr1g6PY3shIuPKcSfqLcl"
                                 "+Sdvt3NHzRLM8CEgJSWrUu919xo/IUKhFyFdN5ClYwpvaXaK/MVM1AV8gihLHpEsQT9gNfTgwDrVxU=\n"
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

    printf(" *** CIPHERTEXT:\n\n%s\n", b_ktask->out);

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

    printf(" *** CIPHERTEXT:\n\n%s\n", b_ktask->out);

    // INFO(Rafael): For some reason during the transfer the cryptogram becomes corrupted.

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_C, b_ktask->out, b_ktask->out_size) == 1);

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

CUTE_TEST_CASE(kryptos_elgamal_mk_key_pair_tests)
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL, *data = NULL;
    size_t k_pub_size, k_priv_size, data_size;

    CUTE_ASSERT(kryptos_elgamal_mk_key_pair(40, 20, NULL, &k_pub_size, &k_priv, &k_priv_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_elgamal_mk_key_pair(40, 20, &k_pub, NULL, &k_priv, &k_priv_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_elgamal_mk_key_pair(40, 20, &k_pub, &k_pub_size, NULL, &k_priv_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_elgamal_mk_key_pair(40, 20, &k_pub, &k_pub_size, &k_priv, NULL) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_elgamal_mk_key_pair(80, 40, &k_pub, &k_pub_size, &k_priv, &k_priv_size) == kKryptosSuccess);
    CUTE_ASSERT(k_pub != NULL && k_pub_size != 0 && k_priv != NULL && k_priv_size != 0);

    printf(" *** ELGAMAL PUBLIC KEY:\n\n");
    printf("%s", k_pub);

    printf("\n *** ELGAMAL PRIVATE KEY:\n\n");
    printf("%s", k_priv);

    // INFO(Rafael): Verifying the parameters in public key.

    data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, k_pub, k_pub_size, &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Q, k_pub, k_pub_size, &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_G, k_pub, k_pub_size, &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_B, k_pub, k_pub_size, &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    kryptos_freeseg(data);

    // WARN(Rafael): D parameter cannot be in public key.
    data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_D, k_pub, k_pub_size, &data_size);
    CUTE_ASSERT(data == NULL);

    // INFO(Rafael): Verifying the parameters in private key.

    data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, k_priv, k_priv_size, &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_D, k_priv, k_priv_size, &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    kryptos_freeseg(data);

    kryptos_freeseg(k_pub);
    kryptos_freeseg(k_priv);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_elgamal_verify_public_key_tests)
    kryptos_u8_t *valid_k_pub = "-----BEGIN ELGAMAL PARAM P-----\n"
                                "q5jud0t7MBc=\n"
                                "-----END ELGAMAL PARAM P-----\n"
                                "-----BEGIN ELGAMAL PARAM Q-----\n"
                                "lS0rXw==\n"
                                "-----END ELGAMAL PARAM Q-----\n"
                                "-----BEGIN ELGAMAL PARAM G-----\n"
                                "V3l+1MA9EwQ=\n"
                                "-----END ELGAMAL PARAM G-----\n"
                                "-----BEGIN ELGAMAL PARAM B-----\n"
                                "i525HXApOwc=\n"
                                "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *weak_k_pub = "-----BEGIN ELGAMAL PARAM P-----\n"
                                "kW+7WMY/t+ksDA8wN05Xik1hnRv7lLrV19fFLPfguqAM0em5kJsEP4Y57byre/U0dMt8fSqzAI+PtScC\n"
                                "-----END ELGAMAL PARAM P-----\n"
                                "-----BEGIN ELGAMAL PARAM G-----\n"
                                "2K1E/hpeAd4igi3RwZnibVM5ZUyNeAJtkfqLp0L+wG0MlOT04lnC/JAeJUXY97wgw/IQpJNmY+4++tcA\n"
                                "-----END ELGAMAL PARAM G-----\n"
                                "-----BEGIN ELGAMAL PARAM B-----\n"
                                "qAE80AtRrkkiL98tqV40En1FsSb2D8AFi68Ng8jwgBWLnlTrAoxliMK747CVBef4lExUSyv3CpeJ4MEB\n"
                                "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *no_beta_k_pub = "-----BEGIN ELGAMAL PARAM P-----\n"
                                  "kW+7WMY/t+ksDA8wN05Xik1hnRv7lLrV19fFLPfguqAM0em5kJsEP4Y57byre/U0dMt8fSqzAI+PtScC\n"
                                  "-----END ELGAMAL PARAM P-----\n"
                                  "-----BEGIN ELGAMAL PARAM Q-----\n"
                                  "1/qPyUr0rD4=\n"
                                  "-----END ELGAMAL PARAM Q-----\n"
                                  "-----BEGIN ELGAMAL PARAM G-----\n"
                                  "2K1E/hpeAd4igi3RwZnibVM5ZUyNeAJtkfqLp0L+wG0MlOT04lnC/JAeJUXY97wgw/IQpJNmY+4++tcA\n"
                                  "-----END ELGAMAL PARAM G-----\n";

    kryptos_u8_t *invalid_q_k_pub = "-----BEGIN ELGAMAL PARAM P-----\n"
                                    "kW+7WMY/t+ksDA8wN05Xik1hnRv7lLrV19fFLPfguqAM0em5kJsEP4Y57byre/U0dMt8fSqzAI+PtScC\n"
                                    "-----END ELGAMAL PARAM P-----\n"
                                    "-----BEGIN ELGAMAL PARAM Q-----\n"
                                    "ticktickbOoM\n"
                                    "-----END ELGAMAL PARAM Q-----\n"
                                    "-----BEGIN ELGAMAL PARAM G-----\n"
                                    "2K1E/hpeAd4igi3RwZnibVM5ZUyNeAJtkfqLp0L+wG0MlOT04lnC/JAeJUXY97wgw/IQpJNmY+4++tcA\n"
                                    "-----END ELGAMAL PARAM G-----\n"
                                    "-----BEGIN ELGAMAL PARAM B-----\n"
                                    "qAE80AtRrkkiL98tqV40En1FsSb2D8AFi68Ng8jwgBWLnlTrAoxliMK747CVBef4lExUSyv3CpeJ4MEB\n"
                                    "-----END ELGAMAL PARAM B-----\n";

    // INFO(Rafael): NULL key buffer duh!
    CUTE_ASSERT(kryptos_elgamal_verify_public_key(NULL, 100) == kKryptosInvalidParams);

    // INFO(Rafael): Zeroed key buffer size duh!
    CUTE_ASSERT(kryptos_elgamal_verify_public_key(valid_k_pub, 0) == kKryptosInvalidParams);

    // INFO(Rafael): Key buffer size with no Q parameter.
    CUTE_ASSERT(kryptos_elgamal_verify_public_key(weak_k_pub, strlen(weak_k_pub)) == kKryptosInvalidParams);

    // INFO(Rafael): Useless key buffer without the B parameter.
    CUTE_ASSERT(kryptos_elgamal_verify_public_key(no_beta_k_pub, strlen(no_beta_k_pub)) == kKryptosInvalidParams);

    // INFO(Rafael): Key buffer with an invalid Q.
    CUTE_ASSERT(kryptos_elgamal_verify_public_key(invalid_q_k_pub, strlen(invalid_q_k_pub)) == kKryptosInvalidParams);

    // INFO(Rafael): Guess what?
    CUTE_ASSERT(kryptos_elgamal_verify_public_key(valid_k_pub, strlen(valid_k_pub)) == kKryptosSuccess);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_elgamal_cipher_tests)
    kryptos_u8_t *k_pub_alice = "-----BEGIN ELGAMAL PARAM P-----\n"
                                "kW+7WMY/t+ksDA8wN05Xik1hnRv7lLrV19fFLPfguqAM0em5kJsEP4Y57byre/U0dMt8fSqzAI+PtScC\n"
                                "-----END ELGAMAL PARAM P-----\n"
                                "-----BEGIN ELGAMAL PARAM Q-----\n"
                                "1/qPyUr0rD4=\n"
                                "-----END ELGAMAL PARAM Q-----\n"
                                "-----BEGIN ELGAMAL PARAM G-----\n"
                                "2K1E/hpeAd4igi3RwZnibVM5ZUyNeAJtkfqLp0L+wG0MlOT04lnC/JAeJUXY97wgw/IQpJNmY+4++tcA\n"
                                "-----END ELGAMAL PARAM G-----\n"
                                "-----BEGIN ELGAMAL PARAM B-----\n"
                                "qAE80AtRrkkiL98tqV40En1FsSb2D8AFi68Ng8jwgBWLnlTrAoxliMK747CVBef4lExUSyv3CpeJ4MEB\n"
                                "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN ELGAMAL PARAM P-----\n"
                                 "kW+7WMY/t+ksDA8wN05Xik1hnRv7lLrV19fFLPfguqAM0em5kJsEP4Y57byre/U0dMt8fSqzAI+PtScC\n"
                                 "-----END ELGAMAL PARAM P-----\n"
                                 "-----BEGIN ELGAMAL PARAM D-----\n"
                                 "8KUZ47r90x0=\n"
                                 "-----END ELGAMAL PARAM D-----\n";

    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *m = "yo no creo en brujas, pero que las hay, las hay.\x00\x00\x00\x00\x00\x00\x00\x00";
    size_t m_size = 56;

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    // INFO(Rafael): Bob wants to send a message to Alice.

    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);
    bob->in = m;
    bob->in_size = m_size;

    bob->cipher = kKryptosCipherELGAMAL;
    kryptos_task_set_encrypt_action(bob);
    kryptos_elgamal_cipher(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);

    printf(" *** CIPHERTEXT:\n\n%s\n", bob->out);

    // INFO(Rafael): Bob sends the cryptogram to Alice.

    alice->in = bob->out;
    alice->in_size = bob->out_size;

    alice->key = k_priv_alice;
    alice->key_size = strlen(k_priv_alice);
    alice->cipher = kKryptosCipherELGAMAL;
    kryptos_task_set_decrypt_action(alice);
    kryptos_elgamal_cipher(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);

    CUTE_ASSERT(alice->out != NULL);

    printf(" *** PLAINTEXT:\n\n'%s'\n", alice->out);

    CUTE_ASSERT(alice->out_size == m_size);
    CUTE_ASSERT(memcmp(alice->out, m, m_size) == 0);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_elgamal_cipher_c99_tests)
#ifdef KRYPTOS_C99
    kryptos_u8_t *k_pub_bob = "-----BEGIN ELGAMAL PARAM P-----\n"
                              "cxCr4JOOvFjrdQ/JvbFfwtZJOxOjKTgmYRwU0/x8s+vh1BCj2bnhqAY8iDwjssZOjZSFI3WfMat80ngB\n"
                              "-----END ELGAMAL PARAM P-----\n"
                              "-----BEGIN ELGAMAL PARAM Q-----\n"
                              "oQGiaDjNdCc=\n"
                              "-----END ELGAMAL PARAM Q-----\n"
                              "-----BEGIN ELGAMAL PARAM G-----\n"
                              "WKaDp9g2bYqI6BeSdi1giVohhVGslK7o0Zjocu31Sh9YjeW/k7vvR/pQZmZlbgTqNUKUwEroQI/AKpQA\n"
                              "-----END ELGAMAL PARAM G-----\n"
                              "-----BEGIN ELGAMAL PARAM B-----\n"
                              "64Uee8Q42Vj8cxt9zwyrxd5jnQBXsTMIwgLmmQW7SYUblkiZUFbf2EoMbJPdt1BIUGle+z8nZpEyd2kB\n"
                              "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN ELGAMAL PARAM P-----\n"
                               "cxCr4JOOvFjrdQ/JvbFfwtZJOxOjKTgmYRwU0/x8s+vh1BCj2bnhqAY8iDwjssZOjZSFI3WfMat80ngB\n"
                               "-----END ELGAMAL PARAM P-----\n"
                               "-----BEGIN ELGAMAL PARAM D-----\n"
                               "6cAd5Y8akwE=\n"
                               "-----END ELGAMAL PARAM D-----\n";

    kryptos_u8_t *m = "This Machine Kills Fascists\x00\x00\x00\x00\x00";
    size_t m_size = 32;
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    // INFO(Rafael): Alice wants to send a message to Bob.

    kryptos_task_set_in(alice, m, m_size);
    kryptos_task_set_encrypt_action(alice);

    kryptos_run_cipher(elgamal, alice, k_pub_bob, strlen(k_pub_bob));

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);

    printf(" *** CIPHERTEXT:\n\n%s\n", alice->out);

    // INFO(Rafael): All done, Alice sends her cryptogram to Bob.
    //               Bob receives it and configure his input with the data.

    kryptos_task_set_in(bob, alice->out, alice->out_size);

    // INFO(Rafael): Asks the library for a decryption task and call Elgamal passing his private key.
    kryptos_task_set_decrypt_action(bob);

    kryptos_run_cipher(elgamal, bob, k_priv_bob, strlen(k_priv_bob));

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);

    CUTE_ASSERT(bob->out != NULL);

    CUTE_ASSERT(bob->out_size == m_size);
    CUTE_ASSERT(memcmp(bob->out, m, bob->out_size) == 0);

    printf(" *** PLAINTEXT:\n\n'%s'\n", bob->out);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
#else
    printf("WARN: No c99 support, this test was skipped.\n");
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_elgamal_oaep_cipher_tests)
    kryptos_u8_t *k_pub_bob = "-----BEGIN ELGAMAL PARAM P-----\n"
                              "ub1yArM/5LO8iGWyQoTnXo7eq3kT9JYnO"
                              "YF1e328owL/2OsFwEzvzEPgvQf3iAjYbh"
                              "QiTxZsHsUJ0w6NQqAPB2+v+jt7JVqOAt3"
                              "ovtmRgdHA1LyPf5YIRcHfIajJcIq1uXmu"
                              "XlNa3w663vwpeB6axF43C3WViqOCnYN8H"
                              "Jbmaoc=\n"
                              "-----END ELGAMAL PARAM P-----\n"
                              "-----BEGIN ELGAMAL PARAM Q-----\n"
                              "+bUNFB6uJ+3Yif48ULYb0QaNWbI=\n"
                              "-----END ELGAMAL PARAM Q-----\n"
                              "-----BEGIN ELGAMAL PARAM G-----\n"
                              "IDVrez91IjjHsPbVHZjxrgvF0bZ7CzqPy"
                              "AvelU1scRIrQ3hOexXGShLAT9kJEpHDC7"
                              "QtWWXXpsKfh6fIxuvexWYgyU50zESlzgz"
                              "QzU060LrhXvL6BlFt3DIrgWkqiSt9U0J3"
                              "CnKB9R347kPzQl04K6IWl2qqEGVDknBSM"
                              "ExqhHg=\n"
                              "-----END ELGAMAL PARAM G-----\n"
                              "-----BEGIN ELGAMAL PARAM B-----\n"
                              "7HXRFK+NOnOrsT6VKqdFNhw8U1qnVU9S8"
                              "7v6R6XH/BYQxFy30FasKTkMMijXISy5VE"
                              "zL3YZV+++dN7V7ng31o3nv/R6kX+cQbz/"
                              "IvrUsCJ5KtPp9+gnORZWHa4uMbZHhDQgY"
                              "Go6nOv/1AljcG8ZMSNPuMGpGp0fRb77yP"
                              "IkkY2o=\n"
                              "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN ELGAMAL PARAM P-----\n"
                               "ub1yArM/5LO8iGWyQoTnXo7eq3kT9JYnO"
                               "YF1e328owL/2OsFwEzvzEPgvQf3iAjYbh"
                               "QiTxZsHsUJ0w6NQqAPB2+v+jt7JVqOAt3"
                               "ovtmRgdHA1LyPf5YIRcHfIajJcIq1uXmu"
                               "XlNa3w663vwpeB6axF43C3WViqOCnYN8H"
                               "Jbmaoc=\n"
                               "-----END ELGAMAL PARAM P-----\n"
                               "-----BEGIN ELGAMAL PARAM D-----\n"
                               "9Nz8YxvIEqdfeaAoJcNgey2kDWo=\n"
                               "-----END ELGAMAL PARAM D-----\n";

    kryptos_u8_t *m = "I don't need no make up, I got real scars\x00\x00\x00\x00\x00\x00\x00";
    size_t m_size = 48;
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *label = "ChocalateJesus";
    size_t label_size = 14;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    alice->in = m;
    alice->in_size = m_size;
    alice->key = k_pub_bob;
    alice->key_size = strlen(k_pub_bob);
    alice->action = kKryptosEncrypt;

    alice->cipher = kKryptosCipherELGAMALOAEP;
    alice->arg[0] = label;
    alice->arg[1] = &label_size;
    alice->arg[2] = kryptos_sha1_hash;
    alice->arg[3] = kryptos_sha1_hash_size;

    kryptos_elgamal_oaep_cipher(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->out != NULL);

    printf(" *** CIPHERTEXT:\n\n%s\n", alice->out);

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_priv_bob;
    bob->key_size = strlen(k_priv_bob);
    bob->action = kKryptosDecrypt;

    bob->cipher = kKryptosCipherELGAMALOAEP;
    bob->arg[0] = label;
    bob->arg[1] = &label_size;
    bob->arg[2] = kryptos_sha1_hash;
    bob->arg[3] = kryptos_sha1_hash_size;

    kryptos_elgamal_oaep_cipher(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->out != NULL);

    CUTE_ASSERT(bob->out_size == m_size);
    CUTE_ASSERT(memcmp(bob->out, m, m_size) == 0);

    printf(" *** PLAINTEXT:\n\n'%s'\n\n", bob->out);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Now with a corrupted cryptogram.

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    alice->in = m;
    alice->in_size = m_size;
    alice->key = k_pub_bob;
    alice->key_size = strlen(k_pub_bob);
    alice->action = kKryptosEncrypt;

    alice->cipher = kKryptosCipherELGAMALOAEP;
    alice->arg[0] = label;
    alice->arg[1] = &label_size;
    alice->arg[2] = kryptos_sha1_hash;
    alice->arg[3] = kryptos_sha1_hash_size;

    kryptos_elgamal_oaep_cipher(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->out != NULL);

    printf(" *** CIPHERTEXT:\n\n%s\n", alice->out);

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_priv_bob;
    bob->key_size = strlen(k_priv_bob);
    bob->action = kKryptosDecrypt;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Y, bob->in, bob->in_size) == 1);

    printf(" ( the cryptogram was intentionally corrupted )\n\n");

    bob->cipher = kKryptosCipherELGAMALOAEP;
    bob->arg[0] = label;
    bob->arg[1] = &label_size;
    bob->arg[2] = kryptos_sha1_hash;
    bob->arg[3] = kryptos_sha1_hash_size;

    kryptos_elgamal_oaep_cipher(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->out_size == 0);
    CUTE_ASSERT(bob->out == NULL);

    printf(" *** PLAINTEXT:\n\n (null)\n\n");

    printf(" *** Nice, the unexpected cryptogram was successfully detected => '%s'.\n", bob->result_verbose);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_elgamal_oaep_cipher_c99_tests)
#ifdef KRYPTOS_C99
    kryptos_u8_t *k_pub_alice = "-----BEGIN ELGAMAL PARAM P-----\n"
                                "I+oUuRaQpiwFa0Saa5pJFGDro22vya7hh"
                                "9mkyC5bQADl5BuqXT862/mOX5VWz+UNjR"
                                "XU2tx380GzWp6UQnbhxM0ptehr+VRJvIL"
                                "/Lzg5j46tWuv3gbBHHDuC1qREmnAbYmuI"
                                "1TdPRHsqalbMKOir2+WVg/RSkKlUhxwqO"
                                "Omhc1Y=\n"
                                "-----END ELGAMAL PARAM P-----\n"
                                "-----BEGIN ELGAMAL PARAM Q-----\n"
                                "CRWNcTQc/I9LD6wEhVMdL6Hfa4Y=\n"
                                "-----END ELGAMAL PARAM Q-----\n"
                                "-----BEGIN ELGAMAL PARAM G-----\n"
                                "RzYrWiANW0FFKw53zqXapqj/YeJDHlcnL"
                                "ubErvtxulWx9HRRBdQW77U2a9LL/WemDo"
                                "ssouBpJxHQzbzI4awVHRcBcukKgYM693Y"
                                "F1OnwQVPfy2xdzPdxKcexYNdp5Q1rq6mL"
                                "5n5/5zhZwZbuRtqampC/bn/BrmODbpwbF"
                                "6Ppwiw=\n"
                                "-----END ELGAMAL PARAM G-----\n"
                                "-----BEGIN ELGAMAL PARAM B-----\n"
                                "KlBWeqbION6MuCVYZ+6/lmURkupmJX6LW"
                                "E37/wOH/HbkLoWJhxU3XzRRoRO9rmCZHB"
                                "HFlPPEJOnPIdyq5m0BOFNNb26c3SlNImO"
                                "EsQTaV+3/urZ+lwITX7oqnEv6Tyoi+2mz"
                                "dNQTLzYZH/SCN/ILQb6Jg0ri/QUddywcH"
                                "GyLFCI=\n"
                                "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN ELGAMAL PARAM P-----\n"
                                 "I+oUuRaQpiwFa0Saa5pJFGDro22vya7hh"
                                 "9mkyC5bQADl5BuqXT862/mOX5VWz+UNjR"
                                 "XU2tx380GzWp6UQnbhxM0ptehr+VRJvIL"
                                 "/Lzg5j46tWuv3gbBHHDuC1qREmnAbYmuI"
                                 "1TdPRHsqalbMKOir2+WVg/RSkKlUhxwqO"
                                 "Omhc1Y=\n"
                                 "-----END ELGAMAL PARAM P-----\n"
                                 "-----BEGIN ELGAMAL PARAM D-----\n"
                                 "0VDQAgkcbyRksu/NskgCkva8rn0=\n"
                                 "-----END ELGAMAL PARAM D-----\n";

    kryptos_u8_t *m = "a right is not what someone gives you; it's what no one can take from you.\x00\x00";
    size_t m_size = 76;
    kryptos_u8_t *label = "Elcabong";
    size_t label_size = 8;
    kryptos_task_ctx at, bt, *bob = &bt, *alice = &at;

    kryptos_task_init_as_null(bob);
    kryptos_task_init_as_null(alice);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_set_in(bob, m, m_size);
    kryptos_task_set_encrypt_action(bob);
    kryptos_run_cipher(elgamal_oaep, bob,
                       k_pub_alice, strlen(k_pub_alice),
                       label, &label_size,
                       kryptos_sha1_hash, kryptos_sha1_hash_size);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->out != NULL);

    printf(" *** CIPHERTEXT:\n\n%s\n", bob->out);

    kryptos_task_set_in(alice, bob->out, bob->out_size);
    kryptos_task_set_decrypt_action(alice);
    kryptos_run_cipher(elgamal_oaep, alice,
                       k_priv_alice, strlen(k_priv_alice),
                       label, &label_size,
                       kryptos_sha1_hash, kryptos_sha1_hash_size);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->out != NULL);

    CUTE_ASSERT(alice->out_size == m_size);
    CUTE_ASSERT(alice->out != NULL);

    CUTE_ASSERT(memcmp(alice->out, m, alice->out_size) == 0);

    printf(" *** PLAINTEXT:\n\n'%s'\n\n", alice->out);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Corrupted cryptogram.

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_set_in(bob, m, m_size);
    kryptos_task_set_encrypt_action(bob);
    kryptos_run_cipher(elgamal_oaep, bob,
                       k_pub_alice, strlen(k_pub_alice),
                       label, &label_size,
                       kryptos_sha1_hash, kryptos_sha1_hash_size);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->out != NULL);

    printf(" *** CIPHERTEXT:\n\n%s\n", bob->out);

    kryptos_task_set_in(alice, bob->out, bob->out_size);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Y, alice->in, alice->in_size) == 1);

    printf(" ( the cryptogram was intentionally corrupted )\n\n");

    kryptos_task_set_decrypt_action(alice);
    kryptos_run_cipher(elgamal_oaep, alice,
                       k_priv_alice, strlen(k_priv_alice),
                       label, &label_size,
                       kryptos_sha1_hash, kryptos_sha1_hash_size);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);

    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** PLAINTEXT:\n\n (null)\n\n");

    printf(" *** Nice, the unexpected cryptogram was successfully detected => '%s'.\n", alice->result_verbose);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
#else
    printf("WARN: No c99 support, this test was skipped.\n");
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_pss_encoding_tests)
    // WARN(Rafael): Here this case tests kryptos_pss_encode() and also kryptos_pss_verify() functions.
    struct pss_encoding_tests {
        kryptos_u8_t *m;
        size_t k, salt_size;
        kryptos_hash_func hash;
        kryptos_hash_size_func hash_size;
        int corrupt;
    };

    struct pss_encoding_tests test_vector[] = {
        { "...tears from the sky, in pools of pain...", 1024, 20, kryptos_sha1_hash, kryptos_sha1_hash_size, 0 },
        { "...well baby tonite, I'm gonna go & dance in the rain!!", 1024, 30, kryptos_sha1_hash, kryptos_sha1_hash_size, 0 },
        { "...tears from the sky, in pools of pain...", 1024, 0, kryptos_sha1_hash, kryptos_sha1_hash_size, 0 },
        { "...well baby tonite, I'm gonna go & dance in the rain!!", 1024, 0, kryptos_sha1_hash, kryptos_sha1_hash_size, 0 },
        { "brazil................................................."
          "......................................................."
          "....", 1024, 90, kryptos_sha1_hash, kryptos_sha1_hash_size, 1 },
        { "compliance============================================="
          "======================================================="
          "====", 1024, 8, kryptos_sha1_hash, kryptos_sha1_hash_size, 1 },
        { "true ethics, from home!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
          "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
          "!!!!", 1024, 7, kryptos_sha1_hash, kryptos_sha1_hash_size, 0 },
        { "We've built a Great Wall around our power\n"
          "Economic Great Wall around our power\n"
          "Worldwide Great Wall around our power\n"
          "Give us your poor,\n"
          "Your tired and your weak\n"
          "We'll send'em right back\n"
          "To their certain death\n", 1024, 4, kryptos_sha1_hash, kryptos_sha1_hash_size, 0 }
    };
    size_t tv_size = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_u8_t *em = NULL;
    const kryptos_u8_t *m = NULL;
    size_t em_size = 0, m_size = 0, x;

    for (tv = 0; tv < tv_size; tv++) {
        m_size = em_size = strlen(test_vector[tv].m);

        em = kryptos_pss_encode(test_vector[tv].m, &em_size,
                                test_vector[tv].k, test_vector[tv].salt_size,
                                test_vector[tv].hash, test_vector[tv].hash_size);

        CUTE_ASSERT(em != NULL);

        if (test_vector[tv].corrupt) {
            em[em_size >> 1] = ~em[em_size >> 1];
        }

        m = kryptos_pss_verify(test_vector[tv].m, m_size, em, em_size,
                               test_vector[tv].k, test_vector[tv].salt_size,
                               test_vector[tv].hash, test_vector[tv].hash_size);

        if (test_vector[tv].corrupt) {
            CUTE_ASSERT(m == NULL);
        } else {
            CUTE_ASSERT(m == test_vector[tv].m);
        }

        kryptos_freeseg(em);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_digital_signature_basic_scheme_tests)
    kryptos_u8_t *k_pub_alice = "-----BEGIN RSA PARAM N-----\n"
                                "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNo"
                                "Vg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                                "-----END RSA PARAM N-----\n"
                                "-----BEGIN RSA PARAM E-----\n"
                                "o13jdPAiis0sJZeh0OL9jL8Tib/EgoVNLqNXCM966j1qD4yq5KcXgrDezI48lxWDn66cZnppeXGfK8d0ym8U85JsXVgV2a"
                                "o45ESDnBQFoRSoeQ3p3QVqDzfgViMeHIinMzFxx/OYpSgxpuQq4em4CwrBkqn1DxlRCzNCrdAqiwo=\n"
                                "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN RSA PARAM N-----\n"
                                 "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjN"
                                 "oVg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM D-----\n"
                                 "D3fMDiyVdMeojcOJuo4rB8CdgjNrxS2M9eORsLeiI6t+AiQpsE9LDlk62xHRAKfvX42RDkrlnr1g6PY3shIuPKcSfqLcl"
                                 "+Sdvt3NHzRLM8CEgJSWrUu919xo/IUKhFyFdN5ClYwpvaXaK/MVM1AV8gihLHpEsQT9gNfTgwDrVxU=\n"
                                 "-----END RSA PARAM D-----\n";

    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *m = "The Bad In Each Other\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    size_t m_size = 32;
    kryptos_u8_t *signature = NULL;
    size_t signature_size = 0;

    // INFO(Rafael): Valid signature case.

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    alice->cipher = kKryptosCipherRSA;

    alice->in = m;
    alice->in_size = m_size;
    alice->key = k_priv_alice;
    alice->key_size = strlen(k_priv_alice);

    kryptos_rsa_sign(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);

    CUTE_ASSERT(alice->out != NULL);

    printf(" *** SIGNED OUTPUT:\n\n%s\n", alice->out);

    // INFO(Rafael): Once upon a time, Alice sent a signed message to bob.... blah, blah, blah.

    bob->cipher = kKryptosCipherRSA;

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);

    kryptos_rsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);

    CUTE_ASSERT(bob->out != NULL);
    CUTE_ASSERT(bob->out_size == m_size);
    CUTE_ASSERT(memcmp(bob->out, m, bob->out_size) == 0);

    printf(" *** AUTHENTICATED OUTPUT:\n\n'%s'\n\n", bob->out);

    signature = alice->out;
    signature_size = alice->out_size;

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Invalid signature cases.

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    alice->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    memset(alice->out, 0, signature_size + 1);
    CUTE_ASSERT(alice->out != NULL);
    alice->out_size = signature_size;
    CUTE_ASSERT(memcpy(alice->out, signature, signature_size) == alice->out);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, alice->out, alice->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH X PARAMETER CORRUPTED:\n\n%s\n", alice->out);

    // INFO(Rafael): Once upon a time, Bob received a signed message by Alice with X corrupted.

    bob->cipher = kKryptosCipherRSA;

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);

    kryptos_rsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);
    CUTE_ASSERT(bob->out == NULL);
    CUTE_ASSERT(bob->out_size == 0);

    printf(" *** Nice, the signed output with x corrupted was successfully detected => '%s'\n\n", bob->result_verbose);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    alice->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    memset(alice->out, 0, signature_size + 1);
    CUTE_ASSERT(alice->out != NULL);
    alice->out_size = signature_size;
    CUTE_ASSERT(memcpy(alice->out, signature, signature_size) == alice->out);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, alice->out, alice->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH S PARAMETER CORRUPTED:\n\n%s\n", alice->out);

    // INFO(Rafael): Once upon a time, Bob received a signed message by Alice with S corrupted.

    bob->cipher = kKryptosCipherRSA;

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);

    kryptos_rsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);

    printf(" *** Nice, the signed output with s corrupted was successfully detected => '%s'\n\n", bob->result_verbose);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    alice->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    memset(alice->out, 0, signature_size + 1);
    CUTE_ASSERT(alice->out != NULL);
    alice->out_size = signature_size;
    CUTE_ASSERT(memcpy(alice->out, signature, signature_size) == alice->out);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, alice->out, alice->out_size) == 1);
    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, alice->out, alice->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH BOTH X AND S PARAMETERS CORRUPTED:\n\n%s\n", alice->out);

    // INFO(Rafael): Once upon a time, Bob received a signed message by Alice, totally corrupted.

    bob->cipher = kKryptosCipherRSA;

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);

    kryptos_rsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);

    printf(" *** Nice, the signed output with x and s corrupted was successfully detected => '%s'\n", bob->result_verbose);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_freeseg(signature);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_digital_signature_basic_scheme_c99_tests)
#ifdef KRYPTOS_C99
    kryptos_u8_t *k_pub_bob = "-----BEGIN RSA PARAM N-----\n"
                              "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoVg"
                              "7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "o13jdPAiis0sJZeh0OL9jL8Tib/EgoVNLqNXCM966j1qD4yq5KcXgrDezI48lxWDn66cZnppeXGfK8d0ym8U85JsXVgV2ao4"
                              "5ESDnBQFoRSoeQ3p3QVqDzfgViMeHIinMzFxx/OYpSgxpuQq4em4CwrBkqn1DxlRCzNCrdAqiwo=\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
                               "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoV"
                               "g7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "D3fMDiyVdMeojcOJuo4rB8CdgjNrxS2M9eORsLeiI6t+AiQpsE9LDlk62xHRAKfvX42RDkrlnr1g6PY3shIuPKcSfqLcl+S"
                               "dvt3NHzRLM8CEgJSWrUu919xo/IUKhFyFdN5ClYwpvaXaK/MVM1AV8gihLHpEsQT9gNfTgwDrVxU=\n"
                               "-----END RSA PARAM D-----\n";

    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *m = "We're gonna steal your mail, on a Friday night... "
                      "We're gonna steal your mail, by the pale moonlight\x00\x00\x00\x00";
    size_t m_size = 104;
    kryptos_u8_t *signature = NULL;
    size_t signature_size = 0;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    // INFO(Rafael): Bob sign the message.

    kryptos_sign(rsa, bob, m, m_size, k_priv_bob, strlen(k_priv_bob));

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->out != NULL);

    printf(" *** SIGNED OUTPUT:\n\n%s\n", bob->out);

    // INFO(Rafael): Now Alice simply verify.

    kryptos_verify(rsa, alice, bob->out, bob->out_size, k_pub_bob, strlen(k_pub_bob));

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->out != NULL);

    printf(" *** AUTHENTICATED OUTPUT:\n\n'%s'\n\n", alice->out);

    signature = bob->out;
    signature_size = bob->out_size;

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Corrupted signature cases.

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(bob->out != NULL);
    memset(bob->out, 0, signature_size + 1);
    bob->out_size = signature_size;
    CUTE_ASSERT(memcpy(bob->out, signature, signature_size) == bob->out);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, bob->out, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH X CORRUPTED:\n\n%s\n", bob->out);

    kryptos_verify(rsa, alice, bob->out, bob->out_size, k_pub_bob, strlen(k_pub_bob));

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);

    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with x corrupted was successfully detected => '%s'\n\n", alice->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_task_free(alice, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(bob->out != NULL);
    memset(bob->out, 0, signature_size + 1);
    bob->out_size = signature_size;
    CUTE_ASSERT(memcpy(bob->out, signature, signature_size) == bob->out);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, bob->out, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH S CORRUPTED:\n\n%s\n", bob->out);

    kryptos_verify(rsa, alice, bob->out, bob->out_size, k_pub_bob, strlen(k_pub_bob));

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);

    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with s corrupted was successfully detected => '%s'\n\n", alice->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_task_free(alice, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(bob->out != NULL);
    memset(bob->out, 0, signature_size + 1);
    bob->out_size = signature_size;
    CUTE_ASSERT(memcpy(bob->out, signature, signature_size) == bob->out);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, bob->out, bob->out_size) == 1);
    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, bob->out, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH BOTH X AND S CORRUPTED:\n\n%s\n", bob->out);

    kryptos_verify(rsa, alice, bob->out, bob->out_size, k_pub_bob, strlen(k_pub_bob));

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);

    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with x and s corrupted was successfully detected => '%s'\n", alice->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_freeseg(signature);
#else
    printf("WARN: No c99 support, this test was skipped.\n");
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_emsa_pss_digital_signature_scheme_tests)
    kryptos_u8_t *k_pub_alice = "-----BEGIN RSA PARAM N-----\n"
                                "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNo"
                                "Vg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                                "-----END RSA PARAM N-----\n"
                                "-----BEGIN RSA PARAM E-----\n"
                                "o13jdPAiis0sJZeh0OL9jL8Tib/EgoVNLqNXCM966j1qD4yq5KcXgrDezI48lxWDn66cZnppeXGfK8d0ym8U85JsXVgV2a"
                                "o45ESDnBQFoRSoeQ3p3QVqDzfgViMeHIinMzFxx/OYpSgxpuQq4em4CwrBkqn1DxlRCzNCrdAqiwo=\n"
                                "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN RSA PARAM N-----\n"
                                 "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjN"
                                 "oVg7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM D-----\n"
                                 "D3fMDiyVdMeojcOJuo4rB8CdgjNrxS2M9eORsLeiI6t+AiQpsE9LDlk62xHRAKfvX42RDkrlnr1g6PY3shIuPKcSfqLcl"
                                 "+Sdvt3NHzRLM8CEgJSWrUu919xo/IUKhFyFdN5ClYwpvaXaK/MVM1AV8gihLHpEsQT9gNfTgwDrVxU=\n"
                                 "-----END RSA PARAM D-----\n";

    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *m = "Every fortress falls.\x00\x00\x00\x00\x00\x00\x00";
    size_t m_size = 28;
    size_t salt_size = 4;
    kryptos_u8_t *signature = NULL;
    size_t signature_size = 0;

    // INFO(Rafael): Valid signature case.

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    alice->cipher = kKryptosCipherRSAEMSAPSS;

    alice->in = m;
    alice->in_size = m_size;
    alice->key = k_priv_alice;
    alice->key_size = strlen(k_priv_alice);
    alice->arg[0] = &salt_size;
    alice->arg[1] = alice->arg[2] = NULL;

    kryptos_rsa_sign(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);

    CUTE_ASSERT(alice->out != NULL);

    printf(" *** SIGNED OUTPUT:\n\n%s\n", alice->out);

    // INFO(Rafael): Once upon a time, Alice sent a signed message to bob.... blah, blah, blah.

    bob->cipher = kKryptosCipherRSAEMSAPSS;

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);
    bob->arg[0] = &salt_size;
    bob->arg[1] = bob->arg[2] = NULL;

    kryptos_rsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);

    CUTE_ASSERT(bob->out != NULL);
    CUTE_ASSERT(bob->out_size == m_size);
    CUTE_ASSERT(memcmp(bob->out, m, bob->out_size) == 0);

    printf(" *** AUTHENTICATED OUTPUT:\n\n'%s'\n\n", bob->out);

    signature = alice->out;
    signature_size = alice->out_size;

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Invalid signature cases.

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    alice->cipher = kKryptosCipherRSAEMSAPSS;

    alice->in = m;
    alice->in_size = m_size;
    alice->key = k_priv_alice;
    alice->key_size = strlen(k_priv_alice);
    alice->arg[0] = &salt_size;
    alice->arg[1] = alice->arg[2] = NULL;

    alice->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(alice->out != NULL);
    memset(alice->out, 0, signature_size + 1);
    CUTE_ASSERT(memcpy(alice->out, signature, signature_size) == alice->out);
    alice->out_size = signature_size;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, alice->out, alice->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH X PARAMETER CORRUPTED:\n\n%s\n", alice->out);

    // INFO(Rafael): Once upon a time, Bob received a signed message by Alice with X corrupted.

    bob->cipher = kKryptosCipherRSAEMSAPSS;

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);
    bob->arg[0] = &salt_size;
    bob->arg[1] = bob->arg[2] = NULL;

    kryptos_rsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);
    CUTE_ASSERT(bob->out == NULL);
    CUTE_ASSERT(bob->out_size == 0);

    printf(" *** Nice, the signed output with x corrupted was successfully detected => '%s'\n\n", bob->result_verbose);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    alice->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(alice->out != NULL);
    memset(alice->out, 0, signature_size + 1);
    CUTE_ASSERT(memcpy(alice->out, signature, signature_size) == alice->out);
    alice->out_size = signature_size;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, alice->out, alice->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH S PARAMETER CORRUPTED:\n\n%s\n", alice->out);

    // INFO(Rafael): Once upon a time, Bob received a signed message by Alice with S corrupted.

    bob->cipher = kKryptosCipherRSAEMSAPSS;

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);
    bob->arg[0] = &salt_size;
    bob->arg[1] = bob->arg[2] = NULL;

    kryptos_rsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);

    printf(" *** Nice, the signed output with s corrupted was successfully detected => '%s'\n\n", bob->result_verbose);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    alice->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(alice->out != NULL);
    memset(alice->out, 0, signature_size + 1);
    CUTE_ASSERT(memcpy(alice->out, signature, signature_size) == alice->out);
    alice->out_size = signature_size;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, alice->out, alice->out_size) == 1);
    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, alice->out, alice->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH BOTH X AND S PARAMETERS CORRUPTED:\n\n%s\n", alice->out);

    // INFO(Rafael): Once upon a time, Bob received a signed message by Alice, totally corrupted.

    bob->cipher = kKryptosCipherRSAEMSAPSS;

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);
    bob->arg[0] = &salt_size;
    bob->arg[1] = bob->arg[2] = NULL;

    kryptos_rsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);

    printf(" *** Nice, the signed output with x and s corrupted was successfully detected => '%s'\n", bob->result_verbose);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_freeseg(signature);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rsa_emsa_pss_digital_signature_scheme_c99_tests)
#ifdef KRYPTOS_C99
    kryptos_u8_t *k_pub_bob = "-----BEGIN RSA PARAM N-----\n"
                              "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoVg"
                              "7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "o13jdPAiis0sJZeh0OL9jL8Tib/EgoVNLqNXCM966j1qD4yq5KcXgrDezI48lxWDn66cZnppeXGfK8d0ym8U85JsXVgV2ao4"
                              "5ESDnBQFoRSoeQ3p3QVqDzfgViMeHIinMzFxx/OYpSgxpuQq4em4CwrBkqn1DxlRCzNCrdAqiwo=\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
                               "NVI5j80KqEf1P7rxVnVSHVs0OJCvXigDIQpLnaujZae01zTqDMTT92+/i1ft4rpRqaJYat/DzQn+kJLPtxBESlJV84xjNoV"
                               "g7EqHRKl+6isyC/UbyAF1ioQr6LnoQ5fxFRtDbKEvKU8AUPPndYBuY3UcdJU+p2ezf4s5u3sMOhs=\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "D3fMDiyVdMeojcOJuo4rB8CdgjNrxS2M9eORsLeiI6t+AiQpsE9LDlk62xHRAKfvX42RDkrlnr1g6PY3shIuPKcSfqLcl+S"
                               "dvt3NHzRLM8CEgJSWrUu919xo/IUKhFyFdN5ClYwpvaXaK/MVM1AV8gihLHpEsQT9gNfTgwDrVxU=\n"
                               "-----END RSA PARAM D-----\n";

    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *m = "We live in a political world, wisdom is thrown in jail\x00\x00";
    size_t m_size = 56;
    size_t salt_size = 8;
    kryptos_u8_t *signature = NULL;
    size_t signature_size = 0;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    // INFO(Rafael): Bob sign the message.

    kryptos_sign(rsa_emsa_pss, bob, m, m_size, k_priv_bob, strlen(k_priv_bob), &salt_size, NULL, NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->out != NULL);

    printf(" *** SIGNED OUTPUT:\n\n%s\n", bob->out);

    // INFO(Rafael): Now Alice simply verify.

    kryptos_verify(rsa_emsa_pss, alice, bob->out, bob->out_size, k_pub_bob, strlen(k_pub_bob), &salt_size, NULL, NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->out != NULL);

    printf(" *** AUTHENTICATED OUTPUT:\n\n'%s'\n\n", alice->out);


    signature = bob->out;
    signature_size = bob->out_size;

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Corrupted signature cases.

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(bob->out != NULL);
    memset(bob->out, 0, signature_size + 1);
    CUTE_ASSERT(memcpy(bob->out, signature, signature_size) == bob->out);
    bob->out_size = signature_size;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, bob->out, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH X CORRUPTED:\n\n%s\n", bob->out);

    kryptos_verify(rsa_emsa_pss, alice, bob->out, bob->out_size, k_pub_bob, strlen(k_pub_bob), &salt_size, NULL, NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);

    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with x corrupted was successfully detected => '%s'\n\n", alice->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_task_free(alice, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(bob->out != NULL);
    memset(bob->out, 0, signature_size + 1);
    CUTE_ASSERT(memcpy(bob->out, signature, signature_size) == bob->out);
    bob->out_size = signature_size;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, bob->out, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH S CORRUPTED:\n\n%s\n", bob->out);

    kryptos_verify(rsa_emsa_pss, alice, bob->out, bob->out_size, k_pub_bob, strlen(k_pub_bob), &salt_size, NULL, NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);

    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with s corrupted was successfully detected => '%s'\n\n", alice->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_task_free(alice, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->out = (kryptos_u8_t *) kryptos_newseg(signature_size + 1);
    CUTE_ASSERT(bob->out != NULL);
    memset(bob->out, 0, signature_size + 1);
    CUTE_ASSERT(memcpy(bob->out, signature, signature_size) == bob->out);
    bob->out_size = signature_size;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, bob->out, bob->out_size) == 1);
    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, bob->out, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH BOTH X AND S CORRUPTED:\n\n%s\n", bob->out);

    kryptos_verify(rsa_emsa_pss, alice, bob->out, bob->out_size, k_pub_bob, strlen(k_pub_bob), &salt_size, NULL, NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);

    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with x and s corrupted was successfully detected => '%s'\n", alice->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_freeseg(signature);
#else
    printf("WARN: No c99 support, this test was skipped.\n");
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dsa_mk_key_pair_tests)
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size = 0, k_priv_size = 0;
    kryptos_u8_t *data = NULL;
    size_t dsize = 0;

    CUTE_ASSERT(kryptos_dsa_mk_key_pair(80, 40, NULL, &k_pub_size, &k_priv, &k_priv_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dsa_mk_key_pair(80, 40, &k_pub, NULL, &k_priv, &k_priv_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dsa_mk_key_pair(80, 40, &k_pub, &k_pub_size, NULL, &k_priv_size) == kKryptosInvalidParams);
    CUTE_ASSERT(kryptos_dsa_mk_key_pair(80, 40, &k_pub, &k_pub_size, &k_priv, NULL) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_dsa_mk_key_pair(80, 40, &k_pub, &k_pub_size, &k_priv, &k_priv_size) == kKryptosSuccess);

    CUTE_ASSERT(k_pub != NULL && k_priv != NULL && k_pub_size > 0 && k_priv_size > 0);

    printf(" *** DSA PUBLIC KEY:\n\n");
    printf("%s", k_pub);

    printf("\n *** DSA PRIVATE KEY:\n\n");
    printf("%s", k_priv);

    // INFO(Rafael): Verifying the public exported parameters.

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_P, k_pub, k_pub_size, &dsize);
    CUTE_ASSERT(data != NULL);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_Q, k_pub, k_pub_size, &dsize);
    CUTE_ASSERT(data != NULL);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_G, k_pub, k_pub_size, &dsize);
    CUTE_ASSERT(data != NULL);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_E, k_pub, k_pub_size, &dsize);
    CUTE_ASSERT(data != NULL);
    kryptos_freeseg(data);

    // WARN(Rafael): D parameter must not be in public key.

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_D, k_pub, k_pub_size, &dsize);
    CUTE_ASSERT(data == NULL);

    // INFO(Rafael): Verifying the private exported parameters.

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_P, k_priv, k_priv_size, &dsize);
    CUTE_ASSERT(data != NULL);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_Q, k_priv, k_priv_size, &dsize);
    CUTE_ASSERT(data != NULL);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_G, k_priv, k_priv_size, &dsize);
    CUTE_ASSERT(data != NULL);
    kryptos_freeseg(data);

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_D, k_priv, k_priv_size, &dsize);
    CUTE_ASSERT(data != NULL);
    kryptos_freeseg(data);

    // WARN(Rafael): E parameter should not be in private key. It is useless.

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_E, k_priv, k_priv_size, &dsize);
    CUTE_ASSERT(data == NULL);

    kryptos_freeseg(k_pub);
    kryptos_freeseg(k_priv);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dsa_digital_signature_scheme_tests)
    kryptos_u8_t *k_pub = "-----BEGIN DSA P-----\n"
                          "76+T2iexCO+8DyRunM+C/s2"
                          "ZnFkMkjMc//9s73K5/amsrt"
                          "OkdSV7lk7pzJ42F+r6ADDUi"
                          "lrhuACKPIB1njip52eqhqAW"
                          "saaRlqO4NreuuP6xrklIyjO"
                          "XsMCyE42lbqPFcz0cQ6dMF8"
                          "QRMfMoOG2p876TyZ27j+Rcn"
                          "PW3FkUfdwM=\n"
                          "-----END DSA P-----\n"
                          "-----BEGIN DSA Q-----\n"
                          "A1ZqYQysooTOXh1vSDb97Cc"
                          "nOw4=\n"
                          "-----END DSA Q-----\n"
                          "-----BEGIN DSA G-----\n"
                          "rjWQKTVIrNOBCEf34l9rg+u"
                          "TsHpCRqco+LlHmkYUCxgvm6"
                          "ovn0tItPDhur9P6yL4Laqo4"
                          "pdRI2amS2AromXKeHF13X3D"
                          "6VamG1QJRN9atfwoj924M2z"
                          "9BNjszTI6gNZjSp9pw7Iytu"
                          "fjsqiA4ZYRysiL9JSWdadW1"
                          "2Bhp/1xeQA=\n"
                          "-----END DSA G-----\n"
                          "-----BEGIN DSA E-----\n"
                          "2Sl6jikSmoZiUucvseQA9/s"
                          "hs2HHP2BUVEJ+KysWltx9T6"
                          "TuT7vSkX7L7ovTbFJEQHI3s"
                          "ZPtj7GGDpxCPSYHw8KoV4W7"
                          "1iHLQArwfd0/s5J/GyeCoB1"
                          "vLi+2T7EdqsF7mXomJfb7WX"
                          "mF+pvKUoMnJpmVIpSifPkke"
                          "Q35lzdxSgE=\n"
                          "-----END DSA E-----\n";

    kryptos_u8_t *k_priv = "-----BEGIN DSA P-----\n"
                           "76+T2iexCO+8DyRunM+C/s2"
                           "ZnFkMkjMc//9s73K5/amsrt"
                           "OkdSV7lk7pzJ42F+r6ADDUi"
                           "lrhuACKPIB1njip52eqhqAW"
                           "saaRlqO4NreuuP6xrklIyjO"
                           "XsMCyE42lbqPFcz0cQ6dMF8"
                           "QRMfMoOG2p876TyZ27j+Rcn"
                           "PW3FkUfdwM=\n"
                           "-----END DSA P-----\n"
                           "-----BEGIN DSA Q-----\n"
                           "A1ZqYQysooTOXh1vSDb97Cc"
                           "nOw4=\n"
                           "-----END DSA Q-----\n"
                           "-----BEGIN DSA G-----\n"
                           "rjWQKTVIrNOBCEf34l9rg+u"
                           "TsHpCRqco+LlHmkYUCxgvm6"
                           "ovn0tItPDhur9P6yL4Laqo4"
                           "pdRI2amS2AromXKeHF13X3D"
                           "6VamG1QJRN9atfwoj924M2z"
                           "9BNjszTI6gNZjSp9pw7Iytu"
                           "fjsqiA4ZYRysiL9JSWdadW1"
                           "2Bhp/1xeQA=\n"
                           "-----END DSA G-----\n"
                           "-----BEGIN DSA D-----\n"
                           "IuY4TKL6Rp2oJQxMuDY37xo"
                           "Reg0=\n"
                           "-----END DSA D-----\n";

    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *m = "Provisoriamente não cantaremos o amor,\n"
                      "que se refugiou mais abaixo dos subterrâneos.\n"
                      "Cantaremos o medo, que estereliza os abraços.\n\n"
                      "não cantaremos o ódio, porque este não existe,\n"
                      "existe apenas o medo, nosso pai e nosso companheiro,\n"
                      "o medo grande dos sertões, dos mares, dos desertos,\n"
                      "o medo dos soldados, o medo das mães, o medo das igrejas,\n"
                      "cantaremos o medo dos ditadores, o medo dos democratas,\n"
                      "cantaremos o medo da morte e o medo de depois da morte.\n"
                      "Depois morreremos de medo\n"
                      "e sobre nossos túmulos nascerão flores amarelas e medrosas.";
    size_t m_size;

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);
    m_size = strlen(m);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    alice->in = m;
    alice->in_size = m_size;
    alice->key = k_priv;
    alice->key_size = strlen(k_priv);
    alice->cipher = kKryptosCipherDSA;

    kryptos_dsa_sign(&alice);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->out != NULL);

    printf(" *** SIGNED OUTPUT:\n\n%s\n", alice->out);

    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub;
    bob->key_size = strlen(k_pub);
    bob->cipher = kKryptosCipherDSA;

    kryptos_dsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->out != NULL);
    CUTE_ASSERT(bob->out_size == m_size);
    CUTE_ASSERT(memcmp(bob->out, m, m_size) == 0);

    printf(" *** AUTHENTICATED OUTPUT:\n\n'%s'\n\n", bob->out);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->in = (kryptos_u8_t *) kryptos_newseg(alice->out_size + 1);
    CUTE_ASSERT(bob->in != NULL);
    memset(bob->in, 0, alice->out_size + 1);
    memcpy(bob->in, alice->out, alice->out_size);
    bob->in_size = alice->out_size;
    bob->key = k_pub;
    bob->key_size = strlen(bob->key);
    bob->cipher = kKryptosCipherDSA;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_DSA_PEM_HDR_PARAM_R, bob->in, bob->in_size) == 1);

    printf(" *** SIGNED OUTPUT WITH R CORRUPTED:\n\n%s\n", bob->in);

    kryptos_dsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);
    CUTE_ASSERT(bob->out == NULL);
    CUTE_ASSERT(bob->out_size == 0);

    printf(" *** Nice, the signed output with r corrupted was successfully detected => '%s'\n\n", bob->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_IN);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->in = (kryptos_u8_t *) kryptos_newseg(alice->out_size + 1);
    CUTE_ASSERT(bob->in != NULL);
    memset(bob->in, 0, alice->out_size + 1);
    memcpy(bob->in, alice->out, alice->out_size);
    bob->in_size = alice->out_size;
    bob->key = k_pub;
    bob->key_size = strlen(bob->key);
    bob->cipher = kKryptosCipherDSA;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_DSA_PEM_HDR_PARAM_S, bob->in, bob->in_size) == 1);

    printf(" *** SIGNED OUTPUT WITH S CORRUPTED:\n\n%s\n", bob->in);

    kryptos_dsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);
    CUTE_ASSERT(bob->out == NULL);
    CUTE_ASSERT(bob->out_size == 0);

    printf(" *** Nice, the signed output with s corrupted was successfully detected => '%s'\n\n", bob->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_IN);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    bob->in = (kryptos_u8_t *) kryptos_newseg(alice->out_size + 1);
    CUTE_ASSERT(bob->in != NULL);
    memset(bob->in, 0, alice->out_size + 1);
    memcpy(bob->in, alice->out, alice->out_size);
    bob->in_size = alice->out_size;
    bob->key = k_pub;
    bob->key_size = strlen(bob->key);
    bob->cipher = kKryptosCipherDSA;

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_DSA_PEM_HDR_PARAM_R, bob->in, bob->in_size) == 1);
    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_DSA_PEM_HDR_PARAM_S, bob->in, bob->in_size) == 1);

    printf(" *** SIGNED OUTPUT WITH BOTH R AND S CORRUPTED:\n\n%s\n", bob->in);

    kryptos_dsa_verify(&bob);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 0);
    CUTE_ASSERT(bob->result == kKryptosInvalidSignature);
    CUTE_ASSERT(bob->out == NULL);
    CUTE_ASSERT(bob->out_size == 0);

    printf(" *** Nice, the signed output with r and s corrupted was successfully detected => '%s'\n\n", bob->result_verbose);

    kryptos_task_free(bob, KRYPTOS_TASK_IN);
    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dsa_digital_signature_scheme_c99_tests)
#ifdef KRYPTOS_C99
    kryptos_u8_t *k_pub = "-----BEGIN DSA P-----\n"
                          "76+T2iexCO+8DyRunM+C/s2"
                          "ZnFkMkjMc//9s73K5/amsrt"
                          "OkdSV7lk7pzJ42F+r6ADDUi"
                          "lrhuACKPIB1njip52eqhqAW"
                          "saaRlqO4NreuuP6xrklIyjO"
                          "XsMCyE42lbqPFcz0cQ6dMF8"
                          "QRMfMoOG2p876TyZ27j+Rcn"
                          "PW3FkUfdwM=\n"
                          "-----END DSA P-----\n"
                          "-----BEGIN DSA Q-----\n"
                          "A1ZqYQysooTOXh1vSDb97Cc"
                          "nOw4=\n"
                          "-----END DSA Q-----\n"
                          "-----BEGIN DSA G-----\n"
                          "rjWQKTVIrNOBCEf34l9rg+u"
                          "TsHpCRqco+LlHmkYUCxgvm6"
                          "ovn0tItPDhur9P6yL4Laqo4"
                          "pdRI2amS2AromXKeHF13X3D"
                          "6VamG1QJRN9atfwoj924M2z"
                          "9BNjszTI6gNZjSp9pw7Iytu"
                          "fjsqiA4ZYRysiL9JSWdadW1"
                          "2Bhp/1xeQA=\n"
                          "-----END DSA G-----\n"
                          "-----BEGIN DSA E-----\n"
                          "2Sl6jikSmoZiUucvseQA9/s"
                          "hs2HHP2BUVEJ+KysWltx9T6"
                          "TuT7vSkX7L7ovTbFJEQHI3s"
                          "ZPtj7GGDpxCPSYHw8KoV4W7"
                          "1iHLQArwfd0/s5J/GyeCoB1"
                          "vLi+2T7EdqsF7mXomJfb7WX"
                          "mF+pvKUoMnJpmVIpSifPkke"
                          "Q35lzdxSgE=\n"
                          "-----END DSA E-----\n";

    kryptos_u8_t *k_priv = "-----BEGIN DSA P-----\n"
                           "76+T2iexCO+8DyRunM+C/s2"
                           "ZnFkMkjMc//9s73K5/amsrt"
                           "OkdSV7lk7pzJ42F+r6ADDUi"
                           "lrhuACKPIB1njip52eqhqAW"
                           "saaRlqO4NreuuP6xrklIyjO"
                           "XsMCyE42lbqPFcz0cQ6dMF8"
                           "QRMfMoOG2p876TyZ27j+Rcn"
                           "PW3FkUfdwM=\n"
                           "-----END DSA P-----\n"
                           "-----BEGIN DSA Q-----\n"
                           "A1ZqYQysooTOXh1vSDb97Cc"
                           "nOw4=\n"
                           "-----END DSA Q-----\n"
                           "-----BEGIN DSA G-----\n"
                           "rjWQKTVIrNOBCEf34l9rg+u"
                           "TsHpCRqco+LlHmkYUCxgvm6"
                           "ovn0tItPDhur9P6yL4Laqo4"
                           "pdRI2amS2AromXKeHF13X3D"
                           "6VamG1QJRN9atfwoj924M2z"
                           "9BNjszTI6gNZjSp9pw7Iytu"
                           "fjsqiA4ZYRysiL9JSWdadW1"
                           "2Bhp/1xeQA=\n"
                           "-----END DSA G-----\n"
                           "-----BEGIN DSA D-----\n"
                           "IuY4TKL6Rp2oJQxMuDY37xo"
                           "Reg0=\n"
                           "-----END DSA D-----\n";

    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *m = "Esse é tempo de partido,\n"
                      "tempo de homens partidos.\n\n"
                      "É tempo de meio silêncio,\n"
                      "de boca gelada e murmúrio,\n"
                      "palavra indireta, aviso\n"
                      "na esquina. Tempo de cinco sentidos\n"
                      "num só. O espião janta conosco.";
    size_t m_size = strlen(m);
    kryptos_u8_t *signature = NULL;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    kryptos_sign(dsa, bob, m, m_size, k_priv, strlen(k_priv), NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(bob) == 1);
    CUTE_ASSERT(bob->out != NULL);

    printf(" *** SIGNED OUTPUT:\n\n%s\n", bob->out);

    kryptos_verify(dsa, alice, bob->out, bob->out_size, k_pub, strlen(k_pub), NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 1);
    CUTE_ASSERT(alice->out != NULL);
    CUTE_ASSERT(alice->out_size == m_size);
    CUTE_ASSERT(memcmp(alice->out, m, alice->out_size) == 0);

    printf(" *** AUTHENTICATED OUTPUT:\n\n'%s'\n\n", alice->out);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    signature = (kryptos_u8_t *) kryptos_newseg(bob->out_size + 1);
    CUTE_ASSERT(signature != NULL);
    memset(signature, 0, bob->out_size + 1);
    memcpy(signature, bob->out, bob->out_size);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_DSA_PEM_HDR_PARAM_R, signature, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH R CORRUPTED:\n\n%s\n", signature);

    kryptos_verify(dsa, alice, signature, bob->out_size, k_pub, strlen(k_pub), NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);
    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with r corrupted was successfully detected => '%s'\n\n", alice->result_verbose);

    kryptos_freeseg(signature);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    signature = (kryptos_u8_t *) kryptos_newseg(bob->out_size + 1);
    CUTE_ASSERT(signature != NULL);
    memset(signature, 0, bob->out_size + 1);
    memcpy(signature, bob->out, bob->out_size);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_DSA_PEM_HDR_PARAM_S, signature, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH S CORRUPTED:\n\n%s\n", signature);

    kryptos_verify(dsa, alice, signature, bob->out_size, k_pub, strlen(k_pub), NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);
    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with s corrupted was successfully detected => '%s'\n\n", alice->result_verbose);

    kryptos_freeseg(signature);

    printf(" *** ORIGINAL MESSAGE:\n\n'%s'\n\n", m);

    signature = (kryptos_u8_t *) kryptos_newseg(bob->out_size + 1);
    CUTE_ASSERT(signature != NULL);
    memset(signature, 0, bob->out_size + 1);
    memcpy(signature, bob->out, bob->out_size);

    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_DSA_PEM_HDR_PARAM_R, signature, bob->out_size) == 1);
    CUTE_ASSERT(corrupt_pem_data(KRYPTOS_DSA_PEM_HDR_PARAM_S, signature, bob->out_size) == 1);

    printf(" *** SIGNED OUTPUT WITH BOTH R AND S CORRUPTED:\n\n%s\n", signature);

    kryptos_verify(dsa, alice, signature, bob->out_size, k_pub, strlen(k_pub), NULL);

    CUTE_ASSERT(kryptos_last_task_succeed(alice) == 0);
    CUTE_ASSERT(alice->result == kKryptosInvalidSignature);
    CUTE_ASSERT(alice->out == NULL);
    CUTE_ASSERT(alice->out_size == 0);

    printf(" *** Nice, the signed output with r and s corrupted was successfully detected => '%s'\n\n", alice->result_verbose);

    kryptos_freeseg(signature);

    kryptos_task_free(bob, KRYPTOS_TASK_OUT);
#else
    printf("WARN: No c99 support, this test was skipped.\n");
#endif
CUTE_TEST_CASE_END
