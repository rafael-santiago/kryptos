/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "otp_tests.h"
#include <kryptos.h>

static size_t bad_hash_size(void);

static void otp_hash_validator(kryptos_hash_func h,
                               kryptos_hash_size_func h_input_size,
                               kryptos_hash_size_func h_size,
                               kryptos_hash_func *h_addr,
                               kryptos_hash_size_func *h_input_addr,
                               kryptos_hash_size_func *h_size_addr);

KUTE_TEST_CASE(kryptos_hotp_tests)
    struct test_ctx {
        kryptos_u8_t *secret;
        size_t secret_size;
        size_t d;
        kryptos_u64_t count;
        kryptos_u64_t expected_count;
        kryptos_hash_func h;
        kryptos_hash_size_func h_input_size;
        kryptos_hash_size_func h_size;
        kryptos_u32_t expected;
    } test_vector[] = {
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 0,  1,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 755224 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 1,  2,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 287082 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 2,  3,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 359152 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 3,  4,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 969429 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 4,  5,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 338314 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 5,  6,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 254676 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 6,  7,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 287922 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 7,  8,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 162583 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 8,  9,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 399871 },
        { (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 9, 10,
                          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size, 520489 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u64_t c;
    while (test != test_end) {
        c = test->count;
        KUTE_ASSERT(kryptos_hotp_init(ktask,
                                      kKryptosGenerateToken,
                                      test->secret, test->secret_size,
                                      &c,
                                      NULL,
                                      NULL,
                                      &test->d,
                                      test->h, test->h_input_size, test->h_size) == kKryptosSuccess);
        KUTE_ASSERT(kryptos_hotp(&ktask) == kKryptosSuccess);
        KUTE_ASSERT(c == test->expected_count);
        KUTE_ASSERT(ktask->out != NULL);
        KUTE_ASSERT(ktask->out_size == sizeof(kryptos_u32_t));
        KUTE_ASSERT(*(kryptos_u32_t *)ktask->out == test->expected);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        test++;
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_hotp_sequencing_tests)
    static kryptos_u32_t test_values_0[] = {
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489
    };
    struct test_ctx {
        kryptos_u8_t *secret;
        size_t secret_size;
        size_t d;
        size_t initial_counter;
        kryptos_hash_func h;
        kryptos_hash_size_func h_input_size;
        kryptos_hash_size_func h_size;
        kryptos_u32_t *values;
        size_t values_nr;
    } test_vector[] = {
        {
          (kryptos_u8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                          "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30", 20, 6, 0,
          kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size,
          &test_values_0[0],
          sizeof(test_values_0) / sizeof(test_values_0[0]),
        },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u32_t *value = NULL, *value_end = NULL;
    kryptos_u64_t c = 0, cn = 0;
    kryptos_task_ctx t, *ktask = &t;

    while (test != test_end) {
        c = test->initial_counter;
        KUTE_ASSERT(kryptos_hotp_init(ktask,
                                      kKryptosGenerateToken,
                                      test->secret, test->secret_size,
                                      &c,
                                      NULL,
                                      NULL,
                                      &test->d,
                                      test->h, test->h_input_size, test->h_size) == kKryptosSuccess);
        value = test->values;
        value_end = value + test->values_nr;
        while (value != value_end) {
            cn = c + 1;
            KUTE_ASSERT(kryptos_hotp(&ktask) == kKryptosSuccess);
            KUTE_ASSERT(c == cn);
            KUTE_ASSERT(ktask->out != NULL);
            KUTE_ASSERT(ktask->out_size == sizeof(kryptos_u32_t));
            KUTE_ASSERT(*(kryptos_u32_t *)ktask->out == *value);
            kryptos_freeseg(ktask->out, ktask->out_size);
            value++;
        }
        test++;
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_hotp_client_server_syncd_interaction_tests)
    // INFO(Rafael): This test does not take into consideration any exception
    //               that may occur in real world. Things such as wrong tokens
    //               given by the client and so on. It only simulates well
    //               synchronized sessions in order to test the basic
    //               authentication dynamics by generating and validating
    //               tokens from 1 up to 10 digits.
    kryptos_task_ctx s, *server = &s, c, *client = &c;
    kryptos_u64_t client_c = 0, server_c = 0;
    size_t server_throttling_param = 5;
    size_t server_resync_param = 6;
    size_t test_nr = 100000, t;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"FunkyDooEHarris"; // 'Eddie Who?' ;)
    size_t shared_secret_size = 15;
    size_t d, d_nr = 9;
    for (d = 1; d <= d_nr; d++) {
        KUTE_ASSERT(kryptos_hotp_init(server,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &server_c, &server_throttling_param, &server_resync_param, &d,
                                      kryptos_sha256_hash,
                                      kryptos_sha256_hash_input_size,
                                      kryptos_sha256_hash_size) == kKryptosSuccess);

        KUTE_ASSERT(kryptos_hotp_init(client,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &client_c, NULL, NULL, &d,
                                      kryptos_sha256_hash,
                                      kryptos_sha256_hash_input_size,
                                      kryptos_sha256_hash_size) == kKryptosSuccess);

        for (t = 0; t < test_nr; t++) {
            KUTE_ASSERT(kryptos_hotp(&client) == kKryptosSuccess);
            server->in = client->out;
            server->in_size = client->out_size;
            KUTE_ASSERT(kryptos_hotp(&server) == kKryptosSuccess);
            kryptos_freeseg(client->out, client->out_size);
        }
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_hotp_client_server_unsyncd_interaction_tests)
    kryptos_task_ctx p, *poison = &p, l, *lux = &l;
    kryptos_u64_t poison_c = 0, lux_c = 0;
    size_t poison_throttling_param = 0;
    size_t poison_resync_param = 0;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"UltraTwist";
    size_t shared_secret_size = 10;
    size_t d, d_nr = 9;
    size_t t;
    size_t test_nr = 100000;

    // TIP(Rafael): Testing token with 1 digit size is pointless since it is collision prone.
    //              It is also a good proof that you should pick greater digit sizes to get rid off
    //              those weak tokens. A trade-off among resync, throttle and d parameters is
    //              essential, too.
    for (d = 2; d <= d_nr; d++) {
        // INFO(Rafael): Pretty unsyncd counters not chance of authenticate.
        poison_c = 5;
        poison_throttling_param = 10;
        poison_resync_param = 6;
        lux_c = 0;
        KUTE_ASSERT(kryptos_hotp_init(poison,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &poison_c, &poison_throttling_param, &poison_resync_param, &d,
                                      kryptos_sha3_512_hash, kryptos_sha3_512_hash_input_size,
                                      kryptos_sha3_512_hash_size) == kKryptosSuccess);

        KUTE_ASSERT(kryptos_hotp_init(lux,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &lux_c, NULL, NULL, &d,
                                      kryptos_sha3_512_hash, kryptos_sha3_512_hash_input_size,
                                      kryptos_sha3_512_hash_size) == kKryptosSuccess);

        KUTE_ASSERT(kryptos_hotp(&lux) == kKryptosSuccess);

        poison->in = lux->out;
        poison->in_size = lux->out_size;

        KUTE_ASSERT(kryptos_hotp(&poison) == kKryptosInvalidToken);

        for (t = 0; t < test_nr; t++) {
            // INFO(Rafael): It must keep failing until server explicitly re-init it.
            KUTE_ASSERT(kryptos_hotp(&poison) == kKryptosInvalidToken);
        }
        kryptos_freeseg(lux->out, lux->out_size);

        // INFO(Rafael): Client ahead of server within resync window size.
        poison_c = 0;
        poison_throttling_param = 15;
        poison_resync_param = 10;
        lux_c = 5;
        KUTE_ASSERT(kryptos_hotp_init(poison,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &poison_c, &poison_throttling_param, &poison_resync_param, &d,
                                      kryptos_tiger_hash, kryptos_tiger_hash_input_size,
                                      kryptos_tiger_hash_size) == kKryptosSuccess);

        KUTE_ASSERT(kryptos_hotp_init(lux,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &lux_c, NULL, NULL, &d,
                                      kryptos_tiger_hash, kryptos_tiger_hash_input_size,
                                      kryptos_tiger_hash_size) == kKryptosSuccess);

        for (t = 0; t < test_nr; t++) {
            KUTE_ASSERT(kryptos_hotp(&lux) == kKryptosSuccess);
            poison->in = lux->out;
            poison->in_size = lux->out_size;
            // INFO(Rafael): During the first validation attempt, server will synchronize with client.
            KUTE_ASSERT(kryptos_hotp(&poison) == kKryptosSuccess);
            KUTE_ASSERT(poison_c == lux_c);
            kryptos_freeseg(lux->out, lux->out_size);
        }

        // INFO(Rafael): Client ahead of server but exceeding throttling limit.
        poison_c = 0;
        poison_throttling_param = 5;
        poison_resync_param = 6;
        lux_c = 6;
        KUTE_ASSERT(kryptos_hotp_init(poison,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &poison_c, &poison_throttling_param, &poison_resync_param, &d,
                                      kryptos_tiger_hash, kryptos_tiger_hash_input_size,
                                      kryptos_tiger_hash_size) == kKryptosSuccess);

        KUTE_ASSERT(kryptos_hotp_init(lux,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &lux_c, NULL, NULL, &d,
                                      kryptos_tiger_hash, kryptos_tiger_hash_input_size,
                                      kryptos_tiger_hash_size) == kKryptosSuccess);

        KUTE_ASSERT(kryptos_hotp(&lux) == kKryptosSuccess);

        poison->in = lux->out;
        poison->in_size = lux->out_size;

        KUTE_ASSERT(kryptos_hotp(&poison) == kKryptosInvalidToken);

        for (t = 0; t < test_nr; t++) {
            // INFO(Rafael): It must keep failing until user explicitly re-init it.
            KUTE_ASSERT(kryptos_hotp(&poison) == kKryptosInvalidToken);
        }
        kryptos_freeseg(lux->out, lux->out_size);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_hotp_init_bad_params_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"M0nk3yW1thY0urT41l";
    size_t shared_secret_size = 18;
    kryptos_u64_t moving_factor = 5;
    size_t throttling_param = 7;
    size_t resync_param = 4;
    size_t number_of_digits = 4;
    kryptos_hash_func h = kryptos_whirlpool_hash;
    kryptos_hash_size_func h_input_size = kryptos_whirlpool_hash_input_size;
    kryptos_hash_size_func h_size = kryptos_whirlpool_hash_size;

    // INFO(Rafael): Bad parameters for token validation context.

    KUTE_ASSERT(kryptos_hotp_init(NULL,
                                  kKryptosValidateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  &throttling_param,
                                  &resync_param,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosValidateToken,
                                  NULL,
                                  shared_secret_size,
                                  &moving_factor,
                                  &throttling_param,
                                  &resync_param,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);


    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret,
                                  0,
                                  &moving_factor,
                                  &throttling_param,
                                  &resync_param,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  NULL,
                                  &throttling_param,
                                  &resync_param,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  NULL,
                                  &resync_param,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    throttling_param = 0;

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  &throttling_param,
                                  &resync_param,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    throttling_param = 5;

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  &throttling_param,
                                  NULL,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    number_of_digits = 0;

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  &throttling_param,
                                  &resync_param,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    number_of_digits = 10;

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  &throttling_param,
                                  &resync_param,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  bad_hash_size) == kKryptosInvalidParams);

    number_of_digits = 4;

    // INFO(Rafael): Bad parameters for token generation context.

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosGenerateToken,
                                  NULL,
                                  shared_secret_size,
                                  NULL,
                                  NULL,
                                  NULL,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosGenerateToken,
                                  shared_secret,
                                  0,
                                  &moving_factor,
                                  NULL,
                                  NULL,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);


    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosGenerateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  NULL,
                                  NULL,
                                  NULL,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    number_of_digits = 0;

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosGenerateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  NULL,
                                  NULL,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);


    number_of_digits = 10;

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosGenerateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  NULL,
                                  NULL,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    number_of_digits = 4;

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosGenerateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  NULL,
                                  NULL,
                                  &number_of_digits,
                                  NULL,
                                  h_input_size,
                                  h_size) == kKryptosInvalidParams);

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosGenerateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  NULL,
                                  NULL,
                                  &number_of_digits,
                                  h,
                                  NULL,
                                  h_size) == kKryptosInvalidParams);

    KUTE_ASSERT(kryptos_hotp_init(ktask,
                                  kKryptosGenerateToken,
                                  shared_secret,
                                  shared_secret_size,
                                  &moving_factor,
                                  NULL,
                                  NULL,
                                  &number_of_digits,
                                  h,
                                  h_input_size,
                                  bad_hash_size) == kKryptosInvalidParams);

KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_otp_hash_macro_tests)
    kryptos_hash_func h_addr = NULL;
    kryptos_hash_size_func h_input_addr = NULL, h_size_addr = NULL;
    otp_hash_validator(kryptos_otp_hash(sha512), &h_addr, &h_input_addr, &h_size_addr);
    KUTE_ASSERT(h_addr == kryptos_sha512_hash);
    KUTE_ASSERT(h_input_addr == kryptos_sha512_hash_input_size);
    KUTE_ASSERT(h_size_addr == kryptos_sha512_hash_size);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_otp_macro_tests)
#if defined(KRYPTOS_C99)
    kryptos_task_ctx c, s, *client = &c, *server = &s;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"HowFarCanTooFarGo?";
    size_t shared_secret_size = 18;
    kryptos_u64_t moving_factor_client = 9, moving_factor_server = 9;
    size_t throttling = 30;
    size_t resync = 7;
    size_t number_of_digits = 6;
    // INFO(Rafael): For each available OTP algorithm put a successful generate/validation test by using related
    //               general OTP macro functions (that fits with the algorithm, of course).

    // HOTP

    KUTE_ASSERT(kryptos_otp_init(hotp,
                                 server,
                                 kKryptosValidateToken,
                                 shared_secret,
                                 shared_secret_size,
                                 &moving_factor_server,
                                 &throttling,
                                 &resync,
                                 &number_of_digits,
                                 kryptos_otp_hash(sha3_512)) == kKryptosSuccess);

    KUTE_ASSERT(kryptos_otp_init(hotp,
                                 client,
                                 kKryptosGenerateToken,
                                 shared_secret,
                                 shared_secret_size,
                                 &moving_factor_client,
                                 NULL,
                                 NULL,
                                 &number_of_digits,
                                 kryptos_otp_hash(sha3_512)) == kKryptosSuccess);

    KUTE_ASSERT(kryptos_otp(hotp, client) == kKryptosSuccess);

    kryptos_otp_set_token(server, client->out, client->out_size);

    KUTE_ASSERT(kryptos_otp(hotp, server) == kKryptosSuccess);

    kryptos_otp_free_token(client);
#else
    fprintf(stdout, "   Test skipped. Compiled with no C99 support.\n");
#endif
KUTE_TEST_CASE_END

static size_t bad_hash_size(void) {
    return 14;
}

static void otp_hash_validator(kryptos_hash_func h,
                               kryptos_hash_size_func h_input_size,
                               kryptos_hash_size_func h_size,
                               kryptos_hash_func *h_addr,
                               kryptos_hash_size_func *h_input_addr,
                               kryptos_hash_size_func *h_size_addr) {
    *h_addr = h;
    *h_input_addr = h_input_size;
    *h_size_addr = h_size;
}
