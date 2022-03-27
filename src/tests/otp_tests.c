/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "otp_tests.h"
#include <kryptos.h>
#if defined(__unix__)
# include <dlfcn.h>
#elif defined(_WIN32)
# include <windows.h>
#endif

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// WARN(Rafael): Avoid including time.h on Windows, when compiling from MingGW. !!
//               It will break TOTP validation tests.                           !!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#if !defined(_WIN32) && !defined(RTLD_NEXT)
# define RTLD_NEXT -1
#endif


// INFO(Rafael): On some nosy systems even not have been included the 'time.h'
//               header they are linking local time reference with the original
//               one instead of with our local hook. This will force them to
//               not mess with our setup.
extern time_t time(time_t *);

static size_t bad_hash_size(void);

static kryptos_u64_t g_totp_curr_systime = 10800;

static time_t (*g_tru_time)(time_t *) = NULL;

static int g_do_time_hook = 0;

static void set_totp_current_systime(const kryptos_u64_t value);

static int enable_time_hook(void);

static void disable_time_hook(void);

#if defined(__unix__) || (defined(_WIN32) && !defined(_MSC_VER))
# if defined(_WIN32)
#  define _time64 time
# endif
time_t time(time_t *t) {
    if (!g_do_time_hook && g_tru_time != NULL) {
        return g_tru_time(t);
    }
    return g_totp_curr_systime;
}
#elif defined(_WIN32) && defined(_MSC_VER)
time_t _time64(time_t *t) {
    if (!g_do_time_hook && g_tru_time != NULL) {
        return g_tru_time(t);
    }
    return g_totp_curr_systime;
}
#else
# error Some code wanted.
#endif

static void otp_hash_validator(kryptos_hash_func hash,
                               kryptos_hash_size_func hash_input_size,
                               kryptos_hash_size_func hash_size,
                               kryptos_hash_func *hash_addr,
                               kryptos_hash_size_func *hash_input_addr,
                               kryptos_hash_size_func *hash_size_addr);

CUTE_TEST_CASE(kryptos_totp_client_server_syncd_interaction_tests)
    kryptos_task_ctx s, *server = &s, c, *client = &c;
    kryptos_u64_t t0 = 10800;
    kryptos_u64_t x = 30;
    size_t d;
    size_t t, t_nr = 100000;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"walden";
    size_t shared_secret_size = 6;

    for (d = 1; d <= 9; d++) {
        CUTE_ASSERT(kryptos_totp_init(server,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &t0, &x, &d,
                                      kryptos_sha512_hash,
                                      kryptos_sha512_hash_input_size,
                                      kryptos_sha512_hash_size) == kKryptosSuccess);

        CUTE_ASSERT(kryptos_totp_init(client,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &t0, &x, &d,
                                      kryptos_sha512_hash,
                                      kryptos_sha512_hash_input_size,
                                      kryptos_sha512_hash_size) == kKryptosSuccess);

        for (t = 1; t <= t_nr; t++) {
            CUTE_ASSERT(kryptos_totp(&client) == kKryptosSuccess);
            server->in = client->out;
            server->in_size = client->out_size;
            CUTE_ASSERT(kryptos_totp(&server) == kKryptosSuccess);
            kryptos_freeseg(client->out, client->out_size);
            fprintf(stdout, "       \r   %.0f%% complete (token with %zu digit(s)).", ((float)t / (float)t_nr) * 100, d);
        }
    }
    fprintf(stdout, "       \r                                                       \r");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_totp_client_server_unsyncd_interaction_tests)
    kryptos_task_ctx s, *server = &s, c, *client = &c;
    kryptos_u64_t t0 = 10800;
    kryptos_u64_t x = 30;
    size_t d;
    size_t t, t_nr = 100000;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"rock and a hard place";
    size_t shared_secret_size = 21;
    kryptos_u64_t timelapse = 108000;

    // INFO(Rafael): Here on this test we will simulate an unsynchronization
    //               by making client generate sent token 30 secs before server.
    //               It will force server to resynchronize.

    CUTE_ASSERT(enable_time_hook() == 0);

    for (d = 1; d <= 9; d++) {
        CUTE_ASSERT(kryptos_totp_init(server,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &t0, &x, &d,
                                      kryptos_sha512_hash,
                                      kryptos_sha512_hash_input_size,
                                      kryptos_sha512_hash_size) == kKryptosSuccess);

        CUTE_ASSERT(kryptos_totp_init(client,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &t0, &x, &d,
                                      kryptos_sha512_hash,
                                      kryptos_sha512_hash_input_size,
                                      kryptos_sha512_hash_size) == kKryptosSuccess);

        for (t = 1; t <= t_nr; t++) {
            set_totp_current_systime(timelapse);

            CUTE_ASSERT(kryptos_totp(&client) == kKryptosSuccess);

            // INFO(Rafael): TOTP authors recommend 2 backward checks when
            //               the current timestamp has failed. But here we
            //               will do only one.

            set_totp_current_systime(timelapse + 30);

            server->in = client->out;
            server->in_size = client->out_size;
            CUTE_ASSERT(kryptos_totp(&server) == kKryptosSuccess);

            set_totp_current_systime(timelapse + 60);

            server->in = client->out;
            server->in_size = client->out_size;
            CUTE_ASSERT(kryptos_totp(&server) == kKryptosInvalidToken);

            set_totp_current_systime(timelapse + 120);

            server->in = client->out;
            server->in_size = client->out_size;
            CUTE_ASSERT(kryptos_totp(&server) == kKryptosInvalidToken);

            kryptos_freeseg(client->out, client->out_size);

            // INFO(Rafael): Seeking to mitigate device synchronization issues
            //               we will do one check ahead.

            set_totp_current_systime(timelapse + 15);

            CUTE_ASSERT(kryptos_totp(&client) == kKryptosSuccess);

            set_totp_current_systime(timelapse);

            server->in = client->out;
            server->in_size = client->out_size;
            CUTE_ASSERT(kryptos_totp(&server) == kKryptosSuccess);

            kryptos_freeseg(client->out, client->out_size);

            fprintf(stdout, "       \r   %.0f%% complete (token with %zu digit(s)).", ((float)t / (float)t_nr) * 100, d);
        }
    }
    fprintf(stdout, "       \r                                                       \r");
    disable_time_hook();
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_totp_init_bad_params_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u64_t t0 = 10800;
    kryptos_u64_t x = 2;
    size_t d = 6;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"working day and night";
    size_t shared_secret_size = 21;

    CUTE_ASSERT(kryptos_totp_init(NULL,
                                  kKryptosValidateToken,
                                  shared_secret, shared_secret_size,
                                  &t0, &x, &d,
                                  kryptos_whirlpool_hash,
                                  kryptos_whirlpool_hash_input_size,
                                  kryptos_whirlpool_hash_size) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_totp_init(ktask,
                                  kKryptosEncrypt,
                                  shared_secret, shared_secret_size,
                                  &t0, &x, &d,
                                  kryptos_whirlpool_hash,
                                  kryptos_whirlpool_hash_input_size,
                                  kryptos_whirlpool_hash_size) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_totp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret, shared_secret_size,
                                  NULL, &x, &d,
                                  kryptos_whirlpool_hash,
                                  kryptos_whirlpool_hash_input_size,
                                  kryptos_whirlpool_hash_size) == kKryptosInvalidParams);

    CUTE_ASSERT(kryptos_totp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret, shared_secret_size,
                                  &t0, NULL, &d,
                                  kryptos_whirlpool_hash,
                                  kryptos_whirlpool_hash_input_size,
                                  kryptos_whirlpool_hash_size) == kKryptosInvalidParams);


    CUTE_ASSERT(kryptos_totp_init(ktask,
                                  kKryptosValidateToken,
                                  shared_secret, shared_secret_size,
                                  &t0, &x, &d,
                                  kryptos_whirlpool_hash,
                                  kryptos_whirlpool_hash_input_size,
                                  kryptos_whirlpool_hash_size) == kKryptosSuccess);

    CUTE_ASSERT(kryptos_totp_init(ktask,
                                  kKryptosGenerateToken,
                                  shared_secret, shared_secret_size,
                                  &t0, &x, &d,
                                  kryptos_whirlpool_hash,
                                  kryptos_whirlpool_hash_input_size,
                                  kryptos_whirlpool_hash_size) == kKryptosSuccess);

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_totp_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u64_t t0 = 10800;
    kryptos_u64_t x = 30;
    size_t number_of_digits = 8;
    struct test_ctx {
        const kryptos_u64_t timelapse;
        kryptos_u8_t *shared_secret;
        size_t shared_secret_size;
        kryptos_hash_func hash;
        kryptos_hash_size_func hash_input_size;
        kryptos_hash_size_func hash_size;
        kryptos_u32_t expected;
    } test_vector[] = {
        // INFO(Rafael): Picked from RFC-6238.
        //
        //               TOTP validation is demanding since we need to have the same timestamp on the test machine.
        //               I dislike messing with the environment when testing my stuff, due to it TOTP validation
        //               have been done only in user space testing. Here we are hooking the time() call making
        //               it spit the timelapse since Unix epoch that we need for each test step.
        //               TOTP's test vector is pretty messy. It states 'The test token shared secret uses ASCII string
        //               value "12345678901234567890"', but in fact it varies according to the hash algorithm by
        //               making the shared secret has the same size of the output produced by the hash, you can see it
        //               reading their Java code.
        //
        //               The provided time supplied on RFC's testing section here (timelapse field) were adjusted for
        //               a real-world testing necessity, which re-uses a previous HOTP implementation and avoid messing
        //               with testing environment date time.
        {
            10859,
            (kryptos_u8_t *)"12345678901234567890", 20,
            kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size,
            94287082
        },
        {
            10859,
            (kryptos_u8_t *)"12345678901234567890123456789012", 32,
            kryptos_sha256_hash, kryptos_sha256_hash_input_size, kryptos_sha256_hash_size,
            46119246
        },
        {
            10859,
            (kryptos_u8_t *)"1234567890123456789012345678901234567890123456789012345678901234", 64,
            kryptos_sha512_hash, kryptos_sha512_hash_input_size, kryptos_sha512_hash_size,
            90693936
        },
        {
            1111121899,
            (kryptos_u8_t *)"12345678901234567890", 20,
            kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size,
            7081804
        },
        {
            1111121899,
            (kryptos_u8_t *)"12345678901234567890123456789012", 32,
            kryptos_sha256_hash, kryptos_sha256_hash_input_size, kryptos_sha256_hash_size,
            68084774
        },
        {
            1111121899,
            (kryptos_u8_t *)"1234567890123456789012345678901234567890123456789012345678901234", 64,
            kryptos_sha512_hash, kryptos_sha512_hash_input_size, kryptos_sha512_hash_size,
            25091201
        },
        {
            1234578690,
            (kryptos_u8_t *)"12345678901234567890", 20,
            kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size,
            89005924
        },
        {
            1234578690,
            (kryptos_u8_t *)"12345678901234567890123456789012", 32,
            kryptos_sha256_hash, kryptos_sha256_hash_input_size, kryptos_sha256_hash_size,
            91819424
        },
        {
            1234578690,
            (kryptos_u8_t *)"1234567890123456789012345678901234567890123456789012345678901234", 64,
            kryptos_sha512_hash, kryptos_sha512_hash_input_size, kryptos_sha512_hash_size,
            93441116
        },
        {
            2000010800,
            (kryptos_u8_t *)"12345678901234567890", 20,
            kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size,
            69279037
        },
        {
            2000010800,
            (kryptos_u8_t *)"12345678901234567890123456789012", 32,
            kryptos_sha256_hash, kryptos_sha256_hash_input_size, kryptos_sha256_hash_size,
            90698825
        },
        {
            2000010800,
            (kryptos_u8_t *)"1234567890123456789012345678901234567890123456789012345678901234", 64,
            kryptos_sha512_hash, kryptos_sha512_hash_input_size, kryptos_sha512_hash_size,
            38618901
        },
        {
            20000010800,
            (kryptos_u8_t *)"12345678901234567890", 20,
            kryptos_sha1_hash, kryptos_sha1_hash_input_size, kryptos_sha1_hash_size,
            65353130
        },
        {
            20000010800,
            (kryptos_u8_t *)"12345678901234567890123456789012", 32,
            kryptos_sha256_hash, kryptos_sha256_hash_input_size, kryptos_sha256_hash_size,
            77737706
        },
        {
            20000010800,
            (kryptos_u8_t *)"1234567890123456789012345678901234567890123456789012345678901234", 64,
            kryptos_sha512_hash, kryptos_sha512_hash_input_size, kryptos_sha512_hash_size,
            47863826
        },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    CUTE_ASSERT(enable_time_hook() == 0);

    while (test != test_end) {
        set_totp_current_systime(test->timelapse); // INFO(Rafael): The time traveling routine our Y(), I meant our
                                                   //               flux capacitor ;)
        CUTE_ASSERT(kryptos_totp_init(ktask, kKryptosGenerateToken,
                                      test->shared_secret, test->shared_secret_size,
                                      &t0, &x,
                                      &number_of_digits,
                                      test->hash, test->hash_input_size, test->hash_size) == kKryptosSuccess);
        CUTE_ASSERT(kryptos_totp(&ktask) == kKryptosSuccess);
        CUTE_ASSERT(ktask->out_size == sizeof(kryptos_u32_t));
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(*(kryptos_u32_t *)ktask->out == test->expected);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        test++;
    }

    disable_time_hook();
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hotp_tests)
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
        CUTE_ASSERT(kryptos_hotp_init(ktask,
                                      kKryptosGenerateToken,
                                      test->secret, test->secret_size,
                                      &c,
                                      NULL,
                                      NULL,
                                      &test->d,
                                      test->h, test->h_input_size, test->h_size) == kKryptosSuccess);
        CUTE_ASSERT(kryptos_hotp(&ktask) == kKryptosSuccess);
        CUTE_ASSERT(c == test->expected_count);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == sizeof(kryptos_u32_t));
        CUTE_ASSERT(*(kryptos_u32_t *)ktask->out == test->expected);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hotp_sequencing_tests)
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
        CUTE_ASSERT(kryptos_hotp_init(ktask,
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
            CUTE_ASSERT(kryptos_hotp(&ktask) == kKryptosSuccess);
            CUTE_ASSERT(c == cn);
            CUTE_ASSERT(ktask->out != NULL);
            CUTE_ASSERT(ktask->out_size == sizeof(kryptos_u32_t));
            CUTE_ASSERT(*(kryptos_u32_t *)ktask->out == *value);
            kryptos_freeseg(ktask->out, ktask->out_size);
            value++;
        }
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hotp_client_server_syncd_interaction_tests)
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
        CUTE_ASSERT(kryptos_hotp_init(server,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &server_c, &server_throttling_param, &server_resync_param, &d,
                                      kryptos_sha256_hash,
                                      kryptos_sha256_hash_input_size,
                                      kryptos_sha256_hash_size) == kKryptosSuccess);

        CUTE_ASSERT(kryptos_hotp_init(client,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &client_c, NULL, NULL, &d,
                                      kryptos_sha256_hash,
                                      kryptos_sha256_hash_input_size,
                                      kryptos_sha256_hash_size) == kKryptosSuccess);

        for (t = 0; t < test_nr; t++) {
            CUTE_ASSERT(kryptos_hotp(&client) == kKryptosSuccess);
            server->in = client->out;
            server->in_size = client->out_size;
            CUTE_ASSERT(kryptos_hotp(&server) == kKryptosSuccess);
            kryptos_freeseg(client->out, client->out_size);
            fprintf(stdout, "       \r   %.0f%% complete (token with %zu digit(s)).", ((float)t / (float)test_nr) * 100, d);
        }
    }
    fprintf(stdout, "       \r                                                       \r");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hotp_client_server_unsyncd_interaction_tests)
    kryptos_task_ctx p, *poison = &p, l, *lux = &l;
    kryptos_u64_t poison_c = 0, lux_c = 0;
    size_t poison_throttling_param = 0;
    size_t poison_resync_param = 0;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"UltraTwist";
    size_t shared_secret_size = 10;
    size_t d, d_nr = 9;
    size_t t;
    size_t test_nr = 100000;

    fprintf(stdout, "   Hold on. Do not fall asleep...");

    // TIP(Rafael): Testing token with 1 digit size is pointless since it is collision prone.
    //              It is also a good proof that you should pick greater digit sizes to get rid off
    //              those weak tokens. A trade-off among resync, throttle and d parameters is
    //              essential, too.
    for (d = 2; d <= d_nr; d++) {
        // INFO(Rafael): Pretty unsyncd counters not chance of authenticate.
        poison_c = 5;
        poison_throttling_param = 5;
        poison_resync_param = 6;
        lux_c = 0;
        CUTE_ASSERT(kryptos_hotp_init(poison,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &poison_c, &poison_throttling_param, &poison_resync_param, &d,
                                      kryptos_sha3_512_hash, kryptos_sha3_512_hash_input_size,
                                      kryptos_sha3_512_hash_size) == kKryptosSuccess);

        CUTE_ASSERT(kryptos_hotp_init(lux,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &lux_c, NULL, NULL, &d,
                                      kryptos_sha3_512_hash, kryptos_sha3_512_hash_input_size,
                                      kryptos_sha3_512_hash_size) == kKryptosSuccess);

        CUTE_ASSERT(kryptos_hotp(&lux) == kKryptosSuccess);

        poison->in = lux->out;
        poison->in_size = lux->out_size;

        CUTE_ASSERT(kryptos_hotp(&poison) == kKryptosInvalidToken);

        for (t = 0; t < test_nr; t++) {
            // INFO(Rafael): It must keep failing until server explicitly re-init it.
            CUTE_ASSERT(kryptos_hotp(&poison) == kKryptosInvalidToken);
        }
        kryptos_freeseg(lux->out, lux->out_size);

        // INFO(Rafael): Client ahead of server within resync window size.
        poison_c = 0;
        poison_throttling_param = 15;
        poison_resync_param = 10;
        lux_c = 5;
        CUTE_ASSERT(kryptos_hotp_init(poison,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &poison_c, &poison_throttling_param, &poison_resync_param, &d,
                                      kryptos_tiger_hash, kryptos_tiger_hash_input_size,
                                      kryptos_tiger_hash_size) == kKryptosSuccess);

        CUTE_ASSERT(kryptos_hotp_init(lux,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &lux_c, NULL, NULL, &d,
                                      kryptos_tiger_hash, kryptos_tiger_hash_input_size,
                                      kryptos_tiger_hash_size) == kKryptosSuccess);

        for (t = 0; t < test_nr; t++) {
            CUTE_ASSERT(kryptos_hotp(&lux) == kKryptosSuccess);
            poison->in = lux->out;
            poison->in_size = lux->out_size;
            // INFO(Rafael): During the first validation attempt, server will synchronize with client.
            CUTE_ASSERT(kryptos_hotp(&poison) == kKryptosSuccess);
            CUTE_ASSERT(poison_c == lux_c);
            kryptos_freeseg(lux->out, lux->out_size);
        }

        // INFO(Rafael): Client ahead of server but exceeding throttling limit.
        poison_c = 0;
        poison_throttling_param = 5;
        poison_resync_param = 6;
        lux_c = 6;
        CUTE_ASSERT(kryptos_hotp_init(poison,
                                      kKryptosValidateToken,
                                      shared_secret, shared_secret_size,
                                      &poison_c, &poison_throttling_param, &poison_resync_param, &d,
                                      kryptos_tiger_hash, kryptos_tiger_hash_input_size,
                                      kryptos_tiger_hash_size) == kKryptosSuccess);

        CUTE_ASSERT(kryptos_hotp_init(lux,
                                      kKryptosGenerateToken,
                                      shared_secret, shared_secret_size,
                                      &lux_c, NULL, NULL, &d,
                                      kryptos_tiger_hash, kryptos_tiger_hash_input_size,
                                      kryptos_tiger_hash_size) == kKryptosSuccess);

        CUTE_ASSERT(kryptos_hotp(&lux) == kKryptosSuccess);

        poison->in = lux->out;
        poison->in_size = lux->out_size;

        CUTE_ASSERT(kryptos_hotp(&poison) == kKryptosInvalidToken);

        for (t = 0; t < test_nr; t++) {
            // INFO(Rafael): It must keep failing until user explicitly re-init it.
            CUTE_ASSERT(kryptos_hotp(&poison) == kKryptosInvalidToken);
        }
        kryptos_freeseg(lux->out, lux->out_size);

        fprintf(stdout, "       \r   %.0f%% complete (token with %zu digit(s)).", ((float)d / (float)d_nr) * 100, d);
    }
    fprintf(stdout, "       \r                                                       \r");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hotp_init_bad_params_tests)
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

    CUTE_ASSERT(kryptos_hotp_init(NULL,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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


    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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


    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

    CUTE_ASSERT(kryptos_hotp_init(ktask,
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

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_otp_hash_macro_tests)
    kryptos_hash_func hash_func_addr = NULL;
    kryptos_hash_size_func hash_func_input_addr = NULL, hash_func_size_addr = NULL;
    otp_hash_validator(kryptos_otp_hash(sha512), &hash_func_addr, &hash_func_input_addr, &hash_func_size_addr);
    CUTE_ASSERT(hash_func_addr == kryptos_sha512_hash);
    CUTE_ASSERT(hash_func_input_addr == kryptos_sha512_hash_input_size);
    CUTE_ASSERT(hash_func_size_addr == kryptos_sha512_hash_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_otp_macro_tests)
#if defined(KRYPTOS_C99)
    kryptos_task_ctx c, s, *client = &c, *server = &s;
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"HowFarCanTooFarGo?";
    size_t shared_secret_size = 18;
    kryptos_u64_t moving_factor_client = 9, moving_factor_server = 9;
    size_t throttling = 30;
    size_t resync = 7;
    size_t number_of_digits = 6;
    kryptos_u64_t t0 = 10800, x = 30;

    // INFO(Rafael): For each available OTP algorithm put a successful generate/validation test by using related
    //               general OTP macro functions (that fits with the algorithm, of course).

    // HOTP

    CUTE_ASSERT(kryptos_otp_init(hotp,
                                 server,
                                 kKryptosValidateToken,
                                 shared_secret,
                                 shared_secret_size,
                                 &moving_factor_server,
                                 &throttling,
                                 &resync,
                                 &number_of_digits,
                                 kryptos_otp_hash(sha3_512)) == kKryptosSuccess);

    CUTE_ASSERT(kryptos_otp_init(hotp,
                                 client,
                                 kKryptosGenerateToken,
                                 shared_secret,
                                 shared_secret_size,
                                 &moving_factor_client,
                                 NULL,
                                 NULL,
                                 &number_of_digits,
                                 kryptos_otp_hash(sha3_512)) == kKryptosSuccess);

    CUTE_ASSERT(kryptos_otp(hotp, client) == kKryptosSuccess);

    kryptos_otp_set_token(server, client->out, client->out_size);

    CUTE_ASSERT(kryptos_otp(hotp, server) == kKryptosSuccess);

    kryptos_otp_free_token(client);

    // TOTP

    CUTE_ASSERT(kryptos_otp_init(totp,
                                 server,
                                 kKryptosValidateToken,
                                 shared_secret,
                                 shared_secret_size,
                                 &t0,
                                 &x,
                                 &number_of_digits,
                                 kryptos_otp_hash(sha384)) == kKryptosSuccess);

    CUTE_ASSERT(kryptos_otp_init(totp,
                                 client,
                                 kKryptosGenerateToken,
                                 shared_secret,
                                 shared_secret_size,
                                 &t0,
                                 &x,
                                 &number_of_digits,
                                 kryptos_otp_hash(sha384)) == kKryptosSuccess);

    CUTE_ASSERT(kryptos_otp(totp, client) == kKryptosSuccess);

    kryptos_otp_set_token(server, client->out, client->out_size);

    CUTE_ASSERT(kryptos_otp(totp, server) == kKryptosSuccess);

    kryptos_otp_free_token(client);

#else
    fprintf(stdout, "   Test skipped. Compiled without C99 support.\n");
#endif
CUTE_TEST_CASE_END

static size_t bad_hash_size(void) {
    return 14;
}

static void otp_hash_validator(kryptos_hash_func hash,
                               kryptos_hash_size_func hash_input_size,
                               kryptos_hash_size_func hash_size,
                               kryptos_hash_func *hash_addr,
                               kryptos_hash_size_func *hash_input_addr,
                               kryptos_hash_size_func *hash_size_addr) {
    *hash_addr = hash;
    *hash_input_addr = hash_input_size;
    *hash_size_addr = hash_size;
}

static void set_totp_current_systime(const kryptos_u64_t value) {
    g_totp_curr_systime = value;
}

static int enable_time_hook(void) {
    int err = 1;
#if defined(_WIN32)
    HMODULE handle = NULL;
#elif defined(__unix__)
    void *handle = NULL;
#endif
    if (g_tru_time == NULL) {
#if defined(__unix__)
        handle = (void *)RTLD_NEXT;
        g_tru_time = (void *)dlsym(handle, "time");
#elif defined(_WIN32)
        handle = LoadLibrary("ucrtbase.dll");
        if (handle != NULL) {
            g_tru_time = (void *)GetProcAddress(handle, "_time64");
        }
#else
# error Some code wanted.
#endif
    }
    if (g_tru_time != NULL) {
        g_do_time_hook = 1;
        err = 0;
    }
    return err;
}

static void disable_time_hook(void) {
    g_do_time_hook = 0;
}
