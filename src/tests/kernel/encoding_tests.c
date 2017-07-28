/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <encoding_tests.h>
#include <kassert.h>
#include <kryptos_base64.h>
#include <kryptos_uuencode.h>
#include <kryptos_huffman.h>
#include <kryptos_pem.h>
#include <kryptos.h>

int kryptos_base64_tests(void) {
    kryptos_task_ctx t, *ktask = &t;

    struct base64_test {
        kryptos_u8_t *in;
        size_t in_size;
        kryptos_u8_t *out;
        size_t out_size;
    };

    struct base64_test test_vector[] = {
        {      "f", 1,     "Zg==", 4 },
        {     "fo", 2,     "Zm8=", 4 },
        {    "foo", 3,     "Zm9v", 4 },
        {   "foob", 4, "Zm9vYg==", 8 },
        {  "fooba", 5, "Zm9vYmE=", 8 },
        { "foobar", 6, "Zm9vYmFy", 8 }
    }; // INFO(Rafael): Test data from RFC-4648.

    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);

    t.encoder = kKryptosEncodingBASE64;

    for (tv = 0; tv < tv_nr; tv++) {
        t.in = test_vector[tv].in;
        t.in_size = test_vector[tv].in_size;
        kryptos_task_set_encode_action(ktask);
        kryptos_base64_processor(&ktask);
        KUTE_ASSERT(t.out != NULL);
        KUTE_ASSERT(t.out_size == test_vector[tv].out_size);
        KUTE_ASSERT(memcmp(t.out, test_vector[tv].out, t.out_size) == 0);

        t.in = t.out;
        t.in_size = t.out_size;
        kryptos_task_set_decode_action(ktask);
        kryptos_base64_processor(&ktask);
        KUTE_ASSERT(t.out != NULL);
        KUTE_ASSERT(t.out_size == test_vector[tv].in_size);
        KUTE_ASSERT(memcmp(t.out, test_vector[tv].in, t.out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    }
    return 0;
}

int kryptos_uuencode_tests(void) {
    kryptos_task_ctx t, *ktask = &t;

    struct uuencode_test {
        kryptos_u8_t *in;
        kryptos_u8_t in_size;
        kryptos_u8_t *out;
        kryptos_u8_t out_size;
    };

    struct uuencode_test test_vector[] = {
        { "ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC", 60,
          "M04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#\n"
          "/04)#04)#04)#04)#04)#\n"
          "`\n", 86 }
    };

    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);

    t.encoder = kKryptosEncodingUUENCODE;

    for (tv = 0; tv < tv_nr; tv++) {
        t.in = test_vector[tv].in;
        t.in_size = test_vector[tv].in_size;
        kryptos_task_set_encode_action(ktask);
        kryptos_uuencode_processor(&ktask);
        KUTE_ASSERT(t.out != NULL);
        KUTE_ASSERT(t.out_size == test_vector[tv].out_size);
        KUTE_ASSERT(memcmp(t.out, test_vector[tv].out, t.out_size) == 0);

        t.in = t.out;
        t.in_size = t.out_size;
        kryptos_task_set_decode_action(ktask);
        kryptos_uuencode_processor(&ktask);
        KUTE_ASSERT(t.out != NULL);
        KUTE_ASSERT(t.out_size == test_vector[tv].in_size);
        KUTE_ASSERT(memcmp(t.out, test_vector[tv].in, t.out_size) == 0);

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    }
    return 0;
}

int kryptos_huffman_tests(void) {
kryptos_u8_t *test_vector[] = {
        "AAAAAAAAAABBBBBCCDEEEEEFFFGGGGZZZZYYXXXXXXXX",

        "ACAAGATGCCATTGTCCCCCGGCCTCCTGCTGCTGCTGCTCTCCGGGGCCACGGCCACCGCTGCCCTGCC"
        "CCTGGAGGGTGGCCCCACCGGCCGAGACAGCGAGCATATGCAGGAAGCGGCAGGAATAAGGAAAAGCAGC"
        "CTCCTGACTTTCCTCGCTTGGTGGTTTGAGTGGACCTCCCAGGCCAGTGCCGGGCCCCTCATAGGAGAGG"
        "AAGCTCGGGAGGTGGCCAGGCGGCAGGAAGGCGCACCCCCCCAGCAATCCGCGCGCCGGGACAGAATGCC"
        "CTGCAGGAACTTCTTCTGGAAGACCTTCTCCTCCTGCAAATAAAACCTCACCCATGAATGCTCACGCAAG"
        "TTTAATTACAGACCTGAA"
    };
    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    size_t in_size, deflated_buffer_size, inflated_buffer_size;
    kryptos_u8_t *deflated_buffer = NULL, *inflated_buffer = NULL;

    for (tv = 0; tv < tv_nr; tv++) {
        in_size = strlen(test_vector[tv]);
        deflated_buffer = kryptos_huffman_deflate(test_vector[tv], in_size, &deflated_buffer_size);
        KUTE_ASSERT(deflated_buffer != NULL);
        inflated_buffer = kryptos_huffman_inflate(deflated_buffer, deflated_buffer_size, &inflated_buffer_size);
        KUTE_ASSERT(inflated_buffer != NULL);
        KUTE_ASSERT(inflated_buffer_size == in_size);
        KUTE_ASSERT(memcmp(inflated_buffer, test_vector[tv], inflated_buffer_size) == 0);
        kryptos_freeseg(deflated_buffer);
        kryptos_freeseg(inflated_buffer);
    }
    return 0;
}

int kryptos_pem_get_data_tests(void) {
    kryptos_u8_t *buf = "-----BEGIN FOOBAR (1)-----\n"
                        "Rm9vYmFyMQ==\n"
                        "-----END FOOBAR (1)-----\n"
                        "-----BEGIN FOOBAR (0)-----\n"
                        "Rm9vYmFyMA==\n"
                        "-----END FOOBAR (0)-----\n";
    size_t data_size = 0;
    kryptos_u8_t *data = NULL;

    data = kryptos_pem_get_data("THE-DROIDS-WE-ARE-LOOKING-FOR", buf, strlen(buf), &data_size);

    KUTE_ASSERT(data == NULL);

    data = kryptos_pem_get_data("FOOBAR (0)", buf, strlen(buf), &data_size);

    KUTE_ASSERT(data != NULL);
    KUTE_ASSERT(data_size == 7);
    KUTE_ASSERT(strcmp(data, "Foobar0") == 0);

    kryptos_freeseg(data);

    data_size = 0;
    data = kryptos_pem_get_data("FOOBAR (1)", buf, strlen(buf), &data_size);

    KUTE_ASSERT(data != NULL);
    KUTE_ASSERT(data_size == 7);
    KUTE_ASSERT(strcmp(data, "Foobar1") == 0);

    kryptos_freeseg(data);

    return 0;
}

int kryptos_pem_put_data_tests(void) {
    kryptos_u8_t *foobar1 = "Foobar1", *foobar0 = "Foobar0";
    kryptos_u8_t *pem_buf = NULL;
    size_t pem_buf_size = 0;
    kryptos_u8_t *expected_buffer = "-----BEGIN FOOBAR (1)-----\n"
                                    "Rm9vYmFyMQ==\n"
                                    "-----END FOOBAR (1)-----\n"
                                    "-----BEGIN FOOBAR (0)-----\n"
                                    "Rm9vYmFyMA==\n"
                                    "-----END FOOBAR (0)-----\n";

    KUTE_ASSERT(kryptos_pem_put_data(&pem_buf, &pem_buf_size, "FOOBAR (1)", foobar1, strlen(foobar1)) == kKryptosSuccess);
    KUTE_ASSERT(pem_buf != NULL);
    KUTE_ASSERT(kryptos_pem_put_data(&pem_buf, &pem_buf_size, "FOOBAR (1)", foobar0, strlen(foobar0)) == kKryptosInvalidParams);
    KUTE_ASSERT(pem_buf != NULL);
    KUTE_ASSERT(kryptos_pem_put_data(&pem_buf, &pem_buf_size, "FOOBAR (0)", foobar0, strlen(foobar0)) == kKryptosSuccess);
    KUTE_ASSERT(pem_buf != NULL);
    KUTE_ASSERT(pem_buf_size == strlen(expected_buffer));
    KUTE_ASSERT(strcmp(pem_buf, expected_buffer) == 0);
    kryptos_freeseg(pem_buf);

    return 0;
}

int kryptos_pem_get_mp_data_tests(void) {
    kryptos_mp_value_t *mp = NULL;
    kryptos_mp_value_t *emp = NULL;
    kryptos_u8_t *pem_buf = NULL;
    size_t pem_buf_size = 0;

    emp = kryptos_hex_value_as_mp("00112233", 8);

    KUTE_ASSERT(emp != NULL);

    KUTE_ASSERT(kryptos_pem_put_data(&pem_buf, &pem_buf_size, "MULTIPRECISION VALUE",
                                     (kryptos_u8_t *)emp->data,
                                      emp->data_size * sizeof(kryptos_mp_digit_t)) == kKryptosSuccess);

    KUTE_ASSERT(kryptos_pem_get_mp_data("MULTIPRECISION VALUE", pem_buf, pem_buf_size, &mp) == kKryptosSuccess);

    KUTE_ASSERT(kryptos_mp_eq(mp, emp) == 1);

    kryptos_freeseg(pem_buf);
    kryptos_del_mp_value(emp);
    kryptos_del_mp_value(mp);
    return 0;
}
