/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "poly1305_tests.h"
#include <kryptos.h>

CUTE_TEST_CASE(kryptos_poly1305_tests)
    struct test_ctx {
        kryptos_u8_t *key;
        size_t key_size;
        kryptos_u8_t *msg;
        size_t msg_size;
        kryptos_u8_t *tag;
        size_t tag_size;
    } test_vector[] = {
        "\x85\xD6\xBE\x78\x57\x55\x6D\x33\x7F\x44\x52\xFE\x42\xD5\x06\xA8"
        "\x01\x03\x80\x8A\xFB\x0D\xB2\xFD\x4A\xBF\xF6\xAF\x41\x49\xF5\x1B",
        32,
        "\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x46\x6F"
        "\x72\x75\x6D\x20\x52\x65\x73\x65\x61\x72\x63\x68\x20\x47\x72\x6F"
        "\x75\x70",
        34,
        "\xA8\x06\x1D\xC1\x30\x51\x36\xC6\xC2\x2B\x8B\xAF\x0C\x01\x27\xA9",
        16
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_task_ctx t, *ktask = &t;
    //kryptos_u8_t *xp, *xp_end;

    while (test != test_end) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_encrypt_action(ktask);

        ktask->key = test->key;
        ktask->key_size = test->key_size;

        ktask->out = (kryptos_u8_t *)kryptos_newseg(test->msg_size);
        CUTE_ASSERT(ktask->out != NULL);
        memcpy(ktask->out, test->msg, test->msg_size);
        ktask->out_size = test->msg_size;

        kryptos_poly1305(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosSuccess);

        CUTE_ASSERT(ktask->out_size == test->tag_size + test->msg_size);
        CUTE_ASSERT(ktask->out != NULL);

        /*xp = ktask->out;
        xp_end = xp + test->tag_size;
        printf("TAG: ");
        while (xp != xp_end) {
            printf("%.2X", *xp);
            xp++;
        }
        printf("\n");*/
        CUTE_ASSERT(memcmp(ktask->out, test->tag, test->tag_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

        // TODO(Rafael): Implement the final part of this test by verifying if after switch action to kKryptosDecrypt
        //               the verifying stuff of poly is working accordingly.

        test++;
    }
CUTE_TEST_CASE_END

// TODO(Rafael): Implement a test that uses poly1305 with all available ciphes (following the idea of HMAC tests).
//               A function macro that automates the encryption,tag/verify,decryption must be implemented first.