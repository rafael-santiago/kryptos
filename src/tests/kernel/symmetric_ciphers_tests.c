/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <symmetric_ciphers_tests.h>
#include <kryptos.h>

KUTE_TEST_CASE(kryptos_ctr_mode_sequencing_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u32_t ctr = 10;
    kryptos_u8_t *data = "ISLEEPTHROUGHTHEWAR";
    size_t data_size = 19;

    kryptos_task_init_as_null(ktask);

    kryptos_task_set_in(ktask, data, data_size);

    kryptos_task_set_encrypt_action(ktask);

    kryptos_task_set_ctr_mode(ktask, &ctr);
    kryptos_misty1_setup(ktask, "bulls", 5, kKryptosCTR);
    kryptos_misty1_cipher(&ktask);

    KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    KUTE_ASSERT(ktask->out != NULL);

    KUTE_ASSERT(ctr == 13);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);

    kryptos_task_set_decrypt_action(ktask);

    kryptos_misty1_setup(ktask, "bulls", 5, kKryptosCTR);
    kryptos_misty1_cipher(&ktask);

    KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    KUTE_ASSERT(ktask->out != NULL);
    KUTE_ASSERT(ktask->out_size == data_size);

    KUTE_ASSERT(memcmp(ktask->out, data, data_size) == 0);

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_des_weak_keys_detection_tests)
#define REGISTER_DES_WEAK_KEY(k) (k)
    static kryptos_u8_t *wkey[] = {
        // WARN(Rafael): DES' weak keys.
        REGISTER_DES_WEAK_KEY("\x01\x01\x01\x01\x01\x01\x01\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1"), REGISTER_DES_WEAK_KEY("\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE"),
        // WARN(Rafael): DES' semiweak keys.
        REGISTER_DES_WEAK_KEY("\x01\xFE\x01\xFE\x01\xFE\x01\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x01\xFE\x01\xFE\x01\xFE\x01"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1"), REGISTER_DES_WEAK_KEY("\xE0\xF1\xE0\xF1\xF1\x0E\xF1\x0E"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\x01\xE0\x01\xF1\x01\xF1"), REGISTER_DES_WEAK_KEY("\xE0\x01\xE0\x01\xF1\x01\xF1\x01"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E"),
        REGISTER_DES_WEAK_KEY("\x01\xF1\x01\xF1\x01\x0E\x01\x0E"), REGISTER_DES_WEAK_KEY("\x1F\x01\x1F\x01\x0E\x01\x0E\x01"),
        REGISTER_DES_WEAK_KEY("\x0E\xFE\x0E\xFE\xF1\xFE\xF1\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x0E\xFE\x0E\xFE\xF1\xFE\xF1"),
        // WARN(Rafael): DES' possibly weak keys.
        REGISTER_DES_WEAK_KEY("\x1F\x1F\x01\x01\x0E\x0E\x01\x01"), REGISTER_DES_WEAK_KEY("\x0E\x01\x0E\xF1\xF1\x01\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\x1F\x1F\x01\x01\x0E\x0E\x01"), REGISTER_DES_WEAK_KEY("\xFE\xF1\x01\xE0\xFE\x0E\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\x1F\x01\x01\x1F\x0E\x01\x01\x0E"), REGISTER_DES_WEAK_KEY("\xFE\x01\x1F\xE0\xFE\x01\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\x01\x1F\x1F\x01\x01\x0E\x0E"), REGISTER_DES_WEAK_KEY("\xE0\x1F\x1F\xE0\xF1\x0E\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\x01\x01\xF1\xF1\x01\x01"), REGISTER_DES_WEAK_KEY("\xFE\x01\x01\xFE\xFE\x01\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xFE\x01\x01\xFE\xFE\x01\x01"), REGISTER_DES_WEAK_KEY("\xE0\x1F\x01\xFE\xF1\x0E\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xE0\x1F\x01\xFE\xF1\x0E\x01"), REGISTER_DES_WEAK_KEY("\xE0\x01\x1F\xFE\xF1\x01\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xE0\xFE\x1F\x01\xF1\xFE\x0E\x01"), REGISTER_DES_WEAK_KEY("\xFE\x1F\x1F\xFE\xFE\x0E\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xE0\x01\x1F\xFE\xF1\x01\x0E"), REGISTER_DES_WEAK_KEY("\x1F\xFE\x01\xE0\x0E\xFE\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xFE\x01\x1F\xF1\xFE\x01\x0E"), REGISTER_DES_WEAK_KEY("\x01\xFE\x1F\xE0\x01\xFE\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\x1F\x1F\xF1\xF1\x0E\x0E"), REGISTER_DES_WEAK_KEY("\x1F\xE0\x01\xFE\x0E\xF1\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xFE\x1F\x1F\xFE\xFE\x0E\x0E"), REGISTER_DES_WEAK_KEY("\x01\xE0\x1F\xFE\x01\xF1\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\x1F\xE0\x01\xFE\x0E\xF1\x01"), REGISTER_DES_WEAK_KEY("\x01\x01\xE0\xE0\x01\x01\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\x1F\xFE\x01\xF1\x0E\xFE\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\xE0\xE0\x0E\x0E\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\xFE\x01\xE0\x1F\xFE\x01\xF1\x0E"), REGISTER_DES_WEAK_KEY("\x1F\x01\xFE\xE0\x0E\x01\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\x01\xFE\x1F\xF1\x01\xFE\x0E"), REGISTER_DES_WEAK_KEY("\x01\x1F\xFE\xE0\x01\x0E\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\xE0\x01\x01\xF1\xF1\x01"), REGISTER_DES_WEAK_KEY("\x1F\x01\xE0\xFE\x0E\x01\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\xE0\x01\x0E\xFE\xF0\x01"), REGISTER_DES_WEAK_KEY("\x01\x1F\xE0\xFE\x01\x0E\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\xFE\x01\x0E\xF1\xFE\x01"), REGISTER_DES_WEAK_KEY("\x01\x01\xFE\xFE\x01\x01\xFE\xFE"),
        REGISTER_DES_WEAK_KEY("\x01\xFE\xFE\x01\x01\xFE\xFE\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\xFE\xFE\x0E\x0E\xFE\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\xE0\x1F\x0E\xF1\xF1\x0E"), REGISTER_DES_WEAK_KEY("\xFE\xFE\xE0\xE0\xFE\xFE\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xFE\xE0\x1F\x01\xFE\xF1\x0E"), REGISTER_DES_WEAK_KEY("\xE0\xFE\xFE\xE0\xF1\xFE\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\xFE\x1F\x01\xF1\xFE\x0E"), REGISTER_DES_WEAK_KEY("\xFE\xE0\xE0\xFE\xFE\xF1\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\xFE\x1F\x0E\xFE\xFE\x0E"), REGISTER_DES_WEAK_KEY("\xE0\xE0\xFE\xFE\xF1\xF1\xFE\xFE")
    };
#undef REGISTER_DES_WEAK_KEY
    size_t wkey_nr = sizeof(wkey) / sizeof(wkey[0]), w, wkeys_size = 8;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *k1 = "101", *k2 = "255";
    size_t k1_size = 3, k2_size = 3;

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_des_setup(ktask, wkey[w], wkeys_size, kKryptosECB);
        kryptos_des_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
    }

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_triple_des_setup(ktask, wkey[w], wkeys_size, kKryptosECB, k1, &k1_size, k2, &k2_size);
        kryptos_triple_des_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_setup(ktask, k1, k1_size, kKryptosECB, wkey[w], &wkeys_size, k2, &k2_size);
        kryptos_triple_des_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_setup(ktask, k1, k1_size, kKryptosECB, k2, &k2_size, wkey[w], &wkeys_size);
        kryptos_triple_des_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
    }

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_triple_des_ede_setup(ktask, wkey[w], wkeys_size, kKryptosECB, k1, &k1_size, k2, &k2_size);
        kryptos_triple_des_ede_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_ede_setup(ktask, k1, k1_size, kKryptosECB, wkey[w], &wkeys_size, k2, &k2_size);
        kryptos_triple_des_ede_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_ede_setup(ktask, k1, k1_size, kKryptosECB, k2, &k2_size, wkey[w], &wkeys_size);
        kryptos_triple_des_ede_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
    }
KUTE_TEST_CASE_END
