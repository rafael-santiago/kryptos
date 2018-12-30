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

KUTE_TEST_CASE(kryptos_bcrypt_tests)
    struct bcrypt_test {
        const kryptos_u8_t *password;
        const size_t password_size;
        const int cost;
        const kryptos_u8_t *salt;
        const size_t salt_size;
        const kryptos_u8_t *hash;
        const size_t hash_size;
    };
#define add_test_step(p, p_sz, c, s, s_sz, h, h_sz) { p, p_sz, c, s, s_sz, h, h_sz }
    struct bcrypt_test test_vector[] = {
        add_test_step("", 0,
                       4, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$04$zVHmKQtGGQob.b/Nc7l9NO8UlrYcW05FiuCj/SxsFO/ZtiN9.mNzy", 60),
        add_test_step("", 0,
                       5, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$05$zVHmKQtGGQob.b/Nc7l9NOWES.1hkVBgy5IWImh9DOjKNU8atY4Iy", 60),
        add_test_step("", 0,
                       6, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$06$zVHmKQtGGQob.b/Nc7l9NOjOl7l4oz3WSh5fJ6414Uw8IXRAUoiaO", 60),
        add_test_step("", 0,
                       7, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$07$zVHmKQtGGQob.b/Nc7l9NOBsj1dQpBA1HYNGpIETIByoNX9jc.hOi", 60),
        add_test_step("", 0,
                       8, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$08$zVHmKQtGGQob.b/Nc7l9NOiLTUh/9MDpX86/DLyEzyiFjqjBFePgO", 60),
        add_test_step("messycrypt", 10,
                       4, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC", 60)
    };
#undef add_test_step
    size_t t, test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t *hash;
    size_t hash_size;

    for (t = 0; t < test_vector_nr; t++) {
        hash = kryptos_bcrypt(test_vector[t].cost,
                              test_vector[t].salt, test_vector[t].salt_size,
                              test_vector[t].password, test_vector[t].password_size, &hash_size);
        KUTE_ASSERT(hash != NULL);
        KUTE_ASSERT(hash_size == test_vector[t].hash_size);
        KUTE_ASSERT(memcmp(hash, test_vector[t].hash, hash_size) == 0);
        kryptos_freeseg(hash, hash_size);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_bcrypt_verify_tests)
    kryptos_u8_t *password[] = {
        "messycrypt", "No Good, Mr. Holden", "Bad idea.", "Nothing Ventured"
    };
    size_t password_nr = sizeof(password) / sizeof(password[0]), p;
    kryptos_u8_t *hash;
    size_t hash_size;
    kryptos_u8_t *salt;

    // INFO(Rafael): Malformed or unsupported hashes.

    hash = "$3a$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "2x$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2a04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$0a$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$a4$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$32$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$00$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$04$zVHmKQtGGQo";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    for (p = 0; p < password_nr; p++) {
        salt = kryptos_get_random_block(16);
        KUTE_ASSERT(salt != NULL);
        hash = kryptos_bcrypt(4 + p, salt, 16, password[p], strlen(password[p]), &hash_size);
        KUTE_ASSERT(hash != NULL);
        KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, hash_size) == 0);
        KUTE_ASSERT(kryptos_bcrypt_verify(password[p], strlen(password[p]), hash, hash_size) == 1);
        kryptos_freeseg(hash, hash_size);
        kryptos_freeseg(salt, 16);
    }
KUTE_TEST_CASE_END

