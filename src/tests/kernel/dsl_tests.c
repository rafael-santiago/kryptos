/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <dsl_tests.h>
#include <kryptos.h>
#include <kstring.h>

KUTE_TEST_CASE(kryptos_dsl_tests)
    // WARN(Rafael): The correctness of each available cipher must not be tested here. It
    //               should be done within a dedicated test case. Here only the mechanics about
    //               using these ciphers indirectly is tested (when C99 support is present).
    //               For testing it is used only one fixed plaintext and short keys.
    kryptos_task_ctx task;
    kryptos_u8_t *data = "IDIOT, n. A member of a large and powerful tribe whose influence in "
                         "human affairs has always been dominant and controlling. The Idiot's "
                         "activity is not confined to any special field of throught or action, but "
                         "'pervades and regulates the whole'. He has the last word in everything; his "
                         "decision is unappealable. He sets the fashions of opinion and taste, dictates "
                         "the limitations of speech and circumscribes conduct with a dead-line."; 
                         //... Everyone can point at least one.
    size_t data_size = kstrlen(data);
    kryptos_seal_version_t seal_version;
    size_t seal_n, seal_l;
    int feal_rounds;
    int rc2_t1;
    int saferk64_rounds;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;
    int xtea_rounds;
    int rc5_rounds;
    int rc6_rounds;

    kryptos_task_set_ecb_mode(&task);
    KUTE_ASSERT(task.mode == kKryptosECB);

    kryptos_task_set_cbc_mode(&task);
    KUTE_ASSERT(task.mode == kKryptosCBC);

    kryptos_task_set_encrypt_action(&task);
    KUTE_ASSERT(task.action == kKryptosEncrypt);

    kryptos_task_set_decrypt_action(&task);
    KUTE_ASSERT(task.action == kKryptosDecrypt);

    task.result = kKryptosSuccess;
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    task.result = kKryptosKeyError;
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosProcessError;
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosInvalidParams;
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosInvalidCipher;
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosTaskResultNr;
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    kryptos_task_set_in(&task, data, data_size);
    KUTE_ASSERT(task.in == data);
    KUTE_ASSERT(task.in_size == data_size);

    kryptos_task_init_as_null(&task);

    task.in = NULL;
    task.in_size = 0;
    task.out = data;
    task.out_size = data_size;
    KUTE_ASSERT(kryptos_task_get_out(&task) == data);
    KUTE_ASSERT(kryptos_task_get_out_size(&task) == data_size);

#ifdef KRYPTOS_C99
    // INFO(Rafael): The cipher indirect calling tests. Let's test the variadic macro kryptos_run_cipher() variations.

    // INFO(Rafael): Stream ciphers.
    kryptos_task_init_as_null(&task);

    kryptos_task_set_in(&task, data, data_size);

    // ARC4
    kryptos_run_cipher(arc4, &task, "arc4", 4);
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    kryptos_task_set_in(&task, kryptos_task_get_out(&task), kryptos_task_get_out_size(&task));

    kryptos_run_cipher(arc4, &task, "arc4", 4);
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(task.out != NULL);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SEAL 2.0
    kryptos_task_set_in(&task, data, data_size);

    seal_version = kKryptosSEAL20;
    seal_l = 1024;
    seal_n = 0;
    kryptos_run_cipher(seal, &task, "seal", 4, &seal_version, &seal_l, &seal_n);
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    kryptos_task_set_in(&task, kryptos_task_get_out(&task), kryptos_task_get_out_size(&task));

    kryptos_run_cipher(seal, &task, "seal", 4, &seal_version, &seal_l, &seal_n);
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(task.out != NULL);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SEAL 3.0
    kryptos_task_set_in(&task, data, data_size);

    seal_version = kKryptosSEAL30;
    seal_l = 2048;
    seal_n = 0;
    kryptos_run_cipher(seal, &task, "seal", 4, &seal_version, &seal_l, &seal_n);
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    kryptos_task_set_in(&task, kryptos_task_get_out(&task), kryptos_task_get_out_size(&task));

    kryptos_run_cipher(seal, &task, "seal", 4, &seal_version, &seal_l, &seal_n);
    KUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(task.out != NULL);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // INFO(Rafael): Block ciphers.
    kryptos_task_init_as_null(&task);

    // DES ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(des, &task, "des", 3, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(des, &task, "des", 3, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // DES CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(des, &task, "des", 3, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(des, &task, "des", 3, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // IDEA ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(idea, &task, "idea", 4, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(idea, &task, "idea", 4, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // IDEA CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(idea, &task, "idea", 4, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(idea, &task, "idea", 4, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // BLOWFISH ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(blowfish, &task, "blowfish", 8, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(blowfish, &task, "blowfish", 8, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // BLOWFISH CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(blowfish, &task, "blowfish", 8, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(blowfish, &task, "blowfish", 8, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // FEAL ECB
    feal_rounds = 16;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(feal, &task, "feal", 4, kKryptosECB, &feal_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(feal, &task, "feal", 4, kKryptosECB, &feal_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // FEAL CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(feal, &task, "feal", 4, kKryptosCBC, &feal_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(feal, &task, "feal", 4, kKryptosCBC, &feal_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-128 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia128, &task, "camellia", 8, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia128, &task, "camellia", 8, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-128 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia128, &task, "camellia", 8, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia128, &task, "camellia", 8, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-192 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia192, &task, "camellia", 8, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia192, &task, "camellia", 8, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-192 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia192, &task, "camellia", 8, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia192, &task, "camellia", 8, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-256 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia256, &task, "camellia", 8, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia256, &task, "camellia", 8, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-256 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia256, &task, "camellia", 8, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia256, &task, "camellia", 8, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAST5 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(cast5, &task, "cast5", 5, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(cast5, &task, "cast5", 5, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAST5 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(cast5, &task, "cast5", 5, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(cast5, &task, "cast5", 5, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC2 ECB

    rc2_t1 = 128;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosECB, &rc2_t1);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosECB, &rc2_t1);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC2 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosCBC, &rc2_t1);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosCBC, &rc2_t1);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC5 ECB

    rc5_rounds = 32;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc5, &task, "rc5", 3, kKryptosECB, &rc5_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc5, &task, "rc5", 3, kKryptosECB, &rc5_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC5 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc5, &task, "rc5", 3, kKryptosCBC, &rc5_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc5, &task, "rc5", 3, kKryptosCBC, &rc5_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-128 ECB

    rc6_rounds = 40;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc6_128, &task, "rc6", 3, kKryptosECB, &rc6_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc6_128, &task, "rc6", 3, kKryptosECB, &rc6_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC6-128 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc6_128, &task, "rc6", 3, kKryptosCBC, &rc6_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc6_128, &task, "rc6", 3, kKryptosCBC, &rc6_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-192 ECB

    rc6_rounds = 40;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc6_192, &task, "rc6", 3, kKryptosECB, &rc6_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc6_192, &task, "rc6", 3, kKryptosECB, &rc6_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC6-192 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc6_192, &task, "rc6", 3, kKryptosCBC, &rc6_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc6_192, &task, "rc6", 3, kKryptosCBC, &rc6_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-256 ECB

    rc6_rounds = 40;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc6_256, &task, "rc6", 3, kKryptosECB, &rc6_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc6_256, &task, "rc6", 3, kKryptosECB, &rc6_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC6-256 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc6_256, &task, "rc6", 3, kKryptosCBC, &rc6_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc6_256, &task, "rc6", 3, kKryptosCBC, &rc6_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SAFER K-64 ECB

    saferk64_rounds = 32;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosECB, &saferk64_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosECB, &saferk64_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SAFER K-64 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosCBC, &saferk64_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosCBC, &saferk64_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-128 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(aes128, &task, "aes128", 6, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(aes128, &task, "aes128", 6, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // AES-128 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(aes128, &task, "aes128", 6, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(aes128, &task, "aes128", 6, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-192 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(aes192, &task, "aes192", 6, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(aes192, &task, "aes192", 6, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // AES-192 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(aes192, &task, "aes192", 6, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(aes192, &task, "aes192", 6, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-256 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(aes256, &task, "aes256", 6, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(aes256, &task, "aes256", 6, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // AES-256 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(aes256, &task, "aes256", 6, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(aes256, &task, "aes256", 6, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SERPENT ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(serpent, &task, "serpent", 7, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(serpent, &task, "serpent", 7, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SERPENT CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(serpent, &task, "serpent", 7, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(serpent, &task, "serpent", 7, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    triple_des_key2 = "noel";
    triple_des_key2_size = 4;
    triple_des_key3 = "mitch";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, &task, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(triple_des, &task, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TRIPLE-DES CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, &task, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(triple_des, &task, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES EDE ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    triple_des_key2 = "noel";
    triple_des_key2_size = 4;
    triple_des_key3 = "mitch";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, &task, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(triple_des_ede, &task, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TRIPLE-DES EDE CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, &task, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(triple_des_ede, &task, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TEA ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(tea, &task, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(tea, &task, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TEA CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(tea, &task, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(tea, &task, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // XTEA ECB

    xtea_rounds = 48;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(xtea, &task, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosECB, &xtea_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(xtea, &task, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosECB, &xtea_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // XTEA CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(xtea, &task, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCBC, &xtea_rounds);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(xtea, &task, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCBC, &xtea_rounds);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MISTY1 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(misty1, &task, "misty1", 6, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(misty1, &task, "misty1", 6, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // MISTY1 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(misty1, &task, "misty1", 6, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(misty1, &task, "misty1", 6, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-128 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(mars128, &task, "mars128", 7, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(mars128, &task, "mars128", 7, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // MARS-128 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(mars128, &task, "mars128", 7, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(mars128, &task, "mars128", 7, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-192 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(mars192, &task, "mars192", 7, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(mars192, &task, "mars192", 7, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // MARS-192 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(mars192, &task, "mars192", 7, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(mars192, &task, "mars192", 7, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-256 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(mars256, &task, "mars256", 7, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(mars256, &task, "mars256", 7, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // MARS-256 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(mars256, &task, "mars256", 7, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(mars256, &task, "mars256", 7, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // PRESENT-80 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(present80, &task, "present80", 9, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(present80, &task, "present80", 9, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // PRESENT-80 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(present80, &task, "present80", 9, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(present80, &task, "present80", 9, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
#endif
KUTE_TEST_CASE_END
