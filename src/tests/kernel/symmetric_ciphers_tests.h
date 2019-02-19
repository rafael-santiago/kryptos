/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SYMMETRIC_CIPHERS_TESTS_H
#define KRYPTOS_TESTS_SYMMETRIC_CIPHERS_TESTS_H 1

#include <tests/cutest/src/kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_ctr_mode_sequencing_tests);

KUTE_DECLARE_TEST_CASE(kryptos_des_weak_keys_detection_tests);

KUTE_DECLARE_TEST_CASE(kryptos_bcrypt_tests);

KUTE_DECLARE_TEST_CASE(kryptos_bcrypt_verify_tests);

KUTE_DECLARE_TEST_CASE(kryptos_des_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_idea_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_blowfish_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_feal_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_rc2_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_camellia128_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_camellia192_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_camellia256_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_cast5_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_saferk64_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_aes128_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_aes192_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_aes256_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_serpent_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_triple_des_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_triple_des_ede_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_tea_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_xtea_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_misty1_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_rc5_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_rc6_128_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_rc6_192_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_rc6_256_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mars128_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mars192_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mars256_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_present80_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_present128_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_shacal1_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_shacal2_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_noekeon_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_noekeon_d_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_gost_ds_gcm_tests);

KUTE_DECLARE_TEST_CASE(kryptos_gost_gcm_tests);

#endif
