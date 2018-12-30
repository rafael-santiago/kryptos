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

#endif
