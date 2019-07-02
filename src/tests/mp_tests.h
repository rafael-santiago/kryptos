/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_MP_TESTS_H
#define KRYPTOS_TESTS_MP_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_mp_new_value_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_hex_value_as_mp_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_value_as_hex_tests);

CUTE_DECLARE_TEST_CASE(kryptos_assign_mp_value_tests);

CUTE_DECLARE_TEST_CASE(kryptos_assign_hex_value_to_mp_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_eq_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_ne_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_get_gt_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_gt_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_ge_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_lt_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_le_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_is_neg_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_add_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_sub_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_mul_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_karatsuba_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_not_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_inv_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_signed_add_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_signed_sub_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_signed_mul_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_lsh_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_rsh_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_div_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_div_2p_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_pow_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_is_odd_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_is_even_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_me_mod_n_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_fermat_test_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_miller_rabin_test_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_is_prime_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_gen_prime_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_montgomery_reduction_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_gcd_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_modinv_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_mul_digit_tests);

CUTE_DECLARE_TEST_CASE(kryptos_raw_buffer_as_mp_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_as_task_out_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_mod_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_add_s_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_sub_s_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_mul_s_tests);

CUTE_DECLARE_TEST_CASE(kryptos_mp_get_bitmap_tests);

//CUTE_DECLARE_TEST_CASE(poke_bloody_poke);

#endif
