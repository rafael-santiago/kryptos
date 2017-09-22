/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_ASYMMETRIC_CIPHERS_TESTS_H
#define KRYPTOS_TESTS_ASYMMETRIC_CIPHERS_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_verify_dl_params_tests);

CUTE_DECLARE_TEST_CASE(kryptos_generate_dl_params_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_mk_domain_params_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_verify_domain_params_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_get_modp_from_params_buf_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_get_modp_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_get_random_s_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_eval_t_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_standard_key_exchange_bare_bone_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_process_stdxchg_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_mk_key_pair_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dh_process_modxchg_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_mk_key_pair_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_cipher_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_cipher_c99_tests);

CUTE_DECLARE_TEST_CASE(kryptos_padding_mgf_tests);

CUTE_DECLARE_TEST_CASE(kryptos_oaep_padding_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_oaep_cipher_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_oaep_cipher_c99_tests);

CUTE_DECLARE_TEST_CASE(kryptos_elgamal_mk_key_pair_tests);

CUTE_DECLARE_TEST_CASE(kryptos_elgamal_verify_public_key_tests);

CUTE_DECLARE_TEST_CASE(kryptos_elgamal_cipher_tests);

CUTE_DECLARE_TEST_CASE(kryptos_elgamal_cipher_c99_tests);

CUTE_DECLARE_TEST_CASE(kryptos_elgamal_oaep_cipher_tests);

CUTE_DECLARE_TEST_CASE(kryptos_elgamal_oaep_cipher_c99_tests);

CUTE_DECLARE_TEST_CASE(kryptos_pss_encoding_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_digital_signature_basic_scheme_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_digital_signature_basic_scheme_c99_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_emsa_pss_digital_signature_scheme_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rsa_emsa_pss_digital_signature_scheme_c99_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dsa_mk_key_pair_tests);

CUTE_DECLARE_TEST_CASE(kryptos_dsa_digital_signature_scheme_tests);

#endif
