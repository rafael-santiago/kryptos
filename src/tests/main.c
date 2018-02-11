/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <cutest.h>
#include "generic_tests.h"
#include "dsl_tests.h"
#include "symmetric_ciphers_tests.h"
#include "hash_tests.h"
#include "encoding_tests.h"
#include "mp_tests.h"
#include "asymmetric_ciphers_tests.h"

CUTE_TEST_CASE(kryptos_test_monkey)
    // CLUE(Rafael): Before adding a new test try to find out the best place that it fits.
    //               At first glance you should consider the utility that it implements into the library.

    // INFO(Rafael): Generic/shared stuff.

    CUTE_RUN_TEST(kryptos_padding_tests);
    CUTE_RUN_TEST(kryptos_get_random_block_tests);
    CUTE_RUN_TEST(kryptos_block_parser_tests);
    CUTE_RUN_TEST(kryptos_endianness_utils_tests);
    CUTE_RUN_TEST(kryptos_apply_iv_tests);
    CUTE_RUN_TEST(kryptos_iv_data_flush_tests);
    CUTE_RUN_TEST(kryptos_task_check_tests);
    CUTE_RUN_TEST(kryptos_task_check_sign_tests);
    CUTE_RUN_TEST(kryptos_task_check_verify_tests);
    CUTE_RUN_TEST(kryptos_hex_tests);
    CUTE_RUN_TEST(kryptos_hash_common_tests);

    //  -=-=-=-=- If you have just added a new cipher take a look in "kryptos_dsl_tests" case, there is some work to
    //                                               be done there too! -=-=-=-=-=-=-

    // INFO(Rafael): Internal DSL stuff.
    CUTE_RUN_TEST(kryptos_dsl_tests);

    // INFO(Rafael): Symmetric stuff.

    // INFO(Rafael): Cipher validation using official test vectors.
    CUTE_RUN_TEST(kryptos_arc4_tests);
    CUTE_RUN_TEST(kryptos_seal_tests);
    CUTE_RUN_TEST(kryptos_des_tests);
    CUTE_RUN_TEST(kryptos_idea_tests);
    CUTE_RUN_TEST(kryptos_blowfish_tests);
    CUTE_RUN_TEST(kryptos_feal_tests);
    CUTE_RUN_TEST(kryptos_rc2_tests);
    CUTE_RUN_TEST(kryptos_rc5_tests);
    CUTE_RUN_TEST(kryptos_rc6_128_tests);
    CUTE_RUN_TEST(kryptos_rc6_192_tests);
    CUTE_RUN_TEST(kryptos_rc6_256_tests);
    CUTE_RUN_TEST(kryptos_camellia128_tests);
    CUTE_RUN_TEST(kryptos_camellia192_tests);
    CUTE_RUN_TEST(kryptos_camellia256_tests);
    CUTE_RUN_TEST(kryptos_cast5_tests);
    CUTE_RUN_TEST(kryptos_saferk64_tests);
    CUTE_RUN_TEST(kryptos_aes128_tests);
    CUTE_RUN_TEST(kryptos_aes192_tests);
    CUTE_RUN_TEST(kryptos_aes256_tests);
    CUTE_RUN_TEST(kryptos_serpent_tests);
    CUTE_RUN_TEST(kryptos_triple_des_tests);
    CUTE_RUN_TEST(kryptos_triple_des_ede_tests);
    CUTE_RUN_TEST(kryptos_tea_tests);
    CUTE_RUN_TEST(kryptos_xtea_tests);
    CUTE_RUN_TEST(kryptos_misty1_tests);
    CUTE_RUN_TEST(kryptos_mars128_tests);
    CUTE_RUN_TEST(kryptos_mars192_tests);
    CUTE_RUN_TEST(kryptos_mars256_tests);
    CUTE_RUN_TEST(kryptos_present80_tests);
    CUTE_RUN_TEST(kryptos_present128_tests);

    // INFO(Rafael): Hash validation (also official data).
    CUTE_RUN_TEST(kryptos_sha1_tests);
    CUTE_RUN_TEST(kryptos_sha1_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_sha224_tests);
    CUTE_RUN_TEST(kryptos_sha224_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_sha256_tests);
    CUTE_RUN_TEST(kryptos_sha256_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_sha384_tests);
    CUTE_RUN_TEST(kryptos_sha384_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_sha512_tests);
    CUTE_RUN_TEST(kryptos_sha512_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_md4_tests);
    CUTE_RUN_TEST(kryptos_md4_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_md5_tests);
    CUTE_RUN_TEST(kryptos_md5_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_ripemd128_tests);
    CUTE_RUN_TEST(kryptos_ripemd128_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_ripemd160_tests);
    CUTE_RUN_TEST(kryptos_ripemd160_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_sha3_224_tests);
    CUTE_RUN_TEST(kryptos_sha3_224_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_sha3_256_tests);
    CUTE_RUN_TEST(kryptos_sha3_256_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_sha3_384_tests);
    CUTE_RUN_TEST(kryptos_sha3_384_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_sha3_512_tests);
    CUTE_RUN_TEST(kryptos_sha3_512_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_keccak224_tests);
    CUTE_RUN_TEST(kryptos_keccak224_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_keccak256_tests);
    CUTE_RUN_TEST(kryptos_keccak256_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_keccak384_tests);
    CUTE_RUN_TEST(kryptos_keccak384_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_keccak512_tests);
    CUTE_RUN_TEST(kryptos_keccak512_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_tiger_tests);
    CUTE_RUN_TEST(kryptos_tiger_hash_macro_tests);

    //  -=-=-=-=-=-=- New block ciphers/hash functions should be added to HMAC tests. -=-=-=-=-=-=-=-

    // INFO(Rafael): HMAC tests.
    CUTE_RUN_TEST(kryptos_hmac_tests);

    // INFO(Rafael): Encoding stuff.
    CUTE_RUN_TEST(kryptos_base64_tests);
    CUTE_RUN_TEST(kryptos_base64_dsl_tests);
    CUTE_RUN_TEST(kryptos_uuencode_tests);
    CUTE_RUN_TEST(kryptos_uuencode_dsl_tests);
    CUTE_RUN_TEST(kryptos_huffman_tests);
    CUTE_RUN_TEST(kryptos_pem_get_data_tests);
    CUTE_RUN_TEST(kryptos_pem_put_data_tests);

    // INFO(Rafael): Multiprecision stuff.
    CUTE_RUN_TEST(kryptos_mp_new_value_tests);
    CUTE_RUN_TEST(kryptos_mp_hex_value_as_mp_tests);
    CUTE_RUN_TEST(kryptos_mp_value_as_hex_tests);
    CUTE_RUN_TEST(kryptos_assign_mp_value_tests);
    CUTE_RUN_TEST(kryptos_assign_hex_value_to_mp_tests);
    CUTE_RUN_TEST(kryptos_mp_eq_tests);
    CUTE_RUN_TEST(kryptos_mp_ne_tests);
    CUTE_RUN_TEST(kryptos_mp_get_gt_tests);
    CUTE_RUN_TEST(kryptos_mp_gt_tests);
    CUTE_RUN_TEST(kryptos_mp_ge_tests);
    CUTE_RUN_TEST(kryptos_mp_lt_tests);
    CUTE_RUN_TEST(kryptos_mp_le_tests);
    CUTE_RUN_TEST(kryptos_mp_is_neg_tests);
    CUTE_RUN_TEST(kryptos_mp_bitcount_tests);
    CUTE_RUN_TEST(kryptos_mp_add_tests);
    CUTE_RUN_TEST(kryptos_mp_sub_tests);
    CUTE_RUN_TEST(kryptos_mp_mul_tests);
    CUTE_RUN_TEST(kryptos_mp_mul_digit_tests);
    CUTE_RUN_TEST(kryptos_mp_not_tests);
    CUTE_RUN_TEST(kryptos_mp_inv_signal_tests);
    CUTE_RUN_TEST(kryptos_mp_lsh_tests);
    CUTE_RUN_TEST(kryptos_mp_rsh_tests);
    CUTE_RUN_TEST(kryptos_mp_signed_rsh_tests);
    CUTE_RUN_TEST(kryptos_mp_div_tests);
    CUTE_RUN_TEST(kryptos_mp_div_2p_tests);
    CUTE_RUN_TEST(kryptos_mp_pow_tests);
    CUTE_RUN_TEST(kryptos_mp_is_odd_tests);
    CUTE_RUN_TEST(kryptos_mp_is_even_tests);
    CUTE_RUN_TEST(kryptos_mp_me_mod_n_tests);
    CUTE_RUN_TEST(kryptos_mp_fermat_test_tests);
    CUTE_RUN_TEST(kryptos_mp_miller_rabin_test_tests);
    CUTE_RUN_TEST(kryptos_mp_is_prime_tests);
    CUTE_RUN_TEST(kryptos_mp_gen_prime_tests);
    CUTE_RUN_TEST(kryptos_mp_montgomery_reduction_tests);
    CUTE_RUN_TEST(kryptos_mp_gcd_tests);
    CUTE_RUN_TEST(kryptos_mp_modinv_tests);
    CUTE_RUN_TEST(kryptos_raw_buffer_as_mp_tests);
    CUTE_RUN_TEST(kryptos_mp_as_task_out_tests);

    // INFO(Rafael): This encoding function depends on multiprecision stuff, this is because we need
    //               to test it later than other encoding stuff.

    CUTE_RUN_TEST(kryptos_pem_get_mp_data_tests);

    // INFO(Rafael): Asymmetric stuff

    CUTE_RUN_TEST(kryptos_verify_dl_params_tests);
    CUTE_RUN_TEST(kryptos_generate_dl_params_tests);

    CUTE_RUN_TEST(kryptos_dh_mk_domain_params_tests);
    CUTE_RUN_TEST(kryptos_dh_verify_domain_params_tests);
    CUTE_RUN_TEST(kryptos_dh_get_modp_from_params_buf_tests);
    CUTE_RUN_TEST(kryptos_dh_get_modp_tests);
    CUTE_RUN_TEST(kryptos_dh_get_random_s_tests);
    CUTE_RUN_TEST(kryptos_dh_eval_t_tests);

    if (CUTE_GET_OPTION("skip-dh-xchg-tests") == NULL) {
        CUTE_RUN_TEST(kryptos_dh_standard_key_exchange_bare_bone_tests);
        CUTE_RUN_TEST(kryptos_dh_process_stdxchg_tests);
        CUTE_RUN_TEST(kryptos_dh_mk_key_pair_tests);
        CUTE_RUN_TEST(kryptos_dh_process_modxchg_tests);
    } else {
        printf("WARN: The Diffie-Hellman-Merkle exchange tests were skipped.\n");
    }

    CUTE_RUN_TEST(kryptos_rsa_mk_key_pair_tests);
    CUTE_RUN_TEST(kryptos_rsa_cipher_tests);
    CUTE_RUN_TEST(kryptos_rsa_cipher_c99_tests);
    CUTE_RUN_TEST(kryptos_padding_mgf_tests);
    CUTE_RUN_TEST(kryptos_oaep_padding_tests);

    if (CUTE_GET_OPTION("skip-rsa-oaep-tests") == NULL) {
        CUTE_RUN_TEST(kryptos_rsa_oaep_cipher_tests);
        CUTE_RUN_TEST(kryptos_rsa_oaep_cipher_c99_tests);
    } else {
        printf("WARN: The RSA-OAEP tests were skipped.\n");
    }

    CUTE_RUN_TEST(kryptos_elgamal_mk_key_pair_tests);
    CUTE_RUN_TEST(kryptos_elgamal_verify_public_key_tests);
    CUTE_RUN_TEST(kryptos_elgamal_cipher_tests);
    CUTE_RUN_TEST(kryptos_elgamal_cipher_c99_tests);

    if (CUTE_GET_OPTION("skip-elgamal-oaep-tests") == NULL) {
        CUTE_RUN_TEST(kryptos_elgamal_oaep_cipher_tests);
        CUTE_RUN_TEST(kryptos_elgamal_oaep_cipher_c99_tests);
    } else {
        printf("WARN: The Elgamal-OAEP tests were skipped.\n");
    }

    // INFO(Rafael): Digital signature stuff.

    CUTE_RUN_TEST(kryptos_pss_encoding_tests);

    if (CUTE_GET_OPTION("skip-rsa-signature-tests") == NULL) {
        CUTE_RUN_TEST(kryptos_rsa_digital_signature_basic_scheme_tests);
        CUTE_RUN_TEST(kryptos_rsa_digital_signature_basic_scheme_c99_tests);
        CUTE_RUN_TEST(kryptos_rsa_emsa_pss_digital_signature_scheme_tests);
        CUTE_RUN_TEST(kryptos_rsa_emsa_pss_digital_signature_scheme_c99_tests);
    } else {
        printf("WARN: The RSA signature tests were skipped.\n");
    }

    if (CUTE_GET_OPTION("skip-dsa-signature-tests") == NULL) {
        CUTE_RUN_TEST(kryptos_dsa_mk_key_pair_tests);
        CUTE_RUN_TEST(kryptos_dsa_digital_signature_scheme_tests);
        CUTE_RUN_TEST(kryptos_dsa_digital_signature_scheme_c99_tests);
    } else {
        printf("WARN: The DSA signature tests were skipped.\n");
    }

//    CUTE_RUN_TEST(poke_bloody_poke);
CUTE_TEST_CASE_END

CUTE_MAIN(kryptos_test_monkey);
