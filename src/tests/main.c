/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <cutest.h>
#include <kryptos_random.h>
#include "generic_tests.h"
#include "dsl_tests.h"
#include "symmetric_ciphers_tests.h"
#include "hash_tests.h"
#include "kdf_tests.h"
#include "encoding_tests.h"
#include "mp_tests.h"
#include "asymmetric_ciphers_tests.h"
#include "bad_buf_tests.h"
#include "ecc_tests.h"

CUTE_TEST_CASE(kryptos_test_monkey)

    // CLUE(Rafael): Before adding a new test try to find out the best place that it fits.
    //               At first glance you should consider the utility that it implements into the library.

    // INFO(Rafael): Generic/shared stuff.

    CUTE_RUN_TEST(kryptos_memcmp_tests);
    CUTE_RUN_TEST(kryptos_memset_tests);
    CUTE_RUN_TEST(kryptos_memory_tests);
    CUTE_RUN_TEST(kryptos_u32_rev_tests);
    CUTE_RUN_TEST(kryptos_u64_rev_tests);
    CUTE_RUN_TEST(kryptos_padding_tests);
    CUTE_RUN_TEST(kryptos_unbiased_rand_mod_u8_tests);
    CUTE_RUN_TEST(kryptos_unbiased_rand_mod_u16_tests);
    CUTE_RUN_TEST(kryptos_unbiased_rand_mod_u32_tests);
    CUTE_RUN_TEST(kryptos_unbiased_rand_mod_u64_tests);
    CUTE_RUN_TEST(kryptos_sys_get_random_block_tests);
    CUTE_RUN_TEST(kryptos_get_random_block_tests);
    CUTE_RUN_TEST(kryptos_fortuna_general_tests);
    CUTE_RUN_TEST(kryptos_csprng_context_change_tests);
    CUTE_RUN_TEST(kryptos_block_parser_tests);
    CUTE_RUN_TEST(kryptos_endianness_utils_tests);
    CUTE_RUN_TEST(kryptos_apply_iv_tests);
    CUTE_RUN_TEST(kryptos_iv_inc_u32_tests);
    CUTE_RUN_TEST(kryptos_iv_data_flush_tests);
    CUTE_RUN_TEST(kryptos_gcm_gf_mul_tests);
    CUTE_RUN_TEST(kryptos_gcm_tests);
    CUTE_RUN_TEST(kryptos_task_check_tests);
    CUTE_RUN_TEST(kryptos_task_check_sign_tests);
    CUTE_RUN_TEST(kryptos_task_check_verify_tests);
    CUTE_RUN_TEST(kryptos_hex_tests);
    CUTE_RUN_TEST(kryptos_u8_ptr_to_hex_tests);
    CUTE_RUN_TEST(kryptos_hash_common_tests);

    //  -=-=-=-=- If you have just added a new cipher take a look in "kryptos_dsl_tests" case, there is some work to
    //                                               be done there too! -=-=-=-=-=-=-

    //  -=-=-=-=- If you have just added a new cipher you must implement a GCM test case for this new cipher, even being
    //                 a unsupported mode for this cipher, take a look at previous gcm test cases -=-=-=-=-

    // INFO(Rafael): Internal DSL stuff.
    CUTE_RUN_TEST(kryptos_dsl_tests);

    // INFO(Rafael): Symmetric stuff.

    CUTE_RUN_TEST(kryptos_salsa20_H_tests);
    CUTE_RUN_TEST(kryptos_chacha20_H_tests);

    // INFO(Rafael): Cipher validation using official test vectors.
    CUTE_RUN_TEST(kryptos_arc4_tests);
    CUTE_RUN_TEST(kryptos_seal_tests);
    CUTE_RUN_TEST(kryptos_rabbit_tests);
    CUTE_RUN_TEST(kryptos_salsa20_tests);
    CUTE_RUN_TEST(kryptos_chacha20_tests);
    CUTE_RUN_TEST(kryptos_des_weak_keys_detection_tests);
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
    CUTE_RUN_TEST(kryptos_shacal1_tests);
    CUTE_RUN_TEST(kryptos_shacal2_tests);
    CUTE_RUN_TEST(kryptos_noekeon_tests);
    CUTE_RUN_TEST(kryptos_noekeon_d_tests);
    CUTE_RUN_TEST(kryptos_gost_ds_tests);
    CUTE_RUN_TEST(kryptos_gost_tests);

    // INFO(Rafael): Operation modes (complementary tests).

    CUTE_RUN_TEST(kryptos_ctr_mode_sequencing_tests);

    // INFO(Rafael): We only test the GCM mode after ensuring that everything is fine with CTR.

    CUTE_RUN_TEST(kryptos_des_gcm_tests);
    CUTE_RUN_TEST(kryptos_idea_gcm_tests);
    CUTE_RUN_TEST(kryptos_blowfish_gcm_tests);
    CUTE_RUN_TEST(kryptos_feal_gcm_tests);
    CUTE_RUN_TEST(kryptos_rc2_gcm_tests);
    CUTE_RUN_TEST(kryptos_camellia128_gcm_tests);
    CUTE_RUN_TEST(kryptos_camellia192_gcm_tests);
    CUTE_RUN_TEST(kryptos_camellia256_gcm_tests);
    CUTE_RUN_TEST(kryptos_cast5_gcm_tests);
    CUTE_RUN_TEST(kryptos_saferk64_gcm_tests);
    CUTE_RUN_TEST(kryptos_aes128_gcm_tests);
    CUTE_RUN_TEST(kryptos_aes192_gcm_tests);
    CUTE_RUN_TEST(kryptos_aes256_gcm_tests);
    CUTE_RUN_TEST(kryptos_serpent_gcm_tests);
    CUTE_RUN_TEST(kryptos_triple_des_gcm_tests);
    CUTE_RUN_TEST(kryptos_triple_des_ede_gcm_tests);
    CUTE_RUN_TEST(kryptos_tea_gcm_tests);
    CUTE_RUN_TEST(kryptos_xtea_gcm_tests);
    CUTE_RUN_TEST(kryptos_misty1_gcm_tests);
    CUTE_RUN_TEST(kryptos_rc5_gcm_tests);
    CUTE_RUN_TEST(kryptos_rc6_128_gcm_tests);
    CUTE_RUN_TEST(kryptos_rc6_192_gcm_tests);
    CUTE_RUN_TEST(kryptos_rc6_256_gcm_tests);
    CUTE_RUN_TEST(kryptos_mars128_gcm_tests);
    CUTE_RUN_TEST(kryptos_mars192_gcm_tests);
    CUTE_RUN_TEST(kryptos_mars256_gcm_tests);
    CUTE_RUN_TEST(kryptos_present80_gcm_tests);
    CUTE_RUN_TEST(kryptos_present128_gcm_tests);
    CUTE_RUN_TEST(kryptos_shacal1_gcm_tests);
    CUTE_RUN_TEST(kryptos_shacal2_gcm_tests);
    CUTE_RUN_TEST(kryptos_noekeon_gcm_tests);
    CUTE_RUN_TEST(kryptos_noekeon_d_gcm_tests);
    CUTE_RUN_TEST(kryptos_gost_ds_gcm_tests);
    CUTE_RUN_TEST(kryptos_gost_gcm_tests);

    CUTE_RUN_TEST(kryptos_bad_decryption_tests);
    CUTE_RUN_TEST(kryptos_bad_hmac_tests);

    CUTE_RUN_TEST(kryptos_bcrypt_tests);
    CUTE_RUN_TEST(kryptos_bcrypt_verify_tests);

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
    CUTE_RUN_TEST(kryptos_whirlpool_tests);
    CUTE_RUN_TEST(kryptos_whirlpool_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_blake2s256_tests);
    CUTE_RUN_TEST(kryptos_blake2s256_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_blake2s256_keyed_tests);
    CUTE_RUN_TEST(kryptos_blake2s256_hash_macro_keyed_tests);
    CUTE_RUN_TEST(kryptos_blake2b512_tests);
    CUTE_RUN_TEST(kryptos_blake2b512_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_blake2b512_keyed_tests);
    CUTE_RUN_TEST(kryptos_blake2b512_hash_macro_keyed_tests);
    CUTE_RUN_TEST(kryptos_blake2sN_tests);
    CUTE_RUN_TEST(kryptos_blake2sN_hash_macro_tests);
    CUTE_RUN_TEST(kryptos_blake2bN_tests);
    CUTE_RUN_TEST(kryptos_blake2bN_hash_macro_tests);

    // INFO(Rafael): Non-cryptographic hashes.
    CUTE_RUN_TEST(kryptos_djb2_tests);

    //  -=-=-=-=-=-=- New block ciphers/hash functions should be added to HMAC tests. -=-=-=-=-=-=-=-

    // INFO(Rafael): HMAC tests.
    CUTE_RUN_TEST(kryptos_hmac_basic_tests);
    CUTE_RUN_TEST(kryptos_hmac_tests);

    // INFO(Rafael): KDF stuff.

    CUTE_RUN_TEST(kryptos_do_hkdf_tests);
    CUTE_RUN_TEST(kryptos_hkdf_macro_tests);
    CUTE_RUN_TEST(kryptos_do_pbkdf2_tests);
    CUTE_RUN_TEST(kryptos_pbkdf2_macro_tests);
    CUTE_RUN_TEST(kryptos_do_argon2_tests);
    CUTE_RUN_TEST(kryptos_argon2_macro_tests);
    CUTE_RUN_TEST(kryptos_do_argon2_bounds_tests);
    CUTE_RUN_TEST(kryptos_argon2_macro_bounds_tests);

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
    CUTE_RUN_TEST(kryptos_mp_add_tests);
    CUTE_RUN_TEST(kryptos_mp_sub_tests);
    CUTE_RUN_TEST(kryptos_mp_mul_tests);
    CUTE_RUN_TEST(kryptos_mp_mul_digit_tests);
    CUTE_RUN_TEST(kryptos_mp_not_tests);
    CUTE_RUN_TEST(kryptos_mp_inv_tests);
    CUTE_RUN_TEST(kryptos_mp_lsh_tests);
    CUTE_RUN_TEST(kryptos_mp_rsh_tests);
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
    CUTE_RUN_TEST(kryptos_mp_modinv_rs_tests);
    CUTE_RUN_TEST(kryptos_mp_modinv_tests);
    CUTE_RUN_TEST(kryptos_raw_buffer_as_mp_tests);
    CUTE_RUN_TEST(kryptos_mp_as_task_out_tests);
    CUTE_RUN_TEST(kryptos_mp_add_s_tests);
    CUTE_RUN_TEST(kryptos_mp_sub_s_tests);
    CUTE_RUN_TEST(kryptos_mp_mul_s_tests);
    CUTE_RUN_TEST(kryptos_mp_mod_tests);
    CUTE_RUN_TEST(kryptos_mp_get_bitmap_tests);
    // INFO(Rafael): Barrett reduction depends on kryptos_mp_get_bitmap(), so it needs to run after that.
    CUTE_RUN_TEST(kryptos_mp_barrett_reduction_tests);

    // INFO(Rafael): This encoding function depends on multiprecision stuff, this is because we need
    //               to test it later than other encoding stuff.

    CUTE_RUN_TEST(kryptos_pem_get_mp_data_tests);

    // INFO(Rafael): Elliptic curve base functions.

    CUTE_RUN_TEST(kryptos_ec_set_point_tests);
    CUTE_RUN_TEST(kryptos_ec_set_curve_tests);
    CUTE_RUN_TEST(kryptos_ec_add_tests);
    CUTE_RUN_TEST(kryptos_ec_dbl_tests);
    CUTE_RUN_TEST(kryptos_ec_mul_tests);

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

    CUTE_RUN_TEST(kryptos_new_standard_curve_tests);
    CUTE_RUN_TEST(kryptos_ecdh_get_curve_from_params_buf_tests);
    CUTE_RUN_TEST(kryptos_ecdh_get_random_k_tests);
    CUTE_RUN_TEST(kryptos_ecdh_process_xchg_tests);
    CUTE_RUN_TEST(kryptos_ecdh_process_xchg_with_stdcurves_tests);

    if (CUTE_GET_OPTION("skip-ecdsa-signature-tests") == NULL) {
        CUTE_RUN_TEST(kryptos_ecdsa_mk_key_pair_tests);
        CUTE_RUN_TEST(kryptos_ecdsa_digital_signature_scheme_tests);
        CUTE_RUN_TEST(kryptos_ecdsa_digital_signature_scheme_c99_tests);
    } else {
        printf("WARN: The ECDSA signature tests were skipped.\n");
    }

//    CUTE_RUN_TEST(poke_bloody_poke);
CUTE_TEST_CASE_END

CUTE_MAIN(kryptos_test_monkey);
