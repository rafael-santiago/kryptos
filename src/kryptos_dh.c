/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_dh.h>
#include <kryptos_random.h>
#include <kryptos_dl_params.h>
#include <kryptos_pem.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

struct kryptos_dh_modp_group_entry_ctx {
    size_t p_size;
    size_t g_size;
    char *p;
    char *g;
};

struct kryptos_dh_modp_group_ctx {
    size_t data_nr;
    struct kryptos_dh_modp_group_entry_ctx *data;
};

#define KRYPTOS_DH_MODP_GROUP_BEGIN(bits) static struct kryptos_dh_modp_group_entry_ctx dh_ ## bits ## _modp[] = {

#define KRYPTOS_DH_MODP_GROUP_END };

#define KRYPTOS_DH_ADD_GROUP_ENTRY(p, ps, g, gs) { ps, gs, p, g }

#define KRYPTOS_DH_GROUPS_BEGIN(name) static struct kryptos_dh_modp_group_ctx name [] = {

#define KRYPTOS_DH_GROUPS_END };

#define KRYPTOS_DH_ADD_BIT_GROUP(bits) { sizeof(dh_ ## bits ## _modp) / sizeof(dh_ ## bits ## _modp[0]), dh_ ## bits ## _modp }

KRYPTOS_DH_MODP_GROUP_BEGIN(1536)
    KRYPTOS_DH_ADD_GROUP_ENTRY("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                               "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                               "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                               "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                               "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                               "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                               "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                               "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 384, "2", 1) // INFO(Rafael): RFC-3526.
KRYPTOS_DH_MODP_GROUP_END

KRYPTOS_DH_MODP_GROUP_BEGIN(2048)
    KRYPTOS_DH_ADD_GROUP_ENTRY("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                               "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                               "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                               "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                               "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                               "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                               "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                               "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                               "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                               "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                               "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 512, "2", 1) // INFO(Rafael): RFC-3526.
KRYPTOS_DH_MODP_GROUP_END

KRYPTOS_DH_MODP_GROUP_BEGIN(3072)
    KRYPTOS_DH_ADD_GROUP_ENTRY("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                               "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                               "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                               "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                               "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                               "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                               "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                               "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                               "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                               "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                               "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                               "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                               "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                               "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                               "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                               "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 768, "2", 1) // INFO(Rafael): RFC-3526.
KRYPTOS_DH_MODP_GROUP_END

KRYPTOS_DH_MODP_GROUP_BEGIN(4096)
    KRYPTOS_DH_ADD_GROUP_ENTRY("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                               "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                               "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                               "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                               "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                               "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                               "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                               "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                               "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                               "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                               "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                               "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                               "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                               "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                               "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                               "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
                               "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
                               "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
                               "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
                               "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
                               "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
                               "FFFFFFFFFFFFFFFF", 1024, "2", 1) // INFO(Rafael): RFC-3526.
KRYPTOS_DH_MODP_GROUP_END

KRYPTOS_DH_MODP_GROUP_BEGIN(6144)
    KRYPTOS_DH_ADD_GROUP_ENTRY("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                               "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
                               "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
                               "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                               "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
                               "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                               "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
                               "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
                               "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
                               "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
                               "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
                               "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                               "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
                               "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
                               "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
                               "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
                               "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
                               "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
                               "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
                               "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
                               "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
                               "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
                               "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
                               "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
                               "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
                               "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
                               "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
                               "6DCC4024FFFFFFFFFFFFFFFF", 1536, "2", 1) // INFO(Rafael): RFC-3526.
KRYPTOS_DH_MODP_GROUP_END

KRYPTOS_DH_MODP_GROUP_BEGIN(8192)
      KRYPTOS_DH_ADD_GROUP_ENTRY("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                                 "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                                 "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                                 "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                                 "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                                 "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                                 "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                                 "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                                 "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                                 "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                                 "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                                 "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                                 "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                                 "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                                 "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                                 "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
                                 "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
                                 "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
                                 "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
                                 "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
                                 "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
                                 "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
                                 "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
                                 "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
                                 "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
                                 "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
                                 "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
                                 "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
                                 "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
                                 "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
                                 "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
                                 "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
                                 "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
                                 "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
                                 "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
                                 "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
                                 "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
                                 "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
                                 "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
                                 "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
                                 "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
                                 "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
                                 "60C980DD98EDD3DFFFFFFFFFFFFFFFFF", 2048, "2", 1) // INFO(Rafael): RFC-3526.
KRYPTOS_DH_MODP_GROUP_END

KRYPTOS_DH_GROUPS_BEGIN(dh_groups)
    KRYPTOS_DH_ADD_BIT_GROUP(1536),
    KRYPTOS_DH_ADD_BIT_GROUP(2048),
    KRYPTOS_DH_ADD_BIT_GROUP(3072),
    KRYPTOS_DH_ADD_BIT_GROUP(4096),
    KRYPTOS_DH_ADD_BIT_GROUP(6144),
    KRYPTOS_DH_ADD_BIT_GROUP(8192)
KRYPTOS_DH_GROUPS_END

static void kryptos_dh_get_random_modp_entry(const struct kryptos_dh_modp_group_ctx *entries,
                                             kryptos_mp_value_t **p, kryptos_mp_value_t **g);

kryptos_task_result_t kryptos_dh_mk_domain_params(const size_t p_bits, const size_t q_bits,
                                                  kryptos_u8_t **params, size_t *params_size) {
    kryptos_task_result_t result = kKryptosSuccess;
    kryptos_mp_value_t *p = NULL, *q = NULL, *g = NULL;

    if (params == NULL || params_size == NULL || p_bits == 0 || q_bits == 0) {
        return kKryptosInvalidParams;
    }

    (*params) = NULL;
    *params_size = 0;

    if ((result = kryptos_generate_dl_params(p_bits, q_bits, &p, &q, &g)) == kKryptosSuccess) {
        // INFO(Rafael): The exportation of the q besides the prime p and the primitive element g is
        //               for verification issues. Since the data will be shared with other people, they will
        //               be able to verify if the prime and the generator are 'trustable' before actually accepting
        //               them.

        result = kryptos_pem_put_data(params, params_size, KRYPTOS_DH_PEM_HDR_PARAM_P,
                                      (kryptos_u8_t *)p->data, p->data_size * sizeof(kryptos_mp_digit_t));

        if (result != kKryptosSuccess) {
            goto kryptos_dh_mk_domain_params_epilogue;
        }

        result = kryptos_pem_put_data(params, params_size, KRYPTOS_DH_PEM_HDR_PARAM_Q,
                                      (kryptos_u8_t *)q->data, q->data_size * sizeof(kryptos_mp_digit_t));

        if (result != kKryptosSuccess) {
            goto kryptos_dh_mk_domain_params_epilogue;
        }

        result = kryptos_pem_put_data(params, params_size, KRYPTOS_DH_PEM_HDR_PARAM_G,
                                      (kryptos_u8_t *)g->data, g->data_size * sizeof(kryptos_mp_digit_t));
    }

kryptos_dh_mk_domain_params_epilogue:

    if (result != kKryptosSuccess && (*params) != NULL) {
        kryptos_freeseg(*params, *params_size);
        *params_size = 0;
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    return result;
}

kryptos_task_result_t kryptos_dh_verify_domain_params(const kryptos_u8_t *params, const size_t params_size) {
    kryptos_task_result_t result = kKryptosSuccess;
    kryptos_mp_value_t *p = NULL, *q = NULL, *g = NULL;

    if (params == NULL || params_size == 0) {
        return kKryptosInvalidParams;
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_P, params, params_size, &p);

    if (result != kKryptosSuccess) {
        result = kKryptosInvalidParams;
        goto kryptos_dh_verify_domain_params_epilogue;
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_Q, params, params_size, &q);

    if (result != kKryptosSuccess) {
        result = kKryptosInvalidParams;
        goto kryptos_dh_verify_domain_params_epilogue;
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_G, params, params_size, &g);

    if (result != kKryptosSuccess) {
        result = kKryptosInvalidParams;
        goto kryptos_dh_verify_domain_params_epilogue;
    }

    result = kryptos_verify_dl_params(p, q, g);

kryptos_dh_verify_domain_params_epilogue:

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    return result;
}

kryptos_task_result_t kryptos_dh_get_modp_from_params_buf(const kryptos_u8_t *params, const size_t params_size,
                                                          kryptos_mp_value_t **p, kryptos_mp_value_t **q,
                                                          kryptos_mp_value_t **g) {
    kryptos_task_result_t result = kKryptosSuccess;

    if (p == NULL || g == NULL || params == NULL || params_size == 0) {
        return kKryptosInvalidParams;
    }

    (*p) = (*g) = NULL;

    if (q != NULL) {
        (*q) = NULL;
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_P, params, params_size, p);

    if (result != kKryptosSuccess) {
        goto kryptos_dh_get_modp_from_params_buf_epilogue;
    }

    if (q != NULL) {
        result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_Q, params, params_size, q);
        if (result != kKryptosSuccess) {
            goto kryptos_dh_get_modp_from_params_buf_epilogue;
        }
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_G, params, params_size, g);

kryptos_dh_get_modp_from_params_buf_epilogue:

    if (result != kKryptosSuccess) {
        if ((*p) != NULL) {
            kryptos_del_mp_value(*p);
            (*p) = NULL;
        }

        if (q != NULL && (*q) != NULL) {
            kryptos_del_mp_value(*q);
            (*q) = NULL;
        }

        if ((*g) != NULL) {
            kryptos_del_mp_value(*g);
            (*g) = NULL;
        }
    }

    return result;
}

void kryptos_dh_mk_key_pair(kryptos_u8_t **k_pub, size_t *k_pub_size, kryptos_u8_t **k_priv, size_t *k_priv_size,
                            struct kryptos_dh_xchg_ctx **data) {

    if (data == NULL) {
        return;
    }

    if (k_pub == NULL || k_priv == NULL || k_pub_size == NULL || k_priv_size == NULL) {
        (*data)->result = kKryptosInvalidParams;
        (*data)->result_verbose = "NULL key pair pointers.";
        return;
    }

    if ((*data)->p == NULL || (*data)->g == NULL) {
        (*data)->result = kKryptosInvalidParams;
        (*data)->result_verbose = "The p and g parameters cannot be NULL.";
        return;
    }

    if ((*data)->s != NULL) {
        kryptos_del_mp_value((*data)->s);
    }

    (*data)->result = kryptos_dh_get_random_s(&(*data)->s, ((*data)->q == NULL) ? (*data)->p : (*data)->q, (*data)->s_bits);
    if (!kryptos_last_task_succeed(*data)) {
        (*data)->result_verbose = "Error while generating s.";
        return;
    }

    (*data)->result = kryptos_dh_eval_t(&(*data)->t, (*data)->g, (*data)->s, (*data)->p);
    if (!kryptos_last_task_succeed(*data)) {
        (*data)->result_verbose = "Unable to get t.";
        return;
    }

    if ((*k_pub) != NULL) {
        kryptos_freeseg(*k_pub, *k_pub_size);
    }

    (*data)->result = kryptos_pem_put_data(k_pub,
                                           k_pub_size,
                                           KRYPTOS_DH_PEM_HDR_PARAM_P,
                                           (kryptos_u8_t *)(*data)->p->data,
                                           (*data)->p->data_size * sizeof(kryptos_mp_digit_t));
    if (!kryptos_last_task_succeed(*data)) {
        (*data)->result_verbose = "Unable to export p into the public buffer.";
        return;
    }

    if ((*data)->q != NULL) {
        (*data)->result = kryptos_pem_put_data(k_pub,
                                               k_pub_size,
                                               KRYPTOS_DH_PEM_HDR_PARAM_Q,
                                               (kryptos_u8_t *)(*data)->q->data,
                                               (*data)->q->data_size * sizeof(kryptos_mp_digit_t));
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to export q into the public buffer.";
            return;
        }
    }

    (*data)->result = kryptos_pem_put_data(k_pub,
                                           k_pub_size,
                                           KRYPTOS_DH_PEM_HDR_PARAM_G,
                                           (kryptos_u8_t *)(*data)->g->data,
                                           (*data)->g->data_size * sizeof(kryptos_mp_digit_t));
    if (!kryptos_last_task_succeed(*data)) {
        (*data)->result_verbose = "Unable to export g into the public buffer.";
        return;
    }

    (*data)->result = kryptos_pem_put_data(k_pub,
                                           k_pub_size,
                                           KRYPTOS_DH_PEM_HDR_PARAM_T,
                                           (kryptos_u8_t *)(*data)->t->data,
                                           (*data)->t->data_size * sizeof(kryptos_mp_digit_t));
    if (!kryptos_last_task_succeed(*data)) {
        (*data)->result_verbose = "Unable to export t into the public buffer.";
        return;
    }

    kryptos_del_mp_value((*data)->t);
    (*data)->t = NULL;

    if ((*k_priv) != NULL) {
        kryptos_freeseg(*k_priv, *k_priv_size);
    }

    (*data)->result = kryptos_pem_put_data(k_priv,
                                           k_priv_size,
                                           KRYPTOS_DH_PEM_HDR_PARAM_S,
                                           (kryptos_u8_t *)(*data)->s->data,
                                           (*data)->s->data_size * sizeof(kryptos_mp_digit_t));

    if (!kryptos_last_task_succeed(*data)) {
        (*data)->result_verbose = "Unable to export s into the private buffer.";
        return;
    }

    // INFO(Rafael): P is public but it is also relevant during the "decryption" at receiver's side. So let's simplify the
    //               things to him/her putting all together in one place.

    (*data)->result = kryptos_pem_put_data(k_priv,
                                           k_priv_size,
                                           KRYPTOS_DH_PEM_HDR_PARAM_P,
                                           (kryptos_u8_t *)(*data)->p->data,
                                           (*data)->p->data_size * sizeof(kryptos_mp_digit_t));

    if (!kryptos_last_task_succeed(*data)) {
        (*data)->result_verbose = "Unable to export p into the private buffer.";
    }

    kryptos_del_mp_value((*data)->s);
    (*data)->s = NULL;
}

void kryptos_dh_process_modxchg(struct kryptos_dh_xchg_ctx **data) {
    // INFO(Rafael): This modified implementation eliminates (or at least mitigates) man-in-the-middle attacks.

    kryptos_mp_value_t *u = NULL;

    if (data == NULL) {
        return;
    }

    (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_U, (*data)->in, (*data)->in_size, &u);

    if (!kryptos_last_task_succeed(*data)) {
        // INFO(Rafael): This means that the user wants calculates K and also U (U will be sent to someone, calm down not you).
        //               In other words, the caller is the sender.

        // INFO(Rafael): Loading the receiver public key info...

        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_P, (*data)->in, (*data)->in_size,
                                                  &(*data)->p);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get p from input.";
            return;
        }

        // INFO(Rafael): Trying to parse q. Notice that here is assumed that since q was also passed, the
        //               user has already verified and accepted the <p, q, g> parameters using
        //               kryptos_dh_verify_domain_params().

        kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_Q,
                                (*data)->in, (*data)->in_size, &(*data)->q);

        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_G, (*data)->in, (*data)->in_size,
                                                  &(*data)->g);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get g from input.";
            return;
        }

        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_T, (*data)->in, (*data)->in_size,
                                                  &(*data)->t);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get t from input.";
            return;
        }

        // INFO(Rafael): The sender will pick a random s.

        (*data)->result = kryptos_dh_get_random_s(&(*data)->s, ((*data)->q == NULL) ? (*data)->p : (*data)->q, (*data)->s_bits);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Error while generating s.";
            return;
        }

        // INFO(Rafael): Now the sender calculates u.

        (*data)->result = kryptos_dh_eval_t(&u, (*data)->g, (*data)->s, (*data)->p);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get u.";
            return;
        }

        // INFO(Rafael): The sender also prepares this u for sending. If she/he wants to include the cryptogram into this
        //               PEM and send all together is possible. But this is out of scope here...

        (*data)->result = kryptos_pem_put_data(&(*data)->out,
                                               &(*data)->out_size,
                                               KRYPTOS_DH_PEM_HDR_PARAM_U,
                                               (kryptos_u8_t *)u->data,
                                               u->data_size * sizeof(kryptos_mp_digit_t));

        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to export u into the output buffer.";
            return;
        }

        kryptos_del_mp_value(u);

        // INFO(Rafael): Now the sender calculates the session key.

        (*data)->result = kryptos_dh_eval_t(&(*data)->k, (*data)->t, (*data)->s, (*data)->p);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get k.";
            return;
        }

        kryptos_del_mp_value((*data)->p);
        if ((*data)->q != NULL) {
            kryptos_del_mp_value((*data)->q);
            (*data)-> q = NULL;
        }
        kryptos_del_mp_value((*data)->g);
        kryptos_del_mp_value((*data)->t);
        kryptos_del_mp_value((*data)->s);

        (*data)->p = (*data)->g = (*data)->t = (*data)->s = NULL;
    } else {
        // INFO(Rafael): The caller is the receiver. Loading the receiver private key info...

        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_P, (*data)->in, (*data)->in_size,
                                                  &(*data)->p);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get p from input.";
            return;
        }

        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_S, (*data)->in, (*data)->in_size,
                                                  &(*data)->s);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get s from input.";
            return;
        }

        // INFO(Rafael): Getting the session key.

        (*data)->result = kryptos_dh_eval_t(&(*data)->k, u, (*data)->s, (*data)->p);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get k.";
        }

        kryptos_del_mp_value((*data)->p);
        kryptos_del_mp_value((*data)->s);
        kryptos_del_mp_value(u);

        (*data)->p = (*data)->s = NULL;

        // INFO(Rafael): No dialogue between the sender and receiver so no man-in-the-middle. If the input also includes
        //               the cryptogram, it must be processed later, here this is out of scope.
    }
}

void kryptos_dh_process_stdxchg(struct kryptos_dh_xchg_ctx **data) {
    int at_sender_side = 1;

    if ((*data)->p == NULL || (*data)->g == NULL) {
        // INFO(Rafael): The p, g and t must have in the input buffer. Otherwise it will fail.

        // INFO(Rafael): Parsing p.
        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_P,
                                                  (*data)->in, (*data)->in_size, &(*data)->p);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get " KRYPTOS_DH_PEM_HDR_PARAM_P ".";
            return;
        }

        // INFO(Rafael): Trying to parse q. Notice that here is assumed that since q was also passed, the
        //               user has already verified and accepted the <p, q, g> parameters using
        //               kryptos_dh_verify_domain_params().

        kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_Q,
                                (*data)->in, (*data)->in_size, &(*data)->q);

        // INFO(Rafael): Parsing g.
        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_G,
                                                  (*data)->in, (*data)->in_size, &(*data)->g);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get " KRYPTOS_DH_PEM_HDR_PARAM_G ".";
            return;
        }

        at_sender_side = 0;
    }

    if ((*data)->t == NULL && (*data)->in != NULL) {
        // INFO(Rafael): Parsing t.
        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_DH_PEM_HDR_PARAM_T,
                                                  (*data)->in, (*data)->in_size, &(*data)->t);
        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get " KRYPTOS_DH_PEM_HDR_PARAM_T ".";
            return;
        }
    }

#define kryptos_dh_process_stdxchg_eval_k(data) {\
    (*data)->result = kryptos_dh_eval_t(&(*data)->k, (*data)->t, (*data)->s, (*data)->p);\
    if (!kryptos_last_task_succeed(*data)) {\
        (*data)->result_verbose = "Unable to get k.";\
        return;\
    }\
}

    if ((*data)->s == NULL) {
        (*data)->result = kryptos_dh_get_random_s(&(*data)->s, ((*data)->q == NULL) ? (*data)->p : (*data)->q, (*data)->s_bits);

        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to get s.";
            return;
        }

        if ((*data)->out != NULL) {
            // INFO(Rafael): Since it is about a protocol, it can fail, if the user try again let's avoid any memory leak.
            kryptos_freeseg((*data)->out, (*data)->out_size);
            (*data)->out = NULL;
        }

        if (at_sender_side) {
            (*data)->result = kryptos_pem_put_data(&(*data)->out,
                                                   &(*data)->out_size,
                                                   KRYPTOS_DH_PEM_HDR_PARAM_P,
                                                   (kryptos_u8_t *)(*data)->p->data,
                                                   (*data)->p->data_size * sizeof(kryptos_mp_digit_t));
            if (!kryptos_last_task_succeed(*data)) {
                (*data)->result_verbose = "Unable to pack p into a PEM.";
                return;
            }

            if ((*data)->q != NULL) {
                (*data)->result = kryptos_pem_put_data(&(*data)->out,
                                                       &(*data)->out_size,
                                                       KRYPTOS_DH_PEM_HDR_PARAM_Q,
                                                       (kryptos_u8_t *)(*data)->q->data,
                                                       (*data)->q->data_size * sizeof(kryptos_mp_digit_t));
                if (!kryptos_last_task_succeed(*data)) {
                    (*data)->result_verbose = "Unable to pack q into a PEM.";
                    return;
                }
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out,
                                                   &(*data)->out_size,
                                                   KRYPTOS_DH_PEM_HDR_PARAM_G,
                                                   (kryptos_u8_t *)(*data)->g->data,
                                                   (*data)->g->data_size * sizeof(kryptos_mp_digit_t));
            if (!kryptos_last_task_succeed(*data)) {
                (*data)->result_verbose = "Unable to pack g into a PEM.";
                return;
            }

        } else {
            // INFO(Rafael): The receiver does not need to wait for any other value in order to get k.
            kryptos_dh_process_stdxchg_eval_k(data);
            kryptos_del_mp_value((*data)->t);
            (*data)->t = NULL;
        }

        (*data)->result = kryptos_dh_eval_t(&(*data)->t, (*data)->g, (*data)->s, (*data)->p);
        (*data)->result = kryptos_pem_put_data(&(*data)->out,
                                               &(*data)->out_size,
                                               KRYPTOS_DH_PEM_HDR_PARAM_T,
                                               (kryptos_u8_t *)(*data)->t->data,
                                               (*data)->t->data_size * sizeof(kryptos_mp_digit_t));

        if (!kryptos_last_task_succeed(*data)) {
            (*data)->result_verbose = "Unable to pack t into a PEM.";
        }

        kryptos_del_mp_value((*data)->t);
        (*data)->t = NULL;
    } else {
        // INFO(Rafael): All that we need to do is finally calculate k.
        kryptos_dh_process_stdxchg_eval_k(data);
    }

#undef kryptos_dh_process_stdxchg_eval_k
}

void kryptos_clear_dh_xchg_ctx(struct kryptos_dh_xchg_ctx *data) {
    if (data == NULL) {
        return;
    }

    if (data->p != NULL) {
        kryptos_del_mp_value(data->p);
    }

    if (data->q != NULL) {
        kryptos_del_mp_value(data->q);
    }

    if (data->g != NULL) {
        kryptos_del_mp_value(data->g);
    }

    if (data->t != NULL) {
        kryptos_del_mp_value(data->t);
    }

    if (data->s != NULL) {
        kryptos_del_mp_value(data->s);
    }

    if (data->k != NULL) {
        kryptos_del_mp_value(data->k);
    }

    if (data->in != NULL) {
        kryptos_freeseg(data->in, data->in_size);
    }

    if (data->out != NULL) {
        kryptos_freeseg(data->out, data->out_size);
    }

    kryptos_dh_init_xchg_ctx(data);
}

kryptos_task_result_t kryptos_dh_eval_t(kryptos_mp_value_t **t,
                                        const kryptos_mp_value_t *g, const kryptos_mp_value_t *s, const kryptos_mp_value_t *p) {
    if (t == NULL || g == NULL || s == NULL || p == NULL) {
        return kKryptosInvalidParams;
    }

    (*t) = kryptos_mp_me_mod_n(g, s, p);

    if ((*t) == NULL) {
        return kKryptosProcessError;
    }

    return kKryptosSuccess;
}

kryptos_task_result_t kryptos_dh_get_random_s(kryptos_mp_value_t **s, const kryptos_mp_value_t *p, const size_t s_bits) {
    kryptos_mp_value_t *p_2 = NULL, *_2 = NULL;
    kryptos_task_result_t result = kKryptosProcessError;
    ssize_t d;
    kryptos_mp_digit_t mask = 0;

    if (p == NULL || s == NULL) {
        return kKryptosInvalidParams;
    }

    if ((_2 = kryptos_hex_value_as_mp("2", 1)) == NULL) {
        goto kryptos_dh_get_random_s_epilogue;
    }

    if ((p_2 = kryptos_assign_mp_value(&p_2, p)) == NULL) {
        goto kryptos_dh_get_random_s_epilogue;
    }

    if ((p_2 = kryptos_mp_sub(&p_2, _2)) == NULL) {
        goto kryptos_dh_get_random_s_epilogue;
    }

    (*s) = kryptos_new_mp_value((s_bits == 0 || kryptos_mp_bit2byte(s_bits) > p->data_size) ? kryptos_mp_byte2bit(p->data_size) : s_bits);

    if ((*s) == NULL) {
        goto kryptos_dh_get_random_s_epilogue;
    }

#ifndef KRYPTOS_MP_U32_DIGIT
    mask = 0xFF;
#else
    mask = 0xFFFFFFFF;
    if (s_bits < 32) {
        mask = mask >> (32 - s_bits);
    }
#endif

    do {
        for (d = 0; d < (*s)->data_size; d++) {
#ifndef KRYPTOS_MP_U32_DIGIT
            (*s)->data[d] = kryptos_get_random_byte();
#else
            (*s)->data[d] = (((kryptos_u32_t)kryptos_get_random_byte()) << 24 |
                             ((kryptos_u32_t)kryptos_get_random_byte()) << 16 |
                             ((kryptos_u32_t)kryptos_get_random_byte()) <<  8 |
                             ((kryptos_u32_t)kryptos_get_random_byte())) & mask;
#endif
        }
    } while (kryptos_mp_gt(*s, p_2) || kryptos_mp_lt(*s, _2));

    result = kKryptosSuccess;

kryptos_dh_get_random_s_epilogue:
    if (_2 != NULL) {
        kryptos_del_mp_value(_2);
    }

    if (p_2 != NULL) {
        kryptos_del_mp_value(p_2);
    }

    return result;
}

kryptos_task_result_t kryptos_dh_get_modp(const kryptos_dh_modp_group_bits_t bits,
                                          kryptos_mp_value_t **p, kryptos_mp_value_t **g) {
    kryptos_task_result_t result = kKryptosSuccess;

    if (bits > kKryptosDHGroupNr || p == NULL || g == NULL) {
        result = kKryptosInvalidParams;
        goto kryptos_dh_get_modp_epilogue;
    }


    kryptos_dh_get_random_modp_entry(&dh_groups[bits], p, g);

    if ((*p) == NULL || (*g) == NULL) {
        result = kKryptosProcessError;

        if ((*p) != NULL) {
            kryptos_del_mp_value(*p);
            (*p) = NULL;
        } else if ((*g) != NULL) {
            kryptos_del_mp_value(*g);
            (*p) = NULL;
        }
    }

kryptos_dh_get_modp_epilogue:
    if (result != kKryptosSuccess) {
        if (p != NULL) {
            (*p) = NULL;
        }

        if (g != NULL) {
            (*g) = NULL;
        }
    }

    return result;
}

static void kryptos_dh_get_random_modp_entry(const struct kryptos_dh_modp_group_ctx *entries,
                                             kryptos_mp_value_t **p, kryptos_mp_value_t **g) {
    size_t index =
#if __WORDSIZE == 64
                    (size_t) kryptos_get_random_byte() << 56 |
                    (size_t) kryptos_get_random_byte() << 48 |
                    (size_t) kryptos_get_random_byte() << 40 |
                    (size_t) kryptos_get_random_byte() << 32 |
                    (size_t) kryptos_get_random_byte() << 24 |
                    (size_t) kryptos_get_random_byte() << 16 |
                    (size_t) kryptos_get_random_byte() <<  8 |
                    (size_t) kryptos_get_random_byte();
#else
                    (size_t) kryptos_get_random_byte() << 24 |
                    (size_t) kryptos_get_random_byte() << 16 |
                    (size_t) kryptos_get_random_byte() <<  8 |
                    (size_t) kryptos_get_random_byte();

#endif
    index = index % entries->data_nr;
    (*p) = kryptos_hex_value_as_mp(entries->data[index].p, entries->data[index].p_size);
    (*g) = kryptos_hex_value_as_mp(entries->data[index].g, entries->data[index].g_size);
}

#undef KRYPTOS_DH_MODP_GROUP_BEGIN

#undef KRYPTOS_DH_MODP_GROUP_END

#undef KRYPTOS_DH_ADD_GROUP_ENTRY

#undef KRYPTOS_DH_GROUPS_BEGIN

#undef KRYPTOS_DH_GROUPS_END

#undef KRYPTOS_DH_ADD_BIT_GROUP
