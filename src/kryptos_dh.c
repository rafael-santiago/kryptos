/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_dh.h>
#include <kryptos_random.h>

struct kryptos_dh_modp_group_entry_ctx {
    kryptos_u8_t *p;
    size_t p_size;
    kryptos_u8_t *g;
    size_t g_size;
};

struct kryptos_dh_modp_group_ctx {
    struct kryptos_dh_modp_group_entry_ctx *data;
    size_t data_nr;
};

#define KRYPTOS_DH_MODP_GROUP_BEGIN(bits) static struct kryptos_dh_modp_group_entry_ctx dh_ ## bits ## _modp[] = {

#define KRYPTOS_DH_MODP_GROUP_END };

#define KRYPTOS_DH_ADD_GROUP_ENTRY(p, ps, g, gs) { p, ps, g, gs }

#define KRYPTOS_DH_GROUPS_BEGIN(name) static struct kryptos_dh_modp_group_ctx name [] = {

#define KRYPTOS_DH_GROUPS_END };

#define KRYPTOS_DH_ADD_BIT_GROUP(bits) { dh_ ## bits ## _modp, sizeof(dh_ ## bits ## _modp) / sizeof(dh_ ## bits ## _modp[0]) }

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

kryptos_task_result_t kryptos_dh_get_modp(const kryptos_dh_modp_group_bits_t bits,
                                          kryptos_mp_value_t **p, kryptos_mp_value_t **g) {
    kryptos_task_result_t result = kKryptosSuccess;

    if (bits < 0 || bits > kKryptosDHGroupNr || p == NULL || g == NULL) {
        result = kKryptosInvalidParams;
        goto kryptos_dh_get_modp_epilogue;
    }


    kryptos_dh_get_random_modp_entry(&dh_groups[bits], p, g);

    if ((*p) == NULL || (*g) == NULL) {
        result = kKryptosProcessError;

        if ((*p) != NULL) {
            kryptos_del_mp_value(*p);
        } else if ((*g) != NULL) {
            kryptos_del_mp_value(*g);
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

#undef KRYPTOS_DH_MODP_GROUP_BEGIN

#undef KRYPTOS_DH_MODP_GROUP_END

#undef KRYPTOS_DH_ADD_GROUP_ENTRY

#undef KRYPTOS_DH_GROUPS_BEGIN

#undef KRYPTOS_DH_GROUPS_END

#undef KRYPTOS_DH_ADD_BIT_GROUP
