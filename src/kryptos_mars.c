/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_mars.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// INFO(Rafael): The SBOXES 'from MARS'...

static kryptos_u32_t kryptos_mars_S[512] = {
    0x09D0C479, 0x28C8FFE0, 0x84AA6C39, 0x9DAD7287, 0x7DFF9BE3, 0xD4268361, 0xC96DA1D4, 0x7974CC93,
    0x85D0582E, 0x2A4B5705, 0x1CA16A62, 0xC3BD279D, 0x0F1F25E5, 0x5160372F, 0xC695C1FB, 0x4D7FF1E4,
    0xAE5F6BF4, 0x0D72EE46, 0xFF23DE8A, 0xB1CF8E83, 0xF14902E2, 0x3E981E42, 0x8BF53EB6, 0x7F4BF8AC,
    0x83631F83, 0x25970205, 0x76AFE784, 0x3A7931D4, 0x4F846450, 0x5C64C3F6, 0x210A5F18, 0xC6986A26,
    0x28F4E826, 0x3A60A81C, 0xD340A664, 0x7EA820C4, 0x526687C5, 0x7EDDD12B, 0x32A11D1D, 0x9C9EF086,
    0x80F6E831, 0xAB6F04AD, 0x56FB9B53, 0x8B2E095C, 0xB68556AE, 0xD2250B0D, 0x294A7721, 0xE21FB253,
    0xAE136749, 0xE82AAE86, 0x93365104, 0x99404A66, 0x78A784DC, 0xB69BA84B, 0x04046793, 0x23DB5C1E,
    0x46CAE1D6, 0x2FE28134, 0x5A223942, 0x1863CD5B, 0xC190C6E3, 0x07DFB846, 0x6EB88816, 0x2D0DCC4A,
    0xA4CCAE59, 0x3798670D, 0xCBFA9493, 0x4F481D45, 0xEAFC8CA8, 0xDB1129D6, 0xB0449E20, 0x0F5407FB,
    0x6167D9A8, 0xD1F45763, 0x4DAA96C3, 0x3BEC5958, 0xABABA014, 0xB6CCD201, 0x38D6279F, 0x02682215,
    0x8F376CD5, 0x092C237E, 0xBFC56593, 0x32889D2C, 0x854B3E95, 0x05BB9B43, 0x7DCD5DCD, 0xA02E926C,
    0xFAE527E5, 0x36A1C330, 0x3412E1AE, 0xF257F462, 0x3C4F1D71, 0x30A2E809, 0x68E5F551, 0x9C61BA44,
    0x5DED0AB8, 0x75CE09C8, 0x9654F93E, 0x698C0CCA, 0x243CB3E4, 0x2B062B97, 0x0F3B8D9E, 0x00E050DF,
    0xFC5D6166, 0xE35F9288, 0xC079550D, 0x0591AEE8, 0x8E531E74, 0x75FE3578, 0x2F6D829A, 0xF60B21AE,
    0x95E8EB8D, 0x6699486B, 0x901D7D9B, 0xFD6D6E31, 0x1090ACEF, 0xE0670DD8, 0xDAB2E692, 0xCD6D4365,
    0xE5393514, 0x3AF345F0, 0x6241FC4D, 0x460DA3A3, 0x7BCF3729, 0x8BF1D1E0, 0x14AAC070, 0x1587ED55,
    0x3AFD7D3E, 0xD2F29E01, 0x29A9D1F6, 0xEFB10C53, 0xCF3B870F, 0xB414935C, 0x664465ED, 0x024ACAC7,
    0x59A744C1, 0x1D2936A7, 0xDC580AA6, 0xCF574CA8, 0x040A7A10, 0x6CD81807, 0x8A98BE4C, 0xACCEA063,
    0xC33E92B5, 0xD1E0E03D, 0xB322517E, 0x2092BD13, 0x386B2C4A, 0x52E8DD58, 0x58656DFB, 0x50820371,
    0x41811896, 0xE337EF7E, 0xD39FB119, 0xC97F0DF6, 0x68FEA01B, 0xA150A6E5, 0x55258962, 0xEB6FF41B,
    0xD7C9CD7A, 0xA619CD9E, 0xBCF09576, 0x2672C073, 0xF003FB3C, 0x4AB7A50B, 0x1484126A, 0x487BA9B1,
    0xA64FC9C6, 0xF6957D49, 0x38B06A75, 0xDD805FCD, 0x63D094CF, 0xF51C999E, 0x1AA4D343, 0xB8495294,
    0xCE9F8E99, 0xBFFCD770, 0xC7C275CC, 0x378453A7, 0x7B21BE33, 0x397F41BD, 0x4E94D131, 0x92CC1F98,
    0x5915EA51, 0x99F861B7, 0xC9980A88, 0x1D74FD5F, 0xB0A495F8, 0x614DEED0, 0xB5778EEA, 0x5941792D,
    0xFA90C1F8, 0x33F824B4, 0xC4965372, 0x3FF6D550, 0x4CA5FEC0, 0x8630E964, 0x5B3FBBD6, 0x7DA26A48,
    0xB203231A, 0x04297514, 0x2D639306, 0x2EB13149, 0x16A45272, 0x532459A0, 0x8E5F4872, 0xF966C7D9,
    0x07128DC0, 0x0D44DB62, 0xAFC8D52D, 0x06316131, 0xD838E7CE, 0x1BC41D00, 0x3A2E8C0F, 0xEA83837E,
    0xB984737D, 0x13BA4891, 0xC4F8B949, 0xA6D6ACB3, 0xA215CDCE, 0x8359838B, 0x6BD1AA31, 0xF579DD52,
    0x21B93F93, 0xF5176781, 0x187DFDDE, 0xE94AEB76, 0x2B38FD54, 0x431DE1DA, 0xAB394825, 0x9AD3048F,
    0xDFEA32AA, 0x659473E3, 0x623F7863, 0xF3346C59, 0xAB3AB685, 0x3346A90B, 0x6B56443E, 0xC6DE01F8,
    0x8D421FC0, 0x9B0ED10C, 0x88F1A1E9, 0x54C1F029, 0x7DEAD57B, 0x8D7BA426, 0x4CF5178A, 0x551A7CCA,
    0x1A9A5F08, 0xFCD651B9, 0x25605182, 0xE11FC6C3, 0xB6FD9676, 0x337B3027, 0xB7C8EB14, 0x9E5FD030,
    0x6B57E354, 0xAD913CF7, 0x7E16688D, 0x58872A69, 0x2C2FC7DF, 0xE389CCC6, 0x30738DF1, 0x0824A734,
    0xE1797A8B, 0xA4A8D57B, 0x5B5D193B, 0xC8A8309B, 0x73F9A978, 0x73398D32, 0x0F59573E, 0xE9DF2B03,
    0xE8A5B6C8, 0x848D0704, 0x98DF93C2, 0x720A1DC3, 0x684F259A, 0x943BA848, 0xA6370152, 0x863B5EA3,
    0xD17B978B, 0x6D9B58EF, 0x0A700DD4, 0xA73D36BF, 0x8E6A0829, 0x8695BC14, 0xE35B3447, 0x933AC568,
    0x8894B022, 0x2F511C27, 0xDDFBCC3C, 0x006662B6, 0x117C83FE, 0x4E12B414, 0xC2BCA766, 0x3A2FEC10,
    0xF4562420, 0x55792E2A, 0x46F5D857, 0xCEDA25CE, 0xC3601D3B, 0x6C00AB46, 0xEFAC9C28, 0xB3C35047,
    0x611DFEE3, 0x257C3207, 0xFDD58482, 0x3B14D84F, 0x23BECB64, 0xA075F3A3, 0x088F8EAD, 0x07ADF158,
    0x7796943C, 0xFACABF3D, 0xC09730CD, 0xF7679969, 0xDA44E9ED, 0x2C854C12, 0x35935FA3, 0x2F057D9F,
    0x690624F8, 0x1CB0BAFD, 0x7B0DBDC6, 0x810F23BB, 0xFA929A1A, 0x6D969A17, 0x6742979B, 0x74AC7D05,
    0x010E65C4, 0x86A3D963, 0xF907B5A0, 0xD0042BD3, 0x158D7D03, 0x287A8255, 0xBBA8366F, 0x096EDC33,
    0x21916A7B, 0x77B56B86, 0x951622F9, 0xA6C5E650, 0x8CEA17D1, 0xCD8C62BC, 0xA3D63433, 0x358A68FD,
    0x0F9B9D3C, 0xD6AA295B, 0xFE33384A, 0xC000738E, 0xCD67EB2F, 0xE2EB6DC2, 0x97338B02, 0x06C9F246,
    0x419CF1AD, 0x2B83C045, 0x3723F18A, 0xCB5B3089, 0x160BEAD7, 0x5D494656, 0x35F8A74B, 0x1E4E6C9E,
    0x000399BD, 0x67466880, 0xB4174831, 0xACF423B2, 0xCA815AB3, 0x5A6395E7, 0x302A67C5, 0x8BDB446B,
    0x108F8FA4, 0x10223EDA, 0x92B8B48B, 0x7F38D0EE, 0xAB2701D4, 0x0262D415, 0xAF224A30, 0xB3D88ABA,
    0xF8B2C3AF, 0xDAF7EF70, 0xCC97D3B7, 0xE9614B6C, 0x2BAEBFF4, 0x70F687CF, 0x386C9156, 0xCE092EE5,
    0x01E87DA6, 0x6CE91E6A, 0xBB7BCC84, 0xC7922C20, 0x9D3B71FD, 0x060E41C6, 0xD7590F15, 0x4E03BB47,
    0x183C198E, 0x63EEB240, 0x2DDBF49A, 0x6D5CBA54, 0x923750AF, 0xF9E14236, 0x7838162B, 0x59726C72,
    0x81B66760, 0xBB2926C1, 0x48A0CE0D, 0xA6C0496D, 0xAD43507B, 0x718D496A, 0x9DF057AF, 0x44B1BDE6,
    0x054356DC, 0xDE7CED35, 0xD51A138B, 0x62088CC9, 0x35830311, 0xC96EFCA2, 0x686F86EC, 0x8E77CB68,
    0x63E1D6B8, 0xC80F9778, 0x79C491FD, 0x1B4C67F2, 0x72698D7D, 0x5E368C31, 0xF7D95E2E, 0xA1D3493F,
    0xDCD9433E, 0x896F1552, 0x4BC4CA7A, 0xA6D1BAF4, 0xA5A96DCC, 0x0BEF8B46, 0xA169FDA7, 0x74DF40B7,
    0x4E208804, 0x9A756607, 0x038E87C8, 0x20211E44, 0x8B7AD4BF, 0xC6403F35, 0x1848E36D, 0x80BDB038,
    0x1E62891C, 0x643D2107, 0xBF04D6F8, 0x21092C8C, 0xF644F389, 0x0778404E, 0x7B78ADB8, 0xA2C52D53,
    0x42157ABE, 0xA2253E2E, 0x7BF3F4AE, 0x80F594F9, 0x953194E7, 0x77EB92ED, 0xB3816930, 0xDA8D9336,
    0xBF447469, 0xF26D9483, 0xEE6FAED5, 0x71371235, 0xDE425F73, 0xB4E59F43, 0x7DBE2D4E, 0x2D37B185,
    0x49DC9A63, 0x98C39D98, 0x1301C9A2, 0x389B1BBF, 0x0C18588D, 0xA421C1BA, 0x7AA3865C, 0x71E08558,
    0x3C5CFCAA, 0x7D239CA4, 0x0297D9DD, 0xD7DC2830, 0x4B37802B, 0x7428AB54, 0xAEEE0347, 0x4B3FBB85,
    0x692F2F08, 0x134E578E, 0x36D9E0BF, 0xAE8B5FCF, 0xEDB93ECF, 0x2B27248E, 0x170EB1EF, 0x7DC57FD6,
    0x1E760F16, 0xB1136601, 0x864E1B9B, 0xD7EA7319, 0x3AB871BD, 0xCFA4D76F, 0xE31BD782, 0x0DBEB469,
    0xABB96061, 0x5370F85D, 0xFFB07E37, 0xDA30D0FB, 0xEBC977B6, 0x0B98B40F, 0x3A4D0FE6, 0xDF4FC26B,
    0x159CF22A, 0xC298D6E2, 0x2B78EF6A, 0x61A94AC0, 0xAB561187, 0x14EEA0F0, 0xDF0D4164, 0x19AF70EE
};

static kryptos_u32_t *kryptos_mars_S0 = &kryptos_mars_S[0];

static kryptos_u32_t *kryptos_mars_S1 = &kryptos_mars_S[256];

static kryptos_u32_t *kryptos_mars_B = &kryptos_mars_S[265];

#define kryptos_mars_rotl(w, s) ( ( (w) << (s) ) | ( (w) >> (32 - (s)) ) )

#define kryptos_mars_E(in, k1, k2, L, M, R) {\
    M = in + k1;\
    R = kryptos_mars_rotl(in, 13) * k2;\
    L = kryptos_mars_S[M & 0x1FF];\
    R = kryptos_mars_rotl(R, 5);\
    L = L ^ R;\
    M = kryptos_mars_rotl(M, R & 0x1F);\
    R = kryptos_mars_rotl(R, 5);\
    L = L ^ R;\
    L = kryptos_mars_rotl(L, R & 0x1F);\
}

#define kryptos_mars_rotwr(D) {\
    D[4] = D[0];\
    D[5] = D[1];\
    D[6] = D[2];\
    D[7] = D[3];\
    D[3] = D[4];\
    D[2] = D[7];\
    D[1] = D[6];\
    D[0] = D[5];\
}\

#define kryptos_mars_get_byte_n(D, n) ( ( (D) >> ((n) << 3) ) & 0xFF )

#define kryptos_mars_rotwl(D) {\
    D[4] = D[0];\
    D[5] = D[1];\
    D[6] = D[2];\
    D[7] = D[3];\
    D[3] = D[6];\
    D[2] = D[5];\
    D[1] = D[4];\
    D[0] = D[7];\
}\

#define kryptos_mars_rotr(w, s) ( ( (w) >> (s) ) | ( (w) << (32 - (s)) ) )

// CLUE(Rafael): This implementation is suitable for little-endian machines,
//               if you are tilting at big-endian windmills... simply use a 'mirror' as shield, Sancho! ;)
#define kryptos_mars_rev_u32(w) ( ((w) << 24) | (((w) & 0xFF0000) >> 8) | (((w) & 0xFF00) << 8) | ((w) >> 24) )

struct kryptos_mars_subkeys {
    kryptos_u32_t K[40];
};

typedef void (*kryptos_mars_block_processor)(kryptos_u8_t *block, const struct kryptos_mars_subkeys *sks);

static void kryptos_mars_key_sched(const kryptos_u8_t *key, const size_t key_size, struct kryptos_mars_subkeys *sks,
                                   const size_t effective_key_size);

static void kryptos_mars_ld_user_key_bytes(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_mars_block_encrypt(kryptos_u8_t *block, const struct kryptos_mars_subkeys *sks);

static void kryptos_mars_block_decrypt(kryptos_u8_t *block, const struct kryptos_mars_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(mars128, kKryptosCipherMARS128, KRYPTOS_MARS_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(mars128,
                                    ktask,
                                    kryptos_mars_subkeys,
                                    sks,
                                    kryptos_mars_block_processor,
                                    mars_block_processor,
                                    kryptos_mars_key_sched((*ktask)->key, (*ktask)->key_size, &sks, 16),
                                    kryptos_mars_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_mars_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_MARS_BLOCKSIZE,
                                    mars128_cipher_epilogue,
                                    outblock,
                                    mars_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(mars128)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(mars192, kKryptosCipherMARS192, KRYPTOS_MARS_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(mars192,
                                    ktask,
                                    kryptos_mars_subkeys,
                                    sks,
                                    kryptos_mars_block_processor,
                                    mars_block_processor,
                                    kryptos_mars_key_sched((*ktask)->key, (*ktask)->key_size, &sks, 24),
                                    kryptos_mars_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_mars_block_decrypt, /* No additional steps before encrypting */,
                                    KRYPTOS_MARS_BLOCKSIZE,
                                    mars128_cipher_epilogue,
                                    outblock,
                                    mars_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(mars192)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(mars256, kKryptosCipherMARS256, KRYPTOS_MARS_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(mars256,
                                    ktask,
                                    kryptos_mars_subkeys,
                                    sks,
                                    kryptos_mars_block_processor,
                                    mars_block_processor,
                                    kryptos_mars_key_sched((*ktask)->key, (*ktask)->key_size, &sks, 32),
                                    kryptos_mars_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_mars_block_decrypt, /* No additional steps before encrypting */,
                                    KRYPTOS_MARS_BLOCKSIZE,
                                    mars128_cipher_epilogue,
                                    outblock,
                                    mars_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(mars256)

static void kryptos_mars_ld_user_key_bytes(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    // INFO(Rafael): Even being able to support up to 256-bit keys, let's set the limit of this implementation to 256-bit.
    kryptos_ld_user_key_prologue(key, 8, user_key, user_key_size, kp, kp_end, w, b, return);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_mars_ld_user_key_epilogue);
    kryptos_ld_user_key_epilogue(kryptos_mars_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_mars_key_sched(const kryptos_u8_t *key, const size_t key_size, struct kryptos_mars_subkeys *sks,
                                   const size_t effective_key_size) {
    ssize_t i;
    size_t n;
    kryptos_u32_t T[15], *TP, w, j, m;
    // WARN(Rafael): Even being possible to use keys until 440 bits let's set 256 as the bit size limit here in this
    //               'AES "compliant"' implementation.
    kryptos_u8_t wkey[32];

    // INFO(Rafael): Key buffer size in words.
    n = (effective_key_size << 3) >> 5;

    memset(wkey, 0, sizeof(wkey));

    memcpy(wkey, key, key_size);

    kryptos_mars_ld_user_key_bytes(T, wkey, effective_key_size);

    for (i = 0; i < n; i++) {
        // CLUE(Rafael): This implementation is suitable for little-endian machines,
        //               if you are tilting at big-endian windmills... simply use a 'mirror' as shield, Sancho! ;)
        T[i] = kryptos_mars_rev_u32(T[i]);
    }

    T[n] = n;

    for (i = n + 1; i < 15; i++) {
        T[i] = 0;
    }

// CLUE(Rafael): We could also just setting up lookup tables for i - 7, i - 2 and i - 1 progressions instead of calculating it.
//               However, I must confess that I love when I have the opportunity of handling negative subscripts in my code.
//
//               The progression dictated by '4i + j' could be stored into a lookup table too but I do not think it
//               time consuming enough to deserve a table. Take a look in '..._sched_linear()'.

#define kryptos_mars_T(i, T) ( (i) < 0 ? ((T) + 15)[(i)] : (T)[(i)] )

#define kryptos_mars_key_sched_linear(i, T, j)\
    (T)[(i)] ^= kryptos_mars_rotl(kryptos_mars_T(((i) - 7) % 15, T) ^\
                 kryptos_mars_T(((i) - 2) % 15, T), 3) ^ (((i) << 2) + (j))

#define kryptos_mars_key_sched_stirring_round_chunk(T, S, i)\
    (T)[(i)] = kryptos_mars_rotl(kryptos_mars_T(i, T) +\
                S[0x1FF & kryptos_mars_T(((i) - 1) % 15, T)], 9)

#define kryptos_mars_key_sched_stiring_round(T) {\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  0);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  1);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  2);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  3);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  4);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  5);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  6);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  7);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  8);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S,  9);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S, 10);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S, 11);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S, 12);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S, 13);\
    kryptos_mars_key_sched_stirring_round_chunk(T, kryptos_mars_S, 14);\
}

#define kryptos_mars_setmask(w, m, i, K) {\
    (w) = (K)[(i)] | 0x03;\
    (m) = (~(w) ^ ((w) << 1)) & (~(w) ^ ((w) >> 1)) & 0x7FFFFFFE;\
    (m) &= (m) >> 1;\
    (m) &= (m) >> 2;\
    (m) &= (m) >> 4;\
    (m) |= (m) << 1;\
    (m) |= (m) << 2;\
    (m) |= (m) << 4;\
    (m) &= 0x7FFFFFFC;\
    (w) ^= kryptos_mars_rotl(kryptos_mars_B[(K)[(i)] & 0x3], (K)[(i) - 1] & 0x1F) & (m);\
    (K)[(i)] = (w);\
}

    TP = &T[0];

    for (j = 0; j < 4; j++) {
        kryptos_mars_key_sched_linear( 0, TP, j);
        kryptos_mars_key_sched_linear( 1, TP, j);
        kryptos_mars_key_sched_linear( 2, TP, j);
        kryptos_mars_key_sched_linear( 3, TP, j);
        kryptos_mars_key_sched_linear( 4, TP, j);
        kryptos_mars_key_sched_linear( 5, TP, j);
        kryptos_mars_key_sched_linear( 6, TP, j);
        kryptos_mars_key_sched_linear( 7, TP, j);
        kryptos_mars_key_sched_linear( 8, TP, j);
        kryptos_mars_key_sched_linear( 9, TP, j);
        kryptos_mars_key_sched_linear(10, TP, j);
        kryptos_mars_key_sched_linear(11, TP, j);
        kryptos_mars_key_sched_linear(12, TP, j);
        kryptos_mars_key_sched_linear(13, TP, j);
        kryptos_mars_key_sched_linear(14, TP, j);

        kryptos_mars_key_sched_stiring_round(TP);
        kryptos_mars_key_sched_stiring_round(TP);
        kryptos_mars_key_sched_stiring_round(TP);
        kryptos_mars_key_sched_stiring_round(TP);

        sks->K[10 * j    ] = T[ 0];
        sks->K[10 * j + 1] = T[ 4];
        sks->K[10 * j + 2] = T[ 8];
        sks->K[10 * j + 3] = T[12];
        sks->K[10 * j + 4] = T[ 1];
        sks->K[10 * j + 5] = T[ 5];
        sks->K[10 * j + 6] = T[ 9];
        sks->K[10 * j + 7] = T[13];
        sks->K[10 * j + 8] = T[ 2];
        sks->K[10 * j + 9] = T[ 6];
    }

    // INFO(Rafael): 'Modify multiplication keys'.

    for (i = 5; i < 37; i += 2) {
        kryptos_mars_setmask(w, m, i, sks->K);
    }

    w = m = 0;

    memset(wkey, 0, sizeof(wkey));

#undef kryptos_mars_T

#undef kryptos_mars_key_sched_linear

#undef kryptos_mars_key_sched_stirring_round_chunk

#undef kryptos_mars_key_sched_stiring_round

#undef kryptos_mars_setmask
}

static void kryptos_mars_block_encrypt(kryptos_u8_t *block, const struct kryptos_mars_subkeys *sks) {
    kryptos_u32_t D[8], L, M, R;

    // CLUE(Rafael): This implementation is suitable for little-endian machines,
    //               if you are tilting at big-endian windmills... simply use a 'mirror' as shield, Sancho! ;)

    D[0] = kryptos_mars_rev_u32(kryptos_get_u32_as_big_endian(block, 4));
    D[1] = kryptos_mars_rev_u32(kryptos_get_u32_as_big_endian(block + 4, 4));
    D[2] = kryptos_mars_rev_u32(kryptos_get_u32_as_big_endian(block + 8, 4));
    D[3] = kryptos_mars_rev_u32(kryptos_get_u32_as_big_endian(block + 12, 4));

#define kryptos_mars_forward_mixing_round(i, D) {\
    D[1] ^= kryptos_mars_S0[kryptos_mars_get_byte_n(D[0], 0)];\
    D[1] += kryptos_mars_S1[kryptos_mars_get_byte_n(D[0], 1)];\
    D[2] += kryptos_mars_S0[kryptos_mars_get_byte_n(D[0], 2)];\
    D[3] ^= kryptos_mars_S1[kryptos_mars_get_byte_n(D[0], 3)];\
    D[0] = kryptos_mars_rotr(D[0], 24);\
    if (i == 0 || i == 4) {\
        D[0] += D[3];\
    } else if (i == 1 || i == 5) {\
        D[0] += D[1];\
    }\
    kryptos_mars_rotwr(D);\
}

#define kryptos_mars_keyed_transformation_round(i, D, K, L, M, R) {\
    kryptos_mars_E(D[0], K[(i << 1) + 4], K[(i << 1) + 5], L, M, R);\
    D[0] = kryptos_mars_rotl(D[0], 13);\
    D[2] += M;\
    if (i < 8) {\
        D[1] += L;\
        D[3] ^= R;\
    } else {\
        D[3] += L;\
        D[1] ^= R;\
    }\
    kryptos_mars_rotwr(D);\
}

#define kryptos_mars_backwards_mixing_round(i, D) {\
    if (i == 2 || i == 6) {\
        D[0] -= D[3];\
    } else if (i == 3 || i == 7) {\
        D[0] -= D[1];\
    }\
    D[1] ^= kryptos_mars_S1[kryptos_mars_get_byte_n(D[0], 0)];\
    D[2] -= kryptos_mars_S0[kryptos_mars_get_byte_n(D[0], 3)];\
    D[3] -= kryptos_mars_S1[kryptos_mars_get_byte_n(D[0], 2)];\
    D[3] ^= kryptos_mars_S0[kryptos_mars_get_byte_n(D[0], 1)];\
    D[0] = kryptos_mars_rotl(D[0], 24);\
    kryptos_mars_rotwr(D);\
}

    // IMFO(Rafael): Key whitening.

    D[0] += sks->K[0];
    D[1] += sks->K[1];
    D[2] += sks->K[2];
    D[3] += sks->K[3];

    // INFO(Rafael): Eight rounds of forward mixing.

    kryptos_mars_forward_mixing_round(0, D);
    kryptos_mars_forward_mixing_round(1, D);
    kryptos_mars_forward_mixing_round(2, D);
    kryptos_mars_forward_mixing_round(3, D);
    kryptos_mars_forward_mixing_round(4, D);
    kryptos_mars_forward_mixing_round(5, D);
    kryptos_mars_forward_mixing_round(6, D);
    kryptos_mars_forward_mixing_round(7, D);

    // INFO(Rafael): Sixteen rounds of keyed transformation.

    kryptos_mars_keyed_transformation_round( 0, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 1, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 2, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 3, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 4, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 5, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 6, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 7, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 8, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round( 9, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round(10, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round(11, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round(12, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round(13, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round(14, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round(15, D, sks->K, L, M, R);

    // INFO(Rafael): Eight rounds of backwards mixing.

    kryptos_mars_backwards_mixing_round(0, D);
    kryptos_mars_backwards_mixing_round(1, D);
    kryptos_mars_backwards_mixing_round(2, D);
    kryptos_mars_backwards_mixing_round(3, D);
    kryptos_mars_backwards_mixing_round(4, D);
    kryptos_mars_backwards_mixing_round(5, D);
    kryptos_mars_backwards_mixing_round(6, D);
    kryptos_mars_backwards_mixing_round(7, D);

    // INFO(Rafael): Key whitening stuff.

    D[0] -= sks->K[36];
    D[1] -= sks->K[37];
    D[2] -= sks->K[38];
    D[3] -= sks->K[39];

    kryptos_cpy_u32_as_big_endian(block, 16, kryptos_mars_rev_u32(D[0]));
    kryptos_cpy_u32_as_big_endian(block + 4, 12, kryptos_mars_rev_u32(D[1]));
    kryptos_cpy_u32_as_big_endian(block + 8, 8, kryptos_mars_rev_u32(D[2]));
    kryptos_cpy_u32_as_big_endian(block + 12, 4, kryptos_mars_rev_u32(D[3]));

    D[0] = D[1] = D[2] = D[3] =
    D[4] = D[5] = D[6] = D[7] = L = M = R = 0;

#undef kryptos_mars_forward_mixing_round

#undef kryptos_mars_keyed_transformation_round

#undef kryptos_mars_backwards_mixing_round
}

static void kryptos_mars_block_decrypt(kryptos_u8_t *block, const struct kryptos_mars_subkeys *sks) {
    kryptos_u32_t D[8], L, M, R;

    // CLUE(Rafael): This implementation is suitable for little-endian machines,
    //               if you are tilting at big-endian windmills... simply use a 'mirror' as shield, Sancho! ;)

    D[0] = kryptos_mars_rev_u32(kryptos_get_u32_as_big_endian(block, 4));
    D[1] = kryptos_mars_rev_u32(kryptos_get_u32_as_big_endian(block + 4, 4));
    D[2] = kryptos_mars_rev_u32(kryptos_get_u32_as_big_endian(block + 8, 4));
    D[3] = kryptos_mars_rev_u32(kryptos_get_u32_as_big_endian(block + 12, 4));

#define kryptos_mars_forward_mixing_round_1(i, D) {\
    kryptos_mars_rotwl(D);\
    D[0] = kryptos_mars_rotr(D[0], 24);\
    D[3] ^= kryptos_mars_S0[kryptos_mars_get_byte_n(D[0], 1)];\
    D[3] += kryptos_mars_S1[kryptos_mars_get_byte_n(D[0], 2)];\
    D[2] += kryptos_mars_S0[kryptos_mars_get_byte_n(D[0], 3)];\
    D[1] ^= kryptos_mars_S1[kryptos_mars_get_byte_n(D[0], 0)];\
    if (i == 2 || i == 6) {\
        D[0] += D[3];\
    } else if (i == 3 || i == 7) {\
        D[0] += D[1];\
    }\
}

#define kryptos_mars_keyed_transformation_round_1(i, D, K, L, M, R) {\
    kryptos_mars_rotwl(D);\
    D[0] = kryptos_mars_rotr(D[0], 13);\
    kryptos_mars_E(D[0], K[(i << 1) + 4], K[(i << 1) + 5], L, M, R);\
    D[2] -= M;\
    if (i < 8) {\
        D[1] -= L;\
        D[3] ^= R;\
    } else {\
        D[3] -= L;\
        D[1] ^= R;\
    }\
}

#define kryptos_mars_backwards_mixing_round_1(i, D) {\
    kryptos_mars_rotwl(D);\
    if (i == 0 || i == 4) {\
        D[0] -= D[3];\
    } else if (i == 1 || i == 5) {\
        D[0] -= D[1];\
    }\
    D[0] = kryptos_mars_rotl(D[0], 24);\
    D[3] ^= kryptos_mars_S1[kryptos_mars_get_byte_n(D[0], 3)];\
    D[2] -= kryptos_mars_S0[kryptos_mars_get_byte_n(D[0], 2)];\
    D[1] -= kryptos_mars_S1[kryptos_mars_get_byte_n(D[0], 1)];\
    D[1] ^= kryptos_mars_S0[kryptos_mars_get_byte_n(D[0], 0)];\
}

    // INFO(Rafael): Key whitening.

    D[0] += sks->K[36];
    D[1] += sks->K[37];
    D[2] += sks->K[38];
    D[3] += sks->K[39];

    // INFO(Rafael): Forward mixing inverse.

    kryptos_mars_forward_mixing_round_1(7, D);
    kryptos_mars_forward_mixing_round_1(6, D);
    kryptos_mars_forward_mixing_round_1(5, D);
    kryptos_mars_forward_mixing_round_1(4, D);
    kryptos_mars_forward_mixing_round_1(3, D);
    kryptos_mars_forward_mixing_round_1(2, D);
    kryptos_mars_forward_mixing_round_1(1, D);
    kryptos_mars_forward_mixing_round_1(0, D);

    // INFO(Rafael): Keyed transformation inverse.

    kryptos_mars_keyed_transformation_round_1(15, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1(14, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1(13, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1(12, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1(11, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1(10, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 9, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 8, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 7, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 6, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 5, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 4, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 3, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 2, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 1, D, sks->K, L, M, R);
    kryptos_mars_keyed_transformation_round_1( 0, D, sks->K, L, M, R);

    // INFO(Rafael): Backwards mixing inverse.

    kryptos_mars_backwards_mixing_round_1(7, D);
    kryptos_mars_backwards_mixing_round_1(6, D);
    kryptos_mars_backwards_mixing_round_1(5, D);
    kryptos_mars_backwards_mixing_round_1(4, D);
    kryptos_mars_backwards_mixing_round_1(3, D);
    kryptos_mars_backwards_mixing_round_1(2, D);
    kryptos_mars_backwards_mixing_round_1(1, D);
    kryptos_mars_backwards_mixing_round_1(0, D);

    // INFO(Rafael): Key whitening.

    D[0] -= sks->K[0];
    D[1] -= sks->K[1];
    D[2] -= sks->K[2];
    D[3] -= sks->K[3];

    kryptos_cpy_u32_as_big_endian(block, 16, kryptos_mars_rev_u32(D[0]));
    kryptos_cpy_u32_as_big_endian(block + 4, 12, kryptos_mars_rev_u32(D[1]));
    kryptos_cpy_u32_as_big_endian(block + 8, 8, kryptos_mars_rev_u32(D[2]));
    kryptos_cpy_u32_as_big_endian(block + 12, 4, kryptos_mars_rev_u32(D[3]));

    D[0] = D[1] = D[2] = D[3] =
    D[4] = D[5] = D[6] = D[7] = L = M = R = 0;

#undef kryptos_mars_forward_mixing_round_1

#undef kryptos_mars_keyed_transformation_round_1

#undef kryptos_mars_backwards_mixing_round_1
}

#undef kryptos_mars_rotl

#undef kryptos_mars_E

#undef kryptos_mars_rotwr

#undef kryptos_mars_get_byte_n

#undef kryptos_mars_rotwl

#undef kryptos_mars_rotr

#undef kryptos_mars_rev_u32
