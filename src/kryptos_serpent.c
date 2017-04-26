/*
 *                          Copyright (C) 2007, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_serpent.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#include <stdarg.h>
#include <string.h>

#define kryptos_serpent_get_u8_from_u32(w,b) ( (kryptos_u8_t) ( (w) >> (24 - ((b) << 3)) )

#define kryptos_serpent_u32_rl(w,l) (kryptos_u32_t) ( ( (w) << (l) ) | ( (w) >> ( 32 - (l) ) ) )

#define kryptos_serpent_u32_rr(w,l) (kryptos_u32_t) ( ( (w) >> (l) ) | ( (w) << ( 32 - (l) ) ) )

#define kryptos_serpent_phi 0x9E3779B9

// INFO(Rafael): The "bitslicing" take away any sanity when doing it on software, so now I am using
//               the method presented by Dag Arne Osvik in his article called "Speeding up Serpent".
//

#define kryptos_serpent_lk(w0, w1, w2, w3, w4, r, k) {\
    (w0) = kryptos_serpent_u32_rl(w0, 13);\
    (w2) = kryptos_serpent_u32_rl(w2, 3);\
    (w1) = (w1) ^ (w0);\
    (w4) = (w0) << 3;\
    (w3) = (w3) ^ (w2);\
    (w1) = (w1) ^ (w2);\
    (w1) = kryptos_serpent_u32_rl(w1, 1);\
    (w3) = (w3) ^ (w4);\
    (w3) = kryptos_serpent_u32_rl(w3, 7);\
    (w4) = (w1);\
    (w0) = (w0) ^ (w1);\
    (w4) = (w4) << 7;\
    (w2) = (w2) ^ (w3);\
    (w0) = (w0) ^ (w3);\
    (w2) = (w2) ^ (w4);\
    (w3) = (w3) ^ (k)[4 * (r) + 3];\
    (w1) = (w1) ^ (k)[4 * (r) + 1];\
    (w0) = kryptos_serpent_u32_rl(w0, 5);\
    (w2) = kryptos_serpent_u32_rl(w2, 22);\
    (w0) = (w0) ^ (k)[4 * (r)];\
    (w2) = (w2) ^ (k)[4 * (r) + 2];\
}

#define kryptos_serpent_lk_1(w0, w1, w2, w3, w4, r, k) {\
    (w0) = (w0) ^ (k)[4 * (r)];\
    (w1) = (w1) ^ (k)[4 * (r) + 1];\
    (w2) = (w2) ^ (k)[4 * (r) + 2];\
    (w3) = (w3) ^ (k)[4 * (r) + 3];\
    (w0) = kryptos_serpent_u32_rr(w0, 5);\
    (w2) = kryptos_serpent_u32_rr(w2, 22);\
    (w4) = (w1);\
    (w2) = (w2) ^ (w3);\
    (w0) = (w0) ^ (w3);\
    (w4) = (w4) << 7;\
    (w0) = (w0) ^ (w1);\
    (w1) = kryptos_serpent_u32_rr(w1, 1);\
    (w2) = (w2) ^ (w4);\
    (w3) = kryptos_serpent_u32_rr(w3, 7);\
    (w4) = (w0) << 3;\
    (w1) = (w1) ^ (w0);\
    (w3) = (w3) ^ (w4);\
    (w0) = kryptos_serpent_u32_rr(w0, 13);\
    (w1) = (w1) ^ (w2);\
    (w3) = (w3) ^ (w2);\
    (w2) = kryptos_serpent_u32_rr(w2, 3);\
}

#define kryptos_serpent_sbox0(w0, w1, w2, w3, w4) {\
    (w4) = (w3);\
    (w3) = (w3) | (w0);\
    (w0) = (w0) ^ (w4);\
    (w4) = (w4) ^ (w2);\
    (w4) = ~(w4);\
    (w3) = (w3) ^ (w1);\
    (w1) = (w1) & (w0);\
    (w1) = (w1) ^ (w4);\
    (w2) = (w2) ^ (w0);\
    (w0) = (w0) ^ (w3);\
    (w4) = (w4) | (w0);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) & (w1);\
    (w3) = (w3) ^ (w2);\
    (w1) = ~(w1);\
    (w2) = (w2) ^  (w4);\
    (w1) = (w1) ^ (w2);\
}

#define kryptos_serpent_sbox1(w0, w1, w2, w3, w4) {\
    (w4) = (w1);\
    (w1) = (w1) ^ (w0);\
    (w0) = (w0) ^ (w3);\
    (w3) = ~(w3);\
    (w4) = (w4) & (w1);\
    (w0) = (w0) | (w1);\
    (w3) = (w3) ^ (w2);\
    (w0) = (w0) ^ (w3);\
    (w1) = (w1) ^ (w3);\
    (w3) = (w3) ^ (w4);\
    (w1) = (w1) | (w4);\
    (w4) = (w4) ^ (w2);\
    (w2) = (w2) & (w0);\
    (w2) = (w2) ^ (w1);\
    (w1) = (w1) | (w0);\
    (w0) = ~(w0);\
    (w0) = (w0) ^ (w2);\
    (w4) = (w4) ^ (w1);\
}

#define kryptos_serpent_sbox2(w0, w1, w2, w3, w4) {\
    (w3) = ~(w3);\
    (w1) = (w1) ^ (w0);\
    (w4) = (w0);\
    (w0) = (w0) & (w2);\
    (w0) = (w0) ^ (w3);\
    (w3) = (w3) | (w4);\
    (w2) = (w2) ^ (w1);\
    (w3) = (w3) ^ (w1);\
    (w1) = (w1) & (w0);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) & (w3);\
    (w3) = (w3) | (w1);\
    (w0) = ~(w0);\
    (w3) = (w3) ^ (w0);\
    (w4) = (w4) ^ (w0);\
    (w0) = (w0) ^ (w2);\
    (w1) = (w1) | (w2);\
}

#define kryptos_serpent_sbox3(w0, w1, w2, w3, w4) {\
    (w4) = (w1);\
    (w1) = (w1) ^ (w3);\
    (w3) = (w3) | (w0);\
    (w4) = (w4) & (w0);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) ^ (w1);\
    (w1) = (w1) & (w3);\
    (w2) = (w2) ^ (w3);\
    (w0) = (w0) | (w4);\
    (w4) = (w4) ^ (w3);\
    (w1) = (w1) ^ (w0);\
    (w0) = (w0) & (w3);\
    (w3) = (w3) & (w4);\
    (w3) = (w3) ^ (w2);\
    (w4) = (w4) | (w1);\
    (w2) = (w2) & (w1);\
    (w4) = (w4) ^ (w3);\
    (w0) = (w0) ^ (w3);\
    (w3) = (w3) ^ (w2);\
}

#define kryptos_serpent_sbox4(w0, w1, w2, w3, w4) {\
    (w4) = (w3);\
    (w3) = (w3) & (w0);\
    (w0) = (w0) ^ (w4);\
    (w3) = (w3) ^ (w2);\
    (w2) = (w2) | (w4);\
    (w0) = (w0) ^ (w1);\
    (w4) = (w4) ^ (w3);\
    (w2) = (w2) | (w0);\
    (w2) = (w2) ^ (w1);\
    (w1) = (w1) & (w0);\
    (w1) = (w1) ^ (w4);\
    (w4) = (w4) & (w2);\
    (w2) = (w2) ^ (w3);\
    (w4) = (w4) ^ (w0);\
    (w3) = (w3) | (w1);\
    (w1) = ~(w1);\
    (w3) = (w3) ^ (w0);\
}

#define kryptos_serpent_sbox5(w0, w1, w2, w3, w4) {\
    (w4) = (w1);\
    (w1) = (w1) | (w0);\
    (w2) = (w2) ^ (w1);\
    (w3) = ~(w3);\
    (w4) = (w4) ^ (w0);\
    (w0) = (w0) ^ (w2);\
    (w1) = (w1) & (w4);\
    (w4) = (w4) | (w3);\
    (w4) = (w4) ^ (w0);\
    (w0) = (w0) & (w3);\
    (w1) = (w1) ^ (w3);\
    (w3) = (w3) ^ (w2);\
    (w0) = (w0) ^ (w1);\
    (w2) = (w2) & (w4);\
    (w1) = (w1) ^ (w2);\
    (w2) = (w2) & (w0);\
    (w3) = (w3) ^ (w2);\
}

#define kryptos_serpent_sbox6(w0, w1, w2, w3, w4) {\
    (w4) = (w1);\
    (w3) = (w3) ^ (w0);\
    (w1) = (w1) ^ (w2);\
    (w2) = (w2) ^ (w0);\
    (w0) = (w0) & (w3);\
    (w1) = (w1) | (w3);\
    (w4) = ~(w4);\
    (w0) = (w0) ^ (w1);\
    (w1) = (w1) ^ (w2);\
    (w3) = (w3) ^ (w4);\
    (w4) = (w4) ^ (w0);\
    (w2) = (w2) & (w0);\
    (w4) = (w4) ^ (w1);\
    (w2) = (w2) ^ (w3);\
    (w3) = (w3) & (w1);\
    (w3) = (w3) ^ (w0);\
    (w1) = (w1) ^ (w2);\
}

#define kryptos_serpent_sbox7(w0, w1, w2, w3, w4) {\
    (w1) = ~(w1);\
    (w4) = (w1);\
    (w0) = ~(w0);\
    (w1) = (w1) & (w2);\
    (w1) = (w1) ^ (w3);\
    (w3) = (w3) | (w4);\
    (w4) = (w4) ^ (w2);\
    (w2) = (w2) ^ (w3);\
    (w3) = (w3) ^ (w0);\
    (w0) = (w0) | (w1);\
    (w2) = (w2) & (w0);\
    (w0) = (w0) ^ (w4);\
    (w4) = (w4) ^ (w3);\
    (w3) = (w3) & (w0);\
    (w4) = (w4) ^ (w1);\
    (w2) = (w2) ^ (w4);\
    (w3) = (w3) ^ (w1);\
    (w4) = (w4) | (w0);\
    (w4) = (w4) ^ (w1);\
}

#define kryptos_serpent_sbox0_1(w0, w1, w2, w3, w4) {\
    (w4) = (w3);\
    (w1) = (w1) ^ (w0);\
    (w3) = (w3) | (w1);\
    (w4) = (w4) ^ (w1);\
    (w0) = ~(w0);\
    (w2) = (w2) ^ (w3);\
    (w3) = (w3) ^ (w0);\
    (w0) = (w0) & (w1);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) & (w3);\
    (w3) = (w3) ^ (w4);\
    (w2) = (w2) ^ (w3);\
    (w1) = (w1) ^ (w3);\
    (w3) = (w3) & (w0);\
    (w1) = (w1) ^ (w0);\
    (w0) = (w0) ^ (w2);\
    (w4) = (w4) ^ (w3);\
}

#define kryptos_serpent_sbox1_1(w0, w1, w2, w3, w4) {\
    (w1) = (w1) ^ (w3);\
    (w4) = (w0);\
    (w0) = (w0) ^ (w2);\
    (w2) = ~(w2);\
    (w4) = (w4) | (w1);\
    (w4) = (w4) ^ (w3);\
    (w3) = (w3) & (w1);\
    (w1) = (w1) ^ (w2);\
    (w2) = (w2) & (w4);\
    (w4) = (w4) ^ (w1);\
    (w1) = (w1) | (w3);\
    (w3) = (w3) ^ (w0);\
    (w2) = (w2) ^ (w0);\
    (w0) = (w0) | (w4);\
    (w2) = (w2) ^ (w4);\
    (w1) = (w1) ^ (w0);\
    (w4) = (w4) ^ (w1);\
}

#define kryptos_serpent_sbox2_1(w0, w1, w2, w3, w4) {\
    (w2) = (w2) ^ (w1);\
    (w4) = (w3);\
    (w3) = ~(w3);\
    (w3) = (w3) | (w2);\
    (w2) = (w2) ^ (w4);\
    (w4) = (w4) ^ (w0);\
    (w3) = (w3) ^ (w1);\
    (w1) = (w1) | (w2);\
    (w2) = (w2) ^ (w0);\
    (w1) = (w1) ^ (w4);\
    (w4) = (w4) | (w3);\
    (w2) = (w2) ^ (w3);\
    (w4) = (w4) ^ (w2);\
    (w2) = (w2) & (w1);\
    (w2) = (w2) ^ (w3);\
    (w3) = (w3) ^ (w4);\
    (w4) = (w4) ^ (w0);\
}

#define kryptos_serpent_sbox3_1(w0, w1, w2, w3, w4) {\
    (w2) = (w2) ^ (w1);\
    (w4) = (w1);\
    (w1) = (w1) & (w2);\
    (w1) = (w1) ^ (w0);\
    (w0) = (w0) | (w4);\
    (w4) = (w4) ^ (w3);\
    (w0) = (w0) ^ (w3);\
    (w3) = (w3) | (w1);\
    (w1) = (w1) ^ (w2);\
    (w1) = (w1) ^ (w3);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) ^ (w3);\
    (w3) = (w3) & (w1);\
    (w1) = (w1) ^ (w0);\
    (w0) = (w0) & (w2);\
    (w4) = (w4) ^ (w3);\
    (w3) = (w3) ^ (w0);\
    (w0) = (w0) ^ (w1);\
}

#define kryptos_serpent_sbox4_1(w0, w1, w2, w3, w4) {\
    (w2) = (w2) ^ (w3);\
    (w4) = (w0);\
    (w0) = (w0) & (w1);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) | (w3);\
    (w4) = ~(w4);\
    (w1) = (w1) ^ (w0);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) & (w4);\
    (w2) = (w2) ^ (w0);\
    (w0) = (w0) | (w4);\
    (w0) = (w0) ^ (w3);\
    (w3) = (w3) & (w2);\
    (w4) = (w4) ^ (w3);\
    (w3) = (w3) ^ (w1);\
    (w1) = (w1) & (w0);\
    (w4) = (w4) ^ (w1);\
    (w0) = (w0) ^ (w3);\
}

#define kryptos_serpent_sbox5_1(w0, w1, w2, w3, w4) {\
    (w4) = (w1);\
    (w1) = (w1) | (w2);\
    (w2) = (w2) ^ (w4);\
    (w1) = (w1) ^ (w3);\
    (w3) = (w3) & (w4);\
    (w2) = (w2) ^ (w3);\
    (w3) = (w3) | (w0);\
    (w0) = ~(w0);\
    (w3) = (w3) ^ (w2);\
    (w2) = (w2) | (w0);\
    (w4) = (w4) ^ (w1);\
    (w2) = (w2) ^ (w4);\
    (w4) = (w4) & (w0);\
    (w0) = (w0) ^ (w1);\
    (w1) = (w1) ^ (w3);\
    (w0) = (w0) & (w2);\
    (w2) = (w2) ^ (w3);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) ^ (w4);\
    (w4) = (w4) ^ (w3);\
}

#define kryptos_serpent_sbox6_1(w0, w1, w2, w3, w4) {\
    (w0) = (w0) ^ (w2);\
    (w4) = (w0);\
    (w0) = (w0) & (w3);\
    (w2) = (w2) ^ (w3);\
    (w0) = (w0) ^ (w2);\
    (w3) = (w3) ^ (w1);\
    (w2) = (w2) | (w4);\
    (w2) = (w2) ^ (w3);\
    (w3) = (w3) & (w0);\
    (w0) = ~(w0);\
    (w3) = (w3) ^ (w1);\
    (w1) = (w1) & (w2);\
    (w4) = (w4) ^ (w0);\
    (w3) = (w3) ^ (w4);\
    (w4) = (w4) ^ (w2);\
    (w0) = (w0) ^ (w1);\
    (w2) = (w2) ^ (w0);\
}

#define kryptos_serpent_sbox7_1(w0, w1, w2, w3, w4) {\
    (w4) = (w3);\
    (w3) = (w3) & (w0);\
    (w0) = (w0) ^ (w2);\
    (w2) = (w2) | (w4);\
    (w4) = (w4) ^ (w1);\
    (w0) = ~(w0);\
    (w1) = (w1) | (w3);\
    (w4) = (w4) ^ (w0);\
    (w0) = (w0) & (w2);\
    (w0) = (w0) ^ (w1);\
    (w1) = (w1) & (w2);\
    (w3) = (w3) ^ (w2);\
    (w4) = (w4) ^ (w3);\
    (w2) = (w2) & (w3);\
    (w3) = (w3) | (w0);\
    (w1) = (w1) ^ (w4);\
    (w3) = (w3) ^ (w4);\
    (w4) = (w4) & (w0);\
    (w4) = (w4) ^ (w2);\
}

#define kryptos_serpent_ld_regs(r0, r1, r2, r3, r, k) {\
    (r0) = (k)[(r)];\
    (r1) = (k)[(r) + 1];\
    (r2) = (k)[(r) + 2];\
    (r3) = (k)[(r) + 3];\
};

#define kryptos_serpent_sto_key(k, r0, r1, r2, r3, r) {\
    (k)[(r)] = (r0);\
    (k)[(r) + 1] = (r1);\
    (k)[(r) + 2] = (r2);\
    (k)[(r) + 3] = r3;\
}

struct kryptos_serpent_subkeys {
    kryptos_u32_t k[132];
};

typedef void (*kryptos_serpent_block_processor)(kryptos_u8_t * block, struct kryptos_serpent_subkeys sks);

static void kryptos_serpent_ld_user_key(kryptos_u32_t key[8], const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_serpent_key_schedule(const kryptos_u8_t *key, const size_t key_size, struct kryptos_serpent_subkeys *sks);

static void kryptos_serpent_block_encrypt(kryptos_u8_t *block, struct kryptos_serpent_subkeys sks);

static void kryptos_serpent_block_decrypt(kryptos_u8_t *block, struct kryptos_serpent_subkeys sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(serpent, kKryptosCipherSERPENT, KRYPTOS_SERPENT_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(serpent,
                                    ktask,
                                    kryptos_serpent_subkeys,
                                    sks,
                                    kryptos_serpent_block_processor,
                                    serpent_block_processor,
                                    kryptos_serpent_key_schedule((*ktask)->key, (*ktask)->key_size, &sks),
                                    kryptos_serpent_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_serpent_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_SERPENT_BLOCKSIZE,
                                    serpent_cipher_epilogue,
                                    outblock,
                                    serpent_block_processor(outblock, sks))

static void kryptos_serpent_ld_user_key(kryptos_u32_t key[8], const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;

#define kryptos_ld_user_key_byte_serpent_craziness101(state, kp, kp_end, epilogue) {\
    if (kp == kp_end) goto epilogue;\
    state |= ( ((kryptos_u32_t) *kp) << (b << 3) );\
    kp++;\
    b = (b + 1) % sizeof(state);\
    if (b == 0) {\
        w++;\
    }\
}

    kryptos_ld_user_key_prologue(key, 8, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte_serpent_craziness101(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);

#undef kryptos_ld_user_key_byte_serpent_craziness101

    kryptos_ld_user_key_epilogue(kryptos_aes_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_serpent_key_schedule(const kryptos_u8_t *key, const size_t key_size, struct kryptos_serpent_subkeys *sks) {
    // INFO(Rafael): This function expands the user key to 132 32-bit values.
    kryptos_u32_t wkey[8];
    kryptos_u32_t tw[140];
    size_t w;
    kryptos_u8_t padded_ukey[32];
    kryptos_u32_t r0, r1, r2, r3, r4;

    memset(wkey, 0, sizeof(kryptos_u32_t) << 3);
    memset(padded_ukey, 0, sizeof(padded_ukey));
    memcpy(padded_ukey, key, key_size);

    if (key_size < 32){ // INFO(Rafael): We must pad the user-key if it has less than 256-bits.
        padded_ukey[key_size] = 0x01;
    }

    kryptos_serpent_ld_user_key(tw, padded_ukey, sizeof(padded_ukey));

    for (w = 8; w < 140; w++) {
        // CAUTION(Rafael): The Serpent spec is a little bit messy because it states:
        //
        //              w_i := (w_{i-8} ^ w_{i-5} ^ w_{i-3} ^ w_{i-1} ^ phi ^ i) <<< 11
        //
        // However, if you do not use "...phi ^ (i - 8)" instead of "...phi ^ i" you can waste hours into this trap,
        // I mean... loop.
        //
        tw[w] = kryptos_serpent_u32_rl(tw[w - 8] ^ tw[w - 5] ^ tw[w - 3] ^ tw[w - 1] ^ kryptos_serpent_phi ^ (w - 8), 11);
    }

    r0 = tw[w - 2];
    r1 = tw[w - 1];
    r2 = tw[w - 5];
    r3 = tw[w - 4];
    r4 = tw[w - 3];

    kryptos_serpent_sbox3(r3, r4, r0, r1, r2);
    kryptos_serpent_sto_key(sks->k, r1, r2, r4, r3, 128);
    kryptos_serpent_ld_regs(r1, r2, r4, r3, 132, tw);

    kryptos_serpent_sbox4(r1, r2, r4, r3, r0);
    kryptos_serpent_sto_key(sks->k, r2, r4, r3, r0, 124);
    kryptos_serpent_ld_regs(r2, r4, r3, r0, 128, tw);

    kryptos_serpent_sbox5(r2, r4, r3, r0, r1);
    kryptos_serpent_sto_key(sks->k, r1, r2, r4, r0, 120);
    kryptos_serpent_ld_regs(r1, r2, r4, r0, 124, tw);

    kryptos_serpent_sbox6(r1, r2, r4, r0, r3);
    kryptos_serpent_sto_key(sks->k, r4, r3, r2, r0, 116);
    kryptos_serpent_ld_regs(r4, r3, r2, r0, 120, tw);

    kryptos_serpent_sbox7(r4, r3, r2, r0, r1);
    kryptos_serpent_sto_key(sks->k, r1, r2, r0, r4, 112);
    kryptos_serpent_ld_regs(r1, r2, r0, r4, 116, tw);

    kryptos_serpent_sbox0(r1, r2, r0, r4, r3);
    kryptos_serpent_sto_key(sks->k, r0, r2, r4, r1, 108);
    kryptos_serpent_ld_regs(r0, r2, r4, r1, 112, tw);

    kryptos_serpent_sbox1(r0, r2, r4, r1, r3);
    kryptos_serpent_sto_key(sks->k, r3, r4, r1, r0, 104);
    kryptos_serpent_ld_regs(r3, r4, r1, r0, 108, tw);

    kryptos_serpent_sbox2(r3, r4, r1, r0, r2);
    kryptos_serpent_sto_key(sks->k, r2, r4, r3, r0, 100);
    kryptos_serpent_ld_regs(r2, r4, r3, r0, 104, tw);

    kryptos_serpent_sbox3(r2, r4, r3, r0, r1);
    kryptos_serpent_sto_key(sks->k, r0, r1, r4, r2, 96);
    kryptos_serpent_ld_regs(r0, r1, r4, r2, 100, tw);

    kryptos_serpent_sbox4(r0, r1, r4, r2, r3);
    kryptos_serpent_sto_key(sks->k, r1, r4, r2, r3, 92);
    kryptos_serpent_ld_regs(r1, r4, r2, r3, 96, tw);

    kryptos_serpent_sbox5(r1, r4, r2, r3, r0);
    kryptos_serpent_sto_key(sks->k, r0, r1, r4, r3, 88);
    kryptos_serpent_ld_regs(r0, r1, r4, r3, 92, tw);

    kryptos_serpent_sbox6(r0, r1, r4, r3, r2);
    kryptos_serpent_sto_key(sks->k, r4, r2, r1, r3, 84);
    kryptos_serpent_ld_regs(r4, r2, r1, r3, 88, tw);

    kryptos_serpent_sbox7(r4, r2, r1, r3, r0);
    kryptos_serpent_sto_key(sks->k, r0, r1, r3, r4, 80);
    kryptos_serpent_ld_regs(r0, r1, r3, r4, 84, tw);

    kryptos_serpent_sbox0(r0, r1, r3, r4, r2);
    kryptos_serpent_sto_key(sks->k, r3, r1, r4, r0, 76);
    kryptos_serpent_ld_regs(r3, r1, r4, r0, 80, tw);

    kryptos_serpent_sbox1(r3, r1, r4, r0, r2);
    kryptos_serpent_sto_key(sks->k, r2, r4, r0, r3, 72);
    kryptos_serpent_ld_regs(r2, r4, r0, r3, 76, tw);

    kryptos_serpent_sbox2(r2, r4, r0, r3, r1);
    kryptos_serpent_sto_key(sks->k, r1, r4, r2, r3, 68);
    kryptos_serpent_ld_regs(r1, r4, r2, r3, 72, tw);

    kryptos_serpent_sbox3(r1, r4, r2, r3, r0);
    kryptos_serpent_sto_key(sks->k, r3, r0, r4, r1, 64);
    kryptos_serpent_ld_regs(r3, r0, r4, r1, 68, tw);

    kryptos_serpent_sbox4(r3, r0, r4, r1, r2);
    kryptos_serpent_sto_key(sks->k, r0, r4, r1, r2, 60);
    kryptos_serpent_ld_regs(r0, r4, r1, r2, 64, tw);

    kryptos_serpent_sbox5(r0, r4, r1, r2, r3);
    kryptos_serpent_sto_key(sks->k, r3, r0, r4, r2, 56);
    kryptos_serpent_ld_regs(r3, r0, r4, r2, 60, tw);

    kryptos_serpent_sbox6(r3, r0, r4, r2, r1);
    kryptos_serpent_sto_key(sks->k, r4, r1, r0, r2, 52);
    kryptos_serpent_ld_regs(r4, r1, r0, r2, 56, tw);

    kryptos_serpent_sbox7(r4, r1, r0, r2, r3);
    kryptos_serpent_sto_key(sks->k, r3, r0, r2, r4, 48);
    kryptos_serpent_ld_regs(r3, r0, r2, r4, 52, tw);

    kryptos_serpent_sbox0(r3, r0, r2, r4, r1);
    kryptos_serpent_sto_key(sks->k, r2, r0, r4, r3, 44);
    kryptos_serpent_ld_regs(r2, r0, r4, r3, 48, tw);

    kryptos_serpent_sbox1(r2, r0, r4, r3, r1);
    kryptos_serpent_sto_key(sks->k, r1, r4, r3, r2, 40);
    kryptos_serpent_ld_regs(r1, r4, r3, r2, 44, tw);

    kryptos_serpent_sbox2(r1, r4, r3, r2, r0);
    kryptos_serpent_sto_key(sks->k, r0, r4, r1, r2, 36);
    kryptos_serpent_ld_regs(r0, r4, r1, r2, 40, tw);

    kryptos_serpent_sbox3(r0, r4, r1, r2, r3);
    kryptos_serpent_sto_key(sks->k, r2, r3, r4, r0, 32);
    kryptos_serpent_ld_regs(r2, r3, r4, r0, 36, tw);

    kryptos_serpent_sbox4(r2, r3, r4, r0, r1);
    kryptos_serpent_sto_key(sks->k, r3, r4, r0, r1, 28);
    kryptos_serpent_ld_regs(r3, r4, r0, r1, 32, tw);

    kryptos_serpent_sbox5(r3, r4, r0, r1, r2);
    kryptos_serpent_sto_key(sks->k, r2, r3, r4, r1, 24);
    kryptos_serpent_ld_regs(r2, r3, r4, r1, 28, tw);

    kryptos_serpent_sbox6(r2, r3, r4, r1, r0);
    kryptos_serpent_sto_key(sks->k, r4, r0, r3, r1, 20);
    kryptos_serpent_ld_regs(r4, r0, r3, r1, 24, tw);

    kryptos_serpent_sbox7(r4, r0, r3, r1, r2);
    kryptos_serpent_sto_key(sks->k, r2, r3, r1, r4, 16);
    kryptos_serpent_ld_regs(r2, r3, r1, r4, 20, tw);

    kryptos_serpent_sbox0(r2, r3, r1, r4, r0);
    kryptos_serpent_sto_key(sks->k, r1, r3, r4, r2, 12);
    kryptos_serpent_ld_regs(r1, r3, r4, r2, 16, tw);

    kryptos_serpent_sbox1(r1, r3, r4, r2, r0);
    kryptos_serpent_sto_key(sks->k, r0, r4, r2, r1, 8);
    kryptos_serpent_ld_regs(r0, r4, r2, r1, 12, tw);

    kryptos_serpent_sbox2(r0, r4, r2, r1, r3);
    kryptos_serpent_sto_key(sks->k, r3, r4, r0, r1, 4);
    kryptos_serpent_ld_regs(r3, r4, r0, r1, 8, tw);

    kryptos_serpent_sbox3(r3, r4, r0, r1, r2);
    kryptos_serpent_sto_key(sks->k, r1, r2, r4, r3, 0);

    memset(padded_ukey, 0, sizeof(padded_ukey));
    memset(wkey, 0, sizeof(wkey));
    memset(tw, 0, sizeof(tw));
    r0 = r1 = r2 = r3 = r4 = 0;
    w = 0;
}

static void kryptos_serpent_block_encrypt(kryptos_u8_t *block, struct kryptos_serpent_subkeys sks) {
    kryptos_u32_t r0, r1, r2, r3, r4;

    r0 = kryptos_get_u32_as_little_endian(block, 4);
    r1 = kryptos_get_u32_as_little_endian(block + 4, 4);
    r2 = kryptos_get_u32_as_little_endian(block + 8, 4);
    r3 = kryptos_get_u32_as_little_endian(block + 12, 4);

    r0 = r0 ^ sks.k[0];
    r1 = r1 ^ sks.k[1];
    r2 = r2 ^ sks.k[2];
    r3 = r3 ^ sks.k[3];

    kryptos_serpent_sbox0(r0, r1, r2, r3, r4);
    kryptos_serpent_lk(r2, r1, r3, r0, r4, 1, sks.k);

    kryptos_serpent_sbox1(r2, r1, r3, r0, r4);
    kryptos_serpent_lk(r4, r3, r0, r2, r1, 2, sks.k);

    kryptos_serpent_sbox2(r4, r3, r0, r2, r1);
    kryptos_serpent_lk(r1, r3, r4, r2, r0, 3, sks.k);

    kryptos_serpent_sbox3(r1, r3, r4, r2, r0);
    kryptos_serpent_lk(r2, r0, r3, r1, r4, 4, sks.k);

    kryptos_serpent_sbox4(r2, r0, r3, r1, r4);
    kryptos_serpent_lk(r0, r3, r1, r4, r2, 5, sks.k);

    kryptos_serpent_sbox5(r0, r3, r1, r4, r2);
    kryptos_serpent_lk(r2, r0, r3, r4, r1, 6, sks.k);

    kryptos_serpent_sbox6(r2, r0, r3, r4, r1);
    kryptos_serpent_lk(r3, r1, r0, r4, r2, 7, sks.k);

    kryptos_serpent_sbox7(r3, r1, r0, r4, r2);
    kryptos_serpent_lk(r2, r0, r4, r3, r1, 8, sks.k);

    kryptos_serpent_sbox0(r2, r0, r4, r3, r1);
    kryptos_serpent_lk(r4, r0, r3, r2, r1, 9, sks.k);

    kryptos_serpent_sbox1(r4, r0, r3, r2, r1);
    kryptos_serpent_lk(r1, r3, r2, r4, r0, 10, sks.k);

    kryptos_serpent_sbox2(r1, r3, r2, r4, r0);
    kryptos_serpent_lk(r0, r3, r1, r4, r2, 11, sks.k);

    kryptos_serpent_sbox3(r0, r3, r1, r4, r2);
    kryptos_serpent_lk(r4, r2, r3, r0, r1, 12, sks.k);

    kryptos_serpent_sbox4(r4, r2, r3, r0, r1);
    kryptos_serpent_lk(r2, r3, r0, r1, r4, 13, sks.k);

    kryptos_serpent_sbox5(r2, r3, r0, r1, r4);
    kryptos_serpent_lk(r4, r2, r3, r1, r0, 14, sks.k);

    kryptos_serpent_sbox6(r4, r2, r3, r1, r0);
    kryptos_serpent_lk(r3, r0, r2, r1, r4, 15, sks.k);

    kryptos_serpent_sbox7(r3, r0, r2, r1, r4);
    kryptos_serpent_lk(r4, r2, r1, r3, r0, 16, sks.k);

    kryptos_serpent_sbox0(r4, r2, r1, r3, r0);
    kryptos_serpent_lk(r1, r2, r3, r4, r0, 17, sks.k);

    kryptos_serpent_sbox1(r1, r2, r3, r4, r0);
    kryptos_serpent_lk(r0, r3, r4, r1, r2, 18, sks.k);

    kryptos_serpent_sbox2(r0, r3, r4, r1, r2);
    kryptos_serpent_lk(r2, r3, r0, r1, r4, 19, sks.k);

    kryptos_serpent_sbox3(r2, r3, r0, r1, r4);
    kryptos_serpent_lk(r1, r4, r3, r2, r0, 20, sks.k);

    kryptos_serpent_sbox4(r1, r4, r3, r2, r0);
    kryptos_serpent_lk(r4, r3, r2, r0, r1, 21, sks.k);

    kryptos_serpent_sbox5(r4, r3, r2, r0, r1);
    kryptos_serpent_lk(r1, r4, r3, r0, r2, 22, sks.k);

    kryptos_serpent_sbox6(r1, r4, r3, r0, r2);
    kryptos_serpent_lk(r3, r2, r4, r0, r1, 23, sks.k);

    kryptos_serpent_sbox7(r3, r2, r4, r0, r1);
    kryptos_serpent_lk(r1, r4, r0, r3, r2, 24, sks.k);

    kryptos_serpent_sbox0(r1, r4, r0, r3, r2);
    kryptos_serpent_lk(r0, r4, r3, r1, r2, 25, sks.k);

    kryptos_serpent_sbox1(r0, r4, r3, r1, r2);
    kryptos_serpent_lk(r2, r3, r1, r0, r4, 26, sks.k);

    kryptos_serpent_sbox2(r2, r3, r1, r0, r4);
    kryptos_serpent_lk(r4, r3, r2, r0, r1, 27, sks.k);

    kryptos_serpent_sbox3(r4, r3, r2, r0, r1);
    kryptos_serpent_lk(r0, r1, r3, r4, r2, 28, sks.k);

    kryptos_serpent_sbox4(r0, r1, r3, r4, r2);
    kryptos_serpent_lk(r1, r3, r4, r2, r0, 29, sks.k);

    kryptos_serpent_sbox5(r1, r3, r4, r2, r0);
    kryptos_serpent_lk(r0, r1, r3, r2, r4, 30, sks.k);

    kryptos_serpent_sbox6(r0, r1, r3, r2, r4);
    kryptos_serpent_lk(r3, r4, r1, r2, r0, 31, sks.k);

    kryptos_serpent_sbox7(r3, r4, r1, r2, r0);

    r0 = r0 ^ sks.k[128];
    r1 = r1 ^ sks.k[129];
    r2 = r2 ^ sks.k[130];
    r3 = r3 ^ sks.k[131];

    kryptos_cpy_u32_as_little_endian(block, 16, r0);
    kryptos_cpy_u32_as_little_endian(block + 4, 12, r1);
    kryptos_cpy_u32_as_little_endian(block + 8, 8, r2);
    kryptos_cpy_u32_as_little_endian(block + 12, 4, r3);

    r0 = r1 = r2 = r3 = r4;
}

static void kryptos_serpent_block_decrypt(kryptos_u8_t *block, struct kryptos_serpent_subkeys sks) {
    kryptos_u32_t r0, r1, r2, r3, r4;

    r0 = kryptos_get_u32_as_little_endian(block, 4);
    r1 = kryptos_get_u32_as_little_endian(block + 4, 4);
    r2 = kryptos_get_u32_as_little_endian(block + 8, 4);
    r3 = kryptos_get_u32_as_little_endian(block + 12, 4);

    r0 = r0 ^ sks.k[128];
    r1 = r1 ^ sks.k[129];
    r2 = r2 ^ sks.k[130];
    r3 = r3 ^ sks.k[131];

    kryptos_serpent_sbox7_1(r0, r1, r2, r3, r4);
    kryptos_serpent_lk_1(r1, r3, r0, r4, r2, 31, sks.k);

    kryptos_serpent_sbox6_1(r1, r3, r0, r4, r2);
    kryptos_serpent_lk_1(r0, r2, r4, r1, r3, 30, sks.k);

    kryptos_serpent_sbox5_1(r0, r2, r4, r1, r3);
    kryptos_serpent_lk_1(r2, r3, r0, r4, r1, 29, sks.k);

    kryptos_serpent_sbox4_1(r2, r3, r0, r4, r1);
    kryptos_serpent_lk_1(r2, r0, r1, r4, r3, 28, sks.k);

    kryptos_serpent_sbox3_1(r2, r0, r1, r4, r3);
    kryptos_serpent_lk_1(r1, r2, r3, r4, r0, 27, sks.k);

    kryptos_serpent_sbox2_1(r1, r2, r3, r4, r0);
    kryptos_serpent_lk_1(r2, r0, r4, r3, r1, 26, sks.k);

    kryptos_serpent_sbox1_1(r2, r0, r4, r3, r1);
    kryptos_serpent_lk_1(r1, r0, r4, r3, r2, 25, sks.k);

    kryptos_serpent_sbox0_1(r1, r0, r4, r3, r2);
    kryptos_serpent_lk_1(r4, r2, r0, r1, r3, 24, sks.k);

    kryptos_serpent_sbox7_1(r4, r2, r0, r1, r3);
    kryptos_serpent_lk_1(r2, r1, r4, r3, r0, 23, sks.k);

    kryptos_serpent_sbox6_1(r2, r1, r4, r3, r0);
    kryptos_serpent_lk_1(r4, r0, r3, r2, r1, 22, sks.k);

    kryptos_serpent_sbox5_1(r4, r0, r3, r2, r1);
    kryptos_serpent_lk_1(r0, r1, r4, r3, r2, 21, sks.k);

    kryptos_serpent_sbox4_1(r0, r1, r4, r3, r2);
    kryptos_serpent_lk_1(r0, r4, r2, r3, r1, 20, sks.k);

    kryptos_serpent_sbox3_1(r0, r4, r2, r3, r1);
    kryptos_serpent_lk_1(r2, r0, r1, r3, r4, 19, sks.k);

    kryptos_serpent_sbox2_1(r2, r0, r1, r3, r4);
    kryptos_serpent_lk_1(r0, r4, r3, r1, r2, 18, sks.k);

    kryptos_serpent_sbox1_1(r0, r4, r3, r1, r2);
    kryptos_serpent_lk_1(r2, r4, r3, r1, r0, 17, sks.k);

    kryptos_serpent_sbox0_1(r2, r4, r3, r1, r0);
    kryptos_serpent_lk_1(r3, r0, r4, r2, r1, 16, sks.k);

    kryptos_serpent_sbox7_1(r3, r0, r4, r2, r1);
    kryptos_serpent_lk_1(r0, r2, r3, r1, r4, 15, sks.k);

    kryptos_serpent_sbox6_1(r0, r2, r3, r1, r4);
    kryptos_serpent_lk_1(r3, r4, r1, r0, r2, 14, sks.k);

    kryptos_serpent_sbox5_1(r3, r4, r1, r0, r2);
    kryptos_serpent_lk_1(r4, r2, r3, r1, r0, 13, sks.k);

    kryptos_serpent_sbox4_1(r4, r2, r3, r1, r0);
    kryptos_serpent_lk_1(r4, r3, r0, r1, r2, 12, sks.k);

    kryptos_serpent_sbox3_1(r4, r3, r0, r1, r2);
    kryptos_serpent_lk_1(r0, r4, r2, r1, r3, 11, sks.k);

    kryptos_serpent_sbox2_1(r0, r4, r2, r1, r3);
    kryptos_serpent_lk_1(r4, r3, r1, r2, r0, 10, sks.k);

    kryptos_serpent_sbox1_1(r4, r3, r1, r2, r0);
    kryptos_serpent_lk_1(r0, r3, r1, r2, r4, 9, sks.k);

    kryptos_serpent_sbox0_1(r0, r3, r1, r2, r4);
    kryptos_serpent_lk_1(r1, r4, r3, r0, r2, 8, sks.k);

    kryptos_serpent_sbox7_1(r1, r4, r3, r0, r2);
    kryptos_serpent_lk_1(r4, r0, r1, r2, r3, 7, sks.k);

    kryptos_serpent_sbox6_1(r4, r0, r1, r2, r3);
    kryptos_serpent_lk_1(r1, r3, r2, r4, r0, 6, sks.k);

    kryptos_serpent_sbox5_1(r1, r3, r2, r4, r0);
    kryptos_serpent_lk_1(r3, r0, r1, r2, r4, 5, sks.k);

    kryptos_serpent_sbox4_1(r3, r0, r1, r2, r4);
    kryptos_serpent_lk_1(r3, r1, r4, r2, r0, 4, sks.k);

    kryptos_serpent_sbox3_1(r3, r1, r4, r2, r0);
    kryptos_serpent_lk_1(r4, r3, r0, r2, r1, 3, sks.k);

    kryptos_serpent_sbox2_1(r4, r3, r0, r2, r1);
    kryptos_serpent_lk_1(r3, r1, r2, r0, r4, 2, sks.k);

    kryptos_serpent_sbox1_1(r3, r1, r2, r0, r4);
    kryptos_serpent_lk_1(r4, r1, r2, r0, r3, 1, sks.k);

    kryptos_serpent_sbox0_1(r4, r1, r2, r0, r3);

    r2 = r2 ^ sks.k[0];
    r3 = r3 ^ sks.k[1];
    r1 = r1 ^ sks.k[2];
    r4 = r4 ^ sks.k[3];

    kryptos_cpy_u32_as_little_endian(block, 16, r2);
    kryptos_cpy_u32_as_little_endian(block + 4, 12, r3);
    kryptos_cpy_u32_as_little_endian(block + 8, 8, r1);
    kryptos_cpy_u32_as_little_endian(block + 12, 4, r4);

    r0 = r1 = r2 = r3  = r4 = 0;
}
