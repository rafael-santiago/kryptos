/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_rc2.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos_task_check.h>
#include <kryptos_pw2.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define kryptos_rc2_get_byte(x, b) (kryptos_u16_t) ( ( (x)  >> (8 - (b << 3)) ) & 0xff )

#define kryptos_rc2_rol(x, s) (kryptos_u16_t) ( (x) << (s) | (x) >> ( (sizeof(x) << 3) - (s) ) )

#define kryptos_rc2_rollevel(i) ( (i) == 0 ? 1 : (i) == 1 ? 2 : (i) == 2 ? 3 : (i) == 3 ? 5 : -1 )

#define kryptos_rc2_mixupr(r, i, k, j) ( (r)[(i)] = (r)[(i)] + (k)[(j)] + ((r)[((i) + 3) % 4] & (r)[((i) + 2) % 4]) +\
                                                    ((~(r)[((i) + 3) % 4]) & (r)[((i) + 1) % 4]),\
                                         (j)++,\
                                         (r)[i] = kryptos_rc2_rol((r)[i], kryptos_rc2_rollevel(i)) )

#define kryptos_rc2_mashr(r, i, k) ( (r)[(i)] = (r)[(i)] + (k)[(r)[((i) + 3) % 4] & 63] )

#define kryptos_rc2_mixinground(r, k, j) ( kryptos_rc2_mixupr(r, 0, k, j),\
                                           kryptos_rc2_mixupr(r, 1, k, j),\
                                           kryptos_rc2_mixupr(r, 2, k, j),\
                                           kryptos_rc2_mixupr(r, 3, k, j) )

#define kryptos_rc2_mashinground(r, k) ( kryptos_rc2_mashr(r, 0, k),\
                                         kryptos_rc2_mashr(r, 1, k),\
                                         kryptos_rc2_mashr(r, 2, k),\
                                         kryptos_rc2_mashr(r, 3, k) )

#define kryptos_rc2_ror(x, s) (kryptos_u16_t) ( (x) >> (s) | (x) << ( (sizeof(x) << 3) - (s) ) )

#define kryptos_rc2_rmixupr(r, i, k, j) ( (r)[(i)] = kryptos_rc2_ror((r)[(i)], kryptos_rc2_rollevel(i)),\
                                          (r)[(i)] = (r)[(i)] - (k)[(j)] - ((r)[((i) + 3) % 4] & (r)[((i) + 2) % 4]) -\
                                                     ((~(r)[((i) + 3) % 4]) & (r)[((i) + 1) % 4]),\
                                          (j)-- )

#define kryptos_rc2_rmashr(r, i, k) ( (r)[(i)] = (r)[(i)] - (k)[(r)[((i) + 3) % 4] & 63] )

#define kryptos_rc2_rmixinground(r, k, j) ( kryptos_rc2_rmixupr(r, 3, k, j),\
                                            kryptos_rc2_rmixupr(r, 2, k, j),\
                                            kryptos_rc2_rmixupr(r, 1, k, j),\
                                            kryptos_rc2_rmixupr(r, 0, k, j) )

#define kryptos_rc2_rmashinground(r, k) ( kryptos_rc2_rmashr(r, 3, k),\
                                          kryptos_rc2_rmashr(r, 2, k),\
                                          kryptos_rc2_rmashr(r, 1, k),\
                                          kryptos_rc2_rmashr(r, 0, k) )

// INFO(Rafael): random bytes based on PI-digits.
static kryptos_u8_t kryptos_rc2_PITABLE[256] = {
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};

struct kryptos_rc2_subkeys {
    kryptos_u16_t K[64]; // INFO(Rafael): It stores the 64 16-bit sub-keys after the key expansion.
    int T1;              // INFO(Rafael): This is the effective key size.
};

typedef void (*kryptos_rc2_block_processor)(kryptos_u8_t *block, const struct kryptos_rc2_subkeys *sks);

static void kryptos_rc2_ld_user_key(kryptos_u16_t key[64], const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_rc2_inflate_key(const kryptos_u8_t *key, const size_t key_size, struct kryptos_rc2_subkeys *sks);

static void kryptos_rc2_block_encrypt(kryptos_u8_t *block, const struct kryptos_rc2_subkeys *sks);

static void kryptos_rc2_block_decrypt(kryptos_u8_t *block, const struct kryptos_rc2_subkeys *sks);

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(rc2, ktask, kKryptosCipherRC2, KRYPTOS_RC2_BLOCKSIZE, int *T1,
                                       {
                                            if (T1 != NULL) {
                                                ktask->arg[0] = T1;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                       })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(rc2,
                                    ktask,
                                    kryptos_rc2_subkeys,
                                    sks,
                                    kryptos_rc2_block_processor,
                                    rc2_block_processor,
                                    {
                                        // INFO(Rafael): RC2 key expansion algorithm does not work with keys
                                        //               longer than 1024-bit.
                                        if ((*ktask)->key_size > 128) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC2 key has more bits than 1024.";
                                            goto kryptos_rc2_cipher_epilogue;
                                        }
                                        // INFO(Rafael): Verifying and loading the T1 parameter.
                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC2 T1 parameter is missing.";
                                            goto kryptos_rc2_cipher_epilogue;
                                        }
                                        // INFO(Rafael): T1 also has its limitations.
                                        sks.T1 = *(int *)(*ktask)->arg[0];
                                        if (sks.T1 > 1025 || sks.T1 < 1) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC2 T1 parameter must be a value between 1 and 1025.";
                                            goto kryptos_rc2_cipher_epilogue;
                                        }
                                        // INFO(Rafael): All ok, we can inflate the supplied user key.
                                        kryptos_rc2_inflate_key((*ktask)->key, (*ktask)->key_size, &sks);
                                    },
                                    kryptos_rc2_block_encrypt, /*No additional steps are necessary before encrypting*/,
                                    kryptos_rc2_block_decrypt, /*No additional steps are necessary before decrypting*/,
                                    KRYPTOS_RC2_BLOCKSIZE,
                                    rc2_cipher_epilogue,
                                    outblock,
                                    rc2_block_processor(outblock, &sks))

static void kryptos_rc2_ld_user_key(kryptos_u16_t key[64], const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;

    kryptos_ld_user_key_prologue(key, 64, user_key, user_key_size, kp, kp_end, w, b, return);

    //  INFO(Rafael): Ugly but faster than cute iterations. The RC2 is an "old days" algorithm
    //                and it works based on words, when "words" was about 16-bit values.
    //
    //                Four bytes laid on a single memory cell was such a "remote" dream... :)
    //

    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_rc2_ld_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_rc2_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_rc2_inflate_key(const kryptos_u8_t *key, const size_t key_size, struct kryptos_rc2_subkeys *sks) {
    ssize_t i;
    size_t j, TM, Tn;
    kryptos_u16_t K[64];
    kryptos_u8_t L[128];
    size_t T = key_size;

    kryptos_rc2_ld_user_key(K, key, key_size);

    for (i = 0, j = 0; i < T; j++) {
        // INFO(Rafael): Dividing the L state into L_{words total x 2} bytes
        L[j] = kryptos_rc2_get_byte(K[i], j % 2);
        if(j % 2 == 1) {
            i++;
        }
    }

    // INFO(Rafael): Evaluating TM.

    Tn = (sks->T1 + 7) / 8;
    TM = 255 % kryptos_pw2((8 + sks->T1) - (Tn << 3));

    // INFO(Rafael): start of the expansion.

    for (i = T; i < 128; L[i] = kryptos_rc2_PITABLE[(L[i - 1] + L[i - T]) % 256], i++)
        ;

    L[128 - Tn] = kryptos_rc2_PITABLE[L[128 - Tn] & TM];

    for (i = 127 - Tn; i >= 0; L[i] = kryptos_rc2_PITABLE[L[i + 1] ^ L[i + Tn]], i--)
        ;

    for (i = 0, j = 0; i < 128; sks->K[j] = (kryptos_u16_t) L[i + 1] << 8 | (kryptos_u16_t) L[i], i += 2, j++)
        ;

    i = j = Tn = TM = T = 0;
    memset(L, 0, sizeof(L));
    memset(K, 0, sizeof(K));
}

static void kryptos_rc2_block_encrypt(kryptos_u8_t *block, const struct kryptos_rc2_subkeys *sks) {
    size_t ri;
    kryptos_u16_t r[4];

    r[0] = kryptos_get_u16_as_big_endian(block, 2);
    r[1] = kryptos_get_u16_as_big_endian(block + 2, 2);
    r[2] = kryptos_get_u16_as_big_endian(block + 4, 2);
    r[3] = kryptos_get_u16_as_big_endian(block + 6, 2);

    ri = 0;

    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);

    kryptos_rc2_mashinground(r, sks->K);

    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);

    kryptos_rc2_mashinground(r, sks->K);

    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);
    kryptos_rc2_mixinground(r, sks->K, ri);

    kryptos_cpy_u16_as_big_endian(block, 8, r[0]);
    kryptos_cpy_u16_as_big_endian(block + 2, 6, r[1]);
    kryptos_cpy_u16_as_big_endian(block + 4, 4, r[2]);
    kryptos_cpy_u16_as_big_endian(block + 6, 2, r[3]);

    memset(r, 0, sizeof(r));
    ri = 0;
}

static void kryptos_rc2_block_decrypt(kryptos_u8_t *block, const struct kryptos_rc2_subkeys *sks) {
    size_t ri;
    kryptos_u16_t r[4];

    r[0] = kryptos_get_u16_as_big_endian(block, 2);
    r[1] = kryptos_get_u16_as_big_endian(block + 2, 2);
    r[2] = kryptos_get_u16_as_big_endian(block + 4, 2);
    r[3] = kryptos_get_u16_as_big_endian(block + 6, 2);

    ri = 63;

    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);

    kryptos_rc2_rmashinground(r, sks->K);

    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);

    kryptos_rc2_rmashinground(r, sks->K);

    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);
    kryptos_rc2_rmixinground(r, sks->K, ri);

    kryptos_cpy_u16_as_big_endian(block, 8, r[0]);
    kryptos_cpy_u16_as_big_endian(block + 2, 6, r[1]);
    kryptos_cpy_u16_as_big_endian(block + 4, 4, r[2]);
    kryptos_cpy_u16_as_big_endian(block + 6, 2, r[3]);

    memset(r, 0L, sizeof(r));
    ri = 0;
}

#undef kryptos_rc2_get_byte

#undef kryptos_rc2_rol

#undef kryptos_rc2_rollevel

#undef kryptos_rc2_mixupr

#undef kryptos_rc2_mashr

#undef kryptos_rc2_mixinground

#undef kryptos_rc2_mashinground

#undef kryptos_rc2_ror

#undef kryptos_rc2_rmixupr

#undef kryptos_rc2_rmashr

#undef kryptos_rc2_rmixinground

#undef kryptos_rc2_rmashinground
