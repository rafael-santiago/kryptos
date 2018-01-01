/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_misty1.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>

// INFO(Rafael): MISTY1's transformation functions. Maybe the modulus 8 could be
//               changed for a more efficient way of calculating it. However,
//               by now, we will use it.

#define kryptos_misty1_FI(i, k, d7, d9) (\
    (d9) = ((i) >> 7) & 0x1FF,\
    (d7) = (i) & 0x7F,\
    (d9) = kryptos_misty1_S9[(d9)] ^ d7,\
    (d7) = (kryptos_misty1_S7[(d7)] ^ d9) & 0x7F,\
    (d7) = (d7) ^ ((k) >> 9),\
    (d9) = (d9) ^ ((k) & 0x1FF),\
    (d9) = kryptos_misty1_S9[(d9)] ^ (d7),\
    ((d7 << 9) | (d9)) )

#define kryptos_misty1_FO(i, k, sks, t0, t1, d7, d9) (\
    (t0) = (i)  >> 16,\
    (t1) = (i) & 0xFFFF,\
    (t0) = (t0) ^ (sks)->EK[(k)],\
    (t0) = kryptos_misty1_FI(t0, (sks)->EK[(( (k) + 5 ) % 8) + 8], d7, d9),\
    (t0) = (t0) ^ (t1),\
    (t1) = (t1) ^ (sks)->EK[( (k) + 2 ) % 8],\
    (t1) = kryptos_misty1_FI(t1, (sks)->EK[(( (k) + 1 ) % 8) + 8], d7, d9),\
    (t1) = (t1) ^ (t0),\
    (t0) = (t0) ^ (sks)->EK[( (k) + 7 ) % 8],\
    (t0) = kryptos_misty1_FI(t0, (sks)->EK[(((k) + 3) % 8) + 8], d7, d9),\
    (t0) = (t0) ^ (t1),\
    (t1) = (t1) ^ (sks)->EK[( (k) + 4 ) % 8],\
    ( (((kryptos_u32_t)(t1)) << 16) | (t0) ) )

#define kryptos_misty1_FL(i, k, sks, d0, d1) (\
    (d0) = (i) >> 16,\
    (d1) = (i) & 0xFFFF,\
    (d1) = (( (k) & 1 ) == 0) ? (d1) ^ ((d0) & (sks)->EK[(k) >> 1])\
                              : (d1) ^ ((d0) & (sks)->EK[(((((k) - 1) >> 1) + 2) % 8) + 8]),\
    (d0) = (( (k) & 1 ) == 0) ? (d0) ^ ((d1) | (sks)->EK[((((k) >> 1) + 6) % 8) + 8])\
                              : (d0) ^ ((d1) | (sks)->EK[((((k) - 1) >> 1) + 4) % 8]),\
    ( (((kryptos_u32_t)(d0)) << 16) | (d1) ) )

#define kryptos_misty1_FL_1(i, k, sks, d0, d1) (\
    (d0) = (i) >> 16,\
    (d1) = (i) & 0xFFFF,\
    (d0) = (( (k) & 1 ) == 0) ? (d0) ^ ((d1) | (sks)->EK[((((k) >> 1) + 6) % 8) + 8])\
                              : (d0) ^ ((d1) | (sks)->EK[((((k) - 1) >> 1) + 4) % 8]),\
    (d1) = (( (k) & 1 ) == 0) ? (d1) ^ ((d0) & (sks)->EK[(k) >> 1])\
                              : (d1) ^ ((d0) & (sks)->EK[(((((k) - 1) >> 1) + 2) % 8) + 8]),\
    ( (((kryptos_u32_t)(d0)) << 16) | (d1) ) )

// INFO(Rafael): The 7 and 9-bit sboxes, respectivelly.

static kryptos_u8_t kryptos_misty1_S7[128] = {
    0x1B, 0x32, 0x33, 0x5A, 0x3B, 0x10, 0x17, 0x54, 0x5B, 0x1A, 0x72, 0x73, 0x6B, 0x2C, 0x66, 0x49,
    0x1F, 0x24, 0x13, 0x6C, 0x37, 0x2E, 0x3F, 0x4A, 0x5D, 0x0F, 0x40, 0x56, 0x25, 0x51, 0x1C, 0x04,
    0x0B, 0x46, 0x20, 0x0D, 0x7B, 0x35, 0x44, 0x42, 0x2B, 0x1E, 0x41, 0x14, 0x4B, 0x79, 0x15, 0x6F,
    0x0E, 0x55, 0x09, 0x36, 0x74, 0x0C, 0x67, 0x53, 0x28, 0x0A, 0x7E, 0x38, 0x02, 0x07, 0x60, 0x29,
    0x19, 0x12, 0x65, 0x2F, 0x30, 0x39, 0x08, 0x68, 0x5F, 0x78, 0x2A, 0x4C, 0x64, 0x45, 0x75, 0x3D,
    0x59, 0x48, 0x03, 0x57, 0x7C, 0x4F, 0x62, 0x3C, 0x1D, 0x21, 0x5E, 0x27, 0x6A, 0x70, 0x4D, 0x3A,
    0x01, 0x6D, 0x6E, 0x63, 0x18, 0x77, 0x23, 0x05, 0x26, 0x76, 0x00, 0x31, 0x2D, 0x7A, 0x7F, 0x61,
    0x50, 0x22, 0x11, 0x06, 0x47, 0x16, 0x52, 0x4E, 0x71, 0x3E, 0x69, 0x43, 0x34, 0x5C, 0x58, 0x7D };

static kryptos_u16_t kryptos_misty1_S9[512] = {
    0x1C3, 0x0CB, 0x153, 0x19F, 0x1E3, 0x0E9, 0x0FB, 0x035, 0x181, 0x0B9, 0x117, 0x1EB, 0x133, 0x009, 0x02D, 0x0D3,
    0x0C7, 0x14A, 0x037, 0x07E, 0x0EB, 0x164, 0x193, 0x1D8, 0x0A3, 0x11E, 0x055, 0x02C, 0x01D, 0x1A2, 0x163, 0x118,
    0x14B, 0x152, 0x1D2, 0x00F, 0x02B, 0x030, 0x13A, 0x0E5, 0x111, 0x138, 0x18E, 0x063, 0x0E3, 0x0C8, 0x1F4, 0x01B,
    0x001, 0x09D, 0x0F8, 0x1A0, 0x16D, 0x1F3, 0x01C, 0x146, 0x07D, 0x0D1, 0x082, 0x1EA, 0x183, 0x12D, 0x0F4, 0x19E,
    0x1D3, 0x0DD, 0x1E2, 0x128, 0x1E0, 0x0EC, 0x059, 0x091, 0x011, 0x12F, 0x026, 0x0DC, 0x0B0, 0x18C, 0x10F, 0x1F7,
    0x0E7, 0x16C, 0x0B6, 0x0F9, 0x0D8, 0x151, 0x101, 0x14C, 0x103, 0x0B8, 0x154, 0x12B, 0x1AE, 0x017, 0x071, 0x00C,
    0x047, 0x058, 0x07F, 0x1A4, 0x134, 0x129, 0x084, 0x15D, 0x19D, 0x1B2, 0x1A3, 0x048, 0x07C, 0x051, 0x1CA, 0x023,
    0x13D, 0x1A7, 0x165, 0x03B, 0x042, 0x0DA, 0x192, 0x0CE, 0x0C1, 0x06B, 0x09F, 0x1F1, 0x12C, 0x184, 0x0FA, 0x196,
    0x1E1, 0x169, 0x17D, 0x031, 0x180, 0x10A, 0x094, 0x1DA, 0x186, 0x13E, 0x11C, 0x060, 0x175, 0x1CF, 0x067, 0x119,
    0x065, 0x068, 0x099, 0x150, 0x008, 0x007, 0x17C, 0x0B7, 0x024, 0x019, 0x0DE, 0x127, 0x0DB, 0x0E4, 0x1A9, 0x052,
    0x109, 0x090, 0x19C, 0x1C1, 0x028, 0x1B3, 0x135, 0x16A, 0x176, 0x0DF, 0x1E5, 0x188, 0x0C5, 0x16E, 0x1DE, 0x1B1,
    0x0C3, 0x1DF, 0x036, 0x0EE, 0x1EE, 0x0F0, 0x093, 0x049, 0x09A, 0x1B6, 0x069, 0x081, 0x125, 0x00B, 0x05E, 0x0B4,
    0x149, 0x1C7, 0x174, 0x03E, 0x13B, 0x1B7, 0x08E, 0x1C6, 0x0AE, 0x010, 0x095, 0x1EF, 0x04E, 0x0F2, 0x1FD, 0x085,
    0x0FD, 0x0F6, 0x0A0, 0x16F, 0x083, 0x08A, 0x156, 0x09B, 0x13C, 0x107, 0x167, 0x098, 0x1D0, 0x1E9, 0x003, 0x1FE,
    0x0BD, 0x122, 0x089, 0x0D2, 0x18F, 0x012, 0x033, 0x06A, 0x142, 0x0ED, 0x170, 0x11B, 0x0E2, 0x14F, 0x158, 0x131,
    0x147, 0x05D, 0x113, 0x1CD, 0x079, 0x161, 0x1A5, 0x179, 0x09E, 0x1B4, 0x0CC, 0x022, 0x132, 0x01A, 0x0E8, 0x004,
    0x187, 0x1ED, 0x197, 0x039, 0x1BF, 0x1D7, 0x027, 0x18B, 0x0C6, 0x09C, 0x0D0, 0x14E, 0x06C, 0x034, 0x1F2, 0x06E,
    0x0CA, 0x025, 0x0BA, 0x191, 0x0FE, 0x013, 0x106, 0x02F, 0x1AD, 0x172, 0x1DB, 0x0C0, 0x10B, 0x1D6, 0x0F5, 0x1EC,
    0x10D, 0x076, 0x114, 0x1AB, 0x075, 0x10C, 0x1E4, 0x159, 0x054, 0x11F, 0x04B, 0x0C4, 0x1BE, 0x0F7, 0x029, 0x0A4,
    0x00E, 0x1F0, 0x077, 0x04D, 0x17A, 0x086, 0x08B, 0x0B3, 0x171, 0x0BF, 0x10E, 0x104, 0x097, 0x15B, 0x160, 0x168,
    0x0D7, 0x0BB, 0x066, 0x1CE, 0x0FC, 0x092, 0x1C5, 0x06F, 0x016, 0x04A, 0x0A1, 0x139, 0x0AF, 0x0F1, 0x190, 0x00A,
    0x1AA, 0x143, 0x17B, 0x056, 0x18D, 0x166, 0x0D4, 0x1FB, 0x14D, 0x194, 0x19A, 0x087, 0x1F8, 0x123, 0x0A7, 0x1B8,
    0x141, 0x03C, 0x1F9, 0x140, 0x02A, 0x155, 0x11A, 0x1A1, 0x198, 0x0D5, 0x126, 0x1AF, 0x061, 0x12E, 0x157, 0x1DC,
    0x072, 0x18A, 0x0AA, 0x096, 0x115, 0x0EF, 0x045, 0x07B, 0x08D, 0x145, 0x053, 0x05F, 0x178, 0x0B2, 0x02E, 0x020,
    0x1D5, 0x03F, 0x1C9, 0x1E7, 0x1AC, 0x044, 0x038, 0x014, 0x0B1, 0x16B, 0x0AB, 0x0B5, 0x05A, 0x182, 0x1C8, 0x1D4,
    0x018, 0x177, 0x064, 0x0CF, 0x06D, 0x100, 0x199, 0x130, 0x15A, 0x005, 0x120, 0x1BB, 0x1BD, 0x0E0, 0x04F, 0x0D6,
    0x13F, 0x1C4, 0x12A, 0x015, 0x006, 0x0FF, 0x19B, 0x0A6, 0x043, 0x088, 0x050, 0x15F, 0x1E8, 0x121, 0x073, 0x17E,
    0x0BC, 0x0C2, 0x0C9, 0x173, 0x189, 0x1F5, 0x074, 0x1CC, 0x1E6, 0x1A8, 0x195, 0x01F, 0x041, 0x00D, 0x1BA, 0x032,
    0x03D, 0x1D1, 0x080, 0x0A8, 0x057, 0x1B9, 0x162, 0x148, 0x0D9, 0x105, 0x062, 0x07A, 0x021, 0x1FF, 0x112, 0x108,
    0x1C0, 0x0A9, 0x11D, 0x1B0, 0x1A6, 0x0CD, 0x0F3, 0x05C, 0x102, 0x05B, 0x1D9, 0x144, 0x1F6, 0x0AD, 0x0A5, 0x03A,
    0x1CB, 0x136, 0x17F, 0x046, 0x0E1, 0x01E, 0x1DD, 0x0E6, 0x137, 0x1FA, 0x185, 0x08C, 0x08F, 0x040, 0x1B5, 0x0BE,
    0x078, 0x000, 0x0AC, 0x110, 0x15E, 0x124, 0x002, 0x1BC, 0x0A2, 0x0EA, 0x070, 0x1FC, 0x116, 0x15C, 0x04C, 0x1C2 };

// WARN(Rafael): Total of sub-keys, since this implementation assumes eight fixed rounds.
#define KRYPTOS_MISTY1_SKEYS_NR 32

struct kryptos_misty1_subkeys {
    kryptos_u16_t EK[KRYPTOS_MISTY1_SKEYS_NR];
};

typedef void (*kryptos_misty1_block_processor)(kryptos_u8_t *block, const struct kryptos_misty1_subkeys *sks);

static void kryptos_misty1_ld_user_key(kryptos_u16_t *key, const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_misty1_sched_skeys(const kryptos_u8_t *key, const size_t key_size, struct kryptos_misty1_subkeys *sks);

static void kryptos_misty1_block_encrypt(kryptos_u8_t *block, const struct kryptos_misty1_subkeys *sks);

static void kryptos_misty1_block_decrypt(kryptos_u8_t *block, const struct kryptos_misty1_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(misty1, kKryptosCipherMISTY1, KRYPTOS_MISTY1_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(misty1,
                                    ktask,
                                    kryptos_misty1_subkeys,
                                    sks,
                                    kryptos_misty1_block_processor,
                                    misty1_block_processor,
                                    kryptos_misty1_sched_skeys((*ktask)->key, (*ktask)->key_size, &sks),
                                    kryptos_misty1_block_encrypt, /* No additional steps for encrypting */,
                                    kryptos_misty1_block_decrypt, /* No additional steps for decrypting */,
                                    KRYPTOS_MISTY1_BLOCKSIZE,
                                    misty1_cipher_epilogue,
                                    outblock,
                                    misty1_block_processor(outblock, &sks))

static void kryptos_misty1_ld_user_key(kryptos_u16_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;

    kryptos_ld_user_key_prologue(key, 8, user_key, user_key_size, kp, kp_end, w, b, return);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_misty1_ld_user_key_epilogue);
    kryptos_ld_user_key_epilogue(kryptos_misty1_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_misty1_sched_skeys(const kryptos_u8_t *key, const size_t key_size, struct kryptos_misty1_subkeys *sks) {
    kryptos_u8_t d7;
    kryptos_u16_t d9;

    kryptos_misty1_ld_user_key(sks->EK, key, key_size);

#define kryptos_misty1_sched_sk_chunk(i, sks, d7, d9) {\
    (sks)->EK[(i) +  8] = kryptos_misty1_FI((sks)->EK[(i)], (sks)->EK[((i) + 1) % 8], d7, d9);\
    (sks)->EK[(i) + 16] = (sks)->EK[(i) + 8] & 0x1FF;\
    (sks)->EK[(i) + 24] = (sks)->EK[(i) + 8] >> 9;\
}

    kryptos_misty1_sched_sk_chunk(0, sks, d7, d9);
    kryptos_misty1_sched_sk_chunk(1, sks, d7, d9);
    kryptos_misty1_sched_sk_chunk(2, sks, d7, d9);
    kryptos_misty1_sched_sk_chunk(3, sks, d7, d9);
    kryptos_misty1_sched_sk_chunk(4, sks, d7, d9);
    kryptos_misty1_sched_sk_chunk(5, sks, d7, d9);
    kryptos_misty1_sched_sk_chunk(6, sks, d7, d9);
    kryptos_misty1_sched_sk_chunk(7, sks, d7, d9);

#undef kryptos_misty1_sched_sk_chunk

    d7 = d9 = 0;
}

static void kryptos_misty1_block_encrypt(kryptos_u8_t *block, const struct kryptos_misty1_subkeys *sks) {
    kryptos_u8_t d7;
    kryptos_u16_t d9, t0, t1, d0, d1;
    kryptos_u32_t D0, D1;

    D0 = kryptos_get_u32_as_big_endian(block, 4);
    D1 = kryptos_get_u32_as_big_endian(block + 4, 4);

    // 0 round:
    D0 = kryptos_misty1_FL(D0, 0, sks, d0, d1);
    D1 = kryptos_misty1_FL(D1, 1, sks, d0, d1);
    D1 ^= kryptos_misty1_FO(D0, 0, sks, t0, t1, d7, d9);

    // 1 round:
    D0 ^= kryptos_misty1_FO(D1, 1, sks, t0, t1, d7, d9);

    // 2 round:
    D0 = kryptos_misty1_FL(D0, 2, sks, d0, d1);
    D1 = kryptos_misty1_FL(D1, 3, sks, d0, d1);
    D1 ^= kryptos_misty1_FO(D0, 2, sks, t0, t1, d7, d9);

    // 3 round:
    D0 ^= kryptos_misty1_FO(D1, 3, sks, t0, t1, d7, d9);

    // 4 round:
    D0 = kryptos_misty1_FL(D0, 4, sks, d0, d1);
    D1 = kryptos_misty1_FL(D1, 5, sks, d0, d1);
    D1 ^= kryptos_misty1_FO(D0, 4, sks, t0, t1, d7, d9);

    // 5 round:
    D0 ^= kryptos_misty1_FO(D1, 5, sks, t0, t1, d7, d9);

    // 6 round:
    D0 = kryptos_misty1_FL(D0, 6, sks, d0, d1);
    D1 = kryptos_misty1_FL(D1, 7, sks, d0, d1);
    D1 ^= kryptos_misty1_FO(D0, 6, sks, t0, t1, d7, d9);

    // 7 round:
    D0 ^= kryptos_misty1_FO(D1, 7, sks, t0, t1, d7, d9);

    // Final round:
    D0 = kryptos_misty1_FL(D0, 8, sks, d0, d1);
    D1 = kryptos_misty1_FL(D1, 9, sks, d0, d1);

    kryptos_cpy_u32_as_big_endian(block, 8, D1);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, D0);

    d7 = d9 = 0;
    t0 = t1 = d0 = d1 = 0;
}

static void kryptos_misty1_block_decrypt(kryptos_u8_t *block, const struct kryptos_misty1_subkeys *sks) {
    kryptos_u8_t d7;
    kryptos_u16_t d9, t0, t1, d0, d1;
    kryptos_u32_t D0, D1;

    D1 = kryptos_get_u32_as_big_endian(block, 4);
    D0 = kryptos_get_u32_as_big_endian(block + 4, 4);

    // reversing final round:
    D0 = kryptos_misty1_FL_1(D0, 8, sks, d0, d1);
    D1 = kryptos_misty1_FL_1(D1, 9, sks, d0, d1);

    // reversing 7 round:
    D0 ^= kryptos_misty1_FO(D1, 7, sks, t0, t1, d7, d9);

    // reversing 6 round:
    D1 ^= kryptos_misty1_FO(D0, 6, sks, t0, t1, d7, d9);
    D0 = kryptos_misty1_FL_1(D0, 6, sks, d0, d1);
    D1 = kryptos_misty1_FL_1(D1, 7, sks, d0, d1);

    // reversing 5 round:
    D0 ^= kryptos_misty1_FO(D1, 5, sks, t0, t1, d7, d9);

    // reversing 4 round:
    D1 ^= kryptos_misty1_FO(D0, 4, sks, t0, t1, d7, d9);
    D0 = kryptos_misty1_FL_1(D0, 4, sks, d0, d1);
    D1 = kryptos_misty1_FL_1(D1, 5, sks, d0, d1);

    // reversing 3 round:
    D0 ^= kryptos_misty1_FO(D1, 3, sks, t0, t1, d7, d9);

    // reversing 2 round:
    D1 ^= kryptos_misty1_FO(D0, 2, sks, t0, t1, d7, d9);
    D0 = kryptos_misty1_FL_1(D0, 2, sks, d0, d1);
    D1 = kryptos_misty1_FL_1(D1, 3, sks, d0, d1);

    // reversing 1 round:
    D0 ^= kryptos_misty1_FO(D1, 1, sks, t0, t1, d7, d9);

    // reversing 0 round:
    D1 ^= kryptos_misty1_FO(D0, 0, sks, t0, t1, d7, d9);
    D0 = kryptos_misty1_FL_1(D0, 0, sks, d0, d1);
    D1 = kryptos_misty1_FL_1(D1, 1, sks, d0, d1);

    kryptos_cpy_u32_as_big_endian(block, 8, D0);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, D1);

    d7 = d9 = 0;
    t0 = t1 = d0 = d1 = 0;
}

#undef KRYPTOS_MISTY1_SKEYS_NR

#undef kryptos_misty1_FI

#undef kryptos_misty1_FO

#undef kryptos_misty1_FL

#undef kryptos_misty1_FL_1
