/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_salsa20_core.h>
#include <kryptos.h>

// INFO(Rafael): Salsa-20 functions.

#define kryptos_salsa20_rotl(u, c) ( ((kryptos_u32_t)(u) << (c)) | ((u) >> ((sizeof(kryptos_u32_t) << 3) - (c))) )

#define kryptos_salsa20_quarterround(y0, y1, y2, y3) {\
    y1 ^= kryptos_salsa20_rotl(y0 + y3, 7);\
    y2 ^= kryptos_salsa20_rotl(y1 + y0, 9);\
    y3 ^= kryptos_salsa20_rotl(y2 + y1, 13);\
    y0 ^= kryptos_salsa20_rotl(y3 + y2, 18);\
}

#define kryptos_salsa20_rowround(y) {\
    kryptos_salsa20_quarterround(y[ 0], y[ 1], y[ 2], y[ 3]);\
    kryptos_salsa20_quarterround(y[ 5], y[ 6], y[ 7], y[ 4]);\
    kryptos_salsa20_quarterround(y[10], y[11], y[ 8], y[ 9]);\
    kryptos_salsa20_quarterround(y[15], y[12], y[13], y[14]);\
}

#define kryptos_salsa20_columnround(x) {\
    kryptos_salsa20_quarterround(x[ 0], x[ 4], x[ 8], x[12]);\
    kryptos_salsa20_quarterround(x[ 5], x[ 9], x[13], x[ 1]);\
    kryptos_salsa20_quarterround(x[10], x[14], x[ 2], x[ 6]);\
    kryptos_salsa20_quarterround(x[15], x[ 3], x[ 7], x[11]);\
}

#define kryptos_salsa20_doubleround(x) {\
    kryptos_salsa20_columnround(x);\
    kryptos_salsa20_rowround(x);\
}

#define kryptos_salsa20_littleendian(w) ( (((kryptos_u32_t)(w)) << 24) |\
                                          (((kryptos_u32_t)(w) & 0x0000FF00) << 8) |\
                                          (((kryptos_u32_t)(w) & 0x00FF0000) >> 8) |\
                                          (((kryptos_u32_t)(w)) >> 24) )

#define kryptos_salsa20_ld_u32(x) ( (((kryptos_u32_t)(x)[0]) << 24) |\
                                    (((kryptos_u32_t)(x)[1]) << 16) |\
                                    (((kryptos_u32_t)(x)[2]) <<  8) |\
                                    (((kryptos_u32_t)(x)[3])) )

int kryptos_salsa20_H(kryptos_u8_t *x, const size_t x_size) {
    // INFO(Rafael): Let's keep unrolled loops. This algorithm structure is well-simple and
    //               ready to go. There is no necessity of using repetition structures here.

    kryptos_u32_t xregs[2][16];

    memset(xregs, 0, sizeof(xregs));

    if (x == NULL || x_size != 64) {
        return 0;
    }

    // INFO(Rafael): We start applying littleendian() over all 32-bit sub-sets from the input buffer.

    xregs[0][ 0] = xregs[1][ 0] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[ 0]));
    xregs[0][ 1] = xregs[1][ 1] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[ 4]));
    xregs[0][ 2] = xregs[1][ 2] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[ 8]));
    xregs[0][ 3] = xregs[1][ 3] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[12]));
    xregs[0][ 4] = xregs[1][ 4] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[16]));
    xregs[0][ 5] = xregs[1][ 5] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[20]));
    xregs[0][ 6] = xregs[1][ 6] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[24]));
    xregs[0][ 7] = xregs[1][ 7] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[28]));
    xregs[0][ 8] = xregs[1][ 8] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[32]));
    xregs[0][ 9] = xregs[1][ 9] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[36]));
    xregs[0][10] = xregs[1][10] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[40]));
    xregs[0][11] = xregs[1][11] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[44]));
    xregs[0][12] = xregs[1][12] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[48]));
    xregs[0][13] = xregs[1][13] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[52]));
    xregs[0][14] = xregs[1][14] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[56]));
    xregs[0][15] = xregs[1][15] = kryptos_salsa20_littleendian(kryptos_salsa20_ld_u32(&x[60]));

    // INFO(Rafael): So, 10 double iterations...

    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);
    kryptos_salsa20_doubleround(xregs[0]);

    // INFO(Rafael): ...now x + doubleround^10...

    xregs[0][ 0] += xregs[1][ 0];
    xregs[0][ 1] += xregs[1][ 1];
    xregs[0][ 2] += xregs[1][ 2];
    xregs[0][ 3] += xregs[1][ 3];
    xregs[0][ 4] += xregs[1][ 4];
    xregs[0][ 5] += xregs[1][ 5];
    xregs[0][ 6] += xregs[1][ 6];
    xregs[0][ 7] += xregs[1][ 7];
    xregs[0][ 8] += xregs[1][ 8];
    xregs[0][ 9] += xregs[1][ 9];
    xregs[0][10] += xregs[1][10];
    xregs[0][11] += xregs[1][11];
    xregs[0][12] += xregs[1][12];
    xregs[0][13] += xregs[1][13];
    xregs[0][14] += xregs[1][14];
    xregs[0][15] += xregs[1][15];

    // INFO(Rafael): Finally, we applying littleendian-1.
    xregs[0][ 0] = kryptos_salsa20_littleendian(xregs[0][ 0]);
    xregs[0][ 1] = kryptos_salsa20_littleendian(xregs[0][ 1]);
    xregs[0][ 2] = kryptos_salsa20_littleendian(xregs[0][ 2]);
    xregs[0][ 3] = kryptos_salsa20_littleendian(xregs[0][ 3]);
    xregs[0][ 4] = kryptos_salsa20_littleendian(xregs[0][ 4]);
    xregs[0][ 5] = kryptos_salsa20_littleendian(xregs[0][ 5]);
    xregs[0][ 6] = kryptos_salsa20_littleendian(xregs[0][ 6]);
    xregs[0][ 7] = kryptos_salsa20_littleendian(xregs[0][ 7]);
    xregs[0][ 8] = kryptos_salsa20_littleendian(xregs[0][ 8]);
    xregs[0][ 9] = kryptos_salsa20_littleendian(xregs[0][ 9]);
    xregs[0][10] = kryptos_salsa20_littleendian(xregs[0][10]);
    xregs[0][11] = kryptos_salsa20_littleendian(xregs[0][11]);
    xregs[0][12] = kryptos_salsa20_littleendian(xregs[0][12]);
    xregs[0][13] = kryptos_salsa20_littleendian(xregs[0][13]);
    xregs[0][14] = kryptos_salsa20_littleendian(xregs[0][14]);
    xregs[0][15] = kryptos_salsa20_littleendian(xregs[0][15]);

    x[ 0] = (xregs[ 0][ 0] >> 24) & 0xFF;
    x[ 1] = (xregs[ 0][ 0] >> 16) & 0xFF;
    x[ 2] = (xregs[ 0][ 0] >>  8) & 0xFF;
    x[ 3] = xregs[ 0][ 0] & 0xFF;
    x[ 4] = (xregs[ 0][ 1] >> 24) & 0xFF;
    x[ 5] = (xregs[ 0][ 1] >> 16) & 0xFF;
    x[ 6] = (xregs[ 0][ 1] >>  8) & 0xFF;
    x[ 7] = xregs[ 0][ 1] & 0xFF;
    x[ 8] = (xregs[ 0][ 2] >> 24) & 0xFF;
    x[ 9] = (xregs[ 0][ 2] >> 16) & 0xFF;
    x[10] = (xregs[ 0][ 2] >>  8) & 0xFF;
    x[11] = xregs[ 0][ 2] & 0xFF;
    x[12] = (xregs[ 0][ 3] >> 24) & 0xFF;
    x[13] = (xregs[ 0][ 3] >> 16) & 0xFF;
    x[14] = (xregs[ 0][ 3] >>  8) & 0xFF;
    x[15] = xregs[ 0][ 3] & 0xFF;
    x[16] = (xregs[ 0][ 4] >> 24) & 0xFF;
    x[17] = (xregs[ 0][ 4] >> 16) & 0xFF;
    x[18] = (xregs[ 0][ 4] >>  8) & 0xFF;
    x[19] = xregs[ 0][ 4] & 0xFF;
    x[20] = (xregs[ 0][ 5] >> 24) & 0xFF;
    x[21] = (xregs[ 0][ 5] >> 16) & 0xFF;
    x[22] = (xregs[ 0][ 5] >>  8) & 0xFF;
    x[23] = xregs[ 0][ 5] & 0xFF;
    x[24] = (xregs[ 0][ 6] >> 24) & 0xFF;
    x[25] = (xregs[ 0][ 6] >> 16) & 0xFF;
    x[26] = (xregs[ 0][ 6] >>  8) & 0xFF;
    x[27] = xregs[ 0][ 6] & 0xFF;
    x[28] = (xregs[ 0][ 7] >> 24) & 0xFF;
    x[29] = (xregs[ 0][ 7] >> 16) & 0xFF;
    x[30] = (xregs[ 0][ 7] >>  8) & 0xFF;
    x[31] = xregs[ 0][ 7] & 0xFF;
    x[32] = (xregs[ 0][ 8] >> 24) & 0xFF;
    x[33] = (xregs[ 0][ 8] >> 16) & 0xFF;
    x[34] = (xregs[ 0][ 8] >>  8) & 0xFF;
    x[35] = xregs[ 0][ 8] & 0xFF;
    x[36] = (xregs[ 0][ 9] >> 24) & 0xFF;
    x[37] = (xregs[ 0][ 9] >> 16) & 0xFF;
    x[38] = (xregs[ 0][ 9] >>  8) & 0xFF;
    x[39] = xregs[ 0][ 9] & 0xFF;
    x[40] = (xregs[ 0][10] >> 24) & 0xFF;
    x[41] = (xregs[ 0][10] >> 16) & 0xFF;
    x[42] = (xregs[ 0][10] >>  8) & 0xFF;
    x[43] = xregs[ 0][10] & 0xFF;
    x[44] = (xregs[ 0][11] >> 24) & 0xFF;
    x[45] = (xregs[ 0][11] >> 16) & 0xFF;
    x[46] = (xregs[ 0][11] >>  8) & 0xFF;
    x[47] = xregs[ 0][11] & 0xFF;
    x[48] = (xregs[ 0][12] >> 24) & 0xFF;
    x[49] = (xregs[ 0][12] >> 16) & 0xFF;
    x[50] = (xregs[ 0][12] >>  8) & 0xFF;
    x[51] = xregs[ 0][12] & 0xFF;
    x[52] = (xregs[ 0][13] >> 24) & 0xFF;
    x[53] = (xregs[ 0][13] >> 16) & 0xFF;
    x[54] = (xregs[ 0][13] >>  8) & 0xFF;
    x[55] = xregs[ 0][13] & 0xFF;
    x[56] = (xregs[ 0][14] >> 24) & 0xFF;
    x[57] = (xregs[ 0][14] >> 16) & 0xFF;
    x[58] = (xregs[ 0][14] >>  8) & 0xFF;
    x[59] = xregs[ 0][14] & 0xFF;
    x[60] = (xregs[ 0][15] >> 24) & 0xFF;
    x[61] = (xregs[ 0][15] >> 16) & 0xFF;
    x[62] = (xregs[ 0][15] >>  8) & 0xFF;
    x[63] = xregs[ 0][15] & 0xFF;

    memset(xregs, 0, sizeof(xregs));

    return 1;
}

int kryptos_chacha20_H(kryptos_u8_t *x, const size_t x_size) {
    kryptos_u32_t xregs[2][16];

    memset(xregs, 0, sizeof(xregs));

    if (x == NULL || x_size != 64) {
        // INFO(Rafael): It should never happen in normal conditions.
        return 0;
    }

    // INFO(Rafael): ...

    xregs[0][ 0] = xregs[1][ 0] = kryptos_salsa20_ld_u32(&x[ 0]);
    xregs[0][ 1] = xregs[1][ 1] = kryptos_salsa20_ld_u32(&x[ 4]);
    xregs[0][ 2] = xregs[1][ 2] = kryptos_salsa20_ld_u32(&x[ 8]);
    xregs[0][ 3] = xregs[1][ 3] = kryptos_salsa20_ld_u32(&x[12]);
    xregs[0][ 4] = xregs[1][ 4] = kryptos_salsa20_ld_u32(&x[16]);
    xregs[0][ 5] = xregs[1][ 5] = kryptos_salsa20_ld_u32(&x[20]);
    xregs[0][ 6] = xregs[1][ 6] = kryptos_salsa20_ld_u32(&x[24]);
    xregs[0][ 7] = xregs[1][ 7] = kryptos_salsa20_ld_u32(&x[28]);
    xregs[0][ 8] = xregs[1][ 8] = kryptos_salsa20_ld_u32(&x[32]);
    xregs[0][ 9] = xregs[1][ 9] = kryptos_salsa20_ld_u32(&x[36]);
    xregs[0][10] = xregs[1][10] = kryptos_salsa20_ld_u32(&x[40]);
    xregs[0][11] = xregs[1][11] = kryptos_salsa20_ld_u32(&x[44]);
    xregs[0][12] = xregs[1][12] = kryptos_salsa20_ld_u32(&x[48]);
    xregs[0][13] = xregs[1][13] = kryptos_salsa20_ld_u32(&x[52]);
    xregs[0][14] = xregs[1][14] = kryptos_salsa20_ld_u32(&x[56]);
    xregs[0][15] = xregs[1][15] = kryptos_salsa20_ld_u32(&x[60]);

#define kryptos_chacha20_quarterround(a, b, c, d) {\
    (a) += (b);\
    (d) ^= (a);\
    (d) = kryptos_salsa20_rotl(d, 16);\
    (c) += (d);\
    (b) ^= (c);\
    (b) = kryptos_salsa20_rotl(b, 12);\
    (a) += (b);\
    (d) ^= (a);\
    (d) = kryptos_salsa20_rotl(d, 8);\
    (c) += (d);\
    (b) ^= (c);\
    (b) = kryptos_salsa20_rotl(b, 7);\
}

#define kryptos_chacha20_cr(x) {\
    kryptos_chacha20_quarterround((x)[ 0], (x)[ 4], (x)[ 8], (x)[12]);\
    kryptos_chacha20_quarterround((x)[ 1], (x)[ 5], (x)[ 9], (x)[13]);\
    kryptos_chacha20_quarterround((x)[ 2], (x)[ 6], (x)[10], (x)[14]);\
    kryptos_chacha20_quarterround((x)[ 3], (x)[ 7], (x)[11], (x)[15]);\
}

#define kryptos_chacha20_dr(x) {\
    kryptos_chacha20_quarterround((x)[ 0], (x)[ 5], (x)[10], (x)[15]);\
    kryptos_chacha20_quarterround((x)[ 1], (x)[ 6], (x)[11], (x)[12]);\
    kryptos_chacha20_quarterround((x)[ 2], (x)[ 7], (x)[ 8], (x)[13]);\
    kryptos_chacha20_quarterround((x)[ 3], (x)[ 4], (x)[ 9], (x)[14]);\
}

    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);
    kryptos_chacha20_cr(xregs[0]);
    kryptos_chacha20_dr(xregs[0]);

#undef kryptos_chacha20_quarterround

#undef kryptos_chacha20_cr

#undef kryptos_chacha20_dr

    xregs[0][ 0] += xregs[1][ 0];
    xregs[0][ 1] += xregs[1][ 1];
    xregs[0][ 2] += xregs[1][ 2];
    xregs[0][ 3] += xregs[1][ 3];
    xregs[0][ 4] += xregs[1][ 4];
    xregs[0][ 5] += xregs[1][ 5];
    xregs[0][ 6] += xregs[1][ 6];
    xregs[0][ 7] += xregs[1][ 7];
    xregs[0][ 8] += xregs[1][ 8];
    xregs[0][ 9] += xregs[1][ 9];
    xregs[0][10] += xregs[1][10];
    xregs[0][11] += xregs[1][11];
    xregs[0][12] += xregs[1][12];
    xregs[0][13] += xregs[1][13];
    xregs[0][14] += xregs[1][14];
    xregs[0][15] += xregs[1][15];

    xregs[0][ 0] = kryptos_salsa20_littleendian(xregs[0][ 0]);
    xregs[0][ 1] = kryptos_salsa20_littleendian(xregs[0][ 1]);
    xregs[0][ 2] = kryptos_salsa20_littleendian(xregs[0][ 2]);
    xregs[0][ 3] = kryptos_salsa20_littleendian(xregs[0][ 3]);
    xregs[0][ 4] = kryptos_salsa20_littleendian(xregs[0][ 4]);
    xregs[0][ 5] = kryptos_salsa20_littleendian(xregs[0][ 5]);
    xregs[0][ 6] = kryptos_salsa20_littleendian(xregs[0][ 6]);
    xregs[0][ 7] = kryptos_salsa20_littleendian(xregs[0][ 7]);
    xregs[0][ 8] = kryptos_salsa20_littleendian(xregs[0][ 8]);
    xregs[0][ 9] = kryptos_salsa20_littleendian(xregs[0][ 9]);
    xregs[0][10] = kryptos_salsa20_littleendian(xregs[0][10]);
    xregs[0][11] = kryptos_salsa20_littleendian(xregs[0][11]);
    xregs[0][12] = kryptos_salsa20_littleendian(xregs[0][12]);
    xregs[0][13] = kryptos_salsa20_littleendian(xregs[0][13]);
    xregs[0][14] = kryptos_salsa20_littleendian(xregs[0][14]);
    xregs[0][15] = kryptos_salsa20_littleendian(xregs[0][15]);

    x[ 0] = (xregs[ 0][ 0] >> 24) & 0xFF;
    x[ 1] = (xregs[ 0][ 0] >> 16) & 0xFF;
    x[ 2] = (xregs[ 0][ 0] >>  8) & 0xFF;
    x[ 3] = xregs[ 0][ 0] & 0xFF;
    x[ 4] = (xregs[ 0][ 1] >> 24) & 0xFF;
    x[ 5] = (xregs[ 0][ 1] >> 16) & 0xFF;
    x[ 6] = (xregs[ 0][ 1] >>  8) & 0xFF;
    x[ 7] = xregs[ 0][ 1] & 0xFF;
    x[ 8] = (xregs[ 0][ 2] >> 24) & 0xFF;
    x[ 9] = (xregs[ 0][ 2] >> 16) & 0xFF;
    x[10] = (xregs[ 0][ 2] >>  8) & 0xFF;
    x[11] = xregs[ 0][ 2] & 0xFF;
    x[12] = (xregs[ 0][ 3] >> 24) & 0xFF;
    x[13] = (xregs[ 0][ 3] >> 16) & 0xFF;
    x[14] = (xregs[ 0][ 3] >>  8) & 0xFF;
    x[15] = xregs[ 0][ 3] & 0xFF;
    x[16] = (xregs[ 0][ 4] >> 24) & 0xFF;
    x[17] = (xregs[ 0][ 4] >> 16) & 0xFF;
    x[18] = (xregs[ 0][ 4] >>  8) & 0xFF;
    x[19] = xregs[ 0][ 4] & 0xFF;
    x[20] = (xregs[ 0][ 5] >> 24) & 0xFF;
    x[21] = (xregs[ 0][ 5] >> 16) & 0xFF;
    x[22] = (xregs[ 0][ 5] >>  8) & 0xFF;
    x[23] = xregs[ 0][ 5] & 0xFF;
    x[24] = (xregs[ 0][ 6] >> 24) & 0xFF;
    x[25] = (xregs[ 0][ 6] >> 16) & 0xFF;
    x[26] = (xregs[ 0][ 6] >>  8) & 0xFF;
    x[27] = xregs[ 0][ 6] & 0xFF;
    x[28] = (xregs[ 0][ 7] >> 24) & 0xFF;
    x[29] = (xregs[ 0][ 7] >> 16) & 0xFF;
    x[30] = (xregs[ 0][ 7] >>  8) & 0xFF;
    x[31] = xregs[ 0][ 7] & 0xFF;
    x[32] = (xregs[ 0][ 8] >> 24) & 0xFF;
    x[33] = (xregs[ 0][ 8] >> 16) & 0xFF;
    x[34] = (xregs[ 0][ 8] >>  8) & 0xFF;
    x[35] = xregs[ 0][ 8] & 0xFF;
    x[36] = (xregs[ 0][ 9] >> 24) & 0xFF;
    x[37] = (xregs[ 0][ 9] >> 16) & 0xFF;
    x[38] = (xregs[ 0][ 9] >>  8) & 0xFF;
    x[39] = xregs[ 0][ 9] & 0xFF;
    x[40] = (xregs[ 0][10] >> 24) & 0xFF;
    x[41] = (xregs[ 0][10] >> 16) & 0xFF;
    x[42] = (xregs[ 0][10] >>  8) & 0xFF;
    x[43] = xregs[ 0][10] & 0xFF;
    x[44] = (xregs[ 0][11] >> 24) & 0xFF;
    x[45] = (xregs[ 0][11] >> 16) & 0xFF;
    x[46] = (xregs[ 0][11] >>  8) & 0xFF;
    x[47] = xregs[ 0][11] & 0xFF;
    x[48] = (xregs[ 0][12] >> 24) & 0xFF;
    x[49] = (xregs[ 0][12] >> 16) & 0xFF;
    x[50] = (xregs[ 0][12] >>  8) & 0xFF;
    x[51] = xregs[ 0][12] & 0xFF;
    x[52] = (xregs[ 0][13] >> 24) & 0xFF;
    x[53] = (xregs[ 0][13] >> 16) & 0xFF;
    x[54] = (xregs[ 0][13] >>  8) & 0xFF;
    x[55] = xregs[ 0][13] & 0xFF;
    x[56] = (xregs[ 0][14] >> 24) & 0xFF;
    x[57] = (xregs[ 0][14] >> 16) & 0xFF;
    x[58] = (xregs[ 0][14] >>  8) & 0xFF;
    x[59] = xregs[ 0][14] & 0xFF;
    x[60] = (xregs[ 0][15] >> 24) & 0xFF;
    x[61] = (xregs[ 0][15] >> 16) & 0xFF;
    x[62] = (xregs[ 0][15] >>  8) & 0xFF;
    x[63] = xregs[ 0][15] & 0xFF;

    memset(xregs, 0, sizeof(xregs));

    return 1;
}

#undef kryptos_salsa20_ld_u32

#undef kryptos_salsa20_littleendian

#undef kryptos_salsa20_doubleround

#undef kryptos_salsa20_columnround

#undef kryptos_salsa20_rowround

#undef kryptos_salsa20_quarterround

#undef kryptos_salsa20_rotl
