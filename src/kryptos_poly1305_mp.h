/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_POLY1305_MP_H
#define KRYPTOS_KRYPTOS_POLY1305_MP_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// TIP(Rafael): The idea behind kryptos_poly1305_number_t is providing a self-contained multiprecision structure for
//              fitting up 128-bit math operations results without needing to allocate any memory, using only stack based
//              limbs.
//
//              Important:
//
//                      - On environments with support for 128-bit native type, kryptos_poly1305_number_t has
//                        seven 64-bit limbs. The macro KRYPTOS_MP_EXTENTED_RADIX is defined.
//
//                      - On enviroments without support for 128-bit native type, kryptos_poly1305_number_t has
//                        eleven 32-bit limbs (Windows with VS2019, for example).
//
//               Limbs are always stored from *** the least significant to the most significant *** number fraction:
//
//               Thus, 0xAABBCCDDEEFF00112233445566778899 has the following memory storage layout:
//
//                      [ 0] = 0xAABBCCDDEEFF0011,
//                      [ 1] = 0x2233445566778899,
//                      [ 2] = 0x0000000000000000,
//                      [ 3] = 0x0000000000000000,
//                      [ 4] = 0x0000000000000000,
//                      [ 5] = 0x0000000000000000,
//                      [ 6] = 0x0000000000000000 with KRYPTOS_MP_EXTENDED_RADIX, or without:
//
//                      [ 0] = 0xEEFF0011,
//                      [ 1] = 0xAABBCCDD,
//                      [ 2] = 0x66778899,
//                      [ 3] = 0x22334455,
//                      [ 4] = 0x00000000
//                      [ 5] = 0x00000000,
//                      [ 6] = 0x00000000,
//                      [ 7] = 0x00000000,
//                      [ 8] = 0x00000000,
//                      [ 9] = 0x00000000,
//                      [10] = 0x00000000 (so when reading from 10 down to 0 we will got the same from the extended radix
//                                         presented above, it seems up-side-down and clumsy but avoids a bunch of extra
//                                         work when consuming, operating over the value).
//

# if defined(KRYPTOS_MP_EXTENDED_RADIX)
#  include <inttypes.h>
    typedef kryptos_u64_t kryptos_poly1305_numfrac_t;
    // INFO(Rafael): 128-bits + 128-bits + 1. Since this tiny mp module is implemented thinking about 128-bit values
    //               and does not use allocations we need to make it prepared to fit all additions and multiplications
    //               results.
    typedef kryptos_poly1305_numfrac_t kryptos_poly1305_number_t[(3 << 1) + 1];
    typedef unsigned __int128 kryptos_poly1305_overflown_numfrac_t;
# define kKryptosPoly1305_128bit_NumberSize 2
# else
    typedef kryptos_u32_t kryptos_poly1305_numfrac_t;
    // INFO(Rafael): 128-bits + 128-bits + 1. Since this tiny mp module is implemented thinking about 128-bit values
    //               and does not use allocations we need to make it prepared to fit all additions and multiplications
    //               results.
    typedef kryptos_poly1305_numfrac_t kryptos_poly1305_number_t[(5 << 1) + 1];
    typedef kryptos_u64_t kryptos_poly1305_overflown_numfrac_t;

# define kKryptosPoly1305_128bit_NumberSize 4
# endif

#define kKryptosPoly1305NumberSize sizeof(kryptos_poly1305_number_t) / sizeof(kryptos_poly1305_numfrac_t)

#define kKryptosPoly1305MaxMpDigit KRYPTOS_MAX_MP_DIGIT

void kryptos_poly1305_add(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y);

void kryptos_poly1305_sub(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y);

void kryptos_poly1305_mul(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y);

void kryptos_poly1305_mul_digit(kryptos_poly1305_number_t x, const kryptos_poly1305_numfrac_t digit);

void kryptos_poly1305_div(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y, kryptos_poly1305_number_t r);

void kryptos_poly1305_le_bytes_to_num(kryptos_poly1305_number_t n, const kryptos_u8_t *bytes, const size_t bytes_nr);

void kryptos_poly1305_ld_raw_bytes(kryptos_poly1305_number_t n, const kryptos_u8_t *bytes, const size_t bytes_nr);

void kryptos_poly1305_le_num(kryptos_poly1305_number_t n, const kryptos_u8_t *bytes, const size_t bytes_nr) ;

int kryptos_poly1305_eq(const kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y);

const kryptos_poly1305_numfrac_t *kryptos_poly1305_get_gt(const kryptos_poly1305_number_t x,
                                                          const kryptos_poly1305_number_t y);

void kryptos_poly1305_lsh(kryptos_poly1305_number_t x, const size_t level);

void kryptos_poly1305_rsh(kryptos_poly1305_number_t x, const size_t level);

void kryptos_poly1305_inv_cmplt(kryptos_poly1305_number_t x);

void kryptos_poly1305_not(kryptos_poly1305_number_t x);

#define kryptos_poly1305_ne(x, y) ( kryptos_poly1305_eq((x), (y)) == 0 )

#define kryptos_poly1305_gt(x, y) ( kryptos_poly1305_ne((x), (y)) && kryptos_poly1305_get_gt((x), (y)) == &(x)[0] )

#define kryptos_poly1305_lt(x, y) kryptos_poly1305_gt((y), (x))

#define kryptos_poly1305_ge(x, y) ( kryptos_poly1305_eq((x), (y)) || kryptos_poly1305_gt((x), (y)) )

#ifdef __cplusplus
}
#endif

#endif

