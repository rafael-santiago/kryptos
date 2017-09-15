/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_MP_H
#define KRYPTOS_KRYPTOS_MP_H 1

#include <kryptos_types.h>

kryptos_mp_value_t *kryptos_new_mp_value(const size_t bitsize);

void kryptos_del_mp_value(kryptos_mp_value_t *mp);

kryptos_mp_value_t *kryptos_assign_mp_value(kryptos_mp_value_t **dest,
                                              const kryptos_mp_value_t *src);

kryptos_mp_value_t *kryptos_hex_value_as_mp(const kryptos_u8_t *value, const size_t value_size);

kryptos_u8_t *kryptos_mp_value_as_hex(const kryptos_mp_value_t *value, size_t *hex_size);

kryptos_mp_value_t *kryptos_mp_add(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src);

kryptos_mp_value_t *kryptos_mp_sub(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src);

kryptos_mp_value_t *kryptos_assign_hex_value_to_mp(kryptos_mp_value_t **dest,
                                                   const kryptos_u8_t *value, const size_t value_size);

kryptos_mp_value_t *kryptos_mp_mul(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src);

int kryptos_mp_eq(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

const kryptos_mp_value_t *kryptos_mp_get_gt(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

#ifndef KRYPTOS_MP_U32_DIGIT

#define kryptos_mp_is_neg(a) ( ((a)->data[(a)->data_size - 1] >> 7) )

#else

#define kryptos_mp_is_neg(a) ( ((a)->data[(a)->data_size - 1] >> 31) )

#endif

#define kryptos_mp_ne(a, b) ( kryptos_mp_eq((a), (b)) == 0 )

#define kryptos_mp_gt(a, b) ( kryptos_mp_ne((a), (b)) && kryptos_mp_get_gt((a), (b)) == (a) )

#define kryptos_mp_lt(a, b) ( kryptos_mp_gt((b), (a)) )

#define kryptos_mp_ge(a, b) ( kryptos_mp_eq((a), (b)) || kryptos_mp_get_gt((a), (b)) == (a) )

#define kryptos_mp_le(a, b) ( kryptos_mp_eq((a), (b)) || kryptos_mp_get_gt((a), (b)) == (b) )

#define kryptos_mp_is_odd(a) ( ( (a)->data[0] & 1 ) )

#define kryptos_mp_is_even(a) ( kryptos_mp_is_odd(a) == 0 )

kryptos_mp_value_t *kryptos_mp_div(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **r);

kryptos_mp_value_t *kryptos_mp_exp(kryptos_mp_value_t *b, const kryptos_mp_value_t *e);

kryptos_mp_value_t *kryptos_mp_pow(const kryptos_mp_value_t *g, const kryptos_mp_value_t *e);

kryptos_mp_value_t *kryptos_mp_me_mod_n(const kryptos_mp_value_t *m, const kryptos_mp_value_t *e, const kryptos_mp_value_t *n);

kryptos_mp_value_t *kryptos_mp_rand(const size_t bits);

kryptos_mp_value_t *kryptos_mp_gen_random(const kryptos_mp_value_t *n);

int kryptos_mp_is_prime(const kryptos_mp_value_t *n);

int kryptos_mp_miller_rabin_test(const kryptos_mp_value_t *n, const int sn);

int kryptos_mp_fermat_test(const kryptos_mp_value_t *n, const int k);

kryptos_mp_value_t *kryptos_mp_lsh(kryptos_mp_value_t **a, const int level);

kryptos_mp_value_t *kryptos_mp_rsh_op(kryptos_mp_value_t **a, const int level, const int signed_op);

#define kryptos_mp_rsh(a, l) ( kryptos_mp_rsh_op((a), (l), 0) )

#define kryptos_mp_signed_rsh(a, l) ( kryptos_mp_rsh_op((a), (l), 1) )

kryptos_mp_value_t *kryptos_mp_gen_prime(const size_t bitsize);

kryptos_mp_value_t *kryptos_mp_montgomery_reduction(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y);

void kryptos_print_mp(const kryptos_mp_value_t *v);

kryptos_mp_value_t *kryptos_mp_div_2p(const kryptos_mp_value_t *x, const kryptos_u32_t power, kryptos_mp_value_t **r);

kryptos_mp_value_t *kryptos_mp_gcd(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

kryptos_mp_value_t *kryptos_mp_modinv(const kryptos_mp_value_t *a, const kryptos_mp_value_t *m);

kryptos_mp_value_t *kryptos_mp_not(kryptos_mp_value_t *n);

kryptos_mp_value_t *kryptos_mp_inv_signal(kryptos_mp_value_t *n);

ssize_t kryptos_mp_bitcount(const kryptos_mp_value_t *n);

kryptos_mp_value_t *kryptos_mp_mul_digit(kryptos_mp_value_t **x, const kryptos_mp_digit_t digit);

kryptos_mp_value_t *kryptos_raw_buffer_as_mp(const kryptos_u8_t *buf, const size_t buf_size);

#ifndef KRYPTOS_MP_U32_DIGIT
# define kryptos_mp_bit2byte(b) ( (b) >> 3 )

# define kryptos_mp_byte2bit(b) ( (b) << 3 )


# define kryptos_mp_as_raw_buffer(ktask, m, o, o_size, xd, epilogue) {\
    (*(ktask))->out_size = (m)->data_size * sizeof(kryptos_mp_digit_t);\
    (*(ktask))->out = (kryptos_u8_t *) kryptos_newseg((*(ktask))->out_size);\
    if ((*(ktask))->out == NULL) {\
        (*(ktask))->result = kKryptosProcessError;\
        (*(ktask))->result_verbose = "No memory to produce the output.";\
        goto epilogue;\
    }\
    memset((*(ktask))->out, 0, (*(ktask))->out_size);\
    (o) = (*(ktask))->out;\
    (o_size) = (*(ktask))->out_size;\
    for ((xd) = (m)->data_size - 1; (xd) >= 0; (xd)--, (o) += sizeof(kryptos_mp_digit_t), (o_size) -= sizeof(kryptos_mp_digit_t)) {\
        *(o) = (m)->data[(xd)];\
    }\
    (o) = NULL;\
    (o_size) = (xd) = 0;\
}

#else

# define kryptos_mp_bit2byte(b) ( (b) >> 5 )

# define kryptos_mp_byte2bit(b) ( (b) << 5 )

# define kryptos_mp_as_raw_buffer(ktask, m, o, o_size, xd, epilogue) {\
    (*(ktask))->out_size = (m)->data_size * sizeof(kryptos_mp_digit_t);\
    (*(ktask))->out = (kryptos_u8_t *) kryptos_newseg((*(ktask))->out_size);\
    if ((*(ktask))->out == NULL) {\
        (*(ktask))->result = kKryptosProcessError;\
        (*(ktask))->result_verbose = "No memory to produce the output.";\
        goto epilogue;\
    }\
    memset((*(ktask))->out, 0, (*(ktask))->out_size);\
    (o) = (*(ktask))->out;\
    (o_size) = (*(ktask))->out_size;\
    for ((xd) = (m)->data_size - 1; (xd) >= 0; (xd)--, (o) += sizeof(kryptos_mp_digit_t), (o_size) -= sizeof(kryptos_mp_digit_t)) {\
        kryptos_cpy_u32_as_big_endian((o), (o_size), (m)->data[xd]);\
    }\
    (o) = NULL;\
    (o_size) = (xd) = 0;\
}

#endif

#endif
