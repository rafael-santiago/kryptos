/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */

// 'Hexadecimals. Hexadecimals to the rescue.'
//              -- Mark Watney (The Martian)

#include <kryptos_mp.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#define kryptos_mp_xnb(n) ( isdigit((n)) ? ( (n) - 48 ) : ( toupper((n)) - 55 )  )

static kryptos_u8_t nbxlt[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

#define kryptos_mp_nbx(x) ( nbxlt[(x)] )

#define kryptos_mp_max_min(aa, bb, a, b) {\
    if ((a)->data_size >= (b)->data_size) {\
        (aa) = (a);\
        (bb) = (b);\
    } else {\
        (aa) = (b);\
        (bb) = (a);\
    }\
}

#define KRYPTOS_MP_MULTIBYTE_FLOOR 4

#define kryptos_mp_get_u32_from_mp(m, i) ( ((i) < (m)->data_size) ? ( (kryptos_u32_t)((m)->data[(i) + 3] << 24) |\
                                                                      (kryptos_u32_t)((m)->data[(i) + 2] << 16) |\
                                                                      (kryptos_u32_t)((m)->data[(i) + 1] <<  8) |\
                                                                      (kryptos_u32_t)((m)->data[  (i)  ]) ) : 0 )

#define kryptos_mp_put_u32_into_mp(m, i, v) {\
    (m)->data[(i) + 3] = (v) >> 24;\
    (m)->data[(i) + 2] = ((v) >> 16) & 0xFF;\
    (m)->data[(i) + 1] = ((v) >>  8) & 0xFF;\
    (m)->data[  (i)  ] = (v) & 0xFF;\
}

static kryptos_mp_value_t *kryptos_mp_pad_for_multibyte(const kryptos_mp_value_t *v);

static kryptos_mp_value_t *kryptos_mp_multibyte_add(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

static kryptos_mp_value_t *kryptos_mp_multibyte_sub(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

static kryptos_mp_value_t *kryptos_mp_multibyte_mul(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

static kryptos_mp_value_t *kryptos_mp_montgomery_reduction_2kx_mod_y(const kryptos_mp_value_t *x,
                                                                     const kryptos_mp_value_t *y);

kryptos_mp_value_t *kryptos_new_mp_value(const size_t bitsize) {
    kryptos_mp_value_t *mp;

    mp = (kryptos_mp_value_t *) kryptos_newseg(sizeof(kryptos_mp_value_t));

    if (mp == NULL) {
        return NULL;
    }

    mp->data_size = bitsize;

    while (mp->data_size < 8) {
        mp->data_size++;
    }

    while ((mp->data_size % 8) != 0) {
        mp->data_size++;
    }

    mp->data_size = mp->data_size >> 3;

    mp->data = (kryptos_u8_t *) kryptos_newseg(mp->data_size);
    memset(mp->data, 0, mp->data_size);

    return mp;
}

void kryptos_del_mp_value(kryptos_mp_value_t *mp) {
    if (mp == NULL) {
        return;
    }

    if (mp->data != NULL) {
        memset(mp->data, 0, mp->data_size);
        free(mp->data);
        mp->data_size = 0;
    }

    free(mp);
}

kryptos_mp_value_t *kryptos_assign_mp_value(kryptos_mp_value_t **dest,
                                            const kryptos_mp_value_t *src) {
    ssize_t d;

    if (src == NULL || dest == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(src->data_size << 3);
    }

    if (src->data_size > (*dest)->data_size) {
        kryptos_freeseg((*dest)->data);
        (*dest)->data_size = src->data_size;
        //(*dest)->data = (kryptos_u8_t *) kryptos_newseg(src->data_size << 3);
        (*dest)->data = (kryptos_u8_t *) kryptos_newseg(src->data_size);
    }

    memset((*dest)->data, 0, (*dest)->data_size);

    d = src->data_size - 1;

    while (d >= 0) {
        (*dest)->data[d] = src->data[d];
        d--;
    }

    return *dest;
}

kryptos_mp_value_t *kryptos_hex_value_as_mp(const kryptos_u8_t *value, const size_t value_size) {
    kryptos_mp_value_t *mp;
    const kryptos_u8_t *vp, *vp_end;
    size_t d;
    kryptos_u8_t nb;

    if (value == NULL || value_size == 0) {
        return NULL;
    }

    mp = kryptos_new_mp_value(value_size << 2);

    if (mp == NULL) {
        return NULL;
    }

    vp = value;
    vp_end = vp + value_size;

    d = mp->data_size - 1;

    if ((value_size % 2) != 0) {
        mp->data[d] = kryptos_mp_xnb(*vp);
        d--;
        vp++;
    }

    while (vp < vp_end && d >= 0) {
        nb = 0;
        if ((vp + 1) != vp_end) {
            nb = kryptos_mp_xnb(*(vp + 1));
        }

        mp->data[d] = (kryptos_mp_xnb(*vp) << 4) | nb;

        vp += 2;

        d--;
    }

    return mp;
}

kryptos_u8_t *kryptos_mp_value_as_hex(const kryptos_mp_value_t *value, size_t *hex_size) {
    ssize_t d;
    kryptos_u8_t *hex, *hp, *hp_end;

    if (value == NULL || hex_size == NULL) {
        return NULL;
    }

    *hex_size = value->data_size << 1;

    hex = (kryptos_u8_t *) kryptos_newseg(*hex_size + 1);

    if (hex == NULL) {
        *hex_size = 0;
        return NULL;
    }

    memset(hex, 0, *hex_size + 1);

    d = value->data_size - 1;

    hp = hex;
    hp_end = hp + *hex_size;

    while (d >= 0) {
        *hp       = kryptos_mp_nbx(value->data[d] >> 4);
        *(hp + 1) = kryptos_mp_nbx(value->data[d] & 0xF);
        hp += 2;
        d--;
    }

    return hex;
}

static kryptos_mp_value_t *kryptos_mp_pad_for_multibyte(const kryptos_mp_value_t *v) {
    ssize_t s = v->data_size;
    kryptos_mp_value_t *p = NULL;

    while ((s % 4) != 0) {
        s++;
    }

    p = kryptos_new_mp_value(s << 3);
    p = kryptos_assign_mp_value(&p, v);

    return p;
}

static kryptos_mp_value_t *kryptos_mp_multibyte_add(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    // FACTS(Rafael):   1. a and b are non-null values.
    //                  2. a is always longer than b.
    //
    //                  if not you have introduced a bug.
    kryptos_mp_value_t *a4 = NULL, *b4 = NULL, *sum = NULL;
    kryptos_u64_t u64sum;
    kryptos_u8_t c;
    ssize_t i, sn, s;

    if ((a4 = kryptos_mp_pad_for_multibyte(a)) == NULL) {
        goto kryptos_mp_multibyte_add_epilogue;
    }

    if ((b4 = kryptos_mp_pad_for_multibyte(b)) == NULL) {
        goto kryptos_mp_multibyte_add_epilogue;
    }

    sum = kryptos_new_mp_value((a4->data_size + b4->data_size) << 3);

    if (sum == NULL) {
        goto kryptos_mp_multibyte_add_epilogue;
    }

    s = i = 0;
    c = 0;

    while (i < a4->data_size) {
        u64sum = (kryptos_u64_t) kryptos_mp_get_u32_from_mp(a4, i) + (kryptos_u64_t) kryptos_mp_get_u32_from_mp(b4, i) + c;
        c = (u64sum > 0xFFFFFFFF);
        kryptos_mp_put_u32_into_mp(sum, s, u64sum);
        i += 4;
        s += 4;
    }

    if (c > 0 && s < sum->data_size) {
        sum->data[s] = c;
    }

kryptos_mp_multibyte_add_epilogue:

    if (a4 != NULL) {
        kryptos_del_mp_value(a4);
    }

    if (b4 != NULL) {
        kryptos_del_mp_value(b4);
    }

    return sum;
}

kryptos_mp_value_t *kryptos_mp_add(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    ssize_t d, s, sn;
    kryptos_u16_t bsum;
    kryptos_u8_t c;
    kryptos_mp_value_t *sum;
    const kryptos_mp_value_t *a, *b;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(src->data_size << 3);
        memcpy((*dest)->data, src->data, src->data_size);
        return (*dest);
    }

    kryptos_mp_max_min(a, b, (*dest), src);

    if (a->data_size >= KRYPTOS_MP_MULTIBYTE_FLOOR) {
        // INFO(Rafael): We can process the data bytes as 32-bit groups. So, for example, if we have 128 bytes to sum
        //               96 iterations will be avoided.
        if ((sum = kryptos_mp_multibyte_add(a, b)) != NULL) {
            goto kryptos_mp_add_epilogue;
        }
    }

    sum = kryptos_new_mp_value((src->data_size + (*dest)->data_size) << 3);

    if (sum == NULL) {
        return NULL;
    }

    d = s = 0;
    c = 0;

    while (d < a->data_size) {
        bsum = a->data[d] + ( (d < b->data_size) ? b->data[d] : 0 ) + c;
        c = (bsum > 0xFF);
        sum->data[s] = bsum & 0xFF;
        s++;
        d++;
    }

    if (c > 0 && s < sum->data_size) {
        sum->data[s] = c;
    }

kryptos_mp_add_epilogue:

    for (sn = sum->data_size - 1; sn >= 0 && sum->data[sn] == 0; sn--)
        ;

    (*dest)->data_size = (sn < sum->data_size) ? sn + 1 : sum->data_size;
    kryptos_freeseg((*dest)->data);

    (*dest)->data = (kryptos_u8_t *) kryptos_newseg((*dest)->data_size);
    if ((*dest)->data != NULL) {
        for (s = sn; s >= 0; s--) {
            (*dest)->data[s] = sum->data[s];
        }
    } else {
        (*dest)->data = sum->data;
        sum->data = NULL;
    }

    kryptos_del_mp_value(sum);

    return (*dest);
}

static kryptos_mp_value_t *kryptos_mp_multibyte_sub(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    kryptos_mp_value_t *a4 = NULL, *b4 = NULL, *delta = NULL;
    kryptos_u64_t u64sub;
    kryptos_u64_t c;
    ssize_t s, dn, d;

    if ((a4 = kryptos_mp_pad_for_multibyte(a)) == NULL) {
        goto kryptos_mp_multibyte_sub_epilogue;
    }

    if ((b4 = kryptos_mp_pad_for_multibyte(b)) == NULL) {
        goto kryptos_mp_multibyte_sub_epilogue;
    }

    delta = kryptos_new_mp_value((a4->data_size + b4->data_size) << 3);

    if (delta == NULL) {
        goto kryptos_mp_multibyte_sub_epilogue;
    }

    s = d = 0;
    c = 0;
    dn = (a4->data_size > b4->data_size) ? a4->data_size : b4->data_size;
//printf("a4 = "); print_mp(a4);
//printf("b4 = "); print_mp(b4);
    while (d < dn) {
        u64sub = (kryptos_u64_t) kryptos_mp_get_u32_from_mp(a4, d) - (kryptos_u64_t) kryptos_mp_get_u32_from_mp(b4, d) + c;
//        printf("\t%X - %X + %X = %"PRIx64"\n", kryptos_mp_get_u32_from_mp(a4, d), kryptos_mp_get_u32_from_mp(b4, d), c, u64sub);
        c += u64sub >> 32;
        kryptos_mp_put_u32_into_mp(delta, s, u64sub);
        d += 4;
        s += 4;
    }

    if (c == 0xFFFFFFFF && s < delta->data_size) {
        delta->data[s] = 0x0F;
    }

kryptos_mp_multibyte_sub_epilogue:

    if (a4 != NULL) {
        kryptos_del_mp_value(a4);
    }

    if (b4 != NULL) {
        kryptos_del_mp_value(b4);
    }

//printf("delta = "); print_mp(delta);
//printf("--\n");
    return delta;
}

kryptos_mp_value_t *kryptos_mp_sub(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    ssize_t d, s, sn, dn;
    kryptos_u16_t bsub;
    kryptos_u8_t c;
    kryptos_mp_value_t *delta;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(src->data_size << 3);
        memcpy((*dest)->data, src->data, src->data_size);
        return (*dest);
    }

/*
    if ((*dest)->data_size >= KRYPTOS_MP_MULTIBYTE_FLOOR) {
        if ((delta = kryptos_mp_multibyte_sub((*dest), src)) != NULL) {
            goto kryptos_mp_sub_epilogue;
        }
    }
*/

    delta = kryptos_new_mp_value((src->data_size + (*dest)->data_size) << 3);

    if (delta == NULL) {
        return NULL;
    }

    d = s = 0;
    c = 0;
    dn = ((*dest)->data_size > src->data_size) ? (*dest)->data_size : src->data_size;

    while (d < dn) {
        bsub = ( (d < (*dest)->data_size) ? (*dest)->data[d] : 0 ) - ( (d < src->data_size) ? src->data[d] : 0 ) + c;
//        printf("X = %x / Y = %x / c = %x / BSUB = %x / BYTE-SUB = %x\n", (*dest)->data[d], src->data[d], c, bsub, bsub & 0xFF);
        c += bsub >> 8;
        delta->data[s] = bsub & 0xFF;
        s++;
        d++;
    }

    if (c == 0xFF && s < delta->data_size) {
        // INFO(Rafael): Here in this code I am not really concerned about signals, the numbers are expressed with 2^b bits.
        //               However, we will sign that the src was greater than dest by setting the most significant nibble to 0xF.
        delta->data[s] = 0x0F;
    }

kryptos_mp_sub_epilogue:

    for (sn = delta->data_size - 1; sn >= 0 && delta->data[sn] == 0; sn--)
        ;

    (*dest)->data_size = (sn < delta->data_size) ? sn + 1 : delta->data_size;
    kryptos_freeseg((*dest)->data);

    (*dest)->data = (kryptos_u8_t *) kryptos_newseg((*dest)->data_size);
    memset((*dest)->data, 0, (*dest)->data_size);
    if ((*dest)->data != NULL) {
        for (s = sn; s >= 0; s--) {
            (*dest)->data[s] = delta->data[s];
        }
    } else {
        (*dest)->data = delta->data;
        delta->data = NULL;
    }

    kryptos_del_mp_value(delta);

    return (*dest);
}

kryptos_mp_value_t *kryptos_assign_hex_value_to_mp(kryptos_mp_value_t **dest,
                                                   const kryptos_u8_t *value, const size_t value_size) {
    const kryptos_u8_t *vp, *vp_end;
    ssize_t d;
    kryptos_u8_t nb;

    if (dest == NULL || value == NULL || value_size == 0) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_hex_value_as_mp(value, value_size);
        return (*dest);
    }

    vp = value;
    vp_end = vp + value_size;

    memset((*dest)->data, 0, (*dest)->data_size);

    if ((value_size >> 1) > (*dest)->data_size) {
        d = (*dest)->data_size - 1;
    } else {
        d = (value_size >> 1) - 1;
    }

    while (vp < vp_end && d >= 0) {
        nb = 0;

        if ((vp + 1) != vp_end) {
            nb = kryptos_mp_xnb(*(vp + 1));
        }

        (*dest)->data[d] = (kryptos_mp_xnb(*vp) << 4) | nb;

        vp += 2;
        d--;
    }

    return (*dest);
}

static kryptos_mp_value_t *kryptos_mp_multibyte_mul(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    kryptos_mp_value_t *a4 = NULL, *b4 = NULL, *mul = NULL;
    kryptos_u64_t u64mul, u64sum;
    kryptos_u8_t ac;
    ssize_t ad, bd, r;
    kryptos_u32_t mc;

    if ((a4 = kryptos_mp_pad_for_multibyte(a)) == NULL) {
        goto kryptos_mp_multibyte_mul_epilogue;
    }

    if ((b4 = kryptos_mp_pad_for_multibyte(b)) == NULL) {
        goto kryptos_mp_multibyte_mul_epilogue;
    }

    mul = kryptos_new_mp_value((a4->data_size + b4->data_size + 4) << 3);

    if (mul == NULL) {
        goto kryptos_mp_multibyte_mul_epilogue;
    }

    for (bd = 0, r = 0; bd < b4->data_size; bd += 4, r += 4) {
        mc = 0;
        ac = 0;

        for (ad = 0; ad < a4->data_size; ad += 4) {
            u64mul = (kryptos_u64_t) kryptos_mp_get_u32_from_mp(b4, bd) *
                        (kryptos_u64_t) kryptos_mp_get_u32_from_mp(a4, ad) + (kryptos_u64_t) mc;
            mc = u64mul >> 32;

            u64sum = (kryptos_u64_t) kryptos_mp_get_u32_from_mp(mul, ad + r) + (u64mul & 0xFFFFFFFF) + (kryptos_u64_t) ac;
            ac = (u64sum > 0xFFFFFFFF);
            kryptos_mp_put_u32_into_mp(mul, ad + r, u64sum);
        }

        if ((ad + r) < mul->data_size) {
            u64sum = ((kryptos_u64_t) kryptos_mp_get_u32_from_mp(mul, ad + r) + mc + ac) & 0xFFFFFFFF;
            kryptos_mp_put_u32_into_mp(mul, ad + r, u64sum);
        }
    }

kryptos_mp_multibyte_mul_epilogue:

    if (a4 != NULL) {
        kryptos_del_mp_value(a4);
    }

    if (b4 != NULL) {
        kryptos_del_mp_value(b4);
    }

    return mul;
}

kryptos_mp_value_t *kryptos_mp_mul(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    size_t r;
    kryptos_mp_value_t *m;
    const kryptos_mp_value_t *x, *y;
    ssize_t xd, yd;
    short bmul;
    kryptos_u16_t bsum;
    kryptos_u8_t mc, ac;

    if (src == NULL || dest == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(src->data_size << 3);
        memcpy((*dest)->data, src->data, src->data_size);
        return (*dest);
    }

    kryptos_mp_max_min(x, y, (*dest), src);

    if (x->data_size >= KRYPTOS_MP_MULTIBYTE_FLOOR) {
        if ((m = kryptos_mp_multibyte_mul(x, y)) != NULL) {
            goto kryptos_mp_mul_epilogue;
        }
    }

    // CLUE(Rafael): Encantamentos baseados em algumas propriedades que talvez a tia Tetéia não quis te contar.

    m = kryptos_new_mp_value(((*dest)->data_size + src->data_size + 1) << 3);

    if (m == NULL) {
        // WARN(Rafael): Better let a memory leak than return a wrong result.
        return NULL;
    }

    // CLUE(Rafael): Multiplicando igual na aula da tia Tetéia.

    for (yd = 0, r = 0; yd < y->data_size; yd++, r++) {
        mc = 0;
        ac = 0;

        for (xd = 0; xd < x->data_size; xd++) {
            bmul = y->data[yd] * x->data[xd] + mc;
            mc = (bmul >> 8);
            // INFO(Rafael): "Parallelizing" the multiplications sum in order to not call kryptos_mp_add() x->data_size times.
            //               Besides time it will also save memory.
            bsum = m->data[xd + r] + (bmul & 0xFF) + ac;
            ac = (bsum > 0xFF);
            m->data[xd + r] = (bsum & 0xFF);
        }

        if ((xd + r) < m->data_size) {
            m->data[xd + r] = (m->data[xd + r] + mc + ac) & 0xFF;
        }
    }

kryptos_mp_mul_epilogue:

    for (xd = m->data_size - 1; xd >= 0 && m->data[xd] == 0; xd--)
        ;

    kryptos_del_mp_value((*dest));
    (*dest) = NULL;

    (*dest) = kryptos_new_mp_value((xd + 1) << 3);

    for (yd = xd; yd >= 0; yd--) {
        (*dest)->data[yd] = m->data[yd];
    }

    // INFO(Rafael): Housekeeping.
    kryptos_del_mp_value(m);
    r = 0;
    bmul = 0;
    ac = mc = 0;
    bmul = 0;
    bsum = 0;

    return (*dest);
}

int kryptos_mp_eq(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    size_t d;
    const kryptos_mp_value_t *aa, *bb;

    if (a == NULL || b == NULL) {
        return 0;
    }

    if (a->data_size == b->data_size) {
        return (memcmp(a->data, b->data, a->data_size) == 0);
    }

    kryptos_mp_max_min(aa, bb, a, b);

    if (aa->data_size != bb->data_size) {
        for (d = bb->data_size; d < aa->data_size; d++) {
            if (aa->data[d] != 0) {
                return 0;
            }
        }
    }

    for (d = 0; d < bb->data_size; d++) {
        if (aa->data[d] != bb->data[d]) {
            return 0;
        }
    }

    return 1;
}

const kryptos_mp_value_t *kryptos_mp_get_gt(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    ssize_t d;
    const kryptos_mp_value_t *aa, *bb;
    kryptos_u8_t x, y;

    if (a == NULL || b == NULL) {
        return NULL;
    }

    kryptos_mp_max_min(aa, bb, a, b);

    if (aa->data_size != bb->data_size) {
        for (d = bb->data_size; d < aa->data_size; d++) {
            if (aa->data[d] != 0) {
                return aa;
            }
        }
    }

#define kryptos_mp_get_gt_bitcmp(aa, bb, n, b, ax, bx) {\
    (ax) = ((aa)->data[n] & (1 << (b))) >> (b);\
    (bx) = ((bb)->data[n] & (1 << (b))) >> (b);\
    if ((ax) && !(bx)) {\
        return (aa);\
    }\
    if ((bx) && !(ax)) {\
        return (bb);\
    }\
}

    for (d = bb->data_size - 1; d >= 0; d--) {
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 7, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 6, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 5, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 4, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 3, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 2, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 1, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 0, x, y);
    }

#undef kryptos_mp_get_gt_bitcmp

    return NULL;
}

kryptos_mp_value_t *kryptos_mp_pow(const kryptos_mp_value_t *g, const kryptos_mp_value_t *e) {
    kryptos_mp_value_t *A = NULL;
    ssize_t t;

    if (g == NULL || e == NULL) {
        return NULL;
    }

    A = kryptos_hex_value_as_mp("1", 1);

#define kryptos_mp_pow_step(e, t, bn, A, g) {\
    A = kryptos_mp_mul(&A, A);\
    if ( ( ((e)->data[t] & (1 << (bn))) >> (bn) ) ) {\
        A = kryptos_mp_mul(&A, g);\
    }\
}

    for (t = e->data_size - 1; t >= 0; t--) {
        kryptos_mp_pow_step(e, t, 7, A, g);
        kryptos_mp_pow_step(e, t, 6, A, g);
        kryptos_mp_pow_step(e, t, 5, A, g);
        kryptos_mp_pow_step(e, t, 4, A, g);
        kryptos_mp_pow_step(e, t, 3, A, g);
        kryptos_mp_pow_step(e, t, 2, A, g);
        kryptos_mp_pow_step(e, t, 1, A, g);
        kryptos_mp_pow_step(e, t, 0, A, g);
    }

#undef kryptos_mp_pow_step

    return A;
}

void print_mp(const kryptos_mp_value_t *v) {
    ssize_t d;
    for (d = v->data_size - 1; d >= 0; d--) printf("%.2X", v->data[d]);
    printf("\n");
}

static ssize_t kryptos_mp_max_used_byte(const kryptos_mp_value_t *x) {
    ssize_t b;
    for (b = x->data_size - 1; b >= 0 && x->data[b] == 0; b--)
        ;
    return b;
}

#ifndef KRYPTOS_MP_SLOWER_MP_DIV

#undef KRYPTOS_MP_DIV_DEBUG_INFO

kryptos_mp_value_t *kryptos_mp_div(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **r) {
    kryptos_mp_value_t *q = NULL, *xn = NULL, *yn = NULL, *b = NULL;
    ssize_t d, dn;
    ssize_t n, m, j, xi;
    kryptos_u16_t qtemp;
    int is_zero = 0, is_less;

    if (x == NULL || y == NULL) {  // INFO(Rafael): One or both div op variables passed as null.
        if (r != NULL) {
            (*r) = NULL;  // INFO(Rafael): Who knows.... who knows...
        }
        return NULL;
    }

    is_zero = 1;
    for (d = y->data_size - 1; d >= 0 && is_zero; d--) {
        is_zero = (y->data[d] == 0x00);
    }

    if (is_zero) {  // INFO(Rafael): Division by zero.
        if (r != NULL) {
            (*r) = NULL;
        }
        return NULL;
    }

    is_zero = 1;
    for (d = x->data_size - 1; d >= 0 && is_zero; d--) {
        is_zero = (x->data[d] == 0x00);
    }

    if (is_zero) {  // INFO(Rafael): 0 divided by y.
        if (r != NULL) {
            (*r) = kryptos_hex_value_as_mp("0", 1);
        }
        return kryptos_hex_value_as_mp("0", 1);
    }

    if (kryptos_mp_lt(x, y)) {  // INFO(Rafael): x < y.
        if (r != NULL) {
            (*r) = NULL;
            (*r) = kryptos_assign_mp_value(r, x);
        }
        return kryptos_hex_value_as_mp("0", 1);
    }

    m = x->data_size << 3;

    while (m % 64) {
        m++;
    }

    if ((xn = kryptos_new_mp_value(m)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    if ((xn = kryptos_assign_mp_value(&xn, x)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    if ((yn = kryptos_assign_mp_value(&yn, y)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    n = yn->data_size;

    m = x->data_size - yn->data_size;
    if (m <= 0) {
        m = 1;
    }

    if ((q = kryptos_new_mp_value((m + 1) << 3)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    if ((b = kryptos_assign_mp_value(&b, yn)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    b = kryptos_mp_lsh(&b, 8 * m);

    while (kryptos_mp_ge(xn, b)) {
        q->data[m]++;
        xn = kryptos_mp_sub(&xn, b);
    }

    kryptos_del_mp_value(b);

    if (kryptos_mp_lt(xn, yn)) {
        goto kryptos_mp_div_epilogue;
    }

    for (j = m - 1; j >= 0; j--) {

        xi = n + j;

        while (xi >= xn->data_size) {
            xi--;
        }

        qtemp = xn->data[xi];

        if ((xi - 1) >= 0) {
            qtemp = (qtemp << 8) | xn->data[xi - 1];
        }

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO

        printf("\tqtemp = %X\n", qtemp);
        printf("\t%X / %X = ", qtemp, yn->data[n - 1]);
#endif

        qtemp /= yn->data[n - 1];

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("%X\n", qtemp);
#endif

        d = j;

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("\t-- is_less loop begin.\n");
#endif

        do {

            if (qtemp <= 0xFF) {
                q->data[j] = qtemp & 0xFF;
            } else {
                q->data[j--] = qtemp >> 8;
                if (j >= 0) {
                    q->data[j  ] = qtemp & 0xFF;
                }
            }

            b = kryptos_new_mp_value(2 << 3);
            b->data[1] = qtemp >> 8;
            b->data[0] = qtemp & 0xFF;
            b = kryptos_mp_mul(&b, yn);
            b = kryptos_mp_lsh(&b, 8 * d);

            is_less = kryptos_mp_lt(xn, b);

            if (is_less) {
                qtemp--;
                kryptos_del_mp_value(b);
                b = NULL;
                j = d;
#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
                printf("\t\tis_less == 1, qtemp = %X\n", qtemp);
#endif
            }
        } while (is_less);

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("\t-- is_less loop end.\n");
        printf("\txn' = "); print_mp(xn);
        printf("\tb   = "); print_mp(b);
#endif

        xn = kryptos_mp_sub(&xn, b);

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("\txn- = "); print_mp(xn);
#endif

        if (b != NULL) {
            kryptos_del_mp_value(b);
        }

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("-- end of iteration.\n");
        printf("\tQ'  = "); print_mp(q);
        printf("\tXN' = "); print_mp(xn);
        printf("--\n");
#endif

    }

kryptos_mp_div_epilogue:

    // INFO(Rafael): Eliminating unused bytes from remainder and quotient.

    if (r != NULL) {
        for (dn = xn->data_size - 1; dn >= 0 && xn->data[dn] == 0; dn--)
            ;

        if (((*r) = kryptos_new_mp_value((dn + 1) << 3)) != NULL) {
            for (d = 0; d <= dn; d++) {
                (*r)->data[d] = xn->data[d];
            }
         } else {
            (*r) = xn;
            xn = NULL;
         }
    }

    if (q != NULL) {
        for (dn = q->data_size - 1; dn >= 0 && q->data[dn] == 0; dn--)
            ;

        if (dn >= 0) {
            if ((b = kryptos_new_mp_value((dn + 1) << 3)) != NULL) {
                for (d = 0; d <= dn; d++) {
                    b->data[d] = q->data[d];
                }
                kryptos_del_mp_value(q);
                q = b;
            }
        }
    }

    if (xn != NULL) {
        kryptos_del_mp_value(xn);
    }

    if (yn != NULL) {
        kryptos_del_mp_value(yn);
    }

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
    printf("-- end of algorithm\n");
    printf("\tQ = "); print_mp(q);
    printf("\tR = "); print_mp(*r);
#endif

    return q;
}

#else

kryptos_mp_value_t *kryptos_mp_div(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **r) {
    kryptos_mp_value_t *q = NULL;
    kryptos_mp_value_t *i = NULL;
    kryptos_mp_value_t *curr_x = NULL, *_1 = NULL, *sy = NULL;
    ssize_t d, di;
    int div_nr = 0, is_zero = 0;

    if (x == NULL || y == NULL) {  // INFO(Rafael): One or both div op variables passed as null.
        if (r != NULL) {
            (*r) = NULL;  // INFO(Rafael): Who knows.... who knows...
        }
        return NULL;
    }

    is_zero = 1;
    for (di = y->data_size - 1; di >= 0 && is_zero; di--) {
        is_zero = (y->data[di] == 0x00);
    }

    if (is_zero) {  // INFO(Rafael): Division by zero.
        if (r != NULL) {
            (*r) = NULL;
        }
        return NULL;
    }

    is_zero = 1;
    for (di = x->data_size - 1; di >= 0 && is_zero; di--) {
        is_zero = (x->data[di] == 0x00);
    }

    if (is_zero) {  // INFO(Rafael): 0 divided by y.
        if (r != NULL) {
            (*r) = kryptos_hex_value_as_mp("0", 1);
        }
        return kryptos_hex_value_as_mp("0", 1);
    }

    if (kryptos_mp_lt(x, y)) {  // INFO(Rafael): x < y.
        if (r != NULL) {
            (*r) = NULL;
            (*r) = kryptos_assign_mp_value(r, x);
        }
        return kryptos_hex_value_as_mp("0", 1);
    }

    q = kryptos_new_mp_value(x->data_size << 3);

    if (q == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    curr_x = kryptos_new_mp_value(x->data_size << 3);
    if (curr_x == NULL) {
        kryptos_del_mp_value(q);
        q = NULL;
        goto kryptos_mp_div_epilogue;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);
    if (_1 == NULL) {
        kryptos_del_mp_value(q);
        q = NULL;
        goto kryptos_mp_div_epilogue;
    }

    for (d = x->data_size - 1; d >= 0; d--) {
        curr_x->data[0] = x->data[d];
        if (kryptos_mp_ge(curr_x, y)) {
            do {
                div_nr = 1;
                if ((sy = kryptos_hex_value_as_mp("0", 1)) == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }
                if ((i = kryptos_hex_value_as_mp("0", 1)) == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }

                while (kryptos_mp_le(sy, curr_x)) {
                    sy = kryptos_mp_add(&sy, y);

                    if (sy == NULL) {
                        kryptos_del_mp_value(q);
                        q = NULL;
                        goto kryptos_mp_div_epilogue;
                    }

                    i = kryptos_mp_add(&i, _1);

                    if (i == NULL) {
                        kryptos_del_mp_value(q);
                        q = NULL;
                        goto kryptos_mp_div_epilogue;
                    }
                }

                i = kryptos_mp_sub(&i, _1);

                if (i == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }

                sy = kryptos_mp_sub(&sy, y);

                if (sy == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }

                curr_x = kryptos_mp_sub(&curr_x, sy);

                if (curr_x == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }

                for (di = i->data_size - 1; di >= 0; di--) {
                    q = kryptos_mp_lsh(&q, 8);
                    q->data[0] = i->data[di];
                }

                kryptos_del_mp_value(sy);
                kryptos_del_mp_value(i);
                sy = i = NULL;
            } while (kryptos_mp_ge(curr_x, y)); // INFO(Rafael): While is possible to divide... go into the loop again.
            curr_x = kryptos_mp_lsh(&curr_x, 8); // INFO(Rafael): Opens one position for the next digit.
            if (curr_x == NULL) {
                kryptos_del_mp_value(q);
                q = NULL;
                goto kryptos_mp_div_epilogue;
            }
        } else {
            curr_x = kryptos_mp_lsh(&curr_x, 8); // INFO(Rafael): Opens one position for the next digit.

            if (curr_x == NULL) {
                kryptos_del_mp_value(q);
                q = NULL;
                goto kryptos_mp_div_epilogue;
            }

            if (div_nr > 0) {
                q = kryptos_mp_lsh(&q, 8); // INFO(Rafael): The curr_x is not enough for dividing (curr_x < y).
                                           //               Thus, adds one digit zero to the quotient before getting
                                           //               the next digit from x.

                if (q == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }
            }
        }
    }

kryptos_mp_div_epilogue:
    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (r != NULL) {
        // INFO(Rafael): Reverting the remainder because there is nothing to get from x anymore.
        if (q != NULL) {
            curr_x = kryptos_mp_rsh(&curr_x, 8);
            (*r) = curr_x;
            curr_x = NULL;
        } else {
            (*r) = NULL;
        }
    }

    if (curr_x != NULL) {
        kryptos_del_mp_value(curr_x);
    }

    if (q != NULL) {  // INFO(Rafael): Eliminating unused bytes.
        for (di = q->data_size - 1; di >= 0 && q->data[di] == 0; di--)
            ;

        i = q;

        q = kryptos_new_mp_value((di + 1) << 3);

        for (d = 0; d <= di; d++) {
            q->data[d] = i->data[d];
        }

        kryptos_del_mp_value(i);
    }

    return q;
}

#endif

kryptos_mp_value_t *kryptos_mp_div_2p(const kryptos_mp_value_t *x, const kryptos_u32_t power, kryptos_mp_value_t **r) {
    kryptos_mp_value_t *q = NULL;
    kryptos_mp_value_t *p = NULL, *tr = NULL;
    ssize_t dn, d;

    if (x == NULL) {
        return NULL;
    }

    if ((q = kryptos_assign_mp_value(&q, x)) == NULL) {
        return NULL;
    }

    if ((q = kryptos_mp_rsh(&q, power)) == NULL) {
        return NULL;
    }

    if (r != NULL) {
        (*r) = NULL;
        if ((p = kryptos_new_mp_value(8)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        p->data[0] = 1;
        if ((p = kryptos_mp_lsh(&p, power)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        if ((p = kryptos_mp_mul(&p, q)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        if ((tr = kryptos_assign_mp_value(&tr, x)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        if ((tr = kryptos_mp_sub(&tr, p)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        for (dn = tr->data_size - 1; dn >= 0 && tr->data[dn] == 0; dn--)
            ;

        if (dn >= 0) {
            (*r) = kryptos_new_mp_value((dn + 1) << 3);
            if ((*r) != NULL) {
                for (d = 0; d <= dn; d++) {
                    (*r)->data[d] = tr->data[d];
                }
            }
        } else {
            (*r) = kryptos_new_mp_value(8);
        }

    }

kryptos_mp_div_2p_epilogue:

    if (tr != NULL) {
        kryptos_del_mp_value(tr);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    return q;
}

kryptos_mp_value_t *kryptos_mp_me_mod_n(const kryptos_mp_value_t *m, const kryptos_mp_value_t *e, const kryptos_mp_value_t *n) {
    kryptos_mp_value_t *A = NULL, *mod = NULL, *div = NULL;
    ssize_t t;
    int is_odd;

    if (m == NULL || e == NULL || n == NULL) {
        return NULL;
    }

    if ((A = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        return NULL;
    }

    is_odd = kryptos_mp_is_odd(n);

#define kryptos_mp_me_mod_n_mont(e, t, bn, A, m, n, mod) {\
    A = kryptos_mp_mul(&A, A);\
    mod = kryptos_mp_montgomery_reduction(A, n);\
    kryptos_del_mp_value(A);\
    A = mod;\
    mod = NULL;\
    if ( ( ((e)->data[t] & (1 << (bn))) >> (bn) ) ) {\
        A = kryptos_mp_mul(&A, m);\
        mod = kryptos_mp_montgomery_reduction(A, n);\
        kryptos_del_mp_value(A);\
        A = mod;\
        mod = NULL;\
    }\
}

#define kryptos_mp_me_mod_n(e, t, bn, A, m, n, div, mod) {\
    A = kryptos_mp_mul(&A, A);\
    div = kryptos_mp_div(A, n, &mod);\
    kryptos_del_mp_value(A);\
    kryptos_del_mp_value(div);\
    A = mod;\
    div = mod = NULL;\
    if ( ( ((e)->data[t] & (1 << (bn))) >> (bn) ) ) {\
        A = kryptos_mp_mul(&A, m);\
        div = kryptos_mp_div(A, n, &mod);\
        kryptos_del_mp_value(A);\
        kryptos_del_mp_value(div);\
        A = mod;\
        div = mod = NULL;\
    }\
}
/*
    if (kryptos_mp_is_odd(n)) {
        for (t = e->data_size - 1; t >= 0; t--) {
            kryptos_mp_me_mod_n_mont(e, t, 7, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 6, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 5, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 4, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 3, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 2, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 1, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 0, A, m, n, mod);
        }
    } else {*/
        for (t = e->data_size - 1; t >= 0; t--) {
            kryptos_mp_me_mod_n(e, t, 7, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 6, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 5, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 4, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 3, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 2, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 1, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 0, A, m, n, div, mod);
        }
/*    }*/

#undef kryptos_mp_me_mod_n_mont

#undef kryptos_mp_me_mod_n

    return A;

}

kryptos_mp_value_t *kryptos_mp_gen_random(const kryptos_mp_value_t *n) {
    kryptos_mp_value_t *r = NULL, *r_div = NULL, *r_mod = NULL;
    ssize_t ri;

    if (n == NULL) {
        return NULL;
    }

    r = kryptos_new_mp_value(n->data_size << 3);

    if (r == NULL) {
        return NULL;
    }

    for (ri = r->data_size - 1; ri >= 0; ri--) {
        r->data[ri] = kryptos_get_random_byte();
    }

    if ((r_div = kryptos_mp_div(r, n, &r_mod)) != NULL) {
        kryptos_del_mp_value(r_div);
    }

    kryptos_del_mp_value(r);

    return r_mod;
}

int kryptos_mp_is_prime(const kryptos_mp_value_t *n) {
    int is_prime = kryptos_mp_fermat_test(n, 7);

    if (is_prime) {
        // INFO(Rafael): Avoiding any Carmichael's number.
        return kryptos_mp_miller_rabin_test(n, 14);
    }

    return is_prime;
}

int kryptos_mp_miller_rabin_test(const kryptos_mp_value_t *n, const int sn) {
    kryptos_mp_value_t *k = NULL, *m = NULL, *n_1 = NULL, *_1 = NULL, *_0 = NULL,
                       *e = NULL, *p = NULL, *n_div = NULL, *n_mod = NULL, *a = NULL, *bs = NULL;
    int is_prime = 1;
    int s, pn;

    if (n == NULL) {
        return 0;
    }

    if (kryptos_mp_is_even(n)) {
        return 0;
    }

    a = kryptos_hex_value_as_mp("2", 1);

    if (a == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    if (kryptos_mp_eq(n, a)) {
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    // INFO(Rafael): Setting up some initial values.

    _1 = kryptos_hex_value_as_mp("1", 1); // 1.
    if (_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    n_1 = kryptos_assign_mp_value(&n_1, n);
    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    // INFO(Rafael): Step 1, finding n - 1, m and k.

    n_1 = kryptos_mp_sub(&n_1, _1); // n - 1.
    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    // INFO(Rafael): Now k and m.

    _0 = kryptos_hex_value_as_mp("0", 1);

    if (_0 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    pn = 1;
    n_div = kryptos_mp_div_2p(n_1, pn, &n_mod);
    if ((k = kryptos_new_mp_value(32)) == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    do {
        // INFO(Rafael): Initially always should enter into this loop because n - 1 mod 2^1 is zero (n should be > 2 and odd).
        m = kryptos_assign_mp_value(&m, n_div); // temp m.
        k->data[3] = pn >> 24;
        k->data[2] = (pn >> 16) & 0xFF;
        k->data[1] = (pn >>  8) & 0xFF;
        k->data[0] = pn & 0xFF;
        if (m == NULL) {
            is_prime = 0;
            goto kryptos_mp_miller_rabin_test_epilogue;
        }
        kryptos_del_mp_value(n_div);
        kryptos_del_mp_value(n_mod);
        n_div = n_mod = NULL;
        pn++;
        n_div = kryptos_mp_div_2p(n_1, pn, &n_mod);
        if (n_div == NULL || n_mod == NULL) {
            is_prime = 0;
            goto kryptos_mp_miller_rabin_test_epilogue;
        }
    } while (kryptos_mp_eq(n_mod, _0));

    kryptos_del_mp_value(n_div);
    kryptos_del_mp_value(n_mod);
    n_div = n_mod = NULL;

    // INFO(Rafael): Now we got n - 1 = 2^k x m.

    // INFO(Rafael): Step 2, guessing a. Where 1 < a < n - 1.

    p = kryptos_assign_mp_value(&p, n_1);

    if (p == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    p = kryptos_mp_sub(&p, _1); // n - 2.

    if (p == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    if (!kryptos_mp_eq(p, _1)) {
        do {
            if (a != NULL) {
                kryptos_del_mp_value(a);
            }
            if ((a = kryptos_mp_gen_random(p)) == NULL) {
                is_prime = 0;
                goto kryptos_mp_miller_rabin_test_epilogue;
            }
        } while kryptos_mp_le(a, _1);
    } else {
        if ((a = kryptos_assign_mp_value(&a, p)) == NULL) {
            is_prime = 0;
            goto kryptos_mp_miller_rabin_test_epilogue;
        }
    }
    kryptos_del_mp_value(p);
    p = NULL;

    // INFO(Rafael): Step 3, b0 = a^m mod n.

    n_mod = kryptos_mp_me_mod_n(a, m, n);

    if (n_mod == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    is_prime = kryptos_mp_eq(n_mod, _1) || kryptos_mp_eq(n_mod, n_1); // INFO(Rafael): n - 1 means "-1".

    if (!is_prime) {
        if ((e = kryptos_hex_value_as_mp("2", 1)) == NULL) {
            is_prime = 0;
            goto kryptos_mp_miller_rabin_test_epilogue;
        }

        // INFO(Rafael): The last test failed let's calculate b_s .. b_sn.
        //               If bs = a^2 mod n = 1 is composite, -1 is prime, otherwise go ahead trying until s = sn.
        for (s = 0; s < sn && !is_prime; s++) {

            bs = kryptos_mp_me_mod_n(n_mod, e, n); // INFO(Rafael): bs = a^2 mod n.
            kryptos_del_mp_value(n_mod);
            n_mod = bs;

            if (n_mod == NULL) {
                is_prime = 0;
                goto kryptos_mp_miller_rabin_test_epilogue;
            }

            if (kryptos_mp_eq(n_mod, _1)) {
                // INFO(Rafael): Nevermind, it is composite.
                goto kryptos_mp_miller_rabin_test_epilogue;
            }

            is_prime = kryptos_mp_eq(n_mod, n_1);
        }
    }

kryptos_mp_miller_rabin_test_epilogue:

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (e != NULL) {
        kryptos_del_mp_value(e);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (n_div != NULL) {
        kryptos_del_mp_value(n_div);
    }

    if (n_mod != NULL) {
        kryptos_del_mp_value(n_mod);
    }

    if (m != NULL) {
        kryptos_del_mp_value(m);
    }

    if (k != NULL) {
        kryptos_del_mp_value(k);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    if (n_1 != NULL) {
        kryptos_del_mp_value(n_1);
    }

    return is_prime;
}

int kryptos_mp_fermat_test(const kryptos_mp_value_t *n, const int k) {
    kryptos_mp_value_t *a = NULL, *n_1 = NULL, *_1 = NULL, *p_mod = NULL, *n_2 = NULL;
    int i, is_prime = 1;

    if (n == NULL) {
        return 0;
    }

    a = kryptos_hex_value_as_mp("2", 1);

    if (a == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    if (kryptos_mp_le(n, a)) {
        is_prime = kryptos_mp_eq(n, a);
        goto kryptos_mp_fermat_test_epilogue;
    }

    kryptos_del_mp_value(a);
    a = NULL;

    if (kryptos_mp_is_even(n)) { // WARN(Rafael): Almost like that old 80's song "Don't get mad AND AIN'T even..." ;)
        return 0;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    n_1 = kryptos_assign_mp_value(&n_1, n);

    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    n_1 = kryptos_mp_sub(&n_1, _1);

    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    n_2 = kryptos_assign_mp_value(&n_2, n_1);

    if (n_2 == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    n_2 = kryptos_mp_sub(&n_2, _1);

    for (i = 0; i < k && is_prime; i++) {
        a = kryptos_mp_gen_random(n_2);
        a = kryptos_mp_add(&a, _1);

        if (a == NULL) {
            is_prime = 0;
            goto kryptos_mp_fermat_test_epilogue;
        }

        p_mod = kryptos_mp_me_mod_n(a, n_1, n);

        kryptos_del_mp_value(a);
        a = NULL;

        if (p_mod == NULL) {
            is_prime = 0;
            goto kryptos_mp_fermat_test_epilogue;
        }

        is_prime = kryptos_mp_eq(p_mod, _1);

        kryptos_del_mp_value(p_mod);
        p_mod = NULL;
    }

kryptos_mp_fermat_test_epilogue:

    // INFO(Rafael): Housekeeping

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (p_mod != NULL) {
        kryptos_del_mp_value(p_mod);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (n_1 != NULL) {
        kryptos_del_mp_value(n_1);
    }

    if (n_2 != NULL) {
        kryptos_del_mp_value(n_2);
    }

    // INFO(Rafael): If you have picked only Fermat liars, sorry! ;)
    return is_prime;
}

kryptos_mp_value_t *kryptos_mp_lsh(kryptos_mp_value_t **a, const int level) {
    int l;
    ssize_t d;
    kryptos_u8_t cb, lc;
    kryptos_mp_value_t *t = NULL;

    if (a == NULL || (*a) == NULL) {
        return NULL;
    }

    t = kryptos_new_mp_value((((*a)->data_size) << 3) + level);

    if (t == NULL) {
        goto kryptos_mp_lsh_epilogue;
    }

    t = kryptos_assign_mp_value(&t, *a);

    for (l = 0; l < level; l++) {
        cb = lc = 0;
        for (d = 0; d < t->data_size; d++, lc = cb) {
            cb = t->data[d] >> 7;
            t->data[d] = (t->data[d] << 1) | lc;
        }
    }

kryptos_mp_lsh_epilogue:

    kryptos_del_mp_value(*a);
    *a = t;

    return (*a);
}

kryptos_mp_value_t *kryptos_mp_rsh(kryptos_mp_value_t **a, const int level) {
    int l;
    ssize_t d, dn;
    kryptos_u8_t cb, lc;
    kryptos_mp_value_t *t = NULL;

    if (a == NULL || (*a) == NULL) {
        return NULL;
    }

    t = kryptos_new_mp_value((((*a)->data_size) << 3));

    if (t == NULL) {
        return NULL;
    }

    t = kryptos_assign_mp_value(&t, *a);

    for (l = 0; l < level; l++) {
        cb = lc = 0;
        for (d = t->data_size - 1; d >= 0; d--, lc = cb) {
            cb = t->data[d] & 1;
            t->data[d] = (t->data[d] >> 1) | (lc << 7);
        }
    }

kryptos_mp_rsh_epilogue:

    kryptos_del_mp_value(*a);

    (*a) = kryptos_new_mp_value(t->data_size << 3);

    d = 0;
    while (d < t->data_size) {
        (*a)->data[d] = t->data[d];
        d++;
    }

    kryptos_del_mp_value(t);

    return (*a);
}

kryptos_mp_value_t *kryptos_mp_gen_prime(const size_t bitsize, const int fast_method) {
    kryptos_mp_value_t *pn = NULL;
    ssize_t d;
    int is_prime = 0;

    pn = kryptos_new_mp_value(bitsize);

    if (pn == NULL) {
        return NULL;
    }

    while (!is_prime) {
        for (d = 0; d < pn->data_size; d++) {
            pn->data[d] = kryptos_get_random_byte();
        }

        pn->data[0] |= 0x1;

        if (!fast_method) {
            is_prime = kryptos_mp_is_prime(pn);
        } else {
            // INFO(Rafael): The Miller-Rabin tends to converge sooner than Fermat.
            is_prime = kryptos_mp_miller_rabin_test(pn, 14);
        }
    }

    return pn;
}

kryptos_mp_value_t *kryptos_mp_gen_prime_2k1(const size_t k_bitsize) {
    // INFO(Rafael): This function will generate a p = 2k + 1. k is also a prime.
    kryptos_mp_value_t *k = NULL;
    kryptos_mp_value_t *p = NULL, *_2 = NULL, *_1 = NULL;
    int is_prime = 0;

    if ((_1 = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        goto kryptos_mp_gen_prime_2k1_epilogue;
    }

    if ((_2 = kryptos_hex_value_as_mp("2", 1)) == NULL) {
        goto kryptos_mp_gen_prime_2k1_epilogue;
    }

    do {
        if ((k = kryptos_mp_gen_prime(k_bitsize, 0)) == NULL) {
            goto kryptos_mp_gen_prime_2k1_epilogue;
        }
printf("k = ");print_mp(k);
        if ((p = kryptos_assign_mp_value(&p, k)) == NULL) {
            goto kryptos_mp_gen_prime_2k1_epilogue;
        }

        if ((p = kryptos_mp_mul(&p, _2)) == NULL) {
            goto kryptos_mp_gen_prime_2k1_epilogue;
        }

        if((p = kryptos_mp_add(&p, _1)) == NULL) {
            goto kryptos_mp_gen_prime_2k1_epilogue;
        }
printf("p = ");print_mp(p);
        kryptos_del_mp_value(k);
        k = NULL;

        if ((is_prime = kryptos_mp_is_prime(p)) == 0) {
            kryptos_del_mp_value(p);
            p = NULL;
        }

    } while (!is_prime);


kryptos_mp_gen_prime_2k1_epilogue:

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (_2 != NULL) {
        kryptos_del_mp_value(_2);
    }

    if (k != NULL) {
        kryptos_del_mp_value(k);
    }

    if (!is_prime && p != NULL) {
        kryptos_del_mp_value(p);
        p = NULL;
    }

    return p;
}

kryptos_mp_value_t *kryptos_mp_montgomery_reduction(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y) {
    // INFO(Rafael): This calculates ZR mod Y.
    kryptos_mp_value_t *z = NULL, *r = NULL, *b = NULL, *d = NULL;
    kryptos_u8_t buf[255];
    ssize_t rdn, rd;

    if (x == NULL || y == NULL) {
        return NULL;
    }

    if ((z = kryptos_mp_montgomery_reduction_2kx_mod_y(x, y)) == NULL) {
        return NULL;
    }

    b = kryptos_hex_value_as_mp("1", 1);
    b = kryptos_mp_lsh(&b, x->data_size << 3);
//printf("DIV1-BEGIN\n");
    if ((d = kryptos_mp_div(b, y, &r)) == NULL) {
        goto kryptos_mp_montgomery_reduction_epilogue;
    }
//printf("x = "); print_mp(x);
//printf("d = "); print_mp(d);
//printf("r = "); print_mp(r);
//printf("z = "); print_mp(z);
//printf("DIV1-END\n");
    kryptos_del_mp_value(d);

    if ((z = kryptos_mp_mul(&z, r)) == NULL) {
        goto kryptos_mp_montgomery_reduction_epilogue;
    }

    kryptos_del_mp_value(r);
    r = NULL;
//printf("z = ");print_mp(z);
//printf("y = ");print_mp(y);
//printf("DIV2-BEGIN\n");
    if ((d = kryptos_mp_div(z, y, &r)) == NULL) {
        goto kryptos_mp_montgomery_reduction_epilogue;
    }
//printf("DIV2-END\n");
    kryptos_del_mp_value(d);

    if (r != NULL) {
        for (rdn = r->data_size - 1; rdn >= 0 && r->data[rdn] == 0; rdn--)
            ;

        if (rdn > - 1) {
            d = r;
            r = kryptos_new_mp_value((rdn + 1) << 3);
            for (rd = 0; rd <= rdn; rd++) {
                r->data[rd] = d->data[rd];
            }
            kryptos_del_mp_value(d);
        }
    }

kryptos_mp_montgomery_reduction_epilogue:

    if (z != NULL) {
        kryptos_del_mp_value(z);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    return r;
}

static kryptos_mp_value_t *kryptos_mp_montgomery_reduction_2kx_mod_y(const kryptos_mp_value_t *x,
                                                                     const kryptos_mp_value_t *y) {
    // INFO(Rafael): Calculates 2^-K X mod Y. K is the bit length.
    kryptos_mp_value_t *xt = NULL;
    ssize_t k, ks;

    if (x == NULL || y == NULL) {
        return NULL;
    }

    xt = kryptos_assign_mp_value(&xt, x);
    ks = xt->data_size << 3;

    for (k = 0; k < ks; k++) {
        if (kryptos_mp_is_odd(xt)) {
            xt = kryptos_mp_add(&xt, y);
        }
        xt = kryptos_mp_rsh(&xt, 1);
    }

    if (kryptos_mp_ge(xt, y)) {
        xt = kryptos_mp_sub(&xt, y);
    }

    return xt;
}

kryptos_mp_value_t *kryptos_mp_gcd(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    kryptos_mp_value_t *x = NULL, *y = NULL;
    kryptos_mp_value_t *g = NULL, *t = NULL, *gcd = NULL, *_0 = NULL;

    if (a == NULL || b == NULL) {
        return NULL;
    }

    if (kryptos_mp_gt(a, b)) {
        x = kryptos_assign_mp_value(&x, a);
        y = kryptos_assign_mp_value(&y, b);
    } else {
        x = kryptos_assign_mp_value(&x, b);
        y = kryptos_assign_mp_value(&y, a);
    }

    if ((g = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        goto kryptos_mp_gcd_epilogue;
    }

    while (kryptos_mp_is_even(x) && kryptos_mp_is_even(y)) {
        x = kryptos_mp_rsh(&x, 1);
        y = kryptos_mp_rsh(&y, 1);
        g = kryptos_mp_lsh(&g, 1);
    }

    if ((_0 = kryptos_hex_value_as_mp("0", 1)) == NULL) {
        goto kryptos_mp_gcd_epilogue;
    }

    while (kryptos_mp_ne(x, _0)) {
        while (kryptos_mp_is_even(x)) {
            x = kryptos_mp_rsh(&x, 1);
        }

        while (kryptos_mp_is_even(y)) {
            y = kryptos_mp_rsh(&y, 1);
        }

        if (kryptos_mp_lt(y, x)) {
            t = kryptos_assign_mp_value(&t, x);
            t = kryptos_mp_sub(&t, y);
        } else {
            t = kryptos_assign_mp_value(&t, y);
            t = kryptos_mp_sub(&t, x);
        }

        t = kryptos_mp_rsh(&t, 1);

        if (kryptos_mp_ge(x, y)) {
            x = kryptos_assign_mp_value(&x, t);
        } else {
            y = kryptos_assign_mp_value(&y, t);
        }
    }

    gcd = kryptos_assign_mp_value(&gcd, g);
    gcd = kryptos_mp_mul(&gcd, y);

kryptos_mp_gcd_epilogue:

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    if (t != NULL) {
        kryptos_del_mp_value(t);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    return gcd;
}

#undef kryptos_mp_xnb

#undef kryptos_mp_nbx

#undef kryptos_mp_max_min

#undef KRYPTOS_MP_MULTIBYTE_FLOOR

#undef kryptos_mp_get_u32_from_mp

#undef kryptos_mp_put_u32_into_mp
