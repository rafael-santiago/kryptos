/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_mp.h>
#include <kryptos_memory.h>
#include <string.h>
#include <ctype.h>

// 'Hexadecimals. Hexadecimals to the rescue.'
//              -- Mark Watney (The Martian)

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

kryptos_mp_value_t *kryptos_new_mp_value(const size_t bitsize) {
    kryptos_mp_value_t *mp;

//    if (bitsize < 8) {
//        return NULL;
//    }

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

    mp->data_size =  mp->data_size >> 3;

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

    while (vp < vp_end) {
        nb = 0;
        if (vp + 1 != vp_end) {
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

    sum = kryptos_new_mp_value((src->data_size + (*dest)->data_size) << 3);

    if (sum == NULL) {
        return NULL;
    }

    kryptos_mp_max_min(a, b, (*dest), src);

    d = s = 0;
    c = 0;

    while (d < a->data_size) {
        bsum = (*dest)->data[d] + ( (d < src->data_size) ? src->data[d] : 0 ) + c;
        c = (bsum > 0xFF);
        sum->data[s] = bsum & 0xFF;
        s++;
        d++;
    }

    if (c > 0 && s < sum->data_size) {
        sum->data[s] = c;
    }

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

    delta = kryptos_new_mp_value((src->data_size + (*dest)->data_size) << 3);

    if (delta == NULL) {
        return NULL;
    }

    d = s = 0;
    c = 0;
    dn = ((*dest)->data_size > src->data_size) ? (*dest)->data_size : src->data_size;

    while (d < dn) {
        bsub = ( (d < (*dest)->data_size) ? (*dest)->data[d] : 0 ) - ( (d < src->data_size) ? src->data[d] : 0 ) + c;
        //printf("X = %x / Y = %x / c = %x / BSUB = %x / BYTE-SUB = %x\n", (*dest)->data[d], src->data[d], c, bsub, bsub & 0xFF);
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

    for (sn = delta->data_size - 1; sn >= 0 && delta->data[sn] == 0; sn--)
        ;

    (*dest)->data_size = (sn < delta->data_size) ? sn + 1 : delta->data_size;
    kryptos_freeseg((*dest)->data);

    (*dest)->data = (kryptos_u8_t *) kryptos_newseg((*dest)->data_size);
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

kryptos_mp_value_t *kryptos_mp_mul(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    size_t bitsize, r, rn;
    kryptos_mp_value_t **a;
    const kryptos_mp_value_t *x, *y;
    ssize_t xd, yd;
    short bmul;
    kryptos_u8_t c;
//    ssize_t rd;

    if (src == NULL || dest == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(src->data_size << 3);
        memcpy((*dest)->data, src->data, src->data_size);
        return (*dest);
    }

    // CLUE(Rafael): Encantamentos baseados em algumas propriedades que talvez a tia Tetéia não quis te contar.

    if ((*dest) != NULL) {
        bitsize = ((*dest)->data_size + src->data_size + 1) << 3;
    } else {
        bitsize = (src->data_size + 1) << 4;
    }

    kryptos_mp_max_min(x, y, (*dest), src);

    a = (kryptos_mp_value_t **) kryptos_newseg(sizeof(kryptos_mp_value_t **) * y->data_size);

    for (r = 0; r < y->data_size; r++) {
        a[r] = kryptos_new_mp_value(bitsize);
    }

    // CLUE(Rafael): Multiplicando igual na aula da tia Tetéia.
    for (yd = 0, r = 0; yd < y->data_size; yd++, r++) {
        c = 0;
        for (xd = 0; xd < x->data_size; xd++) {
            bmul = y->data[yd] * x->data[xd] + c;
            c = (bmul >> 8);
            a[r]->data[xd + r] = (bmul & 0xFF);
//            printf("X = %x / Y = %x / c = %x / BMUL = %x / BYTE-SUB = %x\n", x->data[xd], y->data[yd], c, bmul, bmul & 0xFF);
        }

        if ((xd + r) < a[r]->data_size) {
            a[r]->data[xd + r] += c;
        }
    }
/*
    for (r = 0; r < y->data_size; r++) {
        printf("A[%2d] = ", r);
        for (rd = a[r]->data_size - 1; rd >= 0; rd--) printf("%.2X ", a[r]->data[rd]);
        printf("\n");
    }
*/
    kryptos_del_mp_value((*dest));
    (*dest) = NULL;

    for (r = 0; r < y->data_size; r++) {
        // CLUE(Rafael): Somando as multiplicações igual na aula da tia Tetéia.

        // INFO(Rafael): Maybe it should be done inside the inner loop. In the first bmul expr. A tia Tetéia nos daria zero, pois é
        //               ofuscado pra cacete. O tio Pressman teria um treco, pois não estariamos reutilizando a callstack Hahah.
        //               Eita maldade, the zueira never ends.
        (*dest) = kryptos_mp_add(dest, a[r]);
    }

    // INFO(Rafael): Housekeeping.

    for (r = 0; r < y->data_size; r++) {
        kryptos_del_mp_value(a[r]);
    }

    kryptos_freeseg(a);

    bitsize = r = rn = 0;
    bmul = 0;
    c = 0;

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

#undef kryptos_mp_xnb

#undef kryptos_mp_nbx

#undef kryptos_mp_max_min
