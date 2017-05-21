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
#include <string.h>
#include <ctype.h>

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

    // CLUE(Rafael): Encantamentos baseados em algumas propriedades que talvez a tia Tetéia não quis te contar.

    m = kryptos_new_mp_value(((*dest)->data_size + src->data_size + 1) << 3);

    if (m == NULL) {
        // WARN(Rafael): Better let a memory leak than return a wrong result.
        return NULL;
    }

    kryptos_mp_max_min(x, y, (*dest), src);

    // CLUE(Rafael): Multiplicando igual na aula da tia Tetéia.

    for (yd = 0, r = 0; yd < y->data_size; yd++, r++) {
        mc = 0;
        ac = 0;

        for (xd = 0; xd < x->data_size; xd++) {
            bmul = y->data[yd] * x->data[xd] + mc;
            mc = (bmul >> 8);
            // INFO(Rafael): "Parallelizing" the multiplications sum in order to not call kryptos_mp_add() x->data_size times.
            //               Besides time it will also save memory.
            //
            //               Somando as multiplicações igual na aula da tia Tetéia, mas de uma forma não usual para Humanos.
            //               A tia Tetéia vai nos dar um zero, pois é ofuscado pra cacete. O tio Pressman já teve um treco,
            //               pois não estamos Re-u-ti-li-zan-do a... callstack, chamando kryptos_mp_add() x->data_size vezes.
            //               Hahah!! The zueira never ends.
            //
            //               Mas sério: uma coisa é fazer algo fácil de entender quando dá para fazer, outra coisa é subutilizar
            //               o Hardware em prol de gente preguiçosa que não consegue pensar fora da caixa. Um programa
            //               tem acima de tudo que fazer de forma mais eficiente o que se presta, código é para ser executado.
            //               A CPU não se importa se vai bufferizar cada multiplicação ou executá-las de forma "paralela".
            //               Mas tem uma forma (um tanto peculiar) de protestar, executando mais lentamente, a forma menos
            //               indicada segundo ela. E programamos acima de tudo para ela, pois é ela quem executa o que está
            //               abstraído aqui em prol de usuários seres Humanos. ;)
            bsum = m->data[xd + r] + (bmul & 0xFF) + ac;
            ac = (bsum > 0xFF);
            m->data[xd + r] = (bsum & 0xFF);
        }

        if ((xd + r) < m->data_size) {
            m->data[xd + r] = (m->data[xd + r] + mc + ac) & 0xFF;
        }
    }

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

kryptos_mp_value_t *kryptos_mp_pow(kryptos_mp_value_t *b, const kryptos_mp_value_t *e) {
    kryptos_mp_value_t *ee = NULL, *one = NULL, *pow = NULL, *zero = NULL;

    if (b == NULL || e == NULL) {
        return NULL;
    }

    one = kryptos_hex_value_as_mp("1", 1);
    zero = kryptos_new_mp_value(e->data_size << 3);

    ee = kryptos_assign_mp_value(&ee, e);

    // INFO(Rafael): Seeking more precision.
    pow = kryptos_new_mp_value(b->data_size << 3);
    pow->data[0] = 1;

    while (kryptos_mp_ne(ee, zero)) {
        pow = kryptos_mp_mul(&pow, b);

        ee = kryptos_mp_sub(&ee, one);
    }

    if (one != NULL) {
        kryptos_del_mp_value(one);
    }

    if (zero != NULL) {
        kryptos_del_mp_value(zero);
    }

    if (ee != NULL) {
        kryptos_del_mp_value(ee);
    }

    return pow;
}

/*
kryptos_mp_value_t *kryptos_mp_div_slow(kryptos_mp_value_t *dest,
                                        const kryptos_mp_value_t *src, kryptos_mp_value_t **remainder) {
    kryptos_mp_value_t *q, *r, *one;

    // TODO(Rafael): This is pretty slow. Optimize it.

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    if (kryptos_mp_lt(dest, src)) {
        if (remainder != NULL) {
            (*remainder) = NULL;
        }

        return kryptos_hex_value_as_mp("0", 1);
    }

    one = kryptos_hex_value_as_mp("1", 1);

    r = NULL;
    r = kryptos_assign_mp_value(&r, dest);

    q = NULL;

    while (kryptos_mp_ge(r, src)) {
        r = kryptos_mp_sub(&r, src);
        q = kryptos_mp_add(&q, one);
    }

    kryptos_del_mp_value(one);

    if (remainder != NULL) {
        (*remainder) = r;
    } else {
        kryptos_del_mp_value(r);
    }

    return q;
}
*/

kryptos_mp_value_t *kryptos_mp_div(kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **r) {
    // WARN(Rafael): This algorithm is expensive. However, less expensive than sucessive subtractions. If you really
    //               need to use standard divisions you should find a better solution. Standard division is not
    //               a relevant thing for the library's scope.

    kryptos_mp_value_t *p = NULL, *qd = NULL, *qu = NULL, *_1 = NULL, *q = NULL;
    ssize_t qi, xi;
    kryptos_u8_t msb;
    int q_found = 0;

    if (x == NULL || y == NULL) {
        return NULL;
    }

    q_found = 1;
    for (xi = y->data_size - 1; xi >= 0 && q_found; xi--) {
        q_found = (y->data[xi] == 0);
    }

    if (q_found) {
        // WARN(Rafael): Division by zero.
        return NULL;
    }

    q_found = 1;
    for (xi = x->data_size - 1; xi >= 0 && q_found; xi--) {
        q_found = (x->data[xi] == 0);
    }

    if (q_found) {
        // WARN(Rafael): 0 / (y > 0).
        if (r != NULL) {
            (*r) = kryptos_new_mp_value(x->data_size << 3);
        }
        return kryptos_new_mp_value(x->data_size << 3);
    }

    // CLUE(Rafael): My approach here is based on finding the bit-size of the quotient and its first byte.
    //               Having this info, I use two search windows. One is decreased (down window) and another
    //               is increased (up window).
    //
    //               For each search step, all that should be done is multiply the divisior by the window and check
    //               if it is less than or greater than (depending on the window type [i.e.: up, down]).
    //
    //               Once one of these stop criterias satisfied. The remainder is denoted by |x - p|. Where "p" denotes the
    //               last multiplication calculated into the search loop.
    //
    //               Well, formalizing a little my craziness:
    //
    //               The n is given by: n = number of digits of X - (number of digits of Y - 1). Since we are dividing X by Y.
    //
    //               The first byte of the quotient is denoted by:
    //
    //                          Q_n = { |X_n - Y_nb| | |X_n - Y_nb| & 1 = 0 }
    //                          Q_n = { |X_n - Y_nb| & 0xF | |X_n - Y_nb| & 1 <> 0 }
    //                          Y_nb = (Y_n & 0xF0) | (Y_n >> 4)
    //
    //                The down window is given by: Q_n, X_n - 1 ... X_0
    //
    //                The up window is given by: Q_n, 0, 0, 0, ... 0_0

    // INFO(Rafael): Setting up the "quotient window down".

    qd = kryptos_new_mp_value((x->data_size - (y->data_size - 1)) << 3);

    if (qd == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    xi = x->data_size - 1;
    qi = qd->data_size - 1;

    while (qi >= 0) {
        qd->data[qi] = x->data[xi];
        qi--;
        xi--;
    }

    // INFO(Rafael): Setting up the "quotient window up".

    qu = kryptos_new_mp_value(qd->data_size << 3);

    if (qu == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    // INFO(Rafael): Applying the window down reduction.

    if (y->data_size != x->data_size) {
        msb = (y->data[y->data_size - 1] & 0xF0) | (y->data[y->data_size - 1] >> 4);
        if (msb > x->data[x->data_size - 1]) {
            msb = msb - x->data[x->data_size - 1];
        } else {
            msb = x->data[x->data_size - 1] - msb;
        }
        if (msb & 1) {
            msb = msb & 0xF;
        }
        qd->data[qd->data_size - 1] = msb;
    }

    // INFO(Rafael): Applying the window up reduction.

    qu->data[qu->data_size - 1] = qd->data[qd->data_size - 1];

    xi = qi = 0;

    // INFO(Rafael): Looping over the reduced search spaces (backward and forward).

    q = qd;
    p = kryptos_assign_mp_value(&p, qd);
    p = kryptos_mp_mul(&p, y);
    q_found = kryptos_mp_lt(p, x);

    while (!q_found) {
        q = qu;

        p = kryptos_assign_mp_value(&p, qu);
        p = kryptos_mp_mul(&p, y);
        q_found = kryptos_mp_gt(p, x) == 0;

        if (q_found) {
            continue;
        }

        qu = kryptos_mp_add(&qu, _1);

        q = qd;
        qd = kryptos_mp_sub(&qd, _1);

        p = kryptos_assign_mp_value(&p, qd);
        p = kryptos_mp_mul(&p, y);

        q_found = kryptos_mp_le(p, x);
    }

    if (r != NULL) {
        (*r) = NULL;
        (*r) = kryptos_assign_mp_value(r, x);
        (*r) = kryptos_mp_sub(r, p);
    }

kryptos_mp_div_epilogue:

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (qd != NULL && q != qd) {
        kryptos_del_mp_value(qd);
    }

    if (qu != NULL && q != qu) {
        kryptos_del_mp_value(qu);
    }

    return q;
}

//kryptos_mp_value_t *kryptos_mp_div_crazy(kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **remainder) {
//    kryptos_mp_value_t *q = NULL, *r = NULL, *yb_nt = NULL, *yb = NULL, *xx = NULL, *yy = NULL, *b = NULL, *nt = NULL, *q_it_1 = NULL, *yb_it_1 = NULL, *it_1 = NULL;
//    size_t bitsize = 0;
//    kryptos_u8_t xb[255];
//    ssize_t i, t;
//
//    if (x == NULL || y == NULL) {
//        return NULL;
//    }
//
//    xx = kryptos_assign_mp_value(&xx, x);
//    yy = kryptos_assign_mp_value(&yy, y);
//
//    bitsize = ((xx->data_size > yy->data_size) ? xx->data_size - yy->data_size :
//                                                 yy->data_size - xx->data_size) << 3;
//    //r = kryptos_new_mp_value(bitsize);
//    b = kryptos_hex_value_as_mp("FF", 2);
//
//    yb_nt = kryptos_assign_mp_value(&yb_nt, y);
//    yb_nt = kryptos_assign_mp_value(&yb_nt, b);
//    yb = kryptos_assign_mp_value(&yb, yb_nt);
//
//    kryptos_u64_to_hex(xb, sizeof(xb) - 1, (kryptos_u64_t) (bitsize >> 3) /*INFO(Rafael): Size in bytes (sic).*/);
//    nt = kryptos_hex_value_as_mp(xb, strlen(xb));
//
//    yb_nt = kryptos_mp_pow(yb_nt, nt);
//
//    if (xx == NULL || yy == NULL || b == NULL) {
//        goto kryptos_mp_div_epilogue;
//    }
//
//    q = kryptos_new_mp_value(xx->data_size << 3);
//
//    while (kryptos_mp_ge(xx, yb_nt)) {
//        q->data[q->data_size - 1] += 1;
//        xx = kryptos_mp_sub(&xx, yb_nt);
//    }
//
//    i = xx->data_size - 1;
//    t = yy->data_size - 1;
//
//    while (i >= (t + 1)) {
//        if (xx->data[i] == yy->data[t]) {
//            q->data[i - t - 1] = 0xFE;
//        } else {
//            q->data[i - t - 1] = (xx->data[i] * 0xFF + xx->data[i - 1]) / yy->data[t];
//        }
//
//        while (xx->data[i - t - 1] * (yy->data[t] * 0xFF + yy->data[t - 1]) >
//                    xx->data[i] * 0xFE01 + xx->data[i - 1] * 0xFF + xx->data[i - 2]) {
//            q->data[i - t - 1] -= 1;
//        }
//
//        kryptos_u64_to_hex(xb, sizeof(xb) - 1, (kryptos_u64_t) q->data[i - t - 1]);
//        q_it_1 = kryptos_hex_value_as_mp(xb, strlen(xb));
//
//        kryptos_u64_to_hex(xb, sizeof(xb) - 1, (kryptos_u64_t) i - t - 1);
//        it_1 = kryptos_hex_value_as_mp(xb, strlen(xb));
//
//        yb_it_1 = kryptos_mp_pow(yb, it_1);
//
//        q_it_1 = kryptos_mp_mul(&q_it_1, yb_it_1);
//
//        xx = kryptos_mp_sub(&xx, q_it_1);
//
//        if ((xx->data[xx->data_size - 1] >> 4) == 0xF) { // x < 0
//            xx = kryptos_mp_add(&xx, yb_it_1);
//            q->data[i - t - 1] -= 1;
//        }
//
//        kryptos_del_mp_value(q_it_1);
//        kryptos_del_mp_value(it_1);
//        kryptos_del_mp_value(yb_it_1);
//        q_it_1 = it_1 = yb_it_1 = NULL;
//
//        i--;
//        t--;
//    }
//
//    r = kryptos_assign_mp_value(&r, xx);
//
//kryptos_mp_div_epilogue:
//
//    // INFO(Rafael): Housekeeping.
//
//    if (xx != NULL) {
//        kryptos_del_mp_value(xx);
//    }
//
//    if (yy != NULL) {
//        kryptos_del_mp_value(yy);
//    }
//
//    if (r != NULL) {
//        if (q != NULL && remainder != NULL) {
//            (*remainder) = r;
//        } else {
//            kryptos_del_mp_value(r);
//        }
//    }
//
//    if (b != NULL) {
//        kryptos_del_mp_value(b);
//    }
//
//    if (yb_nt != NULL) {
//        kryptos_del_mp_value(yb_nt);
//    }
//
//    if (yb != NULL) {
//        kryptos_del_mp_value(yb);
//    }
//
//    if (nt != NULL) {
//        kryptos_del_mp_value(nt);
//    }
//
//    return q;
//}

#undef kryptos_mp_xnb

#undef kryptos_mp_nbx

#undef kryptos_mp_max_min
