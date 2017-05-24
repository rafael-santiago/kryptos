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
#include <kryptos_hex.h>
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

kryptos_mp_value_t *kryptos_mp_div(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **r) {
    kryptos_mp_value_t *q = NULL, *yb_e_nt = NULL, *_1 = NULL, *xt = NULL, *q_i_t_1 = NULL, *yb = NULL;
    kryptos_u8_t xb[6535];
    ssize_t i, t, xi, c, cn;
    int less_than_zero = 0, is_zero;

    if (x == NULL || y == NULL) {
        return NULL;
    }

    is_zero = 1;

    for (xi = y->data_size - 1; xi >= 0 && is_zero; xi--) {
        is_zero = (y->data[xi] == 0);
    }

    if (is_zero) {
         // INFO(Rafael): Division by zero.
        if (r != NULL) {
            (*r) = NULL;
        }
        return NULL;
    }

    if (r != NULL) {
        (*r) = NULL;
    }

    if (kryptos_mp_lt(x, y)) {
        if (r != NULL) {
            (*r) = kryptos_assign_mp_value(r, x);
        }
        return kryptos_new_mp_value(8);
    } else if (kryptos_mp_eq(x, y)) {
        if (r != NULL) {
            (*r) = kryptos_new_mp_value(8);
        }
        return kryptos_hex_value_as_mp("1", 1);
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    xb[0] = '0';
    xb[1] = '1';
    cn = x->data_size - y->data_size;

    if (cn > sizeof(xb)) {
        // INFO(Rafael): A hexadecimal with more than 65535 nibbles is a HUGE number and we will not cover it.
        goto kryptos_mp_div_epilogue;
    }

    for (c = 0, xi = 2; c < cn; c++, xi += 2) {
        xb[xi] = '0';
        xb[xi + 1] = '0';
    }
    xb[xi] = 0;

    yb_e_nt = kryptos_hex_value_as_mp(xb, strlen(xb)); // INFO(Rafael): b^n-t.

    if (yb_e_nt == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    // INFO(Rafael): q is automatically zeroed.
    q = kryptos_new_mp_value((x->data_size - y->data_size + 1) << 3);

    if (q == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    // INFO(Rafael): Calculating yb^(n-t).

    yb_e_nt = kryptos_mp_mul(&yb_e_nt, y); // INFO(Rafael): y = yb^n-t.

    if (yb_e_nt == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    xt = kryptos_assign_mp_value(&xt, x);

    if (xt == NULL) {
        goto kryptos_mp_div_epilogue;
    }

//    printf("xt = ");
//    for (i = xt->data_size - 1; i >= 0; i--) printf("%.2X ", xt->data[i]);
//    printf("\n");

    while (kryptos_mp_ge(xt, yb_e_nt)) {
        q->data[q->data_size - 1] += 1;
        xt = kryptos_mp_sub(&xt, yb_e_nt);
//        printf("\tq' = ");
//        for (i = q->data_size - 1; i >= 0; i--) printf("%.2X ", q->data[i]);
//        printf("\n");
    }

    if (q->data_size == 1) {
        goto kryptos_mp_div_epilogue;
    }

    t = y->data_size - 1;

    for (i = xt->data_size - 1; i >= (t + 1); i--) {
        if (xt->data[i] == y->data[t]) {
            q->data[i - t - 1] = 0xFF;
        } else {
            q->data[i - t - 1] = (xt->data[i] * 0x100 + xt->data[i - 1]) / y->data[t];
        }

        while (q->data[i - t - 1] * (y->data[t] * 0x100 + y->data[t - 1]) >
                xt->data[i] * 0x10000 + xt->data[i - 1] * 0x100 + xt->data[i - 2]) {
            q->data[i - t - 1] -= 1;
        }

        kryptos_u64_to_hex(xb, sizeof(xb) - 1, q->data[i - t - 1]);
        q_i_t_1 = kryptos_hex_value_as_mp(xb, strlen(xb)); // INFO(Rafael): q_i - t - 1.

        if (q_i_t_1 == NULL) {
            kryptos_del_mp_value(q);
            q = NULL;
            goto kryptos_mp_div_epilogue;
        }

        xb[0] = '0';
        xb[1] = '1';
        cn = i - t - 1;

        for (c = 0, xi = 2; c < cn; c++, xi += 2) {
            xb[xi] = '0';
            xb[xi + 1] = '0';
        }
        xb[xi] = 0;
        yb = kryptos_hex_value_as_mp(xb, strlen(xb)); // INFO(Rafael): b^i-t-1.

        if (yb == NULL) {
            kryptos_del_mp_value(q);
            q = NULL;
            goto kryptos_mp_div_epilogue;
        }

        yb = kryptos_mp_mul(&yb, y); // INFO(Rafael): yb^i-t-1.

        if (yb == NULL) {
            kryptos_del_mp_value(q);
            q = NULL;
            goto kryptos_mp_div_epilogue;
        }

        q_i_t_1 = kryptos_mp_mul(&q_i_t_1, yb); // INFO(Rafael): q_i - t - 1 * yb^i-t-1.

        if (q_i_t_1 == NULL) {
            kryptos_del_mp_value(q);
            q = NULL;
            goto kryptos_mp_div_epilogue;
        }

        less_than_zero = kryptos_mp_lt(xt, q_i_t_1);

        xt = kryptos_mp_sub(&xt, q_i_t_1); // INFO(Rafael): x = x - q_i - t - 1 * yb^i-t-1.

        if (xt == NULL) {
            kryptos_del_mp_value(q);
            q = NULL;
            goto kryptos_mp_div_epilogue;
        }

        if (less_than_zero) {
            xt = kryptos_mp_add(&xt, yb);

            if (xt == NULL) {
                kryptos_del_mp_value(q);
                q = NULL;
                goto kryptos_mp_div_epilogue;
            }

            q->data[i - t - 1] -= 1;
        }

        kryptos_del_mp_value(q_i_t_1);
        kryptos_del_mp_value(yb);
        q_i_t_1 = yb = NULL;
    }

kryptos_mp_div_epilogue:

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (yb_e_nt != NULL) {
        kryptos_del_mp_value(yb_e_nt);
    }

    if (r != NULL) {
        // INFO(Rafael): Cutting out unused bytes in the remainder.

        is_zero = 1;
        for (cn = xt->data_size - 1; cn >= 0 && is_zero; cn--) {
            is_zero = (xt->data[cn] == 0);
        }

        if (!is_zero) {
            for (cn = xt->data_size - 1; cn >= 0 && xt->data[cn] == 0; cn--)
                ;

            if (cn >= 0) {
                (*r) = kryptos_new_mp_value((cn + 1) << 3);

                for (c = cn; c >= 0; c--) {
                    (*r)->data[c] = xt->data[c];
                }
            } else {
                (*r) = xt;
                xt = NULL;
            }
        } else {
            (*r) = kryptos_new_mp_value(8);
        }
    }

    if (xt != NULL) {
        kryptos_del_mp_value(xt);
    }

    if (q != NULL) {
        // INFO(Rafael): Cutting out unused bytes in the quotient.

        xt = q;

        for (cn = q->data_size - 1; cn >= 0 && q->data[cn] == 0; cn--)
            ;

        if (cn >= 0) {
            q = kryptos_new_mp_value((cn + 1) << 3);

            for (c = cn; c >= 0; c--) {
                q->data[c] = xt->data[c];
            }

            kryptos_del_mp_value(xt);
        }
    }

    return q;
}

kryptos_mp_value_t *kryptos_mp_me_mod_n(const kryptos_mp_value_t *m, const kryptos_mp_value_t *e, const kryptos_mp_value_t *n) {
    kryptos_mp_value_t *me = NULL, *mod_n = NULL, *div = NULL;

    me = kryptos_mp_pow(m, e);

    if (me == NULL) {
        return NULL;
    }

    div = kryptos_mp_div(me, n, &mod_n);

    kryptos_del_mp_value(me);

    if (div == NULL) {
        return NULL;
    }

    kryptos_del_mp_value(div);

    return mod_n;
}

#undef kryptos_mp_xnb

#undef kryptos_mp_nbx

#undef kryptos_mp_max_min
