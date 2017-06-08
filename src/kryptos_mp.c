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
        (*dest)->data = (kryptos_u8_t *) kryptos_newseg(src->data_size << 3);
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
        //(*dest) = kryptos_new_mp_value(src->data_size << 3);
        //memcpy((*dest)->data, src->data, src->data_size);
        //return (*dest);
        (*dest) = kryptos_assign_mp_value(dest, src);
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
        bsum = a->data[d] + ( (d < b->data_size) ? b->data[d] : 0 ) + c;
//printf("[BSUM = %X]\n", bsum);
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

void print_mp(const kryptos_mp_value_t *v) {
    ssize_t d;
    for (d = v->data_size - 1; d >= 0; d--) printf("%.2X", v->data[d]);
    printf("\n");
}

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

//    printf("q = ");print_mp(q);
    curr_x = kryptos_new_mp_value(x->data_size << 3);
//    printf("curr_x = ");print_mp(curr_x);
//    printf("x = ");print_mp(x);

    _1 = kryptos_hex_value_as_mp("1", 1);

    for (d = x->data_size - 1; d >= 0; d--) {
        curr_x->data[0] = x->data[d];
        if (kryptos_mp_ge(curr_x, y)) {
//            printf("CURR_X => "); print_mp(curr_x);
            do {
                div_nr++;
                sy = kryptos_hex_value_as_mp("0", 1);
                i = kryptos_hex_value_as_mp("0", 1);
//                printf("\tINITIAL-SY'(%d) = ", sy->data_size); print_mp(sy);
//                printf("\tINITIAL-I'(%d) = ", i->data_size); print_mp(i);
                while (kryptos_mp_le(sy, curr_x)) {
                    sy = kryptos_mp_add(&sy, y);
                    i = kryptos_mp_add(&i, _1);
//                    printf("\tSY' = "); print_mp(sy);
//                    printf("\tI' = "); print_mp(i);
                }

                i = kryptos_mp_sub(&i, _1);
                sy = kryptos_mp_sub(&sy, y);

//                printf("\tNEXT-CURR-X = "); print_mp(curr_x);
//                printf("\tSY = "); print_mp(sy);
                curr_x = kryptos_mp_sub(&curr_x, sy);
//                printf("\tNEXT-CURR-X' = "); print_mp(curr_x);
                for (di = i->data_size - 1; di >= 0; di--) {
                    q = kryptos_mp_lsh(&q, 8);
                    q->data[0] = i->data[di];
                }

                kryptos_del_mp_value(sy);
                kryptos_del_mp_value(i);
                sy = i = NULL;
//                printf("Q' = "); print_mp(q);
            } while (kryptos_mp_ge(curr_x, y)); // INFO(Rafael): While is possible to divide... go into the loop again.
            curr_x = kryptos_mp_lsh(&curr_x, 8); // INFO(Rafael): Opens one position for the next digit.
        } else {
            curr_x = kryptos_mp_lsh(&curr_x, 8); // INFO(Rafael): Opens one position for the next digit.
            if (div_nr > 0) {
                q = kryptos_mp_lsh(&q, 8); // INFO(Rafael): The curr_x is not enough for dividing (curr_x < y).
                                           //               Thus, adds one digit zero to the quocient before getting
                                           //               the next digit from x.
            }
        }
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (r != NULL) {
        // INFO(Rafael): Reverting the remainder because there is nothing to get from x anymore.
        curr_x = kryptos_mp_rsh(&curr_x, 8);
        (*r) = curr_x;
    } else {
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

    r_div = kryptos_mp_div(r, n, &r_mod);

    kryptos_del_mp_value(r);

    kryptos_del_mp_value(r_div);

    return r_mod;
}

int kryptos_mp_is_prime(const kryptos_mp_value_t *n) {
    int is_prime = kryptos_mp_fermat_test(n, 7);

    if (is_prime) {
        // INFO(Rafael): Avoiding Carmichel's numbers.
        is_prime = kryptos_mp_miller_rabin_test(n, 14);
    }

    return is_prime;
}

int kryptos_mp_miller_rabin_test(const kryptos_mp_value_t *n, const int sn) {
    kryptos_mp_value_t *k = NULL, *m = NULL, *n_1 = NULL, *_1 = NULL, *_0 = NULL, *b = NULL,
                       *e = NULL, *p = NULL, *n_div = NULL, *n_mod = NULL, *a = NULL;
    int is_prime = 1;
    int s;

    if (n == NULL) {
        return 0;
    }

    if (kryptos_mp_is_even(n)) {
        return 0;
    }

    a = kryptos_hex_value_as_mp("2", 1);

    if (kryptos_mp_eq(n, a)) {
        goto kryptos_mp_miller_rabin_epilogue;
    }

    // INFO(Rafael): Setting up some initial values.

    _1 = kryptos_hex_value_as_mp("1", 1); // 1.
    if (_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_epilogue;
    }

    n_1 = kryptos_assign_mp_value(&n_1, n);
    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_epilogue;
    }

    // INFO(Rafael): Step 1, finding n - 1, m and k.

    n_1 = kryptos_mp_sub(&n_1, _1); // n - 1.
    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_epilogue;
    }

    // INFO(Rafael): Now k and m.

    _0 = kryptos_hex_value_as_mp("0", 1);

    b = kryptos_hex_value_as_mp("2", 1);
    e = kryptos_hex_value_as_mp("1", 1);
    p = kryptos_mp_pow(b, e);
    n_div = kryptos_mp_div(n_1, p, &n_mod); // INFO(Rafael): Maybe it should be replaced by "n_1 << e".

    do {
        // INFO(Rafael): Initially always should enter into this loop because n - 1 mod 2^1 is zero (n should be > 2 and odd).
        m = kryptos_assign_mp_value(&m, n_div); // temp m.
        k = kryptos_assign_mp_value(&k, e); // temp k.
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(n_div);
        kryptos_del_mp_value(n_mod);
        p = n_div = n_mod = NULL;
        e = kryptos_mp_add(&e, _1);
        p = kryptos_mp_pow(b, e);
        n_div = kryptos_mp_div(n_1, p, &n_mod); // INFO(Rafael): Maybe it should be replaced by "n_1 << e".
    } while (kryptos_mp_eq(n_mod, _0));

    kryptos_del_mp_value(p);
    kryptos_del_mp_value(n_div);
    kryptos_del_mp_value(n_mod);
    kryptos_del_mp_value(e);
    e = p = n_div = n_mod = NULL;

    // INFO(Rafael): Now we got n - 1 = 2^k x m.

    // INFO(Rafael): Step 2, guessing a. Where 1 < a < n - 1.

    p = kryptos_assign_mp_value(&p, n_1);
    p = kryptos_mp_sub(&p, _1); // n - 2.
    if (!kryptos_mp_eq(p, _1)) {
        do {
            if (a != NULL) {
                kryptos_del_mp_value(a);
            }
            a = kryptos_mp_gen_random(p);
        } while kryptos_mp_le(a, _1);
    } else {
        a = kryptos_assign_mp_value(&a, p);
    }
    kryptos_del_mp_value(p);
    p = NULL;

    // INFO(Rafael): Step 3, b0 = a^m mod n.
    p = kryptos_mp_pow(a, m);
    n_div = kryptos_mp_div(p, n, &n_mod);

    is_prime = kryptos_mp_eq(n_mod, _1) || kryptos_mp_eq(n_mod, n_1); // INFO(Rafael): n - 1 means "-1".

    if (!is_prime) {
        e = kryptos_hex_value_as_mp("2", 1);
        // INFO(Rafael): The last test failed let's calculate b_s .. b_sn.
        //               If bs = a^2 mod n = 1 is composite, -1 is prime, otherwise go ahead trying until s = sn.
        for (s = 0; s < sn && !is_prime; s++) {
            kryptos_del_mp_value(p);
            p = kryptos_mp_pow(n_mod, e); // INFO(Rafael): b_s-1 ^ 2.
            kryptos_del_mp_value(n_div);
            kryptos_del_mp_value(n_mod);
            n_mod = NULL;
            n_div = kryptos_mp_div(p, n, &n_mod); // bs = a^2 mod n.

            if (kryptos_mp_eq(n_mod, _1)) {
                // INFO(Rafael): Nevermind, it is composite.
                goto kryptos_mp_miller_rabin_epilogue;
            }

            is_prime = kryptos_mp_eq(n_mod, n_1);
        }
    }

kryptos_mp_miller_rabin_epilogue:

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
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
    kryptos_mp_value_t *a = NULL, *n_1 = NULL, *_1 = NULL, *p = NULL, *p_div = NULL, *p_mod = NULL, *n_2 = NULL;
    int i, is_prime = 1;

    if (n == NULL) {
        return 0;
    }

    a = kryptos_hex_value_as_mp("2", 1);

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
        return 0;
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

        p = kryptos_mp_pow(a, n_1);

        kryptos_del_mp_value(a);
        a = NULL;

        if (p == NULL) {
            is_prime = 0;
            goto kryptos_mp_fermat_test_epilogue;
        }

        p_div = kryptos_mp_div(p, n, &p_mod);

        if (p_div == NULL || p_mod == NULL) {
            is_prime = 0;
            goto kryptos_mp_fermat_test_epilogue;
        }

        is_prime = kryptos_mp_eq(p_mod, _1);

        kryptos_del_mp_value(p);
        kryptos_del_mp_value(p_div);
        kryptos_del_mp_value(p_mod);

        p = p_div = p_mod = NULL;
    }

kryptos_mp_fermat_test_epilogue:

    // INFO(Rafael): Housekeeping

    if (a != NULL) {
        kryptos_del_mp_value(a);
        a = NULL;
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (p_div != NULL) {
        kryptos_del_mp_value(p_div);
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
        return NULL;
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
        goto kryptos_mp_rsh_epilogue;
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

    for (dn = 0; dn < t->data_size && t->data[dn] != 0; dn++)
        ;

    kryptos_del_mp_value(*a);

    (*a) = kryptos_new_mp_value((dn + (dn == 0)) << 3);

    d = 0;
    while (d <= dn) {
        (*a)->data[d] = t->data[d];
        d++;
    }

    kryptos_del_mp_value(t);

    return (*a);
}

#undef kryptos_mp_xnb

#undef kryptos_mp_nbx

#undef kryptos_mp_max_min
