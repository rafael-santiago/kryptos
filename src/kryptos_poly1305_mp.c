/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_poly1305_mp.h>
#include <kryptos.h>
#if !defined(KRYPTOS_MP_EXTENDED_RADIX) && defined(KRYPTOS_POLY1305_DIV_USING_HEAP)
# include <kryptos_mp.h>
#endif
#if !defined(KRYPTOS_KERNEL_MODE)
# include <ctype.h>
#endif

#if !defined(KRYPTOS_MP_EXTENDED_RADIX) && defined(KRYPTOS_POLY1305_DIV_USING_HEAP)

static void kryptos_poly1305_to_hex(char *xn, const size_t xn_size, const kryptos_poly1305_number_t n);

#endif

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-+
// INFO(Rafael): The following multi-precision functions are totally guided to what Poly1305 needs. Do not use     /
//               them when solving general purposes requirements. It does not allocate memory so values operations |
//               here will not be greater than about 130 bits. On Poly1305, allocate memory into those functions   /
//               becomes a bottleneck due to it I have decided avoid it by re-writing a minimalistic and           |
//               well-contained "multi-precision" functions subset just for Poly.                                  /
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-+

void kryptos_poly1305_add(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y) {
    kryptos_poly1305_overflown_numfrac_t bsum = 0;
    kryptos_poly1305_numfrac_t *xp = &x[0];
    kryptos_poly1305_numfrac_t *xp_end = xp + kKryptosPoly1305NumberSize;
    const kryptos_poly1305_numfrac_t *yp = &y[0];
    const kryptos_poly1305_numfrac_t *yp_end = yp + kKryptosPoly1305NumberSize;
    kryptos_poly1305_number_t s;
    kryptos_poly1305_numfrac_t *sp = &s[0];
    kryptos_poly1305_numfrac_t *sp_end = sp + kKryptosPoly1305NumberSize;
    kryptos_u8_t c = 0;

    memset(s, 0, sizeof(kryptos_poly1305_number_t));

    while (xp != xp_end) {
        bsum = ((kryptos_poly1305_overflown_numfrac_t)(*xp)) + ((kryptos_poly1305_overflown_numfrac_t)(*yp)) + c;
        c = (bsum > kKryptosPoly1305MaxMpDigit);
        *sp = (bsum & kKryptosPoly1305MaxMpDigit);
        xp++;
        yp++;
        sp++;
    }

    if (c > 0 && sp < sp_end) {
        *sp = c;
    }

    memcpy(x, s, sizeof(kryptos_poly1305_number_t));

    memset(s, 0, sizeof(kryptos_poly1305_number_t));
    bsum = 0;
    xp = xp_end = sp = sp_end = NULL;
    yp = yp_end = NULL;
    c = 0;
}

void kryptos_poly1305_sub(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y) {
    kryptos_poly1305_numfrac_t *xp = &x[0];
    kryptos_poly1305_numfrac_t *xp_end = xp + kKryptosPoly1305NumberSize;
    const kryptos_poly1305_numfrac_t *yp = &y[0];
    const kryptos_poly1305_numfrac_t *yp_end = yp + kKryptosPoly1305NumberSize;
    int is_zero = 1;
    kryptos_poly1305_numfrac_t c = 0;
    kryptos_poly1305_overflown_numfrac_t bsub = 0;
    kryptos_poly1305_number_t d;
    kryptos_poly1305_numfrac_t *delta = &d[0];
    kryptos_poly1305_numfrac_t *delta_end = delta + kKryptosPoly1305NumberSize;

    memset(d, 0, sizeof(kryptos_poly1305_number_t));

    while (yp != yp_end && is_zero) {
        is_zero = (*yp == 0);
        yp++;
    }

    if (is_zero) {
        return;
    }

    is_zero = 1;
    while (xp != xp_end && is_zero) {
        is_zero = (*xp == 0);
        xp++;
    }

    if (is_zero) {
        memcpy(x, y, sizeof(kryptos_poly1305_number_t));
        return;
    }

    xp = &x[0];
    yp = &y[0];

    while (xp != xp_end) {
        bsub = ((kryptos_poly1305_overflown_numfrac_t)(*xp) -
                (kryptos_poly1305_overflown_numfrac_t)(*yp)) + (kryptos_poly1305_overflown_numfrac_t)c;
        c += bsub >> (sizeof(kryptos_poly1305_numfrac_t) << 3);
        *delta = bsub & kKryptosPoly1305MaxMpDigit;
        xp++;
        yp++;
        delta++;
    }

    if (c == kKryptosPoly1305MaxMpDigit) {
        kryptos_poly1305_inv_cmplt(d);
    }

    memcpy(x, d, sizeof(kryptos_poly1305_number_t));

    memset(d, 0, sizeof(kryptos_poly1305_number_t));
    delta = delta_end = xp = xp_end = NULL;
    yp = yp_end = NULL;
    is_zero = 0;
    c = bsub = 0;
}

void kryptos_poly1305_inv_cmplt(kryptos_poly1305_number_t x) {
    kryptos_poly1305_number_t _1;
    memset(_1, 0, sizeof(kryptos_poly1305_number_t));
    _1[0] = 1;
    kryptos_poly1305_not(x);
    kryptos_poly1305_add(x, _1);
}

void kryptos_poly1305_not(kryptos_poly1305_number_t x) {
    kryptos_poly1305_numfrac_t *xp = &x[0];
    kryptos_poly1305_numfrac_t *xp_end = xp + kKryptosPoly1305NumberSize;

    while (xp != xp_end) {
        *xp = ~(*xp);
        xp++;
    }
}

void kryptos_poly1305_mul(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y) {
    kryptos_poly1305_numfrac_t *xp = NULL;
    // INFO(Rafael): We are not using the entire mp size (this is always about a 128-bit value).
    kryptos_poly1305_numfrac_t *xp_end = &x[0] + kKryptosPoly1305NumberSize;
    const kryptos_poly1305_numfrac_t *yp = &y[0];
    // INFO(Rafael): We are not using the entire mp size (this is always about a 128-bit value).
    const kryptos_poly1305_numfrac_t *yp_end = yp + kKryptosPoly1305NumberSize;
    kryptos_poly1305_number_t p;
    kryptos_poly1305_numfrac_t *pp = &p[0];
    kryptos_poly1305_numfrac_t *pp_end = pp + kKryptosPoly1305NumberSize;
    kryptos_poly1305_overflown_numfrac_t bsum = 0;
    kryptos_u8_t ac = 0;
    kryptos_poly1305_overflown_numfrac_t bmul = 0;
    kryptos_poly1305_numfrac_t mc = 0;
    size_t x_off = 0, y_off = 0;

    memset(p, 0, sizeof(kryptos_poly1305_number_t));

    while (yp != yp_end) {
        mc = 0;
        ac = 0;
        for (xp = &x[0], x_off = 0; xp != xp_end; xp++, x_off++) {
            bmul = ((kryptos_poly1305_overflown_numfrac_t)(*yp)) *
                   ((kryptos_poly1305_overflown_numfrac_t)(*xp)) + (kryptos_poly1305_overflown_numfrac_t)mc;
            mc = (bmul >> (sizeof(kryptos_poly1305_numfrac_t) << 3));
            bsum = pp[y_off + x_off] + (bmul & kKryptosPoly1305MaxMpDigit) + ac;
            ac = (bsum > kKryptosPoly1305MaxMpDigit);
            pp[y_off + x_off] = (bsum & kKryptosPoly1305MaxMpDigit);
        }

        if ((x_off + y_off) < kKryptosPoly1305NumberSize) {
            pp[x_off + y_off] = (pp[x_off + y_off] + mc + ac) & kKryptosPoly1305MaxMpDigit;
        }

        yp++;
        y_off++;
    }

    memcpy(x, p, sizeof(kryptos_poly1305_number_t));

    xp = xp_end =
    pp = pp_end = NULL;
    yp = yp_end = NULL;
    bsum = bmul = 0;
    ac = 0;
    mc = 0;
    x_off = y_off = 0;
}

void kryptos_poly1305_mul_digit(kryptos_poly1305_number_t x, const kryptos_poly1305_numfrac_t digit) {
    kryptos_poly1305_numfrac_t *xp = &x[0];
    kryptos_poly1305_numfrac_t *xp_end = xp + kKryptosPoly1305NumberSize;
    kryptos_poly1305_numfrac_t mc = 0;
    kryptos_poly1305_overflown_numfrac_t bmul = 0;

    while (xp != xp_end) {
        bmul = (kryptos_poly1305_overflown_numfrac_t)(*xp) *
               (kryptos_poly1305_overflown_numfrac_t)digit +
               (kryptos_poly1305_overflown_numfrac_t)mc;
        mc = (bmul >> (sizeof(kryptos_poly1305_numfrac_t) << 3));
        *xp = (bmul & kKryptosPoly1305MaxMpDigit);
        xp++;
    }

    if (mc > 0) {
        kryptos_poly1305_lsh(x, (sizeof(kryptos_poly1305_numfrac_t) << 3));
        kryptos_poly1305_rsh(x, (sizeof(kryptos_poly1305_numfrac_t) << 3));
        xp[-1] = mc;
    }

    xp = xp_end = NULL;
    mc = 0;
    bmul = 0;
}

#if !defined(KRYPTOS_POLY1305_DIV_USING_HEAP)

void kryptos_poly1305_div(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y, kryptos_poly1305_number_t r) {
    kryptos_poly1305_number_t x_cp, y_cp, b, q, t;
    int is_zero = 0, dec_nr = 0, is_less = 0;
    size_t shlv_nm = 0;
    ssize_t m = 0, n = 0, j = 0, xi = 0;
    kryptos_poly1305_overflown_numfrac_t qtemp = 0;

    memcpy(x_cp, x, sizeof(kryptos_poly1305_number_t));
    memcpy(y_cp, y, sizeof(kryptos_poly1305_number_t));

    for (n = kKryptosPoly1305NumberSize - 1, is_zero = 1; n >= 0 && is_zero; n--) {
        is_zero = (y_cp[n] == 0);
    }

    if (is_zero) {
        memset(x, 0, sizeof(kryptos_poly1305_number_t));
        memset(r, 0, sizeof(kryptos_poly1305_number_t));
        goto kryptos_poly1305_div_epilogue_cleanup;
    }

    for (n = kKryptosPoly1305NumberSize - 1, is_zero = 1; n >= 0 && is_zero; n--) {
        is_zero = (x_cp[n] == 0);
    }

    if (is_zero && kryptos_poly1305_lt(x, y)) {
        memset(x, 0, sizeof(kryptos_poly1305_number_t));
        memset(r, 0, sizeof(kryptos_poly1305_number_t));
        goto kryptos_poly1305_div_epilogue_cleanup;
    }

    n = kKryptosPoly1305NumberSize;
    while (y_cp[n - 1] == 0 && n >= 1) {
        n--;
    }

    j = kKryptosPoly1305NumberSize;
    while (x_cp[j - 1] == 0 && j >= 1) {
        j--;
    }

    m = (j - n);
    if (m <= 0) {
        m = 1;
    }

#if defined(KRYPTOS_MP_EXTENDED_RADIX)
    while (y_cp[n - 1] < 0x8000000000000000) {
        shlv_nm++;
        kryptos_poly1305_lsh(x_cp, 1);
        kryptos_poly1305_lsh(y_cp, 1);
        n = kKryptosPoly1305NumberSize;
        while (y_cp[n - 1] == 0 && n >= 1) {
            n--;
        }
    }
#else
    while (y_cp[n - 1] < 0x80000000) {
        shlv_nm++;
        kryptos_poly1305_lsh(x_cp, 1);
        kryptos_poly1305_lsh(y_cp, 1);
        n = kKryptosPoly1305NumberSize;
        while (y_cp[n - 1] == 0 && n >= 1) {
            n--;
        }
    }
#endif

    memcpy(b, y_cp, sizeof(kryptos_poly1305_number_t));
    memset(q, 0, sizeof(kryptos_poly1305_number_t));

    kryptos_poly1305_lsh(b, (sizeof(kryptos_poly1305_numfrac_t) << 3) * (size_t)m);
    if (kryptos_poly1305_ge(x_cp, b)) {
        memcpy(t, x_cp, sizeof(kryptos_poly1305_number_t));
    }

    while (kryptos_poly1305_ge(x_cp, b) && q[m] < 0xFF) {
        q[m]++;
        kryptos_poly1305_sub(x_cp, b);
    }

    if (q[m] == 0xFF && kryptos_poly1305_ge(x_cp, b)) {
        q[m] = 0;
        memcpy(x_cp, t, sizeof(kryptos_poly1305_number_t));
        m++;
    }

    if (kryptos_poly1305_lt(x_cp, y_cp)) {
        goto kryptos_poly1305_div_epilogue;
    }

    for (j = m - 1; j >= 0; j--) {
        xi = n + j;
        while ((size_t)xi >= kKryptosPoly1305NumberSize) {
            xi--;
        }

        qtemp = x_cp[xi];

        if ((xi - 1) >= 0) {
            xi--;
            qtemp = (qtemp << (sizeof(kryptos_poly1305_numfrac_t) << 3)) | x_cp[xi];
        }

#if defined(__linux__) && defined(KRYPTOS_KERNEL_MODE)
        do_div(qtemp, (kryptos_poly1305_overflown_numfrac_t)y_cp[n - 1]);
#else
        qtemp = qtemp / (kryptos_poly1305_overflown_numfrac_t)y_cp[n - 1];
#endif

        if (qtemp > kKryptosPoly1305MaxMpDigit) {
            qtemp = 0xFF;
        }

        dec_nr = 0;

        do {
            q[j] = qtemp & kKryptosPoly1305MaxMpDigit;
            memcpy(b, y_cp, sizeof(kryptos_poly1305_number_t));
            kryptos_poly1305_mul_digit(b, q[j]);
            kryptos_poly1305_lsh(b, (sizeof(kryptos_poly1305_numfrac_t) << 3) * (size_t)j);
            is_less = kryptos_poly1305_lt(x_cp, b);
            if (is_less) {
                dec_nr++;
                if (dec_nr == 0xFF) {
                    q[j] = 0;
                    goto kryptos_poly1305_div_end_of_iteration;
                }
                qtemp--;
            }
        } while (is_less);

        kryptos_poly1305_sub(x_cp, b);

kryptos_poly1305_div_end_of_iteration:
            ;
    }

kryptos_poly1305_div_epilogue:

    if (shlv_nm > 0) {
        kryptos_poly1305_rsh(x_cp, shlv_nm);
    }

    memcpy(r, x_cp, sizeof(kryptos_poly1305_number_t));
    memcpy(x, q, sizeof(kryptos_poly1305_number_t));

kryptos_poly1305_div_epilogue_cleanup:

    memset(x_cp, 0, sizeof(kryptos_poly1305_number_t));
    memset(y_cp, 0, sizeof(kryptos_poly1305_number_t));
    memset(b, 0, sizeof(kryptos_poly1305_number_t));
    memset(q, 0, sizeof(kryptos_poly1305_number_t));
    memset(t, 0, sizeof(kryptos_poly1305_number_t));
    is_zero = dec_nr = is_less = 0;
    shlv_nm = 0;
    m = n = j = xi = 0;
    qtemp = 0;
}

#else // defined(KRYPTOS_POLY1305_DIV_USING_HEAP)

static void kryptos_poly1305_to_hex(char *xn, const size_t xn_size, const kryptos_poly1305_number_t n) {
    char *xn_p = xn;
    char *xn_p_end = xn + xn_size;
    kryptos_u8_t curr_byte;
    ssize_t i;

    memset(xn, 0, xn_size);

#define get_byte_from_u32(n, b) ( ( (n) >> (((4 - (b)) << 3) - 8) ) & 0xFF )
#define get_xnibble(n) ( ((n) < 0xA) ? ((n) + '0') : ((n) + 55) )

    for (i = kKryptosPoly1305NumberSize - 1; xn_p != xn_p_end && i >= 0; i--) {
        curr_byte = get_byte_from_u32(n[i], 0);
        xn_p[0] = get_xnibble(curr_byte >> 4);
        xn_p[1] = get_xnibble(curr_byte & 0xF);

        curr_byte = get_byte_from_u32(n[i], 1);
        xn_p[2] = get_xnibble(curr_byte >> 4);
        xn_p[3] = get_xnibble(curr_byte & 0xF);

        curr_byte = get_byte_from_u32(n[i], 2);
        xn_p[4] = get_xnibble(curr_byte >> 4);
        xn_p[5] = get_xnibble(curr_byte & 0xF);

        curr_byte = get_byte_from_u32(n[i], 3);
        xn_p[6] = get_xnibble(curr_byte >> 4);
        xn_p[7] = get_xnibble(curr_byte & 0xF);

        xn_p += 8;
    }

#undef get_xnibble
#undef get_byte_from_u32
}

void kryptos_poly1305_div(kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y, kryptos_poly1305_number_t r) {
    // INFO(Rafael): This function is slow because it uses the heap. Use it as your last resort.

    char x_hex[88];
    char y_hex[88];
    kryptos_mp_value_t *x_mp = NULL, *y_mp = NULL, *r_mp = NULL, *q_mp = NULL;
    size_t d = 0;

    kryptos_poly1305_to_hex(x_hex, sizeof(x_hex), x);
    kryptos_poly1305_to_hex(y_hex, sizeof(y_hex), y);

    if ((x_mp = kryptos_hex_value_as_mp(x_hex, sizeof(x_hex))) == NULL) {
        goto kryptos_poly1305_div_epilogue;
    }

    if ((y_mp = kryptos_hex_value_as_mp(y_hex, sizeof(y_hex))) == NULL) {
        goto kryptos_poly1305_div_epilogue;
    }

    q_mp = kryptos_mp_div(x_mp, y_mp, &r_mp);

    if (q_mp == NULL || r_mp == NULL) {
        goto kryptos_poly1305_div_epilogue;
    }

    memset(x, 0, sizeof(kryptos_poly1305_number_t));
    for (d = 0; d < kKryptosPoly1305NumberSize && d < q_mp->data_size; d++) {
        x[d] = q_mp->data[d];
    }

    memset(r, 0, sizeof(kryptos_poly1305_number_t));
    for (d = 0; d < kKryptosPoly1305NumberSize && d < r_mp->data_size; d++) {
        r[d] = r_mp->data[d];
    }

kryptos_poly1305_div_epilogue:

    if (x_mp != NULL) {
        kryptos_del_mp_value(x_mp);
    }

    if (y_mp != NULL) {
        kryptos_del_mp_value(y_mp);
    }

    if (r_mp != NULL) {
        kryptos_del_mp_value(r_mp);
    }

    if (q_mp != NULL) {
        kryptos_del_mp_value(q_mp);
    }

    x_mp = y_mp = r_mp = NULL;

    memset(x_hex, 0, sizeof(x_hex));
    memset(y_hex, 0, sizeof(y_hex));

    d = 0;
}

#endif //defined(KRYPTOS_POLY1305_DIV_USING_HEAP)

void kryptos_poly1305_lsh(kryptos_poly1305_number_t x, const size_t level) {
    kryptos_poly1305_numfrac_t *xp = &x[0];
    kryptos_poly1305_numfrac_t *xp_end = &x[0] + kKryptosPoly1305NumberSize;
    kryptos_u8_t cb = 0, lc = 0;
    size_t l;

    for (l = 0; l < level; l++) {
        while (xp != xp_end) {
            cb = *xp >> ((sizeof(kryptos_poly1305_numfrac_t) << 3) - 1);
            *xp = ((*xp) << 1) | lc;
            lc = cb;
            xp++;
        }
        xp = &x[0];
        lc = 0;
    }

    l = 0;
    cb = 0;
    xp = xp_end = NULL;
}

void kryptos_poly1305_rsh(kryptos_poly1305_number_t x, const size_t level) {
    kryptos_poly1305_numfrac_t *xp = &x[0] + kKryptosPoly1305NumberSize - 1;
    kryptos_poly1305_numfrac_t *xp_end = &x[0] - 1;
    size_t l;
    kryptos_u8_t cb = 0, lc = 0;

    for (l = 0; l < level; l++) {
        while (xp != xp_end) {
            cb = (*xp) & 1;
            *xp = ((*xp) >> 1) | ((kryptos_poly1305_numfrac_t)lc << ((sizeof(kryptos_poly1305_numfrac_t)<<3) - 1));
            lc = cb;
            xp--;
        }
        xp = &x[0] + kKryptosPoly1305NumberSize - 1;
        lc = 0;
    }

    l = 0;
    cb = 0;
    xp = xp_end = NULL;
}

void kryptos_poly1305_le_bytes_to_num(kryptos_poly1305_number_t n, const kryptos_u8_t *bytes, const size_t bytes_nr) {
    kryptos_poly1305_numfrac_t *np = &n[0];
    kryptos_poly1305_numfrac_t *np_end = &n[0] + kKryptosPoly1305NumberSize;
    size_t p = 0;
    const kryptos_u8_t *bp = bytes;
    const kryptos_u8_t *bp_end = bytes + bytes_nr;

    memset(n, 0, sizeof(kryptos_poly1305_number_t));

    while (np != np_end && bp != bp_end) {
        *np = (*np) | ((kryptos_poly1305_numfrac_t)*bp << (p << 3));
        bp += 1;
        p = (p + 1) % sizeof(kryptos_poly1305_numfrac_t);
        np += (p == 0);
    }

    p = 0;
}

void kryptos_poly1305_ld_raw_bytes(kryptos_poly1305_number_t n, const kryptos_u8_t *bytes, const size_t bytes_nr) {
    kryptos_poly1305_numfrac_t *np = &n[0] + kKryptosPoly1305_128bit_NumberSize - 1;
    kryptos_poly1305_numfrac_t *np_end = &n[0] - 1;
    size_t p = 0;
    const kryptos_u8_t *bp = bytes;
    const kryptos_u8_t *bp_end = bp + bytes_nr;

    memset(n, 0, sizeof(kryptos_poly1305_number_t));

//#if 1
    while (np != np_end && bp != bp_end) {
        *np = ((*np) << 8) | *bp;
        bp += 1;
        p = (p + 1) % sizeof(kryptos_poly1305_numfrac_t);
        np -= (p == 0);
    }
/*#else
    while (np != np_end && bp != bp_end) {
        *np = ((*np) << 8) | *bp;
        bp += 1;
        p = (p + 1) % sizeof(kryptos_poly1305_numfrac_t);
        np -= (p == 0);
        if (p == 0 && ((np - np_end) % 2) == 0) {
            // INFO(Rafael): Even being about a radix 2^32 the general working is based on radix 2^64.
            np[1] ^= np[2];
            np[2] ^= np[1];
            np[1] ^= np[2];
        }
    }
#endif*/
}

void kryptos_poly1305_le_num(kryptos_poly1305_number_t n, const kryptos_u8_t *bytes, const size_t bytes_nr) {
    kryptos_poly1305_numfrac_t *np = &n[0] + kKryptosPoly1305_128bit_NumberSize - 1;
    kryptos_poly1305_numfrac_t *np_end = &n[0] - 1;
    size_t p = 0;
    const kryptos_u8_t *bp = bytes + bytes_nr - 1;
    const kryptos_u8_t *bp_end = bytes - 1;

    memset(n, 0, sizeof(kryptos_poly1305_number_t));

//#if 1
    while (np != np_end && bp != bp_end) {
        *np = ((*np) << 8) | *bp;
        bp -= 1;
        p = (p + 1) % sizeof(kryptos_poly1305_numfrac_t);
        np -= (p == 0);
    }
/*#else
    while (np != np_end && bp != bp_end) {
        *np = ((*np) << 8) | *bp;
        bp -= 1;
        p = (p + 1) % sizeof(kryptos_poly1305_numfrac_t);
        np -= (p == 0);
        if (p == 0 && ((np - np_end) % 2) == 0) {
            // INFO(Rafael): Even being about 2^32 radix the endianness idea is based on 64-bit values, according to
            //               the algorithm specs.
            np[1] ^= np[2];
            np[2] ^= np[1];
            np[1] ^= np[2];
        }
    }
#endif*/
}

int kryptos_poly1305_eq(const kryptos_poly1305_number_t x, const kryptos_poly1305_number_t y) {
    return (kryptos_poly1305_get_gt(x, y) == NULL);
}

const kryptos_poly1305_numfrac_t *kryptos_poly1305_get_gt(const kryptos_poly1305_number_t x,
                                                          const kryptos_poly1305_number_t y) {
    const kryptos_poly1305_numfrac_t *xp = &x[0] + kKryptosPoly1305NumberSize - 1;
    const kryptos_poly1305_numfrac_t *xp_end = &x[0] - 1;
    const kryptos_poly1305_numfrac_t *yp = &y[0] + kKryptosPoly1305NumberSize - 1;
    const kryptos_poly1305_numfrac_t *yp_end = &y[0] - 1;
    kryptos_u8_t x_reg = 0, y_reg = 0;

#define kryptos_poly1305_get_gt_bitcmp(xx, yy, b, xr, yr) {\
    (xr) = (*(xx) & ((kryptos_poly1305_numfrac_t)1 << (b))) >> (b);\
    (yr) = (*(yy) & ((kryptos_poly1305_numfrac_t)1 << (b))) >> (b);\
    if ((xr) && !(yr)) {\
        xp = xp_end = yp = yp_end = NULL;\
        x_reg = y_reg = 0;\
        return &(x)[0];\
    }\
    if ((yr) && !(xr)) {\
        xp = xp_end = yp = yp_end = NULL;\
        x_reg = y_reg = 0;\
        return &(y)[0];\
    }\
}

    while (xp != xp_end) {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 63, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 62, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 61, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 60, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 59, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 58, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 57, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 56, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 55, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 54, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 53, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 52, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 51, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 50, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 49, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 48, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 47, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 46, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 45, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 44, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 43, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 42, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 41, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 40, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 39, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 38, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 37, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 36, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 35, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 34, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 33, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 32, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 31, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 29, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 28, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 27, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 26, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 25, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 24, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 23, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 22, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 21, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 20, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 19, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 18, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 17, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 16, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 15, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 14, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 13, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 12, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 11, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 10, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  9, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  8, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  7, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  6, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  5, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  4, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  3, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  2, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  1, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  0, x_reg, y_reg);
#else
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 31, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 30, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 29, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 28, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 27, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 26, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 25, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 24, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 23, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 22, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 21, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 20, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 19, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 18, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 17, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 16, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 15, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 14, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 13, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 12, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 11, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp, 10, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  9, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  8, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  7, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  6, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  5, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  4, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  3, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  2, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  1, x_reg, y_reg);
        kryptos_poly1305_get_gt_bitcmp(xp, yp,  0, x_reg, y_reg);
#endif
        xp -= 1;
        yp -= 1;
    }

#undef kryptos_poly1305_get_gt_bitcmp

    xp = xp_end = yp = yp_end = NULL;
    x_reg = y_reg = 0;

    return NULL; // INFO(Rafael): They are equal.
}
