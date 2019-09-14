/*
 *                          Copyright (C) 2007, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_seal.h>
#include <kryptos_task_check.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// INFO(Rafael): Macro version of functions f(), g() and h() from SHA-1.
#define kryptos_seal_f(B, C, D) (kryptos_u32_t) ( ( (B) & (C) ) | ( ( ~(B) ) &  (D) ) )
#define kryptos_seal_g(B, C, D) (kryptos_u32_t) ( ( (B) & (C) ) | ( (B) & (D) ) | ( (C) & (D) ) )
#define kryptos_seal_h(B, C, D) (kryptos_u32_t) ( ( (B) ^ (C) ^ (D) )  )

// INFO(Rafael): ``aux = (x & y) / z`` in general takes the same CPU time than ``(x & y) / z``
//               because it will be moved into a register. Due to it I have adopted the "inline" construction.

#define kryptos_seal_roll(A, s) ( (kryptos_u32_t) ( (A) << (s) | (A) >> ( ( sizeof( (A) ) << 3 ) - (s) ) ) )
#define kryptos_seal_rolr(A, s) ( (kryptos_u32_t) ( (A) >> (s) | (A) << ( ( sizeof( (A) ) << 3 ) - (s) ) ) )
#define kryptos_seal_safe_inc(i, m, r) ( ( (i) = ( (i) + (m) ) % (r) ) )
#define kryptos_seal_initialize(n, l, A, B, C, D, n1, n2, n3, n4, R, T) (\
 ( (A) =  (n) ^ (R)[( (l) << 2 )] ),\
 ( (B) = (kryptos_seal_rolr(n,  8)) ^ (R)[( (l) << 2 ) + 1] ),\
 ( (C) = (kryptos_seal_rolr(n, 16)) ^ (R)[( (l) << 2 ) + 2] ),\
 ( (D) = (kryptos_seal_rolr(n, 24)) ^ (R)[( (l) << 2 ) + 3] ),\
 ( (B) = (B) + (T)[( (A) & 0x000007fc ) >> 2], (A) = kryptos_seal_rolr(A, 9) ),\
 ( (C) = (C) + (T)[( (B) & 0x000007fc ) >> 2], (B) = kryptos_seal_rolr(B, 9) ),\
 ( (D) = (D) + (T)[( (C) & 0x000007fc ) >> 2], (C) = kryptos_seal_rolr(C, 9) ),\
 ( (A) = (A) + (T)[( (D) & 0x000007fc ) >> 2], (D) = kryptos_seal_rolr(D, 9) ),\
 ( (B) = (B) + (T)[( (A) & 0x000007fc ) >> 2], (A) = kryptos_seal_rolr(A, 9) ),\
 ( (C) = (C) + (T)[( (B) & 0x000007fc ) >> 2], (B) = kryptos_seal_rolr(B, 9) ),\
 ( (D) = (D) + (T)[( (C) & 0x000007fc ) >> 2], (C) = kryptos_seal_rolr(C, 9) ),\
 ( (A) = (A) + (T)[( (D) & 0x000007fc ) >> 2], (D) = kryptos_seal_rolr(D, 9) ),\
 ( (n1) = (D), (n2) = (B), (n3) = (A), (n4) = (C) ),\
 ( (B) = (B) + (T)[( (A) & 0x000007fc ) >> 2], (A) = kryptos_seal_rolr(A, 9) ),\
 ( (C) = (C) + (T)[( (B) & 0x000007fc ) >> 2], (B) = kryptos_seal_rolr(B, 9) ),\
 ( (D) = (D) + (T)[( (C) & 0x000007fc ) >> 2], (C) = kryptos_seal_rolr(C, 9) ),\
 ( (A) = (A) + (T)[( (D) & 0x000007fc ) >> 2], (D) = kryptos_seal_rolr(D, 9) ) )

#define KRYPTOS_SEALKEYSTREAMSIZE               0xffff
#define KRYPTOS_SEALMAXL                        0xffffff
#define KRYPTOS_SEAL_Y1                         0x5a827999
#define KRYPTOS_SEAL_Y2                         0x6ed9eba1
#define KRYPTOS_SEAL_Y3                         0x8f1bbcdc
#define KRYPTOS_SEAL_Y4                         0xca62c1d6

struct kryptos_seal_keystream_ctx {
    kryptos_u32_t keystream[KRYPTOS_SEALKEYSTREAMSIZE];
    kryptos_u32_t n;
    kryptos_u32_t L;
    kryptos_seal_version_t version;
};

static void kryptos_seal_ga(kryptos_u32_t *a, int i, kryptos_u32_t *o);

static void kryptos_seal_ld_userkey(kryptos_u32_t *state, const size_t state_size,
                                    const kryptos_u8_t *key, const size_t key_size);

static void kryptos_seal_keystream(const kryptos_u8_t *userkey, const size_t userkey_size,
                                   struct kryptos_seal_keystream_ctx *kstream);

static void kryptos_seal_xor(const kryptos_u32_t *in,
                             const kryptos_u32_t *key,
                             const size_t key_size,
                             kryptos_u32_t *out);

static void kryptos_seal_ga(kryptos_u32_t *a, int i, kryptos_u32_t *o) {
    kryptos_u32_t X[80], A, B, C, D, E, t;
    int w;

    // INFO(Rafael): initializing X[0]..X[79]
    X[0] = (kryptos_u32_t) i;
    for (w = 1; w < 16; w++) {
        X[w] = 0L;
    }

    for (; w < 80; w++) {
        X[w] = kryptos_seal_roll((X[w-3] ^ X[w-8] ^ X[w-14] ^ X[w-16]), 1);
    }

    // INFO(Rafael): user key splitting
    A = a[0];
    B = a[1];
    C = a[2];
    D = a[3];
    E = a[4];

    // Round#1
    for(w = 0; w < 20; w++) {
        t = kryptos_seal_roll(A, 5) + kryptos_seal_f(B, C, D)  + E + X[w] + KRYPTOS_SEAL_Y1;
        E = D;
        D = C;
        C = kryptos_seal_roll(B, 30);
        B = A;
        A = t;
    }

    // Round#2
    for (; w < 40; w++) {
        t = kryptos_seal_roll(A, 5) + kryptos_seal_h(B, C, D) + E + X[w] + KRYPTOS_SEAL_Y2;
        E = D;
        D = C;
        C = kryptos_seal_roll(B, 30);
        B = A;
        A = t;
    }

    // Round#3
    for (; w < 60; w++) {
        t = kryptos_seal_roll(A, 5) + kryptos_seal_g(B, C, D) + E + X[w] + KRYPTOS_SEAL_Y3;
        E = D;
        D = C;
        C = kryptos_seal_roll(B, 30);
        B = A;
        A = t;
    }

    // Round#4
    for (; w < 80; w++) {
        t = kryptos_seal_roll(A, 5) + kryptos_seal_h(B, C, D) + E + X[w] + KRYPTOS_SEAL_Y4;
        E = D;
        D = C;
        C = kryptos_seal_roll(B, 30);
        B = A;
        A = t;
    }

    // Update
    o[0] = a[0] + A;
    o[1] = a[1] + B;
    o[2] = a[2] + C;
    o[3] = a[3] + D;
    o[4] = a[4] + E;

    A = B = C = D = E = 0;
    memset(X, 0, sizeof(X));
}

static void kryptos_seal_ld_userkey(kryptos_u32_t *state, const size_t state_size,
                                    const kryptos_u8_t *key, const size_t key_size) {
    size_t s, k;

    memset(state, 0, sizeof(kryptos_u32_t) * state_size);

    if (key == NULL || key_size == 0) {
        return;
    }

    s = 0;
    for (k = 0; k < key_size; k++) {
        state[s] = state[s] << 8 | (kryptos_u32_t) key[k];
        if (((k+1) % 4) == 0) {
            kryptos_seal_safe_inc(s, 1, state_size);
        }
    }

    while (((k) % 4) != 0) {
        state[s] = state[s] << 4;
        k++;
    }
}

static void kryptos_seal_keystream(const kryptos_u8_t *userkey, const size_t userkey_size,
                                   struct kryptos_seal_keystream_ctx *kstream) {
    int i, l, p;
    int until;
#ifdef KRYPTOS_KERNEL_MODE
    static kryptos_u32_t T[512], S[256], R[ 4 * ((KRYPTOS_SEALMAXL - 1) / 8192) - 1];
#else
    kryptos_u32_t T[512], S[256], R[ 4 * ((KRYPTOS_SEALMAXL - 1) / 8192) - 1];
#endif
    kryptos_u32_t a[5], P, Q, o[5], LL;
    kryptos_u32_t n1, n2, n3, n4, A, B, C, D;

    if ((kstream->L >> 5) > KRYPTOS_SEALMAXL) {
        // INFO(Rafael): L > 2^19.
        return;
    }

    if (kstream->version != kKryptosSEAL20 && kstream->version != kKryptosSEAL30) {
        //  INFO(Rafael): Unknown version.
        return;
    }

    //  INFO(Rafael): Making the user key a 160-bit value.
    kryptos_seal_ld_userkey(a, 5, userkey, userkey_size);

    for (i = 0, l = 0; i < 103 && l < 512; i++) {
        kryptos_seal_ga(a, i, o);
        do {
            T[l] = o[l%5];
            l++;
        } while (((l) % 5) != 0 && l < 512);
    }

    kryptos_seal_ga(a, 819L, o);
    // INFO(Rafael): Skipping a[0] because in the test vector the S[0] starts with '0x907c1ed1' that in this case
    //               is the second kryptos_u32_t from the 160-bit stream. (Note: 819L = 0x1000 / 5).
    S[0] = o[1];
    S[1] = o[2];
    S[2] = o[3];
    S[3] = o[4];
    for (i = 1, l = 4, p = 0; i < 52 && l < 256; i++) {
        kryptos_seal_ga(a, 819L + i, o);
        for (p = 0; p < 5 && l < 256; p++, l++) {
           S[l] = o[p];
        }
    }

    until = (((kstream->L - 1) >> 13) << 2) - 1; // INFO(Rafael): (4 * ((L - 1) / 8192) - 1)

    kryptos_seal_ga(a, 1638L, o);
    R[0] = o[2];
    R[1] = o[3];
    R[2] = o[4];
    kryptos_seal_ga(a, 1639L, o);
    R[3] = o[0];
    R[4] = o[1];
    R[5] = o[2];
    R[6] = o[3];
    R[7] = o[4];
    for (i = 2, l = 8; i <= until; i++, l += 5) {
        kryptos_seal_ga(a, 1638L + i, o);
        R[ l ] = o[0];
        R[l+1] = o[1];
        R[l+2] = o[2];
        R[l+3] = o[3];
        R[l+4] = o[4];
    }

    // WARN(Rafael): If you do not have any solid idea about the SEAL internals,
    //               please do not improve! Just accept and use.
    //

    memset(kstream->keystream, 0L, sizeof(kryptos_u32_t) * KRYPTOS_SEALKEYSTREAMSIZE);
    LL = kstream->L >> 5;
    for (p = 0, l = 0; p < LL; l++) {
        kryptos_seal_initialize(kstream->n, l, A, B, C, D, n1, n2, n3, n4, R, T);
        for (i = 1; i < 65 && p < LL; i++, p += 4) {
            P = A & 0x000007fc; B = B + T[P >> 2]; A = kryptos_seal_rolr(A, 9); B = B ^ A;
            Q = B & 0x000007fc; C = C ^ T[Q >> 2]; B = kryptos_seal_rolr(B, 9); C = C + B;
            P = (P + C) & 0x000007fc; D = D + T[P >> 2]; C = kryptos_seal_rolr(C, 9); D = D ^ C;
            Q = (Q + D) & 0x000007fc; A = A ^ T[Q >> 2]; D = kryptos_seal_rolr(D, 9); A = A + D;

            P = (P + A) & 0x000007fc; B = B ^ T[P >> 2]; A = kryptos_seal_rolr(A, 9);
            Q = (Q + B) & 0x000007fc; C = C + T[Q >> 2]; B = kryptos_seal_rolr(B, 9);
            P = (P + C) & 0x000007fc; D = D ^ T[P >> 2]; C = kryptos_seal_rolr(C, 9);
            Q = (Q + D) & 0x000007fc; A = A + T[Q >> 2]; D = kryptos_seal_rolr(D, 9);

            kstream->keystream[ p ] = B + S[(i << 2) - 4];
            if ((p+1) < LL) {
                kstream->keystream[p + 1] = C ^ S[(i << 2) - 3];
                if ((p+2) < LL) {
                    kstream->keystream[p + 2] = D + S[(i << 2) - 2];
                    if ((p+3) < LL) {
                        kstream->keystream[p + 3] = A ^ S[(i << 2) - 1];
                    }
                }
            }

            if ((i & 1) != 0) {
                switch (kstream->version) {
                    case kKryptosSEAL20:
                        A += n1;
                        C += n2;
                        break;

                    case kKryptosSEAL30:
                        A += n1;
                        B += n2;
                        C ^= n1;
                        D ^= n2;
                        break;
                }
            } else {
                switch(kstream->version) {
                    case kKryptosSEAL20:
                        A += n3;
                        C += n4;
                        break;

                    case kKryptosSEAL30:
                        A += n3;
                        B += n4;
                        C ^= n3;
                        D ^= n4;
                        break;
                }
            }

        }
    }

    until = i = l = p = 0;

    memset(&R, 0, sizeof(R));
    memset(&S, 0, sizeof(S));
    memset(&T, 0, sizeof(T));
    memset(&a, 0, sizeof(a));
    memset(&o, 0, sizeof(o));

    P = Q = LL = 0;

    n1 = n2 = n3 = n4 = A = B = C = D = 0;

    //                                         +-=-=-=-=-=-=-=-=-=-=-=-=+
    //                                         |  A FLASHY COMMENT BOX  |
    //                                         +-=-=-=-=-=-=-=-=-=-=-=-=+
    //               ###########################################################################
    //               ##########   <NEON-LIGHTS> ::= (<NEON-LIGTHS>)+ | "blink!"   ##############
    //               ###########################################################################
    //  ############## ``` <NEON-LIGHTS> ``` ## ``` <NEON-LIGHTS> ``` ## ``` <NEON-LIGHTS> ``` ############
    // ############################           A FLASHY COMMENT BOX              ############################
    // #####################################################################################################
    // ############################            YOU CANNOT MISS IT               ############################
    // #####################################################################################################
    // #                                                                                                   #
    // # WARN(Rafael): Hi, Tasmanian devel!                                                                #
    // #                                                                                                   #
    // #               The SEAL specification does not provide any "oracle" test vector.                   #
    // #               I meant, "Input (X, K, ...) -> Output (X')". However, the spec provides             #
    // #               the content of the R, T, S tables, besides the keystream. Also is                   #
    // #               provided a value that denotes all words of the final keystream xored.               #
    // #                                                                                                   #
    // #               If you have made some changes exactly here or in any other critical component of    #
    // #               this implementation, you must be sure that using the setup described in SEAL spec,  #
    // #               the xoring of all final keystream words on SEAL 2.0 is "0x098045fc" and             #
    // #               SEAL 3.0 is "0x3e0fe99f".                                                           #
    // #                                                                                                   #
    // #               Happy coding! ;)                                                                    #
    // #                                                                                                   #
    // #####################################################################################################
    // ############################     IF YOU MISSED THE FAULT IS YOURS!     ##############################
    // #####################################################################################################
}

static void kryptos_seal_xor(const kryptos_u32_t *in,
                             const kryptos_u32_t *key,
                             const size_t key_size,
                             kryptos_u32_t *out) {
    size_t k;
    //  INFO(Rafael): The additive stuff.
    for (k = 0; k < key_size; k++) {
         out[k] = in[k] ^ key[k];
    }
}

void kryptos_seal_cipher(kryptos_task_ctx **ktask) {
    size_t wordsize = 0, w, wt;
    const kryptos_u8_t *in_p, *in_end;
    kryptos_u8_t *out_p;
#ifdef KRYPTOS_KERNEL_MODE
    static struct kryptos_seal_keystream_ctx kstream;
    static kryptos_u32_t inblock[KRYPTOS_SEALKEYSTREAMSIZE], outblock[KRYPTOS_SEALKEYSTREAMSIZE];
#else
    struct kryptos_seal_keystream_ctx kstream;
    kryptos_u32_t inblock[KRYPTOS_SEALKEYSTREAMSIZE], outblock[KRYPTOS_SEALKEYSTREAMSIZE];
#endif
    size_t b, t;

    if (kryptos_task_check(ktask) == 0) {
        return;
    }

    if ((*ktask)->arg[0] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "SEAL version not informed.";
        return;
    }

    if ((*ktask)->arg[1] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "SEAL L parameter not supplied.";
        return;
    }

    wordsize = *(size_t *)(*ktask)->arg[1];

    if (wordsize < 1 || wordsize > KRYPTOS_SEALKEYSTREAMSIZE) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "SEAL word-size has an illegal value -> not(> 1 or < 65535).";
        return;
    }

    if ((*ktask)->arg[2] != NULL) {
        kstream.n = *(kryptos_u32_t *)(*ktask)->arg[2];
    } else {
        //  INFO(Rafael): If n was not supplied we will assume the initial
        //                relative position of the data in the buffer. (i.e. -> 0)
        kstream.n = 0;
    }

    kstream.L = wordsize << 5; // INFO(Rafael): I mean "wordsize * 32".
    kstream.version = *(kryptos_seal_version_t *)(*ktask)->arg[0];

    in_p = (*ktask)->in;
    in_end = in_p + (*ktask)->in_size;

    b = 0;

    (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((*ktask)->in_size);

    if ((*ktask)->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "No memory to get a valid output.";
        goto kryptos_seal_stream_epilogue;
    }

    (*ktask)->out_size = (*ktask)->in_size;
    out_p = (*ktask)->out;

    w = 0;

// INFO(Rafael).1.0: Have you ever heard Programming juggernauts speeching against C macros? (...)
#define kryptos_seal_get_next_block(ww, bb, in, ip, ip_end, sub_label) {\
        (in)[(ww)] = (in)[(ww)] << 8 | (kryptos_u32_t) *(ip);\
        (bb) = ( (bb) + 1 ) % sizeof(kryptos_u32_t);\
        (ip)++;\
        if ((ip) == (ip_end)) goto kryptos_seal_stream_## sub_label;\
        if ( (bb) == 0 ) (ww)++;\
}

#define kryptos_seal_fill_out(out, block, ww, ww_nr) {\
    for ((ww) = 0; (ww) < (ww_nr); (ww)++) {\
        *(out) = (block)[(ww)] >> 24;\
        (out)++;\
        *(out) = ((block)[(ww)] >> 16) & 0xff;\
        (out)++;\
        *(out) = ((block)[(ww)] >> 8) & 0xff;\
        (out)++;\
        *(out) = (block)[(ww)] & 0xff;\
        (out)++;\
    }\
}

    memset(inblock, 0, sizeof(kryptos_u32_t) * KRYPTOS_SEALKEYSTREAMSIZE);

    while (in_p != in_end) {
        // INFO(Rafael).1.1: (...) Sometimes it sounds like a Monty Python sketch, isn't it?
        kryptos_seal_get_next_block(w, b, inblock, in_p, in_end, apply_xor);
        if (w == wordsize) {
            kryptos_seal_stream_apply_xor:
            if (b > 0) {
                t = b;
                while (t < 4) {
                    inblock[w] = inblock[w] << 8;
                    t++;
                }
            }

            wt = w;

            if (w < wordsize) {
                w++;
            }

            kryptos_seal_keystream((*ktask)->key, (*ktask)->key_size, &kstream);
            kryptos_seal_xor(inblock, kstream.keystream, wordsize, outblock);
            kstream.n++;
            if (wt > 0) {
                kryptos_seal_fill_out(out_p, outblock, t, w - 1);
            }

            switch (b) {

                case 0:
                    *out_p       = (outblock[w - 1] >> 24) & 0xff;
                    *(out_p + 1) = (outblock[w - 1] >> 16) & 0xff;
                    *(out_p + 2) = (outblock[w - 1] >>  8) & 0xff;
                    *(out_p + 3) =  outblock[w - 1] & 0xff;
                    break;

                case 1:
                    *out_p       = (outblock[w - 1] >> 24) & 0xff;
                    break;

                case 2:
                    *out_p       = (outblock[w - 1] >> 24) & 0xff;
                    *(out_p + 1) = (outblock[w - 1] >> 16) & 0xff;
                    break;

                case 3:
                    *out_p       = (outblock[w - 1] >> 24) & 0xff;
                    *(out_p + 1) = (outblock[w - 1] >> 16) & 0xff;
                    *(out_p + 2) = (outblock[w - 1] >>  8) & 0xff;
                    break;
            }

            w = 0;
            memset(inblock, 0, sizeof(kryptos_u32_t) * KRYPTOS_SEALKEYSTREAMSIZE);
            b = 0;
        }
    }

    (*ktask)->result = kKryptosSuccess;

#undef kryptos_seal_get_next_block

#undef kryptos_seal_fill_out

kryptos_seal_stream_epilogue:
    memset(inblock, 0, sizeof(kryptos_u32_t) * KRYPTOS_SEALKEYSTREAMSIZE);
    memset(outblock, 0, sizeof(kryptos_u32_t) * KRYPTOS_SEALKEYSTREAMSIZE);
    b = w = wordsize = 0;
    in_p = in_end = NULL;
    out_p = NULL;
    memset(&kstream, 0, sizeof(kstream));
}

void kryptos_seal_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size,
                        kryptos_seal_version_t *algo_version, size_t *L, size_t *n) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherSEAL;
    ktask->key = key;
    ktask->key_size = key_size;
    ktask->arg[0] = algo_version;
    ktask->arg[1] = L;
    ktask->arg[2] = n;
}

#undef kryptos_seal_f
#undef kryptos_seal_g
#undef kryptos_seal_h

#undef kryptos_seal_roll
#undef kryptos_seal_rolr
#undef kryptos_seal_safe_inc
#undef kryptos_seal_initialize

#undef KRYPTOS_SEALKEYSTREAMSIZE
#undef KRYPTOS_SEALMAXL
#undef KRYPTOS_SEAL_Y1
#undef KRYPTOS_SEAL_Y2
#undef KRYPTOS_SEAL_Y3
#undef KRYPTOS_SEAL_Y4
