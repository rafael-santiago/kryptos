/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_arc4.h>
#include <kryptos_task_check.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define kryptos_arc4stream(s) ( s->i = (s->i + 1) % 256,\
                                s->j = (s->j + s->S[s->i]) % 256,\
                                temp = s->S[s->i],\
                                s->S[s->i] = s->S[s->j],\
                                s->S[s->j] = temp,\
                                temp = (s->S[s->i] + s->S[s->j]) % 256,\
                                s->S[temp] )

struct kryptos_arc4_subkey {
    kryptos_u8_t S[256];
    int i, j;
};

static void kryptos_arc4_clear_and_go(struct kryptos_arc4_subkey *sk);

static void kryptos_arc4_key_setup(const kryptos_u8_t *userkey, const size_t userkey_size, struct kryptos_arc4_subkey *sk);

static kryptos_u8_t kryptos_arc4_xor(const kryptos_u8_t byte, struct kryptos_arc4_subkey *sk);

static void kryptos_arc4_key_setup(const kryptos_u8_t *userkey, const size_t userkey_size, struct kryptos_arc4_subkey *sk) {
    kryptos_u8_t S2[256];
    kryptos_u8_t temp;

    for (sk->i = 0; sk->i < 256; sk->S[sk->i] = sk->i++)
        ;

    for (sk->i = 0; sk->i < 256; S2[sk->i] = userkey[sk->i % userkey_size], sk->i++)
        ;

    for(sk->i = 0, sk->j = 0; sk->i < 256; sk->i++) {
        sk->j = (sk->j + sk->S[sk->i] + S2[sk->i]) % 256;
        temp = sk->S[sk->i];
        sk->S[sk->i] = sk->S[sk->j];
        sk->S[sk->j] = temp;
    }

    temp = 0;
    sk->i = 0;
    sk->j = 0;
    memset(S2, 0, sizeof(S2));
}

static kryptos_u8_t kryptos_arc4_xor(const kryptos_u8_t byte, struct kryptos_arc4_subkey *sk) {
    kryptos_u8_t K;
    kryptos_u8_t temp;
    kryptos_u8_t result = 0;

    K = kryptos_arc4stream(sk);
    temp = 0;
    result = byte ^ K;
    K = 0;

    return result;
}

static void kryptos_arc4_clear_and_go(struct kryptos_arc4_subkey *sk) {
    sk->i = 0;
    sk->j = 0;
    memset(sk->S, 0, sizeof(sk->S));
}

void kryptos_arc4_cipher(kryptos_task_ctx **ktask) {
    kryptos_u8_t *in_end, *in_p;
    kryptos_u8_t *out_p;
    struct kryptos_arc4_subkey sk;

    if (kryptos_task_check(ktask) == 0) {
        return;
    }

    kryptos_arc4_key_setup((*ktask)->key, (*ktask)->key_size, &sk);

    in_end = (*ktask)->in + (*ktask)->in_size;
    in_p = (*ktask)->in;

    (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(in_end - in_p);

    if ((*ktask)->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "No memory to get a valid output.";
        goto kryptos_arc4_stream_epilogue;
    }

    out_p = (*ktask)->out;

    while (in_p != in_end) {
        *out_p = kryptos_arc4_xor(*in_p, &sk);
        out_p++;
        in_p++;
    }

kryptos_arc4_stream_epilogue:
    (*ktask)->out_size = ((*ktask)->out != NULL) ? in_end - (*ktask)->in : 0;
    in_p = NULL;
    in_end = NULL;
    kryptos_arc4_clear_and_go(&sk);
}

void kryptos_arc4_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherARC4;
    ktask->key = key;
    ktask->key_size = key_size;
}

#undef kryptos_arc4stream
