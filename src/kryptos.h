/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_H
#define KRYPTOS_KRYPTOS_H 1

#include <kryptos_types.h>
#include <kryptos_memory.h>
#include <kryptos_block_parser.h>

#include <kryptos_arc4.h>
#include <kryptos_seal.h>
#include <kryptos_des.h>

#define kryptos_task_set_ecb_mode(ktask) ( (ktask)->mode = kKryptosECB )

#define kryptos_task_set_cbc_mode(ktask) ( (ktask)->mode = kKryptosCBC )

#define kryptos_task_set_encrypt_action(ktask) ( (ktask)->action = kKryptosEncrypt )

#define kryptos_task_set_decrypt_action(ktask) ( (ktask)->action = kKryptosDecrypt )

#define kryptos_last_task_succeed(ktask) ( (ktask)->result == kKryptosSuccess )

#define kryptos_task_set_in(ktask, inb, inb_size) ( (ktask)->in = (inb), (ktask)->in_size = (inb_size) )

#define kryptos_task_get_out(ktask) ( (ktask)->out )

#define kryptos_task_get_out_size(ktask) ( (ktask)->out_size )

#define kryptos_task_free(ktask, also_in) {\
    if ((ktask)->out != NULL) {\
        kryptos_freeseg((ktask)->out);\
        (ktask)->out = NULL;\
        (ktask)->out_size = 0;\
    }\
    if (also_in && (ktask)->in != NULL) {\
        kryptos_freeseg((ktask)->in);\
        (ktask)->in = NULL;\
        (ktask)->in_size = 0;\
    }\
}

#define kryptos_meta_block_processing_ecb(block_size_in_bytes,\
                                          action,\
                                          in, in_p, in_end, in_size,\
                                          out, out_size, out_p,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme) {\
    if (action == kKryptosEncrypt) {\
        in_p = kryptos_ansi_x923_padding(in, in_size, block_size_in_bytes);\
    } else {\
        in_p = in;\
    }\
    in_end = in_p + *in_size;\
    in_block = in_p;\
    out = (kryptos_u8_t *) kryptos_newseg(*in_size);\
    if (out == NULL) {\
        goto kryptos_ ## epilogue;\
    }\
    *out_size = *in_size;\
    out_p = out;\
    out_block = kryptos_block_parser(out_block, block_size_in_bytes, in_block, in_end, &in_block);\
    while (out_block != NULL) {\
        block_processor_call_scheme;\
        memcpy(out_p, out_block, block_size_in_bytes);\
        out_p += block_size_in_bytes;\
        out_block = kryptos_block_parser(out_block, block_size_in_bytes, in_block, in_end, &in_block);\
    }\
    if (action == kKryptosDecrypt) {\
        *out_size = *(out + (*in_size) - 1);\
        *(out + (*in_size) - 1) = 0;\
    } else {\
        kryptos_freeseg(in_p);\
    }\
}

#ifdef KRYPTOS_C99

static kryptos_task_ctx *kryptos_task_run_cipher_p = NULL;

#define kryptos_run_cipher(cname, ktask, cipher_args...) {\
    kryptos_ ## cname ## _setup((ktask), cipher_args);\
    kryptos_task_run_cipher_p = (ktask);\
    kryptos_ ## cname ## _cipher(&kryptos_task_run_cipher_p);\
    kryptos_task_run_cipher_p = NULL;\
}

#endif // KRYPTOS_C99

#endif // KRYPTOS_KRYPTOS_H
