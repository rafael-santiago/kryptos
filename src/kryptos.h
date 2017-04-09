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
#include <kryptos_iv_utils.h>

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

#define kryptos_meta_block_processing_prologue(block_size_in_bytes,\
                                               inblock, inblock_p,\
                                               outblock, outblock_p,\
                                               in_size_var, in_size_val) {\
    inblock = (kryptos_u8_t *) kryptos_newseg(block_size_in_bytes);\
    inblock_p = inblock;\
    outblock = (kryptos_u8_t *) kryptos_newseg(block_size_in_bytes);\
    outblock_p = outblock;\
    in_size = in_size_val;\
}

#define kryptos_meta_block_processing(block_size_in_bytes,\
                                      action,\
                                      mode,\
                                      iv,\
                                      in, in_p, in_end, in_size,\
                                      out, out_p, out_size,\
                                      in_block, out_block,\
                                      epilogue, block_processor_call_scheme) {\
    if (mode == kKryptosCBC) {\
        kryptos_meta_block_processing_cbc(block_size_in_bytes,\
                                          action,\
                                          iv,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme);\
    } else {\
        kryptos_meta_block_processing_ecb(block_size_in_bytes,\
                                          action,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme);\
    }\
}

#define kryptos_meta_block_processing_epilogue(inblock, inblock_p, in_p, in_end,\
                                               outblock, outblock_p, out_p,\
                                               in_size, sks, ktask) {\
    if ((*ktask)->out == NULL) {\
        (*ktask)->result = kKryptosProcessError;\
        (*ktask)->result_verbose = "No memory to get a valid output.";\
    }\
    memset(inblock, 0, 8);\
    memset(outblock, 0, 8);\
    kryptos_freeseg(inblock);\
    kryptos_freeseg(outblock);\
    inblock_p = outblock_p = NULL;\
    in_size = 0;\
    in_p = in_end = out_p = NULL;\
    memset(&sks, 0, sizeof(sks));\
}

#define kryptos_meta_block_processing_cbc(block_size_in_bytes,\
                                          action,\
                                          iv,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme) {\
    if (action == kKryptosEncrypt) {\
        in_p = kryptos_ansi_x923_padding(in, in_size, block_size_in_bytes);\
        out = (kryptos_u8_t *) kryptos_newseg(*in_size + block_size_in_bytes);\
        if (out == NULL) {\
            goto kryptos_ ## epilogue;\
        }\
        *out_size = *in_size + block_size_in_bytes;\
        out_p = out + block_size_in_bytes;\
        kryptos_iv_data_flush(out, iv, block_size_in_bytes);\
        in_end = in_p + *in_size;\
        in_block = in_p;\
    } else {\
        in_p = in;\
        out = (kryptos_u8_t *) kryptos_newseg(*in_size - block_size_in_bytes);\
        if (out == NULL) {\
            goto kryptos_ ## epilogue;\
        }\
        *out_size = *in_size - block_size_in_bytes;\
        out_p = out;\
        kryptos_iv_data_flush(iv, in_p, block_size_in_bytes);\
        in_p += block_size_in_bytes;\
        in_end = in_p + *in_size - block_size_in_bytes;\
        in_block = in_p;\
    }\
    if (action == kKryptosEncrypt) {\
        kryptos_apply_iv(in_block, iv, block_size_in_bytes);\
    }\
    out_block = kryptos_block_parser(out_block, block_size_in_bytes, in_block, in_end, &in_block);\
    while (out_block != NULL) {\
        block_processor_call_scheme;\
        if (action == kKryptosDecrypt) {\
            kryptos_apply_iv(out_block, iv, block_size_in_bytes);\
        }\
        memcpy(out_p, out_block, block_size_in_bytes);\
        out_p += block_size_in_bytes;\
        if (action == kKryptosEncrypt) {\
            kryptos_iv_data_flush(iv, out_block, block_size_in_bytes);\
        } else {\
            kryptos_iv_data_flush(iv, in_block - block_size_in_bytes, block_size_in_bytes);\
        }\
        out_block = kryptos_block_parser(out_block, block_size_in_bytes, in_block, in_end, &in_block);\
    }\
    if (action == kKryptosDecrypt) {\
        *out_size = *(out + (*in_size) + block_size_in_bytes - 1);\
        *(out + (*in_size) + block_size_in_bytes - 1) = 0;\
    } else {\
        kryptos_freeseg(in_p);\
    }\
    memset(iv, 0, block_size_in_bytes);\
}


#define kryptos_meta_block_processing_ecb(block_size_in_bytes,\
                                          action,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
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
