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
#include <kryptos_idea.h>
#include <kryptos_blowfish.h>
#include <kryptos_feal.h>
#include <kryptos_camellia.h>
#include <kryptos_cast5.h>
#include <kryptos_rc2.h>
#include <kryptos_saferk64.h>
#include <kryptos_aes.h>

// DONE(Rafael): Verify the iv block size based on the chosen block cipher.
// DONE(Rafael): Add more ECB tests for DES.
// DONE(Rafael): Test the CBC mode on DES.

#define kryptos_task_set_ecb_mode(ktask) ( (ktask)->mode = kKryptosECB )

#define kryptos_task_set_cbc_mode(ktask) ( (ktask)->mode = kKryptosCBC )

#define kryptos_task_set_encrypt_action(ktask) ( (ktask)->action = kKryptosEncrypt )

#define kryptos_task_set_decrypt_action(ktask) ( (ktask)->action = kKryptosDecrypt )

#define kryptos_last_task_succeed(ktask) ( (ktask)->result == kKryptosSuccess )

#define kryptos_task_set_in(ktask, inb, inb_size) ( (ktask)->in = (inb), (ktask)->in_size = (inb_size) )

#define kryptos_task_get_out(ktask) ( (ktask)->out )

#define kryptos_task_get_out_size(ktask) ( (ktask)->out_size )

#define KRYPTOS_TASK_FREEALL (KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_KEY | KRYPTOS_TASK_IV)

#define kryptos_ld_user_key_prologue(state, state_nr, user_key, user_key_size, kp, kp_end, w, b, statement) {\
    memset(state, 0, sizeof(state[0]) * state_nr);\
    if (user_key == NULL || user_key_size == 0) {\
        statement;\
    }\
    kp = user_key;\
    kp_end = kp + user_key_size;\
    b = 0;\
    w = 0;\
}

#define kryptos_ld_user_key_byte(state, kp, kp_end, epilogue) {\
    if (kp == kp_end) goto epilogue;\
    state = (state << 8) | *kp;\
    kp++;\
    b = (b + 1) % sizeof(state);\
    if (b == 0) {\
        w++;\
    }\
}

#define kryptos_ld_user_key_epilogue(epilogue, state, w, b, kp, kp_end) {\
epilogue:\
    state[w] = state[w] << (b * sizeof(kryptos_u8_t));\
    b = w = 0;\
    kp = NULL;\
    kp_end = NULL;\
}

#define kryptos_custom_ld_user_key_epilogue(epilogue, state, w, b, kp, kp_end, stmt) {\
epilogue:\
    state[w] = state[w] << (b * sizeof(kryptos_u8_t));\
    stmt;\
    b = w = 0;\
    kp = NULL;\
    kp_end = NULL;\
}


#define kryptos_task_init_as_null(ktask) {\
    (ktask)->out = NULL;\
    (ktask)->out_size = 0;\
    (ktask)->in = NULL;\
    (ktask)->in_size = 0;\
    (ktask)->key = NULL;\
    (ktask)->key_size = 0;\
    (ktask)->iv = NULL;\
    (ktask)->iv_size = 0;\
    (ktask)->cipher = kKryptosCipherNr;\
    (ktask)->action = kKryptosActionNr;\
    (ktask)->mode = kKryptosCipherModeNr;\
    (ktask)->result = kKryptosTaskResultNr;\
    (ktask)->result_verbose = NULL;\
    memset((ktask)->arg, 0, sizeof((ktask)->arg));\
}

#define kryptos_task_free(ktask, freemask) {\
    if ((ktask)->out != NULL && ((freemask) & KRYPTOS_TASK_OUT) ) {\
        memset((ktask)->out, 0, (ktask)->out_size);\
        kryptos_freeseg((ktask)->out);\
        (ktask)->out = NULL;\
        (ktask)->out_size = 0;\
    }\
    if ((ktask)->in != NULL && ((freemask) & KRYPTOS_TASK_IN) ) {\
        memset((ktask)->in, 0, (ktask)->in_size);\
        kryptos_freeseg((ktask)->in);\
        (ktask)->in = NULL;\
        (ktask)->in_size = 0;\
    }\
    if ((ktask)->key != NULL && ((freemask) & KRYPTOS_TASK_KEY) ) {\
        memset((ktask)->key, 0, (ktask)->key_size);\
        kryptos_freeseg((ktask)->key);\
        (ktask)->key = NULL;\
        (ktask)->key_size = 0;\
    }\
    if ((ktask)->iv != NULL && ((freemask) & KRYPTOS_TASK_IV) ) {\
        memset((ktask)->iv, 0, (ktask)->iv_size);\
        kryptos_freeseg((ktask)->iv);\
        (ktask)->iv = NULL;\
        (ktask)->iv_size = 0;\
    }\
    (ktask)->cipher = kKryptosCipherNr;\
    (ktask)->action = kKryptosActionNr;\
    (ktask)->mode = kKryptosCipherModeNr;\
    (ktask)->result = kKryptosTaskResultNr;\
    (ktask)->result_verbose = NULL;\
    memset((ktask)->arg, 0, sizeof((ktask)->arg));\
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


#define kryptos_meta_block_processing_epilogue(label_name,\
                                               inblock, inblock_p, in_p, in_end,\
                                               outblock, outblock_p, out_p,\
                                               in_size, sks, ktask) {\
kryptos_ ## label_name:\
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
        in_p = kryptos_ansi_x923_padding(in, in_size, block_size_in_bytes, 1);\
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
        if (action == kKryptosEncrypt && in_block != in_end) {\
            kryptos_iv_data_flush(iv, out_block, block_size_in_bytes);\
            kryptos_apply_iv(in_block, iv, block_size_in_bytes);\
        } else {\
            kryptos_iv_data_flush(iv, in_block - block_size_in_bytes, block_size_in_bytes);\
        }\
        out_block = kryptos_block_parser(out_block, block_size_in_bytes, in_block, in_end, &in_block);\
    }\
    if (action == kKryptosDecrypt) {\
        (*out_size) = (*in_size) - block_size_in_bytes - *(out + (*in_size) - block_size_in_bytes - 1);\
        *(out + (*in_size) - block_size_in_bytes - 1) = 0;\
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
        in_p = kryptos_ansi_x923_padding(in, in_size, block_size_in_bytes, 1);\
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
        *out_size = (*in_size) - *(out + (*in_size) - 1);\
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
