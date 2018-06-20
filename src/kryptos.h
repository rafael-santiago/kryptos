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
#include <kryptos_pem.h>
#include <kryptos_random.h>

#include <kryptos_arc4.h>
#include <kryptos_seal.h>
#include <kryptos_rabbit.h>
#include <kryptos_des.h>
#include <kryptos_idea.h>
#include <kryptos_blowfish.h>
#include <kryptos_feal.h>
#include <kryptos_camellia.h>
#include <kryptos_cast5.h>
#include <kryptos_rc2.h>
#include <kryptos_rc5.h>
#include <kryptos_rc6.h>
#include <kryptos_saferk64.h>
#include <kryptos_aes.h>
#include <kryptos_serpent.h>
#include <kryptos_tea.h>
#include <kryptos_xtea.h>
#include <kryptos_misty1.h>
#include <kryptos_mars.h>
#include <kryptos_present.h>
#include <kryptos_shacal1.h>
#include <kryptos_shacal2.h>
#include <kryptos_noekeon.h>

#include <kryptos_sha1.h>
#include <kryptos_sha224_256.h>
#include <kryptos_sha384_512.h>
#include <kryptos_md4.h>
#include <kryptos_md5.h>
#include <kryptos_ripemd128_160.h>
#include <kryptos_keccak.h>
#include <kryptos_tiger.h>
#include <kryptos_whirlpool.h>

#include <kryptos_base64.h>
#include <kryptos_uuencode.h>
#include <kryptos_huffman.h>

#include <kryptos_hmac.h>

#include <kryptos_dl_params.h>
#include <kryptos_dh.h>
#include <kryptos_elgamal.h>
#include <kryptos_dsa.h>

#include <kryptos_rsa.h>

#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define kryptos_task_set_ecb_mode(ktask) ( (ktask)->mode = kKryptosECB )

#define kryptos_task_set_cbc_mode(ktask) ( (ktask)->mode = kKryptosCBC )

#define kryptos_task_set_ctr_mode(ktask, uctr) ( (ktask)->mode = kKryptosCTR, (ktask)->ctr = (uctr) )

#define kryptos_task_set_encrypt_action(ktask) ( (ktask)->action = kKryptosEncrypt )

#define kryptos_task_set_decrypt_action(ktask) ( (ktask)->action = kKryptosDecrypt )

#define kryptos_last_task_succeed(ktask) ( (ktask)->result == kKryptosSuccess )

#define kryptos_task_set_in(ktask, inb, inb_size) ( (ktask)->in = (inb), (ktask)->in_size = (inb_size) )

#define kryptos_task_get_out(ktask) ( (ktask)->out )

#define kryptos_task_get_out_size(ktask) ( (ktask)->out_size )

#define kryptos_task_set_encode_action(ktask) ( (ktask)->action = kKryptosEncode )

#define kryptos_task_set_decode_action(ktask) ( (ktask)->action = kKryptosDecode )

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

#define kryptos_ld_user_key_byte(state, w, b, kp, kp_end, epilogue) {\
    if (kp == kp_end) goto epilogue;\
    state[w] = (state[w] << 8) | *kp;\
    kp++;\
    b = (b + 1) % sizeof(state[0]);\
    if (b == 0) {\
        w++;\
    }\
}

#define kryptos_ld_user_key_epilogue(epilogue, state, w, b, kp, kp_end) {\
epilogue:\
    state[w] = state[w] << (b << 3);\
    b = w = 0;\
    kp = NULL;\
    kp_end = NULL;\
}

#define kryptos_custom_ld_user_key_epilogue(epilogue, state, w, b, kp, kp_end, stmt) {\
epilogue:\
    state[w] = state[w] << (b << 3);\
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
    (ktask)->ctr = NULL;\
    (ktask)->cipher = kKryptosCipherNr;\
    (ktask)->encoder = kKryptosEncodingNr;\
    (ktask)->action = kKryptosActionNr;\
    (ktask)->mode = kKryptosCipherModeNr;\
    (ktask)->result = kKryptosTaskResultNr;\
    (ktask)->result_verbose = NULL;\
    memset((ktask)->arg, 0, sizeof((ktask)->arg));\
    memset(&(ktask)->aux_buffers, 0, sizeof((ktask)->aux_buffers));\
    (ktask)->mirror_p = NULL;\
}

#define kryptos_task_free(ktask, freemask) {\
    if ((ktask)->out != NULL && ((freemask) & KRYPTOS_TASK_OUT) ) {\
        kryptos_freeseg((ktask)->out, (ktask)->out_size);\
        (ktask)->out = NULL;\
        (ktask)->out_size = 0;\
    }\
    if ((ktask)->in != NULL && ((freemask) & KRYPTOS_TASK_IN) ) {\
        kryptos_freeseg((ktask)->in, (ktask)->in_size);\
        (ktask)->in = NULL;\
        (ktask)->in_size = 0;\
    }\
    if ((ktask)->key != NULL && ((freemask) & KRYPTOS_TASK_KEY) ) {\
        kryptos_freeseg((ktask)->key, (ktask)->key_size);\
        (ktask)->key = NULL;\
        (ktask)->key_size = 0;\
    }\
    if ((ktask)->iv != NULL && ((freemask) & KRYPTOS_TASK_IV) ) {\
        kryptos_freeseg((ktask)->iv, (ktask)->iv_size);\
        (ktask)->iv = NULL;\
        (ktask)->iv_size = 0;\
    }\
    if ((ktask)->aux_buffers.buf0 != NULL && ((freemask) & KRYPTOS_TASK_AUX_BUF0) ) {\
        kryptos_freeseg((ktask)->aux_buffers.buf0, (ktask)->aux_buffers.buf0_size);\
        (ktask)->aux_buffers.buf0 = NULL;\
        (ktask)->aux_buffers.buf0_size = 0;\
    }\
    if ((ktask)->aux_buffers.buf1 != NULL && ((freemask) & KRYPTOS_TASK_AUX_BUF1) ) {\
        kryptos_freeseg((ktask)->aux_buffers.buf1, (ktask)->aux_buffers.buf1_size);\
        (ktask)->aux_buffers.buf1 = NULL;\
        (ktask)->aux_buffers.buf1_size = 0;\
    }\
    if ((ktask)->ctr != NULL) {\
        (ktask)->ctr = NULL;\
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
                                      in_block, out_block, bufs, ctr,\
                                      epilogue, block_processor_call_scheme) {\
    if (mode == kKryptosCBC) {\
        kryptos_meta_block_processing_cbc(block_size_in_bytes,\
                                          action,\
                                          iv,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme);\
    } else if (mode == kKryptosECB) {\
        kryptos_meta_block_processing_ecb(block_size_in_bytes,\
                                          action,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme);\
    } else if (mode == kKryptosOFB) {\
        kryptos_meta_block_processing_ofb(block_size_in_bytes,\
                                          action,\
                                          iv,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme);\
    } else if (mode == kKryptosCTR) {\
        kryptos_meta_block_processing_ctr(block_size_in_bytes,\
                                          action,\
                                          iv,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block, bufs, ctr,\
                                          epilogue, block_processor_call_scheme);\
    }\
}

#define kryptos_meta_block_processing_epilogue(label_name,\
                                               inblock, inblock_p, in_p, in_end,\
                                               outblock, outblock_p, out_p,\
                                               in_size, block_size_in_bytes, sks, ktask) {\
kryptos_ ## label_name:\
    if ((*ktask)->out == NULL && (*ktask)->result != kKryptosKeyError) {\
        (*ktask)->result = kKryptosProcessError;\
        (*ktask)->result_verbose = "No memory to get a valid output.";\
    }\
    if (inblock != NULL) {\
        kryptos_freeseg(inblock, block_size_in_bytes);\
    }\
    if (outblock != NULL) {\
        kryptos_freeseg(outblock, block_size_in_bytes);\
    }\
    inblock_p = outblock_p = NULL;\
    in_size = 0;\
    in_p = in_end = out_p = NULL;\
    memset(&sks, 0, sizeof(sks));\
}

#define kryptos_meta_block_processing_ctr(block_size_in_bytes,\
                                          action,\
                                          iv,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block, bufs, ctr,\
                                          epilogue, block_processor_call_scheme) {\
    if ((void *)(bufs) == NULL) {\
        goto kryptos_ ## epilogue;\
    }\
    if (action == kKryptosEncrypt || action == kKryptosEncryptWithoutRandomPad) {\
        in_p = kryptos_ansi_x923_padding(in, in_size, block_size_in_bytes, action == kKryptosEncrypt);\
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
    (bufs)->buf0 = (kryptos_u8_t *) kryptos_newseg(block_size_in_bytes);\
    if ((bufs)->buf0 == NULL) {\
        goto kryptos_ ## epilogue;\
    }\
    memcpy((bufs)->buf0, iv, block_size_in_bytes);\
    memcpy(out_block, iv, block_size_in_bytes);\
    while (out_block != NULL) {\
        block_processor_call_scheme;\
        kryptos_iv_data_flush(iv, out_block, block_size_in_bytes);\
        out_block = kryptos_block_parser(out_block, block_size_in_bytes, in_block, in_end, &in_block);\
        if (out_block == NULL) {\
            break;\
        }\
        kryptos_apply_iv(out_block, iv, block_size_in_bytes);\
        memcpy(out_p, out_block, block_size_in_bytes);\
        out_p += block_size_in_bytes;\
        memcpy(iv, (bufs)->buf0, block_size_in_bytes);\
        kryptos_iv_inc_u32(iv, block_size_in_bytes);\
        memcpy((bufs)->buf0, iv, block_size_in_bytes);\
        kryptos_iv_data_flush(out_block, iv, block_size_in_bytes);\
    }\
    if ((bufs) != NULL && ctr != NULL && (bufs)->buf0 != NULL) {\
        *ctr = ((kryptos_u32_t)((kryptos_u8_t *)(bufs)->buf0)[block_size_in_bytes - 4]) << 24 |\
               ((kryptos_u32_t)((kryptos_u8_t *)(bufs)->buf0)[block_size_in_bytes - 3]) << 16 |\
               ((kryptos_u32_t)((kryptos_u8_t *)(bufs)->buf0)[block_size_in_bytes - 2]) <<  8 |\
               ((kryptos_u32_t)((kryptos_u8_t *)(bufs)->buf0)[block_size_in_bytes - 1]);\
    }\
    if ((bufs) != NULL && (bufs)->buf0 != NULL) {\
        kryptos_freeseg((bufs)->buf0, block_size_in_bytes);\
        (bufs)->buf0 = NULL;\
    }\
    if (action == kKryptosDecrypt) {\
        (*out_size) = (*in_size) - block_size_in_bytes - *(out + (*in_size) - block_size_in_bytes - 1);\
        *(out + (*in_size) - block_size_in_bytes - 1) = 0;\
    } else {\
        kryptos_freeseg(in_p, *in_size);\
    }\
    memset(iv, 0, block_size_in_bytes);\
}

#define kryptos_meta_block_processing_ofb(block_size_in_bytes,\
                                          action,\
                                          iv,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme) {\
    if (action == kKryptosEncrypt || action == kKryptosEncryptWithoutRandomPad) {\
        in_p = kryptos_ansi_x923_padding(in, in_size, block_size_in_bytes, action == kKryptosEncrypt);\
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
    memcpy(out_block, iv, block_size_in_bytes);\
    while (out_block != NULL) {\
        block_processor_call_scheme;\
        kryptos_iv_data_flush(iv, out_block, block_size_in_bytes);\
        out_block = kryptos_block_parser(out_block, block_size_in_bytes, in_block, in_end, &in_block);\
        if (out_block == NULL) {\
            break;\
        }\
        kryptos_apply_iv(out_block, iv, block_size_in_bytes);\
        memcpy(out_p, out_block, block_size_in_bytes);\
        out_p += block_size_in_bytes;\
        kryptos_iv_data_flush(out_block, iv, block_size_in_bytes);\
    }\
    if (action == kKryptosDecrypt) {\
        (*out_size) = (*in_size) - block_size_in_bytes - *(out + (*in_size) - block_size_in_bytes - 1);\
        *(out + (*in_size) - block_size_in_bytes - 1) = 0;\
    } else {\
        kryptos_freeseg(in_p, *in_size);\
    }\
    memset(iv, 0, block_size_in_bytes);\
}

#define kryptos_meta_block_processing_cbc(block_size_in_bytes,\
                                          action,\
                                          iv,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme) {\
    if (action == kKryptosEncrypt || action == kKryptosEncryptWithoutRandomPad) {\
        in_p = kryptos_ansi_x923_padding(in, in_size, block_size_in_bytes, action == kKryptosEncrypt);\
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
        kryptos_freeseg(in_p, *in_size);\
    }\
    memset(iv, 0, block_size_in_bytes);\
}

#define kryptos_meta_block_processing_ecb(block_size_in_bytes,\
                                          action,\
                                          in, in_p, in_end, in_size,\
                                          out, out_p, out_size,\
                                          in_block, out_block,\
                                          epilogue, block_processor_call_scheme) {\
    if (action == kKryptosEncrypt || action == kKryptosEncryptWithoutRandomPad) {\
        in_p = kryptos_ansi_x923_padding(in, in_size, block_size_in_bytes, action == kKryptosEncrypt);\
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
        kryptos_freeseg(in_p, *in_size);\
    }\
}

#define kryptos_oaep_hash(hname) kryptos_ ## hname ## _hash, kryptos_ ## hname ## _hash_size

#define kryptos_pss_hash(hname) kryptos_oaep_hash(hname)

#define kryptos_dsa_hash(hname) kryptos_ ## hname ## _hash

#define kryptos_hash(hname, ktask, data, data_size, hex) {\
    (ktask)->in = data;\
    (ktask)->in_size = data_size;\
    (ktask)->mirror_p = (ktask);\
    kryptos_ ## hname ## _hash(&(ktask)->mirror_p, hex);\
    (ktask)->mirror_p = NULL;\
}

#ifdef KRYPTOS_C99

#define kryptos_run_cipher(cname, ktask, cipher_args...) {\
    kryptos_ ## cname ## _setup((ktask), cipher_args);\
    (ktask)->mirror_p = (ktask);\
    kryptos_ ## cname ## _cipher(&(ktask)->mirror_p);\
    (ktask)->mirror_p = NULL;\
}

#define kryptos_run_cipher_hmac(cname, hname, ktask, cipher_args...) {\
    if ((ktask)->action == kKryptosEncrypt) {\
        kryptos_run_cipher(cname, ktask, cipher_args);\
        if (kryptos_last_task_succeed(ktask)) {\
            (ktask)->mirror_p = (ktask);\
            kryptos_hmac(&(ktask)->mirror_p,\
                         kryptos_ ## hname ## _hash,\
                         kryptos_ ## hname ## _hash_input_size,\
                         kryptos_ ## hname ## _hash_size);\
            (ktask)->mirror_p = NULL;\
        }\
    } else if ((ktask)->action == kKryptosDecrypt) {\
            (ktask)->mirror_p = (ktask);\
            kryptos_ ## cname ## _setup((ktask), cipher_args);\
            kryptos_hmac(&(ktask)->mirror_p,\
                         kryptos_ ## hname ## _hash,\
                         kryptos_ ## hname ## _hash_input_size,\
                         kryptos_ ## hname ## _hash_size);\
            if (kryptos_last_task_succeed(ktask)) {\
                kryptos_run_cipher(cname, ktask, cipher_args);\
            }\
            (ktask)->mirror_p = NULL;\
    }\
}

// TIP(Rafael): Pretty weird name in order to nobody never ever call it directly. :)

#define kryptos_perform_digsig_proto_action(cname, proto_level, ktask, cipher_args...) {\
    kryptos_ ## cname ## _digital_signature_setup((ktask), cipher_args);\
    (ktask)->mirror_p = (ktask);\
    kryptos_ ## cname ## _## proto_level(&(ktask)->mirror_p);\
    (ktask)->mirror_p = NULL;\
}

#define kryptos_sign(cname, ktask, cipher_args...) {\
    kryptos_perform_digsig_proto_action(cname, sign, ktask, cipher_args);\
}

#define kryptos_verify(cname, ktask, cipher_args...) {\
    kryptos_perform_digsig_proto_action(cname, verify, ktask, cipher_args);\
}

#endif // KRYPTOS_C99

#define kryptos_run_encoder(ename, ktask, data, data_size) {\
    kryptos_ ## ename ## _setup(ktask);\
    (ktask)->in = data;\
    (ktask)->in_size = data_size;\
    (ktask)->mirror_p = (ktask);\
    kryptos_ ## ename ## _processor(&(ktask)->mirror_p);\
    (ktask)->mirror_p = NULL;\
}

#endif // KRYPTOS_KRYPTOS_H
