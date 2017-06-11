/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_pem.h>
#include <kryptos.h>
#include <kryptos_memory.h>
#include <string.h>

#define KRYPTOS_PEM_BEGIN_PFX "-----BEGIN "

#define KRYPTOS_PEM_BEGIN_SFX "-----\n"

#define KRYPTOS_PEM_END_PFX "-----END "

#define KRYPTOS_PEM_END_SFX "-----\n"

static const kryptos_u8_t *kryptos_pem_header_begin(const kryptos_u8_t *header, const kryptos_u8_t *buf, const size_t buf_size);

static const kryptos_u8_t *kryptos_pem_header_end(const kryptos_u8_t *header, const kryptos_u8_t *buf, const size_t buf_size);

static kryptos_u8_t *kryptos_pem_header(const kryptos_u8_t *pfx, const kryptos_u8_t *header, const kryptos_u8_t *sfx);

static const kryptos_u8_t *kryptos_find_header(const kryptos_u8_t *header, const kryptos_u8_t *buf, const size_t buf_size);

static kryptos_u8_t *kryptos_pem_header(const kryptos_u8_t *pfx, const kryptos_u8_t *header, const kryptos_u8_t *sfx) {
    size_t header_size = 0;
    const kryptos_u8_t *p;
    kryptos_u8_t *hdata = NULL, *hp = NULL;

    p = pfx;
    while (*p != 0) {
        p++;
        header_size++;
    }

    p = header;
    while (*p != 0) {
        p++;
        header_size++;
    }

    p = sfx;
    while (*p != 0) {
        p++;
        header_size++;
    }

    hdata = (kryptos_u8_t *) kryptos_newseg(header_size + 1);

    if (hdata == NULL) {
        return NULL;
    }

    memset(hdata, 0, header_size + 1);

    hp = hdata;

    p = pfx;
    while (*p != 0) {
        *hp = *p;
        p++;
        hp++;
    }

    p = header;
    while (*p != 0) {
        *hp = *p;
        p++;
        hp++;
    }

    p = sfx;
    while (*p != 0) {
        *hp = *p;
        p++;
        hp++;
    }

    return hdata;
}

static const kryptos_u8_t *kryptos_find_header(const kryptos_u8_t *header, const kryptos_u8_t *buf, const size_t buf_size) {
    const kryptos_u8_t *bp = buf;
    const kryptos_u8_t *bp_end = bp + buf_size;
    const kryptos_u8_t *hp, *data = NULL;
    int equals = 1;

    hp = header;

    while (bp != bp_end && data == NULL) {
        if ((equals = (*hp == *bp)) == 0) {
            hp = header;
        } else {
            if (*(hp + 1) == 0) {
                data = (bp + 1);
            }
            hp++;
        }
        bp++;
    }

    return data;
}

static const kryptos_u8_t *kryptos_pem_header_begin(const kryptos_u8_t *header,
                                                    const kryptos_u8_t *buf, const size_t buf_size) {
    kryptos_u8_t *hmark = kryptos_pem_header(KRYPTOS_PEM_BEGIN_PFX, header, KRYPTOS_PEM_BEGIN_SFX);
    const kryptos_u8_t *data = NULL;

    if (hmark == NULL) {
        return NULL;
    }

    data = kryptos_find_header(hmark, buf, buf_size);

    kryptos_freeseg(hmark);

    return data;
}

static const kryptos_u8_t *kryptos_pem_header_end(const kryptos_u8_t *header,
                                                  const kryptos_u8_t *buf, const size_t buf_size) {
    kryptos_u8_t *hmark = kryptos_pem_header(KRYPTOS_PEM_END_PFX, header, KRYPTOS_PEM_END_SFX), *hmark_end = NULL;
    const kryptos_u8_t *data = NULL;

    if (hmark == NULL) {
        return NULL;
    }

    data = kryptos_find_header(hmark, buf, buf_size);

    if (data != NULL) {
        for (hmark_end = hmark; *hmark_end != 0; hmark_end++)
            ;
        data -= (hmark_end - hmark + 1); // INFO(Rafael): +1 due to the "\n" stated by the format.
    }

    kryptos_freeseg(hmark);

    return data;

}

kryptos_u8_t *kryptos_pem_get_data(const kryptos_u8_t *header, const kryptos_u8_t *buf, const size_t buf_size,
                                   size_t *data_size) {
    kryptos_task_ctx task, *ktask = &task;
    const kryptos_u8_t *data_begin = NULL, *data_end = NULL;

    kryptos_task_init_as_null(ktask);
    ktask->result = kKryptosProcessError;

    if (header == NULL || buf == NULL || buf_size == 0) {
        goto kryptos_pem_get_data_from_buffer_epilogue;
    }

    data_begin = kryptos_pem_header_begin(header, buf, buf_size);

    if (data_begin == NULL) {
        goto kryptos_pem_get_data_from_buffer_epilogue;
    }

    data_end = kryptos_pem_header_end(header, buf, buf_size);

    if (data_begin == NULL) {
        goto kryptos_pem_get_data_from_buffer_epilogue;
    }

    ktask->in_size = data_end - data_begin;
    ktask->in = kryptos_newseg(ktask->in_size);
    memset(ktask->in, 0, ktask->in_size);
    ktask->encoder = kKryptosEncodingBASE64;

    kryptos_task_set_decode_action(ktask);

    if (ktask->in == NULL) {
        goto kryptos_pem_get_data_from_buffer_epilogue;
    }

    memcpy(ktask->in, data_begin, ktask->in_size);

    kryptos_base64_processor(&ktask);

kryptos_pem_get_data_from_buffer_epilogue:

    if (kryptos_last_task_succeed(ktask)) {
        *data_size = ktask->out_size;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_IN);

    return ktask->out;
}

#undef KRYPTOS_PEM_BEGIN_PFX

#undef KRYPTOS_PEM_BEGIN_SFX

#undef KRYPTOS_PEM_END_PFX

#undef KRYPTOS_PEM_END_SFX
