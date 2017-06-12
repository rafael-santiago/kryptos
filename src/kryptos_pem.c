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

static size_t kryptos_pem_strlen(const kryptos_u8_t *data);

kryptos_task_result_t kryptos_pem_put_data(kryptos_u8_t **pem_buf, size_t *pem_buf_size,
                                           const kryptos_u8_t *header, const kryptos_u8_t *data, const size_t data_size) {
    kryptos_u8_t *header_begin = NULL, *header_end = NULL;
    kryptos_task_ctx task, *ktask = &task;
    kryptos_u8_t *new_pem_buf = NULL;
    size_t new_pem_buf_size = 0;
    size_t old_pem_buf_size = 0, header_begin_size = 0, header_end_size = 0;
    kryptos_task_result_t result = kKryptosProcessError;

    if (pem_buf == NULL || header == NULL || data == NULL || data_size == 0) {
        return result;
    }

    if ((*pem_buf) != NULL) {
        old_pem_buf_size = (pem_buf_size == NULL) ? kryptos_pem_strlen(*pem_buf) : *pem_buf_size;
        if (kryptos_find_header(header, (*pem_buf), old_pem_buf_size) != NULL) {
            return kKryptosInvalidParams;
        }
    }

    kryptos_task_init_as_null(ktask);
    ktask->result = kKryptosProcessError;

    header_begin = kryptos_pem_header(KRYPTOS_PEM_BEGIN_PFX, header, KRYPTOS_PEM_BEGIN_SFX);

    if (header_begin == NULL) {
        goto kryptos_pem_put_data_epilogue;
    }

    header_end = kryptos_pem_header(KRYPTOS_PEM_END_PFX, header, KRYPTOS_PEM_END_SFX);

    if (header_end == NULL) {
        goto kryptos_pem_put_data_epilogue;
    }

    header_begin_size = kryptos_pem_strlen(header_begin);

    header_end_size = kryptos_pem_strlen(header_end);

    new_pem_buf_size = header_begin_size + header_end_size + old_pem_buf_size;

    ktask->in = (kryptos_u8_t *) data; // INFO(Rafael): Yes, I know, shut up.
    ktask->in_size = data_size;
    ktask->encoder = kKryptosEncodingBASE64;

    kryptos_task_set_encode_action(ktask);

    kryptos_base64_processor(&ktask);

    result = ktask->result;

kryptos_pem_put_data_epilogue:

    if (kryptos_last_task_succeed(ktask)) {
        new_pem_buf_size += ktask->out_size + 1; // INFO(Rafael): +1 is related with '\n' before the header end.

        new_pem_buf = (kryptos_u8_t *) kryptos_newseg(new_pem_buf_size);
        if (new_pem_buf != NULL) {
            memset(new_pem_buf, 0, new_pem_buf_size);

            if ((*pem_buf) != NULL) {
                memcpy(new_pem_buf, (*pem_buf), old_pem_buf_size);
            }

            memcpy(new_pem_buf + old_pem_buf_size, header_begin, header_begin_size);
            memcpy(new_pem_buf + old_pem_buf_size + header_begin_size, ktask->out, ktask->out_size);
            *(new_pem_buf + old_pem_buf_size + header_begin_size + ktask->out_size) = '\n';
            memcpy(new_pem_buf + old_pem_buf_size + header_begin_size + ktask->out_size + 1, header_end, header_end_size);

            if ((*pem_buf) != NULL) {
                kryptos_freeseg(*pem_buf);
            }

            (*pem_buf) = new_pem_buf;

            if (pem_buf_size != NULL) {
                *pem_buf_size = new_pem_buf_size;
            }
        }
    }

    if (header_begin != NULL) {
        kryptos_freeseg(header_begin);
    }

    if (header_end != NULL) {
        kryptos_freeseg(header_end);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return result;
}

kryptos_u8_t *kryptos_pem_get_data(const kryptos_u8_t *header, const kryptos_u8_t *buf, const size_t buf_size,
                                   size_t *data_size) {
    kryptos_task_ctx task, *ktask = &task;
    const kryptos_u8_t *data_begin = NULL, *data_end = NULL;

    kryptos_task_init_as_null(ktask);
    ktask->result = kKryptosProcessError;

    if (header == NULL || buf == NULL || buf_size == 0) {
        goto kryptos_pem_get_data_epilogue;
    }

    data_begin = kryptos_pem_header_begin(header, buf, buf_size);

    if (data_begin == NULL) {
        goto kryptos_pem_get_data_epilogue;
    }

    data_end = kryptos_pem_header_end(header, buf, buf_size);

    if (data_begin == NULL) {
        goto kryptos_pem_get_data_epilogue;
    }

    ktask->in_size = data_end - data_begin;
    ktask->in = (kryptos_u8_t *) kryptos_newseg(ktask->in_size);

    if (ktask->in == NULL) {
        goto kryptos_pem_get_data_epilogue;
    }

    memset(ktask->in, 0, ktask->in_size);
    ktask->encoder = kKryptosEncodingBASE64;

    kryptos_task_set_decode_action(ktask);

    memcpy(ktask->in, data_begin, ktask->in_size);

    kryptos_base64_processor(&ktask);

kryptos_pem_get_data_epilogue:

    if (kryptos_last_task_succeed(ktask)) {
        *data_size = ktask->out_size;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_IN);

    return ktask->out;
}

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

static size_t kryptos_pem_strlen(const kryptos_u8_t *data) {
    // WARN(Rafael): Let's avoid using <string.h> high level stuff because in some cases we will not be able to use the
    //               entire libc conveniences.
    const kryptos_u8_t *d = data;

    if (d == NULL) {
        return 0;
    }

    while (*d != 0) {
        d++;
    }

    return (d - data);
}

#undef KRYPTOS_PEM_BEGIN_PFX

#undef KRYPTOS_PEM_BEGIN_SFX

#undef KRYPTOS_PEM_END_PFX

#undef KRYPTOS_PEM_END_SFX
