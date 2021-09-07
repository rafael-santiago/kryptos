/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_huffman.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// WARN(Rafael): The aim of this module is to provide a way of increasing the entropy. Common worries such as not bloat
//               the deflated output with the encoding tree is not a real issue here.
//
//               Moreover use the compression to "increase" the entropy is not a silver bullet. Depending on your
//               communication channel/data, compressing could be harmful because it could leak information about the
//               data. If the attacker can make assumptions about the type of the data you should use it with care.

#define KRYPTOS_HUFFMAN_MAX_CODE_SIZE 255

#define kryptos_huffman_new_tree(t) {\
    (t) = (struct kryptos_huffman_tree_ctx *) kryptos_newseg(sizeof(struct kryptos_huffman_tree_ctx));\
    (t)->l = NULL;\
    (t)->r = NULL;\
    (t)->byte = 0;\
}

#define kryptos_huffman_del_tree(t) {\
    kryptos_huffman_deltree_recurr((t));\
    kryptos_freeseg((t), sizeof(struct kryptos_huffman_tree_ctx));\
    (t) = NULL;\
}

#define kryptos_huffman_get_code(hcodes, b) ( (hcodes)[(b)].data )

#define kryptos_huffman_get_code_size(hcodes, b) ( (hcodes)[(b)].data_size )

#define kryptos_huffman_get_code_bit(c) ( ((c) - 48) & 0x1 )

struct kryptos_huffman_tree_ctx {
    struct kryptos_huffman_tree_ctx *l, *r;
    kryptos_u8_t byte;
};

struct kryptos_huffman_freq_ctx {
    size_t freq;
    struct kryptos_huffman_tree_ctx *subtree;
    kryptos_u8_t byte;
};

struct kryptos_huffman_code_ctx {
    size_t data_size;
    kryptos_u8_t data[KRYPTOS_HUFFMAN_MAX_CODE_SIZE];
};

static void kryptos_huffman_eval_byte_freq(struct kryptos_huffman_freq_ctx *freq_table, size_t *raw_freq,
                                           const kryptos_u8_t *in, const size_t in_size);

static void kryptos_huffman_sort_nodes(struct kryptos_huffman_freq_ctx *freq_table);

static struct kryptos_huffman_tree_ctx *kryptos_huffman_mk_tree(struct kryptos_huffman_freq_ctx *freq_table);

static void kryptos_huffman_deltree_recurr(struct kryptos_huffman_tree_ctx *htree);

static void kryptos_huffman_get_codes(struct kryptos_huffman_code_ctx *hcodes, struct kryptos_huffman_tree_ctx *htree);

static void kryptos_huffman_scan_codes(struct kryptos_huffman_code_ctx *hcodes,
                                       kryptos_u8_t *path_buff,
                                       const size_t path_index,
                                       const size_t path_buff_size, struct kryptos_huffman_tree_ctx *branch);

static size_t kryptos_huffman_eval_deflated_out_size(size_t *raw_freq, struct kryptos_huffman_code_ctx *hcodes,
                                                     const kryptos_u8_t *in, const size_t in_size);

static kryptos_u8_t *kryptos_huffman_dump_tree(kryptos_u8_t *out, const kryptos_u8_t *out_end,
                                               struct kryptos_huffman_code_ctx *hcodes);

static const kryptos_u8_t *kryptos_huffman_add_node(struct kryptos_huffman_tree_ctx **tree,
                                                    const kryptos_u8_t *in, const kryptos_u8_t *in_end);

static const kryptos_u8_t *kryptos_huffman_rebuild_tree(struct kryptos_huffman_tree_ctx **htree,
                                                        const kryptos_u8_t *in, const size_t in_size);

kryptos_u8_t *kryptos_huffman_inflate(const kryptos_u8_t *in, const size_t in_size, size_t *out_size) {
    kryptos_u8_t *out = NULL, *out_p, *out_p_end;
    const kryptos_u8_t *in_p, *in_p_end;
    struct kryptos_huffman_tree_ctx *tp;
    ssize_t bit;
    struct kryptos_huffman_tree_ctx *htree = NULL;

    in_p_end = in + in_size;
    in_p = kryptos_huffman_rebuild_tree(&htree, in, in_size);
    tp = htree;

    if (out_size == NULL) {
        goto kryptos_huffman_inflate_epilogue;
    }

    memcpy(out_size, in_p, sizeof(size_t));
    in_p += sizeof(size_t);

    out = (kryptos_u8_t *) kryptos_newseg(*out_size + 1);

    if (out == NULL) {
        goto kryptos_huffman_inflate_epilogue;
    }

    memset(out, 0, *out_size + 1);

    out_p = out;
    out_p_end = out_p + *out_size;

    while (out_p != out_p_end && in_p < in_p_end) {
        for (bit = 7; bit >= 0 && out_p != out_p_end; bit--) {
            if (((*in_p & (0x1 << bit)) >> bit) == 0) {
                tp = tp->l;
            } else {
                tp = tp->r;
            }

            if (tp->l == NULL && tp->r == NULL) {
                *out_p = tp->byte;
                out_p++;
                tp = htree;
            }
        }
        in_p++;
    }

kryptos_huffman_inflate_epilogue:

    kryptos_huffman_del_tree(htree);
    out_p = out_p_end = NULL;
    tp = htree = NULL;
    in_p = in_p_end = NULL;
    bit = 0;

    return out;
}

kryptos_u8_t *kryptos_huffman_deflate(const kryptos_u8_t *in, const size_t in_size, size_t *out_size) {
    const kryptos_u8_t *in_p, *in_p_end;
    kryptos_u8_t *out = NULL, *out_p, *out_p_end;
    kryptos_u8_t bitbuf[1024], *bitbuf_p, *bitbuf_p_end, *code_p;
    struct kryptos_huffman_freq_ctx freq_table[256];
    size_t raw_freq[256];
    struct kryptos_huffman_tree_ctx *htree = NULL;
#ifdef KRYPTOS_KERNEL_MODE
    // INFO(Rafael): Avoiding stack consumption in kernel mode.
    static struct kryptos_huffman_code_ctx hcodes[256];
#else
    struct kryptos_huffman_code_ctx hcodes[256];
#endif

    if (in == NULL || in_size == 0 || out_size == NULL) {
        return NULL;
    }

    // INFO(Rafael): Huffman coding evaluation.
    kryptos_huffman_eval_byte_freq(freq_table, raw_freq, in, in_size);

    htree = kryptos_huffman_mk_tree(freq_table);

    if (htree == NULL) {
        goto kryptos_huffman_deflate_epilogue;
    }

    kryptos_huffman_get_codes(hcodes, htree);

    *out_size = kryptos_huffman_eval_deflated_out_size(raw_freq, hcodes, in, in_size);

    out = (kryptos_u8_t *) kryptos_newseg(*out_size);

    if (out == NULL) {
        goto kryptos_huffman_deflate_epilogue;
    }

    out_p = out;
    out_p_end = out_p + *out_size;
    out_p = kryptos_huffman_dump_tree(out_p, out_p_end, hcodes);

    memcpy(out_p, &in_size, sizeof(in_size));
    out_p += sizeof(in_size);

    in_p = in;
    in_p_end = in_p + in_size;

    memset(bitbuf, '0', sizeof(bitbuf));
    bitbuf_p = &bitbuf[0];
    bitbuf_p_end = bitbuf_p + sizeof(bitbuf);

    while (in_p < in_p_end) {
        if ((bitbuf_p + kryptos_huffman_get_code_size(hcodes, *in_p)) >= bitbuf_p_end) {
            code_p = kryptos_huffman_get_code(hcodes, *in_p);

            while (bitbuf_p != bitbuf_p_end && *code_p != 0) {
                *bitbuf_p = *code_p;
                code_p++;
                bitbuf_p++;
            }

            bitbuf_p = &bitbuf[0];

            while (bitbuf_p < bitbuf_p_end) {
                *out_p = (kryptos_huffman_get_code_bit(bitbuf_p[0]) << 7) |
                         (kryptos_huffman_get_code_bit(bitbuf_p[1]) << 6) |
                         (kryptos_huffman_get_code_bit(bitbuf_p[2]) << 5) |
                         (kryptos_huffman_get_code_bit(bitbuf_p[3]) << 4) |
                         (kryptos_huffman_get_code_bit(bitbuf_p[4]) << 3) |
                         (kryptos_huffman_get_code_bit(bitbuf_p[5]) << 2) |
                         (kryptos_huffman_get_code_bit(bitbuf_p[6]) << 1) |
                         kryptos_huffman_get_code_bit(bitbuf_p[7]);
                bitbuf_p += 8;
                out_p++;
            }

            memset(bitbuf, '0', sizeof(bitbuf));

            bitbuf_p = &bitbuf[0];

            while (*code_p != 0) {
                *bitbuf_p = *code_p;
                bitbuf_p++;
                code_p++;
            }

            in_p++;

            if (in_p >= in_p_end) {
                continue;
            }

        }
        memcpy(bitbuf_p, kryptos_huffman_get_code(hcodes, *in_p), kryptos_huffman_get_code_size(hcodes, *in_p));
        bitbuf_p += kryptos_huffman_get_code_size(hcodes, *in_p);
        in_p++;
    }

    if (bitbuf_p != &bitbuf[0]) {
        bitbuf_p_end = bitbuf_p + 1;
        bitbuf_p = &bitbuf[0];
        while (bitbuf_p < bitbuf_p_end) {
            *out_p = (kryptos_huffman_get_code_bit(bitbuf_p[0]) << 7) |
                     (kryptos_huffman_get_code_bit(bitbuf_p[1]) << 6) |
                     (kryptos_huffman_get_code_bit(bitbuf_p[2]) << 5) |
                     (kryptos_huffman_get_code_bit(bitbuf_p[3]) << 4) |
                     (kryptos_huffman_get_code_bit(bitbuf_p[4]) << 3) |
                     (kryptos_huffman_get_code_bit(bitbuf_p[5]) << 2) |
                     (kryptos_huffman_get_code_bit(bitbuf_p[6]) << 1) |
                     kryptos_huffman_get_code_bit(bitbuf_p[7]);
            bitbuf_p += 8;
            out_p++;
        }
    }

    *out_size = out_p - out;

    out = kryptos_realloc(out, *out_size);

kryptos_huffman_deflate_epilogue:

    if (htree != NULL) {
        kryptos_huffman_del_tree(htree);
        htree = NULL;
    }

    memset(hcodes, 0, sizeof(hcodes));
    memset(freq_table, 0, sizeof(freq_table));
    memset(raw_freq, 0, sizeof(raw_freq));
    memset(bitbuf, 0, sizeof(bitbuf));
    in_p = in_p_end = NULL;
    out_p = out_p_end = bitbuf_p = bitbuf_p_end = code_p = NULL;

    return out;
}

static void kryptos_huffman_eval_byte_freq(struct kryptos_huffman_freq_ctx *freq_table, size_t *raw_freq,
                                           const kryptos_u8_t *in, const size_t in_size) {
    const kryptos_u8_t *in_p, *in_p_end;
    struct kryptos_huffman_freq_ctx *curr_byte;
    size_t n;

    for (n = 0; n < 256; n++) {
        freq_table[n].byte = 0;
        freq_table[n].freq = 0;
        freq_table[n].subtree = NULL;
        raw_freq[n] = 0;
    }

    in_p = in;
    in_p_end = in + in_size;

    while (in_p != in_p_end) {
        curr_byte = &freq_table[*in_p];

        if (curr_byte->byte == 0) {
            curr_byte->byte = *in_p;
        }

        curr_byte->freq++;
        raw_freq[*in_p] = curr_byte->freq;

        in_p++;
    }

    kryptos_huffman_sort_nodes(freq_table);
}

static void kryptos_huffman_sort_nodes(struct kryptos_huffman_freq_ctx *freq_table) {
    int swp;
    struct kryptos_huffman_freq_ctx aux;
    size_t n;

    swp = 1;

    while (swp) {
        swp = 0;

        for (n = 0; n < 255 && swp == 0; n++) {
            if (freq_table[n].freq > freq_table[n + 1].freq) {
                aux = freq_table[n];
                freq_table[n] = freq_table[n + 1];
                freq_table[n + 1] = aux;
                swp = 1;
            }
        }
    }
/*
    for (n = 0; n < 255; n++) {
        if (freq_table[n].freq > 0) {
            printf("%c %d times.\n", freq_table[n].byte, freq_table[n].freq);
        }
    }
    printf("--\n");
*/
}

static struct kryptos_huffman_tree_ctx *kryptos_huffman_mk_tree(struct kryptos_huffman_freq_ctx *freq_table) {
    size_t n;
    struct kryptos_huffman_tree_ctx *subtree = NULL, *htree = NULL;

    for (n = 0; n < 256; n++) {
        if (freq_table[n].freq > 0) {
            kryptos_huffman_new_tree(freq_table[n].subtree);
            kryptos_huffman_new_tree(freq_table[n].subtree->l);
            freq_table[n].subtree->l->byte = freq_table[n].byte;
        }
    }

    for (n = 0; n < 255; n++) {
        if (freq_table[n].freq > 0 && freq_table[n + 1].freq > 0) {
            if (freq_table[n].subtree->r == NULL) {
                // INFO(Rafael): freq_table[n].subtree->r points.
                freq_table[n].subtree->r = (freq_table[n + 1].subtree->r == NULL) ?
                                                freq_table[n + 1].subtree->l :
                                                freq_table[n + 1].subtree;
                freq_table[n].freq += freq_table[n + 1].freq;
                freq_table[n].byte = 0;
                freq_table[n + 1].byte = 0;
                freq_table[n + 1].freq = 0;
                if (freq_table[n + 1].subtree->r == NULL) {
                    kryptos_freeseg(freq_table[n + 1].subtree, sizeof(struct kryptos_huffman_tree_ctx));
                }
                freq_table[n + 1].subtree = NULL;
                htree = freq_table[n].subtree;
            } else if (freq_table[n + 1].subtree->r == NULL) {
                // INFO(Rafael): freq_table[n + 1].subtree->r points.
                freq_table[n + 1].subtree->r = (freq_table[n].subtree->r == NULL) ?
                                                    freq_table[n].subtree->l :
                                                    freq_table[n].subtree;
                freq_table[n + 1].freq += freq_table[n].freq;
                freq_table[n + 1].byte = 0;
                freq_table[n].byte = 0;
                freq_table[n].freq = 0;
                if (freq_table[n].subtree->r == NULL) {
                    kryptos_freeseg(freq_table[n].subtree, sizeof(struct kryptos_huffman_tree_ctx));
                }
                freq_table[n].subtree = NULL;
                htree = freq_table[n + 1].subtree;
            } else {
                // INFO(Rafael): A new subtree points (L: freq_table[n].subtree / R: freq_table[n+1].subtree).
                subtree = freq_table[n].subtree;
                freq_table[n].freq += freq_table[n + 1].freq;
                kryptos_huffman_new_tree(freq_table[n].subtree);
                freq_table[n].subtree->l = subtree;
                freq_table[n].subtree->r = freq_table[n + 1].subtree;
                freq_table[n + 1].subtree = NULL;
                freq_table[n + 1].freq = 0;
                htree = freq_table[n].subtree;
            }
            kryptos_huffman_sort_nodes(freq_table);
        }
    }

    return htree;
}

static void kryptos_huffman_deltree_recurr(struct kryptos_huffman_tree_ctx *htree) {
    if (htree == NULL) {
        return;
    }

    kryptos_huffman_deltree_recurr(htree->l);

    kryptos_huffman_deltree_recurr(htree->r);

    htree->byte = 0;

    if (htree->l != NULL) {
        kryptos_freeseg(htree->l, sizeof(struct kryptos_huffman_tree_ctx));
        htree->l = NULL;
    }

    if (htree->r != NULL) {
        kryptos_freeseg(htree->r, sizeof(struct kryptos_huffman_tree_ctx));
        htree->r = NULL;
    }
}

static void kryptos_huffman_get_codes(struct kryptos_huffman_code_ctx *hcodes, struct kryptos_huffman_tree_ctx *htree) {
    size_t c;
    kryptos_u8_t path_buff[KRYPTOS_HUFFMAN_MAX_CODE_SIZE];
    for (c = 0; c < 256; c++) {
        hcodes[c].data_size = 0;
    }
    kryptos_huffman_scan_codes(hcodes, path_buff, 0, KRYPTOS_HUFFMAN_MAX_CODE_SIZE, htree);
    memset(path_buff, 0, sizeof(path_buff));
}

static void kryptos_huffman_scan_codes(struct kryptos_huffman_code_ctx *hcodes,
                                       kryptos_u8_t *path_buff,
                                       const size_t path_index,
                                       const size_t path_buff_size, struct kryptos_huffman_tree_ctx *branch) {
    struct kryptos_huffman_code_ctx *code;

    if (path_index > path_buff_size) {
        // WARN(Rafael): It should never happen.
        return;
    }

    if (branch->l == NULL && branch->r == NULL) {
        code = &hcodes[branch->byte];
        memset(code->data, 0, sizeof(code->data));
        memcpy(code->data, path_buff, path_index);
        code->data_size = path_index;
        return;
    }

    if (branch->l != NULL) {
        path_buff[path_index] = '0';
        kryptos_huffman_scan_codes(hcodes, path_buff, path_index + 1, path_buff_size, branch->l);
    }

    if (branch->r != NULL) {
        path_buff[path_index] = '1';
        kryptos_huffman_scan_codes(hcodes, path_buff, path_index + 1, path_buff_size, branch->r);
    }
}

static size_t kryptos_huffman_eval_deflated_out_size(size_t *raw_freq, struct kryptos_huffman_code_ctx *hcodes,
                                                     const kryptos_u8_t *in, const size_t in_size) {
    size_t total_size = 2 + sizeof(size_t);
    size_t n;

    // WARN(Rafael): This function will request more than the enough.

    for (n = 0; n < 256; n++) {
        if (raw_freq[n] > 0) {
            total_size += raw_freq[n] * hcodes[n].data_size;
        }
    }

    while ((total_size % 8) != 0) {
        total_size++;
    }

    for (n = 0; n < 256; n++) {
        if (hcodes[n].data_size != 0) {
            total_size += sizeof(kryptos_u8_t) + hcodes[n].data_size;
        }
    }

    return total_size;
}

static kryptos_u8_t *kryptos_huffman_dump_tree(kryptos_u8_t *out, const kryptos_u8_t *out_end,
                                               struct kryptos_huffman_code_ctx *hcodes) {
    unsigned int c;
    for (c = 0; c < 256; c++) {
        if (hcodes[c].data_size != 0) {
            if ((out + hcodes[c].data_size) > out_end) {
                // INFO(Rafael): It should never happen.
                return NULL;
            }
            memcpy(out, hcodes[c].data, hcodes[c].data_size);
            out += hcodes[c].data_size;
            *out = c;
            out++;
        }
    }
    *out = 0;
    *(out + 1) = 0;
    out += 2;
    return out;
}

static const kryptos_u8_t *kryptos_huffman_add_node(struct kryptos_huffman_tree_ctx **tree,
                                                    const kryptos_u8_t *in, const kryptos_u8_t *in_end) {

    if ((*in == 0 && *(in + 1) == 0) || (in == in_end)) {
        return in;
    }

    if (*tree == NULL) {
        kryptos_huffman_new_tree((*tree));
    }

    if (*in == '0') {
        return kryptos_huffman_add_node(&(*tree)->l, in + 1, in_end);
    } else if (*in == '1') {
        return kryptos_huffman_add_node(&(*tree)->r, in + 1, in_end);
    } else {
        (*tree)->byte = *in;
    }

    return in + 1;
}

static const kryptos_u8_t *kryptos_huffman_rebuild_tree(struct kryptos_huffman_tree_ctx **htree,
                                                        const kryptos_u8_t *in, const size_t in_size) {
    const kryptos_u8_t *in_p, *in_p_end;
    in_p = in;
    in_p_end = in_p + in_size;

    while (in_p < in_p_end && !(*in_p == 0 && *(in_p + 1) == 0)) {
        in_p = kryptos_huffman_add_node(htree, in_p, in_p_end);
    }

    return in_p + 2;
}

#undef KRYPTOS_HUFFMAN_MAX_CODE_SIZE

#undef kryptos_huffman_new_tree

#undef kryptos_huffman_del_tree

#undef kryptos_huffman_get_code

#undef kryptos_huffman_get_code_size

#undef kryptos_huffman_get_code_bit
