/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_huffman.h>
#include <kryptos_memory.h>
#include <string.h>

// WARN(Rafael): The aim of this module is to provide a way of increasing entropy. Common worries such as not bloat
//               the deflated output with the encoding tree is not a real issue here.
//
//               Moreover use compression to "increase" the entropy is not a silver bullet. Depending on your
//               communication channel/data, compress could be harmful because it could leak information about the
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
    kryptos_freeseg((t));\
    (t) = NULL;\
}

#define kryptos_huffman_get_code(b) ( hcodes[(b)].data )

#define kryptos_huffman_get_code_size(b) ( hcodes[(b)].data_size )

#define kryptos_huffman_get_code_bit(c) ( ((c) - 48) & 0x1 )

struct kryptos_huffman_tree_ctx {
    kryptos_u8_t byte;
    struct kryptos_huffman_tree_ctx *l, *r;
};

struct kryptos_huffman_freq_ctx {
    kryptos_u8_t byte;
    size_t freq;
    struct kryptos_huffman_tree_ctx *subtree;
};

struct kryptos_huffman_code_ctx {
    kryptos_u8_t data[KRYPTOS_HUFFMAN_MAX_CODE_SIZE];
    size_t data_size;
};

static struct kryptos_huffman_freq_ctx freq_table[256];

static size_t raw_freq[256];

static struct kryptos_huffman_tree_ctx *htree = NULL;

static struct kryptos_huffman_code_ctx hcodes[256];

static void kryptos_huffman_eval_byte_freq(const kryptos_u8_t *in, const size_t in_size);

static void kryptos_huffman_sort_nodes(void);

static void kryptos_huffman_mk_tree(void);

static void kryptos_huffman_get_codes(void);

static void kryptos_huffman_scan_codes(kryptos_u8_t *path_buff,
                                       const size_t path_index,
                                       const size_t path_buff_size, struct kryptos_huffman_tree_ctx *branch);

static void kryptos_huffman_deltree_recurr(struct kryptos_huffman_tree_ctx *htree);

static kryptos_u8_t *kryptos_huffman_dump_tree(kryptos_u8_t *out, const kryptos_u8_t *out_end);

static size_t kryptos_huffman_eval_deflated_out_size(const kryptos_u8_t *in, const size_t in_size);

static void kryptos_huffman_eval_byte_freq(const kryptos_u8_t *in, const size_t in_size) {
    const kryptos_u8_t *in_p, *in_p_end;
    struct kryptos_huffman_freq_ctx *curr_byte;
    size_t n;

    for (n = 0; n < 255; n++) {
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

    kryptos_huffman_sort_nodes();
}

static void kryptos_huffman_sort_nodes(void) {
    int swp;
    struct kryptos_huffman_freq_ctx aux;
    size_t n;

    swp = 1;

    while (swp) {
        swp = 0;

        for (n = 0; n < 254 && swp == 0; n++) {
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

static void kryptos_huffman_mk_tree(void) {
    size_t n;
    int has_merged = 1;
    struct kryptos_huffman_tree_ctx *subtree = NULL;

    for (n = 0; n < 255; n++) {
        if (freq_table[n].freq > 0) {
            kryptos_huffman_new_tree(freq_table[n].subtree);
            kryptos_huffman_new_tree(freq_table[n].subtree->l);
            freq_table[n].subtree->l->byte = freq_table[n].byte;
        }
    }

    while (has_merged) {
        has_merged = 0;
        for (n = 0; n < 254; n++) {
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
                        kryptos_freeseg(freq_table[n + 1].subtree);
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
                        kryptos_freeseg(freq_table[n].subtree);
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
                kryptos_huffman_sort_nodes();
            }
        }
    }
}

static void kryptos_huffman_deltree_recurr(struct kryptos_huffman_tree_ctx *htree) {
    if (htree == NULL) {
        return;
    }

    kryptos_huffman_deltree_recurr(htree->l);

    kryptos_huffman_deltree_recurr(htree->r);

    if (htree->l != NULL) {
        kryptos_freeseg(htree->l);
        htree->l = NULL;
    }

    if (htree->r != NULL) {
        kryptos_freeseg(htree->r);
        htree->r = NULL;
    }
}

static void kryptos_huffman_get_codes(void) {
    size_t c;
    kryptos_u8_t path_buff[KRYPTOS_HUFFMAN_MAX_CODE_SIZE];
    for (c = 0; c < 255; c++) {
        hcodes[c].data_size = 0;
    }
    kryptos_huffman_scan_codes(path_buff, 0, KRYPTOS_HUFFMAN_MAX_CODE_SIZE, htree);
}

static void kryptos_huffman_scan_codes(kryptos_u8_t *path_buff,
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
        //printf("%c %s\n", branch->byte, code);
        return;
    }

    if (branch->l != NULL) {
        path_buff[path_index] = '0';
        kryptos_huffman_scan_codes(path_buff, path_index + 1, path_buff_size, branch->l);
    }

    if (branch->r != NULL) {
        path_buff[path_index] = '1';
        kryptos_huffman_scan_codes(path_buff, path_index + 1, path_buff_size, branch->r);
    }
}

static size_t kryptos_huffman_eval_deflated_out_size(const kryptos_u8_t *in, const size_t in_size) {
    size_t total_size = 0;
    size_t n;

    // WARN(Rafael): This function will request more than is really needed.

    for (n = 0; n < 255; n++) {
        if (raw_freq[n] > 0) {
            total_size += raw_freq[n] * hcodes[n].data_size;
        }
    }

    while ((total_size % 8) != 0) {
        total_size++;
    }

    for (n = 0; n < 255; n++) {
        if (hcodes[n].data_size != 0) {
            total_size += sizeof(kryptos_u8_t) + hcodes[n].data_size;
        }
    }

    return total_size;
}

static kryptos_u8_t *kryptos_huffman_dump_tree(kryptos_u8_t *out, const kryptos_u8_t *out_end) {
    size_t c;
    for (c = 0; c < 255; c++) {
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
    return out;
}

kryptos_u8_t *kryptos_huffman_deflate(const kryptos_u8_t *in, const size_t in_size, size_t *out_size) {
    const kryptos_u8_t *in_p, *in_p_end;
    kryptos_u8_t *out, *out_p, *out_p_end;
    kryptos_u8_t bitbuf[1024], *bitbuf_p, *bitbuf_p_end;

    if (in == NULL || in_size == 0 || out_size == NULL) {
        return NULL;
    }

    // INFO(Rafael): Huffman coding evaluation.
    kryptos_huffman_eval_byte_freq(in, in_size);
    kryptos_huffman_mk_tree();
    kryptos_huffman_get_codes();

    *out_size = kryptos_huffman_eval_deflated_out_size(in, in_size);

    out = (kryptos_u8_t *) kryptos_newseg(*out_size);

    if (out == NULL) {
        goto kryptos_huffman_deflate_epilogue;
    }

    out_p = out;
    out_p_end = out_p + *out_size;
    out_p = kryptos_huffman_dump_tree(out_p, out_p_end);

    in_p = in;
    in_p_end = in_p + in_size;

    memset(bitbuf, '0', sizeof(bitbuf[0]) * KRYPTOS_HUFFMAN_MAX_CODE_SIZE);
    bitbuf_p = &bitbuf[0];
    bitbuf_p_end = bitbuf_p + sizeof(bitbuf[0]) * KRYPTOS_HUFFMAN_MAX_CODE_SIZE;

    while (in_p < in_p_end) {
        if ((bitbuf_p + kryptos_huffman_get_code_size(*in_p)) >= bitbuf_p_end) {
            bitbuf_p = &bitbuf[0];
            while (bitbuf_p < bitbuf_p_end) {
                *out_p = (kryptos_huffman_get_code_bit(*bitbuf_p    ) << 7) |
                         (kryptos_huffman_get_code_bit(*bitbuf_p + 1) << 6) |
                         (kryptos_huffman_get_code_bit(*bitbuf_p + 2) << 5) |
                         (kryptos_huffman_get_code_bit(*bitbuf_p + 3) << 4) |
                         (kryptos_huffman_get_code_bit(*bitbuf_p + 4) << 3) |
                         (kryptos_huffman_get_code_bit(*bitbuf_p + 5) << 2) |
                         (kryptos_huffman_get_code_bit(*bitbuf_p + 6) << 1) |
                         kryptos_huffman_get_code_bit(*bitbuf_p  + 7);
                bitbuf_p += 8;
                out_p++;
            }
            memset(bitbuf, '0', sizeof(bitbuf[0]) * KRYPTOS_HUFFMAN_MAX_CODE_SIZE);
            bitbuf_p = &bitbuf[0];
        }
        memcpy(bitbuf_p, kryptos_huffman_get_code(*in_p), kryptos_huffman_get_code_size(*in_p));
        bitbuf_p += kryptos_huffman_get_code_size(*in_p);
        in_p++;
    }

    if (bitbuf_p != &bitbuf[0]) {
        bitbuf_p_end = bitbuf_p + 1;
        bitbuf_p = &bitbuf[0];
        while (bitbuf_p < bitbuf_p_end) {
            *out_p = (kryptos_huffman_get_code_bit(*bitbuf_p    ) << 7) |
                     (kryptos_huffman_get_code_bit(*bitbuf_p + 1) << 6) |
                     (kryptos_huffman_get_code_bit(*bitbuf_p + 2) << 5) |
                     (kryptos_huffman_get_code_bit(*bitbuf_p + 3) << 4) |
                     (kryptos_huffman_get_code_bit(*bitbuf_p + 4) << 3) |
                     (kryptos_huffman_get_code_bit(*bitbuf_p + 5) << 2) |
                     (kryptos_huffman_get_code_bit(*bitbuf_p + 6) << 1) |
                     kryptos_huffman_get_code_bit(*bitbuf_p  + 7);
            bitbuf_p += 8;
            out_p++;
        }
    }

    kryptos_huffman_del_tree(htree);

    *out_size = out_p - out;

    out = kryptos_realloc(out, *out_size);

kryptos_huffman_deflate_epilogue:

    return out;
}

#undef kryptos_huffman_new_tree

#undef kryptos_huffman_del_tree

#undef KRYPTOS_HUFFMAN_MAX_CODE_SIZE
