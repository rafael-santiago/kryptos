/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "encoding_tests.h"
#include <kryptos_base64.h>
#include <kryptos_uuencode.h>
#include <kryptos_huffman.h>
#include <kryptos_pem.h>
#include <kryptos.h>
#include <string.h>

CUTE_TEST_CASE(kryptos_base64_tests)
    kryptos_task_ctx t, *ktask = &t;

    struct base64_test {
        kryptos_u8_t *in;
        size_t in_size;
        kryptos_u8_t *out;
        size_t out_size;
    };

    struct base64_test test_vector[] = {
        {      "f", 1,     "Zg==", 4 },
        {     "fo", 2,     "Zm8=", 4 },
        {    "foo", 3,     "Zm9v", 4 },
        {   "foob", 4, "Zm9vYg==", 8 },
        {  "fooba", 5, "Zm9vYmE=", 8 },
        { "foobar", 6, "Zm9vYmFy", 8 }
    }; // INFO(Rafael): Test data from RFC-4648.

    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);

    t.encoder = kKryptosEncodingBASE64;

    for (tv = 0; tv < tv_nr; tv++) {
        t.in = test_vector[tv].in;
        t.in_size = test_vector[tv].in_size;
        kryptos_task_set_encode_action(ktask);
        kryptos_base64_processor(&ktask);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[tv].out_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].out, t.out_size) == 0);

        t.in = t.out;
        t.in_size = t.out_size;
        kryptos_task_set_decode_action(ktask);
        kryptos_base64_processor(&ktask);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[tv].in_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].in, t.out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_uuencode_tests)
    kryptos_task_ctx t, *ktask = &t;

    struct uuencode_test {
        kryptos_u8_t *in;
        kryptos_u8_t in_size;
        kryptos_u8_t *out;
        kryptos_u8_t out_size;
    };

    struct uuencode_test test_vector[] = {
        { "ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC", 60,
          "M04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#\n"
          "/04)#04)#04)#04)#04)#\n"
          "`\n", 86 }
    };

    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t *out;
    size_t out_size;

    t.encoder = kKryptosEncodingUUENCODE;

    for (tv = 0; tv < tv_nr; tv++) {
        t.in = test_vector[tv].in;
        t.in_size = test_vector[tv].in_size;
        kryptos_task_set_encode_action(ktask);
        kryptos_uuencode_processor(&ktask);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[tv].out_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].out, t.out_size) == 0);

        t.in = t.out;
        t.in_size = t.out_size;
        kryptos_task_set_decode_action(ktask);
        kryptos_uuencode_processor(&ktask);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[tv].in_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].in, t.out_size) == 0);

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_huffman_tests)
    kryptos_u8_t *test_vector[] = {
        "AAAAAAAAAABBBBBCCDEEEEEFFFGGGGZZZZYYXXXXXXXX",

        "ACAAGATGCCATTGTCCCCCGGCCTCCTGCTGCTGCTGCTCTCCGGGGCCACGGCCACCGCTGCCCTGCC"
        "CCTGGAGGGTGGCCCCACCGGCCGAGACAGCGAGCATATGCAGGAAGCGGCAGGAATAAGGAAAAGCAGC"
        "CTCCTGACTTTCCTCGCTTGGTGGTTTGAGTGGACCTCCCAGGCCAGTGCCGGGCCCCTCATAGGAGAGG"
        "AAGCTCGGGAGGTGGCCAGGCGGCAGGAAGGCGCACCCCCCCAGCAATCCGCGCGCCGGGACAGAATGCC"
        "CTGCAGGAACTTCTTCTGGAAGACCTTCTCCTCCTGCAAATAAAACCTCACCCATGAATGCTCACGCAAG"
        "TTTAATTACAGACCTGAA",

        "E como eu palmilhasse vagamente\n"
        "uma estrada de Minas, pedregosa,\n"
        "e no fecho da tarde um sino rouco\n\n"
        "se misturasse ao som de meus sapatos\n"
        "que era pausado e seco; e aves pairassem\n"
        "no céu de chumbo, e suas formas pretas\n\n"
        "lentamente se fossem diluindo\n"
        "na escuridão maior, vinda dos montes\n"
        "e de meu próprio ser desenganado,\n\n"
        "a máquina do mundo se entreabriu\n"
        "para quem de a romper já se esquivava\n"
        "e só de o ter pensado se carpia.\n\n"
        "Abriu-se majestosa e circunspecta,\n"
        "sem emitir um som que fosse impuro\n"
        "nem um clarão maior que o tolerável\n\n"
        "pelas pupilas gastas na inspeção\n"
        "contínua e dolorosa do deserto,\n"
        "e pela mente exausta de mentar\n\n"
        "toda uma realidade que transcende\n"
        "a própria imagem sua debuxada\n"
        "no rosto do mistério, nos abismos.\n\n"
        "Abriu-se em calma pura, e convidando\n"
        "quantos sentidos e intuições restavam\n"
        "a quem de os ter usado os já perdera\n\n"
        "e nem desejaria recobrá-los,\n"
        "se em vão e para sempre repetimos\n"
        "os mesmos sem roteiro tristes périplos,\n\n"
        "convidando-os a todos, em coorte,\n"
        "a se aplicarem sobre o pasto inédito\n"
        "da natureza mítica das coisas,\n\n"
        "assim me disse, embora voz alguma\n"
        "ou sopro ou eco ou simples percussão\n"
        "atestasse que alguém, sobre a montanha,\n\n"
        "a outro alguém, noturno e miserável,\n"
        "em colóquio se estava dirigindo:\n"
        "O que procuraste em ti ou fora de\n\n"
        "teu ser restrito e nunca se mostrou,\n"
        "mesmo afetando dar-se ou se rendendo,\n"
        "e a cada instante mais se retraindo,\n\n"
        "olha, repara, ausculta: essa riqueza\n"
        "sobrante a toda pérola, essa ciência\n"
        "sublime e formidável, mas hermética,\n\n"
        "essa total explicação da vida,\n"
        "esse nexo primeiro e singular,\n"
        "que nem concebes mais, pois tão esquivo\n\n"
        "se revelou ante a pesquisa ardente\n"
        "em que te consumiste... vê, contempla,\n"
        "abre teu peito para agasalhá-lo.\n\n"
        "As mais soberbas pontes e edifícios,\n"
        "o que nas oficinas se elabora,\n"
        "o que pensado foi e logo atinge\n\n"
        "distância superior ao pensamento,\n"
        "os recursos da terra dominados,\n"
        "e as paixões e os impulsos e os tormentos\n\n"
        "e tudo que define o ser terrestre\n"
        "ou se prolonga até nos animais\n"
        "e chega às plantas para se embeber\n\n"
        "no sono rancoroso dos minérios,\n"
        "dá volta ao mundo e torna a se engolfar,\n"
        "na estranha ordem geométrica de tudo,\n\n"
        "e o absurdo original e seus enigmas,\n"
        "suas verdades altas mais que todos\n"
        "monumentos erguidos à verdade:\n\n"
        "e a memória dos deuses, e o solene\n"
        "sentimento de morte, que floresce\n"
        "no caule da existência mais gloriosa,\n\n"
        "tudo se apresentou nesse relance\n"
        "e me chamou para seu reino augusto,\n"
        "afinal submetido à vista humana.\n\n"
        "Mas, como eu relutasse em responder\n"
        "a tal apelo assim maravilhoso,\n"
        "pois a fé se abrandara, e mesmo o anseio,\n\n"
        "a esperança mais mínima — esse anelo\n"
        "de ver desvanecida a treva espessa\n"
        "que entre os raios do sol inda se filtra;\n\n"
        "como defuntas crenças convocadas\n"
        "presto e fremente não se produzissem\n"
        "a de novo tingir a neutra face\n\n"
        "que vou pelos caminhos demonstrando,\n"
        "e como se outro ser, não mais aquele\n"
        "habitante de mim há tantos anos,\n\n"
        "passasse a comandar minha vontade\n"
        "que, já de si volúvel, se cerrava\n"
        "semelhante a essas flores reticentes\n\n"
        "em si mesmas abertas e fechadas;\n"
        "como se um dom tardio já não fora\n"
        "apetecível, antes despiciendo,\n\n"
        "baixei os olhos, incurioso, lasso,\n"
        "desdenhando colher a coisa oferta\n"
        "que se abria gratuita a meu engenho.\n\n"
        "A treva mais estrita já pousara\n"
        "sobre a estrada de Minas, pedregosa,\n"
        "e a máquina do mundo, repelida,\n\n"
        "se foi miudamente recompondo,\n"
        "enquanto eu, avaliando o que perdera,\n"
        "seguia vagaroso, de mãos pensas.\n\n\n\n"
        "-- A Máquina do Mundo - Carlos Drummond de Andrade"
    };
    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    size_t in_size, deflated_buffer_size, inflated_buffer_size;
    kryptos_u8_t *deflated_buffer = NULL, *inflated_buffer = NULL;

    for (tv = 0; tv < tv_nr; tv++) {
        in_size = strlen(test_vector[tv]);
        deflated_buffer = kryptos_huffman_deflate(test_vector[tv], in_size, &deflated_buffer_size);
        CUTE_ASSERT(deflated_buffer != NULL);
        inflated_buffer = kryptos_huffman_inflate(deflated_buffer, deflated_buffer_size, &inflated_buffer_size);
        CUTE_ASSERT(inflated_buffer != NULL);
        CUTE_ASSERT(inflated_buffer_size == in_size);
        CUTE_ASSERT(memcmp(inflated_buffer, test_vector[tv], inflated_buffer_size) == 0);
        kryptos_freeseg(deflated_buffer);
        kryptos_freeseg(inflated_buffer);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_pem_get_data_tests)
    kryptos_u8_t *buf = "-----BEGIN FOOBAR (1)-----\n"
                        "Rm9vYmFyMQ==\n"
                        "-----END FOOBAR (1)-----\n"
                        "-----BEGIN FOOBAR (0)-----\n"
                        "Rm9vYmFyMA==\n"
                        "-----END FOOBAR (0)-----\n";
    size_t data_size = 0;
    kryptos_u8_t *data = NULL;

    data = kryptos_pem_get_data("THE-DROIDS-WE-ARE-LOOKING-FOR", buf, strlen(buf), &data_size);

    CUTE_ASSERT(data == NULL);

    data = kryptos_pem_get_data("FOOBAR (0)", buf, strlen(buf), &data_size);

    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 7);
    CUTE_ASSERT(strcmp(data, "Foobar0") == 0);

    kryptos_freeseg(data);

    data_size = 0;
    data = kryptos_pem_get_data("FOOBAR (1)", buf, strlen(buf), &data_size);

    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 7);
    CUTE_ASSERT(strcmp(data, "Foobar1") == 0);

    kryptos_freeseg(data);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_pem_put_data_tests)
    kryptos_u8_t *foobar1 = "Foobar1", *foobar0 = "Foobar0";
    kryptos_u8_t *pem_buf = NULL;
    size_t pem_buf_size = 0;
    kryptos_u8_t *expected_buffer = "-----BEGIN FOOBAR (1)-----\n"
                                    "Rm9vYmFyMQ==\n"
                                    "-----END FOOBAR (1)-----\n"
                                    "-----BEGIN FOOBAR (0)-----\n"
                                    "Rm9vYmFyMA==\n"
                                    "-----END FOOBAR (0)-----\n";

    CUTE_ASSERT(kryptos_pem_put_data(&pem_buf, &pem_buf_size, "FOOBAR (1)", foobar1, strlen(foobar1)) == kKryptosSuccess);
    CUTE_ASSERT(pem_buf != NULL);
    CUTE_ASSERT(kryptos_pem_put_data(&pem_buf, &pem_buf_size, "FOOBAR (1)", foobar0, strlen(foobar0)) == kKryptosInvalidParams);
    CUTE_ASSERT(pem_buf != NULL);
    CUTE_ASSERT(kryptos_pem_put_data(&pem_buf, &pem_buf_size, "FOOBAR (0)", foobar0, strlen(foobar0)) == kKryptosSuccess);
    CUTE_ASSERT(pem_buf != NULL);
    CUTE_ASSERT(pem_buf_size == strlen(expected_buffer));
    CUTE_ASSERT(strcmp(pem_buf, expected_buffer) == 0);
    kryptos_freeseg(pem_buf);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_pem_get_mp_data_tests)
    kryptos_mp_value_t *mp = NULL;
    kryptos_mp_value_t *emp = NULL;
    kryptos_u8_t *pem_buf = NULL;
    size_t pem_buf_size = 0;

    emp = kryptos_hex_value_as_mp("00112233", 8);

    CUTE_ASSERT(emp != NULL);

    CUTE_ASSERT(kryptos_pem_put_data(&pem_buf, &pem_buf_size, "MULTIPRECISION VALUE",
                                     (kryptos_u8_t *)emp->data,
                                      emp->data_size * sizeof(kryptos_mp_digit_t)) == kKryptosSuccess);

    CUTE_ASSERT(kryptos_pem_get_mp_data("MULTIPRECISION VALUE", pem_buf, pem_buf_size, &mp) == kKryptosSuccess);

    CUTE_ASSERT(kryptos_mp_eq(mp, emp) == 1);

    kryptos_freeseg(pem_buf);
    kryptos_del_mp_value(emp);
    kryptos_del_mp_value(mp);
CUTE_TEST_CASE_END
