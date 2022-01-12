/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_TEST_VECTORS_H
#define KRYPTOS_TESTS_TEST_VECTORS_H 1

#include <kryptos_types.h>
#include "rabbit_test_vector.h"
#include "des_test_vector.h"
#include "idea_test_vector.h"
#include "blowfish_test_vector.h"
#include "feal_test_vector.h"
#include "rc2_test_vector.h"
#include "rc5_test_vector.h"
#include "rc6_test_vector.h"
#include "camellia_test_vector.h"
#include "cast5_test_vector.h"
#include "saferk64_test_vector.h"
#include "aes_test_vector.h"
#include "serpent_test_vector.h"
#include "triple_des_test_vector.h"
#include "triple_des_ede_test_vector.h"
#include "tea_test_vector.h"
#include "xtea_test_vector.h"
#include "misty1_test_vector.h"
#include "mars_test_vector.h"
#include "present_test_vector.h"
#include "shacal1_test_vector.h"
#include "shacal2_test_vector.h"
#include "noekeon_test_vector.h"
#include "gost_test_vector.h"
#include "sha1_test_vector.h"
#include "sha224_test_vector.h"
#include "sha256_test_vector.h"
#include "sha384_test_vector.h"
#include "sha512_test_vector.h"
#include "md4_test_vector.h"
#include "md5_test_vector.h"
#include "ripemd128_test_vector.h"
#include "ripemd160_test_vector.h"
#include "sha3_224_test_vector.h"
#include "sha3_256_test_vector.h"
#include "sha3_384_test_vector.h"
#include "sha3_512_test_vector.h"
#include "keccak224_test_vector.h"
#include "keccak256_test_vector.h"
#include "keccak384_test_vector.h"
#include "keccak512_test_vector.h"
#include "tiger_test_vector.h"
#include "whirlpool_test_vector.h"
//#include "blake2s224_test_vector.h"
#include "blake2s256_test_vector.h"
//#include "blake2b384_test_vector.h"
#include "blake2b512_test_vector.h"
#include <string.h>

static kryptos_u8_t *cbc_test_data[] = {
    "PEACE, n.In international affairs, a period of cheating "
        "between two periods of fighting. -- Ambrose Pierce, The Devil's Dictionary",
    "PAST, n.That part of Eternity with some small fraction of which we "
        "have a slight and regrettable acquaintance. A moving line called the "
        "Present parts it from an imaginary period known as the Future. These "
        "two grand divisions of Eternity, of which the one is continually "
        "effacing the other, are entirely unlike. The one is dark with sorrow "
        "and disappointment, the other bright with prosperity and joy. The "
        "Past is the region of sobs, the Future is the realm of song. In the one "
        "crouches Memory, clad in sackcloth and ashes, mumbling penitential prayer; "
        "in the sunshine of the other Hope flies with a free wing, beckoning to temples "
        "of success and bowers of ease. Yet the Past is the Future of yesterday, the Future "
        "is the Past of tomorrow. They are one -- the knowledge and the dream. -- Ambrose Pierce, The Devil's Dictionary",
    "PAGAN, n.A benighted person who prefers home-made deities and indigenous religious "
        "rites. -- Ambrose Pierce, The Devil's Dictionary",
    "PASSPORT, n.A document treacherously inflicted upon a citizen "
        "going abroad, exposing him as an alien and pointing him out for "
        "special reprobation and outrage. -- Ambrose Pierce, The Devil's Dictionary",
    "PARDON, v.To remit a penalty and restore to a life of crime. To add to the lure "
        "of crime the temptation of ingratitude. -- Ambrose Pierce, The Devil's Dictionary",
    "PLEASE, v.To lay the foundation for a superstructure of imposition. "
        "-- Ambrose Pierce, The Devil's Dictionary",
    "PAINTING, n.The art of protecting flat surfaces from the weather and exposing "
        "them to the critic. -- Ambrose Pierce, The Devil's Dictionary",
    "QUOTIENT, n.A number showing how many times a sum of money "
        "belonging to one person is contained in the pocket of another -- "
        "usually about as many times as it can got there. -- Ambrose Pierce, The Devil's Dictionary",
    "VIRTUES, n.pl.Certain abstentions. -- Ambrose Pierce, The Devil's Dictionary",
    "BED, n.A rack for the torture of the wicked; a citadel unfortified against remorse. "
        " -- Ambrose Pierce, The Devil's Dictionary",
    "BAYONET, n.An instrument for pricking the bubble of a nation's conceit. "
        " -- Ambrose Pierce, The Devil's Dictionary",
    "BELLADONNA, n.In Italian a beautiful lady; In English a deadly poison. "
        "A striking example of the essential identity of the two tongues."
        " -- Ambrose Pierce, The Devil's Dictionary",
    "BORE, n.A person who talks when you wish him to listen. -- Ambrose Pierce, The Devil's Dictionary",
    "BRIDE, n.A Woman with a fine prospect of happiness behind her. -- Ambrose Pierce, The Devil's Dictionary",
    "BRUTE, n.See HUSBAND. -- Ambrose Pierce, The Devil's Dictionary",
    "HUSBAND, n.One who, having dined, is charged with the care of the plate. -- Ambrose Pierce, The Devil's Dictionary",
    "WEDDING, n.A ceremony at which two persons undertake to become one, one undertakes to become nothing, "
        "and nothing undertakes to become supportable. -- Ambrose Pierce, The Devil's Dictionary",
    "WITCH, n.[1.] An ugly and repulsive old woman, in a wicked league with the devil. "
        "[2] A beautiful and attractive young woman, in wickedness a league beyond the devil."
        " -- Ambrose Pierce, The Devil's Dictionary",
    "\"When you have learned to snatch the error code from the trap frame, it will be time for you to leave.\"\n\n"
        "-- The Tao of Programming BOOK 1.",
    "A program should be light and agile, its subroutines connected like a string of pearls. "
        "The spirit and intent of the program should be retained throughout. There should be neither too "
        "little nor too much. Neither needless loops nor useless variables; neither lack of structure nor "
        "overwhelming rigidity.\n"
        "A program should follow the \"Law of Least Astonishment\". What is this law? It is simply that the "
        "program should always respond to the users in the way that least astonishes them. "
        "A program, no matter how complex, should act as a single unit. The program should be directed by the "
        "logic within rather than by outward appearances.\n"
        "If the program fails in these requirements, it will be in a state of disorder and confusion. "
        "The only way to correct this is to rewrite the program. -- The Tao of Programming [BOOK 4]"
    "Epilogue\n"
        "Thus spake the Master Programmer:\n"
        "\t\t\"Time for you to leave.\" -- The Tao of Programming"
};

static kryptos_u8_t *hmac_test_data[] = {
    "'There once was a Master Programmer who wrote unstructured programs. A novice programmer, seeking to imitate him, "
    "also began to write unstructured programs. When the novice asked the Master to evaluate his progress, the Master "
    "criticized him for writing unstructured programs, saying, 'What is appropriate for the Master is not appropriate "
    "for the novice. You must understand Tao before transcending structure.'",

    "There was once a programmer who was attached to the court of the warlord of Wu. The warlord asked the programmer: "
    "'Which is easier to design: an accounting package or an operating system?' 'An operating system,' replied the programmer."
    "The warlord uttered an exclamation of disbelief. 'Surely an accounting package is trivial next to the complexity of an "
    "operating system,' he said. 'Not so,' said the programmer, 'When designing an accounting package, the programmer "
    "operates as a mediator between people having different ideas: how it must operate, how its reports must appear, and "
    "how it must conform to the tax laws. By contrast, an operating system is not limited by outside appearances. When "
    "designing an operating system, the programmer seeks the simplest harmony between machine and ideas. This is why an "
    "operating system is easier to design.' The warlord of Wu nodded and smiled. 'That is all good and well, but which "
    "is easier to debug?' The programmer made no reply.",

    "'A well-written program is its own Heaven; a poorly-written program is its own Hell.'",

    "Does a good farmer neglect a crop he has planted? "
    "Does a good teacher overlook even the most humble student? "
    "Does a good father allow a single child to starve? "
    "Does a good programmer refuse to maintain his code?",

    "'Without the wind, the grass does not move. Without software hardware is useless.'"
};

static kryptos_u8_t *poly1305_test_data[] = {
    "Ao redor da vida do homem"
    "ha certas caixas de vidro,"
    "dentro das quais, como em jaula,"
    "se ouve palpitar um bicho.",

    "Se sao jaulas nao e certo;"
    "mais perto estao das gaiolas"
    "ao menos, pelo tamanho"
    "e quadradico de forma.",

    "Uma vezes, tais gaiolas"
    "vao penduradas nos muros;"
    "outras vezes, mais privadas,"
    "vao num bolso, num dos pulsos.",

    "Mas onde esteja: a gaiola"
    "sera de passaro ou passara:"
    "e alada a palpitacao,",

    "a saltacao que ela guarda;",

    "e de passaro cantor,"
    "nao passaro de plumagem:"
    "pois delas se emite um canto"
    "de uma tal continuidade",

    "que continua cantando"
    "se deixa de ouvi-lo a gente:"
    "como a gente às vezes canta"
    "para sentir-se existente.",

    "O que eles cantam, se passaros,"
    "e diferente de todos:"
    "cantam numa linha baixa,"
    "com voz de passaro rouco;",

    "desconhecem as variantes"
    "e o estilo numeroso"
    "dos passaros que sabemos,"
    "estejam presos ou soltos;",

    "tem sempre o mesmo compasso"
    "horizontal e monotono,"
    "e nunca, em nenhum momento,"
    "variam de repertorio:",

    "dir-se-ia que nao importa"
    "a nenhum ser escutado."
    "Assim, que nao sao artistas"
    "nem artesaos, mas operarios",

    "para quem tudo o que cantam"
    "e simplesmente trabalho,"
    "trabalho rotina, em serie,"
    "impessoal, nao assinado,",

    "de operario que executa"
    "seu martelo regular"
    "proibido (ou sem querer)"
    "do minimo variar.",

    "A mao daquele martelo"
    "nunca muda de compasso."
    "Mas tao igual sem fadiga,"
    "mal deve ser de operario;",

    "ela e por demais precisa"
    "para nao ser mao de maquina,"
    "a maquina independente"
    "de operacao operaria.",

    "De maquina, mas movida"
    "por uma forca qualquer"
    "que a move passando nela,"
    "regular, sem decrescer:",

    "quem sabe se algum monjolo"
    "ou antiga roda de agua"
    "que vai rodando, passiva,"
    "gracar a um fluido que a passa;",

    "que fluido e ninguem ve:"
    "da agua nao mostra os senoes:"
    "alem de igual, e continuo,"
    "sem mares, sem estacoes.",

    "E porque tampouco cabe,"
    "por isso, pensar que e o vento,"
    "ha de ser um outro fluido"
    "que a move: quem sabe, o tempo.",

    "Quando por algum motivo"
    "a roda de agua se rompe,"
    "outra maquina se escuta:"
    "agora, de dentro do homem;",

    "outra maquina de dentro,"
    "imediata, a reveza,"
    "soando nas veias, no fundo"
    "de poca no corpo, imersa.",

    "Entao se sente que o som"
    "da maquina, ora interior,"
    "nada possui de passivo,"
    "de roda de agua: e motor;",

    "se descobre nele o afogo"
    "de quem, ao fazer, se esforca,"
    "e que ele, dentro, afinal,"
    "revela vontade propria,",

    "incapaz, agora, dentro,"
    "de ainda disfarcar que nasce"
    "daquela bomba motor"
    "(coracao, noutra linguagem)",

    "que, sem nenhum coracao,"
    "vive a esgotar, gota a gota,"
    "o que o homem, de reserva,"
    "possa ter na intima poca.",

    "O Relogio / Joao Cabral de Melo Neto",

    "Come gather 'round people, wherever you roam"
    "And admit that the waters around you have grown"
    "And accept it that soon you'll be drenched to the bone"
    "If your time to you is worth saving"
    "Then you better start swimmin' or you'll sink like a stone"
    "For the times, they are a-changin'",

    "Come writers and critics who prophesize with your pen"
    "And keep your eyes wide, the chance won't come again"
    "And don't speak too soon, for the wheel's still in spin"
    "And there's no tellin' who that it's namin'"
    "For the loser now will be later to win"
    "For the times, they are a-changin'",

    "Come senators, congressmen, please heed the call"
    "Don't stand in the doorway, don't block up the hall"
    "For he that gets hurt will be he who has stalled"
    "The battle outside ragin'"
    "Will soon shake your windows and rattle your walls"
    "For the times, they are a-changin'",

    "Come mothers and fathers throughout the land"
    "And don't criticize what you can't understand"
    "Your sons and your daughters are beyond your command"
    "Your old road is rapidly aging"
    "Please get out of the new one if you can't lend your hand"
    "For the times, they are a-changin'"
    "The line, it is drawn, the curse, it is cast"
    "The slow one now will later be fast"
    "As the present now will later be past"
    "The order is rapidly fading"
    "And the first one now will later be last"
    "For the times, they are a-changin'",

    "The Times They Are A-Changin' / Bob Dylan",

    "Lay down your weary tune, lay down"
    "Lay down the song you strum"
    "And rest yourself 'neath the strength of strings"
    "No voice can hope to hum",

    "Struck by the sounds before the sun"
    "I knew the night had gone"
    "The morning breeze like a bugle blew"
    "Against the drums of dawn",

    "Lay down your weary tune, lay down"
    "Lay down the song you strum"
    "And rest yourself 'neath the strength of strings"
    "No voice can hope to hum",

    "The ocean wild like an organ played"
    "The seaweed's wove its strands"
    "The crashin' waves like cymbals clashed"
    "Against the rocks and sands",

    "Lay down your weary tune, lay down"
    "Lay down the song you strum"
    "And rest yourself 'neath the strength of strings"
    "No voice can hope to hum",

    "I stood unwound beneath the skies"
    "And clouds unbound by laws"
    "The cryin' rain like a trumpet sang"
    "And asked for no applause",

    "Lay down your weary tune, lay down"
    "Lay down the song you strum"
    "And rest yourself 'neath the strength of strings"
    "No voice can hope to hum",

    "The last of leaves fell from the trees"
    "And clung to a new love's breast"
    "The branches bare like a banjo played"
    "To the winds that listened best",

    "I gazed down in the river's mirror"
    "And watched its winding strum"
    "The water smooth ran like a hymn"
    "And like a harp did hum",

    "Lay down your weary tune, lay down"
    "Lay down the song you strum"
    "And rest yourself 'neath the strength of strings"
    "No voice can hope to hum",

    "Lay Down Your Weary Tune / Bob Dylan"
};

#define kryptos_run_block_cipher_tests(cipher_name, blocksize) {\
    kryptos_task_ctx t, *ktask = &t;\
    size_t cbc_test_data_nr = sizeof(cbc_test_data) / sizeof(cbc_test_data[0]);\
    size_t data_size = 0;\
    kryptos_u8_t *key = "beetlejuice\x00\x00\x00\x00\x00";\
    size_t key_size = 16;\
    size_t test_vector_nr = sizeof(cipher_name ## _test_vector) / sizeof(cipher_name ## _test_vector[0]), tv;\
    kryptos_task_init_as_null(&t);\
    /*INFO(Rafael): ECB tests.*/\
    for (tv = 0; tv < test_vector_nr; tv++) {\
        kryptos_ ## cipher_name ## _setup(&t,\
                                          cipher_name ## _test_vector[tv].key,\
                                          cipher_name ## _test_vector[tv].key_size, kKryptosECB);\
        t.in = cipher_name ## _test_vector[tv].plain;\
        t.in_size = cipher_name ## _test_vector[tv].block_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name  ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == (t.in_size << 1));\
        /*if (t.out_size == 32) {\
            printf("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "\
                   "%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",\
                     t.out[0], t.out[1], t.out[2], t.out[3], t.out[4], t.out[5], t.out[6], t.out[7], t.out[8], t.out[9], t.out[10], t.out[11], t.out[12], t.out[13], t.out[14], t.out[15]);\
        }*/\
        CUTE_ASSERT(memcmp(t.out, cipher_name ## _test_vector[tv].cipher, cipher_name ## _test_vector[tv].block_size) == 0);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == cipher_name ## _test_vector[tv].block_size);\
        CUTE_ASSERT(memcmp(t.out, cipher_name ## _test_vector[tv].decrypted, cipher_name ## _test_vector[tv].block_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    }\
    /*INFO(Rafael): CBC tests.*/\
    for (tv = 0; tv < cbc_test_data_nr; tv++) {\
        t.iv = NULL;\
        data_size = strlen(cbc_test_data[tv]);\
        kryptos_ ## cipher_name ## _setup(&t, key, 16, kKryptosCBC);\
        t.in = cbc_test_data[tv];\
        t.in_size = data_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, cbc_test_data[tv], t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
    /*INFO(Rafael): OFB tests.*/\
    for (tv = 0; tv < cbc_test_data_nr; tv++) {\
        t.iv = NULL;\
        data_size = strlen(cbc_test_data[tv]);\
        kryptos_ ## cipher_name ## _setup(&t, key, 16, kKryptosOFB);\
        t.in = cbc_test_data[tv];\
        t.in_size = data_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, cbc_test_data[tv], t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
    /*INFO(Rafael): CTR tests.*/\
    for (tv = 0; tv < cbc_test_data_nr; tv++) {\
        t.iv = NULL;\
        data_size = strlen(cbc_test_data[tv]);\
        kryptos_ ## cipher_name ## _setup(&t, key, 16, kKryptosCTR);\
        t.in = cbc_test_data[tv];\
        t.in_size = data_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, cbc_test_data[tv], t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

#define kryptos_run_block_cipher_tests_with_custom_setup(cipher_name, blocksize, t, tv, args, args_nr,\
                                                         cipher_setup_ecb_stmt,\
                                                         cipher_setup_cbc_stmt,\
                                                         cipher_setup_ofb_stmt,\
                                                         cipher_setup_ctr_stmt) {\
    kryptos_task_ctx *ktask = &t;\
    size_t cbc_test_data_nr = sizeof(cbc_test_data) / sizeof(cbc_test_data[0]);\
    size_t data_size = 0;\
    size_t test_vector_nr = sizeof(cipher_name ## _test_vector) / sizeof(cipher_name ## _test_vector[0]), tv;\
    kryptos_task_init_as_null(&t);\
    /*INFO(Rafael): ECB tests.*/\
    for (tv = 0; tv < test_vector_nr; tv++) {\
        cipher_setup_ecb_stmt;\
        t.in = cipher_name ## _test_vector[tv].plain;\
        t.in_size = cipher_name ## _test_vector[tv].block_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name  ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == (t.in_size << 1));\
        /*if (t.out_size == 20) {\
            printf("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",\
                 *(t.out), *(t.out+1), *(t.out+2), *(t.out+3), *(t.out+4), *(t.out+5), *(t.out+6), *(t.out+7));\
        }*/\
        CUTE_ASSERT(memcmp(t.out, cipher_name ## _test_vector[tv].cipher, cipher_name ## _test_vector[tv].block_size) == 0);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == cipher_name ## _test_vector[tv].block_size);\
        CUTE_ASSERT(memcmp(t.out, cipher_name ## _test_vector[tv].decrypted, cipher_name ## _test_vector[tv].block_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    }\
    /*INFO(Rafael): CBC tests.*/\
    for (tv = 0; tv < cbc_test_data_nr; tv++) {\
        t.iv = NULL;\
        data_size = strlen(cbc_test_data[tv]);\
        cipher_setup_cbc_stmt;\
        t.in = cbc_test_data[tv];\
        t.in_size = data_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, cbc_test_data[tv], t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
    /*INFO(Rafael): OFB tests.*/\
    for (tv = 0; tv < cbc_test_data_nr; tv++) {\
        t.iv = NULL;\
        data_size = strlen(cbc_test_data[tv]);\
        cipher_setup_ofb_stmt;\
        t.in = cbc_test_data[tv];\
        t.in_size = data_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, cbc_test_data[tv], t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
    /*INFO(Rafael): CTR tests.*/\
    for (tv = 0; tv < cbc_test_data_nr; tv++) {\
        t.iv = NULL;\
        t.ctr = NULL;\
        data_size = strlen(cbc_test_data[tv]);\
        cipher_setup_ctr_stmt;\
        t.in = cbc_test_data[tv];\
        t.in_size = data_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, cbc_test_data[tv], t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

#define kryptos_run_gcm_tests_no_support(cipher_name) {\
    kryptos_task_ctx t, *ktask = &t;\
    kryptos_u8_t *key = "GCMTest";\
    size_t key_size = 7;\
    kryptos_task_init_as_null(ktask);\
    ktask->in = "nosupp";\
    ktask->in_size = 6;\
    kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
    kryptos_task_set_encrypt_action(ktask);\
    kryptos_ ## cipher_name ## _cipher(&ktask);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);\
    CUTE_ASSERT(ktask->out == NULL);\
    kryptos_task_free(ktask, KRYPTOS_TASK_IV);\
}

#define kryptos_run_gcm_tests_no_support_with_custom_setup(cipher_name, ktask, setup_stmt) {\
    kryptos_task_ctx t, *ktask = &t;\
    kryptos_task_init_as_null(ktask);\
    ktask->in = "nosupp";\
    ktask->in_size = 6;\
    setup_stmt;\
    kryptos_task_set_encrypt_action(ktask);\
    kryptos_ ## cipher_name ## _cipher(&ktask);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);\
    CUTE_ASSERT(ktask->out == NULL);\
    kryptos_task_free(ktask, KRYPTOS_TASK_IV);\
}

#define kryptos_run_gcm_tests(cipher_name) {\
    size_t tv, tv_nr = sizeof(cbc_test_data) / sizeof(cbc_test_data[0]);\
    kryptos_task_ctx t, *ktask = &t;\
    kryptos_u8_t *key = "GCMTest";\
    size_t key_size = 7, data_size;\
    for (tv = 0; tv < tv_nr; tv++) {\
        /*INFO(Rafael): Authentication success without aad.*/\
        kryptos_task_init_as_null(ktask);\
        ktask->in = cbc_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        CUTE_ASSERT(ktask->out_size == data_size);\
        CUTE_ASSERT(memcmp(ktask->out, cbc_test_data[tv], data_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication failure without add.*/\
        kryptos_task_init_as_null(ktask);\
        ktask->in = cbc_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        ktask->out = NULL;\
        ktask->out_size = 0;\
        ktask->in[ktask->in_size >> 1] = ~ktask->in[ktask->in_size >> 1];\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
        CUTE_ASSERT(ktask->result == kKryptosGMACError);\
        CUTE_ASSERT(ktask->out == NULL);\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication success with aad.*/\
        kryptos_task_init_as_null(ktask);\
        kryptos_task_set_gcm_aad(ktask, "boo", 3);\
        ktask->in = cbc_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        CUTE_ASSERT(ktask->out_size == data_size);\
        CUTE_ASSERT(memcmp(ktask->out, cbc_test_data[tv], data_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication failure with add.*/\
        kryptos_task_init_as_null(ktask);\
        kryptos_task_set_gcm_aad(ktask, "boo", 3);\
        ktask->in = cbc_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        ktask->out = NULL;\
        ktask->out_size = 0;\
        kryptos_task_set_gcm_aad(ktask, "bo", 2);\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
        CUTE_ASSERT(ktask->result == kKryptosGMACError);\
        CUTE_ASSERT(ktask->out == NULL);\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

#define kryptos_run_gcm_tests_with_custom_setup(cipher_name, ktask, setup_stmt) {\
    size_t tv, tv_nr = sizeof(cbc_test_data) / sizeof(cbc_test_data[0]);\
    kryptos_task_ctx t, *ktask = &t;\
    size_t data_size;\
    for (tv = 0; tv < tv_nr; tv++) {\
        /*INFO(Rafael): Authentication success without aad.*/\
        kryptos_task_init_as_null(ktask);\
        ktask->in = cbc_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        setup_stmt;\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        CUTE_ASSERT(ktask->out_size == data_size);\
        CUTE_ASSERT(memcmp(ktask->out, cbc_test_data[tv], data_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication failure without add.*/\
        kryptos_task_init_as_null(ktask);\
        ktask->in = cbc_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        setup_stmt;\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        ktask->out = NULL;\
        ktask->out_size = 0;\
        ktask->in[ktask->in_size >> 1] = ~ktask->in[ktask->in_size >> 1];\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
        CUTE_ASSERT(ktask->result == kKryptosGMACError);\
        CUTE_ASSERT(ktask->out == NULL);\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication success with aad.*/\
        kryptos_task_init_as_null(ktask);\
        kryptos_task_set_gcm_aad(ktask, "boo", 3);\
        ktask->in = cbc_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        setup_stmt;\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        CUTE_ASSERT(ktask->out_size == data_size);\
        CUTE_ASSERT(memcmp(ktask->out, cbc_test_data[tv], data_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication failure with add.*/\
        kryptos_task_init_as_null(ktask);\
        kryptos_task_set_gcm_aad(ktask, "boo", 3);\
        ktask->in = cbc_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        setup_stmt;\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        CUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        ktask->out = NULL;\
        ktask->out_size = 0;\
        kryptos_task_set_gcm_aad(ktask, "bo", 2);\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
        CUTE_ASSERT(ktask->result == kKryptosGMACError);\
        CUTE_ASSERT(ktask->out == NULL);\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

#define kryptos_run_hash_tests(hash, input_size, size) {\
    kryptos_task_ctx t, *ktask = &t;\
    size_t tv, tv_nr = sizeof(hash ## _test_vector) / sizeof(hash ## _test_vector[0]);\
    CUTE_ASSERT(kryptos_ ## hash ## _hash_input_size() == input_size);\
    CUTE_ASSERT(kryptos_ ## hash ## _hash_size() == size);\
    kryptos_task_init_as_null(ktask);\
    for (tv = 0; tv < tv_nr; tv++) {\
        t.in = hash ## _test_vector[tv].message;\
        t.in_size = hash ## _test_vector[tv].message_size;\
        kryptos_ ## hash ## _hash(&ktask, 0);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == hash ## _test_vector[tv].raw_hash_size);\
        /*if (t.out_size == 24) {\
            printf("%.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\n", t.out[0], t.out[1], t.out[2], t.out[3], t.out[4], t.out[5], t.out[6], t.out[7], t.out[8], t.out[9], t.out[10], t.out[11], t.out[12], t.out[13], t.out[14], t.out[15], t.out[16], t.out[17], t.out[18], t.out[19], t.out[20], t.out[21], t.out[22], t.out[23]);\
        }*/\
        CUTE_ASSERT(memcmp(t.out, hash ## _test_vector[tv].raw_hash, t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
        kryptos_ ## hash ## _hash(&ktask, 1);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == hash## _test_vector[tv].hex_hash_size);\
        CUTE_ASSERT(memcmp(t.out, hash ## _test_vector[tv].hex_hash, t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    }\
}

#define kryptos_run_hash_macro_tests(hash, input_size, size) {\
    kryptos_task_ctx t, *ktask = &t;\
    size_t tv, tv_nr = sizeof(hash ## _test_vector) / sizeof(hash ## _test_vector[0]);\
    CUTE_ASSERT(kryptos_ ## hash ## _hash_input_size() == input_size);\
    CUTE_ASSERT(kryptos_ ## hash ## _hash_size() == size);\
    kryptos_task_init_as_null(ktask);\
    for (tv = 0; tv < tv_nr; tv++) {\
        kryptos_hash(hash, ktask, hash ## _test_vector[tv].message, hash ## _test_vector[tv].message_size, 0);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == hash ## _test_vector[tv].raw_hash_size);\
        CUTE_ASSERT(memcmp(t.out, hash ## _test_vector[tv].raw_hash, t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
        kryptos_hash(hash, ktask, hash ## _test_vector[tv].message, hash ## _test_vector[tv].message_size, 1);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == hash ## _test_vector[tv].hex_hash_size);\
        CUTE_ASSERT(memcmp(t.out, hash ## _test_vector[tv].hex_hash, t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    }\
}

#ifdef KRYPTOS_C99

#define kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cname, hname, ...) {\
    tv_nr = sizeof(hmac_test_data) / sizeof(hmac_test_data[0]);\
    for (tv = 0; tv < tv_nr; tv++) {\
        kryptos_task_init_as_null(&t);\
        data_size = strlen(hmac_test_data[tv]);\
        t.iv = NULL;\
        kryptos_task_set_in(&t, hmac_test_data[tv], data_size);\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_run_cipher_hmac(cname, hname, &t, __VA_ARGS__);\
        CUTE_ASSERT(t.in != NULL);\
        CUTE_ASSERT(t.out != NULL);\
        kryptos_task_set_in(&t, t.out, t.out_size);\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_run_cipher_hmac(cname, hname, &t, __VA_ARGS__);\
        CUTE_ASSERT(t.in != NULL);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, hmac_test_data[tv], t.out_size) == 0);\
        if (t.mode == kKryptosECB) {\
            kryptos_task_free(&t, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
        } else {\
            kryptos_task_free(&t, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        }\
        /*INFO(Rafael): Corrupted the cryptograms.*/\
        t.iv = NULL;\
        kryptos_task_set_in(&t, hmac_test_data[tv], data_size);\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_run_cipher_hmac(cname, hname, &t, __VA_ARGS__);\
        CUTE_ASSERT(t.in != NULL);\
        CUTE_ASSERT(t.out != NULL);\
        kryptos_task_set_in(&t, t.out, t.out_size);\
        t.in[t.in_size >> 1] = ~t.in[t.in_size >> 1];\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_run_cipher_hmac(cname, hname, &t, __VA_ARGS__);\
        CUTE_ASSERT(kryptos_last_task_succeed(&t) == 0);\
        CUTE_ASSERT(t.result == kKryptosHMACError);\
        if (t.mode == kKryptosECB) {\
            kryptos_task_free(&t, KRYPTOS_TASK_IN);\
        } else {\
            kryptos_task_free(&t, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        }\
        /*INFO(Rafael): Incomplete cryptograms.*/\
        t.iv = NULL;\
        kryptos_task_set_in(&t, hmac_test_data[tv], data_size);\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_run_cipher_hmac(cname, hname, &t, __VA_ARGS__);\
        CUTE_ASSERT(t.in != NULL);\
        CUTE_ASSERT(t.out != NULL);\
        kryptos_task_set_in(&t, t.out, t.out_size);\
        t.in_size = kryptos_ ## hname ## _hash_size();\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_run_cipher_hmac(cname, hname, &t, __VA_ARGS__);\
        CUTE_ASSERT(kryptos_last_task_succeed(&t) == 0);\
        CUTE_ASSERT(t.result == kKryptosHMACError);\
        if (t.mode == kKryptosECB) {\
            kryptos_task_free(&t, KRYPTOS_TASK_IN);\
        } else {\
            kryptos_task_free(&t, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        }\
    }\
}

#define kryptos_bad_buf_run_hmac(cname, hname, ktask, ...) {\
    kryptos_task_init_as_null(ktask);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    kryptos_task_set_decrypt_action(ktask);\
    kryptos_run_cipher_hmac(cname, hname, ktask, __VA_ARGS__);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
    CUTE_ASSERT(ktask->result == kKryptosHMACError);\
    if (ktask->mode != kKryptosECB) {\
        kryptos_task_free(ktask, KRYPTOS_TASK_IV);\
    }\
    ktask->in = "abc";\
    ktask->in_size = 3;\
    kryptos_task_set_decrypt_action(ktask);\
    kryptos_run_cipher_hmac(cname, hname, ktask, __VA_ARGS__);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
    CUTE_ASSERT(ktask->result == kKryptosHMACError);\
    if (ktask->mode != kKryptosECB) {\
        kryptos_task_free(ktask, KRYPTOS_TASK_IV);\
    }\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    kryptos_task_set_decrypt_action(ktask);\
    kryptos_run_cipher_hmac(cname, hname, ktask, __VA_ARGS__);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
    CUTE_ASSERT(ktask->result == kKryptosHMACError);\
    if (ktask->mode != kKryptosECB) {\
        kryptos_task_free(ktask, KRYPTOS_TASK_IV | KRYPTOS_TASK_IN);\
    } else {\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN);\
    }\
}

#define kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, cname, ...) {\
    tv_nr = sizeof(poly1305_test_data) / sizeof(poly1305_test_data[0]);\
    for (tv = 0; tv < tv_nr; tv++) {\
        /*INFO(Rafael): Normal flow, no authentication error.*/\
        kryptos_task_init_as_null(&t);\
        data_size = strlen(poly1305_test_data[tv]);\
        kryptos_task_set_in(&t, poly1305_test_data[tv], data_size);\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_run_cipher_poly1305(cname, &t, __VA_ARGS__);\
        CUTE_ASSERT(t.result == kKryptosSuccess);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size > data_size);\
        kryptos_task_set_in(&t, t.out, t.out_size);\
        t.out = NULL;\
        t.out_size = 0;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_run_cipher_poly1305(cname, &t, __VA_ARGS__);\
        CUTE_ASSERT(t.result == kKryptosSuccess);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, poly1305_test_data[tv], t.out_size) == 0);\
        if (strcmp(#cname, "salsa20") != 0 && strcmp(#cname, "chacha20") != 0) {\
            kryptos_task_free(&t, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        } else {\
            kryptos_task_free(&t, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
        }\
        /*INFO(Rafael): Copputed message flow.*/\
        kryptos_task_init_as_null(&t);\
        data_size = strlen(poly1305_test_data[tv]);\
        kryptos_task_set_in(&t, poly1305_test_data[tv], data_size);\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_run_cipher_poly1305(cname, &t, __VA_ARGS__);\
        CUTE_ASSERT(t.result == kKryptosSuccess);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size > data_size);\
        kryptos_task_set_in(&t, t.out, t.out_size);\
        t.out[t.out_size >> 1] += 1;\
        t.out = NULL;\
        t.out_size = 0;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_run_cipher_poly1305(cname, &t, __VA_ARGS__);\
        CUTE_ASSERT(t.result == kKryptosPOLY1305Error);\
        CUTE_ASSERT(strcmp(t.result_verbose, "Corrupted data.") == 0);\
        if (strcmp(#cname, "salsa20") != 0 && strcmp(#cname, "chacha20") != 0) {\
            kryptos_task_free(&t, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        } else {\
            kryptos_task_free(&t, KRYPTOS_TASK_IN);\
        }\
    }\
}

#endif

#define kryptos_bad_buf_run_block_cipher(cipher_name, ktask) {\
    kryptos_task_init_as_null(ktask);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosECB);\
    kryptos_task_set_encrypt_action(ktask);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosCBC);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosOFB);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosCTR);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_IV | KRYPTOS_TASK_OUT);\
    kryptos_task_init_as_null(ktask);\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosECB);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosCBC);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosOFB);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosCTR);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    ktask->in = kryptos_get_random_block(3);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 3;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosECB);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(3);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 3;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosCBC);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(3);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 3;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosOFB);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(3);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 3;\
    kryptos_ ## cipher_name ## _setup(&t, "Boom!!!!!!!!!!!!", 16, kKryptosCTR);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
}

#define kryptos_bad_buf_run_block_cipher_with_custom_setup(cipher_name,\
                                         setup_stmt_ecb, setup_stmt_cbc, setup_stmt_ofb, setup_stmt_ctr, ktask) {\
    kryptos_task_init_as_null(ktask);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    setup_stmt_ecb;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    setup_stmt_cbc;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    setup_stmt_ofb;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    ktask->in = "Wabba labba dub dub Wabba labba dub dub";\
    ktask->in_size = 39;\
    setup_stmt_ctr;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_IV | KRYPTOS_TASK_OUT);\
    kryptos_task_init_as_null(ktask);\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    setup_stmt_ecb;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    setup_stmt_cbc;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    setup_stmt_ofb;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(1024);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 1024;\
    setup_stmt_ofb;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    ktask->in = kryptos_get_random_block(3);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 3;\
    setup_stmt_ecb;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(3);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 3;\
    setup_stmt_cbc;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(3);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 3;\
    setup_stmt_ofb;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    ktask->in = kryptos_get_random_block(3);\
    CUTE_ASSERT(ktask->in != NULL);\
    ktask->in_size = 3;\
    setup_stmt_ofb;\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_ ## cipher_name  ## _cipher(&ktask);\
    CUTE_ASSERT(ktask->out != NULL);\
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
}

#endif // KRYPTOS_TESTS_TEST_VECTORS_H
