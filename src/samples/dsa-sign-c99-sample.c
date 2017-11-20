/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *message = (kryptos_u8_t *)"Hellnation's what they teach us, profiting from greed\n"
                                            "Hellnation's where they give us coke, heroin, and speed\n"
                                            "Hellnation's when they tell you gotta go clean up your act\n"
                                            "You're the one who dragged me here and now you drag me back\n\n"
                                            "To this hellnation\n"
                                            "Hellnation\n"
                                            "Hellnation\n"
                                            "Hellnation\n\n"
                                            "Problem is few care\n"
                                            "About the people in despair\n"
                                            "If you help no one\n"
                                            "You're guilty in this hellnation\n\n"
                                            "Hellnation's when the president asks for four more fucking years\n"
                                            "Hellnation's when he gets it by conning poor people and peers\n"
                                            "Hellnation, got no choice, what's the point in trying to vote?\n"
                                            "When this country makes war we all die in the same boat\n\n"
                                            "In this hellnation\n"
                                            "Hellnation\n"
                                            "Hellnation\n"
                                            "Hellnation\n\n"
                                            "Problem is few care\n"
                                            "About the people in despair\n"
                                            "If you help no one\n"
                                            "You're guilty in this hellnation\n\n"
                                            "Problem is few care\n"
                                            "About the people in despair\n"
                                            "If you help no one\n"
                                            "You're guilty in this hellnation\n\n"
                                            "It's the only world we've got\n"
                                            "Let's protect it while we can\n"
                                            "That's all there is and there ain't no more\n\n"
                                            "Hellnation, asking please for a nuclear freeze\n"
                                            "So the unborn kids get their chance to live and breathe\n"
                                            "Hellnation, asking aid for the minimum wage\n"
                                            "So the kids of tomorrow don't wind up slaves to their trade\n\n"
                                            "In this hellnation\n"
                                            "Hellnation\n"
                                            "Hellnation\n"
                                            "Hellnation\n"
                                            "Problem is few care\n"
                                            "About the people in despair\n"
                                            "If you help no one\n"
                                            "You're guilty in this hellnation\n";

    kryptos_u8_t *k_pub_alice = (kryptos_u8_t *)"-----BEGIN DSA P-----\n"
                                                "+TyfXiVPtBkAIRwp5ZDMNNOvx36w9DG0kQVWmbaeIm9VJanCQb+pTfbDTn"
                                                "CnnyZ10h4bibG6CKJFk75bYgL6QzveLHdQO2WIPhXLtv0U08c0DRNdjZu9"
                                                "aRvvHj2RXiumUz5pVCbhQoeAv9YI1yxYa+I4J+FNyMnwC6LKtRQGKAM=\n"
                                                "-----END DSA P-----\n"
                                                "-----BEGIN DSA Q-----\n"
                                                "t4dXC9PBaAnSUv0fB30fm9PyUS8=\n"
                                                "-----END DSA Q-----\n"
                                                "-----BEGIN DSA G-----\n"
                                                "xP+KKzjMo3H+gLZKa/UXnZIO7n8RNHNSDE7puR0VOsmWJtXf8wYDb/23+T"
                                                "N+eyMQgF2FOrwQYHj+hS4MbE+yWiMa6nyFhoNbaMU5voVDw7Jhpm2Jq23m"
                                                "4kfkjwE4ICzg+uLKRe+U+5ESfWLrRvbrKAxVlBYHfP8RppLRIyv64AA=\n"
                                                "-----END DSA G-----\n"
                                                "-----BEGIN DSA E-----\n"
                                                "RH6V4fmnt9dQA+rCqBsdYUDmKtymXfmx15nlYiCK8hhwf4UWJn760igxwa"
                                                "fCx15wnSaYnG2+950eN24MK9UAL69E2VvCir3BXbuWXmPPGIWsSuJ8QYIG"
                                                "3vQtbr3yWiJI22zguxOnPzATBF4X5Yl/gjP7/BhDZcQJoFOaZaOATQI=\n"
                                                "-----END DSA E-----\n";

    kryptos_u8_t *k_priv_alice = (kryptos_u8_t *)"-----BEGIN DSA P-----\n"
                                                 "+TyfXiVPtBkAIRwp5ZDMNNOvx36w9DG0kQVWmbaeIm9VJanCQb+pTfbDT"
                                                 "nCnnyZ10h4bibG6CKJFk75bYgL6QzveLHdQO2WIPhXLtv0U08c0DRNdjZ"
                                                 "u9aRvvHj2RXiumUz5pVCbhQoeAv9YI1yxYa+I4J+FNyMnwC6LKtRQGKAM=\n"
                                                 "-----END DSA P-----\n"
                                                 "-----BEGIN DSA Q-----\n"
                                                 "t4dXC9PBaAnSUv0fB30fm9PyUS8=\n"
                                                 "-----END DSA Q-----\n"
                                                 "-----BEGIN DSA G-----\n"
                                                 "xP+KKzjMo3H+gLZKa/UXnZIO7n8RNHNSDE7puR0VOsmWJtXf8wYDb/23+"
                                                 "TN+eyMQgF2FOrwQYHj+hS4MbE+yWiMa6nyFhoNbaMU5voVDw7Jhpm2Jq2"
                                                 "3m4kfkjwE4ICzg+uLKRe+U+5ESfWLrRvbrKAxVlBYHfP8RppLRIyv64AA=\n"
                                                 "-----END DSA G-----\n"
                                                 "-----BEGIN DSA D-----\n"
                                                 "vLOB3BI4FOgD7HJCRrL7eQsbRxw=\n"
                                                 "-----END DSA D-----\n";

    int exit_code = 0;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("*** MESSAGE:\n\n%s\n", message);

    kryptos_sign(dsa, alice, message, strlen((char *)message),
                 k_priv_alice, strlen((char *)k_priv_alice), kryptos_dsa_hash(sha256));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while siginging the message.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** SIGNED OUTPUT:\n\n%s\n", alice->out);

    kryptos_verify(dsa, bob, alice->out, alice->out_size, k_pub_alice, strlen((char *)k_pub_alice), kryptos_dsa_hash(sha256));

    if (!kryptos_last_task_succeed(bob)) {
        if (bob->result == kKryptosInvalidSignature) {
            printf("ERROR: The signature is invalid.\n");
        } else {
            printf("ERROR: while verifying the signature.\n");
        }
        exit_code = 1;
    } else {
        printf("*** AUTHENTICATED MESSAGE:\n\n%s\n", bob->out);
    }

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
