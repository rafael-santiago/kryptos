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
    kryptos_u8_t *data = (kryptos_u8_t *)"Lie, lie, lie\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n\n"
                                         "The full moon is rising over dark water\n"
                                         "And the fools below are picking up sticks\n"
                                         "And the man in the gallows\n"
                                         "Lies permanently waiting for the doctors\n"
                                         "To come back and tend to him\n\n"
                                         "The Flat earth society is meeting here today\n"
                                         "Singing happy little lies\n"
                                         "And the Bright Ship Humana\n"
                                         "Is sailing far away\n"
                                         "With grave determination...\n"
                                         "And no destination!\n\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n"
                                         "Lie, lie, lie\n\n"
                                         "Nothing feels better than a spray of clean water\n"
                                         "And the whistling wind\n"
                                         "On a calm summer night\n"
                                         "But you'd better believe that down in their quarters\n"
                                         "The men are holding on for their dear lives\n"; // National Anthem of Anywhere.
    kryptos_u8_t *deflated_data = NULL, *inflated_data = NULL;
    size_t deflated_data_size, inflated_data_size;
    int exit_code = 0;

    printf("Original data:\n\n%s\n", data);

    printf("Compressing... Please wait...\n");

    deflated_data = kryptos_huffman_deflate(data, strlen((char *)data), &deflated_data_size);

    printf("Done!\n");

    if (deflated_data == NULL) {
        printf("Error while compressing!\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Now decompressing... Please wait...\n");

    inflated_data = kryptos_huffman_inflate(deflated_data, deflated_data_size, &inflated_data_size);

    printf("Done!\n\n");

    if (inflated_data == NULL) {
        printf("Error while decompressing!\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Decompressed data:\n\n%s\n", inflated_data);

epilogue:

    if (deflated_data != NULL) {
        kryptos_freeseg(deflated_data);
    }

    if (inflated_data != NULL) {
        kryptos_freeseg(inflated_data);
    }

    return exit_code;
}
