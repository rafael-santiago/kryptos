# Manual

**Abstract**: This library was designed to be used in user mode applications and also in kernel mode. The following
sections will guide the readers through the main aspects of how to use ``kryptos`` in their own stuff. This documentation
considers that the readers have at least a minimal formal knowledge of cryptology.

## Link101

### Linking user mode applications

Once the ar file generated and being the ``libkryptos.a`` in the current directory, all that should be done is:

```
Watson@221B:~/src/kryptos-test# gcc test.c libkryptos.a
```

Also is possible to use ``-lkryptos``, in the following way:

```
Watson@221B:~/src/kryptos-test# gcc test.c -L/usr/well-known-place/ -lkryptos
```

Of course, you should indicate where the ``kryptos`` headers are. In ``GCC``, ``Clang`` it can be done using the option
``-I<path>``.

### Linking kernel mode stuff

For kernel mode, until now, kryptos can be used in ``FreeBSD`` and ``Linux``. The main idea was create a tiny library
easy to embed in any project. Thus all you need to do is define the C macro ``KRYPTOS_KERNEL_MODE`` during the compilation
of your code.

In ``Linux`` if you want to use the c99 capabilities of ``kryptos`` you also need to pass the compiler flag ``-std=gnu99``.

## The main idea behind this library

The main idea here is to provide a way of using some cryptographic primitives without the necessity of longer and confuse
codes. Your code does not need to be the ciphertext, unlike it should clearly generate it.

Almost all cryptographic operations done in kryptos are based on simple tasks. A task is expressed by the C struct
``kryptos_task_ctx``.

You do not need to worry about where this struct is specifically defined in kryptos. For all user code, just including
``kryptos.h`` will give you access to every relevant feature.

### The kryptos_task_ctx struct

The ``kryptos_task_ctx`` is responsible for storing the plaintext, ciphertext, the current used algorithm, the key parameters
besides the additional parameters when necessary.

There is no field called "plaintext" or "ciphertext". There are the fields ``in`` and ``out``. Then, for encrypting the **plaintext**
must be stored into ``in``. When decrypting the **ciphertext** also must be stored into ``in``. The resultant data of the two operations
always will be stored (allocated) into ``out``.

However, when you store the input data into the task context is necessary also indicate the size in bytes of that data. The
field ``in_size`` holds the input size.

After any executed task, the field ``result`` will contain a code which describes the status of that last task. The additional
field called ``result_verbose`` may also contain some literal description about. Sometimes ``result_verbose`` may be null.

The following code defines the input of a task:

```c
#include <kryptos.h>

int main(int argc, char **argv) {
    kryptos_task_ctx task;
    unsigned char *data = "test";
    task.in = data;
    task.in_size = 4;
    ...
    return 0;
}
```

The following code does the same but using C macros conveniences:

```c
#include <kryptos.h>

int main(int argc, char **argv) {
    kryptos_task_ctx task;
    unsigned char *data = "test";
    kryptos_task_set_in(&task, data, 4);
    ...
    return 0;
}
```

Notice that the ``in`` field only points to the original data unlike the ``out`` field, that in this case will point to a
new allocated pointer representing the result of the processed input. The ``out_size`` will hold the size of the output.

All relevant ``kryptos_task_ctx`` fields can be handled by C macros but the remaining information of how manipulate the
``kryptos_task_ctx`` will be introduced together with the related crypto stuff.

## The symmetric stuff

Until now, ``kryptos`` has the following symmetric ciphers:

**Table 1**: The available symmetric ciphers.

|    **Cipher**    |      **Type**         |    **Internal ID constant**      |
|:----------------:|:---------------------:|:--------------------------------:|
|   ``ARC4``       |       Stream          |       ``kKryptosCipherARC4``     |
|   ``SEAL``       |       Stream          |       ``kKryptosCipherSEAL``     |
| ``AES-128``      |       Block           |       ``kKryptosCipherAES``      |
|   ``DES``        |       Block           |       ``kKryptosCipherDES``      |
|   ``3DES``       |       Block           |       ``kKryptosCipher3DES``     |
| ``3DES-EDE``     |       Block           |       ``kKryptosCipher3DESEDE``  |
|   ``IDEA``       |       Block           |       ``kKryptosCipherIDEA``     |
|    ``RC2``       |       Block           |       ``kKryptosCipherRC2``      |
|   ``FEAL``       |       Block           |       ``kKryptosCipherFEAL``     |
|  ``CAST5``       |       Block           |       ``kKryptosCipherCAST5``    |
| ``CAMELLIA-128`` |       Block           |       ``kKryptosCipherCAMELLIA`` |
| ``CAMELLIA-192`` |       Block           |       ``kKryptosCipherCAMELLIA`` |
| ``CAMELLIA-256`` |       Block           |       ``kKryptosCipherCAMELLIA`` |
| ``SAFER-K64``    |       Block           |       ``kKryptosCipherSAFERK64`` |
| ``BLOWFISH``     |       Block           |       ``kKryptosCipherBLOWFISH`` |
| ``SERPENT``      |       Block           |       ``kKryptosCipherSERPENT``  |

The available modes of operation for the block ciphers are: ``ECB``, ``CBC`` and ``OFB``. So in practice, considering the OFB
mode, we have 16 stream ciphers instead of only two. More on cipher modes will be treated later.

The way of indicating the desired cipher for an encryption task is by setting the field ``cipher`` from the ``kryptos_task_ctx``
to the ``Internal ID constant`` listed in **Table 1**.

Similarly the indication of the operation mode is done by setting the field ``mode``. The values could be: ``kKryptosECB``,
``kKryptosCBC``, ``kKryptosOFB``. Of course that this field is only relevant when you are using a block cipher.

The following code is an example of how to use the algorithm ``ARC4`` to encrypt and decrypt data:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    unsigned char *data = "hello world!";
    kryptos_task_ctx task, *ktask = &task;
    int exit_code = 0;

    // INFO(Rafael): Defining the input data information for the desired task.

    ktask->in = data;
    ktask->in_size = 12;

    printf("In: %s\n", ktask->in);

    // INFO(Rafael): Setting up the user key data information.

    kryptos_arc4_setup(ktask, "1234", 4);

    // INFO(Rafael): Running the ARC4 cipher over the input (plaintext).

    kryptos_arc4_cipher(&ktask);

    if (ktask->result == kKryptosSuccess) {
        printf("Encrypted... now decrypting...\n");

        // INFO(Rafael): Moving the output (ciphertext) to the input.

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;
        ktask->out = NULL;
        ktask->out_size = 0;

        // INFO(Rafael): Running the ARC4 cipher over the input (ciphertext).

        kryptos_arc4_cipher(&ktask);

        if (ktask->result == kKryptosSuccess) {
            printf("Out: ");
            fwrite(ktask->out, ktask->out_size, 1, stdout);
            printf("\n");
        } else {
            printf("Error during decryption.\n");
            exit_code = 1;
        }

        kryptos_freeseg(ktask->in);
        kryptos_freeseg(ktask->out);
    } else {
        printf("Error during encryption.\n");
        exit_code = 1;
    }
    return exit_code;
}
```

Maybe you can find curious the lack of the second ``kryptos_arc4_setup()`` call. But this arc4 setup is just for storing
the user key reference inside the task context. The real keystream generation is performed on every task execution.
Once the user key and some internal control sets defined by ``kryptos_arc4_setup()`` you do not need call it anymore. The
``kryptos_arc4_setup()`` sets the ``cipher`` field from ``kryptos_task_ctx`` to ``kKryptosCipherARC4``.

Another curious thing could be the lack of the explicit indication of encryption or decryption intentions, however, ``ARC4``
is a stream cipher, the encryption and decryption are the same. It only depends on the input.

The use of ``kryptos_freeseg()`` in order to free memory is indicated because in kernel mode it can abstract some complications
to you. In user mode you can call the default libc ``free()`` function, there is no problem with that.

It is possible to simplify a little bit more the previous sample by using C macros and c99 capabilities:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    unsigned char *data = "hello world!";
    kryptos_task_ctx task, *ktask = &task;
    int exit_code = 0;

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Defining the input data information for the desired task.

    kryptos_task_set_in(ktask, data, 12);

    printf("In: %s\n", ktask->in);

    // INFO(Rafael): Running the ARC4 cipher over the input (plaintext).

    kryptos_run_cipher(arc4, ktask, "1234", 4);

    if (kryptos_last_task_succeed(ktask)) {
        printf("Encrypted... now decrypting...\n");

        // INFO(Rafael): Moving the output (ciphertext) to the input.

        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);

        // INFO(Rafael): Running the ARC4 cipher over the input (ciphertext).

        kryptos_run_cipher(arc4, ktask, "1234", 4);

        if (kryptos_last_task_succeed(ktask)) {
            printf("Out: ");
            fwrite(ktask->out, ktask->out_size, 1, stdout);
            printf("\n");
        } else {
            printf("Error during decryption.\n");
            exit_code = 1;
        }

        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    } else {
        printf("Error during encryption.\n");
        exit_code = 1;
    }
    return exit_code;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
```

As you can see the kryptos task manipulation C macros implement a direct and simple internal ``DSL``.

The general using form of ``kryptos_run_cipher`` macro is:

``kryptos_run_cipher(<cipher>, <ktask pointer>, key, key_size[, args]...)``

Block ciphers should be used in almost the same way:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx task, *ktask = &task;
    kryptos_u8_t *key = "foo";
    kryptos_u8_t *data = "plaintext";
    size_t data_size = 9;

    printf("Original data: %s\n", data);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Loading the basic information about the task involving the chosen cipher.
    kryptos_blowfish_setup(ktask, key, strlen(key), kKryptosECB);

    // INFO(Rafael): Since we need to encrypt, we need to inform it.
    kryptos_task_set_encrypt_action(ktask);

    // INFO(Rafael): Setting up the input information for the desired task.
    ktask->in = data;
    ktask->in_size = data_size;

    // INFO(Rafael): Encrypting.
    kryptos_blowfish_cipher(&ktask);

    if (ktask->result == kKryptosSuccess) {
        printf("Data encrypted!\n");

        kryptos_task_set_decrypt_action(ktask);

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;
        ktask->out = NULL;

        // INFO(Rafael): Decrypting.
        kryptos_blowfish_cipher(&ktask);

        if (ktask->result == kKryptosSuccess) {
            printf("Data decrypted: ");
            fwrite(ktask->out, ktask->out_size, 1, stdout);
            printf("\n");
        } else {
            printf("ERROR: during decryption.\n");
        }

        // INFO(Rafael): Freeing input and output.
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    } else {
        printf("ERROR: during encryption.\n");
    }

    return 0;
}
```

The c99 conventions are handy to produce a smaller and straightfoward code:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    kryptos_task_ctx task, *ktask = &task;
    kryptos_u8_t *key = "foo";
    kryptos_u8_t *data = "plaintext";
    size_t data_size = 9;
    int exit_code = 0;

    printf("Original data: %s\n", data);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Encrypting.
    kryptos_task_set_in(ktask, data, data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(blowfish, ktask, key, strlen(key), kKryptosECB);

    if (kryptos_last_task_succeed(ktask)) {
        printf("Encryption success!\n");
        // INFO(Rafael): Decrypting.
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(blowfish, ktask, key, strlen(key), kKryptosECB);

        printf("Plaintext: ");
        fwrite(ktask->out, ktask->out_size, 1, stdout);
        printf("\n");

        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    } else {
        printf("Error during encryption.\n");
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        exit_code = 1;
    }

    return exit_code;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
```

The ECB mode is the weakest mode to be used with block ciphers.

Until now is possible to use block ciphers in three modes: ``ECB``, ``CBC`` and ``OFB``.

The **Table 2** lists the identifiers related with each available operation mode.

**Table 2**: The available operation modes for block ciphers.

| **Operation Mode** |       **Identifier**             |
|:------------------:|:--------------------------------:|
|       ``ECB``      |         kKryptosECB              |
|       ``CBC``      |         kKryptosCBC              |
|       ``OFB``      |         kKryptosOFB              |

When using CBC and OFB modes you do not have to worry about generating the initialization vector if you do not want to.
Once the iv field from ``kryptos_task_ctx`` initialized as NULL, a new iv will be generated and used. In addition, after
encrypting you do not need to worry about transfering the iv as a separated piece of information. The out field from
``kryptos_task_ctx`` gathers all information that you will need for a later decryption. As you may known there is no
necessity of an IV be secret. If you use a static IV, in the end you are using a more complicated scheme for ECB mode,
sadly, this kind of naive "approach" is common. Avoid doing this, it is irresponsible and stupid.

The following code sample uses the SERPENT cipher in CBC mode with the c99 conveniences:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    kryptos_task_ctx task, *ktask = &task;
    kryptos_u8_t *key = "foo";
    kryptos_u8_t *data = "plaintext";
    size_t data_size = 9;
    int exit_code = 0;

    printf("Original data: %s\n", data);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Encrypting.
    kryptos_task_set_in(ktask, data, data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(serpent, ktask, key, strlen(key), kKryptosCBC);

    if (kryptos_last_task_succeed(ktask)) {
        printf("Encryption success!\n");
        // INFO(Rafael): Decrypting.
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(serpent, ktask, key, strlen(key), kKryptosCBC);

        printf("Plaintext: ");
        fwrite(ktask->out, ktask->out_size, 1, stdout);
        printf("\n");

        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    } else {
        printf("Encryption error.\n");
        exit_code = 1;
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }

    return exit_code;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
```

If you want to generate the iv on your own, you need to care about the content of the fields ``iv`` and ``iv_size`` from the
``kryptos_task_ctx`` struct. The iv should point to the chunk of bytes required as iv by the current used cipher and
the iv_size must store the total in bytes of that byte chunk. If you generate an invalid iv the encryption/decryption will
fail. As a result the kryptos_last_task_succeed(...) will indicate a zero value.

Details about a failure always can be accessed by watching the field ``result_verbose`` from the ``kryptos_task_ctx`` struct.

Not all block ciphers only need a key, a size of this key and an operation mode. In kryptos we also have block ciphers
that need more than the standard parameters. In this case the additional parameters are always passed after the operation
mode and they must be pointers to the data. As sample, let's pick the cipher CAMELLIA. The CAMELLIA algorithm supports key
sizes of 128, 192 and also 256.

When calling CAMELLIA in kryptos the desired key size should be passed, in the following way (c99):

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx task, *ktask = &task;
    kryptos_u8_t *key = "foo";
    kryptos_u8_t *data = "plaintext";
    size_t data_size = 9;
    kryptos_camellia_keysize_t key_size = kKryptosCAMELLIA192; // Let's use Camellia-192.
    int exit_code = 0;

    printf("Original data: %s\n", data);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Encrypting.
    kryptos_task_set_in(ktask, data, data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(camellia, ktask, key, strlen(key), kKryptosCBC, &key_size);

    if (kryptos_last_task_succeed(ktask)) {
        printf("Encryption success!\n");
        // INFO(Rafael): Decrypting.
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(camellia, ktask, key, strlen(key), kKryptosCBC, &key_size);
        printf("Plaintext: ");
        fwrite(ktask->out, ktask->out_size, 1, stdout);
        printf("\n");
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    } else {
        printf("Encryption error!\n");
        exit_code = 1;
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }

    return exit_code;
}
```

The available CAMELLIA key size constants are: ``kKryptosCAMELLIA128``, ``kKryptosCAMELLIA192``, ``kKryptosCAMELLIA256``.

The **Table 3** lists the other ciphers which use additional parameters during their call.

**Table 3**: The additional parameters required by some implemented block ciphers.

| **Cipher** |              **Parameters**       |            **Parameters data type**                 |                                     **Call example**                                                 |
|:----------:|:---------------------------------:|----------------------------------------------------:|-----------------------------------------------------------------------------------------------------:|
|    FEAL    |  Rounds total                     |          ``int``                                    | ``kryptos_run_cipher(feal, &task, "feal", 4, kKryptosCBC, &feal_rounds)``                            |
|    RC2     |  T1 parameter                     |          ``int``                                    | ``kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosOFB, &rc2_t1)``                                   |
| SAFER K-64 |  Rounds total                     |          ``int``                                    | ``kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosECB, &saferk64_rounds)``                |
|    3DES    |  Key2, Key2 size, Key3, Key3 size | ``unsigned char`` for keys and ``size_t`` for sizes | ``kryptos_run_cipher(triple_des, &task, k1, &k1_size, kKryptosECB, k2, &k2_size, k3, &k3_size)``     |
|  3DES-EDE  |  Key2, Key2 size, Key3, Key3 size | ``unsigned char`` for keys and ``size_t`` for sizes | ``kryptos_run_cipher(triple_des_ede, &task, k1, &k1_size, kKryptosECB, k2, &k2_size, k3, &k3_size)`` |

### Hashes

Firstly I will show you how to generate hashes without using the c99 conveniences, after we will generate hashes through
the available macros.

Until now the available hash algorithms follow listed in **Table 4**.

**Table 4**: Currently available hash algorithms.

|  **Algorithm** |        **HASHID**                  |
|:--------------:|:----------------------------------:|
|   ``SHA-1``    |       ``sha1``                     |
|   ``SHA-224``  |       ``sha224``                   |
|   ``SHA-256``  |       ``sha256``                   |
|   ``SHA-384``  |       ``sha384``                   |
|   ``SHA-512``  |       ``sha512``                   |
|    ``MD4``     |       ``md4``                      |
|    ``MD5``     |       ``md5``                      |
| ``RIPEMD-128`` |      ``ripemd128``                 |
| ``RIPEMD-160`` |      ``ripemd160``                 |

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    size_t o;

    // INFO(Rafael): Defining the input that must be "hashed".

    t.in = "abc";
    t.in_size = 3;

    printf("Hashed data: %s\n", t.in);

    // INFO(Rafael): Executing the hash algorithm over the input.
    //               The second parameter when 0 requests a raw byte output.

    kryptos_sha1_hash(&ktask, 0);

    if (ktask->out != NULL) {
        printf("Raw output: ");
        for (o = 0; o < ktask->out_size; o++) {
            printf("%c", isprint(ktask->out[o]) ? ktask->out[o] : '.');
        }
        printf("\n");

        // INFO(Rafael): Freeing the output buffer.

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    } else {
        printf("ERROR: when executing the hash with raw byte output.\n");
        return 1;
    }

    // INFO(Rafael): Executing again the hash algorithm over the previously defined input.
    //               The second parameter when 1 requests a hexadecimal output.

    kryptos_sha1_hash(&ktask, 1);

    if (ktask->out != NULL) {
        printf("Hex output: %s\n", ktask->out);

        // INFO(Rafael): Freeing the output buffer.

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    } else {
        printf("ERROR: when executing the hash with hexdecimal output.\n");
        return 1;
    }

    return 0;
}
```

According to the presented sample above, you should define the input and its size in bytes in a ``kryptos_task_ctx`` struct.
To actually execute the desired hash algorithm you should pass a ``kryptos_task_ctx **`` and a flag requesting hexadecimal
output (1 => hex, 0 => raw byte). The function to be called is ``kryptos_HASHID_hash``, where ``HASHID`` can be found
in **Table 4**.

### HMACs

``Kryptos`` offers the possibility of easily generate a Message Authentication Code based on Hashes (HMACs) when
the ``c99`` capabilities are present.

This feature can be accessed using the macro ``kryptos_run_cipher_hmac``. The following code sample shows how to generate
a message authenticated taking advantage from the implemented hash algorithms.

```c
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
    kryptos_task_ctx m;
    int exit_code = 1;

    // INFO(Rafael): Always set everything to null is a good practice.

    kryptos_task_init_as_null(&m);

    // INFO(Rafael): Setting the plaintext.

    kryptos_task_set_in(&m, "As I was saying...", 18);

    printf("Data: %s\n", m.in);

    // INFO(Rafael): Encrypting with CAST5-CBC and generating our MAC based on SHA-512.

    kryptos_task_set_encrypt_action(&m);
    kryptos_run_cipher_hmac(cast5, sha512, &m, "silent passenger", 16, kKryptosCBC);

    if (kryptos_last_task_succeed(&m)) {
        printf("Data successfully encrypted... Now we will intentionally corrupt it.\n");
        // INFO(Rafael): Let us corrupt the cryptogram on purpose of seeing the decryption fail.
        //               Do not do it at home! ;)

        kryptos_task_set_in(&m, m.out, m.out_size);

        m.in[m.in_size >> 1] = ~m.in[m.in_size >> 1];

        // INFO(Rafael): Now trying to decrypt.

        kryptos_task_set_decrypt_action(&m);
        kryptos_run_cipher_hmac(cast5, sha512, &m, "silent passenger", 16, kKryptosCBC);

        if (!kryptos_last_task_succeed(&m) && m.result == kKryptosHMACError) {
            printf("Nice! The cryptogram corruption was detected. Do not consider this, "
                   "ask for a retransmission... ;)\n");
            // INFO(Rafael): Note that we do not need to free the output, because a corruption was detected
            //               and due to it the decryption process was not performed, since we would not
            //               have a valid plaintext. On normal conditions, with valid plaintexts you should
            //               also combine the bitmask KRYPTOS_TASK_OUT in kryptos_task_free() call.
            //
            //               The bitmask KRYPTOS_TASK_IV is being passed because the used block cipher was
            //               CAST5 in CBC with a null IV. CBC requested with a null iv internally asks
            //               kryptos to generate a pseudo-random IV and this action allocates memory.
            //
            kryptos_task_free(&m, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
            exit_code = 0;
        } else {
            // INFO(Rafael): It should never happen.
            printf("Rascals! We were fooled!!\n");
            exit_code = 1;
        }
    } else {
        // INFO(Rafael): It should never happen.
        printf("ERROR: Hmmmm it should be at least encrypted.\n");
        exit_code = 1;
    }

    // INFO(Rafael): Housekeeping.

    kryptos_task_init_as_null(&m);

    return exit_code;
}
```

Even if the decryption has failed and you are sure about of the out field nullity from ``kryptos_task_ctx``, you can
call ``kryptos_task_free`` passing the bitmask ``KRYPTOS_TASK_OUT`` but I personally dislike this kind of code.

As you may have noticed the general form of using the ``kryptos_run_cipher_hmac`` macro is:

```
    kryptos_run_cipher_hmac(<block cipher>,
                            <hash algorithm>,
                            <kryptos_task_ctx *>,
                            <block cipher user key>, <block cipher user key size>,
                            <block cipher mode>
                            [, <block cipher add. args, when the block cipher has some>)
```

## Asymmetric stuff

Until now the ``Diffie-Hellman-Merkle`` key exchange scheme and the algorithms ``RSA`` and ``Elgamal`` are available.
For digital signature the library includes ``RSA`` (basic scheme), ``RSA-EMSA-PSS`` and the widely used ``DSA``.

Firstly let's discusse the ``DHKE`` and after the other stuff.

### The Diffie-Hellman-Merkle key exchange

This key exchange scheme is implemented in two forms. The first one is the standard way, well-known and presented
in tons of crypto-books. The second one is a modified implementation of this protocol, this little modification
mitigates the man-in-the-middle attacks.

The standard method is shown as following:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    struct kryptos_dh_xchg_ctx alice_data, bob_data, *alice = &alice_data, *bob = &bob_data;
    int exit_code = 1;

    // INFO(Rafael): The actors should initialize their data contexts.

    kryptos_dh_init_xchg_ctx(alice);
    kryptos_dh_init_xchg_ctx(bob);

    // INFO(Rafael): Inside the kryptos_dh_xchg_ctx there are two meaningful fields called 'p' and 'g'.
    //               You can generate your own primes if you want to. However, kryptos has built-in
    //               standarnized primes and generators based on RFC-3526, and in this sample we will
    //               use them.

    if (kryptos_dh_get_modp(kKryptosDHGroup1536, &alice->p, &alice->g) != kKryptosSuccess) {
        printf("ERROR: Unexpected error during prime and generator loading.\n");
        return 1;
    }

    // INFO(Rafael): Alice defines the size in bits of her secret random number.
    alice->s_bits = 160;

    // INFO(Rafael): Now Alice processes the setup data.

    printf("INFO: Alice is processing...\n");

    kryptos_dh_process_stdxchg(&alice);

    if (!kryptos_last_task_succeed(alice) || alice->s == NULL || alice->out == NULL) {
        printf("ERROR: Error during exchange process. (1)\n");
        kryptos_clear_dh_xchg_ctx(alice);
        goto main_epilogue;
    }

    // INFO(Rafael): The s field inside 'alice' context is [S]ecret, the out field should be sent to bob.
    //               This data is automatically generated as PEM format.
    //               Bob receives in his input the Alice's output.

    printf("INFO: Alice -> Bob\n");

    bob->in = alice->out;
    bob->in_size = alice->out_size;

    // INFO(Rafael): Bob also defines the size in bits of his secret random number.
    bob->s_bits = 160;

    // INFO(Rafael): Now Bob passes to kryptos_dh_process_stdxchg() "oracle" his input

    printf("INFO: Bob is processing...\n");

    kryptos_dh_process_stdxchg(&bob);

    if (!kryptos_last_task_succeed(bob) || bob->s == NULL || bob->out == NULL || bob->k == NULL) {
        printf("ERROR: Error during exchange process. (2)\n");
        kryptos_clear_dh_xchg_ctx(alice);
        kryptos_clear_dh_xchg_ctx(bob);
        goto main_epilogue;
    }

    // INFO(Rafael): Now Bob should send back his output to Alice.
    //               Bob already got k, Alice will get it soon.

    printf("INFO: Bob got a k value.\n");
    printf("INFO: Bob -> Alice\n");

    alice->in = bob->out;
    alice->in_size = bob->out_size;

    // INFO(Rafael): Now Alice passes to "oracle" the output received from bob in her input.

    printf("INFO: Alice is processing...\n");

    kryptos_dh_process_stdxchg(&alice);

    printf("INFO: Alice got a k value.\n");

    if (!kryptos_last_task_succeed(alice) || alice->k == NULL) {
        printf("ERROR: Error during exchange process. (3)\n");
        kryptos_clear_dh_xchg_ctx(alice);
        kryptos_clear_dh_xchg_ctx(bob);
        return exit_code;
    }

    if (alice->k->data_size == bob->k->data_size &&
        memcmp(alice->k->data, bob->k->data, alice->k->data_size) == 0) {
        alice->in = NULL;
        bob->in = NULL;
        printf("SUCCESS: Alice and Bob have agreed about a session key.\n");
    } else {
        printf("ERROR: The k values between Alice and Bob are not the same.\n");
    }

    exit_code = 0;

main_epilogue:

    kryptos_clear_dh_xchg_ctx(alice);
    kryptos_clear_dh_xchg_ctx(bob);


    return exit_code;
}
```

As you may have seen the standard ``DHKE`` implementation using kryptos involves the usage of a specific structure
called ``kryptos_dh_xchg_ctx`` and a "oracle" function called ``kryptos_dh_process_stdxchg()``. I like to call it
"oracle" because this function is smart enough to know the stage of the exchange process. This "oracle" behavior
avoids the necessity of driving the process with different functions or explicit code.

The calls ``kryptos_init_dh_xchg_ctx()`` and ``kryptos_clear_dh_xchg_ctx()`` are always needed. The first obviously initializes
the related structures and the second frees any allocated memory inside them.

Even the standard implementation of the ``Diffie-Hellman-Merkle`` protocol seeming secure, it is not strong enough
against ``mitm`` attacks.

Fortunately, a simple change in this protocol mitigates this kind of attack.

The modified ``Diffie-Hellman-Merkle`` key exchange protocol involves a preparation phase that should be done once.

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    struct kryptos_dh_xchg_ctx alice_data, bob_data, *alice = &alice_data, *bob = &bob_data;
    kryptos_u8_t *k_pub_bob = NULL, *k_priv_bob = NULL;
    size_t k_pub_bob_size = 0, k_priv_bob_size = 0;
    int exit_code = 0;

    // INFO(Rafael): Always initializing the dh_xchg_ctx is a best practice.

    kryptos_dh_init_xchg_ctx(bob);
    kryptos_dh_init_xchg_ctx(alice);

    // INFO(Rafael): Let's use some standarnized prime and generator again in this sample.

    if (kryptos_dh_get_modp(kKryptosDHGroup1536, &bob->p, &bob->g) != kKryptosSuccess) {
        exit_code = 1;
        printf("ERROR: while getting P and G parameters.\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Bob defines the size in bits of his random secret value and then he makes a key pair
    //               based on p, g and s.
    //
    //               Actually it will generate a fouth value t what should be published by him.

    bob->s_bits = 160;

    kryptos_dh_mk_key_pair(&k_pub_bob, &k_pub_bob_size, &k_priv_bob, &k_priv_bob_size, &bob);

    if (!kryptos_last_task_succeed(bob)) {
        exit_code = 1;
        printf("ERROR: while generating the key pair.\n");
        goto main_epilogue;
    }

    kryptos_clear_dh_xchg_ctx(bob);

    // INFO(Rafael): Bob should make public the data in k_pub_bob and save safely the data in k_priv_bob.

    // INFO(Rafael): Now let's suppose that Alice wants to communicate with Bob. She must put the public key
    //               info from Bob in her input task buffer and also picks a size in bits for her [s]ecret s
    //               value.

    alice->in = k_pub_bob;
    alice->in_size = k_pub_bob_size;
    alice->s_bits = 160;

    // INFO(Rafael): Notice that she needs to call kryptos_dh_process_modxchg() instead of
    //               kryptos_dh_process_stdxchg().

    kryptos_dh_process_modxchg(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        exit_code = 1;
        printf("ERROR: while modified dh was processing [Alice's side].\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Alice has already the session key but she must send to Bob her produced output. Thus,
    //               Bob will also got the same session key.

    // INFO(Rafael): By his side, Bob must append the received data from Alice with his private key data.
    //               This involves mere pointer math loved by any true C programmer ;)

    bob->in_size = alice->out_size + k_priv_bob_size;
    bob->in = (kryptos_u8_t *) kryptos_newseg(bob->in_size);

    if (bob->in == NULL) {
        exit_code = 1;
        printf("ERROR: no memory to produce the input.\n");
        goto main_epilogue;
    }

    if (memcpy(bob->in, alice->out, alice->out_size) != bob->in) {
        exit_code = 1;
        printf("ERROR: during input copy.\n");
        goto main_epilogue;
    }

    if (memcpy(bob->in + alice->out_size, k_priv_bob, k_priv_bob_size) != (bob->in + alice->out_size)) {
        exit_code = 1;
        printf("ERROR: during input copy.\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Bob picks again a size in bits for his [s]ecret s value.

    bob->s_bits = 160;

    // INFO(Rafael): Having defined the data from Alice appended with his private key information and also
    //               the size in bits of his s, all that Bob should do is call kryptos_dh_process_modxchg().

    kryptos_dh_process_modxchg(&bob);

    if (!kryptos_last_task_succeed(bob)) {
        exit_code = 1;
        printf("ERROR: while modified dh was processing [Bob's side].\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Now all indicate that Alice and Bob have agreed about k and this value can be accessed
    //               by them into their task contexts by the field 'k'.

    if (alice->k->data_size == bob->k->data_size &&
        memcmp(alice->k->data, bob->k->data, alice->k->data_size) == 0) {
        alice->in = NULL;
        bob->in = NULL;
        printf("SUCCESS: Alice and Bob have agreed about a session key.\n");
    } else {
        printf("ERROR: The k values between Alice and Bob are not the same.\n");
    }

main_epilogue:

    kryptos_clear_dh_xchg_ctx(bob);
    kryptos_clear_dh_xchg_ctx(alice);

    if (k_pub_bob != NULL) {
        kryptos_freeseg(k_pub_bob);
    }

    if (k_priv_bob != NULL) {
        kryptos_freeseg(k_priv_bob);
    }

    k_priv_bob_size = k_pub_bob_size = 0;

    return exit_code;
}
```

The nice part about the modified version of the ``Diffie-Hellman-Merkle`` protocol is that we do not have a previous
communication that could be hijacked by some attacker. As a result this mitigates a bunch the possibility of mitm attacks.
Actually, we have only one data exchange during the key agreement and the public part of the generated key can be of
knowledge of anyone, there is no problem with that.

Until now a show you DHKE sample using standarnized MODP values but kryptos also includes a way of generating your own
domain parameters. The following sample is a program that can generate those domain parameters.

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int is_valid_number(const char *number, const size_t number_size);

int main(int argc, char **argv) {
    kryptos_u8_t *params = NULL;
    size_t params_size = 0, p_bits = 0, q_bits = 0;

    if (argc > 2) {
        if (!is_valid_number(argv[1], strlen(argv[1])) &&
            !is_valid_number(argv[2], strlen(argv[2]))) {
            goto usage;
        }

        p_bits = atoi(argv[1]);
        q_bits = atoi(argv[2]);

        if (p_bits < q_bits) {
            printf("ERROR: the size of p must be greater than the size of q.\n");
            return 1;
        }

        if (kryptos_dh_mk_domain_params(p_bits, q_bits, &params, &params_size) != kKryptosSuccess) {
            printf("ERROR: while generating the domain parameters.\n");
            return 1;
        }

        fwrite(params, params_size, 1, stdout);

        kryptos_freeseg(params);
    } else {
usage:
        printf("use: %s <p size in bits> <q size in bits>\n", argv[0]);
        return 1;
    }

    return 0;
}

static int is_valid_number(const char *number, const size_t number_size) {
    const char *np, *np_end;

    if (number == NULL) {
        return 0;
    }

    np = number;
    np_end = np + number_size;

    if (np == np_end) {
        return 0;
    }

    while (np != np_end) {
        if (!isdigit(*np)) {
            return 0;
        }
        np++;
    }

    return 1;
}
```

In order to generate domain DHKE parameters with the code shown above you should inform the size in bits of P and Q
respectively:

```
Watson@221B:~/src/kryptos-test/samples# ./dh-domain-params-sample 160 80 > params.txt
```

Once generated the parameters can be used insted of the standarnized MODP values. Of course that use p=160 bits and q=80 is
pretty insecure. The domain parameters calculating process can be slow. Since it depends on finding primes with specific
relations between them. It is driven by luck... Fortunatelly, you should do it once.

In practice you should use at least p=1024 and q=160 bits.

The domain parameters are exported as a ``PEM`` buffer. When receving a ``PEM`` buffer containing DHKE domain parameters
a best practice is to verify if these parameters are really "trustable" before accepting and starting using them.

```c
```

You should avoid using any domain parameters rejected by the verifying function.

