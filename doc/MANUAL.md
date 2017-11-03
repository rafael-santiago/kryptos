# Manual

**Abstract**: This library was designed to be used in user mode applications and also in kernel mode. The following
sections will guide the readers through the main aspects of how to use ``kryptos`` in their own stuff. This documentation
considers that the readers have at least a minimal formal knowledge of modern cryptography. All complete sample code
presented here can be built with the command ``hefesto --mk-samples``.

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
besides the additional parameters when necessary. You always use this structure to express what you want.

There is no field called "plaintext" or "ciphertext". There are the fields ``in`` and ``out``. Then, to encrypt data the **plaintext**
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

|    **Cipher**    |      **Type**         |    **Internal constant ID**      |
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

The available modes of operation for the block ciphers are: ``ECB``, ``CBC`` and ``OFB``. So in practice, considering the
``OFB`` mode, we have 16 stream ciphers instead of only two. More on cipher modes will be treated later.

The way of indicating the desired cipher for an encryption task is by setting the field ``cipher`` from the ``kryptos_task_ctx``
to the ``Internal constant ID`` listed in **Table 1**.

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
``kryptos_arc4_setup()`` also sets the ``cipher`` field from ``kryptos_task_ctx`` to ``kKryptosCipherARC4``.

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

When using ``CBC`` and ``OFB`` modes you do not have to worry about generating the initialization vector if you do not want to.
Once the iv field from ``kryptos_task_ctx`` initialized as NULL, a new iv will be generated and used. In addition, after
encrypting you do not need to worry about transfering the iv as a separated piece of information. The out field from
``kryptos_task_ctx`` gathers all information that you will need for a later decryption. As you may known there is no
necessity of an IV be secret. If you use a static IV, in the end you are using a more complicated scheme for ``ECB`` mode,
sadly, this kind of naive "pro-approach" is common. Avoid doing this, it is irresponsible and stupid.

The following code sample uses the SERPENT cipher in ``CBC`` mode with the c99 conveniences:

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
fail. As a result the ``kryptos_last_task_succeed(...)`` will indicate a zero value.

Details about a failure always can be accessed by watching the field ``result_verbose`` from the ``kryptos_task_ctx`` struct.
However, again, some errors let it ``NULL`` (always check its nullity before continuing).

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

Firstly I will show you how to generate hashes without using C macro conveniences, after we will generate hashes through
the available macro.

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

The following code uses the macro ``kryptos_hash()`` to generate a SHA-512 hash output in hexadecimal:

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
    int exit_code = 0;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *data = "Empty arms";
    size_t data_size = 10;

    kryptos_task_init_as_null(ktask);

    kryptos_hash(sha512, ktask, data, data_size, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        exit_code = 1;
        printf("Error while computing the message hash.\n");
        goto epilogue;
    }

    printf("Message hash: %s\n", ktask->out);

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return exit_code;
}
```

The general idea behind ``kryptos_hash()`` is:

```c
    kryptos_hash(<HASHID>,
                 <kryptos_task_ctx pointer>,
                 <input data>, <input data size>,
                 <to hex boolean flag>)
```

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
#if defined(KRYPTOS_C99)
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
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
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
avoids the necessity of driving the process with different functions or more explicit code.

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
    //               Actually it will generate a fourth value t what should be published by him.

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

Until now I show you DHKE samples using standarnized MODP values but kryptos also includes a way of generating your own
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

In order to generate DHKE domain parameters with the code shown above you should inform the size in bits of P and Q
respectively:

```
Watson@221B:~/src/kryptos-test/samples# ./dh-domain-params-sample 160 80 > params.txt
```

Once generated the parameters can be used instead of the standarnized MODP values. Of course that use p=160 bits and q=80 is
pretty insecure. The domain parameters calculating process can be slow. Since it depends on finding primes with specific
relations between them. It is driven by luck, it can take 15 minutes or 2/3 hours... Fortunately, you should do it once.

In practice you should use at least p=1024 and q=160 bits.

The domain parameters are exported as a ``PEM`` buffer. When receving a ``PEM`` buffer containing DHKE domain parameters
the best practice is to verify if those parameters are really "trustable" before accepting and starting using them.

The code below shows how to verify the values inside a ``PEM`` buffer.

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
    kryptos_u8_t *domain_params = "-----BEGIN DH PARAM P-----\n"
                                  "VSsW7ufPMgFn+MceQyQHgBtpq/q/"
                                  "xLAZ00q/hRh8Of7Wvto1lsS6iBWs"
                                  "mz4mYiSiOiPZkv6asUoBF8JhxMs4"
                                  "LHEGaTV0uiRzIPxOABkXDGUnXjwd"
                                  "EfpwkG3H+EuZK9fINggkkS+cxJ+P"
                                  "DwkaoMgpwZEZj+ieeeOSnZgKuvaN"
                                  "pVQ=\n"
                                  "-----END DH PARAM P-----\n"
                                  "-----BEGIN DH PARAM Q-----\n"
                                  "Xdy01wlOrsxucvEv7bz+7VBT9X0=\n"
                                  "-----END DH PARAM Q-----\n"
                                  "-----BEGIN DH PARAM G-----\n"
                                  "PdxLwCCBNeXR4EnVZb30SOHClBpr"
                                  "bfJkZs3WHyct4mbI71Yo6tqFLXZZ"
                                  "ozZCnP9ijWpsfz9qsfrcifcixEb0"
                                  "Ewd+Xf3ne3sHVrFwC/VLCAAi1Ccc"
                                  "a4GqzyO5juyIdjn2Bx8hWvV4E0G0"
                                  "jgP58tlcjSNYP2lJj7TGafmyom44"
                                  "Zxg=\n"
                                  "-----END DH PARAM G-----\n";
    int exit_code = 0;

    printf("I'm verifying the following DH domain parameters...\n\n%s\n", domain_params);

    printf("Wait...\n");

    if (kryptos_dh_verify_domain_params(domain_params, strlen(domain_params)) == kKryptosSuccess) {
        printf("INFO: The domain parameters are valid!\n");
    } else {
        printf("ERROR: Invalid domain parameters!\n");
        exit_code = 1;
    }

    return exit_code;
}
```

You really should avoid using any domain parameters rejected by the verifying function.

In order to load valid domain parameters and use them with DHKE stuff you should use the function
``kryptos_dh_get_modp_from_params_buf()``. The following code shows how to use domain parameters instead of
the standard internal MODP values with the ``Diffie-Hellman-Merkle`` key exchange scheme.

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
    kryptos_u8_t *params = "-----BEGIN DH PARAM P-----\n"
                           "VSsW7ufPMgFn+MceQyQHgBtpq/q/"
                           "xLAZ00q/hRh8Of7Wvto1lsS6iBWs"
                           "mz4mYiSiOiPZkv6asUoBF8JhxMs4"
                           "LHEGaTV0uiRzIPxOABkXDGUnXjwd"
                           "EfpwkG3H+EuZK9fINggkkS+cxJ+P"
                           "DwkaoMgpwZEZj+ieeeOSnZgKuvaN"
                           "pVQ=\n"
                           "-----END DH PARAM P-----\n"
                           "-----BEGIN DH PARAM Q-----\n"
                           "Xdy01wlOrsxucvEv7bz+7VBT9X0=\n"
                           "-----END DH PARAM Q-----\n"
                           "-----BEGIN DH PARAM G-----\n"
                           "PdxLwCCBNeXR4EnVZb30SOHClBpr"
                           "bfJkZs3WHyct4mbI71Yo6tqFLXZZ"
                           "ozZCnP9ijWpsfz9qsfrcifcixEb0"
                           "Ewd+Xf3ne3sHVrFwC/VLCAAi1Ccc"
                           "a4GqzyO5juyIdjn2Bx8hWvV4E0G0"
                           "jgP58tlcjSNYP2lJj7TGafmyom44"
                           "Zxg=\n"
                           "-----END DH PARAM G-----\n";
    int exit_code = 0;

    // INFO(Rafael): Always initializing the dh_xchg_ctx is a best practice.

    kryptos_dh_init_xchg_ctx(bob);
    kryptos_dh_init_xchg_ctx(alice);

    // INFO(Rafael): Loading the domain parameters from the previously generated PEM data.

    if (kryptos_dh_get_modp_from_params_buf(params, strlen(params),
                                            &bob->p, &bob->q, &bob->g) != kKryptosSuccess) {
        exit_code = 1;
        printf("ERROR: while getting P and G parameters.\n");
        goto main_epilogue;
    }

    // INFO(Rafael): Bob defines the size in bits of his random secret value and then he makes a key pair
    //               based on p, g and s.
    //
    //               Actually it will generate a fourth value t what should be published by him.

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

The function ``kryptos_dh_get_modp_from_params_buf()`` accepts a NULL Q parameter. You must pass it as NULL when your domain
parameter buffer does not contain the Q parameter. However be aware that a ``PEM`` buffer containing only P and G parameters
implies in an unverified domain parameters buffer. The verifying function cannot ascertain anything without Q.
Due to it you may be using small groups on your DHKE stuff. Maybe who have generated the used P and G values was naive or
malicious. Accept domain parameters like these at your own risk.

Well, I think that we have done with DHKE. For awhile let's forget a little about discrete logarithm cryptosystems and dive
into RSA available stuff...

### RSA

The best way of introducing the usage of ``RSA`` in kryptos is by showing you how to generate the key pair.

Well, the following code shows the way:

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

static int is_valid_number(const char *number, const size_t number_size);

int main(int argc, char **argv) {
    kryptos_u8_t *k_priv = NULL, *k_pub = NULL;
    size_t k_priv_size = 0, k_pub_size = 0;
    int exit_code = 0;

    if (argc > 1 && is_valid_number(argv[1], strlen(argv[1]))) {
        if (kryptos_rsa_mk_key_pair(atoi(argv[1]),
                                    &k_pub, &k_pub_size,
                                    &k_priv, &k_priv_size) == kKryptosSuccess) {
            // INFO(Rafael): This is just for demo issues, the best here would be
            //               save the k_pub and k_priv buffers to separated files
            //               for a later usage. Duh! :)
            printf("*** Public key:\n\n");
            printf("%s\n", k_pub);
            printf("*** Private key:\n\n");
            printf("%s\n", k_priv);
        } else {
            printf("ERROR: while generating the key pair.\n");
            exit_code = 1;
        }
    } else {
        printf("use: %s <key size in bits>\n", argv[0]);
        exit_code = 1;
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv);
    }

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub);
    }

    return exit_code;
}

static int is_valid_number(const char *number, const size_t number_size) {
    const char *np, *np_end;

    if (number == NULL) {
        return 0;
    }

    np = number;
    np_end = np + number_size;

    while (np != np_end) {
        if (!isdigit(*np)) {
            return 0;
        }
        np++;
    }

    return 1;
}
```

The function ``kryptos_rsa_mk_key_pair()`` does the job, it receives the key size (in bits), a (kryptos_u8_t **) for
the public key buffer, a pointer to store the public key size, a (kryptos_u8_t **) for the private key buffer, a
pointer to store the private key size. If the function succeeds it returns ``kKryptosSuccess``. Once generated
all that you should do is store the output data in somewhere for later usage. Free the key pair data when not necessary
anymore, because the buffers were allocated by the ``kryptos_rsa_mk_key_pair()`` function. Do not be sloppy! :)

Notice that the process of finding primes can be slow, so the key pair producing will become slow for greater
key sizes. Fortunately, you should do it once.

For example in a 32-bit SMP, the code above executed using the following command line:

```
Lestrade@221B:~/src/kryptos-test/src/samples# ../../samples/rsa-mk-key-pair-sample 2048
```

Took about 42, 43 minutes to generate this key pair:

```
*** Public key:

-----BEGIN RSA PARAM N-----
s9aTg1yS/b0cioPBdaFxwlbXFT0qDjx0aaM6QmImGMfSqg1ycAloDg2d/kP8M8qndrzdX3cOepuoKkGB6iSsMMS8otBSRve8Px5q3woN79T4
1r1Al9PvW0lIPi+oBtNcVOqKCeUlObfzxZecKm2jS+0mcWG+9hSuxl9A9EBxX4APcLUyVRDpX5VLe/IWJL0UzsWZB25FnED1FcqOHRQslDYi
mFVfnBv6UCU3E+/XfZInpxZ9yvntspV8ebuxHOgxKaUgDEfb985yUaRx9ZQfhtDM600nH0PaW4pdOV/BXoVmioO2bM/Rmwkth3/SMgcmjHRI
DrsDl+415Rbc+upTDw==
-----END RSA PARAM N-----
-----BEGIN RSA PARAM E-----
b5ZwnpaLpdIdqDv3OLKfKSmGYm1YNwoU+4wsNZaSATDs7HcsH9gUEKykuxMe7aypsuNuzyxNaM+jOGRfMcC5W+7YQJolurDZw9UV1WFdH0Rt
stcQpZDp/x0/ZcXCDBOK0qjoalL43C2+Hpcw6iaRjrtPGWksWAk6feWe/fAjdZaxA6+jUjHdcMP064dpDhv188WfjkvXkvZkM5A/aUm+sQsc
0QDzPeKI37TNrVL2RfoJadeTxyoOERy8DX973UevG8oFptfJbTE5QSWn+gln6LA/cCaW07TGQpeZ917BibntPDDrenOw+Ox8wN1yTCVx3+tY
L4amoEjaxvevM+SgBQ==
-----END RSA PARAM E-----

*** Private key:

-----BEGIN RSA PARAM N-----
s9aTg1yS/b0cioPBdaFxwlbXFT0qDjx0aaM6QmImGMfSqg1ycAloDg2d/kP8M8qndrzdX3cOepuoKkGB6iSsMMS8otBSRve8Px5q3woN79T4
1r1Al9PvW0lIPi+oBtNcVOqKCeUlObfzxZecKm2jS+0mcWG+9hSuxl9A9EBxX4APcLUyVRDpX5VLe/IWJL0UzsWZB25FnED1FcqOHRQslDYi
mFVfnBv6UCU3E+/XfZInpxZ9yvntspV8ebuxHOgxKaUgDEfb985yUaRx9ZQfhtDM600nH0PaW4pdOV/BXoVmioO2bM/Rmwkth3/SMgcmjHRI
DrsDl+415Rbc+upTDw==
-----END RSA PARAM N-----
-----BEGIN RSA PARAM D-----
DxId/jUln36fB1XhFEtLf8d30+A6Sznf9rU923pkUqK7h34TuyuwmKHumOlLXCGwGpzldMu2J+t6gP3WmTjuKNIHfq/BBd6G6Qh2aDeh4hdg
+Iz0Y377NV6mXqDhXELrs0oGBfsn0rARQV5rbugY2MqAttYhYf3hBDbTjkv20K4kqb1uKS++/M3UlE/n3pbs5O50SLV0uCgwzkmVZ3ii4k31
6hXc1wua9NnvVgALl1vXdVkpJo7mqQaBrSDKhgvovKWnpt4NjIJRXkX1IgF0n1lUp1ph1A5Mm8NJMiCwNn/LiIuw3nhUDOxD4U3U5Raj6lsW
Hu5edzYetSfSrSwHDw==
-----END RSA PARAM D-----
```

With the key pair well-generated is time to know how to use it in order to encrypt and decrypt some data.

The following code shows the very basic usage of RSA cipher in ``kryptos``:

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
    kryptos_u8_t *k_pub_bob = "-----BEGIN RSA PARAM N-----\n"
                              "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                              "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                              "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                              "8otBSRve8Px5q3woN79T41r1Al9Pv"
                              "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                              "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                              "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                              "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                              "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                              "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                              "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                              "mjHRIDrsDl+415Rbc+upTDw==\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "b5ZwnpaLpdIdqDv3OLKfKSmGYm1YN"
                              "woU+4wsNZaSATDs7HcsH9gUEKykux"
                              "Me7aypsuNuzyxNaM+jOGRfMcC5W+7"
                              "YQJolurDZw9UV1WFdH0RtstcQpZDp"
                              "/x0/ZcXCDBOK0qjoalL43C2+Hpcw6"
                              "iaRjrtPGWksWAk6feWe/fAjdZaxA6"
                              "+jUjHdcMP064dpDhv188WfjkvXkvZ"
                              "kM5A/aUm+sQsc0QDzPeKI37TNrVL2"
                              "RfoJadeTxyoOERy8DX973UevG8oFp"
                              "tfJbTE5QSWn+gln6LA/cCaW07TGQp"
                              "eZ917BibntPDDrenOw+Ox8wN1yTCV"
                              "x3+tYL4amoEjaxvevM+SgBQ==\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
                               "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                               "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                               "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                               "8otBSRve8Px5q3woN79T41r1Al9Pv"
                               "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                               "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                               "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                               "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                               "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                               "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                               "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                               "mjHRIDrsDl+415Rbc+upTDw==\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "DxId/jUln36fB1XhFEtLf8d30+A6S"
                               "znf9rU923pkUqK7h34TuyuwmKHumO"
                               "lLXCGwGpzldMu2J+t6gP3WmTjuKNI"
                               "Hfq/BBd6G6Qh2aDeh4hdg+Iz0Y377"
                               "NV6mXqDhXELrs0oGBfsn0rARQV5rb"
                               "ugY2MqAttYhYf3hBDbTjkv20K4kqb"
                               "1uKS++/M3UlE/n3pbs5O50SLV0uCg"
                               "wzkmVZ3ii4k316hXc1wua9NnvVgAL"
                               "l1vXdVkpJo7mqQaBrSDKhgvovKWnp"
                               "t4NjIJRXkX1IgF0n1lUp1ph1A5Mm8"
                               "NJMiCwNn/LiIuw3nhUDOxD4U3U5Ra"
                               "j6lsWHu5edzYetSfSrSwHDw==\n"
                               "-----END RSA PARAM D-----\n";

    kryptos_u8_t *message = "This is weak!\x00\x00\x00";
    size_t message_size = 16;
    kryptos_task_ctx a, b, *alice = &a, *bob = &b;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("Message: %s\n\n", message);

    alice->in = message;
    alice->in_size = message_size;

    kryptos_rsa_setup(alice, k_pub_bob, strlen(k_pub_bob));
    kryptos_task_set_encrypt_action(alice);

    kryptos_rsa_cipher(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while encrypting!\n");
        exit(1);
    }

    printf("Ciphertext:\n\n%s\n", alice->out);

    bob->in = alice->out;
    bob->in_size = alice->out_size;

    kryptos_rsa_setup(bob, k_priv_bob, strlen(k_priv_bob));
    kryptos_task_set_decrypt_action(bob);

    kryptos_rsa_cipher(&bob);

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: while decrypting!\n");
        exit(1);
    }

    printf("Plaintext: %s\n", bob->out);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return 0;
}
```

The same code can be simplified using ``c99`` capabilities, take a look:

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
#if defined(KRYPTOS_C99)
    kryptos_u8_t *k_pub_bob = "-----BEGIN RSA PARAM N-----\n"
                              "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                              "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                              "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                              "8otBSRve8Px5q3woN79T41r1Al9Pv"
                              "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                              "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                              "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                              "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                              "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                              "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                              "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                              "mjHRIDrsDl+415Rbc+upTDw==\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "b5ZwnpaLpdIdqDv3OLKfKSmGYm1YN"
                              "woU+4wsNZaSATDs7HcsH9gUEKykux"
                              "Me7aypsuNuzyxNaM+jOGRfMcC5W+7"
                              "YQJolurDZw9UV1WFdH0RtstcQpZDp"
                              "/x0/ZcXCDBOK0qjoalL43C2+Hpcw6"
                              "iaRjrtPGWksWAk6feWe/fAjdZaxA6"
                              "+jUjHdcMP064dpDhv188WfjkvXkvZ"
                              "kM5A/aUm+sQsc0QDzPeKI37TNrVL2"
                              "RfoJadeTxyoOERy8DX973UevG8oFp"
                              "tfJbTE5QSWn+gln6LA/cCaW07TGQp"
                              "eZ917BibntPDDrenOw+Ox8wN1yTCV"
                              "x3+tYL4amoEjaxvevM+SgBQ==\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
                               "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                               "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                               "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                               "8otBSRve8Px5q3woN79T41r1Al9Pv"
                               "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                               "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                               "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                               "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                               "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                               "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                               "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                               "mjHRIDrsDl+415Rbc+upTDw==\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "DxId/jUln36fB1XhFEtLf8d30+A6S"
                               "znf9rU923pkUqK7h34TuyuwmKHumO"
                               "lLXCGwGpzldMu2J+t6gP3WmTjuKNI"
                               "Hfq/BBd6G6Qh2aDeh4hdg+Iz0Y377"
                               "NV6mXqDhXELrs0oGBfsn0rARQV5rb"
                               "ugY2MqAttYhYf3hBDbTjkv20K4kqb"
                               "1uKS++/M3UlE/n3pbs5O50SLV0uCg"
                               "wzkmVZ3ii4k316hXc1wua9NnvVgAL"
                               "l1vXdVkpJo7mqQaBrSDKhgvovKWnp"
                               "t4NjIJRXkX1IgF0n1lUp1ph1A5Mm8"
                               "NJMiCwNn/LiIuw3nhUDOxD4U3U5Ra"
                               "j6lsWHu5edzYetSfSrSwHDw==\n"
                               "-----END RSA PARAM D-----\n";

    kryptos_u8_t *message = "This is shorter but still weak!\x00";
    size_t message_size = 32;
    kryptos_task_ctx a, b, *alice = &a, *bob = &b;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("Message: %s\n\n", message);

    kryptos_task_set_in(alice, message, message_size);
    kryptos_task_set_encrypt_action(alice);
    kryptos_run_cipher(rsa, alice, k_pub_bob, strlen(k_pub_bob));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while encrypting!\n");
        exit(1);
    }

    printf("Ciphertext:\n\n%s\n", alice->out);

    kryptos_task_set_in(bob, alice->out, alice->out_size);
    kryptos_task_set_decrypt_action(bob);
    kryptos_run_cipher(rsa, bob, k_priv_bob, strlen(k_priv_bob));

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: while decrypting!\n");
        exit(1);
    }

    printf("Plaintext: %s\n", bob->out);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return 0;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
```

These two samples should be actually used only for introductory issues, since the ``RSA`` as it is usually explained in many
crypto books is a very weak system. One of the several weaknesses present is the fact of being a deterministic cryptosystem.
It works as a block cipher in ``ECB`` mode. It always produces the same result for the same input. In practice the
"schoolbook RSA" is a naive approach and should be avoided.

As you should know a strengthened way of using RSA is to pad the input before encrypting. Kryptos implements ``RSA`` with
``OAEP`` padding. The following code is a sample of how to use it with ``c99``:

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
#if defined(KRYPTOS_C99)
    kryptos_u8_t *k_pub_bob = "-----BEGIN RSA PARAM N-----\n"
                              "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                              "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                              "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                              "8otBSRve8Px5q3woN79T41r1Al9Pv"
                              "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                              "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                              "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                              "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                              "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                              "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                              "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                              "mjHRIDrsDl+415Rbc+upTDw==\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "b5ZwnpaLpdIdqDv3OLKfKSmGYm1YN"
                              "woU+4wsNZaSATDs7HcsH9gUEKykux"
                              "Me7aypsuNuzyxNaM+jOGRfMcC5W+7"
                              "YQJolurDZw9UV1WFdH0RtstcQpZDp"
                              "/x0/ZcXCDBOK0qjoalL43C2+Hpcw6"
                              "iaRjrtPGWksWAk6feWe/fAjdZaxA6"
                              "+jUjHdcMP064dpDhv188WfjkvXkvZ"
                              "kM5A/aUm+sQsc0QDzPeKI37TNrVL2"
                              "RfoJadeTxyoOERy8DX973UevG8oFp"
                              "tfJbTE5QSWn+gln6LA/cCaW07TGQp"
                              "eZ917BibntPDDrenOw+Ox8wN1yTCV"
                              "x3+tYL4amoEjaxvevM+SgBQ==\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_bob = "-----BEGIN RSA PARAM N-----\n"
                               "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                               "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                               "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                               "8otBSRve8Px5q3woN79T41r1Al9Pv"
                               "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                               "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                               "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                               "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                               "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                               "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                               "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                               "mjHRIDrsDl+415Rbc+upTDw==\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "DxId/jUln36fB1XhFEtLf8d30+A6S"
                               "znf9rU923pkUqK7h34TuyuwmKHumO"
                               "lLXCGwGpzldMu2J+t6gP3WmTjuKNI"
                               "Hfq/BBd6G6Qh2aDeh4hdg+Iz0Y377"
                               "NV6mXqDhXELrs0oGBfsn0rARQV5rb"
                               "ugY2MqAttYhYf3hBDbTjkv20K4kqb"
                               "1uKS++/M3UlE/n3pbs5O50SLV0uCg"
                               "wzkmVZ3ii4k316hXc1wua9NnvVgAL"
                               "l1vXdVkpJo7mqQaBrSDKhgvovKWnp"
                               "t4NjIJRXkX1IgF0n1lUp1ph1A5Mm8"
                               "NJMiCwNn/LiIuw3nhUDOxD4U3U5Ra"
                               "j6lsWHu5edzYetSfSrSwHDw==\n"
                               "-----END RSA PARAM D-----\n";

    kryptos_u8_t *message = "This is not deterministic!";
    kryptos_task_ctx a, b, *alice = &a, *bob = &b;
    kryptos_u8_t *label = "L";
    size_t label_size = 1;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("Message: %s\n\n", message);

    kryptos_task_set_in(alice, message, strlen(message));
    kryptos_task_set_encrypt_action(alice);
    kryptos_run_cipher(rsa_oaep, alice, k_pub_bob, strlen(k_pub_bob), label, &label_size,
                       kryptos_oaep_hash(sha1));


    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while encrypting!\n");
        exit(1);
    }

    printf("Ciphertext:\n\n%s\n", alice->out);

    kryptos_task_set_in(bob, alice->out, alice->out_size);
    kryptos_task_set_decrypt_action(bob);
    kryptos_run_cipher(rsa_oaep, bob, k_priv_bob, strlen(k_priv_bob), label, &label_size,
                       kryptos_oaep_hash(sha1));

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: while decrypting!\n");
        exit(1);
    }

    printf("Plaintext: %s\n", bob->out);

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return 0;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
```

I am assuming that the reader has a previously knowledge about how ``OAEP`` padding works.

Thus, the ``RSA OAEP`` should receive the key and its size and also a label and the size of this label and a pointer to a hash
function and a pointer to a hash function size.

In kryptos any available hash function is named by using this format: ``kryptos_<HASHID>_hash``.

The hash size function is named by using this format: ``kryptos_<HASHID>_hash_size``.

The ``HASHID`` can be found in **Table 4**.

The macro ``kryptos_oaep_hash()`` is a way of making easier the function parameters passing. All that you should do with
this macro is to pass the ``HASHID`` of the desired hash algorithm to be used in the OAEP stuff.

Then now with those tips I hope that the following code snippet becomes clearer to you:

```c
    kryptos_run_cipher(rsa_oaep, bob, k_priv_bob, strlen(k_priv_bob), label, &label_size,
                       kryptos_oaep_hash(sha1));
```

### Elgamal

The Elgamal encryption is available in kryptos in two modes: the schoolbook mode and with OAEP padding.

As you may know the Elgamal is a probabilistic cryptosystem so the schoolbook mode is stronger than the RSA schoolbook.

The key pair generating can take several minutes since it is driven by luck... This process can be time consuming due to it
go read a book, walk the dog, jog, wash the dishes and so come back later... the following code is capable of generating
the key pair buffers for Elgamal:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static int is_valid_number(const char *number, const size_t number_size);

int main(int argc, char **argv) {
    size_t p_bits, q_bits;
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size, k_priv_size;
    int exit_code = 0;

    if (argc > 2) {
        if (!is_valid_number(argv[1], strlen(argv[1])) ||
            !is_valid_number(argv[2], strlen(argv[2]))) {
            goto usage;
        }

        if (kryptos_elgamal_mk_key_pair(atoi(argv[1]), atoi(argv[2]),
                                        &k_pub, &k_pub_size,
                                        &k_priv, &k_priv_size) == kKryptosSuccess) {
            printf("Public key:\n");
            printf("\n%s\n", k_pub);
            printf("Private key:\n");
            printf("\n%s\n", k_priv);
        } else {
            printf("ERROR: while making the key pair.\n");
            exit_code = 1;
        }
    } else {
usage:
        printf("use: %s <p size in bits> <q size in bits>\n", argv[0]);
        exit_code = 1;
    }

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub);
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv);
    }

    return exit_code;
}

static int is_valid_number(const char *number, const size_t number_size) {
    const char *np, *np_end;

    if (number == NULL || number_size == 0) {
        return 0;
    }

    np = number;
    np_end = np + number_size;

    while (np != np_end) {
        if (!isdigit(*np)) {
            return 0;
        }
        np++;
    }

    return 1;
}
```

In order to generate the sample key pair used in Elgamal stuff here I used the following command line:

```
MsHudson@221B:~/src/kryptos-test/src/samples# ../../samples/elgamal-mk-key-pair-sample 1024 160
```

It took me about 90/91 minutes in a SMP 32-bit environment.

According to the code shown above, it uses the function ``kryptos_elgamal_mk_key_pair()`` to generate
the Elgamal key pair. The arguments are: the P parameter size, the Q parameter size, a pointer to the public buffer,
a pointer to store the size of the public buffer, a pointer to the private buffer and a pointer to store the size of the
private buffer. When the function succeeds it returns ``kKryptosSuccess``.

For brevity I will show you only the ``c99`` applications of the Elgamal in kryptos. The ``raw`` usage mode without ``c99``
conveniences is similar to ``RSA``, I find you can figure it out by yourself. Thus, this is the way of using the Elgamal
schoolbook with ``c99``:

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
    kryptos_u8_t *k_pub = "-----BEGIN ELGAMAL PARAM P-----\n"
                          "VRdEtMLDjy6jSMKvM83QDgAR1Y/2ZI9"
                          "rDvT4nmFFBoV9/0q5HA+29b3V54aBOv"
                          "G2Z31lqsfTWldx8AEnfs7N6gOlNmHC4"
                          "xoST0rv/80gjdb+Kc+LWQAjmsSpdWBJ"
                          "ZiAeBX7nZ4yyDFbFTTFiLvYwRj48YSr"
                          "KWnA7aJQwwcSLtQQ=\n"
                          "-----END ELGAMAL PARAM P-----\n"
                          "-----BEGIN ELGAMAL PARAM Q-----\n"
                          "SXShpt+AsZ2nSsm6W+sxh3wVqFY=\n"
                          "-----END ELGAMAL PARAM Q-----\n"
                          "-----BEGIN ELGAMAL PARAM G-----\n"
                          "RiMRb7ClUb6s0ibMlVIlpHA6uXTyZ4J"
                          "xwzKsNKpMNibCWurQMiW728/mh9krRL"
                          "1a1rxt0G0ZQJWKBbFbZxGoDOZQW1ltO"
                          "sJaibQBZ1WELtnN8HI581nJ3Np0sGXn"
                          "1CvsWm9CuCBroLCpFAVKDJFIwcdSZmD"
                          "KHPd/aworRwZANAQ=\n"
                          "-----END ELGAMAL PARAM G-----\n"
                          "-----BEGIN ELGAMAL PARAM B-----\n"
                          "mdIQuCFoT4nscK6AcpfkY0cCWmrVHGm"
                          "UTM3SDL3K0+0mFG6JkhhM0BcI3C7leH"
                          "UdMW6RD8vYq7qjcsGil6rNu1Ur4MQtw"
                          "0jtZhxYT8CQAJ0oH8XnwSCGWpgQedb4"
                          "ViGbiqtR0ZN7o3ScmSbd4o8EIzaVleW"
                          "BSy5Eb4B1aE2fwQE=\n"
                          "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *k_priv = "-----BEGIN ELGAMAL PARAM P-----\n"
                           "VRdEtMLDjy6jSMKvM83QDgAR1Y/2ZI9"
                           "rDvT4nmFFBoV9/0q5HA+29b3V54aBOv"
                           "G2Z31lqsfTWldx8AEnfs7N6gOlNmHC4"
                           "xoST0rv/80gjdb+Kc+LWQAjmsSpdWBJ"
                           "ZiAeBX7nZ4yyDFbFTTFiLvYwRj48YSr"
                           "KWnA7aJQwwcSLtQQ=\n"
                           "-----END ELGAMAL PARAM P-----\n"
                           "-----BEGIN ELGAMAL PARAM D-----\n"
                           "onkj9oCz4yimIihUZWsEoEVtl0M=\n"
                           "-----END ELGAMAL PARAM D-----\n";

    kryptos_u8_t *message = "moon over marin\x00";
    size_t message_size = 16;
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    int exit_code = 0;

    printf("*** ORIGINAL MESSAGE: '%s'\n", message);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    kryptos_task_set_in(alice, message, message_size);
    kryptos_task_set_encrypt_action(alice);
    kryptos_run_cipher(elgamal, alice, k_pub, strlen(k_pub));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while encrypting.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** CIPHERTEXT:\n\n%s\n", alice->out);

    kryptos_task_set_in(bob, alice->out, alice->out_size);
    kryptos_task_set_decrypt_action(bob);
    kryptos_run_cipher(elgamal, bob, k_priv, strlen(k_priv));

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: while decrypting.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** PLAINTEXT: '%s'\n", bob->out);

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
}
```

The ``OAEP`` version of Elgamal is similar to the RSA, you need to pass a label, label size and a hash algorithm to be used
during the padding process. Look:

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
    int exit_code = 0;
    kryptos_u8_t *k_pub = "-----BEGIN ELGAMAL PARAM P-----\n"
                          "VRdEtMLDjy6jSMKvM83QDgAR1Y/2ZI9"
                          "rDvT4nmFFBoV9/0q5HA+29b3V54aBOv"
                          "G2Z31lqsfTWldx8AEnfs7N6gOlNmHC4"
                          "xoST0rv/80gjdb+Kc+LWQAjmsSpdWBJ"
                          "ZiAeBX7nZ4yyDFbFTTFiLvYwRj48YSr"
                          "KWnA7aJQwwcSLtQQ=\n"
                          "-----END ELGAMAL PARAM P-----\n"
                          "-----BEGIN ELGAMAL PARAM Q-----\n"
                          "SXShpt+AsZ2nSsm6W+sxh3wVqFY=\n"
                          "-----END ELGAMAL PARAM Q-----\n"
                          "-----BEGIN ELGAMAL PARAM G-----\n"
                          "RiMRb7ClUb6s0ibMlVIlpHA6uXTyZ4J"
                          "xwzKsNKpMNibCWurQMiW728/mh9krRL"
                          "1a1rxt0G0ZQJWKBbFbZxGoDOZQW1ltO"
                          "sJaibQBZ1WELtnN8HI581nJ3Np0sGXn"
                          "1CvsWm9CuCBroLCpFAVKDJFIwcdSZmD"
                          "KHPd/aworRwZANAQ=\n"
                          "-----END ELGAMAL PARAM G-----\n"
                          "-----BEGIN ELGAMAL PARAM B-----\n"
                          "mdIQuCFoT4nscK6AcpfkY0cCWmrVHGm"
                          "UTM3SDL3K0+0mFG6JkhhM0BcI3C7leH"
                          "UdMW6RD8vYq7qjcsGil6rNu1Ur4MQtw"
                          "0jtZhxYT8CQAJ0oH8XnwSCGWpgQedb4"
                          "ViGbiqtR0ZN7o3ScmSbd4o8EIzaVleW"
                          "BSy5Eb4B1aE2fwQE=\n"
                          "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *k_priv = "-----BEGIN ELGAMAL PARAM P-----\n"
                           "VRdEtMLDjy6jSMKvM83QDgAR1Y/2ZI9"
                           "rDvT4nmFFBoV9/0q5HA+29b3V54aBOv"
                           "G2Z31lqsfTWldx8AEnfs7N6gOlNmHC4"
                           "xoST0rv/80gjdb+Kc+LWQAjmsSpdWBJ"
                           "ZiAeBX7nZ4yyDFbFTTFiLvYwRj48YSr"
                           "KWnA7aJQwwcSLtQQ=\n"
                           "-----END ELGAMAL PARAM P-----\n"
                           "-----BEGIN ELGAMAL PARAM D-----\n"
                           "onkj9oCz4yimIihUZWsEoEVtl0M=\n"
                           "-----END ELGAMAL PARAM D-----\n";

    kryptos_u8_t *message = "The Man With The Dogs";
    size_t message_size = 21;
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *label = NULL;

    printf("*** ORIGINAL MESSAGE: '%s'\n", message);

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    kryptos_task_set_in(alice, message, message_size);
    kryptos_task_set_encrypt_action(alice);
    kryptos_run_cipher(elgamal_oaep, alice, k_pub, strlen(k_pub),
                       label, NULL, kryptos_oaep_hash(sha384));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while encrypting. %s\n", alice->result_verbose);
        exit_code = 1;
        goto epilogue;
    }

    printf("*** CIPHERTEXT:\n\n%s\n", alice->out);

    kryptos_task_set_in(bob, alice->out, alice->out_size);
    kryptos_task_set_decrypt_action(bob);
    kryptos_run_cipher(elgamal_oaep, bob, k_priv, strlen(k_priv),
                       label, NULL, kryptos_oaep_hash(sha384));

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: while decrypting.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** PLAINTEXT: '%s'\n", bob->out);

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
}
```

The sample code shown above introduces a interesting thing about ciphers with support to OAEP padding. If you pass a NULL
label and also a NULL label size, internally the OAEP padding function will use an empty string as a label.

If you pass the hash function and the hash function size as NULL pointers, internally the OAEP padding function will use
``SHA1`` to do the hashing stuff. Something like:

```c
    kryptos_run_cipher(elgamal_oaep, alice, k_pub, strlen(k_pub),
                       label, NULL,
                       NULL /*NULL hash function*/,
                       NULL /*NULL hash size function*/);
```

Now is time to talk about digital signature.

### Digital signature

Until now two digital signature algorithms are implemented: ``RSA`` and ``DSA``. The two implementions are
a general way of signing data so the details about the sign protocol is up to you. Maybe you want to encrypt
and then sign or just signing, it depends on your requirements. Due to it, the sign process only focuses in ascertain
if the input is authenticated or not. When the verification process fails the output buffer from the task will be
NULL and the task result will be equal to ``kKryptosInvalidSignature``. When the verification succeeds the output
buffer will contain the authenticated data and so you can process this verified output as you intend. The output
buffer when not NULL should be freed.

#### RSA

Firstly I will show you the way of sign an input buffer with the standard RSA sign algorithm without ``C99`` conveniences.
Take a look:

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
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *message = "The Lost Art of Keeping a Secret";
    size_t message_size = 32;
    kryptos_u8_t *k_pub_alice =  "-----BEGIN RSA PARAM N-----\n"
                                 "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                                 "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                                 "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                                 "8otBSRve8Px5q3woN79T41r1Al9Pv"
                                 "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                                 "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                                 "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                                 "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                                 "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                                 "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                                 "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                                 "mjHRIDrsDl+415Rbc+upTDw==\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM E-----\n"
                                 "b5ZwnpaLpdIdqDv3OLKfKSmGYm1YN"
                                 "woU+4wsNZaSATDs7HcsH9gUEKykux"
                                 "Me7aypsuNuzyxNaM+jOGRfMcC5W+7"
                                 "YQJolurDZw9UV1WFdH0RtstcQpZDp"
                                 "/x0/ZcXCDBOK0qjoalL43C2+Hpcw6"
                                 "iaRjrtPGWksWAk6feWe/fAjdZaxA6"
                                 "+jUjHdcMP064dpDhv188WfjkvXkvZ"
                                 "kM5A/aUm+sQsc0QDzPeKI37TNrVL2"
                                 "RfoJadeTxyoOERy8DX973UevG8oFp"
                                 "tfJbTE5QSWn+gln6LA/cCaW07TGQp"
                                 "eZ917BibntPDDrenOw+Ox8wN1yTCV"
                                 "x3+tYL4amoEjaxvevM+SgBQ==\n"
                                 "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN RSA PARAM N-----\n"
                                 "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                                 "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                                 "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                                 "8otBSRve8Px5q3woN79T41r1Al9Pv"
                                 "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                                 "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                                 "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                                 "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                                 "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                                 "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                                 "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                                 "mjHRIDrsDl+415Rbc+upTDw==\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM D-----\n"
                                 "DxId/jUln36fB1XhFEtLf8d30+A6S"
                                 "znf9rU923pkUqK7h34TuyuwmKHumO"
                                 "lLXCGwGpzldMu2J+t6gP3WmTjuKNI"
                                 "Hfq/BBd6G6Qh2aDeh4hdg+Iz0Y377"
                                 "NV6mXqDhXELrs0oGBfsn0rARQV5rb"
                                 "ugY2MqAttYhYf3hBDbTjkv20K4kqb"
                                 "1uKS++/M3UlE/n3pbs5O50SLV0uCg"
                                 "wzkmVZ3ii4k316hXc1wua9NnvVgAL"
                                 "l1vXdVkpJo7mqQaBrSDKhgvovKWnp"
                                 "t4NjIJRXkX1IgF0n1lUp1ph1A5Mm8"
                                 "NJMiCwNn/LiIuw3nhUDOxD4U3U5Ra"
                                 "j6lsWHu5edzYetSfSrSwHDw==\n"
                                 "-----END RSA PARAM D-----\n";

    int exit_code = 0;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("*** MESSAGE: '");
    fwrite(message, message_size, 1, stdout);
    printf("'\n");

    alice->cipher = kKryptosCipherRSA;

    alice->in = message;
    alice->in_size = message_size;
    alice->key = k_priv_alice;
    alice->key_size = strlen(k_priv_alice);

    kryptos_rsa_sign(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while signing the message.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** SIGNED OUTPUT:\n\n%s\n", alice->out);

    bob->cipher = kKryptosCipherRSA;
    bob->in = alice->out;
    bob->in_size = alice->out_size;
    bob->key = k_pub_alice;
    bob->key_size = strlen(k_pub_alice);

    kryptos_rsa_verify(&bob);

    if (!kryptos_last_task_succeed(bob)) {
        if (bob->result != kKryptosInvalidSignature) {
            printf("ERROR: invalid signature.\n");
        } else {
            printf("ERROR: while verifying the signature.\n");
        }
        exit_code = 1;
        goto epilogue;
    }

    printf("*** AUTHENTICATED OUTPUT: '");
    fwrite(bob->out, bob->out_size, 1, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
}
```

The code above is a little bit longer since it does not use the internal dsl implemented by some ``c99`` macros. The following
code sample does the same thing but it uses ``c99``:

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
#if defined(KRYPTOS_C99)
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *message = "The Lost Art of Keeping a Secret";
    size_t message_size = 32;
    kryptos_u8_t *k_pub_alice =  "-----BEGIN RSA PARAM N-----\n"
                                 "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                                 "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                                 "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                                 "8otBSRve8Px5q3woN79T41r1Al9Pv"
                                 "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                                 "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                                 "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                                 "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                                 "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                                 "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                                 "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                                 "mjHRIDrsDl+415Rbc+upTDw==\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM E-----\n"
                                 "b5ZwnpaLpdIdqDv3OLKfKSmGYm1YN"
                                 "woU+4wsNZaSATDs7HcsH9gUEKykux"
                                 "Me7aypsuNuzyxNaM+jOGRfMcC5W+7"
                                 "YQJolurDZw9UV1WFdH0RtstcQpZDp"
                                 "/x0/ZcXCDBOK0qjoalL43C2+Hpcw6"
                                 "iaRjrtPGWksWAk6feWe/fAjdZaxA6"
                                 "+jUjHdcMP064dpDhv188WfjkvXkvZ"
                                 "kM5A/aUm+sQsc0QDzPeKI37TNrVL2"
                                 "RfoJadeTxyoOERy8DX973UevG8oFp"
                                 "tfJbTE5QSWn+gln6LA/cCaW07TGQp"
                                 "eZ917BibntPDDrenOw+Ox8wN1yTCV"
                                 "x3+tYL4amoEjaxvevM+SgBQ==\n"
                                 "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN RSA PARAM N-----\n"
                                 "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                                 "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                                 "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                                 "8otBSRve8Px5q3woN79T41r1Al9Pv"
                                 "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                                 "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                                 "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                                 "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                                 "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                                 "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                                 "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                                 "mjHRIDrsDl+415Rbc+upTDw==\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM D-----\n"
                                 "DxId/jUln36fB1XhFEtLf8d30+A6S"
                                 "znf9rU923pkUqK7h34TuyuwmKHumO"
                                 "lLXCGwGpzldMu2J+t6gP3WmTjuKNI"
                                 "Hfq/BBd6G6Qh2aDeh4hdg+Iz0Y377"
                                 "NV6mXqDhXELrs0oGBfsn0rARQV5rb"
                                 "ugY2MqAttYhYf3hBDbTjkv20K4kqb"
                                 "1uKS++/M3UlE/n3pbs5O50SLV0uCg"
                                 "wzkmVZ3ii4k316hXc1wua9NnvVgAL"
                                 "l1vXdVkpJo7mqQaBrSDKhgvovKWnp"
                                 "t4NjIJRXkX1IgF0n1lUp1ph1A5Mm8"
                                 "NJMiCwNn/LiIuw3nhUDOxD4U3U5Ra"
                                 "j6lsWHu5edzYetSfSrSwHDw==\n"
                                 "-----END RSA PARAM D-----\n";

    int exit_code = 0;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("*** MESSAGE: '");
    fwrite(message, message_size, 1, stdout);
    printf("'\n");

    kryptos_sign(rsa, alice, message, message_size, k_priv_alice, strlen(k_priv_alice));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while signing the message.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** SIGNED OUTPUT:\n\n%s\n", alice->out);

    kryptos_verify(rsa, bob, alice->out, alice->out_size, k_pub_alice, strlen(k_pub_alice));

    if (!kryptos_last_task_succeed(bob)) {
        if (bob->result != kKryptosInvalidSignature) {
            printf("ERROR: invalid signature.\n");
        } else {
            printf("ERROR: while verifying the signature.\n");
        }
        exit_code = 1;
        goto epilogue;
    }

    printf("*** AUTHENTICATED OUTPUT: '");
    fwrite(bob->out, bob->out_size, 1, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
```

The code above is shorter and simpler than the previous one. You just use the dsl primitives ``kryptos_sign()`` and
``kryptos_verify()``.

The ``kryptos_sign()`` primitive expects the signature algorithm name, a pointer to the task context, the message and its
size, the private key buffer and its size.

The ``kryptos_verify()`` similarly expects the signature algorithm name, a pointer to the task context, the signed buffer and
its size, the public key buffer and its size.

The ``RSA`` signature tends to be time consuming depending on the size of the input and of course the modulus. There is also
a trick that can speed up the verification process and it can be achieved by choosing a small public key factor,
however, it is out of scope of the manual. You can also hash the input before signing.

The standard RSA digital signature is weak. The best practice to avoid some flaws present in the standard way is to pad the
input. Thus, kryptos implements the ``RSA-EMSA-PSS`` signature scheme. The following code sample shows how to use this
stronger scheme with ``c99`` conveniences.

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
#if defined(KRYPTOS_C99)
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *message = "The Lost Art of Keeping a Secret";
    size_t message_size = 32;
    kryptos_u8_t *k_pub_alice =  "-----BEGIN RSA PARAM N-----\n"
                                 "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                                 "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                                 "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                                 "8otBSRve8Px5q3woN79T41r1Al9Pv"
                                 "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                                 "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                                 "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                                 "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                                 "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                                 "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                                 "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                                 "mjHRIDrsDl+415Rbc+upTDw==\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM E-----\n"
                                 "b5ZwnpaLpdIdqDv3OLKfKSmGYm1YN"
                                 "woU+4wsNZaSATDs7HcsH9gUEKykux"
                                 "Me7aypsuNuzyxNaM+jOGRfMcC5W+7"
                                 "YQJolurDZw9UV1WFdH0RtstcQpZDp"
                                 "/x0/ZcXCDBOK0qjoalL43C2+Hpcw6"
                                 "iaRjrtPGWksWAk6feWe/fAjdZaxA6"
                                 "+jUjHdcMP064dpDhv188WfjkvXkvZ"
                                 "kM5A/aUm+sQsc0QDzPeKI37TNrVL2"
                                 "RfoJadeTxyoOERy8DX973UevG8oFp"
                                 "tfJbTE5QSWn+gln6LA/cCaW07TGQp"
                                 "eZ917BibntPDDrenOw+Ox8wN1yTCV"
                                 "x3+tYL4amoEjaxvevM+SgBQ==\n"
                                 "-----END RSA PARAM E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN RSA PARAM N-----\n"
                                 "s9aTg1yS/b0cioPBdaFxwlbXFT0qD"
                                 "jx0aaM6QmImGMfSqg1ycAloDg2d/k"
                                 "P8M8qndrzdX3cOepuoKkGB6iSsMMS"
                                 "8otBSRve8Px5q3woN79T41r1Al9Pv"
                                 "W0lIPi+oBtNcVOqKCeUlObfzxZecK"
                                 "m2jS+0mcWG+9hSuxl9A9EBxX4APcL"
                                 "UyVRDpX5VLe/IWJL0UzsWZB25FnED"
                                 "1FcqOHRQslDYimFVfnBv6UCU3E+/X"
                                 "fZInpxZ9yvntspV8ebuxHOgxKaUgD"
                                 "Efb985yUaRx9ZQfhtDM600nH0PaW4"
                                 "pdOV/BXoVmioO2bM/Rmwkth3/SMgc"
                                 "mjHRIDrsDl+415Rbc+upTDw==\n"
                                 "-----END RSA PARAM N-----\n"
                                 "-----BEGIN RSA PARAM D-----\n"
                                 "DxId/jUln36fB1XhFEtLf8d30+A6S"
                                 "znf9rU923pkUqK7h34TuyuwmKHumO"
                                 "lLXCGwGpzldMu2J+t6gP3WmTjuKNI"
                                 "Hfq/BBd6G6Qh2aDeh4hdg+Iz0Y377"
                                 "NV6mXqDhXELrs0oGBfsn0rARQV5rb"
                                 "ugY2MqAttYhYf3hBDbTjkv20K4kqb"
                                 "1uKS++/M3UlE/n3pbs5O50SLV0uCg"
                                 "wzkmVZ3ii4k316hXc1wua9NnvVgAL"
                                 "l1vXdVkpJo7mqQaBrSDKhgvovKWnp"
                                 "t4NjIJRXkX1IgF0n1lUp1ph1A5Mm8"
                                 "NJMiCwNn/LiIuw3nhUDOxD4U3U5Ra"
                                 "j6lsWHu5edzYetSfSrSwHDw==\n"
                                 "-----END RSA PARAM D-----\n";

    int exit_code = 0;
    size_t salt_size = 8;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("*** MESSAGE: '");
    fwrite(message, message_size, 1, stdout);
    printf("'\n");

    kryptos_sign(rsa_emsa_pss, alice, message, message_size, k_priv_alice, strlen(k_priv_alice),
                 &salt_size, kryptos_pss_hash(sha1));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while signing the message.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** SIGNED OUTPUT:\n\n%s\n", alice->out);

    kryptos_verify(rsa_emsa_pss, bob, alice->out, alice->out_size, k_pub_alice, strlen(k_pub_alice),
                   &salt_size, kryptos_pss_hash(sha1));

    if (!kryptos_last_task_succeed(bob)) {
        if (bob->result != kKryptosInvalidSignature) {
            printf("ERROR: invalid signature.\n");
        } else {
            printf("ERROR: while verifying the signature.\n");
        }
        exit_code = 1;
        goto epilogue;
    }

    printf("*** AUTHENTICATED OUTPUT: '");
    fwrite(bob->out, bob->out_size, 1, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
```

The ``kryptos_sign()`` and ``kryptos_verify()`` calls are similar to the standard RSA signature scheme sample. However was
added three parameters: the salt size in bytes, the hash function pointer and its hash size function pointer. The passing
of the function pointers are abstracted with the another macro ``kryptos_pss_hash()``.

If you pass both function pointers as NULL the ``PSS`` stuff will use ``SHA-1`` to hash the data.

#### DSA

The ``DSA`` is one of the most popular signature algorithms. As you may know it involves a key pair calculation. The following
code is capable of generating the public and private key ``PEM`` buffers. The data that will be used for signing and verifying.

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

static int is_valid_number(const char *number, const size_t number_size);

int main(int argc, char **argv) {
    int exit_code = 0;
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size, k_priv_size;

    if (argc >= 3) {
        if (!is_valid_number(argv[1], strlen(argv[1])) ||
            !is_valid_number(argv[2], strlen(argv[2]))) {
            exit_code = 1;
            goto usage;
        }

        if (kryptos_dsa_mk_key_pair(atoi(argv[1]), atoi(argv[2]),
                                    &k_pub, &k_pub_size,
                                    &k_priv, &k_priv_size) != kKryptosSuccess) {
            exit_code = 1;
            printf("ERROR: while generating key pair.\n");
        } else {
            printf("*** PUBLIC KEY:\n\n%s\n", k_pub);
            printf("*** PRIVATE KEY:\n\n%s\n", k_priv);
        }
    } else {
usage:
        printf("use: %s <p size in bits> <q size in bits>\n", argv[0]);
    }

epilogue:

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub);
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv);
    }

    return exit_code;
}

static int is_valid_number(const char *number, const size_t number_size) {
    const char *np, *np_end;

    if (number == NULL || number_size == 0) {
        return 0;
    }

    np = number;
    np_end = np + number_size;

    while (np != np_end) {
        if (!isdigit(*np)) {
            return 0;
        }

        np++;
    }

    return 1;
}
```

I ran the code above in a simple 32-bit SMP Linux box and it tooks me about 00:25:28 minutes to generate a ``DSA`` key pair
with <P=1024, Q=160>. Again, it is driven by luck, like ``RSA``, ``DH``, ``Elgamal`` stuff. It is about to find primes
with some specific relations between them.

The exact command line was:

```
Mycroft@221B:~/src/kryptos-test/src/samples# ../../samples/dsa-mk-key-pair-sample 1024 160
```

As a result it produced the following output:

```
*** PUBLIC KEY:

-----BEGIN DSA P-----
+TyfXiVPtBkAIRwp5ZDMNNOvx36w9DG0kQVWmbaeIm9VJanCQb+pTfbDTnCnnyZ10h4bibG6CKJFk75bYgL6QzveLHdQO2WIPhXLtv0U08c
0DRNdjZu9aRvvHj2RXiumUz5pVCbhQoeAv9YI1yxYa+I4J+FNyMnwC6LKtRQGKAM=
-----END DSA P-----
-----BEGIN DSA Q-----
t4dXC9PBaAnSUv0fB30fm9PyUS8=
-----END DSA Q-----
-----BEGIN DSA G-----
xP+KKzjMo3H+gLZKa/UXnZIO7n8RNHNSDE7puR0VOsmWJtXf8wYDb/23+TN+eyMQgF2FOrwQYHj+hS4MbE+yWiMa6nyFhoNbaMU5voVDw7
Jhpm2Jq23m4kfkjwE4ICzg+uLKRe+U+5ESfWLrRvbrKAxVlBYHfP8RppLRIyv64AA=
-----END DSA G-----
-----BEGIN DSA E-----
RH6V4fmnt9dQA+rCqBsdYUDmKtymXfmx15nlYiCK8hhwf4UWJn760igxwafCx15wnSaYnG2+950eN24MK9UAL69E2VvCir3BXbuWXmPPG
IWsSuJ8QYIG3vQtbr3yWiJI22zguxOnPzATBF4X5Yl/gjP7/BhDZcQJoFOaZaOATQI=
-----END DSA E-----

*** PRIVATE KEY:

-----BEGIN DSA P-----
+TyfXiVPtBkAIRwp5ZDMNNOvx36w9DG0kQVWmbaeIm9VJanCQb+pTfbDTnCnnyZ10h4bibG6CKJFk75bYgL6QzveLHdQO2WIPhXLtv0U0
8c0DRNdjZu9aRvvHj2RXiumUz5pVCbhQoeAv9YI1yxYa+I4J+FNyMnwC6LKtRQGKAM=
-----END DSA P-----
-----BEGIN DSA Q-----
t4dXC9PBaAnSUv0fB30fm9PyUS8=
-----END DSA Q-----
-----BEGIN DSA G-----
xP+KKzjMo3H+gLZKa/UXnZIO7n8RNHNSDE7puR0VOsmWJtXf8wYDb/23+TN+eyMQgF2FOrwQYHj+hS4MbE+yWiMa6nyFhoNbaMU5voVDw
7Jhpm2Jq23m4kfkjwE4ICzg+uLKRe+U+5ESfWLrRvbrKAxVlBYHfP8RppLRIyv64AA=
-----END DSA G-----
-----BEGIN DSA D-----
vLOB3BI4FOgD7HJCRrL7eQsbRxw=
-----END DSA D-----
```

Now we will use those key pair in the next ``DSA`` sample stuff.

The way of use ``DSA`` without ``c99`` conveniences is almost the same way shown in ``RSA``, due to it, for brevity, from
now on I will show only the sign and verify procedures by using ``c99`` conveniences.

The following code shows how to sign and verify with ``DSA``:

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
#if defined(KRYPTOS_C99)
    kryptos_task_ctx at, bt, *alice = &at, *bob = &bt;
    kryptos_u8_t *message = "Hellnation's what they teach us, profiting from greed\n"
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

    kryptos_u8_t *k_pub_alice = "-----BEGIN DSA P-----\n"
                                "+TyfXiVPtBkAIRwp5ZDMNNOvx36w9DG0kQVWmbaeIm9VJanCQb+pTfbDTnCnnyZ10h4bibG6"
                                "CKJFk75bYgL6QzveLHdQO2WIPhXLtv0U08c0DRNdjZu9aRvvHj2RXiumUz5pVCbhQoeAv9YI"
                                "1yxYa+I4J+FNyMnwC6LKtRQGKAM=\n"
                                "-----END DSA P-----\n"
                                "-----BEGIN DSA Q-----\n"
                                "t4dXC9PBaAnSUv0fB30fm9PyUS8=\n"
                                "-----END DSA Q-----\n"
                                "-----BEGIN DSA G-----\n"
                                "xP+KKzjMo3H+gLZKa/UXnZIO7n8RNHNSDE7puR0VOsmWJtXf8wYDb/23+TN+eyMQgF2FOrwQ"
                                "YHj+hS4MbE+yWiMa6nyFhoNbaMU5voVDw7Jhpm2Jq23m4kfkjwE4ICzg+uLKRe+U+5ESfWLr"
                                "RvbrKAxVlBYHfP8RppLRIyv64AA=\n"
                                "-----END DSA G-----\n"
                                "-----BEGIN DSA E-----\n"
                                "RH6V4fmnt9dQA+rCqBsdYUDmKtymXfmx15nlYiCK8hhwf4UWJn760igxwafCx15wnSaYnG2+"
                                "950eN24MK9UAL69E2VvCir3BXbuWXmPPGIWsSuJ8QYIG3vQtbr3yWiJI22zguxOnPzATBF4X"
                                "5Yl/gjP7/BhDZcQJoFOaZaOATQI=\n"
                                "-----END DSA E-----\n";

    kryptos_u8_t *k_priv_alice = "-----BEGIN DSA P-----\n"
                                 "+TyfXiVPtBkAIRwp5ZDMNNOvx36w9DG0kQVWmbaeIm9VJanCQb+pTfbDTnCnnyZ10h4bibG"
                                 "6CKJFk75bYgL6QzveLHdQO2WIPhXLtv0U08c0DRNdjZu9aRvvHj2RXiumUz5pVCbhQoeAv9"
                                 "YI1yxYa+I4J+FNyMnwC6LKtRQGKAM=\n"
                                 "-----END DSA P-----\n"
                                 "-----BEGIN DSA Q-----\n"
                                 "t4dXC9PBaAnSUv0fB30fm9PyUS8=\n"
                                 "-----END DSA Q-----\n"
                                 "-----BEGIN DSA G-----\n"
                                 "xP+KKzjMo3H+gLZKa/UXnZIO7n8RNHNSDE7puR0VOsmWJtXf8wYDb/23+TN+eyMQgF2FOrw"
                                 "QYHj+hS4MbE+yWiMa6nyFhoNbaMU5voVDw7Jhpm2Jq23m4kfkjwE4ICzg+uLKRe+U+5ESfW"
                                 "LrRvbrKAxVlBYHfP8RppLRIyv64AA=\n"
                                 "-----END DSA G-----\n"
                                 "-----BEGIN DSA D-----\n"
                                 "vLOB3BI4FOgD7HJCRrL7eQsbRxw=\n"
                                 "-----END DSA D-----\n";

    int exit_code = 0;

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("*** MESSAGE:\n\n%s\n", message);

    kryptos_sign(dsa, alice, message, strlen(message), k_priv_alice, strlen(k_priv_alice),
                 kryptos_dsa_hash(sha256));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: while siginging the message.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** SIGNED OUTPUT:\n\n%s\n", alice->out);

    kryptos_verify(dsa, bob, alice->out, alice->out_size, k_pub_alice, strlen(k_pub_alice),
                   kryptos_dsa_hash(sha256));

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
```

As you can see the macros ``kryptos_sign`` and ``kryptos_verify`` are used but now is requested ``dsa`` instead of ``rsa``.
The remaining parameters are: the buffer to be processed (signed or verified), the size of this buffer, the key buffer
(when sigining the private key and when verifying the public key), the size of the key buffer and also a pointer to the hash
function that ``DSA`` will use internally. For convenience was used the macro ``kryptos_dsa_hash``, this macro only
expects a ``HASHID`` and you can find the available hash ids in **Table 4**. When NULL is passed as the hash function
parameter, the ``SHA-1`` is chosen as the default hash function. In the sample above ``SHA-256`` is used, in order to
pass it without the macro you should use ``kryptos_sha256_hash`` since it is the function name that performs ``SHA-256``
stuff in kryptos (a.k.a the ``SHA-256`` hash processor).

## Secondary stuff

Besides the cryptographic tasks, ``kryptos`` also has some secondary stuff such as encoding, compression and data export
functionalities. In the following section we will discuss them a little.

### Encoding algorithms

Until now are available two encoding algorithms: ``Base64`` and ``UUEncode``.

Here follows the way of using ``Base64`` without taking advantage of any dsl convenience:

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
    kryptos_task_ctx t, *ktask = &t;
    int exit_code = 0;

    // INFO(Rafael): Indicating which encoder use.

    t.encoder = kKryptosEncodingBASE64;

    t.in = "Hey Beavis, I will become a encoded string Huh!";
    t.in_size = strlen(t.in);

    printf("Original text: '%s'\n", t.in);

    // INFO(Rafael): Once the encoder indicated we need to inform our encode intentions
    //               and then call the encoding processor.

    kryptos_task_set_encode_action(ktask);
    kryptos_base64_processor(&ktask);

    if (!kryptos_last_task_succeed(ktask)) {
        t.in = NULL;
        t.in_size = 0;
        printf("Error during encoding task.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Encoded text: '%s'\n", t.out);

    t.in = t.out;
    t.in_size = t.out_size;

    t.out = NULL;
    t.out_size = 0;

    // INFO(Rafael): Once the encoder indicated we need to inform our decode intentions
    //               and then call the encoding processor again.


    kryptos_task_set_decode_action(ktask);
    kryptos_base64_processor(&ktask);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("Error during decoding task.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Decoded text: '");
    fwrite(t.out, t.out_size, 1, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return exit_code;
}
```

Using the kryptos internal dsl features the code above becomes much more simpler, look:

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
    kryptos_task_ctx t, *ktask = &t;
    int exit_code = 0;
    char *data = "Hey Beavis, I will become a encoded string Huh!";

    printf("Original text: '%s'\n", data);

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(base64, ktask, data, strlen(data));

    if (!kryptos_last_task_succeed(ktask)) {
        t.in = NULL;
        t.in_size = 0;
        printf("Error during encoding task.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Encoded text: '%s'\n", ktask->out);

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(base64, ktask, ktask->out, ktask->out_size);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("Error during decoding task.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Decoded text: '");
    fwrite(ktask->out, ktask->out_size, 1, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return exit_code;
}
```

The "raw usage" of ``UUEncode`` is similar to the way shown in ``Base64`` related sample. Due to it, for the sake of our
patience, the code below uses ``UUEncode`` with the kryptos internal dsl primitive ``kryptos_run_encoder()``:

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
    int exit_code = 0;
    kryptos_task_ctx t, *ktask = &t;
    char *data = "Angel of Harlem";

    kryptos_task_init_as_null(ktask);

    printf("Original data: '%s'\n", data);

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(uuencode, ktask, data, strlen(data));

    if (!kryptos_last_task_succeed(ktask)) {
        exit_code = 1;
        printf("Encoding error!\n");
        ktask->in = NULL;
        goto epilogue;
    }

    printf("Encoded data: '%s'\n", ktask->out);

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(uuencode, ktask, ktask->out, ktask->out_size);

    if (!kryptos_last_task_succeed(ktask)) {
        exit_code = 1;
        printf("Decoding error!\n");
        goto epilogue;
    }

    printf("Decoded data: '");
    fwrite(ktask->out, 1, ktask->out_size, stdout);
    printf("'\n");

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return exit_code;
}
```

### Data compression

The data compression routine available here is only for entropy issues. However, as you may know not always is
a good idea compress data before encrypting, it depends on your data and your communication channel. Anyway, kryptos
ships a huffman code stuff in cases that you really want to compress data (at your own risk):

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
    kryptos_u8_t *data = "Lie, lie, lie\n"
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

    deflated_data = kryptos_huffman_deflate(data, strlen(data), &deflated_data_size);

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
```

### Handling PEM buffers

The export format used in kryptos is ``PEM``. In order to handle this type of data kryptos exposes three functions. A function
to put some information into a ``PEM`` buffer. A function to get some information from a ``PEM`` buffer and also another function
to load a multiprecision number from a ``PEM`` buffer.

The code below shows the way of putting data inside a ``PEM`` buffer:

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

#define FIRST_NAME "FIRST"

#define SECOND_NAME "SECOND"

int main(int argc, char **argv) {
    kryptos_u8_t *pem_buffer = NULL;
    size_t pem_buffer_size;
    int exit_code = 0;

    if (kryptos_pem_put_data(&pem_buffer, &pem_buffer_size, SECOND_NAME,
                             "Bond", 4) != kKryptosSuccess) {
        printf("Error while putting data labeled as %s into buffer.\n", SECOND_NAME);
        exit_code = 1;
        goto epilogue;
    }

    printf("PEM:\n\n%s\n", pem_buffer);

    if (kryptos_pem_put_data(&pem_buffer, &pem_buffer_size, FIRST_NAME,
                             "James", 5) != kKryptosSuccess) {
        printf("Error while putting data labeled as %s into buffer.\n", FIRST_NAME);
    }

    printf("PEM:\n\n%s\n", pem_buffer);

epilogue:

    if (pem_buffer != NULL) {
        kryptos_freeseg(pem_buffer);
    }

    return exit_code;
}
```

The following code shows how to get plain data from a ``PEM`` buffer:

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

#define SECOND_NAME "SECOND"

#define FIRST_NAME "FIRST"

int main(int argc, char **argv) {
    int exit_code = 0;
    kryptos_u8_t *pem_buffer = "-----BEGIN SECOND-----\n"
                               "Qm9uZA==\n"
                               "-----END SECOND-----\n"
                               "-----BEGIN FIRST-----\n"
                               "SmFtZXM=\n"
                               "-----END FIRST-----\n";

    kryptos_u8_t *first = NULL, *second = NULL;
    size_t first_size, second_size, pem_buffer_size = strlen(pem_buffer);

    second = kryptos_pem_get_data(SECOND_NAME, pem_buffer, pem_buffer_size, &second_size);

    if (second == NULL) {
        printf("Error while getting data labeled as %s from buffer.\n", SECOND_NAME);
        exit_code = 1;
        goto epilogue;
    }

    first = kryptos_pem_get_data(FIRST_NAME, pem_buffer, pem_buffer_size, &first_size);

    if (first == NULL) {
        printf("Error while getting data labeled as %s from buffer.\n", FIRST_NAME);
        exit_code = 1;
        goto epilogue;
    }

    printf("My name is ");

    fwrite(second, second_size, 1, stdout);

    printf(", ");

    fwrite(first, first_size, 1, stdout);

    printf(" ");

    fwrite(second, second_size, 1, stdout);

    printf(".\n");

epilogue:

    if (second != NULL) {
        kryptos_freeseg(second);
    }

    if (first != NULL) {
        kryptos_freeseg(first);
    }

    return exit_code;
}
```

The third ``PEM`` buffer function is destinated to read multiprecision data. The following code does the job:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <kryptos_mp.h>
#include <stdio.h>

#define PRIME "PRIME"

int main(int argc, char **argv) {
    int exit_code = 0;
    kryptos_u8_t *pem_buffer = "-----BEGIN PRIME-----\n"
                               "+TyfXiVPtBkAIRwp5ZDMN"
                               "NOvx36w9DG0kQVWmbaeIm"
                               "9VJanCQb+pTfbDTnCnnyZ"
                               "10h4bibG6CKJFk75bYgL6"
                               "QzveLHdQO2WIPhXLtv0U0"
                               "8c0DRNdjZu9aRvvHj2RXi"
                               "umUz5pVCbhQoeAv9YI1yx"
                               "Ya+I4J+FNyMnwC6LKtRQG"
                               "KAM=\n"
                               "-----END PRIME-----\n";

    kryptos_mp_value_t *prime = NULL;
    int is_prime;

    if (kryptos_pem_get_mp_data(PRIME, pem_buffer, strlen(pem_buffer), &prime) != kKryptosSuccess) {
        printf("Error while getting the prime number from buffer.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("Number successfully loaded from the PEM buffer.\n");

    printf("By the way, this is the exact number loaded (in hexadecimal format) "); kryptos_print_mp(prime);

    printf("Now I am testing the primality of it, please wait...\n");

    is_prime = kryptos_mp_is_prime(prime);

    if (is_prime) {
        printf("The number is prime.\n");
    } else {
        printf("The number is not prime as expected.\n");
        exit_code = 1;
    }

epilogue:

    if (prime != NULL) {
        kryptos_del_mp_value(prime);
    }

    return exit_code;
}
```

More details about the multiprecision handling functions are not given because it is considered an advanced
topic for a final user manual. For more details try the technical documentation destinated to contributors.

## So it is enough

If you have understood every single sample code presented in here, I think that you are ready for some action
with this library. I hope you enjoy! Happy coding! :)

Do you think that something is still unclear? Please let me [know](https://github.com/rafael-santiago/kryptos/issues)
and thank you!
