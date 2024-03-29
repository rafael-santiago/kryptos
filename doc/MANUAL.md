# Manual

**Abstract**: This library was designed to be used in user mode applications and also in kernel mode. The following
sections will guide the readers through the main aspects of how to use ``kryptos`` in their own stuff. This documentation
considers that the readers have at least a minimal formal knowledge of modern cryptography. All complete sample code
presented here can be built with the command ``hefesto --mk-samples``.

## Contents

- [Link101](#link101)
    - [Linking user mode applications](#linking-user-mode-applications)
    - [Linking kernel mode stuff](#linking-kernel-mode-stuff)
- [The main idea behind this library](#the-main-idea-behind-this-library)
    - [How it has been versioned](#how-it-has-been-versioned)
    - [The kryptos_task_ctx struct](#the-kryptos_task_ctx-struct)
- [The symmetric stuff](#the-symmetric-stuff)
    - [Hashes](#hashes)
    - [HMACs](#hmacs)
    - [Poly1305](#poly1305)
    - [SipHash](#siphash)
    - [Incremental input reading](#incremental-input-reading)
- [Asymmetric stuff](#asymmetric-stuff)
    - [The Diffie-Hellman-Merkle key exchange](#the-diffie-hellman-merkle-key-exchange)
    - [RSA](#rsa)
    - [Elgamal](#elgamal)
    - [Digital signature](#digital-signature)
        - [RSA](#rsa)
        - [DSA](#dsa)
        - [ECDSA](#ecdsa)
- [Secondary stuff](#secondary-stuff)
    - [Encoding algorithms](#encoding-algorithms)
    - [Data compression](#data-compression)
    - [Handling PEM buffers](#handling-pem-buffers)
    - [CSPRNG](#csprng)
    - [Avoiding RAM swap](#avoiding-ram-swap)
    - [Key derivation functions](#key-derivation-functions)
    - [Bcrypt](#bcrypt)
- [OTPs](#otps)
    - [HOTP](#hotp)
    - [TOTP](#totp)
- [So it is enough](#so-it-is-enough)

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

On Windows we also must link your code with ``bcrypt.(lib|a)`` due to the random generator system pool.

Yes, ``Libkryptos`` also offers support for compilation on ``Microsoft Visual C``, take a look at ``doc/BUILD.md`` for
more details.

[Back](#contents)

### Linking kernel mode stuff

For kernel mode, until now, kryptos can be used on ``FreeBSD``, ``NetBSD``, ``Linux`` and ``Windows``. The main idea was
create a tiny library easy to embed in any project. Thus all you need to do is define the C macro ``KRYPTOS_KERNEL_MODE``
during the compilation of your code.

On ``Linux`` if you want to use the c99 capabilities of ``kryptos`` you also need to pass the compiler flag ``-std=gnu99``.

On ``Windows`` c99 capabilities are on by default. In addition you must link your stuff with ``cng.lib`` (due to the random
pool used from there) and ``libcntpr.lib`` due to some libc conveniences offered within Windows kernel and used by us. Since
you are linking with ``libcntpr.lib`` define ``USE_LIBCNTPR=1``.

[Back](#contents)

## The main idea behind this library

The main idea here is to provide a way of using some cryptographic primitives without the necessity of longer and confuse
codes. Your code does not need to be the ciphertext, unlike it should clearly generate it.

Almost all cryptographic operations done in kryptos are based on simple tasks. A task is expressed by the C struct
``kryptos_task_ctx``.

You do not need to worry about where this struct is specifically defined in kryptos. For all user code, just including
``kryptos.h`` will give you access to every relevant feature.

[Back](#contents)

### How it has been versioned

``Libkryptos`` expresses its version through ``KRYPTOS_VERSION`` defined into ``kryptos_types.h`` (but you should include
``kryptos.h`` instead).

The version number is expressed in a big-endian hexadecimal value. Being the most significant 16-bit value the current year in
which the library was released (in decimal) and the least significant 16-bit is used to release increment (starting at zero):

```c
#define KRYPTOS_VERSION 0x20210000
```

**Remark**: More than 2^16 versions in a year is not an extremelly active project but a pretty bad bugged one! ;)

[Back](#contents)

### The kryptos_task_ctx struct

The ``kryptos_task_ctx`` is responsible for storing the plaintext, ciphertext, the current used algorithm, the key parameters
besides the additional parameters when necessary. You always use this structure to express what you want to do.

There is no field called "plaintext" or "ciphertext". There are the fields ``in`` and ``out``. Then, to encrypt data the **plaintext**
must be stored into ``in``. When decrypting the **ciphertext** also must be stored into ``in``. The resultant data of the two operations
always will be stored (allocated) into ``out``.

However, when you store the input data into the task context is necessary also indicate the size in bytes of that data. The
field ``in_size`` holds the input size.

After any executed task, the field ``result`` will contain a code which describes the status of that last task. The additional
field called ``result_verbose`` may also contain some literal description about. **Sometimes ``result_verbose`` may be null**.

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

[Back](#contents)

## The symmetric stuff

Until now, ``kryptos`` has the following symmetric ciphers:

**Table 1**: The available symmetric ciphers.

|    **Cipher**                   |**Type**|    **Internal constant ID**        |  **Internal Name** |
|:-------------------------------:|:------:|:----------------------------------:|:------------------:|
|   ``ARC4``                      | Stream |       ``kKryptosCipherARC4``       |      ``arc4``      |
|   ``SEAL``                      | Stream |       ``kKryptosCipherSEAL``       |      ``seal``      |
|  ``RABBIT``                     | Stream |       ``kKryptosCipherRABBIT``     |      ``rabbit``    |
|  ``SALSA20``                    | Stream |       ``kKryptosCipherSALSA20``    |      ``salsa20``   |
|  ``CHACHA20``                   | Stream |       ``kKryptosCipherCHACHA20``   |      ``chacha20``  |
| ``AES-128``                     | Block  |       ``kKryptosCipherAES128``     |      ``aes128``    |
| ``AES-192``                     | Block  |       ``kKryptosCipherAES192``     |      ``aes192``    |
| ``AES-256``                     | Block  |       ``kKryptosCipherAES256``     |      ``aes256``    |
|   ``DES``                       | Block  |       ``kKryptosCipherDES``        |       ``des``      |
|   ``3DES``                      | Block  |       ``kKryptosCipher3DES``       |    ``triple_des``  |
| ``3DES-EDE``                    | Block  |       ``kKryptosCipher3DESEDE``    |  ``triple_des_ede``|
|   ``IDEA``                      | Block  |       ``kKryptosCipherIDEA``       |       ``idea``     |
|    ``RC2``                      | Block  |       ``kKryptosCipherRC2``        |        ``rc2``     |
|    ``RC5``                      | Block  |       ``kKryptosCipherRC5``        |        ``rc5``     |
|   ``RC6-128``                   | Block  |       ``kKryptosCipherRC6128``     |      ``rc6_128``   |
|   ``RC6-192``                   | Block  |       ``kKryptosCipherRC6192``     |      ``rc6_192``   |
|   ``RC6-256``                   | Block  |       ``kKryptosCipherRC6256``     |      ``rc6_256``   |
|   ``FEAL``                      | Block  |       ``kKryptosCipherFEAL``       |       ``feal``     |
|  ``CAST5``                      | Block  |       ``kKryptosCipherCAST5``      |       ``cast5``    |
| ``CAMELLIA-128``                | Block  |       ``kKryptosCipherCAMELLIA``   |    ``camellia128`` |
| ``CAMELLIA-192``                | Block  |       ``kKryptosCipherCAMELLIA``   |    ``camellia192`` |
| ``CAMELLIA-256``                | Block  |       ``kKryptosCipherCAMELLIA``   |    ``camellia256`` |
| ``SAFER-K64``                   | Block  |       ``kKryptosCipherSAFERK64``   |     ``saferk64``   |
| ``BLOWFISH``                    | Block  |       ``kKryptosCipherBLOWFISH``   |     ``blowfish``   |
| ``SERPENT``                     | Block  |       ``kKryptosCipherSERPENT``    |      ``serpent``   |
|   ``TEA``                       | Block  |       ``kKryptosCipherTEA``        |        ``tea``     |
|   ``XTEA``                      | Block  |       ``kKryptosCipherXTEA``       |        ``xtea``    |
|  ``MISTY1``                     | Block  |       ``kKryptosCipherMISTY1``     |        ``misty1``  |
| ``MARS-128``                    | Block  |       ``kKryptosCipherMARS128``    |       ``mars128``  |
| ``MARS-192``                    | Block  |       ``kKryptosCipherMARS192``    |       ``mars192``  |
| ``MARS-256``                    | Block  |       ``kKryptosCipherMARS256``    |       ``mars256``  |
| ``PRESENT-80``                  | Block  |       ``kKryptosCipherPRESENT``    |      ``present80`` |
| ``PRESENT-128``                 | Block  |       ``kKryptosCipherPRESENT``    |      ``present128``|
| ``SHACAL-1``                    | Block  |       ``kKryptosCipherSHACAL1``    |       ``shacal1``  |
| ``SHACAL-2``                    | Block  |       ``kKryptosCipherSHACAL2``    |       ``shacal2``  |
| ``NOEKEON`` (indirect key mode) | Block  |       ``kKryptosCipherNOEKEON``    |       ``noekeon``  |
| ``NOEKEON`` (direct key mode)   | Block  |       ``kKryptosCipherNOEKEOND``   |       ``noekeon_d``|
|  ``GOST`` (with DES s-boxes)    | Block  |       ``kKryptosCipherGOSTDS``     |       ``gost_ds``  |
|  ``GOST``                       | Block  |       ``kKryptosCipherGOST``       |       ``gost``     |
| ``TWOFISH-128``                 | Block  |       ``kKryptosCipherTwofish128`` |    ``twofish128``  |
| ``TWOFISH-192``                 | Block  |       ``kKryptosCipherTwofish192`` |    ``twofish192``  |
| ``TWOFISH-256``                 | Block  |       ``kKryptosCipherTwofish256`` |    ``twofish256``  |

The available modes of operation for block ciphers are: ``ECB``, ``CBC``, ``CTR``, ``OFB`` and ``GCM``. So in practice,
considering the ``OFB`` and ``CTR`` modes (also ``GCM`` indirectly), we have much more stream ciphers.

As you should know, originally, the GCM mode is only supported by block ciphers which work with 128-bit blocks. Currently
these are the ciphers with support for GCM mode in kryptos: ``AES-128``, ``AES-192``, ``AES-256``, ``RC6-128``, ``RC6-192``,
``RC6-256``, ``CAMELLIA-128``, ``CAMELLIA-192``, ``CAMELLIA-256``, ``SERPENT``, ``MARS-128``, ``MARS-192``, ``MARS-256``,
``NOEKEON`` (indirect key mode), ``NOEKEON`` (direct key mode), ``TWOFISH-128``, ``TWOFISH-192``, ``TWOFISH-256``.

When you try to run a cipher whithout support for GCM mode an error will be returned (``kKryptosNoSupport``).
More on cipher modes will be treated later. Similarly, more details about how to use GCM will be shown later, too.

The way of indicating the desired cipher for an encryption task is by setting the field ``cipher`` from the ``kryptos_task_ctx``
to the ``Internal constant ID`` listed in **Table 1**.

Similarly the indication of the operation mode is done by setting the field ``mode``. The values could be: ``kKryptosECB``,
``kKryptosCBC``, ``kKryptosOFB``, ``kKryptosCTR``, ``kKryptosGCM``. Of course, this field is only relevant when you are
dealing with block ciphers.

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

        kryptos_freeseg(ktask->in, ktask->in_size);
        kryptos_freeseg(ktask->out, ktask->out_size);
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

The use of ``kryptos_freeseg()`` in order to free memory is encouraged because in kernel mode it can abstract some complications
for you. In user mode you can call the default libc ``free()`` function, there is no problem with that if you do not worry about
letting data behind (``kryptos_freeseg()`` zeroes the segment before actually freeing it).

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

The general usage of ``kryptos_run_cipher`` macro is:

``kryptos_run_cipher(<cipher internal name>, <ktask pointer>, key, key_size[, args]...)``

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

Until now is possible to use block ciphers in five modes: ``ECB``, ``CBC``, ``OFB``, ``CTR`` and ``GCM``.

The **Table 2** lists the identifiers related with each available operation mode.

**Table 2**: The available operation modes for block ciphers.

| **Operation Mode** |       **Identifier**             |
|:------------------:|:--------------------------------:|
|       ``ECB``      |         kKryptosECB              |
|       ``CBC``      |         kKryptosCBC              |
|       ``OFB``      |         kKryptosOFB              |
|       ``CTR``      |         kKryptosCTR              |
|       ``GCM``      |         kKryptosGCM              |

When using ``CBC``, ``OFB`` and ``CTR`` modes you do not have to worry about generating the initialization vector if you do not
want to. Once the iv field from ``kryptos_task_ctx`` initialized as NULL, a new iv will be generated and used. In addition, after
encrypting you do not need to worry about transferring the iv as a separated piece of information. The out field from
``kryptos_task_ctx`` gathers all information that you will need for a later decryption. As you may known, there is no
necessity of an IV be secret. If you use a static IV, in the end you are using a more complicated scheme for ``ECB`` mode,
sadly, this kind of naive "pro-approach" is common. Avoid doing this. It is stupid.

In order to strengthen the ``CTR`` mode, kryptos uses a common strategy of concatenating a random chosen IV with the current
counter value. It reserves 4 bytes for the counter data. So we have 2^32 different values for the counter. The library does
not control if the counter is recycled, it is up to you, but usually in ordinary cryptographic tasks you should not
mind so much about that. Assuming you are using AES-128 in CTR mode, you will be able of processing 2^35 bytes (2^3 + 2^32)
before choosing a new random IV. This is something near to 32 gigabytes, if your application does disk encryption or even
network encryption you should mind about it.

If you want to get the current state of the counter in order to save it you should use the following macro:

```c
    kryptos_u32_t counter;
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    kryptos_task_set_ctr_mode(ktask, &counter);

    /* Perform the encryption steps and then 'counter' will be
            storing the current value of the counter of the CTR mode. */
```

If you just want to use CTR mode without saving the counter status:

```c
    kryptos_task_ctx t, *ktask = &t;

    (...)

    kryptos_task_set_ctr_mode(ktask, NULL);
```

You also should initialize the task context as null and do not mess with its internal counter:

```c
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);
```

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
However, again, some errors let it ``NULL`` (**always check its nullity before continuing access it**).

Okay, now coming back to CTR mode let's use AES-256 in this mode:

```c
/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    int error = 0;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u32_t ctr = 9;
    kryptos_u8_t *plain = "But why don't you take him with you into the light? "
                          "He does not deserve the light, he deserves peace.";
    kryptos_u8_t *p, *p_end;
    size_t plain_size = strlen(plain);
    kryptos_u8_t *key = "Fly Me To The Moon";
    size_t key_size = strlen(key);

    kryptos_task_init_as_null(ktask);

    kryptos_task_set_in(ktask, plain, plain_size);
    kryptos_task_set_ctr_mode(ktask, &ctr);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, key, key_size, kKryptosCTR);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: %s\n", ktask->result_verbose);
        error = 1;
        goto epilogue;
    }

    p = ktask->out;
    p_end = p + ktask->out_size;

    printf("CRYPTOGRAM: ");

    while (p != p_end) {
        printf("%c", isprint(*p) ? *p : '.');
        p++;
    }

    printf("\n");

    printf("NEXT COUNTER VALUE: %d\n", ctr);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, key, key_size, kKryptosCTR);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: %s\n", ktask->result_verbose);
        error = 1;
        goto epilogue;
    }

    printf("PLAINTEXT: ");
    fwrite(ktask->out, ktask->out_size, 1, stdout);
    printf("\n");

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IV | KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return error;
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return 1;
#endif
}
```

All ciphers that uses 128-bit data block supports the Galois counter mode (``GCM``). This mode implements confidentiality
and authenticity. If someone tamper with the cryptogram during its transmission, it will be detected. The following sample uses
AES-256 in ``GCM`` mode:

```c
/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <kryptos.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *plaintext = "Do not tamper with me!";
    kryptos_u8_t *key = "the worst and common way of using a user key.";
    kryptos_u8_t *p, *p_end;
    int exit_code = 0;

    printf("plaintext: '%s'\n", plaintext);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): You can set the additional authenticated data via kryptos_task_set_gcm_aad():
    //
    //                  kryptos_task_set_gcm_aad(ktask, aad_buf, aad_buf_size)
    //
    //               You can set the counter via kryptos_task_set_gcm_ctr():
    //
    //                  kryptos_task_set_gcm_ctr(ktask, &ctr_var)
    //
    //               You can set counter and add via kryptos_task_set_gcm_mode():
    //
    //                  kryptos_task_set_gcm_mode(ktask, &ctr_var, aad_buf, aad_buf_size)
    //

    kryptos_task_set_in(ktask, plaintext, strlen(plaintext));
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(aes256, ktask, key, strlen(key), kKryptosGCM);

    ktask->in = NULL;
    ktask->in_size = 0;

    if (!kryptos_last_task_succeed(ktask)) {
        if (ktask->result_verbose != NULL) {
            printf("ERROR: %s\n", ktask->result_verbose);
        } else {
            printf("ERROR: What?!\n");
        }
        exit_code = 1;
    } else {
        printf("ciphertext: '");

        p = ktask->out;
        p_end = p + ktask->out_size;

        while (p != p_end) {
            printf("%c", isprint(*p) ? *p : '.');
            p++;
        }

        printf("'\n");

        kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));
        ktask->out = NULL;
        ktask->out_size = 0;

        // TIP(Rafael): Try to tamper with ktask->in just by uncommenting the following line.
        //ktask->in[ktask->in_size >> 1] = ~ktask->in[ktask->in_size >> 1];

        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(aes256, ktask, key, strlen(key), kKryptosGCM);

        if (kryptos_last_task_succeed(ktask)) {
            printf("decrypted data: '");
            fwrite(ktask->out, 1, ktask->out_size, stdout);
            printf("'\n");
        } else {
            if (ktask->result == kKryptosGMACError && ktask->result_verbose != NULL) {
                printf("GMAC ERROR: %s\n", ktask->result_verbose);
            } else {
                printf("ERROR: %s\n", (ktask->result_verbose != NULL) ? ktask->result_verbose : "What?");
            }
            exit_code = 1;
        }
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);

    return exit_code;
}
```

For ciphers with no support for ``GCM``, if you need to provide authenticity, you should use ``HMACs`` (more on later).

Not all block ciphers only need a key, a size of this key and an operation mode. In kryptos we also have block ciphers
that need more than the standard parameters. In this case the additional parameters are always passed after the operation
mode and they must be pointers to the data. As sample, let's pick the cipher FEAL. The FEAL algorithm supports variable
rounds total.

When calling FEAL in kryptos the desired rounds total should be passed, in the following way (c99):

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
    int rounds = 80; /* Let's use FEAL with 80 rounds */
    int exit_code = 0;

    printf("Original data: %s\n", data);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Encrypting.
    kryptos_task_set_in(ktask, data, data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(feal, ktask, key, strlen(key), kKryptosCBC, &rounds);

    if (kryptos_last_task_succeed(ktask)) {
        printf("Encryption success!\n");
        // INFO(Rafael): Decrypting.
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(feal, ktask, key, strlen(key), kKryptosCBC, &rounds);
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

The **Table 3** lists the other ciphers which use additional parameters during their call.

**Table 3**: The additional parameters required by some implemented block ciphers.

| **Cipher** |              **Parameters**       |            **Parameters data type**                 |                                     **Call example**                                                 |
|:----------:|:---------------------------------:|----------------------------------------------------:|-----------------------------------------------------------------------------------------------------:|
|    RC2     |  T1 parameter                     |          ``int``                                    | ``kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosOFB, &rc2_t1)``                                   |
|    RC5     |  Rounds total                     |          ``int``                                    | ``kryptos_run_cipher(rc5, &task, "rc5", 3, kKryptosOFB, &rounds)``                                   |
|  RC6-128   |  Rounds total                     |          ``int``                                    | ``kryptos_run_cipher(rc6_128, &task, "rc6", 3, kKryptosOFB, &rounds)``                               |
|  RC6-192   |  Rounds total                     |          ``int``                                    | ``kryptos_run_cipher(rc6_192, &task, "rc6", 3, kKryptosOFB, &rounds)``                               |
|  RC6-256   |  Rounds total                     |          ``int``                                    | ``kryptos_run_cipher(rc6_256, &task, "rc6", 3, kKryptosOFB, &rounds)``                               |
| SAFER K-64 |  Rounds total                     |          ``int``                                    | ``kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosECB, &saferk64_rounds)``                |
|    3DES    |  Key2, Key2 size, Key3, Key3 size | ``unsigned char`` for keys and ``size_t`` for sizes | ``kryptos_run_cipher(triple_des, &task, k1, &k1_size, kKryptosECB, k2, &k2_size, k3, &k3_size)``     |
|  3DES-EDE  |  Key2, Key2 size, Key3, Key3 size | ``unsigned char`` for keys and ``size_t`` for sizes | ``kryptos_run_cipher(triple_des_ede, &task, k1, &k1_size, kKryptosECB, k2, &k2_size, k3, &k3_size)`` |
|    GOST    |  Eight custom s-boxes             |      ``unsigned char[16]``                          | ``kryptos_run_cipher(gost, &task, "gost", 4, kKryptosCBC, s1, s2, s3, s4, s5, s6, s7, s8)``          |

[Back](#contents)

### Hashes

Firstly I will show you how to generate hashes without using C macro conveniences, after we will generate hashes through
the available macro.

The **Table 4** lists the available hash algorithms.

**Table 4**: Currently available hash algorithms.

|  **Algorithm** |        **HASHID**                  |
|:--------------:|:----------------------------------:|
|   ``SHA-1``    |       ``sha1``                     |
|   ``SHA-224``  |       ``sha224``                   |
|   ``SHA-256``  |       ``sha256``                   |
|   ``SHA-384``  |       ``sha384``                   |
|   ``SHA-512``  |       ``sha512``                   |
|   ``SHA3-224`` |       ``sha3_224``                 |
|   ``SHA3-256`` |       ``sha3_256``                 |
|   ``SHA3-384`` |       ``sha3_384``                 |
|   ``SHA3-512`` |       ``sha3_512``                 |
|  ``KECCAK-224``|       ``keccak224``                |
|  ``KECCAK-256``|       ``keccak256``                |
|  ``KECCAK-384``|       ``keccak384``                |
|  ``KECCAK-512``|       ``keccak512``                |
|    ``MD4``     |       ``md4``                      |
|    ``MD5``     |       ``md5``                      |
| ``RIPEMD-128`` |      ``ripemd128``                 |
| ``RIPEMD-160`` |      ``ripemd160``                 |
| ``TIGER``      |      ``tiger``                     |
| ``WHIRLPOOL``  |      ``whirlpool``                 |
| ``Blake2s256`` |      ``blake2s256``                |
| ``Blake2b512`` |      ``blake2b512``                |
| ``Blake2sN``   |      ``blake2sN``                  |
| ``Blake2bN``   |      ``blake2bN``                  |
| ``Blake3``     |      ``blake3``                    |

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

According to the presented sample, you should define the input and its size in bytes in a ``kryptos_task_ctx`` struct.
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

The hash algorithm Blake2 supports a keyed hash. The following sample shows how to generate keyed hashes with Blake2 in
``kryptos``:

```c
/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *write_in_c = "When I find my code in tons of trouble,\n"
                               "Friends and colleagues come to me,\n"
                               "Speaking words of wisdom:\n"
                               "Write in C.\n\n"
                               " -- Write in C(\"Let it Be\")\n";

    kryptos_task_init_as_null(ktask);

    kryptos_hash(blake2b512, ktask, write_in_c, strlen(write_in_c), 1);

    printf("Unkeyed hash: %s\n", ktask->out);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->key = "John Paul Ritchie";
    ktask->key_size = strlen(ktask->key);

    kryptos_hash(blake2b512, ktask, write_in_c, strlen(write_in_c), 1);

    printf("Keyed hash:   %s\n", ktask->out);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return 0;
}
```

The hash algorithm ``Blake2s`` and ``Blake2b`` supports variable hash sizes from 8 up to 256 and 512 bits respectively. The
following code shows the way of using those variable versions in ``kryptos``:

```c
/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *bp, *bp_end;

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): You can call blake2bN and blake2sN through the kryptos_hash macro.
    //               You must specify the hash size (in bytes) by using the out_size field from kryptos_task_ctx.

    ktask->out_size = 28;
    kryptos_hash(blake2sN, ktask, "Lenny", 5, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: when trying to compute blake2s224.\n");
        goto epilogue;
    }

    printf("Blake2s224: %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->out_size = 48;
    kryptos_hash(blake2bN, ktask, "Lenny", 5, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: when trying to compute blake2b384.\n");
        goto epilogue;
    }

    printf("Blake2b384: %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): Keyed hash are the same of implementations of blake with fixed output size.

    ktask->key = "Blake2s";
    ktask->key_size = 7;
    ktask->out_size = 28;
    kryptos_hash(blake2sN, ktask, "Lenny", 5, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: when trying to compute blake2s224.\n");
        goto epilogue;
    }

    printf("Blake2s224 (Keyed): %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->key = "Blake2b";
    ktask->key_size = 7;
    ktask->out_size = 48;
    kryptos_hash(blake2bN, ktask, "Lenny", 5, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: when trying to compute blake2b384.\n");
        goto epilogue;
    }

    printf("Blake2b384 (Keyed): %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return 0;
}
```

The algorithm Blake3 besides supporting flat hash, keyed hash, it also ships a ``KDF`` mode that can be used by
calling ``kryptos_blake3`` as follows:

```c
/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TEST_STR "Entre os animais ferozes, o de mais perigosa mordedura eh o delator;"\
                 "entre os animais domesticos, o adulador."

#define KEY_STR "DiogenesDeSinopeDiogenesDeSinope"

int main(void) {
    kryptos_task_ctx t, *ktask = &t;
    int err = EXIT_SUCCESS;
    kryptos_u8_t *derived_key = NULL;
    size_t derived_key_size = 0;
    kryptos_u8_t *d = NULL, *d_end = NULL;

    kryptos_task_init_as_null(ktask);

    kryptos_hash(blake3, ktask, (kryptos_u8_t *)TEST_STR, strlen(TEST_STR), 1);

    if (!kryptos_last_task_succeed(ktask)) {
        err = EXIT_FAILURE;
        fprintf(stderr, "error: while computing hash : detail : '%s'\n",
            (ktask->result_verbose != NULL) ? ktask->result_verbose : "no details.");
        goto epilogue;
    }

    fprintf(stdout, "BLAKE3 on hash mode = %s\n", ktask->out);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->key = (kryptos_u8_t *)KEY_STR;
    ktask->key_size = 32;

    kryptos_hash(blake3, ktask, (kryptos_u8_t *)TEST_STR, strlen(TEST_STR), 1);

    if (!kryptos_last_task_succeed(ktask)) {
        err = EXIT_FAILURE;
        fprintf(stderr, "error: while computing hash : detail : '%s'\n",
            (ktask->result_verbose != NULL) ? ktask->result_verbose : "no details.");
        goto epilogue;
    }

    fprintf(stdout, "BLAKE3 on keyed-hash mode = %s\n", ktask->out);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    derived_key_size = 32;
    derived_key = kryptos_blake3(TEST_STR, strlen(TEST_STR), KEY_STR, 32, derived_key_size);

    if (derived_key == NULL) {
        err = EXIT_FAILURE;
        fprintf(stderr, "error: while deriving key.\n");
        goto epilogue;
    }

    fprintf(stdout, "BLAKE3 as a general KDF (on derive-key mode) = ");

    d = derived_key;
    d_end = d + derived_key_size;
    while (d != d_end) {
        fprintf(stdout, "%.2X", *d);
        d++;
    }
    fprintf(stdout, "\n");
    d = d_end = NULL;

epilogue:

    if (derived_key != NULL) {
        kryptos_freeseg(derived_key, derived_key_size);
    }

    derived_key_size = 0;

    kryptos_task_init_as_null(ktask);

    return err;
}
```

Notice that ``kryptos_blake3`` is the key derivation of Blake3, the hash function (that can be keyed or not) is
accessed by calling ``kryptos_blake3_hash`` or using ``kryptos_hash`` function macro.

[Back](#contents)

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
[Back](#contents)

### Poly1305

If the necessity of a hash function for your requirements is a bit overkill or even you find the overhead added
by HMACs is not an option for your setup, an alternative can be Poly1305.

This MAC is based only in mathematical operations over 130-bit (approximately) values. The idea is quite similar of you
find in Galois Counter Mode from block ciphers, for example (but Poly can be more intensive in terms of computation). Here on
``kryptos`` Poly1305 was implemented by using a dedicated multiprecision support functions subset. Those functions do
not use heap memory to make the things happen, in this way much overhead from all demanded multiprecision operations are
eliminated or at least mitigated. Since ``kryptos`` has as requirement the possibility of working on kernel-side of some
operating systems, this care also makes easy the use of Poly1305 into the supported kernels in a very constant, clean and
well-contained and portable way (I meant, from an OS to other and also from a compiler to other).

On ``kryptos`` you can use Poly1305 as a flat MAC. I meant it does not care if the data is about a plaintext or a
ciphertext. Let's call it "bare bone Poly".

```c
/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_u8_t *message = "\"I don't know why people are so keen to put the details of "
                            "their private life in public; they forget that invisibility "
                            "is a superpower.\" (Banksy)", *mp, *mp_end;
    size_t message_size = strlen(message);
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "123mudar*";

    kryptos_task_init_as_null(ktask);

    ktask->key = key;
    ktask->key_size = strlen(key);

    printf("Original message: %s\n\n", message);

    ktask->out = (kryptos_u8_t *)kryptos_newseg(message_size);
    if (ktask->out == NULL) {
        printf("Error: Not enough memory.\n");
        return 1;
    }

    memcpy(ktask->out, message, message_size);
    ktask->out_size = message_size;
    kryptos_task_set_encrypt_action(ktask);

    kryptos_poly1305(&ktask);

    if (kryptos_last_task_succeed(ktask)) {
        mp = ktask->out;
        mp_end = mp + ktask->out_size;
        printf("MAC + nonce + message: ");
        while (mp != mp_end) {
            printf("%c", isprint(*mp) ? *mp : '.');
            mp++;
        }
        printf("\n\n");

        // INFO(Rafael): Wrong key will not authenticate.
        //ktask->key = "321mudei*";
        //ktask->key_size = strlen(ktask->key);

        // INFO(Rafael): Incomplete key will not authenticate.
        //ktask->key_size -= 1;

        kryptos_task_set_decrypt_action(ktask);
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        ktask->out = NULL;
        ktask->out_size = 0;

        // INFO(Rafael): Corrupted mac will not authenticate.
        //ktask->in[0] += 1;

        // INFO(Rafael): Corrupted message will not authenticate.
        //ktask->in[ktask->in_size >> 1] += 1;

        // INFO(Rafael): Incomplete message will not authenticate.
        //ktask->in_size -= 1;

        kryptos_poly1305(&ktask);

        if (kryptos_last_task_succeed(ktask)) {
            printf("Authenticated message: ");
            fwrite(ktask->in, 1, ktask->in_size, stdout);
            printf("\n");
        } else {
            printf("Error: %s\n", ktask->result_verbose);
        }
    } else {
        printf("Unexpected error: '%s'\n", ktask->result_verbose);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    return 0;
}
```

Poly1305 primitive needs a message and a key. Here on ``kryptos`` you set those information in ``kryptos_task_ctx``
passed to ``kryptos_poly1305()`` function.

Since Poly1305 is about a MAC it is suitable to tag outputs produced by a prior task processing. Due to it, when you
need to generate a mac (or tag a message), you need to set this data into output buffer of the ``kryptos_task_ctx``.
Once it done, you just need to set task action to ``encrypt`` and call ``kryptos_poly1305()``.
Your tag and nonce will be added to your previous output (**it will free the prior allocation and copy everything into
a new memory segment**).

In order to verify a tagged message you will need to set this data into ``kryptos_task_ctx`` input buffer, also set
the key information and the task action to ``decrypt``. Once it done, call ``kryptos_poly1305()`` function and
if the message was authenticated, the original message was extracted from the tagged buffer and reallocated into
the input buffer of passed the ``kryptos_task_ctx``.

Notice that here in this "bare-bone" sample the message buffer is not protected before being tagged but it is also
possible to do that.

If you have ``C99`` capabilities on your environment you can use the convenience that ships Poly1305 and
(encryption,tagging)/(verification,decryption) in an almost "automagic" way. Take a look:

```c
/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
#if defined(KRYPTOS_C99)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *plaintext = "Nao e possivel ser bom pela metade (Liev Tolstoi)";
    size_t plaintext_size = strlen(plaintext);
    kryptos_u8_t *weak_key = "1234n41v3";
    size_t weak_key_size = strlen(weak_key);
    kryptos_u8_t *p, *p_end;

    printf("Plaintext: '%s'\n", plaintext);

    kryptos_task_init_as_null(ktask);
    kryptos_task_set_in(ktask, plaintext, plaintext_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher_poly1305(aes128, ktask, weak_key, weak_key_size, kKryptosCBC);

    if (kryptos_last_task_succeed(ktask)) {
        p = ktask->out;
        p_end = p + ktask->out_size;
        printf("Authenticated ciphertext: ");
        while (p != p_end) {
            printf("%c", isprint(*p) ? *p : '.');
            p++;
        }
        printf("\n");
        // INFO(Rafael): Try to uncomment the following line.
        //ktask->out[ktask->out_size >> 1] += 1;
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        // INFO(Rafael): Try to uncomment the following line and comment the next one.
        //kryptos_run_cipher_poly1305(aes128, ktask, "wr0ngk3y", strlen("wr0ngk3y"), kKryptosCBC);
        kryptos_run_cipher_poly1305(aes128, ktask, weak_key, weak_key_size, kKryptosCBC);
        if (kryptos_last_task_succeed(ktask)) {
            printf("Decrypted authenticated data: '");
            fwrite(ktask->out, 1, ktask->out_size, stdout);
            printf("'\n");
            kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        } else {
            printf("Decryption error: %s\n", ktask->result_verbose);
        }
    }
#else
    printf("WARNING: libkryptos was compiled without C99 support.\n");
    return EXIT_FAILURE;
#endif
}
```

The macro ``kryptos_run_cipher_poly1305`` is able to ``encrypt and tag`` or ``verify and decrypt``. The parameters are:

- The cipher name;
- The task context;
- The key;
- The key size in bytes;
- The operation mode (if it is about a block cipher);
- Specific cipher argument(s) (if it has one(s));

All you should do before calling ``kryptos_run_cipher_poly1305`` is to set up the input, the action (if it is about a
encryption or decryption) and go.

If some error has occurred the ``result`` field of the passed ``kryptos_task_ctx`` will be different from ``kKryptosSuccess``.
It will be equals to ``kKryptosPoly1305Error`` if some error has occurred when doing some Poly1305 processing and in this
case the details will be explained by the field ``result_verbose`` from the passed ``kryptos_task_ctx``.

The ``kryptos_run_cipher_poly1305`` function macro when validating data, it changes its allocation by adding or removing
the tag. So, when encrypting it changes the output from the task context, when decrypting it changes the input from the
task context. So, depending on your task action you need to take care on freeing the related buffer.

You can pass 256-bit keys without minding about nonce re-use issues. We always make a random nonce at this macro.
Keys greater than 256-bits are "compressed" by xoring what exceeds with the effective supported 32 bytes. Anyway,
personally I would not use Poly1305 with algorithms that require keys greater than 256-bit. It was designed
thinking about 256-bit keys as its limit.

Okay, I know: how can you could use Poly1305 with ChaCha20? Well, pretty easy, look:

```c
    #include <kryptos.h>

    (...)

    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *user_key = "5h33p 54mpl3, m33333333!!!!!!!!!";
    size_t user_key_size = 32;

    (...)

    kryptos_task_init_as_null(ktask);

    (...)

    // Passing null here it will ask a random nonce also in chacha20
    kryptos_run_cipher_poly1305(chacha20, ktask, user_key, user_key_size, NULL);
```

**Remembering that all key material passed to an encryption algorithm must come from a KDF processing not from a
na�ve hardcoded buffer (All code shown here is just about quick samples. Using modern crypto professionally into
computer programs is a thing that goes much beyond from those flat examples. Do not grasp into those practices
as correct, please)**.

[Back](#contents)

### SipHash

The ``PRF`` SipHash is available in ``libkryptos``, too. In order to use it with your hash table
solution call the function ``kryptos_siphash_sum``. It takes:

- The data to be hashed.
- The size (in bytes) of this data.
- A key.
- The size (in bytes) of this key.
- The rounds parameter required by Siphash, c and d respectively.

The function ``kryptos_siphash_sum`` returns the a 64-bit value which stands for the hash of
the passed data using the passed key and rounds parameters.

```c
/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

#define SIPHASH_SAMPLE_KEY "Lazy-people-that-dislike-reading: it-s-not-crypto-hash. Be careful!!!"

int main(int argc, char **argv) {
    int exit_code = EXIT_FAILURE;
    if (argc == 1) {
        printf("use: %s <data>\n", argv[0]);
    } else {
        printf("%llx\n", kryptos_siphash_sum((kryptos_u8_t *)argv[1], strlen(argv[1]),
                                             (kryptos_u8_t *)SIPHASH_SAMPLE_KEY,
                                             strlen(SIPHASH_SAMPLE_KEY), 4, 2));
        exit_code = EXIT_SUCCESS;
    }
    return exit_code;
}

#undef SIPHASH_SAMPLE_KEY
```

``SipHash`` can also be used as a ``MAC``. It is more suitable for short messages. In order
to use this ``PRF`` as a ready-to-go ``MAC`` with ``libkryptos`` call the function macro
``kryptos_run_cipher_siphash``.

It will (encrypt,tag) or (verify,decrypt) depending on the passed action. The function
macro requires the following parameters:

- The name of the symmetric encryption primitive.
- The ``SipHash`` round parameters, c and d, respectively.
- The ``kryptos_task_ctx`` context which express/gather data for your intended task.
- The remaining parameters required by the chosen encryption primitive.

For more details, take a look at the example below:

```c
/*
 *                                Copyright (C) 2022 by Rafael Santiago
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

#define MESSAGE "Two headed dog, two headed dog, "
                "I've been working in the Kremlin with two-headed dog."

int main(int argc, char **argv) {
    int exit_code = EXIT_FAILURE;
#if defined(KRYPTOS_C99)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *bad_hardcoded_key = (kryptos_u8_t *)"Red Temple Prayer";
    size_t bad_hardcoded_key_size = strlen((char *)bad_hardcoded_key);
    kryptos_u8_t *p = NULL, *p_end = NULL;

    kryptos_task_init_as_null(ktask);
    kryptos_task_set_in(ktask, (kryptos_u8_t *)MESSAGE, strlen(MESSAGE));
    printf("Message to authenticate and send: '%s'\n", ktask->in);

    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher_siphash(aes256, 8, 4, ktask,
                               bad_hardcoded_key, bad_hardcoded_key_size, kKryptosOFB);

    if (kryptos_last_task_succeed(ktask)) {
        p = ktask->out;
        p_end = p + ktask->out_size;
        printf("Message with authentication code: ");
        while (p != p_end) {
            printf("%c", isprint(*p) ? *p : '.');
            p++;
        }
        printf("\n");
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        ktask->out = NULL;
        ktask->out_size = 0;
        kryptos_task_set_decrypt_action(ktask);
        // INFO(Rafael): Try to comment one of the following lines or even both.
        // bad_hardcoded_key_size <<= 1;
        // ktask->in[ktask->in_size >> 1] += 1;
        kryptos_run_cipher_siphash(aes256, 8, 4, ktask,
                                   bad_hardcoded_key, bad_hardcoded_key_size, kKryptosOFB);
        if (kryptos_last_task_succeed(ktask)) {
            p = ktask->out;
            p_end = p + ktask->out_size;
            printf("Authenticated plaintext: ");
            while (p != p_end) {
                printf("%c", isprint(*p) ? *p : '.');
                p++;
            }
            printf("\n");
        } else {
            printf("error: '%s'\n", (ktask->result_verbose != NULL) ?
                                        ktask->result_verbose : "Unexpected.");
        }
    } else {
        kryptos_task_set_in(ktask, NULL, 0);
        printf("error: '%s'\n", (ktask->result_verbose != NULL) ?
                                        ktask->result_verbose : "Unexpected.");
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
#else
    printf("warning: libkryptos was compiled without c99 support.");
#endif
    return exit_code;
}

#undef MESSAGE
```

When verifying, ``kryptos_run_cipher_siphash`` will re-allocate memory passed as the input of
your verification/decryption task, thus, in a well-succeeded context, the input address will
change and you do not have to mind about free the old address (because it was freed already).

[Back](#contents)

### Incremental input reading

``Kryptos`` does not implement incremental hashing as another libraries. Now you need to have
every bytes that you want to hash in memory. Anyway, it is possible to emulate the incremental
idea. By combining ``kryptos_hash_init``, ``kryptos_hash_update`` and ``kryptos_hash_finalize``.
Take a look:

```c
/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *alpha = (kryptos_u8_t *)"abcdefghijklmnopqrstuvwxyz";
    kryptos_hash_init(sha3_512, ktask);
    while (*alpha != 0) {
        kryptos_hash_update(ktask, alpha, 2);
        alpha += 2;
    }
    kryptos_hash_finalize(ktask, 1);
    printf("SHA3-512 hex result = %s\n", ktask->out);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    return EXIT_SUCCESS;
}
```

So it is just about informing ``kryptos`` what hash primitive you are intending to use through ``kryptos_hash_init``.
After that to pass the incremental input bytes by specifying how many byte there are currently into this buffer by
using ``kryptos_hash_update``. Once all bytes passed it is just about calling ``kryptos_hash_finalize``.

The second parameter of macro ``kryptos_hash_finalize`` is about hexadecimal output requesting. When a binary output
is wanted just pass zero on it.

For hash primitives that support variable size hashes and/or keyed hashing, you must configure those parameters
before calling the finalization macro. I meant set ``out_size`` and/or ``key`` and ``key_size`` fields from the
related task context.

[Back](#contents)

## Asymmetric stuff

Until now the ``Diffie-Hellman-Merkle`` key exchange scheme and the algorithms ``RSA`` and ``Elgamal`` are available.
For digital signature the library includes ``RSA`` (basic scheme), ``RSA-EMSA-PSS`` and the widely used ``DSA``, also
its elliptic curve version, ``ECDSA`` is available.

Firstly let's discuss the ``DHKE`` and after the other stuff.

[Back](#contents)

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
avoids the necessity of driving the process with different functions or a more specific code.

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
        kryptos_freeseg(k_pub_bob, k_pub_bob_size);
    }

    if (k_priv_bob != NULL) {
        kryptos_freeseg(k_priv_bob, k_priv_bob_size);
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

        kryptos_freeseg(params, params_size);
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

Once generated the parameters can be used instead of the standarnized MODP values. Of course, use p=160 bits and q=80 is
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
        kryptos_freeseg(k_pub_bob, k_pub_bob_size);
    }

    if (k_priv_bob != NULL) {
        kryptos_freeseg(k_priv_bob, k_priv_bob_size);
    }

    k_priv_bob_size = k_pub_bob_size = 0;

    return exit_code;
}
```

The function ``kryptos_dh_get_modp_from_params_buf()`` accepts a NULL Q parameter. You must pass it as NULL when your domain
parameter buffer does not contain the Q parameter. However, be aware that a ``PEM`` buffer containing only P and G parameters
implies in an unverified domain parameters buffer. The verifying function cannot ascertain anything without Q.
Due to it, you may be using small groups on your DHKE stuff. Maybe who have generated the used P and G values was naive or
malicious. Accept domain parameters like these at your own risk.

All stuff shown until now related to DHKE is based on discrete logarithm problem. ``Kryptos`` also counts with an
implementation of ``Diffie-Hellman-Merkle`` that uses elliptic curves. The following is a well simple sample of how to use
ECDH in ``kryptos``:

```c
/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    // WARN: Never send out the exchange parameters without signing the data.
    //       This is just a simplified sample.
    struct kryptos_ecdh_xchg_ctx alice_ctx, bob_ctx, *alice = &alice_ctx, *bob = &bob_ctx;
    int exit_code = 0;

    kryptos_ecdh_init_xchg_ctx(alice);
    kryptos_ecdh_init_xchg_ctx(bob);

    // INFO: We will use the standard curve named BrainpoolP160R1.
    //       Take a look at the enum kryptos_curve_id_t in kryptos_types.h to know more
    //       available curves.
    alice->curve = kryptos_new_standard_curve(kBrainPoolP160R1);

    if (alice->curve == NULL) {
        printf("ERROR: when trying to load BrainpoolP160R1 curve.\n");
        exit_code = 1;
        goto epilogue;
    }

    // INFO: Alice's first step.

    kryptos_ecdh_process_xchg(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: during ECDH processing (Alice's side).\n");
        exit_code = 1;
        goto epilogue;
    }

    // WARN: Again, it would be signed before has sent.

    bob->in = alice->out;
    bob->in_size = alice->out_size;

    alice->out = NULL;

    // INFO: Bob's only step.

    kryptos_ecdh_process_xchg(&bob);

    if (!kryptos_last_task_succeed(bob)) {
        printf("ERROR: during ECDH processing (Bob's side).\n");
        exit_code = 1;
        goto epilogue;
    }

    // WARN: Again, it would be signed before has sent.

    alice->in = bob->out;
    alice->in_size = bob->out_size;

    bob->out = NULL;

    // INFO: Alice's final step.

    kryptos_ecdh_process_xchg(&alice);

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: during ECDH processing (Alice's side, last step).\n");
        exit_code = 1;
        goto epilogue;
    }

    if (kryptos_mp_eq(alice->k, bob->k)) {
        printf("INFO: Alice and Bob have agreed a session key.\n");
        printf("      Key from Alice's context = "); kryptos_print_mp(alice->k);
        printf("      Key from Bob's context   = "); kryptos_print_mp(bob->k);
    } else {
        printf("ERROR: key agreement has failed.\n");
        exit_code = 1;
    }

epilogue:

    kryptos_clear_ecdh_xchg_ctx(alice);
    kryptos_clear_ecdh_xchg_ctx(bob);

    return exit_code;
}
```

Well, I think that we have done with DHKE. For awhile let's forget a little about it and dive into RSA available stuff...

[Back](#contents)

### RSA

The best way of introducing the usage of ``RSA`` in kryptos is by showing you how to generate the key pair.

Well, the following code shows you the way:

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
        kryptos_freeseg(k_priv, k_priv_size);
    }

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub, k_pub_size);
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

The function ``kryptos_rsa_mk_key_pair()`` does the job. It receives the key size (in bits), a (kryptos_u8_t **) for
the public key buffer, a pointer to store the public key size, a (kryptos_u8_t **) for the private key buffer, a
pointer to store the private key size. If the function succeeds it returns ``kKryptosSuccess``. Once generated
all you should do is store the output data in somewhere for later usage. Free the key pair data when not necessary
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

Thus, the ``RSA OAEP`` should receive the key and its size and also a label and the size of this label and a pointer to a hash
function and a pointer to a hash function size.

In kryptos any available hash function is named by using this format: ``kryptos_<HASHID>_hash``.

The hash size function is named by using this format: ``kryptos_<HASHID>_hash_size``.

The ``HASHID`` can be found in **Table 4**.

The macro ``kryptos_oaep_hash()`` is a way of making easier the function parameters passing. All you should do with
this macro is to pass the ``HASHID`` of the desired hash algorithm for the OAEP stuff.

Then now with those tips I hope that the following code snippet becomes clearer to you:

```c
    kryptos_run_cipher(rsa_oaep, bob, k_priv_bob, strlen(k_priv_bob), label, &label_size,
                       kryptos_oaep_hash(sha1));
```

[Back](#contents)

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
        kryptos_freeseg(k_pub, k_pub_size);
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv, k_priv_size);
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

In order to generate the sample key pair used in Elgamal stuff here. I used the following command line:

```
MsHudson@221B:~/src/kryptos-test/src/samples# ../../samples/elgamal-mk-key-pair-sample 1024 160
```

It took me about 90/91 minutes in a SMP 32-bit environment.

According to the code shown above, it uses the function ``kryptos_elgamal_mk_key_pair()`` to generate
the Elgamal key pair. The arguments are: the P parameter size, the Q parameter size, a pointer to the public buffer,
a pointer to store the size of the public buffer, a pointer to the private buffer and a pointer to store the size of the
private buffer. When the function succeeds it returns ``kKryptosSuccess``.

For brevity, I will show you only the ``c99`` applications of the Elgamal in kryptos. The ``raw`` usage mode without ``c99``
conveniences is similar to ``RSA``, I find you can figure it out by yourself easily. Thus, this is the way of using the Elgamal
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

[Back](#contents)

### Digital signature

Until now three digital signature algorithms are implemented: ``RSA``, ``DSA`` and ``ECDSA``. The three implementions are
a general way of signing data so the details about the sign protocol is up to you. Maybe you want to encrypt
and then sign or just signing, it depends on your requirements. Due to it, the sign process only focuses in ascertain
if the input is authenticated or not. When the verification process fails the output buffer from the task will be
NULL and the task result will be equal to ``kKryptosInvalidSignature``. When the verification succeeds the output
buffer will contain the authenticated data and so you can process this verified output as you intend. The output
buffer when not NULL should be freed.

[Back](#contents)

#### RSA

Firstly I will show you the way of signing an input buffer with the standard RSA sign algorithm without ``C99`` conveniences.
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
code sample does the same job but it uses ``c99``:

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

Similarly, the ``kryptos_verify()`` expects the signature algorithm name, a pointer to the task context, the signed buffer and
its size, the public key buffer and its size.

The ``RSA`` signature tends to be time consuming depending on the size of the input and, of course, the modulus. There is also
a trick that can speed up the verification process and it can be achieved by choosing a small public key factor,
however, it is out of scope of the manual. You can also hash the input before signing. Moreover it is about generic tricks.

The standard RSA digital signature is weak. The best practice to avoid some flaws present in the standard way is by padding the
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

[Back](#contents)

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
        kryptos_freeseg(k_pub, k_pub_size);
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv, k_priv_size);
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

The way of using ``DSA`` without ``c99`` conveniences is almost the same way shown in ``RSA``, due to it, for brevity, from
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

[Back](#contents)

## ECDSA

The algorithm ``ECDSA`` is the elliptic curve version of the standard ``DSA``. ``ECDSA`` also needs to a key pair calculation
before signing and verifying stuff. The following code shows how to generate a ``ECDSA`` key pair:

```c
/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL;
    size_t k_pub_size, k_priv_size;
    kryptos_curve_ctx *curve = NULL;
    int exit_code = 0;

    if ((curve = kryptos_new_standard_curve(kBrainPoolP160R1)) == NULL) {
        printf("ERROR: on curve data loading.\n");
        exit_code = 1;
        goto epilogue;
    }

    if (kryptos_ecdsa_mk_key_pair(curve,
                                  &k_pub, &k_pub_size, &k_priv, &k_priv_size) != kKryptosSuccess) {
        printf("ERROR: on key pair calculation.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("*** PUBLIC KEY:\n\n%s\n*** PRIVATE KEY:\n\n%s\n", k_pub, k_priv);

epilogue:

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub, k_pub_size);
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv, k_priv_size);
    }

    if (curve != NULL) {
        kryptos_del_curve_ctx(curve);
    }

    return exit_code;
}
```

The code below brings a general idea of how sign and verify data by using ``ECDSA`` and ``Kryptos C99`` conveniences:

```c
/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(void) {
    int exit_code = 0;
    kryptos_u8_t *k_pub = "-----BEGIN ECDSA P-----\n"
                          "D2IVlRPYs5Wtx99g3Flwc19KXuk=\n"
                          "-----END ECDSA P-----\n"
                          "-----BEGIN ECDSA A-----\n"
                          "AMP36JdddNq6Yb7idOuAouJ7DjQ=\n"
                          "-----END ECDSA A-----\n"
                          "-----BEGIN ECDSA B-----\n"
                          "WF5n2MiV7L0tqk8TEjRClYWaWB4=\n"
                          "-----END ECDSA B-----\n"
                          "-----BEGIN ECDSA Q-----\n"
                          "CfxgnkApUNSRWd9g3Flwc19KXuk=\n"
                          "-----END ECDSA Q-----\n"
                          "-----BEGIN ECDSA A X-----\n"
                          "w9u8vfda6zFGjJNiT2o/6hav1b4=\n"
                          "-----END ECDSA A X-----\n"
                          "-----BEGIN ECDSA A Y-----\n"
                          "IWPaFmOXnGZBR/k4w44aekfLZxY=\n"
                          "-----END ECDSA A Y-----\n"
                          "-----BEGIN ECDSA B X-----\n"
                          "C9yDV1KdKboG3FLz2hkjuxc6eHk=\n"
                          "-----END ECDSA B X-----\n"
                          "-----BEGIN ECDSA B Y-----\n"
                          "o2LrZwgxAjDmOYoV6d+BotCbuuE=\n"
                          "-----END ECDSA B Y-----\n";
    kryptos_u8_t *k_priv = "-----BEGIN ECDSA D-----\n"
                           "7DukDiEY0PFh2MuVORfJkudyJqE=\n"
                           "-----END ECDSA D-----\n"
                           "-----BEGIN ECDSA P-----\n"
                           "D2IVlRPYs5Wtx99g3Flwc19KXuk=\n"
                           "-----END ECDSA P-----\n"
                           "-----BEGIN ECDSA A-----\n"
                           "AMP36JdddNq6Yb7idOuAouJ7DjQ=\n"
                           "-----END ECDSA A-----\n"
                           "-----BEGIN ECDSA B-----\n"
                           "WF5n2MiV7L0tqk8TEjRClYWaWB4=\n"
                           "-----END ECDSA B-----\n"
                           "-----BEGIN ECDSA Q-----\n"
                           "CfxgnkApUNSRWd9g3Flwc19KXuk=\n"
                           "-----END ECDSA Q-----\n"
                           "-----BEGIN ECDSA A X-----\n"
                           "w9u8vfda6zFGjJNiT2o/6hav1b4=\n"
                           "-----END ECDSA A X-----\n"
                           "-----BEGIN ECDSA A Y-----\n"
                           "IWPaFmOXnGZBR/k4w44aekfLZxY=\n"
                           "-----END ECDSA A Y-----\n";
    kryptos_task_ctx a_ctx, b_ctx, *alice = &a_ctx, *bob = &b_ctx;
    kryptos_u8_t *message = "Never ever hardcode keys Bob!";

    kryptos_task_init_as_null(alice);
    kryptos_task_init_as_null(bob);

    printf("ORIGINAL MESSAGE:\n\n'%s'\n\n", message);

    // INFO(Rafael): Alice signs the message and sends it to Bob...

    kryptos_sign(ecdsa, alice, message, strlen(message),
                 k_priv, strlen(k_priv), kryptos_ecdsa_hash(sha3_512));

    if (!kryptos_last_task_succeed(alice)) {
        printf("ERROR: when signing the input.\n");
        exit_code = 1;
        goto epilogue;
    }

    printf("SIGNED MESSAGE:\n\n%s\n\n", alice->out);

    // INFO(Rafael): ... Now Bob verifies the authenticity of it...

    kryptos_verify(ecdsa, bob, alice->out, alice->out_size,
                   k_pub, strlen(k_pub), kryptos_ecdsa_hash(sha3_512));

    if (!kryptos_last_task_succeed(bob)) {
        if (bob->result == kKryptosInvalidSignature) {
            // INFO(Rafael): Try to corrupt some parameter in the alice->out PEM buffer and you
            //               will fall into this branch.
            printf("SIGNATURE ERROR: %s\n", bob->result_verbose);
        } else {
            printf("GENERAL ERROR: when verifying signature.\n");
        }
    }

    printf("AUTHENTICATED MESSAGE:\n\n'");
    fwrite(bob->out, 1, bob->out_size, stdout);
    printf("'\n\n");

epilogue:

    kryptos_task_free(alice, KRYPTOS_TASK_OUT);
    kryptos_task_free(bob, KRYPTOS_TASK_OUT);

    return exit_code;
}
```

[Back](#contents)

## Secondary stuff

Besides the cryptographic tasks, ``kryptos`` also has some secondary stuff such as encoding, compression and data exporting
functionalities. In the following section we will discuss them a little.

[Back](#contents)

### Encoding algorithms

Until now are available two encoding algorithms: ``Base64``, ``Base32``, ``Base16`` and ``UUEncode``.

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

[Back](#contents)

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
        kryptos_freeseg(deflated_data, deflated_data_size);
    }

    if (inflated_data != NULL) {
        kryptos_freeseg(inflated_data, inflated_data_size);
    }

    return exit_code;
}
```

[Back](#contents)

### Handling PEM buffers

The export format used in kryptos is ``PEM``. In order to handle this type of data, kryptos exposes three functions. A function
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
        kryptos_freeseg(pem_buffer, pem_buffer_size);
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
        kryptos_freeseg(second, second_size);
    }

    if (first != NULL) {
        kryptos_freeseg(first, first_size);
    }

    return exit_code;
}
```

The third ``PEM`` buffer function is intended for reading multiprecision data. The following code does the job:

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
topic for a final user manual. For more details try the technical documentation intended for contributors besides
reading the library's code.

[Back](#contents)

### CSPRNG

By default kryptos uses the native CSPRNG but the library also features a Fortuna implementation.

The usage of fortuna is pretty straightforward. It is possible to use it just by changing the kryptos CSPRNG,
with the following statement:

```c
if (!kryptos_set_csprng(kKryptosCSPRNGFortuna)) {
    printf("ERROR: the CSPRNG was not switched!\n");
}
```

If you want to switch back to the native CSPRNG:

```c
if (!kryptos_set_csprng(kKryptosCSPRNGSystem)) {
    printf("ERROR: the CSPRNG was not switched!\n");
}
```

Maybe your requirements demands the usage of several random pools besides managing the reseed of it. Kryptos does not
create seed files, it is up to you if you want to. The library only gives you access to the current seed, you do what
you want with it:

```c
/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>

int main(int argc, char **argv) {
    struct kryptos_fortuna_ctx *fortuna;
    kryptos_u8_t *block, *bp, *bp_end;
    size_t block_size;
    int error = 0;

    // INFO(Rafael): When passing 1 it signales kryptos to alloc a new context,
    //               instead of using a static one.
    fortuna = kryptos_fortuna_init(1);

    if (fortuna != NULL) {

        if (kryptos_fortuna_reseed(fortuna, "fortes fortuna adiuvat", 22)) {
            block_size = 16;
            block = kryptos_fortuna_get_random_block(fortuna, block_size);
            if (block != NULL) {
                bp = block;
                bp_end = bp + block_size;

                printf("Random 128-bit block from external generator: ");

                while (bp != bp_end) {
                    printf("%c", isprint(*bp) ? *bp : '.');
                    bp++;
                }

                printf("\n");

                kryptos_freeseg(block, block_size);

                // INFO(Rafael): You should save it somewhere, if you want to restore
                //               the CSPRNG state later.

                printf("Current seed from external generator: 0x");
                bp = fortuna->seed;
                bp_end = bp + fortuna->seed_size;

                while (bp != bp_end) {
                    printf("%.2X", *bp);
                    bp++;
                }

                printf("\n");

                // INFO(Rafael): Now let's switch the internal kryptos CSPRNG to Fortuna.

                if (kryptos_set_csprng(kKryptosCSPRNGFortuna)) {

                    // INFO(Rafael): Notice that we call 'kryptos_get_random_block' instead of
                    //               'kryptos_fortuna_get_random_block'.
                    block = kryptos_get_random_block(block_size);
                    if (block != NULL) {
                        bp = block;
                        bp_end = bp + block_size;

                        printf("Random 128-bit block from internal generator: ");

                        while (bp != bp_end) {
                            printf("%c", isprint(*bp) ? *bp : '.');
                            bp++;
                        }

                        printf("\n");

                        kryptos_freeseg(block, block_size);
                    } else {
                        error = 1;
                        printf("ERROR: Unable to get a random block.\n");
                    }
                } else {
                    error = 1;
                    printf("ERROR: Unable to set the internal kryptos CSPRNG to Fortuna.\n");
                }

            } else {
                error = 1;
                printf("ERROR: Unable to get a random block.\n");
            }
        } else {
            error = 1;
            printf("ERROR: Unable to reseed Fortuna.\n");
        }

        kryptos_fortuna_fini(fortuna);
    } else {
        error = 1;
        printf("ERROR: Unable to initialize Fortuna.\n");
    }

    return error;
}
```

[Back](#contents)

## Avoiding RAM swap

Sometimes you need to hold (for short periods of time) sensible data into RAM. In this case, a swap would be harmful because
it would leak data to a smart attacker. There is a way of avoiding those cumbersome swaps.

You need to call ``kryptos_avoid_ram_swap()``. After this call all allocated memory with ``kryptos_newseg`` will stay in RAM
without being swapped to disk.

Internally kryptos uses mlock/munlock POSIX functions. As you may know, it is better to allocate blocks having a size multiple
of the page size. If you do not know nothing about mlock/unlock, please, read the related man page.

When you call ``kryptos_freeseg`` the page related with the freed data will be unlocked. In this case, if you are locking
two addresses that fit into the same page, one of them will be available for swaps after the first ``kryptos_freeseg``. The
better approach is hold all locked data into a huge sensible area or only free locked areas at the same time.

By default, any allocated memory by ``kryptos_newseg`` is able to be swapped. In order to disable the RAM swap avoidance call
the function ``kryptos_allow_ram_swap()``.

In Windows, the RAM swap avoidance is achieved by using VirtualLock from WINAPI function. The locked region will still locked
until the related process exits.

If you are using ``MINIX``, sorry, but until the current version (3.3.0) it does not implement mlock. The functions
``kryptos_avoid_ram_swap()`` and ``kryptos_allow_ram_swap()`` are present just for compability issues. These functions
do nothing in ``MINIX``.

[Back](#contents)

## Key derivation functions

Until now ``kryptos`` has three key derivation functions implemented: ``HKDF``, ``PBKDF2`` and ``Argon2`` (version 19). The
usage of them is very straightforward:

```c
/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_u8_t temp[4096];
    kryptos_u8_t *key = NULL, *kp, *kp_end;
    size_t temp_size;

    printf("User key: ");

    fgets(temp, sizeof(temp) - 1, stdin);

    if ((temp_size = strlen(temp)) > 0) {
        temp[temp_size--] = 0;
    }

    key = kryptos_hkdf(temp, temp_size, sha3_256, "salt", 4, "info", 4, 16);

    if (key != NULL) {
        kp = key;
        kp_end = kp + 16;

        printf("Effective key: ");

        while (kp != kp_end) {
            printf("%c", isprint(*kp) ? *kp : '.');
            kp++;
        }

        printf("\n");
        kryptos_freeseg(key, 16);
    }

    return 0;
}
```

The ``PBKDF2`` usage is similar to ``HKDF``:

```c
/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

#define PBKDF2_COUNT 20
#define PBKDF2_DK_SIZE 16

int main(int argc, char **argv) {
    char password[4096];
    kryptos_u8_t *dk, *d, *d_end;
    size_t dk_size, password_size;

    printf("Password: ");
    fgets(password, sizeof(password) - 1, stdin);

    if ((password_size = strlen(password)) > 0) {
        password[password_size--] = 0;
    }

    dk = kryptos_pbkdf2(password, password_size, whirlpool, "Salt", 4, PBKDF2_COUNT, PBKDF2_DK_SIZE);

    if (dk == NULL) {
        printf("ERROR: Unable to derive the user password.\n");
        return 1;
    }

    d = dk;
    d_end = d + 16;

    printf("Derived key: ");

    while (d != d_end) {
        printf("%c", isprint(*d) ? *d : '.');
        d++;
    }

    printf("\n");

    kryptos_freeseg(dk, 16);

    return 0;
}
```

The ``PBKDF2`` implementation considers PRF as HMAC combined with the passed hash algorithm. The current implementation
is compliant to RFC-6070.

The ``Argon2`` algorithm is more complicated. The three variants are implemented: ``Argon2d``, ``Argon2i`` and ``Argon2id``.
The following code shows how to use them:

```c
/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_u8_t *tag[3] = { NULL, NULL, NULL }, *p, *p_end;
    // INFO(Rafael): You should never use parallelism greater than 1 because kryptos does not support
    //               multi-threading and due to it timing attacks can be done when using parallelism
    //               greater than 1.
    kryptos_u32_t parallelism = 1, tag_size = 32, memory_size_kb = 512, iterations = 50;
    int exit_code = 0;
    kryptos_u8_t *variant[3] = { "argon2d", "argon2i", "argon2id" };
    size_t i;

    tag[0] = kryptos_argon2d("Tales of Brave Ulysses", 22,
                             "salt", 4,
                             parallelism, tag_size, memory_size_kb, iterations,
                             "key", 3,
                             "associated data", 15);

    if (tag[0] == NULL) {
        printf("ERROR: when trying to expand the key by using argon2d.\n");
        exit_code = 1;
        goto epilogue;
    }

    tag[1] = kryptos_argon2i("Tales of Brave Ulysses", 11,
                             "salt", 4,
                             parallelism, tag_size, memory_size_kb, iterations,
                             "key", 3,
                             "associated data", 15);

    if (tag[1] == NULL) {
        printf("ERROR: when trying to expand the key by using argon2i.\n");
        exit_code = 1;
        goto epilogue;
    }

    tag[2] = kryptos_argon2id("Tales of Brave Ulysses", 11,
                              "salt", 4,
                              parallelism, tag_size, memory_size_kb, iterations,
                              "key", 3,
                              "associated data", 15);

    if (tag[2] == NULL) {
        printf("ERROR: when trying to expand the key by using argon2id.\n");
        exit_code = 1;
        goto epilogue;
    }

    for (i = 0; i < sizeof(variant) / sizeof(variant[0]); i++) {
        printf("%s resulting tag: ", variant[i]);
        p = tag[i];
        p_end = p + tag_size;
        while (p != p_end) {
            printf("%.2X", *p);
            p++;
        }
        printf("\n");
        kryptos_freeseg(tag[i], tag_size);
    }

epilogue:

    return exit_code;
}
```

Avoid passing the parameter parallelism with values greater than one, because ``kryptos`` does not implement argon2's multi-threading
conveniences. Using parallelism greater than one with this implementation will allow timing attacks.

[Back](#contents)

## Bcrypt

If you like ``bcrypt`` you can generate and verify "hashed" passwords by using ``kryptos``. The usage is as follows:

```c
/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_u8_t *password = "1234";
    size_t password_size = 4;
    kryptos_u8_t *hash;
    size_t hash_size;
    kryptos_u8_t *salt;

    if ((salt = kryptos_get_random_block(16)) == NULL) {
        printf("Unable to generate a valid 16-byte salt.\n");
        return 1;
    }

    hash = kryptos_bcrypt(4, salt, 16, password, password_size, &hash_size);
    kryptos_freeseg(salt, 16);

    if (hash == NULL) {
        printf("Error!\n");
        return 1;
    } else {
        printf("Hashed password: ");
        fwrite(hash, 1, hash_size, stdout);
        printf("\n");
        if (kryptos_bcrypt_verify(password, password_size, hash, hash_size)) {
            printf("Valid password.\n");
        } else {
            printf("Invalid password.\n");
        }
    }

    return 0;
}
```

**Warning**: I am not intending to provide a huge support for ``bcrypt`` (including its bugs and necessary backward
compatibility). Only "$2a$" is being considered here.

[Back](#contents)

## OTPs

Until now ``Kryptos`` features two one-time password algorithms: ``HOTP`` and ``TOTP``.

### HOTP

Roughly speaking this algorithm is based on the equation: ``shared password`` + ``counter`` + ``HMAC``

Since it will exist a client wanting to authenticate and a server offering a ``HOTP`` authentication, it is
necessary to do some initialisation on both sides.

This iniatisation is done by calling the following function macro:

```c
    kryptos_otp_init(algorithm, task_context, action, [specific parameters of the algorithm])
```

In this case, the "algorithm" parameter will be ``hotp``. The "task_context" parameter will be a ``(kryptos_task_ctx *)``
declared by you and the "action" parameter (for the server side context) will be ``kKryptosValidateToken``.

The specific parameters on the server side for ``HOTP`` are:

- A shared secret.
- The size (in bytes) of this shared secret.
- The moving factor (the counter).
- The throttling parameter.
- The resynchronisation parameter.
- The number of digits (how many digits the tokens will have).

Any doubt about throttling and resynchronisation you should take a look at ``HOTP``'s related ``RFC``. It is out of scope here.

On the client side you need to specify less parameters, look:

- The shared secret.
- The size (in bytes) of this shared secret.
- The moving factor (the counter).
- The number of digits (how many digits the tokens will have).

The "action" parameter (for the client side context) will be ``kKryptosGenerateToken``.

Well, once initialised you should call ``kryptos_otp(algorithm, task_context)`` on both sides. If result field from
the passed task context is ``kKryptosSuccess`` the authentication has succeeded otherwise it has failed by returning
``kKryptosInvalidToken``, probably. Anything different from ``kKryptosSuccess`` means that something went wrong and
in this case more details would be presented in ``result_verbose`` field from the ``task_context``.

Now that you know the basics about what to do let's take a look at the following ``HOTP`` implementation sample:

```c
/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <sys/stat.h>
#if !defined(_MSC_VER)
# include <unistd.h>
#else
# include <io.h>
# define read _read
# define write _write
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define HOTP_SAMPLE_COUNTER_FILE ".hotpct"

#define HOTP_SAMPLE_SHARED_SECRET "SingASimpleSong"

#define HOTP_SAMPLE_SHARED_SECRET_SIZE 15

static int server(void);

static int client(void);

static int read_counter_data(const char *counter_filepath, kryptos_u64_t *data);

static int write_counter_data(const char *counter_filepath, const kryptos_u64_t data);

int main(int argc, char **argv) {
    int err = EXIT_FAILURE;
#if defined(KRYPTOS_C99)
    if (argc > 1) {
        if (strcmp(argv[1], "--server") == 0) {
            err = server();
        } else if (strcmp(argv[1], "--client") == 0) {
            err = client();
        } else {
            goto main_usage;
        }
    } else {
main_usage:
        fprintf(stderr, "use: %s --server | --client\n", argv[0]);
    }
#else
    fprintf(stderr, "error: your kryptos build has no support for c99 conveniences.\n");
#endif
    return err;
}

static int server(void) {
    kryptos_u64_t counter = 0;
    int err = EXIT_FAILURE;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u32_t token = 0;
    size_t number_of_digits = 6;
    size_t resync = 5;
    size_t throttling = 10 * resync;

    kryptos_task_init_as_null(ktask);

    if ((err = read_counter_data(HOTP_SAMPLE_COUNTER_FILE, &counter))  != EXIT_SUCCESS) {
        fprintf(stderr, "error: unable to read counter file (%s).\n", HOTP_SAMPLE_COUNTER_FILE);
        goto server_epilogue;
    }

    if (kryptos_otp_init(hotp, ktask, kKryptosValidateToken,
                         (kryptos_u8_t *)HOTP_SAMPLE_SHARED_SECRET, HOTP_SAMPLE_SHARED_SECRET_SIZE,
                         &counter, &throttling, &resync, &number_of_digits,
                         kryptos_otp_hash(sha384)) != kKryptosSuccess) {
        fprintf(stderr, "error: %s\n",
                            (ktask->result_verbose != NULL) ? ktask->result_verbose
                                                            : "during HOTP initialising.");
        goto server_epilogue;
    }

    do {
        fprintf(stderr, "Type the required token: ");
#if !defined(_MSC_VER)
        scanf("%d", &token);
#else
        scanf_s("%d", &token, sizeof(token));
#endif
        ktask->in = (kryptos_u8_t *)&token;
        ktask->in_size = sizeof(token);
        kryptos_otp(hotp, ktask);
    } while (throttling != 0 && ktask->result != kKryptosSuccess);

    if (kryptos_last_task_succeed(ktask)) {
        fprintf(stdout, "info: the token was successfully validated.\n");
        err = write_counter_data(HOTP_SAMPLE_COUNTER_FILE, counter);
    } else {
        fprintf(stdout, "error: %s\n", (ktask->result_verbose != NULL) ?
                      ktask->result_verbose : "max attempts exceeded.");
    }

server_epilogue:

    return err;
}

static int client(void) {
    kryptos_u64_t counter = 0;
    int err = EXIT_FAILURE;
    kryptos_task_ctx t, *ktask = &t;
    size_t number_of_digits = 6;

    kryptos_task_init_as_null(ktask);

    if ((err = read_counter_data(HOTP_SAMPLE_COUNTER_FILE, &counter)) != EXIT_SUCCESS) {
        fprintf(stderr, "error: unbale to read counter file (%s).\n", HOTP_SAMPLE_COUNTER_FILE);
        goto client_epilogue;
    }

    if (kryptos_otp_init(hotp, ktask, kKryptosGenerateToken,
                         (kryptos_u8_t *)HOTP_SAMPLE_SHARED_SECRET, HOTP_SAMPLE_SHARED_SECRET_SIZE,
                         &counter, NULL, NULL, &number_of_digits,
                         kryptos_otp_hash(sha384)) != kKryptosSuccess) {
        fprintf(stderr, "error: %s\n",
                    (ktask->result_verbose != NULL) ? ktask->result_verbose
                                                    : "during HOTP initalising.");
        goto client_epilogue;
    }

    kryptos_otp(hotp, ktask);
    if (kryptos_last_task_succeed(ktask)) {
        fprintf(stdout, "info: your token is '%d'.\n", *(kryptos_u32_t *)ktask->out);
        err = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "error: %s\n",
                (ktask->result_verbose != NULL) ? ktask->result_verbose
                                                : "unbale to generate a token.");
    }

client_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return err;
}

static int read_counter_data(const char *counter_filepath, kryptos_u64_t *data) {
    int fd = -1;
    struct stat st;
    int err = EXIT_FAILURE;

    if (counter_filepath == NULL || data == NULL) {
        return EXIT_FAILURE;
    }

    if (stat(counter_filepath, &st) != 0) {
        *data = 0;
        return EXIT_SUCCESS;
    }

#if !defined(_MSC_VER)
    if ((fd = open(counter_filepath, O_RDONLY)) == -1) {
        fprintf(stderr, "error: unable to open counter file.\n");
        return EXIT_FAILURE;
    }
#else
    if (_sopen_s(&fd, counter_filepath, O_RDONLY, _SH_DENYWR, _S_IREAD) != 0) {
        fprintf(stderr, "error: unable to open counter file.\n");
        return EXIT_FAILURE;
    }
#endif

    if (read(fd, data, sizeof(kryptos_u64_t)) == -1) {
        fprintf(stderr, "error: unable to read counter data.\n");
        goto read_counter_data_epilogue;
    }

    err = EXIT_SUCCESS;

read_counter_data_epilogue:

    if (fd > -1) {
#if !defined(_MSC_VER)
        close(fd);
#else
        _close(fd);
#endif
    }

    return err;
}

static int write_counter_data(const char *counter_filepath, const kryptos_u64_t data) {
    int fd = -1;
    int err = EXIT_FAILURE;
#if !defined(_MSC_VER)
    if ((fd = open(counter_filepath, O_WRONLY | O_CREAT | S_IRUSR | S_IWUSR)) == -1) {
        fprintf(stderr, "error: unable to open counter file.\n");
        return EXIT_SUCCESS;
    }
#else
    if (_sopen_s(&fd, counter_filepath, O_WRONLY | O_CREAT, _SH_DENYNO, _S_IREAD | _S_IWRITE) != 0) {
        fprintf(stderr, "error: unable to open counter file.\n");
        return EXIT_SUCCESS;
    }
#endif
    if (write(fd, &data, sizeof(kryptos_u64_t)) == -1) {
        fprintf(stderr, "error: unable to write counter data.\n");
        goto write_counter_data_epilogue;
    }

    err = EXIT_SUCCESS;

write_counter_data_epilogue:

    if (fd > -1) {
#if !defined(_MSC_VER)
        close(fd);
#else
        _close(fd);
#endif
    }

    return err;
}

#undef HOTP_SAMPLE_COUNTER_FILE

#undef HOTP_SAMPLE_SHARED_SECRET

#undef HOTP_SAMPLE_SHARED_SECRET_SIZE

#if defined(_MSC_VER)
# undef read
# undef write
#endif
```

In order to test you should call ``./hotp-c99-sample --client`` to get a token and ``./hotp-c99-sample --server``
to validate this token.

When the throttling parameter has exceeded its limit all ``HOTP`` session will need to be reinitialised by
calling ``kryptos_otp_init`` again. However, you will also need to reset the throttling variable to the wanted limit
before calling init. In this way you will be able to apply your desired policy about brute force attack mitigations.
It is up to you!

[Back](#contents)

### TOTP

The idea behind ``TOTP`` is similar to ``HOTP`` but instead of using a defined counter it uses the system timestamp
(``UNIX`` epoch) as its counter.

The calls you must make in order to use it are also similar to ``HOTP`` but here you will not inform throttling nor
resynchronization parameters.

At server side you will do:

```c
    kryptos_u64_t t0 = (kryptos_u64_t)time(NULL); // Often configured to UNIX epoch.
    kryptos_u64_t x = 30; // Window time which the token will be valid (more or less).
    size_t d = 6; // Number of digits
    kryptos_u8_t *shared_secret = (kryptos_u8_t *)"w-e-a-k-k-e-y";
    size_t shared_secret_size = 13;
    if (kryptos_otp_init(server,
                         kKryptosValidateToken,
                         shared_secret, shared_secret_size,
                         &t0, &x, &d,
                         kryptos_otp_hash(sha512)) == kKryptosSuccess) {
        // Init done, go ahead with your auth stuff...
    }
```

At client side you will do:

```c
    (...)
    if (kryptos_otp_init(totp,
                         client,
                         kKryptosGenerateToken,
                         shared_secret,
                         shared_secret_size,
                         &t0,
                         &x,
                         &d,
                         kryptos_otp_hash(sha512)) == kKryptosSuccess) {
        // Init done, go ahead with your auth stuff...
    }
```

At both sides you will call:

```c
    // client
    if (kryptos_otp(totp, client) == kKryptosSuccess) {
        // Send out your token and wait for having your access granted.
    }

    // server
    // wait for the client token...
    kryptos_otp_set_token(server, client_token, client_token_size);
    if (kryptos_otp(totp, server) == kKryptosSuccess) {
        // Grant access to client.
    } else {
        // Deny access to client.
    }
```

Follows a well-simple sample that you can play around with:

```c
/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DIGITS_NR 6
#define TIME_STEP 30
// INFO(Rafael): If you want to test it with your smartphone
//               by using "LastPass... Authenticator" or "Google
//               Authenticator" and stuff just add the following
//               base-32 encoded key:
//
//                      ONRWSZLOORUWC3DJMJSXEYLU
#define SHARED_SECRET (kryptos_u8_t *)"scientialiberat"
#define SHARED_SECRET_SIZE 15
#define T0 0

static int server(void);

static int client(void);

int main(int argc, char **argv) {
    int err = EXIT_FAILURE;
#if defined(KRYPTOS_C99)
    if (argc >= 2) {
        if (strcmp(argv[1], "--client") == 0) {
            err = client();
        } else if (strcmp(argv[1], "--server") == 0) {
            err = server();
        } else {
            goto usage;
        }
    } else {
usage:
        fprintf(stderr, "user: %s --client | --server\n", argv[0]);
    }
#else
    fprintf(stderr, "error: your kryptos build has no support for c99 conveniences.\n");
#endif

    return err;
}

static int client(void) {
    kryptos_task_ctx c, *client = &c;
    kryptos_u64_t t0 = 0;
    kryptos_u64_t x = TIME_STEP;
    size_t d = DIGITS_NR;
    kryptos_u8_t *shared_secret = SHARED_SECRET;
    size_t shared_secret_size = SHARED_SECRET_SIZE;
    int err = EXIT_FAILURE;

    if (kryptos_otp_init(totp,
                         client,
                         kKryptosGenerateToken,
                         shared_secret, shared_secret_size,
                         &t0, &x, &d, kryptos_otp_hash(sha1)) != kKryptosSuccess) {
        fprintf(stderr, "error: %s\n", (client->result_verbose != NULL) ? client->result_verbose
                                                                        : "Generic failure.");
        return EXIT_FAILURE;
    }

    if (kryptos_otp(totp, client) == kKryptosSuccess) {
        fprintf(stdout, "Your current token is '%06u'\n", *(kryptos_u32_t *)client->out);
        err = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "error: %s\n", (client->result_verbose != NULL) ? client->result_verbose
                                                                        : "Generic failure.");
    }

    kryptos_otp_free_token(client);
    if (err == EXIT_SUCCESS) {
        kryptos_task_set_encode_action(client);
        kryptos_run_encoder(base32, client, shared_secret, shared_secret_size);
        if (kryptos_last_task_succeed(client)) {
            fprintf(stdout, "Try to add the following key to your 2FA favorite app: '");
            fwrite(client->out, 1, client->out_size, stdout);
            fprintf(stdout, "'.\n");
            kryptos_task_free(client, KRYPTOS_TASK_OUT);
        }
    }

    return err;
}

static int server(void) {
    kryptos_task_ctx s, *server = &s;
    kryptos_u64_t t0 = T0;
    kryptos_u64_t x = TIME_STEP;
    size_t d = DIGITS_NR;
    kryptos_u8_t *shared_secret = SHARED_SECRET;
    size_t shared_secret_size = SHARED_SECRET_SIZE;
    int err = EXIT_FAILURE;
    kryptos_u32_t token = 0;

    if (kryptos_otp_init(totp,
                         server,
                         kKryptosValidateToken,
                         shared_secret, shared_secret_size,
                         &t0, &x, &d, kryptos_otp_hash(sha1)) != kKryptosSuccess) {
        fprintf(stderr, "error: %s\n", (server->result_verbose != NULL) ? server->result_verbose
                                                                        : "Generic failure.");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Type the required token: ");
#if !defined(_MSC_VER)
    scanf("%d", &token);
#else
    scanf_s("%d", &token, sizeof(token));
#endif

    kryptos_otp_set_token(server, (kryptos_u8_t *)&token, sizeof(token));

    if (kryptos_otp(totp, server) == kKryptosSuccess) {
        fprintf(stdout, "Access granted.\n");
        err = EXIT_SUCCESS;
    } else {
        printf("error: %s\n", (server->result_verbose != NULL) ? server->result_verbose
                                                               : "Generic failure.");
    }

    return err;
}

#undef DIGITS_NR
#undef TIME_STEP
#undef SHARED_SECRET
#undef SHARED_SECRET_SIZE
#undef T0
```

Testing the code above it is straightforward. If you want to get a new token just run
``./totp-c99-sample --client``. If you want to validate just run ``./totp-c99-sample --server``.

**Tip**: If for some reason you add the key of this sample into your smartphone token app prefered
one and after some rebooting it stop working. Try to run ``ntpdate time.nist.gov``. Maybe the
clock of your machine is not well synchronized with the clock of your smartphone. When you start
working with stuff well dependent of time you realize how it is relative and imprecise
(especially within computers).



[Back](#contents)

## So it is enough

If you have understood every single sample code presented in here, I think that you are ready for some action
with this library. I hope you enjoy! Happy coding! :)

Do you think that something is still unclear? Please let me [know](https://github.com/rafael-santiago/kryptos/issues)
and thank you!

[Back](#contents)
