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

Of course, you should indicates where the ``kryptos`` headers are. In ``GCC``, ``Clang`` it can be done using the option
``-I<path>``.

### Linking kernel mode stuff

For kernel mode, until now kryptos can be used in ``FreeBSD`` and ``Linux``. The main idea was create a tiny library
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
besides the additional parameters.

There is no field called "plaintext" or "ciphertext". There are the fields ``in`` and ``out``. Then, for encrypting the **plaintext**
must be stored into ``in``. When decrypting the **ciphertext** also must be stored into ``in``. The resultant data of the two operations
always will be stored (allocated) into ``out``.

However when you store the input data into the task context is necessary also indicate the size in bytes of that data. The
field ``in_size`` holds the input size.

After any executed task, the field ``result`` will contain a code which describes the status of that last task. The additional
field called ``result_verbose`` may also contain some literal description about.

The following code defines the input for a task:

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

All relevant kryptos_task_ctx fields can be handled by C macros but the remaining information of how manipulate the
``kryptos_task_ctx`` will be introduced together with the crypto stuff.

### The symmetric stuff

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
// arc4-sample.c
//
// Compilation: gcc arc4-sample.c -oarc4-sample -I<path to kryptos headers> -L<path to libkryptos.a>
//              -lkryptos
//

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

    kryptos_arc4_cipher(ktask);

    if (ktask->result == kKryptosSuccess) {
        printf("Encrypted... now decrypting...\n");

        // INFO(Rafael): Moving the output (ciphertext) to the input.

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;
        ktask->out = NULL;
        ktask->out_size = 0;

        // INFO(Rafael): Running the ARC4 cipher over the input (ciphertext).

        kryptos_arc4_cipher(ktask);

        if (ktask->result == kKryptosSuccess) {
            printf("Out: %s\n", ktask->out);
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
the user key reference inside the task context. The real keystream generation is performed in every task execution.
Once the user key and some internal control sets defined by ``kryptos_arc4_setup()`` you do not need call it anymore. The
``kryptos_arc4_setup()`` sets the ``cipher`` field from ``kryptos_task_ctx`` to ``kKryptosCipherARC4``.

Another curious thing could be the lack of the explicit indication of encryption or decryption intentions, however, ``ARC4``
is a stream cipher, the encryption and decryption are the same it only depends on the input.

The use of ``kryptos_freeseg()`` in order to free memory is indicated because in kernel mode it can abstract some complications
to you. In user mode you can call the default libc ``free()`` function, there is no problem with that.

It is possible to simplify a little bit more the previous sample by using C macros and c99 capabilities:

```c
// arc4-sample-c99.c
//
// Compilation: gcc arc4-sample-c99.c -oarc4-sample-c99 -I<path to kryptos headers>
//              -L<path to libkryptos.a> -lkryptos
//

#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
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

        kryptos_task_init_as_null(ktask);

        // INFO(Rafael): Moving the output (ciphertext) to the input.

        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);

        // INFO(Rafael): Running the ARC4 cipher over the input (ciphertext).

        kryptos_run_cipher(arc4, ktask, "1234", 4);

        if (kryptos_last_task_succeed(ktask)) {
            printf("Out: %s\n", ktask->out);
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
}
```

As you can see the kryptos task manipulation C macros implement a direct and simple internal ``DSL``.

The general using form of ``kryptos_run_cipher`` macro is:

``kryptos_run_cipher(<cipher>, <ktask pointer>, key, key_size[, args]...)``

Block ciphers should be used in almost the same way:

```c
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
    kryptos_blowfish_cipher(ktask);

    if (ktask->result == kKryptosSuccess) {
        printf("Data encrypted!\n");

        kryptos_task_set_decrypt_action(ktask);

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;
        ktask->out = NULL;

        // INFO(Rafael): Decrypting.
        kryptos_blowfish_cipher(ktask);

        if (ktask->result == kKryptosSuccess) {
            printf("Data decrypted: '%s'\n", ktask->out);
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

    // INFO(Rafael): Encrypting.
    kryptos_task_set_in(ktask, data, data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(blowfish, ktask, key, strlen(key), kKryptosECB);

    if (kryptos_last_task_succeed(ktask)) {
        // INFO(Rafael): Decrypting.
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(blowfish, ktask, key, strlen(key), kKryptosECB);

        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    }

    return 0;
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
sadly, this kind of naive "approach" is common. Avoid doing this, it is unresponsible and stupid.

The following code sample uses the SERPENT cipher in CBC mode with the c99 conveniences:

```c
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

    // INFO(Rafael): Encrypting.
    kryptos_task_set_in(ktask, data, data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(serpent, ktask, key, strlen(key), kKryptosCBC);

    if (kryptos_last_task_succeed(ktask)) {
        // INFO(Rafael): Decrypting.
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(serpent, ktask, key, strlen(key), kKryptosCBC);

        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    }

    return 0;
}
```

If you want to generate the iv on your own, you need to care about the content of the fields ``iv`` and ``iv_size`` from the
``kryptos_task_ctx`` struct. The iv should point to the chunk of bytes required as iv by the current used cipher and
the iv_size must store the total in byte of that byte chunk. If you generate na invalid iv the encryption/decryption will
fail. As a result the kryptos_last_task_succeed(...) will indicate a zero value.

Details about a failure always can be accessed by the field ``result_verbose`` from the ``kryptos_task_ctx`` struct.

Not all block ciphers only need a key, a size of this key and an operation mode. In kryptos we also have block ciphers
that need more than the standard parameters. In this case the additional parameters are always passed after the operation
mode and they must be pointers. As sample, let's pick the cipher CAMELLIA. The CAMELLIA algorithm supports key sizes
of 128, 192 and also 256.

When calling CAMELLIA in kryptos the desired key size should be passed, in the following way (c99):

```c
#include <kryptos.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx task, *ktask = &task;
    kryptos_u8_t *key = "foo";
    kryptos_u8_t *data = "plaintext";
    size_t data_size = 9;
    kryptos_camellia_keysize_t key_size = kKryptosCAMELLIA192; // Let's use Camellia-192.

    printf("Original data: %s\n", data);

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): Encrypting.
    kryptos_task_set_in(ktask, data, data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(camellia, ktask, key, strlen(key), kKryptosCBC, &key_size);

    if (kryptos_last_task_succeed(ktask)) {
        // INFO(Rafael): Decrypting.
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        kryptos_run_cipher(camellia, ktask, key, strlen(key), kKryptosCBC, &key_size);

        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    }

    return 0;
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
// bare-bone-hash-sample.c
// compilation command line: gcc bare-bone-hash-sample.c -obbhs -lkryptos

#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx t, *ktask = &t;
    size_t o;

    // INFO(Rafael): Defining the input that must be "hashed".

    t.in = "abc";
    t.in_size = 3;

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
    }

    return 0;
}
```

According to the presented sample above, you should define the input and its size in bytes in a ``kryptos_task_ctx`` struct.
To actually execute the desired hash algorithm you should pass a ``kryptos_task_ctx **`` and a flag requesting hexadecimal
output (1 => hex, 0 => raw byte). The function to be called is ``kryptos_HASHID_hash``, where ``HASHID`` can be found
in **Table 4**.

### HMACs

``Kryptos`` offers the possibility of easily generate a Message authentication code based on Hashes (HMACs) when
the ``c99`` capabilities are present.

This feature can be accessed using the macro ``kryptos_run_cipher_hmac``. The following code sample shows how to generate
a message authenticated taking advantage from the implemented hash algorithms.

```c
// hmac-sample.c
// compilation command line: gcc hmac-sample.c -ohmac-sample -lkryptos
#include <kryptos.h>
#include <stdio.h>

int main(int argc, char **argv) {
    kryptos_task_ctx m;
    int exit_code = 1;

    // INFO(Rafael): Always set everything to null is a good practice.

    kryptos_task_init_as_null(&m);

    // INFO(Rafael): Setting the plaintext.

    kryptos_task_set_in(&m, "As I was saying...", 18);

    // INFO(Rafael): Encrypting with CAST5-CBC and generating our MAC based on SHA-512.

    kryptos_task_set_encrypt_action(&m);
    kryptos_run_cipher_hmac(cast5, sha512, &m, "silent passenger", 16, kKryptosCBC);

    if (kryptos_last_task_succeed(&m)) {
        // INFO(Rafael): Let us corrupt the cryptogram on purpose of seeing the decryption fail.
        //               Do not do it at home! ;)

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
            //               CAST5 in CBC with a null iv. CBC asked with a null iv internally asks kryptos
            //               to generate a pseudo-random one.
            //
            kryptos_task_free(&m, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
            exit_code = 0;
        } else {
            // INFO(Rafael): It should never happen.
            printf("Rascals! We were fooled!!\n");
        }
    } else {
        // INFO(Rafael): It should happen.
        printf("ERROR: Hmmmm it should be at least encrypted.\n");
    }

    // INFO(Rafael): Housekeeping.

    kryptos_task_init_as_null(&m);

    return exit_code;
}
```

Even if the decryption has failed and you is sure about of the out field nullity from ``kryptos_task_ctx``, you can
call ``kryptos_task_free`` passing the bitmask ``KRYPTOS_TASK_OUT`` but I personally dislike this kind of code.

As you may have noticed the general form of using the ``kryptos_run_cipher_hmac`` macro is:

```
    kryptos_run_cipher_hmac(<block cipher>,
                            <hash algorithm>,
                            <kryptos_task_ctx *>,
                            <block cipher user key>, <block cipher user key size>,
                            <block cipher mode>
                            [, <block cipher add. args, when the block cipher has some>)``
```
