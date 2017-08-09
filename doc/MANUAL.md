# Manual

**Abstract**: This library was designed to be used in user mode applications and also in kernel mode. The following
sections will guide the readers through the main aspects of how to use ``kryptos`` in their own stuff.

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

The way of indicating the desired cipher for a encryption task is by setting the field ``cipher`` from the ``kryptos_task_ctx``
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
// Compilation: gcc arc4-sample-c99.c -oarc4-sample-c99 -I<path to kryptos headers> -L<path to libkryptos.a>
//              -lkryptos
//

#include <kryptos.h>
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
