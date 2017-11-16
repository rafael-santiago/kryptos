# Libkryptos developer's manual

**Abstract**: This document is intended for contributors. Here you will find information about how to code new stuff besides maintaining the current ones.
Due to it is assumed that the reader has a medium to advanced C knowledge.

## The libkryptos repo tree layout

The repository tree has the following layout:

```
libkryptos/         <-------------- Root directory (duh).
    doc/            <-------------- Sub-directory intended to documentation stuff.
    etc/            <-------------- Sub-directory intended to miscellaneous stuff.
    src/            <-------------- Sub-directory intended to the main library source code.
        samples/    <-------------- Sub-directory intended to the sample programs.
        tests/      <-------------- Sub-directory intended to the unit tests for the 'src' stuff
                                                                                     (user mode).
            cutest/ <-------------- This is the sub-directory of the adopted unit test library.
            kernel/ <-------------- Sub-directory intended to the unit tests for the 'src' stuff
                                                                                   (kernel mode).
```

After a well suceeded build task the ar file was created within ``libkryptos/lib``. When the samples are also requested in a build task, they will be
created within ``libkryptos/samples``. Supposing that you ran the build using this command: ``hefesto --mk-samples``. As a result you will get the
following repo tree:

```
libkryptos/
    doc/
    etc/
    lib/            <-------------- Ar file sub-directory.
        libkryptos.a
    samples/        <-------------- Samples sub-directory
            (a bunch of executables)
    src/
        o/          <-------------- Object files sub-directory (library).
        samples/
                o/  <-------------- Object files sub-directory (samples).
        tests/
                o/  <-------------- Object files sub-directory (tests).
            cutest/
            kernel/
```

When you also request the kernel mode tests the native kernel's build system will create the object files directly within the source code's sub-directory
(lib and tests source [tests/kernel/*]).

## Some meaningful header files

Some of the detailed headers includes their own implementation files. A header implementation file usually has the same name of
the header file but the file extension is ``.c`` instead of ``.h``.

### src/kryptos_types.h

This header file contains the main definitions of some constants. It also includes a detection stuff related with cpu word size
and the C language's version (if the compiler actually supports C99 or not). Still it also includes some compiler directives
driven by the macro ``KRYPTOS_KERNEL_MODE``. This macro signales if the current compilation task is being done for a user
(the default) or a kernel project.

The two main types (structs) defined within this header files are: ``kryptos_task_ctx`` and ``kryptos_mp_value_t``.

The ``kryptos_types.h`` file also defines some macros that make up the developer's internal dsl. This internal dsl
makes easier the addition of new features (more on later).

### src/kryptos.h

This header file merges the whole library and exposes some final user's macros. In fact, this is the header file that
the library users will include in their own stuff. By including this header the users will be able to access any relevant
cryptographic feature.

When you add some new cipher you must include the header of this new cipher in ``kryptos.h``.

Also when you extend the kryptos user's internal dsl, the new dsl stuff must be defined within this header file.

### src/kryptos_mp.h

This header file contains all function prototypes/macros related with multi-precision arithmetic. This header exports important
functions for PK crypto.

### src/kryptos_padding.h

This header file contains all function prototypes related with padding tasks. Actually it is important for block ciphers.

### src/kryptos_pem.h

This header file exposes some functions for PEM buffer reading and writing. This is very important for PK crypto, because all
of PK crypto algorithms implemented in kryptos expects and returns their data using the PEM format.

### src/kryptos_task_check.h

Any interaction by the users with the library is represented as a task, due to it before doing the requested task
the library must verify if the current task makes sense or not. The ``kryptos_task_check.h`` exports some important task
check entry points. This also could be understood as a task "compiler".

### src/kryptos_hash_common.h

If you will add a new hash algorithm and this algorithm uses Merkle-Damgard construction, the ``kryptos_hash_common.h``
exports some useful functions that will make your implementation easier (more on later).

## Okay, let's add a new block cipher called "foofish" to libkryptos...

Now let's suppose you read about a brand new awesome, super-secure block cipher called foofish and you want to add it to
kryptos.

The foofish cipher encrypts blocks of 128-bits, it needs a user's key of 256-bits in order to expand the final key (generate
the sub-keys).

The first thing you should do is define a new constant into the typed enum called ``kryptos_cipher_t``. This enum
is located in ``kryptos_types.h``, take a look:

```c
typedef enum {
    kKryptosCipherARC4 = 0,
    kKryptosCipherSEAL,
    kKryptosCipherAES128,
    kKryptosCipherAES192,
    kKryptosCipherAES256,
    kKryptosCipherDES,
    kKryptosCipher3DES,
    kKryptosCipher3DESEDE,
    kKryptosCipherIDEA,
    kKryptosCipherRC2,
    kKryptosCipherFEAL,
    kKryptosCipherCAST5,
    kKryptosCipherCAMELLIA,
    kKryptosCipherSAFERK64,
    kKryptosCipherBLOWFISH,
    kKryptosCipherSERPENT,
    kKryptosCipherFOOFISH, // Nice, you should respect the order: stream ciphers, block ciphers, pk stuff.
    kKryptosCipherRSA,
    kKryptosCipherRSAOAEP,
    kKryptosCipherELGAMAL,
    kKryptosCipherELGAMALOAEP,
    kKryptosCipherRSAEMSAPSS,
    kKryptosCipherDSA,
    kKryptosCipherNr
}kryptos_cipher_t;

```

After you should create two files: ``src/kryptos_foofish.h`` and ``src/kryptos_foofish.c``. Let's start with the
``kryptos_foofish.c``.

All s-boxes, internal constants, sub-keys struct, etc should be defined into the algorithm implementation file. If it
performs shifts and you want to code it as macros you should create it in this implementation file and after undefine
this macro. This is a way of keeping the stuff sanitized.

The function ``kryptos_foofish_ld_user_key`` is responsible for reading the user key into the sub-keys initial state.
The function ``kryptos_foofish_mk_skeys`` is responsible for expanding the user key:

```c
(...)
    static void kryptos_foofish_ld_user_key(kryptos_u32_t *key,
                                            const kryptos_u8_t *user_key,
                                            const size_t user_key_size);

    static void kryptos_foofish_mk_skeys(const kryptos_u8_t *key,
                                         const size_t key_size,
                                         struct kryptos_foofish_subkeys *sks);
(...)
```

The struct ``kryptos_foofish_subkeys`` is abstracted but it will contain the final key used for encrypt and decrypt the data.

As said before the foofish expects a 256-bit key from the user. This data is put into a initial state and processed in some
way to produce the final key. The function ``kryptos_foofish_ld_user_key`` will load this data. There's a way of making
this reading stuff easier. Take a look:

```c

static void kryptos_foofish_ld_user_key(kryptos_u32_t *key,
                                        const kryptos_u8_t *user_key,
                                        const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;

    kryptos_ld_user_key_prologue(key, 8, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_foofish_ld_user_key_epilogue, key, w, b, kp, kp_end);
}
```

The ``kryptos_foofish_ld_user_key`` uses three useful macros: ``kryptos_ld_user_key_prologue``, ``kryptos_ld_user_key_byte``,
``kryptos_ld_user_key_epilogue``.

Using those three macros allow you deal with keys that do not have the exact expected size. Maybe the user supplied a shorter
key. With the macros is possible to read the passed bytes and assume the remaining as zeroed bytes. Another thing is that
those macros avoid using loops in order to load the bytes into the state, as a result the code tends to drop out any kind
of useless instructions.

All that you need to use the ``kryptos_ld_user_key_*`` macros are four variables: two ``kryptos_u8_t *`` and two ``size_t``.
Do not worry about their initialization, the ``kryptos_ld_user_key_prologue`` does it:

```c
    kryptos_ld_user_key_prologue(<pointer to the state>,
                                 <total of n-bit values produced by the expected key size>,
                                 <pointer to the user key>,
                                 <size in bytes of the user key>,
                                 <head key pointer>,
                                 <tail key pointer>,
                                 <state's index>,
                                 <byte counter>,
                                 <panic statement [if something is wrong this is what to do]>);
```

Translating:

```c
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;

    kryptos_ld_user_key_prologue(key, 8, user_key, user_key_size, kp, kp_end, w, b, return);
```

Since 32 * 8 = 256 (in this case n-bit is 32-bit). We are saying that is expected to read 256 bytes from "key", if not possible
the remaining are assumed as zero. **Remark**: The ``kryptos_ld_user_key_prologue/byte/epilogue`` can work with key state of
any type not only 32-bit, this is just an example!

Now you need to call ``kryptos_ld_user_key_byte`` 32 times. Because we will read the data byte-by-byte. The main idea
behind the macro ``kryptos_ld_user_key_byte`` is:

```c
    kryptos_ld_user_key_byte(<exact position where the current byte must be loaded>,
                             <state's index>,
                             <byte counter>,
                             <key's head pointer>,
                             <key's tail pointer>,
                             <escape label defined in the epilogue macro>)
```

Translating:

```c
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_foofish_ld_user_key_epilogue);
```

Now the epilogue macro:

```c
    kryptos_ld_user_key_epilogue(<escape label>,
                                 <state pointer>,
                                 <state's index>,
                                 <byte counter>,
                                 <key's head pointer>,
                                 <key's tail pointer>);
```

Translating:

```c
    kryptos_ld_user_key_epilogue(kryptos_foofish_ld_user_key_epilogue, key, w, b, kp, kp_end);
```

All you should do is call ```kryptos_foofish_ld_user_key``. It will transfer the user's key
to the key state and you can process the next sub-keys.

```c
static void kryptos_foofish_mk_skeys(const kryptos_u8_t *key,
                                     const size_t key_size,
                                     struct kryptos_foofish_subkeys *sks) {
    kryptos_u32_t W[60];

    kryptos_foofish_ld_user_key(&W[0], key, key_size);

    (...)
}
```

The algorithm should be implemented as you think better, however, is a good practice use the following
prototypes for the block encryption/decryption functions (almost all basic implemented block ciphers
are following this prototype):

```c
static void kryptos_foofish_block_encrypt(kryptos_u8_t *block,
                                          const struct kryptos_foofish_subkeys *sks);

static void kryptos_foofish_block_decrypt(kryptos_u8_t *block,
                                          const struct kryptos_foofish_subkeys *sks);
```

Notice that these are basic functions and any block cipher will need them. For any block cipher, kryptos will
parse a buffer by getting the amount of bytes necessary by the block cipher and invoke encrypt or decrypt
(still following the chosen operation mode). The nice part is that almost always you should not worry about
this parser/processor. Kryptos has a nice abstraction for doing it through its internal developer's dsl.

The first thing to do in order to take advantage of it is to define a function pointer type that expresses the
block encrypt/decrypt prototype followed by you:

```c
typedef void (*kryptos_foofish_block_processor)(kryptos_u8_t *block,
                                                const struct kryptos_foofish_subkeys *sks);
```

Now here goes the "magic":

```c
KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(foofish,
                                    ktask,
                                    kryptos_foofish_subkeys,
                                    sks,
                                    kryptos_foofish_block_processor,
                                    foofish_block_processor,
                                    kryptos_foofish_mk_skeys((*ktask)->key, (*ktask)->key_size, &sks),
                                    kryptos_foofish_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_foofish_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_FOOFISH_BLOCKSIZE,
                                    foofish_cipher_epilogue,
                                    outblock,
                                    foofish_block_processor(outblock, &sks))
```

Explaining:

```
KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(<internal cipher name>,
                                    <name given for the (kryptos_task_ctx **)>,
                                    <the cipher subkeys struct of the cipher>,
                                    <name given for the instance cipher subkeys struct>,
                                    <the function type of your encrypt/decrypt functions>,
                                    <name given for the pointer to the encrypt/decrypt function>,
                                    <the key expansion statement>,
                                    <the block encrypt function>,
                                    <if additional steps are necessary before encrypting they go here>,
                                    <the block decrypt function>,
                                    <if additional steps are necessary before decrypting they go here>,
                                    <the block size (in bytes) of the cipher>,
                                    <the epilogue/escape label>,
                                    <name given for the current processed data block>,
                                    <the block processing statement>)
```

The encrypt and decrypt block functions in foofish return the data into the own input block. Due to it the block
processing statement is simply ``foofish_block_processor(outblock, &sks)``.

There is also a "magic" to implement the cipher setup function:

```c
    KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(foofish,
                                             kKryptosCipherFOOFISH,
                                             KRYPTOS_FOOFISH_BLOCKSIZE)
```

Notice that "setup" in kryptos is not the key expansion. The setup phase is when the user supplies basic information
for the desired encryption/decryption task. This will load the task context with the relevant supplied data.

I showed you the way of implementing the two important components of a block cipher in a more automated way, however,
you also need to make those functions visible outside the block cipher module. In order to do it you should include
the following basic content into the ``kryptos_foofish.h`` header file:

```c
#ifndef KRYPTOS_KRYPTOS_FOOFISH_H
#define KRYPTOS_KRYPTOS_FOOFISH_H 1

#include <kryptos_types.h>

#define KRYPTOS_FOOFISH_BLOCKSIZE 16

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(foofish)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(foofish)

#endif
```

The macro ``KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP`` will make visible the function
``kryptos_foofish_setup(kryptos_task_ctx *, kryptos_u8_t *, const size_t, const kryptos_cipher_mode_t)``.
The macro ``KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR`` will make visible the function
``kryptos_foofish_cipher(kryptos_task_ctx **)``.

The macro ``KRYPTOS_FOOFISH_BLOCKSIZE`` is also important it states in bytes the size of processed blocks.

By doing it foofish can be called by the user macro ``kryptos_run_cipher``.

The cipher module is done, but you still need to teach the task check module how to handle this new cipher otherwise
the final users never will be able to use your new cipher. The task check module stands for the file
``src/kryptos_task_check.c``. For almost new block ciphers all you should do is edit the function
``kryptos_task_check_iv_data`` adding the following case statement:

```c
static int kryptos_task_check_iv_data(kryptos_task_ctx **ktask) {
    if ((*ktask)->iv == NULL || (*ktask)->iv_size == 0) {
        return 0;
    }

    switch ((*ktask)->cipher) {
        case kKryptosCipherDES:
        case kKryptosCipher3DES:
        case kKryptosCipher3DESEDE:
            return ((*ktask)->iv_size == KRYPTOS_DES_BLOCKSIZE);
            break;

        (...)

        case kKryptosCipherFOOFISH: // You should add this -------------+
            return ((*ktask)->iv_size == KRYPTOS_FOOFISH_BLOCKSIZE); // |
            break; // --------------------------------------------------+

        default: // WARN(Rafael): Only to shut up the cumbersome compiler warning.
            break;
    }

    return 0;
}

```

All done! Now the new cipher is actually added into kryptos. However, you should not add a new stuff without also adding
tests for it.

## Okay, let's write some tests for "foofish"...

The basic test to be added for a new block cipher is the encryption/decryption test following the standard test vector
supplied by the cipher's official specification. There is a more automated way of doing it in kryptos.

You should create a header file containing the test vector data in ``tests/foofish_test_vector.h``, look:

```c
#ifndef KRYPTOS_TESTS_FOOFISH_TEST_VECTOR_H
#define KRYPTOS_TESTS_FOOFISH_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(foofish, block_cipher) = {
    add_test_vector_data("\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"
                         "\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x01\x2E\xB2\xEE\xDF\xBC\x20\x20\x30\x02\x11\x90\x80\x6F\xEE\x47",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    (...)
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x01\x2A\x34\x93\x28\xEA\xCB\xDE\xF0\x31\x33\x3A\xBC\xAF\x5E\x01",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16)
};
```

The ``test_vector`` expects the name of the algorithm and the type of it. The type can be  ``block_cipher`` or ``hash``.

The macro ``add_test_vector_data`` has the following prototype (for block ciphers):

```c
add_test_vector(<key>,
                <key size in bytes>,
                <text>,
                <ciphertext>,
                <plaintext>, // Maybe someone want to test data corruption cases so...
                <block size in bytes>)
```

Now you should edit the header ``tests/test_vectors.h`` and add the include statement:

```c
#include "foofish_test_vector.h"
```

In the header file ``tests/symmetric_ciphers_tests.h`` you should declare the following new test case:

```c
CUTE_DECLARE_TEST_CASE(kryptos_foofish_tests);
```

In the implementation file ``tests/symmetric_ciphers_tests.c`` you add the following "incantation" ;)...

```c
CUTE_TEST_CASE(kryptos_foofish_tests)
    kryptos_run_block_cipher_tests(foofish, KRYPTOS_FOOFISH_BLOCKSIZE);
CUTE_TEST_CASE_END
```

... and your basic test is ready to be called by the krypto's test monkey in ``tests/main.c``. There, you should add it:

```c
CUTE_TEST_CASE(kryptos_test_monkey)
(...)
    // INFO(Rafael): Cipher validation using official test vectors.
    (...)
    CUTE_RUN_TEST(kryptos_foofish_tests); // Invoking the foofish's basic test.

(...)
```

Since kryptos has an internal dsl for users you also should test if your new stuff is working well with this dsl.
In order to add a test related with this stuff, you should edit the file ``tests/dsl_tests.c``. More specifically,
the test case named as "kryptos_dsl_tests".

The code within ``kryptos_dsl_tests`` has a compiler directive:

```c
CUTE_TEST_CASE(kryptos_dsl_tests)
(...)
#ifdef KRYPTOS_C99

#endif
(...)
CUTE_TEST_CASE_END
```

Within this directive you should add tests for foofish using the ``kryptos_run_cipher`` macro, look:

```c
#ifdef KRYPTOS_C99
    (...)
    // FOOFISH ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(foofish, &task, "foofish", 7, kKryptosECB);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(foofish, &task, "foofish", 7, kKryptosECB);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // FOOFISH CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(foofish, &task, "foofish", 7, kKryptosCBC);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(foofish, &task, "foofish", 7, kKryptosCBC);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
    (...)
#endif
```

Only the modes ``ECB`` and ``CBC`` should be tested.

The last part to be edited is the file ``tests/hash_tests.c``. Inside the test case called ``kryptos_hmac_tests``, you
should add the following "incantation" :)...


```c
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd160, key, key_size, kKryptosCBC);
```

... congrats! You just added a new well tested stuff...

However, you also should ascertain that your new stuff is working well in kernel mode scenarios too. Then
you should add the following code into the file ``tests/kernel/dsl_tests.c``:

```c
KUTE_TEST_CASE(kryptos_dsl_tests)
(...)
#ifdef KRYPTOS_C99
    (...)
    // FOOFISH ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(foofish, &task, "foofish", 7, kKryptosECB);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(foofish, &task, "foofish", 7, kKryptosECB);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // FOOFISH CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(foofish, &task, "foofish", 7, kKryptosCBC);

    KUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(foofish, &task, "foofish", 7, kKryptosCBC);

    KUTE_ASSERT(task.out_size == data_size);
    KUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
    (...)
#endif
(...)
KUTE_TEST_CASE_END
```

Also into the file ``tests/kernel/hash_tests.c`` you should add the following code:

```
KUTE_TEST_CASE(kryptos_hmac_tests)
(...)
#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)
(...)
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd160, key, key_size, kKryptosCBC);
(...)
KUTE_TEST_CASE_END
```

Almost the same things done in user mode tests but in kernel mode if there is a wrong thing in your code it will cause
a kernel panic, reboot your machine, corrupt your repository, etc. So be sure about your work still in user mode before
enabling the kernel tests.

Now, it is real, congrats! Your stuff is being really tested according the project requirements. Your job is done!
