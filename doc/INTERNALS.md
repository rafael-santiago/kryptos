# Libkryptos developer's manual

**Abstract**: This document is intended for contributors. Here you will find information about how to code new stuff besides maintaining the current ones.
Due to it the reader is assumed as a medium to advanced C programmer and also a "cryptoholic" ;)

## Contents

- [The libkryptos repo tree layout](#the-libkryptos-repo-tree-layout)
- [Some meaningful header files](#some-meaningful-header-files)
    - [src/kryptos_types.h](#srckryptos_typesh)
    - [src/kryptos.h](#srckryptosh)
    - [src/kryptos_mp.h](#srckryptos_mph)
    - [src/kryptos_padding.h](#srckryptos_paddingh)
    - [src/kryptos_pem.h](#srckryptos_pemh)
    - [src/kryptos_task_check.h](#srckryptos_task_checkh)
    - [src/kryptos_hash_common.h](#srckryptos_hash_commonh)
- [Okay, let's add a new block cipher called "foofish" to libkryptos...](#okay-lets-add-a-new-block-cipher-called-foofish-to-libkryptos)
- [Okay, let's write some tests for "foofish"...](#okay-lets-write-some-tests-for-foofish)
- [Steps to add a new hash algorithm based on Merkle-Damgard construction](#steps-to-add-a-new-hash-algorithm-based-on-merkle-damgard-construction)
- [Adding a new stream cipher](#adding-a-new-stream-cipher)
- [Encoding algorithms](#encoding-algorithms)

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
created within ``libkryptos/samples``. Supposing you ran the build using this command: ``hefesto --mk-samples``. As a result you will get the
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

[Back](#contents)

## Some meaningful header files

Some of the detailed headers include their own implementation files. A header implementation file usually has the same name of
the header file but the file extension is ``.c`` instead of ``.h``.

For the library code never include using "..."  always use ``<...>``.

[Back](#contents)

### src/kryptos_types.h

This header file contains the main definitions of some constants. It also includes a detection stuff related with cpu word size
and the C language's version (if the compiler actually supports C99 or not). Still it also includes some compiler directives
driven by the macro ``KRYPTOS_KERNEL_MODE``. This macro signales if the current compilation task is being done for a user
(the default) or a kernel project.

The two main types (structs) defined within this header files are: ``kryptos_task_ctx`` and ``kryptos_mp_value_t``.

The ``kryptos_types.h`` file also defines some macros that make up the developer's internal dsl. This internal dsl
makes easier the addition of new features (more on later).

[Back](#contents)

### src/kryptos.h

This header file merges the whole library and exposes some final user's macros. In fact, this is the header file that
the library users will include in their own stuff. By including this header the users will be able to access any relevant
cryptographic feature.

When you add some new cipher you must include the header of this new cipher in ``kryptos.h``.

Also when you extend the kryptos user's internal dsl, the new dsl stuff must be defined within this header file.

[Back](#contents)

### src/kryptos_mp.h

This header file contains all function prototypes/macros related with multi-precision arithmetic. This header exports important
functions for PK crypto.

[Back](#contents)

### src/kryptos_padding.h

This header file contains all function prototypes related with padding tasks. Actually it is quite important for block ciphers.

[Back](#contents)

### src/kryptos_pem.h

This header file exposes some functions for PEM buffer reading and writing. This is very important for PK crypto, because all
PK crypto algorithms implemented in kryptos expects and returns their data using the PEM format.

[Back](#contents)

### src/kryptos_task_check.h

Any interaction by the users with the library is represented as a task, due to it before doing the requested task
the library must verify if the current task makes sense or not. The ``kryptos_task_check.h`` exports some important task
check entry points. This also could be understood as a "task compiler".

[Back](#contents)

### src/kryptos_hash_common.h

If you will add a new hash algorithm and this algorithm uses Merkle-Damgard construction, the ``kryptos_hash_common.h``
exports some useful functions that will make your implementation easier (more on later).

[Back](#contents)

## Okay, let's add a new block cipher called "foofish" to libkryptos...

Now let's suppose you read about a brand new awesome, super-secure block cipher called foofish and you want to add it to
kryptos.

The foofish cipher encrypts blocks of 128-bits, it needs a user's key of 256-bits in order to expand the final key (generate
the round sub-keys).

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
this macro. This is a way of keeping the stuff sanitized and self contained.

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

The struct ``kryptos_foofish_subkeys`` is abstracted but it will contain the final key used in data encryption/decryption.

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
those macros avoid using loops in order to load the bytes into the state and as a result the code tends to drop out any kind
of useless instructions.

All you need to use the ``kryptos_ld_user_key_*`` macros are some local variables. Do not worry about their initialization,
the ``kryptos_ld_user_key_prologue`` does it:

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
any primitive type not only 32-bit data, this is just an example.

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

The first thing to do in order to take advantage of it is to define a function pointer type expressing the
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
                                    kryptos_foofish_block_encrypt, /* No additional steps */,
                                    kryptos_foofish_block_decrypt, /* No additional steps */,
                                    KRYPTOS_FOOFISH_BLOCKSIZE,
                                    foofish_cipher_epilogue,
                                    outblock,
                                    foofish_block_processor(outblock, &sks),
                                    NULL)
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
                                    <the block processing statement>,
                                    <E function additional argument>)
```

The encrypt and decrypt block functions in foofish return the data into the own input block. Due to it the block
processing statement is simply ``foofish_block_processor(outblock, &sks)``.

Do not worry about giving support for the supported cipher modes. The "incantation" above does this job for you.

There is also a "magic" to implement the cipher setup function:

```c
    KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(foofish,
                                             kKryptosCipherFOOFISH,
                                             KRYPTOS_FOOFISH_BLOCKSIZE)
```

Notice that "setup" in kryptos is not the key expansion. The setup phase is when the user supplies basic information
for the desired encryption/decryption task. This will load the task context with the relevant supplied data.

Since kryptos implements the Galois counter mode, even if your block cipher does not support it, you still need to
implement the E function used by this mode. In cases where the GCM is not applicable, the E function should return
the kKryptosNoSupport error code.

E functions can have the following prototypes:

```c
    kryptos_task_result_t kryptos_type1_e(kryptos_u8_t **h, size_t *h_size,
                                            kryptos_u8_t *key, size_t key_size, void *additional_arg);
```

Or:

```c
    kryptos_task_result_t kryptos_type2_e(kryptos_u8_t **h, size_t *h_size,
                                          kryptos_u8_t *key, size_t key_size, additional_args);
```

The type1 is suitable for block cipher without any additional parameter. The type2 is suitable for block cipher that
receive additional arguments.

Fortunately the kryptos DSL includes statements to save you from always remembering those tricky prototypes:

```c
    KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(type1)
```

Or:

```c
    KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_GCM_E(type2, void *arg)
```

In GCM an E function is a function that encrypts a zeroed block by using the user key. This is pretty mechanical, thus the DSL
also provides conveniences for implementing those E functions:

```c
    KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(type1)
```

Or:

```c
    KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_GCM_E(type2, key, key_size, void *arg, ktask,
                                           {
                                                type2_setup(ktask, key, kKryptosECB)
                                           })
```

For ciphers without support there are two functions. One for ciphers without additional parameters and another for ciphers with
additional parameters:

```c
    KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(type1)
```

```c
    KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_GCM_E_NO_SUPPORT(type2, void *arg)
```

The ``foofish`` cipher encrypts 128-bit blocks so it supports ``GCM``. In its implementation file we need to implement an E
function. Just by doing the following:

```c
    KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(foofish)
```

I showed you the way of implementing the three important components of a block cipher in a more automated way, however,
you also need to make those functions visible outside the block cipher module. In order to do it you should include
the following basic content into the ``kryptos_foofish.h`` header file:

```c
#ifndef KRYPTOS_KRYPTOS_FOOFISH_H
#define KRYPTOS_KRYPTOS_FOOFISH_H 1

#include <kryptos_types.h>

#define KRYPTOS_FOOFISH_BLOCKSIZE 16

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(foofish)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(foofish)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(foofish)

#endif
```

The macro ``KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP`` will make visible the function
``kryptos_foofish_setup(kryptos_task_ctx *, kryptos_u8_t *, const size_t, const kryptos_cipher_mode_t)``.
The macro ``KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR`` will make visible the function
``kryptos_foofish_cipher(kryptos_task_ctx **)``.
The macro ``KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E`` will make visible the function
``kryptos_foofish_e(kryptos_u8_t **h, size_t *h_size, kryptos_u8_t *key, size_t key_size, void *additional_arg)``

The macro ``KRYPTOS_FOOFISH_BLOCKSIZE`` is also important it states in bytes the size of processed blocks.

By doing it foofish also can be called by the user macro ``kryptos_run_cipher``.

The cipher module is done, but you still need to teach the task check module how to handle this new cipher, otherwise
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

All done! Now the new cipher is actually added into kryptos. However, you should not add a new stuff without adding
tests for it too.

[Back](#contents)

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

Inside this directive block you should add tests for foofish using the ``kryptos_run_cipher`` macro, look:

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
    (...)
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd160, key, key_size, kKryptosECB);
    (...)

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha512, key, key_size, kKryptosCBC);
    (...)
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd160, key, key_size, kKryptosCBC);
    (...)
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

```c
KUTE_TEST_CASE(kryptos_hmac_tests)
(...)
#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)
(...)
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha512, key, key_size, kKryptosECB);
    (...)
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, ripemd160, key, key_size, kKryptosECB);
    (...)

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, foofish, sha512, key, key_size, kKryptosCBC);
    (...)
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

Now, it is real, congrats! Your stuff is being really tested according to the project requirements. Your job is done!
Let's celebrate coding a little more...

[Back](#contents)

## Steps to add a new hash algorithm based on Merkle-Damgard construction

Well it is almost the same thing done with block ciphers. Let's analyse the files ``src/kryptos_sha1.[ch]``.

The following content is what you will find within ``kryptos_sha1.h``:

```c
/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SHA1_H
#define KRYPTOS_KRYPTOS_SHA1_H 1

#include <kryptos_types.h>

KRYPTOS_DECL_HASH_PROCESSOR(sha1, ktask)

KRYPTOS_DECL_HASH_SIZE(sha1)

KRYPTOS_DECL_HASH_INPUT_SIZE(sha1)

#endif
```

As you can see the header file basically uses some internal dsl macros in order to automate the declaration of some meaningful
entry points.

- KRYPTOS_DECL_HASH_PROCESSOR(<hash algorithm name, <kryptos_task_ctx **>): creates the function ``kryptos_<hname>_hash(kryptos_task_ctx **)`` and this function is the main entry point to the hash algorithm.
- KRYPTOS_DECL_HASH_SIZE(<hash algorithm name>): creates the function ``kryptos_<hname>_hash_size(void)`` and this function must return the size of the output hash in bytes.
- KRYPTOS_DECL_HASH_INPUT_SIZE(<hash algorithm name>): create the function ``kryptos_<hname>_hash_input_size(void)`` and this function must return the size of the input block in bytes.

Now let's see some relevant parts of the implementation file ``kryptos_sha1.c``:

```c
// The hash processor is accessible outside this module but the message processor is not. The message processor
// is responsible for processing the whole message block-by-block. So here we are declaring this static function.
KRYPTOS_DECL_HASH_MESSAGE_PROCESSOR(sha1, kryptos_sha1_ctx, ctx)

// The message processor implementation requires:
//      - The algorithm name.
//      - The context T that gathers all algorithm stuff (states, input block, etc).
//      - The name of the typed context T variable.
//      - How many bytes are processed "per block".
//      - How many positions the input array has. -> 16 x 32 = 512-bits
//      - How many bits each input array item has. -----> 32
//      - The algorithm initialization code stuff (for the current block).
//      - The block processing stuff.
//      - The block decision table (more on later).
KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR(sha1, kryptos_sha1_ctx, ctx,
                                    KRYPTOS_SHA1_BYTES_PER_BLOCK,
                                    16, 32,
                                    kryptos_sha1_init(ctx),
                                    kryptos_sha1_do_block(ctx),
                                    kryptos_sha1_block_index_decision_table)

// The implementation is quite straightforward: Inform the algorithm name and
// how many bytes there are in its output.
KRYPTOS_IMPL_HASH_SIZE(sha1, KRYPTOS_SHA1_HASH_SIZE)

// The implementation is quite straightforward: Inform the algorithm name and
// how many bytes there are in its input.
KRYPTOS_IMPL_HASH_INPUT_SIZE(sha1, KRYPTOS_SHA1_BYTES_PER_BLOCK)

// This is the hash processor implementation and it requires:
//      - The algorithm name.
//      - The typed (kryptos_task_ctx **) variable name.
//      - The context T that gathers all algorithm stuff (states, input block, etc).
//      - The name of the typed context T variable.
//      - The name of the escape/epilogue label.
//      - The algorithm initial setup stuff.
//      - The message processor statement 'kryptos_sha1_process_message'.
//        It was implemented by the KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR macro.
//      - The statements necessary to produce a raw byte output.
//      - The statemenets necessary to produce a hexadecimal output.
KRYPTOS_IMPL_HASH_PROCESSOR(sha1, ktask, kryptos_sha1_ctx, ctx, sha1_hash_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3; // INFO(Rafael): Should be expressed in bits.
                            },
                            kryptos_sha1_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(KRYPTOS_SHA1_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha1_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA1_HASH_SIZE;
                                kryptos_cpy_u32_as_big_endian(     (*ktask)->out, 20, ctx.state[0]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  4, 16, ctx.state[1]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  8, 12, ctx.state[2]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 12,  8, ctx.state[3]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 16,  4, ctx.state[4]);
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_SHA1_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha1_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA1_HASH_SIZE << 1;
                                kryptos_u32_to_hex(     (*ktask)->out, 41, ctx.state[0]);
                                kryptos_u32_to_hex((*ktask)->out  + 8, 33, ctx.state[1]);
                                kryptos_u32_to_hex((*ktask)->out + 16, 25, ctx.state[2]);
                                kryptos_u32_to_hex((*ktask)->out + 24, 17, ctx.state[3]);
                                kryptos_u32_to_hex((*ktask)->out + 32,  9, ctx.state[4]);
                            })

```

Yes, at first glance it seems quite trick but believe in me, those tricks presented above will save you hours of work. The
buffer parsing functions are all well tested and all you should do is to focus in the hash algorithm implementation itself.

Maybe the most misterious trinket presented above is the 'block decision table'... For SHA-1 this is the block decision
table "layout":

```c
static size_t kryptos_sha1_block_index_decision_table[KRYPTOS_SHA1_BYTES_PER_BLOCK] = {
     0,  0,  0,  0,
     1,  1,  1,  1,
     2,  2,  2,  2,
     3,  3,  3,  3,
     4,  4,  4,  4,
     5,  5,  5,  5,
     6,  6,  6,  6,
     7,  7,  7,  7,
     8,  8,  8,  8,
     9,  9,  9,  9,
    10, 10, 10, 10,
    11, 11, 11, 11,
    12, 12, 12, 12,
    13, 13, 13, 13,
    14, 14, 14, 14,
    15, 15, 15, 15
};
```

This table will help the input buffer parsing functions by putting the current byte into the right word and also by padding it
correctly. For SHA-1 the input is expressed by the following struct:

```c
struct kryptos_sha1_input_message {
    kryptos_u32_t block[16]; // each array position can hold 4-bytes.
};
```

So the input bytes [0], [1], [2] and [3] will be loaded into block[0]. The input bytes [60], [61], [62] and [63] will
be loaded into block[15]. Yep! Now you understood and now it seems pretty boring, huh? :)

The Merkle-Damgard construction also needs a padding step during the current block processing (if the current is the last block)
and depeding on the size of the block this padding must happen in "two acts". Look the SHA-1 block processing code:

```c
static void kryptos_sha1_do_block(struct kryptos_sha1_ctx *ctx) {
    kryptos_u32_t A, B, C, D, E, TEMP, Fx, Kx;
    kryptos_u32_t W[80];
    size_t t;

    if (ctx->curr_len < KRYPTOS_SHA1_BYTES_PER_BLOCK) {
        kryptos_hash_apply_pad_on_u32_block(ctx->input.block, 16,
                                            kryptos_sha1_block_index_decision_table,
                                            ctx->curr_len, ctx->total_len, &ctx->paddin2times, 0x80,
                                            KRYPTOS_SHA1_LEN_BLOCK_OFFSET);
    }

(...)

    if (ctx->paddin2times) {
        kryptos_hash_ld_u8buf_as_u32_blocks((kryptos_u8_t *)"", 0, ctx->input.block, 16,
                                            kryptos_sha1_block_index_decision_table);
        kryptos_sha1_do_block(ctx);
    }
}
```

The function ``kryptos_hash_apply_pad_on_u32_block`` signales if this padding operation will happen in "two acts" or not
by setting the int pointer ``&ctx->paddin2times``.

To test the algorithm you also should create a test vector header file under ``tests/``. This is the content from
``tests/sha1_test_vector.h``:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA1_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA1_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha1, hash) = {
    add_test_vector_data("", 0,
                         "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", 40,
                         "\xDA\x39\xA3\xEE\x5E\x6B\x4B\x0D\x32\x55\xBF\xEF\x95\x60\x18\x90\xAF\xD8\x07\x09", 20),
    add_test_vector_data("a", 1,
                         "86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8", 40,
                         "\x86\xF7\xE4\x37\xFA\xA5\xA7\xFC\xE1\x5D\x1D\xDC\xB9\xEA\xEA\xEA\x37\x76\x67\xB8", 20),
    add_test_vector_data("abc", 3,
                         "A9993E364706816ABA3E25717850C26C9CD0D89D", 40,
                         "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D", 20),
    add_test_vector_data("message digest", 14,
                         "C12252CEDA8BE8994D5FA0290A47231C1D16AAE3", 40,
                         "\xC1\x22\x52\xCE\xDA\x8B\xE8\x99\x4D\x5F\xA0\x29\x0A\x47\x23\x1C\x1D\x16\xAA\xE3", 20),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "32D10C7B8CF96570CA04CE37F2A19D84240D3A89", 40,
                         "\x32\xD1\x0C\x7B\x8C\xF9\x65\x70\xCA\x04\xCE\x37\xF2\xA1\x9D\x84\x24\x0D\x3A\x89", 20),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "84983E441C3BD26EBAAE4AA1F95129E5E54670F1", 40,
                         "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1", 20)
};

#endif

```

The ``add_test_vector_data`` expects the input data, input data size, the expected hash in hexadecimal, the size of this
hexadecimal data, the expected hash in raw bytes, the amount of expected bytes.

You also should include the new test vector header file into ``tests/test_vectors.h``.

In ``tests/hash_tests.h`` you need to declare two new test cases related with the hash algorithm:

```c
(...)
CUTE_DECLARE_TEST_CASE(kryptos_sha1_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha1_hash_macro_tests);
(...)
```

Now into ``tests/hash_tests.c`` you implement them as follows:

```c
CUTE_TEST_CASE(kryptos_sha1_tests)
    kryptos_run_hash_tests(sha1, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha1_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha1, 64, 20);
CUTE_TEST_CASE_END
```

The macros expect the algorithm name, the size of the input in bytes (64 * 8 = 512-bits) and the size in bytes of the hash
output.

If you have implemented a new hash algorithm is also important extend the HMAC tests. These tests are located into
``tests/hash_tests.c``. There you should include for each supported cipher a test using the new hash algorithm with
ECB and CBC modes:

```c
CUTE_TEST_CASE(kryptos_hmac_tests)

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)
    kryptos_u8_t *key = "nooneknows";
    size_t key_size = 10;
    int feal_rounds = 8, rc2_T1 = 64, saferk64_rounds = 6;
    kryptos_camellia_keysize_t camellia_size;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosECB);
    (...)
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosCBC);
    (...)
CUTE_TEST_CASE_END
```

In order to actually execute the hash algorithm tests you should call it from the kryptos' test monkey in ``tests/main.c``:

```c
CUTE_TEST_CASE(kryptos_test_monkey)
(...)
    // INFO(Rafael): Hash validation (also official data).
    CUTE_RUN_TEST(kryptos_sha1_tests);
    CUTE_RUN_TEST(kryptos_sha1_hash_macro_tests);
(...)
CUTE_TEST_CASE_END
```

The kernel tests for hash algorithms only verify the result for the "abc" hashing. So you should edit the file
``src/tests/kernel/hash_tests.c`` and in test case ``kryptos_hash_tests`` to add your new test code stuff.

In kernel mode, still in the file ``src/tests/kernel/hash_tests.c``, you should edit the test case ``kryptos_hmac_tests``
and add the verifying macros for your new hash algorithm. The same thing done in user mode tests.

[Back](#contents)

## Adding a new stream cipher

Stream ciphers do not have an internal dsl macro that abstracts the cipher entry points implementation. So if you want
to probe what is done under the hood the best way is by reading a stream cipher implementation. The processing of it
is pretty straightforward: just handle the data byte-by-byte.

The following code was extracted from ``src/kryptos_arc4.h``:

```c
(...)
void kryptos_arc4_cipher(kryptos_task_ctx **ktask);

void kryptos_arc4_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size);
(...)
```

Any symmetric cipher (I said any) must have those two entry points listed above.

The function ``kryptos_<cipher-name>_cipher(kryptos_task_ctx **ktask)`` is called during encryption and also decryption.
This function receives the input, the user key and then it processes all data and outputs some new data (I meant it
allocates some bytes pointed by ``(*ktask)->out`` and of course indicates the size of the output in ``(*ktask)->out_size``).
This function also sets the task result and the result verbose (when it should be done). Before performing the data
encryption/decryption this function must ascertain that all task is well expressed, it can be done by the following code
snippet:

```c
    // CLUE(Rafael): Always put this code at the beginning of a cipher function.
    //               Usually, anything else must not be done before.
    if (kryptos_task_check(ktask) == 0) {
        return;
    }
```

The function ``kryptos_<cipher-name>_setup(kryptos_task_ctx *ktask, '.*')`` is called before calling the
encryption/decryption entry point. Usually, this function receives the user key, its length and sometimes more
additional data according to the related algorithm. All received data must be referenced by the ``(kryptos_task_ctx *)``
variable. This function also must set the ``cipher`` field from ``(kryptos_task_ctx *)`` to the expected internal
algorithm constant.

[Back](#contents)

## Encoding algorithms

The addition of new encoding algorithms are automated by some internal dsl macros.

Let's take the header file ``src/kryptos_uuencode.h``:

```c
/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_UUENCODE_H
#define KRYPTOS_KRYPTOS_UUENCODE_H 1

#include <kryptos_types.h>

KRYPTOS_DECL_ENCODING_SETUP(uuencode, ktask);

KRYPTOS_DECL_ENCODING_PROCESSOR(uuencode, ktask)

#endif
```

About the macro ``KRYPTOS_DECL_ENCODING_SETUP``:

```c
    KRYPTOS_DECL_ENCODING_SETUP(<encoding name>,
                                <the name of the (kryptos_task_ctx *) typed variable>)
```

About the macro ``KRYPTOS_DECL_ENCODING_PROCESSOR``:

```c
    KRYPTOS_DECL_ENCODING_PROCESSOR(<encoding name>,
                                    <the name of the (kryptos_task_ctx **) typed variable>)

```

Now the implementation of those to macros extracted from ``src/kryptos_uuencode.c`` implementation file:

```c
    KRYPTOS_IMPL_ENCODING_SETUP(uuencode, ktask, kKryptosEncodingUUENCODE);

    KRYPTOS_IMPL_ENCODING_PROCESSOR(uuencode, kKryptosEncodingUUENCODE, ktask,
                                    kryptos_uuencode_buffer_processor,
                                    uuencode_buffer_processor,
                                    kryptos_uuencode_encode_buffer,
                                    kryptos_uuencode_decode_buffer,
        (*ktask)->out = uuencode_buffer_processor((*ktask)->in, (*ktask)->in_size, &(*ktask)->out_size))
```

About the macro ``KRYPTOS_IMPL_ENCODING_SETUP``:

```c
    KRYPTOS_IMPL_ENCODING_SETUP(<encoding name>,
                                <the name of the (kryptos_task_ctx **) typed variable>,
                                <the internal constant representing the encoding algorithm>)
```

Finally, about the macro ``KRYPTOS_IMPL_ENCODING_PROCESSOR``:

```c
    KRYPTOS_IMPL_ENCODING_PROCESSOR(<encoding name>,
                                    <the internal constant representing the encoding algorithm>,
                                    <the name of the (kryptos_task_ctx **) typed variable>,
                                    <the buffer processor function type T>,
                                    <the name of the typed T buffer processor variable>,
                                    <the buffer processor encoder>,
                                    <the buffer processor decoder>,
                                    <the processing statement or statements>)

```

Piece of cake! All encoding algorithms are pretty boring because they just receive some data and spit some data
based on the input. Due to it all four presented macros will cover all or at least almost all the new encoding stuff
you need to add here in this library.

New constants for encoding algorithms must be added into the ``kryptos_encoding_t`` typed enum defined in
``src/kryptos_types.h``.

[Back](#contents)
