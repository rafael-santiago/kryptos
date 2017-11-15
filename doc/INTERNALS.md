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

