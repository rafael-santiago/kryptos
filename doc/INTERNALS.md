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

Now let's suppose you read about a brand new awesome, super-secure block cipher called foofish and want to add it to
kryptos.

The foofish cipher encrypts blocks of 128-bits, this needs a user's key of 256-bits in order to expand the final key (generate
the sub-keys).

The first thing that you should do is define a new constant into the typed enum called ``kryptos_cipher_t``. This enum
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
    kKryptosCipherFOOFISH, // Nice, you should respect the order: stream cipher, block ciphers, pk stuff.
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
