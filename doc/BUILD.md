# Build instructions

In this document you find basic information about how to build ``kryptos`` (a.k.a. libkryptos) besides advanced
build commands intended for contributors.

## Cloning the kryptos repository

The simplest way of cloning the repository is as follows:

```
Mycroft@221B:~# git clone https://github.com/rafael-santiago/kryptos --recursive
```

The ``--recursive`` option will handle the git-submodules "complications".

## The build system

The ``kryptos`` build is based on my build system called [``Hefesto``](https://github.com/rafael-santiago/hefesto).
All instructions about how to install this build system can be found in its repository.

## How final users should build kryptos

Once ``Hefesto`` well installed and running in your system. For building ``kryptos`` you should execute the following
commands (supposing you have cloned your kryptos copy within ``~/src/kryptos``):

```
MrsHudson@221B:~/src/kryptos# cd src
MrsHudson@221B:~/src/kryptos/src# hefesto
```

The command above will compile the library and run its unit tests. The ``.a`` file will be created under the path
``../lib``:

```
MrsHudson@221B:~/src/kryptos/src# ls ../lib
libkryptos.a
```

All done!

## How to install the library and its headers

Pretty easy, being within the ``src`` sub-directory execute the following command:

```
MrsHudson@221B:~/src/kryptos/src# hefesto --install
```

To uninstall:

```
MrsHudson@221B:~/src/kryptos/src# hefesto --uninstall
```

### Building the kernel mode version

``Kryptos`` has some parts designed to be used in kernel mode. Until now it supports ``FreeBSD`` and ``Linux``. However, there is no "kernel mode" build.
The library was written taking in consideration that the users will compile ``kryptos`` together with their own stuff (as a monolithic project).
The only thing you should do is define the macro ``KRYPTOS_KERNEL_MODE`` and ``kryptos`` will "become" a kernel mode stuff.

You should use some features with care. Personally I find that execute some features in kernel mode is overkill. You should do only the
most "straightforward" cryptographic stuff in kernel but you are free... But take my point in consideration. ;)

## Advanced build commands for contributors

If you want to contribute, thank you! Maybe the following information can be useful to you.

### Skipping the HMAC tests

Run the standard build tons of time can become pretty boring, because it is a kind of slow. When we are developing
sometimes we need to get a faster feedback. The slowest thing in the kryptos build is the compilation of the HMAC tests.
It is because the C macros expansions. However, there is a way of skipping the HMAC tests since the
compile-time and this can be done by calling ``Hefesto`` as follows:

```
Sherlock@221B:~/src/kryptos/src# hefesto --no-hmac-tests
```

### Skipping the Diffie-Hellman-Merkle exchange tests

The Diffie-Hellman-Merkle tests can be skipped as follows:

```
Sherlock@221B:~/src/kryptos/src# hefesto --skip-dh-xchg-tests
```

### Speeding up the Diffie-Hellman-Merkle exchange tests

The option you should use is ``--quick-dh-tests`` and this option is enabled by default (take a look in the
``src/.ivk`` file). When you do not specify this build option, the unit tests for Diffie-Hellman-Merkle will use ``256-bit``
secret values. As a result it will take longer to conclude the tests. Otherwise when you specify the build option
``--quick-dh-tests`` it will use ``8-bit`` secret values. As a result the test will be fast.

The usage of this build option through command line is pretty straightforward:

```
Sherlock@221B:~/src/kryptos/src# hefesto --quick-dh-tests
```

### Skipping the OAEP tests from some PK algorithms

The OAEP tests not only test the data encryption and its correct data decryption. The test also simulates invalid data passing.
Due to it the test can be slow. To speed up the build you can skip the OAEP test stuff as follows:

```
Sherlock@221B:~/src/kryptos/src# hefesto --skip-rsa-oaep-tests \
> --skip-elgamal-oaep-tests
```

### Skipping the digital signature tests

The digital signature tests also can be time consuming. The following command line skips them:

```
Sherlock@221B:~/src/kryptos/src# hefesto --skip-rsa-signature-tests \
> --skip-dsa-signature-tests
```

### Stressing the tests in order to see if you have introduced some undefined behavior

Sometimes little bad bugs can corrupt some data but instead of directly break something it can indirectly
introduce a bug into a place where you did not change anything. A good way of detecting this kind of
unexpected behavior is by executing the build as follows:

```
Sherlock@221B:~/src/kryptos/src# hefesto --stress-tests --runnings-nr=100
```

This will compile the library and re-run the unit tests a hundred of times.

I usually like the following stress testing command line:

```
Sherlock@221B:~/src/kryptos/src# hefesto --no-hmac-tests --stress-tests \
> --runnings-nr=1024 --skip-rsa-oaep-tests --skip-elgamal-oaep-tests \
> --skip-rsa-signature-tests --skip-dsa-signature-tests
```

When you are dealing with random bugs this is a friendly way of trying to reproduce the bug.

### The default build options (library)

The default build options are defined into the file ``src/.ivk``. The **Table 1** gathers these options.

**Table 1**: The default build options.

|          **Option**         |                    **Description**                                             |
|:---------------------------:|:------------------------------------------------------------------------------:|
| ``--bin-output-dir=../lib`` |   Defines where the ar file will be generated.                                 |
| ``--obj-output-dir=o``      |   Defines where the object files will be generated.                            |
| ``--includes=./``           |   Defines the additional includes directories. This is a comma separated list. |
| ``--quick-dh-tests``        |   Speeding up the Diffie-Hellman-Merkle tests.                                 |


### The default build options (unit tests)

The default build options are defined into the file ``src/tests/.ivk``. The **Table 2** gathers these options and also
additional options. The **Table 3** gathers the options related with the kernel mode tests.

**Table 2**: The default and additional build options of the unit tests.

|             **Option**                   |               **Description**                                                |
|:----------------------------------------:|:----------------------------------------------------------------------------:|
| ``--bin-output-dir=bin``                 | Defines where the binary will be generated.                                  |
| ``--obj-output-dir=o``                   | Defines where the object files will be generated.                            |
| ``--libraries=../../lib,cutest/src/lib`` | Defines paths of additional libraries.                                       |
| ``--ldflags=-lkryptos,-lcutest``         | Defines the default linker flags.                                            |
| ``--includes=../,cutest/src``            | Defines paths of additional include directories.                             |
| ``--kernel-mode-tests``                  | Requests the kernel mode tests execution.                                    |
| ``--no-hmac-tests``                      | Does not include the HMAC tests in the test binary. Speeds up the build.     |
| ``--skip-dh-xchg-tests``                 | Skips the Diffie-Hellman-Merkle exchange tests.                              |
| ``--skip-rsa-oaep-tests``                | Skips the RSA-OAEP tests. The tests execution becomes faster.                |
| ``--skip-elgamal-oaep-tests``            | Skips the Elgamal-OAEP tests. The tests execution becomes faster.            |
| ``--dh-use-q-size``                      | Enables the DH tests to use recommended bit sizes for s parameters (slower)  |
| ``--skip-rsa-signature-tests``           | Skips the RSA signature tests. The tests execution becomes faster.           |
| ``--skip-dsa-signature-tests``           | Skips the DSA signature tests. The tests execution becomes faster.           |
| ``--mk-samples``                         | Requests the code samples build.                                             |
| ``--toolset=<gcc or clang>``             | Defines the C compiler (the default is ``GCC``).                             |
| ``--language=<c or cc>``                 | Defines the compiler's language (samples only). Obviously the default is ``c``. |

**Table 3**: The build options for the kernel mode unit tests.

|             **Option**                   |               **Description**                                                |
|:----------------------------------------:|:----------------------------------------------------------------------------:|
| ``--clean``                              | Removes the object files generated by the kernel mode tests.                 |
| ``--no-hmac-tests``                      | Does not include the HMAC tests in the test binary. Speeds up the build.     |
| ``--skip-dh-xchg-tests``                 | Skips the Diffie-Hellman-Merkle exchange tests.                              |
| ``--skip-rsa-oaep-tests``                | Skips the RSA-OAEP tests. The tests execution becomes faster.                |
| ``--skip-elgamal-oaep-tests``            | Skips the Elgamal-OAEP tests. The tests execution becomes faster.            |
| ``--dh-use-q-size``                      | Enables the DH tests to use recommended bit sizes for s parameters (slower)  |
| ``--skip-rsa-signature-tests``           | Skips the RSA signature tests. The tests execution becomes faster.           |
| ``--skip-dsa-signature-tests``           | Skips the DSA signature tests. The tests execution becomes faster.           |

### How the kernel mode tests are executed

The kernel mode tests are almost the same of the user mode tests. However, the correctness of the ciphers are not verified since
it was already done in user mode. The execution is pretty straightforward: a loadable kernel module is generated and inserted into
the kernel. If it was successfully loaded it means that all is ok, otherwise some issues were found.

Beware: A ``LKM`` is inserted into the kernel. Thus, invalid memory accesses, double frees will result in kernel panics. If you
have made some changes and you are not so sure about them, backup your work before continuing and happy kernel hacking! ;)

In ``Linux``, during kernel mode tests you probably will receive some RCU CPU stall warnings, this is "normal" because the
kernel test executes some insane and uncommon tasks (considering the current context). Things like running several PK crypto
primitives and protocols. Warnings like "kthread starved for N jiffies" are expected, so calm down.

In ``FreeBSD``, you will experience a big and frightening freeze but the machine not rebooting you are safe. It means
that all tests were passed.

Sometimes ``make`` (the build system used by the two supported platforms) does not detect correctly changes and as a result
some piece of code that should be recompiled remains untouched. If you have been experiencing some weird errors during the
kernel mode tests, your tests have been breaking where it should not... try to clean up the kernel objects. In order to do
it you must be within the ``tests/kernel`` sub-directory, once there run the command ``hefesto --clean`` and re-run the
build.

### The GCC is being killed during the build process

I only observed it when compiling kernel stuff (so, in Linux). I was experiencing the following run-time error message:

```
gcc: internal compiler error: Killed (program cc1)
```

This have been occurred more precisely when compiling the source file ``tests/kernel/hash_tests.c``. This module has tons of
macro stuff so the C pre-processor seems to be defeated by them... The solution is skip the HMAC tests, btw where the C
pre-processor is abused. Try to re-run the kernel-mode tests as follows:

```
Sherlock@221B:~/src/kryptos/src/tests/kernel# hefesto --no-hmac-tests
```

or...

```
Sherlock@221B:~/src/kryptos/src# hefesto --kernel-mode-tests --no-hmac-tests
```

It depends on your location in the project's source tree.

## Are you searching for some build information not detailed here?

Please let me know more by opening an [issue](https://github.com/rafael-santiago/kryptos/issues). Thank you!

