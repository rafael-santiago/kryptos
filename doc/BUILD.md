# Build instructions

In this document you find basic information about how to build the ``kryptos`` (a.k.a. libkryptos) besides advanced
build commands destinated for contributors.

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

Once ``Hefesto`` well-installed and running in your system. For building ``kryptos`` you should execute the following
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

## Advanced build commands for contributors

If you want to contribute, thank you! Maybe the following informations can be useful to you.

### Skipping the HMAC tests

Run the standard build tons of time can become pretty boring, because it is a kind of slow. When we are developing
sometimes we need to get a faster feedback. The slowest thing in the kryptos build is the compilation of the HMAC tests.
It can be explained due to the C macros expansions. However, there is a way of skipping the HMAC tests since the
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

The option that you should use is ``--quick-dh-tests`` and this options is enabled by default (take a look in the
``src/.ivk`` file). When you do not specify this build option the unit tests for Diffie-Hellman-Merkle will use ``256-bit``
secret values. As a result it will take longer to conclude the tests. Otherwise when you specify the build option
``--quick-dh-tests`` it will use ``8-bit`` secret values. As a result the test will be fast.

The explicity usage of this build option is pretty straightforward:

```
Sherlock@221B:~/src/kryptos/src# hefesto --quick-dh-tests
```

### Stressing the tests in order to see if you have introduced some undefined behavior

Sometimes little bad bugs can corrupt some data but instead of directly break with something it can indirectly
break a thing that you did not change anything. A good way of detecting this kind of behavior is executing
the build as follows:

```
Sherlock@221B:~/src/kryptos/src# hefesto --stress-tests --runnings-nr=100
```

This will compile the library and re-run the unit tests a hundred of times.

I usually like the following stress testing command line:

```
Sherlock@221B:~/src/kryptos/src# hefesto --no-hmac-tests --stress-tests \
> --runnings-nr=1024
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

The default build options are defined into the file ``src/tests/.ivk``. The **Table 2** gathers these options.

**Table 2**: The default build options for the unit tests.

|             **Option**                   |               **Description**                                                |
|:----------------------------------------:|:----------------------------------------------------------------------------:|
| ``--bin-output-dir=bin``                 | Defines where the binary will be generated.                                  |
| ``--obj-output-dir=o``                   | Defines where the object files will be generated.                            |
| ``--libraries=../../lib,cutest/src/lib`` | Defines paths of additional libraries.                                       |
| ``--ldflags=-lkryptos,-lcutest``         | Defines the default linker flags.                                            |
| ``--includes=../,cutest/src``            | Defines paths of additional include directories.                             |
| ``--bin-output-dir=../lib``              | Defines where the ar file will be generated.                                 |
| ``--obj-output-dir=o``                   | Defines where the object files will be generated.                            |
| ``--includes=./``                        | Defines the additional includes directories. This is a comma separated list. |
| ``--quick-dh-tests``                     | It speed up the Diffie-Hellman-Merkle tests.                                 |

## Are you searching for some build information not detailed here?

Please let me know more by opening an [issue](https://github.com/rafael-santiago/kryptos/issues). Thank you!

