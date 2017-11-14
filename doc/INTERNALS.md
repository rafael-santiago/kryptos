# Libkryptos developer's manual

**Abstract**: This document is intended for contributors. Here you will find informations about how to code new stuff besides maintaining the current ones.
Due to it is assumed that the reader has a medium to advanced C knowledge.

## The libkryptos repo tree layout

The repository tree has the following layout:

```
    libkryptos/         <-------------- Root directory (duh).
        doc/            <-------------- Sub-directory intended to documentation stuff.
        etc/            <-------------- Sub-directory intended to miscellaneous stuff.
        src/            <-------------- Sub-directory intended to the main library source code.
            samples/    <-------------- Sub-directory intended to the sample programs.
            tests/      <-------------- Sub-directory intended to the unit tests for the 'src' stuff (user mode).
                cutest/ <-------------- This is the sub-directory of the adopted unit test library.
                kernel/ <-------------- Sub-directory intended to the unit tests for the 'src' stuff (kernel mode).
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
            o/          <-------------- Object files sub-directory (main source code).
            samples/
                    o/  <-------------- Object files sub-directory (samples source code).
            tests/
                cutest/
                kernel/
```

When you also request the kernel mode tests the native kernel's build system will create the object files directly within the source code's sub-directory
(lib and tests source [tests/kernel/*]).

## Some meaningful header files

