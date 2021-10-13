# Code style guide

This is a not exhaustive description of the code style that I have been using for this project. Anyway, if you are intending to contribute, please,
read this document first. I personally like some points present in [pike's style](https://doc.cat-v.org/bell_labs/pikestyle).

This is not an absolute truth (a.k.a. unicorn) but this is the truth that I have been taking into consideration.

## Contents

- [Comments](#comments)
- [Code constructions](#code-constructions)
    - [If-statement](#if-statement)
    - [While-statement](#while-statement)
    - [Do/while-statement](#do/while-statement)
    - [Switches](#switches)
    - [Expressions](#expressions)
    - [Functions](#functions)
    - [Pointers](#pointers)
    - ["String" terminator](#string-terminator)
    - [Gotos](#gotos)
    - [Macros](#macros)
    - [Unit tests](#unit-tests)
- [Use inclusive and neutral language](#use-inclusive-and-neutral-language)

## Comments

It is necessary when is necessary. Try do not think like a blasé "bodisatva coder" who likes to repeat "uh! the code must speak by itself".
You are dealing with cryptography, so things tend to become tricky. A good comment can save time and avoid misunderstanding
and improper improvements by other people.

A good way of commenting is by identifying yourself using meaningful short labels. The general idea is: *LABEL(YourNameOrNickname): blah, blah, blah.*.
Take a look at the **Table 1** to know more about those labels and their proper usage.

**Table 1**: Recommended comment labels.

|       **Label**        |                                                **What does it mean?**                                                                       |
|:----------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------:|
|   ``INFO``             |  instructs someone about something                                                                                                          |
|   ``WARN``             |  warns someone about something                                                                                                              |
|   ``CLUE``, ``TIP``    |  gives the tips of an intricate passage of your work (in other words do not mess with the code just because you cannot instantly understand)|
|  ``TODO``              |  marks a section of the code as a part to be improved or even developed                                                                     |
|  ``FIXME``, ``HELPME`` |  you are in trouble and do not know how to deal with that "beast" to get the issue solved                                                   |
|   ``BUG``              |  you have commented some code in order to avoid an evil bug                                                                                 |
| ``CAUTION``            |  you want to warn people about the implications of messing with the related code                                                            |

I prefer using ``// ...`` instead of ``/* ... */``. However, I find it is up to you, pick your prefered one.

[Back](#contents)

## Code constructions

Well, here we go...

### If-statement

Always use braces.

```c
    if (<expr>) {
        ...
    } [ else {
        ...
    } ]
```

```c
    if (<expr>) {
        ...
    } else if (expr) {
        ...
    }
```

... and please avoid using:

```c
    if (<expr>)
    {
        ...
    }
```

[Back](#contents)

### While-statement

```c
    while (<expr>) {
        ...
    }
```

[Back](#contents)

### Do/while-statement

```c
    do {
        ...
    } while (<expr>);
```

[Back](#contents)

### Switches

```c
    switch (<expr>) {
        case x:
            ...
            break;

        case y:
            ...
            continue;

        case z:
            ...
            break;

        default:
            break;
    }
```

[Back](#contents)

### Expressions

Do not trust in precedence. Try to make the stuff clearer. If you used to write crypto code you may know that everytime we see and write pretty "insane"
and long expressions. I think that trust in precedence is evidence of naivety. Nothing should obfuscate correctness.

You should use ``(...)`` when you want to communicate and make clearer your intentions about precedence.

[Back](#contents)

### Functions

This is a function:

```c
    <type> function(<args>) {
        ...
    }
```

This isn't:

```c
    <type> function(<args>)
    {
        ...
    }
```

;)

- Static stuff even used only by one function should be prototyped at the beginning of the module.
- Not use ``<type> function()`` when defining or prototyping, this is about C. Thus ``<type> function(void)`` is a better choice for us.
- Try not use char arrays as function parameters, since this does not exist in C. Use pointers! I am sure that you are very well skilled in it.
- If you are passing a char pointer, try also pass its size. Specially for non-static functions, since users can mess with them.
- In kernel mode, try to avoid stack and heap consumption.
- Never ever perform busy waits in kernel.
- Also try not complicate the stuff with native incantations for process synchronization, remember that this is a cryptographic library.
  If you need syncronize something just **inside this library**, you should review your requirements. They are possibly pretty wrong.

[Back](#contents)

### Pointers

``NULL`` <- This is a null pointer.

[Back](#contents)

### "String" terminator

``0`` <- This is a "string" terminator. But try not to be dependent of it, if you can pass the amount of bytes, pass it!

[Back](#contents)

### Gotos

Well, well, well, polemic is loaded... Some goto stuff is used here. But it is used with care. Here the main purpose of goto is for cleaning up issues. The
rule of thumb is never perform a goto that goes backward, the goto always need to jump forward.

If you have got reasons for a spaghetti code let's discuss the idea before.

[Back](#contents)

### Macros

C macros are sharp and great, if you know how to proper use them.

Macros should be designed for doing a single thing.

If you have to use a macro and it is relevant only into the current code context you should emulate a scope by ``#define`` and just after ``#undef`` it. There is no
problem with that, we are all literate in C and you will be understood.

Try always wrapping your macro parameters with (...) during the computations.

Yes, global macros into a code module (``*.c``) should be undefined at the end of the module.

[Back](#contents)

### Unit tests

For unit tests (user and kernel modes) I am using my own [stuff](https://github.com/rafael-santiago/cutest).

The default way of naming a test is by using the name of the function currently tested appended with ("_tests"). Try not be so pedant, describing inputs, behaviors
and all this kind of shit in the test name. This just creates mess and boredom.

You should test the function, period. Go ahead and test it. Comment if you need and that's alright.

Even code that is not probable of being executed into kernel should be tested in kernel mode (if possible). This is a good way of making sure that nothing is
exploding after your changes. You should not fear good code, should you?

Otherwise, if your code should not be executed in kernel mode, inform it explaining why. Do not let people spend their time on it. Comment.

The correctness of any cipher (symmetric) must be tested with official test vectors. When not possible, the custom test vector should be
derived from key expansion samples present in the cipher spec written by the algorithm authors. These test vectors should not be
tested in kernel mode since they were well-tested in user mode.

[Back](#contents)

## Use inclusive and neutral language

Always try to use inclusive and neutral words/terms in your source codes and documentations. If you find something that
for you seems to be not so correct, please let me know by opening an issue and suggesting improvements. Thank you in
advance.

In general avoid use colors to name what should be "good" or "bad". Outdated terms such as ``whitelist``/``blacklist``
are deprecated/banned here. You should use ``allowlist/denylist`` or anything more related to what you really are doing. Terms
like ``master/slave`` are out too. You could use ``main``, ``secondary``, ``next``, ``trunk``, ``current``, ``supervisor``,
``worker`` in replacement.

Do not use sexist and/or machist terms, too.

[Back](#contents)
