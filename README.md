# Kryptos

I started the core of this project on about 2004 and since then it is being an attempt of building a tiny and straightforward
crypto library which can be easily integrated with user and also kernel mode code.

Until now these are the supported platforms:

| **Platform** | **User mode** | **Kernel mode** |
|:------------:|:-------------:|:---------------:|
|![FreeBSD](https://github.com/rafael-santiago/kryptos/blob/main/etc/small-freebsd.png "FreeBSD")|:heavy_check_mark:|:heavy_check_mark:|
|![Linux](https://github.com/rafael-santiago/kryptos/blob/main/etc/small-tux.png "Linux")|:heavy_check_mark:|:heavy_check_mark:|
|![OpenBSD](https://github.com/rafael-santiago/kryptos/blob/main/etc/small-puffy.png "OpenBSD")|:heavy_check_mark:|:x:|
|![NetBSD](https://github.com/rafael-santiago/kryptos/blob/main/etc/small-netbsd-flag.png "NetBSD")|:heavy_check_mark:|:heavy_check_mark:|
|![MINIX](https://github.com/rafael-santiago/kryptos/blob/main/etc/small-raccoon.png "MINIX")|:heavy_check_mark:|:x:|
|![SOLARIS](https://github.com/rafael-santiago/kryptos/blob/main/etc/small-solaris-sun.png "Solaris")|:heavy_check_mark:|:x:|
|![Windows](https://github.com/rafael-santiago/kryptos/blob/main/etc/small-windows-logo.png "Windows")|:heavy_check_mark:|:heavy_check_mark:|

## Features

**Stream cipher**: ``ARC4``, ``SEAL``, ``RABBIT``, ``Salsa20``, ``ChaCha20``.

**Block cipher**: ``AES``, ``DES``, ``3DES``, ``3DES-EDE``, ``IDEA``, ``RC2``, ``RC5``, ``RC6``, ``FEAL``, ``CAST5``,
``Camellia``, ``SAFER-K64``, ``Blowfish``, ``Serpent``, ``TEA``, ``XTEA``, ``MISTY1``, ``MARS``, ``PRESENT``, ``SHACAL-1``,
``SHACAL-2``, ``NOEKEON``, ``GOST``, ``TWOFISH``.

**Modes of operation**: ``ECB``, ``CBC``, ``OFB``, ``CTR``, ``GCM``.

**Cryptographic hashes**: ``SHA-1``, ``SHA-224``, ``SHA-256``, ``SHA-384``, ``SHA-512``, ``MD4``, ``MD5``, ``RIPEMD-128``,
``RIPEMD-160``, ``SHA3-224``, ``SHA3-256``, ``SHA3-384``, ``SHA3-512``, ``KECCAK-224``, ``KECCAK-256``, ``KECCAK-384``,
``KECCAK-512``, ``BLAKE2s-256``, ``BLAKE2b-512``, ``BLAKE2s-N``, ``BLAKE2b-N``, ``Tiger``, ``Whirlpool``.

**Non-cryptographic hashes**: ``djb2`` (string hashing), ``SipHash``.

**Message authentication code**: ``HMAC``, ``Poly1305``, ``SipHash`` (recommended for short messages only),
``GCM`` (for all 128-bit block ciphers).

**PK crypto**: ``RSA``, ``RSA-OAEP``, ``El Gamal``, ``RSA-EMSA/PSS``, ``DSA``, ``ECDSA``, ``DH``, ``ECDH``.

**CSPRNG**: From the system (default one), ``Fortuna``.

**Codification stuff**: ``Base64``, ``UUEncode``.

**Compression stuff**: ``Huffman coding``.

**Key derivation functions**: ``HKDF``, ``PBKDF2``, ``Argon2``.

**One-time passwords**: ``HOTP``, ``TOTP``.

**Extras**: Common API between user space / kernel space (``Windows``, ``FreeBSD``, ``NetBSD`` and ``Linux``), ``RAM`` swapping
cares, data wiping when freeing memory, ``PEM`` as its common input/output (for some algorithms), convenience function macros
to make it easy to use all available cryptographic functions (``C99`` required).

In order to know more you should start [here](https://github.com/rafael-santiago/kryptos/blob/main/doc/README.md).

This library is licensed under ``GPLv2`` if for some reason it does not fit into your stuff you can contact me and let's
talk about.

---

**Bear in mind**: Use this software at your own risk. I am not responsible for any misuse of it, including some kind of damage,
data loss etc. The software is provided with no warranty. Also watch the crypto regulations for your country and the licenses
of the current available ciphers before using this library.

**Remark**: I do not provide pre-builts, if you have found any pre-built of this library somewhere, I **do not** endorse it.
