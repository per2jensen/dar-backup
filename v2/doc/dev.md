# Dev snippets

## Setup the development environment

The easiest way to set up a fully reproducible environment is to

use the included helper script:

```bash
cd <path/to/dar-backup/v2>
./setup_environment.py
```

This will:

✅ Create a unique Python virtual environment (like venv or venv-YYYYMMDD-{N})

✅ Install all development dependencies listed in requirements-dev.txt

✅ Run build.sh to build the project wheel in the new environment

## Howto activate the venv

```` bash
cd <path/to/dar-backup/v2>
. venv/bin/activate
````

## Howto build & deploy to dev venv

Make sure __about__.py has the correct version number

```` bash
VERSION=$(cat src/dar_backup/__about__.py |grep -E -o  '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(\.[[:digit:]]+)?')
python3 -m build && pip install --force-reinstall dist/dar_backup-${VERSION}-py3-none-any.whl
````

## Howto use pytest in venv

A pytest.ini is located in the v2 directory, so that pytest writes out captures to  console.

That is useful when working with a single test and is the default

```` bash
PYTHONPATH=src  pytest -c pytest-minimal.ini tests/test_verbose.py::test_verbose_error_reporting
````

Use to get the minimal info on successful test cases

```` bash
PYTHONPATH=src pytest -c pytest-minimal.ini
````

or for specific file with test cases

```` bash
PYTHONPATH=src pytest -c pytest-minimal.ini tests/test_verbose.py
````

## Release to PyPI

```bash
cd <path/to/dar-backup/v2>
./release.sh --upload-to-pypi # provide password to GPG to sign the built artifacts
```

## Git log

```` bash
git log --pretty=format:"%ad - %an: %s %d" --date=short
````

## tarball for chatgpt

```bash
tar --exclude='*/__pycache__' \
  -cvf dar-backup.tar \
  tests/ \
  doc/dev.md \
  doc/doc.md \
  src/  \
  README.md \
  Changelog.md \
  pyproject.toml \
  testall.sh \
  build.sh \
  release.sh \
  pytest.ini  \
  MANIFEST.in \
  pytest-cov.sh \
  pytest.ini \
  requirements-dev.tx
```

## build dar

## check signature

gpg --import <key>

Verify source code has not been tampered with:

```bash
gpg --verify dar-2.7.18.tar.gz.sig dar-2.7.18.tar.gz

gpg: Signature made tir 20 maj 2025 18:02:15 CEST
gpg:                using RSA key 55E484A6A5C5BC7F53F7F72EA8B14160D36B3BA7
gpg: Good signature from "Denis Corbin (http://dar.linux.free.fr/) <dar.linux@free.fr>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 1BE4 7606 A74F 178C 7328  43B0 5F64 5B19 16D5 6546
     Subkey fingerprint: 55E4 84A6 A5C5 BC7F 53F7  F72E A8B1 4160 D36B 3BA7
```

## build

This worked for dar version 2.7.17 on ubuntu 24.04

export SRC_CODE=/some/dir
export DAR_DIR=$HOME/.local/dar-2.7.18

```` bash
# I probably miss some libraries here, as they  were already installed
sudo apt-get install libkrb5-dev 
sudo apt-get install libgcrypt-dev libgpgme-dev libext2fs-dev  libthreadar-dev  librsync-dev  libcurl4-gnutls-dev
cd "$SRC_CODE"
CXXFLAGS=-O
export CXXFLAGS
make clean distclean
./configure --prefix="$DAR_DIR" LDFLAGS="-lgssapi_krb5"
make
make install-strip
````

This gives:

```` code
$HOME/.local/dar/bin/ --version

 dar version 2.7.17, Copyright (C) 2002-2025 Denis Corbin
   Long options support         : YES

 Using libdar 6.8.1 built with compilation time options:
   gzip compression (libz)      : YES
   bzip2 compression (libbzip2) : YES
   lzo compression (liblzo2)    : NO
   xz compression (liblzma)     : YES
   zstd compression (libzstd)   : YES
   lz4 compression (liblz4)     : NO
   Strong encryption (libgcrypt): YES
   Public key ciphers (gpgme)   : YES
   Extended Attributes support  : YES
   Large files support (> 2GB)  : YES
   ext2fs NODUMP flag support   : YES
   Integer size used            : 64 bits
   Thread safe support          : YES
   Furtive read mode support    : YES
   Linux ext2/3/4 FSA support   : YES
   Mac OS X HFS+ FSA support    : NO
   Linux statx() support        : YES
   Detected system/CPU endian   : little
   Posix fadvise support        : YES
   Large dir. speed optimi.     : YES
   Timestamp read accuracy      : 1 nanosecond
   Timestamp write accuracy     : 1 nanosecond
   Restores dates of symlinks   : YES
   Multiple threads (libthreads): YES (1.4.0 - barrier using pthread_barrier_t)
   Delta compression (librsync) : YES
   Remote repository (libcurl)  : YES (libcurl/8.5.0 GnuTLS/3.8.3 zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libpsl/0.21.2 (+libidn2/2.3.7) libssh/0.10.6/openssl/zlib nghttp2/1.59.0 librtmp/2.3 OpenLDAP/2.6.7)
   argon2 hashing (libargon2)   : NO

 compiled the Mar 25 2025 with GNUC version 13.3.0
 dar is part of the Disk ARchive suite (Release 2.7.17)
 dar comes with ABSOLUTELY NO WARRANTY; for details
 type `dar -W'. This is free software, and you are welcome
 to redistribute it under certain conditions; type `dar -L | more'
 for details.
````
