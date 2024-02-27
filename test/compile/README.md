# Compile dar

## Problems

## dar_manager cannot find dar

dar_manager cannot find it's dar binary, even though they are in the same directory.

I suspect a config somewhere is teasing me - temporary "fix" unti I figure out what is wrong:

- sudo apt remove dar

- sudo ln -s /home/$USER/.local/dar/bin/dar /usr/bin/dar


### --disable-libcurl-linking

currently I get errors building dar if not issueing this config option


## package prereg
This kind of works on Ubuntu 23.10

```
sudo apt install \
    zlib1g-dev \
    libbz2-dev \
    liblzo2-dev \
    liblzma-dev \
    libzstd-dev \
    liblz4-dev \
    libgcrypt20-dev \
    libgpgme-dev \
    doxygen \
    graphviz \
    upx-ucl \
    groff \
    libext2fs-dev \
    libthreadar-dev \
    librsync-dev \
    libcurl4-openssl-dev \
    python3-pybind11 \
    python3-dev \
    libargon2-dev 
```

## Compile

```
DAR_VERSION=2.7.13
if [[ -d /.local/dar-${DAR_VERSION} ]]; then
  mv /.local/dar-${DAR_VERSION}  /.local/dar-${DAR_VERSION}.old
fi
mkdir -p ~/.local/dar-${DAR_VERSION}

if [[ -d /tmp/dar-${DAR_VERSION} ]]; then
  rm -fr /tmp/dar-${DAR_VERSION}  || exit 2
fi

tar xvf src/dar-${DAR_VERSION}.tar.gz --directory /tmp

cd /tmp/dar-${DAR_VERSION}
./configure \
   --prefix=/home/$USER/.local/dar-${DAR_VERSION}  \
   --disable-libcurl-linking 

make
make install-strip

rm ~/.local/dar
ln -s ~/.local/dar-${DAR_VERSION}  ~/.local/dar
```


