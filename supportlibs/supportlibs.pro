TEMPLATE = subdirs

CONFIG += ordered

# gxs: sqlcipher

# for rs-nogui/ssh-rpc
# libssh
# protobuf

SUBDIRS += \
    miniupnp    \
    zlib        \
    bzip2       \
    crypto      \
    ssl

crypto.file = openssl/crypto.pro
ssl.file = openssl/ssl.pro
