TEMPLATE = lib
CONFIG += staticlib
CONFIG -= qt
#TARGET = openssl # want to split into libcrypto and libssl?
TARGET = crypto
DESTDIR = lib

OPENSSL_DIR = openssl-1.0.1f

DEFINES *= NO_WINDOWS_BRAINDEATH

# to disable camellia
include(../supportlibs.pri)

INCLUDEPATH +=              \
    $$OPENSSL_DIR           \
    $$OPENSSL_DIR/include   \
    $$OPENSSL_DIR/crypto    \
    $$OPENSSL_DIR/crypto/asn1   \
    $$OPENSSL_DIR/crypto/evp    \
    $$OPENSSL_DIR/crypto/modes

include(openssl_crypto_sources.pri)

# first had crypto and ssl in one library, but crypto/bio/bss_file.c did not get compilen when ssl was enabled
#include(openssl_ssl_sources.pri)

for(file, OPENSSL_CRYPTO_SOURCES): SOURCES += $${OPENSSL_DIR}/$${file}

#for(file, OPENSSL_SSL_SOURCES): SOURCES += $${OPENSSL_DIR}/$${file}

# this sourcefile does not get into the makefile
# even it is in SOURCES
#SOURCES += $$OPENSSL_DIR/crypto/bio/bss_file.c

#HEADERS += $$OPENSSL_DIR/crypto/bio/bio.h
