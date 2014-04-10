SSL_DIR = openssl/openssl-1.0.1g
SSL_INCLUDE_DIR = $$SSL_DIR/include
SSL_LIBRARY = openssl/lib/libssl.a
CRYPTO_LIBRARY = openssl/lib/libcrypto.a
DEFINES *= OPENSSL_NO_CAMELLIA
DEFINES *= OPENSSL_NO_CMS
DEFINES *= OPENSSL_NO_IDEA
DEFINES *= OPENSSL_NO_SEED

ZLIB_DIR = zlib/zlib-1.2.8
ZLIB_INCLUDE_DIR = $$ZLIB_DIR
ZLIB_LIBRARY = zlib/lib/libzlib.a

BZIP_DIR = bzip2/bzip2-1.0.6
BZIP_INCLUDE_DIR = $$BZIP_DIR
BZIP_LIBRARY = bzip2/lib/libbzip2.a

UPNPC_DIR = miniupnp/miniupnpc-1.9
UPNPC_INCLUDE_DIR = $$UPNPC_DIR
UPNPC_LIBRARY = miniupnp/lib/libminiupnpc.a
