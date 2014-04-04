TEMPLATE = lib
CONFIG += staticlib
CONFIG -= qt
TARGET = zlib
DESTDIR = lib

ZLIB_DIR = zlib-1.2.8

HEADERS +=\
        $${ZLIB_DIR}/adler32.h	\
        $${ZLIB_DIR}/compress.h	\
        $${ZLIB_DIR}/crc32.h	\
        $${ZLIB_DIR}/gzio.h	\
        $${ZLIB_DIR}/uncompr.h	\
        $${ZLIB_DIR}/deflate.h	\
        $${ZLIB_DIR}/trees.h	\
        $${ZLIB_DIR}/zutil.h	\
        $${ZLIB_DIR}/inflate.h	\
        $${ZLIB_DIR}/infback.h	\
        $${ZLIB_DIR}/inftrees.h	\
        $${ZLIB_DIR}/inffast.h

SOURCES +=\
        $${ZLIB_DIR}/adler32.c	\
        $${ZLIB_DIR}/compress.c	\
        $${ZLIB_DIR}/crc32.c	\
        # gzio was there in 1.2.3
        # but is missing in 1.2.8
        #$${ZLIB_DIR}/gzio.c	\
        $${ZLIB_DIR}/uncompr.c	\
        $${ZLIB_DIR}/deflate.c	\
        $${ZLIB_DIR}/trees.c	\
        $${ZLIB_DIR}/zutil.c	\
        $${ZLIB_DIR}/inflate.c	\
        $${ZLIB_DIR}/infback.c	\
        $${ZLIB_DIR}/inftrees.c	\
        $${ZLIB_DIR}/inffast.c
