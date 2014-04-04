TEMPLATE = lib
CONFIG += staticlib
CONFIG -= qt
TARGET = bzip2
DESTDIR = lib

BZIP2_DIR = bzip2-1.0.6

HEADERS +=\
        $${BZIP2_DIR}/blocksort.h	\
        $${BZIP2_DIR}/huffman.h		\
        $${BZIP2_DIR}/crctable.h	\
        $${BZIP2_DIR}/randtable.h	\
        $${BZIP2_DIR}/compress.h	\
        $${BZIP2_DIR}/decompress.h	\
        $${BZIP2_DIR}/bzlib.h

SOURCES +=\
        $${BZIP2_DIR}/blocksort.c	\
        $${BZIP2_DIR}/huffman.c         \
        $${BZIP2_DIR}/crctable.c	\
        $${BZIP2_DIR}/randtable.c	\
        $${BZIP2_DIR}/compress.c	\
        $${BZIP2_DIR}/decompress.c	\
        $${BZIP2_DIR}/bzlib.c
