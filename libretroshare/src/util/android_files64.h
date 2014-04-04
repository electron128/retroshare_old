#ifndef ANDROID_FILES64_H
#define ANDROID_FILES64_H

// 64 bit file operations for android

#include <stdio.h>
#include <stdint.h>
#include <limits.h>

inline FILE* fopen64(const char *filename, const char *mode ){
    return fopen(filename, mode);
}

/* from manual:

       The fseeko() and ftello() functions are identical to fseek(3) and
       ftell(3) (see fseek(3)), respectively, except that the offset
       argument of fseeko() and the return value of ftello() is of type
       off_t instead of long.

       On many architectures both off_t and long are 32-bit types, but
       compilation with

              #define _FILE_OFFSET_BITS 64

       will turn off_t into a 64-bit type.

 */
inline int fseeko64(FILE *stream, uint64_t offset, int whence){
    // i don't know if android has 64 file offset bits, so we limit it to 32-1 bit
    if(offset > LONG_MAX){
        return -1;
    }
    // fseek takes long int as parameter
    return fseek(stream, offset, whence);
}

inline uint64_t ftello64(FILE *stream){
    return ftell(stream);
}

#endif // ANDROID_FILES64_H
