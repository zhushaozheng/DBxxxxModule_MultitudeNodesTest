#ifndef QT_COMMON_API_H
#define QT_COMMON_API_H

#include "string.h"

typedef long long int64;
typedef unsigned long long uint64;
typedef unsigned long uint32;
typedef unsigned short int uint16;
typedef unsigned char uint8;
typedef signed long int32;
typedef signed short int int16;
typedef signed char int8;

typedef int64 i64;
typedef unsigned long ui32;
typedef unsigned short int ui16;
typedef unsigned char ui8;
typedef long i32;
typedef short int i16;
typedef char i8;

int Qt_printf(const char *apFormat, ...);

#endif // QT_COMMON_API_H