// 
// Create by kong on 2024/6/27
// Copyright 2024 Kong.
//

#include "provider_print.h"
#include "stdio.h"
#include "stdarg.h"

#define SSSPROV_MAX_PRINT_BUF_SIZE 512

void provider_print(const char *format, ...)
{
    unsigned char buffer[512];
    va_list vArgs;
    va_start(vArgs, format);
    vsnprintf((char *)buffer, SSSPROV_MAX_PRINT_BUF_SIZE, (char const *)format, vArgs);
    va_end(vArgs);
    printf("%s", buffer);
}
