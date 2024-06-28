// 
// Create by kong on 2024/6/27
// Copyright 2024 Kong.
//
#ifndef OPENSSL_PROVIDER_PROVIDER_MAIN_H
#define OPENSSL_PROVIDER_PROVIDER_MAIN_H

#include <openssl/provider.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const OSSL_CORE_HANDLE *handle;
    void *p_ex_sss_boot_ctx;
    void *pKeyPair;
} provider_context_t;

// Load provider
void load_provider();

void unload_provider();

#ifdef __cplusplus
}
#endif



#endif //OPENSSL_PROVIDER_PROVIDER_MAIN_H
