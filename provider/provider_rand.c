// 
// Create by kong on 2024/7/1
// Copyright Kong.
//
// Ref: https://www.openssl.org/docs/man3.0/man7/provider-rand.html
//

#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include "provider_main.h"
#include "provider_print.h"
#include "openssl/params.h"

#define MAX_RND_REQUEST 512

typedef struct
{
    provider_context_t *pProviderCtx;
} provider_rand_ctx_st;

/* Context management */

// OSSL_FUNC_rand_newctx() should create and return a pointer
// to a provider side structure for holding context information
// during a rand operation.
static void *provider_rand_newctx(void *provctx, void *parent,
                                  const OSSL_DISPATCH *parent_calls) {
    provider_print("%s %d\n", __FUNCTION__ , __LINE__);
    provider_rand_ctx_st *pRandCtx = OPENSSL_zalloc(sizeof(provider_rand_ctx_st));
    if (pRandCtx == NULL) {
        return NULL;
    }
    (void)(parent);
    (void)(parent_calls);
    if (pRandCtx != NULL) {
        pRandCtx->pProviderCtx = provctx;
    }
    return pRandCtx;
}

// This function should free any resources associated with that context.
static void provider_rand_freectx(void *ctx) {
    provider_print("%s %d\n", __FUNCTION__ , __LINE__);
    provider_rand_ctx_st *pRandCtx = ctx;
    if (pRandCtx != NULL) {
        OPENSSL_clear_free(pRandCtx, sizeof(provider_rand_ctx_st));
    }
}

// OSSL_FUNC_rand_instantiate() is used to instantiate the
// DRBG (Deterministic Random Bit Generator) ctx at a requested security strength.
static int provider_rand_instantiate(void *ctx,
                                     unsigned int strength,
                                     int prediction_resistance,
                                     const unsigned char *pstr,
                                     size_t pstr_len,
                                     const OSSL_PARAM params[])
{
    provider_print("%s %d\n", __FUNCTION__ , __LINE__);
    (void)(ctx);
    (void)(strength);
    (void)(prediction_resistance);
    (void)(pstr);
    (void)(pstr_len);
    (void)(params);
    return 1;
}

// OSSL_FUNC_rand_uninstantiate() is used to uninstantiate the
// DRBG (Deterministic Random Bit Generator) ctx.
static int provider_rand_uninstantiate(void *ctx)
{
    provider_print("%s %d\n", __FUNCTION__ , __LINE__);
    (void)(ctx);
    return 1;
}

// OSSL_FUNC_rand_generate() is used to generate random bytes from the
// DRBG (Deterministic Random Bit Generator) ctx.
static int provider_rand_generate(void *ctx,
                                  unsigned char *out,
                                  size_t outlen,
                                  unsigned int strength,
                                  int prediction_resistance,
                                  const unsigned char *adin,
                                  size_t adinlen)
{
    provider_print("%s %d\n", __FUNCTION__ , __LINE__);
    provider_rand_ctx_st *pRandCtx = (provider_rand_ctx_st *)ctx;
    int ret = 0;
    (void)(strength);
    (void)(prediction_resistance);
    (void)(adin);
    (void)(adinlen);
    if (out == NULL || pRandCtx == NULL || pRandCtx->pProviderCtx == NULL) {
        provider_print("Incorrect input parameter");
        goto cleanup;
    }
    for (int i = 0; i < outlen; ++i) {
        out[i] = 0x01;
    }
    ret = 1;
cleanup:
    return ret;
}

// OSSL_FUNC_rand_enable_locking() allows locking to be turned on for
// a DRBG and all of its parent DRBGs.
static int provider_rand_enable_locking(void *ctx)
{
    provider_print("%s %d\n", __FUNCTION__ , __LINE__);
    (void)(ctx);
    return 1;
}

static const OSSL_PARAM *provider_rand_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM table_ctx_params[] = {
            OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL), OSSL_PARAM_END};
    provider_print("%s %d\n", __FUNCTION__ , __LINE__);
    (void)(ctx);
    (void)(provctx);
    return table_ctx_params;
}

static int provider_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    provider_print("%s %d\n", __FUNCTION__ , __LINE__);
    OSSL_PARAM *p;
    (void)(ctx);
    if (params == NULL) {
        return 1;
    }
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, MAX_RND_REQUEST)) {
        return 0;
    }
    return 1;
}

const OSSL_DISPATCH cc_rand_functions[] = {
        {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))provider_rand_newctx},
        {OSSL_FUNC_RAND_FREECTX, (void (*)(void))provider_rand_freectx},
        {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))provider_rand_instantiate},
        {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))provider_rand_uninstantiate},
        {OSSL_FUNC_RAND_GENERATE, (void (*)(void))provider_rand_generate},
        {OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))provider_rand_enable_locking},
        {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))provider_rand_gettable_ctx_params},
        {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))provider_rand_get_ctx_params},
        {0, NULL}};