// 
// Create by kong on 2024/6/27
// Copyright 2024 Kong.
//
#include "provider_main.h"
#include "provider_print.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>

#define CC_PROVIDER_NAME_STR      "OpenSSL CC Provider"
#define CC_PROVIDER_VERSION_STR   "1.0.1"
#define CC_PROVIDER_BUILDINFO_STR "CC Provider v."

// Function provider query
static const OSSL_ALGORITHM *provider_query_operation(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    (void)(provctx);
    provider_print("Enter - %s, operation_id: %d\n", __FUNCTION__, operation_id);
    switch (operation_id) {
        case OSSL_OP_RAND:
//            return sss_rands;
        case OSSL_OP_KEYMGMT:
//            return sss_keymgmts;
        case OSSL_OP_SIGNATURE:
//            return sss_signatures;
        case OSSL_OP_STORE:
//            return sss_store;
        case OSSL_OP_KEYEXCH:
//            return sss_keyexchs;

        default:
            return NULL;
    }
}

// Function provider teardown
static void provider_teardown(void *provctx)
{
    provider_print("Enter - %s \n", __FUNCTION__);
//    ex_sss_session_close(&gProvider_boot_ctx);
    if (provctx != NULL) {
//        OPENSSL_free(provctx);
    }
}

static const OSSL_PARAM *provider_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {
            OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
            OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
            OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
            OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
            OSSL_PARAM_END};
    provider_print("Enter - %s \n", __FUNCTION__);
    (void)(provctx);
    return param_types;
}

static int provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    provider_print("Enter - %s \n", __FUNCTION__);
    (void)(provctx);
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, CC_PROVIDER_NAME_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, CC_PROVIDER_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, CC_PROVIDER_BUILDINFO_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

// Functions provided by the provider to the Core
static const OSSL_DISPATCH provider_dispatch_table[] = {
        {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provider_query_operation},
        {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provider_teardown},
        {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))provider_gettable_params},
        {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provider_get_params},
        {0, NULL}};

// Provider 模块入口
// handle: 执行 Core 所属 Provider 对象的句柄
// in:     核心传递给 Provider 的函数数组  <函数id, 函数指针>
// out:    Provider 传递回 Core 的 Provider 函数数组 <函数id, 函数指针>
// provider_ctx: Provider 可选创建的对象，用于自身使用
int OSSL_provider_init(
        const OSSL_CORE_HANDLE *handle,
        const OSSL_DISPATCH *in,
        const OSSL_DISPATCH **out,
        void **provider_ctx)
{
    provider_context_t *ctx = OPENSSL_zalloc(sizeof(provider_context_t));
    if (ctx == NULL) {
        provider_print("OPENSSL_zalloc fail.");
        return 0;
    }
    ctx->handle   = handle;
    *out          = provider_dispatch_table;
    *provider_ctx = ctx;
    return 1;
}

static OSSL_LIB_CTX *libctx = NULL;
static const char *kOQSProviderName = "cprovider";

// Load provider
void load_provider()
{
    if (libctx == NULL) {
         libctx = OSSL_LIB_CTX_new();
    }
    int ret = OSSL_PROVIDER_available(libctx, kOQSProviderName);
    if (ret != 0) {
        fprintf(stderr,
                "`OSSL_PROVIDER_available` returned %i, but 0 was expected\n",
                ret);
    }
    ret = OSSL_PROVIDER_add_builtin(libctx, kOQSProviderName,
                                    OSSL_provider_init);
    if (ret != 1) {
        fprintf(stderr,
                "`OSSL_PROVIDER_add_builtin` failed with returned code %i\n",
                ret);
    }

    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, kOQSProviderName);
    if (provider == NULL) {
        fputs("`OSSL_PROVIDER_load` failed\n", stderr);
        ERR_print_errors_fp(stdout);
    }

    ret = OSSL_PROVIDER_available(libctx, kOQSProviderName);
    if (ret != 1) {
        fprintf(stderr,
                "`OSSL_PROVIDER_available` returned %i, but 0 was expected\n",
                ret);
    }

    ret = OSSL_PROVIDER_self_test(provider);
    if (ret != 1) {
        fprintf(stderr,
                "`OSSL_PROVIDER_self_test` failed with returned code %i\n",
                ret);
    }
}

void unload_provider()
{

}