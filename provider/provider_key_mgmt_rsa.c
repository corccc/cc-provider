// 
// Create by kong on 2024/6/27
// Copyright 2024 Kong.
//
// Ref: /providers/implementations/keymgmt/rsa_kmgmt.c

#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include "provider_main.h"
#include "provider_print.h"


static void *provider_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
    // 全局变量
    printf("%s: %d", __FUNCTION__, __LINE__);
    (void)(reference);
    (void)(reference_sz);
    return NULL;
}

static void provider_rsa_keymgmt_free(void *keydata)
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    (void)(keydata);
    // RSA_free(keydata)
}

static int provider_rsa_get_params(void *key, OSSL_PARAM params[])
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    (void)(key);
    (void)(params);
    return 1;
}

static const OSSL_PARAM *provider_rsa_gettable_params(void *provctx)
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    static OSSL_PARAM gettable[] = {
            OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
            OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
            OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
            OSSL_PARAM_END};
    (void)(provctx);
    return gettable;
}

// operation_id:  OSSL_OP_SIGNATURE | OSSL_OP_ASYM_CIPHER | ...
static const char *provider_rsa_keymgmt_query_operation_name(int operation_id)
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    (void)(operation_id);
    return "RSA";
}

// Check whether the key data in keyData is valid based on selection
static int provider_rsa_keymgmt_has(const void *keydata, int selection)
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    int ok = 1;
    (void)(keydata);
    (void)(selection);
    /* OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS are always available even if empty */
//    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
//        ok = ok && (RSA_get0_n(rsa) != NULL);
//    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
//        ok = ok && (RSA_get0_e(rsa) != NULL);
//    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
//        ok = ok && (RSA_get0_d(rsa) != NULL);
    return ok;
}

static int provider_rsa_export(void *keydata, int selection,
                               OSSL_CALLBACK *param_callback, void *cbarg)
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    int ok = 1;
    (void)(keydata);
    (void)(selection);
    (void)(param_callback);
    (void)(cbarg);
    return ok;
}

static const OSSL_PARAM *sss_rsa_keymgmt_export_types(int selection)
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    static OSSL_PARAM exporatble[9] = {0};
    exporatble[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_RSA_N, 0, 0);
    exporatble[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_RSA_E, 0, 0);
    exporatble[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0);
    exporatble[3] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL);
    exporatble[4] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL);
    exporatble[5] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL),
    exporatble[6] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    exporatble[7] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL),
    exporatble[8] = OSSL_PARAM_construct_end();
    (void)(selection);
    return exporatble;
}

// 配置 keyID 信息，Pin 信息等安全芯片调用信息
static void *provider_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    provider_store_obj_t *pStoreCtx = NULL;
    (void)(selection);
    (void)(params);
    if ((pStoreCtx = OPENSSL_zalloc(sizeof(provider_store_obj_t))) == NULL) {
        return NULL;
    }
    pStoreCtx->pProvCtx = provctx;
    return pStoreCtx;
}

static int provider_keymgmt_rsa_gen_set_params(void *keydata, const OSSL_PARAM params[]) {
    printf("%s: %d", __FUNCTION__, __LINE__);
    provider_store_obj_t *pStoreCtx = keydata;
    return 1;
}

static const OSSL_PARAM *provider_keymgmt_rsa_gen_settable_params(void *keydata, void *vprovctx) {
    printf("%s: %d", __FUNCTION__, __LINE__);
    static OSSL_PARAM settable[] = {OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
                                    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
                                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
                                    OSSL_PARAM_END};
    (void)(keydata);
    (void)(vprovctx);
    return settable;
}

static void *provider_keymgmt_rsa_gen(void *keydata, OSSL_CALLBACK *osslcb, void *cbarg)
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    (void)(osslcb);
    (void)(cbarg);
    return keydata;
}

static void provider_keymgmt_rsa_gen_cleanup(void *keydata)
{
    printf("%s: %d", __FUNCTION__, __LINE__);
    (void)(keydata);
}

const OSSL_DISPATCH cc_rsa_keymgmt_dispatch[] ={
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))provider_rsa_keymgmt_load},
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))provider_rsa_keymgmt_free},
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))provider_rsa_get_params},
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))provider_rsa_gettable_params},
        {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))provider_rsa_keymgmt_query_operation_name},
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))provider_rsa_keymgmt_has},
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))provider_rsa_export},
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))sss_rsa_keymgmt_export_types},

        /* To generate the key in SE */
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))provider_rsa_keymgmt_gen_init},
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))provider_keymgmt_rsa_gen_set_params},
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))provider_keymgmt_rsa_gen_settable_params},
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))provider_keymgmt_rsa_gen},
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))provider_keymgmt_rsa_gen_cleanup},
        {0, NULL}};