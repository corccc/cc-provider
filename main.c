#include <stdio.h>
#include "provider/provider_main.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

int GenerateKeyPair() {
//    EVP_PKEY *pkey = EVP_PKEY_new();
//    EVP_PKEY_CTX *ctx;
//    if (!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) {
//    }
//    if (EVP_PKEY_keygen_init(ctx) <= 0) {
//    }
//    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024);
//    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
//    }
//    EVP_PKEY_print_public_fp(stdout, pkey, 0, 0);
//    EVP_PKEY_print_private_fp(stdout, pkey, 0, 0);
//    EVP_PKEY_free(pkey);
//    EVP_PKEY_CTX_free(ctx);
    unsigned char buffer[16] = {0};
    int buffer_len = 16;
    RAND_bytes(buffer, buffer_len);

    printf("Buffer: \n");
    for (int i = 0; i < buffer_len; ++i) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    return 1;
}

//static
int main() {
    printf("Hello, World!\n");
    load_cc_provider();
    GenerateKeyPair();
    unload_cc_provider();
    return 0;
}
