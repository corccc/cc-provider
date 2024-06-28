#include <stdio.h>
#include "provider/provider_main.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <string.h>

int main() {
    printf("Hello, World!\n");
    load_provider();
    return 0;
}
