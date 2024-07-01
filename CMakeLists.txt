cmake_minimum_required(VERSION 3.11)
project(se_provider C)
set(CMAKE_C_STANDARD 11)

include(ExternalProject)

# Download and build OpenSSL
set(OPENSSL_PROJECT_NAME openssl)
set(OPENSSL_FETCHED_DIR "${CMAKE_BINARY_DIR}/${OPENSSL_PROJECT_NAME}")

ExternalProject_Add(
        ${OPENSSL_PROJECT_NAME}
        URL "https://www.openssl.org/source/openssl-3.0.12.tar.gz"
        URL_HASH SHA256=f93c9e8edde5e9166119de31755fc87b4aa34863662f67ddfcba14d0b6b69b61
        PREFIX    ${OPENSSL_FETCHED_DIR}
        CONFIGURE_COMMAND
        ${OPENSSL_FETCHED_DIR}/src/${OPENSSL_PROJECT_NAME}/config
        --prefix=${OPENSSL_FETCHED_DIR}/install
        shared no-asm no-tests
        BUILD_COMMAND make
        INSTALL_COMMAND make install_sw
)
ExternalProject_Get_Property(${OPENSSL_PROJECT_NAME} SOURCE_DIR BINARY_DIR)

link_directories(${OPENSSL_FETCHED_DIR}/install/lib)
# Custom Provider
aux_source_directory(provider SRC_PROVIDER)
add_library(provider SHARED ${SRC_PROVIDER})
target_link_libraries(provider -lcrypto)

include_directories(
        ${OPENSSL_FETCHED_DIR}/install/include
        provider)
add_executable(se_provider main.c)
add_dependencies(se_provider ${OPENSSL_PROJECT_NAME})
target_link_libraries(se_provider -lcrypto provider)