cmake_minimum_required(VERSION 3.13)
project(mbed_embed)

file(GLOB
  MBEDTLS_SOURCES
  ../../modules/crypto/mbedtls/library/*.c
)

add_library(mbedtls STATIC ${MBEDTLS_SOURCES})
target_include_directories(mbedtls PUBLIC ../../modules/crypto/mbedtls/include)
target_compile_options(mbedtls PUBLIC -m32)
target_link_options(mbedtls PUBLIC -m32)

add_executable(mbed_embed mbed_embed.cpp)
target_link_libraries(mbed_embed mbedtls)
target_compile_options(mbed_embed PUBLIC -m32 -std=c++17)
target_link_options(mbed_embed PUBLIC -m32)
