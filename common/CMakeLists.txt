add_library(gk_crypto STATIC gk_crypto.c)
target_include_directories(gk_crypto
  PRIVATE ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(gk_crypto
  PRIVATE ${WOLFSSL_LIBRARY})

add_library(hashmap STATIC hashmap.c)
