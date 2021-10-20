# wolfSSL extension
# NOTE: may submit a pull request in the future?
add_library(wolfssl_ext STATIC wolfssl_ext.c)
target_include_directories(wolfssl_ext
  PRIVATE ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(wolfssl_ext
  PRIVATE ${WOLFSSL_LIBRARY})

# Time-lock puzzle
add_library(time_lock_puzzle
  time_lock_puzzle.cpp)
target_include_directories(time_lock_puzzle
  PRIVATE ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(time_lock_puzzle
  PRIVATE ${WOLFSSL_LIBRARY}
  PRIVATE wolfssl_ext)

# Gatekeeper crypto operations
add_library(gk_crypto STATIC gk_crypto.c)
target_include_directories(gk_crypto
  PRIVATE ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(gk_crypto
  PRIVATE ${WOLFSSL_LIBRARY}
  PRIVATE wolfssl_ext)

# Hashmap in C
add_library(hashmap STATIC hashmap.c)
