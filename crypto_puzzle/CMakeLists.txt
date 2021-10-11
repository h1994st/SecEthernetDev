add_executable(bench_crypto_puzzle bench_crypto_puzzle.c)
target_link_libraries(bench_crypto_puzzle
  PRIVATE ${WOLFSSL_LIBRARY})

add_library(time_lock_puzzle
  time_lock_puzzle.cpp)
target_link_libraries(time_lock_puzzle
  PRIVATE ${WOLFSSL_LIBRARY})

add_executable(bench_time_lock_puzzle bench_time_lock_puzzle.cpp)
target_link_libraries(bench_time_lock_puzzle
  PRIVATE time_lock_puzzle
  PRIVATE benchmark::benchmark)
