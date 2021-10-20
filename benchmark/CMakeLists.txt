include_directories(${CMAKE_SOURCE_DIR}/common)

add_executable(bench_crypto_puzzle bench_crypto_puzzle.c)
target_include_directories(bench_crypto_puzzle
  PRIVATE ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(bench_crypto_puzzle
  PRIVATE ${WOLFSSL_LIBRARY})

add_executable(bench_time_lock_puzzle bench_time_lock_puzzle.cpp)
target_link_libraries(bench_time_lock_puzzle
  PRIVATE time_lock_puzzle
  PRIVATE benchmark::benchmark)

add_executable(bench_time_lock_puzzle_encryption bench_time_lock_puzzle_encryption.cpp)
target_link_libraries(bench_time_lock_puzzle_encryption
  PRIVATE time_lock_puzzle
  PRIVATE benchmark::benchmark)

add_executable(bench_time_lock_puzzle_decryption bench_time_lock_puzzle_decryption.cpp)
target_link_libraries(bench_time_lock_puzzle_decryption
  PRIVATE time_lock_puzzle
  PRIVATE benchmark::benchmark)
