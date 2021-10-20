# Download and unpack googletest at configure time
configure_file(
  googletest-download/CMakeLists.txt.in
  googletest-download/CMakeLists.txt)
execute_process(
  COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)
if (result)
  message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif ()
execute_process(
  COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)
if (result)
  message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif ()

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This defines
# the gtest and gtest_main targets.
add_subdirectory(
  ${CMAKE_CURRENT_BINARY_DIR}/googletest-src
  ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
  EXCLUDE_FROM_ALL)

include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${WOLFSSL_INCLUDE_DIR})

# wolfSSL Test
add_executable(test_wolfssl test_wolfssl.cpp)
target_link_libraries(test_wolfssl
  PRIVATE gtest_main
  PRIVATE ${WOLFSSL_LIBRARY}
  PRIVATE wolfssl_ext)
add_test(
  NAME test_wolfssl
  COMMAND test_wolfssl
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# TESLA Test
add_executable(test_tesla test_tesla.cpp)
target_include_directories(test_tesla
  PRIVATE ${CMAKE_SOURCE_DIR}/tesla)
target_link_libraries(test_tesla
  PRIVATE gtest_main
  PRIVATE tesla)
add_test(
  NAME test_tesla
  COMMAND test_tesla
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Time-lock Puzzle Test
add_executable(test_time_lock_puzzle test_time_lock_puzzle.cpp)
target_include_directories(test_time_lock_puzzle
  PRIVATE ${CMAKE_SOURCE_DIR}/common)
target_link_libraries(test_time_lock_puzzle
  PRIVATE gtest_main
  PRIVATE time_lock_puzzle)
add_test(
  NAME test_time_lock_puzzle
  COMMAND test_time_lock_puzzle
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Gatekeeper crypto
add_executable(test_gk_crypto test_gk_crypto.cpp)
target_include_directories(test_gk_crypto
  PRIVATE ${CMAKE_SOURCE_DIR}/common)
target_link_libraries(test_gk_crypto
  PRIVATE gtest_main
  PRIVATE gk_crypto)
add_test(
  NAME test_gk_crypto
  COMMAND test_time_lock_puzzle
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
