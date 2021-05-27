cmake_minimum_required(VERSION 3.10.0 FATAL_ERROR)
project(SecEthernetDev)

# Undocumented options
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed.")
endif ()

# CMake modules
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CTest)

# C++ language standard
set(CMAKE_CXX_STANDARD 14)

# wolfSSL
find_package(WolfSSL REQUIRED)
message("WolfSSL include: ${WOLFSSL_INCLUDE_DIR}")
message("WolfSSL libs: ${WOLFSSL_LIBRARY}")

# CAN over UDP
add_subdirectory(can_udp)

# TESLA
add_subdirectory(tesla)

# TESLA: CAN over UDP
add_subdirectory(tesla_can_udp)

# Testing
enable_testing()
add_subdirectory(tests)

  # Valgrind
  add_custom_target(test_memcheck
    COMMAND ${CMAKE_CTEST_COMMAND} --force-new-ctest-process --test-action memcheck
    # Throw an error while finding any non-empty memory check reports
    # - `find` always returns zero, even if it does not find anything
    # - `grep .` will return non-zero, if no memory leaks are found
    COMMAND find "${CMAKE_BINARY_DIR}/Testing/Temporary" -name "MemoryChecker.*.log" -not -empty -exec cat {} + | grep . || exit 0 && exit 2)