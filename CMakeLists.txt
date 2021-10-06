cmake_minimum_required(VERSION 3.10.0 FATAL_ERROR)
project(SecEthernetDev)

# Undocumented options
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
#set(CMAKE_DISABLE_SOURCE_CHANGES ON)
if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "In-source builds are not allowed.")
endif ()

# CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CTest)

# C++ language standard
set(CMAKE_CXX_STANDARD 14)

# Linux Kernel Module (LKM)
if (NOT LKM_DIR)
  find_package(LKM REQUIRED)
  message(STATUS "Kernel release: ${LKM_RELEASE}")
  message(STATUS "Kernel headers: ${LKM_INCLUDE_DIR}")
endif ()
include(KernelModule)

# wolfSSL
find_package(WolfSSL REQUIRED)
message(STATUS "WolfSSL version: ${WOLFSSL_VERSION}")
message(STATUS "WolfSSL include: ${WOLFSSL_INCLUDE_DIR}")
message(STATUS "WolfSSL libs: ${WOLFSSL_LIBRARY}")

#
# Targets
#

# Gatekeeper Kernel Modules
add_subdirectory(kernel_modules)

# CAN over UDP
add_subdirectory(can_udp)

# CAN over UDP + GK sender/receiver + raw socket
add_subdirectory(can_udp_raw)

# LiDAR UDP replay
add_subdirectory(lidar_udp)

# LiDAR UDP replay
add_subdirectory(lidar_udp_raw)

# TESLA library
add_subdirectory(tesla)

# TESLA: CAN over UDP
add_subdirectory(tesla_can_udp)

# TESLA LiDAR UDP replay
add_subdirectory(tesla_lidar_udp)

# Crypto puzzle
add_subdirectory(crypto_puzzle)

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
