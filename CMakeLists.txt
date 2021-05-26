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

# C++ language standard
set(CMAKE_CXX_STANDARD 14)

# WolfSSL
find_package(WolfSSL REQUIRED)
message("WolfSSL include: ${WOLFSSL_INCLUDE_DIR}")
message("WolfSSL libs: ${WOLFSSL_LIBRARY}")

# CAN over UDP
add_subdirectory(can_udp)

# TESLA
add_subdirectory(tesla)

# TESLA: CAN over UDP
add_subdirectory(tesla_can_udp)
