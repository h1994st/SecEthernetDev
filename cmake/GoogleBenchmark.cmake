set(GOOGLEBM_PREFIX "${CMAKE_BINARY_DIR}/third_party/benchmark")
configure_file(
  ${CMAKE_SOURCE_DIR}/cmake/GoogleBenchmark.cmake.in
  ${GOOGLEBM_PREFIX}/benchmark-download/CMakeLists.txt)

execute_process(
  COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${GOOGLEBM_PREFIX}/benchmark-download)
if (result)
  message(FATAL_ERROR "CMake step for google benchmark failed: ${result}")
endif ()
execute_process(
  COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${GOOGLEBM_PREFIX}/benchmark-download)
if (result)
  message(FATAL_ERROR "Build step for google benchmark failed: ${result}")
endif ()

# Disable testing for benchmark
set(BENCHMARK_ENABLE_TESTING OFF)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_INSTALL OFF)
add_subdirectory(
  ${GOOGLEBM_PREFIX}/benchmark-src
  ${GOOGLEBM_PREFIX}/benchmark-build
  EXCLUDE_FROM_ALL)
