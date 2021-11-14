include_directories(${WOLFSSL_INCLUDE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/common)

add_executable(udp_client_raw udp_client_raw.c)
target_link_libraries(udp_client_raw
  PRIVATE pcap
  PRIVATE gk_crypto)

add_executable(udp_server_raw udp_server_raw.c)
target_link_libraries(udp_server_raw
  PRIVATE pcap
  PRIVATE gk_crypto
  PRIVATE hashmap)

add_executable(udp_server_rsa_raw udp_server_raw.c)
target_link_libraries(udp_server_rsa_raw
  PRIVATE pcap
  PRIVATE gk_crypto
  PRIVATE hashmap)
target_compile_definitions(udp_server_rsa_raw
  PRIVATE GK_AUTH_RSA)
