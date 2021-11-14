include_directories(${WOLFSSL_INCLUDE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/common)

add_executable(lidar_udp_client_raw lidar_udp_client_raw.c)
target_link_libraries(lidar_udp_client_raw
  PRIVATE pcap
  PRIVATE gk_crypto)

add_executable(lidar_udp_server_raw lidar_udp_server_raw.c)
target_link_libraries(lidar_udp_server_raw
  PRIVATE pcap
  PRIVATE gk_crypto
  PRIVATE hashmap)

add_executable(lidar_udp_server_rsa_raw lidar_udp_server_raw.c)
target_link_libraries(lidar_udp_server_rsa_raw
  PRIVATE pcap
  PRIVATE gk_crypto
  PRIVATE hashmap)
target_compile_definitions(lidar_udp_server_rsa_raw
  PRIVATE GK_AUTH_RSA)
