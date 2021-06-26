include_directories(${WOLFSSL_INCLUDE_DIR})

add_executable(lidar_udp_client_raw lidar_udp_client_raw.c gk_crypto.c)
target_link_libraries(lidar_udp_client_raw pcap ${WOLFSSL_LIBRARY})

add_executable(lidar_udp_server_raw lidar_udp_server_raw.c gk_crypto.c hashmap.c)
target_link_libraries(lidar_udp_server_raw pcap ${WOLFSSL_LIBRARY})
