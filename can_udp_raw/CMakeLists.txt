include_directories(${WOLFSSL_INCLUDE_DIR})

add_executable(udp_client_raw udp_client_raw.c gk_crypto.c)
target_link_libraries(udp_client_raw pcap ${WOLFSSL_LIBRARY})

add_executable(udp_server_raw udp_server_raw.c gk_crypto.c hashmap.c)
target_link_libraries(udp_server_raw pcap ${WOLFSSL_LIBRARY})
