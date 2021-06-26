add_executable(udp_client_raw udp_client_raw.c)
target_link_libraries(udp_client_raw pcap)

add_executable(udp_server_raw udp_server_raw.c)
target_link_libraries(udp_server_raw pcap)
