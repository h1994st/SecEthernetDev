add_executable(udp_client udp_client.c)
target_link_libraries(udp_client pcap)

add_executable(udp_server udp_server.c)
target_link_libraries(udp_server pcap)

add_executable(analyze_recorded_can analyze_recorded_can.c)
target_link_libraries(analyze_recorded_can pcap)
