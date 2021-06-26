include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/tesla)

add_executable(tesla_lidar_udp_client tesla_lidar_udp_client.c)
target_link_libraries(tesla_lidar_udp_client pcap tesla)

add_executable(tesla_lidar_udp_server tesla_lidar_udp_server.c)
target_link_libraries(tesla_lidar_udp_server pcap tesla)
