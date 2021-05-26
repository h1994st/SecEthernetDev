set(TESLA_SRCS tesla.c NTP.c client.c sender.c octet_stream.c hashtable.c)

include_directories(${WOLFSSL_INCLUDE_DIR})

# tesla library
add_library(tesla SHARED ${TESLA_SRCS})
target_link_libraries(tesla ${WOLFSSL_LIBRARY})

# sample_server
add_executable(sample_server sample_server.c sample.c)
target_link_libraries(sample_server tesla)

# sample_client
add_executable(sample_client sample_client.c sample.c)
target_link_libraries(sample_client tesla)
