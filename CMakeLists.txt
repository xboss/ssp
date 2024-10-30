cmake_minimum_required(VERSION 3.20.0)
project(ssp VERSION 0.1.0)


#SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -std=c89 -O0 -Wno-deprecated-declarations -DDEBUG -ggdb -fsanitize=address")
SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -DDEBUG -g -ggdb ")
SET(CMAKE_C_FLAGS_RELEASE "$ENV{CXXFLAGS} -std=c89 -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR} compiler: ${CMAKE_C_COMPILER_ID} platform: ${CMAKE_SYSTEM_NAME}")

#link_directories("/usr/local/lib")

include_directories(${PROJECT_SOURCE_DIR}/src/)

aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SRCS)

############# ssp #############
add_executable(ssp ${DIR_SRCS})
target_link_libraries(ssp ssl)
target_link_libraries(ssp crypto)

aux_source_directory(${PROJECT_SOURCE_DIR}/src/socks DIR_SOCKS_SRCS)
############# socks5 server (linux only) #############
if(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
list(APPEND DIR_SOCKS_SRCS "${PROJECT_SOURCE_DIR}/src/sslog.c")
list(APPEND DIR_SOCKS_SRCS "${PROJECT_SOURCE_DIR}/src/ssev_epoll.c")
list(APPEND DIR_SOCKS_SRCS "${PROJECT_SOURCE_DIR}/src/sspipe.c")
list(APPEND DIR_SOCKS_SRCS "${PROJECT_SOURCE_DIR}/src/ssnet.c")
list(APPEND DIR_SOCKS_SRCS "${PROJECT_SOURCE_DIR}/src/stream_buf.c")
list(APPEND DIR_SOCKS_SRCS "${PROJECT_SOURCE_DIR}/src/pconn.c")
list(APPEND DIR_SOCKS_SRCS "${PROJECT_SOURCE_DIR}/src/cipher.c")
list(APPEND DIR_SOCKS_SRCS "${PROJECT_SOURCE_DIR}/src/thread_pool.c")
add_executable(socks5_server ${DIR_SOCKS_SRCS})
#target_compile_definitions(socks5_server PUBLIC -DSOCKS5)
target_link_libraries(socks5_server pthread)
target_link_libraries(socks5_server ssl)
target_link_libraries(socks5_server crypto)
endif()


# ############# static #############
# add_executable(ssp ${DIR_SRCS})
# target_link_libraries(ssp_static ssl -static)
# target_link_libraries(ssp_static crypto -static)

#cmake -DCMAKE_BUILD_TYPE=Debug ..
