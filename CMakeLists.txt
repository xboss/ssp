cmake_minimum_required(VERSION 3.20.0)
project(ssp VERSION 0.1.0)


SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -std=c89 -O0 -Wno-deprecated-declarations -DDEBUG -ggdb")
# SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb ")
SET(CMAKE_C_FLAGS_RELEASE "$ENV{CXXFLAGS} -std=c89 -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR} compiler: ${CMAKE_C_COMPILER_ID} platform: ${CMAKE_SYSTEM_NAME}")

#link_directories("/usr/local/lib")

include_directories(${PROJECT_SOURCE_DIR}/src/)

aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SRCS)

############# ssp #############
add_executable(ssp ${DIR_SRCS})
target_link_libraries(ssp ssl)
target_link_libraries(ssp crypto)

############# socks5 server (linux only) #############
if(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
ADD_DEFINITIONS(-DSOCKS5)
#SET (SOCKS5_SRCS network.c nwpipe.c socks.c main.c ssev_epoll.c dns_resolver.c thread_pool.c)
#add_executable(socks5_server ${SOCKS5_SRCS})
list(REMOVE_ITEM DIR_SRCS "${PROJECT_SOURCE_DIR}/src/cipher.c")
#message("src:${DIR_SRCS}")
add_executable(socks5_server ${DIR_SRCS})
target_link_libraries(socks5_server pthread)
endif()


# ############# static #############
# add_executable(ssp ${DIR_SRCS})
# target_link_libraries(ssp_static ssl -static)
# target_link_libraries(ssp_static crypto -static)

#cmake -DCMAKE_BUILD_TYPE=Debug ..
