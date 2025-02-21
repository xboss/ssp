cmake_minimum_required(VERSION 3.20.0)
project(ssp VERSION 0.1.0)


#SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -std=c89 -O0 -Wno-deprecated-declarations -DDEBUG -ggdb -fsanitize=address")
SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -DDEBUG -g -ggdb ")
SET(CMAKE_C_FLAGS_RELEASE "$ENV{CXXFLAGS} -std=c99 -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR} compiler: ${CMAKE_C_COMPILER_ID} platform: ${CMAKE_SYSTEM_NAME}")

#link_directories("/usr/local/lib")

include_directories(${PROJECT_SOURCE_DIR}/src/)

aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SRCS)

############# ssp #############
# add_executable(ssp ${DIR_SRCS})
# target_link_libraries(ssp ssl)
# target_link_libraries(ssp crypto)


############# static #############
# add_executable(ssp_static ${DIR_SRCS})
# target_link_libraries(ssp_static ssl -static)
# target_link_libraries(ssp_static crypto -static)

############# test #############
list(REMOVE_ITEM DIR_SRCS "${PROJECT_SOURCE_DIR}/src/main.c")
message("DIR_SRCS: ${DIR_SRCS}")
add_executable(test ${DIR_SRCS})
target_link_libraries(test pthread)
target_link_libraries(test ssl)
target_link_libraries(test crypto)

#cmake -DCMAKE_BUILD_TYPE=Debug ..
