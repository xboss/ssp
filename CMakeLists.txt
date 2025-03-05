cmake_minimum_required(VERSION 3.10)
project(ssp)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_WALL ON)


# 添加源文件
set(SOURCE_FILES
src/crypto.c
src/main.c
src/ssconf.c
src/sslog.c
src/sspipe.c
src/sstcp.c
src/stream_buf.c
)


############# ssp #############
add_executable(ssp ${SOURCE_FILES})
target_link_libraries(ssp ssl)
target_link_libraries(ssp crypto)
target_link_libraries(ssp pthread)


############# static #############
# add_executable(ssp_static ${SOURCE_FILES})
# target_link_libraries(ssp_static ssl -static)
# target_link_libraries(ssp_static crypto -static)

#cmake -DCMAKE_BUILD_TYPE=Debug ..
