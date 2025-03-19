cmake_minimum_required(VERSION 3.10)
project(ssp)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wno-unused-function -D_GNU_SOURCE")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -D_GNU_SOURCE")

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# 添加源文件
set(SOURCE_FILES
src/sspipe.c
src/crypto.c
src/ssconf.c
src/sslog.c
src/ssbuff.c
# src/ssp_server.c
# src/main.c
)


############# ssp #############
add_executable(ssp ${SOURCE_FILES})
target_link_libraries(ssp ssl)
target_link_libraries(ssp crypto)
target_link_libraries(ssp ev)

# add_executable(ssplibev ${SOURCE_FILES})
# target_link_libraries(ssplibev ssl)
# target_link_libraries(ssplibev crypto)
# target_link_libraries(ssplibev ev)


############# static #############
# add_executable(ssplibev_static ${SOURCE_FILES})
# target_link_libraries(ssplibev_static ssl -static)
# target_link_libraries(ssplibev_static crypto -static)
# target_link_libraries(ssplibev_static ev -static)

#cmake -DCMAKE_BUILD_TYPE=Debug ..
