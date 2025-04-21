cmake_minimum_required(VERSION 3.12)
project(SEcrypt)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -zmuldefs")

#find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

set(SRCS src/main.cpp src/md5.cpp src/aes256.cpp src/dFile.cpp src/crypt.cpp src/tracealloc.cpp src/stealth.c src/rsa.cpp src/textsteg.cpp)

add_executable(SEcrypt ${SRCS} )
target_link_libraries(SEcrypt ${CURSES_LIBRARIES})
add_subdirectory(builder)
