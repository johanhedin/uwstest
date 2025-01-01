cmake_minimum_required(VERSION 3.10...3.27)
project(sdrx C CXX)

# We use C17 and C++20 stuff
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# We need the PkgConfig cmake module to be able to find libraries we depend on
find_package(PkgConfig REQUIRED)

# Use GNUInstallDirs to get standard install directories for include, lib, bin and so on
include(GNUInstallDirs)

add_executable(uwstest src/main.cpp)

pkg_check_modules(LIBUV REQUIRED libuv)
include_directories(${LIBUV_INCLUDE_DIRS})
target_link_libraries(uwstest ${LIBUV_LIBRARIES})

pkg_check_modules(ZLIB REQUIRED zlib)
include_directories(${ZLIB_INCLUDE_DIRS})
target_link_libraries(uwstest ${ZLIB_LIBRARIES})

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
target_link_libraries(uwstest ${OPENSSL_LIBRARIES})
