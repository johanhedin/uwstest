cmake_minimum_required(VERSION 3.10...3.27)
project(uwstest C CXX)

# We use C17 and C++20
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# We need the PkgConfig cmake module to be able to find libraries we depend on
find_package(PkgConfig REQUIRED)

# Use GNUInstallDirs to get standard install directories for include, lib, bin and so on
include(GNUInstallDirs)

FILE(GLOB USOCKET_SRCS "uWebSockets/uSockets/src/*.c"
                       "uWebSockets/uSockets/src/eventing/*.c"
                       "uWebSockets/uSockets/src/crypto/*.c"
                       "uWebSockets/uSockets/src/crypto/*.cpp"
)
add_library(usockets ${USOCKET_SRCS})
target_include_directories(usockets PRIVATE ${PROJECT_SOURCE_DIR}/uWebSockets/uSockets/src)

#target_compile_options(usockets PRIVATE "-Wno-unused-parameter")
#target_compile_options(usockets PRIVATE "-Wno-sign-compare")
#target_compile_options(usockets PRIVATE "-Wno-use-after-free")
target_compile_options(usockets PRIVATE "-Wno-deprecated-declarations")

target_compile_options(usockets PRIVATE "-DLIBUS_USE_OPENSSL")
target_compile_options(usockets PRIVATE "-DLIBUS_USE_LIBUV")

add_executable(${CMAKE_PROJECT_NAME} src/main.cpp)
target_link_libraries(${CMAKE_PROJECT_NAME} usockets)

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wall)
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wextra)
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -pedantic)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/uWebSockets/uSockets/src)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/uWebSockets/src)

pkg_check_modules(LIBUV REQUIRED libuv)
include_directories(${LIBUV_INCLUDE_DIRS})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBUV_LIBRARIES})

pkg_check_modules(ZLIB REQUIRED zlib)
include_directories(${ZLIB_INCLUDE_DIRS})
target_link_libraries(${CMAKE_PROJECT_NAME} ${ZLIB_LIBRARIES})

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
target_link_libraries(${CMAKE_PROJECT_NAME} ${OPENSSL_LIBRARIES})
