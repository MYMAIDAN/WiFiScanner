cmake_minimum_required(VERSION 3.10)

project(WiFiScanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FindPkgConfig)
pkg_search_module(LIBNL REQUIRED libnl-genl-3.0)
set(CMAKE_CXX_FLAGS -pthread )
add_executable(WiFiScanner main.cpp WiFiScanner.cpp)


target_include_directories(WiFiScanner SYSTEM PUBLIC ${LIBNL_INCLUDE_DIRS})
target_link_libraries(WiFiScanner ${LIBNL_LIBRARIES})

