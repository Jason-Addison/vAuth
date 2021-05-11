# CMakeList.txt : CMake project for Auravyx-Launcher, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("vAuth")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE vAuthSource CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/Source/*.h" "${CMAKE_SOURCE_DIR}/Source/*.cpp")

# Add source to this project's executable.
add_executable (vAuth ${vAuthSource})

target_link_libraries(vAuth pthread -ldl)

include_directories(src ${CMAKE_SOURCE_DIR}/Source)
include_directories(src ${CMAKE_SOURCE_DIR}/Dependencies/Include)

include_directories(src ${CMAKE_SOURCE_DIR}/)

#####################
#      OpenSSL      #
#####################

add_subdirectory(${CMAKE_SOURCE_DIR}/Dependencies/Include/openssl)

if(WIN32)
add_library(OpenSSL STATIC IMPORTED ${CMAKE_SOURCE_DIR}/Dependencies/Lib/windows/libssl_static.lib)
set_target_properties(OpenSSL PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/Dependencies/Lib/windows/libssl_static.lib)
target_link_libraries(vAuth ${CMAKE_SOURCE_DIR}/Dependencies/Lib/windows/libssl_static.lib ${CMAKE_SOURCE_DIR}/Dependencies/Lib/windows/libcrypto_static.lib)
endif(WIN32)
if(UNIX)
add_library(OpenSSL STATIC IMPORTED ${CMAKE_SOURCE_DIR}/Dependencies/Lib/unix/libssl.a)
set_target_properties(OpenSSL PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/Dependencies/Lib/unix/libssl.a)
target_link_libraries(vAuth ${CMAKE_SOURCE_DIR}/Dependencies/Lib/unix/libssl.a ${CMAKE_SOURCE_DIR}/Dependencies/Lib/unix/libcrypto.a -ldl)
endif(UNIX)
set_target_properties(OpenSSL PROPERTIES INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/Dependencies/Include/OpenSSL/include)
target_link_libraries(vAuth OpenSSL)