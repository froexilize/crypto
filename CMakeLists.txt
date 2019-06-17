cmake_minimum_required(VERSION 3.7)

#configure_file(CMakeLists.txt.in blake2-download/CMakeLists.txt)
#execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
#	RESULT_VARIABLE result
#	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/blake2-download)
#if(result)
#	message(FATAL_ERROR "CMake step for blake2 failed: ${result}")
#endif()
#add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/blake2-src
#	${CMAKE_CURRENT_BINARY_DIR}/blake2-build
#	EXCLUDE_FROM_ALL)
#include_directories("${blake2_SOURCE_DIR}/include")

project(crypto)

set(CMAKE_CXX_STANDARD 11)

function(assign_source_group)
	foreach(_source IN ITEMS ${ARGN})
		if (IS_ABSOLUTE "${_source}")
			file(RELATIVE_PATH _source_rel "${CMAKE_CURRENT_SOURCE_DIR}" "${_source}")
		else()
			set(_source_rel "${_source}")
		endif()
		get_filename_component(_source_path "${_source_rel}" PATH)
		string(REPLACE "/" "\\" _source_path_msvc "${_source_path}")
		source_group("${_source_path_msvc}" FILES "${_source}")
	endforeach()
endfunction(assign_source_group)

if(MSVC)
	add_definitions(/arch:AVX)
endif()

include("External_blake2.cmake")
include_directories("${BLAKE2_INCLUDE_DIR}")

file(GLOB ED_SRCS "ed25519/src/*.c*")
file(GLOB CSC_SRCS "crypto/src/*.cpp")
file(GLOB CURV_SRCS "contrib/curve25519-donna/curve25519-donna-c64.c")

set(RALIB_FILES
	${BLAKE2_SOURCES}
	${ED_SRCS}
	${CSC_SRCS}
	curve25519.h
	curve25519.cpp
	rc4/rc4.c
	rc4/rc4.h
	crypto/src/crypto.cpp
	)

# Build both shared and static lib
add_library(crypto SHARED ${RALIB_FILES}
		crypto/include/defs.h
		crypto/include/export_decl.h
		crypto/include/ra_types.h
		crypto/include/macro.h
		crypto/include/ra_log.h
		crypto/src/ra_log.cpp)

add_library(crypto_static ${RALIB_FILES})

assign_source_group(${RALIB_FILES})

target_include_directories(crypto_static SYSTEM PUBLIC rc4)
target_include_directories(crypto_static SYSTEM PUBLIC ed25519/src)
target_include_directories(crypto_static SYSTEM PUBLIC crypto/include)
target_include_directories(crypto_static SYSTEM PUBLIC ./)
target_link_libraries(crypto_static)

set_target_properties(crypto_static PROPERTIES OUTPUT_NAME ra_lib)

target_include_directories(crypto SYSTEM PUBLIC rc4)
target_include_directories(crypto SYSTEM PUBLIC ed25519/src)
target_include_directories(crypto SYSTEM PUBLIC crypto/include)
target_include_directories(crypto SYSTEM PUBLIC ./)
target_link_libraries(crypto)

add_dependencies(crypto blake2_ext)
add_dependencies(crypto_static blake2_ext)

