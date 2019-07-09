cmake_minimum_required(VERSION 3.7)

project(test_crypto)
if(NOT CRYPTO_DIR)
	message(FATAL_ERROR "Please set CRYPTO_DIR env var")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../cmake")

find_package(Crypto)

if(CRYPTO_FOUND)
	message(STATUS "CRYPTO_LIBRARIES=${CRYPTO_LIBRARIES}")
	message(STATUS "CRYPTO_INCLUDE_DIR=${CRYPTO_INCLUDE_DIRS}")
endif()


