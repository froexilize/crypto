cmake_minimum_required(VERSION 3.7)

project(test_crypto)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../cmake")

find_package(Crypto)

if(CRYPTO_FOUND)
	message(STATUS "CRYPTO_LIBRARIES=${CRYPTO_LIBRARIES}")
	message(STATUS "CRYPTO_INCLUDE_DIR=${CRYPTO_INCLUDE_DIRS}")
endif()


