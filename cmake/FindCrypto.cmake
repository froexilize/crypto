find_path(
		CRYPTO_INCLUDE_DIR
		NAMES crypto/crypto.h
		PATHS
			/usr/local/include
			/usr/include
			${CRYPTO_DIR}/include
			${CRYPTO_DIR}/usr/include
			${CRYPTO_DIR}/usr/local/include
)

message(STATUS "CRYPTO_DIR=${CRYPTO_DIR}")

if(CRYPTO_INCLUDE_DIR)
	find_library(CRYPTO_LIBRARY
			NAMES ra_lib
			PATHS
				/usr/local/lib
				/usr/lib
				${CRYPTO_DIR}/lib
				${CRYPTO_DIR}/usr/lib
				${CRYPTO_DIR}/usr/local/lib
	)
	if(CRYPTO_LIBRARY)
		set(CRYPTO_LIBRARY_DIR "")
		get_filename_component(CRYPTO_LIBRARY_DIRS ${CRYPTO_LIBRARY} PATH)
		set(CRYPTO_FOUND ON)
		set(CRYPTO_INCLUDE_DIRS ${CRYPTO_INCLUDE_DIR})
		set(CRYPTO_LIBRARIES ${CRYPTO_LIBRARY})
	endif()
else()
	message(STATUS "FindCrypto: Could not find crypto.h")
endif()

if(CRYPTO_FOUND)
	if(NOT CRYPTO_FIND_QUIETLY)
		message(STATUS "FindCrypto: Found crypto.h and ra_lib")
	endif()
else()
	if(CRYPTO_FIND_REQUIRED)
		message(FATAL_ERROR "FindCrypto: Could not find crypto.h and/or ra_lib")
	endif()
endif()

