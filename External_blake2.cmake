include(ExternalProject)

ExternalProject_Add(blake2_ext
	GIT_REPOSITORY https://github.com/froexilize/BLAKE2.git
	SOURCE_DIR "${CMAKE_BINARY_DIR}/third-party/blake2-src"
	BINARY_DIR "${CMAKE_BINARY_DIR}/third-party/blake2-build"
	UPDATE_COMMAND ""
	CONFIGURE_COMMAND ""
	BUILD_COMMAND ""
	INSTALL_COMMAND ""
	TEST_COMMAND ""
	)
set(BLAKE2_INCLUDE_DIR "${CMAKE_BINARY_DIR}/third-party/blake2-src/sse" CACHE PATH "Blake2 include directory" FORCE)

set(BLAKE2_SOURCES "${BLAKE2_INCLUDE_DIR}/blake2b.c")
set_source_files_properties(${BLAKE2_SOURCES} PROPERTIES GENERATED TRUE)

