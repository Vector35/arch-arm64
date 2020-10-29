cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(arch_arm64)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()
if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h
	disassembler/*.c
	disassembler/*.h)

if(DEMO)
	add_library(arch_arm64 STATIC ${SOURCES})
else()
	add_library(arch_arm64 SHARED ${SOURCES})
endif()

if(NOT WIN32)
	set_source_files_properties(disassembler/arm64dis.c PROPERTIES COMPILE_FLAGS -fno-strict-aliasing)
endif()

target_include_directories(arch_arm64
	PRIVATE ${PROJECT_SOURCE_DIR}
	PRIVATE ${PROJECT_SOURCE_DIR}/disassembler)

target_link_libraries(arch_arm64 binaryninjaapi)

set_target_properties(arch_arm64 PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(arch_arm64)
	set_target_properties(arch_arm64 PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
