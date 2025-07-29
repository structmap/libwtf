if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    cmake_minimum_required(VERSION 3.20)
else()
    cmake_minimum_required(VERSION 3.16)
endif()

include(cmake/GetGitVersion.cmake)
get_git_version(GIT_VERSION WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

project(wtf 
    VERSION ${GIT_VERSION_MAJOR}.${GIT_VERSION_MINOR}.${GIT_VERSION_PATCH}
    DESCRIPTION "High-Performance WebTransport Library"
    LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set(WTF_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/output CACHE STRING "Output directory for build artifacts")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${WTF_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${WTF_OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${WTF_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${WTF_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${WTF_OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${WTF_OUTPUT_DIR})

foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG} CONFIG_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG})
endforeach()

option(WTF_BUILD_TESTS "Build tests" OFF)
option(WTF_BUILD_SAMPLES "Build sample applications" OFF)
option(WTF_ENABLE_LOGGING "Enable logging support" ON)
option(WTF_USE_EXTERNAL_MSQUIC "Use an external msquic installation" OFF)

set(WTF_VERSION ${GIT_VERSION})
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/wtf_version.h
    @ONLY
)

set(WTF_LIBRARY_NAME "wtf")
set(WTF_VERSION_MAJOR ${GIT_VERSION_MAJOR})
set(WTF_VERSION_MINOR ${GIT_VERSION_MINOR})
set(WTF_VERSION_PATCH ${GIT_VERSION_PATCH})

if(WIN32)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /NODEFAULTLIB:libucrt.lib /DEFAULTLIB:ucrt.lib")
    add_compile_definitions(WIN32_LEAN_AND_MEAN)
    if(HAS_SPECTRE)
        add_compile_options(/Qspectre)
    endif()
    add_compile_options(/W3)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Od /Zi /RTC1)
        add_link_options(/DEBUG:FULL)
    else()
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL /Zi")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL /Zi")
        set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
        add_compile_options(/O2 /DNDEBUG)
    endif()
else()
    add_compile_options(-Wall -Wextra)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0 -DDEBUG -fno-omit-frame-pointer)
        if(APPLE)
            add_compile_options(-fno-limit-debug-info -gdwarf-4)
            add_link_options(-Wl,-no_compact_unwind)
        endif()
    else()
        add_compile_options(-O2 -DNDEBUG)
        add_link_options(-flto)
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            add_compile_options(-fuse-linker-plugin -ffat-lto-objects)
            add_link_options(-fuse-linker-plugin)
        endif()
    endif()
endif()

if(WTF_USE_EXTERNAL_MSQUIC)
    find_package(msquic CONFIG REQUIRED)
    set(MSQUIC_LIBRARIES msquic)
else()
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    
    if(WIN32)
        set(QUIC_TLS_LIB "schannel" CACHE STRING "Use Schannel on Windows")
    else()
        set(QUIC_TLS_LIB "openssl" CACHE STRING "Use OpenSSL on non-Windows")
    endif()
    
    set(QUIC_BUILD_SHARED ON CACHE BOOL "Builds MsQuic as a dynamic library")
    set(QUIC_BUILD_TOOLS OFF CACHE BOOL "Don't build MsQuic tools")
    set(QUIC_BUILD_TEST OFF CACHE BOOL "Don't build MsQuic tests")
    set(QUIC_BUILD_PERF OFF CACHE BOOL "Don't build MsQuic perf tools")
    
    if(CMAKE_CONFIGURATION_TYPES)
        set(QUIC_OUTPUT_DIR ${WTF_OUTPUT_DIR}/$<CONFIG> CACHE STRING "Output directory for MsQuic artifacts")
    else()
        set(QUIC_OUTPUT_DIR ${WTF_OUTPUT_DIR} CACHE STRING "Output directory for MsQuic artifacts")
    endif()
    
    if(WTF_ENABLE_LOGGING OR CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(QUIC_ENABLE_LOGGING ON CACHE BOOL "Enable MsQuic logging")
        set(QUIC_LOGGING_TYPE "stdout" CACHE STRING "Set MsQuic logging output to stdout")
    else()
        set(QUIC_ENABLE_LOGGING OFF CACHE BOOL "Disable MsQuic logging")
    endif()
    
    add_compile_definitions(QUIC_API_ENABLE_PREVIEW_FEATURES=1)

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-Wno-invalid-unevaluated-string)
    endif()
    
    add_subdirectory(msquic)
    
    if(TARGET msquic)
        set_target_properties(msquic PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR}
            LIBRARY_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR}
            ARCHIVE_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR}
        )
        foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
            string(TOUPPER ${CONFIG} CONFIG_UPPER)
            set_target_properties(msquic PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG}
                LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG}
                ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG}
            )
        endforeach()
    endif()
    
    set(MSQUIC_LIBRARIES msquic)
    set(MSQUIC_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/msquic/src/inc)
endif()

if(WIN32)
    set(PLATFORM_LIBS ws2_32 iphlpapi bcrypt)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        list(APPEND PLATFORM_LIBS dbghelp)
    endif()
else()
    find_package(Threads REQUIRED)
    set(PLATFORM_LIBS Threads::Threads)
    if(NOT APPLE)
        list(APPEND PLATFORM_LIBS rt)
        list(APPEND PLATFORM_LIBS m)
    else()
        list(APPEND PLATFORM_LIBS "-framework Security")
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            list(APPEND PLATFORM_LIBS dl)
        endif()
        if(APPLE)
            list(APPEND PLATFORM_LIBS "-framework CoreFoundation")
        endif()
    endif()
endif()

if(WIN32)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/export/windows/wtf.def.in
        ${CMAKE_CURRENT_BINARY_DIR}/wtf.def
        @ONLY
    )
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/export/windows/wtf.rc.in
        ${CMAKE_CURRENT_BINARY_DIR}/wtf.rc
        @ONLY
    )
    set(WTF_EXPORT_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/wtf.rc)
else()
    set(WTF_EXPORT_SOURCES "")
endif()

set(WTF_SOURCES
    deps/tinycthreads/tinycthread.c
    deps/ls-qpack/lsqpack.c
    deps/xxhash/xxhash.c
    src/log.c
    src/qpack.c
    src/varint.c
    src/utils.c
    src/datagram.c
    src/stream.c
    src/session.c   
    src/settings.c
    src/conn.c
    src/http3.c
    src/server.c
    src/context.c
    ${WTF_EXPORT_SOURCES}
)

set(WTF_PUBLIC_HEADERS
    include/wtf.h
)

add_library(wtf SHARED ${WTF_SOURCES})

set_target_properties(wtf PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${WTF_PUBLIC_HEADERS}"
)

if(WIN32)
    set_target_properties(wtf PROPERTIES
        ARCHIVE_OUTPUT_NAME wtf
        RUNTIME_OUTPUT_NAME wtf
    )
endif()

target_include_directories(wtf
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycthreads
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ls-qpack
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/xxhash
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/verstable
        ${MSQUIC_INCLUDE_DIRS}
)

if(WIN32 OR EMSCRIPTEN)
    target_include_directories(wtf PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/wincompat
    )
endif()

target_link_libraries(wtf
    PRIVATE
        ${MSQUIC_LIBRARIES}
        ${PLATFORM_LIBS}
)

if(WTF_ENABLE_LOGGING)
    target_compile_definitions(wtf PRIVATE WTF_ENABLE_LOGGING=1)
endif()

target_compile_definitions(wtf PRIVATE WTF_EXPORTS)

if(NOT WIN32)
    target_compile_options(wtf PRIVATE -fvisibility=hidden)
    target_compile_options(wtf PRIVATE -fvisibility-inlines-hidden)
endif()

if(WIN32)
    set_target_properties(wtf PROPERTIES
        LINK_FLAGS "/DEF:${CMAKE_CURRENT_BINARY_DIR}/wtf.def"
    )
elseif(APPLE)
    set_target_properties(wtf PROPERTIES
        LINK_FLAGS "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/export/darwin/exports.txt -Wl,-dead_strip -Wl,-x"
    )
elseif(UNIX)
    set_target_properties(wtf PROPERTIES
        LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/export/linux/exports.txt -Wl,--gc-sections -Wl,--strip-all"
    )
endif()

if(NOT WIN32)
    set_target_properties(wtf PROPERTIES
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
    )
endif()

add_library(WebTransport::wtf ALIAS wtf)

if(WTF_BUILD_SAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/samples")
    add_subdirectory(samples)
endif()

if(WTF_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    enable_testing()
    add_subdirectory(tests)
endif()

include(GNUInstallDirs)

install(FILES ${WTF_PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(TARGETS wtf
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)