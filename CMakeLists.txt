cmake_minimum_required(VERSION 3.15)

# datazoo-oauth2 -- provider-agnostic OAuth2 library for DuckDB extensions.
#
# Two consumption modes, both required (see README.md):
#
#  1. Standalone: `cmake -S . -B build && cmake --build build && ctest --test-dir build`
#     Builds ONLY the pure-logic sources (no duckdb.hpp, no network) into the
#     Catch2 unit-test binary. DuckDB is not available standalone, so the
#     full library target is not built in this mode.
#
#  2. add_subdirectory() from a DuckDB extension (e.g. duckdb-gdrive,
#     erpl-web), which has already put duckdb.hpp and DuckDB's vendored
#     httplib (`duckdb_httplib_openssl`) on the include path -- this is the
#     "two deliberate couplings" from hld.md §5.4, deliberate and permanent.
#     In this mode the full `datazoo_oauth2` static target is built and can
#     be linked with `target_link_libraries(<your_extension> PRIVATE datazoo_oauth2)`.
#
# We tell the two modes apart with get_directory_property(... PARENT_DIRECTORY):
# if this CMakeLists.txt has a parent, someone add_subdirectory()'d us and is
# expected to have wired up the DuckDB include paths already.

project(datazoo_oauth2 CXX)

set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_directory_property(DATAZOO_OAUTH2_HAS_PARENT PARENT_DIRECTORY)

find_package(OpenSSL REQUIRED)

add_library(datazoo_oauth2_include INTERFACE)
target_include_directories(datazoo_oauth2_include INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/include>
)

# ---------------------------------------------------------------------------
# Source sets
# ---------------------------------------------------------------------------

# Pure-logic sources: no #include "duckdb.hpp", no network, no DuckDB linkage.
# These are the only sources compiled into the standalone Catch2 binary.
set(DATAZOO_OAUTH2_PURE_SOURCES
    src/oauth2_types.cpp
    src/oauth2_browser.cpp
    src/oauth2_callback_handler.cpp
    src/oauth2_url_pure.cpp
)

# DuckDB-coupled sources: need duckdb.hpp and/or DuckDB's vendored httplib.
# Only built when we are add_subdirectory()'d into a DuckDB extension build.
set(DATAZOO_OAUTH2_DUCKDB_SOURCES
    src/charset_converter.cpp
    src/http_client.cpp
    src/timeout_http_client.cpp
    src/oauth2_server.cpp
    src/oauth2_flow_v2.cpp
    src/oauth2_secret_token_manager.cpp
)

if(DATAZOO_OAUTH2_HAS_PARENT)
    add_library(datazoo_oauth2 STATIC
        ${DATAZOO_OAUTH2_PURE_SOURCES}
        ${DATAZOO_OAUTH2_DUCKDB_SOURCES}
    )
    target_include_directories(datazoo_oauth2 PUBLIC src/include)
    target_compile_features(datazoo_oauth2 PUBLIC cxx_std_17)
    target_link_libraries(datazoo_oauth2 PUBLIC OpenSSL::SSL OpenSSL::Crypto)
else()
    message(STATUS
        "datazoo-oauth2: configuring standalone (no parent project). "
        "Only the pure-logic sources + Catch2 unit tests will be built; "
        "the full datazoo_oauth2 target requires DuckDB and is built when "
        "this repo is add_subdirectory()'d from a DuckDB extension.")
endif()

# ---------------------------------------------------------------------------
# Catch2 unit tests -- pure-logic only, no DuckDB linkage, no network.
# ---------------------------------------------------------------------------
find_package(Catch2 3 CONFIG QUIET)
if(Catch2_FOUND)
    file(GLOB DATAZOO_OAUTH2_TEST_SOURCES CONFIGURE_DEPENDS test/test_*.cpp)
    if(DATAZOO_OAUTH2_TEST_SOURCES)
        add_executable(datazoo_oauth2_unit_tests
            ${DATAZOO_OAUTH2_PURE_SOURCES}
            ${DATAZOO_OAUTH2_TEST_SOURCES}
        )
        target_include_directories(datazoo_oauth2_unit_tests PRIVATE src/include)
        target_compile_features(datazoo_oauth2_unit_tests PRIVATE cxx_std_17)
        target_link_libraries(datazoo_oauth2_unit_tests PRIVATE
            Catch2::Catch2WithMain
            OpenSSL::Crypto
        )
        set_target_properties(datazoo_oauth2_unit_tests PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
        )

        # Match the static CRT (/MT) of vcpkg-provided deps (Catch2/OpenSSL
        # ship from a *-static-* triplet on Windows). Without this, a naked
        # add_executable() defaults to /MD and fails to link Catch2 with
        # LNK2038 (RuntimeLibrary mismatch). Same gotcha quack-oauth hit
        # (quack-oauth/CMakeLists.txt) -- MSVC-only, ignored elsewhere.
        if(MSVC)
            set_target_properties(datazoo_oauth2_unit_tests PROPERTIES
                MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
            )
        endif()

        include(CTest)
        include(Catch)
        catch_discover_tests(datazoo_oauth2_unit_tests)
    endif()
else()
    message(STATUS "datazoo-oauth2: Catch2 3 not found, unit test target skipped.")
endif()

# ---------------------------------------------------------------------------
# S-0.15 / REQ-A-03: zero-vendor-names CI gate, wired into the build so it
# runs the same way locally and in CI (`cmake --build build --target
# check_no_vendor_names`, or via `ctest` alongside the unit tests).
# ---------------------------------------------------------------------------
find_program(DATAZOO_OAUTH2_BASH_EXE bash)
if(DATAZOO_OAUTH2_BASH_EXE)
    add_custom_target(check_no_vendor_names
        COMMAND ${DATAZOO_OAUTH2_BASH_EXE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_no_vendor_names.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Checking src/ for vendor-specific code (REQ-A-03)"
        VERBATIM
    )
    include(CTest)
    add_test(NAME check_no_vendor_names
        COMMAND ${DATAZOO_OAUTH2_BASH_EXE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_no_vendor_names.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()
