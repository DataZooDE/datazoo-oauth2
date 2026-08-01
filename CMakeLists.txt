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

    # See the note on the unit-test target below: oauth2_browser.cpp needs
    # platform libraries on macOS and Windows. PUBLIC so a consumer linking
    # this static library inherits them -- otherwise the undefined symbols
    # surface in the CONSUMER's link step, which is a considerably worse place
    # to find out.
    if(APPLE)
        target_link_libraries(datazoo_oauth2 PUBLIC
            "-framework CoreFoundation"
            "-framework ApplicationServices"
        )
    elseif(WIN32)
        target_link_libraries(datazoo_oauth2 PUBLIC shell32)
    endif()

    # DuckDB installs and EXPORTS the consuming extension target. CMake refuses
    # to export a target that links one which is not itself in an export set:
    #
    #   install(EXPORT "DuckDBExports" ...) includes target "<ext>_extension"
    #   which requires target "datazoo_oauth2" that is not in any export set.
    #
    # Guarded on the variable being defined so a non-DuckDB parent (or the
    # standalone build) is unaffected. Same pattern as posthog-telemetry.
    if(DEFINED DUCKDB_EXPORT_SET)
        install(
            TARGETS datazoo_oauth2
            EXPORT "${DUCKDB_EXPORT_SET}"
            LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
            ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
        )
    endif()
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
# Only when we are the top-level project. A consumer that add_subdirectory()s
# this library wants the library, not its test suite.
#
# Building them in a consumer's tree is not merely wasteful, it breaks the
# build: vcpkg ships Catch2 against the DYNAMIC CRT (/MD) while a DuckDB
# extension compiles its sources against the STATIC one (/MT), so the link
# fails with
#
#   Catch2.lib(catch_stringref.cpp.obj) : error LNK2038: mismatch detected for
#   'RuntimeLibrary': value 'MD_DynamicRelease' doesn't match value
#   'MT_StaticRelease' in oauth2_types.cpp.obj
#
# That is what broke duckdb-gdrive's Windows LTS build. It surfaced there and
# not in erpl-web purely because gdrive's vcpkg manifest happens to include
# catch2, so find_package succeeded and the target got built; erpl-web's does
# not, so it was silently skipped. Consumers should not depend on that luck.
if(NOT DATAZOO_OAUTH2_HAS_PARENT)
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

        # oauth2_browser.cpp opens the system browser through platform APIs.
        # On Linux that is fork/exec and needs nothing; on macOS and Windows it
        # needs libraries the linker will not find by itself. This never
        # surfaced before CI existed, because the library had only ever been
        # built on Linux -- which is the entire argument for having CI here
        # rather than discovering it in a consumer's release build.
        if(APPLE)
            target_link_libraries(datazoo_oauth2_unit_tests PRIVATE
                "-framework CoreFoundation"
                "-framework ApplicationServices"
            )
        elseif(WIN32)
            # ShellExecute* lives in shell32.
            target_link_libraries(datazoo_oauth2_unit_tests PRIVATE shell32)
        endif()

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
endif() # NOT DATAZOO_OAUTH2_HAS_PARENT

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
