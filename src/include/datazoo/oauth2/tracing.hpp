#pragma once

// Minimal tracing shim.
//
// The erpl-web sources this library was extracted from call ERPL_TRACE_*
// macros throughout (see docs/EXTRACTION_NOTES.md). Those macros come from
// erpl-web's own `tracing.hpp`, which is a heavier singleton logger
// (file rotation, trace levels, etc.) that is out of scope for this
// provider-agnostic library and would pull in unrelated machinery.
//
// To keep the moved .cpp files byte-for-byte unchanged (REQ: behaviour
// preserving move), this header defines compatible macros with the exact
// same names and call signature (component, message). By default they are
// silent no-ops so the library never writes to stdout/stderr on its own;
// define DATAZOO_OAUTH2_TRACE_TO_STDERR at compile time (or set the
// environment variable DATAZOO_OAUTH2_TRACE=1 at runtime) to get simple
// stderr line logging, which is useful while debugging a flow locally.
//
// This header intentionally does not reference any vendor/provider name.

#include <cstdlib>
#include <iostream>
#include <string>

namespace duckdb {
namespace datazoo_oauth2 {

inline bool TracingEnabledAtRuntime() {
    const char *v = std::getenv("DATAZOO_OAUTH2_TRACE");
    return v != nullptr && std::string(v) != "0" && std::string(v) != "";
}

inline void EmitTraceLine(const char *level, const std::string &component, const std::string &message) {
#if defined(DATAZOO_OAUTH2_TRACE_TO_STDERR)
    std::cerr << "[" << level << "] " << component << ": " << message << std::endl;
#else
    if (TracingEnabledAtRuntime()) {
        std::cerr << "[" << level << "] " << component << ": " << message << std::endl;
    }
#endif
}

// Minimal stand-in for erpl-web's ErplTracer singleton (tracing.hpp), whose
// only use in the moved http_client.cpp is a single `IsEnabled()` check that
// gates an extra httplib logger callback (itself only for local debugging).
// The heavier machinery (levels, file rotation, output modes) is genuinely
// out of scope for this library.
class SimpleTracer {
public:
    static SimpleTracer &Instance() {
        static SimpleTracer instance;
        return instance;
    }
    bool IsEnabled() const {
        return TracingEnabledAtRuntime();
    }
};

} // namespace datazoo_oauth2
} // namespace duckdb

namespace erpl_web {
// Alias so moved .cpp files that call `ErplTracer::Instance().IsEnabled()`
// (originally erpl-web's tracing.hpp singleton) keep compiling unchanged.
using ErplTracer = ::duckdb::datazoo_oauth2::SimpleTracer;
} // namespace erpl_web

#define ERPL_TRACE_ERROR(component, message) \
    ::duckdb::datazoo_oauth2::EmitTraceLine("ERROR", component, message)
#define ERPL_TRACE_WARN(component, message) \
    ::duckdb::datazoo_oauth2::EmitTraceLine("WARN", component, message)
#define ERPL_TRACE_INFO(component, message) \
    ::duckdb::datazoo_oauth2::EmitTraceLine("INFO", component, message)
#define ERPL_TRACE_DEBUG(component, message) \
    ::duckdb::datazoo_oauth2::EmitTraceLine("DEBUG", component, message)
#define ERPL_TRACE_TRACE(component, message) \
    ::duckdb::datazoo_oauth2::EmitTraceLine("TRACE", component, message)
