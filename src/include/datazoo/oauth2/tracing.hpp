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
//
// ---------------------------------------------------------------------------
// Consumers with their own tracer: define DATAZOO_OAUTH2_USE_HOST_TRACING.
//
// The shim below defines ERPL_TRACE_* macros AND an `erpl_web::ErplTracer`
// alias. A consumer that already has both -- which is the case for the
// codebase these sources came from, whose tracing.hpp declares a real
// `class ErplTracer` and its own macros -- would hit a macro redefinition and
// an outright type conflict in every translation unit that sees both headers.
//
// So when DATAZOO_OAUTH2_USE_HOST_TRACING is defined, this header defines
// NOTHING and the host's tracing header is expected to be on the include path
// and included first (the library's .cpp files include it via this header).
// That is deterministic, unlike an `#ifndef ERPL_TRACE_ERROR` guard, which
// would silently depend on include order.
// ---------------------------------------------------------------------------

#if defined(DATAZOO_OAUTH2_USE_HOST_TRACING)

// The host owns the macros and the tracer type. Pull its header in so the
// moved .cpp files -- which include only this one -- still resolve them.
//
// Angle brackets, not quotes, and it matters: a quoted include searches the
// includer's own directory first, so `"tracing.hpp"` from THIS file resolves
// to THIS file, which `#pragma once` then turns into a silent no-op --
// leaving every macro undefined. Angle brackets search only the -I path,
// where the host's src/include lives.
#include <tracing.hpp> // NOLINT: resolved from the CONSUMER's include path

#else

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

#endif // DATAZOO_OAUTH2_USE_HOST_TRACING
