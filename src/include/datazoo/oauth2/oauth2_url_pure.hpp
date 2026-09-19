#pragma once

#include "datazoo/oauth2/oauth2_types.hpp"
#include <cstddef>
#include <string>

namespace erpl_web {

// Pure (no DuckDB linkage, no network) helpers extracted from
// OAuth2FlowV2::BuildAuthorizationUrl so they can be tested with the
// project's Catch2 unit-test binary (see docs/EXTRACTION_NOTES.md).
//
// OAuth2FlowV2 itself is DuckDB-coupled (it pulls in yyjson + the HTTP
// client), so its private method just delegates to this free function --
// this is the "one header, a _pure.cpp with no DuckDB linkage" split the
// implementation plan asks for (mirrors quack-oauth's module convention).

// application/x-www-form-urlencoded percent-encoding used throughout the
// OAuth2 flow (spaces as '+', RFC 3986 unreserved characters passed
// through). Identical to the private UrlEncode() previously duplicated in
// oauth2_flow_v2.cpp and microsoft_entra_secret.cpp.
std::string UrlEncode(const std::string &value);

// Builds the authorization-request URL. Behaviour-preserving: when
// config.extra_auth_params is empty the output is byte-identical to
// erpl-web's pre-extraction BuildAuthorizationUrl. When populated, each
// entry is appended as an additional `&key=value` query parameter (used by
// Google's access_type=offline&prompt=consent requirement, S-0.13).
std::string BuildAuthorizationUrlPure(const OAuth2Config &config, const std::string &code_challenge,
                                       const std::string &state);


// ---------------------------------------------------------------------------
// Security primitives for the authorization_code flow.
//
// Here, in the pure-logic translation unit, because this is the only part of the library
// the standalone Catch2 target compiles - and these two are exactly the things that need
// covering. See DataZooDE/erpl-web#248.

// Cryptographically secure random, base64url-encoded, unpadded.
//
// The PKCE code_verifier and the CSRF state both come from here. They were drawn from
// std::mt19937 seeded with one 32-bit std::random_device value, which fails twice: mt19937
// is not a CSPRNG, so one output reveals the state and the next value, and a <=2^32 seed
// space is brute-forceable anyway. Predicting either defeats the protection it exists for.
//
// Throws if the system CSPRNG is unavailable rather than falling back to anything weaker:
// a caller cannot distinguish a weak token from a strong one.
//
// The output alphabet is RFC 7636's unreserved set, so the result is a valid code_verifier
// as-is. Encoding raw bytes also avoids the modulo bias that indexing a 66-character
// charset with uniform_int_distribution carried.
std::string GenerateSecureRandomToken(std::size_t num_bytes);

// Escapes text for interpolation into HTML.
//
// The loopback callback server's error page wrote the `error` and `error_description` query
// parameters into its markup raw - on the origin that RECEIVES AUTHORIZATION CODES. While
// the flow waits, any page the browser visits can navigate to
// http://localhost:<port>/?error=<img src=x onerror=...> and run script in that origin.
std::string EscapeHtmlText(const std::string &text);

} // namespace erpl_web
