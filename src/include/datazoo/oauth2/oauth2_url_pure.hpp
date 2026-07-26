#pragma once

#include "datazoo/oauth2/oauth2_types.hpp"
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

} // namespace erpl_web
