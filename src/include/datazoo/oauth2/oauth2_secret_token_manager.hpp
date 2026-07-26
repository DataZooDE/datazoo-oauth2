#pragma once

// S-0.14: OAuth2SecretTokenManager, generalised from erpl-web's
// MicrosoftEntraTokenManager (src/microsoft_entra_secret.{hpp,cpp}).
//
// The valuable, provider-agnostic part of MicrosoftEntraTokenManager is:
//   get token from secret -> check expiry -> (re)acquire if needed ->
//   write the new tokens back into the DuckDB secret.
// What was NOT provider-agnostic: the token endpoint URL and the exact
// shape of the token-acquisition/refresh POST request (Microsoft Entra's
// client_credentials and refresh_token bodies, Basic-auth-or-not, etc).
//
// Those are lifted out as an injected OAuth2RefreshRequestBuilder: given the
// current secret, it returns the token-endpoint URL and POST body to use to
// obtain a fresh token (whether that means "first acquisition via
// client_credentials" or "refresh via refresh_token" is entirely the
// builder's business -- it inspects the secret's own fields, e.g.
// grant_type, to decide). This covers both erpl-web's Entra use (Wave 6)
// and Google's authorization_code + refresh_token use (duckdb-gdrive).

#include "duckdb/main/secret/secret_manager.hpp"
#include <functional>
#include <string>

namespace erpl_web {

// A concrete request to (re)acquire a token, built by the caller from the
// secret's own fields.
struct OAuth2RefreshRequest {
    std::string token_url;
    std::string content_type = "application/x-www-form-urlencoded";
    std::string post_body;

    // If set, an `Authorization: Basic base64(client_id:client_secret)`
    // header is added (SAP Datasphere's pre-delivered-client shape; Entra
    // does not need this, Google's client-secret-in-body flow does not
    // either -- provider decides via the builder).
    bool use_basic_auth = false;
    std::string basic_auth_username;
    std::string basic_auth_password;
};

// Inspects the current secret and returns the request to run to obtain a
// fresh token. Called by OAuth2SecretTokenManager::GetToken exactly when a
// new token is required (no cached token, or the cached one is expired).
using OAuth2RefreshRequestBuilder = std::function<OAuth2RefreshRequest(const duckdb::KeyValueSecret &kv_secret)>;

// Result of executing a refresh/acquisition request.
struct OAuth2SecretTokenResponse {
    std::string access_token;
    std::string refresh_token; // optional, may be empty
    int expires_in = 0;        // seconds; 0 means "unknown / do not persist expiry"
};

class OAuth2SecretTokenManager {
public:
    // Returns a usable access token for the given secret, transparently
    // acquiring/refreshing (via build_refresh_request) and persisting the
    // result back into the named DuckDB secret when the cached token is
    // missing or expired (5-minute buffer, matching erpl-web's original
    // MicrosoftEntraTokenManager behaviour).
    static std::string GetToken(duckdb::ClientContext &context, const duckdb::KeyValueSecret *kv_secret,
                                const OAuth2RefreshRequestBuilder &build_refresh_request);

    // True if secret_map["access_token"] is present, non-empty, and
    // secret_map["expires_at"] (unix seconds) is more than 5 minutes away.
    static bool HasValidCachedToken(const duckdb::KeyValueSecret *kv_secret);

    // Throws InvalidInputException if no access_token is cached.
    static std::string GetCachedToken(const duckdb::KeyValueSecret *kv_secret);

    // Clones the current registered secret (to preserve persist_type /
    // storage_mode / other fields), overlays the new token fields, and
    // re-registers it with REPLACE_ON_CONFLICT. A no-op (with a trace
    // warning) if the secret has no name or cannot be found -- the caller
    // still gets the token back from GetToken, it just won't be cached.
    static void UpdateSecretWithTokens(duckdb::ClientContext &context, const duckdb::KeyValueSecret *kv_secret,
                                       const std::string &access_token, int expires_in,
                                       const std::string &refresh_token);

private:
    static OAuth2SecretTokenResponse ExecuteRefreshRequest(const OAuth2RefreshRequest &request);
};

// Keeps credential/token fields out of duckdb_secrets() output (REQ-NF-03).
// Extracted from erpl-web's CreateMicrosoftEntraSecretFunctions::RedactCommonKeys.
void RedactCommonKeys(duckdb::KeyValueSecret &result);

} // namespace erpl_web
