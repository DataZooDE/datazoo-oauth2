#pragma once

#include <string>
#include <chrono>
#include <map>

namespace erpl_web {

// OAuth2 grant types
enum class GrantType {
    authorization_code,
    client_credentials,
    refresh_token
};

// OAuth2 client types
enum class OAuth2ClientType {
    pre_delivered,
    custom
};

// OAuth2 configuration structure (supports SAP and Microsoft identity platforms)
struct OAuth2Config {
    std::string tenant_name;
    std::string data_center;
    std::string client_id;
    std::string client_secret;
    std::string scope;
    std::string redirect_uri;
    GrantType authorization_flow;
    bool custom_client;          // Whether this is a custom OAuth client

    // Custom URL overrides (for non-SAP identity providers like Microsoft Entra)
    std::string custom_auth_url;   // If set, overrides GetAuthorizationUrl()
    std::string custom_token_url;  // If set, overrides GetTokenUrl()

    // Additional provider-specific authorization-request parameters
    // (e.g. Google requires access_type=offline&prompt=consent to receive a
    // refresh token). Generic on purpose: no provider branches in the flow
    // code. Empty by default -- an empty map produces byte-identical
    // authorization URLs to the pre-extraction behaviour. Added during the
    // datazoo-oauth2 extraction (S-0.13); see docs/EXTRACTION_NOTES.md.
    std::map<std::string, std::string> extra_auth_params;

    // Constructor to properly initialize fields
    OAuth2Config() :
        tenant_name(""),
        data_center(""),
        client_id(""),
        client_secret(""),
        scope(""),
        redirect_uri(""),
        authorization_flow(GrantType::authorization_code),
        custom_client(false),
        custom_auth_url(""),
        custom_token_url("") {}

    // Get authorization URL
    std::string GetAuthorizationUrl() const;

    // Get token URL
    std::string GetTokenUrl() const;

    // Get default port based on client type
    int GetDefaultPort() const;

    // Get client type based on client ID
    OAuth2ClientType GetClientType() const;
};

// OAuth2 tokens structure (matching SAP CLI exactly)
struct OAuth2Tokens {
    std::string access_token;
    std::string refresh_token;
    std::string token_type;
    std::string scope;
    int expires_in;              // Seconds until token expires
    int expires_after;           // Unix timestamp when token expires

    // Constructor to properly initialize fields
    OAuth2Tokens() : expires_in(0), expires_after(0) {}

    // Check if token is expired
    bool IsExpired() const;

    // Check if token needs refresh
    bool NeedsRefresh() const;

    // Calculate expires_after based on expires_in
    void CalculateExpiresAfter();
};

// Utility functions for OAuth2 operations
namespace OAuth2Utils {
    // Generate PKCE code verifier
    std::string GenerateCodeVerifier();

    // Generate PKCE code challenge from verifier
    //
    // NOTE (see docs/EXTRACTION_NOTES.md): this implementation is copied
    // verbatim from erpl-web and is NOT RFC 7636 compliant -- it hashes with
    // std::hash rather than SHA-256. It is preserved byte-for-byte because
    // erpl-web's own test suite (test_datasphere_oauth2_consolidated.cpp,
    // which must pass UNCHANGED at Wave 6) asserts this exact behaviour
    // (a 64-character result). The REAL SHA-256/base64url PKCE challenge
    // used at runtime by the authorization-code flow lives in
    // OAuth2FlowV2's internal implementation and is exposed for reuse and
    // RFC-vector testing as GenerateCodeChallengeS256() below.
    std::string GenerateCodeChallenge(const std::string& code_verifier);

    // RFC 7636 compliant PKCE code challenge: SHA-256 over the verifier,
    // base64url-encoded without padding. This is a new, additive-only
    // function (not present in erpl-web) extracted from OAuth2FlowV2's
    // internal (previously private, still also used there unchanged)
    // algorithm so it can be tested against the RFC 7636 Appendix B.1
    // published test vector without a live OAuth2 flow.
    std::string GenerateCodeChallengeS256(const std::string& code_verifier);

    // Generate random state parameter
    std::string GenerateState();

    // Validate state parameter
    bool ValidateState(const std::string& received_state, const std::string& expected_state);
}

} // namespace erpl_web
