#include <catch2/catch_test_macros.hpp>
#include "datazoo/oauth2/oauth2_types.hpp"
#include <chrono>

using namespace erpl_web;

// ---------------------------------------------------------------------------
// S-0.10: OAuth2Config / OAuth2Tokens / OAuth2Utils, moved unchanged from
// erpl-web's oauth2_types.{hpp,cpp}.
// ---------------------------------------------------------------------------

TEST_CASE("OAuth2Config: default-constructed values", "[oauth2_types][config]") {
    OAuth2Config config;
    REQUIRE(config.tenant_name.empty());
    REQUIRE(config.data_center.empty());
    REQUIRE(config.custom_client == false);
    REQUIRE(config.authorization_flow == GrantType::authorization_code);
    REQUIRE(config.extra_auth_params.empty());
}

TEST_CASE("OAuth2Config: GetAuthorizationUrl prefers custom_auth_url", "[oauth2_types][config]") {
    OAuth2Config config;
    config.tenant_name = "acme";
    config.data_center = "eu10";
    REQUIRE(config.GetAuthorizationUrl() == "https://acme.authentication.eu10.hana.ondemand.com/oauth/authorize");

    config.custom_auth_url = "https://example.com/authorize";
    REQUIRE(config.GetAuthorizationUrl() == "https://example.com/authorize");
}

TEST_CASE("OAuth2Config: GetTokenUrl prefers custom_token_url", "[oauth2_types][config]") {
    OAuth2Config config;
    config.tenant_name = "acme";
    config.data_center = "eu10";
    REQUIRE(config.GetTokenUrl() == "https://acme.authentication.eu10.hana.ondemand.com/oauth/token");

    config.custom_token_url = "https://example.com/token";
    REQUIRE(config.GetTokenUrl() == "https://example.com/token");
}

TEST_CASE("OAuth2Config: GetDefaultPort depends on custom_client", "[oauth2_types][config]") {
    OAuth2Config config;
    REQUIRE(config.GetDefaultPort() == 65000);
    config.custom_client = true;
    REQUIRE(config.GetDefaultPort() == 8080);
}

TEST_CASE("OAuth2Config: GetClientType detects pre-delivered SAP CLI pattern", "[oauth2_types][config]") {
    OAuth2Config config;
    config.client_id = "sb-abc123!b1234";
    REQUIRE(config.GetClientType() == OAuth2ClientType::pre_delivered);
}

TEST_CASE("OAuth2Config: GetClientType detects pre-delivered UUID pattern", "[oauth2_types][config]") {
    OAuth2Config config;
    config.client_id = "5a638330-5899-366e-ac00-ab62cc32dcda";
    REQUIRE(config.GetClientType() == OAuth2ClientType::pre_delivered);
}

TEST_CASE("OAuth2Config: GetClientType defaults to custom", "[oauth2_types][config]") {
    OAuth2Config config;
    config.client_id = "my-app-client-id";
    REQUIRE(config.GetClientType() == OAuth2ClientType::custom);
}

TEST_CASE("OAuth2Config: GetClientType returns custom when explicitly marked", "[oauth2_types][config]") {
    OAuth2Config config;
    config.client_id = "5a638330-5899-366e-ac00-ab62cc32dcda"; // otherwise pre_delivered
    config.custom_client = true;
    REQUIRE(config.GetClientType() == OAuth2ClientType::custom);
}

// ---------------------------------------------------------------------------
// OAuth2Tokens boundary cases
// ---------------------------------------------------------------------------

TEST_CASE("OAuth2Tokens: default-constructed token is expired and needs refresh", "[oauth2_types][tokens]") {
    OAuth2Tokens tokens;
    REQUIRE(tokens.expires_after == 0);
    REQUIRE(tokens.IsExpired() == true);
    REQUIRE(tokens.NeedsRefresh() == true);
}

TEST_CASE("OAuth2Tokens: IsExpired boundary at expires_after", "[oauth2_types][tokens]") {
    OAuth2Tokens tokens;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Comfortably in the future: not expired, does not need refresh.
    tokens.expires_after = static_cast<int>(now + 3600);
    REQUIRE(tokens.IsExpired() == false);
    REQUIRE(tokens.NeedsRefresh() == false);

    // Exactly now (boundary: IsExpired uses >=) -> expired.
    tokens.expires_after = static_cast<int>(now);
    REQUIRE(tokens.IsExpired() == true);

    // In the past -> expired.
    tokens.expires_after = static_cast<int>(now - 10);
    REQUIRE(tokens.IsExpired() == true);
}

TEST_CASE("OAuth2Tokens: NeedsRefresh fires 5 minutes before expiry (boundary)", "[oauth2_types][tokens]") {
    OAuth2Tokens tokens;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Just outside the 5-minute (300s) refresh window: still fresh.
    tokens.expires_after = static_cast<int>(now + 301);
    REQUIRE(tokens.NeedsRefresh() == false);
    REQUIRE(tokens.IsExpired() == false);

    // Exactly at the 300s boundary -> needs refresh (>= threshold).
    tokens.expires_after = static_cast<int>(now + 300);
    REQUIRE(tokens.NeedsRefresh() == true);
    REQUIRE(tokens.IsExpired() == false); // not yet actually expired

    // Well inside the window -> needs refresh.
    tokens.expires_after = static_cast<int>(now + 60);
    REQUIRE(tokens.NeedsRefresh() == true);
}

TEST_CASE("OAuth2Tokens: CalculateExpiresAfter derives expires_after from expires_in", "[oauth2_types][tokens]") {
    OAuth2Tokens tokens;
    tokens.expires_in = 3600;
    auto before = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    tokens.CalculateExpiresAfter();
    auto after = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    REQUIRE(tokens.expires_after >= before + 3600);
    REQUIRE(tokens.expires_after <= after + 3600);
}

TEST_CASE("OAuth2Tokens: CalculateExpiresAfter is a no-op when expires_in <= 0", "[oauth2_types][tokens]") {
    OAuth2Tokens tokens;
    tokens.expires_in = 0;
    tokens.expires_after = 42;
    tokens.CalculateExpiresAfter();
    REQUIRE(tokens.expires_after == 42); // untouched

    OAuth2Tokens tokens_neg;
    tokens_neg.expires_in = -5;
    tokens_neg.expires_after = 7;
    tokens_neg.CalculateExpiresAfter();
    REQUIRE(tokens_neg.expires_after == 7); // untouched
}

// ---------------------------------------------------------------------------
// OAuth2Utils: PKCE and state
// ---------------------------------------------------------------------------

TEST_CASE("OAuth2Utils::GenerateCodeVerifier meets RFC 7636 length bounds", "[oauth2_types][pkce]") {
    auto verifier = OAuth2Utils::GenerateCodeVerifier();
    REQUIRE(verifier.length() >= 43);
    REQUIRE(verifier.length() <= 128);
}

TEST_CASE("OAuth2Utils::GenerateState produces distinct 32-char values", "[oauth2_types][state]") {
    auto s1 = OAuth2Utils::GenerateState();
    auto s2 = OAuth2Utils::GenerateState();
    REQUIRE(s1.length() == 32);
    REQUIRE(s1 != s2);
}

TEST_CASE("OAuth2Utils::ValidateState is exact string equality", "[oauth2_types][state]") {
    REQUIRE(OAuth2Utils::ValidateState("abc", "abc") == true);
    REQUIRE(OAuth2Utils::ValidateState("abc", "abd") == false);
    REQUIRE(OAuth2Utils::ValidateState("", "") == true);
    REQUIRE(OAuth2Utils::ValidateState("", "abc") == false);
}

TEST_CASE("OAuth2Utils::GenerateCodeChallenge (erpl-web legacy behaviour) is preserved byte-for-byte",
          "[oauth2_types][pkce][regression]") {
    // NOT RFC 7636 compliant -- see the header comment and
    // docs/EXTRACTION_NOTES.md. This test pins the exact (non-standard)
    // behaviour erpl-web's test_datasphere_oauth2_consolidated.cpp already
    // depends on (a deterministic 64-character result), so nobody "fixes"
    // this function during the Wave 6 migration and silently breaks that
    // gate test.
    auto challenge = OAuth2Utils::GenerateCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    REQUIRE(challenge.length() == 64);
    // Deterministic: same verifier always produces the same challenge.
    auto challenge2 = OAuth2Utils::GenerateCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    REQUIRE(challenge == challenge2);
    // And it is NOT the RFC 7636 answer -- documenting the defect, not just
    // asserting a property.
    REQUIRE(challenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
}

TEST_CASE("OAuth2Utils::GenerateCodeChallengeS256 matches the RFC 7636 Appendix B.1 published test vector",
          "[oauth2_types][pkce][s0.12]") {
    // https://www.rfc-editor.org/rfc/rfc7636#appendix-B
    const std::string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const std::string expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    auto challenge = OAuth2Utils::GenerateCodeChallengeS256(verifier);
    REQUIRE(challenge == expected_challenge);
}
