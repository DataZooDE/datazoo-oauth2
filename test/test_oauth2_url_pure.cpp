#include <catch2/catch_test_macros.hpp>
#include "datazoo/oauth2/oauth2_url_pure.hpp"

using namespace erpl_web;

// S-0.13: BuildAuthorizationUrl gains a generic extra_auth_params hook
// (Google needs access_type=offline&prompt=consent to get a refresh token).
// The empty-map case is the erpl-web behaviour-preservation assertion: byte
// identical output to the pre-extraction implementation.

TEST_CASE("BuildAuthorizationUrlPure: empty extra_auth_params is byte-identical to pre-extraction erpl-web output",
          "[oauth2_url][s0.13][behaviour-preservation]") {
    OAuth2Config config;
    config.custom_auth_url = "https://example.com/oauth/authorize";
    config.client_id = "my-client-id";
    config.redirect_uri = "http://localhost:65000/callback";
    config.scope = "openid profile";
    REQUIRE(config.extra_auth_params.empty());

    auto url = BuildAuthorizationUrlPure(config, "the-code-challenge", "the-state");

    REQUIRE(url ==
            "https://example.com/oauth/authorize"
            "?response_type=code"
            "&client_id=my-client-id"
            "&redirect_uri=http%3A%2F%2Flocalhost%3A65000%2Fcallback"
            "&state=the-state"
            "&code_challenge=the-code-challenge"
            "&code_challenge_method=S256"
            "&scope=openid+profile");
}

TEST_CASE("BuildAuthorizationUrlPure: without scope, no &scope= segment is emitted",
          "[oauth2_url][s0.13][behaviour-preservation]") {
    OAuth2Config config;
    config.custom_auth_url = "https://example.com/oauth/authorize";
    config.client_id = "my-client-id";
    config.redirect_uri = "http://localhost:65000/callback";

    auto url = BuildAuthorizationUrlPure(config, "chal", "state1");
    REQUIRE(url.find("&scope=") == std::string::npos);
    REQUIRE(url ==
            "https://example.com/oauth/authorize"
            "?response_type=code"
            "&client_id=my-client-id"
            "&redirect_uri=http%3A%2F%2Flocalhost%3A65000%2Fcallback"
            "&state=state1"
            "&code_challenge=chal"
            "&code_challenge_method=S256");
}

TEST_CASE("BuildAuthorizationUrlPure: populated extra_auth_params emits access_type=offline&prompt=consent",
          "[oauth2_url][s0.13]") {
    OAuth2Config config;
    config.custom_auth_url = "https://accounts.google.com/o/oauth2/v2/auth";
    config.client_id = "google-client-id";
    config.redirect_uri = "http://localhost:8080/callback";
    config.scope = "https://www.googleapis.com/auth/drive.readonly";
    config.extra_auth_params["access_type"] = "offline";
    config.extra_auth_params["prompt"] = "consent";

    auto url = BuildAuthorizationUrlPure(config, "chal", "state1");

    // std::map iterates in ascending key order, so access_type precedes prompt.
    REQUIRE(url.find("&access_type=offline") != std::string::npos);
    REQUIRE(url.find("&prompt=consent") != std::string::npos);
    REQUIRE(url.find("access_type=offline&prompt=consent") != std::string::npos);
}

TEST_CASE("BuildAuthorizationUrlPure: extra_auth_params values are URL-encoded", "[oauth2_url][s0.13]") {
    OAuth2Config config;
    config.custom_auth_url = "https://example.com/authorize";
    config.client_id = "cid";
    config.redirect_uri = "http://localhost/cb";
    config.extra_auth_params["login_hint"] = "user@example.com";

    auto url = BuildAuthorizationUrlPure(config, "chal", "state1");
    REQUIRE(url.find("login_hint=user%40example.com") != std::string::npos);
}

TEST_CASE("UrlEncode: RFC 3986 unreserved characters pass through, others are percent-encoded", "[oauth2_url]") {
    REQUIRE(UrlEncode("abcXYZ019-._~") == "abcXYZ019-._~");
    REQUIRE(UrlEncode("a b") == "a+b");
    REQUIRE(UrlEncode("a/b") == "a%2Fb");
    REQUIRE(UrlEncode("") == "");
}
