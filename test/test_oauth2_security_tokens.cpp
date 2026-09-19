#include <catch2/catch_test_macros.hpp>

#include "datazoo/oauth2/oauth2_url_pure.hpp"

#include <set>
#include <string>

using namespace erpl_web;

// The PKCE code_verifier and the CSRF state are the two values whose unpredictability the
// authorization_code flow depends on. Both were drawn from std::mt19937 seeded with a single
// 32-bit std::random_device value: not a CSPRNG, so one observed output reveals the
// generator state and therefore the next value, and a <=2^32 seed space is brute-forceable
// regardless.
//
// That matters more here than it might elsewhere - this is a loopback redirect flow whose
// authorization URL is passed to the browser as a command-line argument, readable from /proc
// by any local user. A predictable verifier turns an intercepted code into a usable one.
//
// See DataZooDE/erpl-web#248.

TEST_CASE("a security token has the requested length over the base64url alphabet",
          "[oauth2_security][pkce]") {
    // 48 bytes -> 64 characters, which is what the PKCE verifier uses (RFC 7636 allows
    // 43-128 over the unreserved set).
    const auto verifier = GenerateSecureRandomToken(48);
    REQUIRE(verifier.size() == 64);

    // 24 bytes -> 32 characters, the state.
    const auto state = GenerateSecureRandomToken(24);
    REQUIRE(state.size() == 32);

    const std::string allowed =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (const char c : verifier + state) {
        INFO("unexpected character: " << c);
        REQUIRE(allowed.find(c) != std::string::npos);
    }

    // No padding: '=' is not in the RFC 7636 unreserved set and would have to be encoded
    // when the verifier is sent.
    REQUIRE(verifier.find('=') == std::string::npos);
}

TEST_CASE("security tokens do not repeat", "[oauth2_security][pkce]") {
    // A weak generator shows up here as collisions or as a short cycle. This will not detect
    // mt19937's predictability on its own - that is not testable from outputs alone, which is
    // exactly why the SOURCE matters and why this file exists alongside the change rather
    // than in place of it.
    std::set<std::string> seen;
    const int draws = 500;
    for (int i = 0; i < draws; ++i) {
        seen.insert(GenerateSecureRandomToken(24));
    }
    REQUIRE(seen.size() == static_cast<size_t>(draws));
}

TEST_CASE("a zero-length request yields an empty token rather than misbehaving",
          "[oauth2_security][pkce]") {
    REQUIRE(GenerateSecureRandomToken(0).empty());
}

// ---------------------------------------------------------------------------

// The loopback callback server serves an error page on the origin that RECEIVES
// AUTHORIZATION CODES, and it interpolated the `error` and `error_description` query
// parameters into that page's markup raw. While the flow's wait loop runs, any page the
// user's browser visits can navigate to
// http://localhost:<port>/?error=<img src=x onerror=...> and execute script in that origin.

TEST_CASE("HTML escaping neutralises the characters that start markup",
          "[oauth2_security][xss]") {
    REQUIRE(EscapeHtmlText("<img src=x onerror=alert(1)>") ==
            "&lt;img src=x onerror=alert(1)&gt;");
    REQUIRE(EscapeHtmlText("</p><script>steal()</script>") ==
            "&lt;/p&gt;&lt;script&gt;steal()&lt;/script&gt;");
}

TEST_CASE("escaping covers attribute delimiters and the ampersand itself",
          "[oauth2_security][xss]") {
    // Quotes matter because the page interpolates into attribute-bearing markup, and an
    // unescaped quote escapes the attribute rather than the element.
    REQUIRE(EscapeHtmlText("\"") == "&quot;");
    REQUIRE(EscapeHtmlText("'") == "&#39;");

    // The ampersand has to be escaped FIRST in any correct implementation, or the entities
    // produced for the other characters get mangled. Asserted directly so a reordering that
    // double-escapes is caught.
    REQUIRE(EscapeHtmlText("&") == "&amp;");
    REQUIRE(EscapeHtmlText("&lt;") == "&amp;lt;");
    REQUIRE(EscapeHtmlText("a&<b") == "a&amp;&lt;b");
}

TEST_CASE("ordinary text passes through unchanged", "[oauth2_security][xss]") {
    // An error page that mangles legitimate messages is its own bug.
    REQUIRE(EscapeHtmlText("access_denied") == "access_denied");
    REQUIRE(EscapeHtmlText("The user cancelled the request.") ==
            "The user cancelled the request.");
    REQUIRE(EscapeHtmlText("").empty());
}
