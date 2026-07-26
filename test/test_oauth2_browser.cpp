#include <catch2/catch_test_macros.hpp>
#include "datazoo/oauth2/oauth2_browser.hpp"

using namespace erpl_web;

// S-0.11: free-port selection logic, pure (no sockets opened, no browser
// actually launched).

TEST_CASE("OAuth2Browser::FindAvailablePort returns a port in range", "[oauth2_browser]") {
    int port = OAuth2Browser::FindAvailablePort(65000);
    REQUIRE(port >= 65000);
    REQUIRE(port < 65100);
}

TEST_CASE("OAuth2Browser::GetDefaultBrowser returns a non-empty platform command", "[oauth2_browser]") {
    REQUIRE(!OAuth2Browser::GetDefaultBrowser().empty());
}

TEST_CASE("OAuth2Browser::IsPortAvailable: KNOWN LIMITATION -- always reports available",
          "[oauth2_browser][regression]") {
    // Moved verbatim from erpl-web. IsPortAvailableWindows/MacOS/Linux are
    // all stubs that unconditionally return true; no platform actually
    // probes the socket. This means FindAvailablePort always returns
    // start_port immediately and never detects a real collision. Preserved
    // byte-for-byte (behaviour-preserving extraction) and pinned here so a
    // future consumer (duckdb-gdrive's loopback OAuth2Server) does not
    // assume port selection is real without first fixing this. See
    // docs/EXTRACTION_NOTES.md.
    REQUIRE(OAuth2Browser::IsPortAvailable(65000) == true);
    REQUIRE(OAuth2Browser::IsPortAvailable(1) == true); // even a privileged/invalid port "looks" free
}
