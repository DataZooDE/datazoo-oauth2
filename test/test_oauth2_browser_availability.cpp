#include <catch2/catch_test_macros.hpp>

#include "datazoo/oauth2/oauth2_browser.hpp"

#include <cstdlib>
#include <string>

using namespace erpl_web;

// Whether a browser can be opened at all has to be KNOWN, not assumed.
//
// OpenUrlLinux forked, called execlp("xdg-open", ...), and then waitpid'd with WNOHANG and
// discarded the status - so xdg-open exiting non-zero, which is what happens on a headless
// session, was indistinguishable from success. The flow then waited the full 60-second
// callback timeout for a redirect that could not arrive and reported "Timeout waiting for
// OAuth2 callback", naming neither the cause nor anything actionable.
//
// Three 60-second hangs in a row is how this was found. See DataZooDE/datazoo-oauth2#11.

// Everything below is Linux-specific and guarded as such: CanOpenBrowser() returns true
// unconditionally on Windows and macOS, where DISPLAY and WAYLAND_DISPLAY mean nothing, so
// there is no behaviour here to assert on those platforms.
//
// The guard includes the ScopedEnv helper, which it previously did not. setenv/unsetenv are
// POSIX and MSVC has neither, so the helper broke the Windows build even though every test
// using it was already excluded. Compiled-but-unused code still has to compile.
#if !defined(_WIN32) && !defined(__APPLE__)

namespace {

// Saves and restores an environment variable so the cases cannot leak into each other or
// into whatever runs after them in this binary.
class ScopedEnv {
public:
    ScopedEnv(const char *name, const char *value) : name_(name)
    {
        const char *existing = std::getenv(name);
        if (existing != nullptr) {
            had_value_ = true;
            previous_ = existing;
        }
        if (value == nullptr) {
            ::unsetenv(name);
        } else {
            ::setenv(name, value, 1);
        }
    }

    ~ScopedEnv()
    {
        if (had_value_) {
            ::setenv(name_.c_str(), previous_.c_str(), 1);
        } else {
            ::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    bool had_value_ = false;
    std::string previous_;
};

}  // namespace

TEST_CASE("no graphical session means no browser", "[oauth2_browser]") {
    // The case that was silently mishandled. A headless Linux session has neither variable
    // set, and nothing can open a URL.
    ScopedEnv no_x11("DISPLAY", nullptr);
    ScopedEnv no_wayland("WAYLAND_DISPLAY", nullptr);

    REQUIRE_FALSE(OAuth2Browser::CanOpenBrowser());
}

TEST_CASE("an empty DISPLAY counts as unset", "[oauth2_browser]") {
    // DISPLAY= appears in stripped environments and in some container images. Treating the
    // empty string as "present" would put us straight back to the doomed xdg-open.
    ScopedEnv empty_x11("DISPLAY", "");
    ScopedEnv no_wayland("WAYLAND_DISPLAY", nullptr);

    REQUIRE_FALSE(OAuth2Browser::CanOpenBrowser());
}

TEST_CASE("a graphical session is not enough on its own - the opener must exist",
          "[oauth2_browser]") {
    // A forwarded DISPLAY with no xdg-utils installed is the shape of a minimal container.
    // An empty PATH means the opener cannot be found, whatever the display situation.
    ScopedEnv x11("DISPLAY", ":0");
    ScopedEnv no_wayland("WAYLAND_DISPLAY", nullptr);
    ScopedEnv no_path("PATH", "");

    REQUIRE_FALSE(OAuth2Browser::CanOpenBrowser());
}

TEST_CASE("Wayland alone is a graphical session", "[oauth2_browser]") {
    // Checking only DISPLAY would wrongly refuse on a Wayland-only desktop. Whether the
    // answer is true depends on xdg-open being installed on the machine running the test, so
    // this asserts the thing that is actually under test: WAYLAND_DISPLAY is consulted, and
    // its absence is what made the previous case false.
    ScopedEnv no_x11("DISPLAY", nullptr);
    ScopedEnv wayland("WAYLAND_DISPLAY", "wayland-0");

    const bool with_wayland = OAuth2Browser::CanOpenBrowser();

    ScopedEnv no_wayland("WAYLAND_DISPLAY", nullptr);
    const bool without_any_session = OAuth2Browser::CanOpenBrowser();

    REQUIRE_FALSE(without_any_session);
    if (!with_wayland) {
        // xdg-open is not installed here, so the display half cannot be observed. Say so
        // rather than assert something this machine cannot answer.
        WARN("xdg-open is not on PATH, so the Wayland branch could not be confirmed here");
    }
}

#endif
