#pragma once
#include <string>

namespace erpl_web {

// Browser helper for opening URLs (cross-platform)
class OAuth2Browser {
public:
    // Open URL in default browser. Throws when the browser could not be launched.
    static void OpenUrl(const std::string& url);

    // Whether a browser could plausibly be opened at all.
    //
    // On a headless Linux session there is nothing to open: xdg-open reports
    // "no method available" and exits non-zero. That used to go unnoticed - OpenUrlLinux
    // forked, called execlp, and then waitpid'd with WNOHANG, so the child's failure was
    // never observed - and the flow went on to wait the full callback timeout for a
    // redirect that could not arrive, finally reporting "Timeout waiting for OAuth2
    // callback". Which named neither the real cause nor anything the user could act on.
    //
    // Checked BEFORE attempting, so the doomed xdg-open is not run and its stderr does not
    // land in the user's output either. See DataZooDE/datazoo-oauth2#11.
    static bool CanOpenBrowser();

    // Find available port for local server
    static int FindAvailablePort(int start_port = 65000);

    // Check if a port is available
    static bool IsPortAvailable(int port);

    // Platform-specific browser detection
    static std::string GetDefaultBrowser();

private:
    // Platform-specific browser opening
    static void OpenUrlWindows(const std::string& url);
    static void OpenUrlMacOS(const std::string& url);
    static void OpenUrlLinux(const std::string& url);

    // Platform-specific port checking
    static bool IsPortAvailableWindows(int port);
    static bool IsPortAvailableMacOS(int port);
    static bool IsPortAvailableLinux(int port);
};

} // namespace erpl_web
