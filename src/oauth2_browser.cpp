#include "datazoo/oauth2/oauth2_browser.hpp"
#include <thread>
#include <chrono>
#include <cstdlib>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace erpl_web {

void OAuth2Browser::OpenUrl(const std::string& url) {
#ifdef _WIN32
    OpenUrlWindows(url);
#elif defined(__APPLE__)
    OpenUrlMacOS(url);
#else
    OpenUrlLinux(url);
#endif
}

int OAuth2Browser::FindAvailablePort(int start_port) {
    for (int port = start_port; port < start_port + 100; ++port) {
        if (IsPortAvailable(port)) {
            return port;
        }
    }
    throw std::runtime_error("No available ports found in range " + std::to_string(start_port) + "-" + std::to_string(start_port + 99));
}

bool OAuth2Browser::IsPortAvailable(int port) {
#ifdef _WIN32
    return IsPortAvailableWindows(port);
#elif defined(__APPLE__)
    return IsPortAvailableMacOS(port);
#else
    return IsPortAvailableLinux(port);
#endif
}

std::string OAuth2Browser::GetDefaultBrowser() {
#ifdef _WIN32
    return "default"; // Windows will use default browser
#elif defined(__APPLE__)
    return "open"; // macOS open command
#else
    return "xdg-open"; // Linux xdg-open command
#endif
}

void OAuth2Browser::OpenUrlWindows(const std::string& url) {
#ifdef _WIN32
    HINSTANCE result = ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
    if (result <= (HINSTANCE)32) {
        throw std::runtime_error("Failed to open browser on Windows");
    }
#else
    // Not Windows - throw error or use fallback
    throw std::runtime_error("Windows-specific browser opening not available on this platform");
#endif
}

void OAuth2Browser::OpenUrlMacOS(const std::string& url) {
#ifdef __APPLE__
    CFStringRef urlString = CFStringCreateWithCString(NULL, url.c_str(), kCFStringEncodingUTF8);
    CFURLRef urlRef = CFURLCreateWithString(NULL, urlString, NULL);

    if (urlRef) {
        LSOpenCFURLRef(urlRef, NULL);
        CFRelease(urlRef);
    }

    CFRelease(urlString);
#else
    // Not macOS - throw error or use fallback
    throw std::runtime_error("macOS-specific browser opening not available on this platform");
#endif
}

bool OAuth2Browser::CanOpenBrowser() {
#if defined(_WIN32) || defined(__APPLE__)
    // Both platforms have a documented system opener that works without a display server
    // being separately advertised.
    return true;
#else
    // Linux: a graphical session has to be reachable, and the opener has to exist.
    const char *display = std::getenv("DISPLAY");
    const char *wayland = std::getenv("WAYLAND_DISPLAY");
    const bool has_session = (display != nullptr && *display != '\0') ||
                             (wayland != nullptr && *wayland != '\0');
    if (!has_session) {
        return false;
    }

    // xdg-open on PATH. Checked rather than assumed: a minimal container has a DISPLAY
    // forwarded and no xdg-utils installed.
    const char *path_env = std::getenv("PATH");
    if (path_env == nullptr) {
        return false;
    }
    std::string path(path_env);
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto end = path.find(':', start);
        const auto dir = path.substr(start, (end == std::string::npos) ? std::string::npos : end - start);
        if (!dir.empty() && ::access((dir + "/xdg-open").c_str(), X_OK) == 0) {
            return true;
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return false;
#endif
}

void OAuth2Browser::OpenUrlLinux(const std::string& url) {
#ifndef _WIN32
#ifndef __APPLE__
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execlp("xdg-open", "xdg-open", url.c_str(), NULL);
        _exit(127); // If execlp fails - _exit, not exit: no duplicate atexit handlers
    }
    if (pid < 0) {
        throw std::runtime_error("Failed to fork process for opening browser");
    }

    // The child's outcome is actually observed now. It used to be waitpid'd with WNOHANG
    // and the status discarded, so xdg-open exiting non-zero - which is what happens on a
    // headless session - looked exactly like success.
    //
    // Polled rather than blocked outright: xdg-open normally returns as soon as it has
    // handed the URL off, but an implementation that stays alive for the browser's lifetime
    // must not hang this call. Still running after the grace period means it launched
    // something, which is the answer we want.
    constexpr int POLL_INTERVAL_MS = 50;
    constexpr int GRACE_PERIOD_MS = 2000;
    for (int waited = 0; waited < GRACE_PERIOD_MS; waited += POLL_INTERVAL_MS) {
        int status = 0;
        const pid_t finished = waitpid(pid, &status, WNOHANG);
        if (finished == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                return;  // opened
            }
            throw std::runtime_error(
                "xdg-open could not open the URL (exit status " +
                std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) +
                "). There is usually no browser reachable from this session.");
        }
        if (finished < 0) {
            return;  // cannot tell; do not claim failure
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
    }
#else
    throw std::runtime_error("Linux-specific browser opening not available on this platform");
#endif
#else
    throw std::runtime_error("Linux-specific browser opening not available on this platform");
#endif
}

bool OAuth2Browser::IsPortAvailableWindows(int port) {
    // Windows implementation would use WinSock to check port availability
    // For now, return true to avoid blocking
    return true;
}

bool OAuth2Browser::IsPortAvailableMacOS(int port) {
    // macOS implementation would use socket to check port availability
    // For now, return true to avoid blocking
    return true;
}

bool OAuth2Browser::IsPortAvailableLinux(int port) {
    // Linux implementation would use socket to check port availability
    // For now, return true to avoid blocking
    return true;
}

} // namespace erpl_web
