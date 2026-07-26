#include "datazoo/oauth2/oauth2_url_pure.hpp"
#include <sstream>
#include <iomanip>

namespace erpl_web {

std::string UrlEncode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (unsigned char c : value) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else if (c == ' ') {
            escaped << '+';
        } else {
            escaped << '%' << std::uppercase << std::setw(2) << int(c) << std::nouppercase;
        }
    }
    return escaped.str();
}

std::string BuildAuthorizationUrlPure(const OAuth2Config &config, const std::string &code_challenge,
                                       const std::string &state) {
    std::ostringstream auth_url;
    auth_url << config.GetAuthorizationUrl()
             << "?response_type=code"
             << "&client_id=" << UrlEncode(config.client_id)
             << "&redirect_uri=" << UrlEncode(config.redirect_uri)
             << "&state=" << UrlEncode(state)
             << "&code_challenge=" << UrlEncode(code_challenge)
             << "&code_challenge_method=S256";

    // Add scope if provided (required by Microsoft Entra ID)
    if (!config.scope.empty()) {
        auth_url << "&scope=" << UrlEncode(config.scope);
    }

    // Additional provider-specific parameters (S-0.13). config.extra_auth_params
    // is a std::map, so iteration order is deterministic (ascending key).
    // Empty by default -- when empty this loop appends nothing, so output is
    // byte-identical to the pre-extraction erpl-web behaviour.
    for (const auto &param : config.extra_auth_params) {
        auth_url << "&" << UrlEncode(param.first) << "=" << UrlEncode(param.second);
    }

    return auth_url.str();
}

} // namespace erpl_web
