#include "datazoo/oauth2/oauth2_url_pure.hpp"
#include <vector>
#include <stdexcept>
#include <openssl/rand.h>
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


std::string GenerateSecureRandomToken(std::size_t num_bytes) {
    std::vector<unsigned char> buffer(num_bytes);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error(
            "Could not obtain cryptographically secure random bytes for an OAuth2 security "
            "token (RAND_bytes failed). Refusing to continue with a predictable value.");
    }

    static const char *const ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string encoded;
    encoded.reserve(((num_bytes + 2) / 3) * 4);
    for (std::size_t i = 0; i < buffer.size(); i += 3) {
        const unsigned int byte0 = buffer[i];
        const unsigned int byte1 = (i + 1 < buffer.size()) ? buffer[i + 1] : 0u;
        const unsigned int byte2 = (i + 2 < buffer.size()) ? buffer[i + 2] : 0u;
        const unsigned int triple = (byte0 << 16) | (byte1 << 8) | byte2;

        encoded += ALPHABET[(triple >> 18) & 0x3F];
        encoded += ALPHABET[(triple >> 12) & 0x3F];
        if (i + 1 < buffer.size()) {
            encoded += ALPHABET[(triple >> 6) & 0x3F];
        }
        if (i + 2 < buffer.size()) {
            encoded += ALPHABET[triple & 0x3F];
        }
    }
    return encoded;
}

std::string EscapeHtmlText(const std::string &text) {
    std::string escaped;
    escaped.reserve(text.size());
    for (const char c : text) {
        switch (c) {
        case '&':  escaped += "&amp;";  break;
        case '<':  escaped += "&lt;";   break;
        case '>':  escaped += "&gt;";   break;
        case '"':  escaped += "&quot;"; break;
        case '\'': escaped += "&#39;";  break;
        default:   escaped += c;        break;
        }
    }
    return escaped;
}

} // namespace erpl_web
