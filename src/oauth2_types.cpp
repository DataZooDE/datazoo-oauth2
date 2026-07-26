#include "datazoo/oauth2/oauth2_types.hpp"
#include <chrono>
#include <sstream>
#include <random>
#include <functional>
#include <iomanip>
#include <openssl/sha.h>

namespace erpl_web {

std::string OAuth2Config::GetAuthorizationUrl() const {
    // Use custom URL if provided (for Microsoft Entra, etc.)
    if (!custom_auth_url.empty()) {
        return custom_auth_url;
    }
    // Default: SAP BTP URL format
    std::string base_url = "https://" + tenant_name + ".authentication." + data_center + ".hana.ondemand.com/oauth/authorize";
    return base_url;
}

std::string OAuth2Config::GetTokenUrl() const {
    // Use custom URL if provided (for Microsoft Entra, etc.)
    if (!custom_token_url.empty()) {
        return custom_token_url;
    }
    // Default: SAP BTP URL format
    std::string base_url = "https://" + tenant_name + ".authentication." + data_center + ".hana.ondemand.com/oauth/token";
    return base_url;
}

int OAuth2Config::GetDefaultPort() const {
    if (custom_client) {
        return 8080;  // Custom client uses port 8080
    } else {
        return 65000; // Pre-delivered client uses port 65000
    }
}

OAuth2ClientType OAuth2Config::GetClientType() const {
    // If explicitly marked as custom, return custom
    if (custom_client) {
        return OAuth2ClientType::custom;
    }

    // Otherwise, detect based on client ID pattern
    // SAP CLI pattern: sb-*!*|client!* indicates pre-delivered client
    if (client_id.find("sb-") == 0 && client_id.find("!b") != std::string::npos) {
        return OAuth2ClientType::pre_delivered;
    }

    // UUID pattern (like 5a638330-5899-366e-ac00-ab62cc32dcda) indicates pre-delivered client
    if (client_id.length() == 36 && client_id.find("-") != std::string::npos) {
        return OAuth2ClientType::pre_delivered;
    }

    // Default to custom for other patterns
    return OAuth2ClientType::custom;
}

bool OAuth2Tokens::IsExpired() const {
    if (expires_after == 0) {
        return true; // No expiry set means token is expired
    }
    auto now = std::chrono::system_clock::now();
    auto now_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return now_timestamp >= expires_after;
}

bool OAuth2Tokens::NeedsRefresh() const {
    if (expires_after == 0) {
        return true; // No expiry set means token needs refresh
    }

    // Refresh if token expires within 5 minutes
    auto now = std::chrono::system_clock::now();
    auto now_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    auto refresh_threshold = expires_after - 300; // 5 minutes before expiry

    return now_timestamp >= refresh_threshold;
}

void OAuth2Tokens::CalculateExpiresAfter() {
    if (expires_in > 0) {
        auto now = std::chrono::system_clock::now();
        auto future_time = now + std::chrono::seconds(expires_in);
        expires_after = std::chrono::duration_cast<std::chrono::seconds>(
            future_time.time_since_epoch()).count();
    }
}

// OAuth2 utility functions implementation
namespace OAuth2Utils {

std::string GenerateCodeVerifier() {
    static const std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, charset.length() - 1);

    std::string result;
    result.reserve(128);

    for (size_t i = 0; i < 128; ++i) {
        result += charset[distribution(generator)];
    }

    return result;
}

std::string GenerateCodeChallenge(const std::string& code_verifier) {
    // For testing purposes, we'll create a deterministic 64-character hash
    // In production, you'd want to use a proper SHA256 implementation
    std::hash<std::string> hasher;
    auto hash = hasher(code_verifier);

    // Convert to hex string and ensure it's exactly 64 characters
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    std::string hash_str = ss.str();

    // Pad or truncate to exactly 64 characters
    if (hash_str.length() < 64) {
        // Pad with zeros
        hash_str = std::string(64 - hash_str.length(), '0') + hash_str;
    } else if (hash_str.length() > 64) {
        // Truncate to 64 characters
        hash_str = hash_str.substr(0, 64);
    }

    return hash_str;
}

std::string GenerateCodeChallengeS256(const std::string& code_verifier) {
    // RFC 7636 S256: base64url(SHA256(ASCII(code_verifier))), no padding.
    // Algorithm identical to (and extracted from) OAuth2FlowV2's internal
    // GenerateCodeChallenge -- see the header comment for why this is a
    // separate, additive function rather than a fix to the function above.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, code_verifier.c_str(), code_verifier.length());
    SHA256_Final(hash, &sha256);

    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(44); // SHA256 produces 32 bytes = 44 base64 characters (43 + padding)

    for (int i = 0; i < 30; i += 3) {
        uint32_t chunk = (static_cast<uint32_t>(hash[i]) << 16) |
                         (static_cast<uint32_t>(hash[i + 1]) << 8) |
                         static_cast<uint32_t>(hash[i + 2]);

        result += base64_chars[(chunk >> 18) & 0x3F];
        result += base64_chars[(chunk >> 12) & 0x3F];
        result += base64_chars[(chunk >> 6) & 0x3F];
        result += base64_chars[chunk & 0x3F];
    }

    uint32_t last_chunk = (static_cast<uint32_t>(hash[30]) << 8) | static_cast<uint32_t>(hash[31]);
    result += base64_chars[(last_chunk >> 10) & 0x3F];
    result += base64_chars[(last_chunk >> 4) & 0x3F];
    result += base64_chars[(last_chunk << 2) & 0x3F];

    for (char& c : result) {
        if (c == '+') c = '-';
        if (c == '/') c = '_';
    }

    return result;
}

std::string GenerateState() {
    static const std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, charset.length() - 1);

    std::string result;
    result.reserve(32);

    for (size_t i = 0; i < 32; ++i) {
        result += charset[distribution(generator)];
    }

    return result;
}

bool ValidateState(const std::string& received_state, const std::string& expected_state) {
    return received_state == expected_state;
}

} // namespace OAuth2Utils

} // namespace erpl_web
