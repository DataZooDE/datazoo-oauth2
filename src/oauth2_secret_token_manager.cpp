#include "datazoo/oauth2/oauth2_secret_token_manager.hpp"
#include "datazoo/oauth2/http_client.hpp"
#include "datazoo/oauth2/tracing.hpp"
#include "duckdb/common/exception.hpp"
#include "yyjson.hpp"
#include <ctime>

using namespace duckdb_yyjson;

namespace erpl_web {

namespace {

OAuth2SecretTokenResponse ParseTokenResponse(const std::string &content, const std::string &endpoint_name) {
    auto doc = yyjson_read(content.c_str(), content.size(), 0);
    if (!doc) {
        throw duckdb::IOException("Failed to parse %s token response", endpoint_name.c_str());
    }

    OAuth2SecretTokenResponse result;
    auto root = yyjson_doc_get_root(doc);
    auto access_token_json = yyjson_obj_get(root, "access_token");
    if (!access_token_json || !yyjson_is_str(access_token_json)) {
        yyjson_doc_free(doc);
        throw duckdb::IOException("access_token missing in %s token response", endpoint_name.c_str());
    }
    result.access_token = yyjson_get_str(access_token_json);

    auto refresh_token_json = yyjson_obj_get(root, "refresh_token");
    if (refresh_token_json && yyjson_is_str(refresh_token_json)) {
        result.refresh_token = yyjson_get_str(refresh_token_json);
    }

    auto expires_in_json = yyjson_obj_get(root, "expires_in");
    if (expires_in_json && yyjson_is_num(expires_in_json)) {
        result.expires_in = static_cast<int>(yyjson_get_int(expires_in_json));
    }

    yyjson_doc_free(doc);
    return result;
}

std::string ParseTokenErrorDescription(const std::string &content) {
    if (content.empty()) {
        return "";
    }
    auto doc = yyjson_read(content.c_str(), content.size(), 0);
    if (!doc) {
        return "";
    }
    std::string result;
    auto root = yyjson_doc_get_root(doc);
    auto error_desc = yyjson_obj_get(root, "error_description");
    if (error_desc && yyjson_is_str(error_desc)) {
        result = yyjson_get_str(error_desc);
    }
    yyjson_doc_free(doc);
    return result;
}

} // anonymous namespace

OAuth2SecretTokenResponse OAuth2SecretTokenManager::ExecuteRefreshRequest(const OAuth2RefreshRequest &request) {
    ERPL_TRACE_DEBUG("OAUTH2_TOKEN_MANAGER", "Executing token request: " + request.token_url);

    HttpRequest http_request(HttpMethod::POST, request.token_url, request.content_type, request.post_body);
    http_request.headers.emplace("Accept", "application/json");
    if (request.use_basic_auth) {
        http_request.headers.emplace(
            "Authorization",
            "Basic " + HttpAuthParams::Base64Encode(request.basic_auth_username + ":" + request.basic_auth_password));
    }

    HttpClient http;
    auto resp = http.SendRequest(http_request);
    if (!resp) {
        throw duckdb::IOException("No response from token endpoint: " + request.token_url);
    }
    if (resp->Code() != 200) {
        std::string error_msg = "Token endpoint returned HTTP " + std::to_string(resp->Code()) + ": " + request.token_url;
        auto details = ParseTokenErrorDescription(resp->Content());
        if (!details.empty()) {
            error_msg += " (" + details + ")";
        }
        throw duckdb::IOException(error_msg);
    }

    return ParseTokenResponse(resp->Content(), request.token_url);
}

bool OAuth2SecretTokenManager::HasValidCachedToken(const duckdb::KeyValueSecret *kv_secret) {
    auto token_val = kv_secret->secret_map.find("access_token");
    if (token_val == kv_secret->secret_map.end()) {
        return false;
    }
    auto token_str = token_val->second.ToString();
    if (token_str.empty()) {
        return false;
    }

    auto expires_at_val = kv_secret->secret_map.find("expires_at");
    if (expires_at_val == kv_secret->secret_map.end()) {
        return false;
    }

    try {
        std::time_t expiration_time = std::stoll(expires_at_val->second.ToString());
        std::time_t current_time = std::time(nullptr);
        // 5-minute buffer, matching erpl-web's MicrosoftEntraTokenManager.
        return expiration_time > (current_time + 300);
    } catch (...) {
        return false;
    }
}

std::string OAuth2SecretTokenManager::GetCachedToken(const duckdb::KeyValueSecret *kv_secret) {
    auto token_val = kv_secret->secret_map.find("access_token");
    if (token_val == kv_secret->secret_map.end()) {
        throw duckdb::InvalidInputException("'access_token' not found in secret");
    }
    return token_val->second.ToString();
}

std::string OAuth2SecretTokenManager::GetToken(duckdb::ClientContext &context, const duckdb::KeyValueSecret *kv_secret,
                                                const OAuth2RefreshRequestBuilder &build_refresh_request) {
    ERPL_TRACE_DEBUG("OAUTH2_TOKEN_MANAGER", "Getting token");

    if (HasValidCachedToken(kv_secret)) {
        ERPL_TRACE_DEBUG("OAUTH2_TOKEN_MANAGER", "Using cached token");
        return GetCachedToken(kv_secret);
    }

    ERPL_TRACE_DEBUG("OAUTH2_TOKEN_MANAGER", "Cached token invalid or expired, acquiring/refreshing");

    auto request = build_refresh_request(*kv_secret);
    auto acquired = ExecuteRefreshRequest(request);

    if (acquired.access_token.empty()) {
        throw duckdb::IOException("Token endpoint response did not contain an access token");
    }

    if (acquired.expires_in > 0) {
        UpdateSecretWithTokens(context, kv_secret, acquired.access_token, acquired.expires_in, acquired.refresh_token);
    }

    return acquired.access_token;
}

void OAuth2SecretTokenManager::UpdateSecretWithTokens(duckdb::ClientContext &context,
                                                       const duckdb::KeyValueSecret *kv_secret,
                                                       const std::string &access_token, int expires_in,
                                                       const std::string &refresh_token) {
    ERPL_TRACE_DEBUG("OAUTH2_TOKEN_MANAGER", "Updating secret with new token");

    auto &secret_manager = duckdb::SecretManager::Get(context);
    auto secret_name = kv_secret->GetName();
    if (secret_name.empty()) {
        ERPL_TRACE_WARN("OAUTH2_TOKEN_MANAGER", "Secret has no name; refreshed token will not be persisted");
        return;
    }

    auto transaction = duckdb::CatalogTransaction::GetSystemCatalogTransaction(context);
    auto old_secret = secret_manager.GetSecretByName(transaction, secret_name);
    if (!old_secret) {
        ERPL_TRACE_WARN("OAUTH2_TOKEN_MANAGER", "Secret not found while persisting refreshed token: " + secret_name);
        return;
    }
    auto persist_type = old_secret->persist_type;
    auto storage_mode = old_secret->storage_mode;

    auto new_secret = old_secret->secret->Clone();
    auto new_secret_kv = dynamic_cast<const duckdb::KeyValueSecret *>(new_secret.get());
    if (!new_secret_kv) {
        throw duckdb::InvalidInputException("Failed to clone secret as KeyValueSecret");
    }

    duckdb::KeyValueSecret updated_secret(*new_secret_kv);
    updated_secret.secret_map["access_token"] = duckdb::Value(access_token);
    if (!refresh_token.empty()) {
        updated_secret.secret_map["refresh_token"] = duckdb::Value(refresh_token);
    }

    std::time_t expires_at = std::time(nullptr) + expires_in;
    updated_secret.secret_map["expires_at"] = duckdb::Value(std::to_string(expires_at));

    secret_manager.RegisterSecret(transaction, duckdb::make_uniq<duckdb::KeyValueSecret>(updated_secret),
                                   duckdb::OnCreateConflict::REPLACE_ON_CONFLICT, persist_type, storage_mode);

    ERPL_TRACE_INFO("OAUTH2_TOKEN_MANAGER", "Successfully updated secret with new token");
}

void RedactCommonKeys(duckdb::KeyValueSecret &result) {
    result.redact_keys.insert("client_secret");
    result.redact_keys.insert("access_token");
    result.redact_keys.insert("refresh_token");
}

} // namespace erpl_web
