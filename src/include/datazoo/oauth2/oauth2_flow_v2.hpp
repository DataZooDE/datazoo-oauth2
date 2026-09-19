#pragma once

#include "datazoo/oauth2/oauth2_types.hpp"
#include "datazoo/oauth2/oauth2_server.hpp"
#include "datazoo/oauth2/timeout_http_client.hpp"
#include <memory>
#include <string>

namespace erpl_web {

class OAuth2FlowV2 {
public:
    OAuth2FlowV2();
    ~OAuth2FlowV2();

    OAuth2Tokens ExecuteFlow(const OAuth2Config& config);

private:
    std::string ExecuteAuthorizationCodeFlow(const OAuth2Config& config);
    OAuth2Tokens ExchangeCodeForTokens(const OAuth2Config& config, const std::string& authorization_code, const std::string& code_verifier);
    std::string BuildTokenExchangePostData(const OAuth2Config& config, const std::string& authorization_code, const std::string& code_verifier);
    OAuth2Tokens ParseTokenResponse(const std::string& response_content);
    std::string GenerateCodeVerifier();
    std::string GenerateCodeChallenge(const std::string& code_verifier);
    std::string GenerateState();
    std::string BuildAuthorizationUrl(const OAuth2Config& config, const std::string& code_challenge, const std::string& state);
    void OpenBrowser(const std::string& url);
    // `browser_will_open` decides between "a browser will open" and "open this yourself".
    // Promising an automatic open on a headless session and then reporting that it could not
    // happen is worse than saying so once, up front.
    void DisplayOAuth2Instructions(const std::string& auth_url, bool browser_will_open);

    // Prints, on the console, why no browser opened and what to do instead.
    static void ExplainManualAuthorizationStep(const std::string& url, const std::string& reason);

    std::unique_ptr<OAuth2Server> server_;
    std::unique_ptr<TimeoutHttpClient> http_client_;
    std::string stored_code_verifier_;
};

} // namespace erpl_web
