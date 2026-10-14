#include <catch2/catch_test_macros.hpp>
#include "datazoo/oauth2/oauth2_callback_handler.hpp"

using namespace erpl_web;

// S-0.11: state/CSRF validation and callback bookkeeping, pure (no sockets).

TEST_CASE("OAuth2CallbackHandler: matching state stores the code", "[oauth2_callback_handler]") {
    OAuth2CallbackHandler handler;
    handler.SetExpectedState("expected-state");
    handler.HandleCallback("auth-code-123", "expected-state");

    REQUIRE(handler.IsCallbackReceived() == true);
    REQUIRE(handler.HasError() == false);
    REQUIRE(handler.GetReceivedCode() == "auth-code-123");
}

TEST_CASE("OAuth2CallbackHandler: a mismatched state is ignored, not accepted and not fatal",
          "[oauth2_callback_handler]") {
    // Any web page can navigate the browser to the loopback port while the flow
    // waits. A request without our state must neither deliver a code nor abort
    // the flow (that would let any page cancel a sign-in) -- it is ignored.
    OAuth2CallbackHandler handler;
    handler.SetExpectedState("expected-state");
    REQUIRE(handler.HandleCallback("auth-code-123", "attacker-state") == false);

    REQUIRE(handler.IsCallbackReceived() == false);
    REQUIRE(handler.HasError() == false);
    REQUIRE(handler.GetReceivedCode().empty());

    // The genuine redirect still completes the flow afterwards.
    REQUIRE(handler.HandleCallback("real-code", "expected-state") == true);
    REQUIRE(handler.IsCallbackReceived() == true);
    REQUIRE(handler.GetReceivedCode() == "real-code");
}

TEST_CASE("OAuth2CallbackHandler: an empty expected state never matches", "[oauth2_callback_handler]") {
    OAuth2CallbackHandler handler;
    REQUIRE(handler.HandleCallback("code", "") == false);
    REQUIRE(handler.IsCallbackReceived() == false);
}

TEST_CASE("OAuth2CallbackHandler: HandleError surfaces the OAuth2 error text", "[oauth2_callback_handler]") {
    OAuth2CallbackHandler handler;
    handler.SetExpectedState("expected-state");
    REQUIRE(handler.HandleError("access_denied", "user cancelled", "expected-state") == true);

    REQUIRE(handler.HasError() == true);
    REQUIRE(handler.IsCallbackReceived() == false);
    REQUIRE(handler.GetErrorMessage() == "OAuth2 error: access_denied - user cancelled");
}

TEST_CASE("OAuth2CallbackHandler: HandleError with mismatched state is ignored", "[oauth2_callback_handler]") {
    OAuth2CallbackHandler handler;
    handler.SetExpectedState("expected-state");
    REQUIRE(handler.HandleError("access_denied", "forged", "wrong-state") == false);

    REQUIRE(handler.HasError() == false);
    REQUIRE(handler.GetErrorMessage().empty());
}

TEST_CASE("OAuth2CallbackHandler: error text never carries the state", "[oauth2_callback_handler]") {
    OAuth2CallbackHandler handler;
    handler.SetExpectedState("expected-state-secret");
    handler.HandleError("access_denied", "user cancelled", "expected-state-secret");
    REQUIRE(handler.HasError() == true);
    REQUIRE(handler.GetErrorMessage().find("expected-state-secret") == std::string::npos);
}

TEST_CASE("OAuth2CallbackHandler: Reset clears prior callback/error state", "[oauth2_callback_handler]") {
    OAuth2CallbackHandler handler;
    handler.SetExpectedState("s1");
    handler.HandleCallback("code", "s1");
    REQUIRE(handler.IsCallbackReceived() == true);

    handler.Reset();
    REQUIRE(handler.IsCallbackReceived() == false);
    REQUIRE(handler.HasError() == false);
    REQUIRE(handler.GetReceivedCode().empty());
    REQUIRE(handler.GetErrorMessage().empty());
}

TEST_CASE("OAuth2CallbackHandler: WaitForCode returns immediately once a matching callback already arrived",
          "[oauth2_callback_handler]") {
    OAuth2CallbackHandler handler;
    handler.SetExpectedState("s1");
    handler.HandleCallback("code-xyz", "s1");

    auto code = handler.WaitForCode(std::chrono::seconds(1));
    REQUIRE(code == "code-xyz");
}

TEST_CASE("OAuth2CallbackHandler: WaitForCode throws when an error already arrived", "[oauth2_callback_handler]") {
    OAuth2CallbackHandler handler;
    handler.SetExpectedState("s1");
    handler.HandleError("access_denied", "no", "s1");

    REQUIRE_THROWS(handler.WaitForCode(std::chrono::seconds(1)));
}
