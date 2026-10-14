#include "datazoo/oauth2/oauth2_callback_handler.hpp"
#include "datazoo/oauth2/tracing.hpp"
#include <future>
#include <stdexcept>
#include <mutex>
#include <atomic>
#include <string>
#include <condition_variable>
#include <memory>
#include <chrono>

namespace erpl_web {

OAuth2CallbackHandler::OAuth2CallbackHandler() = default;

void OAuth2CallbackHandler::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    expected_state_.clear();
    received_code_.clear();
    error_message_.clear();
    callback_received_.store(false);
    has_error_.store(false);
}

void OAuth2CallbackHandler::SetExpectedState(const std::string& expected_state) {
    std::lock_guard<std::mutex> lock(mutex_);
    expected_state_ = expected_state;
}

bool OAuth2CallbackHandler::HandleCallback(const std::string& code, const std::string& state) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Neither the code nor the state is traced: both are credentials for the
    // few seconds they live.
    if (!ValidateState(state)) {
        ERPL_TRACE_WARN("OAUTH2_CALLBACK", "Ignoring a callback whose state does not match this flow");
        return false;
    }

    ERPL_TRACE_INFO("OAUTH2_CALLBACK", "Received the authorization callback");
    received_code_ = code;
    callback_received_.store(true);
    code_cv_.notify_all(); // Notify waiting threads
    return true;
}

bool OAuth2CallbackHandler::HandleError(const std::string& error, const std::string& error_description, const std::string& state) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!ValidateState(state)) {
        ERPL_TRACE_WARN("OAUTH2_CALLBACK", "Ignoring an error callback whose state does not match this flow");
        return false;
    }

    ERPL_TRACE_WARN("OAUTH2_CALLBACK", std::string("Received error: ") + error + " - " + error_description);
    error_message_ = "OAuth2 error: " + error + " - " + error_description;
    has_error_.store(true);
    code_cv_.notify_all(); // Notify waiting threads
    return true;
}

std::string OAuth2CallbackHandler::WaitForCode(std::chrono::seconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);

    // Wait for callback or error with timeout
    if (!code_cv_.wait_for(lock, timeout, [this] {
        return callback_received_.load() || has_error_.load();
    })) {
        throw std::runtime_error("Timeout waiting for OAuth2 callback");
    }

    // Check for errors first
    if (has_error_.load()) {
        throw std::runtime_error("OAuth2 error: " + error_message_);
    }

    // Return the received code
    if (callback_received_.load() && !received_code_.empty()) {
        return received_code_;
    }

    throw std::runtime_error("No authorization code received");
}

std::string OAuth2CallbackHandler::GetErrorMessage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return error_message_;
}

std::string OAuth2CallbackHandler::GetReceivedCode() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return received_code_;
}

bool OAuth2CallbackHandler::ValidateState(const std::string& received_state) const {
    // An unset expected state matches nothing. Compared in constant time: the
    // state is a CSRF secret, and the loopback port is reachable by any page.
    if (expected_state_.empty() || received_state.size() != expected_state_.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < received_state.size(); i++) {
        diff |= static_cast<unsigned char>(received_state[i] ^ expected_state_[i]);
    }
    return diff == 0;
}

} // namespace erpl_web
