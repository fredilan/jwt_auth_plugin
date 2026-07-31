#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <chrono>
#include <jwt-cpp/jwt.h>

#include "flashmq_plugin.h"

// Path to your secret file
static const std::string SECRET_FILE_PATH = "/etc/flashmq/jwt_secret.key";
static std::string g_jwt_secret;

/**
 * Helper to read and trim the secret file
 */
static bool load_jwt_secret(const std::string &filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[JWT Auth Plugin] ERROR: Could not open secret file at " << filepath << std::endl;
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    g_jwt_secret = buffer.str();

    // Trim trailing whitespace/newlines
    g_jwt_secret.erase(g_jwt_secret.find_last_not_of(" \n\r\t") + 1);

    if (g_jwt_secret.empty()) {
        std::cerr << "[JWT Auth Plugin] ERROR: Secret file is empty!" << std::endl;
        return false;
    }

    return true;
}

extern "C" {

/**
 * MANDATORY: FlashMQ inspects this symbol to verify it is a valid native plugin.
 */
int flashmq_plugin_version() {
    return FLASHMQ_PLUGIN_VERSION;
}

/**
 * 1. Thread Memory Allocation Hooks
 */
void flashmq_plugin_allocate_thread_memory(void **thread_data, std::unordered_map<std::string, std::string> &plugin_opts) {
    *thread_data = nullptr;
}

void flashmq_plugin_deallocate_thread_memory(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts) {
}

/**
 * 2. Plugin Init
 */
void flashmq_plugin_init(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts, bool reloading) {
    if (!reloading) {
        std::cout << "[JWT Auth Plugin] Initializing..." << std::endl;
        if (!load_jwt_secret(SECRET_FILE_PATH)) {
            throw std::runtime_error("Failed to load JWT secret file");
        }
        std::cout << "[JWT Auth Plugin] Secret successfully loaded." << std::endl;
    }
}

void flashmq_plugin_deinit(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts, bool reloading) {
}

/**
 * 3. Client Login Verification (CONNECT packet)
 */
AuthResult flashmq_plugin_login_check(
    void *thread_data,
    const std::string &clientid,
    const std::string &username,
    const std::string &password,
    const std::vector<std::pair<std::string, std::string>> *userProperties,
    const std::weak_ptr<Client> &client
) {
    if (password.empty()) {
        std::cerr << "[JWT Auth Plugin] Auth failed for client '" << clientid << "': missing token." << std::endl;
        return AuthResult::login_denied;
    }

    try {
        auto decoded = jwt::decode(password);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{g_jwt_secret});

        verifier.verify(decoded);

        if (decoded.has_subject() && !username.empty() && decoded.get_subject() != username) {
            std::cerr << "[JWT Auth Plugin] Auth failed: username mismatch." << std::endl;
            return AuthResult::login_denied;
        }

        return AuthResult::success;
    } 
    catch (const std::exception &e) {
        std::cerr << "[JWT Auth Plugin] JWT validation failed for client '" 
                  << clientid << "': " << e.what() << std::endl;
        return AuthResult::login_denied;
    }
}

/**
 * 4. ACL Check (PUBLISH / SUBSCRIBE)
 */
AuthResult flashmq_plugin_acl_check(
    void *thread_data,
    const AclAccess access,
    const std::string &clientid,
    const std::string &username,
    const std::string &topic,
    const std::vector<std::string> &subtopics,
    const std::string &shareName,
    std::string_view payload,
    const uint8_t qos,
    const bool retain,
    const std::optional<std::string> &correlationData,
    const std::optional<std::string> &responseTopic,
    const std::optional<std::string> &contentType,
    std::optional<std::chrono::time_point<std::chrono::steady_clock>> expiryTime,
    const std::vector<std::pair<std::string, std::string>> *userProperties
) {
    return AuthResult::success;
}

} // extern "C"