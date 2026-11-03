#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <ctime>
#include <sys/stat.h>
#include <jwt-cpp/jwt.h>

#include "flashmq_plugin.h"

/*
 * Options (flashmq.conf, `plugin_opt_<name> <value>`):
 *
 *   jwt_secret_file   HS256 key file. Default /etc/flashmq/jwt_secret.key
 *   revocation_file   Revocation list from the API (one "<username> <unix-time>" per line); JWTs for
 *                     <username> issued before <unix-time> are refused, and connected clients holding
 *                     one are disconnected. Empty (default) = revocation checks off.
 *
 *   acl_mode          Topic ACL from the JWT `acl` claim: off (default) | log | enforce.
 *                     log = allow everything, log what enforce would deny. Unknown value = enforce.
 *
 * The revocation file is re-read when it changes, from flashmq_plugin_periodic_event (interval:
 * `plugin_timer_period`). Write it atomically (temp file + rename).
 *
 * `acl` claim (set by the API, version 1):
 *   {"v": 1, "pub": ["<filter>", ...], "sub": ["<filter>", ...]}   or   {"v": 1, "super": true}
 * `pub` covers publish and the will; `sub` covers subscribe and delivery. MQTT wildcards (+, #) are
 * allowed in the filters. A subscription is allowed only if every topic it can match is covered.
 * The legacy `subs` / `publ` claims are ignored.
 */

static const std::string DEFAULT_SECRET_FILE_PATH = "/etc/flashmq/jwt_secret.key";

static std::string g_jwt_secret;
static std::mutex g_secret_mutex;

// username -> JWTs issued before this time (unix seconds) are revoked
using RevocationMap = std::unordered_map<std::string, std::time_t>;
static std::shared_ptr<const RevocationMap> g_revocations = std::make_shared<RevocationMap>();
static std::shared_mutex g_revocations_mutex;
static std::mutex g_reload_mutex;
static std::string g_revocation_file;
static struct timespec g_revocation_mtime = {0, 0};

// Authenticated clients, so newly revoked ones can be disconnected: clientid -> username + JWT iat
struct ConnectedClient {
    std::string username;
    std::time_t issued_at;
};
static std::unordered_map<std::string, ConnectedClient> g_clients;
static std::mutex g_clients_mutex;

// Topic ACL (acl_mode)
enum class AclMode { off, log, enforce };
static std::atomic<AclMode> g_acl_mode{AclMode::off};
static constexpr double ACL_VERSION = 1;

using TopicLevels = std::vector<std::string>;

struct ClientAcl {
    std::string username;
    bool present = false; // token carried a valid `acl` claim
    bool super = false;
    std::vector<TopicLevels> pub;
    std::vector<TopicLevels> sub;
};

// clientid -> ACL of its token. Replaced on every login; stale entries pruned in the periodic event
// (not on disconnect: with a session takeover the old client's disconnect can follow the new login).
static std::unordered_map<std::string, std::shared_ptr<const ClientAcl>> g_acls;
static std::shared_mutex g_acls_mutex;

static std::string opt(const std::unordered_map<std::string, std::string> &opts, const std::string &key, const std::string &fallback) {
    auto it = opts.find(key);
    return (it == opts.end() || it->second.empty()) ? fallback : it->second;
}

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
    std::string secret = buffer.str();

    // Trim trailing whitespace/newlines
    secret.erase(secret.find_last_not_of(" \n\r\t") + 1);

    if (secret.empty()) {
        std::cerr << "[JWT Auth Plugin] ERROR: Secret file is empty!" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(g_secret_mutex);
    g_jwt_secret = secret;
    return true;
}

static std::string jwt_secret() {
    std::lock_guard<std::mutex> lock(g_secret_mutex);
    return g_jwt_secret;
}

static std::shared_ptr<const RevocationMap> revocations() {
    std::shared_lock<std::shared_mutex> lock(g_revocations_mutex);
    return g_revocations;
}

/** True when $username's tokens issued before some time are revoked and $issued_at is before it. */
static bool is_revoked(const RevocationMap &map, const std::string &username, std::time_t issued_at) {
    auto it = map.find(username);
    return it != map.end() && issued_at < it->second;
}

/** Disconnects tracked clients whose token is revoked under $map, and forgets clients that are gone. */
static void disconnect_revoked_clients(const RevocationMap &map) {
    std::vector<std::pair<std::string, std::string>> to_disconnect;

    {
        std::lock_guard<std::mutex> lock(g_clients_mutex);
        for (auto it = g_clients.begin(); it != g_clients.end();) {
            std::weak_ptr<Session> session;
            flashmq_get_session_pointer(it->first, it->second.username, session);
            std::weak_ptr<Client> client;
            flashmq_get_client_pointer(session, client);

            if (client.expired()) {
                it = g_clients.erase(it);
                continue;
            }

            if (is_revoked(map, it->second.username, it->second.issued_at)) {
                to_disconnect.emplace_back(it->first, it->second.username);
                it = g_clients.erase(it);
                continue;
            }

            ++it;
        }
    }

    for (const auto &[clientid, username] : to_disconnect) {
        std::weak_ptr<Session> session;
        flashmq_get_session_pointer(clientid, username, session);
        flashmq_plugin_remove_client_v4(session, true, ServerDisconnectReasons::NotAuthorized);
        flashmq_logf(LOG_NOTICE, "[JWT Auth Plugin] Disconnected client '%s' (username '%s'): token revoked.", clientid.c_str(), username.c_str());
    }
}

/**
 * Re-reads the revocation file when its mtime changed (or always when $force). On a read error
 * the previous list stays in place.
 */
static void reload_revocations(bool force) {
    if (g_revocation_file.empty()) {
        return;
    }

    std::unique_lock<std::mutex> reload_lock(g_reload_mutex, std::try_to_lock);
    if (!reload_lock.owns_lock()) {
        return; // another thread is reloading
    }

    struct stat st;
    if (stat(g_revocation_file.c_str(), &st) != 0) {
        flashmq_logf(LOG_ERR, "[JWT Auth Plugin] Revocation file '%s' not found; keeping the previous list.", g_revocation_file.c_str());
        return;
    }

    if (!force && st.st_mtim.tv_sec == g_revocation_mtime.tv_sec && st.st_mtim.tv_nsec == g_revocation_mtime.tv_nsec) {
        return;
    }

    std::ifstream file(g_revocation_file);
    if (!file.is_open()) {
        flashmq_logf(LOG_ERR, "[JWT Auth Plugin] Could not open revocation file '%s'; keeping the previous list.", g_revocation_file.c_str());
        return;
    }

    auto map = std::make_shared<RevocationMap>();
    std::string line;
    size_t line_number = 0;
    while (std::getline(file, line)) {
        line_number++;
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::istringstream fields(line);
        std::string username;
        long long revoked_after = 0;
        if (!(fields >> username >> revoked_after) || revoked_after <= 0) {
            flashmq_logf(LOG_WARNING, "[JWT Auth Plugin] Revocation file line %zu ignored: malformed.", line_number);
            continue;
        }

        auto &entry = (*map)[username];
        entry = std::max<std::time_t>(entry, static_cast<std::time_t>(revoked_after));
    }

    {
        std::unique_lock<std::shared_mutex> lock(g_revocations_mutex);
        g_revocations = map;
    }
    g_revocation_mtime = st.st_mtim;

    flashmq_logf(LOG_INFO, "[JWT Auth Plugin] Loaded %zu revocation(s) from '%s'.", map->size(), g_revocation_file.c_str());

    disconnect_revoked_clients(*map);
}

static TopicLevels split_topic(const std::string &topic) {
    TopicLevels levels;
    std::string::size_type start = 0;
    while (true) {
        auto pos = topic.find('/', start);
        levels.push_back(topic.substr(start, pos == std::string::npos ? std::string::npos : pos - start));
        if (pos == std::string::npos) {
            return levels;
        }
        start = pos + 1;
    }
}

/**
 * True when every topic $filter can match is also matched by $pattern. A topic name (no wildcards)
 * is a filter that matches only itself, so this is also the publish/deliver check.
 */
static bool pattern_covers(const TopicLevels &pattern, const TopicLevels &filter) {
    std::size_t i = 0;
    for (; i < pattern.size(); ++i) {
        const std::string &p = pattern[i];
        if (p == "#") {
            return true; // the rest, including the parent level
        }
        if (i >= filter.size()) {
            return false;
        }
        const std::string &f = filter[i];
        if (f == "#") {
            return false;
        }
        if (p == "+") {
            continue;
        }
        if (f != p) {
            return false; // includes a filter '+' against a literal level
        }
    }
    return i == filter.size();
}

static bool any_covers(const std::vector<TopicLevels> &patterns, const TopicLevels &filter) {
    return std::any_of(patterns.begin(), patterns.end(), [&](const TopicLevels &p) { return pattern_covers(p, filter); });
}

static AclMode parse_acl_mode(const std::string &value) {
    if (value.empty() || value == "off") return AclMode::off;
    if (value == "log") return AclMode::log;
    if (value != "enforce") {
        std::cerr << "[JWT Auth Plugin] Unknown acl_mode '" << value << "': using enforce." << std::endl;
    }
    return AclMode::enforce;
}

static const char *acl_mode_name(AclMode mode) {
    return mode == AclMode::off ? "off" : (mode == AclMode::log ? "log" : "enforce");
}

/** Reads the `acl` claim; an absent, malformed or wrong-version claim gives an ACL with present = false. */
template <typename Decoded>
static std::shared_ptr<const ClientAcl> parse_acl(const Decoded &decoded, const std::string &username) {
    auto acl = std::make_shared<ClientAcl>();
    acl->username = username;
    if (!decoded.has_payload_claim("acl")) {
        return acl;
    }

    picojson::value value = decoded.get_payload_claim("acl").to_json();
    if (!value.is<picojson::object>()) {
        return acl;
    }
    const picojson::object &obj = value.get<picojson::object>();

    auto version = obj.find("v");
    if (version == obj.end() || !version->second.is<double>() || version->second.get<double>() != ACL_VERSION) {
        return acl;
    }

    auto read_list = [&](const char *key, std::vector<TopicLevels> &out) -> bool {
        auto it = obj.find(key);
        if (it == obj.end()) {
            return true; // no list = nothing allowed
        }
        if (!it->second.is<picojson::array>()) {
            return false;
        }
        for (const auto &entry : it->second.get<picojson::array>()) {
            if (!entry.is<std::string>()) {
                return false;
            }
            out.push_back(split_topic(entry.get<std::string>()));
        }
        return true;
    };

    auto super = obj.find("super");
    bool is_super = super != obj.end() && super->second.is<bool>() && super->second.get<bool>();
    std::vector<TopicLevels> pub;
    std::vector<TopicLevels> sub;
    if (!read_list("pub", pub) || !read_list("sub", sub)) {
        return acl;
    }

    auto result = std::make_shared<ClientAcl>();
    result->username = username;
    result->present = true;
    result->super = is_super;
    result->pub = std::move(pub);
    result->sub = std::move(sub);
    return result;
}

/** Forgets ACLs of clients that are no longer connected. */
static void prune_acls() {
    std::vector<std::pair<std::string, std::shared_ptr<const ClientAcl>>> entries;
    {
        std::shared_lock<std::shared_mutex> lock(g_acls_mutex);
        entries.assign(g_acls.begin(), g_acls.end());
    }

    std::vector<std::pair<std::string, std::shared_ptr<const ClientAcl>>> gone;
    for (const auto &[clientid, acl] : entries) {
        std::weak_ptr<Session> session;
        flashmq_get_session_pointer(clientid, acl->username, session);
        std::weak_ptr<Client> client;
        flashmq_get_client_pointer(session, client);
        if (client.expired()) {
            gone.emplace_back(clientid, acl);
        }
    }

    if (gone.empty()) {
        return;
    }
    std::unique_lock<std::shared_mutex> lock(g_acls_mutex);
    for (const auto &[clientid, acl] : gone) {
        auto it = g_acls.find(clientid);
        if (it != g_acls.end() && it->second == acl) { // not replaced by a new login meanwhile
            g_acls.erase(it);
        }
    }
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
    (void)plugin_opts;
    *thread_data = nullptr;
}

void flashmq_plugin_deallocate_thread_memory(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts) {
    (void)thread_data;
    (void)plugin_opts;
}

/**
 * 2. Plugin Init: once, before the worker threads start. Also re-run on reload (SIGHUP), so a
 *    rotated secret or a changed revocation file path takes effect.
 */
void flashmq_plugin_main_init(std::unordered_map<std::string, std::string> &plugin_opts) {
    std::cout << "[JWT Auth Plugin] Initializing..." << std::endl;

    if (!load_jwt_secret(opt(plugin_opts, "jwt_secret_file", DEFAULT_SECRET_FILE_PATH))) {
        throw std::runtime_error("Failed to load JWT secret file");
    }
    std::cout << "[JWT Auth Plugin] Secret successfully loaded." << std::endl;

    g_revocation_file = opt(plugin_opts, "revocation_file", "");
    g_revocation_mtime = {0, 0};
    if (g_revocation_file.empty()) {
        std::unique_lock<std::shared_mutex> lock(g_revocations_mutex);
        g_revocations = std::make_shared<RevocationMap>();
        std::cout << "[JWT Auth Plugin] No revocation_file configured: revocation checks are off." << std::endl;
    } else {
        reload_revocations(true);
    }

    g_acl_mode = parse_acl_mode(opt(plugin_opts, "acl_mode", "off"));
    {
        std::unique_lock<std::shared_mutex> lock(g_acls_mutex);
        g_acls.clear();
    }
    std::cout << "[JWT Auth Plugin] Topic ACL mode: " << acl_mode_name(g_acl_mode) << "." << std::endl;
}

void flashmq_plugin_main_deinit(std::unordered_map<std::string, std::string> &plugin_opts) {
    (void)plugin_opts;
}

void flashmq_plugin_init(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts, bool reloading) {
    (void)thread_data;
    (void)plugin_opts;
    (void)reloading;
}

void flashmq_plugin_deinit(void *thread_data, std::unordered_map<std::string, std::string> &plugin_opts, bool reloading) {
    (void)thread_data;
    (void)plugin_opts;
    (void)reloading;
}

/**
 * Re-reads the revocation file when it changed (interval: plugin_timer_period).
 */
void flashmq_plugin_periodic_event(void *thread_data) {
    (void)thread_data;
    reload_revocations(false);
    if (g_acl_mode != AclMode::off) {
        prune_acls();
    }
}

/**
 * 3. Client Login Verification (CONNECT packet)
 *
 * On a listener with client_verification_ca_file, FlashMQ has already replaced the MQTT username
 * with the client certificate's CN, so `sub == username` binds the JWT to the certificate.
 * Everything below fails closed.
 */
AuthResult flashmq_plugin_login_check(
    void *thread_data,
    const std::string &clientid,
    const std::string &username,
    const std::string &password,
    const std::vector<std::pair<std::string, std::string>> *userProperties,
    const std::weak_ptr<Client> &client
) {
    (void)thread_data;
    (void)userProperties;
    (void)client;

    if (username.empty()) {
        std::cerr << "[JWT Auth Plugin] Auth failed for client '" << clientid << "': missing username." << std::endl;
        return AuthResult::login_denied;
    }

    if (password.empty()) {
        std::cerr << "[JWT Auth Plugin] Auth failed for client '" << clientid << "': missing token." << std::endl;
        return AuthResult::login_denied;
    }

    try {
        auto decoded = jwt::decode(password);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{jwt_secret()});

        verifier.verify(decoded);

        if (!decoded.has_expires_at()) {
            std::cerr << "[JWT Auth Plugin] Auth failed for client '" << clientid << "': token has no exp." << std::endl;
            return AuthResult::login_denied;
        }

        if (!decoded.has_subject() || decoded.get_subject() != username) {
            std::cerr << "[JWT Auth Plugin] Auth failed for client '" << clientid << "': token subject does not match username '" << username << "'." << std::endl;
            return AuthResult::login_denied;
        }

        // A token without iat can't be compared with a revocation time: treat it as issued at 0.
        std::time_t issued_at = decoded.has_issued_at() ? std::chrono::system_clock::to_time_t(decoded.get_issued_at()) : 0;

        if (is_revoked(*revocations(), username, issued_at)) {
            std::cerr << "[JWT Auth Plugin] Auth failed for client '" << clientid << "': token for '" << username << "' was revoked." << std::endl;
            return AuthResult::login_denied;
        }

        AclMode acl_mode = g_acl_mode;
        if (acl_mode != AclMode::off) {
            auto acl = parse_acl(decoded, username);
            if (!acl->present) {
                if (acl_mode == AclMode::enforce) {
                    std::cerr << "[JWT Auth Plugin] Auth failed for client '" << clientid << "': token for '" << username << "' has no valid acl claim." << std::endl;
                    return AuthResult::login_denied;
                }
                flashmq_logf(LOG_NOTICE, "[JWT Auth Plugin] acl: token for '%s' (client '%s') has no valid acl claim (enforce would deny the login).", username.c_str(), clientid.c_str());
            }
            std::unique_lock<std::shared_mutex> lock(g_acls_mutex);
            g_acls[clientid] = acl;
        }

        if (!g_revocation_file.empty()) {
            std::lock_guard<std::mutex> lock(g_clients_mutex);
            g_clients[clientid] = ConnectedClient{username, issued_at};
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
    (void)thread_data; (void)subtopics; (void)shareName;
    (void)payload; (void)qos; (void)retain; (void)correlationData; (void)responseTopic; (void)contentType;
    (void)expiryTime; (void)userProperties;

    AclMode mode = g_acl_mode;
    if (mode == AclMode::off) {
        return AuthResult::success;
    }

    std::shared_ptr<const ClientAcl> acl;
    {
        std::shared_lock<std::shared_mutex> lock(g_acls_mutex);
        auto it = g_acls.find(clientid);
        if (it != g_acls.end()) {
            acl = it->second;
        }
    }

    if (acl && !acl->present) {
        // Token without an acl claim: logged once at login; only reachable in log mode.
        return mode == AclMode::log ? AuthResult::success : AuthResult::acl_denied;
    }

    bool allowed = false;
    const char *what = "access";
    if (acl && acl->super) {
        allowed = true;
    } else if (acl) {
        TopicLevels levels = split_topic(topic);
        switch (access) {
            case AclAccess::write:
                what = "publish";
                allowed = any_covers(acl->pub, levels);
                break;
            case AclAccess::register_will:
                what = "will";
                allowed = any_covers(acl->pub, levels);
                break;
            case AclAccess::read:
                what = "deliver";
                allowed = any_covers(acl->sub, levels);
                break;
            case AclAccess::subscribe:
                what = "subscribe";
                allowed = any_covers(acl->sub, levels);
                break;
            default:
                allowed = false;
        }
    }

    if (allowed) {
        return AuthResult::success;
    }

    flashmq_logf(access == AclAccess::read ? LOG_INFO : LOG_NOTICE,
        "[JWT Auth Plugin] acl denied%s: %s '%s' for client '%s' (username '%s')%s.",
        mode == AclMode::log ? " (would deny)" : "", what, topic.c_str(), clientid.c_str(), username.c_str(),
        acl ? "" : ", no ACL for this client");
    return mode == AclMode::log ? AuthResult::success : AuthResult::acl_denied;
}

} // extern "C"
