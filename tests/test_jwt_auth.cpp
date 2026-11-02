// Unit tests for jwt_auth.cpp: compiles the plugin with stubbed FlashMQ functions.
//   make test
#include <cstdarg>
#include <cstdio>
#include <unistd.h>
#include "../jwt_auth.cpp"

// --- FlashMQ stubs ---------------------------------------------------------------------------

static std::vector<std::string> g_removed_clients;
static std::unordered_map<std::string, std::shared_ptr<Client>> g_live_clients; // clientid -> fake client
static std::string g_last_session_lookup;

void flashmq_logf(int, const char *str, ...) {
    va_list args;
    va_start(args, str);
    vfprintf(stderr, str, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void flashmq_get_session_pointer(const std::string &clientid, const std::string &, std::weak_ptr<Session> &sessionOut) {
    g_last_session_lookup = clientid;
    sessionOut.reset();
}

void flashmq_get_client_pointer(const std::weak_ptr<Session> &, std::weak_ptr<Client> &clientOut) {
    auto it = g_live_clients.find(g_last_session_lookup);
    if (it == g_live_clients.end()) {
        clientOut.reset();
    } else {
        clientOut = it->second;
    }
}

void flashmq_plugin_remove_client_v4(const std::weak_ptr<Session> &, bool, ServerDisconnectReasons) {
    g_removed_clients.push_back(g_last_session_lookup);
}

// --- helpers -------------------------------------------------------------------------------------

static const std::string SECRET = "test-secret-0123456789";
static int g_failures = 0;

#define CHECK(name, cond) do { \
    if (cond) { std::cout << "ok   " << name << std::endl; } \
    else { std::cout << "FAIL " << name << std::endl; g_failures++; } \
} while (0)

static std::string token(std::optional<std::string> sub, bool with_exp, std::optional<std::time_t> iat, const std::string &secret = SECRET) {
    auto builder = jwt::create().set_type("JWT");
    if (sub) builder.set_subject(*sub);
    if (with_exp) builder.set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(1));
    if (iat) builder.set_issued_at(std::chrono::system_clock::from_time_t(*iat));
    return builder.sign(jwt::algorithm::hs256{secret});
}

static AuthResult login(const std::string &clientid, const std::string &username, const std::string &password) {
    std::weak_ptr<Client> client;
    return flashmq_plugin_login_check(nullptr, clientid, username, password, nullptr, client);
}

static std::string write_file(const std::string &path, const std::string &content) {
    std::string tmp = path + ".tmp";
    std::ofstream(tmp) << content;
    rename(tmp.c_str(), path.c_str());
    return path;
}

int main() {
    char dir_template[] = "/tmp/jwt_auth_test.XXXXXX";
    std::string dir = mkdtemp(dir_template);
    std::string secret_file = write_file(dir + "/secret.key", SECRET + "\n");
    std::string revocation_file = dir + "/revocations.txt";
    std::time_t now = std::time(nullptr);

    std::unordered_map<std::string, std::string> opts{{"jwt_secret_file", secret_file}, {"revocation_file", revocation_file}};
    write_file(revocation_file, "# header\nSN-REVOKED " + std::to_string(now - 100) + "\nbad line\n");
    flashmq_plugin_main_init(opts);

    // --- login checks ---
    CHECK("valid token, sub == username", login("c1", "SN001", token("SN001", true, now)) == AuthResult::success);
    CHECK("sub != username denied", login("c2", "SN001", token("SN002", true, now)) == AuthResult::login_denied);
    CHECK("missing sub denied", login("c3", "SN001", token(std::nullopt, true, now)) == AuthResult::login_denied);
    CHECK("empty username denied", login("c4", "", token("SN001", true, now)) == AuthResult::login_denied);
    CHECK("missing exp denied", login("c5", "SN001", token("SN001", false, now)) == AuthResult::login_denied);
    CHECK("wrong secret denied", login("c6", "SN001", token("SN001", true, now, "other-secret")) == AuthResult::login_denied);
    CHECK("empty password denied", login("c7", "SN001", "") == AuthResult::login_denied);
    CHECK("garbage token denied", login("c8", "SN001", "not.a.jwt") == AuthResult::login_denied);

    std::string expired = jwt::create().set_subject("SN001").set_issued_at(std::chrono::system_clock::from_time_t(now - 7200))
        .set_expires_at(std::chrono::system_clock::from_time_t(now - 3600)).sign(jwt::algorithm::hs256{SECRET});
    CHECK("expired token denied", login("c9", "SN001", expired) == AuthResult::login_denied);

    std::string none_alg = jwt::create().set_subject("SN001").set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(1))
        .sign(jwt::algorithm::none{});
    CHECK("alg none denied", login("c10", "SN001", none_alg) == AuthResult::login_denied);

    // --- revocation at login ---
    CHECK("token issued before revocation denied", login("r1", "SN-REVOKED", token("SN-REVOKED", true, now - 200)) == AuthResult::login_denied);
    CHECK("token issued after revocation allowed", login("r2", "SN-REVOKED", token("SN-REVOKED", true, now - 50)) == AuthResult::success);
    CHECK("token without iat for revoked user denied", login("r3", "SN-REVOKED", token("SN-REVOKED", true, std::nullopt)) == AuthResult::login_denied);
    CHECK("token without iat for other user allowed", login("r4", "SN-OTHER", token("SN-OTHER", true, std::nullopt)) == AuthResult::success);

    // --- reload: newly revoked connected client is disconnected, others stay ---
    g_live_clients["live-a"] = nullptr; g_live_clients["live-b"] = nullptr;
    g_live_clients["live-a"] = std::shared_ptr<Client>(reinterpret_cast<Client *>(0x1), [](Client *) {});
    g_live_clients["live-b"] = std::shared_ptr<Client>(reinterpret_cast<Client *>(0x2), [](Client *) {});
    CHECK("live-a connects", login("live-a", "SN-A", token("SN-A", true, now - 30)) == AuthResult::success);
    CHECK("live-b connects", login("live-b", "SN-B", token("SN-B", true, now - 30)) == AuthResult::success);

    sleep(1); // distinct mtime
    write_file(revocation_file, "SN-A " + std::to_string(now) + "\n");
    g_removed_clients.clear();
    flashmq_plugin_periodic_event(nullptr);
    CHECK("revoked live client disconnected", g_removed_clients == std::vector<std::string>{"live-a"});
    CHECK("SN-A old token now denied", login("x1", "SN-A", token("SN-A", true, now - 30)) == AuthResult::login_denied);
    CHECK("SN-REVOKED dropped from new list", login("x2", "SN-REVOKED", token("SN-REVOKED", true, now - 200)) == AuthResult::success);

    g_removed_clients.clear();
    flashmq_plugin_periodic_event(nullptr);
    CHECK("unchanged file: no reload, no disconnect", g_removed_clients.empty());

    // --- missing file keeps last good list ---
    unlink(revocation_file.c_str());
    flashmq_plugin_periodic_event(nullptr);
    CHECK("missing file keeps previous list", login("x3", "SN-A", token("SN-A", true, now - 30)) == AuthResult::login_denied);

    // --- revocation off ---
    std::unordered_map<std::string, std::string> opts_off{{"jwt_secret_file", secret_file}};
    flashmq_plugin_main_init(opts_off);
    CHECK("no revocation_file: old SN-A token allowed", login("y1", "SN-A", token("SN-A", true, now - 30)) == AuthResult::success);

    std::cout << (g_failures == 0 ? "ALL PASSED" : std::to_string(g_failures) + " FAILED") << std::endl;
    return g_failures == 0 ? 0 : 1;
}
