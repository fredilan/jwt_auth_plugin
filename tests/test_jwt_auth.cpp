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

static std::string acl_token(const std::string &sub, const std::string &acl_json) {
    picojson::value acl;
    std::string err = picojson::parse(acl, acl_json);
    if (!err.empty()) {
        std::cerr << "bad test acl json: " << err << std::endl;
    }
    return jwt::create().set_type("JWT").set_subject(sub)
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(1))
        .set_payload_claim("acl", jwt::claim(acl))
        .sign(jwt::algorithm::hs256{SECRET});
}

static AuthResult acl(const std::string &clientid, const std::string &username, AclAccess access, const std::string &topic) {
    std::vector<std::string> subtopics;
    return flashmq_plugin_acl_check(nullptr, access, clientid, username, topic, subtopics, "", std::string_view(),
        0, false, std::nullopt, std::nullopt, std::nullopt, std::nullopt, nullptr);
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


    // --- topic ACL (acl_mode) ---
    const std::string DEVICE_ACL = R"({"v":1,"pub":["/duke/iot/SN1/status","/duke/iot/SN1/response/+"],"sub":["/duke/iot/SN1/request/+","/duke/iot/SN1/command"]})";
    const std::string GATEWAY_ACL = R"({"v":1,"pub":["/duke/iot/GW1/status","/duke/iot/gateways/GW1/provision"],"sub":["/duke/iot/gateways/GW1/provision/response"]})";
    const AuthResult OK = AuthResult::success;
    const AuthResult NO = AuthResult::acl_denied;

    std::unordered_map<std::string, std::string> opts_enforce{{"jwt_secret_file", secret_file}, {"acl_mode", "enforce"}};
    flashmq_plugin_main_init(opts_enforce);

    CHECK("acl: device login", login("a1", "SN1", acl_token("SN1", DEVICE_ACL)) == OK);
    CHECK("acl: publish own status", acl("a1", "SN1", AclAccess::write, "/duke/iot/SN1/status") == OK);
    CHECK("acl: publish own response/<id>", acl("a1", "SN1", AclAccess::write, "/duke/iot/SN1/response/abc") == OK);
    CHECK("acl: publish response/<id>/<extra> denied", acl("a1", "SN1", AclAccess::write, "/duke/iot/SN1/response/a/b") == NO);
    CHECK("acl: publish other device denied", acl("a1", "SN1", AclAccess::write, "/duke/iot/SN2/status") == NO);
    CHECK("acl: publish on own sub-only topic denied", acl("a1", "SN1", AclAccess::write, "/duke/iot/SN1/command") == NO);
    CHECK("acl: deliver own request", acl("a1", "SN1", AclAccess::read, "/duke/iot/SN1/request/x") == OK);
    CHECK("acl: deliver other device denied", acl("a1", "SN1", AclAccess::read, "/duke/iot/SN2/request/x") == NO);
    CHECK("acl: subscribe own request/+", acl("a1", "SN1", AclAccess::subscribe, "/duke/iot/SN1/request/+") == OK);
    CHECK("acl: subscribe own request/<id>", acl("a1", "SN1", AclAccess::subscribe, "/duke/iot/SN1/request/abc") == OK);
    CHECK("acl: subscribe # denied", acl("a1", "SN1", AclAccess::subscribe, "#") == NO);
    CHECK("acl: subscribe /duke/iot/# denied", acl("a1", "SN1", AclAccess::subscribe, "/duke/iot/#") == NO);
    CHECK("acl: subscribe own /# denied", acl("a1", "SN1", AclAccess::subscribe, "/duke/iot/SN1/#") == NO);
    CHECK("acl: subscribe +/request/+ denied", acl("a1", "SN1", AclAccess::subscribe, "/duke/iot/+/request/+") == NO);
    CHECK("acl: will on own status", acl("a1", "SN1", AclAccess::register_will, "/duke/iot/SN1/status") == OK);
    CHECK("acl: will on other topic denied", acl("a1", "SN1", AclAccess::register_will, "/duke/iot/SN2/status") == NO);
    CHECK("acl: device can't act as gateway", acl("a1", "SN1", AclAccess::write, "/duke/iot/gateways/SN1/provision") == NO);
    CHECK("acl: device can't read gateway responses", acl("a1", "SN1", AclAccess::subscribe, "/duke/iot/gateways/GW1/provision/response") == NO);

    CHECK("acl: gateway login", login("g1", "GW1", acl_token("GW1", GATEWAY_ACL)) == OK);
    CHECK("acl: gateway publishes own provision", acl("g1", "GW1", AclAccess::write, "/duke/iot/gateways/GW1/provision") == OK);
    CHECK("acl: gateway publishes other gateway denied", acl("g1", "GW1", AclAccess::write, "/duke/iot/gateways/GW2/provision") == NO);
    CHECK("acl: gateway reads own provision response", acl("g1", "GW1", AclAccess::read, "/duke/iot/gateways/GW1/provision/response") == OK);

    CHECK("acl: service login", login("svc", "api", acl_token("api", R"({"v":1,"super":true})")) == OK);
    CHECK("acl: super subscribes /duke/iot/#", acl("svc", "api", AclAccess::subscribe, "/duke/iot/#") == OK);
    CHECK("acl: super receives any delivery", acl("svc", "api", AclAccess::read, "/duke/iot/SN1/status") == OK);
    CHECK("acl: super publishes requests", acl("svc", "api", AclAccess::write, "/duke/iot/SN1/request/1") == OK);

    CHECK("acl: pattern /# covers parent level", login("h1", "SN9", acl_token("SN9", R"({"v":1,"pub":["/a/#"]})")) == OK
        && acl("h1", "SN9", AclAccess::write, "/a") == OK && acl("h1", "SN9", AclAccess::write, "/a/b/c") == OK
        && acl("h1", "SN9", AclAccess::write, "/b") == NO);
    CHECK("acl: missing sub list = no subscriptions", acl("h1", "SN9", AclAccess::subscribe, "/a/b") == NO);

    CHECK("acl: token without acl denied in enforce", login("n1", "SN3", token("SN3", true, now)) == AuthResult::login_denied);
    CHECK("acl: wrong acl version denied", login("n2", "SN3", acl_token("SN3", R"({"v":2,"pub":[],"sub":[]})")) == AuthResult::login_denied);
    CHECK("acl: malformed pub list denied", login("n3", "SN3", acl_token("SN3", R"({"v":1,"pub":"/duke/iot/SN3/status"})")) == AuthResult::login_denied);
    CHECK("acl: unknown client denied", acl("nobody", "SN4", AclAccess::write, "/duke/iot/SN4/status") == NO);
    CHECK("acl: sub must still equal username", login("n4", "SN1", acl_token("SN2", DEVICE_ACL)) == AuthResult::login_denied);

    // prune: entries of clients that are gone are dropped, live ones and re-logins kept
    g_live_clients.clear();
    g_live_clients["g1"] = std::shared_ptr<Client>(reinterpret_cast<Client *>(0x3), [](Client *) {});
    flashmq_plugin_periodic_event(nullptr);
    CHECK("acl: pruned client loses access", acl("a1", "SN1", AclAccess::write, "/duke/iot/SN1/status") == NO);
    CHECK("acl: live client keeps access", acl("g1", "GW1", AclAccess::write, "/duke/iot/gateways/GW1/provision") == OK);
    CHECK("acl: re-login restores access", login("a1", "SN1", acl_token("SN1", DEVICE_ACL)) == OK
        && acl("a1", "SN1", AclAccess::write, "/duke/iot/SN1/status") == OK);

    std::unordered_map<std::string, std::string> opts_log{{"jwt_secret_file", secret_file}, {"acl_mode", "log"}};
    flashmq_plugin_main_init(opts_log);
    CHECK("acl log: token without acl allowed", login("l1", "SN3", token("SN3", true, now)) == OK);
    CHECK("acl log: its traffic allowed", acl("l1", "SN3", AclAccess::write, "/duke/iot/SN9/status") == OK);
    CHECK("acl log: device login", login("l2", "SN1", acl_token("SN1", DEVICE_ACL)) == OK);
    CHECK("acl log: would-deny publish allowed", acl("l2", "SN1", AclAccess::write, "/duke/iot/SN2/status") == OK);
    CHECK("acl log: unknown client allowed", acl("nobody", "SN4", AclAccess::subscribe, "#") == OK);

    std::unordered_map<std::string, std::string> opts_bad{{"jwt_secret_file", secret_file}, {"acl_mode", "strict"}};
    flashmq_plugin_main_init(opts_bad);
    CHECK("acl: unknown mode = enforce", login("u1", "SN3", token("SN3", true, now)) == AuthResult::login_denied);

    flashmq_plugin_main_init(opts_off);
    CHECK("acl off: unknown client allowed", acl("nobody", "SN4", AclAccess::subscribe, "#") == OK);

    std::cout << (g_failures == 0 ? "ALL PASSED" : std::to_string(g_failures) + " FAILED") << std::endl;
    return g_failures == 0 ? 0 : 1;
}
