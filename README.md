# FlashMQ JWT Authentication Plugin
An enterprise-grade C++ authentication plugin for [FlashMQ](https://www.flashmq.org/) that validates **HS256-signed JSON Web Tokens (JWTs)** passed in the MQTT password field.

## Features
- **HS256 JWT Verification:** Validates token signatures and structure using `jwt-cpp` and OpenSSL. `exp` is **required** and enforced.
- **Username / Subject Matching (fail closed):** The MQTT username must be non-empty and equal the JWT's `sub` claim; a token without `sub` is refused. On a listener with `client_verification_ca_file`, FlashMQ replaces the username with the client certificate's CN, so this check **binds the JWT to the client certificate**.
- **Token Revocation:** Optional revocation list from the API (`plugin_opt_revocation_file`). JWTs for a username issued before its revocation time are refused, and connected clients holding one are disconnected (FlashMQ has no CRL support).
- **Externalized Secret Key:** Loads the HMAC key from a separate secured file (`plugin_opt_jwt_secret_file`) instead of hardcoding credentials. Re-read on reload (SIGHUP).
- **Strict Network Security:** Compatible with dual-layer authentication (mTLS + Application-level JWT) and strict non-anonymous connection configurations.

---

## 1. Prerequisites & Dependencies
To build the plugin on Debian/Ubuntu or Linux-based environments, install the C++17 build tools, OpenSSL development headers, CMake, and `git`:

``` bash
sudo apt update
sudo apt install -y build-essential cmake git libssl-dev
```

### Install Header-Only `jwt-cpp`
This plugin uses the header-only library [jwt-cpp](https://github.com/Thalhammer/jwt-cpp). Install it system-wide:

``` bash
git clone https://github.com/Thalhammer/jwt-cpp.git
sudo cp -r jwt-cpp/include/jwt-cpp /usr/local/include/
```

Note: Ensure `flashmq_plugin.h` and `flashmq_public.h` from your FlashMQ installation is present in your build folder or available in standard system include paths (`/usr/include` or `/usr/local/include`).

### Copy Header files from FlashMQ repo

``` bash
wget https://raw.githubusercontent.com/halfgaar/FlashMQ/master/flashmq_plugin.h
wget https://raw.githubusercontent.com/halfgaar/FlashMQ/master/flashmq_public.h
```


### 2. Directory Structure
Organize your project repository as follows:

``` plaintext
.
├── jwt_auth.cpp          # C++ Plugin Source Code
├── Makefile              # Optional build script
└── README.md             # Documentation
```

### 3. Compilation
Compile the C++ plugin source code (`jwt_auth.cpp`) into a dynamic shared library (`.so`):

``` C++
g++ -fPIC -shared -O2 -std=c++17 jwt_auth.cpp -o /etc/flashmq/jwt_auth_plugin.so -lcrypto
```

### 3.1 Using Makefile

Usage Commands
``` bash
# Compile the plugin (add CPPFLAGS="-I. -I/path/to/jwt-cpp/include" if jwt-cpp isn't in /usr/local/include)
make
# Run the unit tests (stubs FlashMQ; no broker needed)
make test
# Verify FlashMQ plugin symbols are correctly exported
make check-symbols
# Install the .so file to /etc/flashmq (requires elevated privileges if writing to system dirs)
sudo make install
# Clean build output
make clean
```

### Verify Exported Symbols
Confirm that FlashMQ symbols are exported cleanly without C++ name mangling:

``` bash
nm -D /etc/flashmq/jwt_auth_plugin.so | grep flashmq_plugin_version
```

Expected output: `000000000000... T flashmq_plugin_version`

### 4. Secret Key Provisioning
Create the secret key file and enforce restricted read permissions so only the flashmq service user can view it:
``` bash
printf "your-super-secret-hs256-key-here" | sudo tee /etc/flashmq/jwt_secret.key > /dev/null

sudo chmod 600 /etc/flashmq/jwt_secret.key
sudo chown flashmq:flashmq /etc/flashmq/jwt_secret.key
```

### 5. FlashMQ Broker Configuration
Configure `/etc/flashmq/flashmq.conf`. Ensure `allow_anonymous false` is defined at the top of the file before any `listen` blocks to prevent unauthenticated bypasses.

Use **only the TLS listener with client verification**. A plain listener (port 1883) takes the username from the CONNECT packet instead of the certificate, so it bypasses mTLS and the JWT ↔ certificate binding, and sends tokens in clear.

``` plaintext
# Global Auth Rules (MUST BE PLACED BEFORE LISTENERS)
allow_anonymous false

# Listeners
listen {
    protocol  mqtt
    port      8883

    # Server Certificate and Private Key
    fullchain /etc/flashmq/certs/server.crt
    privkey   /etc/flashmq/certs/server.key

    # Client CA for mTLS
    client_verification_ca_file /etc/flashmq/certs/ca.crt

    # Force dual authentication (mTLS + JWT Password Check)
    client_verification_still_do_authn true
    allow_anonymous false
}

# Authentication Plugin
plugin /etc/flashmq/jwt_auth_plugin.so
plugin_opt_jwt_secret_file /etc/flashmq/jwt_secret.key
# Optional: token revocation (§7). Re-read every plugin_timer_period seconds when it changes.
plugin_opt_revocation_file /etc/flashmq/revocations.txt
plugin_timer_period 30

# Storage & System Options
storage_dir /var/lib/flashmq
max_qos_msg_pending_per_client 1000
log_level info
```

| Option | Default | Meaning |
|---|---|---|
| `plugin_opt_jwt_secret_file` | `/etc/flashmq/jwt_secret.key` | HS256 key file |
| `plugin_opt_revocation_file` | empty (revocation off) | `<username> <unix-time>` per line; `#` comments |
### Restart FlashMQ to apply changes:

``` bash
sudo systemctl restart flashmq
```

## 6. Verification & Testing
#### 1. Test Anonymous Rejection (Should Fail)
Connecting without credentials will be rejected at the handshake layer:

``` bash
mosquitto_sub -h localhost -p 1883 -t "test/#"
# Output: Error: Connection refused: Not authorized
```
#### 2. Test JWT Authentication (Should Succeed)
Generate a valid HS256 JWT containing a subject claim (e.g., `"sub": "device01"`):

``` bash
mosquitto_sub -h localhost -p 1883 -u "device01" -P "<YOUR_VALID_HS256_JWT>" -t "test/#"
```

#### 3. Revocation
``` bash
# Token for device01 issued before 1767225600 → refused; a connected device01 holding one is disconnected
echo "device01 1767225600" | sudo tee /etc/flashmq/revocations.txt.tmp >/dev/null && sudo mv /etc/flashmq/revocations.txt.tmp /etc/flashmq/revocations.txt
```

#### 4. Debug Logs
To observe realtime plugin auth checks or rejection reasons:

``` bash
sudo journalctl -u flashmq -f
```

## 7. Revocation list from the SousChef API
The API publishes `GET /api/v2/broker/revocations` (text/plain, `<serial> <unix-time>` per line) for an OAuth2 client with the `broker` scope. A systemd timer fetches it every minute into `plugin_opt_revocation_file`; on any error the previous file stays in place.

1. Create the OAuth2 client on the API (once per broker host and environment):
   ``` bash
   docker exec -u duke <api_container> bin/console league:oauth2-server:create-client "broker <host>" --grant-type=client_credentials --scope=broker
   ```
2. On the broker host, create `/etc/flashmq/revocations.env` (mode `600`, owner `root`):
   ``` bash
   API_URL=https://api.souscheftech.com
   API_VERSION=v2
   OAUTH_CLIENT_ID=<identifier>
   OAUTH_CLIENT_SECRET=<secret>
   REVOCATION_FILE=/etc/flashmq/revocations.txt
   ```
3. Install and start the timer:
   ``` bash
   sudo make install-revocations
   sudo systemctl enable --now flashmq-revocations.timer
   sudo systemctl start flashmq-revocations.service && cat /etc/flashmq/revocations.txt
   ```
4. Set `plugin_opt_revocation_file` and `plugin_timer_period` in `flashmq.conf` (§5) and restart FlashMQ.

**Effect:** when a device is re-provisioned or deprovisioned, its old JWTs stop working within about `60 s + plugin_timer_period`, and connected sessions using them are dropped. The device has to call `/login_check` again for a new token.

