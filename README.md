# FlashMQ JWT Authentication Plugin
An enterprise-grade C++ authentication plugin for [FlashMQ](https://www.flashmq.org/) that validates **HS256-signed JSON Web Tokens (JWTs)** passed in the MQTT password field.

## Features
- **HS256 JWT Verification:** Validates token signatures, expiration dates (`exp`), and structure using `jwt-cpp` and OpenSSL.
- **Username / Subject Matching:** Enforces that the MQTT username matches the JWT's `sub` claim.
- **Externalized Secret Key:** Loads the HMAC key from a separate secured file on startup instead of hardcoding credentials.
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
# Compile the plugin
make
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

``` plaintext
# Global Auth Rules (MUST BE PLACED BEFORE LISTENERS)
allow_anonymous false

# Listeners
listen {
protocol mqtt
port     1883
allow_anonymous false
}

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

# Storage & System Options
storage_dir /var/lib/flashmq
max_qos_msg_pending_per_client 1000
log_level debug
```
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

#### 3. Debug Logs
To observe realtime plugin auth checks or rejection reasons:

``` bash
sudo journalctl -u flashmq -f
```