# -----------------------------------------------------------------------------
# FlashMQ JWT Auth Plugin - Build System
# -----------------------------------------------------------------------------

CXX        ?= g++
CXXFLAGS   ?= -O2 -Wall -Wextra -std=c++17 -fPIC
CPPFLAGS   ?= -I. -I/usr/local/include
LDFLAGS    ?= -shared
LIBS       ?= -lcrypto

# Source and Target definitions
SRC        := jwt_auth.cpp
TARGET     := jwt_auth_plugin.so

# Default installation paths
DESTDIR    ?= /etc/flashmq
KEY_FILE   := $(DESTDIR)/jwt_secret.key
CONF_FILE  := $(DESTDIR)/flashmq.conf

.PHONY: all clean install install-revocations check-symbols test help

# Default target
all: $(TARGET)

# Build the dynamic shared object (.so)
$(TARGET): $(SRC)
	@echo "==> Compiling FlashMQ JWT Auth Plugin..."
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LIBS)
	@echo "==> Build successful: $@"

# Check exported symbols to ensure C++ name mangling didn't hide required FlashMQ exports
check-symbols: $(TARGET)
	@echo "==> Verifying FlashMQ exported symbols in $(TARGET)..."
	@nm -D $(TARGET) | grep -q "flashmq_plugin_version" && \
		echo "[OK] Symbol 'flashmq_plugin_version' found." || \
		(echo "[ERROR] 'flashmq_plugin_version' symbol missing!" && exit 1)

# Install built plugin to destination directory
install: $(TARGET)
	@echo "==> Installing $(TARGET) to $(DESTDIR)..."
	install -d $(DESTDIR)
	install -m 755 $(TARGET) $(DESTDIR)/$(TARGET)
	@echo "==> Installed successfully."

# Unit tests: compiles the plugin source with stubbed FlashMQ functions
test: tests/test_jwt_auth.cpp $(SRC)
	@echo "==> Running unit tests..."
	$(CXX) $(CPPFLAGS) -O0 -g -Wall -Wextra -std=c++17 $< -o tests/test_jwt_auth $(LIBS)
	./tests/test_jwt_auth

# Install the revocation fetcher and its systemd timer (README §7)
install-revocations:
	install -m 755 contrib/fetch-revocations.sh /usr/local/bin/flashmq-fetch-revocations
	install -m 644 contrib/flashmq-revocations.service /etc/systemd/system/flashmq-revocations.service
	install -m 644 contrib/flashmq-revocations.timer /etc/systemd/system/flashmq-revocations.timer
	systemctl daemon-reload
	@echo "==> Create /etc/flashmq/revocations.env, then: systemctl enable --now flashmq-revocations.timer"

# Clean compiled artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	rm -f $(TARGET) tests/test_jwt_auth

# Display target help
help:
	@echo "Available targets:"
	@echo "  make              - Compile the plugin ($(TARGET))"
	@echo "  make check-symbols- Verify exported FlashMQ functions in .so"
	@echo "  make install      - Install plugin .so to $(DESTDIR)"
	@echo "  make test         - Build and run the unit tests"
	@echo "  make install-revocations - Install the revocation fetcher + systemd timer"
	@echo "  make clean        - Remove build artifacts"