# -----------------------------------------------------------------------------
# FlashMQ JWT Auth Plugin - Build System
# -----------------------------------------------------------------------------

CXX        ?= g++
CXXFLAGS   ?= -O2 -Wall -Wextra -std=c++17 -fPIC
LDFLAGS    ?= -shared
LIBS       ?= -lcrypto

# Source and Target definitions
SRC        := jwt_auth.cpp
TARGET     := jwt_auth_plugin.so

# Default installation paths
DESTDIR    ?= /etc/flashmq
KEY_FILE   := $(DESTDIR)/jwt_secret.key
CONF_FILE  := $(DESTDIR)/flashmq.conf

.PHONY: all clean install check-symbols help

# Default target
all: $(TARGET)

# Build the dynamic shared object (.so)
$(TARGET): $(SRC)
	@echo "==> Compiling FlashMQ JWT Auth Plugin..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< -o $@ $(LIBS)
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

# Clean compiled artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	rm -f $(TARGET)

# Display target help
help:
	@echo "Available targets:"
	@echo "  make              - Compile the plugin ($(TARGET))"
	@echo "  make check-symbols- Verify exported FlashMQ functions in .so"
	@echo "  make install      - Install plugin .so to $(DESTDIR)"
	@echo "  make clean        - Remove build artifacts"