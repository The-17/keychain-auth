#!/bin/bash
set -e

# Comprehensive Installer for keychain-auth dedicated system user service

# 1. Check root
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo ./install.sh)"
  exit 1
fi

REAL_USER=${SUDO_USER:-$(whoami)}
if [ "$REAL_USER" = "root" ]; then
  echo "Warning: Running as root without SUDO_USER. Group assignments might need manual adjustments."
fi

echo "Setting up dedicated system user/group..."

# 2. Create keychain-auth system group and user if not exists
if ! getent group keychain-auth >/dev/null; then
  groupadd -r keychain-auth
  echo "Created group 'keychain-auth'."
fi

if ! getent passwd keychain-auth >/dev/null; then
  useradd -r -s /usr/sbin/nologin -d /var/lib/keychain-auth -g keychain-auth keychain-auth
  echo "Created system user 'keychain-auth'."
else
  # Ensure user has correct primary group
  usermod -g keychain-auth keychain-auth
fi

# 3. Create directories with strict permissions
echo "Creating system directories..."
mkdir -p /etc/keychain-auth
mkdir -p /var/lib/keychain-auth
mkdir -p /run/keychain-auth
mkdir -p /var/log/keychain-auth

# Set ownership
chown -R keychain-auth:keychain-auth /etc/keychain-auth
chown -R keychain-auth:keychain-auth /var/lib/keychain-auth
chown -R keychain-auth:keychain-auth /run/keychain-auth
chown -R keychain-auth:keychain-auth /var/log/keychain-auth

# Set permissions
chmod 700 /etc/keychain-auth
chmod 700 /var/lib/keychain-auth
chmod 755 /run/keychain-auth
chmod 700 /var/log/keychain-auth

# 4. Initialize config.json if not exists
CONFIG_FILE="/etc/keychain-auth/config.json"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Initializing empty config.json..."
  cat <<EOF > "$CONFIG_FILE"
{
  "registered_binaries": [],
  "protocol_version": "1",
  "trusted_signers": []
}
EOF
  chown keychain-auth:keychain-auth "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
fi

# 5. Copy binary to /usr/local/bin
if [ -f "./keychain-auth" ] && [ ! "./keychain-auth" -ef "/usr/local/bin/keychain-auth" ]; then
  echo "Installing binary to /usr/local/bin/keychain-auth..."
  install -m 755 ./keychain-auth /usr/local/bin/keychain-auth
elif [ -f "./bin/keychain-auth" ] && [ ! "./bin/keychain-auth" -ef "/usr/local/bin/keychain-auth" ]; then
  echo "Installing binary to /usr/local/bin/keychain-auth..."
  install -m 755 ./bin/keychain-auth /usr/local/bin/keychain-auth
fi

# 6. Setup systemd service if systemd is available
if [ -d /etc/systemd/system ]; then
  echo "Installing systemd service..."
  cat <<EOF > /etc/systemd/system/keychain-auth.service
[Unit]
Description=Keychain Auth Daemon
After=network.target

[Service]
Type=simple
User=keychain-auth
Group=keychain-auth
ExecStart=/usr/local/bin/keychain-auth start
Restart=always
RuntimeDirectory=keychain-auth
RuntimeDirectoryMode=0755
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable keychain-auth.service || true
  echo "Systemd service 'keychain-auth.service' installed and enabled."
fi

echo "Installation complete!"
