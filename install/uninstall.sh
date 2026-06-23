#!/bin/bash
set -e

# Comprehensive Uninstaller for keychain-auth

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo ./uninstall.sh)"
  exit 1
fi

echo "Uninstalling keychain-auth..."

# 1. Stop and disable systemd service
if [ -f /etc/systemd/system/keychain-auth.service ]; then
  echo "Stopping and disabling systemd service..."
  systemctl stop keychain-auth.service || true
  systemctl disable keychain-auth.service || true
  rm -f /etc/systemd/system/keychain-auth.service
  systemctl daemon-reload
fi

# 2. Remove binary
if [ -f /usr/local/bin/keychain-auth ]; then
  echo "Removing binary..."
  rm -f /usr/local/bin/keychain-auth
fi

# 3. Clean up directories
echo "Cleaning up directories..."
rm -rf /run/keychain-auth
rm -rf /var/log/keychain-auth

# Note: We keep /etc/keychain-auth and /var/lib/keychain-auth to prevent data loss,
# but prompt the user or allow manual deletion.
echo "To prevent data loss, configuration files and database files have been kept at:"
echo "  - /etc/keychain-auth"
echo "  - /var/lib/keychain-auth"
echo "If you wish to delete them permanently, run:"
echo "  sudo rm -rf /etc/keychain-auth /var/lib/keychain-auth"

# 4. Delete system user/group if they are no longer needed
# (We don't delete them automatically as they might own other resources, but we print a message).
echo "To remove the system user and group, you can run:"
echo "  sudo userdel keychain-auth"
echo "  sudo groupdel keychain-auth"

echo "Uninstall complete!"
