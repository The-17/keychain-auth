# Getting Started with Keychain-Auth

`keychain-auth` is an identity-verified operating system keychain security daemon. It provides fine-grained, process-attested access to native keychains (Apple Keychain, Linux D-Bus Secret Service, Windows Credential Manager) and hardware-sealed fallback storage.

---

## Prerequisites

- **Go**: Version 1.24 or higher (for building from source).
- **Operating System**: Linux (systemd / D-Bus), macOS (10.15+), or Windows (10/11 / Windows Server).
- **Permissions**: Unprivileged user execution supported. System-wide daemon installation requires administrative privileges (`sudo` / Administrator).

---

## Step 1: Building and Installing

### Option A: System-Wide Installation (Recommended for Production)

The system installation builds the binary, creates a dedicated unprivileged system user (`keychain-auth`), configures standard socket permissions, and registers a systemd or launchd service:

```bash
# Clone repository
git clone https://github.com/The-17/keychain-auth.git
cd keychain-auth

# Build binary
go build -o keychain-auth ./cmd/keychain-auth

# Install system service (requires sudo)
sudo ./keychain-auth install
```

### Option B: User-Space Execution (Development)

To run the daemon in user mode without administrative elevation:

```bash
# Start daemon in background (user mode)
./keychain-auth start
```

---

## Step 2: Verifying Daemon Health

Check that the daemon is active and reporting health metrics:

```bash
# Human-readable status output
keychain-auth status
```

Example Output:
```text
Daemon:       running
Version:      3.2.0
Mode:         user
RequiresSudo: false
ConfigPath:   /home/user/.config/keychain-auth/config.json
SocketPath:   /home/user/.config/keychain-auth/agent.sock
```

For programmatic inspection, use `status --json`:

```bash
keychain-auth status --json
```

---

## Step 3: Registering Your First Client Binary

`keychain-auth` operates on a Zero-Trust policy. Unregistered binaries connecting over IPC are denied access and enqueued for user authorization.

To explicitly authorize a CLI tool or application executable (e.g., `agentsecrets`):

```bash
keychain-auth register $(which agentsecrets)
```

This calculates the SHA-256 hash of the binary and writes an access control entry to `config.json`.

---

## Step 4: Testing IPC Connectivity

You can verify that your registered binary can communicate with the daemon using a simple status query or check:

```bash
keychain-auth check $(which agentsecrets)
```

---

## Next Steps

- Explore the [Security Architecture](architecture.md) to understand kernel IPC attestation.
- Review [Supported Storage Backends](storage_backends.md) for TPM2 hardware sealing and WSL Host Interop.
- Inspect the [Command Line Interface Reference](cli_reference.md) for full command flags.
- See [Multi-Language Client SDKs](client_sdks.md) to build client integrations in Go, Python, or Node.js.
