# Changelog

All notable changes to the `keychain-auth` project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.0.0] - 2026-11-03

This major release moves authorization into the daemon and hardens the trust boundary between clients and the trust store. Authorizing a binary is now an administrative action gated on the caller's OS identity, the daemon owns and writes its own trust store, and the dormant signed-upgrade path is hardened against four bypasses.

### Added
*   **Daemon-mediated `authorize` action**: The daemon writes the trust store itself, as its own unprivileged user, instead of the client running `sudo keychain-auth authorize` and writing a root-owned file. New protocol action `authorize`; the daemon re-hashes the target and grants read, write, and search for the requested service.
*   **`admin_required` reason code**: Returned when an administrative action is requested by a peer without administrator rights. The CLI turns it into a clear "run with `sudo`" message.
*   **Superseded-hash ledger**: Hashes replaced by a signed upgrade are recorded and refused if replayed, as a rollback defence.
*   **Daemon started at install**: `install.sh` now starts the systemd unit after enabling it, so the daemon is immediately available to mediate authorization.

### Changed
*   **Authorization gated on OS identity**: The `authorize` action is no longer sufficient merely because the caller is the `keychain-auth` binary, since any process can execute that binary. On a system store the peer must be root (`sudo keychain-auth authorize`); on a user-mode store it must be the daemon's own user. Unknown credentials fail closed.
*   **Trust store owned by the daemon**: `/etc/keychain-auth/config.json` is `0600 keychain-auth:keychain-auth`, not `0644 root`. The daemon can read and write it, and it is not world-readable.
*   **`register` resets privileges on a hash change**: Re-registering a path with a new hash resets its service grants to Zero Trust instead of inheriting the old binary's access.
*   **Signed-upgrade path hardened**: A valid signature may only replace the hash of an already-registered path (upgrade-only), is verified over the same bytes that were hashed (no TOCTOU), must match the policy's service, and cannot replay a superseded hash.
*   **Direct-write fallbacks keep the store daemon-owned**: `authorize`, `approve`, and `register` restore `keychain-auth:keychain-auth` `0600` after a privileged direct write.

### Fixed
*   **Self-authorization loophole**: A process running as the user could previously have used the daemon-mediated `authorize` path to authorize its own binary. Closed by the OS-identity gate.
*   **Privilege inheritance on re-registration**: `register` no longer carries old service grants across a hash change.
*   **Four signed-upgrade bypasses**: path binding, new-path grants, hash/signature TOCTOU, and rollback.
*   **Test-suite data race**: The handler mock keychain is now thread-safe.

### Security notes
*   **Re-authorization after an upgrade now requires `sudo`.** Authorizing a binary grants it service access, so it is an administrative action. This is a deliberate trade for closing the self-authorization loophole.
*   **Passwordless upgrades are not included.** Release signing (a `TrustedSigner`) was evaluated and deliberately not added: the signing key would become a global single point of compromise. The dormant signature path was hardened instead.

---

## [3.1.0] - 2026-06-23

This release introduces automated Windows helper binary embedding/extraction for zero-manual WSL setup, protocol support for unprivileged client-binary authorization status checks, and more robust IPC permissions.

### Added
*   **WSL Host Interop Auto-Extraction**: Automatically cross-compiles, embeds, and extracts the Windows `keychain-helper.exe` utility to the Windows host profile directory (`C:\Users\<user>\.config\keychain-auth\keychain-helper.exe`) on daemon demand, making WSL keychain integrations completely zero-setup.
*   **IPC Check Action (`check`)**: Added support for an unprivileged `check` action in the JSON wire protocol to allow client CLIs to query connection and registration authorization status directly.
*   **CLI Status Command (`keychain-auth status`)**: Implemented a daemon status query command returning JSON or plain text reporting running mode, socket path, mode, and sudo requirements.

### Changed
*   **Socket Directory & Socket Permissions**: Relaxed socket directory permissions to `0755` and socket file permissions to `0666` to facilitate seamless daemon access for standard WSL user processes.
*   **Gitignore Tracking**: Updated `.gitignore` to track `internal/keychain/keychain-helper.exe` while preserving overall `.exe` exclusions.

---

## [3.0.0] - 2026-06-21

This major release transforms the `keychain-auth` daemon into a hardened, zero-trust **Process Anti-Impersonation Boundary** with developer code signature verification, hardware-sealed fallbacks, and Go-native sandboxed installation.

### Added
*   **Ed25519 Developer Code Signature Verification**: Introduces Go-native asymmetric signature validation computed over client binaries (`agentsecrets`). Allows client updates (hash changes) to be silently auto-approved and registered without manual user/sudo prompt fatigue.
*   **Process Anti-Impersonation**: Enforces kernel-level connection verification options (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS, and pipe properties on Windows) to obtain the caller's true PID and binary path. Ignores all client-provided PIDs and paths.
*   **WSL Host Interop Fallback Key Storage**: Under WSL, the master encryption key is persisted dynamically in the Windows Host's Credential Manager via the `keychain-helper.exe` utility, leaving a zero-disk footprint on the WSL Linux VM.
*   **TPM2 hardware key sealing**: Added Linux TPM2 sealing support (`/dev/tpm0` using `tpm2_create` -> `tpm2_load` -> `tpm2_unseal`) to lock the fallback keyring master key directly to system hardware registers.
*   **Symmetric Keyring Payload Encryption**: Keyring credential payloads are now fully encrypted with AES-256-GCM before writing to the native OS keyring (GNOME Keyring/D-Bus, DPAPI, macOS Keychain).
*   **Go-Native CLI Installation Command**: Added a native `keychain-auth install` CLI command which embeds `install.sh` using `//go:embed` and executes it directly under root (`sudo`) to establish the dedicated system user (`keychain-auth`), the socket group (`agentgroup`), and systemd unit configurations.
*   **Structured Technical Documentation**: Added detailed guides inside the `docs/` folder:
    *   📘 `docs/architecture_and_integration_guide.md` (System manual)
    *   📜 `docs/integration_spec.md` (JSON wire protocol specification)
    *   🔑 `docs/ci_cd_signing_tutorial.md` (Code signing release instructions)

### Changed
*   **Connection-Bound Authentication**: Replaced old token-based handshakes with connection-bound kernel-authenticated sessions. Closing the socket/pipe instantly terminates the authorized session.
*   **Hardened Sandbox Socket Location**: Default Linux system service socket changed to `/run/keychain-auth/agent.sock` with `0660` permissions owned by `keychain-auth:agentgroup`.
*   **Muted Successful Setup Outputs**: Silenced stdout/stderr logs on successful installation/registration command calls to prevent terminal noise. Full logs are now returned only on execution failure.

---

## [2.1.0] - 2026-05-15

### Added
*   JSON Wire Protocol support for batch operations (prefix reads, bulk writes, and bulk deletes).
*   Atomic batch operations validation (pre-flight checks ensure all-or-nothing execution).

### Changed
*   Structured audit logging output changed to JSON Lines format under `audit.log`.

---

## [2.0.0] - 2026-03-10

### Added
*   Linux GNOME Keyring/Secret Service D-Bus integration.
*   Windows Credential Manager integration.
*   The "Pending Approval" queue workflow for unauthorized drive-by binary connections.
