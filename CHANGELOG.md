# Changelog

All notable changes to the `keychain-auth` project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
