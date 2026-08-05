# Platform Storage Backends & Sealed Fallbacks

`keychain-auth` abstracts underlying platform secret storage backends while guaranteeing consistent zero-trust access control across all major operating systems and deployment environments.

---

## Storage Architecture Overview

| Platform / Environment | Primary IPC Transport | Kernel Identity Attestation | Storage Backend Mechanism |
| :--- | :--- | :--- | :--- |
| **macOS** | Unix Domain Socket (`agent.sock`) | `LOCAL_PEERPID` | Apple Keychain Services |
| **Linux (Desktop)** | Unix Domain Socket (`agent.sock`) | `SO_PEERCRED` | Secret Service API (D-Bus / GNOME Keyring / KWallet) |
| **Windows (Native)** | Named Pipe (`keychain-auth`) | Named Pipe Client PID | Windows Credential Manager (DPAPI) |
| **WSL (Subsystem)** | Unix Domain Socket (`agent.sock`) | `SO_PEERCRED` | Windows Host Interop via `keychain-helper.exe` |
| **Headless Linux / TPM2** | Unix Domain Socket (`agent.sock`) | `SO_PEERCRED` | AES-256-GCM sealed to Hardware TPM 2.0 (`/dev/tpm0`) |

---

## 1. Native Operating System Keychains

### macOS: Apple Keychain Services
On macOS, `keychain-auth` interacts directly with Apple Keychain Services via native Cgo wrappers or Security framework APIs. Secrets are stored in namespaced SecKeychain items.

### Linux: D-Bus Secret Service API
On desktop Linux (Ubuntu, Fedora, Arch, Debian running GNOME/KDE), the daemon interfaces with the `org.freedesktop.secrets` D-Bus service to read and write items under namespaced collections.

### Windows: Windows Credential Manager (DPAPI)
On Windows, `keychain-auth` delegates storage to the Windows Credential Manager. Plaintext values are encrypted using the Windows Data Protection API (DPAPI) tied to the user's login SID.

---

## 2. Sealed Fallback Backends

Headless Linux servers, Docker containers, and Windows Subsystem for Linux (WSL) lack a running graphical D-Bus keyring daemon. In these environments, `keychain-auth` uses sealed fallback storage:

### WSL Host Interop (`keychain-helper.exe`)
- **The Problem**: Storing master keys inside a Linux virtual machine disk (WSL vdisk) exposes the key to any process running inside the VM.
- **The Solution**: Under WSL, `keychain-auth` never writes master encryption keys to the Linux virtual disk. Instead, the daemon delegates key persistence to the Windows Host's native Credential Manager via a companion Windows binary (`keychain-helper.exe`).
- **Data Flow**: When `keychain-auth` starts up inside WSL, it invokes `keychain-helper.exe get` over WSL interop to retrieve the master key dynamically into daemon memory. The key leaves zero footprint on the Linux VM disk.

```
┌────────────────────────────────┐                 ┌─────────────────────────────┐
│  WSL Linux (keychain-auth)     │ ── Interop ───► │  Windows Host               │
│  (Daemon in VM memory only)    │                 │  (keychain-helper.exe)      │
└────────────────────────────────┘                 └──────────────┬──────────────┘
                                                                  │
                                                                  ▼
                                                   ┌─────────────────────────────┐
                                                   │ Windows Credential Manager │
                                                   └─────────────────────────────┘
```

### TPM 2.0 Hardware Platform Sealing
- **The Architecture**: On headless Linux servers equipped with a Trusted Platform Module (TPM 2.0 at `/dev/tpm0`), `keychain-auth` seals the master 256-bit AES-256-GCM database key directly to hardware platform configuration registers (PCRs).
- **Security Guarantee**: The key can only be unsealed by the hardware TPM chip if system boot state measurements match authorized PCR policies. Physical disk extraction or cold-boot attacks cannot extract the master key.

---

## Next Steps

- Inspect [Security Architecture](architecture.md) for identity attestation details.
- Review [Configuration Reference](config_reference.md) for file paths.
