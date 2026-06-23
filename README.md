# keychain-auth v3

`keychain-auth` is a hardened, process-isolated **Zero-Trust Security Broker** for operating system keychains (macOS Keychain, Linux Secret Service/D-Bus, and Windows Credential Manager). 

It acts as a secure local gatekeeper for command-line tools and local applications. Instead of applications directly querying OS keychains (which lack process verification on Linux/Windows and suffer from prompt fatigue on macOS), applications query `keychain-auth` over a secure local IPC channel. The daemon validates the caller's process identity using kernel-level peer credentials, audits their cryptographic signatures, and enforces fine-grained access control policies.

---

## 📖 Project Documentation Manuals

The codebase contains detailed manuals and specifications. If you are integrating a CLI tool (like `agentsecrets`) or building a client SDK, refer to these guides:

*   📘 **[The Master Architecture & Client Integration Book](file:///Ubuntu/home/theapiartist/work/keychain-auth/docs/architecture_and_integration_guide.md)**: Deep dive into threat models, kernel transport layers, and step-by-step client implementations in Go, Python, and Node.js.
*   📜 **[JSON Wire Protocol Integration Specification](file:///Ubuntu/home/theapiartist/work/keychain-auth/docs/integration_spec.md)**: Canonical reference for wire protocol request/response schemas, match types, and blast-radius limits.
*   🔑 **[Developer Code Signing & CI/CD Tutorial](file:///Ubuntu/home/theapiartist/work/keychain-auth/docs/ci_cd_signing_tutorial.md)**: Tutorial on how to configure Ed25519 signing keys, sign executables, and integrate validation into automated release pipelines.
*   💻 **[CLI Commands & Administration Tutorial](file:///Ubuntu/home/theapiartist/work/keychain-auth/docs/tutorial.md)**: End-user manual detailing the daemon commands, approval queues, and policy configurations.

---

## 🛡️ Core Security Pillars (Why keychain-auth?)

Native operating system keychains were designed for a legacy desktop era and contain significant security vulnerabilities for modern developers, CLIs, and automated workflows. `keychain-auth` introduces a hardened security boundary:

### 1. Process Anti-Impersonation (Spoof-Proof Identity)
*   **The Problem:** On Linux and Windows, any script, curl piped to bash, or compromised dependency (npm/pip/cargo) running under your user account can query D-Bus (`org.freedesktop.secrets`) or DPAPI (`CredRead`) to read all your plaintext credentials without your knowledge or consent.
*   **The Solution:** `keychain-auth` verifies callers using kernel-enforced connection credentials. The daemon queries the IPC socket using OS-level transport structures (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS, and pipe client process validation on Windows). Self-reported PIDs are completely ignored, preventing spoofing.

### 2. Cryptographic Binary Attestation & Code Signing (v3)
*   **The Problem:** Developers update their CLI tools frequently. When a binary is updated, its SHA-256 hash changes. Requiring manual approval or elevated permissions on every minor update causes prompt fatigue, leading users to compromise security.
*   **The Solution:** Version 3 introduces native **Ed25519 Developer Code Signature Verification**. By appending a 64-byte cryptographic signature and magic bytes (`KCAS`) to the compiled binary, the daemon verifies that the binary was built by a trusted developer. If the signature matches a trusted public key registered in `config.json`, the daemon auto-registers the new binary hash and grants access silently—providing seamless upgrades with absolute integrity.

### 3. Sealed Fallback Key Storage (WSL Host Interop & TPM2)
*   **The Problem:** Headless servers, Docker containers, and Windows Subsystem for Linux (WSL) lack desktop keyring daemons. Fallbacks that write plaintext keys to files on the VM disk are highly vulnerable to extraction.
*   **The Solution:** When fallback file storage is required, `keychain-auth` uses state-of-the-art key persistence:
    *   **WSL Host Interop:** Under WSL, the master encryption key is never written to the Linux filesystem. Instead, `keychain-auth` retrieves the key dynamically from the Windows Host's native Credential Manager using a lightweight Windows helper (`keychain-helper.exe`), leaving zero footprint on the Linux disk.
    *   **TPM2 Hardware Sealing:** On generic headless Linux systems, if a TPM 2.0 module is present (`/dev/tpm0`), the master key is sealed directly to the hardware TPM platform configuration registers. The key cannot be extracted or copied by malware.

### 4. Zero-Trust Access Control & Namespace Isolation
*   Registered binaries are restricted to explicit read and write service namespaces (e.g. `openai` or `AgentSecrets`). 
*   Destructive operations like `delete` explicitly require the service to be in the binary's `allowed_write_services` policy.
*   Batch queries are strictly atomic: if a client requests multiple keys and a single key fails policy verification, the entire batch is rejected.

---

## ⚡ Quick Start

### 1. System Installation (Linux/WSL)
On Linux systems, install the sandboxed daemon using the Go-native install command (requires `sudo` to configure the unprivileged `keychain-auth` system user and register the systemd service):
```bash
sudo keychain-auth install
```

### 2. Basic Commands
```bash
keychain-auth start               # Start the security daemon in the background
keychain-auth list-pending        # List binaries waiting for user authorization
keychain-auth approve <hash>      # Approve a pending binary hash from the queue
keychain-auth register <path>     # Directly register and configure a trusted binary
keychain-auth upgrade <path>      # Update the registered hash for a compiled update
```

### 3. The "Pending Approval" Workflow
If an unregistered binary attempts to query the socket:
1.  The daemon denies the request with an `unregistered_binary_pending_approval` reason code and drops the socket connection.
2.  It logs the caller's path, CLI arguments, and SHA-256 hash to a secure local queue (`pending.json`).
3.  The user runs `keychain-auth list-pending` to inspect the queue, and grants access using `keychain-auth approve <hash>`.

---

## 🔌 JSON Wire Protocol Specification

Applications communicate with the `keychain-auth` daemon by exchange of newline-delimited JSON messages over the local IPC channel.

### IPC Transport Path
* **Linux/macOS (Unix Domain Socket)**: `/run/keychain-auth/agent.sock` (falls back to `~/.config/keychain-auth/agent.sock` if run in user space).
* **Windows (Named Pipe)**: `\\.\pipe\keychain-auth`.

### Request Schema
Requests are JSON objects containing the following fields:

```json
{
  "type": "REQUEST",
  "action": "read" | "write" | "delete" | "search" | "check",
  "service": "ServiceNamespace",
  "match": "exact" | "prefix",
  "targets": ["key1", "key2"],
  "values": ["value1", "value2"]
}
```

* `type` (string, required): Must be `"REQUEST"`.
* `action` (string, required): 
  * `read`: Decrypts and retrieves the values for the specified `targets`.
  * `write`: Encrypts and writes the corresponding `values` for the specified `targets`.
  * `delete`: Removes the specified `targets` from the keychain.
  * `search`: Lists all registered key names under the `service` namespace.
  * `check`: Checks if the caller binary (or the binary passed as the target) is registered and authorized.
* `service` (string, required): The service/app namespace isolating the secrets (e.g. `AgentSecrets`).
* `match` (string, optional): `"exact"` (default) or `"prefix"`. If `"prefix"`, matches target keys starting with the specified string. (Not allowed for `write`).
* `targets` (array of strings, optional): The key/account names being acted on. Required for `read`, `write`, `delete`, and `check`.
* `values` (array of strings, optional): The plaintext values to store. Required and must align 1-to-1 in length with `targets` for `write`.

### Response Schema
Responses are JSON objects containing the following fields:

```json
{
  "type": "RESPONSE",
  "status": "success" | "denied" | "error",
  "reason": "ReasonCode",
  "results": [
    {
      "target": "key1",
      "value": "plaintext_value"
    }
  ]
}
```

* `type` (string): Always `"RESPONSE"`.
* `status` (string): `"success"`, `"denied"`, or `"error"`.
* `reason` (string, optional): Present if `status` is `"denied"` or `"error"`. Granular codes include:
  * `unregistered_binary_pending_approval`: The calling binary is not registered.
  * `service_not_allowed`: The binary does not have access permissions for the requested service.
  * `action_not_in_policy`: The binary's policy denies the specific action (e.g. attempting to `write` when only `read` is authorized).
  * `malformed_request`: Invalid JSON envelope, field mismatch, or illegal match type.
  * `internal_error`: OS-level or hardware-level keychain operation failed.
* `results` (array, optional): Present on successful `read` or `search` operations. For `search`, the `value` field is omitted to prevent leaking secrets.

---

## 📋 Platform Support

| Platform | IPC Transport | Process Verification | Entitlement Keychain Storage |
| :--- | :--- | :--- | :--- |
| **macOS** | Unix Domain Socket | `LOCAL_PEERPID` & Code Signatures | Apple Keychain Services |
| **Linux** | Unix Domain Socket | `SO_PEERCRED` & `/proc/<pid>/exe` | GNOME Keyring / KWallet (`dbus`) |
| **Windows**| Named Pipe | Named Pipe Client PID | Windows Credential Manager |

*Note: Headless systems, WSL, and legacy environments automatically fall back to an AES-256-GCM encrypted database file sealed via TPM2 or Windows Host Interop.*

---

## 🛠️ Development

```bash
# Prerequisites: Go 1.24+
go mod tidy
go build -o keychain-auth ./cmd/keychain-auth
go test ./...
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).
