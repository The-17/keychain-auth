# keychain-auth

`keychain-auth` is a low-level, high-security gatekeeper and intermediary proxy for operating system keychains (macOS Keychain, Linux Secret Service, Windows Credential Manager). 

It acts as a secure local broker for command-line tools and local applications. Instead of applications directly querying the keychain (which lacks process verification on Linux/Windows and suffers from prompt fatigue on macOS), applications query `keychain-auth` over a secure local channel. The daemon validates the caller's process identity using kernel-level peer credentials and executes fine-grained access control policies.

---

## Why Use It? (Security Enhancements)

Native keychains have major security gaps for local development and CLI utilities:
1.  **No Process Sandboxing on Linux/Windows:** Any script, curl piped to bash, or compromised package dependency (npm/pip/cargo) running under your user account can query D-Bus (`org.freedesktop.secrets`) or DPAPI (`CredRead`) to read all your credentials (AWS keys, OpenAI tokens, database passwords) without your knowledge.
2.  **macOS Prompt Fatigue:** Command-line tools lack application bundles and signatures, triggering constant macOS SecurityAgent permission dialogs. This leads to users clicking "Always Allow," exposing keys to any CLI invocation.

`keychain-auth` fixes these flaws:
*   **Kernel-Level Process Verification (Spoof-Proof):** The daemon retrieves the caller's actual PID using kernel-enforced connection options (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS, and named pipe verification on Windows). Self-reported PIDs are ignored.
*   **Cryptographic Attestation:** It resolves the executable path of the caller and computes its SHA-256 binary hash, checking it against a database of user-approved hashes. Active processes are protected from in-place tampering by the OS (`ETXTBSY`), making long-lived connections secure.
*   **Zero-Trust Access Control:** Registered binaries are restricted to explicit read and write service namespaces. A compromised read-only binary cannot overwrite or poison secrets. Destructive operations like `delete` explicitly require the target service to be in the binary's `allowed_write_services`.
*   **Unified Search & Query Interface:** Solves the lack of a cross-platform, clean search API. Applications can securely filter, list, and retrieve keys based on custom attributes.

### ⚠️ Security Contract: The `O_CLOEXEC` Requirement
If a parent process forks and executes an untrusted binary, the child inherits open file descriptors by default. The daemon cannot detect this. To prevent session hijacking across `exec()`, **clients must ensure the socket is opened with the `O_CLOEXEC` flag.** (The official client SDK handles this automatically).

---

## The Audit Log (Observability Pillar)
A core benefit of `keychain-auth` is granular, local observability. Every approved request, denied request, and search operation is written to a structured JSON audit log at `~/.local/share/keychain-auth/audit.log` (or `Library/Logs` on macOS).
Because searches return targets only, fetching secret values requires explicit `read` requests. This guarantees the audit log captures granular, per-secret access records rather than opaque "search granted" entries, severely limiting the blast-radius of compromised binaries.

---

## How It Works (Protocol Architecture)

```
┌──────────────────┐      Local Socket      ┌──────────────────┐     Native API     ┌──────────────┐
│  Client Application │ ◄──────────────────► │  keychain-auth   │ ◄────────────────►│  OS Keychain │
│  (e.g., CLI, app)   │   JSON-over-socket   │  (Security Daemon)│    (Read/Write)   │  (Storage)   │
└──────────────────┘                        └──────────────────┘                   └──────────────┘
```

### Connection-Bound Auth (No Session Tokens)
1.  **Connection Initiation:** The client connects over a local Unix domain socket (or a secure Windows Named Pipe).
2.  **Process Verification:** The daemon retrieves the caller's true PID from the kernel and verifies its binary path and SHA-256 hash.
3.  **Policy Binding:** The daemon re-reads `config.json` instantly and binds the binary's access policy to the active socket connection. 
4.  **Request Handling:** The client issues general `REQUEST` payloads (for read, write, delete, or search). The connection *is* the session.

---

## Flexible Batch Query Protocol

Clients communicate with the daemon using a generalized JSON protocol optimized for batch operations.

### 1. Request Structure (Batch & Prefix Support)
Clients can request, write, or delete multiple secrets in a single socket round-trip. Using the optional `"match": "prefix"` field, they can perform bulk operations (read/delete) matching target name prefixes.
```json
{
  "type": "REQUEST",
  "action": "read | write | delete | search",
  "service": "aws",
  "match": "exact | prefix",
  "targets": ["prod-api-key", "prod-db-password"],
  "values": ["optional-value-for-write-1", "optional-value-for-write-2"],
  "attributes": {
    "environment": "production"
  }
}
```
*Notes:*
* Write requests enforce strict array alignment: `len(targets)` must exactly match `len(values)`.
* `"match": "prefix"` is supported for `read`, `delete`, and `search` actions (not allowed for `write`).
* Prefix reads/deletes require that the binary has `can_search: true` in addition to target service permission.

### 2. Batch Atomicity & Pre-Flight Checks
Requests are **all-or-nothing**. The daemon evaluates all requested `targets` against the binary's access policy *before* executing any OS keychain operations. If a single target is denied, the entire batch is rejected.

### 3. Response Structure & Blast-Radius Limits
* **Standard search operations return key targets only, never plaintext secrets.** To fetch their secrets, subsequent explicit `read` requests are required to maintain a secure audit trail.
* **Prefix reads** (using `"match": "prefix"` with `"action": "read"`) retrieve both the target keys and their actual plaintext values for all matched keys in a single socket roundtrip.

```json
{
  "type": "RESPONSE",
  "status": "success | denied | error",
  "reason": "unregistered_binary | action_not_in_policy | service_not_allowed | malformed_request",
  "results": [
    {
      "target": "prod-api-key",
      "value": "secret-value-only-if-authorized-read",
      "attributes": {
        "environment": "production"
      }
    }
  ]
}
```


---

## Installation & CLI Commands

```bash
keychain-auth start               # Start the security daemon
keychain-auth list-pending        # List binaries currently waiting for authorization
keychain-auth approve <hash>      # Authorize a pending binary (defaults to 0 privileges)
keychain-auth register <path>     # Directly register a trusted binary path & hash
keychain-auth upgrade <path>      # Update the registered hash for an updated binary
```

### The "Pending Approval" Workflow
If a drive-by script or unregistered binary attempts to query the proxy, it is dropped gracefully with an `unregistered_binary` reason code. The daemon securely logs its command-line arguments, timestamps, and hash to `~/.config/keychain-auth/pending.json` for 24 hours. The user can inspect the queue using `list-pending` and authorize safe tools via `approve <hash>`.

### Installation Integration (for CLI creators)
If you are building a CLI tool that integrates with `keychain-auth`, add this to your tool's initialization/setup script:
```bash
keychain-auth register $(which your-cli-tool)
```
Since the setup script runs in the user's active shell, it writes the configuration directly to `~/.config/keychain-auth/config.json`. When your tool runs next, it will seamlessly connect.

---

## Platform Support & Backends

| Platform | IPC Mechanism | Verification Backend | Keychain Storage |
| :--- | :--- | :--- | :--- |
| **macOS** | Unix Domain Socket | `LOCAL_PEERPID` & Code Signatures | Apple Keychain Services |
| **Linux** | Unix Domain Socket | `SO_PEERCRED` & `/proc/<pid>/exe` | GNOME Keyring / KWallet (`dbus`) |
| **Windows**| Named Pipe | `GetNamedPipeClientProcessId` | Windows Credential Manager |

*Note: Headless Linux systems and WSL environments automatically fall back to a secure file-based storage backend at `~/.keychain-auth/keyring.json`.*

---

## Development

```bash
# Prerequisites: Go 1.24+
go mod tidy
go build -o keychain-auth ./cmd/keychain-auth
go test ./...
```

## License

MIT — see [LICENSE](LICENSE).
