# Integration Specification: keychain-auth Daemon

This document is the canonical reference for developers building clients or applications that interface with the `keychain-auth` security daemon.

---

## 1. Protocol Architecture Overview

`keychain-auth` implements a high-performance, low-latency, and zero-trust security boundary. It mediates all reads, writes, searches, and deletes targeting namespaced OS keychain storage. 

Instead of accessing native keychains directly (which lacks fine-grained application-level sandboxing on Linux/Windows and triggers prompt fatigue dialogs on macOS), clients delegate requests to `keychain-auth` over a secure local transport channel.

```
┌──────────────────────────┐                   ┌──────────────────┐
│   Your CLI Application   │ ◄───────────────► │  keychain-auth   │
│ (e.g. AWS, AgentSecrets) │    Local IPC      │     (Daemon)     │
└──────────────────────────┘                   └──────────────────┘
```

### IPC Channel Details
*   **macOS / Linux:** Unix domain socket at `/var/run/keychain-auth/agent.sock` (Default permissions `0600`).
*   **Windows:** Named pipe at `\\.\pipe\keychain-auth`.
*   **Format:** Newline-delimited JSON. Every message is sent as a single JSON object terminated by a newline (`\n`).

### Connection-Bound Authentication (Zero Session Tokens)
`keychain-auth` does not use API keys or session tokens. **The connection itself is the authenticated session.**
1.  **Connection:** The client establishes a connection to the socket/named pipe.
2.  **Kernel Verification:** The daemon immediately retrieves the caller's actual process ID (PID) from the kernel via socket options (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS, and pipe properties on Windows).
3.  **Identity Attestation:** The daemon looks up the caller's true binary path, computes its SHA-256 hash, and verifies it against the approved `/config.json` database.
4.  **Policy Binding:** The daemon binds the corresponding fine-grained policy configuration to the active connection for the remainder of its lifetime.
5.  **Pipelining:** Clients can send multiple requests sequentially on the same active connection. Pipelining is sequential (one message out, one message back).

---

## 2. Protocol Schemas & Messages

All messages are JSON objects. Every request from a client is a single line, and every response from the daemon is a single line.

### 2.1 The Request Envelope
Clients initiate operations by sending a generalized `REQUEST` envelope.

```json
{
  "type": "REQUEST",
  "action": "read | write | delete | search",
  "service": "aws",
  "match": "exact | prefix",
  "targets": ["prod-api-key", "prod-db-password"],
  "values": ["value-for-write-1", "value-for-write-2"],
  "attributes": {
    "environment": "production"
  }
}
```

#### Fields Description:
| Field | Type | Description | Mandatory |
| :--- | :--- | :--- | :--- |
| `type` | String | Must be exactly `"REQUEST"`. | Yes |
| `action` | String | Must be `"read"`, `"write"`, `"delete"`, or `"search"`. | Yes |
| `service` | String | The service namespace (e.g. `aws`, `openai`, `github`). | Yes |
| `match` | String | Interpret targets: `"exact"` (default) or `"prefix"`. If `"prefix"`, targets are treated as prefix filters. (Not allowed for `"write"`). | Optional |
| `targets` | Array of Strings | The key identifiers/accounts being acted upon. For `search` action, this is optional; if specified, they act as prefix filters. | Yes (except for `search`) |
| `values` | Array of Strings | Values corresponding to `targets`. | Only for `write` action |
| `attributes` | Object | Arbitrary key-value metadata filters (e.g., environment, tags). | Optional |


> [!IMPORTANT]
> **Strict Array Alignment (Writes):** If `action` is `"write"`, the length of the `targets` array **must exactly match** the length of the `values` array. If they do not, the daemon rejects the entire payload with a `malformed_request` reason.

---

### 2.2 The Response Envelope
The daemon responds to all requests with a `RESPONSE` envelope.

```json
{
  "type": "RESPONSE",
  "status": "success | denied | error",
  "reason": "service_not_allowed | action_not_in_policy | malformed_request | internal_error",
  "results": [
    {
      "target": "prod-api-key",
      "value": "plaintext-secret-only-if-authorized-read",
      "attributes": {
        "environment": "production"
      }
    }
  ]
}
```

#### Fields Description:
| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | String | Always `"RESPONSE"`. |
| `status` | String | `"success"`, `"denied"`, or `"error"`. |
| `reason` | String | Set only when status is `"denied"` or `"error"`. |
| `results` | Array of Objects | Key-value objects representing operation results. |

---

## 3. Action Scoping & Security Rules

`keychain-auth` enforces strict, all-or-nothing security checks before executing any backend operations.

### 3.1 Pre-Flight Batch Atomicity
All requested `targets` are checked against the binary's policy **before any keychain operation is initiated**. If a client requests 5 targets and even one of them is unauthorized, the **entire batch is rejected**, and no reads or writes occur.

### 3.2 Permission Scopes
*   `read`: Requires the requested `service` namespace to be listed in the binary's `allowed_read_services` list. 
    *   *Note:* If `match` is set to `"prefix"`, the binary **must also** have `can_search: true` since the daemon needs to enumerate keys to resolve prefixes.
*   `search`: Requires `can_search: true` and the `service` to be listed in `allowed_read_services`.
*   `write`: Requires the requested `service` namespace to be listed in `allowed_write_services`.
*   `delete`: Requires the requested `service` namespace to be listed in `allowed_write_services` (treated as a write-level privilege).
    *   *Note:* If `match` is set to `"prefix"`, the binary **must also** have `can_search: true` since the daemon needs to enumerate keys to resolve prefixes.

### 3.3 Search Blast-Radius & Prefix Filtering

*   **Search Returns Targets Only:** To prevent bulk harvesting of credentials, **search operations return key targets and attributes only — never plaintext values.**
*   **Daemon-Side Search Prefix Filtering:** To avoid transferring large sets of keys across the socket and executing client-side filtering, clients can specify one or more prefixes in the `targets` array of a `search` request. The daemon will perform high-performance, in-memory filtering and return only the matching targets:
    ```json
    {
      "type": "REQUEST",
      "action": "search",
      "service": "AgentSecrets",
      "targets": ["proj_123:production:"]
    }
    ```
    *Response:* Returns a list of target keys only (the `value` field is omitted).
*   **Subsequent Explicit Reads:** To fetch the actual secrets, the client can issue subsequent explicit `read` requests targeting those specific matched keys, generating individual granular entries in the daemon's local forensic audit log.

### 3.4 Single-Roundtrip Bulk Operations (Prefix Matching)
While the default pattern separates discovery (`search`) from retrieval (`read`) to minimize the blast radius of credentials, `keychain-auth` supports optimized, single-roundtrip prefix-based bulk operations using the optional `"match": "prefix"` field.

#### 1. Single-Roundtrip Bulk Retrieval (Prefix Read)
To retrieve both the target keys and their actual plaintext values for all keys matching a prefix in a single socket roundtrip:
```json
{
  "type": "REQUEST",
  "action": "read",
  "service": "AgentSecrets",
  "match": "prefix",
  "targets": ["proj_123:production:"]
}
```
*   **Requirements:** The calling binary must have the service in `allowed_read_services` **and** have `can_search: true` policy enabled.
*   **Response:** Returns an array of results with both `target` and `value` populated for every matched key.

#### 2. Single-Roundtrip Bulk Deletion (Prefix Delete)
To delete all keys matching a prefix in a single socket roundtrip:
```json
{
  "type": "REQUEST",
  "action": "delete",
  "service": "AgentSecrets",
  "match": "prefix",
  "targets": ["proj_123:production:"]
}
```
*   **Requirements:** The calling binary must have the service in `allowed_write_services` **and** have `can_search: true` policy enabled.
*   **Response:** Returns standard success on completion. All matched keys are removed from the keychain.



---

## 4. Connection & Error Scenarios

When interfacing with `keychain-auth`, clients must handle specific error cases gracefully:

### 4.1 Rejections & Socket Drops
If an unregistered binary attempts to query the socket:
1.  The daemon logs the verification failure and captures details (command-line arguments, timestamps, and path) in `pending.json` for manual user approval.
2.  The daemon sends a graceful, final JSON response before closing the connection:
    ```json
    {
      "type": "RESPONSE",
      "status": "denied",
      "reason": "unregistered_binary_pending_approval"
    }
    ```
3.  The socket connection is immediately closed by the daemon.

### 4.2 Reason Codes Reference
*   `unregistered_binary_pending_approval`: The binary has not been registered or approved yet.
*   `service_not_allowed`: The service namespace requested is not in the allowed lists.
*   `action_not_in_policy`: The binary attempted a `search` but does not have search permissions.
*   `malformed_request`: Invalid JSON syntax, unrecognized properties, or mismatch in array lengths.
*   `internal_error`: A low-level failure querying the OS keychain.

---

## 5. Implementation Best Practices (The Client Contract)

When writing client integrations, adhere to these critical security practices:

### 5.1 Enforce `O_CLOEXEC` on Unix Sockets
If a parent process forks and executes an untrusted command, the child process inherits open file descriptors by default. To prevent untrusted child binaries from hijacking active authenticated socket sessions:
*   **Always open the Unix socket with the `O_CLOEXEC` flag (or `SOCK_CLOEXEC`).**
*   This ensures that the OS automatically closes the active file descriptor upon any call to `exec()`.

### 5.2 Graceful Fallbacks & Setup Integration
*   **Setup Provisioning:** At client installation/setup, invoke `keychain-auth register $(which your-cli-tool)` to register the binary's path and SHA-256 hash.
*   **Missing Daemon:** If the socket connection fails (e.g., the daemon is not running), client CLIs should surface a clear, helpful error instruction:
    ```
    keychain-auth daemon is not running.
    Please start it manually with: keychain-auth start
    ```
