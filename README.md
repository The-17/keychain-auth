# keychain-auth

An identity-verified, zero-trust security daemon that mediates access to native operating system keychains and hardware-sealed secret stores. Designed for CLI tools, developer utilities, automated pipelines, and AI agents.

---

## Overview

Modern developer workflows and CLI utilities routinely handle sensitive credentials (API tokens, private keys, database passwords). Accessing native OS keychains directly poses significant security challenges:

- **Linux & Windows Lack Process Isolation**: On Linux (Secret Service API over D-Bus) and Windows (Credential Manager / DPAPI), any process running under the current user account can query and extract all stored credentials without privilege elevation or user confirmation.
- **macOS Prompt Fatigue**: Prompting users for Keychain access on every CLI command or binary compilation leads to prompt fatigue, encouraging users to grant overly broad access permissions.
- **Headless & Container Constraints**: Environments such as WSL, Docker containers, and headless Linux servers often lack a graphical keyring daemon, forcing tools to store plaintext secrets on disk.

`keychain-auth` solves these issues by acting as a hardened local security daemon. Applications request keychain operations over a local IPC channel. The daemon verifies the caller process identity using kernel-enforced socket metadata, matches the process executable against an authorized binary hash policy, and enforces strict service namespace sandboxing before performing any OS keychain operation.

---

## Architecture & Threat Model

```
┌──────────────────────────┐                  ┌──────────────────────────────┐                  ┌─────────────────────────────┐
│  Client CLI / AI Agent   │                  │     keychain-auth Daemon     │                  │    Native OS Secret Store   │
│  (e.g., agentsecrets)    │                  │  (Identity & Policy Engine)  │                  │  (Keychain / D-Bus / DPAPI) │
└────────────┬─────────────┘                  └──────────────┬───────────────┘                  └──────────────┬──────────────┘
             │                                               │                                                 │
             │  1. Connect via Local IPC                     │                                                 │
             ├──────────────────────────────────────────────►│                                                 │
             │                                               │  2. Kernel Peer Identity Attestation            │
             │                                               │     (SO_PEERCRED / LOCAL_PEERPID)               │
             │                                               ├────────────────────────┐                        │
             │                                               │                        │                        │
             │                                               │  3. Verify Executable  │                        │
             │                                               │     Path & SHA-256 Hash │                        │
             │                                               │◄───────────────────────┘                        │
             │                                               │                                                 │
             │                                               │  4. Enforce Namespace & Policy                  │
             │  5. Perform Keychain Read/Write               │     (allowed_read_services / allowed_write)     │
             │◄──────────────────────────────────────────────┼────────────────────────────────────────────────►│
             │                                               │                                                 │
```

### 1. Kernel-Enforced Process Identity
`keychain-auth` does not rely on self-reported client credentials, process IDs, or environment variables. Identity verification occurs entirely at the OS kernel transport layer:

- **Linux**: Interrogates the Unix domain socket using `SO_PEERCRED` to extract the authenticated caller PID and UID.
- **macOS**: Queries socket credentials using `LOCAL_PEERPID` via `getsockopt`.
- **Windows**: Evaluates the client process ID directly from the Windows Named Pipe server API.

The daemon resolves the executable path directly from `/proc/<pid>/exe` (or platform equivalent) and computes its SHA-256 binary hash.

### 2. Zero-Trust Namespace & Policy Isolation
Every registered binary is granted an explicit access control policy in `/etc/keychain-auth/config.json` (or `~/.config/keychain-auth/config.json`):

- **Service Namespace Boundaries**: A binary authorized for `allowed_read_services: ["agentsecrets"]` cannot access credentials under `openai`, `aws`, or any other service.
- **Action Scopes**: Binaries are restricted to explicit actions (`read`, `write`, `delete`, `search`, `check`). Destructive actions (`delete`) require explicit entry in `allowed_write_services`.
- **Atomic Batch Evaluation**: If a request contains multiple targets and any single target fails policy validation, the entire request is rejected atomically.

### 3. Pending Authorization Queue
When an unregistered binary attempts to query the daemon:
1. Access is immediately denied with reason code `unregistered_binary_pending_approval`.
2. The caller executable path, CLI arguments, and SHA-256 hash are recorded in a local pending queue (`pending.json`).
3. An administrator inspects the queue using `keychain-auth list-pending` and approves the binary using `keychain-auth approve <hash>`.

---

## Supported Storage Backends

| Platform | IPC Transport | Kernel Identity Verification | Storage Backend |
| :--- | :--- | :--- | :--- |
| **macOS** | Unix Domain Socket (`/run/keychain-auth/agent.sock`) | `LOCAL_PEERPID` | Apple Keychain Services |
| **Linux** | Unix Domain Socket (`/run/keychain-auth/agent.sock`) | `SO_PEERCRED` | Secret Service API (D-Bus / GNOME Keyring / KWallet) |
| **Windows** | Named Pipe (`\\.\pipe\keychain-auth`) | Named Pipe Client Process PID | Windows Credential Manager (DPAPI) |
| **WSL** | Unix Domain Socket | `SO_PEERCRED` | Windows Host Interop via `keychain-helper.exe` |
| **Headless / TPM2** | Unix Domain Socket | `SO_PEERCRED` | AES-256-GCM sealed to TPM2 Hardware (`/dev/tpm0`) |

> [!NOTE]
> On WSL and headless Linux nodes without a D-Bus secret service, `keychain-auth` uses sealed fallback storage. Under WSL, master keys are securely delegated to the Windows Host Credential Manager via `keychain-helper.exe` without writing unencrypted key material to the WSL Linux filesystem. On TPM2-equipped Linux nodes, keys are sealed directly to hardware platform registers.

---

## Installation & Service Setup

### System-Wide Installation (Linux / macOS)

`keychain-auth` includes a native installer that configures system services and unprivileged user sandboxing:

```bash
# Build binary
go build -o keychain-auth ./cmd/keychain-auth

# Run system installation (configures system service and unprivileged daemon user)
sudo ./keychain-auth install
```

### User-Space Execution

For development or environments without root privileges, start the daemon in user mode:

```bash
keychain-auth start
```

---

## Command Line Interface Reference

```bash
keychain-auth start              # Launch the security daemon process
keychain-auth status             # Display human-readable daemon health and version
keychain-auth status --json      # Return machine-readable JSON status (includes daemon version)
keychain-auth list-pending       # List binaries awaiting user authorization
keychain-auth approve <hash>     # Approve a pending binary hash from the queue
keychain-auth register <path>    # Register a trusted binary and assign service scopes
keychain-auth upgrade <path>     # Update the registered hash for a compiled binary update
keychain-auth check <path>       # Verify whether a binary is registered and authorized
```

### Daemon Health Inspection (v3.2.0)

Integrating tools can query daemon health and version metadata programmatically using `status --json`:

```json
{
  "daemon_running": true,
  "version": "3.2.0",
  "mode": "user",
  "config_path": "/home/user/.config/keychain-auth/config.json",
  "socket_path": "/home/user/.config/keychain-auth/agent.sock",
  "requires_sudo": false
}
```

---

## JSON Wire Protocol Specification

Applications communicate with the daemon by exchanging newline-delimited JSON messages over the local IPC channel.

### IPC Transport Channels
- **Unix Domain Socket (Linux / macOS)**: `/run/keychain-auth/agent.sock` (falls back to `~/.config/keychain-auth/agent.sock`).
- **Named Pipe (Windows)**: `\\.\pipe\keychain-auth`.

### Request Envelope

```json
{
  "type": "REQUEST",
  "action": "read",
  "service": "agentsecrets",
  "match": "exact",
  "targets": ["api_key"],
  "values": []
}
```

#### Request Fields
- `type` (string, required): Must be `"REQUEST"`.
- `action` (string, required): One of `"read"`, `"write"`, `"delete"`, `"search"`, or `"check"`.
- `service` (string, required): The target service namespace (e.g., `"agentsecrets"`).
- `match` (string, optional): `"exact"` (default) or `"prefix"`.
- `targets` (array of strings, optional): Key names to operate on.
- `values` (array of strings, optional): Plaintext values for `"write"` operations (must match `targets` length 1-to-1).

### Response Envelope

```json
{
  "type": "RESPONSE",
  "status": "success",
  "reason": "",
  "results": [
    {
      "target": "api_key",
      "value": "sec_live_9f83a2..."
    }
  ]
}
```

#### Response Status & Reason Codes
- `status` (string): `"success"`, `"denied"`, or `"error"`.
- `reason` (string): Present when `status` is `"denied"` or `"error"`:
  - `unregistered_binary_pending_approval`: Calling binary hash is not registered in configuration.
  - `service_not_allowed`: Calling binary is not permitted to access the requested service namespace.
  - `action_not_in_policy`: Requested action (e.g., `write` or `delete`) is denied by binary policy.
  - `malformed_request`: Invalid JSON envelope, missing fields, or length mismatches.
  - `internal_error`: Lower-level OS keychain or IPC failure.

---

## Client Integration Example (Go)

```go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
)

type Request struct {
	Type    string   `json:"type"`
	Action  string   `json:"action"`
	Service string   `json:"service"`
	Targets []string `json:"targets"`
}

type Response struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Results []struct {
		Target string `json:"target"`
		Value  string `json:"value"`
	} `json:"results,omitempty"`
}

func main() {
	conn, err := net.Dial("unix", "/run/keychain-auth/agent.sock")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	req := Request{
		Type:    "REQUEST",
		Action:  "read",
		Service: "agentsecrets",
		Targets: []string{"api_key"},
	}

	payload, _ := json.Marshal(req)
	payload = append(payload, '\n')
	conn.Write(payload)

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		var resp Response
		json.Unmarshal(scanner.Bytes(), &resp)
		fmt.Printf("Status: %s, Results: %+v\n", resp.Status, resp.Results)
	}
}
```

---

## Documentation Index

- [Architecture & Client Integration Manual](docs/architecture_and_integration_guide.md)
- [IPC Wire Protocol Specification](docs/integration_spec.md)
- [Client Integration Tutorial](docs/tutorial.md)

---

## License

MIT — see [LICENSE](LICENSE).
