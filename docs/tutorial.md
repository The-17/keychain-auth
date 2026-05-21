# End-to-End Integration Tutorial: Building the AgentSecrets Client

This tutorial walks you through integrating a custom CLI tool like `agentsecrets` with the `keychain-auth` daemon. You will learn how to handle install-time registration, elevate binary permissions, and write high-performance client code in Go to securely save and retrieve secrets.

---

## 1. Lifecycle Overview

The integration of any companion client tool with `keychain-auth` spans three distinct phases:

```
┌─────────────────────────────────┐
│     Phase 1: Registration       │  <-- Performed once during client installation
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│     Phase 2: Authorization      │  <-- Performed once by user/installer to grant scopes
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│     Phase 3: Runtime Queries    │  <-- Performed by client CLI on every execution
└─────────────────────────────────┘
```

---

## Phase 1: Registration at Install Time

When a user installs your CLI companion tool (e.g., `agentsecrets`), your installer or package post-install script must register the binary path and its SHA-256 cryptographic hash with `keychain-auth`. This registers the binary in a default zero-trust state.

In your installer script (e.g., `install.sh` or post-install package hooks):

```bash
# Locate the installed agentsecrets binary and register it with the security daemon
keychain-auth register $(which agentsecrets)
```

### Under the Hood:
This command:
1. Scans the `/usr/local/bin/agentsecrets` binary on disk.
2. Computes its SHA-256 hash.
3. Automatically appends a secure entry into the `~/.config/keychain-auth/config.json` database:

```json
{
  "path": "/usr/local/bin/agentsecrets",
  "hash": "sha256:fd7ecae9159e6f93a25178d3489fbffa7219917ca12567d5e42b156948",
  "allowed_read_services": [],
  "allowed_write_services": [],
  "can_search": false
}
```

> [!NOTE]
> Registered binaries start with **empty permission sets** (Zero-Trust). The binary is recognized, but it cannot read, write, search, or delete any keys yet.

---

## Phase 2: Elevating Permissions (Policy Configuration)

To allow the companion CLI to read or write credentials, the allowed service namespaces must be configured. 

There are two primary architectural patterns to choose from when design-integrating:

### Pattern A: Direct Shared Namespaces (Recommended for Interoperability)
If `agentsecrets` needs to share credentials with other ecosystem CLIs (e.g., allowing the standard `aws-cli` to read keys written by `agentsecrets`), you authorize `agentsecrets` to operate directly on the target third-party namespaces (e.g., `"openai"`, `"aws"`, `"github"`):

Open `~/.config/keychain-auth/config.json` and grant access to these namespaces:

```json
{
  "path": "/usr/local/bin/agentsecrets",
  "hash": "sha256:fd7ecae...",
  "allowed_read_services": ["openai", "aws", "github"],
  "allowed_write_services": ["openai", "aws", "github"],
  "can_search": true
}
```

### Pattern B: Private Namespace Isolation (Recommended for Strict Isolation)
If `agentsecrets` wants to guarantee that no other binaries can accidentally or intentionally read its credentials, it should isolate everything under its own dedicated service namespace (e.g. `"agentsecrets"` or `"AgentSecrets"`):

```json
{
  "path": "/usr/local/bin/agentsecrets",
  "hash": "sha256:fd7ecae...",
  "allowed_read_services": ["agentsecrets"],
  "allowed_write_services": ["agentsecrets"],
  "can_search": true
}
```
Within this single namespace, the companion CLI segments different secrets by prefixing the targets (e.g., targets named `"openai/api-key"`, `"aws/db-pass"`).

---

## Phase 3: Implementing Multi-Tenant Key Isolation

For advanced companion apps like `agentsecrets` that need to isolate secrets by **environment** (e.g., `production`, `development`), **project ID**, and **workspace**, `keychain-auth` supports a clean, robust isolation model.

### Hierarchical Namespacing & Key Prefixing
Because native OS keychains only index credentials by a `service` and an `account/target` keypair, trying to store rich metadata (such as project IDs or workspaces) natively is slow and unreliable across platforms. 

The industry standard and most robust solution is to **encode the tenant context directly into the `target` parameter using a hierarchical prefix**:

```
Format:  [environment]/[workspace_id]/[project_id]/[secret_name]
Example: "production/workspace_abc/proj_123/OPENAI_API_KEY"
```

Using this approach, you create full isolation using standard string operations.

#### Write Operation Payload:
```json
{
  "type": "REQUEST",
  "action": "write",
  "service": "agentsecrets",
  "targets": ["production/workspace_abc/proj_123/OPENAI_API_KEY"],
  "values": ["sk-proj-456"]
}
```

#### Read Operation Payload:
```json
{
  "type": "REQUEST",
  "action": "read",
  "service": "agentsecrets",
  "targets": ["production/workspace_abc/proj_123/OPENAI_API_KEY"]
}
```

> [!TIP]
> This key-prefixing approach ensures absolute compatibility across macOS Keychain, Linux Secret Service, and Windows Credential Manager without performance degradation.

### Highly Optimized Bulk Retrieval with Prefix Matching
If a client has hundreds of secrets stored in the keychain, fetching all target keys across the socket to filter them locally can introduce unnecessary latency and resource overhead. 

To solve this, `keychain-auth` supports two powerful prefix-matching features:

#### Option 1: Single-Roundtrip Bulk Retrieval (Prefix Read) — *Recommended*
You can fetch both the target keys and their actual plaintext values for all keys matching a prefix in a single socket roundtrip by setting `"match": "prefix"` on a `read` request:

```json
{
  "type": "REQUEST",
  "action": "read",
  "service": "agentsecrets",
  "match": "prefix",
  "targets": ["production/workspace_abc/proj_123/"]
}
```

*Daemon returns all matching keys and their values:*
```json
{
  "type": "RESPONSE",
  "status": "success",
  "results": [
    {
      "target": "production/workspace_abc/proj_123/OPENAI_API_KEY",
      "value": "sk-proj-456"
    },
    {
      "target": "production/workspace_abc/proj_123/AWS_SECRET_KEY",
      "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  ]
}
```
> [!IMPORTANT]
> To execute a prefix-based `read` (or `delete`), your binary's policy must have `"can_search": true` in addition to being allowed for that service.

#### Option 2: Search Prefix Filtering (Keys-Only Discovery)
If you only want to retrieve the *names* of the stored keys matching a prefix without reading their actual values (reducing the risk of exposing secrets in memory), you can use the `search` action:

```json
{
  "type": "REQUEST",
  "action": "search",
  "service": "agentsecrets",
  "targets": ["production/workspace_abc/proj_123/"]
}
```

*Daemon returns only matching target keys:*
```json
{
  "type": "RESPONSE",
  "status": "success",
  "results": [
    { "target": "production/workspace_abc/proj_123/OPENAI_API_KEY" },
    { "target": "production/workspace_abc/proj_123/AWS_SECRET_KEY" }
  ]
}
```
You can then follow up with explicit `read` requests targeting only the keys you actually need to access.

---

## Phase 4: Inside the Client CLI Code (Go Example)

The following Go code is a complete, production-grade example demonstrating how a client CLI like `agentsecrets` establishes a zero-trust connection, enforces `O_CLOEXEC` to prevent handle inheritance leaks, and executes batch reads and writes.

```go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"
)

// Request defines the JSON schema sent by the client.
type Request struct {
	Type    string   `json:"type"`             // Must be "REQUEST"
	Action  string   `json:"action"`           // "read", "write", "delete", "search"
	Service string   `json:"service"`          // e.g. "agentsecrets" or "openai"
	Targets []string `json:"targets,omitempty"` // Batch target keys
	Values  []string `json:"values,omitempty"`  // Batch values (only for write)
}

// ResultItem represents a single returned target/secret pair.
type ResultItem struct {
	Target string `json:"target"`
	Value  string `json:"value,omitempty"` // Only populated on successful reads
}

// Response defines the JSON schema returned by the daemon.
type Response struct {
	Type    string       `json:"type"`             // Always "RESPONSE"
	Status  string       `json:"status"`           // "success", "denied", "error"
	Reason  string       `json:"reason,omitempty"` // Set only when status != "success"
	Results []ResultItem `json:"results,omitempty"`
}

func main() {
	// Standard macOS / Linux daemon socket location
	socketPath := "/var/run/keychain-auth/agent.sock"

	// 1. Open the Unix socket WITH SOCK_CLOEXEC to prevent fd leaks across fork/exec
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Printf("Error creating socket: %v\n", err)
		os.Exit(1)
	}
	
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(s uintptr) {
				// The socket descriptor (s) has SOCK_CLOEXEC set by the standard syscall above.
			})
		},
	}

	conn, err := dialer.Dial("unix", socketPath)
	if err != nil {
		fmt.Println("keychain-auth daemon is not running.")
		fmt.Println("Please start it manually with: keychain-auth start")
		os.Exit(1)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	encoder := json.NewEncoder(conn)

	// ==========================================
	// BATCH WRITE EXAMPLE
	// ==========================================
	writeReq := Request{
		Type:    "REQUEST",
		Action:  "write",
		Service: "agentsecrets",
		Targets: []string{
			"production/workspace_abc/proj_123/OPENAI_API_KEY",
			"production/workspace_abc/proj_123/AWS_SECRET_KEY",
		},
		Values: []string{
			"sk-proj-456",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	fmt.Println("Sending batch write request...")
	if err := encoder.Encode(writeReq); err != nil {
		fmt.Printf("Failed to encode write request: %v\n", err)
		return
	}

	// Read and parse response
	writeRespLine, err := reader.ReadBytes('\n')
	if err != nil {
		fmt.Printf("Socket closed or error reading write response: %v\n", err)
		return
	}

	var writeResp Response
	if err := json.Unmarshal(writeRespLine, &writeResp); err != nil {
		fmt.Printf("Failed to parse response: %v\n", err)
		return
	}

	if writeResp.Status != "success" {
		fmt.Printf("Write operation denied: %s\n", writeResp.Reason)
		return
	}
	fmt.Println("Successfully wrote batch secrets to OS keychain!")

	// ==========================================
	// BATCH READ EXAMPLE
	// ==========================================
	readReq := Request{
		Type:    "REQUEST",
		Action:  "read",
		Service: "agentsecrets",
		Targets: []string{
			"production/workspace_abc/proj_123/OPENAI_API_KEY",
			"production/workspace_abc/proj_123/AWS_SECRET_KEY",
		},
	}

	fmt.Println("\nSending batch read request...")
	if err := encoder.Encode(readReq); err != nil {
		fmt.Printf("Failed to encode read request: %v\n", err)
		return
	}

	readRespLine, err := reader.ReadBytes('\n')
	if err != nil {
		fmt.Printf("Socket closed or error reading read response: %v\n", err)
		return
	}

	var readResp Response
	if err := json.Unmarshal(readRespLine, &readResp); err != nil {
		fmt.Printf("Failed to parse read response: %v\n", err)
		return
	}

	if readResp.Status != "success" {
		fmt.Printf("Read operation denied: %s\n", readResp.Reason)
		return
	}

	// Safely print values
	for _, res := range readResp.Results {
		fmt.Printf("Retrieved target key: %s\n", res.Target)
		fmt.Printf(" -> Plaintext secret: %s\n", res.Value)
	}
}
```
