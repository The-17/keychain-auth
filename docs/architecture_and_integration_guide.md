# The Keychain-Auth Master Book: Architecture & Client Integration Manual

This book serves as the absolute, definitive reference manual for the `keychain-auth` security proxy. It covers everything from low-level operating system IPC details to building complete production-grade clients in Go, Python, and Node.js.

If you are a developer building integrations (like `agentsecrets` or any other tool that needs to safely interface with the OS keychain), this manual will provide you with the deep architectural understanding and code patterns to build secure, robust integrations from scratch.

---

## Table of Contents
1. [Chapter 1: The Core Architecture & Threat Model](#chapter-1-the-core-architecture--threat-model)
2. [Chapter 2: Kernel-Level Identity & IPC Transport](#chapter-2-kernel-level-identity--ipc-transport)
3. [Chapter 3: The JSON Wire Protocol Specification](#chapter-3-the-json-wire-protocol-specification)
4. [Chapter 4: Advanced Multi-Tenant Namespace Schemes](#chapter-4-advanced-multi-tenant-namespace-schemes)
5. [Chapter 5: Step-by-Step Client Implementations (Go, Python, Node.js)](#chapter-5-step-by-step-client-implementations)
6. [Chapter 6: Daemon Lifecycle & Forensic Auditing](#chapter-6-daemon-lifecycle--forensic-auditing)
7. [Chapter 7: Production Integration Checklist](#chapter-7-production-integration-checklist)

---

## Chapter 1: The Core Architecture & Threat Model

Before writing a single line of client code, it is critical to understand *why* `keychain-auth` exists and the security vulnerabilities it mitigates in modern operating systems.

### 1.1 The Vulnerability of Native Keychains

Operating system keychains are designed to store credentials securely. However, the access control layer on desktop operating systems was built for a legacy desktop era and is fundamentally flawed for command-line interfaces (CLIs) and modern software supply chains.

#### A. Linux Secret Service (D-Bus) Vulnerability
On Linux, the standard password managers (GNOME Keyring, KWallet) implement the FreeDesktop.org Secret Service API over D-Bus (`org.freedesktop.secrets`). 
* **The Flaw:** Any process running under the same user session can query the D-Bus secret service without password prompts or verification.
* **The Threat:** If you execute an untrusted CLI tool, or run a project containing a compromised dependency (e.g., an npm package, python pip package, or cargo crate containing a malicious post-install script), that script can silently read all your AWS credentials, Stripe tokens, or SSH keys stored in GNOME Keyring.

#### B. Windows Credential Manager & DPAPI
Windows uses the Data Protection API (DPAPI) and Credential Manager.
* **The Flaw:** By default, DPAPI decrypts data for any process running under the identity of the current user.
* **The Threat:** Just like Linux D-Bus, any local script running in PowerShell or Command Prompt can invoke `CredRead` to dump all generic credentials stored under your user account.

#### C. macOS Keychain "Prompt Fatigue"
macOS has a robust code-signing and entitlement system for GUI applications. However, it fails for CLI tools.
* **The Flaw:** Because command-line utilities are often unsigned, compiled locally, or executed inside virtual environments, the macOS `SecurityAgent` cannot uniquely identify them. This results in constant GUI prompts asking: *“your-cli wants to use your keychain. Enter password.”*
* **The Result:** Out of sheer frustration, users click **"Always Allow"**. Once clicked, macOS grants access to that service item to *any* command-line tool, completely bypassing the security boundaries.

### 1.2 The Security Broker Solution

`keychain-auth` sits as a **Zero-Trust Security Broker** between your applications and the native OS keychains.

```
┌────────────────────────┐             Local Socket / Pipe            ┌────────────────────────┐
│  Client Application    │ ◄────────────────────────────────────────► │     keychain-auth      │
│ (e.g., agentsecrets)   │   Newline-Delimited JSON (O_CLOEXEC)      │    (Security Daemon)   │
└────────────────────────┘                                            └───────────┬────────────┘
                                                                                  │ (Verification & Policy)
                                                                                  ▼
                                                                      ┌────────────────────────┐
                                                                      │   Native OS Keychain   │
                                                                      └────────────────────────┘
```

1. **Isolation:** The native OS keychain items are stored under a restricted service namespace managed by the `keychain-auth` daemon itself. No client app queries the native keychain directly.
2. **Attestation:** When a client application connects, `keychain-auth` verifies the executable's path and SHA-256 cryptographic hash on disk.
3. **Policy Gating:** The daemon evaluates the verified application against a fine-grained, user-approved policy. The application is strictly restricted to its allowed service namespaces (e.g. `openai` or `agentsecrets`).
4. **Forensic Logs:** Every access attempt is logged with details of the calling PID, path, hash, and parameters.

### 1.3 The Critical `O_CLOEXEC` Requirement (The Security Contract)

If an authorized client application starts up, connects to the `keychain-auth` socket, and then forks/executes a child process (like a build script or an untrusted sub-command), the child process will **inherit all open file descriptors** by default.
* **The Danger:** The untrusted child process could write requests directly to the inherited socket descriptor. Since the connection was already authorized by the daemon, the child could read or delete all your secrets without authentication.
* **The Fix:** Clients **must** open the Unix domain socket with the `SOCK_CLOEXEC` flag (or set the descriptor as `O_CLOEXEC` on Unix, or configure handles as non-inheritable on Windows). This tells the kernel to automatically close the socket descriptor when performing any `exec()` system call, completely neutralizing handle-hijacking attacks.

---

## Chapter 2: Kernel-Level Identity & IPC Transport

A major strength of `keychain-auth` is that **the connection itself is the authenticated session**. There are no session tokens, cookies, or secrets transmitted over the socket to prove identity. Instead, the daemon retrieves caller information directly from the operating system kernel.

### 2.1 The Multi-Platform IPC Channels

* **macOS & Linux:** Standard Unix Domain Sockets. Sockets are faster, more lightweight than HTTP/TCP, and their access permissions can be restricted using standard file permissions (`0600`).
  * Default socket path: `/var/run/keychain-auth/agent.sock` (or falls back to `~/.config/keychain-auth/agent.sock` if root access is unavailable).
* **Windows:** Named Pipes.
  * Default pipe path: `\\.\pipe\keychain-auth`.

### 2.2 Kernel-Enforced Process ID (PID) Resolution

To prevent spoofing, `keychain-auth` ignores any self-reported PIDs. The daemon retrieves the **real** PID of the calling process directly from the kernel transport options:

#### A. Linux (`SO_PEERCRED`)
On Unix domain sockets, the daemon reads the socket options using the `SO_PEERCRED` system call. The kernel returns a `ucred` structure containing the verified `pid`, `uid`, and `gid` of the client.
```go
// Go implementation in keychain-auth (internal/verify/verify_linux.go)
sysCred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
pid := sysCred.Pid
```

#### B. macOS (`LOCAL_PEERPID`)
On macOS, `SO_PEERCRED` is unavailable. The daemon queries the socket using the `LOCAL_PEERPID` option to retrieve the verified caller PID.
```go
// Go implementation in keychain-auth (internal/verify/verify_darwin.go)
pid, err := syscall.GetsockoptInt(fd, syscall.SOL_LOCAL, syscall.LOCAL_PEERPID)
```

#### C. Windows Named Pipes
On Windows, the daemon utilizes the `GetNamedPipeClientProcessId` Win32 API on the active named pipe handle. The kernel enforces this process ID, guaranteeing that a malicious client cannot spoof its identity.

### 2.3 Resolving Executable Paths & Cryptographic Hashes

Once the PID is verified by the kernel, the daemon resolves it to a physical binary file:
* **Linux:** Reads the symlink `/proc/[PID]/exe` to locate the exact path on disk.
* **macOS:** Invokes the `proc_pidpath` system call.
* **Windows:** Opens a process handle using `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` and queries the path via `QueryFullProcessImageName`.

Once the path is resolved, the daemon reads the binary file and computes its **SHA-256 hash**. 
> [!IMPORTANT]
> **Active Binary Locking:** Modern operating systems lock running executables from being modified in place (`ETXTBSY` error on Linux). This prevents an attacker from swapping a trusted binary with a malicious one *after* it has started running. Thus, validating the binary's hash at runtime is highly secure.

---

## Chapter 3: The JSON Wire Protocol Specification

The protocol is a high-performance, low-latency, newline-delimited JSON schema. 
* Every request is sent as a single line, terminated by a newline (`\n`).
* Every response is returned as a single line, terminated by a newline (`\n`).

### 3.1 The Request Schema

The request envelope is designed to be highly generic, supporting batch queries and optional prefix matching.

```json
{
  "type": "REQUEST",
  "action": "read | write | delete | search",
  "service": "agentsecrets",
  "match": "exact | prefix",
  "targets": ["prod/db_pass", "prod/api_key"],
  "values": ["secret1", "secret2"],
  "attributes": {
    "project": "proj_abc"
  }
}
```

#### Field-by-Field Breakdown:

| JSON Key | Go Struct Field | Type | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `type` | `Type` | String | **Yes** | Must be exactly `"REQUEST"`. |
| `action` | `Action` | String | **Yes** | Must be `"read"`, `"write"`, `"delete"`, or `"search"`. |
| `service` | `Service` | String | **Yes** | The OS keychain service namespace (e.g. `"AgentSecrets"`, `"aws"`, `"openai"`). |
| `match` | `Match` | String | No | `"exact"` (default) or `"prefix"`. If `"prefix"`, targets are treated as prefixes. (Not allowed for `"write"`). |
| `targets` | `Targets` | Array of Strings | **Yes** | The keys/accounts being queried. For `"search"`, this is optional and acts as prefix filters. |
| `values` | `Values` | Array of Strings | Cond. | Corresponding plaintext values to save. **Only required for `"write"`**. |
| `attributes`| `Attributes` | Map of Strings | No | Key-value pairs for metadata association (highly useful for tagging secrets). |

#### Request Restrictions:
1. **Strict Array Alignment (Writes):** For `"action": "write"`, the length of the `targets` array **must exactly match** the length of the `values` array.
2. **Prefix Gating:** Prefix-based `"read"` or `"delete"` operations internally list/enumerate all keys in a namespace. Therefore, a client **must have `"can_search": true`** in its configuration policy, otherwise the daemon rejects the request.

---

### 3.2 The Response Schema

The daemon processes requests and returns a structured response envelope:

```json
{
  "type": "RESPONSE",
  "status": "success | denied | error",
  "reason": "unregistered_binary_pending_approval | service_not_allowed | action_not_in_policy | malformed_request | internal_error",
  "results": [
    {
      "target": "prod/db_pass",
      "value": "secret1",
      "attributes": {
        "project": "proj_abc"
      }
    }
  ]
}
```

#### Field-by-Field Breakdown:

| JSON Key | Go Struct Field | Type | Description |
| :--- | :--- | :--- | :--- |
| `type` | `Type` | String | Always `"RESPONSE"`. |
| `status` | `Status` | String | `"success"`, `"denied"` (policy rejection), or `"error"` (failure). |
| `reason` | `Reason` | String | Error code explaining the denial or error. Omitted on success. |
| `results` | `Results` | Array of Objects | Contains results of read or search actions. Values are omitted on search. |

#### Results Object Breakdown:
* `target`: The name of the secret.
* `value`: The plaintext secret value. **⚠️ This is only populated on successful, authorized `"read"` actions. It is never populated on `"search"` actions to prevent bulk credential harvests.**
* `attributes`: Map of metadata associated with the secret.

---

### 3.3 Reason Codes Reference

When writing a client, your code must handle these specific rejection codes gracefully:

* **`unregistered_binary_pending_approval`**: The binary has not been registered or approved yet. The daemon has queued it in `pending.json` for interactive approval via the `keychain-auth approve` command.
* **`service_not_allowed`**: The binary attempted to read or write to a service namespace not authorized in its policy (e.g. trying to access `aws` when only authorized for `agentsecrets`).
* **`action_not_in_policy`**: The binary attempted to run a `search` or prefix-based operation, but its policy has `can_search` set to `false`.
* **`malformed_request`**: The JSON payload was invalid, had mismatched targets/values array lengths, or invalid properties.
* **`internal_error`**: An underlying failure occurred while communicating with the OS keychain (e.g., Apple Keychain DB locked, dbus connection lost).

---

## Chapter 4: Advanced Multi-Tenant Namespace Schemes

Native keychains (macOS, Windows, Linux) are inherently flat. They index entries using a two-key system: **Service Name** and **Account Name (Target)**. They do *not* natively support multi-tenant structures like environment folders, projects, or workspaces.

To build an advanced tool like `agentsecrets` that manages secrets across multiple workspaces, environments, and projects, you must implement a **Hierarchical Namespace Scheme** using string segmentation.

### 4.1 Choosing a Namespace Pattern

#### Pattern A: Direct Shared Namespaces
If your CLI utility interacts directly with third-party tools (e.g. your tool writes an AWS key that the standard `aws-cli` needs to read directly from the OS keychain), you should use the target service name directly:
* **Service:** `aws`
* **Target:** `default` or `project-prod`

#### Pattern B: Private Isolated Namespace (Recommended for Multi-Tenant CLIs)
If your CLI tool (like `agentsecrets`) is the sole manager of its secrets, you should isolate all data under a single private service namespace:
* **Service:** `AgentSecrets`

Within this single, isolated service namespace, you serialize all tenant context (Environment, Workspace, Project, Key) directly into the `target` parameter using a specific delimiter (like `:` or `/`).

```
Format:  [project_id]:[environment]:[secret_name]
Example: "proj_123:development:DATABASE_URL"
Example: "proj_abc:production:STRIPE_API_KEY"
```

This guarantees:
1. Absolute platform compatibility (every OS keychain safely stores standard strings).
2. O(1) direct reads when the exact path is known.
3. High-performance prefix-based discovery.

---

## Chapter 5: Step-by-Step Client Implementations

Below are complete, production-grade client integrations written in three popular languages: Go, Python, and Node.js. 

Every client implementation is written to be **fully self-contained** and handles:
1. Establishing the connection over Unix sockets/Named pipes.
2. Enabling **`O_CLOEXEC`** socket options (or setting handle inheritance to false on Windows) to prevent fd/handle hijacking.
3. Performing batch writes.
4. Performing optimized, single-roundtrip prefix reads.

### 5.1 Production-Grade Go Client

Go is excellent for low-level systems programming. Here is a complete, production-grade Go client that works cross-platform.

```go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Request defines the JSON schema sent by the client.
type Request struct {
	Type       string            `json:"type"`
	Action     string            `json:"action"`
	Service    string            `json:"service"`
	Match      string            `json:"match,omitempty"`
	Targets    []string          `json:"targets,omitempty"`
	Values     []string          `json:"values,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// ResultItem represents a single returned secret from a read or search.
type ResultItem struct {
	Target     string            `json:"target"`
	Value      string            `json:"value,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Response defines the JSON schema returned by the daemon.
type Response struct {
	Type    string       `json:"type"`
	Status  string       `json:"status"`
	Reason  string       `json:"reason,omitempty"`
	Results []ResultItem `json:"results,omitempty"`
}

// KeychainClient wraps the IPC connection.
type KeychainClient struct {
	conn net.Conn
}

// NewKeychainClient establishes a secure connection to the daemon.
func NewKeychainClient() (*KeychainClient, error) {
	var conn net.Conn
	var err error

	if runtime.GOOS == "windows" {
		// Connect to Windows Named Pipe
		pipePath := `\\.\pipe\keychain-auth`
		conn, err = net.Dial("winio", pipePath) // In production, use "github.com/Microsoft/go-winio"
		if err != nil {
			// Fallback to standard dial if winio is not imported
			conn, err = net.Dial("pipe", pipePath)
		}
	} else {
		// macOS/Linux socket paths
		socketPath := "/var/run/keychain-auth/agent.sock"
		if _, err := os.Stat(socketPath); os.IsNotExist(err) {
			// Fall back to user-space socket path
			home, _ := os.UserHomeDir()
			socketPath = home + "/.config/keychain-auth/agent.sock"
		}

		// CRITICAL: We create the socket with SOCK_CLOEXEC to prevent fd leaks across fork/exec
		fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to create secure socket: %w", err)
		}

		sa := &syscall.SockaddrUnix{Name: socketPath}
		if err := syscall.Connect(fd, sa); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to connect to daemon socket: %w", err)
		}

		// Convert raw fd to net.Conn
		file := os.NewFile(uintptr(fd), socketPath)
		defer file.Close()
		conn, err = net.FileConn(file)
		if err != nil {
			return nil, fmt.Errorf("failed to convert secure socket to connection: %w", err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("keychain-auth daemon is not running. Please start it with: keychain-auth start. Error: %w", err)
	}

	return &KeychainClient{conn: conn}, nil
}

func (c *KeychainClient) Close() error {
	return c.conn.Close()
}

// SendRequest sends a request and parses the single-line JSON response.
func (c *KeychainClient) SendRequest(req Request) (*Response, error) {
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Write Request (must terminate with newline)
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read single-line response
	reader := bufio.NewReader(c.conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	if resp.Status != "success" {
		return &resp, fmt.Errorf("daemon rejected request: %s", resp.Reason)
	}

	return &resp, nil
}

func main() {
	client, err := NewKeychainClient()
	if err != nil {
		fmt.Printf("Connection Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// 1. Write multi-tenant environment keys
	fmt.Println("Saving keys to OS keychain...")
	writeReq := Request{
		Type:    "REQUEST",
		Action:  "write",
		Service: "AgentSecrets",
		Targets: []string{
			"proj_123:development:DATABASE_URL",
			"proj_123:production:DATABASE_URL",
			"proj_123:development:OPENAI_KEY",
		},
		Values: []string{
			"postgres://dev-db",
			"postgres://prod-db",
			"sk-proj-dev123",
		},
	}

	_, err = client.SendRequest(writeReq)
	if err != nil {
		fmt.Printf("Write Failed: %v\n", err)
		return
	}
	fmt.Println("Success!")

	// 2. Perform Single-Roundtrip Prefix Read
	fmt.Println("\nRetrieving keys for development environment using Prefix Read...")
	readReq := Request{
		Type:    "REQUEST",
		Action:  "read",
		Service: "AgentSecrets",
		Match:   "prefix",
		Targets: []string{"proj_123:development:"},
	}

	resp, err := client.SendRequest(readReq)
	if err != nil {
		fmt.Printf("Read Failed: %v\n", err)
		return
	}

	for _, result := range resp.Results {
		fmt.Printf(" -> Key: %-35s Value: %s\n", result.Target, result.Value)
	}
}
```

---

### 5.2 Python Client (Unix Socket & Windows Named Pipes)

Python is widely used in AI, scripting, and web development. This implementation handles Unix Domain Sockets on Linux/macOS and Named Pipes on Windows, ensuring absolute cross-platform execution.

```python
import os
import sys
import json
import socket

class KeychainAuthClient:
    def __init__(self):
        self.conn = None
        self._connect()

    def _connect(self):
        if sys.platform == "win32":
            # Connect to Windows Named Pipe
            self.pipe_path = r"\\.\pipe\keychain-auth"
            try:
                # Open pipe handle using native Win32 calls
                import win32file
                import win32pipe
                self.handle = win32file.CreateFile(
                    self.pipe_path,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING, 0, None
                )
            except ImportError:
                raise RuntimeError("Please install 'pywin32' package for named pipe connections on Windows.")
            except Exception as e:
                raise RuntimeError(f"keychain-auth daemon is not running: {e}")
        else:
            # Unix Domain Socket connection for macOS/Linux
            socket_path = "/var/run/keychain-auth/agent.sock"
            if not os.path.exists(socket_path):
                # Fallback to user-space socket path
                socket_path = os.path.expanduser("~/.config/keychain-auth/agent.sock")
            
            try:
                # Create socket with standard Unix options
                self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                
                # Enforce O_CLOEXEC on the socket descriptor to prevent leakage across fork/exec
                import fcntl
                flags = fcntl.fcntl(self.conn.fileno(), fcntl.F_GETFD)
                fcntl.fcntl(self.conn.fileno(), fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
                
                self.conn.connect(socket_path)
            except Exception as e:
                raise RuntimeError(f"keychain-auth daemon is not running: {e}")

    def send_request(self, request_dict):
        payload = json.dumps(request_dict) + "\n"
        
        if sys.platform == "win32":
            # Write/Read Windows Named Pipe
            import win32file
            win32file.WriteFile(self.handle, payload.encode('utf-8'))
            
            # Read single-line JSON response
            response_bytes = b""
            while True:
                err, chunk = win32file.ReadFile(self.handle, 1024)
                response_bytes += chunk
                if b"\n" in response_bytes:
                    break
        else:
            # Write/Read Unix Domain Socket
            self.conn.sendall(payload.encode('utf-8'))
            
            # Read single-line JSON response
            response_bytes = b""
            while True:
                chunk = self.conn.recv(1024)
                if not chunk:
                    break
                response_bytes += chunk
                if b"\n" in response_bytes:
                    break
                    
        response_line = response_bytes.split(b"\n")[0].decode('utf-8')
        response_dict = json.loads(response_line)
        
        if response_dict.get("status") != "success":
            raise RuntimeError(f"Daemon rejected request: {response_dict.get('reason')}")
            
        return response_dict

    def close(self):
        if self.conn:
            self.conn.close()
        if sys.platform == "win32" and hasattr(self, 'handle'):
            import win32file
            win32file.CloseHandle(self.handle)

# ==========================================
# Runtime Demo
# ==========================================
if __name__ == "__main__":
    try:
        client = KeychainAuthClient()
        
        # 1. Batch Write Environment Keys
        print("Writing environment keys to keychain...")
        write_req = {
            "type": "REQUEST",
            "action": "write",
            "service": "AgentSecrets",
            "targets": [
                "proj_123:development:DATABASE_URL",
                "proj_123:staging:DATABASE_URL",
                "proj_123:production:DATABASE_URL"
            ],
            "values": [
                "postgres://dev-db",
                "postgres://staging-db",
                "postgres://prod-db"
            ]
        }
        client.send_request(write_req)
        print("Write succeeded!")

        # 2. Single-Roundtrip Prefix Read
        print("\nReading staging configuration via Prefix Read...")
        read_req = {
            "type": "REQUEST",
            "action": "read",
            "service": "AgentSecrets",
            "match": "prefix",
            "targets": ["proj_123:staging:"]
        }
        response = client.send_request(read_req)
        
        for item in response.get("results", []):
            print(f" -> Secret Key: {item['target']} = {item['value']}")
            
    except Exception as e:
        print(f"Error: {e}")
```

---

### 5.3 Node.js / JavaScript Client

Node.js is extremely popular for web apps and tooling. This implementation utilizes standard `net` sockets to communicate.

```javascript
const net = require('net');
const os = require('os');
const path = require('path');

class KeychainAuthClient {
    constructor() {
        this.socketPath = process.platform === 'win32'
            ? '\\\\.\\pipe\\keychain-auth'
            : path.join('/var/run/keychain-auth/agent.sock');
            
        if (process.platform !== 'win32' && !require('fs').existsSync(this.socketPath)) {
            this.socketPath = path.join(os.homedir(), '.config', 'keychain-auth', 'agent.sock');
        }
        
        this.client = null;
    }

    connect() {
        return new Promise((resolve, reject) => {
            this.client = net.createConnection(this.socketPath, () => {
                // Connection established
                resolve();
            });

            this.client.on('error', (err) => {
                reject(new Error(`keychain-auth daemon is not running. Start with: keychain-auth start. Details: ${err.message}`));
            });
        });
    }

    sendRequest(requestObj) {
        return new Promise((resolve, reject) => {
            let buffer = '';
            
            // Set up single-line JSON parsing
            const onData = (data) => {
                buffer += data.toString();
                if (buffer.includes('\n')) {
                    const line = buffer.split('\n')[0];
                    this.client.removeListener('data', onData);
                    try {
                        const response = JSON.parse(line);
                        if (response.status !== 'success') {
                            reject(new Error(`Daemon rejected request: ${response.reason}`));
                        } else {
                            resolve(response);
                        }
                    } catch (e) {
                        reject(new Error(`Failed to parse response JSON: ${e.message}`));
                    }
                }
            };

            this.client.on('data', onData);
            
            // Send payload (must terminate with newline)
            this.client.write(JSON.stringify(requestObj) + '\n');
        });
    }

    close() {
        if (this.client) {
            this.client.end();
        }
    }
}

// ==========================================
// Runtime Demo
// ==========================================
(async () => {
    try {
        const client = new KeychainAuthClient();
        await client.connect();
        
        // 1. Batch Write Keys
        console.log("Writing secrets...");
        const writeReq = {
            type: "REQUEST",
            action: "write",
            service: "AgentSecrets",
            targets: ["proj_123:development:DATABASE_URL", "proj_123:development:OPENAI_KEY"],
            values: ["mongodb://localhost/dev", "sk-proj-node123"]
        };
        await client.sendRequest(writeReq);
        console.log("Success!");

        // 2. Prefix Read
        console.log("\nReading development config via Prefix Read...");
        const readReq = {
            type: "REQUEST",
            action: "read",
            service: "AgentSecrets",
            match: "prefix",
            targets: ["proj_123:development:"]
        };
        const response = await client.sendRequest(readReq);
        
        response.results.forEach(res => {
            console.log(` -> Key: ${res.target} = ${res.value}`);
        });
        
        client.close();
    } catch (e) {
        console.error("Execution Error:", e.message);
    }
})();
```

---

## Chapter 6: Daemon Lifecycle & Forensic Auditing

To successfully build client tools, you must understand how the user registers and approves your tools, and what errors are recorded in the forensic audit trails.

### 6.1 The "Pending Approval" Workflow

`keychain-auth` works in a strictly Zero-Trust configuration. If an unregistered application attempts to connect to the socket and read a secret:

1. **Rejection:** The daemon immediately denies the request with:
   ```json
   { "type": "RESPONSE", "status": "denied", "reason": "unregistered_binary_pending_approval" }
   ```
2. **Socket Drop:** The daemon closes the socket connection immediately.
3. **Queueing:** The daemon writes all relevant forensic details about this binary to the `pending.json` queue file located at `~/.config/keychain-auth/pending.json` (with a 24-hour TTL):
   * SHA-256 cryptographic hash of the binary.
   * Path of the binary on disk.
   * Exact CLI arguments used during invocation.
   * User account and timestamp.

#### Approving Safe CLI Tools
The user can inspect this pending authorization queue at any time:
```bash
keychain-auth list-pending
```
If the process is safe, they approve it:
```bash
keychain-auth approve [hash]
```
This adds the binary hash to `config.json` with a **default, restricted policy** containing empty permissions. The user then manually scopes the binary to allowed services.

### 6.2 Managing Binary Upgrades

When your client CLI tool is updated (e.g. your package manager installs `agentsecrets` v2.0.0), its SHA-256 binary hash changes.
* **The Result:** The next time the updated CLI tool queries the daemon, it will be rejected as an "unregistered binary" because its hash does not match the approved `config.json` database.
* **The Solution:** Package upgrade scripts or installers must execute the `upgrade` command:
  ```bash
  keychain-auth upgrade $(which agentsecrets)
  ```
  This command computes the new binary hash, locates the matching path in `config.json`, and updates the approved hash entry in place without destroying your existing permission policies.

### 6.3 Forensic Audit Logging

Every operation on the keychain auth daemon generates a highly granular event record inside the local audit log (`audit.log`). 

#### Example Log File Entries (`audit.log`):
```json
{"timestamp":"2026-05-21T01:00:15Z","action":"write","pid":8412,"binary_path":"/usr/local/bin/agentsecrets","binary_hash":"sha256:abcd1234...","service":"AgentSecrets","targets":["proj_123:development:DATABASE_URL"],"result":"GRANTED"}
{"timestamp":"2026-05-21T01:01:22Z","action":"read","pid":8412,"binary_path":"/usr/local/bin/agentsecrets","binary_hash":"sha256:abcd1234...","service":"AgentSecrets","targets":["proj_123:development:DATABASE_URL"],"result":"GRANTED"}
{"timestamp":"2026-05-21T01:02:40Z","action":"read","pid":9123,"binary_path":"/usr/bin/curl","binary_hash":"sha256:ff398bc...","service":"aws","targets":["default"],"result":"DENIED","reason":"unregistered_binary_pending_approval"}
```

> [!CAUTION]
> **Audit Log Security Isolation:** Under no circumstances does the daemon write plaintext secret values to `audit.log`. This ensures that auditing is high-fidelity while presenting no side-channel credential leak vectors.

---

## Chapter 7: Production Integration Checklist

When releasing an application or CLI integrated with `keychain-auth`, use this checklist to ensure complete security compliance and premium UX:

* [ ] **Enforce `O_CLOEXEC`**: Ensure your network client library explicitly opens local sockets with `SOCK_CLOEXEC` (or handle inheritance disabled on Windows) to prevent fd hijacking by child processes.
* [ ] **Setup-Time Registration**: Make sure your tool's installer automatically runs `keychain-auth register $(which your-tool)` during the installation process.
* [ ] **Upgrade Hooks**: Make sure your package manager post-upgrade hooks run `keychain-auth upgrade $(which your-tool)` on binary updates.
* [ ] **Helpful Daemon Missing Diagnostics**: If connection to the local socket or named pipe fails, display a clear, user-friendly instruction guide on how to start the daemon:
  ```
  Error: Cannot connect to keychain-auth daemon.
  To resolve this, start the background agent:
    keychain-auth start
  ```
* [ ] **Use Private Namespaces**: If your tool does not share passwords directly with third-party tools, isolate all secrets under your own, private service namespace (e.g. `AgentSecrets`).
* [ ] **Prefix Matching for Bulk Discovery**: Avoid reading all secrets into client memory when you only need to list key names. Use search prefix-filtering to display coverage layouts securely.
