# Chapter 5: Step-by-Step Client Implementations

Below are complete, production-grade client integrations written in three popular languages: Go, Python, and Node.js. 

Every client implementation is written to be **fully self-contained** and handles:
1. Establishing the connection over Unix sockets/Named pipes.
2. Enabling **`O_CLOEXEC`** socket options (or setting handle inheritance to false on Windows) to prevent fd/handle hijacking.
3. Performing batch writes.
4. Performing optimized, single-roundtrip prefix reads.

---

## 5.1 Production-Grade Go Client

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

## 5.2 Python Client (Unix Socket & Windows Named Pipes)

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

## 5.3 Node.js / JavaScript Client

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
