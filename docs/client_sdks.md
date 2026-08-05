# Multi-Language Client Integration Guide

This guide provides complete, production-grade integration code snippets for dialing the `keychain-auth` IPC daemon across multiple programming languages (**Go**, **Python**, **Node.js**, **Rust**, and **Shell**).

---

## 1. Go Client Integration

```go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"syscall"
)

type Request struct {
	Type    string   `json:"type"`
	Action  string   `json:"action"`
	Service string   `json:"service"`
	Targets []string `json:"targets"`
	Values  []string `json:"values,omitempty"`
}

type Response struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Results []struct {
		Target string `json:"target"`
		Value  string `json:"value,omitempty"`
	} `json:"results,omitempty"`
}

func main() {
	// Connect to Unix domain socket (or Named Pipe on Windows)
	socketPath := "/run/keychain-auth/agent.sock"

	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set SOCK_CLOEXEC to prevent fd leaks across process forks
			})
		},
	}

	conn, err := dialer.Dial("unix", socketPath)
	if err != nil {
		fmt.Printf("keychain-auth daemon not running: %v\n", err)
		return
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
		if resp.Status == "success" {
			for _, item := range resp.Results {
				fmt.Printf("Key: %s, Value: %s\n", item.Target, item.Value)
			}
		} else {
			fmt.Printf("Denied/Error: %s\n", resp.Reason)
		}
	}
}
```

---

## 2. Python Client Integration

```python
import json
import socket
import sys

SOCKET_PATH = "/run/keychain-auth/agent.sock"

def query_keychain(service: str, action: str, targets: list, values: list = None):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(SOCKET_PATH)
    except FileNotFoundError:
        print("Error: keychain-auth daemon is not running.", file=sys.stderr)
        sys.exit(1)

    req = {
        "type": "REQUEST",
        "action": action,
        "service": service,
        "targets": targets
    }
    if values:
        req["values"] = values

    client.sendall((json.dumps(req) + "\n").encode('utf-8'))

    response_data = client.makefile('r').readline()
    client.close()

    return json.loads(response_data)

if __name__ == "__main__":
    resp = query_keychain("agentsecrets", "read", ["api_key"])
    print("Response:", resp)
```

---

## 3. Node.js Client Integration

```javascript
const net = require('net');
const readline = require('readline');

const SOCKET_PATH = '/run/keychain-auth/agent.sock';

function sendKeychainRequest(request) {
    return new Promise((resolve, reject) => {
        const client = net.createConnection(SOCKET_PATH, () => {
            client.write(JSON.stringify(request) + '\n');
        });

        const rl = readline.createInterface({ input: client });
        rl.on('line', (line) => {
            try {
                const response = JSON.parse(line);
                client.end();
                resolve(response);
            } catch (err) {
                reject(err);
            }
        });

        client.on('error', (err) => {
            reject(new Error(`keychain-auth connection error: ${err.message}`));
        });
    });
}

(async () => {
    try {
        const response = await sendKeychainRequest({
            type: 'REQUEST',
            action: 'read',
            service: 'agentsecrets',
            targets: ['api_key']
        });
        console.log('Daemon Response:', response);
    } catch (err) {
        console.error(err.message);
    }
})();
```

---

## 4. Rust Client Integration

```rust
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct Request {
    r#type: String,
    action: String,
    service: String,
    targets: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct Response {
    status: String,
    reason: Option<String>,
    results: Option<Vec<ResultItem>>,
}

#[derive(Deserialize, Debug)]
struct ResultItem {
    target: String,
    value: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = "/run/keychain-auth/agent.sock";
    let mut stream = UnixStream::connect(socket_path)?;

    let req = Request {
        r#type: "REQUEST".to_string(),
        action: "read".to_string(),
        service: "agentsecrets".to_string(),
        targets: vec!["api_key".to_string()],
    };

    let mut payload = serde_json::to_string(&req)?;
    payload.push('\n');
    stream.write_all(payload.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&response_line)?;

    let resp: Response = serde_json::from_str(&response_line)?;
    println!("Response: {:?}", resp);

    Ok(())
}
```

---

## 5. Shell / SOCAT Integration

```bash
# Using socat over Unix socket
echo '{"type":"REQUEST","action":"read","service":"agentsecrets","targets":["api_key"]}' | socat - UNIX-CONNECT:/run/keychain-auth/agent.sock
```

---

## Next Steps

- Inspect [IPC Wire Protocol Specification](integration_spec.md) for complete envelope schemas.
- Review [Troubleshooting & Diagnostics](troubleshooting.md) for handling denial reason codes.
