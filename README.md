# keychain-auth

A local daemon that gives CLI tools and AI agents controlled access to the OS keychain.

It answers one question: *is this process allowed to touch these credentials?* The kernel supplies the caller's identity. The daemon checks a registered binary hash and a service policy before every operation.

---

## Why it exists

- On Linux and Windows, any process running as the user can read the user's credential store. There is no per-app isolation.
- On macOS, repeated Keychain prompts cause prompt fatigue and overly broad grants.
- Headless Linux and WSL often have no graphical keyring, so tools fall back to plaintext files.

keychain-auth puts one policy check in front of the store. Clients never hold raw store access.

---

## How it works

1. A client connects over a local Unix socket or Windows named pipe.
2. The daemon reads the peer PID and UID from the kernel (`SO_PEERCRED`, `LOCAL_PEERPID`, or the Windows pipe API). Self-reported IDs are ignored.
3. It resolves the executable, hashes its bytes, and looks up the registered policy.
4. It enforces service namespaces and action scopes, then performs the keychain operation.

If the binary is unknown, access is denied and a pending entry records its path and hash. An administrator approves it with `keychain-auth list-pending` and `keychain-auth approve <hash>`.

The daemon is client neutral. Service names, key formats, and recovery messages belong to the calling client.

---

## Platform support

| Platform | Transport | Identity source | Store |
| --- | --- | --- | --- |
| Linux | Unix socket | `SO_PEERCRED` | Secret Service, or TPM2-sealed fallback |
| macOS | Unix socket | `LOCAL_PEERPID` | Apple Keychain |
| Windows | Named pipe | Pipe client PID | Credential Manager (DPAPI) |
| WSL | Unix socket | `SO_PEERCRED` | Windows host via `keychain-helper.exe` |

---

## Install and run

```bash
# System install, Linux and macOS. Configures service and daemon user.
sudo ./keychain-auth install

# User mode, no root required.
keychain-auth start
```

---

## Commands

| Command | Purpose |
| --- | --- |
| `keychain-auth start` | Start the daemon |
| `keychain-auth ensure-running [--json]` | Start only if needed and report the dialable socket |
| `keychain-auth restart [--json]` | Restart the daemon and report the dialable socket |
| `keychain-auth self-update [--version X] [--json]` | Verify and install a signed release |
| `keychain-auth status [--json]` | Show daemon health and configuration |
| `keychain-auth identity [--json]` | Show this binary's hash, mode, socket, and protocol version |
| `keychain-auth list-pending` | List binaries waiting for approval |
| `keychain-auth approve <hash>` | Approve a pending binary |
| `keychain-auth register <path>` | Register a binary with service scopes |
| `keychain-auth upgrade <path>` | Update a registered binary's hash |
| `keychain-auth check <path> <service>` | Check registration and authorization |

`status --json` is the bootstrap view. Integrators should prefer the wire `status` action, which describes the daemon the client is actually talking to. `identity` lets a client verify the peer before sending secrets. `ensure-running` returns the socket to dial, so clients do not reimplement service detection.

`self-update` verifies the downloaded archive against `checksums.txt` before replacing the binary. On Windows it writes `<binary>.new` because a running executable cannot be replaced in place.

---

## Wire protocol

Newline-delimited JSON over the local transport. One request per line, one response per line. Frames are limited to 10 MiB.

```json
{"type":"REQUEST","action":"read","service":"example","targets":["api_key"]}
```

```json
{"type":"RESPONSE","status":"success","results":[{"target":"api_key","value":"..."}]}
```

Actions are `read`, `write`, `delete`, `search`, `check`, `authorize`, and `status`. `status` is read-only and works before registration.

Full contract, including reason codes and response fields: [docs/integration_spec.md](docs/integration_spec.md).

---

## Client checklist

- Verify the daemon peer before sending secret values. Use `identity` plus your platform's peer credentials.
- Treat an unknown response action or `malformed_request` from `status` as "old daemon" and fall back to local diagnostics.
- Do not read the trust store yourself. On a system install it is not readable by the caller.
- Sign downloaded releases. See [docs/signing.md](docs/signing.md).

---

## Documentation

- [Architecture and integration guide](docs/architecture_and_integration_guide.md)
- [Wire protocol specification](docs/integration_spec.md)
- [Client tutorial](docs/tutorial.md)
- [Release signature verification](docs/signing.md)

## License

MIT. See [LICENSE](LICENSE).
