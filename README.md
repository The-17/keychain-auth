# keychain-auth

A long-running daemon that mediates access between [AgentSecrets](https://agentsecrets.theseventeen.co) and the OS keychain. It verifies the identity of every requesting process and enforces policy on every secret read — no caching, no shortcuts, no trust.

## What It Does

keychain-auth sits between AgentSecrets and the operating system's native keychain (macOS Keychain / Linux Secret Service). When AgentSecrets needs to read a secret, it connects to keychain-auth over a Unix socket, proves its identity, and receives a session. Every subsequent secret request is re-verified against the live process before the secret is returned.

**keychain-auth owns:**
- Process identity verification (PID, binary path, binary hash)
- Session lifecycle (creation, validation, invalidation)
- OS keychain reads strictly bound to `{project_id}:{environment}:{key}` namespaces
- Audit logging of all access events

**keychain-auth does not own:**
- Writing or deleting secrets (AgentSecrets handles this directly)
- Encryption (the OS keychain handles this)
- Cloud sync, key rotation, or any product feature

## Architecture

```
┌─────────────────┐     Unix Socket      ┌──────────────────┐     OS API      ┌──────────────┐
│  AgentSecrets    │ ◄──────────────────► │  keychain-auth   │ ◄────────────► │  OS Keychain  │
│  (client)        │   JSON-over-socket   │  (daemon)        │   read-only    │  (storage)    │
└─────────────────┘                      └──────────────────┘                └──────────────┘
```

### Session Flow

1. AgentSecrets connects to `/var/run/keychain-auth/agent.sock`
2. Sends `SESSION_INIT` with its PID, binary path, and binary hash
3. keychain-auth verifies PID exists, resolves the real exe path from the OS, checks the SHA-256 hash against both the live binary and the registered hash
4. On success: issues a 256-bit random session token
5. AgentSecrets sends `SECRET_REQUEST` with the session token and a bare key name
6. keychain-auth re-verifies PID liveness and binary integrity on **every request**
7. Reads from `{project_id}:{environment}:{key}` (or development legacy fallbacks) in the OS keychain via `go-keyring` and returns the value

### Security Properties

- **No cached verification.** PID and binary hash are checked on every single request.
- **Namespace isolation.** keychain-auth will never read any keychain entry that doesn't strictly match the `{projectID}:{environment}:{key}` secret format (e.g. keypairs and allowlists are off-limits).
- **Secret values never leak.** They never appear in logs, error messages, or any response except `SECRET_RESPONSE`.
- **Sessions are memory-only.** On daemon restart, all sessions are invalidated. No disk persistence.
- **Registration required.** Binary hashes must be pre-registered via `keychain-auth register` before sessions are accepted.

## Platform Support

| Platform | Keychain Backend | Service Manager | Status |
|----------|-----------------|-----------------|--------|
| macOS    | Keychain Services | launchd (LaunchAgent) | Planned |
| Linux    | Secret Service API | systemd (user unit) | Planned |

## CLI Commands

```bash
keychain-auth start      # Start the daemon (usually managed by the OS service layer)
keychain-auth register   # Register a trusted AgentSecrets binary
keychain-auth upgrade    # Upgrade registration after an AgentSecrets update
```

## Development

```bash
# Prerequisites: Go 1.22+
go mod tidy
go build -o keychain-auth ./cmd/keychain-auth
go test ./...
```

## Project Structure

```
cmd/
  keychain-auth/          # Main entry point
internal/
  daemon/                 # Daemon lifecycle, signal handling, socket management
  session/                # Session map, token generation, session lifecycle
  verify/                 # PID verification, binary hash verification
  keychain/               # OS keychain abstraction (platform-specific)
  protocol/               # Message types, JSON serialisation, validation
  audit/                  # Audit log writer
  config/                 # Config file loading, registered binaries
  namespace/              # Key validation and namespace enforcement
```

## License

MIT — see [LICENSE](LICENSE).

## Links

- [AgentSecrets](https://agentsecrets.theseventeen.co)
- [The Seventeen](https://theseventeen.co)
