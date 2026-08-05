# Command Line Interface Reference

The `keychain-auth` executable functions as both the background security daemon and the administration CLI tool for managing registered binary policies.

---

## Global Syntax

```bash
keychain-auth [command] [flags]
```

---

## Commands Summary

| Command | Usage | Description |
| :--- | :--- | :--- |
| `start` | `keychain-auth start` | Launches the security daemon process in the background. |
| `status` | `keychain-auth status [--json]` | Reports health, operating mode, paths, and running version. |
| `list-pending` | `keychain-auth list-pending` | Lists unauthorized binaries currently queued in `pending.json`. |
| `approve` | `keychain-auth approve <hash>` | Approves a queued binary hash from the pending queue. |
| `register` | `keychain-auth register <path>` | Registers a trusted binary path and assigns initial service policies. |
| `upgrade` | `keychain-auth upgrade <path>` | Updates the registered SHA-256 hash after a binary update. |
| `check` | `keychain-auth check <path>` | Checks whether a binary is registered and authorized. |

---

## Detailed Command Specification

### `keychain-auth start`

Launches the background daemon listener. On Unix platforms, it binds to the Unix domain socket `/run/keychain-auth/agent.sock` (system mode) or `~/.config/keychain-auth/agent.sock` (user mode). On Windows, it creates the Named Pipe `\\.\pipe\keychain-auth`.

```bash
keychain-auth start
```

---

### `keychain-auth status`

Displays the health, operating mode, config path, socket path, and running version of the `keychain-auth` daemon.

#### Flags
- `--json`: Output status in machine-readable JSON format.

```bash
# Human-readable output
keychain-auth status

# Programmatic JSON output
keychain-auth status --json
```

#### Example JSON Response (v3.2.0)
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

### `keychain-auth list-pending`

Inspects the pending authorization queue (`pending.json`). When an unregistered binary attempts to query the socket, its request is denied and queued for administrator inspection.

```bash
keychain-auth list-pending
```

Example Output:
```text
PENDING BINARIES AWAITING AUTHORIZATION (1)
--------------------------------------------------------------------------------
Binary Path: /usr/local/bin/new-cli-tool
SHA-256:     a3b2c1...
Invoked At:  2026-08-05T20:15:00Z
CLI Args:    ["new-cli-tool", "get", "secret"]
--------------------------------------------------------------------------------
Run 'keychain-auth approve <hash>' to grant access.
```

---

### `keychain-auth approve`

Approves a pending binary hash from the pending queue and adds it to `config.json`.

```bash
keychain-auth approve <sha256-hash>
```

---

### `keychain-auth register`

Calculates the SHA-256 hash of an executable binary at `<path>` and registers its policy in `config.json`.

```bash
keychain-auth register /usr/local/bin/agentsecrets
```

---

### `keychain-auth upgrade`

Re-calculates the SHA-256 binary hash of an updated binary executable and updates the matching path entry in `config.json` without wiping assigned service policies.

```bash
keychain-auth upgrade $(which agentsecrets)
```

---

### `keychain-auth check`

Queries whether the executable at `<path>` is registered in `config.json` and permitted to communicate with the daemon.

```bash
keychain-auth check /usr/local/bin/agentsecrets
```

---

## Next Steps

- Review [Configuration & Policy Reference](config_reference.md) for config schema details.
- Read [Troubleshooting & Diagnostics](troubleshooting.md) for common error resolution.
