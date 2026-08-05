# Troubleshooting & Diagnostics Guide

This guide provides operational solutions for common daemon connection errors, policy denials, queue management issues, and forensic log analysis.

---

## Common Error Reason Codes

When a daemon request fails, the response envelope includes a `status` of `"denied"` or `"error"` along with a `reason` code.

### 1. `unregistered_binary_pending_approval`
- **Cause**: The calling binary executable hash is not registered in `config.json`.
- **Diagnostic Step**: Check the pending authorization queue:
  ```bash
  keychain-auth list-pending
  ```
- **Resolution**: Approve the binary hash:
  ```bash
  keychain-auth approve <sha256-hash>
  # Or explicitly register the binary path:
  keychain-auth register $(which your-cli-tool)
  ```

---

### 2. `service_not_allowed`
- **Cause**: The calling binary is registered, but its policy does not authorize access to the requested `service` namespace.
- **Diagnostic Step**: Inspect `config.json` for the binary's entry:
  ```bash
  cat ~/.config/keychain-auth/config.json
  ```
- **Resolution**: Add the target service namespace (e.g., `"agentsecrets"`) to `allowed_read_services` or `allowed_write_services` for that binary hash entry.

---

### 3. `action_not_in_policy`
- **Cause**: The binary attempted an action (e.g. `delete` or `search` prefix match) that requires write or search permissions, but `can_search` is false or the action is restricted.
- **Resolution**: Ensure `can_search: true` is enabled in `config.json` if prefix matching or search operations are required.

---

### 4. `malformed_request`
- **Cause**: The JSON payload sent by the client is invalid, missing required envelope fields (`type`, `action`, `service`), or contains mismatched `targets` and `values` array lengths for `write` actions.
- **Resolution**: Verify client JSON encoding and ensure every request ends with a `\n` newline character.

---

### 5. `internal_error`
- **Cause**: Low-level OS keychain failure, D-Bus service unreachability, or permission error accessing host storage.
- **Resolution**: Check daemon logs (`audit.log` or systemd `journalctl -u keychain-auth`) for underlying kernel or keychain system errors.

---

## Daemon Connection Issues

### Socket File Not Found (`ENOENT` / `connection refused`)
- **Cause**: The `keychain-auth` background daemon is not running.
- **Resolution**: Start the daemon:
  ```bash
  keychain-auth start
  ```

### Stale Daemon Running After Package Upgrade
- **Symptom**: Integrating tool upgraded `keychain-auth`, but running daemon is serving old binary logic.
- **Resolution**: Query `status --json` to detect running daemon version and restart:
  ```bash
  keychain-auth status --json
  # If version mismatch detected, restart daemon:
  pkill keychain-auth && keychain-auth start
  ```

---

## Inspecting Audit Logs (`audit.log`)

The daemon writes structured JSON event records to `audit.log` for forensic inspection:

```json
{"timestamp":"2026-08-05T20:15:00Z","action":"read","pid":8412,"binary_path":"/usr/local/bin/agentsecrets","binary_hash":"sha256:e3b0c442...","service":"agentsecrets","targets":["api_key"],"result":"GRANTED"}
{"timestamp":"2026-08-05T20:16:12Z","action":"read","pid":9123,"binary_path":"/usr/bin/curl","binary_hash":"sha256:ff398bc...","service":"aws","targets":["default"],"result":"DENIED","reason":"unregistered_binary_pending_approval"}
```

> [!NOTE]
> `audit.log` never records plaintext secret values under any circumstances, preserving full forensic visibility without credential leakage vectors.
