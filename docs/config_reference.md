# Configuration & Policy Reference

`keychain-auth` uses JSON configuration files to maintain authorized binary hash policies, pending approval queues, and system runtime parameters.

---

## File Locations & Permissions

The daemon resolves configuration files based on execution mode:

| File / Purpose | Linux / macOS Path | Windows Path | Mode & Permissions |
| :--- | :--- | :--- | :--- |
| **System Config** | `/etc/keychain-auth/config.json` | `C:\ProgramData\keychain-auth\config.json` | Mode `0600` (root/System) |
| **User Config** | `~/.config/keychain-auth/config.json` | `%APPDATA%\keychain-auth\config.json` | Mode `0600` (User owner) |
| **Pending Queue** | `~/.config/keychain-auth/pending.json` | `%APPDATA%\keychain-auth\pending.json` | Mode `0600` (User owner) |
| **Audit Log** | `/var/log/keychain-auth/audit.log` | `%APPDATA%\keychain-auth\audit.log` | Mode `0600` (User owner) |

---

## Configuration Schema (`config.json`)

```json
{
  "protocol_version": "1",
  "registered_binaries": [
    {
      "path": "/usr/local/bin/agentsecrets",
      "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "registered_at": "2026-08-05T20:00:00Z",
      "allowed_read_services": [
        "agentsecrets"
      ],
      "allowed_write_services": [
        "agentsecrets"
      ],
      "can_search": true
    }
  ]
}
```

### Top-Level Fields

- `protocol_version` (string, required): Wire protocol version (currently `"1"`).
- `registered_binaries` (array of objects): Array of registered binary policy objects.

### Binary Policy Schema (`registered_binaries[]`)

- `path` (string, required): Absolute file path to the registered executable binary.
- `hash` (string, required): Lowercase hexadecimal SHA-256 hash of the executable file.
- `registered_at` (string, optional): ISO 8601 UTC timestamp of registration.
- `allowed_read_services` (array of strings): Service namespaces the binary is authorized to `read` or `search`.
- `allowed_write_services` (array of strings): Service namespaces the binary is authorized to `write` or `delete`.
- `can_search` (array or boolean): If `true`, permits binary to issue `search` actions and prefix-based reads/deletes.

---

## Pending Queue Schema (`pending.json`)

When an unregistered binary attempts to query the socket, access is denied and the event is enqueued into `pending.json` for 24 hours:

```json
[
  {
    "hash": "a3b2c1d4...",
    "path": "/usr/local/bin/new-cli-tool",
    "invoked_at": "2026-08-05T20:15:00Z",
    "cli_args": ["new-cli-tool", "get", "secret"],
    "pid": 8412
  }
]
```

---

## Next Steps

- Inspect [CLI Reference](cli_reference.md) for management commands.
- Review [IPC Wire Protocol Specification](integration_spec.md) for request envelopes.
