# Chapter 6: Daemon Lifecycle & Forensic Auditing

To successfully build client tools, you must understand how the user registers and approves your tools, and what errors are recorded in the forensic audit trails.

---

## 6.1 The "Pending Approval" Workflow

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

### Approving Safe CLI Tools
The user can inspect this pending authorization queue at any time:
```bash
keychain-auth list-pending
```
If the process is safe, they approve it:
```bash
keychain-auth approve [hash]
```
This adds the binary hash to `config.json` with a **default, restricted policy** containing empty permissions. The user then manually scopes the binary to allowed services.

---

## 6.2 Managing Binary Upgrades

When your client CLI tool is updated (e.g. your package manager installs `agentsecrets` v2.0.0), its SHA-256 binary hash changes.
* **The Result:** The next time the updated CLI tool queries the daemon, it will be rejected as an "unregistered binary" because its hash does not match the approved `config.json` database.
* **The Solution:** Package upgrade scripts or installers must execute the `upgrade` command:
  ```bash
  keychain-auth upgrade $(which agentsecrets)
  ```
  This command computes the new binary hash, locates the matching path in `config.json`, and updates the approved hash entry in place without destroying your existing permission policies.

---

## 6.3 Forensic Audit Logging

Every operation on the keychain auth daemon generates a highly granular event record inside the local audit log (`audit.log`). 

### Example Log File Entries (`audit.log`):
```json
{"timestamp":"2026-05-21T01:00:15Z","action":"write","pid":8412,"binary_path":"/usr/local/bin/agentsecrets","binary_hash":"sha256:abcd1234...","service":"AgentSecrets","targets":["proj_123:development:DATABASE_URL"],"result":"GRANTED"}
{"timestamp":"2026-05-21T01:01:22Z","action":"read","pid":8412,"binary_path":"/usr/local/bin/agentsecrets","binary_hash":"sha256:abcd1234...","service":"AgentSecrets","targets":["proj_123:development:DATABASE_URL"],"result":"GRANTED"}
{"timestamp":"2026-05-21T01:02:40Z","action":"read","pid":9123,"binary_path":"/usr/bin/curl","binary_hash":"sha256:ff398bc...","service":"aws","targets":["default"],"result":"DENIED","reason":"unregistered_binary_pending_approval"}
```

> [!CAUTION]
> **Audit Log Security Isolation:** Under no circumstances does the daemon write plaintext secret values to `audit.log`. This ensures that auditing is high-fidelity while presenting no side-channel credential leak vectors.
