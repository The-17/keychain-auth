# Chapter 1: The Core Architecture & Threat Model

Before writing client code, it is critical to understand *why* `keychain-auth` exists and the security vulnerabilities it mitigates in modern operating systems.

---

## 1.1 The Vulnerability of Native Keychains

Operating system keychains are designed to store credentials securely. However, the access control layer on desktop operating systems was built for a legacy desktop era and is fundamentally flawed for command-line interfaces (CLIs) and modern software supply chains.

### A. Linux Secret Service (D-Bus) Vulnerability
On Linux, the standard password managers (GNOME Keyring, KWallet) implement the FreeDesktop.org Secret Service API over D-Bus (`org.freedesktop.secrets`). 
* **The Flaw:** Any process running under the same user session can query the D-Bus secret service without password prompts or verification.
* **The Threat:** If you execute an untrusted CLI tool, or run a project containing a compromised dependency (e.g., an npm package, python pip package, or cargo crate containing a malicious post-install script), that script can silently read all your AWS credentials, Stripe tokens, or SSH keys stored in GNOME Keyring.

### B. Windows Credential Manager & DPAPI
Windows uses the Data Protection API (DPAPI) and Credential Manager.
* **The Flaw:** By default, DPAPI decrypts data for any process running under the identity of the current user.
* **The Threat:** Just like Linux D-Bus, any local script running in PowerShell or Command Prompt can invoke `CredRead` to dump all generic credentials stored under your user account.

### C. macOS Keychain "Prompt Fatigue"
macOS has a robust code-signing and entitlement system for GUI applications. However, it fails for CLI tools.
* **The Flaw:** Because command-line utilities are often unsigned, compiled locally, or executed inside virtual environments, the macOS `SecurityAgent` cannot uniquely identify them. This results in constant GUI prompts asking: *“your-cli wants to use your keychain. Enter password.”*
* **The Result:** Out of sheer frustration, users click **"Always Allow"**. Once clicked, macOS grants access to that service item to *any* command-line tool, completely bypassing the security boundaries.

---

## 1.2 The Security Broker Solution

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

---

## 1.3 The Critical `O_CLOEXEC` Requirement (The Security Contract)

If an authorized client application starts up, connects to the `keychain-auth` socket, and then forks/executes a child process (like a build script or an untrusted sub-command), the child process will **inherit all open file descriptors** by default.
* **The Danger:** The untrusted child process could write requests directly to the inherited socket descriptor. Since the connection was already authorized by the daemon, the child could read or delete all your secrets without authentication.
* **The Fix:** Clients **must** open the Unix domain socket with the `SOCK_CLOEXEC` flag (or set the descriptor as `O_CLOEXEC` on Unix, or configure handles as non-inheritable on Windows). This tells the kernel to automatically close the socket descriptor when performing any `exec()` system call, completely neutralizing handle-hijacking attacks.
