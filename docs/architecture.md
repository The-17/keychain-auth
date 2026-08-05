# Security Architecture & Threat Model

`keychain-auth` implements an identity-verified security boundary between client applications (CLIs, microservices, AI agents) and native operating system keychains.

---

## The Core Threat Vector

Native operating system secret stores were designed for traditional desktop environments:

- **Linux (D-Bus Secret Service)**: Any process running under the logged-in user account can issue D-Bus requests to read all stored secrets without elevation or user notification.
- **Windows (Credential Manager / DPAPI)**: Any local process under the same user token can invoke `CredRead` to extract plaintext credentials.
- **macOS (Keychain Services)**: Frequent security prompts trigger prompt fatigue, causing users to grant unrestricted access to untrusted binaries.
- **Malicious Dependency Scraping**: Compromised package manager dependencies (`npm`, `pip`, `cargo`, `PyPI`) can execute background scripts that query OS keychains directly.

`keychain-auth` eliminates these vectors by forcing all keychain requests through a hardened daemon that verifies process identity at the OS kernel level.

---

## Identity Attestation Architecture

```
┌──────────────────────────┐                  ┌──────────────────────────────┐                  ┌─────────────────────────────┐
│  Client CLI / AI Agent   │                  │     keychain-auth Daemon     │                  │    Native OS Secret Store   │
│  (e.g., agentsecrets)    │                  │  (Identity & Policy Engine)  │                  │  (Keychain / D-Bus / DPAPI) │
└────────────┬─────────────┘                  └──────────────┬───────────────┘                  └──────────────┬──────────────┘
             │                                               │                                                 │
             │  1. Connect via Local IPC                     │                                                 │
             ├──────────────────────────────────────────────►│                                                 │
             │                                               │  2. Kernel Peer Identity Attestation            │
             │                                               │     (SO_PEERCRED / LOCAL_PEERPID)               │
             │                                               ├────────────────────────┐                        │
             │                                               │                        │                        │
             │                                               │  3. Verify Executable  │                        │
             │                                               │     Path & SHA-256 Hash │                        │
             │                                               │◄───────────────────────┘                        │
             │                                               │                                                 │
             │                                               │  4. Enforce Namespace & Policy                  │
             │  5. Perform Keychain Read/Write               │     (allowed_read_services / allowed_write)     │
             │◄──────────────────────────────────────────────┼────────────────────────────────────────────────►│
             │                                               │                                                 │
```

### 1. Kernel-Enforced Peer Attestation
`keychain-auth` never trusts caller-supplied process IDs, tokens, or environment headers. When a client dials the local IPC socket, the daemon queries kernel socket structures:

- **Linux (`SO_PEERCRED`)**: Extracts `ucred` structure (`pid`, `uid`, `gid`) directly from the socket option.
- **macOS (`LOCAL_PEERPID`)**: Interrogates socket options via `getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID)` to obtain the verified PID.
- **Windows (Named Pipe Impersonation)**: Uses Named Pipe server APIs (`GetNamedPipeServerProcessId`) to retrieve the authenticated caller process ID.

### 2. Executable Path & SHA-256 Binary Hash Verification
Once the caller PID is verified by the kernel:
1. The daemon resolves the absolute executable path from `/proc/<pid>/exe` (Linux), `proc_pidpath` (macOS), or `QueryFullProcessImageName` (Windows).
2. It evaluates symlinks to establish canonical binary identity.
3. It computes the SHA-256 cryptographic hash of the target executable file on disk.
4. It compares the SHA-256 hash against `/etc/keychain-auth/config.json` (or `~/.config/keychain-auth/config.json`).

### 3. Zero-Trust Namespace Policy Engine
Access policies are configured per binary hash:

```json
{
  "path": "/usr/local/bin/agentsecrets",
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "allowed_read_services": ["agentsecrets"],
  "allowed_write_services": ["agentsecrets"],
  "can_search": true
}
```

- **Service Isolation**: A binary authorized for service `"agentsecrets"` cannot read or write keys under `"aws"`, `"openai"`, or any other namespace.
- **Action Restriction**: Destructive actions (`delete`) require explicit entry in `allowed_write_services`.
- **Atomic Batch Evaluation**: If a request contains multiple targets and any single target fails policy validation, the entire request is rejected atomically.

---

## Next Steps

- Review [Supported Storage Backends](storage_backends.md) for TPM2 hardware sealing and WSL Host Interop.
- Inspect the [Configuration Reference](config_reference.md) for policy schema details.
- Read [IPC Wire Protocol Specification](integration_spec.md) for wire protocol envelopes.
