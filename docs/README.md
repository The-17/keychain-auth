# Keychain-Auth Documentation Hub

Welcome to the `keychain-auth` documentation hub. This directory contains modular, dedicated guides covering every aspect of the `keychain-auth` identity-verified security daemon.

---

## Documentation Categories

### Getting Started & Core Concepts
- [Getting Started Guide](getting_started.md): Installation, daemon initialization, basic binary registration, and health checks.
- [Security Architecture & Threat Model](architecture.md): Kernel-enforced IPC process identity attestation (`SO_PEERCRED`, `LOCAL_PEERPID`, Named Pipe Client PID), SHA-256 binary hash validation, and zero-trust namespace isolation.
- [Supported Storage Backends](storage_backends.md): Native OS keychains (Apple Keychain Services, Linux Secret Service D-Bus, Windows Credential Manager DPAPI), WSL Host Interop (`keychain-helper.exe`), and TPM2 hardware platform sealing.

### References & Configurations
- [Command Line Interface Reference](cli_reference.md): Complete CLI reference for `start`, `status [--json]`, `list-pending`, `approve`, `register`, `upgrade`, and `check`. Includes daemon version introspection schema (v3.2.0).
- [Configuration & Policy Reference](config_reference.md): JSON configuration schemas (`config.json`, `pending.json`), policy fields (`allowed_read_services`, `allowed_write_services`, `can_search`), file locations across OS platforms, and file permission security.
- [IPC Wire Protocol Specification](integration_spec.md): JSON wire protocol specification, IPC socket paths, request/response envelopes, actions (`read`, `write`, `delete`, `search`, `check`), match modes (`exact`, `prefix`), and granular error reason codes.

### Client Integration & Operations
- [Multi-Language Client SDKs](client_sdks.md): Step-by-step code patterns for connecting over local IPC in **Go**, **Python**, **Node.js**, **Rust**, and **Shell**.
- [Troubleshooting & Diagnostics Guide](troubleshooting.md): Troubleshooting common connection issues, error reason codes (`unregistered_binary_pending_approval`, `service_not_allowed`, `action_not_in_policy`), managing pending authorization queues, and analyzing `audit.log`.

---

## Full Architecture Manual & Tutorials

For deep-dive architectural references and step-by-step integration walkthroughs:
- [Master Architecture & Client Integration Manual](architecture_and_integration_guide.md): Monolithic deep-dive manual covering internal data flows, security guarantees, and multi-tenant namespace schemes.
- [End-to-End Client Integration Tutorial](tutorial.md): Detailed tutorial for building custom client CLI tools that interface with `keychain-auth`.
