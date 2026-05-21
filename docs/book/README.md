# The Keychain-Auth Master Book: Architecture & Client Integration Manual

Welcome to the official developer manual for the `keychain-auth` security proxy. This book is divided into seven technical chapters designed to guide you through the low-level operating system mechanics, IPC channels, custom protocol schemas, and client-side implementations in various languages.

Use this directory to understand the system and build secure companion applications (like `agentsecrets` or any other tool) that safely query namespaced OS keychains.

---

## Chapters

### 1. [Chapter 1: The Core Architecture & Threat Model](chapter_1_threat_model.md)
* Understand the security gaps in native OS keychains (D-Bus, DPAPI, and macOS prompt fatigue).
* Learn about the **Zero-Trust Security Broker** design.
* Explore the critical **`O_CLOEXEC`** security contract to prevent socket handle hijacking.

### 2. [Chapter 2: Kernel-Level Identity & IPC Transport](chapter_2_ipc_transport.md)
* Learn how the Unix sockets and Windows named pipes are set up.
* Deep-dive into verified process identity extraction (`SO_PEERCRED`, `LOCAL_PEERPID`, and pipe handles).
* Explore process binary path resolution and disk SHA-256 cryptographic hashing.

### 3. [Chapter 3: The JSON Wire Protocol Specification](chapter_3_protocol_spec.md)
* Canonical JSON request and response envelope definitions.
* Detailed field breakdown tables.
* Dictionary of granular response reason codes.

### 4. [Chapter 4: Advanced Multi-Tenant Namespace Schemes](chapter_4_namespace_schemes.md)
* Direct Shared Namespaces vs Private Isolated Namespaces.
* Hierarchical target key naming patterns (e.g. `{project}:{env}:{key}`).
* Segmenting environment topologies inside flat OS keychain storage.

### 5. [Chapter 5: Step-by-Step Client Implementations](chapter_5_client_implementations.md)
* Comprehensive, fully self-contained socket clients with `O_CLOEXEC` capabilities.
* Step-by-step production-grade code in **Go**.
* Step-by-step production-grade code in **Python** (Unix socket + Windows named pipe).
* Step-by-step production-grade code in **Node.js**.

### 6. [Chapter 6: Daemon Lifecycle & Forensic Auditing](chapter_6_lifecycle_auditing.md)
* Exploring the unregistered process "Pending Approval Queue" workflow.
* Managing binary upgrades and hash migrations via the CLI.
* High-fidelity, zero-leak forensic JSON audit logs.

### 7. [Chapter 7: Production Integration Checklist](chapter_7_production_checklist.md)
* Go-to checklist for client security compliance, installation hooks, and UX.
